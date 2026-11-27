/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.net.quic.openssl;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.res.StringManager;

/**
 * OpenSSL endpoint specialization of the shared poll-task mailbox
 * ({@code org.apache.tomcat.util.net.quic.QuicNativeMailbox}), adding three
 * work queues that cross the endpoint's poll-thread confinement boundary
 * beside the base poll-task queue:
 * <ul>
 * <li>{@code pendingStreamDrains}: streams whose native SSL free must wait for
 * their OpenSSL stream write buffer to drain (all bytes acknowledged by the
 * peer); freeing the SSL earlier discards the buffered response bytes. The
 * wait is bounded by {@link #STREAM_DRAIN_TIMEOUT_MS}: a peer that withholds
 * stream-level ACKs can no longer retain the queue, the wrappers and their
 * buffers indefinitely.</li>
 * <li>{@code cleanerStreamFrees}: stream frees requested by the
 * {@link QuicStreamWrapper} Cleaner running on the GC thread; the free
 * decision is deferred to the poll thread so it is serialized with
 * connection teardown.</li>
 * <li>{@code cleanerConnectionFrees}: connection frees requested by the
 * {@link QuicConnectionWrapper} Cleaner running on the GC thread; the free
 * decision is deferred to the poll thread for the same reason (OpenSSL's
 * QUIC objects are single-threaded by default and the poll thread drives
 * the shared engine).</li>
 * </ul>
 * The extra drains perform native work and must run on the poll thread, or -
 * once the poll loop has stopped - on a single thread at a time accepted by
 * the endpoint's native-access policy (the stop thread, or the last handler's
 * worker during retained-connection reclaim); the confinement check inherited
 * from the base is applied to each so a future mis-threading is caught under
 * {@code -ea}.
 * <p>
 * This class owns all three queues. {@code QuicOpenSSLEndpoint} exposes
 * one-line delegating wrappers for the drains so call sites document the
 * required ordering (streams before connections); those wrappers add no state
 * and must stay that way.
 */
class QuicNativeMailbox extends org.apache.tomcat.util.net.quic.QuicNativeMailbox {

    private static final Log log = LogFactory.getLog(QuicNativeMailbox.class);
    // quicEndpoint.* messages live in this package's string bundle; sharing
    // the endpoint's StringManager keeps the wording identical to the
    // transports that never had a separate bundle entry for these two
    // stream-free errors.
    private static final StringManager sm =
            StringManager.getManager(QuicOpenSSLEndpoint.class);

    /**
     * Maximum time a stream SSL is retained waiting for the peer to
     * acknowledge its native send buffer. A peer can keep a connection alive
     * with transport-level traffic while withholding stream-level ACKs;
     * without this bound the deferred queue, the stream wrappers (which hold
     * their connection), the Java read buffers and the native send buffers
     * would accumulate indefinitely.
     */
    static final long STREAM_DRAIN_TIMEOUT_MS = 5000;

    /**
     * Streams whose native write buffer still holds bytes the peer has not
     * acknowledged. Their SSL must stay alive until the buffer drains,
     * otherwise the buffered response bytes are discarded instead of being
     * delivered. The poll thread re-checks them (see
     * {@link #drainPendingStreamDrains(QuicConnectionWrapper, boolean)}),
     * which frees the stream SSL directly once the buffer has drained or
     * fails the owning connection when the bounded acknowledgement wait
     * expires.
     */
    private final ConcurrentLinkedQueue<QuicStreamWrapper> pendingStreamDrains =
            new ConcurrentLinkedQueue<>();

    /**
     * Invoked on the poll thread after a deferred stream SSL was freed because
     * its send buffer was still unacknowledged when the drain deadline
     * expired. The endpoint fails the owning connection, because the stream
     * data could no longer be delivered and the stream must not be left
     * dangling on a connection that retains its native send state.
     */
    private final Consumer<QuicStreamWrapper> stalledDrainHandler;

    /**
     * Receives a fatal native-binding failure detected during a deferred
     * free/drain. The endpoint marks the generation failed; after notifying it
     * the drain rethrows the fatal error so the poll/stop thread does not
     * continue driving broken bindings. May be {@code null} for tests.
     */
    private final Consumer<Throwable> fatalFailureHandler;

    private final ConcurrentLinkedQueue<QuicStreamWrapper.DeferredStreamFree>
            cleanerStreamFrees = new ConcurrentLinkedQueue<>();

    private final ConcurrentLinkedQueue<QuicConnectionWrapper.DeferredConnectionFree>
            cleanerConnectionFrees = new ConcurrentLinkedQueue<>();

    /**
     * Ensures the warning about an unavailable native stream write-buffer
     * statistic is logged at most once per mailbox. The statistic is optional
     * in the OpenSSL value table and is the only way to decide whether a
     * deferred stream SSL still has unacknowledged response bytes.
     */
    private final AtomicBoolean writeBufStatUnavailableWarned =
            new AtomicBoolean(false);


    /**
     * Creates the mailbox.
     *
     * @param confinementCheck applied at the start of every drain (this
     *                         class's and the base's) with the operation
     *                         name; asserts the poll-thread (or
     *                         stopped-poll-thread) confinement invariant
     * @param stalledDrainHandler invoked on the poll thread after a stalled
     *                         stream SSL was freed at its drain deadline
     * @param taskFailureHandler handles a poll-task failure; may be
     *                         {@code null} for the base log-and-continue policy
     * @param fatalFailureHandler receives fatal native-binding failures from
     *                         the deferred drains; may be {@code null}
     */
    QuicNativeMailbox(Consumer<String> confinementCheck,
            Consumer<QuicStreamWrapper> stalledDrainHandler,
            Consumer<Throwable> taskFailureHandler,
            Consumer<Throwable> fatalFailureHandler) {
        super(confinementCheck, taskFailureHandler);
        this.stalledDrainHandler = stalledDrainHandler;
        this.fatalFailureHandler = fatalFailureHandler;
    }


    /**
     * Closes the mailbox and drains the transport-specific deferred-free
     * queues. A late worker or Cleaner request can be enqueued after the
     * endpoint stop's explicit drain pass but before the mailbox close; leaving
     * it here would keep its wrapper and native SSL reachable across a
     * destroy/unbind or until the next start. The poll thread is stopped when
     * the endpoint closes the mailbox, so the closing thread is the permitted
     * single native caller.
     */
    @Override
    public void close() {
        super.close();
        drainDeferredQueues();
    }


    /**
     * Drains deferred work left by the previous generation before re-opening
     * the mailbox for a new start. The endpoint already drains these queues
     * before calling open(); this second drain closes the small window in
     * which a late worker enqueued work between that drain and the open.
     */
    @Override
    public void open() {
        drainDeferredQueues();
        super.open();
    }


    private void drainDeferredQueues() {
        drainPendingStreamDrains(null, true);
        drainCleanerStreamFrees();
        drainCleanerConnectionFrees();
    }


    /**
     * Reports a possible fatal binding failure to the endpoint before a drain
     * rethrows it. The endpoint handler marks the generation failed and must
     * not throw; any accidental handler failure is contained here.
     *
     * @param t The caught failure
     *
     * @return The fatal binding failure, or {@code null}
     */
    private Throwable reportFatalFailure(Throwable t) {
        Throwable fatal = QuicOpenSSLEndpoint.findFatalBindingFailure(t);
        if (fatal != null && fatalFailureHandler != null) {
            try {
                fatalFailureHandler.accept(fatal);
            } catch (Throwable handlerFailure) {
                ExceptionUtils.handleThrowable(handlerFailure);
                log.warn(sm.getString("quicEndpoint.pollTaskError"),
                        handlerFailure);
            }
        }
        return fatal;
    }


    /**
     * Reports whether any deferred stream or connection SSL free is queued
     * (from a close path or from either Cleaner).
     * <p>
     * The poll loop treats a non-empty queue as pending work, so a free that
     * is already queued when an iteration computes its wait is not delayed by
     * an idle-rate {@code SSL_poll()} timeout. Close-path enqueues run on the
     * poll thread (the loop sees them before waiting). A Cleaner enqueue
     * happens on the GC thread and does not kick the wake descriptor (see the
     * note in {@code QuicStreamWrapper.State.run()} for why), so a free queued
     * while a wait is already in progress waits out at most that wait - bounded
     * by the loop's idle-rate timeout, or {@code pollTimeoutMs} while the
     * endpoint is busy - before the next iteration drains it. This is bounded
     * latency, not a lost free.
     *
     * @return {@code true} if at least one deferred free is queued
     */
    boolean hasDeferredStreamFrees() {
        return !pendingStreamDrains.isEmpty()
                || !cleanerStreamFrees.isEmpty()
                || !cleanerConnectionFrees.isEmpty();
    }


    /**
     * Defers freeing a stream's native SSL until its write buffer has
     * drained. OpenSSL's stream write buffer can still hold bytes accepted
     * from the application after the handler has finished; freeing the stream
     * SSL at close time discards those bytes. The poll thread checks the
     * native {@code SSL_get_stream_write_buf_used()} counter and only frees
     * the stream once the peer has acknowledged everything it accepted (or
     * the connection is going away, when delivery can no longer be
     * guaranteed anyway).
     *
     * @param stream The stream whose free is deferred until its write buffer
     *               drains
     */
    void queueStreamDrain(QuicStreamWrapper stream) {
        stream.setStreamDrainDeadlineIfUnset(
                System.currentTimeMillis() + STREAM_DRAIN_TIMEOUT_MS);
        pendingStreamDrains.add(stream);
    }


    /**
     * Re-checks the streams queued by {@link #queueStreamDrain()} and frees
     * the stream SSL directly once its native write buffer has drained. The
     * direct free has no second deferral hop: callers must invoke this after
     * {@code SSL_poll()} has flushed any pending frame (the normal poll-loop
     * point) or after a batch {@code SSL_handle_events()} tick on a stopped
     * poll loop, because freeing the SSL before the engine sends the queued
     * stream output discards it. Must run on the poll thread, or on a single
     * permitted thread once the poll loop has stopped (see the class-level
     * threading rule).
     *
     * @param forceFreeConn If non-{@code null}, streams belonging to this
     *                      connection are freed regardless of their write
     *                      buffer state (the connection is being torn down).
     *                      A stream still owned by a handler is always kept
     *                      until that handler releases it, whatever the force
     *                      flag.
     * @param forceAll      {@code true} to free every queued stream except
     *                      those still owned by a handler (endpoint stop)
     */
    void drainPendingStreamDrains(QuicConnectionWrapper forceFreeConn,
            boolean forceAll) {
        confinementCheck.accept("drainPendingStreamDrains");
        List<QuicStreamWrapper> waiting = new ArrayList<>();
        QuicStreamWrapper stream;
        while ((stream = pendingStreamDrains.poll()) != null) {
            if (stream.isFreed()) {
                continue;
            }
            // Atomically claim the stream before inspecting its write buffer
            // or freeing its SSL. A plain isProcessing() read leaves a window
            // in which a dispatch worker claims the stream between the check
            // and the free, turning the deferred free into a use-after-free.
            if (!stream.compareAndSetProcessing(false, true)) {
                // A handler still owns the stream: do not free its SSL
                // regardless of force flags. The worker's
                // finishStreamDispatch() queues the free once the handler has
                // released the claim.
                waiting.add(stream);
                continue;
            }
            boolean keep = false;
            try {
                QuicConnectionWrapper conn = stream.getConnection();
                boolean force = forceAll ||
                        (forceFreeConn != null && forceFreeConn == conn) ||
                        conn == null || conn.isClosing() || conn.isClosed() ||
                        conn.isFreed();
                long used = force ? 0L
                        : QuicBindings.SSL_get_stream_write_buf_used(stream.getSsl());
                if (used != 0L) {
                    long deadline = stream.getStreamDrainDeadlineMs();
                    if (!force && deadline != 0L &&
                            System.currentTimeMillis() >= deadline) {
                        // The peer did not acknowledge the stream's send
                        // buffer within the bounded wait. Keeping the SSL any
                        // longer lets a peer that withholds ACKs while sending
                        // other traffic accumulate native send buffers and
                        // Java read buffers indefinitely. Discard the
                        // remaining stream data, free the stream SSL (before
                        // any connection teardown, per SSL_new_stream(3)) and
                        // fail the owning connection through the endpoint
                        // handler.
                        stream.freeSslOnce();
                        if (stream.isFreed()) {
                            stalledDrainHandler.accept(stream);
                        }
                    } else {
                        // A positive value means unacknowledged bytes remain. A
                        // negative value means the query could not be answered
                        // (for example because the linked OpenSSL does not
                        // expose SSL_VALUE_STREAM_WRITE_BUF_USED), so the safe
                        // default is to keep the SSL rather than discard
                        // buffered response bytes. The binding clears the
                        // handled error-queue entry for the rejected query. The
                        // connection teardown paths force the free once delivery
                        // can no longer be guaranteed, and the drain deadline
                        // bounds even this "statistic unavailable" case.
                        keep = true;
                        if (used < 0L && writeBufStatUnavailableWarned.compareAndSet(
                                false, true)) {
                            log.warn(sm.getString(
                                    "quicEndpoint.streamWriteBufStatUnavailable",
                                    Long.valueOf(stream.getStreamId())));
                        }
                    }
                } else {
                    stream.freeSslOnce();
                }
            } catch (Throwable t) {
                // freeSslOnce() marks the shared freed flag before calling
                // SSL_free(), so a failed free cannot be retried safely. If
                // the failure happened before the stream was freed (for
                // example the write-buffer statistic query failed), mark the
                // connection sticky so its own SSL is retained rather than
                // freed under a possibly-live stream.
                if (!stream.isFreed()) {
                    QuicConnectionWrapper conn = stream.getConnection();
                    if (conn != null) {
                        conn.markStreamFreeFailed();
                    }
                }
                Throwable fatal = reportFatalFailure(t);
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("quicEndpoint.streamFreeDrainError",
                        Long.valueOf(stream.getStreamId())), t);
                if (fatal != null) {
                    throw (Error) fatal;
                }
            } finally {
                stream.clearProcessing();
            }
            if (keep) {
                waiting.add(stream);
            }
        }
        pendingStreamDrains.addAll(waiting);
    }


    /**
     * Drains the Cleaner's deferred stream SSL free requests. Each request's
     * free is guarded by the shared {@code freed} CAS, so it is a no-op for
     * streams already freed by any of the explicit close paths. The free is
     * NOT skipped when the owning connection is closing: per SSL_new_stream(3)
     * the stream SSL must be freed before the connection SSL, and
     * closeAllStreams() deliberately skips streams whose handler is still
     * running, so a closing connection can still be waiting on this free (see
     * QuicStreamWrapper.DeferredStreamFree).
     */
    void drainCleanerStreamFrees() {
        confinementCheck.accept("drainCleanerStreamFrees");
        QuicStreamWrapper.DeferredStreamFree request;
        while ((request = cleanerStreamFrees.poll()) != null) {
            try {
                request.run();
            } catch (Throwable t) {
                Throwable fatal = reportFatalFailure(t);
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("quicEndpoint.streamFreeCleanerError"), t);
                if (fatal != null) {
                    throw (Error) fatal;
                }
            }
        }
    }


    /**
     * Drains the Cleaner's deferred connection SSL free requests. Each
     * request's free is guarded by the shared {@code freed} CAS, so it is a
     * no-op for connections already freed by any of the teardown paths.
     * Every stream SSL of a connection must be freed before the connection
     * SSL (per SSL_new_stream(3)), so callers run this after
     * {@link #drainPendingStreamDrains(QuicConnectionWrapper, boolean)} and
     * {@link #drainCleanerStreamFrees()}.
     */
    void drainCleanerConnectionFrees() {
        confinementCheck.accept("drainCleanerConnectionFrees");
        QuicConnectionWrapper.DeferredConnectionFree request;
        while ((request = cleanerConnectionFrees.poll()) != null) {
            try {
                request.run();
            } catch (Throwable t) {
                Throwable fatal = reportFatalFailure(t);
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("quicEndpoint.connectionFreeCleanerError"), t);
                if (fatal != null) {
                    throw (Error) fatal;
                }
            }
        }
    }


    /**
     * Returns the queue the {@link QuicStreamWrapper} Cleaner uses to request
     * a stream SSL free on the poll thread.
     *
     * @return The cleaner stream free queue
     */
    ConcurrentLinkedQueue<QuicStreamWrapper.DeferredStreamFree>
            getCleanerStreamFrees() {
        return cleanerStreamFrees;
    }


    /**
     * Returns the queue the {@link QuicConnectionWrapper} Cleaner uses to
     * request a connection SSL free on the poll thread.
     *
     * @return The cleaner connection free queue
     */
    ConcurrentLinkedQueue<QuicConnectionWrapper.DeferredConnectionFree>
            getCleanerConnectionFrees() {
        return cleanerConnectionFrees;
    }
}

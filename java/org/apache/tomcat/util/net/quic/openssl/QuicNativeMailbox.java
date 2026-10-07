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

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Consumer;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;

/**
 * OpenSSL endpoint specialization of the shared poll-task mailbox
 * ({@code org.apache.tomcat.util.net.quic.QuicNativeMailbox}), adding the two
 * work queues that cross the endpoint's poll-thread confinement boundary
 * beside the base poll-task queue:
 * <ul>
 * <li>{@code pendingStreamFrees}: streams whose native SSL free was deferred
 * to run just after {@code SSL_poll()} flushed any pending frame.</li>
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
 * The two extra drains perform native work and must run on the poll thread
 * (or on the stop thread once the poll loop has stopped); the confinement
 * check inherited from the base is applied to each so a future mis-threading
 * is caught under {@code -ea}.
 */
class QuicNativeMailbox extends org.apache.tomcat.util.net.quic.QuicNativeMailbox {

    private static final Log log = LogFactory.getLog(QuicNativeMailbox.class);
    // quicEndpoint.* messages live in this package's string bundle; sharing
    // the endpoint's StringManager keeps the wording identical to the
    // transports that never had a separate bundle entry for these two
    // stream-free errors.
    private static final StringManager sm =
            StringManager.getManager(QuicOpenSSLEndpoint.class);

    private final ConcurrentLinkedQueue<QuicStreamWrapper> pendingStreamFrees =
            new ConcurrentLinkedQueue<>();

    private final ConcurrentLinkedQueue<QuicStreamWrapper.DeferredStreamFree>
            cleanerStreamFrees = new ConcurrentLinkedQueue<>();

    private final ConcurrentLinkedQueue<QuicConnectionWrapper.DeferredConnectionFree>
            cleanerConnectionFrees = new ConcurrentLinkedQueue<>();


    /**
     * Creates the mailbox.
     *
     * @param confinementCheck applied at the start of every drain (this
     *                         class's and the base's) with the operation
     *                         name; asserts the poll-thread (or
     *                         stopped-poll-thread) confinement invariant
     */
    QuicNativeMailbox(Consumer<String> confinementCheck) {
        super(confinementCheck);
    }


    /**
     * Reports whether any deferred stream or connection SSL free is queued
     * (from a close path or from either Cleaner). The poll loop treats a
     * non-empty queue as pending work so a queued free is not delayed by an
     * idle-rate {@code SSL_poll()} timeout.
     * <p>
     * That statement is a steady-state one: it holds for every iteration that
     * observes the queue before computing its wait. Close-path enqueues run
     * on the poll thread (the loop sees them before waiting); the Cleaner's
     * enqueue happens on the GC thread and does not kick the wake descriptor
     * (see the note in {@code QuicStreamWrapper.State.run()} for why), so a
     * free queued while a wait is already in progress waits out at most that
     * wait - bounded by
     * the loop's idle-rate timeout, or {@code pollTimeoutMs} while the
     * endpoint is busy - before the next iteration drains it. Bounded
     * latency, not a lost free.
     *
     * @return {@code true} if at least one deferred free is queued
     */
    boolean hasDeferredStreamFrees() {
        return !pendingStreamFrees.isEmpty() || !cleanerStreamFrees.isEmpty()
                || !cleanerConnectionFrees.isEmpty();
    }


    /**
     * Defers freeing a stream's native SSL object to the next post-{@code
     * SSL_poll()} drain, so a frame queued during the same iteration (for
     * example a RESET_STREAM) reaches the network first. Keeping the wrapper
     * in the queue also keeps it reachable so its Cleaner cannot free the
     * native object early.
     *
     * @param stream The stream whose free is deferred
     */
    void queueStreamFree(QuicStreamWrapper stream) {
        pendingStreamFrees.add(stream);
    }


    /**
     * Frees the stream SSL objects whose free the close paths deferred to run
     * after {@code SSL_poll()} has flushed any pending frames.
     * {@code freeSslOnce()} is a no-op when the stream was already freed by
     * another path (shared freed CAS). Every stream SSL must be freed before
     * the connection SSL it holds a reference on (per SSL_new_stream(3)), so
     * the connection free paths drain this queue first.
     */
    void drainPendingStreamFrees() {
        confinementCheck.accept("drainPendingStreamFrees");
        QuicStreamWrapper deferredStream;
        while ((deferredStream = pendingStreamFrees.poll()) != null) {
            try {
                deferredStream.freeSslOnce();
            } catch (Throwable t) {
                log.warn(sm.getString("quicEndpoint.streamFreeDeferredError",
                        Long.valueOf(deferredStream.getStreamId())), t);
            }
        }
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
                log.warn(sm.getString("quicEndpoint.streamFreeCleanerError"), t);
            }
        }
    }


    /**
     * Drains the Cleaner's deferred connection SSL free requests. Each
     * request's free is guarded by the shared {@code freed} CAS, so it is a
     * no-op for connections already freed by any of the teardown paths.
     * Every stream SSL of a connection must be freed before the connection
     * SSL (per SSL_new_stream(3)), so callers run this after
     * {@link #drainPendingStreamFrees()} and {@link #drainCleanerStreamFrees()}.
     */
    void drainCleanerConnectionFrees() {
        confinementCheck.accept("drainCleanerConnectionFrees");
        QuicConnectionWrapper.DeferredConnectionFree request;
        while ((request = cleanerConnectionFrees.poll()) != null) {
            try {
                request.run();
            } catch (Throwable t) {
                log.warn(sm.getString("quicEndpoint.connectionFreeCleanerError"), t);
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

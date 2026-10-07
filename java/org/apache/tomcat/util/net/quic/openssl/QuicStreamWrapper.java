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

import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.tomcat.util.net.quic.QuicStream;
import org.apache.tomcat.util.openssl.openssl_h;

/**
 * Wraps a QUIC stream (an {@code SSL *} representing a bidirectional or
 * unidirectional stream on a QUIC connection).
 * <p>
 * Each stream is associated with a parent {@link QuicConnectionWrapper} and
 * has its own {@link QuicPollItem} for event-driven I/O.
 */
public class QuicStreamWrapper implements QuicStream {

    private static final Cleaner cleaner = Cleaner.create();

    /**
     * The native SSL* pointer for this stream.
     */
    private final MemorySegment ssl;

    /**
     * The unique QUIC stream identifier.
     */
    private final long streamId;

    /**
     * Stream direction: {@link QuicPoll#SSL_STREAM_TYPE_READ},
     * {@link QuicPoll#SSL_STREAM_TYPE_WRITE}, or
     * {@link QuicPoll#SSL_STREAM_TYPE_BIDI}.
     */
    private final int streamType;

    /**
     * The parent connection.
     */
    private final QuicConnectionWrapper connection;

    /**
     * Poll item for this stream.
     */
    private QuicPollItem pollItem;

    /**
     * Read buffer for data received from the stream.
     */
    private final ByteBuffer readBuffer;

    /**
     * Write buffer for pending data to send on the stream.
     */
    private ByteBuffer writeBuffer;

    /**
     * Current read state of the stream.
     */
    private volatile ReadState readState;

    /**
     * Whether this stream is currently being processed by an executor thread.
     * Used to prevent concurrent R/W dispatches in the same poll iteration.
     */
    private final AtomicBoolean processing = new AtomicBoolean(false);


    /**
     * Atomically sets the processing flag if currently not processing.
     *
     * @param expect The value expected for the flag
     * @param update The new value for the flag
     *
     * @return {@code true} if successfully set to processing
     */
    public boolean compareAndSetProcessing(boolean expect, boolean update) {
        return processing.compareAndSet(expect, update);
    }


    /**
     * Clears the processing flag.
     */
    public void clearProcessing() {
        processing.set(false);
    }

    /**
     * Checks whether this stream is currently being processed by an executor
     * thread.
     *
     * @return {@code true} if a worker is running the HTTP handler for this
     *         stream
     */
    public boolean isProcessing() {
        return processing.get();
    }

    /**
     * Whether this stream has been concluded (FIN sent).
     */
    private volatile boolean concluded;

    /**
     * Whether the native SSL object has been freed.
     * Prevents double-free from both explicit cleanup and Cleaner.
     * <p>
     * An {@link AtomicBoolean} shared with the Cleaner's {@link State} so the
     * State can check/set the flag WITHOUT holding a strong reference to this
     * wrapper. Holding the wrapper strongly from the (static) Cleaner would
     * keep every stream (and its connection) alive forever.
     */
    private final AtomicBoolean freed = new AtomicBoolean(false);

    /**
     * Whether the endpoint has removed this stream from its bookkeeping
     * (stream map, poll set and wrapper map). Set on the poll thread by
     * {@code QuicOpenSSLEndpoint.deregisterStream()}. A worker thread that is
     * still processing the stream when deregistration happens defers the SSL
     * free until it stops touching the native object.
     */
    private volatile boolean deregistered;

   /**
    * Whether this is the primary server-initiated unidirectional stream
    * (protocol index 0; for HTTP/3 the server control stream). The endpoint
    * writes its protocol data (SETTINGS, stream retirement notifications)
    * on this stream.
    */
    private volatile boolean primaryUniStream;


    /**
     * Creates a new stream wrapper.
     *
     * @param ssl        The SSL* pointer for the stream
     * @param streamId   The QUIC stream ID
     * @param streamType The stream type (read, write, bidi)
     * @param connection The parent connection
     * @param buffer     The read buffer
     */
    public QuicStreamWrapper(MemorySegment ssl, long streamId, int streamType,
            QuicConnectionWrapper connection, ByteBuffer buffer) {
        this.ssl = ssl;
        this.streamId = streamId;
        this.streamType = streamType;
        this.connection = connection;
        this.readBuffer = buffer;
        this.writeBuffer = null;
        this.readState = ReadState.OK;
        this.concluded = false;
        this.primaryUniStream = false;

        // Pass the shared freed flag (NOT 'this' / the connection) so the
        // Cleaner does not keep this wrapper (or its connection) strongly
        // reachable. The endpoint's cleaner-stream-free queue lets the
        // Cleaner defer the free decision to the poll thread (serialized
        // with connection teardown) instead of calling SSL_free on the GC
        // thread, where it can race the teardown sequence and double-free
        // the stream.
        QuicOpenSSLEndpoint endpoint =
                (connection != null) ? connection.getEndpoint() : null;
        State state = new State(ssl, this.freed,
                (endpoint != null) ? endpoint.getCleanerStreamFrees() : null);
        cleaner.register(this, state);
    }


    /**
     * Returns the native SSL* pointer for this stream.
     *
     * @return The SSL* pointer
     */
    public MemorySegment getSsl() {
        return ssl;
    }


    /**
     * Returns the QUIC stream identifier.
     *
     * @return The stream ID
     */
    @Override
    public long getStreamId() {
        return streamId;
    }


    /**
     * Returns the stream type.
     *
     * @return The stream type constant
     */
    public int getStreamType() {
        return streamType;
    }


    /**
     * Returns the parent connection.
     *
     * @return The parent connection wrapper
     */
    @Override
    public QuicConnectionWrapper getConnection() {
        return connection;
    }


    /**
     * Returns the poll item for this stream.
     *
     * @return The poll item
     */
    public QuicPollItem getPollItem() {
        return pollItem;
    }


    /**
     * Sets the poll item for this stream.
     *
     * @param pollItem The poll item
     */
    public void setPollItem(QuicPollItem pollItem) {
        this.pollItem = pollItem;
    }


    /**
     * Returns the read buffer.
     *
     * @return The read ByteBuffer
     */
    public ByteBuffer getReadBuffer() {
        return readBuffer;
    }


    /**
     * Moves buffered bytes from a put-mode source buffer into a destination
     * buffer, restoring the source's put-mode protocol
     * ({@code [0, position)} occupied, limit == capacity) on the way out.
     * This is the single implementation of the pre-read hand-over; the body
     * used to exist in duplicate (the endpoint's prefetch and the wrapper's
     * pre-read branch) and the {@code drainStreamInto} javadoc identifies
     * that body as the historical divergence spot.
     * <p>
     * The copy is bound to the destination's remaining space; bytes that do
     * not fit stay buffered at the head of the source, ready for the next
     * hand-over.
     *
     * @param src The put-mode source buffer. On return it is in put mode
     *            again, holding any undelivered remainder at the head
     * @param dst The destination buffer, expected in write mode; delivered
     *            bytes are appended through its position/limit
     *
     * @return The number of bytes transferred
     */
    static int transferPutMode(ByteBuffer src, ByteBuffer dst) {
        int available = src.position();
        if (available == 0) {
            return 0;
        }
        int toCopy = Math.min(available, dst.remaining());
        if (toCopy == 0) {
            // Destination full: the old duplicated bodies ran the flip/put/
            // compact round-trip here, which is a state-preserving no-op.
            return 0;
        }
        src.flip();
        src.limit(toCopy);
        dst.put(src);
        src.limit(available);
        src.compact();
        return toCopy;
    }


    /**
     * Returns the current read state.
     *
     * @return The read state
     */
    @Override
    public ReadState getReadState() {
        return readState;
    }


    /**
     * Sets the current read state. Called by the endpoint with the state
     * mapped from the native stream state.
     *
     * @param state The read state
     */
    public void setReadState(ReadState state) {
        this.readState = state;
    }


    /**
     * Maps a native stream state (an {@code SSL_STREAM_STATE_*} value
     * reported by the OpenSSL QUIC API) to the transport-neutral
     * {@link QuicStream.ReadState}.
     *
     * @param state The native stream read state constant
     *
     * @return The mapped read state
     */
    static ReadState mapNativeState(int state) {
        return switch (state) {
            // WRONG_DIR means "not readable in this direction"; it cannot
            // be reported for a read-eligible stream (R events are only
            // delivered for read-capable streams), so it - like the
            // SSL_STREAM_STATE_NONE sentinel the default covers - is
            // harmless and maps to OK. Listing it explicitly documents the
            // invariant the default relied on.
            case QuicPoll.SSL_STREAM_STATE_OK, QuicPoll.SSL_STREAM_STATE_WRONG_DIR -> ReadState.OK;
            case QuicPoll.SSL_STREAM_STATE_FINISHED -> ReadState.FINISHED;
            case QuicPoll.SSL_STREAM_STATE_RESET_LOCAL -> ReadState.RESET_LOCAL;
            case QuicPoll.SSL_STREAM_STATE_RESET_REMOTE -> ReadState.RESET_REMOTE;
            case QuicPoll.SSL_STREAM_STATE_CONN_CLOSED -> ReadState.CONN_CLOSED;
            default -> ReadState.OK;
        };
    }


    /**
     * Checks if this stream has been concluded.
     *
     * @return {@code true} if FIN was sent
     */
    public boolean isConcluded() {
        return concluded;
    }


    /**
     * Marks this stream as concluded.
     */
    public void setConcluded() {
        this.concluded = true;
    }


    /**
     * Sets the write buffer for pending data.
     *
     * @param buffer The write buffer
     */
    public void setWriteBuffer(ByteBuffer buffer) {
        this.writeBuffer = buffer;
    }


    /**
     * Returns the current write buffer.
     *
     * @return The write buffer, or {@code null} if none
     */
    @Override
    public ByteBuffer getWriteBuffer() {
        return writeBuffer;
    }


    /**
     * Checks whether the stream type permits reading (a capability check based
     * on the stream direction, not current event readiness).
     *
     * @return {@code true} if the stream supports reading
     */
    public boolean isReadable() {
        return (streamType & QuicPoll.SSL_STREAM_TYPE_READ) != 0;
    }


    /**
     * Checks if the native SSL object has been freed. Native operations
     * against a freed SSL object are undefined; code paths that may race
     * with connection teardown must check this first and fail fast.
     *
     * @return true if the stream's native SSL object has been freed
     */
    @Override
    public boolean isFreed() {
        return freed.get();
    }

    /**
     * Marks this stream as deregistered from the endpoint.
     */
    public void setDeregistered() {
        this.deregistered = true;
    }

    /**
     * Checks if this stream has been deregistered from the endpoint.
     *
     * @return {@code true} if this stream has been deregistered
     */
    public boolean isDeregistered() {
        return deregistered;
    }

    /**
     * Frees the native stream SSL object exactly once, atomically. Both
     * explicit cleanup (closeStream/closeStreamByHandler) and the Cleaner call
     * the same check-and-free, so {@code SSL_free} runs at most once even if
     * they race. A stream SSL holds a reference on the owning connection, so
     * it must be freed before the connection SSL (per SSL_new_stream(3));
     * {@code SSL_free} on the connection does not free its streams.
     */
    public void freeSslOnce() {
        if (freed.getAndSet(true)) {
            return;
        }
        openssl_h.SSL_free(ssl);
    }

    /**
     * The single primitive for freeing a stream SSL from a teardown path. It
     * atomically claims the processing flag; if this call wins it frees the
     * native SSL (via {@link #freeSslOnce()}, the same once-guard shared with
     * the Cleaner) and releases the claim, otherwise it frees nothing. Every
     * connection/stream teardown sequence that frees a stream SSL "claim →
     * free → release" inline must go through here: the claim was historically
     * written as a plain {@code isProcessing()} read in one copy, which raced a
     * worker's {@code compareAndSetProcessing} claim and freed the SSL under a
     * running handler (a fixed use-after-free). Keeping the claim atomic in one
     * place stops that divergence from recurring.
     * <p>
     * A throw from the free propagates to the caller after the claim is
     * released, so a teardown loop may choose to skip freeing the owning
     * connection (per {@code SSL_new_stream(3)} the connection must not be
     * freed while a stream SSL may still be alive).
     *
     * @return {@code true} if this call claimed the flag and freed the stream
     *         SSL; {@code false} if an executor worker still owns the stream,
     *         in which case the caller must defer the free to that worker
     */
    public boolean freeSslIfIdle() {
        if (!compareAndSetProcessing(false, true)) {
            return false;
        }
        try {
            freeSslOnce();
        } finally {
            clearProcessing();
        }
        return true;
    }

    /**
     * Sets whether this is the primary server-initiated unidirectional
     * stream (protocol index 0, e.g. the HTTP/3 control stream).
     *
     * @param primaryUniStream {@code true} if this is the primary server
     *            unidirectional stream
     */
    public void setPrimaryUniStream(boolean primaryUniStream) {
        this.primaryUniStream = primaryUniStream;
    }

    /**
     * Checks if this is the primary server-initiated unidirectional stream
     * (protocol index 0, e.g. the HTTP/3 control stream).
     *
     * @return {@code true} if this is the primary server unidirectional
     *         stream
     */
    public boolean isPrimaryUniStream() {
        return primaryUniStream;
    }


    /**
     * Returns the SSL pointer address for use as a map key.
     *
     * @return The SSL pointer address
     */
    public long getSslAddress() {
        return ssl.address();
    }


    @Override
    public String toString() {
        return "QuicStream[id=" + streamId + ",type=" + streamType +
                ",readState=" + readState + "]";
    }


    /**
     * A deferred native free request for a stream whose wrapper became
     * phantom-reachable before any close path freed it. The free decision is
     * made on the endpoint's poll thread (where the stream teardown sequence
     * {@code setClosed()} → {@code closeAllStreams()} → {@code SSL_free(conn)}
     * also runs), so it can no longer interleave with connection teardown and
     * double-free the stream. Reaching the request means the wrapper was
     * phantom-reachable: no worker task can be using the stream, so no
     * processing claim is needed for the free to be safe. Carries only the
     * shared flags (never the wrapper or connection) so nothing keeps the
     * wrapper reachable.
     */
    static final class DeferredStreamFree {

        private final MemorySegment ssl;
        private final AtomicBoolean freed;

        DeferredStreamFree(MemorySegment ssl, AtomicBoolean freed) {
            this.ssl = ssl;
            this.freed = freed;
        }

        void run() {
            // CAS with every other free path (closeStream, closeAllStreams,
            // finishStreamDispatch, stopInternal), and the free must NOT be
            // skipped when the owning connection is closing: per
            // SSL_new_stream(3) every stream SSL (which holds a reference on
            // the connection) must be freed before the connection SSL, and
            // closeAllStreams() deliberately skips streams whose handler is
            // still running - so a closing connection can still be waiting on
            // this free.
            if (!freed.getAndSet(true)) {
                openssl_h.SSL_free(ssl);
            }
        }
    }


    /**
     * State object for Cleaner-based native resource cleanup.
     */
    private static class State implements Runnable {
        private final MemorySegment ssl;
        // Shared freed flag (NOT the wrapper) so this State does not keep the
        // QuicStreamWrapper strongly reachable from the static Cleaner.
        private final AtomicBoolean freed;
        // The endpoint's poll-thread queue for deferred stream frees (NOT the
        // endpoint) so the free decision is serialized with connection
        // teardown. May be null if no endpoint was available.
        private final ConcurrentLinkedQueue<DeferredStreamFree> cleanerStreamFrees;

        State(MemorySegment ssl, AtomicBoolean freed,
                ConcurrentLinkedQueue<DeferredStreamFree> cleanerStreamFrees) {
            this.ssl = ssl;
            this.freed = freed;
            this.cleanerStreamFrees = cleanerStreamFrees;
        }

        @Override
        public void run() {
            // Never call SSL_free on the GC thread: hand the request to the
            // poll thread, where it is serialized with the connection
            // teardown sequence. The queue is only null for a wrapper
            // constructed without a connection/endpoint - such a wrapper has
            // no poll thread and no teardown sequence to race, so freeing
            // directly (still guarded by the shared freed CAS) is the only
            // alternative to leaking the stream SSL. The endpoint never
            // constructs a wrapper without wiring the connection first, so
            // the fallback is defensive, not a live path.
            //
            // No wake-descriptor kick here on purpose: a kick would need the
            // State to hold the endpoint (or its wakeup), defeating the
            // minimal-reachability design of this class. The queued free is
            // drained by the next poll-loop iteration; enqueued during an
            // in-progress wait, it waits out at most that wait - bounded by
            // the loop's idle-rate timeout, or pollTimeoutMs while the
            // endpoint is busy (see QuicNativeMailbox.hasDeferredStreamFrees).
            if (cleanerStreamFrees != null) {
                cleanerStreamFrees.add(new DeferredStreamFree(ssl, freed));
            } else {
                new DeferredStreamFree(ssl, freed).run();
            }
        }
    }
}

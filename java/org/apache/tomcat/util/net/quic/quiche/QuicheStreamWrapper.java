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
package org.apache.tomcat.util.net.quic.quiche;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.tomcat.util.net.quic.QuicStream;

/**
 * Wraps a QUIC stream on a quiche connection and implements the transport
 * view {@link QuicStream} the application protocol layer operates on.
 * <p>
 * Unlike the OpenSSL transport, quiche streams have no native handle: a
 * stream is identified by its QUIC stream ID and its native state lives
 * inside the parent {@code quiche_conn}. There is therefore no per-stream
 * native lifetime, no stream Cleaner, and no stream-free ordering
 * constraint - "freeing" a stream here is pure bookkeeping (clearing the
 * wrapper's state and removing it from the connection maps), which is what
 * {@link #setFreed()} does despite the name. The parent connection does
 * have a native handle and a Cleaner (see
 * {@code QuicheConnectionWrapper.State}); that lifetime is owned by the
 * connection, not by any stream wrapper.
 * <p>
 * The read buffer follows the put-mode protocol shared with the OpenSSL
 * transport: buffered bytes occupy {@code [0..position)} with
 * {@code limit == capacity}.
 */
public class QuicheStreamWrapper implements QuicStream {

    /** Stream direction flags (parity with the OpenSSL transport's types). */
    public static final int TYPE_READ = 1;
    public static final int TYPE_WRITE = 2;
    public static final int TYPE_BIDI = TYPE_READ | TYPE_WRITE;

    /**
     * The QUIC stream identifier.
     */
    private final long streamId;

    /**
     * Stream direction, derived from the QUIC stream ID bits (RFC 9000
     * Section 2.1): bit 0 is the initiator, bit 1 the direction.
     */
    private final int streamType;

    /**
     * The parent connection.
     */
    private final QuicheConnectionWrapper connection;

    /**
     * The socket wrapper the endpoint publishes for this stream, kept as a
     * back-pointer so the re-arm sweeps (which already hold the stream) reach
     * it directly instead of paying the endpoint's two-level
     * connection-address / stream-ID map lookup. Written once when the
     * wrapper is created, cleared when the stream deregisters; every reader
     * gates on the deregistered/freed flags first, so a window left open by a
     * concurrent clear can only ever cost a redundant no-op signal.
     */
    private volatile QuicheSocketWrapper socketWrapper;

    /**
     * Read buffer for data received from the stream (put-mode protocol).
     */
    private final ByteBuffer readBuffer;

    /**
     * Write buffer for pending data to send on the stream.
     */
    private volatile ByteBuffer writeBuffer;

    /**
     * Claim-retry tasks waiting for the processing flag to free. Registered
     * by {@link QuicheEndpoint}'s scheduleStreamDispatch when a dispatch
     * claim fails; drained and submitted by the dispatch that releases the
     * claim (and by teardown), so a blocked event is re-run on release
     * instead of resubmitting itself at mailbox-drain rate (which never
     * terminates the drain and starves the poll loop). Registration and the
     * claim attempt, and the flag clear and the drain, are each ordered
     * before/after their respective volatile touches, so a release either
     * lands on a free claim (the retry wins it) or observes the parked
     * waiter and re-runs it.
     */
    private final java.util.concurrent.ConcurrentLinkedQueue<Runnable> claimWaiters =
            new java.util.concurrent.ConcurrentLinkedQueue<>();

    /**
     * Current read state of the stream.
     */
    private volatile ReadState readState;

    /**
     * Whether the peer's FIN has been observed (every data read with the
     * fin flag, and the terminal state for reads that follow).
     */
    private volatile boolean finReceived;

    /**
     * Whether this stream is currently being processed by an executor
     * thread. Used to prevent concurrent R/W dispatches in the same poll
     * iteration and to claim the stream for teardown.
     */
    private final AtomicBoolean processing = new AtomicBoolean(false);

    /**
     * Whether this stream has been concluded (FIN sent).
     */
    private volatile boolean concluded;

    /**
     * Whether the endpoint has removed this stream from its bookkeeping.
     * Set on the poll thread by the endpoint's stream close paths.
     */
    private volatile boolean deregistered;

    /**
     * Whether the stream's transport state is gone (connection torn down or
     * stream explicitly closed). Operations against a freed stream are
     * undefined; racing paths check this first and fail fast.
     */
    private volatile boolean freed;

    /**
     * Write interest flag, latched by {@link #setWriteInterestIfAbsent()}
     * and consulted by the writable sweep to decide which buffered writes to
     * retry. CAS-based so the false→true / true→false transitions can be
     * counted exactly against the connection's write re-arm index (a stream is
     * keyed in that index while the latch - or a parked blocking writer -
     * holds interest).
     */
    private final AtomicBoolean writeInterest = new AtomicBoolean(false);

    /**
     * Creates a new stream wrapper.
     *
     * @param streamId   The QUIC stream ID
     * @param connection The parent connection
     * @param buffer     The read buffer
     */
    public QuicheStreamWrapper(long streamId, QuicheConnectionWrapper connection,
            ByteBuffer buffer) {
        this.streamId = streamId;
        this.connection = connection;
        this.streamType = deriveType(streamId);
        this.readBuffer = buffer;
        this.writeBuffer = null;
        this.readState = ReadState.OK;
    }


    /*
     * RFC 9000 Section 2.1 stream ID bits as seen by a server: bit 0 is the
     * initiator (0: client-initiated, 1: server-initiated), bit 1 is the
     * direction (0: bidirectional, 1: unidirectional).
     */
    private static int deriveType(long id) {
        boolean clientInitiated = (id & 0x01) == 0;
        boolean unidirectional = (id & 0x02) != 0;
        if (unidirectional) {
            // Client-initiated uni: readable. Server-initiated uni: writable.
            return clientInitiated ? TYPE_READ : TYPE_WRITE;
        }
        return TYPE_BIDI;
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
     * Returns the stream direction flags.
     *
     * @return One of {@link #TYPE_READ}, {@link #TYPE_WRITE},
     *         {@link #TYPE_BIDI}
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
    public QuicheConnectionWrapper getConnection() {
        return connection;
    }


    /**
     * Returns the socket wrapper the endpoint publishes for this stream.
     *
     * @return the socket wrapper, or {@code null} if none was ever created
     *         (the stream was rejected before it got a wrapper) or the stream
     *         has deregistered
     */
    public QuicheSocketWrapper getSocketWrapper() {
        return socketWrapper;
    }


    /**
     * Sets the socket wrapper back-pointer. Called once by the endpoint when
     * it creates the wrapper for this stream.
     *
     * @param wrapper The socket wrapper created for this stream
     */
    void setSocketWrapper(QuicheSocketWrapper wrapper) {
        this.socketWrapper = wrapper;
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
     * Returns the current read state.
     *
     * @return The read state
     */
    @Override
    public ReadState getReadState() {
        return readState;
    }


    /**
     * Sets the current read state.
     *
     * @param state The read state
     */
    public void setReadState(ReadState state) {
        this.readState = state;
    }


    /**
     * Whether the peer's FIN has been observed on this stream.
     *
     * @return {@code true} if the FIN was seen
     */
    public boolean isFinReceived() {
        return finReceived;
    }


    /**
     * Records that the peer's FIN was observed, transitioning the read state.
     * A terminal reset state is never downgraded to FINISHED: quiche reports
     * a reset stream as finished once the one-shot reset error has been
     * consumed, and losing the reset would turn an aborted body into a clean
     * end of stream.
     */
    public void setFinReceived() {
        this.finReceived = true;
        ReadState state = this.readState;
        if (state == ReadState.RESET_REMOTE ||
                state == ReadState.RESET_LOCAL ||
                state == ReadState.CONN_CLOSED) {
            return;
        }
        this.readState = ReadState.FINISHED;
    }


    /**
     * Atomically sets the processing flag if currently not processing.
     *
     * @param expect The value expected for the flag
     * @param update The new value for the flag
     *
     * @return {@code true} if successfully set
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
     * Registers a claim-retry task to be re-run when the processing claim
     * is released. Callers add the waiter before attempting the claim, so
     * a release that races the attempt cannot miss it.
     *
     * @param waiter The retry task (endpoint-side scheduleStreamDispatch)
     */
    public void addClaimWaiter(Runnable waiter) {
        claimWaiters.add(waiter);
    }


    /**
     * Removes a claim-retry task that no longer needs a wake (the claim was
     * won, the stream went away, or the task handed the event over).
     *
     * @param waiter The task to remove
     */
    public void removeClaimWaiter(Runnable waiter) {
        claimWaiters.remove(waiter);
    }


    /**
     * Takes one pending claim-retry task, or {@code null} when none is
     * waiting. The releaser (or teardown) polls until empty and re-submits
     * each waiter to the poll thread.
     *
     * @return The next waiter, or {@code null}
     */
    public Runnable pollClaimWaiter() {
        return claimWaiters.poll();
    }


    /**
     * Checks whether this stream is currently being processed by an executor
     * thread.
     *
     * @return {@code true} if a worker is running the handler for this stream
     */
    public boolean isProcessing() {
        return processing.get();
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
     * Marks the stream as freed (transport state gone). Idempotent.
     */
    public void setFreed() {
        this.freed = true;
    }


    /**
     * Checks if the stream has been freed.
     *
     * @return {@code true} if the stream's transport state is gone
     */
    @Override
    public boolean isFreed() {
        return freed;
    }


    /**
     * Marks this stream as deregistered from the endpoint.
     */
    public void setDeregistered() {
        this.deregistered = true;
        // Drop the socket wrapper back-pointer alongside the endpoint
        // bookkeeping that owns it: the wrapper is off the endpoint's maps by
        // the time a stream reaches this state, and leaving the link would
        // keep the pair alive past its usefulness.
        this.socketWrapper = null;
        // Release a write-interest latch abandoned by the close so the
        // connection's write re-arm index (re-arm sweep work set) stays
        // balanced; the CAS makes this race-free against the notify path
        // that normally clears the latch (exactly one of them sees the
        // true→false transition and releases the re-arm registration).
        if (clearWriteInterest()) {
            connection.releaseWriteRearm(this);
        }
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
     * Sets the write interest flag if it was not set.
     *
     * @return {@code true} if this call made the false→true transition
     *         (the caller then owns the matching write re-arm registration on
     *         the parent connection)
     */
    public boolean setWriteInterestIfAbsent() {
        return writeInterest.compareAndSet(false, true);
    }


    /**
     * Clears the write interest flag.
     *
     * @return {@code true} if this call made the true→false transition
     *         (the caller then owns the matching write re-arm release on the
     *         parent connection)
     */
    public boolean clearWriteInterest() {
        return writeInterest.compareAndSet(true, false);
    }


    /**
     * Returns the write interest flag.
     *
     * @return {@code true} if a consumer registered write interest
     */
    public boolean hasWriteInterest() {
        return writeInterest.get();
    }


    @Override
    public String toString() {
        return "QuicStream[id=" + streamId + ",type=" + streamType +
                ",readState=" + readState + "]";
    }
}

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

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.concurrent.Callable;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.net.ApplicationBufferHandler;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SendfileDataBase;
import org.apache.tomcat.util.net.SendfileState;
import org.apache.tomcat.util.net.SocketBufferHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.net.WriteBuffer;
import org.apache.tomcat.util.net.quic.QuicSocketWrapper;
import org.apache.tomcat.util.net.quic.QuicStream;
import org.apache.tomcat.util.res.StringManager;

/**
 * Socket wrapper for a QUIC stream on the quiche transport. Wraps a
 * {@link QuicheStreamWrapper} to provide the {@link SocketWrapperBase}
 * behaviour expected by {@code AbstractProtocol} and the generic QUIC view
 * declared by {@link QuicSocketWrapper}, which this class extends.
 * <p>
 * This is the quiche port of
 * {@code org.apache.tomcat.util.net.quic.openssl.QuicOpenSSLSocketWrapper}:
 * the same read/write buffering, wake-up and interest semantics, with the
 * native calls expressed through the quiche stream API on the parent
 * connection ({@code quiche_conn_stream_recv/send/shutdown}) instead of the
 * OpenSSL per-stream {@code SSL} objects.
 */
public class QuicheSocketWrapper extends QuicSocketWrapper
        implements WriteBuffer.Sink {

    private static final Log log = LogFactory.getLog(QuicheSocketWrapper.class);
    private static final StringManager sm = StringManager.getManager(QuicheSocketWrapper.class);

    /**
     * writeChunk() result: the stream is in a terminal state (reset,
     * finished or connection closed).
     */
    private static final int WRITE_TERMINAL = -2;

    /**
     * The endpoint that owns this wrapper.
     */
    private final QuicheEndpoint endpoint;

    /**
     * SSL session support for this stream.
     */
    private QuicheSSLSupport sslSupport;

    /**
     * Serializes every operation that touches the shared write staging
     * buffer ({@code socketBufferHandler} and
     * {@code nonBlockingWriteBuffer}). This is the QUIC equivalent of the
     * write lock in HTTP/2's {@code Stream.StreamOutputBuffer}.
     */
    private final ReentrantLock writeLock = new ReentrantLock();

    /**
     * Number of trailing bytes of stream output held back so the stream FIN
     * can ride on a data-bearing frame instead of a zero-length one.
     * quiche considers a stream's send side complete (and collects the
     * stream, discarding any un-acknowledged FIN frame with it) as soon as
     * the last data byte is acknowledged, but a zero-length FIN frame is not
     * covered by the acked data range. Attaching the FIN flag to the final
     * bytes means the FIN can only be acknowledged once real data delivery
     * is acknowledged, and a lost final packet carries data, so loss
     * recovery retransmits it.
     */
    private static final int FIN_TAIL_SIZE = 128;

    /**
     * The held-back trailing bytes ({@code null} when nothing is held), and
     * how much of them has already been forwarded to quiche. Guarded by
     * {@code writeLock}: every mutation sits inside a write-path wrapper
     * method or inside the reset path that takes the same lock.
     */
    private byte[] finTail;
    private int finTailPos;


    /**
     * Creates a new socket wrapper for a QUIC stream.
     *
     * @param stream   The underlying QUIC stream
     * @param endpoint The owning QUIC endpoint
     */
    public QuicheSocketWrapper(QuicheStreamWrapper stream, QuicheEndpoint endpoint) {
        super(stream, endpoint);
        this.endpoint = endpoint;
        // The write staging buffer is sized well above the 8 KiB
        // application output buffer chunks: the real send buffer is the
        // quiche transmit queue, so a larger staging buffer lets many
        // framed chunks accumulate before one poll-thread hop is needed.
        this.socketBufferHandler = new SocketBufferHandler(
                endpoint.getSocketProperties().getAppReadBufSize(),
                Math.max(65536, endpoint.getSocketProperties().getAppWriteBufSize()),
                false);
        QuicheConnectionWrapper conn = stream.getConnection();
        if (conn != null) {
            // Display-side copies: IPv4 peers on a dual-stack wildcard bind
            // arrive with v4-mapped IPv6 addresses; present the dotted IPv4
            // form the java.net transports present (the connection keeps the
            // mapped form for the native sockaddr paths).
            this.remoteAddress = QuicheBindings.unmapIpv4Mapped(conn.getRemoteAddress());
            this.localAddress = QuicheBindings.unmapIpv4Mapped(conn.getLocalAddress());
            // Deliberately do not copy the connection's negotiated protocol
            // to the stream wrapper (see the OpenSSL endpoint's note):
            // AbstractProtocol would try to resolve it as an upgrade.
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public QuicheStreamWrapper getQuicStream() {
        return getSocket();
    }


    /**
     * {@inheritDoc}
     * <p>
     * Narrows the socket to the concrete stream wrapper type used by this
     * endpoint.
     */
    @Override
    public QuicheStreamWrapper getSocket() {
        return (QuicheStreamWrapper) super.getSocket();
    }


    /**
     * Returns the stream backing this wrapper iff its transport state is
     * safe to touch: the stream is present, not freed, and the parent
     * connection is neither closed nor freed. Callers translate a
     * {@code null} result into their own contract: read paths throw
     * {@code EOFException}, write paths throw {@code IOException}, and
     * best-effort paths ({@code concludeStream}, {@code resetStream},
     * {@code processSendfile}) return silently.
     *
     * @return the live stream, or {@code null} if it must not be touched
     */
    private QuicheStreamWrapper liveStream() {
        QuicheStreamWrapper stream = getSocket();
        if (stream == null || stream.isFreed()) {
            return null;
        }
        QuicheConnectionWrapper conn = stream.getConnection();
        if (conn == null || conn.isClosed() || conn.isFreed()) {
            return null;
        }
        return stream;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public QuicheConnectionWrapper getConnection() {
        QuicheStreamWrapper stream = getSocket();
        return (stream != null) ? stream.getConnection() : null;
    }


    /**
     * Runs a native QUIC operation on the QUIC poll thread. quiche
     * connections are not thread-safe for concurrent access, so every
     * native call of this wrapper executes on the poll thread: when the
     * caller already is the poll thread the task runs directly, otherwise it
     * is queued and the caller blocks until the poll loop has executed it.
     *
     * <p>The task must be a single fast operation (one native call) and
     * must never block: the poll thread is the only thread that drains the
     * queue, so a blocking task would deadlock.</p>
     *
     * @param task The native operation to run on the poll thread
     * @return The task's result
     * @throws IOException If the task fails or the poll thread does not
     *                     complete it in time
     */
    private <T> T onPollThread(Callable<T> task) throws IOException {
        // The hop itself and the exception translation live in the endpoint
        // so every caller shares one error contract (endpoint-side callers
        // that prefer the raw Exception surface use callOnPollThread). The
        // connection is named so the woken loop sweeps this connection only
        // rather than the whole fleet.
        return endpoint.callOnPollThreadChecked(getConnection(), task);
    }


    /**
     * Runs a void native QUIC operation on the poll thread, see
     * {@link #onPollThread(Callable)}.
     */
    private void onPollThreadVoid(Runnable task) throws IOException {
        onPollThread(() -> {
            task.run();
            return null;
        });
    }


    /**
     * Drives the QUIC state machine for the parent connection. quiche owns
     * packet I/O in the endpoint's poll loop, so "pumping" is reduced to
     * waking the loop: it performs the socket read, the per-connection
     * recv/timer/send sweep and the stream readiness sweeps that signal
     * parked waiters.
     */
    @Override
    public void pumpConnectionEvents() {
        QuicheConnectionWrapper conn = getConnection();
        if (conn == null) {
            return;
        }
        endpoint.kickPollLoop(conn);
    }


    // ------------------------------------- Blocking I/O wake-up

    /**
     * Whether this wrapper still has outbound data waiting for stream write
     * capacity (the wrapper staging buffer or the non-blocking write buffer).
     *
     * @return {@code true} if a flush would have something to send
     */
    boolean hasBufferedWrites() {
        return !socketBufferHandler.isWriteBufferEmpty() || !nonBlockingWriteBuffer.isEmpty();
    }


    /**
     * One wait cycle of a stalled blocking read: wake the poll loop (it
     * performs the socket read, the recv pass and the readable sweep that
     * will signal this waiter), arm read interest, then park until the poll
     * thread signals readiness / a terminal state or the deadline passes.
     *
     * @param deadlineNanos Absolute deadline from {@link System#nanoTime()}
     *
     * @return {@code true} to retry the read, {@code false} to give up
     *         (interest is armed either way, so the poll loop delivers a
     *         regular read event when data does arrive)
     */
    @Override
    public boolean awaitReadableData(long deadlineNanos) {
        long seq = readWakeups().get();
        Thread self = Thread.currentThread();
        QuicheStreamWrapper stream = rearmStream();
        QuicheConnectionWrapper conn = stream == null ? null : stream.getConnection();
        if (conn != null) {
            conn.addReadRearm(stream);
        }
        readWaiter().set(self);
        try {
            pumpConnectionEvents();
            if (System.nanoTime() >= deadlineNanos) {
                return false;
            }
            if (endpoint.isPollThread()) {
                // The poll loop cannot deliver a signal while it is blocked
                // here (inline processing during shutdown): pause briefly so
                // the just-pumped datagrams can be consumed on the retry.
                return pauseBriefly(deadlineNanos);
            }
            return awaitWakeRemaining(readWaiter(), readWakeups(), seq, deadlineNanos);
        } finally {
            readWaiter().compareAndSet(self, null);
            if (conn != null) {
                conn.removeReadRearm(stream);
            }
        }
    }


    /**
     * One wait cycle of a stalled blocking write: see
     * {@link #awaitReadableData(long)} for the pattern, with write interest
     * and write events (flow-control updates) instead of read ones.
     *
     * @param deadlineNanos Absolute deadline from {@link System#nanoTime()}
     *
     * @return {@code true} to retry the write, {@code false} to give up
     */
    private boolean awaitWritable(long deadlineNanos) {
        long seq = writeWakeups().get();
        Thread self = Thread.currentThread();
        QuicheStreamWrapper stream = rearmStream();
        QuicheConnectionWrapper conn = stream == null ? null : stream.getConnection();
        if (conn != null) {
            conn.addWriteRearm(stream);
        }
        writeWaiter().set(self);
        try {
            pumpConnectionEvents();
            registerWriteInterest();
            if (System.nanoTime() >= deadlineNanos) {
                return false;
            }
            if (endpoint.isPollThread()) {
                return pauseBriefly(deadlineNanos);
            }
            return awaitWakeRemaining(writeWaiter(), writeWakeups(), seq, deadlineNanos);
        } finally {
            writeWaiter().compareAndSet(self, null);
            if (conn != null) {
                conn.releaseWriteRearm(stream);
            }
        }
    }


    /*
     * The stream for the park-time re-arm index registration (the re-arm
     * sweep work set). Null when the stream is already detached, in which
     * case there is no sweep that could serve this wait anyway.
     */
    private QuicheStreamWrapper rearmStream() {
        return getSocket();
    }


    // ------------------------------------- Read

    @Override
    public boolean isReadyForRead() throws IOException {
        checkNotClosed();
        socketBufferHandler.configureReadBufferForRead();
        if (socketBufferHandler.getReadBuffer().remaining() > 0) {
            return true;
        }
        return fillReadBuffer() > 0;
    }


    @Override
    public int read(boolean block, byte[] b, int off, int len) throws IOException {
        // SocketWrapperBase contract: a blocking read waits for data. On a
        // would-block, wake the poll loop and retry, bounded. Each native
        // step runs on the poll thread (see onPollThread); the wait below
        // parks on the calling (worker) thread and is released by a
        // poll-thread signal.
        checkNotClosed();
        long deadline = block
                ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(blockingReadTimeoutMs())
                : 0L;
        while (true) {
            int nRead = populateReadBuffer(b, off, len);
            if (nRead > 0) {
                return nRead;
            }
            nRead = fillReadBuffer();
            if (nRead != 0) {
                // Data (>0) or EOF (-1); either way this is the result.
                if (nRead > 0) {
                    socketBufferHandler.configureReadBufferForRead();
                    nRead = Math.min(nRead, len);
                    socketBufferHandler.getReadBuffer().get(b, off, nRead);
                }
                return nRead;
            }
            if (!block) {
                return 0;
            }
            if (!awaitReadableData(deadline)) {
                // Socket transport contract: a blocking read that runs out
                // of time reports the timeout rather than the would-block
                // marker 0, which callers cannot distinguish from a real
                // no-data result.
                throw new SocketTimeoutException(
                        sm.getString("socketWrapper.quicReadTimeout"));
            }
        }
    }


    @Override
    public int read(boolean block, ByteBuffer to) throws IOException {
        if (!to.hasRemaining()) {
            return 0;
        }
        checkNotClosed();
        long deadline = block
                ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(blockingReadTimeoutMs())
                : 0L;
        while (true) {
            int nRead = populateReadBuffer(to);
            if (nRead > 0) {
                return nRead;
            }
            int limit = socketBufferHandler.getReadBuffer().capacity();
            if (to.remaining() >= limit) {
                // Direct path: read straight from the QUIC stream into the
                // caller's buffer, up to its full remaining space.
                nRead = fillReadBufferDirect(to);
                if (nRead != 0) {
                    return nRead;
                }
            } else {
                nRead = fillReadBuffer();
                if (nRead != 0) {
                    if (nRead > 0) {
                        nRead = populateReadBuffer(to);
                    }
                    return nRead;
                }
            }
            if (!block) {
                return 0;
            }
            if (!awaitReadableData(deadline)) {
                // Socket transport contract: see the byte[] read above.
                throw new SocketTimeoutException(
                        sm.getString("socketWrapper.quicReadTimeout"));
            }
        }
    }


    /**
     * Reads data from the QUIC stream into the socket read buffer.
     *
     * @return The number of bytes read, or -1 for EOF
     * @throws IOException If an I/O error occurs
     */
    private int fillReadBuffer() throws IOException {
        socketBufferHandler.configureReadBufferForWrite();
        return fillReadBufferDirect(socketBufferHandler.getReadBuffer());
    }


    private int fillReadBufferDirect(ByteBuffer buffer) throws IOException {
        return onPollThread(() -> fillReadBufferDirect0(buffer));
    }


    private int fillReadBufferDirect0(ByteBuffer buffer) throws IOException {
        QuicheStreamWrapper stream = liveStream();
        if (stream == null) {
            throw new EOFException(sm.getString("socketWrapper.quicStreamClosed"));
        }

        QuicheConnectionWrapper conn = stream.getConnection();

        // Serve pre-read data from the stream's buffer first. The endpoint
        // may have pre-read stream data immediately after discovering the
        // stream to prevent later state changes from hiding the FIN.
        // Read buffer protocol (put mode): buffered bytes occupy
        // [0..position), limit == capacity.
        ByteBuffer preReadBuf = stream.getReadBuffer();
        if (preReadBuf != null) {
            int available = preReadBuf.position();
            if (available > 0) {
                preReadBuf.flip();
                int toCopy = Math.min(available, buffer.remaining());
                // Transfer only what the destination can hold; the limit is
                // restored before compact() so the bytes that did not fit
                // stay buffered for the next read.
                preReadBuf.limit(toCopy);
                buffer.put(preReadBuf);
                preReadBuf.limit(available);
                preReadBuf.compact();
                return toCopy;
            }
        }

        // Stable per-call terminal-state mapping (same discipline as the
        // OpenSSL wrapper, which re-checks the stream state on every call):
        // once FIN was consumed, quiche removes the completed stream from
        // the connection, so a second native read would no longer report EOF
        // but fail with INVALID_STREAM_STATE. Report the cached state
        // instead, so reads after EOF always return -1 (or the recorded
        // reset/close as EOFException) rather than a spurious IOException.
        if (stream.isFinReceived()) {
            return -1;
        }
        QuicStream.ReadState readState = stream.getReadState();
        if (readState == QuicStream.ReadState.RESET_LOCAL ||
                readState == QuicStream.ReadState.RESET_REMOTE ||
                readState == QuicStream.ReadState.CONN_CLOSED) {
            throw new EOFException(sm.getString("socketWrapper.quicStreamClosed"));
        }

        int remaining = buffer.remaining();
        if (remaining == 0) {
            return 0;
        }

        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment nativeBuf = localArena.allocate(remaining);
            MemorySegment finPtr = localArena.allocate(ValueLayout.JAVA_BOOLEAN);
            finPtr.set(ValueLayout.JAVA_BOOLEAN, 0, false);
            MemorySegment errPtr = localArena.allocate(ValueLayout.JAVA_LONG);
            errPtr.set(ValueLayout.JAVA_LONG, 0, 0L);

            long rc = QuicheBindings.quiche_conn_stream_recv(conn.getConn(),
                    stream.getStreamId(), nativeBuf, remaining, finPtr, errPtr);

            if (rc >= 0) {
                int actualLen = (int) Math.min(rc, remaining);
                boolean fin = finPtr.get(ValueLayout.JAVA_BOOLEAN, 0);
                if (fin) {
                    stream.setFinReceived();
                }
                if (actualLen == 0) {
                    // FIN with no payload: terminal for reads.
                    return fin ? -1 : 0;
                }
                // Single native -> heap copy.
                buffer.put(nativeBuf.asSlice(0, actualLen).asByteBuffer());
                return actualLen;
            }
            if (rc == QuicheBindings.QUICHE_ERR_DONE) {
                // No buffered data. If the FIN was already observed (or the
                // stream is finished in quiche), this is EOF.
                if (stream.isFinReceived() ||
                        QuicheBindings.quiche_conn_stream_finished(conn.getConn(),
                                stream.getStreamId())) {
                    stream.setFinReceived();
                    return -1;
                }
                return 0;
            }
            if (rc == QuicheBindings.QUICHE_ERR_STREAM_RESET) {
                stream.setReadState(QuicStream.ReadState.RESET_REMOTE);
                throw new EOFException(sm.getString("socketWrapper.quicStreamClosed"));
            }
            // No QUICHE_ERR_STREAM_STOPPED branch: quiche's read path
            // (do_stream_recv / recv_buf.emit_or_discard) can only surface
            // Done, data, or StreamReset - StreamStopped belongs to the send
            // direction (stream_send/capacity/shutdown), and a locally-sent
            // STOP_SENDING does not reset our read side anyway.
            if (rc == QuicheBindings.QUICHE_ERR_INVALID_STREAM_STATE) {
                // The stream is gone from the connection's map: normally a
                // completed stream collected after its FIN byte was
                // consumed. Report the stable EOF (or a benign no-data if no
                // terminal state can be confirmed) rather than a hard read
                // failure.
                if (stream.isConcluded() ||
                        QuicheBindings.quiche_conn_stream_finished(conn.getConn(),
                                stream.getStreamId())) {
                    stream.setFinReceived();
                    return -1;
                }
                return 0;
            }
            if (QuicheBindings.quiche_conn_is_closed(conn.getConn()) ||
                    conn.isClosed() || conn.isFreed()) {
                stream.setReadState(QuicStream.ReadState.CONN_CLOSED);
                throw new EOFException(sm.getString("socketWrapper.quicStreamClosed"));
            }
            throw new IOException(sm.getString("socketWrapper.quicReadFailed"));
        }
    }


    @Override
    public void setAppReadBufHandler(ApplicationBufferHandler handler) {
        // No-op: QUIC stream I/O is managed by quiche_conn_stream_recv/send
    }


    // ------------------------------------- Write

    /**
     * Concludes this QUIC stream by sending a FIN (stream-level close) as an
     * empty write with the fin flag set.
     */
    @Override
    public void concludeStream() throws IOException {
        QuicheStreamWrapper stream = liveStream();
        if (stream == null) {
            return;
        }
        // The tail is written under the write lock, so take it here too: the
        // tail mutations in concludeStream(stream) must not race a concurrent
        // write (same discipline as resetStream). A conclusion triggered from
        // within a write path just re-enters the lock.
        writeLock.lock();
        try {
            concludeStream(stream);
            stream.setConcluded();
        } finally {
            writeLock.unlock();
        }
    }


    /**
     * Checks if this stream has been concluded.
     *
     * @return {@code true} if this stream has been concluded
     */
    @Override
    public boolean isStreamConcluded() {
        QuicheStreamWrapper stream = getSocket();
        return (stream != null) && stream.isConcluded();
    }


    /**
     * Resets this QUIC stream with the given error code. Per RFC 9000
     * Section 2.4, the transport sends a {@code RESET_STREAM} frame via
     * {@code quiche_conn_stream_shutdown(WRITE, code)}. The native work runs
     * on the poll thread via
     * {@link QuicheEndpoint#resetStream(QuicheStreamWrapper, long)}.
     *
     * @param errorCode The error code (HTTP/3 stream error or connection
     *                  error)
     * @return {@code true} if the reset took effect
     * @throws IOException If an I/O error occurs
     */
    @Override
    public boolean resetStream(long errorCode) throws IOException {
        QuicheStreamWrapper stream = liveStream();
        if (stream == null) {
            return false;
        }
        // The tail is written under the write lock, so take it here too:
        // the mutation must not race a concurrent write, and a reset
        // triggered from within a write (concludeStream's give-up) just
        // re-enters the lock.
        writeLock.lock();
        try {
            // The stream is going away: the held-back tail goes with it.
            finTail = null;
            finTailPos = 0;
            Boolean done = onPollThread(() -> endpoint.resetStream(stream, errorCode));
            return done != null && done;
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    protected void writeBlocking(byte[] buf, int off, int len) throws IOException {
        checkNotClosed();
        writeLock.lock();
        try {
            super.writeBlocking(buf, off, len);
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    protected void writeBlocking(ByteBuffer from) throws IOException {
        checkNotClosed();
        writeLock.lock();
        try {
            super.writeBlocking(from);
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    protected void writeNonBlocking(byte[] buf, int off, int len) throws IOException {
        checkNotClosed();
        writeLock.lock();
        try {
            super.writeNonBlocking(buf, off, len);
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    protected void writeNonBlocking(ByteBuffer from) throws IOException {
        checkNotClosed();
        writeLock.lock();
        try {
            super.writeNonBlocking(from);
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    protected void flushBlocking() throws IOException {
        writeLock.lock();
        try {
            super.flushBlocking();
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    protected boolean flushNonBlocking() throws IOException {
        if (!writeLock.tryLock()) {
            // An application write is in progress on another thread and is
            // actively draining the staging buffers itself. This
            // opportunistic flush never blocks: report data left to keep the
            // caller's write interest armed.
            return true;
        }
        try {
            return flushNonBlockingLocked();
        } finally {
            writeLock.unlock();
        }
    }


    private boolean flushNonBlockingLocked() throws IOException {
        boolean dataLeft = !socketBufferHandler.isWriteBufferEmpty();
        if (dataLeft) {
            doWrite(false);
            dataLeft = !socketBufferHandler.isWriteBufferEmpty();
        }
        if (!dataLeft && !nonBlockingWriteBuffer.isEmpty()) {
            dataLeft = nonBlockingWriteBuffer.write(this, false);
            if (!dataLeft && !socketBufferHandler.isWriteBufferEmpty()) {
                doWrite(false);
                dataLeft = !socketBufferHandler.isWriteBufferEmpty();
            }
        }
        return dataLeft;
    }


    /**
     * Writes data to the QUIC stream. Stream conclusion (the FIN) is not a
     * write concern here: it is performed by {@link #concludeStream()} only,
     * which releases the held-back tail with the FIN flag set once the
     * application is done writing (the tail stash below is that tail).
     *
     * @param block    Whether to block
     * @param buffer   The data buffer
     * @throws IOException If an I/O error occurs
     */
    @Override
    protected void doWrite(boolean block, ByteBuffer buffer) throws IOException {
        QuicheStreamWrapper stream = liveStream();
        if (stream == null) {
            throw new IOException(sm.getString("socketWrapper.quicStreamClosed"));
        }

        if (log.isDebugEnabled()) {
            log.debug("doWrite: streamId=" + stream.getStreamId() + " len=" + buffer.remaining()
                    + " block=" + block);
        }

        // Bounded deadline for blocking writes. A blocking write must either
        // write the entire buffer or throw (SocketWrapperBase contract), so
        // on would-block (flow control / full send buffer) we wait for the
        // poll thread to signal a write event (or a terminal state) and
        // retry until the data is sent or the deadline passes.
        long deadline = block
                ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(blockingWriteTimeoutMs())
                : 0L;

        // Stream order requires previously held-back tail bytes to go out
        // before any new data. A non-blocking write that cannot forward them
        // right now leaves the caller's buffer untouched and re-arms write
        // interest.
        if (finTail != null && !releaseFinTail(stream, block, deadline)) {
            registerWriteInterest();
            return;
        }

        // Hold the final bytes of this write back from quiche: they are
        // forwarded at conclude time with the FIN flag set, so the FIN rides
        // on a data-bearing frame (see FIN_TAIL_SIZE). The loop below only
        // sees the truncated buffer; the caller's view is restored on every
        // exit path.
        int startPos = buffer.position();
        int endLimit = buffer.limit();
        int total = endLimit - startPos;
        byte[] newTail = null;
        if (total > 0 && !stream.isConcluded()) {
            int keep = Math.min(FIN_TAIL_SIZE, total);
            ByteBuffer view = buffer.duplicate();
            view.limit(endLimit);
            view.position(endLimit - keep);
            newTail = new byte[keep];
            view.get(newTail);
            buffer.limit(endLimit - keep);
        }

        try {
            while (true) {
                int remaining = buffer.remaining();
                if (remaining == 0) {
                    // Entire (truncated) buffer written: the held tail now
                    // covers the stream's final bytes, and from the caller's
                    // point of view the whole buffer was consumed.
                    if (newTail != null) {
                        finTail = newTail;
                        finTailPos = 0;
                    }
                    buffer.limit(endLimit);
                    buffer.position(startPos + total);
                    return;
                }

                // Anchor progress to the position at the start of this
                // iteration: writeChunk() consumes all remaining bytes, but
                // quiche may accept only a prefix of them.
                int iterPos = buffer.position();

                int written;
                try {
                    written = writeChunk(stream, buffer);
                } catch (IOException ioe) {
                    buffer.position(iterPos);
                    throw new IOException(sm.getString("socketWrapper.quicWriteError"), ioe);
                }

                if (written >= 0) {
                    buffer.position(iterPos + written);
                    if (buffer.remaining() == 0) {
                        // Full write; the tail stash and conclusion are
                        // handled at the top of the loop next iteration. The
                        // queued data is flushed to the wire by the poll
                        // loop's send pass.
                        continue;
                    }
                    if (!block) {
                        // Non-blocking: re-arm write interest so the poll loop
                        // retries the remainder; the rest stays in the buffer.
                        registerWriteInterest();
                        return;
                    }
                    // Blocking: wait for the next write opportunity, then loop
                    // to write the remainder. A failed wait (deadline expired
                    // or interrupted) ends the write, as in every other wait
                    // site: an un-honoured interrupt must not buy extra
                    // native write attempts.
                    if (!awaitWritable(deadline)) {
                        registerWriteInterest();
                        // Socket transport contract: see the blocking reads.
                        throw new SocketTimeoutException(
                                sm.getString("socketWrapper.quicWriteTimeout"));
                    }
                    continue;
                }

                if (written == WRITE_TERMINAL) {
                    finTail = null;
                    finTailPos = 0;
                    buffer.position(iterPos);
                    throw new IOException(sm.getString("socketWrapper.quicStreamClosed"));
                }

                // Would-block (no progress). Restore the position to the start
                // of this iteration so the remainder stays in the buffer.
                buffer.position(iterPos);
                if (!block) {
                    // Non-blocking: re-arm write interest and return with data
                    // still pending in the buffer.
                    registerWriteInterest();
                    return;
                }
                // Blocking: wake the poll loop (which runs the send/recv sweep
                // that recovers flow-control credit), arm write interest and
                // park until the poll thread signals a write event or a
                // terminal stream state, bounded.
                if (!awaitWritable(deadline)) {
                    registerWriteInterest();
                    // Socket transport contract: a blocking write that runs
                    // out of time reports the timeout, matching the blocking
                    // reads.
                    throw new SocketTimeoutException(
                            sm.getString("socketWrapper.quicWriteTimeout"));
                }
                // Loop and retry the write.
            }
        } finally {
            buffer.limit(endLimit);
        }
    }


    /**
     * Forwards held-back tail bytes to quiche without the FIN flag (they are
     * no longer the stream's final bytes once new data follows).
     *
     * @return {@code true} if the tail was fully forwarded (or vanished),
     *         {@code false} if a non-blocking write would block
     * @throws IOException If the stream is in a terminal write state, the
     *         native write fails, or a blocking write times out
     */
    private boolean releaseFinTail(QuicheStreamWrapper stream, boolean block, long deadline)
            throws IOException {
        while (finTail != null) {
            int written = writeBytes(stream, finTail, finTailPos,
                    finTail.length - finTailPos, false);
            if (written == WRITE_TERMINAL) {
                finTail = null;
                finTailPos = 0;
                throw new IOException(sm.getString("socketWrapper.quicStreamClosed"));
            }
            if (written < 0) {
                if (!block) {
                    return false;
                }
                if (!awaitWritable(deadline)) {
                    // Socket transport contract: see the blocking reads.
                    throw new SocketTimeoutException(
                            sm.getString("socketWrapper.quicWriteTimeout"));
                }
                continue;
            }
            finTailPos += written;
            if (finTailPos >= finTail.length) {
                finTail = null;
                finTailPos = 0;
            }
        }
        return true;
    }


    /**
     * Writes the remaining bytes of the buffer to the stream on the poll
     * thread via quiche_conn_stream_send().
     *
     * @return the number of bytes written, {@code -1} if the write would
     *         block, or {@link #WRITE_TERMINAL} if the stream/connection is
     *         in a terminal write state
     * @throws IOException if the native write fails unexpectedly
     */
    private int writeChunk(QuicheStreamWrapper stream, ByteBuffer buffer) throws IOException {
        int remaining = buffer.remaining();
        byte[] data = new byte[remaining];
        buffer.get(data);
        return writeBytes(stream, data, 0, data.length, false);
    }


    /**
     * Writes a slice of the given bytes to the stream on the poll thread via
     * quiche_conn_stream_send().
     *
     * @return the number of bytes written, {@code -1} if the write would
     *         block, or {@link #WRITE_TERMINAL} if the stream/connection is
     *         in a terminal write state
     * @throws IOException if the native write fails unexpectedly
     */
    private int writeBytes(QuicheStreamWrapper stream, byte[] data, int off, int len,
            boolean fin) throws IOException {
        byte[] payload = fin ? java.util.Arrays.copyOfRange(data, off, off + len) : data;
        int payloadLen = fin ? payload.length : len;
        return onPollThread(() -> {
            QuicheConnectionWrapper conn = stream.getConnection();
            MemorySegment connPtr = conn.getConn();
            long capacity = QuicheBindings.quiche_conn_stream_capacity(connPtr,
                    stream.getStreamId());
            if (capacity < 0) {
                // Any negative quiche_conn_stream_capacity - quiche 0.30.0
                // returns StreamStopped (peer STOP_SENDING) or
                // InvalidStreamState (stream collected / never created), and
                // a future quiche could add others - means the stream can
                // never accept the write: terminal write state. (A
                // per-code list would only pin the reachable subset; here
                // the whole negative range shares one outcome. The twin
                // server-uni path, QuicheConnectionWrapper.writeToStream(),
                // applies the same whole-negative-range rule - when a
                // quiche update adds a capacity error, revisit both
                // together.)
                return WRITE_TERMINAL;
            }
            if (capacity == 0) {
                return -1;
            }
            if (fin && capacity < payloadLen) {
                // quiche truncates a fin-marked send that does not fit to the
                // available capacity and silently drops the FIN flag with the
                // excess (send_buf.reserve_for_write: len = cap, fin = false),
                // so a partial acceptance would send the head of the tail
                // without FIN and leave the conclusion to a later send. Wait
                // for room for the whole tail instead: the FIN keeps riding
                // the complete tail in one data-bearing frame (see
                // FIN_TAIL_SIZE) and the tail bookkeeping stays unsplit.
                return -1;
            }
            int toSend = (int) Math.min(capacity, payloadLen);
            try (Arena localArena = Arena.ofConfined()) {
                MemorySegment dataSeg = localArena.allocate(toSend);
                dataSeg.asByteBuffer().put(payload, fin ? 0 : off, toSend);
                MemorySegment errPtr = localArena.allocate(ValueLayout.JAVA_LONG);
                errPtr.set(ValueLayout.JAVA_LONG, 0, 0L);
                long written = QuicheBindings.quiche_conn_stream_send(connPtr,
                        stream.getStreamId(), dataSeg, toSend, fin, errPtr);
                if (written > 0) {
                    return (int) written;
                }
                if (written == 0) {
                    // quiche accepted nothing (it can report usable capacity
                    // yet still take zero). Treat as would-block: a zero
                    // return makes the callers - doWrite, concludeStream and
                    // releaseFinTail - advance their positions by nothing
                    // and busy-spin without waiting.
                    return -1;
                }
                if (written == QuicheBindings.QUICHE_ERR_FLOW_CONTROL ||
                        written == QuicheBindings.QUICHE_ERR_DONE) {
                    return -1;
                }
                if (written == QuicheBindings.QUICHE_ERR_STREAM_RESET ||
                        written == QuicheBindings.QUICHE_ERR_STREAM_STOPPED ||
                        written == QuicheBindings.QUICHE_ERR_INVALID_STREAM_STATE ||
                        written == QuicheBindings.QUICHE_ERR_FINAL_SIZE) {
                    return WRITE_TERMINAL;
                }
                if (QuicheBindings.quiche_conn_is_closed(connPtr) ||
                        conn.isClosed() || conn.isFreed()) {
                    return WRITE_TERMINAL;
                }
                return -1;
            }
        });
    }


    /**
     * Concludes a QUIC stream by sending its final bytes (the held-back tail,
     * if any) with the fin flag set, falling back to an empty fin-send when
     * the stream produced no held tail. The FIN rides on a data-bearing frame
     * whenever possible: quiche collects a stream whose send data is fully
     * acknowledged - discarding an un-acknowledged zero-length FIN frame with
     * it - but a data+FIN frame can only be acknowledged by actually
     * delivering the FIN, and is retransmitted by loss recovery when lost.
     */
    private void concludeStream(QuicheStreamWrapper stream) throws IOException {
        long deadline = System.nanoTime() +
                TimeUnit.MILLISECONDS.toNanos(blockingWriteTimeoutMs());
        boolean finSent = false;
        while (finTail != null) {
            int written = writeBytes(stream, finTail, finTailPos,
                    finTail.length - finTailPos, true);
            if (written == WRITE_TERMINAL) {
                // Stream/connection is gone: nothing to conclude.
                finTail = null;
                finTailPos = 0;
                return;
            }
            if (written < 0) {
                if (!awaitWritable(deadline)) {
                    // The held tail never drained. Dropping it would hand
                    // the client a body that is short by the undelivered
                    // bytes with the stream left looking complete, so
                    // surface the failure instead: reset the stream (the
                    // transport delivers the reset to the client) and drop
                    // the tail.
                    log.warn(sm.getString("socketWrapper.concludeIncomplete",
                            Long.valueOf(stream.getStreamId()),
                            Integer.valueOf(finTailPos),
                            Integer.valueOf(finTail.length)));
                    finTail = null;
                    finTailPos = 0;
                    resetStream(endpoint.getDefaultStreamErrorCode());
                    return;
                }
                continue;
            }
            finTailPos += written;
            if (finTailPos >= finTail.length) {
                finTail = null;
                finTailPos = 0;
                finSent = true;
            }
        }
        boolean sent = finSent;
        onPollThreadVoid(() -> {
            QuicheConnectionWrapper conn = stream.getConnection();
            // Defense-in-depth: a task queued during a late endpoint stop
            // can run after the connection was freed (or after this stream's
            // connection was replaced). Never hand a freed pointer to quiche.
            if (conn == null || conn.isFreed()) {
                return;
            }
            try (Arena localArena = Arena.ofConfined()) {
                if (!sent) {
                    // Zero-length send with fin=true. Pass a one-byte
                    // allocation so the buffer pointer is never NULL.
                    MemorySegment buf = localArena.allocate(1);
                    MemorySegment errPtr = localArena.allocate(ValueLayout.JAVA_LONG);
                    errPtr.set(ValueLayout.JAVA_LONG, 0, 0L);
                    long rc = QuicheBindings.quiche_conn_stream_send(conn.getConn(),
                            stream.getStreamId(), buf, 0, true, errPtr);
                    if (rc < 0 && log.isDebugEnabled()) {
                        log.debug("concludeStream: stream_send(fin) rc=" + rc +
                                " err=" + errPtr.get(ValueLayout.JAVA_LONG, 0) +
                                " on stream " + stream.getStreamId());
                    }
                }
            }
            endpoint.flushConnectionOnce(conn);
        });
    }


    // ------------------------------------- Interest registration

    @Override
    public void registerReadInterest() {
        // No-op on quiche. Readiness is owned by the transport: the poll
        // loop's readable sweep (rearmReadWaiters) signals a parked waiter
        // from quiche_conn_stream_readable directly, so there is no
        // registration to make - unlike registerWriteInterest(), which
        // latches a flag the writable sweep consults for buffered data.
    }


    @Override
    public void registerWriteInterest() {
        QuicheStreamWrapper stream = getSocket();
        if (stream != null && stream.setWriteInterestIfAbsent()) {
            // The false→true transition: register the stream in the
            // connection's write re-arm index (re-arm sweep work set) before
            // the latch becomes observable to the writable sweep.
            stream.getConnection().addWriteRearm(stream);
        }
    }


    // ------------------------------------- Sendfile (emulated via read+write for QUIC)

    @Override
    public SendfileDataBase createSendfileData(String filename, long pos, long length) {
        return new QuicSendfileData(filename, pos, length);
    }


    @Override
    public SendfileState processSendfile(SendfileDataBase sendfileData) {
        // Fail closed by design. The HTTP/3 connector disables sendfile
        // (AbstractHttp3Protocol's endpoint constructor calls setUseSendfile(false))
        // because responses must be framed as DATA frames by the processor;
        // a raw-byte emulation would write the file bytes onto the stream
        // with no DATA-frame framing, so enabling sendfile for a H3 wrapper
        // without adding framing here would corrupt the response body. The
        // guard is code, not just a comment: if reachability ever opens,
        // this reports an error instead of corrupting data, until the path
        // gains proper framing.
        if (log.isDebugEnabled()) {
            log.debug(sm.getString("socketWrapper.quicSendfileUnsupported"));
        }
        return SendfileState.ERROR;
    }


    /**
     * Sendfile data for QUIC streams, emulated via read+write.
     */
    private static class QuicSendfileData extends SendfileDataBase {

        QuicSendfileData(String filename, long pos, long length) {
            super(filename, pos, length);
        }
    }


    // ------------------------------------- SSL

    @Override
    public void doClientAuth(SSLSupport sslSupport) throws IOException {
        // QUIC does not support renegotiation
        throw new IOException(sm.getString("socketWrapper.quicNoRenegotiation"));
    }


    @Override
    public SSLSupport getSslSupport() {
        if (sslSupport == null) {
            sslSupport = new QuicheSSLSupport(this);
        }
        return sslSupport;
    }


    // ------------------------------------- Close

    @Override
    protected void doClose() {
        try {
            QuicheStreamWrapper stream = getSocket();
            if (stream != null) {
                // Remove the stream from the endpoint's bookkeeping. This
                // must run on the poll thread: the poll loop must not be
                // mid-sweep over the stream's state when it is removed.
                if (!endpoint.isPollThread()) {
                    onPollThreadVoid(() -> endpoint.closeStreamByHandler(stream));
                } else {
                    endpoint.closeStreamByHandler(stream);
                }
            }
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            if (isInterrupted(t)) {
                // The calling request handler was interrupted - by the
                // executor shutdown at endpoint stop - while this close
                // hopped to the poll thread. Expected shutdown noise, not a
                // transport failure: stopInternal() frees (or retains) the
                // whole connection regardless, so no native state is left
                // behind by the skipped stream removal.
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("socketWrapper.quicCloseInterrupted"), t);
                }
            } else {
                // A close failure leaves native state behind; surface it
                // unconditionally rather than hiding it behind a debug
                // guard.
                log.error(sm.getString("socketWrapper.quicCloseError"), t);
            }
        } finally {
            socketBufferHandler = null;
        }
    }


    /**
     * Whether the failure surface wraps a thread interruption (the hop's
     * {@link InterruptedException} translated into an {@link IOException},
     * flag already restored by {@code callOnPollThreadChecked}).
     *
     * @param t The failure to inspect
     *
     * @return {@code true} if an {@link InterruptedException} appears in
     *         the cause chain
     */
    private static boolean isInterrupted(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof InterruptedException) {
                return true;
            }
        }
        return false;
    }


    // ------------------------------------- WriteBuffer.Sink

    @Override
    public boolean writeFromBuffer(ByteBuffer buffer, boolean block) throws IOException {
        doWrite(block, buffer);
        return buffer.hasRemaining();
    }


    // ------------------------------------- NIO2 vectored I/O

    @Override
    protected <A> OperationState<A> newOperationState(boolean read, ByteBuffer[] buffers, int offset, int length,
            BlockingMode block, long timeout, TimeUnit unit, A attachment, CompletionCheck check,
            java.nio.channels.CompletionHandler<Long, ? super A> handler, Semaphore semaphore,
            VectoredIOCompletionHandler<A> completion) {
        return new QuicOperationState<>(read, buffers, offset, length, block, timeout, unit,
                attachment, check, handler, semaphore, completion);
    }


    @Override
    public boolean needSemaphores() {
        return true;
    }


    /**
     * Operation state for QUIC vectored I/O.
     *
     * @param <A> The attachment type
     */
    private class QuicOperationState<A> extends OperationState<A> {

        @Override
        protected boolean isInline() {
            return true;
        }


        private QuicOperationState(boolean read, ByteBuffer[] buffers, int offset, int length,
                BlockingMode block, long timeout, TimeUnit unit, A attachment, CompletionCheck check,
                java.nio.channels.CompletionHandler<Long, ? super A> handler, Semaphore semaphore,
                VectoredIOCompletionHandler<A> completion) {
            super(read, buffers, offset, length, block, timeout, unit, attachment, check, handler, semaphore,
                    completion);
        }


        @Override
        public void run() {
            long nBytes = 0;
            if (getError() == null) {
                try {
                    synchronized (this) {
                        if (!completionDone) {
                            if (log.isTraceEnabled()) {
                                log.trace("Skip concurrent " + (read ? "read" : "write") + " notification");
                            }
                            return;
                        }
                    }

                    if (read) {
                        for (int i = 0; i < length; i++) {
                            int bytes = read(false, buffers[offset + i]);
                            if (bytes > 0) {
                                nBytes += bytes;
                            } else {
                                break;
                            }
                        }
                    } else {
                        // The vectored path calls doWrite() without taking
                        // writeLock - shared upstream behaviour. Safety
                        // rests on two preconditions, not one: the NIO2
                        // machinery keeps at most one operation state per
                        // wrapper in flight, so no second vectored writer
                        // overlaps this loop; and flushNonBlocking() -
                        // called from the poll thread's opportunistic
                        // write-ready flush as well as from the worker-side
                        // dispatch re-arm and sendfile - takes writeLock,
                        // which this loop does not hold and which therefore
                        // cannot exclude it, but reaches doWrite() only
                        // through staged residue (socketBufferHandler write
                        // buffer / nonBlockingWriteBuffer), which a
                        // contract-conforming producer has already drained
                        // before issuing a vectored write. Note when
                        // touching either wrapper: doWrite() also mutates
                        // the finTail/finTailPos conclusion bookkeeping,
                        // which every other writer holds under writeLock -
                        // relaxing either precondition would let this
                        // unsynchronised loop race that state. The OpenSSL
                        // twin (QuicOpenSSLSocketWrapper's
                        // QuicOperationState) states the same rule with the
                        // same preconditions; keep the two in step.
                        for (int i = 0; i < length; i++) {
                            int start = buffers[offset + i].position();
                            doWrite(false, buffers[offset + i]);
                            nBytes += buffers[offset + i].position() - start;
                            if (buffers[offset + i].hasRemaining()) {
                                // Non-blocking would-block: stop here.
                                // Writing the next buffer now would append
                                // its bytes ahead of the undelivered
                                // remainder and corrupt the byte order.
                                break;
                            }
                        }
                    }
                } catch (IOException ioe) {
                    completion.failed(ioe, this);
                    return;
                }
            }
            completion.completed(Long.valueOf(nBytes), this);
        }
    }


    // ------------------------------------- SSL Support

    /**
     * SSLSupport implementation for QUIC streams on the quiche transport.
     * quiche exposes none of the per-connection TLS details (cipher suite,
     * session id, peer chain) through its C API, so those report
     * "unavailable" ({@code null}), which is what
     * {@code QuicOpenSSLSocketWrapper}'s support does for its unknowns.
     * QUIC always runs over TLS 1.3 (RFC 9001 Section 4.2).
     */
    private static class QuicheSSLSupport implements SSLSupport {
        private final QuicheSocketWrapper wrapper;

        private QuicheSSLSupport(QuicheSocketWrapper wrapper) {
            this.wrapper = wrapper;
        }

        @Override
        public String getCipherSuite() throws IOException {
            return null;
        }

        @Override
        public java.security.cert.X509Certificate[] getPeerCertificateChain() throws IOException {
            return null;
        }

        @Override
        public String getSessionId() throws IOException {
            return null;
        }

        @Override
        public String getProtocol() throws IOException {
            // QUIC runs on TLS 1.3 exclusively (RFC 9001 Section 4.2).
            return "TLSv1.3";
        }

        @Override
        public String getRequestedProtocols() throws IOException {
            // Deliberate deviation from the interface contract:
            // SSLSupport.getRequestedProtocols() is documented as "the list
            // of SSL/TLS protocol versions requested by the client", but
            // QUIC runs on TLS 1.3 exclusively (see getProtocol above) and
            // quiche exposes no requested-version list - only the ALPN
            // result. Return the negotiated protocol (e.g. "h3"), matching
            // what the OpenSSL transport's QuicOpenSSLSocketWrapper does.
            QuicheStreamWrapper stream = wrapper.getQuicStream();
            if (stream != null) {
                QuicheConnectionWrapper conn = stream.getConnection();
                if (conn != null) {
                    return conn.getNegotiatedProtocol();
                }
            }
            return null;
        }

        @Override
        public String getRequestedCiphers() throws IOException {
            return null;
        }

        @Override
        public Integer getKeySize() throws IOException {
            return null;
        }
    }
}

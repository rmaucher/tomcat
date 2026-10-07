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

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
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
import org.apache.tomcat.util.openssl.openssl_h;
import org.apache.tomcat.util.res.StringManager;


/**
 * Socket wrapper for a QUIC stream on the OpenSSL transport. Wraps a
 * {@link QuicStreamWrapper} to provide the {@link SocketWrapperBase}
 * behaviour expected by {@code AbstractProtocol} and the generic QUIC view
 * declared by {@link QuicSocketWrapper}, which this class extends.
 * <p>
 * Each QUIC stream is wrapped in an instance of this class and passed to the
 * Coyote processor via {@code AbstractEndpoint.processSocket()}. The wrapper
 * delegates I/O operations to the underlying OpenSSL QUIC SSL* object.
 */
public class QuicOpenSSLSocketWrapper extends QuicSocketWrapper
        implements WriteBuffer.Sink {

    private static final Log log = LogFactory.getLog(QuicOpenSSLSocketWrapper.class);
    private static final StringManager sm = StringManager.getManager(QuicOpenSSLSocketWrapper.class);

    /**
     * The endpoint that owns this wrapper.
     */
    private final QuicOpenSSLEndpoint endpoint;

    /**
     * SSL session support for this stream.
     */
    private QuicSSLSupport sslSupport;

    /**
     * Serializes every operation that touches the shared write staging buffer
     * ({@code socketBufferHandler} and {@code nonBlockingWriteBuffer}).
     * <p>
     * An asynchronous application may write from a non-container thread (the
     * thread it started after {@code WriteListener.onWritePossible()}), while
     * the endpoint concurrently drains the same buffers from a dispatch thread
     * (the LONG-state flush in {@code QuicOpenSSLEndpoint.runStreamDispatch})
     * or from the async completion path. Neither {@link SocketBufferHandler}
     * nor {@link java.nio.ByteBuffer} is thread-safe, so without this lock
     * concurrent writers corrupt the staged HTTP/3 frame stream (duplicated,
     * skipped or interleaved bytes), which breaks framing on the peer. This is
     * the QUIC equivalent of the write lock in HTTP/2's
     * {@code Stream.StreamOutputBuffer}.
     */
    private final ReentrantLock writeLock = new ReentrantLock();

    /**
     * Creates a new socket wrapper for a QUIC stream.
     *
     * @param stream   The underlying QUIC stream
     * @param endpoint The owning QUIC endpoint
     */
    public QuicOpenSSLSocketWrapper(QuicStreamWrapper stream, QuicOpenSSLEndpoint endpoint) {
        super(stream, endpoint);
        this.endpoint = endpoint;
        // The write staging buffer is sized well above the 8 KiB application
        // output buffer chunks: the real send buffer is OpenSSL's QUIC
        // transmit queue, so a larger staging buffer lets many framed chunks
        // accumulate before one poll-thread hop (one SSL_write_ex2) is
        // needed. With the default 8 KiB size every 8 KiB of response data
        // cost a round trip to the poll thread, throttling uploads.
        this.socketBufferHandler = new SocketBufferHandler(
                endpoint.getSocketProperties().getAppReadBufSize(),
                Math.max(65536, endpoint.getSocketProperties().getAppWriteBufSize()),
                false);
        QuicConnectionWrapper conn = stream.getConnection();
        if (conn != null) {
            this.remoteAddress = conn.getRemoteAddress();
            this.localAddress = conn.getLocalAddress();
            // Deliberately do not copy the connection's negotiated protocol
            // to the stream wrapper. HTTP/3 is not an upgrade: AbstractProtocol
            // would try to resolve it via its UpgradeProtocol (ALPN-upgrade)
            // lookup, which AbstractHttp3Protocol does not participate in, and fail
            // the stream. The connection-level negotiated protocol (conn) is
            // still used by the endpoint to gate dispatch.
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public QuicStreamWrapper getQuicStream() {
        return getSocket();
    }


    /**
     * {@inheritDoc}
     * <p>
     * Narrows the socket to the concrete stream wrapper type used by this
     * endpoint.
     */
    @Override
    public QuicStreamWrapper getSocket() {
        return (QuicStreamWrapper) super.getSocket();
    }


    /**
     * Returns the stream backing this wrapper iff its native {@code SSL*} is
     * safe to touch, otherwise {@code null}. "Safe" is the full set of
     * conditions that every native-accessing path must satisfy - the stream is
     * present, has not been freed, and still holds a non-NULL {@code SSL*} -
     * so that no call site has to re-decide (and can never accidentally omit)
     * part of the check. A freed stream's {@code SSL*} may already be back in
     * the allocator, so touching it is the use-after-free class of bug (F1)
     * this guard exists to prevent.
     * <p>
     * This is the wrapper-side entry guard; the endpoint-side equivalent is
     * {@code QuicOpenSSLEndpoint.isStreamLive()} (which additionally rejects a
     * closed or freed connection, because endpoint poll paths can be reached
     * for streams whose connection is going away). Callers translate a
     * {@code null} result into their own contract: read paths throw
     * {@code EOFException}, write paths throw {@code IOException}, and
     * best-effort paths ({@code concludeStream}, {@code resetStream},
     * {@code processSendfile}) return silently.
     *
     * @return the live stream, or {@code null} if its {@code SSL*} must not be
     *         touched
     */
    private QuicStreamWrapper liveStream() {
        QuicStreamWrapper stream = getSocket();
        if (stream == null || stream.isFreed()) {
            return null;
        }
        MemorySegment ssl = stream.getSsl();
        if (ssl == null || ssl.equals(MemorySegment.NULL)) {
            return null;
        }
        return stream;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public QuicConnectionWrapper getConnection() {
        QuicStreamWrapper stream = getSocket();
        return (stream != null) ? stream.getConnection() : null;
    }


    /**
     * Runs a native QUIC operation on the QUIC poll thread. OpenSSL QUIC is
     * not thread-safe for concurrent access to a connection, so every native
     * call of this wrapper executes on the poll thread: when the caller
     * already is the poll thread the task runs directly, otherwise it is
     * queued and the caller blocks until the poll loop has executed it
     * (see {@link QuicOpenSSLEndpoint#callOnPollThread}).
     *
     * <p>The task must be a single fast operation (one native call or one
     * poll-set mutation) and must never block: the poll thread is the only
     * thread that drains the queue, so a blocking task would deadlock.</p>
     *
     * @param task The native operation to run on the poll thread
     * @return The task's result
     * @throws IOException If the task fails or the poll thread does not
     *                     complete it in time
     */
    private <T> T onPollThread(Callable<T> task) throws IOException {
        try {
            return endpoint.callOnPollThread(task);
        } catch (IOException | RuntimeException | Error e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        } catch (TimeoutException e) {
            throw new IOException(sm.getString("socketWrapper.quicPollTaskTimeout"), e);
        } catch (Exception e) {
            Throwable cause = (e instanceof ExecutionException ec && ec.getCause() != null)
                    ? ec.getCause() : e;
            if (cause instanceof Error err) {
                // A failed native binding call (AssertionError from
                // QuicBindings) means OpenSSL is broken: fatal, do not
                // downgrade it to an IOException the caller may survive.
                throw err;
            }
            if (cause instanceof IOException ioe) {
                throw ioe;
            }
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            throw new IOException(cause);
        }
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
     * Drives the QUIC state machine on the parent connection by calling
     * SSL_handle_events(). Because the endpoint attaches a datagram BIO to the
     * UDP socket FD, this also recvs and processes any newly arrived datagrams,
     * making their stream data available to a subsequent SSL_read_ex.
     *
     * <p>The native call is always executed on the poll thread (see
     * {@link #onPollThread(Callable)}) to avoid racing the poll loop's own
     * SSL_handle_events on the connection.</p>
     */
    @Override
    public void pumpConnectionEvents() {
        QuicConnectionWrapper conn = getConnection();
        if (conn == null) {
            return;
        }
        try {
            onPollThreadVoid(() -> QuicBindings.SSL_handle_events(conn.getSsl()));
        } catch (IOException e) {
            // Ignore - the poll loop will surface any real errors
        }
    }


    // ------------------------------------- Blocking I/O wake-up

    /**
     * One wait cycle of a stalled blocking read: pump the connection state
     * machine once (processing any datagrams that already arrived), arm read
     * interest so the level-triggered R event will fire for data that
     * arrives after this worker went to sleep, then park until the poll
     * thread signals a read event / terminal state or the deadline passes.
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
        readWaiter().set(self);
        try {
            pumpConnectionEvents();
            registerReadInterest();
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
        writeWaiter().set(self);
        try {
            pumpConnectionEvents();
            registerWriteInterest();
            if (System.nanoTime() >= deadlineNanos) {
                return false;
            }
            if (endpoint.isPollThread()) {
                // The poll loop cannot deliver a signal while it is blocked
                // here (inline processing during shutdown): pause briefly so
                // the just-pumped flow-control updates can take effect on the
                // retry.
                return pauseBriefly(deadlineNanos);
            }
            return awaitWakeRemaining(writeWaiter(), writeWakeups(), seq, deadlineNanos);
        } finally {
            writeWaiter().compareAndSet(self, null);
        }
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
        checkNotClosed();
        // SocketWrapperBase contract: a blocking read waits for data and
        // reports a timed-out wait as a SocketTimeoutException (the socket
        // transports all do); the would-block marker 0 stays reserved for
        // non-blocking reads, which callers cannot otherwise distinguish from
        // a timeout. On a would-block (e.g. flow-control window exhausted)
        // pump the QUIC state machine and retry, bounded - mirroring
        // doWrite(). Each native step runs on the poll thread (see
        // onPollThread); the wait below parks on the calling (worker) thread
        // and is released by a poll-thread signal, so a stalled stream neither
        // occupies the poll loop nor polls it at a fixed interval.
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
                // Socket transport contract: a blocking read that runs out of
                // time reports the timeout rather than the would-block marker
                // 0, which callers cannot distinguish from a real no-data
                // result.
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
                // caller's buffer, up to its full remaining space. Unlike the
                // TCP path there is no socket read buffer that bounds the read,
                // so clamping to its size would force one poll-thread hop per
                // 8 KiB and throttle throughput.
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
        QuicStreamWrapper stream = liveStream();
        if (stream == null) {
            throw new EOFException(sm.getString("socketWrapper.quicStreamClosed"));
        }

        MemorySegment ssl = stream.getSsl();

        // Serve pre-read data from the stream's buffer first.
        // The endpoint may have pre-read stream data immediately after SSL_accept_stream
        // to prevent SSL_handle_events from processing the FIN before we read.
        // Read buffer protocol (put mode): buffered bytes occupy [0..position),
        // limit == capacity. Every path that touches the buffer maintains this
        // state; the hand-over itself is the shared transferPutMode, bound to
        // what the destination can still hold.
        ByteBuffer preReadBuf = stream.getReadBuffer();
        if (preReadBuf != null && preReadBuf.position() > 0) {
            return QuicStreamWrapper.transferPutMode(preReadBuf, buffer);
        }

        try (Arena localArena = Arena.ofConfined()) {
            int remaining = buffer.remaining();
            if (remaining == 0) {
                return 0;
            }

            MemorySegment nativeBuf = localArena.allocate(remaining);
            MemorySegment lenPtr = localArena.allocate(ValueLayout.JAVA_LONG);
            lenPtr.set(ValueLayout.JAVA_LONG, 0, 0L);

            int rc = QuicBindings.SSL_read_ex(ssl, nativeBuf, (long) remaining, lenPtr);

            if (rc == 1) {
                long bytesRead = lenPtr.get(ValueLayout.JAVA_LONG, 0);
                int actualLen = (int) Math.min(bytesRead, remaining);
                // Single native -> heap copy. ByteBuffer.put(ByteBuffer) resolves
                // the native source address directly; a Java byte[] staging copy
                // is not needed.
                buffer.put(nativeBuf.asSlice(0, actualLen).asByteBuffer());
                return actualLen;
            } else if (rc == 0) {
                int state = QuicBindings.SSL_get_stream_read_state(ssl);
                stream.setReadState(QuicStreamWrapper.mapNativeState(state));

                if (state == QuicPoll.SSL_STREAM_STATE_FINISHED) {
                    return -1;
                }
                if (state == QuicPoll.SSL_STREAM_STATE_RESET_LOCAL ||
                        state == QuicPoll.SSL_STREAM_STATE_RESET_REMOTE ||
                        state == QuicPoll.SSL_STREAM_STATE_CONN_CLOSED) {
                    throw new EOFException(sm.getString("socketWrapper.quicStreamClosed"));
                }
                return 0;
            } else {
                throw new IOException(sm.getString("socketWrapper.quicReadFailed"));
            }
        }
    }


    @Override
    public void setAppReadBufHandler(ApplicationBufferHandler handler) {
        // No-op: QUIC stream I/O is managed by OpenSSL SSL_read_ex/SSL_write_ex
    }


    // ------------------------------------- Write

    /**
     * Concludes this QUIC stream by sending a FIN (stream-level close).
     * Calls SSL_stream_conclude() on the underlying stream SSL object.
     */
    @Override
    public void concludeStream() throws IOException {
        QuicStreamWrapper stream = liveStream();
        if (stream == null) {
            return;
        }
        concludeStream(stream.getSsl());
        stream.setConcluded();
    }


    /**
     * Checks if this stream has been concluded.
     *
     * @return {@code true} if this stream has been concluded
     */
    @Override
    public boolean isStreamConcluded() {
        QuicStreamWrapper stream = getSocket();
        return (stream != null) && stream.isConcluded();
    }


    /**
     * Resets this QUIC stream with the given error code.
     * Per RFC 9000 Section 2.4, RESET_STREAM sends a transport-level
     * reset with the given QUIC error code. The native work (including the
     * retry loop that drives the state machine until the reset lands) is
     * shared with the endpoint-side resets and runs on the poll thread via
     * {@link QuicOpenSSLEndpoint#resetStream(QuicStreamWrapper, long)}.
     *
     * @param errorCode The error code (HTTP/3 stream error or connection error)
     * @return {@code true} if the reset took effect; {@code false} if the
     *         stream was already gone or the reset never landed after the
     *         retry loop (in which case the stream is later freed in its
     *         current state and OpenSSL emits a spurious error-0 RESET_STREAM
     *         instead of the intended error code - logged as a warning by the
     *         shared implementation)
     * @throws IOException If an I/O error occurs
     */
    @Override
    public boolean resetStream(long errorCode) throws IOException {
        QuicStreamWrapper stream = liveStream();
        if (stream == null) {
            return false;
        }
        Boolean done = onPollThread(() -> endpoint.resetStream(stream, errorCode));
        return done != null && done;
    }


    @Override
    protected void writeBlocking(byte[] buf, int off, int len) throws IOException {
        writeLock.lock();
        try {
            super.writeBlocking(buf, off, len);
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    protected void writeBlocking(ByteBuffer from) throws IOException {
        writeLock.lock();
        try {
            super.writeBlocking(from);
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    protected void writeNonBlocking(byte[] buf, int off, int len) throws IOException {
        writeLock.lock();
        try {
            super.writeNonBlocking(buf, off, len);
        } finally {
            writeLock.unlock();
        }
    }


    @Override
    protected void writeNonBlocking(ByteBuffer from) throws IOException {
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
            /*
             * An application write is in progress on another thread and is
             * actively draining the staging buffers itself (a blocking write
             * either fully drains the buffer or throws, re-arming write
             * interest). Wait for that writer instead of corrupting the shared
             * buffer; a waiting poll thread could deadlock that writer (its
             * native operations are served by the poll loop), so this
             * opportunistic flush never blocks: report data left to keep the
             * caller's write interest armed. The pending flush is picked up by
             * a later dispatch (and, at the latest, by the blocking flush on
             * async completion).
             */
            return true;
        }
        try {
            return flushNonBlockingLocked();
        } finally {
            writeLock.unlock();
        }
    }


    private boolean flushNonBlockingLocked() throws IOException {
        if (socketBufferHandler == null) {
            // Closed (see the doClose() contract): nothing to stage into or
            // drain, and no data is left for the caller to care about.
            return false;
        }
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


    @Override
    protected void doWrite(boolean block, ByteBuffer buffer) throws IOException {
        doWrite(block, buffer, false);
    }


    /**
     * Writes data to the QUIC stream, optionally concluding (FIN-ing) the
     * stream once the whole buffer has been written. The conclusion is a
     * separate {@code SSL_stream_conclude()} step performed after the last
     * byte is accepted - not the atomic {@code SSL_write_ex2} with
     * {@code SSL_WRITE_FLAG_CONCLUDE} variant - so a would-block or partial
     * write can never conclude the stream prematurely. Every in-tree
     * caller writes with {@code conclude == false} and concludes the stream
     * separately via {@link #concludeStream()}.
     *
     * @param block Whether to block
     * @param buffer The data buffer
     * @param conclude Whether to conclude (FIN) the stream after writing
     * @throws IOException If an I/O error occurs
     */
    protected void doWrite(boolean block, ByteBuffer buffer, boolean conclude) throws IOException {
        QuicStreamWrapper stream = liveStream();
        if (stream == null) {
            throw new IOException(sm.getString("socketWrapper.quicStreamClosed"));
        }

        MemorySegment ssl = stream.getSsl();

        if (log.isDebugEnabled()) {
            log.debug("doWrite: streamId=" + stream.getStreamId() + " len=" + buffer.remaining()
                    + " conclude=" + conclude + " block=" + block);
        }

        // Bounded deadline for blocking writes. A blocking write must either
        // write the entire buffer or throw (SocketWrapperBase contract), so on
        // would-block (flow control / full send buffer) we wait for the poll
        // thread to signal a write event (or a terminal state) and retry
        // until the data is sent or the deadline passes. Each native step
        // executes on the poll thread (see onPollThread); the wait happens on
        // the calling (worker) thread, so a flow control stall neither
        // occupies the poll loop nor hammers it at a fixed interval.
        long deadline = block
                ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(blockingWriteTimeoutMs())
                : 0L;
        while (true) {
            int remaining = buffer.remaining();
            if (remaining == 0) {
                // Entire buffer written; conclude the stream if requested.
                if (conclude) {
                    concludeStream(ssl);
                    stream.setConcluded();
                }
                return;
            }

            // Anchor progress to the position at the start of this iteration.
            // writeChunk() consumes all remaining bytes, but OpenSSL may accept
            // only a prefix of them; the rewind on would-block/error must
            // preserve the progress accumulated by earlier iterations, so the
            // anchor is re-captured every time round the loop rather than
            // being fixed at the buffer's original position.
            int startPos = buffer.position();

            // Write without the conclude flag; the stream is concluded
            // separately once the whole buffer has been sent, so a partial
            // write never concludes the stream prematurely.
            int written;
            try {
                written = writeChunk(ssl, buffer);
            } catch (IOException ioe) {
                buffer.position(startPos);
                throw new IOException(sm.getString("socketWrapper.quicWriteError"), ioe);
            }

            if (written >= 0) {
                buffer.position(startPos + written);
                if (buffer.remaining() == 0) {
                    // Full write; conclude is handled at the top of the loop
                    // next iteration. No pump needed: the queued data is
                    // flushed to the wire by the poll loop's SSL_poll.
                    continue;
                }
                if (!block) {
                    // Non-blocking: re-arm write interest so the poll loop
                    // retries the remainder; the rest stays in the buffer.
                    // No pump in the hop: the loop ticks right after the
                    // hop lands (the mailbox kick wakes it), which drives
                    // the state machine at least once per hop, and the
                    // in-hop pump would scale with the whole connection
                    // fleet.
                    registerWriteInterest();
                    return;
                }
                // Blocking: wait for the next write opportunity (the poll
                // thread signals a write event after a flow-control update)
                // instead of retrying at a fixed interval, then loop to write
                // the remainder. A timed-out (or interrupted) wait ends the
                // write immediately - the deadline must not be discovered one
                // extra native-write hop late by the would-block branch
                // below.
                if (!awaitWritable(deadline)) {
                    // Socket transport contract: see the blocking reads.
                    throw new SocketTimeoutException(
                            sm.getString("socketWrapper.quicWriteTimeout"));
                }
                continue;
            }

            // Would-block (no progress). Nothing was written this iteration;
            // restore the position to the start of this iteration so the
            // remainder (including anything accepted by earlier iterations is
            // already past the anchor) stays in the buffer.
            buffer.position(startPos);
            // Check write state for a terminal error.
            if (QuicPoll.isTerminalWriteState(getStreamWriteState(ssl))) {
                throw new IOException(sm.getString("socketWrapper.quicStreamClosed"));
            }
            if (!block) {
                // Non-blocking: re-arm write interest and return with data
                // still pending in the buffer.
                registerWriteInterest();
                return;
            }
            // Blocking: pump the QUIC state machine (sends buffered packets,
            // processes incoming WINDOW_UPDATE/ACKs), arm write interest and
            // park until the poll thread signals a write event (flow-control
            // update) or a terminal stream state, bounded. Write interest is
            // armed by awaitWritable on every return path.
            if (!awaitWritable(deadline)) {
                // Socket transport contract: a blocking write that runs out of
                // time reports the timeout, matching the blocking reads.
                throw new SocketTimeoutException(
                        sm.getString("socketWrapper.quicWriteTimeout"));
            }
            // Loop and retry the write.
        }
    }


    /**
     * Writes the remaining bytes of the buffer to the stream on the poll
     * thread via SSL_write_ex(2).
     *
     * @return the number of bytes written, or -1 if the write would block
     * @throws IOException if the native write fails
     */
    private int writeChunk(MemorySegment ssl, ByteBuffer buffer) throws IOException {
        // Hand the live buffer to the kernel instead of snapshotting it into
        // an array: the kernel leaves its position untouched (the caller
        // anchors progress itself) and this worker stays blocked in the hop
        // while the native call reads it, so neither position nor content can
        // change underneath the call.
        return onPollThread(() -> {
            try (Arena localArena = Arena.ofConfined()) {
                return QuicOpenSSLEndpoint.writeStreamData(ssl, buffer, localArena);
            }
        });
    }


    /**
     * Queries the stream write state on the poll thread.
     */
    private int getStreamWriteState(MemorySegment ssl) throws IOException {
        return onPollThread(() -> QuicBindings.SSL_get_stream_write_state(ssl));
    }


    /**
     * Concludes a QUIC stream by calling SSL_stream_conclude().
     * <p>
     * No engine pump is run in the hop. The stream's send queue serialises
     * its buffered data and the FIN inside OpenSSL, so no tick can send the
     * FIN ahead of the data, and the endpoint's poll loop always ticks at
     * least once right after this hop lands (the mailbox kick wakes the
     * wait and every drained hop sets the tick reason) - the loop's once-
     * per-iteration engine tick flushes data and FIN together. The pump
     * calls this method used to run (one full-engine tick per hop) are
     * redundant under the single-tick loop and scale with the whole
     * connection fleet, so they were removed; this is what keeps the
     * per-response worker-hop cost constant in the fleet size.
     */
    private void concludeStream(MemorySegment ssl) throws IOException {
        onPollThreadVoid(() -> QuicBindings.SSL_stream_conclude(ssl, 0L));
    }


    // ------------------------------------- Interest registration

    @Override
    public void registerReadInterest() {
        // Reference: pe_resume_read adds R to want_events
        resumeInterest(QuicPoll.SSL_POLL_EVENT_R);
    }


    @Override
    public void registerWriteInterest() {
        // Reference: pe_resume_write adds W to want_events
        resumeInterest(QuicPoll.SSL_POLL_EVENT_W);
    }


    /*
     * Adds an event to the stream's want_events. The want_events
     * read-modify-write must be atomic with the poll thread's R/W strip in
     * dispatchStreamEvent, so it runs on the poll thread when called from a
     * worker. Fire-and-forget: the worker never waits for this, so a stopped
     * poll thread cannot deadlock it.
     */
    private void resumeInterest(long event) {
        QuicPollItem item = getPollItem();
        if (item == null) {
            return;
        }
        if (endpoint.isPollThread()) {
            long current = item.getWantEvents();
            item.setWantEvents(current | event);
            return;
        }
        endpoint.submitPollTask(() -> {
            long current = item.getWantEvents();
            item.setWantEvents(current | event);
        });
    }


    /**
     * Returns the stream's poll item, which carries both read and write
     * interest (a single SSL_POLL_ITEM per stream, with R and W bits).
     */
    private QuicPollItem getPollItem() {
        QuicStreamWrapper stream = getSocket();
        return (stream != null) ? stream.getPollItem() : null;
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
        // the emulation below writes raw bytes straight onto the stream with
        // no DATA-frame framing, so enabling sendfile for a H3 wrapper
        // without adding framing here would corrupt the response body. The
        // guard is code, not just a comment: if reachability ever opens,
        // this reports an error instead of corrupting data, until the path
        // gains proper framing.
        if (log.isDebugEnabled()) {
            log.debug(sm.getString("socketWrapper.quicSendfileUnsupported"));
        }
        return SendfileState.ERROR;
    }


    /*
     * The raw-byte sendfile emulation kept for shape parity with the
     * quiche transport's copy. Not reachable while processSendfile() above
     * fails closed (see its guard); wire HTTP/3 DATA-frame framing into it
     * before making it reachable.
     */
    @SuppressWarnings("unused")
    private SendfileState processSendfileUnframed(SendfileDataBase sendfileData) {
        try {
            QuicStreamWrapper stream = liveStream();
            if (stream == null) {
                return SendfileState.ERROR;
            }
            java.io.RandomAccessFile raf = new java.io.RandomAccessFile(sendfileData.fileName, "r");
            try {
                raf.seek(sendfileData.pos);
                byte[] buf = new byte[65536];
                long remaining = sendfileData.length;
                while (remaining > 0) {
                    int toRead = (int) Math.min(remaining, buf.length);
                    int bytesRead = raf.read(buf, 0, toRead);
                    if (bytesRead <= 0) {
                        break;
                    }
                    // The HTTP/3 connector does not use sendfile (responses are
                    // framed as DATA frames by the processor), so this emulated
                    // path is defensive only. It writes raw bytes straight to
                    // the stream via doWrite() - no DATA-frame framing happens
                    // here - so it must not be used to emit an HTTP/3 message
                    // body directly.
                    // doWrite() is non-blocking and may write only part of the
                    // buffer (or nothing, re-arming write interest). Loop on the
                    // same buffer until it is fully consumed and advance the
                    // file offsets only by the bytes actually written so an
                    // interrupted sendfile resumes at the right offset.
                    ByteBuffer dataBuf = ByteBuffer.wrap(buf, 0, bytesRead);
                    long deadline = System.nanoTime() +
                            TimeUnit.MILLISECONDS.toNanos(STALL_TIMEOUT_MS);
                    boolean stalled = false;
                    while (dataBuf.hasRemaining()) {
                        int startPos = dataBuf.position();
                        doWrite(false, dataBuf);
                        int written = dataBuf.position() - startPos;
                        if (written > 0) {
                            sendfileData.pos += written;
                            remaining -= written;
                            sendfileData.length = remaining;
                            deadline = System.nanoTime() +
                                    TimeUnit.MILLISECONDS.toNanos(STALL_TIMEOUT_MS);
                        } else if (awaitWritable(deadline)) {
                            // No progress: doWrite() re-armed write interest.
                            // Park until the poll thread signals a write event
                            // (QUIC flow control recovered).
                        } else {
                            stalled = true;
                            break;
                        }
                    }
                    if (stalled) {
                        break;
                    }
                }
                flushNonBlocking();
                return remaining <= 0 ? SendfileState.DONE : SendfileState.PENDING;
            } finally {
                raf.close();
            }
        } catch (IOException | RuntimeException e) {
            // A container calling processSendfile() expects a SendfileState,
            // not an exception: a RuntimeException from doWrite() (invalid
            // buffer state, poll-thread failure) would otherwise propagate raw.
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("socketWrapper.quicSendfileError"), e);
            }
            return SendfileState.ERROR;
        }
    }


    /**
     * Sendfile data for QUIC streams. Since QUIC doesn't support kernel-level
     * zero-copy sendfile, it is emulated by reading from the file and writing
     * the bytes to the QUIC stream via {@code doWrite()}. The bytes are
     * written raw - no HTTP/3 DATA-frame framing happens here - so this path
     * is defensive only: the HTTP/3 connector disables sendfile and frames
     * response bodies as DATA frames in the processor.
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
            sslSupport = new QuicSSLSupport(this);
        }
        return sslSupport;
    }


    // ------------------------------------- Close

    /**
     * Closes the stream and releases the socket buffer handler. Contract
     * afterwards (the base class keeps the handler as a plain volatile field,
     * so releasing it here is deliberate, not a dangling half-state): read
     * entry points report an {@link java.io.EOFException} for the closed
     * stream (see {@link #checkNotClosed()}), write paths report the closed
     * stream through {@link #liveStream()}, and the interest/query paths
     * tolerate the null handler as the base class does. A dispatch racing
     * this close therefore sees "stream closed", never an NPE.
     */
    @Override
    protected void doClose() {
        try {
            QuicStreamWrapper stream = getSocket();
            if (stream != null) {
                // Remove the stream from the poll set and connection
                // bookkeeping and free its SSL via the endpoint. This must
                // run on the poll thread: the poll item must be removed and
                // the SSL freed between SSL_poll() calls, never while the
                // poll thread is inside SSL_poll().
                if (!endpoint.isPollThread()) {
                    onPollThreadVoid(() -> endpoint.closeStreamByHandler(stream));
                } else {
                    endpoint.closeStreamByHandler(stream);
                }
            }
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            // A close failure leaves native state behind; surface it
            // unconditionally rather than hiding it behind a debug guard.
            log.error(sm.getString("socketWrapper.quicCloseError"), t);
        } finally {
            // Release point of the documented post-close contract (above);
            // the read paths guard on it, the write paths never touch it.
            socketBufferHandler = null;
        }
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
                        // overlaps this loop; and
                        // flushNonBlocking() - called from the worker-side
                        // dispatch re-arm and sendfile - takes writeLock,
                        // which this loop does not hold and which therefore
                        // cannot exclude it, but reaches doWrite() only
                        // through staged residue (socketBufferHandler write
                        // buffer / nonBlockingWriteBuffer), which a
                        // contract-conforming producer has already drained
                        // before issuing a vectored write. Note when
                        // touching either wrapper: doWrite() mutates per-
                        // wrapper write state that every other writer holds
                        // under writeLock - relaxing either precondition
                        // would let this unsynchronised loop race that
                        // state. The quiche twin (QuicheSocketWrapper's
                        // QuicOperationState) states the same rule with the
                        // same preconditions; keep the two in step.
                        for (int i = 0; i < length; i++) {
                            int start = buffers[offset + i].position();
                            doWrite(false, buffers[offset + i]);
                            nBytes += buffers[offset + i].position() - start;
                            if (buffers[offset + i].hasRemaining()) {
                                // Non-blocking would-block (flow control / full
                                // send buffer): the remainder of this buffer is
                                // still queued in front of the later buffers, so
                                // stop here. Writing buffers[i+1] now would
                                // append its bytes to the stream ahead of the
                                // undelivered remainder and corrupt the byte
                                // order. doWrite() has re-armed write interest;
                                // the completion handler reports the partial
                                // transfer and the caller resumes later.
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
     * SSLSupport implementation for QUIC streams.
     */
    private static class QuicSSLSupport implements SSLSupport {
        private final QuicOpenSSLSocketWrapper wrapper;


        private QuicSSLSupport(QuicOpenSSLSocketWrapper wrapper) {
            this.wrapper = wrapper;
        }


        /**
         * The underlying stream.
         */
        private QuicStreamWrapper stream() {
            return wrapper.getQuicStream();
        }


        /**
         * The connection whose cache holds the connection-level SSL values.
         * Cipher suite, session id and peer certificates are per-connection,
         * so they are cached on the connection wrapper and shared by every
         * stream wrapper of the connection rather than resolved per stream.
         */
        private QuicConnectionWrapper connection() {
            QuicStreamWrapper s = stream();
            return s == null ? null : s.getConnection();
        }


        @Override
        public String getCipherSuite() throws IOException {
            QuicConnectionWrapper conn = connection();
            if (conn != null) {
                String cached = conn.getCachedCipherSuite();
                if (cached != null) {
                    return cached;
                }
            }
            try {
                return wrapper.onPollThread(() -> {
                    // The cipher suite is negotiated on the connection's
                    // SSL; OpenSSL QUIC allocates a separate SSL per
                    // stream and those stream SSL objects carry no cipher
                    // or session, so the connection-level handle must be
                    // used here.
                    QuicConnectionWrapper c = connection();
                    if (c == null) {
                        return null;
                    }
                    MemorySegment ssl = c.getSsl();
                    if (ssl.equals(MemorySegment.NULL)) {
                        return null;
                    }
                    MemorySegment cipher = openssl_h.SSL_get_current_cipher(ssl);
                    if (cipher.equals(MemorySegment.NULL)) {
                        return null;
                    }
                    String name = openssl_h.SSL_CIPHER_get_name(cipher).getString(0);
                    c.setCachedCipherSuite(name);
                    return name;
                });
            } catch (IOException ioe) {
                return null;
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to read the QUIC cipher suite", t);
                }
                return null;
            }
        }


        @Override
        public java.security.cert.X509Certificate[] getPeerCertificateChain() throws IOException {
            QuicConnectionWrapper conn = connection();
            if (conn != null && conn.isPeerCertsResolved()) {
                return conn.getCachedPeerCerts();
            }
            try {
                return wrapper.onPollThread(() -> {
                    try {
                        // The peer certificate chain belongs to the
                        // connection's SSL, not the per-stream SSL
                        // (see getCipherSuite()).
                        QuicConnectionWrapper c = connection();
                        if (c == null) {
                            return null;
                        }
                        MemorySegment ssl = c.getSsl();
                        if (ssl.equals(MemorySegment.NULL)) {
                            return null;
                        }
                        MemorySegment chain = openssl_h.SSL_get_peer_cert_chain(ssl);
                        int count = chain.equals(MemorySegment.NULL)
                                ? 0 : openssl_h.OPENSSL_sk_num(chain);
                        java.security.cert.CertificateFactory cf =
                                java.security.cert.CertificateFactory.getInstance("X.509");
                        // OPENSSL_sk_value can return NULL and i2d_X509 can
                        // fail; collecting the resolved certificates into a
                        // list (rather than a fixed-count array) keeps the
                        // returned chain free of null holes that would NPE
                        // callers iterating it. A missing or empty chain
                        // (typical when the peer sends only its leaf) still
                        // falls through to the leaf handling below.
                        java.util.List<java.security.cert.X509Certificate> certs =
                                new java.util.ArrayList<>(count + 1);
                        try (Arena localArena = Arena.ofConfined()) {
                            if (!chain.equals(MemorySegment.NULL)) {
                                for (int i = 0; i < count; i++) {
                                    MemorySegment x509 = openssl_h.OPENSSL_sk_value(chain, i);
                                    if (x509.equals(MemorySegment.NULL)) {
                                        log.warn(sm.getString(
                                                "socketWrapper.quicPeerCertSkipped", "NULL"));
                                        continue;
                                    }
                                    // i2d_X509 serializes to DER; out pointer receives buffer address
                                    MemorySegment outPtr = localArena.allocate(ValueLayout.ADDRESS);
                                    outPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);
                                    int derLen = openssl_h.i2d_X509(x509, outPtr);
                                    if (derLen <= 0) {
                                        log.warn(sm.getString(
                                                "socketWrapper.quicPeerCertSkipped", "i2d_X509"));
                                        continue;
                                    }
                                    MemorySegment derBuf = outPtr.get(ValueLayout.ADDRESS, 0);
                                    try {
                                        byte[] derBytes = new byte[derLen];
                                        derBuf.reinterpret(derLen).asByteBuffer().get(derBytes);
                                        certs.add((java.security.cert.X509Certificate) cf.generateCertificate(
                                                new java.io.ByteArrayInputStream(derBytes)));
                                    } finally {
                                        // Free the DER buffer allocated by i2d_X509 even
                                        // if the certificate parsing failed
                                        openssl_h.CRYPTO_free(derBuf, MemorySegment.NULL, 0);
                                    }
                                }
                            }
                            // The endpoint is always the TLS server, and
                            // SSL_get_peer_cert_chain() may not carry the
                            // peer's leaf on the server side (mirrors the
                            // socket OpenSSLEngine.getPeerCertificates()
                            // handling; see SSL_get_peer_cert_chain(3)).
                            // SSL_get0_peer_certificate borrows the leaf -
                            // no free needed - and the instance need not be
                            // the stack's first element even when equal, so
                            // compare by encoding.
                            MemorySegment leaf = openssl_h.SSL_get0_peer_certificate(ssl);
                            if (!leaf.equals(MemorySegment.NULL)) {
                                MemorySegment leafOutPtr = localArena.allocate(ValueLayout.ADDRESS);
                                leafOutPtr.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);
                                int leafLen = openssl_h.i2d_X509(leaf, leafOutPtr);
                                if (leafLen > 0) {
                                    MemorySegment leafBuf = leafOutPtr.get(ValueLayout.ADDRESS, 0);
                                    try {
                                        byte[] leafDer = new byte[leafLen];
                                        leafBuf.reinterpret(leafLen).asByteBuffer().get(leafDer);
                                        java.security.cert.X509Certificate leafCert =
                                                (java.security.cert.X509Certificate) cf.generateCertificate(
                                                        new java.io.ByteArrayInputStream(leafDer));
                                        boolean present = !certs.isEmpty() &&
                                                java.util.Arrays.equals(leafCert.getEncoded(),
                                                        certs.get(0).getEncoded());
                                        if (!present) {
                                            certs.add(0, leafCert);
                                        }
                                    } finally {
                                        openssl_h.CRYPTO_free(leafBuf, MemorySegment.NULL, 0);
                                    }
                                }
                            }
                        }
                        java.security.cert.X509Certificate[] result =
                                certs.toArray(new java.security.cert.X509Certificate[0]);
                        conn.setCachedPeerCerts(result);
                        return result;
                    } catch (Throwable t) {
                        // Cache the failure so i2d_X509 is not re-run on
                        // every request
                        if (log.isDebugEnabled()) {
                            log.debug("Failed to read the QUIC peer certificate chain", t);
                        }
                        return null;
                    } finally {
                        if (conn != null) {
                            conn.setPeerCertsResolved(true);
                        }
                    }
                });
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to hop the QUIC peer certificate read to the poll thread", t);
                }
                if (conn != null) {
                    conn.setPeerCertsResolved(true);
                }
                return null;
            }
        }


        @Override
        public String getSessionId() throws IOException {
            QuicConnectionWrapper conn = connection();
            if (conn != null) {
                String cached = conn.getCachedSessionId();
                if (cached != null) {
                    return cached;
                }
            }
            try {
                return wrapper.onPollThread(() -> {
                    // The session is held by the connection's SSL, not the
                    // per-stream SSL (see getCipherSuite()).
                    QuicConnectionWrapper c = connection();
                    if (c == null) {
                        return null;
                    }
                    MemorySegment ssl = c.getSsl();
                    if (ssl.equals(MemorySegment.NULL)) {
                        return null;
                    }
                    MemorySegment session = openssl_h.SSL_get_session(ssl);
                    if (session.equals(MemorySegment.NULL)) {
                        return null;
                    }
                    try (Arena localArena = Arena.ofConfined()) {
                        MemorySegment lenPtr = localArena.allocate(ValueLayout.JAVA_INT);
                        lenPtr.set(ValueLayout.JAVA_INT, 0, 0);
                        MemorySegment id = openssl_h.SSL_SESSION_get_id(session, lenPtr);
                        if (id.equals(MemorySegment.NULL)) {
                            return null;
                        }
                        int len = lenPtr.get(ValueLayout.JAVA_INT, 0);
                        if (len == 0) {
                            c.setCachedSessionId("");
                            return "";
                        }
                        byte[] sessionIdBytes = new byte[len];
                        id.reinterpret(len).asByteBuffer().get(sessionIdBytes);
                        String sessionId = bytesToHex(sessionIdBytes);
                        c.setCachedSessionId(sessionId);
                        return sessionId;
                    }
                });
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to read the QUIC session id", t);
                }
                return null;
            }
        }


        @Override
        public String getProtocol() throws IOException {
            try {
                String version = wrapper.onPollThread(() -> {
                    // Use the connection's SSL: cipher suite, session and
                    // the negotiated version are connection-level (see
                    // getCipherSuite()).
                    QuicConnectionWrapper c = connection();
                    if (c != null) {
                        MemorySegment ssl = c.getSsl();
                        if (!ssl.equals(MemorySegment.NULL)) {
                            return openssl_h.SSL_get_version(ssl).getString(0);
                        }
                    }
                    return null;
                });
                if (version != null) {
                    // OpenSSL reports the pseudo-version "QUICv1" for the
                    // SSL objects of a QUIC connection. QUIC runs on TLS
                    // 1.3 exclusively (RFC 9001 Section 4.2: TLS 1.3 is
                    // the only permitted version), so report the TLS
                    // version the application semantics are about.
                    if ("QUICv1".equals(version)) {
                        return "TLSv1.3";
                    }
                    return version;
                }
            } catch (Throwable t) {
                // Fall through
            }
            return "QUIC";
        }


        @Override
        public String getRequestedProtocols() throws IOException {
            // Deliberate deviation from the interface contract ("the list of
            // SSL/TLS protocol versions requested by the client"): QUIC hides
            // the TLS handshake from the application, so the protocol the
            // client actually requested at the level that matters here is the
            // ALPN one (e.g. "h3") - return the negotiated ALPN identifier,
            // matching what the quiche transport's QuicheSocketWrapper does.
            QuicConnectionWrapper conn = stream().getConnection();
            if (conn != null) {
                return conn.getNegotiatedProtocol();
            }
            return null;
        }


        @Override
        public String getRequestedCiphers() throws IOException {
            return null;
        }


        @Override
        public Integer getKeySize() throws IOException {
            // Key size not available in current OpenSSL bindings
            return null;
        }


        private static final java.util.HexFormat HEX = java.util.HexFormat.of();

        private static String bytesToHex(byte[] bytes) {
            return HEX.formatHex(bytes);
        }
    }
}

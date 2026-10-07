/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.net.quic;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.res.StringManager;

/**
 * The QUIC-specific base of a stream socket wrapper.
 * <p>
 * Every QUIC socket wrapper extends this class, making the requirement that a
 * QUIC wrapper is a {@link SocketWrapperBase} explicit in the type hierarchy.
 * Application protocol code (HTTP/3 in practice) narrows its
 * {@code SocketWrapperBase} references to this class after an
 * {@code instanceof} check.
 * <p>
 * Beyond the abstract QUIC view declared here, this base carries the
 * machinery the transport implementations share: the event-driven wake-up of
 * threads blocked in synchronous reads and writes, the configured blocking
 * timeout resolution, the closed-stream guard and the stream address
 * population. The concrete transport implementation (OpenSSL and quiche each
 * provide one in a sub-package) supplies the native operations behind the
 * abstract methods; application protocol code must not reference those
 * transport packages.
 */
public abstract class QuicSocketWrapper extends SocketWrapperBase<QuicStream> {

    private static final StringManager sm = StringManager.getManager(QuicSocketWrapper.class);

    /**
     * How long a blocking operation waits for QUIC flow control to recover
     * before giving up when no per-connection timeout is configured. Also
     * bounds the emulated sendfile paths.
     */
    protected static final long STALL_TIMEOUT_MS = 30000;

    /**
     * Local address for this stream (inherited from the connection). Assigned
     * by the transport subclass constructor.
     */
    protected InetSocketAddress localAddress;

    /**
     * Remote address for this stream (inherited from the connection).
     * Assigned by the transport subclass constructor.
     */
    protected InetSocketAddress remoteAddress;

    /**
     * Event-driven wake-up for threads blocked in a synchronous read or
     * write on this stream. The transport's poll thread unparks the
     * registered worker when it observes stream readiness (or a terminal
     * state), replacing a fixed-interval retry loop. {@link LockSupport}
     * park/unpark is used rather than wait/notify so a signal racing the park
     * cannot be lost (an unpark that arrives before the park is stored as a
     * permit and the wake check re-validates it against the sequence
     * counter). At most one thread blocks per direction in practice (the
     * stream's processing flag serialises handlers); a second concurrent
     * waiter would simply fall back to waiting out the configured timeout.
     */
    private final AtomicReference<Thread> readWaiter = new AtomicReference<>();
    private final AtomicReference<Thread> writeWaiter = new AtomicReference<>();
    private final AtomicLong readWakeups = new AtomicLong();
    private final AtomicLong writeWakeups = new AtomicLong();


    /**
     * Creates a new socket wrapper for a QUIC stream.
     *
     * @param stream   The underlying QUIC stream
     * @param endpoint The owning QUIC endpoint
     */
    protected QuicSocketWrapper(QuicStream stream, AbstractEndpoint<QuicStream,?> endpoint) {
        super(stream, endpoint);
    }


    // ------------------------------------- Abstract QUIC view

    /**
     * Returns the QUIC stream this wrapper is bound to.
     *
     * @return The stream, or {@code null} if the wrapper is not bound to a
     *         stream
     */
    public abstract QuicStream getQuicStream();


    /**
     * Returns the QUIC connection the bound stream belongs to.
     *
     * @return The parent connection, or {@code null} if not set
     */
    public abstract QuicConnection getConnection();


    /**
     * Drives the transport state machine for the bound stream's connection:
     * processes any transport events that are due (expired timers, pending
     * acknowledgments, newly arrived datagrams). Call this before deciding
     * on end-of-stream or error reporting based on the stream state.
     */
    public abstract void pumpConnectionEvents();


    /**
     * One wait cycle for a worker thread blocked on a synchronous read of
     * this stream: drives the connection state machine once, arms read
     * interest and then blocks until the transport thread signals that the
     * stream became readable (or reached a terminal state), or until the
     * deadline passes or the thread is interrupted. This replaces a
     * fixed-interval retry loop: a stalled read costs no work on the
     * transport thread until an event actually occurs.
     *
     * @param deadlineNanos Absolute deadline from {@link System#nanoTime()}
     *
     * @return {@code true} if the caller should retry the read (a signal was
     *         received before the deadline), {@code false} to give up. When
     *         {@code false} is returned, read interest has been armed so the
     *         transport delivers a regular read event once data does arrive
     */
    public abstract boolean awaitReadableData(long deadlineNanos);


    /**
     * Returns whether the write side of the stream has been concluded (the
     * FIN has been sent).
     *
     * @return {@code true} if this stream has been concluded
     */
    public abstract boolean isStreamConcluded();


    /**
     * Concludes the stream by sending a FIN (stream-level close, RFC 9000
     * Section 2.4). No error code is transmitted; the peer sees a graceful
     * end of stream.
     *
     * @throws IOException If an I/O error occurs
     */
    public abstract void concludeStream() throws IOException;


    /**
     * Resets the stream with the given error code: the transport sends a
     * {@code RESET_STREAM} frame (RFC 9000 Section 2.4). Unlike
     * {@link #concludeStream()} this aborts the stream and informs the peer
     * of the error code.
     *
     * @param appErrorCode The application protocol error code carried in the
     *                     {@code RESET_STREAM} frame
     *
     * @return {@code true} if the reset took effect
     *
     * @throws IOException If an I/O error occurs
     */
    public abstract boolean resetStream(long appErrorCode) throws IOException;


    // ------------------------------------- Addresses

    /**
     * Returns the local address.
     *
     * @return The local address
     */
    public InetSocketAddress getLocalAddress() {
        return localAddress;
    }


    /**
     * Returns the remote address. The value is captured when the connection
     * was accepted and does not track QUIC connection migration (RFC 9000
     * Section 9): a client that migrates to a new address keeps reporting the
     * address the connection was accepted from. Whether migration is
     * supported at all depends on the transport.
     *
     * @return The remote address
     */
    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }


    @Override
    protected void populateRemoteAddr() {
        if (remoteAddress != null) {
            remoteAddr = remoteAddress.getAddress() != null ?
                    remoteAddress.getAddress().getHostAddress() : remoteAddress.getHostString();
        }
    }


    @Override
    protected void populateRemoteHost() {
        if (remoteAddress != null) {
            remoteHost = remoteAddress.getHostName();
        }
    }


    @Override
    protected void populateRemotePort() {
        if (remoteAddress != null) {
            remotePort = remoteAddress.getPort();
        }
    }


    @Override
    protected void populateLocalName() {
        if (localAddress != null) {
            localName = localAddress.getHostName();
        }
    }


    @Override
    protected void populateLocalAddr() {
        if (localAddress != null) {
            localAddr = localAddress.getAddress() != null ?
                    localAddress.getAddress().getHostAddress() : localAddress.getHostString();
        }
    }


    @Override
    protected void populateLocalPort() {
        if (localAddress != null) {
            localPort = localAddress.getPort();
        }
    }


    // ------------------------------------- Blocking I/O wake-up

    /**
     * Whether a worker is currently parked waiting for this stream to become
     * readable. Queried by the transport's poll loop: while a waiter is
     * registered the corresponding interest must stay armed across
     * dispatches, so a signal that races the waiter's registration cannot be
     * lost.
     *
     * @return {@code true} if a read wait is in progress
     */
    public boolean hasReadWaiter() {
        return readWaiter.get() != null;
    }


    /**
     * Whether a worker is currently parked waiting for this stream to become
     * writable. See {@link #hasReadWaiter()}.
     *
     * @return {@code true} if a write wait is in progress
     */
    public boolean hasWriteWaiter() {
        return writeWaiter.get() != null;
    }


    /**
     * Wakes a worker parked in {@link #awaitReadableData(long)}. Called by
     * the transport's poll thread on a read event for this stream and on
     * every terminal stream/connection state change. Safe to call with no
     * waiter present.
     */
    public void signalReadWaiter() {
        readWakeups.incrementAndGet();
        unparkWaiter(readWaiter);
    }


    /**
     * Wakes a worker parked in the transport's write wait. Called by the
     * transport's poll thread on a write event for this stream and on every
     * terminal stream/connection state change. Safe to call with no waiter
     * present.
     */
    public void signalWriteWaiter() {
        writeWakeups.incrementAndGet();
        unparkWaiter(writeWaiter);
    }


    /**
     * The read waiter slot. Subclass wait implementations register the
     * waiting thread here (the base contract: register before driving the
     * state machine, clear with {@code compareAndSet} in a finally block).
     *
     * @return The read waiter slot
     */
    protected AtomicReference<Thread> readWaiter() {
        return readWaiter;
    }


    /**
     * The write waiter slot. See {@link #readWaiter()}.
     *
     * @return The write waiter slot
     */
    protected AtomicReference<Thread> writeWaiter() {
        return writeWaiter;
    }


    /**
     * The read wake-up sequence counter. Subclasses read it as the baseline
     * before registering and compare against it via {@link
     * #awaitWakeRemaining(AtomicReference, AtomicLong, long, long)}.
     *
     * @return The read wake-up counter
     */
    protected AtomicLong readWakeups() {
        return readWakeups;
    }


    /**
     * The write wake-up sequence counter. See {@link #readWakeups()}.
     *
     * @return The write wake-up counter
     */
    protected AtomicLong writeWakeups() {
        return writeWakeups;
    }


    /**
     * Wakes the thread registered in the given waiter slot, if any. Safe to
     * call with no waiter present.
     *
     * @param waiter The waiter slot
     */
    protected static void unparkWaiter(AtomicReference<Thread> waiter) {
        Thread t = waiter.get();
        if (t != null) {
            LockSupport.unpark(t);
        }
    }


    /**
     * Park loop shared by the transports' read and write waits: the waiter
     * slot and sequence baseline are already established by the caller
     * (which registers before driving the state machine so a signal racing
     * that drive cannot be lost).
     *
     * @param waiter        The waiter slot the caller registered on
     * @param wakeups       The wake-up counter paired with {@code waiter}
     * @param seq           The counter value read before registering
     * @param deadlineNanos Absolute deadline from {@link System#nanoTime()}
     *
     * @return {@code true} if a signal arrived before the deadline and the
     *         caller was not interrupted
     */
    protected boolean awaitWakeRemaining(AtomicReference<Thread> waiter, AtomicLong wakeups,
            long seq, long deadlineNanos) {
        Thread self = Thread.currentThread();
        // Re-check after registering and driving the state machine: the drive
        // can itself make the stream readable, and the poll thread may have
        // signalled at any point between the caller's sequence read and its
        // registration.
        if (wakeups.get() == seq) {
            long remaining = deadlineNanos - System.nanoTime();
            while (wakeups.get() == seq && remaining > 0 && !self.isInterrupted()) {
                LockSupport.parkNanos(remaining);
                remaining = deadlineNanos - System.nanoTime();
            }
        }
        return wakeups.get() != seq && !self.isInterrupted();
    }


    /**
     * Fallback wait for a caller that is itself the transport's poll thread
     * and therefore cannot be signalled by the poll loop (inline processing
     * during shutdown): a fixed-interval pause, bounded by the deadline.
     *
     * @param deadlineNanos Absolute deadline from {@link System#nanoTime()}
     *
     * @return {@code true} if the deadline has not passed and the pause was
     *         not interrupted
     */
    protected boolean pauseBriefly(long deadlineNanos) {
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
        return System.nanoTime() < deadlineNanos;
    }


    // ------------------------------------- Blocking timeouts

    /**
     * Configured blocking timeout for reads, in milliseconds: the per-stream
     * read timeout (wired from the connector's connection timeout at wrapper
     * creation, like the NIO endpoints) when set, otherwise the historical
     * hard-coded stall bound. A blocking read never waits indefinitely: a
     * stalled peer must not be able to pin a worker thread forever.
     *
     * @return The timeout in milliseconds
     */
    protected long blockingReadTimeoutMs() {
        long configured = getReadTimeout();
        return configured > 0 ? configured : STALL_TIMEOUT_MS;
    }


    /**
     * Configured blocking timeout for writes, in milliseconds. See
     * {@link #blockingReadTimeoutMs()}.
     *
     * @return The timeout in milliseconds
     */
    protected long blockingWriteTimeoutMs() {
        long configured = getWriteTimeout();
        return configured > 0 ? configured : STALL_TIMEOUT_MS;
    }


    // ------------------------------------- Closed-stream guard

    /**
     * doClose() releases the socket buffer handler. A late read must report
     * the closed stream, not an NPE from the buffer access paths.
     *
     * @throws EOFException If the wrapper has been closed
     */
    protected void checkNotClosed() throws EOFException {
        if (socketBufferHandler == null) {
            throw new EOFException(sm.getString("socketWrapper.quicStreamClosed"));
        }
    }
}

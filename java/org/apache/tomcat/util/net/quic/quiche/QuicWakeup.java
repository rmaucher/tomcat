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

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.res.StringManager;

/**
 * The quiche endpoint poll loop's blocking wait primitive.
 * <p>
 * quiche has no blocking poll entry point of its own: the loop must wait
 * until the UDP socket has a datagram, a worker thread queues native work on
 * the endpoint mailbox, or the earliest quiche timer expires. This class
 * performs that wait with a single {@code poll(2)} over {UDP socket fd,
 * eventfd counter}, with the timer expiry supplied as the poll timeout. Any
 * thread can make the poll loop run immediately by calling {@link #kick()},
 * which is what the mailbox does for every queued poll task.
 * <p>
 * This is a deliberate duplicate of the
 * {@code org.apache.tomcat.util.net.quic.openssl.QuicWakeup} primitive
 * (the OpenSSL original cannot be shared: it lives in an FFM-gated transport
 * package and its libc downcalls route through the OpenSSL bindings, whose
 * initialization requires libssl). It keeps the same public surface, but its
 * libc downcalls are served by {@link QuicheBindings} so a machine running
 * only the quiche endpoint never needs libssl.
 * <p>
 * {@link #kick()} may be called from any thread. {@link #await(long)},
 * {@link #consumeWake()} and {@link #close()} are called only from the poll
 * thread (close also from the stop path after the poll loop has stopped).
 */
final class QuicWakeup {

    private static final Log log = LogFactory.getLog(QuicWakeup.class);
    private static final StringManager sm =
            StringManager.getManager(QuicheEndpoint.class);

    // poll(2) constants (Linux ABI values)
    private static final short POLLIN = 0x0001;
    private static final short POLLERR = 0x0008;
    private static final short POLLHUP = 0x0010;
    private static final short POLLNVAL = 0x0020;
    private static final int EINTR = 4;

    /** The kick eventfd counter became readable. */
    static final int EVENT_WAKE = 1;
    /** The UDP socket became readable (a QUIC packet may be pending). */
    static final int EVENT_SOCK = 2;

    // struct pollfd { int fd; short events; short revents; }
    private static final MemoryLayout POLLFD_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("fd"),
            ValueLayout.JAVA_SHORT.withName("events"),
            ValueLayout.JAVA_SHORT.withName("revents")).withName("pollfd");
    private static final long POLLFD_SIZE = POLLFD_LAYOUT.byteSize();
    private static final long REVENTS_OFFSET =
            POLLFD_LAYOUT.byteOffset(PathElement.groupElement("revents"));

    /**
     * Index of the UDP socket entry in the native pollfd array.
     */
    private static final int SLOT_SOCK = 0;
    /**
     * Index of the wake eventfd entry in the native pollfd array.
     */
    private static final int SLOT_WAKE = 1;

    private final Arena arena;
    private final int wakeFd;
    private final MemorySegment pollfds;
    /**
     * Shared 8-byte scratch holding the value written to / read from the
     * eventfd counter. Every kick writes the same constant, so concurrent
     * {@link #kick()} calls from different threads do not race on content.
     */
    private final MemorySegment counter;

    /**
     * Set by {@link #close()} so a racing {@link #kick()} (whose caller read
     * the mailbox waker reference before it was nulled) becomes a no-op
     * instead of touching the released arena. The volatile read is only the
     * fast path of {@link #kick()}; the authoritative check runs under the
     * instance monitor that {@link #close()} also holds while it releases the
     * eventfd, closing the check-then-write window against fd-number reuse.
     */
    private volatile boolean closed;


    /**
     * Creates the wake primitive for the given UDP socket.
     *
     * @param socketFd The endpoint's UDP socket file descriptor
     *
     * @throws IOException If the eventfd cannot be created
     */
    QuicWakeup(int socketFd) throws IOException {
        this.arena = Arena.ofShared();
        int fd = QuicheBindings.eventfd(0,
                QuicheBindings.EFD_NONBLOCK | QuicheBindings.EFD_CLOEXEC);
        if (fd < 0) {
            arena.close();
            throw new IOException(sm.getString("quicheEndpoint.wakeupCreateError"));
        }
        this.wakeFd = fd;
        this.pollfds = arena.allocate(POLLFD_LAYOUT, 2);
        pollfds.set(ValueLayout.JAVA_INT, SLOT_SOCK * POLLFD_SIZE, socketFd);
        pollfds.set(ValueLayout.JAVA_SHORT,
                SLOT_SOCK * POLLFD_SIZE + 4, POLLIN);
        pollfds.set(ValueLayout.JAVA_INT, SLOT_WAKE * POLLFD_SIZE, wakeFd);
        pollfds.set(ValueLayout.JAVA_SHORT,
                SLOT_WAKE * POLLFD_SIZE + 4, POLLIN);
        this.counter = arena.allocate(ValueLayout.JAVA_LONG);
        counter.set(ValueLayout.JAVA_LONG, 0, 1L);
    }


    /**
     * Signals the poll loop that mailbox work has been queued. Safe to call
     * from any thread, including racing {@link #close()}: the flag check and
     * the write are performed under the monitor close() also takes, so a kick
     * can never issue its {@code write(2)} after the eventfd descriptor has
     * been released (fd numbers are reused, so writing a stale one could land
     * 8 bytes on an unrelated file). The downcall itself stays guarded
     * because the {@code counter} segment belongs to the shared arena that
     * close() releases - touching it after close makes the FFM layer throw on
     * the <em>caller</em> thread, e.g. an executor worker inside
     * {@code submitPollTask}.
     */
    void kick() {
        // Fast path: stay out of the monitor once the loop has stopped.
        if (closed) {
            return;
        }
        synchronized (this) {
            // Re-check: close() may have run between the fast-path read and
            // taking the monitor.
            if (closed) {
                return;
            }
            try {
                QuicheBindings.write(wakeFd, counter, Long.BYTES);
            } catch (Throwable t) {
                // Defensive: the fd should be open while the monitor is held,
                // but a failed wake is meaningless anyway (the loop may have
                // stopped by the time it would be observed); keep it out of
                // the caller.
                ExceptionUtils.handleThrowable(t);
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("quicheEndpoint.wakeupKickFailed"), t);
                }
            }
        }
    }


    /**
     * Waits for the UDP socket to become readable, for a {@link #kick()}, or
     * for the timeout to expire. Retries transparently on {@code EINTR}
     * (thread interrupt / signal) with the remaining time.
     *
     * @param timeoutMs Maximum time to wait; {@code 0} returns immediately.
     *        A negative value requests a wait without a deadline (served by
     *        the {@code -1} timeout of {@code poll(2)}); that form is a
     *        supported part of this primitive's contract but is currently
     *        unexercised - the only caller computes its wait in
     *        {@code [0, WAIT_CAP_MS]} and never passes a negative value
     *        (keep its {@code computeWait()} bounds in mind before relying
     *        on the infinite form, whose code path is not covered by the
     *        current callers)
     *
     * @return A bitmask of {@link #EVENT_WAKE} and {@link #EVENT_SOCK};
     *         {@code 0} means the wait timed out, a negative value means the
     *         wait failed (the caller should treat the iteration as
     *         no-progress and back off, so a persistent failure does not
     *         spin the CPU).
     */
    int await(long timeoutMs) {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        while (true) {
            long remainingMs = 0;
            boolean finite = timeoutMs >= 0;
            if (finite) {
                remainingMs = (deadline - System.nanoTime() + 999_999) / 1_000_000;
                if (remainingMs > Integer.MAX_VALUE) {
                    remainingMs = Integer.MAX_VALUE;
                } else if (remainingMs < 0) {
                    // Deadline already gone (a deschedule between the EINTR
                    // deadline check and this recomputation can overshoot it).
                    // A negative value passed to poll() would mean infinite
                    // wait; report the timeout instead.
                    return 0;
                }
            }
            int rc = QuicheBindings.poll(pollfds, 2, finite ? (int) remainingMs : -1);
            if (rc < 0) {
                // errno_location() returns an unbounded zero-length segment
                // (ADDRESS without a target layout); read through the helper
                // that reinterprets it.
                int err = QuicheBindings.errno();
                if (err == EINTR) {
                    if (!finite) {
                        continue;
                    }
                    if (System.nanoTime() - deadline >= 0) {
                        return 0;
                    }
                    continue;
                }
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("quicheEndpoint.wakeupPollError",
                            Integer.valueOf(err)));
                }
                return -1;
            }
            if (invalid(SLOT_WAKE) || invalid(SLOT_SOCK)) {
                // POLLNVAL: a descriptor is not (or no longer) open, so it
                // can never deliver a real event. Reporting it as ready
                // would keep the loop spinning at full rate on a phantom
                // wake; surface it as a wait failure so the caller backs
                // off instead.
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("quicheEndpoint.wakeupPollFdInvalid",
                            invalid(SLOT_WAKE) ? "wake" : "socket"));
                }
                return -1;
            }
            int events = 0;
            if (ready(SLOT_WAKE)) {
                events |= EVENT_WAKE;
            }
            if (ready(SLOT_SOCK)) {
                events |= EVENT_SOCK;
            }
            return events;
        }
    }


    /**
     * Drains the eventfd counter. Called by the poll loop at the top of every
     * iteration, BEFORE the mailbox is drained, so a kick queued while the
     * drain runs still leaves the counter set and the next
     * {@link #await(long)} returns immediately.
     */
    void consumeWake() {
        QuicheBindings.read(wakeFd, counter, Long.BYTES);
    }


    /**
     * Releases the eventfd and the native scratch memory. Must be called
     * only once the poll loop has stopped.
     */
    synchronized void close() {
        // Serialize with kick(): holding the monitor across the flag set and
        // the fd close means no kick can be mid-write when the descriptor is
        // released (a kick waiting for the monitor re-checks the flag and
        // returns). The arena close waits for any segment acquisition that
        // predates the monitor; none can be in flight once it is held, so it
        // does not block here.
        closed = true;
        try {
            QuicheBindings.close(wakeFd);
        } finally {
            try {
                arena.close();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("quicheEndpoint.wakeupCloseError"), t);
                }
            }
        }
    }


    /*
     * POLLNVAL: the fd is not open. Never delivers a usable event - the
     * caller surfaces it as a wait failure (see await()).
     */
    private boolean invalid(int slot) {
        short revents = pollfds.get(ValueLayout.JAVA_SHORT,
                slot * POLLFD_SIZE + REVENTS_OFFSET);
        return (revents & POLLNVAL) != 0;
    }


    /*
     * Ready for a read pass. POLLERR/POLLHUP are treated as readable on
     * purpose: for both fds the subsequent read (recvmsg on the socket,
     * read on the eventfd) surfaces the error condition to the loop's
     * existing error handling, which is the standard way to learn of them
     * - suppressing the wake here would hide the failure behind the
     * timeout instead.
     */
    private boolean ready(int slot) {
        short revents = pollfds.get(ValueLayout.JAVA_SHORT,
                slot * POLLFD_SIZE + REVENTS_OFFSET);
        if ((revents & (POLLERR | POLLHUP)) != 0) {
            return true;
        }
        return (revents & POLLIN) != 0;
    }
}

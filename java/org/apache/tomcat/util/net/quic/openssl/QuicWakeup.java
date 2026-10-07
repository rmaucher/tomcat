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

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;

/**
 * The endpoint poll loop's blocking wait primitive.
 * <p>
 * {@code SSL_poll()} blocks only on the QUIC sockets it was given; it has no
 * external wake hook (per {@code SSL_poll(3)} and the OpenSSL 4.0
 * implementation, foreign file descriptors are rejected outright). A worker
 * thread that queues a native hop on the endpoint's mailbox therefore cannot
 * interrupt an in-flight {@code SSL_poll()}, and every such hop would wait
 * out the remainder of the poll interval - the source of the fixed-interval
 * hop quantization.
 * <p>
 * This class restores the missing wake-up: the poll loop waits here on the
 * UDP socket and an {@code eventfd()} counter together via {@code poll(2)},
 * and calls {@code SSL_poll()} in non-blocking mode (timeout zero,
 * {@code SSL_POLL_FLAG_NO_HANDLE_EVENTS} - the loop drives the engine
 * explicitly with its own single {@code SSL_handle_events()} tick) whenever
 * the wait returns. Any thread can then make the poll loop run immediately
 * by calling {@link #kick()}, which is what the mailbox does for every
 * queued poll task. The wait also bounds itself with a caller-supplied
 * timeout so QUIC timer-driven processing still advances at the configured
 * cadence even with no packets and no kicks.
 * <p>
 * {@link #kick()} may be called from any thread. {@link #await(long)},
 * {@link #consumeWake()} and {@link #close()} are called only from the poll
 * thread (close also from the stop path after the poll loop has stopped).
 */
final class QuicWakeup {

    private static final Log log = LogFactory.getLog(QuicWakeup.class);
    private static final StringManager sm =
            StringManager.getManager(QuicOpenSSLEndpoint.class);

    // poll(2) / eventfd(2) constants (Linux ABI values)
    private static final short POLLIN = 0x0001;
    private static final short POLLERR = 0x0008;
    private static final short POLLHUP = 0x0010;
    private static final short POLLNVAL = 0x0020;
    private static final int EINTR = 4;
    // EFD_NONBLOCK == O_NONBLOCK (04000 octal), EFD_CLOEXEC == O_CLOEXEC
    // (02000000 octal) in the Linux ABI.
    private static final int EFD_NONBLOCK = 0x800;
    private static final int EFD_CLOEXEC = 0x80000;

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
    private static final long EVENTS_OFFSET =
            POLLFD_LAYOUT.byteOffset(PathElement.groupElement("events"));
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
    /**
     * Set by {@link #close()} under {@code this} (which also guards
     * {@link #kick()}) once the wake FD has been closed, so a kick racing
     * with the close either writes before the descriptor goes away or sees
     * the flag and skips the write. Without the guard, a submitter that read
     * a not-yet-nulled waker could write the FD number after the close, in
     * the window where the kernel has already handed the number to a newer
     * socket - a spurious wakeup on an unrelated endpoint.
     */
    private boolean closed;
    private final MemorySegment pollfds;
    /**
     * Shared 8-byte scratch holding the value written to / read from the
     * eventfd counter. Every kick writes the same constant, so concurrent
     * {@link #kick()} calls from different threads do not race on content.
     */
    private final MemorySegment counter;


    /**
     * Creates the wake primitive for the given UDP socket.
     *
     * @param socketFd The endpoint's UDP socket file descriptor
     *
     * @throws IOException If the eventfd cannot be created
     */
    QuicWakeup(int socketFd) throws IOException {
        this.arena = Arena.ofShared();
        int fd = QuicBindings.eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (fd < 0) {
            arena.close();
            throw new IOException(sm.getString("quicEndpoint.wakeupCreateError"));
        }
        this.wakeFd = fd;
        this.pollfds = arena.allocate(POLLFD_LAYOUT, 2);
        pollfds.set(ValueLayout.JAVA_INT, SLOT_SOCK * POLLFD_SIZE, socketFd);
        pollfds.set(ValueLayout.JAVA_SHORT,
                SLOT_SOCK * POLLFD_SIZE + EVENTS_OFFSET, POLLIN);
        pollfds.set(ValueLayout.JAVA_INT, SLOT_WAKE * POLLFD_SIZE, wakeFd);
        pollfds.set(ValueLayout.JAVA_SHORT,
                SLOT_WAKE * POLLFD_SIZE + EVENTS_OFFSET, POLLIN);
        this.counter = arena.allocate(ValueLayout.JAVA_LONG);
        counter.set(ValueLayout.JAVA_LONG, 0, 1L);
    }


    /**
     * Signals the poll loop that mailbox work has been queued. Safe to call
     * from any thread, including after {@link #close()}: the monitor makes
     * the check of the closed flag and the write atomic against the close, so
     * a late kick is a no-op rather than a write to a possibly-recycled
     * descriptor number (the task itself is already queued and the shutdown
     * drain will execute it without a kick).
     */
    void kick() {
        synchronized (this) {
            if (closed) {
                return;
            }
            QuicBindings.write(wakeFd, counter, Long.BYTES);
        }
    }


    /**
     * Waits for the UDP socket to become readable, for a {@link #kick()}, or
     * for the timeout to expire. Retries transparently on {@code EINTR}
     * (thread interrupt / signal) with the remaining time.
     *
     * @param timeoutMs Maximum time to wait; {@code 0} returns immediately
     *
     * @return A bitmask of {@link #EVENT_WAKE} and {@link #EVENT_SOCK};
     *         {@code 0} means the wait timed out, a negative value means the
     *         wait failed - either {@code poll(2)} itself failed or a poll
     *         entry reported {@code POLLERR}/{@code POLLHUP}/{@code POLLNVAL}
     *         without readable data (the caller should treat the iteration as
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
            int rc = QuicBindings.poll(pollfds, 2, finite ? (int) remainingMs : -1);
            if (rc < 0) {
                // Read errno through the helper that reinterprets the
                // returned pointer to an int-sized view (the pointer already
                // carries the openssl_h.C_POINTER target layout, so the
                // reinterpret is bound-limiting, not a prerequisite).
                int err = QuicBindings.errno();
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
                    log.debug(sm.getString("quicEndpoint.wakeupPollError",
                            Integer.valueOf(err)));
                }
                return -1;
            }
            int events = 0;
            short wakeRevents = revents(SLOT_WAKE);
            short sockRevents = revents(SLOT_SOCK);
            if ((wakeRevents & POLLIN) != 0) {
                events |= EVENT_WAKE;
            }
            if ((sockRevents & POLLIN) != 0) {
                events |= EVENT_SOCK;
            }
            if (events == 0 &&
                    ((wakeRevents | sockRevents) & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                // An error condition without readable data. Reporting it as
                // ready would make poll(2) return immediately on every
                // iteration and the poll loop would spin at full rate;
                // reporting it as a failed wait instead makes the caller
                // back off with a bounded sleep while still ticking the
                // engine, so a readable socket (POLLIN also set on a UDP
                // socket that received an ICMP error) is never lost and a
                // broken descriptor fails explicitly instead of hot-looping.
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("quicEndpoint.wakeupErrorEvents",
                            Integer.valueOf(wakeRevents & 0xFFFF),
                            Integer.valueOf(sockRevents & 0xFFFF)));
                }
                return -1;
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
        QuicBindings.read(wakeFd, counter, Long.BYTES);
    }


    /**
     * Releases the eventfd and the native scratch memory. Must be called
     * only once the poll loop has stopped. Concurrent {@link #kick()} calls
     * either completed before the closed flag was set (the write happened
     * while the descriptor was still ours) or observe it and skip the write.
     */
    void close() {
        synchronized (this) {
            closed = true;
            try {
                QuicBindings.close(wakeFd);
            } finally {
                try {
                    arena.close();
                } catch (Throwable t) {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("quicEndpoint.wakeupCloseError"), t);
                    }
                }
            }
        }
    }


    private short revents(int slot) {
        return pollfds.get(ValueLayout.JAVA_SHORT,
                slot * POLLFD_SIZE + REVENTS_OFFSET);
    }
}

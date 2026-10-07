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
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SSLContext;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SocketBufferHandler;
import org.apache.tomcat.util.net.SocketEvent;
import org.apache.tomcat.util.net.SocketProcessorBase;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.net.openssl.panama.CertificateLoader;
import org.apache.tomcat.util.net.openssl.panama.OpenSSLContext;
import org.apache.tomcat.util.net.openssl.panama.OpenSSLLibrary;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicEndpoint;
import org.apache.tomcat.util.net.quic.QuicProtocol;
import org.apache.tomcat.util.net.quic.QuicSSLContext;
import org.apache.tomcat.util.net.quic.QuicStream;
import org.apache.tomcat.util.openssl.openssl_h;
import org.apache.tomcat.util.res.StringManager;
import org.apache.tomcat.util.threads.LimitLatch;

/**
 * QUIC endpoint implementation using OpenSSL 4.x QUIC APIs via Java FFM
 * (Panama). OpenSSL 3.5 is not a supported target: the directional
 * {@code SSL_accept_stream()} filters used here (see {@link QuicPoll}), the
 * engine-shared reactor tick model and the {@code SSL_CTX_ctrl}-based
 * servername callback are 4.x behaviour.
 * <p>
 * Follows the OpenSSL poll-server reference pattern:
 * <ul>
 * <li>Creates a UDP socket via native socket() syscall</li>
 * <li>Creates an OpenSSL QUIC listener via SSL_new_listener()</li>
 * <li>Attaches the socket FD to the listener via SSL_set_fd()</li>
 * <li>Openssl manages all I/O internally through its own datagram BIO</li>
 * <li>Uses SSL_poll() with BIO_POLL_DESCRIPTOR_TYPE_SSL for event discovery</li>
 * <li>Uses SSL_read_ex()/SSL_write_ex2() for stream I/O</li>
 * </ul>
 * <p>
 * This endpoint is server-authentication TLS 1.3 only: it never requests a
 * client certificate, so a host configured with
 * {@code certificateVerification="want"/"required"} (or a trust store) is
 * served as a plain server-auth connection. The configuration build warns
 * once per affected host ({@code quicEndpoint.clientAuthUnsupported}) rather
 * than dropping the setting silently, matching the quiche transport.
 */
public class QuicOpenSSLEndpoint extends QuicEndpoint<Long> {

    private static final Log log = LogFactory.getLog(QuicOpenSSLEndpoint.class);
    /**
     * StringManager for this endpoint's package, backing the
     * {@code quicEndpoint.*} messages.
     */
    protected static final StringManager sm = StringManager.getManager(QuicOpenSSLEndpoint.class);

    /**
     * The StringManager of the base endpoint class, used to access the
     * shared {@code endpoint.*} messages.
     */
    private static final StringManager baseSm = StringManager.getManager(AbstractEndpoint.class);

    /**
     * Default read buffer size for QUIC streams.
     */
    private static final int DEFAULT_READ_BUFFER_SIZE = 16384;
    private static final int MIN_READ_BUFFER_SIZE = 1;

    /**
     * Default poll timeout in milliseconds.
     */
    private static final long DEFAULT_POLL_TIMEOUT_MS = 10;
    // A zero timeout makes SSL_poll() non-blocking (100 % CPU busy loop) and a
    // negative one makes it block indefinitely (NULL timeval), so both are
    // rejected. The upper bound keeps a misconfiguration from stalling every
    // connection on the endpoint.
    private static final long MIN_POLL_TIMEOUT_MS = 1;
    private static final long MAX_POLL_TIMEOUT_MS = 60_000;
    // Cap passed to the native SSL_poll(): a large configured poll timeout
    // would block the poll thread for that long inside the native call with no
    // way to observe the stop flag, defeating the bounded shutdown join. The
    // loop re-iterates (and re-checks the stop flag) for the remainder.
    private static final long NATIVE_POLL_TIMEOUT_CAP_MS = 1000;

    // Timeout used while poll tasks are queued (late worker hops, bounded
    // dispatch retries): short, so a queued task is picked up on the next
    // loop iteration instead of after a full poll interval. Mailbox
    // submissions also kick the QuicWakeup, so this bound only applies to
    // work that was already queued when the wait began.
    private static final long PENDING_TASK_POLL_TIMEOUT_MS = 10;

    // Timeout used when the endpoint has no connections and no queued work.
    // Every SSL_poll() call carries a fixed per-call cost (OpenSSL ticks each
    // poll item), so a constant 10 ms cadence on an idle endpoint burns a
    // measurable share of a core (measured: ~9 % at the default timeout with
    // zero connections) for work that cannot exist. Idle iterations use the
    // same value as the native poll cap: an incoming packet wakes the socket
    // poll immediately (the poll thread waits on the UDP socket in
    // QuicWakeup), so accept latency is unchanged, and the wait is further
    // capped by the earliest QUIC timer deadline reported by
    // SSL_get_event_timeout for any polled SSL object, so timer-driven
    // events are not delayed either. The value stays within the bound the
    // shutdown join in stopInternal() is already budgeted for (the native
    // poll cap).
    private static final long IDLE_POLL_TIMEOUT_MS = NATIVE_POLL_TIMEOUT_CAP_MS;

    // Due-tick coalescing. The engine's merged tick deadline chatters at
    // sub-10 ms intervals even when every connection is idle (per-channel
    // ACKM ack-flush deadlines), and each tick costs O(channels) on the
    // poll thread. The floor coalesces those deadline-driven ticks: after
    // one due tick, the next one is held back until the floor has passed,
    // with the floor growing adaptively (only while due ticks keep firing
    // without any other wake source) and resetting to zero on every packet,
    // hop or queued free, so genuine reactive work always runs at full
    // speed. The first due tick after any activity always runs immediately.
    private static final long DEFAULT_DUE_TICK_FLOOR_CAP_MS = 50;
    // Initial (and reset) floor. Doubles up to dueTickFloorCapMs while due
    // ticks keep firing without progress: one 20 ms hold-back, then 40, 50.
    private static final long DUE_TICK_FLOOR_BASE_MS = 20;

    /**
     * Default maximum number of concurrent connections.
     */
    private static final int DEFAULT_MAX_CONNECTIONS = 8192;

    // ------------------------------------- Retry / budget constants
    // Bounded-loop budgets. Each caps a spin or retry so a stalled or
    // not-yet-ready state cannot occupy the poll thread or busy-loop
    // indefinitely; they are not wired to SocketProperties tuning.

    /**
     * Times the QUIC state machine is driven after queueing a CONNECTION_CLOSE,
     * to give the frame a bounded number of chances to reach the socket before
     * the connection SSL is freed.
     */
    private static final int CONNECTION_CLOSE_FLUSH_ATTEMPTS = 5;

    /**
     * Error code with which a connection whose negotiated ALPN protocol is not
     * served must be closed: the TLS {@code no_application_protocol} alert
     * (120, RFC 7301) prefixed with {@code 0x100} as RFC 9001 Section 4.8
     * defines for alert-derived codes, giving {@code 0x0178} as required by RFC
     * 9001 Section 8.1. OpenSSL's {@code SSL_shutdown_ex()} can only carry the
     * code in an application CONNECTION_CLOSE (it exposes no transport-error
     * close), so the frame conveys {@code 0x0178} in the application error
     * field; the client then learns of the rejection immediately instead of
     * timing out.
     */
    private static final long NO_APPLICATION_PROTOCOL_ERROR = 0x100 + 120;

    /**
     * Upper bound on the connection drain performed at endpoint stop after
     * the GOAWAY notification: while request handlers are still active the
     * stop thread keeps running worker hop tasks and driving each live
     * connection so the GOAWAY frames and final response bytes reach the
     * peers before the connections are closed. Bounded so a wedged handler
     * cannot stall the stop beyond this delay.
     */
    private static final long GRACEFUL_SHUTDOWN_DRAIN_MS = 500;

    /**
     * Upper bound on the wait for request handlers that are still running
     * when the endpoint stops, performed after the executor shutdown before
     * the connection and stream native objects are released. Handlers that
     * still own native state after this wait are retained (leaked) rather
     * than freed under them.
     */
    private static final long ACTIVE_HANDLER_SHUTDOWN_WAIT_MS = 1000;

    /**
     * Maximum SSL_read_ex calls made while draining a stream into the read
     * buffer in one go, bounding a single burst so a continuously-readable
     * stream cannot starve the poll loop of the other connections.
     */
    private static final int READ_DRAIN_MAX_ATTEMPTS = 20;

    /**
     * Maximum write attempts for a server unidirectional stream write made
     * directly on the poll thread (the eager init-data write, the post-accept
     * buffered retry and the stream limit notification) before falling back
     * to the buffered W-event retry path. Measured against a normal request
     * workload (664 calls): 62 calls succeeded outright, 1 on the second
     * attempt, and the rest could not progress at all within the loop -
     * they only complete once the client's next packets arrive, which is
     * the W-event flush's job. Three attempts is the useful budget: one
     * engine tick to let freshly-arrived crypto/credit state through, one
     * flush attempt behind it, one more for the interleaved case. Each
     * attempt is a full-engine tick, so a larger bound would multiply the
     * O(fleet) tick cost per accepted stream for no effect.
     */
    private static final int STREAM_WRITE_RETRY_ATTEMPTS = 3;

    /**
     * Attempts made to land a RESET_STREAM before giving up: a single
     * SSL_stream_reset() can be rejected until the stream's send part becomes
     * resettable, which a state-machine pump may take a few iterations to
     * reach. See {@link #resetStream(QuicStreamWrapper, long)}.
     */
    private static final int RESET_STREAM_ATTEMPTS = 8;

    /**
     * The idle timeout OpenSSL applies when a
     * {@code SSL_VALUE_QUIC_IDLE_TIMEOUT} feature request is rejected because
     * the connection's transport parameters were already generated (30 s).
     * Used to detect when the fallback is visible (a non-default configured
     * timeout silently becoming 30 s).
     */
    private static final long OPENSSL_DEFAULT_IDLE_TIMEOUT_MS = 30000;

    // Ensures the visible-idle-timeout-fallback warning is emitted at most
    // once per endpoint (it reflects a configuration/reach-timing condition,
    // not a per-connection fault, so repeating it per connection is noise).
    private final AtomicBoolean idleTimeoutFallbackWarned = new AtomicBoolean(false);

    // Same once-per-endpoint pattern for the warning that the transport
    // refuses the EXPLICIT event-handling mode (see
    // configureExplicitEventHandling): a library-version condition, not a
    // per-connection fault.
    private final AtomicBoolean eventHandlingModeWarned = new AtomicBoolean(false);

    // ------------------------------------- Instance fields

    /**
     * The address this endpoint is bound to.
     */
    private volatile InetSocketAddress bindAddress;

    /**
     * Owns the TLS side of the endpoint: the native SSL_CTX, the ALPN and SNI
     * callbacks installed on it, the current certificate snapshot and the
     * callback arenas. The endpoint delegates all certificate lifecycle to it
     * and reads the native SSL_CTX from it when creating the listener and
     * reporting TLS information.
     */
    private final QuicCertificateManager certManager = new QuicCertificateManager(
            this::getName, this::getQuicProtocol, this::resolveHostConfigForSni);

    // Listener error (EL) reporting state: EL is level-triggered, so
    // rate-limit the log and escalate once it proves persistent.
    private long listenerErrorCount = 0;
    private long lastListenerErrorLog = 0;
    private static final long LISTENER_ERROR_LOG_INTERVAL_MS = 60_000;
    private static final long LISTENER_ERROR_PERSISTENT_COUNT = 1000;

    // Poll failure (SSL_POLL_EVENT_F) reporting state: a failing listener
    // item is retained (it cannot be dropped without killing the endpoint)
    // and OpenSSL re-raises F for an unhandled failing item on every
    // SSL_poll() call, so the warning and the error-queue dump are
    // rate-limited the same way the listener EL reporting above is;
    // otherwise a persistent listener failure floods the log at the
    // poll-loop rate.
    private long pollFailureCount = 0;
    private long lastPollFailureLog = 0;
    private static final long POLL_FAILURE_LOG_INTERVAL_MS = 60_000;

    // Set once the transport/application stream-limit mismatch has been
    // reported, so the (level-triggered per-connection) warning logs once per
    // endpoint rather than once per connection.
    private volatile boolean streamLimitMismatchWarned = false;

    /**
     * The SSL* listener object.
     */
    private MemorySegment listener = MemorySegment.NULL;

    /**
     * The socket file descriptor (created by native socket() call).
     */
    private int socketFd = -1;

    /**
     * Poll set for SSL_poll.
     */
    private QuicPollSet pollSet;

    /**
     * Map of connection SSL address to connection wrapper. The entries are
     * also the retention that keeps a wrapper strongly reachable while its
     * native SSL is still live: like the stream Cleaner, the connection
     * Cleaner hands its free request to the poll thread's mailbox queue
     * (QuicConnectionWrapper.DeferredConnectionFree) rather than freeing on
     * the GC thread, but reaching that queue means the wrapper dropped out
     * of this map, so every {@code connections.remove(...)} /
     * {@code connections.clear()} must still stay at a terminal point where
     * the streams are already freed or deferred and the connection SSL free
     * is immediate or claimed (see the comments at those sites) - dropping
     * the entry earlier would let the Cleaner free the connection while a
     * live stream still references it.
     */
    private final ConcurrentHashMap<Long, QuicConnectionWrapper> connections =
            new ConcurrentHashMap<>();

    /**
     * Map of stream SSL address to socket wrapper.
     */
    private final ConcurrentHashMap<Long, QuicOpenSSLSocketWrapper> streamWrappers =
            new ConcurrentHashMap<>();

    /**
     * Connections a request handler still owned when {@link #stopInternal()}
     * released the rest of the endpoint. Their native SSL objects (and the
     * stream SSL objects still referenced by the wrapper) are not freed and
     * must not become phantom-reachable: the connection Cleaner frees the
     * connection SSL unconditionally once the wrapper is unreachable, which
     * would violate the streams-before-connection order of
     * {@code SSL_new_stream(3)} while a handler still runs. Holding them here
     * is the safe alternative to freeing them under a running handler. The
     * retained connections carry a pending-free claim, so the worker that
     * brings the active-handler count to zero completes the deferred free
     * (see {@link #finishStreamDispatch}) and drops the wrapper from this
     * set; a worker that finishes after the mailbox was closed has its free
     * task rejected/discarded, and {@link #startInternal()} completes such
     * pending frees on the start thread once the handler count reached zero,
     * so repeated stop/start cycles cannot grow the set without bound.
     */
    private final java.util.Set<QuicConnectionWrapper> stoppedBusyConnections =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    /**
     * Timestamp of the last log message for an SSL_poll usage error (see
     * {@link #pollLoop()}) so a persistent misconfiguration does not flood
     * the log.
     */
    private long lastPollUsageErrorLogMs;


    /**
     * Poll loop thread. Published across threads (the reload/unbind guards
     * read it from lifecycle and JMX threads), so it must be volatile: a
     * stale {@code null} seen by {@link #reloadCertificates} while the poll
     * loop is live would take the off-thread direct-install branch and touch
     * native state the poll thread is still using.
     */
    private volatile Thread pollThread;

    /**
     * Single owner of the queues that cross the poll-thread confinement
     * boundary (poll tasks, deferred stream frees and Cleaner free requests).
     * The confinement check it applies is the endpoint's own
     * {@link #assertNativeAccess(String)}.
     */
    private final QuicNativeMailbox mailbox =
            new QuicNativeMailbox(this::assertNativeAccess);

    /**
     * The poll thread's blocking wait primitive (UDP socket + mailbox kick
     * eventfd). Created in {@code bind()} once the UDP socket exists,
     * released with the bind resources.
     */
    private volatile QuicWakeup quicWakeup;

    /**
     * Number of connections with protocol data (QPACK decoder instructions)
     * pending flush. The poll loop runs the per-connection protocol-data
     * sweep only while this is positive, so an endpoint whose connections
     * all have nothing to flush pays nothing for the sweep.
     */
    private final AtomicInteger protocolDataPendingCount = new AtomicInteger();

    /**
     * Cross-thread companion of {@link #protocolDataPendingCount}: every
     * transition into the pending state marks its connection here (before
     * publishing the count, so a sweep that observes a positive count always
     * finds the mark). The poll loop consumes the queue into the confined
     * {@link #protocolDataConns} set and flushes only those connections,
     * turning the protocol-data sweep into O(pending connections) instead of
     * O(live connections) - the same naming trick the mailbox hops use,
     * which matters most when a large idle fleet coexists with traffic
     * (QPACK output on a few connections used to make every ticked
     * iteration walk the whole fleet).
     */
    private final ConcurrentLinkedQueue<QuicConnectionWrapper> protocolDataMarks =
            new ConcurrentLinkedQueue<>();

    /**
     * Poll-thread confined set of connections with protocol data to flush,
     * fed from {@link #protocolDataMarks} each sweep. Connections whose
     * flush could not drain their queue stay in the set for the next sweep;
     * everything else leaves it (drained flag, closed/freed teardown, null
     * connection manager), so the set tracks the live pending population.
     */
    private final Set<QuicConnectionWrapper> protocolDataConns = new HashSet<>();

    /**
     * Scratch swap set for the confined {@link #protocolDataConns} rebuild
     * (iteration over the set cannot add to it).
     */
    private final Set<QuicConnectionWrapper> protocolDataRetry = new HashSet<>();

    /**
     * Returns the queue used by the {@link QuicStreamWrapper} Cleaner to
     * request a stream SSL free on the poll thread.
     *
     * @return The cleaner stream free queue
     */
    ConcurrentLinkedQueue<QuicStreamWrapper.DeferredStreamFree> getCleanerStreamFrees() {
        return mailbox.getCleanerStreamFrees();
    }


    /**
     * Returns the queue used by the {@link QuicConnectionWrapper} Cleaner to
     * request a connection SSL free on the poll thread.
     *
     * @return The cleaner connection free queue
     */
    ConcurrentLinkedQueue<QuicConnectionWrapper.DeferredConnectionFree>
            getCleanerConnectionFrees() {
        return mailbox.getCleanerConnectionFrees();
    }


    /**
     * Drains the Cleaner's deferred stream SSL free requests. Each request's
     * free is guarded by the shared {@code freed} CAS, so it is a no-op for
     * streams already freed by any of the explicit close paths. The free is
     * NOT skipped when the owning connection is closing: per
     * SSL_new_stream(3) the stream SSL must be freed before the connection
     * SSL, and closeAllStreams() deliberately skips streams whose handler is
     * still running, so a closing connection can still be waiting on this
     * free (see QuicStreamWrapper.DeferredStreamFree).
     */
    private void drainCleanerStreamFrees() {
        mailbox.drainCleanerStreamFrees();
    }


    /**
     * Drains the Cleaner's deferred connection SSL free requests. Each
     * request's free is guarded by the shared {@code freed} CAS, so it is a
     * no-op for connections already freed by any of the teardown paths. Run
     * after the stream free drains: per SSL_new_stream(3) the stream SSLs
     * must be gone before the connection SSL (see
     * QuicConnectionWrapper.DeferredConnectionFree).
     */
    private void drainCleanerConnectionFrees() {
        mailbox.drainCleanerConnectionFrees();
    }

    /**
     * Frees the stream SSL objects whose free the close paths deferred to
     * run after {@code SSL_poll()} has flushed any pending frames.
     * {@code freeSslOnce()} is a no-op when the stream was already freed by
     * another path (shared freed CAS). Every stream SSL must be freed before
     * the connection SSL it holds a reference on (per SSL_new_stream(3)), so
     * the connection free paths drain this queue first.
     */
    private void drainPendingStreamFrees() {
        mailbox.drainPendingStreamFrees();
    }

    /**
     * Maximum concurrent connections.
     */
    private int maxConnections = DEFAULT_MAX_CONNECTIONS;

    /**
     * Last time (ms) the "maximum connections reached" warning was logged.
     * The warning is rate-limited because the capacity check can be reached on
     * every poll iteration while the listener has a pending incoming
     * connection.
     */
    private long lastMaxConnectionsLogMs = 0;

    /**
     * Last time (ms) the "endpoint paused" debug message was logged. Rate
     * limited for the same reason as the max-connections warning: the check
     * is reached on every poll iteration while a pending incoming connection
     * is queued on the level-triggered listener event.
     */
    private long lastPausedLogMs = 0;

    /**
     * Poll timeout in milliseconds used while the endpoint has connections or
     * queued work. Every poll-loop iteration carries a fixed native cost (OpenSSL
     * ticks every poll item inside {@code SSL_poll()}), so this value trades that
     * per-iteration cost against two latencies it bounds: the maximum wait for a
     * worker's queued native hop and the loop's responsiveness to the stop flag
     * (the native call caps it at {@link #NATIVE_POLL_TIMEOUT_CAP_MS} per call).
     * An idle endpoint (no connections, no queued work) ignores this value and
     * uses {@link #IDLE_POLL_TIMEOUT_MS} instead, so the per-iteration cost is
     * only paid while there is something to deliver.
     */
    private long pollTimeoutMs = DEFAULT_POLL_TIMEOUT_MS;

    /**
     * Read buffer size for streams.
     */
    private int readBufferSize = DEFAULT_READ_BUFFER_SIZE;

    /**
     * Upper bound for the adaptive due-tick floor; {@code 0} disables the
     * floor (due-deadline ticks run whenever the engine reports one due, the
     * exact-timer behaviour). See {@link #dueTickFloorCapMs}.
     */
    private long dueTickFloorCapMs = DEFAULT_DUE_TICK_FLOOR_CAP_MS;

    /**
     * Whether QUIC is available in the linked OpenSSL.
     */
    private static final boolean QUIC_AVAILABLE = QuicBindings.QUIC_AVAILABLE;


    /**
     * Creates the endpoint. Instances are created reflectively by
     * {@code org.apache.coyote.http3.Http3OpenSSLProtocol}, which requires a
     * public default constructor.
     */
    public QuicOpenSSLEndpoint() {
        // Configuration arrives via the property setters before bind()/start.
    }


    // ------------------------------------- Properties

    /**
     * Returns the configured maximum number of concurrent connections.
     *
     * @return The connection limit
     */
    public int getMaxConnections() {
        return maxConnections;
    }

    /**
     * Sets the maximum number of concurrent connections.
     *
     * @param maxConnections The connection limit
     */
    public void setMaxConnections(int maxConnections) {
        // Deliberately no super.setMaxConnections() call: the base
        // implementation couples the limit to the connection-limit latch,
        // which the QUIC endpoints must never initialize (see
        // initializeConnectionLatch() below). This endpoint does not run the
        // base acceptor infrastructure; enforcement is done against the
        // connections map in handleIncomingConnection() and the limit is
        // reported through the getMaxConnections() override above.
        this.maxConnections = maxConnections;
    }

    /**
     * {@inheritDoc}
     * <p>
     * The QUIC endpoints never create the base-class connection-limit latch
     * (see {@link #initializeConnectionLatch()}), so the base implementation
     * would always report {@code -1}. Report the live count from the
     * connections map instead: the same population the {@code maxConnections}
     * enforcement is measured against in handleIncomingConnection().
     */
    @Override
    public long getConnectionCount() {
        return connections.size();
    }

    /**
     * Never initialize the base-class connection-limit latch.
     * <p>
     * The latch models acceptor-based counting: one count up per accepted
     * socket (Acceptor / {@code countUpOrAwaitConnection()}) paired with one
     * count down per socket close. A QUIC endpoint has neither side of that
     * pair: no acceptor takes slots, while {@code SocketWrapperBase.close()}
     * calls {@code countDownConnection()} once per request stream wrapper -
     * many per connection, never matched by a count up. A latch created here
     * (setMaxConnections(), or a pause/resume cycle) would therefore only
     * ever be driven negative, logging a spurious incorrect-connection-count
     * warning per stream close and reporting a bogus negative count through
     * JMX. Connection slots are enforced against the connections map in
     * handleIncomingConnection() instead, and the accurate live count is
     * reported by {@link #getConnectionCount()}.
     *
     * @return {@code null} always: connection counting through the latch is
     *         disabled for this endpoint
     */
    @Override
    protected LimitLatch initializeConnectionLatch() {
        return null;
    }

    /**
     * Returns the idle-rate {@code SSL_poll()} timeout.
     *
     * @return The poll timeout in milliseconds
     */
    public long getPollTimeoutMs() {
        return pollTimeoutMs;
    }

    /**
     * Sets the idle-rate {@code SSL_poll()} timeout. A value outside
     * {@code [MIN_POLL_TIMEOUT_MS, MAX_POLL_TIMEOUT_MS]} is logged and
     * ignored.
     *
     * @param pollTimeoutMs The poll timeout in milliseconds
     */
    public void setPollTimeoutMs(long pollTimeoutMs) {
        if (pollTimeoutMs < MIN_POLL_TIMEOUT_MS || pollTimeoutMs > MAX_POLL_TIMEOUT_MS) {
            log.warn(sm.getString("quicEndpoint.pollTimeoutInvalid",
                    String.valueOf(pollTimeoutMs),
                    String.valueOf(MIN_POLL_TIMEOUT_MS),
                    String.valueOf(MAX_POLL_TIMEOUT_MS)));
            return;
        }
        this.pollTimeoutMs = pollTimeoutMs;
    }

    /**
     * Returns the floor applied to deadline-driven waits (see the due-tick
     * floor in {@code pollLoop()}).
     *
     * @return The due-tick floor in milliseconds
     */
    public long getDueTickFloorMs() {
        return dueTickFloorCapMs;
    }

    /**
     * Sets the floor applied to deadline-driven waits. A negative value or
     * one above {@code MAX_POLL_TIMEOUT_MS} is logged and ignored.
     *
     * @param dueTickFloorCapMs The due-tick floor in milliseconds
     */
    public void setDueTickFloorMs(long dueTickFloorCapMs) {
        if (dueTickFloorCapMs < 0 || dueTickFloorCapMs > MAX_POLL_TIMEOUT_MS) {
            log.warn(sm.getString("quicEndpoint.dueTickFloorInvalid",
                    String.valueOf(dueTickFloorCapMs),
                    String.valueOf(MAX_POLL_TIMEOUT_MS)));
            return;
        }
        this.dueTickFloorCapMs = dueTickFloorCapMs;
    }

    /**
     * Returns the per-stream read buffer size.
     *
     * @return The read buffer size in bytes
     */
    public int getReadBufferSize() {
        return readBufferSize;
    }

    /**
     * Sets the per-stream read buffer size. A value below
     * {@code MIN_READ_BUFFER_SIZE} is logged and ignored.
     *
     * @param readBufferSize The read buffer size in bytes
     */
    public void setReadBufferSize(int readBufferSize) {
        if (readBufferSize < MIN_READ_BUFFER_SIZE) {
            // A non-positive buffer is fatal for the stream paths that read
            // exclusively through it: drainStreamInto() would never progress
            // while the level-triggered R re-arm of client-initiated
            // unidirectional streams keeps firing, spinning the poll thread,
            // and ByteBuffer.allocate() would throw for negative values when
            // a stream is accepted. Warn and keep the current value.
            log.warn(sm.getString("quicEndpoint.readBufferSizeInvalid",
                    String.valueOf(readBufferSize),
                    String.valueOf(MIN_READ_BUFFER_SIZE),
                    String.valueOf(this.readBufferSize)));
            return;
        }
        this.readBufferSize = readBufferSize;
    }

    /**
     * Returns the endpoint's poll set. Exposed for the poll items created by
     * the connection and stream wrappers.
     *
     * @return The poll set
     */
    public QuicPollSet getPollSet() {
        return pollSet;
    }

    /**
     * Reports whether the linked OpenSSL provides QUIC support.
     *
     * @return {@code true} if OpenSSL QUIC is available
     */
    public static boolean isQuicAvailable() {
        return QUIC_AVAILABLE;
    }


    /**
     * Availability entry point, part of the convention any QUIC endpoint
     * implementation follows (used by the HTTP/3 test suite to decide
     * whether to skip). The quiche endpoint exposes the same method.
     *
     * @return {@code true} if the OpenSSL QUIC transport is usable
     */
    public static boolean isAvailable() {
        return isQuicAvailable();
    }


    // ------------------------------------- AbstractEndpoint overrides

    @Override
    public void bind() throws Exception {
        if (!QUIC_AVAILABLE) {
            throw new IllegalStateException(sm.getString("quicEndpoint.quicNotAvailable"));
        }

        // QUIC mandates TLS (RFC 9001) and the transport needs the native
        // SSL_CTX to exist first, so - unlike NioEndpoint, which opens the
        // server socket before calling initialiseSsl() - the SSL setup happens
        // here before the UDP socket is created. Cleanup on a failure is
        // delegated to unbind() (invoked by AbstractEndpoint.bindWithCleanup()
        // when bind() throws), mirroring NioEndpoint which has no bind-time
        // try/catch of its own.
        initialiseSsl();

        pollSet = new QuicPollSet();
        createUdpSocket();
        createListener();

        if (log.isInfoEnabled()) {
            log.info(sm.getString("quicEndpoint.bind", getName(),
                    bindAddress != null ? bindAddress.toString() : "0.0.0.0:0"));
        }
    }


    /**
     * Initialises the TLS side of the endpoint: the native QUIC {@code SSL_CTX}
     * with its ALPN and SNI callbacks, and the per-host certificate
     * configuration.
     * <p>
     * QUIC always runs over TLS 1.3 (RFC 9001): the SNI callback installs no
     * certificate when SSL is disabled, so every client handshake would fail.
     * A non-TLS configuration therefore cannot serve any connection; fail fast
     * rather than start a listener that can never complete a handshake. The
     * native {@code SSL_CTX} is created before
     * {@link AbstractEndpoint#initialiseSsl()} runs so the per-host
     * {@link #createSSLContext(SSLHostConfig)} can read the enabled ciphers
     * from it.
     *
     * @throws Exception If the TLS setup failed
     */
    @Override
    public void initialiseSsl() throws Exception {
        if (!isSSLEnabled()) {
            throw new IllegalStateException(sm.getString("quicEndpoint.tlsRequired"));
        }

        OpenSSLLibrary.initLibrary();

        // Fail fast if no default SSLHostConfig is configured
        getSSLHostConfig(null);
        QuicCertConfig initialConfig = buildCertConfig();
        if (initialConfig == null) {
            throw new IOException(sm.getString("quicEndpoint.certificateLoadFailed",
                    getDefaultSSLHostConfigName(), null));
        }

        // Install the initial certificate snapshot and create the native
        // SSL_CTX with its ALPN and SNI callbacks.
        certManager.initialize(initialConfig);

        // Populate the JMX / Manager TLS information (protocols, ciphers,
        // certificates) for every configured host. The base loop calls the
        // createSSLContext(SSLHostConfig) override, which reads the ciphers
        // from the native SSL_CTX created just above.
        super.initialiseSsl();
    }


    /**
     * Releases the native resources allocated by {@link #bind()} in reverse
     * order. Idempotent and safe to call when nothing (or only part) has been
     * allocated; used from {@link #unbind()}, which {@code AbstractEndpoint}
     * also calls when {@code bind()} fails, so a failed or partial bind can
     * always be reclaimed. The poll thread is not running at this point (bind
     * has not started it, or {@link #stopInternal()} has stopped it), so there
     * are no live connections or streams to free.
     */
    private void releaseBindResources() {
        // Free the listener first, then close the socket FD explicitly:
        // SSL_set_fd() attaches the datagram BIO with BIO_NOCLOSE
        // (openssl/ssl/ssl_lib.c), so SSL_free() does not close the FD.
        if (listener != null && !listener.equals(MemorySegment.NULL)) {
            try {
                openssl_h.SSL_free(listener);
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error freeing QUIC listener during bind cleanup", t);
                }
            }
            listener = MemorySegment.NULL;
        }
        // The listener never owns the FD (BIO_NOCLOSE), so close it here.
        if (socketFd >= 0) {
            QuicBindings.close(socketFd);
            socketFd = -1;
        }
        // Detach the mailbox waker so no further submission even reaches the
        // wake primitive. A submitter that already read the waker is covered
        // by QuicWakeup.close() itself: kick() and close() are serialized, so
        // a kick racing with the close is a no-op rather than a write to a
        // descriptor number the kernel may hand to a later socket (the task
        // itself is queued and the shutdown drain executes it without a
        // kick).
        mailbox.setWaker(null);
        QuicWakeup wakeup = quicWakeup;
        if (wakeup != null) {
            quicWakeup = null;
            try {
                wakeup.close();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error closing QUIC wakeup during bind cleanup", t);
                }
            }
        }
        // Release the native SSL_CTX, the current certificate snapshot and the
        // callback arenas. The SSL_CTX must go after the listener (freed above)
        // that was created from it, and before the poll set below; the arenas
        // are only referenced by callbacks installed on the SSL_CTX, which the
        // manager frees first, so releasing them here is safe.
        certManager.release();
        if (pollSet != null) {
            try {
                // Dispose any item structs still in the set (the listener item
                // added in createListener(), and any that a partial bind left
                // behind) before releasing the array arenas.
                pollSet.clear();
                pollSet.close();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error closing QUIC poll set during bind cleanup", t);
                }
            }
            pollSet = null;
        }
    }


    /**
     * Checks whether the given ALPN-negotiated protocol is one the
     * application protocol ({@link QuicProtocol#getAlpnIdentifiers()}) can
     * actually serve.
     *
     * @param negotiated The negotiated protocol name; may be {@code null}
     *                   when no protocol was negotiated
     *
     * @return {@code true} if the name is a supported identifier
     */
    private boolean isServedProtocol(String negotiated) {
        QuicProtocol protocol = getQuicProtocol();
        return protocol != null && protocol.isServedIdentifier(negotiated);
    }


    /**
     * Checks the negotiated application protocol before any stream of the
     * connection is served.
     * <p>
     * {@code SSL_accept_connection()} may return before the SNI and ALPN
     * callbacks have run, so the protocol cannot be checked reliably while the
     * connection is accepted. Once the poll loop reports a stream event, the
     * handshake is complete; the negotiated protocol is then verified here.
     * RFC 9114 Section 3 identifies HTTP/3 by the ALPN {@code h3} identifier:
     * a connection that negotiated no protocol, or one the application
     * protocol does not serve, must not have frames dispatched to the protocol -
     * tear it down instead, closing with the {@code no_application_protocol}
     * code ({@link #NO_APPLICATION_PROTOCOL_ERROR}) so the peer is notified
     * rather than timing out.
     *
     * @param conn The connection whose negotiated protocol should be checked
     *
     * @return {@code true} if the connection negotiated a served protocol,
     *         {@code false} if it was rejected and torn down
     */
    private boolean ensureServedProtocol(QuicConnectionWrapper conn) {
        if (conn == null || conn.isClosed() || conn.isFreed()) {
            return false;
        }
        if (conn.getNegotiatedProtocol() == null) {
            String alpn = readAlpnProtocol(conn.getSsl());
            if (alpn == null) {
                // Drive the connection once. Stream events are reported after
                // the handshake, but the ALPN callback may still have pending
                // work that needs to be run before the result can be read.
                pumpEvents(conn.getSsl());
                alpn = readAlpnProtocol(conn.getSsl());
            }
            if (alpn != null) {
                conn.setNegotiatedProtocol(alpn);
            }
        }

        String negotiated = conn.getNegotiatedProtocol();
        if (isServedProtocol(negotiated)) {
            return true;
        }

        log.warn(sm.getString("quicEndpoint.alpnNotServed",
                Long.toHexString(conn.getSslAddress()),
                String.valueOf(negotiated)));
        failConnection(conn, NO_APPLICATION_PROTOCOL_ERROR,
                "Negotiated application protocol is not served");
        return false;
    }


    /**
     * Loads all configured certificates into a new
     * {@link QuicCertConfig} via
     * {@link QuicCertConfig#buildCertConfig(SSLHostConfig, SSLHostConfig[])}.
     * A missing default host configuration is reported the same way as a
     * failed build (logged, {@code null} returned) so callers can decide how
     * fatal the failure is.
     *
     * @return the new certificate configuration, or {@code null} if it could
     *         not be built
     */
    private QuicCertConfig buildCertConfig() {
        try {
            return QuicCertConfig.buildCertConfig(getSSLHostConfig(null), findSslHostConfigs());
        } catch (Throwable t) {
            log.error(sm.getString("quicEndpoint.certificateBuildError"), t);
            return null;
        }
    }


    /**
     * Resolves an (already lower-cased) SNI host name to its
     * {@link SSLHostConfig} for the {@link QuicCertificateManager}'s SNI
     * callback, which cannot reach the base endpoint's protected resolution
     * directly. A name that resolves to no host (including the case of no
     * default host being configured, which the base resolution signals with
     * {@link IllegalStateException}) yields {@code null}, letting the callback
     * fall back to the default certificate.
     *
     * @param name The lower-cased SNI host name
     *
     * @return The resolved host configuration, or {@code null} if none
     */
    private SSLHostConfig resolveHostConfigForSni(String name) {
        try {
            return getSSLHostConfig(name);
        } catch (IllegalStateException e) {
            // No default host configured; fall through to null
            return null;
        }
    }


    // ------------------------------------- Certificate lifecycle

    /**
     * Logs the certificate configuration for the given host and records the
     * TLS information exposed via JMX (enabled protocols and ciphers).
     * Unlike the other endpoints this endpoint does not create a real
     * per-certificate SSLContext: the certificates are loaded natively by
     * {@link #buildCertConfig()} and applied per connection by the SNI
     * callback, so the TLS information is taken from the endpoint's native
     * SSL_CTX instead of a Java SSLUtil. QUIC mandates TLS 1.3 (RFC 9001);
     * the TLS 1.3 cipher suites are those of the context (certificate
     * selection does not constrain TLS 1.3 suite negotiation).
     * <p>
     * Consumers that read the certificate data through the certificate's
     * SSLContext (the Manager application, the certificate expiry checks)
     * are served by a {@link QuicSSLContext} reporting the configured
     * chain. An SSLContext provided directly (e.g. embedded) is left in
     * place; a context created here is replaced on reload so a rotated
     * certificate becomes visible.
     */
    @Override
    protected void createSSLContext(SSLHostConfig sslHostConfig) throws IllegalArgumentException {
        MemorySegment sslCtx = certManager.getSslCtx();
        if (!sslCtx.equals(MemorySegment.NULL)) {
            sslHostConfig.setEnabledProtocols(new String[] { "TLSv1.3" });
            String[] ciphers = OpenSSLContext.getCiphers(sslCtx);
            if (ciphers != null) {
                sslHostConfig.setEnabledCiphers(ciphers);
            }
        }
        for (SSLHostConfigCertificate certificate : sslHostConfig.getCertificates()) {
            SSLContext sslContext = certificate.getSslContext();
            if (sslContext == null || sslContext instanceof QuicSSLContext) {
                certificate.setSslContext(new QuicSSLContext(
                        CertificateLoader.getCertificateChain(certificate)));
            }
            logCertificate(certificate);
        }
    }


    /**
     * Adds an SSL host configuration and reloads the native certificate
     * configuration so the change is visible to new connections.
     */
    @Override
    public void addSslHostConfig(SSLHostConfig sslHostConfig, boolean replace)
            throws IllegalArgumentException {
        super.addSslHostConfig(sslHostConfig, replace);
        reloadCertificates("addSslHostConfig");
    }


    /**
     * Removes an SSL host configuration and reloads the native certificate
     * configuration so the removed host is no longer offered.
     */
    @Override
    public SSLHostConfig removeSslHostConfig(String hostName) {
        SSLHostConfig removed = super.removeSslHostConfig(hostName);
        if (removed != null) {
            reloadCertificates("removeSslHostConfig");
        }
        return removed;
    }


    /**
     * Reloads all SSL host configurations with a single rebuild of the
     * native certificate configuration (instead of one rebuild per host as
     * in the base implementation).
     */
    @Override
    public void reloadSslHostConfigs() {
        for (String hostName : sslHostConfigs.keySet()) {
            // Re-register each host (what the base class reload does: the
            // same in-memory SSLHostConfig through addSslHostConfig, which
            // refreshes the per-host TLS information) without triggering a
            // native rebuild for every host; the configuration files are
            // re-read by the single reloadCertificates() call below.
            SSLHostConfig sslHostConfig = sslHostConfigs.get(hostName.toLowerCase(Locale.ENGLISH));
            if (sslHostConfig == null) {
                throw new IllegalArgumentException(baseSm.getString("endpoint.unknownSslHostName", hostName));
            }
            super.addSslHostConfig(sslHostConfig, true);
        }
        reloadCertificates("reloadSslHostConfigs");
    }


    /**
     * Rebuilds the native certificate configuration from the current
     * {@link SSLHostConfig} set and swaps it into the
     * {@link QuicCertificateManager}. The swap happens on the poll thread so
     * it is serialized with the SNI callback (which applies certificates
     * during handshakes). A failed rebuild keeps the previous configuration.
     *
     * @param reason a short description of what triggered the reload, used
     *               for logging
     */
    private void reloadCertificates(String reason) {
        if (!isSSLEnabled()) {
            return;
        }
        if (getBindState() == BindState.UNBOUND) {
            // Not bound yet; bind() will build the configuration
            return;
        }
        QuicCertConfig newConfig = buildCertConfig();
        if (newConfig == null) {
            // Keep the previous configuration
            return;
        }
        if (pollThread != null && pollThread.isAlive()) {
            final QuicCertConfig toInstall = newConfig;
            if (!submitPollTask(() -> certManager.swapConfig(toInstall, reason))) {
                // The mailbox was closed between the liveness check and the
                // submission (the endpoint finished stopping): the swap will
                // never run. The configuration was never installed, so no
                // connection references it - release it here, pairing the
                // certificate free with the arena close as every other
                // discard site does (free() does not close the arena).
                toInstall.free();
                CertificateLoader.closeQuietly(toInstall.arena);
            }
        } else {
            // No running poll loop to serialize against (not started, or
            // already stopped): applying the swap here is safe for the same
            // reason the drain of the poll-thread queue is during stop.
            assertNativeAccess("swapCertConfig");
            certManager.swapConfig(newConfig, reason);
        }
    }


    private void createListener() throws Exception {
        // Create QUIC listener SSL object from the manager's native SSL_CTX
        listener = QuicBindings.SSL_new_listener(certManager.getSslCtx(), 0L);
        if (listener.equals(MemorySegment.NULL)) {
            throw new IOException(sm.getString("quicEndpoint.listenerCreateError"));
        }

        // Attach socket FD to listener - OpenSSL creates internal datagram BIO
        int rc = QuicBindings.SSL_set_fd(listener, socketFd);
        if (rc != 1) {
            throw new IOException(sm.getString("quicEndpoint.sslSetFdError", Integer.valueOf(rc)));
        }

        // Set the listener non-blocking. Child connection objects set their own
        // blocking mode when they are accepted (see handleIncomingConnection).
        int blockingRc = QuicBindings.SSL_set_blocking_mode(listener, 0);
        if (blockingRc != 1) {
            throw new IOException(sm.getString("quicEndpoint.sslSetBlockingModeError",
                    Integer.valueOf(blockingRc)));
        }

        // Initialize QUIC listener state
        int listenRc = QuicBindings.SSL_listen(listener);
        if (listenRc != 1) {
            throw new IOException(sm.getString("quicEndpoint.sslListenError", Integer.valueOf(listenRc)));
        }

        if (log.isDebugEnabled()) {
            log.debug("Created QUIC listener on FD " + socketFd + " (0x" +
                    Long.toHexString(listener.address()) + ")");
        }

     // Set up listener poll item
        QuicPollItem listenerItem = new QuicPollItem(listener,
                  -1L, // want_events: all bits set, so the listener receives every event type
                  null);
        pollSet.add(listenerItem);
    }


    /**
     * Creates the UDP socket, binds it and configures it (the socket FD is
     * kept in {@link #socketFd}; the attachment to the listener via
     * SSL_set_fd() is done separately by {@link #createListener()}, and
     * OpenSSL internally creates a datagram BIO for the socket FD).
     * Supports both IPv4 and IPv6; with no connector address configured it
     * binds the dual-stack wildcard ({@code ::} accepting IPv4 as well),
     * mirroring the NIO endpoints' default, and falls back to the IPv4
     * wildcard when the IPv6 family is unusable.
     */
    private void createUdpSocket() throws Exception {
        int port = getPortWithOffset();
        // Port -1 (Tomcat's ephemeral convention) or 0 means "assign any free
        // port". Use port 0 so the OS assigns one, then resolve the actual
        // port after bind() (mirrors NioEndpoint). Mapping to a well-known
        // port here would make two port=-1 connectors share UDP via
        // SO_REUSEPORT (split-brain).
        boolean ephemeralPort = port <= 0;
        if (ephemeralPort) {
            port = 0;
        }

        try (Arena localArena = Arena.ofConfined()) {
            InetAddress configuredAddr = getAddress();
            InetAddress bindAddr;
            int sockFd;
            if (configuredAddr != null) {
                // Explicit address: family taken from the address, V6ONLY
                // left at the system default (previous behaviour).
                bindAddr = configuredAddr;
                sockFd = bindUdpSocket(localArena, bindAddr, port, false);
            } else {
                // No configured address: mirror the NIO endpoints' default of
                // the dual-stack wildcard (:: with IPV6_V6ONLY=0, which also
                // accepts IPv4), falling back to the IPv4 wildcard when the
                // IPv6 family is unusable in this environment or when the
                // JVM prefers IPv4 (java.net.preferIPv4Stack, the same switch
                // the NIO bind honours).
                bindAddr = null;
                sockFd = -1;
                if (!Boolean.getBoolean("java.net.preferIPv4Stack")) {
                    try {
                        bindAddr = InetAddress.getByName("::");
                        sockFd = bindUdpSocket(localArena, bindAddr, port, true);
                    } catch (DualStackUnavailable e) {
                        if (log.isDebugEnabled()) {
                            log.debug("IPv6 wildcard bind unavailable, "
                                    + "falling back to IPv4: " + e.getMessage());
                        }
                        sockFd = -1;
                    }
                }
                if (sockFd < 0) {
                    bindAddr = InetAddress.getByName("0.0.0.0");
                    sockFd = bindUdpSocket(localArena, bindAddr, port, false);
                }
            }
            boolean isIPv6 = bindAddr instanceof java.net.Inet6Address;
            int addrlen = isIPv6 ? 28 : 16;

            // Publish the FD as soon as it is bound so any later setup
            // failure (non-blocking, listener creation) releases it through
            // releaseBindResources() instead of leaking it. Failures inside
            // bindUdpSocket() are not published: that method releases its fd
            // before throwing.
            this.socketFd = sockFd;

            // Set non-blocking
            int flags = QuicBindings.fcntl(sockFd, QuicBindings.F_GETFL, 0);
            int setFlResult = QuicBindings.fcntl(
                    sockFd, QuicBindings.F_SETFL, flags | QuicBindings.O_NONBLOCK);
            if (setFlResult != 0) {
                throw new IOException(sm.getString("quicEndpoint.fcntlError"));
            }

            // Wake primitive for the poll loop: the poll thread waits on
            // this socket together with an eventfd, and the mailbox kicks
            // that eventfd whenever another thread queues a poll task
            // (SSL_poll() itself cannot be woken from outside - see
            // QuicWakeup).
            quicWakeup = new QuicWakeup(sockFd);
            mailbox.setWaker(quicWakeup::kick);

            // Resolve the actually-assigned port for an ephemeral (port 0)
            // bind so bindAddress - and therefore getLocalAddress() /
            // getLocalPort(), which dispatch to the endpoint's overridden
            // bind address getter - reflects the real port. getPort() keeps
            // returning the configured port.
            int actualPort = port;
            if (ephemeralPort) {
                MemorySegment nameAddr = localArena.allocate(28);
                MemorySegment nameLen = localArena.allocate(4);
                nameLen.set(ValueLayout.JAVA_INT, 0, addrlen);
                int rcName = QuicBindings.getsockname(
                        sockFd, nameAddr, nameLen);
                if (rcName == 0) {
                    // Port is big-endian at offset 2 in both
                    // sockaddr_in and sockaddr_in6.
                    actualPort = ((nameAddr.get(ValueLayout.JAVA_BYTE, 2) & 0xFF) << 8)
                            | (nameAddr.get(ValueLayout.JAVA_BYTE, 3) & 0xFF);
                }
            }
            bindAddress = new InetSocketAddress(bindAddr, actualPort);

            if (log.isDebugEnabled()) {
                log.debug("Created UDP socket FD " + sockFd + " bound to " + bindAddress +
                        (isIPv6 ? " (IPv6)" : " (IPv4)"));
            }
        }
    }


    /**
     * Creates a UDP socket, arms the endpoint's socket options on it and
     * binds it to {@code bindAddr:port}. Every failure path closes the fd
     * before throwing, so the fd belongs to the caller only once this
     * method returns it.
     *
     * @param localArena  Arena for the bind/option scratch
     * @param bindAddr    The address to bind. Any IPv6 scope information
     *                    (a link-local {@code fe80::…%iface} obtained via
     *                    {@link java.net.Inet6Address#getNetworkInterface()})
     *                    is NOT translated: the raw bind below writes the
     *                    16 address bytes only and leaves
     *                    {@code sin6_scope_id} zero, which {@code java.net}
     *                    would fill from the scope. Binding an IPv6 wildcard
     *                    or a global address is unaffected; an explicit
     *                    link-local bind address is not honoured and the bind
     *                    fails (surfaced as the bind error it is) rather than
     *                    silently landing on the wrong interface.
     * @param port        The port to bind (already offset-mapped; {@code 0}
     *                    requests an ephemeral port)
     * @param dualStack   {@code true} to clear IPV6_V6ONLY before the bind so
     *                    an {@code ::} bind also accepts IPv4 (the NIO
     *                    endpoints' default); the option is immutable after
     *                    bind, so this has to be armed here
     *
     * @return The bound socket fd
     *
     * @throws DualStackUnavailable  The attempt failed for a reason that
     *         rules out only this address family (no IPv6 stack, IPv6
     *         administratively disabled, dual-stack mode refused) - the
     *         default-bind caller falls back to the IPv4 wildcard
     * @throws IOException  A genuine failure: socket(), a bind failure that
     *         is not family-related (port in use, no permission), or a
     *         refused socket option on an otherwise usable socket
     */
    private int bindUdpSocket(Arena localArena, InetAddress bindAddr, int port,
            boolean dualStack) throws DualStackUnavailable, IOException {
        boolean isIPv6 = bindAddr instanceof java.net.Inet6Address;
        int af = isIPv6 ? QuicBindings.AF_INET6 : QuicBindings.AF_INET;
        int sockFd = QuicBindings.socket(af, QuicBindings.SOCK_DGRAM, 0);
        if (sockFd < 0) {
            int errno = QuicBindings.errno();
            if (dualStack && errno == QuicBindings.EAFNOSUPPORT) {
                // No IPv6 stack at all (e.g. ipv6.disable=1): the IPv4
                // wildcard fallback covers this, it is not a bind failure.
                throw new DualStackUnavailable("socket(AF_INET6): "
                        + QuicBindings.strerror(errno));
            }
            throw new IOException(sm.getString("quicEndpoint.socketCreateNegativeFd",
                    Integer.valueOf(sockFd)));
        }
        try {
            // Neither SO_REUSEADDR nor SO_REUSEPORT is set, deliberately.
            // SO_REUSEPORT lets independent processes share a UDP unicast port
            // but Linux then load-balances datagrams across those sockets by
            // hash, so packets of one QUIC connection can be delivered to
            // different listener processes (e.g. during a rolling restart),
            // silently breaking connections. SO_REUSEADDR is omitted too: a
            // single listener restarts cleanly without it (UDP has no
            // TIME_WAIT state), yet on Linux it relaxes the UDP bind-conflict
            // rule to last-binder-wins - a second local process that also sets
            // the flag can bind this endpoint's address and port and then
            // receive the unicast datagrams addressed to it, a same-host
            // hijack. Staying on the default keeps the single-binder guarantee.

            // Receive/send buffer sizes. A single UDP socket carries every
            // connection of the endpoint, so bursts (an accept stampede, a
            // large response batch) can overflow the default OS buffer and
            // the resulting losses amplify into retransmits. Values come from
            // the connector's socket.rxBufSize/socket.txBufSize properties
            // (0 or unset keeps the OS default). Best effort: the kernel may
            // silently clamp the value to net.core.rmem_max/wmem_max, which
            // Linux does without an error.
            int rxBufSize = socketProperties.getRxBufSize();
            if (rxBufSize > 0) {
                MemorySegment rxBufVal = localArena.allocate(4);
                rxBufVal.set(ValueLayout.JAVA_INT, 0, rxBufSize);
                setOption(sockFd, QuicBindings.SOL_SOCKET, QuicBindings.SO_RCVBUF,
                        rxBufVal, "SO_RCVBUF");
            }
            int txBufSize = socketProperties.getTxBufSize();
            if (txBufSize > 0) {
                MemorySegment txBufVal = localArena.allocate(4);
                txBufVal.set(ValueLayout.JAVA_INT, 0, txBufSize);
                setOption(sockFd, QuicBindings.SOL_SOCKET, QuicBindings.SO_SNDBUF,
                        txBufVal, "SO_SNDBUF");
            }

            if (isIPv6 && dualStack) {
                // Clear V6ONLY before the bind: an :: bind then also accepts
                // IPv4 (the NIO endpoints' dual-stack default). If the kernel
                // refuses it, this socket cannot give the wildcard candidate
                // its whole purpose - defer to the IPv4 wildcard instead.
                MemorySegment zero = localArena.allocate(4);
                zero.set(ValueLayout.JAVA_INT, 0, 0);
                if (QuicBindings.setsockopt(sockFd, QuicBindings.IPPROTO_IPV6,
                        QuicBindings.IPV6_V6ONLY, zero, 4) != 0) {
                    throw new DualStackUnavailable("IPV6_V6ONLY: "
                            + QuicBindings.strerror(QuicBindings.errno()));
                }
            }

            MemorySegment sockaddr;
            int addrlen;
            if (isIPv6) {
                // sockaddr_in6: sin6_family(2) + sin6_port(2) + sin6_flowinfo(4) + sin6_addr(16) + sin6_scope_id(4) = 28 bytes
                sockaddr = localArena.allocate(28);
                // sin6_family uses the platform-native byte order (JAVA_SHORT
                // is native-endian), so the kernel reads the correct family
                // on big- as well as little-endian targets.
                sockaddr.set(ValueLayout.JAVA_SHORT, 0, (short) QuicBindings.AF_INET6);
                // sin6_port is network byte order on every platform: write
                // the bytes explicitly rather than via a short layout.
                sockaddr.set(ValueLayout.JAVA_BYTE, 2, (byte) (port >> 8));  // sin6_port MSB
                sockaddr.set(ValueLayout.JAVA_BYTE, 3, (byte) (port & 0xFF)); // sin6_port LSB
                // sin6_flowinfo at offset 4: zero
                byte[] addrBytes = bindAddr.getAddress();
                if (addrBytes != null && addrBytes.length == 16) {
                    for (int i = 0; i < 16; i++) {
                        sockaddr.set(ValueLayout.JAVA_BYTE, 8 + i, addrBytes[i]);
                    }
                }
                // sin6_scope_id at offset 24: left zero. The bindAddr scope
                // is not consulted (see the bindUdpSocket javadoc), so a
                // scoped link-local address cannot bind here; the bind fails
                // visibly instead of silently picking an interface.
                addrlen = 28;
            } else {
                // sockaddr_in: sin_family(2) + sin_port(2) + sin_addr(4) + sin_zero(8) = 16 bytes
                sockaddr = localArena.allocate(16);
                // sin_family: platform-native byte order (see above);
                // sin_port: explicit network byte order (see above).
                sockaddr.set(ValueLayout.JAVA_SHORT, 0, (short) QuicBindings.AF_INET);
                sockaddr.set(ValueLayout.JAVA_BYTE, 2, (byte) (port >> 8));  // sin_port MSB
                sockaddr.set(ValueLayout.JAVA_BYTE, 3, (byte) (port & 0xFF)); // sin_port LSB
                byte[] addrBytes = bindAddr.getAddress();
                if (addrBytes != null) {
                    for (int i = 0; i < Math.min(4, addrBytes.length); i++) {
                        sockaddr.set(ValueLayout.JAVA_BYTE, 4 + i, addrBytes[i]);
                    }
                }
                addrlen = 16;
            }

            int rc = QuicBindings.bind(sockFd, sockaddr, addrlen);
            if (rc != 0) {
                int errno = QuicBindings.errno();
                String errmsg = QuicBindings.strerror(errno);
                if (dualStack && (errno == QuicBindings.EAFNOSUPPORT ||
                        errno == QuicBindings.EADDRNOTAVAIL ||
                        errno == QuicBindings.EPERM)) {
                    // The IPv6 family itself cannot carry the bind (disabled
                    // or refused): fall back to the IPv4 wildcard. A busy
                    // port (EADDRINUSE) or a permission problem (EACCES) is
                    // a real failure - it would sink the IPv4 attempt too.
                    throw new DualStackUnavailable("bind(::): " + errmsg);
                }
                throw new IOException(sm.getString("quicEndpoint.socketBindErrnoError",
                        errmsg, Integer.valueOf(errno)));
            }
            return sockFd;
        } catch (Exception | Error e) {
            // Nothing has seen this fd yet; releaseBindResources() cannot
            // reach it and the caller never receives it.
            QuicBindings.close(sockFd);
            throw e;
        }
    }


    /**
     * Signals a bind candidate that failed for a reason which rules out
     * only its address family, so the default (no configured address) bind
     * can fall back from the dual-stack wildcard to the IPv4 wildcard. A
     * genuine bind failure (busy port, no permission) is never reported
     * this way: it propagates as the bind error it is.
     */
    private static final class DualStackUnavailable extends Exception {

        private static final long serialVersionUID = 1L;

        private DualStackUnavailable(String message) {
            super(message);
        }
    }


    private void setOption(int fd, int level, int opt, MemorySegment val, String name)
            throws IOException {
        if (QuicBindings.setsockopt(fd, level, opt, val, (int) val.byteSize()) != 0) {
            throw new IOException(sm.getString("quicEndpoint.socketOptionError",
                    name, Integer.valueOf(QuicBindings.errno())));
        }
    }


    @Override
    public void startInternal() throws Exception {
        // A poll loop that survived stopInternal()'s bounded join still owns
        // the native state: it is running pollLoop() against the same poll
        // set, listener, SSL_CTX and mailbox (stopInternal logged and
        // deliberately leaked them, and unbind() skipped releasing them).
        // Starting a second loop on top of it would run SSL_poll(),
        // SSL_handle_events() and poll-set mutations concurrently on that
        // shared native state - the exact confinement violation the
        // single-owner design exists to prevent, and one that -ea builds
        // would assert on as well. Refuse the start rather than race it; a
        // start attempt once the leaked loop has terminated is allowed again.
        Thread oldPollThread = pollThread;
        if (oldPollThread != null && oldPollThread.isAlive()) {
            throw new IllegalStateException(sm.getString(
                    "quicEndpoint.pollThreadStillRunning", getName()));
        }
        if (getExecutor() == null) {
            createExecutor();
        }
        // A start clears any prior pause, as the other endpoints do, so a
        // restart after pause() does not come back up refusing connections.
        paused = false;
        running = true;
        // Drain the stream frees a previous lifecycle left queued after its
        // stop drains had run: a worker that finished after stopInternal()
        // queued its deferred stream frees into the mailbox, and they would
        // otherwise run only on the first iteration of the new poll loop,
        // retaining the wrapper, its streams and the connection SSL in
        // between. These are real frees (guarded by the shared freed CAS) of
        // objects stop deliberately did NOT free (streams owned by a still
        // running handler, whose connection stop retained), so running them
        // here is required, not hazardous. The guard above proved the old
        // loop dead (a live one refuses the start) and the new one is not
        // started yet, so this thread is the single native caller. The
        // deferred stream frees are drained before the retention
        // sweep below so every stream SSL goes before the connection SSL the
        // sweep frees (every queueStreamFree precedes its owner's handler
        // decrement, so a handler count of zero means no further stream free
        // can arrive).
        if (pollThread == null || !pollThread.isAlive()) {
            drainPendingStreamFrees();
            drainCleanerStreamFrees();
            drainCleanerConnectionFrees();
        }
        // Stop-time retentions whose handler has since completed: complete
        // their deferred free here (the mailbox task that carried it may have
        // been discarded by the mailbox close below) and drop them from the
        // set - otherwise the wrappers and their native connection SSLs
        // accumulate across stop/start cycles for the endpoint's lifetime.
        // Entries with handlers still running stay retained (a free under a
        // live handler would be a use-after-free). The liveness condition is
        // belt-and-braces: the guard above already refused the start while
        // the previous poll thread was alive to touch these connections.
        if (pollThread == null || !pollThread.isAlive()) {
            java.util.Iterator<QuicConnectionWrapper> iterator =
                    stoppedBusyConnections.iterator();
            while (iterator.hasNext()) {
                QuicConnectionWrapper conn = iterator.next();
                if (conn.hasActiveHandlers()) {
                    continue;
                }
                // Balance the endpoint-wide protocol-data tally for this
                // retained connection: a handler that outlived the stop's
                // handler wait could still have marked it pending after the
                // stop loop cleared it, and its queued data can never be
                // flushed (stop already dropped the manager state).
                setConnectionProtocolDataPending(conn, false);
                // Every queueStreamFree precedes its owner's handler
                // decrement, so a count of zero means no further stream free
                // can arrive: drain them, then free (streams-before-connection
                // per SSL_new_stream(3)).
                drainPendingStreamFrees();
                drainCleanerStreamFrees();
                drainCleanerConnectionFrees();
                try {
                    conn.freeSslOnce();
                } catch (Throwable t) {
                    log.warn(sm.getString("quicEndpoint.connectionSslFreeError",
                            Long.toHexString(conn.getSslAddress())), t);
                }
                iterator.remove();
            }
        }
        // Re-open the mailbox and drop any poll task left over from a previous
        // generation's stop before the new poll thread can drain it: such a
        // task was submitted after the stop had already freed (or deferred)
        // every connection it owned, so running it would operate on freed
        // native state (e.g. an SSL_write_ex/SSL_handle_events hop for a
        // connection a late-completing worker no longer owns). Workers whose
        // hops are rejected observe a RejectedExecutionException from
        // callOnPollThread instead of a 30s hop timeout.
        mailbox.open();
        // One poll thread, deliberately: the per-connection native work (the
        // SSL_poll() ticks, event handling and stream lifecycle) is not
        // parallelised. Sharding connections across several native threads was
        // implemented and measured (OpenSSL 4.0, 100 idle connections, 1 vs 4
        // workers): throughput gained at most ~3 % while the native threads'
        // CPU cost rose from ~0.51 to ~0.67 cores idle and ~0.54 to ~0.86
        // cores under a 32x32-stream load. OpenSSL serialises those operations
        // on internal per-connection/engine locks, so concurrent SSL_poll()
        // calls do not overlap - they only add lock-spinning - and per-
        // connection confinement removes the intra-connection (stream)
        // parallelism that actually matters for throughput. The single thread
        // therefore stays, and the thread count is not configurable.
        pollThread = new Thread(() -> {
            try {
                pollLoop();
            } catch (Throwable t) {
                log.error(sm.getString("quicEndpoint.pollLoopCrashed"), t);
            }
        }, getName() + "-Poller");
        pollThread.setDaemon(true);
        pollThread.start();
        log.info(sm.getString("quicEndpoint.started", getName()));
    }


    @Override
    public void stopInternal() throws Exception {
        running = false;

        if (pollThread != null) {
            pollThread.interrupt();
            // A thread blocked in the native poll(2)/SSL_poll() call is not
            // interrupted by Thread.interrupt(): kick the wake eventfd so the
            // loop re-checks the stop flag on its next iteration instead of
            // after the wait timeout.
            QuicWakeup wakeup = quicWakeup;
            if (wakeup != null) {
                wakeup.kick();
            }
            pollThread.join(5000);
            // If the poll thread is still alive here it may be dereferencing
            // the native poll set, listener, SSL_CTX and arenas, so freeing
            // them from this thread would be a use-after-free. Leak the
            // native state (log a warning) instead of risking a crash.
            if (pollThread.isAlive()) {
                log.warn(sm.getString("quicEndpoint.pollThreadNotStopped"));
                return;
            }
        }

        // Run tasks that worker threads submitted but the poll thread did not
        // drain before stopping, so workers waiting on a hop complete instead
        // of timing out. The poll loop is stopped, so no other thread calls
        // the native QUIC API concurrently with these tasks.
        drainWhile(System.currentTimeMillis() + 5000, () -> mailbox.hasPollTasks());

        // Tell the peers of live connections about the shutdown before their
        // SSL objects are freed: GOAWAY announces that no new streams will be
        // accepted, the bounded drain flushes those frames (and final
        // response bytes of handlers still in flight), and the queued
        // CONNECTION_CLOSE (no-error code from the application protocol)
        // terminates the connections explicitly. Without these the peer only
        // learns about the stop when its idle timer fires (HTTP/3
        // graceful shutdown, RFC 9114 Section 5.2). The poll loop is stopped,
        // so this thread is the only caller of the native QUIC API while
        // these run (worker native operations arrive as poll tasks drained
        // here, as in the drain above).
        notifyConnectionsGoingAway();
        drainConnectionsForShutdown();
        queueConnectionClosesForShutdown();

        // Wait for request handlers still running on executor workers.
        // This must run before shutdownExecutor(): shutdownNow() interrupts
        // the worker threads that are executing those handlers, so waiting
        // only after the shutdown can never wait for them - the handlers
        // would be cut off after the graceful drain at the latest, dropping
        // their in-flight responses and surfacing the interrupt inside the
        // transport. Keep servicing the workers' hop tasks while waiting so
        // a handler blocked on a native round trip completes instead of only
        // unblocking when the hop times out. Handlers that outlive this
        // budget are interrupted by the executor shutdown below.
        drainWhile(System.currentTimeMillis() + ACTIVE_HANDLER_SHUTDOWN_WAIT_MS,
                this::hasActiveRequestHandlers);

        shutdownExecutor();

        // Give the handlers the executor shutdown just interrupted a short
        // window to unwind while their hop tasks keep being serviced, so
        // their close paths run against live native state rather than
        // stranding in-flight poll tasks.
        drainWhile(System.currentTimeMillis() + ACTIVE_HANDLER_SHUTDOWN_WAIT_MS,
                this::hasActiveRequestHandlers);

        // Clean up HTTP/3 connection managers first
        for (QuicConnectionWrapper conn : connections.values()) {
            QuicConnectionManager connManager = conn.getQuicConnectionManager();
            conn.setQuicConnectionManager(null);
            if (connManager != null) {
                connManager.connectionClose(conn);
            }
        }

        // Free all stream SSL objects explicitly before connections. The
        // shared freed CAS (freeSslOnce) makes this safe against a Cleaner
        // that already ran for the same object, so shutdown does not rely on
        // the wrappers still being reachable via the connections map. A
        // stream a worker still owns (processing flag claimed, mirroring
        // closeAllStreams()) is skipped rather than freed under the running
        // handler, and its connection is retained below.
        java.util.Set<QuicConnectionWrapper> busyConnections =
                new java.util.HashSet<>();
        for (QuicConnectionWrapper conn : connections.values()) {
            for (QuicStreamWrapper stream : conn.getStreams().values()) {
                try {
                    // Single teardown primitive (QuicStreamWrapper.
                    // freeSslIfIdle): atomically claim, free and release. A
                    // stream an executor worker still owns is not freed here -
                    // the claim is lost and the connection is retained below.
                    // A throw from the free is logged and the loop continues
                    // (the primitive has already released the claim); unlike
                    // closeAllStreams(), stop proceeds to tear every connection
                    // down regardless.
                    if (!stream.freeSslIfIdle()) {
                        // Same ownership hand-off as closeAllStreams():
                        // marking the stream deregistered lets the owning
                        // worker's finishStreamDispatch() queue the deferred
                        // stream free instead of leaking it with the
                        // connection.
                        stream.setDeregistered();
                        busyConnections.add(conn);
                    }
                } catch (Throwable t) {
                    log.warn(sm.getString("quicEndpoint.streamSslFreeError",
                            Long.toHexString(stream.getSslAddress())), t);
                }
            }
            if (!busyConnections.contains(conn)) {
                conn.getStreams().clear();
            }
        }

        // Free any stream SSL objects whose deferred free the poll loop did
        // not get to run.
        drainPendingStreamFrees();

        // Run any stream SSL free requests the Cleaner handed over. Each is
        // guarded by the shared freed CAS, so streams already freed above or
        // by the teardown paths are no-ops.
        drainCleanerStreamFrees();

        // Run any connection SSL free requests the Cleaner handed over
        // before the connection frees below. Each is guarded by the shared
        // freed CAS, so connections already freed by the teardown paths are
        // no-ops; running them here (streams are gone at this point) keeps
        // the poll-thread-side free ordering on the stop thread's
        // equivalent rather than the GC thread.
        drainCleanerConnectionFrees();

        streamWrappers.clear();

        // Transmit the CONNECTION_CLOSE frames queued before the executor was
        // shut down. Like failConnection(), drive the engine after the stream
        // SSL objects are gone: the close frame only reliably reaches the
        // socket once the streams no longer occupy the send queue, and it must
        // be flushed before the connection SSL is freed below.
        flushQueuedConnectionCloses();

        // Free all connection SSL objects explicitly. The shared freed CAS
        // (freeSslOnce) makes this safe against a Cleaner that already ran for
        // the same connection, so shutdown does not rely on the wrappers still
        // being reachable via the connections map. A connection a handler
        // still owns - directly (active handler count) or via a skipped busy
        // stream - is NOT freed here: its stream SSL objects may still be
        // alive and per SSL_new_stream(3) the connection SSL must not be
        // freed while a stream references it. The wrapper is retained (see
        // stoppedBusyConnections) so its Cleaner cannot run while those
        // streams live, and carries a pending-free claim so the worker that
        // brings the active-handler count to zero completes the free instead
        // of the wrapper being retained after the handler has finished.
        for (QuicConnectionWrapper conn : connections.values()) {
            // Protocol data still queued for this connection can never be
            // flushed now (the manager state was dropped by the
            // connectionClose() sweep above, so the flush finds no state),
            // so clear the pending mark to keep the endpoint-wide tally
            // balanced - the same balance teardownConnection() maintains.
            // Without it, a connection stopped while its flush had not yet
            // drained leaves the tally positive for the endpoint's (and any
            // restart's) lifetime, holding every loop iteration in the
            // protocol-data branch.
            setConnectionProtocolDataPending(conn, false);
            if (busyConnections.contains(conn) || conn.hasActiveHandlers()) {
                // Claim the free first, then re-check (same ordering as
                // freeConnectionOrDefer): a worker that completes between the
                // outer check and the claim would otherwise find nothing
                // pending and leave the wrapper retained forever.
                conn.setPendingFree();
                if (!conn.hasActiveHandlers() && conn.clearPendingFree()) {
                    // The handler completed underneath this loop. Every
                    // queueStreamFree precedes its owner's handler decrement,
                    // so a count of zero means no further stream free can
                    // arrive: drain them, then free.
                    drainPendingStreamFrees();
                    drainCleanerStreamFrees();
                    drainCleanerConnectionFrees();
                    try {
                        conn.freeSslOnce();
                    } catch (Throwable t) {
                        log.warn(sm.getString("quicEndpoint.connectionSslFreeError",
                                Long.toHexString(conn.getSslAddress())), t);
                    }
                    continue;
                }
                stoppedBusyConnections.add(conn);
                if (log.isDebugEnabled()) {
                    log.debug("Retaining connection SSL 0x" +
                            Long.toHexString(conn.getSslAddress()) +
                            " still owned by a request handler at stop");
                }
                continue;
            }
            try {
                conn.freeSslOnce();
            } catch (Throwable t) {
                log.warn(sm.getString("quicEndpoint.connectionSslFreeError",
                        Long.toHexString(conn.getSslAddress())), t);
            }
        }
        // Drops the retention entries: every wrapper in the map has either
        // been freed above or parked into stoppedBusyConnections (with its
        // pending-free claim and its own retention), so no Cleaner can free
        // an in-use connection SSL from the GC thread (see the connections
        // field javadoc).
        connections.clear();

        // Generation-confined protocol-data bookkeeping: the mark queue and
        // the poll-thread set reference wrappers of this generation (whose
        // native state is now freed), and the poll loop that would consume
        // them is stopped, so nothing races with these clears.
        protocolDataMarks.clear();
        protocolDataConns.clear();
        protocolDataRetry.clear();

        // Close the mailbox now that every connection this generation owns
        // has been freed (or retained as stopped-busy): tasks submitted from
        // here on - e.g. by a request handler that outlived the bounded
        // handler wait - target native connections that are freed or whose
        // ownership already moved on, and must not linger in the queue to be
        // drained against them by the next start (the mailbox is reused
        // across stop/start cycles; startInternal re-opens and discards).
        // The early return above (poll thread survived its join) deliberately
        // skips this: that generation still owns the queue, and its loop may
        // still drain it.
        mailbox.close();

        // The poll set, listener, UDP socket FD, native SSL_CTX, certificate
        // configuration and callback arenas are released by unbind() (via
        // releaseBindResources()) after this method returns, so every
        // connection and stream SSL object is freed before the SSL_CTX it
        // references. This mirrors NioEndpoint, whose unbind() frees the
        // bind-time resources that stopInternal() leaves behind.

        if (log.isInfoEnabled()) {
            log.info(sm.getString("quicEndpoint.stopped", getName()));
        }
    }


    /**
     * Announces the endpoint shutdown to every live connection by sending the
     * application protocol's stream retirement notification (for HTTP/3 the
     * GOAWAY frame, RFC 9114 Section 5.2) on its primary server
     * unidirectional stream. Must run while the connection and stream SSL
     * objects are still alive and while no other thread touches them (the
     * poll loop is stopped and worker operations arrive as tasks drained by
     * {@link #drainConnectionsForShutdown()}).
     */
    private void notifyConnectionsGoingAway() {
        for (QuicConnectionWrapper conn : connections.values()) {
            if (conn.isFreed() || conn.isClosed()) {
                continue;
            }
            try {
                QuicConnectionManager connManager = conn.getQuicConnectionManager();
                if (connManager == null) {
                    continue;
                }
                QuicConnectionManager.ConnectionState state =
                        connManager.getState(conn);
                if (state == null) {
                    continue;
                }
                sendStreamLimitNotification(connManager, state);
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error announcing go-away on connection 0x" +
                            Long.toHexString(conn.getSslAddress()), t);
                }
            }
        }
    }


    /**
     * Bounded shutdown drain: keeps executing worker hop tasks and driving
     * each live connection until the request handlers that were in flight
     * when the endpoint stopped have finished (their final response bytes go
     * out through the same event pump that flushes the GOAWAY frames) or the
     * {@link #GRACEFUL_SHUTDOWN_DRAIN_MS} budget is used up. Buffered
     * protocol data on server unidirectional streams (whose W-event flush
     * the stopped poll loop can no longer run) is retried here too.
     */
    private void drainConnectionsForShutdown() {
        long deadline = System.currentTimeMillis() + GRACEFUL_SHUTDOWN_DRAIN_MS;
        // Streams whose send part can no longer accept data (the peer closed
        // or reset the connection while the endpoint was still running, for
        // example). Flushing them again cannot make progress and would log
        // the same failure once per loop iteration.
        java.util.Set<QuicStreamWrapper> flushFailed =
                new java.util.HashSet<>();
        while (true) {
            drainPollTasks();
            boolean activity = mailbox.hasPollTasks();
            for (QuicConnectionWrapper conn : connections.values()) {
                if (conn.isFreed()) {
                    continue;
                }
                if (conn.hasActiveHandlers()) {
                    activity = true;
                }
                for (QuicStreamWrapper stream : conn.getServerUniStreams()) {
                    QuicPollItem item = stream.getPollItem();
                    ByteBuffer writeBuf = stream.getWriteBuffer();
                    if (item == null || writeBuf == null ||
                            !writeBuf.hasRemaining() ||
                            flushFailed.contains(stream)) {
                        continue;
                    }
                    if (flushServerUniStreamWrite(stream, item) ==
                            UniStreamWriteResult.RETRY) {
                        activity = true;
                    } else {
                        flushFailed.add(stream);
                    }
                }
                QuicBindings.SSL_handle_events(conn.getSsl());
            }
            if (!activity || System.currentTimeMillis() >= deadline) {
                break;
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        // Pick up tasks queued by the handlers whose completion ended the
        // loop (or by the deadline itself) so their waits resolve.
        drainPollTasks();
    }


    /**
     * Queues a {@code CONNECTION_CLOSE} carrying the application protocol's
     * graceful-shutdown error code (for HTTP/3 {@code H3_NO_ERROR}, RFC 9114
     * Sections 5.2 and 8) on every connection that is still live, so the
     * peer does not have to wait for its idle timeout to learn about the
     * stop. The frames are flushed by
     * {@link #flushQueuedConnectionCloses()} once the stream SSL objects are
     * freed.
     */
    private void queueConnectionClosesForShutdown() {
        long errorCode = getGracefulShutdownErrorCode();
        for (QuicConnectionWrapper conn : connections.values()) {
            if (conn.isFreed() || conn.isClosed()) {
                continue;
            }
            sendConnectionCloseWithError(conn, errorCode);
        }
    }


    /**
     * Drives the state machine of every connection that still owns a native
     * SSL object to transmit the CONNECTION_CLOSE frames queued by
     * {@link #queueConnectionClosesForShutdown()} before those objects are
     * freed.
     */
    private void flushQueuedConnectionCloses() {
        for (QuicConnectionWrapper conn : connections.values()) {
            if (conn.isFreed()) {
                continue;
            }
            flushConnectionClose(conn.getSsl());
        }
    }


    /**
     * Checks whether any live connection still has an executor worker
     * running its HTTP handler (see
     * {@link QuicConnectionWrapper#hasActiveHandlers()}).
     *
     * @return {@code true} if at least one handler is still in flight
     */
    private boolean hasActiveRequestHandlers() {
        for (QuicConnectionWrapper conn : connections.values()) {
            if (conn.hasActiveHandlers()) {
                return true;
            }
        }
        return false;
    }


    /**
     * Releases the bind-time native resources (poll set, listener, UDP socket
     * FD, native {@code SSL_CTX}, certificate configuration and callback
     * arenas) that {@link #bind()} allocated and {@link #stopInternal()} left
     * in place, then lets the base class drop any generated SSLContexts.
     * <p>
     * {@code AbstractEndpoint} calls this after {@link #stop()} and from
     * {@code destroy()} for an endpoint bound on init, so it is the single
     * reclaim path for both a normal stop and a bind that never started.
     */
    @Override
    public void unbind() throws Exception {
        // releaseBindResources() frees native objects the poll thread
        // dereferences. If the poll thread is still alive (it is blocked in the
        // native SSL_poll() and could not be joined during stop), freeing them
        // here would be a use-after-free; leak the native state (log a warning)
        // instead of crashing, mirroring the guard in stopInternal().
        if (pollThread != null && pollThread.isAlive()) {
            log.warn(sm.getString("quicEndpoint.pollThreadNotStopped"));
        } else {
            releaseBindResources();
        }
        super.unbind();
    }


    @Override
    protected void doCloseServerSocket() throws IOException {
        // No-op by design. A QUIC endpoint multiplexes every connection over
        // the single listener datagram socket: closing it here (the graceful
        // shutdown hook) would black-hole the in-flight connections that
        // awaitConnectionsClose() is about to wait for. The FD is closed by
        // unbind() (via releaseBindResources()) after the poll thread and the
        // connections are gone; deliberately do not reset socketFd here so
        // that path can still find and close it.
    }


    @Override
    protected InetSocketAddress getLocalAddress() throws IOException {
        return bindAddress;
    }


    @Override
    protected Log getLog() {
        return log;
    }


    @Override
    protected Long serverSocketAccept() throws Exception {
        throw new UnsupportedOperationException(sm.getString("quicEndpoint.noTcpAccept"));
    }


    @Override
    protected boolean setSocketOptions(Long socket) {
        return false;
    }


    /*
     * Required override (AbstractEndpoint's abstract contract), reached only
     * through AbstractEndpoint.processSocket() - which no QUIC code path
     * calls; see the QuicSocketProcessor comment for the dispatch reality.
     */
    @Override
    protected SocketProcessorBase<QuicStream>
            createSocketProcessor(SocketWrapperBase<QuicStream> socket,
                    SocketEvent event) {
        return new QuicSocketProcessor(socket, event);
    }


    @Override
    protected void startAcceptorThread() {
        // No-op - QUIC uses SSL_poll instead of acceptor thread
    }


    @Override
    protected void destroySocket(Long socket) {
        // No-op. The endpoint does not cache stream sockets (the AbstractEndpoint
        // socket cache is an NIO mechanism), so this hook is never called for a
        // QUIC stream; stream teardown is owned by the QUIC close paths, which
        // de-register and free streams on the poll thread (and any leftovers by
        // the drain performed during stop).
    }


    @Override
    protected void unlockAccept() {
        // No-op - QUIC does not use acceptor locking
    }


    /**
     * Checks whether the current thread is the QUIC poll thread.
     */
    boolean isPollThread() {
        return Thread.currentThread() == pollThread;
    }


    /**
     * Debug-only guard for the endpoint's poll-thread confinement discipline.
     * All native QUIC state (connections, streams, the poll set and the
     * deferred-free queues) is owned by the poll thread; executor workers hop
     * every native operation onto it through {@link #callOnPollThread}, and the
     * single protocol executor hops its completions back through
     * {@link #submitPollTask}. The only other thread that legitimately touches
     * that state is the stop thread, and only once the poll loop has stopped
     * ({@link #stopInternal()} joins the poll thread before it drains), when the
     * poll thread can no longer run concurrently. An off-thread access while
     * the poll loop is live is a use-after-free waiting to happen. Assertions
     * are compiled but only enforced with {@code -ea}.
     *
     * @param operation a short name for the guarded operation, reported if the
     *                  confinement check fails
     */
    private void assertNativeAccess(String operation) {
        assert isPollThread() || pollThread == null || !pollThread.isAlive()
                : "Native QUIC access (" + operation + ") reached off the poll thread from "
                        + Thread.currentThread().getName();
    }


    /**
     * Submits a task to be executed on the poll thread. The task must be a
     * single fast operation (one native QUIC call or one poll-set mutation);
     * it must never block, because the poll thread is the only thread that
     * drains the queue.
     *
     * @return {@code true} if the task was queued, {@code false} if it was
     *         dropped because the mailbox is closed (endpoint stopped)
     */
    boolean submitPollTask(Runnable task) {
        return mailbox.submitPollTask(task);
    }


    /**
     * Records whether a connection has protocol data (for HTTP/3: QPACK
     * decoder instructions) pending emission. Called from any thread (the
     * HTTP/3 connection manager queues instructions from worker and protocol
     * threads); the poll loop consults {@link #protocolDataPendingCount} to
     * decide whether to run the protocol-data sweep, and sweeps only the
     * connections named in {@link #protocolDataMarks}.
     *
     * @param conn    The connection wrapper
     * @param pending {@code true} when instructions were queued,
     *                {@code false} once the flush drained them
     */
    void setConnectionProtocolDataPending(QuicConnectionWrapper conn,
            boolean pending) {
        if (conn.protocolDataPendingTransition(pending)) {
            if (pending) {
                // Mark before publishing the count: a sweep gated on a
                // positive count then always finds this connection's mark
                // too (the reverse order can only ever cost one sweep that
                // sees the count but not the mark, but this ordering keeps
                // the pair atomic for the gate).
                protocolDataMarks.add(conn);
                protocolDataPendingCount.incrementAndGet();
            } else {
                protocolDataPendingCount.decrementAndGet();
            }
        }
    }


    /**
     * Maximum time (ms) a worker thread blocks waiting for a native QUIC
     * operation to be executed on the poll thread via
     * {@link #callOnPollThread(Callable)}. The poll loop drains the task
     * queue on every iteration, so a running poll thread completes a hop
     * within a couple of poll timeouts; this bound only triggers if the
     * poll thread is gone (endpoint shutdown).
     */
    private static final long POLL_TASK_HOP_TIMEOUT_MS = 30000;


    /**
     * Runs {@code task} on the QUIC poll thread and waits for its result.
     * OpenSSL QUIC is not thread-safe for concurrent access to a
     * connection, so native operations must execute on the poll thread:
     * when the caller already is the poll thread the task runs directly,
     * otherwise it is queued via {@link #submitPollTask} and the caller
     * blocks until the poll loop has executed it.
     * <p>
     * The task must be a single fast operation (one native call or one
     * poll-set mutation) and must never block: the poll thread is the only
     * thread that drains the queue, so a blocking task would deadlock.
     *
     * @param task The operation to run on the poll thread
     * @param <T>  The task's result type
     *
     * @return The task's result
     *
     * @throws Exception The task's exception, or a
     *                   {@link java.util.concurrent.TimeoutException} if
     *                   the poll thread did not execute the task in time,
     *                   or a {@link RejectedExecutionException} if the
     *                   mailbox is closed (endpoint stopped)
     */
    <T> T callOnPollThread(Callable<T> task) throws Exception {
        if (isPollThread()) {
            return task.call();
        }
        CompletableFuture<T> future = new CompletableFuture<>();
        if (!submitPollTask(() -> {
            try {
                future.complete(task.call());
            } catch (Throwable t) {
                future.completeExceptionally(t);
            }
        })) {
            // Mailbox closed (endpoint stopped): fail fast rather than wait
            // out the hop timeout for a task that will never run.
            throw new RejectedExecutionException(
                    sm.getString("quicEndpoint.pollTaskRejected"));
        }
        return future.get(POLL_TASK_HOP_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    }


    /**
     * Runs all queued poll tasks on the poll thread. Called at the top of
     * every poll loop iteration, BEFORE {@code pollSet.rebuild()} and
     * {@code SSL_poll()}, so tasks that mutate the poll set or free native
     * objects take effect before the next {@code SSL_poll()} sees them.
     *
     * @return {@code true} if at least one task ran
     */
    private boolean drainPollTasks() {
        return mailbox.drainPollTasks();
    }

    /**
     * Drains the poll-task queue repeatedly until {@code hasWork} reports no
     * more work or {@code deadline} (an absolute
     * {@link System#currentTimeMillis()} value) passes, sleeping briefly
     * between drains so a worker whose native hop the poll loop would normally
     * service can complete while the poll loop is stopped. A final
     * unconditional drain runs on exit so a task queued between the last check
     * and the deadline still resolves the waiter's future. Restores the
     * interrupt flag and stops early if the calling thread is interrupted.
     *
     * @param deadline absolute deadline in {@link System#currentTimeMillis()}
     *                 units
     * @param hasWork  reports whether another drain is worthwhile
     */
    private void drainWhile(long deadline, BooleanSupplier hasWork) {
        while (hasWork.getAsBoolean() && System.currentTimeMillis() < deadline) {
            drainPollTasks();
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        drainPollTasks();
    }


    /**
     * Frees the connection SSL, or defers the free if an executor worker is
     * still running the HTTP handler for a stream on this connection. The
     * worker that brings {@code activeHandlers} to zero schedules the free
     * as a poll task.
     */
    private void freeConnectionOrDefer(QuicConnectionWrapper conn) {
        assertNativeAccess("freeConnectionOrDefer");
        // Claim the free first, then re-check the handler count: a handler
        // that exits between an initial count check and setting the flag
        // would find nothing pending and the deferred free would never run
        // (the worker that brings activeHandlers to zero claims the flag).
        conn.setPendingFree();
        if (!conn.hasActiveHandlers() && conn.clearPendingFree()) {
            conn.freeSslOnce();
            return;
        }
        if (log.isDebugEnabled()) {
            log.debug("Deferring connection SSL free (0x"
                    + Long.toHexString(conn.getSslAddress())
                    + ") until active handlers complete");
        }
    }


    // ------------------------------------- Poll Loop

    /**
     * Reports whether the endpoint has no connections and no queued deferred
     * stream frees, so the poll loop can drop to its idle cadence. Callers
     * must also check {@link QuicNativeMailbox#hasPollTasks()}: a worker can
     * only hop work for a connection that is in the connections map (or a
     * stream free deferred from its close path), so this check combined with
     * an empty task queue means the next iteration can only be woken by an
     * incoming packet or a native timer - both handled by {@code SSL_poll()}
     * regardless of the caller-chosen timeout.
     *
     * @return {@code true} if the endpoint is idle
     */
    private boolean isIdle() {
        return connections.isEmpty() && !mailbox.hasDeferredStreamFrees();
    }


    /**
     * Main poll loop following the OpenSSL poll-server reference pattern,
     * adapted so the blocking wait is interruptible from other threads, and
     * so the QUIC engine is ticked once per iteration that needs a tick
     * instead of once per poll item.
     * <p>
     * {@code SSL_poll()} itself is never used in blocking mode and never used
     * to drive the engine: OpenSSL 4.x ticks the whole shared QUIC engine
     * (every connection of the listener, plus the socket receive pump) when
     * <em>any</em> poll item is ticked, so a full {@code SSL_poll()} with
     * {@code event handling enabled} pays for N full-engine ticks per call,
     * one per item. The loop instead:
     * <ol>
     * <li>Waits in {@link QuicWakeup#await(long)} for a packet on the UDP
     *     socket, a mailbox kick (another thread queued a native hop or
     *     poll-set mutation), or the timeout - additionally capped by the
     *     earliest timer deadline the engine reported on its last tick.</li>
     * <li>Drains the mailbox tasks (worker native hops), then decides whether
     *     anything can have changed: an arrived packet, a drained hop, a due
     *     deadline, queued stream frees, or the first iteration. If and only
     *     if so, ticks the engine exactly once with
     *     {@code SSL_handle_events()} (packet receive pump, all channels,
     *     all timers) and refreshes the engine-wide next deadline with a
     *     single {@code SSL_get_event_timeout()} call on the listener (the
     *     deadline the reactor merged across all channels on the last
     *     tick).</li>
     * <li>Then calls {@code SSL_poll()} in non-blocking mode with
     *     {@code SSL_POLL_FLAG_NO_HANDLE_EVENTS} so it only tests (events
     *     enabled vs disabled is now moot) and reports readiness instead of
     *     re-ticking per item.</li>
     * <li>If the event handlers (or a QPACK protocol-data flush) produced
     *     output, ticks the engine once more so that output goes out within
     *     the iteration. The connections are configured for EXPLICIT
     *     event-handling mode ({@link #configureExplicitEventHandling}), so
     *     the handler calls themselves no longer tick the engine; this is
     *     their single flush. In the implicit default mode the flush is
     *     redundant and this step is skipped whenever no handler did
     *     anything.</li>
     * </ol>
     * Iterations where nothing can have changed skip the tick, the poll-set
     * rebuild and the {@code SSL_poll()} call entirely; the wait alone bounds
     * the idle cost of any number of connections, which is what decouples the
     * idle keep-alive cost from the connection count.
     * <p>
     * OpenSSL manages all I/O through the datagram BIO created by SSL_set_fd().
     * The application calls SSL_accept_connection(), SSL_accept_stream(),
     * SSL_read_ex(), and SSL_write_ex() which all operate through the internal BIO.
     * <p>
     * Event dispatch follows the strict OpenSSL reference priority:
     * ERROR → IN → OUT.
     */
    private void pollLoop() {
        if (log.isDebugEnabled()) {
            log.debug("QUIC poll loop starting, socketFd=" + socketFd);
        }

        // Scratch for the SSL_get_event_timeout() read (struct timeval + int),
        // confined to this thread for the duration of the loop. The timeval
        // layout and the field offsets used to read it come from the single
        // definition in QuicPoll, so the two ABI assumptions (LP64
        // time_t/suseconds_t) can never drift apart.
        Arena timerArena = Arena.ofConfined();
        MemorySegment timerTv = timerArena.allocate(QuicPoll.TIMEVAL_LAYOUT);
        MemorySegment timerInf = timerArena.allocate(ValueLayout.JAVA_INT);
        // Absolute System.currentTimeMillis() of the engine-wide deadline the
        // reactor reported on the last tick, or 0 while unknown.
        long quicDeadlineAbsMs = 0;
        // True once at least one tick has run, so the cached deadline above
        // can be trusted for wait-capping.
        boolean haveQuicDeadline = false;
        // Due-tick coalescing state (see DUE_TICK_FLOOR_BASE_MS): the current
        // adaptive floor and the absolute time from which the next
        // deadline-driven tick may run. Both are zero while no deadline is
        // overdue or the floor is disabled.
        long dueTickFloorMs = 0;
        long nextDueTickFreeAtMs = 0;

        while (running && !Thread.interrupted()) {
            try {
                  // Sleep here until the next UDP packet, a mailbox kick or
                  // the timeout. The mailbox/SSL_poll interplay no longer
                  // depends on the poll timeout for hop latency: every task
                  // submission kicks the wait, and tasks queued after the
                  // drain below are picked up immediately on the next
                  // iteration.
                long waitMs;
                if (mailbox.hasPollTasks()) {
                    waitMs = PENDING_TASK_POLL_TIMEOUT_MS;
                } else if (isIdle()) {
                    waitMs = IDLE_POLL_TIMEOUT_MS;
                } else {
                    waitMs = Math.min(pollTimeoutMs,
                            NATIVE_POLL_TIMEOUT_CAP_MS);
                }
                if (quicDeadlineAbsMs != 0) {
                    waitMs = Math.max(0, Math.min(waitMs,
                            quicDeadlineAbsMs - System.currentTimeMillis()));
                }
                int waitEvents = quicWakeup.await(waitMs);
                quicWakeup.consumeWake();

                   // Hop native operations from executor worker threads to this
                   // thread before touching the poll set or calling SSL_poll.
                boolean ranHops = drainPollTasks();
                boolean deferredFrees = mailbox.hasDeferredStreamFrees();

                 // Nothing can have changed since the last tick when the wait
                 // hit its timeout, no hop ran, no free is queued and no QUIC
                 // timer is due: tick, poll set rebuild and SSL_poll() can
                 // all be skipped, keeping an iteration with idle connections
                 // down to the bare wake. (First iteration: no deadline is
                 // cached yet, so the tick boots the engine and the event
                 // scan.)
                long nowMs = System.currentTimeMillis();
                // A failed wait is signalled by the negative return value
                // (QuicWakeup.await() contract: treat the iteration as
                // no-progress and back off). Handle it explicitly rather than
                // relying on the two's-complement bits of -1 to fall out of
                // the bit test: treat it as a possible event so the
                // iteration still runs the engine tick (a broken wake
                // descriptor must not stop the engine, and the due-tick park
                // below must not spin on an instantly failing await), and
                // keep waitEvents negative through to the bottom of the loop,
                // so the "wait timed out" shortcut does not engage there and
                // the no-progress backoff sleeps a bounded amount per
                // iteration instead of spinning.
                boolean sockWake = waitEvents < 0 ||
                        (waitEvents & QuicWakeup.EVENT_SOCK) != 0;
                boolean deadlineDue = quicDeadlineAbsMs != 0 &&
                        quicDeadlineAbsMs <= nowMs;
                boolean reactiveWake = ranHops || deferredFrees || sockWake ||
                        !haveQuicDeadline;

                  // The due-tick coalescing floor: while the deadline stays
                  // overdue (the engine's own deadline chatter at idle) the
                  // next due-driven tick waits out the floor - which grows
                  // with each consecutive silent due tick up to the cap - so
                  // an idle fleet is ticked a bounded number of times per
                  // second. Any reactive wake (packet, hop, queued free)
                  // resets the floor: real work always runs at full speed,
                  // and the first due tick after it, too.
                if (reactiveWake) {
                    dueTickFloorMs = 0;
                    nextDueTickFreeAtMs = 0;
                }
                boolean dueTickHeld = deadlineDue && !reactiveWake &&
                        dueTickFloorCapMs > 0 &&
                        nowMs < nextDueTickFreeAtMs;
                if (dueTickHeld) {
                    // Park until the floor releases the next due tick instead
                    // of burning the interval on deadline-due wakes.
                    long remain = nextDueTickFreeAtMs - nowMs;
                    quicWakeup.await(remain);
                    continue;
                }
                boolean tickNeeded = reactiveWake || deadlineDue;
                if (!tickNeeded) {
                    continue;
                }

                // One engine tick services everything: the receive pump
                // (arrival of packets, demux to the connections), all
                // channels (timers, retransmission, pending send queue) and
                // the pending listener handshakes. Doing it once here instead
                // of once per poll item is what removes the per-item engine
                // cost from SSL_poll(), and the EXPLICIT event-handling mode
                // of the connections (configureExplicitEventHandling) removes
                // the per-API-call engine ticks the implicit default would
                // run from the event handlers and the mailbox hops - their
                // output is flushed by the flush tick at the bottom of this
                // iteration instead. Tick even while connections is empty:
                // during an accept burst the map is empty until the first
                // accept, and the handshake only progresses on engine ticks.
                QuicBindings.SSL_handle_events(listener);
                quicDeadlineAbsMs = listenerQuicDeadlineMs(timerTv, timerInf);
                haveQuicDeadline = true;
                if (deadlineDue && !reactiveWake && dueTickFloorCapMs > 0) {
                    dueTickFloorMs = (dueTickFloorMs == 0)
                            ? DUE_TICK_FLOOR_BASE_MS
                            : Math.min(dueTickFloorMs * 2, dueTickFloorCapMs);
                    nextDueTickFreeAtMs = nowMs + dueTickFloorMs;
                }

                pollSet.rebuild();
                pollSet.resetResultCount();

                  // SSL_poll() in non-blocking mode (timeout zero), with
                  // SSL_POLL_FLAG_NO_HANDLE_EVENTS: readiness of each item is
                  // tested and reported against the state the tick above just
                  // produced, without OpenSSL ticking the engine again per
                  // item.
                int sslPollResult = QuicPoll.poll(
                            pollSet.getNativeArray(),
                            pollSet.size(),
                            0,
                            QuicPoll.SSL_POLL_FLAG_NO_HANDLE_EVENTS,
                            pollSet.getResultCountSegment()
                    );

                   // The tick above has flushed any pending packets (including
                   // RESET_STREAM frames) to the network, so it is now safe to
                   // free the stream SSL objects deferred by the close paths.
                drainPendingStreamFrees();

                   // Run the stream SSL free requests the Cleaner handed over
                    // from the GC thread. Deciding here (on the poll thread)
                    // serializes them with the connection teardown sequence.
                    // The connection free requests are drained after the
                    // stream ones: per SSL_new_stream(3) the streams go
                    // first.
                drainCleanerStreamFrees();
                drainCleanerConnectionFrees();

                long resultCount = pollSet.getResultCount();
                if (sslPollResult <= 0 && resultCount <= 0) {
                       // Per SSL_poll(3) (OpenSSL 3.5+) this combination (0
                       // with no events) indicates a basic usage error. Log
                       // it, rate-limited, instead of failing silently. Back
                       // off before the next iteration like the no-progress
                       // path below, otherwise a persistent failure here
                       // spins the CPU at 100%.
                    long now = System.currentTimeMillis();
                    if (now - lastPollUsageErrorLogMs >= 30000) {
                        lastPollUsageErrorLogMs = now;
                        log.warn(sm.getString("quicEndpoint.pollUsageError",
                                    Integer.valueOf(sslPollResult)));
                    }
                    Thread.sleep(1);
                    continue;
                }

                boolean processedAnything = false;
                  // A zero result count means SSL_poll found nothing on any
                  // item - an item it failed to poll reports F and is counted
                  // (FAIL_ITEM increments the result count), so nothing is
                  // pending and every revents is zero. The revents sync and
                  // the item scan are both O(poll set); skipping them here
                  // keeps a ticked iteration over an otherwise idle fleet
                  // (the keep-alive-only case) at zero Java-side scan work.
                  // The scan runs only when the native readout actually
                  // reported something.
                if (resultCount > 0) {
                    // SSL_POLL_EVENT_F is an *error* flag in OpenSSL 3.5:
                    // SSL_poll sets it on an item it failed to poll and
                    // zeroes the revents of every item after it. It must
                    // never be cleared silently - doing so both hides the
                    // failure and starves all subsequent items. It is
                    // handled per-item below.
                    pollSet.syncRevents();

                    // Process items with events. Follow OpenSSL reference
                    // priority: ERROR -> IN -> OUT.
                    for (int slot = 0; slot < pollSet.size(); slot++) {
                        QuicPollItem item = pollSet.itemAt(slot);
                        // A handler that ran earlier in this same iteration
                        // may have removed the item from the poll set (and
                        // freed the SSL it refers to). Skip items that are
                        // no longer members of the set.
                        if (pollSet.get(item.getSsl().address()) != item) {
                            continue;
                        }
                        long revents = item.getRevents();
                        if (revents == 0) {
                            continue;
                        }

                        // F means SSL_poll failed to poll this item and
                        // zeroed the revents of all items after it. Evict
                        // the item before anything else, otherwise it would
                        // silently starve the rest of the poll set on every
                        // iteration. A failing listener is retained (see
                        // handlePollFailure); that does not count as
                        // progress, otherwise the no-progress backoff below
                        // is defeated and the loop spins at full CPU while
                        // the failure persists.
                        if ((revents & QuicPoll.SSL_POLL_EVENT_F) != 0) {
                            if (handlePollFailure(item)) {
                                processedAnything = true;
                            }
                            continue;
                        }
                        processedAnything = handlePollItemEvents(item,
                                revents, processedAnything);
                    }
                }

                  // Emit any pending protocol data queued for the peer on a
                  // server-initiated stream. For HTTP/3 these are the QPACK
                  // decoder instructions (Section Acknowledgment, Stream
                  // Cancellation, Insert Count Increment) that must not be
                  // left waiting for feedback that is only queued, not sent,
                  // when no client unidirectional stream data arrives
                  // (RFC 9204 Sections 2.2.2.1, 2.2.2.2, 2.2.2.3). The sweep
                  // is skipped entirely while no connection has anything
                  // queued, and walks only the marked connections instead of
                  // the fleet: a connection enters the set through the mark
                  // queue, and leaves it when its flush drains the queue
                  // (flag cleared), when it tears down, or - if the flush
                  // only got part way out (no re-drive of a blocked send by
                  // the transport here) - it stays for the next sweep.
                boolean protocolDataFlushed = false;
                if (protocolDataPendingCount.get() > 0) {
                    QuicConnectionWrapper marked;
                    while ((marked = protocolDataMarks.poll()) != null) {
                        protocolDataConns.add(marked);
                    }
                    if (!protocolDataConns.isEmpty()) {
                        protocolDataRetry.clear();
                        for (QuicConnectionWrapper conn : protocolDataConns) {
                            if (conn.isClosed() || conn.isFreed() ||
                                    !conn.isProtocolDataPending()) {
                                // Dropping the entry is final: a pending
                                // re-mark after this point (new instructions
                                // queued) re-adds it through the mark queue.
                                continue;
                            }
                            QuicConnectionManager connManager =
                                    conn.getQuicConnectionManager();
                            if (connManager == null) {
                                continue;
                            }
                            connManager.flushPendingProtocolData(conn);
                            protocolDataFlushed = true;
                            if (conn.isProtocolDataPending()) {
                                protocolDataRetry.add(conn);
                            }
                        }
                        protocolDataConns.clear();
                        protocolDataConns.addAll(protocolDataRetry);
                        protocolDataRetry.clear();
                    }
                }

                  // Flush tick for EXPLICIT event handling (see
                  // configureExplicitEventHandling): the event handlers above
                  // and the protocol-data sweep queue their output into the
                  // stream send queues instead of flushing it to the network
                  // with an engine tick per call, so one engine tick here
                  // moves everything this iteration produced onto the wire.
                  // Without it that output would wait for the loop's next
                  // wake - bounded in any case (the delivered work re-armed
                  // engine timers, the deadline refresh right after this
                  // tick reads them, and the poll timeout caps the wait),
                  // but pointlessly late; with it the flush stays on the
                  // poll thread inside the same iteration, where the
                  // per-call implicit ticks used to run.
                if (processedAnything || protocolDataFlushed) {
                    QuicBindings.SSL_handle_events(listener);
                    quicDeadlineAbsMs = listenerQuicDeadlineMs(timerTv, timerInf);
                }

                  // No item produced progress on this iteration. Either
                  // SSL_poll returned failure (0) with an item reporting F,
                  // or it reported events that every handler treated as a
                  // no-op - a persistent listener EL is the level-triggered
                  // case (see handleListenerError). Both otherwise make the
                  // loop spin at full CPU while the condition persists, so
                  // back off briefly; the next genuine event still wakes the
                  // wait. A wait that simply timed out already blocked for
                  // its whole budget and needs no extra sleep (a failed
                  // wait is reported as an error, not a timeout, so a
                  // persistent wait failure backs off here too).
                boolean pollTimedOut = sslPollResult == 1 && resultCount == 0
                        && waitEvents == 0;
                if (!processedAnything && !pollTimedOut) {
                    Thread.sleep(1);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error(sm.getString("quicEndpoint.pollLoopError"), e);
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        timerArena.close();

        if (log.isDebugEnabled()) {
            log.debug("QUIC poll loop stopped");
        }
    }


    /**
     * Reports the engine's next tick deadline as an absolute
     * {@link System#currentTimeMillis()} value, or {@code 0} when no timer is
     * armed. Reading it on the listener is enough for the whole endpoint: all
     * connections of a listener share the listener's QUIC engine and its
     * reactor, whose tick deadline the engine merges across all of its
     * channels on every tick (OpenSSL 4.x {@code qeng_tick} /
     * {@code ossl_quic_port_subtick}), and {@code SSL_get_event_timeout()}
     * returns precisely that reactor deadline. One call replaces the previous
     * full per-connection deadline scan. Called only from the poll thread,
     * right after {@code SSL_handle_events()}.
     *
     * @param timerTv   Reusable scratch for the timeval output
     * @param timerInf  Reusable scratch for the is-infinite flag
     *
     * @return The earliest deadline, or {@code 0} if none
     */
    private long listenerQuicDeadlineMs(MemorySegment timerTv, MemorySegment timerInf) {
        return earlierQuicDeadline(listener, timerTv, timerInf,
                System.currentTimeMillis(), 0);
    }


    /**
     * Reports the given SSL object's next event deadline as an absolute
     * {@link System#currentTimeMillis()} value, or {@code current} when the
     * object has an infinite deadline (or no armed timer).
     */
    private long earlierQuicDeadline(MemorySegment ssl, MemorySegment timerTv,
            MemorySegment timerInf, long nowMs, long current) {
        if (ssl == null || ssl.equals(MemorySegment.NULL)) {
            return current;
        }
        if (QuicBindings.SSL_get_event_timeout(ssl, timerTv, timerInf) == 0 ||
                timerInf.get(ValueLayout.JAVA_INT, 0) != 0) {
            return current;
        }
        long secs = timerTv.get(ValueLayout.JAVA_LONG, QuicPoll.TV_SEC_OFFSET);
        long usecs = timerTv.get(ValueLayout.JAVA_LONG, QuicPoll.TV_USEC_OFFSET);
        long deadline = nowMs + secs * 1000 + Math.max(0, usecs / 1000);
        return current == 0 || deadline < current ? deadline : current;
    }


    /**
     * Dispatches one poll item's event flags to its handler, following the
     * OpenSSL reference priority. Extracted from {@link #pollLoop()} so the
     * loop body stays readable; each handler call is wrapped so an unexpected
     * exception does not derail the whole iteration. Called only from the
     * poll thread while iterating over a freshly synced poll set.
     *
     * @param item              The poll item (fresh revents; not the F flag,
     *                          which is evicted by the caller)
     * @param revents           The item's revents
     * @param processedAnything Whether earlier items of this iteration already
     *                          produced progress
     *
     * @return The updated progress flag ({@code true} when this item's event
     *         counted as poll-loop progress)
     */
    private boolean handlePollItemEvents(QuicPollItem item, long revents,
            boolean processedAnything) {
        if (log.isTraceEnabled()) {
            String eventType = "";
            if (item.hasError()) {
                eventType += "ERROR ";
            }
            if (item.hasIncomingConnection()) {
                eventType += "IC ";
            }
            if (item.hasConnectionClose()) {
                eventType += "CC ";
            }
            if (item.hasIncomingStream()) {
                eventType += "IS ";
            }
            if (item.hasOutgoingStream()) {
                eventType += "OS ";
            }
            if (item.isReadable()) {
                eventType += "R ";
            }
            if (item.isWritable()) {
                eventType += "W ";
            }
            if (item.hasPollFailure()) {
                eventType += "FAIL ";
            }
            log.trace("Event ssl=0x" + Long.toHexString(item.getSsl().address())
                     + " revents=0x" + Long.toHexString(revents) + " " + eventType);
        }

        boolean isListener = (item.getAppData() == null &&
                 item.getSsl().equals(listener));

        if (isListener &&
                 (revents & QuicPoll.SSL_POLL_EVENT_EL) == 0) {
            // The listener was polled without an EL error event: it
            // has recovered (or was never failing). Clear the
            // escalation state so a later, transient EL is reported
            // at warn level again instead of permanently as
            // "persistent".
            listenerErrorCount = 0;
        }

        // Service the highest-priority bucket whose flags are set, following
        // the OpenSSL reference ERROR -> IN -> OUT order: within a bucket
        // exactly one handler runs and the buckets are mutually exclusive per
        // item. The pure priority decision lives in QuicEventDispatcher.classify()
        // so it can be unit tested without native calls; the handlers themselves
        // stay in the endpoint. A poll-failure (F) was evicted by the caller and
        // never reaches the classifier.
        QuicEventDispatcher.QuicEvent event =
                QuicEventDispatcher.classify(revents, isListener);
        try {
            switch (event) {
                case LISTENER_ERROR:
                    // EL on the listener is level-triggered: it re-fires while the
                    // condition persists and the handler only reports it, so it
                    // deliberately does not count as progress for the backoff in
                    // pollLoop().
                    handleListenerError(item);
                    break;
                case CONNECTION_CLOSE:
                    try {
                        handleConnectionClose(item);
                    } catch (Exception ex) {
                        log.warn(sm.getString(
                                "quicEndpoint.connectionCloseError"), ex);
                    }
                    break;
                case STREAM_ERROR:
                    try {
                        handleErrorEvent(item);
                    } catch (Exception ex) {
                        log.warn(sm.getString(
                                "quicEndpoint.streamErrorEventError"), ex);
                    }
                    break;
                case ERROR_OTHER:
                    // Error bucket with no specific handler (for example a non-listener
                    // EL with no EC/ECD/ER/EW): nothing to run, but the bucket was hit.
                    break;
                case INCOMING_CONNECTION:
                    try {
                        handleIncomingConnection(item);
                    } catch (Exception ex) {
                        log.warn(sm.getString(
                                "quicEndpoint.incomingConnectionError"), ex);
                    }
                    break;
                case INCOMING_STREAM:
                    try {
                        handleIncomingStream(item);
                    } catch (Exception ex) {
                        log.warn(sm.getString(
                                "quicEndpoint.incomingStreamError"), ex);
                    }
                    break;
                case READABLE:
                    try {
                        dispatchStreamEvent(item, SocketEvent.OPEN_READ);
                    } catch (Exception ex) {
                        log.warn(sm.getString(
                                "quicEndpoint.readEventDispatchError"), ex);
                    }
                    break;
                case OUTGOING_STREAM:
                    try {
                        handleOutgoingStream(item);
                    } catch (Exception ex) {
                        log.warn(sm.getString(
                                "quicEndpoint.outgoingStreamError"), ex);
                    }
                    break;
                case WRITABLE:
                    try {
                        dispatchStreamEvent(item, SocketEvent.OPEN_WRITE);
                    } catch (Exception ex) {
                        log.warn(sm.getString(
                                "quicEndpoint.writeEventDispatchError"), ex);
                    }
                    break;
                case NONE:
                default:
                    break;
            }
        } catch (Exception e) {
            log.warn(sm.getString("quicEndpoint.eventProcessError"), e);
        }

        return event.countsAsProgress() || processedAnything;
    }


    // ------------------------------------- Event Handlers

    private void handleListenerError(QuicPollItem item) {
        // SSL_POLL_EVENT_EL per SSL_poll(3): the listener experienced an
        // error. It is level-triggered - while the condition persists it
        // reasserts on every poll iteration - so rate-limit the reporting
        // instead of warning at the poll-loop rate (~100/s). The loop is
        // not crashed: the listener may recover, and existing connections
        // keep working even if it cannot accept new ones.
        long count = ++listenerErrorCount;
        long now = System.currentTimeMillis();
        if (now - lastListenerErrorLog >= LISTENER_ERROR_LOG_INTERVAL_MS) {
            lastListenerErrorLog = now;
            if (count >= LISTENER_ERROR_PERSISTENT_COUNT) {
                log.error(sm.getString("quicEndpoint.listenerErrorPersistent",
                        Long.valueOf(count)));
            } else {
                log.warn(sm.getString("quicEndpoint.listenerErrorEvent",
                        Long.valueOf(count)));
            }
        }
    }


    /**
     * Handles {@code SSL_POLL_EVENT_F} on a poll item: SSL_poll() failed to poll
     * the item (for example because the underlying SSL object is invalid or
     * already destroyed) and zeroed the revents of every item after it in the
     * array.
     * <p>
     * Dumps the OpenSSL error queue for diagnosis and evicts the item so it
     * cannot starve the rest of the poll set on every iteration. The warning
     * and the error-queue dump are rate-limited: a failing item that cannot
     * be evicted (the listener) re-raises F on every SSL_poll() call while
     * the failure persists, so logging every occurrence would flood the log
     * at the poll-loop rate. The first occurrence is reported immediately,
     * then at most once per interval with a cumulative occurrence count.
     *
     * @return {@code true} if the item was evicted (a stream was closed or a
     *         connection torn down), {@code false} if it was retained (a
     *         failing listener is kept: dropping it would break the whole
     *         endpoint). A {@code false} result must not be counted as poll
     *         loop progress, or the no-progress backoff is defeated and the
     *         loop spins at full CPU while the failure persists.
     */
    private boolean handlePollFailure(QuicPollItem item) {
        long count = ++pollFailureCount;
        long now = System.currentTimeMillis();
        if (now - lastPollFailureLog >= POLL_FAILURE_LOG_INTERVAL_MS) {
            lastPollFailureLog = now;
            String errors = QuicDiagnostics.dumpErrorQueue();
            log.warn(sm.getString("quicEndpoint.pollItemFailure",
                    Long.toHexString(item.getSsl().address()),
                    Long.toHexString(item.getRevents()),
                    Long.valueOf(count), errors));
        }
        Object appData = item.getAppData();
        if (appData instanceof QuicStreamWrapper stream) {
            try {
                closeStream(stream, false);
            } catch (Throwable t) {
                log.warn(sm.getString("quicEndpoint.streamCloseAfterPollFailure"), t);
            }
            return true;
        } else if (appData instanceof QuicConnectionWrapper conn) {
            try {
                teardownConnection(conn, null);
            } catch (Throwable t) {
                log.warn(sm.getString("quicEndpoint.connectionTeardownAfterPollFailure"), t);
            }
            return true;
        }
        // A failing listener item is kept: dropping the listener would break the
        // whole endpoint. It is not counted as progress, so the 1ms backoff in
        // pollLoop() engages and prevents a CPU spin.
        return false;
    }


    /**
     * Removes every stream wrapper of the given connection from the
     * {@link #streamWrappers} map. Must be called before the connection's
     * stream map is cleared, otherwise the {@link QuicOpenSSLSocketWrapper}
     * entries (and the stream/poll objects they reference) leak. The ECD
     * teardown path does this inline while collecting the BIDI wrappers; the
     * {@code failConnection}, {@code handlePollFailure} and
     * {@code abortConnectionSetup} paths only need the removal.
     *
     * @param conn The connection whose stream wrappers should be removed
     */
    private void removeStreamWrappers(QuicConnectionWrapper conn) {
        for (QuicStreamWrapper sw : conn.getStreams().values()) {
            streamWrappers.remove(sw.getSslAddress());
        }
        for (QuicStreamWrapper sw : conn.getPendingStreams()) {
            streamWrappers.remove(sw.getSslAddress());
        }
    }


    /**
     * Tears down a QUIC connection after an application protocol connection
     * error. For HTTP/3, per RFC 9114 Section 8, the QUIC connection is
     * terminated with a {@code CONNECTION_CLOSE} frame carrying the protocol
     * error code in the application error code field. Must be called on the
     * QUIC poll thread.
     *
     * @param conn             The connection to tear down
     * @param protocolErrorCode The application protocol error code for the
     *                         CONNECTION_CLOSE frame (0 to send no protocol
     *                         error code)
     * @param reason           A short description of the error (for logging)
     */
    public void failConnection(QuicConnectionWrapper conn, long protocolErrorCode, String reason) {
        if (log.isDebugEnabled()) {
            log.debug(reason + " conn=0x" + Long.toHexString(conn.getSsl().address())
                    + " protocolErrorCode=0x" + Long.toHexString(protocolErrorCode));
        }
        try {
            if (protocolErrorCode > 0) {
                sendConnectionCloseWithError(conn, protocolErrorCode);
            }
            teardownConnection(conn, () -> {
                // Transmit the queued CONNECTION_CLOSE before the connection
                // SSL is freed.
                flushConnectionClose(conn.getSsl());
            });
        } catch (Throwable t) {
            log.warn(sm.getString("quicEndpoint.connectionTeardownError"), t);
        }
    }


    /**
     * Sends a QUIC {@code CONNECTION_CLOSE} frame with the given application
     * protocol error code in the application error code field (for HTTP/3,
     * RFC 9114 Section 8) and flushes it to the network. Must be called on
     * the QUIC poll thread while the connection SSL is still alive.
     *
     * @param conn             The connection to close
     * @param protocolErrorCode The application protocol error code to carry
     *                         in the frame
     */
    private void sendConnectionCloseWithError(QuicConnectionWrapper conn, long protocolErrorCode) {
        sendConnectionCloseFrame(conn.getSsl(), protocolErrorCode);
        // Kick the engine once; the reliable transmission is driven later
        // (see flushConnectionClose() for why more pumping may be needed).
        QuicBindings.SSL_handle_events(conn.getSsl());
    }


    /**
     * Queues a QUIC {@code CONNECTION_CLOSE} frame carrying
     * {@code errorCode} in the application error code field via
     * {@code SSL_shutdown_ex} with the RAPID and NO_BLOCK flags (RFC 9114
     * Section 8; the reason string is left empty). The frame is only queued:
     * transmission requires driving the engine afterwards, either with a
     * single {@code SSL_handle_events} kick or - if the connection SSL is
     * about to be freed - with {@link #flushConnectionClose}. Must be called
     * on the QUIC poll thread while the connection SSL is still alive.
     *
     * @param ssl       The connection {@code SSL*} to shut down
     * @param errorCode The application protocol error code to carry
     */
    private void sendConnectionCloseFrame(MemorySegment ssl, long errorCode) {
        try (Arena localArena = Arena.ofConfined()) {
            // SSL_SHUTDOWN_EX_ARGS { uint64_t quic_error_code; const char *quic_reason; }
            MemorySegment args = localArena.allocate(16);
            args.set(ValueLayout.JAVA_LONG, 0, errorCode);
            args.set(ValueLayout.ADDRESS, 8, MemorySegment.NULL);
            long flags = QuicBindings.SSL_SHUTDOWN_FLAG_RAPID
                    | QuicBindings.SSL_SHUTDOWN_FLAG_NO_BLOCK;
            int rc = QuicBindings.SSL_shutdown_ex(ssl, flags, args, 16L);
            if (rc < 0 && log.isDebugEnabled()) {
                log.debug("SSL_shutdown_ex failed rc=" + rc
                        + " errors=" + QuicDiagnostics.dumpErrorQueue());
            }
        }
    }


    /**
     * Drives the connection's state machine a bounded number of times to
     * transmit a {@code CONNECTION_CLOSE} queued by
     * {@link #sendConnectionCloseFrame}. A frame queued while streams are
     * still alive is only reliably written once the stream SSL objects are
     * freed (or the connection is being torn down), so a single
     * {@code SSL_handle_events} pass is not enough when the connection SSL is
     * about to go away. Must be called on the QUIC poll thread while the
     * connection SSL is still alive.
     *
     * @param ssl The connection {@code SSL*} to drive
     */
    private void flushConnectionClose(MemorySegment ssl) {
        for (int flush = 0; flush < CONNECTION_CLOSE_FLUSH_ATTEMPTS; flush++) {
            QuicBindings.SSL_handle_events(ssl);
        }
    }


    /**
     * Resolves the peer (client) address of an accepted QUIC connection via
     * {@code SSL_get_peer_addr()} and stores it on the connection wrapper. This
     * lets the request's {@code getRemoteAddr()}/{@code getPeerAddr()} report the
     * actual client address (required by valves such as RemoteCIDRValve).
     * {@code BIO_ADDR} is an opaque type in OpenSSL (currently a union of
     * sockaddr structs, but that layout is not ABI), so it is read through the
     * documented accessors {@code BIO_ADDR_family()},
     * {@code BIO_ADDR_rawaddress()} and {@code BIO_ADDR_rawport()}.
     * <p>
     * The address is captured once, at accept. QUIC connection migration
     * (RFC 9000 Section 9) can legitimately move a live connection to a new
     * client address afterwards; this endpoint does not re-read the peer
     * address on migration, so {@code getRemoteAddr()} - and everything
     * derived from it, such as {@code RemoteCIDRValve} decisions - keeps
     * reporting the address the connection was accepted from. That matches
     * the per-connection address semantics HTTP has always had over TCP, but
     * is surprising for QUIC, where the same connection can outlive the
     * reported address.
     *
     * @param connSsl the connection SSL object
     * @param conn the connection wrapper to update
     */
    private void populatePeerAddress(MemorySegment connSsl, QuicConnectionWrapper conn)
            throws java.net.UnknownHostException {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment bioAddr = arena.allocate(128);
            int rc = QuicBindings.SSL_get_peer_addr(connSsl, bioAddr);
            if (rc != 1) {
                if (log.isDebugEnabled()) {
                    log.debug("SSL_get_peer_addr rc=" + rc + " errors=" + QuicDiagnostics.dumpErrorQueue());
                }
                return;
            }
            int family = QuicBindings.BIO_ADDR_family(bioAddr);
            if (family != QuicBindings.AF_INET && family != QuicBindings.AF_INET6) {
                if (log.isDebugEnabled()) {
                    log.debug("SSL_get_peer_addr unsupported family=" + family);
                }
                return;
            }
            // BIO_ADDR_rawport() hands back sin_port/sin6_port as the host
            // reads it from the socket struct: the two memory bytes are
            // network order, so the 16-bit result is the port byte-swapped
            // on a little-endian host and already the plain port value on a
            // big-endian one - twiddle only in the first case.
            int rawPort = QuicBindings.BIO_ADDR_rawport(bioAddr) & 0xFFFF;
            int port = ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN
                    ? ((rawPort & 0xFF) << 8) | (rawPort >>> 8)
                    : rawPort;

            int addrLen = family == QuicBindings.AF_INET ? 4 : 16;
            MemorySegment rawAddr = arena.allocate(addrLen);
            MemorySegment lenPtr = arena.allocate(ValueLayout.JAVA_LONG);
            int addrRc = QuicBindings.BIO_ADDR_rawaddress(bioAddr, rawAddr, lenPtr);
            long copied = lenPtr.get(ValueLayout.JAVA_LONG, 0);
            if (addrRc != 1 || copied != addrLen) {
                if (log.isDebugEnabled()) {
                    log.debug("BIO_ADDR_rawaddress rc=" + addrRc + " len=" + copied);
                }
                return;
            }
            byte[] addr = rawAddr.toArray(ValueLayout.JAVA_BYTE);
            conn.setRemoteAddress(new InetSocketAddress(InetAddress.getByAddress(addr), port));
        }
    }


    /**
     * Reject-budget per IC-handling iteration. Under an accept burst the
     * listener reports a pending connection on every iteration; draining one
     * per iteration bounds the per-iteration cost, which keeps the poll loop
     * responsive while a hole opens for the burst to drain (limited by the
     * rate the engine completes handshakes for the pending connections).
     */
    private static final int REJECT_BURST_LIMIT = 32;

    /**
     * Flush ticks used when draining >1 rejection in one iteration. All
     * rejected frames sit in the shared engine's per-channel send queues, so
     * a couple of engine ticks transmit every queued CONNECTION_CLOSE of the
     * batch (each tick is the whole-engine service; see the tick discussion
     * on {@link #pollLoop()}).
     */
    private static final int REJECT_BATCH_FLUSH_ATTEMPTS = 3;


    /**
     * Consumes a single pending incoming connection on the listener by
     * accepting it and immediately freeing the resulting connection SSL. Used
     * at {@code maxConnections} to drain the listener queue so the
     * level-triggered {@code SSL_POLL_EVENT_IC} stops re-firing and the poll
     * thread stops spinning. The accepted connection is never registered with
     * the endpoint; it is dropped after a bounded {@code CONNECTION_CLOSE} is
     * sent so the rejection is observable to the client (an immediate
     * {@code SSL_free} alone would leave the client to time out).
     */
    private void rejectIncomingConnection() {
        rejectIncomingConnections(1);
    }


    /**
     * Drains pending incoming connections on the listener (as bounded by
     * {@code maxPending}) by accepting each and immediately rejecting it with
     * a {@code CONNECTION_CLOSE}. Used at {@code maxConnections}, on pause and
     * in the drain path of a burst of incoming connections.
     * <p>
     * Every pending connection has already paid its handshake inside the
     * engine (OpenSSL surfaces one only once the handshake completes); the
     * batching wins on what the rejection loop itself costs: one close frame
     * is queued per connection, then a fixed handful of engine ticks
     * ({@value #REJECT_BATCH_FLUSH_ATTEMPTS} instead of
     * {@value #CONNECTION_CLOSE_FLUSH_ATTEMPTS} per connection) transmits
     * them all at once, since the ticks service every channel of the shared
     * engine. The frames are queued before any SSL_free so each connection's
     * close frame is written while its own channel still exists.
     * <p>
     * Draining a bounded batch per iteration (rather than the whole queue)
     * keeps the loop responsive while the level-triggered IC re-fires across
     * iterations for the remainder.
     *
     * @param maxPending Maximum connections to accept-and-reject in this call
     */
    private void rejectIncomingConnections(int maxPending) {
        java.util.List<MemorySegment> rejected = null;
        int drained = 0;
        while (drained < maxPending) {
            MemorySegment connSsl = QuicBindings.SSL_accept_connection(listener, 0L);
            if (connSsl == null || connSsl.equals(MemorySegment.NULL)) {
                break;
            }
            if (maxPending == 1) {
                // Single-connection path: the batched flush below runs the
                // same ticks; keep the original per-connection flush depth.
                sendConnectionCloseFrame(connSsl, getConnectionRejectErrorCode());
                flushConnectionClose(connSsl);
                openssl_h.SSL_free(connSsl);
                return;
            }
            if (rejected == null) {
                rejected = new java.util.ArrayList<>(maxPending);
            }
            sendConnectionCloseFrame(connSsl, getConnectionRejectErrorCode());
            rejected.add(connSsl);
            drained++;
        }
        if (rejected == null) {
            return;
        }
        // Transmit every queued frame: one tick per channel of the batched
        // connections (the engine ticks everything at once), with a spare
        // pass for channels whose frames are queued after the first tick.
        for (int flush = 0; flush < REJECT_BATCH_FLUSH_ATTEMPTS; flush++) {
            QuicBindings.SSL_handle_events(listener);
        }
        for (MemorySegment connSsl : rejected) {
            openssl_h.SSL_free(connSsl);
        }
    }


    private void handleIncomingConnection(QuicPollItem listenerItem) throws Exception {
        if (paused) {
            // A paused endpoint accepts no new connections (the contract every
            // AbstractEndpoint implementation honours). Existing connections
            // keep being served. The pending connection is consumed and
            // rejected with a CONNECTION_CLOSE (same drain mechanism as the
            // max-connections path) so the level-triggered IC event stops
            // re-firing and the client learns the connection was refused
            // instead of timing out.
            long now = System.currentTimeMillis();
            if (log.isDebugEnabled() && now - lastPausedLogMs >= 5000) {
                lastPausedLogMs = now;
                log.debug(sm.getString("quicEndpoint.paused", getName()));
            }
            rejectIncomingConnection();
            return;
        }

        if (getQuicProtocol() == null) {
            // No application protocol configured (the endpoint allows the
            // protocol to arrive after start). Nothing can serve an accepted
            // connection - the connection-manager creation below would throw
            // on every accept - so consume and reject pending handshakes with
            // the same mechanism as the paused path: the listener queue
            // drains, the level-triggered IC stops re-firing, and the client
            // learns the connection was refused instead of timing out.
            rejectIncomingConnections(REJECT_BURST_LIMIT);
            return;
        }

        // AbstractEndpoint documents maxConnections = -1 as "unlimited".
        // This endpoint enforces the limit against the connections map
        // directly, so the -1 sentinel has to be honoured here too: without
        // the guard "size() >= -1" is always true and every connection is
        // rejected.
        if (maxConnections >= 0 && connections.size() >= maxConnections) {
            // Rate-limit the warning: SSL_POLL_EVENT_IC is level-triggered, so
            // while a connection is pending this can be reached on every poll
            // iteration and would otherwise flood the log at line rate.
            long now = System.currentTimeMillis();
            if (now - lastMaxConnectionsLogMs >= 5000) {
                lastMaxConnectionsLogMs = now;
                log.warn(sm.getString("quicEndpoint.maxConnections", String.valueOf(maxConnections)));
            }
            // Consume the pending handshakes: accept and reject a bounded
            // batch immediately so the listener queue drains fast (the
            // level-triggered IC re-fires across iterations for the rest).
            // Without draining, the queue of half-handshaken native
            // connections grows without bound and the poll thread spins.
            rejectIncomingConnections(REJECT_BURST_LIMIT);
            return;
        }

        // SSL_accept_connection() (SSL_accept_connection(3)) completes the
        // pending handshake, so the transport configuration below runs on a
        // live connection.
        MemorySegment connSsl = QuicBindings.SSL_accept_connection(listener, 0L);
        if (connSsl.equals(MemorySegment.NULL)) {
            return;
        }

        QuicConnectionWrapper conn = new QuicConnectionWrapper(connSsl,
                getCleanerConnectionFrees());
        connections.put(connSsl.address(), conn);
        QuicPollItem connItem = null;
        try {
            conn.setLocalAddress(bindAddress);
            // Resolve the peer (client) address so request.getRemoteAddr()/
            // getPeerAddr() report the real client address (e.g. for
            // RemoteCIDRValve). Must run while the connection SSL is live.
            populatePeerAddress(connSsl, conn);

            configureConnectionTransport(connSsl);

            // Request all events (-1 want mask), as for the listener item:
            // the handshake and connection lifecycle can report any event
            // type. Per SSL_poll(3) the failure flag (SSL_POLL_EVENT_F) is a
            // poll result, not a pollable interest: it is raised regardless of
            // want_events and is handled by eviction in the poll loop.
            connItem = new QuicPollItem(connSsl, -1L, conn);
            conn.setPollItem(connItem);
            conn.setEndpoint(this);

            // Record the ALPN negotiated protocol (e.g. "h3") so the connection
            // handler can route this connection's streams through the upgrade
            // protocol's getProcessor(). The value may not be available until
            // the handshake completes, so the served-protocol check is deferred
            // to ensureServedProtocol() before stream dispatch.
            String alpn = readAlpnProtocol(connSsl);
            if (alpn != null) {
                conn.setNegotiatedProtocol(alpn);
            }

            conn.setSniHostName(conn.readSniHostName());

            configureIncomingStreamPolicy(connSsl);
            configureIdleTimeout(connSsl);

            QuicConnectionManager connManager =
                    getQuicProtocol().createQuicConnectionManager();
            connManager.connectionOpen(conn);
            conn.setQuicConnectionManager(connManager);

            // Accept the client's streams and create the server's, honouring the
            // order the protocol bootstrap requires (see bootstrapIncomingStreams).
            int[] accepted = bootstrapIncomingStreams(connSsl, conn, connItem);
            int uniAccepted = accepted[0];
            int bidiAccepted = accepted[1];

            if (!isConnectionLive(conn)) {
                // Inline protocol processing of a client stream failed the
                // connection during bootstrap: teardownConnection() already
                // freed (or deferred the free of) the connection SSL and
                // removed the connection from the maps and the poll set.
                // Continuing would run applyTransportStreamLimits() and
                // pollSet.add() on freed memory.
                return;
            }

            applyTransportStreamLimits(conn, connManager, bidiAccepted, uniAccepted);

            // Now add connection to poll set. SSL_handle_events on the connection
            // is safe now because BIDI stream data has already been pre-read.
            pollSet.add(connItem);
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicEndpoint.connectionAccepted",
                        String.valueOf(connections.size())));
            }
            if (log.isDebugEnabled()) {
                log.debug("handleIncomingConnection: conn=0x" + Long.toHexString(connSsl.address()) +
                        " bidiAccepted=" + bidiAccepted + " uniAccepted=" + uniAccepted);
            }
        } catch (Exception e) {
            log.warn(sm.getString("quicEndpoint.connectionSetupError",
                    Long.toHexString(connSsl.address())), e);
            abortConnectionSetup(conn);
        }
    }


    /**
     * Applies the per-connection transport settings immediately after the
     * connection object is created: non-blocking mode, multi-stream
     * (no-default-stream) mode and EXPLICIT event-handling mode. All are best
     * effort - a failure is logged and the connection continues with
     * OpenSSL's defaults, matching the previous inline behaviour.
     *
     * @param connSsl The connection SSL (live)
     */
    private void configureConnectionTransport(MemorySegment connSsl) {
        QuicBindings.SSL_set_blocking_mode(connSsl, 0);

        // Disable default stream mode: HTTP/3 requires explicit stream
        // management (multi-stream mode). Without this, OpenSSL may
        // auto-associate a single stream with the connection object, causing
        // conflicts when we create multiple streams.
        QuicBindings.SSL_set_default_stream_mode(
                connSsl, QuicBindings.SSL_DEFAULT_STREAM_MODE_NONE);

        configureExplicitEventHandling(connSsl);
    }


    /**
     * Switches the connection - and, through OpenSSL's INHERIT resolution of
     * the object parent chain, every stream of it - to EXPLICIT
     * event-handling mode.
     * <p>
     * In the default mode every API call on a QUIC SSL object
     * ({@code SSL_read_ex()}, {@code SSL_write_ex()},
     * {@code SSL_stream_conclude()}, {@code SSL_shutdown()},
     * {@code SSL_accept_stream()}) drives event handling implicitly, which
     * for these objects means ticking the whole shared QUIC engine reactor:
     * one walk of every channel of the listener per call (OpenSSL's
     * {@code qctx_should_autotick()} / {@code quic_post_write()}). That makes
     * each poll-loop dispatch iteration a burst of O(fleet) engine walks -
     * every response byte written pays for a scan of every unrelated
     * connection. This endpoint is already an explicit-mode reactor: the poll
     * loop ticks the engine exactly once per iteration that needs a tick
     * (plus one flush tick when the event handlers produced output, see
     * {@link #pollLoop()}) and the close/teardown paths pump
     * {@code SSL_handle_events()} explicitly. The implicit per-call ticks are
     * therefore pure duplicate cost; disabling them moves the flush of output
     * queued by an event handler from the write call itself to the flush tick
     * at the end of the same iteration, on the same thread, before the loop
     * waits.
     * <p>
     * A rejection is not fatal: the connection stays in the default
     * (implicit) mode, which is functionally identical - the endpoint's own
     * ticks are correct in both modes - only slower. The mode is settable on
     * connection and stream objects but not on the listener (OpenSSL gates
     * {@code SSL_VALUE_EVENT_HANDLING_MODE} to those types), hence the
     * per-configuration rather than one listener-wide call.
     *
     * @param connSsl The connection SSL (live)
     */
    private void configureExplicitEventHandling(MemorySegment connSsl) {
        int rc = QuicBindings.SSL_set_value_uint(
                connSsl,
                QuicBindings.SSL_VALUE_CLASS_GENERIC,
                QuicBindings.SSL_VALUE_EVENT_HANDLING_MODE,
                QuicBindings.SSL_VALUE_EVENT_HANDLING_MODE_EXPLICIT);
        if (rc != 1 && eventHandlingModeWarned.compareAndSet(false, true)) {
            log.warn(sm.getString("quicEndpoint.eventHandlingModeRejected"));
        }
    }


    /**
     * Reads the ALPN-negotiated application protocol (e.g. "h3") from a live
     * connection SSL. The returned memory is owned by the SSL object and is
     * decoded before the confined arena is released.
     *
     * @param connSsl The connection SSL (live)
     *
     * @return the negotiated protocol, or {@code null} if none was read
     *         (including on error)
     */
    private String readAlpnProtocol(MemorySegment connSsl) {
        try (Arena alpnArena = Arena.ofConfined()) {
            MemorySegment alpnData = alpnArena.allocate(ValueLayout.ADDRESS);
            MemorySegment alpnLen = alpnArena.allocate(ValueLayout.JAVA_INT);
            QuicBindings.SSL_get0_alpn_selected(connSsl, alpnData, alpnLen);
            long alpnAddr = alpnData.get(ValueLayout.ADDRESS, 0).address();
            int alpnLength = alpnLen.get(ValueLayout.JAVA_INT, 0);
            if (alpnAddr != 0 && alpnLength > 0) {
                return StandardCharsets.US_ASCII.decode(
                        MemorySegment.ofAddress(alpnAddr).reinterpret(alpnLength)
                            .asByteBuffer()).toString();
            }
        }
        return null;
    }


    /**
     * Sets the incoming-stream policy to ACCEPT for all stream types.
     * Inherited from the listener, but set explicitly to be safe. AEC=0 (no
     * additional error code).
     *
     * @param connSsl The connection SSL (live)
     */
    private void configureIncomingStreamPolicy(MemorySegment connSsl) {
        int policyRc = QuicBindings.SSL_set_incoming_stream_policy(
                connSsl, QuicBindings.SSL_INCOMING_STREAM_POLICY_ACCEPT, 0L);
        if (log.isDebugEnabled()) {
            log.debug("SSL_set_incoming_stream_policy(ACCEPT) rc=" + policyRc);
        }
    }


    /**
     * Requests the QUIC idle timeout (RFC 9000 Section 10.1) for a connection.
     * SSL_VALUE_QUIC_IDLE_TIMEOUT is a negotiated feature value: it may only be
     * set as SSL_VALUE_CLASS_FEATURE_REQUEST, on the connection object, before
     * the transport parameters are generated (which happens when the server
     * sends its first flight). This is called immediately after
     * SSL_accept_connection, the earliest the connection object exists. The
     * poll loop's reactor tick (which advances QUIC timers) may already have
     * sent the first flight by the time we get here; in that case OpenSSL
     * rejects the set ("feature not renegotiable", rc == 0) and its 30 second
     * default applies. That default equals this endpoint's default idleTimeoutMs,
     * so the fallback is only visible (warned once) when a non-default timeout
     * is configured. The value is in milliseconds.
     *
     * @param connSsl The connection SSL (live)
     */
    private void configureIdleTimeout(MemorySegment connSsl) {
        QuicProtocol protocol = getQuicProtocol();
        if (protocol != null && protocol.getIdleTimeoutMs() > 0) {
            long configuredIdleTimeoutMs = protocol.getIdleTimeoutMs();
            int rc = QuicBindings.SSL_set_value_uint(
                    connSsl,
                    QuicBindings.SSL_VALUE_CLASS_FEATURE_REQUEST,
                    QuicBindings.SSL_VALUE_QUIC_IDLE_TIMEOUT,
                    configuredIdleTimeoutMs);
            if (log.isTraceEnabled()) {
                log.trace(sm.getString("quicEndpoint.idleTimeout",
                        Long.valueOf(configuredIdleTimeoutMs))
                        + " rc=" + rc
                        + (rc == 0 ? " (transport params already generated; using OpenSSL default)" : ""));
            }
            if (rc == 0 &&
                    configuredIdleTimeoutMs != OPENSSL_DEFAULT_IDLE_TIMEOUT_MS &&
                    idleTimeoutFallbackWarned.compareAndSet(false, true)) {
                log.warn(sm.getString("quicEndpoint.idleTimeoutRejected",
                        Long.valueOf(configuredIdleTimeoutMs),
                        Long.valueOf(OPENSSL_DEFAULT_IDLE_TIMEOUT_MS)));
            }
        }
    }


    /**
     * Accepts the connection's streams and creates the server's, following the
     * order the QUIC/HTTP-3 bootstrap requires:
     * <ol>
     * <li>Accept client UNI streams FIRST (stream 1 = client control,
     *     5 = QPACK encoder, 9 = QPACK decoder) so the client's SETTINGS and any
     *     QPACK instructions are processed before the server creates its own UNI
     *     streams (3, 7, 11).</li>
     * <li>Drive the QUIC state machine to flush queued data.</li>
     * <li>Create the server-initiated UNI streams the protocol requires (control
     *     /SETTINGS, then - once the client's SETTINGS are known - the QPACK
     *     encoder/decoder streams).</li>
     * <li>Drive the state machine to flush SETTINGS and other control data, then
     *     retry any buffered server UNI writes.</li>
     * <li>Accept BIDI streams and pre-read their data. This must happen before
     *     any further state-machine pump, because SSL_handle_events would
     *     process FIN packets and mark the streams FINISHED, making the buffered
     *     data unreadable.</li>
     * <li>Add the pending streams to the poll set.</li>
     * </ol>
     *
     * @param connSsl  The connection SSL (live)
     * @param conn     The connection wrapper
     * @param connItem The connection's poll item
     *
     * @return a two element array {uniAccepted, bidiAccepted}
     */
    private int[] bootstrapIncomingStreams(MemorySegment connSsl, QuicConnectionWrapper conn,
            QuicPollItem connItem) {
        int uniAccepted = acceptStreams(connSsl, QuicPoll.SSL_ACCEPT_STREAM_UNI,
                conn, "IC: accepted UNI", true);

        if (!isConnectionLive(conn)) {
            // Inline protocol processing of a client UNI stream failed the
            // connection: teardown already freed (or deferred the free of)
            // the connection SSL. Every native call below (pumpEvents,
            // createServerUniStreams, the buffered writes, the BIDI accept)
            // would run on freed memory.
            return new int[] { uniAccepted, 0 };
        }

        pumpEvents(connSsl);

        try {
            createServerUniStreams(connItem, conn);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("createServerUniStreams failed", e);
            }
        }

        pumpEvents(connSsl);

        // Try writing buffered server unidirectional stream init data one
        // more time.
        for (QuicStreamWrapper uniStream : conn.getServerUniStreams()) {
            ByteBuffer buffered = uniStream.getWriteBuffer();
            if (buffered != null && buffered.hasRemaining()) {
                writeBufferedUniStream(connSsl, uniStream);
            }
        }

        int bidiAccepted = acceptStreams(connSsl, QuicPoll.SSL_ACCEPT_STREAM_BIDI,
                conn, "IC: accepted BIDI", true);

        if ((uniAccepted + bidiAccepted) > 0 && conn.getPendingStreams().size() > 0) {
            addPendingStreamsToPollSet(conn);
        }

        return new int[] { uniAccepted, bidiAccepted };
    }


    /**
     * Tears down a connection whose setup in {@link #handleIncomingConnection(QuicPollItem)}
     * failed. The teardown itself is {@link #teardownConnection}'s single
     * implementation - the two used to be near-copies that had already begun
     * to diverge under failure, so the common body lives in one place. The
     * abort-specific parts are the swallow-and-log of a mid-teardown failure
     * (the caller is already reporting the setup error) and the guaranteed
     * free tail below.
     * <p>
     * The frees go through the same deferral machinery as
     * {@code teardownConnection} itself: {@code closeAllStreams()} claims
     * each stream's processing flag and leaves a stream that an executor
     * worker still owns to that worker, and {@link #freeConnectionOrDefer}
     * defers the connection free on {@code activeHandlers}. A dispatch can
     * already have run before a later bootstrap step threw (streams are
     * dispatched inside {@code bootstrapIncomingStreams}), and the
     * dispatched handler's connection-level SSL-support reads have no
     * per-call freed guard - an unconditional free here would let that
     * worker call into a freed connection SSL. The connection's poll item is
     * disposed by teardownConnection's never-promoted-item fallback
     * ({@code conn.getPollItem()} is the item the setup created, or null if
     * the failure happened before it existed).
     */
    private void abortConnectionSetup(QuicConnectionWrapper conn) {
        try {
            teardownConnection(conn, null);
        } catch (Throwable t) {
            log.warn(sm.getString("quicEndpoint.connectionSetupAbortError"), t);
        }
        // Mandatory tail: drain the stream frees the teardown queued (an
        // unfreed stream XSO keeps the connection reference count non-zero)
        // and hand the connection free to the deferral path. These run
        // outside the catch above: a Throwable from a middle step (most
        // plausibly the protocol's connectionClose) must not skip them,
        // or the connection SSL is never fenced by the pending-free
        // machinery (leaked until stopInternal) and the streams that
        // escaped closeAllStreams() lose the streams-before-connection
        // ordering the deferral guarantees. On the success path
        // teardownConnection ran this tail itself; re-running it is a no-op
        // (empty queues, shared freed CAS). drainPendingStreamFrees() is
        // itself per-item guarded and cannot throw; freeConnectionOrDefer
        // is last so no later step can be skipped by it.
        drainPendingStreamFrees();
        freeConnectionOrDefer(conn);
    }


    /**
     * Reconciles the configured application protocol concurrent-stream limit
     * with the limit the QUIC transport advertises to the peer
     * ({@code initial_max_streams_bidi}).
     * <p>
     * The OpenSSL QUIC implementation (3.5 / 4.0) fixes the transport stream
     * limits: {@code SSL_set_value_uint()} only accepts the idle timeout and
     * the event-handling mode as feature requests; the stream-availability
     * identifiers are read-only ({@code SSL_get_value_uint()} with
     * {@code SSL_VALUE_CLASS_GENERIC}). The endpoint therefore cannot make
     * the peer see the configured limit - it can only enforce a limit that
     * matches the transport:
     * <ul>
     * <li>configured limit &gt; transport limit: enforcement is clamped to
     *     the transport limit (the peer cannot open more streams than it was
     *     granted anyway, but the protocol layer no longer believes it has
     *     more headroom than the transport actually provides);</li>
     * <li>configured limit &lt; transport limit: the configured limit is
     *     kept - streams beyond it are refused after they arrive (HTTP/3
     *     GOAWAY), so the peer may still open up to the transport limit.</li>
     * </ul>
     * A mismatch between the two values is logged once per endpoint.
     * <p>
     * Must be called on the poll thread, after the initial streams of the
     * connection have been accepted (the remaining transport credit is
     * combined with the accepted-stream count to recover the advertised
     * initial limit).
     *
     * @param conn         The connection
     * @param connManager  The connection's protocol manager (may be
     *                     {@code null} if the connection was closed)
     * @param bidiAccepted Client-initiated BIDI streams accepted while
     *                     handling the incoming-connection event
     * @param uniAccepted  Client-initiated UNI streams accepted while
     *                     handling the incoming-connection event
     */
    private void applyTransportStreamLimits(QuicConnectionWrapper conn,
            QuicConnectionManager connManager, int bidiAccepted, int uniAccepted) {
        if (connManager == null) {
            return;
        }
        long configured = 0;
        QuicProtocol protocol = getQuicProtocol();
        if (protocol != null) {
            configured = protocol.getMaxConcurrentStreams();
        }

        long bidiAvail = -1;
        long uniAvail = -1;
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment value = localArena.allocate(ValueLayout.JAVA_LONG);
            if (QuicBindings.SSL_get_value_uint(conn.getSsl(),
                    QuicBindings.SSL_VALUE_CLASS_GENERIC,
                    QuicBindings.SSL_VALUE_QUIC_STREAM_BIDI_REMOTE_AVAIL, value) == 1) {
                bidiAvail = value.get(ValueLayout.JAVA_LONG, 0);
            }
            if (QuicBindings.SSL_get_value_uint(conn.getSsl(),
                    QuicBindings.SSL_VALUE_CLASS_GENERIC,
                    QuicBindings.SSL_VALUE_QUIC_STREAM_UNI_REMOTE_AVAIL, value) == 1) {
                uniAvail = value.get(ValueLayout.JAVA_LONG, 0);
            }
        }

        if (bidiAvail < 0) {
            // Transport limit unavailable - keep the configured limit as is.
            return;
        }
        if (bidiAccepted >= MAX_ACCEPT_PER_EVENT) {
            // The accept loop hit its cap, so more client streams may be
            // queued: avail + accepted would underestimate the advertised
            // limit. Skip the reconciliation for this connection.
            if (log.isDebugEnabled()) {
                log.debug("Transport stream limit reconciliation skipped for conn=0x" +
                        Long.toHexString(conn.getSslAddress()) + " (accept cap hit)");
            }
            return;
        }

        // REMOTE_AVAIL is the credit still left to the peer; the streams the
        // peer already opened (and this endpoint just accepted) consumed the
        // rest of the advertised initial limit.
        long transportLimit = bidiAvail + bidiAccepted;

        if (log.isDebugEnabled()) {
            log.debug("Transport stream limits for conn=0x" + Long.toHexString(conn.getSslAddress()) +
                    ": initial_max_streams_bidi=" + transportLimit +
                    ", initial_max_streams_uni=" +
                    (uniAvail < 0 ? "unknown" : Long.valueOf(uniAvail + uniAccepted)));
        }

        QuicConnectionManager.ConnectionState state = connManager.getState(conn);
        if (state != null) {
            long effective = configured > 0 ? Math.min(configured, transportLimit) : transportLimit;
            if (effective > 0) {
                state.setMaxConcurrentStreams(effective);
            }
        }

        if (configured > 0 && configured != transportLimit && !streamLimitMismatchWarned) {
            streamLimitMismatchWarned = true;
            log.warn(sm.getString("quicEndpoint.streamLimitMismatch",
                    Long.valueOf(configured), Long.valueOf(transportLimit)));
        }
    }


 /**
  * Creates the server-initiated unidirectional streams the application
  * protocol currently requires for this connection, driven entirely by the
  * protocol's {@link QuicConnectionManager}: the endpoint repeatedly asks
  * for the next stream index the protocol wants (for HTTP/3: index 0 the
  * control stream carrying SETTINGS, then - once the peer's SETTINGS are
  * known - the QPACK encoder and decoder streams), opens it, writes the
  * protocol-supplied init bytes, and hands the created stream back to the
  * protocol. Streams that could not be written immediately keep their data
  * in the stream's write buffer for the W event handler
  * ({@link #flushServerUniStreamWrite}) to retry.
  * <p>
  * Without a protocol manager the connection has nothing protocol-valid to
  * write, so no server unidirectional streams are created.
  */
    private void createServerUniStreams(QuicPollItem connItem, QuicConnectionWrapper conn) throws Exception {
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null) {
            // The connection has no protocol manager (already closed): the
            // streams would have nothing protocol-valid to write.
            return;
        }

        boolean created = false;
        long[] streamInfo = new long[2];
        int index;
        while ((index = connManager.nextServerUniStream(conn)) >= 0) {
            MemorySegment streamSsl = newUniStream(connItem.getSsl(), streamInfo);
            if (streamSsl.equals(MemorySegment.NULL)) {
                // Not ready yet (peer has not yet advertised stream
                // capacity). Retried on the next OSU event; OSU stays in
                // want_events while nextServerUniStream() is >= 0.
                if (log.isDebugEnabled()) {
                    log.debug("SSL_new_stream for server unidirectional stream index "
                            + index + " returned NULL: " + QuicDiagnostics.dumpErrorQueue());
                }
                break;
            }
            long streamId = streamInfo[0];
            int streamType = (int) streamInfo[1];
            if (log.isDebugEnabled()) {
                log.debug("Server unidirectional stream created: index=" + index +
                        " id=" + streamId + " type=" + streamType);
            }

            QuicStreamWrapper stream = registerOutgoingStream(
                    streamSsl, streamId, streamType, conn, index);

            // Stage the protocol-provided init bytes (may be null) in the
            // stream's write buffer and drive the shared buffered-write path
            // (pumping SSL_handle_events between attempts: a freshly created
            // stream is only writable once the QUIC state machine has
            // processed the handshake and stream credit). If the retries run
            // out the bytes stay buffered and the W event handler retries the
            // write.
            ByteBuffer initData = connManager.getServerUniStreamInitData(index);
            if (initData != null && initData.hasRemaining()) {
                byte[] data = new byte[initData.remaining()];
                initData.get(data);
                if (log.isDebugEnabled()) {
                    // Payload redacted (see drainStreamInto): size only.
                    log.debug("Server unidirectional stream index " + index +
                            " buffering " + data.length + " init bytes");
                }
                stream.setWriteBuffer(ByteBuffer.wrap(data));
                writeBufferedUniStream(connItem.getSsl(), stream);
            }
            connManager.serverUniStreamCreated(conn, index, stream);
            created = true;
        }

        if (created) {
            // Add pending streams to poll set now that the protocol streams
            // exist, and let the client unidirectional stream data flow.
            addPendingStreamsToPollSet(conn);
            enableReadOnClientUnidirectionalStreams(conn);
        }
    }


    private void handleConnectionClose(QuicPollItem item) throws Exception {
        QuicConnectionWrapper conn = (QuicConnectionWrapper) item.getAppData();
        if (conn == null) {
            // Could be listener - ignore close events on listener
            return;
        }

        long revents = item.getRevents();
        if (log.isDebugEnabled()) {
            log.debug("handleConnectionClose revents=0x" + Long.toHexString(revents) +
                    " EC=" + ((revents & QuicPoll.SSL_POLL_EVENT_EC) != 0) +
                    " ECD=" + ((revents & QuicPoll.SSL_POLL_EVENT_ECD) != 0));
        }

        // SSL_poll(3) reports connection close in two phases which arrive in
        // different poll iterations, so they are handled separately:
        // EC = connection close initiated (by peer or locally)
        // ECD = connection close complete (drain finished)

        if ((revents & QuicPoll.SSL_POLL_EVENT_ECD) != 0) {
            // Shutdown complete - destroy connection
            if (log.isDebugEnabled()) {
                log.debug("QUIC connection closed (ECD) ssl=0x" +
                        Long.toHexString(item.getSsl().address()));
            }
            conn.setClosed();

            // Snapshot the BIDI stream wrappers before teardown so their
            // processors can be woken up (below) after the streams have
            // been freed.
            java.util.List<QuicOpenSSLSocketWrapper> streamWrapperList =
                    new java.util.ArrayList<>();
            // Clean up stream wrappers BEFORE closeAllStreams() clears the
            // stream map, otherwise this loop would iterate an empty map and
            // the wrappers (and the stream/poll objects they reference) leak.
            for (QuicStreamWrapper sw : conn.getStreams().values()) {
                QuicOpenSSLSocketWrapper streamWrapper =
                        streamWrappers.remove(sw.getSslAddress());
                if (streamWrapper != null) {
                    // No further data can ever arrive: release any worker
                    // parked in a synchronous read or write on the stream.
                    streamWrapper.signalReadWaiter();
                    streamWrapper.signalWriteWaiter();
                    if (sw.getStreamType() == QuicPoll.SSL_STREAM_TYPE_BIDI) {
                        streamWrapperList.add(streamWrapper);
                    }
                }
            }
            for (QuicStreamWrapper sw : conn.getPendingStreams()) {
                QuicOpenSSLSocketWrapper streamWrapper =
                        streamWrappers.remove(sw.getSslAddress());
                if (streamWrapper != null) {
                    streamWrapper.signalReadWaiter();
                    streamWrapper.signalWriteWaiter();
                }
            }
            // closeAllStreams() removes each stream's poll item from the poll
            // set, marks the wrappers deregistered and frees the stream SSL
            // objects (ordered before the connection SSL, per
            // SSL_new_stream(3)).
            conn.closeAllStreams();

            // Wake up the processors of the streams that still hold one
            // (for example waiting for more request body data via a
            // non-blocking Read Listener). The connection is closed so no
            // further data can arrive; the dispatch lets the processor
            // deliver a terminal event (onAllDataRead) to the pending Read
            // Listener instead of abandoning it. dispatchToExecutor() is a
            // no-op for a stream that is already being processed (its
            // worker will observe the closed stream through its read in
            // flight) and the active handler count keeps the connection SSL
            // alive until these dispatches have finished.
            for (QuicOpenSSLSocketWrapper streamWrapper : streamWrapperList) {
                QuicStreamWrapper wakeStream = (QuicStreamWrapper) streamWrapper.getSocket();
                if (wakeStream == null) {
                    continue;
                }
                dispatchToExecutor(streamWrapper, wakeStream,
                        SocketEvent.OPEN_READ);
                // The connection is gone, so a request that has not
                // completed (an asynchronous response still being
                // written, for example) can never complete normally.
                // Deliver an error event so the container raises the
                // asynchronous error notification (onError) rather than
                // leaving the application waiting; the stream's own error
                // event was discarded when its poll entry was removed
                // above. Requests that already completed are no longer
                // registered and are not reached here, and the async
                // state machine ignores an error event once the request
                // has been recycled. With no later event to re-trigger a
                // dropped dispatch, the ERROR dispatch must not be lost
                // while the wake-up dispatch above still holds the
                // stream's processing flag - claim it as a bounded poll
                // task instead of spinning here (a spin stalls the poll
                // thread, and with it every other connection, for as long
                // as a worker's handler runs).
                scheduleStreamDispatch(streamWrapper, wakeStream,
                        SocketEvent.ERROR);
            }

            // Clean up HTTP/3 connection state
            QuicConnectionManager connManager = conn.getQuicConnectionManager();
            conn.setQuicConnectionManager(null);
            if (connManager != null) {
                connManager.connectionClose(conn);
            }

            setConnectionProtocolDataPending(conn, false);
            // Drops the retention entry right before the deferred drain and
            // CAS-guarded free below; removing earlier (streams still live)
            // would let the GC-thread Cleaner race them (see the connections
            // field javadoc).
            connections.remove(item.getSsl().address());
            pollSet.remove(item.getSsl().address());
            // Free any stream SSL objects whose free was deferred by the
            // wake-up/error dispatches above before dropping the connection
            // reference: per SSL_new_stream(3) every stream SSL must be
            // freed before the connection SSL.
            drainPendingStreamFrees();
            // Free the connection SSL exactly once (shared with the Cleaner),
            // deferring the free if an executor worker is still running the
            // HTTP handler for a stream on this connection.
            freeConnectionOrDefer(conn);
            return;
        }

        // EC without ECD: connection close in progress.
        // Use SSL_shutdown_ex with RAPID flag to initiate rapid drain,
        // then wait for ECD to confirm the connection is fully closed.
        if ((revents & QuicPoll.SSL_POLL_EVENT_EC) != 0) {
            if (conn.isClosing()) {
                // Already processed EC - don't process again to avoid tight loop
                // Just wait for ECD
                return;
            }
            if (log.isDebugEnabled()) {
                log.debug("QUIC connection close initiated (EC) for conn=0x" +
                        Long.toHexString(item.getSsl().address()));
            }
            conn.setClosing();

            // Flush pending data to network. This is critical: response data
            // written during stream processing must reach the client before
            // the connection is torn down.
            pumpEvents(item.getSsl());

            // Accept any remaining streams that arrived before close
            try {
                acceptPendingBidiStreams(item, conn);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error accepting streams during EC: " + e.getMessage());
                }
            }

            // Do NOT call SSL_shutdown() here. Let the connection close naturally.
            // The peer initiated the close (EC), so just wait for ECD.
            // Calling SSL_shutdown() can race with pending data flush.

            // Update want_events: only wait for ECD (NOT EC to avoid tight loop).
            // Keep IS (both flavours) so streams which arrive while closing are
            // still reported (acceptPendingBidiStreams above consumes them),
            // drop OS - while a peer close is in flight the server must not
            // create further streams anyway - and keep EW so write errors
            // during the final flush are surfaced: per SSL_poll(3) only
            // requested pollable interests are reported.
            item.setWantEvents(
                    QuicPoll.SSL_POLL_EVENT_ECD |
                    QuicPoll.SSL_POLL_EVENT_ISB |
                    QuicPoll.SSL_POLL_EVENT_ISU |
                    QuicPoll.SSL_POLL_EVENT_ER |
                    QuicPoll.SSL_POLL_EVENT_EW);
            return;
        }
    }


    /**
     * Budget for a deferred stream dispatch (see
     * {@link #scheduleStreamDispatch}) to acquire the stream's processing
     * flag from a still-running worker.
     */
    private static final long STREAM_CLAIM_BUDGET_MS = 500;


    /**
     * Schedules {@code event} for {@code stream} once the stream's processing
     * flag is free, without blocking the caller and without ever running the
     * handler concurrently with the current flag owner. Used for the terminal
     * ERROR dispatch on connection close (the wake-up OPEN_READ dispatch may
     * still be owned by a worker) and for dispatch events that find the
     * processing claim busy (the lost-claim fallbacks in the stream dispatch
     * paths; the call site in {@link QuicSocketProcessor#doRun()} is
     * currently unreached scaffolding - see that class' comment).
     * <p>
     * Waiting for the flag on the poll thread would stall every other
     * connection for as long as the owner's handler runs, so the claim is
     * retried from the poll loop's task queue: the task re-queues itself
     * while the budget lasts (retried on every drain, which the loop runs at
     * a short timeout whenever tasks are pending). A dispatch that acquires
     * the flag is delivered with flag ownership, exactly like the synchronous
     * path. If the budget expires the event is dropped with a log line: the
     * flag owner re-arms the stream's poll interest on exit, so a pending
     * I/O wake-up cannot be lost, and an in-flight handler observes the
     * closed stream through its own reads.
     */
    private void scheduleStreamDispatch(QuicOpenSSLSocketWrapper wrapper,
            QuicStreamWrapper stream, SocketEvent event) {
        QuicConnectionWrapper conn = stream.getConnection();
        if (conn != null) {
            // Hold an active-handler reference from scheduling onwards so the
            // connection's native SSL cannot be freed before this dispatch (or
            // its give-up) completes.
            conn.incrActiveHandlers();
        }
        long deadline = System.nanoTime() +
                TimeUnit.MILLISECONDS.toNanos(STREAM_CLAIM_BUDGET_MS);
        // submitPollTask can fail once the mailbox is closed (endpoint
        // stopping). The active-handler reference taken above is then the
        // only thing left to release: finishStreamDispatch balances the
        // count and, if it drops the last handler of a connection whose free
        // was deferred, submits that free - which is rejected in the same
        // situation and left to the start-time sweep. Without this the count
        // would stay elevated forever on a wrapper the endpoint has already
        // detached.
        if (!submitPollTask(new Runnable() {
            @Override
            public void run() {
                if (stream.compareAndSetProcessing(false, true)) {
                    dispatchToExecutor(wrapper, stream, event, true);
                    // Release the scheduling reference; the executor dispatch
                    // carries its own until its processor finishes.
                    finishStreamDispatch(stream, conn, false);
                    return;
                }
                if (System.nanoTime() - deadline < 0) {
                    if (!submitPollTask(this)) {
                        finishStreamDispatch(stream, conn, false);
                    }
                    return;
                }
                if (log.isDebugEnabled()) {
                    log.debug("Stream " + stream.getStreamId() + " still busy" +
                            " after the claim budget - " + event +
                            " dispatch dropped; the flag owner re-arms the" +
                            " stream's poll interest on exit");
                }
                finishStreamDispatch(stream, conn, false);
            }
        })) {
            finishStreamDispatch(stream, conn, false);
        }
    }


   /**
    * Accepts incoming streams. Accepts UNI streams first, then BIDI streams.
    * BIDI stream data must be read immediately to prevent SSL_handle_events
    * from processing the FIN packet before we read the data.
    */
    private void handleIncomingStream(QuicPollItem connItem) throws Exception {
        QuicConnectionWrapper conn = (QuicConnectionWrapper) connItem.getAppData();
        if (conn == null) {
            return;
        }

        if (!ensureServedProtocol(conn)) {
            return;
        }

        long revents = connItem.getRevents();
        if (log.isDebugEnabled()) {
            log.debug("handleIncomingStream called, revents=0x" + Long.toHexString(revents));
        }

        // Accept UNI streams first
        // Read UNI stream data immediately. Client control stream (1) carries
        // SETTINGS, QPACK encoder stream (5) carries encoder instructions.
        // These must be read before processing BIDI stream data.
        int uniAccepted = acceptStreams(connItem.getSsl(), QuicPoll.SSL_ACCEPT_STREAM_UNI,
                conn, "handleIncomingStream: accepted UNI", true);

        if (!isConnectionLive(conn)) {
            // Inline protocol processing of a client UNI stream failed the
            // connection (the accept loop stopped on the teardown): the
            // connection SSL is freed (or the free is deferred) and its poll
            // item disposed. Everything below would run on freed memory.
            return;
        }

        // Accept BIDI streams. Read BIDI stream data IMMEDIATELY after
        // SSL_accept_stream. This is critical because SSL_handle_events in
        // the next poll iteration will process the FIN packet and mark the
        // stream as FINISHED, making the buffered data unreadable.
        int bidiAccepted = acceptStreams(connItem.getSsl(), QuicPoll.SSL_ACCEPT_STREAM_BIDI,
                conn, "handleIncomingStream: accepted BIDI", true);
        if (log.isDebugEnabled()) {
            log.debug("handleIncomingStream: accepted " + uniAccepted + " UNI + " + bidiAccepted + " BIDI stream(s)");
        }

        // Add pending streams to poll set if server control stream already exists
        if ((uniAccepted + bidiAccepted) > 0 && conn.getPendingStreams().size() > 0) {
            addPendingStreamsToPollSet(conn);
        }

        // After accepting client UNI streams, request OSU to create any
        // server streams the protocol now wants (for HTTP/3: control/
        // SETTINGS, then the QPACK encoder/decoder streams once the
        // client's SETTINGS have been received)
        if (uniAccepted > 0) {
            requestServerUniStreamEvent(conn);
        }
    }


    /**
     * Requests the {@code SSL_POLL_EVENT_OSU} event on the connection if
     * the application protocol currently wants more server-initiated
     * unidirectional streams ({@link
     * QuicConnectionManager#nextServerUniStream(QuicConnectionWrapper)}).
     * Called after client stream data or new client streams may have
     * advanced the protocol state so the protocol's pending stream requests
     * are acted on without waiting for another trigger. No-op when the
     * protocol manager is gone or has nothing pending (the OSU handler
     * clears the event interest once the protocol is satisfied).
     *
     * @param conn The QUIC connection
     */
    private void requestServerUniStreamEvent(QuicConnectionWrapper conn) {
        QuicPollItem connItem = conn.getPollItem();
        if (connItem == null) {
            return;
        }
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null) {
            return;
        }
        try {
            if (connManager.nextServerUniStream(conn) < 0) {
                return;
            }
        } catch (Throwable t) {
            return;
        }
        long currentEvents = connItem.getWantEvents();
        if ((currentEvents & QuicPoll.SSL_POLL_EVENT_OSU) == 0) {
            currentEvents |= QuicPoll.SSL_POLL_EVENT_OSU;
            connItem.setWantEvents(currentEvents);
            if (log.isDebugEnabled()) {
                log.debug("Added OSU to want_events for server unidirectional stream creation");
            }
        }
    }


    /**
     * Performs a single {@code SSL_read_ex} drain attempt on a QUIC stream,
     * appending any bytes read to the tail of the stream's read buffer. The
     * buffer is left in put mode ({@code [0, position)} buffered, limit ==
     * capacity); the caller owns everything beyond the appended bytes.
     * <p>
     * This is the single read-loop primitive shared by the bidi and
     * unidirectional pre-read paths. The retry policy and the surrounding
     * logging/protocol handling stay with the callers - the immediate pre-read
     * paths share {@link #drainStreamImmediately}, the deferred unidirectional
     * read performs a single-shot drain; only the "allocate -&gt; SSL_read_ex
     * -&gt; copy -&gt; refresh state" body is common to all of them, and that
     * body is exactly where the F1/F8-class divergences used to creep in.
     * <p>
     * On an {@code SSL_read_ex} return of 0 the stream's read state is refreshed
     * via {@code SSL_get_stream_read_state} so callers can inspect it through
     * {@link QuicStreamWrapper#getReadState()}.
     *
     * @param stream   The stream (for state updates and trace identity)
     * @param ssl      The stream's {@code SSL*} pointer
     * @param readBuf  The stream's put-mode read buffer
     *
     * @return the number of bytes appended (possibly 0)
     */
    private int drainStreamInto(QuicStreamWrapper stream, MemorySegment ssl, ByteBuffer readBuf) {
        int space = readBuf.remaining();
        if (space <= 0) {
            return 0;
        }

        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment nativeBuf = localArena.allocate(space);
            MemorySegment lenPtr = localArena.allocate(ValueLayout.JAVA_LONG);
            lenPtr.set(ValueLayout.JAVA_LONG, 0, 0L);

            int rc = QuicBindings.SSL_read_ex(ssl, nativeBuf, (long) space, lenPtr);

            if (rc == 1) {
                long bytesRead = lenPtr.get(ValueLayout.JAVA_LONG, 0);
                int actualLen = (int) Math.min(bytesRead, space);
                readBuf.put(nativeBuf.asSlice(0, actualLen).asByteBuffer());
                if (log.isTraceEnabled()) {
                    // Payload redacted: like the HTTP/2 transport, log what
                    // happened (stream, size), never the bytes - request data
                    // can carry cookies, Authorization and other secrets that
                    // must not reach the log when debug/trace is enabled.
                    log.trace("Read " + actualLen + " bytes from stream " + stream.getStreamId());
                }
                return actualLen;
            }

            if (rc == 0) {
                stream.setReadState(QuicStreamWrapper.mapNativeState(
                        QuicBindings.SSL_get_stream_read_state(ssl)));
            }
            return 0;
        }
    }


    /**
     * Immediate-drain shell shared by the pre-read paths of freshly accepted
     * streams ({@link #readBidiStreamImmediately},
     * {@link #readUnidirectionalStreamImmediately}): up to
     * {@code READ_DRAIN_MAX_ATTEMPTS} append attempts through
     * {@link #drainStreamInto}, stopping when the read buffer is full or when
     * a read yields no data. The buffer is left in put mode. Caller-specific
     * policy (post-read logging, protocol hand-off) stays with the callers.
     *
     * @param streamSsl The stream's {@code SSL*} pointer
     * @param streamId  The stream ID (for trace identity)
     * @param kind      Stream-kind label (for trace identity)
     * @param stream    The stream (for state updates)
     * @param readBuf   The stream's put-mode read buffer
     *
     * @return the number of bytes appended
     */
    private int drainStreamImmediately(MemorySegment streamSsl, long streamId,
            String kind, QuicStreamWrapper stream, ByteBuffer readBuf) {
        int totalRead = 0;
        for (int attempt = 0; attempt < READ_DRAIN_MAX_ATTEMPTS; attempt++) {
            if (readBuf.remaining() == 0) {
                break;
            }

            int read = drainStreamInto(stream, streamSsl, readBuf);
            if (read == 0) {
                if (stream.getReadState() == QuicStream.ReadState.FINISHED &&
                        log.isDebugEnabled()) {
                    log.debug(kind + " stream " + streamId + " read " + totalRead +
                            " bytes, state=FINISHED (data preserved)");
                }
                break;
            }
            totalRead += read;
        }
        return totalRead;
    }


    /**
     * Locates the target of an immediate pre-read of a freshly accepted
     * stream: the wrapper registered by {@link #processAcceptedStream} for
     * the stream ID, provided it still exists and owns a read buffer.
     * <p>
     * Read buffer protocol (put mode, shared by both immediate pre-read
     * paths): buffered bytes occupy [0..position), limit == capacity. Every
     * path that touches a stream read buffer leaves it in this state (the
     * unidirectional paths compact() in place after protocol processing,
     * moving any unconsumed partial frame or instruction to the start), so
     * new data can always be appended after data that is still waiting to be
     * served or consumed. A pre-read may run multiple times for the same
     * stream (accept path + promotion path).
     *
     * @param streamId The accepted stream's ID
     * @param conn     The connection the stream was accepted on
     *
     * @return the stream wrapper with its read buffer available for append,
     *         or {@code null} when there is nothing to pre-read
     */
    private QuicStreamWrapper locateImmediatelyReadableStream(long streamId,
            QuicConnectionWrapper conn) {
        QuicStreamWrapper stream = conn.getStreams().get(streamId);
        if (stream == null || stream.getReadBuffer() == null) {
            return null;
        }
        return stream;
    }


    /**
     * Reads BIDI stream data immediately after SSL_accept_stream, before
     * SSL_handle_events can process the FIN packet: once OpenSSL has marked a
     * stream FINISHED, data which arrived but was not read is no longer
     * retrievable, so acceptance and the first read must stay adjacent.
     */
    private void readBidiStreamImmediately(MemorySegment streamSsl, long streamId, QuicConnectionWrapper conn) {
        QuicStreamWrapper stream = locateImmediatelyReadableStream(streamId, conn);
        if (stream == null) {
            return;
        }

        ByteBuffer readBuf = stream.getReadBuffer();
        int totalRead = drainStreamImmediately(streamSsl, streamId, "BIDI", stream, readBuf);

        if (totalRead > 0) {
            // Keep put mode (no flip). Data starts at position-totalRead.
            // Payload redacted (see drainStreamInto): size only.
            if (log.isDebugEnabled()) {
                log.debug("BIDI stream " + streamId + " pre-read " + totalRead +
                        " bytes into buffer");
            }
            // Do not dispatch here. The wrapper may not exist yet (created by
            // addPendingStreamToPollSet) or may be stale from a previous stream
            // that reused the same SSL address. The pre-read data is safe in the
            // stream's buffer and will be served by fillReadBufferDirect when
            // the stream is dispatched on the next poll iteration.
        }
    }


    /**
     * Reads client unidirectional stream data immediately after
     * SSL_accept_stream (same FIN race as {@link
     * #readBidiStreamImmediately}) and hands the buffered bytes to the
     * application protocol inline.
     */
    private void readUnidirectionalStreamImmediately(MemorySegment streamSsl, long streamId, QuicConnectionWrapper conn) {
        QuicStreamWrapper stream = locateImmediatelyReadableStream(streamId, conn);
        if (stream == null) {
            return;
        }

        ByteBuffer readBuf = stream.getReadBuffer();
        int totalRead = drainStreamImmediately(streamSsl, streamId, "UNI", stream, readBuf);

        if (totalRead > 0) {
            // Process pre-read data for client unidirectional streams.
            // The stream is identified by type (not by stream ID) inside
            // the manager (RFC 9114 Section 6.2.1, RFC 9204 Section 4.2,
            // RFC 9000 Section 2.1). Process the buffered bytes inline; the
            // native side effects and the read-interest re-arm run here on
            // the poll thread.
            QuicConnectionManager connManager = conn.getQuicConnectionManager();
            if (connManager != null) {
                // Payload redacted (see drainStreamInto): size only.
                if (log.isDebugEnabled()) {
                    log.debug("UNI stream " + streamId + " pre-read " + totalRead +
                            " bytes (buffer holds " + readBuf.position() + ")");
                }
                processUniStreamData(stream, conn, connManager);
            }
        }
    }


    /*
     * Maximum number of streams accepted from one connection per event, so
     * a flood cannot starve the rest of the poll set within one iteration.
     */
    private static final int MAX_ACCEPT_PER_EVENT = 40;


    /**
     * Accepts up to {@link #MAX_ACCEPT_PER_EVENT} pending incoming streams of
     * one direction from a connection, registering each via
     * {@link #processAcceptedStream}. When {@code readImmediately} is set the
     * stream data is pre-read right after acceptance, before any further
     * {@code SSL_handle_events()} can process the FIN packet and mark the
     * stream FINISHED with unread data still buffered.
     *
     * @param connSsl         The connection SSL
     * @param acceptFlag      {@code SSL_ACCEPT_STREAM_UNI} or {@code
     *                        SSL_ACCEPT_STREAM_BIDI} - a directional filter
     *                        honoured only by OpenSSL 4.x; a 3.5 library
     *                        ignores it and the pass may return either
     *                        direction (the immediate read below routes by
     *                        the observed stream type)
     * @param conn            The connection wrapper
     * @param logPrefix       Prefix for the per-stream debug log
     * @param readImmediately Whether to pre-read stream data immediately
     *
     * @return The number of streams accepted
     */
    private int acceptStreams(MemorySegment connSsl, long acceptFlag,
            QuicConnectionWrapper conn, String logPrefix,
            boolean readImmediately) {
        int accepted = 0;
        for (int attempt = 0; attempt < MAX_ACCEPT_PER_EVENT; attempt++) {
            if (!isConnectionLive(conn)) {
                // Inline protocol processing of a stream accepted in an
                // earlier iteration (readUnidirectionalStreamImmediately ->
                // processUniStreamData -> failConnection) tore the connection
                // down: its SSL is freed (or the free is deferred) and every
                // further native call below would run on freed memory.
                break;
            }
            MemorySegment streamSsl = QuicBindings.SSL_accept_stream(
                    connSsl, acceptFlag);
            if (streamSsl.equals(MemorySegment.NULL)) {
                break;
            }
            long[] streamInfo = new long[2];
            readStreamIdType(streamSsl, streamInfo);
            long sid = streamInfo[0];
            int stype = (int) streamInfo[1];
            if (log.isDebugEnabled()) {
                log.debug(logPrefix + " stream id=" + sid + " type=" + stype);
            }
            accepted++;
            processAcceptedStream(streamSsl, sid, stype, conn);
            if (readImmediately) {
                // Route by the observed stream type, not by the accept flag:
                // the directional filter of SSL_ACCEPT_STREAM_UNI/BIDI is
                // OpenSSL 4.x-only - a 3.5 library does not define the flags
                // and accepts the next pending stream of any direction, so a
                // pass can hand back a stream of the other direction than its
                // flag requested. Reading that stream through the path chosen
                // by the flag would feed bidirectional request bytes to the
                // unidirectional (control/QPACK) parser.
                if (stype == QuicPoll.SSL_STREAM_TYPE_BIDI) {
                    readBidiStreamImmediately(streamSsl, sid, conn);
                } else {
                    readUnidirectionalStreamImmediately(streamSsl, sid, conn);
                }
            }
        }
        return accepted;
    }


    /**
     * Drives the QUIC state machine for one object once.
     *
     * @param ssl The connection or stream SSL to pump
     */
    private void pumpEvents(MemorySegment ssl) {
        QuicBindings.SSL_handle_events(ssl);
    }


    /*
     * Reads the stream ID and type into out[0]/out[1].
     */
    private static void readStreamIdType(MemorySegment streamSsl, long[] out) {
        out[0] = QuicBindings.SSL_get_stream_id(streamSsl);
        out[1] = QuicBindings.SSL_get_stream_type(streamSsl);
    }


    /*
     * Creates a server-initiated unidirectional stream and reads its ID and
     * type into out[0]/out[1]. Returns the stream SSL, or NULL when the
     * stream could not be created (the peer has not yet advertised stream
     * capacity).
     */
    private MemorySegment newUniStream(MemorySegment connSsl, long[] out) {
        MemorySegment streamSsl = QuicBindings.SSL_new_stream(
                connSsl, QuicPoll.SSL_STREAM_FLAG_UNI);
        if (streamSsl.equals(MemorySegment.NULL)) {
            return MemorySegment.NULL;
        }
        readStreamIdType(streamSsl, out);
        return streamSsl;
    }


    /**
     * Writes a buffer's remaining bytes to a stream with a single
     * SSL_write_ex2() call (bound unconditionally: a library without it is
     * rejected by the {@code QUIC_AVAILABLE} probe before the endpoint
     * binds). This is the shared native write kernel used by the
     * connection wrapper's protocol writes, the poll-thread buffered flush
     * ({@link #flushServerUniStreamWrite}) and the socket wrapper's worker
     * write path (see {@code QuicOpenSSLSocketWrapper.writeChunk}).
     * <p>
     * The bytes reach the native call without a staging copy for direct
     * buffers (handed over in place); a heap buffer is staged with a single
     * bulk copy from its backing array - the bindings declare the buffer
     * parameter as a target-layout pointer (openssl_h.C_POINTER), and like
     * any downcall pointer argument it accepts native segments only, so a
     * heap segment cannot be handed over across the call. The buffer's
     * position is never consumed - callers anchor and advance it themselves.
     * <p>
     * Must be called on the poll thread with a live stream SSL object. A
     * caller hopped onto the poll thread must stay blocked while the call
     * runs (as {@code callOnPollThread} does), so a zero-copy handover cannot
     * see the buffer's content change underneath it.
     *
     * @param streamSsl The stream SSL to write to
     * @param data      The bytes to write; position untouched by this method
     * @param arena     Arena backing the native staging buffers
     * @return the number of bytes accepted by the stream - a prefix of
     *         {@code data}'s remaining bytes is possible (the endpoint's SSL
     *         context sets {@code SSL_MODE_ENABLE_PARTIAL_WRITE}, so the
     *         caller must advance/queue exactly the returned count), or
     *         {@code -1} if the stream accepted nothing (would-block or
     *         error; use SSL_get_error() on the stream SSL to tell the two
     *         apart). A {@code -1} never hides an accepted prefix: with
     *         partial writes enabled the all-or-nothing retry state that
     *         would demand the same buffer on the next call is never armed.
     */
    static int writeStreamData(MemorySegment streamSsl, ByteBuffer data, Arena arena) {
        int len = data.remaining();
        if (len == 0) {
            return 0;
        }
        MemorySegment dataSeg;
        if (data.hasArray()) {
            // One bulk copy from the backing array (the old code paid two:
            // get() into a fresh array, then a per-byte-array loop into the
            // staging segment).
            dataSeg = arena.allocate(ValueLayout.JAVA_BYTE, len);
            MemorySegment src = MemorySegment.ofArray(data.array())
                    .asSlice(data.arrayOffset() + data.position(), len);
            MemorySegment.copy(src, 0L, dataSeg, 0L, (long) len);
        } else if (data.isDirect() && !data.isReadOnly()) {
            dataSeg = MemorySegment.ofBuffer(data);
        } else {
            dataSeg = arena.allocate(ValueLayout.JAVA_BYTE, len);
            dataSeg.asByteBuffer().put(data.duplicate());
        }
        MemorySegment lenPtr = arena.allocate(ValueLayout.JAVA_LONG);
        lenPtr.set(ValueLayout.JAVA_LONG, 0, 0L);
        // SSL_write_ex2 is part of the probed symbol set: QUIC_AVAILABLE
        // rejects a library that lacks it before bind() succeeds, so every
        // endpoint that runs reaches this call with ex2 bound.
        int rc = QuicBindings.SSL_write_ex2(streamSsl, dataSeg, (long) len, 0L, lenPtr);
        if (rc != 1) {
            return -1;
        }
        return (int) lenPtr.get(ValueLayout.JAVA_LONG, 0);
    }


    /**
     * Endpoint-side entry guard: checks that a stream may still be touched, as
     * a single spelled-out condition so no poll-thread path re-invents its own
     * subset of "stream freed? connection closed/freed?". A stream is live when
     * it is present, has not been freed, and its connection is neither closed
     * nor freed - connection teardown frees the stream SSL objects, so a stream
     * whose connection is going away must not have its native object touched.
     * <p>
     * This is the counterpart of {@code QuicOpenSSLSocketWrapper.liveStream()}
     * (the wrapper-side guard used by the read/write paths); the endpoint also
     * checks the connection because its dispatch/flush/error handlers can be
     * reached for streams whose connection has begun closing.
     *
     * @param stream The stream to check (may be {@code null})
     *
     * @return {@code true} if the stream's native object may be used
     */
    private static boolean isStreamLive(QuicStreamWrapper stream) {
        if (stream == null || stream.isFreed()) {
            return false;
        }
        QuicConnectionWrapper conn = stream.getConnection();
        return conn == null || (!conn.isClosed() && !conn.isFreed());
    }


    /**
     * Reports whether a connection's native SSL may still be driven from the
     * poll thread. A connection whose teardown has begun is not live:
     * {@code teardownConnection()} frees (or defers the free of) the
     * connection SSL, so no further native call may run against it. Loops
     * that iterate over per-stream work must re-check this after every step
     * that can hand control to the application protocol, because an inline
     * protocol failure calls {@link #failConnection} - and with it the
     * teardown - underneath the loop.
     *
     * @param conn The connection to check (may be {@code null})
     *
     * @return {@code true} if the connection's native SSL may be used
     */
    private static boolean isConnectionLive(QuicConnectionWrapper conn) {
        return conn != null && !conn.isClosed() && !conn.isFreed();
    }


    /**
     * Tears down a QUIC connection: marks it closed, removes its stream
     * wrappers and streams, HTTP/3 state, connection map and poll-set
     * entries, then frees (or defers the free of) the connection SSL.
     *
     * @param conn              The connection to tear down
     * @param afterStreamsFreed Optional callback run after the stream SSL
     *            objects have been freed but before the connection SSL is
     *            freed (used to flush a queued CONNECTION_CLOSE)
     */
    private void teardownConnection(QuicConnectionWrapper conn, Runnable afterStreamsFreed) {
        assertNativeAccess("teardownConnection");
        conn.setClosed();
        // Remove the stream wrappers before closeAllStreams() clears the
        // stream map, otherwise they leak (see removeStreamWrappers()).
        removeStreamWrappers(conn);
        conn.closeAllStreams();
        if (afterStreamsFreed != null) {
            afterStreamsFreed.run();
        }
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        conn.setQuicConnectionManager(null);
        if (connManager != null) {
            connManager.connectionClose(conn);
        }
        setConnectionProtocolDataPending(conn, false);
        // Drops the retention entry right before the deferred drain and
        // CAS-guarded free below; closeAllStreams() above left no live
        // streams for a GC-thread Cleaner to race (see the connections
        // field javadoc).
        connections.remove(conn.getSslAddress());
        QuicPollItem removedItem = pollSet.remove(conn.getSslAddress());
        if (removedItem == null) {
            // The connection item may never have been promoted into the poll
            // set: bootstrapIncomingStreams() runs before the pollSet.add() in
            // handleIncomingConnection(), and inline stream processing there
            // can fail the connection (protocol error -> failConnection ->
            // this teardown). The poll set only disposes items it removes, so
            // release the item's native SSL_POLL_ITEM struct (and its shared
            // arena) here; abortConnectionSetup() reaches this fallback
            // through this method, deregisterStream() has its own. dispose()
            // is idempotent.
            QuicPollItem item = conn.getPollItem();
            if (item != null) {
                item.dispose();
            }
        }
        // Free stream SSL objects whose free closeAllStreams() / the workers
        // deferred, before dropping the connection reference: per
        // SSL_new_stream(3) every stream SSL must be freed first.
        drainPendingStreamFrees();
        freeConnectionOrDefer(conn);
    }


    private void processAcceptedStream(MemorySegment streamSsl, long streamId,
            int streamType, QuicConnectionWrapper conn) {
        if (log.isDebugEnabled()) {
            log.debug("Stream accepted: id=" + streamId + " type=" + streamType);
        }

        QuicStreamWrapper stream = new QuicStreamWrapper(
                 streamSsl, streamId, streamType, conn,
                 ByteBuffer.allocate(readBufferSize));

         // Reference: stream monitors ER | EW base events only.
         // R and W are managed separately via pe_resume_read/pe_pause_write.
        long events = QuicPoll.SSL_POLL_EVENT_ER |
                  QuicPoll.SSL_POLL_EVENT_EW;
        QuicPollItem streamItem = new QuicPollItem(streamSsl, events, stream);
        stream.setPollItem(streamItem);

        // Check the concurrent stream limit before tracking the stream: a
        // refused stream must not enter the connection's stream map, since
        // deregistration derives the active-stream decrement from map
        // membership (see deregisterAndReleaseStream()) and a refused stream
        // was never counted by incrementActiveStreams().
        if (streamType == QuicPoll.SSL_STREAM_TYPE_BIDI) {
            QuicConnectionManager connManager = conn.getQuicConnectionManager();
            if (connManager != null) {
                QuicConnectionManager.ConnectionState state = connManager.getState(conn);
                if (state != null && !state.canAcceptStream(streamId)) {
                    log.warn(sm.getString("quicEndpoint.streamLimitReached",
                                  Long.toHexString(conn.getSslAddress()),
                                  Long.valueOf(streamId)));
                          // Inform the client that no new streams will be
                          // accepted so it stops creating them (HTTP/3
                          // GOAWAY, RFC 9114 Section 7.2.6).
                    sendStreamLimitNotification(connManager, state);
                    // Tell the peer why this stream is refused BEFORE the
                    // stream SSL is freed: freeing without a prior reset
                    // makes OpenSSL emit a spurious error-0 (NO_ERROR)
                    // RESET_STREAM, which gives the client no signal to back
                    // off (resetStream warns if the reset itself fails).
                    resetStream(stream, getStreamRejectErrorCode());
                    // The abandoned stream owes the protocol its
                    // abandonment bookkeeping (for HTTP/3: a QPACK Stream
                    // Cancellation, RFC 9204 Section 2.2.2.2) even though no
                    // processor ever read a byte of it.
                    connManager.noteStreamRejected(conn, streamId);
                    // The stream was never tracked or counted: releasing it
                    // leaves the active-stream counter unchanged.
                    closeStreamByHandler(stream);
                    return;
                }
                state.incrementActiveStreams();
                state.setLastProcessedStreamId(streamId);
            }
        }

        conn.getStreams().put(streamId, stream);

        // Park the stream outside the poll set: it is promoted once the
        // server control stream exists (immediately below, or by
        // addPendingStreamsToPollSet), so stream events are only delivered
        // once the connection's HTTP/3 state (server control stream /
        // SETTINGS created via QuicConnectionManager) exists.
        conn.getPendingStreams().add(stream);

        if (streamType == QuicPoll.SSL_STREAM_TYPE_BIDI) {

                // If the primary server unidirectional stream already
                // exists, promote this stream immediately
            if (conn.getServerUniStream(0) != null) {
                conn.getPendingStreams().remove(stream);
                    // Pre-read stream data into buffer before adding to poll set,
                    // since processSocketInline will read from the buffer first.
                    // If we don't pre-read, SSL_handle_events may process FIN before data read.
                readBidiStreamImmediately(streamSsl, streamId, conn);
                addPendingStreamToPollSet(stream, streamItem);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Bidirectional stream " + streamId + " (read deferred, pending poll set)");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Unidirectional stream " + streamId + " (type=" + streamType + ", read deferred, pending poll set)");
            }
        }
    }


    /**
     * Reads data from an incoming unidirectional stream (client control, QPACK).
     * Reference: app_read_cb reads from the stream and processes the data.
     * Data is passed to QuicConnectionManager for control stream processing.
     */
    private void readUnidirectionalStream(QuicStreamWrapper stream, QuicPollItem item) {
        // Defensive: the stream's native SSL object may have been freed by
        // connection teardown before this dispatch ran.
        if (!isStreamLive(stream)) {
            return;
        }
        ByteBuffer readBuf = stream.getReadBuffer();
        if (readBuf == null) {
            return;
        }
        // Read buffer protocol (put mode, same as readBidiStreamImmediately):
        // buffered bytes occupy [0..position), limit == capacity. Any
        // unconsumed bytes from a previous read (partial frame or
        // instruction) were compacted to the start by that read; this
        // method compacts again before returning, so the buffer is never
        // observed in get mode here.
        MemorySegment ssl = stream.getSsl();

        // Drain fresh bytes only while the buffer has room. A full buffer
        // (remaining == 0 implies retained bytes fill it, the capacity is at
        // least MIN_READ_BUFFER_SIZE) is not a stall: the retained bytes are
        // processed below and the stream stays armed for the next R event.
        if (readBuf.remaining() > 0) {
            int read = drainStreamInto(stream, ssl, readBuf);
            if (read == 0 && stream.getReadState() == QuicStream.ReadState.FINISHED &&
                    log.isDebugEnabled()) {
                log.debug("Uni stream " + stream.getStreamId() + " finished (buffer holds " +
                        readBuf.position() + " bytes)");
            }
        }

        QuicConnectionWrapper conn = stream.getConnection();
        if (readBuf.position() > 0 && conn != null) {
            // Process the data (new and/or retained) for unidirectional-stream
            // processing: flips/compacts the buffer, runs the protocol, then
            // performs the native side effects - the decoder-instruction flush,
            // the server-stream creation request and the critical-stream closure
            // check - to fail the connection on a protocol error, and re-arms
            // read interest.
            QuicConnectionManager connManager = conn.getQuicConnectionManager();
            if (connManager != null) {
                processUniStreamData(stream, conn, connManager);
                return;
            }
        }

        // No data to process (e.g. a FIN-only event that carried no bytes): run
        // the closure check and finish or re-arm the stream synchronously.
        // Closure of a client stream the protocol marks as critical (for
        // HTTP/3 the control stream, RFC 9114 Section 6.2.1, and the QPACK
        // encoder/decoder streams, RFC 9204 Section 4.2) is a connection error.
        if (conn != null) {
            checkClientUniStreamClosed(stream, conn);
        }
        finishOrRearmUniStreamRead(stream, item);
    }


    /**
     * Terminates or re-asserts read (R) interest on a client unidirectional
     * stream after a read pass.
     * <p>
     * {@code dispatchStreamEvent} strips R before the stream is read and, per
     * {@code SSL_poll(3)}, events are level-triggered: a masked event is not
     * reported again until it is unmasked. Uni streams have no wrapper to
     * re-register interest (unlike BIDI streams), so every outcome that could
     * still deliver data must re-assert R here - the read may have been
     * skipped (buffer full), failed (native error) or returned no data while
     * unconsumed bytes remain buffered, and leaving R masked in those cases
     * silently stalls the stream (client control / QPACK encoder) until the
     * connection closes. A terminal read state (stream reset or connection
     * closed) has nothing left to deliver and leaves R masked.
     * <p>
     * A FINISHED stream whose buffer holds no unconsumed data is finished for
     * good and must not re-arm either: OpenSSL's R readiness latches once the
     * stream's receive part is totally read (quic_impl.c's
     * {@code test_poll_event_r} reports R unconditionally in
     * {@code QUIC_RSTREAM_STATE_DATA_READ}, and nothing clears it while the
     * XSO lives), so a re-armed R would fire on every poll iteration for the
     * connection's lifetime - a full engine tick, poll-set rebuild, SSL_poll
     * scan and native read round trip per iteration, counted as forward
     * progress so the no-progress backoff never engages. The FINISHED state
     * here already implies the confirming zero-return read happened (the
     * drain sets it on that read), so deregister the stream and free it
     * instead. (A stream the protocol marked critical was handled by
     * {@link #checkClientUniStreamClosed} before this call, which failed the
     * connection - the liveness guard then skips this path and the teardown
     * reaps the stream with the connection.)
     *
     * @param stream The client unidirectional stream
     * @param item   The stream's poll item
     */
    private void finishOrRearmUniStreamRead(QuicStreamWrapper stream, QuicPollItem item) {
        QuicStream.ReadState readState = stream.getReadState();
        if (readState == QuicStream.ReadState.RESET_LOCAL ||
                readState == QuicStream.ReadState.RESET_REMOTE ||
                readState == QuicStream.ReadState.CONN_CLOSED) {
            return;
        }
        if (readState == QuicStream.ReadState.FINISHED) {
            ByteBuffer readBuf = stream.getReadBuffer();
            if ((readBuf == null || readBuf.position() == 0) && isStreamLive(stream)) {
                // End of stream confirmed and the protocol consumed
                // everything it buffered: nothing can ever arrive again.
                closeStream(stream, true);
                return;
            }
        }
        item.setWantEvents(item.getWantEvents() | QuicPoll.SSL_POLL_EVENT_R);
    }


    /**
     * Runs the application protocol's unidirectional-stream processing
     * (HTTP/3 control-stream frame parsing and QPACK instruction /
     * dynamic-table work) for the data currently buffered (put mode,
     * {@code [0, position)}) in a client unidirectional stream's read buffer.
     * Called on the poll thread. The processing itself is pure Java, but it
     * runs inline here: every side effect it produces (the decoder-instruction
     * flush, the server-stream creation request, the critical-stream closure
     * check, failing the connection on a protocol error) is native work that
     * has to run on the poll thread anyway, and the measured protocol-only
     * cost is too small to justify dedicating a separate thread to it.
     *
     * @param stream      The client unidirectional stream
     * @param conn        The connection
     * @param connManager The connection's protocol connection manager
     */
    private void processUniStreamData(QuicStreamWrapper stream,
            QuicConnectionWrapper conn, QuicConnectionManager connManager) {
        ByteBuffer readBuf = stream.getReadBuffer();
        Throwable error = null;
        long errorCode = 0;
        readBuf.flip();
        try {
            connManager.processClientUniStreamData(conn, stream.getStreamId(), readBuf);
        } catch (Throwable t) {
            // Record the failure before handing the throwable to
            // handleThrowable(), which rethrows fatal VM errors: capturing it
            // first guarantees the completion below carries the error rather
            // than a spurious success if a fatal error unwinds this frame.
            error = t;
            errorCode = connManager.getProtocolErrorCode(t);
            ExceptionUtils.handleThrowable(t);
        }
        // Restore the put-mode invariant: unconsumed bytes (partial frame or
        // instruction) move back to the start for the next read.
        readBuf.compact();

        // The stream may have been reset while the protocol was running. In
        // that case nothing below is valid: the read buffer goes with the
        // stream, so simply return.
        if (!isStreamLive(stream)) {
            return;
        }

        if (error != null) {
            failConnection(conn, errorCode,
                    "Protocol connection error on stream " + stream.getStreamId());
            return;
        }

        connManager.flushPendingProtocolData(conn);
        // New client data may have advanced the protocol state (e.g. SETTINGS
        // arrival allows HTTP/3 to request the QPACK encoder/decoder streams):
        // let the OSU handler create the streams the protocol now wants.
        requestServerUniStreamEvent(conn);
        checkClientUniStreamClosed(stream, conn);

        QuicPollItem item = stream.getPollItem();
        if (item != null) {
            finishOrRearmUniStreamRead(stream, item);
        }
    }

    /**
     * Fails the connection if a client-initiated unidirectional stream was
     * cleanly closed after the protocol identified it as critical (for
     * HTTP/3 the control stream — RFC 9114 Section 6.2.1 — and the QPACK
     * encoder or decoder stream — RFC 9204 Section 4.2 — all of which make
     * closure a connection error of type H3_CLOSED_CRITICAL_STREAM, with
     * the exact code supplied by the protocol via
     * {@link QuicConnectionManager.ConnectionState#getClosedCriticalStreamErrorCode()}).
     * Streams that carried no data (and so have no identified type) are not
     * handled here.
     *
     * @param stream The client unidirectional stream
     * @param conn The QUIC connection
     */
    private void checkClientUniStreamClosed(QuicStreamWrapper stream, QuicConnectionWrapper conn) {
        if (stream.getReadState() != QuicStream.ReadState.FINISHED) {
            return;
        }
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null) {
            return;
        }
        QuicConnectionManager.ConnectionState state = connManager.getState(conn);
        if (state == null) {
            return;
        }
        if (state.isCriticalClientUniStream(stream.getStreamId())) {
            log.warn(sm.getString("quicEndpoint.criticalStreamClosed",
                    Long.valueOf(stream.getStreamId())));
            failConnection(conn, state.getClosedCriticalStreamErrorCode(),
                    "Client closed critical unidirectional stream " +
                    stream.getStreamId());
        }
    }


  /**
   * Accepts any pending bidirectional and unidirectional streams on a connection.
   * Called on every poll iteration to ensure no streams are missed.
   */
    private void acceptPendingBidiStreams(QuicPollItem connItem, QuicConnectionWrapper conn) throws Exception {
        int accepted = acceptStreams(connItem.getSsl(),
                  QuicPoll.SSL_ACCEPT_STREAM_UNI, conn,
                  "acceptPendingStreams: accepted UNI", false) +
                  acceptStreams(connItem.getSsl(),
                  QuicPoll.SSL_ACCEPT_STREAM_BIDI, conn,
                  "acceptPendingStreams: accepted BIDI", false);
        if (accepted > 0) {
            if (log.isDebugEnabled()) {
                log.debug("acceptPendingBidiStreams: accepted " + accepted + " stream(s)");
            }
              // After accepting client streams, request OSU to create any
              // server streams the protocol now wants
            requestServerUniStreamEvent(conn);
        }
    }


    private void handleOutgoingStream(QuicPollItem connItem) throws Exception {
        QuicConnectionWrapper conn = (QuicConnectionWrapper) connItem.getAppData();
        if (conn == null) {
            return;
        }

        if (!ensureServedProtocol(conn)) {
            return;
        }

        // Create every server-initiated unidirectional stream the
        // application protocol currently requires (for HTTP/3: control/
        // SETTINGS, then the QPACK encoder/decoder streams after the
        // client's SETTINGS have been received). The protocol decides which
        // streams to create and what to write on them; the endpoint only
        // provides the stream-creation mechanics.
        createServerUniStreams(connItem, conn);

        // When the protocol has no further server unidirectional stream
        // pending, stop asking for the OSU/OSB events (they are re-added by
        // requestServerUniStreamEvent() when new client data may advance the
        // protocol state).
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null || connManager.nextServerUniStream(conn) < 0) {
            long currentEvents = connItem.getWantEvents();
            currentEvents &= ~QuicPoll.SSL_POLL_EVENT_OSU;
            currentEvents &= ~QuicPoll.SSL_POLL_EVENT_OSB;
            connItem.setWantEvents(currentEvents);
        }
    }


    /**
     * Registers an outgoing stream for lifecycle management.
     *
     * @param serverUniIndex The protocol-assigned server unidirectional
     *        stream index, or {@code -1} if this is not a server
     *        unidirectional stream
     */
    private QuicStreamWrapper registerOutgoingStream(MemorySegment streamSsl, long streamId, int streamType,
            QuicConnectionWrapper conn, int serverUniIndex) {
        QuicStreamWrapper stream = new QuicStreamWrapper(
                streamSsl, streamId, streamType, conn,
                ByteBuffer.allocate(readBufferSize));
        if (serverUniIndex >= 0) {
            conn.registerServerUniStream(serverUniIndex, stream);
            if (serverUniIndex == 0) {
                // Index 0 is the primary stream the endpoint writes its own
                // protocol data on (for HTTP/3 the control stream).
                stream.setPrimaryUniStream(true);
            }
        }
        long events = QuicPoll.SSL_POLL_EVENT_ER |
                QuicPoll.SSL_POLL_EVENT_EW |
                QuicPoll.SSL_POLL_EVENT_W;
        QuicPollItem streamItem = new QuicPollItem(streamSsl, events, stream);
        stream.setPollItem(streamItem);
        conn.getStreams().put(streamId, stream);
        pollSet.add(streamItem);
        return stream;
    }


    /**
     * Enables read on all client unidirectional streams for a connection.
     * Called after the server's own unidirectional streams (control, QPACK
     * encoder/decoder) are created, so the server's SETTINGS (RFC 9114
     * Section 7.2.4 requires them to be sent immediately after connection
     * establishment) are on the wire before client stream data is handled.
     * The ordering is an implementation choice, not an RFC requirement.
     */
    private void enableReadOnClientUnidirectionalStreams(QuicConnectionWrapper conn) {
        for (QuicStreamWrapper stream : conn.getStreams().values()) {
             // Only enable read on client-initiated unidirectional streams
             // (type=1 means SSL_STREAM_TYPE_READ, i.e., client-to-server).
             // Server-initiated unidirectional streams are WRITE-typed and
             // are skipped by that check.
            if (stream.getStreamType() == QuicPoll.SSL_STREAM_TYPE_READ) {
                QuicPollItem item = stream.getPollItem();
                if (item != null) {
                    long events = item.getWantEvents();
                    events |= QuicPoll.SSL_POLL_EVENT_R;
                    item.setWantEvents(events);
                    if (log.isDebugEnabled()) {
                        log.debug("Enabled read on client uni stream " + stream.getStreamId());
                    }
                }
            }
        }
    }


      /**
       * Adds a single pending stream to the poll set. BIDI (request) streams
       * additionally get a socket wrapper and their read interest armed; UNI
       * streams keep the base ER | EW interest they were created with (read
       * is enabled separately by
       * {@link #enableReadOnClientUnidirectionalStreams}).
       */
    private void addPendingStreamToPollSet(QuicStreamWrapper stream, QuicPollItem streamItem) {
        boolean bidi = stream.getStreamType() == QuicPoll.SSL_STREAM_TYPE_BIDI;
        if (bidi) {
            // Set want_events BEFORE adding to poll set. Only pollable
            // interests are requested; the failure flag (SSL_POLL_EVENT_F)
            // is a poll result, not a pollable interest, and per
            // SSL_poll(3) is raised regardless of want_events.
            long events = QuicPoll.SSL_POLL_EVENT_R |
                    QuicPoll.SSL_POLL_EVENT_W |
                    QuicPoll.SSL_POLL_EVENT_RE |
                    QuicPoll.SSL_POLL_EVENT_WE;
            streamItem.setWantEvents(events);
        }
        pollSet.add(streamItem);
        if (!bidi) {
            if (log.isDebugEnabled()) {
                log.debug("Adding UNI stream " + stream.getStreamId() + " to poll set");
            }
            return;
        }
        QuicOpenSSLSocketWrapper wrapper = new QuicOpenSSLSocketWrapper(stream, this);
        // Wire the connector-configured socket timeouts into the wrapper so
        // its blocking reads and writes honour them, as the NIO endpoints do
        // for their stream/socket wrappers.
        wrapper.setReadTimeout(getConnectionTimeout());
        wrapper.setWriteTimeout(getConnectionTimeout());
        streamWrappers.put(stream.getSslAddress(), wrapper);
        if (log.isDebugEnabled()) {
            log.debug("Adding BIDI stream " + stream.getStreamId() + " to poll set");
        }

        // Dispatch any buffered request data immediately if either
        // pre-read data is present or the client's SETTINGS have
        // already been received. Pre-read BIDI stream data sits in
        // the wrapper's read buffer, not in OpenSSL, so SSL_poll
        // will never report a read event for it: without an
        // immediate dispatch the data would sit unread until the
        // client sends more data or ends the stream. When the read
        // buffer is empty the R event fires when data becomes
        // readable (or the stream ends) and dispatchStreamEvent()
        // handles it. RFC 9114 does not require waiting for the
        // client's SETTINGS before processing request streams; that
        // check is only an optimisation to avoid one extra poll
        // round.
        boolean canDispatch = hasBufferedReadData(stream.getReadBuffer());
        QuicConnectionWrapper conn = stream.getConnection();
        if (conn != null) {
            QuicConnectionManager connManager = conn.getQuicConnectionManager();
            if (connManager != null) {
                QuicConnectionManager.ConnectionState state = connManager.getState(conn);
                if (state != null && state.isClientSettingsReceived()) {
                    canDispatch = true;
                }
            }
        }
        if (canDispatch) {
            if (stream.compareAndSetProcessing(false, true)) {
                dispatchToExecutor(wrapper, stream, SocketEvent.OPEN_READ, true);
            } else {
                // Claim lost - unexpected for a freshly promoted stream, but
                // the drop must not rely on that: dispatchToExecutor would
                // return silently and the pre-read bytes would sit in the
                // Java-side read buffer (no SSL_poll R event, see above)
                // until some later native event re-triggered the stream.
                // Hand the event to the bounded claim retry instead, the same
                // recovery the terminal ERROR dispatch uses, which re-claims
                // and never leaves the buffer to a future event.
                scheduleStreamDispatch(wrapper, stream, SocketEvent.OPEN_READ);
            }
        }
    }


    /**
     * Checks whether the stream read buffer holds bytes that have not
     * been served to a processor yet.
     * <p>
     * Read buffer protocol: the buffer is always in put mode between reads -
     * buffered bytes occupy [0, position) with limit == capacity. The flip
     * needed to consume data is always paired with a {@code compact()}
     * before the consuming method returns, so no mode detection is needed
     * here.
     */
    private static boolean hasBufferedReadData(ByteBuffer buffer) {
        return buffer != null && buffer.position() > 0;
    }


    /**
     * Promotes every parked stream of a connection into the poll set once the
     * server control stream has been created. Streams are parked until then
     * (see {@code QuicConnectionWrapper.getPendingStreams()}), so stream
     * events are only delivered once the HTTP/3 connection state (server
     * control stream / SETTINGS) exists.
     */
    private void addPendingStreamsToPollSet(QuicConnectionWrapper conn) {
        int added = 0;
        for (QuicStreamWrapper stream : conn.getPendingStreams()) {
            QuicPollItem streamItem = stream.getPollItem();
            if (streamItem != null) {
                addPendingStreamToPollSet(stream, streamItem);
                added++;
            }
        }
        conn.getPendingStreams().clear();
        if (added > 0) {
            if (log.isDebugEnabled()) {
                log.debug("Added " + added + " pending stream(s) to poll set");
            }
        }
        // Enable read on the client's unidirectional streams. The OSU
        // handler does the same when it creates the server streams, but if
        // the server streams were created by the early path (or already
        // exist when late client streams are promoted), no OSU event is
        // ever requested and the read interest would never be set: the
        // client's SETTINGS and QPACK instructions would sit unread
        // forever. Enabling it here is idempotent.
        enableReadOnClientUnidirectionalStreams(conn);
    }


    private void dispatchStreamEvent(QuicPollItem item, SocketEvent event) {
        // The poll loop routes any item with R/W that has no IC/IS/OS/CC
        // counterpart here. Connection poll items (app data =
        // QuicConnectionWrapper, requested with the all-events want mask)
        // have no stream-level R/W meaning in no-default-stream mode, so a
        // stray R/W report on one must be ignored. An unchecked cast would
        // turn such a report into a ClassCastException on every poll
        // iteration while the condition lasts - a spinning warn generator.
        if (!(item.getAppData() instanceof QuicStreamWrapper stream)) {
            if (log.isDebugEnabled()) {
                Object appData = item.getAppData();
                log.debug("Ignoring stream event " + event + " for poll item "
                        + "with app data " + (appData == null ? "null"
                                : appData.getClass().getSimpleName()));
            }
            return;
        }
        // Defensive: the stream (or its connection) may have been torn down
        // after this item was observed by the poll loop. The native SSL
        // object may already be freed - never touch it in that case.
        if (!isStreamLive(stream)) {
            return;
        }
        QuicConnectionWrapper conn = stream.getConnection();
        if (conn == null || !ensureServedProtocol(conn)) {
            return;
        }
        long streamId = stream.getStreamId();
        if (log.isDebugEnabled()) {
            log.debug("dispatchStreamEvent: streamId=" + streamId + " event=" + event + " type=" + stream.getStreamType());
        }

        QuicOpenSSLSocketWrapper wrapper = streamWrappers.get(stream.getSslAddress());

        // Remove R/W from want_events to prevent tight loop.
        // Handler will re-register interest via registerReadInterest()/registerWriteInterest()
        // if it needs more I/O. Reference: pe_disable_read/pe_disable_write after processing.
        // Exception: while a worker is parked on the wrapper's event-driven
        // wake-up (a synchronous read/write blocked in the handler), keep that
        // direction's interest armed. OpenSSL reports R/W level-triggered from
        // the current stream state, so the event re-fires on every poll
        // iteration while the condition holds and the worker is signalled
        // each time; a signal that races the worker's registration therefore
        // cannot be lost. Once the worker consumes the data (or the window
        // closes), the condition goes quiet and the interest stops firing.
        long current = item.getWantEvents();
        long strip = QuicPoll.SSL_POLL_EVENT_R | QuicPoll.SSL_POLL_EVENT_W;
        if (wrapper != null) {
            // Each parked direction keeps *its own* interest regardless of
            // which direction is being dispatched: a worker parked in
            // awaitWritable needs the level-triggered W re-report as its wake
            // even when an unrelated R event fires while it is parked (and
            // symmetrically for the reader) - stripping the other direction
            // here would disarm it with nothing to re-arm it before the
            // waiter's deadline, turning a prompt wake into a stall-then-
            // timeout.
            if (wrapper.hasReadWaiter()) {
                strip &= ~QuicPoll.SSL_POLL_EVENT_R;
            }
            if (wrapper.hasWriteWaiter()) {
                strip &= ~QuicPoll.SSL_POLL_EVENT_W;
            }
        }
        item.setWantEvents(current & ~strip);

        // Pre-read whatever the stream can deliver right now into the
        // wrapper's socket read buffer, so the handler's first reads are
        // served from Java memory instead of a poll-thread hop per read
        // call. Gated on the stream being idle: while a waiter is parked or
        // a worker is inside the handler, the worker's own read machinery
        // owns the read buffer (poll-thread fills only ever happen inside a
        // hop the worker is parked on) - prefetching then would race the
        // worker's reads.
        if (wrapper != null && event == SocketEvent.OPEN_READ &&
                !wrapper.hasReadWaiter() && !stream.isProcessing()) {
            prefetchStreamData(wrapper, stream);
        }

        // Release a worker parked in awaitReadableData/awaitWritable for this
        // stream. This must happen regardless of whether the dispatch below
        // is claimed by the running handler (it is not, while the same
        // handler blocks in a synchronous read or write).
        if (wrapper != null) {
            if (event == SocketEvent.OPEN_READ) {
                wrapper.signalReadWaiter();
            } else if (event == SocketEvent.OPEN_WRITE) {
                wrapper.signalWriteWaiter();
            }
        }

        if (wrapper == null) {
            // For server-initiated unidirectional streams (e.g. the HTTP/3
            // control stream) with buffered protocol data, retry the write
            // now that the stream is writable
            if (stream.isPrimaryUniStream() && event == SocketEvent.OPEN_WRITE) {
                flushServerUniStreamWrite(stream, item);
                return;
            }
            if (event == SocketEvent.OPEN_WRITE && stream.getWriteBuffer() != null &&
                    stream.getWriteBuffer().hasRemaining()) {
                flushServerUniStreamWrite(stream, item);
                return;
            }
            // For incoming unidirectional streams (client control, QPACK), read and process data
            if (stream.isReadable() && event == SocketEvent.OPEN_READ) {
                readUnidirectionalStream(stream, item);
                return;
            }
            // Uni-directional streams - no HTTP handler
            return;
        }

        // No gating here: every readable/writable BIDI stream event is
        // dispatched. Streams added to the poll set before the client's
        // SETTINGS arrived are served by their R event; clients that never
        // send a control stream at all (non-conformant, but observed in the
        // wild) still get responses.

        dispatchToExecutor(wrapper, stream, event);
    }


    /**
     * Moves whatever the stream's QUIC receive buffer holds into the
     * wrapper's socket read buffer, so a subsequent read on the worker thread
     * is served from Java memory without a poll-thread hop. Called on the
     * poll thread from {@link #dispatchStreamEvent(QuicPollItem, SocketEvent)}
     * for readable bidirectional streams whose handler is not already
     * running (see the gating discussion there).
     * <p>
     * Byte order across the two buffers is preserved: bytes left in the
     * stream's own pre-read buffer (filled on the accept path) are handed
     * over first, fresh native data is drained behind them. Both buffers use
     * the put-mode protocol ({@code [0, position)} occupied, limit ==
     * capacity); the socket buffer is left in write mode so the wrapper's
     * {@code populateReadBuffer} flips it for the worker.
     *
     * @param wrapper The stream's socket wrapper
     * @param stream  The stream
     */
    private void prefetchStreamData(QuicOpenSSLSocketWrapper wrapper,
            QuicStreamWrapper stream) {
        SocketBufferHandler socketBufferHandler = wrapper.getSocketBufferHandler();
        ByteBuffer socketBuf = socketBufferHandler.getReadBuffer();
        socketBufferHandler.configureReadBufferForWrite();
        if (!socketBuf.hasRemaining()) {
            return;
        }
        // Hand over leftovers from the stream's own pre-read buffer first.
        ByteBuffer streamBuf = stream.getReadBuffer();
        if (streamBuf != null) {
            QuicStreamWrapper.transferPutMode(streamBuf, socketBuf);
            if (streamBuf.position() > 0) {
                // The socket read buffer could not take everything; the rest
                // stays for the fillReadBufferDirect pre-read branch, which
                // serves it before any fresh native read.
                return;
            }
        }
        // Drain fresh native data while the wrapper buffer still has room.
        if (socketBuf.hasRemaining() && isStreamLive(stream)) {
            drainStreamInto(stream, stream.getSsl(), socketBuf);
        }
    }


    /**
     * Dispatches a stream event to the HTTP handler. The handler (and the
     * servlet it runs) executes on an executor worker thread so that one slow
     * request cannot block the poll thread and stall every other connection.
     * <p>
     * OpenSSL QUIC is not thread-safe for concurrent access to a connection,
     * so every native QUIC operation the handler triggers (SSL_read_ex,
     * SSL_write_ex, SSL_handle_events, poll-set mutations, SSL frees) is
     * hopped back to the poll thread via {@link #submitPollTask}; the poll loop
     * drains those hops on every iteration. The worker therefore only ever
     * blocks for the duration of one fast native operation, never for the
     * whole request.
     * <p>
     * The processing flag prevents concurrent dispatches of the same stream.
     * Multiple R/W events can fire for the same stream simultaneously; only
     * the first one dispatches, the rest are served when the processor
     * re-registers interest via registerReadInterest()/registerWriteInterest().
     */
    private void dispatchToExecutor(QuicOpenSSLSocketWrapper wrapper,
            QuicStreamWrapper stream, SocketEvent event) {
        dispatchToExecutor(wrapper, stream, event, false);
    }

    /**
     * Dispatches the given event for the stream to the protocol executor,
     * optionally taking over ownership of the stream's processing flag from
     * the caller.
     *
     * @param flagClaimed {@code true} if the caller has already claimed the
     *            stream's processing flag and must hand it over with this
     *            dispatch (used to chain dispatches that must not be dropped
     *            because no later event will re-trigger them)
     */
    private void dispatchToExecutor(QuicOpenSSLSocketWrapper wrapper,
            QuicStreamWrapper stream, SocketEvent event, boolean flagClaimed) {
        if (!flagClaimed && !stream.compareAndSetProcessing(false, true)) {
            return;
        }
        QuicConnectionWrapper conn = stream.getConnection();
        if (conn != null) {
            conn.incrActiveHandlers();
        }
        if (log.isDebugEnabled()) {
            log.debug("Dispatching stream event: streamId=" + stream.getStreamId()
                    + " event=" + event);
        }
        Runnable dispatch = () -> runStreamDispatch(wrapper, stream, conn, event, true);
        java.util.concurrent.Executor executor = (running && conn != null) ?
                getExecutor() : null;
        if (executor == null) {
            // No executor available (shutting down or no connection): process
            // inline on the poll thread as before.
            dispatch.run();
        } else {
            try {
                executor.execute(dispatch);
            } catch (java.util.concurrent.RejectedExecutionException ree) {
                // A rejecting pool will never run the task, so the claimed
                // processing flag and the active-handler increment have to be
                // released here. The handler must NOT run inline: a full
                // request on the poll thread stalls every other connection on
                // the endpoint. Treat the overload as fatal for this
                // connection and close it without any further processing. A
                // connection that is already closing (this dispatch comes from
                // the teardown wake-up, or the failure above raced with one)
                // is already going away; releasing the claim is all that is
                // left to do there.
                log.warn(sm.getString("quicEndpoint.dispatchRejected",
                        Long.valueOf(stream.getStreamId())), ree);
                stream.clearProcessing();
                conn.decrActiveHandlers();
                if (!conn.isClosing() && !conn.isClosed()) {
                    failConnection(conn, getConnectionRejectErrorCode(),
                            "Executor rejected the dispatch for stream " +
                                    Long.valueOf(stream.getStreamId()));
                }
            }
        }
    }


    /**
     * Runs one dispatch of the HTTP handler for a stream the caller has
     * claimed. The stream's processing flag must be set on entry (held by the
     * caller for the duration of this call); it is cleared here, followed by
     * the dispatch-completion accounting (see
     * {@link #finishStreamDispatch(QuicStreamWrapper, QuicConnectionWrapper,
     * boolean)}). Both stream-dispatch paths funnel through this method so
     * the handler invocation sequence, the claim release ordering and the
     * active-handler accounting have a single owner: the poll path (through
     * the {@link #dispatchToExecutor} lambda, {@code longRearm} {@code
     * true}) and the processor-driven async re-dispatch path (through
     * {@code QuicSocketProcessor.doRun()}, {@code longRearm} {@code false}
     * - currently unreached scaffolding, see that class' comment).
     *
     * @param longRearm {@code true} for poll-path dispatches, where a LONG
     *            return means the processor wants to keep the stream open for
     *            more I/O: pending non-blocking writes are drained and read
     *            interest is re-registered so the next poll iteration
     *            dispatches. Async re-dispatch events do not drive read
     *            interest and pass {@code false}.
     */
    private void runStreamDispatch(QuicOpenSSLSocketWrapper wrapper,
            QuicStreamWrapper stream, QuicConnectionWrapper conn,
            SocketEvent event, boolean longRearm) {
        try {
            AbstractEndpoint.Handler.SocketState state = processSocketInline(wrapper, event);
            if (log.isDebugEnabled()) {
                log.debug("processSocketInline returned: streamId=" + stream.getStreamId()
                        + " state=" + state);
            }
            if (longRearm && state == AbstractEndpoint.Handler.SocketState.LONG) {
                // Drain write data that non-blocking writes (trailers, error
                // responses, early hints) may have left in the buffer. When
                // their re-armed W event fired, process() above returned LONG
                // without flushing, so without this the data would sit in the
                // buffer forever and W would never be re-armed.
                // doWrite() re-arms W itself if data remains.
                try {
                    wrapper.flushNonBlocking();
                } catch (IOException ioe) {
                    if (log.isDebugEnabled()) {
                        log.debug("Pending write flush failed on stream " +
                                stream.getStreamId(), ioe);
                    }
                }
                // Processor wants to keep the stream open for more I/O.
                // Re-register read interest so the next poll iteration dispatches.
                wrapper.registerReadInterest();
            }
        } finally {
            // Clear the processing flag BEFORE the connection's active handler
            // count is decremented: once this flag is clear, the poll thread
            // may tear the stream down, so no native operation may follow.
            stream.clearProcessing();
            finishStreamDispatch(stream, conn, true);
        }
    }


    /**
     * Completes a stream dispatch: decrements the connection's active handler
     * count and performs any native frees that the poll thread had to defer
     * while a worker was still running.
     *
     * @param stream            The stream that was dispatched (may be null)
     * @param conn              The stream's connection
     * @param completedDispatch {@code true} if the caller actually owned the
     *            stream's processing flag for this dispatch; only that dispatch
     *            may complete a deferred stream SSL free, since the poll thread
     *            deferred it to the worker that held the flag
     */
    private void finishStreamDispatch(QuicStreamWrapper stream,
            QuicConnectionWrapper conn, boolean completedDispatch) {
        if (conn == null) {
            return;
        }
        if (completedDispatch && stream.isDeregistered() && !stream.isFreed()) {
            // The poll thread deregistered this stream while this worker was
            // active and deferred the stream SSL free; complete it now that
            // the worker no longer touches the native object. The free is
            // queued so it runs after the next SSL_poll() flush has given any
            // pending RESET_STREAM a chance to reach the network. This must
            // happen regardless of the connection state: a closing
            // connection's closeAllStreams() skips streams whose handler is
            // still running, and per SSL_new_stream(3) every stream SSL must
            // be freed before the connection SSL - skipping the queue here
            // leaked the stream XSO (which holds a reference on the
            // connection) and with it the whole connection.
            mailbox.queueStreamFree(stream);
        }
        int remaining = conn.decrActiveHandlers();
        if (remaining == 0 && conn.clearPendingFree()) {
            // Last worker on a connection whose SSL free the poll thread
            // deferred (teardown, or a stop that found a handler still
            // running): free it now, on the poll thread, after draining the
            // deferred stream frees so every stream SSL is gone before the
            // connection SSL reference is dropped. Dropping the wrapper from
            // the stop-time retention set (no-op before any stop) lets it go
            // once its native objects are gone. A rejection (mailbox closed,
            // endpoint stopped) leaves the free to the startInternal sweep,
            // which completes pending frees of retained connections whose
            // handler count has reached zero; the wrapper stays retained
            // until then, so its Cleaner cannot free the connection SSL
            // under a live stream reference.
            if (!submitPollTask(() -> {
                drainPendingStreamFrees();
                conn.freeSslOnce();
                stoppedBusyConnections.remove(conn);
            })) {
                if (log.isDebugEnabled()) {
                    log.debug("Connection SSL 0x" +
                            Long.toHexString(conn.getSslAddress()) +
                            " deferred free rejected (endpoint stopped);" +
                            " completing it at the next start");
                }
            }
        }
    }


    /**
     * Processes a socket event through the HTTP handler. May run on the poll
     * thread (inline fallback, connection teardown) or on an executor worker
     * thread; native QUIC operations are hopped to the poll thread by the
     * socket wrapper either way.
     */
    private AbstractEndpoint.Handler.SocketState processSocketInline(QuicOpenSSLSocketWrapper wrapper, SocketEvent event) {
        AbstractEndpoint.Handler.SocketState state = AbstractEndpoint.Handler.SocketState.CLOSED;

        if (!wrapper.isClosed()) {
            try {
                wrapper.checkError();
            } catch (IOException x) {
                event = SocketEvent.ERROR;
                wrapper.setError(x);
                log.error(sm.getString("quicEndpoint.socketCheckError"), x);
            }
        }

        Handler<QuicStream> handler = getHandler();
        if (handler != null) {
            try {
                state = handler.process(wrapper, event);
                if (state == AbstractEndpoint.Handler.SocketState.CLOSED ||
                        state == AbstractEndpoint.Handler.SocketState.SUSPENDED) {
                    wrapper.close();
                }
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.error(sm.getString("quicEndpoint.handlerProcessError"), t);
                wrapper.close();
                state = AbstractEndpoint.Handler.SocketState.CLOSED;
            }
        }
        return state;
    }


    /**
     * Sends the protocol's stream retirement notification on the primary
     * server unidirectional stream (index 0) when the concurrent stream
     * limit is reached, so the client stops creating new streams (for
     * HTTP/3 the GOAWAY frame, RFC 9114 Section 7.2.6). When the frame
     * cannot be written immediately it is appended to the stream's write
     * buffer, which the W event handler
     * ({@link #flushServerUniStreamWrite}) retries.
     *
     * @param connManager The connection's protocol manager
     * @param state The connection state
     */
    private void sendStreamLimitNotification(QuicConnectionManager connManager,
            QuicConnectionManager.ConnectionState state) {
        try {
            QuicConnectionWrapper conn = (QuicConnectionWrapper) state.getConnection();
            QuicStreamWrapper primaryStream = conn.getServerUniStream(0);
            if (primaryStream == null) {
                return;
            }
            // getStreamLimitFrame derives the RFC 9114 Section 5.2
            // identifier from the last processed stream ID (a negative
            // one - no request stream ever accepted on this connection,
            // the limit was reached on the very first stream - becomes
            // identifier 0, "no streams processed") and clamps it against
            // the identifier of any GOAWAY previously sent on the
            // connection.
            ByteBuffer limitFrame = connManager.getStreamLimitFrame(
                    state, state.getLastProcessedStreamId());
            byte[] data = new byte[limitFrame.remaining()];
            limitFrame.get(data);

            // Append the frame to the stream's write buffer (behind anything
            // already pending, preserving wire order) and drive the shared
            // buffered-write path. If the retries run out the frame stays
            // buffered and the W event handler retries the write.
            ByteBuffer existing = primaryStream.getWriteBuffer();
            if (existing != null && existing.hasRemaining()) {
                ByteBuffer combined = ByteBuffer.allocate(existing.remaining() + data.length);
                combined.put(existing);
                combined.put(data);
                combined.flip();
                primaryStream.setWriteBuffer(combined);
            } else {
                primaryStream.setWriteBuffer(ByteBuffer.wrap(data));
            }
            writeBufferedUniStream(conn.getSsl(), primaryStream);
            if (log.isDebugEnabled()) {
                log.debug("Stream limit notification sent, lastStreamId=" +
                        state.getLastProcessedStreamId());
            }
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("Error sending stream limit notification", t);
            }
        }
    }


    /**
     * Outcome of one buffered server unidirectional stream write attempt
     * (see {@link #flushServerUniStreamWrite}).
     */
    private enum UniStreamWriteResult {
        /** Buffer fully delivered (or nothing was buffered). */
        DONE,
        /** Data remains buffered and the stream may still accept it. */
        RETRY,
        /** Data remains buffered but the stream can no longer accept it. */
        FAILED
    }


    /**
     * Makes one attempt to flush the buffered protocol data (init bytes or a
     * stream limit notification) of a server-initiated unidirectional stream,
     * updating the stream's poll interest to match the outcome. Used both
     * when a W event fires and, driven by the retry loop of
     * {@link #writeBufferedUniStream}, right after connection acceptance, so
     * the two paths classify a failed {@code SSL_write_ex()} identically.
     *
     * @return the outcome of the write attempt
     */
    private UniStreamWriteResult flushServerUniStreamWrite(QuicStreamWrapper stream,
            QuicPollItem item) {
        // Defensive: the stream's native SSL object may have been freed by
        // connection teardown before this dispatch ran.
        if (!isStreamLive(stream)) {
            return UniStreamWriteResult.FAILED;
        }
        if (log.isDebugEnabled()) {
            log.debug("flushServerUniStreamWrite: streamId=" + stream.getStreamId() +
                    " writeBuffer=" + (stream.getWriteBuffer() != null && stream.getWriteBuffer().hasRemaining()));
        }
        try (Arena localArena = Arena.ofConfined()) {
            ByteBuffer writeBuf = stream.getWriteBuffer();
            if (writeBuf == null || !writeBuf.hasRemaining()) {
                // Nothing to write. The primary server unidirectional stream
                // (for HTTP/3 the control stream, RFC 9114 Section 4.3.1)
                // stays open for the connection lifetime.
                // Remove W event since nothing left to write
                long events = item.getWantEvents();
                events &= ~QuicPoll.SSL_POLL_EVENT_W;
                item.setWantEvents(events);
                return UniStreamWriteResult.DONE;
            }

            // Anchor progress at the current position: a reset to 0 would
            // re-queue bytes a previous partial flush already delivered, and
            // the retry would send them again - duplicated bytes on the wire.
            // The kernel does not consume the buffer's position; this method
            // advances it by the accepted count below.
            int savedPos = writeBuf.position();

            int rc = writeStreamData(stream.getSsl(), writeBuf, localArena);
            if (rc >= 0) {
                long written = rc;
                if (log.isDebugEnabled()) {
                    log.debug("Server unidirectional stream wrote " + written + " bytes");
                }
                writeBuf.position(savedPos + (int) written);
                if (writeBuf.hasRemaining()) {
                    // Partial write - retry remaining on next W event
                    long events = item.getWantEvents();
                    events |= QuicPoll.SSL_POLL_EVENT_W;
                    item.setWantEvents(events);
                    return UniStreamWriteResult.RETRY;
                }
                // All data written - remove W event, stream stays open
                long events = item.getWantEvents();
                events &= ~QuicPoll.SSL_POLL_EVENT_W;
                item.setWantEvents(events);
                stream.setWriteBuffer(null);
                return UniStreamWriteResult.DONE;
            }

            // The rejected ex-call returns 0, which alone is ambiguous:
            // SSL_get_error() says whether the stream merely lacks peer
            // credit/ACKs (a transient state while stream credit settles, or
            // a connection the peer is tearing down) or the write really
            // failed; the stream write state says whether the stream can
            // accept these bytes at all any more.
            int sslError = QuicBindings.SSL_get_error(stream.getSsl(), 0);
            int writeState = QuicBindings.SSL_get_stream_write_state(stream.getSsl());
            boolean wantMore = sslError == QuicBindings.SSL_ERROR_WANT_READ ||
                    sslError == QuicBindings.SSL_ERROR_WANT_WRITE;
            if (wantMore) {
                if (log.isDebugEnabled()) {
                    log.debug("Server unidirectional stream write pending, sslError=" + sslError);
                }
            } else {
                log.warn(sm.getString("quicEndpoint.serverUniStreamWriteFailed", Integer.valueOf(0)) +
                        " sslError=" + sslError + " errors=" + QuicDiagnostics.dumpErrorQueue());
            }
            // Retry on next W event (and next R event when the write is
            // blocked on peer credit, which arrives as readable input)
            long events = item.getWantEvents();
            events |= QuicPoll.SSL_POLL_EVENT_W;
            if (sslError == QuicBindings.SSL_ERROR_WANT_READ) {
                events |= QuicPoll.SSL_POLL_EVENT_R;
            }
            item.setWantEvents(events);
            // A merely FINISHED stream is not treated as closed here: the
            // retry-vs-fail decision only demotes on reset/loss (see the
            // helper's javadoc).
            return wantMore && !QuicPoll.isWriteStateClosed(writeState)
                    ? UniStreamWriteResult.RETRY : UniStreamWriteResult.FAILED;
        }
    }


    /**
     * Writes buffered server unidirectional stream data.
     * Called after connection acceptance to retry writing data that couldn't
     * be sent during early stream creation. Drives the connection state
     * machine between attempts (a freshly created stream is only writable
     * once the handshake and stream credit have been processed) and reuses
     * {@link #flushServerUniStreamWrite} for the write itself, so this path
     * and the W-event flush classify a failed write identically and arm the
     * same interests. If the loop runs out of attempts or the stream can no
     * longer accept the data, the bytes stay buffered and the W interest
     * (armed when the stream was registered) lets the W-event flush pick the
     * retry up.
     */
    private void writeBufferedUniStream(MemorySegment connSsl, QuicStreamWrapper uniStream) {
        QuicPollItem item = uniStream.getPollItem();
        if (item == null) {
            // Should not happen: server unidirectional streams are registered
            // (poll item and W interest included) before their data is
            // buffered. Leave the data to the W-event flush either way.
            return;
        }
        // Retry with more attempts since handshake may still be completing
        for (int retry = 0; retry < STREAM_WRITE_RETRY_ATTEMPTS; retry++) {
            pumpEvents(connSsl);
            if (flushServerUniStreamWrite(uniStream, item) != UniStreamWriteResult.RETRY) {
                return;
            }
        }
    }


    private void handleErrorEvent(QuicPollItem item) {
        Object appData = item.getAppData();
        long revents = item.getRevents();

        if (appData instanceof QuicStreamWrapper stream) {
            // Defensive: the stream (or its connection) may have been torn
            // down before this handler ran. Same entry guard as the dispatch
            // and flush paths (see isStreamLive).
            if (!isStreamLive(stream)) {
                return;
            }
            // Reference: handle_read_stream_state / handle_write_stream_state
            if ((revents & QuicPoll.SSL_POLL_EVENT_ER) != 0) {
                int nativeReadState = QuicBindings.SSL_get_stream_read_state(
                        stream.getSsl());
                stream.setReadState(QuicStreamWrapper.mapNativeState(nativeReadState));
                if (nativeReadState == QuicPoll.SSL_STREAM_STATE_FINISHED) {
                    // Remote peer concluded the stream - clean close
                    closeStream(stream, true);
                    return;
                }
                if (nativeReadState == QuicPoll.SSL_STREAM_STATE_RESET_LOCAL ||
                        nativeReadState == QuicPoll.SSL_STREAM_STATE_RESET_REMOTE) {
                    // The stream was reset. Record the failure on the socket
                    // wrapper so the processor's error dispatch carries a
                    // throwable: the container's async error handling (and
                    // therefore ReadListener.onError with a meaningful
                    // cause) depends on it, as for a peer reset in the
                    // HTTP/2 or NIO transport paths.
                    QuicOpenSSLSocketWrapper wrapper =
                            streamWrappers.get(stream.getSslAddress());
                    if (wrapper != null) {
                        wrapper.setError(new IOException(
                                sm.getString("quicEndpoint.streamResetByPeer",
                                        Long.valueOf(stream.getStreamId()))));
                    }
                    closeStream(stream, false);
                    return;
                }
                if (nativeReadState == QuicPoll.SSL_STREAM_STATE_CONN_CLOSED) {
                    closeStream(stream, false);
                    return;
                }
                // Stream read error but not in terminal state - reset the stream
                // with an error code to inform the peer (resetStream warns on
                // failure; the intended code being lost is logged there).
                resetStream(stream, getDefaultStreamErrorCode());
                closeStream(stream, false);
                return;
            } else if ((revents & QuicPoll.SSL_POLL_EVENT_EW) != 0) {
                int writeState = QuicBindings.SSL_get_stream_write_state(
                        stream.getSsl());
                if (QuicPoll.isWriteStateClosed(writeState)) {
                    closeStream(stream, false);
                    return;
                }
                // Stream write error but not in terminal state - reset the stream
                // with an error code to inform the peer (resetStream warns on
                // failure; the intended code being lost is logged there).
                resetStream(stream, getDefaultStreamErrorCode());
                closeStream(stream, false);
                return;
            }
            closeStream(stream, false);
        } else if (appData instanceof QuicConnectionWrapper conn) {
            // Defensive: the connection's native SSL object may have been
            // freed by teardown before this handler ran.
            if (conn.isFreed()) {
                return;
            }
            // Connection-level stream error (ER/EW on connection object).
            // EC/ECD are handled separately by handleConnectionClose.
            // Mark as closing and wait for ECD.
            if (!conn.isClosing()) {
                conn.setClosing();
                if (log.isDebugEnabled()) {
                    log.debug("QUIC connection error revents=0x" + Long.toHexString(revents) +
                            " for conn=0x" + Long.toHexString(item.getSsl().address()));
                }
            }
        }
    }


    /**
     * Reads one of the endpoint-initiated application protocol error codes
     * from the configured {@link QuicProtocol}, shared by the four specific
     * accessors below. The endpoint's own lifecycle events (stream reset,
     * connection/stream rejection, graceful shutdown) can fire before an
     * application protocol is configured, so a missing protocol yields
     * {@code 0} (no application error code) rather than a failure.
     *
     * @param getter Reads the specific error code off the protocol
     *
     * @return The error code, or {@code 0} if no application protocol is
     *         configured
     */
    private long protocolErrorCode(Function<QuicProtocol, Long> getter) {
        QuicProtocol protocol = getQuicProtocol();
        return protocol == null ? 0L : getter.apply(protocol).longValue();
    }


    /**
     * Returns the application protocol error code to use when this endpoint
     * resets a stream on its own (for HTTP/3 {@code H3_INTERNAL_ERROR},
     * RFC 9114 Section 8.1).
     *
     * @return The default stream error code, or {@code 0} if no application
     *         protocol is configured
     */
    private long getDefaultStreamErrorCode() {
        return protocolErrorCode(QuicProtocol::getDefaultStreamErrorCode);
    }


    /**
     * Returns the application protocol error code to use when the endpoint
     * rejects a connection on its own initiative (at {@code maxConnections}).
     *
     * @return The connection rejection error code, or {@code 0} if no
     *         application protocol is configured
     */
    private long getConnectionRejectErrorCode() {
        return protocolErrorCode(QuicProtocol::getConnectionRejectErrorCode);
    }


    /**
     * Returns the application protocol error code to use when the endpoint
     * refuses a new client-initiated stream on its own initiative (at the
     * concurrent-stream limit), as reported by the configured
     * {@link QuicProtocol}.
     *
     * @return The stream rejection error code, or {@code 0} if no
     *         application protocol is configured
     */
    private long getStreamRejectErrorCode() {
        return protocolErrorCode(QuicProtocol::getStreamRejectErrorCode);
    }


    /**
     * Returns the application protocol error code to carry in the
     * {@code CONNECTION_CLOSE} sent when the endpoint stops normally.
     *
     * @return The graceful shutdown error code, or {@code 0} if no
     *         application protocol is configured
     */
    private long getGracefulShutdownErrorCode() {
        return protocolErrorCode(QuicProtocol::getGracefulShutdownErrorCode);
    }


    /**
     * Resets a QUIC stream using SSL_stream_reset, sending a RESET_STREAM
     * frame to the peer with the given application error code. This is the
     * single implementation shared by the endpoint poll paths and the socket
     * wrapper (whose {@code resetStream()} hops here via the poll thread).
     * <p>
     * Must be called on the poll thread: it drives the QUIC state machine
     * with SSL_handle_events() on the parent connection, which may only
     * happen there.
     *
     * @param stream The stream to reset
     * @param appErrorCode The application protocol error code (8-byte native-endian uint64_t)
     * @return {@code true} if the reset took effect; {@code false} if the
     *         request was still rejected after the retry loop, in which case
     *         the caller's subsequent stream teardown frees the stream in its
     *         current state and OpenSSL emits a spurious error-0 RESET_STREAM
     *         instead of the intended error code (logged as a warning here)
     */
    boolean resetStream(QuicStreamWrapper stream, long appErrorCode) {
        QuicConnectionWrapper conn = stream.getConnection();
        boolean resetDone = false;
        try (Arena localArena = Arena.ofConfined()) {
            // SSL_stream_reset takes SSL_STREAM_RESET_ARGS: 8-byte error code
            // (uint64_t), platform byte order
            MemorySegment args = localArena.allocate(ValueLayout.JAVA_LONG, 1);
            args.set(ValueLayout.JAVA_LONG, 0, appErrorCode);
            // Request the reset, driving the QUIC state machine (and
            // re-checking the result) until it takes effect. A single
            // SSL_stream_reset() can be rejected if the stream's send part
            // is not yet in a resettable state (e.g. the peer's data/FIN has
            // not been fully processed); retrying after a state-machine pump
            // lets it land. Without this the stream is later freed in its
            // original state and OpenSSL emits a spurious error-0 (NO_ERROR)
            // RESET_STREAM instead of the intended error code.
            for (int attempt = 0; attempt < RESET_STREAM_ATTEMPTS && !resetDone; attempt++) {
                int rc = QuicBindings.SSL_stream_reset(stream.getSsl(), args, 8L);
                int writeState = QuicBindings.SSL_get_stream_write_state(
                        stream.getSsl());
                // Deliberately the closed set minus RESET_REMOTE (not
                // QuicPoll.isWriteStateClosed): a peer-reset stream never
                // carried this reset's error code, so reporting done would
                // silence the streamResetFailed warning below while the
                // intended code was in fact lost.
                resetDone = (rc == 1)
                        || (writeState == QuicPoll.SSL_STREAM_STATE_RESET_LOCAL)
                        || (writeState == QuicPoll.SSL_STREAM_STATE_CONN_CLOSED);
                if (!resetDone && conn != null && !conn.isFreed()) {
                    QuicBindings.SSL_handle_events(conn.getSsl());
                }
            }
            // Flush the RESET_STREAM frame to the network immediately, while
            // we are still on the poll thread and the stream is not yet
            // freed, so it cannot be lost to a later free.
            if (conn != null && !conn.isFreed()) {
                QuicBindings.SSL_handle_events(conn.getSsl());
            }
        }
        if (!resetDone) {
            // The reset never landed within the retry budget: the intended
            // error code is lost and OpenSSL will emit a spurious error-0
            // RESET_STREAM when the stream is later freed. Surface it so the
            // transport behavior can be diagnosed.
            log.warn(sm.getString("quicEndpoint.streamResetFailed",
                    Long.valueOf(stream.getStreamId()),
                    Long.valueOf(appErrorCode)));
        }
        return resetDone;
    }


    /**
     * Removes a stream from all endpoint-level bookkeeping (poll set, socket
     * wrappers, connection stream maps) without freeing the native SSL and
     * without notifying the HTTP handler. Safe to call multiple times.
     * <p>
     * Critical: a stream MUST be removed from the poll set before its SSL
     * object is freed, otherwise SSL_poll() fails on the stale pointer and
     * zeroes the events of every item after it in the array, silently
     * starving all remaining connections and streams.
     *
     * @return {@code true} if the stream was tracked on its connection
     */
    boolean deregisterStream(QuicStreamWrapper stream) {
        QuicConnectionWrapper conn = stream.getConnection();
        boolean wasTracked = false;
        if (conn != null) {
            wasTracked = conn.getStreams().remove(stream.getStreamId()) != null;
            conn.getPendingStreams().remove(stream);
        }
        streamWrappers.remove(stream.getSslAddress());
        QuicPollItem removedItem = pollSet.remove(stream.getSslAddress());
        if (removedItem == null) {
            // The poll item was never promoted into the poll set (e.g. a
            // stream refused at the concurrent-stream limit, or one closed
            // before the server control stream was created). The poll set
            // only disposes items it removes, so release the item's native
            // SSL_POLL_ITEM struct (and its arena) here; closeAllStreams()
            // does the same for un-promoted items on connection teardown.
            // dispose() is idempotent.
            QuicPollItem item = stream.getPollItem();
            if (item != null) {
                item.dispose();
            }
        }
        stream.setDeregistered();
        return wasTracked;
    }


    /*
     * Removes a stream from the connection and decrements the active
     * bidirectional stream count if the stream was tracked. Notifies the
     * protocol of the termination of a client-initiated unidirectional
     * stream so it can release any per-stream state it retained.
     */
    private void deregisterAndReleaseStream(QuicStreamWrapper stream) {
        QuicConnectionWrapper conn = stream.getConnection();
        boolean wasTracked = deregisterStream(stream);
        if (conn == null) {
            return;
        }
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null) {
            return;
        }
        QuicConnectionManager.ConnectionState state = connManager.getState(conn);
        if (state == null) {
            return;
        }
        int streamType = stream.getStreamType();
        if (streamType == QuicPoll.SSL_STREAM_TYPE_BIDI) {
            // Decrement active stream count for bidirectional streams
            if (wasTracked) {
                state.decrementActiveStreams();
            }
        } else if (streamType == QuicPoll.SSL_STREAM_TYPE_READ) {
            // Client-initiated unidirectional stream terminated while the
            // connection stays open: let the protocol drop any state it kept
            // for the stream (for HTTP/3 the read-and-discard tracking of an
            // unknown stream type, RFC 9114 Section 9). The notification is
            // idempotent, so paths that deregister the same stream twice are
            // harmless.
            state.clientUniStreamClosed(stream.getStreamId());
        }
    }


    /**
     * Closes a stream after the HTTP handler requested the close
     * (SocketWrapperBase.close()). Unlike {@link #closeStream(QuicStreamWrapper,
     * boolean)} it does not notify the handler again.
     */
    void closeStreamByHandler(QuicStreamWrapper stream) {
        deregisterAndReleaseStream(stream);
        mailbox.queueStreamFree(stream);
    }


    private void closeStream(QuicStreamWrapper stream, boolean clean) {
        QuicOpenSSLSocketWrapper wrapper =
                streamWrappers.get(stream.getSslAddress());
        // The stream is done: release any worker parked in a synchronous
        // read or write on it so it observes the terminal state (EOF /
        // reset) instead of waiting out the full stall timeout.
        if (wrapper != null) {
            wrapper.signalReadWaiter();
            wrapper.signalWriteWaiter();
        }
        deregisterAndReleaseStream(stream);

        // An executor worker may be running the HTTP handler for this stream.
        // It must not be interrupted by a concurrent handler.process() call,
        // and its native SSL object must not be freed while it may still make
        // a native call on the poll thread. In that case the worker's
        // finishStreamDispatch() completes the SSL free once it is done.
        //
        // Claim the processing flag atomically rather than reading it: a
        // plain isProcessing() check was not atomic against the worker's
        // compareAndSetProcessing() claim in the dispatchToExecutor lambda
        // running on an executor worker, so a worker could
        // acquire the flag in the window between the read and the
        // processSocketInline() call below and two threads would run
        // handler.process() on the same wrapper.
        // Losing the claim means a worker owns the stream: as before, the
        // handler is left undisturbed and the teardown is deferred to it.
        boolean claimed = stream.compareAndSetProcessing(false, true);
        if (!claimed) {
            if (log.isDebugEnabled()) {
                log.debug("Deferring stream " + stream.getStreamId()
                        + " teardown to the worker still processing it");
            }
            return;
        }

        try {
            if (wrapper != null) {
                try {
                    processSocketInline(wrapper, clean ? SocketEvent.DISCONNECT : SocketEvent.ERROR);
                } catch (Exception e) {
                    ExceptionUtils.handleThrowable(e);
                }
            }
        } finally {
            stream.clearProcessing();
        }

        // Defer the native free until the next poll iteration, after
        // SSL_poll() has flushed any pending packets (for example a
        // RESET_STREAM requested just before this close) to the network.
        // freeSslOnce() is atomic with the Cleaner and runs unconditionally,
        // including while the owning connection is closing: a stream SSL
        // holds a reference on the connection and must be freed before the
        // connection SSL (SSL_new_stream(3)), which the teardown paths
        // preserve by draining the pending stream frees before freeing the
        // connection.
        mailbox.queueStreamFree(stream);
    }


    // ------------------------------------- Socket Processor

    /*
     * Currently unreached scaffolding: this processor is only ever created
     * through AbstractEndpoint.processSocket() -> createSocketProcessor(),
     * and no code path dispatches a QUIC wrapper through processSocket -
     * this endpoint runs its own dispatchToExecutor() ->
     * executor.execute(lambda) path, so the claim/requeue/cache logic below
     * has no production caller today. The override exists because
     * AbstractEndpoint declares createSocketProcessor() abstract. Reason
     * about dispatch from dispatchToExecutor()/runStreamDispatch(), not
     * from this class. (The quiche endpoint has the same unreached shape.)
     */
    private class QuicSocketProcessor extends SocketProcessorBase<QuicStream> {

        private QuicSocketProcessor(SocketWrapperBase<QuicStream> socket,
                SocketEvent event) {
            super(socket, event);
        }


        @Override
        protected void doRun() {
            QuicStreamWrapper stream = (QuicStreamWrapper) socketWrapper.getSocket();
            QuicConnectionWrapper conn = (stream != null) ? stream.getConnection() : null;
            if (conn != null) {
                conn.incrActiveHandlers();
            }
            boolean claimed = false;
            boolean requeued = false;
            try {
                // Claim the stream for the duration of this dispatch, the same
                // way the poll-path dispatch does in dispatchToExecutor(). The
                // re-dispatch path (AbstractProcessor async events) used to run
                // the handler without holding the flag, so the poll-thread
                // close paths (closeStream/closeAllStreams) did not defer the
                // stream SSL free to this worker and could free the native
                // object while the handler was still using it (use-after-free),
                // and a concurrent poll-path dispatch could re-enter the
                // handler.
                if (stream != null) {
                    claimed = stream.compareAndSetProcessing(false, true);
                    if (!claimed) {
                        // A poll-path dispatch owns the stream. Running the
                        // handler now would execute handler.process()
                        // concurrently with the owner on the same wrapper -
                        // the exact concurrent-dispatch hazard the processing
                        // flag exists to prevent. The event must not simply be
                        // dropped either (unlike poll events it is not level-
                        // triggered), so re-queue it: scheduleStreamDispatch()
                        // claims the flag once the owner releases it and
                        // delivers the event with flag ownership, without this
                        // worker ever blocking on the flag.
                        scheduleStreamDispatch(
                                (QuicOpenSSLSocketWrapper) socketWrapper,
                                stream, event);
                        requeued = true;
                        return;
                    }
                }

                if (stream != null) {
                    // Shared dispatch core with the poll path: releases the
                    // claim and completes the dispatch accounting (see
                    // runStreamDispatch). No LONG re-arm: async re-dispatch
                    // events do not drive read interest.
                    runStreamDispatch((QuicOpenSSLSocketWrapper) socketWrapper,
                            stream, conn, event, false);
                } else {
                    processSocketInline((QuicOpenSSLSocketWrapper) socketWrapper, event);
                }
            } finally {
                // The claimed path released its claim and completed its
                // accounting inside runStreamDispatch(). A re-queued dispatch
                // (return above) never held the flag and has handed the event
                // to scheduleStreamDispatch(), which manages its own claim and
                // active-handler accounting; together with the stream-less run
                // these only owe the active-handler reference taken above.
                if (!claimed) {
                    finishStreamDispatch(stream, conn, false);
                }
                // Return the processor to the cache only after this run's
                // cleanup has finished. Pushing it from inside the try (before
                // the finally) let another worker pop, re-init and re-run the
                // instance while this run was still finishing, so under a tight
                // race it could be pushed twice or run concurrently. Never push
                // on the re-queued path, whose event is now owned by
                // scheduleStreamDispatch().
                if (!requeued && processorCache != null) {
                    SocketProcessorBase<QuicStream> sc = this;
                    processorCache.push(sc);
                }
            }
        }
    }
}

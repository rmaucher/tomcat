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
 * (Panama). OpenSSL 4.x is the supported target: the directional
 * {@code SSL_accept_stream()} filters used here (see {@link QuicPoll}), the
 * engine-shared reactor tick model and the {@code SSL_CTX_ctrl}-based
 * servername callback are 4.x behaviour. The symbol probe in
 * {@link QuicBindings} requires every bound symbol, including
 * {@code SSL_get_peer_addr()}, which stock OpenSSL 3.5 does not export, so a
 * stock 3.5 library is rejected at initialization. Only a 3.5 build carrying
 * that 4.x symbol as a backport can bind; on such a backport the code still
 * degrades where the directional filters and stream values are unavailable
 * and does not claim full 3.5 compatibility. The native socket, wake-up and
 * ABI layer is currently implemented for Linux LP64; other platforms are
 * reported unavailable by {@link QuicPlatformSupport} instead of binding with
 * a mismatched ABI.
 * <p>
 * Follows the OpenSSL poll-server reference pattern:
 * <ul>
 * <li>Creates and binds a UDP socket through {@link QuicPlatformSupport}</li>
 * <li>Creates an OpenSSL QUIC listener via SSL_new_listener()</li>
 * <li>Attaches the platform socket handle to the listener via SSL_set_fd()</li>
 * <li>Openssl manages all I/O internally through its own datagram BIO</li>
 * <li>Uses SSL_poll() with BIO_POLL_DESCRIPTOR_TYPE_SSL for event discovery</li>
 * <li>Uses SSL_read_ex()/SSL_write_ex2() for stream I/O</li>
 * </ul>
 * <p>
 * OpenSSL exposes no accessor for the per-connection local address of a QUIC
 * connection, so {@code getLocalAddress()} reports the configured bind address
 * (the wildcard address for the default bind) rather than the interface address
 * a particular client connected to. The remote address is read from
 * {@code SSL_get_peer_addr()} at accept.
 * <p>
 * This endpoint is server-authentication TLS 1.3 only: it never requests a
 * client certificate. A host configured with
 * {@code certificateVerification="want"} is served as a plain server-auth
 * connection and warned about ({@code quicEndpoint.clientAuthUnsupported});
 * {@code certificateVerification="required"} fails the bind, because silently
 * dropping a mandatory client-authentication setting would serve that host
 * unauthenticated. This matches the quiche transport's warning for the
 * optional case.
 * <p>
 * OCSP stapling and CRL/revocation configuration are not implemented: the
 * per-host {@code ocspEnabled}, {@code revocationEnabled} and
 * {@code certificateRevocationListFile} settings are warned about and ignored
 * rather than silently dropped. All hosts share one native {@code SSL_CTX}, so
 * the default host's {@code cipherSuites} are applied; per-host differences
 * are warned about. The following settings cannot be represented and are
 * warned about/ignored rather than silently fail-open:
 * <ul>
 * <li>{@code groups}: OpenSSL's default key-exchange groups are used because
 *     the shared context is not configured with a group list;</li>
 * <li>{@code protocols}: a set that excludes TLS 1.3 still gets TLS 1.3
 *     service, because QUIC mandates TLS 1.3 (RFC 9001);</li>
 * <li>{@code ciphers} (TLS 1.2 list): ignored, as QUIC uses TLS 1.3
 *     {@code cipherSuites};</li>
 * <li>session resumption: TLS session tickets are disabled on the shared
 *     context, since OpenSSL does not bind a TLS 1.3 session to the SNI host
 *     that established it and there is no per-host ticket isolation.</li>
 * </ul>
 * Protocol-compliance limitation: OpenSSL's {@code SSL_shutdown_ex()} exposes
 * only an application error code and has no API to send a transport error
 * code, so RFC 9001 alert-derived transport codes (for example
 * {@link #NO_APPLICATION_PROTOCOL_ERROR}) are conveyed in the application
 * error field; the connection still closes immediately rather than timing out.
 * <p>
 * A directly supplied/programmatic {@link javax.net.ssl.SSLContext} is kept for
 * Manager/MBean consumers but is not used to load the native QUIC certificate
 * material; certificates come from the {@link SSLHostConfig} files/keystores
 * loaded by {@link QuicCertConfig}. Clients that negotiate a non-DHE PSK key
 * exchange on a pre-shared-key-only endpoint get no forward secrecy; the
 * endpoint warns about that tradeoff when it enables the corresponding OpenSSL
 * option.
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
     * Initial read-buffer size for accepted client unidirectional streams,
     * whose type is not yet known. An unknown stream keeps this small buffer
     * because its payload is read and discarded (RFC 9114 Section 9); an
     * identified control/QPACK stream grows to the configured
     * {@link #readBufferSize} before processing full-buffer data, preserving
     * the protocol's frame re-assembly window.
     */
    private static final int UNI_INITIAL_READ_BUFFER_SIZE = 1024;

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
    // Cap applied to the QuicWakeup.await() wait: a large configured poll
    // timeout would otherwise keep the poll thread waiting without re-checking
    // the stop flag, defeating the bounded shutdown join. The loop
    // re-iterates (and re-checks the stop flag) for the remainder.
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
    // same value as the wake-wait cap: an incoming packet wakes the socket
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
     * defines for alert-derived transport error codes, giving {@code 0x0178}
     * as required by RFC 9001 Section 8.1.
     * <p>
     * Protocol-compliance limitation: OpenSSL's {@code SSL_shutdown_ex()} only
     * exposes an application error code and has no API to send a transport
     * error code. The endpoint therefore conveys {@code 0x0178} in the
     * application error field. A peer sees an application error code rather
     * than the RFC 9001 transport code, but the connection still closes
     * immediately instead of timing out.
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

    // Attacker-influenced per-connection/per-stream warnings. A client can
    // trigger these repeatedly (no ALPN, critical-stream closure, failed
    // resets), so each warning is emitted at most once per interval instead of
    // at the per-connection/per-stream rate. Accessed on the poll thread only.
    private static final long SECURITY_WARNING_LOG_INTERVAL_MS = 60_000;
    private long lastAlpnNotServedLogMs = 0;
    private long lastCriticalStreamClosedLogMs = 0;
    private long lastStreamResetFailedLogMs = 0;
    private long lastServerUniWriteLogMs = 0;

    // Set once the transport/application stream-limit mismatch has been
    // reported, so the (level-triggered per-connection) warning logs once per
    // endpoint rather than once per connection.
    private volatile boolean streamLimitMismatchWarned = false;

    /**
     * The SSL* listener object.
     */
    private MemorySegment listener = MemorySegment.NULL;

    /**
     * The listener's poll item. Retained so the poll set can be reduced to the
     * listener alone when the endpoint stops: bind resources (and therefore the
     * poll set) are reused by a restart of a BOUND_ON_INIT endpoint, and any
     * connection/stream item left behind would keep polling an SSL that
     * stopInternal() has already freed.
     */
    private QuicPollItem listenerPollItem;

    /**
     * Set when the configured idle timeout was successfully applied to the
     * listener. Accepted connections then inherit the value and the
     * per-connection feature request is skipped.
     */
    private volatile boolean listenerIdleTimeoutApplied;

    /**
     * The selected platform implementation. Resolved once at class
     * initialisation; never queried on the per-request path.
     */
    private static final QuicPlatformSupport PLATFORM = QuicPlatformSupport.get();

    /**
     * The platform ABI, cached so the per-read and per-write native hot paths
     * do not pay a virtual call on every size_t/layout access.
     */
    private static final QuicPlatformSupport.Abi ABI = PLATFORM.abi();

    /**
     * Per-thread scratch for {@link #readStreamIdType(MemorySegment, long[])}
     * results, so the accept/new-stream hot paths do not allocate a two-long
     * array per stream. The values are consumed before any callback can
     * re-enter the same path.
     */
    private static final ThreadLocal<long[]> STREAM_INFO_SCRATCH =
            ThreadLocal.withInitial(() -> new long[2]);

    /**
     * The native UDP socket handle.
     */
    private QuicPlatformSupport.SocketHandle socketHandle;

    /**
     * Sockets whose FD cannot be closed at unbind time because connections
     * retained in {@link #stoppedBusyConnections} still need the datagram BIO
     * to flush their final frames and free their native SSLs. The FD is kept
     * open until the last retained connection has been reclaimed; closing it
     * earlier would leave the QUIC BIO pointing at a closed (and possibly
     * reused) descriptor. Guarded by {@link #retainedCleanupLock}.
     */
    private final Set<QuicPlatformSupport.SocketHandle> deferredSocketCloses =
            new HashSet<>();

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
     * Poll items for registered streams. Stream items stay in the poll subset
     * for their whole registered lifetime; idle connections, by contrast, are
     * only added for the iterations in which the ready-channel API reports
     * them. Concurrent because stream registration/deregistration follows the
     * same poll-thread confinement as the poll set, but teardown and worker
     * paths can also reach the removal hook.
     */
    private final Set<QuicPollItem> streamPollItems =
            ConcurrentHashMap.newKeySet();

    /**
     * Stream items kept in the poll subset for a bounded number of follow-up
     * passes after a registration or a ready-connection touch. See
     * {@link #STREAM_POLL_LINGER_PASSES}.
     */
    private final Set<QuicPollItem> lingeringStreamItems =
            ConcurrentHashMap.newKeySet();

    /**
     * Stream wrappers whose application-side write interest is latched (see
     * {@link QuicOpenSSLSocketWrapper#registerWriteInterest()}). OpenSSL's
     * {@code SSL_POLL_EVENT_W} condition requires free space in the stream's
     * native write buffer as well as remaining flow-control credit, so a
     * stream whose buffer is full but whose flow-control window has just
     * reopened reports no W event even though a write would grow the buffer
     * and make progress. The poll loop therefore re-checks this work set on
     * every iteration (the level-triggered counterpart of the quiche/ngtcp2
     * {@code stream_capacity} re-arm sweep) instead of relying solely on the
     * edge-shaped W report.
     */
    private final Set<QuicOpenSSLSocketWrapper> writeInterestedWrappers =
            ConcurrentHashMap.newKeySet();

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
     * Serializes the fallback reclamation of connections retained because a
     * handler outlived the stop budget. The stop thread, unbind/destroy and a
     * late worker that completes the last handler can all attempt the same
     * cleanup; native stream/connection frees must not overlap.
     */
    private final Object retainedCleanupLock = new Object();

    /**
     * Timestamp of the last log message for an SSL_poll usage error (see
     * {@link #pollLoop()}) so a persistent misconfiguration does not flood
     * the log.
     */
    private long lastPollUsageErrorLogMs;


    /**
     * Timestamp of the last warning for a failing protocol-data flush (see
     * {@link #flushProtocolData(QuicConnectionWrapper, QuicConnectionManager)})
     * so a persistent protocol bug cannot flood the log at poll-loop rate.
     */
    private long lastProtocolDataFlushWarnMs;

    /**
     * Timestamps of the last warnings for a failing SSL_handle_events() and
     * for a NULL accept with a non-empty OpenSSL error queue, rate-limited
     * because both conditions can persist on every poll iteration.
     */
    private long lastHandleEventsErrorLogMs;
    private long lastAcceptErrorLogMs;

    /**
     * Timestamp of the last warning for an incoming-connection setup failure,
     * rate-limited because a persistent failure can repeat for every accepted
     * connection.
     */
    private long lastIncomingConnectionErrorLogMs;

    /**
     * Timestamp of the last per-connection setup-failure warning. A client
     * that repeatedly drives a protocol callback into an error can otherwise
     * flood the log with one warning per attempted connection.
     */
    private long lastConnectionSetupErrorLogMs;


    /**
     * Poll loop thread. Published across threads (the reload/unbind guards
     * read it from lifecycle and JMX threads), so it must be volatile: a
     * stale {@code null} seen by {@link #reloadCertificates} while the poll
     * loop is live would take the off-thread direct-install branch and touch
     * native state the poll thread is still using.
     */
    private volatile Thread pollThread;

    /**
     * Thread currently executing {@link #stopInternal()}. Once the poll thread
     * has stopped, this thread is the only allowed native caller; a protocol
     * callback invoked during stop may therefore run a native operation inline
     * instead of waiting for a poll-thread hop. Cleared in a finally block.
     */
    private volatile Thread stopThread;

    /**
     * Set when stopInternal() could not join the poll thread and returned
     * without cleaning the native generation. Once that thread has exited, a
     * later bind/start reruns stopInternal() to reclaim the old connections
     * and resources before creating a new generation.
     */
    private volatile boolean failedStopCleanupRequired;

    /**
     * Single owner of the queues that cross the poll-thread confinement
     * boundary (poll tasks, deferred stream frees and Cleaner free requests).
     * The poll thread is the normal drainer; once it has stopped, drains may
     * run on a single thread at a time accepted by the endpoint's
     * {@link #assertNativeAccess(String)} policy (the stop thread or the last
     * handler's worker during retained-connection reclaim).
     */
    private final QuicNativeMailbox mailbox =
            new QuicNativeMailbox(this::assertNativeAccess);

    /**
     * The poll thread's blocking wait primitive (UDP socket + mailbox kick
     * platform wake object). Created in {@code bind()} once the UDP socket
     * exists,
     * released with the bind resources.
     */
    private volatile QuicWakeup quicWakeup;

    /**
     * One-shot wake flag set when protocol data transitions from “nothing
     * pending” to “pending” on any thread. The poll loop consults it before
     * deciding whether it may skip a tick/poll iteration, so a worker's mark
     * cannot wait for an unrelated engine timer or packet.
     */
    private final AtomicBoolean protocolDataWakePending = new AtomicBoolean();

    /**
     * One-shot wake flag set when a poll item's want-events mask changes.
     * Interest changes made by handlers on the poll thread (for example
     * re-arming R after a unidirectional read or adding OSU for a protocol
     * stream) must force the next tick/poll pass even when no packet, hop,
     * queued free or engine deadline would otherwise wake the loop.
     */
    private final AtomicBoolean pollInterestWakePending = new AtomicBoolean();

    /**
     * Guards the per-connection protocol-data flag transition together with
     * the mark publication, and serializes those transitions against the
     * generation reset in {@link #startInternal()}. Without this, a late worker
     * can be between the flag change and the mark publication when the
     * start-time reset clears the queues, leaving a mark for a connection whose
     * flag has moved on.
     */
    private final Object protocolDataLock = new Object();

    /**
     * Cross-thread companion of {@link #protocolDataConns}: every transition
     * into the pending state marks its connection here. The poll loop consumes
     * the queue into the confined {@link #protocolDataConns} set and flushes
     * only those connections, turning the protocol-data sweep into
     * O(pending connections) instead of O(live connections) - the same naming
     * trick the mailbox hops use, which matters most when a large idle fleet
     * coexists with traffic (QPACK output on a few connections used to make
     * every ticked iteration walk the whole fleet).
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
     * Adds a wrapper to the write-interest work set. Called by the wrapper
     * when a non-blocking write leaves data behind (or when readiness must be
     * re-checked before another application write).
     * <p>
     * The wrapper uses the return value to keep its latch consistent with the
     * set: while the endpoint is stopped the wrapper must not remain latched
     * without being present in the sweep set.
     *
     * @param wrapper The wrapper with pending write interest
     *
     * @return {@code true} if the registration was accepted, {@code false} if
     *         the endpoint is stopped and the registration was ignored
     */
    boolean addWriteInterest(QuicOpenSSLSocketWrapper wrapper) {
        // Ignore registrations while stopped: stopInternal() has cleared the
        // set and there is no poll loop to sweep it. A handler that survives
        // the stop will re-register when it performs its next write/wait
        // after a restart.
        if (running) {
            writeInterestedWrappers.add(wrapper);
            return true;
        }
        return false;
    }


    /**
     * Removes a wrapper from the write-interest work set. Called when the
     * wrapper drains its buffers, or closes.
     *
     * @param wrapper The wrapper whose write interest is cleared
     */
    void removeWriteInterest(QuicOpenSSLSocketWrapper wrapper) {
        writeInterestedWrappers.remove(wrapper);
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
    private volatile int maxConnections = DEFAULT_MAX_CONNECTIONS;

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
     * Last time (ms) the stream-limit refusal warning was logged, plus the
     * cumulative refusal count. The warning is rate-limited because a client
     * that keeps opening streams beyond the configured limit reaches this path
     * per stream and could otherwise flood the log.
     */
    private long streamLimitWarnCount = 0;
    private long lastStreamLimitWarnLogMs = 0;
    private static final long STREAM_LIMIT_LOG_INTERVAL_MS = 60_000;

    /**
     * Poll timeout in milliseconds used while the endpoint has connections or
     * queued work. Every poll-loop iteration carries a fixed native cost (OpenSSL
     * ticks every poll item inside {@code SSL_poll()}), so this value trades that
     * per-iteration cost against two latencies it bounds: the maximum wait for a
     * worker's queued native hop and the loop's responsiveness to the stop flag
     * (the wake wait caps it at {@link #NATIVE_POLL_TIMEOUT_CAP_MS} per call).
     * An idle endpoint (no connections, no queued work) ignores this value and
     * uses {@link #IDLE_POLL_TIMEOUT_MS} instead, so the per-iteration cost is
     * only paid while there is something to deliver.
     */
    private volatile long pollTimeoutMs = DEFAULT_POLL_TIMEOUT_MS;

    /**
     * Read buffer size for streams.
     */
    private volatile int readBufferSize = DEFAULT_READ_BUFFER_SIZE;

    /**
     * Upper bound for the adaptive due-tick floor; {@code 0} disables the
     * floor (due-deadline ticks run whenever the engine reports one due, the
     * exact-timer behaviour). See {@link #dueTickFloorCapMs}.
     */
    private volatile long dueTickFloorCapMs = DEFAULT_DUE_TICK_FLOOR_CAP_MS;

    /**
     * Whether QUIC is available in the linked OpenSSL.
     */
    private static final boolean QUIC_AVAILABLE = QuicBindings.QUIC_AVAILABLE;

    /**
     * Whether the optional ready-channel poll API is available in the linked
     * OpenSSL. When absent, the endpoint keeps the legacy all-items poll path.
     */
    private static final boolean READY_CHANNELS_AVAILABLE =
            QuicBindings.hasQuicReadyChannelsApi();

    /**
     * Number of ready connection SSL pointers read per native call. A larger
     * ready set is drained over a bounded number of calls so one iteration
     * cannot monopolise the poll thread.
     */
    private static final int READY_CHANNEL_BATCH = 1024;

    /**
     * Maximum ready-channel drain calls per poll iteration. Any channels left
     * queued are picked up on a later wake. The batch and loop bound together
     * let one iteration drain a full default-sized fleet without unbounded
     * native calls.
     */
    private static final int READY_CHANNEL_DRAIN_LOOPS = 16;

    /**
     * Follow-up poll passes for a newly registered or connection-touched
     * stream item. Buffered stream data can remain readable one pass after the
     * parent connection's ready entry was drained, before the next network
     * wake would return the connection again.
     */
    private static final int STREAM_POLL_LINGER_PASSES = 4;

    /**
     * Stream events which refresh the linger. W is excluded: it is a
     * level-triggered "buffer has space" condition on a write stream and would
     * otherwise keep quiescent server unidirectional streams polled forever.
     */
    private static final long STREAM_LINGER_EVENTS =
            QuicPoll.SSL_POLL_EVENT_R |
            QuicPoll.SSL_POLL_EVENT_ER |
            QuicPoll.SSL_POLL_EVENT_EW;

    /**
     * Events requested for connection poll items. The endpoint never creates
     * server-initiated bidirectional streams, so {@code SSL_POLL_EVENT_OSB}
     * is deliberately excluded: it is level-triggered whenever the peer grants
     * bidirectional stream credit, and keeping it requested would re-enter the
     * outgoing-stream handler on every iteration even when no bidirectional
     * stream is wanted (a CPU spin while a server unidirectional stream is
     * waiting for peer credit).
     */
    static final long CONNECTION_POLL_EVENTS =
            -1L & ~QuicPoll.SSL_POLL_EVENT_OSB;


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
        if (listener != null && !listener.equals(MemorySegment.NULL)) {
            // The listener's pending-handshake bound is derived from
            // maxConnections at bind time. Reapply it on a runtime change;
            // native listener access stays on the poll thread when it is
            // running.
            if (pollThread != null && pollThread.isAlive()) {
                if (isPollThread()) {
                    configureListenerPendingConnections();
                } else {
                    submitPollTask(this::configureListenerPendingConnections);
                }
            }
            // If no poll thread is running, the value is picked up by the
            // next startInternal() before the poll thread starts; native
            // listener access must not race a start in progress.
        }
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
        // Connections retained from a previous generation still have live
        // native state and still count against maxConnections, even though
        // their handlers outlived the stop budget and they are no longer in
        // the current connections map. A connection retained forever because
        // a native stream SSL_free() failed (the fail-safe ordering in
        // freeIdleStreams()/freeConnectionOrDefer()) is deliberately included:
        // it still owns native resources and cannot be freed safely. Such a
        // connection permanently reduces the usable capacity of this endpoint
        // until it is restarted; the retention path logs a one-time warning
        // (quicEndpoint.connectionRetentionExhaustion) so this does not look
        // like an ordinary maxConnections problem.
        return connections.size() + stoppedBusyConnections.size();
    }


    @Override
    public java.util.Set<SocketWrapperBase<QuicStream>> getConnections() {
        return new HashSet<>(streamWrappers.values());
    }


    /**
     * The base-class map is not used by this endpoint (the QUIC connection
     * wrappers are not SocketWrapperBase instances), so graceful stop must
     * consult the endpoint's own connection/stream maps instead.
     */
    @Override
    protected boolean hasOpenConnections() {
        return !connections.isEmpty() || !streamWrappers.isEmpty() ||
                !stoppedBusyConnections.isEmpty();
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
     * Returns the poll-loop wait timeout used while the endpoint has
     * connections or queued work.
     *
     * @return The poll-loop wait timeout in milliseconds
     */
    public long getPollTimeoutMs() {
        return pollTimeoutMs;
    }

    /**
     * Sets the poll-loop wait timeout used while the endpoint has connections
     * or queued work. {@code SSL_poll()} itself always runs in non-blocking
     * mode; this value bounds {@code QuicWakeup.await()}. A value outside
     * {@code [MIN_POLL_TIMEOUT_MS, MAX_POLL_TIMEOUT_MS]} is logged and
     * ignored.
     *
     * @param pollTimeoutMs The poll-loop wait timeout in milliseconds
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
     * one above {@code NATIVE_POLL_TIMEOUT_CAP_MS} is logged and ignored:
     * the floor is awaited directly on the poll thread, so it must not exceed
     * the same cap that keeps the stop join bounded.
     *
     * @param dueTickFloorCapMs The due-tick floor in milliseconds
     */
    public void setDueTickFloorMs(long dueTickFloorCapMs) {
        if (dueTickFloorCapMs < 0 || dueTickFloorCapMs > NATIVE_POLL_TIMEOUT_CAP_MS) {
            log.warn(sm.getString("quicEndpoint.dueTickFloorInvalid",
                    String.valueOf(dueTickFloorCapMs),
                    String.valueOf(NATIVE_POLL_TIMEOUT_CAP_MS)));
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
     * Reports whether the selected platform and the linked OpenSSL provide
     * QUIC support.
     *
     * @return {@code true} if OpenSSL QUIC is available on this platform
     */
    public static boolean isQuicAvailable() {
        // The platform selector owns the OS/ABI availability gate and
        // QuicBindings adds the OpenSSL symbol check. Both are folded into
        // QUIC_AVAILABLE, so callers see one verdict.
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
        if (!isQuicAvailable()) {
            if (!PLATFORM.isAvailable()) {
                throw new IllegalStateException(PLATFORM.unavailableReason());
            }
            if (!ABI.isSupported()) {
                throw new IllegalStateException(sm.getString(
                        "quicPlatform.unsupportedAbi",
                        String.valueOf(ValueLayout.ADDRESS.byteSize() * 8)));
            }
            throw new IllegalStateException(sm.getString("quicEndpoint.quicNotAvailable"));
        }
        // A poll thread that survived stopInternal()'s bounded join still owns
        // the native listener/poll set/SSL_CTX/wakeup objects. AbstractEndpoint
        // calls bind() before startInternal(), so the startInternal() guard
        // alone would let bind() overwrite those live objects first. Refuse
        // here, before allocating or replacing any native state.
        Thread oldPollThread = pollThread;
        if (oldPollThread != null && oldPollThread.isAlive()) {
            throw new IllegalStateException(sm.getString(
                    "quicEndpoint.pollThreadStillRunning", getName()));
        }
        // Do not create a new UDP socket generation while a handler from the
        // previous generation still owns a connection: releaseBindResources()
        // has to close the old socket, and after that close there is no poll
        // thread or open mailbox through which the old handler could safely
        // perform native I/O. Refusing the bind until the handler finishes
        // also prevents the kernel from reusing the old fd number for the new
        // generation's socket.
        if (hasActiveRetainedHandlers()) {
            throw new IllegalStateException(sm.getString(
                    "quicEndpoint.retainedHandlersRunning", getName()));
        }
        if (failedStopCleanupRequired) {
            // A previous stop could not join the poll thread and left its
            // connections and bind resources behind. The thread has now
            // exited; rerun the full cleanup before replacing the listener,
            // socket, SSL_CTX and poll set with this new generation.
            log.warn(sm.getString("quicEndpoint.failedStopRecovery", getName()));
            stopInternal();
            releaseBindResources();
        }
        synchronized (retainedCleanupLock) {
            // Complete deferred frees of connections whose handlers finished
            // after the last stop, and close sockets that no longer have a
            // retained user, before creating the new socket. Otherwise a
            // handler finishing concurrently with bind can let the endpoint
            // pass hasActiveRetainedHandlers() while the previous
            // generation's socket is still open, and rebinding the same port
            // fails with EADDRINUSE. A connection whose stream SSL free failed
            // is retained forever, so surface that state instead of repeating
            // the bind failure.
            java.util.Iterator<QuicConnectionWrapper> retainedIterator =
                    stoppedBusyConnections.iterator();
            while (retainedIterator.hasNext()) {
                reclaimRetainedConnection(retainedIterator.next(), true);
            }
            closeDeferredSocketsIfSafe();
            if (!stoppedBusyConnections.isEmpty() ||
                    !deferredSocketCloses.isEmpty()) {
                throw new IllegalStateException(sm.getString(
                        "quicEndpoint.retainedConnectionsNotReclaimed",
                        getName()));
            }
        }

        // QUIC mandates TLS (RFC 9001) and the transport needs the native
        // SSL_CTX to exist first, so - unlike NioEndpoint, which opens the
        // server socket before calling initialiseSsl() - the SSL setup happens
        // here before the UDP socket is created. Cleanup on a failure is
        // delegated to unbind() (invoked by AbstractEndpoint.bindWithCleanup()
        // when bind() throws), mirroring NioEndpoint which has no bind-time
        // try/catch of its own.
        listenerIdleTimeoutApplied = false;
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
     * <p>
     * This is a bind-time initialiser. Calling it while a native
     * {@code SSL_CTX} is already initialized is rejected: replacing the context
     * under a live listener/retained connections would leak the old generation
     * and expose inconsistent TLS state. Use
     * {@link #reloadCertificates(String)} for a live certificate reload
     * instead. A reload that fails keeps the previous snapshot and fails the
     * management operation.
     *
     * @throws IllegalStateException If the endpoint is already initialized
     * @throws Exception If the TLS setup failed
     */
    @Override
    public void initialiseSsl() throws Exception {
        if (!isSSLEnabled()) {
            throw new IllegalStateException(sm.getString("quicEndpoint.tlsRequired"));
        }
        synchronized (certManager) {
            if (!certManager.getSslCtx().equals(MemorySegment.NULL)) {
                // This is a bind-time initializer. Calling it on a running
                // endpoint would replace the native SSL_CTX/certificate
                // snapshot while the live listener still uses the old
                // generation; a certificate reload must go through
                // reloadCertificates() instead.
                throw new IllegalStateException(sm.getString(
                        "quicEndpoint.sslAlreadyInitialized", getName()));
            }
        }

        OpenSSLLibrary.initLibrary();

        // Fail fast if no default SSLHostConfig is configured
        getSSLHostConfig(null);
        QuicCertConfig initialConfig = buildCertConfig();
        if (initialConfig == null) {
            throw new IOException(sm.getString("quicEndpoint.certificateLoadFailed",
                    getDefaultSSLHostConfigName(),
                    sm.getString("certificateLoader.noCertificateOrPsk")));
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
     * has not started it, or {@link #stopInternal()} has stopped it). A
     * connection whose handler outlived the stop budget is retained in
     * {@code stoppedBusyConnections}; its native SSL objects are kept alive by
     * OpenSSL references, and its UDP socket is not closed here until the
     * last retained connection has been reclaimed (see
     * {@link #deferredSocketCloses}).
     */
    private void releaseBindResources() {
        synchronized (retainedCleanupLock) {
            // Connections retained because a handler outlived the stop budget
            // are reclaimed here when their handler has since completed. A
            // connection whose handler is still running is left retained; its
            // worker (or the start-time sweep if the endpoint is restarted)
            // completes the free.
            reclaimRetainedConnections();
            closeDeferredSocketsIfSafe();
            // Free the listener first, then detach the socket FD explicitly:
            // SSL_set_fd() attaches the datagram BIO with BIO_NOCLOSE
            // (openssl/ssl/ssl_lib.c), so SSL_free() does not close the FD.
            // The listener SSL references keep the port/engine alive while
            // retained connections still exist.
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
            // The listener never owns the socket (BIO_NOCLOSE). Keep the FD
            // open while any retained connection can still drive its datagram
            // BIO; otherwise the BIO would reference a closed/reused FD.
            QuicPlatformSupport.SocketHandle socket = socketHandle;
            socketHandle = null;
            if (socket != null && socket.isValid()) {
                if (stoppedBusyConnections.isEmpty()) {
                    PLATFORM.close(socket);
                } else {
                    deferredSocketCloses.add(socket);
                    if (log.isDebugEnabled()) {
                        log.debug("Deferring QUIC socket close until retained connections are reclaimed");
                    }
                }
            }
            bindAddress = null;
            // Release the native SSL_CTX, the current certificate snapshot and
            // the callback arenas. The SSL_CTX must go after the listener
            // (freed above) that was created from it, and before the poll set
            // below; the arenas are only referenced by callbacks installed on
            // the SSL_CTX, which the manager frees first, so releasing them
            // here is safe. Retained connection SSLs hold their own SSL_CTX
            // and certificate references.
            certManager.release();
            if (pollSet != null) {
                try {
                    // Dispose any item structs still in the set (the listener
                    // item added in createListener(), and any that a partial
                    // bind left behind) before releasing the array arenas.
                    pollSet.clear();
                    streamPollItems.clear();
                    lingeringStreamItems.clear();
                    pollSet.close();
                } catch (Throwable t) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error closing QUIC poll set during bind cleanup", t);
                    }
                }
                pollSet = null;
                listenerPollItem = null;
            }
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
    }


    /**
     * Closes sockets whose close was deferred because retained connections
     * still needed their datagram BIO. Must be called with
     * {@link #retainedCleanupLock} held.
     */
    private void closeDeferredSocketsIfSafe() {
        if (stoppedBusyConnections.isEmpty() && !deferredSocketCloses.isEmpty()) {
            for (QuicPlatformSupport.SocketHandle socket : deferredSocketCloses) {
                try {
                    PLATFORM.close(socket);
                } catch (Throwable t) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error closing deferred QUIC socket", t);
                    }
                }
            }
            deferredSocketCloses.clear();
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
        return ensureServedProtocol(conn, false);
    }


    /**
     * Checks the negotiated application protocol. During the accept/bootstrap
     * path the handshake may still be in progress, so the ALPN result may not
     * be available yet. In that case {@code deferProtocolCheck} lets the
     * caller continue and the regular stream-event paths re-check the result
     * once the handshake has completed.
     *
     * @param conn                The connection to check
     * @param deferProtocolCheck  {@code true} when called from the accept path,
     *                            where a missing ALPN result is not yet fatal
     *
     * @return {@code true} if the protocol is served or the check is deferred,
     *         {@code false} if the connection was rejected and torn down
     */
    private boolean ensureServedProtocol(QuicConnectionWrapper conn,
            boolean deferProtocolCheck) {
        if (conn == null || conn.isClosed() || conn.isFreed()) {
            return false;
        }

        // The accept path may read SNI before the ClientHello has been fully
        // processed, so an empty cached value there is "not resolved yet",
        // not "the client sent no SNI". Retry the native read until the
        // non-deferred stream-event path, which runs after the handshake, can
        // mark the empty result authoritative; after that the per-event
        // native SSL_get_servername() call is skipped.
        if (!conn.isSniResolved() && conn.getSniHostName().isEmpty()) {
            String sni = conn.readSniHostName();
            if (!sni.isEmpty()) {
                conn.setSniHostName(sni);
            } else if (!deferProtocolCheck) {
                conn.setSniResolved();
            }
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
        if (negotiated == null) {
            if (deferProtocolCheck && !isHandshakeComplete(conn)) {
                // A missing ALPN result is only deferrable while the handshake
                // is still in progress. Once it has completed, a null result
                // means the peer sent no ALPN extension (or the callback
                // rejected every protocol) and is a rejection, whether or not
                // this is the accept/bootstrap path.
                return true;
            }
            // The handshake is complete without a negotiated protocol.
        } else if (isServedProtocol(negotiated)) {
            return true;
        }

        long now = System.currentTimeMillis();
        if (now - lastAlpnNotServedLogMs >= SECURITY_WARNING_LOG_INTERVAL_MS) {
            lastAlpnNotServedLogMs = now;
            log.warn(sm.getString("quicEndpoint.alpnNotServed",
                    Long.toHexString(conn.getSslAddress()),
                    String.valueOf(negotiated)));
        }
        failConnection(conn, NO_APPLICATION_PROTOCOL_ERROR,
                "Negotiated application protocol is not served");
        return false;
    }


    /**
     * Whether the QUIC connection's TLS handshake has completed. Until it has,
     * a null ALPN result cannot be distinguished from "not available yet".
     *
     * @param conn The connection to check
     *
     * @return {@code true} if the handshake has finished
     */
    private static boolean isHandshakeComplete(QuicConnectionWrapper conn) {
        if (conn == null || conn.isClosed() || conn.isFreed()) {
            return false;
        }
        return QuicBindings.SSL_is_init_finished(conn.getSsl()) == 1;
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
            ExceptionUtils.handleThrowable(t);
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
     * are served by a {@link QuicSSLContext} reporting the configured chain.
     * A directly provided SSLContext is left in place for those consumers,
     * but it is not used to load the native QUIC certificate material: the
     * handshake uses the SSLHostConfigCertificate files/keystores loaded by
     * QuicCertConfig. A context created here is replaced on reload so a
     * rotated certificate becomes visible.
     */
    @Override
    protected void createSSLContext(SSLHostConfig sslHostConfig) throws IllegalArgumentException {
        refreshTlsInformation(sslHostConfig);
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
     * Refreshes the JMX-visible TLS protocol/cipher information of a host
     * configuration from the currently installed native {@code SSL_CTX}.
     * <p>
     * The native SSL_CTX can be freed concurrently by release() (stop /
     * unbind) or replaced by swapConfig() on a JMX reload. The manager's
     * lifecycle methods are synchronized on the manager instance; hold the
     * same monitor while the pointer is dereferenced for the ciphers so a
     * stale SSL_CTX can never be touched.
     *
     * @param sslHostConfig The host configuration to refresh
     */
    private void refreshTlsInformation(SSLHostConfig sslHostConfig) {
        synchronized (certManager) {
            MemorySegment sslCtx = certManager.getSslCtx();
            if (!sslCtx.equals(MemorySegment.NULL)) {
                sslHostConfig.setEnabledProtocols(new String[] { "TLSv1.3" });
                String[] ciphers = OpenSSLContext.getCiphers(sslCtx);
                if (ciphers != null) {
                    sslHostConfig.setEnabledCiphers(ciphers);
                }
            }
        }
    }


    /**
     * Adds an SSL host configuration and reloads the native certificate
     * configuration so the change is visible to new connections. If the native
     * rebuild fails the base configuration is rolled back, so a failed
     * management operation leaves the endpoint serving exactly its previous
     * configuration instead of a half-committed one.
     */
    @Override
    public void addSslHostConfig(SSLHostConfig sslHostConfig, boolean replace)
            throws IllegalArgumentException {
        String hostName = sslHostConfig == null ? null : sslHostConfig.getHostName();
        SSLHostConfig previous = hostName == null ? null : sslHostConfigs.get(hostName);
        try {
            super.addSslHostConfig(sslHostConfig, replace);
            reloadCertificates("addSslHostConfig");
        } catch (RuntimeException e) {
            if (hostName != null) {
                rollbackSslHostConfigAdd(hostName, previous);
            }
            throw e;
        }
    }


    /**
     * Removes an SSL host configuration and reloads the native certificate
     * configuration so the removed host is no longer offered. If the native
     * rebuild fails the removed configuration is restored, so a failed
     * management operation does not silently keep the old native snapshot
     * active while the management view says the host was removed.
     */
    @Override
    public SSLHostConfig removeSslHostConfig(String hostName) {
        String key = hostName == null ? null : hostName.toLowerCase(Locale.ENGLISH);
        SSLHostConfig previous = key == null ? null : sslHostConfigs.get(key);
        try {
            SSLHostConfig removed = super.removeSslHostConfig(hostName);
            if (removed != null) {
                reloadCertificates("removeSslHostConfig");
            }
            return removed;
        } catch (RuntimeException e) {
            if (key != null && previous != null) {
                restoreSslHostConfig(key, previous);
            }
            throw e;
        }
    }


    /**
     * Restores the base host map after a failed add/remove. The native
     * snapshot was not changed because the reload failed before the swap, so
     * restoring the base map makes the two representations consistent again.
     *
     * @param hostName The lower-case host name
     * @param previous The previous host configuration, or {@code null} if the
     *                 host did not exist before the add
     */
    private void rollbackSslHostConfigAdd(String hostName, SSLHostConfig previous) {
        if (previous == null) {
            try {
                super.removeSslHostConfig(hostName);
            } catch (RuntimeException e) {
                // The default host cannot be removed through the public path;
                // removing the map entry is still the correct rollback.
                sslHostConfigs.remove(hostName);
            }
        } else {
            restoreSslHostConfig(hostName, previous);
        }
    }


    /**
     * Restores one host configuration in the base map and refreshes its JMX
     * registration/TLS information.
     *
     * @param hostName The lower-case host name
     * @param config   The configuration to restore
     */
    private void restoreSslHostConfig(String hostName, SSLHostConfig config) {
        sslHostConfigs.put(hostName, config);
        try {
            super.addSslHostConfig(config, true);
        } catch (RuntimeException e) {
            log.warn(sm.getString("quicEndpoint.certificateRollbackFailed",
                    hostName), e);
        }
    }


    /**
     * Reloads all SSL host configurations with a single rebuild of the
     * native certificate configuration (instead of one rebuild per host as
     * in the base implementation). The rebuild uses the current in-memory
     * {@link SSLHostConfig} objects; it does not re-read configuration files.
     */
    @Override
    public void reloadSslHostConfigs() {
        for (String hostName : sslHostConfigs.keySet()) {
            // Re-register each host (what the base class reload does: the
            // same in-memory SSLHostConfig through addSslHostConfig, which
            // refreshes the per-host TLS information) without triggering a
            // native rebuild for every host; the single reloadCertificates()
            // call below rebuilds from the current in-memory configurations.
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
     * during handshakes). A failed rebuild keeps the previous native
     * configuration and fails the calling management operation.
     *
     * @param reason a short description of what triggered the reload, used
     *               for logging
     *
     * @throws IllegalStateException If the native configuration could not be
     *         rebuilt; the previous configuration stays active
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
            // Keep the previous native configuration, but fail the management
            // operation instead of reporting success while the old
            // certificate/PSK material is still being served.
            throw new IllegalStateException(sm.getString(
                    "quicEndpoint.certificateReloadFailed", reason));
        }
        if (pollThread != null && pollThread.isAlive()) {
            // Run the swap on the poll thread (serialized with the SNI
            // callback) but wait for its result, so a validation failure is
            // reported to the management caller instead of being logged by
            // the mailbox after the call already returned success.
            Runnable discardSnapshot = () -> {
                newConfig.free();
                CertificateLoader.closeQuietly(newConfig.arena);
            };
            try {
                callOnPollThread(() -> {
                    try {
                        certManager.swapConfig(newConfig, reason);
                    } catch (IllegalArgumentException e) {
                        // swapConfig() validates the cipher policy before
                        // taking ownership, so the task that is running still
                        // owns the snapshot and must release it itself. A
                        // timed-out caller must not free it here.
                        discardSnapshot.run();
                        throw e;
                    }
                    return null;
                });
            } catch (IllegalArgumentException e) {
                // The task either released the snapshot before throwing or,
                // for an inline invocation, did so in the same task body.
                throw new IllegalStateException(sm.getString(
                        "quicEndpoint.certificateReloadFailed", reason), e);
            } catch (RejectedExecutionException e) {
                // The task never started (closed mailbox or stopped poll
                // thread), so the caller still owns the snapshot.
                discardSnapshot.run();
                throw new IllegalStateException(sm.getString(
                        "quicEndpoint.certificateReloadFailed", reason), e);
            } catch (Exception e) {
                // A timeout/interrupt means the queued task may still run and
                // take ownership of the snapshot, so it must not be freed
                // here. If the task never runs the snapshot is leaked rather
                // than risking a use-after-free. Report the management
                // failure regardless.
                throw new IllegalStateException(sm.getString(
                        "quicEndpoint.certificateReloadFailed", reason), e);
            }
        } else {
            // No running poll loop to serialize against (not started, or
            // already stopped): applying the swap here is safe for the same
            // reason the drain of the poll-thread queue is during stop.
            // Serialize the liveness check and the swap with certManager's
            // own monitor, which release() also uses: an unbind/release may
            // be running on stopThread after the poll thread has gone. If
            // the context has already been released, installing the snapshot
            // would leak it (nothing would ever free the new configuration).
            assertNativeAccess("swapCertConfig");
            synchronized (certManager) {
                if (certManager.getSslCtx().equals(MemorySegment.NULL)) {
                    // The endpoint released the context while this management
                    // operation was in flight. Discarding the snapshot and
                    // returning normally would report success without applying
                    // anything, contradicting the method's failure contract.
                    newConfig.free();
                    CertificateLoader.closeQuietly(newConfig.arena);
                    throw new IllegalStateException(sm.getString(
                            "quicEndpoint.certificateReloadFailed", reason));
                }
                try {
                    certManager.swapConfig(newConfig, reason);
                } catch (IllegalArgumentException e) {
                    // swapConfig() validates the cipher policy before taking
                    // ownership, so this snapshot is still ours to release. Keep
                    // the previous configuration active and fail the management
                    // operation instead of reporting success.
                    newConfig.free();
                    CertificateLoader.closeQuietly(newConfig.arena);
                    throw new IllegalStateException(sm.getString(
                            "quicEndpoint.certificateReloadFailed", reason), e);
                }
            }
        }
        // The management paths re-register the host configurations before the
        // native snapshot swap, so createSSLContext() populated their JMX
        // "enabled ciphers" from the previous SSL_CTX. Refresh them from the
        // newly installed context now that the swap has completed, otherwise
        // enabledCiphers reports the old cipher policy until the next
        // management operation.
        for (SSLHostConfig sslHostConfig : sslHostConfigs.values()) {
            refreshTlsInformation(sslHostConfig);
        }
    }


    private void createListener() throws Exception {
        // Create QUIC listener SSL object from the manager's native SSL_CTX
        listener = QuicBindings.SSL_new_listener(certManager.getSslCtx(), 0L);
        if (listener.equals(MemorySegment.NULL)) {
            throw new IOException(sm.getString("quicEndpoint.listenerCreateError"));
        }

        configureListenerIdleTimeout();
        configureListenerPendingConnections();

        // Attach the socket to the listener - OpenSSL creates the internal
        // datagram BIO from the platform-provided native descriptor.
        int rc = QuicBindings.SSL_set_fd(listener, PLATFORM.openSslFd(socketHandle));
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
            log.debug("Created QUIC listener on " + PLATFORM.describe(socketHandle) +
                    " (0x" + Long.toHexString(listener.address()) + ")");
        }

     // Set up listener poll item
        QuicPollItem listenerItem = new QuicPollItem(listener,
                  -1L, // want_events: all bits set, so the listener receives every event type
                  null, this::markPollInterestChanged);
        listenerPollItem = listenerItem;
        pollSet.add(listenerItem);
    }


    /**
     * Creates the UDP socket and binds it through the platform implementation.
     * The socket handle is kept in {@link #socketHandle}; the attachment to the
     * listener via {@code SSL_set_fd()} is done separately by
     * {@link #createListener()}. Supports both IPv4 and IPv6; with no connector
     * address configured it binds the dual-stack wildcard ({@code ::} accepting
     * IPv4 as well), mirroring the NIO endpoints' default, and falls back to
     * the IPv4 wildcard when the IPv6 family is unusable.
     */
    private void createUdpSocket() throws Exception {
        int port = getPortWithOffset();
        // Port -1 (Tomcat's ephemeral convention) or 0 means "assign any free
        // port". Use port 0 so the OS assigns one and let the platform resolve
        // the actual port after bind() (mirrors NioEndpoint). Mapping to a
        // well-known port here would make two port=-1 connectors share UDP via
        // SO_REUSEPORT (split-brain).
        if (port > 65535) {
            throw new IOException(sm.getString("quicEndpoint.portOutOfRange",
                    Integer.valueOf(port)));
        }
        if (port <= 0) {
            port = 0;
        }

        InetAddress configuredAddr = getAddress();
        InetAddress bindAddr;
        QuicPlatformSupport.SocketHandle boundSocket;
        int actualPort;
        if (configuredAddr != null) {
            // Explicit address: family taken from the address. For an IPv6
            // address the platform implementation sets IPV6_V6ONLY explicitly
            // (1, so it cannot accept IPv4-mapped connections).
            bindAddr = configuredAddr;
            QuicPlatformSupport.BoundUdpSocket bound = bindUdpSocket(bindAddr, port, false);
            boundSocket = bound.socket();
            actualPort = bound.boundPort();
        } else {
            // No configured address: mirror the NIO endpoints' default of the
            // dual-stack wildcard (:: with IPV6_V6ONLY=0, which also accepts
            // IPv4), falling back to the IPv4 wildcard when the IPv6 family is
            // unusable in this environment or when the JVM prefers IPv4
            // (java.net.preferIPv4Stack, the same switch the NIO bind honours).
            bindAddr = null;
            boundSocket = null;
            actualPort = port;
            if (!Boolean.getBoolean("java.net.preferIPv4Stack")) {
                try {
                    InetAddress candidate = InetAddress.getByName("::");
                    QuicPlatformSupport.BoundUdpSocket bound = bindUdpSocket(candidate, port, true);
                    bindAddr = candidate;
                    boundSocket = bound.socket();
                    actualPort = bound.boundPort();
                } catch (DualStackUnavailable | java.net.UnknownHostException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("IPv6 wildcard bind unavailable, falling back "
                                + "to IPv4: " + e.getMessage());
                    }
                }
            }
            if (boundSocket == null) {
                bindAddr = InetAddress.getByName("0.0.0.0");
                QuicPlatformSupport.BoundUdpSocket bound = bindUdpSocket(bindAddr, port, false);
                boundSocket = bound.socket();
                actualPort = bound.boundPort();
            }
        }

        // Publish the socket as soon as it is bound so any later setup failure
        // (wake-up creation, listener creation) releases it through
        // releaseBindResources() instead of leaking it.
        this.socketHandle = boundSocket;

        // Wake primitive for the poll loop: the poll thread waits on this
        // socket together with the platform wake object, and the mailbox kicks
        // that object whenever another thread queues a poll task (SSL_poll()
        // itself cannot be woken from outside - see QuicWakeup).
        quicWakeup = new QuicWakeup(boundSocket);
        mailbox.setWaker(quicWakeup::kick);

        bindAddress = new InetSocketAddress(bindAddr, actualPort);

        if (log.isDebugEnabled()) {
            log.debug("Created UDP socket " + PLATFORM.describe(boundSocket) +
                    " bound to " + bindAddress +
                    (bindAddr instanceof java.net.Inet6Address ? " (IPv6)" : " (IPv4)"));
        }
    }


    /**
     * Binds a UDP socket through the selected platform implementation. The
     * endpoint keeps the address-selection and IPv4 fallback policy; the
     * platform owns the native socket setup. An explicit IPv6 link-local bind
     * address with a scope is not translated into {@code sin6_scope_id} and
     * fails rather than binding the wrong interface.
     *
     * @param bindAddr  The address to bind
     * @param port      The port to bind; {@code 0} requests an ephemeral port
     * @param dualStack {@code true} for the IPv6 wildcard candidate
     *
     * @return The bound socket and its actual port
     *
     * @throws DualStackUnavailable The failure rules out only the address
     *         family, so the caller may try the IPv4 wildcard
     * @throws IOException A genuine bind failure
     */
    private QuicPlatformSupport.BoundUdpSocket bindUdpSocket(InetAddress bindAddr, int port,
            boolean dualStack) throws DualStackUnavailable, IOException {
        try {
            return PLATFORM.bindUdpSocket(bindAddr, port, new QuicPlatformSupport.UdpSocketOptions(
                    socketProperties.getRxBufSize(),
                    socketProperties.getTxBufSize(), dualStack));
        } catch (QuicPlatformSupport.QuicPlatformException e) {
            if (dualStack && (e.isAddressFamilyUnavailable() ||
                    e.isAddressNotAvailable() || e.isPermissionDenied())) {
                throw new DualStackUnavailable(e.getMessage());
            }
            throw e;
        }
    }


    /**
     * Signals a bind candidate that failed for a reason which rules out only
     * its address family, so the default (no configured address) bind can fall
     * back from the dual-stack wildcard to the IPv4 wildcard. A genuine bind
     * failure (busy port, no permission) is never reported this way: it
     * propagates as the bind error it is.
     */
    private static final class DualStackUnavailable extends Exception {

        private static final long serialVersionUID = 1L;

        private DualStackUnavailable(String message) {
            super(message);
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
        if (failedStopCleanupRequired) {
            // The previous stop could not join the poll thread. Its cleanup
            // was deferred until the thread exited; run it now before a new
            // loop starts against the same listener and poll set.
            log.warn(sm.getString("quicEndpoint.failedStopRecovery", getName()));
            stopInternal();
        }
        if (hasActiveRetainedHandlers()) {
            // Previous-generation handlers still own streams whose poll items
            // stopInternal() cleared from the poll set. The bind resources may
            // still be allocated (BOUND_ON_INIT) or already released
            // (bindOnInit=false), but in both cases a start would either run
            // against a closed socket or leave those handlers' streams
            // unpolled. Wait until they finish and the next bind re-creates a
            // consistent generation.
            throw new IllegalStateException(sm.getString(
                    "quicEndpoint.retainedHandlersRunning", getName()));
        }
        if (getExecutor() == null) {
            createExecutor();
        }
        // A start clears any prior pause, as the other endpoints do, so a
        // restart after pause() does not come back up refusing connections.
        paused = false;
        running = true;
        // Reapply the listener's pending-handshake bound and idle timeout in
        // case either changed at runtime while no poll thread was running.
        // A BOUND_ON_INIT restart reuses the listener from the previous bind
        // without calling bind()/createListener(), so the listener otherwise
        // keeps the timeout applied at the original bind even though
        // QuicProtocol.getIdleTimeoutMs() may have changed while stopped.
        // The poll thread is not started yet, so this thread is the single
        // native caller.
        configureListenerPendingConnections();
        configureListenerIdleTimeout();
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
        // sweep frees (every queueStreamDrain precedes its owner's handler
        // decrement, so a handler count of zero means no further stream free
        // can arrive).
        if (pollThread == null || !pollThread.isAlive()) {
            mailbox.drainPendingStreamDrains(null, true);
            drainPendingStreamFrees();
            drainCleanerStreamFrees();
            drainCleanerConnectionFrees();
        }
        // Re-open the mailbox before the retention sweep so a handler that
        // completes while the sweep runs is not orphaned: its deferred free
        // must be accepted here. Previously the sweep ran against a closed
        // mailbox; a handler finishing between the sweep's
        // hasActiveHandlers() check and mailbox.open() had its free rejected
        // and the connection stayed in stoppedBusyConnections forever.
        // open() also drops poll tasks left over from the previous
        // generation's stop before the new poll thread can drain them: such a
        // task was submitted after the stop had already freed (or deferred)
        // every connection it owned, so running it would operate on freed
        // native state. Workers whose hops are rejected observe a
        // RejectedExecutionException from callOnPollThread instead of a 30 s
        // hop timeout.
        mailbox.open();
        // Stop-time retentions whose handler has since completed: complete
        // their deferred free here (the mailbox task that carried it may have
        // been discarded by the mailbox close below) and drop them from the
        // set - otherwise the wrappers and their native connection SSLs
        // accumulate across stop/start cycles for the endpoint's lifetime.
        // Entries with handlers still running stay retained (a free under a
        // live handler would be a use-after-free). The liveness condition is
        // belt-and-braces: the guards above already refused the start while
        // the previous poll thread was alive and while previous-generation
        // handlers were still active.
        if (pollThread == null || !pollThread.isAlive()) {
            java.util.Iterator<QuicConnectionWrapper> iterator =
                    stoppedBusyConnections.iterator();
            while (iterator.hasNext()) {
                reclaimRetainedConnection(iterator.next(), true);
            }
        }
        // Drop protocol-data bookkeeping left over from the previous
        // generation. A handler that outlived the stop budget can mark a
        // retained connection after stopInternal() cleared the queues; those
        // marks can never be flushed (the previous stop dropped the manager
        // state) and would otherwise keep the wrapper retained for the
        // endpoint's lifetime. Clear the retained flags first, then the
        // queues; hold protocolDataLock across the clear so a late worker
        // cannot slip a flag transition between the flag clear and the queue
        // clear.
        synchronized (protocolDataLock) {
            for (QuicConnectionWrapper conn : stoppedBusyConnections) {
                setConnectionProtocolDataPending(conn, false);
            }
            protocolDataMarks.clear();
            protocolDataConns.clear();
            protocolDataRetry.clear();
            protocolDataWakePending.set(false);
        }
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
        stopThread = Thread.currentThread();
        try {
            if (pollThread != null) {
                pollThread.interrupt();
                // A thread blocked in the native poll(2)/SSL_poll() call is not
                // interrupted by Thread.interrupt(): kick the platform wake object
                // so the
                // loop re-checks the stop flag on its next iteration instead of
                // after the wait timeout.
                QuicWakeup wakeup = quicWakeup;
                if (wakeup != null) {
                    wakeup.kick();
                }
                // Wait out the same bounded budget even if the stopping thread
                // is interrupted: Thread.interrupt() clears the interrupt status
                // when it throws, so keep joining until the deadline and restore
                // the flag afterwards. Proceeding to the native cleanup while
                // the poll thread is still alive would be a use-after-free.
                long joinDeadline = System.currentTimeMillis() + 5000L;
                boolean interrupted = false;
                while (pollThread.isAlive()) {
                    long remaining = joinDeadline - System.currentTimeMillis();
                    if (remaining <= 0L) {
                        break;
                    }
                    try {
                        pollThread.join(remaining);
                    } catch (InterruptedException e) {
                        interrupted = true;
                    }
                }
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
                // If the poll thread is still alive here it may be dereferencing
                // the native poll set, listener, SSL_CTX and arenas, so freeing
                // them from this thread would be a use-after-free. Leak the
                // native state (log a warning) instead of risking a crash.
                if (pollThread.isAlive()) {
                    log.warn(sm.getString("quicEndpoint.pollThreadNotStopped"));
                    failedStopCleanupRequired = true;
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
            // transport. Any hop tasks queued before the poll loop stopped are
            // drained while waiting; new hops submitted after the poll thread
            // exited fail fast with RejectedExecutionException. Handlers that
            // outlive this budget are interrupted by the executor shutdown
            // below.
            drainWhile(System.currentTimeMillis() + ACTIVE_HANDLER_SHUTDOWN_WAIT_MS,
                    this::hasActiveRequestHandlers);

            shutdownExecutor();

            // Give the handlers the executor shutdown just interrupted a short
            // window to unwind. Only hop tasks already queued before the poll
            // thread exited can still run; new hops are rejected immediately,
            // so their close paths fail fast instead of stranding in-flight
            // poll tasks.
            drainWhile(System.currentTimeMillis() + ACTIVE_HANDLER_SHUTDOWN_WAIT_MS,
                    this::hasActiveRequestHandlers);

            // shutdownExecutor() uses shutdownNow() for the internal executor.
            // Queued tasks may be discarded without running their finally block,
            // or may still start (VirtualThreadExecutor does not cancel them).
            // discardQueuedDispatches() balances only tasks that lost the
            // per-record claim to the stop path; a task that starts owns its
            // active-handler reference and releases it when it finishes. An
            // external executor is not shut down here, so its tasks may still
            // run and must not be balanced.
            if (getExecutor() == null) {
                for (QuicConnectionWrapper conn : connections.values()) {
                    discardQueuedDispatches(conn);
                }
                for (QuicConnectionWrapper conn : stoppedBusyConnections) {
                    discardQueuedDispatches(conn);
                }
            }

            // Clean up HTTP/3 connection managers first
            for (QuicConnectionWrapper conn : connections.values()) {
                QuicConnectionManager connManager = conn.getQuicConnectionManager();
                conn.setQuicConnectionManager(null);
                if (connManager != null) {
                    try {
                        connManager.connectionClose(conn);
                    } catch (Throwable t) {
                        // A failing protocol callback must not abort the rest of
                        // the shutdown cleanup.
                        logTeardownError(conn, t);
                    }
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
                        ExceptionUtils.handleThrowable(t);
                        log.warn(sm.getString("quicEndpoint.streamSslFreeError",
                                Long.toHexString(stream.getSslAddress())), t);
                        // The stream may still be alive after a failed free.
                        // Retain the connection instead of freeing it while a
                        // stream SSL could still reference it; the retention
                        // sweep will retry the complete cleanup later.
                        busyConnections.add(conn);
                    }
                }
                if (!busyConnections.contains(conn)) {
                    conn.getStreams().clear();
                }
                // Server unidirectional streams have no executor handler, so
                // their SSLs are always freed by the loop above. Drop their
                // bookkeeping even for a busy connection; the connection manager
                // has already been closed at this point of stopInternal().
                conn.clearServerUniStreams();
            }

            // Free any stream SSL objects whose deferred free the poll loop did
            // not get to run, including streams still waiting for their native
            // write buffer to drain: stop cannot wait for ACK processing.
            mailbox.drainPendingStreamDrains(null, true);
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
            writeInterestedWrappers.clear();

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
                // so clear the pending mark; this is the same bookkeeping
                // teardownConnection() maintains.
                // Without it, a connection stopped while its flush had not yet
                // drained leaves a stale mark in the protocol-data bookkeeping
                // until stop/restart.
                setConnectionProtocolDataPending(conn, false);
                // Claim the free first, then re-check (same ordering as
                // freeConnectionOrDefer): a worker that completes between the
                // outer check and the claim would otherwise find nothing
                // pending and leave the wrapper retained forever. This claim is
                // taken for every connection, including one that is not in
                // busyConnections: a handler that deregistered its stream just
                // before the stream-free pass can queue a deferred stream free
                // after that pass, and the direct free path must not race it.
                conn.setPendingFree();
                if (!conn.hasActiveHandlers() && !busyConnections.contains(conn) &&
                        !conn.hasStreamFreeFailure() &&
                        conn.clearPendingFree()) {
                    // Every deferred stream free is queued before its owner's
                    // handler decrement, so a count of zero means no further
                    // stream free can arrive. Drain all queues for this
                    // connection before freeing its SSL; this also handles a
                    // connection that was not marked busy because its stream had
                    // already been deregistered by a closing handler.
                    mailbox.drainPendingStreamDrains(conn, false);
                    drainPendingStreamFrees();
                    drainCleanerStreamFrees();
                    drainCleanerConnectionFrees();
                    boolean freed = false;
                    try {
                        freed = conn.freeSslOnce() || conn.isFreed();
                    } catch (Throwable t) {
                        ExceptionUtils.handleThrowable(t);
                        log.warn(sm.getString("quicEndpoint.connectionSslFreeError",
                                Long.toHexString(conn.getSslAddress())), t);
                    }
                    if (freed) {
                        continue;
                    }
                    // A stream SSL free failed during the drains above. Keep
                    // the connection (and any deferred socket) retained so its
                    // native object is not leaked without a Java-side owner.
                    conn.setPendingFree();
                }
                stoppedBusyConnections.add(conn);
                if (log.isDebugEnabled()) {
                    log.debug("Retaining connection SSL 0x" +
                            Long.toHexString(conn.getSslAddress()) +
                            " for deferred cleanup at stop");
                }
            }
            // Complete frees for connections that were torn down and retained
            // before stop() (their teardown removed them from the connections map)
            // once their handler has finished. Connections still owned by a
            // running handler stay in stoppedBusyConnections for the start-time
            // sweep; a connection whose handler completed during this stop must
            // not leak its native SSL just because it is absent from the
            // connections map.
            java.util.Iterator<QuicConnectionWrapper> retainedIterator =
                    stoppedBusyConnections.iterator();
            while (retainedIterator.hasNext()) {
                QuicConnectionWrapper conn = retainedIterator.next();
                if (conn.hasActiveHandlers()) {
                    continue;
                }
                // Use the same cleanup path as the start-time and unbind sweeps:
                // it re-checks that every stream SSL is actually freed before
                // releasing the connection SSL, instead of assuming the earlier
                // stop loop and worker completions covered every stream.
                reclaimRetainedConnection(conn, false);
            }
            // Drops the retention entries: every wrapper in the map has either
            // been freed above or parked into stoppedBusyConnections (with its
            // pending-free claim and its own retention), so no Cleaner can free
            // an in-use connection SSL from the GC thread (see the connections
            // field javadoc).
            connections.clear();

            // Drop every connection/stream item from the poll set, leaving only the
            // listener. The poll set is part of the bind resources and is reused by
            // a restart of an endpoint bound on init (stop() does not unbind a
            // BOUND_ON_INIT endpoint), so leaving items whose SSLs were freed above
            // would make the next poll loop call SSL_poll() on freed pointers.
            if (pollSet != null && listenerPollItem != null) {
                pollSet.clear();
                streamPollItems.clear();
                lingeringStreamItems.clear();
                // clear() disposes every member, including the old listener
                // item. Recreate the item rather than re-adding a disposed
                // object, so the lifecycle marker stays truthful.
                listenerPollItem = new QuicPollItem(listener, -1L, null,
                        this::markPollInterestChanged);
                pollSet.add(listenerPollItem);
            }

            // Generation-confined protocol-data bookkeeping: the mark queue and
            // the poll-thread set reference wrappers of this generation (whose
            // native state is now freed). A late worker on a retained
            // connection can still transition a flag, so take the same lock
            // used by setConnectionProtocolDataPending() instead of clearing
            // the queues unsynchronized.
            synchronized (protocolDataLock) {
                protocolDataMarks.clear();
                protocolDataConns.clear();
                protocolDataRetry.clear();
            }

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

            failedStopCleanupRequired = false;
            if (log.isInfoEnabled()) {
                log.info(sm.getString("quicEndpoint.stopped", getName()));
            }
        } finally {
            stopThread = null;
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
     * <p>
     * The frames are only buffered here; one engine tick after the loop then
     * lets the batched shutdown drain flush every connection's stream output.
     * Writing through {@code writeBufferedUniStream()} per connection would
     * pump the whole shared engine once per connection, making this pass
     * O(fleet²).
     */
    private void notifyConnectionsGoingAway() {
        boolean queuedAny = false;
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
                queuedAny |= queueStreamLimitNotification(connManager, state);
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                if (log.isDebugEnabled()) {
                    log.debug("Error announcing go-away on connection 0x" +
                            Long.toHexString(conn.getSslAddress()), t);
                }
            }
        }
        if (queuedAny) {
            MemorySegment tickSsl = engineTickSsl();
            if (tickSsl != null) {
                handleEvents(tickSsl, "shutdown go-away batch");
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
        // Connections whose protocol-data flush keeps throwing. The loop runs
        // every 1 ms for up to GRACEFUL_SHUTDOWN_DRAIN_MS; log the failure once
        // per connection instead of once per iteration.
        java.util.Set<QuicConnectionWrapper> protocolFlushFailed =
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
                    UniStreamWriteResult result =
                            flushServerUniStreamWrite(stream, item);
                    if (result == UniStreamWriteResult.RETRY) {
                        activity = true;
                    } else {
                        flushFailed.add(stream);
                        if (result == UniStreamWriteResult.FAILED) {
                            // The queued shutdown GOAWAY could not be written
                            // on this control stream; let the protocol classify
                            // the critical-stream failure instead of silently
                            // dropping it.
                            handleServerUniWriteResult(stream, result);
                            if (!isConnectionLive(conn)) {
                                break;
                            }
                        }
                    }
                }
                // Flush protocol data that would normally be emitted by the
                // stopped poll loop, then tick the engine so the output (and
                // any received data) is current before waking waiters.
                QuicConnectionManager connManager = conn.getQuicConnectionManager();
                if (connManager != null && conn.isProtocolDataPending()) {
                    try {
                        connManager.flushPendingProtocolData(conn);
                        protocolFlushFailed.remove(conn);
                    } catch (Throwable t) {
                        if (protocolFlushFailed.add(conn)) {
                            logTeardownError(conn, t);
                        } else if (log.isDebugEnabled()) {
                            log.debug(sm.getString(
                                    "quicEndpoint.teardownCleanupError",
                                    Long.toHexString(conn.getSslAddress())), t);
                        }
                    }
                    if (!isConnectionLive(conn)) {
                        // The protocol callback failed the connection inline;
                        // do not touch its native SSL below.
                        continue;
                    }
                    if (conn.isProtocolDataPending()) {
                        activity = true;
                    }
                }
                if (signalStreamWaiters(conn)) {
                    activity = true;
                }
            }
            // One engine tick per drain iteration services every connection
            // (SSL_handle_events ticks the whole shared engine); ticking per
            // connection made each pass O(N) engine walks.
            MemorySegment tickSsl = engineTickSsl();
            if (tickSsl != null) {
                handleEvents(tickSsl, "shutdown drain batch");
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
     * Wakes workers parked in the wrapper's read/write waits for one
     * connection. The poll loop normally does this from
     * {@code dispatchStreamEvent()}; the shutdown drain must do it explicitly
     * because the poll loop has stopped. Signalling is harmless when no waiter
     * is registered and does not touch native state.
     *
     * @param conn The connection whose stream waiters should be signalled
     *
     * @return {@code true} if at least one read or write waiter was registered
     */
    private boolean signalStreamWaiters(QuicConnectionWrapper conn) {
        boolean found = false;
        for (QuicStreamWrapper stream : conn.getStreams().values()) {
            QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(stream);
            if (wrapper == null) {
                continue;
            }
            if (wrapper.hasReadWaiter() || wrapper.hasWriteWaiter()) {
                found = true;
            }
            wrapper.signalReadWaiter();
            wrapper.signalWriteWaiter();
        }
        for (QuicStreamWrapper stream : conn.getPendingStreams()) {
            QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(stream);
            if (wrapper == null) {
                continue;
            }
            if (wrapper.hasReadWaiter() || wrapper.hasWriteWaiter()) {
                found = true;
            }
            wrapper.signalReadWaiter();
            wrapper.signalWriteWaiter();
        }
        return found;
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
        if (connections.isEmpty()) {
            return;
        }
        // SSL_shutdown_ex() was called once by queueConnectionClosesForShutdown()
        // while the connections still had streams. If the stream-flush phase
        // was still in progress it returned 0 without queueing a
        // CONNECTION_CLOSE. Now that the stream SSLs have been freed (the stop
        // stream pass above), re-enter shutdown with NO_STREAM_FLUSH so the
        // close frame is actually queued. This is a cheap native call per
        // connection; the engine is still ticked once for the whole batch.
        for (QuicConnectionWrapper conn : connections.values()) {
            if (!conn.isFreed()) {
                completeConnectionShutdown(conn.getSsl(),
                        conn.getConnectionCloseErrorCode());
            }
        }
        // SSL_handle_events() ticks the whole shared engine, so one batched
        // pass over the listener transmits every queued CONNECTION_CLOSE.
        // Tick once per batch instead of CONNECTION_CLOSE_FLUSH_ATTEMPTS per
        // connection: the per-connection loop made stop O(N^2) in the fleet.
        MemorySegment tickSsl = engineTickSsl();
        if (tickSsl == null) {
            return;
        }
        for (int flush = 0; flush < CONNECTION_CLOSE_FLUSH_ATTEMPTS; flush++) {
            handleEvents(tickSsl, "flush queued connection closes");
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
        // Tear down connections removed from the connections map while a
        // handler was still active are retained in stoppedBusyConnections;
        // they must be included in the wait or their worker is interrupted
        // before it can finish and queue its deferred free.
        for (QuicConnectionWrapper conn : stoppedBusyConnections) {
            if (conn.hasActiveHandlers()) {
                return true;
            }
        }
        return false;
    }


    /**
     * Checks whether a retained connection still has an executor worker
     * running its HTTP handler. Unlike {@link #hasActiveRequestHandlers()},
     * this deliberately does not include the current generation's connections
     * map: it is the guard used before creating a new bind generation.
     *
     * @return {@code true} if a previous-generation handler is still active
     */
    private boolean hasActiveRetainedHandlers() {
        for (QuicConnectionWrapper conn : stoppedBusyConnections) {
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
     * reclaim path for both a normal stop and a bind that never started. If
     * the previous {@link #stopInternal()} could not join the poll thread and
     * deferred its cleanup, this method first completes that full cleanup once
     * the thread has exited, before releasing the bind resources.
     */
    @Override
    public void unbind() throws Exception {
        // releaseBindResources() frees native objects the poll thread
        // dereferences. If the poll thread is still alive (it is blocked in the
        // native SSL_poll() and could not be joined during stop), freeing them
        // here would be a use-after-free. Fail the unbind instead of reporting
        // success: the caller keeps the endpoint bound, so a later stop/destroy
        // can retry once the poll thread has exited. Silently returning would
        // let the lifecycle commit an UNBOUND state while the native
        // generation is still allocated.
        if (pollThread != null && pollThread.isAlive()) {
            failedStopCleanupRequired = true;
            log.warn(sm.getString("quicEndpoint.pollThreadNotStopped"));
            throw new IllegalStateException(
                    sm.getString("quicEndpoint.pollThreadNotStopped"));
        }
        if (failedStopCleanupRequired) {
            // A previous stop returned early because the poll thread
            // outlived its join budget, leaving the listener, SSL_CTX,
            // connections and streams uncleaned. The thread has now
            // exited, so complete that deferred full cleanup before
            // releaseBindResources() drops the native generation the
            // connections still reference.
            log.warn(sm.getString("quicEndpoint.failedStopRecovery", getName()));
            stopInternal();
        }
        if (failedStopCleanupRequired) {
            // The recovery stop could not complete either; do not free
            // the bind resources under the leftover native state.
            log.warn(sm.getString("quicEndpoint.pollThreadNotStopped"));
        } else {
            releaseBindResources();
        }
        super.unbind();
    }


    @Override
    protected void doCloseServerSocket() throws IOException {
        // Do not close the listener datagram socket: a QUIC endpoint
        // multiplexes every connection over it, and closing it here (the
        // graceful shutdown hook) would black-hole the in-flight connections
        // that awaitConnectionsClose() is about to wait for. The FD is closed
        // by unbind() (via releaseBindResources()) after the poll thread and
        // the connections are gone; deliberately do not reset socketHandle here so
        // that path can still find and close it.
        // The base closeServerSocketGraceful() stops an acceptor; QUIC has no
        // acceptor, so pause the endpoint here instead. handleIncomingConnection
        // and Http3Processor then refuse new connections/streams during the
        // graceful window while existing requests drain.
        paused = true;
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
     * Required override (AbstractEndpoint's abstract contract). This is a
     * live QUIC path: async servlet completion, dispatch, error and timeout
     * events reach it through SocketWrapperBase.processSocket() ->
     * AbstractEndpoint.processSocket() -> createSocketProcessor(); see the
     * QuicSocketProcessor comment for the dispatch accounting.
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
     * Marks the poll interest changed for the next poll-loop iteration. Called
     * by {@link QuicPollItem#setWantEvents(long)} on the poll thread.
     */
    void markPollInterestChanged() {
        pollInterestWakePending.set(true);
    }


    /**
     * Records whether a connection has protocol data (for HTTP/3: QPACK
     * decoder instructions) pending emission. Called from any thread (the
     * HTTP/3 connection manager queues instructions from worker and protocol
     * threads); the poll loop consumes the marks and sweeps only the
     * connections named in {@link #protocolDataMarks}.
     *
     * @param conn    The connection wrapper
     * @param pending {@code true} when instructions were queued,
     *                {@code false} once the flush drained them
     */
    void setConnectionProtocolDataPending(QuicConnectionWrapper conn,
            boolean pending) {
        boolean kick = false;
        synchronized (protocolDataLock) {
            if (conn.protocolDataPendingTransition(pending)) {
                if (pending) {
                    protocolDataMarks.add(conn);
                    protocolDataWakePending.set(true);
                    kick = true;
                }
            }
        }
        if (kick && !isPollThread()) {
            // A worker's mark must not wait out an in-progress poll-loop wait.
            // The poll thread itself will notice protocolDataWakePending on its
            // current iteration, so only off-thread transitions need the kick.
            QuicWakeup wakeup = quicWakeup;
            if (wakeup != null) {
                wakeup.kick();
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
        if (pollThread == null || !pollThread.isAlive()) {
            // After the poll loop has stopped, the stop thread is the only
            // allowed native caller (assertNativeAccess() permits it once
            // the loop is gone). Protocol callbacks invoked by
            // stopInternal() run on that thread; run their native operation
            // inline instead of queuing a hop that nothing will drain and
            // blocking for the full hop timeout.
            if (Thread.currentThread() == stopThread) {
                assertNativeAccess("callOnPollThread");
                return task.call();
            }
            // Any other caller has no poll thread left to execute the hop.
            // Fail fast instead of waiting out the full timeout (the mailbox
            // may still be open during the stop drain).
            throw new RejectedExecutionException(
                    sm.getString("quicEndpoint.pollTaskRejected"));
        }
        CompletableFuture<T> future = new CompletableFuture<>();
        DiscardablePollTask hopTask = new DiscardablePollTask() {
            @Override
            public void run() {
                try {
                    future.complete(task.call());
                } catch (Throwable t) {
                    future.completeExceptionally(t);
                }
            }

            @Override
            public void onDiscard() {
                // The mailbox was closed/opened while the hop was queued, so
                // it will never run. Complete the waiter immediately instead
                // of letting it wait out the full hop timeout.
                future.completeExceptionally(new RejectedExecutionException(
                        sm.getString("quicEndpoint.pollTaskRejected")));
            }
        };
        if (!submitPollTask(hopTask)) {
            // Mailbox closed (endpoint stopped): fail fast rather than wait
            // out the hop timeout for a task that will never run.
            throw new RejectedExecutionException(
                    sm.getString("quicEndpoint.pollTaskRejected"));
        }
        return future.get(POLL_TASK_HOP_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    }


    /**
     * Runs all queued poll tasks on the poll thread. Called at the top of
     * every poll loop iteration, BEFORE the poll subset is built and
     * {@code SSL_poll()} runs, so tasks that mutate the poll set or free
     * native objects take effect before the next {@code SSL_poll()} sees them.
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
            // A handler blocked in awaitReadableData()/awaitWritable() is
            // parked on LockSupport and is not a poll task, so draining the
            // mailbox alone does not release it. Signal the stream waiters on
            // every iteration so shutdown is observed promptly even when an
            // external executor keeps the handler thread alive past the
            // executor shutdown (or no shutdown is performed at all).
            signalAllStreamWaiters();
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        drainPollTasks();
        signalAllStreamWaiters();
    }


    /**
     * Signals every read/write waiter parked on a live connection. Harmless
     * when no waiter is registered and does not touch native state.
     */
    private void signalAllStreamWaiters() {
        for (QuicConnectionWrapper conn : connections.values()) {
            if (!conn.isFreed()) {
                signalStreamWaiters(conn);
            }
        }
        for (QuicConnectionWrapper conn : stoppedBusyConnections) {
            if (!conn.isFreed()) {
                signalStreamWaiters(conn);
            }
        }
    }


    /**
     * Balances dispatch tasks that never started and releases the processing
     * claims they still hold. The per-record claim ensures a task that started
     * concurrently keeps its own active-handler reference and runs normally;
     * only the losing task is discarded here. A task that never runs its
     * finally block would otherwise leave the stream claimed and the
     * connection retained forever.
     *
     * @param conn The connection whose discarded dispatch tasks to process
     */
    private void discardQueuedDispatches(QuicConnectionWrapper conn) {
        for (QuicStreamWrapper stream : conn.discardQueuedDispatches()) {
            stream.clearProcessing();
            if (stream.isDeregistered() && !stream.isFreed()) {
                // The discarded dispatch was the only owner that could have
                // queued this stream's SSL free. The stream is no longer in
                // the connection's stream map (closeStream() deregisters it
                // before queueing the dispatch), so the stop-time stream-free
                // pass will not find it. Queue the deferred free now that the
                // processing claim has been released.
                mailbox.queueStreamDrain(stream);
            }
            wakeClaimWaiters(stream, conn);
        }
    }


    /**
     * Completes the deferred free of a connection retained in
     * {@link #stoppedBusyConnections}, provided no handler still owns it and
     * every stream SSL is gone (or can be freed here). Safe to call after the
     * poll thread has stopped, from the stop/unbind thread or from the last
     * handler's worker. If the connection is still owned by a handler, it is
     * left retained.
     *
     * @param conn            The retained connection
     * @param allowDuringStart {@code true} when called from the start-time
     *                         retention sweep, which runs before the new poll
     *                         thread is created; otherwise the endpoint must
     *                         not be running (a worker finishing during a
     *                         restart leaves the cleanup to that sweep)
     *
     * @return {@code true} if the connection was freed or was already freed
     */
    private boolean reclaimRetainedConnection(QuicConnectionWrapper conn,
            boolean allowDuringStart) {
        synchronized (retainedCleanupLock) {
            if (conn.isFreed()) {
                // The connection SSL is already gone, but a deferred stream
                // free for this connection may still be queued (for example
                // when stop had to skip a stream owned by a handler). Do not
                // drop the retention entry without releasing those streams:
                // the connection is freed, so force the connection-specific
                // drains while no poll loop is running.
                if (pollThread == null || !pollThread.isAlive()) {
                    try {
                        mailbox.drainPendingStreamDrains(conn, false);
                        drainPendingStreamFrees();
                        drainCleanerStreamFrees();
                        drainCleanerConnectionFrees();
                    } catch (Throwable t) {
                        ExceptionUtils.handleThrowable(t);
                        log.warn(sm.getString("quicEndpoint.connectionSslFreeError",
                                Long.toHexString(conn.getSslAddress())), t);
                    }
                }
                stoppedBusyConnections.remove(conn);
                closeDeferredSocketsIfSafe();
                return true;
            }
            if (conn.hasStreamFreeFailure()) {
                // A stream SSL free failed. Its native object may still be
                // alive even though the Java wrapper is marked freed; do not
                // free the connection SSL under it. Retain/leak the native
                // connection rather than risk the stream-before-connection
                // ordering violation.
                if (conn.claimRetentionWarningLog()) {
                    log.warn(sm.getString(
                            "quicEndpoint.connectionRetentionExhaustion",
                            Long.toHexString(conn.getSslAddress())));
                } else if (log.isDebugEnabled()) {
                    log.debug("Retaining connection SSL 0x" +
                            Long.toHexString(conn.getSslAddress()) +
                            " because a stream SSL free failed");
                }
                return false;
            }
            if (conn.hasActiveHandlers()) {
                return false;
            }
            if (pollThread != null && pollThread.isAlive()) {
                // The poll thread still owns native state and will finish the
                // cleanup through its normal paths.
                return false;
            }
            if (running && !allowDuringStart) {
                // The endpoint is running (or a start is in progress). Native
                // state must remain confined to the poll thread/start sweep.
                return false;
            }
            setConnectionProtocolDataPending(conn, false);
            try {
                // Free idle streams directly (the stop paths may not have
                // queued every stream) and drain the deferred/cleaner queues.
                for (QuicStreamWrapper stream : conn.getStreams().values()) {
                    if (!stream.isFreed() && !stream.freeSslIfIdle()) {
                        // A stream is still claimed by a worker. Keep the
                        // connection retained; that worker queues the free.
                        return false;
                    }
                }
                mailbox.drainPendingStreamDrains(conn, false);
                drainPendingStreamFrees();
                drainCleanerStreamFrees();
                drainCleanerConnectionFrees();
                for (QuicStreamWrapper stream : conn.getStreams().values()) {
                    if (!stream.isFreed()) {
                        return false;
                    }
                }
                conn.getStreams().clear();
                conn.getPendingStreams().clear();
                conn.clearServerUniStreams();
                // The close frame queued by stopInternal()/failConnection()
                // may not have been transmitted while the streams were still
                // alive. Flush it now that every stream SSL is gone, before
                // SSL_free() discards it.
                if (!conn.isFreed()) {
                    flushConnectionClose(conn);
                }
                boolean freed = conn.freeSslOnce() || conn.isFreed();
                if (!freed) {
                    // The free was skipped because a stream SSL free failed.
                    // Keep the retention entry (and the deferred socket) so a
                    // later sweep can retry; dropping them now would leak the
                    // native connection with no Java-side owner.
                    return false;
                }
                stoppedBusyConnections.remove(conn);
                closeDeferredSocketsIfSafe();
                return true;
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("quicEndpoint.connectionSslFreeError",
                        Long.toHexString(conn.getSslAddress())), t);
                return false;
            }
        }
    }


    /**
     * Reclaims retained connections whose handlers have completed. Called
     * when the endpoint is unbound/destroyed and no later start can run the
     * retention sweep.
     */
    private void reclaimRetainedConnections() {
        if (pollThread != null && pollThread.isAlive()) {
            return;
        }
        java.util.Iterator<QuicConnectionWrapper> iterator =
                stoppedBusyConnections.iterator();
        while (iterator.hasNext()) {
            reclaimRetainedConnection(iterator.next(), false);
        }
    }


    /**
     * Frees every stream SSL of a connection that is not currently claimed by
     * a worker.
     *
     * @param conn The connection
     *
     * @return {@code true} if all stream SSLs are freed, {@code false} if at
     *         least one is still owned or could not be freed
     */
    private boolean freeIdleStreams(QuicConnectionWrapper conn) {
        boolean allFreed = true;
        // Attempt every stream even if an earlier free failed. The connection
        // must remain retained when any stream is still owned or failed to
        // free, but the other independent stream SSLs can still be released
        // instead of being leaked with the retained connection.
        for (QuicStreamWrapper stream : conn.getStreams().values()) {
            if (stream.isFreed()) {
                continue;
            }
            try {
                if (!stream.freeSslIfIdle()) {
                    allFreed = false;
                }
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("quicEndpoint.streamSslFreeError",
                        Long.toHexString(stream.getSslAddress())), t);
                allFreed = false;
            }
        }
        return allFreed && !conn.hasStreamFreeFailure();
    }


    /**
     * Frees the connection SSL, or defers the free if an executor worker is
     * still running the HTTP handler for a stream on this connection. The
     * worker that brings {@code activeHandlers} to zero schedules the free
     * as a poll task.
     *
     * @param conn The connection whose SSL should be freed
     */
    private void freeConnectionOrDefer(QuicConnectionWrapper conn) {
        assertNativeAccess("freeConnectionOrDefer");
        // Claim the free before inspecting the streams or the handler count.
        // Otherwise a worker that finishes during freeIdleStreams() sees no
        // pending-free flag, does not schedule the free, and the connection
        // is retained forever with no worker left to complete it.
        conn.setPendingFree();
        // A teardown callback or a failed close sequence may leave streams
        // that closeAllStreams() never reached. Never free the connection SSL
        // while any stream SSL is still alive; free idle streams here, and
        // retain the connection (with the pending-free claim taken above)
        // when a stream is still owned by a worker.
        if (!freeIdleStreams(conn)) {
            stoppedBusyConnections.add(conn);
            if (conn.hasStreamFreeFailure() && conn.claimRetentionWarningLog()) {
                log.warn(sm.getString(
                        "quicEndpoint.connectionRetentionExhaustion",
                        Long.toHexString(conn.getSslAddress())));
            } else if (log.isDebugEnabled()) {
                log.debug("Retaining connection SSL 0x" +
                        Long.toHexString(conn.getSslAddress()) +
                        " until its stream SSLs are released");
            }
            return;
        }
        // Re-check the handler count only after the claim is visible: a
        // handler that exits between an initial count check and setting the
        // flag would find nothing pending and the deferred free would never
        // run (the worker that brings activeHandlers to zero claims the
        // flag).
        if (!conn.hasActiveHandlers() && conn.clearPendingFree()) {
            // A worker that finished after teardown drained the queues may
            // have queued a stream drain or a Cleaner free since then. Drain
            // every queue for this connection before SSL_free so no stream
            // SSL outlives the connection SSL (SSL_new_stream(3)).
            mailbox.drainPendingStreamDrains(conn, false);
            drainPendingStreamFrees();
            drainCleanerStreamFrees();
            drainCleanerConnectionFrees();
            if (!freeIdleStreams(conn)) {
                // A stream SSL is still alive (or could not be freed).
                // Re-claim the pending free and retain the connection; the
                // worker that owns the stream completes it.
                conn.setPendingFree();
                stoppedBusyConnections.add(conn);
                if (conn.hasStreamFreeFailure() && conn.claimRetentionWarningLog()) {
                    log.warn(sm.getString(
                            "quicEndpoint.connectionRetentionExhaustion",
                            Long.toHexString(conn.getSslAddress())));
                } else if (log.isDebugEnabled()) {
                    log.debug("Retaining connection SSL 0x" +
                            Long.toHexString(conn.getSslAddress()) +
                            " after a stream SSL could not be released");
                }
                return;
            }
            boolean freed = conn.freeSslOnce() || conn.isFreed();
            if (!freed) {
                // The free was skipped because a stream SSL free failed: keep
                // the retention entry rather than dropping the only strong
                // reference to a still-allocated connection.
                conn.setPendingFree();
                stoppedBusyConnections.add(conn);
                if (conn.hasStreamFreeFailure() && conn.claimRetentionWarningLog()) {
                    log.warn(sm.getString(
                            "quicEndpoint.connectionRetentionExhaustion",
                            Long.toHexString(conn.getSslAddress())));
                }
                return;
            }
            // The connection SSL is gone. abortConnectionSetup() can reach
            // this branch after a teardown already parked the connection in
            // stoppedBusyConnections; drop that stale retention entry and
            // release any deferred socket whose last user just went away.
            synchronized (retainedCleanupLock) {
                stoppedBusyConnections.remove(conn);
                closeDeferredSocketsIfSafe();
            }
            return;
        }
        if (log.isDebugEnabled()) {
            log.debug("Deferring connection SSL free (0x"
                    + Long.toHexString(conn.getSslAddress())
                    + ") until active handlers complete");
        }
        // Retention: a connection removed from the connections map by a
        // deferred teardown must still be visible to stopInternal()'s handler
        // wait/cleanup and to the start-time retention sweep. The worker that
        // brings activeHandlers to zero removes it after freeing.
        stoppedBusyConnections.add(conn);
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
     * Re-drives write interest level-wise, independent of OpenSSL's W poll
     * event. A stream whose native write buffer is full reports no W event
     * even after the peer opens more flow-control credit, because OpenSSL's
     * writable test also requires free space in that buffer (the buffer is
     * growable on the next write, so the test is stricter than the actual
     * write contract). Re-checking the latched interests every iteration lets
     * the wrapper drain staged bytes, or dispatch OPEN_WRITE so the protocol
     * can hand more application data to the transport once the stream is
     * writable again.
     * <p>
     * Runs on the poll thread, after the engine tick and SSL_poll. A wrapper
     * whose write lock is held by an application thread is skipped until that
     * write finishes; a stream already claimed by an executor dispatch is
     * left for the next iteration.
     *
     * @return {@code true} if a wrapper made progress (drained bytes or had a
     *         dispatch queued)
     */
    private boolean sweepWriteInterestedStreams() {
        if (writeInterestedWrappers.isEmpty()) {
            return false;
        }
        boolean progress = false;
        // writeInterestedWrappers is a concurrent set: its weakly consistent
        // iterator tolerates the clearWriteInterest() removals below, so the
        // per-sweep snapshot copy is unnecessary.
        for (QuicOpenSSLSocketWrapper wrapper : writeInterestedWrappers) {
            QuicStreamWrapper stream = wrapper.getSocket();
            if (stream == null || stream.isFreed() || stream.isDeregistered() ||
                    wrapper.isClosed()) {
                wrapper.clearWriteInterest();
                continue;
            }
            QuicConnectionWrapper conn = stream.getConnection();
            if (conn == null || conn.isClosing() || conn.isClosed() ||
                    conn.isFreed()) {
                wrapper.clearWriteInterest();
                continue;
            }
            // An application write owns the staging buffers right now: let it
            // finish rather than dispatching a second writer into the handler.
            // If the latch was cleared while the wrapper was still in the
            // set, drop the stale entry now (the writer will re-register if
            // it still has data).
            if (wrapper.isWriteLocked()) {
                if (!wrapper.hasWriteInterest()) {
                    wrapper.clearWriteInterestIfUnlatched();
                }
                continue;
            }
            boolean stagedData = wrapper.hasDataToWrite();
            boolean flushProgress;
            try {
                flushProgress = wrapper.flushNonBlockingWithProgress();
            } catch (IOException ioe) {
                log.debug(sm.getString("quicEndpoint.writeEventDispatchError"), ioe);
                try {
                    failConnection(conn, getDefaultStreamErrorCode(),
                            "Write-interest sweep flush failed on stream " +
                                    stream.getStreamId());
                } catch (Throwable t) {
                    log.warn(sm.getString("quicEndpoint.connectionTeardownError"), t);
                }
                wrapper.clearWriteInterest();
                continue;
            }
            if (stagedData && !flushProgress) {
                // Staged bytes remain, but the native send side accepted none
                // of them: the stream is flow-control/send-buffer stalled.
                // Re-dispatching OPEN_WRITE would only re-run the same failed
                // flush, and counting it as progress defeats the poll loop's
                // no-progress backoff. Leave the interest armed for the next
                // W event or sweep pass; a later pass that accepts bytes
                // counts as progress and dispatches the handler.
                continue;
            }
            if (flushProgress) {
                progress = true;
            }
            if (!wrapper.hasWriteInterest()) {
                // The flush drained the buffers (or the interest was cleared
                // by a concurrent close). Remove the stale sweep entry; a
                // later registration re-adds it. If a registration raced the
                // stale observation, the conditional clear leaves it intact
                // and the wrapper is processed again below.
                if (wrapper.clearWriteInterestIfUnlatched()) {
                    progress = true;
                    continue;
                }
            }
            if (stream.compareAndSetProcessing(false, true)) {
                wrapper.clearWriteInterest();
                dispatchToExecutor(wrapper, stream, SocketEvent.OPEN_WRITE, true);
                progress = true;
            }
        }
        return progress;
    }


    /**
     * Removes a stream's poll item from the persistent stream poll subset.
     * Called from every path that removes a stream from the poll set,
     * including connection teardown.
     *
     * @param stream The stream being untracked
     */
    void untrackStreamPollItem(QuicStreamWrapper stream) {
        QuicPollItem item = stream.getPollItem();
        if (item != null) {
            streamPollItems.remove(item);
            lingeringStreamItems.remove(item);
            item.setPollLinger(0);
        }
    }


    /**
     * Adds the registered stream items belonging to a ready connection to the
     * current poll subset. A stream is only added when its poll item is still
     * registered in the set; un-promoted streams (for example streams waiting
     * for the server control stream) are not polled yet.
     *
     * @param conn The ready connection
     */
    private void addConnectionStreamPollItems(QuicConnectionWrapper conn) {
        for (QuicStreamWrapper stream : conn.getStreams().values()) {
            QuicPollItem item = stream.getPollItem();
            if (item != null && streamPollItems.contains(item)
                    && pollSet.get(item.getSsl().address()) == item) {
                pollSet.addPollItem(item);
                lingerStreamPollItem(item);
            }
        }
    }


    /**
     * Marks a stream item for a bounded number of follow-up poll passes.
     *
     * @param item The stream poll item
     */
    private void lingerStreamPollItem(QuicPollItem item) {
        if (item == null || !streamPollItems.contains(item)) {
            return;
        }
        if (item.getPollLinger() < STREAM_POLL_LINGER_PASSES) {
            item.setPollLinger(STREAM_POLL_LINGER_PASSES);
        }
        lingeringStreamItems.add(item);
    }


    /**
     * Adds the poll items of all bidirectional request streams which have a
     * socket wrapper. These streams can carry application read/write interest
     * independent of new network activity on the parent connection, so they
     * remain polled for their registered lifetime. Idle connections have no
     * such wrappers, keeping the idle fleet subset small.
     */
    private void addSocketWrapperStreamPollItems() {
        for (QuicOpenSSLSocketWrapper wrapper : streamWrappers.values()) {
            QuicStreamWrapper stream = wrapper.getSocket();
            if (stream == null) {
                continue;
            }
            QuicPollItem item = stream.getPollItem();
            if (item != null && streamPollItems.contains(item)
                    && pollSet.get(item.getSsl().address()) == item) {
                pollSet.addPollItem(item);
            }
        }
    }


    /**
     * Adds stream items which are in their bounded linger window after a
     * registration or a ready-connection touch.
     */
    private void addLingeringStreamPollItems() {
        for (QuicPollItem item : lingeringStreamItems) {
            if (item.getPollLinger() > 0 && streamPollItems.contains(item)
                    && pollSet.get(item.getSsl().address()) == item) {
                pollSet.addPollItem(item);
            }
        }
    }


    /**
     * Drains ready accepted connections from OpenSSL and adds their connection
     * and stream poll items to the current poll subset. This is the work-gated
     * replacement for including every established connection and all of its
     * streams in every {@code SSL_poll()} call.
     *
     * @param readyChannels Native array receiving the connection SSL pointers
     * @param capacity      The array capacity
     */
    private void addReadyConnectionPollItems(MemorySegment readyChannels,
            int capacity) {
        long addressSize = ValueLayout.ADDRESS.byteSize();
        int loops = 0;
        long n;

        do {
            n = QuicBindings.SSL_get_quic_ready_channels(listener,
                    readyChannels, capacity);
            for (int i = 0; i < n; i++) {
                MemorySegment ssl = readyChannels.get(ValueLayout.ADDRESS,
                        i * addressSize);
                if (ssl.equals(MemorySegment.NULL)) {
                    continue;
                }
                QuicConnectionWrapper conn = connections.get(ssl.address());
                if (conn == null || conn.isClosed() || conn.isFreed()) {
                    continue;
                }
                QuicPollItem item = conn.getPollItem();
                if (item != null &&
                        pollSet.get(item.getSsl().address()) == item) {
                    pollSet.addPollItem(item);
                    addConnectionStreamPollItems(conn);
                }
            }
        } while (n == capacity && ++loops < READY_CHANNEL_DRAIN_LOOPS);
    }


    /**
     * Ages the linger window of stream items polled in this iteration. An
     * item which produced a read/error event resets the window; otherwise it
     * decrements, and an item reaching zero leaves the linger set. Write-only
     * W events do not reset the window because they are level-triggered on
     * quiescent write streams.
     */
    private void ageLingeringStreamPollItems() {
        for (int i = 0; i < pollSet.getPollCount(); i++) {
            QuicPollItem item = pollSet.pollItemAt(i);
            if (!streamPollItems.contains(item)) {
                lingeringStreamItems.remove(item);
                item.setPollLinger(0);
                continue;
            }
            int linger = item.getPollLinger();
            if (linger <= 0) {
                continue;
            }
            if ((item.getRevents() & STREAM_LINGER_EVENTS) != 0) {
                linger = STREAM_POLL_LINGER_PASSES;
            } else {
                linger--;
            }
            if (linger <= 0) {
                lingeringStreamItems.remove(item);
                item.setPollLinger(0);
            } else {
                item.setPollLinger(linger);
                lingeringStreamItems.add(item);
            }
        }
    }


    /**
     * Builds the compact poll subset for the current iteration.
     * <p>
     * With the ready-channel API the subset is the listener plus only the
     * connections OpenSSL reports as ready (and their registered streams).
     * With the compatibility path (older OpenSSL) every member of the poll
     * set is included, preserving the previous behaviour.
     *
     * @param readyChannels Native scratch array for ready connection pointers
     * @param readyCapacity The scratch array capacity
     */
    private void buildPollSubset(MemorySegment readyChannels, int readyCapacity) {
        pollSet.beginPoll();
        if (READY_CHANNELS_AVAILABLE) {
            addSocketWrapperStreamPollItems();
            addLingeringStreamPollItems();
            addReadyConnectionPollItems(readyChannels, readyCapacity);
        } else {
            // Add every member except the listener, then append the listener
            // last. SSL_poll() zeroes the revents of every item after the first
            // failing item, so a failing listener must not precede connections.
            for (int i = 0; i < pollSet.size(); i++) {
                QuicPollItem item = pollSet.itemAt(i);
                if (item != listenerPollItem) {
                    pollSet.addPollItem(item);
                }
            }
        }
        // The listener is deliberately the last poll item: a listener
        // SSL_POLL_EVENT_F (FAIL_FROM in OpenSSL's poll implementation) then
        // cannot clear the events of the connection and stream items.
        pollSet.addPollItem(listenerPollItem);
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
            log.debug("QUIC poll loop starting, socket=" +
                    PLATFORM.describe(socketHandle));
        }

        // Scratch for the SSL_get_event_timeout() read (struct timeval + int),
        // confined to this thread for the duration of the loop. The timeval
        // layout and the field offsets used to read it come from the single
        // definition in QuicPoll, so the two ABI assumptions (LP64
        // time_t/suseconds_t) can never drift apart.
        try (Arena timerArena = Arena.ofConfined()) {
            MemorySegment timerTv = timerArena.allocate(ABI.timeval());
            MemorySegment timerInf = timerArena.allocate(ValueLayout.JAVA_INT);
            MemorySegment readyChannels = timerArena.allocate(
                    ValueLayout.ADDRESS, READY_CHANNEL_BATCH);
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
                    // One-shot reasons that require an immediate engine tick
                    // and SSL_poll() pass even when the engine deadline says
                    // nothing is due: a poll-set membership/order change (a
                    // slot added by a handler after the previous poll can
                    // already be readable), an interest-mask change made by a
                    // poll-thread handler, and a worker's transition of
                    // protocol data from absent to pending.
                    boolean pollSetChanged = pollSet.consumeChanged();
                    boolean pollInterestWake = pollInterestWakePending.getAndSet(false);
                    boolean protocolDataWake = protocolDataWakePending.getAndSet(false);
                    long waitMs;
                    if (pollSetChanged || pollInterestWake || protocolDataWake) {
                        waitMs = 0;
                    } else if (mailbox.hasPollTasks()) {
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
                            pollSetChanged || pollInterestWake || protocolDataWake ||
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
                        // of burning the interval on deadline-due wakes. If the
                        // wait reports a packet or a kick (or fails), that is a
                        // real reactive wake: reset the floor so the next
                        // iteration handles it at full speed rather than
                        // discarding the wake for a floor interval.
                        long remain = nextDueTickFreeAtMs - nowMs;
                        int holdEvents = quicWakeup.await(remain);
                        quicWakeup.consumeWake();
                        if (holdEvents != 0) {
                            dueTickFloorMs = 0;
                            nextDueTickFreeAtMs = 0;
                        }
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
                    if (!handleEvents(listener, "poll-loop tick")) {
                        // The engine failed to advance; the cached deadline
                        // and timers are stale. Back off briefly so the
                        // level-triggered condition cannot spin the loop.
                        Thread.sleep(1);
                        continue;
                    }
                    quicDeadlineAbsMs = listenerQuicDeadlineMs(timerTv, timerInf);
                    haveQuicDeadline = true;
                    if (deadlineDue && !reactiveWake && dueTickFloorCapMs > 0) {
                        dueTickFloorMs = (dueTickFloorMs == 0)
                                ? Math.min(DUE_TICK_FLOOR_BASE_MS,
                                        dueTickFloorCapMs)
                                : Math.min(dueTickFloorMs * 2, dueTickFloorCapMs);
                        nextDueTickFreeAtMs = nowMs + dueTickFloorMs;
                    }

                    buildPollSubset(readyChannels, READY_CHANNEL_BATCH);
                    pollSet.writePollItems();
                    pollSet.resetResultCount();

                      // SSL_poll() in non-blocking mode (timeout zero), with
                      // SSL_POLL_FLAG_NO_HANDLE_EVENTS: readiness of the current
                      // poll subset is tested and reported against the state the
                      // tick above just produced, without OpenSSL ticking the
                      // engine again per item. With the ready-channel API the
                      // subset is O(work) instead of the whole idle fleet.
                    int sslPollResult = QuicPoll.poll(
                                pollSet.getNativeArray(),
                                pollSet.getPollCount(),
                                0,
                                QuicPoll.SSL_POLL_FLAG_NO_HANDLE_EVENTS,
                                pollSet.getResultCountSegment()
                        );

                       // The tick above has flushed any pending packets (including
                       // RESET_STREAM frames) to the network, so it is now safe to
                       // free the stream SSL objects deferred by the close paths.
                       // Streams waiting for their native write buffer to drain are
                       // re-checked here; only the drained ones move to the free
                       // queue.
                    mailbox.drainPendingStreamDrains(null, false);
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
                        // SSL_poll() leaves its usage-error diagnostics on the
                        // OpenSSL error queue. Clear it on every occurrence,
                        // including while the warning is rate-limited, so a
                        // persistent failure cannot overwrite the root cause in
                        // the fixed-size per-thread ERR ring.
                        QuicDiagnostics.clearErrorQueue();
                        Thread.sleep(1);
                        continue;
                    }

                    boolean processedAnything = false;
                      // A zero result count means SSL_poll found nothing on any
                      // item - an item it failed to poll reports F and is counted
                      // (FAIL_ITEM increments the result count), so nothing is
                      // pending and every revents is zero. The revents sync and
                      // the item scan are both O(poll subset); skipping them here
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
                        pollSet.syncPollRevents();
                        // The OpenSSL error queue is per thread and handled
                        // non-fatal failures elsewhere in this endpoint clear
                        // their own entries. Drain any residual entries before
                        // the item scan so the accept calls below see only
                        // errors raised during this iteration - except when an
                        // item reported SSL_POLL_EVENT_F: SSL_poll() leaves the
                        // cause of that failure on the ERR stack, and
                        // handlePollFailure() must be able to dump it.
                        boolean hasPollFailure = false;
                        for (int slot = 0; slot < pollSet.getPollCount(); slot++) {
                            if (pollSet.pollItemAt(slot).hasPollFailure()) {
                                hasPollFailure = true;
                                break;
                            }
                        }
                        if (!hasPollFailure) {
                            QuicDiagnostics.clearErrorQueue();
                        }

                        // Process items with events. Follow OpenSSL reference
                        // priority: ERROR -> IN -> OUT.
                        for (int slot = 0; slot < pollSet.getPollCount(); slot++) {
                            QuicPollItem item = pollSet.pollItemAt(slot);
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

                    ageLingeringStreamPollItems();

                    // Re-drive latched write interest level-wise: OpenSSL's
                    // W event is not reported while the native send buffer is
                    // full even if flow-control credit has reopened.
                    processedAnything |= sweepWriteInterestedStreams();

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
                    // Drain marks and prune the confined set on every poll
                    // iteration, not only while protocolDataConns is
                    // non-empty. A connection can transition back to "nothing
                    // pending" (for example in teardown) after it was marked
                    // but before this sweep; gating the cleanup on the marks
                    // would then leave the mark/set/retry entries retaining
                    // the wrapper (and its cached data) until stop/start.
                    QuicConnectionWrapper marked;
                    while ((marked = protocolDataMarks.poll()) != null) {
                        protocolDataConns.add(marked);
                    }
                    if (!protocolDataConns.isEmpty()) {
                        protocolDataRetry.clear();
                        for (QuicConnectionWrapper conn : protocolDataConns) {
                            if (conn.isClosed() || conn.isFreed()) {
                                // Balance a mark left by a worker that
                                // raced the teardown clear; the wrapper
                                // now rejects new marks on a closed/freed
                                // connection.
                                setConnectionProtocolDataPending(conn, false);
                                continue;
                            }
                            if (!conn.isProtocolDataPending()) {
                                // Do not clear a live connection's flag
                                // here: a worker may have set it after the
                                // read above. Leave the concurrent mark in
                                // the mark queue for the next sweep.
                                continue;
                            }
                            QuicConnectionManager connManager =
                                    conn.getQuicConnectionManager();
                            if (connManager == null) {
                                setConnectionProtocolDataPending(conn, false);
                                continue;
                            }
                            if (flushProtocolData(conn, connManager)) {
                                protocolDataFlushed = true;
                                if (conn.isProtocolDataPending()) {
                                    protocolDataRetry.add(conn);
                                }
                            }
                        }
                        protocolDataConns.clear();
                        protocolDataConns.addAll(protocolDataRetry);
                        protocolDataRetry.clear();
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
                        if (!handleEvents(listener, "flush tick")) {
                            // No deadline refresh is valid when the engine did
                            // not advance; back off before the next iteration.
                            Thread.sleep(1);
                            continue;
                        }
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

        } finally {
            // Release the thread-confined SSL_poll() timeval scratch; the
            // poll thread is the owner of this ThreadLocal arena for the
            // duration of the loop.
            QuicPoll.releaseThreadScratch();
        }

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
        if (QuicBindings.SSL_get_event_timeout(ssl, timerTv, timerInf) == 0) {
            // A failed query leaves a native error-queue entry; clear it so it
            // cannot be attributed to a later accept operation.
            QuicDiagnostics.clearErrorQueue();
            return current;
        }
        if (timerInf.get(ValueLayout.JAVA_INT, 0) != 0) {
            return current;
        }
        long secs = ABI.readTimevalSeconds(timerTv);
        long usecs = ABI.readTimevalMicroseconds(timerTv);
        long secsMs;
        if (secs > Long.MAX_VALUE / 1000) {
            secsMs = Long.MAX_VALUE;
        } else if (secs < Long.MIN_VALUE / 1000) {
            secsMs = Long.MIN_VALUE;
        } else {
            secsMs = secs * 1000;
        }
        // Saturate instead of letting a pathological timeval (or a future
        // OpenSSL returning a huge finite deadline) wrap the absolute
        // millisecond deadline into a nonsensical wait.
        long deadline = saturatedAdd(
                saturatedAdd(nowMs, secsMs), Math.max(0, usecs / 1000));
        return current == 0 || deadline < current ? deadline : current;
    }


    /**
     * Adds two millisecond values, saturating at the long range limits instead
     * of overflowing.
     *
     * @param a The first value
     * @param b The second value
     *
     * @return The sum, saturated to {@link Long#MIN_VALUE} or
     *         {@link Long#MAX_VALUE}
     */
    private static long saturatedAdd(long a, long b) {
        try {
            return Math.addExact(a, b);
        } catch (ArithmeticException e) {
            return a < 0 ? Long.MIN_VALUE : Long.MAX_VALUE;
        }
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
            log.trace("Event ssl=0x" + Long.toHexString(item.getSsl().address())
                     + " revents=0x" + Long.toHexString(revents) + " " + eventType);
        }

        boolean isListener = (item.getAppData() == null &&
                 item.getSsl().equals(listener));

        if (isListener &&
                 (revents & QuicPoll.SSL_POLL_EVENT_EL) == 0) {
            // The listener produced some non-EL event in this iteration
            // without an EL error: clear the escalation state so a later,
            // transient EL is reported at warn level again instead of
            // permanently as "persistent". An idle listener (zero revents)
            // never reaches this method, so a historical count can survive
            // until the next non-EL listener event.
            listenerErrorCount = 0;
        }

        // Service the highest-priority bucket whose flags are set, following
        // the OpenSSL reference ERROR -> IN -> OUT order: within a bucket
        // exactly one handler runs and the buckets are mutually exclusive per
        // item. The pure priority decision lives in QuicEventDispatcher.classify()
        // without native calls; the handlers themselves stay in the endpoint.
        // A poll-failure (F) was evicted by the caller and never reaches the
        // classifier.
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
                        failConnectionAfterPollHandlerError(item, ex);
                    }
                    break;
                case STREAM_ERROR:
                    try {
                        handleErrorEvent(item);
                    } catch (Exception ex) {
                        log.warn(sm.getString(
                                "quicEndpoint.streamErrorEventError"), ex);
                        failConnectionAfterPollHandlerError(item, ex);
                    }
                    break;
                case ERROR_OTHER:
                    // Error bucket with no specific handler (for example a non-listener
                    // EL with no EC/ECD/ER/EW): nothing to run, but the bucket was hit.
                    break;
                case INCOMING_CONNECTION:
                    try {
                        handleIncomingConnection();
                    } catch (Exception ex) {
                        // A persistent setup failure (for example an
                        // SSL_ctrl write-mode error) would otherwise log a
                        // full stack trace for every incoming connection.
                        long now = System.currentTimeMillis();
                        if (now - lastIncomingConnectionErrorLogMs >=
                                SECURITY_WARNING_LOG_INTERVAL_MS) {
                            lastIncomingConnectionErrorLogMs = now;
                            log.warn(sm.getString(
                                    "quicEndpoint.incomingConnectionError"), ex);
                        } else if (log.isDebugEnabled()) {
                            log.debug(sm.getString(
                                    "quicEndpoint.incomingConnectionError"), ex);
                        }
                    }
                    break;
                case INCOMING_STREAM:
                    try {
                        handleIncomingStream(item);
                    } catch (IOException ioe) {
                        log.debug(sm.getString(
                                "quicEndpoint.incomingStreamError"), ioe);
                        failConnectionAfterStreamIoError(item, ioe);
                    } catch (Exception ex) {
                        log.debug(sm.getString(
                                "quicEndpoint.incomingStreamError"), ex);
                        failConnectionAfterPollHandlerError(item, ex);
                    }
                    break;
                case READABLE:
                    try {
                        dispatchStreamEvent(item, SocketEvent.OPEN_READ);
                    } catch (IOException ioe) {
                        log.debug(sm.getString(
                                "quicEndpoint.readEventDispatchError"), ioe);
                        failConnectionAfterStreamIoError(item, ioe);
                    } catch (Exception ex) {
                        log.debug(sm.getString(
                                "quicEndpoint.readEventDispatchError"), ex);
                        failConnectionAfterPollHandlerError(item, ex);
                    }
                    break;
                case OUTGOING_STREAM:
                    try {
                        handleOutgoingStream(item);
                    } catch (Exception ex) {
                        log.warn(sm.getString(
                                "quicEndpoint.outgoingStreamError"), ex);
                        failConnectionAfterPollHandlerError(item, ex);
                    }
                    break;
                case WRITABLE:
                    try {
                        dispatchStreamEvent(item, SocketEvent.OPEN_WRITE);
                    } catch (Exception ex) {
                        log.debug(sm.getString(
                                "quicEndpoint.writeEventDispatchError"), ex);
                        failConnectionAfterPollHandlerError(item, ex);
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


    /**
     * Fails the connection behind a poll item after a hard stream read/hand-off
     * IOException. A hard stream I/O failure is not recoverable for the stream;
     * leaving the connection running with a half-registered stream would strand
     * the request. The item may already have been deregistered by the cleanup
     * path, so only Java references are used here.
     *
     * @param item The poll item whose handler raised the error
     * @param ioe  The hard I/O error
     */
    private void failConnectionAfterStreamIoError(QuicPollItem item, IOException ioe) {
        failConnectionAfterPollItemError(item, "Stream I/O failure: " + ioe);
    }


    /**
     * Fails the connection behind a poll item after an unexpected exception
     * escaped one of the poll-loop handlers. A handler failure leaves the
     * level-triggered event armed, so without evicting/failing the item the
     * loop would re-enter the failing handler at poll rate while counting the
     * event as progress.
     *
     * @param item The poll item whose handler failed
     * @param t    The handler failure
     */
    private void failConnectionAfterPollHandlerError(QuicPollItem item, Throwable t) {
        failConnectionAfterPollItemError(item, "Poll handler failure: " + t);
    }


    /**
     * Common failure path for a poll item whose stream I/O or handler failed:
     * fail the owning connection (if any), then evict the level-triggered item
     * so it cannot starve the rest of the poll set if teardown did not remove
     * it. A null appData identifies the listener item and must never be
     * removed.
     *
     * @param item   The poll item
     * @param reason Failure description used as the connection failure reason
     */
    private void failConnectionAfterPollItemError(QuicPollItem item, String reason) {
        Object data = item.getAppData();
        QuicConnectionWrapper conn = null;
        if (data instanceof QuicStreamWrapper stream) {
            conn = stream.getConnection();
        } else if (data instanceof QuicConnectionWrapper connection) {
            conn = connection;
        }
        if (conn != null && !conn.isFreed()) {
            try {
                // Do not use the public failConnection() guard here. It
                // returns for a connection that is already closing (or was
                // provisionally marked closed by a timed-out worker hop), and
                // the caller would then evict the poll item without tearing
                // the connection down: the wrapper would stay in
                // connections/pollSet, unpolled, with its native SSL still
                // allocated until stop. failConnectionNow() completes the
                // teardown, wakes the terminal handlers and removes the
                // connection's poll item in both states.
                failConnectionNow(conn, getDefaultStreamErrorCode(), reason);
            } catch (Throwable teardownError) {
                log.warn(sm.getString("quicEndpoint.connectionTeardownError"),
                        teardownError);
            }
        }
        if (data != null && (conn == null || conn.isFreed())) {
            // Only evict the item once the owning connection was torn down
            // (or when there is no live connection behind it). If teardown
            // failed while native state is still retained, removing the item
            // would leave that state unpolled and unrecoverable.
            forceRemovePollItem(item);
        }
    }


    /**
     * Removes a poll item that a failed event handler could not evict through
     * its normal close/teardown path. The item may already have been removed
     * (in which case dispose() is a no-op), or may no longer be the item
     * registered for its SSL address (a stale item from an earlier iteration).
     *
     * @param item The item to evict
     */
    private void forceRemovePollItem(QuicPollItem item) {
        if (item == null || pollSet == null) {
            return;
        }
        if (item.getAppData() instanceof QuicStreamWrapper stream) {
            untrackStreamPollItem(stream);
        }
        long address = item.getSsl().address();
        if (pollSet.get(address) == item) {
            pollSet.remove(address);
        } else {
            item.dispose();
        }
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
     * Dumps and clears the OpenSSL error queue for diagnosis and evicts the
     * item so it cannot starve the rest of the poll set on every iteration.
     * The warning and the error-queue dump are rate-limited: a failing item
     * that cannot be evicted (the listener) re-raises F on every SSL_poll()
     * call while the failure persists, so logging every occurrence would flood
     * the log at the poll-loop rate. The first occurrence is reported
     * immediately, then at most once per interval with a cumulative occurrence
     * count; suppressed occurrences still clear the queue.
     *
     * @return {@code true} if the item was evicted (a stream was closed or a
     *         connection torn down), {@code false} if it was retained (a
     *         failing listener is kept: dropping it would break the whole
     *         endpoint). A {@code false} result must not be counted as poll
     *         loop progress, or the no-progress backoff is defeated and the
     *         loop spins at full CPU while the failure persists.
     */
    private boolean handlePollFailure(QuicPollItem item) {
        if (log.isTraceEnabled()) {
            log.trace("Poll failure ssl=0x" +
                    Long.toHexString(item.getSsl().address()) +
                    " revents=0x" + Long.toHexString(item.getRevents()));
        }
        long count = ++pollFailureCount;
        long now = System.currentTimeMillis();
        if (now - lastPollFailureLog >= POLL_FAILURE_LOG_INTERVAL_MS) {
            lastPollFailureLog = now;
            String errors = QuicDiagnostics.dumpErrorQueue();
            log.warn(sm.getString("quicEndpoint.pollItemFailure",
                    Long.toHexString(item.getSsl().address()),
                    Long.toHexString(item.getRevents()),
                    Long.valueOf(count), errors));
        } else {
            // Keep the OpenSSL error queue drained even while the warning is
            // rate-limited so repeated failures do not overwrite the root
            // cause in the fixed-size per-thread ERR ring before the next dump.
            QuicDiagnostics.clearErrorQueue();
        }
        Object appData = item.getAppData();
        if (appData instanceof QuicStreamWrapper stream) {
            if (stream.getStreamType() == QuicPoll.SSL_STREAM_TYPE_READ) {
                // A poll failure loses the stream. If it is a critical
                // client-initiated unidirectional stream (HTTP/3 control or
                // QPACK), this is a connection error (H3_CLOSED_CRITICAL_STREAM
                // or the truncated-frame code), not a clean stream close.
                QuicConnectionWrapper pollConn = stream.getConnection();
                if (pollConn != null) {
                    checkClientUniStreamClosed(stream, pollConn, true);
                    if (!isStreamLive(stream)) {
                        // The protocol callback failed the connection inline
                        // and the teardown already claimed the stream.
                        return true;
                    }
                }
            }
            if (stream.getStreamType() == QuicPoll.SSL_STREAM_TYPE_WRITE) {
                // Mirror the write-stream error path: a server-initiated
                // unidirectional stream lost to a poll failure must reach the
                // protocol before its SSL is freed. For HTTP/3 this fails the
                // connection for a critical control/QPACK stream and drops
                // the protocol's stale stream handle.
                try {
                    notifyServerUniStreamClosed(stream);
                } catch (Throwable t) {
                    log.warn(sm.getString("quicEndpoint.streamErrorEventError"), t);
                }
                if (!isStreamLive(stream)) {
                    // The protocol callback failed the connection inline and
                    // the teardown already claimed the stream.
                    return true;
                }
            }
            try {
                setStreamErrorIfAbsent(stream, "quicEndpoint.streamPollFailure");
                closeStream(stream, false);
            } catch (Throwable t) {
                log.warn(sm.getString("quicEndpoint.streamCloseAfterPollFailure"), t);
                // The normal close path failed before deregistering. Remove
                // the failing item from the poll set and queue the stream for
                // deferred release so the F flag cannot re-fire forever.
                try {
                    deregisterStream(stream);
                    mailbox.queueStreamDrain(stream);
                } catch (Throwable cleanupError) {
                    log.warn(sm.getString("quicEndpoint.streamSslFreeError",
                            Long.toHexString(stream.getSslAddress())),
                            cleanupError);
                }
                forceRemovePollItem(item);
            }
            return true;
        } else if (appData instanceof QuicConnectionWrapper conn) {
            try {
                wakeAndScheduleTerminalStreamEvents(conn);
                teardownConnection(conn, null);
            } catch (Throwable t) {
                log.warn(sm.getString("quicEndpoint.connectionTeardownAfterPollFailure"), t);
                // Teardown failed before removing the item. Drop the failing
                // item so its F flag does not starve the rest of the poll set;
                // the connection is left for the stop/retention cleanup paths.
                forceRemovePollItem(item);
            }
            return true;
        }
        // A failing listener item is kept: dropping the listener would break the
        // whole endpoint. buildPollSubset() appends the listener after every
        // connection/stream item, so the failure flag (which zeroes the revents
        // of all later items) cannot starve existing connections. It is not
        // counted as progress, so the 1ms backoff in pollLoop() engages and
        // prevents a CPU spin.
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
            QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(sw);
            if (wrapper != null) {
                streamWrappers.remove(sw.getSslAddress(), wrapper);
            }
        }
        for (QuicStreamWrapper sw : conn.getPendingStreams()) {
            QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(sw);
            if (wrapper != null) {
                streamWrappers.remove(sw.getSslAddress(), wrapper);
            }
        }
    }


    /**
     * Returns the endpoint's socket wrapper for a stream only when the map
     * entry still belongs to that stream. The wrapper map is keyed by the raw
     * native {@code SSL *} address, and OpenSSL may reuse an address after a
     * stream SSL has been freed. A stale entry found by address must never be
     * treated as the caller's wrapper: removing it, clearing its write
     * interest or signalling its waiters would detach an unrelated live
     * stream (or connection) from the endpoint. Identity is checked through
     * the wrapper's socket, which is fixed for the wrapper's lifetime.
     *
     * @param stream The stream whose wrapper is wanted (may be {@code null})
     *
     * @return The wrapper owned by the stream, or {@code null}
     */
    private QuicOpenSSLSocketWrapper getOwnedStreamWrapper(QuicStreamWrapper stream) {
        if (stream == null) {
            return null;
        }
        QuicOpenSSLSocketWrapper wrapper =
                streamWrappers.get(stream.getSslAddress());
        if (wrapper != null && wrapper.getSocket() == stream) {
            return wrapper;
        }
        return null;
    }


    /**
     * Wakes blocked read/write waiters and schedules terminal events for the
     * BIDI stream wrappers of a connection that is being torn down. The ECD
     * path does the same after it has freed the streams; this helper is used
     * by the failConnection/poll-failure/abort paths so those teardowns do
     * not leave a parked handler or non-blocking Read Listener waiting for an
     * event that can never arrive.
     * <p>
     * Must run before removeStreamWrappers()/closeAllStreams(), while the
     * wrappers and the stream SSLs are still available. The scheduled events
     * take the normal processing claim and active-handler reference; if a
     * handler is already running the claim is retried by the existing
     * scheduleStreamDispatch() machinery.
     *
     * @param conn The connection being torn down
     */
    private void wakeAndScheduleTerminalStreamEvents(QuicConnectionWrapper conn) {
        for (QuicStreamWrapper sw : conn.getStreams().values()) {
            QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(sw);
            if (wrapper == null) {
                continue;
            }
            wrapper.signalReadWaiter();
            wrapper.signalWriteWaiter();
            if (sw.getStreamType() == QuicPoll.SSL_STREAM_TYPE_BIDI &&
                    !wrapper.isClosed()) {
                scheduleStreamDispatch(wrapper, sw, SocketEvent.OPEN_READ, true);
                scheduleStreamDispatch(wrapper, sw, SocketEvent.ERROR, true);
            }
        }
        for (QuicStreamWrapper sw : conn.getPendingStreams()) {
            QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(sw);
            if (wrapper != null) {
                wrapper.signalReadWaiter();
                wrapper.signalWriteWaiter();
            }
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
        // A connection that is already closed or freed (for example after a
        // peer close, a previous protocol error, or a race with another
        // worker's failConnection hop) must not be touched again. Without
        // this guard SSL_shutdown_ex/SSL_handle_events below would run on a
        // freed SSL pointer. A connection already closing is left to its
        // normal drain/ECD path, as in the quiche/ngtcp2 implementations.
        if (conn == null || conn.isClosed() || conn.isFreed() || conn.isClosing()) {
            return;
        }
        failConnectionNow(conn, protocolErrorCode, reason);
    }


    /**
     * Schedules the teardown of a connection whose worker-to-poll-thread
     * {@code failConnection()} hop failed. The wrapper has already marked the
     * connection closed as a provisional safety flag; without this retry the
     * timed-out hop eventually runs into the public {@code isClosed()} guard
     * and the native SSL stays in the endpoint maps/poll set until a stop.
     * The retry runs on the poll thread and ignores that provisional flag.
     * A mailbox that is already closed cannot run it; the stop cleanup then
     * owns the connection.
     *
     * @param conn             The connection to tear down
     * @param protocolErrorCode The application protocol error code
     * @param reason           The failure description
     */
    void scheduleHopFailureTeardown(QuicConnectionWrapper conn,
            long protocolErrorCode, String reason) {
        submitPollTask(() -> {
            if (conn == null || conn.isFreed()) {
                return;
            }
            failConnectionNow(conn, protocolErrorCode, reason);
        });
    }


    /**
     * Performs the terminal connection failure once the caller has established
     * that the connection is not already closing/closed/freed, or when a
     * failed hop retry deliberately overrides the provisional closed flag.
     */
    private void failConnectionNow(QuicConnectionWrapper conn,
            long protocolErrorCode, String reason) {
        if (conn == null || conn.isFreed()) {
            return;
        }
        if (conn.isClosing()) {
            // The connection close is already in progress; complete the
            // teardown rather than leaving it to an ECD event that may never
            // be delivered after the failed hop. The normal open path below
            // runs both steps; this branch must do the same or blocked stream
            // waiters and asynchronous ReadListeners are left without a
            // terminal wake/error event. A close frame queued before the
            // closing transition is flushed by the teardown callback while
            // the connection SSL is still alive.
            try {
                wakeAndScheduleTerminalStreamEvents(conn);
            } catch (Throwable t) {
                logTeardownError(conn, t);
            }
            try {
                teardownConnection(conn, () -> flushConnectionClose(conn));
            } catch (Throwable t) {
                log.warn(sm.getString("quicEndpoint.connectionTeardownError"), t);
            }
            return;
        }
        if (log.isDebugEnabled()) {
            log.debug(reason + " conn=0x" + Long.toHexString(conn.getSsl().address())
                    + " protocolErrorCode=0x" + Long.toHexString(protocolErrorCode));
        }
        try {
            // A zero code means "no application error code", not "no close
            // frame": SSL_shutdown_ex() accepts zero and the peer must still
            // learn that the connection is terminating.
            sendConnectionCloseWithError(conn, protocolErrorCode);
        } catch (Throwable t) {
            // Sending the close frame is best effort; teardown must still run.
            logTeardownError(conn, t);
        }
        try {
            wakeAndScheduleTerminalStreamEvents(conn);
        } catch (Throwable t) {
            logTeardownError(conn, t);
        }
        try {
            teardownConnection(conn, () -> {
                // Transmit the queued CONNECTION_CLOSE before the connection
                // SSL is freed.
                flushConnectionClose(conn);
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
        conn.setConnectionCloseErrorCode(protocolErrorCode);
        sendConnectionCloseFrame(conn.getSsl(), protocolErrorCode);
        // Deliberately no per-connection engine tick here: a tick walks the
        // whole shared engine, so ticking once per connection made a
        // shutdown/failure storm O(fleet²). Callers drive transmission with a
        // batch tick: queueConnectionClosesForShutdown() is followed by
        // flushQueuedConnectionCloses() (one engine tick for the batch), and
        // failConnectionNow() tears down through flushConnectionClose() while
        // the connection SSL is still alive.
    }


    /**
     * Queues a QUIC {@code CONNECTION_CLOSE} frame carrying
     * {@code errorCode} in the application error code field via
     * {@code SSL_shutdown_ex} with the RAPID and NO_BLOCK flags (RFC 9114
     * Section 8; the reason string is left empty). With live streams whose
     * send buffers are not yet acknowledged, OpenSSL returns 0 from the
     * stream-flush phase and does not queue the close yet. Callers that are
     * about to free the streams must therefore complete the shutdown with
     * {@link #completeConnectionShutdown(MemorySegment, long)} after the
     * streams are gone. Must be called on the QUIC poll thread while the SSL is
     * still alive.
     *
     * @param ssl       The connection {@code SSL*} to shut down
     * @param errorCode The application protocol error code to carry
     */
    private void sendConnectionCloseFrame(MemorySegment ssl, long errorCode) {
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment args = shutdownExArgs(localArena, errorCode);
            long flags = QuicBindings.SSL_SHUTDOWN_FLAG_RAPID
                    | QuicBindings.SSL_SHUTDOWN_FLAG_NO_BLOCK;
            int rc = QuicBindings.SSL_shutdown_ex(ssl, flags, args, 16L);
            if (rc != 1) {
                if (log.isDebugEnabled()) {
                    log.debug("SSL_shutdown_ex returned " + rc
                            + " (zero means the shutdown is still in progress,"
                            + " for example waiting for stream data to drain)");
                }
                QuicDiagnostics.clearErrorQueue();
            }
        }
    }


    /**
     * Builds the 16-byte {@code SSL_SHUTDOWN_EX_ARGS} struct ({@code uint64_t
     * quic_error_code; const char *quic_reason}) in the caller's arena. Shared
     * by the initial shutdown call and the completion call so the layout and
     * the empty reason pointer cannot drift.
     *
     * @param arena     The arena owning the struct
     * @param errorCode The QUIC application error code
     *
     * @return The initialised argument struct
     */
    private static MemorySegment shutdownExArgs(Arena arena, long errorCode) {
        MemorySegment args = arena.allocate(16);
        args.set(ValueLayout.JAVA_LONG, 0, errorCode);
        args.set(ValueLayout.ADDRESS, 8, MemorySegment.NULL);
        return args;
    }


    /**
     * Completes a shutdown started by {@link #sendConnectionCloseFrame()} once
     * the connection's stream SSL objects are gone. The first
     * {@code SSL_shutdown_ex()} call may have returned 0 without queueing a
     * {@code CONNECTION_CLOSE} because its stream-flush phase was still in
     * progress. The no-stream-flush flag now skips that phase and lets
     * OpenSSL enter local close and queue the frame. Arguments supplied to the
     * first call are ignored on subsequent calls. Must be called on the QUIC
     * poll thread while the connection SSL is still alive.
     *
     * @param ssl       The connection {@code SSL*} whose shutdown to complete
     * @param errorCode The application error code supplied to the first call
     */
    private void completeConnectionShutdown(MemorySegment ssl, long errorCode) {
        if (ssl == null || ssl.equals(MemorySegment.NULL)) {
            return;
        }
        try (Arena localArena = Arena.ofConfined()) {
            // OpenSSL's local-close path uses the arguments supplied to the
            // call that actually completes the shutdown, even though the
            // manual describes subsequent-call arguments as ignored. Repeat
            // the original error code so it is not replaced by zero.
            MemorySegment args = shutdownExArgs(localArena, errorCode);
            long flags = QuicBindings.SSL_SHUTDOWN_FLAG_RAPID
                    | QuicBindings.SSL_SHUTDOWN_FLAG_NO_BLOCK
                    | QuicBindings.SSL_SHUTDOWN_FLAG_NO_STREAM_FLUSH;
            int rc = QuicBindings.SSL_shutdown_ex(ssl, flags, args, 16L);
            if (rc < 0) {
                if (log.isDebugEnabled()) {
                    log.debug("SSL_shutdown_ex failed while completing connection close: " + rc);
                }
                QuicDiagnostics.clearErrorQueue();
            }
        }
    }


    /**
     * Drives the connection's state machine a bounded number of times to
     * transmit a {@code CONNECTION_CLOSE} queued by
     * {@link #sendConnectionCloseFrame}. Completes the shutdown first, since
     * the initial call may have left it in progress, then ticks the engine so
     * the queued frame reaches the socket. Must be called on the QUIC poll
     * thread while the connection SSL is still alive.
     *
     * @param conn The connection to drive
     */
    private void flushConnectionClose(QuicConnectionWrapper conn) {
        if (conn == null || conn.isFreed()) {
            return;
        }
        MemorySegment ssl = conn.getSsl();
        completeConnectionShutdown(ssl, conn.getConnectionCloseErrorCode());
        for (int flush = 0; flush < CONNECTION_CLOSE_FLUSH_ATTEMPTS; flush++) {
            handleEvents(ssl, "flush connection close");
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
     * The address is first captured at accept and refreshed before new
     * incoming streams are accepted, so a request that starts after QUIC
     * connection migration (RFC 9000 Section 9) reports the address it was
     * actually received from. An already-running request keeps the address
     * captured when its stream was accepted; that matches the per-request
     * address semantics HTTP has always had over TCP and prevents the remote
     * address from changing under an in-flight request.
     *
     * @param connSsl the connection SSL object
     * @param conn the connection wrapper to update
     *
     * @return {@code true} if the peer address was resolved and stored,
     *         {@code false} if the native address could not be read
     */
    private boolean populatePeerAddress(MemorySegment connSsl, QuicConnectionWrapper conn)
            throws java.net.UnknownHostException {
        MemorySegment bioAddr = QuicBindings.BIO_ADDR_new();
        if (bioAddr == null || bioAddr.equals(MemorySegment.NULL)) {
            if (log.isDebugEnabled()) {
                log.debug("BIO_ADDR_new failed; peer address unavailable: "
                        + QuicDiagnostics.dumpErrorQueue());
            } else {
                QuicDiagnostics.clearErrorQueue();
            }
            return false;
        }
        try {
            try (Arena arena = Arena.ofConfined()) {
                int rc = QuicBindings.SSL_get_peer_addr(connSsl, bioAddr);
                if (rc != 1) {
                    if (log.isDebugEnabled()) {
                        log.debug("SSL_get_peer_addr rc=" + rc + " errors="
                                + QuicDiagnostics.dumpErrorQueue());
                    } else {
                        // Handled failure must not leave a stale error-queue
                        // entry for a later accept check to misattribute.
                        QuicDiagnostics.clearErrorQueue();
                    }
                    return false;
                }
                int family = QuicBindings.BIO_ADDR_family(bioAddr);
                if (!PLATFORM.isIPv4Family(family) && !PLATFORM.isIPv6Family(family)) {
                    if (log.isDebugEnabled()) {
                        log.debug("SSL_get_peer_addr unsupported family=" + family);
                    }
                    QuicDiagnostics.clearErrorQueue();
                    return false;
                }
                // BIO_ADDR_rawport() returns the two network-order port bytes
                // in the host's 16-bit value. The platform implementation owns
                // the byte-order decode.
                int rawPort = QuicBindings.BIO_ADDR_rawport(bioAddr);
                int port = PLATFORM.decodePeerPort(rawPort);

                int addrLen = PLATFORM.isIPv4Family(family) ? 4 : 16;
                MemorySegment rawAddr = arena.allocate(addrLen);
                MemorySegment lenPtr = arena.allocate(ABI.sizeT());
                int addrRc = QuicBindings.BIO_ADDR_rawaddress(bioAddr, rawAddr, lenPtr);
                long copied = ABI.getSizeT(lenPtr, 0);
                if (addrRc != 1 || copied != addrLen) {
                    if (log.isDebugEnabled()) {
                        log.debug("BIO_ADDR_rawaddress rc=" + addrRc + " len=" + copied);
                    }
                    QuicDiagnostics.clearErrorQueue();
                    return false;
                }
                byte[] addr = rawAddr.toArray(ValueLayout.JAVA_BYTE);
                conn.setRemoteAddress(unmapIpv4Mapped(
                        new InetSocketAddress(InetAddress.getByAddress(addr), port)));
                return true;
            }
        } finally {
            QuicBindings.BIO_ADDR_free(bioAddr);
        }
    }


    /**
     * Refreshes a live connection's remote address from OpenSSL before new
     * streams are accepted. {@code SSL_get_peer_addr()} returns the channel's
     * current peer address, which follows a validated client migration
     * (RFC 9000 Section 9). Called on the poll thread only while the
     * connection's SSL is live; failures leave the previously captured
     * address in place, matching the pre-refresh behaviour.
     *
     * @param conn The connection to refresh
     */
    private void refreshPeerAddress(QuicConnectionWrapper conn) {
        if (conn == null || conn.isClosed() || conn.isFreed()) {
            return;
        }
        try {
            populatePeerAddress(conn.getSsl(), conn);
        } catch (java.net.UnknownHostException e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not refresh peer address for conn=0x"
                        + Long.toHexString(conn.getSslAddress()), e);
            }
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
     * Drains pending incoming connections on the listener (as bounded by
     * {@code maxPending}) by accepting each and immediately rejecting it with
     * a {@code CONNECTION_CLOSE}. Used at {@code maxConnections}, on pause and
     * in the drain path of a burst of incoming connections.
     * <p>
     * OpenSSL may surface a pending connection before its handshake has
     * completed; the batching still wins on what the rejection loop itself
     * costs: one close frame
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
                // NULL normally means nothing pending; with a non-empty error
                // queue it is a real failure and must not be mistaken for it.
                checkAcceptFailure("SSL_accept_connection");
                break;
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
            handleEvents(listener, "reject batch");
        }
        for (MemorySegment connSsl : rejected) {
            openssl_h.SSL_free(connSsl);
        }
    }


    private void handleIncomingConnection() throws Exception {
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
            rejectIncomingConnections(REJECT_BURST_LIMIT);
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
        if (maxConnections >= 0 &&
                connections.size() + stoppedBusyConnections.size() >= maxConnections) {
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

        // SSL_accept_connection() returns the pending connection; its
        // handshake may still be completing. The bootstrap defers the ALPN
        // decision until the handshake has progressed far enough.
        MemorySegment connSsl = QuicBindings.SSL_accept_connection(listener, 0L);
        if (connSsl.equals(MemorySegment.NULL)) {
            checkAcceptFailure("SSL_accept_connection");
            return;
        }

        // The accepted connection does not consistently inherit the
        // context's write modes in this OpenSSL build (the QUIC connection's
        // default stream mode reads back as zero here), so apply the stream
        // write modes explicitly to the connection. Stream SSL objects
        // created from it inherit them: without
        // SSL_MODE_ENABLE_PARTIAL_WRITE a would-blocked stream write stays
        // in an all-or-nothing retry state, and without
        // SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER the retry from a freshly
        // staged remainder buffer fails with SSL_R_BAD_WRITE_RETRY.
        long streamWriteModeRc = QuicBindings.SSL_ctrl(connSsl,
                QuicBindings.SSL_CTRL_MODE,
                QuicBindings.SSL_MODE_ENABLE_PARTIAL_WRITE |
                        QuicBindings.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,
                MemorySegment.NULL);
        long streamWriteModes = QuicBindings.SSL_MODE_ENABLE_PARTIAL_WRITE |
                QuicBindings.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
        if ((streamWriteModeRc & streamWriteModes) != streamWriteModes) {
            // Without these modes a stream write that would-blocks has to be
            // retried with the exact same buffer address, which the write
            // paths (staging into a fresh buffer per attempt) cannot honour.
            openssl_h.SSL_free(connSsl);
            throw new IOException(sm.getString("quicEndpoint.contextCreateError"));
        }

        QuicConnectionWrapper conn = null;
        QuicPollItem connItem = null;
        try {
            conn = new QuicConnectionWrapper(connSsl,
                    getCleanerConnectionFrees());
            connections.put(connSsl.address(), conn);
            // OpenSSL exposes no per-connection local-address accessor; report
            // the configured bind address (wildcard for the default bind).
            conn.setLocalAddress(bindAddress);
            // Resolve the peer (client) address so request.getRemoteAddr()/
            // getPeerAddr() report the real client address (e.g. for
            // RemoteCIDRValve). Must run while the connection SSL is live.
            if (!populatePeerAddress(connSsl, conn)) {
                throw new IOException(sm.getString(
                        "quicEndpoint.peerAddressError",
                        Long.toHexString(connSsl.address())));
            }

            configureConnectionTransport(connSsl);

            // Request all connection events except OSB: this endpoint does
            // not create server-initiated bidirectional streams, and a
            // level-triggered OSB would otherwise keep re-entering the
            // outgoing-stream handler while a server unidirectional stream
            // waits for peer credit. Per SSL_poll(3) the failure flag
            // (SSL_POLL_EVENT_F) is a poll result, not a pollable interest: it
            // is raised regardless of want_events and is handled by eviction
            // in the poll loop.
            connItem = new QuicPollItem(connSsl, CONNECTION_POLL_EVENTS, conn,
                    this::markPollInterestChanged);
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
            // Register the manager before connectionOpen(): if the protocol
            // callback throws after creating per-connection state, teardown
            // can still call connectionClose(); and if it fails the connection
            // inline the manager must already be reachable from the wrapper.
            conn.setQuicConnectionManager(connManager);
            connManager.connectionOpen(conn);
            if (!isConnectionLive(conn)) {
                // connectionOpen() may fail the connection (or another
                // protocol callback may have done so), in which case the
                // native connection SSL is already freed/deferred. Do not
                // continue with bootstrap on freed native state.
                return;
            }

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

            applyTransportStreamLimits(conn, connManager);

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
        } catch (Throwable t) {
            // The wrapper may not exist yet (construction failed before the
            // Cleaner was registered). Without a wrapper there is no teardown
            // path that knows the native SSL, so free it here.
            if (conn == null) {
                try {
                    openssl_h.SSL_free(connSsl);
                } catch (Throwable freeFailure) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error freeing QUIC connection SSL after setup failure", freeFailure);
                    }
                }
            } else {
                abortConnectionSetup(conn);
            }
            ExceptionUtils.handleThrowable(t);
            long now = System.currentTimeMillis();
            if (now - lastConnectionSetupErrorLogMs >=
                    SECURITY_WARNING_LOG_INTERVAL_MS) {
                lastConnectionSetupErrorLogMs = now;
                log.warn(sm.getString("quicEndpoint.connectionSetupError",
                        Long.toHexString(connSsl.address())), t);
            } else if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicEndpoint.connectionSetupError",
                        Long.toHexString(connSsl.address())), t);
            }
        }
    }


    /**
     * Applies the per-connection transport settings immediately after the
     * connection object is created: non-blocking mode, multi-stream
     * (no-default-stream) mode and EXPLICIT event-handling mode. The blocking
     * mode and default stream mode are required for HTTP/3 (HTTP/3 needs
     * stream-aware, non-blocking operation), so a failure aborts the connection
     * setup; the EXPLICIT mode is an optimisation and remains best effort.
     *
     * @param connSsl The connection SSL (live)
     *
     * @throws IOException If a required transport setting could not be applied
     */
    private void configureConnectionTransport(MemorySegment connSsl) throws IOException {
        int blockingRc = QuicBindings.SSL_set_blocking_mode(connSsl, 0);
        if (blockingRc != 1) {
            throw new IOException(sm.getString("quicEndpoint.sslSetBlockingModeError",
                    Integer.valueOf(blockingRc)));
        }

        // Disable default stream mode: HTTP/3 requires explicit stream
        // management (multi-stream mode). Without this, OpenSSL may
        // auto-associate a single stream with the connection object, causing
        // conflicts when we create multiple streams.
        int streamModeRc = QuicBindings.SSL_set_default_stream_mode(
                connSsl, QuicBindings.SSL_DEFAULT_STREAM_MODE_NONE);
        if (streamModeRc != 1) {
            throw new IOException(sm.getString("quicEndpoint.setDefaultStreamModeError",
                    Integer.valueOf(streamModeRc)));
        }

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
        if (rc != 1) {
            // Handled non-fatal failure: do not leave the error-queue entry
            // behind for a later accept diagnostic to misread.
            QuicDiagnostics.clearErrorQueue();
            if (eventHandlingModeWarned.compareAndSet(false, true)) {
                log.warn(sm.getString("quicEndpoint.eventHandlingModeRejected"));
            }
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
     *
     * @throws IOException If the policy could not be applied
     */
    private void configureIncomingStreamPolicy(MemorySegment connSsl) throws IOException {
        int policyRc = QuicBindings.SSL_set_incoming_stream_policy(
                connSsl, QuicBindings.SSL_INCOMING_STREAM_POLICY_ACCEPT, 0L);
        if (policyRc != 1) {
            throw new IOException(sm.getString("quicEndpoint.setIncomingStreamPolicyError",
                    Integer.valueOf(policyRc)));
        }
        if (log.isDebugEnabled()) {
            log.debug("SSL_set_incoming_stream_policy(ACCEPT) rc=" + policyRc);
        }
    }


    /**
     * Applies the configured idle timeout to the listener, so every accepted
     * connection inherits it before its transport parameters are generated.
     * Per-connection requests are too late once the handshake has progressed.
     */
    private void configureListenerIdleTimeout() {
        if (listener == null || listener.equals(MemorySegment.NULL)) {
            return;
        }
        QuicProtocol protocol = getQuicProtocol();
        if (protocol == null || protocol.getIdleTimeoutMs() <= 0) {
            return;
        }
        long configured = protocol.getIdleTimeoutMs();
        int rc = QuicBindings.SSL_set_value_uint(
                listener,
                QuicBindings.SSL_VALUE_CLASS_FEATURE_REQUEST,
                QuicBindings.SSL_VALUE_QUIC_IDLE_TIMEOUT,
                configured);
        if (rc == 1) {
            listenerIdleTimeoutApplied = true;
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicEndpoint.idleTimeout",
                        Long.valueOf(configured)));
            }
        } else {
            QuicDiagnostics.clearErrorQueue();
            log.warn(sm.getString("quicEndpoint.listenerIdleTimeoutRejected",
                    Long.valueOf(configured), Integer.valueOf(rc)));
        }
    }


    /**
     * Bounds the listener's pending-handshake queue by the configured
     * connection limit. OpenSSL's default is 256; the limit is capped at that
     * default so a large maxConnections value does not enlarge the
     * pre-handshake queue. Setting 0 would disable the bound in OpenSSL, so
     * at least one pending entry is allowed.
     */
    private void configureListenerPendingConnections() {
        if (listener == null || listener.equals(MemorySegment.NULL)) {
            return;
        }
        long maxPending;
        if (maxConnections < 0) {
            maxPending = 256;
        } else {
            maxPending = Math.max(1, Math.min(maxConnections, 256));
        }
        int rc = QuicBindings.SSL_set_value_uint(
                listener,
                QuicBindings.SSL_VALUE_CLASS_GENERIC,
                QuicBindings.SSL_VALUE_QUIC_MAX_PENDING_CONNS,
                maxPending);
        if (rc != 1) {
            // Older OpenSSL builds may not expose this value. The library
            // default (256) remains in force, which is still bounded.
            QuicDiagnostics.clearErrorQueue();
            if (log.isDebugEnabled()) {
                log.debug("SSL_set_value_uint(SSL_VALUE_QUIC_MAX_PENDING_CONNS) failed rc=" +
                        rc + "; keeping the OpenSSL default pending limit");
            }
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
        if (listenerIdleTimeoutApplied) {
            // The listener-level feature request already covers this
            // connection and avoids the transport-parameter timing race.
            return;
        }
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
            if (rc == 0) {
                // Handled non-fatal failure (the transport parameters may
                // already have been generated): drain the queue entry so a
                // later accept check cannot mistake it for an accept failure.
                QuicDiagnostics.clearErrorQueue();
                if (configuredIdleTimeoutMs != OPENSSL_DEFAULT_IDLE_TIMEOUT_MS &&
                        idleTimeoutFallbackWarned.compareAndSet(false, true)) {
                    log.warn(sm.getString("quicEndpoint.idleTimeoutRejected",
                            Long.valueOf(configuredIdleTimeoutMs),
                            Long.valueOf(OPENSSL_DEFAULT_IDLE_TIMEOUT_MS)));
                }
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
     * <li>Accept BIDI streams and pre-read their data before any further
     *     state-machine pump, so the request bytes are staged for the handler
     *     dispatch. This is a latency/ordering choice, not a correctness
     *     requirement: OpenSSL keeps received stream data readable until the
     *     application consumes it, including after FIN has been processed.</li>
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
            QuicPollItem connItem) throws IOException {
        // Gate stream processing (including the inline pre-read of client UNI
        // streams below) on the negotiated ALPN being one the application
        // protocol serves. The ALPN select callback normally rejects an
        // unsupported handshake, but the bootstrap path must not depend on
        // that: it can run before the first gated poll event and would
        // otherwise feed stream data to the protocol on a connection that is
        // about to be rejected. A null ALPN is only deferrable while the
        // handshake is still in progress; the check below stops the bootstrap
        // until it has completed.
        if (!ensureServedProtocol(conn, true)) {
            return new int[] { 0, 0 };
        }
        if (!isHandshakeComplete(conn)) {
            // The handshake has not finished yet, so the ALPN result may still
            // change. Do not feed any stream data to the protocol now; the
            // connection's later IS/IC event re-runs the gated accept path
            // once the handshake has completed.
            return new int[] { 0, 0 };
        }
        int[] accepted = acceptStreams(connSsl, QuicPoll.SSL_ACCEPT_STREAM_UNI,
                conn, "IC: accepted UNI", true);
        int uniAccepted = accepted[0];
        int bidiAccepted = accepted[1];

        if (!isConnectionLive(conn)) {
            // Inline protocol processing of a client UNI stream failed the
            // connection: teardown already freed (or deferred the free of)
            // the connection SSL. Every native call below (pumpEvents,
            // createServerUniStreams, the buffered writes, the BIDI accept)
            // would run on freed memory.
            return new int[] { uniAccepted, bidiAccepted };
        }

        pumpEvents(connSsl);

        try {
            createServerUniStreams(connItem, conn);
        } catch (Exception e) {
            // A server-stream creation failure may be partial: a stream can
            // already have been registered (and its init bytes staged) before
            // a protocol callback throws. Continuing the bootstrap would
            // promote request streams while the control stream/SETTINGS state
            // is incomplete, so fail the connection instead of swallowing the
            // failure and relying on an OSU retry that the duplicate-index
            // guard may suppress.
            log.warn(sm.getString("quicEndpoint.serverUniStreamCreateFailed"), e);
            if (isConnectionLive(conn)) {
                failConnection(conn, getDefaultStreamErrorCode(),
                        "Server unidirectional stream creation failed: " +
                                e.getMessage());
            }
            return new int[] { uniAccepted, bidiAccepted };
        }

        if (!isConnectionLive(conn)) {
            // A protocol callback during stream creation failed the
            // connection inline; the connection SSL may be freed.
            return new int[] { uniAccepted, bidiAccepted };
        }

        // createServerUniStreams() flushed every buffered server
        // unidirectional stream once for the whole batch (a pump per stream
        // would be O(fleet²) under an accept burst).

        accepted = acceptStreams(connSsl, QuicPoll.SSL_ACCEPT_STREAM_BIDI,
                conn, "IC: accepted BIDI", true);
        uniAccepted += accepted[0];
        bidiAccepted += accepted[1];

        // An inline failure during the BIDI accept/dispatch pass may have
        // torn the connection down; its stream SSLs are freed then.
        if (isConnectionLive(conn) && (uniAccepted + bidiAccepted) > 0 &&
                conn.getPendingStreams().size() > 0) {
            addPendingStreamsToPollSet(conn);
        }

        return new int[] { uniAccepted, bidiAccepted };
    }


    /**
     * Tears down a connection whose setup in {@link #handleIncomingConnection()}
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
        if (conn == null) {
            return;
        }
        // An inline protocol failure (failConnection) may already have torn
        // the connection down, scheduled its terminal stream events and freed
        // (or deferred the free of) its SSL. Calling teardown again on that
        // wrapper would run native stream/connection frees and flush
        // callbacks on freed pointers; the teardown-started CAS is the
        // authoritative guard. Only schedule the terminal events if this call
        // owns a fresh teardown: a deferred teardown that is still waiting for
        // a busy handler has already queued them, and a second scheduling
        // would invoke handler.process() twice.
        boolean teardownStarted = conn.isTeardownStarted();
        // A provisional or already-observed closed flag does not mean the
        // terminal stream events were scheduled: QuicConnectionWrapper's
        // failConnection() marks the connection closed before the retry
        // teardown runs, and a peer-close setup race can observe closed
        // without this call having queued the wakes. Only the teardown-started
        // claim proves that a terminal dispatch is already owned elsewhere.
        boolean scheduleTerminalEvents = !conn.isFreed() && !teardownStarted;
        if (scheduleTerminalEvents) {
            try {
                wakeAndScheduleTerminalStreamEvents(conn);
            } catch (Throwable t) {
                // A failure to schedule the wakes must not skip the teardown:
                // the connection would remain in the maps/poll set with its
                // native SSL alive and the protocol manager still registered.
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("quicEndpoint.connectionSetupAbortError"), t);
            }
        }
        if (!conn.isFreed() && !teardownStarted) {
            try {
                teardownConnection(conn, null);
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("quicEndpoint.connectionSetupAbortError"), t);
            }
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
        mailbox.drainPendingStreamDrains(conn, false);
        drainPendingStreamFrees();
        freeConnectionOrDefer(conn);
    }


    /**
     * Reconciles the configured application protocol concurrent-stream limit
     * with the limit the QUIC transport advertises to the peer
     * ({@code initial_max_streams_bidi}).
     * <p>
     * The OpenSSL QUIC implementation (3.5 / 4.0) fixes the transport stream
     * limits. OpenSSL 4.x accepts several QUIC feature requests through
     * {@code SSL_set_value_uint()} (for example the idle timeout, event
     * handling mode, UDP payload size and flow-control window values), but the
     * stream-availability identifiers are read-only
     * ({@code SSL_get_value_uint()} with {@code SSL_VALUE_CLASS_GENERIC}). The
     * endpoint therefore cannot make the peer see the configured limit - it
     * can only enforce a limit that matches the transport:
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
     * Must be called on the poll thread after the streams currently queued by
     * the peer have been accepted (the remaining transport credit is combined
     * with the per-connection accepted-stream count to recover the advertised
     * initial limit). The count includes every stream accepted so far, not
     * only those accepted during bootstrap, so a reconciliation deferred until
     * after the handshake cannot underestimate the limit when request streams
     * arrived first.
     *
     * @param conn        The connection
     * @param connManager The connection's protocol manager (may be
     *                    {@code null} if the connection was closed)
     */
    private void applyTransportStreamLimits(QuicConnectionWrapper conn,
            QuicConnectionManager connManager) {
        if (conn.isStreamLimitsReconciled()) {
            return;
        }
        int bidiAccepted = conn.getAcceptedBidiStreams();
        int uniAccepted = conn.getAcceptedUniStreams();
        if (connManager == null || conn.getNegotiatedProtocol() == null) {
            // The transport parameters are not necessarily available yet when
            // SSL_accept_connection() returns before the handshake completes.
            // The configured limit remains in force; the transport itself
            // caps the peer at its advertised initial_max_streams_* value.
            // The reconciliation is retried once ALPN becomes readable.
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

        if (bidiAvail < 0 || uniAvail < 0) {
            // A failed SSL_get_value_uint() leaves an error-queue entry.
            QuicDiagnostics.clearErrorQueue();
        }
        if (bidiAvail < 0) {
            // Transport limit unavailable - keep the configured limit as is.
            return;
        }
        if (bidiAccepted >= MAX_ACCEPT_PER_EVENT) {
            // The accept loop hit its cap, so more client streams may be
            // queued: avail + accepted would underestimate the advertised
            // limit. Skip the reconciliation for this connection, and do not
            // retry it later with the same incomplete bootstrap counts.
            if (log.isDebugEnabled()) {
                log.debug("Transport stream limit reconciliation skipped for conn=0x" +
                        Long.toHexString(conn.getSslAddress()) + " (accept cap hit)");
            }
            conn.setStreamLimitsReconciled(true);
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
        conn.setStreamLimitsReconciled(true);
    }


    /**
     * Runs transport stream-limit reconciliation when it was deferred because
     * the ALPN result was not readable during connection bootstrap. Uses the
     * per-connection accepted-stream counters, including streams accepted
     * after bootstrap, so the advertised transport limit is reconstructed
     * correctly.
     *
     * @param conn The connection to reconcile
     */
    private void reconcileTransportStreamLimitsIfNeeded(QuicConnectionWrapper conn) {
        if (conn == null || conn.isClosed() || conn.isFreed() ||
                conn.isStreamLimitsReconciled() || conn.getNegotiatedProtocol() == null) {
            return;
        }
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null) {
            return;
        }
        applyTransportStreamLimits(conn, connManager);
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
        if (connManager == null || conn.isClosed() || conn.isFreed()) {
            // The connection has no protocol manager or is already gone: the
            // streams would have nothing protocol-valid to write, or must not
            // be created on freed native state.
            return;
        }

        boolean created = false;
        long[] streamInfo = STREAM_INFO_SCRATCH.get();
        while (true) {
            if (!isConnectionLive(conn)) {
                // A protocol callback from the previous iteration (or the
                // nextServerUniStream() call below) may have failed the
                // connection inline; do not touch its freed SSL.
                return;
            }
            int index = connManager.nextServerUniStream(conn);
            if (index < 0) {
                break;
            }
            if (!isConnectionLive(conn)) {
                return;
            }
            if (conn.getServerUniStream(index) != null) {
                // Already created. A protocol manager that keeps handing out
                // the same index - for example after a failure before
                // serverUniStreamCreated() - would otherwise make this loop
                // create an unbounded number of streams, overwrite the
                // serverUniStreams entry and emit duplicate control/QPACK
                // streams.
                if (log.isDebugEnabled()) {
                    log.debug("Server unidirectional stream index " + index +
                            " already exists; stopping creation for this pass");
                }
                // Clear OSU interest: otherwise the level-triggered OSU event
                // (stream credit is still available) re-enters this method and
                // immediately breaks here on every poll iteration when the
                // protocol manager fails to advance past the existing index.
                // A later client-data trigger may re-add OSU, but it will not
                // be re-armed by this no-progress path. OSB is cleared too for
                // the same reason: it is also an outgoing-stream trigger, and
                // stale masks (or a future request of that event) must not
                // spin on the same duplicate index.
                connItem.setWantEvents(connItem.getWantEvents() &
                        ~(QuicPoll.SSL_POLL_EVENT_OSU |
                                QuicPoll.SSL_POLL_EVENT_OSB));
                break;
            }
            // Fetch the protocol-provided init bytes before creating the
            // native stream: a protocol callback that throws here must not
            // leave a registered stream without its SETTINGS/init data behind.
            ByteBuffer initData = connManager.getServerUniStreamInitData(index);
            MemorySegment streamSsl = newUniStream(connItem.getSsl(), streamInfo);
            if (streamSsl.equals(MemorySegment.NULL)) {
                // Not ready yet (peer has not yet advertised stream
                // capacity). Retried on the next OSU event; OSU stays in
                // want_events while nextServerUniStream() is >= 0.
                long localAvail = localUniStreamCredit(connItem.getSsl());
                if (localAvail > 0L) {
                    // The peer granted creation credit, so NULL is not the
                    // ordinary "not ready yet" case. Fail the pass instead of
                    // leaving OSU armed and retrying a hard failure on every
                    // writable event (a full CPU poll-loop spin).
                    throw new IOException(sm.getString(
                            "quicEndpoint.serverUniStreamCreateError",
                            Integer.valueOf(index), Long.valueOf(localAvail),
                            QuicDiagnostics.dumpErrorQueue()));
                }
                if (log.isDebugEnabled()) {
                    log.debug("SSL_new_stream for server unidirectional stream index "
                            + index + " returned NULL: " + QuicDiagnostics.dumpErrorQueue());
                } else {
                    // The NULL is the ordinary "no credit yet" result; do not
                    // leave a native error entry behind for checkAcceptFailure.
                    QuicDiagnostics.clearErrorQueue();
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
            // stream's write buffer. Do not drive the engine here: the
            // batched flush below pumps once per retry round for all server
            // streams, so creating N streams on one connection no longer
            // costs N whole-engine ticks (an accept burst would otherwise be
            // O(fleet²)). If the retries run out the bytes stay buffered and
            // the W event handler retries the write.
            try {
                if (initData != null && initData.hasRemaining()) {
                    byte[] data = new byte[initData.remaining()];
                    initData.get(data);
                    if (log.isDebugEnabled()) {
                        // Payload redacted (see drainStreamInto): size only.
                        log.debug("Server unidirectional stream index " + index +
                                " buffering " + data.length + " init bytes");
                    }
                    stream.setWriteBuffer(ByteBuffer.wrap(data));
                }
                connManager.serverUniStreamCreated(conn, index, stream);
            } catch (RuntimeException | Error e) {
                // The stream was registered before the protocol call failed.
                // Remove it from the connection's maps/poll set and release
                // its SSL so the bootstrap failure cannot leave a partially
                // created control/QPACK stream behind.
                cleanupAcceptedStream(stream);
                throw e;
            }
            created = true;
        }

        if (created && isConnectionLive(conn)) {
            flushServerUniStreams(connItem.getSsl(), conn);
        }

        if (created && isConnectionLive(conn)) {
            // Add pending streams to poll set now that the protocol streams
            // exist, and let the client unidirectional stream data flow.
            addPendingStreamsToPollSet(conn);
            enableReadOnClientUnidirectionalStreams(conn);
        }
    }


    /**
     * Writes the buffered init/protocol data of every server unidirectional
     * stream of one connection, pumping the shared engine once per retry round
     * rather than once per stream/attempt. Streams whose bytes cannot be
     * accepted keep their buffer for the W-event retry. Must run on the poll
     * thread while the connection SSL is alive.
     *
     * @param connSsl The connection SSL object
     * @param conn    The connection wrapper
     */
    private void flushServerUniStreams(MemorySegment connSsl,
            QuicConnectionWrapper conn) {
        for (int retry = 0; retry < STREAM_WRITE_RETRY_ATTEMPTS; retry++) {
            if (!isConnectionLive(conn)) {
                return;
            }
            pumpEvents(connSsl);
            boolean anyRetry = false;
            for (QuicStreamWrapper stream : conn.getServerUniStreams()) {
                if (!isConnectionLive(conn)) {
                    return;
                }
                ByteBuffer buffered = stream.getWriteBuffer();
                QuicPollItem item = stream.getPollItem();
                if (item == null || buffered == null ||
                        !buffered.hasRemaining()) {
                    continue;
                }
                UniStreamWriteResult result =
                        flushServerUniStreamWrite(stream, item);
                if (result == UniStreamWriteResult.RETRY) {
                    anyRetry = true;
                } else if (result == UniStreamWriteResult.FAILED) {
                    handleServerUniWriteResult(stream, result);
                }
            }
            if (!anyRetry) {
                return;
            }
        }
    }


    /**
     * Returns the number of server-initiated unidirectional streams the
     * transport currently permits, or {@code -1} when the query is not
     * supported.
     *
     * @param connSsl The connection SSL object
     *
     * @return The local creation credit, or {@code -1}
     */
    private static long localUniStreamCredit(MemorySegment connSsl) {
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment value = localArena.allocate(ValueLayout.JAVA_LONG);
            if (QuicBindings.SSL_get_value_uint(connSsl,
                    QuicBindings.SSL_VALUE_CLASS_GENERIC,
                    QuicBindings.SSL_VALUE_QUIC_STREAM_UNI_LOCAL_AVAIL,
                    value) == 1) {
                return value.get(ValueLayout.JAVA_LONG, 0);
            }
        }
        QuicDiagnostics.clearErrorQueue();
        return -1L;
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
                QuicOpenSSLSocketWrapper streamWrapper = getOwnedStreamWrapper(sw);
                if (streamWrapper != null) {
                    streamWrappers.remove(sw.getSslAddress(), streamWrapper);
                    // No further data can ever arrive: release any worker
                    // parked in a synchronous read or write on the stream.
                    streamWrapper.signalReadWaiter();
                    streamWrapper.signalWriteWaiter();
                    if (sw.getStreamType() == QuicPoll.SSL_STREAM_TYPE_BIDI &&
                            !streamWrapper.isClosed()) {
                        // Do not dispatch terminal events to a wrapper whose
                        // request already completed: its close path may have
                        // failed to remove it from streamWrappers (for example
                        // a timed-out onPollThread hop), but processing it
                        // again would run handler code on a released wrapper.
                        // quiche/ngtcp2 apply the same guard.
                        streamWrapperList.add(streamWrapper);
                    }
                }
            }
            for (QuicStreamWrapper sw : conn.getPendingStreams()) {
                QuicOpenSSLSocketWrapper streamWrapper = getOwnedStreamWrapper(sw);
                if (streamWrapper != null) {
                    streamWrappers.remove(sw.getSslAddress(), streamWrapper);
                    streamWrapper.signalReadWaiter();
                    streamWrapper.signalWriteWaiter();
                }
            }
            // teardownConnection() removes the wrappers and stream items,
            // frees the stream SSLs and then runs the callback; this is the
            // single teardown implementation, so the ECD path cannot drift
            // from the normal/failConnection teardown again.
            teardownConnection(conn, () -> {
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
                            SocketEvent.ERROR, true, streamWrapper.getError() == null
                                    ? new IOException(sm.getString(
                                            "quicEndpoint.streamConnectionClosed",
                                            Long.valueOf(wakeStream.getStreamId())))
                                    : null);
                }
            });
            return;
        }

        // EC without ECD: connection close in progress.
        // Use SSL_shutdown_ex with RAPID flag to initiate rapid drain,
        // then wait for ECD to confirm the connection is fully closed.
        if ((revents & QuicPoll.SSL_POLL_EVENT_EC) != 0) {
            if (conn.isClosing()) {
                // Already processed EC - don't process again to avoid tight loop.
                // Disarm the level-triggered EC event while waiting for ECD,
                // keeping the same interests as the normal EC branch below:
                // EC would otherwise be re-reported on every poll iteration
                // and counted as progress, spinning the poll thread.
                item.setWantEvents(
                        QuicPoll.SSL_POLL_EVENT_ECD |
                        QuicPoll.SSL_POLL_EVENT_ISB |
                        QuicPoll.SSL_POLL_EVENT_ISU |
                        QuicPoll.SSL_POLL_EVENT_ER |
                        QuicPoll.SSL_POLL_EVENT_EW);
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
                acceptPendingStreams(item, conn);
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
            // still reported (acceptPendingStreams above consumes them),
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
     * A poll task that holds an active-handler reference from scheduling until
     * it runs; the mailbox notifies it if a close/open discards it unrun.
     */
    private interface DiscardablePollTask extends Runnable,
            QuicNativeMailbox.DiscardListener {
    }


    /**
     * Schedules {@code event} for {@code stream} once the stream's processing
     * flag is free, without blocking the caller and without ever running the
     * handler concurrently with the current flag owner. Used for the terminal
     * ERROR dispatch on connection close (the wake-up OPEN_READ dispatch may
     * still be owned by a worker) and for dispatch events that find the
     * processing claim busy (the lost-claim fallbacks in the stream dispatch
     * paths; the call site in {@link QuicSocketProcessor#doRun()} is the live
     * async-completion/dispatch path - see that class' comment).
     * <p>
     * Waiting for the flag on the poll thread would stall every other
     * connection for as long as the owner's handler runs, so the attempt is
     * parked as a claim waiter on the stream and re-run when the claim is
     * released. A dispatch that acquires the flag is delivered with flag
     * ownership, exactly like the synchronous path. If the budget expires when
     * the task is finally re-run the event is dropped with a log line: the
     * flag owner re-arms the stream's poll interest on exit, so a pending
     * I/O wake-up cannot be lost, and an in-flight handler observes the
     * closed stream through its own reads. The task must never re-submit
     * itself from inside its own run: that re-enters the mailbox drain that
     * is executing it, makes the drain loop spin until the budget expires and
     * starves every other poll-loop job.
     */
    private void scheduleStreamDispatch(QuicOpenSSLSocketWrapper wrapper,
            QuicStreamWrapper stream, SocketEvent event) {
        scheduleStreamDispatch(wrapper, stream, event, false);
    }


    /**
     * Schedules {@code event} for {@code stream} once the stream's processing
     * flag is free.
     *
     * @param allowDead {@code true} for intentional terminal wakes (connection
     *                  close) that must still reach a handler after the stream
     *                  SSL has been freed; {@code false} for ordinary
     *                  async/re-dispatch events, which are dropped if the
     *                  stream has since been deregistered or freed
     */
    private void scheduleStreamDispatch(QuicOpenSSLSocketWrapper wrapper,
            QuicStreamWrapper stream, SocketEvent event, boolean allowDead) {
        scheduleStreamDispatch(wrapper, stream, event, allowDead, null);
    }


    /**
     * Schedules {@code event} for {@code stream} once the stream's processing
     * flag is free, optionally installing a terminal error on the wrapper only
     * when the deferred dispatch actually runs.
     *
     * @param allowDead     {@code true} for intentional terminal wakes
     * @param terminalError Error to set on the wrapper when the deferred
     *                      dispatch runs, or {@code null} to leave the wrapper
     *                      error untouched
     */
    private void scheduleStreamDispatch(QuicOpenSSLSocketWrapper wrapper,
            QuicStreamWrapper stream, SocketEvent event, boolean allowDead,
            IOException terminalError) {
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
        if (!submitPollTask(new DiscardablePollTask() {

            /**
             * The scheduling reference is owned once per task object, not
             * once per execution. A wake can poll this task from
             * claimWaiters while it is still running and re-submit the same
             * object; making the release idempotent prevents the duplicate
             * execution from decrementing activeHandlers a second time.
             */
            private final AtomicBoolean handlerRefHeld = new AtomicBoolean(true);

            /**
             * Whether this task object currently owns one claim-waiter queue
             * entry. A wake can re-submit the same object while an earlier
             * execution is still between addClaimWaiter() and the CAS; without
             * this guard both executions would add an entry, the winner would
             * remove only one, and the loser would leave a stale entry that
             * later re-dispatches the same event a second time.
             */
            private final AtomicBoolean waiterRegistered = new AtomicBoolean(false);

            private void releaseHandlerRef() {
                if (handlerRefHeld.getAndSet(false)) {
                    finishStreamDispatch(stream, conn, false);
                }
            }

            @Override
            public void run() {
                // Register before touching the claim. The dispatch that
                // releases the flag drains this queue after clearing it, so
                // either this attempt wins the freed claim or the release
                // re-runs it. Only one registration per task object is kept:
                // a re-submitted execution must not add a second reference
                // for the same attempt.
                if (waiterRegistered.compareAndSet(false, true)) {
                    stream.addClaimWaiter(this);
                }
                if (stream.compareAndSetProcessing(false, true)) {
                    stream.removeClaimWaiter(this);
                    waiterRegistered.set(false);
                    if (wrapper != null && wrapper.isClosed()) {
                        // A terminal wake queued after the native free may
                        // run after the earlier OPEN_READ dispatch already
                        // closed the wrapper. Invoking handler.process() now
                        // would be a second dispatch on a retired wrapper;
                        // close was already requested, so drop the event and
                        // release the claim/accounting.
                        stream.clearProcessing();
                        wakeClaimWaiters(stream, conn);
                        if (conn != null && stream.isDeregistered() &&
                                !stream.isFreed()) {
                            mailbox.queueStreamDrain(stream);
                        }
                        releaseHandlerRef();
                        return;
                    }
                    if (!allowDead && !isStreamLive(stream)) {
                        // The ordinary event lost the race with teardown: the
                        // stream was deregistered or its SSL was freed after
                        // the caller's initial liveness check but before the
                        // claim was taken. Do not invoke the handler on a
                        // released stream; release this scheduling reference
                        // and let the claim waiters re-check themselves.
                        stream.clearProcessing();
                        wakeClaimWaiters(stream, conn);
                        releaseHandlerRef();
                        return;
                    }
                    if (terminalError != null && wrapper != null &&
                            wrapper.getError() == null) {
                        // Install the terminal cause only for the deferred
                        // terminal dispatch. Setting it before a clean OPEN_READ
                        // wake-up made processSocketInline() convert that wake
                        // into an ERROR event and log a stack trace.
                        wrapper.setError(terminalError);
                    }
                    dispatchToExecutor(wrapper, stream, event, true);
                    // Release the scheduling reference; the executor dispatch
                    // carries its own until its processor finishes.
                    releaseHandlerRef();
                    return;
                }
                if (System.nanoTime() - deadline < 0) {
                    // Claim still held: stay registered and let the releasing
                    // dispatch re-run this attempt.
                    return;
                }
                stream.removeClaimWaiter(this);
                waiterRegistered.set(false);
                if (log.isDebugEnabled()) {
                    log.debug("Stream " + stream.getStreamId() + " still busy" +
                            " after the claim budget - " + event +
                            " dispatch dropped; the flag owner re-arms the" +
                            " stream's poll interest on exit");
                }
                releaseHandlerRef();
            }

            @Override
            public void onDiscard() {
                // The mailbox was closed/opened while this attempt was still
                // queued (a late handler submitted it after the stop drain).
                // It never ran, so release the claim-waiter registration and
                // the active-handler reference it owns; otherwise the count
                // stays elevated and stopInternal() retains the connection
                // forever. The release is idempotent against a duplicate
                // execution of this same task object.
                stream.removeClaimWaiter(this);
                waiterRegistered.set(false);
                releaseHandlerRef();
            }
        })) {
            finishStreamDispatch(stream, conn, false);
        }
    }


    /**
     * Re-runs claim-retry attempts parked on a stream whose processing flag
     * has just been released. Each waiter owns an active-handler reference,
     * which it balances itself when it runs; a waiter that cannot be submitted
     * (the mailbox is closed, i.e. the endpoint is stopping) has its reference
     * balanced here.
     *
     * @param stream The stream whose waiters to wake
     * @param conn   The stream's connection (may be {@code null})
     */
    private void wakeClaimWaiters(QuicStreamWrapper stream,
            QuicConnectionWrapper conn) {
        Runnable waiter;
        while ((waiter = stream.pollClaimWaiter()) != null) {
            if (conn == null || !submitPollTask(waiter)) {
                finishStreamDispatch(stream, conn, false);
            }
        }
    }


   /**
    * Accepts incoming streams. Accepts UNI streams first, then BIDI streams.
    * BIDI stream data is pre-read immediately so the request bytes are staged
    * before the next engine tick; OpenSSL would keep the data readable after
    * FIN in any case, so this is an ordering/performance choice rather than a
    * correctness requirement.
    */
    private void handleIncomingStream(QuicPollItem connItem) throws Exception {
        QuicConnectionWrapper conn = (QuicConnectionWrapper) connItem.getAppData();
        if (conn == null) {
            return;
        }

        if (!ensureServedProtocol(conn)) {
            return;
        }

        // A client may have migrated since the connection was accepted
        // (RFC 9000 Section 9). Refresh before accepting new streams so the
        // socket wrappers created for this batch report the address the
        // packets actually came from.
        refreshPeerAddress(conn);

        long revents = connItem.getRevents();
        if (log.isDebugEnabled()) {
            log.debug("handleIncomingStream called, revents=0x" + Long.toHexString(revents));
        }

        // Accept UNI streams first
        // Read UNI stream data immediately. Client control stream (1) carries
        // SETTINGS, QPACK encoder stream (5) carries encoder instructions.
        // These must be read before processing BIDI stream data.
        int[] accepted = acceptStreams(connItem.getSsl(), QuicPoll.SSL_ACCEPT_STREAM_UNI,
                conn, "handleIncomingStream: accepted UNI", true);
        int uniAccepted = accepted[0];
        int bidiAccepted = accepted[1];

        if (!isConnectionLive(conn)) {
            // Inline protocol processing of a client UNI stream failed the
            // connection (the accept loop stopped on the teardown): the
            // connection SSL is freed (or the free is deferred) and its poll
            // item disposed. Everything below would run on freed memory.
            return;
        }

        // Accept BIDI streams and pre-read their data immediately after
        // SSL_accept_stream so the request bytes are staged before the next
        // poll iteration's engine tick and handler dispatch. OpenSSL keeps
        // received data readable after FIN, so this is an ordering/performance
        // choice, not a correctness requirement.
        accepted = acceptStreams(connItem.getSsl(), QuicPoll.SSL_ACCEPT_STREAM_BIDI,
                conn, "handleIncomingStream: accepted BIDI", true);
        uniAccepted += accepted[0];
        bidiAccepted += accepted[1];
        if (log.isDebugEnabled()) {
            log.debug("handleIncomingStream: accepted " + uniAccepted + " UNI + " + bidiAccepted + " BIDI stream(s)");
        }

        // Add pending streams to poll set if server control stream already
        // exists. An inline failure of the BIDI accept pass above (or of a
        // dispatch during it) may have torn the connection down; do not
        // promote streams whose SSLs have already been freed.
        if (isConnectionLive(conn) && (uniAccepted + bidiAccepted) > 0 &&
                conn.getPendingStreams().size() > 0) {
            addPendingStreamsToPollSet(conn);
        }

        // Reconcile only after this accept pass: streams the peer opened
        // before the handshake completed consumed transport credit, and the
        // accepted-stream counters must include them before the advertised
        // initial limit is reconstructed. Doing this before the accept pass
        // would store an underestimated limit and reject later streams.
        reconcileTransportStreamLimitsIfNeeded(conn);

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
        if (!isConnectionLive(conn)) {
            return;
        }
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
            // Do not silently swallow a protocol failure: without the
            // requested server streams (HTTP/3 control/QPACK), requests can
            // stall while the endpoint stays alive with no diagnostic.
            ExceptionUtils.handleThrowable(t);
            log.warn(sm.getString("quicEndpoint.serverUniStreamEventError"), t);
            if (isConnectionLive(conn)) {
                failConnection(conn, getDefaultStreamErrorCode(),
                        "nextServerUniStream failed: " + t.getMessage());
            }
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
     * Flushes the protocol data a connection manager has queued for the peer,
     * containing a failing protocol callback to its own connection. Without
     * this containment one RuntimeException would abort the whole
     * protocol-data sweep (and every later connection in it) and escape to
     * the poll loop, which would retry the same failing connection forever.
     * On failure the pending mark is cleared and the connection is failed;
     * the caller must not touch the connection's native state afterwards.
     *
     * @param conn        The connection whose protocol data to flush
     * @param connManager The connection's protocol manager
     *
     * @return {@code true} if the flush returned normally
     */
    private boolean flushProtocolData(QuicConnectionWrapper conn,
            QuicConnectionManager connManager) {
        try {
            connManager.flushPendingProtocolData(conn);
            return true;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            long now = System.currentTimeMillis();
            if (now - lastProtocolDataFlushWarnMs >=
                    SECURITY_WARNING_LOG_INTERVAL_MS) {
                lastProtocolDataFlushWarnMs = now;
                log.warn(sm.getString("quicEndpoint.protocolDataFlushError",
                        Long.toHexString(conn.getSslAddress())), t);
            } else if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicEndpoint.protocolDataFlushError",
                        Long.toHexString(conn.getSslAddress())), t);
            }
            // Clear the pending mark so a persistent protocol failure cannot
            // keep re-entering the sweep.
            setConnectionProtocolDataPending(conn, false);
            if (isConnectionLive(conn)) {
                failConnection(conn, getDefaultStreamErrorCode(),
                        "Protocol data flush failed: " + t.getMessage());
            }
            return false;
        }
    }


    /**
     * Drives the QUIC state machine once, checking the {@code SSL_handle_events}
     * return value (1 success, 0 failure). A failure is reported rate-limited
     * with the OpenSSL error queue and the queue is cleared so the next
     * diagnostic dump is not masked by stale entries. The caller may treat a
     * {@code false} result as a failed/non-progressing tick; the native engine
     * state is left untouched so a later tick can retry.
     *
     * @param ssl       The listener, connection or stream SSL to drive
     * @param operation Short description of the calling operation for logging
     *
     * @return {@code true} if the call reported success
     */
    boolean handleEvents(MemorySegment ssl, String operation) {
        try {
            if (QuicBindings.SSL_handle_events(ssl) == 1) {
                return true;
            }
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            // A persistent binding failure (for example a broken native
            // AssertionError) would otherwise log a full stack trace on every
            // poll iteration. Share the rate limiter used by the return-code
            // failure path.
            long now = System.currentTimeMillis();
            if (now - lastHandleEventsErrorLogMs >=
                    SECURITY_WARNING_LOG_INTERVAL_MS) {
                lastHandleEventsErrorLogMs = now;
                log.warn(sm.getString("quicEndpoint.handleEventsError", operation), t);
            } else if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicEndpoint.handleEventsError", operation), t);
            }
            QuicDiagnostics.clearErrorQueue();
            return false;
        }
        long now = System.currentTimeMillis();
        if (now - lastHandleEventsErrorLogMs >=
                SECURITY_WARNING_LOG_INTERVAL_MS) {
            lastHandleEventsErrorLogMs = now;
            log.warn(sm.getString("quicEndpoint.handleEventsFailed",
                    operation, QuicDiagnostics.dumpErrorQueue()));
        } else {
            QuicDiagnostics.clearErrorQueue();
        }
        return false;
    }


    /**
     * Returns an SSL object whose {@code SSL_handle_events()} call services
     * the whole shared QUIC engine: the listener when it is available, or any
     * live connection SSL otherwise. Used by batched tick paths so a pass over
     * N connections costs one engine walk, not N.
     *
     * @return A live engine SSL, or {@code null} when none is available
     */
    private MemorySegment engineTickSsl() {
        if (listener != null && !listener.equals(MemorySegment.NULL)) {
            return listener;
        }
        for (QuicConnectionWrapper conn : connections.values()) {
            if (!conn.isFreed()) {
                return conn.getSsl();
            }
        }
        return null;
    }


    /**
     * Checks the OpenSSL error queue after an accept call returned NULL. A NULL
     * normally means "nothing pending"; a non-empty queue means the call
     * actually failed. Callers clear the per-thread queue immediately before
     * the accept call, so handled failures from earlier native operations can
     * no longer be mistaken for an accept failure. Report it rate-limited and
     * back off briefly so a level-triggered accept event cannot spin the poll
     * loop without bound.
     *
     * @param operation The accept operation name for logging
     */
    private void checkAcceptFailure(String operation) {
        long error = QuicBindings.ERR_peek_error();
        if (error == 0) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastAcceptErrorLogMs >= SECURITY_WARNING_LOG_INTERVAL_MS) {
            lastAcceptErrorLogMs = now;
            log.warn(sm.getString("quicEndpoint.acceptFailed", operation,
                    Long.toHexString(error), QuicDiagnostics.dumpErrorQueue()));
        } else {
            QuicDiagnostics.clearErrorQueue();
        }
        // The accept event is level-triggered: a failed accept would re-fire
        // immediately after this handler returns. A brief backoff keeps that
        // failure from spinning the poll thread at full CPU.
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }


    /**
     * Performs a single {@code SSL_read_ex} drain attempt on a QUIC stream,
     * appending any bytes read to the tail of the stream's read buffer. The
     * buffer is left in put mode ({@code [0, position)} buffered, limit ==
     * capacity); the caller owns everything beyond the appended bytes.
     * <p>
     * This is the single read-loop primitive shared by the endpoint's bidi
     * and unidirectional pre-read paths and by the socket wrapper's direct
     * read path. The retry policy and the surrounding logging/protocol
     * handling stay with the callers - the immediate pre-read paths share
     * {@link #drainStreamImmediately}, the deferred unidirectional read
     * performs a single-shot drain; only the "allocate -&gt; SSL_read_ex
     * -&gt; copy -&gt; refresh state" body is common to all of them, and that
     * body is exactly where the F1/F8-class divergences used to creep in.
     * <p>
     * On an {@code SSL_read_ex} return of 0 the stream's read state is refreshed
     * via {@code SSL_get_stream_read_state} so callers can inspect it through
     * {@link QuicStreamWrapper#getReadState()}.
     *
     * @param stream   The stream (for state updates and trace identity)
     * @param ssl      The stream's {@code SSL*} pointer
     * @param readBuf  The destination buffer
     *
     * @return the number of bytes appended (possibly 0)
     */
    static int drainStreamInto(QuicStreamWrapper stream, MemorySegment ssl, ByteBuffer readBuf)
            throws IOException {
        int space = readBuf.remaining();
        if (space <= 0) {
            return 0;
        }

        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment nativeBuf = localArena.allocate(space);
            MemorySegment lenPtr = localArena.allocate(ABI.sizeT());
            ABI.setSizeT(lenPtr, 0, 0L);

            int rc = QuicBindings.SSL_read_ex(ssl, nativeBuf, (long) space, lenPtr);

            if (rc == 1) {
                long bytesRead = ABI.getSizeT(lenPtr, 0);
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
                // SSL_get_error() must be read before any other native call;
                // only WANT_READ/WANT_WRITE are retryable. A clean FIN is
                // reported as ZERO_RETURN (equivalent to EOF), and a hard
                // read failure with a still-OK stream state must surface as
                // IOException instead of being treated as would-block.
                int sslError = QuicBindings.SSL_get_error(ssl, 0);
                stream.setReadState(QuicStreamWrapper.mapNativeState(
                        QuicBindings.SSL_get_stream_read_state(ssl)));
                if (sslError == QuicBindings.SSL_ERROR_ZERO_RETURN) {
                    stream.setReadState(QuicStream.ReadState.FINISHED);
                } else if (stream.getReadState() == QuicStream.ReadState.RESET_LOCAL ||
                        stream.getReadState() == QuicStream.ReadState.RESET_REMOTE ||
                        stream.getReadState() == QuicStream.ReadState.CONN_CLOSED) {
                    // A peer-local reset or connection loss is a terminal
                    // stream state, not a hard read failure. OpenSSL reports
                    // RESET_RECVD/terminated streams through SSL_ERROR_SSL,
                    // but callers must inspect the read state and close the
                    // stream (or fail the connection only for a critical
                    // unidirectional stream) instead of treating every
                    // reset as a connection-level I/O error. The SSL_R_STREAM_RESET
                    // entry raised for this handled read must not survive into
                    // the next SSL_accept_stream() call, where a NULL result
                    // would be misreported by checkAcceptFailure() as an accept
                    // failure.
                    QuicDiagnostics.clearErrorQueue();
                    return 0;
                } else if (sslError != QuicBindings.SSL_ERROR_WANT_READ &&
                        sslError != QuicBindings.SSL_ERROR_WANT_WRITE) {
                    throw new IOException(sm.getString(
                            "quicEndpoint.streamReadNativeError",
                            Long.valueOf(stream.getStreamId()),
                            Integer.valueOf(sslError),
                            QuicDiagnostics.dumpErrorQueue()));
                }
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
            String kind, QuicStreamWrapper stream, ByteBuffer readBuf)
            throws IOException {
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
     * Reads BIDI stream data immediately after SSL_accept_stream, before the
     * next SSL_handle_events() tick, so the request bytes are staged for the
     * handler dispatch. This is a latency/ordering choice, not a correctness
     * requirement: OpenSSL keeps received stream data readable until the
     * application consumes it, even after FIN has been processed.
     */
    private void readBidiStreamImmediately(MemorySegment streamSsl, long streamId, QuicConnectionWrapper conn)
            throws IOException {
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
    private void readUnidirectionalStreamImmediately(MemorySegment streamSsl, long streamId, QuicConnectionWrapper conn)
            throws IOException {
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
     * {@code SSL_handle_events()} tick, so the bytes are staged before the
     * handler dispatch. This is a latency/ordering choice, not a correctness
     * requirement: OpenSSL keeps received data readable after FIN.
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
     * @param readImmediately Whether to immediately read client UNI stream
     *                        data; BIDI streams are pre-read by
     *                        {@link #processAcceptedStream()} when promoted
     *                        regardless of this flag
     *
     * @return a two element array {uniAccepted, bidiAccepted} counted by the
     *         observed {@code SSL_get_stream_type()}, not by the requested
     *         accept flag (a 3.5 library ignores the filter and may return
     *         either direction from a pass)
     */
    private int[] acceptStreams(MemorySegment connSsl, long acceptFlag,
            QuicConnectionWrapper conn, String logPrefix,
            boolean readImmediately) throws IOException {
        int uniAccepted = 0;
        int bidiAccepted = 0;
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
                checkAcceptFailure("SSL_accept_stream");
                break;
            }
            long[] streamInfo = STREAM_INFO_SCRATCH.get();
            readStreamIdType(streamSsl, streamInfo);
            long sid = streamInfo[0];
            int stype = (int) streamInfo[1];
            if (log.isDebugEnabled()) {
                log.debug(logPrefix + " stream id=" + sid + " type=" + stype);
            }
            if (stype == QuicPoll.SSL_STREAM_TYPE_BIDI) {
                bidiAccepted++;
                // Count immediately: the stream has consumed transport credit
                // even if later protocol processing rejects it or fails.
                conn.addAcceptedStreams(1, 0);
            } else {
                uniAccepted++;
                conn.addAcceptedStreams(0, 1);
            }
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
                //
                // BIDI streams were already pre-read by processAcceptedStream()
                // when it promoted them (and, while the server control stream
                // is missing, remain pending with their data still readable in
                // OpenSSL); do not read them a second time here, where the
                // first read may already have dispatched a handler.
                if (stype != QuicPoll.SSL_STREAM_TYPE_BIDI) {
                    readUnidirectionalStreamImmediately(streamSsl, sid, conn);
                }
            }
        }
        return new int[] { uniAccepted, bidiAccepted };
    }


    /**
     * Drives the QUIC state machine for one object once.
     *
     * @param ssl The connection or stream SSL to pump
     */
    private void pumpEvents(MemorySegment ssl) {
        handleEvents(ssl, "pump events");
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
        MemorySegment lenPtr = arena.allocate(ABI.sizeT());
        ABI.setSizeT(lenPtr, 0, 0L);
        // SSL_write_ex2 is part of the probed symbol set: QUIC_AVAILABLE
        // rejects a library that lacks it before bind() succeeds, so every
        // endpoint that runs reaches this call with ex2 bound.
        int rc = QuicBindings.SSL_write_ex2(streamSsl, dataSeg, (long) len, 0L, lenPtr);
        if (rc != 1) {
            return -1;
        }
        return (int) ABI.getSizeT(lenPtr, 0);
    }


    /**
     * Endpoint-side entry guard: checks that a stream may still be touched, as
     * a single spelled-out condition so no poll-thread path re-invents its own
     * subset of "stream freed/deregistered? connection closed/freed?". A stream
     * is live when it is present, has not been freed or deregistered, and its
     * connection is neither closed nor freed - connection teardown frees the
     * stream SSL objects, and a deregistered stream's SSL is owned by the
     * deferred-free queue, so neither may have its native object touched.
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
        if (stream == null || stream.isFreed() || stream.isDeregistered()) {
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
        if (conn == null || conn.isFreed() || !conn.markTeardownStarted()) {
            // Already torn down (or its SSL is already gone): repeating the
            // native stream/connection frees and flush callbacks would use a
            // freed connection SSL. The first caller owns the whole teardown.
            return;
        }
        assertNativeAccess("teardownConnection");
        conn.setClosed();
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        conn.setQuicConnectionManager(null);
        try {
            // Remove the stream wrappers before closeAllStreams() clears the
            // stream map, otherwise they leak (see removeStreamWrappers()).
            removeStreamWrappers(conn);
            conn.closeAllStreams();
            if (afterStreamsFreed != null) {
                afterStreamsFreed.run();
            }
        } catch (Throwable t) {
            logTeardownError(conn, t);
        }
        try {
            if (connManager != null) {
                connManager.connectionClose(conn);
            }
        } catch (Throwable t) {
            logTeardownError(conn, t);
        }
        // The connection must always leave the endpoint's maps/poll set and
        // have its SSL freed even when a protocol callback above throws or a
        // poll-set shrink allocation fails after taking the item out. The
        // free tail therefore runs unconditionally in the finally block; the
        // only exception is a poll-set removal that genuinely failed before
        // taking the item out, because freeing the SSL would then leave a
        // stale pointer in SSL_poll().
        try {
            setConnectionProtocolDataPending(conn, false);
            // Drops the retention entry right before the deferred drain and
            // CAS-guarded free below; closeAllStreams() above left no live
            // streams for a GC-thread Cleaner to race (see the connections
            // field javadoc).
            connections.remove(conn.getSslAddress());
            QuicPollItem removedItem = pollSet.remove(conn.getSslAddress());
            if (removedItem == null) {
                // The connection item may never have been promoted into the
                // poll set: bootstrapIncomingStreams() runs before the
                // pollSet.add() in handleIncomingConnection(), and inline
                // stream processing there can fail the connection (protocol
                // error -> failConnection -> this teardown). The poll set only
                // disposes items it removes, so release the item's native
                // SSL_POLL_ITEM struct (and its shared arena) here;
                // abortConnectionSetup() reaches this fallback through this
                // method, deregisterStream() has its own. dispose() is
                // idempotent.
                QuicPollItem item = conn.getPollItem();
                if (item != null) {
                    item.dispose();
                }
            }
        } catch (Throwable t) {
            logTeardownError(conn, t);
        } finally {
            try {
                // Free stream SSL objects whose free closeAllStreams() / the
                // workers deferred, before dropping the connection reference:
                // per SSL_new_stream(3) every stream SSL must be freed first.
                // Streams still waiting for their write buffer to drain are
                // force-freed now: the connection is going away, so delivery
                // can no longer be guaranteed and the stream SSL must not
                // outlive the connection.
                mailbox.drainPendingStreamDrains(conn, false);
                drainPendingStreamFrees();
            } catch (Throwable t) {
                // A drain failure must not skip the connection free below.
                logTeardownError(conn, t);
            }
            try {
                if (pollSet.get(conn.getSslAddress()) != null) {
                    // The poll-set removal failed before taking the item out.
                    // Keeping the SSL alive is safer than leaving a stale
                    // pointer in SSL_poll(); retain it for the stop/restart
                    // cleanup instead of freeing it here.
                    conn.setPendingFree();
                    stoppedBusyConnections.add(conn);
                    log.warn(sm.getString("quicEndpoint.teardownPollItemRetained",
                            Long.toHexString(conn.getSslAddress())));
                } else {
                    freeConnectionOrDefer(conn);
                }
            } catch (Throwable t) {
                logTeardownError(conn, t);
            }
        }
    }


    /**
     * Reports a failure in a teardown step without aborting the remaining
     * cleanup.
     *
     * @param conn The connection being torn down
     * @param t    The failure
     */
    private void logTeardownError(QuicConnectionWrapper conn, Throwable t) {
        ExceptionUtils.handleThrowable(t);
        log.warn(sm.getString("quicEndpoint.teardownCleanupError",
                Long.toHexString(conn.getSslAddress())), t);
    }


    private void processAcceptedStream(MemorySegment streamSsl, long streamId,
            int streamType, QuicConnectionWrapper conn) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Stream accepted: id=" + streamId + " type=" + streamType);
        }

        QuicConnectionManager connManager = null;
        QuicConnectionManager.ConnectionState state = null;
        boolean rejectStream = false;
        try {
            if (streamType == QuicPoll.SSL_STREAM_TYPE_BIDI) {
                connManager = conn.getQuicConnectionManager();
                if (connManager != null) {
                    state = connManager.getState(conn);
                    if (state != null && !state.canAcceptStream(streamId)) {
                        // Check before constructing the wrapper/read buffer: a
                        // refused stream is immediately freed, so allocating the
                        // full per-stream buffer and poll item first only creates
                        // churn under a stream-limit flood.
                        rejectStream = true;
                    }
                }
            }
        } catch (RuntimeException | Error e) {
            // The pre-check failed before any wrapper was constructed. The
            // stream SSL has not been registered with the connection, so it
            // must be released here; otherwise the connection teardown cannot
            // see it and may free the connection SSL while this stream still
            // references it.
            freeUnregisteredStreamSsl(streamSsl, conn);
            throw e;
        }

        if (rejectStream) {
            rejectAcceptedStream(streamSsl, streamId, conn, connManager, state);
            return;
        }

        QuicStreamWrapper stream = null;
        boolean streamCounted = false;
        try {
            // Client uni streams start small while their type is unknown: an
            // unknown stream discards its payload, so retaining a full
            // re-assembly buffer per stream would be pure amplification. An
            // identified control/QPACK stream grows on demand (see
            // processUniStreamData()).
            int initialReadBufferSize = streamType == QuicPoll.SSL_STREAM_TYPE_READ
                    ? Math.min(readBufferSize, UNI_INITIAL_READ_BUFFER_SIZE)
                    : readBufferSize;
            stream = new QuicStreamWrapper(
                    streamSsl, streamId, streamType, conn,
                    ByteBuffer.allocate(initialReadBufferSize));

            // Reference: stream monitors ER | EW base events only.
            // R and W are managed separately via pe_resume_read/pe_pause_write.
            long events = QuicPoll.SSL_POLL_EVENT_ER |
                      QuicPoll.SSL_POLL_EVENT_EW;
            QuicPollItem streamItem = new QuicPollItem(streamSsl, events, stream,
                    this::markPollInterestChanged);
            stream.setPollItem(streamItem);

            if (streamType == QuicPoll.SSL_STREAM_TYPE_BIDI && state != null) {
                state.incrementActiveStreams();
                streamCounted = true;
                state.setLastProcessedStreamId(streamId);
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
                        // Pre-read stream data into the buffer before adding it
                        // to the poll set, so the first handler dispatch finds
                        // the request bytes staged. This is a latency choice:
                        // OpenSSL keeps received data readable after FIN, and
                        // the later buffer-based read would retrieve it too.
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
        } catch (Error e) {
            // A setup/hand-off failure before the stream is fully registered
            // must not leave an untracked stream SSL behind, including when
            // the failure is an Error (for example OOME while allocating the
            // per-stream read buffer).
            cleanupPartiallyAcceptedStream(stream, streamSsl, conn, state,
                    streamId, streamCounted);
            ExceptionUtils.handleThrowable(e);
            throw e;
        } catch (Exception e) {
            // A setup/hand-off failure before the stream is fully registered
            // must not leave an untracked stream SSL behind: a later connection
            // teardown cannot see it in the stream map and would free the
            // connection before the stream SSL. Remove whatever tracking was
            // established, release the SSL if no worker owns it, then let the
            // caller abort the connection setup.
            cleanupPartiallyAcceptedStream(stream, streamSsl, conn, state,
                    streamId, streamCounted);
            throw e;
        }
    }


    /**
     * Releases an SSL accepted/created by OpenSSL that has not been wrapped or
     * registered yet. Used on failure paths where no teardown path knows the
     * native object.
     *
     * @param streamSsl The untracked stream SSL
     * @param conn      The owning connection, or {@code null} when unknown
     */
    private static void freeUnregisteredStreamSsl(MemorySegment streamSsl,
            QuicConnectionWrapper conn) {
        try {
            openssl_h.SSL_free(streamSsl);
        } catch (Throwable t) {
            // The stream SSL may still be alive even though it was never
            // tracked on the connection. Record the sticky failure so the
            // connection-free paths retain the connection instead of freeing
            // it underneath a possibly-live stream (SSL_new_stream(3)).
            if (conn != null) {
                conn.markStreamFreeFailed();
            }
            log.warn(sm.getString("quicEndpoint.streamSslFreeError",
                    Long.toHexString(streamSsl.address())), t);
        }
    }


    /**
     * Cleans up a stream that failed during {@link #processAcceptedStream()}.
     * The wrapper may be null (construction failed), already tracked, or only
     * partially registered. The active-stream count is rolled back when the
     * map put failed after the increment.
     *
     * @param stream        The wrapper, or {@code null}
     * @param streamSsl     The native stream SSL
     * @param conn          The owning connection
     * @param state         The protocol connection state, or {@code null}
     * @param streamId      The stream ID
     * @param streamCounted Whether {@code incrementActiveStreams()} completed
     */
    private void cleanupPartiallyAcceptedStream(QuicStreamWrapper stream,
            MemorySegment streamSsl, QuicConnectionWrapper conn,
            QuicConnectionManager.ConnectionState state, long streamId,
            boolean streamCounted) {
        if (stream == null) {
            freeUnregisteredStreamSsl(streamSsl, conn);
            return;
        }
        boolean nowTracked = conn.getStreams().containsKey(Long.valueOf(streamId));
        if (streamCounted && !nowTracked && state != null) {
            // The map put did not happen, so deregisterAndReleaseStream() in
            // cleanupAcceptedStream() cannot perform the matching decrement.
            state.decrementActiveStreams();
        }
        cleanupAcceptedStream(stream);
    }


    /**
     * Resets and immediately frees an accepted stream that exceeds the
     * concurrent-stream limit. This deliberately avoids allocating the full
     * read buffer and poll item used by accepted streams: the stream is never
     * tracked, read or dispatched, so only the native SSL reset/free and the
     * protocol abandonment bookkeeping are needed.
     *
     * @param streamSsl  The native stream SSL
     * @param streamId   The stream ID
     * @param conn       The connection
     * @param connManager The connection protocol manager
     * @param state      The protocol connection state
     */
    private void rejectAcceptedStream(MemorySegment streamSsl, long streamId,
            QuicConnectionWrapper conn, QuicConnectionManager connManager,
            QuicConnectionManager.ConnectionState state) {
        QuicStreamWrapper stream = null;
        try {
            stream = new QuicStreamWrapper(
                    streamSsl, streamId, QuicPoll.SSL_STREAM_TYPE_BIDI, conn,
                    ByteBuffer.allocate(0));
            try {
                long now = System.currentTimeMillis();
                long count = ++streamLimitWarnCount;
                if (now - lastStreamLimitWarnLogMs >= STREAM_LIMIT_LOG_INTERVAL_MS) {
                    lastStreamLimitWarnLogMs = now;
                    log.warn(sm.getString("quicEndpoint.streamLimitReached",
                            Long.toHexString(conn.getSslAddress()),
                            Long.valueOf(streamId), Long.valueOf(count)));
                }
                // A single GOAWAY announces that the peer must stop opening
                // streams; successive identifiers may not increase, so repeated
                // refusals must not append duplicate frames.
                if (!conn.isStreamLimitGoawaySent() &&
                        sendStreamLimitNotification(connManager, state)) {
                    conn.setStreamLimitGoawaySent(true);
                }
                // Tell the peer why this stream is refused before freeing it.
                // Freeing without a prior reset makes OpenSSL emit a spurious
                // error-0 RESET_STREAM instead of the intended code.
                resetStream(stream, getStreamRejectErrorCode());
                // The refused stream is deliberately not tracked in the
                // connection's stream map. Free its SSL before handing the
                // rejection to the protocol: noteStreamRejected() can fail the
                // connection inline, and an untracked stream SSL must not outlive
                // the connection SSL.
                stream.setDeregistered();
                boolean freed = false;
                try {
                    freed = stream.freeSslIfIdle();
                } catch (Throwable t) {
                    log.warn(sm.getString("quicEndpoint.streamSslFreeError",
                            Long.toHexString(stream.getSslAddress())), t);
                }
                if (freed) {
                    connManager.noteStreamRejected(conn, streamId);
                } else if (log.isDebugEnabled()) {
                    log.debug("Rejected stream " + streamId
                            + " is still-owned; deferring its SSL free");
                }
            } finally {
                // Remove the never-promoted wrapper bookkeeping. The free above
                // (or its deferred worker free) is already CAS-guarded.
                closeStreamByHandler(stream);
            }
        } catch (Error e) {
            cleanupRejectedStream(stream, streamSsl, conn);
            ExceptionUtils.handleThrowable(e);
            throw e;
        } catch (Exception e) {
            cleanupRejectedStream(stream, streamSsl, conn);
            throw e;
        }
    }


    /**
     * Releases a refused stream after a failure while rejecting it. If the
     * wrapper was not constructed, the SSL is untracked and must be freed
     * directly; otherwise the normal cleanup path deregisters and frees it.
     *
     * @param stream    The wrapper, or {@code null}
     * @param streamSsl The native stream SSL
     * @param conn      The owning connection
     */
    private void cleanupRejectedStream(QuicStreamWrapper stream,
            MemorySegment streamSsl, QuicConnectionWrapper conn) {
        if (stream == null) {
            freeUnregisteredStreamSsl(streamSsl, conn);
        } else {
            cleanupAcceptedStream(stream);
        }
    }


    /**
     * Best-effort removal/release of a partially processed accepted stream.
     * Called when {@link #processAcceptedStream} fails before returning.
     *
     * @param stream The partially registered stream
     */
    private void cleanupAcceptedStream(QuicStreamWrapper stream) {
        try {
            deregisterAndReleaseStream(stream);
        } catch (Throwable t) {
            log.warn(sm.getString("quicEndpoint.streamSslFreeError",
                    Long.toHexString(stream.getSslAddress())), t);
        }
        try {
            if (!stream.isFreed()) {
                stream.setDeregistered();
                stream.freeSslIfIdle();
            }
        } catch (Throwable t) {
            log.warn(sm.getString("quicEndpoint.streamSslFreeError",
                    Long.toHexString(stream.getSslAddress())), t);
        }
    }


    /**
     * Reads data from an incoming unidirectional stream (client control, QPACK).
     * Reference: app_read_cb reads from the stream and processes the data.
     * Data is passed to QuicConnectionManager for control stream processing.
     */
    private void readUnidirectionalStream(QuicStreamWrapper stream, QuicPollItem item)
            throws IOException {
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
            // A FINISHED stream can never deliver another byte. Retained
            // bytes are a truncated frame/instruction for an identified
            // control/QPACK stream; checkClientUniStreamClosed() has already
            // failed the connection for those cases. An unfinished stream
            // type is tolerated per RFC 9114 Section 6.2 and is closed here.
            // Never re-arm R: OpenSSL reports R unconditionally once the FIN
            // has been read, so a re-armed R would spin until the connection
            // is torn down.
            if (isStreamLive(stream)) {
                closeStream(stream, true);
            }
            return;
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
        // A client uni stream starts with a small buffer while its type is
        // unknown. Once identified as a control/QPACK stream it needs the
        // configured re-assembly window before the protocol inspects a full
        // buffer: the protocol treats that window as the maximum frame or
        // instruction it will reassemble. Discarded unknown streams do not
        // need it and stay small.
        if (!connManager.isClientUniStreamDiscarded(conn, stream.getStreamId())
                && readBuf.capacity() < readBufferSize
                && readBuf.position() == readBuf.capacity()) {
            stream.growReadBuffer(readBufferSize);
            readBuf = stream.getReadBuffer();
        }
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

        // An unknown stream is now being discarded: release the full
        // re-assembly buffer it may have grown into while its type was still
        // unknown, so open unknown streams cost only the small initial
        // buffer each. The protocol consumed every byte above, so the buffer
        // is empty and can be replaced safely.
        if (connManager.isClientUniStreamDiscarded(conn, stream.getStreamId()) &&
                readBuf.position() == 0) {
            stream.shrinkReadBuffer(UNI_INITIAL_READ_BUFFER_SIZE);
        }

        if (error != null) {
            if (errorCode == 0) {
                // Unexpected throwable without an HTTP/3 code: use the same
                // protocol default as the quiche and ngtcp2 endpoints rather
                // than closing with application error code 0.
                errorCode = getDefaultStreamErrorCode();
            }
            failConnection(conn, errorCode,
                    "Protocol connection error on stream " + stream.getStreamId());
            return;
        }

        if (!flushProtocolData(conn, connManager)) {
            // The protocol flush failed and failed the connection inline; do
            // not touch its freed native state below.
            return;
        }
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
     * A stream that carried no complete type header (including a zero-byte or
     * partial-varint stream closed before its header) is tolerated and is not
     * a connection error, per RFC 9114 Section 6.2.
     *
     * @param stream The client unidirectional stream
     * @param conn The QUIC connection
     */
    private void checkClientUniStreamClosed(QuicStreamWrapper stream, QuicConnectionWrapper conn) {
        checkClientUniStreamClosed(stream, conn, false);
    }


    /**
     * Fails the connection if a client-initiated unidirectional stream was
     * closed, reset or lost through a poll failure. A poll failure closes the
     * stream even when its last observed read state was not terminal, so that
     * path passes {@code forceClosed}.
     *
     * @param stream      The client unidirectional stream
     * @param conn        The QUIC connection
     * @param forceClosed {@code true} to treat a non-terminal read state as a
     *                    close (a poll failure), {@code false} to check only
     *                    terminal FINISHED/reset states
     */
    private void checkClientUniStreamClosed(QuicStreamWrapper stream,
            QuicConnectionWrapper conn, boolean forceClosed) {
        if (stream.getStreamType() != QuicPoll.SSL_STREAM_TYPE_READ) {
            // Only client-initiated unidirectional streams are checked here.
            // A BIDI request-stream reset is a stream-level event.
            return;
        }
        QuicStream.ReadState readState = stream.getReadState();
        if (!forceClosed &&
                readState != QuicStream.ReadState.FINISHED &&
                readState != QuicStream.ReadState.RESET_REMOTE &&
                readState != QuicStream.ReadState.RESET_LOCAL) {
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
        ByteBuffer readBuf = stream.getReadBuffer();
        boolean partialRetained = readBuf != null && readBuf.position() > 0;
        long truncatedCode = connManager.getTruncatedClientUniStreamErrorCode(
                conn, stream.getStreamId(), partialRetained);
        long errorCode;
        String reason;
        if (truncatedCode != 0) {
            // RFC 9114 Section 7.1 / RFC 9204: a stream ending inside a frame
            // or QPACK instruction is a frame/QPACK stream error. An
            // unfinished stream type is tolerated per RFC 9114 Section 6.2
            // and yields no truncated error code.
            errorCode = truncatedCode;
            reason = "Truncated client unidirectional stream " +
                    stream.getStreamId();
        } else if (state.isCriticalClientUniStream(stream.getStreamId())) {
            errorCode = state.getClosedCriticalStreamErrorCode();
            reason = "Client closed critical unidirectional stream " +
                    stream.getStreamId();
        } else {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastCriticalStreamClosedLogMs >=
                SECURITY_WARNING_LOG_INTERVAL_MS) {
            lastCriticalStreamClosedLogMs = now;
            log.warn(sm.getString(truncatedCode != 0
                    ? "quicEndpoint.truncatedUniStream"
                    : "quicEndpoint.criticalStreamClosed",
                    Long.valueOf(stream.getStreamId())));
        }
        failConnection(conn, errorCode, reason);
    }


    /**
     * Accepts remaining pending unidirectional and bidirectional streams when
     * a peer-initiated connection close (EC) is being processed. The streams are
     * accepted so the transport queue drains. Client UNI streams are not
     * immediately pre-read by this path, but BIDI streams may still be promoted,
     * pre-read and dispatched by {@link #processAcceptedStream()} when the
     * server control stream already exists; they remain tracked so the ECD
     * teardown can reap them.
     */
    private void acceptPendingStreams(QuicPollItem connItem, QuicConnectionWrapper conn) throws Exception {
        // The EC path must apply the same ALPN gate as the normal accept
        // paths. Without it a client that negotiated no served protocol could
        // send request streams immediately followed by CONNECTION_CLOSE and
        // have them promoted and dispatched before the connection is rejected.
        if (!ensureServedProtocol(conn)) {
            return;
        }
        // The peer may have migrated before this closing-path accept; use the
        // current peer address for any wrapper created for these streams.
        refreshPeerAddress(conn);
        int[] accepted = acceptStreams(connItem.getSsl(),
                  QuicPoll.SSL_ACCEPT_STREAM_UNI, conn,
                  "acceptPendingStreams: accepted UNI", false);
        int uniAccepted = accepted[0];
        int bidiAccepted = accepted[1];
        accepted = acceptStreams(connItem.getSsl(),
                  QuicPoll.SSL_ACCEPT_STREAM_BIDI, conn,
                  "acceptPendingStreams: accepted BIDI", false);
        uniAccepted += accepted[0];
        bidiAccepted += accepted[1];
        if (uniAccepted + bidiAccepted > 0) {
            if (log.isDebugEnabled()) {
                log.debug("acceptPendingStreams: accepted " + uniAccepted +
                        " UNI + " + bidiAccepted + " BIDI stream(s)");
            }
        }
        // Reconcile after the accept pass so the accepted-stream counters
        // include the streams that consumed transport credit (see
        // applyTransportStreamLimits()).
        reconcileTransportStreamLimitsIfNeeded(conn);
        if (uniAccepted > 0) {
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

        // This endpoint never creates bidirectional streams, so OSB can never
        // be a useful outgoing-stream trigger. Mask it before doing any work:
        // the connection item's initial mask already excludes it, but an item
        // created by an older build or mutated elsewhere must not be able to
        // re-enter this handler forever while a server unidirectional stream
        // waits for credit.
        long events = connItem.getWantEvents();
        if ((events & QuicPoll.SSL_POLL_EVENT_OSB) != 0) {
            connItem.setWantEvents(events & ~QuicPoll.SSL_POLL_EVENT_OSB);
        }

        if (!ensureServedProtocol(conn)) {
            return;
        }

        reconcileTransportStreamLimitsIfNeeded(conn);

        // Create every server-initiated unidirectional stream the
        // application protocol currently requires (for HTTP/3: control/
        // SETTINGS, then the QPACK encoder/decoder streams after the
        // client's SETTINGS have been received). The protocol decides which
        // streams to create and what to write on them; the endpoint only
        // provides the stream-creation mechanics.
        createServerUniStreams(connItem, conn);

        if (!isConnectionLive(conn)) {
            // A protocol callback during stream creation failed the
            // connection inline; do not use the freed connection SSL.
            return;
        }

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
        QuicStreamWrapper stream = null;
        try {
            // Server-initiated streams are write-only. Allocate the per-stream
            // read buffer only when the observed stream type actually has a
            // read side; otherwise an HTTP/3 connection wastes 3 *
            // readBufferSize bytes on its control/QPACK streams.
            ByteBuffer readBuffer =
                    (streamType & QuicPoll.SSL_STREAM_TYPE_READ) != 0
                            ? ByteBuffer.allocate(readBufferSize)
                            : ByteBuffer.allocate(0);
            stream = new QuicStreamWrapper(
                    streamSsl, streamId, streamType, conn, readBuffer);
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
            QuicPollItem streamItem = new QuicPollItem(streamSsl, events, stream,
                    this::markPollInterestChanged);
            stream.setPollItem(streamItem);
            conn.getStreams().put(streamId, stream);
            pollSet.add(streamItem);
            streamPollItems.add(streamItem);
            lingerStreamPollItem(streamItem);
            return stream;
        } catch (RuntimeException | Error e) {
            if (stream == null) {
                freeUnregisteredStreamSsl(streamSsl, conn);
            } else {
                // The wrapper may have been put into serverUniStreams or the
                // stream map before the failure. cleanupAcceptedStream()
                // removes those entries, the poll item and the wrapper before
                // releasing the SSL, so no partially registered stream is
                // left behind.
                cleanupAcceptedStream(stream);
            }
            throw e;
        }
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
        // A promotion loop may continue after an inline dispatch failure tore
        // the connection down and freed its stream SSLs. Never touch a stream
        // whose connection is gone, or a stream that has already been
        // deregistered/freed.
        if (!isConnectionLive(stream.getConnection()) || stream.isFreed() ||
                stream.isDeregistered()) {
            return;
        }
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
        streamPollItems.add(streamItem);
        lingerStreamPollItem(streamItem);
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
        if (conn.getServerUniStream(0) == null) {
            // Streams accepted before the server control stream exists stay
            // parked. Promoting them here would dispatch requests before the
            // server has sent SETTINGS, contrary to the pending-stream
            // contract; creation of the control stream later re-enters this
            // method through createServerUniStreams().
            if (log.isDebugEnabled()) {
                log.debug("Server control stream not created yet; keeping " +
                        conn.getPendingStreams().size() + " stream(s) pending");
            }
            return;
        }
        int added = 0;
        for (QuicStreamWrapper stream : conn.getPendingStreams()) {
            if (!isConnectionLive(conn)) {
                // A dispatch performed by addPendingStreamToPollSet() for an
                // earlier stream failed the connection inline on the poll
                // thread. That teardown freed the remaining streams' SSLs but
                // cannot stop this CopyOnWriteArrayList snapshot from being
                // iterated, so stop before touching the next freed stream.
                break;
            }
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


    private void dispatchStreamEvent(QuicPollItem item, SocketEvent event)
            throws IOException {
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
        reconcileTransportStreamLimitsIfNeeded(conn);
        long streamId = stream.getStreamId();
        if (log.isDebugEnabled()) {
            log.debug("dispatchStreamEvent: streamId=" + streamId + " event=" + event + " type=" + stream.getStreamType());
        }

        QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(stream);

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
        // worker's reads. Claim the processing flag before touching the
        // buffer: checking isProcessing() and then prefetching was a TOCTOU
        // window in which an async dispatch could claim the stream and read
        // the same SocketBufferHandler concurrently. The claim is handed to
        // dispatchToExecutor() below.
        boolean prefetchClaimed = false;
        if (wrapper != null && event == SocketEvent.OPEN_READ &&
                !wrapper.hasReadWaiter()) {
            if (stream.compareAndSetProcessing(false, true)) {
                prefetchClaimed = true;
                try {
                    prefetchStreamData(wrapper, stream);
                } catch (IOException | RuntimeException | Error e) {
                    // The prefetch failed while owning the claim: release it
                    // so a claim waiter can still run and the connection
                    // teardown is not blocked by a phantom handler.
                    stream.clearProcessing();
                    wakeClaimWaiters(stream, conn);
                    throw e;
                }
            }
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
            // now that the stream is writable.
            if (stream.isPrimaryUniStream() && event == SocketEvent.OPEN_WRITE) {
                handleServerUniWriteResult(stream,
                        flushServerUniStreamWrite(stream, item));
                return;
            }
            // A send-only stream write blocked on SSL_ERROR_WANT_READ arms
            // read interest as its retry wake. Service that wake here too:
            // OPEN_WRITE is not the only event that can make a buffered
            // server-unidirectional write progress.
            if ((event == SocketEvent.OPEN_WRITE || event == SocketEvent.OPEN_READ) &&
                    stream.getStreamType() == QuicPoll.SSL_STREAM_TYPE_WRITE) {
                ByteBuffer writeBuf = stream.getWriteBuffer();
                if (writeBuf != null && writeBuf.hasRemaining()) {
                    handleServerUniWriteResult(stream,
                            flushServerUniStreamWrite(stream, item));
                } else {
                    // No buffered data: disarm W instead of letting a
                    // level-triggered writable event spin for a stream that
                    // has nothing to send.
                    item.setWantEvents(item.getWantEvents() &
                            ~QuicPoll.SSL_POLL_EVENT_W);
                }
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

        dispatchToExecutor(wrapper, stream, event, prefetchClaimed);
    }


    /**
     * Handles the outcome of a server-unidirectional stream write. A hard
     * write failure must not leave a level-triggered W interest armed: notify
     * the protocol (which may treat a critical control/QPACK stream as a
     * connection error) and close the stream if it is still live.
     *
     * @param stream The server unidirectional stream
     * @param result The write outcome
     */
    private void handleServerUniWriteResult(QuicStreamWrapper stream,
            UniStreamWriteResult result) {
        if (result != UniStreamWriteResult.FAILED || !isStreamLive(stream)) {
            return;
        }
        try {
            notifyServerUniStreamClosed(stream);
        } catch (Throwable t) {
            log.warn(sm.getString("quicEndpoint.streamErrorEventError"), t);
        }
        if (!isStreamLive(stream)) {
            return;
        }
        try {
            closeStream(stream, false);
        } catch (Throwable t) {
            log.warn(sm.getString("quicEndpoint.streamCloseAfterPollFailure"), t);
            // The normal close path may have failed before deregistering the
            // stream. Do not leave a live stream in the connection map with
            // its poll item removed: deregister and queue the deferred free,
            // then force the item out of the current poll set.
            try {
                deregisterStream(stream);
                mailbox.queueStreamDrain(stream);
            } catch (Throwable cleanupError) {
                log.warn(sm.getString("quicEndpoint.streamSslFreeError",
                        Long.toHexString(stream.getSslAddress())), cleanupError);
            }
            forceRemovePollItem(stream.getPollItem());
        }
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
            QuicStreamWrapper stream) throws IOException {
        SocketBufferHandler socketBufferHandler = wrapper.getSocketBufferHandler();
        if (socketBufferHandler == null) {
            // The wrapper was closed concurrently with this dispatch.
            return;
        }
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
        java.util.concurrent.Executor executor = conn != null ? getExecutor() : null;
        if (executor == null) {
            // No executor available (torn down by the shutdown, or a
            // connection-less stream). Never run the handler inline on the
            // poll thread: an application writer may hold the wrapper's write
            // lock while waiting for that same poll thread to service a native
            // hop, which would deadlock the endpoint. A stop-path drain on any
            // other thread would park the handler in a mailbox hop that
            // nothing services. Drop the dispatch the way a rejecting pool
            // does.
            log.warn(sm.getString("quicEndpoint.dispatchNoExecutor",
                    Long.valueOf(stream.getStreamId())));
            stream.clearProcessing();
            wakeClaimWaiters(stream, conn);
            if (conn != null) {
                // Queue any deferred stream SSL free and release the
                // scheduling active-handler reference before failing the
                // connection; the teardown drains pending stream frees before
                // freeing the connection SSL.
                finishStreamDispatch(stream, conn, true);
                if (!conn.isClosing() && !conn.isClosed()) {
                    failConnection(conn, getConnectionRejectErrorCode(),
                            "No executor available for the dispatch of stream " +
                                    Long.valueOf(stream.getStreamId()));
                }
            }
            return;
        } else {
            // The active-handler reference above is now held by a queued task.
            // The task and the stop path race on the queued record's claim:
            // only a task that never starts is balanced by the stop path.
            QuicConnectionWrapper.QueuedDispatch queuedDispatch =
                    conn.incrQueuedDispatch(stream);
            Runnable queued = () -> {
                if (!queuedDispatch.tryClaim()) {
                    // The stop path claimed the record first and already
                    // balanced this task; it must not run.
                    return;
                }
                conn.decrQueuedDispatch(queuedDispatch);
                dispatch.run();
            };
            try {
                executor.execute(queued);
            } catch (RuntimeException ree) {
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
                if (!queuedDispatch.tryClaim()) {
                    // The task already claimed the record: it either started
                    // (and owns the processing flag and active-handler
                    // accounting until its own finally block) or was already
                    // discarded by the stop path. This catch must not balance
                    // the same accounting a second time.
                    return;
                }
                conn.decrQueuedDispatch(queuedDispatch);
                stream.clearProcessing();
                wakeClaimWaiters(stream, conn);
                // Queue any deferred stream SSL free and release the
                // active-handler reference before failing the connection.
                // The teardown drains pending stream frees before the
                // connection SSL free, preserving SSL_new_stream(3) order.
                finishStreamDispatch(stream, conn, true);
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
     * {@code QuicSocketProcessor.doRun()}, {@code longRearm} {@code false};
     * that is the live async-completion/dispatch path, see that class'
     * comment).
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
        boolean rearmRead = false;
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
                boolean flushError = false;
                try {
                    wrapper.flushNonBlocking();
                } catch (IOException ioe) {
                    flushError = true;
                    log.debug(sm.getString("quicEndpoint.writeEventDispatchError"), ioe);
                    if (conn != null) {
                        try {
                            conn.failConnection(getDefaultStreamErrorCode(),
                                    "Pending write flush failed on stream " +
                                            stream.getStreamId());
                        } catch (Throwable t) {
                            log.warn(sm.getString(
                                    "quicEndpoint.connectionTeardownError"), t);
                        }
                    }
                }
                // Processor wants to keep the stream open for more I/O.
                // Remember to re-register read interest once the processing
                // flag is cleared below; registering it while the flag is
                // still set races the poll thread's R/W strip, which can drop
                // the R bit when it loses the processing claim.
                rearmRead = !flushError;
            }
        } finally {
            // Clear the processing flag BEFORE the connection's active handler
            // count is decremented: once this flag is clear, the poll thread
            // may tear the stream down, so no native operation may follow.
            stream.clearProcessing();
            wakeClaimWaiters(stream, conn);
            finishStreamDispatch(stream, conn, true);
            // Register read interest only after the processing flag is clear
            // and the dispatch accounting is complete. The poll thread then
            // observes both the idle stream and the armed interest, so the
            // readable data cannot be stripped in the gap between the two.
            // The interest registration is a poll-set mutation, not a native
            // stream operation; a teardown that raced this far has merely
            // disposed the item, and setting the interest on the disposed
            // item has no effect.
            if (rearmRead) {
                wrapper.registerReadInterest();
            }
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
            // Keep the stream SSL alive until its native write buffer has
            // drained. The stream may already be deregistered, but OpenSSL
            // can still hold response bytes accepted from SSL_write_ex2();
            // freeing the SSL now discards them.
            mailbox.queueStreamDrain(stream);
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
            DiscardablePollTask freeTask = new DiscardablePollTask() {
                @Override
                public void run() {
                    if (!conn.isFreed()) {
                        // The close frame queued by failConnection()/stop may
                        // still be pending: the teardown callback flushed it
                        // while the active handler's stream SSLs were still
                        // alive, which is not a reliable transmission point.
                        // Now that the last stream SSL has been drained above,
                        // drive the engine once more to flush the
                        // CONNECTION_CLOSE before freeing the connection SSL
                        // (otherwise SSL_free discards the frame).
                        mailbox.drainPendingStreamDrains(conn, false);
                        drainPendingStreamFrees();
                        drainCleanerStreamFrees();
                        drainCleanerConnectionFrees();
                        flushConnectionClose(conn);
                    }
                    if (!freeIdleStreams(conn)) {
                        // A stream SSL is still owned (or could not be freed);
                        // keep the connection retained so the per-stream
                        // ordering is never violated.
                        conn.setPendingFree();
                        stoppedBusyConnections.add(conn);
                        return;
                    }
                    boolean freed = conn.freeSslOnce() || conn.isFreed();
                    if (!freed) {
                        // A stream SSL free failed during the drains above;
                        // keep the connection retained (and re-claim the free)
                        // rather than dropping the only Java-side owner of the
                        // still-allocated native connection.
                        conn.setPendingFree();
                        stoppedBusyConnections.add(conn);
                        return;
                    }
                    synchronized (retainedCleanupLock) {
                        stoppedBusyConnections.remove(conn);
                        closeDeferredSocketsIfSafe();
                    }
                }

                @Override
                public void onDiscard() {
                    // The task was discarded by a mailbox close/open before it
                    // could run. Reclaim the retained connection here (the
                    // reclaim path is serialized and leaves it retained if a
                    // handler is still active) instead of waiting for the next
                    // start/unbind sweep.
                    reclaimRetainedConnection(conn, false);
                }
            };
            if (!submitPollTask(freeTask)) {
                boolean reclaimed = false;
                if (pollThread == null || !pollThread.isAlive()) {
                    // The endpoint has stopped and no poll task can run. The
                    // last handler has just completed, so reclaim the retained
                    // connection here (on this worker, serialized by
                    // retainedCleanupLock) rather than leaking it until a
                    // restart/destroy.
                    reclaimed = reclaimRetainedConnection(conn, false);
                }
                if (!reclaimed && log.isDebugEnabled()) {
                    log.debug("Connection SSL 0x" +
                            Long.toHexString(conn.getSslAddress()) +
                            " deferred free rejected (endpoint stopped);" +
                            " retained for a later start/unbind cleanup");
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

        if (wrapper.isClosed()) {
            // Terminal events are scheduled after the native stream SSLs are
            // freed, and an earlier OPEN_READ dispatch may have run the
            // handler to CLOSED and closed/released the wrapper in the
            // meantime. Never invoke handler.process() on a retired wrapper:
            // the stream has already been deregistered, no data can arrive,
            // and a second dispatch would duplicate release/onError handling.
            return state;
        }

        try {
            wrapper.checkError();
        } catch (IOException x) {
            event = SocketEvent.ERROR;
            wrapper.setError(x);
            // The wrapper error is often installed deliberately by the
            // transport itself (peer reset, clean connection close, poll
            // failure). Logging every such conversion at ERROR let a
            // client trigger one full stack trace per in-flight stream.
            // The handler still receives the ERROR event and the cause.
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicEndpoint.socketCheckError"), x);
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
     *
     * @return {@code true} if the notification was queued, {@code false} if
     *         it could not be queued and should be retried
     */
    private boolean sendStreamLimitNotification(QuicConnectionManager connManager,
            QuicConnectionManager.ConnectionState state) {
        QuicConnectionWrapper conn = (QuicConnectionWrapper) state.getConnection();
        if (!queueStreamLimitNotification(connManager, state)) {
            return false;
        }
        QuicStreamWrapper primaryStream = conn.getServerUniStream(0);
        UniStreamWriteResult writeResult =
                writeBufferedUniStream(conn.getSsl(), primaryStream);
        if (writeResult == UniStreamWriteResult.FAILED) {
            // The frame could not be queued on the primary stream. The
            // protocol is notified (a failed control stream is a connection
            // error for HTTP/3) and the stream is closed; the caller must not
            // mark the GOAWAY as sent.
            handleServerUniWriteResult(primaryStream, writeResult);
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Stream limit notification sent, lastStreamId=" +
                    state.getLastProcessedStreamId());
        }
        return true;
    }


    /**
     * Appends the protocol's stream-retirement (GOAWAY) frame to the primary
     * server unidirectional stream's write buffer without driving the engine.
     * Used by the shutdown batch path, which queues one frame per connection
     * and then lets the batched drain/flush pass drive the engine once.
     *
     * @param connManager The connection protocol manager
     * @param state       The connection state
     *
     * @return {@code true} if the frame was buffered
     */
    private boolean queueStreamLimitNotification(QuicConnectionManager connManager,
            QuicConnectionManager.ConnectionState state) {
        try {
            QuicConnectionWrapper conn = (QuicConnectionWrapper) state.getConnection();
            QuicStreamWrapper primaryStream = conn.getServerUniStream(0);
            if (primaryStream == null) {
                return false;
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
            // already pending, preserving wire order).
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
            return true;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            if (log.isDebugEnabled()) {
                log.debug("Error queuing stream limit notification", t);
            }
            return false;
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
     * the two paths classify a failed {@code SSL_write_ex2()} identically (both
     * go through {@code writeStreamData()}).
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
                long now = System.currentTimeMillis();
                if (now - lastServerUniWriteLogMs >=
                        SECURITY_WARNING_LOG_INTERVAL_MS) {
                    lastServerUniWriteLogMs = now;
                    log.warn(sm.getString("quicEndpoint.serverUniStreamWriteFailed",
                            Integer.valueOf(sslError)) +
                            " errors=" + QuicDiagnostics.dumpErrorQueue());
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Server unidirectional stream write failed, sslError=" +
                                sslError);
                    }
                    // Clear the ERR ring even when the warning is suppressed,
                    // so a client-triggered failure cannot overwrite the root
                    // cause before the next diagnostic dump.
                    QuicDiagnostics.clearErrorQueue();
                }
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
     * same interests. If the loop runs out of attempts the bytes stay buffered
     * and the W interest (armed when the stream was registered) lets the
     * W-event flush pick the retry up. A non-retryable failure is returned to
     * the caller so it can notify the protocol and close the stream: the W
     * event is not re-raised for a stream whose send part is already closed.
     *
     * @return the outcome of the final write attempt
     */
    private UniStreamWriteResult writeBufferedUniStream(MemorySegment connSsl,
            QuicStreamWrapper uniStream) {
        QuicPollItem item = uniStream.getPollItem();
        if (item == null) {
            // Should not happen: server unidirectional streams are registered
            // (poll item and W interest included) before their data is
            // buffered.
            return UniStreamWriteResult.FAILED;
        }
        // Retry with more attempts since handshake may still be completing
        for (int retry = 0; retry < STREAM_WRITE_RETRY_ATTEMPTS; retry++) {
            if (!isStreamLive(uniStream)) {
                return UniStreamWriteResult.FAILED;
            }
            pumpEvents(connSsl);
            UniStreamWriteResult result = flushServerUniStreamWrite(uniStream, item);
            if (result != UniStreamWriteResult.RETRY) {
                return result;
            }
        }
        return UniStreamWriteResult.RETRY;
    }


    /**
     * Sets a terminal error on a stream's socket wrapper if it does not
     * already carry a more specific one. The container uses
     * {@code SocketWrapper.getError()} to populate the async error cause and
     * the ERROR_EXCEPTION request attribute; without it an ERROR dispatch
     * reports no cause (the read-reset path already sets one explicitly).
     *
     * @param stream     The stream
     * @param messageKey The message key for the error text
     */
    private void setStreamErrorIfAbsent(QuicStreamWrapper stream,
            String messageKey) {
        QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(stream);
        if (wrapper != null && wrapper.getError() == null) {
            wrapper.setError(new IOException(sm.getString(messageKey,
                    Long.valueOf(stream.getStreamId()))));
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
            if (stream.getStreamType() == QuicPoll.SSL_STREAM_TYPE_WRITE) {
                // A server-initiated unidirectional stream reached a
                // terminal/error state (for example the peer sent
                // STOP_SENDING). The protocol must classify its own critical
                // streams (HTTP/3 control and QPACK streams) before the
                // connection can continue.
                notifyServerUniStreamClosed(stream);
                // The protocol callback may fail the connection inline and
                // tear the stream down. Re-check before touching the native
                // SSL object: a failed connection makes isStreamLive() false
                // and the stream SSL may already be freed.
                if (!isStreamLive(stream)) {
                    return;
                }
            }
            // Reference: handle_read_stream_state / handle_write_stream_state
            if ((revents & QuicPoll.SSL_POLL_EVENT_ER) != 0) {
                int nativeReadState = QuicBindings.SSL_get_stream_read_state(
                        stream.getSsl());
                stream.setReadState(QuicStreamWrapper.mapNativeState(nativeReadState));
                if (nativeReadState == QuicPoll.SSL_STREAM_STATE_FINISHED) {
                    // Remote peer concluded the stream. A FIN on a critical
                    // client-initiated unidirectional stream is still a
                    // connection error, even though it is a clean FIN.
                    if (stream.getStreamType() == QuicPoll.SSL_STREAM_TYPE_READ) {
                        QuicConnectionWrapper finishedConn = stream.getConnection();
                        if (finishedConn != null) {
                            checkClientUniStreamClosed(stream, finishedConn);
                            if (!isStreamLive(stream)) {
                                // The check failed the connection inline and
                                // the teardown claimed the stream.
                                return;
                            }
                        }
                    }
                    closeStream(stream, true);
                    return;
                }
                if (nativeReadState == QuicPoll.SSL_STREAM_STATE_RESET_LOCAL ||
                        nativeReadState == QuicPoll.SSL_STREAM_STATE_RESET_REMOTE) {
                    // A reset terminates the stream just like a FIN. If this
                    // is an identified critical client unidirectional stream
                    // (HTTP/3 control or QPACK), fail the connection with the
                    // protocol-specific closed/truncated stream error code.
                    // BIDI streams are request streams: a reset is a
                    // stream-level event, never a client-unidirectional-stream
                    // connection error.
                    if (stream.getStreamType() == QuicPoll.SSL_STREAM_TYPE_READ) {
                        QuicConnectionWrapper resetConn = stream.getConnection();
                        if (resetConn != null) {
                            checkClientUniStreamClosed(stream, resetConn);
                        }
                    }
                    // The stream was reset. Record the failure on the socket
                    // wrapper so the processor's error dispatch carries a
                    // throwable: the container's async error handling (and
                    // therefore ReadListener.onError with a meaningful
                    // cause) depends on it, as for a peer reset in the
                    // HTTP/2 or NIO transport paths.
                    QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(stream);
                    if (wrapper != null) {
                        wrapper.setError(new IOException(
                                sm.getString("quicEndpoint.streamResetByPeer",
                                        Long.valueOf(stream.getStreamId()))));
                    }
                    closeStream(stream, false);
                    return;
                }
                if (nativeReadState == QuicPoll.SSL_STREAM_STATE_CONN_CLOSED) {
                    setStreamErrorIfAbsent(stream,
                            "quicEndpoint.streamConnectionClosed");
                    closeStream(stream, false);
                    return;
                }
                // Stream read error but not in terminal state - reset the stream
                // with an error code to inform the peer (resetStream warns on
                // failure; the intended code being lost is logged there).
                setStreamErrorIfAbsent(stream, "quicEndpoint.streamReadError");
                resetStream(stream, getDefaultStreamErrorCode());
                closeStream(stream, false);
                return;
            } else if ((revents & QuicPoll.SSL_POLL_EVENT_EW) != 0) {
                int writeState = QuicBindings.SSL_get_stream_write_state(
                        stream.getSsl());
                setStreamErrorIfAbsent(stream, "quicEndpoint.streamWriteError");
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
     * Fails a connection after a hard stream write error that did not change
     * the stream write state. Runs as a poll task so the protocol write call
     * that observed the error can return before the stream/connection native
     * objects are torn down.
     *
     * @param conn     The connection
     * @param sslError The OpenSSL error code observed after the failed write
     */
    void failConnectionForStreamWriteError(QuicConnectionWrapper conn, int sslError) {
        failConnection(conn, getDefaultStreamErrorCode(),
                "Hard QUIC stream write error (SSL error " + sslError + ")");
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
        if (!isStreamLive(stream)) {
            return false;
        }
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
                    handleEvents(conn.getSsl(), "reset stream");
                }
            }
            // Flush the RESET_STREAM frame to the network immediately, while
            // we are still on the poll thread and the stream is not yet
            // freed, so it cannot be lost to a later free.
            if (conn != null && !conn.isFreed()) {
                handleEvents(conn.getSsl(), "reset stream flush");
            }
        }
        if (!resetDone) {
            // The reset never landed within the retry budget: the intended
            // error code is lost and OpenSSL will emit a spurious error-0
            // RESET_STREAM when the stream is later freed. Surface it so the
            // transport behavior can be diagnosed, but rate-limit it: a client
            // can trigger the failure repeatedly.
            long now = System.currentTimeMillis();
            if (now - lastStreamResetFailedLogMs >=
                    SECURITY_WARNING_LOG_INTERVAL_MS) {
                lastStreamResetFailedLogMs = now;
                log.warn(sm.getString("quicEndpoint.streamResetFailed",
                        Long.valueOf(stream.getStreamId()),
                        Long.valueOf(appErrorCode)));
            }
            // The retry loop can leave an ERR per failed attempt. Clear the
            // fixed-size ERR ring even when the warning is rate-limited.
            QuicDiagnostics.clearErrorQueue();
        } else {
            // A later attempt succeeded but earlier rejected attempts may
            // still have left entries queued; drain them so they cannot be
            // misattributed to a subsequent accept.
            QuicDiagnostics.clearErrorQueue();
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
        untrackStreamPollItem(stream);
        QuicConnectionWrapper conn = stream.getConnection();
        boolean wasTracked = false;
        if (conn != null) {
            wasTracked = conn.getStreams().remove(stream.getStreamId()) != null;
            conn.getPendingStreams().remove(stream);
            conn.removeServerUniStream(stream);
        }
        // Both maps are keyed by the raw native SSL address, which OpenSSL may
        // reuse after a stream SSL has been freed. Remove only the entries
        // that still belong to this stream; blindly removing whatever is
        // currently at the address would detach another, live stream (or, for
        // the poll set, an unrelated connection item) from the endpoint and
        // leave it silently unpolled.
        QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(stream);
        if (wrapper != null) {
            streamWrappers.remove(stream.getSslAddress(), wrapper);
            wrapper.clearWriteInterest();
        }
        QuicPollItem item = stream.getPollItem();
        try {
            QuicPollItem registered = (item == null) ? null
                    : pollSet.get(stream.getSslAddress());
            if (registered != null && registered == item) {
                pollSet.remove(stream.getSslAddress());
            } else if (item != null && !item.isDisposed()) {
                // The poll item was never promoted into the poll set (e.g. a
                // stream refused at the concurrent-stream limit, or one closed
                // before the server control stream was created), or the
                // address now belongs to a different SSL object. The poll set
                // only disposes items it removes, so release this stream's own
                // item here; closeAllStreams() does the same for un-promoted
                // items on connection teardown. dispose() is idempotent.
                item.dispose();
            }
        } finally {
            // QuicPollSet.remove() can throw during its shrink allocation
            // after the item has already been removed from the set. Mark the
            // stream deregistered whenever its item is provably not the one
            // registered for its address any more (the get() check also
            // covers a partial failure), so the close paths can queue its SSL
            // for deferred free instead of leaving an untracked live stream
            // behind. If the item is still in the poll set, leave deregistered
            // unset: freeing it now would leave a stale native pointer in
            // SSL_poll().
            QuicPollItem registered = (item == null) ? null
                    : pollSet.get(stream.getSslAddress());
            if (item == null || registered != item) {
                stream.setDeregistered();
            }
        }
        return wasTracked;
    }


    /*
     * Removes a stream from the connection and decrements the active
     * bidirectional stream count if the stream was tracked. Notifies the
     * protocol of the termination of a client-initiated unidirectional
     * stream so it can release any per-stream state it retained.
     * <p>
     * Protocol notifications must happen while the stream is still present
     * in the connection's stream map: a callback can fail the connection
     * inline, and the teardown must then see the stream and free (or defer
     * the free of) its SSL before freeing the connection SSL. Removing the
     * stream first would leave its native object untracked and let the
     * connection be freed underneath it (SSL_new_stream(3) requires every
     * stream SSL to be freed first).
     */
    private void deregisterAndReleaseStream(QuicStreamWrapper stream) {
        QuicConnectionWrapper conn = stream.getConnection();
        boolean wasTracked = conn != null &&
                conn.getStreams().containsKey(Long.valueOf(stream.getStreamId()));
        int streamType = stream.getStreamType();
        QuicConnectionManager.ConnectionState state = null;
        Throwable notificationFailure = null;
        if (conn != null) {
            QuicConnectionManager connManager = conn.getQuicConnectionManager();
            state = connManager == null ? null : connManager.getState(conn);
            if (state != null && wasTracked) {
                try {
                    if (streamType == QuicPoll.SSL_STREAM_TYPE_BIDI) {
                        if (stream.getReadState() == QuicStream.ReadState.RESET_REMOTE) {
                            // A peer reset abandons the request stream. If no
                            // processor observed the reset (for example the
                            // stream was reset before dispatch), the protocol
                            // still owes its encoder a QPACK Stream Cancellation
                            // (RFC 9204 Section 2.2.2.2). The callback may fail
                            // the connection inline; the stream is still tracked
                            // at this point, so the teardown handles the SSL
                            // ordering correctly.
                            connManager.noteStreamAbandoned(conn,
                                    stream.getStreamId());
                        }
                    } else if (streamType == QuicPoll.SSL_STREAM_TYPE_READ) {
                        // Client-initiated unidirectional stream terminated
                        // while the connection stays open: let the protocol drop
                        // any state it kept for the stream (for HTTP/3 the
                        // read-and-discard tracking of an unknown stream type,
                        // RFC 9114 Section 9). The notification is idempotent,
                        // so paths that deregister the same stream twice are
                        // harmless.
                        state.clientUniStreamClosed(stream.getStreamId());
                    }
                } catch (Throwable t) {
                    // A throwing notification must not abort the deregistration
                    // and active-stream accounting below. Non-fatal failures are
                    // logged; fatal VM errors are rethrown after cleanup.
                    notificationFailure = t;
                }
            }
        }
        try {
            deregisterStream(stream);
        } catch (RuntimeException | Error cleanupFailure) {
            if (stream.isDeregistered() && !stream.isFreed()) {
                // The stream was removed from the poll set but the shrink (or
                // another bookkeeping step) failed before the caller could
                // queue its SSL. The deregistered flag makes it invisible to
                // connection teardown, so queue the deferred free here rather
                // than leaking the native object.
                mailbox.queueStreamDrain(stream);
            }
            if (notificationFailure != null) {
                cleanupFailure.addSuppressed(notificationFailure);
            }
            throw cleanupFailure;
        } finally {
            if (conn != null && wasTracked && state != null &&
                    streamType == QuicPoll.SSL_STREAM_TYPE_BIDI) {
                // Decrement the active stream count exactly when it was
                // incremented for this tracked BIDI stream, regardless of
                // whether the protocol notification failed above.
                state.decrementActiveStreams();
            }
        }
        if (notificationFailure instanceof Error error) {
            throw error;
        } else if (notificationFailure != null) {
            log.warn(sm.getString("quicEndpoint.streamNotificationError",
                    Long.valueOf(stream.getStreamId())), notificationFailure);
        }
    }


    /**
     * Closes a stream after the HTTP handler requested the close
     * (SocketWrapperBase.close()). Unlike {@link #closeStream(QuicStreamWrapper,
     * boolean)} it does not notify the handler again.
     */
    void closeStreamByHandler(QuicStreamWrapper stream) {
        QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(stream);
        try {
            if (stream.isFreed() || stream.isDeregistered()) {
                // Terminal events are deliberately dispatched after the
                // connection teardown has freed the stream SSLs (see
                // handleConnectionClose()). The handler then returns CLOSED
                // and its wrapper.close() reaches this method on a dead
                // stream. Running the address-keyed deregistration again would
                // remove whichever live stream (or connection poll item) now
                // occupies the reused native address. The Java wrapper entry,
                // however, may still be this stream's own (for example a
                // rejected, never-registered stream); drop it only when the
                // map entry still belongs to this stream.
                if (wrapper != null) {
                    streamWrappers.remove(stream.getSslAddress(), wrapper);
                    wrapper.clearWriteInterest();
                }
            } else {
                deregisterAndReleaseStream(stream);
            }
        } finally {
            if (wrapper != null) {
                // Release any worker parked in a synchronous read or write on
                // this stream so it observes the terminal state instead of
                // waiting out the full stall timeout. Capture the wrapper
                // before deregistration removes it from streamWrappers.
                wrapper.signalReadWaiter();
                wrapper.signalWriteWaiter();
            }
            if (stream.isDeregistered() && !stream.isFreed()) {
                mailbox.queueStreamDrain(stream);
            }
        }
    }


    private void notifyServerUniStreamClosed(QuicStreamWrapper stream) {
        QuicConnectionWrapper conn = stream.getConnection();
        if (conn == null || conn.isClosed() || conn.isFreed() ||
                conn.isClosing()) {
            return;
        }
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null) {
            return;
        }
        long streamId = stream.getStreamId();
        if (streamId < 3 || (streamId & 3) != 3) {
            return;
        }
        long index = (streamId - 3) / 4;
        if (index > Integer.MAX_VALUE) {
            return;
        }
        connManager.serverUniStreamClosed(conn, (int) index);
    }


    private void closeStream(QuicStreamWrapper stream, boolean clean) {
        QuicConnectionWrapper conn = stream.getConnection();
        QuicOpenSSLSocketWrapper wrapper = getOwnedStreamWrapper(stream);
        // The stream is done: release any worker parked in a synchronous
        // read or write on it so it observes the terminal state (EOF /
        // reset) instead of waiting out the full stall timeout.
        if (wrapper != null) {
            wrapper.signalReadWaiter();
            wrapper.signalWriteWaiter();
        }
        deregisterAndReleaseStream(stream);

        if (conn != null && (conn.isClosed() || conn.isFreed())) {
            // A protocol callback above failed the connection inline and the
            // teardown already claimed this stream (it was still tracked when
            // the callback ran). Do not dispatch or queue native work for a
            // stream whose connection is gone; the teardown or the owning
            // handler owns the remaining cleanup.
            if (!conn.isFreed() && !conn.isTeardownStarted()) {
                // A provisional closed flag (QuicConnectionWrapper's
                // failConnection() hop timeout) is not proof that teardown
                // has claimed this stream: no teardown has started yet and
                // deregisterAndReleaseStream() just removed it from the
                // connection's stream map, so closeAllStreams() will never
                // see it. Queue the deferred free here rather than leaking a
                // live stream SSL under a connection that may then be freed.
                mailbox.queueStreamDrain(stream);
            }
            return;
        }

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
            if (wrapper != null) {
                // The worker owns the stream and will release the claim after
                // its handler returns. It has no way to know that this close
                // path discarded a terminal event, so park the terminal
                // dispatch behind the claim. Otherwise an asynchronous request
                // that is not performing I/O can wait forever for an
                // onError/onAllDataRead notification that never arrives.
                // allowDead is required because the stream is already
                // deregistered here; the dispatch itself only touches the Java
                // wrapper and is safe after the stream SSL has been freed.
                scheduleStreamDispatch(wrapper, stream,
                        clean ? SocketEvent.DISCONNECT : SocketEvent.ERROR, true);
            }
            return;
        }

        if (wrapper != null) {
            // Hand the claimed processing flag to the normal executor dispatch
            // instead of running handler.process() on the poll thread. The
            // poll thread must never acquire the wrapper's writeLock through
            // application handler code: an async writer may hold that lock
            // while waiting for this same poll thread to service its native
            // hop, which would deadlock the whole endpoint.
            // runStreamDispatch()/finishStreamDispatch() take over the claim
            // release, active-handler accounting and the deferred stream SSL
            // free.
            dispatchToExecutor(wrapper, stream,
                    clean ? SocketEvent.DISCONNECT : SocketEvent.ERROR, true);
            return;
        }

        stream.clearProcessing();
        wakeClaimWaiters(stream, conn);

        // Defer the native free until the next poll iteration, after
        // SSL_poll() has flushed any pending packets (for example a
        // RESET_STREAM requested just before this close) to the network.
        // freeSslOnce() is atomic with the Cleaner and runs unconditionally,
        // including while the owning connection is closing: a stream SSL
        // holds a reference on the connection and must be freed before the
        // connection SSL (SSL_new_stream(3)), which the teardown paths
        // preserve by draining the pending stream frees before freeing the
        // connection.
        mailbox.queueStreamDrain(stream);
    }


    // ------------------------------------- Socket Processor

    /*
     * Socket processor used for events that arrive through
     * {@link AbstractEndpoint#processSocket}. The poll loop's own dispatches
     * use {@code dispatchToExecutor()}, but async servlet completion,
     * dispatch, error and timeout events from {@code AbstractProcessor}
     * reach this class through
     * {@code SocketWrapperBase.processSocket()} ->
     * {@code AbstractEndpoint.processSocket()} ->
     * {@code createSocketProcessor()}. It is therefore a live dispatch path
     * and must keep the same claim, active-handler and requeue accounting as
     * the poll-path dispatch. (The quiche endpoint's own processor has the
     * same live role.)
     */
    private class QuicSocketProcessor extends SocketProcessorBase<QuicStream> {

        private QuicSocketProcessor(SocketWrapperBase<QuicStream> socket,
                SocketEvent event) {
            super(socket, event);
        }


        @Override
        protected void doRun() {
            QuicStreamWrapper stream = (QuicStreamWrapper) socketWrapper.getSocket();
            if (stream != null && (stream.isFreed() || stream.isDeregistered())) {
                // An async event was queued before the stream/connection was
                // torn down and this processor started only after the free.
                // Do not increment the handler count or invoke the handler on
                // destroyed stream/protocol state; return the processor to the
                // cache and drop the stale event.
                if (processorCache != null) {
                    processorCache.push(this);
                }
                return;
            }
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
                    if (stream.isFreed() || stream.isDeregistered()) {
                        // The stream passed the initial liveness check above,
                        // but a connection teardown (or a close path on the
                        // poll thread) freed/deregistered it before this
                        // worker won the processing claim. Re-check after the
                        // claim, while no poll-thread close path can run
                        // (the close paths take the same claim before
                        // freeing), and drop the event instead of invoking
                        // the handler on a released stream. The claim must be
                        // released and the accounting below balanced.
                        stream.clearProcessing();
                        wakeClaimWaiters(stream, conn);
                        if (conn != null) {
                            // The poll-thread close path deregistered the
                            // stream before this worker won the claim and
                            // deferred its SSL free to the claim owner. Since
                            // no handler will run for this dropped event, the
                            // worker must queue that free itself (the normal
                            // dispatch would do it in finishStreamDispatch).
                            mailbox.queueStreamDrain(stream);
                        }
                        claimed = false;
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

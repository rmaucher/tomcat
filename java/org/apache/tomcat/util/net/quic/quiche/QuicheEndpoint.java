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
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.ToLongFunction;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SocketEvent;
import org.apache.tomcat.util.net.SocketProcessorBase;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicEndpoint;
import org.apache.tomcat.util.net.quic.QuicNativeMailbox;
import org.apache.tomcat.util.net.quic.QuicProtocol;
import org.apache.tomcat.util.net.quic.QuicSSLContext;
import org.apache.tomcat.util.net.quic.QuicStream;
import org.apache.tomcat.util.res.StringManager;
import org.apache.tomcat.util.threads.LimitLatch;

/**
 * QUIC endpoint implementation using the Cloudflare quiche library via the
 * Java FFM (Panama) API - the transport backend selected by
 * {@code org.apache.coyote.http3.Http3QuicheProtocol}, serving the unchanged
 * HTTP/3 stack through the same
 * {@link QuicProtocol} / QuicConnection / QuicStream / QuicSocketWrapper
 * abstraction as {@code QuicOpenSSLEndpoint}.
 * <p>
 * The endpoint owns the UDP socket and all packet I/O: quiche has no
 * listener engine, so the single poll thread demultiplexes every datagram by
 * destination connection ID, feeds it to the right {@code quiche_conn}
 * ({@code quiche_accept()} for unknown Initials, {@code quiche_conn_recv()}
 * otherwise), drives each connection's timers ({@code on_timeout}) and
 * transmits its output ({@code quiche_conn_send()} until DONE, sent via
 * {@code sendmsg()} with the source address pinned from
 * {@code quiche_send_info}). Stream readiness is discovered by the
 * {@code stream_readable_next()} / {@code stream_writable_next()} sweeps
 * instead of an event poll set.
 * <p>
 * Threading follows the OpenSSL endpoint exactly: one poll thread owns every
 * {@code quiche_conn}; executor workers hop all native operations onto it
 * through {@link QuicNativeMailbox} ({@link #callOnPollThread} /
 * {@link #submitPollTask}) and are woken via {@link QuicWakeup}. All server
 * connection IDs are minted at a fixed 16-byte length so short-header
 * demuxing with a constant {@code dcil} is reliable.
 * <p>
 * Source connection IDs: quiche only emits NEW_CONNECTION_ID frames for
 * SCIDs the application supplies, so on accept the endpoint issues one
 * additional random source CID per connection (via
 * {@code quiche_conn_new_scid}, saturating quiche's default
 * {@code active_connection_id_limit=2}) and registers it in the demux map,
 * which lets a spec-compliant deliberate client migration (RFC 9000
 * Section 9.5) switch to a fresh destination CID. There is no CID rotation
 * or retirement yet; the OpenSSL backend issues more CIDs automatically,
 * which is library-internal behaviour there (OpenSSL's QUIC implementation
 * manages and retires source CIDs itself - see the OpenSSL QUIC docs -
 * no endpoint code supplies them on that side).
 */
public class QuicheEndpoint extends QuicEndpoint<Long> {

    private static final Log log = LogFactory.getLog(QuicheEndpoint.class);
    protected static final StringManager sm = StringManager.getManager(QuicheEndpoint.class);

    /**
     * The StringManager of the base endpoint class, used to access the
     * shared {@code endpoint.*} messages.
     */
    private static final StringManager baseSm = StringManager.getManager(AbstractEndpoint.class);

    private static final int DEFAULT_READ_BUFFER_SIZE = 16384;
    private static final int MIN_READ_BUFFER_SIZE = 1;

    private static final long DEFAULT_POLL_TIMEOUT_MS = 10;
    private static final long MIN_POLL_TIMEOUT_MS = 1;
    private static final long MAX_POLL_TIMEOUT_MS = 60_000;
    // Upper bound on any single wait: bounds shutdown responsiveness even
    // without a wake kick (the stop path always kicks, this is the fallback).
    private static final long WAIT_CAP_MS = 1000;
    // Cadence of the safety-net scan reclaiming connections closed JVM-side
    // without a mailbox hop (see scanClosedForTeardown). Every real close
    // path hops or kicks, so this only bounds a future path that forgets
    // both; a second is plenty for a reclaim that is otherwise immediate.
    private static final long CLOSED_SCAN_INTERVAL_MS = 1000;
    // Timer heap stale-entry backlog floor before a rebuild: the heap may
    // hold four times the live fleet plus this many re-stamped entries
    // before the wrapper-cached deadlines are used to rebuild it.
    private static final int HEAP_STALE_FLOOR = 256;
    private static final long PENDING_TASK_POLL_TIMEOUT_MS = 10;
    // Idle cadence: no connections and no queued work. An incoming packet
    // wakes the socket fd immediately, so this only bounds timer-less wake
    // checks; keep it low enough to bound stop latency.
    private static final long IDLE_POLL_TIMEOUT_MS = 100;

    private static final int DEFAULT_MAX_CONNECTIONS = 8192;
    private static final int PENDING_LIMIT_FLOOR = 1024;

    /** Length of every server-minted connection ID (see class doc). */
    private static final int SERVER_CID_LEN = 16;

    /** Stateless-reset token byte length read by quiche_conn_new_scid. */
    private static final int RESET_TOKEN_LEN = 16;

    /** Maximum datagrams read per poll-loop iteration (fairness bound). */
    private static final int RECV_BUDGET = 64;

    /**
     * Messages taken per recvmmsg call. Each slot carries its own data
     * buffer (full size, because GRO coalescing happens inside the kernel
     * before the read lands in a slot), so the count trades syscalls
     * against buffer memory; eight covers the queue depth a busy poll
     * iteration typically finds at half a megabyte per endpoint thread.
     */
    private static final int RECV_BATCH = 8;
    /** Maximum sweep iterator steps per connection per iteration. */
    private static final int SWEEP_BUDGET = 256;

    private static final int MAX_DATAGRAM_SIZE = 65536;
    private static final int SEND_BUFFER_SIZE = 1500;

    /**
     * Packets staged for one segmented (GSO) sendmsg; the staging region
     * carries one extra slot so a destination change mid-collection parks
     * the odd packet for the next batch head instead of losing it.
     */
    private static final int GSO_MAX_BATCH = QuicheBindings.GSO_MAX_BATCH;

    /**
     * Smallest datagram a client-initiated connection may specify, per
     * RFC 9000 Section 5.2.2 ("an Initial packet ... MUST be padded to at
     * least 1200 bytes"; "a server MUST drop smaller packets that specify
     * unsupported versions"). Used as the size gate for Version Negotiation
     * replies so the server never answers an undersized datagram.
     */
    private static final int MIN_CLIENT_DATAGRAM_SIZE = 1200;

    /**
     * Layout for reading the wire (big-endian) version field of a long
     * header at datagram offset 1.
     */
    private static final ValueLayout.OfInt VERSION_FIELD =
            ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.BIG_ENDIAN);

    /**
     * Error code with which a connection whose negotiated ALPN protocol is
     * not served is closed: the TLS {@code no_application_protocol} alert
     * (120) prefixed with {@code 0x100} (RFC 9001 Section 4.8/8.1).
     */
    private static final long NO_APPLICATION_PROTOCOL_ERROR = 0x100 + 120;

    private static final long GRACEFUL_SHUTDOWN_DRAIN_MS = 500;
    private static final long ACTIVE_HANDLER_SHUTDOWN_WAIT_MS = 1000;
    private static final int READ_DRAIN_MAX_ATTEMPTS = 20;
    /**
     * Bound on the drain/process rounds one
     * {@link #readUnidirectionalStream} call performs, mirroring the
     * {@link #READ_DRAIN_MAX_ATTEMPTS} bound of the bidirectional drain.
     * A stream still readable level-wise when the budget runs out is handed
     * to the connection's pending uni-stream drain set so a later sweep
     * continues the drain.
     */
    private static final int UNI_DRAIN_MAX_ROUNDS = 20;
    private static final int STREAM_WRITE_RETRY_ATTEMPTS = 3;
    private static final long STREAM_CLAIM_BUDGET_MS = 500;
    private static final long POLL_TASK_HOP_TIMEOUT_MS = 30000;
    private static final long MAX_CONNECTIONS_LOG_INTERVAL_MS = 60_000;

    private static final boolean QUICHE_AVAILABLE = QuicheBindings.QUICHE_AVAILABLE;

    // ------------------------------------- Instance fields

    /**
     * The address this endpoint is bound to.
     */
    private volatile InetSocketAddress bindAddress;

    /**
     * Owns the TLS side of the endpoint: the {@code quiche_config}
     * generations, the ALPN list and the certificate reload lifecycle.
     */
    private final QuicheCertificateManager certManager =
            new QuicheCertificateManager(this::getQuicProtocol);

    /**
     * The certificate configuration generation staged for a reload swap.
     * A reload builds the new generation off the poll thread and stores it
     * here; the poll task that performs the swap claims it with
     * {@code getAndSet(null)} and {@link #stopInternal()} claims and frees
     * whatever the task never got to run (a task can be queued but then
     * discarded/stranded by a concurrent mailbox close, so the payload must
     * not live in the task closure - the claim is what guarantees the
     * generation is installed exactly once or freed exactly once).
     */
    private final AtomicReference<QuicheCertificateManager.Config> stagedCertConfig =
            new AtomicReference<>();

    /**
     * The native UDP socket file descriptor (created by libc socket()).
     */
    private int socketFd = -1;

    /**
     * Poll-loop scratch: shared arena (used by the poll thread and, after
     * the loop has stopped, by the stop thread's shutdown drain) holding all
     * native buffers the packet loop and the send/recv paths need.
     */
    private volatile Arena loopArena;
    private MemorySegment recvBuf;
    private MemorySegment sendBuf;
    private MemorySegment saFrom;
    private MemorySegment saTo;
    private MemorySegment saBind;
    private MemorySegment saSendFallback;
    private MemorySegment scratchRecv;
    private MemorySegment scratchSend;
    // recvmmsg batch slots (poll-thread confined; recvBatchVec stays null
    // when the symbol is unavailable and recvPass keeps reading one recvmsg
    // at a time). Every slot pointer is invariant, so the mmsghdr array is
    // filled once at bind and only msg_namelen/msg_controllen are re-armed
    // per call.
    private MemorySegment recvBatchVec;
    private MemorySegment recvBatchFrom;
    private MemorySegment recvBatchTo;
    private MemorySegment recvBatchToLen;
    private MemorySegment recvBatchCmsg;
    private MemorySegment[] recvBatchBuf;
    private MemorySegment recvInfo;
    private MemorySegment sendInfo;
    private MemorySegment hdrVersion;
    private MemorySegment hdrType;
    private MemorySegment hdrScid;
    private MemorySegment hdrScidLen;
    private MemorySegment hdrDcid;
    private MemorySegment hdrDcidLen;
    private MemorySegment hdrToken;
    private MemorySegment hdrTokenLen;
    private MemorySegment mintedScid;
    private MemorySegment toLenOut;
    private MemorySegment errCode;
    private MemorySegment finFlag;
    private MemorySegment extraScid;
    private MemorySegment scidResetToken;
    private MemorySegment scidSeqOut;
    /**
     * GSO send staging: {@code GSO_MAX_BATCH + 1} slots of SEND_BUFFER_SIZE
     * (the extra slot parks the packet whose destination ended a batch, so
     * it becomes the next batch's head without another quiche_conn_send), the
     * batch scratch for the segmented sendmsg, and the sockaddr storage the
     * pending-send drain re-sends through.
     */
    private MemorySegment batchSlots;
    private MemorySegment batchScratch;
    private MemorySegment sendInfoK;
    private MemorySegment drainTo;
    private MemorySegment drainFrom;
    /**
     * The datagram currently being delivered: recvBuf, or - while a GRO
     * coalesced read is being split - the slice holding the current segment.
     * Poll-thread confined.
     */
    private MemorySegment curPkt;
    /** Whether the receive socket has UDP_GRO enabled (probe-gated). */
    private boolean groReceive;
    /** groSegOut sink for recvDatagram (poll-thread confined). */
    private final int[] groSeg = new int[1];
    /** Per-slot lengths for the next segmented sendmsg. */
    private final int[] batchLens = new int[QuicheBindings.GSO_MAX_BATCH];

    /**
     * Established connections, keyed by the {@code quiche_conn} pointer
     * address.
     */
    private final ConcurrentHashMap<Long, QuicheConnectionWrapper> connections =
            new ConcurrentHashMap<>();

    /**
     * Accepted-but-not-yet-established connections, keyed by conn address.
     * Membership doubles as the "not yet accepted" marker: the first datagram
     * that finds {@code quiche_conn_is_established()} true promotes the
     * connection out of this map (and into {@link #connections}).
     */
    private final ConcurrentHashMap<Long, QuicheConnectionWrapper> pendingConns =
            new ConcurrentHashMap<>();

    /**
     * CID to connection demux map. Both the minted SCID and the client's
     * original DCID (ODCID) are registered for a pending connection so the
     * client's Initial retransmissions (which keep the ODCID until they see
     * the server's response) demux correctly.
     */
    private final ConcurrentHashMap<CidKey, QuicheConnectionWrapper> cidMap =
            new ConcurrentHashMap<>();

    /**
     * Socket wrappers: connection address to stream ID to wrapper.
     */
    private final ConcurrentHashMap<Long, ConcurrentHashMap<Long, QuicheSocketWrapper>>
            streamWrappers = new ConcurrentHashMap<>();

    /**
     * Connections a request handler still owned when {@link #stopInternal()}
     * released the rest of the endpoint. Their native connections are not
     * freed (a free under a running handler is a use-after-free); holding the
     * wrappers keeps their Cleaners from running too.
     * <p>
     * The list is not drained during the stop itself - that is deliberate,
     * not an oversight: reachability via this list is what holds the
     * Cleaner back while a handler may still touch the connection.
     * {@link #startInternal()} releases the entries whose handlers have
     * completed (freeing their native connections), so the list cannot
     * accumulate across stop/start cycles; entries whose handlers outlived
     * even that are reclaimed when the endpoint itself becomes unreachable
     * (an undeployed connector) and the Cleaner runs.
     */
    private final List<QuicheConnectionWrapper> stoppedBusyConnections =
            new ArrayList<>();

    /**
     * Poll loop thread. Published across threads (the reload/unbind guards
     * read it from lifecycle and JMX threads), so it must be volatile: a
     * stale {@code null} seen by {@link #reloadCertificates} while the poll
     * loop is live would take the off-thread direct-install branch and free a
     * config the poll thread is still using in {@code quiche_accept}.
     */
    private volatile Thread pollThread;

    /**
     * Single owner of the queue that crosses the poll-thread confinement
     * boundary. The confinement check it applies is the endpoint's own
     * {@link #assertNativeAccess(String)}.
     */
    private final QuicNativeMailbox mailbox =
            new QuicNativeMailbox(this::assertNativeAccess);

    /**
     * The poll thread's blocking wait primitive (UDP socket + mailbox kick
     * eventfd). Created in {@code bind()} once the UDP socket exists.
     */
    private volatile QuicWakeup quicWakeup;

    /**
     * Number of connections with protocol data (QPACK decoder instructions)
     * pending flush. The poll loop runs the protocol-data sweep only while
     * this is positive.
     */
    private final AtomicInteger protocolDataPendingCount = new AtomicInteger();

    /**
     * Poll-thread confined sweep gating state (idle cost scaling). quiche
     * connection state can only change through poll-thread actions: a
     * datagram delivered to the connection ({@link #sweepTouchedConns}), a
     * timer deadline expiring (the timer heap), a worker mailbox hop (named
     * via {@link #hopInterest}, or unattributed - which forces a full pass),
     * a queued protocol-data flush (full pass), a handshake still pending
     * ({@code pendingConns} is processed every pass that runs) or a deferred
     * dispatch replay ({@link #sweepRetryConns}). Iterations with none of
     * these skip the connection sweep entirely, so the poll loop's
     * per-iteration work is O(work), not O(live connections).
     */
    private final Set<QuicheConnectionWrapper> sweepTouchedConns = new HashSet<>();
    private final Set<QuicheConnectionWrapper> sweepRetryConns = new HashSet<>();
    private final Set<QuicheConnectionWrapper> sweepDueConns = new HashSet<>();
    private final Set<QuicheConnectionWrapper> sweepScratch = new HashSet<>();
    private final Set<QuicheConnectionWrapper> sweepHopConns = new HashSet<>();

    /**
     * Hop interest crossing the confinement boundary: every mailbox
     * submission marks the connection whose native state its task changes
     * (or {@link #HOP_UNKNOWN} when the submitting caller does not know one,
     * which conservatively forces a full pass). The poll loop consumes the
     * queue immediately before draining the mailbox, so every mark it sees
     * belongs to a task that drain executes and the sweep that follows sees
     * the task's effects.
     */
    private final ConcurrentLinkedQueue<Object> hopInterest =
            new java.util.concurrent.ConcurrentLinkedQueue<>();
    private static final Object HOP_UNKNOWN = new Object();

    /**
     * Timer deadline index: a min-heap of (absolute deadline, stamp,
     * connection) entries, one pushed every time a connection's
     * {@code quiche_conn_timeout_as_millis()} is re-read (see
     * {@link #refreshTimerDeadline}). Entries whose stamp no longer matches
     * the connection's current one are stale and dropped on pop without a
     * native call; the heap is rebuilt from the per-connection deadlines
     * when stale entries pile up. Replaces the per-iteration O(fleet)
     * earliest-timer scan and pinpoints which connections a timer wake must
     * service.
     */
    private final PriorityQueue<TimerEntry> timerHeap = new PriorityQueue<>(
            Comparator.comparingLong(e -> e.deadlineMs));

    /**
     * Absolute {@code System.currentTimeMillis()} of the last pass that
     * walked every connection (a full sweep, or a full teardown scan).
     * Bounds the reclaim latency of the JVM-side-closed safety scan to
     * {@link #WAIT_CAP_MS} even while the loop stays event-driven.
     */
    private long lastClosedScanMs;

    /**
     * Connection ID randomness (per-connection SCIDs).
     */
    private final SecureRandom cidRandom = new SecureRandom();

    private int maxConnections = DEFAULT_MAX_CONNECTIONS;
    private long lastMaxConnectionsLogMs = 0;
    private long lastPausedLogMs = 0;
    private long pollTimeoutMs = DEFAULT_POLL_TIMEOUT_MS;
    private int readBufferSize = DEFAULT_READ_BUFFER_SIZE;


    // ------------------------------------- Properties

    public int getMaxConnections() {
        return maxConnections;
    }

    public void setMaxConnections(int maxConnections) {
        // Deliberately no super.setMaxConnections() call: the base
        // implementation couples the limit to the connection-limit latch,
        // which the QUIC endpoints must never initialize (see
        // initializeConnectionLatch() below). The limit is enforced against
        // the connections/pending maps in the demux path and reported
        // through the getMaxConnections() override above.
        this.maxConnections = maxConnections;
    }

    /**
     * {@inheritDoc}
     * <p>
     * The QUIC endpoints never create the base-class connection-limit latch
     * (see {@link #initializeConnectionLatch()}), so the base implementation
     * would always report {@code -1}. Report the live count from the
     * connection maps instead: the same population the {@code maxConnections}
     * enforcement is measured against in the demux path.
     */
    @Override
    public long getConnectionCount() {
        return connections.size() + pendingConns.size();
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
     * JMX. Connection slots are enforced against the connections/pending
     * maps in the demux path instead, and the accurate live count is
     * reported by {@link #getConnectionCount()}.
     *
     * @return {@code null} always: connection counting through the latch is
     *         disabled for this endpoint
     */
    @Override
    protected LimitLatch initializeConnectionLatch() {
        return null;
    }

    public long getPollTimeoutMs() {
        return pollTimeoutMs;
    }

    public void setPollTimeoutMs(long pollTimeoutMs) {
        if (pollTimeoutMs < MIN_POLL_TIMEOUT_MS || pollTimeoutMs > MAX_POLL_TIMEOUT_MS) {
            log.warn(sm.getString("quicheEndpoint.pollTimeoutInvalid",
                    String.valueOf(pollTimeoutMs),
                    String.valueOf(MIN_POLL_TIMEOUT_MS),
                    String.valueOf(MAX_POLL_TIMEOUT_MS)));
            return;
        }
        this.pollTimeoutMs = pollTimeoutMs;
    }

    public int getReadBufferSize() {
        return readBufferSize;
    }

    public void setReadBufferSize(int readBufferSize) {
        if (readBufferSize < MIN_READ_BUFFER_SIZE) {
            log.warn(sm.getString("quicheEndpoint.readBufferSizeInvalid",
                    String.valueOf(readBufferSize),
                    String.valueOf(MIN_READ_BUFFER_SIZE),
                    String.valueOf(this.readBufferSize)));
            return;
        }
        this.readBufferSize = readBufferSize;
    }


    /**
     * Availability entry point, part of the convention any QUIC endpoint
     * implementation follows (used by the HTTP/3 test suite to decide
     * whether to skip). Mirrors
     * {@code QuicOpenSSLEndpoint.isAvailable()}.
     *
     * @return {@code true} if the quiche QUIC transport is usable
     */
    public static boolean isAvailable() {
        return QUICHE_AVAILABLE;
    }


    // ------------------------------------- AbstractEndpoint overrides

    @Override
    public void bind() throws Exception {
        if (!QUICHE_AVAILABLE) {
            throw new IllegalStateException(sm.getString("quicheEndpoint.quicNotAvailable"));
        }

        // QUIC mandates TLS (RFC 9001) and the config must exist before the
        // first connection can be created, so the SSL setup runs before the
        // UDP socket is created. Cleanup on failure is delegated to
        // unbind() (bindWithCleanup), like the OpenSSL endpoint.
        initialiseSsl();
        createUdpSocket();

        if (log.isInfoEnabled()) {
            log.info(sm.getString("quicheEndpoint.bind", getName(),
                    bindAddress != null ? bindAddress.toString() : "0.0.0.0:0",
                    String.valueOf(QuicheBindings.QUICHE_VERSION)));
        }
    }


    /**
     * Initialises the TLS side of the endpoint: validates the host
     * configuration (the quiche transport serves a single default host with
     * a single certificate) and builds the initial {@code quiche_config}.
     *
     * @throws Exception If the TLS setup failed
     */
    @Override
    public void initialiseSsl() throws Exception {
        if (!isSSLEnabled()) {
            throw new IllegalStateException(sm.getString("quicheEndpoint.tlsRequired"));
        }

        // Fail fast if no default SSLHostConfig is configured.
        getSSLHostConfig(null);

        // quiche's config is baked into the connection at accept time,
        // before the handshake, so the certificate cannot be selected from
        // the client's SNI.
        if (sslHostConfigs.size() > 1) {
            throw new IllegalStateException(sm.getString("quicheEndpoint.sniUnsupported"));
        }

        certManager.initialize(getSSLHostConfig(null));

        // Populate the JMX / Manager TLS information (protocols,
        // certificates) for every configured host via the base loop, which
        // calls the createSSLContext(SSLHostConfig) override below.
        super.initialiseSsl();
    }


    /**
     * Releases the native resources allocated by {@link #bind()} in reverse
     * order. Idempotent; also called when {@code bind()} fails (via
     * {@code unbind()}), so a partial bind is always reclaimed. The poll
     * thread is not running at this point.
     */
    private void releaseBindResources() {
        if (socketFd >= 0) {
            QuicheBindings.close(socketFd);
            socketFd = -1;
        }
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
        // Release the config generations last: a config is only referenced
        // by accepts (poll thread, stopped) and by connections' TLS material
        // through BoringSSL internal references that quiche_config_free
        // decrements safely once no accept can run.
        certManager.release();
        Arena arena = loopArena;
        if (arena != null) {
            loopArena = null;
            try {
                arena.close();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error closing QUIC loop arena during bind cleanup", t);
                }
            }
        }
    }


    /**
     * Creates the UDP socket, binds it and arms the packet-info socket
     * options (IP_PKTINFO / IPV6_RECVPKTINFO) the demux path needs for the
     * local address of every datagram. With no connector address configured
     * it binds the dual-stack wildcard ({@code ::} accepting IPv4 as well),
     * mirroring the NIO endpoints' default, and falls back to the IPv4
     * wildcard when the IPv6 family is unusable. Ported from the OpenSSL
     * endpoint's createUdpSocket() (no listener attachment).
     */
    private void createUdpSocket() throws Exception {
        int port = getPortWithOffset();
        // Port -1 (Tomcat's ephemeral convention) or 0 means "assign any free
        // port". Use port 0 so the OS assigns one, then resolve the actual
        // port after bind() (mirrors NioEndpoint).
        boolean ephemeralPort = port <= 0;
        if (ephemeralPort) {
            port = 0;
        }

        loopArena = Arena.ofShared();
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

            // Publish the FD as soon as it is bound so any later setup
            // failure releases it through releaseBindResources(). Failures
            // inside bindUdpSocket() are not published: that method releases
            // its fd before throwing.
            this.socketFd = sockFd;

            try {
                // Allocate the poll-loop scratch now the socket exists.
                allocateLoopScratch();

                // Wake primitive for the poll loop: the loop waits on this
                // socket together with an eventfd, and the mailbox kicks that
                // eventfd whenever another thread queues a poll task.
                quicWakeup = new QuicWakeup(sockFd);
                mailbox.setWaker(quicWakeup::kick);

                // Resolve the actually-assigned port for an ephemeral bind.
                int actualPort = port;
                if (ephemeralPort) {
                    MemorySegment nameAddr = localArena.allocate(
                            QuicheBindings.SOCKADDR_STORAGE_SIZE);
                    MemorySegment nameLen = localArena.allocate(ValueLayout.JAVA_INT);
                    nameLen.set(ValueLayout.JAVA_INT, 0,
                            QuicheBindings.SOCKADDR_STORAGE_SIZE);
                    if (QuicheBindings.getsockname(sockFd, nameAddr, nameLen) != 0) {
                        // Without the assigned port the endpoint would
                        // publish a port-0 bindAddress (wrong log/JMX value
                        // for a socket that is actually bound). There is no
                        // sane fallback for an ephemeral bind: fail the bind
                        // like the other socket setup errors do.
                        int errno = QuicheBindings.errno();
                        throw new IOException(sm.getString(
                                "quicheEndpoint.socketNameError",
                                QuicheBindings.strerror(errno),
                                String.valueOf(errno)));
                    }
                    actualPort = ((nameAddr.get(ValueLayout.JAVA_BYTE, 2) & 0xFF) << 8)
                            | (nameAddr.get(ValueLayout.JAVA_BYTE, 3) & 0xFF);
                }
                bindAddress = new InetSocketAddress(bindAddr, actualPort);
            } catch (Exception | Error e) {
                // Past the publish above, the fd is published: release it
                // (and un-publish, so releaseBindResources() does not close
                // a reused number).
                QuicheBindings.close(socketFd);
                socketFd = -1;
                Arena arena = loopArena;
                loopArena = null;
                if (arena != null) {
                    arena.close();
                }
                throw e;
            }
        }
    }


    /**
     * Creates a non-blocking UDP socket, arms the endpoint's socket options
     * on it and binds it to {@code bindAddr:port}. Every failure path closes
     * the fd before throwing, so the fd belongs to the caller only once this
     * method returns it.
     *
     * @param localArena  Arena for the bind/option scratch
     * @param bindAddr    The address to bind
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
        int af = isIPv6 ? QuicheBindings.AF_INET6 : QuicheBindings.AF_INET;
        int sockFd = QuicheBindings.socket(af,
                QuicheBindings.SOCK_DGRAM | QuicheBindings.SOCK_NONBLOCK, 0);
        if (sockFd < 0) {
            int errno = QuicheBindings.errno();
            if (dualStack && errno == QuicheBindings.EAFNOSUPPORT) {
                // No IPv6 stack at all (e.g. ipv6.disable=1): the IPv4
                // wildcard fallback covers this, it is not a bind failure.
                throw new DualStackUnavailable("socket(AF_INET6): "
                        + QuicheBindings.strerror(errno));
            }
            throw new IOException(sm.getString("quicheEndpoint.socketCreateError",
                    String.valueOf(errno)));
        }
        try {
            // Neither SO_REUSEADDR nor SO_REUSEPORT is set, deliberately.
            // SO_REUSEPORT would let independent processes share the port and
            // Linux would then split datagrams of one QUIC connection across
            // them (silently breaking connections). SO_REUSEADDR is omitted
            // too: for a UDP listener it buys nothing (there is no TIME_WAIT
            // to shorten, so a single listener restarts cleanly without it),
            // yet on Linux it relaxes the UDP bind-conflict rule to
            // last-binder-wins - a second local process that also sets the
            // flag can bind this endpoint's address and port and then receive
            // the unicast datagrams addressed to it, a same-host hijack.
            // Staying on the default keeps the single-binder guarantee.

            int rxBufSize = socketProperties.getRxBufSize();
            if (rxBufSize > 0) {
                MemorySegment v = localArena.allocate(ValueLayout.JAVA_INT);
                v.set(ValueLayout.JAVA_INT, 0, rxBufSize);
                setOption(sockFd, QuicheBindings.SOL_SOCKET, QuicheBindings.SO_RCVBUF,
                        v, "SO_RCVBUF");
            }
            int txBufSize = socketProperties.getTxBufSize();
            if (txBufSize > 0) {
                MemorySegment v = localArena.allocate(ValueLayout.JAVA_INT);
                v.set(ValueLayout.JAVA_INT, 0, txBufSize);
                setOption(sockFd, QuicheBindings.SOL_SOCKET, QuicheBindings.SO_SNDBUF,
                        v, "SO_SNDBUF");
            }

            if (isIPv6 && dualStack) {
                // Clear V6ONLY before the bind: an :: bind then also accepts
                // IPv4 (the NIO endpoints' dual-stack default). If the kernel
                // refuses it, this socket cannot give the wildcard candidate
                // its whole purpose - defer to the IPv4 wildcard instead.
                MemorySegment zero = localArena.allocate(ValueLayout.JAVA_INT);
                zero.set(ValueLayout.JAVA_INT, 0, 0);
                if (QuicheBindings.setsockopt(sockFd, QuicheBindings.IPPROTO_IPV6,
                        QuicheBindings.IPV6_V6ONLY, zero,
                        (int) zero.byteSize()) != 0) {
                    throw new DualStackUnavailable("IPV6_V6ONLY: "
                            + QuicheBindings.strerror(QuicheBindings.errno()));
                }
            }

            // Packet info: the receive path needs the local address of
            // every datagram (wildcard binds otherwise tell quiche
            // "0.0.0.0" for every path) and the send path pins the
            // source address from quiche_send_info via IP_PKTINFO cmsg.
            // On a dual-stack socket every datagram - IPv4 included -
            // arrives with an IPV6_PKTINFO cmsg carrying the (v4-mapped
            // where applicable) local address, and the send path picks
            // its cmsg per packet from the quiche-recorded family, so
            // the IPv6 option serves the whole mixed traffic.
            MemorySegment one = localArena.allocate(ValueLayout.JAVA_INT);
            one.set(ValueLayout.JAVA_INT, 0, 1);
            if (isIPv6) {
                setOption(sockFd, QuicheBindings.IPPROTO_IPV6,
                        QuicheBindings.IPV6_RECVPKTINFO, one, "IPV6_RECVPKTINFO");
            } else {
                setOption(sockFd, QuicheBindings.IPPROTO_IP,
                        QuicheBindings.IP_PKTINFO, one, "IP_PKTINFO");
            }

            // UDP_GRO: let GRO-delivered runs of same-size datagrams arrive
            // as single reads with a segment-size cmsg the recv pass splits
            // back into packets. Enabled only when the class-init probe
            // proved this kernel answers coalesced reads WITH that cmsg;
            // without the cmsg a merged read cannot be taken apart (quiche
            // wants one packet per quiche_conn_recv call), and the plain
            // socket then keeps receiving the kernel's own per-datagram
            // segmentation - the safe fallback, identical to pre-feature
            // behaviour.
            if (QuicheBindings.UDP_GRO_RECEIVE &&
                    QuicheBindings.setsockopt(sockFd, QuicheBindings.SOL_UDP,
                            QuicheBindings.UDP_GRO, one,
                            (int) one.byteSize()) == 0) {
                groReceive = true;
                if (log.isInfoEnabled()) {
                    log.info(sm.getString("quicheEndpoint.udpGroEnabled"));
                }
            }

            // Bind via a native sockaddr built from the Java address.
            MemorySegment sockaddr = localArena.allocate(QuicheBindings.SOCKADDR_STORAGE_SIZE);
            int addrlen = QuicheBindings.fillSockaddr(sockaddr,
                    new InetSocketAddress(bindAddr, port));

            int rc = QuicheBindings.bind(sockFd, sockaddr, addrlen);
            if (rc != 0) {
                int errno = QuicheBindings.errno();
                if (dualStack && (errno == QuicheBindings.EAFNOSUPPORT ||
                        errno == QuicheBindings.EADDRNOTAVAIL ||
                        errno == QuicheBindings.EPERM)) {
                    // The IPv6 family itself cannot carry the bind (disabled
                    // or refused): fall back to the IPv4 wildcard. A busy
                    // port (EADDRINUSE) or a permission problem (EACCES) is
                    // a real failure - it would sink the IPv4 attempt too.
                    throw new DualStackUnavailable("bind(::): "
                            + QuicheBindings.strerror(errno));
                }
                throw new IOException(sm.getString("quicheEndpoint.socketBindError",
                        QuicheBindings.strerror(errno), String.valueOf(errno)));
            }
            return sockFd;
        } catch (Exception | Error e) {
            // Nothing has seen this fd yet; releaseBindResources() cannot
            // reach it and the caller never receives it.
            QuicheBindings.close(sockFd);
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
        if (QuicheBindings.setsockopt(fd, level, opt, val, (int) val.byteSize()) != 0) {
            throw new IOException(sm.getString("quicheEndpoint.socketOptionError",
                    name, String.valueOf(QuicheBindings.errno())));
        }
    }


    /**
     * Allocates all poll-loop native scratch buffers from the (shared) loop
     * arena. Runs once, at bind, before the poll loop starts.
     */
    private void allocateLoopScratch() {
        Arena a = loopArena;
        recvBuf = a.allocate(MAX_DATAGRAM_SIZE);
        sendBuf = a.allocate(SEND_BUFFER_SIZE);
        saFrom = a.allocate(QuicheBindings.SOCKADDR_STORAGE_SIZE);
        saTo = a.allocate(QuicheBindings.SOCKADDR_STORAGE_SIZE);
        saBind = a.allocate(QuicheBindings.SOCKADDR_STORAGE_SIZE);
        saSendFallback = a.allocate(QuicheBindings.SOCKADDR_STORAGE_SIZE);
        scratchRecv = QuicheBindings.allocateScratch(a);
        scratchSend = QuicheBindings.allocateScratch(a);
        recvInfo = a.allocate(QuicheBindings.RECV_INFO_SIZE);
        sendInfo = a.allocate(QuicheBindings.SEND_INFO_SIZE);
        hdrVersion = a.allocate(ValueLayout.JAVA_INT);
        hdrType = a.allocate(ValueLayout.JAVA_BYTE);
        hdrScid = a.allocate(QuicheBindings.QUICHE_MAX_CONN_ID_LEN);
        hdrScidLen = a.allocate(ValueLayout.JAVA_LONG);
        hdrDcid = a.allocate(QuicheBindings.QUICHE_MAX_CONN_ID_LEN);
        hdrDcidLen = a.allocate(ValueLayout.JAVA_LONG);
        // Sized to the largest possible datagram: a header token can never
        // be longer than the packet carrying it, and quiche_header_info
        // fails the whole parse (returning -1 without reporting the needed
        // size) when the token does not fit the provided buffer. A smaller
        // buffer would silently drop Initials carrying larger address-
        // validation tokens, blackholing those clients.
        hdrToken = a.allocate(MAX_DATAGRAM_SIZE);
        hdrTokenLen = a.allocate(ValueLayout.JAVA_LONG);
        mintedScid = a.allocate(QuicheBindings.QUICHE_MAX_CONN_ID_LEN);
        toLenOut = a.allocate(ValueLayout.JAVA_INT);
        errCode = a.allocate(ValueLayout.JAVA_LONG);
        finFlag = a.allocate(ValueLayout.JAVA_BOOLEAN);
        extraScid = a.allocate(SERVER_CID_LEN);
        scidResetToken = a.allocate(RESET_TOKEN_LEN);
        scidSeqOut = a.allocate(ValueLayout.JAVA_LONG);
        batchSlots = a.allocate((long) (GSO_MAX_BATCH + 1) * SEND_BUFFER_SIZE);
        batchScratch = a.allocate(QuicheBindings.BATCH_SCRATCH_SIZE);
        sendInfoK = a.allocate(QuicheBindings.SEND_INFO_SIZE);
        drainTo = a.allocate(QuicheBindings.SOCKADDR_STORAGE_SIZE);
        drainFrom = a.allocate(QuicheBindings.SOCKADDR_STORAGE_SIZE);
        if (QuicheBindings.RECV_MMSG) {
            recvBatchVec = a.allocate((long) RECV_BATCH * QuicheBindings.MMSGHDR_SIZE);
            recvBatchFrom = a.allocate(
                    (long) RECV_BATCH * QuicheBindings.SOCKADDR_STORAGE_SIZE);
            recvBatchTo = a.allocate(
                    (long) RECV_BATCH * QuicheBindings.SOCKADDR_STORAGE_SIZE);
            recvBatchToLen = a.allocate(
                    (long) RECV_BATCH * ValueLayout.JAVA_INT.byteSize());
            recvBatchCmsg = a.allocate((long) RECV_BATCH * QuicheBindings.CMSG_SPACE);
            recvBatchBuf = new MemorySegment[RECV_BATCH];
            for (int i = 0; i < RECV_BATCH; i++) {
                recvBatchBuf[i] = a.allocate(MAX_DATAGRAM_SIZE);
            }
            // Fill the slot headers once: the kernel writes back name
            // length, control length, flags and msg_len, but reads only
            // name/iov/control pointers, which never change.
            for (int i = 0; i < RECV_BATCH; i++) {
                MemorySegment iov = a.allocate(QuicheBindings.IOVEC_LAYOUT.byteSize());
                iov.set(ValueLayout.ADDRESS, QuicheBindings.IOVEC_BASE, recvBatchBuf[i]);
                iov.set(ValueLayout.JAVA_LONG, QuicheBindings.IOVEC_LEN, MAX_DATAGRAM_SIZE);
                MemorySegment hdr = recvBatchVec.asSlice(
                        (long) i * QuicheBindings.MMSGHDR_SIZE, QuicheBindings.MMSGHDR_SIZE);
                hdr.set(ValueLayout.ADDRESS, QuicheBindings.MSGHDR_NAME,
                        recvBatchFrom.asSlice(
                                (long) i * QuicheBindings.SOCKADDR_STORAGE_SIZE,
                                QuicheBindings.SOCKADDR_STORAGE_SIZE));
                hdr.set(ValueLayout.JAVA_INT, QuicheBindings.MSGHDR_NAMELEN,
                        QuicheBindings.SOCKADDR_STORAGE_SIZE);
                hdr.set(ValueLayout.ADDRESS, QuicheBindings.MSGHDR_IOV, iov);
                hdr.set(ValueLayout.JAVA_LONG, QuicheBindings.MSGHDR_IOVLEN, 1);
                hdr.set(ValueLayout.ADDRESS, QuicheBindings.MSGHDR_CONTROL,
                        recvBatchCmsg.asSlice((long) i * QuicheBindings.CMSG_SPACE,
                                QuicheBindings.CMSG_SPACE));
                hdr.set(ValueLayout.JAVA_LONG, QuicheBindings.MSGHDR_CONTROLLEN,
                        QuicheBindings.CMSG_SPACE);
                hdr.set(ValueLayout.JAVA_INT, QuicheBindings.MSGHDR_FLAGS, 0);
            }
        }
        curPkt = recvBuf;
        // saBind (the recv_info.to fallback) stays zero-filled here: every
        // use re-fills it from the current local/bind address immediately
        // before use, and pre-filling at bind time would either run before
        // bindAddress exists or use a stale address on a rebind.
    }


    @Override
    public void startInternal() throws Exception {
        // A poll loop that survived stopInternal()'s bounded join still owns
        // the native state: it is running pollLoop() against the same socket
        // FD, loop-arena scratch buffers, wakeup and mailbox (stopInternal
        // logged and deliberately leaked them, and unbind() skipped releasing
        // them). Starting a second loop on top of it would interleave quiche
        // calls on that shared native state - the exact use-after-free the
        // native-access guard and the stoppedBusyConnections lifecycle exist
        // to prevent. Refuse the start rather than race it; a start attempt
        // once the leaked loop has terminated is allowed again (port of the
        // OpenSSL endpoint's guard).
        Thread oldPollThread = pollThread;
        if (oldPollThread != null && oldPollThread.isAlive()) {
            throw new IllegalStateException(sm.getString(
                    "quicheEndpoint.pollThreadStillRunning", getName()));
        }
        // Release the connections a previous generation's stop retained
        // because a handler still owned them: the retention exists only
        // while such a handler might still touch the native connection.
        // Once the handler count reached zero, nothing can reference the
        // connection any more, so free it and drop it from the list -
        // otherwise the wrappers and their native connections accumulate
        // across stop/start cycles for the endpoint's lifetime. Entries
        // with handlers still running stay on the list (a free under a
        // live handler would be a use-after-free). The liveness condition
        // is belt-and-braces: the guard above already refused the start
        // while the previous poll thread was alive to touch these
        // connections.
        if (pollThread == null || !pollThread.isAlive()) {
            Iterator<QuicheConnectionWrapper> iterator =
                    stoppedBusyConnections.iterator();
            while (iterator.hasNext()) {
                QuicheConnectionWrapper conn = iterator.next();
                if (conn.hasActiveHandlers()) {
                    continue;
                }
                // Balance the endpoint-wide protocol-data tally for this
                // retained connection: a handler that outlived the stop's
                // handler wait could still have marked it pending after the
                // stop loop cleared it, and its queued data can never be
                // flushed (stop already dropped the manager state).
                setConnectionProtocolDataPending(conn, false);
                conn.setClosed();
                try {
                    conn.freeConnOnce();
                } catch (Throwable t) {
                    log.warn(sm.getString("quicheEndpoint.connectionFreeError",
                            Long.toHexString(conn.getConnAddress())), t);
                }
                iterator.remove();
            }
        }
        // Re-open the mailbox and drop any task left over from a previous
        // generation's stop before the new poll thread can drain it.
        mailbox.open();
        if (getExecutor() == null) {
            createExecutor();
        }
        // A start clears any prior pause, as the other endpoints do.
        paused = false;
        running = true;
        // One poll thread, deliberately (same reasoning as the OpenSSL
        // endpoint: quiche connections are not thread-safe and all
        // per-connection work is serialized on this thread anyway).
        pollThread = new Thread(() -> {
            try {
                pollLoop();
            } catch (Throwable t) {
                log.error(sm.getString("quicheEndpoint.pollLoopCrashed"), t);
            }
        }, getName() + "-Poller");
        pollThread.setDaemon(true);
        pollThread.start();
        log.info(sm.getString("quicheEndpoint.started", getName()));
    }


    @Override
    public void stopInternal() throws Exception {
        running = false;

        if (pollThread != null) {
            pollThread.interrupt();
            // A thread blocked in the native poll(2) is not woken by
            // Thread.interrupt(): kick the wake eventfd so the loop
            // re-checks the stop flag on its next iteration.
            QuicWakeup wakeup = quicWakeup;
            if (wakeup != null) {
                wakeup.kick();
            }
            pollThread.join(5000);
            // If the poll thread is still alive it may be dereferencing the
            // native state; leak it (logged) instead of a use-after-free.
            if (pollThread.isAlive()) {
                log.warn(sm.getString("quicheEndpoint.pollThreadNotStopped"));
                return;
            }
        }

        // Run tasks that worker threads submitted but the poll thread did not
        // drain before stopping, so workers waiting on a hop complete.
        drainWhile(System.currentTimeMillis() + 5000, mailbox::hasPollTasks);

        // Graceful shutdown (RFC 9114 Section 5.2): GOAWAY, a bounded drain
        // so in-flight responses and GOAWAY frames reach the peers, then the
        // queued CONNECTION_CLOSEs (graceful error code) terminate the
        // connections explicitly. The poll loop is stopped, so this thread is
        // the only native caller while these run (worker operations arrive as
        // poll tasks drained here).
        notifyConnectionsGoingAway();
        drainConnectionsForShutdown();
        queueConnectionClosesForShutdown();

        // Wait for request handlers still running on executor workers,
        // keeping the workers' hop tasks serviced while waiting. This must
        // run before shutdownExecutor(): shutdownNow() interrupts the worker
        // threads that are executing those handlers, so waiting only after
        // the shutdown can never wait for them - the handlers would be cut
        // off after the graceful drain (500 ms) at the latest, dropping
        // their in-flight responses and surfacing the interrupt as a close
        // failure inside the transport. Handlers that outlive this budget
        // are interrupted by the executor shutdown below.
        drainWhile(System.currentTimeMillis() + ACTIVE_HANDLER_SHUTDOWN_WAIT_MS,
                this::hasActiveRequestHandlers);

        shutdownExecutor();

        // Give the handlers the executor shutdown just interrupted a short
        // window to unwind while their hop tasks keep being serviced, so
        // their close paths run against live native state rather than
        // stranding in-flight poll tasks.
        drainWhile(System.currentTimeMillis() + ACTIVE_HANDLER_SHUTDOWN_WAIT_MS,
                this::hasActiveRequestHandlers);

        // Clean up HTTP/3 connection managers.
        for (QuicheConnectionWrapper conn : connections.values()) {
            QuicConnectionManager connManager = conn.getQuicConnectionManager();
            conn.setQuicConnectionManager(null);
            if (connManager != null) {
                connManager.connectionClose(conn);
            }
        }

        // Release every connection. A connection a handler still owns is
        // retained (leaked) rather than freed under it - the same rule as the
        // OpenSSL endpoint's stoppedBusyConnections handling.
        for (QuicheConnectionWrapper conn : connections.values()) {
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
            if (conn.hasActiveHandlers()) {
                stoppedBusyConnections.add(conn);
                if (log.isDebugEnabled()) {
                    log.debug("Retaining connection 0x" +
                            Long.toHexString(conn.getConnAddress()) +
                            " still owned by a request handler at stop");
                }
                continue;
            }
            conn.closeAllStreams();
            conn.setClosed();
            try {
                conn.freeConnOnce();
            } catch (Throwable t) {
                log.warn(sm.getString("quicheEndpoint.connectionFreeError",
                        Long.toHexString(conn.getConnAddress())), t);
            }
        }
        for (QuicheConnectionWrapper conn : pendingConns.values()) {
            if (conn.hasActiveHandlers()) {
                // Unreachable today: a pending connection is never
                // dispatched to a handler (acceptConnection moves it into
                // the established map first, and only the established-side
                // sweeps dispatch). The guard makes the invariant local
                // rather than structural: should a future dispatch path
                // ever reach a pending connection while the mailbox is
                // still open, the same retain-don't-free rule as the
                // established loop above applies instead of freeing the
                // native connection under a running handler.
                stoppedBusyConnections.add(conn);
                if (log.isDebugEnabled()) {
                    log.debug("Retaining pending connection 0x" +
                            Long.toHexString(conn.getConnAddress()) +
                            " still owned by a request handler at stop");
                }
                continue;
            }
            conn.setClosed();
            try {
                conn.freeConnOnce();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error freeing pending connection at stop", t);
                }
            }
        }
        connections.clear();
        pendingConns.clear();
        cidMap.clear();
        streamWrappers.clear();
        // Poll-thread confined sweep state: the poll loop is stopped (the
        // guard at the top of this section refuses to proceed otherwise),
        // so clearing here races with nothing.
        sweepTouchedConns.clear();
        sweepRetryConns.clear();
        sweepDueConns.clear();
        sweepScratch.clear();
        sweepHopConns.clear();
        hopInterest.clear();
        timerHeap.clear();
        lastClosedScanMs = 0;

        // Close the mailbox now that every connection this generation owns
        // has been freed (or retained as stopped-busy): tasks submitted from
        // here on - e.g. by a request handler that outlived the bounded
        // handler wait - target freed native connections and must not linger
        // in the queue to be drained against them by the next start.
        mailbox.close();

        // A staged certificate reload generation whose install task was
        // discarded by the close (or never submitted) is still claimed here:
        // the mailbox is closed, so no task can claim it any more and this
        // stop generation owns it.
        QuicheCertificateManager.Config staged = stagedCertConfig.getAndSet(null);
        if (staged != null) {
            certManager.discardPrepared(staged);
        }

        if (log.isInfoEnabled()) {
            log.info(sm.getString("quicheEndpoint.stopped", getName()));
        }
    }


    /**
     * Announces the endpoint shutdown to every live connection by sending the
     * application protocol's stream retirement notification (GOAWAY for
     * HTTP/3) on its primary server unidirectional stream. Must run while the
     * connections are alive and no other thread touches them.
     */
    private void notifyConnectionsGoingAway() {
        for (QuicheConnectionWrapper conn : connections.values()) {
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
                // Push the GOAWAY (and any other buffered server-stream
                // data) onto the wire now. quiche_conn_close() discards
                // still-queued stream frames, so the notification must be
                // transmitted before queueConnectionClosesForShutdown()
                // closes the connection, or it never reaches the peer.
                if (!conn.isClosed() && !conn.isFreed()) {
                    flushSend(conn);
                }
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error announcing go-away on connection 0x" +
                            Long.toHexString(conn.getConnAddress()), t);
                }
            }
        }
    }


    /**
     * Bounded shutdown drain: keeps executing worker hop tasks and driving
     * each live connection (readable sweep, writable flush, send pass) until
     * the request handlers that were in flight when the endpoint stopped have
     * finished, or the budget is used up.
     */
    private void drainConnectionsForShutdown() {
        long deadline = System.currentTimeMillis() + GRACEFUL_SHUTDOWN_DRAIN_MS;
        while (hasActiveRequestHandlers() && System.currentTimeMillis() < deadline) {
            drainWhile(System.currentTimeMillis() + 50, mailbox::hasPollTasks);
            for (QuicheConnectionWrapper conn : connections.values()) {
                if (conn.isClosed() || conn.isFreed()) {
                    continue;
                }
                try {
                    sweepReadable(conn);
                    sweepWritable(conn);
                    flushSend(conn);
                } catch (Throwable t) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error driving connection during shutdown drain", t);
                    }
                }
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        drainWhile(System.currentTimeMillis() + 500, mailbox::hasPollTasks);
    }


    /**
     * Queues a CONNECTION_CLOSE (application protocol graceful-shutdown code)
     * on every live connection and transmits it.
     */
    private void queueConnectionClosesForShutdown() {
        long code = getGracefulShutdownErrorCode();
        for (QuicheConnectionWrapper conn : connections.values()) {
            try {
                if (!conn.isClosed() && !conn.isFreed()) {
                    queueConnectionClose(conn, code, "endpoint shutdown");
                }
                if (!conn.isFreed()) {
                    flushSend(conn);
                }
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error queuing connection close on shutdown", t);
                }
            }
        }
    }


    private boolean hasActiveRequestHandlers() {
        for (QuicheConnectionWrapper conn : connections.values()) {
            if (conn.hasActiveHandlers()) {
                return true;
            }
        }
        return false;
    }


    @Override
    public void unbind() throws Exception {
        // releaseBindResources() frees native objects the poll thread
        // dereferences; guard against a poll thread that could not be joined
        // (mirror of the stopInternal() guard).
        if (pollThread != null && pollThread.isAlive()) {
            log.warn(sm.getString("quicheEndpoint.pollThreadNotStopped"));
        } else {
            releaseBindResources();
        }
        super.unbind();
    }


    @Override
    protected void doCloseServerSocket() throws IOException {
        // No-op by design (same reasoning as the OpenSSL endpoint): closing
        // the shared listener socket here would black-hole the in-flight
        // connections that the graceful shutdown still waits for. The FD is
        // closed in releaseBindResources().
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
        throw new UnsupportedOperationException(sm.getString("quicheEndpoint.noTcpAccept"));
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
    protected SocketProcessorBase<QuicStream> createSocketProcessor(
            SocketWrapperBase<QuicStream> socket, SocketEvent event) {
        return new QuicSocketProcessor(socket, event);
    }


    @Override
    protected void startAcceptorThread() {
        // No-op - QUIC uses the packet loop instead of an acceptor thread.
    }


    @Override
    protected void destroySocket(Long socket) {
        // No-op. Stream teardown is owned by the QUIC close paths.
    }


    @Override
    protected void unlockAccept() {
        // No-op - QUIC does not use acceptor locking.
    }


    // ------------------------------------- Certificate lifecycle

    /**
     * The TLS 1.3 cipher suites the quiche native stack supports and has
     * enabled by default. QUIC mandates TLS 1.3 (RFC 9001) and the quiche C
     * API exposes neither the enabled-suite list nor the per-connection
     * negotiated suite (suite selection happens inside the native stack), so
     * the connector-level information consumers read from the
     * {@link SSLHostConfig} (the Manager application, JMX) reports this fixed
     * built-in set rather than nothing - a null there trips callers that
     * assume a configured connector reports a list.
     */
    private static final String[] DEFAULT_CIPHER_SUITES = {
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
    };


    /**
     * Logs the certificate configuration for the given host and records the
     * TLS information exposed via JMX. QUIC mandates TLS 1.3 (RFC 9001); the
     * enabled cipher suites are the fixed TLS 1.3 set the native stack
     * supports (see {@link #DEFAULT_CIPHER_SUITES}). Consumers that read the
     * certificate data through the certificate's SSLContext (the Manager
     * application, the certificate expiry checks) are served by a
     * {@link QuicSSLContext} reporting the Java-parsed chain. An
     * SSLContext provided directly (e.g. embedded) is left in place.
     */
    @Override
    protected void createSSLContext(SSLHostConfig sslHostConfig) throws IllegalArgumentException {
        sslHostConfig.setEnabledProtocols(new String[] { "TLSv1.3" });
        sslHostConfig.setEnabledCiphers(DEFAULT_CIPHER_SUITES);
        for (SSLHostConfigCertificate certificate : sslHostConfig.getCertificates()) {
            org.apache.tomcat.util.net.SSLContext sslContext = certificate.getSslContext();
            if (sslContext == null || sslContext instanceof QuicSSLContext) {
                certificate.setSslContext(new QuicSSLContext(
                        certManager.parseChain(certificate)));
            }
            logCertificate(certificate);
        }
    }


    @Override
    public void addSslHostConfig(SSLHostConfig sslHostConfig, boolean replace)
            throws IllegalArgumentException {
        if (!getDefaultSSLHostConfigName().equals(sslHostConfig.getHostName())) {
            // Per-SNI certificate selection is not supported by the quiche
            // transport.
            throw new IllegalArgumentException(sm.getString("quicheEndpoint.sniUnsupported"));
        }
        super.addSslHostConfig(sslHostConfig, replace);
        reloadCertificates("addSslHostConfig");
    }


    @Override
    public SSLHostConfig removeSslHostConfig(String hostName) {
        SSLHostConfig removed = super.removeSslHostConfig(hostName);
        if (removed != null) {
            reloadCertificates("removeSslHostConfig");
        }
        return removed;
    }


    /**
     * Re-registers every configured host and rebuilds the quiche
     * certificate configuration once. Note what "reload" means here (the
     * base class javadoc's "re-read the configuration files" is loose for
     * this transport): the base {@code addSslHostConfig(..., true)} only
     * re-runs {@link #createSSLContext()}, which for quiche re-parses the
     * configured PEM files, and the actual {@code quiche_config} rebuild
     * happens in the trailing {@link #reloadCertificates(String)}.
     */
    @Override
    public void reloadSslHostConfigs() {
        for (String hostName : sslHostConfigs.keySet()) {
            SSLHostConfig sslHostConfig = sslHostConfigs.get(hostName.toLowerCase(Locale.ENGLISH));
            if (sslHostConfig == null) {
                throw new IllegalArgumentException(
                        baseSm.getString("endpoint.unknownSslHostName", hostName));
            }
            super.addSslHostConfig(sslHostConfig, true);
        }
        reloadCertificates("reloadSslHostConfigs");
    }


    /**
     * Rebuilds the {@code quiche_config} from the current host
     * configuration and swaps it in. The (blocking) rebuild runs on the
     * calling thread; only the fast pointer swap is submitted to the poll
     * thread, where it is serialized with connection accepts - submitting
     * the build there would stall the packet loop on (slow) disk reads,
     * which the mailbox fast-task contract forbids. A failed rebuild keeps
     * the previous configuration.
     *
     * @param reason a short description of what triggered the reload
     */
    private void reloadCertificates(String reason) {
        if (!isSSLEnabled()) {
            return;
        }
        if (getBindState() == BindState.UNBOUND) {
            // Not bound yet; bind() will build the configuration.
            return;
        }
        SSLHostConfig sslHostConfig;
        try {
            sslHostConfig = getSSLHostConfig(null);
        } catch (IllegalStateException e) {
            // No host configuration left. Defense-in-depth only: the base
            // getSSLHostConfig signals an empty host map with
            // IllegalStateException, and the map cannot actually become
            // empty through this API - removeSslHostConfig refuses to
            // remove the default host and this transport rejects additional
            // hosts. Should a future change break that invariant, fail the
            // reload softly: the caller's removal has already taken effect,
            // failing it here too would report a failure after the fact,
            // and going without a config is not an option for live
            // connections. Keep serving the previous certificate generation
            // and say so.
            log.info(sm.getString("quicheEndpoint.noSslHostConfigReload", reason));
            return;
        }
        if (pollThread != null && pollThread.isAlive()) {
            QuicheCertificateManager.Config prepared;
            try {
                prepared = certManager.prepareConfig(sslHostConfig, reason);
            } catch (IOException e) {
                // prepareConfig already logged; keep the previous config.
                return;
            }
            // The install task claims the staged generation (it must not
            // capture it in the closure: a task can be queued and then
            // discarded by a concurrent mailbox close). A generation already
            // staged by a racing reload is superseded: no later claim can
            // see it (the staging getAndSet removed it), so it is safe to
            // free here.
            QuicheCertificateManager.Config superseded =
                    stagedCertConfig.getAndSet(prepared);
            if (superseded != null) {
                certManager.discardPrepared(superseded);
            }
            if (!submitPollTask(this::runStagedCertInstall)) {
                // The mailbox is closed (endpoint stopping): the swap will
                // never run. Claim the staged generation back (nobody else
                // can) and release it.
                QuicheCertificateManager.Config leftover = stagedCertConfig.getAndSet(null);
                if (leftover != null) {
                    certManager.discardPrepared(leftover);
                }
            }
        } else {
            // No running poll loop to serialize against.
            assertNativeAccess("swapCertConfig");
            try {
                certManager.installConfig(
                        certManager.prepareConfig(sslHostConfig, reason));
            } catch (IOException e) {
                // Keep the previous configuration.
            }
        }
    }


    /*
     * Poll-task half of a certificate reload: claim the staged generation and
     * install it. Runs on the poll thread (or the stop thread during a stop
     * drain), serialized with connection accepts. A concurrent stop may claim
     * and discard the staged generation instead; the AtomicReference claim
     * gives exactly one of the two paths the object.
     */
    private void runStagedCertInstall() {
        QuicheCertificateManager.Config prepared = stagedCertConfig.getAndSet(null);
        if (prepared != null) {
            certManager.installConfig(prepared);
        }
    }


    // ------------------------------------- Poll-thread confinement

    /**
     * Checks whether the current thread is the QUIC poll thread.
     */
    boolean isPollThread() {
        return Thread.currentThread() == pollThread;
    }


    /**
     * Debug-only guard for the endpoint's poll-thread confinement
     * discipline (same semantics as the OpenSSL endpoint's). Assertions are
     * compiled but only enforced with {@code -ea}.
     *
     * @param operation a short name for the guarded operation
     */
    private void assertNativeAccess(String operation) {
        assert isPollThread() || pollThread == null || !pollThread.isAlive()
                : "Native QUIC access (" + operation + ") reached off the poll thread from "
                        + Thread.currentThread().getName();
    }


    /**
     * Submits an unattributed task to be executed on the poll thread. The
     * task must be a single fast operation; it must never block. Every
     * submission kicks the wake primitive so a queued task is executed on
     * the next iteration. An unattributed submission conservatively forces
     * a full sweep pass (the caller cannot name the connection its task
     * touches); prefer {@link #submitConnPollTask}.
     */
    boolean submitPollTask(Runnable task) {
        hopInterest.add(HOP_UNKNOWN);
        return mailbox.submitPollTask(task);
    }


    /**
     * Submits a task whose native effects are confined to {@code conn} (a
     * {@code null} conn degenerates to the unattributed full-pass case).
     * The named connection is marked for sweeping in the iteration that
     * runs the task, keeping the sweep targeted instead of fleet-wide.
     */
    boolean submitConnPollTask(QuicheConnectionWrapper conn, Runnable task) {
        // Submit the task first, then announce the interest mark: the drain
        // can then never run the task before the mark queue has seen it.
        // The mark is picked up by this iteration's post-recv consumption
        // (or, worst case, the next iteration's), so the effects of the
        // task are always followed by a sweep naming its connection - no
        // iteration needs the unattributed full-pass fallback for it.
        boolean submitted = mailbox.submitPollTask(task);
        if (submitted) {
            hopInterest.add(conn != null ? conn : HOP_UNKNOWN);
        }
        return submitted;
    }


    /**
     * Wakes the poll loop so it runs a full recv/sweep/send pass promptly.
     * This is the quiche equivalent of pumping the OpenSSL engine: packet
     * I/O and stream readiness are only computed by the loop itself.
     */
    void kickPollLoop() {
        kickPollLoop(null);
    }


    /**
     * Wakes the poll loop to sweep one specific connection (see
     * {@link #kickPollLoop()} for the full-pass variant).
     */
    void kickPollLoop(QuicheConnectionWrapper conn) {
        submitConnPollTask(conn, () -> {
            // No-op: the mailbox submission itself kicks the wait, and the
            // woken loop iteration performs the recv/sweep/send pass.
        });
    }


    /**
     * Records whether a connection has protocol data (for HTTP/3: QPACK
     * decoder instructions) pending emission. Called from any thread.
     *
     * @param conn    The connection wrapper
     * @param pending {@code true} when instructions were queued,
     *                {@code false} once the flush drained them
     */
    void setConnectionProtocolDataPending(QuicheConnectionWrapper conn, boolean pending) {
        if (conn.protocolDataPendingTransition(pending)) {
            if (pending) {
                protocolDataPendingCount.incrementAndGet();
                // Target the flush sweep at this connection (consumed by the
                // next iteration; the 10 ms cadence term in computeWait
                // guarantees that iteration arrives while the count is up).
                hopInterest.add(conn);
            } else {
                protocolDataPendingCount.decrementAndGet();
            }
        }
    }


    /**
     * Runs {@code task} on the QUIC poll thread and waits for its result.
     * quiche connections are not thread-safe for concurrent access, so
     * native operations must execute on the poll thread: when the caller
     * already is the poll thread the task runs directly, otherwise it is
     * queued and the caller blocks until the poll loop has executed it.
     * An unattributed hop conservatively forces a full sweep pass.
     *
     * @param task The operation to run on the poll thread
     * @param <T>  The task's result type
     *
     * @return The task's result
     *
     * @throws Exception The task's exception, or a
     *                   {@link java.util.concurrent.TimeoutException} if the
     *                   poll thread did not execute the task in time
     */
    <T> T callOnPollThread(Callable<T> task) throws Exception {
        return callOnPollThread(null, task);
    }


    /**
     * {@link #callOnPollThread(Callable)} for a task whose native effects
     * are confined to {@code conn}: the hop marks only that connection for
     * the following sweep instead of forcing a full pass.
     *
     * @param conn The connection the task touches, or {@code null} when it
     *             touches more than one (or none) and the full-pass
     *             behaviour is required
     * @param task The operation to run on the poll thread
     * @param <T>  The task's result type
     *
     * @return The task's result
     *
     * @throws Exception The task's exception, or a
     *                   {@link java.util.concurrent.TimeoutException} if the
     *                   poll thread did not execute the task in time
     */
    <T> T callOnPollThread(QuicheConnectionWrapper conn, Callable<T> task)
            throws Exception {
        if (isPollThread()) {
            return task.call();
        }
        CompletableFuture<T> future = new CompletableFuture<>();
        // Task before mark (see submitConnPollTask): the hop's native
        // effects always precede a sweep naming this connection.
        if (!mailbox.submitPollTask(() -> {
            try {
                future.complete(task.call());
            } catch (Throwable t) {
                future.completeExceptionally(t);
            }
        })) {
            // Mailbox closed (endpoint stopped): fail fast rather than wait
            // out the hop timeout for a task that will never run.
            throw new RejectedExecutionException(
                    sm.getString("quicheEndpoint.pollTaskRejected"));
        }
        hopInterest.add(conn != null ? conn : HOP_UNKNOWN);
        return future.get(POLL_TASK_HOP_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    }


    /**
     * {@link #callOnPollThread(Callable)} with the socket wrapper's
     * exception surface: the hop failure modes are translated into plain
     * {@link IOException}s (interrupts restore the interrupt flag, the hop
     * timeout reports the poll-task timeout, execution failures surface
     * their cause; a failed native binding call stays an {@link Error}).
     * One translation implementation shared by the wrapper's native-call
     * paths and any endpoint-side caller that wants the same contract
     * instead of the raw {@code Exception} surface of
     * {@link #callOnPollThread(Callable)}.
     *
     * @param task The operation to run on the poll thread
     * @param <T>  The task's result type
     *
     * @return The task's result
     *
     * @throws IOException If the task fails or the poll thread does not
     *                     complete it in time
     */
    <T> T callOnPollThreadChecked(Callable<T> task) throws IOException {
        return callOnPollThreadChecked(null, task);
    }


    /**
     * {@link #callOnPollThreadChecked(Callable)} for a task confined to
     * {@code conn} (see
     * {@link #callOnPollThread(QuicheConnectionWrapper, Callable)}).
     *
     * @param conn The connection the task touches, or {@code null} for the
     *             conservative full-pass behaviour
     * @param task The operation to run on the poll thread
     * @param <T>  The task's result type
     *
     * @return The task's result
     *
     * @throws IOException If the task fails or the poll thread does not
     *                     complete it in time
     */
    <T> T callOnPollThreadChecked(QuicheConnectionWrapper conn, Callable<T> task)
            throws IOException {
        try {
            return callOnPollThread(conn, task);
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
                // QuicheBindings) means quiche is broken: fatal, do not
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


    private boolean drainPollTasks() {
        return mailbox.drainPollTasks();
    }


    /**
     * Drains the poll-task queue repeatedly until {@code hasWork} reports no
     * more work or {@code deadline} passes, sleeping briefly between drains,
     * so a worker whose native hop the poll loop would normally service can
     * complete while the poll loop is stopped. A final unconditional drain
     * runs on exit. Used by the stop path.
     *
     * @param deadline absolute deadline in {@link System#currentTimeMillis()}
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
     * Frees the connection, or defers the free if an executor worker is
     * still running the HTTP handler for a stream on this connection. The
     * worker that brings {@code activeHandlers} to zero schedules the free
     * as a poll task.
     */
    private void freeConnectionOrDefer(QuicheConnectionWrapper conn) {
        assertNativeAccess("freeConnectionOrDefer");
        // Claim the free first, then re-check the handler count: a handler
        // that exits between an initial count check and setting the flag
        // would find nothing pending and the deferred free would never run.
        conn.setPendingFree();
        if (!conn.hasActiveHandlers() && conn.clearPendingFree()) {
            conn.freeConnOnce();
            return;
        }
        if (log.isDebugEnabled()) {
            log.debug("Deferring connection free (0x"
                    + Long.toHexString(conn.getConnAddress())
                    + ") until active handlers complete");
        }
    }


    // ------------------------------------- Poll loop

    /**
     * Main packet loop: wait on {UDP socket, mailbox kick, earliest quiche
     * timer}, drain the mailbox (worker hops), read datagrams into the
     * demuxer, then process the connections the iteration produced work for
     * (readable/writable sweeps, timers, protocol-data flush, send flush,
     * close detection).
     * <p>
     * The sweep is work-gated, not fleet-gated: a datagram delivered to a
     * connection marks it touched, timer expiries are collected from the
     * deadline heap ({@link #timerHeap}), worker hops name the connection
     * they touch ({@link #hopInterest}), and deferred replays keep their own
     * retry set; only unattributed hops, queued protocol data and wait
     * failures sweep every connection. An iteration whose wait timed out
     * with none of these pending skips the sweep entirely, so an idle fleet
     * costs the poll thread O(events) per wake, not O(live connections) -
     * the property the kernel selector gives the NIO endpoint for TCP.
     */
    private void pollLoop() {
        if (log.isDebugEnabled()) {
            log.debug("QUIC poll loop starting, socketFd=" + socketFd);
        }
        boolean recvBudgetExhausted = false;
        while (running && !Thread.currentThread().isInterrupted()) {
            try {
                long waitMs = computeWait(recvBudgetExhausted);
                int events = quicWakeup.await(waitMs);
                quicWakeup.consumeWake();
                // Consume hop interest before draining the mailbox: a mark
                // already in the queue belongs to a task this drain will
                // execute, so marking the connection for sweeping now makes
                // this iteration's sweep see the task's effects. Tasks
                // submitted during the drain queue their mark for the next
                // iteration (whose drain runs the task) - a one-iteration
                // delay at worst, never a lost sweep.
                boolean unknownHops = false;
                sweepHopConns.clear();
                Object hopMark;
                while ((hopMark = hopInterest.poll()) != null) {
                    if (hopMark == HOP_UNKNOWN) {
                        unknownHops = true;
                    } else {
                        sweepHopConns.add((QuicheConnectionWrapper) hopMark);
                    }
                }
                drainPollTasks();
                if (events < 0) {
                    // Persistent wait failure: back off instead of spinning.
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
                sweepTouchedConns.addAll(sweepHopConns);
                recvBudgetExhausted = false;
                if (events >= 0) {
                    boolean[] exhausted = new boolean[1];
                    recvPass(exhausted);
                    recvBudgetExhausted = exhausted[0];
                }
                // Hops submitted during the drain or the recv pass (worker
                // stream I/O reacting to delivered data) mark interest that
                // the pre-drain consumption missed; consuming again before
                // gating closes the race that would strand their effects
                // with no pending sweep.
                while ((hopMark = hopInterest.poll()) != null) {
                    if (hopMark == HOP_UNKNOWN) {
                        unknownHops = true;
                    } else {
                        sweepHopConns.add((QuicheConnectionWrapper) hopMark);
                    }
                }
                sweepTouchedConns.addAll(sweepHopConns);

                long nowMs = System.currentTimeMillis();
                collectDueTimers(nowMs);
                boolean anyPending = !pendingConns.isEmpty();
                // Unattributed hops, queued protocol data (any connection
                // may hold the flush) and wait failures can touch any
                // connection: full pass. A mailbox drain that ran work not
                // naming any connection also falls back to the full pass.
                // Named hops and work sets sweep only what they name.
                boolean hopPass = unknownHops || events < 0;
                boolean closedScanDue = nowMs - lastClosedScanMs >=
                        CLOSED_SCAN_INTERVAL_MS;
                if (hopPass || closedScanDue || anyPending ||
                        !sweepDueConns.isEmpty() ||
                        !sweepTouchedConns.isEmpty() ||
                        !sweepRetryConns.isEmpty()) {
                    if (anyPending) {
                        processPendingConnections();
                    }
                    if (hopPass) {
                        // Full pass (it also reclaims any JVM-side closed
                        // connection on the way).
                        for (QuicheConnectionWrapper conn : connections.values()) {
                            sweepConn(conn);
                        }
                        lastClosedScanMs = nowMs;
                    } else {
                        // Targeted pass over the union of this iteration's
                        // work sets; the retry set is re-derived by the sweep
                        // itself (connections still holding deferred replays
                        // re-register).
                        sweepScratch.clear();
                        sweepScratch.addAll(sweepDueConns);
                        sweepScratch.addAll(sweepTouchedConns);
                        sweepScratch.addAll(sweepRetryConns);
                        sweepRetryConns.clear();
                        for (QuicheConnectionWrapper conn : sweepScratch) {
                            sweepConn(conn);
                        }
                        if (closedScanDue) {
                            // Slow-path reclaim of flag-only closes (see
                            // scanClosedForTeardown): a flag scan, no native
                            // work for the fleet.
                            scanClosedForTeardown();
                            lastClosedScanMs = nowMs;
                        }
                    }
                    sweepTouchedConns.clear();
                }
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.error(sm.getString("quicheEndpoint.pollLoopError"), t);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("QUIC poll loop stopped");
        }
    }


    /**
     * Sweeps one connection: reclaims it if closed, otherwise runs its
     * stream sweeps, timers, protocol data, send flush and close detection,
     * then re-registers its deferred-replay interest (if any) and refreshes
     * its timer-deadline heap entry. Runs only on the poll thread.
     */
    private void sweepConn(QuicheConnectionWrapper conn) {
        if (conn.isFreed()) {
            return;
        }
        if (conn.isClosed()) {
            // Closed JVM-side but still registered: a close path that
            // flipped the flag without running the teardown (e.g. a failed
            // worker hop). Reclaim its state here; the teardown claim makes
            // this race-free against any other trigger.
            teardownConnSafe(conn);
            return;
        }
        processConnection(conn);
        if (!conn.getPendingReadDispatches().isEmpty() ||
                !conn.getPendingUniStreamDrains().isEmpty() ||
                conn.isProtocolDataPending()) {
            // Deferred replays and partially flushed QPACK output both need
            // another sweep of this connection; the retry set keeps the
            // pass targeted while the computeWait floor keeps the cadence.
            sweepRetryConns.add(conn);
        }
        if (!conn.isFreed() && !conn.isClosed()) {
            refreshTimerDeadline(conn);
        }
    }


    private void teardownConnSafe(QuicheConnectionWrapper conn) {
        try {
            teardownConnection(conn);
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            log.warn(sm.getString("quicheEndpoint.connectionError",
                    Long.toHexString(conn.getConnAddress())), t);
        }
    }


    /*
     * Safety-net reclaim of connections closed JVM-side without a mailbox
     * hop: every current close path runs its teardown on a poll-thread hop
     * or kicks the loop naming this connection when the hop failed, so this
     * scan only bounds a future close path that forgets both. It runs at
     * most once per CLOSED_SCAN_INTERVAL_MS and is a pure JVM flag scan.
     */
    private void scanClosedForTeardown() {
        for (QuicheConnectionWrapper conn : connections.values()) {
            if (conn.isClosed() && !conn.isFreed()) {
                teardownConnSafe(conn);
            }
        }
    }


    // ------------------------------------- Timer deadline index

    /**
     * One heap entry: a connection's timer deadline at the moment it was
     * read, stamped with the connection's sequence number at that moment.
     */
    private static final class TimerEntry {

        final long deadlineMs;
        final int seq;
        final QuicheConnectionWrapper conn;

        TimerEntry(long deadlineMs, int seq, QuicheConnectionWrapper conn) {
            this.deadlineMs = deadlineMs;
            this.seq = seq;
            this.conn = conn;
        }
    }


    /**
     * Re-reads a swept connection's quiche timer and pushes its new deadline
     * entry onto the heap, stamping it (which invalidates every entry pushed
     * for the previous read). Callers run it after every poll-thread action
     * that can move the connection's timers: the sweep (on_timeout, recv
     * servicing, send flush) and nothing else - quiche timers only advance
     * through native calls, and every native call site on this transport
     * either runs inside the sweep or forces a hop pass, whose full sweep
     * refreshes every connection.
     */
    private void refreshTimerDeadline(QuicheConnectionWrapper conn) {
        long t = QuicheBindings.quiche_conn_timeout_as_millis(conn.getConn());
        conn.setTimerDeadline(t < 0 ? Long.MAX_VALUE :
                System.currentTimeMillis() + t);
        timerHeap.add(new TimerEntry(conn.getTimerDeadlineMs(),
                conn.getTimerSeq(), conn));
        if (timerHeap.size() > (connections.size() << 2) + HEAP_STALE_FLOOR) {
            rebuildTimerHeap();
        }
    }


    /**
     * Peeks the earliest deadline, dropping stale (re-stamped) and
     * freed-connection entries as they surface at the head. Poll thread
     * only.
     */
    private TimerEntry heapPeekFresh() {
        while (!timerHeap.isEmpty()) {
            TimerEntry entry = timerHeap.peek();
            // Closed connections are dropped, not just stale ones: quiche
            // reports a zero timeout for a closed connection forever, and a
            // closed connection whose free is deferred (active handler)
            // would otherwise surface as due on every iteration - a
            // wait-zero spin. Their reclaim is flag-driven (teardown claim,
            // deferred free on handler completion, the closed scan), never
            // timer-driven.
            if (entry.conn.isFreed() || entry.conn.isClosed() ||
                    entry.seq != entry.conn.getTimerSeq()) {
                timerHeap.poll();
            } else {
                return entry;
            }
        }
        return null;
    }


    /**
     * Collects the connections whose cached deadline has passed into
     * {@link #sweepDueConns} for this iteration's sweep (each is refreshed
     * and re-pushed by the sweep itself). Poll thread only.
     */
    private void collectDueTimers(long nowMs) {
        sweepDueConns.clear();
        TimerEntry entry;
        while ((entry = heapPeekFresh()) != null && entry.deadlineMs <= nowMs) {
            timerHeap.poll();
            sweepDueConns.add(entry.conn);
        }
    }


    /**
     * Drops every heap entry and re-pushes one per live connection from the
     * deadlines stored on the wrappers - no native calls. Triggered when the
     * stale-entry backlog grows past four times the live fleet.
     */
    private void rebuildTimerHeap() {
        timerHeap.clear();
        for (QuicheConnectionWrapper conn : connections.values()) {
            if (!conn.isFreed() && !conn.isClosed()) {
                timerHeap.add(new TimerEntry(conn.getTimerDeadlineMs(),
                        conn.getTimerSeq(), conn));
            }
        }
    }


    /**
     * Computes the wait bound: queued work shortens it to the pending-task
     * cadence; otherwise pollTimeoutMs (idle endpoints use the idle
     * cadence), capped by the earliest quiche timer deadline (the timer-heap
     * head for established connections, a small linear scan of the bounded
     * pending set) and by the stop-responsiveness cap.
     */
    private long computeWait(boolean recvBudgetExhausted) {
        if (recvBudgetExhausted) {
            return 0;
        }
        long wait = PENDING_TASK_POLL_TIMEOUT_MS;
        if (!mailbox.hasPollTasks()) {
            wait = (connections.isEmpty() && pendingConns.isEmpty())
                    ? IDLE_POLL_TIMEOUT_MS : pollTimeoutMs;
        }
        TimerEntry head = heapPeekFresh();
        if (head != null) {
            wait = Math.min(wait, head.deadlineMs - System.currentTimeMillis());
        }
        // Pending (handshaking) connections are absent from the heap; their
        // set is bounded by the handshake limit, so the scan is cheap and
        // only runs while handshakes are actually in flight.
        wait = earliestTimer(pendingConns.values(), wait);
        // Deferred dispatch replays and pending protocol-data flushes keep
        // the service cadence regardless of the fleet timer state.
        if (!sweepRetryConns.isEmpty() || protocolDataPendingCount.get() > 0) {
            wait = Math.min(wait, pollTimeoutMs);
        }
        if (wait > WAIT_CAP_MS) {
            wait = WAIT_CAP_MS;
        }
        if (wait < 0) {
            wait = 0;
        }
        return wait;
    }


    /**
     * Folds the earliest quiche timer deadline of one connection map into
     * the running minimum. Used for the pending (handshaking) set of
     * {@link #computeWait(boolean)} - established connections are covered by
     * the timer heap instead.
     *
     * @param conns   The connection values to scan
     * @param current The minimum so far
     *
     * @return The smaller of {@code current} and the earliest timer in
     *         {@code conns}
     */
    private static long earliestTimer(Iterable<QuicheConnectionWrapper> conns,
            long current) {
        for (QuicheConnectionWrapper conn : conns) {
            long t = QuicheBindings.quiche_conn_timeout_as_millis(conn.getConn());
            if (t < 0) {
                // u64::MAX through the signed read: quiche reports this when
                // the connection has no timer armed (ffi.rs maps a None
                // timeout to u64::MAX). Folding it in would drive the wait to
                // zero and spin the poll loop; a timer-less connection has
                // no deadline to honour, so skip it.
                continue;
            }
            if (t < current) {
                current = t;
            }
        }
        return current;
    }


    /**
     * Reads datagrams until EAGAIN or the per-iteration budget is used.
     *
     * @param exhaustedOut {@code out[0]} is set {@code true} when the budget
     *                     ran out with the socket still readable
     *
     * @return {@code true} if at least one datagram was delivered
     */
    private boolean recvPass(boolean[] exhaustedOut) {
        if (recvBatchVec != null) {
            return recvPassBatched(exhaustedOut);
        }
        boolean any = false;
        int delivered = 0;
        while (delivered < RECV_BUDGET) {
            long n = QuicheBindings.recvDatagram(socketFd, recvBuf, MAX_DATAGRAM_SIZE,
                    scratchRecv, saFrom, saTo, toLenOut, groSeg);
            if (n < 0) {
                int err = QuicheBindings.errno();
                if (err == QuicheBindings.EINTR) {
                    // A signal interrupted the receive without delivering a
                    // datagram: retry without consuming a budget slot
                    // (charging it would cost one receive per signal). The
                    // arrival rate of signals bounds these retries, not the
                    // socket, so no datagram flow can livelock the loop.
                    continue;
                }
                // EAGAIN/EWOULDBLOCK (and any hard error) end the pass.
                return any;
            }
            delivered++;
            any = true;
            int seg = groReceive ? groSeg[0] : 0;
            try {
                if (seg > 0 && n > seg) {
                    // Coalesced GRO read: equal-size segments, the last one
                    // possibly short (the kernel splits exactly this way on
                    // the wire for a UDP_SEGMENT batch). Deliver each slice
                    // as its own datagram; saFrom/saTo apply unchanged to
                    // every segment (a merged run is by construction one
                    // flow - same socket, same addresses).
                    for (int off = 0, rem = (int) n; rem > 0; off += seg) {
                        int size = Math.min(seg, rem);
                        curPkt = recvBuf.asSlice(off, size);
                        rem -= size;
                        deliverDatagram(size);
                    }
                } else {
                    curPkt = recvBuf;
                    deliverDatagram((int) n);
                }
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.error(sm.getString("quicheEndpoint.deliverError"), t);
            } finally {
                curPkt = recvBuf;
            }
        }
        exhaustedOut[0] = true;
        return any;
    }


    /**
     * Reads datagrams with recvmmsg until EAGAIN or the per-iteration
     * budget is used: the receive-side counterpart of the sendmmsg send
     * path. One call takes up to RECV_BATCH messages; a message the kernel
     * GRO-merged is split and delivered segment by segment exactly as the
     * single-read path does. The per-datagram delivery code reads the
     * "last received" state (saFrom/saTo/toLenOut/curPkt), so those point
     * at the slot being delivered for the duration of the batch.
     */
    private boolean recvPassBatched(boolean[] exhaustedOut) {
        boolean any = false;
        int delivered = 0;
        while (delivered < RECV_BUDGET) {
            int room = Math.min(RECV_BATCH, RECV_BUDGET - delivered);
            for (int i = 0; i < room; i++) {
                // Re-arm the two inputs the kernel consumed (the read-back
                // values overwrote them).
                MemorySegment hdr = recvBatchVec.asSlice(
                        (long) i * QuicheBindings.MMSGHDR_SIZE,
                        QuicheBindings.MMSGHDR_SIZE);
                hdr.set(ValueLayout.JAVA_INT, QuicheBindings.MSGHDR_NAMELEN,
                        QuicheBindings.SOCKADDR_STORAGE_SIZE);
                hdr.set(ValueLayout.JAVA_LONG, QuicheBindings.MSGHDR_CONTROLLEN,
                        QuicheBindings.CMSG_SPACE);
            }
            int got = QuicheBindings.recvmmsg(socketFd, recvBatchVec, room,
                    QuicheBindings.MSG_DONTWAIT);
            if (got < 0) {
                int err = QuicheBindings.errno();
                if (err == QuicheBindings.EINTR) {
                    // A signal interrupted without delivering messages;
                    // retry without consuming budget (same reasoning as
                    // recvPass).
                    continue;
                }
                // EAGAIN/EWOULDBLOCK (and any hard error) end the pass.
                return any;
            }
            if (got == 0) {
                // Defensive: a non-blocking recvmmsg either takes at least
                // one message or reports EAGAIN. Zero would spin the loop.
                return any;
            }
            delivered += got;
            any = true;
            MemorySegment savedFrom = saFrom;
            MemorySegment savedTo = saTo;
            MemorySegment savedToLen = toLenOut;
            try {
                for (int i = 0; i < got; i++) {
                    MemorySegment hdr = recvBatchVec.asSlice(
                            (long) i * QuicheBindings.MMSGHDR_SIZE,
                            QuicheBindings.MMSGHDR_SIZE);
                    saFrom = recvBatchFrom.asSlice(
                            (long) i * QuicheBindings.SOCKADDR_STORAGE_SIZE,
                            QuicheBindings.SOCKADDR_STORAGE_SIZE);
                    saTo = recvBatchTo.asSlice(
                            (long) i * QuicheBindings.SOCKADDR_STORAGE_SIZE,
                            QuicheBindings.SOCKADDR_STORAGE_SIZE);
                    toLenOut = recvBatchToLen.asSlice(
                            (long) i * ValueLayout.JAVA_INT.byteSize(),
                            ValueLayout.JAVA_INT.byteSize());
                    long controllen = Math.min(
                            hdr.get(ValueLayout.JAVA_LONG,
                                    QuicheBindings.MSGHDR_CONTROLLEN),
                            QuicheBindings.CMSG_SPACE);
                    QuicheBindings.parseRecvCmsgs(recvBatchCmsg.asSlice(
                            (long) i * QuicheBindings.CMSG_SPACE,
                            QuicheBindings.CMSG_SPACE),
                            controllen, saTo, toLenOut, groSeg);
                    long n = hdr.get(ValueLayout.JAVA_INT,
                            QuicheBindings.MMSGHDR_MSGLEN) & 0xFFFFFFFFL;
                    int seg = groReceive ? groSeg[0] : 0;
                    MemorySegment slotBuf = recvBatchBuf[i];
                    try {
                        if (seg > 0 && n > seg) {
                            // Coalesced GRO read: equal-size segments, the
                            // last one possibly short. saFrom/saTo apply
                            // unchanged to every segment (a merged run is
                            // by construction one flow).
                            for (int off = 0, rem = (int) n; rem > 0; off += seg) {
                                int size = Math.min(seg, rem);
                                curPkt = slotBuf.asSlice(off, size);
                                rem -= size;
                                deliverDatagram(size);
                            }
                        } else {
                            curPkt = slotBuf;
                            deliverDatagram((int) n);
                        }
                    } catch (Throwable t) {
                        ExceptionUtils.handleThrowable(t);
                        log.error(sm.getString("quicheEndpoint.deliverError"), t);
                    }
                }
            } finally {
                saFrom = savedFrom;
                saTo = savedTo;
                toLenOut = savedToLen;
                curPkt = recvBuf;
            }
        }
        exhaustedOut[0] = true;
        return any;
    }


    /**
     * Demuxes one received datagram (the segment currently being delivered,
     * {@code curPkt}, {@code len} bytes long) to its connection, creating a
     * connection for an unknown Initial (with version negotiation and
     * capacity/pause rejection handling), and feeds it to
     * {@code quiche_conn_recv()}.
     */
    private void deliverDatagram(int len) {
        if (len < 5) {
            return;
        }
        hdrType.set(ValueLayout.JAVA_BYTE, 0, (byte) 0);
        // quiche_header_info treats the *_len outputs as capacity inputs: they
        // must be seeded with the size of the destination buffers.
        hdrScidLen.set(ValueLayout.JAVA_LONG, 0, QuicheBindings.QUICHE_MAX_CONN_ID_LEN);
        hdrDcidLen.set(ValueLayout.JAVA_LONG, 0, QuicheBindings.QUICHE_MAX_CONN_ID_LEN);
        hdrTokenLen.set(ValueLayout.JAVA_LONG, 0, MAX_DATAGRAM_SIZE);
        int rc = QuicheBindings.quiche_header_info(curPkt, len, SERVER_CID_LEN,
                hdrVersion, hdrType, hdrScid, hdrScidLen, hdrDcid, hdrDcidLen,
                hdrToken, hdrTokenLen);
        int typeByte = hdrType.get(ValueLayout.JAVA_BYTE, 0) & 0xFF;
        if (rc < 0) {
            // Either malformed for its version (quiche rejects, for example,
            // CIDs longer than 20 bytes on a supported version), or parsed
            // but with fields that do not fit the fixed-capacity outputs
            // (return -1): an unsupported-version packet with a CID longer
            // than 20 bytes, or a short-header packet not addressed by a
            // minted CID. RFC 9000 Section 17.2.1: version-specific
            // connection ID rules MUST NOT influence the decision to send a
            // Version Negotiation packet, so the unsupported-version case
            // gets its verdict from the raw datagram here too; everything
            // else is dropped.
            negotiateVersionIfNeeded(len);
            return;
        }
        long dcidLen = hdrDcidLen.get(ValueLayout.JAVA_LONG, 0);
        CidKey dcidKey = new CidKey(hdrDcid, (int) dcidLen);

        QuicheConnectionWrapper conn = cidMap.get(dcidKey);
        if (conn == null) {
            boolean longHeader = typeByte != QuicheBindings.QUICHE_PACKET_TYPE_SHORT;
            if (!longHeader) {
                // Short-header packet with an unknown DCID: stale or
                // spoofed. Drop. (Emitting a stateless reset for these is
                // not implemented.)
                return;
            }
            int version = hdrVersion.get(ValueLayout.JAVA_INT, 0);
            if (!QuicheBindings.quiche_version_is_supported(version)) {
                negotiateVersionIfNeeded(len);
                return;
            }
            boolean initial = typeByte == QuicheBindings.QUICHE_PACKET_TYPE_INITIAL;
            if (!initial || dcidLen < 8) {
                // A connection may be created only from a first Initial
                // (RFC 9000 Section 5.2).
                return;
            }
            if (pendingConns.size() >= pendingLimit()) {
                // Bounded pending queue: drop; the client retries or times
                // out (quiche's equivalent of OpenSSL's pending queue).
                return;
            }
            // A negative maxConnections means unlimited (Tomcat convention):
            // the raw comparison would reject every connection because
            // 0 >= -1.
            boolean reject = paused ||
                    (maxConnections >= 0 &&
                            connections.size() + pendingConns.size() >= maxConnections);
            if (reject) {
                rejectIncoming(len);
                return;
            }
            // No Retry / address validation: the Initial is accepted
            // without demanding a token. This is deliberate - RFC 9000
            // Section 8.1.2 makes Retry optional, the token parsed into
            // hdrToken above exists only so quiche_header_info succeeds and
            // is discarded here, and quiche_retry is not bound. A
            // spoofed-source first flight is therefore answered with
            // unauthenticated crypto work per datagram, bounded by the 3x
            // server-flight limit rather than gated by a token.
            conn = createConnection();
            if (conn == null) {
                return;
            }
        }
        if (conn.isClosed() || conn.isFreed()) {
            return;
        }
        feedConnection(conn, len);
        // Handshake-completion promotion, once per connection.
        long addr = conn.getConnAddress();
        if (pendingConns.containsKey(addr)) {
            if (QuicheBindings.quiche_conn_is_established(conn.getConn())) {
                acceptConnection(conn);
            }
        } else if (!conn.isClosed() && !conn.isFreed()) {
            // Established: the feed can have opened readable/writable edges
            // and moved the timers, so schedule this connection's sweep for
            // this iteration.
            sweepTouchedConns.add(conn);
        }
    }


    /**
     * Sends a Version Negotiation reply for the datagram currently being
     * delivered ({@code curPkt}, {@code len} bytes), if one is due.
     * The decision and the CID echo are parsed from the raw datagram rather
     * than from the {@code quiche_header_info} outputs so they work for
     * packets whose CIDs exceed the fixed parse buffers: RFC 9000
     * Section 17.2.1 ("version-specific rules for the connection ID ...
     * MUST NOT influence a decision about whether to send a Version
     * Negotiation packet"). Two further MUST-level guards: no reply to a
     * Version Negotiation packet (version 0, Section 6.1), and no reply to
     * a datagram smaller than any supported version needs to initiate a
     * connection (Section 5.2.2) - which also keeps the reply
     * non-amplifying (at most ~520 bytes for a 1200-byte input).
     */
    private void negotiateVersionIfNeeded(int len) {
        if (len < MIN_CLIENT_DATAGRAM_SIZE) {
            // RFC 9000 Section 5.2.2: drop unsupported-version datagrams
            // smaller than the minimum any supported version needs.
            return;
        }
        if ((curPkt.get(ValueLayout.JAVA_BYTE, 0) & 0xC0) != 0xC0) {
            // Short header: no version field, nothing to negotiate.
            return;
        }
        int version = curPkt.get(VERSION_FIELD, 1);
        if (version == 0 || QuicheBindings.quiche_version_is_supported(version)) {
            // A Version Negotiation packet (never answer one, Section 6.1)
            // or a supported version (the caller routes it).
            return;
        }
        // Long header prefix: flags(1) version(4) dcil(1) dcid scil(1) scid.
        long off = 6;
        long dcidLen = curPkt.get(ValueLayout.JAVA_BYTE, 5) & 0xFF;
        if (off + dcidLen + 1 > len) {
            return;
        }
        long dcidOff = off;
        off += dcidLen;
        long scidLen = curPkt.get(ValueLayout.JAVA_BYTE, off) & 0xFF;
        off++;
        if (off + scidLen > len) {
            return;
        }
        long scidOff = off;
        // negotiate_version writes the reply's DCID from its first argument:
        // RFC 9000 Section 17.2.1 - the reply echoes the client's SCID as the
        // DCID and the client's DCID as the SCID.
        long out = QuicheBindings.quiche_negotiate_version(
                curPkt.asSlice(scidOff, scidLen), scidLen,
                curPkt.asSlice(dcidOff, dcidLen), dcidLen,
                sendBuf, sendBuf.byteSize());
        if (out > 0) {
            QuicheBindings.sendDatagram(socketFd, sendBuf, (int) out,
                    saFrom, QuicheBindings.sockaddrLength(saFrom),
                    MemorySegment.NULL, scratchSend);
        }
    }


    private int pendingLimit() {
        return Math.max(PENDING_LIMIT_FLOOR, maxConnections * 2);
    }


    /*
     * Parses the peer address from the last-received datagram (saFrom),
     * creates the quiche connection for a new Initial with a freshly minted
     * SCID, and registers it in the demux maps (SCID and ODCID keys).
     */
    private QuicheConnectionWrapper createConnection() {
        MemorySegment cfg = certManager.getConfig();
        if (cfg.equals(MemorySegment.NULL)) {
            if (log.isTraceEnabled()) {
                log.trace("createConnection: no config");
            }
            return null;
        }
        int peerLen = QuicheBindings.sockaddrLength(saFrom);
        if (peerLen <= 0) {
            if (log.isTraceEnabled()) {
                log.trace("createConnection: unknown peer family");
            }
            return null;
        }
        long dcidLen = hdrDcidLen.get(ValueLayout.JAVA_LONG, 0);
        InetSocketAddress local = QuicheBindings.readSockaddr(saTo,
                toLenOut.get(ValueLayout.JAVA_INT, 0));
        if (local == null) {
            local = bindAddress;
        }
        // local already degenerated to bindAddress above when the received
        // destination sockaddr was absent or unparseable, so one fill covers
        // both cases.
        MemorySegment connPtr = acceptWithMintedScid(local, peerLen, cfg);
        if (connPtr.equals(MemorySegment.NULL)) {
            if (log.isTraceEnabled()) {
                log.trace("createConnection: quiche_accept returned NULL (dcidLen=" +
                        dcidLen + " peerLen=" + peerLen +
                        " cfg=0x" + Long.toHexString(cfg.address()) + ")");
            }
            return null;
        }
        QuicheConnectionWrapper conn = new QuicheConnectionWrapper(connPtr);
        conn.setEndpoint(this);
        conn.setRemoteAddress(QuicheBindings.readSockaddr(saFrom, peerLen));
        conn.setLocalAddress(local);
        // The SCID minted by acceptWithMintedScid is the one registered
        // here (mintedScid is its buffer; CidKey copies it).
        CidKey scidKey = new CidKey(mintedScid, SERVER_CID_LEN);
        CidKey odcidKey = new CidKey(hdrDcid, (int) dcidLen);
        cidMap.put(scidKey, conn);
        cidMap.putIfAbsent(odcidKey, conn);
        pendingConns.put(conn.getConnAddress(), conn);
        if (log.isDebugEnabled()) {
            log.debug("Created pending connection 0x" +
                    Long.toHexString(conn.getConnAddress()) + " from " +
                    conn.getRemoteAddress() + " scid=" + scidKey);
        }
        return conn;
    }


    /**
     * Shared accept core of {@link #createConnection()} and
     * {@link #rejectIncoming(int)}: mints a random accept SCID into
     * {@code mintedScid}, fills {@code saBind} with the caller-chosen local
     * address, verifies both sockaddr pairs against the quiche contract and
     * runs {@code quiche_accept} with a NULL odcid. The minted SCID stays in
     * {@code mintedScid} for the caller to register (createConnection) or
     * discard (rejectIncoming); both callers run on the poll thread, so the
     * shared buffers need no extra synchronisation.
     * <p>
     * The odcid is deliberately NULL: quiche 0.30 treats a non-NULL odcid as
     * "this connection answered a Retry" and advertises
     * retry_source_connection_id accordingly. Without it the
     * original_destination_connection_id is advertised automatically from
     * the first received Initial packet.
     *
     * @param local   The local address to advertise for the new connection
     *                (createConnection prefers the datagram's PKTINFO local
     *                address and falls back to bindAddress; rejectIncoming
     *                has no handshake state to pin and always uses
     *                bindAddress - the divergence is deliberate)
     * @param peerLen The peer sockaddr length (already validated as a
     *                known family by the caller)
     * @param cfg     The TLS config to accept with
     *
     * @return The raw connection pointer, or {@link MemorySegment#NULL} if
     *         quiche_accept refused the packet
     */
    private MemorySegment acceptWithMintedScid(InetSocketAddress local,
            int peerLen, MemorySegment cfg) {
        byte[] scid = new byte[SERVER_CID_LEN];
        cidRandom.nextBytes(scid);
        mintedScid.asByteBuffer().put(scid, 0, SERVER_CID_LEN);
        QuicheBindings.fillSockaddr(saBind, local);
        int localLen = QuicheBindings.sockaddrLength(saBind);
        // Boundary check against quiche's std_addr_from_c assert (see the
        // helper): a violation aborts the JVM from native code, so the
        // pair is verified before the call rather than trusted.
        QuicheBindings.requireSockaddrContract(saBind, localLen);
        QuicheBindings.requireSockaddrContract(saFrom, peerLen);
        return QuicheBindings.quiche_accept(mintedScid, SERVER_CID_LEN,
                MemorySegment.NULL, 0, saBind, localLen, saFrom, peerLen, cfg);
    }


    /*
     * Accept-and-reject path for capacity/pause: quiche_accept, feed the
     * triggering datagram, queue the rejection CONNECTION_CLOSE, transmit
     * it, free. The handshake cost was already paid by the peer; this is
     * the rejectIncomingConnection analogue, adapted to quiche's
     * synchronous accept.
     * <p>
     * The triggering Initial has to be fed with quiche_conn_recv() before
     * the close is queued, exactly as createConnection()/feedConnection()
     * feed accepted connections: a freshly accepted server connection has
     * not derived its Initial secrets (quiche derives them only while
     * parsing the first received Initial on the server side) and has
     * processed no packet, so quiche_conn_close() marks it closed
     * outright ("close immediately if no packet was processed") and
     * quiche_conn_send() then emits nothing for it - the refusal would be
     * a silent drop. Feeding the Initial first derives the secrets and
     * keeps the connection open through the queued close, so the refusal
     * CONNECTION_CLOSE is actually transmittable.
     * <p>
     * The close is deliberately a transport-level close (is_app=false) with
     * CONNECTION_REFUSED: the connection is freshly accepted and its
     * handshake is not established, and quiche silently rewrites an
     * application-level close on such a connection to a transport close
     * with code 0x0c (protocol violation), discarding the requested
     * application error code ({@code getConnectionRejectErrorCode()} cannot
     * reach the peer here). Requesting the transport close explicitly keeps
     * the emitted code intentional rather than an accident of quiche's
     * internal fallback.
     */
    private void rejectIncoming(int len) {
        long now = System.currentTimeMillis();
        if (paused) {
            if (now - lastPausedLogMs > MAX_CONNECTIONS_LOG_INTERVAL_MS) {
                lastPausedLogMs = now;
                if (log.isDebugEnabled()) {
                    log.debug("Endpoint paused - rejecting incoming connection");
                }
            }
        } else if (now - lastMaxConnectionsLogMs > MAX_CONNECTIONS_LOG_INTERVAL_MS) {
            lastMaxConnectionsLogMs = now;
            log.warn(sm.getString("quicheEndpoint.maxConnectionsReached",
                    String.valueOf(maxConnections)));
        }
        MemorySegment cfg = certManager.getConfig();
        if (cfg.equals(MemorySegment.NULL)) {
            return;
        }
        int peerLen = QuicheBindings.sockaddrLength(saFrom);
        if (peerLen <= 0) {
            return;
        }
        MemorySegment connPtr = acceptWithMintedScid(bindAddress, peerLen, cfg);
        if (connPtr.equals(MemorySegment.NULL)) {
            return;
        }
        // Feed the triggering datagram first (see the javadoc): without a
        // processed packet the close is never transmittable.
        int pktToLen = toLenOut.get(ValueLayout.JAVA_INT, 0);
        if (pktToLen > 0) {
            recvIntoConn(connPtr, len, saTo, pktToLen);
        } else {
            // The reject path always fills saBind with bindAddress (the
            // helper's local argument), so it is the fallback destination.
            recvIntoConn(connPtr, len, saBind,
                    QuicheBindings.sockaddrLength(saBind));
        }
        QuicheBindings.quiche_conn_close(connPtr, false,
                QuicheBindings.QUICHE_TRANSPORT_CONNECTION_REFUSED,
                MemorySegment.NULL, 0);
        sendLoop(null, connPtr, saFrom, peerLen);
        QuicheBindings.quiche_conn_free(connPtr);
    }


    /*
     * quiche_conn_recv() one datagram into a known connection, with local
     * error surfacing.
     */
    private void feedConnection(QuicheConnectionWrapper conn, int len) {
        int pktToLen = toLenOut.get(ValueLayout.JAVA_INT, 0);
        MemorySegment toSeg;
        int toLen;
        if (pktToLen > 0) {
            toSeg = saTo;
            toLen = pktToLen;
        } else {
            QuicheBindings.fillSockaddr(saBind, conn.getLocalAddress() != null
                    ? conn.getLocalAddress() : bindAddress);
            toSeg = saBind;
            toLen = QuicheBindings.sockaddrLength(saBind);
        }

        long rc = recvIntoConn(conn.getConn(), len, toSeg, toLen);
        if (rc < 0 && rc != QuicheBindings.QUICHE_ERR_DONE) {
            noteConnectionError(conn, rc, "recv");
        }
    }


    /*
     * quiche_conn_recv() the datagram currently being delivered (curPkt,
     * with its peer address in saFrom) into a raw connection pointer, wiring the
     * recv_info struct from the received datagram's addresses. Shared by
     * feedConnection() and the rejectIncoming() feed so both present the
     * identical socket-address context to quiche.
     */
    private long recvIntoConn(MemorySegment connPtr, int len,
            MemorySegment toSeg, int toLen) {
        int fromLen = QuicheBindings.sockaddrLength(saFrom);
        // Boundary check against quiche's std_addr_from_c assert (see the
        // helper): quiche_conn_recv dereferences both recv_info addresses,
        // so a violating pair here aborts the JVM rather than erroring.
        QuicheBindings.requireSockaddrContract(saFrom, fromLen);
        QuicheBindings.requireSockaddrContract(toSeg, toLen);
        recvInfo.set(ValueLayout.ADDRESS, QuicheBindings.RECV_INFO_FROM, saFrom);
        recvInfo.set(ValueLayout.JAVA_INT, QuicheBindings.RECV_INFO_FROM_LEN, fromLen);
        recvInfo.set(ValueLayout.ADDRESS, QuicheBindings.RECV_INFO_TO, toSeg);
        recvInfo.set(ValueLayout.JAVA_INT, QuicheBindings.RECV_INFO_TO_LEN, toLen);
        return QuicheBindings.quiche_conn_recv(connPtr, curPkt, len, recvInfo);
    }


    /**
     * Processes one established connection: stream sweeps, timers, protocol
     * data, the send flush and close detection.
     */
    private void processConnection(QuicheConnectionWrapper conn) {
        try {
            sweepReadable(conn);
            sweepWritable(conn);
            // Unconditional, not gated on is_timed_out(): that flag tracks the
            // idle timeout only, while on_timeout() also expires the draining
            // timer set on a received CONNECTION_CLOSE (quiche's contract is
            // "call on_timeout whenever timeout_as_millis reports zero"; the
            // call is cheap and a no-op when no timer has elapsed).
            QuicheBindings.quiche_conn_on_timeout(conn.getConn());
            if (conn.isProtocolDataPending()) {
                flushProtocolData(conn);
            }
            if (flushSend(conn)) {
                sweepRetryConns.add(conn);
            }
            detectClose(conn);
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            log.warn(sm.getString("quicheEndpoint.connectionError",
                    Long.toHexString(conn.getConnAddress())), t);
        }
    }


    /*
     * Pending (un-established) connections: timers, send flush, teardown of
     * those that closed or timed out before establishing.
     */
    private void processPendingConnections() {
        for (QuicheConnectionWrapper conn : pendingConns.values()) {
            if (conn.isClosed() || conn.isFreed()) {
                discardPending(conn);
                continue;
            }
            try {
                // See processConnection(): unconditional covers draining.
                QuicheBindings.quiche_conn_on_timeout(conn.getConn());
                flushSend(conn);
                if (QuicheBindings.quiche_conn_is_closed(conn.getConn())) {
                    discardPending(conn);
                }
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error processing pending connection", t);
                }
            }
        }
    }


    private void discardPending(QuicheConnectionWrapper conn) {
        pendingConns.remove(conn.getConnAddress(), conn);
        cidMap.values().removeIf(v -> v == conn);
        conn.setClosed();
        conn.freeConnOnce();
    }


    // ------------------------------------- Connection accept

    /**
     * Promotes an established pending connection to service: reads ALPN and
     * SNI, gates on the served protocol, registers the protocol connection
     * manager and bootstraps the server unidirectional streams. Port of the
     * OpenSSL endpoint's handleIncomingConnection from the handshake-complete
     * point on. Runs once, on the poll thread.
     */
    private void acceptConnection(QuicheConnectionWrapper conn) {
        if (!pendingConns.remove(conn.getConnAddress(), conn)) {
            // Already accepted (or discarded) by a racing path.
            return;
        }
        QuicProtocol protocol = getQuicProtocol();
        if (protocol == null) {
            discardPending(conn);
            return;
        }
        String alpn = readAlpnProtocol(conn);
        conn.setNegotiatedProtocol(alpn);
        // Eagerly read (and cache) the SNI host name on the poll thread;
        // the wrapper's own read is the lazy fallback for worker threads.
        conn.getSniHostName();

        if (!isServedProtocol(alpn)) {
            log.warn(sm.getString("quicheEndpoint.alpnNotServed",
                    Long.toHexString(conn.getConnAddress()), String.valueOf(alpn)));
            connections.put(conn.getConnAddress(), conn);
            failConnection(conn, NO_APPLICATION_PROTOCOL_ERROR,
                    "Negotiated application protocol is not served");
            // failConnection only queues the CONNECTION_CLOSE; transmitting
            // it needs a sweep of this connection. The caller evaluated
            // pendingConns.containsKey() as true before this method removed
            // the entry, so its "established" else-branch (which would have
            // marked the connection touched) does not run, and the connection
            // is otherwise invisible to the work sets, the timer heap and the
            // flag-only close scan. Schedule the sweep explicitly so the close
            // leaves the socket this iteration (and close detection reclaims
            // the connection) instead of waiting for the peer's next datagram
            // or its own idle timeout - mirroring the served path below.
            sweepTouchedConns.add(conn);
            return;
        }

        QuicConnectionManager connManager = protocol.createQuicConnectionManager();
        conn.setQuicConnectionManager(connManager);
        connManager.connectionOpen(conn);

        QuicConnectionManager.ConnectionState state = connManager.getState(conn);
        long configured = protocol.getMaxConcurrentStreams();
        // With quiche the advertised initial_max_streams_bidi IS the
        // configured value: the reconciliation degenerates to
        // set-if-configured (no mismatch warning needed, unlike OpenSSL).
        // A configured value of 0 or less means "use the transport
        // default"; quiche's own default is zero streams (which would
        // advertise a limit of no bidirectional streams at all), so the
        // config build floors the advertised value to one — mirror the
        // same floor here to keep enforcement in step with what the peer
        // observes.
        if (state != null) {
            state.setMaxConcurrentStreams(Math.max(configured, 1));
        }

        connections.put(conn.getConnAddress(), conn);
        createServerUniStreams(conn);
        issueAdditionalScid(conn);
        // The freshly established connection has server-uni stream writes
        // (SETTINGS etc.) and possibly the first request already buffered:
        // schedule its sweep for this iteration (and its first timer-heap
        // entry via the sweep's refresh).
        sweepTouchedConns.add(conn);
        if (log.isDebugEnabled()) {
            log.debug("Accepted connection 0x" + Long.toHexString(conn.getConnAddress()) +
                    " alpn=" + alpn + " from " + conn.getRemoteAddress());
        }
    }


    /*
     * Issues one additional source connection ID for an established
     * connection (RFC 9000 Section 5.1.1: "MAY"). quiche only emits
     * NEW_CONNECTION_ID frames for SCIDs the application supplies via
     * quiche_conn_new_scid, so without this the connection keeps a single
     * source CID for its lifetime and a spec-compliant deliberate client
     * migration (RFC 9000 Section 9.5: no CID reuse across local
     * addresses) has no spare DCID to switch to. The peer stores at most
     * active_connection_id_limit server CIDs (quiche default 2), so the
     * mint-at-accept CID plus this one saturate it; retire_if_needed is
     * false because nothing retires before the limit. The issued CID is
     * registered in the demux map: post-migration short-header packets
     * carry it as the DCID. Best effort - a failure (e.g. a peer limit of
     * 1) costs only the migration feature. Runs on the poll thread; the
     * CID is published (NEW_CONNECTION_ID) by the next flush of
     * quiche_conn_send.
     */
    private void issueAdditionalScid(QuicheConnectionWrapper conn) {
        byte[] scid = new byte[SERVER_CID_LEN];
        byte[] resetToken = new byte[RESET_TOKEN_LEN];
        for (int attempt = 0; attempt < 4; attempt++) {
            cidRandom.nextBytes(scid);
            CidKey key = new CidKey(scid);
            if (cidMap.containsKey(key)) {
                // Astronomically unlikely at 16 random bytes, but never
                // shadow another connection's CID.
                continue;
            }
            cidRandom.nextBytes(resetToken);
            extraScid.asByteBuffer().put(scid, 0, SERVER_CID_LEN);
            scidResetToken.asByteBuffer().put(resetToken, 0, RESET_TOKEN_LEN);
            int rc = QuicheBindings.quiche_conn_new_scid(conn.getConn(),
                    extraScid, SERVER_CID_LEN, scidResetToken, false, scidSeqOut);
            if (rc == 0) {
                cidMap.put(key, conn);
                if (log.isDebugEnabled()) {
                    log.debug("Issued additional SCID " + key + " on connection 0x" +
                            Long.toHexString(conn.getConnAddress()));
                }
            } else if (log.isDebugEnabled()) {
                log.debug("quiche_conn_new_scid failed on connection 0x" +
                        Long.toHexString(conn.getConnAddress()) + ": " + rc);
            }
            return;
        }
    }


    private boolean isServedProtocol(String negotiated) {
        QuicProtocol protocol = getQuicProtocol();
        return protocol != null && protocol.isServedIdentifier(negotiated);
    }


    /*
     * ALPN gate before any stream data is dispatched (port of the OpenSSL
     * ensureServedProtocol): the protocol is read at accept, so this is a
     * cheap re-check for connections accepted before the field was set.
     */
    private boolean ensureServedProtocol(QuicheConnectionWrapper conn) {
        if (conn == null || conn.isClosed() || conn.isFreed()) {
            return false;
        }
        if (conn.getNegotiatedProtocol() == null) {
            String alpn = readAlpnProtocol(conn);
            if (alpn != null) {
                conn.setNegotiatedProtocol(alpn);
            }
        }
        if (isServedProtocol(conn.getNegotiatedProtocol())) {
            return true;
        }
        log.warn(sm.getString("quicheEndpoint.alpnNotServed",
                Long.toHexString(conn.getConnAddress()),
                String.valueOf(conn.getNegotiatedProtocol())));
        failConnection(conn, NO_APPLICATION_PROTOCOL_ERROR,
                "Negotiated application protocol is not served");
        return false;
    }


    private String readAlpnProtocol(QuicheConnectionWrapper conn) {
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment out = localArena.allocate(ValueLayout.ADDRESS);
            MemorySegment outLen = localArena.allocate(ValueLayout.JAVA_LONG);
            out.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);
            outLen.set(ValueLayout.JAVA_LONG, 0, 0L);
            QuicheBindings.quiche_conn_application_proto(conn.getConn(), out, outLen);
            MemorySegment data = out.get(ValueLayout.ADDRESS, 0);
            long len = outLen.get(ValueLayout.JAVA_LONG, 0);
            if (data.equals(MemorySegment.NULL) || len == 0) {
                return null;
            }
            byte[] bytes = data.reinterpret(len).toArray(ValueLayout.JAVA_BYTE);
            return new String(bytes, java.nio.charset.StandardCharsets.US_ASCII);
        }
    }


    // ------------------------------------- Stream sweeps

    /**
     * Readable sweep: {@code quiche_conn_stream_readable_next()} replaces
     * the OpenSSL poll-set R events. Client-initiated unidirectional streams
     * feed the protocol path; bidirectional streams get the request
     * dispatch.
     */
    private void sweepReadable(QuicheConnectionWrapper conn) {
        int guard = 0;
        while (guard++ < SWEEP_BUDGET) {
            long id = QuicheBindings.quiche_conn_stream_readable_next(conn.getConn());
            if (id < 0) {
                break;
            }
            if ((id & 0x02) != 0) {
                if ((id & 0x01) == 0) {
                    readUnidirectionalStream(conn, id);
                }
                // Server-initiated uni streams are never readable; ignore.
            } else {
                processAcceptedBidi(conn, id);
            }
        }
        rearmPendingUniStreamDrains(conn);
        rearmReadWaiters(conn);
        rearmPendingReadDispatches(conn);
    }


    /*
     * Level-trigger re-drain for client unidirectional streams, the uni-side
     * counterpart of rearmReadWaiters/rearmPendingReadDispatches. The
     * readable_next pop consumed the edge and quiche only re-inserts the
     * stream when new data is buffered, so a stream left readable level-wise
     * by the bounded per-call drain would strand its tail (including the FIN
     * and the terminal handling that rides on it) until unrelated traffic
     * happened to re-fire the edge. Re-drain every tracked stream quiche
     * still reports readable; readUnidirectionalStream re-tracks it if the
     * budget runs out again and clears it once drained or terminal.
     */
    private void rearmPendingUniStreamDrains(QuicheConnectionWrapper conn) {
        if (conn.isClosed() || conn.isFreed()) {
            return;
        }
        Set<QuicheStreamWrapper> pending = conn.getPendingUniStreamDrains();
        if (pending.isEmpty()) {
            return;
        }
        Iterator<QuicheStreamWrapper> iterator = pending.iterator();
        while (iterator.hasNext()) {
            QuicheStreamWrapper stream = iterator.next();
            if (stream.isDeregistered() || stream.isFreed()) {
                iterator.remove();
                continue;
            }
            if (!QuicheBindings.quiche_conn_stream_readable(conn.getConn(),
                    stream.getStreamId())) {
                iterator.remove();
                continue;
            }
            readUnidirectionalStream(conn, stream.getStreamId());
        }
    }


    /*
     * Replay of OPEN_READ dispatches that the claim-retry budget dropped.
     * The readable edge was consumed by the readable_next pop before the
     * dispatch was scheduled, and registerReadInterest() is a no-op on this
     * transport, so a dropped event would strand the buffered data on a
     * quiet stream. Re-dispatch when the processing claim has freed; keep
     * the entry otherwise so a later sweep retries. Terminal streams are
     * evicted (their data no longer has a consumer).
     */
    private void rearmPendingReadDispatches(QuicheConnectionWrapper conn) {
        if (conn.isClosed() || conn.isFreed()) {
            return;
        }
        Set<QuicheStreamWrapper> pending = conn.getPendingReadDispatches();
        if (pending.isEmpty()) {
            return;
        }
        Iterator<QuicheStreamWrapper> iterator = pending.iterator();
        while (iterator.hasNext()) {
            QuicheStreamWrapper stream = iterator.next();
            if (stream.isDeregistered() || stream.isFreed()) {
                iterator.remove();
                continue;
            }
            if (stream.isProcessing() ||
                    !stream.compareAndSetProcessing(false, true)) {
                // Claim still held: retry on a later sweep.
                continue;
            }
            QuicheSocketWrapper wrapper = stream.getSocketWrapper();
            if (wrapper == null) {
                stream.clearProcessing();
                wakeClaimWaiters(stream, conn);
                continue;
            }
            iterator.remove();
            if (log.isDebugEnabled()) {
                log.debug("Replaying OPEN_READ dispatch for stream " +
                        stream.getStreamId());
            }
            dispatchToExecutor(wrapper, stream, SocketEvent.OPEN_READ, true);
        }
    }


    /*
     * Level-trigger re-arm. The readable_next iterator is edge-driven: a
     * stream is reported when it transitions to readable. When a drain
     * stopped early (stream read buffer full, or the iterator popped the
     * stream before all buffered bytes were consumed) the remainder sits in
     * quiche's buffer with no pending edge, and a worker parked in
     * awaitReadableData would never be signalled until some future packet
     * happened to re-fire the edge (or never, on a quiet stream). Re-signal
     * every bidirectional stream that quiche reports readable level-wise
     * while a worker is parked on it. Signalling is a no-op cost when there
     * is no waiter.
     */
    private void rearmReadWaiters(QuicheConnectionWrapper conn) {
        if (conn.isClosed() || conn.isFreed()) {
            return;
        }
        // Walk the read re-arm index (the parked-reader work set) rather than
        // the live-stream map, so the sweep costs O(interest) not O(streams)
        // (see QuicheConnectionWrapper.readRearm). A registration that lands
        // after this view is taken is served by the next iteration's walk (the
        // stream is indexed before the waiter parks and the pump kicks the
        // loop), so the guard bounds latency to one iteration rather than
        // losing the signal.
        if (!conn.hasReadRearm()) {
            return;
        }
        for (QuicheStreamWrapper stream : conn.readRearmStreams()) {
            long id = stream.getStreamId();
            // Client-initiated unidirectional streams are processed on the
            // poll thread itself; only bidirectional request streams park
            // workers.
            if ((id & 0x02) != 0) {
                continue;
            }
            if (stream.isDeregistered() || stream.isFreed()) {
                continue;
            }
            QuicheSocketWrapper wrapper = stream.getSocketWrapper();
            if (wrapper != null && wrapper.hasReadWaiter() &&
                    QuicheBindings.quiche_conn_stream_readable(conn.getConn(), id)) {
                wrapper.signalReadWaiter();
            }
        }
    }


    /**
     * Writable sweep: {@code quiche_conn_stream_writable_next()} replaces
     * the OpenSSL poll-set W events. Buffered server-uni writes get their
     * retry from the per-iteration flush below; bidi wrappers with parked
     * write waiters or buffered writes are served here.
     */
    private void sweepWritable(QuicheConnectionWrapper conn) {
        // Server unidirectional streams with buffered data (SETTINGS, GOAWAY,
        // QPACK instructions): retry on every pass; a RETRY that finds no
        // capacity costs one bounded attempt (no spin: writes only become
        // possible after input or time, which wake the loop).
        for (QuicheStreamWrapper stream : conn.getServerUniStreams()) {
            ByteBuffer writeBuf = stream.getWriteBuffer();
            if (writeBuf != null && writeBuf.hasRemaining()) {
                flushServerUniStreamWrite(conn, stream);
            }
        }
        int guard = 0;
        while (guard++ < SWEEP_BUDGET) {
            long id = QuicheBindings.quiche_conn_stream_writable_next(conn.getConn());
            if (id < 0) {
                break;
            }
            QuicheSocketWrapper wrapper = getSocketWrapper(conn.getConnAddress(), id);
            if (wrapper == null) {
                continue;
            }
            notifyWriteReady(wrapper, conn.getStreams().get(Long.valueOf(id)));
        }
        rearmWriteWaiters(conn);
    }


    /*
     * Deliver write-readiness for one bidirectional stream to whoever waits
     * for it: wake a worker parked in awaitWritable (a blocking write drains
     * itself; the opportunistic flush helps the would-block retry along) and,
     * for async write listeners, dispatch an OPEN_WRITE event so the protocol
     * path runs serviceWritePossible / onWritePossible (port of the OpenSSL
     * WRITABLE dispatchStreamEvent branch, which the quiche sweep replaces).
     * The write-interest latch is cleared when the dispatch claim is taken:
     * the handler re-arms it via doWrite() if its writes stall again, and a
     * busy claim keeps it set so the level re-arm retries the delivery.
     */
    private void notifyWriteReady(QuicheSocketWrapper wrapper, QuicheStreamWrapper stream) {
        if (wrapper.hasWriteWaiter()) {
            wrapper.signalWriteWaiter();
        }
        if (!wrapper.isClosed()) {
            try {
                wrapper.flushNonBlocking();
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Writable notify flush failed", e);
                }
            }
        }
        if (stream != null && !stream.isFreed() && !stream.isDeregistered() &&
                stream.hasWriteInterest() && stream.compareAndSetProcessing(false, true)) {
            if (stream.clearWriteInterest()) {
                // The true→false transition: match the registration the latch
                // made in the connection's write re-arm index.
                stream.getConnection().releaseWriteRearm(stream);
            }
            dispatchToExecutor(wrapper, stream, SocketEvent.OPEN_WRITE, true);
        }
    }


    /*
     * Level-trigger re-arm for writes, mirroring rearmReadWaiters. The
     * writable_next iterator is edge-driven, and quiche only pushes a stream
     * onto the writable queue on stream-level events (SSE, stream MAX_STREAMS
     * window opens): a connection-level MAX_DATA that frees tx credit fires
     * no edge at all, so neither a worker parked in awaitWritable nor an
     * async write listener waiting for its OPEN_WRITE event would ever hear
     * about the recovered capacity. Re-notify every bidirectional stream that
     * quiche reports writable level-wise (non-zero stream_capacity, which
     * accounts for both the stream and the connection window) while a worker
     * is parked with data buffered or an async write-interest latch is set.
     */
    private void rearmWriteWaiters(QuicheConnectionWrapper conn) {
        if (conn.isClosed() || conn.isFreed()) {
            return;
        }
        // Walk the write re-arm index (the parked-writer + latched-interest
        // work set) rather than the live-stream map, so the sweep costs
        // O(interest) not O(streams) (see QuicheConnectionWrapper.writeRearm).
        // A registration that lands after this view is taken is served by the
        // next iteration's walk (the stream is indexed before the interest
        // becomes observable and the pump kicks the loop).
        if (!conn.hasWriteRearm()) {
            return;
        }
        for (QuicheStreamWrapper stream : conn.writeRearmStreams().keySet()) {
            long id = stream.getStreamId();
            // Client-initiated unidirectional streams are written on the poll
            // thread itself; only bidirectional response streams park
            // workers or latch write interest.
            if ((id & 0x02) != 0) {
                continue;
            }
            boolean latched = stream.hasWriteInterest();
            QuicheSocketWrapper wrapper = stream.getSocketWrapper();
            if (wrapper == null) {
                continue;
            }
            boolean parked = wrapper.hasWriteWaiter() && wrapper.hasBufferedWrites();
            if (!latched && !parked) {
                continue;
            }
            if (QuicheBindings.quiche_conn_stream_capacity(conn.getConn(), id) <= 0) {
                continue;
            }
            notifyWriteReady(wrapper, stream);
        }
    }


    /**
     * Drains a client-initiated unidirectional stream into its read buffer
     * and feeds the protocol manager (port of the OpenSSL
     * readUnidirectionalStream/processUniStreamData/checkClientUniStreamClosed
     * trio). The sweep re-fires a stream while it still holds unread data:
     * {@code readable_next} only pops the transition edge, so the drain
     * re-checks quiche's level-wise readable state after each
     * drain/process round and continues while it holds - bounded per call
     * by {@link #UNI_DRAIN_MAX_ROUNDS} and handed to the connection's
     * pending uni-stream drain set (see
     * {@link #rearmPendingUniStreamDrains}) when the budget runs out with
     * data still buffered.
     */
    private void readUnidirectionalStream(QuicheConnectionWrapper conn, long streamId) {
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null) {
            return;
        }
        QuicheStreamWrapper stream = conn.getStreams().computeIfAbsent(
                Long.valueOf(streamId),
                id -> new QuicheStreamWrapper(id.longValue(), conn,
                        ByteBuffer.allocate(readBufferSize)));
        if (stream.isFreed()) {
            return;
        }
        for (int round = 0; round < UNI_DRAIN_MAX_ROUNDS; round++) {
            drainIntoStreamBuffer(conn, stream);

            ByteBuffer buffer = stream.getReadBuffer();
            int avail = buffer.position();
            if (avail > 0) {
                buffer.flip();
                try {
                    connManager.processClientUniStreamData(conn, streamId, buffer);
                } catch (Throwable t) {
                    ExceptionUtils.handleThrowable(t);
                    long code = connManager.getProtocolErrorCode(t);
                    if (code == 0) {
                        code = getDefaultStreamErrorCode();
                    }
                    conn.getPendingUniStreamDrains().remove(stream);
                    failConnection(conn, code, t.toString());
                    return;
                }
                // Restore put mode, retaining the unconsumed tail. The
                // compact MUST happen while the limit is still the flipped
                // read limit: compact copies [position, limit), so widening
                // the limit first would retain the stale buffer tail.
                buffer.compact();
                buffer.limit(buffer.capacity());
                // The protocol data the processing queued (QPACK decoder
                // instructions) must reach the peer.
                flushProtocolData(conn);
                // Processing may have advanced the protocol state enough for
                // the next server stream (HTTP/3: QPACK streams after
                // SETTINGS).
                createServerUniStreams(conn);
                if (buffer.position() == buffer.capacity()) {
                    // The protocol consumed nothing and the buffer is full:
                    // no further progress is possible until it can, and new
                    // data re-fires the edge for another attempt.
                    break;
                }
            }
            if (!QuicheBindings.quiche_conn_stream_readable(conn.getConn(), streamId)) {
                break;
            }
        }

        boolean terminal = stream.isFinReceived() ||
                stream.getReadState() == QuicStream.ReadState.RESET_REMOTE ||
                stream.getReadState() == QuicStream.ReadState.RESET_LOCAL;
        if (terminal) {
            QuicConnectionManager.ConnectionState state = connManager.getState(conn);
            if (state != null && state.isCriticalClientUniStream(streamId)) {
                failConnection(conn, state.getClosedCriticalStreamErrorCode(),
                        "Critical client unidirectional stream closed");
            } else if (state != null) {
                state.clientUniStreamClosed(streamId);
            }
            conn.getStreams().remove(Long.valueOf(streamId));
            conn.getPendingUniStreamDrains().remove(stream);
            stream.setDeregistered();
        } else if (QuicheBindings.quiche_conn_stream_readable(conn.getConn(), streamId)) {
            // The drain budget ran out (or the buffer refilled without
            // protocol consumption) while quiche still buffers data. The
            // readable_next pop consumed the edge and only new datagrams
            // re-fire it, so track the stream for the next sweep's level
            // re-drain instead of stranding the tail on a quiet stream.
            conn.getPendingUniStreamDrains().add(stream);
            sweepRetryConns.add(conn);
        } else {
            conn.getPendingUniStreamDrains().remove(stream);
        }
    }


    /**
     * Handles a readable bidirectional (request) stream: ALPN gate, stream
     * limit gate, wrapper pair creation, prefetch, and dispatch to the
     * executor (or a read-waiter signal when a handler owns the stream).
     * Port of the OpenSSL processAcceptedStream/dispatchStreamEvent path.
     */
    private void processAcceptedBidi(QuicheConnectionWrapper conn, long streamId) {
        if (!ensureServedProtocol(conn)) {
            return;
        }
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null) {
            log.trace("processAcceptedBidi: no connManager");
            return;
        }
        QuicConnectionManager.ConnectionState state = connManager.getState(conn);
        if (state == null) {
            log.trace("processAcceptedBidi: no state");
            return;
        }

        boolean known = conn.getStreams().containsKey(Long.valueOf(streamId));
        if (!known && !state.canAcceptStream(streamId)) {
            // Concurrent stream limit: GOAWAY + reject this stream (RFC 9114
            // H3_REQUEST_REJECTED - retryable, before processing began). The
            // READ shutdown below makes the rejection terminal - the stream
            // can never re-enter this sweep - so each fresh rejection gets
            // its own GOAWAY. The single-slot cache keeps a repeat of the
            // most recent rejection quiet defensively: client bidi stream IDs
            // never repeat on a connection, so an ID equal to the last
            // rejected one can only be a repeat of that rejection, while a
            // higher ID is a fresh rejection.
            if (streamId != conn.getLastRejectedStreamId()) {
                conn.setLastRejectedStreamId(streamId);
                sendStreamLimitNotification(connManager, state);
                QuicheBindings.quiche_conn_stream_shutdown(conn.getConn(),
                        streamId, QuicheBindings.QUICHE_SHUTDOWN_WRITE,
                        getStreamRejectErrorCode());
                // Shutdown the read direction too: without it the client's
                // continued sending keeps re-firing the readable edge for a
                // stream that nothing will ever own, and every edge repeats
                // the GOAWAY/reset once the single-slot cache below is
                // overwritten by another rejected ID. The READ shutdown
                // drops the buffered data, removes the stream from quiche's
                // readable set and keeps it permanently non-readable, and
                // sends STOP_SENDING so the client stops writing.
                QuicheBindings.quiche_conn_stream_shutdown(conn.getConn(),
                        streamId, QuicheBindings.QUICHE_SHUTDOWN_READ,
                        getStreamRejectErrorCode());
                // The abandoned stream owes the protocol its abandonment
                // bookkeeping (for HTTP/3: a QPACK Stream Cancellation,
                // RFC 9204 Section 2.2.2.2) even though no processor ever
                // read a byte of it.
                connManager.noteStreamRejected(conn, streamId);
            }
            return;
        }

        QuicheStreamWrapper stream = conn.getStreams().computeIfAbsent(
                Long.valueOf(streamId),
                id -> new QuicheStreamWrapper(id.longValue(), conn,
                        ByteBuffer.allocate(readBufferSize)));
        if (stream.isFreed() || stream.isDeregistered()) {
            return;
        }

        long addr = conn.getConnAddress();
        ConcurrentHashMap<Long, QuicheSocketWrapper> perConn =
                streamWrappers.computeIfAbsent(Long.valueOf(addr),
                        k -> new ConcurrentHashMap<>());
        QuicheSocketWrapper wrapper = perConn.computeIfAbsent(Long.valueOf(streamId),
                id -> {
                    QuicheSocketWrapper w = new QuicheSocketWrapper(stream, this);
                    // Wire the connector-configured socket timeouts into the
                    // wrapper so its blocking reads and writes honour them,
                    // as the NIO endpoints do for their stream/socket
                    // wrappers.
                    w.setReadTimeout(getConnectionTimeout());
                    w.setWriteTimeout(getConnectionTimeout());
                    // Back-pointer so the re-arm sweeps, which hold the
                    // stream, reach the wrapper without the two-level map
                    // walk. The write lands before the mapping function
                    // publishes w into the map, so any thread that sees the
                    // wrapper in the map also sees the link.
                    stream.setSocketWrapper(w);
                    return w;
                });

        if (!known) {
            state.incrementActiveStreams();
            state.setLastProcessedStreamId(streamId);
        }

        // Prefetch so the handler sees the first bytes from the stream's read
        // buffer (parity with the OpenSSL read-immediately path) and - on
        // every readable edge - so the stream's terminal state (FIN observed,
        // or the one-shot quiche reset error) is captured on the poll thread
        // before the dispatch, not only when the handler eventually reads.
        drainIntoStreamBuffer(conn, stream);

        if (stream.compareAndSetProcessing(false, true)) {
            // Processing was just claimed by the compareAndSet above;
            // pass it on so dispatchToExecutor does not re-claim (and
            // fail its own claim, dropping the task).
            dispatchToExecutor(wrapper, stream, SocketEvent.OPEN_READ, true);
        } else if (wrapper.hasReadWaiter()) {
            wrapper.signalReadWaiter();
        } else {
            // The edge is consumed by the pop and the claim is busy (a
            // running dispatch): the event must not be dropped or an async
            // read waiting for its next OPEN_READ never hears about the
            // buffered data. Re-queue the delivery until the claim frees
            // (abandoning if the handler completes first - the running
            // dispatch drains the data itself and the stream is gone).
            scheduleStreamDispatch(wrapper, stream, SocketEvent.OPEN_READ, true);
        }
    }


    /*
     * Reads from a stream into its put-mode read buffer, up to the drain
     * bound. Stops on would-block, FIN or terminal state; the FIN/terminal
     * observation updates the stream's read state. Runs on the poll thread.
     */
    private void drainIntoStreamBuffer(QuicheConnectionWrapper conn,
            QuicheStreamWrapper stream) {
        ByteBuffer buffer = stream.getReadBuffer();
        for (int attempt = 0; attempt < READ_DRAIN_MAX_ATTEMPTS; attempt++) {
            int pos = buffer.position();
            // The native read writes into the shared, fixed-size recvBuf, so
            // never ask quiche for more than that buffer can hold, even when
            // the configured readBufferSize makes the stream buffer larger.
            int space = Math.min(buffer.capacity() - pos, (int) recvBuf.byteSize());
            if (space == 0) {
                return;
            }
            finFlag.set(ValueLayout.JAVA_BOOLEAN, 0, false);
            errCode.set(ValueLayout.JAVA_LONG, 0, 0L);
            long rc = QuicheBindings.quiche_conn_stream_recv(conn.getConn(),
                    stream.getStreamId(), recvBuf, space, finFlag, errCode);
            if (rc > 0) {
                int n = (int) Math.min(rc, space);
                buffer.position(pos);
                buffer.put(recvBuf.asSlice(0, n).asByteBuffer());
                if (finFlag.get(ValueLayout.JAVA_BOOLEAN, 0)) {
                    stream.setFinReceived();
                    return;
                }
                continue;
            }
            if (rc == QuicheBindings.QUICHE_ERR_STREAM_RESET) {
                // Quiche surfaces a peer RESET_STREAM as this error exactly
                // once; every later read only reports the stream as finished.
                // Capture the terminal read state here or the drain would
                // silently swallow the reset and the aborted body would read
                // as a clean end of stream.
                stream.setReadState(QuicStream.ReadState.RESET_REMOTE);
                return;
            }
            if (rc == QuicheBindings.QUICHE_ERR_STREAM_STOPPED) {
                stream.setReadState(QuicStream.ReadState.RESET_LOCAL);
                return;
            }
            if (rc == 0 && finFlag.get(ValueLayout.JAVA_BOOLEAN, 0)) {
                stream.setFinReceived();
            }
            return;
        }
    }


    // ------------------------------------- Server unidirectional streams

    /**
     * Creates the server-initiated unidirectional streams the protocol
     * requests (port of createServerUniStreams): for quiche a stream needs
     * no native creation call - sending on id {@code 3 + 4*index} implicitly
     * opens it - so this registers the wrapper, hands the protocol its init
     * data and drives the first write.
     */
    private void createServerUniStreams(QuicheConnectionWrapper conn) {
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null || conn.isClosed() || conn.isFreed()) {
            return;
        }
        int index;
        while ((index = connManager.nextServerUniStream(conn)) >= 0) {
            long streamId = 3 + 4L * index;
            if (conn.getServerUniStream(index) != null) {
                // Already created; a protocol manager that keeps handing out
                // the same index would spin the loop.
                break;
            }
            QuicheStreamWrapper stream = new QuicheStreamWrapper(streamId, conn,
                    ByteBuffer.allocate(readBufferSize));
            conn.registerServerUniStream(index, stream);
            conn.getStreams().put(Long.valueOf(streamId), stream);

            ByteBuffer initData = connManager.getServerUniStreamInitData(index);
            if (initData != null && initData.hasRemaining()) {
                byte[] data = new byte[initData.remaining()];
                initData.get(data);
                stream.setWriteBuffer(ByteBuffer.wrap(data));
                writeBufferedUniStream(conn, stream);
            }
            connManager.serverUniStreamCreated(conn, index, stream);
            if (log.isDebugEnabled()) {
                log.debug("Server unidirectional stream created: index=" + index +
                        " id=" + streamId);
            }
        }
    }


    /**
     * Buffered server-uni stream write, bounded retries (port of
     * writeBufferedUniStream). Capacity grows only with input or time, both
     * of which wake the loop, so leaving the data buffered for the next
     * sweep's retry is sufficient.
     */
    private void writeBufferedUniStream(QuicheConnectionWrapper conn,
            QuicheStreamWrapper uniStream) {
        for (int retry = 0; retry < STREAM_WRITE_RETRY_ATTEMPTS; retry++) {
            if (flushServerUniStreamWrite(conn, uniStream) != UniStreamWriteResult.RETRY) {
                return;
            }
        }
    }


    /**
     * Outcome of one buffered server unidirectional stream write attempt.
     */
    private enum UniStreamWriteResult {
        /** Buffer fully delivered (or nothing was buffered). */
        DONE,
        /** Data remains buffered and the stream may still accept it. */
        RETRY,
        /**
         * The stream can no longer accept the data; the buffered write is
         * dropped so the per-iteration writable sweep does not re-attempt it
         * (and re-log the failure) until connection teardown.
         */
        FAILED
    }


    /**
     * Makes one attempt to flush the buffered protocol data (init bytes or a
     * stream limit notification) of a server-initiated unidirectional
     * stream. quiche's partial-write feedback (accepted byte count +
     * stream_capacity) replaces the OpenSSL SSL_get_error dance.
     *
     * @return the outcome of the write attempt
     */
    private UniStreamWriteResult flushServerUniStreamWrite(QuicheConnectionWrapper conn,
            QuicheStreamWrapper stream) {
        if (conn.isClosed() || conn.isFreed() || stream.isFreed()) {
            stream.setWriteBuffer(null);
            return UniStreamWriteResult.FAILED;
        }
        ByteBuffer writeBuf = stream.getWriteBuffer();
        if (writeBuf == null || !writeBuf.hasRemaining()) {
            return UniStreamWriteResult.DONE;
        }
        int remaining = writeBuf.remaining();
        byte[] data = new byte[remaining];
        // Anchor progress at the current position: a reset to 0 would
        // re-queue bytes a previous partial flush already delivered.
        int savedPos = writeBuf.position();
        writeBuf.get(data);
        writeBuf.position(savedPos);

        long capacity = QuicheBindings.quiche_conn_stream_capacity(conn.getConn(),
                stream.getStreamId());
        int toSend = data.length;
        if (capacity > 0 && capacity < toSend) {
            toSend = (int) capacity;
        }
        errCode.set(ValueLayout.JAVA_LONG, 0, 0L);
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment dataSeg = localArena.allocate(toSend);
            dataSeg.asByteBuffer().put(data, 0, toSend);
            long written = QuicheBindings.quiche_conn_stream_send(conn.getConn(),
                    stream.getStreamId(), dataSeg, toSend, false, errCode);
            if (written > 0) {
                writeBuf.position(savedPos + (int) written);
                if (writeBuf.hasRemaining()) {
                    return UniStreamWriteResult.RETRY;
                }
                stream.setWriteBuffer(null);
                return UniStreamWriteResult.DONE;
            }
            if (written == QuicheBindings.QUICHE_ERR_FLOW_CONTROL ||
                    written == QuicheBindings.QUICHE_ERR_DONE || written == 0) {
                return UniStreamWriteResult.RETRY;
            }
            log.warn(sm.getString("quicheEndpoint.serverUniStreamWriteFailed",
                    Long.valueOf(stream.getStreamId())) + " rc=" + written);
            // The stream will never accept these bytes; drop the buffered
            // write so the writable sweep's per-iteration retry stops
            // re-attempting and re-warning on this failure.
            stream.setWriteBuffer(null);
            return UniStreamWriteResult.FAILED;
        } catch (RuntimeException e) {
            log.warn(sm.getString("quicheEndpoint.serverUniStreamWriteFailed",
                    Long.valueOf(stream.getStreamId())), e);
            stream.setWriteBuffer(null);
            return UniStreamWriteResult.FAILED;
        }
    }


    /**
     * Sends the protocol's stream retirement notification (GOAWAY for
     * HTTP/3) on the primary server unidirectional stream (port of
     * sendStreamLimitNotification). If the frame cannot be written
     * immediately it stays buffered and the writable sweep retries it.
     */
    private void sendStreamLimitNotification(QuicConnectionManager connManager,
            QuicConnectionManager.ConnectionState state) {
        try {
            QuicheConnectionWrapper conn = (QuicheConnectionWrapper) state.getConnection();
            QuicheStreamWrapper primaryStream = conn.getServerUniStream(0);
            if (primaryStream == null) {
                return;
            }
            // getStreamLimitFrame derives the RFC 9114 Section 5.2
            // identifier from the last processed stream ID (a negative
            // one - no request stream ever accepted - becomes identifier
            // 0, "no streams processed") and clamps it against the
            // identifier of any GOAWAY previously sent on the connection.
            ByteBuffer limitFrame = connManager.getStreamLimitFrame(
                    state, state.getLastProcessedStreamId());
            byte[] data = new byte[limitFrame.remaining()];
            limitFrame.get(data);

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
            writeBufferedUniStream(conn, primaryStream);
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
     * Flushes any protocol data the connection manager has queued (QPACK
     * decoder instructions) onto its server unidirectional stream. Runs on
     * the poll thread (the manager writes via
     * {@code connection.writeToStream}, which is poll-thread confined).
     */
    private void flushProtocolData(QuicheConnectionWrapper conn) {
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        if (connManager == null) {
            return;
        }
        try {
            connManager.flushPendingProtocolData(conn);
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            log.warn(sm.getString("quicheEndpoint.protocolDataFlushError",
                    Long.toHexString(conn.getConnAddress())), t);
        }
    }


    // ------------------------------------- Send flush

    /**
     * Runs one send pass for a connection from a poll-thread hop (used by
     * the socket wrapper after queueing a stream fin, so the fin reaches the
     * wire before the loop's next recv pass can process a peer ACK that would
     * make quiche collect the stream with the fin still queued).
     */
    void flushConnectionOnce(QuicheConnectionWrapper conn) {
        if (conn.isClosed() || conn.isFreed()) {
            return;
        }
        if (flushSend(conn)) {
            sweepRetryConns.add(conn);
        }
    }


    /**
     * Transmits everything a connection has queued: {@code quiche_conn_send}
     * until DONE, each packet sent with {@code sendmsg()} honouring the
     * destination (and, via the {@code IP_PKTINFO} cmsg, the source) that
     * quiche recorded in {@code quiche_send_info} - which keeps client
     * migration send-correct without needing path-event handling.
     *
     * @return {@code true} when the socket buffer filled before the output
     *         drained: the remainder stays queued inside quiche with no
     *         quiche-side re-drive, so the caller must schedule another
     *         sweep of this connection (the sweep retry set).
     */
    private boolean flushSend(QuicheConnectionWrapper conn) {
        int fallbackLen = 0;
        if (conn.getRemoteAddress() != null) {
            fallbackLen = QuicheBindings.fillSockaddr(saSendFallback, conn.getRemoteAddress());
        }
        return sendLoop(conn, conn.getConn(), saSendFallback, fallbackLen);
    }


    /**
     * Core send loop for one connection (or a raw rejection connection,
     * {@code conn == null}): quiche_conn_send until DONE, sending each
     * output datagram - batching runs of equal-size, same-destination
     * packets into one segmented sendmsg (one send syscall per batch) when
     * the kernel passed the UDP GSO probe, and parking a batch that met
     * EAGAIN whole on the connection's pending queue so nothing that left
     * quiche's queue is silently lost and order survives.
     *
     * @param connPtr      the quiche_conn pointer
     * @param fallbackTo   destination sockaddr to use when quiche's
     *                     send_info carries none (peer address known from
     *                     the last received datagram), may be NULL with
     *                     length 0 when unknown
     */
    private boolean sendLoop(QuicheConnectionWrapper conn, MemorySegment connPtr,
            MemorySegment fallbackTo, int fallbackToLen) {
        // Output-length invariant (checked against quiche 0.30.0,
        // lib.rs send()): quiche clamps every packet to
        // min(out.len(), max_send_udp_payload_size), so clamping bufLen to
        // SEND_BUFFER_SIZE here makes QUICHE_ERR_BUFFER_TOO_SHORT
        // structurally unreachable regardless of the quiche default or any
        // future max_send_udp_payload_size change - the effective per-packet
        // cap always stays within the staging slots without pinning the
        // config value.
        long maxSend = QuicheBindings.quiche_conn_max_send_udp_payload_size(connPtr);
        int bufLen = (int) Math.max(1200, Math.min(SEND_BUFFER_SIZE, maxSend));

        // A batch that EAGAIN'd earlier is drained (as single datagrams, in
        // order) before anything new is pulled from quiche: those packets
        // left quiche's queue already, so anything newer must not overtake
        // them. The socket is just as likely full now as then - EAGAIN here
        // keeps the queue intact and asks for a retry sweep.
        ArrayDeque<QuicheConnectionWrapper.PendingSend> pending =
                conn == null ? null : conn.pendingSends();
        if (pending != null && !pending.isEmpty()) {
            while (!pending.isEmpty()) {
                QuicheConnectionWrapper.PendingSend p = pending.peekFirst();
                MemorySegment data = batchSlots.asSlice(0, p.data.length);
                MemorySegment.copy(p.data, 0, data, ValueLayout.JAVA_BYTE, 0,
                        p.data.length);
                MemorySegment.copy(p.to, 0, drainTo, ValueLayout.JAVA_BYTE, 0,
                        p.to.length);
                MemorySegment pinFrom = null;
                if (p.from != null) {
                    MemorySegment.copy(p.from, 0, drainFrom, ValueLayout.JAVA_BYTE, 0,
                            p.from.length);
                    pinFrom = drainFrom;
                }
                long s = QuicheBindings.sendDatagram(socketFd, data, p.data.length,
                        drainTo, p.toLen, pinFrom, scratchSend);
                if (s >= 0) {
                    pending.pollFirst();
                    continue;
                }
                int err = QuicheBindings.errno();
                if (err == QuicheBindings.EINTR) {
                    continue;
                }
                if (err == QuicheBindings.EAGAIN) {
                    return true;
                }
                if (log.isDebugEnabled()) {
                    log.debug("pending send failed: " + QuicheBindings.strerror(err));
                }
                pending.pollFirst();
            }
        }

        // carry: a packet already pulled from quiche that could not join the
        // batch being assembled (different destination, or larger than the
        // batch's segment size); it is parked in the staging slot after the
        // batch slots and becomes the next batch's head.
        boolean carry = false;
        int carryLen = 0;
        boolean retryNeeded = false;
        while (true) {
            int n0;
            if (carry) {
                MemorySegment.copy(batchSlots, (long) GSO_MAX_BATCH * SEND_BUFFER_SIZE,
                        batchSlots, 0, carryLen);
                MemorySegment.copy(sendInfoK, 0, sendInfo, 0,
                        QuicheBindings.SEND_INFO_SIZE);
                n0 = carryLen;
                carry = false;
            } else {
                long n = QuicheBindings.quiche_conn_send(connPtr,
                        batchSlots.asSlice(0, bufLen), bufLen, sendInfo);
                if (n == QuicheBindings.QUICHE_ERR_DONE) {
                    break;
                }
                if (n < 0) {
                    // Defensive: BUFFER_TOO_SHORT cannot occur while the bufLen
                    // invariant above holds; any other negative is terminal for
                    // this pass and retried next iteration (no storm: quiche
                    // keeps the output queued and re-drives on recv/timer).
                    if (log.isDebugEnabled()) {
                        log.debug("quiche_conn_send error " + n);
                    }
                    break;
                }
                n0 = (int) n;
            }
            int toLen = sendInfo.get(ValueLayout.JAVA_INT, QuicheBindings.SEND_INFO_TO_LEN);
            MemorySegment to;
            int useLen;
            if (toLen > 0) {
                to = sendInfo.asSlice(QuicheBindings.SEND_INFO_TO,
                        QuicheBindings.SOCKADDR_STORAGE_SIZE);
                useLen = toLen;
            } else if (fallbackToLen > 0) {
                to = fallbackTo;
                useLen = fallbackToLen;
            } else {
                continue;
            }
            int fromLen = sendInfo.get(ValueLayout.JAVA_INT, QuicheBindings.SEND_INFO_FROM_LEN);
            MemorySegment from = null;
            if (fromLen > 0) {
                from = sendInfo.asSlice(QuicheBindings.SEND_INFO_FROM,
                        QuicheBindings.SOCKADDR_STORAGE_SIZE);
            }

            // Greedily extend the head packet into a same-destination run of
            // equal-size segments (plus one optional short tail, the shape a
            // UDP_SEGMENT batch must have). The head is only sent as a
            // singleton if the run does not reach two packets - so a pure-
            // ack connection never pays the collection, and a bulk response
            // pays one sendmsg per GSO_MAX_BATCH packets.
            int seg = n0;
            int count = 1;
            batchLens[0] = n0;
            while (QuicheBindings.UDP_GSO_SEND && count < GSO_MAX_BATCH) {
                long nk = QuicheBindings.quiche_conn_send(connPtr,
                        batchSlots.asSlice((long) count * SEND_BUFFER_SIZE, bufLen),
                        bufLen, sendInfoK);
                if (nk <= 0) {
                    // DONE or error: the batch stands; the next round's head
                    // pull reports it again (cheap - quiche's queue did not
                    // move).
                    break;
                }
                if (!sameSendDest(sendInfo, sendInfoK)) {
                    // A batch is one sendmsg to one destination: park this
                    // packet for the next round.
                    MemorySegment.copy(batchSlots, (long) count * SEND_BUFFER_SIZE,
                            batchSlots, (long) GSO_MAX_BATCH * SEND_BUFFER_SIZE,
                            (int) nk);
                    carry = true;
                    carryLen = (int) nk;
                    break;
                }
                if ((int) nk == seg) {
                    batchLens[count++] = (int) nk;
                    continue;
                }
                if ((int) nk < seg) {
                    // Short packet: legal only as the batch's final segment.
                    batchLens[count++] = (int) nk;
                    break;
                }
                // Larger than the segment size (possible when the head is a
                // short packet and quiche then produced a bigger one): it
                // cannot join as a segment; park it, the next batch starts
                // with its own segment size.
                MemorySegment.copy(batchSlots, (long) count * SEND_BUFFER_SIZE,
                        batchSlots, (long) GSO_MAX_BATCH * SEND_BUFFER_SIZE, (int) nk);
                carry = true;
                carryLen = (int) nk;
                break;
            }

            boolean batchOut = false;
            while (true) {
                long s;
                if (count == 1) {
                    s = QuicheBindings.sendDatagram(socketFd, batchSlots, n0, to,
                            useLen, from, scratchSend);
                } else {
                    s = QuicheBindings.sendSegmentedDatagram(socketFd, batchSlots,
                            batchLens, count, SEND_BUFFER_SIZE, seg, to, useLen,
                            from, batchScratch);
                }
                if (s >= 0) {
                    batchOut = true;
                    break;
                }
                int err = QuicheBindings.errno();
                if (err == QuicheBindings.EINTR) {
                    continue;
                }
                if (err == QuicheBindings.EAGAIN) {
                    // The segmented sendmsg is atomic: nothing of the batch
                    // reached the socket. Park the whole batch on the
                    // connection's pending queue (when there is a queue to
                    // park it on) so a later sweep resends it in order; a
                    // raw rejection path has none, and one dropped
                    // refuse-packet is exactly what the pre-batching code
                    // lost on its first EAGAIN.
                    if (pending != null) {
                        enqueuePending(pending, 0, count, to, useLen, from, fromLen);
                    } else if (log.isDebugEnabled()) {
                        log.debug("send EAGAIN: GSO batch dropped (no pending queue)");
                    }
                    retryNeeded = true;
                    break;
                }
                if (log.isDebugEnabled()) {
                    log.debug("sendmsg failed: " + QuicheBindings.strerror(err));
                }
                if (count > 1) {
                    // Hard error on a batch: fall back to exactly what the
                    // pre-GSO code would have done, packet by packet.
                    int i = 0;
                    boolean abort = false;
                    while (i < count) {
                        long s1 = QuicheBindings.sendDatagram(socketFd,
                                batchSlots.asSlice((long) i * SEND_BUFFER_SIZE,
                                        batchLens[i]),
                                batchLens[i], to, useLen, from, scratchSend);
                        if (s1 >= 0) {
                            i++;
                            continue;
                        }
                        int err1 = QuicheBindings.errno();
                        if (err1 == QuicheBindings.EINTR) {
                            continue;
                        }
                        if (err1 == QuicheBindings.EAGAIN) {
                            if (pending != null) {
                                enqueuePending(pending, i, count - i, to, useLen,
                                        from, fromLen);
                            }
                            retryNeeded = true;
                            abort = true;
                            break;
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("sendmsg failed: " + QuicheBindings.strerror(err1));
                        }
                        i++;
                    }
                    batchOut = !abort;
                    break;
                }
                break;
            }
            if (!batchOut) {
                // A carry that is still pending here already left quiche's
                // output queue but never joined a batch that made it onto the
                // socket: the loop is exiting without ever consuming it, so
                // its (method-local) state would be dropped and the datagram
                // silently lost until PTO retransmission - the exact outcome
                // the pending-send queue exists to prevent. Park it (with the
                // send_info recorded when it was pulled, which is why its
                // destination differs from the batch it could not join) and
                // ask for a retry sweep so a later flush drains it in order.
                if (carry && pending != null) {
                    enqueuePendingCarry(pending, carryLen, fallbackTo, fallbackToLen);
                    retryNeeded = true;
                }
                break;
            }
        }
        return retryNeeded;
    }


    /*
     * The two send_info destinations match exactly (address family, length
     * and the same address bytes on both directions) - the precondition for
     * sharing one sendmsg (and one PKTINFO pin) across a GSO batch. Fields
     * quiche does not apply on this path (timestamps, DSCP) may differ
     * freely; the wire header they would touch is not set here at all.
     */
    private static boolean sameSendDest(MemorySegment a, MemorySegment b) {
        int aToLen = a.get(ValueLayout.JAVA_INT, QuicheBindings.SEND_INFO_TO_LEN);
        int bToLen = b.get(ValueLayout.JAVA_INT, QuicheBindings.SEND_INFO_TO_LEN);
        if (aToLen != bToLen) {
            return false;
        }
        if (aToLen > 0 && MemorySegment.mismatch(a, QuicheBindings.SEND_INFO_TO,
                QuicheBindings.SEND_INFO_TO + aToLen, b, QuicheBindings.SEND_INFO_TO,
                QuicheBindings.SEND_INFO_TO + bToLen) != -1) {
            return false;
        }
        int aFromLen = a.get(ValueLayout.JAVA_INT, QuicheBindings.SEND_INFO_FROM_LEN);
        int bFromLen = b.get(ValueLayout.JAVA_INT, QuicheBindings.SEND_INFO_FROM_LEN);
        if (aFromLen != bFromLen) {
            return false;
        }
        if (aFromLen > 0 && MemorySegment.mismatch(a, QuicheBindings.SEND_INFO_FROM,
                QuicheBindings.SEND_INFO_FROM + aFromLen, b,
                QuicheBindings.SEND_INFO_FROM,
                QuicheBindings.SEND_INFO_FROM + bFromLen) != -1) {
            return false;
        }
        return true;
    }


    /*
     * Copies an unsent run of staged packets (batch slots from
     * {@code slotBase}, lengths from the matching batchLens entries) onto the
     * connection's pending-send queue, bounding it at the wrapper's cap by
     * dropping its OLDEST entries - the same loss the kernel's socket limit
     * already imposes on everything else.
     */
    private void enqueuePending(ArrayDeque<QuicheConnectionWrapper.PendingSend> queue,
            int slotBase, int count, MemorySegment to, int toLen, MemorySegment from,
            int fromLen) {
        byte[] toBytes = new byte[toLen];
        MemorySegment.copy(to, ValueLayout.JAVA_BYTE, 0, toBytes, 0, toLen);
        byte[] fromBytes = null;
        if (from != null && fromLen > 0) {
            fromBytes = new byte[fromLen];
            MemorySegment.copy(from, ValueLayout.JAVA_BYTE, 0, fromBytes, 0, fromLen);
        }
        for (int j = 0; j < count; j++) {
            int idx = slotBase + j;
            byte[] data = new byte[batchLens[idx]];
            MemorySegment.copy(batchSlots, ValueLayout.JAVA_BYTE,
                    (long) idx * SEND_BUFFER_SIZE, data, 0, data.length);
            queue.addLast(new QuicheConnectionWrapper.PendingSend(data, toBytes,
                    toLen, fromBytes));
        }
        while (queue.size() > QuicheConnectionWrapper.MAX_PENDING_SENDS) {
            queue.pollFirst();
        }
    }


    /*
     * Parks the carried packet (staged in the slot after the batch slots, its
     * send_info left in sendInfoK by the pull that could not join the batch)
     * onto the pending-send queue when the batch it rode with failed to leave
     * the socket. The destination is read from sendInfoK - the packet's own
     * - because that is what made it a carry; it falls back to the caller's
     * fallback destination exactly as the batch head's extraction does, and
     * an undeliverable carry is dropped rather than parked (mirroring the
     * head path's no-destination continue). Appended after the batch packets
     * (it was pulled after them) and bounded oldest-first like enqueuePending.
     */
    private void enqueuePendingCarry(ArrayDeque<QuicheConnectionWrapper.PendingSend> queue,
            int len, MemorySegment fallbackTo, int fallbackToLen) {
        int toLen = sendInfoK.get(ValueLayout.JAVA_INT, QuicheBindings.SEND_INFO_TO_LEN);
        MemorySegment to;
        int useLen;
        if (toLen > 0) {
            to = sendInfoK.asSlice(QuicheBindings.SEND_INFO_TO,
                    QuicheBindings.SOCKADDR_STORAGE_SIZE);
            useLen = toLen;
        } else if (fallbackToLen > 0) {
            to = fallbackTo;
            useLen = fallbackToLen;
        } else {
            return;
        }
        int fromLen = sendInfoK.get(ValueLayout.JAVA_INT,
                QuicheBindings.SEND_INFO_FROM_LEN);
        byte[] fromBytes = null;
        if (fromLen > 0) {
            fromBytes = new byte[fromLen];
            MemorySegment.copy(sendInfoK, ValueLayout.JAVA_BYTE,
                    QuicheBindings.SEND_INFO_FROM, fromBytes, 0, fromLen);
        }
        byte[] toBytes = new byte[useLen];
        MemorySegment.copy(to, ValueLayout.JAVA_BYTE, 0, toBytes, 0, useLen);
        byte[] data = new byte[len];
        MemorySegment.copy(batchSlots, ValueLayout.JAVA_BYTE,
                (long) GSO_MAX_BATCH * SEND_BUFFER_SIZE, data, 0, len);
        queue.addLast(new QuicheConnectionWrapper.PendingSend(data, toBytes,
                useLen, fromBytes));
        while (queue.size() > QuicheConnectionWrapper.MAX_PENDING_SENDS) {
            queue.pollFirst();
        }
    }


    // ------------------------------------- Close detection / teardown

    /*
     * Surfaces a negative quiche_conn_recv/send result: read the connection's
     * local error, log it and tear the connection down (the close-detection
     * analogue of the OpenSSL EC/ECD handling).
     */
    private void noteConnectionError(QuicheConnectionWrapper conn, long rc, String where) {
        boolean isApp;
        long code;
        String reasonText;
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment isAppSeg = localArena.allocate(ValueLayout.JAVA_BOOLEAN);
            MemorySegment codeSeg = localArena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment reasonSeg = localArena.allocate(ValueLayout.ADDRESS);
            MemorySegment reasonLenSeg = localArena.allocate(ValueLayout.JAVA_LONG);
            isApp = QuicheBindings.quiche_conn_local_error(conn.getConn(), isAppSeg,
                    codeSeg, reasonSeg, reasonLenSeg);
            if (!isApp) {
                // No local error (e.g. a transient recv parse rejection):
                // log and let the normal close detection decide.
                if (log.isDebugEnabled()) {
                    log.debug("quiche_conn_" + where + " error " + rc +
                            " on 0x" + Long.toHexString(conn.getConnAddress()));
                }
                return;
            }
            code = codeSeg.get(ValueLayout.JAVA_LONG, 0);
            reasonText = readReason(reasonSeg, reasonLenSeg);
        }
        log.warn(sm.getString("quicheEndpoint.localConnectionError",
                Long.toHexString(conn.getConnAddress()),
                Long.valueOf(code), String.valueOf(reasonText)));
        teardownConnection(conn);
    }


    private static String readReason(MemorySegment reasonSeg, MemorySegment reasonLenSeg) {
        MemorySegment data = reasonSeg.get(ValueLayout.ADDRESS, 0);
        long len = reasonLenSeg.get(ValueLayout.JAVA_LONG, 0);
        if (data.equals(MemorySegment.NULL) || len == 0) {
            return null;
        }
        byte[] bytes = data.reinterpret(len).toArray(ValueLayout.JAVA_BYTE);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }


    /**
     * Close detection (port of the OpenSSL EC→ECD two-phase, collapsed into
     * loop-driven detection): a locally-initiated close stays in the live set
     * until {@code quiche_conn_is_closed()} confirms the close frame left; a
     * peer close / drain / idle timeout tears down on observation.
     */
    private void detectClose(QuicheConnectionWrapper conn) {
        // No on_timeout() here: processConnection() runs it unconditionally
        // immediately before this method in the same iteration (it also
        // covers the draining timer that is_timed_out() does not track).
        boolean closed = QuicheBindings.quiche_conn_is_closed(conn.getConn()) ||
                conn.isClosed();
        if (!closed && conn.isClosing() && QuicheBindings.quiche_conn_is_draining(conn.getConn())) {
            // The close frame has left; the connection enters its draining
            // quiet period. is_closed() will follow; keep it live until then
            // so retransmits keep going out.
            return;
        }
        if (closed) {
            logPeerError(conn);
            teardownConnection(conn);
        }
    }


    private void logPeerError(QuicheConnectionWrapper conn) {
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment isAppSeg = localArena.allocate(ValueLayout.JAVA_BOOLEAN);
            MemorySegment codeSeg = localArena.allocate(ValueLayout.JAVA_LONG);
            MemorySegment reasonSeg = localArena.allocate(ValueLayout.ADDRESS);
            MemorySegment reasonLenSeg = localArena.allocate(ValueLayout.JAVA_LONG);
            if (QuicheBindings.quiche_conn_peer_error(conn.getConn(), isAppSeg, codeSeg,
                    reasonSeg, reasonLenSeg)) {
                log.debug(sm.getString("quicheEndpoint.peerConnectionError",
                        Long.toHexString(conn.getConnAddress()),
                        Long.valueOf(codeSeg.get(ValueLayout.JAVA_LONG, 0)),
                        readReason(reasonSeg, reasonLenSeg)));
            }
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("Error reading peer connection error", t);
            }
        }
    }


    /**
     * Tears a connection down: remove from all maps, wake parked waiters,
     * terminal-dispatch the bidi stream handlers, deregister the streams,
     * close the protocol manager and free the connection (deferred while
     * handlers are still active). Runs on the poll thread (or the stop
     * thread once the loop is stopped).
     */
    private void teardownConnection(QuicheConnectionWrapper conn) {
        if (!conn.markTeardownStarted()) {
            // Teardown already ran. The JVM-side closed flag alone is not
            // the dedup key: it can be set by paths that do not tear the
            // connection down (e.g. a worker-side failConnection whose hop
            // to this thread failed), and the loop's sweep of such
            // connections must still be able to reach this method.
            return;
        }
        assertNativeAccess("teardownConnection");
        long addr = conn.getConnAddress();
        connections.remove(addr, conn);
        pendingConns.remove(addr, conn);
        cidMap.values().removeIf(v -> v == conn);
        // Protocol data queued when the connection dies can never be
        // flushed (the flush runs only for registered connections), so
        // clear the mark here to keep the endpoint-wide pending tally
        // balanced; otherwise the poll loop takes the protocol-data
        // branch at the idle cadence for the endpoint's lifetime.
        setConnectionProtocolDataPending(conn, false);

        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        ConcurrentHashMap<Long, QuicheSocketWrapper> wrappers = streamWrappers.remove(Long.valueOf(addr));
        if (wrappers != null) {
            QuicConnectionManager.ConnectionState state =
                    (connManager != null) ? connManager.getState(conn) : null;
            for (QuicheSocketWrapper wrapper : wrappers.values()) {
                wrapper.signalReadWaiter();
                wrapper.signalWriteWaiter();
                QuicheStreamWrapper stream = wrapper.getSocket();
                if (stream == null) {
                    continue;
                }
                if (state != null && stream.getStreamType() == QuicheStreamWrapper.TYPE_BIDI) {
                    state.decrementActiveStreams();
                }
                stream.setDeregistered();
                // Wake-up (OPEN_READ) plus terminal (ERROR) dispatch for every
                // live wrapper (port of the OpenSSL connection-close
                // dispatches): a pending Read Listener parked on a
                // non-blocking async read holds no processing claim, and
                // gating on it would abandon the listener without
                // onError/onAllDataRead. Completed requests have closed their
                // wrapper and are skipped; a handler that claimed the stream
                // observes the closed stream through its read in flight.
                if (!wrapper.isClosed()) {
                    // Scheduled (claim-retrying) dispatches: a single CAS
                    // attempt would silently drop both events while a slow
                    // dispatch still holds the claim, leaving a pending read
                    // listener with no EOF/error report.
                    scheduleStreamDispatch(wrapper, stream, SocketEvent.OPEN_READ);
                    scheduleStreamDispatch(wrapper, stream,
                            SocketEvent.ERROR);
                }
            }
        }
        conn.closeAllStreams();
        conn.setClosed();
        if (connManager != null) {
            conn.setQuicConnectionManager(null);
            connManager.connectionClose(conn);
        }
        freeConnectionOrDefer(conn);
    }


    /**
     * Removes a stream whose HTTP handler finished (called via the socket
     * wrapper's close path). quiche streams have no native object to free;
     * an unconcluded stream gets an error-0 RESET_STREAM, the quiche parity
     * of OpenSSL's SSL_free-on-unconcluded-stream behaviour, and bidirectional
     * streams additionally get an error-0 READ shutdown (STOP_SENDING unless
     * the client already finished) so late client data cannot re-fire the
     * readable edge and re-enter the dispatch path for a finalised stream.
     * Runs on the poll thread.
     */
    void closeStreamByHandler(QuicheStreamWrapper stream) {
        QuicheConnectionWrapper conn = stream.getConnection();
        if (conn == null) {
            return;
        }
        stream.setDeregistered();
        conn.getStreams().remove(Long.valueOf(stream.getStreamId()));
        long addr = conn.getConnAddress();
        ConcurrentHashMap<Long, QuicheSocketWrapper> wrappers =
                streamWrappers.get(Long.valueOf(addr));
        QuicheSocketWrapper wrapper = null;
        if (wrappers != null) {
            wrapper = wrappers.remove(Long.valueOf(stream.getStreamId()));
        }
        if (wrapper != null) {
            wrapper.signalReadWaiter();
            wrapper.signalWriteWaiter();
        }
        QuicConnectionManager connManager = conn.getQuicConnectionManager();
        QuicConnectionManager.ConnectionState state =
                (connManager != null) ? connManager.getState(conn) : null;
        if (state != null && stream.getStreamType() == QuicheStreamWrapper.TYPE_BIDI) {
            state.decrementActiveStreams();
        }
        if (!conn.isClosed() && !conn.isFreed()) {
            if (!stream.isConcluded()) {
                QuicheBindings.quiche_conn_stream_shutdown(conn.getConn(),
                        stream.getStreamId(), QuicheBindings.QUICHE_SHUTDOWN_WRITE, 0L);
            }
            if (stream.getStreamType() == QuicheStreamWrapper.TYPE_BIDI) {
                // Quiesce the read direction as well. The bookkeeping removal
                // above is not the end of the stream: a client that is still
                // sending (aborted upload, or a response that completed
                // before the request body arrived) keeps buffering data in
                // quiche, which re-fires the edge-driven readable set and
                // re-enters processAcceptedBidi for a stream the protocol
                // already finalised (duplicate dispatch, or a re-rejection
                // when the limit happens to bite). A READ shutdown drops the
                // buffered data, removes the stream from quiche's readable
                // set and keeps it permanently non-readable, and sends
                // STOP_SENDING unless the client already sent FIN (which is
                // why concluded streams are included here too). The error
                // code matches the RESET_STREAM above.
                QuicheBindings.quiche_conn_stream_shutdown(conn.getConn(),
                        stream.getStreamId(), QuicheBindings.QUICHE_SHUTDOWN_READ, 0L);
            }
        }
        stream.setFreed();
        if (wrappers != null && wrappers.isEmpty()) {
            streamWrappers.remove(Long.valueOf(addr), wrappers);
        }
    }


    // ------------------------------------- Failure / reset

    /**
     * Fails a connection with an application protocol error: queue the
     * CONNECTION_CLOSE; the packet loop transmits it and the close detection
     * tears the connection down once it has left. Must run on the poll
     * thread (worker entries hop through
     * {@link QuicheConnectionWrapper#failConnection}).
     *
     * @param conn       The connection
     * @param errorCode  The application protocol error code
     * @param reason     A diagnostic reason phrase
     */
    void failConnection(QuicheConnectionWrapper conn, long errorCode, String reason) {
        assertNativeAccess("failConnection");
        if (conn.isClosed() || conn.isFreed()) {
            return;
        }
        if (log.isDebugEnabled()) {
            log.debug("Failing connection 0x" + Long.toHexString(conn.getConnAddress()) +
                    " with code " + errorCode + ": " + reason);
        }
        queueConnectionClose(conn, errorCode, reason);
    }


    private void queueConnectionClose(QuicheConnectionWrapper conn, long errorCode,
            String reason) {
        if (conn.isClosing()) {
            return;
        }
        conn.setClosing();
        if (QuicheBindings.quiche_conn_is_established(conn.getConn())) {
            QuicheBindings.quiche_conn_close(conn.getConn(), true, errorCode,
                    MemorySegment.NULL, 0);
        } else {
            // quiche discards an application error code when the handshake
            // is not established, rewriting the close to transport error
            // 0x0c (protocol violation). Request an explicit transport close
            // instead so the peer receives an intentional code; the
            // application diagnostic code cannot be carried pre-handshake.
            if (log.isDebugEnabled()) {
                log.debug("Connection 0x" + Long.toHexString(conn.getConnAddress()) +
                        " not established; app error " + errorCode +
                        " (" + reason + ") cannot be sent, closing with" +
                        " transport CONNECTION_REFUSED");
            }
            QuicheBindings.quiche_conn_close(conn.getConn(), false,
                    QuicheBindings.QUICHE_TRANSPORT_CONNECTION_REFUSED,
                    MemorySegment.NULL, 0);
        }
    }


    /**
     * Resets a stream with the given application protocol error code via
     * {@code quiche_conn_stream_shutdown(WRITE, code)} (RESET_STREAM).
     * Must run on the poll thread.
     *
     * @param stream The stream to reset
     * @param errorCode The application protocol error code
     *
     * @return {@code true} if the reset took effect
     */
    boolean resetStream(QuicheStreamWrapper stream, long errorCode) {
        QuicheConnectionWrapper conn = stream.getConnection();
        if (conn == null || conn.isClosed() || conn.isFreed()) {
            return false;
        }
        int rc = QuicheBindings.quiche_conn_stream_shutdown(conn.getConn(),
                stream.getStreamId(), QuicheBindings.QUICHE_SHUTDOWN_WRITE, errorCode);
        if (rc == 0) {
            return true;
        }
        if (log.isDebugEnabled()) {
            log.debug("Reset of stream " + stream.getStreamId() +
                    " returned " + rc + " (stream may already be gone)");
        }
        return false;
    }


    // ------------------------------------- Dispatch machinery

    private QuicheSocketWrapper getSocketWrapper(long connAddr, long streamId) {
        ConcurrentHashMap<Long, QuicheSocketWrapper> perConn =
                streamWrappers.get(Long.valueOf(connAddr));
        return perConn == null ? null : perConn.get(Long.valueOf(streamId));
    }


    /**
     * Dispatches the given event for the stream to the protocol executor,
     * optionally taking over ownership of the stream's processing flag from
     * the caller (port of the OpenSSL dispatchToExecutor).
     */
    private void dispatchToExecutor(QuicheSocketWrapper wrapper,
            QuicheStreamWrapper stream, SocketEvent event, boolean flagClaimed) {
        if (!flagClaimed && !stream.compareAndSetProcessing(false, true)) {
            return;
        }
        QuicheConnectionWrapper conn = stream.getConnection();
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
            // connection-less stream). Inline processing is only safe on
            // the poll thread, where the handler's wrapper I/O runs its
            // native operations directly; any other thread (a stop-path
            // drain running a queued dispatch after shutdownExecutor()
            // tore the executor down) would park the handler in a mailbox
            // hop that nothing services until the hop timeout - the
            // drainer being blocked inside the handler it would have to
            // drain. Drop the dispatch the way a rejecting pool does.
            if (isPollThread()) {
                dispatch.run();
                return;
            }
            log.warn(sm.getString("quicheEndpoint.dispatchNoExecutor",
                    Long.valueOf(stream.getStreamId())));
            stream.clearProcessing();
            wakeClaimWaiters(stream, conn);
            if (conn != null) {
                conn.decrActiveHandlers();
                if (!conn.isClosing() && !conn.isClosed()) {
                    failConnection(conn, getConnectionRejectErrorCode(),
                            "No executor available for the dispatch of stream " +
                                    Long.valueOf(stream.getStreamId()));
                }
            }
            return;
        }
        try {
            executor.execute(dispatch);
        } catch (java.util.concurrent.RejectedExecutionException ree) {
            // A rejecting pool will never run the task; release the claim
            // and the active-handler count. Do NOT run inline (a full
            // request on the poll thread stalls every other connection);
            // treat the overload as fatal for the connection.
            log.warn(sm.getString("quicheEndpoint.dispatchRejected",
                    Long.valueOf(stream.getStreamId())), ree);
            stream.clearProcessing();
            wakeClaimWaiters(stream, conn);
            if (conn != null) {
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
     * Runs one dispatch of the HTTP handler for a claimed stream: invokes
     * the handler, releases the processing claim and completes the active-
     * handler accounting. Both dispatch paths funnel through here (port of
     * the OpenSSL runStreamDispatch).
     */
    private void runStreamDispatch(QuicheSocketWrapper wrapper,
            QuicheStreamWrapper stream, QuicheConnectionWrapper conn,
            SocketEvent event, boolean longRearm) {
        try {
            AbstractEndpoint.Handler.SocketState state = processSocketInline(wrapper, event);
            if (log.isDebugEnabled()) {
                log.debug("processSocketInline returned: streamId=" + stream.getStreamId()
                        + " state=" + state);
            }
            if (longRearm && state == AbstractEndpoint.Handler.SocketState.LONG) {
                // Drain write data the handler may have left in the buffer;
                // doWrite() re-arms write interest itself if data remains.
                try {
                    wrapper.flushNonBlocking();
                } catch (IOException ioe) {
                    if (log.isDebugEnabled()) {
                        log.debug("Pending write flush failed on stream " +
                                stream.getStreamId(), ioe);
                    }
                }
                // Processor wants more I/O: no read re-registration is needed
                // (unlike the OpenSSL original). quiche owns readiness: the
                // readable sweep re-dispatches when new data arrives, the
                // level re-arm covers a waiter parked on buffered data, and
                // the pending-dispatch replay covers an OPEN_READ that the
                // claim budget dropped while this dispatch was running.
            }
        } finally {
            // Clear the processing flag BEFORE the active-handler count is
            // decremented: once clear, the poll thread may tear the stream
            // down, so no native operation may follow. The claim waiters go
            // through the mailbox (no native operation either), so a
            // dispatch blocked on this claim re-runs promptly on the next
            // poll iteration instead of ever spinning for it.
            stream.clearProcessing();
            wakeClaimWaiters(stream, conn);
            finishStreamDispatch(conn);
        }
    }


    /**
     * Re-runs the parked claim-retry attempts of a stream whose processing
     * claim has just been released (scheduleStreamDispatch parks them
     * here). Each waiter carries its own active-handler reference, which it
     * balances itself when it runs; a waiter that cannot be submitted (the
     * mailbox is closed - the endpoint is stopping) has its reference
     * balanced here, mirroring the scheduling-side handling.
     *
     * @param stream The stream whose waiters to re-run
     * @param conn   The stream's connection (may be {@code null})
     */
    private void wakeClaimWaiters(QuicheStreamWrapper stream,
            QuicheConnectionWrapper conn) {
        Runnable waiter;
        while ((waiter = stream.pollClaimWaiter()) != null) {
            if (conn == null || !submitConnPollTask(conn, waiter)) {
                finishStreamDispatch(conn);
            }
        }
    }


    /**
     * Completes a stream dispatch: decrements the connection's active handler
     * count and performs the connection free the poll thread deferred while
     * a worker was still running. The OpenSSL original additionally takes the
     * stream and a completed-dispatch flag to finish a deferred stream SSL
     * free there is nothing to mirror on quiche.
     */
    private void finishStreamDispatch(QuicheConnectionWrapper conn) {
        if (conn == null) {
            return;
        }
        int remaining = conn.decrActiveHandlers();
        if (remaining == 0 && conn.clearPendingFree()) {
            // Last worker on a connection whose free was deferred: free it,
            // on the poll thread.
            submitConnPollTask(conn, () -> conn.freeConnOnce());
        }
    }


    /**
     * Re-queues a dispatch whose processing flag is still claimed (port of
     * the OpenSSL scheduleStreamDispatch): the event must not be dropped
     * (async re-dispatch events are not level-triggered), so the attempt
     * parks as a claim waiter on the stream and is re-run by the dispatch
     * that releases the claim, handing the event to the readable sweep's
     * replay (or dropping it, for events without a replay path) once its
     * budget expires without the claim having freed.
     */
    private void scheduleStreamDispatch(QuicheSocketWrapper wrapper,
            QuicheStreamWrapper stream, SocketEvent event) {
        scheduleStreamDispatch(wrapper, stream, event, false);
    }


    /**
     * @param abortIfDeregistered Whether the retry chain gives up once the
     *        stream has been deregistered (handler completion / teardown).
     *        Teardown's own terminal dispatches pass {@code false}: those
     *        are scheduled after the deregistration flag is set.
     */
    private void scheduleStreamDispatch(QuicheSocketWrapper wrapper,
            QuicheStreamWrapper stream, SocketEvent event,
            boolean abortIfDeregistered) {
        QuicheConnectionWrapper conn = stream.getConnection();
        if (conn != null) {
            // Hold an active-handler reference from scheduling onwards so the
            // connection cannot be freed before this dispatch (or its
            // give-up) completes.
            conn.incrActiveHandlers();
        }
        long deadline = System.nanoTime() +
                TimeUnit.MILLISECONDS.toNanos(STREAM_CLAIM_BUDGET_MS);
        // submitPollTask can fail once the mailbox is closed (endpoint
        // stopping). The active-handler reference taken above is then the
        // only thing left to release: finishStreamDispatch balances the
        // count and, if it drops the last handler of a connection whose
        // free was deferred, submits that free - which is rejected in the
        // same situation. The free then falls to the stop path, whose bulk
        // loop only sees still-registered connections: for one teardown
        // already removed from the map it is left to the
        // QuicheConnectionWrapper Cleaner (a bounded delay, not a
        // guaranteed stop-path free). Without this the count would stay
        // elevated forever on a wrapper the endpoint has already detached.
        if (!submitConnPollTask(conn, new Runnable() {
            @Override
            public void run() {
                // Register as a claim waiter before touching the claim, and
                // stay registered while this attempt is in flight: the
                // dispatch holding the claim drains the stream's waiters
                // after clearing the flag, so either this attempt wins the
                // freed claim or the release re-runs it. The retry must
                // never resubmit itself from here: a self-resubmitting task
                // re-enters the very mailbox drain that is running it, that
                // drain then never terminates, and the retry runs at drain
                // rate instead of on releases (measured on the cap500
                // 8x190 shape: 381M retry runs for 249 schedules - ~1.5M
                // per chain, the claim essentially never won inside
                // budget, and every other poll-loop job starved).
                stream.addClaimWaiter(this);
                if (abortIfDeregistered && (stream.isDeregistered() || stream.isFreed())) {
                    stream.removeClaimWaiter(this);
                    finishStreamDispatch(conn);
                    return;
                }
                if (stream.compareAndSetProcessing(false, true)) {
                    stream.removeClaimWaiter(this);
                    dispatchToExecutor(wrapper, stream, event, true);
                    // Release the scheduling reference; the executor dispatch
                    // carries its own until its processor finishes.
                    finishStreamDispatch(conn);
                    return;
                }
                if (System.nanoTime() - deadline < 0) {
                    // Claim still held: stay registered and let the
                    // releasing dispatch re-run this attempt.
                    return;
                }
                stream.removeClaimWaiter(this);
                if (event == SocketEvent.OPEN_READ && abortIfDeregistered &&
                        conn != null) {
                    // The readable edge was already popped by the readable
                    // sweep, and this transport has no read-interest
                    // re-registration - dropping the event would strand the
                    // buffered data on a quiet stream. Hand the dispatch to
                    // the readable sweep's replay instead of dropping it.
                    conn.getPendingReadDispatches().add(stream);
                    sweepRetryConns.add(conn);
                    if (log.isDebugEnabled()) {
                        log.debug("Stream " + stream.getStreamId() + " still busy" +
                                " after the claim budget - " + event +
                                " dispatch deferred to the readable sweep replay");
                    }
                } else if (log.isDebugEnabled()) {
                    log.debug("Stream " + stream.getStreamId() + " still busy" +
                            " after the claim budget - " + event +
                            " dispatch dropped");
                }
                finishStreamDispatch(conn);
            }
        })) {
            finishStreamDispatch(conn);
        }
    }


    /**
     * Processes a socket event through the HTTP handler. May run on the poll
     * thread (inline fallback, connection teardown) or on an executor
     * worker; native QUIC operations are hopped to the poll thread by the
     * socket wrapper either way.
     */
    private AbstractEndpoint.Handler.SocketState processSocketInline(
            QuicheSocketWrapper wrapper, SocketEvent event) {
        AbstractEndpoint.Handler.SocketState state = AbstractEndpoint.Handler.SocketState.CLOSED;

        if (!wrapper.isClosed()) {
            try {
                wrapper.checkError();
            } catch (IOException x) {
                event = SocketEvent.ERROR;
                wrapper.setError(x);
                log.error(sm.getString("quicheEndpoint.socketCheckError"), x);
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
                log.error(sm.getString("quicheEndpoint.handlerProcessError"), t);
                wrapper.close();
                state = AbstractEndpoint.Handler.SocketState.CLOSED;
            }
        }
        return state;
    }


    // ------------------------------------- Protocol error codes

    long getDefaultStreamErrorCode() {
        return errorCode(getQuicProtocol(), QuicProtocol::getDefaultStreamErrorCode);
    }

    private long getConnectionRejectErrorCode() {
        return errorCode(getQuicProtocol(), QuicProtocol::getConnectionRejectErrorCode);
    }

    private long getStreamRejectErrorCode() {
        return errorCode(getQuicProtocol(), QuicProtocol::getStreamRejectErrorCode);
    }

    private long getGracefulShutdownErrorCode() {
        return errorCode(getQuicProtocol(), QuicProtocol::getGracefulShutdownErrorCode);
    }

    /*
     * Shared null-guard for the protocol error-code accessors: without a
     * protocol (not started yet / already stopped) report code 0.
     */
    private static long errorCode(QuicProtocol protocol, ToLongFunction<QuicProtocol> code) {
        return protocol == null ? 0 : code.applyAsLong(protocol);
    }


    // ------------------------------------- Socket Processor

    /*
     * Currently unreached scaffolding: this processor is only ever created
     * through AbstractEndpoint.processSocket() -> createSocketProcessor(),
     * and no code path dispatches a QUIC wrapper through processSocket -
     * both QUIC endpoints run their own dispatchToExecutor() ->
     * executor.execute(lambda) path, so the claim/requeue/cache logic below
     * has no production caller today. The override exists because
     * AbstractEndpoint declares createSocketProcessor() abstract. Reason
     * about dispatch from dispatchToExecutor()/runStreamDispatch(), not
     * from this class. (The OpenSSL endpoint has the same unreached shape;
     * the QuicOpenSSLEndpoint comments that cite QuicSocketProcessor.doRun()
     * as a live path are stale in the same way.)
     */
    private class QuicSocketProcessor extends SocketProcessorBase<QuicStream> {

        private QuicSocketProcessor(SocketWrapperBase<QuicStream> socket,
                SocketEvent event) {
            super(socket, event);
        }


        @Override
        protected void doRun() {
            QuicheStreamWrapper stream = (QuicheStreamWrapper) socketWrapper.getSocket();
            QuicheConnectionWrapper conn = (stream != null) ? stream.getConnection() : null;
            if (conn != null) {
                conn.incrActiveHandlers();
            }
            boolean claimed = false;
            boolean requeued = false;
            try {
                // Claim the stream for the duration of this dispatch, the
                // same way the poll-path dispatch does in
                // dispatchToExecutor(): concurrent handler execution on the
                // same wrapper is exactly what the flag prevents.
                if (stream != null) {
                    claimed = stream.compareAndSetProcessing(false, true);
                    if (!claimed) {
                        // A poll-path dispatch owns the stream. The event is
                        // not level-triggered, so re-queue it rather than
                        // dropping it.
                        scheduleStreamDispatch(
                                (QuicheSocketWrapper) socketWrapper, stream, event);
                        requeued = true;
                        return;
                    }
                }

                if (stream != null) {
                    // Shared dispatch core with the poll path. No LONG
                    // re-arm: async re-dispatch events do not drive read
                    // interest.
                    runStreamDispatch((QuicheSocketWrapper) socketWrapper,
                            stream, conn, event, false);
                } else {
                    processSocketInline((QuicheSocketWrapper) socketWrapper, event);
                }
            } finally {
                if (!claimed) {
                    finishStreamDispatch(conn);
                }
                // Return the processor to the cache only after this run's
                // cleanup has finished; never push on the re-queued path,
                // whose event is now owned by scheduleStreamDispatch().
                if (!requeued && processorCache != null) {
                    SocketProcessorBase<QuicStream> sc = this;
                    processorCache.push(sc);
                }
            }
        }
    }
}

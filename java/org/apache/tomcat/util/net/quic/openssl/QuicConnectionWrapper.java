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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.net.quic.QuicConnection;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicStream;
import org.apache.tomcat.util.openssl.openssl_h;
import org.apache.tomcat.util.res.StringManager;

/**
 * Wraps a QUIC connection (an {@code SSL *} representing a QUIC-level
 * connection between a client and the server) and implements the
 * QUIC transport view {@link QuicConnection} the application protocol layer
 * (HTTP/3) operates on.
 * <p>
 * Each connection manages its own set of {@link QuicStreamWrapper} instances
 * and has a {@link QuicPollItem} for event-driven connection lifecycle events.
 */
public class QuicConnectionWrapper implements QuicConnection {

    private static final Log log = LogFactory.getLog(QuicConnectionWrapper.class);
    private static final StringManager sm =
            StringManager.getManager(QuicOpenSSLEndpoint.class);

    private static final Cleaner cleaner = Cleaner.create();

    /**
     * The native SSL* pointer for this connection.
     */
    private final MemorySegment ssl;

    /**
     * Poll item for this connection.
     */
    private QuicPollItem pollItem;

    /**
     * Map of stream ID to stream wrapper.
     */
    private final ConcurrentHashMap<Long, QuicStreamWrapper> streams = new ConcurrentHashMap<>();

    /**
     * Streams accepted before the connection's HTTP/3 state exists. An
     * accepted stream is not added to the poll set immediately; it is parked
     * here and promoted by the endpoint (via
     * {@code QuicOpenSSLEndpoint.addPendingStreamsToPollSet}) once the server
     * control stream has been created through the connection's
     * {@link QuicConnectionManager}. Poll-set membership drives event
     * delivery, so parking delays stream events - and therefore request
     * dispatch - until the server has committed its SETTINGS.
     */
    private final CopyOnWriteArrayList<QuicStreamWrapper> pendingStreams =
            new CopyOnWriteArrayList<>();

    /**
     * The negotiated ALPN protocol (e.g., "h3").
     */
    private volatile String negotiatedProtocol;

    /**
     * The SNI host name sent by the client. Read once on the poll thread
     * during connection setup and cached so worker threads never make a
     * native call on the connection SSL. {@code null} only if the
     * setup-time read has not (successfully) happened; an empty string
     * means the client sent no SNI.
     */
    private volatile String sniHostName;

    /**
     * Whether the SNI host name has been resolved authoritatively. An empty
     * cached {@link #sniHostName} is otherwise ambiguous between "the client
     * sent no SNI" and "not read yet": the accept path may cache an empty
     * value before the handshake is complete, and the stream-event path then
     * needs to retry the native {@code SSL_get_servername()} read. Once the
     * handshake has completed and the read returned empty, this flag lets
     * that path stop re-reading on every stream event.
     */
    private volatile boolean sniResolved;

    /**
     * Remote address (client).
     */
    private volatile InetSocketAddress remoteAddress;

    /**
     * Local address (server).
     */
    private volatile InetSocketAddress localAddress;

    /**
     * The application protocol connection manager registered for this
     * connection by the endpoint at connection accept.
     */
    private volatile QuicConnectionManager quicConnectionManager;


    /**
     * Whether the connection is closing.
     */
    private volatile boolean closing;

    /**
     * Whether the connection has been fully closed.
     */
    private volatile boolean closed;

    /**
     * Application error code supplied to the first {@code SSL_shutdown_ex()}
     * call that initiated the local connection close. The shutdown can complete
     * only after the stream SSLs are freed, and the completing
     * {@code SSL_shutdown_ex()} call must present the same error code again:
     * OpenSSL's {@code ossl_quic_channel_local_close()} uses the arguments
     * passed to the call that finishes the stream-flush phase. Zero is a valid
     * code (no application error).
     */
    private volatile long connectionCloseErrorCode;

    /**
     * Whether the stream-limit GOAWAY notification has already been queued on
     * this connection. RFC 9114 Section 5.2 requires successive GOAWAY
     * identifiers not to increase; once the limit notification has been sent,
     * further refused streams only need their RESET_STREAM, not another
     * GOAWAY frame appended to the primary stream buffer. Set on the poll
     * thread.
     */
    private volatile boolean streamLimitGoawaySent;

    /**
     * Whether the native SSL object has been freed.
     * Prevents double-free from both explicit cleanup and Cleaner.
     * <p>
     * An {@link AtomicBoolean} shared with the Cleaner's {@link State} so the
     * State can check/set the flag WITHOUT holding a strong reference to this
     * wrapper. Holding the wrapper strongly from the (static) Cleaner would
     * keep every connection alive forever, leaking the wrapper, its streams
     * and poll items.
     */
    private final AtomicBoolean freed = new AtomicBoolean(false);

    /**
     * Set when freeing any stream SSL of this connection failed. The
     * connection SSL must then never be freed, because OpenSSL requires every
     * stream SSL to be released first and a failed free may have left a
     * native stream object alive even though its Java wrapper is marked
     * {@code freed}. This is deliberately sticky: retrying a failed
     * {@code SSL_free} is unsafe (it may already have partially run), so the
     * connection is retained/leaked rather than freed under a live stream.
     */
    private final AtomicBoolean streamFreeFailed = new AtomicBoolean(false);

    /**
     * Set when freeing the connection SSL itself failed. A failed
     * {@code SSL_free} may have partially run, so retrying it is unsafe; the
     * connection must be retained/leaked rather than reported as freed. The
     * freed CAS is reset on this failure so the Java side never claims the
     * native object is gone, while this sticky flag prevents a later
     * explicit/cleaner free attempt.
     */
    private final AtomicBoolean connectionFreeFailed = new AtomicBoolean(false);

    /**
     * Guards the one-time warning emitted when a sticky stream-free failure
     * makes this connection permanently retained and counted against the
     * endpoint's connection limits. Later sweeps still see the same failure,
     * so the warning is logged once per connection instead of on every poll
     * or stop sweep.
     */
    private final AtomicBoolean retentionWarningLogged = new AtomicBoolean(false);

    /**
     * Number of executor worker threads currently executing the HTTP handler
     * for a stream on this connection. While greater than zero, the native
     * connection SSL object (and the stream SSLs it owns) must NOT be freed,
     * because a worker may still be about to make a native call on the poll
     * thread. The connection SSL free is deferred until this count reaches
     * zero (see {@link #pendingFree}).
     */
    private final AtomicInteger activeHandlers = new AtomicInteger(0);

    /**
     * Dispatch tasks queued in the executor that have not started yet. Each
     * record carries an atomic claim shared by the task and the stop path:
     * the task claims it before running, and the stop path claims it only to
     * balance tasks that never started. A task that has already started keeps
     * its active-handler reference and runs normally; it is never balanced by
     * the stop path. This works for executors whose shutdownNow() does not
     * cancel already-submitted tasks (for example VirtualThreadExecutor) as
     * well as for a ThreadPoolExecutor whose termination timed out.
     */
    private final ConcurrentLinkedQueue<QueuedDispatch> queuedDispatchStreams =
            new ConcurrentLinkedQueue<>();

    /**
     * Set when the poll thread wants to free this connection's SSL but must
     * wait for {@link #activeHandlers} to reach zero. The worker that decrements
     * the count to zero clears this flag and schedules the free on the poll
     * thread.
     */
    private final AtomicBoolean pendingFree = new AtomicBoolean(false);

    /**
     * Set when a connection teardown has been started. A teardown is a
     * one-shot operation: it frees stream and connection SSL objects and runs
     * native flush callbacks, so a second invocation must not repeat it (for
     * example after a protocol worker reports a second error, or when the
     * peer close races a protocol failure). This mirrors the
     * markTeardownStarted()/CAS protocol of the quiche/ngtcp2 wrappers.
     */
    private final AtomicBoolean teardownStarted = new AtomicBoolean(false);

    /**
     * The server-initiated unidirectional streams of this connection, keyed
     * by the protocol-assigned stream index (index 0 is the primary stream
     * the endpoint uses for its own writes, e.g. the HTTP/3 control stream).
     * Populated by {@link #registerServerUniStream(int, QuicStreamWrapper)}
     * when the stream is created.
     */
    private final ConcurrentHashMap<Integer, QuicStreamWrapper> serverUniStreams =
            new ConcurrentHashMap<>();

    /**
     * Connection-level {@link org.apache.tomcat.util.net.SSLSupport} cache.
     * The negotiated cipher suite,
     * session id and peer certificate chain are properties of the TLS
     * connection, not of an individual QUIC stream, so every stream wrapper
     * that shares this connection reports the same values. Caching them here
     * (rather than on each stream wrapper) means the native reads and - for the
     * peer chain - the X.509 parsing are performed once per connection instead
     * of once per stream. All values are resolved on the poll thread; the fields
     * are volatile so the cached result is visible to the worker threads that
     * read them. Concurrent resolution of the same value is idempotent (the
     * values are connection-invariant), so the check-then-populate is left
     * unsynchronized and simply converges on the same result.
     */
    private volatile String cachedCipherSuite;
    private volatile X509Certificate[] cachedPeerCerts;
    private volatile boolean peerCertsResolved;
    private volatile String cachedSessionId;

    /**
     * Number of client bidirectional and unidirectional streams accepted on
     * this connection so far. Retained so transport-limit reconciliation can
     * recover the advertised initial limit at any time: the remaining remote
     * credit plus the streams already accepted equals that initial limit,
     * regardless of whether reconciliation happens during bootstrap or later
     * when the ALPN result became readable.
     */
    private volatile int acceptedBidiStreams;
    private volatile int acceptedUniStreams;

    /**
     * Whether the transport stream limits have been reconciled for this
     * connection. Set on the poll thread by the endpoint.
     */
    private volatile boolean streamLimitsReconciled;


    String getCachedCipherSuite() {
        return cachedCipherSuite;
    }


    void setCachedCipherSuite(String cipherSuite) {
        this.cachedCipherSuite = cipherSuite;
    }


    X509Certificate[] getCachedPeerCerts() {
        X509Certificate[] certs = cachedPeerCerts;
        return certs == null ? null : certs.clone();
    }


    void setCachedPeerCerts(X509Certificate[] peerCerts) {
        // The cache must not alias a caller's array: getPeerCertificateChain()
        // returns the freshly built array to the caller that populated the
        // cache, and an application can replace/nulls elements in it. Storing
        // a private copy keeps later streams on the connection from observing
        // those mutations through getCachedPeerCerts().
        this.cachedPeerCerts = peerCerts == null ? null : peerCerts.clone();
    }


    boolean isPeerCertsResolved() {
        return peerCertsResolved;
    }


    void setPeerCertsResolved(boolean resolved) {
        this.peerCertsResolved = resolved;
    }


    String getCachedSessionId() {
        return cachedSessionId;
    }


    void setCachedSessionId(String sessionId) {
        this.cachedSessionId = sessionId;
    }


    /**
     * Records accepted client streams. Must be called on the poll thread,
     * once per stream returned by {@code SSL_accept_stream()}, including
     * streams that are rejected by the protocol limit: they still consumed
     * transport credit and so are part of the advertised initial limit.
     *
     * @param bidiStreamsAccepted Bidirectional streams accepted in this pass
     * @param uniStreamsAccepted  Unidirectional streams accepted in this pass
     */
    void addAcceptedStreams(int bidiStreamsAccepted, int uniStreamsAccepted) {
        this.acceptedBidiStreams += bidiStreamsAccepted;
        this.acceptedUniStreams += uniStreamsAccepted;
    }


    /**
     * Returns the number of client bidirectional streams accepted so far.
     *
     * @return The accepted client bidirectional stream count
     */
    int getAcceptedBidiStreams() {
        return acceptedBidiStreams;
    }


    /**
     * Returns the number of client unidirectional streams accepted so far.
     *
     * @return The accepted client unidirectional stream count
     */
    int getAcceptedUniStreams() {
        return acceptedUniStreams;
    }


    boolean isStreamLimitsReconciled() {
        return streamLimitsReconciled;
    }


    void setStreamLimitsReconciled(boolean reconciled) {
        this.streamLimitsReconciled = reconciled;
    }


    /**
     * Reference to the owning endpoint (for stream buffer allocation and
     * poll-thread hops).
     */
    private volatile QuicOpenSSLEndpoint endpoint;


    /**
     * Whether protocol data (HTTP/3: QPACK decoder instructions) is queued
     * for emission on this connection. Set from worker threads via
     * {@link #setProtocolDataPending(boolean)} and cleared by the poll thread
     * when the flush drains the queue; the endpoint's protocol-data sweep
     * skips connections whose flag is clear and counts the set flags so an
     * endpoint with nothing queued skips the sweep entirely.
     */
    private final AtomicBoolean protocolDataPending = new AtomicBoolean();


    @Override
    public void setProtocolDataPending(boolean pending) {
        if (pending && (isClosed() || isFreed())) {
            // A late worker/manager mark on a connection that has already
            // been torn down cannot be flushed and would otherwise strand
            // the endpoint-wide pending counter. A false transition is still
            // allowed so an existing mark can be balanced.
            return;
        }
        QuicOpenSSLEndpoint ep = endpoint;
        if (ep != null) {
            ep.setConnectionProtocolDataPending(this, pending);
        } else {
            protocolDataPending.set(pending);
        }
    }


    @Override
    public boolean isProtocolDataPending() {
        return protocolDataPending.get();
    }


    /**
     * Applies a pending-state transition, reporting whether it actually
     * changed the flag. Package-private: the owning endpoint keeps its
     * endpoint-wide pending count consistent with the flag.
     *
     * @param pending The new pending state
     *
     * @return {@code true} if the state changed
     */
    boolean protocolDataPendingTransition(boolean pending) {
        return protocolDataPending.getAndSet(pending) != pending;
    }


    /**
     * Creates a new connection wrapper.
     *
     * @param ssl                   The SSL* pointer for the connection
     * @param cleanerConnectionFrees The endpoint's poll-thread queue for
     *            deferred connection frees (not the endpoint) so the Cleaner's
     *            free runs on the poll thread, serialized with the teardown
     *            sequences and inside the poll thread's native-access
     *            confinement. May be {@code null} if no endpoint was
     *            available.
     */
    public QuicConnectionWrapper(MemorySegment ssl,
            ConcurrentLinkedQueue<DeferredConnectionFree> cleanerConnectionFrees) {
        this.ssl = ssl;
        this.closing = false;
        this.closed = false;

        // Pass the shared freed flag (not 'this') to the State so the Cleaner
        // does not keep this wrapper strongly reachable.
        State state = new State(ssl, this.freed, this.streamFreeFailed,
                this.connectionFreeFailed, cleanerConnectionFrees);
        cleaner.register(this, state);
    }


    /**
     * Returns the native SSL* pointer for this connection.
     *
     * @return The SSL* pointer
     */
    public MemorySegment getSsl() {
        return ssl;
    }


    /**
     * Returns the SSL pointer address for use as a map key.
     *
     * @return The SSL pointer address
     */
    public long getSslAddress() {
        return ssl.address();
    }


    /**
     * Returns the poll item for this connection.
     *
     * @return The poll item
     */
    public QuicPollItem getPollItem() {
        return pollItem;
    }


    /**
     * Sets the poll item for this connection.
     *
     * @param pollItem The poll item
     */
    public void setPollItem(QuicPollItem pollItem) {
        this.pollItem = pollItem;
    }


    /**
     * Returns the negotiated ALPN protocol.
     *
     * @return The protocol string, or {@code null} if not yet negotiated
     */
    public String getNegotiatedProtocol() {
        return negotiatedProtocol;
    }


    /**
     * Sets the negotiated ALPN protocol.
     *
     * @param protocol The protocol string
     */
    public void setNegotiatedProtocol(String protocol) {
        this.negotiatedProtocol = protocol;
    }


    /**
     * Whether the cached SNI host name is authoritative.
     *
     * @return {@code true} if the setup-time read resolved the cached value
     *         (including the case where the client sent no SNI)
     */
    public boolean isSniResolved() {
        return sniResolved;
    }


    /**
     * Marks the cached SNI host name as authoritatively resolved (including
     * the case where the client sent none).
     */
    void setSniResolved() {
        this.sniResolved = true;
    }


    /**
     * Returns the SNI host name sent by the client.
     * <p>
     * The value is read on the poll thread during connection setup and cached,
     * so this method normally makes no native call on the calling (worker)
     * thread. If the cache was never populated ({@code null}) the native read
     * is hopped to the poll thread once and cached; with no endpoint to hop to
     * (early setup) or an unreachable poll thread the native object is not
     * touched.
     * <p>
     * An empty cached value is <b>not</b> re-read here: it means "no usable
     * SNI" (either the client sent none or the setup-time ClientHello was not
     * processed yet). {@code ensureServedProtocol()} performs the explicit
     * native retry once the handshake has progressed. Callers must therefore
     * treat an empty result as "no usable SNI".
     *
     * @return the SNI host name, or an empty string if none was sent or the
     *         value could not be determined; never {@code null}
     */
    @Override
    public String getSniHostName() {
        String result = sniHostName;
        if (result == null) {
            QuicOpenSSLEndpoint endpoint = this.endpoint;
            if (endpoint == null || isClosed() || isFreed()) {
                // No poll thread to hop the native call to (endpoint not
                // wired in yet), or the native connection is already gone.
                // Calling SSL_get_servername here would race the poll loop
                // with the connection SSL (which is not thread-safe and may
                // be mid-free). The SNI host name is not critical: report
                // "no SNI" (empty, as for a client that sent none) and do
                // not touch native memory.
                return "";
            }
            try {
                result = endpoint.callOnPollThread(this::readSniHostNameCached);
            } catch (Throwable t) {
                // The poll thread is not (or no longer) reachable: the SNI
                // host name is not critical, report "no SNI". Fatal VM
                // errors still propagate.
                ExceptionUtils.handleThrowable(t);
                result = "";
            }
        }
        return result;
    }


    /**
     * Reads the SNI host name from the native connection SSL and caches it.
     * Must only be called on the QUIC poll thread.
     */
    private String readSniHostNameCached() {
        if (isClosed() || isFreed()) {
            // The connection was torn down between queueing this hop and its
            // execution (the free is poll-thread-confined too, so this check
            // is race-free). The native connection may already be freed;
            // report "no SNI" and do not touch it. Do not cache the result:
            // it means "unknown", not "the client sent no SNI".
            return "";
        }
        String value = readSniHostName();
        sniHostName = value;
        sniResolved = true;
        return value;
    }


    /**
     * Reads the SNI host name from a native SSL object - the single SNI read
     * of the package. Both the post-accept read (through the connection's own
     * {@link #readSniHostName()} below) and the mid-handshake host resolution
     * in the certificate manager's
     * {@code resolveServingHostKey(ssl, config)} go through this method, so
     * the {@code TLSEXT_NAMETYPE_HOST_NAME} selection and the lower-casing
     * convention cannot drift between them. Must only be called on the QUIC
     * poll thread (or from a TLS callback running on it).
     *
     * @param ssl The SSL object to read the server name from
     *
     * @return the SNI host name, in lower case, or {@code null} if the client
     *         sent no SNI (or a name containing control/line-separator
     *         characters, which is rejected to keep it out of log output)
     */
    public static String readSniHostNameNative(MemorySegment ssl) {
        MemorySegment namePtr = QuicBindings.SSL_get_servername(
                ssl, QuicBindings.TLSEXT_NAMETYPE_HOST_NAME);
        if (namePtr.equals(MemorySegment.NULL)) {
            return null;
        }
        // Host names are case-insensitive and the endpoint's SSL host config
        // look-ups are keyed by lower-cased names. Normalise at the source.
        String name = namePtr.getString(0).toLowerCase(Locale.ENGLISH);
        // OpenSSL only rejects an empty name or embedded NUL; other control
        // bytes are accepted. The name is logged by the certificate manager
        // and the HTTP/3 processor, so a client could otherwise inject CR/LF
        // into the log. Fail closed to "no SNI": a name containing control or
        // line-separator characters is not a valid host name anyway.
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isISOControl(c) || Character.getType(c) ==
                    Character.LINE_SEPARATOR || Character.getType(c) ==
                    Character.PARAGRAPH_SEPARATOR) {
                return null;
            }
        }
        return name;
    }


    /**
     * Reads the SNI host name from the native connection SSL. Must only be
     * called on the QUIC poll thread. Used by the setup-time cache and by the
     * explicit retry in {@code ensureServedProtocol()}; {@link #getSniHostName()}
     * does not call it for an already-cached empty value.
     *
     * @return the SNI host name, in lower case, or an empty string if the
     *         client sent no SNI or the read failed
     */
    String readSniHostName() {
        String name = readSniHostNameNative(ssl);
        return name == null ? "" : name;
    }


    /**
     * Caches the SNI host name. Called on the poll thread during
     * connection setup so that worker threads never need to read the value
     * from the native connection SSL.
     *
     * @param sniHostName The SNI host name (empty string if none)
     */
    public void setSniHostName(String sniHostName) {
        this.sniHostName = sniHostName;
        if (sniHostName != null && !sniHostName.isEmpty()) {
            // A non-empty value is authoritative regardless of handshake
            // timing; an empty cached value at setup may simply mean the
            // ClientHello has not been processed yet, so leave the resolved
            // flag unset for the stream-event path to retry.
            this.sniResolved = true;
        }
    }


    /**
     * Fails this QUIC connection with the given application protocol error
     * (for HTTP/3, RFC 9114 Section 8): the connection is terminated with a
     * QUIC {@code CONNECTION_CLOSE} frame carrying the error code and its
     * resources are released.
     * <p>
     * The native teardown must run on the QUIC poll thread. When called
     * from a worker thread the teardown is hopped there; if the hop cannot
     * be completed in time the connection is marked closed and a best-effort
     * poll-thread teardown is scheduled. If the mailbox is already closed,
     * the stop cleanup owns the remaining native state.
     *
     * @param appErrorCode The application protocol error code for the
     *                     CONNECTION_CLOSE frame
     * @param reason       A short description of the error (for logging)
     */
    @Override
    public void failConnection(long appErrorCode, String reason) {
        QuicOpenSSLEndpoint endpoint = this.endpoint;
        if (endpoint == null) {
            setClosed();
            return;
        }
        try {
            endpoint.callOnPollThread(() -> {
                endpoint.failConnection(this, appErrorCode, reason);
                return null;
            });
        } catch (Throwable t) {
            // The hop timed out or was rejected. Mark the connection closed so
            // no new work starts on it, then arrange a best-effort poll-thread
            // teardown: the timed-out hop itself will hit the endpoint's
            // isClosed() guard when it eventually runs, which would otherwise
            // leave the native state alive until stop. Fatal VM errors still
            // propagate after the retry has been scheduled.
            setClosed();
            endpoint.scheduleHopFailureTeardown(this, appErrorCode, reason);
            ExceptionUtils.handleThrowable(t);
        }
    }


    /**
     * Returns the remote (client) address.
     *
     * @return The remote address
     */
    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }


    /**
     * Sets the remote (client) address.
     *
     * @param address The remote address
     */
    public void setRemoteAddress(InetSocketAddress address) {
        this.remoteAddress = address;
    }


    /**
     * Returns the local (server) address.
     *
     * @return The local address
     */
    public InetSocketAddress getLocalAddress() {
        return localAddress;
    }


    /**
     * Sets the local (server) address.
     *
     * @param address The local address
     */
    public void setLocalAddress(InetSocketAddress address) {
        this.localAddress = address;
    }


    /**
     * Checks if this connection is closing.
     *
     * @return {@code true} if a close has been initiated
     */
    public boolean isClosing() {
        return closing;
    }


    /**
     * Marks this connection as closing.
     */
    public void setClosing() {
        this.closing = true;
    }


    /**
     * Checks if this connection is fully closed.
     *
     * @return {@code true} if the connection is closed
     */
    public boolean isClosed() {
        return closed;
    }


    /**
     * Marks this connection as closed.
     */
    public void setClosed() {
        this.closed = true;
    }

    /**
     * Records the application error code of the local connection close so the
     * shutdown-completion call can present the same code after the stream SSLs
     * are freed.
     *
     * @param errorCode The application error code supplied to the initial
     *                  {@code SSL_shutdown_ex()} call
     */
    void setConnectionCloseErrorCode(long errorCode) {
        this.connectionCloseErrorCode = errorCode;
    }

    /**
     * Returns the application error code of the local connection close.
     *
     * @return The application error code, or zero if no local close was
     *         initiated
     */
    long getConnectionCloseErrorCode() {
        return connectionCloseErrorCode;
    }

    /**
     * Returns whether the stream-limit GOAWAY notification has already been
     * queued for this connection.
     *
     * @return {@code true} if the notification has been sent
     */
    public boolean isStreamLimitGoawaySent() {
        return streamLimitGoawaySent;
    }

    /**
     * Marks the stream-limit GOAWAY notification as sent, so subsequent
     * stream-limit refusals do not append duplicate frames.
     *
     * @param sent {@code true} once the notification has been queued
     */
    public void setStreamLimitGoawaySent(boolean sent) {
        this.streamLimitGoawaySent = sent;
    }

    /**
     * Checks if the native SSL object has been freed.
     * @return {@code true} if the native SSL object has been freed
     */
    public boolean isFreed() {
        return freed.get();
    }

    /**
     * Records that freeing a stream SSL of this connection failed.
     */
    void markStreamFreeFailed() {
        streamFreeFailed.set(true);
    }

    /**
     * Returns whether any stream SSL free has failed. Once true, this
     * connection SSL must not be freed.
     *
     * @return {@code true} if a stream free failed
     */
    boolean hasStreamFreeFailure() {
        return streamFreeFailed.get();
    }


    /**
     * Returns whether the connection SSL free failed once and must not be
     * retried. The wrapper is retained (and remains counted against the
     * endpoint's connection limit) in that case.
     *
     * @return {@code true} if a previous connection SSL free failed
     */
    boolean hasConnectionFreeFailure() {
        return connectionFreeFailed.get();
    }


    /**
     * Returns whether the one-time retention warning for this connection has
     * not been logged yet, atomically claiming it.
     *
     * @return {@code true} for the first caller only
     */
    boolean claimRetentionWarningLog() {
        return retentionWarningLogged.compareAndSet(false, true);
    }

    /**
     * Returns the shared stream-free-failure flag. Used by the stream Cleaner
     * state so a deferred free failure can mark the connection without
     * retaining the wrapper.
     *
     * @return The shared failure flag
     */
    AtomicBoolean getStreamFreeFailedFlag() {
        return streamFreeFailed;
    }

    /**
     * Claims the single connection teardown. The first caller gets
     * {@code true}; every later caller gets {@code false} and must not repeat
     * the native teardown/free steps. This mirrors the quiche/ngtcp2
     * wrappers and prevents repeated {@code failConnection()} calls from
     * touching an already-freed connection SSL.
     *
     * @return {@code true} if this call claimed the teardown
     */
    boolean markTeardownStarted() {
        return !teardownStarted.getAndSet(true);
    }


    /**
     * Whether the single connection teardown has already been claimed by an
     * earlier caller (for example a protocol callback that failed the
     * connection inline). A setup-abort path must not schedule the terminal
     * stream events a second time in that case.
     *
     * @return {@code true} if teardown has already been claimed
     */
    boolean isTeardownStarted() {
        return teardownStarted.get();
    }

    /**
     * Frees the native SSL object exactly once, atomically. Explicit cleanup
     * paths call this; the Cleaner's {@link DeferredConnectionFree} uses the
     * same shared {@link AtomicBoolean} and {@code SSL_free} guard instead of
     * calling this method, so the native free still runs at most once even if
     * they race.
     *
     * @return {@code true} only if this call performed the native
     *         {@code SSL_free}; {@code false} if the SSL was already freed or
     *         the free was skipped because a stream SSL free failed. Callers
     *         must keep the connection retained (and its deferred socket open)
     *         unless the result is {@code true} or {@link #isFreed()} is
     *         already {@code true}.
     */
    public boolean freeSslOnce() {
        return freeSslOnce(ssl, freed, streamFreeFailed, connectionFreeFailed);
    }


    /**
     * Shared single-free guard used by the explicit free path and the
     * Cleaner's {@link DeferredConnectionFree}, so both copies cannot drift on
     * the stream-free-failure check or the freed CAS.
     *
     * @param ssl                 The connection SSL
     * @param freed               Shared freed flag
     * @param streamFreeFailed    Shared sticky stream-free-failure flag
     * @param connectionFreeFailed Shared sticky connection-free-failure flag
     *
     * @return {@code true} only if this call performed {@code SSL_free}
     */
    static boolean freeSslOnce(MemorySegment ssl, AtomicBoolean freed,
            AtomicBoolean streamFreeFailed,
            AtomicBoolean connectionFreeFailed) {
        if (streamFreeFailed.get()) {
            // At least one stream SSL free failed; freeing the connection now
            // could violate SSL_new_stream(3). Leave the connection allocated
            // (leaked) rather than risking a free under a live stream.
            return false;
        }
        if (connectionFreeFailed.get()) {
            // A previous SSL_free() failed; it may have partially run, so
            // retrying is unsafe. Keep the native object retained.
            return false;
        }
        if (freed.getAndSet(true)) {
            return false;
        }
        try {
            openssl_h.SSL_free(ssl);
            return true;
        } catch (Throwable t) {
            // Do not leave freed=true: the callers use isFreed() to decide
            // whether the native object is gone and can drop retention
            // entries. Mark the connection sticky-first so a concurrent
            // Cleaner cannot retry the unsafe free.
            connectionFreeFailed.set(true);
            freed.set(false);
            throw t;
        }
    }

    /**
     * Records that an executor worker is about to run the HTTP handler for a
     * stream on this connection.
     */
    public void incrActiveHandlers() {
        activeHandlers.incrementAndGet();
    }

    /**
     * Records that an executor worker finished running the HTTP handler.
     *
     * @return the remaining number of active handlers
     */
    public int decrActiveHandlers() {
        return activeHandlers.decrementAndGet();
    }

    /**
     * Records that a dispatch task carrying an active-handler reference was
     * queued in the executor.
     *
     * @param stream The stream whose processing flag the task owns
     *
     * @return The claim record shared with the task and the stop path
     */
    QueuedDispatch incrQueuedDispatch(QuicStreamWrapper stream) {
        QueuedDispatch queued = new QueuedDispatch(stream);
        queuedDispatchStreams.add(queued);
        return queued;
    }

    /**
     * Removes a queued dispatch record when its task starts (or when the
     * executor rejects it).
     *
     * @param queued The queued dispatch record
     */
    void decrQueuedDispatch(QueuedDispatch queued) {
        queuedDispatchStreams.remove(queued);
    }

    /**
     * Balances the active-handler references of dispatch tasks that never
     * started and returns the streams whose processing claims those tasks
     * still hold. A task that won its claim and started is left alone: it owns
     * its active-handler reference and will release it when it finishes, even
     * if this method runs concurrently with its start.
     *
     * @return The streams whose dispatch tasks were discarded unrun
     */
    List<QuicStreamWrapper> discardQueuedDispatches() {
        List<QuicStreamWrapper> streams = new ArrayList<>();
        QueuedDispatch queued;
        while ((queued = queuedDispatchStreams.poll()) != null) {
            if (queued.tryClaim()) {
                // The task did not start. Balance the active-handler reference
                // that was added when the task was queued and let the caller
                // release the processing claim.
                streams.add(queued.getStream());
                activeHandlers.decrementAndGet();
            }
        }
        return streams;
    }

    /**
     * Checks whether any executor worker is currently running the HTTP handler
     * for a stream on this connection.
     *
     * @return {@code true} if at least one handler is active
     */
    public boolean hasActiveHandlers() {
        return activeHandlers.get() > 0;
    }

    /**
     * Marks this connection's SSL free as pending, waiting for
     * {@link #activeHandlers} to reach zero.
     */
    public void setPendingFree() {
        pendingFree.set(true);
    }

    /**
     * Clears the pending-free flag if it is set.
     *
     * @return {@code true} if this caller cleared the flag and is therefore
     *         responsible for performing the deferred free
     */
    public boolean clearPendingFree() {
        return pendingFree.compareAndSet(true, false);
    }

    /**
     * Returns the wrapper of the server-initiated unidirectional stream with
     * the given protocol-assigned index, if it has been registered (index 0
     * is the primary stream, e.g. the HTTP/3 control stream).
     *
     * @param index The protocol-assigned server unidirectional stream index
     *
     * @return The stream wrapper, or {@code null} if the stream has not been
     *         created yet
     */
    public QuicStreamWrapper getServerUniStream(int index) {
        return serverUniStreams.get(Integer.valueOf(index));
    }


    /**
     * Returns the collection of the server-initiated unidirectional streams
     * created for this connection.
     *
     * @return The server unidirectional stream wrappers
     */
    public Collection<QuicStreamWrapper> getServerUniStreams() {
        return serverUniStreams.values();
    }


    /**
     * Registers the wrapper of a server-initiated unidirectional stream.
     *
     * @param index  The protocol-assigned server unidirectional stream index
     * @param stream The stream wrapper
     */
    public void registerServerUniStream(int index, QuicStreamWrapper stream) {
        serverUniStreams.put(Integer.valueOf(index), stream);
    }


    /**
     * Removes a server-initiated unidirectional stream from the connection's
     * bookkeeping when it is deregistered. The stream SSL is freed by the
     * stream teardown, so keeping the wrapper here would retain it after close
     * and let {@link #getServerUniStream(int)} return a freed stream.
     *
     * @param stream The stream wrapper to remove
     */
    void removeServerUniStream(QuicStreamWrapper stream) {
        serverUniStreams.values().remove(stream);
    }


    /**
     * Releases all server-unidirectional-stream bookkeeping, for example when
     * the connection is being torn down.
     */
    void clearServerUniStreams() {
        serverUniStreams.clear();
    }


    /**
     * Writes the remaining bytes of the given buffer to the provided stream in
     * a single native {@code SSL_write_ex(2)} call (through the endpoint's
     * shared write kernel), allocating the native buffers from a confined
     * arena. This keeps the {@code java.lang.foreign} and {@code QuicBindings}
     * usage behind this wrapper so callers (e.g. the HTTP/3 protocol layer) do
     * not touch OpenSSL directly.
     * <p>
     * As required by the {@link QuicConnection#writeToStream} contract, the
     * buffer's position is advanced by exactly the number of accepted bytes:
     * with partial writes enabled on the endpoint's SSL context the stream may
     * accept a prefix (typically when the peer's stream credit is nearly
     * exhausted), and a caller that retries must re-present the remaining
     * bytes unchanged. A would-block accepts nothing (position unchanged); a
     * stream in a terminal state consumes the buffer and reports everything
     * as accepted, so the caller drops its pending state instead of retrying
     * forever (quiche-parity semantics).
     * <p>
     * Must be called on the QUIC poll thread: it writes to the native stream
     * SSL object, which is not thread-safe.
     *
     * @param stream The stream to write to
     * @param data   The data to write, from the buffer's current position to
     *               its limit; the position is advanced by the accepted count
     *
     * @return the number of bytes accepted by the stream
     */
    @Override
    public int writeToStream(QuicStream stream, ByteBuffer data) {
        int startPos = data.position();
        int len = data.remaining();
        if (len == 0) {
            return 0;
        }
        QuicStreamWrapper s = (QuicStreamWrapper) stream;
        QuicConnectionWrapper conn = (QuicConnectionWrapper) s.getConnection();
        if (s.isFreed() || (conn != null &&
                (conn.isClosed() || conn.isFreed() ||
                        conn.hasConnectionFreeFailure()))) {
            // The stream or its connection has already been torn down. Do not
            // touch the stream SSL; report all bytes as consumed so the
            // protocol caller drops its pending state instead of retrying a
            // write that can never reach the wire.
            data.position(startPos + len);
            return len;
        }
        try (Arena localArena = Arena.ofConfined()) {
            int written = QuicOpenSSLEndpoint.writeStreamData(s.getSsl(), data, localArena);
            if (written >= 0) {
                data.position(startPos + written);
                return written;
            }
            // Nothing was accepted. Tell a would-block (retry the same bytes
            // once the peer's credit/ACKs arrive) from a terminal stream
            // state or a hard write error that can never accept them. The
            // write state alone is not enough: an internal failure can leave
            // the state OK while SSL_write_ex2() failed, and returning 0 would
            // make the protocol layer retry the same bytes forever.
            int sslError = QuicBindings.SSL_get_error(s.getSsl(), 0);
            int writeState = QuicBindings.SSL_get_stream_write_state(s.getSsl());
            boolean wouldBlock = sslError == QuicBindings.SSL_ERROR_WANT_READ ||
                    sslError == QuicBindings.SSL_ERROR_WANT_WRITE;
            if (QuicPoll.isTerminalWriteState(writeState)) {
                // The stream can never accept these bytes: consume them so
                // the caller drops its pending state instead of retrying
                // forever. The connection's terminal path is already running.
                data.position(startPos + len);
                return len;
            }
            if (!wouldBlock) {
                // A hard error that left the write state non-terminal must
                // not be reported as "all bytes accepted" (that silently
                // loses protocol data). Leave the bytes pending so the caller
                // stops this flush attempt, and fail the connection on the
                // next poll-loop iteration, after this method has returned.
                // Drain the handled native failure so a later accept check
                // cannot mistake it for an accept failure.
                if (log.isDebugEnabled()) {
                    log.debug("QUIC stream write failed: stream=" +
                            s.getStreamId() + " sslError=" + sslError +
                            " errors=" + QuicDiagnostics.dumpErrorQueue());
                } else {
                    QuicDiagnostics.clearErrorQueue();
                }
                QuicOpenSSLEndpoint ep = endpoint;
                if (ep != null) {
                    ep.submitPollTask(
                            () -> ep.failConnectionForStreamWriteError(this, sslError));
                } else {
                    data.position(startPos + len);
                    return len;
                }
            }
            data.position(startPos);
            return 0;
        }
    }


    /**
     * Returns the map of streams for this connection.
     *
     * @return The stream map
     */
    public ConcurrentHashMap<Long, QuicStreamWrapper> getStreams() {
        return streams;
    }

    /**
     * Returns the list of pending streams waiting for server control stream.
     *
     * @return The pending streams list
     */
    public CopyOnWriteArrayList<QuicStreamWrapper> getPendingStreams() {
        return pendingStreams;
    }


    /**
     * Returns the owning endpoint.
     *
     * @return The endpoint
     */
    public QuicOpenSSLEndpoint getEndpoint() {
        return endpoint;
    }


    /**
     * Sets the owning endpoint.
     *
     * @param endpoint The endpoint
     */
    public void setEndpoint(QuicOpenSSLEndpoint endpoint) {
        this.endpoint = endpoint;
    }


    /**
     * {@inheritDoc}
     * <p>
     * The manager is registered by the endpoint at connection accept.
     */
    @Override
    public QuicConnectionManager getQuicConnectionManager() {
        return quicConnectionManager;
    }


    /**
     * Sets the application protocol connection manager for this connection.
     *
     * @param quicConnectionManager The connection manager
     */
    public void setQuicConnectionManager(QuicConnectionManager quicConnectionManager) {
        this.quicConnectionManager = quicConnectionManager;
    }


    /**
     * Closes all streams associated with this connection. Each stream is
     * removed from the endpoint's poll set (its poll item is disposed when it
     * was never promoted into the set), marked deregistered and, unless an
     * executor worker is still running its HTTP handler, its native SSL
     * object is freed. Per {@code SSL_new_stream(3)} every stream SSL must be
     * freed before the connection SSL: OpenSSL's QUIC engine asserts that no
     * stream SSL objects remain when the connection is freed.
     * <p>
     * A stream whose HTTP handler is still running is NOT freed here: the
     * ownership of the stream is decided by atomically claiming the
     * processing flag (see {@code closeStream()} - a plain read was not
     * atomic against the claim a re-dispatched worker performs when it
     * starts). A stream whose native SSL object must not be freed because
     * the worker may still make native calls on the stream (hopped to the
     * poll thread) has its free completed by the worker's
     * {@code finishStreamDispatch()} once the handler has finished, ordered
     * before the connection free. Callers must therefore keep the connection
     * SSL alive until all active handlers complete
     * ({@link #hasActiveHandlers()} / pending-free deferral). Must run on the
     * QUIC poll thread.
     */
    public void closeAllStreams() {
        boolean failed = hasStreamFreeFailure();
        for (QuicStreamWrapper stream : streams.values()) {
            // Mark the stream non-live first so a failure below cannot leave a
            // poll item dispatching handler code against a half-torn stream.
            stream.setDeregistered();
            try {
                if (endpoint != null) {
                    endpoint.untrackStreamPollItem(stream);
                }
                QuicPollItem item = stream.getPollItem();
                if (item != null) {
                    QuicPollSet pollSet = endpoint == null ? null : endpoint.getPollSet();
                    if (pollSet != null &&
                            pollSet.get(stream.getSslAddress()) == item) {
                        pollSet.remove(stream.getSslAddress());
                    } else {
                        // Never promoted into the poll set (the server control
                        // stream had not been created before teardown) or the
                        // poll set is already gone.
                        item.dispose();
                    }
                }
                // The single teardown primitive; its javadoc explains why the
                // claim is an atomic CAS. Losing the claim defers the free to
                // the worker's finishStreamDispatch() (see this method's
                // javadoc). A failed free marks the connection sticky; the
                // map is kept below so connection-free paths can retain it.
                if (!stream.freeSslIfIdle()) {
                    if (hasStreamFreeFailure()) {
                        failed = true;
                    }
                }
            } catch (Throwable t) {
                failed = true;
                markStreamFreeFailed();
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("quicEndpoint.streamTeardownError",
                        Long.toHexString(stream.getSslAddress())), t);
            }
        }
        if (!failed && !hasStreamFreeFailure()) {
            streams.clear();
            pendingStreams.clear();
            serverUniStreams.clear();
        }
    }


    @Override
    public String toString() {
        return "QuicConnection[ssl=0x" + Long.toHexString(ssl.address()) +
                ",streams=" + streams.size() +
                ",protocol=" + negotiatedProtocol + "]";
    }


    /**
     * One queued dispatch task's claim state. The task and the stop path race
     * on {@link AtomicBoolean#compareAndSet(boolean, boolean)}: exactly one of
     * them wins. The loser must not touch the stream claim or the
     * active-handler reference because the winner owns that accounting.
     */
    static final class QueuedDispatch {

        private final QuicStreamWrapper stream;
        private final AtomicBoolean claimed = new AtomicBoolean();

        QueuedDispatch(QuicStreamWrapper stream) {
            this.stream = stream;
        }

        QuicStreamWrapper getStream() {
            return stream;
        }

        /**
         * Attempts to claim this dispatch for either starting or discarding.
         *
         * @return {@code true} if this caller won the claim
         */
        boolean tryClaim() {
            return claimed.compareAndSet(false, true);
        }
    }


    /**
     * A deferred native free request for a connection whose wrapper became
     * phantom-reachable before any teardown path freed it. The free decision
     * is made on the endpoint's poll thread (where every teardown sequence
     * and every other native call runs), so it no longer executes on the GC
     * thread outside the OpenSSL QUIC single-threaded threading contract
     * while the poll thread may be inside SSL_poll()/SSL_handle_events() on
     * the shared engine. The endpoint's maps normally keep a connection with
     * live streams strongly reachable, so phantom reachability means the
     * connection free is not otherwise claimed. Cleaner processing order is
     * not guaranteed to match registration order; the native lifetime
     * ordering is enforced by OpenSSL's XSO-to-connection reference count and
     * by the mailbox draining stream-free requests before connection-free
     * requests that are already queued. Carries only the shared flags (never
     * the wrapper) so nothing keeps the wrapper reachable. Mirrors
     * QuicStreamWrapper.DeferredStreamFree.
     */
    static final class DeferredConnectionFree {

        private final MemorySegment ssl;
        private final AtomicBoolean freed;
        private final AtomicBoolean streamFreeFailed;
        private final AtomicBoolean connectionFreeFailed;

        DeferredConnectionFree(MemorySegment ssl, AtomicBoolean freed,
                AtomicBoolean streamFreeFailed,
                AtomicBoolean connectionFreeFailed) {
            this.ssl = ssl;
            this.freed = freed;
            this.streamFreeFailed = streamFreeFailed;
            this.connectionFreeFailed = connectionFreeFailed;
        }

        void run() {
            // Shared single-free guard: skips when a stream SSL free failed
            // (stream-before-connection ordering), when a previous connection
            // free failed, and CASes with every other free path
            // (teardownConnection, freeConnectionOrDefer, stopInternal).
            freeSslOnce(ssl, freed, streamFreeFailed, connectionFreeFailed);
        }
    }


    /**
     * State object for Cleaner-based native resource cleanup.
     */
    private static class State implements Runnable {
        private final MemorySegment ssl;
        // Shared freed flag (NOT the wrapper) so this State does not keep the
        // QuicConnectionWrapper strongly reachable from the static Cleaner.
        private final AtomicBoolean freed;
        // Shared stream-free-failure flag (NOT the wrapper) so the Cleaner
        // does not free the connection after a failed stream free.
        private final AtomicBoolean streamFreeFailed;
        // Shared connection-free-failure flag so a failed SSL_free() is not
        // retried by the Cleaner or a later explicit free path.
        private final AtomicBoolean connectionFreeFailed;
        // The endpoint's poll-thread queue for deferred connection frees (NOT
        // the endpoint) so the free decision is serialized with the teardown
        // sequences and stays inside the poll thread's native-access
        // confinement. May be null if no endpoint was available.
        private final ConcurrentLinkedQueue<DeferredConnectionFree>
                cleanerConnectionFrees;

        State(MemorySegment ssl, AtomicBoolean freed,
                AtomicBoolean streamFreeFailed,
                AtomicBoolean connectionFreeFailed,
                ConcurrentLinkedQueue<DeferredConnectionFree>
                        cleanerConnectionFrees) {
            this.ssl = ssl;
            this.freed = freed;
            this.streamFreeFailed = streamFreeFailed;
            this.connectionFreeFailed = connectionFreeFailed;
            this.cleanerConnectionFrees = cleanerConnectionFrees;
        }

        @Override
        public void run() {
            // Never call SSL_free on the GC thread: hand the request to the
            // poll thread, where it is serialized with the teardown
            // sequences, mirroring QuicStreamWrapper.State.run(). The queue
            // is only null for a wrapper constructed without an endpoint;
            // that fallback leaves the native SSL allocated and logs instead
            // of violating OpenSSL's single-threaded QUIC object contract.
            //
            // No wake-descriptor kick here on purpose: a kick would need the
            // State to hold the endpoint (or its wakeup), defeating the
            // minimal-reachability design of this class. The queued free is
            // drained by the next poll-loop iteration; enqueued during an
            // in-progress wait, it waits out at most that wait - bounded by
            // the loop's idle-rate timeout, or pollTimeoutMs while the
            // endpoint is busy (see QuicNativeMailbox.hasDeferredStreamFrees).
            if (freed.get()) {
                // The explicit free paths already released the native SSL;
                // do not enqueue a no-op request that would accumulate in the
                // deferred-free queue after the endpoint has stopped.
                return;
            }
            if (streamFreeFailed.get()) {
                // A stream SSL free failed; the connection must be retained/
                // leaked rather than freed under a possibly-live stream.
                return;
            }
            if (connectionFreeFailed.get()) {
                // A previous connection SSL_free() failed and may have
                // partially run; do not retry it from the Cleaner.
                return;
            }
            if (cleanerConnectionFrees != null) {
                cleanerConnectionFrees.add(
                        new DeferredConnectionFree(ssl, freed,
                                streamFreeFailed, connectionFreeFailed));
            } else {
                // Never call SSL_free on the Cleaner thread: leave the
                // native connection allocated rather than touching OpenSSL
                // outside the poll-thread confinement. This fallback is
                // defensive only (endpoint connections always carry an
                // endpoint queue), so log it instead of leaking silently.
                log.warn(sm.getString("quicEndpoint.cleanerFreeSkipped"));
            }
        }
    }
}

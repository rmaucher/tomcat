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
import java.util.Collection;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.tomcat.util.net.quic.QuicConnection;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicStream;
import org.apache.tomcat.util.openssl.openssl_h;

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
     * Number of executor worker threads currently executing the HTTP handler
     * for a stream on this connection. While greater than zero, the native
     * connection SSL object (and the stream SSLs it owns) must NOT be freed,
     * because a worker may still be about to make a native call on the poll
     * thread. The connection SSL free is deferred until this count reaches
     * zero (see {@link #pendingFree}).
     */
    private final AtomicInteger activeHandlers = new AtomicInteger(0);

    /**
     * Set when the poll thread wants to free this connection's SSL but must
     * wait for {@link #activeHandlers} to reach zero. The worker that decrements
     * the count to zero clears this flag and schedules the free on the poll
     * thread.
     */
    private final AtomicBoolean pendingFree = new AtomicBoolean(false);

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


    String getCachedCipherSuite() {
        return cachedCipherSuite;
    }


    void setCachedCipherSuite(String cipherSuite) {
        this.cachedCipherSuite = cipherSuite;
    }


    X509Certificate[] getCachedPeerCerts() {
        return cachedPeerCerts;
    }


    void setCachedPeerCerts(X509Certificate[] peerCerts) {
        this.cachedPeerCerts = peerCerts;
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
        State state = new State(ssl, this.freed, cleanerConnectionFrees);
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
     * Returns the SNI host name sent by the client.
     * <p>
     * The value is normally read on the poll thread during connection setup and
     * cached, so this method does not make a native call on the calling (worker)
     * thread. Only if the setup-time read did not populate the cache is the
     * native read hopped to the poll thread once and cached; with no endpoint to
     * hop to (early setup) or an unreachable poll thread the native object is
     * not touched (the connection SSL is not thread-safe and a worker must never
     * call into it directly).
     * <p>
     * An empty string is returned both when the client sent no SNI and when the
     * value could not be obtained, and these two cases cannot be distinguished
     * through this method; callers must treat an empty result as "no usable SNI".
     *
     * @return the SNI host name, or an empty string if none was sent or the
     *         value could not be determined; never {@code null}
     */
    @Override
    public String getSniHostName() {
        String result = sniHostName;
        if (result == null) {
            QuicOpenSSLEndpoint endpoint = this.endpoint;
            if (endpoint == null) {
                // No poll thread to hop the native call to (endpoint not
                // wired in yet). Calling SSL_get_servername here would race
                // the poll loop with the connection SSL (which is not
                // thread-safe and may be mid-free). The SNI host name is
                // not critical: report "no SNI" (empty, as for a client
                // that sent none) and do not touch native memory.
                return "";
            }
            try {
                result = endpoint.callOnPollThread(this::readSniHostNameCached);
            } catch (Throwable t) {
                // The poll thread is not (or no longer) reachable: the SNI
                // host name is not critical, report "no SNI".
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
        String value = readSniHostName();
        sniHostName = value;
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
     *         sent no SNI
     */
    static String readSniHostNameNative(MemorySegment ssl) {
        MemorySegment namePtr = QuicBindings.SSL_get_servername(
                ssl, QuicBindings.TLSEXT_NAMETYPE_HOST_NAME);
        if (namePtr.equals(MemorySegment.NULL)) {
            return null;
        }
        // Host names are case-insensitive and the endpoint's SSL host config
        // look-ups are keyed by lower-cased names. Normalise at the source.
        return namePtr.getString(0).toLowerCase(Locale.ENGLISH);
    }


    /**
     * Reads the SNI host name from the native connection SSL. Must only be
     * called on the QUIC poll thread. The endpoint's connection setup caches
     * the value via {@link #setSniHostName(String)} and worker threads use
     * {@link #getSniHostName()} (which re-reads through this method on a
     * cache miss).
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
    }


    /**
     * Fails this QUIC connection with the given application protocol error
     * (for HTTP/3, RFC 9114 Section 8): the connection is terminated with a
     * QUIC {@code CONNECTION_CLOSE} frame carrying the error code and its
     * resources are released.
     * <p>
     * The native teardown must run on the QUIC poll thread. When called
     * from a worker thread the teardown is hopped there; if the hop cannot
     * be completed in time the connection is marked closed and torn down
     * by the normal teardown paths.
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
            setClosed();
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
     * Checks if the native SSL object has been freed.
     * @return {@code true} if the native SSL object has been freed
     */
    public boolean isFreed() {
        return freed.get();
    }

    /**
     * Frees the native SSL object exactly once, atomically. Both explicit
     * cleanup and the Cleaner call this, so the {@link AtomicBoolean}
     * guarantees {@code SSL_free} runs at most once even if they race.
     */
    public void freeSslOnce() {
        if (!freed.getAndSet(true)) {
            openssl_h.SSL_free(ssl);
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
        try (Arena localArena = Arena.ofConfined()) {
            int written = QuicOpenSSLEndpoint.writeStreamData(s.getSsl(), data, localArena);
            if (written >= 0) {
                data.position(startPos + written);
                return written;
            }
            // Nothing was accepted. Tell a would-block (retry the same bytes
            // once the peer's credit/ACKs arrive) from a terminal stream
            // state that can never accept them.
            int writeState = QuicBindings.SSL_get_stream_write_state(s.getSsl());
            boolean terminal = QuicPoll.isTerminalWriteState(writeState);
            if (terminal) {
                data.position(startPos + len);
                return len;
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
        for (QuicStreamWrapper stream : streams.values()) {
            QuicPollItem item = stream.getPollItem();
            if (item != null) {
                if (endpoint != null &&
                        endpoint.getPollSet().get(stream.getSslAddress()) == item) {
                    endpoint.getPollSet().remove(stream.getSslAddress());
                } else {
                    // Never promoted into the poll set (the server control
                    // stream had not been created before teardown)
                    item.dispose();
                }
            }
            stream.setDeregistered();
            // The single teardown primitive; its javadoc explains why the
            // claim is an atomic CAS. Losing the claim defers the free to the
            // worker's finishStreamDispatch() (see this method's javadoc),
            // and that is the whole story for this iteration - there is
            // nothing left in the loop body to branch on, so the result is
            // deliberately ignored.
            stream.freeSslIfIdle();
        }
        streams.clear();
        pendingStreams.clear();
    }


    @Override
    public String toString() {
        return "QuicConnection[ssl=0x" + Long.toHexString(ssl.address()) +
                ",streams=" + streams.size() +
                ",protocol=" + negotiatedProtocol + "]";
    }


    /**
     * A deferred native free request for a connection whose wrapper became
     * phantom-reachable before any teardown path freed it. The free decision
     * is made on the endpoint's poll thread (where every teardown sequence
     * and every other native call runs), so it no longer executes on the GC
     * thread outside the OpenSSL QUIC single-threaded threading contract
     * while the poll thread may be inside SSL_poll()/SSL_handle_events() on
     * the shared engine. Reaching the request means the wrapper was
     * phantom-reachable, which (per the connections field invariant of
     * QuicOpenSSLEndpoint) only happens once every live stream SSL is
     * freed-or-deferred and the connection free is not otherwise claimed, so
     * no processing claim is needed for the free to be safe. Carries only the
     * shared flags (never the wrapper) so nothing keeps the wrapper
     * reachable. Mirrors QuicStreamWrapper.DeferredStreamFree.
     */
    static final class DeferredConnectionFree {

        private final MemorySegment ssl;
        private final AtomicBoolean freed;

        DeferredConnectionFree(MemorySegment ssl, AtomicBoolean freed) {
            this.ssl = ssl;
            this.freed = freed;
        }

        void run() {
            // CAS with every other free path (teardownConnection,
            // freeConnectionOrDefer, stopInternal): free the native SSL
            // exactly once.
            if (!freed.getAndSet(true)) {
                openssl_h.SSL_free(ssl);
            }
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
        // The endpoint's poll-thread queue for deferred connection frees (NOT
        // the endpoint) so the free decision is serialized with the teardown
        // sequences and stays inside the poll thread's native-access
        // confinement. May be null if no endpoint was available.
        private final ConcurrentLinkedQueue<DeferredConnectionFree>
                cleanerConnectionFrees;

        State(MemorySegment ssl, AtomicBoolean freed,
                ConcurrentLinkedQueue<DeferredConnectionFree>
                        cleanerConnectionFrees) {
            this.ssl = ssl;
            this.freed = freed;
            this.cleanerConnectionFrees = cleanerConnectionFrees;
        }

        @Override
        public void run() {
            // Never call SSL_free on the GC thread: hand the request to the
            // poll thread, where it is serialized with the teardown
            // sequences, mirroring QuicStreamWrapper.State.run().
            //
            // No wake-descriptor kick here on purpose: a kick would need the
            // State to hold the endpoint (or its wakeup), defeating the
            // minimal-reachability design of this class. The queued free is
            // drained by the next poll-loop iteration; enqueued during an
            // in-progress wait, it waits out at most that wait - bounded by
            // the loop's idle-rate timeout, or pollTimeoutMs while the
            // endpoint is busy (see QuicNativeMailbox.hasDeferredStreamFrees).
            if (cleanerConnectionFrees != null) {
                cleanerConnectionFrees.add(
                        new DeferredConnectionFree(ssl, freed));
            } else {
                new DeferredConnectionFree(ssl, freed).run();
            }
        }
    }
}

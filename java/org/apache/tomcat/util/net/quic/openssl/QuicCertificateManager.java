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
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.openssl.OpenSSLPreSharedKeySelector;
import org.apache.tomcat.util.net.openssl.panama.CertificateLoader;
import org.apache.tomcat.util.net.quic.QuicProtocol;
import org.apache.tomcat.util.openssl.openssl_h;
import org.apache.tomcat.util.openssl.openssl_h_Compatibility;
import org.apache.tomcat.util.res.StringManager;

/**
 * Owns the TLS side of an OpenSSL QUIC endpoint: the native QUIC
 * {@code SSL_CTX}, the ALPN, SNI and TLS 1.3 pre-shared key callbacks
 * installed on it, the current {@link QuicCertConfig}
 * certificate snapshot the SNI callback applies per connection, and the
 * arenas holding the FFM upcall stubs for those callbacks.
 * <p>
 * This collaborator is deliberately decoupled from the endpoint: it is given
 * everything it needs through its constructor (the endpoint name for logging,
 * a supplier for the {@link QuicProtocol} whose ALPN identifiers are
 * negotiated, and a resolver that maps an SNI host name to its
 * {@link SSLHostConfig}) and it owns no thread of its own. The native
 * certificate context is created once during bind and released during
 * unbind; the certificate snapshot is swapped in on the endpoint's poll
 * thread so it is serialized with the SNI callback, or on the calling thread
 * when no poll loop is running (stopped/unbound lifecycle). The same manager
 * is also used by the ngtcp2 transport adapter with a normal
 * {@code TLS_server_method()} context.
 * <p>
 * Server certificates and TLS 1.3 pre-shared keys are supported. Client
 * certificate verification is not implemented (optional verification is
 * warned about; required verification fails the build). OCSP stapling and
 * CRL/revocation configuration are not loaded; configuring them produces a
 * warning because the settings would otherwise be silently ignored.
 */
public class QuicCertificateManager {

    private static final Log log =
            LogFactory.getLog(QuicCertificateManager.class);
    // quicEndpoint.* messages live in this package's string bundle; sharing the
    // endpoint's StringManager keeps the wording identical to before the
    // certificate logic was extracted.
    private static final StringManager sm =
            StringManager.getManager(QuicOpenSSLEndpoint.class);

    /**
     * The current set of certificates loaded natively from the configured
     * {@link SSLHostConfig} entries. The SNI callback applies the matching
     * host's certificates to each incoming connection. Replaced atomically
     * when the certificate configuration is reloaded. {@code null} until the
     * first successful build.
     */
    private volatile QuicCertConfig certConfig;

    /**
     * The {@code SSL_CTX*} for QUIC, created by {@link #initialize}.
     */
    private MemorySegment sslCtx = MemorySegment.NULL;

    /**
     * Arena for the ALPN callback upcall stub. Tracked to prevent GC and
     * freed during {@link #release()}.
     */
    private Arena alpnCallbackArena;

    /**
     * Arena for the SNI (server name) callback upcall stub. Tracked to
     * prevent GC and freed during {@code release()}.
     */
    private Arena sniCallbackArena;

    /**
     * Arena for the TLS 1.3 pre-shared key find-session callback upcall stub.
     * Tracked to prevent GC and freed during {@code release()}.
     */
    private Arena pskCallbackArena;

    private final Supplier<String> nameSupplier;
    private final Supplier<QuicProtocol> protocolSupplier;
    private final Function<String, SSLHostConfig> hostResolver;

    private final MemorySegment sslMethod;

    /**
     * Set once the PSK-only SSL option could not be aligned with the current
     * configuration snapshot, so the (unlikely) failure does not repeat on
     * every reload.
     */
    private boolean pskOptionWarned;

    /**
     * Set when the native context's {@code SSL_OP_ALLOW_NO_DHE_KEX} option
     * could not be aligned with the current snapshot. In that state the
     * endpoint must not offer pre-shared keys, because it cannot tell whether
     * a PSK handshake would use the non-forward-secret no-DHE mode.
     */
    private volatile boolean pskOptionMisaligned;

    /**
     * Set once the PSK-only (no-DHE) forward-secrecy tradeoff was reported, so
     * a certificate reload or context re-initialisation does not repeat it.
     */
    private boolean pskOnlyNoDheWarned;

    /**
     * Last time the missing-certificate warning was emitted for an SNI host,
     * so a client repeatedly requesting a configured-but-unloadable host
     * cannot flood the log at handshake rate.
     */
    private long lastSniMissingLogMs;
    private static final long SNI_MISSING_LOG_INTERVAL_MS = 60_000;


    /**
     * Creates the certificate manager for an endpoint.
     *
     * @param nameSupplier     Supplies the endpoint name for logging
     * @param protocolSupplier Supplies the application protocol whose ALPN
     *                         identifiers are negotiated; may return
     *                         {@code null} before one is configured
     * @param hostResolver     Maps a lower-cased SNI host name to its
     *                         {@link SSLHostConfig}, returning {@code null}
     *                         when no host resolves
     */
    public QuicCertificateManager(Supplier<String> nameSupplier,
            Supplier<QuicProtocol> protocolSupplier,
            Function<String, SSLHostConfig> hostResolver) {
        this(nameSupplier, protocolSupplier, hostResolver, null);
    }


    /**
     * Creates a certificate manager using an explicit SSL method.
     *
     * @param nameSupplier     Supplies the endpoint name for logging
     * @param protocolSupplier Supplies the application protocol whose ALPN
     *                         identifiers are negotiated
     * @param hostResolver     Maps an SNI host name to its host configuration
     * @param sslMethod        The SSL method to use, or {@code null} for the
     *                         OpenSSL QUIC server method
     */
    public QuicCertificateManager(Supplier<String> nameSupplier,
            Supplier<QuicProtocol> protocolSupplier,
            Function<String, SSLHostConfig> hostResolver,
            MemorySegment sslMethod) {
        this.nameSupplier = nameSupplier;
        this.protocolSupplier = protocolSupplier;
        this.hostResolver = hostResolver;
        this.sslMethod = sslMethod;
    }


    /**
     * Installs the initial certificate snapshot and creates the native
     * {@code SSL_CTX} with its ALPN and SNI callbacks. Called once from the
     * endpoint's {@code initialiseSsl()} before the per-host TLS information
     * is populated. A second call while the context is still initialized is
     * rejected (it would otherwise overwrite and leak the live context and its
     * callback arenas); call {@link #release()} first for a restart.
     *
     * @param initialConfig The certificate snapshot built by the endpoint
     *                      before this call
     *
     * @throws IllegalStateException If the manager is already initialized
     * @throws Exception If the context or a callback could not be created
     */
    public synchronized void initialize(QuicCertConfig initialConfig)
            throws Exception {
        if (sslCtx != null && !sslCtx.equals(MemorySegment.NULL)) {
            // Re-initializing would overwrite (and leak) the live SSL_CTX and
            // its callback arenas while the listener/connections still use the
            // old generation. Release first for a restart.
            throw new IllegalStateException(sm.getString(
                    "quicEndpoint.certificateManagerAlreadyInitialized"));
        }
        // A previous initialize() that failed in SSL_CTX_new() left its
        // initial snapshot owned by this manager (sslCtx is still NULL). A
        // retry must release that snapshot before replacing it; otherwise its
        // native X509/EVP_PKEY objects and arena are lost. release() is still
        // the normal cleanup for a failed bind, this makes a direct retry on
        // the public manager API safe as well.
        QuicCertConfig previousConfig = certConfig;
        certConfig = initialConfig;
        if (previousConfig != null && previousConfig != initialConfig) {
            // Never free the snapshot that is being installed. A caller may
            // retry initialize() with the same QuicCertConfig object it passed
            // before; freeing it here would leave certConfig (and the SNI/PSK
            // callbacks) pointing at freed native X509/EVP_PKEY objects and a
            // closed arena.
            try {
                previousConfig.free();
            } finally {
                CertificateLoader.closeQuietly(previousConfig.arena);
            }
        }
        createNativeSslContext();
    }


    /**
     * Returns the native {@code SSL_CTX} so the endpoint can create its
     * listener from it and read the negotiated ciphers for JMX reporting.
     *
     * @return The native SSL_CTX, or {@link MemorySegment#NULL} before
     *         {@link #initialize} has run
     */
    public synchronized MemorySegment getSslCtx() {
        return sslCtx;
    }


    /**
     * Creates the native QUIC {@code SSL_CTX} and installs the ALPN, SNI and
     * pre-shared key callbacks. The context itself holds no certificates;
     * they are applied per connection by the SNI callback from the current
     * {@link QuicCertConfig}.
     *
     * @throws Exception If the context or a callback could not be created
     */
    private void createNativeSslContext() throws Exception {
        MemorySegment method = sslMethod != null ? sslMethod : QuicBindings.OSSL_QUIC_server_method();

        sslCtx = openssl_h.SSL_CTX_new(method);
        if (sslCtx.equals(MemorySegment.NULL)) {
            throw new java.io.IOException(
                    sm.getString("quicEndpoint.contextCreateError"));
        }

        // ngtcp2 uses a normal TLS_server_method context; QUIC mandates TLS
        // 1.3, so constrain the protocol range explicitly. This is harmless
        // for the OpenSSL QUIC method as well. A failure must abort rather
        // than silently allowing a wider protocol range (the shared manager
        // also serves the ngtcp2 TLS_server_method context).
        long minVersionRc = QuicBindings.SSL_CTX_set_min_proto_version(sslCtx,
                openssl_h.TLS1_3_VERSION());
        long maxVersionRc = QuicBindings.SSL_CTX_set_max_proto_version(sslCtx,
                openssl_h.TLS1_3_VERSION());
        if (minVersionRc < 1 || maxVersionRc < 1) {
            throw new java.io.IOException(sm.getString(
                    "quicEndpoint.tlsVersionSetError",
                    Long.valueOf(minVersionRc), Long.valueOf(maxVersionRc)));
        }

        // Session resumption is deliberately disabled. All SNI hosts share
        // this one SSL_CTX, and OpenSSL does not associate a TLS 1.3 session
        // with the SNI of the ClientHello that established it: a ticket from
        // one host could be resumed under another, bypassing that host's
        // pre-shared-key policy. Ticket keys also survive swapConfig(), so a
        // PSK removal would not revoke tickets already held by clients.
        // Without per-host session/ticket isolation there is no safe
        // resumption policy for virtual hosts, so issue no tickets at all.
        if (QuicBindings.SSL_CTX_set_num_tickets(sslCtx, 0) != 1) {
            throw new java.io.IOException(
                    sm.getString("quicEndpoint.sessionTicketPolicyError"));
        }
        openssl_h_Compatibility.SSL_CTX_set_options(sslCtx,
                openssl_h.SSL_OP_NO_TICKET());

        // Enable partial and moving-buffer writes on the TLS context. The
        // standard TLS stack (used by the ngtcp2 transport's
        // TLS_server_method context) copies these modes into each
        // connection; the OpenSSL QUIC endpoint additionally applies them
        // explicitly to accepted QUIC connections, whose default stream
        // mode is not populated from the context in this build.
        // Without SSL_MODE_ENABLE_PARTIAL_WRITE, SSL_write_ex() on a QUIC
        // stream is an all-or-nothing writer: a write that only gets a
        // prefix appended arms an internal retry state that rejects every
        // later call not presenting the exact same buffer address and
        // length (SSL_R_BAD_WRITE_RETRY), permanently wedging the stream's
        // send side - and every write path in this package stages into a
        // fresh buffer per attempt. Without
        // SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, a write that would-blocks
        // before accepting any byte may only be retried with the exact same
        // address; the retry from a freshly staged remainder buffer would
        // otherwise fail with the same SSL_R_BAD_WRITE_RETRY. With both
        // modes set, a partial acceptance simply returns the accepted count
        // and a would-block retry may re-present the remainder from a new
        // buffer.
        long ctxModeRc = QuicBindings.SSL_CTX_ctrl(sslCtx, QuicBindings.SSL_CTRL_MODE,
                QuicBindings.SSL_MODE_ENABLE_PARTIAL_WRITE |
                        QuicBindings.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,
                MemorySegment.NULL);
        if (ctxModeRc == 0) {
            throw new java.io.IOException(
                    sm.getString("quicEndpoint.contextCreateError"));
        }

        applyPskOnlyOptions();
        applyCipherSuites(certConfig);

        // Set up ALPN callback for "h3" protocol
        setupAlpnCallback();

        // Note: QUIC datagram support (RFC 9297 / HTTP Datagrams RFC 9221)
        // is requested via SSL_set_value_uint with the
        // SSL_VALUE_CLASS_FEATURE_REQUEST class, not via
        // SSL_CTX_set_options: OpenSSL has no SSL_OP bit for datagrams
        // (bit 30 is SSL_OP_NO_RENEGOTIATION). Datagram support is not
        // implemented here.

        // Set up the SNI (server name) callback used for per-connection
        // certificate selection. The SSL_CTX itself holds no certificates;
        // every connection's certificate is applied by the callback from the
        // current QuicCertConfig.
        setupSniCallback();

        // Set up the TLS 1.3 pre-shared key find-session callback. OpenSSL
        // copies the context's callback to every connection SSL it creates,
        // including the connections a QUIC listener accepts, so one
        // context-level callback covers all connections.
        setupPskCallback();
    }


    /**
     * Aligns the native context's pre-shared-key options with the current
     * configuration snapshot.
     * <p>
     * With no certificate anywhere on the endpoint, a pre-shared key
     * handshake is the only handshake possible and the pre-shared key alone
     * must authenticate the server. TLS 1.3 puts the server in the (no DHE)
     * key exchange mode for that, which OpenSSL only lets the server select
     * when SSL_OP_ALLOW_NO_DHE_KEX is set. Without the option (a mixed
     * certificate + pre-shared key endpoint) a resolved identity still
     * produces a pre-shared key handshake, but in the DHE mode. When the
     * serving host also has a certificate, that certificate is an additional
     * authenticator (the forward-secure shape preferred for hosts that have a
     * certificate); a mixed endpoint whose serving host has no certificate
     * gets a DHE PSK handshake without a certificate.
     * <p>
     * The option is applied to the context, so it governs connections created
     * from now on; already handshaken connections keep the options they
     * inherited at creation. Must be re-applied whenever the snapshot is
     * swapped, not only at context creation, or a reload that turns the
     * endpoint pre-shared-key-only (or restores certificates) is served
     * inconsistently until restart.
     */
    private void applyPskOnlyOptions() {
        if (sslCtx == null || sslCtx.equals(MemorySegment.NULL)) {
            // No context to configure (before initialize, or after release)
            return;
        }
        QuicCertConfig config = certConfig;
        boolean wantOption = config != null && config.pskOnly;
        if (wantOption) {
            if (!pskOnlyNoDheWarned) {
                pskOnlyNoDheWarned = true;
                log.warn(sm.getString("quicEndpoint.pskOnlyNoForwardSecrecy"));
            }
            openssl_h_Compatibility.SSL_CTX_set_options(sslCtx,
                    QuicBindings.SSL_OP_ALLOW_NO_DHE_KEX);
        } else {
            openssl_h_Compatibility.SSL_CTX_clear_options(sslCtx,
                    QuicBindings.SSL_OP_ALLOW_NO_DHE_KEX);
        }
        boolean optionSet =
                (openssl_h_Compatibility.SSL_CTX_get_options(sslCtx)
                        & QuicBindings.SSL_OP_ALLOW_NO_DHE_KEX) != 0;
        pskOptionMisaligned = optionSet != wantOption;
        if (pskOptionMisaligned) {
            // Handled non-fatal native failure: drain the error queue entry so
            // it cannot be mistaken for a later accept failure. PSK selection
            // is disabled while the option state is unknown (see
            // resolvePskSelector) so a certificate endpoint can never fall
            // back to a non-forward-secret PSK handshake.
            QuicDiagnostics.clearErrorQueue();
            if (!pskOptionWarned) {
                pskOptionWarned = true;
                log.warn(sm.getString("quicEndpoint.pskOnlyOptionRejected",
                        Boolean.valueOf(wantOption)));
            }
        }
    }


    /**
     * Applies the TLS 1.3 cipher suites of the snapshot to the native
     * SSL_CTX. The QUIC endpoint uses a single shared context; per-host
     * cipher configurations that differ from the default host cannot be
     * represented and are reported when the snapshot is built.
     *
     * @param config The certificate snapshot whose suite list to apply
     */
    private void applyCipherSuites(QuicCertConfig config) {
        if (config == null || config.cipherSuites == null ||
                sslCtx == null || sslCtx.equals(MemorySegment.NULL)) {
            return;
        }
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment suites = localArena.allocateFrom(config.cipherSuites);
            int rc = openssl_h.SSL_CTX_set_ciphersuites(sslCtx, suites);
            if (rc != 1) {
                // SSL_CTX_set_ciphersuites() leaves the previous (default)
                // TLS 1.3 suite list in place on parse failure. Continuing
                // would silently serve suites the operator did not configure,
                // so fail the configuration like the ngtcp2 transport does.
                String message = sm.getString(
                        "quicEndpoint.cipherSuitesSetError",
                        config.cipherSuites, Integer.valueOf(rc));
                QuicDiagnostics.clearErrorQueue();
                throw new IllegalArgumentException(message);
            }
        }
    }


    /**
     * Swaps in the new certificate configuration and frees the native objects
     * of the previous one. Must only run on the poll thread (or when the poll
     * thread is not running) so it is serialized with the SNI callback.
     * <p>
     * Freeing the previous configuration is safe: every connection that
     * applied its certificates during a handshake holds its own references
     * taken by {@code SSL_use_certificate()}/{@code SSL_use_PrivateKey()} /
     * {@code SSL_add1_chain_cert()}, and no callback can be running
     * concurrently on the poll thread.
     *
     * @param newConfig The configuration to install
     * @param reason    A short description of what triggered the reload
     *
     * @throws IllegalArgumentException If the cipher policy cannot be parsed;
     *         the caller still owns {@code newConfig}
     * @throws IllegalStateException If the manager has already been released;
     *         {@code newConfig} is discarded and freed here, so the caller
     *         must not release it again
     */
    public synchronized void swapConfig(QuicCertConfig newConfig, String reason) {
        if (sslCtx == null || sslCtx.equals(MemorySegment.NULL)) {
            // A swap after release() would replace certConfig with a snapshot
            // that nothing will ever free (the context and arena owner is
            // gone). Discard the new snapshot here so a public-API caller
            // cannot leak it, and reject the operation.
            try {
                newConfig.free();
            } finally {
                CertificateLoader.closeQuietly(newConfig.arena);
            }
            throw new IllegalStateException(sm.getString(
                    "quicEndpoint.certificateManagerReleased"));
        }
        // Validate and apply the new cipher policy before taking ownership of
        // the snapshot. On failure the caller still owns newConfig and the
        // previous snapshot stays active; applyCipherSuites() does not change
        // the context's cipher list when parsing fails.
        applyCipherSuites(newConfig);
        QuicCertConfig oldConfig = certConfig;
        certConfig = newConfig;
        if (oldConfig != null && oldConfig != newConfig) {
            // Installing the same snapshot again must not free the live
            // configuration now referenced by certConfig (see initialize()).
            try {
                oldConfig.free();
            } finally {
                CertificateLoader.closeQuietly(oldConfig.arena);
            }
        }
        // The snapshot swap can change the endpoint's pre-shared-key-only
        // state; the context option must follow it for the connections
        // handshaked from now on.
        applyPskOnlyOptions();
        if (log.isInfoEnabled()) {
            log.info(sm.getString("quicEndpoint.certificateReloaded",
                    nameSupplier.get(), reason));
        }
    }


    /**
     * Releases the native resources owned by this manager: the SSL_CTX, the
     * current certificate snapshot and the callback arenas. Idempotent
     * and safe to call before {@link #initialize} has run. Called from the
     * endpoint's bind-resource cleanup after the poll thread has stopped, so
     * no handshake can be applying certificates concurrently.
     */
    public synchronized void release() {
        if (sslCtx != null && !sslCtx.equals(MemorySegment.NULL)) {
            try {
                openssl_h.SSL_CTX_free(sslCtx);
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error freeing QUIC SSL_CTX during bind cleanup",
                            t);
                }
            }
            sslCtx = MemorySegment.NULL;
        }
        QuicCertConfig configToFree = certConfig;
        certConfig = null;
        if (configToFree != null) {
            try {
                configToFree.free();
            } finally {
                CertificateLoader.closeQuietly(configToFree.arena);
            }
        }
        if (alpnCallbackArena != null) {
            try {
                alpnCallbackArena.close();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error closing ALPN arena during bind cleanup", t);
                }
            }
            alpnCallbackArena = null;
        }
        if (sniCallbackArena != null) {
            try {
                sniCallbackArena.close();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error closing SNI arena during bind cleanup", t);
                }
            }
            sniCallbackArena = null;
        }
        if (pskCallbackArena != null) {
            try {
                pskCallbackArena.close();
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Error closing PSK arena during bind cleanup", t);
                }
            }
            pskCallbackArena = null;
        }
    }


    /**
     * Sets up ALPN select callback on the SSL_CTX to negotiate the protocols
     * advertised by the {@link QuicProtocol}. Uses a Java FFM upcall stub to
     * bridge the C callback to a Java method.
     * <p>
     * A QUIC server must negotiate an application protocol (RFC 9001 requires
     * TLS 1.3; RFC 9114 Section 3 identifies HTTP/3 by the ALPN "h3"
     * identifier). Without the callback no protocol is ever selected and the
     * endpoint would accept connections it cannot serve, so a setup failure
     * is fatal: the bind fails instead of starting such a listener.
     *
     * @throws java.io.IOException If the callback could not be installed
     */
    private void setupAlpnCallback() throws java.io.IOException {
        try {
            alpnCallbackArena = Arena.ofShared();

            // Upcall method signature: int(SSL*, const unsigned char**,
            // unsigned char*, const unsigned char*, unsigned int, void*)
            MethodHandle alpnCb = MethodHandles.lookup()
                    .findVirtual(QuicCertificateManager.class,
                            "alpnSelectCallback",
                            MethodType.methodType(int.class,
                                    MemorySegment.class, MemorySegment.class,
                                    MemorySegment.class, MemorySegment.class,
                                    int.class, MemorySegment.class))
                    .bindTo(this);

            FunctionDescriptor upcallDesc = FunctionDescriptor.of(
                    openssl_h.C_INT,
                    openssl_h.C_POINTER, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, openssl_h.C_POINTER,
                    openssl_h.C_INT, openssl_h.C_POINTER);

            MemorySegment callback = Linker.nativeLinker()
                    .upcallStub(alpnCb, upcallDesc, alpnCallbackArena);

            // SSL_CTX_set_alpn_select_cb via direct symbol lookup
            MemorySegment alpnAddr =
                    openssl_h.SSL_CTX_set_alpn_select_cb$address();
            MethodHandle setAlpnCb = Linker.nativeLinker().downcallHandle(
                    alpnAddr,
                    FunctionDescriptor.ofVoid(
                            openssl_h.C_POINTER, openssl_h.C_POINTER,
                            openssl_h.C_POINTER));
            setAlpnCb.invokeExact(sslCtx, callback, MemorySegment.NULL);
            if (log.isDebugEnabled()) {
                log.debug("ALPN callback set for QUIC");
            }
        } catch (Throwable t) {
            throw new java.io.IOException(
                    sm.getString("quicEndpoint.alpnCallbackSetError"), t);
        }
    }


    /**
     * ALPN select callback - selects the first identifier, in the preference
     * order supplied by the application protocol
     * ({@link QuicProtocol#getAlpnIdentifiers()}), that the client offered.
     * When no application protocol has been configured yet, no identifier can
     * be selected and the handshake is rejected. Returns
     * {@code SSL_TLSEXT_ERR_OK} (0) on success and
     * {@code SSL_TLSEXT_ERR_ALERT_FATAL} (2) when no supported protocol is
     * offered.
     * <p>
     * Never called from Java code; the FFM upcall stub looks it up by name in
     * {@link #setupAlpnCallback()}, hence {@code @SuppressWarnings("unused")}.
     */
    @SuppressWarnings("unused")
    private int alpnSelectCallback(MemorySegment ssl, MemorySegment out,
            MemorySegment outlen, MemorySegment in, int inlen,
            MemorySegment arg) {
        // A throwable escaping an FFM upcall ends the process, so the whole
        // body - including the protocol access that precedes the arena work -
        // is guarded down to Throwable: an Error must not cross the native
        // boundary either. A failure rejects the handshake.
        try {
            QuicProtocol protocol = protocolSupplier.get();
            if (protocol == null) {
                return QuicBindings.SSL_TLSEXT_ERR_ALERT_FATAL;
            }
            String[] identifiers = protocol.getAlpnIdentifiers();
            try (Arena localArena = Arena.ofConfined()) {
                // The upcall descriptor declares the pointer arguments as
                // openssl_h.C_POINTER - an address layout carrying an
                // unbounded byte-sequence target layout - so the delivered
                // segment is already readable and writable (only a bare
                // ValueLayout.ADDRESS declaration would deliver a
                // zero-length segment; see the errno comments for that
                // case). The reinterpret is therefore a bound-limiting
                // defence, not a prerequisite for the reads: it shrinks the
                // unbounded segment to inlen so the scan below cannot run
                // past the offered-protocol list. The writes to out/outlen
                // need no such treatment.
                in = in.reinterpret(inlen, localArena, null);
                // Server preference order: for each configured identifier, scan
                // the client's list. This honours the order documented by
                // QuicProtocol.getAlpnIdentifiers(); scanning the client list
                // first would select the client's preferred match instead.
                for (String identifier : identifiers) {
                    int identifierLength = identifier.length();
                    if (identifierLength <= 0 || identifierLength > 255) {
                        continue;
                    }
                    int offset = 0;
                    while (offset < inlen) {
                        int protoLen = in.get(ValueLayout.JAVA_BYTE, offset) & 0xFF;
                        if (protoLen == 0) {
                            break;
                        }
                        // A malformed offered-protocol list can declare a
                        // length that overruns the buffer. Reject it explicitly
                        // (fall through to the no-match ALERT_FATAL below)
                        // rather than relying on the outer catch to turn an
                        // out-of-bounds read into an alert by accident.
                        if (protoLen > inlen - (offset + 1)) {
                            break;
                        }
                        if (protoLen == identifierLength &&
                                matchesAlpnIdentifier(in, offset + 1,
                                        identifierLength, identifier)) {
                            out.set(ValueLayout.ADDRESS, 0,
                                    MemorySegment.ofAddress(
                                            in.address() + offset + 1));
                            outlen.set(ValueLayout.JAVA_BYTE, 0,
                                    (byte) protoLen);
                            return QuicBindings.SSL_TLSEXT_ERR_OK;
                        }
                        offset += 1 + protoLen;
                    }
                }
            }
        } catch (Throwable t) {
            // Must not throw across the native boundary; report and reject
            // the handshake instead of failing silently.
            log.warn(sm.getString("quicEndpoint.alpnSelectError"), t);
        }
        // For an endpoint that only serves one application protocol family,
        // ALERT_FATAL on no-match is the RFC 7301 / RFC 9114 correct behaviour
        // (returning the undefined warning code 1 makes OpenSSL continue the
        // handshake with no protocol selected).
        return QuicBindings.SSL_TLSEXT_ERR_ALERT_FATAL;
    }


    /**
     * Checks whether the protocol bytes offered at the given position of the
     * ALPN list match one supported identifier.
     *
     * @param in         The (reinterpreted) offered-protocol list
     * @param start      Offset of the first byte of the offered protocol
     * @param length     Length of the offered protocol
     * @param identifier The identifier supported by the application protocol
     *
     * @return {@code true} if the offered protocol matches the identifier
     */
    private static boolean matchesAlpnIdentifier(MemorySegment in, long start,
            int length, String identifier) {
        if (identifier.length() != length) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            if (in.get(ValueLayout.JAVA_BYTE, start + i) !=
                    (byte) identifier.charAt(i)) {
                return false;
            }
        }
        return true;
    }


    /**
     * Sets up the SNI (server name) callback on the SSL_CTX. In OpenSSL 4.0
     * {@code SSL_CTX_set_tlsext_servername_callback()} is a macro over
     * {@code SSL_CTX_callback_ctrl()}.
     *
     * @throws java.io.IOException            If the callback could not be
     *                                        installed
     * @throws ReflectiveOperationException   If the upcall stub could not be
     *                                        created
     */
    private void setupSniCallback()
            throws java.io.IOException, ReflectiveOperationException {
        sniCallbackArena = Arena.ofShared();

        // Upcall method signature: int(SSL*, int *al, void *arg)
        MethodHandle sniCb = MethodHandles.lookup()
                .findVirtual(QuicCertificateManager.class, "sniCallback",
                        MethodType.methodType(int.class, MemorySegment.class,
                                MemorySegment.class, MemorySegment.class))
                .bindTo(this);

        FunctionDescriptor upcallDesc = FunctionDescriptor.of(
                openssl_h.C_INT,
                openssl_h.C_POINTER, openssl_h.C_POINTER, openssl_h.C_POINTER);

        MemorySegment callback = Linker.nativeLinker()
                .upcallStub(sniCb, upcallDesc, sniCallbackArena);

        long rc = QuicBindings.SSL_CTX_callback_ctrl(sslCtx,
                QuicBindings.SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, callback);
        if (rc == 0) {
            throw new java.io.IOException(
                    sm.getString("quicEndpoint.sniCallbackSetError"));
        }
        if (log.isDebugEnabled()) {
            log.debug("SNI callback set for QUIC certificate selection");
        }
    }


    /**
     * SNI (server name) callback. Resolves the requested host name against
     * the configured {@link SSLHostConfig} entries using the same algorithm
     * as the endpoint's host resolution (exact match, then wildcard, then
     * default) and applies that host's certificate(s) to this connection. The
     * callback is invoked for every connection, including those without an
     * SNI extension (in which case the host name is {@code null} and the
     * default host is used). The name is always accepted so that unknown host
     * names simply fall back to the default certificate.
     * <p>
     * This runs on the poll thread during the handshake. The native
     * certificate objects applied here belong to the current
     * {@link #certConfig}; {@code SSL_use_certificate()} and
     * {@code SSL_use_PrivateKey()} take their own references so the
     * configuration may be discarded afterwards.
     * <p>
     * Never called from Java code; the FFM upcall stub looks it up by name in
     * {@link #setupSniCallback()}, hence {@code @SuppressWarnings("unused")}.
     *
     * @param ssl the connection SSL object
     * @param al  pointer to the alert value to send on rejection
     * @param arg unused
     *
     * @return {@code SSL_TLSEXT_ERR_OK} when the host's certificate material
     *         was applied, otherwise {@code SSL_TLSEXT_ERR_ALERT_FATAL}; a
     *         host that also has pre-shared keys must not continue with PSK
     *         authentication after its configured certificates failed to
     *         apply, because that would silently change the authentication
     *         mode
     */
    @SuppressWarnings("unused")
    private int sniCallback(MemorySegment ssl, MemorySegment al,
            MemorySegment arg) {
        try {
            QuicCertConfig config = certConfig;
            if (config == null) {
                return QuicBindings.SSL_TLSEXT_ERR_OK;
            }
            if (!applyCertEntries(ssl, resolveCertEntries(ssl, config))) {
                if (log.isErrorEnabled()) {
                    log.error(sm.getString("quicEndpoint.sniCertApplyFailed"));
                }
                setSniAlert(al, QuicBindings.SSL_AD_INTERNAL_ERROR);
                return QuicBindings.SSL_TLSEXT_ERR_ALERT_FATAL;
            }
            return QuicBindings.SSL_TLSEXT_ERR_OK;
        } catch (Throwable t) {
            if (log.isErrorEnabled()) {
                log.error(sm.getString("quicEndpoint.sniCallbackError"), t);
            }
            // A throwable escaping an FFM upcall ends the process. Reject the
            // handshake instead of continuing without the configured material.
            setSniAlert(al, QuicBindings.SSL_AD_INTERNAL_ERROR);
            return QuicBindings.SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }


    /**
     * Sets the alert value OpenSSL sends when the SNI callback returns
     * {@code SSL_TLSEXT_ERR_ALERT_FATAL}. Failure to write the optional
     * pointer is ignored; OpenSSL then uses its default alert.
     *
     * @param al    The {@code int *al} callback argument
     * @param alert The TLS alert description
     */
    private static void setSniAlert(MemorySegment al, int alert) {
        if (al == null || al.equals(MemorySegment.NULL)) {
            return;
        }
        try {
            al.reinterpret(ValueLayout.JAVA_INT.byteSize())
                    .set(ValueLayout.JAVA_INT, 0, alert);
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("Could not set QUIC SNI alert", t);
            }
        }
    }


    /**
     * Resolves the certificate entries of the host that serves one connection,
     * applying the endpoint's host resolution and default-host fallback.
     *
     * @param ssl    The connection SSL object
     * @param config The current configuration snapshot
     *
     * @return The entries of the serving host: the default host's entries when
     *         no SNI was sent or no configured host matched; an empty list
     *         for a pre-shared key-only host and for a host whose
     *         certificates failed to load (the latter is logged)
     */
    private List<CertificateLoader.CertificateEntry> resolveCertEntries(
            MemorySegment ssl, QuicCertConfig config) {
        return resolveCertEntries(config, resolveServingHostKey(ssl, config));
    }


    /**
     * Resolves the certificate entries for an already resolved serving host
     * key, so callers that need both the entries and the host's PSK selector
     * (the find-session callback) read the native SNI value only once.
     *
     * @param config  The current configuration snapshot
     * @param hostKey The lower-cased serving host key
     *
     * @return The entries of the serving host
     */
    private List<CertificateLoader.CertificateEntry> resolveCertEntries(
            QuicCertConfig config, String hostKey) {
        List<CertificateLoader.CertificateEntry> entries =
                config.certsByHost.get(hostKey);
        if (entries != null) {
            return entries;
        }
        if (hostKey.equals(config.defaultHostName)) {
            // The name matched no configured host (resolution already fell
            // back to the default host config) or matched the default host
            // itself: serving the default certificate is the documented
            // behaviour for both cases.
            return config.defaultCerts;
        }
        // The name matched a specifically configured host whose certificates
        // failed to load (a pre-shared key-only host is mapped to an empty
        // list and handled above, so it never reaches this branch). The
        // configuration builder rejects a host that also has pre-shared keys,
        // so no PSK selector can make this handshake succeed. Presenting the
        // default host's certificate would silently serve a name-mismatched
        // identity; apply nothing so the handshake fails visibly for this
        // host.
        long now = System.currentTimeMillis();
        if (now - lastSniMissingLogMs >= SNI_MISSING_LOG_INTERVAL_MS) {
            lastSniMissingLogMs = now;
            log.error(sm.getString("quicEndpoint.sniHostCertificateMissing",
                    hostKey));
        }
        return List.of();
    }


    /**
     * Resolves the host a connection is served by, the single shared form of
     * "server name (if any) -&gt; lower-case -&gt; endpoint host resolver
     * -&gt; default-host fallback" used by both the SNI certificate callback
     * and the pre-shared key find-session callback, so the two cannot drift
     * apart.
     *
     * @param ssl    The connection SSL object
     * @param config The current configuration snapshot
     *
     * @return The lower-cased key of the serving host in the snapshot maps;
     *         {@link QuicCertConfig#defaultHostName} when no SNI was sent or
     *         the name resolved to no host at all
     */
    private String resolveServingHostKey(MemorySegment ssl, QuicCertConfig config) {
        // Single shared SNI read (TLSEXT_NAMETYPE_HOST_NAME + lower-casing),
        // see QuicConnectionWrapper.readSniHostNameNative().
        String name = QuicConnectionWrapper.readSniHostNameNative(ssl);

        if (name == null) {
            return config.defaultHostName;
        }
        SSLHostConfig hostConfig = hostResolver.apply(name);
        if (hostConfig == null) {
            // No host resolved at all (no default configured): previous
            // behaviour, serve the default host's material.
            return config.defaultHostName;
        }
        return hostConfig.getHostName().toLowerCase(Locale.ENGLISH);
    }


    /**
     * Applies a host's certificate entries to one connection. Applying the
     * same entries twice (the pre-shared key callback may have applied them
     * already, see {@link #resolvePskSelector}) is idempotent: the leaf and
     * key replace the ones of the same key type, and each applied entry's
     * chain replaces (never accumulates onto) the chain of its key slot -
     * see the chain handling inside.
     *
     * @param ssl     The connection SSL object
     * @param entries The entries to apply; an empty list applies nothing
     *
     * @return {@code true} if every entry was applied (including the vacuous
     *         case of an empty list), {@code false} if at least one failed
     */
    private boolean applyCertEntries(MemorySegment ssl,
            List<CertificateLoader.CertificateEntry> entries) {
        // Apply every entry of the host. Entries of different key types
        // coexist on the connection (a repeated
        // SSL_use_certificate()/SSL_use_PrivateKey() pair only replaces the
        // certificate of the same key type), and OpenSSL selects among them
        // per handshake according to the client's signature algorithms.
        boolean allApplied = true;
        for (CertificateLoader.CertificateEntry entry : entries) {
            try {
                int rcCert = QuicBindings.SSL_use_certificate(ssl,
                        entry.leaf);
                int rcKey = QuicBindings.SSL_use_PrivateKey(ssl,
                        entry.key);
                if (rcCert != 1 || rcKey != 1) {
                    throw new IllegalStateException(
                            sm.getString(
                                    "quicEndpoint.certApplyError",
                                    Integer.valueOf(rcCert),
                                    Integer.valueOf(rcKey)));
                }
                // Replace the chain of the key slot the use_certificate call
                // above just selected, rather than accumulating onto it:
                // SSL_CTRL_CHAIN with a NULL stack is the
                // SSL_clear_chain_certs() macro (it frees the current key
                // entry's chain) and SSL_CTRL_CHAIN_CERT below is append-
                // only. Doing this replace-then-append on every application
                // makes re-applying the same entries idempotent (a client
                // offering a pre-shared key sees them applied by the PSK
                // callback first and by the SNI callback again), and stops
                // two same-key-type entries of one host from accumulating
                // each other's intermediates. (The original code attempted
                // the clear with SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS, which is
                // implemented only on SSL_CTX_ctrl: the SSL-level
                // ssl3_ctrl has no case for it, the call returned 0 having
                // cleared nothing - and the accepted-as-success 0 let every
                // re-application double the chain on the wire.)
                long rcClear = QuicBindings.SSL_ctrl(ssl,
                        QuicBindings.SSL_CTRL_CHAIN,
                        0L, MemorySegment.NULL);
                if (rcClear != 1) {
                    throw new IllegalStateException(
                            sm.getString(
                                    "quicEndpoint.chainCertClearError",
                                    Long.valueOf(rcClear)));
                }
                for (MemorySegment chainCert : entry.chain) {
                    long rcChain = QuicBindings.SSL_ctrl(ssl,
                            QuicBindings.SSL_CTRL_CHAIN_CERT, 1L,
                            chainCert);
                    if (rcChain != 1) {
                        throw new IllegalStateException(
                                sm.getString(
                                        "quicEndpoint.chainCertApplyError",
                                        Long.valueOf(rcChain)));
                    }
                }
            } catch (Throwable t) {
                // Applying this entry failed; keep trying the remaining
                // entries but report the failure to the caller so the
                // handshake can be rejected instead of falling back to PSK.
                allApplied = false;
                // SSL_use_certificate() only replaces a previously set
                // certificate of the *same* key type
                // (SSL_CTX_use_certificate(3)), so the entries already
                // applied for this connection stay in effect for their key
                // types, and the remaining entries are still offered as
                // alternatives (a later entry of the failed entry's type can
                // replace the partially applied state). OpenSSL selects the
                // certificate per handshake from the types applied so far.
                // The exception already carries the specific reason (the
                // certApplyError / chainCertClearError / chainCertApplyError
                // message formatted with the return codes) and this method is
                // not SNI-specific (the PSK resolver applies entries too), so
                // report it under its own message rather than a
                // callback-specific headline.
                if (log.isWarnEnabled()) {
                    String message = t.getMessage();
                    log.warn(message != null ? message : t.toString(), t);
                }
            }
        }
        return allApplied;
    }


    /**
     * Sets up the TLS 1.3 pre-shared key find-session callback on the
     * SSL_CTX using {@link CertificateLoader#installFindSessionCallback} (the
     * same installation used by the socket connector), with a per-connection
     * resolver (one listener serves every configured host). The callback stub
     * is installed unconditionally because hosts may gain pre-shared keys on a
     * configuration reload and the context-level callback is created once, so
     * an installation failure aborts the bind rather than surfacing later as a
     * connection that cannot complete a pre-shared-key handshake.
     *
     * @throws java.io.IOException If the callback could not be installed
     */
    private void setupPskCallback() throws java.io.IOException {
        try {
            pskCallbackArena = Arena.ofShared();
            CertificateLoader.installFindSessionCallback(sslCtx,
                    this::resolvePskSelector, pskCallbackArena);
            if (log.isDebugEnabled()) {
                log.debug("PSK find-session callback set for QUIC");
            }
        } catch (Throwable t) {
            throw new java.io.IOException(
                    sm.getString("quicEndpoint.pskCallbackSetError"), t);
        }
    }


    /**
     * Resolves the pre-shared key selector for one connection from its SNI
     * host name, using the same host resolution and default-host fallback as
     * the SNI certificate callback.
     * <p>
     * As a side effect the serving host's certificates (if any) are applied
     * to the connection here, before the selector is returned. The
     * find-session callback runs while the psk extension is being parsed;
     * the SNI callback (the certificate application point) only runs
     * afterwards, in the client-extension finalisation phase. OpenSSL decides
     * inside the psk parsing whether an unresolvable identity may fall back to
     * a full handshake by checking whether the connection already has a
     * certificate ({@code tls_parse_ctos_psk()},
     * {@code ssl/statem/extensions_srvr.c}), so without this early
     * application an unknown identity would abort the connection instead of
     * falling through to the certificate handshake. The SNI callback applies
     * the same entries again later, which is idempotent.
     *
     * @param ssl The connection SSL object (provided by the find-session
     *            callback, which runs while the ClientHello extensions are
     *            being parsed, after the server name extension)
     *
     * @return The selector for the host the connection is served by, or
     *         {@code null} when that host has no pre-shared keys (the
     *         handshake then proceeds without pre-shared key authentication)
     */
    private OpenSSLPreSharedKeySelector resolvePskSelector(MemorySegment ssl) {
        QuicCertConfig config = certConfig;
        if (config == null || pskOptionMisaligned) {
            // If the context option could not be aligned with the snapshot,
            // the endpoint cannot know whether a PSK handshake would be
            // non-forward-secret. Fail closed by not offering PSK identities;
            // certificate authentication remains available.
            return null;
        }
        // Resolve the serving host once and use it for both the certificate
        // entries and the PSK selector instead of reading the native SNI
        // value twice per PSK handshake.
        String hostKey = resolveServingHostKey(ssl, config);
        if (!applyCertEntries(ssl, resolveCertEntries(config, hostKey))) {
            // Do not offer a PSK identity after the configured certificate
            // material failed to apply: that would let a certificate host
            // complete the handshake with pre-shared-key authentication
            // instead. The SNI callback runs later in this handshake and
            // rejects the connection if the re-application also fails; a
            // transient failure can still fall back to the certificate
            // handshake with no authentication downgrade.
            return null;
        }
        OpenSSLPreSharedKeySelector selector =
                config.pskByHost.get(hostKey);
        if (selector == null && hostKey.equals(config.defaultHostName)) {
            // The name resolved to the default host itself (or fell back to
            // it): its keys apply, which may be none.
            return config.defaultPskSelector;
        }
        return selector;
    }
}

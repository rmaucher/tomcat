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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.quic.QuicProtocol;
import org.apache.tomcat.util.res.StringManager;

/**
 * Owns the {@code quiche_config} of the endpoint: the ALPN list, the
 * resolved default-host certificate entry and the rebuild/swap lifecycle.
 * <p>
 * A {@code quiche_config} carries exactly one certificate chain and one
 * private key (BoringSSL {@code SSL_CTX_use_certificate_chain_file} /
 * {@code SSL_CTX_use_PrivateKey_file}; a repeated load replaces the first),
 * so the endpoint serves the default host with a single certificate entry: the
 * RSA entry when one is configured (widest client support), otherwise the
 * single configured entry; further entries are ignored with a warning. When
 * the entry references a separate chain file, the manager materializes one
 * concatenated PEM (leaf + intermediates) for quiche to load.
 * <p>
 * The config swap on reload is serialized on the endpoint's poll thread
 * (like the OpenSSL transport's {@code QuicCertificateManager.swapConfig}):
 * existing connections keep the config they were created with (a
 * {@code quiche_conn} holds its own reference on the TLS material), new
 * accepts use the new generation. On reload the (blocking) build runs
 * {@link #prepareConfig} off the poll thread and only the fast
 * {@link #installConfig} swap is submitted to the poll thread, so the slow
 * file/native work never stalls the packet loop.
 */
class QuicheCertificateManager {

    private static final Log log = LogFactory.getLog(QuicheCertificateManager.class);
    private static final StringManager sm =
            StringManager.getManager(QuicheEndpoint.class);

    /**
     * Server-advertised limit for client-initiated unidirectional streams.
     * HTTP/3 needs three (control, QPACK encoder, QPACK decoder); the value
     * is generous to leave headroom, the memory cost is negligible.
     */
    private static final long INITIAL_MAX_STREAMS_UNI = 128;

    private static final long INITIAL_MAX_DATA = 16L * 1024 * 1024;

    private static final long INITIAL_MAX_STREAM_DATA = 16L * 1024 * 1024;

    private final Supplier<QuicProtocol> protocolSupplier;

    /**
     * The current configuration generation. Immutable once published; read
     * by the poll thread when accepting connections.
     */
    private volatile Config config;

    private final AtomicLong generation = new AtomicLong();

    /**
     * Sequence for materialized PEM file names. Separate from
     * {@link #generation}: a file name only needs a fresh, distinct name,
     * and letting it consume from the config-generation counter would make
     * the installed generation numbers (logs, Config identity) jump about
     * whenever a chain file happens to be configured.
     */
    private final AtomicLong pemFileSequence = new AtomicLong();

    QuicheCertificateManager(Supplier<QuicProtocol> protocolSupplier) {
        this.protocolSupplier = protocolSupplier;
    }


    /**
     * An immutable configuration generation: the native config pointer plus
     * the materialized PEM file backing it (if any).
     */
    static final class Config {
        private final MemorySegment ptr;
        private final File materializedPem;
        private final long generation;
        // The reload trigger that built this generation; part of the object
        // so the install-time log line names the trigger of the generation
        // actually installed, not of whichever reload submitted the task
        // (two racing reloads otherwise mismatch reason and generation).
        // Null for the generation built by initialize().
        private final String reason;

        Config(MemorySegment ptr, File materializedPem, long generation,
                String reason) {
            this.ptr = ptr;
            this.materializedPem = materializedPem;
            this.generation = generation;
            this.reason = reason;
        }
    }


    MemorySegment getConfig() {
        Config c = config;
        return c == null ? MemorySegment.NULL : c.ptr;
    }


    /**
     * Builds and installs the initial configuration. Called from
     * {@code bind()} before the poll thread exists. A generation left over
     * from a previous bind of a restarted (not recreated) endpoint is
     * superseded and freed here; freeing is safe precisely because bind
     * runs with the poll loop stopped, so no connection can hold the old
     * config. Callers must not invoke this while the poll thread is
     * running - use {@link #prepareConfig} plus {@link #installConfig} for
     * reloads.
     *
     * @param sslHostConfig The default host configuration
     *
     * @throws IOException If the configuration (certificate, key, ALPN)
     *                     could not be built
     */
    void initialize(SSLHostConfig sslHostConfig) throws IOException {
        Config newConfig = buildConfig(sslHostConfig, null);
        Config old = config;
        config = newConfig;
        if (old != null) {
            freeConfig(old);
        }
    }


    /**
     * Builds a new configuration generation from the current host
     * configuration without installing it. Runs the file I/O (certificate
     * files, materialized PEM) and the native parsing, so it must NOT be
     * called on the endpoint's poll thread; the caller installs the result
     * with {@link #installConfig} on the poll thread and frees an unused
     * result with {@link #discardPrepared}.
     *
     * @param sslHostConfig The (new) default host configuration
     * @param reason        A short description of the reload trigger (log)
     *
     * @return The (not yet installed) configuration generation
     *
     * @throws IOException If the new configuration could not be built (the
     *                     previous configuration stays in place)
     */
    Config prepareConfig(SSLHostConfig sslHostConfig, String reason) throws IOException {
        try {
            return buildConfig(sslHostConfig, reason);
        } catch (IOException e) {
            log.warn(sm.getString("quicheEndpoint.certificateReloadFailed", reason), e);
            throw e;
        }
    }


    /**
     * Installs a prepared configuration generation as the current one. Must
     * run on the poll thread (or with the poll loop stopped) so the swap is
     * serialized with connection accepts. This is a fast operation (a field
     * swap, freeing the superseded generation and a log line) and is what
     * the endpoint's reload path submits as a poll task.
     *
     * @param newConfig A generation from {@link #prepareConfig}, not yet
     *                  installed or discarded. Its stored reason names the
     *                  reload trigger in the log line.
     */
    void installConfig(Config newConfig) {
        Config old = config;
        config = newConfig;
        if (old != null) {
            // A quiche_conn takes its own reference on the TLS material at
            // creation (SSL_new up-refs the SSL_CTX), so freeing the config
            // here cannot affect live connections; accepts run on the same
            // thread as this swap.
            freeConfig(old);
        }
        log.info(sm.getString("quicheEndpoint.certificateReloaded",
                newConfig.reason, Long.valueOf(newConfig.generation)));
    }


    /**
     * Frees a prepared generation that was never installed (e.g. the reload
     * task could not be submitted because the endpoint stopped).
     *
     * @param prepared A generation from {@link #prepareConfig}, not yet
     *                 installed
     */
    void discardPrepared(Config prepared) {
        freeConfig(prepared);
    }


    /**
     * Releases the current configuration and any materialized PEM file.
     * Called after the poll loop has stopped (no config user can remain).
     */
    void release() {
        Config old = config;
        config = null;
        if (old != null) {
            freeConfig(old);
        }
    }


    private void freeConfig(Config c) {
        try {
            QuicheBindings.quiche_config_free(c.ptr);
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("Error freeing quiche config generation " + c.generation, t);
            }
        }
        if (c.materializedPem != null) {
            try {
                Files.deleteIfExists(c.materializedPem.toPath());
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error deleting materialized certificate file " +
                            c.materializedPem, e);
                }
            }
        }
    }


    /**
     * Resolves the single certificate entry of the default host and builds a
     * new {@code quiche_config} from it.
     *
     * @param reason The reload trigger stored with the generation for the
     *               install-time log (null for the initial build)
     */
    private Config buildConfig(SSLHostConfig sslHostConfig, String reason)
            throws IOException {
        if (sslHostConfig.getCertificateVerification() !=
                SSLHostConfig.CertificateVerification.NONE) {
            // quiche's server config exposes no client-auth hook (and the
            // OpenSSL QUIC endpoint does not implement one either): make the
            // ignored setting visible rather than silently dropping it.
            log.warn(sm.getString("quicheEndpoint.clientAuthUnsupported",
                    sslHostConfig.getHostName(),
                    sslHostConfig.getCertificateVerification().name()));
        }
        SSLHostConfigCertificate certificate = resolveCertificate(sslHostConfig);

        String certFile = certificate.getCertificateFile();
        String keyFile = certificate.getCertificateKeyFile();
        if (certFile == null || certFile.length() == 0 ||
                keyFile == null || keyFile.length() == 0) {
            throw new IOException(sm.getString("quicheEndpoint.certificateLoadFailed",
                    sslHostConfig.getHostName(),
                    "certificateFile/certificateKeyFile are required by the quiche " +
                    "transport (keystore and PKCS#12 sources are not supported)"));
        }
        if (certFile.toLowerCase(java.util.Locale.ENGLISH).endsWith(".p12") ||
                certFile.toLowerCase(java.util.Locale.ENGLISH).endsWith(".pkcs12")) {
            throw new IOException(sm.getString("quicheEndpoint.certificateLoadFailed",
                    sslHostConfig.getHostName(),
                    "PKCS#12 certificate sources are not supported by the quiche " +
                    "transport (PEM files required)"));
        }

        File materialized = null;
        String chainFile = certificate.getCertificateChainFile();
        String certPath = certFile;
        if (chainFile != null && chainFile.length() > 0) {
            materialized = materializeChainPem(certFile, chainFile);
            certPath = materialized.getAbsolutePath();
        }

        MemorySegment cfg = QuicheBindings.quiche_config_new(
                QuicheBindings.QUICHE_PROTOCOL_VERSION);
        if (cfg.equals(MemorySegment.NULL)) {
            IOException ioe = new IOException(
                    sm.getString("quicheEndpoint.configCreateError"));
            // The config never existed to own the materialized PEM: delete
            // it here, or it leaks on the restart-per-reload failure path.
            if (materialized != null) {
                try {
                    Files.deleteIfExists(materialized.toPath());
                } catch (IOException suppressed) {
                    ioe.addSuppressed(suppressed);
                }
            }
            throw ioe;
        }
        long gen = generation.incrementAndGet();
        try (Arena localArena = Arena.ofConfined()) {
            int rc = QuicheBindings.quiche_config_load_cert_chain_from_pem_file(cfg,
                    localArena.allocateFrom(certPath));
            if (rc < 0) {
                throw new IOException(sm.getString("quicheEndpoint.certificateLoadFailed",
                        sslHostConfig.getHostName(),
                        "quiche_config_load_cert_chain_from_pem_file(" + certPath +
                        ") failed: " + quicheErrorName(rc)));
            }
            rc = QuicheBindings.quiche_config_load_priv_key_from_pem_file(cfg,
                    localArena.allocateFrom(keyFile));
            if (rc < 0) {
                throw new IOException(sm.getString("quicheEndpoint.certificateLoadFailed",
                        sslHostConfig.getHostName(),
                        "quiche_config_load_priv_key_from_pem_file(" + keyFile +
                        ") failed: " + quicheErrorName(rc)));
            }

            QuicProtocol protocol = protocolSupplier.get();
            if (protocol != null) {
                byte[] alpn = encodeAlpn(protocol.getAlpnIdentifiers());
                MemorySegment alpnSeg = localArena.allocate(alpn.length);
                alpnSeg.asByteBuffer().put(alpn);
                rc = QuicheBindings.quiche_config_set_application_protos(cfg,
                        alpnSeg, alpn.length);
                if (rc < 0) {
                    throw new IOException(sm.getString("quicheEndpoint.alpnEncodeFailed",
                            quicheErrorName(rc)));
                }
                long idleMs = protocol.getIdleTimeoutMs();
                if (idleMs > 0) {
                    // Reliable: applied before any connection is created,
                    // unlike the OpenSSL feature-request fallback.
                    QuicheBindings.quiche_config_set_max_idle_timeout(cfg, idleMs);
                }
                long maxStreams = protocol.getMaxConcurrentStreams();
                if (maxStreams <= 0) {
                    // QuicProtocol documents "0 or less" as "use the
                    // transport default", but quiche's own default for
                    // initial_max_streams_bidi is 0 and a zero value (the
                    // encoder omits the parameter when it is zero, which
                    // RFC 9000 Section 18.2 reads as a limit of zero)
                    // disallows every bidirectional stream — an HTTP/3
                    // endpoint configured that way would serve no requests,
                    // silently. Floor to one usable stream.
                    maxStreams = 1;
                    if (log.isDebugEnabled()) {
                        log.debug("maxConcurrentStreams is " +
                                protocol.getMaxConcurrentStreams() +
                                "; advertising one bidirectional stream " +
                                "instead of quiche's default of zero");
                    }
                }
                // Actually advertised (initial_max_streams_bidi is a
                // transport parameter quiche controls), unlike OpenSSL.
                QuicheBindings.quiche_config_set_initial_max_streams_bidi(cfg, maxStreams);
            }
            QuicheBindings.quiche_config_set_initial_max_streams_uni(cfg,
                    INITIAL_MAX_STREAMS_UNI);
            // quiche defaults every flow-control transport parameter to
            // zero, which silently discards all incoming stream data.
            // Without these, requests are fed but streams never become
            // readable.
            QuicheBindings.quiche_config_set_initial_max_data(cfg,
                    INITIAL_MAX_DATA);
            QuicheBindings.quiche_config_set_initial_max_stream_data_bidi_local(
                    cfg, INITIAL_MAX_STREAM_DATA);
            QuicheBindings.quiche_config_set_initial_max_stream_data_bidi_remote(
                    cfg, INITIAL_MAX_STREAM_DATA);
            QuicheBindings.quiche_config_set_initial_max_stream_data_uni(cfg,
                    INITIAL_MAX_STREAM_DATA);
        } catch (IOException | RuntimeException | Error e) {
            // Errors (OOM and friends) included: the native config and the
            // materialized PEM would otherwise leak on the way out. The
            // throwable is re-thrown unchanged (same propagation an
            // ExceptionUtils.handleThrowable pass-through would give).
            QuicheBindings.quiche_config_free(cfg);
            if (materialized != null) {
                try {
                    Files.deleteIfExists(materialized.toPath());
                } catch (IOException suppressed) {
                    e.addSuppressed(suppressed);
                }
            }
            throw e;
        }
        return new Config(cfg, materialized, gen, reason);
    }


    /**
     * Picks the single certificate entry the quiche config will carry: the
     * RSA entry when several are configured (widest client support),
     * otherwise the only entry.
     */
    private SSLHostConfigCertificate resolveCertificate(SSLHostConfig sslHostConfig)
            throws IOException {
        Collection<SSLHostConfigCertificate> certificates = sslHostConfig.getCertificates(true);
        if (certificates.isEmpty()) {
            throw new IOException(sm.getString("quicheEndpoint.certificateLoadFailed",
                    sslHostConfig.getHostName(), "no certificate configured"));
        }
        if (certificates.size() == 1) {
            return certificates.iterator().next();
        }
        SSLHostConfigCertificate chosen = null;
        for (SSLHostConfigCertificate certificate : certificates) {
            if (SSLHostConfigCertificate.Type.RSA.equals(certificate.getType())) {
                chosen = certificate;
                break;
            }
        }
        if (chosen == null) {
            chosen = certificates.iterator().next();
        }
        log.warn(sm.getString("quicheEndpoint.multipleCertificates",
                sslHostConfig.getHostName(),
                String.valueOf(chosen.getType())));
        return chosen;
    }


    /**
     * Materializes the concatenated PEM (leaf + intermediates) quiche loads
     * as a single chain file. The file is created atomically (temp + move)
     * with owner-only permissions, and deleted when its generation is
     * released.
     * <p>
     * The file lives in {@code java.io.tmpdir} (deliberate, reviewed): its
     * content is public certificate-chain data only - the private key is
     * never written here, quiche loads it from the configured key file - so
     * the shared temp directory is not a confidentiality boundary. The
     * write is race- and symlink-safe without extra configuration: the temp
     * name is unguessable (createTempFile, exclusive create) and the
     * ATOMIC_MOVE rename replaces rather than follows a pre-planted symlink
     * at the target name, while a key/cert swap between materialize and
     * load is self-defeating because the separately loaded key must still
     * match. A per-connector work/temp directory was considered and
     * rejected: the util.net layer has no access to the Server's temp
     * location without new configuration surface, and no config-free
     * alternative here changes the risk.
     */
    private File materializeChainPem(String certFile, String chainFile) throws IOException {
        File dir = new File(System.getProperty("java.io.tmpdir", "."));
        File tmp = File.createTempFile("quiche-cert-", ".pem", dir);
        File target = null;
        boolean materialized = false;
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(new String(Files.readAllBytes(new File(certFile).toPath()),
                    StandardCharsets.US_ASCII));
            sb.append('\n');
            sb.append(new String(Files.readAllBytes(new File(chainFile).toPath()),
                    StandardCharsets.US_ASCII));
            Files.write(tmp.toPath(), sb.toString().getBytes(StandardCharsets.US_ASCII));
            target = new File(dir, "quiche-cert-" + pemFileSequence.incrementAndGet() +
                    "-" + System.nanoTime() + ".pem");
            Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE);
            tightenPermissions(target);
            materialized = true;
            return target;
        } finally {
            if (!materialized) {
                // The materialization failed (unreadable chain, failed
                // write, failed rename, permission tightening failing
                // badly, Error, ...): do not leave the PEM behind under
                // whichever name the bytes ended up. After a completed
                // rename the temp name is gone, so deleting both names is
                // exact: one of the two deletes is a no-op.
                deleteQuietly(tmp);
                if (target != null) {
                    deleteQuietly(target);
                }
            }
        }
    }


    private void deleteQuietly(File f) {
        try {
            Files.deleteIfExists(f.toPath());
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error deleting certificate file " + f, e);
            }
        }
    }


    private void tightenPermissions(File f) {
        try {
            Files.setPosixFilePermissions(f.toPath(),
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not tighten permissions of " + f, e);
            }
        }
    }


    /**
     * Encodes the ALPN identifiers in the length-prefixed wire form quiche
     * expects ({@code [len][bytes][len][bytes]...}).
     *
     * @throws IOException if an identifier exceeds the 255 byte length the
     *                     one-byte wire prefix can carry
     */
    private static byte[] encodeAlpn(String[] identifiers) throws IOException {
        int total = 0;
        byte[][] encoded = new byte[identifiers.length][];
        for (int i = 0; i < identifiers.length; i++) {
            encoded[i] = identifiers[i].getBytes(StandardCharsets.US_ASCII);
            if (encoded[i].length > 255) {
                // Silent truncation by the (byte) cast below would corrupt
                // the wire format; reject instead.
                throw new IOException(sm.getString(
                        "quicheEndpoint.alpnIdentifierTooLong", identifiers[i]));
            }
            total += encoded[i].length + 1;
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] id : encoded) {
            out[pos++] = (byte) id.length;
            System.arraycopy(id, 0, out, pos, id.length);
            pos += id.length;
        }
        return out;
    }


    /**
     * Parses the certificate chain of the given entry with the JDK's
     * {@link java.security.cert.CertificateFactory} (quiche needs no Java
     * certificate objects; this serves the JMX/Manager/expiry consumers of
     * {@link org.apache.tomcat.util.net.quic.QuicSSLContext}).
     *
     * @param certificate The configured certificate entry
     *
     * @return The parsed chain, or {@code null} if it could not be read
     */
    X509Certificate[] parseChain(SSLHostConfigCertificate certificate) {
        List<X509Certificate> chain = new ArrayList<>();
        try {
            java.security.cert.CertificateFactory cf =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            addCertificates(cf, chain, certificate.getCertificateFile());
            String chainFile = certificate.getCertificateChainFile();
            if (chainFile != null && chainFile.length() > 0) {
                addCertificates(cf, chain, chainFile);
            }
        } catch (CertificateException | IOException e) {
            log.warn(sm.getString("quicheEndpoint.certParseError",
                    certificate.getCertificateFile()), e);
            return null;
        }
        if (chain.isEmpty()) {
            return null;
        }
        return chain.toArray(new X509Certificate[0]);
    }


    private void addCertificates(java.security.cert.CertificateFactory cf,
            List<X509Certificate> chain, String path) throws IOException, CertificateException {
        File f = new File(path);
        if (!f.isFile()) {
            return;
        }
        try (InputStream in = new FileInputStream(f)) {
            Collection<? extends java.security.cert.Certificate> certs =
                    cf.generateCertificates(in);
            for (java.security.cert.Certificate c : certs) {
                if (c instanceof X509Certificate) {
                    chain.add((X509Certificate) c);
                }
            }
        }
    }


    private static String quicheErrorName(int rc) {
        return switch (rc) {
            case QuicheBindings.QUICHE_ERR_BUFFER_TOO_SHORT -> "BUFFER_TOO_SHORT";
            case QuicheBindings.QUICHE_ERR_UNKNOWN_VERSION -> "UNKNOWN_VERSION";
            case QuicheBindings.QUICHE_ERR_INVALID_FRAME -> "INVALID_FRAME";
            case QuicheBindings.QUICHE_ERR_INVALID_PACKET -> "INVALID_PACKET";
            case QuicheBindings.QUICHE_ERR_INVALID_STATE -> "INVALID_STATE";
            case QuicheBindings.QUICHE_ERR_INVALID_STREAM_STATE -> "INVALID_STREAM_STATE";
            case QuicheBindings.QUICHE_ERR_INVALID_TRANSPORT_PARAM -> "INVALID_TRANSPORT_PARAM";
            case QuicheBindings.QUICHE_ERR_CRYPTO_FAIL -> "CRYPTO_FAIL";
            case QuicheBindings.QUICHE_ERR_TLS_FAIL -> "TLS_FAIL";
            case QuicheBindings.QUICHE_ERR_FLOW_CONTROL -> "FLOW_CONTROL";
            case QuicheBindings.QUICHE_ERR_STREAM_LIMIT -> "STREAM_LIMIT";
            case QuicheBindings.QUICHE_ERR_FINAL_SIZE -> "FINAL_SIZE";
            case QuicheBindings.QUICHE_ERR_CONGESTION_CONTROL -> "CONGESTION_CONTROL";
            case QuicheBindings.QUICHE_ERR_STREAM_STOPPED -> "STREAM_STOPPED";
            case QuicheBindings.QUICHE_ERR_STREAM_RESET -> "STREAM_RESET";
            case QuicheBindings.QUICHE_ERR_ID_LIMIT -> "ID_LIMIT";
            case QuicheBindings.QUICHE_ERR_OUT_OF_IDENTIFIERS -> "OUT_OF_IDENTIFIERS";
            case QuicheBindings.QUICHE_ERR_KEY_UPDATE -> "KEY_UPDATE";
            case QuicheBindings.QUICHE_ERR_CRYPTO_BUFFER_EXCEEDED -> "CRYPTO_BUFFER_EXCEEDED";
            default -> "ERROR(" + rc + ")";
        };
    }
}

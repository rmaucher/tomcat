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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigPreSharedKey;
import org.apache.tomcat.util.net.openssl.OpenSSLPreSharedKeySelector;
import org.apache.tomcat.util.net.openssl.panama.CertificateLoader;
import org.apache.tomcat.util.net.openssl.panama.CertificateLoader.CertificateEntry;
import org.apache.tomcat.util.res.StringManager;

/**
 * Structurally immutable snapshot of all certificates and pre-shared keys
 * configured on an endpoint, keyed by lower case host name, plus the default
 * host's material. The arena owns the DER staging allocations of the snapshot
 * and is closed when the snapshot is discarded on reload or shutdown; the
 * OpenSSL-heap certificate objects are not arena-owned and are released
 * only by {@link #free()}. The collection structure is immutable, but the
 * {@link CertificateEntry#chain} array is a mutable Java-side view (see its
 * documentation).
 * <p>
 * The snapshot is built once by {@link #buildCertConfig(SSLHostConfig,
 * SSLHostConfig[])} on top of {@link CertificateLoader#loadCertEntry} and is
 * released with {@link #free()} when discarded (on certificate reload or
 * endpoint shutdown). The endpoint's SNI callback applies the certificates of
 * the host matching the negotiated server name to each incoming connection
 * from the current snapshot.
 * <p>
 * A host that configures both certificates and pre-shared keys is rejected if
 * none of its certificates can be loaded, so its authentication mode cannot
 * silently change to pre-shared-key-only. Client certificate verification,
 * OCSP stapling and CRL/revocation data are not part of this snapshot; see
 * {@link QuicCertificateManager} for the supported TLS surface.
 */
public class QuicCertConfig {

    private static final Log log = LogFactory.getLog(QuicCertConfig.class);
    private static final StringManager sm =
            StringManager.getManager(QuicCertConfig.class);

    /**
     * Lower case host name of the default host.
     */
    public final String defaultHostName;

    /**
     * Certificates of the default host. Used when no SNI is sent, when
     * the SNI matches no configured host and as the fallback for the
     * default host itself. Empty for a pre-shared-key-only default host.
     */
    public final List<CertificateEntry> defaultCerts;

    /**
     * All hosts (including the default one) keyed by lower case host
     * name. Hosts that are pre-shared-key-only map to an empty list.
     */
    public final Map<String, List<CertificateEntry>> certsByHost;

    /**
     * Pre-shared key selectors of the hosts that have pre-shared keys
     * configured, keyed by lower case host name.
     */
    public final Map<String, OpenSSLPreSharedKeySelector> pskByHost;

    /**
     * Selector for the default host's pre-shared keys, or {@code null} if
     * the default host has none. Used when no SNI is sent, when the SNI
     * matches no configured host and as the fallback for the default host
     * itself.
     */
    public final OpenSSLPreSharedKeySelector defaultPskSelector;

    /**
     * Whether the endpoint has pre-shared keys configured and no host
     * offers a certificate.
     */
    public final boolean pskOnly;

    /**
     * TLS 1.3 cipher suites to apply to the native SSL_CTX. Kept in the
     * snapshot so a certificate reload can re-apply the configured suites.
     */
    public final String cipherSuites;

    /**
     * Arena owning the DER staging allocations of this snapshot. The native
     * X.509 and private-key objects are allocated on the OpenSSL heap and are
     * released by {@link #free()}, not by closing this arena.
     */
    public final Arena arena;

    /**
     * Identity set of entries whose native material has already been
     * released. {@link CertificateEntry} does not override {@code equals()},
     * so a HashSet de-duplicates by identity (an entry object is shared
     * between {@link #defaultCerts} and the {@link #certsByHost} values). It
     * also makes {@link #free()} idempotent if an entry free throws.
     */
    private final Set<CertificateEntry> freedEntries = new HashSet<>();


    /**
     * Creates an immutable certificate snapshot.
     *
     * @param defaultHostName       Lower case host name of the default host
     * @param defaultCerts          Certificates of the default host
     * @param certsByHost           All hosts (including the default one)
     *                              keyed by lower case host name
     * @param pskByHost             PSK selectors of the hosts that have
     *                              pre-shared keys configured, keyed by
     *                              lower case host name
     * @param defaultPskSelector    Selector for the default host's
     *                              pre-shared keys, or {@code null} if the
     *                              default host has none
     * @param pskOnly               Whether the endpoint has pre-shared keys
     *                              configured and no host offers a
     *                              certificate
     * @param cipherSuites          TLS 1.3 cipher suites for the native context
     * @param arena                 Arena owning the native objects of this
     *                              snapshot
     */
    public QuicCertConfig(String defaultHostName, List<CertificateEntry> defaultCerts,
            Map<String, List<CertificateEntry>> certsByHost,
            Map<String, OpenSSLPreSharedKeySelector> pskByHost,
            OpenSSLPreSharedKeySelector defaultPskSelector, boolean pskOnly,
            String cipherSuites, Arena arena) {
        // The snapshot is handed to the native SNI/PSK callbacks and read
        // while a later reload swaps in a new instance; copy and wrap the
        // collections so the documented immutability cannot be violated by a
        // caller and the input map is not mutated.
        this.defaultHostName = defaultHostName;
        Map<String, List<CertificateEntry>> certsCopy = new HashMap<>();
        for (Map.Entry<String, List<CertificateEntry>> host : certsByHost.entrySet()) {
            certsCopy.put(host.getKey(), Collections.unmodifiableList(
                    new ArrayList<>(host.getValue())));
        }
        this.defaultCerts = Collections.unmodifiableList(
                new ArrayList<>(defaultCerts));
        this.certsByHost = Collections.unmodifiableMap(certsCopy);
        this.pskByHost = Collections.unmodifiableMap(new HashMap<>(pskByHost));
        this.defaultPskSelector = defaultPskSelector;
        this.pskOnly = pskOnly;
        this.cipherSuites = cipherSuites;
        this.arena = arena;
    }


    // ------------------------------------- Configuration build

    /**
     * Loads all configured certificates and pre-shared keys into a new
     * {@link QuicCertConfig}.
     * <p>
     * Individual certificate failures are logged and skipped. A host without
     * certificates is accepted when it is pre-shared-key-only. A host that
     * configures both certificates and pre-shared keys but whose certificates
     * all fail to load is rejected (the build fails), because serving it would
     * silently change its authentication mode to pre-shared-key-only. A host
     * that configures neither a loadable certificate nor pre-shared keys also
     * rejects the whole build. The method returns {@code null} (after logging
     * the specific error) when the build cannot produce a usable snapshot;
     * {@link #buildCertConfigOrThrow(SSLHostConfig, SSLHostConfig[])} is the
     * variant that propagates the specific failure instead.
     *
     * @param defaultHostConfig The configuration of the default host, whose
     *                          certificates and pre-shared keys are used when
     *                          no SNI match is found
     * @param hostConfigs       The configurations of all hosts (including
     *                          the default one) to load material for
     *
     * @return the new configuration, or {@code null} if the snapshot cannot
     *         be built
     */
    public static QuicCertConfig buildCertConfig(SSLHostConfig defaultHostConfig,
            SSLHostConfig[] hostConfigs) {
        return buildCertConfigInternal(defaultHostConfig, hostConfigs, false);
    }


    /**
     * Builds the certificate snapshot like {@link #buildCertConfig(SSLHostConfig,
     * SSLHostConfig[])} but propagates configuration failures as an
     * {@link IllegalStateException} containing the specific reason instead of
     * returning {@code null}. Used by the OpenSSL endpoint so a bind/reload
     * error names the real failure (for example unsupported required client
     * authentication) instead of a generic "no certificate" message.
     *
     * @param defaultHostConfig The configuration of the default host
     * @param hostConfigs       The configurations of all hosts
     *
     * @return the new configuration
     *
     * @throws IllegalStateException If the snapshot cannot be built
     */
    static QuicCertConfig buildCertConfigOrThrow(SSLHostConfig defaultHostConfig,
            SSLHostConfig[] hostConfigs) {
        return buildCertConfigInternal(defaultHostConfig, hostConfigs, true);
    }


    private static QuicCertConfig buildCertConfigInternal(SSLHostConfig defaultHostConfig,
            SSLHostConfig[] hostConfigs, boolean throwOnFailure) {
        Arena arena = Arena.ofShared();
        // Every entry successfully loaded before a failure leaves this
        // method must be released on the failure paths: the native X509 and
        // EVP_PKEY objects live on the OpenSSL heap, so closing the arena
        // alone does not free them.
        List<CertificateEntry> loaded = new ArrayList<>();
        try {
            String defaultHostName = defaultHostConfig.getHostName().toLowerCase(Locale.ENGLISH);

            Map<String, List<CertificateEntry>> certsByHost = new HashMap<>();
            Map<String, OpenSSLPreSharedKeySelector> pskByHost = new HashMap<>();
            for (SSLHostConfig hostConfig : hostConfigs) {
                String hostName = hostConfig.getHostName().toLowerCase(Locale.ENGLISH);
                if (hostConfig != defaultHostConfig &&
                        !hostConfig.getCipherSuites().equals(
                                defaultHostConfig.getCipherSuites())) {
                    log.warn(sm.getString("quicEndpoint.perHostCipherSuitesUnsupported",
                            hostConfig.getHostName()));
                }
                String groups = hostConfig.getGroups();
                if (groups != null && !groups.trim().isEmpty()) {
                    // The native context never calls SSL_CTX_set1_groups_list(),
                    // so a key-exchange group restriction would otherwise be
                    // silently replaced by OpenSSL's default group list.
                    log.warn(sm.getString("quicEndpoint.groupsUnsupported",
                            hostConfig.getHostName(), groups));
                }
                Set<String> protocols = hostConfig.getProtocols();
                if (protocols != null && !protocols.isEmpty() &&
                        !protocols.contains("TLSv1.3")) {
                    // QUIC mandates TLS 1.3 (RFC 9001); a protocol set that
                    // excludes it cannot be honoured by this transport.
                    log.warn(sm.getString("quicEndpoint.protocolsUnsupported",
                            hostConfig.getHostName(), protocols.toString()));
                }
                String ciphers = hostConfig.getCiphers();
                if (ciphers != null && !ciphers.trim().isEmpty() &&
                        !SSLHostConfig.DEFAULT_TLS_CIPHERS_12.equals(ciphers)) {
                    // TLS 1.3 selects cipher suites through cipherSuites, not
                    // the TLS 1.2 ciphers list, and the QUIC context uses only
                    // TLS 1.3. getCiphers() returns the default TLS 1.2 list
                    // when nothing was configured; warning about that default
                    // would incorrectly tell every operator they configured a
                    // TLS 1.2 setting.
                    log.warn(sm.getString("quicEndpoint.tls12CiphersUnsupported",
                            hostConfig.getHostName(), ciphers));
                }
                if (hostConfig.getOcspEnabled() ||
                        hostConfig.getRevocationEnabled() ||
                        hostConfig.getCertificateRevocationListFile() != null) {
                    // The OpenSSL QUIC transport does not load OCSP responses
                    // or CRLs, so these settings would otherwise be silently
                    // ignored by an operator expecting revocation checking.
                    log.warn(sm.getString("quicEndpoint.ocspCrlUnsupported",
                            hostConfig.getHostName()));
                }
                SSLHostConfig.CertificateVerification verification =
                        hostConfig.getCertificateVerification();
                if (verification != SSLHostConfig.CertificateVerification.NONE) {
                    // This transport installs no client-certificate verify
                    // hook (no SSL_set_verify/trust-store wiring): make the
                    // ignored setting visible rather than silently dropping
                    // it, matching the quiche transport's warning. A required
                    // verification is a security setting that cannot be
                    // honoured, so fail the build instead of serving the host
                    // without client authentication.
                    log.warn(sm.getString("quicEndpoint.clientAuthUnsupported",
                            hostConfig.getHostName(), verification.name()));
                    if (verification == SSLHostConfig.CertificateVerification.REQUIRED) {
                        throw new IllegalStateException(sm.getString(
                                "quicEndpoint.clientAuthRequiredUnsupported",
                                hostConfig.getHostName(), verification.name()));
                    }
                }
                List<CertificateEntry> entries = new ArrayList<>();
                for (SSLHostConfigCertificate certificate : hostConfig.getCertificates()) {
                    CertificateEntry entry = CertificateLoader.loadCertEntry(certificate, arena);
                    if (entry != null) {
                        entries.add(entry);
                        loaded.add(entry);
                        if (log.isInfoEnabled()) {
                            log.info(sm.getString("certificateLoader.certificateLoaded",
                                    hostConfig.getHostName(),
                                    certificateFileForLog(certificate), entry.chain.length));
                        }
                    }
                }

                OpenSSLPreSharedKeySelector pskSelector = null;
                Set<SSLHostConfigPreSharedKey> psks = hostConfig.getPreSharedKeys();
                if (!psks.isEmpty()) {
                    // Duplicate identities within a host are a configuration
                    // error: the selector rejects them and the build fails.
                    pskSelector = new OpenSSLPreSharedKeySelector(psks);
                    pskByHost.put(hostName, pskSelector);
                }

                List<CertificateEntry> displaced;
                if (entries.isEmpty()) {
                    if (pskSelector != null && !hostConfig.isPreSharedKeyOnly()) {
                        // The host is configured with certificates and
                        // pre-shared keys, but none of its certificates could
                        // be loaded. Keeping the pre-shared key selector would
                        // silently switch the host from certificate
                        // authentication to pre-shared-key-only authentication,
                        // although the operator did not configure a
                        // pre-shared-key-only host. Fail the build (and
                        // therefore the bind or keep the previous reload
                        // snapshot) instead of accepting that downgrade.
                        return failBuild(sm.getString(
                                "certificateLoader.mixedAuthCertificateLoadFailed",
                                hostConfig.getHostName()), throwOnFailure, loaded,
                                arena);
                    } else if (pskSelector != null) {
                        // Host intentionally has no certificate: connections
                        // are authenticated with its pre-shared keys. Map it
                        // to an empty list so the SNI callback applies no
                        // certificate instead of falling back to the default
                        // host's.
                        displaced = certsByHost.put(hostName, List.of());
                        if (log.isInfoEnabled()) {
                            log.info(sm.getString("certificateLoader.pskOnlyHost",
                                    hostConfig.getHostName()));
                        }
                    } else {
                        // The host is neither pre-shared-key-only nor has a
                        // loadable certificate. Accepting it would make the
                        // endpoint start successfully but every handshake for
                        // this SNI fail later with no certificate to apply.
                        // Reject the whole build instead.
                        return failBuild(sm.getString(
                                "certificateLoader.certificateLoadFailed",
                                hostConfig.getHostName(),
                                sm.getString("certificateLoader.noCertificate")),
                                throwOnFailure, loaded, arena);
                    }
                } else {
                    displaced = certsByHost.put(hostName, entries);
                }
                if (displaced != null && !displaced.isEmpty()) {
                    // Two configurations share one lower-cased host name (the
                    // endpoint's host map is keyed case-sensitively): the
                    // later one replaces the earlier, as everywhere else. The
                    // displaced entries are unreachable from the snapshot
                    // afterwards, so release their native material now and
                    // drop them from the failure-path list to keep a later
                    // failure from freeing them a second time.
                    for (CertificateEntry entry : displaced) {
                        loaded.remove(entry);
                        try {
                            CertificateLoader.freeCertEntry(entry);
                        } catch (Throwable t) {
                            // Match freeEntry()/freeLoadedEntries(): a failure
                            // releasing one displaced entry must not abort the
                            // loop and leave the remaining displaced entries
                            // unreleased. The failed entry has already been
                            // removed from the failure-path list (retrying a
                            // partially freed certificate is unsafe), so log it
                            // rather than leaking silently.
                            ExceptionUtils.handleThrowable(t);
                            log.warn(sm.getString("certificateLoader.freeError"), t);
                        }
                    }
                }
            }

            List<CertificateEntry> defaultCerts = certsByHost.get(defaultHostName);
            if (defaultCerts == null) {
                defaultCerts = List.of();
            }
            OpenSSLPreSharedKeySelector defaultPskSelector = pskByHost.get(defaultHostName);
            if (defaultCerts.isEmpty() && defaultPskSelector == null) {
                return failBuild(sm.getString(
                        "certificateLoader.certificateLoadFailed",
                        defaultHostConfig.getHostName(),
                        sm.getString("certificateLoader.noCertificateOrPsk")),
                        throwOnFailure, loaded, arena);
            }
            boolean pskOnly = !pskByHost.isEmpty() && !certsByHost.values().stream()
                    .anyMatch(entries -> !entries.isEmpty());
            return new QuicCertConfig(defaultHostName, defaultCerts, certsByHost, pskByHost,
                    defaultPskSelector, pskOnly,
                    defaultHostConfig.getCipherSuites(), arena);
        } catch (IllegalStateException e) {
            freeLoadedEntries(loaded);
            CertificateLoader.closeQuietly(arena);
            if (throwOnFailure) {
                throw e;
            }
            log.error(sm.getString("certificateLoader.certificateBuildError"), e);
            return null;
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            freeLoadedEntries(loaded);
            CertificateLoader.closeQuietly(arena);
            if (throwOnFailure) {
                throw new IllegalStateException(
                        sm.getString("certificateLoader.certificateBuildError"), t);
            }
            log.error(sm.getString("certificateLoader.certificateBuildError"), t);
            return null;
        }
    }


    /**
     * Releases the partially built material and either fails the build with a
     * specific message or logs it and returns {@code null}, depending on
     * {@code throwOnFailure}.
     *
     * @param message        The specific failure message
     * @param throwOnFailure Whether to throw or return {@code null}
     * @param loaded         Entries loaded before the failure
     * @param arena          The snapshot arena
     *
     * @return {@code null} when not throwing
     */
    private static QuicCertConfig failBuild(String message, boolean throwOnFailure,
            List<CertificateEntry> loaded, Arena arena) {
        log.error(message);
        if (throwOnFailure) {
            throw new IllegalStateException(message);
        }
        freeLoadedEntries(loaded);
        CertificateLoader.closeQuietly(arena);
        return null;
    }


    /**
     * Releases the native objects of this snapshot. The arena is not closed
     * here: the caller owns it (see {@link #arena}).
     * <p>
     * An entry object is shared between {@link #defaultCerts} and the
     * {@link #certsByHost} values, so entries are de-duplicated to avoid a
     * double free.
     */
    public synchronized void free() {
        for (CertificateEntry entry : defaultCerts) {
            freeEntry(entry);
        }
        for (List<CertificateEntry> entries : certsByHost.values()) {
            for (CertificateEntry entry : entries) {
                freeEntry(entry);
            }
        }
    }


    /**
     * Frees one entry unless it has already been released. The entry is
     * marked before the native call so a throw cannot lead to a later second
     * free of the same native object; a failure is logged and the remaining
     * entries are still released.
     *
     * @param entry The entry to release
     */
    private void freeEntry(CertificateEntry entry) {
        if (!freedEntries.add(entry)) {
            return;
        }
        try {
            CertificateLoader.freeCertEntry(entry);
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            log.warn(sm.getString("certificateLoader.freeError"), t);
        }
    }


    /**
     * Releases the native objects of the given entries (each entry appears
     * exactly once in the list built by {@link #buildCertConfig}, so no
     * de-duplication is needed). A failure frees the remaining entries rather
     * than aborting the cleanup loop.
     *
     * @param entries The entries to release
     */
    private static void freeLoadedEntries(List<CertificateEntry> entries) {
        for (CertificateEntry entry : entries) {
            try {
                CertificateLoader.freeCertEntry(entry);
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("certificateLoader.freeError"), t);
            }
        }
    }


    /**
     * Returns a short, log-safe description of where a certificate is
     * loaded from.
     *
     * @param certificate The certificate configuration to describe
     *
     * @return The certificate file, the key store file, or a marker string
     *         when the certificate comes from an in-memory key manager
     */
    private static String certificateFileForLog(SSLHostConfigCertificate certificate) {
        String file = certificate.getCertificateFile();
        if (file == null) {
            file = certificate.getCertificateKeystoreFile();
        }
        if (file == null) {
            return sm.getString("certificateLoader.inMemoryKeyManager");
        }
        return file;
    }
}

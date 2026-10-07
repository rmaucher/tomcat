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
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigPreSharedKey;
import org.apache.tomcat.util.net.openssl.OpenSSLPreSharedKeySelector;
import org.apache.tomcat.util.net.openssl.panama.CertificateLoader;
import org.apache.tomcat.util.net.openssl.panama.CertificateLoader.CertificateEntry;
import org.apache.tomcat.util.res.StringManager;

/**
 * Immutable snapshot of all certificates and pre-shared keys configured
 * on an endpoint, keyed by lower case host name, plus the default host's
 * material. The arena owns the DER staging allocations of the snapshot and
 * is closed when the snapshot is discarded on reload or shutdown; the
 * OpenSSL-heap certificate objects are not arena-owned and are released
 * only by {@link #free()}.
 * <p>
 * The snapshot is built once by {@link #buildCertConfig(SSLHostConfig,
 * SSLHostConfig[])} on top of {@link CertificateLoader#loadCertEntry} and is
 * released with {@link #free()} when discarded (on certificate reload or
 * endpoint shutdown). The endpoint's SNI callback applies the certificates of
 * the host matching the negotiated server name to each incoming connection
 * from the current snapshot.
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
     * Arena holding every native object in this snapshot.
     */
    public final Arena arena;


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
     * @param arena                 Arena owning the native objects of this
     *                              snapshot
     */
    public QuicCertConfig(String defaultHostName, List<CertificateEntry> defaultCerts,
            Map<String, List<CertificateEntry>> certsByHost,
            Map<String, OpenSSLPreSharedKeySelector> pskByHost,
            OpenSSLPreSharedKeySelector defaultPskSelector, boolean pskOnly, Arena arena) {
        // The snapshot is handed to the native SNI/PSK callbacks and read
        // while a later reload swaps in a new instance; wrap the collections
        // so the documented immutability cannot be violated by a caller.
        this.defaultHostName = defaultHostName;
        for (Map.Entry<String, List<CertificateEntry>> host : certsByHost.entrySet()) {
            host.setValue(Collections.unmodifiableList(host.getValue()));
        }
        this.defaultCerts = Collections.unmodifiableList(defaultCerts);
        this.certsByHost = Collections.unmodifiableMap(certsByHost);
        this.pskByHost = Collections.unmodifiableMap(pskByHost);
        this.defaultPskSelector = defaultPskSelector;
        this.pskOnly = pskOnly;
        this.arena = arena;
    }


    // ------------------------------------- Configuration build

    /**
     * Loads all configured certificates and pre-shared keys into a new
     * {@link QuicCertConfig}.
     * <p>
     * Individual certificate failures are logged and skipped. A host without
     * certificates is accepted when it is pre-shared-key-only. The method
     * returns {@code null} (and logs the error) when the default host has
     * neither a loadable certificate nor pre-shared keys.
     *
     * @param defaultHostConfig The configuration of the default host, whose
     *                          certificates and pre-shared keys are used when
     *                          no SNI match is found
     * @param hostConfigs       The configurations of all hosts (including
     *                          the default one) to load material for
     *
     * @return the new configuration, or {@code null} if the default host has
     *         no loadable certificate and no pre-shared keys
     */
    public static QuicCertConfig buildCertConfig(SSLHostConfig defaultHostConfig,
            SSLHostConfig[] hostConfigs) {
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
                if (hostConfig.getCertificateVerification() !=
                        SSLHostConfig.CertificateVerification.NONE) {
                    // This transport installs no client-certificate verify
                    // hook (no SSL_set_verify/trust-store wiring): make the
                    // ignored setting visible rather than silently dropping
                    // it, matching the quiche transport's warning.
                    log.warn(sm.getString("quicEndpoint.clientAuthUnsupported",
                            hostConfig.getHostName(),
                            hostConfig.getCertificateVerification().name()));
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
                    if (pskSelector != null && hostConfig.isPreSharedKeyOnly()) {
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
                        // Nothing to map for this host: a previously mapped
                        // configuration for the same (lower-cased) name stays
                        // in effect.
                        displaced = null;
                        log.warn(sm.getString("certificateLoader.certificateLoadFailed",
                                hostConfig.getHostName(), sm.getString("certificateLoader.noCertificate")));
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
                        CertificateLoader.freeCertEntry(entry);
                    }
                }
            }

            List<CertificateEntry> defaultCerts = certsByHost.get(defaultHostName);
            if (defaultCerts == null) {
                defaultCerts = List.of();
            }
            OpenSSLPreSharedKeySelector defaultPskSelector = pskByHost.get(defaultHostName);
            if (defaultCerts.isEmpty() && defaultPskSelector == null) {
                log.error(sm.getString("certificateLoader.certificateLoadFailed",
                        defaultHostConfig.getHostName(),
                        sm.getString("certificateLoader.noCertificateOrPsk")));
                freeLoadedEntries(loaded);
                CertificateLoader.closeQuietly(arena);
                return null;
            }
            boolean pskOnly = !pskByHost.isEmpty() && !certsByHost.values().stream()
                    .anyMatch(entries -> !entries.isEmpty());
            return new QuicCertConfig(defaultHostName, defaultCerts, certsByHost, pskByHost,
                    defaultPskSelector, pskOnly, arena);
        } catch (Throwable t) {
            freeLoadedEntries(loaded);
            CertificateLoader.closeQuietly(arena);
            log.error(sm.getString("certificateLoader.certificateBuildError"), t);
            return null;
        }
    }


    /**
     * Releases the native objects of this snapshot. The arena is not closed
     * here: the caller owns it (see {@link #arena}).
     * <p>
     * An entry object is shared between {@link #defaultCerts} and the
     * {@link #certsByHost} values, so entries are de-duplicated to avoid a
     * double free.
     */
    public void free() {
        // CertificateEntry does not override equals(), so a HashSet de-duplicates
        // by identity (the same entry object is shared between defaultCerts
        // and certsByHost).
        Set<CertificateEntry> seen = new HashSet<>();
        for (CertificateEntry entry : defaultCerts) {
            if (seen.add(entry)) {
                CertificateLoader.freeCertEntry(entry);
            }
        }
        for (List<CertificateEntry> entries : certsByHost.values()) {
            for (CertificateEntry entry : entries) {
                if (seen.add(entry)) {
                    CertificateLoader.freeCertEntry(entry);
                }
            }
        }
    }


    /**
     * Releases the native objects of the given entries (each entry appears
     * exactly once in the list built by {@link #buildCertConfig}, so no
     * de-duplication is needed).
     *
     * @param entries The entries to release
     */
    private static void freeLoadedEntries(List<CertificateEntry> entries) {
        for (CertificateEntry entry : entries) {
            CertificateLoader.freeCertEntry(entry);
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

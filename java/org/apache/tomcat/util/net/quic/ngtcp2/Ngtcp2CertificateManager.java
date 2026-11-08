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
package org.apache.tomcat.util.net.quic.ngtcp2;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.security.cert.X509Certificate;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.openssl.panama.CertificateLoader;
import org.apache.tomcat.util.net.quic.QuicProtocol;
import org.apache.tomcat.util.net.quic.openssl.QuicCertConfig;
import org.apache.tomcat.util.net.quic.openssl.QuicCertificateManager;
import org.apache.tomcat.util.openssl.openssl_h;

/**
 * TLS configuration adapter for the ngtcp2 transport.
 * <p>
 * ngtcp2 uses a normal OpenSSL TLS context ({@code TLS_server_method}) through
 * {@code ngtcp2_crypto_ossl}. The common certificate loading, ALPN and SNI
 * machinery lives in {@link QuicCertificateManager}; this adapter gives it the
 * ngtcp2-specific SSL method and exposes the small configuration-generation
 * API the ported endpoint control flow expects.
 */
final class Ngtcp2CertificateManager {

    private static final org.apache.juli.logging.Log log =
            org.apache.juli.logging.LogFactory.getLog(Ngtcp2CertificateManager.class);
    private static final StringManagerHolder SM = new StringManagerHolder();

    private final QuicCertificateManager delegate;
    private final Supplier<QuicProtocol> protocolSupplier;
    private final Function<String, SSLHostConfig> hostResolver;

    Ngtcp2CertificateManager(Supplier<QuicProtocol> protocolSupplier,
            Function<String, SSLHostConfig> hostResolver) {
        this.protocolSupplier = protocolSupplier;
        this.hostResolver = hostResolver;
        this.delegate = new QuicCertificateManager(
                () -> "ngtcp2",
                protocolSupplier,
                hostResolver,
                openssl_h.TLS_server_method());
    }

    void initialize(SSLHostConfig defaultHostConfig, SSLHostConfig[] hostConfigs)
            throws IOException {
        QuicCertConfig config = build(defaultHostConfig, hostConfigs);
        if (config == null) {
            throw new IOException(SM.get("ngtcp2Endpoint.certificateLoadFailed",
                    defaultHostConfig.getHostName(), "no loadable certificate"));
        }
        try {
            delegate.initialize(config);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    MemorySegment getConfig() {
        return delegate.getSslCtx();
    }

    X509Certificate[] parseChain(SSLHostConfigCertificate certificate) {
        return CertificateLoader.getCertificateChain(certificate);
    }

    Config prepareConfig(SSLHostConfig defaultHostConfig,
            SSLHostConfig[] hostConfigs, String reason) throws IOException {
        QuicCertConfig config = build(defaultHostConfig, hostConfigs);
        if (config == null) {
            throw new IOException(SM.get("ngtcp2Endpoint.certificateLoadFailed",
                    defaultHostConfig.getHostName(), "no loadable certificate"));
        }
        return new Config(config, reason);
    }

    void installConfig(Config config) {
        if (config != null) {
            delegate.swapConfig(config.config, config.reason);
        }
    }

    void discardPrepared(Config config) {
        if (config != null) {
            config.config.free();
            CertificateLoader.closeQuietly(config.config.arena);
        }
    }

    void release() {
        delegate.release();
    }

    private QuicCertConfig build(SSLHostConfig defaultHostConfig,
            SSLHostConfig[] hostConfigs) {
        try {
            return QuicCertConfig.buildCertConfig(defaultHostConfig, hostConfigs);
        } catch (Throwable t) {
            // Never swallow the cause: a failed reload otherwise silently
            // keeps serving the old certificate with no diagnostic at all.
            org.apache.tomcat.util.ExceptionUtils.handleThrowable(t);
            log.error(SM.get("ngtcp2Endpoint.certificateReloadFailed",
                    "certificate configuration build failed"), t);
            return null;
        }
    }

    static final class Config {
        private final QuicCertConfig config;
        private final String reason;

        Config(QuicCertConfig config, String reason) {
            this.config = config;
            this.reason = reason;
        }
    }

    /*
     * Keep the StringManager lookup out of the static fields to avoid an
     * initialization cycle through the endpoint class.
     */
    private static final class StringManagerHolder {
        private final org.apache.tomcat.util.res.StringManager manager =
                org.apache.tomcat.util.res.StringManager.getManager(Ngtcp2Endpoint.class);

        String get(String key, Object... args) {
            return manager.getString(key, args);
        }
    }
}

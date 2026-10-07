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
package org.apache.tomcat.util.net.quic;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;

import org.apache.tomcat.util.net.SSLContext;

/**
 * A minimal {@link SSLContext} implementation used by the QUIC endpoints
 * ({@code org.apache.tomcat.util.net.quic.openssl.QuicOpenSSLEndpoint} and
 * {@code org.apache.tomcat.util.net.quic.quiche.QuicheEndpoint}) to expose
 * the TLS information configured for a certificate to consumers that read it
 * through the certificate's SSLContext (the Manager application, the
 * certificate expiry checks and JMX).
 * <p>
 * The QUIC endpoints perform every handshake natively (OpenSSL or quiche),
 * so there is no real SSLContext behind it. This context therefore only reports the
 * configured certificate data: {@link #getCertificateChain(String)} returns
 * the chain the endpoint presents for the certificate and
 * {@link #getAcceptedIssuers()} returns an empty array since QUIC connections
 * do not request client certificates (no trust material is used). Any other
 * method (everything that would create engines or sockets, or that would
 * initialize native TLS state) throws
 * {@link UnsupportedOperationException}, mirroring how
 * {@link org.apache.tomcat.util.net.openssl.panama.OpenSSLContext} handles
 * operations its implementation does not
 * support.
 */
public class QuicSSLContext implements SSLContext {

    private static final X509Certificate[] NO_ACCEPTED_ISSUERS = new X509Certificate[0];

    private final X509Certificate[] certificateChain;

    /**
     * Creates a context that reports the given certificate chain.
     *
     * @param certificateChain The chain to report, or {@code null} if the
     *                         chain could not be read from the configured
     *                         certificate source
     */
    public QuicSSLContext(X509Certificate[] certificateChain) {
        if (certificateChain == null) {
            this.certificateChain = null;
        } else {
            this.certificateChain = certificateChain.clone();
        }
    }


    /**
     * {@inheritDoc}
     * <p>
     * The alias is never used to select the chain: this context reports the
     * one chain of the certificate it was created for and returns that same
     * chain for any alias. Which certificate is actually presented is decided
     * by the transport, not here: the OpenSSL transport selects among the
     * configured certificates by SNI and key type at handshake time, whereas
     * the quiche transport serves a single default certificate and performs no
     * SNI selection.
     *
     * @param alias The key alias (ignored)
     *
     * @return The configured certificate chain, or {@code null} if the chain
     *         could not be read from the configured certificate source
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (certificateChain == null) {
            return null;
        }
        return certificateChain.clone();
    }


    /**
     * {@inheritDoc}
     * <p>
     * QUIC connections do not request a client certificate, so no trust
     * material is used and there are no accepted issuers.
     *
     * @return An empty array
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return NO_ACCEPTED_ISSUERS;
    }


    /**
     * Not supported. Handshakes (and therefore the initialization of TLS
     * state) are performed natively by the QUIC endpoint, so this method
     * always throws {@link UnsupportedOperationException} (the
     * declared {@link KeyManagementException} is only the interface's
     * signature and is never thrown).
     *
     * @param kms Ignored
     * @param tms Ignored
     * @param sr  Ignored
     */
    @Override
    public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom sr)
            throws KeyManagementException {
        throw new UnsupportedOperationException();
    }


    /**
     * No-op. This context holds no native resources.
     */
    @Override
    public void destroy() {
        // NO-OP
    }


    /**
     * Not supported. Handshakes are performed natively by the QUIC endpoint.
     *
     * @return never returns
     */
    @Override
    public SSLSessionContext getServerSessionContext() {
        throw new UnsupportedOperationException();
    }


    /**
     * Not supported. Handshakes are performed natively by the QUIC endpoint.
     *
     * @return never returns
     */
    @Override
    public SSLEngine createSSLEngine() {
        throw new UnsupportedOperationException();
    }


    /**
     * Not supported. This endpoint does not serve TLS over sockets.
     *
     * @return never returns
     */
    @Override
    public SSLServerSocketFactory getServerSocketFactory() {
        throw new UnsupportedOperationException();
    }


    /**
     * Not supported. The TLS parameters in use are those of the endpoint's
     * native SSL_CTX, exposed via the SSL host configuration.
     *
     * @return never returns
     */
    @Override
    public SSLParameters getSupportedSSLParameters() {
        throw new UnsupportedOperationException();
    }
}

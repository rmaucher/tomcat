/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http3;

import java.io.File;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.net.SSLContext;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLUtilBase;

/**
 * Tests for the SSLContext the QUIC endpoint publishes on each
 * {@link SSLHostConfigCertificate} during {@code createSSLContext()}. The
 * endpoint performs its handshakes natively and has no real SSLContext, but
 * consumers that read certificate data through the certificate's SSLContext
 * (the Manager application, the certificate expiry checks) must see the
 * configured chain. The operations that would require a real context (engine
 * / socket creation, initialization) are unsupported.
 */
public class TestQuicSslContext extends Http3TestBase {

    private static final String CERT_DIR =
            "test/org/apache/coyote/http3/";

    private static final KeyManager[] NO_KEY_MANAGERS = new KeyManager[0];
    private static final TrustManager[] NO_TRUST_MANAGERS =
            new TrustManager[0];


    @Override
    public void setUp() throws Exception {
        super.setUp();
        Assume.assumeTrue("OpenSSL QUIC support not available",
                isQuicSupported());
    }


    /**
     * The keystore based default certificate must expose its chain through
     * the published context and report no accepted issuers (QUIC does not
     * request client certificates).
     */
    @Test
    public void testKeystoreChainExposed() throws Exception {
        Assume.assumeTrue("PKCS12 keystore not found: " + KEYSTORE,
                new File(KEYSTORE).isFile());

        Connector connector = startQuicServer(newHttp3Connector(
                findFreeUdpPort()));

        SSLHostConfigCertificate certificate = singleCertificate(connector);
        SSLContext sslContext = certificate.getSslContext();
        Assert.assertNotNull("The endpoint must publish an SSLContext",
                sslContext);

        X509Certificate[] chain = sslContext.getCertificateChain(
                SSLUtilBase.DEFAULT_KEY_ALIAS);
        Assert.assertNotNull("The chain must be exposed", chain);
        Assert.assertTrue("Chain must have at least the leaf",
                chain.length >= 1);
        Assert.assertTrue("Unexpected leaf subject: "
                        + chain[0].getSubjectX500Principal(),
                chain[0].getSubjectX500Principal().getName()
                        .startsWith("CN=localhost"));

        // The Manager application resolves the chain with the configured
        // alias or the default key alias; a context that reports the
        // configured chain for either (PEM certificates have no key store
        // alias at all) must behave the same way for both and must not
        // hand out its internal array.
        X509Certificate[] otherAlias = sslContext.getCertificateChain(
                "some-other-alias");
        Assert.assertArrayEquals(chain, otherAlias);
        Assert.assertNotSame("Callers must not share the internal array",
                chain, otherAlias);

        X509Certificate[] acceptedIssuers = sslContext.getAcceptedIssuers();
        Assert.assertNotNull("Accepted issuers must be reported (empty), "
                + "not unavailable", acceptedIssuers);
        Assert.assertEquals(0, acceptedIssuers.length);
    }


    /**
     * A PEM certificate with a separate chain file must expose the full
     * chain (leaf first, then the configured intermediates).
     */
    @Test
    public void testPemChainFileExposed() throws Exception {
        SSLHostConfig host = new SSLHostConfig();
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(host,
                        SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateFile(new File(CERT_DIR
                + "quic-leaf-cert.pem").getAbsolutePath());
        certificate.setCertificateKeyFile(new File(CERT_DIR
                + "quic-leaf-key.pem").getAbsolutePath());
        certificate.setCertificateChainFile(new File(CERT_DIR
                + "quic-leaf-chain.pem").getAbsolutePath());
        host.addCertificate(certificate);

        Connector connector = startQuicServer(newHttp3Connector(
                findFreeUdpPort(), host));

        SSLContext sslContext = singleCertificate(connector).getSslContext();
        Assert.assertNotNull(sslContext);

        X509Certificate[] chain = sslContext.getCertificateChain(
                SSLUtilBase.DEFAULT_KEY_ALIAS);
        Assert.assertNotNull("The chain must be exposed", chain);
        Assert.assertEquals("Leaf plus the CA from the chain file", 2,
                chain.length);
        Assert.assertEquals("CN=localhost",
                chain[0].getSubjectX500Principal().getName());
        Assert.assertNotEquals("The chain certificate must differ from the "
                        + "leaf",
                chain[0].getSubjectX500Principal(),
                chain[1].getSubjectX500Principal());
    }


    /**
     * Replacing an SSL host configuration must refresh the published chain
     * so the rotated certificate becomes visible (the context created here
     * is replaced, not treated as user provided).
     */
    @Test
    public void testReloadRefreshesChain() throws Exception {
        // Replacing a non-default (SNI) host configuration requires
        // multi-host support, which the quiche phase-1 transport lacks.
        Assume.assumeTrue(endpointSupportsSni());
        SSLHostConfig defaultHost = pemHost(null, "quic-default-cert.pem",
                "quic-default-key.pem");
        SSLHostConfig sniHost = pemHost("quic-sni.test",
                "quic-sni-ec-cert.pem", "quic-sni-ec-key.pem");

        Connector connector = startQuicServer(newHttp3Connector(
                findFreeUdpPort(), defaultHost, sniHost));

        SSLContext sslContext =
                singleCertificate(sniHost).getSslContext();
        Assert.assertNotNull(sslContext);
        Assert.assertEquals("CN=quic-sni", sslContext.getCertificateChain(
                SSLUtilBase.DEFAULT_KEY_ALIAS)[0]
                .getSubjectX500Principal().getName());

        SSLHostConfig replacement = pemHost("quic-sni.test",
                "quic-sni-ec-v2-cert.pem", "quic-sni-ec-v2-key.pem");
        connector.getProtocolHandler().addSslHostConfig(replacement, true);

        SSLContext replacementContext =
                singleCertificate(replacement).getSslContext();
        Assert.assertNotNull("The replaced host must publish an SSLContext",
                replacementContext);
        Assert.assertEquals("CN=quic-sni-v2", replacementContext
                .getCertificateChain(SSLUtilBase.DEFAULT_KEY_ALIAS)[0]
                .getSubjectX500Principal().getName());
    }


    /**
     * Operations that would require a real TLS context must fail clearly
     * rather than report misleading data.
     */
    @Test
    public void testUnsupportedOperations() throws Exception {
        Assume.assumeTrue("PKCS12 keystore not found: " + KEYSTORE,
                new File(KEYSTORE).isFile());

        Connector connector = startQuicServer(newHttp3Connector(
                findFreeUdpPort()));

        SSLContext sslContext = singleCertificate(connector).getSslContext();
        Assert.assertNotNull(sslContext);

        Assert.assertThrows(UnsupportedOperationException.class,
                () -> sslContext.createSSLEngine());
        Assert.assertThrows(UnsupportedOperationException.class,
                sslContext::getServerSessionContext);
        Assert.assertThrows(UnsupportedOperationException.class,
                sslContext::getSupportedSSLParameters);
        Assert.assertThrows(UnsupportedOperationException.class,
                sslContext::getServerSocketFactory);
        Assert.assertThrows(UnsupportedOperationException.class,
                () -> sslContext.init(NO_KEY_MANAGERS, NO_TRUST_MANAGERS,
                        new SecureRandom()));

        // Releasing the context is always safe (no native resources).
        sslContext.destroy();
    }


    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------


    /**
     * Starts the given connector on the test Tomcat instance and checks it
     * bound successfully.
     *
     * @param connector the connector to start
     *
     * @return the started connector
     *
     * @throws Exception if the server fails to start
     */
    private Connector startQuicServer(Connector connector) throws Exception {
        getTomcatInstance().setConnector(connector);
        getProgrammaticRootContext();
        getTomcatInstance().start();
        Assert.assertEquals("Connector must have started",
                LifecycleState.STARTED, connector.getState());
        return connector;
    }


    /**
     * Returns the single (RSC) certificate published for the default host of
     * the started connector.
     *
     * @param connector the started connector
     *
     * @return the default host's single certificate
     */
    private static SSLHostConfigCertificate singleCertificate(
            Connector connector) {
        SSLHostConfig[] configs =
                connector.getProtocolHandler().findSslHostConfigs();
        Assert.assertEquals(1, configs.length);
        return singleCertificate(configs[0]);
    }


    /**
     * Returns the single (RSC) certificate of the given host configuration.
     *
     * @param sslHostConfig the host configuration
     *
     * @return the host's single certificate
     */
    private static SSLHostConfigCertificate singleCertificate(
            SSLHostConfig sslHostConfig) {
        Assert.assertEquals(1, sslHostConfig.getCertificates().size());
        return sslHostConfig.getCertificates().iterator().next();
    }


    private static SSLHostConfig pemHost(String hostName, String certFile,
            String keyFile) {
        SSLHostConfig host = new SSLHostConfig();
        if (hostName != null) {
            host.setHostName(hostName);
        }
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(
                host, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateFile(new File(CERT_DIR
                + certFile).getAbsolutePath());
        certificate.setCertificateKeyFile(new File(CERT_DIR
                + keyFile).getAbsolutePath());
        host.addCertificate(certificate);
        return host;
    }
}

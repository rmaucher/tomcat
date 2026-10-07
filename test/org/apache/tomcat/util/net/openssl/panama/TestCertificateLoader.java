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
package org.apache.tomcat.util.net.openssl.panama;

import java.io.File;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;

/**
 * Unit tests for {@link CertificateLoader#getCertificateChain(
 * SSLHostConfigCertificate)}, the pure (non-native) certificate chain reader
 * used to publish the chain for JMX and the certificate expiry checks. These
 * run without an OpenSSL QUIC build and without starting a server.
 */
public class TestCertificateLoader {

    private static final String CERT_DIR =
            "test/org/apache/coyote/http3/";


    private static SSLHostConfigCertificate certificate(String certFile,
            String chainFile) {
        SSLHostConfig host = new SSLHostConfig();
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(
                host, SSLHostConfigCertificate.Type.UNDEFINED);
        if (certFile != null) {
            certificate.setCertificateFile(new File(CERT_DIR + certFile)
                    .getAbsolutePath());
        }
        if (chainFile != null) {
            certificate.setCertificateChainFile(new File(CERT_DIR + chainFile)
                    .getAbsolutePath());
        }
        return certificate;
    }


    /**
     * A PEM leaf with a separate chain file yields leaf first, then the CA
     * from the chain file.
     */
    @Test
    public void testPemChainFile() {
        X509Certificate[] chain = CertificateLoader.getCertificateChain(
                certificate("quic-leaf-cert.pem", "quic-leaf-chain.pem"));

        Assert.assertNotNull("The chain must be read", chain);
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
     * A PEM leaf with no chain file still reports at least the leaf, first.
     */
    @Test
    public void testPemLeafOnly() {
        X509Certificate[] chain = CertificateLoader.getCertificateChain(
                certificate("quic-leaf-cert.pem", null));

        Assert.assertNotNull("The leaf must be read", chain);
        Assert.assertTrue("At least the leaf", chain.length >= 1);
        Assert.assertEquals("Leaf must come first", "CN=localhost",
                chain[0].getSubjectX500Principal().getName());
    }


    /**
     * A configured but missing certificate file is reported as a null chain
     * rather than throwing.
     */
    @Test
    public void testMissingFileReturnsNull() {
        Assert.assertNull("A missing file must yield a null chain",
                CertificateLoader.getCertificateChain(
                        certificate("does-not-exist.pem", null)));
    }


    /**
     * A certificate with neither a file nor a key store yields a null chain.
     */
    @Test
    public void testNoSourceReturnsNull() {
        Assert.assertNull("No configured source must yield a null chain",
                CertificateLoader.getCertificateChain(
                        certificate(null, null)));
    }
}

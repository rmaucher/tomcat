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

import java.io.File;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigPreSharedKey;


/**
 * Tests for the certificate snapshot build, in particular the interaction of
 * certificate load failures with pre-shared keys.
 */
public class TestQuicCertConfig {

    private static final String PSK_IDENTITY = "quic-cert-config-test";
    private static final String PSK_KEY =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


    @Test
    public void testFailedCertificateWithPskRejectsConfiguration() {
        SSLHostConfig hostConfig = new SSLHostConfig();
        hostConfig.setHostName("localhost");
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(
                hostConfig, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateKeystoreFile(new File(
                "target/does-not-exist-quic-cert-config-test.p12")
                        .getAbsolutePath());
        certificate.setCertificateKeystorePassword("changeit");
        hostConfig.addCertificate(certificate);
        addPsk(hostConfig);

        // The host configures both a certificate and a PSK. Since the
        // certificate cannot be loaded, accepting the host would silently
        // change its authentication mode to pre-shared-key-only, so the build
        // must fail.
        Assert.assertNull(QuicCertConfig.buildCertConfig(hostConfig,
                new SSLHostConfig[] { hostConfig }));
    }


    @Test
    public void testPskOnlyHostIsAccepted() {
        SSLHostConfig hostConfig = new SSLHostConfig();
        hostConfig.setHostName("localhost");
        addPsk(hostConfig);

        QuicCertConfig config = QuicCertConfig.buildCertConfig(hostConfig,
                new SSLHostConfig[] { hostConfig });
        try {
            Assert.assertNotNull(config);
            Assert.assertTrue(config.pskOnly);
            Assert.assertEquals(0, config.defaultCerts.size());
            Assert.assertEquals(0, config.certsByHost.get("localhost").size());
            Assert.assertNotNull(config.defaultPskSelector);
        } finally {
            if (config != null) {
                config.free();
                config.arena.close();
            }
        }
    }


    private void addPsk(SSLHostConfig hostConfig) {
        SSLHostConfigPreSharedKey psk = new SSLHostConfigPreSharedKey(hostConfig);
        psk.setIdentity(PSK_IDENTITY);
        psk.setKey(PSK_KEY);
        psk.setDigest("SHA256");
        hostConfig.addPreSharedKey(psk);
    }
}

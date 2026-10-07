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

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.net.SSLHostConfig;

/**
 * Tests that a started HTTP/3 connector reports the connector-level TLS
 * information (enabled cipher suites) through its SSLHostConfigs for both
 * QUIC transports. The Manager application reads
 * {@link SSLHostConfig#getEnabledCiphers()} without a null check
 * (ManagerServlet#getConnectorCiphers), so a null there fails the
 * /manager/status page with a NullPointerException.
 */
public class TestQuicConnectorCiphers extends Http3TestBase {

    @Test
    public void testEnabledCiphersAreExposed() throws Exception {
        startHttp3Server();

        SSLHostConfig[] sslHostConfigs =
                connector.getProtocolHandler().findSslHostConfigs();
        Assert.assertEquals(1, sslHostConfigs.length);
        for (SSLHostConfig sslHostConfig : sslHostConfigs) {
            String[] ciphers = sslHostConfig.getEnabledCiphers();
            Assert.assertNotNull(
                    "A started SSL connector must report enabled ciphers " +
                            "through its SSLHostConfig (read unguarded by " +
                            "ManagerServlet.getConnectorCiphers)",
                    ciphers);
            Assert.assertTrue("Enabled cipher list must not be empty",
                    ciphers.length > 0);
            // QUIC mandates TLS 1.3 (RFC 9001): only TLS 1.3 suite names.
            for (String cipher : ciphers) {
                Assert.assertTrue("Unexpected cipher name: " + cipher,
                        cipher.startsWith("TLS_AES_")
                                || cipher.startsWith("TLS_CHACHA20_"));
            }
        }
    }
}

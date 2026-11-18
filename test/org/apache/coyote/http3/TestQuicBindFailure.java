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
import java.lang.reflect.Field;
import java.net.DatagramSocket;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;

/**
 * Tests for the QUIC endpoint's bind failure path. A failed bind must not
 * leak the UDP socket, the SSL context, the poll set or the listener
 * (releaseBindResources()), and the JVM must be able to bind the endpoint
 * successfully afterwards.
 */
public class TestQuicBindFailure extends Http3TestBase {

    @Test
    public void testBindOnOccupiedPortFailsAndRetriesCleanly()
            throws Exception {
        assumeQuicEnvironmentAvailable();

        int udpPort = findFreeUdpPort();

        // Occupy the UDP port the connector is about to bind to.
        // Wildcard bind: matches the endpoint's own wildcard bind so the
        // port is genuinely unavailable (a loopback-only bind would let the
        // server bind the wildcard address next to it).
        try (DatagramSocket blocker = new DatagramSocket(udpPort)) {
            Connector connector = newHttp3Connector(udpPort);
            getTomcatInstance().setConnector(connector);
            getProgrammaticRootContext();

            // LifecycleBase swallows the connector failure: start()
            // completes and the failed connector is left in FAILED state.
            getTomcatInstance().start();
            Assert.assertEquals("Connector must not have bound the "
                    + "occupied UDP port " + udpPort,
                    LifecycleState.FAILED, connector.getState());
        }

        // The port is free again. A fresh endpoint must bind cleanly: a
        // leaked socket or poll set from the failed bind would surface as
        // "address already in use" here.
        Connector retry = newHttp3Connector(udpPort);
        Tomcat tomcat = new Tomcat();
        tomcat.setBaseDir(System.getProperty("tomcat.test.temp") +
                "/bind-retry");
        tomcat.setConnector(retry);
        try {
            tomcat.start();
            Assert.assertEquals(LifecycleState.STARTED,
                    retry.getState());
        } finally {
            try {
                tomcat.stop();
            } finally {
                tomcat.destroy();
            }
        }
    }


    @Test
    public void testEndpointStopsAfterFailedBind() throws Exception {
        assumeQuicEnvironmentAvailable();

        int udpPort = findFreeUdpPort();
        try (DatagramSocket blocker = new DatagramSocket(udpPort)) {
            Connector connector = newHttp3Connector(udpPort);
            getTomcatInstance().setConnector(connector);
            getProgrammaticRootContext();
            getTomcatInstance().start();
            Assert.assertEquals("Connector must not have bound the "
                    + "occupied UDP port " + udpPort,
                    LifecycleState.FAILED, connector.getState());
            // Stopping the server whose connector failed to bind must not
            // throw and must not hang (the poll thread was never started,
            // so there is nothing to join).
            getTomcatInstance().stop();
        }
    }


    @Test
    public void testInvalidCipherSuitesFailBind() throws Exception {
        assumeQuicEnvironmentAvailable();
        Assume.assumeFalse("quiche uses a PEM test certificate here",
                endpointIsQuiche());

        Connector connector = newHttp3Connector(findFreeUdpPort(),
                invalidCipherHostConfig());
        getTomcatInstance().setConnector(connector);
        getProgrammaticRootContext();
        getTomcatInstance().start();
        // A cipher policy OpenSSL cannot parse must fail the bind rather than
        // silently leaving the default TLS 1.3 cipher list active.
        Assert.assertEquals(LifecycleState.FAILED, connector.getState());
    }


    private static SSLHostConfig invalidCipherHostConfig() throws Exception {
        SSLHostConfig hostConfig = new SSLHostConfig();
        hostConfig.setSslProtocol("tls");
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(
                hostConfig, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateKeystoreFile(
                new File(KEYSTORE).getAbsolutePath());
        certificate.setCertificateKeystorePassword(KEYSTORE_PASSWORD);
        hostConfig.addCertificate(certificate);
        // SSLHostConfig silently filters non-TLS-1.3 names in the public
        // setter; bypass that filter to exercise the native cipher parser.
        Field cipherSuitesField = SSLHostConfig.class.getDeclaredField(
                "cipherSuites");
        cipherSuitesField.setAccessible(true);
        cipherSuitesField.set(hostConfig, "TLS_DOES_NOT_EXIST");
        return hostConfig;
    }
}

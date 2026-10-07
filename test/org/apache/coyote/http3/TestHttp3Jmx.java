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

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.ServerSocket;

import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.modeler.Registry;

/*
 * An HTTP/3 connector and a TCP connector may share the same port number (UDP
 * for QUIC, TCP for Alt-Svc fallback). Ensure the JMX ObjectNames for both
 * connectors and their protocol handlers are distinct so that neither
 * registration replaces the other.
 */
public class TestHttp3Jmx extends Http3TestBase {

    @Test
    public void testDistinctMBeanNamesForSamePortConnectors() throws Exception {
        Assume.assumeTrue("OpenSSL QUIC support not available",
                isQuicSupported());

        int port = findFreeCombinedPort();

        Connector h3Connector = newHttp3Connector(port);
        Connector tcpConnector = new Connector("HTTP/1.1");
        tcpConnector.setPort(port);

        Tomcat tomcat = getTomcatInstance();
        tomcat.setConnector(h3Connector);
        tomcat.setConnector(tcpConnector);
        tomcat.start();

        MBeanServer mserver = Registry.getRegistry(null).getMBeanServer();

        ObjectName h3ProtocolOn = new ObjectName(
                "Tomcat:type=ProtocolHandler,port=" + port + ",transport=UDP");
        ObjectName tcpProtocolOn = new ObjectName(
                "Tomcat:type=ProtocolHandler,port=" + port);
        ObjectName h3ConnectorOn = new ObjectName(
                "Tomcat:type=Connector,port=" + port + ",transport=UDP");
        ObjectName tcpConnectorOn = new ObjectName(
                "Tomcat:type=Connector,port=" + port);

        Assert.assertTrue("HTTP/3 ProtocolHandler MBean not registered",
                mserver.isRegistered(h3ProtocolOn));
        Assert.assertTrue("TCP ProtocolHandler MBean not registered",
                mserver.isRegistered(tcpProtocolOn));
        Assert.assertTrue("HTTP/3 Connector MBean not registered",
                mserver.isRegistered(h3ConnectorOn));
        Assert.assertTrue("TCP Connector MBean not registered",
                mserver.isRegistered(tcpConnectorOn));

        String h3Name = (String) mserver.getAttribute(h3ProtocolOn, "name");
        Assert.assertTrue("Unexpected HTTP/3 protocol handler name: " + h3Name,
                h3Name.contains("https-quic"));
        String tcpName = (String) mserver.getAttribute(tcpProtocolOn, "name");
        Assert.assertTrue("Unexpected TCP protocol handler name: " + tcpName,
                tcpName.contains("http-nio"));

        tomcat.stop();
        tomcat.destroy();

        Assert.assertFalse("HTTP/3 ProtocolHandler MBean still registered",
                mserver.isRegistered(h3ProtocolOn));
        Assert.assertFalse("TCP ProtocolHandler MBean still registered",
                mserver.isRegistered(tcpProtocolOn));
        Assert.assertFalse("HTTP/3 Connector MBean still registered",
                mserver.isRegistered(h3ConnectorOn));
        Assert.assertFalse("TCP Connector MBean still registered",
                mserver.isRegistered(tcpConnectorOn));
    }


    /*
     * Locate a port number that is free for both TCP and UDP so the HTTP/3
     * connector and the TCP connector can bind the same port on their
     * respective transports.
     */
    private static int findFreeCombinedPort() throws IOException {
        for (int i = 0; i < 20; i++) {
            int candidate;
            try (ServerSocket socket = new ServerSocket(0)) {
                candidate = socket.getLocalPort();
            }
            try (ServerSocket socket = new ServerSocket(candidate);
                    DatagramSocket dgram =
                            new DatagramSocket(candidate)) {
                return candidate;
            } catch (IOException e) {
                // The port is in use on one of the transports. Try again.
            }
        }
        throw new IOException("Unable to find a free TCP and UDP port");
    }
}

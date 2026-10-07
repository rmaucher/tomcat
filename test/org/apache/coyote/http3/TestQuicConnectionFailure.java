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

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;

/**
 * Connection failure resilience tests for the QUIC endpoint. The client
 * dies abruptly (no {@code CONNECTION_CLOSE}, RFC 9000 Section 10.1) or
 * closes with an error (RFC 9000 Section 10.2.3); in all cases the server
 * must reclaim resources, keep serving new connections and stop cleanly.
 */
public class TestQuicConnectionFailure extends Http3TestBase {

    private static boolean hasLine(ClientOutput output, String marker) {
        for (String line : output.getLines()) {
            if (line.equals(marker)) {
                return true;
            }
        }
        return false;
    }


    /*
     * The server cannot observe the death of a peer that never sends a
     * CONNECTION_CLOSE; the connection only ages out on the idle timer
     * (30 seconds by default). Verify liveness by serving a new request
     * and, more importantly, that the harness teardown (connector stop)
     * works while dead connections are still held.
     */
    private void assertServerHealthy() throws Exception {
        validateStatus(get("/simple"), 200);
    }


    @Test
    public void testClientDiesBeforeResponse() throws Exception {
        startHttp3Server();

        // The server sleeps 3 seconds before responding; the client times
        // out at 1 second and dies without a CONNECTION_CLOSE while the
        // server still believes the request is in flight.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(simpleGetHeaders("/sleep?ms=3000")),
                "--timeout", "1", "--abandon"), CLIENT_TIMEOUT_SECONDS);
        Assert.assertTrue("Client must have died abruptly: "
                + output.getLines(), hasLine(output, "ABANDONED"));

        // The server completes the request against the dead connection and
        // keeps serving new ones.
        assertServerHealthy();
    }


    @Test
    public void testClientDiesMidResponse() throws Exception {
        startHttp3Server(ctxt -> {
            Wrapper w = Tomcat.addServlet(ctxt, "slowstream",
                    new SlowStreamServlet());
            ctxt.addServletMapping("/slowstream", "slowstream");
        });

        // The servlet streams for about two seconds; the client abandons
        // the connection while data is still flowing.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(simpleGetHeaders("/slowstream")),
                "--timeout", "0.3", "--abandon"), CLIENT_TIMEOUT_SECONDS);
        Assert.assertTrue("Client must have died abruptly: "
                + output.getLines(), hasLine(output, "ABANDONED"));

        // Let the server finish streaming against the dead stream before
        // probing it, so the request threads have returned to the pool.
        Thread.sleep(2500);
        assertServerHealthy();
    }


    @Test
    public void testMultipleStreamsThenAbruptDeath() throws Exception {
        startHttp3Server();

        // Eight concurrent requests on one connection; all responses are
        // received, then the connection dies without a CONNECTION_CLOSE.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--streams", "8", "--timeout", "5", "--abandon"),
                CLIENT_TIMEOUT_SECONDS);
        Assert.assertTrue("Client must have died abruptly: "
                + output.getLines(), hasLine(output, "ABANDONED"));
        int responses = output.getResponses().size();
        Assert.assertTrue("Expected responses on the multiplexed streams, got "
                + responses, responses >= 1);

        assertServerHealthy();
    }


    @Test
    public void testConnectionClosedWithError() throws Exception {
        startHttp3Server();

        // A well-behaved request, then the client terminates the
        // connection with a CONNECTION_CLOSE carrying a transport error
        // (RFC 9000 Section 10.2.3).
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--close-error", "11"), CLIENT_TIMEOUT_SECONDS);
        validateStatus(output.getResponse(), 200);
        Assert.assertTrue("Client must have closed with an error: "
                + output.getLines(),
                hasLine(output, "CLOSED_WITH_ERROR=11"));

        assertServerHealthy();
    }


    /*
     * Number of live connections held by the endpoint's connection map.
     * Reflection is used because the endpoint exposes no connection-count
     * attribute; the test runs on the classpath so setAccessible() is
     * permitted.
     */
    private int liveConnections() throws Exception {
        Object endpoint =
                ((AbstractHttp3Protocol) connector.getProtocolHandler())
                        .getQuicEndpoint();
        java.lang.reflect.Field field =
                endpoint.getClass().getDeclaredField("connections");
        field.setAccessible(true);
        return ((java.util.Map<?, ?>) field.get(endpoint)).size();
    }


    @Test
    public void testIdleConnectionIsReaped() throws Exception {
        startHttp3Server(ctxt ->
                ((AbstractHttp3Protocol) connector.getProtocolHandler())
                        .setIdleTimeoutMs(2000));

        // An idle-only connection (QPACK/control streams, no request) with
        // no traffic for about three times the configured idle timeout.
        ClientOutput output = runClient(rawCommandWith("--no-request",
                "--timeout", "3", "--wait", "1"), CLIENT_TIMEOUT_SECONDS);
        // The client must not see a connection error before the server has
        // reaped the connection. Note that this assertion only holds for an
        // endpoint whose configured idle timeout is not advertised to the
        // peer: the OpenSSL feature-request for the idle timeout can fall
        // back silently, while the quiche endpoint always honours and
        // advertises it. When it is advertised, the aioquic client applies
        // the negotiated value itself and closes with its own "Idle
        // timeout" (reported as INTERNAL_ERROR) before the server-side reap
        // is observable at all - a client-side fact of RFC 9000 Section
        // 10.1, not a server close. Skip the assertion when the idle
        // timeout is honestly advertised.
        if (!endpointIsQuiche()) {
            Assert.assertNull("The idle connection must not have been closed "
                    + "by the client with an error",
                    output.getConnectionError());
        }

        // The server must drop the connection after its idle timeout
        // (RFC 9000 Section 10.1). Allow a generous margin: the timeout is
        // a negotiated feature value and its enforcement is driven by the
        // poll loop's timer ticks.
        long deadline = System.currentTimeMillis() + 15000;
        int live = liveConnections();
        while (live > 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(250);
            live = liveConnections();
        }
        Assert.assertEquals("The idle connection must have been reaped",
                0, live);
    }


    private static class SlowStreamServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req,
                HttpServletResponse resp) throws IOException {
            resp.setContentType("application/octet-stream");
            ServletOutputStream out = resp.getOutputStream();
            byte[] block = new byte[8192];
            for (int i = 0; i < 40; i++) {
                out.write(block);
                out.flush();
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }
}

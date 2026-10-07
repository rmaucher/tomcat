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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;

public class TestHttp3Headers extends Http3TestBase {

    @Test
    public void testRequestHeadersEchoed() throws Exception {
        startHttp3Server();

        Http3Response response = get("/echo", "x-test", "hello-h3");

        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected the echoed request header in:\n" + body,
                body.contains("x-test: hello-h3"));
    }


    @Test
    public void testMultipleRequestHeadersEchoed() throws Exception {
        startHttp3Server();

        Http3Response response = get("/echo", "x-test-one", "one", "x-test-two",
                "two");

        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected the echoed request header in:\n" + body,
                body.contains("x-test-one: one"));
        Assert.assertTrue("Expected the echoed request header in:\n" + body,
                body.contains("x-test-two: two"));
    }


    @Test
    public void testRawValueWithControlCharactersRejected() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.1.2: invalid characters in a field value make
        // the message malformed. The production QPACK encoder emits values as
        // raw (non-Huffman) string literals, so this exercises the raw path
        // of the value validation in Http3Processor.emitHeader().
        ClientOutput output = rawGet("/simple", "x-test", "a\r\nb");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRawValueWithNulRejected() throws Exception {
        startHttp3Server();

        ClientOutput output = rawGet("/simple", "x-test", "a\0b");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRawValueWithLeadingSpaceRejected() throws Exception {
        startHttp3Server();

        // RFC 9110 Section 5.5: a field value must start with a VCHAR.
        ClientOutput output = rawGet("/simple", "x-test", " leading");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRawValueWithTrailingSpaceRejected() throws Exception {
        startHttp3Server();

        // RFC 9110 Section 5.5: a field value must end with a VCHAR.
        ClientOutput output = rawGet("/simple", "x-test", "trailing ");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRawValueWithMiddleSpaceAccepted() throws Exception {
        startHttp3Server();

        // Spaces are valid field-content between the first and last
        // character (RFC 9110 Section 5.5); only leading/trailing
        // whitespace and control characters are invalid.
        Http3Response response = get("/echo", "x-test", "a b");

        validateStatus(response, 200);
        Assert.assertTrue("Expected the echoed request header in:\n"
                + response.getBodyAsString(),
                response.getBodyAsString().contains("x-test: a b"));
    }


    @Test
    public void testCookieFieldsCoalesced() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.2.1: multiple cookie field lines in one field
        // section must be concatenated into a single field value using the
        // two-byte delimiter "; " before being passed to a non-HTTP/3
        // context (same behavior as the HTTP/2 connector).
        ClientOutput output = rawGet("/echo", "cookie", "a=1", "cookie",
                "b=2");

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected the joined cookie header in:\n" + body,
                body.contains("cookie: a=1; b=2"));
        Assert.assertFalse("The split cookie lines must not be exposed "
                + "separately: " + body, body.contains("cookie: a=1\n"));
    }


    @Test
    public void testMalformedHostHeaderWithAuthorityYieldsBadRequest() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // A valid :authority sets serverName (so the presence check passes)
        // but a Host header that Host.parse() rejects cannot be compared;
        // the failure is recorded as Request.NOTE_BAD_REQUEST during
        // decoding. The request must be answered with 400 (as the HTTP/2
        // connector does), not dispatched to the container.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "127.0.0.1:" + port,
                "host", "bad host");

        Http3Response response = output.getResponse();
        validateStatus(response, 400);
        Assert.assertNull("Expected no stream error",
                output.getStreamError());
    }


    @Test
    public void testHostHeaderSuppliesAuthority() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // RFC 9114 Section 4.3.1: when :authority is absent the authority
        // may be carried in the Host field. It must populate serverName.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                "host", "127.0.0.1:" + port);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("127.0.0.1:" + port, response.getBodyAsString());
    }


    @Test
    public void testConsistentHostAndAuthorityAccepted() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // RFC 9114 Section 4.3.1: when both :authority and Host are present
        // they must carry the same value; consistent values are accepted.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "127.0.0.1:" + port,
                "host", "127.0.0.1:" + port);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("127.0.0.1:" + port, response.getBodyAsString());
    }


    @Test
    public void testInconsistentHostAndAuthorityRejected() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // RFC 9114 Section 4.3.1: :authority and Host must carry the same
        // value when both are present; a mismatch is malformed. The host is
        // deliberately chosen so that it cannot match the authority port.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "127.0.0.1:" + port,
                "host", "other.example.com:1");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testDuplicateHostRejected() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // Multiple Host fields are malformed.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "127.0.0.1:" + port,
                "host", "127.0.0.1:" + port,
                "host", "127.0.0.1:" + port);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testMissingAuthorityAndHostRejected() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // RFC 9114 Section 4.3.1: a request must carry an authority via
        // :authority and/or Host. Neither present -> malformed.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testEmptyAuthorityRejected() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // An empty :authority yields no host name (Host.parse rejects the
        // empty value) and the resulting missing authority makes the
        // request malformed.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testUserinfoInAuthorityRejected() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // RFC 9114 Section 4.3.1: the deprecated userinfo subcomponent must
        // not appear in :authority; Host.parse rejects it (no host name
        // results), making the request malformed.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "user@127.0.0.1:" + port);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    private void addServerNameServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "serverName", new ServerNameServlet());
        ctxt.addServletMapping("/serverName", "serverName");
    }


    private static class ServerNameServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("ISO-8859-1");
            resp.getWriter().print(
                    req.getServerName() + ":" + req.getServerPort());
        }
    }


    @Test
    public void testConfiguredServerHeaderOverridesAppProvided()
            throws Exception {
        startHttp3Server(this::addServerHeaderServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setServer("TomcatH3Test");

        // Same rules as HTTP/1.1/HTTP/2: a configured server value always
        // overrides anything the application may have set.
        Http3Response response = get("/serverheader");

        validateStatus(response, 200);
        Assert.assertEquals("TomcatH3Test", response.getHeader("server"));
    }


    @Test
    public void testAppProvidedServerHeaderPassesThroughByDefault()
            throws Exception {
        startHttp3Server(this::addServerHeaderServlet);

        Http3Response response = get("/serverheader");

        validateStatus(response, 200);
        Assert.assertEquals("app-provided", response.getHeader("server"));
    }


    @Test
    public void testServerRemoveAppProvidedValues() throws Exception {
        startHttp3Server(this::addServerHeaderServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setServerRemoveAppProvidedValues(true);

        Http3Response response = get("/serverheader");

        validateStatus(response, 200);
        Assert.assertNull(response.getHeader("server"));
    }


    @Test
    public void testAltServiceAnnounced() throws Exception {
        startHttp3Server();
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAltService("h3");

        // Same as HTTP/2: the configured service is announced on the port
        // of the request, unless the application set Alt-Svc itself.
        Http3Response response = get("/simple");

        validateStatus(response, 200);
        Assert.assertEquals(String.format("h3=\":%d\"", Integer.valueOf(port)),
                response.getHeader("alt-svc"));
    }


    @Test
    public void testAppAltServiceHeaderTakesPrecedence() throws Exception {
        startHttp3Server(this::addServerHeaderServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAltService("h3");

        Http3Response response = get("/serverheader");

        validateStatus(response, 200);
        Assert.assertEquals("h2=\":8443\"", response.getHeader("alt-svc"));
    }


    private void addServerHeaderServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "serverheader", new ServerHeaderServlet());
        ctxt.addServletMapping("/serverheader", "serverheader");
    }


    private static class ServerHeaderServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setHeader("Server", "app-provided");
            resp.setHeader("Alt-Svc", "h2=\":8443\"");
            resp.setContentType("text/plain");
            resp.getWriter().print("ok");
        }
    }


    @Test
    public void testSwitchingProtocolsNotSupported() throws Exception {
        startHttp3Server(this::addSwitchingServlet);

        // HTTP/3 supports neither HTTP Upgrade nor the 101 (Switching
        // Protocols) status code (RFC 9114 Section 4.5). An application
        // that commits a 101 is answered with a 500 rather than the
        // forbidden status occupying the stream's only response head.
        ClientOutput output = rawGet("/switching");

        Http3Response response = output.getResponse();
        validateStatus(response, 500);
        Assert.assertNull("Expected no stream error", output.getStreamError());
        Assert.assertTrue("Expected the written body in:\n"
                + response.getBodyAsString(),
                response.getBodyAsString().contains("switched"));
    }


    private void addSwitchingServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "switching", new SwitchingServlet());
        ctxt.addServletMapping("/switching", "switching");
    }


    private static class SwitchingServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setStatus(HttpServletResponse.SC_SWITCHING_PROTOCOLS);
            resp.flushBuffer();
            resp.setContentType("text/plain");
            resp.getWriter().print("switched");
        }
    }
}

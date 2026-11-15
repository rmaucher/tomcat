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
import java.util.HashMap;
import java.util.Map;

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
        ClientOutput output = rawGetUnvalidated("/simple", "x-test",
                "a\r\nb");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRawValueWithNulRejected() throws Exception {
        startHttp3Server();

        ClientOutput output = rawGetUnvalidated("/simple", "x-test", "a\0b");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRawValueWithLeadingSpaceRejected() throws Exception {
        startHttp3Server();

        // RFC 9110 Section 5.5: a field value must start with a VCHAR. The
        // production QPACK encoder now filters leading/trailing whitespace, so
        // bypass it to exercise the decoder's raw-value validation.
        ClientOutput output = rawGetUnvalidated("/simple", "x-test",
                " leading");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRawValueWithTrailingSpaceRejected() throws Exception {
        startHttp3Server();

        // RFC 9110 Section 5.5: a field value must end with a VCHAR. The
        // production QPACK encoder now filters leading/trailing whitespace, so
        // bypass it to exercise the decoder's raw-value validation.
        ClientOutput output = rawGetUnvalidated("/simple", "x-test",
                "trailing ");

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
    public void testErrorResponseOmitsAltSvcWithoutAuthorityPort()
            throws Exception {
        startHttp3Server(this::addServerNameServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAltService("h3");

        // The request has a valid :authority without an explicit port and a
        // malformed Host field, so the protocol answers with a 400 before
        // CoyoteAdapter can apply the scheme-default port. The Alt-Svc
        // advertisement must not contain a placeholder or invalid port.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "127.0.0.1",
                "host", "bad host");

        Http3Response response = output.getResponse();
        validateStatus(response, 400);
        Assert.assertNull("Alt-Svc must be omitted when there is no valid "
                + "request port", response.getHeader("alt-svc"));
    }


    @Test
    public void testAuthorityPortOutOfRangeRejected() throws Exception {
        startHttp3Server(this::addServerNameServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAltService("h3");

        // RFC 3986 Section 3.2.3 defines port as a decimal number in the
        // range 0-65535. A larger authority port must not be accepted and
        // reflected into the Alt-Svc response field.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "127.0.0.1:65536");

        Http3Response response = output.getResponse();
        validateStatus(response, 400);
        Assert.assertNull("An out-of-range authority port must not appear "
                + "in Alt-Svc", response.getHeader("alt-svc"));
    }


    @Test
    public void testErrorResponseCarriesConfiguredServerAndDate()
            throws Exception {
        startHttp3Server(this::addServerNameServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setServer("TestServer");
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAltService("h3");

        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "127.0.0.1:" + port,
                "host", "bad host");

        Http3Response response = output.getResponse();
        validateStatus(response, 400);
        // RFC 9110 Section 6.6.1: an origin server with a clock MUST send a
        // Date field in a 4xx response. The connector's configured Server
        // and Alt-Svc values also apply to responses generated by the
        // protocol itself, not only to container responses.
        Assert.assertNotNull("A 400 response must carry a Date field",
                response.getHeader("date"));
        Assert.assertEquals("TestServer", response.getHeader("server"));
        Assert.assertEquals(String.format("h3=\":%d\"",
                Integer.valueOf(port)), response.getHeader("alt-svc"));
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
    public void testCaseInsensitiveHostAndAuthorityAccepted() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // RFC 3986 Section 3.2.2 and RFC 9110 Section 7.2 define host names
        // as case-insensitive. A Host value differing only in case from
        // :authority is consistent and must be accepted.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "localhost:" + port,
                "host", "LOCALHOST:" + port);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("localhost:" + port, response.getBodyAsString());
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
    public void testEmptyAuthorityPortAccepted() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // RFC 3986 Section 3.2.3 permits an empty port and treats it as
        // equivalent to no port. The request must be accepted and the
        // scheme default port populated by the adapter.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "127.0.0.1:");

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("127.0.0.1:443", response.getBodyAsString());
    }


    @Test
    public void testEmptyHostPortAccepted() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // Same rule when the authority is supplied by the Host field.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                "host", "127.0.0.1:");

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("127.0.0.1:443", response.getBodyAsString());
    }


    @Test
    public void testEmptyAuthorityAndHostPortsAccepted() throws Exception {
        startHttp3Server(this::addServerNameServlet);

        // Both fields carry the empty-port form; the host names are equal
        // and neither carries an explicit port.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":path", "/serverName",
                ":authority", "127.0.0.1:", "host", "127.0.0.1:");

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("127.0.0.1:443", response.getBodyAsString());
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
    public void testNullResponseTrailerValueIgnored() throws Exception {
        startHttp3Server(this::addNullTrailerServlet);

        // The trailer map is application-supplied; a null value must be
        // skipped rather than producing an NPE in the QPACK encoder.
        Http3Response response = get("/nulltrailer");

        validateStatus(response, 200);
        Assert.assertEquals("ok", response.getBodyAsString());
    }


    @Test
    public void testServletProtocolIsHttp30() throws Exception {
        startHttp3Server(this::addProtocolServlet);

        Http3Response response = get("/protocol");

        validateStatus(response, 200);
        Assert.assertEquals("HTTP/3.0", response.getBodyAsString());
    }


    @Test
    public void testResponseCommittedAfterDirectWrite() throws Exception {
        startHttp3Server(this::addCommittedServlet);

        // A write larger than the container's output buffer is passed
        // straight to the processor before Response.commit() runs. The
        // processor must mark the response committed when it writes the
        // final HEADERS frame, otherwise the servlet observes
        // isCommitted() == false after its headers are on the wire.
        Http3Response response = get("/committed");

        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected committed=true in body: " + body,
                body.contains("committed=true"));
    }


    @Test
    public void testContentLengthZeroOn205Response() throws Exception {
        startHttp3Server(this::addResetContentServlet);

        // RFC 9110 Section 15.3.5 requires a Content-Length: 0 field in a
        // 205 response.
        Http3Response response = get("/resetcontent");

        validateStatus(response, 205);
        Assert.assertEquals("205 response must carry Content-Length: 0",
                "0", response.getHeader("content-length"));
    }


    @Test
    public void testNoContentLengthOn204Response() throws Exception {
        startHttp3Server(this::addNoContentLengthServlet);

        // RFC 9110 Section 8.6 forbids Content-Length in a 204 response even
        // when the application supplies one.
        Http3Response response = get("/nocontentlength");

        validateStatus(response, 204);
        Assert.assertNull("Content-Length sent on 204",
                response.getHeader("content-length"));
    }


    @Test
    public void testApplicationStatusPseudoHeaderDoesNotOverrideResponse()
            throws Exception {
        startHttp3Server(this::addStatusHeaderServlet);

        // An application-supplied :status must not replace the status used
        // for the response/body decisions. The wire status must be 200.
        Http3Response response = get("/statusheader");

        validateStatus(response, 200);
        Assert.assertEquals("ok", response.getBodyAsString());
    }


    @Test
    public void testConnectionSpecificResponseHeadersRemoved()
            throws Exception {
        startHttp3Server(this::addConnectionHeaderServlet);

        // RFC 9114 Section 4.2: an endpoint MUST NOT generate a field section
        // containing connection-specific fields. The application can still
        // attempt to set them, so the connector must remove them.
        Http3Response response = get("/connheaders");

        validateStatus(response, 200);
        Assert.assertNull("Connection field sent",
                response.getHeader("connection"));
        Assert.assertNull("Transfer-Encoding field sent",
                response.getHeader("transfer-encoding"));
        Assert.assertNull("Keep-Alive field sent",
                response.getHeader("keep-alive"));
        Assert.assertNull("Upgrade field sent",
                response.getHeader("upgrade"));
        Assert.assertEquals("ok", response.getBodyAsString());
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


    @Test
    public void testEmptyAltServiceNotAnnounced() throws Exception {
        startHttp3Server();
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAltService("");

        // An empty value is not a usable protocol identifier. It must be
        // treated like an unset value rather than emitted as
        // Alt-Svc: =":<port>".
        Http3Response response = get("/simple");

        validateStatus(response, 200);
        Assert.assertNull("An empty Alt-Svc value must not be announced",
                response.getHeader("alt-svc"));
    }


    @Test
    public void testInvalidAltServiceRejected() throws Exception {
        startHttp3Server();
        AbstractHttp3Protocol protocol =
                (AbstractHttp3Protocol) connector.getProtocolHandler();
        protocol.setAltService("h3");

        try {
            protocol.setAltService("h3 not-a-token");
            Assert.fail("An Alt-Svc value that is not a token must be "
                    + "rejected");
        } catch (IllegalArgumentException expected) {
            // Expected: the invalid value must not be stored.
        }
        Assert.assertEquals("An invalid Alt-Svc value must not replace the "
                + "previous valid value", "h3", protocol.getAltService());
    }


    private void addNullTrailerServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "nulltrailer", new NullTrailerServlet());
        ctxt.addServletMapping("/nulltrailer", "nulltrailer");
    }


    private static class NullTrailerServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setTrailerFields(() -> {
                Map<String,String> trailers = new HashMap<>();
                trailers.put("x-null", null);
                return trailers;
            });
            resp.getWriter().print("ok");
        }
    }


    private void addProtocolServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "protocol", new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void doGet(HttpServletRequest req,
                    HttpServletResponse resp) throws IOException {
                resp.setContentType("text/plain");
                resp.getWriter().write(req.getProtocol());
            }
        });
        ctxt.addServletMapping("/protocol", "protocol");
    }


    private void addCommittedServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "committed", new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void doGet(HttpServletRequest req,
                    HttpServletResponse resp) throws IOException {
                resp.setContentType("text/plain");
                jakarta.servlet.ServletOutputStream out =
                        resp.getOutputStream();
                out.write(new byte[9000]);
                out.write(("committed=" + resp.isCommitted())
                        .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            }
        });
        ctxt.addServletMapping("/committed", "committed");
    }


    private void addResetContentServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "resetcontent", new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void doGet(HttpServletRequest req,
                    HttpServletResponse resp) {
                resp.setStatus(205);
            }
        });
        ctxt.addServletMapping("/resetcontent", "resetcontent");
    }


    private void addNoContentLengthServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "nocontentlength", new NoContentLengthServlet());
        ctxt.addServletMapping("/nocontentlength", "nocontentlength");
    }


    private static class NoContentLengthServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
            resp.setHeader("Content-Length", "10");
        }
    }


    private void addStatusHeaderServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "statusheader", new StatusHeaderServlet());
        ctxt.addServletMapping("/statusheader", "statusheader");
    }


    private static class StatusHeaderServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setHeader(":status", "404");
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setContentType("text/plain");
            resp.getWriter().print("ok");
        }
    }


    private void addConnectionHeaderServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "connheaders", new ConnectionHeaderServlet());
        ctxt.addServletMapping("/connheaders", "connheaders");
    }


    private static class ConnectionHeaderServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setHeader("Connection", "close");
            resp.setHeader("Transfer-Encoding", "chunked");
            resp.setHeader("Keep-Alive", "timeout=5");
            resp.setHeader("Upgrade", "h3");
            resp.setContentType("text/plain");
            resp.getWriter().print("ok");
        }
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

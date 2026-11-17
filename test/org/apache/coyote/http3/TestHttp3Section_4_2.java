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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;

/**
 * Tests for the response message requirements of
 * <a href="https://www.rfc-editor.org/rfc/rfc9114#section-4.2">RFC 9114
 * Section 4.2</a>.
 */
public class TestHttp3Section_4_2 extends Http3TestBase {

    @Test
    public void testBasicResponse() throws Exception {
        startHttp3Server();

        Http3Response response = get("/simple");

        validateStatus(response, 200);
        Assert.assertNotNull(response.getHeader("content-type"));
        Assert.assertNotNull(response.getHeader("date"));
    }


    @Test
    public void testInformationalStatusAsFinalResponseReplaced() throws Exception {
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "status", new StatusServlet());
            ctxt.addServletMapping("/status", "status");
        });

        // RFC 9114 Section 4.1: zero or more interim responses are followed
        // by exactly one final response. An application-selected 1xx status
        // must not occupy the final response HEADERS frame (the 102 must be
        // either sent via the interim path or replaced by a final status).
        ClientOutput output = rawGet("/status?code=102");

        Http3Response response = output.getResponse();
        Assert.assertEquals("A final response must not carry a 1xx status",
                Arrays.asList(Integer.valueOf(500)), response.getStatuses());
        Assert.assertEquals("body", response.getBodyAsString());
    }


    @Test
    public void testOutOfRangeStatusReplaced() throws Exception {
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "status", new StatusServlet());
            ctxt.addServletMapping("/status", "status");
        });

        // RFC 9110 Section 15 requires a three-digit status code in the
        // 100-599 range. Values outside that range must never be encoded
        // into :status.
        Http3Response response = rawGet("/status?code=600").getResponse();
        Assert.assertEquals("An out-of-range status must be replaced",
                Arrays.asList(Integer.valueOf(500)), response.getStatuses());

        response = rawGet("/status?code=99").getResponse();
        Assert.assertEquals("An out-of-range status must be replaced",
                Arrays.asList(Integer.valueOf(500)), response.getStatuses());
    }


    @Test
    public void testInvalidStatusDoesNotKeepContentLength() throws Exception {
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "statusLength",
                    new StatusContentLengthServlet());
            ctxt.addServletMapping("/statusLength", "statusLength");
        });

        // Replacing an invalid final status with 500 must also discard the
        // application's framing metadata. A 500 with a stale non-zero
        // Content-Length and no DATA frames would be a truncated response.
        for (String code : new String[] { "103", "600" }) {
            Http3Response response = rawGet(
                    "/statusLength?code=" + code).getResponse();
            Assert.assertEquals("Status " + code + " must be replaced",
                    Arrays.asList(Integer.valueOf(500)), response.getStatuses());
            Assert.assertNull("Status " + code + " must not keep a stale "
                    + "Content-Length", response.getHeader("content-length"));
            Assert.assertEquals("Status " + code + " must not send a body",
                    0, response.getBody().length);
        }
    }


    @Test
    public void testResponseWithContentLength() throws Exception {
        startHttp3Server();

        Http3Response response = get("/simple");

        validateStatus(response, 200);
        Assert.assertEquals("17", response.getHeader("content-length"));
        Assert.assertEquals(17, response.getBody().length);
    }


    @Test
    public void testEarlyHints() throws Exception {
        startHttp3Server();

        // The aioquic H3 stack in the normal client mode rejects the
        // second HEADERS frame of the early hints response, so the raw
        // client mode is used here.
        ClientOutput output = rawGet("/earlyHints");

        Http3Response response = output.getResponse();
        Assert.assertEquals(Arrays.asList(103, 200),
                response.getStatuses());
        Assert.assertEquals("</large>; rel=preload",
                response.getHeader("link"));
        Assert.assertEquals("Hello over HTTP/3",
                response.getBodyAsString());
    }


    @Test
    public void testEarlyHintsNotOvertakenByFinalResponse() throws Exception {
        startHttp3Server();

        // Force the transport to accept only a prefix of the interim 103
        // HEADERS frame: the peer advertises a 26-byte per-stream
        // flow-control window, one byte short of the encoded early-hints
        // frame (27 bytes). If the interim frame were written non-blocking,
        // its remainder would be staged in SocketWrapperBase's non-blocking
        // write buffer, which a later blocking final-response write overtakes
        // (a blocking write appends to the socket buffer and flushBlocking()
        // writes that before draining the staging buffer). The client must
        // decode the complete 103 HEADERS frame before the final 200
        // response.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "GET", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/earlyHints"),
                "--max-stream-data", "26", "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        Assert.assertEquals(Arrays.asList(103, 200), response.getStatuses());
        Assert.assertEquals("</large>; rel=preload",
                response.getHeader("link"));
        Assert.assertEquals("Hello over HTTP/3", response.getBodyAsString());
        Assert.assertNull(output.getStreamError());
        Assert.assertNull(output.getConnectionError());
    }


    @Test
    public void testExpectContinueSendsInterimResponse() throws Exception {
        startHttp3Server();

        // A request carrying expect: 100-continue is acknowledged with an
        // interim 100 response (a HEADERS frame carrying only :status)
        // before the final response (RFC 9110 Section 10.1.1, same
        // behaviour as the HTTP/1.1 and HTTP/2 connectors). With the
        // default timing (immediately) the ack is sent before the servlet
        // runs. Raw mode: the aioquic client rejects interim responses.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "GET", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/simple", "expect", "100-continue")),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        Assert.assertEquals(Arrays.asList(100, 200),
                response.getStatuses());
        Assert.assertEquals("Hello over HTTP/3",
                response.getBodyAsString());
    }


    @Test
    public void testExpectContinueMixedCaseSendsInterimResponse()
            throws Exception {
        startHttp3Server();

        // The expectation value is a case-insensitive token (RFC 9110
        // Section 10.1.1), so a client spelling it "100-Continue" must get
        // the same interim response.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "GET", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/simple", "expect", "100-Continue")),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        Assert.assertEquals(Arrays.asList(100, 200),
                response.getStatuses());
        Assert.assertEquals("Hello over HTTP/3",
                response.getBodyAsString());
    }


    @Test
    public void testExpectContinueTimingOnRead() throws Exception {
        Connector connector = startHttp3Server();
        Assert.assertTrue(connector.setProperty("continueResponseTiming",
                "onRead"));

        // With the onRead timing the servlet may answer before any interim
        // response: /simple never reads the request body, so no 100 is
        // sent...
        ClientOutput servletDoesNotRead = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "GET", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/simple", "expect", "100-continue")),
                CLIENT_TIMEOUT_SECONDS);
        Assert.assertEquals(Arrays.asList(200),
                servletDoesNotRead.getResponse().getStatuses());

        // ...while /echo reads the body, which triggers the ack on the
        // first read (before the response is written).
        byte[] body = "ping".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        ClientOutput servletReads = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/echo", "content-length",
                        Integer.toString(body.length),
                        "expect", "100-continue"),
                "--data", Base64.getEncoder().encodeToString(body)),
                CLIENT_TIMEOUT_SECONDS);
        Assert.assertEquals(Arrays.asList(100, 200),
                servletReads.getResponse().getStatuses());
    }


    @Test
    public void testResponseTrailers() throws Exception {
        startHttp3Server();

        Http3Response response = get("/trailers");

        validateStatus(response, 200);
        Assert.assertEquals("test", response.getTrailer("x-test-trailer"));
        Assert.assertEquals("body", response.getBodyAsString());
    }


    @Test
    public void testHostTrailerFiltered() throws Exception {
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "hostTrailer", new HttpServlet() {

                private static final long serialVersionUID = 1L;

                @Override
                protected void doGet(HttpServletRequest req,
                        HttpServletResponse resp) throws IOException {
                    resp.setContentType("text/plain");
                    resp.setCharacterEncoding(
                            StandardCharsets.ISO_8859_1.name());
                    resp.setTrailerFields(() -> Map.of(
                            "host", "evil.example",
                            "x-test-trailer", "test"));
                    resp.getWriter().print("body");
                    resp.flushBuffer();
                }
            });
            ctxt.addServletMapping("/hostTrailer", "hostTrailer");
        });

        // RFC 9110 Section 6.5.1: a sender MUST NOT generate a trailer field
        // that is necessary for routing (e.g. Host). The connector's trailer
        // filter must drop it even though the application supplied it, while
        // retaining the valid trailer.
        Http3Response response = get("/hostTrailer");

        validateStatus(response, 200);
        Assert.assertNull("Host must not be generated as a response trailer",
                response.getTrailer("host"));
        Assert.assertEquals("test", response.getTrailer("x-test-trailer"));
        Assert.assertEquals("body", response.getBodyAsString());
    }


    @Test
    public void testProhibitedAuthenticationAndConditionalTrailersFiltered()
            throws Exception {
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "prohibitedTrailer", new HttpServlet() {

                private static final long serialVersionUID = 1L;

                @Override
                protected void doGet(HttpServletRequest req,
                        HttpServletResponse resp) throws IOException {
                    resp.setContentType("text/plain");
                    resp.setCharacterEncoding(
                            StandardCharsets.ISO_8859_1.name());
                    resp.setTrailerFields(() -> Map.of(
                            "set-cookie", "session=evil",
                            "authorization", "Bearer secret",
                            "if-match", "\"etag\"",
                            "content-language", "en",
                            "x-test-trailer", "test"));
                    resp.getWriter().print("body");
                    resp.flushBuffer();
                }
            });
            ctxt.addServletMapping("/prohibitedTrailer", "prohibitedTrailer");
        });

        // RFC 9110 Section 6.5.1: authentication, request-modifier/
        // conditional and payload-metadata fields must not be generated as
        // trailers unless the field definition permits it. HTTP/3 must
        // filter these even though the application supplied them, while
        // retaining a valid trailer.
        Http3Response response = get("/prohibitedTrailer");

        validateStatus(response, 200);
        Assert.assertNull("Set-Cookie must not be generated as a trailer",
                response.getTrailer("set-cookie"));
        Assert.assertNull("Authorization must not be generated as a trailer",
                response.getTrailer("authorization"));
        Assert.assertNull("If-Match must not be generated as a trailer",
                response.getTrailer("if-match"));
        Assert.assertNull("Content-Language must not be generated as a trailer",
                response.getTrailer("content-language"));
        Assert.assertEquals("test", response.getTrailer("x-test-trailer"));
        Assert.assertEquals("body", response.getBodyAsString());
    }


    @Test
    public void testContentLengthAndTrailersCanCoexist() throws Exception {
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "lengthTrailers",
                    new LengthTrailersServlet());
            ctxt.addServletMapping("/lengthTrailers", "lengthTrailers");
        });

        // RFC 9114 Section 4.1: an HTTP/3 message is a header section, DATA
        // frames and an optional trailer section. Unlike HTTP/1.1 chunked
        // framing, a trailer section does not make Content-Length mutually
        // exclusive with trailers, so a declared length that matches the
        // DATA payload must be retained.
        Http3Response response = get("/lengthTrailers");

        validateStatus(response, 200);
        Assert.assertEquals("5", response.getHeader("content-length"));
        Assert.assertEquals("body!", response.getBodyAsString());
        Assert.assertEquals("test", response.getTrailer("x-test-trailer"));
    }


    @Test
    public void testHeadResponse() throws Exception {
        startHttp3Server();

        // The aioquic H3 stack in the normal client mode rejects HEAD
        // responses that carry a content-length but no body, so the raw
        // client mode is used here.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "HEAD", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/simple")),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("17", response.getHeader("content-length"));
        Assert.assertEquals(0, response.getBody().length);
    }


    @Test
    public void testHeadResponseWithBodyServlet() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "HEAD", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/echo")),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("29", response.getHeader("content-length"));
        Assert.assertEquals(0, response.getBody().length);
    }


    @Test
    public void testHeadLargeBodyNoDataFrame() throws Exception {
        startHttp3Server();

        // A write larger than the container output buffer is passed straight
        // to the processor before commit. The void-output decision is made
        // when the final HEADERS frame is written, so the processor must
        // re-check it before emitting that first chunk as DATA.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "HEAD", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/large")),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("262144", response.getHeader("content-length"));
        Assert.assertEquals("HEAD response must not carry DATA frames",
                0, response.getBody().length);
    }


    @Test
    public void testNotFound() throws Exception {
        startHttp3Server();

        Http3Response response = get("/does-not-exist");

        validateStatus(response, 404);
    }


    @Test
    public void testResponseReducedToPeerFieldSectionLimit() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.2.2: the peer declared
        // SETTINGS_MAX_FIELD_SECTION_SIZE of 200 bytes. The response to
        // /simple ({:status, content-type, content-length, date}) is reduced
        // to fit; Date is mandatory for a 2xx response (RFC 9110 Section
        // 6.6.1) and must be retained even if the resulting section exceeds
        // the peer's advisory limit. Non-essential fields, if any, are
        // dropped.
        //
        // QUIC does not order the control stream against request streams.
        // Delay the request so the server can process the client SETTINGS
        // first; otherwise the response may legitimately be encoded under
        // the initial "unlimited" default before the SETTINGS arrive.
        ClientOutput output = runClient(rawCommandWith(
                "--control", buildSettingsFrameB64(6, 200),
                "--request-delay", "1.0",
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple"))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);

        long size = 32L + ":status".length() + "200".length();
        for (Map.Entry<String, String> header :
                response.getHeaders().entrySet()) {
            size += 32L + header.getKey().length() +
                    header.getValue().length();
        }
        // The mandatory Date field pushes the section over the peer's
        // advisory limit (RFC 9114 Section 4.2.2 is a SHOULD); RFC 9110
        // Section 6.6.1 requires Date for a 2xx response and the peer limit
        // cannot override that requirement.
        Assert.assertTrue("The response should be over the advisory peer "
                + "limit because the mandatory Date field is retained, "
                + "actual size " + size, size > 200);
        Assert.assertNotNull("The mandatory Date field must be retained",
                response.getHeader("date"));
        Assert.assertNotNull("content-type must be retained",
                response.getHeader("content-type"));
        Assert.assertNotNull("content-length must be retained",
                response.getHeader("content-length"));
    }


    @Test
    public void testSecurityHeadersRetainedUnderPeerFieldSectionLimit()
            throws Exception {
        startHttp3Server(TestHttp3Section_4_2::addSecurityServlet);

        // A peer advertising a tiny SETTINGS_MAX_FIELD_SECTION_SIZE must not
        // cause security-response-policy fields to be dropped from responses
        // to that peer. They are in the essential set and are retained even
        // when the resulting section exceeds the advisory limit.
        ClientOutput output = runClient(rawCommandWith(
                "--control", buildSettingsFrameB64(6, 200),
                "--headers",
                buildFieldSection(simpleGetHeaders("/security"))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNotNull("Strict-Transport-Security must be retained",
                response.getHeader("strict-transport-security"));
        Assert.assertNotNull("Content-Security-Policy must be retained",
                response.getHeader("content-security-policy"));
        Assert.assertNotNull("X-Frame-Options must be retained",
                response.getHeader("x-frame-options"));
        Assert.assertNotNull("Referrer-Policy must be retained",
                response.getHeader("referrer-policy"));
        Assert.assertNotNull("Permissions-Policy must be retained",
                response.getHeader("permissions-policy"));
        Assert.assertNotNull("Cross-Origin-Opener-Policy must be retained",
                response.getHeader("cross-origin-opener-policy"));
        Assert.assertNotNull("Cross-Origin-Embedder-Policy must be retained",
                response.getHeader("cross-origin-embedder-policy"));
        Assert.assertNotNull("Cross-Origin-Resource-Policy must be retained",
                response.getHeader("cross-origin-resource-policy"));
        Assert.assertNotNull("Content-Security-Policy-Report-Only must be "
                + "retained",
                response.getHeader("content-security-policy-report-only"));
        Assert.assertNotNull("X-XSS-Protection must be retained",
                response.getHeader("x-xss-protection"));
        Assert.assertNotNull("Age is a cache-semantics field and must be "
                + "retained", response.getHeader("age"));
        Assert.assertNotNull("Date is a mandatory response field and must be "
                + "retained even above the peer limit",
                response.getHeader("date"));
    }


    private static void addSecurityServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "security", new SecurityServlet());
        ctxt.addServletMapping("/security", "security");
    }


    private static class LengthTrailersServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            resp.setContentLength(5);
            resp.setTrailerFields(() -> Map.of("x-test-trailer", "test"));
            resp.getOutputStream().write("body!".getBytes(
                    StandardCharsets.ISO_8859_1));
        }
    }


    private static class StatusServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setStatus(Integer.parseInt(req.getParameter("code")));
            resp.setContentType("text/plain");
            resp.getWriter().print("body");
        }
    }


    private static class StatusContentLengthServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setStatus(Integer.parseInt(req.getParameter("code")));
            resp.setContentLength(10);
        }
    }


    private static class SecurityServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setHeader("Strict-Transport-Security", "max-age=31536000");
            resp.setHeader("Content-Security-Policy", "default-src 'self'");
            resp.setHeader("X-Frame-Options", "DENY");
            resp.setHeader("Referrer-Policy", "no-referrer");
            resp.setHeader("Permissions-Policy", "camera=()");
            resp.setHeader("Cross-Origin-Opener-Policy", "same-origin");
            resp.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
            resp.setHeader("Cross-Origin-Resource-Policy", "same-origin");
            resp.setHeader("Content-Security-Policy-Report-Only",
                    "default-src 'self'");
            resp.setHeader("X-XSS-Protection", "1; mode=block");
            resp.setHeader("Age", "42");
            resp.getWriter().print("security");
        }
    }
}

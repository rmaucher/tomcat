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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;

/**
 * Tests for the request message requirements of
 * <a href="https://www.rfc-editor.org/rfc/rfc9114#section-4.1">RFC 9114
 * Section 4.1</a>.
 */
public class TestHttp3Section_4_1 extends Http3TestBase {

    @Test
    public void testValidRequest() throws Exception {
        startHttp3Server();

        Http3Response response = get("/simple");

        validateStatus(response, 200);
        Assert.assertEquals("Hello over HTTP/3", response.getBodyAsString());
    }


    @Test
    public void testMissingMethod() throws Exception {
        startHttp3Server();

        ClientOutput output = rawRequest(":scheme", "https",
                ":authority", "127.0.0.1:" + port, ":path", "/simple");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testMissingScheme() throws Exception {
        startHttp3Server();

        ClientOutput output = rawRequest(":method", "GET",
                ":authority", "127.0.0.1:" + port, ":path", "/simple");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testMissingPath() throws Exception {
        startHttp3Server();

        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":authority", "127.0.0.1:" + port);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testEmptyPath() throws Exception {
        startHttp3Server();

        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testEmptyHeadersFrameRejected() throws Exception {
        startHttp3Server();

        // A zero-length HEADERS frame cannot carry a valid field section
        // (a request must at least contain the :method pseudo-header), so
        // it is a malformed message and must be reset immediately rather
        // than ignored and waited on.
        ClientOutput output = runClient(
                rawCommandWith("--frame", buildFrameB64(0x01, new byte[0])),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testEmptyTrailerSectionRejected() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);

        // The same rule applies to a zero-length trailer section: it must
        // raise a stream error of type H3_MESSAGE_ERROR rather than
        // silently completing the request.
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho", "content-length", "5");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body!".getBytes(StandardCharsets.UTF_8)),
                        "--frame-after-data",
                                buildFrameB64(0x01, new byte[0])),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testPseudoHeaderInTrailerSectionRejected() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);

        // RFC 9114 Section 4.3: pseudo-header fields MUST NOT appear in
        // trailer sections. The request field section carries nothing but
        // pseudo-headers, so the ordering gate (a pseudo-header after a
        // regular field) can never fire: the rejection must come from the
        // trailer-mode gate itself. :protocol is used because the four
        // request pseudo-headers would be caught by the duplicate gate
        // instead, masking the hole.
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho");
        String trailers = buildFieldSection(":protocol", "websocket");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body!".getBytes(StandardCharsets.UTF_8)),
                        "--trailers", trailers),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testNonHttpSchemeAcceptedWhenMismatchAllowed() throws Exception {
        startHttp3Server();
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAllowSchemeMismatch(true);

        // RFC 9114 Section 4.3.1: the :scheme pseudo-header is not
        // restricted to "http" and "https"; any (valid) scheme must be
        // accepted for non-CONNECT requests. QUIC always uses TLS, so a
        // non-https scheme is a scheme/TLS mismatch that the connector
        // policy (allowSchemeMismatch) must permit.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "ftp", ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testNonHttpSchemeRejectedByDefault() throws Exception {
        startHttp3Server();

        // By default (allowSchemeMismatch=false), a scheme that is
        // inconsistent with the connector's TLS state is rejected, as the
        // HTTP/2 connector does.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "ftp", ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testHttpSchemeRejectedByDefault() throws Exception {
        startHttp3Server();

        // QUIC always uses TLS: with the default allowSchemeMismatch=false
        // the connector must reject an "http" scheme, mirroring HTTP/2's
        // stream.header.inconsistentScheme check.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "http", ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testHttpSchemeAcceptedWhenMismatchAllowed() throws Exception {
        startHttp3Server();
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAllowSchemeMismatch(true);

        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "http", ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testInvalidSchemeRejected() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.3.1 points the :scheme pseudo-header at the
        // scheme portion of the URI (RFC 3986 grammar); a value that is not
        // a valid scheme is an invalid pseudo-header value and the message
        // is malformed (same HttpParser.isScheme check as HTTP/2).
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "ht!tp", ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testSchemeStartingWithDigitRejected() throws Exception {
        startHttp3Server();

        // RFC 3986: a scheme must start with a letter.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "1https", ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRequestTargetWithBackslashRejected() throws Exception {
        startHttp3Server();

        // RFC 9110 Section 7.1 / HTTP/2 pre-dispatch whitelist: the
        // backslash is outside the request-target character set (it must
        // not reach the mapper to be mistaken for a separator).
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "/foo\\bar");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRequestTargetWithSpaceRejected() throws Exception {
        startHttp3Server();

        // A space in the :path value is valid field-content (so it passes
        // value validation) but not a valid request-target character.
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "/foo bar");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testQueryWithInvalidCharacterRejected() throws Exception {
        startHttp3Server();

        // '<' is valid field-content but outside the query character set
        // (same isQueryRelaxed whitelist HTTP/2 applies before dispatch).
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "/echo?a=<b>");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testDuplicatePseudoHeader() throws Exception {
        startHttp3Server();

        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "/simple", ":path", "/simple");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testPseudoHeaderAfterRegularHeader() throws Exception {
        startHttp3Server();

        // The field section :method GET, x-test: value, :path /simple.
        // It is built with pylsqpack (the QPACK implementation used by
        // the client) because the production QPACK encoder re-orders
        // field section entries (pseudo headers first).
        ClientOutput output = runClient(rawCommandWith("--headers",
                "AADRLfKySoT/hO46LS9RhWEGproL"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testNonTokenMethodRejected() throws Exception {
        startHttp3Server();

        // RFC 9110 Section 9 / RFC 9114 Section 4.1.2: a :method value that
        // is not a token is an invalid pseudo-header value; the message is
        // malformed (it is a syntax violation, not an unknown method).
        ClientOutput output = rawRequest(":method", "GE T",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testUnknownTokenMethodYieldsNotImplemented() throws Exception {
        startHttp3Server();

        // A syntactically valid method token the server does not implement
        // is passed to the container, which responds (RFC 9110 Section
        // 15.6.1) with 501 Not Implemented.
        ClientOutput output = rawRequest(":method", "BREW",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        Http3Response response = output.getResponse();
        validateStatus(response, 501);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testLowercaseConnectMethodIsUnknownMethod() throws Exception {
        startHttp3Server();

        // RFC 9110 Section 9.1: methods are case-sensitive. ":method
        // connect" is an unknown method token, not CONNECT: with the
        // normal :scheme/:path shape it must be dispatched to the
        // container (501), not subjected to the CONNECT pseudo-header
        // checks and rejected as malformed.
        ClientOutput output = rawRequest(":method", "connect",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        Http3Response response = output.getResponse();
        validateStatus(response, 501);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testConnectSchemeNotWildcard() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.4: CONNECT must omit :scheme entirely; any
        // value (including "https" or the legacy "*" convention) is a
        // malformed request.
        ClientOutput output = rawRequest(":method", "CONNECT",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "*");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testConnectWithPath() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.4: CONNECT must omit both :scheme and :path.
        ClientOutput output = rawRequest(":method", "CONNECT",
                ":authority", "127.0.0.1:" + port,
                ":path", "/simple");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testConnectMissingAuthority() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.4: CONNECT requires :authority.
        ClientOutput output = rawRequest(":method", "CONNECT");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testConnectNotImplemented() throws Exception {
        startHttp3Server();

        // A conformant RFC 9114 Section 4.4 CONNECT (no :scheme, no :path,
        // :authority present) reaches the container, which responds 501
        // since tunneling is not implemented.
        ClientOutput output = rawRequest(":method", "CONNECT",
                ":authority", "127.0.0.1:" + port);

        Http3Response response = output.getResponse();
        validateStatus(response, 501);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testConnectProtocolPseudoHeader() throws Exception {
        startHttp3Server();

        ClientOutput output = rawRequest(":method", "CONNECT",
                ":scheme", "*", ":authority", "127.0.0.1:" + port,
                ":protocol", "webtransport");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testExtendedConnectWithoutSettingRejected() throws Exception {
        startHttp3Server();

        // RFC 9220 Section 3.2: :protocol must not be sent unless the
        // server advertised ENABLE_CONNECT_PROTOCOL. It is not enabled by
        // default, so the request must be rejected.
        ClientOutput output = rawRequest(":method", "CONNECT",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":protocol", "websocket");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testExtendedConnectMissingPathRejected() throws Exception {
        startHttp3Server();
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setEnableConnectProtocol(true);

        // RFC 8441 Section 4 (inherited by RFC 9220 Section 3): an extended
        // CONNECT must include :scheme and :path alongside :protocol. The
        // :path identifies the targeted resource; without it the request
        // cannot be routed and is malformed.
        ClientOutput output = rawRequest(":method", "CONNECT",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":protocol", "websocket");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testExtendedConnectWithPathAccepted() throws Exception {
        startHttp3Server();
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setEnableConnectProtocol(true);

        // RFC 9220 Section 3 / RFC 8441 Section 4: the extended CONNECT
        // includes :scheme and :path like a normal request; the :path
        // identifies the resource the extended CONNECT is targeted at. The
        // request must be dispatched, not rejected as malformed.
        ClientOutput output = rawRequest(":method", "CONNECT",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":protocol", "websocket", ":path", "/simple");

        Http3Response response = output.getResponse();
        validateStatus(response, 501);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testExtendedConnectMissingSchemeRejected() throws Exception {
        startHttp3Server();
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setEnableConnectProtocol(true);

        // RFC 9220 Section 3.1: extended CONNECT must include :scheme
        // alongside :protocol.
        ClientOutput output = rawRequest(":method", "CONNECT",
                ":authority", "127.0.0.1:" + port,
                ":protocol", "websocket");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testProtocolOnNonConnectRejected() throws Exception {
        startHttp3Server();
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setEnableConnectProtocol(true);

        // RFC 9220 Section 3: :protocol is only defined for CONNECT. Even
        // with the setting enabled, a GET carrying :protocol is malformed
        // (RFC 9114 Section 4.3).
        ClientOutput output = rawRequest(":method", "GET",
                ":scheme", "https", ":authority", "127.0.0.1:" + port,
                ":path", "/simple", ":protocol", "websocket");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testConnectionHeaderRejected() throws Exception {
        startHttp3Server();

        ClientOutput output = rawGet("/simple", "connection", "close");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testTeHeaderWithoutTrailersRejected() throws Exception {
        startHttp3Server();

        ClientOutput output = rawGet("/simple", "te", "gzip");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testTeHeaderWithTrailersAccepted() throws Exception {
        startHttp3Server();

        ClientOutput output = rawGet("/simple", "te", "trailers");

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testTransferEncodingHeaderRejected() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.1/4.2: Transfer-Encoding MUST NOT be used;
        // a message containing it is malformed.
        ClientOutput output = rawGet("/simple", "transfer-encoding",
                "chunked");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testKeepAliveHeaderRejected() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.2: keep-alive is a connection-specific field;
        // a message containing it is malformed.
        ClientOutput output = rawGet("/simple", "keep-alive", "timeout=5");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testProxyConnectionHeaderRejected() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.2: proxy-connection is a connection-specific
        // field; a message containing it is malformed.
        ClientOutput output = rawGet("/simple", "proxy-connection",
                "keep-alive");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testUpgradeHeaderRejected() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.2: upgrade is a connection-specific field;
        // a message containing it is malformed.
        ClientOutput output = rawGet("/simple", "upgrade", "websocket");

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testRequestWithBody() throws Exception {
        startHttp3Server();

        Http3Response response = request("POST", "/echo",
                "12345".getBytes(StandardCharsets.ISO_8859_1), null);

        validateStatus(response, 200);
        Assert.assertTrue("Expected the echoed request body in:\n"
                + response.getBodyAsString(),
                response.getBodyAsString().contains("BODY: 5:12345"));
    }


    @Test
    public void testStreamedBodyShorterThanContentLengthRejected()
            throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.1.2: a request whose DATA frames total less
        // than the declared Content-Length is malformed (H3_MESSAGE_ERROR).
        // The body crosses the pre-buffering bound, so the short total is
        // only observable on the streaming read path at stream end (FIN):
        // the reset must happen there, not be reported as a complete body.
        byte[] body = new byte[64 * 1024];
        Arrays.fill(body, (byte) 'a');
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length", "70000"),
                "--data", Base64.getEncoder().encodeToString(body),
                "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testTrailersAfterShortBodyRejected() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);

        // RFC 9114 Section 4.1.2 again: the trailer section ends the
        // message, which makes the body shortfall observable as soon as
        // the (otherwise valid) trailer section completes - even
        // pre-dispatch, before any streaming read of the body.
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho", "content-length", "10");
        String trailers = buildFieldSection("x-checksum", "abc123");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body!".getBytes(StandardCharsets.UTF_8)),
                        "--trailers", trailers),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testTrailersAfterShortBodyStreamRejected() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);

        // The same short-body trailer case, with the body crossing the
        // pre-buffering bound so the trailer section completes on the
        // streaming read path instead of the pre-dispatch read.
        byte[] body = new byte[64 * 1024];
        Arrays.fill(body, (byte) 'a');
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho", "content-length", "70000");
        String trailers = buildFieldSection("x-checksum", "abc123");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(body),
                        "--trailers", trailers,
                        "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testTrailingDataAfterTrailerConnectionError() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);

        // RFC 9114 Section 4.1: a DATA or HEADERS frame after the trailing
        // HEADERS frame is an invalid frame sequence and MUST be treated as
        // a connection error of type H3_FRAME_UNEXPECTED. The trailing DATA
        // frame is sent in the same flight (before any FIN), so the server
        // observes it after the trailer section and must fail the
        // connection rather than discard the frame silently at stream
        // teardown. The response itself is unaffected (already sent).
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho", "content-length", "5");
        String trailers = buildFieldSection("x-checksum", "abc123");
        byte[] extra = "trailing".getBytes(StandardCharsets.UTF_8);
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body!".getBytes(StandardCharsets.UTF_8)),
                        "--frame-after-data", buildFrameB64(0x01,
                                Base64.getDecoder().decode(trailers)),
                        "--frame-after-data", buildFrameB64(0x00, extra),
                        "--no-fin",
                        "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        Assert.assertEquals("Expected connection error H3_FRAME_UNEXPECTED, "
                        + "got " + output.getConnectionError(),
                Integer.valueOf(H3_FRAME_UNEXPECTED),
                output.getConnectionError());
    }


    @Test
    public void testTrailingHeadersAfterTrailerConnectionError()
            throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);

        // RFC 9114 Section 4.1 again, for a second HEADERS (trailer) frame
        // after the trailer section: a connection error of type
        // H3_FRAME_UNEXPECTED.
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho", "content-length", "5");
        String trailers = buildFieldSection("x-checksum", "abc123");
        String second = buildFieldSection("x-second", "after");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body!".getBytes(StandardCharsets.UTF_8)),
                        "--frame-after-data", buildFrameB64(0x01,
                                Base64.getDecoder().decode(trailers)),
                        "--frame-after-data", buildFrameB64(0x01,
                                Base64.getDecoder().decode(second)),
                        "--no-fin",
                        "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        Assert.assertEquals("Expected connection error H3_FRAME_UNEXPECTED, "
                        + "got " + output.getConnectionError(),
                Integer.valueOf(H3_FRAME_UNEXPECTED),
                output.getConnectionError());
    }


    @Test
    public void testTrailingHeadersAfterTrailerConnectionErrorAsync()
            throws Exception {
        startHttp3Server(this::addAsyncTrailerEchoServlet);

        // RFC 9114 Section 4.1 again, for a request that completes
        // asynchronously: service() returns LONG before the synchronous
        // post-trailer scan can run, so the scan must also be performed on
        // the async completion path (dispatchEndRequest()). The extra
        // HEADERS frame after the trailer section must fail the connection
        // with H3_FRAME_UNEXPECTED there too, not be discarded silently
        // when the concluded stream is torn down.
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/asynctrailerecho", "content-length", "5");
        String trailers = buildFieldSection("x-checksum", "abc123");
        String second = buildFieldSection("x-second", "after");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body!".getBytes(StandardCharsets.UTF_8)),
                        "--frame-after-data", buildFrameB64(0x01,
                                Base64.getDecoder().decode(trailers)),
                        "--frame-after-data", buildFrameB64(0x01,
                                Base64.getDecoder().decode(second)),
                        "--no-fin",
                        "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        Assert.assertEquals("Expected connection error H3_FRAME_UNEXPECTED, "
                        + "got " + output.getConnectionError(),
                Integer.valueOf(H3_FRAME_UNEXPECTED),
                output.getConnectionError());
    }


    @Test
    public void testRequestTrailers() throws Exception {
        startHttp3Server();

        // Request trailers are sent in a second HEADERS frame. The
        // server does not expose them to the servlet but must not treat
        // the request as malformed.
        Http3Response response = request("POST", "/echo", null,
                new String[] { "x-test-trailer", "test" });

        validateStatus(response, 200);
    }


    @Test
    public void testAllowedRequestTrailerSurfacedWithBody() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAllowedTrailerHeaders("x-checksum");

        // A body larger than zero means the trailer section is read by the
        // streaming body path rather than the pre-dispatch read.
        Http3Response response = request("POST", "/trailerecho",
                "checksum-payload".getBytes(StandardCharsets.UTF_8),
                new String[] { "x-checksum", "abc123" });

        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected ready=true in:\n" + body,
                body.contains("ready=true"));
        Assert.assertTrue("Expected the trailer in:\n" + body,
                body.contains("x-checksum=abc123"));
    }


    @Test
    public void testAllowedRequestTrailerSurfacedEmptyBody() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAllowedTrailerHeaders("x-checksum");

        // No body: the trailer section follows the request headers
        // immediately and is consumed by the pre-dispatch read.
        Http3Response response = request("POST", "/trailerecho", null,
                new String[] { "x-checksum", "abc123" });

        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected ready=true in:\n" + body,
                body.contains("ready=true"));
        Assert.assertTrue("Expected the trailer in:\n" + body,
                body.contains("x-checksum=abc123"));
    }


    @Test
    public void testAllowedCookieTrailerJoinedIntoRequestHeaders()
            throws Exception {
        startHttp3Server(this::addCookieEchoServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAllowedTrailerHeaders("cookie");

        // A trailer field named cookie is processed like any cookie field:
        // the cookie case of emitHeader is not gated on trailer mode (as in
        // HTTP/2's Stream.emitHeader), so the values are joined with "; ".
        // HTTP/2 flushes the joined value into the regular request headers
        // at the end of every field section, trailer sections included
        // (Stream.receivedEndOfHeaders via Http2UpgradeHandler.headersEnd);
        // the same must happen when the trailer section completes here.
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/cookieecho", "content-length", "4");
        String trailers = buildFieldSection("cookie", "a=1", "cookie",
                "b=2");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body".getBytes(StandardCharsets.UTF_8)),
                        "--trailers", trailers),
                CLIENT_TIMEOUT_SECONDS);

        validateStatus(output.getResponse(), 200);
        String body = output.getResponse().getBodyAsString();
        Assert.assertTrue("Expected the joined trailer cookie in:\n" + body,
                body.contains("cookie=a=1; b=2"));
    }


    @Test
    public void testRequestTrailerDroppedWhenNotAllowed() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);

        // Default configuration: the trailer allow-list is empty, so every
        // trailer field must be dropped (same behavior as HTTP/2). The
        // request itself is not malformed.
        Http3Response response = request("POST", "/trailerecho",
                "checksum-payload".getBytes(StandardCharsets.UTF_8),
                new String[] { "x-checksum", "abc123" });

        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected ready=true in:\n" + body,
                body.contains("ready=true"));
        Assert.assertFalse("Trailer should not be exposed: " + body,
                body.contains("x-checksum"));
    }


    @Test
    public void testAllowedContentLengthTrailerHitsDuplicateCheck()
            throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAllowedTrailerHeaders("content-length");

        // A content-length permitted via allowedTrailerHeaders is processed
        // by the content-length case of emitHeader like any other
        // content-length field: emitHeader gates no special case on the
        // trailer state (HTTP/2's Stream.emitHeader gates none either), so
        // the trailer's re-declaration of the head's content-length is the
        // duplicate Content-Length malformed message of RFC 9114 Section
        // 4.2. Allowing the field as a trailer is an operator choice via
        // allowedTrailerHeaders, and its consequences are part of that
        // choice.
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho", "content-length", "5");
        String trailers = buildFieldSection("content-length", "99");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body!".getBytes(StandardCharsets.UTF_8)),
                        "--trailers", trailers),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testAllowedContentLengthTrailerInstallsFraming()
            throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setAllowedTrailerHeaders("content-length");

        // Same for a request whose head carried no content-length: the
        // trailer is processed like any content-length field (no
        // trailer-mode gate in emitHeader), so it installs a framing
        // declaration after the body was already complete; the shortfall
        // against the declared length is then the malformed message of
        // RFC 9114 Section 4.1.2 (stream reset). A misconfigured
        // allowedTrailerHeaders takes effect, as in HTTP/2.
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho");
        String trailers = buildFieldSection("content-length", "5");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--trailers", trailers),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testPseudoHeaderInTrailerRejected() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);

        // RFC 9114 Section 4.3: pseudo-header fields MUST NOT appear in
        // trailer sections; a request that contains one is malformed
        // (H3_MESSAGE_ERROR stream error).
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho", "content-length", "5");
        String trailers = buildFieldSection(":method", "GET");
        ClientOutput output = runClient(
                rawCommandWith("--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body!".getBytes(StandardCharsets.UTF_8)),
                        "--trailers", trailers),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testBlockedTrailerSectionWaitsForInserts() throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);
        AbstractHttp3Protocol protocol =
                (AbstractHttp3Protocol) connector.getProtocolHandler();
        protocol.setQpackBlockedStreams(4);
        protocol.setAllowedTrailerHeaders("x-blocked-header");

        // RFC 9204 Section 2.2.2.1 makes trailer sections a
        // multiple-field-sections-per-stream case, so a trailer that
        // references in-flight dynamic table entries is ordinary blocked
        // behaviour (Section 2.2.1): with qpackBlockedStreams above zero
        // (advertised via SETTINGS_QPACK_BLOCKED_STREAMS) the trailer
        // section must go through the same bounded wait-and-re-decode as
        // a request field section, not fail the connection.
        ByteBuffer encoder = ByteBuffer.allocate(64);
        Qpack.encodeIrp(encoder, 0x20, 5, 512);
        insertLiteral(encoder, "x-blocked-header", "unblocked-value");

        // Trailer section: Required Insert Count 1 (encoded 2, RFC 9204
        // Section 4.5.1.1), Sign 0 / Delta Base 0, one dynamic reference
        // that cannot resolve until the encoder stream delivers the
        // insert one second after the request.
        ByteBuffer trailers = ByteBuffer.allocate(16);
        Qpack.encodeIrp(trailers, 0, 8, 2);
        Qpack.encodeIrp(trailers, 0, 7, 0);
        Qpack.encodeIrp(trailers, 0x80, 6, 0);

        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho", "content-length", "5");
        long start = System.currentTimeMillis();
        ClientOutput output = runClient(
                rawCommandWith("--encoder", b64(encoder),
                        "--encoder-after-request", "1.0",
                        "--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                "body!".getBytes(StandardCharsets.UTF_8)),
                        "--trailers", b64(trailers),
                        "--wait", "2"),
                CLIENT_TIMEOUT_SECONDS);
        long elapsed = System.currentTimeMillis() - start;

        Assert.assertNull("A conformant blocked trailer must not fail the "
                        + "connection: " + output.getLines(),
                output.getConnectionError());
        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected the blocked trailer after unblocking, "
                        + "body was: " + body,
                body.contains("x-blocked-header=unblocked-value"));
        // The response can only have been produced after the encoder
        // stream delivered the insert one second after the request.
        Assert.assertTrue("Response arrived after " + elapsed
                + " ms, expected at least the 1 s encoder delay",
                elapsed >= 800);
    }


    @Test
    public void testBlockedTrailerSectionWaitsOnStreamingPath()
            throws Exception {
        startHttp3Server(this::addTrailerEchoServlet);
        AbstractHttp3Protocol protocol =
                (AbstractHttp3Protocol) connector.getProtocolHandler();
        protocol.setQpackBlockedStreams(4);
        protocol.setAllowedTrailerHeaders("x-blocked-header");

        // The same blocked trailer, with a body beyond the pre-dispatch
        // buffering bound so the trailer section is completed and decoded
        // by the streaming read path instead.
        ByteBuffer encoder = ByteBuffer.allocate(64);
        Qpack.encodeIrp(encoder, 0x20, 5, 512);
        insertLiteral(encoder, "x-blocked-header", "unblocked-value");

        ByteBuffer trailers = ByteBuffer.allocate(16);
        Qpack.encodeIrp(trailers, 0, 8, 2);
        Qpack.encodeIrp(trailers, 0, 7, 0);
        Qpack.encodeIrp(trailers, 0x80, 6, 0);

        byte[] bodyBytes = new byte[70000];
        Arrays.fill(bodyBytes, (byte) 'a');
        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/trailerecho", "content-length", "70000");
        long start = System.currentTimeMillis();
        ClientOutput output = runClient(
                rawCommandWith("--encoder", b64(encoder),
                        "--encoder-after-request", "1.0",
                        "--headers", initial,
                        "--data", Base64.getEncoder().encodeToString(
                                bodyBytes),
                        "--trailers", b64(trailers),
                        "--timeout", "10",
                        "--wait", "2"),
                CLIENT_TIMEOUT_SECONDS);
        long elapsed = System.currentTimeMillis() - start;

        Assert.assertNull("A conformant blocked trailer must not fail the "
                        + "connection: " + output.getLines(),
                output.getConnectionError());
        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected the blocked trailer after unblocking, "
                        + "body was: " + body,
                body.contains("x-blocked-header=unblocked-value"));
        Assert.assertTrue("Response arrived after " + elapsed
                + " ms, expected at least the 1 s encoder delay",
                elapsed >= 800);
    }


    /*
     * Base64 of a flipped buffer's contents.
     */
    private static String b64(ByteBuffer buffer) {
        buffer.flip();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }


    /*
     * Encoder instruction: Insert With Literal Name (RFC 9204 Section
     * 4.3.3, 01 H NameLen(5+)).
     */
    private static void insertLiteral(ByteBuffer target, String name,
            String value) {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        Qpack.encodeIrp(target, 0x40, 5, nameBytes.length);
        target.put(nameBytes);
        byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
        Qpack.encodeIrp(target, 0, 7, valueBytes.length);
        target.put(valueBytes);
    }


    @Test
    public void testServerTrailerInvalidNamesDropped() throws Exception {
        startHttp3Server();

        // Response trailers built directly from the servlet-supplied trailer
        // map (setTrailerFields, unlike addHeader) bypass the container's
        // header-name filtering. A field whose name is not a valid token
        // (empty, contains a space) must be dropped rather than reaching
        // the QPACK encode path (where it used to abort the response mid
        // flight); the valid trailer and the body must still arrive.
        Http3Response response = get("/trailersInvalid");

        validateStatus(response, 200);
        Assert.assertEquals("body", response.getBodyAsString());
        Assert.assertEquals("valid",
                response.getTrailer("x-valid-trailer"));
    }


    private void addTrailerEchoServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "trailerecho", new TrailerEchoServlet());
        ctxt.addServletMapping("/trailerecho", "trailerecho");
    }


    private void addAsyncTrailerEchoServlet(Context ctxt) {
        Wrapper w = Tomcat.addServlet(ctxt, "asynctrailerecho",
                new AsyncTrailerEchoServlet());
        w.setAsyncSupported(true);
        ctxt.addServletMapping("/asynctrailerecho", "asynctrailerecho");
    }


    private static class AsyncTrailerEchoServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            // Suspend and complete from another thread so the request
            // really takes the async path: service() sees isAsync(),
            // returns LONG, and the stream concludes through
            // dispatchEndRequest(). The short delay keeps the suspension
            // observable while service() checks for async.
            AsyncContext asyncContext = req.startAsync();
            asyncContext.start(() -> {
                try {
                    // Reading the body to its end decodes the trailer
                    // section.
                    req.getInputStream().readAllBytes();
                    Thread.sleep(200);
                    resp.setContentType("text/plain");
                    resp.setCharacterEncoding("UTF-8");
                    resp.getWriter().write(
                            "ready=" + req.isTrailerFieldsReady());
                    asyncContext.complete();
                } catch (IOException | InterruptedException e) {
                    throw new IllegalStateException(e);
                }
            });
        }
    }


    private void addCookieEchoServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "cookieecho", new CookieEchoServlet());
        ctxt.addServletMapping("/cookieecho", "cookieecho");
    }


    private static class CookieEchoServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            // Reading the body to its end decodes the trailer section.
            req.getInputStream().readAllBytes();
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().write("cookie=" + req.getHeader("cookie") +
                    ";ready=" + req.isTrailerFieldsReady());
        }
    }


    private static class TrailerEchoServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;


        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            doPost(req, resp);
        }


        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            // The trailer fields are only available once the request body
            // has been fully read.
            req.getInputStream().readAllBytes();

            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            StringBuilder body = new StringBuilder();
            body.append("ready=").append(req.isTrailerFieldsReady());
            req.getTrailerFields().forEach(
                    (name, value) -> body.append(';').append(name).append('=').append(value));
            resp.getWriter().write(body.toString());
        }
    }
}

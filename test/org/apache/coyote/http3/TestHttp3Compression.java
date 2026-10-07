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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;
import java.util.zip.GZIPInputStream;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;

/**
 * Tests for response compression over HTTP/3. The decision logic is the
 * shared {@code org.apache.coyote.CompressionConfig} used by HTTP/1.1 and
 * HTTP/2, so the tests concentrate on the HTTP/3 specifics: the DATA framed
 * gzip body must round-trip through the client, the body framing (no
 * Content-Length once compression is on, no DATA frames for body-less
 * responses) must be correct, and the gzip member must be concluded before
 * any trailers and the stream FIN. HTTP/3 forbids the Transfer-Encoding
 * header (RFC 9114 Section 4.2), which is also why the connector rejects
 * requests carrying a TE header (except {@code te: trailers}) before the
 * compression decision is ever reached.
 */
public class TestHttp3Compression extends Http3TestBase {

    /*
     * Deterministic body generator: the servlet and the test produce the
     * same bytes from the same seed so the response can be compared after
     * decompression. Digits compress to roughly 40% of their size which
     * keeps large bodies comfortably above the DATA frame size.
     */
    private static byte[] body(int n) {
        Random random = new Random(20260928);
        byte[] result = new byte[n];
        for (int i = 0; i < n; i++) {
            result[i] = (byte) ('0' + random.nextInt(10));
        }
        return result;
    }

    private static final byte[] LARGE_BODY = body(4096);
    private static final byte[] SMALL_BODY = body(100);

    private Connector connector;


    private Connector startCompressionServer() throws Exception {
        connector = startHttp3Server(this::registerServlets);
        return connector;
    }


    private void setCompression(String compression) {
        Assert.assertTrue(connector.setProperty("compression", compression));
    }


    private void registerServlets(Context ctxt) {
        Tomcat.addServlet(ctxt, "gen", new GenServlet());
        ctxt.addServletMapping("/gen", "gen");
        Tomcat.addServlet(ctxt, "empty", new EmptyServlet());
        ctxt.addServletMapping("/empty", "empty");
        Tomcat.addServlet(ctxt, "noBody", new NoBodyServlet());
        ctxt.addServletMapping("/noBody", "noBody");
        Tomcat.addServlet(ctxt, "flushing", new FlushingServlet());
        ctxt.addServletMapping("/flushing", "flushing");
    }


    private Http3Response getCompressed(String path, String... extraHeaders) {
        String[] headers = new String[extraHeaders.length + 2];
        headers[0] = "accept-encoding";
        headers[1] = "gzip";
        System.arraycopy(extraHeaders, 0, headers, 2, extraHeaders.length);
        return get(path, headers);
    }


    private void assertCompressed(Http3Response response, byte[] expected)
            throws IOException {
        validateStatus(response, 200);
        Assert.assertEquals("gzip", response.getHeader("content-encoding"));
        Assert.assertArrayEquals(expected,
                gunzip(response.getBody()));
    }


    private void assertNotCompressed(Http3Response response, byte[] expected) {
        validateStatus(response, 200);
        Assert.assertNull("Response must not be compressed",
                response.getHeader("content-encoding"));
        Assert.assertArrayEquals(expected, response.getBody());
    }


    private static byte[] gunzip(byte[] body) throws IOException {
        try (GZIPInputStream in =
                new GZIPInputStream(new ByteArrayInputStream(body))) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }


    // ------------------------------------------------------------- tests


    @Test
    public void testCompressionOffByDefault() throws Exception {
        startCompressionServer();

        Http3Response response = getCompressed("/gen?n=4096");

        assertNotCompressed(response, LARGE_BODY);
        // Without compression the declared length is reported.
        Assert.assertEquals("4096", response.getHeader("content-length"));
    }


    @Test
    public void testCompressionOnCompresses() throws Exception {
        startCompressionServer();
        setCompression("on");

        Http3Response response = getCompressed("/gen?n=4096");

        assertCompressed(response, LARGE_BODY);
        // The compressed length is unknown: no Content-Length header.
        Assert.assertNull(response.getHeader("content-length"));
        Assert.assertEquals("accept-encoding", response.getHeader("vary"));
    }


    @Test
    public void testBelowMinSizeNotCompressed() throws Exception {
        startCompressionServer();
        setCompression("on");

        Http3Response response = getCompressed("/gen?n=100");

        assertNotCompressed(response, SMALL_BODY);
    }


    @Test
    public void testMinSizeAttribute() throws Exception {
        startCompressionServer();
        setCompression("on");
        Assert.assertTrue(connector.setProperty("compressionMinSize", "64"));

        Http3Response response = getCompressed("/gen?n=100");

        assertCompressed(response, SMALL_BODY);
    }


    @Test
    public void testNoAcceptEncodingNotCompressed() throws Exception {
        startCompressionServer();
        setCompression("on");

        Http3Response response = get("/gen?n=4096");

        assertNotCompressed(response, LARGE_BODY);
    }


    @Test
    public void testNonCompressibleMimeTypeNotCompressed() throws Exception {
        startCompressionServer();
        setCompression("on");

        Http3Response response = getCompressed("/gen?n=4096&type=image/png");

        assertNotCompressed(response, LARGE_BODY);
    }


    @Test
    public void testCompressibleMimeTypeOverride() throws Exception {
        startCompressionServer();
        setCompression("on");
        Assert.assertTrue(
                connector.setProperty("compressibleMimeType", "image/png"));

        Http3Response response = getCompressed("/gen?n=4096&type=image/png");

        assertCompressed(response, LARGE_BODY);
    }


    @Test
    public void testForceCompressesEverything() throws Exception {
        startCompressionServer();
        setCompression("force");

        // Small and normally not compressible: force skips both checks.
        Http3Response response = getCompressed("/gen?n=100&type=image/png");

        assertCompressed(response, SMALL_BODY);
    }


    @Test
    public void testStrongETagNotCompressed() throws Exception {
        startCompressionServer();
        setCompression("on");

        // The quote characters must be percent-encoded in the query string;
        // the container decodes them back for the servlet.
        Http3Response response =
                getCompressed("/gen?n=4096&etag=%22abc%22");

        assertNotCompressed(response, LARGE_BODY);
    }


    @Test
    public void testWeakETagCompressed() throws Exception {
        startCompressionServer();
        setCompression("on");

        Http3Response response =
                getCompressed("/gen?n=4096&etag=W/%22abc%22");

        assertCompressed(response, LARGE_BODY);
    }


    @Test
    public void testAlreadyEncodedNotDoubleCompressed() throws Exception {
        startCompressionServer();
        setCompression("on");

        Http3Response response = getCompressed("/gen?n=4096&enc=br");

        // The application-declared encoding stands untouched: the server
        // neither adds a second encoding nor rewrites the body.
        validateStatus(response, 200);
        Assert.assertEquals("br", response.getHeader("content-encoding"));
        Assert.assertArrayEquals(LARGE_BODY, response.getBody());
        // Compression bailed out before touching the declared length.
        Assert.assertEquals("4096", response.getHeader("content-length"));
    }


    @Test
    public void testNoCompressionUserAgents() throws Exception {
        startCompressionServer();
        setCompression("on");
        Assert.assertTrue(
                connector.setProperty("noCompressionUserAgents", "curl.*"));

        assertNotCompressed(
                getCompressed("/gen?n=4096", "user-agent", "curl/8.0"),
                LARGE_BODY);
        assertCompressed(
                getCompressed("/gen?n=4096", "user-agent", "testclient"),
                LARGE_BODY);
    }


    @Test
    public void testTeGzipRejectedBeforeCompression() throws Exception {
        // The TE header is connection-specific: the connector rejects it
        // with H3_MESSAGE_ERROR (RFC 9114 Section 4.2) unless its value is
        // "trailers". A request asking for gzip through TE therefore never
        // reaches the compression logic, which is what keeps the
        // Transfer-Encoding header CompressionConfig would add for such a
        // request off the wire (the protocol layer's guard makes the same
        // choice for safety).
        startCompressionServer();
        setCompression("on");

        List<String> command = clientCommand("get", "127.0.0.1",
                Integer.toString(port), "/gen?n=4096");
        command.add("--header");
        command.add("te: gzip");
        ClientOutput output = runClient(command, CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testTeWithoutGzipStillCompresses() throws Exception {
        startCompressionServer();
        setCompression("on");

        Http3Response response =
                getCompressed("/gen?n=4096", "te", "trailers");

        assertCompressed(response, LARGE_BODY);
    }


    @Test
    public void testHeadNotCompressed() throws Exception {
        startCompressionServer();
        setCompression("on");

        // Raw mode: the aioquic client mode rejects HEAD responses that
        // carry a Content-Length without a body.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "HEAD", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/gen?n=4096", "accept-encoding", "gzip")),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(response.getHeader("content-encoding"));
        Assert.assertEquals(0, response.getBody().length);
    }


    @Test
    public void testNoBodyStatusNotCompressed() throws Exception {
        startCompressionServer();
        // force: compression would apply if the status had a body.
        setCompression("force");

        Http3Response response = getCompressed("/noBody");

        validateStatus(response, 204);
        Assert.assertNull(response.getHeader("content-encoding"));
    }


    @Test
    public void testEmptyBodyGetsCompleteGzipMember() throws Exception {
        startCompressionServer();
        setCompression("force");

        Http3Response response = getCompressed("/empty");

        validateStatus(response, 200);
        Assert.assertEquals("gzip", response.getHeader("content-encoding"));
        // The empty gzip member must still be a valid, decompressible
        // stream (matching the HTTP/1.1 behaviour).
        Assert.assertEquals(0, gunzip(response.getBody()).length);
    }


    @Test
    public void testLargeBodySpansMultipleDataFrames() throws Exception {
        startCompressionServer();
        setCompression("on");

        // 300k digits compress to well over the 16kB DATA frame staging
        // buffer: the compressed bytes have to be split across frames and
        // reassemble on the client.
        byte[] large = body(300000);
        Http3Response response = getCompressed("/gen?n=300000");

        assertCompressed(response, large);
    }


    @Test
    public void testFlushMidStreamStillDecompresses() throws Exception {
        startCompressionServer();
        setCompression("on");

        Http3Response response = getCompressed("/flushing");

        validateStatus(response, 200);
        Assert.assertEquals("gzip", response.getHeader("content-encoding"));
        Assert.assertEquals("first-half-second-half",
                new String(gunzip(response.getBody()),
                        StandardCharsets.ISO_8859_1));
    }


    @Test
    public void testTrailersWithCompression() throws Exception {
        startCompressionServer();
        setCompression("force");

        Http3Response response = getCompressed("/trailers");

        validateStatus(response, 200);
        Assert.assertEquals("gzip", response.getHeader("content-encoding"));
        // The gzip member must be concluded before the trailing HEADERS
        // frame: both the body and the trailer have to arrive intact.
        Assert.assertEquals("body",
                new String(gunzip(response.getBody()),
                        StandardCharsets.ISO_8859_1));
        Assert.assertEquals("test", response.getTrailer("x-test-trailer"));
    }


    @Test
    public void testRepeatedRequestsOnSameConnectionAllCompressed()
            throws Exception {
        // Processors (and their output buffers) are pooled per connection:
        // the compression state of the first response must not leak into
        // the second one, and each response must carry its own gzip member.
        startCompressionServer();
        setCompression("on");

        List<String> command = clientCommand("get", "127.0.0.1",
                Integer.toString(port), "/gen?n=4096");
        command.add("--header");
        command.add("accept-encoding: gzip");
        command.add("--requests");
        command.add("2");
        ClientOutput output = runClient(command, CLIENT_TIMEOUT_SECONDS);

        Assert.assertEquals(2, output.getResponses().size());
        for (Http3Response response : output.getResponses()) {
            assertCompressed(response, LARGE_BODY);
        }
    }


    // ------------------------------------------------------------ servlets


    /*
     * Serves a generated body. Query parameters: n (length), type (content
     * type, default text/plain), etag (ETag header value), enc (pre-set
     * Content-Encoding value).
     */
    private static class GenServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void service(HttpServletRequest req,
                HttpServletResponse resp) throws ServletException, IOException {
            int n = Integer.parseInt(req.getParameter("n"));
            String type = req.getParameter("type");
            resp.setContentType(type == null ? "text/plain" : type);
            String etag = req.getParameter("etag");
            if (etag != null) {
                resp.setHeader("ETag", etag);
            }
            String encoding = req.getParameter("enc");
            if (encoding != null) {
                resp.setHeader("Content-Encoding", encoding);
            }
            resp.setContentLength(n);
            try (OutputStream out = resp.getOutputStream()) {
                out.write(body(n));
            }
        }
    }


    private static class EmptyServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req,
                HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/plain");
            // No body bytes written.
        }
    }


    private static class NoBodyServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req,
                HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setStatus(HttpServletResponse.SC_NO_CONTENT);
        }
    }


    /*
     * Writes the body in two parts with a flush in between, exercising the
     * compression stream flush path. The content length is unknown, which
     * is still compressed under "on".
     */
    private static class FlushingServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req,
                HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            ServletOutputStream out = resp.getOutputStream();
            out.print("first-half-");
            resp.flushBuffer();
            out.print("second-half");
        }
    }
}

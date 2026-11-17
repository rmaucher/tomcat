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

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.CompletionHandler;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.coyote.AbstractProcessor;
import org.apache.coyote.ActionCode;
import org.apache.coyote.AsyncContextCallback;
import org.apache.coyote.ContinueResponseTiming;
import org.apache.coyote.ErrorState;
import org.apache.coyote.RequestInfo;
import org.apache.coyote.Response;
import org.apache.coyote.UpgradeToken;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.ApplicationBufferHandler;
import org.apache.tomcat.util.net.SSLSupport;
import org.apache.tomcat.util.net.SendfileDataBase;
import org.apache.tomcat.util.net.SendfileState;
import org.apache.tomcat.util.net.SocketEvent;
import org.apache.tomcat.util.net.SocketProcessorBase;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.net.quic.QuicConnection;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicSocketWrapper;
import org.apache.tomcat.util.net.quic.QuicStream;

/**
 * Functional tests for the HTTP/3 implementation: request methods,
 * request bodies, query strings and concurrent requests.
 */
public class TestHttp3Functional extends Http3TestBase {

    private static final org.apache.coyote.Adapter TEST_ADAPTER =
            new TestAdapter();

    /*
     * Observation points for the body-capture servlet used by the streaming
     * request-body error tests.
     */
    private static volatile int captureBodyLength;
    private static volatile Throwable captureReadError;

    @Test
    public void testGet() throws Exception {
        startHttp3Server();

        Http3Response response = get("/echo");

        validateStatus(response, 200);
        Assert.assertTrue(response.getBodyAsString().contains(
                "METHOD: GET"));
    }


    @Test
    public void testTeResponseHeaderRemoved() throws Exception {
        // RFC 9114 Section 4.2 permits TE only in a request header (with the
        // value "trailers"). It is a connection-specific field for responses,
        // so an application-supplied response TE must not reach the wire.
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "te", new HttpServlet() {
                private static final long serialVersionUID = 1L;

                @Override
                protected void doGet(HttpServletRequest req,
                        HttpServletResponse resp) throws IOException {
                    resp.addHeader("TE", "trailers");
                    resp.getWriter().print("OK");
                }
            });
            ctxt.addServletMapping("/te", "te");
        });

        Http3Response response = get("/te");

        validateStatus(response, 200);
        Assert.assertNull("A response must not contain the connection-specific "
                + "TE field", response.getHeader("te"));
    }


    @Test
    public void testPeerAddress() throws Exception {
        startHttp3Server();

        // The client connects from the IPv4 loopback address. The endpoint
        // must report the real client address and port on the request (the
        // BIO_ADDR accessors, not a raw layout assumption).
        Http3Response response = get("/remote");

        validateStatus(response, 200);
        String[] parts = response.getBodyAsString().split(":");
        Assert.assertEquals("Unexpected remote address in: "
                + response.getBodyAsString(), "127.0.0.1", parts[0]);
        Assert.assertTrue("Unexpected remote port in: "
                + response.getBodyAsString(),
                parts.length == 2 && Integer.parseInt(parts[1]) > 0);
    }


    @Test
    public void testPostWithBody() throws Exception {
        startHttp3Server();

        byte[] body = "HTTP/3 upload test payload".getBytes(
                StandardCharsets.ISO_8859_1);
        Http3Response response = request("POST", "/echo", body, null);

        validateStatus(response, 200);
        Assert.assertTrue("Expected the echoed request body in:\n"
                + response.getBodyAsString(),
                response.getBodyAsString().contains(
                        "BODY: " + body.length + ":HTTP/3 upload test "
                        + "payload"));
    }


    @Test
    public void testRequestMethods() throws Exception {
        startHttp3Server();

        // HEAD is not included because the aioquic H3 stack in the normal
        // client mode rejects HEAD responses that carry a content-length
        // but no body (see TestHttp3Section_4_2).
        for (String method : new String[] { "GET", "POST", "PUT",
                "DELETE", "PATCH", "OPTIONS" }) {
            Http3Response response = request(method, "/echoMethod", null,
                    null);
            Assert.assertEquals("Unexpected status for " + method, 200,
                    response.getStatus());
            Assert.assertEquals(method, response.getBodyAsString());
        }
    }


    @Test
    public void testQueryString() throws Exception {
        startHttp3Server();

        Http3Response response = get("/echo?foo=bar&baz=qux");

        validateStatus(response, 200);
        Assert.assertTrue(response.getBodyAsString().contains(
                "QUERY: foo=bar&baz=qux"));
    }


    @Test
    public void testConcurrentRequests() throws Exception {
        startHttp3Server();

        // Send several concurrent requests over the same connection.
        int requestCount = 4;
        ClientOutput output = runClient(clientCommand("get", "127.0.0.1",
                Integer.toString(port), "/simple", "--requests",
                Integer.toString(requestCount)),
                CLIENT_TIMEOUT_SECONDS);

        Assert.assertEquals(requestCount, output.getResponses().size());
        for (Http3Response response : output.getResponses()) {
            validateStatus(response, 200);
            Assert.assertEquals("Hello over HTTP/3",
                    response.getBodyAsString());
        }
    }


    @Test
    public void testSequentialRequests() throws Exception {
        startHttp3Server();

        // Send several requests, one after the other.
        for (int i = 0; i < 3; i++) {
            Http3Response response = get("/simple");
            validateStatus(response, 200);
            Assert.assertEquals("Hello over HTTP/3",
                    response.getBodyAsString());
        }
    }


    @Test
    public void testLateResetAfterCompletedResponseIsIgnored() throws Exception {
        Assume.assumeTrue("Late-read-edge suppression is ngtcp2-specific",
                endpointIsNgtcp2());
        startHttp3Server();

        // Two completed requests on one connection, then a late RESET_STREAM
        // on the first (already finalised) stream. The reset must not
        // re-enter request dispatch: doing so would enter service() without a
        // request head, reset the stream with H3_REQUEST_INCOMPLETE and
        // abandon its QPACK section. The second response proves the
        // connection stays usable.
        ClientOutput output = runClient(rawCommandWith(
                "--headers", buildFieldSection(simpleGetHeaders("/simple")),
                "--streams", "2",
                "--reset-request", "2",
                "--wait", "1",
                "--timeout", "5"), CLIENT_TIMEOUT_SECONDS);

        Assert.assertEquals("Both completed requests must have responses",
                2, output.getResponses().size());
        Assert.assertNull("A late reset must not reset the request stream",
                output.getStreamError());
        Assert.assertNull("A late reset must not fail the connection",
                output.getConnectionError());
        if (endpointIsNgtcp2()) {
            Assert.assertFalse("A late reset on a completed request must not "
                    + "abandon its QPACK section",
                    output.getDecoderCancellations().contains(Integer.valueOf(0)));
        }
    }


    @Test
    public void testStreamedBodyOverrunStreamReset() throws Exception {
        startHttp3Server();

        // The body crosses the pre-buffering limit (64 KiB), so the second
        // DATA frame is read on the streaming path. It over-runs the
        // declared Content-Length: the sum of the DATA payload lengths
        // MUST NOT exceed Content-Length (RFC 9114 Section 4.1.2), so the
        // stream is reset with H3_MESSAGE_ERROR.
        byte[] first = new byte[64 * 1024];
        Arrays.fill(first, (byte) 'a');
        byte[] overrun = new byte[5000];
        Arrays.fill(overrun, (byte) 'b');
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length",
                        Integer.toString(first.length + overrun.length - 1)),
                "--data", Base64.getEncoder().encodeToString(first),
                "--frame-after-data",
                buildFrameB64(0x00, overrun),
                "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testStreamedBodyOverrunSurfacedAsIOException()
            throws Exception {
        resetBodyCapture();
        startHttp3Server(this::addBodyCaptureServlet);

        // The first DATA frame fills the pre-dispatch buffer; the second
        // over-runs Content-Length and is observed by the streaming read.
        // The application must see an I/O error rather than a clean EOF for
        // the truncated body (RFC 9114 Section 4.1.2).
        byte[] first = new byte[64 * 1024];
        Arrays.fill(first, (byte) 'a');
        byte[] overrun = new byte[5000];
        Arrays.fill(overrun, (byte) 'b');
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/captureBody",
                        "content-length",
                        Integer.toString(first.length + overrun.length - 1)),
                "--data", Base64.getEncoder().encodeToString(first),
                "--frame-after-data",
                buildFrameB64(0x00, overrun),
                "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
        assertBodyCaptureReadFailed();
    }


    @Test
    public void testControlFrameDuringBodySurfacedAsIOException()
            throws Exception {
        resetBodyCapture();
        startHttp3Server(this::addBodyCaptureServlet);

        // A control-only frame while a declared request body is still
        // incomplete is a connection error (RFC 9114 Section 4.1). The
        // application must see an I/O error while reading the body, not a
        // clean EOF for the truncated body.
        byte[] body = new byte[64 * 1024];
        Arrays.fill(body, (byte) 'a');
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/captureBody", "content-length",
                        Integer.toString(body.length + 5000)),
                "--data", Base64.getEncoder().encodeToString(body),
                "--frame-after-data", buildFrameB64(0x04, new byte[] { 0 }),
                "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionErrorCode(output, H3_FRAME_UNEXPECTED);
        assertBodyCaptureReadFailed();
    }


    private void assertConnectionErrorCode(ClientOutput output,
            int expectedError) {
        Assert.assertEquals("Expected connection error " + expectedError
                + " but got " + output.getConnectionError(),
                Integer.valueOf(expectedError), output.getConnectionError());
    }


    private void resetBodyCapture() {
        captureBodyLength = -1;
        captureReadError = null;
    }


    private void assertBodyCaptureReadFailed() {
        Assert.assertNotNull(
                "The application was not told that its request body was "
                        + "truncated or malformed (read bytes: "
                        + captureBodyLength + ")",
                captureReadError);
        Assert.assertTrue("Expected an IOException, got "
                + captureReadError.getClass().getName(),
                captureReadError instanceof IOException);
    }


    private void addBodyCaptureServlet(Context ctxt) {
        Tomcat.addServlet(ctxt, "captureBody", new HttpServlet() {

            private static final long serialVersionUID = 1L;

            @Override
            protected void doPost(HttpServletRequest req,
                    HttpServletResponse resp)
                    throws ServletException, IOException {
                try {
                    captureBodyLength = req.getInputStream().readAllBytes().length;
                } catch (IOException ioe) {
                    captureReadError = ioe;
                }
                resp.getWriter().print("done");
            }
        });
        ctxt.addServletMapping("/captureBody", "captureBody");
    }


    @Test
    public void testLateContentLengthOverrunAfterBodyCompleteResetsStream()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // Simulate a completed Content-Length body followed by an extra DATA
        // frame that the after-response scan is about to inspect.
        Field requestContentLength = Http3Processor.class.getDeclaredField(
                "requestContentLength");
        requestContentLength.setAccessible(true);
        requestContentLength.setLong(processor, 64 * 1024);
        Field totalDataReceived = Http3Processor.class.getDeclaredField(
                "totalDataReceived");
        totalDataReceived.setAccessible(true);
        totalDataReceived.setLong(processor, 64 * 1024);

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        byte[] frame = Base64.getDecoder().decode(buildFrameB64(0x00,
                "extra".getBytes(StandardCharsets.US_ASCII)));
        inputBuffer.clear();
        inputBuffer.put(frame);
        inputBuffer.flip();

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        try {
            decode.invoke(processor, wrapper);
        } catch (InvocationTargetException ite) {
            throw (Exception) ite.getCause();
        }

        Assert.assertEquals("The late DATA frame must be rejected with "
                + "H3_MESSAGE_ERROR", H3_MESSAGE_ERROR, resetCode.get());
        Field streamReset = Http3Processor.class.getDeclaredField(
                "streamReset");
        streamReset.setAccessible(true);
        Assert.assertTrue("The request stream must be reset",
                ((AtomicBoolean) streamReset.get(processor)).get());
    }


    @Test
    public void testTruncatedDataAfterResponseFailsConnection() throws Exception {
        // A cleanly terminated stream whose last frame is a DATA frame
        // declaring more payload bytes than were received is a connection
        // error of type H3_FRAME_ERROR (RFC 9114 Section 7.1). The
        // after-response scan is the only frame consumer for a body-less
        // request, so it must not silently abandon the truncated frame.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }

            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                int read = super.read(block, to);
                if (read == 0 && getQuicStream() != null &&
                        getQuicStream().getReadState() ==
                                QuicStream.ReadState.FINISHED) {
                    // A stream at FIN with no buffered bytes is at end of
                    // stream, not would-block: the declared payload is
                    // actually truncated.
                    return -1;
                }
                return read;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // DATA frame header declaring five payload bytes, of which only two
        // were received before the clean FIN.
        ByteBuffer frame = ByteBuffer.allocate(32);
        Qpack.encodeQuicInteger(frame, Constants.H3_DATA);
        Qpack.encodeQuicInteger(frame, 5);
        frame.put(new byte[] { 1, 2 });
        frame.flip();

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(frame);
        inputBuffer.flip();

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        try {
            decode.invoke(processor, wrapper);
        } catch (InvocationTargetException ite) {
            throw (Exception) ite.getCause();
        }

        Assert.assertEquals("A truncated DATA frame at a clean FIN must fail "
                + "the connection with H3_FRAME_ERROR",
                Long.valueOf(H3_FRAME_ERROR), wrapper.connection.failureCode);
    }


    @Test
    public void testLateCompleteDataContentLengthShortfallResetsStream()
            throws Exception {
        // A complete DATA frame that arrives after the response is advanced
        // to the running total; a clean FIN then makes a Content-Length
        // shortfall fully observable and must reset the request stream with
        // H3_MESSAGE_ERROR.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }

            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                int read = super.read(block, to);
                if (read == 0 && getQuicStream() != null &&
                        getQuicStream().getReadState() ==
                                QuicStream.ReadState.FINISHED) {
                    return -1;
                }
                return read;
            }

            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field requestContentLength = Http3Processor.class.getDeclaredField(
                "requestContentLength");
        requestContentLength.setAccessible(true);
        requestContentLength.setLong(processor, 5);
        Field totalDataReceived = Http3Processor.class.getDeclaredField(
                "totalDataReceived");
        totalDataReceived.setAccessible(true);
        totalDataReceived.setLong(processor, 2);

        // A complete two-byte DATA frame: the running total reaches four of
        // the declared five bytes when the clean FIN ends the stream.
        ByteBuffer frame = ByteBuffer.allocate(32);
        Qpack.encodeQuicInteger(frame, Constants.H3_DATA);
        Qpack.encodeQuicInteger(frame, 2);
        frame.put(new byte[] { 3, 4 });
        frame.flip();

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(frame);
        inputBuffer.flip();

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        try {
            decode.invoke(processor, wrapper);
        } catch (InvocationTargetException ite) {
            throw (Exception) ite.getCause();
        }

        Assert.assertEquals("A Content-Length shortfall observed at the clean "
                + "FIN must reset the stream with H3_MESSAGE_ERROR",
                H3_MESSAGE_ERROR, resetCode.get());
        Assert.assertEquals("The complete late DATA payload must advance the "
                + "running total", 4, totalDataReceived.getLong(processor));
    }


    @Test
    public void testGetWithDeclaredBodyOverrunStreamReset() throws Exception {
        startHttp3Server();

        // RFC 9110 Section 6.5 / RFC 9114 Section 4.1: any method may
        // carry a body; the content-length declaration - not the method
        // name - drives body handling. A GET that over-runs its declared
        // content-length is malformed and must be reset with
        // H3_MESSAGE_ERROR, like the equivalent POST.
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "GET",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/simple",
                        "content-length", "5"),
                "--data",
                Base64.getEncoder().encodeToString(
                        "123456789".getBytes(StandardCharsets.US_ASCII)),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testGetWithDeclaredBodyAccepted() throws Exception {
        startHttp3Server();

        // A GET carrying a body whose declared length is fully delivered is
        // not malformed: the request is dispatched normally even though the
        // servlet never reads the body.
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "GET",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/simple",
                        "content-length", "5"),
                "--data",
                Base64.getEncoder().encodeToString(
                        "hello".getBytes(StandardCharsets.US_ASCII))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testStreamedBodyAcrossBufferLimitAccepted() throws Exception {
        startHttp3Server();

        // The same body delivered as two DATA frames across the
        // pre-buffering limit without over-running Content-Length: the
        // streaming path must account the pre-buffered bytes in its
        // Content-Length bookkeeping and accept the request (RFC 9114
        // Section 4.1.2).
        byte[] body = new byte[64 * 1024 + 8];
        Arrays.fill(body, (byte) 'a');
        byte[] first = Arrays.copyOf(body, 64 * 1024);
        byte[] second = Arrays.copyOfRange(body, 64 * 1024, body.length);
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length", Integer.toString(body.length)),
                "--data", Base64.getEncoder().encodeToString(first),
                "--frame-after-data", buildFrameB64(0x00, second)),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertTrue("Expected the full body echoed in:\n"
                + response.getBodyAsString(),
                response.getBodyAsString().contains(
                        "BODY: " + body.length + ":"));
    }


    @Test
    public void testErrorResponseSuppressedAfterStreamReset()
            throws Exception {
        // An error response attempted on a stream that was already reset
        // must be suppressed without attempting any write (the other
        // response entry points suppress the same way; an attempted write
        // against the reset stream would only throw and log misleading
        // I/O errors on top of the reset that already happened). The
        // unwired processor has no socket wrapper, so a write attempt
        // would fail the call outright.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, null);
        processor.setStreamId(0);

        Field resetField =
                Http3Processor.class.getDeclaredField("streamReset");
        resetField.setAccessible(true);
        ((AtomicBoolean) resetField.get(processor)).set(true);

        Method sendErrorResponse = Http3Processor.class.getDeclaredMethod(
                "sendErrorResponse", SocketWrapperBase.class, Integer.TYPE);
        sendErrorResponse.setAccessible(true);
        try {
            sendErrorResponse.invoke(processor, null, Integer.valueOf(500));
        } catch (InvocationTargetException ite) {
            throw (Exception) ite.getCause();
        }

        Field startedField =
                Http3Processor.class.getDeclaredField("responseStarted");
        startedField.setAccessible(true);
        Assert.assertTrue("The suppressed error response must still claim "
                + "the response as started",
                startedField.getBoolean(processor));
    }


    @Test
    public void testBlockingIllegalStateBecomesStreamReset() throws Exception {
        // A generic wrapper may report a closed stream with
        // IllegalStateException. The blocking write paths must translate it
        // to IOException so the normal stream-reset handling applies instead
        // of letting an unchecked exception escape.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                throw new IllegalStateException("simulated closed wrapper");
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        try {
            processor.finishResponse();
            Assert.fail("A closed blocking wrapper must propagate an "
                    + "IOException");
        } catch (IOException expected) {
            // Expected.
        }

        Field streamResetField = Http3Processor.class.getDeclaredField(
                "streamReset");
        streamResetField.setAccessible(true);
        Assert.assertTrue("The failed response stream must be reset",
                ((AtomicBoolean) streamResetField.get(processor)).get());
    }


    @Test
    public void testFinalWriteFailureIsStreamScoped() throws Exception {
        // A write failure while ActionCode.CLOSE finishes the response must
        // not be escalated to CLOSE_CONNECTION_NOW: HTTP/3 streams are
        // independent, and the response stream is reset already.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) throws IOException {
                throw new IOException("test final write failure");
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.action(ActionCode.CLOSE, null);

        Method getErrorState = AbstractProcessor.class.getDeclaredMethod(
                "getErrorState");
        getErrorState.setAccessible(true);
        Assert.assertEquals("A stream write failure during CLOSE must be "
                + "stream-scoped", ErrorState.CLOSE_NOW,
                getErrorState.invoke(processor));

        Field streamResetField = Http3Processor.class.getDeclaredField(
                "streamReset");
        streamResetField.setAccessible(true);
        Assert.assertTrue("The failed response stream must be reset",
                ((AtomicBoolean) streamResetField.get(processor)).get());
    }


    @Test
    public void testFinishResponsePropagatesWriteFailure() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubReadSocketWrapper wrapper = new StubReadSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) throws IOException {
                throw new IOException("test write failure");
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        try {
            processor.finishResponse();
            Assert.fail("A failed final write must propagate an IOException");
        } catch (IOException expected) {
            // Expected; AbstractProcessor.action(CLOSE) uses this to set the
            // processor error state instead of concluding the stream.
        }
    }


    @Test
    public void testPostHeaderFinalWriteFailureResetsStream() throws Exception {
        // A final flush failure after the response headers were sent must reset
        // the stream. The async completion path skips dispatchEndRequest() once
        // CLOSE_NOW is set, so finishResponse() itself must reset; otherwise
        // the transports free the unconcluded stream with error 0.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() throws IOException {
                throw new IOException("test post-header final write failure");
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field responseStarted = Http3Processor.class.getDeclaredField(
                "responseStarted");
        responseStarted.setAccessible(true);
        responseStarted.setBoolean(processor, true);

        processor.action(ActionCode.CLOSE, null);

        Method getErrorState = AbstractProcessor.class.getDeclaredMethod(
                "getErrorState");
        getErrorState.setAccessible(true);
        Assert.assertEquals("A post-header stream write failure must stay "
                + "stream-scoped", ErrorState.CLOSE_NOW,
                getErrorState.invoke(processor));

        Field streamResetField = Http3Processor.class.getDeclaredField(
                "streamReset");
        streamResetField.setAccessible(true);
        Assert.assertTrue("The failed response stream must be reset",
                ((AtomicBoolean) streamResetField.get(processor)).get());
    }


    @Test
    public void testFlushFailureIsStreamScoped() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void flushBlocking() throws IOException {
                throw new IOException("test flush failure");
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field responseStarted = Http3Processor.class.getDeclaredField(
                "responseStarted");
        responseStarted.setAccessible(true);
        responseStarted.setBoolean(processor, true);

        processor.action(ActionCode.CLIENT_FLUSH, null);

        Method getErrorState = AbstractProcessor.class.getDeclaredMethod(
                "getErrorState");
        getErrorState.setAccessible(true);
        Assert.assertEquals("A flush failure must not fail the connection",
                ErrorState.CLOSE_NOW, getErrorState.invoke(processor));

        Field streamResetField = Http3Processor.class.getDeclaredField(
                "streamReset");
        streamResetField.setAccessible(true);
        Assert.assertTrue("The failed response stream must be reset",
                ((AtomicBoolean) streamResetField.get(processor)).get());
    }


    @Test
    public void testAckWriteFailureIsStreamScoped() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.getRequest().setExpectation(true);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) throws IOException {
                throw new IOException("test interim write failure");
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.action(ActionCode.ACK, ContinueResponseTiming.ALWAYS);

        Method getErrorState = AbstractProcessor.class.getDeclaredMethod(
                "getErrorState");
        getErrorState.setAccessible(true);
        Assert.assertEquals("An interim write failure must not fail the "
                + "connection", ErrorState.CLOSE_NOW,
                getErrorState.invoke(processor));

        Field streamResetField = Http3Processor.class.getDeclaredField(
                "streamReset");
        streamResetField.setAccessible(true);
        Assert.assertTrue("The failed response stream must be reset",
                ((AtomicBoolean) streamResetField.get(processor)).get());
    }


    @Test
    public void testEarlyHintsWriteFailureIsStreamScoped() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) throws IOException {
                throw new IOException("test interim write failure");
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.action(ActionCode.EARLY_HINTS, null);

        Method getErrorState = AbstractProcessor.class.getDeclaredMethod(
                "getErrorState");
        getErrorState.setAccessible(true);
        Assert.assertEquals("An early hints write failure must not fail the "
                + "connection", ErrorState.CLOSE_NOW,
                getErrorState.invoke(processor));

        Field streamResetField = Http3Processor.class.getDeclaredField(
                "streamReset");
        streamResetField.setAccessible(true);
        Assert.assertTrue("The failed response stream must be reset",
                ((AtomicBoolean) streamResetField.get(processor)).get());
    }


    @Test
    public void testTrailerFieldsRejectedForBodylessStatuses() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        org.apache.coyote.Response response =
                processor.getRequest().getResponse();
        Map<String,String> trailers = new HashMap<>();
        trailers.put("x-trailer", "value");

        response.setStatus(200);
        response.setTrailerFields(() -> trailers);

        for (int status : new int[] { 204, 205, 304 }) {
            response.setStatus(status);
            try {
                response.setTrailerFields(() -> trailers);
                Assert.fail("Trailer fields must not be supported for status "
                        + status);
            } catch (IllegalStateException expected) {
                // Expected.
            }
        }

        response.setStatus(200);
        processor.getRequest().setMethod("HEAD");
        try {
            response.setTrailerFields(() -> trailers);
            Assert.fail("Trailer fields must not be supported for HEAD");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }


    @Test
    public void testNoTrailerFrameFor304Response() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        org.apache.coyote.Response response =
                processor.getRequest().getResponse();
        Map<String,String> trailers = new HashMap<>();
        trailers.put("x-trailer", "value");

        // Register the supplier while the status is still 200, then change the
        // status to a bodyless one: sendResponseTrailers() must not emit a
        // trailing HEADERS frame for a 304 response (RFC 9110 Section 15.4.5).
        response.setStatus(200);
        response.setTrailerFields(() -> trailers);
        response.setStatus(304);

        AtomicInteger writes = new AtomicInteger();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
                writes.incrementAndGet();
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field responseStarted = Http3Processor.class.getDeclaredField(
                "responseStarted");
        responseStarted.setAccessible(true);
        responseStarted.setBoolean(processor, true);

        Method sendTrailers = Http3Processor.class.getDeclaredMethod(
                "sendResponseTrailers", SocketWrapperBase.class);
        sendTrailers.setAccessible(true);
        sendTrailers.invoke(processor, wrapper);

        Assert.assertEquals("A 304 response must not carry trailers", 0,
                writes.get());
    }


    @Test
    public void testAbandonedTrailerReadMarksStreamCancellation() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, null);
        processor.setStreamId(0);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field hasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        hasData.setAccessible(true);
        hasData.setBoolean(processor, true);
        Field bufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        bufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) bufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.limit(1);
        inputBuffer.put(0, (byte) 0x01);
        inputBuffer.position(0);

        Object inBuf = processor.getRequest().getInputBuffer();
        Method handle = Http3Processor.class.getDeclaredMethod(
                "handleTrailerReadEnd", SocketWrapperBase.class,
                inBuf.getClass());
        handle.setAccessible(true);
        Assert.assertEquals(Boolean.TRUE, handle.invoke(processor, wrapper,
                inBuf));

        Field cancellationSent = Http3Processor.class.getDeclaredField(
                "streamCancellationSent");
        cancellationSent.setAccessible(true);
        Assert.assertTrue("An abandoned trailer read must queue the QPACK " +
                "Stream Cancellation", cancellationSent.getBoolean(processor));
    }


    @Test
    public void testReplayWithOpenStreamMarksReadSideAbandoned()
            throws Exception {
        // When the transport stream that carried the swallowed request is
        // still open, the replay must not pretend that it ended cleanly: a
        // later trailer section would be hidden and no QPACK Stream
        // Cancellation would be queued. Mark the read side abandoned instead.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(), null);
        processor.setStreamId(0);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream();
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        byte[] body = "body!".getBytes(StandardCharsets.UTF_8);
        ByteChunk chunk = new ByteChunk();
        chunk.setBytes(body, 0, body.length);
        processor.setRequestBody(chunk);

        Object inBuf = processor.getRequest().getInputBuffer();
        Method aborted = inBuf.getClass().getDeclaredMethod(
                "isStreamAborted");
        aborted.setAccessible(true);
        Assert.assertEquals("Replacing the body while the transport stream is "
                + "still open must mark the read side abandoned",
                Boolean.TRUE, aborted.invoke(inBuf));
        Assert.assertFalse("An abandoned replaced stream must not report ready "
                + "trailer fields", processor.isTrailerFieldsReady());

        Field cancellationSent = Http3Processor.class.getDeclaredField(
                "streamCancellationSent");
        cancellationSent.setAccessible(true);
        Assert.assertTrue("Abandoning the replaced request stream must queue "
                + "the QPACK Stream Cancellation",
                cancellationSent.getBoolean(processor));
    }


    @Test
    public void testStreamErrorAfterFinIsSignalled() throws Exception {
        // A stream-scoped request error detected after the response FIN was
        // handed to the transport must still be signalled: QUIC permits a
        // sender to send RESET_STREAM from the Data Sent state (RFC 9000
        // Section 3.1). Keeping the already-complete response is unaffected.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field finSent = Http3Processor.class.getDeclaredField("finSent");
        finSent.setAccessible(true);
        finSent.setBoolean(processor, true);

        Method handle = Http3Processor.class.getDeclaredMethod(
                "handleStreamError", SocketWrapperBase.class, Http3Error.class);
        handle.setAccessible(true);
        handle.invoke(processor, wrapper, Http3Error.H3_MESSAGE_ERROR);

        Assert.assertEquals("A stream error detected after the response FIN "
                + "must still be sent to the peer",
                Http3Error.H3_MESSAGE_ERROR.getCode(), resetCode.get());
    }


    @Test
    public void testFieldSectionErrorClassifierScope() throws Exception {
        // The shared field-section error classifier must keep the QPACK error
        // contract: an implementation-limit value is stream-scoped, an
        // invalid QPACK encoding fails the connection.
        AbstractHttp3Protocol protocol = newHttp3Protocol();

        Http3Processor streamProcessor = new Http3Processor(protocol,
                TEST_ADAPTER);
        streamProcessor.setStreamId(0);
        AtomicInteger resetCode = new AtomicInteger(-1);
        AtomicLong streamConnectionFailure = new AtomicLong(-1);
        StubQuicSocketWrapper streamWrapper = new StubQuicSocketWrapper() {
            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }

            @Override
            public QuicConnection getConnection() {
                return new StubQuicConnection() {
                    @Override
                    public void failConnection(long appErrorCode,
                            String reason) {
                        streamConnectionFailure.compareAndSet(-1, appErrorCode);
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(streamProcessor, streamWrapper);

        Method classify = Http3Processor.class.getDeclaredMethod(
                "handleFieldSectionError", SocketWrapperBase.class,
                Exception.class);
        classify.setAccessible(true);
        Assert.assertTrue("An implementation-limit QPACK value must be "
                + "classified as stream-scoped",
                ((Boolean) classify.invoke(streamProcessor, streamWrapper,
                        new QpackValueTooLargeException("too large")))
                        .booleanValue());
        Assert.assertEquals("An implementation-limit QPACK value must reset "
                + "the stream with H3_QPACK_DECOMPRESSION_FAILED",
                Http3Error.H3_QPACK_DECOMPRESSION_FAILED.getCode(),
                resetCode.get());
        Assert.assertEquals("An implementation-limit QPACK value must not "
                + "fail the connection", -1L, streamConnectionFailure.get());

        Http3Processor connectionProcessor = new Http3Processor(protocol,
                TEST_ADAPTER);
        connectionProcessor.setStreamId(0);
        AtomicInteger connectionResetCode = new AtomicInteger(-1);
        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicSocketWrapper connectionWrapper = new StubQuicSocketWrapper() {
            @Override
            public boolean resetStream(long appErrorCode) {
                connectionResetCode.set((int) appErrorCode);
                return true;
            }

            @Override
            public QuicConnection getConnection() {
                return new StubQuicConnection() {
                    @Override
                    public void failConnection(long appErrorCode,
                            String reason) {
                        connectionFailure.compareAndSet(-1, appErrorCode);
                    }
                };
            }
        };
        setWrapper.invoke(connectionProcessor, connectionWrapper);

        Assert.assertFalse("An invalid QPACK encoding must be classified as "
                + "connection-scoped",
                ((Boolean) classify.invoke(connectionProcessor,
                        connectionWrapper, new QpackException("invalid")))
                        .booleanValue());
        Assert.assertEquals("An invalid QPACK encoding must fail the "
                + "connection with H3_QPACK_DECOMPRESSION_FAILED",
                Http3Error.H3_QPACK_DECOMPRESSION_FAILED.getCode(),
                connectionFailure.get());
        Assert.assertEquals("An invalid QPACK encoding must not reset only "
                + "the stream", -1, connectionResetCode.get());
    }


    @Test
    public void testRemoteResetBeforeProcessingQueuesStreamCancellation()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setConnectionState(manager.getState(connection));

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.RESET_REMOTE;
                    }
                };
            }

            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.recycle();

        Field pendingField = Http3ConnectionManager.ConnectionState.class
                .getDeclaredField("pendingCancellations");
        pendingField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Set<Long> pending = (Set<Long>) pendingField.get(
                manager.getState(connection));
        Assert.assertTrue("A remotely reset request stream abandoned before "
                + "any field section was processed must generate a QPACK "
                + "Stream Cancellation", pending.contains(Long.valueOf(0)));
    }


    @Test
    public void testAbortedStreamCloseQueuesStreamCancellation()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.RESET_REMOTE;
                    }
                };
            }

            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        Field lastRead = Http3Processor.class.getDeclaredField(
                "lastReadEndedWithException");
        lastRead.setAccessible(true);
        lastRead.setBoolean(processor, true);

        Object inBuf = processor.getRequest().getInputBuffer();
        Method setClosed = inBuf.getClass().getDeclaredMethod(
                "setStreamClosed");
        setClosed.setAccessible(true);
        setClosed.invoke(inBuf);

        Field pendingField = Http3ConnectionManager.ConnectionState.class
                .getDeclaredField("pendingCancellations");
        pendingField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Set<Long> pending = (Set<Long>) pendingField.get(
                manager.getState(connection));
        Assert.assertTrue("Closing a stream after a peer reset must generate "
                + "a QPACK Stream Cancellation", pending.contains(Long.valueOf(0)));
    }


    @Test
    public void testServerCriticalUniStreamClosureFailsConnection()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        AtomicLong failureCode = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }

            @Override
            public void failConnection(long appErrorCode, String reason) {
                failureCode.compareAndSet(-1, appErrorCode);
            }
        };
        manager.connectionOpen(connection);

        manager.serverUniStreamClosed(connection,
                Http3ConnectionManager.SERVER_STREAM_INDEX_CONTROL);
        Assert.assertEquals("Closing the server control stream must fail the "
                + "connection with H3_CLOSED_CRITICAL_STREAM",
                Http3Error.H3_CLOSED_CRITICAL_STREAM.getCode(),
                failureCode.get());

        // A server extension stream outside the critical three indices is
        // not an HTTP/3 critical stream and must not fail the connection.
        AtomicLong extensionFailure = new AtomicLong(-1);
        StubQuicConnection extensionConnection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }

            @Override
            public void failConnection(long appErrorCode, String reason) {
                extensionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        manager.connectionOpen(extensionConnection);
        manager.serverUniStreamClosed(extensionConnection, 3);
        Assert.assertEquals("A non-critical server extension stream must not "
                + "fail the connection", -1, extensionFailure.get());
    }


    @Test
    public void test413ResponseWithSwallowAbortedUploadsDisabled()
            throws Exception {
        startHttp3Server(ctxt -> {
            ctxt.setSwallowAbortedUploads(false);
            Tomcat.addServlet(ctxt, "status413", new Status413Servlet());
            ctxt.addServletMapping("/status413", "status413");
        });

        // Request.finishRequest() calls Request.checkSwallowInput() for a
        // 413 response. With swallowing disabled, the resulting
        // ActionCode.DISABLE_SWALLOW_INPUT action sets ErrorState.CLOSE_CLEAN.
        // CLOSE_CLEAN still permits completing the current response, so the
        // completed 413 must not be turned into a stream reset.
        ClientOutput output = runClient(rawCommandWith(
                "--headers", buildFieldSection(simpleGetHeaders("/status413")),
                "--wait", "2"), CLIENT_TIMEOUT_SECONDS);

        Assert.assertNull("A CLOSE_CLEAN response must not be reset as a "
                + "stream error", output.getStreamError());
        Assert.assertNull("A CLOSE_CLEAN response must not fail the "
                + "connection", output.getConnectionError());
        Assert.assertNotNull("The 413 response must be received",
                output.getResponse());
        validateStatus(output.getResponse(), 413);
    }


    @Test
    public void testAsyncCloseCleanErrorConcludesResponseStream()
            throws Exception {
        // An asynchronous error state that still permits I/O (CLOSE_CLEAN,
        // for example a 413 with swallowAbortedUploads disabled) does not
        // take the dispatchEndRequest() path. If the request body was not
        // read, finishResponse() defers the FIN to the after-response scan
        // that never runs. recycle() must conclude the already completed
        // response stream instead of leaving it for the endpoint's neutral
        // error-0 close.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.getRequest().getResponse().setStatus(
                HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(processor, wrapper);

        processor.action(ActionCode.DISABLE_SWALLOW_INPUT, null);
        Method getErrorState = AbstractProcessor.class.getDeclaredMethod(
                "getErrorState");
        getErrorState.setAccessible(true);
        Assert.assertEquals("The test setup requires CLOSE_CLEAN",
                ErrorState.CLOSE_CLEAN, getErrorState.invoke(processor));

        processor.recycle();
        Assert.assertTrue("A CLOSE_CLEAN error that bypassed "
                + "dispatchEndRequest() must still conclude the response "
                + "stream", wrapper.concluded);
        Assert.assertEquals("A completed CLOSE_CLEAN response must not be "
                + "replaced with a stream reset", -1, wrapper.resetCode);
    }


    @Test
    public void testAsyncCloseCleanErrorFlushesQueuedOutput()
            throws Exception {
        // The CLOSE_CLEAN asynchronous path has no dispatchEndRequest().
        // If non-blocking output is still queued when recycle() runs, the
        // pending frames must be drained with a blocking flush before FIN,
        // otherwise recycle() detaches the queue and the peer sees a
        // truncated response as a cleanly terminated stream.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);
        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        wrapper.writable = false;
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        processor.getRequest().getResponse().setStatus(200);
        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(processor, wrapper);

        ByteBuffer body = ByteBuffer.wrap(new byte[1024]);
        processor.getRequest().getResponse().doWrite(body);
        Assert.assertEquals("The queued body must have been consumed",
                1024, body.position());

        processor.action(ActionCode.DISABLE_SWALLOW_INPUT, null);
        Method getErrorState = AbstractProcessor.class.getDeclaredMethod(
                "getErrorState");
        getErrorState.setAccessible(true);
        Assert.assertEquals("The test setup requires CLOSE_CLEAN",
                ErrorState.CLOSE_CLEAN, getErrorState.invoke(processor));

        processor.recycle();
        Assert.assertTrue("Pending CLOSE_CLEAN output must be flushed before "
                + "the response is concluded", wrapper.concluded);
        Assert.assertEquals("A completed CLOSE_CLEAN response must not be "
                + "replaced with a stream reset", -1, wrapper.resetCode);
        Assert.assertTrue("The queued body chunk must reach the transport",
                wrapper.sentBytes >= 1024);
    }


    @Test
    public void testRequestStartTimeIsNotResetAfterPartialHeader()
            throws Exception {
        // service() is called again when a partial frame header is completed
        // by a later read. The request start time must be recorded by the
        // first call and must not move forward on the second dispatch.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }

            @Override
            protected boolean flushNonBlocking() {
                return true;
            }
        };

        byte[] fieldSection = Base64.getDecoder().decode(buildFieldSection(
                ":method", "GET", ":scheme", "http",
                ":authority", "127.0.0.1:80", ":path", "/simple"));
        byte[] frame = Base64.getDecoder().decode(
                buildFrameB64(0x01, fieldSection));
        wrapper.enqueue(new byte[] { frame[0] });

        Assert.assertEquals(SocketState.LONG, processor.service(wrapper));
        long startTime = processor.getRequest().getStartTimeNanos();
        Assert.assertTrue("The first service() invocation must start the "
                + "request timer", startTime != -1);

        wrapper.enqueue(Arrays.copyOfRange(frame, 1, frame.length));
        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));
        Assert.assertEquals("Completing a split frame header must not reset "
                + "the request start time", startTime,
                processor.getRequest().getStartTimeNanos());
    }


    @Test
    public void testMalformedRequestIsAccessLoggedAndCounted() throws Exception {
        // A request whose field section decodes successfully but lacks a
        // required pseudo-header is still an HTTP request. It is reset at
        // stream scope, but must be counted and visible to the access log
        // with a 400 status, as HTTP/1.1 does for bad requests.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }

            @Override
            protected boolean flushNonBlocking() {
                return true;
            }
        };

        byte[] fieldSection = Base64.getDecoder().decode(buildFieldSection(
                ":scheme", "http", ":authority", "127.0.0.1:80",
                ":path", "/simple"));
        wrapper.enqueue(Base64.getDecoder().decode(
                buildFrameB64(0x01, fieldSection)));

        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));

        RequestInfo rp = processor.getRequest().getRequestProcessor();
        Assert.assertEquals("A decoded but malformed request must be counted",
                1, rp.getRequestCount());
        Assert.assertEquals("A malformed request must count as an error", 1,
                rp.getErrorCount());
        Assert.assertEquals("A malformed request must be access-logged with "
                + "400", HttpServletResponse.SC_BAD_REQUEST,
                processor.getRequest().getResponse().getStatus());
    }


    @Test
    public void testAsyncAdapterExceptionIsCountedOnce() throws Exception {
        // If the adapter starts async and then throws, service() terminates
        // the request and returns CLOSED. The async completion path cannot
        // update the counters, so the adapter catch must do it exactly once.
        AsyncContextCallback asyncCtxt = new AsyncContextCallback() {
            @Override
            public void fireOnComplete() {
                // NO-OP
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public void incrementInProgressAsyncCount() {
                // NO-OP
            }

            @Override
            public void decrementInProgressAsyncCount() {
                // NO-OP
            }
        };

        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(new TestAdapter() {
            @Override
            public void service(org.apache.coyote.Request req,
                    org.apache.coyote.Response res) {
                req.action(ActionCode.ASYNC_START, asyncCtxt);
                throw new IllegalStateException("test async adapter failure");
            }
        });
        Http3Processor processor =
                new Http3Processor(protocol, protocol.getAdapter());
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }

            @Override
            protected boolean flushNonBlocking() {
                return true;
            }
        };

        byte[] fieldSection = Base64.getDecoder().decode(buildFieldSection(
                ":method", "GET", ":scheme", "http",
                ":authority", "127.0.0.1:80", ":path", "/simple"));
        wrapper.enqueue(Base64.getDecoder().decode(
                buildFrameB64(0x01, fieldSection)));

        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));

        RequestInfo rp = processor.getRequest().getRequestProcessor();
        Assert.assertEquals("An async adapter failure terminated by service() "
                + "must be counted exactly once", 1, rp.getRequestCount());
        Assert.assertEquals("The terminated request must count as an error",
                1, rp.getErrorCount());
        Assert.assertEquals("The error response status must be recorded", 500,
                processor.getRequest().getResponse().getStatus());
    }


    @Test
    public void testAdapterExceptionMarksProcessorNotReusable() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(new TestAdapter() {
            @Override
            public void service(org.apache.coyote.Request req,
                    org.apache.coyote.Response res) {
                throw new IllegalStateException("test adapter failure");
            }
        });
        Http3Processor processor =
                new Http3Processor(protocol, protocol.getAdapter());
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }

            @Override
            protected boolean flushNonBlocking() {
                return true;
            }
        };

        byte[] fieldSection = Base64.getDecoder().decode(buildFieldSection(
                ":method", "GET", ":scheme", "http",
                ":authority", "127.0.0.1:80", ":path", "/simple"));
        wrapper.enqueue(Base64.getDecoder().decode(
                buildFrameB64(0x01, fieldSection)));

        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));

        // The adapter exception must mark the response/request as errored and
        // prevent recycling into the shared pool, matching HTTP/1.1/HTTP/2.
        Assert.assertTrue("The response must be marked as an error",
                processor.getRequest().getResponse().isError());
        Assert.assertNotNull("The adapter exception must be exposed as the "
                        + "request error",
                processor.getRequest().getAttribute(
                        RequestDispatcher.ERROR_EXCEPTION));
        processor.recycle();
        Assert.assertFalse("A processor whose adapter threw must not be "
                + "returned to the shared pool", processor.isReusable());
    }


    @Test
    public void testAdapterExceptionConcludesErrorResponse() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(new TestAdapter() {
            @Override
            public void service(org.apache.coyote.Request req,
                    org.apache.coyote.Response res) {
                throw new IllegalStateException("test adapter failure");
            }
        });
        Http3Processor processor =
                new Http3Processor(protocol, protocol.getAdapter());
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }

            @Override
            protected boolean flushNonBlocking() {
                return true;
            }
        };

        byte[] fieldSection = Base64.getDecoder().decode(buildFieldSection(
                ":method", "GET", ":scheme", "http",
                ":authority", "127.0.0.1:80", ":path", "/simple"));
        wrapper.enqueue(Base64.getDecoder().decode(
                buildFrameB64(0x01, fieldSection)));

        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));

        Field finSent = Http3Processor.class.getDeclaredField("finSent");
        finSent.setAccessible(true);
        Assert.assertTrue("A successfully written 500 response must be "
                + "concluded with FIN", finSent.getBoolean(processor));
    }


    @Test
    public void testAdapterExceptionAfterCommitResetsStream() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(new TestAdapter() {
            @Override
            public void service(org.apache.coyote.Request req,
                    org.apache.coyote.Response res) {
                res.action(ActionCode.COMMIT, null);
                try {
                    res.doWrite(ByteBuffer.wrap(
                            "partial".getBytes(StandardCharsets.US_ASCII)));
                } catch (IOException ioe) {
                    throw new IllegalStateException(
                            "test adapter write failure", ioe);
                }
                throw new IllegalStateException(
                        "test adapter failure after commit");
            }
        });
        Http3Processor processor =
                new Http3Processor(protocol, protocol.getAdapter());
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }

            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };

        byte[] fieldSection = Base64.getDecoder().decode(buildFieldSection(
                ":method", "GET", ":scheme", "http",
                ":authority", "127.0.0.1:80", ":path", "/error"));
        wrapper.enqueue(Base64.getDecoder().decode(
                buildFrameB64(0x01, fieldSection)));

        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));
        Assert.assertEquals("A committed response truncated by an adapter "
                + "exception must be reset with H3_INTERNAL_ERROR",
                H3_INTERNAL_ERROR, resetCode.get());
    }


    @Test
    public void testErrorResponseWriteFailureResetsStream() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(new TestAdapter() {
            @Override
            public void service(org.apache.coyote.Request req,
                    org.apache.coyote.Response res) {
                throw new IllegalStateException("test adapter failure");
            }
        });
        Http3Processor processor =
                new Http3Processor(protocol, protocol.getAdapter());
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) throws IOException {
                throw new IOException("test error-response write failure");
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }

            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };

        byte[] fieldSection = Base64.getDecoder().decode(buildFieldSection(
                ":method", "GET", ":scheme", "http",
                ":authority", "127.0.0.1:80", ":path", "/error"));
        wrapper.enqueue(Base64.getDecoder().decode(
                buildFrameB64(0x01, fieldSection)));

        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));
        Assert.assertEquals("A failed 500 response write must reset the "
                + "stream with H3_INTERNAL_ERROR", H3_INTERNAL_ERROR,
                resetCode.get());
    }


    @Test
    public void testNonReusableRecyclePreservesApplicationState()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.getRequest().setMethod("POST");
        processor.getRequest().getResponse().setStatus(201);

        Method setErrorState = AbstractProcessor.class.getDeclaredMethod(
                "setErrorState", ErrorState.class, Throwable.class);
        setErrorState.setAccessible(true);
        setErrorState.invoke(processor, ErrorState.CLOSE_NOW,
                new IOException("simulated response failure"));

        processor.recycle();

        Assert.assertFalse("The errored processor must not be reusable",
                processor.isReusable());
        Assert.assertEquals("Recycling a non-reusable processor must not "
                + "clear request state a non-container thread may still be "
                + "using", "POST", processor.getRequest().getMethod());
        Assert.assertEquals("Recycling a non-reusable processor must not "
                + "clear response state a non-container thread may still be "
                + "using", 201,
                processor.getRequest().getResponse().getStatus());
    }


    @Test
    public void testConnectionCloseWakesBlockedQpackStream() throws Exception {
        // A stream blocked waiting for QPACK encoder inserts must stop waiting
        // as soon as the connection closes: no insert can arrive afterwards.
        // Otherwise it remains parked until qpackBlockedStreamTimeoutMs.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setQpackBlockedStreamTimeoutMs(10_000);

        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setSharedQpackDecoder(manager.getSharedDecoder());
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method awaitRequiredInsertCount = Http3Processor.class
                .getDeclaredMethod("awaitRequiredInsertCount", Long.TYPE,
                        Integer.TYPE);
        awaitRequiredInsertCount.setAccessible(true);

        AtomicBoolean result = new AtomicBoolean(true);
        AtomicBoolean failed = new AtomicBoolean(false);
        Thread waiter = new Thread(() -> {
            try {
                Object value = awaitRequiredInsertCount.invoke(processor,
                        Long.valueOf(1), Integer.valueOf(1));
                result.set(((Boolean) value).booleanValue());
            } catch (Throwable t) {
                failed.set(true);
            }
        }, "http3-blocked-qpack-test");
        waiter.setDaemon(true);
        waiter.start();

        long deadline = System.currentTimeMillis() + 2000;
        while (System.currentTimeMillis() < deadline &&
                waiter.getState() != Thread.State.TIMED_WAITING &&
                waiter.getState() != Thread.State.WAITING) {
            Thread.sleep(5);
        }
        Assert.assertTrue("The test waiter did not enter the blocked wait "
                + "(state=" + waiter.getState() + ")",
                waiter.getState() == Thread.State.TIMED_WAITING ||
                        waiter.getState() == Thread.State.WAITING);

        manager.connectionClose(connection);
        waiter.join(1000);

        Assert.assertFalse("Connection close must wake the blocked QPACK "
                + "stream", waiter.isAlive());
        Assert.assertFalse("The blocked stream wait must not throw", failed.get());
        Assert.assertFalse("A stream blocked when the connection closes must "
                + "report that it could not be unblocked", result.get());
    }


    @Test
    public void testConnectResponseDoesNotSupportTrailers() throws Exception {
        // RFC 9114 Section 4.4 permits only DATA frames once CONNECT has
        // completed, so a trailer HEADERS frame is not valid on a CONNECT
        // response.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.getRequest().getResponse().setStatus(200);

        Method trailerAllowed = Http3Processor.class.getDeclaredMethod(
                "isTrailerSectionAllowed");
        trailerAllowed.setAccessible(true);

        processor.getRequest().setMethod("CONNECT");
        Assert.assertEquals("A CONNECT response must not allow trailers",
                Boolean.FALSE, trailerAllowed.invoke(processor));

        processor.getRequest().setMethod("GET");
        Assert.assertEquals("A normal 200 response must still allow trailers",
                Boolean.TRUE, trailerAllowed.invoke(processor));
    }


    @Test
    public void testFallbackDecoderUsesConfiguredTableCapacity()
            throws Exception {
        // The per-processor fallback decoder must enforce the same hard
        // dynamic table capacity as the shared per-connection decoder and the
        // value advertised in SETTINGS_QPACK_MAX_TABLE_CAPACITY.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setQpackMaxTableCapacity(1024);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);

        ByteBuffer overCapacity = ByteBuffer.allocate(8);
        Qpack.encodeIrp(overCapacity, 0x20, 5, 1025);
        overCapacity.flip();
        try {
            processor.getQpackDecoder().processInstruction(overCapacity);
            Assert.fail("The fallback decoder must reject a table capacity "
                    + "above the configured qpackMaxTableCapacity");
        } catch (QpackException expected) {
            // Expected
        }

        ByteBuffer atCapacity = ByteBuffer.allocate(8);
        Qpack.encodeIrp(atCapacity, 0x20, 5, 1024);
        atCapacity.flip();
        processor.getQpackDecoder().processInstruction(atCapacity);
    }


    @Test
    public void testDetachedProcessorReadAndWriteFail() throws Exception {
        // A processor that has been detached from its stream (for example by
        // recycle() after an error) must report an I/O error for a late read
        // or write. A read returning 0 would make Catalina consume a byte from
        // an empty buffer; the write path must not use an invalid -1 return
        // from the OutputBuffer contract as a "stream gone" sentinel.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        try {
            processor.getRequest().getInputBuffer().doRead(
                    ApplicationBufferHandler.EMPTY);
            Assert.fail("A read on a detached processor must fail with an "
                    + "IOException, not return 0");
        } catch (IOException expected) {
            // Expected
        }

        try {
            processor.getRequest().getResponse().doWrite(
                    ByteBuffer.wrap(new byte[] { 1 }));
            Assert.fail("A write on a detached processor must fail with an "
                    + "IOException");
        } catch (IOException expected) {
            // Expected
        }
    }


    @Test
    public void testVoidAndSuppressedWritesDoNotCountAsContentWritten()
            throws Exception {
        // HEAD/204/205/304 responses consume application output without
        // sending it. HTTP/1.1's VoidOutputFilter leaves the chunk untouched,
        // so contentWritten remains zero; HTTP/3 must do the same or
        // RequestInfo/GlobalRequestProcessor bytesSent will count discarded
        // bytes.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        Field outputBufferField = Http3Processor.class.getDeclaredField(
                "outputBuffer");
        outputBufferField.setAccessible(true);
        Object outputBuffer = outputBufferField.get(processor);
        Method setVoidOutput = outputBuffer.getClass().getDeclaredMethod(
                "setVoidOutput", Boolean.TYPE);
        setVoidOutput.setAccessible(true);
        setVoidOutput.invoke(outputBuffer, Boolean.TRUE);

        processor.getRequest().getResponse().doWrite(ByteBuffer.wrap(
                new byte[10]));
        Assert.assertEquals("Void output must not count discarded bytes as "
                + "content written", 0,
                processor.getRequest().getResponse().getContentWritten());

        setVoidOutput.invoke(outputBuffer, Boolean.FALSE);
        processor.setSwallowResponse();
        processor.getRequest().getResponse().doWrite(ByteBuffer.wrap(
                new byte[10]));
        Assert.assertEquals("Suppressed output must not count discarded bytes "
                + "as content written", 0,
                processor.getRequest().getResponse().getContentWritten());
    }


    @Test
    public void testReadRequestBodyIgnoresUninitializedInputBuffer()
            throws Exception {
        // A freshly recycled input buffer (position=0, limit=capacity) is
        // indistinguishable from a full one by positions alone; the
        // inputBufferHasData flag disambiguates the two (see
        // refillInputBuffer()). A body read must not parse the zero-filled
        // array as frame headers before the first socket read has set the
        // flag.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        wrapper.enqueue(new byte[] { 0x00, 0x03, 'a', 'b', 'c' });
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method readBody = Http3Processor.class.getDeclaredMethod(
                "readRequestBody", SocketWrapperBase.class);
        readBody.setAccessible(true);
        readBody.invoke(processor, wrapper);

        // The one queued DATA frame must be the only frame consumed; the
        // zero-filled fresh buffer must not contribute frames.
        Object inputBuffer = processor.getRequest().getInputBuffer();
        Method doRead = inputBuffer.getClass().getDeclaredMethod("doRead",
                ApplicationBufferHandler.class);
        doRead.setAccessible(true);
        Assert.assertEquals("The queued DATA payload must be delivered "
                + "unchanged", Integer.valueOf(3),
                doRead.invoke(inputBuffer, ApplicationBufferHandler.EMPTY));
    }


    @Test
    public void testPreDispatchBodyBufferGrowsOnlyAsDataArrives()
            throws Exception {
        // A request that declares a large Content-Length must not force a
        // 64 KiB allocation before any DATA payload arrives: the pre-dispatch
        // body buffer grows only as bytes are actually received.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        ByteBuffer frame = ByteBuffer.allocate(32);
        Qpack.encodeQuicInteger(frame, Constants.H3_DATA);
        Qpack.encodeQuicInteger(frame, 5);
        frame.put(new byte[] { 1, 2, 3, 4, 5 });
        frame.flip();
        byte[] bytes = new byte[frame.remaining()];
        frame.get(bytes);
        wrapper.enqueue(bytes);

        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field contentLength = Http3Processor.class.getDeclaredField(
                "requestContentLength");
        contentLength.setAccessible(true);
        contentLength.setLong(processor, 1024 * 1024);

        Method readBody = Http3Processor.class.getDeclaredMethod(
                "readRequestBody", SocketWrapperBase.class);
        readBody.setAccessible(true);
        readBody.invoke(processor, wrapper);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field dataBuffersField = inBuf.getClass().getDeclaredField(
                "dataBuffers");
        dataBuffersField.setAccessible(true);
        List<?> dataBuffers = (List<?>) dataBuffersField.get(inBuf);
        Assert.assertFalse("The received DATA payload must be pre-buffered",
                dataBuffers.isEmpty());
        ByteBuffer preBuffered = (ByteBuffer) dataBuffers.get(0);
        Assert.assertTrue("The pre-dispatch body buffer must grow only as "
                + "DATA arrives, not to the declared-length bound up front: "
                + "capacity=" + preBuffered.capacity(),
                preBuffered.capacity() <= 8 * 1024);
    }


    @Test
    public void testPlainEofFromResetAbortsPreDispatchBody()
            throws Exception {
        // A transport wrapper may report a reset as a plain -1 instead of
        // throwing EOFException. The pre-dispatch body classification must
        // then use the stream state so the request is not dispatched with a
        // truncated body.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                return -1;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.RESET_REMOTE;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field contentLength = Http3Processor.class.getDeclaredField(
                "requestContentLength");
        contentLength.setAccessible(true);
        contentLength.setLong(processor, 10L);

        Method readBody = Http3Processor.class.getDeclaredMethod(
                "readRequestBody", SocketWrapperBase.class);
        readBody.setAccessible(true);
        readBody.invoke(processor, wrapper);

        Object inputBuffer = processor.getRequest().getInputBuffer();
        Method aborted = inputBuffer.getClass().getDeclaredMethod(
                "isStreamAborted");
        aborted.setAccessible(true);
        Assert.assertEquals("A plain -1 with a remote reset must abort the "
                + "pre-dispatch body", Boolean.TRUE, aborted.invoke(inputBuffer));
    }


    @Test
    public void testPlainEofFromConnectionCloseAbortsPreDispatchBody()
            throws Exception {
        // See testPlainEofFromResetAbortsPreDispatchBody(): a connection
        // close reported as plain -1 must be classified from the stream state
        // as an aborted body too.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                return -1;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.CONN_CLOSED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field contentLength = Http3Processor.class.getDeclaredField(
                "requestContentLength");
        contentLength.setAccessible(true);
        contentLength.setLong(processor, 10L);

        Method readBody = Http3Processor.class.getDeclaredMethod(
                "readRequestBody", SocketWrapperBase.class);
        readBody.setAccessible(true);
        readBody.invoke(processor, wrapper);

        Object inputBuffer = processor.getRequest().getInputBuffer();
        Method aborted = inputBuffer.getClass().getDeclaredMethod(
                "isStreamAborted");
        aborted.setAccessible(true);
        Assert.assertEquals("A plain -1 with a connection close must abort "
                + "the pre-dispatch body", Boolean.TRUE,
                aborted.invoke(inputBuffer));
    }


    @Test
    public void testPartialIgnoredSkipAtResetAbortsPreDispatchBody()
            throws Exception {
        // A reset that cuts an ignored frame's payload after some bytes were
        // already skipped is reported as end-of-stream, not as would-block.
        // The pre-dispatch body reader must classify that end as an abort,
        // otherwise the request is dispatched with a body that can never
        // complete.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                return -1;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.RESET_REMOTE;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // An unknown frame declaring five payload bytes of which only two
        // are buffered; the reset cuts the remaining three.
        setProcessorInputBuffer(processor, new byte[] { 0x0a, 0x05, 'x', 'y' });

        Method readBody = Http3Processor.class.getDeclaredMethod(
                "readRequestBody", SocketWrapperBase.class);
        readBody.setAccessible(true);
        readBody.invoke(processor, wrapper);

        Object inputBuffer = processor.getRequest().getInputBuffer();
        Method aborted = inputBuffer.getClass().getDeclaredMethod(
                "isStreamAborted");
        aborted.setAccessible(true);
        Assert.assertEquals("A reset that truncates an ignored frame after a "
                + "partial skip must abort the pre-dispatch body",
                Boolean.TRUE, aborted.invoke(inputBuffer));
    }


    @Test
    public void testPlainEofFromCleanFinClosesPreDispatchBody()
            throws Exception {
        // The state-based classification must keep a real FIN non-aborted:
        // only a reset or connection close marks the pre-dispatch body as
        // aborted.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                return -1;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field contentLength = Http3Processor.class.getDeclaredField(
                "requestContentLength");
        contentLength.setAccessible(true);
        contentLength.setLong(processor, -1L);

        Method readBody = Http3Processor.class.getDeclaredMethod(
                "readRequestBody", SocketWrapperBase.class);
        readBody.setAccessible(true);
        readBody.invoke(processor, wrapper);

        Object inputBuffer = processor.getRequest().getInputBuffer();
        Method aborted = inputBuffer.getClass().getDeclaredMethod(
                "isStreamAborted");
        aborted.setAccessible(true);
        Method closed = inputBuffer.getClass().getDeclaredMethod(
                "isStreamClosed");
        closed.setAccessible(true);
        Assert.assertEquals("A plain -1 with a clean FIN must not abort the "
                + "pre-dispatch body", Boolean.FALSE,
                aborted.invoke(inputBuffer));
        Assert.assertEquals("A clean FIN must close the pre-dispatch body",
                Boolean.TRUE, closed.invoke(inputBuffer));
    }


    @Test
    public void testCloseNowSuppressesApplicationWrites() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.action(ActionCode.CLOSE_NOW, null);
        ByteBuffer body = ByteBuffer.wrap(new byte[100]);
        processor.getRequest().getResponse().doWrite(body);

        Assert.assertFalse("CLOSE_NOW must prevent further response writes",
                wrapper.blockingWrite || wrapper.sentBytes > 0);
    }


    @Test
    public void testConnectionFailureSuppressesApplicationWrites()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method fail = Http3Processor.class.getDeclaredMethod(
                "failConnection", SocketWrapperBase.class, Http3Error.class);
        fail.setAccessible(true);
        fail.invoke(processor, wrapper, Http3Error.H3_INTERNAL_ERROR);

        ByteBuffer body = ByteBuffer.wrap(new byte[100]);
        processor.getRequest().getResponse().doWrite(body);

        Assert.assertFalse("A failed connection must not accept further "
                + "response writes",
                wrapper.blockingWrite || wrapper.sentBytes > 0);
    }


    @Test
    public void testPartialHeaderWritePreventsSecondResponseHead()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger blockingWrites = new AtomicInteger();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) throws IOException {
                if (blockingWrites.incrementAndGet() == 1) {
                    int half = from.remaining() / 2;
                    from.position(from.position() + half);
                    throw new IOException("partial header write");
                }
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        try {
            sendHeaders.invoke(processor, wrapper);
            Assert.fail("The partial header write must fail");
        } catch (InvocationTargetException ite) {
            Assert.assertTrue(ite.getCause() instanceof IOException);
        }

        try {
            sendHeaders.invoke(processor, wrapper);
        } catch (InvocationTargetException ite) {
            // A retry may fail explicitly; either way it must not write.
        }
        Assert.assertEquals("A partial HEADERS frame must not be followed by "
                + "a second response HEADERS frame", 1,
                blockingWrites.get());
    }


    @Test
    public void testResponseResetDoesNotOvertakeQueuedInterimFrames()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        wrapper.writable = false;
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        // Queue a 103 interim response without flushing it.
        processor.earlyHints();
        Field outputBufferField = Http3Processor.class.getDeclaredField(
                "outputBuffer");
        outputBufferField.setAccessible(true);
        Object outputBuffer = outputBufferField.get(processor);
        Method hasPendingData = outputBuffer.getClass().getDeclaredMethod(
                "hasPendingData");
        hasPendingData.setAccessible(true);
        Assert.assertTrue("The interim response must be queued",
                ((Boolean) hasPendingData.invoke(outputBuffer)).booleanValue());

        // Response.reset() clears the write listener but leaves the protocol
        // output queue and the sticky non-blocking mode untouched. The final
        // response must not be written blocking while the interim response is
        // still queued: that would emit the final HEADERS frame first.
        processor.getRequest().getResponse().reset();
        wrapper.writable = true;

        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(processor, wrapper);

        Assert.assertFalse("The final response must not be written while the "
                + "interim response is still queued",
                ((Boolean) hasPendingData.invoke(outputBuffer)).booleanValue());
    }


    @Test
    public void testNonBlockingWritesQueueUntilWritable() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        wrapper.writable = false;
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        ByteBuffer body = ByteBuffer.wrap(new byte[4096]);
        processor.getRequest().getResponse().doWrite(body);

        Assert.assertEquals("The non-blocking write must consume the whole "
                + "application chunk", 4096, body.position());
        Assert.assertFalse("Queued data must make the stream not-ready",
                processor.isReadyForWrite());
        Assert.assertFalse("Non-blocking mode must not call writeBlocking",
                wrapper.blockingWrite);
        Assert.assertTrue("Write interest must be armed while data is queued",
                wrapper.writeInterestCount > 0);

        wrapper.writable = true;
        Assert.assertFalse("The non-blocking flush must drain the queue",
                processor.flushBufferedWrite());
        Assert.assertTrue("A drained live stream must be ready again",
                processor.isReadyForWrite());

        processor.finishResponse();
        Method conclude = Http3Processor.class.getDeclaredMethod(
                "concludeStream", SocketWrapperBase.class);
        conclude.setAccessible(true);
        conclude.invoke(processor, wrapper);
        Assert.assertTrue("The drained response must be concluded",
                wrapper.concluded);
    }


    @Test
    public void testLargeNonBlockingWriteAcceptedAsOneBatch() throws Exception {
        // A single non-blocking application write is split into many DATA
        // frames by Http3OutputBuffer. It must be accepted as one logical
        // batch even when the encoded size exceeds the 256 KiB queue limit;
        // otherwise a legitimate large write resets the response stream.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        ByteBuffer body = ByteBuffer.allocate(300000);
        processor.getRequest().getResponse().doWrite(body);

        Assert.assertEquals("The whole application chunk must be consumed",
                300000, body.position());
        Assert.assertEquals("A legitimate large non-blocking write must not "
                + "reset the stream", -1, wrapper.resetCode);
        while (processor.flushBufferedWrite()) {
            // The controlled wrapper starts writable; each flush drains the
            // bytes staged by the previous write.
        }
        Assert.assertTrue("The large batch must reach the transport",
                wrapper.sentBytes >= 300000);
    }


    @Test
    public void testNonBlockingFinDeferredUntilQueueDrained()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        wrapper.writable = false;
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        processor.getRequest().getResponse().doWrite(
                ByteBuffer.wrap(new byte[4096]));
        processor.finishResponse();

        Method conclude = Http3Processor.class.getDeclaredMethod(
                "concludeStream", SocketWrapperBase.class);
        conclude.setAccessible(true);
        conclude.invoke(processor, wrapper);
        Assert.assertFalse("FIN must not be sent while frames are queued",
                wrapper.concluded);
        Assert.assertFalse("A response with queued bytes is not writable",
                processor.isReadyForWrite());

        wrapper.writable = true;
        Assert.assertFalse(processor.flushBufferedWrite());
        Assert.assertTrue("FIN must be sent after the queue drains",
                wrapper.concluded);
    }


    @Test
    public void testDiscardedOutputQueueNeedsReset() throws Exception {
        // discardPendingFrames() sets resetOrFailed. needsReset() must report
        // that state even when the queue/listener flags are clear, otherwise
        // recycle() skips resetQueue() and a later pooled request inherits
        // the failed output state.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        Field outputBufferField = Http3Processor.class.getDeclaredField(
                "outputBuffer");
        outputBufferField.setAccessible(true);
        Object outputBuffer = outputBufferField.get(processor);
        Method discard = outputBuffer.getClass().getDeclaredMethod(
                "discardPendingFrames");
        discard.setAccessible(true);
        discard.invoke(outputBuffer);
        Method needsReset = outputBuffer.getClass().getDeclaredMethod(
                "needsReset");
        needsReset.setAccessible(true);
        Assert.assertTrue("A discarded output queue must be reset before the "
                + "processor is reused",
                ((Boolean) needsReset.invoke(outputBuffer)).booleanValue());
    }


    @Test
    public void testFailedOutputQueueDoesNotConcludeWithFin()
            throws Exception {
        // A non-blocking queue failure sets resetOrFailed under the queue lock
        // before the processor error state is recorded. A concurrent
        // conclusion during that window sees an empty queue; it must still
        // not send a clean FIN for the truncated response.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicBoolean concluded = new AtomicBoolean();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public void concludeStream() {
                concluded.set(true);
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field outputBufferField = Http3Processor.class.getDeclaredField(
                "outputBuffer");
        outputBufferField.setAccessible(true);
        Object outputBuffer = outputBufferField.get(processor);
        Field resetOrFailed = outputBuffer.getClass().getDeclaredField(
                "resetOrFailed");
        resetOrFailed.setAccessible(true);
        resetOrFailed.setBoolean(outputBuffer, true);

        Method hasPendingData = outputBuffer.getClass().getDeclaredMethod(
                "hasPendingData");
        hasPendingData.setAccessible(true);
        Assert.assertEquals("A terminal output-queue failure must be reported "
                + "as pending so a conclusion that passed the suppression "
                + "check before the failure defers FIN", Boolean.TRUE,
                hasPendingData.invoke(outputBuffer));

        Method conclude = Http3Processor.class.getDeclaredMethod(
                "concludeStream", SocketWrapperBase.class);
        conclude.setAccessible(true);
        conclude.invoke(processor, wrapper);

        Assert.assertFalse("A terminal output-queue failure must not be "
                + "concluded with a clean FIN", concluded.get());
    }


    @Test(timeout = 5000)
    public void testZeroInitialHeaderBlockCapacityGrows() throws Exception {
        // The QPACK prefix needs two bytes. A zero initial capacity must grow
        // rather than leave the encoder loop unable to make progress.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);

        Method encode = Http3Processor.class.getDeclaredMethod(
                "encodeHeaderBlock", MimeHeaders.class, int.class);
        encode.setAccessible(true);
        MimeHeaders headers = new MimeHeaders();
        headers.addValue("content-type").setString("text/plain");
        ByteBuffer block = (ByteBuffer) encode.invoke(processor, headers, 0);
        Assert.assertTrue("The encoded header block must contain bytes",
                block.remaining() >= 2);
    }


    @Test
    public void testNegativeContentLengthNotEmitted() throws Exception {
        // Response.setContentLength(long) accepts negative values other than
        // -1. RFC 9110 Section 8.6 defines Content-Length as 1*DIGIT, so a
        // value such as -2 must not be emitted as an invalid field.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        CapturingQuicSocketWrapper wrapper =
                new CapturingQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.getRequest().getResponse().setStatus(200);
        processor.getRequest().getResponse().setContentType("text/plain");
        processor.getRequest().getResponse().setContentLength(-2);

        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(processor, wrapper);

        Map<String,String> headers = decodeResponseHeaderFrame(
                wrapper.captured.toByteArray());
        Assert.assertEquals("200", headers.get(":status"));
        Assert.assertNull("A negative Content-Length other than -1 must not "
                + "be emitted", headers.get("content-length"));
    }


    @Test
    public void testContentLengthValidatedFor304Response() throws Exception {
        // A 304 response may carry Content-Length (RFC 9110 Section 15.4.5),
        // but it must still be a single valid decimal value. The no-body
        // branch must apply the same validation/normalization as responses
        // that may carry content.
        AbstractHttp3Protocol protocol = newHttp3Protocol();

        Http3Processor malformed = new Http3Processor(protocol, TEST_ADAPTER);
        malformed.setStreamId(0);
        CapturingQuicSocketWrapper malformedWrapper =
                new CapturingQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(malformed, malformedWrapper);

        malformed.getRequest().getResponse().setStatus(304);
        malformed.getRequest().getResponse().getMimeHeaders()
                .addValue("content-length").setString("abc");
        malformed.getRequest().getResponse().getMimeHeaders()
                .addValue("content-length").setString("10");

        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(malformed, malformedWrapper);

        Map<String,String> headers = decodeResponseHeaderFrame(
                malformedWrapper.captured.toByteArray());
        Assert.assertNull("A malformed/duplicate Content-Length must be removed "
                + "from a 304 response", headers.get("content-length"));

        // Identical duplicates are collapsed to one field line.
        Http3Processor duplicate = new Http3Processor(protocol, TEST_ADAPTER);
        duplicate.setStreamId(0);
        CapturingQuicSocketWrapper duplicateWrapper =
                new CapturingQuicSocketWrapper();
        setWrapper.invoke(duplicate, duplicateWrapper);
        duplicate.getRequest().getResponse().setStatus(304);
        duplicate.getRequest().getResponse().getMimeHeaders()
                .addValue("content-length").setString("10");
        duplicate.getRequest().getResponse().getMimeHeaders()
                .addValue("content-length").setString("10");
        sendHeaders.invoke(duplicate, duplicateWrapper);

        headers = decodeResponseHeaderFrame(
                duplicateWrapper.captured.toByteArray());
        Assert.assertEquals("10", headers.get("content-length"));
        java.util.Enumeration<String> values = duplicate.getRequest()
                .getResponse().getMimeHeaders().values("content-length");
        Assert.assertTrue(values.hasMoreElements());
        Assert.assertEquals("10", values.nextElement());
        Assert.assertFalse("Identical duplicate Content-Length fields must be "
                + "collapsed for a 304 response", values.hasMoreElements());
    }


    @Test
    public void testResetDuringPreDispatchBodyReadAbortsRequest()
            throws Exception {
        // A reset or connection close observed while pre-reading the request
        // body must abort the request, not dispatch it to the application
        // with a truncated body.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        RecordingTestAdapter adapter = new RecordingTestAdapter();
        protocol.setAdapter(adapter);
        Http3Processor processor = new Http3Processor(protocol, adapter);
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            private int readCount;

            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                if (readCount++ == 0) {
                    return super.read(block, to);
                }
                throw new EOFException("simulated stream reset");
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.RESET_REMOTE;
                    }
                };
            }

            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        ByteBuffer frame = ByteBuffer.allocate(32);
        Qpack.encodeQuicInteger(frame, Constants.H3_DATA);
        Qpack.encodeQuicInteger(frame, 10);
        frame.put(new byte[] { 1, 2, 3 });
        frame.flip();
        byte[] bytes = new byte[frame.remaining()];
        frame.get(bytes);
        wrapper.enqueue(bytes);

        Field headersReceived = Http3Processor.class.getDeclaredField(
                "headersReceived");
        headersReceived.setAccessible(true);
        headersReceived.setBoolean(processor, true);
        Field requestContentLength = Http3Processor.class.getDeclaredField(
                "requestContentLength");
        requestContentLength.setAccessible(true);
        requestContentLength.setLong(processor, 10);
        processor.getRequest().setMethod("POST");
        // The request head is already received in this unit test, so the
        // protocol input buffer is empty and in read mode (a fresh processor
        // buffer is in write mode and must not be parsed as frame data).
        Field inputBufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer input = (ByteBuffer) inputBufferField.get(processor);
        input.clear();
        input.flip();

        processor.service(wrapper);

        Object inputBuffer = processor.getRequest().getInputBuffer();
        Method isStreamAborted = inputBuffer.getClass().getDeclaredMethod(
                "isStreamAborted");
        isStreamAborted.setAccessible(true);
        Method isBodyComplete = inputBuffer.getClass().getDeclaredMethod(
                "isBodyComplete");
        isBodyComplete.setAccessible(true);
        Assert.assertTrue("The reset must be recorded as an aborted stream",
                ((Boolean) isStreamAborted.invoke(inputBuffer)).booleanValue());
        Assert.assertFalse("The partially received body is not complete",
                ((Boolean) isBodyComplete.invoke(inputBuffer)).booleanValue());
        Assert.assertEquals("The request must not be dispatched after a reset "
                + "during the pre-dispatch body read", 0,
                adapter.serviceCount.get());
        Assert.assertEquals("The response stream must be reset with "
                + "H3_REQUEST_INCOMPLETE", H3_REQUEST_INCOMPLETE,
                resetCode.get());
    }


    @Test
    public void testEmptyPathOnlyRejectedForHttpSchemes() throws Exception {
        // RFC 9114 Section 4.3.1 requires a non-empty :path only for http
        // and https URIs; an empty path is allowed for other schemes.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.getRequest().setMethod("GET");
        processor.getRequest().scheme().setString("urn");
        processor.getRequest().requestURI().setBytes(new byte[0], 0, 0);

        Method validate = Http3Processor.class.getDeclaredMethod(
                "validateRequestTarget");
        validate.setAccessible(true);
        validate.invoke(processor);

        processor.getRequest().scheme().setString("https");
        try {
            validate.invoke(processor);
            Assert.fail("An empty :path must be rejected for https");
        } catch (InvocationTargetException ite) {
            Assert.assertTrue("The rejection must be a stream error",
                    ite.getCause() instanceof Http3StreamException);
            Assert.assertEquals(Http3Error.H3_MESSAGE_ERROR,
                    ((Http3StreamException) ite.getCause()).getError());
        }
    }


    @Test
    public void testExtendedConnectProtocolSupportConfiguration()
            throws Exception {
        // An extended CONNECT whose :protocol value is not registered must be
        // answered with 501 (RFC 9220 Section 3); registering the value via
        // the connector property allows the request to be dispatched.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.getRequest().setMethod("CONNECT");
        processor.getRequest().setAttribute(
                Constants.ATTR_EXTENDED_CONNECT_PROTOCOL, "websocket");

        Method unsupported = Http3Processor.class.getDeclaredMethod(
                "isUnsupportedExtendedConnect");
        unsupported.setAccessible(true);
        Assert.assertTrue("An unregistered :protocol value must be "
                + "unsupported", ((Boolean) unsupported.invoke(processor))
                        .booleanValue());

        protocol.setConnectProtocols("websocket, webtransport");
        Assert.assertFalse("A registered :protocol value must be supported",
                ((Boolean) unsupported.invoke(processor)).booleanValue());

        // RFC 9110 Section 7.8: recipients SHOULD match protocol names
        // case-insensitively. RFC 9220 Section 3 inherits the RFC 8441
        // :protocol semantics, so "WebSocket" matches a registered
        // "websocket".
        processor.getRequest().setAttribute(
                Constants.ATTR_EXTENDED_CONNECT_PROTOCOL, "WebSocket");
        Assert.assertFalse("A registered :protocol value must match "
                + "case-insensitively", ((Boolean) unsupported.invoke(processor))
                        .booleanValue());

        protocol.setConnectProtocols(null);
        Assert.assertTrue("Clearing the supported values must make the "
                + ":protocol value unsupported again",
                ((Boolean) unsupported.invoke(processor)).booleanValue());
    }


    @Test
    public void testSuccessfulConnectResponseHasNoFramingOrCompression()
            throws Exception {
        // RFC 9110 Section 9.3.6: a 2xx response to CONNECT must not carry
        // Content-Length or Transfer-Encoding. Its DATA frames are raw tunnel
        // bytes, so representation metadata and content coding must not be
        // applied either, even when connector compression is enabled.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setCompression("on");
        protocol.setCompressionMinSize(0);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        CapturingQuicSocketWrapper wrapper =
                new CapturingQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.getRequest().setMethod("CONNECT");
        processor.getRequest().getMimeHeaders().addValue("accept-encoding")
                .setString("gzip");
        processor.getRequest().getResponse().setStatus(200);
        processor.getRequest().getResponse().setContentLength(123);
        processor.getRequest().getResponse().setContentType("text/plain");
        processor.getRequest().getResponse().getMimeHeaders()
                .addValue("content-language").setString("en");

        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(processor, wrapper);

        Map<String,String> headers = decodeResponseHeaderFrame(
                wrapper.captured.toByteArray());
        Assert.assertEquals("200", headers.get(":status"));
        Assert.assertNull("A 2xx CONNECT response must not carry "
                + "Content-Length", headers.get("content-length"));
        Assert.assertNull("A 2xx CONNECT response must not carry "
                + "Transfer-Encoding", headers.get("transfer-encoding"));
        Assert.assertNull("A 2xx CONNECT response must not carry "
                + "representation metadata", headers.get("content-type"));
        Assert.assertNull("A 2xx CONNECT response must not carry "
                + "representation metadata", headers.get("content-language"));
        Assert.assertNull("Tunnel bytes must not be content-coded",
                headers.get("content-encoding"));

        Field outputBufferField = Http3Processor.class.getDeclaredField(
                "outputBuffer");
        outputBufferField.setAccessible(true);
        Object outputBuffer = outputBufferField.get(processor);
        Field compressionEnabled = outputBuffer.getClass().getDeclaredField(
                "compressionEnabled");
        compressionEnabled.setAccessible(true);
        Assert.assertFalse("A 2xx CONNECT tunnel must not be compressed",
                compressionEnabled.getBoolean(outputBuffer));
    }


    @Test
    public void testConnectErrorResponseAllowsTrailers() throws Exception {
        // RFC 9110 Section 9.3.6: a non-2xx response to CONNECT means the
        // tunnel was not formed, so the response is an ordinary HTTP
        // message and may carry a trailer section (RFC 9114 Section 4.1).
        // Only a 2xx CONNECT response is restricted to DATA frames
        // (RFC 9114 Section 4.4).
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);
        processor.getRequest().setMethod("CONNECT");

        Method trailersAllowed = Http3Processor.class.getDeclaredMethod(
                "isTrailerSectionAllowed");
        trailersAllowed.setAccessible(true);

        processor.getRequest().getResponse().setStatus(407);
        Assert.assertTrue("A non-2xx CONNECT response must allow trailers",
                ((Boolean) trailersAllowed.invoke(processor)).booleanValue());

        processor.getRequest().getResponse().setStatus(200);
        Assert.assertFalse("A 2xx CONNECT response is a tunnel and must not "
                + "carry trailers",
                ((Boolean) trailersAllowed.invoke(processor)).booleanValue());
    }


    @Test
    public void testAllSuccessfulConnectStatusesAreTunnels() throws Exception {
        // RFC 9110 Section 9.3.6: any 2xx response to CONNECT switches the
        // stream to tunnel mode. 204 and 205 are still 2xx responses, so they
        // must not be treated as ordinary no-body responses: no
        // Content-Length may be generated for 205, and the application's
        // writes must not be discarded (voidOutput).
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        for (int status : new int[] { 204, 205 }) {
            Http3Processor processor = new Http3Processor(protocol,
                    TEST_ADAPTER);
            processor.setStreamId(0);

            CapturingQuicSocketWrapper wrapper =
                    new CapturingQuicSocketWrapper();
            Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                    "setSocketWrapper", SocketWrapperBase.class);
            setWrapper.setAccessible(true);
            setWrapper.invoke(processor, wrapper);

            processor.getRequest().setMethod("CONNECT");
            processor.getRequest().getResponse().setStatus(status);

            Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                    "sendResponseHeadersInternal", SocketWrapperBase.class);
            sendHeaders.setAccessible(true);
            sendHeaders.invoke(processor, wrapper);

            Map<String,String> headers = decodeResponseHeaderFrame(
                    wrapper.captured.toByteArray());
            Assert.assertEquals(Integer.toString(status),
                    headers.get(":status"));
            Assert.assertNull("A 2xx CONNECT response must not carry "
                    + "Content-Length", headers.get("content-length"));

            Field outputBufferField = Http3Processor.class.getDeclaredField(
                    "outputBuffer");
            outputBufferField.setAccessible(true);
            Object outputBuffer = outputBufferField.get(processor);
            Field voidOutput = outputBuffer.getClass().getDeclaredField(
                    "voidOutput");
            voidOutput.setAccessible(true);
            Assert.assertFalse("A " + status + " CONNECT response is a "
                    + "tunnel; application writes must not be discarded",
                    voidOutput.getBoolean(outputBuffer));
        }
    }


    @Test
    public void testWriteQueueOverflowResetsStreamAndSuppressesFin()
            throws Exception {
        // When the ordered non-blocking write queue overflows, a frame is
        // dropped and the response is truncated. Even if the application
        // catches the write IOException and returns normally, the connector
        // must reset the stream instead of concluding it with a clean FIN.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        // Send the response headers while writable so they do not occupy the
        // queue when the body write starts.
        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(processor, wrapper);
        wrapper.writable = false;

        // The first large write is accepted as one oversized batch while the
        // stream is not writable. A second independent write must not join
        // that batch: its frames are bounded by the aggregate queue limit and
        // overflow the queue.
        processor.getRequest().getResponse().doWrite(
                ByteBuffer.wrap(new byte[300 * 1024]));
        try {
            processor.getRequest().getResponse().doWrite(
                    ByteBuffer.wrap(new byte[300 * 1024]));
            Assert.fail("The queue overflow must surface as an IOException");
        } catch (IOException expected) {
            // The application swallowed the failure; the connector must still
            // treat the response as truncated.
        }

        Assert.assertEquals("A dropped frame must reset the stream with "
                + "H3_INTERNAL_ERROR", H3_INTERNAL_ERROR, wrapper.resetCode);
        Field streamReset = Http3Processor.class.getDeclaredField(
                "streamReset");
        streamReset.setAccessible(true);
        Assert.assertTrue("The request stream must be marked reset",
                ((AtomicBoolean) streamReset.get(processor)).get());

        Method conclude = Http3Processor.class.getDeclaredMethod(
                "concludeStream", SocketWrapperBase.class);
        conclude.setAccessible(true);
        conclude.invoke(processor, wrapper);
        Assert.assertFalse("A clean FIN must not follow a truncated response",
                wrapper.concluded);
    }


    @Test
    public void testNonBlockingFlushIllegalStateResetsStream()
            throws Exception {
        // If the wrapper closes during a non-blocking flush, the queued
        // response was not delivered. Record the failure and reset the stream
        // instead of silently clearing the queue and reporting success.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper() {
                    @Override
                    protected boolean flushNonBlocking() throws IOException {
                        throw new IllegalStateException("simulated close");
                    }
                };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        processor.getRequest().getResponse().doWrite(
                ByteBuffer.wrap(new byte[4096]));

        Assert.assertEquals("A wrapper close during a non-blocking flush "
                + "must reset the truncated response with H3_INTERNAL_ERROR",
                H3_INTERNAL_ERROR, wrapper.resetCode);
    }


    @Test
    public void testTeOnlyResponseTrailerSendsNoHeadersFrame()
            throws Exception {
        // RFC 9114 Section 4.2 allows TE only in a request header (and only
        // with the value "trailers"). A trailer map containing only TE must
        // therefore be filtered before the size/encodability checks, so no
        // HEADERS frame carrying just the QPACK prefix is sent.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field responseStarted = Http3Processor.class.getDeclaredField(
                "responseStarted");
        responseStarted.setAccessible(true);
        responseStarted.setBoolean(processor, true);
        processor.getRequest().getResponse().setStatus(200);
        processor.getRequest().getResponse().setTrailerFields(
                () -> Map.of("te", "trailers"));

        Method sendTrailers = Http3Processor.class.getDeclaredMethod(
                "sendResponseTrailers", SocketWrapperBase.class);
        sendTrailers.setAccessible(true);
        sendTrailers.invoke(processor, wrapper);

        Assert.assertEquals("A TE-only response trailer map must not produce "
                + "a HEADERS frame", 0, wrapper.sentBytes);
        Field trailersSent = Http3Processor.class.getDeclaredField(
                "trailersSent");
        trailersSent.setAccessible(true);
        Assert.assertTrue("The filtered trailer section must be marked as "
                + "handled", trailersSent.getBoolean(processor));
    }


    @Test
    public void testSingleOversizedFrameQueuedInNonBlockingMode()
            throws Exception {
        // A single application-supplied HEADERS/trailer frame can be larger
        // than the write queue's aggregate cap. With an empty queue it must
        // be accepted and flushed; only the aggregate queue growth of later
        // frames should hit the limit.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        wrapper.writable = false;
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        Field outputBufferField = Http3Processor.class.getDeclaredField(
                "outputBuffer");
        outputBufferField.setAccessible(true);
        Object outputBuffer = outputBufferField.get(processor);
        Method appendFrame = outputBuffer.getClass().getDeclaredMethod(
                "appendFrame", ByteBuffer.class);
        appendFrame.setAccessible(true);

        int frameSize = 300 * 1024;
        int trailingFrameSize = 1024;
        appendFrame.invoke(outputBuffer, ByteBuffer.allocate(frameSize));
        // A frame queued behind the oversized frame must be bounded by the
        // aggregate limit independently of the oversized frame's size.
        appendFrame.invoke(outputBuffer, ByteBuffer.allocate(
                trailingFrameSize));

        Assert.assertEquals("An oversized frame followed by another frame "
                + "must not reset the stream", -1, wrapper.resetCode);
        wrapper.writable = true;
        while (processor.flushBufferedWrite()) {
            // The wrapper can stage only 64 KiB at a time in this stub; drain
            // repeatedly until both frames have been accepted.
        }
        Assert.assertEquals("Both frames must reach the wrapper",
                frameSize + trailingFrameSize, wrapper.sentBytes);
    }


    @Test
    public void testWriteQueueAccountingIsReleasedAfterFlush()
            throws Exception {
        // Once a queued frame has been written to the wrapper, its bytes must
        // no longer count against the queue growth limit. A stale cumulative
        // pendingBytes count rejects a later frame that is logically behind
        // only one exempt oversized frame, and resets a valid response.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        wrapper.writable = false;
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        Field outputBufferField = Http3Processor.class.getDeclaredField(
                "outputBuffer");
        outputBufferField.setAccessible(true);
        Object outputBuffer = outputBufferField.get(processor);
        Method appendFrame = outputBuffer.getClass().getDeclaredMethod(
                "appendFrame", ByteBuffer.class);
        appendFrame.setAccessible(true);

        int frameSize = 300 * 1024;
        int trailingFrameSize = 1024;
        appendFrame.invoke(outputBuffer, ByteBuffer.allocate(frameSize));
        wrapper.writable = true;
        while (processor.flushBufferedWrite()) {
            // Drain the queue completely before appending the next frames.
        }
        Assert.assertEquals("The first oversized frame must reach the "
                + "wrapper", frameSize, wrapper.sentBytes);

        wrapper.writable = false;
        appendFrame.invoke(outputBuffer, ByteBuffer.allocate(frameSize));
        // Only this frame is logically behind the oversized frame, so it is
        // within the aggregate limit regardless of the first frame's bytes.
        appendFrame.invoke(outputBuffer, ByteBuffer.allocate(
                trailingFrameSize));

        Assert.assertEquals("A frame queued after a fully flushed oversized "
                + "frame must not reset the stream", -1, wrapper.resetCode);
        wrapper.writable = true;
        while (processor.flushBufferedWrite()) {
            // Drain the second batch.
        }
        Assert.assertEquals("All frames must reach the wrapper",
                frameSize + frameSize + trailingFrameSize,
                wrapper.sentBytes);
    }


    @Test
    public void testSwallowedResponseIsNotConcludedOrReused()
            throws Exception {
        // ActionCode.CLOSE_NOW calls setSwallowResponse() before it sets the
        // CLOSE_NOW error state. In that window, the output is already
        // suppressed but the error state is still the old one. Conclusion and
        // recycling must consult the suppression predicate so a swallowed
        // response is neither FIN'd nor returned to the processor pool.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.setSwallowResponse();
        Method conclude = Http3Processor.class.getDeclaredMethod(
                "concludeStream", SocketWrapperBase.class);
        conclude.setAccessible(true);
        conclude.invoke(processor, wrapper);
        Assert.assertFalse("A swallowed response must not be concluded with a "
                + "clean FIN", wrapper.concluded);

        processor.recycle();
        Assert.assertFalse("A processor whose response was swallowed must not "
                + "be returned to the shared pool", processor.isReusable());
    }


    @Test
    public void testNonBlockingCompressedTrailersFollowData()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        wrapper.writable = false;
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setWriteListener(processor);

        Field outputBufferField = Http3Processor.class.getDeclaredField(
                "outputBuffer");
        outputBufferField.setAccessible(true);
        Object outputBuffer = outputBufferField.get(processor);
        Method enableCompression = outputBuffer.getClass().getDeclaredMethod(
                "enableCompression");
        enableCompression.setAccessible(true);
        enableCompression.invoke(outputBuffer);
        processor.getRequest().getResponse().setTrailerFields(
                () -> Map.of("x-trailer", "value"));

        processor.getRequest().getResponse().doWrite(
                ByteBuffer.wrap(new byte[1024]));
        processor.finishResponse();

        Method conclude = Http3Processor.class.getDeclaredMethod(
                "concludeStream", SocketWrapperBase.class);
        conclude.setAccessible(true);
        conclude.invoke(processor, wrapper);
        Assert.assertFalse("FIN must wait for compressed data and trailers",
                wrapper.concluded);

        wrapper.writable = true;
        Assert.assertFalse(processor.flushBufferedWrite());
        Assert.assertTrue(wrapper.concluded);

        List<Integer> types = wrapper.frameTypes;
        Assert.assertTrue("Expected HEADERS frames",
                types.contains(Integer.valueOf(Constants.H3_HEADERS)));
        Assert.assertTrue("Expected DATA frames for the compressed body",
                types.contains(Integer.valueOf(Constants.H3_DATA)));
        Assert.assertEquals("The trailer HEADERS frame must be the last "
                + "frame before FIN", Integer.valueOf(Constants.H3_HEADERS),
                types.get(types.size() - 1));
        Assert.assertTrue("Compressed output must reach the wrapper",
                wrapper.sentBytes > 0);
        Assert.assertFalse("The compressed path must not block",
                wrapper.blockingWrite);
    }


    private static void setWriteListener(Http3Processor processor)
            throws Exception {
        Field listenerField = Response.class.getDeclaredField("listener");
        listenerField.setAccessible(true);
        listenerField.set(processor.getRequest().getResponse(),
                new WriteListener() {
                    @Override
                    public void onWritePossible() {
                        // Not used by these direct processor tests.
                    }

                    @Override
                    public void onError(Throwable t) {
                        // Not used by these direct processor tests.
                    }
                });
    }


    @Test
    public void testSectionAckBacklogAbortsWithExcessiveLoad()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        manager.connectionOpen(connection);
        Http3ConnectionManager.ConnectionState state =
                manager.getState(connection);

        // Fill the pending Section Acknowledgment queue to the per-connection
        // limit so the next acknowledgment cannot be queued.
        Field pendingField = Http3ConnectionManager.ConnectionState.class
                .getDeclaredField("pendingSectionAcks");
        pendingField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.List<Long> pending =
                (java.util.List<Long>) pendingField.get(state);
        for (int i = 0;
                i < Http3ConnectionManager.MAX_PENDING_DECODER_INSTRUCTIONS;
                i++) {
            pending.add(Long.valueOf(0));
        }

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method note = Http3Processor.class.getDeclaredMethod(
                "noteSectionAcknowledgment");
        note.setAccessible(true);
        try {
            note.invoke(processor);
            Assert.fail("A full decoder-instruction backlog must not be "
                    + "silently ignored");
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            Assert.assertTrue("Expected Http3Exception, got " + cause,
                    cause instanceof Http3Exception);
            Assert.assertEquals(Http3Error.H3_EXCESSIVE_LOAD,
                    ((Http3Exception) cause).getError());
        }
    }


    @Test
    public void testSectionAckBacklogOnTrailerFailsConnection()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }

            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        AtomicLong streamReset = new AtomicLong(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public boolean resetStream(long appErrorCode) {
                streamReset.compareAndSet(-1, appErrorCode);
                return true;
            }
        };
        manager.connectionOpen(connection);
        Http3ConnectionManager.ConnectionState state =
                manager.getState(connection);

        // Put one dynamic entry in the shared table so a field section with
        // Required Insert Count = 1 can be decoded, then fill the pending
        // Section Acknowledgment queue to the per-connection limit. The
        // trailer decode must fail the connection (H3_EXCESSIVE_LOAD), not
        // reset only the stream with that connection-level code.
        QpackDecoder decoder = manager.getSharedDecoder();
        ByteBuffer capacity = ByteBuffer.allocate(16);
        Qpack.encodeIrp(capacity, 0x20, 5, Qpack.DEFAULT_TABLE_SIZE);
        capacity.flip();
        decoder.processInstruction(capacity);
        ByteBuffer insert = ByteBuffer.allocate(32);
        Qpack.encodeIrp(insert, 0x80 | 0x40, 6, 1);
        Qpack.encodeIrp(insert, 0, 7, 1);
        insert.put((byte) 'x');
        insert.flip();
        decoder.processInstruction(insert);

        Field pendingField = Http3ConnectionManager.ConnectionState.class
                .getDeclaredField("pendingSectionAcks");
        pendingField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.List<Long> pending =
                (java.util.List<Long>) pendingField.get(state);
        for (int i = 0;
                i < Http3ConnectionManager.MAX_PENDING_DECODER_INSTRUCTIONS;
                i++) {
            pending.add(Long.valueOf(0));
        }

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setSharedQpackDecoder(decoder);
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // A valid field section prefix with Required Insert Count = 1 and no
        // field lines: the decode succeeds, then the Section Acknowledgment
        // hits the full backlog.
        ByteBuffer trailerPayload = ByteBuffer.allocate(2);
        trailerPayload.put((byte) 0x02);
        trailerPayload.put((byte) 0x00);
        Field trailerField = processor.getRequest().getInputBuffer()
                .getClass().getDeclaredField("trailerPayload");
        trailerField.setAccessible(true);
        trailerField.set(processor.getRequest().getInputBuffer(),
                trailerPayload);
        Method finish = processor.getRequest().getInputBuffer().getClass()
                .getDeclaredMethod("finishTrailerSection",
                        SocketWrapperBase.class);
        finish.setAccessible(true);
        finish.invoke(processor.getRequest().getInputBuffer(), wrapper);

        // The application must not see a clean EOF for a request body that
        // was abandoned by a connection-level failure. The read must report
        // an I/O error, and the readiness/body-complete answers must agree.
        Method doRead = processor.getRequest().getInputBuffer().getClass()
                .getDeclaredMethod("doRead", ApplicationBufferHandler.class);
        doRead.setAccessible(true);
        try {
            doRead.invoke(processor.getRequest().getInputBuffer(),
                    ApplicationBufferHandler.EMPTY);
            Assert.fail("A connection-level trailer failure must surface as "
                    + "an IOException, not a clean EOF");
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            Assert.assertTrue("Expected an IOException, got " + cause,
                    cause instanceof IOException);
        }

        Method trailerReady = Http3Processor.class.getDeclaredMethod(
                "isTrailerFieldsReady");
        trailerReady.setAccessible(true);
        Assert.assertEquals("Trailer fields must not be reported ready "
                + "after a connection-level failure", Boolean.FALSE,
                trailerReady.invoke(processor));

        Method bodyFullyRead = Http3Processor.class.getDeclaredMethod(
                "isRequestBodyFullyRead");
        bodyFullyRead.setAccessible(true);
        Assert.assertEquals("An incomplete body must not be reported fully "
                + "read after a connection-level failure", Boolean.FALSE,
                bodyFullyRead.invoke(processor));

        Method trailerSupported = Http3Processor.class.getDeclaredMethod(
                "isTrailerFieldsSupported");
        trailerSupported.setAccessible(true);
        Assert.assertEquals("Trailer registration must be closed after a "
                + "connection-level failure", Boolean.FALSE,
                trailerSupported.invoke(processor));

        Method readyForRead = Http3Processor.class.getDeclaredMethod(
                "isReadyForRead");
        readyForRead.setAccessible(true);
        Assert.assertEquals("An async reader must be woken after a "
                + "connection-level failure so it observes the error",
                Boolean.TRUE, readyForRead.invoke(processor));

        Assert.assertEquals("The connection must be failed with "
                + "H3_EXCESSIVE_LOAD", Http3Error.H3_EXCESSIVE_LOAD.getCode(),
                connectionFailure.get());
        Assert.assertEquals("A connection-level error must not be sent as "
                + "a stream reset", -1, streamReset.get());
    }


    @Test
    public void testExtendedConnectUsesConnectionSettingsSnapshot()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setEnableConnectProtocol(false);
        protocol.setAllowSchemeMismatch(true);
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);
        Http3ConnectionManager.ConnectionState state =
                manager.getState(connection);

        // The connection advertised ENABLE_CONNECT_PROTOCOL as disabled.
        // Changing the live connector property afterwards must not make this
        // connection accept an extended CONNECT it never negotiated.
        protocol.setEnableConnectProtocol(true);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setConnectionState(state);
        processor.emitHeader(":method", "CONNECT");
        processor.emitHeader(":scheme", "https");
        processor.emitHeader(":authority", "127.0.0.1:443");
        processor.emitHeader(":path", "/simple");
        processor.emitHeader(":protocol", "websocket");

        Method validate = Http3Processor.class.getDeclaredMethod(
                "validateHeadersInternal");
        validate.setAccessible(true);
        try {
            validate.invoke(processor);
            Assert.fail("Extended CONNECT accepted although the connection "
                    + "advertised ENABLE_CONNECT_PROTOCOL as disabled");
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            Assert.assertTrue("Expected Http3Exception, got " + cause,
                    cause instanceof Http3Exception);
            Assert.assertEquals(Http3Error.H3_MESSAGE_ERROR,
                    ((Http3Exception) cause).getError());
        }
    }


    @Test
    public void testPartialDataNotReadyWithoutAvailableBytes() throws Exception {
        Http3Processor processor = new Http3Processor(
                newHttp3Protocol(), TEST_ADAPTER);
        processor.setStreamId(0);
        Http3Processor testProcessor = processor;
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            private final QuicStream stream = new StubQuicStream();

            @Override
            public QuicStream getQuicStream() {
                return stream;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // The DATA frame has been partially consumed, but its remaining
        // payload bytes are neither in the protocol input buffer nor
        // available from the transport. The next read would would-block, so
        // the stream must not be reported as ready (a ReadListener looping
        // on isReady() would spin).
        Object h3Input = testProcessor.getRequest().getInputBuffer();
        Field partialDataRemaining = h3Input.getClass().getDeclaredField(
                "partialDataRemaining");
        partialDataRemaining.setAccessible(true);
        partialDataRemaining.setInt(h3Input, 10);
        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(testProcessor, false);
        Field inputBufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        inputBufferField.setAccessible(true);
        ((ByteBuffer) inputBufferField.get(testProcessor)).clear();

        Assert.assertFalse("A partial DATA frame whose remaining bytes are "
                + "not available must not be reported as ready",
                testProcessor.isReadyForRead());
    }


    @Test
    public void testPartialDataPayloadReadyWithBufferedBytes() throws Exception {
        Http3Processor processor = new Http3Processor(
                newHttp3Protocol(), TEST_ADAPTER);
        processor.setStreamId(0);
        Http3Processor testProcessor = processor;
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            private final QuicStream stream = new StubQuicStream();

            @Override
            public QuicStream getQuicStream() {
                return stream;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // A DATA frame header declaring 1000 payload bytes followed by 500
        // payload bytes that are already buffered. The bytes can be delivered
        // immediately even though the frame (and no new socket event) is not
        // complete yet, so the stream must be reported as ready.
        Field inputBufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(
                testProcessor);
        inputBuffer.clear();
        Qpack.encodeQuicInteger(inputBuffer, Constants.H3_DATA);
        Qpack.encodeQuicInteger(inputBuffer, 1000);
        inputBuffer.put(new byte[500]);
        inputBuffer.flip();
        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(testProcessor, true);

        Assert.assertTrue("A partially delivered DATA frame with payload "
                + "bytes already buffered must be reported as ready",
                testProcessor.isReadyForRead());
    }


    @Test
    public void testPartialDataReadyWithPreBufferedBody() throws Exception {
        Http3Processor processor = new Http3Processor(
                newHttp3Protocol(), TEST_ADAPTER);
        processor.setStreamId(0);
        Http3Processor testProcessor = processor;
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            private final QuicStream stream = new StubQuicStream();

            @Override
            public QuicStream getQuicStream() {
                return stream;
            }

            @Override
            public boolean isReadyForRead() {
                return false;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // A partially delivered DATA frame leaves its remainder in the
        // transport, but the pre-dispatch reader already published part of
        // the body into the Http3InputBuffer. The buffered body bytes are
        // available to the application even though the rest of the frame is
        // neither in the protocol input buffer nor in the transport yet, so
        // the stream must be reported as ready.
        Object h3Input = testProcessor.getRequest().getInputBuffer();
        Method setData = h3Input.getClass().getDeclaredMethod("setData",
                ByteBuffer.class);
        setData.setAccessible(true);
        ByteBuffer data = ByteBuffer.allocate(8192);
        data.position(data.capacity());
        data.flip();
        setData.invoke(h3Input, data);
        Field partialDataRemaining = h3Input.getClass().getDeclaredField(
                "partialDataRemaining");
        partialDataRemaining.setAccessible(true);
        partialDataRemaining.setInt(h3Input, 4464);

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(testProcessor, false);
        Field inputBufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        inputBufferField.setAccessible(true);
        ((ByteBuffer) inputBufferField.get(testProcessor)).clear();

        Assert.assertTrue("A partial DATA frame whose remainder is not yet "
                + "available must still be reported as ready while the "
                + "Http3InputBuffer holds buffered body bytes",
                testProcessor.isReadyForRead());
    }


    @Test
    public void testBodyReadAfterTerminalStateFails() throws Exception {
        assertBodyReadFailsAfterTerminalState("streamReset",
                new AtomicBoolean(true));
        assertBodyReadFailsAfterTerminalState("bodyFrameError",
                Http3Error.H3_FRAME_UNEXPECTED);
        assertBodyReadFailsAfterTerminalState("connectionFailed",
                Boolean.TRUE);
    }


    private void assertBodyReadFailsAfterTerminalState(String fieldName,
            Object value) throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            private final QuicStream stream = new StubQuicStream();

            @Override
            public QuicStream getQuicStream() {
                return stream;
            }

            @Override
            public int read(boolean block, ByteBuffer to) {
                return 0;
            }

            @Override
            public boolean isReadyForRead() {
                return false;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field terminalField = Http3Processor.class.getDeclaredField(fieldName);
        terminalField.setAccessible(true);
        terminalField.set(processor, value);

        Field inputBufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        Qpack.encodeQuicInteger(inputBuffer, Constants.H3_DATA);
        Qpack.encodeQuicInteger(inputBuffer, 5);
        inputBuffer.put(new byte[5]);
        inputBuffer.flip();
        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);

        try {
            processor.getRequest().getInputBuffer().doRead(
                    ApplicationBufferHandler.EMPTY);
            Assert.fail("A body read after terminal state [" + fieldName
                    + "] must fail with an IOException");
        } catch (IOException expected) {
            // Expected
        }
    }


    @Test
    public void testCleanFinWithContentLengthShortfallIsNotComplete()
            throws Exception {
        // A clean FIN before the declared Content-Length has been received is
        // a malformed request. The readiness probes must not report the body
        // (or an empty trailer map) as complete before the read path has
        // surfaced the shortfall.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field contentLength = Http3Processor.class.getDeclaredField(
                "requestContentLength");
        contentLength.setAccessible(true);
        contentLength.setLong(processor, 5);
        Field dataReceived = Http3Processor.class.getDeclaredField(
                "totalDataReceived");
        dataReceived.setAccessible(true);
        dataReceived.setLong(processor, 3);

        Object inBuf = processor.getRequest().getInputBuffer();
        Method setStreamClosed = inBuf.getClass().getDeclaredMethod(
                "setStreamClosed");
        setStreamClosed.setAccessible(true);
        setStreamClosed.invoke(inBuf);

        Method bodyFullyRead = Http3Processor.class.getDeclaredMethod(
                "isRequestBodyFullyRead");
        bodyFullyRead.setAccessible(true);
        Assert.assertFalse("A clean FIN with a Content-Length shortfall "
                + "must not report the body as fully read",
                ((Boolean) bodyFullyRead.invoke(processor)).booleanValue());

        Method trailerReady = Http3Processor.class.getDeclaredMethod(
                "isTrailerFieldsReady");
        trailerReady.setAccessible(true);
        Assert.assertFalse("A clean FIN with a Content-Length shortfall "
                + "must not report trailer fields as ready",
                ((Boolean) trailerReady.invoke(processor)).booleanValue());
    }


    @Test
    public void testCleanFinishProbeDoesNotRaceBodyRead() throws Exception {
        // isRequestStreamCleanlyFinished() decides whether finishResponse()
        // may send FIN before the after-response scan. If an application
        // thread is still reading the body, the probe must not take a stale
        // snapshot; defer the FIN instead.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field lockField = Http3Processor.class.getDeclaredField(
                "inputReadLock");
        lockField.setAccessible(true);
        ReentrantLock inputReadLock = (ReentrantLock) lockField.get(processor);

        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread holder = new Thread(() -> {
            inputReadLock.lock();
            try {
                locked.countDown();
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                inputReadLock.unlock();
            }
        }, "http3-read-lock-holder");
        holder.setDaemon(true);
        holder.start();
        locked.await();
        try {
            Method cleanFinish = Http3Processor.class.getDeclaredMethod(
                    "isRequestStreamCleanlyFinished");
            cleanFinish.setAccessible(true);
            Assert.assertFalse("The clean-finish probe must defer while a "
                    + "body read holds the input lock",
                    ((Boolean) cleanFinish.invoke(processor)).booleanValue());
        } finally {
            release.countDown();
            holder.join();
        }
    }


    @Test
    public void testReadinessDoesNotProbeWrapperWhileReaderHoldsLock()
            throws Exception {
        // QuicSocketWrapper.isReadyForRead() reads into the wrapper's
        // SocketBufferHandler, which is not synchronised against a
        // concurrent SocketWrapperBase.read(). While another thread holds
        // inputReadLock, the readiness probe must not touch that buffer; it
        // must register read interest and report not-ready instead.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger probes = new AtomicInteger();
        AtomicInteger interests = new AtomicInteger();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public boolean isReadyForRead() {
                probes.incrementAndGet();
                return true;
            }

            @Override
            public void registerReadInterest() {
                interests.incrementAndGet();
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream();
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field lockField = Http3Processor.class.getDeclaredField(
                "inputReadLock");
        lockField.setAccessible(true);
        ReentrantLock inputReadLock = (ReentrantLock) lockField.get(processor);
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread holder = new Thread(() -> {
            inputReadLock.lock();
            try {
                locked.countDown();
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                inputReadLock.unlock();
            }
        }, "http3-readiness-lock-holder");
        holder.setDaemon(true);
        holder.start();
        locked.await();
        try {
            Assert.assertFalse("Readiness must not report ready while a "
                    + "reader holds the input lock",
                    processor.isReadyForRead());
        } finally {
            release.countDown();
            holder.join();
        }

        Assert.assertEquals("Readiness must not probe the QUIC wrapper read "
                + "buffer while a reader holds the input lock", 0,
                probes.get());
        Assert.assertTrue("Readiness must register read interest when the "
                + "input lock is held", interests.get() > 0);
    }


    @Test
    public void testResetStateWithoutReadExceptionIsNotReady() throws Exception {
        // The generic QuicSocketWrapper contract does not require a reset to
        // be reported as an EOFException. If the reset state is observed
        // directly, the request must still be classified as aborted; it must
        // not report a complete empty body or ready trailer fields.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.RESET_REMOTE;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field pendingSkip = inBuf.getClass().getDeclaredField(
                "pendingSkipRemaining");
        pendingSkip.setAccessible(true);
        pendingSkip.setLong(inBuf, 10L);
        Field inputBufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.flip();

        Method trailerReady = Http3Processor.class.getDeclaredMethod(
                "isTrailerFieldsReady");
        trailerReady.setAccessible(true);
        Assert.assertFalse("A reset request must not report ready trailers",
                ((Boolean) trailerReady.invoke(processor)).booleanValue());
        Assert.assertFalse("A reset request must not report a complete body",
                processor.isRequestBodyFullyRead());
    }


    @Test
    public void testTrailerReadinessAfterLocalResetDoesNotReadStream()
            throws Exception {
        // A response-write failure can reset the stream after the body was
        // fully read. A later getTrailerFields() readiness call must not parse
        // residual bytes of the abandoned request stream: a clean FIN with a
        // partial frame header would otherwise be classified as a truncated
        // frame and fail the whole connection with H3_FRAME_ERROR.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger reads = new AtomicInteger();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                reads.incrementAndGet();
                return -1;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field streamReset = Http3Processor.class.getDeclaredField(
                "streamReset");
        streamReset.setAccessible(true);
        ((AtomicBoolean) streamReset.get(processor)).set(true);

        Object inBuf = processor.getRequest().getInputBuffer();
        Method setBodyComplete = inBuf.getClass().getDeclaredMethod(
                "setBodyComplete", Boolean.TYPE);
        setBodyComplete.setAccessible(true);
        setBodyComplete.invoke(inBuf, Boolean.TRUE);

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        // The first byte of a frame header, left over before the reset.
        inputBuffer.put((byte) 0);
        inputBuffer.flip();

        Method trailerReady = Http3Processor.class.getDeclaredMethod(
                "isTrailerFieldsReady");
        trailerReady.setAccessible(true);
        Assert.assertEquals("A reset stream with a complete body must not "
                + "report ready trailer fields", Boolean.FALSE,
                trailerReady.invoke(processor));
        Assert.assertNull("Readiness on an abandoned stream must not fail the "
                + "connection", wrapper.connection.failureCode);
        Assert.assertEquals("Readiness on an abandoned stream must not touch "
                + "the wrapper", 0, reads.get());
    }


    @Test
    public void testSwallowedResponseTrailerReadinessDoesNotReadStream()
            throws Exception {
        // A swallowed response (ActionCode.CLOSE_NOW) abandons the exchange.
        // Trailer readiness must not read the residual request bytes: a clean
        // FIN in the middle of a frame would otherwise be classified as a
        // truncated frame and fail the whole connection.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger reads = new AtomicInteger();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                reads.incrementAndGet();
                return -1;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.setSwallowResponse();

        Object inBuf = processor.getRequest().getInputBuffer();
        Method setBodyComplete = inBuf.getClass().getDeclaredMethod(
                "setBodyComplete", Boolean.TYPE);
        setBodyComplete.setAccessible(true);
        setBodyComplete.invoke(inBuf, Boolean.TRUE);

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        // The first byte of a frame header, left over before abandonment.
        inputBuffer.put((byte) 0);
        inputBuffer.flip();

        Method trailerReady = Http3Processor.class.getDeclaredMethod(
                "isTrailerFieldsReady");
        trailerReady.setAccessible(true);
        Assert.assertEquals("A swallowed response must not report ready "
                + "trailer fields", Boolean.FALSE,
                trailerReady.invoke(processor));
        Assert.assertNull("Readiness on a swallowed response must not fail the "
                + "connection", wrapper.connection.failureCode);
        Assert.assertEquals("Readiness on a swallowed response must not touch "
                + "the wrapper", 0, reads.get());
    }


    @Test
    public void testAllowedTrailerHeadersGetterAndBlankValue() {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Assert.assertEquals("The default allowed trailer header list must be "
                + "empty", "", protocol.getAllowedTrailerHeaders());

        protocol.setAllowedTrailerHeaders("Cookie, X-Checksum");
        String allowed = protocol.getAllowedTrailerHeaders();
        Assert.assertTrue("The getter must expose the configured names: "
                + allowed, allowed.contains("cookie"));
        Assert.assertTrue("The getter must expose the configured names: "
                + allowed, allowed.contains("x-checksum"));
        Assert.assertTrue("Allowed trailer header matching must stay "
                + "case-insensitive", protocol.isTrailerHeaderAllowed("COOKIE"));

        protocol.setAllowedTrailerHeaders("");
        Assert.assertEquals("A blank value must clear the allowed trailer "
                + "header list", "", protocol.getAllowedTrailerHeaders());
        Assert.assertFalse("A blank value must not allow an empty field name",
                protocol.isTrailerHeaderAllowed(""));
        Assert.assertFalse("A blank value must clear the previous entries",
                protocol.isTrailerHeaderAllowed("cookie"));

        protocol.setAllowedTrailerHeaders("cookie");
        protocol.setAllowedTrailerHeaders(" , ");
        Assert.assertFalse("A list of blank tokens must clear the previous "
                + "entries", protocol.isTrailerHeaderAllowed("cookie"));
        Assert.assertFalse("A list of blank tokens must not allow an empty "
                + "field name", protocol.isTrailerHeaderAllowed(""));
    }


    @Test
    public void testSwallowedResponseTrailerFieldsNotSupported()
            throws Exception {
        // sendResponseTrailers() checks isOutputSuppressed(), so a supplier
        // registered after ActionCode.CLOSE_NOW could never be sent. The
        // Servlet API must report trailers as unsupported in that state.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        processor.setSwallowResponse();

        Method trailerSupported = Http3Processor.class.getDeclaredMethod(
                "isTrailerFieldsSupported");
        trailerSupported.setAccessible(true);
        Assert.assertEquals("Trailer fields must not be reported as supported "
                + "after the response output was suppressed", Boolean.FALSE,
                trailerSupported.invoke(processor));
    }


    @Test
    public void testTrailerFieldsNotReadyAfterResetBeforeBodyRead()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                throw new EOFException("simulated reset");
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method ready = Http3Processor.class.getDeclaredMethod(
                "isTrailerFieldsReady");
        ready.setAccessible(true);
        Assert.assertFalse("Trailer fields must not be reported ready for a "
                + "stream aborted before the body was complete",
                ((Boolean) ready.invoke(processor)).booleanValue());
    }


    @Test
    public void testTrailerReadHardIoErrorIsTerminal() throws Exception {
        // A non-EOF IOException during the opportunistic trailer scan means
        // the stream cannot make further progress. It must be recorded as a
        // terminal state; otherwise every later isTrailerFieldsReady() call
        // repeats the failing read and hides the error from the application.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger reads = new AtomicInteger();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                reads.incrementAndGet();
                throw new IOException("simulated transport read failure");
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream();
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method trailerReady = Http3Processor.class.getDeclaredMethod(
                "isTrailerFieldsReady");
        trailerReady.setAccessible(true);
        Assert.assertEquals("A failing trailer read must not report ready "
                + "trailer fields", Boolean.FALSE, trailerReady.invoke(processor));
        int readsAfterFirstCall = reads.get();
        Assert.assertTrue("The trailer scan must attempt the underlying read",
                readsAfterFirstCall > 0);

        Assert.assertEquals("A terminal trailer-read failure must stay "
                + "terminal", Boolean.FALSE, trailerReady.invoke(processor));
        Assert.assertEquals("A terminal trailer-read failure must not repeat "
                + "the failing read", readsAfterFirstCall, reads.get());
    }


    @Test
    public void testPausedConnectorRejectsNewStream() throws Exception {
        // New streams on an already established QUIC connection must be
        // rejected while the connector is paused, not dispatched. The
        // request is unprocessed, so H3_REQUEST_REJECTED tells the client it
        // can retry on another connection.
        AbstractHttp3Protocol protocol = new Http3OpenSSLProtocol() {
            @Override
            public boolean isPaused() {
                return true;
            }
        };
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };

        SocketState state = processor.service(wrapper);
        Assert.assertEquals(SocketState.CLOSED, state);
        Assert.assertEquals("A paused connector must reject the new stream "
                + "with H3_REQUEST_REJECTED", H3_REQUEST_REJECTED,
                resetCode.get());
    }


    @Test
    public void testServiceIOExceptionQueuesStreamCancellation()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);
        Http3ConnectionManager.ConnectionState state =
                manager.getState(connection);
        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                throw new IOException("simulated transport read failure");
            }

            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        try {
            processor.service(wrapper);
            Assert.fail("Expected the simulated read failure to propagate");
        } catch (IOException expected) {
            // Expected
        }
        Assert.assertEquals("An IOException that tears down the stream "
                + "must reset it with H3_INTERNAL_ERROR", H3_INTERNAL_ERROR,
                resetCode.get());

        Field pendingField = Http3ConnectionManager.ConnectionState.class
                .getDeclaredField("pendingCancellations");
        pendingField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Set<Long> pending =
                (java.util.Set<Long>) pendingField.get(state);
        Assert.assertTrue("An IOException that tears down the stream must "
                + "queue a QPACK Stream Cancellation",
                pending.contains(Long.valueOf(0)));
    }


    @Test
    public void testServiceErrorStateResetsStream() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }

            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        byte[] fieldSection = Base64.getDecoder().decode(buildFieldSection(
                ":method", "GET", ":scheme", "http",
                ":authority", "127.0.0.1:80", ":path", "/simple"));
        wrapper.enqueue(Base64.getDecoder().decode(
                buildFrameB64(0x01, fieldSection)));

        Method setErrorState = AbstractProcessor.class.getDeclaredMethod(
                "setErrorState", ErrorState.class, Throwable.class);
        setErrorState.setAccessible(true);
        setErrorState.invoke(processor, ErrorState.CLOSE_NOW,
                new IOException("simulated response failure"));

        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));
        Assert.assertEquals("An error-state service exit must reset the "
                + "truncated response with H3_INTERNAL_ERROR",
                H3_INTERNAL_ERROR, resetCode.get());
    }


    @Test
    public void testDispatchEndRequestScanFailureResetsStream()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                throw new IOException("simulated post-response read failure");
            }

            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method dispatch = Http3Processor.class.getDeclaredMethod(
                "dispatchEndRequest");
        dispatch.setAccessible(true);
        Assert.assertEquals(SocketState.CLOSED,
                dispatch.invoke(processor));
        Assert.assertEquals("A post-response scan I/O failure must reset "
                + "the stream with H3_INTERNAL_ERROR", H3_INTERNAL_ERROR,
                resetCode.get());
    }


    @Test
    public void testMandatoryResponseFieldsRetainedUnderPeerLimit()
            throws Exception {
        // RFC 9110 Sections 6.6.1, 15.5.6 and 15.4.5/15.3.7 make Date,
        // Allow and Content-Location mandatory in particular responses. The
        // peer's SETTINGS_MAX_FIELD_SECTION_SIZE is advisory (RFC 9114
        // Section 4.2.2) and must not cause them to be dropped.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        Http3ConnectionManager.ConnectionState state =
                new Http3ConnectionManager.ConnectionState(null);
        state.setPeerMaxFieldSectionSize(80);
        Field connectionState = Http3Processor.class.getDeclaredField(
                "connectionState");
        connectionState.setAccessible(true);
        connectionState.set(processor, state);

        org.apache.tomcat.util.http.MimeHeaders headers =
                new org.apache.tomcat.util.http.MimeHeaders();
        headers.addValue(":status").setString("405");
        headers.addValue("date").setString("Tue, 15 Nov 1994 08:12:31 GMT");
        headers.addValue("allow").setString("GET, HEAD");
        headers.addValue("content-location").setString("/other");
        headers.addValue("content-type").setString("text/plain");
        headers.addValue("x-extra-1").setString("aaaaaaaaaaaaaaaa");
        headers.addValue("x-extra-2").setString("bbbbbbbbbbbbbbbb");

        Method apply = Http3Processor.class.getDeclaredMethod(
                "applyPeerFieldSectionLimit",
                org.apache.tomcat.util.http.MimeHeaders.class);
        apply.setAccessible(true);
        org.apache.tomcat.util.http.MimeHeaders reduced =
                (org.apache.tomcat.util.http.MimeHeaders) apply.invoke(
                        processor, headers);

        Assert.assertNotNull("Date must be retained", reduced.getValue("date"));
        Assert.assertNotNull("Allow must be retained",
                reduced.getValue("allow"));
        Assert.assertNotNull("Content-Location must be retained",
                reduced.getValue("content-location"));
        Assert.assertNotNull("content-type must be retained",
                reduced.getValue("content-type"));
        Assert.assertNull("A non-essential field must be dropped",
                reduced.getValue("x-extra-1"));
    }


    @Test
    public void testNullAndMalformedContentLengthHeadersHandled()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();

        // A null-valued Content-Length added through the internal MimeHeaders
        // API must not suppress the automatic value: the QPACK encoder drops
        // null fields, so the response would otherwise have no length despite
        // response.getContentLengthLong() being set.
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        org.apache.coyote.Response response =
                processor.getRequest().getResponse();
        response.setStatus(200);
        response.setContentLength(123);
        response.getMimeHeaders().addValue("content-length");

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(processor, wrapper);

        Assert.assertNotNull("The automatic Content-Length must replace the "
                + "null-valued header",
                response.getMimeHeaders().getValue("content-length"));
        Assert.assertEquals("123",
                response.getMimeHeaders().getValue("content-length").toString());

        // A malformed internal Content-Length must be removed rather than
        // encoded as an invalid field line.
        Http3Processor malformed =
                new Http3Processor(protocol, TEST_ADAPTER);
        malformed.setStreamId(0);
        org.apache.coyote.Response malformedResponse =
                malformed.getRequest().getResponse();
        malformedResponse.setStatus(200);
        malformedResponse.getMimeHeaders().addValue("content-length")
                .setString("not-a-number");
        setWrapper.invoke(malformed, wrapper);
        sendHeaders.invoke(malformed, wrapper);

        Assert.assertNull("A malformed Content-Length must be removed",
                malformedResponse.getMimeHeaders().getValue("content-length"));
    }


    @Test
    public void testDuplicateContentLengthHeadersAreNormalized()
            throws Exception {
        // RFC 9110 Section 8.6: a sender MUST NOT generate multiple
        // Content-Length fields in a single message. A Valve or filter using
        // the internal MimeHeaders API can add more than one; the response
        // must collapse identical values (and replace conflicting ones with
        // the response's content length) before QPACK encodes every field
        // line.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        org.apache.coyote.Response response =
                processor.getRequest().getResponse();
        response.setStatus(200);
        response.getMimeHeaders().addValue("content-length").setString("10");
        response.getMimeHeaders().addValue("content-length").setString("10");

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(processor, wrapper);

        java.util.Enumeration<String> values =
                response.getMimeHeaders().values("content-length");
        Assert.assertTrue("The first Content-Length must remain",
                values.hasMoreElements());
        Assert.assertEquals("10", values.nextElement());
        Assert.assertFalse("Identical duplicate Content-Length fields must "
                + "be collapsed", values.hasMoreElements());

        // Conflicting values cannot be collapsed to one of the supplied
        // values; use the response's content length instead.
        Http3Processor conflicting = new Http3Processor(protocol,
                TEST_ADAPTER);
        conflicting.setStreamId(0);
        org.apache.coyote.Response conflictingResponse =
                conflicting.getRequest().getResponse();
        conflictingResponse.setStatus(200);
        conflictingResponse.setContentLength(20);
        conflictingResponse.getMimeHeaders().addValue("content-length")
                .setString("10");
        conflictingResponse.getMimeHeaders().addValue("content-length")
                .setString("30");
        setWrapper.invoke(conflicting, wrapper);
        sendHeaders.invoke(conflicting, wrapper);

        values = conflictingResponse.getMimeHeaders()
                .values("content-length");
        Assert.assertTrue("A Content-Length must be generated",
                values.hasMoreElements());
        Assert.assertEquals("20", values.nextElement());
        Assert.assertFalse("Conflicting duplicate Content-Length fields "
                + "must not both be emitted", values.hasMoreElements());
    }


    @Test
    public void testContentLengthConflictUsesCoyoteLength() throws Exception {
        // RFC 9110 Section 8.6 requires Content-Length to describe the actual
        // content. When the coyote response length is set it must win over an
        // application/Valve-supplied header with a different value, as it
        // does for HTTP/1.1.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        CapturingQuicSocketWrapper wrapper = new CapturingQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        processor.getRequest().getResponse().setStatus(200);
        processor.getRequest().getResponse().setContentLength(20);
        processor.getRequest().getResponse().getMimeHeaders()
                .addValue("content-length").setString("10");

        Method sendHeaders = Http3Processor.class.getDeclaredMethod(
                "sendResponseHeadersInternal", SocketWrapperBase.class);
        sendHeaders.setAccessible(true);
        sendHeaders.invoke(processor, wrapper);

        Map<String,String> headers = decodeResponseHeaderFrame(
                wrapper.captured.toByteArray());
        Assert.assertEquals("The coyote response length must replace the "
                + "conflicting application value", "20",
                headers.get("content-length"));
    }


    @Test
    public void testMalformedFieldSectionIsAccessLogged() throws Exception {
        // A malformed field section rejected during QPACK decoding must still
        // be access-logged and counted, even though headersReceived is never
        // set. The HEADERS payload contains a literal name "X" (uppercase),
        // which emitHeader rejects after decoding starts.
        RecordingTestAdapter adapter = new RecordingTestAdapter();
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(adapter);
        Http3Processor processor = new Http3Processor(protocol, adapter);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        wrapper.enqueue(new byte[] {
                0x01, 0x06, // HEADERS frame, length 6
                0x00, 0x00, // QPACK prefix: Required Insert Count 0, Base 0
                0x31, 'X',  // literal field line with literal name "X"
                0x01, 'y'   // literal value "y"
        });
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));
        Assert.assertEquals("A malformed field section must be access-logged",
                1, adapter.logCount.get());
    }


    @Test
    public void testTruncatedQpackFieldSectionIsAccessLogged()
            throws Exception {
        RecordingTestAdapter adapter = new RecordingTestAdapter();
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(adapter);
        Http3Processor processor = new Http3Processor(protocol, adapter);
        processor.setStreamId(0);

        // A HEADERS frame whose QPACK payload contains only the Required
        // Insert Count byte. The decoder cannot interpret the truncated prefix
        // and the stream is reset with QPACK_DECOMPRESSION_FAILED; the
        // request must still be access-logged and counted.
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        wrapper.enqueue(new byte[] {
                0x01, 0x01, // HEADERS frame, length 1
                0x00        // QPACK prefix: RIC 0, no Delta Base
        });
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Assert.assertEquals(SocketState.CLOSED, processor.service(wrapper));
        Assert.assertEquals("A truncated QPACK field section must be "
                + "access-logged", 1, adapter.logCount.get());
        Assert.assertEquals("A truncated QPACK field section must be "
                + "counted as an error", 1, processor.getRequest()
                        .getRequestProcessor().getErrorCount());
        Assert.assertEquals("A truncated QPACK field section must be "
                + "access-logged as a malformed request",
                HttpServletResponse.SC_BAD_REQUEST,
                processor.getRequest().getResponse().getStatus());
    }


    @Test
    public void testLogValueEscaping() {
        // Peer-controlled QPACK values may contain CR/LF. Logging them raw
        // would allow log forging; the helper must render control bytes in
        // 0xNN form.
        Assert.assertEquals("abc", Http3Log.printable("abc"));
        Assert.assertEquals("a0x0d0x0ab", Http3Log.printable("a\r\nb"));
        Assert.assertEquals("0xff", Http3Log.printable("\u00ff"));
        Assert.assertEquals("null", Http3Log.printable(null));
    }


    @Test
    public void testConnectionClosedReadWithoutExceptionIsAborted()
            throws Exception {
        // Some QUIC wrappers may report a terminal non-FIN end as a plain -1
        // rather than an EOFException. The stream state must still classify
        // it as an abort so the application does not see a clean EOF.
        Http3Processor processor = new Http3Processor(newHttp3Protocol(),
                TEST_ADAPTER);
        processor.setStreamId(0);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) {
                return -1;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.CONN_CLOSED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Method doRead = processor.getRequest().getInputBuffer().getClass()
                .getDeclaredMethod("doRead", ApplicationBufferHandler.class);
        doRead.setAccessible(true);
        try {
            doRead.invoke(processor.getRequest().getInputBuffer(),
                    ApplicationBufferHandler.EMPTY);
            Assert.fail("A connection close reported as -1 without an "
                    + "exception must surface as an IOException");
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            Assert.assertTrue("Expected an IOException, got " + cause,
                    cause instanceof IOException);
        }
    }


    @Test
    public void testKnownControlFrameBudgetFailsConnection() throws Exception {
        // Known control frames are parsed inline on the QUIC poll thread. A
        // peer must not be able to keep that thread busy with an unbounded
        // stream of valid frames, so the per-connection known-control-frame
        // budget fails the connection with H3_EXCESSIVE_LOAD.
        Http3ConnectionManager manager =
                new Http3ConnectionManager(newHttp3Protocol());
        StubQuicConnection connection = new StubQuicConnection();
        manager.connectionOpen(connection);
        Http3ConnectionManager.ConnectionState state =
                manager.getState(connection);
        for (int i = 0; i < Http3ConnectionManager.MAX_KNOWN_CONTROL_FRAMES;
                i++) {
            Assert.assertFalse("The budget must not trigger within the limit",
                    state.noteKnownControlFrame(0));
        }
        Assert.assertTrue("The budget must trigger above the limit",
                state.noteKnownControlFrame(0));

        // The server must reject the next known control frame rather than
        // parsing it. The buffer contains the control stream type (0x00) and
        // a zero-length SETTINGS frame (0x04 0x00).
        ByteBuffer data = ByteBuffer.allocate(3);
        data.put((byte) 0x00).put((byte) 0x04).put((byte) 0x00).flip();
        try {
            manager.processClientUniStreamData(connection, 2L, data);
            Assert.fail("The control-frame budget must fail the connection");
        } catch (Http3Exception e) {
            Assert.assertEquals(Http3Error.H3_EXCESSIVE_LOAD, e.getError());
        }
    }


    @Test
    public void testNullValuedCommonHeadersDoNotSuppressAutomaticFields()
            throws Exception {
        // A header present with a null MessageBytes value is omitted by the
        // QPACK encoder, but must still be treated as absent when deciding
        // whether to add the protocol-generated Date and Alt-Svc fields.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAltService("h3");
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.getRequest().setServerPort(443);

        org.apache.tomcat.util.http.MimeHeaders headers =
                new org.apache.tomcat.util.http.MimeHeaders();
        headers.addValue("date");
        headers.addValue("alt-svc");

        Method addCommon = Http3Processor.class.getDeclaredMethod(
                "addCommonResponseHeaders",
                org.apache.tomcat.util.http.MimeHeaders.class,
                Integer.TYPE);
        addCommon.setAccessible(true);
        addCommon.invoke(processor, headers, Integer.valueOf(200));

        Assert.assertFalse("A null-valued Date field must not suppress the "
                + "automatic Date", headers.getValue("date").isNull());
        Assert.assertEquals("A null-valued Alt-Svc field must not suppress "
                + "the automatic Alt-Svc", "h3=\":443\"",
                headers.getValue("alt-svc").toString());
    }


    @Test
    public void testConcludeFailureResetsStreamAndDoesNotClaimFin()
            throws Exception {
        // A transport failure while concluding the stream must not be
        // silently swallowed: the response is truncated, so reset the stream
        // and leave finSent false. Otherwise the peer may never receive FIN
        // and the processor can be reported as reusable.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public void concludeStream() throws IOException {
                throw new IOException("simulated conclude failure");
            }

            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field finPending = Http3Processor.class.getDeclaredField(
                "finPending");
        finPending.setAccessible(true);
        finPending.setBoolean(processor, true);

        Method sendFin = Http3Processor.class.getDeclaredMethod(
                "sendFinIfPossible", SocketWrapperBase.class);
        sendFin.setAccessible(true);
        sendFin.invoke(processor, wrapper);

        Assert.assertEquals("A failed FIN conclusion must reset the stream "
                + "with H3_INTERNAL_ERROR", H3_INTERNAL_ERROR,
                resetCode.get());
        Field finSent = Http3Processor.class.getDeclaredField("finSent");
        finSent.setAccessible(true);
        Assert.assertFalse("A failed FIN conclusion must not be recorded as "
                + "a successfully sent FIN", finSent.getBoolean(processor));
    }


    @Test
    public void testInterimResponsesAndConclusionSuppressedAfterReset()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicBoolean wrote = new AtomicBoolean();
        AtomicBoolean concluded = new AtomicBoolean();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            protected void writeBlocking(ByteBuffer from) {
                wrote.set(true);
                from.position(from.limit());
            }

            @Override
            protected void flushBlocking() {
                // NO-OP
            }

            @Override
            public void concludeStream() {
                concluded.set(true);
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field resetField = Http3Processor.class.getDeclaredField(
                "streamReset");
        resetField.setAccessible(true);
        ((AtomicBoolean) resetField.get(processor)).set(true);
        processor.getRequest().setExpectation(true);

        Method readyForWrite = Http3Processor.class.getDeclaredMethod(
                "isReadyForWrite");
        readyForWrite.setAccessible(true);
        Assert.assertEquals("A reset stream must not be advertised as ready "
                + "for writing", Boolean.FALSE,
                readyForWrite.invoke(processor));

        processor.action(ActionCode.ACK, ContinueResponseTiming.ALWAYS);
        Assert.assertFalse("A 100 Continue response must not be written "
                + "after the stream was reset", wrote.get());

        processor.action(ActionCode.EARLY_HINTS, null);
        Assert.assertFalse("A 103 Early Hints response must not be written "
                + "after the stream was reset", wrote.get());

        Method conclude = Http3Processor.class.getDeclaredMethod(
                "concludeStream", SocketWrapperBase.class);
        conclude.setAccessible(true);
        conclude.invoke(processor, wrapper);
        Assert.assertFalse("A reset stream must not be concluded with FIN",
                concluded.get());
    }


    @Test
    public void testOversizedTrailerAfterResponseResetsStream()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // A trailer HEADERS frame whose declared payload exceeds the
        // trailer field-section wire limit. Only the frame header is needed:
        // the scan must reject it before trying to read the payload.
        ByteBuffer frame = ByteBuffer.allocate(8);
        Qpack.encodeQuicInteger(frame, Constants.H3_HEADERS);
        Qpack.encodeQuicInteger(frame, 40000);
        frame.flip();

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(frame);
        inputBuffer.flip();

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        decode.invoke(processor, wrapper);

        Assert.assertEquals("An oversized after-response trailer section "
                + "must be rejected as H3_MESSAGE_ERROR", H3_MESSAGE_ERROR,
                resetCode.get());
    }


    @Test
    public void testOversizedDataAfterResponseResetsStream()
            throws Exception {
        // The after-response scan must apply the same 16 MiB DATA frame
        // limit as the live body-read paths. The declared payload is above
        // the limit, so the frame header is rejected before any payload is
        // consumed (RFC 9114 has no negotiated frame-size limit; this is a
        // local implementation limit).
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger resetCode = new AtomicInteger(-1);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public boolean resetStream(long appErrorCode) {
                resetCode.set((int) appErrorCode);
                return true;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        ByteBuffer frame = ByteBuffer.allocate(16);
        Qpack.encodeQuicInteger(frame, Constants.H3_DATA);
        Qpack.encodeQuicInteger(frame,
                (long) Constants.MAX_FRAME_LENGTH + 1);
        frame.put((byte) 0x01);
        frame.flip();

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(frame);
        inputBuffer.flip();

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        decode.invoke(processor, wrapper);

        Assert.assertEquals("An oversized after-response DATA frame must be "
                + "rejected as H3_FRAME_ERROR", H3_FRAME_ERROR,
                resetCode.get());
    }


    @Test
    public void testCompleteTrailerFollowedByFrameDoesNotOverflow()
            throws Exception {
        // The trailer-readiness scan must copy exactly the declared HEADERS
        // payload, leaving any following frame bytes in the protocol input
        // buffer. An unknown frame after the trailer is valid input (RFC 9114
        // Section 4.1/Section 9); before the fix, the unchecked ByteBuffer.put
        // copied those bytes into the short payload buffer and threw a
        // BufferOverflowException out of isTrailerFieldsReady().
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        ByteBuffer frames = ByteBuffer.allocate(8);
        Qpack.encodeQuicInteger(frames, Constants.H3_HEADERS);
        Qpack.encodeQuicInteger(frames, 2);
        // Empty QPACK field section: Required Insert Count 0, Delta Base 0.
        frames.put((byte) 0x00);
        frames.put((byte) 0x00);
        // A complete unknown frame after the trailer section.
        Qpack.encodeQuicInteger(frames, 0x0a);
        Qpack.encodeQuicInteger(frames, 0);
        frames.flip();

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(frames);
        inputBuffer.flip();

        Method readTrailer = Http3Processor.class.getDeclaredMethod(
                "readTrailerSectionIfAvailable", SocketWrapperBase.class);
        readTrailer.setAccessible(true);
        Assert.assertEquals("A complete trailer followed by an unknown "
                + "frame must decode successfully", Boolean.TRUE,
                readTrailer.invoke(processor, wrapper));
        Assert.assertEquals("The following frame must remain in the input "
                + "buffer after the trailer payload was consumed", 4,
                inputBuffer.position());
    }


    @Test
    public void testSplitDataFrameAtFinIsNotTruncated() throws Exception {
        // A DATA frame whose payload is split across the protocol input
        // buffer and the QUIC wrapper must remain available to the body-read
        // path. A FIN merely means the transport has received all bytes; it
        // is not proof that the frame is truncated.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        wrapper.enqueue(new byte[] { 'b' });

        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        ByteBuffer inputBuffer = setProcessorInputBuffer(processor,
                new byte[] { 0x00, 0x02, 'a' });

        Method readTrailer = Http3Processor.class.getDeclaredMethod(
                "readTrailerSectionIfAvailable", SocketWrapperBase.class);
        readTrailer.setAccessible(true);
        Assert.assertEquals("A split DATA frame at FIN must stay for the "
                + "body-read path", Boolean.FALSE,
                readTrailer.invoke(processor, wrapper));
        Assert.assertEquals("A split DATA frame at FIN must not be "
                + "classified as a truncated frame", -1L,
                connectionFailure.get());
        Assert.assertEquals("The DATA frame header must remain in the input "
                + "buffer", 0, inputBuffer.position());
    }


    @Test
    public void testSplitTrailerAtFinIsCompleted() throws Exception {
        // The trailer payload is split across the protocol input buffer and
        // the QUIC wrapper, with FIN already observed. The scan must read
        // the outstanding payload bytes and decode the trailer instead of
        // treating FIN alone as truncation.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }

            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                int read = super.read(block, to);
                if (read == 0 && getQuicStream() != null &&
                        getQuicStream().getReadState() ==
                                QuicStream.ReadState.FINISHED) {
                    return -1;
                }
                return read;
            }
        };
        wrapper.enqueue(new byte[] { 0x00 });

        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        setProcessorInputBuffer(processor, new byte[] { 0x01, 0x02, 0x00 });

        Method readTrailer = Http3Processor.class.getDeclaredMethod(
                "readTrailerSectionIfAvailable", SocketWrapperBase.class);
        readTrailer.setAccessible(true);
        Assert.assertEquals("A split trailer at FIN must be decoded once the "
                + "outstanding bytes are read", Boolean.TRUE,
                readTrailer.invoke(processor, wrapper));
        Assert.assertEquals("A complete trailer split at FIN must not fail "
                + "the connection", -1L, connectionFailure.get());

        Field trailersReceived = processor.getRequest().getInputBuffer()
                .getClass().getDeclaredField("trailersReceived");
        trailersReceived.setAccessible(true);
        Assert.assertTrue("The trailer section must be recorded as received",
                trailersReceived.getBoolean(processor.getRequest()
                        .getInputBuffer()));
    }


    @Test
    public void testLargeTrailerHeaderDoesNotAllocateFullFrameBeforePayload()
            throws Exception {
        // A trailer HEADERS frame that declares a large payload must not make
        // the receiver allocate the whole declared length before any payload
        // bytes arrive. The trailer payload buffer starts at the configured
        // initial size and grows as bytes are actually received.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        // Allow a frame larger than the default trailer wire limit so the
        // allocation policy, rather than the trailer-size preflight, is what
        // is exercised here.
        protocol.setMaxTrailerSize(-1);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        int frameLength = 1024 * 1024;
        ByteBuffer header = ByteBuffer.allocate(16);
        Qpack.encodeQuicInteger(header, Constants.H3_HEADERS);
        Qpack.encodeQuicInteger(header, frameLength);
        header.flip();
        byte[] headerBytes = new byte[header.remaining()];
        header.get(headerBytes);
        setProcessorInputBuffer(processor, headerBytes);

        Method readTrailer = Http3Processor.class.getDeclaredMethod(
                "readTrailerSectionIfAvailable", SocketWrapperBase.class);
        readTrailer.setAccessible(true);
        Assert.assertEquals("A trailer header with no payload must wait for "
                + "more data", Boolean.FALSE,
                readTrailer.invoke(processor, wrapper));

        Object inBuf = processor.getRequest().getInputBuffer();
        Field trailerField = inBuf.getClass().getDeclaredField(
                "trailerPayload");
        trailerField.setAccessible(true);
        ByteBuffer trailerPayload = (ByteBuffer) trailerField.get(inBuf);
        Assert.assertNotNull("The partial trailer payload must be staged",
                trailerPayload);
        Assert.assertTrue("A declared " + frameLength + " byte trailer frame "
                + "must not allocate its full length before payload arrives "
                + "(capacity=" + trailerPayload.capacity() + ")",
                trailerPayload.capacity() <= 8 * 1024);

        Field trailerLengthField = inBuf.getClass().getDeclaredField(
                "trailerPayloadLength");
        trailerLengthField.setAccessible(true);
        Assert.assertEquals("The declared trailer payload length must be "
                + "retained separately from the current buffer capacity",
                frameLength, trailerLengthField.getInt(inBuf));
    }


    @Test
    public void testSplitIgnoredFrameAtFinIsSkipped() throws Exception {
        // An unknown frame split across the protocol input buffer and the
        // QUIC wrapper must be skipped before the clean FIN is classified.
        // RFC 9114 Section 9 requires unknown frames to be ignored.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }

            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                int read = super.read(block, to);
                if (read == 0 && getQuicStream() != null &&
                        getQuicStream().getReadState() ==
                                QuicStream.ReadState.FINISHED) {
                    return -1;
                }
                return read;
            }
        };
        wrapper.enqueue(new byte[] { 'x', 'y' });

        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // Unknown frame type 0x0a, declared payload length 2, with no
        // payload bytes in the protocol input buffer.
        setProcessorInputBuffer(processor, new byte[] { 0x0a, 0x02 });

        Method readTrailer = Http3Processor.class.getDeclaredMethod(
                "readTrailerSectionIfAvailable", SocketWrapperBase.class);
        readTrailer.setAccessible(true);
        Assert.assertEquals("A split ignored frame at FIN must be skipped "
                + "and the clean end accepted", Boolean.TRUE,
                readTrailer.invoke(processor, wrapper));
        Assert.assertEquals("A split ignored frame at FIN must not fail the "
                + "connection", -1L, connectionFailure.get());
    }


    @Test
    public void testSplitTrailerPayloadWithoutFinIsCompleted() throws Exception {
        // The trailer payload is split across the protocol input buffer and
        // the QUIC wrapper with the stream still open. The readiness scan
        // must read the buffered wrapper bytes and decode the trailer rather
        // than re-parsing the same header forever.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        wrapper.enqueue(new byte[] { 0x00 });
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        setProcessorInputBuffer(processor, new byte[] { 0x01, 0x02, 0x00 });

        Method readTrailer = Http3Processor.class.getDeclaredMethod(
                "readTrailerSectionIfAvailable", SocketWrapperBase.class);
        readTrailer.setAccessible(true);
        Assert.assertEquals("A split trailer payload must be completed from "
                + "the wrapper without waiting for FIN", Boolean.TRUE,
                readTrailer.invoke(processor, wrapper));
        Assert.assertTrue("The split trailer must be decoded",
                wrapper.readCount.get() > 0);
    }


    @Test
    public void testPendingIgnoredFrameSkipIsDrainedBeforeTrailer()
            throws Exception {
        // An ignored frame's payload skip was interrupted by a would-block
        // and its remainder is still owed. The readiness scan must drain
        // that state before parsing the next frame header, otherwise a
        // valid trailer section behind the ignored frame can never become
        // ready.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        // Two outstanding ignored-frame bytes followed by a complete empty
        // trailer HEADERS frame.
        wrapper.enqueue(new byte[] { 'x', 'y', 0x01, 0x02, 0x00, 0x00 });
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field skipRemaining = inBuf.getClass().getDeclaredField(
                "pendingSkipRemaining");
        skipRemaining.setAccessible(true);
        skipRemaining.setLong(inBuf, 2);
        setProcessorInputBuffer(processor, new byte[0]);

        Method readTrailer = Http3Processor.class.getDeclaredMethod(
                "readTrailerSectionIfAvailable", SocketWrapperBase.class);
        readTrailer.setAccessible(true);
        Assert.assertEquals("A drainable ignored-frame skip must not block "
                + "trailer readiness", Boolean.TRUE,
                readTrailer.invoke(processor, wrapper));
        Assert.assertEquals("The ignored-frame skip must be fully drained",
                0L, skipRemaining.getLong(inBuf));

        Field trailersReceived = inBuf.getClass().getDeclaredField(
                "trailersReceived");
        trailersReceived.setAccessible(true);
        Assert.assertTrue("The trailer behind the ignored frame must be "
                + "decoded", trailersReceived.getBoolean(inBuf));
    }


    @Test
    public void testPendingIgnoredFrameSkipWouldBlockAtFinIsNotTruncated()
            throws Exception {
        // The QUIC poll thread can observe the peer's FIN after the worker's
        // last read returned 0 (would-block) while payload bytes are still
        // held in the wrapper/native buffers. The next read would complete
        // the frame, so a would-block must not be classified as a truncated
        // final frame even though the stream state already reports FINISHED.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicInteger reads = new AtomicInteger();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                int call = reads.getAndIncrement();
                if (call == 0) {
                    // Would-block while the FIN state is already visible.
                    return 0;
                }
                if (call == 1) {
                    // The next read delivers the bytes that complete the
                    // outstanding ignored-frame payload.
                    to.put(new byte[] { 'x', 'y', 'z' });
                    return 3;
                }
                return 0;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setProcessorInputBuffer(processor, new byte[0]);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field skipRemaining = inBuf.getClass().getDeclaredField(
                "pendingSkipRemaining");
        skipRemaining.setAccessible(true);
        skipRemaining.setLong(inBuf, 3);

        Method readTrailer = Http3Processor.class.getDeclaredMethod(
                "readTrailerSectionIfAvailable", SocketWrapperBase.class);
        readTrailer.setAccessible(true);
        Assert.assertEquals("A would-block read with the FIN state already "
                + "visible must not be classified as a truncated frame",
                Boolean.FALSE, readTrailer.invoke(processor, wrapper));
        Assert.assertEquals("The interrupted skip must be retained for the "
                + "next attempt", 3L, skipRemaining.getLong(inBuf));

        // The retry must drain the bytes delivered after the would-block.
        Assert.assertEquals("The retried skip must not be classified as a "
                + "truncated frame either", Boolean.FALSE,
                readTrailer.invoke(processor, wrapper));
        Assert.assertEquals("The interrupted skip must be fully drained",
                0L, skipRemaining.getLong(inBuf));
    }


    private ByteBuffer setProcessorInputBuffer(Http3Processor processor,
            byte[] bytes) throws Exception {
        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(bytes);
        inputBuffer.flip();
        return inputBuffer;
    }


    @Test
    public void testAfterResponseSplitTrailerAtFinIsDecoded()
            throws Exception {
        // The response-after scan must complete a staged trailer section from
        // bytes still buffered in the QUIC wrapper before interpreting FIN as
        // truncation.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        wrapper.enqueue(new byte[] { 0x00 });
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setProcessorInputBuffer(processor, new byte[0]);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field trailerField = inBuf.getClass().getDeclaredField(
                "trailerPayload");
        trailerField.setAccessible(true);
        ByteBuffer partial = ByteBuffer.allocate(2);
        partial.put((byte) 0x00);
        trailerField.set(inBuf, partial);

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        decode.invoke(processor, wrapper);

        Assert.assertEquals("A split trailer at FIN must be decoded from the "
                + "buffered wrapper bytes, not treated as truncated", -1L,
                connectionFailure.get());
        Field trailersReceived = inBuf.getClass().getDeclaredField(
                "trailersReceived");
        trailersReceived.setAccessible(true);
        Assert.assertTrue("The split trailer must be decoded",
                trailersReceived.getBoolean(inBuf));
    }


    @Test
    public void testAfterResponsePartialDataAtFinIsDrained() throws Exception {
        // Outstanding DATA payload bytes from an interrupted body read may
        // already be available in the wrapper. The after-response scan must
        // drain them before treating FIN as a truncated frame.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        wrapper.enqueue(new byte[] { 'a', 'b' });
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setProcessorInputBuffer(processor, new byte[0]);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field partialField = inBuf.getClass().getDeclaredField(
                "partialDataRemaining");
        partialField.setAccessible(true);
        partialField.setInt(inBuf, 2);

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        decode.invoke(processor, wrapper);

        Assert.assertEquals("Outstanding DATA payload bytes at FIN must be "
                + "drained, not treated as a truncated frame", -1L,
                connectionFailure.get());
        Assert.assertEquals("The outstanding DATA payload must be fully "
                + "drained", 0, partialField.getInt(inBuf));
    }


    @Test
    public void testAfterResponsePendingSkipAtFinIsDrained() throws Exception {
        // An interrupted ignored-frame skip can also have its remaining
        // bytes buffered in the wrapper. Drain it and continue to the
        // trailer section instead of failing the connection.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        wrapper.enqueue(new byte[] { 'x', 'y', 0x01, 0x02, 0x00, 0x00 });
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setProcessorInputBuffer(processor, new byte[0]);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field skipField = inBuf.getClass().getDeclaredField(
                "pendingSkipRemaining");
        skipField.setAccessible(true);
        skipField.setLong(inBuf, 2);

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        decode.invoke(processor, wrapper);

        Assert.assertEquals("Outstanding ignored-frame bytes at FIN must be "
                + "drained, not treated as a truncated frame", -1L,
                connectionFailure.get());
        Assert.assertEquals("The ignored-frame skip must be fully drained",
                0L, skipField.getLong(inBuf));
        Field trailersReceived = inBuf.getClass().getDeclaredField(
                "trailersReceived");
        trailersReceived.setAccessible(true);
        Assert.assertTrue("The trailer behind the ignored frame must be "
                + "decoded", trailersReceived.getBoolean(inBuf));
    }


    @Test
    public void testAfterResponseHeaderWouldBlockAtFinIsNotTruncated()
            throws Exception {
        // A read boundary may land inside the frame-header varints. The
        // non-blocking scan can return would-block while the poll thread has
        // already observed FIN; the outstanding header bytes may still be in
        // the wrapper. A would-block must not be classified as a truncated
        // final frame.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                // Would-block; the header remainder may arrive later.
                return 0;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        // The first byte of a frame header, which only forms a partial header
        // at this read boundary.
        setProcessorInputBuffer(processor, new byte[] { 0x00 });

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        decode.invoke(processor, wrapper);

        Assert.assertEquals("A would-block header scan at FIN must not be "
                + "classified as a truncated frame", -1L,
                connectionFailure.get());
    }


    @Test
    public void testAfterTrailerHeaderWouldBlockAtFinIsNotTruncated()
            throws Exception {
        // Same race as testAfterResponseHeaderWouldBlockAtFinIsNotTruncated(),
        // on the second after-response scan (the one that rejects frames after
        // a decoded trailer section).
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                return 0;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setProcessorInputBuffer(processor, new byte[] { 0x00 });

        Object inBuf = processor.getRequest().getInputBuffer();
        Method setTrailersReceived = inBuf.getClass().getDeclaredMethod(
                "setTrailersReceived", Boolean.TYPE);
        setTrailersReceived.setAccessible(true);
        setTrailersReceived.invoke(inBuf, Boolean.TRUE);

        Method check = Http3Processor.class.getDeclaredMethod(
                "checkFramesAfterTrailer", SocketWrapperBase.class);
        check.setAccessible(true);
        check.invoke(processor, wrapper);

        Assert.assertEquals("A would-block header scan at FIN must not be "
                + "classified as a truncated frame", -1L,
                connectionFailure.get());
    }


    @Test
    public void testTruncatedTrailerAtFinFailsConnection() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }

            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream() {
                    @Override
                    public ReadState getReadState() {
                        return ReadState.FINISHED;
                    }
                };
            }

            @Override
            public int read(boolean block, ByteBuffer to) throws IOException {
                int read = super.read(block, to);
                if (read == 0 && getQuicStream() != null &&
                        getQuicStream().getReadState() ==
                                QuicStream.ReadState.FINISHED) {
                    return -1;
                }
                return read;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);
        setProcessorInputBuffer(processor, new byte[0]);

        // A partially read trailer section left staged when the client sent
        // FIN: the last frame is truncated (RFC 9114 Section 7.1).
        Field trailerField = processor.getRequest().getInputBuffer()
                .getClass().getDeclaredField("trailerPayload");
        trailerField.setAccessible(true);
        trailerField.set(processor.getRequest().getInputBuffer(),
                ByteBuffer.wrap(new byte[] { 0x01, 0x02 }));

        Method decode = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse", SocketWrapperBase.class);
        decode.setAccessible(true);
        decode.invoke(processor, wrapper);

        Assert.assertEquals("A truncated trailer section followed by a "
                + "clean FIN must fail the connection with H3_FRAME_ERROR",
                Http3Error.H3_FRAME_ERROR.getCode(), connectionFailure.get());
    }


    @Test
    public void testControlFrameAfterHeadersFailsConnectionAtScan()
            throws Exception {
        // Deterministic coverage of the after-response scan: a control-only
        // frame already in the input buffer after the request headers must
        // fail the connection with H3_FRAME_UNEXPECTED.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AtomicLong connectionFailure = new AtomicLong(-1);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public void failConnection(long appErrorCode, String reason) {
                connectionFailure.compareAndSet(-1, appErrorCode);
            }
        };
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };

        Field hasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        hasData.setAccessible(true);
        hasData.setBoolean(processor, true);
        Field bufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        bufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) bufferField.get(processor);
        inputBuffer.clear();
        Qpack.encodeQuicInteger(inputBuffer, Constants.H3_SETTINGS);
        Qpack.encodeQuicInteger(inputBuffer, 0);
        inputBuffer.flip();

        Method scan = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse",
                SocketWrapperBase.class);
        scan.setAccessible(true);
        scan.invoke(processor, wrapper);

        Assert.assertEquals("The after-response scan must classify a "
                + "control-only frame as H3_FRAME_UNEXPECTED",
                H3_FRAME_UNEXPECTED, connectionFailure.get());
    }


    @Test
    public void testRecycleClearsBadRequestNote() throws Exception {
        // Request.recycle() does not clear the notes array. HTTP/2 clears
        // NOTE_BAD_REQUEST explicitly because its processors/request objects
        // may be reused; HTTP/3 processors are pooled across streams and
        // connections, so the same stale note would make later valid
        // requests receive a spurious 400.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.getRequest().setNote(
                org.apache.coyote.Request.NOTE_BAD_REQUEST, Boolean.TRUE);

        processor.recycle();

        Assert.assertNull("NOTE_BAD_REQUEST must not survive recycle()",
                processor.getRequest().getNote(
                        org.apache.coyote.Request.NOTE_BAD_REQUEST));
    }


    @Test
    public void testRecycleWhileInputLockHeldIsNotReusable() throws Exception {
        // A body reader may still hold inputReadLock when the async request
        // is completed by another thread. Recycling the request/input/QPACK
        // state at that point would corrupt the reader's view. The processor
        // must stay out of the pool and keep the per-request objects intact.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.getRequest().getMimeHeaders().addValue("X-Test")
                .setString("preserved");

        Field lockField = Http3Processor.class.getDeclaredField(
                "inputReadLock");
        lockField.setAccessible(true);
        ReentrantLock inputReadLock = (ReentrantLock) lockField.get(processor);
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread holder = new Thread(() -> {
            inputReadLock.lock();
            try {
                locked.countDown();
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                inputReadLock.unlock();
            }
        }, "http3-recycle-lock-holder");
        holder.setDaemon(true);
        holder.start();
        locked.await();
        try {
            processor.recycle();
            Assert.assertFalse("A processor whose input lock is held must "
                    + "not be returned to the shared pool",
                    processor.isReusable());
            Assert.assertNotNull("Recycling must not reset request state "
                    + "under an active reader",
                    processor.getRequest().getMimeHeaders().getValue(
                            "X-Test"));
        } finally {
            release.countDown();
            holder.join();
        }
    }


    @Test
    public void testRecycleWhileInputLockHeldQueuesStreamCancellation()
            throws Exception {
        // A recycle() that cannot acquire the input lock abandons the stream
        // without necessarily processing its remaining field sections. The
        // QPACK Stream Cancellation must still be queued (RFC 9204 Section
        // 2.2.2.2); otherwise the peer's encoder keeps the referenced dynamic
        // table entries outstanding for the connection lifetime.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setConnectionState(manager.getState(connection));

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field lockField = Http3Processor.class.getDeclaredField(
                "inputReadLock");
        lockField.setAccessible(true);
        ReentrantLock inputReadLock = (ReentrantLock) lockField.get(processor);
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread holder = new Thread(() -> {
            inputReadLock.lock();
            try {
                locked.countDown();
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                inputReadLock.unlock();
            }
        }, "http3-cancel-lock-holder");
        holder.setDaemon(true);
        holder.start();
        locked.await();
        try {
            processor.recycle();
        } finally {
            release.countDown();
            holder.join();
        }

        Field pendingField = Http3ConnectionManager.ConnectionState.class
                .getDeclaredField("pendingCancellations");
        pendingField.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Set<Long> pending = (java.util.Set<Long>) pendingField.get(
                manager.getState(connection));
        Assert.assertTrue("Recycling while a reader holds the input lock must "
                + "queue a QPACK Stream Cancellation",
                pending.contains(Long.valueOf(0)));
    }


    @Test
    public void testCompletionScanLockedInputIsNotReusable() throws Exception {
        // The after-response scan can observe the input lock held by another
        // application thread. It must record that observation so the later
        // recycle() cannot reset the request state for a future stream.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.getRequest().getMimeHeaders().addValue("X-Test")
                .setString("preserved");

        Field lockField = Http3Processor.class.getDeclaredField(
                "inputReadLock");
        lockField.setAccessible(true);
        ReentrantLock inputReadLock = (ReentrantLock) lockField.get(processor);
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Thread holder = new Thread(() -> {
            inputReadLock.lock();
            try {
                locked.countDown();
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                inputReadLock.unlock();
            }
        }, "http3-scan-lock-holder");
        holder.setDaemon(true);
        holder.start();
        locked.await();
        try {
            Method scan = Http3Processor.class.getDeclaredMethod(
                    "scanRequestStreamAfterResponse", SocketWrapperBase.class);
            scan.setAccessible(true);
            scan.invoke(processor, new Object[] { null });
        } finally {
            release.countDown();
            holder.join();
        }

        processor.recycle();
        Assert.assertFalse("A processor whose completion scan was blocked by "
                + "an active reader must not be returned to the shared pool",
                processor.isReusable());
        Assert.assertNotNull("Recycling must not reset request state after a "
                + "blocked completion scan",
                processor.getRequest().getMimeHeaders().getValue("X-Test"));
    }


    @Test
    public void testErrorProcessorIsNotReusable() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);

        Http3Processor normal = new Http3Processor(protocol, TEST_ADAPTER);
        normal.recycle();
        Assert.assertTrue("A clean processor may be pooled",
                normal.isReusable());

        Http3Processor reset = new Http3Processor(protocol, TEST_ADAPTER);
        Field resetField =
                Http3Processor.class.getDeclaredField("streamReset");
        resetField.setAccessible(true);
        ((AtomicBoolean) resetField.get(reset)).set(true);
        reset.recycle();
        Assert.assertFalse("A processor whose stream was reset must not be "
                + "returned to the shared pool", reset.isReusable());
    }


    @Test
    public void testBodyFrameErrorFailsConnectionImmediately() throws Exception {
        // A connection-level frame error recorded by a body read must fail
        // the connection on the reading thread itself. Relying on the service
        // loop or a later recycle() can miss it when the app completes through
        // a path that never reaches either.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setConnectionState(manager.getState(connection));

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // Force the next non-body frame over the per-request limit.
        Field limitField = Http3Processor.class.getDeclaredField(
                "MAX_NON_BODY_FRAMES");
        limitField.setAccessible(true);
        int limit = limitField.getInt(null);
        Field countField = Http3Processor.class.getDeclaredField(
                "nonBodyFrameCount");
        countField.setAccessible(true);
        countField.setInt(processor, limit);

        Object inBuf = processor.getRequest().getInputBuffer();
        Method note = inBuf.getClass().getDeclaredMethod(
                "noteNonBodyFrame", Long.TYPE);
        note.setAccessible(true);
        Assert.assertEquals(Boolean.TRUE, note.invoke(inBuf, Long.valueOf(1)));

        Assert.assertEquals("A connection-level body frame error must fail "
                + "the connection immediately",
                Http3Error.H3_EXCESSIVE_LOAD.getCode(),
                connection.failureCode.intValue());
        Assert.assertFalse("A processor that failed the connection must not "
                + "be reusable", processor.isReusable());
    }


    @Test
    public void testRecycleLockedRechecksBodyFrameError() throws Exception {
        // The initial failConnectionOnBodyFrameError() in recycle() runs
        // before inputReadLock is acquired. A reader may record the error
        // after that check, so recycleLocked() must recheck it under the lock
        // before deciding that the processor can be pooled.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setConnectionState(manager.getState(connection));

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field bodyFrameError = Http3Processor.class.getDeclaredField(
                "bodyFrameError");
        bodyFrameError.setAccessible(true);
        bodyFrameError.set(processor, Http3Error.H3_FRAME_UNEXPECTED);

        Method recycleLocked = Http3Processor.class.getDeclaredMethod(
                "recycleLocked");
        recycleLocked.setAccessible(true);
        recycleLocked.invoke(processor);

        Assert.assertEquals("A body frame error observed under the input lock "
                + "must fail the connection",
                Http3Error.H3_FRAME_UNEXPECTED.getCode(),
                connection.failureCode.intValue());
        Assert.assertFalse("A processor with a stale body frame error must "
                + "not be pooled", processor.isReusable());
    }


    @Test
    public void testNonReusableProcessorRetainsProtocolState() throws Exception {
        // A processor that is not returned to the pool may still be reached
        // by a late application call (for example getTrailerFields()) after
        // an error/reset. Its shared QPACK decoder and connection state must
        // therefore remain intact; resetting them before the non-reusable
        // early return would make that late call decode against a fresh
        // fallback decoder and live connector settings.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);
        Http3ConnectionManager.ConnectionState state =
                manager.getState(connection);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setConnectionState(state);
        QpackDecoder decoder = new QpackDecoder();
        processor.setSharedQpackDecoder(decoder);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field resetField = Http3Processor.class.getDeclaredField(
                "streamReset");
        resetField.setAccessible(true);
        ((AtomicBoolean) resetField.get(processor)).set(true);

        processor.recycle();

        Assert.assertFalse("A processor whose stream was reset must not be "
                + "returned to the shared pool", processor.isReusable());
        Assert.assertSame("A non-reusable processor must keep its shared "
                + "QPACK decoder for late application calls",
                decoder, processor.getQpackDecoder());
        Field stateField = Http3Processor.class.getDeclaredField(
                "connectionState");
        stateField.setAccessible(true);
        Assert.assertSame("A non-reusable processor must keep its connection "
                + "state for late application calls",
                state, stateField.get(processor));
    }


    @Test
    public void testConnectionFailureProcessorNotReusable() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setAdapter(TEST_ADAPTER);
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        // bodyFrameError is handled by recycle() after the initial reusable
        // decision; failConnection() must mark the processor non-reusable.
        Field bodyFrameError =
                Http3Processor.class.getDeclaredField("bodyFrameError");
        bodyFrameError.setAccessible(true);
        bodyFrameError.set(processor, Http3Error.H3_FRAME_UNEXPECTED);

        processor.recycle();

        Assert.assertFalse("A processor that failed the connection must not "
                + "be returned to the shared pool", processor.isReusable());
    }


    @Test
    public void testTrailerFieldsNotSupportedAfterConclusion() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, null);
        processor.setStreamId(0);
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Assert.assertTrue("Trailer fields should be supported before the " +
                "response is concluded", processor.isTrailerFieldsSupported());

        Method conclude = Http3Processor.class.getDeclaredMethod(
                "concludeStream", SocketWrapperBase.class);
        conclude.setAccessible(true);
        conclude.invoke(processor, wrapper);

        Assert.assertFalse("Trailer fields must not be supported after the " +
                "response has been concluded",
                processor.isTrailerFieldsSupported());
    }


    @Test
    public void testEmptyEncodedTrailerSectionIsNotSent() throws Exception {
        // A trailer field whose value the QPACK encoder must drop leaves an
        // empty field section. Sending an empty HEADERS frame as trailers is
        // unnecessary; the response must conclude without it.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        ControlledQuicSocketWrapper wrapper =
                new ControlledQuicSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field responseStarted = Http3Processor.class.getDeclaredField(
                "responseStarted");
        responseStarted.setAccessible(true);
        responseStarted.setBoolean(processor, true);
        processor.getRequest().getResponse().setTrailerFields(
                () -> Map.of("x-trailer", "\u0100"));

        invokeSendResponseTrailers(processor, wrapper);

        Assert.assertEquals("An empty encoded trailer section must not be "
                + "written as a HEADERS frame", 0, wrapper.sentBytes);
    }


    @Test
    public void testTrailersSuppressedWithoutFinalHeaders() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, null);
        processor.setStreamId(0);
        setTrailerSupplier(processor);

        // sendResponseHeadersInternal() sets responseStarted only after the
        // final HEADERS frame has been written, so a header-send failure
        // leaves it false. The direct sendResponseTrailers() entry point must
        // not attempt a trailer HEADERS frame without a final response head
        // (RFC 9114 Section 4.1). The stub wrapper throws on any write
        // attempt.
        invokeSendResponseTrailers(processor, new StubReadSocketWrapper());
    }


    @Test
    public void testTrailersSuppressedAfterStreamReset() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, null);
        processor.setStreamId(0);
        setTrailerSupplier(processor);

        // The reset path in sendResponseHeadersInternal() claims the
        // response as started without writing anything. Trailers must still
        // not be sent on a reset stream.
        Field resetField =
                Http3Processor.class.getDeclaredField("streamReset");
        resetField.setAccessible(true);
        ((AtomicBoolean) resetField.get(processor)).set(true);
        Field startedField =
                Http3Processor.class.getDeclaredField("responseStarted");
        startedField.setAccessible(true);
        startedField.setBoolean(processor, true);

        invokeSendResponseTrailers(processor, new StubReadSocketWrapper());
    }


    private static void setTrailerSupplier(Http3Processor processor)
            throws Exception {
        Field responseField =
                AbstractProcessor.class.getDeclaredField("response");
        responseField.setAccessible(true);
        Response response = (Response) responseField.get(processor);
        Map<String,String> trailers = new HashMap<>();
        trailers.put("x-test-trailer", "value");
        response.setTrailerFields(() -> trailers);
    }


    private static void invokeSendResponseTrailers(Http3Processor processor,
            SocketWrapperBase<?> socketWrapper) throws Exception {
        Method sendResponseTrailers = Http3Processor.class.getDeclaredMethod(
                "sendResponseTrailers", SocketWrapperBase.class);
        sendResponseTrailers.setAccessible(true);
        try {
            sendResponseTrailers.invoke(processor, socketWrapper);
        } catch (InvocationTargetException ite) {
            throw (Exception) ite.getCause();
        }
    }


    @Test
    public void testCreateUpgradeProcessorAlwaysIllegalState()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();

        // HTTP/3 rejects every upgrade attempt with IllegalStateException.
        // A token that carries no handler (or no token at all) must not
        // turn the rejection into a NullPointerException.
        try {
            protocol.createUpgradeProcessor(null,
                    new UpgradeToken(null, null, null, "h3"));
            Assert.fail("Expected IllegalStateException");
        } catch (IllegalStateException ise) {
            // Expected
        }
        try {
            protocol.createUpgradeProcessor(null, null);
            Assert.fail("Expected IllegalStateException");
        } catch (IllegalStateException ise) {
            // Expected
        }
    }


    @Test
    public void testFrameHeaderCompletedAfterSplitDelivery()
            throws Exception {
        // A frame header split across reads such that two or more bytes are
        // buffered while a varint is still incomplete (here a HEADERS type
        // byte plus the first byte of a 2-byte length varint) must not
        // stall the stream: the next readFrame() has to re-read the socket
        // and complete the header once the continuation bytes arrive.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, null);
        processor.setStreamId(0);

        StubReadSocketWrapper wrapper = new StubReadSocketWrapper();
        wrapper.enqueue(new byte[] { 0x01, 0x40 });

        Method readFrame = Http3Processor.class.getDeclaredMethod(
                "readFrame", SocketWrapperBase.class);
        readFrame.setAccessible(true);
        Field pendingType = Http3Processor.class.getDeclaredField(
                "pendingFrameType");
        pendingType.setAccessible(true);

        // First delivery: the frame header is incomplete, so readFrame()
        // reports "need more data" without accepting a frame.
        Assert.assertEquals(Boolean.FALSE,
                readFrame.invoke(processor, wrapper));
        Assert.assertEquals(-1L, pendingType.getLong(processor));
        int readsAfterFirstDelivery = wrapper.readCount.get();

        // The continuation byte arrives (completing the varint: declared
        // payload length 1). The next readFrame() must drain it and accept
        // the completed header, not park the stream forever.
        wrapper.enqueue(new byte[] { 0x01 });
        readFrame.invoke(processor, wrapper);

        Assert.assertTrue("readFrame() never re-read the socket after the "
                + "continuation byte became available: the stream stalled "
                + "on an incomplete frame header",
                wrapper.readCount.get() > readsAfterFirstDelivery);
        Assert.assertEquals("readFrame() did not accept the completed frame "
                + "header", Constants.H3_HEADERS,
                pendingType.getLong(processor));
    }


    @Test
    public void testPartialFrameHeaderIsNotReadyForRead() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubReadSocketWrapper wrapper = new StubReadSocketWrapper();
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field hasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        hasData.setAccessible(true);
        hasData.setBoolean(processor, true);
        Field bufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        bufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) bufferField.get(processor);

        // A single byte starting a two-byte frame varint cannot be consumed:
        // the async readiness path must not report it as readable, otherwise
        // an async read would enter the pump/blocking loop waiting for the
        // continuation byte.
        inputBuffer.clear();
        inputBuffer.put((byte) 0x40);
        inputBuffer.flip();
        Assert.assertFalse("A partial frame header must not be reported as "
                + "ready for reading", processor.isReadyForRead());

        // A complete empty DATA frame makes no body progress and is not EOF:
        // a follow-up read would return 0, which Catalina's readByte() treats
        // as an empty buffer (BufferUnderflowException). It must therefore
        // not be reported as ready.
        inputBuffer.clear();
        inputBuffer.put(new byte[] { 0x00, 0x00 });
        inputBuffer.flip();
        Assert.assertFalse("A complete empty DATA frame must not be reported "
                + "as ready for reading", processor.isReadyForRead());

        // A DATA frame header whose payload has not arrived yet must not be
        // advertised: the next read could only block waiting for payload.
        inputBuffer.clear();
        inputBuffer.put(new byte[] { 0x00, 0x05 });
        inputBuffer.flip();
        Assert.assertFalse("A DATA frame with no buffered payload must not be "
                + "reported as ready for reading", processor.isReadyForRead());

        // A complete DATA frame with payload bytes is ready: the next read
        // delivers those bytes.
        inputBuffer.clear();
        inputBuffer.put(new byte[] { 0x00, 0x01, (byte) 'x' });
        inputBuffer.flip();
        Assert.assertTrue("A complete DATA frame with payload must be "
                + "reported as ready for reading", processor.isReadyForRead());

        // A partially received DATA payload with at least one byte is ready:
        // the next read delivers the buffered byte(s).
        inputBuffer.clear();
        inputBuffer.put(new byte[] { 0x00, 0x05, (byte) 'x' });
        inputBuffer.flip();
        Assert.assertTrue("A partial DATA payload with buffered bytes must be "
                + "reported as ready for reading", processor.isReadyForRead());

        // Empty DATA and ignored frames before a DATA frame are padding; the
        // scan must skip them and still report the readable DATA frame.
        inputBuffer.clear();
        inputBuffer.put(new byte[] { 0x00, 0x00,                // empty DATA
                0x21, 0x00,                                      // empty ignored
                0x00, 0x01, (byte) 'y' });                       // DATA: y
        inputBuffer.flip();
        Assert.assertTrue("Padding frames before a DATA frame must not hide "
                + "its payload from the readiness check",
                processor.isReadyForRead());
    }


    @Test
    public void testAsyncPartialFrameHeaderReadPumpsTransport()
            throws Exception {
        // An async request-body read that is waiting for the continuation
        // byte of a frame header must park on the transport rather than spin
        // in the doRead() stall loop. Without the pump, every retry returned
        // immediately with no progress and burned CPU until the stall
        // deadline.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        AsyncContextCallback asyncCtxt = new AsyncContextCallback() {
            @Override
            public void fireOnComplete() {
                // NO-OP
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public void incrementInProgressAsyncCount() {
                // NO-OP
            }

            @Override
            public void decrementInProgressAsyncCount() {
                // NO-OP
            }
        };
        processor.getRequest().action(ActionCode.ASYNC_START, asyncCtxt);
        Assert.assertTrue("The test requires an asynchronous request",
                processor.isAsync());

        AtomicInteger reads = new AtomicInteger();
        AtomicInteger waits = new AtomicInteger();
        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public int read(boolean block, ByteBuffer to) {
                reads.incrementAndGet();
                return 0;
            }

            @Override
            public boolean awaitReadableData(long deadlineNanos) {
                waits.incrementAndGet();
                try {
                    Thread.sleep(1);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return false;
            }
        };
        wrapper.setReadTimeout(20);

        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field hasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        hasData.setAccessible(true);
        hasData.setBoolean(processor, true);
        Field bufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        bufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) bufferField.get(processor);

        // A single byte starting a two-byte frame varint: the header cannot
        // be parsed until more data arrives.
        inputBuffer.clear();
        inputBuffer.put((byte) 0x40);
        inputBuffer.flip();

        try {
            processor.getRequest().getInputBuffer().doRead(
                    ApplicationBufferHandler.EMPTY);
            Assert.fail("A stalled read must fail with a timeout");
        } catch (SocketTimeoutException expected) {
            // Expected: the bounded test read timeout expired.
        }

        Assert.assertTrue("An async partial-header read must park on the "
                + "transport instead of retrying without progress", waits.get() > 0);
        Assert.assertTrue("An async partial-header read must not busy-spin "
                + "(reads=" + reads.get() + ")", reads.get() < 1000);
    }


    @Test
    public void testFramesAfterTrailerChargeConnectionPaddingBudget()
            throws Exception {
        // Padding after the trailer section must count against the
        // connection-lifetime budget, not only the per-request allowance:
        // otherwise sequential requests on one connection can force
        // unbounded discard work.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setConnectionState(manager.getState(connection));

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Object inBuf = processor.getRequest().getInputBuffer();
        Method setTrailers = inBuf.getClass().getDeclaredMethod(
                "setTrailersReceived", Boolean.TYPE);
        setTrailers.setAccessible(true);
        setTrailers.invoke(inBuf, Boolean.TRUE);

        Field hasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        hasData.setAccessible(true);
        hasData.setBoolean(processor, true);
        Field bufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        bufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) bufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(Base64.getDecoder().decode(buildFrameB64(
                0x21, new byte[] { 'x' })));
        inputBuffer.flip();

        // Charge the connection budget up to its exact limit. The padding
        // frame parsed by the after-trailer scan must then exceed it.
        Assert.assertFalse(manager.getState(connection)
                .noteRequestNonBodyFrame(
                        Http3ConnectionManager.MAX_CONNECTION_NON_BODY_BYTES));

        Method scan = Http3Processor.class.getDeclaredMethod(
                "checkFramesAfterTrailer", SocketWrapperBase.class);
        scan.setAccessible(true);
        scan.invoke(processor, wrapper);

        Assert.assertEquals("Padding after the trailer section must be "
                + "charged to the connection-lifetime budget",
                Http3Error.H3_EXCESSIVE_LOAD.getCode(),
                connection.failureCode.intValue());
    }


    @Test
    public void testReadinessDoesNotParsePartialDataPayloadAsPadding()
            throws Exception {
        // While a DATA frame is being streamed, the input buffer contains
        // payload continuation bytes, not frame headers. The readiness
        // padding scan must not interpret those bytes as zero-length DATA
        // frames and consume them as padding.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream();
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field partialField = inBuf.getClass().getDeclaredField(
                "partialDataRemaining");
        partialField.setAccessible(true);
        partialField.setInt(inBuf, 2);

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(new byte[] { 0, 0, 0, 0 });
        inputBuffer.flip();
        int position = inputBuffer.position();

        Method consumePadding = Http3Processor.class.getDeclaredMethod(
                "consumePaddingFrames");
        consumePadding.setAccessible(true);
        Assert.assertEquals("Partial DATA payload bytes must not be consumed "
                + "as padding", Boolean.FALSE,
                consumePadding.invoke(processor));
        Assert.assertEquals("Partial DATA payload bytes must remain in the "
                + "input buffer", position, inputBuffer.position());
    }


    @Test
    public void testReadinessIgnoresPartiallySkippedIgnoredFramePayload()
            throws Exception {
        // While an ignored-frame payload skip is staged, the input buffer
        // contains payload continuation bytes. They must not be parsed as a
        // frame header and advertised as readable.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream();
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field pendingSkip = inBuf.getClass().getDeclaredField(
                "pendingSkipRemaining");
        pendingSkip.setAccessible(true);
        pendingSkip.setLong(inBuf, 10L);

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        // Looks like DATA, length=1, one payload byte, but it is actually the
        // continuation of the ignored frame's payload.
        inputBuffer.put(new byte[] { 0, 1, 0x41 });
        inputBuffer.flip();

        Assert.assertFalse("Partially skipped ignored-frame payload bytes "
                + "must not be parsed as a frame header",
                processor.isReadyForRead());
    }


    @Test
    public void testReadinessIgnoresStagedTrailerPayload() throws Exception {
        // A partially read trailer section is staged in trailerPayload and
        // the input buffer holds its payload continuation. Readiness must not
        // parse those bytes as a frame header.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream();
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Object inBuf = processor.getRequest().getInputBuffer();
        Field trailerPayload = inBuf.getClass().getDeclaredField(
                "trailerPayload");
        trailerPayload.setAccessible(true);
        trailerPayload.set(inBuf,
                ByteBuffer.wrap(new byte[] { 0, 1, 0x41 }));

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(new byte[] { 0, 1, 0x41 });
        inputBuffer.flip();

        Assert.assertFalse("Staged trailer payload bytes must not be parsed "
                + "as a frame header", processor.isReadyForRead());
    }


    @Test
    public void testPaddingOnlyReadinessChargesNonBodyBudget()
            throws Exception {
        // A stream carrying only zero-length DATA frames makes no body
        // progress and is not advertised as readable by the normal frame scan.
        // The readiness probe must nevertheless consume and charge those
        // frames so a peer cannot bypass the padding budget by keeping the
        // stream open with padding alone.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicStream getQuicStream() {
                return new StubQuicStream();
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field inputBufferHasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        inputBufferHasData.setAccessible(true);
        inputBufferHasData.setBoolean(processor, true);
        Field inputBufferField =
                Http3Processor.class.getDeclaredField("inputBuffer");
        inputBufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) inputBufferField.get(processor);
        inputBuffer.clear();
        // One more than Http3Processor.MAX_NON_BODY_FRAMES zero-length DATA
        // frames; each frame is a type 0x00 varint followed by length 0x00.
        for (int i = 0; i < 16385; i++) {
            inputBuffer.put((byte) 0);
            inputBuffer.put((byte) 0);
        }
        inputBuffer.flip();

        Assert.assertTrue("A budget failure must be reported as ready so "
                + "the reader observes the connection error",
                processor.isReadyForRead());
        Assert.assertEquals("Padding-only frames must charge the non-body "
                + "budget", Long.valueOf(H3_EXCESSIVE_LOAD),
                wrapper.connection.failureCode);
    }


    @Test
    public void testAfterResponseTrailerScanChargesConnectionPaddingBudget()
            throws Exception {
        // The after-response trailer scan is the only frame consumer for a
        // request the application never drained. Its padding frames must
        // also count against the connection-lifetime budget.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);
        StubQuicConnection connection = new StubQuicConnection() {
            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }
        };
        manager.connectionOpen(connection);

        Http3Processor processor = new Http3Processor(protocol, TEST_ADAPTER);
        processor.setStreamId(0);
        processor.setConnectionState(manager.getState(connection));

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper() {
            @Override
            public QuicConnection getConnection() {
                return connection;
            }
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

        Field hasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        hasData.setAccessible(true);
        hasData.setBoolean(processor, true);
        Field bufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        bufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) bufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(Base64.getDecoder().decode(buildFrameB64(
                0x21, new byte[] { 'x' })));
        inputBuffer.flip();

        Assert.assertFalse(manager.getState(connection)
                .noteRequestNonBodyFrame(
                        Http3ConnectionManager.MAX_CONNECTION_NON_BODY_BYTES));

        Method scan = Http3Processor.class.getDeclaredMethod(
                "decodeTrailerSectionAfterResponse",
                SocketWrapperBase.class);
        scan.setAccessible(true);
        scan.invoke(processor, wrapper);

        Assert.assertEquals("Padding in the after-response trailer scan must "
                + "be charged to the connection-lifetime budget",
                Http3Error.H3_EXCESSIVE_LOAD.getCode(),
                connection.failureCode.intValue());
    }


    @Test
    public void testFramesAfterTrailerCompletedAfterSplitDelivery()
            throws Exception {
        // A post-trailer frame header split across a read boundary (here a
        // DATA type byte plus the first byte of a two-byte length varint)
        // must not end the after-trailer scan: the scan has to re-read the
        // socket and complete the header once the continuation byte
        // arrives, so the frame is classified and the mandated
        // H3_FRAME_UNEXPECTED connection error is raised. The scan that
        // gave up on the parse failure (rather than refilling) used to drop
        // the error for such a split header.
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, null);
        processor.setStreamId(0);

        Object inBuf = processor.getRequest().getInputBuffer();
        Method setTrailers = inBuf.getClass().getDeclaredMethod(
                "setTrailersReceived", Boolean.TYPE);
        setTrailers.setAccessible(true);
        setTrailers.invoke(inBuf, Boolean.TRUE);

        // readFrame() sets this flag with its first read on any real
        // stream; the scan's refill must then preserve the retained bytes
        // (compact), as it does after any request has been read.
        Field hasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        hasData.setAccessible(true);
        hasData.setBoolean(processor, true);

        // The post-trailer state on a real stream: the input buffer was
        // used by the frame reads and everything received has been
        // consumed (position == limit). A never-read buffer never reaches
        // this scan on a real stream.
        Field bufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        bufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) bufferField.get(processor);
        inputBuffer.limit(0);

        StubQuicSocketWrapper wrapper = new StubQuicSocketWrapper();
        wrapper.enqueue(new byte[] { 0x00, 0x40 });

        Method scan = Http3Processor.class.getDeclaredMethod(
                "checkFramesAfterTrailer", SocketWrapperBase.class);
        scan.setAccessible(true);

        // First delivery: the frame header is incomplete; nothing is
        // classified and the connection stays up.
        scan.invoke(processor, wrapper);
        Assert.assertNull("Connection failed before the header completed",
                wrapper.connection.failureCode);
        int readsAfterFirstDelivery = wrapper.readCount.get();

        // The continuation byte completes the declared length (1). The
        // scan must re-read, complete the header and fail the connection
        // with H3_FRAME_UNEXPECTED (RFC 9114 Section 4.1).
        wrapper.enqueue(new byte[] { 0x01 });
        scan.invoke(processor, wrapper);

        Assert.assertTrue("checkFramesAfterTrailer() never re-read the "
                + "socket after the continuation byte became available: "
                + "the scan gave up on the incomplete header",
                wrapper.readCount.get() > readsAfterFirstDelivery);
        Assert.assertEquals("Expected the H3_FRAME_UNEXPECTED connection "
                + "error for the DATA frame after the trailer section",
                Long.valueOf(H3_FRAME_UNEXPECTED),
                wrapper.connection.failureCode);
    }


    /*
     * Read queue shared by both socket wrapper stubs: serves reads from a
     * queue of byte arrays (a would-block once the queue is drained),
     * counting every read attempt. Only the ByteBuffer read path is
     * exercised; every other operation fails fast so an unintended use of
     * the stub is visible immediately.
     */
    private static class StubReadQueue {

        private final Deque<byte[]> queued = new ArrayDeque<>();
        final AtomicInteger readCount = new AtomicInteger();

        void enqueue(byte[] data) {
            queued.add(data);
        }

        int read(ByteBuffer to) {
            readCount.incrementAndGet();
            byte[] chunk = queued.poll();
            if (chunk == null) {
                return 0;
            }
            int len = Math.min(chunk.length, to.remaining());
            to.put(chunk, 0, len);
            return len;
        }

        boolean isReady() {
            return !queued.isEmpty();
        }
    }


    /*
     * Read-queue stub that is also a QUIC socket wrapper, so the failure
     * paths that navigate from the wrapper to the connection (failConnection)
     * run and record the application error code instead of stopping at the
     * plain-wrapper instanceof check. A QUIC socket wrapper is itself a
     * SocketWrapperBase subclass, so - unlike when QuicSocketWrapper was an
     * interface - the read behaviour cannot be shared by extending
     * StubReadSocketWrapper; it is shared through the queue instead.
     */
    private static class StubQuicSocketWrapper extends QuicSocketWrapper {

        private final StubReadQueue queue = new StubReadQueue();
        final AtomicInteger readCount = queue.readCount;

        private final StubQuicConnection connection =
                new StubQuicConnection();

        StubQuicSocketWrapper() {
            super(new StubQuicStream(), new StubEndpoint<>());
        }

        void enqueue(byte[] data) {
            queue.enqueue(data);
        }

        @Override
        public int read(boolean block, ByteBuffer to) throws IOException {
            return queue.read(to);
        }

        @Override
        public int read(boolean block, byte[] b, int off, int len)
                throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isReadyForRead() throws IOException {
            return queue.isReady();
        }

        @Override
        public void setAppReadBufHandler(ApplicationBufferHandler handler) {
            // Not used
        }

        @Override
        public QuicStream getQuicStream() {
            return null;
        }

        @Override
        public QuicConnection getConnection() {
            return connection;
        }

        @Override
        public void pumpConnectionEvents() {
            // Not used
        }

        @Override
        public boolean awaitReadableData(long deadlineNanos) {
            return false;
        }

        @Override
        public boolean isStreamConcluded() {
            return false;
        }

        @Override
        public void concludeStream() throws IOException {
            // Not used
        }

        @Override
        public boolean resetStream(long appErrorCode) {
            return false;
        }

        @Override
        protected void populateRemoteHost() {
            // Not used
        }

        @Override
        protected void populateRemoteAddr() {
            // Not used
        }

        @Override
        protected void populateRemotePort() {
            // Not used
        }

        @Override
        protected void populateLocalName() {
            // Not used
        }

        @Override
        protected void populateLocalAddr() {
            // Not used
        }

        @Override
        protected void populateLocalPort() {
            // Not used
        }

        @Override
        protected void doClose() {
            // Not used
        }

        @Override
        protected boolean flushNonBlocking() throws IOException {
            return true;
        }

        @Override
        protected void doWrite(boolean block, ByteBuffer from) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerReadInterest() {
            // Not used
        }

        @Override
        public void registerWriteInterest() {
            // Not used
        }

        @Override
        public SendfileDataBase createSendfileData(String filename, long pos,
                long length) {
            throw new UnsupportedOperationException();
        }

        @Override
        public SendfileState processSendfile(SendfileDataBase sendfileData) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void doClientAuth(SSLSupport sslSupport) {
            throw new UnsupportedOperationException();
        }

        @Override
        public SSLSupport getSslSupport() {
            return null;
        }

        @Override
        protected <A> OperationState<A> newOperationState(boolean read,
                ByteBuffer[] buffers, int offset, int length,
                BlockingMode block, long timeout, TimeUnit unit,
                A attachment, CompletionCheck check,
                CompletionHandler<Long, ? super A> handler,
                Semaphore semaphore,
                VectoredIOCompletionHandler<A> completion) {
            throw new UnsupportedOperationException();
        }
    }


    /*
     * Controlled QUIC wrapper used by the non-blocking write tests. It
     * simulates the wrapper staging buffer: writeNonBlocking() consumes the
     * whole frame, flushNonBlocking() drains it only while writable.
     */
    private static class ControlledQuicSocketWrapper
            extends StubQuicSocketWrapper {

        private final List<Integer> frameTypes = new ArrayList<>();
        private int queuedBytes;
        private int sentBytes;
        private int writeInterestCount;
        private boolean writable = true;
        private boolean blockingWrite;
        private boolean concluded;
        private int resetCode = -1;

        @Override
        protected void writeNonBlocking(ByteBuffer from) {
            int len = from.remaining();
            if (len > 0) {
                frameTypes.add(Integer.valueOf(from.get(from.position()) & 0xFF));
            }
            from.position(from.limit());
            queuedBytes += len;
        }

        @Override
        protected void writeBlocking(ByteBuffer from) {
            blockingWrite = true;
            int len = from.remaining();
            from.position(from.limit());
            queuedBytes += len;
        }

        @Override
        protected boolean flushNonBlocking() throws IOException {
            if (writable) {
                sentBytes += queuedBytes;
                queuedBytes = 0;
                return false;
            }
            return queuedBytes > 0;
        }

        @Override
        protected void flushBlocking() {
            blockingWrite = true;
            sentBytes += queuedBytes;
            queuedBytes = 0;
        }

        @Override
        public boolean canWrite() {
            return writable && queuedBytes < 64 * 1024;
        }

        @Override
        public void registerWriteInterest() {
            writeInterestCount++;
        }

        @Override
        public void concludeStream() {
            concluded = true;
        }

        @Override
        public boolean resetStream(long appErrorCode) {
            resetCode = (int) appErrorCode;
            return true;
        }
    }


    /*
     * QUIC stream stub for the QUIC socket wrapper stub above. The wrapper
     * never hands the stream to transport code; only its identity reaches
     * the SocketWrapperBase constructor.
     */
    private static class StubQuicStream implements QuicStream {

        @Override
        public long getStreamId() {
            return 0;
        }

        @Override
        public QuicConnection getConnection() {
            return null;
        }

        @Override
        public ReadState getReadState() {
            return ReadState.OK;
        }

        @Override
        public boolean isFreed() {
            return false;
        }

        @Override
        public ByteBuffer getWriteBuffer() {
            return null;
        }
    }


    /*
     * QUIC connection stub that records the first application error code
     * passed to failConnection().
     */
    private static class StubQuicConnection implements QuicConnection {

        private volatile Long failureCode;

        @Override
        public QuicConnectionManager getQuicConnectionManager() {
            return null;
        }

        @Override
        public String getSniHostName() {
            return "";
        }

        @Override
        public void failConnection(long appErrorCode, String reason) {
            if (failureCode == null) {
                failureCode = Long.valueOf(appErrorCode);
            }
        }

        @Override
        public int writeToStream(QuicStream stream, ByteBuffer data) {
            return 0;
        }
    }


    /*
     * Socket wrapper that serves reads from a shared StubReadQueue. Stays a
     * plain SocketWrapperBase: the failure paths that stop at the
     * QuicSocketWrapper instanceof check are driven by this stub, while
     * StubQuicSocketWrapper drives the ones past that check.
     */
    private static class StubReadSocketWrapper
            extends SocketWrapperBase<Object> {

        private final StubReadQueue queue = new StubReadQueue();
        final AtomicInteger readCount = queue.readCount;

        StubReadSocketWrapper() {
            super(new Object(), new StubEndpoint<>());
        }

        void enqueue(byte[] data) {
            queue.enqueue(data);
        }

        @Override
        public int read(boolean block, ByteBuffer to) throws IOException {
            return queue.read(to);
        }

        @Override
        public int read(boolean block, byte[] b, int off, int len)
                throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isReadyForRead() throws IOException {
            return queue.isReady();
        }

        @Override
        public void setAppReadBufHandler(ApplicationBufferHandler handler) {
            // Not used
        }

        @Override
        protected void populateRemoteHost() {
            // Not used
        }

        @Override
        protected void populateRemoteAddr() {
            // Not used
        }

        @Override
        protected void populateRemotePort() {
            // Not used
        }

        @Override
        protected void populateLocalName() {
            // Not used
        }

        @Override
        protected void populateLocalAddr() {
            // Not used
        }

        @Override
        protected void populateLocalPort() {
            // Not used
        }

        @Override
        protected void doClose() {
            // Not used
        }

        @Override
        protected boolean flushNonBlocking() throws IOException {
            return true;
        }

        @Override
        protected void doWrite(boolean block, ByteBuffer from) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void registerReadInterest() {
            // Not used
        }

        @Override
        public void registerWriteInterest() {
            // Not used
        }

        @Override
        public SendfileDataBase createSendfileData(String filename, long pos,
                long length) {
            throw new UnsupportedOperationException();
        }

        @Override
        public SendfileState processSendfile(SendfileDataBase sendfileData) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void doClientAuth(SSLSupport sslSupport) {
            throw new UnsupportedOperationException();
        }

        @Override
        public SSLSupport getSslSupport() {
            return null;
        }

        @Override
        protected <A> OperationState<A> newOperationState(boolean read,
                ByteBuffer[] buffers, int offset, int length,
                BlockingMode block, long timeout, TimeUnit unit,
                A attachment, CompletionCheck check,
                CompletionHandler<Long, ? super A> handler,
                Semaphore semaphore,
                VectoredIOCompletionHandler<A> completion) {
            throw new UnsupportedOperationException();
        }

    }


    private static class Status413Servlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
            resp.setContentType("text/plain");
            resp.getWriter().print("OK");
        }
    }


    /*
     * Endpoint stub generic in the socket type, so it fits both wrapper
     * stubs' SocketWrapperBase constructors (an Object socket for the plain
     * stub, a QuicStream socket for the QUIC one).
     *
     * @param <S> The socket type
     */
    /*
     * Decodes the single HEADERS frame captured by a response header test.
     * The frame starts with the HEADERS type and length QUIC varints followed
     * by the QPACK field section.
     */
    private static Map<String,String> decodeResponseHeaderFrame(
            byte[] frameBytes) throws Exception {
        ByteBuffer frame = ByteBuffer.wrap(frameBytes);
        long frameType = Qpack.decodeQuicInteger(frame);
        Assert.assertEquals("Expected a HEADERS frame", Constants.H3_HEADERS,
                frameType);
        long frameLength = Qpack.decodeQuicInteger(frame);
        Assert.assertTrue("The captured HEADERS frame is truncated",
                frameLength <= frame.remaining());
        ByteBuffer payload = ByteBuffer.wrap(frameBytes, frame.position(),
                (int) frameLength);
        Map<String,String> headers = new HashMap<>();
        QpackDecoder decoder = new QpackDecoder();
        decoder.decodeHeaderBlock(payload,
                (name, value) -> headers.put(name, value));
        return headers;
    }


    /*
     * Blocking QUIC wrapper that captures every frame written to it, so
     * response header tests can decode the emitted field section.
     */
    private static class CapturingQuicSocketWrapper
            extends ControlledQuicSocketWrapper {

        private final ByteArrayOutputStream captured =
                new ByteArrayOutputStream();

        @Override
        protected void writeBlocking(ByteBuffer from) {
            ByteBuffer view = from.duplicate();
            byte[] bytes = new byte[view.remaining()];
            view.get(bytes);
            captured.write(bytes, 0, bytes.length);
            super.writeBlocking(from);
        }
    }


    private static class RecordingTestAdapter extends TestAdapter {

        private final AtomicInteger serviceCount = new AtomicInteger();
        private final AtomicInteger logCount = new AtomicInteger();

        @Override
        public void service(org.apache.coyote.Request req,
                org.apache.coyote.Response res) {
            serviceCount.incrementAndGet();
        }

        @Override
        public void log(org.apache.coyote.Request req,
                org.apache.coyote.Response res, long time) {
            logCount.incrementAndGet();
        }
    }


    private static class TestAdapter implements org.apache.coyote.Adapter {

        @Override
        public void service(org.apache.coyote.Request req,
                org.apache.coyote.Response res) {
            // NO-OP
        }

        @Override
        public boolean prepare(org.apache.coyote.Request req,
                org.apache.coyote.Response res) {
            return true;
        }

        @Override
        public boolean asyncDispatch(org.apache.coyote.Request req,
                org.apache.coyote.Response res, SocketEvent status) {
            return true;
        }

        @Override
        public void log(org.apache.coyote.Request req,
                org.apache.coyote.Response res, long time) {
            // NO-OP
        }

        @Override
        public void checkRecycled(org.apache.coyote.Request req,
                org.apache.coyote.Response res) {
            // NO-OP
        }

        @Override
        public String getDomain() {
            return "test";
        }
    }


    private static class StubEndpoint<S>
            extends AbstractEndpoint<S, Object> {

        @Override
        protected InetSocketAddress getLocalAddress() {
            return null;
        }

        @Override
        protected SocketProcessorBase<S> createSocketProcessor(
                SocketWrapperBase<S> socketWrapper,
                SocketEvent event) {
            return null;
        }

        @Override
        public void bind() {
            // Not used
        }

        @Override
        public void startInternal() {
            // Not used
        }

        @Override
        public void stopInternal() {
            // Not used
        }

        @Override
        protected Log getLog() {
            return LogFactory.getLog(StubEndpoint.class);
        }

        @Override
        protected void doCloseServerSocket() {
            // Not used
        }

        @Override
        protected Object serverSocketAccept() {
            return null;
        }

        @Override
        protected boolean setSocketOptions(Object socket) {
            return false;
        }

        @Override
        protected void destroySocket(Object socket) {
            // Not used
        }
    }
}

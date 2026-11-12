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
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
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
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

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
import org.apache.coyote.ContinueResponseTiming;
import org.apache.coyote.ErrorState;
import org.apache.coyote.Response;
import org.apache.coyote.UpgradeToken;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
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
        };
        Method setWrapper = AbstractProcessor.class.getDeclaredMethod(
                "setSocketWrapper", SocketWrapperBase.class);
        setWrapper.setAccessible(true);
        setWrapper.invoke(processor, wrapper);

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

        // A complete empty DATA frame is consumable and may be reported ready.
        inputBuffer.clear();
        inputBuffer.put(new byte[] { 0x00, 0x00 });
        inputBuffer.flip();
        Assert.assertTrue("A complete frame must be reported as ready for "
                + "reading", processor.isReadyForRead());
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
        public void concludeStream() {
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
        protected boolean flushNonBlocking() {
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


    /*
     * Endpoint stub generic in the socket type, so it fits both wrapper
     * stubs' SocketWrapperBase constructors (an Object socket for the plain
     * stub, a QuicStream socket for the QUIC one).
     *
     * @param <S> The socket type
     */
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

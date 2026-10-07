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
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Assert;
import org.junit.Test;

import org.apache.coyote.UpgradeToken;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.AbstractEndpoint;
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

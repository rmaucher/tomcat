/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.coyote.http3;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.junit.Assert;
import org.junit.Test;

import org.apache.coyote.InputBuffer;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.net.ApplicationBufferHandler;


/**
 * Tests the saved-request body replay path used by
 * {@code FormAuthenticator} (ActionCode.REQ_SET_BODY_REPLAY).
 */
public class TestHttp3ReplayBody extends Http3TestBase {

    @Test
    public void testReplayedBodyIsServedThenEnds() throws Exception {
        Http3Processor processor =
                new Http3Processor(newHttp3Protocol(), null);
        byte[] body = "body!".getBytes(StandardCharsets.UTF_8);

        ByteChunk chunk = new ByteChunk();
        chunk.setBytes(body, 0, body.length);
        processor.setRequestBody(chunk);

        InputBuffer input = processor.getRequest().getInputBuffer();
        TestBufferHandler handler = new TestBufferHandler();

        Assert.assertEquals("First read length", body.length,
                input.doRead(handler));
        byte[] read = new byte[body.length];
        handler.getByteBuffer().get(read);
        Assert.assertArrayEquals("Replayed body bytes", body, read);
        Assert.assertEquals("End of replayed body", -1,
                input.doRead(handler));
        Assert.assertTrue("A consumed replayed body is reported as fully read",
                processor.isRequestBodyFullyRead());
        Assert.assertFalse("The transport stream was not ended by the replay, "
                + "so trailer readiness must not claim a clean empty trailer "
                + "map", processor.isTrailerFieldsReady());
    }


    @Test
    public void testSetRequestBodyIsSerialisedWithBodyReads() throws Exception {
        // Replacing the input buffer while a body read is copying from it
        // would corrupt the reader's view. The replay installation must take
        // the same input-read lock as doRead().
        Http3Processor processor =
                new Http3Processor(newHttp3Protocol(), null);
        byte[] body = "body!".getBytes(StandardCharsets.UTF_8);
        ByteChunk chunk = new ByteChunk();
        chunk.setBytes(body, 0, body.length);

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
        }, "http3-replay-lock-holder");
        holder.setDaemon(true);
        holder.start();
        locked.await();

        CountDownLatch replayStarted = new CountDownLatch(1);
        CountDownLatch replayDone = new CountDownLatch(1);
        Thread replay = new Thread(() -> {
            replayStarted.countDown();
            processor.setRequestBody(chunk);
            replayDone.countDown();
        }, "http3-replay-installer");
        replay.setDaemon(true);
        replay.start();
        replayStarted.await();

        boolean completedEarly;
        try {
            completedEarly = replayDone.await(200, TimeUnit.MILLISECONDS);
        } finally {
            release.countDown();
            holder.join();
        }
        Assert.assertFalse("setRequestBody() must wait for a concurrent body "
                + "read to release the input-read lock", completedEarly);
        Assert.assertTrue("setRequestBody() did not complete after the input "
                + "read lock was released",
                replayDone.await(5, TimeUnit.SECONDS));
        replay.join();
    }


    @Test
    public void testReplayedBodyResetsContentLengthAccounting()
            throws Exception {
        // FormAuthenticator restores the saved headers before invoking
        // REQ_SET_BODY_REPLAY. The request object may still carry the
        // Content-Length cached from the login request, while the HTTP/3
        // private framing counters describe that login request. The replay
        // must replace both with the saved body's length, otherwise the
        // readiness probes compare unrelated values and never report the
        // replayed body as complete.
        Http3Processor processor =
                new Http3Processor(newHttp3Protocol(), null);
        processor.getRequest().setContentLength(3);
        Field requestContentLength = Http3Processor.class.getDeclaredField(
                "requestContentLength");
        requestContentLength.setAccessible(true);
        requestContentLength.setLong(processor, 3);
        Field totalDataReceived = Http3Processor.class.getDeclaredField(
                "totalDataReceived");
        totalDataReceived.setAccessible(true);
        totalDataReceived.setLong(processor, 0);

        byte[] body = "body!".getBytes(StandardCharsets.UTF_8);
        ByteChunk chunk = new ByteChunk();
        chunk.setBytes(body, 0, body.length);
        processor.setRequestBody(chunk);

        Assert.assertEquals("The restored Content-Length must describe the "
                + "replayed body", body.length,
                processor.getRequest().getContentLengthLong());
        Assert.assertEquals("The HTTP/3 content-length accounting must "
                + "describe the replayed body", body.length,
                requestContentLength.getLong(processor));
        Assert.assertEquals("The received-body accounting must describe the "
                + "replayed body", body.length,
                totalDataReceived.getLong(processor));

        InputBuffer input = processor.getRequest().getInputBuffer();
        TestBufferHandler handler = new TestBufferHandler();
        Assert.assertEquals("First read length", body.length,
                input.doRead(handler));
        Assert.assertEquals("End of replayed body", -1,
                input.doRead(handler));
        Assert.assertTrue("A consumed replayed body must be reported as fully "
                + "read", processor.isRequestBodyFullyRead());
        Assert.assertFalse("The replayed body must not claim a clean transport "
                + "stream end", processor.isTrailerFieldsReady());
    }


    @Test
    public void testReplayDoesNotClaimCleanStreamEndWithoutFin()
            throws Exception {
        // A saved-request body replay is a body replacement, not an end of
        // the QUIC request stream. Without a transport FIN, the readiness
        // probe must not report an empty trailer map for a stream that may
        // still deliver a trailer section, and the abandoned original stream
        // owes a QPACK Stream Cancellation (RFC 9204 Section 2.2.2.2).
        Http3Processor processor =
                new Http3Processor(newHttp3Protocol(), null);
        processor.setStreamId(0);
        byte[] body = "body!".getBytes(StandardCharsets.UTF_8);
        ByteChunk chunk = new ByteChunk();
        chunk.setBytes(body, 0, body.length);
        processor.setRequestBody(chunk);

        InputBuffer input = processor.getRequest().getInputBuffer();
        TestBufferHandler handler = new TestBufferHandler();
        Assert.assertEquals("First read length", body.length,
                input.doRead(handler));
        Assert.assertEquals("End of replayed body", -1,
                input.doRead(handler));

        Assert.assertFalse("A replay must not claim a clean trailer end before "
                + "the transport stream ended",
                processor.isTrailerFieldsReady());
        Assert.assertTrue("The replayed body must still be reported as fully "
                + "read", processor.isRequestBodyFullyRead());

        Field cancellationSent = Http3Processor.class.getDeclaredField(
                "streamCancellationSent");
        cancellationSent.setAccessible(true);
        Assert.assertTrue("Abandoning the replaced request stream must queue "
                + "the QPACK Stream Cancellation",
                cancellationSent.getBoolean(processor));
    }


    @Test
    public void testReplayClearsProtocolFrameState() throws Exception {
        // Protocol frame state left over from the replaced request must not
        // be interpreted as belonging to the replayed body.
        Http3Processor processor =
                new Http3Processor(newHttp3Protocol(), null);
        processor.setStreamId(0);

        Object inBuf = processor.getRequest().getInputBuffer();
        setField(inBuf, "pendingSkipRemaining", Long.valueOf(7));
        setField(inBuf, "partialDataRemaining", Integer.valueOf(3));
        setField(inBuf, "trailerPayload", ByteBuffer.allocate(4));
        Field bufferField = Http3Processor.class.getDeclaredField(
                "inputBuffer");
        bufferField.setAccessible(true);
        ByteBuffer inputBuffer = (ByteBuffer) bufferField.get(processor);
        inputBuffer.clear();
        inputBuffer.put(new byte[] { 1, 2, 3 });
        inputBuffer.flip();
        Field hasData = Http3Processor.class.getDeclaredField(
                "inputBufferHasData");
        hasData.setAccessible(true);
        hasData.setBoolean(processor, true);

        byte[] body = "body!".getBytes(StandardCharsets.UTF_8);
        ByteChunk chunk = new ByteChunk();
        chunk.setBytes(body, 0, body.length);
        processor.setRequestBody(chunk);

        Assert.assertEquals("A replay must discard a pending ignored-frame "
                + "skip", 0L, getField(inBuf, "pendingSkipRemaining"));
        Assert.assertEquals("A replay must discard a partial DATA frame", 0,
                getField(inBuf, "partialDataRemaining"));
        Assert.assertNull("A replay must discard a staged trailer section",
                getField(inBuf, "trailerPayload"));
        Assert.assertEquals("A replay must discard the replaced request's "
                + "protocol input buffer bytes", 0,
                inputBuffer.remaining());
    }


    private static void setField(Object target, String name, Object value)
            throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }


    private static Object getField(Object target, String name)
            throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }


    private static class TestBufferHandler implements ApplicationBufferHandler {

        private ByteBuffer buffer = ApplicationBufferHandler.EMPTY_BUFFER;

        @Override
        public void setByteBuffer(ByteBuffer buffer) {
            this.buffer = buffer;
        }

        @Override
        public ByteBuffer getByteBuffer() {
            return buffer;
        }

        @Override
        public void expand(int newSize) {
            // Not used
        }
    }
}

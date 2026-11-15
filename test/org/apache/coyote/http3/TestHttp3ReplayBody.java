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
        Assert.assertTrue("Replayed body is at end of stream",
                processor.isTrailerFieldsReady());
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
        Assert.assertTrue("A consumed replayed body must report ready trailer "
                + "fields", processor.isTrailerFieldsReady());
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

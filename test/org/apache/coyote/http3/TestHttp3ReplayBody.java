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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

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

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

import java.io.IOException;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;

/*
 * HTTP/3 version of org.apache.coyote.http2.TestAsyncFlush.
 *
 * Based on
 * https://bz.apache.org/bugzilla/show_bug.cgi?id=62635
 *
 * Note: Calling blocking I/O methods (such as flushBuffer()) during
 *       non-blocking I/O is explicitly called out as illegal in the Servlet
 *       specification but also goes on to say the behaviour if such a call is
 *       made is undefined. Which means it is OK if the call works as expected
 *       (a non-blocking flush is triggered) :).
 *       If any of these tests fail, that should not block a release since -
 *       while the specification allows this to work - it doesn't require that
 *       it does work.
 */
public class TestAsyncFlush extends Http3TestBase {

    private static final int BLOCK_SIZE = 1024;

    @Test
    public void testFlush() throws Exception {
        int blockCount = 2048;

        int targetSize = BLOCK_SIZE * blockCount;

        startHttp3Server(ctxt -> {
            Wrapper w = Tomcat.addServlet(ctxt, "async",
                    new AsyncFlushServlet(blockCount));
            w.setAsyncSupported(true);
            ctxt.addServletMapping("/async", "async");
        });

        // The aioquic client handles QUIC flow control (window updates)
        // internally, so no window management is needed here as in the
        // HTTP/2 test. The full body is simply consumed.
        Http3Response response = get("/async");
        validateStatus(response, HttpServletResponse.SC_OK);

        // Check that the right number of bytes were received
        Assert.assertEquals(targetSize, response.getBody().length);
    }


    public static class AsyncFlushServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final int blockLimit;

        public AsyncFlushServlet(int blockLimit) {
            this.blockLimit = blockLimit;
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws IOException {

            final AsyncContext asyncContext = request.startAsync();

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/binary");

            final ServletOutputStream output = response.getOutputStream();
            output.setWriteListener(new WriteListener() {

                int blockCount;
                byte[] bytes = new byte[BLOCK_SIZE];


                @Override
                public void onWritePossible() throws IOException {
                    while (output.isReady()) {
                        blockCount++;
                        output.write(bytes);
                        if (blockCount % 5 == 0) {
                            response.flushBuffer();
                        }
                        if (blockCount == blockLimit) {
                            asyncContext.complete();
                            return;
                        }
                    }
                }


                @Override
                public void onError(Throwable t) {
                    // Complete the response (truncated) so the client sees
                    // an early stream close instead of hanging until the
                    // test harness timeout expires. The assertion on the
                    // body length below then reports the failure.
                    asyncContext.complete();
                }
            });
        }
    }
}

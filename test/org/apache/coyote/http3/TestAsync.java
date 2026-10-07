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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;

/*
 * HTTP/3 version of org.apache.coyote.http2.TestAsync.
 *
 * Based on
 * https://bz.apache.org/bugzilla/show_bug.cgi?id=62614
 * https://bz.apache.org/bugzilla/show_bug.cgi?id=62620
 * https://bz.apache.org/bugzilla/show_bug.cgi?id=62628
 *
 * The HTTP/2 test streams an async response body while exercising the
 * flow-control window limits of the HTTP/2 transport (empty initial
 * windows, window expansion in both orders, unlimited windows, large
 * initial window). QUIC flow control is handled by the aioquic client
 * transparently, so the window parameters have no HTTP/3 equivalent.
 * The remaining significant axis is where the writes to the response
 * body are driven from: a container thread (the thread that reported
 * WriteListener.onWritePossible()) or a non-container thread (a thread
 * started by the application after the listener reported readiness).
 */
@RunWith(Parameterized.class)
public class TestAsync extends Http3TestBase {

    private static final int BLOCK_SIZE = 0x8000;

    @Parameterized.Parameters(name = "{index}: useNonContainerThreadForWrite[{0}]")
    public static Collection<Object[]> parameters() {
        List<Object[]> parameterSets = new ArrayList<>();
        parameterSets.add(new Object[] { Boolean.FALSE });
        parameterSets.add(new Object[] { Boolean.TRUE });
        return parameterSets;
    }


    private final boolean useNonContainerThreadForWrite;


    public TestAsync(boolean useNonContainerThreadForWrite) {
        this.useNonContainerThreadForWrite = useNonContainerThreadForWrite;
    }


    @Test
    public void testEmptyWindow() throws Exception {
        int blockCount = 8;

        int targetSize = BLOCK_SIZE * blockCount;

        startHttp3Server(ctxt -> {
            Wrapper w = Tomcat.addServlet(ctxt, "async",
                    new AsyncServlet(blockCount, useNonContainerThreadForWrite));
            w.setAsyncSupported(true);
            ctxt.addServletMapping("/async", "async");
        });

        Http3Response response = get("/async");
        validateStatus(response, HttpServletResponse.SC_OK);

        // Check that the right number of bytes were received
        Assert.assertEquals(targetSize, response.getBody().length);
    }


    public static class AsyncServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final int blockLimit;
        private final boolean useNonContainerThreadForWrite;
        private final transient ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        private transient volatile Future<?> future;

        public AsyncServlet(int blockLimit, boolean useNonContainerThreadForWrite) {
            this.blockLimit = blockLimit;
            this.useNonContainerThreadForWrite = useNonContainerThreadForWrite;
        }

        /*
         * Not thread-safe. OK for this test. NOt OK for use in the real world.
         */
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

            final AsyncContext asyncContext = request.startAsync();

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/binary");

            final ServletOutputStream output = response.getOutputStream();
            output.setWriteListener(new WriteListener() {

                // Intermittent CI errors were observed where the response body
                // was exactly one block too small. Use an AtomicInteger to be
                // sure blockCount is thread-safe.
                final AtomicInteger blockCount = new AtomicInteger(0);
                byte[] bytes = new byte[BLOCK_SIZE];


                @Override
                public void onWritePossible() throws IOException {
                    if (useNonContainerThreadForWrite) {
                        future = scheduler.schedule(new Runnable() {

                            @Override
                            public void run() {
                                try {
                                    write();
                                } catch (IOException ioe) {
                                    throw new IllegalStateException(ioe);
                                }
                            }
                        }, 200, TimeUnit.MILLISECONDS);
                    } else {
                        write();
                    }
                }


                private void write() throws IOException {
                    while (output.isReady()) {
                        blockCount.incrementAndGet();
                        output.write(bytes);
                        if (blockCount.get() == blockLimit) {
                            asyncContext.complete();
                            scheduler.shutdown();
                            return;
                        }
                    }
                }

                @Override
                public void onError(Throwable t) {
                    if (future != null) {
                        future.cancel(false);
                    }
                    t.printStackTrace();
                }
            });
        }
    }
}
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
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;

/*
 * HTTP/3 version of org.apache.coyote.http2.TestAsyncError.
 *
 * Based on
 * https://bz.apache.org/bugzilla/show_bug.cgi?id=66841
 */
public class TestAsyncError extends Http3TestBase {

    private final AsyncErrorServlet asyncErrorServlet = new AsyncErrorServlet();


    @Test
    public void testError() throws Exception {
        startHttp3Server(ctxt -> {
            Wrapper w = Tomcat.addServlet(ctxt, "async", asyncErrorServlet);
            w.setAsyncSupported(true);
            ctxt.addServletMapping("/async", "async");
        });

        // Cancel the request after three response lines ("OK\n" each). This
        // is the HTTP/3 equivalent of the HTTP/2 test reading three events
        // and then resetting the stream with a CANCEL RST_STREAM frame.
        getCancelled("/async", 3 * "OK\n".length());

        int count = 0;
        while (count < 50 && asyncErrorServlet.getErrorCount() == 0) {
            count++;
            Thread.sleep(100);
        }

        Assert.assertEquals(1, asyncErrorServlet.getErrorCount());
    }


    private static final class AsyncErrorServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final TestListener testListener = new TestListener();

        int getErrorCount() {
            return testListener.getErrorCount();
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {

            final AsyncContext asyncContext = req.startAsync();
            asyncContext.addListener(testListener);

            MessageGenerator msgGenerator = new MessageGenerator(resp);
            asyncContext.start(msgGenerator);
        }
    }


    private static final class MessageGenerator implements Runnable {

        private final HttpServletResponse resp;

        MessageGenerator(HttpServletResponse resp) {
            this.resp = resp;
        }

        @Override
        public void run() {
            try {
                resp.setContentType("text/plain");
                resp.setCharacterEncoding(StandardCharsets.UTF_8);
                PrintWriter pw = resp.getWriter();

                while (true) {
                    pw.println("OK");
                    pw.flush();
                    if (pw.checkError()) {
                        throw new IOException();
                    }
                    Thread.sleep(1000);
                }
            } catch (IOException | InterruptedException e) {
                // Expect async error handler to handle clean-up
            }
        }
    }


    private static final class TestListener implements AsyncListener {

        private final AtomicInteger errorCount = new AtomicInteger(0);

        public int getErrorCount() {
            return errorCount.get();
        }

        @Override
        public void onComplete(AsyncEvent event) throws IOException {
            // NO-OP
        }

        @Override
        public void onTimeout(AsyncEvent event) throws IOException {
            // NO-OP
        }

        @Override
        public void onError(AsyncEvent event) throws IOException {
            errorCount.incrementAndGet();
            event.getAsyncContext().complete();
        }

        @Override
        public void onStartAsync(AsyncEvent event) throws IOException {
            // NO-OP
        }
    }
}

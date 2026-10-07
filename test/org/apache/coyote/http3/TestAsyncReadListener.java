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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;

/*
 * HTTP/3 version of org.apache.coyote.http2.TestAsyncReadListener.
 *
 * The HTTP/2 test relies on the request being dispatched before the body
 * is complete (the servlet registers the ReadListener while the client is
 * still expected to send the body) and asserts that a client disconnect is
 * reported as an error to the ReadListener.
 *
 * The HTTP/3 processor does not dispatch before the request body is
 * complete: it reads until the stream ends (or the read pump gives up) and
 * then dispatches. The adapted test therefore sends a POST with a declared
 * content length and only part of the body (without ending the stream),
 * keeps the connection open briefly and then closes it. The request is
 * dispatched, the servlet registers the ReadListener, the partial body is
 * delivered and the truncated remainder of the body is reported as end of
 * stream (onAllDataRead) rather than as an error.
 */
public class TestAsyncReadListener extends Http3TestBase {

    private static final int DECLARED_BODY_LENGTH = 1000;
    private static final byte[] PARTIAL_BODY =
            "0123456789".getBytes(StandardCharsets.ISO_8859_1);

    private final AsyncServlet asyncServlet = new AsyncServlet();


    @Test
    public void testPartialBodyThenDisconnect() throws Exception {
        startHttp3Server(ctxt -> {
            Wrapper w = Tomcat.addServlet(ctxt, "async", asyncServlet);
            w.setAsyncSupported(true);
            ctxt.addServletMapping("/async", "async");
        });

        // POST with a declared body but only part of the body is sent and
        // the stream is not ended. The client keeps the connection open for
        // a few seconds (during which the server blocks waiting for the
        // rest of the body) and then closes it.
        String headers = buildFieldSection(
                ":method", "POST",
                ":scheme", "https",
                ":authority", "127.0.0.1:" + port,
                ":path", "/async",
                "content-length", Integer.toString(DECLARED_BODY_LENGTH));
        runClient(rawCommandWith(
                "--headers", headers,
                "--data", Base64.getEncoder().encodeToString(PARTIAL_BODY),
                "--no-fin",
                "--timeout", "2",
                "--wait", "4"), CLIENT_TIMEOUT_SECONDS);

        synchronized (asyncServlet) {
            long deadline = System.currentTimeMillis() + 15000;
            while (asyncServlet.error == null && !asyncServlet.allDataRead
                    && System.currentTimeMillis() < deadline) {
                asyncServlet.wait(
                        Math.max(10, deadline - System.currentTimeMillis()));
            }
        }

        Assert.assertNull("Unexpected ReadListener error: "
                + asyncServlet.error, asyncServlet.error);
        Assert.assertTrue("onAllDataRead was not called",
                asyncServlet.allDataRead);
        Assert.assertEquals(PARTIAL_BODY.length, asyncServlet.bytesReceived);
    }


    /**
     * The HTTP/3 equivalent of the HTTP/2 test asserting that the
     * {@link ReadListener} reports an error when the request ends while the
     * body is still incomplete (the HTTP/2 client closes the connection;
     * here the client resets its request stream with
     * {@code RESET_STREAM}, RFC 9000 Section 2.4, after the partial body
     * has been delivered and the listener registered).
     */
    @Test
    public void testRequestStreamReset() throws Exception {
        startHttp3Server(ctxt -> {
            Wrapper w = Tomcat.addServlet(ctxt, "async", asyncServlet);
            w.setAsyncSupported(true);
            ctxt.addServletMapping("/async", "async");
        });

        // POST with a declared body but only part of the body is sent and
        // the stream is not ended. The client resets the request stream
        // after two seconds, by which time the servlet has been dispatched
        // and has received the partial body.
        String headers = buildFieldSection(
                ":method", "POST",
                ":scheme", "https",
                ":authority", "127.0.0.1:" + port,
                ":path", "/async",
                "content-length", Integer.toString(DECLARED_BODY_LENGTH));
        runClient(rawCommandWith(
                "--headers", headers,
                "--data", Base64.getEncoder().encodeToString(PARTIAL_BODY),
                "--no-fin",
                "--reset-request", "2",
                "--timeout", "1",
                "--wait", "4"), CLIENT_TIMEOUT_SECONDS);

        synchronized (asyncServlet) {
            long deadline = System.currentTimeMillis() + 15000;
            while (asyncServlet.error == null && !asyncServlet.allDataRead
                    && System.currentTimeMillis() < deadline) {
                asyncServlet.wait(
                        Math.max(10, deadline - System.currentTimeMillis()));
            }
        }

        Assert.assertNotNull("No ReadListener error on reset. allDataRead="
                + asyncServlet.allDataRead, asyncServlet.error);
        Assert.assertFalse("onAllDataRead was called on a reset stream",
                asyncServlet.allDataRead);
        Assert.assertEquals(PARTIAL_BODY.length, asyncServlet.bytesReceived);
    }


    /*
     * A declared content length of zero describes a complete (empty) body:
     * no DATA frame is expected and none may arrive (a non-empty DATA frame
     * would violate the declared length). onAllDataRead must therefore be
     * delivered as soon as the request is dispatched, without waiting for
     * the client to end the stream. The client keeps the request stream
     * half-open (no FIN) for the whole of its run, so the assertion below
     * can only hold if completion is derived from the declared length and
     * not from the stream close.
     */
    @Test
    public void testZeroLengthBodyAllDataReadWithoutFin() throws Exception {
        startHttp3Server(ctxt -> {
            Wrapper w = Tomcat.addServlet(ctxt, "async", asyncServlet);
            w.setAsyncSupported(true);
            ctxt.addServletMapping("/async", "async");
        });

        String headers = buildFieldSection(
                ":method", "POST",
                ":scheme", "https",
                ":authority", "127.0.0.1:" + port,
                ":path", "/async",
                "content-length", "0");
        List<String> command = rawCommandWith(
                "--headers", headers,
                "--no-fin",
                "--timeout", "2",
                "--wait", "6");
        Thread clientThread = new Thread(
                () -> runClient(command, CLIENT_TIMEOUT_SECONDS));
        clientThread.setDaemon(true);
        clientThread.start();

        synchronized (asyncServlet) {
            // The client holds the stream open for (timeout + wait) seconds
            // after sending the request. Wait only a fraction of that: the
            // event must arrive while the stream is still half-open.
            long deadline = System.currentTimeMillis() + 3000;
            while (asyncServlet.error == null && !asyncServlet.allDataRead
                    && System.currentTimeMillis() < deadline) {
                asyncServlet.wait(
                        Math.max(10, deadline - System.currentTimeMillis()));
            }
        }

        Assert.assertNull("Unexpected ReadListener error: "
                + asyncServlet.error, asyncServlet.error);
        Assert.assertTrue("onAllDataRead was not called before the stream " +
                "was closed by the client", asyncServlet.allDataRead);
        Assert.assertEquals(0, asyncServlet.bytesReceived);

        clientThread.join(20000);
    }


    public static class AsyncServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        volatile int bytesReceived;
        volatile boolean allDataRead;
        volatile Throwable error;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            final AsyncContext asyncContext = req.startAsync();
            req.getInputStream().setReadListener(new ReadListener() {

                @Override
                public void onDataAvailable() throws IOException {
                    // Non-blocking read contract: only read while isReady()
                    // returns true. Reading stops when the buffered data is
                    // consumed and the remaining body is still outstanding;
                    // the connection close (truncating the body) is
                    // delivered as onAllDataRead.
                    jakarta.servlet.ServletInputStream in = req.getInputStream();
                    while (in.isReady()) {
                        int b = in.read();
                        if (b == -1) {
                            break;
                        }
                        bytesReceived++;
                    }
                    synchronized (AsyncServlet.this) {
                        AsyncServlet.this.notifyAll();
                    }
                }

                @Override
                public void onAllDataRead() throws IOException {
                    allDataRead = true;
                    asyncContext.complete();
                    synchronized (AsyncServlet.this) {
                        AsyncServlet.this.notifyAll();
                    }
                }

                @Override
                public void onError(Throwable throwable) {
                    error = throwable;
                    asyncContext.complete();
                    synchronized (AsyncServlet.this) {
                        AsyncServlet.this.notifyAll();
                    }
                }
            });
        }
    }
}

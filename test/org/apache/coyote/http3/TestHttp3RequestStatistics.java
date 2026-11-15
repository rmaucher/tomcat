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
import java.util.Base64;

import javax.management.MBeanServer;
import javax.management.ObjectName;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;
import org.apache.coyote.AbstractProtocol;
import org.apache.tomcat.util.modeler.Registry;

/**
 * Request statistics must count each HTTP/3 request exactly once, including
 * async requests whose request body is aborted during service().
 */
public class TestHttp3RequestStatistics extends Http3TestBase {

    @Test
    public void testAsyncOverrunCountedOnce() throws Exception {
        startHttp3Server(ctxt -> {
            Wrapper w = Tomcat.addServlet(ctxt, "counter",
                    new OverrunAsyncServlet());
            w.setAsyncSupported(true);
            ctxt.addServletMapping("/counter", "counter");
        });

        ObjectName oname = ((AbstractProtocol<?>) connector.getProtocolHandler())
                .getGlobalRequestProcessorMBeanName();
        MBeanServer mserver = Registry.getRegistry(null).getMBeanServer();
        int before = ((Integer) mserver.getAttribute(oname, "requestCount"))
                .intValue();

        String initial = buildFieldSection(":method", "POST", ":scheme",
                "https", ":authority", "127.0.0.1:" + port, ":path",
                "/counter", "content-length", "5");
        byte[] four = new byte[] { 'a', 'b', 'c', 'd' };
        String frame = buildFrameB64(0, four);
        // The first four bytes arrive before dispatch; the second DATA frame
        // arrives afterwards and overruns Content-Length while the async
        // servlet is reading synchronously during service().
        ClientOutput output = runClient(rawCommandWith("--headers", initial,
                "--data", Base64.getEncoder().encodeToString(four),
                "--frame-after-data", frame,
                "--frame-after-data-delay", "0.5",
                "--fin-after", "1", "--timeout", "3", "--wait", "1"),
                CLIENT_TIMEOUT_SECONDS);
        Assert.assertEquals("Expected the content-length overrun to reset "
                        + "the stream", Integer.valueOf(H3_MESSAGE_ERROR),
                output.getStreamError());

        long deadline = System.currentTimeMillis() + 5000;
        int after = before;
        while (after == before && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
            after = ((Integer) mserver.getAttribute(oname, "requestCount"))
                    .intValue();
        }
        Assert.assertEquals("One request must be counted exactly once", 1,
                after - before);
    }


    private static class OverrunAsyncServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws IOException {
            AsyncContext asyncContext = req.startAsync();
            try {
                req.getInputStream().readAllBytes();
            } catch (IOException ignored) {
                // The second DATA frame overruns the declared Content-Length.
            }
            asyncContext.start(() -> {
                try {
                    resp.setContentType("text/plain");
                    resp.getWriter().write("done");
                } catch (IOException ignored) {
                    // The stream has already been reset.
                }
                asyncContext.complete();
            });
        }
    }
}

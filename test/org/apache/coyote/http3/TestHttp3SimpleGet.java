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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.startup.Tomcat;

public class TestHttp3SimpleGet extends Http3TestBase {

    @Test
    public void testSimpleGet() throws Exception {
        startHttp3Server();

        Http3Response response = get("/simple");

        validateStatus(response, 200);
        String contentType = response.getHeader("content-type");
        Assert.assertTrue("Unexpected content type: " + contentType,
                contentType != null && contentType.startsWith("text/plain"));
        Assert.assertEquals("Hello over HTTP/3", response.getBodyAsString());
    }


    @Test
    public void testContentLength() throws Exception {
        startHttp3Server();

        Http3Response response = get("/simple");

        validateStatus(response, 200);
        String contentLength = response.getHeader("content-length");
        Assert.assertEquals(Integer.toString("Hello over HTTP/3".length()),
                contentLength);
    }


    @Test
    public void testProtocolRequestIdIsStreamId() throws Exception {
        // ServletConnection/getProtocolRequestId() must report the QUIC
        // stream ID of the request, matching the HTTP/2 behaviour where the
        // stream processor returns the stream ID (HTTP/2 parity).
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "reqid", new ProtocolRequestIdServlet());
            ctxt.addServletMapping("/reqid", "reqid");
        });

        Http3Response response = get("/reqid");

        validateStatus(response, 200);
        // The first client-initiated bidirectional stream has ID 0.
        Assert.assertEquals("0", response.getBodyAsString());
    }


    private static class ProtocolRequestIdServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req,
                HttpServletResponse resp) throws IOException, ServletException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().print(req.getProtocolRequestId());
        }
    }
}

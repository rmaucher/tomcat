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

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;

/**
 * Tests for the QUIC endpoint's connection limit enforcement. The
 * {@code maxConnections} property follows the AbstractEndpoint convention
 * where {@code -1} means "unlimited"; a configured positive limit must
 * still reject connections beyond the limit.
 */
public class TestQuicMaxConnections extends Http3TestBase {

    public static class PingServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req,
                HttpServletResponse resp) throws IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            resp.getWriter().print("pong");
        }
    }


    private void startWithMaxConnections(String value) throws Exception {
        assumeQuicEnvironmentAvailable();

        port = findFreeUdpPort();
        Connector connector = newHttp3Connector(port);
        Assert.assertTrue("maxConnections must be a valid property",
                connector.setProperty("maxConnections", value));

        Tomcat tomcat = getTomcatInstance();
        tomcat.setConnector(connector);
        Context ctxt = getProgrammaticRootContext();
        Tomcat.addServlet(ctxt, "ping", new PingServlet());
        ctxt.addServletMapping("/ping", "ping");
        tomcat.start();
    }


    @Test
    public void testUnlimitedAcceptsConnections() throws Exception {
        startWithMaxConnections("-1");

        Http3Response response = get("/ping");
        validateStatus(response, 200);
    }


    @Test
    public void testPositiveLimitAcceptsWithinLimit() throws Exception {
        startWithMaxConnections("10");

        Http3Response response = get("/ping");
        validateStatus(response, 200);
    }
}

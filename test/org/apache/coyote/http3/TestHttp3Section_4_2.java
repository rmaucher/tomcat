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

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.connector.Connector;

/**
 * Tests for the response message requirements of
 * <a href="https://www.rfc-editor.org/rfc/rfc9114#section-4.2">RFC 9114
 * Section 4.2</a>.
 */
public class TestHttp3Section_4_2 extends Http3TestBase {

    @Test
    public void testBasicResponse() throws Exception {
        startHttp3Server();

        Http3Response response = get("/simple");

        validateStatus(response, 200);
        Assert.assertNotNull(response.getHeader("content-type"));
        Assert.assertNotNull(response.getHeader("date"));
    }


    @Test
    public void testResponseWithContentLength() throws Exception {
        startHttp3Server();

        Http3Response response = get("/simple");

        validateStatus(response, 200);
        Assert.assertEquals("17", response.getHeader("content-length"));
        Assert.assertEquals(17, response.getBody().length);
    }


    @Test
    public void testEarlyHints() throws Exception {
        startHttp3Server();

        // The aioquic H3 stack in the normal client mode rejects the
        // second HEADERS frame of the early hints response, so the raw
        // client mode is used here.
        ClientOutput output = rawGet("/earlyHints");

        Http3Response response = output.getResponse();
        Assert.assertEquals(Arrays.asList(103, 200),
                response.getStatuses());
        Assert.assertEquals("</large>; rel=preload",
                response.getHeader("link"));
        Assert.assertEquals("Hello over HTTP/3",
                response.getBodyAsString());
    }


    @Test
    public void testExpectContinueSendsInterimResponse() throws Exception {
        startHttp3Server();

        // A request carrying expect: 100-continue is acknowledged with an
        // interim 100 response (a HEADERS frame carrying only :status)
        // before the final response (RFC 9110 Section 10.1.1, same
        // behaviour as the HTTP/1.1 and HTTP/2 connectors). With the
        // default timing (immediately) the ack is sent before the servlet
        // runs. Raw mode: the aioquic client rejects interim responses.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "GET", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/simple", "expect", "100-continue")),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        Assert.assertEquals(Arrays.asList(100, 200),
                response.getStatuses());
        Assert.assertEquals("Hello over HTTP/3",
                response.getBodyAsString());
    }


    @Test
    public void testExpectContinueTimingOnRead() throws Exception {
        Connector connector = startHttp3Server();
        Assert.assertTrue(connector.setProperty("continueResponseTiming",
                "onRead"));

        // With the onRead timing the servlet may answer before any interim
        // response: /simple never reads the request body, so no 100 is
        // sent...
        ClientOutput servletDoesNotRead = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "GET", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/simple", "expect", "100-continue")),
                CLIENT_TIMEOUT_SECONDS);
        Assert.assertEquals(Arrays.asList(200),
                servletDoesNotRead.getResponse().getStatuses());

        // ...while /echo reads the body, which triggers the ack on the
        // first read (before the response is written).
        byte[] body = "ping".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        ClientOutput servletReads = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/echo", "content-length",
                        Integer.toString(body.length),
                        "expect", "100-continue"),
                "--data", Base64.getEncoder().encodeToString(body)),
                CLIENT_TIMEOUT_SECONDS);
        Assert.assertEquals(Arrays.asList(100, 200),
                servletReads.getResponse().getStatuses());
    }


    @Test
    public void testResponseTrailers() throws Exception {
        startHttp3Server();

        Http3Response response = get("/trailers");

        validateStatus(response, 200);
        Assert.assertEquals("test", response.getTrailer("x-test-trailer"));
        Assert.assertEquals("body", response.getBodyAsString());
    }


    @Test
    public void testHeadResponse() throws Exception {
        startHttp3Server();

        // The aioquic H3 stack in the normal client mode rejects HEAD
        // responses that carry a content-length but no body, so the raw
        // client mode is used here.
        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "HEAD", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/simple")),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("17", response.getHeader("content-length"));
        Assert.assertEquals(0, response.getBody().length);
    }


    @Test
    public void testHeadResponseWithBodyServlet() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith("--headers",
                buildFieldSection(":method", "HEAD", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/echo")),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertEquals("29", response.getHeader("content-length"));
        Assert.assertEquals(0, response.getBody().length);
    }


    @Test
    public void testNotFound() throws Exception {
        startHttp3Server();

        Http3Response response = get("/does-not-exist");

        validateStatus(response, 404);
    }


    @Test
    public void testResponseReducedToPeerFieldSectionLimit() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 4.2.2: the peer declared
        // SETTINGS_MAX_FIELD_SECTION_SIZE of 200 bytes. The response to
        // /simple ({:status, content-type, content-length, date}) does not
        // fit; the non-essential date field is dropped so the encoded
        // section stays within the limit.
        ClientOutput output = runClient(rawCommandWith(
                "--control", buildSettingsFrameB64(6, 200),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple"))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);

        long size = 32L + ":status".length() + "200".length();
        for (Map.Entry<String, String> header :
                response.getHeaders().entrySet()) {
            size += 32L + header.getKey().length() +
                    header.getValue().length();
        }
        Assert.assertTrue("Response field section of " + size +
                " bytes exceeds the declared limit of 200", size <= 200);
        Assert.assertNull("Expected the non-essential date field to be " +
                "dropped", response.getHeader("date"));
        Assert.assertNotNull("content-type must be retained",
                response.getHeader("content-type"));
        Assert.assertNotNull("content-length must be retained",
                response.getHeader("content-length"));
    }
}

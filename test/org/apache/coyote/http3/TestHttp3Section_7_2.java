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

import java.util.Base64;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests for the handling of HTTP/3 frames
 * (<a href="https://www.rfc-editor.org/rfc/rfc9114#section-7">RFC 9114
 * Section 7</a>) on request streams.
 */
public class TestHttp3Section_7_2 extends Http3TestBase {

    @Test
    public void testPushPromiseOnRequestStream() throws Exception {
        startHttp3Server();

        // PUSH_PROMISE is only valid on push streams (RFC 9114
        // Section 7.4); receipt on a request stream is a connection
        // error of type H3_FRAME_UNEXPECTED (RFC 9114 Section 4.1).
        ClientOutput output = runClient(rawCommandWith(
                "--frame", buildFrameB64(0x05, new byte[] { 0 }),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    @Test
    public void testGoawayOnRequestStream() throws Exception {
        startHttp3Server();

        // The GOAWAY frame is only valid on the control stream (RFC 9114
        // Section 7.2.6); receipt on a request stream is a connection
        // error of type H3_FRAME_UNEXPECTED.
        ClientOutput output = runClient(rawCommandWith(
                "--frame", buildFrameB64(0x07, encodeVarint(0)),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    @Test
    public void testCancelPushOnRequestStream() throws Exception {
        startHttp3Server();

        // The CANCEL_PUSH frame is only valid on the control stream
        // (RFC 9114 Section 7.2.3); receipt on a request stream is a
        // connection error of type H3_FRAME_UNEXPECTED.
        ClientOutput output = runClient(rawCommandWith(
                "--frame", buildFrameB64(0x03, new byte[0]),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    @Test
    public void testMaxPushIdOnRequestStream() throws Exception {
        startHttp3Server();

        // The MAX_PUSH_ID frame is only valid on the control stream
        // (RFC 9114 Section 7.2.7); receipt on a request stream is a
        // connection error of type H3_FRAME_UNEXPECTED.
        ClientOutput output = runClient(rawCommandWith(
                "--frame", buildFrameB64(0x0D, encodeVarint(0)),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    @Test
    public void testHttp2ReservedFrameOnRequestStream() throws Exception {
        startHttp3Server();

        // The frame types reserved by HTTP/2 (0x02, 0x06, 0x08, 0x09) have
        // no meaning in HTTP/3: their receipt MUST be treated as a
        // connection error of type H3_FRAME_UNEXPECTED, not ignored like
        // genuinely unknown types (RFC 9114 Sections 7.2.8, 11.2.1).
        for (int frameType : new int[] { 0x02, 0x06, 0x08, 0x09 }) {
            ClientOutput output = runClient(rawCommandWith(
                    "--frame", buildFrameB64(frameType, new byte[0]),
                    "--headers",
                    buildFieldSection(simpleGetHeaders("/simple")),
                    "--timeout", "3"),
                    CLIENT_TIMEOUT_SECONDS);

            assertConnectionError(output, H3_FRAME_UNEXPECTED);
        }
    }


    @Test
    public void testHttp2ReservedFrameAfterDataFailsConnection()
            throws Exception {
        startHttp3Server();

        // A reserved HTTP/2 frame type interleaved into the request body
        // is likewise a connection error of type H3_FRAME_UNEXPECTED
        // (RFC 9114 Sections 7.2.8, 11.2.1), unlike unknown types which
        // are ignored (Section 7.2.8 / Section 9).
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length", "5"),
                "--data",
                Base64.getEncoder().encodeToString(
                        "12345".getBytes()),
                "--frame-after-data",
                buildFrameB64(0x06, new byte[0]),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    @Test
    public void testDuplicatePushOnRequestStreamIgnored() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith(
                "--frame", buildFrameB64(0x0E, encodeVarint(0)),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple"))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testUnknownFrameOnRequestStreamIgnored() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith(
                "--frame", buildFrameB64(0x80, new byte[0]),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple"))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testReservedFrameBetweenDataIgnored() throws Exception {
        startHttp3Server();

        // A reserved frame type (0x1f*N+0x21 with N=1: 0x40) interleaved
        // between the body DATA frame and the FIN must be ignored, not
        // rejected: unknown/reserved frames are permitted on a request
        // stream and receivers MUST ignore them (RFC 9114 Sections 4.1
        // and 9).
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length", "5"),
                "--data",
                Base64.getEncoder().encodeToString(
                        "hello".getBytes()),
                "--frame-after-data", buildFrameB64(0x40, new byte[] { 7 })),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
        Assert.assertTrue("Expected the echoed request body in:\n" +
                response.getBodyAsString(),
                response.getBodyAsString().contains("BODY: 5:hello"));
    }


    @Test
    public void testControlFrameBetweenDataFailsConnection() throws Exception {
        startHttp3Server();

        // A control-only frame (SETTINGS, 0x04) interleaved into the request
        // body is a connection error of type H3_FRAME_UNEXPECTED (RFC 9114
        // Sections 4.1, 7.2.3 through 7.2.7).
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length", "5"),
                "--data",
                Base64.getEncoder().encodeToString(
                        "hello".getBytes()),
                "--frame-after-data", buildFrameB64(0x04, new byte[] { 0 }),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    @Test
    public void testDataBeforeHeaders() throws Exception {
        startHttp3Server();

        // A DATA frame received before any HEADERS frame is an invalid
        // sequence of frames: a connection error of type
        // H3_FRAME_UNEXPECTED (RFC 9114 Section 4.1). The raw client
        // sends --frame payloads before --headers.
        ClientOutput output = runClient(rawCommandWith(
                "--frame", buildFrameB64(0x00, "12345".getBytes()),
                "--headers", buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/echo", "content-length", "5"),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    @Test
    public void testSecondHeadersAfterResponseIgnored() throws Exception {
        startHttp3Server();

        // A second HEADERS frame after the response is complete must be
        // ignored.
        byte[] secondHeaders = Base64.getDecoder().decode(
                buildFieldSection("x-test", "after"));
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--frames-after-wait", buildFrameB64(0x01, secondHeaders)),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testEmptyRequestStream() throws Exception {
        startHttp3Server();

        // A request stream that is closed without a HEADERS frame is an
        // incomplete request (RFC 9114 Section 4.1.2): no response is
        // produced and the server aborts the stream with
        // H3_REQUEST_INCOMPLETE rather than waiting for headers that can
        // never arrive.
        ClientOutput output = runClient(rawCommandWith("--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_REQUEST_INCOMPLETE);
    }
}

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
    public void testTruncatedHeadersFrameConnectionError() throws Exception {
        startHttp3Server();

        // RFC 9114 Section 7.1: a cleanly terminated stream whose last
        // frame is truncated is a connection error of type H3_FRAME_ERROR.
        // A HEADERS frame declaring 10 payload bytes but carrying only 2,
        // followed by FIN, must fail the connection rather than reset only
        // the request stream.
        byte[] truncatedHeaders =
                new byte[] { 0x01, 0x0A, 0x00, 0x00 };
        ClientOutput output = runClient(rawCommandWith(
                "--frame", Base64.getEncoder().encodeToString(truncatedHeaders),
                "--timeout", "3"), CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_ERROR);
    }


    @Test
    public void testTruncatedDataFrameConnectionError() throws Exception {
        startHttp3Server();

        // The request declares 10 body bytes. A DATA frame declaring 10
        // payload bytes but delivering only 5 before FIN is a truncated
        // last frame: connection error H3_FRAME_ERROR (RFC 9114 Section
        // 7.1), not H3_MESSAGE_ERROR on the stream.
        byte[] truncatedData = new byte[] {
                0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00 };
        ClientOutput output = runClient(rawCommandWith(
                "--headers", buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length", "10"),
                "--frame-after-data",
                Base64.getEncoder().encodeToString(truncatedData),
                "--timeout", "3"), CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_ERROR);
    }


    @Test
    public void testTruncatedTrailerFrameConnectionError() throws Exception {
        startHttp3Server();

        // The initial body and its Content-Length are complete, then a
        // trailer HEADERS frame is truncated by the FIN. RFC 9114
        // Section 7.1 requires a connection error of type H3_FRAME_ERROR.
        byte[] truncatedTrailer =
                new byte[] { 0x01, 0x0A, 0x00, 0x00 };
        ClientOutput output = runClient(rawCommandWith(
                "--headers", buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length", "5"),
                "--data", Base64.getEncoder().encodeToString(
                        "body!".getBytes()),
                "--frame-after-data",
                Base64.getEncoder().encodeToString(truncatedTrailer),
                "--timeout", "3"), CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_ERROR);
    }


    @Test
    public void testOversizedDataBeforeHeadersIsFrameUnexpected()
            throws Exception {
        startHttp3Server();

        // RFC 9114 Sections 4.1 and 7.2.8: DATA before the initial HEADERS
        // frame is a connection error of type H3_FRAME_UNEXPECTED. The
        // position check must run before the local buffering limit, so an
        // oversized declared length must not downgrade the classification
        // to the stream-scoped H3_FRAME_ERROR used for an oversized DATA
        // frame in a valid position.
        long declaredLength = 16L * 1024 * 1024 + 1;
        ClientOutput output = runClient(rawCommandWith(
                "--frame", oversizedDataFrameB64(declaredLength),
                "--timeout", "3"), CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


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
    public void testControlFrameAfterHeadersWithoutBody() throws Exception {
        startHttp3Server();

        // A body-less GET never runs the live body-read paths, so the
        // after-response scan is the only consumer of a frame that follows
        // the request HEADERS. A control-stream-only frame there is still
        // an invalid frame sequence and MUST be a connection error of type
        // H3_FRAME_UNEXPECTED (RFC 9114 Sections 4.1, 7.2.3 through 7.2.7).
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(simpleGetHeaders("/sleep?ms=1000")),
                "--frame-after-data", buildFrameB64(0x04, new byte[] { 0 }),
                "--no-fin", "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        // The response may already have been sent when the after-response
        // scan detects the invalid trailing frame, so allow a response here
        // and assert the connection error directly.
        Assert.assertEquals("Expected a connection error. Client output: "
                        + output.getLines(), Integer.valueOf(H3_FRAME_UNEXPECTED),
                output.getConnectionError());
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


    /*
     * A DATA frame declaring a length above the implementation's 16 MiB
     * buffering limit, with only one payload byte delivered. Protocol-valid
     * in a valid position (HTTP/3 has no negotiated frame size limit); used
     * here to show that the frame-sequence error wins over the local limit.
     */
    private static String oversizedDataFrameB64(long declaredLength) {
        byte[] type = encodeVarint(0x00);
        byte[] length = encodeVarint(declaredLength);
        byte[] payload = new byte[] { (byte) 'x' };
        byte[] frame = new byte[type.length + length.length + payload.length];
        System.arraycopy(type, 0, frame, 0, type.length);
        System.arraycopy(length, 0, frame, type.length, length.length);
        System.arraycopy(payload, 0, frame, type.length + length.length,
                payload.length);
        return Base64.getEncoder().encodeToString(frame);
    }
}

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
 * Tests for the control stream requirements of
 * <a href="https://www.rfc-editor.org/rfc/rfc9114#section-6.2">RFC 9114
 * Section 6.2</a>, including the validation of the SETTINGS frame
 * (<a href="https://www.rfc-editor.org/rfc/rfc9114#section-11.2">RFC 9114
 * Section 11.2</a>).
 */
public class TestHttp3Section_6_2 extends Http3TestBase {

    /**
     * The client side timeout, in seconds, used for probes where no
     * response is expected. The client exits once its own timeout is
     * reached.
     */
    private static final long NO_RESPONSE_TIMEOUT_SECONDS = 3;


    @Test
    public void testServerSettings() throws Exception {
        startHttp3Server();

        // The server SETTINGS frame is the first frame on the server
        // control stream.
        ClientOutput output = rawGet("/simple");

        Assert.assertEquals(Integer.valueOf(4096),
                output.getCtrlSettingAsInt(1));
        Assert.assertEquals(Integer.valueOf(16384),
                output.getCtrlSettingAsInt(6));
        // The reserved experimental identifier 0x21 (the family
        // 0x1f * N + 0x21, RFC 9114 Section 7.2.4.1) is advertised to
        // exercise the client's obligation to ignore unknown settings.
        Assert.assertEquals(Integer.valueOf(0),
                output.getCtrlSettingAsInt(33));
        Assert.assertEquals(3, output.getCtrlSettings().size());
    }


    @Test
    public void testClientControlStreamAbsent() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith("--no-control",
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple"))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testClientControlStreamFinishedEarly() throws Exception {
        startHttp3Server();

        // Closing the client control stream (FIN after the SETTINGS frame)
        // is a connection error of type H3_CLOSED_CRITICAL_STREAM: RFC 9114
        // Section 6.2.1 requires the receiver to treat closure of either
        // control stream as a MUST-level connection error.
        ClientOutput output = runClient(rawCommandWith("--fin-control",
                "--no-request", "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_CLOSED_CRITICAL_STREAM);
    }


    @Test
    public void testClientPushStreamRejected() throws Exception {
        startHttp3Server();

        // Push streams are server-initiated only (RFC 9114 Section 6.2.2):
        // a client-initiated stream of type 0x01 is a connection error of
        // type H3_STREAM_CREATION_ERROR (0x101).
        ClientOutput output = runClient(rawCommandWith(
                "--uni", "1,,1",
                "--no-request", "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_STREAM_CREATION_ERROR);
    }


    @Test
    public void testClientSettingsUnknownSettingIgnored() throws Exception {
        startHttp3Server();

        // Setting ID 9 is not defined by RFC 9114 (and is not one of the
        // reserved identifiers of Section 7.2.4.1): per RFC 9114
        // Section 7.2.4 it must be ignored.
        ClientOutput output = runClient(rawCommandWith(
                "--control", buildSettingsFrameB64(1, 4096, 9, 7),
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertNoResponseOrError(output);
    }


    @Test
    public void testClientSettingsReservedIdRejected() throws Exception {
        startHttp3Server();

        // Setting ID 2 was defined in HTTP/2 (PUSH_PROMISE) with no
        // HTTP/3 counterpart: per RFC 9114 Section 7.2.4.1 and
        // Section 11.2.2 its receipt MUST be treated as a connection
        // error of type H3_SETTINGS_ERROR.
        ClientOutput output = runClient(rawCommandWith(
                "--control", buildSettingsFrameB64(1, 4096, 2, 7),
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_SETTINGS_ERROR);
    }


    @Test
    public void testClientSettingsDuplicateId() throws Exception {
        startHttp3Server();

        // A SETTINGS frame with a duplicate setting ID is a connection
        // error of type H3_SETTINGS_ERROR (RFC 9114 Section 11.2.2).
        ClientOutput output = runClient(rawCommandWith(
                "--control", buildSettingsFrameB64(1, 4096, 1, 4096),
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_SETTINGS_ERROR);
    }


    @Test
    public void testClientSettingsQpackTableCapacityLargeAccepted()
            throws Exception {
        startHttp3Server();

        // QPACK_MAX_TABLE_CAPACITY declares the peer's maximum table size;
        // RFC 9204 Section 5 defines no upper bound that a receiver must
        // enforce in SETTINGS (the decoder's own limit is enforced via the
        // Set Dynamic Table Capacity instruction). A large declared value
        // must be accepted without error.
        ClientOutput output = runClient(rawCommandWith(
                "--control", buildSettingsFrameB64(1, 16385),
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertNoResponseOrError(output);
    }


    @Test
    public void testClientSettingsQpackBlockedStreamsLargeAccepted()
            throws Exception {
        startHttp3Server();

        // QPACK_BLOCKED_STREAMS declares the peer's blocked stream limit;
        // RFC 9204 Section 5 defines no upper bound that a receiver must
        // enforce. A large declared value must be accepted without error.
        ClientOutput output = runClient(rawCommandWith(
                "--control", buildSettingsFrameB64(7, 16385),
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertNoResponseOrError(output);
    }


    @Test
    public void testClientSettingsQpackValuesAboveIntMaxAccepted()
            throws Exception {
        startHttp3Server();

        // The same rule for values beyond the int range: these settings
        // advertise the PEER's receiving limits (RFC 9204 Section 5), which
        // the server's encoder (that never inserts) does not constrain. The
        // values must be tolerated even where they exceed the local
        // implementation's internal representation.
        String control = buildSettingsFrameB64(
                1, 0x1_0000_0000L,        // capacity 2^32
                7, 0x8000_0000L);         // blocked streams 2^31
        ClientOutput output = runClient(rawCommandWith(
                "--control", control,
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertNoResponseOrError(output);
    }


    @Test
    public void testClientSecondSettingsFrame() throws Exception {
        startHttp3Server();

        // Only the first SETTINGS frame on the control stream is
        // processed; a second one is a connection error of type
        // H3_FRAME_UNEXPECTED (RFC 9114 Section 7.2.4).
        String settings = buildSettingsFrameB64(1, 4096);
        ClientOutput output = runClient(rawCommandWith(
                "--control", buildFramesB64(settings, settings),
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    @Test
    public void testClientControlHttp2ReservedFrameRejected()
            throws Exception {
        startHttp3Server();

        // The frame types reserved by HTTP/2 (0x02, 0x06, 0x08, 0x09) have
        // no meaning in HTTP/3: their receipt on the control stream MUST be
        // treated as a connection error of type H3_FRAME_UNEXPECTED, not
        // ignored like genuinely unknown types (RFC 9114 Sections 7.2.8,
        // 11.2.1).
        for (int frameType : new int[] { 0x02, 0x06, 0x08, 0x09 }) {
            String control = buildFramesB64(
                    buildSettingsFrameB64(1, 4096),
                    buildFrameB64(frameType, new byte[0]));
            ClientOutput output = runClient(rawCommandWith(
                    "--control", control,
                    "--no-request", "--timeout",
                    Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                    CLIENT_TIMEOUT_SECONDS);

            assertConnectionError(output, H3_FRAME_UNEXPECTED);
        }
    }


    @Test
    public void testClientControlRequestStreamFramesRejected()
            throws Exception {
        startHttp3Server();

        // DATA and HEADERS belong to request (or push) streams and a
        // client MUST NOT send PUSH_PROMISE: receipt of any of them on the
        // client control stream MUST be treated as a connection error of
        // type H3_FRAME_UNEXPECTED, not skipped like a genuinely unknown
        // frame type (RFC 9114 Sections 7.2.1, 7.2.2, 7.2.5).
        for (int frameType : new int[] { 0x00, 0x01, 0x05 }) {
            String control = buildFramesB64(
                    buildSettingsFrameB64(1, 4096),
                    buildFrameB64(frameType, new byte[0]));
            ClientOutput output = runClient(rawCommandWith(
                    "--control", control,
                    "--no-request", "--timeout",
                    Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                    CLIENT_TIMEOUT_SECONDS);

            assertConnectionError(output, H3_FRAME_UNEXPECTED);
        }
    }


    @Test
    public void testClientGoawayExtraPayloadBytesRejected() throws Exception {
        startHttp3Server();

        // The GOAWAY payload is exactly one Push ID variable-length integer
        // (RFC 9114 Section 7.2.6). Additional bytes after it MUST be
        // treated as a connection error of type H3_FRAME_ERROR (RFC 9114
        // Section 7.1).
        String control = buildFramesB64(
                buildSettingsFrameB64(1, 4096),
                buildFrameB64(0x07, new byte[] { 0x00, 0x09, 0x09, 0x09 }));
        ClientOutput output = runClient(rawCommandWith(
                "--control", control,
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_ERROR);
    }


    @Test
    public void testClientMaxPushIdExtraPayloadBytesRejected() throws Exception {
        startHttp3Server();

        // The MAX_PUSH_ID payload is exactly one Push ID variable-length
        // integer (RFC 9114 Section 7.2.7). Additional bytes after it MUST
        // be treated as a connection error of type H3_FRAME_ERROR (RFC 9114
        // Section 7.1).
        String control = buildFramesB64(
                buildSettingsFrameB64(1, 4096),
                buildFrameB64(0x0D, new byte[] { 0x00, 0x01, 0x02 }));
        ClientOutput output = runClient(rawCommandWith(
                "--control", control,
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_ERROR);
    }


    @Test
    public void testClientMaxPushIdTruncatedVarintRejected() throws Exception {
        startHttp3Server();

        // A MAX_PUSH_ID payload that terminates before the end of the Push
        // ID variable-length integer (0x80 starts a 4-byte encoding) MUST be
        // treated as a connection error of type H3_FRAME_ERROR (RFC 9114
        // Section 7.1).
        String control = buildFramesB64(
                buildSettingsFrameB64(1, 4096),
                buildFrameB64(0x0D, new byte[] { (byte) 0x80, 0x00 }));
        ClientOutput output = runClient(rawCommandWith(
                "--control", control,
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_ERROR);
    }


    @Test
    public void testClientCancelPushRejected() throws Exception {
        startHttp3Server();

        // CANCEL_PUSH is valid on the client control stream (RFC 9114
        // Table 1, Section 7.2.3) but only for a push ID promised with a
        // PUSH_PROMISE frame. This server does not implement push, so the
        // push ID was never promised and receipt MUST be treated as a
        // connection error of type H3_ID_ERROR (RFC 9114 Section 7.2.3).
        String control = buildFramesB64(
                buildSettingsFrameB64(1, 4096),
                buildFrameB64(0x03, encodeVarint(5)));
        ClientOutput output = runClient(rawCommandWith(
                "--control", control,
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_ID_ERROR);
    }


    /*
     * Build a frame whose declared payload length differs from the number
     * of payload bytes actually sent. Used to probe the server's handling
     * of frames that declare more data than they carry.
     */
    private static String buildDeclaredFrameB64(int frameType,
            long declaredLength, byte[] payload) {
        byte[] type = encodeVarint(frameType);
        byte[] length = encodeVarint(declaredLength);
        byte[] frame = new byte[type.length + length.length + payload.length];
        System.arraycopy(type, 0, frame, 0, type.length);
        System.arraycopy(length, 0, frame, type.length, length.length);
        System.arraycopy(payload, 0, frame, type.length + length.length,
                payload.length);
        return Base64.getEncoder().encodeToString(frame);
    }


    @Test
    public void testClientControlOversizedFrameFailsConnection()
            throws Exception {
        startHttp3Server();

        // A SETTINGS frame declaring a payload larger than the stream read
        // buffer (the endpoint's default readBufferSize) can never be
        // re-assembled from the retained bytes: without an explicit bound
        // the re-assembly would wait for the missing bytes forever and
        // stall all processing of the client control stream (including the
        // SETTINGS themselves). The server must instead fail the
        // connection with H3_EXCESSIVE_LOAD rather than retain state
        // indefinitely.
        String control = buildDeclaredFrameB64(0x04, 20000,
                new byte[64]);
        ClientOutput output = runClient(rawCommandWith(
                "--control", control,
                "--no-request", "--timeout",
                Long.toString(NO_RESPONSE_TIMEOUT_SECONDS)),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_EXCESSIVE_LOAD);
    }


    @Test
    public void testClientControlHugeUnknownFrameSkipped() throws Exception {
        startHttp3Server();

        // An unknown frame type on the control stream MUST be ignored
        // (RFC 9114 Section 9), including one larger than the stream read
        // buffer: the payload is skipped without being retained, so a
        // conformant client sending a 20000-byte unknown frame neither
        // stalls the control stream nor fails the connection. The request
        // that follows must still be answered.
        String control = buildFramesB64(
                buildSettingsFrameB64(1, 4096),
                buildDeclaredFrameB64(0x0e, 20000,
                        new byte[20000]));
        ClientOutput output = runClient(rawCommandWith(
                "--control", control,
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple"))),
                CLIENT_TIMEOUT_SECONDS);

        Assert.assertNull("Expected no connection error",
                output.getConnectionError());
        validateStatus(output.getResponse(), 200);
    }
}

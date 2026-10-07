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
 * Tests for the QPACK (RFC 9204) field section decoding of
 * <a href="https://www.rfc-editor.org/rfc/rfc9114#section-8">RFC 9114
 * Section 8</a>. Ill-formed field sections are built as raw bytes because
 * the production QPACK encoder cannot generate them.
 */
public class TestHttp3Qpack extends Http3TestBase {

    private static String b64(int... bytes) {
        byte[] result = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            result[i] = (byte) bytes[i];
        }
        return Base64.getEncoder().encodeToString(result);
    }


    @Test
    public void testStaticIndexOutOfRange() throws Exception {
        startHttp3Server();

        // The field section references a dynamic table entry (via a
        // post-base index) that has never been inserted. The server
        // advertises no QPACK blocked-stream capacity, so the blocked
        // stream exceeds the advertised limit and the connection is
        // terminated with H3_QPACK_DECOMPRESSION_FAILED (RFC 9204
        // Section 2.1.2, Section 6).
        ClientOutput output = runClient(rawCommandWith("--headers",
                b64(0x00, 0x00, (byte) 0xBF, 0x24), "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_QPACK_DECOMPRESSION_FAILED);
    }


    @Test
    public void testInvalidFieldLineType() throws Exception {
        startHttp3Server();

        // The field section contains a Huffman coded field name that
        // cannot be decoded (invalid Huffman code sequence). Per RFC 9204
        // Section 6 the connection is terminated with
        // H3_QPACK_DECOMPRESSION_FAILED.
        ClientOutput output = runClient(rawCommandWith("--headers",
                b64(0x00, 0x00, 0x29, 0x00, 0x00), "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_QPACK_DECOMPRESSION_FAILED);
    }


    @Test
    public void testInvalidDynamicTableReference() throws Exception {
        startHttp3Server();

        // The field line references a dynamic table entry that does not
        // exist (relative index 0 with Base 0 is absolute index -1). Per
        // RFC 9204 Section 2.2.3 an invalid reference to the dynamic table
        // is a connection error of type H3_QPACK_DECOMPRESSION_FAILED.
        ClientOutput output = runClient(rawCommandWith("--headers",
                b64(0x00, 0x00, 0x40, 0x00), "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_QPACK_DECOMPRESSION_FAILED);
    }


    @Test
    public void testUnsatisfiableRequiredInsertCount() throws Exception {
        startHttp3Server();

        // The Required Insert Count cannot be satisfied because the
        // client QPACK encoder stream did not send any instructions. The
        // server advertises no QPACK blocked-stream capacity, so the
        // blocked stream exceeds the advertised limit and the connection
        // is terminated with H3_QPACK_DECOMPRESSION_FAILED (RFC 9204
        // Section 2.1.2).
        ClientOutput output = runClient(rawCommandWith("--headers",
                b64(0x02, 0x00, (byte) 0x80), "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_QPACK_DECOMPRESSION_FAILED);
    }


    @Test
    public void testTruncatedFieldSection() throws Exception {
        startHttp3Server();

        // The field section is truncated: the value string of the first
        // field line is missing, so the field section cannot be decoded
        // and the request is missing its required pseudo headers. That is
        // a malformed HTTP message (stream error H3_MESSAGE_ERROR), not a
        // QPACK error.
        ClientOutput output = runClient(rawCommandWith("--headers",
                b64(0x00, 0x00, 0x60)),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testOversizeIntegerResetsStreamOnly() throws Exception {
        startHttp3Server();

        // The name length of a literal-name field line is an iRP(3) whose
        // continuation runs past the largest value the decoder can
        // represent. Per RFC 9204 Section 7.4 this MUST be treated as a
        // stream error of type QPACK_DECOMPRESSION_FAILED on a request
        // stream: only the affected stream is reset, the connection
        // survives.
        ClientOutput output = runClient(rawCommandWith("--headers",
                b64(0x00, 0x00, 0x27, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                        0x80, 0x80, 0x80, 0x80), "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_QPACK_DECOMPRESSION_FAILED);
    }


    @Test
    public void testOversizeStringLengthResetsStreamOnly() throws Exception {
        startHttp3Server();

        // The value string of a literal-name field line declares a length
        // whose iRP(7) continuation runs past the largest value the
        // decoder can represent: likewise a stream error of type
        // QPACK_DECOMPRESSION_FAILED, not a connection error (RFC 9204
        // Section 7.4).
        ClientOutput output = runClient(rawCommandWith("--headers",
                b64(0x00, 0x00, 0x21, 'a', 0x7F, 0x80, 0x80, 0x80, 0x80,
                        0x80, 0x80, 0x80, 0x80, 0x80, 0x80),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_QPACK_DECOMPRESSION_FAILED);
    }


    @Test
    public void testSectionAckRejected() throws Exception {
        startHttp3Server();

        // Section Acknowledgment (0x80 prefix bit, 7-bit stream ID 0) on
        // the client decoder stream. The server encoder never inserts
        // into the dynamic table, so no emitted field section can match
        // the acknowledgement: it cannot be associated with a field
        // section and MUST be treated as a connection error of type
        // QPACK_DECODER_STREAM_ERROR (RFC 9204 Section 4.4.1).
        ClientOutput output = runClient(rawCommandWith("--decoder",
                b64(0x80), "--no-request", "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_QPACK_DECODER_STREAM_ERROR);
    }


    @Test
    public void testInsertCountIncrementRejected() throws Exception {
        startHttp3Server();

        // Insert Count Increment instructions (00 prefix, 6-bit value) on
        // the client decoder stream. A zero increment is explicitly a
        // connection error of type QPACK_DECODER_STREAM_ERROR (RFC 9204
        // Section 4.4.3); a non-zero increment references insertions the
        // server encoder never made and cannot be associated (Section
        // 4.4). Both must terminate the connection.
        for (int increment : new int[] { 0x00, 0x01 }) {
            ClientOutput output = runClient(rawCommandWith("--decoder",
                    b64(increment), "--no-request", "--timeout", "3"),
                    CLIENT_TIMEOUT_SECONDS);

            assertConnectionError(output, H3_QPACK_DECODER_STREAM_ERROR);
        }
    }


    @Test
    public void testStreamCancellationIgnored() throws Exception {
        startHttp3Server();

        // Stream Cancellation (01 prefix, 6-bit stream ID 0) is advisory
        // (RFC 9204 Section 4.4.2): with no stream blocked on the server's
        // dynamic-table-free encoder output it has no effect and must not
        // fail the connection.
        ClientOutput output = runClient(rawCommandWith("--decoder",
                b64(0x40), "--headers",
                buildFieldSection(simpleGetHeaders("/simple"))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getConnectionError());
    }


    @Test
    public void testSetCapacityAboveAdvertisedMaximumRejected()
            throws Exception {
        // The shared decoder's hard limit is taken when the connection
        // manager is created, so the capacity must be configured before the
        // connector starts.
        startHttp3Server(ctxt ->
                ((AbstractHttp3Protocol) connector.getProtocolHandler())
                        .setQpackMaxTableCapacity(0));

        // The SETTINGS advertise QPACK_MAX_TABLE_CAPACITY = 0. A Set
        // Dynamic Table Capacity instruction above the advertised maximum
        // (capacity 1: 0x21 = 001 + iRP(m=5) 1) must be rejected as a
        // connection error of type QPACK_ENCODER_STREAM_ERROR (RFC 9204
        // Sections 3.2.3, 4.3.1 and 6); the decoder may not honour more
        // than it advertised.
        ClientOutput output = runClient(rawCommandWith("--encoder",
                b64(0x21), "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_QPACK_ENCODER_STREAM_ERROR);
    }


    @Test
    public void testEncoderInsertOversizedLiteralValueRejected()
            throws Exception {
        startHttp3Server();

        // Insert With Literal Name (0x40: 01 H=0, name length 0) with a
        // value string declaring a length of 20000 bytes (string header
        // 0x7F = prefix 127, then the RFC 7541 Section 5.1 integer
        // 19873 = 0xA1 0x9B 0x01) but sending none of them. The
        // re-assembly of the instruction cannot complete from
        // the bytes the stream read buffer can retain, and an entry of
        // that size could never be inserted (the dynamic table capacity is
        // bounded by the advertised hard limit): the server must fail the
        // connection with QPACK_ENCODER_STREAM_ERROR (RFC 9204 Sections
        // 3.2.2 and 6) instead of stalling the encoder stream forever.
        ClientOutput output = runClient(rawCommandWith("--encoder",
                b64(0x40, 0x7F, 0xA1, 0x9B, 0x01),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_QPACK_ENCODER_STREAM_ERROR);
    }
}

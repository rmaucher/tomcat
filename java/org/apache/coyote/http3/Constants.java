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

/**
 * HTTP/3 protocol constants. The core protocol values are defined by RFC
 * 9114; this class also holds the QPACK constants from RFC 9204 and the
 * PRIORITY_UPDATE constants from RFC 9218 used by the HTTP/3 implementation.
 */
public final class Constants {

    // HTTP/3 identifier
    public static final String PROTOCOL_NAME = "h3";

    // Frame types (RFC 9114 Section 11.2.1, Table 2)
    // Note: trailers are not a distinct frame type; the trailer section is
    // sent as a second HEADERS frame (RFC 9114 Section 4.1).
    public static final int H3_DATA = 0x00;
    public static final int H3_HEADERS = 0x01;
    // Frame types reserved to exercise unknown-frame handling are a whole
    // family (the form 0x1f*N+0x21), not a single value - classify a type
    // with isReservedFrame() below rather than a representative constant.
    // PRIORITY_UPDATE frames (RFC 9218 Sections 7.2 and 16). Sent by
    // clients on the control stream only; 0xF0700 targets request streams,
    // 0xF0701 targets push streams. Servers MUST NOT send these frames.
    // Payload: Prioritized Element ID (QUIC varint) + Priority Field Value
    // (ASCII, same syntax as the Priority header field).
    public static final int H3_PRIORITY_UPDATE_REQUEST = 0xF0700;
    public static final int H3_PRIORITY_UPDATE_PUSH = 0xF0701;
    public static final int H3_CANCEL_PUSH = 0x03;
    public static final int H3_SETTINGS = 0x04;
    public static final int H3_PUSH_PROMISE = 0x05;
    public static final int H3_GOAWAY = 0x07;
    public static final int H3_MAX_PUSH_ID = 0x0d;

    // QPACK stream types (RFC 9204 Section 4.2, Section 8.2)
    // Written as first byte on QPACK unidirectional streams
    public static final int H3_STREAM_TYPE_QPACK_ENCODER = 0x02;
    public static final int H3_STREAM_TYPE_QPACK_DECODER = 0x03;
    // Push stream (RFC 9114 Section 6.2.2): server-initiated only. A client
    // sending one is a connection error of type H3_STREAM_CREATION_ERROR.
    public static final int H3_STREAM_TYPE_PUSH = 0x01;

    // Stream types (RFC 9114 Section 6.2)
    public static final int H3_STREAM_TYPE_CONTROL = 0x00;

    // QUIC stream IDs for HTTP/3
    // Per QUIC RFC 9000 Section 2.1, stream IDs encode initiator and
    // direction in the low 2 bits (bit 0 = initiator, bit 1 = direction):
    //   00 = client-initiated bidirectional  (0, 4, 8, ...)
    //   01 = server-initiated bidirectional  (1, 5, 9, ...)
    //   10 = client-initiated unidirectional (2, 6, 10, ...)
    //   11 = server-initiated unidirectional (3, 7, 11, ...)
    // Per RFC 9114 Section 6.2.1 and RFC 9204 Section 4.2, unidirectional
    // streams are identified by the stream type written as the first varint
    // on the stream, not by stream ID (which is assigned in creation order).

    // Default limits
    public static final int DEFAULT_MAX_FIELD_SECTION_SIZE = 16 * 1024;

    /**
     * Maximum declared payload size of a DATA or HEADERS frame on a request
     * stream. HTTP/3 has no negotiated frame-size limit, so this is a local
     * implementation limit. A DATA or HEADERS frame above the limit is
     * rejected with {@code RESET_STREAM H3_FRAME_ERROR} at stream scope. The
     * distinction is about the payload: a DATA payload within the limit can
     * be streamed to the application, while a HEADERS payload must be
     * buffered whole for decoding, but both oversize cases use the same
     * classification. The limit also bounds the largest field section the
     * receiver can actually accept.
     */
    public static final int MAX_FRAME_LENGTH = 16 * 1024 * 1024;

    /**
     * Largest decoded field-section size that can be carried in a frame
     * within {@link #MAX_FRAME_LENGTH}. QPACK's worst-case wire expansion is
     * 15/4 of the decoded size plus the two prefix iRPs and a little slack
     * (see {@link #fieldSectionWireLimit(long)}); a configured larger
     * field-section size must not be advertised because the frame would be
     * rejected before decoding.
     */
    public static final long MAX_FIELD_SECTION_SIZE_FOR_FRAME_LIMIT =
            maxDecodedFieldSectionSizeForFrameLimit();


    /**
     * Returns the worst-case wire size (the maximum undecoded length) of a
     * field section whose decoded size is at most {@code decodedLimit}
     * bytes. The bound is 15/4 of the decoded size plus the two prefix iRPs
     * and a little slack. The multiplication is integer-truncated toward
     * zero, so for very small limits the bound can be slightly below the
     * mathematical worst case; that rounding direction is intentional (the
     * preflight rejects earlier rather than later) and must not be "fixed"
     * into an over-estimate. A negative limit is clamped to zero so the
     * configured-limit paths agree. The frame-length preflight uses this
     * function; the settings clamp uses its inverse,
     * {@link #maxDecodedFieldSectionSizeForFrameLimit()}, evaluated once at
     * the frame-length limit.
     *
     * @param decodedLimit The decoded field-section size limit in bytes
     * @return The corresponding wire-size bound
     */
    public static long fieldSectionWireLimit(long decodedLimit) {
        if (decodedLimit < 0) {
            decodedLimit = 0;
        }
        if (decodedLimit > (Long.MAX_VALUE - 32L) / 15L) {
            return Long.MAX_VALUE;
        }
        return decodedLimit * 15L / 4L +
                2L * Qpack.MAX_IRP_ENCODED_LENGTH + 12L;
    }


    /**
     * Returns the largest decoded field-section size that can be carried
     * within {@link #MAX_FRAME_LENGTH}, i.e. the inverse of
     * {@link #fieldSectionWireLimit(long)} at the frame-length limit.
     *
     * @return The largest decodable field-section size for a single frame
     */
    public static long maxDecodedFieldSectionSizeForFrameLimit() {
        return (MAX_FRAME_LENGTH -
                (2L * Qpack.MAX_IRP_ENCODED_LENGTH + 12L)) * 4L / 15L;
    }

    // HTTP/3 settings (RFC 9114 Section 7.2.4.1, RFC 9204 Section 5,
    // RFC 9220 Section 5)
    public static final long H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01;
    public static final long H3_SETTINGS_QPACK_BLOCKED_STREAMS = 0x07;
    public static final long H3_SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06;
    public static final long H3_SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08;
    // Not registered in the IANA "HTTP/3 Settings" registry; advertised
    // only if explicitly enabled. Per RFC 9114 Sections 7.2.4 and 9,
    // unknown setting identifiers MUST be ignored by the peer.
    public static final long H3_SETTINGS_H2_COMPATIBLE_IDENTITY = 0x22;
    // Reserved experimental setting identifier: the family 0x1f * N + 0x21
    // for non-negative N (RFC 9114 Section 7.2.4.1; N = 0 here). Members
    // have no defined meaning and MUST be ignored by the receiver; sending
    // one exercises that requirement.
    public static final long H3_SETTINGS_EXPERIMENTAL = 0x21;


    /**
     * Checks whether a frame type is one of the frame types reserved by
     * HTTP/2 that have no meaning in HTTP/3 (RFC 9114 Sections 7.2.8 and
     * 11.2.1: receipt of one MUST be treated as a connection error of type
     * H3_FRAME_UNEXPECTED, unlike genuinely unknown types which are
     * ignored). The other low HTTP/2 frame types overlap with defined HTTP/3
     * frames and are therefore not reserved identifiers: 0x00 (DATA),
     * 0x01 (HEADERS), 0x03 (RST_STREAM/CANCEL_PUSH), 0x04 (SETTINGS),
     * 0x05 (PUSH_PROMISE) and 0x07 (GOAWAY).
     *
     * @param frameType The frame type to classify
     *
     * @return {@code true} for the reserved HTTP/2 frame types 0x02, 0x06,
     *         0x08 and 0x09
     */
    public static boolean isHttp2ReservedFrame(long frameType) {
        return frameType == 0x02 || frameType == 0x06 ||
                frameType == 0x08 || frameType == 0x09;
    }


    /**
     * Checks whether a frame type is one of the frame types reserved to
     * exercise the requirement that unknown frame types are ignored
     * (RFC 9114 Sections 7.2.8 and 11.2.1): values of the form
     * {@code 0x1f * N + 0x21} for non-negative integer {@code N}. These
     * types have no defined semantics - RFC 9218 defines only
     * PRIORITY_UPDATE and does not assign a meaning to this family - and
     * receipt of any member of the family MUST be ignored (RFC 9114
     * Section 9). This is distinct from the HTTP/2 frame
     * types classified by {@link #isHttp2ReservedFrame(long)}, whose
     * receipt MUST be treated as a connection error of type
     * H3_FRAME_UNEXPECTED.
     *
     * @param frameType The frame type to classify
     *
     * @return {@code true} if the frame type has the reserved
     *         {@code 0x1f * N + 0x21} form
     */
    public static boolean isReservedFrame(long frameType) {
        return frameType >= 0x21 && (frameType - 0x21) % 0x1f == 0;
    }

    /**
     * Clamps a configured long into the [0, Integer.MAX_VALUE] range the
     * QPACK decoder limits and the advertised SETTINGS values use. Shared
     * by the decoder construction, the field-section limit accessor and
     * the SETTINGS encoding so the bound cannot drift between them: an
     * unclamped negative would reach the wire as its two's-complement
     * byte sequence with a two-bit prefix that does not represent that
     * value (for example -1 to -64 are misread as the start of an
     * 8-byte varint), and a value above Integer.MAX_VALUE exceeds the
     * int-typed limits the decoder enforces.
     *
     * @param value The configured value
     *
     * @return The value clamped to [0, Integer.MAX_VALUE]
     */
    public static int clampToNonNegativeInt(long value) {
        return (int) Math.max(0, Math.min(value, Integer.MAX_VALUE));
    }

    // Request attribute carrying the :protocol pseudo-header value of an
    // extended CONNECT request (RFC 9220 Section 3). The value is kept
    // separate from the scheme (:scheme and :protocol are distinct
    // pseudo-headers, RFC 9220 Section 3.1). The processor uses the attribute
    // to answer an unsupported :protocol value with 501 and stores it so
    // applications - and a future extended-CONNECT feature (e.g. WebSocket
    // over HTTP/3) - can retrieve it.
    public static final String ATTR_EXTENDED_CONNECT_PROTOCOL =
            "org.apache.coyote.http3.protocol";

    private Constants() {
        // Hide default constructor
    }
}

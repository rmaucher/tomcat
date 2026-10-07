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
 * HTTP/3 error codes from the "HTTP/3 Error Codes" registry.
 *
 * <p>The same set of codes is used for both connection errors (signalled
 * via QUIC {@code CONNECTION_CLOSE}) and stream errors (signalled via QUIC
 * {@code RESET_STREAM}), per RFC 9114 Section 8.1. Which context a given
 * code is used in is determined by the condition that triggered it (see
 * the individual RFC sections); {@link #isStreamError()} records the
 * codes that this implementation only ever emits as stream errors.
 *
 * <ul>
 * <li>0x0100-0x0110: defined in RFC 9114 Section 8.1</li>
 * <li>0x0200-0x0202: defined in RFC 9204 Section 6, registered in
 *     RFC 9204 Section 8.3 (QPACK)</li>
 * </ul>
 */
enum Http3Error {
    // @formatter:off
    // RFC 9114 Section 8.1 - HTTP/3 Error Codes
    H3_NO_ERROR                    (0x100),
    H3_GENERAL_PROTOCOL_ERROR      (0x101),
    H3_INTERNAL_ERROR              (0x102),
    H3_STREAM_CREATION_ERROR       (0x103),
    H3_CLOSED_CRITICAL_STREAM      (0x104),
    H3_FRAME_UNEXPECTED            (0x105),
    H3_FRAME_ERROR                 (0x106),
    H3_EXCESSIVE_LOAD              (0x107),
    H3_ID_ERROR                    (0x108),
    H3_SETTINGS_ERROR              (0x109),
    H3_MISSING_SETTINGS            (0x10a),
    H3_REQUEST_REJECTED            (0x10b),
    H3_REQUEST_CANCELLED           (0x10c),
    H3_REQUEST_INCOMPLETE          (0x10d),
    H3_MESSAGE_ERROR               (0x10e),
    H3_CONNECT_ERROR               (0x10f),
    H3_VERSION_FALLBACK            (0x110),
    // RFC 9204 Section 8.3 - QPACK Error Codes
    H3_QPACK_DECOMPRESSION_FAILED  (0x200),
    H3_QPACK_ENCODER_STREAM_ERROR  (0x201),
    H3_QPACK_DECODER_STREAM_ERROR  (0x202);
    // @formatter:on

    private final long code;

    Http3Error(long code) {
        this.code = code;
    }


    long getCode() {
        return code;
    }


    /**
     * Returns whether the HTTP/3 processor layer only ever emits this code
     * as a stream error (QUIC {@code RESET_STREAM}).
     * <p>
     * Among the codes this classification covers, all others are connection
     * errors in the contexts where the processor emits them (RFC 9114
     * Sections 4.1, 6.2.1, 7.2.3, 7.2.4, 7.2.6, 7.2.7, 7.2.8; RFC 9204
     * Sections 2.1.2, 2.2.3, 4.2, 6). {@link #H3_MESSAGE_ERROR} is the only
     * code that reaches a stream-scoped failure through this
     * classification: it signals a malformed HTTP message (RFC 9114
     * Section 4.1.2), including a field section that exceeds the advertised
     * size or header count limits (RFC 9114 Section 4.2.2), where only the
     * affected stream is failed. Some of these malformed-message emissions
     * carry this code on the base {@link Http3Exception} type rather than on
     * {@link Http3StreamException} (for example in
     * {@link Http3Processor#emitHeader(String, String)}); the processor's
     * {@code service()} classifies them by error code - using this method -
     * rather than by exception type, so they also fail only the affected
     * stream, and the emit sites carry a note.
     * <p>
     * This classification therefore drives only the base-{@link
     * Http3Exception} dispatch in {@code service()}. It does not mean no
     * other code is ever stream-scoped: the processor resets individual
     * streams with other codes directly at their sites via
     * {@code Http3StreamException}/{@code handleStreamError()} - e.g.
     * {@link #H3_REQUEST_INCOMPLETE}, {@link #H3_FRAME_ERROR} and
     * {@link #H3_QPACK_DECOMPRESSION_FAILED} (RFC 9204 Section 7.4) -
     * bypassing this method entirely. A new stream-scoped reset can reuse
     * {@code handleStreamError()} regardless of what this method returns
     * for its code.
     * <p>
     * This classification covers the explicit protocol error emissions of
     * the processor layer, not the QUIC endpoint's default stream reset
     * code: stream-scoped failures handled at the endpoint by its error
     * event handling reset the individual stream with the connector's
     * default stream error code
     * ({@link AbstractHttp3Protocol#getDefaultStreamErrorCode()},
     * {@link #H3_INTERNAL_ERROR} for a stream-scoped reset), so codes that
     * are otherwise classified as connection errors can also appear on a
     * {@code RESET_STREAM} through that path.
     *
     * @return {@code true} if the HTTP/3 processor layer only ever emits
     *         this code as a stream error
     */
    boolean isStreamError() {
        return this == H3_MESSAGE_ERROR;
    }
}

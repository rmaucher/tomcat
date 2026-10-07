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

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;


/**
 * HTTP/3 SETTINGS frame handling per RFC 9114 Section 7.2.4.
 */
final class Http3Settings {

    private static final Log log = LogFactory.getLog(Http3Settings.class);
    private static final StringManager sm = StringManager.getManager(Http3Settings.class);

    /**
     * SETTINGS identifiers reserved by RFC 9114 Table 3 (HTTP/2
     * identifiers with no HTTP/3 counterpart). Per RFC 9114
     * Section 7.2.4.1 their receipt MUST be treated as a connection
     * error of type H3_SETTINGS_ERROR.
     */
    private static final long[] RESERVED_SETTING_IDENTIFIERS = {0x00L, 0x02L, 0x03L, 0x04L, 0x05L};

    private final long maxFieldSectionSize;


    Http3Settings(ByteBuffer payload) throws Http3Exception {
        Map<Long, Long> settings = new HashMap<>();
        while (payload.hasRemaining()) {
            long identifier;
            long value;
            // The frame is known to be complete (the caller only parses
            // fully received frames), so a truncated varint (-1) is
            // malformed; decodeQuicInteger has no failure mode beyond that.
            identifier = Qpack.decodeQuicInteger(payload);
            value = Qpack.decodeQuicInteger(payload);
            if (identifier == -1 || value == -1) {
                throw error(Http3Error.H3_FRAME_ERROR, "http3Settings.incomplete");
            }
            // Per RFC 9114 Section 7.2.4: a receiver MAY treat a duplicate
            // setting identifier as a connection error of type H3_SETTINGS_ERROR
            if (settings.containsKey(identifier)) {
                throw error(Http3Error.H3_SETTINGS_ERROR, "http3Settings.duplicateIdentifier",
                        Long.valueOf(identifier));
            }
            settings.put(identifier, value);
            if (log.isTraceEnabled()) {
                log.trace(sm.getString("http3Settings.debug", Long.valueOf(identifier), Long.valueOf(value)));
            }
        }

        // Only SETTINGS_MAX_FIELD_SECTION_SIZE is consumed (the response
        // field section limit in Http3Processor). RFC 9204 Section 5
        // defaults the QPACK settings to 0 and this implementation's QPACK
        // encoder never inserts into the dynamic table, so the peer's
        // QPACK_MAX_TABLE_CAPACITY and QPACK_BLOCKED_STREAMS values - and
        // the peer's ENABLE_CONNECT_PROTOCOL and H2_COMPATIBLE_IDENTITY
        // flags, which only ever constrain a client's requests, not this
        // server's - are deliberately not retained.
        Long maxFieldSection = settings.remove(Constants.H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
        maxFieldSectionSize = maxFieldSection != null ? maxFieldSection : 0;

        // Per RFC 9114 Section 7.2.4.1, setting identifiers that were
        // defined in HTTP/2 where there is no corresponding HTTP/3 setting
        // are reserved; their receipt MUST be treated as a connection
        // error of type H3_SETTINGS_ERROR. Genuinely unknown identifiers
        // (the remaining entries) MUST be ignored per RFC 9114
        // Section 7.2.4.
        for (long reserved : RESERVED_SETTING_IDENTIFIERS) {
            if (settings.containsKey(reserved)) {
                throw error(Http3Error.H3_SETTINGS_ERROR, "http3Settings.reservedIdentifier",
                        Long.valueOf(reserved));
            }
        }

    }


    /*
     * Resolves the message for key from the string bundle and wraps it in the
     * connection error the SETTINGS violation requires (RFC 9114
     * Section 7.2.4) - the Http3Settings analogue of
     * Http3Processor.messageError(), so the bundle lookup and the exception
     * assembly live in one place.
     */
    private static Http3Exception error(Http3Error error, String key, Object... args) {
        return new Http3Exception(sm.getString(key, args), error);
    }


    /**
     * The peer's SETTINGS_MAX_FIELD_SECTION_SIZE value (RFC 9114
     * Section 4.2.2). Zero means the peer did not declare a limit.
     */
    long getMaxFieldSectionSize() {
        return maxFieldSectionSize;
    }


    /**
     * Encodes server SETTINGS into a buffer.
     * The settings this server can advertise:
     * - QPACK_MAX_TABLE_CAPACITY (0x01, RFC 9204 Section 5)
     * - QPACK_BLOCKED_STREAMS (0x07, RFC 9204 Section 5)
     * - MAX_FIELD_SECTION_SIZE (0x06, RFC 9114 Section 7.2.4.1)
     * - ENABLE_CONNECT_PROTOCOL (0x08, RFC 9220 Section 5)
     * - H2_COMPATIBLE_IDENTITY (0x22, unregistered experimental setting)
     * - reserved experimental identifier (0x21, RFC 9114 Section 7.2.4.1;
     *   always sent)
     *
     * @param buffer The buffer to write to
     * @param qpackMaxTableCapacity QPACK max table capacity
     * @param qpackBlockedStreams Maximum number of streams the local QPACK
     *        decoder may block; advertised only when non-zero (the RFC 9204
     *        Section 5 default)
     * @param maxFieldSectionSize The maximum field section size to advertise
     * @param enableConnectProtocol Whether to enable extended CONNECT (RFC 9220)
     * @param h2CompatibleIdentity Whether to advertise the experimental
     *        0x22 H2_COMPATIBLE_IDENTITY setting (unregistered; peers MUST
     *        ignore unknown settings)
     */
    public static void encode(ByteBuffer buffer, long qpackMaxTableCapacity,
            int qpackBlockedStreams, long maxFieldSectionSize,
            boolean enableConnectProtocol, boolean h2CompatibleIdentity) {
        // SETTINGS frame payload: identifier (QUIC varint) + value (QUIC varint), repeated
        Qpack.encodeQuicInteger(buffer, Constants.H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        // Clamp the configured capacity with the shared bound the decoder
        // construction also applies (Constants.clampToNonNegativeInt): a
        // negative value would otherwise be written as its two's-complement
        // byte, which a conformant peer reads as the start of an 8-byte
        // varint, swallowing the following SETTINGS bytes.
        Qpack.encodeQuicInteger(buffer,
                Constants.clampToNonNegativeInt(qpackMaxTableCapacity));
        // QPACK_BLOCKED_STREAMS (0x07, RFC 9204 Section 5) is sent only when
        // the decoder accepts blocked streams: by default the server does not
        // insert into the QPACK dynamic table and does not wait for encoder
        // stream inserts, so no stream can be blocked and the RFC 9204
        // Section 5 default of 0 applies.
        if (qpackBlockedStreams > 0) {
            Qpack.encodeQuicInteger(buffer, Constants.H3_SETTINGS_QPACK_BLOCKED_STREAMS);
            Qpack.encodeQuicInteger(buffer, qpackBlockedStreams);
        }
        // SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 Section 4.2.2) is advisory;
        // 0 (the default) means unlimited and is not sent. Clamp the
        // configured value with the shared bound the decoder-side consumer
        // (AbstractHttp3Protocol.getMaxFieldSectionSizeInt) also applies: a value of
        // 2^62 or more does not fit a QUIC varint (RFC 9000 Section 16 caps
        // it at 62 payload bits), so writing it raw would merge its top bit
        // with the 2-bit prefix and silently advertise a limit smaller by
        // 2^62 (for the exact power of two: zero); the clamp also keeps the
        // advertisement honest about the limit the decoder enforces.
        if (maxFieldSectionSize > 0) {
            Qpack.encodeQuicInteger(buffer, Constants.H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
            Qpack.encodeQuicInteger(buffer,
                    Constants.clampToNonNegativeInt(maxFieldSectionSize));
        }
        if (enableConnectProtocol) {
            Qpack.encodeQuicInteger(buffer, Constants.H3_SETTINGS_ENABLE_CONNECT_PROTOCOL);
            Qpack.encodeQuicInteger(buffer, 1);
        }
        if (h2CompatibleIdentity) {
            Qpack.encodeQuicInteger(buffer, Constants.H3_SETTINGS_H2_COMPATIBLE_IDENTITY);
            Qpack.encodeQuicInteger(buffer, 1);
        }
        // RFC 9114 Section 7.2.4.1: endpoints SHOULD include at least one
        // setting from the reserved experimental identifier family
        // (0x1f * N + 0x21) in their SETTINGS frame, to exercise the peer's
        // obligation to ignore unknown identifiers (RFC 9114 Section 7.2.4).
        // Such settings have no defined meaning: the value is arbitrary.
        Qpack.encodeQuicInteger(buffer, Constants.H3_SETTINGS_EXPERIMENTAL);
        Qpack.encodeQuicInteger(buffer, 0);
    }
}

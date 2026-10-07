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
import java.nio.charset.StandardCharsets;

import org.apache.tomcat.util.res.StringManager;


/**
 * Core QPACK utilities per RFC 9204: static table, integer encoding/decoding.
 */
final class Qpack {

    private static final StringManager sm = StringManager.getManager(Qpack.class);

    /**
     * Default dynamic table capacity.
     */
    static final int DEFAULT_TABLE_SIZE = 4096;

    /**
     * QPACK static table per RFC 9204 Appendix A.
     * 0-based indexing (99 entries, indices 0 through 98).
     */
    static final HeaderField[] STATIC_TABLE;
    static final int STATIC_TABLE_LENGTH;

    static {
        HeaderField[] fields = new HeaderField[99];
        // RFC 9204 Appendix A - QPACK Static Table (0-based indexing)
        fields[0] = new HeaderField(":authority", null);
        fields[1] = new HeaderField(":path", "/");
        fields[2] = new HeaderField("age", "0");
        fields[3] = new HeaderField("content-disposition", null);
        fields[4] = new HeaderField("content-length", "0");
        fields[5] = new HeaderField("cookie", null);
        fields[6] = new HeaderField("date", null);
        fields[7] = new HeaderField("etag", null);
        fields[8] = new HeaderField("if-modified-since", null);
        fields[9] = new HeaderField("if-none-match", null);
        fields[10] = new HeaderField("last-modified", null);
        fields[11] = new HeaderField("link", null);
        fields[12] = new HeaderField("location", null);
        fields[13] = new HeaderField("referer", null);
        fields[14] = new HeaderField("set-cookie", null);
        fields[15] = new HeaderField(":method", "CONNECT");
        fields[16] = new HeaderField(":method", "DELETE");
        fields[17] = new HeaderField(":method", "GET");
        fields[18] = new HeaderField(":method", "HEAD");
        fields[19] = new HeaderField(":method", "OPTIONS");
        fields[20] = new HeaderField(":method", "POST");
        fields[21] = new HeaderField(":method", "PUT");
        fields[22] = new HeaderField(":scheme", "http");
        fields[23] = new HeaderField(":scheme", "https");
        fields[24] = new HeaderField(":status", "103");
        fields[25] = new HeaderField(":status", "200");
        fields[26] = new HeaderField(":status", "304");
        fields[27] = new HeaderField(":status", "404");
        fields[28] = new HeaderField(":status", "503");
        fields[29] = new HeaderField("accept", "*/*");
        fields[30] = new HeaderField("accept", "application/dns-message");
        fields[31] = new HeaderField("accept-encoding", "gzip, deflate, br");
        fields[32] = new HeaderField("accept-ranges", "bytes");
        fields[33] = new HeaderField("access-control-allow-headers", "cache-control");
        fields[34] = new HeaderField("access-control-allow-headers", "content-type");
        fields[35] = new HeaderField("access-control-allow-origin", "*");
        fields[36] = new HeaderField("cache-control", "max-age=0");
        fields[37] = new HeaderField("cache-control", "max-age=2592000");
        fields[38] = new HeaderField("cache-control", "max-age=604800");
        fields[39] = new HeaderField("cache-control", "no-cache");
        fields[40] = new HeaderField("cache-control", "no-store");
        fields[41] = new HeaderField("cache-control", "public, max-age=31536000");
        fields[42] = new HeaderField("content-encoding", "br");
        fields[43] = new HeaderField("content-encoding", "gzip");
        fields[44] = new HeaderField("content-type", "application/dns-message");
        fields[45] = new HeaderField("content-type", "application/javascript");
        fields[46] = new HeaderField("content-type", "application/json");
        fields[47] = new HeaderField("content-type", "application/x-www-form-urlencoded");
        fields[48] = new HeaderField("content-type", "image/gif");
        fields[49] = new HeaderField("content-type", "image/jpeg");
        fields[50] = new HeaderField("content-type", "image/png");
        fields[51] = new HeaderField("content-type", "text/css");
        fields[52] = new HeaderField("content-type", "text/html; charset=utf-8");
        fields[53] = new HeaderField("content-type", "text/plain");
        fields[54] = new HeaderField("content-type", "text/plain;charset=utf-8");
        fields[55] = new HeaderField("range", "bytes=0-");
        fields[56] = new HeaderField("strict-transport-security", "max-age=31536000");
        fields[57] = new HeaderField("strict-transport-security", "max-age=31536000; includesubdomains");
        fields[58] = new HeaderField("strict-transport-security", "max-age=31536000; includesubdomains; preload");
        fields[59] = new HeaderField("vary", "accept-encoding");
        fields[60] = new HeaderField("vary", "origin");
        fields[61] = new HeaderField("x-content-type-options", "nosniff");
        fields[62] = new HeaderField("x-xss-protection", "1; mode=block");
        fields[63] = new HeaderField(":status", "100");
        fields[64] = new HeaderField(":status", "204");
        fields[65] = new HeaderField(":status", "206");
        fields[66] = new HeaderField(":status", "302");
        fields[67] = new HeaderField(":status", "400");
        fields[68] = new HeaderField(":status", "403");
        fields[69] = new HeaderField(":status", "421");
        fields[70] = new HeaderField(":status", "425");
        fields[71] = new HeaderField(":status", "500");
        fields[72] = new HeaderField("accept-language", null);
        fields[73] = new HeaderField("access-control-allow-credentials", "FALSE");
        fields[74] = new HeaderField("access-control-allow-credentials", "TRUE");
        fields[75] = new HeaderField("access-control-allow-headers", "*");
        fields[76] = new HeaderField("access-control-allow-methods", "get");
        fields[77] = new HeaderField("access-control-allow-methods", "get, post, options");
        fields[78] = new HeaderField("access-control-allow-methods", "options");
        fields[79] = new HeaderField("access-control-expose-headers", "content-length");
        fields[80] = new HeaderField("access-control-request-headers", "content-type");
        fields[81] = new HeaderField("access-control-request-method", "get");
        fields[82] = new HeaderField("access-control-request-method", "post");
        fields[83] = new HeaderField("alt-svc", "clear");
        fields[84] = new HeaderField("authorization", null);
        fields[85] = new HeaderField("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'");
        fields[86] = new HeaderField("early-data", "1");
        fields[87] = new HeaderField("expect-ct", null);
        fields[88] = new HeaderField("forwarded", null);
        fields[89] = new HeaderField("if-range", null);
        fields[90] = new HeaderField("origin", null);
        fields[91] = new HeaderField("purpose", "prefetch");
        fields[92] = new HeaderField("server", null);
        fields[93] = new HeaderField("timing-allow-origin", "*");
        fields[94] = new HeaderField("upgrade-insecure-requests", "1");
        fields[95] = new HeaderField("user-agent", null);
        fields[96] = new HeaderField("x-forwarded-for", null);
        fields[97] = new HeaderField("x-frame-options", "deny");
        fields[98] = new HeaderField("x-frame-options", "sameorigin");

        STATIC_TABLE = fields;
        STATIC_TABLE_LENGTH = STATIC_TABLE.length;
    }


    /**
     * A header field entry in the static or dynamic table.
     */
    static class HeaderField {
        final String name;
        final String value;

        HeaderField(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }


    private Qpack() {
        // Hide default constructor
    }


    /**
     * Decodes a QUIC variable-length integer (RFC 9000 Section 16).
     * Used for HTTP/3 frame types and frame lengths (RFC 9114 Section 7.1)
     * and for SETTINGS identifiers and values (RFC 9114 Section 7.2.4).
     * <p>
     * 2-bit prefix encodes the length:
     * <ul>
     * <li>00: 1 byte (6-bit value, max 63)</li>
     * <li>01: 2 bytes (14-bit value, max 16383)</li>
     * <li>10: 4 bytes (30-bit value, max 1073741823)</li>
     * <li>11: 8 bytes (62-bit value, max 4611686018427387903)</li>
     * </ul>
     *
     * @param source The buffer to read from
     * @return The decoded integer, or -1 if incomplete
     */
    public static long decodeQuicInteger(ByteBuffer source) {
        if (source.remaining() == 0) {
            return -1;
        }
        byte first = source.get();
        int prefix = (first >> 6) & 0x03;

        // The two-bit prefix is fully covered by the four branches below
        // (the mask bounds prefix to 0..3), so this decoder cannot fail on
        // malformed input: it either decodes or reports -1 (incomplete)
        // with the buffer restored to the start of the integer.
        if (prefix == 0) {
            return first & 0x3F;
        }
        if (prefix == 1) {
            if (source.remaining() < 1) {
                source.position(source.position() - 1);
                return -1;
            }
            return ((first & 0x3FL) << 8) | (source.get() & 0xFFL);
        }
        if (prefix == 2) {
            if (source.remaining() < 3) {
                source.position(source.position() - 1);
                return -1;
            }
            return ((first & 0x3FL) << 24) |
                    ((source.get() & 0xFFL) << 16) |
                    ((source.get() & 0xFFL) << 8) |
                    (source.get() & 0xFFL);
        }
        // prefix == 3
        if (source.remaining() < 7) {
            source.position(source.position() - 1);
            return -1;
        }
        long val = first & 0x3FL;
        for (int i = 0; i < 7; i++) {
            val = (val << 8) | (source.get() & 0xFFL);
        }
        return val;
    }


    /**
     * Encodes a QUIC variable-length integer (RFC 9000 Section 16).
     * Used for HTTP/3 frame types and frame lengths (RFC 9114 Section 7.1)
     * and for SETTINGS identifiers and values (RFC 9114 Section 7.2.4).
     * <p>
     * The value MUST be within the encodable domain of the format,
     * {@code 0} to {@code 2^62 - 1} inclusive: this method performs no
     * range check and silently mis-encodes anything outside it (a negative
     * value falls into the one-byte branch and emits a truncated byte
     * whose two-bit prefix names the eight-byte form, desynchronising any
     * reader; a value of {@code 2^62} or greater overlays the two-bit
     * prefix), so
     * bounding the input is the caller's contract (the current callers
     * clamp or use known-bounded values).
     *
     * @param target The buffer to write to
     * @param value The integer to encode, in the range {@code 0} to
     *              {@code 2^62 - 1}
     */
    public static void encodeQuicInteger(ByteBuffer target, long value) {
        if (value < 64) {
            target.put((byte) value);
        } else if (value < 16384) {
            target.put((byte) (0x40 | (value >> 8)));
            target.put((byte) value);
        } else if (value < 1073741824L) {
            target.put((byte) (0x80 | (value >> 24)));
            target.put((byte) (value >> 16));
            target.put((byte) (value >> 8));
            target.put((byte) value);
        } else {
            target.put((byte) (0xC0 | (value >> 56)));
            target.put((byte) (value >> 48));
            target.put((byte) (value >> 40));
            target.put((byte) (value >> 32));
            target.put((byte) (value >> 24));
            target.put((byte) (value >> 16));
            target.put((byte) (value >> 8));
            target.put((byte) value);
        }
    }


    /**
     * Decodes a prefixed integer (iRP) per RFC 9204 Section 4.1.1 which uses
     * RFC 7541 Section 5.1 unmodified: the low {@code n} bits of the (already
     * consumed) first byte hold the value when it fits, otherwise the prefix is
     * all ones and the remainder follows as 7-bit groups, least significant
     * group first (RFC 7541 Section 5.1 Figure 3: the first continuation
     * octet carries the LSB group), with the high bit set on every byte but
     * the last.
     *
     * @param source    The buffer to read the continuation from
     * @param n         Prefix size in bits (1-8)
     * @param firstByte First byte, already consumed from the buffer
     * @return The decoded integer, or -1 if more data is needed. On -1 the
     *             buffer position is restored to just after the first byte.
     * @throws QpackValueTooLargeException If the integer exceeds
     *             {@link #MAX_IRP_VALUE}
     */
    public static long decodeIrp(ByteBuffer source, int n, int firstByte) throws QpackException {
        int maxInline = (1 << n) - 1;
        int prefix = firstByte & maxInline;
        if (prefix < maxInline) {
            return prefix;
        }
        int sp = source.position();
        long value = maxInline;
        int shift = 0;
        int b;
        do {
            if (source.remaining() == 0) {
                source.position(sp);
                return -1;
            }
            b = source.get() & 0xFF;
            // The bound is tested before the addition. A group at a shift
            // beyond 56 cannot represent any bit of a value at or below the
            // 62-bit maximum, and one at shift 56 (or below) whose
            // contribution would take the running sum past it is likewise
            // out of range; adding first would in both cases wrap the sum
            // into a negative long before any guard saw it, and consumers
            // read a negative return as "incomplete" rather than as an
            // error, so the offending bytes would be retained forever
            // instead of failing the connection/stream.
            if (shift >= 63 ||
                    (long) (b & 0x7F) << shift > MAX_IRP_VALUE - value) {
                source.position(sp);
                // RFC 9204 Section 7.4: scope depends on the stream class,
                // decided by the consumer - see QpackValueTooLargeException.
                throw new QpackValueTooLargeException(
                        sm.getString("qpack.integerTooLarge"));
            }
            value += (long) (b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        return value;
    }


    /**
     * Decodes a prefixed integer (iRP), consuming the first byte from the
     * buffer. See {@link #decodeIrp(ByteBuffer, int, int)} for the format.
     *
     * @param source The buffer to read from
     * @param n      Prefix size in bits (1-8)
     * @return The decoded integer, or -1 if more data is needed. On -1 from
     *             an empty buffer the first byte has not been consumed; on
     *             -1 from a missing continuation byte sequence the position
     *             is restored to just after the first byte (see the
     *             three-argument overload)
     * @throws QpackValueTooLargeException If the integer exceeds
     *             {@link #MAX_IRP_VALUE}
     */
    public static long decodeIrp(ByteBuffer source, int n) throws QpackException {
        if (source.remaining() == 0) {
            return -1;
        }
        return decodeIrp(source, n, source.get() & 0xFF);
    }


    /**
     * Upper bound on the value an iRP can carry: RFC 9204 Section 4.1.1
     * obliges an implementation to decode integers up to and including 62
     * bits long (the same family as a QUIC variable-length integer, RFC 9000
     * Section 16); Section 7.4 requires anything larger to be treated as an
     * error, which {@link #decodeIrp} signals with
     * {@link QpackValueTooLargeException}.
     */
    public static final long MAX_IRP_VALUE = (1L << 62) - 1;


    /**
     * Upper bound on the number of bytes {@link #encodeIrp} writes for one
     * value: the first byte plus at most nine 7-bit continuation groups for
     * the largest value a QUIC variable-length integer can carry (62 bits;
     * RFC 9000 Section 16, RFC 9204 Section 4.1.1). Buffers that hold N iRP
     * instructions size themselves as {@code N * MAX_IRP_ENCODED_LENGTH}
     * (plus fixed slack) so no representable value can overflow them.
     */
    public static final int MAX_IRP_ENCODED_LENGTH = 10;


    /**
     * Encodes a prefixed integer (iRP) per RFC 9204 Section 4.1.1 (RFC 7541
     * Section 5.1) into a single first byte carrying {@code upper} in the high
     * (8-n) positions plus the low {@code n} bits of the value, followed by the
     * excess over the prefix maximum as 7-bit groups, least significant group
     * first (RFC 7541 Section 5.1 Figure 3), with the high bit set on every
     * byte but the last.
     *
     * @param target The buffer to write to
     * @param upper  Bits occupying the top (8-n) positions of the first byte
     * @param n      Prefix size in bits (1-8)
     * @param value  Integer to encode
     */
    public static void encodeIrp(ByteBuffer target, int upper, int n, long value) {
        int maxInline = (1 << n) - 1;
        if (value < maxInline) {
            target.put((byte) (upper | (int) value));
            return;
        }
        target.put((byte) (upper | maxInline));
        value -= maxInline;
        while (value >= 128) {
            target.put((byte) ((value & 127) | 128));
            value >>>= 7;
        }
        target.put((byte) value);
    }


    /**
     * Decodes a raw (non-Huffman) string literal of the given length into
     * the target, one char per byte as the Latin-1 widening the (possibly
     * UTF-8) bytes require. The caller must ensure the buffer holds at
     * least {@code length} remaining bytes. Shared by every raw-literal
     * read site (string decoding and the prefix-metadata literals whose
     * length is not a self-describing string prefix) so the loops cannot
     * drift.
     *
     * @param source The buffer to read from
     * @param length The number of bytes to read
     * @param target The builder to append the decoded characters to
     */
    public static void decodeRawLiteral(ByteBuffer source, int length,
            StringBuilder target) {
        for (int i = 0; i < length; i++) {
            target.append((char) (source.get() & 0xFF));
        }
    }


    /**
     * The size of a field line / dynamic table entry: RFC 9204 Section
     * 3.2.1 (entry size) and RFC 9114 Section 4.2.2 (field section limit)
     * use the same accounting - 32 bytes of overhead plus the UTF-8 byte
     * lengths of the name and the value (a null value counts as zero).
     * Shared by the dynamic table / field section limit accounting in
     * QpackDecoder and the response field section size accounting in
     * Http3Processor so the two cannot drift.
     *
     * @param name  Field line name
     * @param value Field line value, possibly null
     *
     * @return The size in bytes
     */
    public static int entrySize(String name, String value) {
        return 32 + name.getBytes(StandardCharsets.UTF_8).length +
                (value != null ? value.getBytes(StandardCharsets.UTF_8).length : 0);
    }


    /**
     * Decodes a QPACK string (RFC 9204 Section 4.1.2).
     * <p>
     * String Literal:
     * <pre>
     *  0   1   2   3   4   5   6   7
     * +---+---+---+---+---+---+---+---+
     * |H |i S(7)                             |
     * +---+---------------------------------------------------+
     * | String Length (continued)                         |
     * +---------------------------------------------------+
     * ~ String Length (continued)                         ~
     * +---------------------------------------------------+
     * | String Data (String Length)                       |
     * +---------------------------------------------------+
     * ~ String Data (String Length)                       ~
     * +---------------------------------------------------+
     * </pre>
     * H = Huffman flag (1 = Huffman-encoded, 0 = literal)
     * i S(7) = iRP(m=7) string length sharing the first byte
     * </p>
     *
     * @param source The buffer to read from
     * @return The decoded string, or null if incomplete
     * @throws QpackException If decoding fails
     */
    public static String decodeString(ByteBuffer source) throws QpackException {
        return decodeString(source, Integer.MAX_VALUE);
    }


    /**
     * Decodes a QPACK encoded string, rejecting one that declares a length
     * above the given bound before its payload is retained. Used on streams
     * whose partial data is re-assembled across reads (the QPACK encoder
     * stream): a string longer than the bound can never complete from the
     * re-assembly buffer, so it must fail the connection rather than stall
     * the stream waiting for bytes that will never be accepted.
     *
     * @param source The buffer to read from
     * @param maxEncodedLength The maximum accepted encoded length
     * @return The decoded string, or null if incomplete
     * @throws QpackException If decoding fails or the declared length
     *         exceeds the bound
     */
    public static String decodeString(ByteBuffer source, int maxEncodedLength)
            throws QpackException {
        if (source.remaining() == 0) {
            return null;
        }
        int sp = source.position();

        byte first = source.get();
        boolean huffman = (first & 0x80) != 0;

        // String length is iRP(m=7) in the low 7 bits of the first byte
        // (RFC 7541 Section 5.1, used unmodified by RFC 9204 Section 4.1.1).
        long lengthValue = decodeIrp(source, 7, first & 0xFF);
        if (lengthValue == -1) {
            source.position(sp);
            return null;
        }
        if (lengthValue > Integer.MAX_VALUE) {
            // RFC 9204 Section 7.4 - see QpackValueTooLargeException.
            throw new QpackValueTooLargeException(
                    sm.getString("qpack.integerOverflow"));
        }
        int length = (int) lengthValue;
        if (length > maxEncodedLength) {
            throw new QpackException(sm.getString("qpack.stringTooLong",
                    Integer.valueOf(length), Integer.valueOf(maxEncodedLength)));
        }

        if (source.remaining() < length) {
            source.position(sp);
            return null;
        }

        if (huffman) {
            StringBuilder sb = new StringBuilder(length);
            QpackHuffman.decode(source, length, sb);
            return sb.toString();
        } else {
            StringBuilder sb = new StringBuilder(length);
            decodeRawLiteral(source, length, sb);
            return sb.toString();
        }
    }
}

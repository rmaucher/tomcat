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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

/**
 * In-process unit tests for the QPACK (RFC 9204) and QUIC (RFC 9000
 * Section 16) integer and string primitives that the HTTP/3 and QPACK
 * parsers are built on. These are the analogue of
 * {@code org.apache.coyote.http2.TestByteUtil}: they run everywhere,
 * independent of the QUIC/OpenSSL/aioquic test environment.
 */
public class TestQpackCoding {

    /*
     * RFC 7541 Appendix C.3: Huffman encoded "www.example.com". Used as a
     * valid Huffman fixture (the server side has no Huffman encoder).
     */
    private static final byte[] HUFFMAN_WWW_EXAMPLE_COM = new byte[] {
            (byte) 0xf1, (byte) 0xe3, (byte) 0xc2, (byte) 0xe5,
            (byte) 0xf2, (byte) 0x3a, (byte) 0x6b, (byte) 0xa0,
            (byte) 0xab, (byte) 0x90, (byte) 0xf4, (byte) 0xff };


    // ------------------------------------------------------------------
    // QUIC variable length integers (RFC 9000 Section 16)
    // ------------------------------------------------------------------

    @Test
    public void testSettingsEncodeClampsNegativeTableCapacity()
            throws Exception {
        // A negative configured qpackMaxTableCapacity must not reach the
        // wire as a two's-complement byte (which a conformant peer would
        // read as the start of an 8-byte varint, swallowing the following
        // SETTINGS bytes). encode() clamps it to the same 0 the decoder
        // construction uses.
        ByteBuffer buffer = ByteBuffer.allocate(64);
        Http3Settings.encode(buffer, -5, 0, 16384, false, false);
        buffer.flip();

        long id = Qpack.decodeQuicInteger(buffer);
        Assert.assertEquals(Constants.H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                id);
        Assert.assertEquals("Negative capacity must be clamped to 0", 0,
                Qpack.decodeQuicInteger(buffer));
        long nextId = Qpack.decodeQuicInteger(buffer);
        Assert.assertEquals("Following setting must still parse",
                Constants.H3_SETTINGS_MAX_FIELD_SECTION_SIZE, nextId);
        Assert.assertEquals(16384, Qpack.decodeQuicInteger(buffer));
    }


    @Test
    public void testSettingsEncodeClampsFieldSectionSizeBeyondVarintRange()
            throws Exception {
        // A configured maxFieldSectionSize of 2^62 or more does not fit a
        // QUIC variable-length integer (RFC 9000 Section 16 caps it at 62
        // payload bits): written raw, its top bit merges with the 2-bit
        // prefix and the peer silently reads a limit smaller by 2^62 (for
        // the exact power of two: zero). encode() clamps it to the same
        // Integer.MAX_VALUE the decoder-side consumer uses, which is also
        // the limit the decoder actually enforces.
        ByteBuffer buffer = ByteBuffer.allocate(64);
        Http3Settings.encode(buffer, 0, 0, 1L << 62, false, false);
        buffer.flip();

        // The always-advertised table capacity comes first.
        Assert.assertEquals(Constants.H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                Qpack.decodeQuicInteger(buffer));
        Assert.assertEquals(0, Qpack.decodeQuicInteger(buffer));
        Assert.assertEquals(Constants.H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
                Qpack.decodeQuicInteger(buffer));
        Assert.assertEquals("Value beyond the varint range must be clamped "
                + "to the decoder-side bound, not silently truncated",
                Integer.MAX_VALUE, Qpack.decodeQuicInteger(buffer));

        buffer.clear();
        Http3Settings.encode(buffer, 0, 0, Long.MAX_VALUE, false, false);
        buffer.flip();
        Assert.assertEquals(Constants.H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                Qpack.decodeQuicInteger(buffer));
        Assert.assertEquals(0, Qpack.decodeQuicInteger(buffer));
        Assert.assertEquals(Constants.H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
                Qpack.decodeQuicInteger(buffer));
        Assert.assertEquals(Integer.MAX_VALUE,
                Qpack.decodeQuicInteger(buffer));
    }


    @Test
    public void testQuicIntegerBoundaries() throws Exception {
        long[] values = { 0, 1, 63, 64, 100, 16383, 16384, 1073741823L,
                1073741824L, 1L << 32, (1L << 62) - 1 };
        for (long value : values) {
            ByteBuffer buffer = ByteBuffer.allocate(8);
            Qpack.encodeQuicInteger(buffer, value);
            buffer.flip();
            Assert.assertEquals("Round trip of " + value, value,
                    Qpack.decodeQuicInteger(buffer));
            Assert.assertFalse("All bytes consumed for " + value,
                    buffer.hasRemaining());
        }
    }


    @Test
    public void testQuicIntegerEncodedLengths() throws Exception {
        Assert.assertEquals(1, encodedQuicLength(63));
        Assert.assertEquals(2, encodedQuicLength(64));
        Assert.assertEquals(2, encodedQuicLength(16383));
        Assert.assertEquals(4, encodedQuicLength(16384));
        Assert.assertEquals(4, encodedQuicLength(1073741823L));
        Assert.assertEquals(8, encodedQuicLength(1073741824L));
    }


    private static int encodedQuicLength(long value) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        Qpack.encodeQuicInteger(buffer, value);
        return buffer.position();
    }


    @Test
    public void testQuicIntegerTruncated() throws Exception {
        // 4-byte form (0x80 prefix) with only two payload bytes.
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] { (byte) 0x80, 0x01,
                0x02 });
        Assert.assertEquals(-1, Qpack.decodeQuicInteger(buffer));
        Assert.assertEquals("Position restored", 0, buffer.position());
    }


    @Test
    public void testQuicIntegerEmpty() throws Exception {
        Assert.assertEquals(-1,
                Qpack.decodeQuicInteger(ByteBuffer.allocate(0)));
    }


    // ------------------------------------------------------------------
    // Prefixed integers, iRP (RFC 9204 Section 4.1.1 / RFC 7541 5.1)
    // ------------------------------------------------------------------

    @Test
    public void testIrpRoundTripAllPrefixes() throws Exception {
        for (int n = 1; n <= 8; n++) {
            long maxInline = (1L << n) - 1;
            long[] values = { 0, Math.min(1, maxInline - 1),
                    Math.max(0, maxInline - 1), maxInline, maxInline + 1,
                    maxInline + 127, maxInline + 128, maxInline + 16384,
                    1_000_000_000L };
            for (long value : values) {
                ByteBuffer buffer = ByteBuffer.allocate(16);
                Qpack.encodeIrp(buffer, 0, n, value);
                buffer.flip();
                Assert.assertEquals("n=" + n + " value=" + value, value,
                        Qpack.decodeIrp(buffer, n));
            }
        }
    }


    @Test
    public void testIrpEncodedLengthBound() throws Exception {
        // Instruction-flush buffers size themselves by
        // Qpack.MAX_IRP_ENCODED_LENGTH per value; the largest 62-bit value
        // must fit that bound (and round-trip) for every prefix, or such a
        // flush throws BufferOverflowException instead of encoding.
        for (int n = 1; n <= 8; n++) {
            long value = (1L << 62) - 1;
            ByteBuffer buffer = ByteBuffer.allocate(
                    Qpack.MAX_IRP_ENCODED_LENGTH);
            Qpack.encodeIrp(buffer, 0, n, value);
            Assert.assertTrue("n=" + n + " used " + buffer.position()
                    + " bytes", buffer.position() <= Qpack.MAX_IRP_ENCODED_LENGTH);
            buffer.flip();
            Assert.assertEquals("n=" + n, value, Qpack.decodeIrp(buffer, n));
        }
    }


    @Test
    public void testIrpCarriesUpperBits() throws Exception {        // The upper (8-n) bits of the first byte must survive the round
        // trip of the value bits (this is how the instruction type and
        // flags share the first byte with the value).
        ByteBuffer buffer = ByteBuffer.allocate(16);
        Qpack.encodeIrp(buffer, 0x20, 5, 1024);
        buffer.flip();
        int first = buffer.get() & 0xFF;
        Assert.assertEquals("Type bits kept", 0x20, first & 0xE0);
        Assert.assertEquals(1024, Qpack.decodeIrp(buffer, 5, first));
    }


    @Test
    public void testIrpKnownVectorCapacity1024() throws Exception {
        // RFC 9204 Section 4.3.1 figure: Set Dynamic Table Capacity 1024
        // is 001 + iRP(m=5) 1024. 1024 exceeds the 5-bit prefix (31):
        // 0x3F, then 1024-31 = 993 as 7-bit groups: 0xE1, 0x07.
        ByteBuffer buffer = ByteBuffer.wrap(
                new byte[] { 0x3F, (byte) 0xE1, 0x07 });
        int first = buffer.get() & 0xFF;
        Assert.assertEquals(1024, Qpack.decodeIrp(buffer, 5, first));
    }


    @Test
    public void testIrpTruncatedContinuation() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] { 0x3F });
        int first = buffer.get() & 0xFF;
        // First byte consumed, continuation missing: -1 with the position
        // restored to just after the first byte so the instruction can be
        // retried when more data arrives.
        Assert.assertEquals(-1, Qpack.decodeIrp(buffer, 5, first));
        Assert.assertEquals(1, buffer.position());
    }


    @Test
    public void testIrpOverflow() throws Exception {
        // Ten continuation bytes all carry the continuation flag: the
        // shifted value would need more than 64 bits.
        byte[] bytes = new byte[11];
        bytes[0] = 0x7F;
        Arrays.fill(bytes, 1, bytes.length, (byte) 0x80);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        int first = buffer.get() & 0xFF;
        try {
            Qpack.decodeIrp(buffer, 7, first);
            Assert.fail("Expected a QpackException for an oversized " +
                    "integer");
        } catch (QpackException e) {
            // Expected
        }
    }


    @Test
    public void testIrpWrapBeforeTerminationRejected() throws Exception {
        // A 10-byte m=8 iRP (nine continuation groups, the last closing the
        // encoding) represents 2^63 + 254: above the 62-bit family RFC 9204
        // Section 4.1.1 obliges a decoder to handle, so Section 7.4 requires
        // it to be treated as an error. With the overflow guard evaluated
        // after the shift-add, the running sum wrapped to a negative long
        // (0x80000000000000FE) on the final group - whose high bit is clear,
        // ending the loop before the guard was reached - and the wrapped
        // value was returned instead of an error. The guard must fire before
        // the addition so the wrap cannot be observed.
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] {
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, 0x7F });
        int first = buffer.get() & 0xFF;
        try {
            long value = Qpack.decodeIrp(buffer, 8, first);
            Assert.fail("Expected QpackValueTooLargeException, got " + value);
        } catch (QpackValueTooLargeException e) {
            // Expected
        }
        Assert.assertEquals("Position restored to just after the first byte",
                1, buffer.position());
    }


    @Test
    public void testIrpValueAboveMaximumRejected() throws Exception {
        // A well-formed encoding of one more than the maximum (2^62,
        // encoded with the encoder's own rules) must be rejected on decode:
        // a running sum that stays positive but passes MAX_IRP_VALUE is
        // still beyond the 62-bit family of RFC 9204 Section 4.1.1.
        for (int n = 1; n <= 8; n++) {
            ByteBuffer buffer = ByteBuffer.allocate(
                    Qpack.MAX_IRP_ENCODED_LENGTH);
            Qpack.encodeIrp(buffer, 0, n, Qpack.MAX_IRP_VALUE + 1);
            buffer.flip();
            try {
                long value = Qpack.decodeIrp(buffer, n);
                Assert.fail("n=" + n +
                        ": expected QpackValueTooLargeException, got " +
                        value);
            } catch (QpackValueTooLargeException e) {
                // Expected
            }
        }
    }


    // ------------------------------------------------------------------
    // String literals (RFC 9204 Section 4.1.2)
    // ------------------------------------------------------------------

    @Test
    public void testStringLiteral() throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(
                new byte[] { 0x05, 'h', 'e', 'l', 'l', 'o' });
        Assert.assertEquals("hello", Qpack.decodeString(buffer));
        Assert.assertFalse(buffer.hasRemaining());
    }


    @Test
    public void testStringLiteralEmpty() throws Exception {
        Assert.assertEquals("",
                Qpack.decodeString(ByteBuffer.wrap(new byte[] { 0x00 })));
    }


    @Test
    public void testStringLiteralLengthOverflow() throws Exception {
        // Length uses the iRP(m=7) prefix: 127 marks the overflow and the
        // excess follows in 7-bit groups. Here: 127 + 1 = 128.
        byte[] payload = new byte[128];
        Arrays.fill(payload, (byte) 'x');
        byte[] bytes = new byte[2 + payload.length];
        bytes[0] = 0x7F;  // H=0, 7-bit length prefix all ones (127)
        bytes[1] = 0x01;  // excess: 127 + 1 = 128
        System.arraycopy(payload, 0, bytes, 2, payload.length);

        String decoded = Qpack.decodeString(ByteBuffer.wrap(bytes));
        Assert.assertEquals(128, decoded.length());
        Assert.assertEquals("xxxx", decoded.substring(0, 4));
    }


    @Test
    public void testStringLiteralHuffman() throws Exception {
        ByteBuffer buffer =
                ByteBuffer.allocate(1 + HUFFMAN_WWW_EXAMPLE_COM.length);
        // H=1, length 12 in the low 7 bits of the first byte.
        buffer.put((byte) (0x80 | HUFFMAN_WWW_EXAMPLE_COM.length));
        buffer.put(HUFFMAN_WWW_EXAMPLE_COM);
        buffer.flip();
        Assert.assertEquals("www.example.com", Qpack.decodeString(buffer));
    }


    @Test
    public void testStringLiteralInvalidHuffman() throws Exception {
        // 0x00 is not a valid Huffman code sequence (no code starts with
        // the bit pattern 000000).
        ByteBuffer buffer = ByteBuffer.wrap(new byte[] { (byte) 0x81, 0x00 });
        try {
            Qpack.decodeString(buffer);
            Assert.fail("Expected a QpackException for invalid Huffman data");
        } catch (QpackException e) {
            // Expected
        }
    }


    @Test
    public void testStringLiteralTruncated() throws Exception {
        // Length announces five bytes, only two are present.
        ByteBuffer buffer =
                ByteBuffer.wrap(new byte[] { 0x05, 'h', 'i' });
        Assert.assertNull(Qpack.decodeString(buffer));
        Assert.assertEquals("Position restored", 0, buffer.position());
    }


    @Test
    public void testStringLiteralTruncatedLength() throws Exception {
        // Overflow length prefix without the continuation byte.
        Assert.assertNull(Qpack.decodeString(
                ByteBuffer.wrap(new byte[] { (byte) 0xFF })));
    }


    @Test
    public void testUtf8StringsCarryRawOctets() throws Exception {
        // The literal (non-Huffman) string form transports the UTF-8
        // octets unmodified; decodeString() yields one char per octet and
        // the charset interpretation happens at a higher layer.
        String value = "h\u00E9llo w\u00F6rld";
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(1 + utf8.length);
        Qpack.encodeIrp(buffer, 0, 7, utf8.length);
        buffer.put(utf8);
        buffer.flip();
        String decoded = Qpack.decodeString(buffer);
        Assert.assertArrayEquals(utf8,
                decoded.getBytes(StandardCharsets.ISO_8859_1));
    }
}

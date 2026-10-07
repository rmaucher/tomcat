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
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

/**
 * In-process unit tests for the {@link QpackDecoder} (RFC 9204) dynamic
 * table: encoder stream instructions (Section 4.3), field line
 * representations (Section 4.5) and the Required Insert Count / Base
 * arithmetic. These complement the end-to-end probes in
 * {@link TestHttp3Qpack}: they exercise the happy paths and the corner
 * cases of the shared-decoder state machine without a QUIC environment,
 * so they run on every platform.
 */
public class TestQpackDecoder {

    /*
     * RFC 7541 Appendix C.3 Huffman encoding of "www.example.com" (used as
     * a valid Huffman fixture; the server has no Huffman encoder).
     */
    private static final byte[] HUFFMAN_WWW_EXAMPLE_COM = new byte[] {
            (byte) 0xf1, (byte) 0xe3, (byte) 0xc2, (byte) 0xe5,
            (byte) 0xf2, (byte) 0x3a, (byte) 0x6b, (byte) 0xa0,
            (byte) 0xab, (byte) 0x90, (byte) 0xf4, (byte) 0xff };

    // Static table indexes used below (RFC 9204 Appendix A).
    private static final int STATIC_METHOD_GET = 17;


    // ------------------------------------------------------------------
    // Payload builders
    // ------------------------------------------------------------------

    private static void putString(ByteBuffer target, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        Qpack.encodeIrp(target, 0, 7, bytes.length);
        target.put(bytes);
    }


    /*
     * Encoder instruction: Insert With Name Reference, static table
     * (RFC 9204 Section 4.3.2, 1T iRP(m=6)).
     */
    private static ByteBuffer insertNameRefStatic(int staticIndex,
            String value) {
        ByteBuffer buffer = ByteBuffer.allocate(64);
        Qpack.encodeIrp(buffer, 0xC0, 6, staticIndex);
        putString(buffer, value);
        buffer.flip();
        return buffer;
    }


    /*
     * Encoder instruction: Insert With Name Reference, dynamic table
     * relative index (RFC 9204 Section 4.3.2, 10 iRP(m=6)).
     */
    private static ByteBuffer insertNameRefDynamic(int relativeIndex,
            String value) {
        ByteBuffer buffer = ByteBuffer.allocate(64);
        Qpack.encodeIrp(buffer, 0x80, 6, relativeIndex);
        putString(buffer, value);
        buffer.flip();
        return buffer;
    }


    /*
     * Encoder instruction: Insert With Literal Name
     * (RFC 9204 Section 4.3.3, 01 H NameLen(5+)).
     */
    private static ByteBuffer insertLiteralName(String name, String value) {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer =
                ByteBuffer.allocate(64 + nameBytes.length);
        Qpack.encodeIrp(buffer, 0x40, 5, nameBytes.length);
        buffer.put(nameBytes);
        putString(buffer, value);
        buffer.flip();
        return buffer;
    }


    /*
     * Encoder instruction: Duplicate (RFC 9204 Section 4.3.4, 000
     * iRP(m=5)).
     */
    private static ByteBuffer duplicate(int relativeIndex) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        Qpack.encodeIrp(buffer, 0x00, 5, relativeIndex);
        buffer.flip();
        return buffer;
    }


    /*
     * Field section prefix (RFC 9204 Section 4.5.1): Encoded Insert Count
     * (iRP m=8), Sign=0, Delta Base (iRP m=7).
     */
    private static void putPrefix(ByteBuffer target, long encodedInsertCount,
            int deltaBase) {
        Qpack.encodeIrp(target, 0, 8, encodedInsertCount);
        Qpack.encodeIrp(target, 0, 7, deltaBase);
    }


    private static void putIndexedStatic(ByteBuffer target, int index) {
        Qpack.encodeIrp(target, 0xC0, 6, index);
    }


    private static void putIndexedDynamic(ByteBuffer target, int index) {
        Qpack.encodeIrp(target, 0x80, 6, index);
    }


    private static void putNameRefDynamic(ByteBuffer target, int index,
            String value) {
        Qpack.encodeIrp(target, 0x40 | 0x20, 4, index);   // N=1, T=0
        putString(target, value);
    }


    private static void putLiteral(ByteBuffer target, String name,
            String value) {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        Qpack.encodeIrp(target, 0x20 | 0x10, 3, nameBytes.length); // N=1,H=0
        target.put(nameBytes);
        putString(target, value);
    }


    private static void putPostBaseIndexed(ByteBuffer target, int index) {
        Qpack.encodeIrp(target, 0x10, 4, index);
    }


    private static void putPostBaseNameRef(ByteBuffer target, int index,
            String value) {
        Qpack.encodeIrp(target, 0x00 | 0x08, 3, index);   // N=1
        putString(target, value);
    }


    /*
     * Collects the headers a field section decodes to.
     */
    private static List<String[]> collect(QpackDecoder decoder,
            ByteBuffer block) throws Exception {
        List<String[]> emitted = new ArrayList<>();
        decoder.decodeHeaderBlock(block,
                (name, value) -> emitted.add(
                        new String[] { name, value }));
        return emitted;
    }


    /*
     * Inserts "key"=v0 .. "key"=v(count-1) as Insert With Literal Name
     * instructions.
     */
    private static void insertSeries(QpackDecoder decoder, int count)
            throws Exception {
        for (int i = 0; i < count; i++) {
            decoder.processInstruction(
                    insertLiteralName("key", "v" + i));
        }
    }


    // ------------------------------------------------------------------
    // Encoder stream instructions (RFC 9204 Section 4.3)
    // ------------------------------------------------------------------

    @Test
    public void testSetCapacityInlineAndOverflow() throws Exception {
        QpackDecoder decoder = new QpackDecoder();

        // 001 + iRP(m=5) 1024: prefix overflow then 7-bit groups.
        ByteBuffer capacity = ByteBuffer.wrap(
                new byte[] { 0x3F, (byte) 0xE1, 0x07 });
        decoder.processInstruction(capacity);
        Assert.assertEquals("Instruction fully consumed", 0,
                capacity.remaining());

        // Shrink to 64 bytes (001 + iRP(m=5) 64 overflows the 5-bit
        // prefix: 64-31 = 33 -> 0x21). A 43 byte entry still fits.
        decoder.processInstruction(
                ByteBuffer.wrap(new byte[] { 0x3F, 0x21 }));
        decoder.processInstruction(
                insertLiteralName("k", "0123456789"));
        Assert.assertEquals(1, decoder.getTotalInserts());
    }


    @Test
    public void testSetCapacityAboveHardLimitRejected() throws Exception {
        QpackDecoder decoder = new QpackDecoder(4096, 0);
        try {
            // 001 + iRP(m=5) 1 : capacity 1 above the advertised maximum 0
            decoder.processInstruction(ByteBuffer.wrap(new byte[] { 0x21 }));
            Assert.fail("Expected QPACK_ENCODER_STREAM_ERROR behaviour");
        } catch (QpackException e) {
            // Expected (RFC 9204 Section 4.3.1)
        }
    }


    @Test
    public void testSetCapacityEvicts() throws Exception {
        QpackDecoder decoder = new QpackDecoder(256, 4096);
        insertSeries(decoder, 4);
        Assert.assertEquals(4, decoder.getTotalInserts());

        // Each entry is 32 + 3 + 2 = 37 bytes; shrink below 4 * 37 so the
        // oldest entries are evicted while the total insert count remains.
        ByteBuffer capacity = ByteBuffer.allocate(8);
        Qpack.encodeIrp(capacity, 0x20, 5, 74);
        capacity.flip();
        decoder.processInstruction(capacity);
        Assert.assertEquals("Insert count survives eviction", 4L,
                decoder.getTotalInserts());

        // Absolute index 3 (most recent) is still present, index 0 was
        // evicted and is now an invalid reference (RFC 9204 Section 2.2.3).
        ByteBuffer ok = ByteBuffer.allocate(64);
        putPrefix(ok, 5, 0);            // RIC = 4, Base = 4
        putIndexedDynamic(ok, 0);       // absolute 3
        ok.flip();
        List<String[]> emitted = collect(decoder, ok);
        Assert.assertEquals("key", emitted.get(0)[0]);
        Assert.assertEquals("v3", emitted.get(0)[1]);

        ByteBuffer gone = ByteBuffer.allocate(64);
        putPrefix(gone, 5, 0);
        putIndexedDynamic(gone, 3);     // absolute 0, evicted
        gone.flip();
        try {
            collect(decoder, gone);
            Assert.fail("Expected an invalid reference error");
        } catch (QpackException e) {
            Assert.assertFalse("Must be a fatal error, not a block",
                    e instanceof QpackBlockedException);
        }
    }


    @Test
    public void testInsertWithNameReferenceStatic() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        // Static index 17 has name ":method"; the instruction inserts the
        // name with a literal value (RFC 9204 Section 4.3.2).
        decoder.processInstruction(insertNameRefStatic(STATIC_METHOD_GET,
                "POST"));
        Assert.assertEquals(1, decoder.getTotalInserts());

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 2, 0);         // RIC = 1, Base = 1
        putIndexedDynamic(block, 0);    // absolute 0
        block.flip();
        List<String[]> emitted = collect(decoder, block);
        Assert.assertEquals(":method", emitted.get(0)[0]);
        Assert.assertEquals("POST", emitted.get(0)[1]);
    }


    @Test
    public void testInsertWithNameReferenceDynamic() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        decoder.processInstruction(insertLiteralName("foo", "v1"));
        // Relative index 0 = most recently inserted (RFC 9204 Sections
        // 3.2.5, 4.3.2): takes the name "foo" with a new value.
        decoder.processInstruction(insertNameRefDynamic(0, "v2"));
        Assert.assertEquals(2, decoder.getTotalInserts());

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 3, 0);         // RIC = 2, Base = 2
        putIndexedDynamic(block, 0);    // absolute 1 = (foo, v2)
        putIndexedDynamic(block, 1);    // absolute 0 = (foo, v1)
        block.flip();
        List<String[]> emitted = collect(decoder, block);
        Assert.assertEquals(2, emitted.size());
        Assert.assertEquals("foo", emitted.get(0)[0]);
        Assert.assertEquals("v2", emitted.get(0)[1]);
        Assert.assertEquals("v1", emitted.get(1)[1]);
    }


    @Test
    public void testInsertWithLiteralNameHuffman() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        // 01 H=1 NameLen(5+) with a Huffman coded name.
        ByteBuffer instruction =
                ByteBuffer.allocate(64);
        Qpack.encodeIrp(instruction, 0x40 | 0x20, 5,
                HUFFMAN_WWW_EXAMPLE_COM.length);
        instruction.put(HUFFMAN_WWW_EXAMPLE_COM);
        putString(instruction, "hv");
        instruction.flip();
        decoder.processInstruction(instruction);
        Assert.assertEquals(1, decoder.getTotalInserts());

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 2, 0);         // RIC = 1, Base = 1
        putIndexedDynamic(block, 0);    // absolute 0
        block.flip();
        List<String[]> emitted = collect(decoder, block);
        Assert.assertEquals("www.example.com", emitted.get(0)[0]);
        Assert.assertEquals("hv", emitted.get(0)[1]);
    }


    /*
     * Bit-pack a repeated Huffman code (RFC 7541 Section 5.2), padding the
     * final partial byte with ones (the EOS prefix, RFC 7541 Section 5.2).
     */
    private static byte[] huffmanRepeat(long code, int codeBits, int count) {
        byte[] out = new byte[(codeBits * count + 7) / 8];
        long acc = 0;
        int bits = 0;
        int pos = 0;
        for (int i = 0; i < count; i++) {
            acc = (acc << codeBits) | code;
            bits += codeBits;
            while (bits >= 8) {
                bits -= 8;
                out[pos++] = (byte) ((acc >> bits) & 0xFF);
            }
            acc &= (1L << bits) - 1;
        }
        if (bits > 0) {
            out[pos] = (byte) (((acc << (8 - bits)) & 0xFF)
                    | ((1 << (8 - bits)) - 1));
        }
        return out;
    }


    @Test
    public void testLargeHuffmanInsertWithinTrueExpansionBoundAccepted()
            throws Exception {
        QpackDecoder decoder = new QpackDecoder();

        // RFC 9204 Section 7.4: implementation limits must be large enough
        // to process the largest field the HTTP implementation accepts.
        // 'ÿ' (U+00FF) has a 26-bit Huffman code (RFC 7541 Appendix B) and
        // 2 UTF-8 bytes: 2000 of them form a 4035-byte entry (fits the
        // default 4096 capacity) on a 6500-byte wire encoding - within the
        // true expansion bound (30-bit longest code, 3.75x) but beyond a
        // wrongly assumed 5/4 bound, which would kill the connection on
        // conformant traffic.
        String value = "\u00ff".repeat(2000);
        byte[] encoded = huffmanRepeat(0x3ffffeeL, 26, 2000);
        Assert.assertEquals(6500, encoded.length);

        ByteBuffer instruction = ByteBuffer.allocate(8192);
        byte[] nameBytes = "key".getBytes(StandardCharsets.UTF_8);
        Qpack.encodeIrp(instruction, 0x40, 5, nameBytes.length);
        instruction.put(nameBytes);
        Qpack.encodeIrp(instruction, 0x80, 7, encoded.length);
        instruction.put(encoded);
        instruction.flip();
        decoder.processInstruction(instruction);
        Assert.assertEquals(1, decoder.getTotalInserts());

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 2, 0);         // RIC = 1, Base = 1
        putIndexedDynamic(block, 0);    // absolute 0
        block.flip();
        List<String[]> emitted = collect(decoder, block);
        Assert.assertEquals(value, emitted.get(0)[1]);
    }


    @Test
    public void testInsertLiteralBeyondExpansionBoundRejected()
            throws Exception {
        QpackDecoder decoder = new QpackDecoder();

        // Fail-fast is preserved above the (corrected) bound: a declared
        // value length above 15/4 * (4096 - 32) + 2 = 15242 can never
        // describe an entry that fits the advertised capacity, so the
        // connection fails rather than the partial instruction being
        // retained across reads forever.
        ByteBuffer instruction = ByteBuffer.allocate(64);
        byte[] nameBytes = "key".getBytes(StandardCharsets.UTF_8);
        Qpack.encodeIrp(instruction, 0x40, 5, nameBytes.length);
        instruction.put(nameBytes);
        Qpack.encodeIrp(instruction, 0x80, 7, 20000);
        instruction.put(new byte[8]);
        instruction.flip();
        try {
            decoder.processInstruction(instruction);
            Assert.fail("Expected the declared length to be rejected");
        } catch (QpackException e) {
            // Expected
        }
    }


    @Test
    public void testDuplicate() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        decoder.processInstruction(insertLiteralName("dup", "a"));
        decoder.processInstruction(duplicate(0));
        Assert.assertEquals(2, decoder.getTotalInserts());

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 3, 0);         // RIC = 2, Base = 2
        putIndexedDynamic(block, 0);    // absolute 1 (the duplicate)
        putIndexedDynamic(block, 1);    // absolute 0 (the original)
        block.flip();
        List<String[]> emitted = collect(decoder, block);
        Assert.assertEquals("dup", emitted.get(0)[0]);
        Assert.assertEquals("a", emitted.get(0)[1]);
        Assert.assertEquals("a", emitted.get(1)[1]);
    }


    @Test
    public void testStaticIndexOutOfRangeInstructionRejected()
            throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        try {
            // Insert With Name Reference, static table index 99 (iRP(m=6)
            // overflow: 0xFF prefix, +36): the table has indexes 0..98.
            decoder.processInstruction(ByteBuffer.wrap(
                    new byte[] { (byte) 0xFF, 0x24, 0x01, 'x' }));
            Assert.fail("Expected an unknown instruction error");
        } catch (QpackException e) {
            // Expected
        }
        Assert.assertEquals(0, decoder.getTotalInserts());
    }


    @Test
    public void testEntryLargerThanCapacityRejected() throws Exception {
        QpackDecoder decoder = new QpackDecoder(64, 4096);
        StringBuilder value = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            value.append('y');
        }
        try {
            // Entry size is 32 + 1 + 40 = 73 bytes, above the 64 byte
            // capacity: QPACK_ENCODER_STREAM_ERROR (RFC 9204 Section
            // 3.2.2).
            decoder.processInstruction(
                    insertLiteralName("x", value.toString()));
            Assert.fail("Expected an entry-too-large error");
        } catch (QpackException e) {
            // Expected
        }
    }


    @Test
    public void testIncompleteInstructionRewindsForRetry() throws Exception {
        QpackDecoder decoder = new QpackDecoder();

        ByteBuffer buffer = ByteBuffer.allocate(64);
        buffer.put((byte) 0xC1);    // Insert name ref, static index 1
        buffer.flip();
        buffer.limit(1);            // only the index byte has arrived

        decoder.processInstruction(buffer);
        Assert.assertEquals("Position restored for retry", 0,
                buffer.position());
        Assert.assertEquals("Nothing inserted yet", 0,
                decoder.getTotalInserts());

        // Value string arrives later; re-process the same buffer.
        buffer.limit(buffer.capacity());
        buffer.position(1);
        putString(buffer, "v");
        buffer.flip();
        decoder.processInstruction(buffer);
        Assert.assertEquals(1, decoder.getTotalInserts());
        Assert.assertEquals("Instruction fully consumed", 0,
                buffer.remaining());
    }


    // ------------------------------------------------------------------
    // Field line representations (RFC 9204 Section 4.5)
    // ------------------------------------------------------------------

    @Test
    public void testAllFieldLineTypes() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        insertSeries(decoder, 4);   // absolute 0..3 = key:v0..key:v3

        ByteBuffer block = ByteBuffer.allocate(256);
        // Sign=1, Delta Base 1: RIC = 4 (encoded 5),
        // Base = RIC - Delta - 1 = 2. Pre-base references cover absolute
        // 0..1 (relative 1..0); post-base references cover absolute 2..3
        // (post-base 0..1) - all strictly below the Required Insert Count,
        // the single-pass encoding of RFC 9204 Section 4.5.1.2.
        Qpack.encodeIrp(block, 0, 8, 5);
        Qpack.encodeIrp(block, 0x80, 7, 1);
        putIndexedStatic(block, STATIC_METHOD_GET);     // (:method, GET)
        putIndexedDynamic(block, 1);        // absolute 2-1-1 = 0 (key, v0)
        putNameRefDynamic(block, 0, "lit"); // name absolute 1 = key
        putLiteral(block, "xy", "z");       // literal name + value
        putPostBaseIndexed(block, 0);       // absolute Base+0 = 2 (key, v2)
        putPostBaseNameRef(block, 1, "pb"); // name absolute 3 = key
        block.flip();

        List<String[]> emitted = collect(decoder, block);
        Assert.assertEquals(6, emitted.size());
        Assert.assertArrayEquals(new String[] { ":method", "GET" },
                emitted.get(0));
        Assert.assertArrayEquals(new String[] { "key", "v0" },
                emitted.get(1));
        Assert.assertArrayEquals(new String[] { "key", "lit" },
                emitted.get(2));
        Assert.assertArrayEquals(new String[] { "xy", "z" },
                emitted.get(3));
        Assert.assertArrayEquals(new String[] { "key", "v2" },
                emitted.get(4));
        Assert.assertArrayEquals(new String[] { "key", "pb" },
                emitted.get(5));
    }


    @Test
    public void testBlockedFieldSection() throws Exception {
        QpackDecoder decoder = new QpackDecoder();

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 3, 0);     // RIC = 2 with 0 inserts: blocked
        putIndexedStatic(block, STATIC_METHOD_GET);
        block.flip();

        try {
            collect(decoder, block);
            Assert.fail("Expected the field section to block");
        } catch (QpackBlockedException e) {
            // Expected (RFC 9204 Section 2.2.1): not a connection error.
            Assert.assertEquals(2, e.getRequiredInsertCount());
        }

        // The blocked signal must leave no per-section state behind: a
        // following independent field section (RIC 0) decodes normally.
        ByteBuffer next = ByteBuffer.allocate(64);
        putPrefix(next, 0, 0);
        putIndexedStatic(next, STATIC_METHOD_GET);
        next.flip();
        List<String[]> emitted = collect(decoder, next);
        Assert.assertEquals(1, emitted.size());
        Assert.assertEquals("GET", emitted.get(0)[1]);
    }


    @Test
    public void testPostBaseAtOrAboveRicRejected() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        insertSeries(decoder, 2);   // absolute 0..1

        ByteBuffer block = ByteBuffer.allocate(64);
        // RIC = 2 (encoded 3), Sign=0, Delta Base 1 -> Base 3. The
        // post-base field line references absolute 3 which is >= RIC: a
        // conformant encoder never does this and the decoder must treat it
        // as QPACK_DECOMPRESSION_FAILED (RFC 9204 Section 2.2.3 applies to
        // every field line reference, post-base included).
        putPrefix(block, 3, 1);
        putPostBaseIndexed(block, 0);
        block.flip();

        try {
            collect(decoder, block);
            Assert.fail("Expected a reference at or above the RIC to be " +
                    "rejected");
        } catch (QpackException e) {
            Assert.assertFalse("Must be a fatal error, not a block",
                    e instanceof QpackBlockedException);
        }
    }


    @Test
    public void testReferenceAtOrAboveRicRejected() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        insertSeries(decoder, 2);   // absolute 0..1

        ByteBuffer block = ByteBuffer.allocate(64);
        // RIC = 2 (encoded 3), Delta Base 1 -> Base 3. The indexed field
        // line references absolute 3-1-0 = 2 which is >= RIC: invalid, not
        // blocked (RFC 9204 Section 2.2.3).
        putPrefix(block, 3, 1);
        putIndexedDynamic(block, 0);
        block.flip();

        try {
            collect(decoder, block);
            Assert.fail("Expected an invalid dynamic table reference");
        } catch (QpackException e) {
            Assert.assertFalse("Must be a fatal error, not a block",
                    e instanceof QpackBlockedException);
        }
    }


    @Test
    public void testSignBitBaseArithmetic() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        insertSeries(decoder, 3);   // absolute 0..2

        ByteBuffer block = ByteBuffer.allocate(64);
        // RIC = 3 (encoded 4), Sign=1, Delta Base 1 ->
        // Base = RIC - Delta - 1 = 1 (RFC 9204 Section 4.5.1.2). Indexed
        // dynamic 0 -> absolute Base-1-0 = 0.
        Qpack.encodeIrp(block, 0, 8, 4);
        Qpack.encodeIrp(block, 0x80, 7, 1);
        putIndexedDynamic(block, 0);
        block.flip();

        List<String[]> emitted = collect(decoder, block);
        Assert.assertEquals("key", emitted.get(0)[0]);
        Assert.assertEquals("v0", emitted.get(0)[1]);
    }


    @Test
    public void testInvalidBaseRejected() throws Exception {
        QpackDecoder decoder = new QpackDecoder();

        ByteBuffer block = ByteBuffer.allocate(64);
        // RIC = 2 (encoded 3) with Sign=1 and Delta Base 2: Sign set and
        // RIC <= Delta Base is invalid (RFC 9204 Section 4.5.1.2).
        Qpack.encodeIrp(block, 0, 8, 3);
        Qpack.encodeIrp(block, 0x80, 7, 2);
        block.flip();

        try {
            collect(decoder, block);
            Assert.fail("Expected an invalid Base");
        } catch (QpackException e) {
            // Expected
        }
    }


    @Test
    public void testEncodedInsertCountOutOfRangeRejected() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        insertSeries(decoder, 2);

        ByteBuffer block = ByteBuffer.allocate(64);
        // With MaxEntries = 4096/32 = 128 the full range is 2*128 = 256.
        // An Encoded Insert Count above the full range could not have been
        // produced by a conformant encoder (RFC 9204 Section 4.5.1.1).
        Qpack.encodeIrp(block, 0, 8, 257);
        Qpack.encodeIrp(block, 0, 7, 0);
        block.flip();

        try {
            collect(decoder, block);
            Assert.fail("Expected an impossible Encoded Insert Count");
        } catch (QpackException e) {
            // Expected
        }
    }


    @Test
    public void testEncodedInsertCountWrapAround() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        // MaxEntries = 4096/32 = 128, Full Range = 256. After 200 inserts
        // MaxValue = 200 + 128 = 328 and
        // MaxWrapped = (MaxValue / Full Range) * Full Range = 256.
        insertSeries(decoder, 200);

        ByteBuffer block = ByteBuffer.allocate(64);
        // Encoded 100: RIC = MaxWrapped + Encoded - 1 = 256 + 99 = 355
        // which exceeds MaxValue (328), so one full range must be
        // subtracted: RIC = 99. Without the wrap fix this section would be
        // reported as blocked (355 > 200 inserts) instead of decoding.
        Qpack.encodeIrp(block, 0, 8, 100);
        Qpack.encodeIrp(block, 0, 7, 0);
        putIndexedStatic(block, STATIC_METHOD_GET);
        block.flip();

        List<String[]> emitted = collect(decoder, block);
        Assert.assertEquals("GET", emitted.get(0)[1]);
    }


    /*
     * Lifts the decoder's lifetime insert counter (RFC 9204 Section 3.2.4
     * TotalNumberOfInserts) to the given value without performing that many
     * real inserts: only the counter is affected; the dynamic table stays
     * empty, so further inserts land at absolute indices on top of the
     * lifted value. Used to reach the beyond-int insert counts that RFC
     * 9204 leaves unbounded (Section 3.2.4: the counter never decreases)
     * without 2^31 actual inserts in a unit test.
     */
    private static void liftTotalInserts(QpackDecoder decoder, long value)
            throws Exception {
        java.lang.reflect.Field field =
                QpackDecoder.class.getDeclaredField("totalInserts");
        field.setAccessible(true);
        field.setLong(decoder, value);
    }


    @Test
    public void testEncodedInsertCountBeyondIntRangeDecodes()
            throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        // More than 2^31 lifetime inserts (Integer.MAX_VALUE + 1 lifted,
        // plus one real insert at absolute index 2^31).
        liftTotalInserts(decoder, 2_147_483_648L);
        decoder.processInstruction(insertLiteralName("key", "big"));
        Assert.assertEquals(2_147_483_649L, decoder.getTotalInserts());

        ByteBuffer block = ByteBuffer.allocate(64);
        // MaxEntries = 4096/32 = 128, Full Range = 256.
        // MaxValue = 2147483649 + 128; MaxWrapped = 2147483648. Encoded 2
        // reconstructs to RIC = 2147483649 = totalInserts (not blocked),
        // Sign = 0 / Delta Base 0 -> Base = 2147483649. The indexed field
        // line references absolute 2147483648, the live entry. Before the
        // long reconstruction this section failed the connection with an
        // impossible Encoded Insert Count (QpackDecoder returned -1 for any
        // RIC above Integer.MAX_VALUE).
        putPrefix(block, 2, 0);
        putIndexedDynamic(block, 0);
        block.flip();

        List<String[]> emitted = collect(decoder, block);
        Assert.assertArrayEquals(new String[] { "key", "big" },
                emitted.get(0));
    }


    @Test
    public void testNameRefInsertBeyondIntRangeResolves() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        liftTotalInserts(decoder, 2_147_483_648L);
        decoder.processInstruction(insertLiteralName("key", "big"));
        // The live entry now sits at absolute index 2^31.

        // Insert With Name Reference, dynamic relative index 0 -> absolute
        // 2^31, i.e. above Integer.MAX_VALUE. The name reference must
        // resolve (it used to be rejected as an invalid dynamic reference,
        // failing the whole connection).
        decoder.processInstruction(insertNameRefDynamic(0, "joined"));
        Assert.assertEquals(2_147_483_650L, decoder.getTotalInserts());

        // The duplicated-name entry (name "key", value "joined") at
        // absolute 2147483649 must then be referenceable from a field
        // section: MaxWrapped = 2147483648 again, so encoded 3 reconstructs
        // RIC = 2147483650 = totalInserts, Base = RIC, index 0 -> absolute
        // 2147483649.
        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 3, 0);
        putIndexedDynamic(block, 0);
        block.flip();

        List<String[]> emitted = collect(decoder, block);
        Assert.assertArrayEquals(new String[] { "key", "joined" },
                emitted.get(0));
    }


    @Test
    public void testStaticIndexOutOfRangeFieldLineRejected()
            throws Exception {
        QpackDecoder decoder = new QpackDecoder();

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 0, 0);
        // Indexed Field Line, static table, index 99: out of range
        // (RFC 9204 Section 4.5.2).
        Qpack.encodeIrp(block, 0xC0, 6, 99);
        block.flip();

        try {
            collect(decoder, block);
            Assert.fail("Expected an invalid static table index");
        } catch (QpackException e) {
            // Expected
        }
    }


    // ------------------------------------------------------------------
    // Size limits (RFC 9204 Section 7.4 / RFC 9114 Section 4.2.2)
    // ------------------------------------------------------------------

    @Test
    public void testHeaderCountLimit() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        decoder.setMaxHeaderCount(1);

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 0, 0);
        putIndexedStatic(block, STATIC_METHOD_GET);
        putLiteral(block, "a", "1");
        block.flip();

        try {
            collect(decoder, block);
            Assert.fail("Expected the header count limit to fire");
        } catch (Http3Exception e) {
            // Stream error, not a connection error (RFC 9204 Section 7.4).
            Assert.assertEquals(Http3Error.H3_MESSAGE_ERROR, e.getError());
        }
    }


    @Test
    public void testCookieCountedOnce() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        decoder.setMaxHeaderCount(2);

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 0, 0);
        // Cookie split into two field lines counts once against the limit
        // (RFC 9114 Section 4.2.1, same accounting as the HTTP/2 decoder).
        putLiteral(block, "cookie", "a=1");
        putLiteral(block, "cookie", "b=2");
        putIndexedStatic(block, STATIC_METHOD_GET);
        block.flip();

        List<String[]> emitted = collect(decoder, block);
        Assert.assertEquals(3, emitted.size());
    }


    @Test
    public void testTruncatedPrefixLeavesBlockUnconsumed() throws Exception {
        QpackDecoder decoder = new QpackDecoder();

        // A 1-byte field section whose only byte is the all-ones 8-bit
        // prefix (0xFF) requires continuation bytes that are missing: the
        // prefix is not decodable and no field section may be considered
        // decoded. The decode must return silently with the block fully
        // unconsumed so the caller's hasRemaining() truncation check fires
        // before it would acknowledge the phantom section
        // (RFC 9204 Sections 2.2.2.1, 4.5.1).
        ByteBuffer block = ByteBuffer.wrap(new byte[] { (byte) 0xFF });

        List<String[]> emitted = collect(decoder, block);
        Assert.assertTrue("Nothing may be emitted for an undecodable prefix",
                emitted.isEmpty());
        Assert.assertTrue("Truncated prefix must leave the block unconsumed",
                block.hasRemaining());
    }


    @Test
    public void testHeaderSizeLimit() throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        // (:method, GET) costs 32 + 7 + 3 = 42 bytes (RFC 9204 Section
        // 3.2.1, RFC 9114 Section 4.2.2 accounting).
        decoder.setMaxHeaderSize(50);

        ByteBuffer block = ByteBuffer.allocate(64);
        putPrefix(block, 0, 0);
        putIndexedStatic(block, STATIC_METHOD_GET);
        putIndexedStatic(block, STATIC_METHOD_GET);
        block.flip();

        try {
            collect(decoder, block);
            Assert.fail("Expected the header size limit to fire");
        } catch (Http3Exception e) {
            Assert.assertEquals(Http3Error.H3_MESSAGE_ERROR, e.getError());
        }
    }
}

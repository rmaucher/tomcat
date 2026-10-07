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
import java.util.Arrays;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.http.MimeHeaders;

/**
 * In-process unit tests for the {@link QpackEncoder} (RFC 9204). The
 * encoder always emits static table references and literal
 * representations, so the output must always be decodable by a fresh
 * {@link QpackDecoder} (no dynamic table instructions in flight). These
 * tests pin the chosen representations, the two-pass pseudo header
 * ordering and the UNDERFLOW/resume behaviour.
 */
public class TestQpackEncoder {

    private static MimeHeaders headers(String... nameValues) {
        MimeHeaders result = new MimeHeaders();
        for (int i = 0; i + 1 < nameValues.length; i += 2) {
            result.addValue(nameValues[i]).setString(nameValues[i + 1]);
        }
        return result;
    }


    private static byte[] encodeFully(QpackEncoder encoder,
            MimeHeaders headers) {
        ByteBuffer buffer = ByteBuffer.allocate(65536);
        while (encoder.encode(headers, buffer)
                == QpackEncoder.State.UNDERFLOW) {
            ByteBuffer larger = ByteBuffer.allocate(buffer.capacity() * 2);
            buffer.flip();
            larger.put(buffer);
            buffer = larger;
        }
        byte[] result = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(result);
        return result;
    }


    private static List<String[]> decode(byte[] block) throws Exception {
        QpackDecoder decoder = new QpackDecoder();
        List<String[]> emitted = new ArrayList<>();
        decoder.decodeHeaderBlock(ByteBuffer.wrap(block),
                (name, value) -> emitted.add(
                        new String[] { name, value }));
        return emitted;
    }


    /*
     * Flatten the emitted field lines into a single String array so the
     * pairs compare by value (String[] does not override equals()).
     */
    private static void assertEmitted(List<String[]> emitted,
            String... expectedPairs) {
        String[] flat = new String[emitted.size() * 2];
        for (int i = 0; i < emitted.size(); i++) {
            flat[i * 2] = emitted.get(i)[0];
            flat[i * 2 + 1] = emitted.get(i)[1];
        }
        Assert.assertEquals(expectedPairs.length, flat.length);
        Assert.assertArrayEquals(expectedPairs, flat);
    }


    @Test
    public void testRoundTripBasic() throws Exception {
        // Regular headers deliberately come before the pseudo headers: the
        // two-pass encoder must emit the pseudo headers first (RFC 9114
        // Section 4.3 requires them at the front of the field section).
        MimeHeaders headers = headers(
                "content-type", "application/json",
                ":method", "GET",
                "x-custom", "foo",
                ":path", "/x",
                ":scheme", "https",
                ":authority", "localhost");

        List<String[]> emitted = decode(encodeFully(new QpackEncoder(),
                headers));

        assertEmitted(emitted,
                ":method", "GET",
                ":path", "/x",
                ":scheme", "https",
                ":authority", "localhost",
                "content-type", "application/json",
                "x-custom", "foo");
    }


    @Test
    public void testStaticExactMatchUsesIndexedRepresentation()
            throws Exception {
        // ("content-type", "application/json") is static table entry 46
        // and indexable: an Indexed Field Line 1T iRP(m=6) = 0xC0 | 46.
        byte[] encoded = encodeFully(new QpackEncoder(),
                headers("content-type", "application/json"));
        Assert.assertArrayEquals(new byte[] { 0x00, 0x00, (byte) 0xEE },
                encoded);
    }


    @Test
    public void testStaticExactMatchStatusUsesIndexedRepresentation()
            throws Exception {
        byte[] encoded = encodeFully(new QpackEncoder(),
                headers(":status", "200"));
        // (:status, 200) is static table entry 25.
        Assert.assertArrayEquals(new byte[] { 0x00, 0x00,
                (byte) (0xC0 | 25) }, encoded);
    }


    @Test
    public void testNameOnlyMatchUsesNameReferenceLiteral() throws Exception {
        // ("content-length", "123"): the static table has the name but not
        // the value; content-length must never be indexed, so a Literal
        // Field Line with Name Reference: 01 N=1 T=1 iRP(m=4) 4.
        byte[] encoded = encodeFully(new QpackEncoder(),
                headers("content-length", "123"));
        Assert.assertArrayEquals(new byte[] { 0x00, 0x00,
                (byte) (0x40 | 0x20 | 0x10 | 0x04), 0x03, '1', '2', '3' },
                encoded);
    }


    @Test
    public void testUnknownHeaderUsesLiteralName() throws Exception {
        // "x-custom" is not in the static table: Literal Field Line with
        // Literal Name 001 N=1 H=0 NameLen(3+). Name length 8 overflows
        // the 3-bit prefix (max 7): [0x37, 0x01].
        byte[] encoded = encodeFully(new QpackEncoder(),
                headers("x-custom", "foo"));
        Assert.assertArrayEquals(new byte[] { 0x00, 0x00,
                0x37, 0x01,
                'x', '-', 'c', 'u', 's', 't', 'o', 'm',
                0x03, 'f', 'o', 'o' }, encoded);
    }


    @Test
    public void testLowerCaseNamesByDefault() throws Exception {
        byte[] encoded = encodeFully(new QpackEncoder(),
                headers("X-Custom-Header", "v"));
        String asLatin1 = new String(encoded, StandardCharsets.ISO_8859_1);
        Assert.assertTrue("Name must be lower cased, got: " + asLatin1,
                asLatin1.contains("x-custom-header"));
    }


    @Test
    public void testLowerCaseNamesCanBeDisabled() throws Exception {
        QpackEncoder encoder = new QpackEncoder();
        MimeHeaders headers = headers("X-Custom", "v");
        ByteBuffer buffer = ByteBuffer.allocate(256);
        Assert.assertEquals(QpackEncoder.State.COMPLETE,
                encoder.encode(headers, buffer, false));
        String asLatin1 = new String(
                Arrays.copyOf(buffer.array(), buffer.position()),
                StandardCharsets.ISO_8859_1);
        Assert.assertTrue("Name case must be preserved, got: " + asLatin1,
                asLatin1.contains("X-Custom"));
    }


    @Test
    public void testUnderflowResumesWithoutCorruption() throws Exception {
        MimeHeaders headers = headers(
                ":method", "GET",
                ":path", "/a-fairly-long-path-for-testing",
                "x-one", "1",
                "x-two", "two-value",
                "x-three", "three-value");

        // Reference encoding with a generously sized buffer.
        byte[] expected = encodeFully(new QpackEncoder(), headers);

        // Encoding into small buffers must UNDERFLOW, resume from the
        // partial state, and produce exactly the same bytes.
        QpackEncoder encoder = new QpackEncoder();
        ByteBuffer buffer = ByteBuffer.allocate(3);
        int underflows = 0;
        while (true) {
            QpackEncoder.State state = encoder.encode(headers, buffer);
            if (state == QpackEncoder.State.COMPLETE) {
                break;
            }
            Assert.assertEquals(QpackEncoder.State.UNDERFLOW, state);
            underflows++;
            Assert.assertTrue("Must make progress before giving up",
                    underflows < 100);
            ByteBuffer larger = ByteBuffer.allocate(
                    Math.max(buffer.capacity() * 2, 64));
            buffer.flip();
            larger.put(buffer);
            buffer = larger;
        }
        Assert.assertTrue("Small buffers must have underflowed",
                underflows > 0);
        byte[] actual = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(actual);
        Assert.assertArrayEquals(expected, actual);
    }


    @Test
    public void testEncodingDifferentHeadersWhileIncompleteThrows()
            throws Exception {
        QpackEncoder encoder = new QpackEncoder();
        MimeHeaders first = headers("x-first",
                "a value long enough not to fit the tiny buffer");
        ByteBuffer tiny = ByteBuffer.allocate(10);
        Assert.assertEquals(QpackEncoder.State.UNDERFLOW,
                encoder.encode(first, tiny));

        try {
            encoder.encode(headers("x-other", "v"),
                    ByteBuffer.allocate(256));
            Assert.fail("Switching header sets mid-encode must throw");
        } catch (IllegalStateException e) {
            // Expected: the resume contract pins the in-flight headers.
        }
    }


    @Test
    public void testResetEncodingStateAllowsNewHeaders() throws Exception {
        QpackEncoder encoder = new QpackEncoder();
        MimeHeaders abandoned = headers("x-abandoned",
                "a value long enough not to fit the tiny buffer");
        ByteBuffer tiny = ByteBuffer.allocate(10);
        Assert.assertEquals(QpackEncoder.State.UNDERFLOW,
                encoder.encode(abandoned, tiny));

        encoder.resetEncodingState();

        List<String[]> emitted = decode(encodeFully(encoder,
                headers(":method", "GET", "x-new", "v")));
        assertEmitted(emitted, ":method", "GET", "x-new", "v");
    }


    @Test
    public void testUtf8ValueLengthIsInBytes() throws Exception {
        // The value is transported as UTF-8 octets; the string length field
        // counts octets, not characters (RFC 9204 Section 4.1.2).
        String value = "caf\u00E9";    // 4 chars, 5 UTF-8 bytes
        byte[] encoded = encodeFully(new QpackEncoder(),
                headers("x-coffee", value));
        List<String[]> emitted = decode(encoded);

        // Qpack.decodeString() yields ISO-8859-1 chars per octet; the
        // octets themselves must be exactly the UTF-8 encoding.
        String octets = emitted.get(0)[1];
        Assert.assertArrayEquals(value.getBytes(StandardCharsets.UTF_8),
                octets.getBytes(StandardCharsets.ISO_8859_1));
    }


    @Test
    public void testEmptyValueRoundTrip() throws Exception {
        List<String[]> emitted = decode(encodeFully(new QpackEncoder(),
                headers("x-empty", "")));
        Assert.assertEquals("x-empty", emitted.get(0)[0]);
        Assert.assertEquals("", emitted.get(0)[1]);
    }


    @Test
    public void testInvalidFieldNamesAreSkipped() throws Exception {
        // An empty field name used to throw
        // StringIndexOutOfBoundsException from the charAt(0) pseudo-header
        // test, and a name containing a space was encoded as a literal
        // (an invalid field section on the wire). Names that are neither
        // tokens (RFC 7230 Section 3.2) nor pseudo-headers must be dropped
        // while the valid fields still encode.
        byte[] encoded = encodeFully(new QpackEncoder(),
                headers("", "empty-name", "not a token", "spaced-name",
                        "x-valid", "ok"));
        List<String[]> emitted = decode(encoded);
        Assert.assertEquals(1, emitted.size());
        Assert.assertEquals("x-valid", emitted.get(0)[0]);
        Assert.assertEquals("ok", emitted.get(0)[1]);
    }
}

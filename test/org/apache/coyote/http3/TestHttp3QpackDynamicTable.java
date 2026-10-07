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
import java.util.Base64;

import org.junit.Assert;
import org.junit.Test;

/**
 * End-to-end tests for the QPACK (RFC 9204) dynamic table over a real
 * HTTP/3 connection: the raw client uses its QPACK encoder stream to
 * insert entries into the server's shared decoder, references them in a
 * request field section, and reads back the server's decoder stream
 * instructions (Section Acknowledgment, Insert Count Increment). The
 * echo servlet confirms what the server decoded.
 *
 * <p>The unit-level state machine behaviour is covered in-process by
 * {@link TestQpackDecoder}; these tests exercise the wire path
 * (encoder stream processing on the poll thread, decoder stream
 * emission, and the per-connection shared decoder).</p>
 */
public class TestHttp3QpackDynamicTable extends Http3TestBase {

    /*
     * Static table indexes used below (RFC 9204 Appendix A).
     */
    private static final int STATIC_PATH = 1;
    private static final int STATIC_CONTENT_DISPOSITION = 3;
    private static final int STATIC_AUTHORITY = 0;
    private static final int STATIC_METHOD_GET = 17;
    private static final int STATIC_SCHEME_HTTPS = 23;


    // ------------------------------------------------------------------
    // Payload builders
    // ------------------------------------------------------------------

    private static String b64(ByteBuffer buffer) {
        buffer.flip();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }


    private static void appendString(ByteBuffer target, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        Qpack.encodeIrp(target, 0, 7, bytes.length);
        target.put(bytes);
    }


    /*
     * Encoder instruction: Insert With Literal Name (RFC 9204 Section
     * 4.3.3, 01 H NameLen(5+)).
     */
    private static void insertLiteral(ByteBuffer target, String name,
            String value) {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        Qpack.encodeIrp(target, 0x40, 5, nameBytes.length);
        target.put(nameBytes);
        appendString(target, value);
    }


    /*
     * Encoder instruction: Insert With Name Reference, static table
     * (RFC 9204 Section 4.3.2, 11 iRP(m=6)).
     */
    private static void insertNameRefStatic(ByteBuffer target, int index,
            String value) {
        Qpack.encodeIrp(target, 0xC0, 6, index);
        appendString(target, value);
    }


    /*
     * Field line: Indexed Field Line, dynamic table (RFC 9204 Section
     * 4.5.2, 10 iRP(m=6)).
     */
    private static void putIndexedDynamic(ByteBuffer target, int index) {
        Qpack.encodeIrp(target, 0x80, 6, index);
    }


    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    @Test
    public void testDynamicTableInsertReferenceAndAck() throws Exception {
        startHttp3Server();

        // Encoder stream: capacity 512, two literal inserts and one insert
        // with a static name reference.
        ByteBuffer encoder = ByteBuffer.allocate(4096);
        Qpack.encodeIrp(encoder, 0x20, 5, 512);
        insertLiteral(encoder, "x-test-header", "inserted-value");  // abs 0
        insertLiteral(encoder, "x-dyn", "v1");                      // abs 1
        insertNameRefStatic(encoder, STATIC_CONTENT_DISPOSITION,
                "inline");                                          // abs 2

        // Field section: RIC = 3 (encoded 4), Delta Base 0, Base = 3. The
        // three dynamic references resolve to absolute 2, 1 and 0
        // (relative index 0 is Base-1). Pseudo headers first.
        ByteBuffer section = ByteBuffer.allocate(4096);
        Qpack.encodeIrp(section, 0, 8, 4);
        Qpack.encodeIrp(section, 0, 7, 0);
        Qpack.encodeIrp(section, 0xC0, 6, STATIC_METHOD_GET);
        Qpack.encodeIrp(section, 0xC0, 6, STATIC_SCHEME_HTTPS);
        Qpack.encodeIrp(section, 0x50, 4, STATIC_AUTHORITY);
        appendString(section, "127.0.0.1:" + port);
        Qpack.encodeIrp(section, 0x50, 4, STATIC_PATH);
        appendString(section, "/echo");
        putIndexedDynamic(section, 0);   // abs 2: content-disposition
        putIndexedDynamic(section, 1);   // abs 1: x-dyn
        putIndexedDynamic(section, 2);   // abs 0: x-test-header

        ClientOutput output = runClient(rawCommandWith(
                "--encoder", b64(encoder),
                "--encoder-delay", "0.5",
                "--headers", b64(section)), CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Decoded field section must contain the dynamic "
                + "references, body was: " + body,
                body.contains("x-test-header: inserted-value"));
        Assert.assertTrue("body was: " + body, body.contains("x-dyn: v1"));
        Assert.assertTrue("body was: " + body,
                body.contains("content-disposition: inline"));

        // The server (acting as QPACK decoder) must acknowledge the field
        // section that used dynamic references (RFC 9204 Section 2.2.2.1)
        // on the client's decoder stream, and must have confirmed the
        // three encoder stream insertions with Insert Count Increments
        // (Sections 2.2.2.3, 4.4.3).
        Assert.assertTrue("Expected a Section Acknowledgment for stream 0, "
                        + "got " + output.getDecoderAcks(),
                output.getDecoderAcks().contains(Integer.valueOf(0)));
        int totalIncrements = 0;
        for (Integer increment : output.getDecoderInsertIncrements()) {
            totalIncrements += increment.intValue();
        }
        Assert.assertEquals("Expected the 3 inserts to be confirmed", 3,
                totalIncrements);

        // The server advertises its dynamic table capacity (RFC 9204
        // Section 5, SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01).
        Assert.assertNotNull("Server SETTINGS must advertise "
                + "QPACK_MAX_TABLE_CAPACITY", output.getCtrlSetting(1));
    }


    /*
     * Builds the bytes of a field section that references the single
     * inserted dynamic-table entry (RIC = 1, encoded 2; Delta Base 0; one
     * indexed line, relative 0 = absolute 0).
     */
    private static byte[] dynamicTrailerSection() {
        ByteBuffer trailer = ByteBuffer.allocate(64);
        Qpack.encodeIrp(trailer, 0, 8, 2);
        Qpack.encodeIrp(trailer, 0, 7, 0);
        putIndexedDynamic(trailer, 0);
        byte[] section = new byte[trailer.position()];
        trailer.flip();
        trailer.get(section);
        return section;
    }


    /*
     * A HEADERS frame carrying only the first byte of the section (the
     * Required Insert Count prefix), declared at the full length: the
     * section is left incomplete on the wire.
     */
    private static String truncatedTrailerFrame(byte[] section) {
        byte[] frame = Base64.getDecoder().decode(buildFrameB64(0x01, section));
        // The frame header is two single-byte varints here (type 0x01 and
        // the small declared length); take it plus the prefix byte.
        byte[] truncated = new byte[] {frame[0], frame[1], frame[2]};
        return Base64.getEncoder().encodeToString(truncated);
    }


    @Test
    public void testStreamCancellationOnTruncatedTrailer() throws Exception {
        startHttp3Server();

        // Encoder stream: capacity 512, one insert (absolute index 0).
        ByteBuffer encoder = ByteBuffer.allocate(4096);
        Qpack.encodeIrp(encoder, 0x20, 5, 512);
        insertLiteral(encoder, "x-dyn", "v1");          // abs 0

        // The trailer section with the dynamic reference is truncated by
        // the FIN before it completes. The section never reaches the
        // decoder, but its Required Insert Count was delivered: abandoning
        // the stream still requires a Stream Cancellation so the peer's
        // encoder may again evict the referenced entry (RFC 9204
        // Sections 2.2.2.2, 4.4.2).
        byte[] section = dynamicTrailerSection();
        ClientOutput output = runClient(rawCommandWith(
                "--encoder", b64(encoder),
                "--encoder-delay", "0.5",
                "--headers",
                buildFieldSection(":method", "POST", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length", "5"),
                "--data", Base64.getEncoder().encodeToString(
                        "body!".getBytes(StandardCharsets.UTF_8)),
                "--frame-after-data", truncatedTrailerFrame(section),
                "--timeout", "5"), CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_MESSAGE_ERROR);
        Assert.assertTrue("Expected a Stream Cancellation for the truncated "
                        + "trailer section, got " + output.getDecoderCancellations(),
                output.getDecoderCancellations().contains(Integer.valueOf(0)));
    }


    @Test
    public void testStreamCancellationOnResetWithPartialTrailer()
            throws Exception {
        startHttp3Server();

        // The same dynamic trailer section, staged partially and never
        // finished (no FIN): the servlet blocks on the incomplete body and
        // the client resets the stream after one second. Receiving a reset
        // abandons reading of the stream just like abandonment on an
        // error: the unacknowledged section must be cancelled
        // (RFC 9204 Section 2.2.2.2).
        ByteBuffer encoder = ByteBuffer.allocate(4096);
        Qpack.encodeIrp(encoder, 0x20, 5, 512);
        insertLiteral(encoder, "x-dyn", "v1");          // abs 0
        byte[] section = dynamicTrailerSection();
        ClientOutput output = runClient(rawCommandWith(
                "--encoder", b64(encoder),
                "--encoder-delay", "0.5",
                "--headers",
                buildFieldSection(":method", "POST", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path", "/echo",
                        "content-length", "100"),
                "--data", Base64.getEncoder().encodeToString(
                        "body!".getBytes(StandardCharsets.UTF_8)),
                "--frame-after-data", truncatedTrailerFrame(section),
                "--no-fin",
                "--reset-request", "1",
                "--timeout", "1",
                "--wait", "4"), CLIENT_TIMEOUT_SECONDS);

        Assert.assertTrue("Expected a Stream Cancellation for the abandoned "
                        + "trailer section, got " + output.getDecoderCancellations(),
                output.getDecoderCancellations().contains(Integer.valueOf(0)));
    }


    @Test
    public void testReferenceToEvictedEntryFailsConnection()
            throws Exception {
        startHttp3Server();

        // Capacity 512 bytes; entries "evict-test-header: v<i>" cost
        // 32 + 17 + value bytes ~ 52 bytes each, so the table holds nine.
        // After twelve insertions the absolute indexes 0..2 are evicted.
        ByteBuffer encoder = ByteBuffer.allocate(8192);
        Qpack.encodeIrp(encoder, 0x20, 5, 512);
        for (int i = 0; i < 12; i++) {
            insertLiteral(encoder, "evict-test-header", "v" + i);
        }

        // Field section: RIC = 12 (encoded 13), Base = 12; relative index
        // 11 resolves to absolute 0, which has been evicted: an invalid
        // reference (RFC 9204 Section 2.2.3) and a connection error of
        // type QPACK_DECOMPRESSION_FAILED.
        ByteBuffer section = ByteBuffer.allocate(4096);
        Qpack.encodeIrp(section, 0, 8, 13);
        Qpack.encodeIrp(section, 0, 7, 0);
        putIndexedDynamic(section, 11);   // abs 0: evicted

        ClientOutput output = runClient(rawCommandWith(
                "--encoder", b64(encoder),
                "--encoder-delay", "0.5",
                "--headers", b64(section),
                "--timeout", "3"), CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_QPACK_DECOMPRESSION_FAILED);

        // The server stays healthy for subsequent connections.
        validateStatus(get("/simple"), 200);
    }


    @Test
    public void testTrailerSectionOnBodylessRequestIsAcknowledged()
            throws Exception {
        startHttp3Server();

        // A trailer section on a request without a declared body, on a
        // stream the application never reads: neither the pre-dispatch
        // body reader (entered only for declared bodies) nor the streaming
        // read (run only by doRead) ever encounters the section, so
        // without a post-response frame scan it would be recycled
        // undecoded - no acknowledgment (RFC 9204 Section 2.2.2.1) and no
        // cancellation (Section 2.2.2.2), leaving the referenced entry
        // outstanding on the peer's encoder for the life of the
        // connection. The dynamic-referencing trailer makes the omission
        // observable: the Section Acknowledgment must arrive after the
        // response.
        ByteBuffer encoder = ByteBuffer.allocate(4096);
        Qpack.encodeIrp(encoder, 0x20, 5, 512);
        insertLiteral(encoder, "x-dyn", "v1");          // abs 0

        ClientOutput output = runClient(rawCommandWith(
                "--encoder", b64(encoder),
                "--encoder-delay", "0.5",
                "--headers",
                buildFieldSection(":method", "GET", ":scheme", "https",
                        ":authority", "127.0.0.1:" + port, ":path",
                        "/simple"),
                "--trailers",
                Base64.getEncoder().encodeToString(
                        dynamicTrailerSection()),
                "--wait", "2"), CLIENT_TIMEOUT_SECONDS);

        validateStatus(output.getResponse(), 200);
        Assert.assertNull("A conformant trailer on a body-less stream must "
                        + "not fail the connection: " + output.getLines(),
                output.getConnectionError());
        Assert.assertTrue("Expected a Section Acknowledgment for the "
                        + "trailer section of the body-less request, got "
                        + output.getDecoderAcks(),
                output.getDecoderAcks().contains(Integer.valueOf(0)));
    }
}

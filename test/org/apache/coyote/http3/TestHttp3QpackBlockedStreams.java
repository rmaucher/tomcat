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

import org.apache.catalina.connector.Connector;

/**
 * End-to-end tests for opt-in QPACK (RFC 9204 Section 2.2.1) blocked
 * streams: the connector's {@code qpackBlockedStreams} property lets a
 * request field section that references not-yet-inserted dynamic table
 * entries wait for the peer's encoder stream instead of failing the
 * connection. The raw client sends such a field section before the
 * encoder stream instructions that satisfy it
 * ({@code --encoder-after-request}).
 */
public class TestHttp3QpackBlockedStreams extends Http3TestBase {

    private static final int STATIC_PATH = 1;
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
     * Field line: Indexed Field Line, dynamic table (RFC 9204 Section
     * 4.5.2, 10 iRP(m=6)).
     */
    private static void putIndexedDynamic(ByteBuffer target, int index) {
        Qpack.encodeIrp(target, 0x80, 6, index);
    }


    /*
     * Field section that requires exactly one encoder stream insert:
     * Required Insert Count 1 (encoded 2, RFC 9204 Section 4.5.1.1),
     * Sign 0 / Delta Base 0 so Base = 1. The dynamic reference resolves
     * to absolute index 0 (relative index 0 is Base-1). Pseudo-headers
     * first (RFC 9114 Section 4.3).
     */
    private ByteBuffer blockedFieldSection() {
        ByteBuffer section = ByteBuffer.allocate(4096);
        Qpack.encodeIrp(section, 0, 8, 2);
        Qpack.encodeIrp(section, 0, 7, 0);
        Qpack.encodeIrp(section, 0xC0, 6, STATIC_METHOD_GET);
        Qpack.encodeIrp(section, 0xC0, 6, STATIC_SCHEME_HTTPS);
        Qpack.encodeIrp(section, 0x50, 4, STATIC_AUTHORITY);
        appendString(section, "127.0.0.1:" + port);
        Qpack.encodeIrp(section, 0x50, 4, STATIC_PATH);
        appendString(section, "/echo");
        putIndexedDynamic(section, 0);   // abs 0: not inserted yet
        return section;
    }


    /*
     * Enable blocked streams on a running server: the property is read
     * per request and per new connection, so setting it after start
     * applies to the connections opened by the subsequent client run.
     */
    private void enableBlockedStreams(int limit) {
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setQpackBlockedStreams(limit);
    }


    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    @Test
    public void testBlockedStreamUnblocksWhenInsertArrives()
            throws Exception {
        Connector server = startHttp3Server();
        enableBlockedStreams(4);

        // Encoder stream (held back until after the request): capacity
        // 512 plus the single insert the field section requires.
        ByteBuffer encoder = ByteBuffer.allocate(4096);
        Qpack.encodeIrp(encoder, 0x20, 5, 512);
        insertLiteral(encoder, "x-blocked-header", "unblocked-value");

        long start = System.currentTimeMillis();
        ClientOutput output = runClient(rawCommandWith(
                "--encoder", b64(encoder),
                "--encoder-after-request", "1.0",
                "--headers", b64(blockedFieldSection()),
                "--wait", "2"), CLIENT_TIMEOUT_SECONDS);
        long elapsed = System.currentTimeMillis() - start;

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull("Connection must not be blocked out: " +
                        output.getLines(),
                output.getConnectionError());
        String body = response.getBodyAsString();
        Assert.assertTrue("The blocked field section must decode after "
                        + "the insert arrives, body was: " + body,
                body.contains("x-blocked-header: unblocked-value"));

        // The response can only have been produced after the encoder
        // stream delivered the insert one second after the request:
        // the stream really was blocked, not decoded eagerly.
        Assert.assertTrue("Response arrived after " + elapsed +
                " ms, expected at least the 1 s encoder delay",
                elapsed >= 800);

        // The blocked field section still used the dynamic table and must
        // be acknowledged (RFC 9204 Section 2.2.2.1), and the connector
        // must advertise the blocked-stream allowance (RFC 9204 Section 5,
        // SETTINGS_QPACK_BLOCKED_STREAMS 0x07).
        Assert.assertTrue("Expected a Section Acknowledgment for stream 0, "
                        + "got " + output.getDecoderAcks(),
                output.getDecoderAcks().contains(Integer.valueOf(0)));
        Assert.assertNotNull("Server SETTINGS must advertise "
                        + "QPACK_BLOCKED_STREAMS",
                output.getCtrlSetting(7));
    }


    @Test
    public void testBlockedStreamWaitTimesOut() throws Exception {
        startHttp3Server();
        enableBlockedStreams(4);

        // No --encoder payload: the default Set Dynamic Table Capacity 0
        // instruction is sent at connect time and the required insert
        // never arrives, so the blocked stream must exhaust the wait
        // (five seconds) before the connection fails with a decompression
        // failure, rather than blocking forever.
        long start = System.currentTimeMillis();
        ClientOutput output = runClient(rawCommandWith(
                "--headers", b64(blockedFieldSection()),
                "--timeout", "12",
                "--wait", "1"), CLIENT_TIMEOUT_SECONDS);
        long elapsed = System.currentTimeMillis() - start;

        assertConnectionError(output, H3_QPACK_DECOMPRESSION_FAILED);
        Assert.assertTrue("The wait must run its full course (" + elapsed +
                " ms), not fail early", elapsed >= 4500);

        // The server stays healthy for subsequent connections.
        validateStatus(get("/simple"), 200);
    }


    @Test
    public void testBlockedStreamLimitExceeded() throws Exception {
        startHttp3Server();
        enableBlockedStreams(1);

        // Three streams whose field sections all require an insert that
        // never arrives. Only one may block (the connector's limit): the
        // next blocked field section fails the connection with a
        // decompression failure immediately, long before the five second
        // wait of the first could expire.
        long start = System.currentTimeMillis();
        ClientOutput output = runClient(rawCommandWith(
                "--headers", b64(blockedFieldSection()),
                "--streams", "3",
                "--timeout", "12",
                "--wait", "1"), CLIENT_TIMEOUT_SECONDS);
        long elapsed = System.currentTimeMillis() - start;

        assertConnectionError(output, H3_QPACK_DECOMPRESSION_FAILED);
        Assert.assertTrue("The blocked-stream limit must reject the excess "
                        + "stream without waiting (" + elapsed + " ms)",
                elapsed < 4000);

        // The server stays healthy for subsequent connections.
        validateStatus(get("/simple"), 200);
    }
}

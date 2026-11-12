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

import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.net.quic.QuicConnection;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicStream;

/**
 * Tests for the limits imposed by the server on the size and number of
 * field section entries, on the length of request stream frames and on the
 * number of concurrent request streams.
 */
public class TestHttp3Limits extends Http3TestBase {


    @Test
    public void testFieldSectionTooLarge() throws Exception {
        startHttp3Server();

        // A field section larger than the MAX_FIELD_SECTION_SIZE setting
        // (16384) is a request error of type H3_MESSAGE_ERROR.
        ClientOutput output = rawRequest(fieldSectionHeaders(20, 1000));

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testFieldSectionUnderLimit() throws Exception {
        startHttp3Server();

        ClientOutput output = rawRequest(fieldSectionHeaders(10, 1200));

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testMaxFieldSectionSizeBeyondIntRangeStillServes()
            throws Exception {
        // maxFieldSectionSize is a long connector property. The decoder limit
        // is an int; 2^32 wraps to 0 under a narrowing cast, which the QPACK
        // decoder reads as "reject every non-empty field section" (the check
        // is maxHeaderSize >= 0 && size > maxHeaderSize), and larger values
        // wrap negative which disables the limit entirely. The cast must be
        // clamped so ordinary requests still succeed while a sane (int
        // range) limit is enforced.
        Connector connector = startHttp3Server();
        Assert.assertTrue(connector.setProperty("maxFieldSectionSize",
                "4294967296"));

        Http3Response response = get("/simple");
        validateStatus(response, 200);
    }


    @Test
    public void testTooManyHeaders() throws Exception {
        startHttp3Server();

        // 97 custom headers plus the 4 pseudo headers exceed the maximum
        // of 100 field section entries.
        ClientOutput output = rawRequest(headerCountHeaders(97));

        assertStreamError(output, H3_MESSAGE_ERROR);
    }


    @Test
    public void testHeaderCountAtLimit() throws Exception {
        startHttp3Server();

        // 96 custom headers plus the 4 pseudo headers reach the maximum
        // of 100 field section entries.
        ClientOutput output = rawRequest(headerCountHeaders(96));

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
    }


    @Test
    public void testOversizedDataFrameResetsStream() throws Exception {
        startHttp3Server();

        // HTTP/3 has no negotiated frame size limit (unlike HTTP/2's
        // SETTINGS_MAX_FRAME_SIZE), so a DATA frame declaring a length
        // above this implementation's 16 MiB buffering limit is protocol-
        // valid. The receiver declines to buffer it and rejects only the
        // affected request (RESET_STREAM with H3_FRAME_ERROR) instead of
        // failing the whole connection.
        long declaredLength = 16L * 1024 * 1024 + 1;
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port,
                        ":path", "/simple",
                        "content-length", Long.toString(declaredLength)),
                "--frame-after-data", oversizedDataFrameB64(declaredLength),
                "--no-fin",
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_FRAME_ERROR);
    }


    @Test
    public void testOversizedDataFrameStreamingResetsStream() throws Exception {
        startHttp3Server();

        // The body crosses the pre-buffering limit (64 KiB), so the
        // oversized DATA frame is parsed on the streaming read path while
        // the servlet reads the body. The frame is likewise rejected at
        // stream scope (RESET_STREAM with H3_FRAME_ERROR); the connection
        // survives and the response is suppressed by the stream reset.
        byte[] first = new byte[64 * 1024];
        Arrays.fill(first, (byte) 'a');
        long declaredLength = 16L * 1024 * 1024 + 1;
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(":method", "POST",
                        ":scheme", "https",
                        ":authority", "127.0.0.1:" + port,
                        ":path", "/echo",
                        "content-length",
                        Long.toString(first.length + declaredLength)),
                "--data", Base64.getEncoder().encodeToString(first),
                "--frame-after-data", oversizedDataFrameB64(declaredLength),
                "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS);

        assertStreamError(output, H3_FRAME_ERROR);
    }


    private static String oversizedDataFrameB64(long declaredLength) {
        byte[] type = encodeVarint(0x00);
        byte[] length = encodeVarint(declaredLength);
        byte[] payload = new byte[] { (byte) 'x' };
        byte[] frame = new byte[type.length + length.length + payload.length];
        System.arraycopy(type, 0, frame, 0, type.length);
        System.arraycopy(length, 0, frame, type.length, length.length);
        System.arraycopy(payload, 0, frame, type.length + length.length,
                payload.length);
        return Base64.getEncoder().encodeToString(frame);
    }


    @Test
    public void testPreHeaderUnknownFrameNotBufferedMidDelivery()
            throws Exception {
        startHttp3Server();

        // A frame with an unknown type must be ignored without buffering its
        // payload (RFC 9114 Sections 4.1, 9). The client declares a large
        // unknown frame (type 0xA0, not in the reserved family) and delivers
        // 10 MiB of it, holding the rest back so the server sits mid-frame.
        // If the server buffered the pre-HEADERS payload as it read it, the
        // heap would have grown by roughly the delivered amount at the midRun
        // sample; the skip path must not allocate at all.
        int delivered = 10 * 1024 * 1024;
        long declared = 16L * 1024 * 1024;
        long[] heapDelta = new long[1];
        long heapBefore = usedHeap();

        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--declared-frame", "0xA0," + declared + "," + delivered,
                "--frame-delay", "5",
                "--timeout", "20",
                "--wait", "2"),
                CLIENT_TIMEOUT_SECONDS, 0, () -> {
                    // Sample while the server has read the delivered payload
                    // of the mid-frame unknown frame but not its remainder
                    // (held back by --frame-delay).
                    try {
                        Thread.sleep(1300);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    heapDelta[0] = usedHeap() - heapBefore;
                });

        // The stream must still serve: the unknown frame is skipped and the
        // HEADERS frame after it processed normally. The client timeout is
        // deliberately generous so a loaded test machine has time to deliver
        // the delayed remainder and process the following HEADERS frame.
        Assert.assertEquals("Expected exactly one response; client output: "
                        + output.getLines(), 1, output.getResponses().size());
        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getConnectionError());

        // The delivered 10 MiB must not have been retained as frame payload.
        // The heap delta stays small because the payload is skipped as it
        // arrives; a buffering implementation would grow by ~10 MiB.
        Assert.assertTrue("Pre-HEADERS unknown frame payload was buffered: "
                + "heap grew by " + heapDelta[0] + " bytes mid-frame",
                heapDelta[0] < 2 * 1024 * 1024);
    }


    @Test
    public void testPreHeaderIgnoredFrameAboveBufferLimitServes()
            throws Exception {
        startHttp3Server();

        // An ignored (unknown/reserved) frame's payload is discarded
        // without ever being buffered, so it may declare any QUIC varint
        // length: the reserved family is explicitly usable as padding
        // (RFC 9114 Sections 7.2.8, 10.7) and unknown values MUST be
        // ignored (Section 9) - the control stream already ignores
        // unknown frames of any size. The 16 MiB limit only protects
        // frames whose payload this receiver buffers (DATA, HEADERS), so
        // padding declared above it must not reset the request: the
        // payload is discarded as it arrives and the HEADERS frame that
        // follows is served normally.
        long declared = 16L * 1024 * 1024 + 1;
        int delivered = 64 * 1024;
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--declared-frame", "0x21," + declared + "," + delivered,
                "--frame-delay", "1",
                "--timeout", "20"),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
        Assert.assertNull(output.getConnectionError());
    }


    @Test
    public void testPreHeaderDataFrameRejectedEarly() throws Exception {
        startHttp3Server();

        // A DATA frame before the first HEADERS frame is an invalid frame
        // sequence (RFC 9114 Section 4.1) and a connection error of type
        // H3_FRAME_UNEXPECTED. It must be rejected at the frame header: the
        // client declares a huge (but protocol-valid, <= MAX_FRAME_LENGTH)
        // DATA length and delivers only a few bytes. A pre-header DATA frame
        // is never legitimate, so the frame payload must never be buffered
        // and the connection must fail as soon as the header is parsed.
        long declaredLength = 15L * 1024 * 1024;
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--frame", declaredDataFrameB64(declaredLength, 4),
                "--no-fin",
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    private static String declaredDataFrameB64(long declaredLength,
            int delivered) {
        byte[] type = encodeVarint(0x00);
        byte[] length = encodeVarint(declaredLength);
        byte[] payload = new byte[delivered];
        Arrays.fill(payload, (byte) 'x');
        byte[] frame =
                new byte[type.length + length.length + payload.length];
        System.arraycopy(type, 0, frame, 0, type.length);
        System.arraycopy(length, 0, frame, type.length, length.length);
        System.arraycopy(payload, 0, frame, type.length + length.length,
                payload.length);
        return Base64.getEncoder().encodeToString(frame);
    }


    private static long usedHeap() {
        // Full GC, then used heap: transient allocations are collected, so a
        // sustained delta means retained live data. System.gc() is only a
        // request: on the busy test JVM a full GC can outlast any fixed
        // sleep, and sampling before it completes reports the uncollected
        // transient garbage of an in-flight transfer (tens of MiB after a
        // 10 MiB stream delivery, near-identical every run because it is
        // proportional to the delivered amount) as a retained delta.
        // Collect repeatedly until consecutive readings stop improving by
        // 256 KiB: at that point the collections reclaim no more and the
        // lowest reading is the live-data floor.
        long lowest = Long.MAX_VALUE;
        long deadline = System.currentTimeMillis() + 3000;
        while (System.currentTimeMillis() < deadline) {
            System.gc();
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            long previous = lowest;
            lowest = Math.min(lowest,
                    ManagementFactory.getMemoryMXBean().getHeapMemoryUsage()
                            .getUsed());
            if (previous != Long.MAX_VALUE
                    && previous - lowest < 256 * 1024) {
                break;
            }
        }
        return lowest;
    }


    @Test
    public void testMaxConcurrentStreams() throws Exception {
        Connector connector = startHttp3Server();

        // Use a non-default limit so the test proves the configured value
        // (not the hard-wired default) is propagated to the connection and
        // enforced (RFC 9114 Section 6.1.1).
        int limit = 50;
        ((AbstractHttp3Protocol) connector.getProtocolHandler())
                .setMaxConcurrentStreams(limit);

        // Open more concurrent request streams than the server accepts.
        // The /sleep endpoint holds each accepted stream open so that the
        // limit is deterministically reached before any stream completes.
        // The streams that are dropped are reset with H3_REQUEST_REJECTED
        // (the retryable refusal, RFC 9114 Section 8.1) and the server
        // informs the client via a GOAWAY frame (RFC 9114 Section 7.2.6).
        int streamCount = limit + 10;
        ClientOutput output = runClient(rawCommandWith(
                "--headers",
                buildFieldSection(simpleGetHeaders("/sleep?ms=2000")),
                "--streams", Integer.toString(streamCount)),
                CLIENT_TIMEOUT_SECONDS);

        int resultCount = output.getResponses().size()
                + output.getStreamResets().size();
        Assert.assertEquals(streamCount, resultCount);
        // At least one stream must have been refused, otherwise the
        // configured limit was not enforced.
        Assert.assertFalse("Expected at least one stream to be refused by the"
                + " concurrent stream limit, but all "
                + output.getResponses().size()
                + " streams were accepted",
                output.getStreamResets().isEmpty());
        // The server must have sent a GOAWAY frame on its control stream.
        Assert.assertFalse("Expected a GOAWAY frame on the server control"
                + " stream but none was received",
                output.getCtrlGoaway().isEmpty());
        // RFC 9114 Section 5.2: the identifier is the ID of the first
        // client-initiated bidirectional stream that may not have been
        // processed - here the first refused stream, so a conformant
        // client retries the refused streams but never a processed one.
        // Successive frames MUST NOT carry a greater identifier (an
        // increase is a connection error of type H3_ID_ERROR at the
        // receiver): with the whole burst arriving at once and the
        // accepted streams held by /sleep, every frame must identify the
        // first refusal.
        long lowestRefused = output.getStreamResets().keySet().stream()
                .mapToLong(Long::parseLong).min().getAsLong();
        for (String goawayId : output.getCtrlGoaway()) {
            Assert.assertEquals("Expected every GOAWAY identifier to name "
                    + "the first unprocessed stream ID",
                    Long.toString(lowestRefused), goawayId);
        }
        for (Map.Entry<String, Integer> reset
                : output.getStreamResets().entrySet()) {
            Assert.assertEquals("Expected the excess stream "
                    + reset.getKey() + " to be reset with "
                    + "H3_REQUEST_REJECTED",
                    Integer.valueOf(H3_REQUEST_REJECTED), reset.getValue());
        }
    }


    @Test
    public void testStreamLimitReachedBeforeAnyStreamSendsGoaway()
            throws Exception {
        startHttp3Server();

        // The endpoint shutdown notification runs the same GOAWAY path as
        // the stream-limit notification. On a connection that never had a
        // request stream the recorded last-processed ID is -1, which the
        // GOAWAY frame builder rejects: the frame must instead be emitted
        // with identifier 0 (RFC 9114 Section 7.2.6: "no streams were
        // processed") rather than being dropped silently.
        // Hold a raw connection open (no request stream), stop the
        // connector while it is up, and check the GOAWAY on the wire.
        Thread stopper = new Thread(() -> {
            try {
                Thread.sleep(1500);
                connector.stop();
            } catch (Exception e) {
                // The connector was already stopping
            }
        });
        stopper.setDaemon(true);
        stopper.start();

        ClientOutput output = runClient(rawCommandWith(
                "--no-request", "--wait", "4"), CLIENT_TIMEOUT_SECONDS);

        stopper.join(CLIENT_TIMEOUT_SECONDS * 1000);

        Assert.assertTrue("Expected a GOAWAY frame with identifier 0 on the "
                + "server control stream but got " + output.getCtrlGoaway(),
                output.getCtrlGoaway().contains("0"));
    }


    @Test
    public void testStreamLimitFrameIdentifierSemantics() throws Exception {
        Http3ConnectionManager manager =
                new Http3ConnectionManager(newHttp3Protocol());

        // RFC 9114 Section 5.2: the frame carries the ID of the first
        // client-initiated bidirectional stream that may not have been
        // processed - one four-ID step (RFC 9000 Section 2.1) after the
        // last processed one, never the last processed ID itself (that
        // request was accepted and may already have been executed). With
        // nothing processed the identifier is the first client stream
        // ID, 0.
        Http3ConnectionManager.ConnectionState noneProcessed =
                new Http3ConnectionManager.ConnectionState(null);
        Assert.assertEquals(0L, parseGoawayIdentifier(
                manager.getStreamLimitFrame(noneProcessed, -1)));

        Http3ConnectionManager.ConnectionState someProcessed =
                new Http3ConnectionManager.ConnectionState(null);
        Assert.assertEquals(12L, parseGoawayIdentifier(
                manager.getStreamLimitFrame(someProcessed, 8)));

        // Successive GOAWAY identifiers on one connection MUST NOT be
        // greater than any previously sent identifier (a conformant
        // receiver treats an increase as a connection error of type
        // H3_ID_ERROR). The last processed ID grows between refusals, so
        // the frame builder must clamp to what was already sent.
        Http3ConnectionManager.ConnectionState state =
                new Http3ConnectionManager.ConnectionState(null);
        Assert.assertEquals(12L, parseGoawayIdentifier(
                manager.getStreamLimitFrame(state, 8)));
        Assert.assertEquals(12L, parseGoawayIdentifier(
                manager.getStreamLimitFrame(state, 1000)));
        Assert.assertEquals(12L, state.getLastSentGoawayId());

        // Once a GOAWAY identifier has been sent, new streams at or above it
        // must be rejected: a client is entitled to retry them on another
        // connection. Streams below the identifier may still be accepted
        // (the client will not retry them).
        Assert.assertFalse("stream at GOAWAY identifier accepted",
                state.canAcceptStream(12));
        Assert.assertFalse("stream above GOAWAY identifier accepted",
                state.canAcceptStream(16));
        Assert.assertTrue("stream below GOAWAY identifier rejected",
                state.canAcceptStream(8));

        // Stream data can arrive out of order. The recorded processed ID is a
        // high-water mark, so a later lower ID must not move the GOAWAY
        // identifier backwards above an already-processed stream.
        Http3ConnectionManager.ConnectionState outOfOrder =
                new Http3ConnectionManager.ConnectionState(null);
        outOfOrder.setLastProcessedStreamId(8);
        outOfOrder.setLastProcessedStreamId(4);
        Assert.assertEquals(8L, outOfOrder.getLastProcessedStreamId());
        Assert.assertEquals(12L, parseGoawayIdentifier(
                manager.getStreamLimitFrame(outOfOrder,
                        outOfOrder.getLastProcessedStreamId())));
    }


    @Test
    public void testMaxFieldSectionSizeZeroIsNotAbsent() throws Exception {
        Http3Settings absent =
                new Http3Settings(ByteBuffer.allocate(0));
        Assert.assertEquals(-1L, absent.getMaxFieldSectionSize());

        ByteBuffer payload = ByteBuffer.allocate(16);
        Qpack.encodeQuicInteger(payload,
                Constants.H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
        Qpack.encodeQuicInteger(payload, 0);
        payload.flip();
        Http3Settings zero = new Http3Settings(payload);
        Assert.assertEquals(0L, zero.getMaxFieldSectionSize());
    }


    @Test
    public void testSharedDecoderRequiresSetCapacityBeforeInsert()
            throws Exception {
        Http3ConnectionManager manager =
                new Http3ConnectionManager(newHttp3Protocol());
        QpackDecoder decoder = manager.getSharedDecoder();

        // RFC 9204 Section 3.2.2: the initial dynamic table capacity is
        // zero, so an insert before Set Dynamic Table Capacity must be a
        // QPACK_ENCODER_STREAM_ERROR (entry larger than the capacity).
        ByteBuffer instruction = ByteBuffer.allocate(32);
        Qpack.encodeIrp(instruction, 0x40, 5, 1); // literal name, length 1
        instruction.put((byte) 'x');
        Qpack.encodeIrp(instruction, 0, 7, 1); // value, length 1
        instruction.put((byte) 'y');
        instruction.flip();
        try {
            decoder.processInstruction(instruction);
            Assert.fail("Insert before Set Dynamic Table Capacity accepted");
        } catch (QpackException expected) {
            // Expected
        }
    }


    @Test
    public void testMaxFieldSectionSizeIsClampedToFrameLimit()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        // A field section limit far above what the per-frame buffer and the
        // QPACK wire overhead can support must not be advertised verbatim.
        protocol.setMaxFieldSectionSize(8L * 1024 * 1024);
        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);

        long effective = (16L * 1024 * 1024
                - (2L * Qpack.MAX_IRP_ENCODED_LENGTH + 12L)) * 4L / 15L;
        Assert.assertEquals("A configured size above the frame limit must be "
                + "clamped to the effective limit", effective,
                manager.getMaxFieldSectionSize());

        ByteBuffer init = manager.getServerUniStreamInitData(
                Http3ConnectionManager.SERVER_STREAM_INDEX_CONTROL);
        Assert.assertEquals(Constants.H3_STREAM_TYPE_CONTROL,
                decodeQuicInteger(init));
        Assert.assertEquals(Constants.H3_SETTINGS,
                decodeQuicInteger(init));
        long settingsLength = decodeQuicInteger(init);
        Assert.assertEquals(settingsLength, init.remaining());
        long advertised = -1;
        while (init.hasRemaining()) {
            long id = decodeQuicInteger(init);
            long value = decodeQuicInteger(init);
            if (id == Constants.H3_SETTINGS_MAX_FIELD_SECTION_SIZE) {
                advertised = value;
            }
        }
        Assert.assertEquals(effective, advertised);
    }


    @Test
    public void testIgnoredControlFrameBudget() throws Exception {
        Http3ConnectionManager manager =
                new Http3ConnectionManager(newHttp3Protocol());
        QuicConnection connection = newConnection(manager);
        manager.connectionOpen(connection);

        // SETTINGS is the required first control-stream frame; it is followed
        // by an unknown frame whose declared payload exceeds the ignored-data
        // budget. The connection must fail with H3_EXCESSIVE_LOAD instead of
        // consuming the padding indefinitely.
        ByteBuffer data = ByteBuffer.allocate(32);
        Qpack.encodeQuicInteger(data, Constants.H3_STREAM_TYPE_CONTROL);
        Qpack.encodeQuicInteger(data, Constants.H3_SETTINGS);
        Qpack.encodeQuicInteger(data, 0);
        Qpack.encodeQuicInteger(data, 0x80);
        Qpack.encodeQuicInteger(data, 33L * 1024 * 1024);
        data.flip();
        try {
            manager.processClientUniStreamData(connection, 2, data);
            Assert.fail("An ignored control frame above the budget must "
                    + "fail the connection");
        } catch (Http3Exception e) {
            Assert.assertEquals(Http3Error.H3_EXCESSIVE_LOAD, e.getError());
        }
    }


    @Test
    public void testUnknownUniStreamDataBudget() throws Exception {
        Http3ConnectionManager manager =
                new Http3ConnectionManager(newHttp3Protocol());
        QuicConnection connection = newConnection(manager);
        manager.connectionOpen(connection);

        // The first chunk identifies a reserved/unknown stream type; all
        // subsequent payload is discarded. Discarding must be bounded per
        // connection rather than allowing arbitrary padding work.
        ByteBuffer first = ByteBuffer.allocate(1024 * 1024 + 4);
        Qpack.encodeQuicInteger(first, 0x40);
        first.position(first.limit());
        first.flip();
        manager.processClientUniStreamData(connection, 2, first);

        boolean failed = false;
        try {
            for (int i = 0; i < 33; i++) {
                ByteBuffer chunk = ByteBuffer.allocate(1024 * 1024);
                chunk.position(chunk.limit());
                chunk.flip();
                manager.processClientUniStreamData(connection, 2, chunk);
            }
        } catch (Http3Exception e) {
            Assert.assertEquals(Http3Error.H3_EXCESSIVE_LOAD, e.getError());
            failed = true;
        }
        Assert.assertTrue("Discarding unknown uni-stream data above the "
                + "budget must fail the connection", failed);
    }


    private static QuicConnection newConnection(Http3ConnectionManager manager) {
        return new QuicConnection() {

            @Override
            public QuicConnectionManager getQuicConnectionManager() {
                return manager;
            }

            @Override
            public String getSniHostName() {
                return "";
            }

            @Override
            public void failConnection(long appErrorCode, String reason) {
                // Not used by these tests
            }

            @Override
            public int writeToStream(QuicStream stream, ByteBuffer data) {
                return 0;
            }
        };
    }


    @Test
    public void testConnectionSettingsAreSnapshotted() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        protocol.setQpackMaxTableCapacity(1024);
        protocol.setQpackBlockedStreams(3);
        protocol.setMaxFieldSectionSize(8192);

        Http3ConnectionManager manager = new Http3ConnectionManager(protocol);

        // Change the connector properties after the per-connection manager
        // has captured its settings. The advertised SETTINGS and the decoder
        // hard limit must keep using the captured values, otherwise a peer
        // could be told a capacity the decoder rejects.
        protocol.setQpackMaxTableCapacity(2048);
        protocol.setQpackBlockedStreams(5);
        protocol.setMaxFieldSectionSize(16384);

        ByteBuffer init = manager.getServerUniStreamInitData(
                Http3ConnectionManager.SERVER_STREAM_INDEX_CONTROL);
        Assert.assertEquals(Constants.H3_STREAM_TYPE_CONTROL,
                decodeQuicInteger(init));
        Assert.assertEquals(Constants.H3_SETTINGS,
                decodeQuicInteger(init));
        long settingsLength = decodeQuicInteger(init);
        Assert.assertEquals(settingsLength, init.remaining());

        long qpackCapacity = -1;
        long blockedStreams = -1;
        long maxFieldSectionSize = -1;
        while (init.hasRemaining()) {
            long id = decodeQuicInteger(init);
            long value = decodeQuicInteger(init);
            if (id == Constants.H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY) {
                qpackCapacity = value;
            } else if (id == Constants.H3_SETTINGS_QPACK_BLOCKED_STREAMS) {
                blockedStreams = value;
            } else if (id == Constants.H3_SETTINGS_MAX_FIELD_SECTION_SIZE) {
                maxFieldSectionSize = value;
            }
        }
        Assert.assertEquals(1024, qpackCapacity);
        Assert.assertEquals(3, blockedStreams);
        Assert.assertEquals(8192, maxFieldSectionSize);

        // The shared decoder hard limit must match the advertised capacity.
        QpackDecoder decoder = manager.getSharedDecoder();
        ByteBuffer tooLarge = ByteBuffer.allocate(16);
        Qpack.encodeIrp(tooLarge, 0x20, 5, 2048);
        tooLarge.flip();
        try {
            decoder.processInstruction(tooLarge);
            Assert.fail("A capacity above the snapshotted maximum must be "
                    + "rejected");
        } catch (QpackException expected) {
            // Expected
        }
        ByteBuffer accepted = ByteBuffer.allocate(16);
        Qpack.encodeIrp(accepted, 0x20, 5, 1024);
        accepted.flip();
        decoder.processInstruction(accepted);
    }


    @Test
    public void testServerQpackEncoderStreamSendsNoInstructions()
            throws Exception {
        Http3ConnectionManager manager =
                new Http3ConnectionManager(newHttp3Protocol());

        // The server encoder never inserts into a dynamic table. In
        // particular it must not send a Set Dynamic Table Capacity
        // instruction when the peer advertised a maximum capacity of zero
        // (the default); the stream carries only its type byte.
        ByteBuffer init = manager.getServerUniStreamInitData(
                Http3ConnectionManager.SERVER_STREAM_INDEX_QPACK_ENCODER);
        Assert.assertEquals(1, init.remaining());
        Assert.assertEquals(Constants.H3_STREAM_TYPE_QPACK_ENCODER, init.get());
    }


    /*
     * Parses the single QUIC variable-length integer payload of a GOAWAY
     * frame built by Http3ConnectionManager.getStreamLimitFrame.
     */
    private static long parseGoawayIdentifier(ByteBuffer frame) {
        Assert.assertEquals("frame type", (byte) Constants.H3_GOAWAY,
                frame.get());
        int len = (int) decodeQuicInteger(frame);
        Assert.assertEquals("payload length", len, frame.remaining());
        long id = decodeQuicInteger(frame);
        Assert.assertEquals("payload fully consumed", 0, frame.remaining());
        return id;
    }


    private static long decodeQuicInteger(ByteBuffer buffer) {
        int first = buffer.get() & 0xFF;
        int length = 1 << (first >> 6);
        long value = first & 0x3F;
        for (int i = 1; i < length; i++) {
            value = (value << 8) | (buffer.get() & 0xFF);
        }
        return value;
    }


    @Test
    public void testLargeResponse() throws Exception {
        startHttp3Server();

        Http3Response response = get("/large");

        validateStatus(response, 200);
        byte[] body = response.getBody();
        Assert.assertEquals(256 * 1024, body.length);
        // The body is a repeating 1024 byte pattern.
        Assert.assertEquals(0, body[0] & 0xFF);
        Assert.assertEquals(1, body[1] & 0xFF);
        Assert.assertEquals(250, body[250] & 0xFF);
        Assert.assertEquals(0, body[251] & 0xFF);
        Assert.assertEquals(1, body[1024 + 1] & 0xFF);
    }


    private String[] fieldSectionHeaders(int headerCount,
            int valueLength) {
        StringBuilder value = new StringBuilder(valueLength);
        for (int i = 0; i < valueLength; i++) {
            value.append((char) ('a' + (i % 26)));
        }
        String[] headers = new String[8 + headerCount * 2];
        headers[0] = ":method";
        headers[1] = "GET";
        headers[2] = ":scheme";
        headers[3] = "https";
        headers[4] = ":authority";
        headers[5] = "127.0.0.1:" + port;
        headers[6] = ":path";
        headers[7] = "/simple";
        for (int i = 0; i < headerCount; i++) {
            headers[8 + i * 2] = "x-large-" + i;
            headers[9 + i * 2] = value.toString();
        }
        return headers;
    }


    private String[] headerCountHeaders(int headerCount) {
        String[] headers = new String[8 + headerCount * 2];
        headers[0] = ":method";
        headers[1] = "GET";
        headers[2] = ":scheme";
        headers[3] = "https";
        headers[4] = ":authority";
        headers[5] = "127.0.0.1:" + port;
        headers[6] = ":path";
        headers[7] = "/simple";
        for (int i = 0; i < headerCount; i++) {
            headers[8 + i * 2] = "x-count-" + i;
            headers[9 + i * 2] = "value";
        }
        return headers;
    }
}

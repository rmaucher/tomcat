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

import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.http.parser.Priority;

/**
 * Tests for the HTTP/3 elements of the extensible priorities scheme
 * (<a href="https://www.rfc-editor.org/rfc/rfc9218">RFC 9218</a>): the
 * Priority request header field (Section 5) and the PRIORITY_UPDATE frames
 * (Sections 7 and 7.2).
 *
 * <p>Note that the server scheduling guidance of RFC 9218 Section 10 is
 * advisory only and is not exercised by these tests; the tests verify the
 * mandatory signal handling (parsing, consumption, error handling and the
 * Section 7 buffering rule).
 */
public class TestRfc9218 extends Http3TestBase {

    // HTTP/3 PRIORITY_UPDATE frame types (RFC 9218 Section 7.2).
    private static final int H3_PRIORITY_UPDATE_REQUEST = 0xF0700;
    private static final int H3_PRIORITY_UPDATE_PUSH = 0xF0701;


    /**
     * Builds the payload of a PRIORITY_UPDATE frame: a Prioritized Element
     * ID variable-length integer (RFC 9218 Section 7.2) followed by the
     * Priority Field Value (ASCII, same representation as the Priority
     * request header field).
     */
    private static byte[] priorityUpdatePayload(long elementId,
            String fieldValue) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte b : encodeVarint(elementId)) {
            out.write(b);
        }
        if (fieldValue != null && !fieldValue.isEmpty()) {
            byte[] value = fieldValue.getBytes(StandardCharsets.US_ASCII);
            out.write(value, 0, value.length);
        }
        return out.toByteArray();
    }


    /**
     * Builds a client control stream payload that starts with a valid
     * (empty) SETTINGS frame, as required by RFC 9114 Section 6.2.1,
     * followed by the given PRIORITY_UPDATE frames.
     */
    private String controlWithPriorityUpdates(int frameType,
            byte[]... payloads) {
        String[] frames = new String[payloads.length + 1];
        frames[0] = buildSettingsFrameB64();
        for (int i = 0; i < payloads.length; i++) {
            frames[i + 1] = buildFrameB64(frameType, payloads[i]);
        }
        return buildFramesB64(frames);
    }


    /**
     * A PRIORITY_UPDATE frame (request-stream variant) sent on the client
     * control stream before the referenced request stream opens must be
     * buffered and applied when the stream opens without any error
     * (RFC 9218 Sections 6 and 7). Since QUIC gives no ordering across
     * streams, this also covers the case where the frame arrives at the
     * server before "its" stream.
     */
    @Test
    public void testPriorityUpdateBeforeRequestStream() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith(
                "--control", controlWithPriorityUpdates(
                        H3_PRIORITY_UPDATE_REQUEST,
                        priorityUpdatePayload(0, "u=6, i")),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple"))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getStreamError());
        Assert.assertNull(output.getConnectionError());
    }


    /**
     * The original Priority request header field is the end-to-end signal
     * (RFC 9218 Section 5). It is consumed as priority signal input and,
     * matching HTTP/2 (Stream.emitHeader), is not forwarded to the
     * application, so the echo servlet's request header list below must not
     * contain it.
     */
    @Test
    public void testPriorityRequestHeaderConsumed() throws Exception {
        startHttp3Server();

        ClientOutput output = rawGet("/echo",
                "priority", "u=6, i", "x-test", "present");

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        String body = response.getBodyAsString();
        Assert.assertTrue("Expected the other header to survive: " + body,
                body.contains("x-test: present"));
        Assert.assertFalse("Priority header must be consumed, not forwarded: "
                + body, body.contains("priority"));
        Assert.assertNull(output.getConnectionError());
    }


    /**
     * An invalid Priority header field value (not a valid Structured Fields
     * Dictionary) is ignored per RFC 9218 Section 4; the request must
     * complete normally.
     */
    @Test
    public void testPriorityRequestHeaderInvalidIgnored() throws Exception {
        startHttp3Server();

        ClientOutput output = rawGet("/echo", "priority", "u=1:i");

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getConnectionError());
    }


    /**
     * A PRIORITY_UPDATE frame (request-stream variant, RFC 9218
     * Section 7.2) received on the client control stream targeting a stream
     * that never opens must be handled without a connection error: the
     * update is buffered ("Servers SHOULD buffer the most recently received
     * PRIORITY_UPDATE frame and apply it once the referenced stream is
     * opened", RFC 9218 Section 7). Since QUIC stream IDs are never reused,
     * an update buffered for an unopened/closed stream is harmless; here
     * the update targets stream 0, which is never opened (the connection
     * only carries the control stream).
     */
    @Test
    public void testPriorityUpdateWithoutRequestStream() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith(
                "--control", controlWithPriorityUpdates(
                        H3_PRIORITY_UPDATE_REQUEST, priorityUpdatePayload(0, "u=6")),
                "--no-request", "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertNoResponseOrError(output);
    }


    /**
     * The request's own Priority header field is older than a PRIORITY_UPDATE
     * that raced ahead of the stream opening. RFC 9218 Section 7: the most
     * recently received PRIORITY_UPDATE overrides any other signal, so once
     * the buffered update has been applied (at processor wiring), decoding
     * the request's Priority field must not supersede it.
     */
    @Test
    public void testPriorityFieldCannotOverrideBufferedPriorityUpdate()
            throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, null);
        Http3ConnectionManager.ConnectionState state =
                new Http3ConnectionManager.ConnectionState(null);

        // Pre-open race: the update is buffered because no consumer is
        // registered yet (RFC 9218 Section 7).
        state.applyPriorityUpdate(0,
                Priority.parsePriority(new StringReader("u=6, i")));
        // Wiring the processor applies the buffered update and marks the
        // signal as update-sourced.
        processor.setStreamId(0);
        state.registerPriorityConsumer(processor, 0);
        Assert.assertEquals("Buffered update must be applied on wiring", 6,
                processor.getUrgency());
        Assert.assertTrue("Buffered update must be incremental",
                processor.getIncremental());

        // The request's own (older) Priority field arrives during field
        // section decoding and must not override the update signal.
        processor.emitHeader("priority", "u=2");
        Assert.assertEquals("Priority field must not override the "
                        + "PRIORITY_UPDATE (RFC 9218 Section 7)", 6,
                processor.getUrgency());
        Assert.assertTrue("Incremental must not be overridden",
                processor.getIncremental());
    }


    /**
     * With no PRIORITY_UPDATE applied, the Priority request header field
     * does set the priority signal (RFC 9218 Section 5).
     */
    @Test
    public void testPriorityFieldSetsSignalWithoutUpdate() throws Exception {
        AbstractHttp3Protocol protocol = newHttp3Protocol();
        Http3Processor processor = new Http3Processor(protocol, null);
        processor.setStreamId(0);

        processor.emitHeader("priority", "u=2, i");
        Assert.assertEquals(2, processor.getUrgency());
        Assert.assertTrue(processor.getIncremental());
    }


    @Test
    public void testPriorityUpdateInvalidFieldValueIgnored() throws Exception {
        startHttp3Server();

        // The PRIORITY_UPDATE frame delivers a Priority Field Value using
        // the same representation as the Priority header field. An
        // unparsable value is ignored: RFC 9218 Section 7 allows (MAY) a
        // connection error for it and RFC 9218 Section 4 requires invalid
        // values to be ignored. The server keeps serving subsequent
        // requests.
        ClientOutput output = runClient(rawCommandWith(
                "--control", controlWithPriorityUpdates(
                        H3_PRIORITY_UPDATE_REQUEST,
                        priorityUpdatePayload(0, "u=1:i")),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple"))),
                CLIENT_TIMEOUT_SECONDS);

        Http3Response response = output.getResponse();
        validateStatus(response, 200);
        Assert.assertNull(output.getConnectionError());
    }


    /**
     * A PRIORITY_UPDATE (request-stream variant) whose prioritized element
     * ID is not a request stream (a client-initiated bidirectional stream
     * ID) is a connection error of type H3_ID_ERROR (RFC 9218 Section 7.2).
     * Element ID 2 is a server-initiated bidirectional stream ID.
     */
    @Test
    public void testPriorityUpdateNotARequestStream() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith(
                "--control", controlWithPriorityUpdates(
                        H3_PRIORITY_UPDATE_REQUEST, priorityUpdatePayload(2, "u=6")),
                "--no-request", "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_ID_ERROR);
    }


    /**
     * The push-stream variant of PRIORITY_UPDATE (0xF0701, RFC 9218
     * Section 7.2) must reference a promised push stream. The server does
     * not implement push (it never sends PUSH_PROMISE), so no push ID can
     * ever have been promised and receipt is a connection error of type
     * H3_ID_ERROR for any push ID.
     */
    @Test
    public void testPriorityUpdatePushVariant() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith(
                "--control", controlWithPriorityUpdates(
                        H3_PRIORITY_UPDATE_PUSH, priorityUpdatePayload(0, "u=6")),
                "--no-request", "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_ID_ERROR);
    }


    /**
     * PRIORITY_UPDATE frames are confined to the client control stream
     * (RFC 9218 Section 7.2); receipt on a request stream is a connection
     * error of type H3_FRAME_UNEXPECTED. The raw client supports sending
     * arbitrary frames before the request HEADERS.
     */
    @Test
    public void testPriorityUpdateOnRequestStream() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith(
                "--frame",
                buildFrameB64(H3_PRIORITY_UPDATE_REQUEST,
                        priorityUpdatePayload(0, "u=6")),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    @Test
    public void testPriorityUpdateOnRequestStreamPushVariant() throws Exception {
        startHttp3Server();

        // The stream confinement applies to both PRIORITY_UPDATE variants:
        // neither may be sent on a request stream (RFC 9218 Section 7.2).
        ClientOutput output = runClient(rawCommandWith(
                "--frame",
                buildFrameB64(H3_PRIORITY_UPDATE_PUSH,
                        priorityUpdatePayload(0, "u=6")),
                "--headers",
                buildFieldSection(simpleGetHeaders("/simple")),
                "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_UNEXPECTED);
    }


    /**
     * A PRIORITY_UPDATE frame payload that does not match the frame
     * definition - here a payload too short to contain the Prioritized
     * Element ID variable-length integer - violates RFC 9114 Section 7.1
     * and is a connection error of type H3_FRAME_ERROR.
     */
    @Test
    public void testPriorityUpdateEmptyPayloadFrameError() throws Exception {
        startHttp3Server();

        ClientOutput output = runClient(rawCommandWith(
                "--control", controlWithPriorityUpdates(
                        H3_PRIORITY_UPDATE_REQUEST, new byte[0]),
                "--no-request", "--timeout", "3"),
                CLIENT_TIMEOUT_SECONDS);

        assertConnectionError(output, H3_FRAME_ERROR);
    }
}
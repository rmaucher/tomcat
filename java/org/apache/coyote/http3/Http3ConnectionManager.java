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

import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.http.parser.Priority;
import org.apache.tomcat.util.net.quic.QuicConnection;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicStream;
import org.apache.tomcat.util.res.StringManager;


/**
 * Manages HTTP/3 connection state per QUIC connection.
 * <p>
 * HTTP/3 unidirectional streams are identified by the stream type, which
 * the sender writes as the first (unframed) QUIC varint on the stream
 * (RFC 9114 Section 6.2.1, RFC 9204 Section 4.2). Stream IDs are assigned
 * in creation order (RFC 9000 Section 2.1), so a conforming client's
 * control stream or QPACK streams may appear on any client-initiated
 * unidirectional stream ID (2, 6, 10, ...). The stream types this
 * implementation recognizes are:
 * <ul>
 * <li>0x00 - control stream (SETTINGS, CANCEL_PUSH, GOAWAY,
 * MAX_PUSH_ID, PRIORITY_UPDATE frames)</li>
 * <li>0x01 - push stream: server-initiated only, so a client-initiated one
 * is rejected with H3_STREAM_CREATION_ERROR (RFC 9114 Section 6.2.2)</li>
 * <li>0x02 - QPACK encoder stream (encoder instructions)</li>
 * <li>0x03 - QPACK decoder stream (decoder instructions)</li>
 * <li>any other type - read and discarded, not a connection error
 * (RFC 9114 Section 9)</li>
 * </ul>
 */
public class Http3ConnectionManager implements QuicConnectionManager {

    private static final Log log = LogFactory.getLog(Http3ConnectionManager.class);
    private static final StringManager sm = StringManager.getManager(Http3ConnectionManager.class);

    /**
     * Per-connection state.
     */
    private final Map<QuicConnection, ConnectionState> connections = new ConcurrentHashMap<>();

    /**
     * HTTP/3 protocol reference for settings.
     */
    private final AbstractHttp3Protocol protocol;

    /**
     * Maximum number of decoder instructions (Section Acknowledgment and
     * Stream Cancellation) that may be pending per connection. When the
     * limit is reached the connection is failed instead of accumulating
     * unbounded state on the shared QUIC poll thread: a peer that never
     * reads its QPACK decoder stream must not be able to grow per-
     * connection memory and per-flush work without bound.
     */
    static final int MAX_PENDING_DECODER_INSTRUCTIONS = 10_000;

    /**
     * Shared QPACK decoder for this connection.
     * Per RFC 9204, all streams on a connection share a single decoder with a
     * unified dynamic table (the client's encoder instructions, received on the
     * client QPACK encoder stream, update this table). The QPACK encoder is
     * not shared: each stream uses its own encoder instance because its
     * in-progress encoding state must not be visible to the worker threads
     * processing other streams of the same connection.
     */
    private final QpackDecoder sharedDecoder;


    public Http3ConnectionManager(AbstractHttp3Protocol protocol) {
        this.protocol = protocol;
        // The hard limit of the shared decoder must match the
        // SETTINGS_QPACK_MAX_TABLE_CAPACITY value advertised to the peer:
        // per RFC 9204 Section 4.5.1.1 the peer reconstructs the Required
        // Insert Count using the decoder's maximum table capacity, so a
        // decoder with a different limit would mis-decode field sections of
        // conformant peers. In particular an advertised maximum of 0 must
        // not be floored above 0 (RFC 9204 Section 3.2.3: with a maximum
        // capacity of 0 no entries may be inserted at all); the decoder
        // handles a zero-capacity table.
        long capacity = protocol.getQpackMaxTableCapacity();
        int tableCapacity = Constants.clampToNonNegativeInt(capacity);
        sharedDecoder = new QpackDecoder(tableCapacity, tableCapacity);
        protocol.configureDecoder(sharedDecoder);
    }


    /**
     * Called when a new QUIC connection is established.
     *
     * @param connection The QUIC connection wrapper
     */
    @Override
    public void connectionOpen(QuicConnection connection) {
        ConnectionState state = new ConnectionState(connection);
        // Start from the configured limit. The endpoint later clamps this to
        // the limit the QUIC transport actually advertises to the peer (see
        // the endpoint's transport stream limits handling), so the enforced
        // limit cannot exceed what the transport grants.
        state.setMaxConcurrentStreams(protocol.getMaxConcurrentStreams());
        connections.put(connection, state);
        if (log.isDebugEnabled()) {
            log.debug(sm.getString("http3ConnectionManager.connectionOpen",
                    Integer.valueOf(System.identityHashCode(connection))));
        }
    }


    /**
     * Called when a QUIC connection is closed.
     *
     * @param connection The QUIC connection wrapper
     */
    @Override
    public void connectionClose(QuicConnection connection) {
        // This manager is created per QUIC connection and a ConnectionState is
        // never reused across connections, so removal is the full cleanup: the
        // state object and everything it references become unreachable with it
        // (no explicit reset of its fields is needed).
        connections.remove(connection);
        if (log.isDebugEnabled()) {
            log.debug(sm.getString("http3ConnectionManager.connectionClose",
                    Integer.valueOf(System.identityHashCode(connection))));
        }
    }


    /**
     * Processes data on a client-initiated unidirectional stream.
     * <p>
     * The stream is identified by its stream type, not its stream ID
     * (RFC 9114 Section 6.2.1, RFC 9204 Section 4.2, RFC 9000 Section
     * 2.1). The stream type varint is read from the start of the stream
     * the first time data is seen; streams with unknown types are read
     * and discarded (RFC 9114 Section 9).
     *
     * @param connection The QUIC connection
     * @param streamId The stream ID
     * @param data The data buffer
     */
    @Override
    public void processClientUniStreamData(QuicConnection connection, long streamId, ByteBuffer data)
            throws Http3Exception, QpackException {
        ConnectionState state = connections.get(connection);
        if (state == null) {
            return;
        }

        // Unknown stream type: consume and discard (RFC 9114 Section 9).
        // Checked before the identification block below so data bytes of an
        // already-discarded stream can never be mistaken for a stream type.
        // Consumed by advancing position to limit: the buffer contract (see
        // QuicConnectionManager.processClientUniStreamData()) requires the
        // buffer to stay in read mode - clear() would have the caller's
        // compact() replay the whole buffer capacity and leave it full.
        if (state.isUniStreamDiscarded(streamId)) {
            data.position(data.limit());
            return;
        }

        long streamType = state.getClientUniStreamType(streamId);
        if (streamType < 0) {
            // First data on this stream: identify it by stream type.
            if (!data.hasRemaining()) {
                return;
            }
            int sp = data.position();
            streamType = Qpack.decodeQuicInteger(data);
            if (streamType == -1) {
                // Incomplete stream type varint: retain for the next read,
                // unless the retained bytes already fill the stream read
                // buffer. The buffer is the entire retention window for a
                // partial frame, so a varint that cannot complete from it
                // never will: fail the connection instead of stalling the
                // stream forever (H3_EXCESSIVE_LOAD).
                data.position(sp);
                if (data.limit() - sp >= data.capacity()) {
                    throw partialDataTooLarge(streamId);
                }
                return;
            }
            if (streamType == Constants.H3_STREAM_TYPE_CONTROL) {
                rejectSecondCriticalStream(state.isClientControlStreamOpen());
                state.setClientControlStreamId(streamId);
            } else if (streamType == Constants.H3_STREAM_TYPE_QPACK_ENCODER) {
                rejectSecondCriticalStream(state.isClientQpackEncoderStreamOpen());
                state.setClientQpackEncoderStreamId(streamId);
            } else if (streamType == Constants.H3_STREAM_TYPE_QPACK_DECODER) {
                rejectSecondCriticalStream(state.isClientQpackDecoderStreamOpen());
                state.setClientQpackDecoderStreamId(streamId);
            } else if (streamType == Constants.H3_STREAM_TYPE_PUSH) {
                // Push streams are server-initiated only (RFC 9114
                // Section 6.2.2): a client-initiated push stream is a
                // connection error of type H3_STREAM_CREATION_ERROR. It is a
                // known type, so the "ignore unknown stream types" rule of
                // Section 9 does not apply.
                throw new Http3Exception(
                        sm.getString("http3ConnectionManager.clientPushStream",
                                Long.valueOf(streamId)),
                        Http3Error.H3_STREAM_CREATION_ERROR);
            } else {
                // Unknown stream type (RFC 9114 Section 9): read and
                // discard; MUST NOT be treated as a connection error.
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http3ConnectionManager.unknownStreamType",
                            Long.valueOf(streamType), Long.valueOf(streamId)));
                }
                state.markUniStreamDiscarded(streamId);
                data.position(data.limit());
                return;
            }
        }

        if (streamType == Constants.H3_STREAM_TYPE_CONTROL) {
            processClientControlStream(state, streamId, data);
        } else if (streamType == Constants.H3_STREAM_TYPE_QPACK_ENCODER) {
            // Client QPACK encoder stream: encoder instructions for the
            // server's QPACK decoder (RFC 9204 Section 4.2). A malformed
            // instruction is a connection error of type
            // H3_QPACK_ENCODER_STREAM_ERROR (RFC 9204 Section 6).
            processQpackEncoderStream(streamId, data);
            // Inserts raise the decoder's insert count, which owes the peer
            // an Insert Count Increment instruction (RFC 9204 Section
            // 2.2.2.3). Mark the connection so the poll-thread flush sweep
            // picks the instruction up (the field-section decode path marks
            // via noteSectionAcknowledgment; encoder-only traffic has no
            // other hook).
            connection.setProtocolDataPending(true);
        } else if (streamType == Constants.H3_STREAM_TYPE_QPACK_DECODER) {
            // Client QPACK decoder stream: decoder instructions for the
            // server's QPACK encoder (RFC 9204 Section 4.2). A malformed
            // instruction is a connection error of type
            // H3_QPACK_DECODER_STREAM_ERROR (RFC 9204 Section 6).
            processQpackDecoderStream(state, streamId, data);
        }

        // No native work here: this method only parses and updates the
        // connection state. Any pending decoder instructions (Section
        // Acknowledgment, Stream Cancellation, Insert Count Increment) are only
        // queued (into the connection state, thread-safely) and are emitted on
        // the poll thread by the caller - either explicitly right after this
        // returns, or by the endpoint's periodic flush
        // ({@link #flushPendingProtocolData}).
    }


    /*
     * At most one control stream and at most one QPACK encoder and decoder
     * stream are permitted per peer: a second stream of any of these types
     * is a connection error of type H3_STREAM_CREATION_ERROR (RFC 9114
     * Section 6.2.1, RFC 9204 Section 4.2).
     */
    private void rejectSecondCriticalStream(boolean alreadyOpen)
            throws Http3Exception {
        if (alreadyOpen) {
            throw new Http3Exception(
                    sm.getString("http3ConnectionManager.streamCreationError"),
                    Http3Error.H3_STREAM_CREATION_ERROR);
        }
    }


    /**
     * {@inheritDoc}
     * <p>
     * For HTTP/3 the server opens three unidirectional streams: index 0 is
     * the control stream, index 1 the QPACK encoder stream and index 2 the
     * QPACK decoder stream (RFC 9114 Section 6.2, RFC 9204 Section 4.2).
     * The two QPACK streams are deferred until the client's SETTINGS have
     * been received: RFC 9204 Section 4.2 does not require this - an
     * endpoint MAY create the streams at any time and MUST allow the peer
     * to do the same - but holding them back keeps the encoder stream from
     * being created before the peer's dynamic table capacity is known
     * (RFC 9204 Section 3.2.3), and the deferral costs nothing on the
     * output side: the server's encoder never uses the dynamic table, so
     * the first - and only - instruction on its encoder stream is a
     * constant-zero Set Dynamic Table Capacity (see
     * {@link #getServerUniStreamInitData(int)}). That constant is the
     * capacity of the server's own encoder table; it is not the
     * SETTINGS_QPACK_MAX_TABLE_CAPACITY the server announces in its
     * SETTINGS, which is the configured (by default non-zero) limit the
     * peer's encoder must respect when inserting into this server's
     * decoder.
     */
    @Override
    public int nextServerUniStream(QuicConnection connection) {
        ConnectionState state = connections.get(connection);
        if (state == null) {
            return -1;
        }
        if (!state.serverControlStreamCreated) {
            return SERVER_STREAM_INDEX_CONTROL;
        }
        if (!state.clientSettingsReceived) {
            return -1;
        }
        if (!state.serverQpackEncoderStreamCreated) {
            return SERVER_STREAM_INDEX_QPACK_ENCODER;
        }
        if (!state.serverQpackDecoderStreamCreated) {
            return SERVER_STREAM_INDEX_QPACK_DECODER;
        }
        return -1;
    }


    /**
     * Server unidirectional stream indices as defined by
     * {@link #nextServerUniStream(QuicConnection)}.
     */
    static final int SERVER_STREAM_INDEX_CONTROL = 0;
    static final int SERVER_STREAM_INDEX_QPACK_ENCODER = 1;
    static final int SERVER_STREAM_INDEX_QPACK_DECODER = 2;


    /**
     * {@inheritDoc}
     * <p>
     * For HTTP/3:
     * <ul>
     * <li>index 0: control stream type plus the SETTINGS frame (RFC 9114
     * Sections 6.2.1 and 7.2.4 require SETTINGS to be the first frame on
     * the control stream)</li>
     * <li>index 1: QPACK encoder stream type byte plus the Set Dynamic
     * Table Capacity instruction with capacity {@code 0}, announcing the
     * initial (zero) capacity of the server's dynamic table for decoding
     * responses (RFC 9204 Section 3.2.2: the dynamic table starts at zero
     * capacity; Section 4.3.1 defines the instruction but imposes no
     * ordering on encoder instructions - the server encoder never
     * inserts, so it announces {@code 0} and no further instructions
     * follow)</li>
     * <li>index 2: QPACK decoder stream type byte (RFC 9204 Section 4.2)</li>
     * </ul>
     */
    @Override
    public ByteBuffer getServerUniStreamInitData(int index) {
        switch (index) {
            case SERVER_STREAM_INDEX_CONTROL:
                return createServerControlStreamData();
            case SERVER_STREAM_INDEX_QPACK_ENCODER:
                // 0x20 = Set Dynamic Table Capacity: 001 + iRP(m=5) capacity=0
                return ByteBuffer.wrap(new byte[]{
                        (byte) Constants.H3_STREAM_TYPE_QPACK_ENCODER, 0x20 });
            case SERVER_STREAM_INDEX_QPACK_DECODER:
                return ByteBuffer.wrap(new byte[]{
                        (byte) Constants.H3_STREAM_TYPE_QPACK_DECODER });
            default:
                return null;
        }
    }


    /**
     * {@inheritDoc}
     * <p>
     * For HTTP/3 the QPACK decoder stream handle (index 2) is stored in the
     * connection state so decoder instructions (Section Acknowledgment,
     * Stream Cancellation, Insert Count Increment) can later be written
     * directly to the stream from the QUIC poll thread.
     */
    @Override
    public void serverUniStreamCreated(QuicConnection connection, int index,
            QuicStream stream) {
        ConnectionState state = connections.get(connection);
        if (state == null) {
            return;
        }
        if (index == SERVER_STREAM_INDEX_CONTROL) {
            state.serverControlStreamCreated = true;
        } else if (index == SERVER_STREAM_INDEX_QPACK_ENCODER) {
            state.serverQpackEncoderStreamCreated = true;
        } else if (index == SERVER_STREAM_INDEX_QPACK_DECODER) {
            state.serverQpackDecoderStream = stream;
            state.serverQpackDecoderStreamCreated = true;
        }
    }


    /**
     * Creates the data for the server control stream.
     * Per RFC 9114 Section 6.2.1, the control stream (stream type 0x00)
     * must begin with the SETTINGS frame, which MUST be the first frame
     * sent on the control stream (RFC 9114 Section 7.2.4).
     *
     * @return ByteBuffer containing the server control stream data
     */
    private ByteBuffer createServerControlStreamData() {
        ByteBuffer buffer = ByteBuffer.allocate(256);

        // Write stream type: control stream (0) - QUIC varint
        Qpack.encodeQuicInteger(buffer, Constants.H3_STREAM_TYPE_CONTROL);

        // Write SETTINGS frame - QUIC varint type + length + payload
        Qpack.encodeQuicInteger(buffer, Constants.H3_SETTINGS);

        // Encode SETTINGS payload first to determine its length
        ByteBuffer settingsPayload = ByteBuffer.allocate(64);
        Http3Settings.encode(settingsPayload, protocol.getQpackMaxTableCapacity(),
                protocol.getQpackBlockedStreams(),
                protocol.getMaxFieldSectionSize(),
                protocol.isEnableConnectProtocol(),
                protocol.isH2CompatibleIdentity());
        settingsPayload.flip();
        int settingsLen = settingsPayload.remaining();

        // Debug: log payload bytes
        if (log.isTraceEnabled()) {
            StringBuilder sb = new StringBuilder("SETTINGS payload (");
            sb.append(settingsLen).append(" bytes): ");
            while (settingsPayload.hasRemaining()) {
                sb.append(String.format("%02X ", settingsPayload.get()));
            }
            settingsPayload.rewind();
            log.trace(sb.toString());
        }

        // Write SETTINGS frame length (QUIC varint)
        Qpack.encodeQuicInteger(buffer, settingsLen);

        // Write SETTINGS payload
        buffer.put(settingsPayload);

        buffer.flip();
        return buffer;
    }


    /**
     * {@inheritDoc}
     * <p>
     * Generates the HTTP/3 GOAWAY frame. Per RFC 9114 Section 5.2 the
     * payload is the ID of the first client-initiated bidirectional
     * stream that may not have been processed: requests with that ID or a
     * greater one are rejected by the sender of the GOAWAY, requests on
     * stream IDs less than it might have been processed. The identifier
     * is also clamped to be no greater than that of any GOAWAY previously
     * sent on the connection, which Section 5.2 requires (a receiver
     * MUST treat a greater identifier as a connection error of type
     * H3_ID_ERROR).
     */
    @Override
    public ByteBuffer getStreamLimitFrame(
            QuicConnectionManager.ConnectionState state,
            long lastProcessedStreamId) {
        // Client-initiated bidirectional stream IDs step by four (RFC 9000
        // Section 2.1), so the first stream that may not have been
        // processed is the one following the last processed one. A
        // negative recorded ID means no request stream was ever accepted:
        // the first client stream ID (0) is then the first that may be
        // unprocessed, and every request on the connection may be retried.
        long identifier =
                lastProcessedStreamId < 0 ? 0 : lastProcessedStreamId + 4;
        // Successive GOAWAY identifiers MUST NOT increase (RFC 9114
        // Section 5.2). The last processed ID grows as previously refused
        // rounds are accepted and completed, so clamp against the
        // identifier already sent on this connection.
        long sent = state.getLastSentGoawayId();
        if (sent >= 0 && identifier > sent) {
            identifier = sent;
        }
        state.setLastSentGoawayId(identifier);

        // GOAWAY frame per RFC 9114 Section 7.2.6
        // Payload: Stream ID / Push ID (i) - QUIC variable-length integer
        ByteBuffer payloadBuf = ByteBuffer.allocate(8);
        Qpack.encodeQuicInteger(payloadBuf, identifier);
        payloadBuf.flip();

        ByteBuffer buffer = ByteBuffer.allocate(4 + payloadBuf.remaining());
        Qpack.encodeQuicInteger(buffer, Constants.H3_GOAWAY);
        Qpack.encodeQuicInteger(buffer, payloadBuf.remaining());
        buffer.put(payloadBuf);
        buffer.flip();
        return buffer;
    }


    private void processClientControlStream(ConnectionState state, long streamId, ByteBuffer data) throws Http3Exception {
        if (log.isDebugEnabled()) {
            log.debug("processClientControlStream: streamId=" + streamId + " remaining=" + data.remaining());
        }

        // The stream type varint has already been read by
        // processClientUniStreamData(). Frames on the control stream are
        // SETTINGS, GOAWAY and MAX_PUSH_ID; per RFC 9114 Section 6.2.1
        // the first frame MUST be SETTINGS (otherwise a connection error
        // of type H3_MISSING_SETTINGS) and a second SETTINGS frame is a
        // connection error of type H3_FRAME_UNEXPECTED (Section 7.2.4).
        while (data.hasRemaining()) {
            // Continuation of a payload skip for an unknown frame whose
            // payload spans reads: consume the bytes without retaining
            // them (an unknown frame is ignored, not buffered; RFC 9114
            // Section 9).
            long skipRemaining = state.controlFrameSkipRemaining;
            if (skipRemaining > 0) {
                long skip = Math.min(skipRemaining, data.remaining());
                data.position(data.position() + (int) skip);
                state.controlFrameSkipRemaining = skipRemaining - skip;
                if (state.controlFrameSkipRemaining > 0) {
                    // Still inside the skipped payload: the whole buffer
                    // was consumed, wait for the rest.
                    break;
                }
                continue;
            }

            int sp = data.position();
            long frameType = Qpack.decodeQuicInteger(data);
            long frameLength = frameType == -1 ? -1 : Qpack.decodeQuicInteger(data);
            if (frameType == -1 || frameLength == -1) {
                // Incomplete frame header: retain for the next read, unless
                // the retained bytes already fill the stream read buffer.
                // The buffer is the entire retention window, so a header
                // that cannot complete from it never will: fail the
                // connection instead of stalling the stream (H3_EXCESSIVE_LOAD).
                data.position(sp);
                if (data.limit() - sp >= data.capacity()) {
                    throw partialDataTooLarge(streamId);
                }
                break;
            }

            // RFC 9114 Section 6.2.1: the first frame on the control
            // stream MUST be SETTINGS. The frame type alone decides, so
            // this is checked on the parsed header, before any payload
            // retention (an oversized or never-completing first frame must
            // not delay the error).
            if (!state.clientControlFirstFrameSeen) {
                state.clientControlFirstFrameSeen = true;
                if (frameType != Constants.H3_SETTINGS) {
                    if (log.isWarnEnabled()) {
                        log.warn(sm.getString("http3ConnectionManager.missingSettings"));
                    }
                    throw new Http3Exception(
                            sm.getString("http3ConnectionManager.missingSettings"),
                            Http3Error.H3_MISSING_SETTINGS);
                }
            }

            if (Constants.isHttp2ReservedFrame(frameType) ||
                    isForbiddenOnClientControlStream(frameType)) {
                // HTTP/2 frame types reserved by HTTP/3 (0x02, 0x06, 0x08,
                // 0x09) have no meaning here, and DATA, HEADERS and
                // PUSH_PROMISE carry request/push-stream semantics a client
                // control stream never has (a client MUST NOT send
                // PUSH_PROMISE at all): none of these are "unknown" values
                // to ignore - their receipt MUST be treated as a connection
                // error of type H3_FRAME_UNEXPECTED (RFC 9114 Sections
                // 7.2.1, 7.2.2, 7.2.5, 7.2.8, 11.2.1). Checked on the
                // header, so a rejected frame cannot claim buffer space
                // with a large declared length before failing.
                if (log.isWarnEnabled()) {
                    log.warn(sm.getString("http3Processor.frameUnexpected",
                            Long.valueOf(streamId), Long.valueOf(frameType)));
                }
                throw new Http3Exception(
                        sm.getString("http3Processor.frameUnexpected",
                                Long.valueOf(streamId), Long.valueOf(frameType)),
                        Http3Error.H3_FRAME_UNEXPECTED);
            }

            if (!isKnownClientControlFrame(frameType)) {
                // Unknown frame type on the control stream: skip the
                // payload. Per RFC 9114 Section 9, unknown values in
                // extensible protocol elements (including frame types)
                // MUST be ignored. The payload is consumed rather than
                // retained, so a frame larger than the stream read buffer
                // is ignored (with any size) without stalling the stream.
                // The only position where a specific frame type is required
                // is the first frame (SETTINGS, enforced above).
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http3Processor.unexpectedFrameOnStream",
                            Long.valueOf(frameType),
                            Long.valueOf(streamId)));
                }
                long skip = Math.min(frameLength, data.remaining());
                data.position(data.position() + (int) skip);
                if (skip < frameLength) {
                    // Payload spans reads: remember what is left to drop.
                    state.controlFrameSkipRemaining = frameLength - skip;
                    break;
                }
                continue;
            }

            if (frameLength > (long) data.capacity() - (data.position() - sp)) {
                // A known frame whose payload cannot fit in the stream read
                // buffer can never be re-assembled from the retained bytes
                // (the buffer is the entire retention window). This is an
                // implementation limit on re-assembly size, signalled with
                // H3_EXCESSIVE_LOAD rather than letting the stream stall.
                if (log.isWarnEnabled()) {
                    log.warn(sm.getString(
                            "http3ConnectionManager.controlFrameTooLarge",
                            Long.valueOf(frameType), Long.valueOf(frameLength),
                            Integer.valueOf(data.capacity())));
                }
                throw new Http3Exception(
                        sm.getString(
                                "http3ConnectionManager.controlFrameTooLarge",
                                Long.valueOf(frameType), Long.valueOf(frameLength),
                                Integer.valueOf(data.capacity())),
                        Http3Error.H3_EXCESSIVE_LOAD);
            }

            if (data.remaining() < frameLength) {
                // Incomplete (but small enough to fit) known frame payload:
                // retain partial bytes for the next read
                data.position(sp);
                break;
            }

            if (frameType == Constants.H3_SETTINGS) {
                // RFC 9114 Section 7.2.4: A receiver MUST treat receipt of a
                // second SETTINGS frame as a connection error of type H3_FRAME_UNEXPECTED.
                if (state.clientSettingsReceived) {
                    if (log.isWarnEnabled()) {
                        log.warn(sm.getString("http3ConnectionManager.duplicateSettings"));
                    }
                    throw new Http3Exception(
                            sm.getString("http3ConnectionManager.duplicateSettings"),
                            Http3Error.H3_FRAME_UNEXPECTED);
                }
                ByteBuffer settingsData = data.slice();
                settingsData.limit((int) frameLength);
                try {
                    // Parse (duplicate/reserved identifier checks, value
                    // ranges). The QPACK limits the peer advertises are not
                    // acted on: the server encoder does not use the dynamic
                    // table, so the peer's table capacity and blocked-stream
                    // count are irrelevant for outgoing field sections. The
                    // peer's SETTINGS_MAX_FIELD_SECTION_SIZE is retained on
                    // the connection state and applied when encoding
                    // response field sections (RFC 9114 Section 4.2.2).
                    Http3Settings clientSettings = new Http3Settings(settingsData);
                    state.clientSettingsReceived = true;
                    state.setPeerMaxFieldSectionSize(clientSettings.getMaxFieldSectionSize());
                    if (log.isTraceEnabled()) {
                        log.trace(sm.getString("http3ConnectionManager.settingsReceived",
                                Long.valueOf(frameType)));
                    }
                } catch (Http3Exception e) {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("http3ConnectionManager.settingsError"), e);
                    }
                    throw e;
                }
                data.position(data.position() + (int) frameLength);
            } else if (frameType == Constants.H3_GOAWAY) {
                // RFC 9114 Section 7.2.6: GOAWAY frame from client
                // Payload: Push ID (i) - QUIC variable-length integer
                consumePushIdFrame(state, data, (int) frameLength, false);
            } else if (frameType == Constants.H3_MAX_PUSH_ID) {
                // RFC 9114 Section 7.2.7: MAX_PUSH_ID frame
                // Payload: Push ID (i) - QUIC variable-length integer
                consumePushIdFrame(state, data, (int) frameLength, true);
            } else if (frameType == Constants.H3_CANCEL_PUSH) {
                // RFC 9114 Section 7.2.3: CANCEL_PUSH is valid on the
                // control stream from either endpoint, but only for a push
                // ID the peer has promised with a PUSH_PROMISE frame. This
                // server does not implement push and never sends
                // PUSH_PROMISE, so the push ID can never have been promised:
                // receipt MUST be treated as a connection error of type
                // H3_ID_ERROR.
                long pushId = readPushId(data, (int) frameLength, Constants.H3_CANCEL_PUSH);
                if (log.isWarnEnabled()) {
                    log.warn(sm.getString("http3ConnectionManager.cancelPushUnknown",
                            Long.valueOf(pushId)));
                }
                throw new Http3Exception(
                        sm.getString("http3ConnectionManager.cancelPushUnknown",
                                Long.valueOf(pushId)),
                        Http3Error.H3_ID_ERROR);
            } else {
                // PRIORITY_UPDATE frames (RFC 9218 Sections 7 and 7.2) are
                // sent by clients on the control stream only; processing
                // applies or buffers the priority signal for the targeted
                // request stream. The type is known here: unknown types were
                // skipped above and reserved types rejected.
                processPriorityUpdateFrame(state, data, (int) frameLength, frameType);
            }
        }
    }


    /*
     * Whether the frame type is one this server parses on the client
     * control stream (as opposed to an unknown value that must be ignored,
     * RFC 9114 Section 9). The HTTP/2 reserved types and the frames
     * classified by isForbiddenOnClientControlStream() are deliberately not
     * part of this set: they are rejected before this check is reached.
     */
    private static boolean isKnownClientControlFrame(long frameType) {
        return frameType == Constants.H3_SETTINGS ||
                frameType == Constants.H3_CANCEL_PUSH ||
                frameType == Constants.H3_GOAWAY ||
                frameType == Constants.H3_MAX_PUSH_ID ||
                frameType == Constants.H3_PRIORITY_UPDATE_REQUEST ||
                frameType == Constants.H3_PRIORITY_UPDATE_PUSH;
    }


    /*
     * Whether the frame type is a defined HTTP/3 frame whose receipt on
     * the client control stream MUST be treated as a connection error of
     * type H3_FRAME_UNEXPECTED rather than ignored as an unknown value:
     * DATA and HEADERS belong to request (or push) streams (RFC 9114
     * Sections 7.2.1 and 7.2.2) and PUSH_PROMISE is never sent by a client
     * (Section 7.2.5). These types do not appear in
     * Constants.isHttp2ReservedFrame() because they overlap with defined
     * HTTP/3 frames; nothing there re-adds the control-stream rejection.
     */
    private static boolean isForbiddenOnClientControlStream(long frameType) {
        return frameType == Constants.H3_DATA ||
                frameType == Constants.H3_HEADERS ||
                frameType == Constants.H3_PUSH_PROMISE;
    }


    /*
     * Reads the single QUIC variable-length integer (the Push ID) that makes
     * up the payload of the GOAWAY, MAX_PUSH_ID and CANCEL_PUSH frames
     * (RFC 9114 Sections 7.2.3, 7.2.6 and 7.2.7) and advances the buffer
     * past the frame payload. Per RFC 9114 Section 7.1 the payload MUST
     * contain exactly that field: additional bytes after it, or a payload
     * that terminates before the end of the integer, MUST be treated as a
     * connection error of type H3_FRAME_ERROR.
     */
    private long readPushId(ByteBuffer data, int frameLength, long frameType)
            throws Http3Exception {
        int payloadStart = data.position();
        long id = Qpack.decodeQuicInteger(data);
        if (id < 0 || data.position() != payloadStart + frameLength) {
            if (log.isWarnEnabled()) {
                log.warn(sm.getString("http3ConnectionManager.pushIdFrameMalformed",
                        Long.valueOf(frameType), Long.valueOf(frameLength)));
            }
            throw new Http3Exception(
                    sm.getString("http3ConnectionManager.pushIdFrameMalformed",
                            Long.valueOf(frameType), Long.valueOf(frameLength)),
                    Http3Error.H3_FRAME_ERROR);
        }
        return id;
    }


    /*
     * Consumes a payload consisting of a single QUIC variable-length
     * integer (the Push ID) shared by the GOAWAY and MAX_PUSH_ID frames
     * (RFC 9114 Sections 7.2.6 and 7.2.7). When forMaxPushId is set, the
     * value is applied as a MAX_PUSH_ID, rejecting (per Section 7.2.7) a
     * value smaller than one previously received with a connection error of
     * type H3_ID_ERROR. When the payload is a GOAWAY identifier, a value
     * larger than one previously received is rejected with H3_ID_ERROR
     * (Section 5.2: successive GOAWAY identifiers must not increase; a
     * decrease is the normal graceful-shutdown pattern and is accepted).
     */
    private void consumePushIdFrame(ConnectionState state, ByteBuffer data, int frameLength,
            boolean forMaxPushId) throws Http3Exception {
        long id = readPushId(data, frameLength,
                forMaxPushId ? Constants.H3_MAX_PUSH_ID : Constants.H3_GOAWAY);
        if (forMaxPushId) {
            if (state.getMaxPushId() >= 0 && id < state.getMaxPushId()) {
                if (log.isWarnEnabled()) {
                    log.warn(sm.getString("http3ConnectionManager.maxPushIdDecreased",
                            Long.valueOf(id), Long.valueOf(state.getMaxPushId())));
                }
                throw new Http3Exception(
                        sm.getString("http3ConnectionManager.maxPushIdDecreased",
                                Long.valueOf(id), Long.valueOf(state.getMaxPushId())),
                        Http3Error.H3_ID_ERROR);
            }
            state.setMaxPushId(id);
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3Processor.maxPushIdProcessed", Long.valueOf(id)));
            }
        } else {
            if (state.getLastGoawayId() >= 0 && id > state.getLastGoawayId()) {
                if (log.isWarnEnabled()) {
                    log.warn(sm.getString("http3ConnectionManager.goawayIdIncreased",
                            Long.valueOf(id), Long.valueOf(state.getLastGoawayId())));
                }
                throw new Http3Exception(
                        sm.getString("http3ConnectionManager.goawayIdIncreased",
                                Long.valueOf(id), Long.valueOf(state.getLastGoawayId())),
                        Http3Error.H3_ID_ERROR);
            }
            state.setLastGoawayId(id);
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3Processor.goawayReceived", Long.valueOf(id)));
            }
        }
    }


    /*
     * Processes a PRIORITY_UPDATE frame (RFC 9218 Sections 7 and 7.2) from
     * the client control stream. Payload: a Prioritized Element ID (a QUIC
     * variable-length integer) followed by the Priority Field Value (ASCII
     * text, using the same representation as the Priority request header
     * field, RFC 9218 Section 5).
     * <p>
     * Validation applied per RFC 9218 Section 7.2:
     * <ul>
     * <li>The request-stream variant (0xF0700) MUST reference a request
     * stream (a client-initiated bidirectional stream ID, i.e. an ID with
     * (ID % 4) == 0); anything else is a connection error of type
     * H3_ID_ERROR. Note that, unlike HTTP/2 where stream 0 is the
     * connection stream, stream ID 0 is a valid request stream in
     * HTTP/3.</li>
     * <li>An ID beyond the client-initiated bidirectional stream limit
     * only SHOULD be an H3_ID_ERROR, and correctly evaluating the limit
     * requires knowledge of the transport-level stream window. The ID is
     * therefore not range-checked here; the pending-update buffer is
     * bounded independently (see ConnectionState.applyPriorityUpdate).</li>
     * <li>The push-stream variant (0xF0701) MUST reference a promised push
     * stream. This implementation does not implement push and never sends
     * PUSH_PROMISE, so receipt is always a connection error of type
     * H3_ID_ERROR (the same reasoning as CANCEL_PUSH).</li>
     * <li>An unparsable Priority Field Value is ignored: RFC 9218 Section 7
     * only permits (MAY) a connection error for it, RFC 9218 Section 4
     * requires invalid priority parameters to be ignored, and this matches
     * the HTTP/2 behavior in Http2Parser.readPriorityUpdateFrame.</li>
     * </ul>
     */
    private void processPriorityUpdateFrame(ConnectionState state, ByteBuffer data,
            int frameLength, long frameType) throws Http3Exception {
        // A failed decode consumes bytes; the elementId check below maps
        // it to the mandated H3_FRAME_ERROR before those bytes are used.
        int varintStart = data.position();
        long elementId = Qpack.decodeQuicInteger(data);
        int varintLength = data.position() - varintStart;

        // Per RFC 9114 Section 7.1, a frame payload that does not match the
        // frame definition (here: a Prioritized Element ID that is incomplete
        // or does not fit in the declared frame length) is a connection error
        // of type H3_FRAME_ERROR (the same treatment as the Push ID payload
        // of GOAWAY/MAX_PUSH_ID/CANCEL_PUSH in readPushId()).
        if (elementId < 0 || varintLength > frameLength) {
            if (log.isWarnEnabled()) {
                log.warn(sm.getString("http3ConnectionManager.priorityUpdateFrameMalformed",
                        Long.valueOf(frameType)));
            }
            throw new Http3Exception(
                    sm.getString("http3ConnectionManager.priorityUpdateFrameMalformed",
                            Long.valueOf(frameType)),
                    Http3Error.H3_FRAME_ERROR);
        }

        if (frameType == Constants.H3_PRIORITY_UPDATE_PUSH) {
            // Push-stream variant: nothing can have been promised - reject
            // with H3_ID_ERROR (RFC 9218 Section 7.2).
            if (log.isWarnEnabled()) {
                log.warn(sm.getString("http3ConnectionManager.priorityUpdateNoPushPromise",
                        Long.valueOf(elementId)));
            }
            throw new Http3Exception(
                    sm.getString("http3ConnectionManager.priorityUpdateNoPushPromise",
                            Long.valueOf(elementId)),
                    Http3Error.H3_ID_ERROR);
        }

        // Request-stream variant (0xF0700): the element ID must be a
        // client-initiated bidirectional stream ID or it is a connection
        // error of type H3_ID_ERROR (RFC 9218 Section 7.2).
        if ((elementId & 3) != 0) {
            if (log.isWarnEnabled()) {
                log.warn(sm.getString("http3ConnectionManager.priorityUpdateRejectedElementId",
                        Long.valueOf(elementId)));
            }
            throw new Http3Exception(
                    sm.getString("http3ConnectionManager.priorityUpdateRejectedElementId",
                            Long.valueOf(elementId)),
                    Http3Error.H3_ID_ERROR);
        }

        // Parse the Priority Field Value. An unparsable value is ignored
        // (RFC 9218 Section 7 MAY-level, Section 4 "MUST be ignored").
        Priority priority = null;
        int fieldValueLength = frameLength - varintLength;
        if (fieldValueLength > 0) {
            byte[] fieldBytes = new byte[fieldValueLength];
            ByteBuffer fieldData = data.duplicate();
            fieldData.limit(fieldData.position() + fieldValueLength);
            fieldData.get(fieldBytes);
            try {
                priority = Priority.parsePriority(new StringReader(
                        new String(fieldBytes, StandardCharsets.US_ASCII)));
            } catch (IOException ioe) {
                // Not possible with StringReader
            } catch (IllegalArgumentException iae) {
                if (log.isTraceEnabled()) {
                    log.trace(sm.getString("http3ConnectionManager.priorityUpdateIgnoredValue",
                            Long.valueOf(elementId), new String(fieldBytes,
                                    StandardCharsets.US_ASCII)), iae);
                }
            }
        }

        if (priority != null) {
            state.applyPriorityUpdate(elementId, priority);
        }

        // Advance past the remainder of the frame payload: the field value
        // was read from a duplicate view, the control-stream loop continues
        // with the next frame at the end of this one.
        data.position(varintStart + frameLength);
    }


    /*
     * A single QPACK instruction handler (encoder or decoder stream).
     */
    private interface QpackInstructionHandler {
        void process(ByteBuffer data) throws QpackException;
    }


    /**
     * Processes the client QPACK encoder stream (stream type 0x02).
     * Per RFC 9204 Section 4.2, the encoder stream carries encoder
     * instructions from encoder to decoder. The stream type varint has
     * already been read by {@link #processClientUniStreamData}.
     */
    private void processQpackEncoderStream(long streamId, ByteBuffer data)
            throws Http3Exception {
        // Process QPACK encoder instructions on the shared decoder
        // (encoder stream -> decoder, per RFC 9204 Section 4.2)
        processQpackInstructions(streamId, data,
                sharedDecoder::processInstruction,
                Http3Error.H3_QPACK_ENCODER_STREAM_ERROR);
    }


    /**
     * Processes the client QPACK decoder stream (stream type 0x03).
     * Per RFC 9204 Section 4.2, the decoder stream carries decoder
     * instructions from decoder to encoder. The stream type varint has
     * already been read by {@link #processClientUniStreamData}.
     */
    private void processQpackDecoderStream(ConnectionState state, long streamId,
            ByteBuffer data) throws Http3Exception {
        // Process QPACK decoder instructions: Section Acknowledgment,
        // Stream Cancellation, Insert Count Increment (RFC 9204 Section 4.4)
        processQpackInstructions(streamId, data,
                this::processDecoderInstruction,
                Http3Error.H3_QPACK_DECODER_STREAM_ERROR);
    }


    /*
     * Consumes whole QPACK instructions from the buffer until it is
     * exhausted or an instruction is incomplete (the handler rewinds the
     * buffer, so the partial bytes are retained for the next read). A
     * failure to interpret an instruction is a connection error whose type
     * depends on the stream the instructions arrived on (RFC 9204
     * Section 6).
     */
    private void processQpackInstructions(long streamId, ByteBuffer data,
            QpackInstructionHandler handler, Http3Error streamError)
            throws Http3Exception {
        while (data.hasRemaining()) {
            int posBefore = data.position();
            try {
                handler.process(data);
            } catch (QpackException e) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http3ConnectionManager.qpackError"), e);
                }
                throw new Http3Exception(
                        sm.getString("http3ConnectionManager.qpackError"), streamError, e);
            }
            if (data.position() == posBefore) {
                // Incomplete instruction: the handler rewound the buffer
                // waiting for more data. Retain it for the next read,
                // unless the retained bytes already fill the stream read
                // buffer: the buffer is the entire retention window, so the
                // instruction can never complete and must fail the
                // connection instead of stalling the stream forever.
                // (Instructions whose declared lengths are individually
                // bounded - see QpackDecoder.encodedLiteralBudget() -
                // always fit a default-sized buffer; this catches a
                // reduced readBufferSize and any instruction form the
                // handler rewinds without a length check.)
                if (data.limit() - data.position() >= data.capacity()) {
                    throw partialDataTooLarge(streamId);
                }
                break;
            }
        }
    }


    /**
     * Processes a single decoder instruction from the client QPACK
     * decoder stream (RFC 9204 Section 4.4). There are three forms:
     * <ul>
     * <li>Section Acknowledgment: 1 + iRP(m=7) stream ID (4.4.1)</li>
     * <li>Stream Cancellation: 01 + iRP(m=6) stream ID (4.4.2)</li>
     * <li>Insert Count Increment: 00 + iRP(m=6) increment (4.4.3)</li>
     * </ul>
     * This server's encoder never inserts into the dynamic table, so no
     * field section it emits references dynamic table entries: no Section
     * Acknowledgment can be associated with a field section (a connection
     * error of type QPACK_DECODER_STREAM_ERROR, RFC 9204 Section 4.4.1)
     * and no Insert Count Increment can be associated with insertions
     * (likewise QPACK_DECODER_STREAM_ERROR, RFC 9204 Section 4.4.3 - the
     * zero increment case is explicitly required there). Stream
     * Cancellation is advisory and has no effect here.
     * When the instruction is incomplete (spanning reads), the buffer
     * is rewound to its position before the instruction so the caller
     * observes no progress and retains the bytes for the next read.
     */
    private void processDecoderInstruction(ByteBuffer buffer) throws QpackException {
        if (buffer.remaining() < 1) {
            return;
        }

        int start = buffer.position();
        int firstByte = buffer.get() & 0xFF;

        boolean isSectionAck = (firstByte & 0x80) != 0;
        long value = Qpack.decodeIrp(buffer, isSectionAck ? 7 : 6, firstByte);
        if (value < 0) {
            // Incomplete instruction: rewind so the caller retains
            // the bytes for the next read.
            buffer.position(start);
            return;
        }

        if (isSectionAck) {
            // Section Acknowledgment (RFC 9204 Section 4.4.1): it cannot
            // be associated with any field section this server emitted
            // (none reference the dynamic table), which the RFC requires
            // to be treated as a connection error of type
            // QPACK_DECODER_STREAM_ERROR.
            throw new QpackException(sm.getString(
                    "http3ConnectionManager.qpackSectionAckUnexpected",
                    Long.valueOf(value)));
        }

        if ((firstByte & 0xC0) == 0x40) {
            // Stream Cancellation (RFC 9204 Section 4.4.2): advisory. No
            // stream can be blocked on this server's encoder output, so
            // the instruction has no state to release and is consumed.
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3ConnectionManager.qpackStreamCancellation",
                        Long.valueOf(value)));
            }
            return;
        }

        // Insert Count Increment (RFC 9204 Section 4.4.3): the increment
        // references insertions on this server's encoder stream that never
        // happened (the encoder does not use the dynamic table) and cannot
        // be associated; a zero increment is explicitly required to be a
        // connection error of type QPACK_DECODER_STREAM_ERROR.
        throw new QpackException(
                sm.getString("http3ConnectionManager.qpackInsertCountIncrementUnexpected",
                        Long.valueOf(value)));
    }


    /**
     * Gets the connection state for a connection.
     *
     * @param connection The QUIC connection for which the state is required
     *
     * @return The connection state for the given connection
     */
    @Override
    public ConnectionState getState(QuicConnection connection) {
        return connections.get(connection);
    }


    /**
     * Returns the shared QPACK decoder for this connection.
     * Per RFC 9204, all streams share a single decoder with a unified dynamic table.
     *
     * @return The shared QPACK decoder for this connection
     */
    public QpackDecoder getSharedDecoder() {
        return sharedDecoder;
    }


    /**
     * Notes that a Section Acknowledgment instruction must be emitted for a
     * field section that was decoded on the given stream using
     * representations containing dynamic table references
     * (RFC 9204 Section 2.2.2.1). The instruction is written to the server
     * QPACK decoder stream by the next flush
     * ({@link #flushPendingDecoderInstructions}).
     *
     * @param connection The QUIC connection
     * @param streamId The stream ID the field section was received on
     *
     * @return {@code true} if the instruction was queued, {@code false} if
     *         the per-connection limit of pending decoder instructions was
     *         reached (the caller MUST fail the connection)
     */
    public boolean noteSectionAcknowledgment(QuicConnection connection, long streamId) {
        ConnectionState state = connections.get(connection);
        if (state != null) {
            boolean queued = state.noteSectionAcknowledgment(streamId);
            if (queued) {
                connection.setProtocolDataPending(true);
            }
            return queued;
        }
        return true;
    }


    /**
     * Notes that a Stream Cancellation instruction must be emitted for the
     * given stream because it was reset or abandoned before all of its
     * encoded field sections were processed (RFC 9204 Section 2.2.2.2).
     * The instruction is written to the server QPACK decoder stream by the
     * next flush ({@link #flushPendingDecoderInstructions}).
     *
     * @param connection The QUIC connection
     * @param streamId The stream ID of the abandoned stream
     *
     * @return {@code true} if the instruction was queued, {@code false} if
     *         the per-connection limit of pending decoder instructions was
     *         reached (the caller MUST fail the connection)
     */
    public boolean noteStreamCancellation(QuicConnection connection, long streamId) {
        ConnectionState state = connections.get(connection);
        if (state != null) {
            boolean queued = state.noteStreamCancellation(streamId);
            if (queued) {
                connection.setProtocolDataPending(true);
            }
            return queued;
        }
        return true;
    }


    /**
     * {@inheritDoc}
     * <p>
     * For HTTP/3 a stream the transport rejected at accept time was
     * abandoned before any of its field sections was processed, so the
     * peer's encoder is owed a Stream Cancellation for any dynamic table
     * entries the section it carried referenced (RFC 9204 Section 2.2.2.2).
     */
    @Override
    public void noteStreamRejected(QuicConnection connection, long streamId) {
        if (!noteStreamCancellation(connection, streamId)) {
            if (log.isWarnEnabled()) {
                log.warn(sm.getString(
                        "http3ConnectionManager.pendingDecoderInstructionsFull",
                        Integer.valueOf(MAX_PENDING_DECODER_INSTRUCTIONS)));
            }
            // Same treatment as the processor-side noteDecoderInstruction:
            // the backlog means the peer never drains the QPACK decoder
            // stream, which must not be able to grow state without bound.
            connection.failConnection(Http3Error.H3_EXCESSIVE_LOAD.getCode(),
                    "HTTP/3 QPACK decoder instruction backlog");
        }
    }


    /**
     * Reserves one of the connection's slots for a request stream blocked
     * waiting for QPACK encoder stream inserts (RFC 9204 Section 2.1.2).
     *
     * @param connection The QUIC connection
     * @param limit      The per-connection limit on concurrently blocked
     *                   streams
     *
     * @return {@code true} if a slot was reserved; {@code false} if the
     *         limit (or the connection's absence) prevents blocking, in
     *         which case the caller MUST treat the field section as a
     *         decompression failure
     */
    public boolean acquireBlockedStreamSlot(QuicConnection connection, int limit) {
        ConnectionState state = connections.get(connection);
        if (state == null) {
            return false;
        }
        return state.acquireBlockedStreamSlot(limit);
    }


    /**
     * Releases a blocked-stream slot reserved by
     * {@link #acquireBlockedStreamSlot}.
     *
     * @param connection The QUIC connection
     */
    public void releaseBlockedStreamSlot(QuicConnection connection) {
        ConnectionState state = connections.get(connection);
        if (state != null) {
            state.releaseBlockedStreamSlot();
        }
    }


    /**
     * Emits the pending decoder instructions (Section Acknowledgment,
     * Stream Cancellation, Insert Count Increment) on the server QPACK
     * decoder stream (RFC 9204 Section 4.4). Any encoder instructions
     * received on the client QPACK encoder stream since the last flush are
     * acknowledged with an Insert Count Increment (Section 2.2.2.3).
     * <p>
     * Must be called on the QUIC poll thread: it writes to the native
     * QPACK decoder stream. The {@code note*} methods that queue
     * instructions may be called from any thread. Internal to this class: the
     * endpoint reaches it through the {@link #flushPendingProtocolData} guard.
     *
     * @param connection The QUIC connection
     */
    private void flushPendingDecoderInstructions(QuicConnection connection) {
        ConnectionState state = connections.get(connection);
        if (state == null) {
            return;
        }
        synchronized (state) {
            // Serialize anything newly pending into the byte queue first.
            // From the moment a batch is serialized, its bytes (queue, then
            // wire) are the instructions' only representation: the ID sets
            // and the insert-count watermark are consumed by the
            // serialization, so a write the transport accepts only as a
            // prefix leaves exactly the unsent suffix queued. Rebuilding a
            // retry from the ID sets would re-emit bytes already in flight.
            long totalInserts = sharedDecoder.getTotalInserts();
            long insertDelta = totalInserts - state.lastReportedInserts;
            int pendingCount = state.pendingSectionAcks.size()
                    + state.pendingCancellations.size();
            if (insertDelta > 0 || pendingCount > 0) {
                // Build the instruction bytes:
                // Section Acknowledgment (4.4.1): 1 + iRP(m=7) stream ID
                // Stream Cancellation (4.4.2): 01 + iRP(m=6) stream ID
                // Insert Count Increment (4.4.3): 00 + iRP(m=6) increment
                // Each iRP-encoded value occupies at most
                // Qpack.MAX_IRP_ENCODED_LENGTH bytes (the +1 accounts for the
                // Insert Count Increment; a 9-byte per-value bound would
                // overflow for a value whose iRP encoding is 10 bytes, and
                // the resulting BufferOverflowException on the poll thread
                // would poison every later flush of this connection).
                ByteBuffer instructions = ByteBuffer.allocate(
                        32 + Qpack.MAX_IRP_ENCODED_LENGTH * (pendingCount + 1));
                for (long streamId : state.pendingSectionAcks) {
                    // Section Acknowledgment (4.4.1): 1 + iRP(m=7) stream ID
                    Qpack.encodeIrp(instructions, 0x80, 7, streamId);
                }
                for (long streamId : state.pendingCancellations) {
                    // Stream Cancellation (4.4.2): 01 + iRP(m=6) stream ID
                    Qpack.encodeIrp(instructions, 0x40, 6, streamId);
                }
                if (insertDelta > 0) {
                    // Insert Count Increment (4.4.3): 00 + iRP(m=6) increment
                    Qpack.encodeIrp(instructions, 0x00, 6, insertDelta);
                }
                instructions.flip();
                int serialized = pendingCount + (insertDelta > 0 ? 1 : 0);
                state.unsentInstructions.addLast(
                        new ConnectionState.InstructionChunk(instructions, serialized));
                state.unsentInstructionCount += serialized;
                state.lastReportedInserts = totalInserts;
                state.pendingSectionAcks.clear();
                state.pendingCancellations.clear();
            }
            if (state.unsentInstructions.isEmpty()) {
                // Nothing pending, so the transport's sweep no longer needs
                // to visit this connection. Clearing under the state lock
                // cannot drop a concurrent mark: any thread that queues
                // sets the mark after it queues, and the queueing happens
                // under this same lock.
                connection.setProtocolDataPending(false);
                return;
            }
            QuicStream decoderStream = state.serverQpackDecoderStream;
            if (decoderStream == null) {
                // The server QPACK decoder stream does not exist yet; the
                // instructions are flushed on a later call.
                return;
            }
            ByteBuffer pendingInit = decoderStream.getWriteBuffer();
            if (pendingInit != null && pendingInit.hasRemaining()) {
                // The stream type byte has not reached the peer yet (the
                // endpoint is retrying the init write); writing instructions
                // before it would corrupt the stream. The flush is retried
                // on a later call once the init bytes are out.
                return;
            }

            // Drain the queue in wire order. A partial accept keeps the head
            // chunk queued with its position advanced past the accepted
            // prefix, so the next attempt re-presents exactly the bytes that
            // are still unsent.
            while (!state.unsentInstructions.isEmpty()) {
                ConnectionState.InstructionChunk chunk = state.unsentInstructions.peekFirst();
                connection.writeToStream(decoderStream, chunk.buffer());
                if (chunk.buffer().hasRemaining()) {
                    break;
                }
                state.unsentInstructions.pollFirst();
                state.unsentInstructionCount -= chunk.instructionCount();
            }
            if (state.unsentInstructions.isEmpty()) {
                // Nothing (further) pending: drop the transport's sweep mark
                // (same lock-based reasoning as the early return above).
                connection.setProtocolDataPending(false);
            } else if (log.isDebugEnabled()) {
                log.debug("Deferred QPACK decoder instruction flush");
            }
        }
    }


    /**
     * {@inheritDoc}
     * <p>
     * For HTTP/3 this emits the pending QPACK decoder instructions, if any,
     * for the given connection. Called periodically from the QUIC poll
     * thread so that Section Acknowledgment, Stream Cancellation and Insert
     * Count Increment instructions reach the peer without having to wait
     * for the next client unidirectional stream read (RFC 9204 Sections
     * 2.2.2.1, 2.2.2.2, 2.2.2.3).
     *
     * @param connection The QUIC connection
     */
    @Override
    public void flushPendingProtocolData(QuicConnection connection) {
        ConnectionState state = connections.get(connection);
        if (state == null) {
            return;
        }
        // Deliberately not clearing the transport's pending mark here even
        // when nothing is pending: that check runs outside the state lock,
        // and a clear could overwrite a mark set by a thread that queued
        // after the check. The (poll-thread) flush clears the mark inside
        // the state lock below.
        flushPendingDecoderInstructions(connection);
    }


    /*
     * A retained partial (uni-stream type varint, control-stream frame
     * header or QPACK instruction) that cannot complete from the stream
     * read buffer - which is the entire retention window - never will:
     * resolve the message, log it at warn level and return the connection
     * error of type H3_EXCESSIVE_LOAD, so callers can use
     * {@code throw partialDataTooLarge(streamId)} instead of stalling the
     * stream.
     */
    private Http3Exception partialDataTooLarge(long streamId) {
        String message = sm.getString(
                "http3ConnectionManager.partialDataTooLarge",
                Long.valueOf(streamId));
        if (log.isWarnEnabled()) {
            log.warn(message);
        }
        return new Http3Exception(message, Http3Error.H3_EXCESSIVE_LOAD);
    }


    /**
     * {@inheritDoc}
     * <p>
     * Returns the HTTP/3 connection error code carried by the given
     * throwable, or 0 if it does not carry one. Used to propagate the
     * error code into the QUIC CONNECTION_CLOSE frame (RFC 9114 Section 8).
     *
     * @param t The throwable
     * @return The HTTP/3 error code, or 0
     */
    @Override
    public long getProtocolErrorCode(Throwable t) {
        return (t instanceof Http3Exception e) ? e.getError().getCode() : 0L;
    }


    /**
     * Per-connection HTTP/3 state.
     */
    public static class ConnectionState implements QuicConnectionManager.ConnectionState {
        private final QuicConnection connection;
        private boolean clientSettingsReceived;
        private long maxPushId = -1;
        private long lastGoawayId = -1;
        // Volatile because it is written on the QUIC poll thread (when the
        // client's SETTINGS are processed) and read by executor worker
        // threads (the response field section limit in Http3Processor).
        private volatile long peerMaxFieldSectionSize = 0;
        private int activeStreamCount = 0;
        // Volatile because it is updated on the QUIC poll thread (transport
        // stream limit reconciliation) after the state has been published
        // via the connection map, and may be read through the public
        // accessor outside the poll thread.
        private volatile long maxConcurrentStreams = 100; // Default per RFC 9114
        private long lastProcessedStreamId = -1;
        // Identifier carried by the most recent GOAWAY sent on this
        // connection, or -1 if none was sent. Successive identifiers MUST
        // NOT be greater than any previously sent one (RFC 9114
        // Section 5.2). Written and read on the QUIC poll thread (the
        // stream-limit notification); the endpoint shutdown notification
        // uses the same field after the poll loop has stopped and the poll
        // tasks have been drained, so it runs with the poll thread as the
        // only other caller serialized behind the drain.
        private long lastSentGoawayId = -1;

        // Client unidirectional streams, keyed by stream ID. Stream IDs are
        // assigned in creation order (RFC 9000 Section 2.1), so the IDs of
        // the client's control/QPACK streams are not known in advance; they
        // are identified by the stream type read from the start of each
        // stream (RFC 9114 Section 6.2.1, RFC 9204 Section 4.2).
        // Volatile because the QUIC poll thread both writes and reads them
        // through the protocol code today (both in-tree endpoints call
        // processClientUniStreamData() and checkClientUniStreamClosed()
        // inline on the poll thread), but the protocol layer makes no
        // assumption about that: an endpoint is free to dispatch this work
        // to its own threads, and these fields carry no synchronization of
        // their own. The volatile makes the cross-thread visibility
        // structural rather than an incident of the current endpoint
        // wiring (a missed write here would skip the
        // H3_CLOSED_CRITICAL_STREAM connection error), and keeps the longs
        // non-torn on 32-bit JVMs, as for the fields below.
        private volatile long clientControlStreamId = -1;
        private volatile long clientQpackEncoderStreamId = -1;
        private volatile long clientQpackDecoderStreamId = -1;
        private boolean clientControlFirstFrameSeen = false;
        // Remaining bytes of an unknown control-stream frame's payload that
        // are being skipped without being retained (RFC 9114 Section 9).
        // Written and read only by the QUIC poll thread, which runs
        // processClientUniStreamData() inline (see the
        // QuicConnectionManager.processClientUniStreamData contract), so no
        // confinement note beyond that is needed; the count is bounded by
        // the frame's declared length and cleared as its payload is
        // consumed.
        private long controlFrameSkipRemaining;
        // IDs of client-initiated unidirectional streams whose type was
        // unknown, so subsequent data on them is consumed without being
        // re-parsed as a stream type (RFC 9114 Section 9). Entries are
        // removed when the stream closes or is reset
        // (clientUniStreamClosed(), called by the QUIC endpoint on the poll
        // thread), bounding the set by the number of concurrently open
        // client unidirectional streams rather than the connection lifetime;
        // stream IDs are never reused (RFC 9000 Section 2.1), so a pruned ID
        // is never seen again.
        // Entries are added/checked and pruned on the QUIC poll thread:
        // processClientUniStreamData runs inline on it (see the
        // QuicConnectionManager.processClientUniStreamData contract) and
        // the endpoints invoke clientUniStreamClosed on the same thread
        // (clientUniStreamClosed via deregisterAndReleaseStream; a worker
        // thread closing a wrapper hops the cleanup to the poll thread
        // first). The concurrent set is retained as cheap insurance so a
        // future teardown path that prunes from another thread cannot
        // corrupt a plain HashSet's add/remove.
        private final Set<Long> discardedUniStreamIds = ConcurrentHashMap.newKeySet();

        // Server unidirectional streams, as reported by
        // serverUniStreamCreated(). The flags drive
        // nextServerUniStream(); the QPACK decoder stream handle is needed
        // to write decoder instructions from the QUIC poll thread.
        private volatile boolean serverControlStreamCreated = false;
        private volatile boolean serverQpackEncoderStreamCreated = false;
        private volatile boolean serverQpackDecoderStreamCreated = false;
        private volatile QuicStream serverQpackDecoderStream = null;

        // Pending decoder instructions to be emitted on the server QPACK
        // decoder stream (RFC 9204 Section 4.4). Accessed under the
        // ConnectionState monitor (worker threads note instructions, the
        // poll thread flushes them).
        private final List<Long> pendingSectionAcks = new ArrayList<>();
        private final Set<Long> pendingCancellations = new HashSet<>();
        private volatile long lastReportedInserts = 0;
        // Serialized decoder instructions whose bytes have not fully reached
        // the transport yet (FIFO, wire order). Once a batch is serialized
        // the ID sets above are consumed and the queue is the byte-exact
        // source of truth: a partially accepted write leaves exactly the
        // unsent suffix at the head chunk. Mutated only on the QUIC poll
        // thread, under the ConnectionState monitor (the same monitor the
        // note* methods take to grow the ID sets and check the pending cap,
        // which counts the queued instructions via unsentInstructionCount).
        private final ArrayDeque<InstructionChunk> unsentInstructions = new ArrayDeque<>();
        private int unsentInstructionCount = 0;

        // One serialized batch of decoder instructions, with the number of
        // instructions it encodes (for the pending cap accounting).
        private record InstructionChunk(ByteBuffer buffer, int instructionCount) {
        }

        // Number of request streams currently blocked on this connection
        // waiting for dynamic table inserts (RFC 9204 Section 2.1.2).
        // Accessed under the ConnectionState monitor.
        private int blockedStreams = 0;

        /*
         * RFC 9218 (Sections 6 and 7) priority signal routing. Client
         * PRIORITY_UPDATE frames arrive on the control stream, which is
         * processed by Http3ConnectionManager, but they target request
         * streams that are handled by Http3Processor instances on other
         * threads, and they may legitimately reference streams that have
         * not been opened yet.
         * <p>
         * {@link #priorityConsumers} maps an open request stream ID to the
         * processor instance handling it (registered when the processor is
         * wired to this connection, unregistered when the processor is
         * recycled); QUIC stream IDs are never reused, so no stale entry
         * can be applied to a different stream.
         * <p>
         * {@link #pendingPriorityUpdates} holds the most recently received
         * PRIORITY_UPDATE for each element ID that has no registered
         * consumer yet ("Servers SHOULD buffer the most recently received
         * PRIORITY_UPDATE frame and apply it once the referenced stream is
         * opened", RFC 9218 Section 7), bounded to local policy (see
         * {@link #applyPriorityUpdate}).
         * <p>
         * Both maps are guarded by, and priority application happens
         * under, {@link #priorityLock} so that the "most recently received
         * PRIORITY_UPDATE ... overrides any other signal" rule (RFC 9218
         * Section 7) holds regardless of how frame arrival and processor
         * registration interleave.
         */
        private final Object priorityLock = new Object();
        private final Map<Long, Http3Processor> priorityConsumers = new HashMap<>();
        private final Map<Long, Priority> pendingPriorityUpdates = new LinkedHashMap<>();


        ConnectionState(QuicConnection connection) {
            this.connection = connection;
        }


        /**
         * Reserves one of this connection's blocked-stream slots if the
         * per-connection limit has not been reached.
         *
         * @param limit The maximum number of concurrently blocked streams
         *
         * @return {@code true} if a slot was reserved
         */
        public boolean acquireBlockedStreamSlot(int limit) {
            synchronized (this) {
                if (blockedStreams >= limit) {
                    return false;
                }
                blockedStreams++;
                return true;
            }
        }


        /**
         * Releases a previously reserved blocked-stream slot.
         */
        public void releaseBlockedStreamSlot() {
            synchronized (this) {
                blockedStreams--;
            }
        }


        /**
         * Registers a request-stream processor as the target of priority
         * signals for the given stream ID (RFC 9218 Section 7) and applies
         * the PRIORITY_UPDATE buffered for it, if any, from the point at
         * which the frame arrived before the stream opened. Called when the
         * processor is wired to the connection, before any request-stream
         * frames are processed. The buffered frame is the most recently
         * received signal, so it wins over the request's own (older)
         * Priority header field, which is consumed but does not supersede
         * it (RFC 9218 Section 7; see
         * {@link Http3Processor#setPriority(Priority)}). Later
         * PRIORITY_UPDATE frames for the stream are applied directly to the
         * registered processor.
         */
        void registerPriorityConsumer(Http3Processor processor, long streamId) {
            Long key = Long.valueOf(streamId);
            synchronized (priorityLock) {
                priorityConsumers.put(key, processor);
                Priority buffered = pendingPriorityUpdates.remove(key);
                if (buffered != null) {
                    processor.setPriority(buffered);
                }
            }
        }


        /**
         * Removes the request-stream processor of an already closed stream
         * from the priority consumer registry. PRIORITY_UPDATE frames that
         * still reference the stream are buffered instead (and evicted by
         * the {@link #applyPriorityUpdate} bounds); this is harmless since
         * QUIC stream IDs are never reused.
         */
        void unregisterPriorityConsumer(Http3Processor processor, long streamId) {
            synchronized (priorityLock) {
                priorityConsumers.remove(Long.valueOf(streamId), processor);
            }
        }


        /**
         * Applies a validated PRIORITY_UPDATE (RFC 9218 Sections 7 and
         * 7.2). If the referenced request stream is open, the signal is
         * applied to its processor; otherwise the signal is buffered,
         * replacing any previous signal for the same element ("the most
         * recently received PRIORITY_UPDATE ... overrides any other
         * signal", RFC 9218 Section 7), so that it is applied when the
         * stream opens.
         * <p>
         * The buffer is bounded by local implementation policy (RFC 9218
         * Section 7): only the most recent signal per element is kept and
         * the total number of buffered elements is limited to the
         * connection's concurrent-stream limit (with a floor of 16), the
         * oldest entries being evicted first.
         *
         * @param prioritizedElementId The target request-stream ID
         * @param priority The parsed priority signal
         */
        void applyPriorityUpdate(long prioritizedElementId, Priority priority) {
            Long key = Long.valueOf(prioritizedElementId);
            synchronized (priorityLock) {
                Http3Processor consumer = priorityConsumers.get(key);
                if (consumer != null) {
                    consumer.setPriority(priority);
                } else {
                    pendingPriorityUpdates.put(key, priority);
                    int maxPending = Math.max(16,
                            (int) Math.min(Integer.MAX_VALUE, maxConcurrentStreams));
                    if (pendingPriorityUpdates.size() > maxPending) {
                        Iterator<Long> eldest = pendingPriorityUpdates.keySet().iterator();
                        eldest.next();
                        eldest.remove();
                    }
                }
                if (log.isDebugEnabled()) {
                    if (consumer != null) {
                        log.debug(sm.getString("http3ConnectionManager.priorityUpdateApplied",
                                Long.valueOf(prioritizedElementId),
                                Integer.valueOf(priority.getUrgency()),
                                Boolean.valueOf(priority.getIncremental())));
                    } else {
                        log.debug(sm.getString("http3ConnectionManager.priorityUpdateBuffered",
                                Long.valueOf(prioritizedElementId),
                                Integer.valueOf(priority.getUrgency()),
                                Boolean.valueOf(priority.getIncremental())));
                    }
                }
            }
        }


        @Override
        public QuicConnection getConnection() {
            return connection;
        }


        /**
         * Returns the stream type of the given client unidirectional stream
         * once it has been identified, or -1 if not yet identified.
         *
         * @param streamId The identifier of the client unidirectional stream
         *
         * @return The stream type of the given client unidirectional stream,
         *         or -1 if it has not yet been identified
         */
        public long getClientUniStreamType(long streamId) {
            if (streamId == clientControlStreamId) {
                return Constants.H3_STREAM_TYPE_CONTROL;
            }
            if (streamId == clientQpackEncoderStreamId) {
                return Constants.H3_STREAM_TYPE_QPACK_ENCODER;
            }
            if (streamId == clientQpackDecoderStreamId) {
                return Constants.H3_STREAM_TYPE_QPACK_DECODER;
            }
            return -1;
        }


        public boolean isClientControlStreamOpen() {
            return clientControlStreamId >= 0;
        }


        public void setClientControlStreamId(long streamId) {
            this.clientControlStreamId = streamId;
        }


        public boolean isClientQpackEncoderStreamOpen() {
            return clientQpackEncoderStreamId >= 0;
        }


        public void setClientQpackEncoderStreamId(long streamId) {
            this.clientQpackEncoderStreamId = streamId;
        }


        public boolean isClientQpackDecoderStreamOpen() {
            return clientQpackDecoderStreamId >= 0;
        }


        public void setClientQpackDecoderStreamId(long streamId) {
            this.clientQpackDecoderStreamId = streamId;
        }


        public void markUniStreamDiscarded(long streamId) {
            discardedUniStreamIds.add(streamId);
        }


        public boolean isUniStreamDiscarded(long streamId) {
            return discardedUniStreamIds.contains(streamId);
        }


        @Override
        public void clientUniStreamClosed(long streamId) {
            // Release the read-and-discard state of an unknown-type stream
            // once the stream itself is gone (RFC 9114 Section 9); harmless
            // for IDs never marked (close/reset of an identified stream).
            discardedUniStreamIds.remove(Long.valueOf(streamId));
        }


        /**
         * Notes that a Section Acknowledgment instruction must be emitted
         * for a field section decoded on the given stream
         * (RFC 9204 Section 2.2.2.1).
         *
         * @param streamId The identifier of the stream whose field section
         *            was acknowledged
         *
         * @return {@code true} if the instruction was queued, {@code false}
         *         if the per-connection limit of pending decoder
         *         instructions was reached
         */
        public boolean noteSectionAcknowledgment(long streamId) {
            return noteDecoderInstruction(pendingSectionAcks, streamId);
        }


        /**
         * Notes that a Stream Cancellation instruction must be emitted for
         * the given stream (RFC 9204 Section 2.2.2.2).
         *
         * @param streamId The identifier of the cancelled stream
         *
         * @return {@code true} if the instruction was queued, {@code false}
         *         if the per-connection limit of pending decoder
         *         instructions was reached
         */
        public boolean noteStreamCancellation(long streamId) {
            return noteDecoderInstruction(pendingCancellations, streamId);
        }


        /*
         * Queues one decoder instruction (Section Acknowledgment or
         * Stream Cancellation) for the next flush, subject to the
         * per-connection pending limit.
         */
        private boolean noteDecoderInstruction(Collection<Long> queue, long streamId) {
            synchronized (this) {
                // The cap covers everything not yet delivered to the
                // transport: the ID sets plus the instructions already
                // serialized into the unsent byte queue.
                if (pendingSectionAcks.size() + pendingCancellations.size()
                        + unsentInstructionCount >= MAX_PENDING_DECODER_INSTRUCTIONS) {
                    return false;
                }
                queue.add(streamId);
            }
            return true;
        }


        @Override
        public boolean isClientSettingsReceived() {
            return clientSettingsReceived;
        }


        public long getMaxPushId() {
            return maxPushId;
        }


        public void setMaxPushId(long maxPushId) {
            this.maxPushId = maxPushId;
        }


        /**
         * Returns the peer's advertised SETTINGS_MAX_FIELD_SECTION_SIZE
         * (RFC 9114 Section 4.2.2).
         *
         * @return The peer's maximum field section size, or {@code 0} if the
         *         peer did not declare a limit
         */
        public long getPeerMaxFieldSectionSize() {
            return peerMaxFieldSectionSize;
        }


        public void setPeerMaxFieldSectionSize(long peerMaxFieldSectionSize) {
            this.peerMaxFieldSectionSize = peerMaxFieldSectionSize;
        }


        public long getLastGoawayId() {
            return lastGoawayId;
        }


        public void setLastGoawayId(long lastGoawayId) {
            this.lastGoawayId = lastGoawayId;
        }


        /**
         * Increments the active stream count.
         * Called when a new bidirectional stream is accepted.
         */
        @Override
        public void incrementActiveStreams() {
            activeStreamCount++;
        }


        /**
         * Decrements the active stream count.
         * Called when a bidirectional stream is closed.
         */
        @Override
        public void decrementActiveStreams() {
            activeStreamCount--;
            if (activeStreamCount < 0) {
                activeStreamCount = 0;
            }
        }


        /**
         * Checks if a new bidirectional stream can be accepted.
         *
         * @param streamId The stream ID of the new stream. Not used: the
         *                 HTTP/3 concurrency limit (the peer's
         *                 SETTINGS_MAX_STREAMS / MAX_STREAMS credit) caps
         *                 the number of concurrently open streams, not any
         *                 particular stream ID; the parameter is required
         *                 by the {@link QuicConnectionManager.ConnectionState}
         *                 interface shape
         * @return true if the stream can be accepted, false if limit reached
         */
        @Override
        public boolean canAcceptStream(long streamId) {
            return activeStreamCount < maxConcurrentStreams;
        }


        /**
         * {@inheritDoc}
         * <p>
         * Updates the last processed stream ID.
         *
         * @param streamId The identifier of the last processed stream
         */
        @Override
        public void setLastProcessedStreamId(long streamId) {
            this.lastProcessedStreamId = streamId;
        }


        /**
         * Returns the last processed stream ID for GOAWAY.
         *
         * @return The last processed stream ID
         */
        @Override
        public long getLastProcessedStreamId() {
            return lastProcessedStreamId;
        }


        /**
         * {@inheritDoc}
         */
        @Override
        public long getLastSentGoawayId() {
            return lastSentGoawayId;
        }


        /**
         * {@inheritDoc}
         */
        @Override
        public void setLastSentGoawayId(long goawayId) {
            this.lastSentGoawayId = goawayId;
        }


        /**
         * {@inheritDoc}
         * <p>
         * A stream counts as critical once it has been identified, by the
         * stream type written at its start, as the client's control stream
         * (RFC 9114 Section 6.2.1: closing either control stream is a
         * connection error of type H3_CLOSED_CRITICAL_STREAM) or as the
         * client's QPACK encoder or decoder stream (RFC 9204 Section 4.2:
         * closing either of them is likewise a connection error of type
         * H3_CLOSED_CRITICAL_STREAM).
         */
        @Override
        public boolean isCriticalClientUniStream(long streamId) {
            return streamId == clientControlStreamId ||
                    streamId == clientQpackEncoderStreamId ||
                    streamId == clientQpackDecoderStreamId;
        }


        @Override
        public long getClosedCriticalStreamErrorCode() {
            return Http3Error.H3_CLOSED_CRITICAL_STREAM.getCode();
        }


        /**
         * Sets the maximum concurrent streams.
         *
         * @param max The new maximum number of concurrent streams
         */
        @Override
        public void setMaxConcurrentStreams(long max) {
            this.maxConcurrentStreams = max;
        }


        /**
         * Returns the maximum concurrent streams.
         *
         * @return The maximum number of concurrent streams
         */
        public long getMaxConcurrentStreams() {
            return maxConcurrentStreams;
        }

    }
}

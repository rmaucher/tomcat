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

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiPredicate;
import java.util.function.Supplier;
import java.util.zip.GZIPOutputStream;

import jakarta.servlet.ServletConnection;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.coyote.AbstractProcessor;
import org.apache.coyote.Adapter;
import org.apache.coyote.ContinueResponseTiming;
import org.apache.coyote.ErrorState;
import org.apache.coyote.InputBuffer;
import org.apache.coyote.OutputBuffer;
import org.apache.coyote.Request;
import org.apache.coyote.RequestInfo;
import org.apache.coyote.Response;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.HeaderUtil;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.http.parser.Host;
import org.apache.tomcat.util.http.parser.HttpParser;
import org.apache.tomcat.util.http.parser.Priority;
import org.apache.tomcat.util.net.AbstractEndpoint.Handler.SocketState;
import org.apache.tomcat.util.net.ApplicationBufferHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.net.quic.QuicConnection;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicSocketWrapper;
import org.apache.tomcat.util.net.quic.QuicStream;
import org.apache.tomcat.util.res.StringManager;


/**
 * HTTP/3 processor. Each QUIC stream is associated with one request/response,
 * so this processor handles a single request per stream (no multiplexing needed).
 */
class Http3Processor extends AbstractProcessor
        implements QpackDecoder.HeaderEmitter {

    private static final Log log = LogFactory.getLog(Http3Processor.class);
    private static final StringManager sm = StringManager.getManager(Http3Processor.class);

    /**
     * Protocol reference.
     */
    private final AbstractHttp3Protocol protocol;

    /**
     * QPACK decoder for this stream.
     * May be shared with other streams on the same connection.
     */
    private QpackDecoder qpackDecoder;

    /**
     * QPACK encoder for this stream.
     * May be shared with other streams on the same connection.
     */
    private QpackEncoder qpackEncoder;

    /**
     * Input buffer for reading frames.
     */
    private final ByteBuffer inputBuffer = ByteBuffer.allocate(65536);

    /**
     * Maximum buffered frame payload length. Guards against allocating a
     * payload buffer for a corrupt or malicious frame length. It applies
     * only to the frame types whose payload this receiver buffers on a
     * request stream (DATA, HEADERS - see {@link #parseFrameHeader});
     * ignored frames (unknown or reserved-family padding) are discarded
     * without buffering at any declared size (RFC 9114 Sections 9, 7.2.8).
     * A buffered frame above this limit is protocol-valid (HTTP/3 has no
     * negotiated frame size limit); the affected request stream is
     * rejected with {@code RESET_STREAM} ({@link Http3Error#H3_FRAME_ERROR})
     * rather than failing the connection.
     */
    private static final int MAX_FRAME_LENGTH = 16 * 1024 * 1024;

    /**
     * Initial capacity of a frame payload buffer. The buffer grows
     * incrementally as the client actually delivers payload bytes, so a
     * frame header that declares a large length (up to
     * {@link #MAX_FRAME_LENGTH}) cannot force a large allocation before any
     * payload has arrived.
     */
    private static final int INITIAL_FRAME_PAYLOAD_SIZE = 8 * 1024;

    /**
     * Maximum time a blocking request-body read may wait for the peer to
     * deliver more data (or close the stream) before the stream is treated
     * as closed. A peer that stalls the body while keeping the QUIC
     * connection alive (for example with PING frames) must not be able to
     * pin a worker thread indefinitely. This matches the 30-second
     * blocking-write deadline of the {@code doWrite} implementation of the
     * QUIC socket wrapper;
     * the individual would-block pump retries within a single read carry
     * their own, shorter deadline (see {@link #PUMP_RETRY_TIMEOUT_MS}).
     */
    private static final int MAX_BODY_READ_STALL_MS = 30_000;

    /**
     * Per-call deadline for the pump-and-retry loop of
     * {@link #readWithPump} once a non-blocking read would-block. The
     * cumulative wait across a whole body read is bounded separately by
     * {@link #MAX_BODY_READ_STALL_MS}.
     */
    private static final int PUMP_RETRY_TIMEOUT_MS = 5_000;

    /**
     * Maximum number of request-body bytes buffered pre-dispatch. The body is
     * read non-blocking and stopped at this bound; the remainder is read on
     * demand as the servlet consumes it, so pre-dispatch heap use and worker
     * time stay bounded regardless of body size.
     */
    private static final int MAX_PRE_BUFFERED_BODY_BYTES = 64 * 1024;

    /**
     * Whether {@code inputBuffer} holds data read from the socket (read mode,
     * unread bytes at [position, limit)). A freshly recycled buffer has
     * position=0, limit=capacity and holds no data, which is
     * indistinguishable from a completely full buffer, so this flag
     * disambiguates the two states.
     */
    private boolean inputBufferHasData = false;

    /**
     * Output buffer for writing frames.
     */
    private final Http3OutputBuffer outputBuffer;

    /**
     * Stream ID from the QUIC stream.
     */
    private long streamId = -1;

    /**
     * The per-connection state (peer SETTINGS, etc.), or {@code null} when
     * not wired (e.g. in unit tests that drive the processor directly).
     */
    private Http3ConnectionManager.ConnectionState connectionState;

    /**
     * Whether headers have been received.
     */
    private boolean headersReceived = false;

    /**
     * Whether the request stream reached a clean end (FIN) before a
     * complete request head was received (an incomplete request,
     * RFC 9114 Section 4.1.2).
     */
    private boolean requestStreamEof = false;

    /**
     * Whether response has been started.
     */
    private boolean responseStarted = false;

    /**
     * Whether the interim 100 (Continue) ACK has already been sent for the
     * current request. Mirrors HTTP/1.1's {@code Http11OutputBuffer.ackSent}
     * flag: the interim send does not commit the coyote response and is not
     * covered by {@code responseStarted} (which is reserved for the final
     * response), so several {@code ActionCode.ACK} dispatches can match the
     * timing guard within a single request (e.g. {@code StandardContextValve}
     * with {@code ContinueResponseTiming.IMMEDIATELY} combined with
     * {@code FormAuthenticator}'s {@code ALWAYS} acknowledgement). The guard
     * makes the interim 100 a send-once per request. Reset in
     * {@link #recycle()}.
     */
    private volatile boolean ackSent = false;

    /**
     * Whether trailers have been sent for the response.
     */
    private boolean trailersSent = false;

    /**
     * Whether the stream has been reset (to prevent double reset).
     */
    private final AtomicBoolean streamReset = new AtomicBoolean(false);

    /**
     * Current frame being assembled (for multi-chunk frames).
     */
    private long pendingFrameType = -1;
    private long pendingFrameLength = 0;
    // Long like pendingFrameLength: an ignored frame may declare any
    // QUIC varint length and is discarded as it arrives without buffering.
    private long pendingFrameRead = 0;
    private ByteBuffer pendingFramePayload;

    /**
     * Scratch result of {@link #parseFrameHeader}: [type, length].
     */
    private final long[] frameHeader = new long[2];

    /**
     * Set by {@link #copyFramePayload} when a payload copy stopped early:
     * the stream ended (EOF) or a socket read would-block.
     */
    private boolean payloadEof = false;
    private boolean payloadBlocked = false;

    /**
     * Header validation state. {@link #seenPseudoHeaders} carries one bit per
     * defined pseudo-header (see {@link #pseudoHeaderBit}) so duplicates can
     * be detected with a single check (RFC 9114 Section 4.3).
     */
    private boolean pseudoHeadersDone = false;
    private int seenPseudoHeaders = 0;

    /*
     * Whether a Host header has been seen. Used with the serverName state to
     * apply the HTTP/2 first-set / consistency-compare / duplicate-reject
     * rules for Host vs :authority (RFC 9114 Section 4.3.1).
     */
    private boolean hostHeaderSeen = false;

    /*
     * Whether the field section currently being decoded is a trailer section
     * (a second HEADERS frame on the request stream, RFC 9114 Section 4.1).
     * While set, emitHeader() applies the connector's trailer allow-list and
     * routes regular fields into MimeTrailerFields (same as HTTP/2's
     * HEADER_STATE_TRAILER handling in Stream.emitHeader).
     */
    private boolean trailerMode = false;

    /*
     * Extensible priority signal state (RFC 9218): the urgency and
     * incremental parameters as signalled by the client in the Priority
     * request header field (RFC 9218 Section 5) and updated by client
     * PRIORITY_UPDATE frames (RFC 9218 Section 7.2). Volatile: updates
     * arrive via the connection state from the control-stream thread and
     * must be visible to this stream's worker thread. Initial values are
     * the RFC defaults (RFC 9218 Section 4: an omitted parameter acts as
     * its default), so a request with no priority signals is handled as
     * urgency 3, non-incremental.
     *
     * NOTE for future readers: nothing consumes these values yet. The
     * ingestion (parse, validate, RFC 9218 Section 7 merge, thread-safe
     * update path) is the full RFC-mandated receive side and is the
     * groundwork for a scheduler, but unlike HTTP/2 - where
     * Http2UpgradeHandler drives stream scheduling from
     * Stream.getUrgency()/getIncremental() - no H3 component reads
     * getUrgency()/getIncremental() and the QUIC layer exposes no
     * stream-priority hook, so the signal does not currently affect
     * send ordering.
     */
    private volatile int urgency = Priority.DEFAULT_URGENCY;
    private volatile boolean incremental = Priority.DEFAULT_INCREMENTAL;

    /**
     * Set once a PRIORITY_UPDATE buffered for this stream (the pre-open race
     * of RFC 9218 Section 7) has been applied to this processor. The
     * buffered frame is the most recently received signal
     * ("overrides any other signal", RFC 9218 Section 7), so the request's
     * own (older) Priority header field must not supersede it; the field is
     * still consumed and not forwarded to the application.
     */
    private volatile boolean priorityFromUpdate = false;

    /*
     * Serialises the writers of the priority signal: the Priority header
     * check-then-act in emitHeader, the grouped store in setPriority (the
     * PRIORITY_UPDATE path, on the control-stream thread) and the reset in
     * recycle(). Volatile fields alone leave the header path's flag load
     * and value stores non-atomic: an update landing in between would be
     * overwritten by the (older) header value, against RFC 9218
     * Section 7's "most recently received signal ... overrides any other".
     * Readers (getUrgency/getIncremental) stay on the volatile fields.
     */
    private final Object prioritySignalLock = new Object();

    /*
     * Buffer for concatenating multiple cookie field lines into a single
     * field value with the "; " delimiter (RFC 9114 Section 4.2.1, same
     * behavior as HTTP/2's Stream.emitHeader/cookie case). Flushed into the
     * request headers when the field section is complete.
     */
    private StringBuilder cookieHeader = null;

    private static final int PSEUDO_METHOD = 1;
    private static final int PSEUDO_SCHEME = 2;
    private static final int PSEUDO_PATH = 4;
    private static final int PSEUDO_AUTHORITY = 8;
    private static final int PSEUDO_PROTOCOL = 16;

    /*
     * Connection-specific field names banned by RFC 9114 Section 4.2 (the
     * Transfer-Encoding header field additionally by RFC 9114 Section 4.1).
     * Same set as the HTTP/2 implementation (Stream.HTTP_CONNECTION_SPECIFIC_
     * HEADERS). A message containing any of them MUST be treated as
     * malformed.
     */
    private static final Set<String> CONNECTION_SPECIFIC_HEADERS = Set.of(
            "connection", "proxy-connection", "keep-alive",
            "transfer-encoding", "upgrade");

    /*
     * Bit used to record a pseudo-header as seen, or 0 for a pseudo-header
     * that is not defined for HTTP/3 requests.
     */
    private static int pseudoHeaderBit(String name) {
        switch (name) {
            case ":method":     return PSEUDO_METHOD;
            case ":scheme":     return PSEUDO_SCHEME;
            case ":path":       return PSEUDO_PATH;
            case ":authority":  return PSEUDO_AUTHORITY;
            case ":protocol":   return PSEUDO_PROTOCOL;
            default:            return 0;
        }
    }

    /**
     * Whether the stream currently has a field section that referenced the
     * dynamic table (Required Insert Count &gt; 0, RFC 9204 Section 4.5.1)
     * and has not been acknowledged yet. Set before each field section
     * decode (and when a trailer section is staged mid-read), cleared when
     * the section's Section Acknowledgment is queued. While set, abandoning
     * the stream emits a Stream Cancellation instruction
     * (RFC 9204 Section 2.2.2.2).
     */
    private boolean fieldSectionUsedDynamicTable = false;

    /**
     * Whether the per-stream Stream Cancellation instruction
     * (RFC 9204 Section 2.2.2.2) has already been queued for this stream.
     * The instruction is single-shot per stream: the abandonment is a
     * per-stream event, even when it is observed through several error
     * paths (a staged-section note followed by the reset itself).
     */
    private boolean streamCancellationSent = false;

    /**
     * Accumulated content-length from request headers.
     * Used to validate DATA frame payload size (RFC 9114 Section 4.1.2:
     * a mismatch is a stream error of type H3_MESSAGE_ERROR).
     */
    private long requestContentLength = -1;

    /**
     * Set when a connection-level frame error is seen while reading the
     * request body in the input buffer read path (which cannot propagate
     * the {@link Http3Exception} it would throw): a control-only frame on a
     * request stream ({@link Http3Error#H3_FRAME_UNEXPECTED}, RFC 9114
     * Section 7.2) is a connection error; {@link #service} and
     * {@link #recycle} fail the connection with the recorded code. (A frame
     * above the local frame length limit is not recorded here: it is
     * protocol-valid and only exceeds this receiver's buffering limit, so
     * the input buffer read path rejects it at stream scope directly.)
     */
    private volatile Http3Error bodyFrameError = null;


    /*
     * Cumulative DATA frame payload bytes received for the current request
     * across both the pre-dispatch pre-buffering path (readRequestBody) and
     * the streaming read path (Http3InputBuffer.readMoreData), used to
     * enforce Content-Length (RFC 9114 Section 4.1.2).
     */
    private long totalDataReceived = 0;


    Http3Processor(AbstractHttp3Protocol protocol, Adapter adapter) {
        super(adapter);
        this.protocol = protocol;
        outputBuffer = new Http3OutputBuffer(this);
        response.setOutputBuffer(outputBuffer);
        request.setInputBuffer(new Http3InputBuffer(this));
        // QPACK encoder/decoder will be set from the shared connection-level
        // instances by the per-stream wiring in service().
        // Fallback to per-processor instances for safety.
        this.qpackDecoder = new QpackDecoder();
        this.qpackEncoder = new QpackEncoder();
    }


    @Override
    protected SocketState service(SocketWrapperBase<?> socketWrapper) throws IOException {
        setSocketWrapper(socketWrapper);

        // Per-stream wiring. HTTP/3 processors are created by
        // AbstractProtocol.ConnectionHandler and recycled across streams and
        // connections, so the stream-specific state is applied here (on every
        // dispatch, to be robust against re-use) rather than at construction
        // time.

        // Extract stream ID from the socket wrapper
        if (socketWrapper.getSocket() instanceof QuicStream quicStream) {
            setStreamId(quicStream.getStreamId());
        }

        // Wire the shared QPACK decoder from the connection manager. Per
        // RFC 9204 all streams of a connection share a single decoder
        // (the client's encoder instructions update the shared dynamic
        // table). The encoder, in contrast, is kept per stream: it is
        // only used to produce field sections from static table
        // references and literals (no dynamic table insertions) and its
        // in-progress encoding state must not be shared between the
        // worker threads that process the connection's streams in
        // parallel.
        if (socketWrapper instanceof QuicSocketWrapper quicWrapper) {
            QuicConnection conn = quicWrapper.getConnection();
            if (conn != null) {
                // Expose the SNI host name (read from the native connection)
                // so the processor can enforce strictSni.
                socketWrapper.setSniHostName(conn.getSniHostName());
                QuicConnectionManager connManager = conn.getQuicConnectionManager();
                if (connManager instanceof Http3ConnectionManager h3Manager) {
                    setSharedQpackDecoder(h3Manager.getSharedDecoder());
                    // Expose the per-connection state (peer SETTINGS,
                    // including the response field section limit per
                    // RFC 9114 Section 4.2.2). The state is created when
                    // the connection is opened, so it is available here.
                    setConnectionState(h3Manager.getState(conn));
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] service() entry, starting request processing");
        }

        // Stage tracking and statistics for the RequestProcessor /
        // GlobalRequestProcessor JMX views. The accounting follows the
        // HTTP/1.1 rule: exactly one request.updateCounters() per request
        // that reached the container (or received an error response),
        // performed once the request is complete. Requests that continue
        // asynchronously are left for AbstractProcessor.asyncDispatch()
        // (which updates on async completion), so nothing is counted twice.
        RequestInfo rp = request.getRequestProcessor();
        rp.setStage(org.apache.coyote.Constants.STAGE_PARSE);
        boolean requestStarted = false;

        try {
            // Read and process frames until we have a complete request
            while (!headersReceived) {
                if (!readFrame(socketWrapper)) {
                    if (requestStreamEof || payloadEof) {
                        // The request stream ended before a complete
                        // request head arrived (a clean FIN at a frame
                        // boundary, or a stop mid-frame-payload). A stream
                        // the client reset or the connection closed simply
                        // aborts the request; a cleanly finished one is an
                        // incomplete request: RFC 9114 Section 4.1.2 has
                        // the server abort the response stream with
                        // H3_REQUEST_INCOMPLETE rather than hold the stream
                        // open forever.
                        if (log.isDebugEnabled()) {
                            log.debug("Stream [" + streamId +
                                    "] request stream ended before headers " +
                                    "were received");
                        }
                        if (isStreamFin(socketWrapper)) {
                            handleStreamError(socketWrapper,
                                    Http3Error.H3_REQUEST_INCOMPLETE);
                        } else {
                            noteAbandonedDynamicTableUse();
                        }
                        return SocketState.CLOSED;
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Stream [" + streamId + "] readFrame returned false, returning LONG");
                    }
                    return SocketState.LONG;
                }
            }

            // Read initial DATA frames before dispatching when the request
            // indicates a body. HTTP/3 framing does not restrict bodies to
            // particular methods (RFC 9114 Section 4.1; RFC 9110 Section 6.5
            // allows content with any method): the body is indicated by the
            // content-length header, independent of the method name.
            if (isRequestBodyIndicated()) {
                readRequestBody(socketWrapper);
            }

            // Validate headers
            validateHeadersInternal();

            // Prepare request
            rp.setStage(org.apache.coyote.Constants.STAGE_PREPARE);
            if (!prepareRequest()) {
                return SocketState.CLOSED;
            }

            // A malformed host header whose value cannot be parsed at all is
            // recorded by compareAuthority() as a note because the decode
            // path cannot itself send the response - provided the
            // :authority already resolved a server name, since
            // validateHeadersInternal() above rejects a request whose
            // server name is still missing (a malformed :authority never
            // sets one, so it takes that stream-error path rather than
            // reaching this note). Surface the note as a 400 Bad Request,
            // mirroring HTTP/2's StreamProcessor.validateRequest().
            if (request.getNote(Request.NOTE_BAD_REQUEST) != null) {
                requestStarted = true;
                sendErrorResponse(socketWrapper,
                        HttpServletResponse.SC_BAD_REQUEST);
                protocol.getAdapter().log(request, response, 0);
                concludeStream(socketWrapper);
                return SocketState.CLOSED;
            }

            // Dispatch to container
            rp.setStage(org.apache.coyote.Constants.STAGE_SERVICE);
            requestStarted = true;
            try {
                protocol.getAdapter().service(request, response);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http3Processor.error", Long.valueOf(streamId)), e);
                }
                // Send 500 error response before closing
                try {
                    sendErrorResponse(socketWrapper, 500);
                } catch (IOException ex) {
                    // Ignore - stream may already be closed
                }
                return SocketState.CLOSED;
            }

            // A connection-level frame error (a control-only frame on the
            // request stream) was seen while the servlet read the request
            // body (RFC 9114: a connection error, not a stream error).
            Http3Error bodyFrameError = this.bodyFrameError;
            if (bodyFrameError != null) {
                this.bodyFrameError = null;
                failConnection(socketWrapper, bodyFrameError);
                return SocketState.CLOSED;
            }

            // Check for async
            if (isAsync()) {
                // Stream stays open for async completion.
                // The async servlet will eventually call response.flush() or complete().
                return SocketState.LONG;
            }

            // Send response
            sendResponse(socketWrapper);

            // A trailer section that no body-read path ever encountered (a
            // body-less stream, or a stream the application never drained)
            // is discovered and decoded here, before the stream is torn
            // down, so its QPACK bookkeeping is not silently lost.
            decodeTrailerSectionAfterResponse(socketWrapper);

            // A HEADERS or DATA frame after the trailer section is an
            // invalid frame sequence (RFC 9114 Section 4.1): the mandated
            // connection error of type H3_FRAME_UNEXPECTED is emitted here
            // rather than the trailing bytes being dropped silently when
            // the concluded stream is torn down.
            checkFramesAfterTrailer(socketWrapper);

            return SocketState.CLOSED;

        } catch (Http3StreamException e) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3Processor.error", Long.valueOf(e.getStreamId())), e);
            }
            // Stream-level error - reset stream with appropriate error code
            handleStreamError(socketWrapper, e.getError());
            return SocketState.CLOSED;
        } catch (Http3Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3Processor.error", Long.valueOf(streamId)), e);
            }
            if (e.getError().isStreamError()) {
                // Malformed HTTP message (RFC 9114 Section 4.1.2): fail only
                // the affected stream.
                handleStreamError(socketWrapper, e.getError());
            } else {
                // Connection error (RFC 9114 Sections 4.1, 6.2.1, 7.2.x):
                // terminate the whole HTTP/3 connection.
                failConnection(socketWrapper, e.getError());
            }
            return SocketState.CLOSED;
        } catch (QpackValueTooLargeException e) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3Processor.error", Long.valueOf(streamId)), e);
            }
            // RFC 9204 Section 7.4: a value larger than the decoder can
            // represent, encountered while decoding this request stream's
            // field section, MUST be treated as a stream error of type
            // QPACK_DECOMPRESSION_FAILED - only this stream is reset, the
            // connection and its other streams survive (the shared decoder
            // state is untouched: the oversize value is rejected before it
            // can mutate anything).
            handleStreamError(socketWrapper,
                    Http3Error.H3_QPACK_DECOMPRESSION_FAILED);
            return SocketState.CLOSED;
        } catch (QpackException e) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3Processor.error", Long.valueOf(streamId)), e);
            }
            // A blocked stream (RFC 9204 Section 2.2.1: the field section
            // references dynamic table entries that have not been inserted
            // yet) is not an error in itself when the connector accepts
            // blocked streams (qpackBlockedStreams), but decodeFieldSection()
            // already waited in that case: reaching here means blocking is
            // disabled (SETTINGS_QPACK_BLOCKED_STREAMS is omitted from the
            // server's SETTINGS, default 0), the per-connection blocked-
            // stream limit was exceeded, or the wait timed out - in each
            // case the section MUST be treated as a connection error (RFC
            // 9204 Section 2.1.2). Any other fatal QPACK error (invalid
            // reference per Section 2.2.3, invalid static table index per
            // Section 3.1, impossible Encoded Insert Count per Section
            // 4.5.1.1) also fails the connection since the QPACK decoder is
            // shared by all streams of the connection.
            failConnection(socketWrapper,
                    Http3Error.H3_QPACK_DECOMPRESSION_FAILED);
            return SocketState.CLOSED;
        } finally {
            if (requestStarted && !isAsync()) {
                // Request completed (synchronously, or with an error):
                // fold its statistics into the RequestInfo totals that the
                // RequestProcessor / GlobalRequestProcessor MBeans expose.
                request.updateCounters();
                rp.setStage(org.apache.coyote.Constants.STAGE_ENDED);
            }
        }
    }


    /*
     * Resets the stream with the given error code. The reset abandons the
     * stream before all of its field sections were processed, so the peer's
     * encoder is owed a Stream Cancellation unconditionally (RFC 9204
     * Section 2.2.2.2): the abandoned section may reference dynamic table
     * entries the peer inserted even when this endpoint never consumed the
     * section's Required Insert Count byte (e.g. a declared-length preflight
     * rejection), and the instruction is a no-op for the peer when it does
     * not. Single-shot per stream (see streamCancellationSent), so a
     * cancellation already queued by an earlier abandonment note is not
     * duplicated.
     */
    private void handleStreamError(SocketWrapperBase<?> socketWrapper,
            Http3Error error) {
        fieldSectionUsedDynamicTable = false;
        if (!streamCancellationSent) {
            streamCancellationSent = true;
            noteStreamCancellation();
        }
        try {
            resetStream(socketWrapper, error);
        } catch (Exception ex) {
            // Ignore
        }
    }


    /*
     * Notes the abandonment of receiving this stream's field sections: any
     * dynamic table references from a field section that was never
     * acknowledged stop being outstanding, which the peer's encoder needs
     * to know for its eviction control (RFC 9204 Sections 2.2.2.2, 4.4.2).
     * Acknowledged sections need no cancellation: their Section
     * Acknowledgment already released their references. Emission is
     * single-shot per field section (the flag is cleared) and — via
     * streamCancellationSent — per stream, so a stream abandoned through
     * several error paths still sends one instruction. Reset paths do not
     * rely on this method's precondition: handleStreamError() emits
     * unconditionally (RFC 9204 Section 2.2.2.2); this variant serves the
     * abandonment paths that never reset the stream (e.g. the after-response
     * scan, where the stream is simply dropped).
     */
    private void noteAbandonedDynamicTableUse() {
        if (fieldSectionUsedDynamicTable) {
            fieldSectionUsedDynamicTable = false;
            if (!streamCancellationSent) {
                streamCancellationSent = true;
                noteStreamCancellation();
            }
        }
    }


    /*
     * Notes dynamic-table use observed in a field section that was only
     * partially received (so processHeadersFrame()/processTrailerSection()
     * never recorded it). The Required Insert Count is an 8-bit prefix
     * integer occupying the whole first byte of the section, so a non-zero
     * first byte means Required Insert Count > 0 (RFC 9204 Section 4.5.1).
     * A partial section in write mode carries the bytes read so far in
     * [0, position()); a zero-length prefix means nothing was observed yet
     * and nothing is recorded.
     */
    private void notePartialSectionDynamicTableUse(ByteBuffer partialRead) {
        if (partialRead.position() > 0 && partialRead.get(0) != 0) {
            fieldSectionUsedDynamicTable = true;
        }
    }


    /**
     * Narrows a socket wrapper to its QUIC stream wrapper, or returns
     * {@code null} if the wrapper is not a QUIC stream wrapper.
     *
     * @param socketWrapper The socket wrapper to narrow
     *
     * @return The QUIC stream wrapper, or {@code null}
     */
    private static QuicSocketWrapper quicWrapper(SocketWrapperBase<?> socketWrapper) {
        return socketWrapper instanceof QuicSocketWrapper qw ? qw : null;
    }


    private static QuicConnection quicConnection(SocketWrapperBase<?> socketWrapper) {
        QuicSocketWrapper qw = quicWrapper(socketWrapper);
        return qw == null ? null : qw.getConnection();
    }


    /**
     * Fails the entire HTTP/3 connection with the given connection error.
     * <p>
     * Per RFC 9114 Section 8 a connection error terminates the QUIC
     * connection, which is signalled with a {@code CONNECTION_CLOSE} frame
     * carrying the HTTP/3 error code in the application error code field.
     * The native teardown must run on the QUIC poll thread, so it is
     * hopped there by the connection wrapper.
     *
     * @param socketWrapper The socket wrapper of the offending stream
     * @param error The connection error
     */
    private void failConnection(SocketWrapperBase<?> socketWrapper, Http3Error error) {
        QuicConnection conn = quicConnection(socketWrapper);
        if (conn != null) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3Processor.connectionFailed",
                        Long.valueOf(streamId), Long.valueOf(error.getCode())));
            }
            conn.failConnection(error.getCode(),
                    "HTTP/3 connection error on stream " + streamId);
        }
    }


    /**
     * Returns the {@link Http3ConnectionManager} for this stream's QUIC
     * connection, or {@code null} if it cannot be determined.
     */
    private Http3ConnectionManager getConnectionManager() {
        QuicConnection conn = quicConnection(getSocketWrapper());
        if (conn != null) {
            QuicConnectionManager manager = conn.getQuicConnectionManager();
            if (manager instanceof Http3ConnectionManager h3Manager) {
                return h3Manager;
            }
        }
        return null;
    }


    /**
     * Notes that a Section Acknowledgment instruction must be emitted for
     * the field section just decoded on this stream (RFC 9204 Section
     * 2.2.2.1). The instruction is written to the server QPACK decoder
     * stream on the QUIC poll thread.
     */
    private void noteSectionAcknowledgment() {
        noteDecoderInstruction(
                (manager, conn) -> manager.noteSectionAcknowledgment(conn, streamId));
    }


    /**
     * Notes that a Stream Cancellation instruction must be emitted for this
     * stream because it is being abandoned before all of its field sections
     * were processed (RFC 9204 Section 2.2.2.2). The instruction is written
     * to the server QPACK decoder stream on the QUIC poll thread.
     */
    private void noteStreamCancellation() {
        noteDecoderInstruction(
                (manager, conn) -> manager.noteStreamCancellation(conn, streamId));
    }


    /*
     * Common path for emitting a decoder instruction on this stream. The
     * BiPredicate returns false when the per-connection backlog of pending
     * instructions was exceeded: a peer that never reads its QPACK decoder
     * stream must not be able to grow per-connection state without bound.
     */
    private void noteDecoderInstruction(
            BiPredicate<Http3ConnectionManager,QuicConnection> note) {
        SocketWrapperBase<?> socketWrapper = getSocketWrapper();
        QuicConnection conn = quicConnection(socketWrapper);
        Http3ConnectionManager manager = getConnectionManager();
        if (conn != null && manager != null && !note.test(manager, conn)) {
            if (log.isWarnEnabled()) {
                log.warn(sm.getString("http3ConnectionManager.pendingDecoderInstructionsFull",
                        Integer.valueOf(Http3ConnectionManager.MAX_PENDING_DECODER_INSTRUCTIONS)));
            }
            // The condition is a peer that never drains our QPACK decoder
            // stream, not a decompression failure: H3_EXCESSIVE_LOAD
            // describes the unbounded state growth it would allow.
            failConnection(socketWrapper, Http3Error.H3_EXCESSIVE_LOAD);
        }
    }


    /*
     * Whether the request declares a body via its content-length header.
     * HTTP/3 framing does not restrict bodies to particular methods
     * (RFC 9114 Section 4.1; RFC 9110 Section 6.5 allows content to be
     * present with any method), so the declaration - not the method name -
     * drives the pre-dispatch body handling (pre-buffering, content-length
     * overrun checks). Bodies without a content-length are delimited by the
     * end of the stream and are not pre-read.
     */
    private boolean isRequestBodyIndicated() {
        return requestContentLength >= 0;
    }


    /**
     * Checks whether the method is one of the methods that commonly carries
     * a request body. Used only for bodies whose length is not declared:
     * for these methods the end of the stream is treated as a possible body
     * boundary rather than as the end of a body-less request. Any method may
     * in principle carry a body (RFC 9110 Section 6.5, RFC 9114 Section 4.1)
     * but bodies on methods outside this set must declare their length to be
     * read; otherwise they are not awaited.
     */
    private boolean isMethodWithBody(String method) {
        if (method == null) {
            return false;
        }
        switch (method) {
            case "POST":
            case "PUT":
            case "PATCH":
            case "DELETE":
            case "CONNECT":
                return true;
            default:
                return false;
        }
    }


    /**
     * Encodes the given headers into a QPACK header block, growing the output
     * buffer as needed. Any in-progress encoding from a previous (aborted)
     * call is abandoned first, so stale partial state is never applied to a
     * new header set.
     *
     * @param headers          The headers to encode
     * @param initialCapacity  Initial capacity of the output buffer
     * @return The finished header block, ready to be read
     */
    private ByteBuffer encodeHeaderBlock(MimeHeaders headers, int initialCapacity) {
        MimeHeaders toEncode = applyPeerFieldSectionLimit(headers);
        qpackEncoder.resetEncodingState();
        ByteBuffer headerBlock = ByteBuffer.allocate(initialCapacity);
        QpackEncoder.State state;
        do {
            state = qpackEncoder.encode(toEncode, headerBlock);
            if (state == QpackEncoder.State.UNDERFLOW) {
                headerBlock.flip();
                ByteBuffer grown = ByteBuffer.allocate(headerBlock.capacity() * 2);
                grown.put(headerBlock);
                headerBlock = grown;
            }
        } while (state == QpackEncoder.State.UNDERFLOW);
        headerBlock.flip();
        return headerBlock;
    }


    /*
     * Applies the peer's SETTINGS_MAX_FIELD_SECTION_SIZE to an outgoing
     * field section (RFC 9114 Section 4.2.2: "An implementation that has
     * received this parameter SHOULD NOT send an HTTP message header that
     * exceeds the indicated size, as the peer will likely refuse to process
     * it.").
     *
     * When the section is larger than the declared limit, field lines are
     * dropped to reduce it: the pseudo-headers and the fields the peer needs
     * to interpret and authenticate the payload (content-type,
     * content-length, set-cookie, www-authenticate, proxy-authenticate) are
     * always retained, the remaining fields are kept in order as long as
     * they still fit. If the retained fields alone still exceed a
     * pathologically small limit, the reduced set is sent unchanged: the
     * limit is advisory and failing a response the peer may still accept is
     * worse than exceeding a SHOULD.
     *
     * The size uses the same accounting as the incoming checks
     * (QpackDecoder.emit()): sum of the UTF-8 byte lengths of the names and
     * values plus 32 bytes per field line.
     */
    private MimeHeaders applyPeerFieldSectionLimit(MimeHeaders headers) {
        long limit = connectionState == null ? 0 : connectionState.getPeerMaxFieldSectionSize();
        if (limit <= 0 || fieldSectionSize(headers) <= limit) {
            return headers;
        }

        MimeHeaders reduced = new MimeHeaders();
        long size = 0;
        // Pass 0 retains the fields that must not be dropped; pass 1 adds
        // the remaining fields in order while they fit.
        for (int pass = 0; pass < 2; pass++) {
            for (int i = 0; i < headers.size(); i++) {
                String name = headers.getName(i).toString();
                boolean retained = isFieldSectionEssential(name);
                if ((pass == 0) != retained) {
                    continue;
                }
                String value = headers.getValue(i).toString();
                long entrySize = Qpack.entrySize(name, value);
                if (pass == 1 && size + entrySize > limit) {
                    continue;
                }
                reduced.addValue(name).setString(value);
                size += entrySize;
            }
        }

        if (log.isWarnEnabled()) {
            log.warn(sm.getString("http3Processor.response.fieldSectionTooLarge",
                    Long.valueOf(streamId), Long.valueOf(size), Long.valueOf(limit)));
        }
        return reduced;
    }


    private static boolean isFieldSectionEssential(String name) {
        if (name.startsWith(":")) {
            return true;
        }
        String lower = name.toLowerCase(Locale.ENGLISH);
        return "content-type".equals(lower) || "content-length".equals(lower) ||
                "set-cookie".equals(lower) || "www-authenticate".equals(lower) ||
                "proxy-authenticate".equals(lower);
    }


    private static long fieldSectionSize(MimeHeaders headers) {
        long size = 0;
        for (int i = 0; i < headers.size(); i++) {
            size += Qpack.entrySize(headers.getName(i).toString(),
                    headers.getValue(i).toString());
        }
        return size;
    }


    /*
     * The wire-side companion of the configured maxFieldSectionSize, used
     * by the pre-decode HEADERS frame-length preflight.
     *
     * RFC 9114 Section 4.2.2 defines the field section limit against the
     * UNCOMPRESSED size (the name and value lengths plus 32 bytes of
     * overhead per field line), and that is what the post-decode check in
     * QpackDecoder.emit() enforces. The preflight runs on the declared
     * encoded length before anything is decoded, so it must not reject a
     * section that is legal on the wire while fitting the uncompressed
     * limit: QPACK string literals may be Huffman-encoded even when that
     * makes them larger than the raw bytes (a 30-bit Huffman code is
     * 3.75 bytes per raw byte, the same inflation bound as
     * QpackDecoder.encodedLiteralBudget()), and the field section prefix
     * (Required Insert Count and Delta Base) adds up to two
     * maximally-encoded iRPs on top of the field lines. Every field line's
     * own wire overhead (indicator, index and length prefixes) is dominated
     * by the 32 bytes of uncompressed overhead the same section is
     * credited for, so the worst wire size of a section whose decoded size
     * is at most L is bounded by 15/4 * L plus the prefix. Sections above
     * this bound can only decode beyond the configured limit; they are
     * rejected at the frame header, which keeps the pre-decode buffering
     * of HEADERS frames bounded per stream.
     */
    private long fieldSectionWireLimit() {
        long limit = protocol.getMaxFieldSectionSize();
        if (limit > (Long.MAX_VALUE - 32L) / 15L) {
            return Long.MAX_VALUE;
        }
        return limit * 15L / 4L + 2L * Qpack.MAX_IRP_ENCODED_LENGTH + 12L;
    }


    /**
     * Sends an HTTP/3 error response with the given status code.
     * Sends a minimal HEADERS frame with :status pseudo-header.
     *
     * @param socketWrapper The socket wrapper to write to
     * @param statusCode    The HTTP status code
     * @throws IOException If an I/O error occurs
     */
    private void sendErrorResponse(SocketWrapperBase<?> socketWrapper, int statusCode) throws IOException {
        if (responseStarted) {
            return;
        }
        // Stream reset (see sendResponse()): no response bytes may be
        // written. Claim the response as started so the attempt does not
        // even reach the write - writing against the reset stream would
        // only throw and log misleading I/O errors on top of the reset
        // that already happened.
        if (streamReset.get()) {
            responseStarted = true;
            return;
        }

        // Set status on the response object so MimeHeaders has :status set
        response.setStatus(statusCode);

        // Build minimal error headers per RFC 9114 Section 4.3.2
        // Only :status pseudo-header is required in responses
        org.apache.tomcat.util.http.MimeHeaders errorHeaders = response.getMimeHeaders();
        MessageBytes statusMb = errorHeaders.getValue(":status");
        if (statusMb == null || statusMb.isNull()) {
            errorHeaders.addValue(":status").setString(String.valueOf(statusCode));
        }

        sendHeadersFrame(socketWrapper, errorHeaders, 256, false);
        responseStarted = true;
    }


    /*
     * Wraps an encoded QPACK field section in a HEADERS frame: QUIC varint
     * type + QUIC varint length + payload.
     */
    private static ByteBuffer buildHeadersFrame(ByteBuffer headerBlock) {
        ByteBuffer frame = ByteBuffer.allocate(4 + headerBlock.remaining());
        Qpack.encodeQuicInteger(frame, Constants.H3_HEADERS);
        Qpack.encodeQuicInteger(frame, headerBlock.remaining());
        frame.put(headerBlock);
        frame.flip();
        return frame;
    }


    /*
     * Shared HEADERS send path: QPACK-encode the field section, wrap it in a
     * HEADERS frame, write it to the stream and flush. All response-side
     * HEADERS frames (error response, early hints, response headers,
     * trailers) go through here.
     *
     * @return The frame written, in read mode
     */
    private ByteBuffer sendHeadersFrame(SocketWrapperBase<?> socketWrapper,
            MimeHeaders headers, int encodeBudget, boolean blocking)
            throws IOException {
        ByteBuffer headerBlock = encodeHeaderBlock(headers, encodeBudget);
        if (log.isTraceEnabled()) {
            log.trace(sm.getString("http3Processor.headersEncoded",
                    Long.valueOf(streamId),
                    Integer.valueOf(headerBlock.remaining())));
        }
        ByteBuffer frame = buildHeadersFrame(headerBlock);
        if (log.isTraceEnabled()) {
            log.trace(sm.getString("http3Processor.sendingHeadersFrame",
                    Long.valueOf(streamId)));
        }
        socketWrapper.write(blocking, frame);
        socketWrapper.flush(blocking);
        return frame;
    }


    /**
     * Reads from the socket wrapper. If the non-blocking read would-block
     * (returns 0) and the wrapper is a QUIC wrapper, waits on the wrapper's
     * event-driven read wake-up (which drives the QUIC state machine once,
     * arms read interest and parks until the poll thread signals data
     * arrival, up to a bounded deadline) and retries. This lets a synchronous
     * body read obtain data that the poll loop's most recent
     * SSL_handle_events has not yet delivered, without polling the poll
     * thread at a fixed interval while waiting. May be called from the poll
     * thread or from worker threads; all native QUIC operations are hopped to
     * the poll thread by the socket wrapper.
     *
     * @return bytes read (&gt;0), 0 (would-block after the deadline), or -1 (EOF)
     */
    private int readWithPump(SocketWrapperBase<?> socketWrapper, ByteBuffer inputBuffer) throws IOException {
        int n;
        try {
            n = socketWrapper.read(false, inputBuffer);
        }
        catch (EOFException eoe) {
            // The stream was reset or the connection was closed (for
            // example the client disconnected mid-body). No further data
            // can arrive, so report end of stream.
            return -1;
        }
        if (n != 0) {
            return n;
        }
        QuicSocketWrapper quicWrapper = quicWrapper(socketWrapper);
        if (quicWrapper == null) {
            return n;
        }
        long deadline = System.nanoTime() +
                TimeUnit.MILLISECONDS.toNanos(PUMP_RETRY_TIMEOUT_MS);
        while (n == 0 && !Thread.currentThread().isInterrupted()) {
            // Pump, arm interest and park until the poll thread signals a
            // read event / terminal state, the deadline passes or the thread
            // is interrupted (false in the latter two cases).
            if (!quicWrapper.awaitReadableData(deadline)) {
                break;
            }
            try {
                n = socketWrapper.read(false, inputBuffer);
            }
            catch (EOFException eoe) {
                // The stream was reset or the connection was closed while
                // waiting for more data. No further data can arrive, so
                // report end of stream.
                return -1;
            }
        }
        return n;
    }



    /**
     * Performs a single non-blocking read from the socket wrapper without
     * driving the QUIC state machine.
     *
     * @param socketWrapper The socket wrapper to read from
     * @param inputBuffer Destination buffer
     * @return bytes read (&gt;0), 0 (would-block), or -1 (stream ended)
     */
    private int readNonBlocking(SocketWrapperBase<?> socketWrapper, ByteBuffer inputBuffer) throws IOException {
        try {
            return socketWrapper.read(false, inputBuffer);
        } catch (EOFException eoe) {
            // The stream was reset or the connection was closed. No further
            // data can arrive, so report end of stream.
            return -1;
        }
    }


    /**
     * Refills the protocol input buffer from the socket, preserving unread
     * bytes: compact (moving the unread tail to the head and switching to
     * write mode; clear for a freshly recycled buffer, see below), a single
     * read (optionally pumping the QUIC state machine), then flip back to
     * read mode. The buffer MUST be flipped again even when
     * nothing was read, so the compacted tail stays in read mode and is
     * neither lost nor re-exposed as stale array bytes to the frame parser.
     * This compact/read/flip triad is the single implementation shared by
     * every input-buffer refill site (frame parsing, payload copy/skip,
     * header completion).
     *
     * @param socketWrapper The socket wrapper to read from
     * @param inputBuffer   The buffer to refill (read mode on entry and
     *                      exit; a freshly recycled write-mode buffer is
     *                      handled via {@code inputBufferHasData})
     * @param pump          Whether to drive the QUIC state machine between
     *                      read attempts (see {@link #readWithPump})
     *
     * @return bytes read (&gt;0), 0 (would-block; after the pump deadline
     *         when {@code pump} is set), or -1 (stream ended)
     */
    private int refillInputBuffer(SocketWrapperBase<?> socketWrapper, ByteBuffer inputBuffer,
            boolean pump) throws IOException {
        // A freshly recycled buffer (position=0, limit=capacity) holds no
        // data yet is indistinguishable from a full one by positions alone;
        // inputBufferHasData tells the two apart. It is set here, by the
        // first successful read (the fresh/full distinction only exists
        // until data has ever been read into the buffer), so the contract
        // of the flag lives entirely in this method; for an empty read-mode
        // buffer compact() is position-for-position equivalent to clear().
        if (inputBufferHasData) {
            inputBuffer.compact();
        } else {
            inputBuffer.clear();
        }
        int n = pump ? readWithPump(socketWrapper, inputBuffer) :
                readNonBlocking(socketWrapper, inputBuffer);
        if (n > 0) {
            inputBufferHasData = true;
        }
        inputBuffer.flip();
        return n;
    }


    /**
     * Checks whether the request stream was cleanly closed by the client
     * (FIN) rather than being reset or aborted by a connection close.
     */
    private static boolean isStreamFin(SocketWrapperBase<?> socketWrapper) {
        QuicSocketWrapper quicWrapper = quicWrapper(socketWrapper);
        if (quicWrapper != null) {
            QuicStream stream = quicWrapper.getQuicStream();
            return stream != null
                    && stream.getReadState() == QuicStream.ReadState.FINISHED;
        }
        return false;
    }


    /**
     * Checks whether the request stream's read side was reset by the client
     * (RESET_STREAM) rather than closed by a FIN. A reset aborts the request:
     * an incomplete body must be reported to a ReadListener as an error, not
     * as end of data (mirrors HTTP/2's Stream.InputBuffer reset handling).
     */
    private static boolean isStreamReset(SocketWrapperBase<?> socketWrapper) {
        QuicSocketWrapper quicWrapper = quicWrapper(socketWrapper);
        if (quicWrapper != null) {
            QuicStream stream = quicWrapper.getQuicStream();
            return stream != null
                    && stream.getReadState() == QuicStream.ReadState.RESET_REMOTE;
        }
        return false;
    }


    /**
     * Reads frames for the request body, pre-dispatch. Called only when the
     * request declares a body via Content-Length (see
     * {@link #isRequestBodyIndicated()}): HTTP/3 bodies are not restricted to
     * particular methods (RFC 9114 Section 4.1; RFC 9110 Section 6.5), so the
     * declaration - not the method name - drives the pre-read. Reads DATA
     * frames until the declared body is buffered, a terminal frame (TRAILERS)
     * is encountered, a read would-block, the stream ends, or the pre-buffer
     * bound is reached.
     * <p>
     * Reads are non-blocking and bounded to
     * {@link #MAX_PRE_BUFFERED_BODY_BYTES}: the body is not drained to
     * completion before dispatch, so a slow or oversized body cannot pin a
     * worker thread or exhaust heap pre-dispatch. The remainder of the body
     * is read on demand by {@link Http3InputBuffer#doRead(ApplicationBufferHandler)},
     * which may pump the QUIC state machine while the servlet is blocked
     * reading the body.
     */
    private void readRequestBody(SocketWrapperBase<?> socketWrapper) throws IOException, QpackException, Http3Exception {
        long totalPayloadBytes = 0;
        boolean eof = false;

        readLoop: while (true) {
            if (totalPayloadBytes >= MAX_PRE_BUFFERED_BODY_BYTES) {
                break;
            }

            if (!inputBuffer.hasRemaining()) {
                // compact + read + flip (see refillInputBuffer)
                int n = refillInputBuffer(socketWrapper, inputBuffer, false);
                if (n <= 0) {
                    eof = n < 0;
                    break;
                }
            }

            if (inputBuffer.remaining() < 2) {
                break;
            }

            if (!parseFrameHeader(inputBuffer, frameHeader)) {
                break;
            }
            long frameType = frameHeader[0];
            long frameLen = frameHeader[1];

            if (log.isDebugEnabled()) {
                log.debug("Stream [" + streamId + "] readRequestBody frame type=0x" + Long.toHexString(frameType)
                        + " len=" + frameLen + " bufRem=" + inputBuffer.remaining());
            }
            Http3InputBuffer inBuf = (Http3InputBuffer) request.getInputBuffer();
            switch (classifyBodyFrame(frameType)) {
                case DATA -> {
                    if (frameLen == 0) {
                        continue;
                    }
                    // The sum of the DATA frame lengths MUST NOT exceed
                    // Content-Length (RFC 9114 Section 4.1.2); the check is
                    // shared with the streaming path.
                    if (dataOverrunsContentLength(totalPayloadBytes, frameLen)) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.dataFrameExceedsContentLength",
                                        Long.valueOf(streamId),
                                        Long.valueOf(totalPayloadBytes + frameLen),
                                        Long.valueOf(requestContentLength)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    // Bound the payload buffered pre-dispatch.
                    int toBuffer = (int) Math.min(frameLen, MAX_PRE_BUFFERED_BODY_BYTES - totalPayloadBytes);
                    if (toBuffer <= 0) {
                        break readLoop;
                    }
                    // Read frame payload
                    ByteBuffer payload = ByteBuffer.allocate(toBuffer);
                    int payloadRead = copyFramePayload(inputBuffer, socketWrapper, payload,
                            payload.remaining(), false);
                    boolean payloadIncomplete = payloadRead < toBuffer;
                    totalPayloadBytes += payloadRead;
                    totalDataReceived = totalPayloadBytes;
                    payload.flip();
                    inBuf.setData(payload);
                    if (payloadIncomplete || payloadRead < frameLen) {
                        // Either the read would-blocked mid-frame or the
                        // pre-buffer bound was reached. Save the partial payload,
                        // record how many payload bytes of this frame are still
                        // outstanding, and stop reading further frames. The
                        // streaming read path (Http3InputBuffer.readMoreData)
                        // will continue reading this frame's remaining payload
                        // without mis-parsing it as a new frame header. The input
                        // buffer is left in read mode (possibly empty), so no
                        // stale bytes can be re-exposed to the frame parser.
                        // Safe cast: parseFrameHeader rejects DATA frames
                        // above MAX_FRAME_LENGTH at the header.
                        inBuf.setPartialDataRemaining((int) (frameLen - payloadRead));
                        if (payloadEof) {
                            // A clean FIN cut the copy short rather than a
                            // would-block: the reads have now exhausted the
                            // stream, so totalPayloadBytes is the complete
                            // received total and the shortfall check after
                            // the loop is conclusive. Without this, a body
                            // truncated mid-frame would only be surfaced if
                            // the application happened to read the body —
                            // otherwise the malformed request (RFC 9114
                            // Section 4.1.2) would be answered with a normal
                            // response.
                            eof = true;
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("Stream [" + streamId + "] readRequestBody DATA frame partial: read="
                                    + payloadRead + "/" + frameLen + ", deferring "
                                    + (frameLen - payloadRead) + " bytes to streaming read");
                        }
                        break readLoop;
                    }
                }
                case TRAILERS -> {
                    // A HEADERS frame after the initial request HEADERS frame
                    // is the trailer section (see BodyFrameKind.TRAILERS).
                    // The declared-length preflight uses the wire-side bound
                    // of the field section limit (see fieldSectionWireLimit);
                    // the RFC-defined uncompressed check runs on decode.
                    long wireLimit = fieldSectionWireLimit();
                    if (frameLen > wireLimit) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.header.sectionTooLarge",
                                        Long.valueOf(streamId), Long.valueOf(frameLen),
                                        Long.valueOf(wireLimit)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    // Safe casts: parseFrameHeader rejects HEADERS frames
                    // above MAX_FRAME_LENGTH at the header.
                    ByteBuffer trailerPayload =
                            ByteBuffer.allocate((int) frameLen);
                    int payloadRead = copyFramePayload(inputBuffer, socketWrapper,
                            trailerPayload, (int) frameLen, false);
                    if (payloadRead < frameLen && payloadEof) {
                        // FIN arrived before the trailer section was complete:
                        // truncated field section, malformed request. The
                        // section never reached the decoder, but its Required
                        // Insert Count is already on the staged bytes: a
                        // dynamic-table use abandoned here still owes the
                        // peer a Stream Cancellation (RFC 9204 Section
                        // 2.2.2.2; the error handler below emits it).
                        notePartialSectionDynamicTableUse(trailerPayload);
                        throw new Http3StreamException(
                                sm.getString("http3Processor.header.error", Long.valueOf(streamId)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    if (payloadRead < frameLen) {
                        // Would-block mid-section: stash the partial payload so
                        // the streaming read completes and decodes it before
                        // parsing any further frame header.
                        notePartialSectionDynamicTableUse(trailerPayload);
                        inBuf.setTrailerPartial(trailerPayload);
                        break readLoop;
                    }
                    trailerPayload.flip();
                    processTrailerSection(trailerPayload);
                    // A trailer section ends the message: the body is
                    // complete with it, so a shortfall against the
                    // declared Content-Length is fully observable here
                    // (RFC 9114 Section 4.1.2), even though no FIN has
                    // been seen by this path yet.
                    if (requestContentLength > 0 &&
                            totalPayloadBytes < requestContentLength) {
                        throw new Http3StreamException(
                                sm.getString(
                                        "http3Processor.bodyShorterThanContentLength",
                                        Long.valueOf(totalPayloadBytes),
                                        Long.valueOf(requestContentLength)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    inBuf.setTrailersReceived(true);
                    inBuf.setBodyComplete(true);
                    break readLoop;
                }
                case CONTROL_ONLY ->
                    // See BodyFrameKind.CONTROL_ONLY: connection error.
                    throw frameUnexpected(frameType);
                case IGNORED -> {
                    // See BodyFrameKind.IGNORED: skip the payload, keep reading.
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("http3Processor.frameIgnored",
                                Long.valueOf(streamId), Long.valueOf(frameType)));
                    }
                    long skipped = frameLen > 0 ?
                            skipFramePayload(socketWrapper, frameLen, false) : frameLen;
                    if (skipped < 0) {
                        eof = true;
                        break readLoop;
                    }
                    if (skipped < frameLen) {
                        // Would-block mid-payload: remember the remainder so the
                        // streaming read path skips it before parsing the next
                        // frame header (the bytes must not be mis-parsed as one).
                        inBuf.setSkipRemaining(frameLen - skipped);
                        break readLoop;
                    }
                }
            }
        }

        // For a content-length body, the body is complete once all expected
        // DATA payload bytes have been received. A declared length of zero
        // means the body is complete as soon as the field section has been
        // decoded: no DATA payload is expected and any non-empty DATA frame
        // would have been rejected as a Content-Length violation above
        // (RFC 9114 Section 4.1.2), so the body is complete without waiting
        // for the stream to close (matching the treatment of a fully
        // received non-zero content length).
        if (requestContentLength >= 0 && totalPayloadBytes >= requestContentLength) {
            ((Http3InputBuffer) request.getInputBuffer()).setBodyComplete(true);
        }

        // Per RFC 9114 Section 4.1.2, a request whose body is shorter than
        // Content-Length is malformed. Only enforce this when the stream was
        // cleanly closed by the client (FIN); a stream reset or connection
        // close simply aborts the request.
        if (eof && requestContentLength > 0 && totalPayloadBytes < requestContentLength
                && isStreamFin(socketWrapper)) {
            throw new Http3StreamException(
                    sm.getString("http3Processor.bodyShorterThanContentLength",
                            Long.valueOf(totalPayloadBytes), Long.valueOf(requestContentLength)),
                    Http3Error.H3_MESSAGE_ERROR, streamId);
        }
    }


    /**
     * Checks whether a frame type must never appear on a request stream:
     * frames confined to the control stream (or, for PUSH_PROMISE, never
     * sent by a client at all), plus the frame types reserved by HTTP/2
     * (RFC 9114 Sections 7.2.8 and 11.2.1). Receipt of any of them on a
     * request stream is a connection error of type H3_FRAME_UNEXPECTED
     * (RFC 9114 Sections 4.1, 7.2.3 through 7.2.8).
     *
     * @param frameType The frame type to classify
     *
     * @return {@code true} if the frame must not appear on a request stream
     */
    private static boolean isControlOnlyFrame(long frameType) {
        return frameType == Constants.H3_SETTINGS ||
                frameType == Constants.H3_CANCEL_PUSH ||
                frameType == Constants.H3_GOAWAY ||
                frameType == Constants.H3_MAX_PUSH_ID ||
                frameType == Constants.H3_PUSH_PROMISE ||
                // PRIORITY_UPDATE is confined to the client control stream
                // (RFC 9218 Section 7.2): receipt on a request stream is a
                // connection error of type H3_FRAME_UNEXPECTED, not an
                // unknown frame to ignore.
                frameType == Constants.H3_PRIORITY_UPDATE_REQUEST ||
                frameType == Constants.H3_PRIORITY_UPDATE_PUSH ||
                Constants.isHttp2ReservedFrame(frameType);
    }


    /**
     * Classification of a frame encountered on a request stream after the
     * initial request field section. The classification is shared by the
     * pre-dispatch body pre-buffering ({@link #readRequestBody}) and the
     * streaming body read ({@code Http3InputBuffer.readMoreData}); the two
     * paths handle the same kind differently only in how the outcome is
     * reported (pre-dispatch throws, the streaming read records the error -
     * {@code readMoreData} cannot throw across the servlet read contract)
     * and in where the payload goes (pre-buffer vs caller destination).
     */
    private enum BodyFrameKind {
        /** Body payload (RFC 9114 Section 4.1). */
        DATA,
        /**
         * Trailer section: a HEADERS frame after the initial request
         * HEADERS frame is the trailer field section, decoded with the
         * trailer emitter state (allow-list + MimeTrailerFields routing,
         * dynamic-table acknowledgment) and marking the body complete
         * (RFC 9114 Section 4.1).
         */
        TRAILERS,
        /**
         * SETTINGS, CANCEL_PUSH, GOAWAY, MAX_PUSH_ID and PUSH_PROMISE are
         * confined to the control stream (or, for PUSH_PROMISE, must never
         * come from a client), as are the frame types reserved by HTTP/2:
         * a connection error of type H3_FRAME_UNEXPECTED (RFC 9114 Sections
         * 4.1, 7.2.3 through 7.2.8).
         */
        CONTROL_ONLY,
        /**
         * Unknown frame type (including the 0x1f*N+0x21 application
         * reserved interval): permitted to be interleaved on a request
         * stream and MUST be ignored, skipping the payload and continuing
         * with the next frame (RFC 9114 Sections 4.1 and 9).
         */
        IGNORED
    }


    /**
     * Classifies a frame read from a request stream. Single source of the
     * frame-type decision shared by the pre-dispatch and streaming body
     * read paths (see {@link BodyFrameKind}).
     *
     * @param frameType The (already varint-decoded) frame type to classify
     *
     * @return The kind of the frame
     */
    private static BodyFrameKind classifyBodyFrame(long frameType) {
        if (frameType == Constants.H3_DATA) {
            return BodyFrameKind.DATA;
        }
        if (frameType == Constants.H3_HEADERS) {
            return BodyFrameKind.TRAILERS;
        }
        if (isControlOnlyFrame(frameType)) {
            return BodyFrameKind.CONTROL_ONLY;
        }
        return BodyFrameKind.IGNORED;
    }


    /**
     * Checks the Content-Length invariant for a DATA frame of the given
     * payload length against the running total of DATA payload bytes
     * received so far for the request. Per RFC 9114 Section 4.1.2, the sum
     * of the DATA frame lengths MUST NOT exceed Content-Length; a longer
     * body is a malformed request. Shared by the pre-dispatch and the
     * streaming body read paths, which report a violation differently
     * (see {@link BodyFrameKind}).
     *
     * @param dataReceivedSoFar The DATA payload bytes received so far for
     *                          this request (across both read paths)
     * @param frameLen          The payload length of the incoming DATA frame
     *
     * @return {@code true} if accepting this frame would overrun the
     *         declared Content-Length
     */
    private boolean dataOverrunsContentLength(long dataReceivedSoFar, long frameLen) {
        return requestContentLength >= 0 &&
                dataReceivedSoFar + frameLen > requestContentLength;
    }


    /**
     * Skips frame payload bytes from the input buffer, reading more data
     * from the socket if needed (pumping the QUIC state machine when
     * {@code pump} is set).
     *
     * @return The number of payload bytes skipped, or {@code -1} if the
     *         stream ended (reset or closed) before the payload was fully
     *         skipped. A return value below {@code frameLen} that is not
     *         {@code -1} means the read would-block; the remainder must be
     *         skipped before the next frame header is parsed.
     */
    private long skipFramePayload(SocketWrapperBase<?> socketWrapper, long frameLen,
            boolean pump) throws IOException {
        long skipped = 0;
        while (skipped < frameLen) {
            int available = inputBuffer.remaining();
            if (available > 0) {
                int toSkip = (int) Math.min(available, frameLen - skipped);
                inputBuffer.position(inputBuffer.position() + toSkip);
                skipped += toSkip;
            } else {
                int n = refillInputBuffer(socketWrapper, inputBuffer, pump);
                if (n < 0) {
                    return skipped > 0 ? skipped : -1;
                }
                if (n == 0) {
                    break;
                }
            }
        }
        return skipped;
    }


    @Override
    protected SocketState dispatchEndRequest() throws IOException {
        // This is where the asynchronous request/response cycle ends. The
        // synchronous path concludes the stream from sendResponse() and never
        // reaches this method, so for async requests the stream must be
        // concluded here, otherwise the client never sees the end of the
        // response. Any response data still buffered is flushed first
        // (asyncPostProcess() has normally already flushed it).
        SocketWrapperBase<?> socketWrapper = getSocketWrapper();
        // A trailer section no body-read path ever encountered is decoded
        // here (the async path never reaches the synchronous scan point in
        // service()), and a HEADERS or DATA frame after the trailer section
        // is an invalid frame sequence that must fail the connection (RFC
        // 9114 Section 4.1). Both scans run before the stream is torn down,
        // otherwise the trailing frames would be discarded silently.
        try {
            decodeTrailerSectionAfterResponse(socketWrapper);
            checkFramesAfterTrailer(socketWrapper);
        } catch (IOException ioe) {
            // Ignore. The stream is about to be concluded and the wrapper
            // will be closed.
        }
        try {
            flushBufferedWrite();
        }
        catch (IOException ioe) {
            // Ignore. The stream is about to be concluded and the wrapper
            // will be closed.
        }
        concludeStream(socketWrapper);
        return SocketState.CLOSED;
    }


    @Override
    protected boolean flushBufferedWrite() throws IOException {
        outputBuffer.flush();
        // Blocking QUIC writes drain the whole buffer (or throw), so no
        // data can remain once the flush succeeds. Returning true would
        // tell the async state machine that a write is still in progress
        // and would prevent the async completion from ever finishing.
        return false;
    }


    @Override
    protected boolean isTrailerFieldsReady() {
        Http3InputBuffer h3Input = (Http3InputBuffer) request.getInputBuffer();
        // Ready once the trailer section has been decoded, or once the
        // request stream has ended without one (the trailer fields are then
        // empty). Same end-of-request semantics as HTTP/2, which reports
        // ready once the stream can no longer read.
        return h3Input.isTrailersReceived() || h3Input.isStreamClosed();
    }


    @Override
    protected boolean isTrailerFieldsSupported() {
        // Response trailers are sent as a second HEADERS frame before the
        // stream is concluded (RFC 9114 Section 4.1).
        return true;
    }


    @Override
    protected boolean isReadyForWrite() {
        return true;
    }


    @Override
    protected void registerReadInterest() {
        SocketWrapperBase<?> wrapper = getSocketWrapper();
        if (wrapper != null) {
            wrapper.registerReadInterest();
        }
    }


    @Override
    protected boolean isRequestBodyFullyRead() {
        Http3InputBuffer h3Input = (Http3InputBuffer) request.getInputBuffer();
        // Unread body data is still pending delivery to the application.
        if (h3Input.available() > 0 || h3Input.getPartialDataRemaining() > 0) {
            return false;
        }
        // The end of the body has been reached: the stream was closed
        // (FIN or connection close), a TRAILERS frame was received, or
        // the declared content length was fully received.
        if (h3Input.isStreamClosed() || h3Input.isTrailersReceived() || h3Input.isBodyComplete()) {
            return true;
        }
        // The stream is being torn down (connection close): no further
        // data can arrive, so the body is treated as ended.
        QuicSocketWrapper quicWrapper = quicWrapper(getSocketWrapper());
        if (quicWrapper != null) {
            QuicStream stream = quicWrapper.getQuicStream();
            if (stream == null || stream.isFreed()) {
                return true;
            }
        }
        // Nothing more can arrive once neither a declared body (content
        // length not yet fully received) nor an undeclared body on a method
        // that commonly sends one is outstanding.
        return !isRequestBodyIndicated() &&
                !isMethodWithBody(request.getMethod());
    }


    @Override
    protected void prepareResponse() throws IOException {
        // HTTP/3: send response headers BEFORE any body data
        // This ensures HEADERS frame is written before DATA frames
        // that may be buffered by the servlet during container dispatch.
        // The wrapper guard is defensive: sendResponseHeadersInternal()
        // writes straight through the wrapper (sendHeadersFrame does
        // socketWrapper.write()), so a cleared wrapper must skip the send
        // rather than NPE. responseStarted stays false, letting a later
        // conclusion point retry once (and only once) a wrapper is present.
        SocketWrapperBase<?> socketWrapper = getSocketWrapper();
        if (socketWrapper == null) {
            return;
        }
        if (!responseStarted) {
            sendResponseHeadersInternal(socketWrapper);
        }
    }


    @Override
    protected void finishResponse() throws IOException {
        // The CLOSE action arrives once catalina's OutputBuffer.close() has
        // drained the response body, but close() does not perform a real
        // flush, so the trailing bytes can still sit in the wrapper's write
        // staging buffer. Drain it before concluding the stream, otherwise
        // the remaining DATA frames would only be written after the FIN and
        // would be lost.
        // Trailers (if any) must also be sent before the stream is
        // concluded: this method runs before sendResponse() on the
        // synchronous path and is the only conclusion point on the
        // asynchronous path (AsyncContext.complete()), so the trailers are
        // sent here and sendResponse()'s own calls are no-ops.
        SocketWrapperBase<?> socketWrapper = getSocketWrapper();
        try {
            if (!responseStarted) {
                sendResponseHeadersInternal(socketWrapper);
            }
            // Finish compression (if enabled) before anything else is
            // written: the final deflate block and the gzip trailer are
            // emitted as DATA frames here and must precede the trailers and
            // the stream FIN. Without a body the gzip member still has to be
            // emitted, matching the HTTP/1.1 GzipOutputFilter behaviour.
            outputBuffer.end();
            flushBufferedWrite();
        }
        catch (IOException ioe) {
            // Ignore. The stream is about to be concluded and the wrapper
            // will be closed.
        }
        try {
            sendResponseTrailers(socketWrapper);
        }
        catch (IOException ioe) {
            // Ignore. The stream is about to be concluded and the wrapper
            // will be closed.
        }
        concludeStream(getSocketWrapper());
    }


    @Override
    protected void ack(ContinueResponseTiming continueResponseTiming) {
        // RFC 9110 Section 10.1.1: a request that carries an
        // expect: 100-continue field (recorded by emitHeader via
        // request.setExpectation) is acknowledged with an interim 100
        // response, as the HTTP/1.1 and HTTP/2 connectors do (see
        // Http11Processor.ack / StreamProcessor.ack for the matching
        // timing filter). The interim response is an independent HEADERS
        // frame before the final response (RFC 9114 Section 4.1), like the
        // early-hints frame written by earlyHints() below.
        if (continueResponseTiming == ContinueResponseTiming.ALWAYS ||
                continueResponseTiming == protocol.getContinueResponseTimingInternal()) {
            if (!response.isCommitted() && request.hasExpectation() &&
                    !responseStarted && !ackSent) {
                SocketWrapperBase<?> socketWrapper = getSocketWrapper();
                if (socketWrapper == null) {
                    return;
                }
                // Send-once (see the ackSent field): the protocol/timing
                // configuration can change between the request being
                // received and the body reads, and more than one dispatch
                // can match the timing guard above, so the interim 100 must
                // not be re-emitted for a request that already got one —
                // same rule as Http11OutputBuffer.sendAck().
                ackSent = true;
                MimeHeaders ackHeaders = new MimeHeaders();
                ackHeaders.addValue(":status").setString("100");
                try {
                    // Blocking write: ack() runs on a container/worker
                    // thread mid-dispatch, like the final response headers.
                    // A would-block non-blocking write could not cut the
                    // interim HEADERS frame short (the wrapper stages the
                    // unsent remainder and flushes it, in order, with the
                    // next flush/blocking write - see
                    // SocketWrapperBase.writeNonBlocking); blocking instead
                    // makes the interim response reach the client now
                    // rather than some time later.
                    sendHeadersFrame(socketWrapper, ackHeaders, 256, true);
                } catch (IOException ioe) {
                    setErrorState(ErrorState.CLOSE_CONNECTION_NOW, ioe);
                }
            }
        }
    }


    @Override
    protected void earlyHints() throws IOException {
        // RFC 8297: 103 Early Hints are an interim response, delivered over
        // HTTP/3 as an interim HEADERS frame before the response HEADERS
        // (RFC 9114 Section 4.1 applies the interim-response rules of
        // [HTTP] to HTTP/3; RFC 9114 Section 7.2 only defines the frame
        // itself). This frame carries the 103 status plus the Link/Location
        // fields copied from the current response headers below. HTTP/2's
        // Stream.writeEarlyHints re-encodes the complete current response
        // header set with the status overridden; this interim frame
        // deliberately stays to the preload hint fields rather than
        // mirroring that set.
        if (responseStarted) {
            return;
        }
        SocketWrapperBase<?> socketWrapper = getSocketWrapper();
        if (socketWrapper == null) {
            return;
        }

        org.apache.tomcat.util.http.MimeHeaders h = response.getMimeHeaders();
        // Build early hints headers with 103 status per RFC 8297
        org.apache.tomcat.util.http.MimeHeaders earlyHeaders = new org.apache.tomcat.util.http.MimeHeaders();
        earlyHeaders.addValue(":status").setString("103");
        // Copy the Link/Location fields of the current response headers
        for (int i = 0; i < h.size(); i++) {
            String name = h.getName(i).toString();
            if ("link".equalsIgnoreCase(name) || "location".equalsIgnoreCase(name)) {
                earlyHeaders.addValue(name).setString(h.getValue(i).toString());
            }
        }

        // Write the early hints as a HEADERS frame with no body
        sendHeadersFrame(socketWrapper, earlyHeaders, 1024, false);
    }


    @Override
    protected void flush() throws IOException {
        outputBuffer.flush();
    }


    @Override
    protected int available(boolean doRead) {
        return request.getInputBuffer().available();
    }


    @Override
    protected boolean isReadyForRead() {
        // A stream reset by the client (RESET_STREAM) counts as "ready": the
        // next read reports the abort as an IOException, which the async read
        // machinery turns into a ReadListener.onError() event instead of
        // leaving the listener registered for a readable event that can never
        // arrive on a stream whose read side is closed.
        if (isStreamReset(getSocketWrapper())) {
            return true;
        }
        return super.isReadyForRead();
    }


    @Override
    protected void setRequestBody(ByteChunk body) {
        // HTTP/3: request body is read from DATA frames via Http3InputBuffer
        // This method is not used for HTTP/3
    }


    @Override
    protected void setSwallowResponse() {
        // HTTP/3: response swallowing is not applicable
    }


    @Override
    protected void disableSwallowRequest() {
        // HTTP/3: request swallowing is not applicable
    }


    /**
     * Reads and processes the next HTTP/3 frame.
     *
     * @return {@code true} if a complete frame was processed, {@code false} if
     *         more data is needed (caller should return LONG and wait for more data)
     * @throws IOException If I/O error
     * @throws Http3Exception If HTTP/3 protocol error
     * @throws QpackException If QPACK error
     */
    private boolean readFrame(SocketWrapperBase<?> socketWrapper) throws IOException, Http3Exception, Http3StreamException, QpackException {
        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] readFrame: reading frame header");
        }

        // Handle pending frame (reading payload for multi-chunk frames)
        if (pendingFrameType >= 0) {
            if (!fillPendingFramePayload(socketWrapper)) {
                return false;
            }
            long frameType = pendingFrameType;
            completePendingFrame();
            if (log.isDebugEnabled()) {
                log.debug("Stream [" + streamId + "] Frame type=0x" + Long.toHexString(frameType) +
                        " (" + getFrameName(frameType) + ") processed successfully");
            }
            return true;
        }

        // Read frame header: type + length, both QUIC variable-length
        // integers (RFC 9000 Section 16) as parsed by parseFrameHeader().
        int headerStatus = parseFrameHeaderWithRefill(socketWrapper);
        if (headerStatus == HEADER_ENDED) {
            // End of stream before the request head is complete (a
            // clean FIN at a frame boundary; a stream reset surfaces
            // the same way). Record it so service() can treat the
            // request as incomplete (RFC 9114 Section 4.1.2) instead
            // of waiting for data that can no longer arrive.
            requestStreamEof = true;
            return false;
        }
        if (headerStatus == HEADER_BLOCKED) {
            // Would-block with a header that may still be incomplete.
            // The parse is retried (before any refill) on the next
            // invocation, so a header completed by data that arrived
            // between invocations is accepted even if the socket then
            // never delivers another byte.
            return false;
        }

        long frameType = frameHeader[0];
        long frameLength = frameHeader[1];

        // Bound pre-field-section buffering to what the frame type can
        // become (readFrame only runs before the first HEADERS frame of a
        // request stream). Frames that can never be valid here -
        // control-stream-confined types and DATA before any HEADERS frame
        // (RFC 9114 Sections 4.1, 7.2) - are rejected at the header without
        // buffering or consuming the payload (matching the CONTROL_ONLY
        // handling in readRequestBody). A HEADERS frame is buffered, but a
        // declared section beyond the field section limit is rejected at the
        // header like the trailer path does in readRequestBody. Unknown and
        // reserved-family frames (RFC 9114 Section 9) have their payload
        // discarded as it arrives: a null pendingFramePayload makes
        // copyFramePayload skip the bytes. Without this scoping, a declared-
        // large payload of a frame that can only ever be rejected or ignored
        // would pin up to MAX_FRAME_LENGTH of heap per stream while the
        // bytes are delivered.
        if (frameType == Constants.H3_DATA || isControlOnlyFrame(frameType)) {
            throw frameUnexpected(frameType);
        }
        if (frameType == Constants.H3_HEADERS &&
                frameLength > fieldSectionWireLimit()) {
            throw new Http3StreamException(
                    sm.getString("http3Processor.header.sectionTooLarge",
                            Long.valueOf(streamId), Long.valueOf(frameLength),
                            Long.valueOf(fieldSectionWireLimit())),
                    Http3Error.H3_MESSAGE_ERROR, streamId);
        }

        pendingFrameType = frameType;
        pendingFrameLength = frameLength;
        pendingFrameRead = 0;
        pendingFramePayload = null;

        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] Frame type=0x" + Long.toHexString(frameType) +
                    " (" + getFrameName(frameType) + ") length=" + frameLength);
        }
        if (frameLength == 0) {
            // Empty frame, process immediately
            completePendingFrame();
            return true;
        }

        if (frameType == Constants.H3_HEADERS) {
            // Allocate an initial (bounded) payload buffer and continue
            // reading iteratively. The buffer grows incrementally as payload
            // bytes actually arrive (ensureFramePayloadCapacity), so a frame
            // header that declares a large length cannot force a large
            // allocation before any payload has arrived.
            pendingFramePayload = ByteBuffer.allocate(
                    (int) Math.min(frameLength, INITIAL_FRAME_PAYLOAD_SIZE));
        }
        // Unknown or reserved-family frame: the null payload discards the
        // bytes as they are read; processFrame's default branch ignores the
        // completed frame (RFC 9114 Section 9).
        if (!fillPendingFramePayload(socketWrapper)) {
            return false;
        }
        completePendingFrame();
        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] Frame type=0x" + Long.toHexString(frameType) +
                    " (" + getFrameName(frameType) + ") processed successfully");
        }
        return true;
    }


    /*
     * Parses the frame header (QUIC varint type + QUIC varint length) at the
     * buffer's current position into out[0]/out[1]. Returns false for an
     * incomplete header, restoring the position so the header is re-parsed
     * once more bytes arrive. A length above the local buffering limit
     * raises a stream-scoped error only for the frame types whose payload
     * this receiver buffers (DATA, HEADERS); every other type is either
     * rejected at the header without touching the payload or ignored with
     * the payload discarded as it streams in, none of which needs the
     * declared size to fit the limit (this only ever parses client request
     * streams).
     */
    private boolean parseFrameHeader(ByteBuffer buffer, long[] out)
            throws Http3StreamException {
        int sp = buffer.position();
        long frameType = Qpack.decodeQuicInteger(buffer);
        if (frameType == -1) {
            buffer.position(sp);
            return false;
        }
        long frameLength = Qpack.decodeQuicInteger(buffer);
        if (frameLength == -1) {
            buffer.position(sp);
            return false;
        }
        if ((frameType == Constants.H3_DATA || frameType == Constants.H3_HEADERS) &&
                frameLength > MAX_FRAME_LENGTH) {
            // HTTP/3 has no negotiated frame size limit (unlike HTTP/2's
            // SETTINGS_MAX_FRAME_SIZE), so a frame larger than this
            // implementation's limit is protocol-valid; this receiver
            // merely declines to buffer it. Only DATA and HEADERS have
            // their payload buffered on a request stream: every other
            // frame type is rejected at the header (connection-scoped,
            // nothing consumed) or ignored with the payload discarded
            // unsaved (RFC 9114 Section 9 unknown-frame rule, Section
            // 7.2.8 reserved-family padding - the same unlimited discard
            // the control stream applies in Http3ConnectionManager), so a
            // large declared length there costs nothing and must not
            // reset the padded request. The frame is confined to a request
            // stream, so only that stream is rejected via RESET_STREAM
            // (RFC 9114 Section 8 uses the same error codes for stream
            // errors) rather than failing the connection.
            throw new Http3StreamException(
                    sm.getString("http3Processor.frameError",
                            Long.valueOf(streamId)),
                    Http3Error.H3_FRAME_ERROR, streamId);
        }
        out[0] = frameType;
        out[1] = frameLength;
        return true;
    }


    // Outcomes of the shared parseFrameHeaderWithRefill() shape.
    private static final int HEADER_PARSED = 0;
    private static final int HEADER_BLOCKED = 1;
    private static final int HEADER_ENDED = 2;


    /*
     * The shared "parse-if-two-bytes-else-refill-retry" shape (the D1
     * shape) used by every frame-header read site on a request stream
     * (readFrame() and the post-trailer scans). A read boundary can land
     * inside either varint of the header, so two or more buffered bytes can
     * still form only a partial header: the parse failure - not the byte
     * count - decides when to refill. Stopping on the byte count alone
     * would park the stream forever on a partial header, since the
     * continuation bytes would never be read, and stopping on a parse
     * failure without a retry would miss a header completed by the refill.
     * The refill goes through the shared refillInputBuffer(), which flips
     * even when no data arrived, so an unread partial header stays in read
     * mode for the next invocation instead of being re-exposed as stale
     * data. The header lands in frameHeader.
     *
     * @return HEADER_PARSED once a complete header was parsed, or why the
     *         scan stopped: HEADER_BLOCKED (would-block; the parse is
     *         retried before any refill on the next invocation) or
     *         HEADER_ENDED (the stream ended at a frame boundary)
     */
    private int parseFrameHeaderWithRefill(SocketWrapperBase<?> socketWrapper)
            throws IOException, Http3StreamException {
        while (true) {
            int unread = inputBufferHasData ?
                    inputBuffer.limit() - inputBuffer.position() : 0;
            // A frame header needs at least 2 bytes, so skip the attempt
            // while the buffer cannot possibly hold one.
            if (unread >= 2 && parseFrameHeader(inputBuffer, frameHeader)) {
                return HEADER_PARSED;
            }
            int n = refillInputBuffer(socketWrapper, inputBuffer, false);
            if (n < 0) {
                return HEADER_ENDED;
            }
            if (n == 0) {
                return HEADER_BLOCKED;
            }
        }
    }


    /*
     * Reads the remaining payload of the pending frame from the socket into
     * pendingFramePayload (non-blocking; returns false on would-block, the
     * frame state is retained for the next call).
     */
    private boolean fillPendingFramePayload(SocketWrapperBase<?> socketWrapper) throws IOException {
        copyFramePayload(inputBuffer, socketWrapper, false);
        return pendingFrameRead >= pendingFrameLength;
    }


    /*
     * Destination for the frame payload bytes consumed by the shared
     * {@link #copyFramePayload(ByteBuffer, SocketWrapperBase, long, boolean,
     * FramePayloadSink)} loop. consume receives the position of the next
     * chunk inside the input buffer and the chunk size; the implementation
     * copies the window out (or discards it) and performs its own
     * bookkeeping.
     */
    private interface FramePayloadSink {
        void consume(int fromPos, int count);
    }


    /*
     * Shared refill/copy/advance loop for frame payloads: reads until
     * {@code want} bytes have been consumed from the socket into the sink,
     * refilling the input buffer as needed (pumping the QUIC state machine
     * when pump is set) and advancing the input buffer position. Returns
     * the number of bytes consumed and reports why an early stop occurred
     * via payloadEof/payloadBlocked.
     */
    private long copyFramePayload(ByteBuffer inputBuf, SocketWrapperBase<?> socketWrapper,
            long want, boolean pump, FramePayloadSink sink) throws IOException {
        payloadEof = false;
        payloadBlocked = false;
        long copied = 0;
        while (copied < want) {
            if (!inputBuf.hasRemaining()) {
                // refillInputBuffer flips before returning, so the buffer is
                // never left in write mode where stale array bytes could be
                // mis-delivered, and it flips even when no data arrived, so
                // unread bytes stay in read mode for the next invocation.
                int n = refillInputBuffer(socketWrapper, inputBuf, pump);
                if (n < 0) {
                    payloadEof = true;
                    break;
                }
                if (n == 0) {
                    payloadBlocked = true;
                    break;
                }
            }
            int chunk = (int) Math.min(want - copied, inputBuf.remaining());
            int fromPos = inputBuf.position();
            sink.consume(fromPos, chunk);
            inputBuf.position(fromPos + chunk);
            copied += chunk;
        }
        return copied;
    }


    /*
     * Variant of {@link #copyFramePayload(ByteBuffer, SocketWrapperBase,
     * long, boolean, FramePayloadSink)} that copies into an explicit
     * destination buffer.
     */
    private int copyFramePayload(ByteBuffer inputBuf, SocketWrapperBase<?> socketWrapper,
            ByteBuffer dst, int want, boolean pump) throws IOException {
        return (int) copyFramePayload(inputBuf, socketWrapper, want, pump,
                (fromPos, count) -> dst.put(inputBuf.array(), fromPos, count));
    }


    /*
     * Variant of {@link #copyFramePayload(ByteBuffer, SocketWrapperBase,
     * long, boolean, FramePayloadSink)} that copies into the incrementally
     * grown {@link #pendingFramePayload}, advancing {@link #pendingFrameRead}
     * as it goes (the bytes are merely discarded when no payload buffer was
     * allocated for this frame).
     */
    private long copyFramePayload(ByteBuffer inputBuf, SocketWrapperBase<?> socketWrapper,
            boolean pump) throws IOException {
        return copyFramePayload(inputBuf, socketWrapper,
                pendingFrameLength - pendingFrameRead, pump,
                (fromPos, count) -> {
                    if (pendingFramePayload != null) {
                        ensureFramePayloadCapacity(count);
                        pendingFramePayload.put(inputBuf.array(), fromPos, count);
                    }
                    pendingFrameRead += count;
                });
    }


    /*
     * Processes the completed pending frame and clears the pending frame
     * state.
     */
    private void completePendingFrame() throws Http3Exception, Http3StreamException, QpackException {
        processFrame(pendingFrameType);
        pendingFrameType = -1;
        pendingFrameLength = 0;
        pendingFrameRead = 0;
        pendingFramePayload = null;
    }


    /**
     * Grows {@link #pendingFramePayload}, if needed, so that at least
     * {@code needed} more payload bytes can be appended. The payload buffer
     * is allocated incrementally: it starts at
     * {@link #INITIAL_FRAME_PAYLOAD_SIZE} and at most doubles per growth,
     * never exceeding the declared frame length (itself capped by
     * {@link #MAX_FRAME_LENGTH}).
     *
     * @param needed The number of additional payload bytes that must fit
     */
    private void ensureFramePayloadCapacity(int needed) {
        if (pendingFramePayload.remaining() >= needed) {
            return;
        }
        // The buffer must hold the bytes already written PLUS the incoming
        // chunk, so grow to at least (written + needed). Doubling the
        // capacity (when it is the larger bound) keeps growth amortised.
        // The result is capped at the declared frame length, which always
        // bounds (written + needed) because written == pendingFrameRead and
        // needed <= pendingFrameLength - pendingFrameRead.
        int written = pendingFramePayload.position();
        long target = Math.min(pendingFrameLength,
                Math.max((long) pendingFramePayload.capacity() * 2,
                        (long) written + needed));
        ByteBuffer grown = ByteBuffer.allocate((int) target);
        pendingFramePayload.flip();
        grown.put(pendingFramePayload);
        pendingFramePayload = grown;
    }


    /**
     * Returns the human-readable name for the given HTTP/3 frame type.
     */
    private static String getFrameName(long frameType) {
        // All defined HTTP/3 frame types fit in a small positive int; only
        // then is the narrowing cast for the switch below safe.
        if (frameType < 0 || frameType > Integer.MAX_VALUE) {
            return "UNKNOWN";
        }
        if (Constants.isReservedFrame(frameType)) {
            // Any member of the reserved 0x1f*N+0x21 family (RFC 9114
            // Section 7.2.8), not just the 0x21 representative.
            return "RESERVED";
        }
        switch ((int) frameType) {
            case Constants.H3_DATA: return "DATA";
            case Constants.H3_HEADERS: return "HEADERS";
            case Constants.H3_CANCEL_PUSH: return "CANCEL_PUSH";
            case Constants.H3_SETTINGS: return "SETTINGS";
            case Constants.H3_PUSH_PROMISE: return "PUSH_PROMISE";
            case Constants.H3_GOAWAY: return "GOAWAY";
            case Constants.H3_MAX_PUSH_ID: return "MAX_PUSH_ID";
            case Constants.H3_PRIORITY_UPDATE_REQUEST:
            case Constants.H3_PRIORITY_UPDATE_PUSH:
                return "PRIORITY_UPDATE";
            default: return "UNKNOWN";
        }
    }


    /**
     * Processes a complete HTTP/3 frame.
     * <p>
     * The frame type is a {@code long} (QUIC variable-length integers are
     * up to 62 bits, RFC 9000 Section 16). Before dispatching it is
     * narrowed to a non-negative {@code int}; frame types that do not fit
     * are unknown and receive the default (ignore) handling required by
     * RFC 9114 Section 9.
     */
    private void processFrame(long frameType) throws Http3Exception, Http3StreamException, QpackException {
        if (log.isTraceEnabled()) {
            log.trace(sm.getString("http3Processor.processingFrame", Long.valueOf(streamId), Long.valueOf(frameType)));
        }
        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] Processing frame: " + getFrameName(frameType) + " pendingPayload=" + (pendingFramePayload != null ? pendingFramePayload.remaining() : 0) + " bytes");
        }
        // Control-stream-confined frames, DATA before any HEADERS frame,
        // PUSH_PROMISE from a client and the HTTP/2 frame types reserved by
        // HTTP/3 are all connection errors of type H3_FRAME_UNEXPECTED
        // (RFC 9114 Sections 4.1, 7.2.3 through 7.2.8, RFC 9218 Section 7.2;
        // PRIORITY_UPDATE is processed on the control stream by
        // Http3ConnectionManager). The only caller (readFrame) rejects every
        // one of them at frame-header time with this same shared predicate,
        // before any payload is buffered or completed, so none of them can
        // reach this method. The check is kept here - as a reuse of the
        // shared predicate rather than a duplication of per-type branches -
        // so the requirement stays enforced wherever a completed frame is
        // dispatched.
        if (frameType == Constants.H3_DATA || isControlOnlyFrame(frameType)) {
            throw frameUnexpected(frameType);
        }
        // Frame types that do not fit in a non-negative int cannot match
        // any defined frame type; map them to a value the switch below
        // cannot alias (RFC 9114 Section 9).
        int switchType = (frameType >= 0 && frameType <= Integer.MAX_VALUE)
                ? (int) frameType : -1;
        switch (switchType) {
            case Constants.H3_HEADERS:
                // The first HEADERS frame carries the request headers; a second
                // HEADERS frame (with no DATA following) carries request
                // trailers. Both are handled by processHeadersFrame().
                processHeadersFrame();
                break;
            // Note: HTTP/3 defines no stream frame type 0x00 other than
            // H3_DATA (rejected above). HTTP Datagrams and the Capsule
            // Protocol (RFC 9297) are not stream frames - they ride on
            // QUIC DATAGRAM frames (the RFC 9221 transport extension),
            // and this QUIC endpoint never negotiates the
            // max_datagram_frame_size transport parameter, so they
            // cannot arrive.
            default:
                if (Constants.isReservedFrame(frameType)) {
                    // Frame types of the form 0x1f*N+0x21 are reserved to
                    // exercise unknown-frame handling; every member of the
                    // family MUST be ignored identically and the payload has
                    // no defined semantics (RFC 9114 Sections 7.2.8, 11.2.1).
                    if (log.isTraceEnabled()) {
                        log.trace(sm.getString("http3Processor.reservedFrameIgnored",
                                Long.valueOf(streamId), Long.valueOf(frameType)));
                    }
                    break;
                }
                // Unknown frame type - ignore (RFC 9114 Section 9: A
                // receiver MUST ignore unknown or unrecognized values for
                // all of the undefined fields, including unknown or
                // undefined frame types).
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http3Processor.frameIgnored",
                            Long.valueOf(streamId), Long.valueOf(frameType)));
                }
                break;
        }
    }


    private void processHeadersFrame() throws Http3Exception, QpackException {
        if (pendingFramePayload == null) {
            // Zero-length HEADERS frame: no payload buffer was allocated in
            // readFrame(). Such a frame can never carry a valid field section
            // (a conformant request must at least contain the :method
            // pseudo-header), so it is a malformed message. Reject it as a
            // stream error of type H3_MESSAGE_ERROR rather than silently
            // ignoring it and waiting for data that will never decode
            // (matching HTTP/2's empty header block handling).
            throw new Http3StreamException(
                    sm.getString("http3Processor.header.empty", Long.valueOf(streamId)),
                    Http3Error.H3_MESSAGE_ERROR, streamId);
        }
        pendingFramePayload.flip();
        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder("Stream [" + streamId + "] Decoding HEADERS frame, payload=" + pendingFramePayload.remaining() + " bytes: ");
            for (int i = 0; i < pendingFramePayload.remaining(); i++) {
                sb.append(String.format("%02X ", pendingFramePayload.get(i)));
            }
            log.debug(sb.toString());
        }
        // Determine whether the field section references the dynamic
        // table (Required Insert Count > 0) from the first byte of the
        // field section prefix (RFC 9204 Section 4.5.1): the Required
        // Insert Count is an 8-bit prefix integer occupying the entire
        // first byte, so it is non-zero iff the first byte is non-zero.
        boolean ricNonZero = pendingFramePayload.remaining() > 0
                && pendingFramePayload.get(0) != 0;
        // Record before decoding: if the field section is rejected or
        // the stream is abandoned mid-decode, a Stream Cancellation
        // instruction must still be emitted (RFC 9204 Section 2.2.2.2).
        fieldSectionUsedDynamicTable = ricNonZero;
        // QpackExceptions from the decode are deliberately not caught and
        // logged here: service() catches, logs and scopes every QPACK error
        // reaching it (at the same debug level), so an inner catch would
        // only duplicate that log line.
        decodeFieldSection(pendingFramePayload);
        if (pendingFramePayload.hasRemaining()) {
            // The frame reader only dispatches complete frame payloads, so
            // unconsumed bytes mean a truncated field line or trailing
            // garbage. Per RFC 9114 Section 4.1 a header block that fails
            // to decode is a stream error of type H3_MESSAGE_ERROR.
            throw new Http3StreamException(
                    sm.getString("http3Processor.header.error", Long.valueOf(streamId)),
                    Http3Error.H3_MESSAGE_ERROR, streamId);
        }
        if (ricNonZero) {
            // The field section used dynamic table references: the
            // decoder MUST acknowledge it (RFC 9204 Section 2.2.2.1).
            // The acknowledgment releases the references, so an
            // abandonment of the stream no longer owes the peer a
            // Stream Cancellation for this section.
            noteSectionAcknowledgment();
            fieldSectionUsedDynamicTable = false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] QPACK decode successful. Headers: " + request.getMethod() + " " + request.requestURI());
        }
        // No connection flush mark is needed here: a field-section decode
        // never inserts into the dynamic table (inserts come only from
        // encoder-stream instruction processing, which marks the connection
        // itself), and the dynamic-table acknowledgment this path may queue
        // marks it too (see Http3ConnectionManager.noteSectionAcknowledgment).
        headersReceived = true;
        // RFC 9114 Section 4.2.1: the field section is complete, so the
        // concatenated cookie field (if any cookie lines were split) can
        // now be added as a single header (HTTP/2 performs this join in
        // Stream.receivedEndOfHeaders).
        if (cookieHeader != null) {
            request.getMimeHeaders().addValue("cookie").setString(cookieHeader.toString());
            cookieHeader = null;
        }
        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] Headers received: " + request.getMethod() + " " + request.requestURI().toString());
        }
    }


    /**
     * Decodes a trailer section: a second field section (HEADERS frame) on a
     * request stream (RFC 9114 Section 4.1). The fields are emitted through
     * {@link #emitHeader} with the trailer state set, which applies the
     * connector's trailer allow-list and routes regular fields into
     * {@code MimeTrailerFields}. Pseudo-headers in a trailer section are
     * rejected by the trailer-mode gate in {@link #emitHeader} (RFC 9114
     * Section 4.3).
     * The size/count limits applied are the connector's trailer limits, as
     * HTTP/2 does (Stream.receivedStartOfHeaders). The field section is
     * acknowledged when it referenced the dynamic table (RFC 9204
     * Section 2.2.2.1). Any cookie field values joined during the section
     * are flushed into the regular request headers once the section is
     * complete, as HTTP/2 does at the end of every field section
     * (Stream.receivedEndOfHeaders).
     *
     * @param payload the complete field section payload, in read mode
     *
     * @throws Http3Exception  if the section is malformed (stream error)
     * @throws QpackException  if the QPACK encoding is invalid (connection
     *                         error)
     */
    private void processTrailerSection(ByteBuffer payload)
            throws Http3Exception, QpackException {
        if (payload.remaining() == 0) {
            // Zero-length trailer section: like an empty request field
            // section, it cannot be a valid field section and must be
            // rejected rather than silently completing the request
            // (same rule as processHeadersFrame(), RFC 9114 Section 4.1).
            throw new Http3StreamException(
                    sm.getString("http3Processor.header.empty", Long.valueOf(streamId)),
                    Http3Error.H3_MESSAGE_ERROR, streamId);
        }
        // Required Insert Count > 0 signals dynamic table use (RFC 9204
        // Section 4.5.1), same detection as processHeadersFrame().
        boolean ricNonZero = payload.remaining() > 0 && payload.get(0) != 0;
        fieldSectionUsedDynamicTable = ricNonZero;
        trailerMode = true;
        try {
            // The trailer limits travel with the decode call: the decoder is
            // shared by all streams of the connection and request field
            // sections may be decoded concurrently on other worker threads,
            // so the limits must not be written to the shared instance
            // around the decode.
            decodeFieldSection(payload, protocol.getMaxTrailerCount(), protocol.getMaxTrailerSize());
            if (payload.hasRemaining()) {
                // Truncated field line or trailing garbage: a header block
                // that fails to decode is a stream error of type
                // H3_MESSAGE_ERROR (RFC 9114 Section 4.1).
                throw new Http3StreamException(
                        sm.getString("http3Processor.header.error", Long.valueOf(streamId)),
                        Http3Error.H3_MESSAGE_ERROR, streamId);
            }
            if (ricNonZero) {
                // Acknowledged: the references are released and an
                // abandonment no longer owes a Stream Cancellation
                // (see processHeadersFrame()).
                noteSectionAcknowledgment();
                fieldSectionUsedDynamicTable = false;
            }
            if (cookieHeader != null) {
                // A trailer field named cookie survives the allow-list gate
                // only when the operator explicitly allow-lists it, and the
                // cookie case of emitHeader (ungated on trailer mode, as in
                // HTTP/2) joins its value(s) into cookieHeader. HTTP/2
                // flushes the joined value into the regular request headers
                // at the end of every field section, trailer sections
                // included (Stream.receivedEndOfHeaders, invoked by
                // Http2UpgradeHandler.headersEnd), so do the same here once
                // this section is complete.
                request.getMimeHeaders().addValue("cookie").setString(cookieHeader.toString());
                cookieHeader = null;
            }
        } finally {
            trailerMode = false;
        }
    }


    /*
     * Maximum time (milliseconds) a request stream will block waiting for
     * the peer's QPACK encoder stream to deliver the inserts a field
     * section requires (RFC 9204 Section 2.1.2). Blocking is opt-in: the
     * qpackBlockedStreams property of AbstractHttp3Protocol must be positive, and
     * it also bounds the number of streams that may block concurrently on
     * one connection. With the default of 0, a field section that requires
     * not-yet-inserted entries is a decompression failure, as advertised
     * via SETTINGS_QPACK_BLOCKED_STREAMS.
     */
    private static final long QPACK_BLOCKED_STREAM_TIMEOUT_MS = 5000;


    /*
     * Decodes a field section, briefly blocking the stream when the section
     * requires dynamic table entries that the peer's encoder stream has not
     * yet delivered (RFC 9204 Section 2.2.1), if stream blocking is enabled
     * on the connector. Retrying the section after the wait is safe: no
     * header line can have been emitted before the blocked signal, because
     * the signal fires at the section prefix (Required Insert Count above
     * the decoder's insert count, before any field line is decoded) and the
     * mid-decode blocked check of QpackDecoder.getDynamicEntryByAbsolute is
     * unreachable by construction - a section's field lines decode only
     * while the insert count already covers its declared (snapshotted)
     * Required Insert Count, and every dynamic reference at or above that
     * RIC is rejected as a decompression failure (RFC 9204 Section 2.2.3)
     * before the blocked check could apply. A field section
     * that blocks a second time after the wait - the sender under-declared
     * its Required Insert Count - or one that cannot be unblocked within
     * the timeout or beyond the per-connection blocked-stream limit is
     * treated as a decompression failure.
     */
    private void decodeFieldSection(ByteBuffer payload)
            throws Http3Exception, QpackException {
        decodeFieldSection(payload, protocol.getMaxHeaderCount(),
                protocol.getMaxFieldSectionSizeInt());
    }


    /*
     * Decodes a field section applying the given limits for this decode only
     * (see QpackDecoder.decodeHeaderBlock for why the limits travel with the
     * call rather than being set on the shared decoder instance).
     */
    private void decodeFieldSection(ByteBuffer payload, int maxHeaderCount, int maxHeaderSize)
            throws Http3Exception, QpackException {
        try {
            qpackDecoder.decodeHeaderBlock(payload, this, maxHeaderCount, maxHeaderSize);
        } catch (QpackBlockedException e) {
            if (protocol.getQpackBlockedStreams() < 1 ||
                    !awaitRequiredInsertCount(e.getRequiredInsertCount())) {
                throw e;
            }
            payload.rewind();
            qpackDecoder.decodeHeaderBlock(payload, this, maxHeaderCount, maxHeaderSize);
        }
    }


    /*
     * Waits until the connection's shared QPACK decoder has processed at
     * least requiredInsertCount encoder stream inserts, up to
     * QPACK_BLOCKED_STREAM_TIMEOUT_MS. A blocked stream holds a slot out of
     * the connector's qpackBlockedStreams per-connection allowance: waiting
     * streams consume a container thread and connection state, and a peer
     * must not be able to pin an unbounded number of them.
     *
     * @param requiredInsertCount The Required Insert Count of the blocked
     *                            field section
     *
     * @return {@code true} if the required insert count was reached
     */
    private boolean awaitRequiredInsertCount(long requiredInsertCount) {
        Http3ConnectionManager manager = getConnectionManager();
        QuicConnection conn = quicConnection(getSocketWrapper());
        if (manager == null || conn == null ||
                !manager.acquireBlockedStreamSlot(conn, protocol.getQpackBlockedStreams())) {
            return false;
        }
        try {
            QpackDecoder decoder = qpackDecoder;
            long deadline = System.currentTimeMillis() + QPACK_BLOCKED_STREAM_TIMEOUT_MS;
            synchronized (decoder) {
                while (decoder.getTotalInserts() < requiredInsertCount) {
                    long remaining = deadline - System.currentTimeMillis();
                    if (remaining <= 0) {
                        return false;
                    }
                    try {
                        decoder.wait(remaining);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return false;
                    }
                }
            }
            return true;
        } finally {
            manager.releaseBlockedStreamSlot(conn);
        }
    }


    /**
     * Resets the QUIC stream with the given HTTP/3 connection error code.
     */
    private void resetStream(SocketWrapperBase<?> socketWrapper, Http3Error error) {
        if (!streamReset.compareAndSet(false, true)) {
            return;
        }
        QuicSocketWrapper quicWrapper = quicWrapper(socketWrapper);
        if (quicWrapper != null) {
            try {
                // resetStream() warns internally when the reset does not land.
                if (quicWrapper.resetStream(error.getCode()) && log.isDebugEnabled()) {
                    log.debug(sm.getString("http3Processor.streamReset",
                            Long.valueOf(streamId), Long.valueOf(error.getCode())));
                }
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http3Processor.streamReset",
                            Long.valueOf(streamId), Long.valueOf(error.getCode())), e);
                }
            }
        }
    }


    /**
     * Sends response trailers as a second HEADERS frame.
     * Per RFC 9114 Section 4.1, the trailer section of an HTTP message is
     * sent as a single HEADERS frame following the DATA frames. The trailer
     * fields are resolved from the supplier registered via
     * {@link Response#setTrailerFields}.
     */
    private void sendResponseTrailers(SocketWrapperBase<?> socketWrapper) throws IOException {
        if (trailersSent) {
            return;
        }

        Supplier<Map<String,String>> trailerFieldsSupplier = response.getTrailerFields();
        if (trailerFieldsSupplier == null) {
            return;
        }

        // Build a dedicated MimeHeaders for the trailers, filtering out any
        // header that is not allowed to appear in a trailer section.
        MimeHeaders trailerHeaders = new MimeHeaders();
        Map<String,String> trailerFields = trailerFieldsSupplier.get();
        if (trailerFields != null) {
            for (Map.Entry<String,String> trailerField : trailerFields.entrySet()) {
                String trailerName = trailerField.getKey();
                // The trailer map bypasses the container's addHeader
                // filtering, so validate the field name here: a name that
                // is not a non-empty token (RFC 7230 Section 3.2) cannot be
                // encoded and is dropped, as an invalid name is on the
                // decode path.
                if (!HttpParser.isToken(trailerName)) {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString(
                                "http3Processor.trailerInvalidName",
                                trailerName));
                    }
                    continue;
                }
                if (HeaderUtil.isHeaderDisallowedInTrailers(trailerName)) {
                    continue;
                }
                MessageBytes mb = trailerHeaders.addValue(trailerName);
                mb.setString(trailerField.getValue());
            }
        }

        // A HEADERS frame with an empty payload is not meaningful as trailers.
        if (trailerHeaders.size() == 0) {
            trailersSent = true;
            return;
        }

        // Encode trailer headers with QPACK and write them as a HEADERS
        // frame. The write must be blocking: unlike HTTP/2 (where HEADERS
        // bypass flow control and the equivalent write is safe
        // non-blocking), QUIC stream frames - HEADERS included - are
        // subject to stream flow control, and this is the last write on
        // the stream: concludeStream slides the FIN right afterwards. A
        // non-blocking write at an exhausted send window would leave the
        // frame bytes in the wrapper's write buffer and the concluded
        // stream would deliver a truncated HEADERS frame followed by FIN.
        sendHeadersFrame(socketWrapper, trailerHeaders, 1024, true);
        trailersSent = true;
    }


    /**
     * Validates received headers per RFC 9114 Sections 4.3 and 4.4.
     */
    private void validateHeadersInternal() throws Http3Exception {
        boolean hasScheme = (seenPseudoHeaders & PSEUDO_SCHEME) != 0;
        boolean hasPath = (seenPseudoHeaders & PSEUDO_PATH) != 0;

        if ((seenPseudoHeaders & PSEUDO_METHOD) == 0) {
            throw messageError("http3Processor.header.missingPseudoHeader",
                    Long.valueOf(streamId));
        }

        String method = request.getMethod();

        // RFC 9110 Section 9: the method must be a token. A :method value
        // that is not a token is an invalid pseudo-header value and makes
        // the message malformed (RFC 9114 Section 4.1.2). Only
        // syntactically valid but unknown methods are passed to the
        // container, which responds (RFC 9110 Section 15.6.1) with 501 Not
        // Implemented.
        if (!HttpParser.isToken(method)) {
            throw messageError("http3Processor.header.methodNotToken",
                    Long.valueOf(streamId), method);
        }

        // RFC 9114 Section 4.4: CONNECT requests have different pseudo-header
        // requirements. RFC 9220 Section 3 distinguishes the plain tunnel
        // CONNECT (:scheme and :path omitted) from the extended CONNECT
        // (:protocol present; :scheme and :path included like a normal
        // request - RFC 8441 Section 4 requires both, the :path is how the
        // request is routed to the targeted resource).
        // RFC 9110 Section 9.1: methods are case-sensitive; only the exact
        // uppercase token is CONNECT. A lowercase "connect" is an unknown
        // method token, passed to the container like any other, and must
        // not be subjected to the CONNECT pseudo-header shape checks.
        boolean isConnect = "CONNECT".equals(method);
        boolean hasProtocol = (seenPseudoHeaders & PSEUDO_PROTOCOL) != 0;

        if (hasProtocol && !isConnect) {
            // RFC 9220 Section 3: :protocol is only defined for CONNECT.
            // For any other method the request is malformed (RFC 9114
            // Section 4.3).
            throw messageError("http3Processor.header.protocolNotConnect",
                    Long.valueOf(streamId));
        }

        if (isConnect) {
            // RFC 9114 Section 4.4: for CONNECT requests the ":path"
            // pseudo-header field MUST be omitted and the ":authority"
            // pseudo-header field MUST be present. ":scheme" is omitted by
            // the plain tunnel CONNECT and included by the extended CONNECT
            // (RFC 9220 Section 3).
            if (!hasProtocol && hasScheme) {
                throw messageError("http3Processor.header.invalidSchemeConnect",
                        Long.valueOf(streamId), request.scheme().toString());
            }
            if (hasProtocol && !hasScheme) {
                // RFC 9220 Section 3: the extended CONNECT includes :scheme
                // (e.g. "https") alongside :protocol.
                throw messageError("http3Processor.header.protocolMissingScheme",
                        Long.valueOf(streamId));
            }
            if (hasProtocol && !hasPath) {
                // RFC 8441 Section 4 (inherited by RFC 9220 Section 3): the
                // extended CONNECT includes :path alongside :protocol; it
                // identifies the resource the CONNECT is targeted at.
                throw messageError("http3Processor.header.protocolMissingPath",
                        Long.valueOf(streamId));
            }
            if (hasProtocol && !protocol.isEnableConnectProtocol()) {
                // RFC 9220 Section 3.2: a client MUST NOT send :protocol
                // unless the server advertised ENABLE_CONNECT_PROTOCOL. A
                // request violating this is rejected.
                throw messageError("http3Processor.header.protocolNotEnabled",
                        Long.valueOf(streamId));
            }
            // :path must NOT be present for the plain tunnel CONNECT
            // (RFC 9114 Section 4.4). The extended CONNECT carries :path to
            // identify the targeted resource (RFC 9220 Section 3, RFC 8441
            // Section 4).
            if (!hasProtocol && hasPath) {
                throw messageError("http3Processor.header.connectPathPresent",
                        Long.valueOf(streamId));
            }
            if (request.serverName().isNull()) {
                // Covers both a missing :authority and one too malformed to
                // yield a host name (the latter also records the bad-request
                // note; the malformed-message handling takes precedence, as
                // in HTTP/2's receivedEndOfHeaders()).
                throw messageError("http3Processor.header.connectAuthorityMissing",
                        Long.valueOf(streamId));
            }
        } else {
            // Non-CONNECT: :scheme and :path are required
            if (!hasScheme || !hasPath) {
                throw messageError("http3Processor.header.missing",
                        Long.valueOf(streamId));
            }

            // RFC 9114 Section 4.3.1: for schemes with a mandatory authority
            // component the request must carry an authority in the
            // :authority pseudo-header and/or the Host field. Neither
            // present -> the authority is undeterminable: malformed. Same
            // serverName-presence check as HTTP/2's receivedEndOfHeaders().
            if (request.serverName().isNull()) {
                throw messageError("http3Processor.header.authorityMissing",
                        Long.valueOf(streamId));
            }

            // RFC 9114 Section 4.3.1 does not restrict the value of the
            // :scheme pseudo-header for non-CONNECT requests; any scheme is
            // accepted.

            // RFC 9114 Section 4.3.1: The :path pseudo-header MUST NOT be empty
            String path = request.requestURI().toString();
            if (path.isEmpty()) {
                throw messageError("http3Processor.header.emptyPath",
                        Long.valueOf(streamId));
            }

            // RFC 9110 Section 7.1: the request target and query string are
            // restricted character sets. Apply the same relaxed whitelists
            // HTTP/2's validateRequest() applies before dispatch, so a
            // target outside the set fails cleanly here as a malformed
            // message instead of hitting undefined behaviour inside the
            // adapter (normalization failure, dispatcher split, odd
            // %-sequences).
            HttpParser httpParser = protocol.getHttpParser();
            ByteChunk bc = request.requestURI().getByteChunk();
            for (int i = bc.getStart(); i < bc.getEnd(); i++) {
                if (httpParser.isNotRequestTargetRelaxed(bc.getBuffer()[i])) {
                    throw messageError("http3Processor.header.invalidRequestTarget",
                            Long.valueOf(streamId));
                }
            }
            String qs = request.queryString().toString();
            if (qs != null) {
                for (int i = 0; i < qs.length(); i++) {
                    if (!httpParser.isQueryRelaxed(qs.charAt(i))) {
                        throw messageError("http3Processor.header.invalidQueryString",
                                Long.valueOf(streamId));
                    }
                }
            }
        }

        // Match host name with SNI if required. An empty SNI host name means
        // the client sent no SNI, which checkSni() treats the same as
        // {@code null}.
        SocketWrapperBase<?> sw = getSocketWrapper();
        String sniHostName = (sw != null) ? sw.getSniHostName() : null;
        if (!protocol.checkSni(sniHostName, request.serverName().toString())) {
            throw messageError("http3Processor.request.sni",
                    Long.valueOf(streamId), sniHostName);
        }
    }


    /*
     * Malformed request (RFC 9114 Section 4.1.2): resolve the message from the
     * string bundle, log it at debug level and return the stream error carrying
     * the same message, so callers can use {@code throw messageError(key, args)}.
     */
    private Http3StreamException messageError(String key, Object... args) {
        String message = sm.getString(key, args);
        if (log.isDebugEnabled()) {
            log.debug(message);
        }
        return new Http3StreamException(message, Http3Error.H3_MESSAGE_ERROR, streamId);
    }


    /*
     * A frame type that must not appear in this position on the stream
     * (RFC 9114 Sections 7.2.3 to 7.2.8 and 11.2.1): resolve the message
     * from the string bundle, log it at debug level and return the
     * connection error of type H3_FRAME_UNEXPECTED carrying the same
     * message, so callers can use {@code throw frameUnexpected(frameType)}
     * (same shape as {@link #messageError}).
     */
    private Http3Exception frameUnexpected(long frameType) {
        String message = sm.getString("http3Processor.frameUnexpected",
                Long.valueOf(streamId), Long.valueOf(frameType));
        if (log.isDebugEnabled()) {
            log.debug(message);
        }
        return new Http3Exception(message, Http3Error.H3_FRAME_UNEXPECTED);
    }


    /**
     * Prepares the request for container processing.
     */
    private boolean prepareRequest() {
        request.markStartTime();
        request.protocol().setString("HTTP/3");
        return true;
    }


    /**
     * Sends the HTTP/3 response.
     */
    private void sendResponse(SocketWrapperBase<?> socketWrapper) throws IOException {
        // The stream was reset while the servlet handled the request (e.g.
        // a request body that over-ran its Content-Length, RFC 9114
        // Section 4.1.2): the response is suppressed.
        if (streamReset.get()) {
            return;
        }
        // Ensure headers were sent (may have been sent by prepareResponse())
        if (!responseStarted) {
            sendResponseHeadersInternal(socketWrapper);
        }

        // Send response body as DATA frame(s)
        sendResponseBody();

        // Send trailers if available (RFC 9114 Section 4.1)
        sendResponseTrailers(socketWrapper);

        // Conclude the stream after response is complete
        concludeStream(socketWrapper);
    }


    /**
     * Sends response headers as an HTTP/3 HEADERS frame.
     * This is called from prepareResponse() to ensure headers are sent
     * before any body data, or from sendResponse() as a fallback.
     */
    private void sendResponseHeadersInternal(SocketWrapperBase<?> socketWrapper) throws IOException {
        if (responseStarted) {
            return;
        }
        // Stream reset (see sendResponse()): no response bytes may be
        // written. Claim the response as started so later attempts
        // (including the servlet's own flushes) stay silent too.
        if (streamReset.get()) {
            responseStarted = true;
            return;
        }

        // Ensure :status pseudo-header is set (required in all responses
        // by RFC 9114 Section 4.3.2)
        if (response.getStatus() == 0) {
            response.setStatus(200);
        }
        int statusCode = response.getStatus();
        // HTTP/3 supports neither the HTTP Upgrade mechanism nor the 101
        // (Switching Protocols) informational status code (RFC 9114
        // Section 4.5). This connector declares no upgrade protocol, so a
        // committed 101 has nothing to hand the stream off to: sending it
        // would occupy the single final-response head of the stream with a
        // status the protocol forbids and leave no valid final response.
        // Report it as a 500 (RFC 9114 Section 4.1.1 recommends an
        // appropriate status code over cancelling) instead.
        if (statusCode == HttpServletResponse.SC_SWITCHING_PROTOCOLS) {
            log.warn(sm.getString("http3Processor.response.switchingProtocols",
                    Long.valueOf(streamId)));
            statusCode = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
            response.setStatus(statusCode);
            // Drop any application-supplied :status value so the rewritten
            // status is the one encoded below.
            response.getMimeHeaders().removeHeader(":status");
        }
        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] Sending response headers, status=" + statusCode);
        }

        // Build response headers, following the same logic as HTTP/2 StreamProcessor.prepareHeaders()
        org.apache.tomcat.util.http.MimeHeaders h = response.getMimeHeaders();
        MessageBytes statusMb = h.getValue(":status");
        if (statusMb == null || statusMb.isNull()) {
            h.addValue(":status").setString(String.valueOf(statusCode));
        }

        // Response compression. The decision must be taken before the
        // content-length header is added below, as enabling compression
        // clears the content length (the compressed size is unknown).
        // Responses without a body (1xx, 204, 205, 304) and HEAD responses
        // are never compressed. A request asking for compression through TE
        // is rejected as a malformed field section by emitHeader (RFC 9114
        // Section 4.2 allows only the value "trailers"), so CompressionConfig
        // can never reach the Transfer-Encoding response field it forbids.
        if (statusCode >= 200 && statusCode != 204 && statusCode != 205 &&
                statusCode != 304 && !"HEAD".equals(request.getMethod())) {
            if (protocol.useCompression(request, response)) {
                outputBuffer.enableCompression();
            }
        }

        // Check to see if a response body is present
        if (!(statusCode < 200 || statusCode == 204 || statusCode == 205 || statusCode == 304)) {
            String contentType = response.getContentType();
            if (contentType != null) {
                h.setValue("content-type").setString(contentType);
            }
            String contentLanguage = response.getContentLanguage();
            if (contentLanguage != null) {
                h.setValue("content-language").setString(contentLanguage);
            }
            // A trailer section and a Content-Length declaration are
            // mutually exclusive framing choices. The rule originates in
            // HTTP/1.1, where a trailer section only exists within the
            // chunked transfer coding and is therefore never used when the
            // body length is defined by a Content-Length field (RFC 9112
            // Sections 6.3, 7.1.2). HTTP/3 carries a trailer section as a
            // trailing HEADERS frame (RFC 9114 Section 4.1) but the same
            // rule is applied here: if trailer fields are registered, the
            // body length is unknown and the content-length header (if any)
            // must be suppressed.
            if (response.getTrailerFields() != null) {
                h.removeHeader("content-length");
                response.setContentLength(-1);
            } else {
                // Add a content-length header if a content length has been set
                // unless the application has already added one
                long contentLengthLong = response.getContentLengthLong();
                if (contentLengthLong != -1 && h.getValue("content-length") == null) {
                    h.addValue("content-length").setLong(contentLengthLong);
                }
            }
        } else {
            if (statusCode == 205) {
                response.setContentLength(0);
            } else {
                response.setContentLength(-1);
            }
            // Responses without a body must not carry DATA frames even if the
            // application writes bytes (RFC 9112 Section 6.3). Swallow them,
            // matching the VoidOutputFilter used by HTTP/1.1 and HTTP/2.
            outputBuffer.setVoidOutput(true);
        }
        // HEAD responses have headers only, never a body (RFC 9110 Section 9.3.2)
        if ("HEAD".equals(request.getMethod())) {
            outputBuffer.setVoidOutput(true);
        }

        // Add date header unless it is an informational response or the
        // application has already set one
        if (statusCode >= 200 && h.getValue("date") == null) {
            h.addValue("date").setString(org.apache.tomcat.util.http.FastHttpDateFormat.getCurrentDate());
        }

        // Server header - same rules as HTTP/2's
        // StreamProcessor.prepareHeaders(): a configured server value
        // always overrides anything the application might have set; with
        // no configured value, an application-provided one can be removed
        // on request.
        String server = protocol.getServer();
        if (server == null) {
            if (protocol.getServerRemoveAppProvidedValues()) {
                h.removeHeader("server");
            }
        } else {
            h.setValue("server").setString(server);
        }

        // Announce the configured alternative service so clients can
        // discover it without any pre-configuration (same as HTTP/2). The
        // alternative service is assumed to listen on the same port as
        // this request. An Alt-Svc header set by the application takes
        // precedence.
        String altService = protocol.getAltService();
        if (altService != null &&
                h.getValue(org.apache.coyote.http11.Constants.ALT_SVC_HEADER_NAME) == null) {
            h.addValue(org.apache.coyote.http11.Constants.ALT_SVC_HEADER_NAME)
                    .setString(altService + "=\":" + request.getServerPort() + "\"");
        }

        // RFC 9114 Section 7.2: :status is the only required pseudo-header in responses
        // Encode response headers with QPACK (encoder handles pseudo-header ordering internally)
        ByteBuffer frame = sendHeadersFrame(socketWrapper,
                response.getMimeHeaders(), 1024, true);

        responseStarted = true;
        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] HEADERS frame sent, total=" + frame.limit() + " bytes");
        }
    }


    /**
     * Sends the response body wrapped in HTTP/3 DATA frames.
     * Per RFC 9114 Section 7.2, the response body must be framed in DATA frames.
     * Body data written by the servlet during container dispatch is already
     * wrapped in DATA frames by Http3OutputBuffer.doWrite(). This method
     * ensures any remaining buffered data is flushed to the socket.
     */
    private void sendResponseBody() throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("Stream [" + streamId + "] Sending response body, bytesWritten=" + outputBuffer.getBytesWritten());
        }
        // Flush any remaining buffered response data
        // Body data written by servlet during dispatch is already sent as DATA frames
        // via Http3OutputBuffer.doWrite(). This flush ensures all data reaches the wire:
        // it flushes the compression stream (whose trailer bytes are themselves DATA
        // frames) and ends with the socket wrapper's own flush(true), which transmits
        // the framed data - no separate socket-level flush is needed here (and the
        // wrapper it flushes is exactly the socketWrapper argument, the same
        // processor-held reference).
        outputBuffer.flush();
    }


    /**
     * Concludes the bidirectional stream after the response is complete.
     * Per RFC 9114, the server must conclude (send FIN) the stream after
     * sending the complete response.
     */
    private void concludeStream(SocketWrapperBase<?> socketWrapper) {
        QuicSocketWrapper quicWrapper = quicWrapper(socketWrapper);
        if (quicWrapper != null) {
            if (quicWrapper.isStreamConcluded()) {
                return;
            }
            try {
                quicWrapper.concludeStream();
                if (log.isDebugEnabled()) {
                    log.debug("Stream [" + streamId + "] Stream concluded successfully");
                }
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http3Processor.concludeError", Long.valueOf(streamId)), e);
                }
            }
        }
    }


    /*
     * After the trailer section the request message is complete: a further
     * HEADERS or DATA frame is an invalid frame sequence and MUST be
     * treated as a connection error of type H3_FRAME_UNEXPECTED (RFC 9114
     * Section 4.1). The read paths stop at the trailer section, so without
     * this check the trailing frames would simply be discarded with the
     * stream and the peer would be told nothing; the response was already
     * sent and is unaffected. The scan is non-blocking (the normal case -
     * nothing follows the trailers - costs at most one buffer check), and
     * unknown/reserved frames keep being ignored per RFC 9114 Section 9
     * even after the trailer section.
     *
     * The mandated connection error is raised via failConnection rather
     * than a throw, so the same method serves both completion paths: the
     * synchronous one (service(), after sendResponse) and the asynchronous
     * one (dispatchEndRequest(), reached via ActionCode.CLOSE →
     * finishResponse), which has no outer catch to classify a throw.
     */
    private void checkFramesAfterTrailer(SocketWrapperBase<?> socketWrapper)
            throws IOException {
        Http3InputBuffer inBuf = (Http3InputBuffer) request.getInputBuffer();
        if (!inBuf.isTrailersReceived()) {
            return;
        }
        try {
            while (true) {
                // Parse (once at least two bytes are buffered), refilling
                // on failure - the shared parseFrameHeaderWithRefill()
                // shape (as in readFrame() and
                // decodeTrailerSectionAfterResponse()): a read boundary
                // inside a varint leaves two or more bytes that are only a
                // partial header, and giving up on the parse failure alone
                // would drop the mandated connection error for a frame
                // completed by a later read.
                if (parseFrameHeaderWithRefill(socketWrapper) !=
                        HEADER_PARSED) {
                    // Would-block or the stream ended: nothing more
                    // observable to classify.
                    return;
                }
                long frameType = frameHeader[0];
                long frameLen = frameHeader[1];
                switch (classifyBodyFrame(frameType)) {
                    case DATA, TRAILERS, CONTROL_ONLY -> {
                        failConnection(socketWrapper,
                                frameUnexpected(frameType).getError());
                        return;
                    }
                    case IGNORED -> {
                        long skipped = frameLen > 0 ? skipFramePayload(
                                socketWrapper, frameLen, false) : frameLen;
                        if (skipped < frameLen) {
                            // Would-block or the stream ended: nothing more
                            // observable to classify.
                            return;
                        }
                    }
                }
            }
        } catch (Http3StreamException e) {
            // A frame header declaring a size above this receiver's frame
            // limit is a stream-scoped condition (see parseFrameHeader);
            // the stream is already concluded, so there is nothing left to
            // reset and the connection outcome is unchanged.
            return;
        }
    }


    /*
     * Decodes and acknowledges a trailer section that no body-read path
     * ever encountered: RFC 9114 Section 4.1 permits a trailer section on
     * any message - including one without a declared body, where the
     * pre-dispatch body reader is never entered - and on any stream the
     * application never drains, where the streaming read never runs. Left
     * alone, the section is recycled undecoded: the trailer fields never
     * reach the request, and - the QPACK consequence - a section that
     * referenced the dynamic table is neither acknowledged (RFC 9204
     * Section 2.2.2.1) nor cancelled (Section 2.2.2.2), so the peer's
     * encoder must hold the referenced entries as outstanding for the life
     * of the connection (its eviction control, Section 2.1.1).
     *
     * Called once the response is complete (both the synchronous path in
     * service() and the asynchronous one in dispatchEndRequest()). The scan
     * is non-blocking (like checkFramesAfterTrailer): frames fully
     * available in the buffer / already delivered by the poll thread are
     * processed, and anything short of that is abandoned - a partially
     * observable section still owes the peer a Stream Cancellation when
     * its Required Insert Count is visible in the bytes received (exactly
     * as notePartialSectionDynamicTableUse() records it for the streaming
     * paths). Frames other than a second HEADERS frame stop the scan
     * without new enforcement: the frame-level violations they would
     * represent are already handled - or deliberately not read - by the
     * live read paths, and re-classifying them after the response has been
     * answered would change outcomes rather than restore the lost QPACK
     * bookkeeping.
     */
    private void decodeTrailerSectionAfterResponse(
            SocketWrapperBase<?> socketWrapper) throws IOException {
        if (socketWrapper == null) {
            return;
        }
        Http3InputBuffer inBuf =
                (Http3InputBuffer) request.getInputBuffer();
        if (inBuf.isTrailersReceived()) {
            // The read paths decoded the trailer section (and acknowledged
            // it); the after-trailer scan owns anything that follows.
            return;
        }
        if (inBuf.trailerPayload != null) {
            // A partially read trailer section was staged by the pre-
            // dispatch read and will never be completed (nothing reads
            // this stream again). Any dynamic-table use was already
            // recorded from its first byte; report the abandonment now so
            // the peer receives its Stream Cancellation rather than a
            // silent drop at recycle.
            noteAbandonedDynamicTableUse();
            inBuf.trailerPayload = null;
            return;
        }
        if (inBuf.partialDataRemaining > 0 || inBuf.pendingSkipRemaining > 0) {
            // Mid-frame: DATA payload bytes still owed, or an ignored
            // frame's skip still in progress. Parsing anything from here
            // would mis-consume them as a frame header.
            return;
        }
        try {
            // Parse (once at least two bytes are buffered), refilling
            // on failure - the shared parseFrameHeaderWithRefill() shape:
            // a read boundary inside a varint leaves two or more bytes
            // that are only a partial header, and giving up on the byte
            // count alone would miss a header completed by the refill.
            if (parseFrameHeaderWithRefill(socketWrapper) != HEADER_PARSED) {
                // Would-block or the stream ended: nothing more is
                // observable to decode.
                return;
            }
            long frameType = frameHeader[0];
            long frameLen = frameHeader[1];
            switch (classifyBodyFrame(frameType)) {
                case TRAILERS -> {
                    long wireLimit = fieldSectionWireLimit();
                    if (frameLen > wireLimit) {
                        // Malformed (declared beyond the field section
                        // limit); the response has been answered - stop.
                        // The section is abandoned without ever being
                        // consumed, so the peer's encoder is owed the
                        // Stream Cancellation unconditionally (RFC 9204
                        // Section 2.2.2.2): its Required Insert Count was
                        // never observable here but the entries it
                        // references are outstanding until released.
                        if (!streamCancellationSent) {
                            streamCancellationSent = true;
                            noteStreamCancellation();
                        }
                        return;
                    }
                    // Safe casts: parseFrameHeader rejects HEADERS frames
                    // above MAX_FRAME_LENGTH at the header.
                    ByteBuffer trailerPayload =
                            ByteBuffer.allocate((int) frameLen);
                    int payloadRead = copyFramePayload(inputBuffer,
                            socketWrapper, trailerPayload, (int) frameLen, false);
                    if (payloadRead < frameLen) {
                        // Would-block or FIN mid-section: the section will
                        // never be decoded. Record any dynamic-table use
                        // observable from the first received byte and
                        // report the abandonment (RFC 9204 Section
                        // 2.2.2.2).
                        notePartialSectionDynamicTableUse(trailerPayload);
                        noteAbandonedDynamicTableUse();
                        return;
                    }
                    trailerPayload.flip();
                    processTrailerSection(trailerPayload);
                    inBuf.setTrailersReceived(true);
                    inBuf.setBodyComplete(true);
                }
                default -> {
                    // DATA before a trailer on a stream with no (further)
                    // body, or a control-stream-confined frame: nothing to
                    // decode here (see the comment on the method).
                }
            }
        } catch (Http3Exception e) {
            // Malformed frame header or trailer section after the response
            // has been answered: report the abandonment (emitted by
            // handleStreamError) for any section that referenced the
            // dynamic table before failing.
            handleStreamError(socketWrapper, e.getError());
        } catch (QpackValueTooLargeException e) {
            // RFC 9204 Section 7.4: stream-scoped (see service()).
            handleStreamError(socketWrapper,
                    Http3Error.H3_QPACK_DECOMPRESSION_FAILED);
        } catch (QpackException e) {
            // Invalid QPACK encoding is a connection error (RFC 9204
            // Section 2.2.3) even this late: the shared decoder may have
            // been left behind, so the connection - not just this
            // concluded stream - must not continue.
            failConnection(socketWrapper,
                    Http3Error.H3_QPACK_DECOMPRESSION_FAILED);
        }
    }


    // ------------------------------------------------- HeaderEmitter

    @Override
    public void emitHeader(String name, String value) throws QpackException, Http3Exception {
        // RFC 9114 Section 4.2: field names MUST be tokens containing only
        // lowercase ASCII characters; a message containing uppercase
        // characters in field names MUST be treated as malformed (stream
        // error H3_MESSAGE_ERROR). Check before lowercasing so that
        // uppercase spellings are rejected consistently whether the name
        // arrived Huffman-encoded or as a raw literal: this message layer
        // is the single place where HTTP syntax is classified, matching
        // HTTP/2 (HpackDecoder performs no character validation; all of
        // it lives in Stream.emitHeader).
        boolean hasUppercase = false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                hasUppercase = true;
                break;
            }
        }
        if (hasUppercase) {
            throw new Http3StreamException(
                    sm.getString("http3Processor.header.invalidNameUppercase",
                            Long.valueOf(streamId), name),
                    Http3Error.H3_MESSAGE_ERROR, streamId);
        }
        name = name.toLowerCase(Locale.US);

        // RFC 9114 Section 4.1.2: a message with invalid characters in a
        // field value is malformed. Enforce the same per-position rule as
        // HTTP/2 (Stream.emitHeader) here rather than in the QPACK layer,
        // so validation does not depend on whether the value arrived
        // Huffman-encoded or as a raw literal.
        if (value != null) {
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                if (i == 0) {
                    if (!HttpParser.isFieldVChar(c)) {
                        throw new Http3StreamException(
                                sm.getString(
                                        "http3Processor.header.value.invalidCharacterStart",
                                        Long.valueOf(streamId),
                                        Character.toString(c), value),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                } else if (i == value.length() - 1) {
                    if (!HttpParser.isFieldVChar(c)) {
                        throw new Http3StreamException(
                                sm.getString(
                                        "http3Processor.header.value.invalidCharacterEnd",
                                        Long.valueOf(streamId),
                                        Character.toString(c), value),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                } else if (!HttpParser.isFieldContent(c)) {
                    throw new Http3StreamException(
                            sm.getString(
                                    "http3Processor.header.value.invalidCharacter",
                                    Long.valueOf(streamId),
                                    Character.toString(c), value),
                            Http3Error.H3_MESSAGE_ERROR, streamId);
                }
            }
        }

        // RFC 9114 Section 4.2: Validate header field wire format.
        // Header field names MUST be tokens (RFC 9110 Section 5.6.2).
        // Header field values MUST be valid UTF-8 (already handled by QPACK decoding).
        if (!name.startsWith(":")) {
            if (!HttpParser.isToken(name)) {
                throw new Http3StreamException(
                        sm.getString("http3Processor.header.invalidName",
                                Long.valueOf(streamId), name),
                        Http3Error.H3_MESSAGE_ERROR, streamId);
            }
            // RFC 9114 Section 4.2: connection-specific field names are not
            // allowed in HTTP/3; any message containing one is malformed.
            // Deliberately the base Http3Exception carrying the otherwise
            // connection-level code H3_MESSAGE_ERROR (rather than
            // Http3StreamException): service() classifies the failure by
            // error code (Http3Error.isStreamError()), not by exception
            // type, so this resets only the affected stream, as RFC 9114
            // Section 4.1.2 requires for malformed messages. The same
            // intent applies to the other base-Http3Exception
            // H3_MESSAGE_ERROR throws below.
            if (CONNECTION_SPECIFIC_HEADERS.contains(name)) {
                throw new Http3Exception(
                        sm.getString("http3Processor.header.connection",
                                Long.valueOf(streamId), name),
                        Http3Error.H3_MESSAGE_ERROR);
            }
            // RFC 9114 Section 4.2: TE header is only allowed with value
            // "trailers". Stream reset by design (see the note on the
            // connection-specific check above).
            if ("te".equals(name) && value != null && !"trailers".equals(value)) {
                throw new Http3Exception(
                        sm.getString("http3Processor.header.invalid", Long.valueOf(streamId), name),
                        Http3Error.H3_MESSAGE_ERROR);
            }
            if (trailerMode && !protocol.isTrailerHeaderAllowed(name)) {
                // Processing trailers and the header is not in the allowed
                // list: drop it silently, matching HTTP/2 (Stream.java
                // 426-429, which delegates to the connector's
                // allowedTrailerHeaders).
                return;
            }
        }

        if (name.startsWith(":")) {
            // Pseudo-header
            if (trailerMode) {
                // RFC 9114 Section 4.3: pseudo-header fields MUST NOT
                // appear in trailer sections; a message that violates the
                // pseudo-header rules is malformed and MUST be treated as
                // a stream error of type H3_MESSAGE_ERROR (RFC 9114
                // Sections 4.1.2, 4.3). This gate is unconditional on
                // trailerMode: the pseudoHeadersDone check below only
                // catches pseudo-headers that follow a regular field, so
                // a request whose field section carried nothing but
                // pseudo-headers would otherwise let a trailer apply a
                // pseudo-header the request did not contain. HTTP/2
                // rejects the same input via its header-state gate
                // (Stream.emitHeader). (Stream reset by design with the
                // base Http3Exception, see the note on the
                // connection-specific check above.)
                throw new Http3Exception(
                        sm.getString("http3Processor.header.invalid", Long.valueOf(streamId), name),
                        Http3Error.H3_MESSAGE_ERROR);
            }
            if (pseudoHeadersDone) {
                // RFC 9114 Section 7.1: All pseudo-header fields MUST appear
                // before regular header fields. A request that violates this
                // is malformed: a stream error of type H3_MESSAGE_ERROR
                // (stream reset by design with the base Http3Exception, see
                // the note on the connection-specific check above).
                throw new Http3Exception(
                        sm.getString("http3Processor.header.invalid", Long.valueOf(streamId), name),
                        Http3Error.H3_MESSAGE_ERROR);
            }
            // Per RFC 9114 Section 4.3, all pseudo-header fields MUST appear
            // before regular header fields (enforced above) and MUST NOT be
            // duplicated; no specific ordering between pseudo-headers is
            // required.
            int pseudoBit = pseudoHeaderBit(name);
            if (pseudoBit == 0) {
                // Per RFC 9114 Section 4.3, a request containing an
                // undefined pseudo-header field is malformed and MUST be
                // treated as a stream error of type H3_MESSAGE_ERROR
                // (RFC 9114 Section 4.1.2).
                throw new Http3StreamException(
                        sm.getString("http3Processor.header.invalid", Long.valueOf(streamId), name),
                        Http3Error.H3_MESSAGE_ERROR, streamId);
            }
            if ((seenPseudoHeaders & pseudoBit) != 0) {
                // RFC 9114 Section 4.3: Duplicate pseudo-header is a stream
                // error (stream reset by design with the base
                // Http3Exception, see the note on the connection-specific
                // check above).
                throw new Http3Exception(
                        sm.getString("http3Processor.header.duplicate", Long.valueOf(streamId), name),
                        Http3Error.H3_MESSAGE_ERROR);
            }
            seenPseudoHeaders |= pseudoBit;
            switch (name) {
                case ":method":
                    request.setMethod(value);
                    break;
                case ":scheme":
                    // RFC 3986: the :scheme value must be a valid URI
                    // scheme (same HttpParser.isScheme check as HTTP/2).
                    // An invalid pseudo-header value makes the message
                    // malformed (RFC 9114 Section 4.1.2).
                    if (!HttpParser.isScheme(value)) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.header.invalidScheme",
                                        Long.valueOf(streamId), value),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    request.scheme().setString(value);
                    // Connector policy ported from HTTP/2 (Stream.java
                    // :scheme case): unless allowSchemeMismatch is set, the
                    // scheme must be consistent with the TLS state of the
                    // connector. QUIC always uses TLS, so "https" is
                    // expected.
                    if (!protocol.getAllowSchemeMismatch() &&
                            "https".equals(value) != protocol.isSSLEnabled()) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.header.inconsistentScheme",
                                        Long.valueOf(streamId), value,
                                        Boolean.toString(protocol.isSSLEnabled())),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    break;
                case ":path":
                    // Split query string from path, same as HTTP/2 Stream.java
                    if (value.isEmpty()) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.header.invalid", Long.valueOf(streamId), name),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    int queryStart = value.indexOf('?');
                    String uri;
                    if (queryStart == -1) {
                        uri = value;
                    } else {
                        uri = value.substring(0, queryStart);
                        String query = value.substring(queryStart + 1);
                        request.queryString().setString(query);
                    }
                    // Set the URI as bytes so path parameters are processed
                    // and normalization security checks are performed
                    byte[] uriBytes = uri.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
                    request.requestURI().setBytes(uriBytes, 0, uriBytes.length);
                    break;
                case ":authority":
                    // Parse authority to extract server name and port, same as HTTP/2
                    parseAuthority(value);
                    break;
                case ":protocol":
                    // RFC 9220 Section 3: extended CONNECT. The :protocol
                    // value is a distinct pseudo-header, not the scheme (the
                    // :scheme pseudo-header is carried separately, e.g.
                    // "https"), so record it as a dedicated request
                    // attribute instead of overwriting the scheme. Presence
                    // rules (CONNECT method only, negotiated
                    // ENABLE_CONNECT_PROTOCOL setting) are enforced in
                    // validateHeadersInternal() once the method is known.
                    request.setAttribute(
                            Constants.ATTR_EXTENDED_CONNECT_PROTOCOL, value);
                    break;
                default:
                    break;
            }
        } else {
            pseudoHeadersDone = true;
            // Track content-length for request body validation. Like every
            // other special case here the case is gated only by the trailer
            // allow-list above (as in HTTP/2's Stream.emitHeader, which
            // gates no switch case on the header state): a field the
            // operator explicitly allowed as a trailer is processed like
            // any field of its name, with the consequences.
            if ("content-length".equals(name)) {
                if (requestContentLength >= 0) {
                    // Per RFC 9114 Section 4.2, a request with multiple
                    // Content-Length header fields is malformed.
                    throw new Http3StreamException(
                            sm.getString("http3Processor.header.duplicate", Long.valueOf(streamId), name),
                            Http3Error.H3_MESSAGE_ERROR, streamId);
                }
                try {
                    long parsedContentLength = Long.parseLong(value);
                    if (parsedContentLength < 0) {
                        throw new NumberFormatException(value);
                    }
                    requestContentLength = parsedContentLength;
                } catch (NumberFormatException e) {
                    // Invalid content-length - a malformed request
                    // (RFC 9114 Section 4.1.2)
                    throw new Http3StreamException(
                            sm.getString("http3Processor.header.invalid", Long.valueOf(streamId), name),
                            Http3Error.H3_MESSAGE_ERROR, streamId);
                }
                request.getMimeHeaders().addValue(name).setString(value);
            } else if ("host".equals(name)) {
                // RFC 9114 Section 4.3.1: the authority may be carried by
                // the Host field when :authority is absent; when both are
                // present they must agree. Same first-set / consistency
                // compare / duplicate-reject rules as HTTP/2
                // (Stream.emitHeader). The value is consumed into
                // serverName/serverPort and is not exposed as a regular
                // header, again matching HTTP/2.
                if (request.serverName().isNull()) {
                    // No :authority (or a :authority too malformed to set
                    // it - the note records that for the 400 path). First
                    // Host field: use it.
                    hostHeaderSeen = true;
                    parseAuthority(value);
                } else if (!hostHeaderSeen) {
                    // First Host field: must be consistent with :authority.
                    hostHeaderSeen = true;
                    compareAuthority(value);
                } else {
                    // Multiple Host fields - malformed.
                    throw new Http3StreamException(
                            sm.getString("http3Processor.header.duplicate", Long.valueOf(streamId), name),
                            Http3Error.H3_MESSAGE_ERROR, streamId);
                }
            } else if ("cookie".equals(name)) {
                // RFC 9114 Section 4.2.1: a decompressed field section
                // containing multiple cookie field lines must have them
                // concatenated into a single field value with the "; "
                // delimiter before being passed to a non-HTTP/3 context
                // (same as HTTP/2, Stream.emitHeader cookie case). The
                // joined field is added once the section is complete.
                if (cookieHeader == null) {
                    cookieHeader = new StringBuilder();
                } else {
                    cookieHeader.append("; ");
                }
                cookieHeader.append(value);
            } else if ("priority".equals(name)) {
                // Extensible priorities (RFC 9218 Section 5): the Priority
                // request header field is consumed as priority signal input
                // and is not forwarded to the application (same as HTTP/2,
                // Stream.java 532-547). Invalid values (not a valid
                // Structured Fields Dictionary, wrong types, out of range)
                // are ignored per RFC 9218 Section 4; the field itself is
                // consumed either way.
                try {
                    Priority p = Priority.parsePriority(new StringReader(value));
                    // A PRIORITY_UPDATE (pre-open buffered frame applied at
                    // wiring, or a live update) is the most recently received
                    // signal and overrides any other, including this request's
                    // own (older) Priority header field (RFC 9218 Section 7).
                    // The field is consumed (not forwarded) either way. The
                    // flag test and the stores are one atomic step under the
                    // signal lock, so an update landing here cannot be
                    // overwritten by this (older) value.
                    synchronized (prioritySignalLock) {
                        if (!priorityFromUpdate) {
                            setUrgency(p.getUrgency());
                            setIncremental(p.getIncremental());
                        }
                    }
                } catch (IOException ioe) {
                    // Not possible with StringReader
                } catch (IllegalArgumentException iae) {
                    if (log.isTraceEnabled()) {
                        log.trace(sm.getString("http3Processor.priorityHeaderInvalid",
                                Long.valueOf(streamId), value), iae);
                    }
                }
            } else if (trailerMode) {
                // Trailer fields go into the dedicated trailer fields
                // container, not the regular request headers (same as
                // HTTP/2, Stream.java 556-558).
                request.getMimeTrailerFields().addValue(name).setString(value);
            } else {
                // 100-continue expectation (RFC 9110 Section 10.1.1): set
                // the coyote expectation flag so ack() can send the interim
                // response (same as HTTP/2, Stream.emitHeader default
                // case). The field itself is still forwarded to the
                // application, also as in HTTP/2.
                if ("expect".equals(name) && "100-continue".equals(value)) {
                    request.setExpectation(true);
                }
                request.getMimeHeaders().addValue(name).setString(value);
            }
        }

        if (log.isTraceEnabled()) {
            log.trace(sm.getString("http3Processor.header.debug", Long.valueOf(streamId), name, value));
        }
    }


    /**
     * Parses the :authority header value to extract server name and port.
     * Same logic as HTTP/2 Stream.parseAuthority().
     */
    private void parseAuthority(String value) {
        int i;
        try {
            i = Host.parse(value);
            if (i > -1) {
                request.serverName().setString(value.substring(0, i));
                request.setServerPort(Integer.parseInt(value.substring(i + 1)));
            } else {
                request.serverName().setString(value);
            }
        } catch (IllegalArgumentException iae) {
            // Bad :authority header
            request.setNote(org.apache.coyote.Request.NOTE_BAD_REQUEST, Boolean.TRUE);
        }
    }


    /**
     * Checks that a Host header value is consistent with the authority
     * already recorded from :authority. Same logic as HTTP/2
     * Stream.compareAuthority(): an inconsistent value is a malformed
     * message (stream error); a value that cannot be parsed at all records
     * the bad-request note (answered with 400 by service()).
     */
    private void compareAuthority(String value) throws Http3StreamException {
        int i;
        try {
            i = Host.parse(value);
            if (i == -1 &&
                    (!value.equals(request.serverName().getString()) || request.getServerPort() != -1) ||
                    i > -1 && ((!value.substring(0, i).equals(request.serverName().getString()) ||
                            Integer.parseInt(value.substring(i + 1)) != request.getServerPort()))) {
                // Host value inconsistent with :authority
                throw new Http3StreamException(
                        sm.getString("http3Processor.host.inconsistent", Long.valueOf(streamId), value,
                                request.serverName().getString(),
                                Integer.toString(request.getServerPort())),
                        Http3Error.H3_MESSAGE_ERROR, streamId);
            }
        } catch (IllegalArgumentException iae) {
            // Bad :authority / host header -> 400 response
            request.setNote(org.apache.coyote.Request.NOTE_BAD_REQUEST, Boolean.TRUE);
        }
    }


    // ------------------------------------------------- Processor interface

    @Override
    public Request getRequest() {
        return request;
    }


    @Override
    public void recycle() {
        // Stop being the RFC 9218 priority consumer for this stream before
        // the per-stream state is discarded, so PRIORITY_UPDATE frames for
        // an already closed stream are buffered (with the ConnectionState
        // bounds) rather than applied to a recycled processor instance.
        Http3ConnectionManager.ConnectionState state = this.connectionState;
        if (state != null && streamId >= 0) {
            state.unregisterPriorityConsumer(this, streamId);
        }
        connectionState = null;
        // Restore the construction-time fallback decoder. service() replaces
        // this field with the shared decoder of the current connection; that
        // decoder's dynamic table can hold field names and values decoded
        // from the previous connection's requests and must not stay
        // reachable from this pooled processor once the connection is
        // closed (service() re-installs the shared decoder on the next
        // dispatch). Mirrors the connectionState cleanup above.
        qpackDecoder = new QpackDecoder();
        protocol.configureDecoder(qpackDecoder);
        // Drop the RFC 9218 priority signal of the previous request: it is
        // set per request from the Priority header field / PRIORITY_UPDATE
        // frames, and must not leak into the next request handled by this
        // recycled processor before that request's own field section arrives.
        synchronized (prioritySignalLock) {
            urgency = Priority.DEFAULT_URGENCY;
            incremental = Priority.DEFAULT_INCREMENTAL;
            priorityFromUpdate = false;
        }

        // A connection-level frame error (a control-only frame on the
        // request stream) was seen while the request body was read during
        // an async dispatch (RFC 9114: connection error). The synchronous
        // path is already handled in service().
        Http3Error bodyFrameError = this.bodyFrameError;
        if (bodyFrameError != null) {
            this.bodyFrameError = null;
            SocketWrapperBase<?> socketWrapper = getSocketWrapper();
            if (socketWrapper != null) {
                failConnection(socketWrapper, bodyFrameError);
            }
        }

        // Reset the request/response objects (headers, status, etc.) so that
        // state does not leak into the next request handled by this processor.
        getAdapter().checkRecycled(request, response);
        super.recycle();
        // Reset the Coyote request/response. HTTP/1.1 does this via
        // Http11InputBuffer.recycle() / Http11OutputBuffer.recycle(); the HTTP/3
        // buffers do not, so it must be done here. Without this, response
        // headers (content-length, etag, date, ...) and request state from the
        // previous request leak into the next one.
        request.recycle();
        response.recycle();

        headersReceived = false;
        requestStreamEof = false;
        responseStarted = false;
        ackSent = false;
        trailersSent = false;
        pseudoHeadersDone = false;
        seenPseudoHeaders = 0;
        hostHeaderSeen = false;
        trailerMode = false;
        cookieHeader = null;
        fieldSectionUsedDynamicTable = false;
        streamCancellationSent = false;
        // Drop any per-response compression state so the next request
        // handled by this (pooled) processor starts uncompressed. Runs
        // before the streamReset flag below is cleared so that, on a reset
        // stream, the close inside emits its trailer bytes into the
        // swallow path instead of a dead QUIC stream.
        outputBuffer.resetCompression();
        streamReset.set(false);
        pendingFrameType = -1;
        pendingFrameLength = 0;
        pendingFrameRead = 0;
        pendingFramePayload = null;
        inputBuffer.clear();
        inputBufferHasData = false;
        requestContentLength = -1;
        totalDataReceived = 0;

        // Reset input buffer data
        if (request.getInputBuffer() instanceof Http3InputBuffer h3Input) {
            h3Input.reset();
        }

        // Reset output buffer byte counter so access log reports per-request bytes
        outputBuffer.resetBytesWritten();
        // Reset void output so a 204/304/HEAD response does not suppress the
        // body of the next request handled by this processor
        outputBuffer.resetVoidOutput();
    }


    @Override
    protected Log getLog() {
        return log;
    }


    @Override
    protected ServletConnection getServletConnection() {
        SocketWrapperBase<?> wrapper = getSocketWrapper();
        if (wrapper != null) {
            return wrapper.getServletConnection("h3", "");
        }
        return null;
    }


    @Override
    protected String getProtocolRequestId() {
        // The QUIC stream ID identifies the request within the connection,
        // mirroring HTTP/2's StreamProcessor which returns the stream ID.
        return Long.toString(streamId);
    }


    @Override
    public void pause() {
        // HTTP/3: pause is handled at the QUIC level by flow control.
        // No explicit pause mechanism needed.
    }


    // ------------------------------------------------- Accessors



    void setStreamId(long streamId) {
        this.streamId = streamId;
    }


    /**
     * Returns the urgency parameter (RFC 9218 Section 4.1) of the current
     * priority signal for this stream. Ranges 0 to 7 (0 = highest
     * precedence).
     */
    int getUrgency() {
        return urgency;
    }


    /**
     * Updates the urgency parameter (RFC 9218 Section 4.1) of the priority
     * signal for this stream.
     */
    void setUrgency(int urgency) {
        this.urgency = urgency;
    }


    /**
     * Returns the incremental parameter (RFC 9218 Section 4.2) of the
     * current priority signal for this stream.
     */
    boolean getIncremental() {
        return incremental;
    }


    /**
     * Updates the incremental parameter (RFC 9218 Section 4.2) of the
     * priority signal for this stream.
     */
    void setIncremental(boolean incremental) {
        this.incremental = incremental;
    }


    /**
     * Applies a complete priority signal (RFC 9218: a Priority header field
     * value or the Priority Field Value of a PRIORITY_UPDATE frame carries
     * the complete set of parameters, so the signal is applied as a whole;
     * omitted parameters revert to the RFC defaults). May be called from a
     * different thread than this stream's worker (PRIORITY_UPDATE arrives
     * via Http3ConnectionManager).
     */
    void setPriority(Priority priority) {
        // Any PRIORITY_UPDATE that lands here is the most recently received
        // signal and wins over the request's own Priority header field
        // (RFC 9218 Section 7), whether it was buffered ahead of the stream
        // opening or arrives live. The lock orders this against the header
        // path's check-then-act: if the header path wins the lock first it
        // sees no update flag and stores its value, which this (newer)
        // update then overwrites; if it loses, it observes the flag and
        // skips. Either way the update is never lost.
        synchronized (prioritySignalLock) {
            priorityFromUpdate = true;
            setUrgency(priority.getUrgency());
            setIncremental(priority.getIncremental());
        }
    }


    /**
     * Sets the shared QPACK decoder from the connection manager.
     * Per RFC 9204, all streams on a connection share a single decoder.
     */
    void setSharedQpackDecoder(QpackDecoder decoder) {
        if (decoder != null) {
            this.qpackDecoder = decoder;
        }
    }


    /**
     * Sets the per-connection state, which carries the peer SETTINGS needed
     * when encoding response field sections (RFC 9114 Section 4.2.2).
     * Once set, this processor is also registered as the RFC 9218 priority
     * consumer for its stream ID so that PRIORITY_UPDATE frames (RFC 9218
     * Section 7.2) that arrived on the control stream before this request
     * stream opened can be applied to it (see ConnectionState).
     */
    void setConnectionState(Http3ConnectionManager.ConnectionState connectionState) {
        this.connectionState = connectionState;
        if (connectionState != null && streamId >= 0) {
            connectionState.registerPriorityConsumer(this, streamId);
        }
    }


    QpackDecoder getQpackDecoder() {
        return qpackDecoder;
    }


    /**
     * Input buffer for HTTP/3 stream data.
     * Accumulates DATA frame payloads for servlet consumption.
     * Supports streaming reads from the QUIC stream.
     */
    private static class Http3InputBuffer implements InputBuffer {
        private final Http3Processor processor;
        private final java.util.ArrayList<ByteBuffer> dataBuffers = new java.util.ArrayList<>();
        private int totalRemaining = 0;
        private int currentBufferIndex = 0;
        private boolean streamClosed = false;
        private boolean trailersReceived = false;

        // Track a DATA frame that readRequestBody started but could not finish
        // (non-blocking read would-blocked). These are payload bytes still
        // outstanding in the stream that MUST be read (not skipped) and treated
        // as a continuation of the request body before the next frame header.
        private int partialDataRemaining = 0;

        // Track an ignored (unknown/reserved) frame whose payload skip was
        // interrupted by a would-block. These payload bytes MUST be skipped
        // before the next frame header is parsed, so they are not mis-read
        // as one (RFC 9114 Sections 4.1 and 9). Long like the declared
        // frame length: ignored frames are discarded without buffering and
        // carry no local size limit.
        private long pendingSkipRemaining = 0;

        // True once readRequestBody has received the complete request body
        // (all DATA bytes for a content-length body, or a TRAILERS frame).
        private boolean bodyComplete = false;

        // Partial payload of an in-progress trailer section (a second
        // HEADERS frame on the request stream). Held in write mode with the
        // bytes read so far; the streaming read completes it and decodes it
        // before parsing any further frame header. Null when no trailer
        // section is in progress.
        private ByteBuffer trailerPayload = null;

        // Pooled delivery buffer for doRead(). Created lazily on the first
        // body read (most streams have no body) and reused for every read on
        // every stream this (pooled) processor serves, like the single pooled
        // read buffer of Http11InputBuffer. Each doRead() call injects a fresh
        // duplicate() view of it to the caller, so per-read allocation is
        // limited to the small view object.
        private ByteBuffer deliveryBuffer = null;


        Http3InputBuffer(Http3Processor processor) {
            this.processor = processor;
        }


        /**
         * Records the number of DATA frame payload bytes that are still
         * outstanding in the stream after a partially-read frame. The streaming
         * read ({@link #readMoreData}) will read and deliver these bytes before
         * parsing the next frame header.
         *
         * @param n the remaining payload bytes of the in-progress DATA frame
         */
        void setPartialDataRemaining(int n) {
            this.partialDataRemaining = n;
        }


        /**
         * Records the number of payload bytes of an ignored (unknown/reserved)
         * frame that still must be skipped before the next frame header is
         * parsed. The streaming read ({@link #readMoreData}) drains these
         * bytes first.
         *
         * @param n the remaining payload bytes of the in-progress ignored frame
         */
        void setSkipRemaining(long n) {
            this.pendingSkipRemaining = n;
        }


        void setData(ByteBuffer data) {
            if (data != null && data.hasRemaining()) {
                dataBuffers.add(data);
                totalRemaining += data.remaining();
            }
        }


        void reset() {
            dataBuffers.clear();
            totalRemaining = 0;
            currentBufferIndex = 0;
            streamClosed = false;
            trailersReceived = false;
            partialDataRemaining = 0;
            pendingSkipRemaining = 0;
            bodyComplete = false;
            trailerPayload = null;
        }


        void setTrailersReceived(boolean b) {
            this.trailersReceived = b;
        }


        /**
         * Records a partially read trailer section payload (a second HEADERS
         * frame on the request stream that would-blocked mid-payload). The
         * streaming read ({@link #readMoreData}) completes and decodes this
         * section before parsing any further frame header.
         *
         * @param payload the bytes read so far, in write mode
         */
        void setTrailerPartial(ByteBuffer payload) {
            this.trailerPayload = payload;
        }


        void setBodyComplete(boolean b) {
            this.bodyComplete = b;
        }


        boolean isBodyComplete() {
            return bodyComplete;
        }


        boolean isStreamClosed() {
            return streamClosed;
        }


        int getPartialDataRemaining() {
            return partialDataRemaining;
        }


        @Override
        public int doRead(ApplicationBufferHandler handler) throws IOException {
            // Refill the pooled protocol-owned buffer, then inject a fresh
            // view of it into the caller via setByteBuffer(). Reuse across
            // calls is explicitly allowed by the coyote contract (see the
            // Request.doRead javadoc: the buffer is owned by the protocol
            // implementation and "will be reused on the next read"), and the
            // caller only asks for more data once it has consumed the view
            // injected by the previous call, so refilling here cannot clobber
            // undelivered bytes. A duplicate() is injected (as in
            // Http11InputBuffer.SocketInputBuffer.doRead) rather than the
            // pooled object itself, so the caller's view keeps stable
            // position/limit for the data just delivered.
            ByteBuffer out = deliveryBuffer;
            if (out == null) {
                out = ByteBuffer.allocate(8192);
                deliveryBuffer = out;
            }
            out.clear();
            int totalRead = 0;
            while (out.hasRemaining() && currentBufferIndex < dataBuffers.size()) {
                ByteBuffer src = dataBuffers.get(currentBufferIndex);
                if (src == null || !src.hasRemaining()) {
                    currentBufferIndex++;
                    continue;
                }
                int toRead = Math.min(out.remaining(), src.remaining());
                out.put(src.array(), src.position(), toRead);
                src.position(src.position() + toRead);
                totalRead += toRead;
                totalRemaining -= toRead;
            }

            // A client reset (RESET_STREAM) aborts the request: once any
            // buffered bytes have been delivered, report the truncated body
            // as an I/O error rather than end of data, so an async read
            // listener sees onError() and not onAllDataRead() (mirrors
            // HTTP/2's Stream.InputBuffer handling of a reset stream).
            if (totalRead == 0 && !trailersReceived && !bodyComplete) {
                SocketWrapperBase<?> socketWrapper = processor.getSocketWrapper();
                if (isStreamReset(socketWrapper)) {
                    throw streamResetError();
                }
            }

            // If no buffered data and the body is not yet complete, stream more
            // from the socket. A blocking read must not give up when the
            // bounded pump deadline expires without data (readMoreData returns
            // 0 in that case), so retry until data is available, the stream
            // ends, or the overall stall deadline expires. The retries cost no
            // work while stalled: each readMoreData() parks on the wrapper's
            // event-driven read wake-up and only resumes when the poll thread
            // signals data arrival. A peer that stalls the body while keeping
            // the QUIC connection alive (for example with PING frames) must
            // not be able to pin this worker thread indefinitely: after the
            // configured read timeout (the connector connection timeout wired
            // into the wrapper, MAX_BODY_READ_STALL_MS as fallback) with no
            // data and no stream close the stream is treated as closed (EOF).
            if (totalRead == 0 && !streamClosed && !trailersReceived && !bodyComplete) {
                SocketWrapperBase<?> socketWrapper = processor.getSocketWrapper();
                if (socketWrapper != null) {
                    long stallMs = socketWrapper.getReadTimeout() > 0
                            ? socketWrapper.getReadTimeout() : MAX_BODY_READ_STALL_MS;
                    long deadline = System.nanoTime()
                            + TimeUnit.MILLISECONDS.toNanos(stallMs);
                    while (totalRead == 0 && !streamClosed && !trailersReceived && !bodyComplete
                            && System.nanoTime() < deadline) {
                        totalRead = readMoreData(socketWrapper, out);
                    }
                    if (totalRead == 0 && !streamClosed && !trailersReceived && !bodyComplete) {
                        streamClosed = true;
                    }
                }
            }
            if (totalRead > 0) {
                out.flip();
                handler.setByteBuffer(out.duplicate());
                return totalRead;
            }
            // The streaming attempt above may itself have observed the reset
            // (quiche reports it during the read): re-check before reporting
            // end of data.
            if (totalRead == 0 && !trailersReceived && !bodyComplete &&
                    isStreamReset(processor.getSocketWrapper())) {
                throw streamResetError();
            }
            // The stream ended cleanly (FIN, not a reset or a stall
            // timeout) with the body short of the declared Content-Length:
            // a malformed message (RFC 9114 Section 4.1.2). The stream is
            // reset with H3_MESSAGE_ERROR and reported as end of data; the
            // pending response is suppressed via the streamReset checks in
            // the response paths (the application must not be able to
            // answer a truncated body with a normal response).
            if (totalRead == 0 && streamClosed && !trailersReceived &&
                    !bodyComplete && processor.requestContentLength > 0 &&
                    processor.totalDataReceived <
                            processor.requestContentLength &&
                    isStreamFin(processor.getSocketWrapper())) {
                streamClosed = true;
                processor.handleStreamError(processor.getSocketWrapper(),
                        Http3Error.H3_MESSAGE_ERROR);
            }
            return (streamClosed || trailersReceived || bodyComplete) ? -1 : 0;
        }


        private IOException streamResetError() {
            // Receiving a stream reset abandons reading of the stream's
            // field sections: an unacknowledged dynamic-table-using
            // section must be cancelled on the encoder stream
            // (RFC 9204 Section 2.2.2.2).
            processor.noteAbandonedDynamicTableUse();
            return new IOException(sm.getString(
                    "http3Processor.inputBuffer.streamReset",
                    Long.valueOf(processor.streamId)));
        }


        /**
         * Decodes the fully read trailer section held in
         * {@link #trailerPayload} and records it as received. On a decoding
         * failure the stream is reset (malformed message) or the connection
         * failed (invalid QPACK encoding), matching how the initial field
         * section reports those errors.
         *
         * @return {@code 0} on success, {@code -1} if the section failed to
         *         decode (stream already closed / reset)
         *
         * @throws IOException if an I/O error occurs while reporting the
         *                     error
         */
        private int finishTrailerSection(SocketWrapperBase<?> socketWrapper)
                throws IOException {
            ByteBuffer payload = trailerPayload;
            trailerPayload = null;
            payload.flip();
            try {
                processor.processTrailerSection(payload);
            } catch (Http3Exception e) {
                // Malformed trailer (including size/count limit violations):
                // reset the stream, as the content-length overrun does.
                streamClosed = true;
                processor.handleStreamError(socketWrapper, e.getError());
                return -1;
            } catch (QpackValueTooLargeException e) {
                // Oversize QPACK value: stream-scoped per RFC 9204
                // Section 7.4 (see the matching catch in service()).
                streamClosed = true;
                processor.handleStreamError(socketWrapper,
                        Http3Error.H3_QPACK_DECOMPRESSION_FAILED);
                return -1;
            } catch (QpackException e) {
                // Invalid QPACK encoding is a connection error (RFC 9204).
                streamClosed = true;
                processor.failConnection(socketWrapper,
                        Http3Error.H3_QPACK_DECOMPRESSION_FAILED);
                return -1;
            }
            // A trailer section ends the message: the body is complete
            // with it, so a shortfall against the declared Content-Length
            // is malformed here (RFC 9114 Section 4.1.2) without waiting
            // for the FIN that the peer will send after the trailers.
            if (processor.requestContentLength > 0 &&
                    processor.totalDataReceived < processor.requestContentLength) {
                streamClosed = true;
                processor.handleStreamError(socketWrapper,
                        Http3Error.H3_MESSAGE_ERROR);
                return -1;
            }
            trailersReceived = true;
            // A trailer section is the last field section of the request:
            // the body is complete once it has been decoded.
            bodyComplete = true;
            return 0;
        }


        /**
         * Completes and decodes an in-progress trailer section: reads the
         * payload bytes still missing from the stream (pumping the QUIC state
         * machine) and, once complete, decodes them via
         * {@link #finishTrailerSection}. Used both to resume a section that a
         * previous call (or the pre-dispatch read) left partially read and to
         * finish a section immediately after its frame header was parsed.
         *
         * @return {@code 1} once the section has been decoded, {@code 0} if
         *         the read would-block (the section stays staged for the next
         *         call), or {@code -1} if the section was truncated by FIN or
         *         failed to decode (the stream has already been reset)
         */
        private int completeTrailerSection(SocketWrapperBase<?> socketWrapper)
                throws IOException {
            int needed = trailerPayload.remaining();
            int copied = needed == 0 ? 0 : processor.copyFramePayload(
                    processor.inputBuffer, socketWrapper, trailerPayload, needed, true);
            // The Required Insert Count may already be among the staged
            // bytes: an abandoned (truncated or reset) section that used
            // the dynamic table still owes the peer a Stream Cancellation
            // (RFC 9204 Section 2.2.2.2).
            processor.notePartialSectionDynamicTableUse(trailerPayload);
            if (copied < needed) {
                if (processor.payloadEof) {
                    // FIN before the section was complete: truncated field
                    // section, malformed request.
                    streamClosed = true;
                    trailerPayload = null;
                    processor.handleStreamError(socketWrapper,
                            Http3Error.H3_MESSAGE_ERROR);
                    return -1;
                }
                // Would-block; the rest is completed on the next call.
                return 0;
            }
            return finishTrailerSection(socketWrapper) < 0 ? -1 : 1;
        }


        /**
         * Reads more DATA frames from the stream, preserving frame boundaries.
         * Tracks partial DATA frames so remaining bytes are skipped on the next call.
         */
        private int readMoreData(SocketWrapperBase<?> socketWrapper, ByteBuffer dst) throws IOException {
            int read = 0;
            ByteBuffer inputBuf = processor.inputBuffer;

            // If an ignored (unknown/reserved) frame's payload skip was
            // interrupted, drain the remainder before parsing any further
            // frame header.
            if (pendingSkipRemaining > 0) {
                long skipped = processor.skipFramePayload(socketWrapper,
                        pendingSkipRemaining, true);
                if (skipped < 0) {
                    streamClosed = true;
                    return read > 0 ? read : -1;
                }
                pendingSkipRemaining -= skipped;
                if (pendingSkipRemaining > 0) {
                    // Would-block again; the rest is skipped on the next call.
                    return read;
                }
            }

            // If a DATA frame was only partially delivered (readRequestBody
            // would-blocked mid-frame, or readMoreData's destination buffer
            // filled up mid-frame), read and deliver the remaining payload
            // bytes of that frame before parsing the next frame header.
            if (partialDataRemaining > 0) {
                int toCopy = Math.min(partialDataRemaining, dst.remaining());
                int bytesCopied = processor.copyFramePayload(inputBuf, socketWrapper,
                        dst, toCopy, true);
                read += bytesCopied;
                processor.totalDataReceived += bytesCopied;
                partialDataRemaining -= bytesCopied;
                if (processor.payloadEof) {
                    streamClosed = true;
                    return read;
                }
                if (processor.payloadBlocked || partialDataRemaining > 0) {
                    // Would-block or destination full; the rest is delivered
                    // on the next call.
                    return read;
                }
                // Frame complete; fall through to normal frame parsing.
            }

            // If a trailer section's payload read was interrupted, complete
            // and decode it before parsing any further frame header.
            if (trailerPayload != null) {
                int result = completeTrailerSection(socketWrapper);
                if (result == 0) {
                    // Would-block; the rest is completed on the next call.
                    return read;
                }
                if (result < 0) {
                    return read > 0 ? read : -1;
                }
                return read > 0 ? read : (dst.hasRemaining() ? -1 : 0);
            }

            // Parse frames until we find a DATA frame to deliver, the stream
            // ends, or the read would-block. Read more from the socket as
            // needed to complete frame headers.
            while (dst.hasRemaining()) {
                boolean headerComplete;
                try {
                    headerComplete = processor.parseFrameHeader(inputBuf,
                            processor.frameHeader);
                } catch (Http3StreamException e) {
                    // A frame longer than the local frame length limit:
                    // protocol-valid (HTTP/3 has no negotiated frame size
                    // limit), merely too large for this receiver to buffer.
                    // Reject the request at stream scope (RESET_STREAM)
                    // instead of failing the connection; no payload of the
                    // declared size is allocated or read.
                    streamClosed = true;
                    processor.handleStreamError(socketWrapper, e.getError());
                    return read > 0 ? read : -1;
                }
                if (!headerComplete) {
                    // Incomplete frame header. parseFrameHeader rewound to the
                    // start of the header, so refillForHeader's compact() cannot
                    // discard a partially consumed type byte and the bytes are
                    // re-parsed as a header on the next iteration.
                    if (!refillForHeader(inputBuf, socketWrapper)) {
                        break;
                    }
                    continue;
                }
                long frameType = processor.frameHeader[0];
                long frameLen = processor.frameHeader[1];

                switch (classifyBodyFrame(frameType)) {
                    case DATA -> {
                        if (frameLen == 0) {
                            continue;
                        }
                        // Enforce Content-Length on the streaming path too,
                        // against the running total received across both read
                        // paths (dataOverrunsContentLength). The over-running
                        // frame is not delivered: the stream is reset with
                        // H3_MESSAGE_ERROR immediately (the response is
                        // suppressed via the streamReset checks in the response
                        // paths, since a response may otherwise be flushed to
                        // the wire from inside the servlet).
                        if (processor.dataOverrunsContentLength(
                                processor.totalDataReceived, frameLen)) {
                            if (log.isDebugEnabled()) {
                                log.debug(sm.getString(
                                        "http3Processor.dataFrameExceedsContentLength",
                                        Long.valueOf(processor.streamId),
                                        Long.valueOf(processor.totalDataReceived +
                                                frameLen),
                                        Long.valueOf(processor.requestContentLength)));
                            }
                            streamClosed = true;
                            processor.handleStreamError(socketWrapper,
                                    Http3Error.H3_MESSAGE_ERROR);
                            return read > 0 ? read : -1;
                        }
                        // Deliver as much of this DATA frame as fits in dst. Any
                        // remainder is request-body bytes that MUST be delivered on a
                        // later call (recorded in partialDataRemaining), never skipped.
                        int toCopy = (int) Math.min(frameLen, dst.remaining());
                        int bytesCopied = processor.copyFramePayload(inputBuf, socketWrapper,
                                dst, toCopy, true);
                        if (bytesCopied < frameLen) {
                            // dst filled up (or the read would-blocked) before the frame
                            // was fully delivered; defer the rest to the next call.
                            // Safe cast: parseFrameHeader rejects DATA frames above
                            // MAX_FRAME_LENGTH at the header.
                            partialDataRemaining = (int) (frameLen - bytesCopied);
                        }
                        read += bytesCopied;
                        processor.totalDataReceived += bytesCopied;
                        if (processor.payloadEof) {
                            streamClosed = true;
                        }
                        return read;
                    }
                    case TRAILERS -> {
                        // See BodyFrameKind.TRAILERS. Declared-length
                        // preflight against the wire-side bound of the
                        // field section limit (see fieldSectionWireLimit);
                        // the RFC-defined uncompressed check runs on decode.
                        if (frameLen > processor.fieldSectionWireLimit()) {
                            streamClosed = true;
                            processor.handleStreamError(socketWrapper,
                                    Http3Error.H3_MESSAGE_ERROR);
                            return read > 0 ? read : -1;
                        }
                        // Safe cast: parseFrameHeader rejects HEADERS frames
                        // above MAX_FRAME_LENGTH at the header.
                        trailerPayload = ByteBuffer.allocate((int) frameLen);
                        int result = completeTrailerSection(socketWrapper);
                        if (result < 0) {
                            return read > 0 ? read : -1;
                        }
                        if (result == 0) {
                            // Would-block mid-section: resume on the next call.
                            return read > 0 ? read : 0;
                        }
                        return read > 0 ? read : (dst.hasRemaining() ? -1 : 0);
                    }
                    case CONTROL_ONLY -> {
                        // See BodyFrameKind.CONTROL_ONLY: a connection error
                        // of type H3_FRAME_UNEXPECTED. This method cannot
                        // throw it, so the code is recorded and service() /
                        // recycle() fail the connection once the servlet
                        // returns.
                        processor.bodyFrameError = Http3Error.H3_FRAME_UNEXPECTED;
                        streamClosed = true;
                        return read > 0 ? read : -1;
                    }
                    case IGNORED -> {
                        // See BodyFrameKind.IGNORED: skip the payload and keep
                        // parsing frames.
                        if (log.isDebugEnabled()) {
                            log.debug(sm.getString("http3Processor.frameIgnored",
                                    Long.valueOf(processor.streamId),
                                    Long.valueOf(frameType)));
                        }
                        long skipped = frameLen > 0 ? processor.skipFramePayload(
                                socketWrapper, frameLen, true) : frameLen;
                        if (skipped < 0) {
                            streamClosed = true;
                            return read > 0 ? read : -1;
                        }
                        if (skipped < frameLen) {
                            // Would-block mid-payload: drain the remainder on the
                            // next call before parsing any further frame header.
                            pendingSkipRemaining = frameLen - skipped;
                            return read;
                        }
                    }
                }
            }
            return read;
        }


        /**
         * Reads more data from the socket into {@code inputBuf} so that a frame
         * header can be completed.
         *
         * @return true if data was read, false if the stream ended or the read
         *         would-block after the deadline
         */
        private boolean refillForHeader(ByteBuffer inputBuf, SocketWrapperBase<?> socketWrapper) throws IOException {
            // refillInputBuffer flips before returning so the compacted tail
            // (an incomplete frame header) stays in read mode and is re-parsed
            // once more data arrives, instead of being lost or re-exposed as
            // stale bytes.
            int n = processor.refillInputBuffer(socketWrapper, inputBuf, true);
            if (n < 0) {
                streamClosed = true;
                return false;
            }
            if (n == 0) {
                return false;
            }
            return true;
        }


        @Override
        public int available() {
            return totalRemaining;
        }

        /**
         * Returns whether trailers have been received on this stream.
         */
        boolean isTrailersReceived() {
            return trailersReceived;
        }
    }


    /**
     * Simple output buffer for HTTP/3 response data.
     * Wraps response body data in HTTP/3 DATA frames (RFC 9114 Section 7.2.1).
     */
    private static class Http3OutputBuffer implements OutputBuffer {
        private final Http3Processor processor;
        private long bytesWritten = 0;
        private final ByteBuffer dataFrameBuffer = ByteBuffer.allocate(16384);
        private boolean voidOutput = false;
        private boolean compressionEnabled = false;
        private GZIPOutputStream compressionStream = null;
        private final OutputStream gzipSink = new GzipSinkOutputStream();

        Http3OutputBuffer(Http3Processor processor) {
            this.processor = processor;
        }

        void setVoidOutput(boolean voidOutput) {
            this.voidOutput = voidOutput;
        }

        void resetVoidOutput() {
            voidOutput = false;
        }

        /**
         * Enables response compression. The decision logic itself lives in
         * {@link org.apache.coyote.CompressionConfig}, invoked by the
         * processor before the response headers are encoded; once enabled,
         * body bytes written through {@link #doWrite(ByteBuffer)} are
         * compressed with gzip before being wrapped in DATA frames.
         */
        void enableCompression() {
            compressionEnabled = true;
        }

        /**
         * Drops all per-response compression state. Called from the
         * processor's recycle() since processors are pooled across requests.
         * The stream is closed before the reference is dropped so the
         * Deflater's native state is released deterministically rather than
         * lingering (reachable from the pooled processor) until the cleaner
         * runs. On a reset stream the trailer bytes the close produces are
         * swallowed by the emitData() streamReset guard (recycle() runs this
         * before clearing the flag); a stream that already completed
         * (end() finished it) throws "Stream closed" here, which is
         * expected - the deflater is released either way.
         */
        void resetCompression() {
            compressionEnabled = false;
            if (compressionStream != null) {
                try {
                    compressionStream.close();
                } catch (IOException ioe) {
                    // Already finished by end(), or the QUIC stream no
                    // longer accepts writes. Nothing left to release.
                }
                compressionStream = null;
            }
        }

        @Override
        public int doWrite(ByteBuffer chunk) throws IOException {
            // The OutputBuffer contract (see Response.doWrite): consume the
            // bytes that were written by advancing the buffer's position,
            // so callers - and the contentWritten statistics that feed the
            // RequestProcessor / GlobalRequestProcessor MBeans - can tell
            // how much was taken.
            int pending = chunk.remaining();
            // Responses without a body (1xx, 204, 205, 304, HEAD) must not
            // send DATA frames; silently consume any bytes the application
            // writes, matching VoidOutputFilter (HTTP/1.1 and HTTP/2).
            if (voidOutput) {
                chunk.position(chunk.limit());
                return pending;
            }
            // The stream was reset (e.g. a request body that over-ran its
            // Content-Length, RFC 9114 Section 4.1.2): silently consume
            // what the application writes so the servlet can finish
            // without seeing a write error against a dead stream.
            if (processor.streamReset.get()) {
                chunk.position(chunk.limit());
                return pending;
            }
            // The wrapper guard precedes the send-headers call below (and
            // the compression it may enable): both write through the wrapper
            // (sendHeadersFrame does socketWrapper.write() directly) and a
            // cleared wrapper must read as "stream gone" here rather than
            // NPE. No live path reaches a response write with a cleared
            // wrapper (it is cleared only around recycle), but the ordering
            // is what makes that non-reachability sufficient.
            if (processor.getSocketWrapper() == null) {
                return -1;
            }
            // Ensure response headers are sent before any DATA frame
            // (RFC 9114 requires HEADERS before DATA on a response stream).
            // This is also the point at which compression may be enabled for
            // this response, so the compression branch below must come after.
            if (!processor.responseStarted) {
                processor.sendResponseHeadersInternal(processor.getSocketWrapper());
            }
            if (pending == 0) {
                return 0;
            }
            if (compressionEnabled) {
                return writeCompressed(chunk, pending);
            }
            return emitData(chunk, pending);
        }

        private int writeCompressed(ByteBuffer chunk, int len) throws IOException {
            // The sync-flush constructor matches the HTTP/1.1
            // GzipOutputFilter: a flush of the compression stream emits the
            // data compressed so far as a complete deflate block.
            if (compressionStream == null) {
                compressionStream = new GZIPOutputStream(gzipSink, true);
            }
            if (chunk.hasArray()) {
                compressionStream.write(chunk.array(), chunk.arrayOffset() + chunk.position(), len);
                chunk.position(chunk.position() + len);
            } else {
                byte[] bytes = new byte[len];
                chunk.get(bytes);
                compressionStream.write(bytes, 0, len);
            }
            return len;
        }

        /**
         * Wraps the (possibly compressed) bytes in HTTP/3 DATA frames and
         * writes them to the stream. Consumes the given buffer.
         *
         * @param chunk    The bytes to send
         * @param dataLen  The number of bytes to send from the buffer
         *
         * @return The number of bytes consumed, or -1 if there is no longer a
         *         socket wrapper to write to
         *
         * @throws IOException If an I/O error occurs while writing
         */
        private int emitData(ByteBuffer chunk, int dataLen) throws IOException {
            SocketWrapperBase<?> wrapper = processor.getSocketWrapper();
            if (wrapper == null) {
                return -1;
            }
            if (dataLen == 0) {
                return 0;
            }
            // A stream reset that arrived after compression started: swallow
            // the bytes the compression stream produces. The application
            // write path already swallows what it is handed once the stream
            // is dead; the gzip pipeline must not see a failure here.
            if (processor.streamReset.get()) {
                chunk.position(chunk.limit());
                return dataLen;
            }
            if (log.isDebugEnabled()) {
                log.debug("Stream [" + processor.streamId + "] Http3OutputBuffer.doWrite: " + dataLen + " bytes -> DATA frame(s)");
            }
            // Wrap data in HTTP/3 DATA frames: QUIC varint type + QUIC varint
            // length + payload. The frame header needs at most 9 bytes
            // (1 + 8), so emit at most the remainder of the buffer per frame;
            // a chunk larger than the buffer would otherwise overflow it.
            int maxPayload = dataFrameBuffer.capacity() - 9;
            int originalLimit = chunk.limit();
            int written = 0;
            while (dataLen > 0) {
                int frameLen = Math.min(dataLen, maxPayload);
                dataFrameBuffer.clear();
                Qpack.encodeQuicInteger(dataFrameBuffer, Constants.H3_DATA);
                Qpack.encodeQuicInteger(dataFrameBuffer, frameLen);

                // Advance the source position through the frame; the limit
                // is restored after the put so subsequent frames see the
                // correct remaining count.
                chunk.limit(chunk.position() + frameLen);
                dataFrameBuffer.put(chunk);
                chunk.limit(originalLimit);

                dataFrameBuffer.flip();
                wrapper.write(true, dataFrameBuffer);
                dataLen -= frameLen;
                written += frameLen;
            }
            bytesWritten += written;
            return written;
        }

        /**
         * Finishes the response body. When compression is enabled this emits
         * the final compressed block and the gzip trailer as the last DATA
         * frames; it must run before any trailers and before the FIN written
         * by concludeStream(). A no-op when compression was never enabled.
         *
         * @throws IOException If an I/O error occurs while writing
         */
        void end() throws IOException {
            if (!compressionEnabled || processor.streamReset.get()) {
                return;
            }
            // An empty body still gets a complete (empty) gzip member,
            // matching the HTTP/1.1 GzipOutputFilter behaviour.
            if (compressionStream == null) {
                compressionStream = new GZIPOutputStream(gzipSink, true);
            }
            compressionStream.finish();
            compressionStream.close();
        }

        @Override
        public long getBytesWritten() {
            return bytesWritten;
        }

        void resetBytesWritten() {
            bytesWritten = 0;
        }

        public void flush() throws IOException {
            if (compressionStream != null) {
                try {
                    if (log.isTraceEnabled()) {
                        log.trace("Flushing the compression stream!");
                    }
                    compressionStream.flush();
                } catch (IOException ioe) {
                    if (log.isDebugEnabled()) {
                        log.debug("Stream [" + processor.streamId + "] failed to flush the compression stream", ioe);
                    }
                }
            }
            SocketWrapperBase<?> wrapper = processor.getSocketWrapper();
            if (wrapper != null) {
                wrapper.flush(true);
            }
        }

        /**
         * Output stream that hands the bytes produced by the compression
         * stream to the DATA framing. The return value is ignored by the
         * compression stream: each write either succeeds or throws.
         */
        private class GzipSinkOutputStream extends OutputStream {
            /**
             * Single-byte buffer used for writing individual bytes.
             */
            private final ByteBuffer outputChunk = ByteBuffer.allocate(1);

            @Override
            public void write(int b) throws IOException {
                outputChunk.clear();
                outputChunk.put((byte) (b & 0xff));
                outputChunk.flip();
                emitData(outputChunk, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                emitData(ByteBuffer.wrap(b, off, len), len);
            }

            @Override
            public void flush() throws IOException {
                // NOOP: the compression stream flush reaches the socket
                // through the outer flush().
            }

            @Override
            public void close() throws IOException {
                // NOOP: stream conclusion is handled by end() and
                // concludeStream().
            }
        }
    }
}

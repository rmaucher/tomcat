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
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiPredicate;
import java.util.function.Supplier;
import java.util.zip.GZIPOutputStream;

import jakarta.servlet.ServletConnection;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.coyote.AbstractProcessor;
import org.apache.coyote.ActionCode;
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
 * so this processor handles a single request per stream (no multiplexing
 * needed).
 * <p>
 * A request lifecycle is: decode the request HEADERS and pre-read the body,
 * dispatch to the container, stream the remaining request body/trailer
 * section, encode the response HEADERS/DATA/trailers, scan any frames that
 * follow the request message, and finally conclude the stream (FIN) or reset
 * it. Errors are classified by scope: {@link Http3StreamException} and
 * {@code Http3Error.isStreamError()} reset only the affected stream, while
 * connection-scoped errors fail the whole HTTP/3 connection. QPACK state is
 * shared per connection through {@link Http3ConnectionManager}; response
 * encoding state is per stream. Async reads and writes are driven by the
 * abstract processor state machine, but QUIC response writes are currently
 * blocking (see {@link #isReadyForWrite()}).
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
     * QPACK encoder for this stream. This is always a per-stream instance:
     * unlike the shared decoder, its in-progress encoding state (header
     * iterator, pending prefix) must not be visible to the worker threads
     * processing other streams of the same connection.
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
     * without buffering, but remain subject to the per-request
     * {@link #MAX_NON_BODY_FRAME_BYTES} and {@link #MAX_NON_BODY_FRAMES}
     * budgets (RFC 9114 Sections 9, 7.2.8).
     * A buffered frame above this limit is protocol-valid (HTTP/3 has no
     * negotiated frame size limit); the affected request stream is
     * rejected with {@code RESET_STREAM} ({@link Http3Error#H3_FRAME_ERROR})
     * rather than failing the connection.
     */
    private static final int MAX_FRAME_LENGTH = Constants.MAX_FRAME_LENGTH;

    /**
     * Maximum number of ignored/padding frames (or zero-length DATA frames)
     * that may be processed for one request before the connection is failed
     * with {@link Http3Error#H3_EXCESSIVE_LOAD}. A peer that keeps sending
     * frames that make no body progress must not be able to keep a worker
     * thread busy indefinitely.
     */
    private static final int MAX_NON_BODY_FRAMES = 4096;

    /**
     * Maximum total payload length of ignored/padding frames for one request.
     * RFC 9114 Section 9 requires unknown frames to be ignored, but an
     * implementation may bound the amount of padding it is willing to consume
     * (the limit is deliberately above the 16 MiB frame limit tested by the
     * padding tests).
     */
    private static final long MAX_NON_BODY_FRAME_BYTES = 32L * 1024 * 1024;

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
     * pin a worker thread indefinitely. The QUIC socket wrapper uses the
     * connector's configured read timeout when one is set and otherwise
     * falls back to its 30-second stall timeout; this is the same default
     * bound used when the wrapper reports no read timeout. The individual
     * would-block pump retries within a single read carry their own,
     * shorter deadline (see {@link #PUMP_RETRY_TIMEOUT_MS}).
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
     * Set by the socket read helpers when a read ended with an
     * {@link EOFException} (connection close or stream reset) rather than a
     * normal {@code -1} result (clean FIN). The input buffer uses this to
     * classify the end of the request stream without re-inspecting a stream
     * wrapper that may already have been released.
     */
    private boolean lastReadEndedWithException = false;

    /**
     * Output buffer for writing frames.
     */
    private final Http3OutputBuffer outputBuffer;

    /**
     * Set when the response is complete but the output queue still holds
     * frames. The FIN is sent when the queue drains.
     */
    private boolean finPending = false;

    /**
     * Set once the FIN has been sent (or the stream was reset), so it cannot
     * be sent twice.
     */
    private boolean finSent = false;

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
     * Whether the response stream has been concluded (the FIN has been sent
     * or a conclusion attempt was made). Once set, no further response fields
     * can be sent, so the trailer-fields supplier is no longer supported.
     */
    private boolean responseConcluded = false;

    /**
     * Whether the stream has been reset (to prevent double reset).
     */
    private final AtomicBoolean streamReset = new AtomicBoolean(false);

    /**
     * Whether this processor may be returned to the shared processor pool.
     * Cleared by recycle() if the request ended with an error or reset, as a
     * non-container thread may still be using the request, response or
     * output buffer in those cases. The HTTP/2 implementation avoids reuse
     * of such objects for the same reason.
     */
    private volatile boolean reusable = true;

    /**
     * Set when the processor has failed the whole HTTP/3 connection. Such a
     * processor is not returned to the shared pool because a non-container
     * thread may still hold its response/output state.
     */
    private volatile boolean connectionFailed = false;

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
     * Response fields that must not be dropped when reducing a field section
     * to the peer's SETTINGS_MAX_FIELD_SECTION_SIZE: they carry framing,
     * body-decoding, authentication, redirect or cache semantics.
     */
    private static final Set<String> ESSENTIAL_FIELD_NAMES = Set.of(
            "content-type", "content-length", "content-encoding",
            "content-range", "content-disposition", "content-language",
            "set-cookie", "www-authenticate", "proxy-authenticate",
            "location", "retry-after", "vary", "etag", "last-modified",
            "cache-control", "expires", "warning",
            // Security/response-policy fields that must not be dropped just
            // because a peer advertised a tiny field-section limit.
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options",
            "access-control-allow-origin", "access-control-allow-credentials",
            "access-control-allow-methods", "access-control-allow-headers",
            "access-control-expose-headers");

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


    /**
     * Per-request budget for frames that do not make request-body progress:
     * unknown/reserved frames and zero-length DATA frames. See
     * {@link #MAX_NON_BODY_FRAMES} and {@link #MAX_NON_BODY_FRAME_BYTES}.
     */
    private int nonBodyFrameCount = 0;
    private long nonBodyFrameBytes = 0;


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

        // A paused connector must not start new requests on connections that
        // are already established. The request has not reached the
        // application, so reject it as unprocessed with H3_REQUEST_REJECTED
        // (RFC 9114 Section 4.1.1); in-flight requests continue. Resume()
        // clears the endpoint pause flag and new streams are accepted again.
        if (!headersReceived && protocol.isPaused()) {
            if (log.isDebugEnabled()) {
                log.debug("Stream [" + streamId + "] rejected: connector is paused");
            }
            handleStreamError(socketWrapper, Http3Error.H3_REQUEST_REJECTED);
            return SocketState.CLOSED;
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
                            if (payloadEof || hasPartialFrameData()) {
                                // RFC 9114 Section 7.1: a cleanly terminated
                                // stream whose last frame (or frame header) is
                                // truncated is a connection error, not the
                                // stream-scoped H3_REQUEST_INCOMPLETE used for
                                // an empty stream at a frame boundary.
                                throw new Http3Exception(
                                        sm.getString("http3Processor.frameError",
                                                Long.valueOf(streamId)),
                                        Http3Error.H3_FRAME_ERROR);
                            }
                            if (socketWrapper.getSocket() instanceof QuicStream
                                    quicStream && quicStream.isLateDuplicate()) {
                                // Late FIN edge for a request that already
                                // completed: the terminal read has been
                                // drained above, so close without resetting
                                // the stream or abandoning its QPACK section.
                                return SocketState.CLOSED;
                            }
                            handleStreamError(socketWrapper,
                                    Http3Error.H3_REQUEST_INCOMPLETE);
                        } else {
                            // A reset cut off the initial HEADERS frame
                            // before it could be decoded. The section was
                            // abandoned, so noteStreamAbandoned() emits the
                            // Stream Cancellation unconditionally.
                            noteStreamAbandoned();
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
            } else if (inputBufferHasData && inputBuffer.hasRemaining()) {
                // A request without Content-Length may still carry content
                // (RFC 9110 Section 6.5, RFC 9114 Section 4.1). If body frames
                // were read together with the request head, transfer them to
                // the processor body buffers so an async reader has data to
                // consume; this does not add a socket read on the hot
                // header-only path.
                readRequestBody(socketWrapper);
            }
            // Trailer decoding and clean-FIN recording are deliberately
            // lazy: isTrailerFieldsReady() performs them on demand (and
            // decodeTrailerSectionAfterResponse() does so for applications
            // that never ask). Eagerly reading here cost one socket read per
            // request on the hot GET path, which is a measurable poller
            // overhead on the QUIC transport.

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
                try {
                    sendErrorResponse(socketWrapper,
                            HttpServletResponse.SC_BAD_REQUEST);
                } catch (IOException ioe) {
                    // A failed 400 response leaves the client without a
                    // complete response. Reset instead of letting the outer
                    // catch hand the stream to the endpoint's error-0 close.
                    noteStreamAbandoned();
                    resetStream(socketWrapper,
                            Http3Error.H3_INTERNAL_ERROR);
                    protocol.getAdapter().log(request, response, 0);
                    return SocketState.CLOSED;
                }
                protocol.getAdapter().log(request, response, 0);
                // The request body/trailer section was not necessarily read;
                // release any dynamic-table references it might have carried.
                noteStreamAbandoned();
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
                // Remember whether any response bytes reached the client
                // before the failure. A committed response cannot be replaced
                // by the minimal 500 response: sendErrorResponse() returns
                // without writing when responseStarted is set. Such a
                // response is incomplete and must be reset, not concluded
                // with a clean FIN, otherwise a body delimited by the end of
                // the stream looks complete to the client.
                boolean responseWasStarted = responseStarted;
                // Clear any application-provided headers while the response
                // is still uncommitted so the minimal error response cannot
                // carry stale framing or content-coding fields.
                if (!response.isCommitted()) {
                    response.reset();
                }
                // Mark the request as errored, exactly as the HTTP/1.1 and
                // HTTP/2 processors do. This also prevents a processor with
                // an active application thread (for example an async request
                // whose adapter failed while unwinding) from being returned
                // to the shared pool.
                setErrorState(response.isCommitted() ? ErrorState.CLOSE_NOW :
                        ErrorState.CLOSE_CLEAN, e);
                noteStreamAbandoned();
                if (responseWasStarted || streamReset.get() ||
                        connectionFailed) {
                    resetStream(socketWrapper, Http3Error.H3_INTERNAL_ERROR);
                    return SocketState.CLOSED;
                }
                try {
                    sendErrorResponse(socketWrapper, 500);
                } catch (IOException ex) {
                    // The error response could not be written (possibly
                    // partway through its HEADERS frame). Do not conclude the
                    // stream: reset it so the peer knows the response is
                    // incomplete.
                    resetStream(socketWrapper, Http3Error.H3_INTERNAL_ERROR);
                    return SocketState.CLOSED;
                }
                if (!responseStarted || streamReset.get()) {
                    // The write did not complete, or the stream was reset
                    // while attempting it. Never send FIN after RESET_STREAM.
                    resetStream(socketWrapper, Http3Error.H3_INTERNAL_ERROR);
                    return SocketState.CLOSED;
                }
                // The complete 500 response is in place; conclude normally.
                concludeStream(socketWrapper);
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

            // A failure while finishing the response (for example a write
            // error during the final headers or compression trailer) sets
            // the error state through AbstractProcessor.action(CLOSE). Do
            // not attempt to send any more response bytes in that state.
            if (getErrorState().isError()) {
                noteStreamAbandoned();
                // The response may have been truncated by the failure that
                // set the error state. Signal that explicitly instead of
                // letting the endpoint close the unconcluded stream with the
                // neutral error code 0 (H3_NO_ERROR).
                resetStream(socketWrapper, Http3Error.H3_INTERNAL_ERROR);
                return SocketState.CLOSED;
            }

            // Check for async
            if (isAsync()) {
                // Stream stays open for async completion.
                // The async servlet will eventually call response.flush() or complete().
                // If body bytes were already pre-buffered before the listener
                // was registered, trigger the initial non-blocking read
                // dispatch; otherwise the listener could wait for a socket
                // event that the already-consumed data will never generate.
                Http3InputBuffer h3Input =
                        (Http3InputBuffer) request.getInputBuffer();
                if (request.getReadListener() != null &&
                        h3Input.available() > 0) {
                    request.action(ActionCode.DISPATCH_READ, null);
                    request.action(ActionCode.DISPATCH_EXECUTE, null);
                }
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

            // Conclude the response stream after the request-stream scans.
            concludeStream(socketWrapper);

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
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3Processor.error", Long.valueOf(streamId)), e);
            }
            // The stream is being torn down by an I/O failure. If its
            // unprocessed field sections may still reference dynamic table
            // entries, the peer's encoder is owed a Stream Cancellation
            // (RFC 9204 Section 2.2.2.2). The response may also be truncated:
            // reset the stream with H3_INTERNAL_ERROR before rethrowing, so
            // the peer does not receive the endpoint's neutral error-0 close.
            noteStreamAbandoned();
            resetStream(socketWrapper, Http3Error.H3_INTERNAL_ERROR);
            throw e;
        } finally {
            // A request that is still asynchronously running is counted by
            // AbstractProcessor.asyncDispatch() when it completes. Once
            // service() returns CLOSED, however, no later async completion
            // will update the counters, so count an errored/aborted async
            // request here even when isAsync() is still true.
            if (requestStarted && (!isAsync() || getErrorState().isError() ||
                    streamReset.get() || connectionFailed)) {
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
     * Classifies an Http3Exception raised while decoding a field section.
     * Http3StreamException is always stream-scoped (including the local
     * H3_FRAME_ERROR resets used for oversized frames). A base Http3Exception
     * is stream-scoped only when Http3Error.isStreamError() says so; other
     * codes - notably H3_EXCESSIVE_LOAD from the decoder-instruction backlog -
     * are connection errors and must not be sent as RESET_STREAM codes.
     */
    private void handleStreamOrConnectionError(
            SocketWrapperBase<?> socketWrapper, Http3Exception e) {
        if (e instanceof Http3StreamException || e.getError().isStreamError()) {
            handleStreamError(socketWrapper, e.getError());
        } else {
            failConnection(socketWrapper, e.getError());
        }
    }


    /*
     * Notes that reading this stream is being abandoned even if no dynamic
     * table use has been observed. RFC 9204 Section 2.2.2.2 requires a Stream
     * Cancellation whenever an endpoint abandons a stream before all of its
     * field sections are processed; a partial or not-yet-inspected section
     * may reference entries the decoder never saw. Emission remains
     * single-shot per stream.
     */
    private void noteStreamAbandoned() {
        if (!streamCancellationSent) {
            streamCancellationSent = true;
            noteStreamCancellation();
        }
    }


    /*
     * Accounts one frame that makes no request-body progress (an
     * unknown/reserved frame, or a zero-length DATA frame) and reports
     * whether the per-request budget has been exceeded. Callers in paths that
     * can throw turn a true result into a connection error of type
     * H3_EXCESSIVE_LOAD; Http3InputBuffer records the error for the service
     * loop because its read contract cannot throw Http3Exception.
     */
    private boolean noteNonBodyFrame(long payloadLength) {
        nonBodyFrameCount++;
        nonBodyFrameBytes += payloadLength;
        return nonBodyFrameCount > MAX_NON_BODY_FRAMES ||
                nonBodyFrameBytes > MAX_NON_BODY_FRAME_BYTES;
    }


    /*
     * The throwing variant used by the request-stream frame paths.
     */
    private void checkNonBodyFrame(long frameType, long payloadLength)
            throws Http3Exception {
        if (noteNonBodyFrame(payloadLength)) {
            throw new Http3Exception(
                    sm.getString("http3Processor.excessiveLoad",
                            Long.valueOf(streamId), Long.valueOf(frameType)),
                    Http3Error.H3_EXCESSIVE_LOAD);
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
        connectionFailed = true;
        reusable = false;
        outputBuffer.discardPendingFrames();
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
    private void noteSectionAcknowledgment() throws Http3Exception {
        if (!noteDecoderInstruction(
                (manager, conn) -> manager.noteSectionAcknowledgment(conn, streamId))) {
            throw new Http3Exception(
                    sm.getString(
                            "http3ConnectionManager.pendingDecoderInstructionsFull",
                            Integer.valueOf(Http3ConnectionManager.MAX_PENDING_DECODER_INSTRUCTIONS)),
                    Http3Error.H3_EXCESSIVE_LOAD);
        }
    }


    /**
     * Notes that a Stream Cancellation instruction must be emitted for this
     * stream because it is being abandoned before all of its field sections
     * were processed (RFC 9204 Section 2.2.2.2). The instruction is written
     * to the server QPACK decoder stream on the QUIC poll thread.
     */
    private void noteStreamCancellation() {
        if (!noteDecoderInstruction(
                (manager, conn) -> manager.noteStreamCancellation(conn, streamId))) {
            if (log.isWarnEnabled()) {
                log.warn(sm.getString(
                        "http3ConnectionManager.pendingDecoderInstructionsFull",
                        Integer.valueOf(Http3ConnectionManager.MAX_PENDING_DECODER_INSTRUCTIONS)));
            }
            failConnection(getSocketWrapper(), Http3Error.H3_EXCESSIVE_LOAD);
        }
    }


    /*
     * Common path for emitting a decoder instruction on this stream. The
     * BiPredicate returns false when the per-connection backlog of pending
     * instructions was exceeded: a peer that never reads its QPACK decoder
     * stream must not be able to grow per-connection state without bound.
     */
    private boolean noteDecoderInstruction(
            BiPredicate<Http3ConnectionManager,QuicConnection> note) {
        SocketWrapperBase<?> socketWrapper = getSocketWrapper();
        QuicConnection conn = quicConnection(socketWrapper);
        Http3ConnectionManager manager = getConnectionManager();
        return conn == null || manager == null || note.test(manager, conn);
    }


    /*
     * Whether the request declares a body via its content-length header.
     * HTTP/3 framing does not restrict bodies to particular methods
     * (RFC 9114 Section 4.1; RFC 9110 Section 6.5 allows content to be
     * present with any method), so the declaration - not the method name -
     * drives the pre-dispatch body handling (pre-buffering, content-length
     * overrun checks). Bodies without a content-length are delimited by the
     * end of the stream; they are not pre-read on the basis of this method,
     * although body frames already buffered with the request head are
     * transferred to the streaming buffers by service().
     */
    private boolean isRequestBodyIndicated() {
        return requestContentLength >= 0;
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
     * dropped to reduce it: the pseudo-headers and the fields needed to
     * interpret, authenticate, redirect or cache the response (see
     * {@link #ESSENTIAL_FIELD_NAMES}) are always retained, the remaining
     * fields are kept in order as long as they still fit. If the retained
     * fields alone still exceed a pathologically small limit, the reduced set
     * is sent unchanged: the limit is advisory and failing a response the
     * peer may still accept is worse than exceeding a SHOULD.
     *
     * The size uses the same accounting as the incoming checks
     * (QpackDecoder.emit()): sum of the byte lengths of the names and values
     * plus 32 bytes per field line.
     */
    private MimeHeaders applyPeerFieldSectionLimit(MimeHeaders headers) {
        long limit = connectionState == null ? -1 :
                connectionState.getPeerMaxFieldSectionSize();
        if (limit < 0 || fieldSectionSize(headers) <= limit) {
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

        // A peer can advertise a tiny limit on every request; logging this at
        // WARN would let it flood the logs. The response itself is unchanged,
        // so debug is sufficient for diagnosis.
        if (log.isDebugEnabled()) {
            log.debug(sm.getString("http3Processor.response.fieldSectionTooLarge",
                    Long.valueOf(streamId), Long.valueOf(size), Long.valueOf(limit)));
        }
        return reduced;
    }


    private static boolean isFieldSectionEssential(String name) {
        if (name.startsWith(":")) {
            return true;
        }
        return ESSENTIAL_FIELD_NAMES.contains(name.toLowerCase(Locale.ENGLISH));
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
        Http3ConnectionManager manager = getConnectionManager();
        long limit = manager != null ? manager.getMaxFieldSectionSize() :
                protocol.getMaxFieldSectionSize();
        return fieldSectionWireLimit(limit);
    }


    /*
     * Trailer sections are bounded by the connector's trailer limits, not by
     * the (possibly different) request-header limit. A negative trailer-size
     * limit means unlimited in QpackDecoder, so the wire preflight must not
     * impose a bound for it either.
     */
    private long trailerFieldSectionWireLimit() {
        long limit = protocol.getMaxTrailerSize();
        if (limit < 0) {
            return Long.MAX_VALUE;
        }
        return fieldSectionWireLimit(limit);
    }


    private static long fieldSectionWireLimit(long limit) {
        // Negative configured limits mean the decoder enforces zero bytes
        // (Constants.clampToNonNegativeInt). Apply the same clamp to the wire
        // preflight so both limit paths agree instead of producing a small
        // positive bound for a small negative value.
        if (limit < 0) {
            limit = 0;
        }
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
        setResponseStatus(errorHeaders, statusCode);

        // Blocking write: this is the last write before concludeStream()
        // sends the FIN. A non-blocking write that the transport accepts only
        // as a prefix would leave the rest of the HEADERS frame staged, and
        // the FIN could then be delivered ahead of those bytes (truncating or
        // losing the error response). This is the same hazard documented for
        // response trailers in sendResponseTrailers().
        sendHeadersFrame(socketWrapper, errorHeaders, 256, true);
        responseStarted = true;
        response.setCommitted(true);
    }


    /*
     * Forces the response field section to carry exactly one :status
     * pseudo-header with the response status. Application-provided pseudo
     * headers are not valid in a response and must not override the status
     * used for the body/compression decisions.
     */
    private static void setResponseStatus(MimeHeaders headers, int statusCode) {
        for (int i = headers.size() - 1; i >= 0; i--) {
            if (headers.getName(i).toString().startsWith(":")) {
                headers.removeHeader(i);
            }
        }
        headers.addValue(":status").setString(Integer.toString(statusCode));
    }


    /*
     * Wraps an encoded QPACK field section in a HEADERS frame: QUIC varint
     * type + QUIC varint length + payload.
     */
    private static ByteBuffer buildHeadersFrame(ByteBuffer headerBlock) {
        // One byte for the HEADERS frame type plus at most eight bytes for the
        // QUIC varint length (RFC 9000 Section 16).
        ByteBuffer frame = ByteBuffer.allocate(1 + 8 + headerBlock.remaining());
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
        // RFC 9114 Section 4.2: an endpoint MUST NOT generate a field section
        // containing connection-specific fields. The request decoder enforces
        // this; apply the same rule to every outgoing HEADERS frame (an
        // application may set these fields even though they are meaningless
        // in HTTP/3).
        for (String name : CONNECTION_SPECIFIC_HEADERS) {
            headers.removeHeader(name);
        }
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
        if (outputBuffer.isNonBlockingMode()) {
            outputBuffer.writeFrame(frame, true);
        } else {
            socketWrapper.write(blocking, frame);
            socketWrapper.flush(blocking);
        }
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
        lastReadEndedWithException = false;
        int n;
        try {
            n = socketWrapper.read(false, inputBuffer);
        }
        catch (EOFException eoe) {
            // The stream was reset or the connection was closed (for
            // example the client disconnected mid-body). No further data
            // can arrive, so report end of stream.
            lastReadEndedWithException = true;
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
        while (n == 0) {
            // An interrupted thread must fail the read rather than return
            // "would block": the caller's outer retry loop would otherwise
            // spin until its deadline because awaitReadableData() keeps
            // returning immediately for an interrupted thread.
            if (Thread.currentThread().isInterrupted()) {
                throw interruptedRead();
            }
            // Pump, arm interest and park until the poll thread signals a
            // read event / terminal state or the deadline passes.
            if (!quicWrapper.awaitReadableData(deadline)) {
                if (Thread.currentThread().isInterrupted()) {
                    throw interruptedRead();
                }
                break;
            }
            try {
                n = socketWrapper.read(false, inputBuffer);
            }
            catch (EOFException eoe) {
                // The stream was reset or the connection was closed while
                // waiting for more data. No further data can arrive, so
                // report end of stream.
                lastReadEndedWithException = true;
                return -1;
            }
        }
        return n;
    }


    /*
     * A body read interrupted while waiting for QUIC data. Reported as an
     * IOException so the read ends instead of busy-spinning to the stall
     * deadline (the interrupt flag makes awaitReadableData() return
     * immediately).
     */
    private InterruptedIOException interruptedRead() {
        return new InterruptedIOException(sm.getString(
                "http3Processor.inputBuffer.interrupted",
                Long.valueOf(streamId)));
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
        lastReadEndedWithException = false;
        try {
            return socketWrapper.read(false, inputBuffer);
        } catch (EOFException eoe) {
            // The stream was reset or the connection was closed. No further
            // data can arrive, so report end of stream.
            lastReadEndedWithException = true;
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
        int n;
        try {
            n = pump ? readWithPump(socketWrapper, inputBuffer) :
                    readNonBlocking(socketWrapper, inputBuffer);
        } finally {
            // Restore read mode even if the read throws: callers (for
            // example isTrailerFieldsReady()) may catch the IOException and
            // continue using the processor, and a retained write-mode buffer
            // would expose stale tail bytes to a later frame-header parse.
            inputBuffer.flip();
        }
        if (n > 0) {
            inputBufferHasData = true;
        }
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


    /*
     * Whether the protocol input buffer currently retains bytes that only
     * form part of a frame header. A clean FIN with such bytes retained means
     * the last frame header was truncated (RFC 9114 Section 7.1, connection
     * error H3_FRAME_ERROR), as opposed to a clean end at a frame boundary.
     */
    private boolean hasPartialFrameData() {
        return inputBufferHasData && inputBuffer.hasRemaining();
    }


    /**
     * Checks whether the protocol input buffer holds at least one complete
     * frame (header and payload). Used by the async readiness path so a
     * partially received frame header is not advertised as readable: the
     * bytes cannot make progress until more socket data arrives.
     *
     * @return {@code true} if a complete frame is buffered
     */
    private boolean hasCompleteFrameInInputBuffer() {
        if (!inputBufferHasData || !inputBuffer.hasRemaining()) {
            return false;
        }
        int start = inputBuffer.position();
        try {
            if (!parseFrameHeader(inputBuffer, frameHeader)) {
                inputBuffer.position(start);
                return false;
            }
            long frameLength = frameHeader[1];
            boolean complete = frameLength <= inputBuffer.remaining();
            inputBuffer.position(start);
            return complete;
        } catch (Http3StreamException e) {
            inputBuffer.position(start);
            return false;
        }
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
     * Checks whether the request stream's read side can never progress again
     * because the owning connection was closed (or the stream wrapper was
     * already released). Unlike a clean FIN this must be reported to the
     * application as an error if the body is incomplete.
     */
    private static boolean isStreamConnectionClosed(
            SocketWrapperBase<?> socketWrapper) {
        QuicSocketWrapper quicWrapper = quicWrapper(socketWrapper);
        if (quicWrapper != null) {
            QuicStream stream = quicWrapper.getQuicStream();
            return stream == null || stream.isFreed() ||
                    stream.getReadState() == QuicStream.ReadState.CONN_CLOSED;
        }
        return false;
    }


    /**
     * Opportunistically consumes frames when the application asks whether
     * the trailer fields are ready. Used to decode a trailer section that is
     * already fully buffered and to record a clean FIN at a frame boundary
     * in the request input buffer, so that {@link #isTrailerFieldsReady()}
     * can report an empty trailer map for a complete request without trailers
     * instead of treating the clean end as an abandoned read.
     * <p>
     * The method never consumes a non-empty DATA frame: it rewinds to the
     * frame start and returns false so the body remains available to the
     * streaming read path. Frames that are only partially buffered are left
     * in the input buffer for the streaming/after-response paths.
     *
     * @param socketWrapper The socket wrapper
     * @return {@code true} if a trailer section was decoded or the stream was
     *         found to have ended cleanly at a frame boundary
     * @throws IOException If an I/O error occurs
     * @throws Http3Exception If a protocol error occurs
     * @throws QpackException If a QPACK error occurs
     */
    private boolean readTrailerSectionIfAvailable(SocketWrapperBase<?> socketWrapper)
            throws IOException, Http3Exception, QpackException {
        Http3InputBuffer inBuf = (Http3InputBuffer) request.getInputBuffer();
        if (inBuf.isTrailersReceived() || inBuf.isStreamClosed()) {
            return true;
        }
        // A partially read trailer section can be completed here: the
        // application is asking for trailer fields and the body may already
        // have been fully read (bodyComplete), in which case the streaming
        // read path will never run again to finish it. Use a non-blocking
        // read so an incomplete section does not block the caller.
        if (inBuf.trailerPayload != null) {
            if (socketWrapper == null) {
                return false;
            }
            return inBuf.completeTrailerSection(socketWrapper, false) == 1;
        }
        // A partially read DATA frame or ignored-frame skip belongs to the
        // streaming/after-response paths; do not touch it.
        if (inBuf.partialDataRemaining > 0 || inBuf.pendingSkipRemaining > 0) {
            return false;
        }
        if (socketWrapper == null) {
            return false;
        }

        while (true) {
            if (!inputBufferHasData || !inputBuffer.hasRemaining()) {
                int n = refillInputBuffer(socketWrapper, inputBuffer, false);
                if (n < 0) {
                    return handleTrailerReadEnd(socketWrapper, inBuf);
                }
                if (n == 0) {
                    return false;
                }
            }
            if (inputBuffer.remaining() < 2) {
                int n = refillInputBuffer(socketWrapper, inputBuffer, false);
                if (n < 0) {
                    return handleTrailerReadEnd(socketWrapper, inBuf);
                }
                if (n == 0) {
                    return false;
                }
                continue;
            }

            int frameStart = inputBuffer.position();
            if (!parseFrameHeader(inputBuffer, frameHeader)) {
                int n = refillInputBuffer(socketWrapper, inputBuffer, false);
                if (n < 0) {
                    return handleTrailerReadEnd(socketWrapper, inBuf);
                }
                if (n == 0) {
                    return false;
                }
                continue;
            }
            long frameType = frameHeader[0];
            long frameLen = frameHeader[1];

            switch (classifyBodyFrame(frameType)) {
                case TRAILERS -> {
                    checkBufferedFrameLength(frameType, frameLen);
                    long wireLimit = trailerFieldSectionWireLimit();
                    if (frameLen > wireLimit) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.header.sectionTooLarge",
                                        Long.valueOf(streamId), Long.valueOf(frameLen),
                                        Long.valueOf(wireLimit)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    if (inputBuffer.remaining() < frameLen) {
                        if (isStreamFin(socketWrapper)) {
                            throw truncatedFrameError();
                        }
                        inputBuffer.position(frameStart);
                        return false;
                    }
                    ByteBuffer payload = ByteBuffer.allocate((int) frameLen);
                    payload.put(inputBuffer);
                    payload.flip();
                    // A trailer section ends the message: the Content-Length
                    // invariant is checkable before decoding it.
                    if (requestContentLength > 0 &&
                            totalDataReceived < requestContentLength) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.bodyShorterThanContentLength",
                                        Long.valueOf(streamId),
                                        Long.valueOf(totalDataReceived),
                                        Long.valueOf(requestContentLength)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    processTrailerSection(payload);
                    // The trailer section may itself have installed a
                    // Content-Length (the allow-list can permit it); the
                    // message is complete here, so check the shortfall after
                    // the decode as finishTrailerSection() does.
                    if (requestContentLength > 0 &&
                            totalDataReceived < requestContentLength) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.bodyShorterThanContentLength",
                                        Long.valueOf(streamId),
                                        Long.valueOf(totalDataReceived),
                                        Long.valueOf(requestContentLength)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    inBuf.setTrailersReceived(true);
                    inBuf.setBodyComplete(true);
                    return true;
                }
                case DATA -> {
                    checkBufferedFrameLength(frameType, frameLen);
                    if (frameLen == 0) {
                        checkNonBodyFrame(frameType, 0);
                        continue;
                    }
                    if (dataOverrunsContentLength(totalDataReceived, frameLen)) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.dataFrameExceedsContentLength",
                                        Long.valueOf(streamId),
                                        Long.valueOf(totalDataReceived + frameLen),
                                        Long.valueOf(requestContentLength)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    if (inputBuffer.remaining() < frameLen) {
                        if (isStreamFin(socketWrapper)) {
                            throw truncatedFrameError();
                        }
                        // Leave the frame (including its header) for the
                        // streaming body read path once more data arrives.
                        inputBuffer.position(frameStart);
                        return false;
                    }
                    // Leave the complete DATA frame (including its header)
                    // for the streaming body read path.
                    inputBuffer.position(frameStart);
                    return false;
                }
                case CONTROL_ONLY -> {
                    inputBuffer.position(frameStart);
                    throw frameUnexpected(frameType);
                }
                case IGNORED -> {
                    checkNonBodyFrame(frameType, frameLen);
                    if (inputBuffer.remaining() < frameLen) {
                        if (isStreamFin(socketWrapper)) {
                            throw truncatedFrameError();
                        }
                        inputBuffer.position(frameStart);
                        return false;
                    }
                    if (frameLen > 0) {
                        inputBuffer.position(inputBuffer.position() + (int) frameLen);
                    }
                }
            }
        }
    }


    /*
     * Handles an end-of-stream encountered by
     * readTrailerSectionIfAvailable(). A clean frame-boundary FIN marks the
     * request input as closed; retained partial frame bytes are a truncated
     * last frame (connection error H3_FRAME_ERROR); a declared body shorter
     * than Content-Length is a malformed message (stream error
     * H3_MESSAGE_ERROR).
     */
    private boolean handleTrailerReadEnd(SocketWrapperBase<?> socketWrapper,
            Http3InputBuffer inBuf) throws Http3Exception {
        if (inputBufferHasData && inputBuffer.hasRemaining()) {
            if (isStreamFin(socketWrapper)) {
                throw truncatedFrameError();
            }
            // An abrupt reset may cut a frame anywhere; it is not a
            // truncated-frame error. The stream is simply abandoned, which
            // owes the peer a Stream Cancellation (RFC 9204 Section 2.2.2.2):
            // the partial frame may be the start of a trailer section that
            // references dynamic table entries.
            inBuf.setStreamClosed(true);
            noteStreamAbandoned();
            return true;
        }
        if (requestContentLength > 0 && totalDataReceived < requestContentLength &&
                isStreamFin(socketWrapper)) {
            throw new Http3StreamException(
                    sm.getString("http3Processor.bodyShorterThanContentLength",
                            Long.valueOf(streamId),
                                        Long.valueOf(totalDataReceived),
                            Long.valueOf(requestContentLength)),
                    Http3Error.H3_MESSAGE_ERROR, streamId);
        }
        inBuf.setStreamClosed(true);
        return true;
    }


    /**
     * Reads frames for the request body, pre-dispatch. Called for a request
     * that declares a body via Content-Length (see
     * {@link #isRequestBodyIndicated()}), and also when body frames were
     * already buffered together with the request head for a request that
     * did not declare a Content-Length: HTTP/3 bodies are not restricted to
     * particular methods (RFC 9114 Section 4.1; RFC 9110 Section 6.5), so
     * the declaration - not the method name - drives the pre-read. Reads
     * DATA frames until the declared body is buffered, a terminal frame
     * (TRAILERS) is encountered, a read would-block, the stream ends, or
     * the pre-buffer bound is reached.
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
        // One growable destination for all pre-dispatch DATA payload. A
        // ByteBuffer per DATA frame would let a peer send thousands of
        // one-byte frames and multiply the retained heap (one buffer object
        // plus array per frame) while staying below the 64 KiB payload bound.
        int bodyBufferCapacity;
        if (requestContentLength > 0) {
            bodyBufferCapacity = (int) Math.min(MAX_PRE_BUFFERED_BODY_BYTES,
                    requestContentLength);
        } else if (requestContentLength < 0) {
            // Undeclared body (delimited by stream end/trailers): pre-buffer
            // up to the same bound.
            bodyBufferCapacity = MAX_PRE_BUFFERED_BODY_BYTES;
        } else {
            // Declared zero-length body.
            bodyBufferCapacity = 0;
        }
        ByteBuffer bodyBuffer = bodyBufferCapacity > 0
                ? ByteBuffer.allocate(bodyBufferCapacity)
                : null;
        Http3InputBuffer inBuf = (Http3InputBuffer) request.getInputBuffer();

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
            switch (classifyBodyFrame(frameType)) {
                case DATA -> {
                    checkBufferedFrameLength(frameType, frameLen);
                    if (frameLen == 0) {
                        // No body progress, but still consumed a frame.
                        checkNonBodyFrame(frameType, 0);
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
                    // Bound the payload buffered pre-dispatch. The loop top
                    // already stops at MAX_PRE_BUFFERED_BODY_BYTES, so the
                    // remaining budget is always positive here.
                    int toBuffer = (int) Math.min(frameLen,
                            MAX_PRE_BUFFERED_BODY_BYTES - totalPayloadBytes);
                    // Read frame payload into the single pre-dispatch body
                    // buffer. Its capacity is bounded by both the content
                    // length and MAX_PRE_BUFFERED_BODY_BYTES, and the
                    // Content-Length check above guarantees toBuffer fits.
                    int payloadRead = copyFramePayload(inputBuffer, socketWrapper, bodyBuffer,
                            toBuffer, false);
                    boolean payloadIncomplete = payloadRead < toBuffer;
                    totalPayloadBytes += payloadRead;
                    totalDataReceived = totalPayloadBytes;
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
                        // Safe cast: the DATA frame length was checked
                        // against MAX_FRAME_LENGTH above.
                        inBuf.setPartialDataRemaining((int) (frameLen - payloadRead));
                        if (payloadEof) {
                            // A clean FIN cut the copy short: RFC 9114
                            // Section 7.1 makes a truncated last frame a
                            // connection error of type H3_FRAME_ERROR. An
                            // abrupt reset is not a truncated-frame error;
                            // the reset aborts the request instead.
                            if (isStreamFin(socketWrapper)) {
                                throw new Http3Exception(
                                        sm.getString("http3Processor.frameError",
                                                Long.valueOf(streamId)),
                                        Http3Error.H3_FRAME_ERROR);
                            }
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
                    checkBufferedFrameLength(frameType, frameLen);
                    // A HEADERS frame after the initial request HEADERS frame
                    // is the trailer section (see BodyFrameKind.TRAILERS).
                    // The declared-length preflight uses the wire-side bound
                    // of the field section limit (see fieldSectionWireLimit);
                    // the RFC-defined uncompressed check runs on decode.
                    long wireLimit = trailerFieldSectionWireLimit();
                    if (frameLen > wireLimit) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.header.sectionTooLarge",
                                        Long.valueOf(streamId), Long.valueOf(frameLen),
                                        Long.valueOf(wireLimit)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    // Safe cast: the HEADERS frame length was checked
                    // against MAX_FRAME_LENGTH above.
                    ByteBuffer trailerPayload =
                            ByteBuffer.allocate((int) frameLen);
                    int payloadRead = copyFramePayload(inputBuffer, socketWrapper,
                            trailerPayload, (int) frameLen, false);
                    if (payloadRead < frameLen && payloadEof) {
                        // FIN arrived before the trailer section was complete:
                        // a cleanly terminated stream with a truncated last
                        // frame is the connection error of RFC 9114 Section
                        // 7.1. An abrupt reset is not a truncated-frame error;
                        // it aborts the request as before.
                        if (isStreamFin(socketWrapper)) {
                            throw new Http3Exception(
                                    sm.getString("http3Processor.frameError",
                                            Long.valueOf(streamId)),
                                    Http3Error.H3_FRAME_ERROR);
                        }
                        throw new Http3StreamException(
                                sm.getString("http3Processor.header.error", Long.valueOf(streamId)),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    if (payloadRead < frameLen) {
                        // Would-block mid-section: stash the partial payload so
                        // the streaming read completes and decodes it before
                        // parsing any further frame header.
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
                                        Long.valueOf(streamId),
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
                    // Bound the amount of padding a peer can make this worker
                    // consume before it reaches the request body/trailer.
                    checkNonBodyFrame(frameType, frameLen);
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("http3Processor.frameIgnored",
                                Long.valueOf(streamId), Long.valueOf(frameType)));
                    }
                    long skipped = frameLen > 0 ?
                            skipFramePayload(socketWrapper, frameLen, false) : frameLen;
                    if (skipped < 0) {
                        if (isStreamFin(socketWrapper)) {
                            throw truncatedFrameError();
                        }
                        eof = true;
                        break readLoop;
                    }
                    if (skipped < frameLen) {
                        if (isStreamFin(socketWrapper)) {
                            // A clean FIN before the ignored frame's payload
                            // was fully skipped leaves a truncated last frame.
                            throw truncatedFrameError();
                        }
                        // Would-block mid-payload: remember the remainder so the
                        // streaming read path skips it before parsing the next
                        // frame header (the bytes must not be mis-parsed as one).
                        inBuf.setSkipRemaining(frameLen - skipped);
                        break readLoop;
                    }
                }
            }
        }

        // Publish the accumulated pre-dispatch body as one buffer. A
        // zero-length body buffer (content-length 0) yields no data.
        if (bodyBuffer != null) {
            bodyBuffer.flip();
            inBuf.setData(bodyBuffer);
        }

        // For a content-length body, the body is complete once all expected
        // DATA payload bytes have been received. A declared length of zero
        // means the body is complete as soon as the field section has been
        // decoded: no DATA payload is expected and any non-empty DATA frame
        // that arrives before dispatch is rejected as a Content-Length
        // violation above (RFC 9114 Section 4.1.2). Frames that arrive after
        // dispatch are checked by the streaming read and by the after-response
        // scan, so the body is complete without waiting for the stream to
        // close (matching the treatment of a fully received non-zero content
        // length).
        if (requestContentLength >= 0 && totalPayloadBytes >= requestContentLength) {
            inBuf.setBodyComplete(true);
        }

        // A clean FIN at a frame boundary means the whole request stream has
        // been consumed: there can be no later trailer section. Record that
        // in the input buffer so isTrailerFieldsReady() can report the empty
        // trailer map and the after-response scan does not mistake the clean
        // end for an abandoned read. A FIN observed mid-frame (payloadEof)
        // is a truncated frame and is handled as an error below/the caller.
        if (eof && !payloadEof && isStreamFin(socketWrapper)) {
            inBuf.setStreamClosed(true);
        }

        // Per RFC 9114 Section 4.1.2, a request whose body is shorter than
        // Content-Length is malformed. Only enforce this when the stream was
        // cleanly closed by the client (FIN); a stream reset or connection
        // close simply aborts the request.
        if (eof && requestContentLength > 0 && totalPayloadBytes < requestContentLength
                && isStreamFin(socketWrapper)) {
            throw new Http3StreamException(
                    sm.getString("http3Processor.bodyShorterThanContentLength",
                            Long.valueOf(streamId),
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
            // The request stream could not be drained after the response was
            // completed. Mark the failure so the processor is not reused, and
            // reset the stream explicitly: leaving an unconcluded stream to
            // the endpoint's close path signals H3_NO_ERROR, which hides the
            // truncation.
            if (socketWrapper != null) {
                setErrorState(ErrorState.CLOSE_CONNECTION_NOW, ioe);
                resetStream(socketWrapper, Http3Error.H3_INTERNAL_ERROR);
            }
            noteStreamAbandoned();
            return SocketState.CLOSED;
        }
        try {
            if (flushBufferedWrite()) {
                outputBuffer.flushBlocking();
            }
        }
        catch (IOException ioe) {
            // A failed final flush means the response was truncated. Reset the
            // stream instead of sending FIN after a partial frame, and mark
            // the processor as failed.
            setErrorState(ErrorState.CLOSE_CONNECTION_NOW, ioe);
            noteStreamAbandoned();
            if (socketWrapper != null) {
                resetStream(socketWrapper, Http3Error.H3_INTERNAL_ERROR);
            }
            return SocketState.CLOSED;
        }
        concludeStream(socketWrapper);
        return SocketState.CLOSED;
    }


    @Override
    protected boolean flushBufferedWrite() throws IOException {
        boolean dataLeft = outputBuffer.flushNonBlocking();
        if (dataLeft) {
            registerWriteInterest();
        } else if (finPending) {
            sendFinIfPossible(getSocketWrapper());
        }
        return dataLeft;
    }


    @Override
    protected boolean isTrailerFieldsReady() {
        Http3InputBuffer h3Input = (Http3InputBuffer) request.getInputBuffer();
        // A connection close before the body was complete is not a valid end
        // of the message: do not report an empty trailer map for it.
        if (h3Input.isStreamAborted() && !h3Input.isTrailersReceived() &&
                !h3Input.isBodyComplete()) {
            return false;
        }
        // A connection failure before the body/trailer section completed is
        // not an end of the message, even if the transport close marked the
        // stream closed. Reporting ready here would expose an empty trailer
        // map for an incomplete request.
        if (connectionFailed && !h3Input.isTrailersReceived() &&
                !h3Input.isBodyComplete()) {
            return false;
        }
        // Ready once the trailer section has been decoded, or once the
        // request stream has ended without one (the trailer fields are then
        // empty). Same end-of-request semantics as HTTP/2, which reports
        // ready once the stream can no longer read.
        if (h3Input.isTrailersReceived() || h3Input.isStreamClosed()) {
            return true;
        }
        // On the synchronous path the servlet thread is the only reader, so
        // opportunistically consume a trailer section or a clean frame-boundary
        // FIN that arrived after the pre-dispatch read. The async path leaves
        // this to the read listener's readMoreData() so the servlet thread
        // never races that reader.
        if (isAsync()) {
            return false;
        }
        SocketWrapperBase<?> socketWrapper = getSocketWrapper();
        try {
            return readTrailerSectionIfAvailable(socketWrapper);
        } catch (Http3StreamException e) {
            handleStreamError(socketWrapper, e.getError());
        } catch (Http3Exception e) {
            if (e.getError().isStreamError()) {
                handleStreamError(socketWrapper, e.getError());
            } else {
                failConnection(socketWrapper, e.getError());
            }
        } catch (QpackValueTooLargeException e) {
            handleStreamError(socketWrapper,
                    Http3Error.H3_QPACK_DECOMPRESSION_FAILED);
        } catch (QpackException e) {
            failConnection(socketWrapper,
                    Http3Error.H3_QPACK_DECOMPRESSION_FAILED);
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("http3Processor.error",
                        Long.valueOf(streamId)), e);
            }
            // The trailer read failed; the stream may still have unprocessed
            // field sections whose dynamic-table references must be released
            // on the peer's encoder stream (RFC 9204 Section 2.2.2.2).
            noteStreamAbandoned();
        }
        return h3Input.isTrailersReceived() || h3Input.isStreamClosed();
    }


    @Override
    protected boolean isTrailerFieldsSupported() {
        // Response trailers are sent as a second HEADERS frame before the
        // stream is concluded (RFC 9114 Section 4.1). Once the trailers have
        // been sent, the stream has been reset, the connection has failed,
        // or the response has been concluded, a newly registered supplier
        // can never be sent.
        return !trailersSent && !responseConcluded && !streamReset.get() &&
                !connectionFailed;
    }


    @Override
    protected boolean isReadyForWrite() {
        SocketWrapperBase<?> wrapper = getSocketWrapper();
        if (wrapper == null || streamReset.get() || connectionFailed ||
                responseConcluded || getErrorState().isError()) {
            return false;
        }
        boolean ready = outputBuffer.isReady();
        if (!ready) {
            registerWriteInterest();
        }
        return ready;
    }


    private void registerWriteInterest() {
        SocketWrapperBase<?> wrapper = getSocketWrapper();
        if (wrapper != null) {
            wrapper.registerWriteInterest();
        }
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
        // A connection close or reset before the body was complete is not a
        // successful end of the request body. The read path reports the
        // abort as an IOException / ReadListener.onError().
        if (h3Input.isStreamAborted() && !h3Input.isTrailersReceived() &&
                !h3Input.isBodyComplete()) {
            return false;
        }
        // A connection-level failure abandons the body even when the
        // transport close marked the stream closed; the read path reports
        // the failure as an I/O error.
        if (connectionFailed && !h3Input.isTrailersReceived() &&
                !h3Input.isBodyComplete()) {
            return false;
        }
        // A local protocol error also aborts the body, even though the stream
        // was not reset by the peer. The application must see an I/O error
        // rather than a clean EOF; the stream reset flag is set by
        // handleStreamError(), and bodyFrameError records connection-level
        // frame errors seen while the servlet was reading.
        if ((streamReset.get() || bodyFrameError != null) &&
                !h3Input.isTrailersReceived() && !h3Input.isBodyComplete()) {
            return false;
        }
        // The end of the body has been reached: the stream was closed
        // (FIN or connection close), a TRAILERS frame was received, or
        // the declared content length was fully received.
        if (h3Input.isStreamClosed() || h3Input.isTrailersReceived() || h3Input.isBodyComplete()) {
            return true;
        }
        // A connection close is not a valid end of an incomplete body: keep
        // reporting the body as unfinished so the read path can surface the
        // abort as an error (and so onAllDataRead() is not delivered).
        if (isStreamConnectionClosed(getSocketWrapper())) {
            return false;
        }
        // With no declared Content-Length the body is delimited by the end of
        // the request stream (FIN) or a trailer section; it cannot be
        // considered complete just because the method commonly does not carry
        // a body. Keep read interest registered so an async reader can consume
        // content sent with any method.
        return false;
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
        // concluded. The actual FIN is deferred to the synchronous service()
        // completion point or to dispatchEndRequest() on the asynchronous
        // path, after the after-response request-stream scan has run, so a
        // malformed request observed at FIN can still be reset at stream
        // scope before the response stream is concluded.
        SocketWrapperBase<?> socketWrapper = getSocketWrapper();
        if (socketWrapper != null && !responseStarted) {
            sendResponseHeadersInternal(socketWrapper);
        }
        // Finish compression (if enabled) before anything else is
        // written: the final deflate block and the gzip trailer are
        // emitted as DATA frames here and must precede the trailers and
        // the stream FIN. Without a body the gzip member still has to be
        // emitted, matching the HTTP/1.1 GzipOutputFilter behaviour.
        outputBuffer.end();
        sendResponseTrailers(socketWrapper);
        outputBuffer.flush();
        // The FIN is sent by the completion path after the request-stream
        // after-response scan; see the method comment.
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
                    !responseStarted && !ackSent && !streamReset.get() &&
                    !connectionFailed && !responseConcluded) {
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
        if (responseStarted || streamReset.get() || connectionFailed ||
                responseConcluded) {
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

        // Write the early hints as a HEADERS frame with no body. Use a
        // blocking write: the final response HEADERS/DATA and trailers are
        // written with blocking writes, and SocketWrapperBase.writeBlocking()
        // does not drain the non-blocking staging buffer before appending to
        // the socket write buffer (flushBlocking() writes the socket buffer
        // first and drains the staging buffer afterwards). A partially
        // accepted non-blocking 103 write would therefore let the final
        // response overtake the remainder of the interim HEADERS frame on
        // the wire. Blocking writes the complete interim frame first.
        sendHeadersFrame(socketWrapper, earlyHeaders, 1024, true);
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
        Http3InputBuffer h3Input = (Http3InputBuffer) request.getInputBuffer();
        // A local protocol error (malformed Content-Length, invalid frame
        // sequence in the body, etc.) must wake the async reader so its next
        // read reports the error rather than waiting for a socket event that
        // will never arrive.
        if ((streamReset.get() || bodyFrameError != null) &&
                !h3Input.isTrailersReceived() && !h3Input.isBodyComplete()) {
            return true;
        }
        // A connection-level failure must also wake the async reader so its
        // next read reports the failure as an I/O error.
        if (connectionFailed && !h3Input.isTrailersReceived() &&
                !h3Input.isBodyComplete()) {
            return true;
        }
        if (isStreamConnectionClosed(getSocketWrapper())) {
            if (!h3Input.isTrailersReceived() && !h3Input.isBodyComplete()) {
                return true;
            }
        }
        // A clean FIN that has not been consumed yet (the body is not marked
        // complete and no trailer section was decoded) must also wake an async
        // reader: the next read drains buffered data and returns EOF, allowing
        // onAllDataRead() (or the Content-Length shortfall error) to be
        // delivered. Without this check the listener would wait for a socket
        // event that never arrives again.
        if (isStreamFin(getSocketWrapper()) && !h3Input.isTrailersReceived() &&
                !h3Input.isBodyComplete()) {
            return true;
        }
        // A stream aborted by a connection close must also be reported as
        // ready: the next read throws an IOException, allowing the async
        // machinery to deliver onError() instead of leaving the listener
        // waiting for an event that can never arrive.
        if (h3Input.isStreamAborted() && !h3Input.isTrailersReceived() &&
                !h3Input.isBodyComplete()) {
            return true;
        }
        // A partially delivered DATA frame leaves body bytes either in the
        // protocol input buffer or in the QUIC stream. The buffered part is
        // immediately readable and must make the request ready; without this
        // check the async reader would wait for a new socket event even though
        // readMoreData() can make progress from bytes already retained.
        if (h3Input.getPartialDataRemaining() > 0) {
            return true;
        }
        // Bytes retained in the protocol input buffer can be consumed by the
        // next read even though no new socket event is pending, but only if
        // they form a complete frame. A partial frame header cannot make
        // progress without more socket data and must not be advertised as
        // readable.
        if (hasCompleteFrameInInputBuffer() &&
                !h3Input.isStreamClosed() && !h3Input.isTrailersReceived()) {
            return true;
        }
        // The wrapper may already hold read data (for example a body frame
        // read together with the request head) that has not yet been copied
        // into the processor input buffer. Such data can be consumed by the
        // next read even though no socket event is pending.
        SocketWrapperBase<?> socketWrapper = getSocketWrapper();
        if (socketWrapper != null) {
            try {
                if (socketWrapper.isReadyForRead()) {
                    return true;
                }
            } catch (IOException ioe) {
                // Report not-ready here; the next real read reports the error.
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("http3Processor.error",
                            Long.valueOf(streamId)), ioe);
                }
            }
        }
        return super.isReadyForRead();
    }


    @Override
    protected void setRequestBody(ByteChunk body) {
        // Saved-request replay (for example FormAuthenticator after a
        // successful login) uses ActionCode.REQ_SET_BODY_REPLAY. HTTP/3 must
        // serve the saved bytes and then report end of stream, as HTTP/1.1
        // and HTTP/2 do; a no-op would lose the replayed POST body.
        if (request.getInputBuffer() instanceof Http3InputBuffer h3Input) {
            h3Input.insertReplayedBody(body);
        }
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
        if (frameType == Constants.H3_HEADERS) {
            // The frame type/sequence is valid here, so a local buffering
            // limit must not downgrade the classification: reject the frame
            // at stream scope only after the position check above.
            checkBufferedFrameLength(frameType, frameLength);
        }
        if (frameType == Constants.H3_HEADERS &&
                frameLength > fieldSectionWireLimit()) {
            throw new Http3StreamException(
                    sm.getString("http3Processor.header.sectionTooLarge",
                            Long.valueOf(streamId), Long.valueOf(frameLength),
                            Long.valueOf(fieldSectionWireLimit())),
                    Http3Error.H3_MESSAGE_ERROR, streamId);
        }
        if (frameType != Constants.H3_HEADERS) {
            // Ignored/reserved padding before the request field section. The
            // frame is not buffered, but a peer must not be able to keep this
            // worker in the pre-header loop indefinitely with padding.
            checkNonBodyFrame(frameType, frameLength);
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
     * once more bytes arrive. Frame-type/position validation and the local
     * buffering limit for DATA/HEADERS are applied by the callers after (or
     * before) this parse, so a protocol-invalid frame keeps its required
     * error classification regardless of its declared length.
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
        out[0] = frameType;
        out[1] = frameLength;
        return true;
    }


    /*
     * Whether a frame type whose payload this receiver buffers on a request
     * stream (DATA, HEADERS) declares a length above the local buffering
     * limit. HTTP/3 has no negotiated frame size limit (unlike HTTP/2's
     * SETTINGS_MAX_FRAME_SIZE), so such a frame is protocol-valid; this
     * receiver merely declines to buffer it.
     * <p>
     * The check is deliberately separate from parseFrameHeader(): frame
     * sequence/position validation must run before it, so an invalid DATA or
     * HEADERS frame (for example DATA before HEADERS) keeps the connection
     * error classification required by RFC 9114 Section 4.1 instead of being
     * downgraded to a stream error by the local limit.
     */
    private boolean exceedsBufferedFrameLimit(long frameType, long frameLength) {
        return (frameType == Constants.H3_DATA ||
                frameType == Constants.H3_HEADERS) &&
                frameLength > MAX_FRAME_LENGTH;
    }


    /*
     * Rejects a valid DATA/HEADERS frame whose declared payload is above the
     * local buffering limit at stream scope (RESET_STREAM H3_FRAME_ERROR).
     * H3_FRAME_ERROR is used deliberately rather than the connection-scoped
     * H3_EXCESSIVE_LOAD suggested for local resource limits in RFC 9114
     * Section 10.5: this failure is scoped to the offending request stream,
     * and a stream reset with H3_FRAME_ERROR lets the client distinguish this
     * local buffering limit from a protocol-level frame-format error without
     * tearing down the other streams on the connection.
     */
    private void checkBufferedFrameLength(long frameType, long frameLength)
            throws Http3StreamException {
        if (exceedsBufferedFrameLimit(frameType, frameLength)) {
            throw new Http3StreamException(
                    sm.getString("http3Processor.frameError",
                            Long.valueOf(streamId)),
                    Http3Error.H3_FRAME_ERROR, streamId);
        }
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
        // The encoded field section can reveal header names and literal
        // values (credentials, cookies, tokens); keep the dump at TRACE.
        if (log.isTraceEnabled()) {
            StringBuilder sb = new StringBuilder("Stream [" + streamId + "] Decoding HEADERS frame, payload=" + pendingFramePayload.remaining() + " bytes: ");
            for (int i = 0; i < pendingFramePayload.remaining(); i++) {
                sb.append(String.format("%02X ", pendingFramePayload.get(i)));
            }
            log.trace(sb.toString());
        }
        // Determine whether the field section references the dynamic
        // table (Required Insert Count > 0) from the first byte of the
        // field section prefix (RFC 9204 Section 4.5.1): the Required
        // Insert Count is an 8-bit prefix integer occupying the entire
        // first byte, so it is non-zero iff the first byte is non-zero.
        boolean ricNonZero = pendingFramePayload.remaining() > 0
                && pendingFramePayload.get(0) != 0;
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
        }
        if (log.isTraceEnabled()) {
            log.trace("Stream [" + streamId + "] QPACK decode successful. Headers: " + request.getMethod() + " " + request.requestURI());
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
        if (log.isTraceEnabled()) {
            log.trace("Stream [" + streamId + "] Headers received: " + request.getMethod() + " " + request.requestURI().toString());
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
        Http3ConnectionManager manager = getConnectionManager();
        int maxHeaderSize = manager != null ?
                Constants.clampToNonNegativeInt(
                        manager.getMaxFieldSectionSize()) :
                protocol.getMaxFieldSectionSizeInt();
        decodeFieldSection(payload, protocol.getMaxHeaderCount(), maxHeaderSize);
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
            Http3ConnectionManager manager = getConnectionManager();
            int blockedStreams = manager != null ?
                    manager.getQpackBlockedStreams() :
                    protocol.getQpackBlockedStreams();
            if (blockedStreams < 1 ||
                    !awaitRequiredInsertCount(e.getRequiredInsertCount(),
                            blockedStreams)) {
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
    private boolean awaitRequiredInsertCount(long requiredInsertCount,
            int blockedStreams) {
        Http3ConnectionManager manager = getConnectionManager();
        QuicConnection conn = quicConnection(getSocketWrapper());
        if (manager == null || conn == null ||
                !manager.acquireBlockedStreamSlot(conn, blockedStreams)) {
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
     * Resets the QUIC stream with the given HTTP/3 stream error code.
     */
    private void resetStream(SocketWrapperBase<?> socketWrapper, Http3Error error) {
        outputBuffer.discardPendingFrames();
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
        // RFC 9114 Section 4.1: a trailer section follows the final response
        // HEADERS frame. Do not attempt a trailer HEADERS frame when the
        // final headers were never written (sendResponseHeadersInternal()
        // only sets responseStarted after the HEADERS frame is written, so a
        // failed header send leaves this false) or when the stream was reset
        // (the reset path claims responseStarted without writing anything).
        // Writing trailers on a reset stream or without a final response
        // head would produce an invalid response sequence.
        if (!responseStarted || streamReset.get() || connectionFailed ||
                responseConcluded || socketWrapper == null) {
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
                String trailerValue = trailerField.getValue();
                if (trailerValue == null) {
                    // The trailer map is application-supplied and may contain
                    // a null value; MessageBytes would become T_NULL and the
                    // QPACK encoder would NPE trying to read it.
                    continue;
                }
                MessageBytes mb = trailerHeaders.addValue(trailerName);
                mb.setString(trailerValue);
            }
        }
        // Apply the HTTP/3 connection-specific prohibition before deciding
        // whether any trailer fields remain.
        for (String name : CONNECTION_SPECIFIC_HEADERS) {
            trailerHeaders.removeHeader(name);
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


    /*
     * The ENABLE_CONNECT_PROTOCOL value advertised in this connection's
     * SETTINGS frame. It must be the per-connection snapshot - not the live
     * connector property - so request validation cannot accept an extension
     * that was never negotiated, or reject one that was.
     */
    private boolean isEnableConnectProtocol() {
        if (connectionState != null) {
            return connectionState.isEnableConnectProtocol();
        }
        return protocol.isEnableConnectProtocol();
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
            if (hasProtocol && !isEnableConnectProtocol()) {
                // RFC 9220 Section 3.2: a client MUST NOT send :protocol
                // unless the server advertised ENABLE_CONNECT_PROTOCOL. The
                // advertisement is a per-connection SETTINGS snapshot, so the
                // validation must use the same snapshot rather than the live
                // connector property (which may have changed at runtime).
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
            if ((seenPseudoHeaders & PSEUDO_AUTHORITY) == 0) {
                // RFC 9114 Section 4.4 requires the :authority pseudo-header
                // for CONNECT; a Host header alone is not sufficient.
                throw messageError("http3Processor.header.connectAuthorityMissing",
                        Long.valueOf(streamId));
            }
            if (request.serverName().isNull()) {
                // The :authority was present but too malformed to yield a
                // host name (the malformed value also records the
                // bad-request note; the malformed-message handling takes
                // precedence, as in HTTP/2's receivedEndOfHeaders()).
                throw messageError("http3Processor.header.connectAuthorityInvalid",
                        Long.valueOf(streamId));
            }
            if (!hasProtocol && request.getServerPort() == -1) {
                // A plain tunnel CONNECT uses the authority-form (host ":"
                // port). RFC 8441 Section 4 interprets the :authority of an
                // extended CONNECT (one carrying :protocol) using the normal
                // request-authority rules instead, where the port is optional.
                throw messageError("http3Processor.header.connectAuthorityNoPort",
                        Long.valueOf(streamId));
            }
            if (hasProtocol) {
                // RFC 9220/8441 extended CONNECT carries a normal :path that
                // identifies the targeted resource (RFC 9114 Section 4.3.1,
                // RFC 3986 path-absolute); apply the same request-target and
                // query validation as a non-CONNECT request.
                validateRequestTarget();
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
            // present -> the authority is undeterminable: malformed. Only
            // http and https have a mandatory authority; a non-HTTP scheme
            // may legitimately omit it.
            String scheme = request.scheme().toString();
            boolean authorityRequired = "http".equalsIgnoreCase(scheme) ||
                    "https".equalsIgnoreCase(scheme);
            if (authorityRequired && request.serverName().isNull()) {
                throw messageError("http3Processor.header.authorityMissing",
                        Long.valueOf(streamId));
            }

            // RFC 9114 Section 4.3.1 does not restrict the value of the
            // :scheme pseudo-header for non-CONNECT requests; any scheme is
            // accepted.

            validateRequestTarget();
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
     * Validates the request-target and query string of a request that carries
     * a :path pseudo-header. Shared by non-CONNECT requests and RFC 9220
     * extended CONNECT requests, whose :path identifies the targeted resource
     * like a normal request.
     */
    private void validateRequestTarget() throws Http3Exception {
        // RFC 9114 Section 4.3.1: The :path pseudo-header MUST NOT be empty
        String path = request.requestURI().toString();
        if (path.isEmpty()) {
            throw messageError("http3Processor.header.emptyPath",
                    Long.valueOf(streamId));
        }

        // RFC 9110 Section 7.1: the request target and query string are
        // restricted character sets. Apply the same relaxed whitelists
        // HTTP/2's validateRequest() applies before dispatch, so a target
        // outside the set fails cleanly here as a malformed message instead
        // of hitting undefined behaviour inside the adapter (normalization
        // failure, dispatcher split, odd %-sequences).
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
     * A cleanly terminated stream whose last frame (or frame header) is
     * truncated is a connection error of type H3_FRAME_ERROR (RFC 9114
     * Section 7.1). Shared by the frame readers so the classification and
     * message live in one place.
     */
    private Http3Exception truncatedFrameError() {
        String message = sm.getString("http3Processor.frameError",
                Long.valueOf(streamId));
        if (log.isDebugEnabled()) {
            log.debug(message);
        }
        return new Http3Exception(message, Http3Error.H3_FRAME_ERROR);
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
        request.protocol().setString("HTTP/3.0");
        return true;
    }


    /**
     * Sends the HTTP/3 response.
     */
    private void sendResponse(SocketWrapperBase<?> socketWrapper) throws IOException {
        // The stream was reset or the connection failed while the servlet
        // handled the request (e.g. a request body that over-ran its
        // Content-Length, RFC 9114 Section 4.1.2): the response is suppressed.
        if (streamReset.get() || connectionFailed) {
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

        // The FIN is sent by service() after the request-stream
        // after-response scan, so a malformed request observed at FIN can
        // still be reset at stream scope before the response is concluded.
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
        // Stream reset or connection failure (see sendResponse()): no
        // response bytes may be written. Claim the response as started so
        // later attempts (including the servlet's own flushes) stay silent.
        if (streamReset.get() || connectionFailed) {
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
        setResponseStatus(h, statusCode);

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
            if (statusCode < 200 || statusCode == 204) {
                // RFC 9110 Section 8.6: a server MUST NOT send a
                // Content-Length field in a 1xx or 204 response.
                h.removeHeader("content-length");
            }
            if (statusCode == 205) {
                // RFC 9110 Section 15.3.5 requires a Content-Length: 0
                // field in a 205 response, and the application-supplied value
                // (if any) must not survive with a non-zero length.
                h.setValue("content-length").setLong(0);
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
        response.setCommitted(true);
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
        // The response is complete from the application's point of view even
        // if the native FIN write fails or the stream was already concluded.
        responseConcluded = true;
        finPending = true;
        if (streamReset.get() || connectionFailed || getErrorState().isError()) {
            // A reset or failed connection already terminated the write side
            // with its own error signal. Sending FIN afterwards would violate
            // QUIC stream ordering (RFC 9000 Section 3.5).
            finPending = false;
            outputBuffer.discardPendingFrames();
            return;
        }
        if (outputBuffer.hasPendingData()) {
            registerWriteInterest();
            return;
        }
        sendFinIfPossible(socketWrapper);
    }


    private void sendFinIfPossible(SocketWrapperBase<?> socketWrapper) {
        if (!finPending || finSent) {
            return;
        }
        if (streamReset.get() || connectionFailed || getErrorState().isError()) {
            finPending = false;
            return;
        }
        if (outputBuffer.hasPendingData()) {
            registerWriteInterest();
            return;
        }
        finPending = false;
        finSent = true;
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
        if (socketWrapper == null) {
            return;
        }
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
                    // observable to classify. A clean FIN with a partially
                    // received frame header is a truncated last frame and
                    // therefore a connection error (RFC 9114 Section 7.1).
                    if (isStreamFin(socketWrapper) && hasPartialFrameData()) {
                        failConnection(socketWrapper,
                                Http3Error.H3_FRAME_ERROR);
                    }
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
                        if (noteNonBodyFrame(frameLen)) {
                            failConnection(socketWrapper,
                                    Http3Error.H3_EXCESSIVE_LOAD);
                            return;
                        }
                        long skipped = frameLen > 0 ? skipFramePayload(
                                socketWrapper, frameLen, false) : frameLen;
                        if (skipped < frameLen) {
                            if (isStreamFin(socketWrapper)) {
                                // Clean FIN in the middle of the ignored
                                // frame's payload: truncated final frame
                                // (RFC 9114 Section 7.1).
                                failConnection(socketWrapper,
                                        Http3Error.H3_FRAME_ERROR);
                            }
                            // Otherwise would-block or an abrupt reset:
                            // nothing more observable to classify.
                            return;
                        }
                    }
                }
            }
        } catch (Http3StreamException e) {
            // Defensive: the header parser no longer rejects an oversized
            // frame itself; the frame sequence is classified before any
            // local limit applies. The stream is already concluded, so
            // there is nothing left to reset and the connection outcome is
            // unchanged.
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
     * processed, and anything short of that is abandoned - an abandoned
     * section still owes the peer a Stream Cancellation (RFC 9204 Section
     * 2.2.2.2). Frames other than a second HEADERS frame stop the scan
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
        if (streamReset.get()) {
            // The stream was already reset (for example at stream scope for a
            // Content-Length overrun). Reading its remaining bytes here could
            // misclassify the already abandoned stream data as a truncated
            // frame and escalate to a connection error; the reset already
            // reported the stream failure and released its QPACK state.
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
            // this stream again). A clean FIN here means the last frame is
            // truncated (RFC 9114 Section 7.1, H3_FRAME_ERROR); without FIN
            // the read is simply abandoned and owes a Stream Cancellation.
            if (isStreamFin(socketWrapper)) {
                failConnection(socketWrapper, Http3Error.H3_FRAME_ERROR);
            } else {
                noteStreamAbandoned();
            }
            inBuf.trailerPayload = null;
            return;
        }
        if (inBuf.partialDataRemaining > 0 || inBuf.pendingSkipRemaining > 0) {
            // Mid-frame: DATA payload bytes still owed, or an ignored
            // frame's skip still in progress. Parsing anything from here
            // would mis-consume them as a frame header. A clean FIN means
            // the last frame is truncated; otherwise the rest of the stream
            // (including a possible trailer section) is abandoned.
            if (isStreamFin(socketWrapper)) {
                failConnection(socketWrapper, Http3Error.H3_FRAME_ERROR);
            } else if (!inBuf.isStreamClosed()) {
                noteStreamAbandoned();
            }
            return;
        }
        try {
            while (true) {
                // Parse (once at least two bytes are buffered), refilling
                // on failure - the shared parseFrameHeaderWithRefill() shape:
                // a read boundary inside a varint leaves two or more bytes
                // that are only a partial header, and giving up on the byte
                // count alone would miss a header completed by the refill.
                if (parseFrameHeaderWithRefill(socketWrapper) != HEADER_PARSED) {
                    // Would-block or the stream ended: nothing more is
                    // observable to decode. A clean frame-boundary FIN means
                    // the request is complete with no trailer section; record
                    // that, so this is not mistaken for an abandoned read and
                    // no unnecessary Stream Cancellation is queued. If bytes
                    // were retained, or the stream is still open, the
                    // remaining data (possibly a trailer section) is being
                    // abandoned.
                    if (!inBuf.isStreamClosed()) {
                        if (isStreamFin(socketWrapper) && hasPartialFrameData()) {
                            // Clean FIN with a partially received frame
                            // header: truncated final frame (RFC 9114
                            // Section 7.1).
                            failConnection(socketWrapper,
                                    Http3Error.H3_FRAME_ERROR);
                        } else if (isStreamFin(socketWrapper)) {
                            if (requestContentLength > 0 &&
                                    totalDataReceived < requestContentLength) {
                                // The clean frame-boundary FIN makes the
                                // Content-Length shortfall fully observable:
                                // the request is malformed (RFC 9114 Section
                                // 4.1.2).
                                throw new Http3StreamException(
                                        sm.getString(
                                                "http3Processor.bodyShorterThanContentLength",
                                                Long.valueOf(streamId),
                                        Long.valueOf(totalDataReceived),
                                                Long.valueOf(requestContentLength)),
                                        Http3Error.H3_MESSAGE_ERROR, streamId);
                            }
                            inBuf.setStreamClosed(true);
                        } else {
                            noteStreamAbandoned();
                        }
                    }
                    return;
                }
                long frameType = frameHeader[0];
                long frameLen = frameHeader[1];
                switch (classifyBodyFrame(frameType)) {
                    case TRAILERS -> {
                        checkBufferedFrameLength(frameType, frameLen);
                        long wireLimit = trailerFieldSectionWireLimit();
                        if (frameLen > wireLimit) {
                            // Malformed (declared beyond the field section
                            // limit). Use the same error as the live trailer
                            // paths, even though the response has already been
                            // answered: the request itself is malformed, and
                            // the reset also releases the QPACK references of
                            // the abandoned section.
                            handleStreamError(socketWrapper,
                                    Http3Error.H3_MESSAGE_ERROR);
                            return;
                        }
                        // Safe cast: the HEADERS frame length was checked
                        // against MAX_FRAME_LENGTH above.
                        ByteBuffer trailerPayload =
                                ByteBuffer.allocate((int) frameLen);
                        int payloadRead = copyFramePayload(inputBuffer,
                                socketWrapper, trailerPayload, (int) frameLen,
                                false);
                        if (payloadRead < frameLen) {
                            // Would-block or FIN mid-section: the section will
                            // never be decoded. Record any dynamic-table use
                            // observable from the first received byte. A clean
                            // FIN with a truncated trailer frame is the
                            // connection error of RFC 9114 Section 7.1;
                            // otherwise this is an abandoned read and owes a
                            // Stream Cancellation (RFC 9204 Section 2.2.2.2).
                            if (isStreamFin(socketWrapper)) {
                                failConnection(socketWrapper,
                                        Http3Error.H3_FRAME_ERROR);
                            } else {
                                noteStreamAbandoned();
                            }
                            return;
                        }
                        trailerPayload.flip();
                        processTrailerSection(trailerPayload);
                        // A trailer section ends the message, so the
                        // Content-Length invariant is fully observable here.
                        // The two live body-read paths apply the same check
                        // (the pre-dispatch trailer reader and
                        // finishTrailerSection()); applying it here as well
                        // keeps a request that the application never drained
                        // from escaping detection just because this
                        // after-response scan is the only path that saw the
                        // trailers (RFC 9114 Section 4.1.2).
                        if (requestContentLength > 0 &&
                                totalDataReceived < requestContentLength) {
                            handleStreamError(socketWrapper,
                                    Http3Error.H3_MESSAGE_ERROR);
                            return;
                        }
                        inBuf.setTrailersReceived(true);
                        inBuf.setBodyComplete(true);
                        // A trailer ends the message. Any frames after it are
                        // handled (and rejected if invalid) by
                        // checkFramesAfterTrailer().
                        return;
                    }
                    case CONTROL_ONLY -> {
                        // A control-stream-confined, PUSH_PROMISE or reserved
                        // HTTP/2 frame type on a request stream is a
                        // connection error of type H3_FRAME_UNEXPECTED (RFC
                        // 9114 Sections 4.1, 7.2.3 through 7.2.8, 11.2.1).
                        // The live body-read paths enforce this, but a
                        // body-less request never runs them; this
                        // after-response scan is then the only frame consumer
                        // and must apply the same rule.
                        failConnection(socketWrapper,
                                frameUnexpected(frameType).getError());
                        return;
                    }
                    case DATA -> {
                        if (frameLen == 0) {
                            // RFC 9114 Section 4.1 permits zero-length DATA
                            // frames before the trailer section. They make no
                            // body progress; ignore them and continue to the
                            // trailer (bounded by the non-body-frame budget).
                            if (noteNonBodyFrame(frameLen)) {
                                failConnection(socketWrapper,
                                        Http3Error.H3_EXCESSIVE_LOAD);
                                return;
                            }
                            continue;
                        }
                        // A non-empty DATA frame is request content. Reading
                        // it here is not needed for the response and would
                        // require consuming the body. Check the declared frame
                        // length against Content-Length before abandoning the
                        // remainder: an overrun that arrives after the body was
                        // completed is still a malformed request (RFC 9114
                        // Section 4.1.2).
                        if (dataOverrunsContentLength(totalDataReceived, frameLen)) {
                            handleStreamError(socketWrapper,
                                    Http3Error.H3_MESSAGE_ERROR);
                            return;
                        }
                        if (!inBuf.isStreamClosed()) {
                            noteStreamAbandoned();
                        }
                        return;
                    }
                    case IGNORED -> {
                        // RFC 9114 Section 9 requires unknown/reserved frames
                        // to be ignored. Skip a complete payload and continue
                        // scanning for the trailer; a truncated payload at a
                        // clean FIN is the connection error of Section 7.1.
                        if (noteNonBodyFrame(frameLen)) {
                            failConnection(socketWrapper,
                                    Http3Error.H3_EXCESSIVE_LOAD);
                            return;
                        }
                        if (frameLen == 0) {
                            continue;
                        }
                        long skipped = skipFramePayload(socketWrapper, frameLen,
                                false);
                        if (skipped < frameLen) {
                            if (isStreamFin(socketWrapper)) {
                                failConnection(socketWrapper,
                                        Http3Error.H3_FRAME_ERROR);
                            } else if (!inBuf.isStreamClosed()) {
                                noteStreamAbandoned();
                            }
                            return;
                        }
                    }
                }
            }
        } catch (Http3Exception e) {
            // Malformed frame header or trailer section after the response
            // has been answered: report the abandonment for any section that
            // referenced the dynamic table before failing. Connection-level
            // codes (H3_EXCESSIVE_LOAD from the decoder-instruction backlog)
            // must fail the connection rather than reset the stream.
            handleStreamOrConnectionError(socketWrapper, e);
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
        // HTTP/3 field values are byte strings validated by the per-position
        // HttpParser.isFieldVChar()/isFieldContent() loop above; QPACK
        // decoding deliberately performs no UTF-8 validation.
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
                // RFC 9114 Section 4.3: All pseudo-header fields MUST appear
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
                    // RFC 3986 Section 3.1: scheme names are
                    // case-insensitive. Store the canonical lower-case form
                    // so downstream consumers (for example
                    // CoyoteAdapter.postParseRequest(), which compares the
                    // request scheme with "https" case-sensitively to set
                    // request.isSecure()) see the same scheme that this
                    // consistency check accepted.
                    String canonicalScheme = value.toLowerCase(Locale.ENGLISH);
                    request.scheme().setString(canonicalScheme);
                    // Connector policy ported from HTTP/2 (Stream.java
                    // :scheme case): unless allowSchemeMismatch is set, the
                    // scheme must be consistent with the TLS state of the
                    // connector. QUIC always uses TLS, so "https" is
                    // expected.
                    if (!protocol.getAllowSchemeMismatch() &&
                            "https".equals(canonicalScheme) != protocol.isSSLEnabled()) {
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
                    if (!HttpParser.isToken(value)) {
                        throw new Http3StreamException(
                                sm.getString("http3Processor.header.invalid",
                                        Long.valueOf(streamId), name),
                                Http3Error.H3_MESSAGE_ERROR, streamId);
                    }
                    request.setAttribute(
                            Constants.ATTR_EXTENDED_CONNECT_PROTOCOL, value);
                    break;
                default:
                    break;
            }
        } else {
            pseudoHeadersDone = true;
            // Track content-length for request body validation. The
            // content-length and host cases are deliberately not applied to
            // trailer sections: RFC 9110 Sections 6.5/6.5.1 forbid using a
            // trailer field for message framing or routing, and using a
            // trailer Host for the request authority would let a trailer
            // satisfy the initial header-section validation. Allowed trailer
            // fields of these names remain ordinary trailer fields below.
            if (!trailerMode && "content-length".equals(name)) {
                if (requestContentLength >= 0) {
                    // Per RFC 9114 Section 4.2, a request with multiple
                    // Content-Length header fields is malformed.
                    throw new Http3StreamException(
                            sm.getString("http3Processor.header.duplicate", Long.valueOf(streamId), name),
                            Http3Error.H3_MESSAGE_ERROR, streamId);
                }
                try {
                    // RFC 9110 Section 8.6 defines Content-Length as
                    // 1*DIGIT. Long.parseLong() alone would also accept a
                    // leading '+' and "-0" (which is numerically zero), so
                    // reject anything outside the digit grammar before
                    // parsing. This also keeps HTTP/3 consistent with the
                    // digit-only parser used by HTTP/1.1.
                    if (value == null || value.isEmpty()) {
                        throw new NumberFormatException();
                    }
                    for (int i = 0; i < value.length(); i++) {
                        char c = value.charAt(i);
                        if (c < '0' || c > '9') {
                            throw new NumberFormatException();
                        }
                    }
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
            } else if (!trailerMode && "host".equals(name)) {
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
                // Host.parse() permits an empty port (RFC 3986 Section
                // 3.2.3): it is equivalent to no port. Do not try to parse
                // the empty string as an integer; leave the server port for
                // CoyoteAdapter to populate from the scheme default.
                String port = value.substring(i + 1);
                if (!port.isEmpty()) {
                    request.setServerPort(Integer.parseInt(port));
                }
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
            String host = i == -1 ? value : value.substring(0, i);
            String portText = i == -1 ? "" : value.substring(i + 1);
            boolean portSpecified = !portText.isEmpty();
            if (!host.equals(request.serverName().getString()) ||
                    (!portSpecified && request.getServerPort() != -1) ||
                    (portSpecified &&
                            Integer.parseInt(portText) != request.getServerPort())) {
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
    public boolean isReusable() {
        return reusable;
    }


    @Override
    public void recycle() {
        // Decide whether this processor may safely be returned to the shared
        // pool before super.recycle() resets the error state. An error or
        // stream/connection reset means an application thread may still be
        // blocked in a write using this processor; reusing it could send the
        // stale response to a later request on another stream/connection.
        reusable = !getErrorState().isError() && !streamReset.get() &&
                !connectionFailed;
        // If this processor is being torn down after a local error/reset and
        // no cancellation was queued by the error path, release any dynamic
        // table references the peer's encoder may still hold for field
        // sections this stream never processed (RFC 9204 Section 2.2.2.2).
        if (!streamCancellationSent && !connectionFailed &&
                (getErrorState().isError() || streamReset.get())) {
            noteStreamAbandoned();
        }
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
        // Drop any in-progress or aborted encoding state, including its
        // reference to the previous response's MimeHeaders.
        qpackEncoder.resetEncodingState();
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

        if (!reusable) {
            // A non-container thread may still hold this processor's request,
            // response or output buffer after an error/reset. The processor is
            // not returned to the pool (isReusable() is false), so do not
            // recycle that state while the application thread can still use
            // it. Detach the processor from the stream so any late write
            // cannot reach a finalised QUIC stream.
            setSocketWrapper(null);
            streamId = -1;
            return;
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
        // Notes are not reset when request is recycled but this is a per
        // request note. Clear it before recycling so a malformed request
        // (bad :authority or Host) cannot make the next request handled by
        // this pooled processor fail with a stale 400 response.
        request.setNote(org.apache.coyote.Request.NOTE_BAD_REQUEST, null);
        request.recycle();
        response.recycle();

        headersReceived = false;
        requestStreamEof = false;
        // payloadEof/payloadBlocked describe the last copyFramePayload()
        // call, but service() also reads payloadEof before any copy in the
        // new request (when a frame header is only partially buffered and the
        // read would block). Leaving the previous request's value set would
        // make a live stream look ended; clear both with the other
        // per-request parser state.
        payloadEof = false;
        payloadBlocked = false;
        responseStarted = false;
        ackSent = false;
        trailersSent = false;
        responseConcluded = false;
        finPending = false;
        finSent = false;
        pseudoHeadersDone = false;
        seenPseudoHeaders = 0;
        hostHeaderSeen = false;
        trailerMode = false;
        cookieHeader = null;
        streamCancellationSent = false;
        // Drop any per-response compression state so the next request
        // handled by this (pooled) processor starts uncompressed. Runs
        // before the streamReset flag below is cleared so that, on a reset
        // stream, the close inside emits its trailer bytes into the
        // swallow path instead of a dead QUIC stream.
        outputBuffer.resetCompression();
        outputBuffer.resetQueue();
        streamReset.set(false);
        pendingFrameType = -1;
        pendingFrameLength = 0;
        pendingFrameRead = 0;
        pendingFramePayload = null;
        inputBuffer.clear();
        inputBufferHasData = false;
        lastReadEndedWithException = false;
        requestContentLength = -1;
        totalDataReceived = 0;
        nonBodyFrameCount = 0;
        nonBodyFrameBytes = 0;

        // Reset input buffer data
        if (request.getInputBuffer() instanceof Http3InputBuffer h3Input) {
            h3Input.reset();
        }

        // Reset output buffer byte counter so access log reports per-request bytes
        outputBuffer.resetBytesWritten();
        // Reset void output so a 204/304/HEAD response does not suppress the
        // body of the next request handled by this processor
        outputBuffer.resetVoidOutput();
        // Do not keep a pooled processor's last stream/connection reachable.
        // HTTP/1.1 and HTTP/2 clear the wrapper in recycle() as well; the
        // compression reset above is the last user of the old wrapper.
        streamId = -1;
        setSocketWrapper(null);
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
        // New streams on existing connections are rejected in service() while
        // the endpoint is paused; requests already being processed continue to
        // completion. (QUIC flow control only limits bytes on existing
        // streams, it does not stop the peer creating new streams.)
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
        /*
         * True when the stream ended without a clean QUIC FIN: a connection
         * close or a stream reset. A stream reset is also reported by
         * processor.isStreamReset() and is handled separately; a connection
         * close has no such per-stream signal and would otherwise be
         * indistinguishable from a clean end of stream at the read layer.
         */
        private boolean streamAborted = false;
        // Whether the first EOF/reset observation has already classified the
        // stream end. Later read attempts may run after the stream wrapper has
        // been released, so they must not reclassify a clean FIN as a
        // connection close.
        private boolean streamEndClassified = false;
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


        /**
         * Replaces the input with a saved request body (for example the body
         * replayed by {@code FormAuthenticator} after authentication) and
         * records that the request stream is complete. The bytes are copied
         * so a later reuse of the source {@link ByteChunk} cannot mutate the
         * replayed input.
         *
         * @param body The saved request body, or {@code null} for an empty one
         */
        void insertReplayedBody(ByteChunk body) {
            dataBuffers.clear();
            totalRemaining = 0;
            currentBufferIndex = 0;
            if (body != null && body.getLength() > 0) {
                ByteBuffer replay = ByteBuffer.allocate(body.getLength());
                replay.put(body.getBytes(), body.getStart(), body.getLength());
                replay.flip();
                dataBuffers.add(replay);
                totalRemaining = replay.remaining();
            }
            markStreamClosed();
            streamAborted = false;
            trailersReceived = false;
            partialDataRemaining = 0;
            pendingSkipRemaining = 0;
            bodyComplete = true;
            trailerPayload = null;
        }


        void reset() {
            dataBuffers.clear();
            totalRemaining = 0;
            currentBufferIndex = 0;
            streamClosed = false;
            streamAborted = false;
            streamEndClassified = false;
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


        /*
         * Marks the body complete once the streaming read path has delivered
         * all bytes declared by Content-Length. The pre-dispatch reader already
         * applies the same rule; without this update a body larger than the
         * pre-dispatch buffer never reaches the completed state, so the
         * application-facing read would wait for FIN/trailers (or the stall
         * timeout) after the declared body was fully delivered.
         */
        private void updateBodyComplete() {
            if (processor.requestContentLength >= 0 &&
                    processor.totalDataReceived >= processor.requestContentLength) {
                bodyComplete = true;
            }
        }


        boolean isBodyComplete() {
            return bodyComplete;
        }


        boolean isStreamClosed() {
            return streamClosed;
        }


        boolean isStreamAborted() {
            return streamAborted;
        }


        /*
         * Records that the stream can no longer produce input and classifies
         * the ending. Only a clean QUIC FIN leaves streamAborted false; a
         * connection close or stream reset marks the stream aborted so a
         * truncated application read is reported as an I/O error instead of
         * a clean EOF. The reset case is additionally detected by
         * isStreamReset() and reported with the reset-specific error before
         * this flag is consulted.
         */
        private void markStreamClosed() {
            if (streamEndClassified) {
                return;
            }
            streamEndClassified = true;
            streamClosed = true;
            streamAborted = processor.lastReadEndedWithException &&
                    !processor.isStreamFin(processor.getSocketWrapper());
        }


        /**
         * Records that the request stream has reached an end of stream.
         * Used when a frame-boundary FIN is observed by a protocol read path
         * that is not the application-facing {@link #doRead()} path, and by
         * the error paths that abandon the stream.
         *
         * @param closed {@code true} once the stream can no longer produce
         *               input
         */
        void setStreamClosed(boolean closed) {
            if (closed) {
                markStreamClosed();
            } else {
                streamClosed = false;
                streamAborted = false;
                streamEndClassified = false;
            }
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
            // data and no stream close, the stream is reset with
            // H3_REQUEST_INCOMPLETE or H3_REQUEST_CANCELLED and the read
            // fails with SocketTimeoutException.
            // Once the declared Content-Length has been received the body is
            // complete. This method returns -1 without waiting for a possible
            // trailer section or FIN; trailer fields are read by
            // isTrailerFieldsReady() and the after-response scan instead.
            if (totalRead == 0 && !streamClosed && !trailersReceived &&
                    !bodyComplete) {
                SocketWrapperBase<?> socketWrapper = processor.getSocketWrapper();
                if (socketWrapper != null) {
                    if (processor.isAsync()) {
                        // A ReadListener callback must not block: perform one
                        // non-blocking attempt and let the async machinery
                        // register read interest if no data is available.
                        totalRead = readMoreData(socketWrapper, out);
                    } else {
                        long stallMs = socketWrapper.getReadTimeout() > 0
                                ? socketWrapper.getReadTimeout() : MAX_BODY_READ_STALL_MS;
                        long deadline = System.nanoTime()
                                + TimeUnit.MILLISECONDS.toNanos(stallMs);
                        while (totalRead == 0 && !streamClosed && !trailersReceived &&
                                !bodyComplete && System.nanoTime() < deadline) {
                            totalRead = readMoreData(socketWrapper, out);
                        }
                        if (totalRead == 0 && !streamClosed && !trailersReceived &&
                                !bodyComplete) {
                            // A stall is not end of stream: the QUIC stream is
                            // still open and the declared body may be incomplete.
                            // Returning -1 here made a truncated content-length
                            // request look complete to the application. Fail the
                            // stream and surface an I/O error instead.
                            markStreamClosed();
                            Http3Error error = processor.requestContentLength >
                                    processor.totalDataReceived
                                            ? Http3Error.H3_REQUEST_INCOMPLETE
                                            : Http3Error.H3_REQUEST_CANCELLED;
                            processor.handleStreamError(socketWrapper, error);
                            throw new SocketTimeoutException(sm.getString(
                                    "http3Processor.inputBuffer.readTimeout",
                                    Long.valueOf(processor.streamId)));
                        }
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
            // end of data. A local stream error (for example a malformed
            // Content-Length or an invalid frame sequence in the body) also
            // ends the stream with a RESET_STREAM; it is an I/O error for the
            // application, not a clean EOF.
            if (totalRead <= 0 && !trailersReceived && !bodyComplete) {
                if (isStreamReset(processor.getSocketWrapper())) {
                    throw streamResetError();
                }
                if (processor.streamReset.get()) {
                    throw streamProtocolError();
                }
                if (streamAborted || processor.bodyFrameError != null) {
                    throw streamAbortedError();
                }
                // A connection-level failure (for example an invalid QPACK
                // trailer section) abandons the request body. The application
                // must see an IOException rather than a clean EOF.
                if (processor.connectionFailed) {
                    throw streamAbortedError();
                }
            }
            // The stream ended cleanly (FIN, not a reset or a stall
            // timeout) with the body short of the declared Content-Length:
            // a malformed message (RFC 9114 Section 4.1.2). Reset the stream
            // and surface the malformed request to the application as an
            // I/O error rather than returning -1: a clean EOF would let a
            // servlet treat the partial body as complete. HTTP/1.1 and
            // HTTP/2 likewise report the truncation as an error.
            if (totalRead <= 0 && streamClosed && !trailersReceived &&
                    !bodyComplete && processor.requestContentLength > 0 &&
                    processor.totalDataReceived <
                            processor.requestContentLength &&
                    processor.bodyFrameError == null &&
                    isStreamFin(processor.getSocketWrapper())) {
                markStreamClosed();
                processor.handleStreamError(processor.getSocketWrapper(),
                        Http3Error.H3_MESSAGE_ERROR);
                throw new IOException(sm.getString(
                        "http3Processor.inputBuffer.contentLengthShortfall",
                        Long.valueOf(processor.streamId),
                        Long.valueOf(processor.totalDataReceived),
                        Long.valueOf(processor.requestContentLength)));
            }
            return (streamClosed || trailersReceived || bodyComplete) ? -1 : 0;
        }


        private IOException streamResetError() {
            // Receiving a stream reset abandons reading of the stream's
            // field sections: an unacknowledged section must be cancelled on
            // the encoder stream (RFC 9204 Section 2.2.2.2), even when this
            // endpoint did not get to inspect its Required Insert Count.
            processor.noteStreamAbandoned();
            return new IOException(sm.getString(
                    "http3Processor.inputBuffer.streamReset",
                    Long.valueOf(processor.streamId)));
        }


        private IOException streamProtocolError() {
            // The processor reset this stream locally after detecting a
            // malformed request. The stream's unprocessed field sections must
            // be released on the peer's encoder stream too (RFC 9204
            // Section 2.2.2.2).
            processor.noteStreamAbandoned();
            return new IOException(sm.getString(
                    "http3Processor.inputBuffer.streamError",
                    Long.valueOf(processor.streamId)));
        }


        private IOException streamAbortedError() {
            // A connection close or connection-level frame error abandons the
            // stream before all field sections were processed; release the
            // QPACK state as for a reset.
            processor.noteStreamAbandoned();
            return new IOException(sm.getString(
                    "http3Processor.inputBuffer.streamAborted",
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
                // reset the stream, as the content-length overrun does. A
                // connection-level code (H3_EXCESSIVE_LOAD from the
                // decoder-instruction backlog) fails the connection instead.
                markStreamClosed();
                processor.handleStreamOrConnectionError(socketWrapper, e);
                return -1;
            } catch (QpackValueTooLargeException e) {
                // Oversize QPACK value: stream-scoped per RFC 9204
                // Section 7.4 (see the matching catch in service()).
                markStreamClosed();
                processor.handleStreamError(socketWrapper,
                        Http3Error.H3_QPACK_DECOMPRESSION_FAILED);
                return -1;
            } catch (QpackException e) {
                // Invalid QPACK encoding is a connection error (RFC 9204).
                markStreamClosed();
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
                markStreamClosed();
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
            return completeTrailerSection(socketWrapper, true);
        }


        private int completeTrailerSection(SocketWrapperBase<?> socketWrapper,
                boolean pump) throws IOException {
            int needed = trailerPayload.remaining();
            int copied = needed == 0 ? 0 : processor.copyFramePayload(
                    processor.inputBuffer, socketWrapper, trailerPayload, needed, pump);
            // An abandoned (truncated or reset) section owes the peer a
            // Stream Cancellation (RFC 9204 Section 2.2.2.2); the error
            // paths below queue it unconditionally.
            if (copied < needed) {
                if (processor.payloadEof) {
                    // FIN before the section was complete: a cleanly
                    // terminated stream with a truncated last frame is the
                    // connection error of RFC 9114 Section 7.1. An abrupt
                    // reset remains a stream-scoped abandonment.
                    markStreamClosed();
                    trailerPayload = null;
                    if (processor.isStreamFin(socketWrapper)) {
                        processor.bodyFrameError = Http3Error.H3_FRAME_ERROR;
                    } else {
                        processor.handleStreamError(socketWrapper,
                                Http3Error.H3_MESSAGE_ERROR);
                    }
                    return -1;
                }
                // Would-block; the rest is completed on the next call.
                return 0;
            }
            return finishTrailerSection(socketWrapper) < 0 ? -1 : 1;
        }


        /*
         * Accounts a frame that makes no body progress and records a
         * connection-level H3_EXCESSIVE_LOAD for the service loop if the
         * per-request budget is exceeded. readMoreData() cannot throw
         * Http3Exception across the InputBuffer contract.
         */
        private boolean noteNonBodyFrame(long frameType, long frameLen) {
            if (processor.noteNonBodyFrame(frameLen)) {
                processor.bodyFrameError = Http3Error.H3_EXCESSIVE_LOAD;
                markStreamClosed();
                return true;
            }
            return false;
        }


        /**
         * Reads more DATA frames from the stream, preserving frame boundaries.
         * Tracks partial DATA frames so their remaining bytes are delivered to
         * the caller on the next call.
         */
        private int readMoreData(SocketWrapperBase<?> socketWrapper, ByteBuffer dst) throws IOException {
            int read = 0;
            ByteBuffer inputBuf = processor.inputBuffer;
            boolean pump = !processor.isAsync();

            // If an ignored (unknown/reserved) frame's payload skip was
            // interrupted, drain the remainder before parsing any further
            // frame header.
            if (pendingSkipRemaining > 0) {
                long skipped = processor.skipFramePayload(socketWrapper,
                        pendingSkipRemaining, pump);
                if (skipped < 0 || (skipped < pendingSkipRemaining &&
                        processor.isStreamFin(socketWrapper))) {
                    markStreamClosed();
                    if (processor.isStreamFin(socketWrapper)) {
                        processor.bodyFrameError = Http3Error.H3_FRAME_ERROR;
                    }
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
                        dst, toCopy, pump);
                read += bytesCopied;
                processor.totalDataReceived += bytesCopied;
                updateBodyComplete();
                partialDataRemaining -= bytesCopied;
                if (processor.payloadEof) {
                    markStreamClosed();
                    if (processor.isStreamFin(socketWrapper)) {
                        // Clean FIN in the middle of a DATA frame: truncated
                        // last frame (RFC 9114 Section 7.1).
                        processor.bodyFrameError = Http3Error.H3_FRAME_ERROR;
                    }
                    return read;
                }
                if (processor.payloadBlocked || partialDataRemaining > 0) {
                    // Would-block or destination full; the rest is delivered
                    // on the next call.
                    return read;
                }
                if (bodyComplete) {
                    // The declared body is complete. Do not parse a possible
                    // following trailer/FIN here; trailer fields are handled by
                    // isTrailerFieldsReady() and the after-response scan, and
                    // parsing now could block waiting for bytes the caller does
                    // not need for the body read.
                    return read;
                }
                // Frame complete; fall through to normal frame parsing.
            }

            // If a trailer section's payload read was interrupted, complete
            // and decode it before parsing any further frame header.
            if (trailerPayload != null) {
                int result = completeTrailerSection(socketWrapper, pump);
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
                    // Defensive: the header parser no longer rejects an
                    // oversized DATA/HEADERS frame itself; the per-frame
                    // checks below run only after the frame sequence has
                    // been classified. Any stream error raised here is
                    // still handled at stream scope.
                    markStreamClosed();
                    processor.handleStreamError(socketWrapper, e.getError());
                    return read > 0 ? read : -1;
                }
                if (!headerComplete) {
                    // Incomplete frame header. parseFrameHeader rewound to the
                    // start of the header, so refillForHeader's compact() cannot
                    // discard a partially consumed type byte and the bytes are
                    // re-parsed as a header on the next iteration.
                    if (!refillForHeader(inputBuf, socketWrapper)) {
                        if (streamClosed &&
                                processor.isStreamFin(socketWrapper) &&
                                processor.hasPartialFrameData()) {
                            // Clean FIN with a partially received frame header:
                            // the last frame header is truncated (RFC 9114
                            // Section 7.1, connection error H3_FRAME_ERROR).
                            processor.bodyFrameError = Http3Error.H3_FRAME_ERROR;
                        }
                        break;
                    }
                    continue;
                }
                long frameType = processor.frameHeader[0];
                long frameLen = processor.frameHeader[1];

                switch (classifyBodyFrame(frameType)) {
                    case DATA -> {
                        if (processor.exceedsBufferedFrameLimit(frameType,
                                frameLen)) {
                            // Sequence classification (the switch) ran first;
                            // a valid DATA frame is only too large for this
                            // receiver, so reset this stream (RESET_STREAM
                            // H3_FRAME_ERROR) instead of failing the
                            // connection.
                            markStreamClosed();
                            processor.handleStreamError(socketWrapper,
                                    Http3Error.H3_FRAME_ERROR);
                            return read > 0 ? read : -1;
                        }
                        if (frameLen == 0) {
                            if (noteNonBodyFrame(frameType, 0)) {
                                return read > 0 ? read : -1;
                            }
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
                            markStreamClosed();
                            processor.handleStreamError(socketWrapper,
                                    Http3Error.H3_MESSAGE_ERROR);
                            return read > 0 ? read : -1;
                        }
                        // Deliver as much of this DATA frame as fits in dst. Any
                        // remainder is request-body bytes that MUST be delivered on a
                        // later call (recorded in partialDataRemaining), never skipped.
                        int toCopy = (int) Math.min(frameLen, dst.remaining());
                        int bytesCopied = processor.copyFramePayload(inputBuf, socketWrapper,
                                dst, toCopy, pump);
                        if (bytesCopied < frameLen) {
                            // dst filled up (or the read would-blocked) before the frame
                            // was fully delivered; defer the rest to the next call.
                            // Safe cast: the DATA frame length was checked
                            // against MAX_FRAME_LENGTH above.
                            partialDataRemaining = (int) (frameLen - bytesCopied);
                        }
                        read += bytesCopied;
                        processor.totalDataReceived += bytesCopied;
                        updateBodyComplete();
                        if (processor.payloadEof) {
                            markStreamClosed();
                            if (processor.isStreamFin(socketWrapper)) {
                                // Clean FIN in the middle of a DATA frame:
                                // truncated last frame (RFC 9114 Section 7.1).
                                processor.bodyFrameError =
                                        Http3Error.H3_FRAME_ERROR;
                            }
                        }
                        return read;
                    }
                    case TRAILERS -> {
                        if (processor.exceedsBufferedFrameLimit(frameType,
                                frameLen)) {
                            markStreamClosed();
                            processor.handleStreamError(socketWrapper,
                                    Http3Error.H3_FRAME_ERROR);
                            return read > 0 ? read : -1;
                        }
                        // See BodyFrameKind.TRAILERS. Declared-length
                        // preflight against the wire-side bound of the
                        // field section limit (see fieldSectionWireLimit);
                        // the RFC-defined uncompressed check runs on decode.
                        if (frameLen > processor.trailerFieldSectionWireLimit()) {
                            markStreamClosed();
                            processor.handleStreamError(socketWrapper,
                                    Http3Error.H3_MESSAGE_ERROR);
                            return read > 0 ? read : -1;
                        }
                        // Safe cast: the HEADERS frame length was checked
                        // against MAX_FRAME_LENGTH above.
                        trailerPayload = ByteBuffer.allocate((int) frameLen);
                        int result = completeTrailerSection(socketWrapper, pump);
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
                        markStreamClosed();
                        return read > 0 ? read : -1;
                    }
                    case IGNORED -> {
                        // See BodyFrameKind.IGNORED: skip the payload and keep
                        // parsing frames. Bound the padding a peer can make a
                        // servlet read consume without body progress.
                        if (noteNonBodyFrame(frameType, frameLen)) {
                            return read > 0 ? read : -1;
                        }
                        if (log.isDebugEnabled()) {
                            log.debug(sm.getString("http3Processor.frameIgnored",
                                    Long.valueOf(processor.streamId),
                                    Long.valueOf(frameType)));
                        }
                        long skipped = frameLen > 0 ? processor.skipFramePayload(
                                socketWrapper, frameLen, pump) : frameLen;
                        if (skipped < 0 || (skipped < frameLen &&
                                processor.isStreamFin(socketWrapper))) {
                            markStreamClosed();
                            if (processor.isStreamFin(socketWrapper)) {
                                processor.bodyFrameError =
                                        Http3Error.H3_FRAME_ERROR;
                            }
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
            int n = processor.refillInputBuffer(socketWrapper, inputBuf,
                    !processor.isAsync());
            if (n < 0) {
                markStreamClosed();
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
        private static final int WRITE_QUEUE_HARD_LIMIT = 256 * 1024;

        private final Http3Processor processor;
        private final ReentrantLock writeLock = new ReentrantLock();
        private final Deque<ByteBuffer> pendingFrames = new ArrayDeque<>();
        private long pendingBytes = 0;
        private boolean dataLeft = false;
        private volatile boolean nonBlockingMode = false;
        private boolean resetOrFailed = false;
        private long bytesWritten = 0;
        private final ByteBuffer dataFrameBuffer = ByteBuffer.allocate(16384);
        private boolean voidOutput = false;
        private boolean compressionEnabled = false;
        private GZIPOutputStream compressionStream = null;
        private final OutputStream gzipSink = new GzipSinkOutputStream();

        Http3OutputBuffer(Http3Processor processor) {
            this.processor = processor;
        }


        /**
         * Whether this response uses the Servlet non-blocking write path.
         * The mode is sticky once entered. Transports that cannot expose a
         * reliable native write-ready signal opt out and keep the bounded
         * blocking path.
         */
        boolean isNonBlockingMode() {
            if (!nonBlockingMode &&
                    processor.getRequest().getResponse().getWriteListener() != null) {
                SocketWrapperBase<?> wrapper = processor.getSocketWrapper();
                if (!(wrapper instanceof QuicSocketWrapper qw) ||
                        qw.supportsNonBlockingWrites()) {
                    nonBlockingMode = true;
                }
            }
            return nonBlockingMode;
        }


        void writeFrame(ByteBuffer frame, boolean flushAfter) throws IOException {
            if (!isNonBlockingMode()) {
                SocketWrapperBase<?> wrapper = processor.getSocketWrapper();
                if (wrapper == null) {
                    return;
                }
                wrapper.write(true, frame);
                if (flushAfter) {
                    wrapper.flush(true);
                }
                return;
            }
            appendFrame(frame);
            if (flushAfter) {
                flushNonBlocking();
            }
        }


        private void appendFrame(ByteBuffer frame) throws IOException {
            writeLock.lock();
            try {
                if (resetOrFailed || processor.streamReset.get() ||
                        processor.connectionFailed) {
                    frame.position(frame.limit());
                    return;
                }
                int len = frame.remaining();
                if (len == 0) {
                    return;
                }
                if (pendingBytes + len > WRITE_QUEUE_HARD_LIMIT) {
                    resetOrFailed = true;
                    pendingFrames.clear();
                    pendingBytes = 0;
                    dataLeft = false;
                    IOException ioe = new IOException(sm.getString(
                            "http3Processor.writeQueueFull",
                            Long.valueOf(processor.streamId),
                            Integer.valueOf(WRITE_QUEUE_HARD_LIMIT)));
                    processor.setErrorState(ErrorState.CLOSE_NOW, ioe);
                    SocketWrapperBase<?> wrapper = processor.getSocketWrapper();
                    if (wrapper != null) {
                        processor.handleStreamError(wrapper,
                                Http3Error.H3_INTERNAL_ERROR);
                    }
                    throw ioe;
                }
                pendingFrames.addLast(frame);
                pendingBytes += len;
                dataLeft = true;
            } finally {
                writeLock.unlock();
            }
        }


        boolean flushNonBlocking() throws IOException {
            writeLock.lock();
            try {
                return flushNonBlockingLocked();
            } finally {
                writeLock.unlock();
            }
        }


        private boolean flushNonBlockingLocked() throws IOException {
            SocketWrapperBase<?> wrapper = processor.getSocketWrapper();
            if (wrapper == null || resetOrFailed) {
                pendingFrames.clear();
                pendingBytes = 0;
                dataLeft = false;
                return false;
            }
            try {
                boolean wrapperLeft = wrapper.flush(false);
                if (wrapperLeft) {
                    dataLeft = true;
                    processor.registerWriteInterest();
                    return true;
                }
                while (!pendingFrames.isEmpty()) {
                    if (!wrapper.canWrite()) {
                        dataLeft = true;
                        processor.registerWriteInterest();
                        return true;
                    }
                    ByteBuffer frame = pendingFrames.removeFirst();
                    int len = frame.remaining();
                    wrapper.write(false, frame);
                    pendingBytes -= len;
                }
                dataLeft = wrapper.flush(false);
                if (dataLeft) {
                    processor.registerWriteInterest();
                }
                return dataLeft;
            } catch (IllegalStateException ise) {
                pendingFrames.clear();
                pendingBytes = 0;
                dataLeft = false;
                return false;
            }
        }


        void flushBlocking() throws IOException {
            writeLock.lock();
            try {
                SocketWrapperBase<?> wrapper = processor.getSocketWrapper();
                if (wrapper == null || resetOrFailed) {
                    pendingFrames.clear();
                    pendingBytes = 0;
                    dataLeft = false;
                    return;
                }
                wrapper.flush(true);
                while (!pendingFrames.isEmpty()) {
                    ByteBuffer frame = pendingFrames.removeFirst();
                    int len = frame.remaining();
                    wrapper.write(true, frame);
                    pendingBytes -= len;
                }
                wrapper.flush(true);
                dataLeft = false;
            } finally {
                writeLock.unlock();
            }
        }


        boolean isReady() {
            writeLock.lock();
            try {
                if (resetOrFailed || dataLeft || !pendingFrames.isEmpty()) {
                    return false;
                }
                SocketWrapperBase<?> wrapper = processor.getSocketWrapper();
                if (wrapper == null) {
                    return false;
                }
                try {
                    return wrapper.canWrite();
                } catch (IllegalStateException ise) {
                    return false;
                }
            } finally {
                writeLock.unlock();
            }
        }


        boolean hasPendingData() {
            writeLock.lock();
            try {
                return resetOrFailed ? false : dataLeft || !pendingFrames.isEmpty();
            } finally {
                writeLock.unlock();
            }
        }


        void discardPendingFrames() {
            writeLock.lock();
            try {
                pendingFrames.clear();
                pendingBytes = 0;
                dataLeft = false;
                resetOrFailed = true;
            } finally {
                writeLock.unlock();
            }
        }


        void resetQueue() {
            writeLock.lock();
            try {
                pendingFrames.clear();
                pendingBytes = 0;
                dataLeft = false;
                resetOrFailed = false;
                nonBlockingMode = false;
            } finally {
                writeLock.unlock();
            }
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
         * before clearing the flag). If end() already closed the stream, the
         * second close is a no-op; any IOException from a dead QUIC stream is
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
            // The header send above may have decided that this response has
            // no body (HEAD or a no-content status) and set voidOutput. It
            // may also have observed a stream reset. Re-check both before
            // handing the current chunk to emitData(), otherwise the first
            // direct-write chunk after the headers would be sent as DATA on
            // a response that must not carry content.
            if (voidOutput || processor.streamReset.get() ||
                    processor.responseConcluded) {
                chunk.position(chunk.limit());
                return pending;
            }
            if (pending == 0) {
                return 0;
            }
            boolean nonBlocking = isNonBlockingMode();
            if (compressionEnabled) {
                writeCompressed(chunk, pending);
            } else {
                emitData(chunk, pending);
            }
            if (nonBlocking) {
                flushNonBlocking();
            }
            return pending;
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
            boolean nonBlocking = isNonBlockingMode();
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
                if (nonBlocking) {
                    ByteBuffer queued = ByteBuffer.allocate(dataFrameBuffer.remaining());
                    queued.put(dataFrameBuffer);
                    queued.flip();
                    appendFrame(queued);
                } else {
                    wrapper.write(true, dataFrameBuffer);
                }
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
                if (log.isTraceEnabled()) {
                    log.trace("Flushing the compression stream!");
                }
                // A failure here means compressed bytes could not be emitted;
                // propagate it rather than silently continuing with a short
                // compressed body.
                compressionStream.flush();
            }
            if (isNonBlockingMode()) {
                flushNonBlocking();
            } else {
                flushBlocking();
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

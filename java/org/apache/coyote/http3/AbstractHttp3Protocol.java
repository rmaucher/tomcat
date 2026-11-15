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

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpUpgradeHandler;

import org.apache.coyote.AbstractProtocol;
import org.apache.coyote.CompressionConfig;
import org.apache.coyote.ContinueResponseTiming;
import org.apache.coyote.Processor;
import org.apache.coyote.Request;
import org.apache.coyote.Response;
import org.apache.coyote.UpgradeProtocol;
import org.apache.coyote.UpgradeToken;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.http.parser.HttpParser;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicEndpoint;
import org.apache.tomcat.util.net.quic.QuicProtocol;
import org.apache.tomcat.util.net.quic.QuicStream;
import org.apache.tomcat.util.res.StringManager;


/**
 * HTTP/3 protocol handler.
 * <p>
 * Extends {@link AbstractProtocol} to integrate with Coyote. Each QUIC stream
 * is processed independently by an {@link Http3Processor} - no multiplexing
 * logic is needed because QUIC provides transport-level multiplexing.
 * <p>
 * This class implements {@link QuicProtocol} to provide the QUIC endpoint
 * with its per-connection configuration and connection managers. The "h3"
 * ALPN identifier is advertised through
 * {@link QuicProtocol#getAlpnIdentifiers()}; the negotiation itself is
 * performed by the endpoint in its native ALPN callback on the TLS context.
 * HTTP/3 is a standalone
 * protocol on its own transport, not an upgrade of another protocol, and
 * therefore - unlike HTTP/2 - does not implement {@link UpgradeProtocol}.
 * <p>
 * This class is independent of the concrete QUIC transport implementation
 * (it only depends on the QUIC interfaces of {@code org.apache.tomcat.util.net}).
 * The concrete transports are selected by the concrete subclasses, each of
 * which instantiates its own endpoint:
 * {@link Http3OpenSSLProtocol} (OpenSSL QUIC), {@link Http3QuicheProtocol}
 * (Cloudflare quiche) and {@link Http3Ngtcp2Protocol} (ngtcp2). The connector
 * {@code protocol} attribute names the subclass to use, following the
 * pattern earlier Tomcat releases used to select the TCP endpoint for
 * HTTP/1.1 (e.g. {@code Http11NioProtocol}).
 */
public abstract class AbstractHttp3Protocol extends AbstractProtocol<QuicStream>
        implements QuicProtocol {

    private static final StringManager sm =
            StringManager.getManager(AbstractHttp3Protocol.class);

    /**
     * ALPN protocol name.
     */
    private static final String ALPN_NAME = Constants.PROTOCOL_NAME;

    /**
     * Hard upper bound on the configured QPACK dynamic table capacity.
     * The dynamic table is per connection and its ring array, entry objects
     * and retained name/value strings all scale with the configured
     * capacity. Limiting the advertised capacity keeps a single peer from
     * being able to amplify the configured value into unbounded
     * per-connection heap use. The default ({@code 4096}) is far below this
     * limit; the bound is only relevant to unusual configurations.
     */
    public static final long MAX_QPACK_TABLE_CAPACITY = 4L * 1024 * 1024;

    /**
     * Largest stream-count value a QUIC transport parameter can carry:
     * a QUIC variable-length integer has at most 62 payload bits (RFC 9000
     * Section 16). The HTTP/3 concurrency limit must stay within this
     * range so it can be advertised consistently by the transport.
     */
    public static final long MAX_CONCURRENT_STREAMS = (1L << 62) - 1;

    /**
     * Largest blocked-stream timeout whose millisecond-to-nanosecond
     * conversion does not overflow {@link Long}. Larger values would make the
     * deadline arithmetic wrap to a negative time and turn a deliberately
     * long wait into an immediate return.
     */
    public static final long MAX_QPACK_BLOCKED_STREAM_TIMEOUT_MS =
            Long.MAX_VALUE / 1_000_000L;

    /**
     * Largest idle timeout whose millisecond-to-microsecond conversion used
     * by the ngtcp2 transport does not overflow {@link Long}. Larger values
     * would wrap the transport parameter to a negative value.
     */
    public static final long MAX_IDLE_TIMEOUT_MS =
            Long.MAX_VALUE / 1_000_000L;

    private long qpackMaxTableCapacity = Qpack.DEFAULT_TABLE_SIZE;

    /**
     * Maximum number of request streams that may block per connection
     * waiting for dynamic table entries to arrive on the QPACK encoder
     * stream (RFC 9204 Section 2.1.2). A value of zero (the default)
     * disables stream blocking: field sections that reference entries not
     * yet present in the dynamic table are then treated as a decompression
     * failure.
     */
    private volatile int qpackBlockedStreams = 0;

    /**
     * Timeout in milliseconds for a request stream blocked waiting for QPACK
     * encoder-stream inserts (RFC 9204 Section 2.1.2). Zero and negative
     * values are rejected, as are values above
     * {@link #MAX_QPACK_BLOCKED_STREAM_TIMEOUT_MS} (whose
     * millisecond-to-nanosecond conversion would overflow); the default is
     * 5000 ms.
     */
    private volatile long qpackBlockedStreamTimeoutMs = 5000;

    /**
     * When to respond with a 100 intermediate response to a request that
     * carries an {@code expect: 100-continue} field (same semantics as the
     * HTTP/1.1 and HTTP/2 connectors).
     */
    private volatile ContinueResponseTiming continueResponseTiming =
            ContinueResponseTiming.IMMEDIATELY;

    /**
     * Maximum field section size (bytes) that this endpoint is willing to
     * decode. Declared to peers via SETTINGS_MAX_FIELD_SECTION_SIZE
     * (RFC 9114 Section 4.2.2) and enforced on incoming field sections.
     */
    private long maxFieldSectionSize = Constants.DEFAULT_MAX_FIELD_SECTION_SIZE;

    /**
     * Maximum concurrent streams per connection.
     */
    private long maxConcurrentStreams = 100;

    /**
     * Whether to enable CONNECT protocol (RFC 9220).
     */
    private volatile boolean enableConnectProtocol = false;

    /**
     * Whether to advertise the experimental (unregistered) H2 compatible
     * identity setting (0x22). Disabled by default.
     */
    private boolean h2CompatibleIdentity = false;

    /**
     * Whether to accept requests whose :scheme pseudo-header is not
     * consistent with the TLS state of the connector. Same connector
     * policy (and default) as the HTTP/2 implementation. Since QUIC always
     * uses TLS, the consistent scheme is "https".
     */
    private boolean allowSchemeMismatch = false;

    /**
     * Idle timeout in milliseconds (RFC 9000 Section 10.1).
     * When no QUIC packets are received for this duration, the connection
     * is closed. Default: 30000ms (30 seconds).
     */
    private long idleTimeoutMs = 30000;


    /**
     * Creates a new HTTP/3 protocol handler with the given endpoint.
     *
     * @param endpoint The QUIC endpoint
     */
    protected AbstractHttp3Protocol(QuicEndpoint<?> endpoint) {
        super(endpoint);
        // HTTP/3 has no sendfile path: response bodies must be written through
        // the output buffer as DATA frames. Disable sendfile so that
        // DefaultServlet uses the buffered copy path.
        endpoint.setUseSendfile(false);
        endpoint.setQuicProtocol(this);
    }


    /**
     * Instantiates the QUIC endpoint implementation with the given class name
     * so that this package does not compile against the implementation (the
     * endpoint classes live in the FFM gated compilation pass).
     * <p>
     * There is no availability probing and no fallback: the concrete protocol
     * subclass names exactly one endpoint class, and a failure to
     * instantiate it (for example when the build lacks the FFM compilation
     * pass that provides the endpoint) is fatal. Transport availability
     * failures surface at bind time with the endpoint's own error.
     *
     * @param endpointClassName The endpoint implementation class name
     *
     * @return The new endpoint
     *
     * @throws IllegalStateException If the endpoint implementation could not
     *         be instantiated
     */
    protected static QuicEndpoint<?> createQuicEndpoint(
            String endpointClassName) {
        try {
            return (QuicEndpoint<?>) Class.forName(endpointClassName)
                    .getConstructor().newInstance();
        } catch (Exception | LinkageError e) {
            // A present but incompatible FFM class fails during linking or
            // static initialisation with an Error, not an Exception; report
            // it with the same actionable message and endpoint class name.
            throw new IllegalStateException(sm.getString(
                    "http3Protocol.noQuicEndpointImplementation",
                    endpointClassName), e);
        }
    }


    /**
     * Returns the QUIC endpoint.
     *
     * @return The QUIC endpoint
     */
    public QuicEndpoint<?> getQuicEndpoint() {
        return (QuicEndpoint<?>) getEndpoint();
    }


    // ------------------------------------------------ Protocol Configuration

    public long getQpackMaxTableCapacity() {
        return qpackMaxTableCapacity;
    }


    /**
     * Sets the maximum QPACK dynamic table capacity. The value must be
     * between {@code 0} and {@link #MAX_QPACK_TABLE_CAPACITY}; a value of
     * {@code 0} disables the dynamic table. Values outside this range are
     * rejected because the decoder limits are int-valued, an out-of-range
     * value would otherwise be silently clamped, and the dynamic table's
     * per-connection memory scales with the configured capacity.
     *
     * @param qpackMaxTableCapacity The maximum QPACK dynamic table capacity
     *                              in bytes
     *
     * @throws IllegalArgumentException If the value is outside the range
     *         {@code 0} to {@link #MAX_QPACK_TABLE_CAPACITY}
     */
    public void setQpackMaxTableCapacity(long qpackMaxTableCapacity) {
        if (qpackMaxTableCapacity < 0 ||
                qpackMaxTableCapacity > MAX_QPACK_TABLE_CAPACITY) {
            throw new IllegalArgumentException(sm.getString(
                    "http3Protocol.invalidQpackMaxTableCapacity",
                    Long.valueOf(qpackMaxTableCapacity),
                    Long.valueOf(MAX_QPACK_TABLE_CAPACITY)));
        }
        this.qpackMaxTableCapacity = qpackMaxTableCapacity;
    }


    /**
     * Returns the maximum number of request streams per connection that may
     * block awaiting dynamic table entries announced on the peer's QPACK
     * encoder stream (RFC 9204 Section 2.1.2). Zero, the default, disables
     * blocking: blocked field sections are then a decompression failure.
     * When positive, the value is also advertised to peers via
     * SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204 Section 5).
     *
     * @return The maximum number of blocked streams per connection
     */
    public int getQpackBlockedStreams() {
        return qpackBlockedStreams;
    }


    /**
     * Sets the maximum number of request streams per connection that may
     * block awaiting QPACK encoder stream inserts. The value must be zero or
     * greater; zero disables blocking. A negative value is rejected rather
     * than silently treated as zero.
     *
     * @param qpackBlockedStreams The maximum number of blocked streams
     *
     * @throws IllegalArgumentException If the value is negative
     */
    public void setQpackBlockedStreams(int qpackBlockedStreams) {
        if (qpackBlockedStreams < 0) {
            throw new IllegalArgumentException(sm.getString(
                    "http3Protocol.invalidQpackBlockedStreams",
                    Integer.valueOf(qpackBlockedStreams)));
        }
        this.qpackBlockedStreams = qpackBlockedStreams;
    }


    /**
     * Returns the timeout, in milliseconds, for a request stream blocked
     * waiting for QPACK encoder-stream inserts.
     *
     * @return The blocked-stream timeout
     */
    public long getQpackBlockedStreamTimeoutMs() {
        return qpackBlockedStreamTimeoutMs;
    }


    /**
     * Sets the timeout, in milliseconds, for a request stream blocked waiting
     * for QPACK encoder-stream inserts (RFC 9204 Section 2.1.2). A blocked
     * stream holds a container worker thread for this duration, so the value
     * should stay small relative to the thread pool.
     *
     * @param qpackBlockedStreamTimeoutMs The timeout in milliseconds; must be
     *                                    greater than zero and at most
     *                                    {@link #MAX_QPACK_BLOCKED_STREAM_TIMEOUT_MS}
     *
     * @throws IllegalArgumentException If the value is not in the supported
     *                                  range
     */
    public void setQpackBlockedStreamTimeoutMs(long qpackBlockedStreamTimeoutMs) {
        if (qpackBlockedStreamTimeoutMs < 1 ||
                qpackBlockedStreamTimeoutMs >
                        MAX_QPACK_BLOCKED_STREAM_TIMEOUT_MS) {
            throw new IllegalArgumentException(sm.getString(
                    "http3Protocol.invalidQpackBlockedStreamTimeout",
                    Long.valueOf(qpackBlockedStreamTimeoutMs),
                    Long.valueOf(MAX_QPACK_BLOCKED_STREAM_TIMEOUT_MS)));
        }
        this.qpackBlockedStreamTimeoutMs = qpackBlockedStreamTimeoutMs;
    }


    /**
     * Get the continue response timing setting as a string, for the
     * configuration API.
     *
     * @return The continue response timing setting
     */
    public String getContinueResponseTiming() {
        return continueResponseTiming.toString();
    }


    /**
     * Set the setting for how responses to 100-Continue requests will be
     * sent.
     *
     * @param continueResponseTiming The new continue response timing setting
     */
    public void setContinueResponseTiming(String continueResponseTiming) {
        this.continueResponseTiming =
                ContinueResponseTiming.fromString(continueResponseTiming);
    }


    /**
     * Returns the timing for 100-continue responses.
     *
     * @return the continue response timing
     */
    public ContinueResponseTiming getContinueResponseTimingInternal() {
        return continueResponseTiming;
    }


    /**
     * Returns the configured maximum field-section size that this endpoint
     * will decode and advertise via
     * {@code SETTINGS_MAX_FIELD_SECTION_SIZE}.
     * <p>
     * The effective value is clamped by the connection manager to
     * {@link Constants#MAX_FIELD_SECTION_SIZE_FOR_FRAME_LIMIT} (4473915
     * bytes, the largest decoded field section that fits the 16 MiB per-frame
     * buffer) and by the QPACK decoder and SETTINGS encoder to the non-negative
     * int range. Values above those bounds are clamped for the decoder, the
     * advertisement and the inbound frame preflight; non-positive values are
     * enforced and advertised as an explicit zero-byte limit.
     *
     * @return the configured maximum field-section size
     */
    public long getMaxFieldSectionSize() {
        return maxFieldSectionSize;
    }


    /**
     * The {@link #getMaxFieldSectionSize()} value as an {@code int} for the
     * QPACK decoder limits (which are int-valued), clamped to the int range:
     * a raw narrowing cast of a configured value beyond
     * {@link Integer#MAX_VALUE} would wrap - to a negative value, which the
     * decoder reads as "no limit at all", or to zero, which rejects every
     * non-empty field section.
     * <p>
     * A configured zero and a negative value both arrive here as 0 and
     * reject every non-empty field section locally. The SETTINGS encoder
     * advertises the same clamped value, so the peer sees the zero-byte
     * limit instead of the RFC 9114 Section 4.2.2 "unlimited" default.
     * The decoder's negative "unlimited" sentinel is deliberately not
     * reachable through this method.
     *
     * @return the decoder header size limit, clamped to [0,
     *         Integer.MAX_VALUE]
     */
    int getMaxFieldSectionSizeInt() {
        return Constants.clampToNonNegativeInt(maxFieldSectionSize);
    }


    /**
     * Sets the maximum field-section size that this endpoint will decode
     * and advertise via {@code SETTINGS_MAX_FIELD_SECTION_SIZE}.
     * <p>
     * The effective value is clamped to
     * {@link Constants#MAX_FIELD_SECTION_SIZE_FOR_FRAME_LIMIT} (4473915 bytes)
     * and to the non-negative int range for the decoder, the advertisement and
     * the inbound frame preflight. A value of zero is enforced and advertised
     * as an explicit zero-byte limit; a negative value is treated the same
     * way.
     *
     * @param maxFieldSectionSize The maximum field-section size in bytes
     */
    public void setMaxFieldSectionSize(long maxFieldSectionSize) {
        this.maxFieldSectionSize = maxFieldSectionSize;
    }


    @Override
    public long getMaxConcurrentStreams() {
        return maxConcurrentStreams;
    }


    /**
     * Sets the maximum number of concurrent request streams per connection.
     * The value must be greater than zero and no greater than
     * {@link #MAX_CONCURRENT_STREAMS} (the 62-bit QUIC varint limit); the
     * effective limit is then clamped to the stream limit advertised by the
     * QUIC transport.
     *
     * @param maxConcurrentStreams The maximum number of concurrent request
     *                              streams
     *
     * @throws IllegalArgumentException If the value is not greater than
     *         zero, or exceeds {@link #MAX_CONCURRENT_STREAMS}
     */
    public void setMaxConcurrentStreams(long maxConcurrentStreams) {
        if (maxConcurrentStreams < 1) {
            throw new IllegalArgumentException(sm.getString(
                    "http3Protocol.invalidMaxConcurrentStreams",
                    Long.valueOf(maxConcurrentStreams)));
        }
        if (maxConcurrentStreams > MAX_CONCURRENT_STREAMS) {
            throw new IllegalArgumentException(sm.getString(
                    "http3Protocol.invalidMaxConcurrentStreamsTooLarge",
                    Long.valueOf(maxConcurrentStreams),
                    Long.valueOf(MAX_CONCURRENT_STREAMS)));
        }
        this.maxConcurrentStreams = maxConcurrentStreams;
    }


    public boolean isEnableConnectProtocol() {
        return enableConnectProtocol;
    }


    public void setEnableConnectProtocol(boolean enableConnectProtocol) {
        this.enableConnectProtocol = enableConnectProtocol;
    }


    public boolean isH2CompatibleIdentity() {
        return h2CompatibleIdentity;
    }


    /**
     * Returns whether a :scheme value that is inconsistent with the TLS
     * state of the connector is permitted.
     *
     * @return {@code true} if a mismatched scheme is permitted, otherwise
     *         {@code false}
     */
    public boolean getAllowSchemeMismatch() {
        return allowSchemeMismatch;
    }


    /**
     * Sets whether a :scheme value that is inconsistent with the TLS state
     * of the connector is permitted.
     *
     * @param allowSchemeMismatch {@code true} if a mismatched scheme is
     *            permitted, otherwise {@code false}
     */
    public void setAllowSchemeMismatch(boolean allowSchemeMismatch) {
        this.allowSchemeMismatch = allowSchemeMismatch;
    }


    public void setH2CompatibleIdentity(boolean h2CompatibleIdentity) {
        this.h2CompatibleIdentity = h2CompatibleIdentity;
    }


    @Override
    public long getIdleTimeoutMs() {
        return idleTimeoutMs;
    }


    /**
     * Sets the QUIC connection idle timeout. Zero or a negative value leaves
     * the transport default in place. Values above
     * {@link #MAX_IDLE_TIMEOUT_MS} are rejected because the ngtcp2 transport
     * multiplies the millisecond value by 1,000,000 to obtain microseconds;
     * a larger value would overflow that conversion and produce an invalid
     * transport parameter.
     *
     * @param idleTimeoutMs The idle timeout in milliseconds
     *
     * @throws IllegalArgumentException If the value exceeds
     *                                  {@link #MAX_IDLE_TIMEOUT_MS}
     */
    public void setIdleTimeoutMs(long idleTimeoutMs) {
        if (idleTimeoutMs > MAX_IDLE_TIMEOUT_MS) {
            throw new IllegalArgumentException(sm.getString(
                    "http3Protocol.invalidIdleTimeout",
                    Long.valueOf(idleTimeoutMs),
                    Long.valueOf(MAX_IDLE_TIMEOUT_MS)));
        }
        this.idleTimeoutMs = idleTimeoutMs;
    }


    /**
     * Characters that are additionally permitted in the request target
     * (path) received by this connector, above those RFC 9110 Section 7.1
     * allows. Same semantics (and same {@link HttpParser} whitelist) as the
     * HTTP/1.1 and HTTP/2 connector property.
     */
    private String relaxedPathChars = null;

    /**
     * Characters that are additionally permitted in the query string
     * received by this connector. Same semantics as the HTTP/1.1 and HTTP/2
     * connector property.
     */
    private String relaxedQueryChars = null;

    /**
     * Parser holding the (relaxed) request-target and query character
     * whitelists used by request validation. Rebuilt when either relaxed
     * character property is changed.
     */
    private volatile HttpParser httpParser = new HttpParser(null, null);


    public String getRelaxedPathChars() {
        return relaxedPathChars;
    }


    public void setRelaxedPathChars(String relaxedPathChars) {
        this.relaxedPathChars = relaxedPathChars;
        this.httpParser = new HttpParser(relaxedPathChars, relaxedQueryChars);
    }


    public String getRelaxedQueryChars() {
        return relaxedQueryChars;
    }


    public void setRelaxedQueryChars(String relaxedQueryChars) {
        this.relaxedQueryChars = relaxedQueryChars;
        this.httpParser = new HttpParser(relaxedPathChars, relaxedQueryChars);
    }


    /**
     * Returns the parser holding the request-target and query character
     * whitelists used by {@link Http3Processor} request validation.
     *
     * @return the HttpParser
     */
    public HttpParser getHttpParser() {
        return httpParser;
    }


    /**
     * The set of trailer header names that are allowed to be processed.
     */
    private final Set<String> allowedTrailerHeaders = ConcurrentHashMap.newKeySet();

    /**
     * Set the names of headers that are allowed to be sent via a trailer.
     *
     * @param commaSeparatedHeaders Comma separated list of header names
     */
    public void setAllowedTrailerHeaders(String commaSeparatedHeaders) {
        // Jump through some hoops so we don't end up with an empty set while
        // doing updates.
        Set<String> toRemove = new HashSet<>(allowedTrailerHeaders);
        if (commaSeparatedHeaders != null) {
            String[] headers = commaSeparatedHeaders.split(",");
            for (String header : headers) {
                String trimmedHeader = header.trim().toLowerCase(Locale.ENGLISH);
                if (toRemove.contains(trimmedHeader)) {
                    toRemove.remove(trimmedHeader);
                } else {
                    allowedTrailerHeaders.add(trimmedHeader);
                }
            }
            allowedTrailerHeaders.removeAll(toRemove);
        } else {
            allowedTrailerHeaders.clear();
        }
    }


    /**
     * Check if a header name is in the set of allowed trailer headers.
     *
     * @param headerName The header name to check
     *
     * @return {@code true} if the header is allowed as a trailer header
     */
    public boolean isTrailerHeaderAllowed(String headerName) {
        return allowedTrailerHeaders.contains(headerName.trim().toLowerCase(Locale.ENGLISH));
    }


    /**
     * The value to be used for the Server header (same semantics as the
     * HTTP/1.1 / HTTP/2 connector attribute). When set, it always
     * overrides any value the application may have provided. When not
     * set, the application-provided value is used unless
     * {@code serverRemoveAppProvidedValues} is enabled.
     */
    private String server = null;

    /**
     * Whether an application-provided Server header is removed from
     * responses when no {@code server} value is configured.
     */
    private boolean serverRemoveAppProvidedValues = false;

    /**
     * The alternative service to announce via the Alt-Svc response header
     * (same semantics as the HTTP/1.1 / HTTP/2 connector attribute). The
     * service is assumed to listen on the port of the request. An
     * Alt-Svc header set by the application takes precedence.
     */
    private String altService = null;


    /**
     * Returns the configured Server header value.
     *
     * @return the Server header value, or {@code null} if not configured
     */
    public String getServer() {
        return server;
    }


    /**
     * Sets the Server header value sent on every response, overriding any
     * application-provided value.
     *
     * @param server The Server header value, or {@code null} to let the
     *               application-provided value stand (subject to
     *               {@code serverRemoveAppProvidedValues})
     */
    public void setServer(String server) {
        this.server = server;
    }


    /**
     * Returns whether application-provided Server headers are removed.
     *
     * @return {@code true} if application-provided Server headers are
     *         removed when no {@code server} value is configured
     */
    public boolean getServerRemoveAppProvidedValues() {
        return serverRemoveAppProvidedValues;
    }


    /**
     * Sets whether application-provided Server headers are removed when
     * no {@code server} value is configured.
     *
     * @param serverRemoveAppProvidedValues {@code true} to remove
     *        application-provided Server headers
     */
    public void setServerRemoveAppProvidedValues(
            boolean serverRemoveAppProvidedValues) {
        this.serverRemoveAppProvidedValues = serverRemoveAppProvidedValues;
    }


    /**
     * Returns the configured Alt-Svc header value.
     *
     * @return the alternative service string, or {@code null} if not
     *         configured
     */
    public String getAltService() {
        return altService;
    }


    /**
     * Sets the alternative service announced via the Alt-Svc response
     * header (the value is the protocol identifier, the port is taken
     * from the request).
     *
     * @param altService The alternative service protocol identifier, or
     *                   {@code null}/empty to announce nothing
     *
     * @throws IllegalArgumentException If the value is not a valid HTTP
     *         token (RFC 9110 Section 5.6.2)
     */
    public void setAltService(String altService) {
        if (altService == null || altService.isEmpty()) {
            this.altService = null;
        } else if (HttpParser.isToken(altService)) {
            this.altService = altService;
        } else {
            throw new IllegalArgumentException(sm.getString(
                    "http3Protocol.invalidAltService", altService));
        }
    }


    /**
     * The response compression configuration. The decision logic (minimum
     * size, compressible MIME types, user-agent exclusions, ETag and
     * content-encoding checks, header updates) lives entirely in
     * {@link CompressionConfig}; the setters below expose the same connector
     * attributes as the HTTP/1.1 protocol.
     */
    private final CompressionConfig compressionConfig = new CompressionConfig();


    /**
     * Returns the compression setting.
     *
     * @return the compression setting
     */
    public String getCompression() {
        return compressionConfig.getCompression();
    }


    /**
     * Sets the compression setting: {@code off}, {@code on}, {@code force}
     * or a numeric minimum response size.
     *
     * @param compression The compression setting
     */
    public void setCompression(String compression) {
        compressionConfig.setCompression(compression);
    }


    /**
     * Returns the list of user agents that should not use compression.
     *
     * @return The user agents that should not use compression
     */
    public String getNoCompressionUserAgents() {
        return compressionConfig.getNoCompressionUserAgents();
    }


    /**
     * Sets the list of user agents (a regular expression) that should not
     * use compression.
     *
     * @param noCompressionUserAgents The user agents that should not use
     *                                compression
     */
    public void setNoCompressionUserAgents(String noCompressionUserAgents) {
        compressionConfig.setNoCompressionUserAgents(noCompressionUserAgents);
    }


    /**
     * Returns the MIME types that may be subject to compression.
     *
     * @return The MIME types that may be subject to compression
     */
    public String getCompressibleMimeType() {
        return compressionConfig.getCompressibleMimeType();
    }


    /**
     * Sets the MIME types that may be subject to compression.
     *
     * @param valueS The MIME types that may be subject to compression
     */
    public void setCompressibleMimeType(String valueS) {
        compressionConfig.setCompressibleMimeType(valueS);
    }


    /**
     * Returns the MIME types that may be subject to compression as an
     * array.
     *
     * @return The MIME types that may be subject to compression
     */
    public String[] getCompressibleMimeTypes() {
        return compressionConfig.getCompressibleMimeTypes();
    }


    /**
     * Returns the minimum response size for compression to be applied.
     *
     * @return The minimum response size in bytes
     */
    public int getCompressionMinSize() {
        return compressionConfig.getCompressionMinSize();
    }


    /**
     * Sets the minimum response size for compression to be applied.
     *
     * @param compressionMinSize The minimum response size in bytes
     */
    public void setCompressionMinSize(int compressionMinSize) {
        compressionConfig.setCompressionMinSize(compressionMinSize);
    }


    /**
     * Returns the content encodings that are never re-compressed.
     *
     * @return The content encodings that should not be used
     */
    public String getNoCompressionEncodings() {
        return compressionConfig.getNoCompressionEncodings();
    }


    /**
     * Sets the content encodings that are never re-compressed.
     *
     * @param encodings The content encodings that should not be used
     */
    public void setNoCompressionEncodings(String encodings) {
        compressionConfig.setNoCompressionEncodings(encodings);
    }


    /**
     * Checks whether the response should be compressed, applying the shared
     * {@link CompressionConfig} decision logic. When the result is
     * {@code true}, the configuration has already updated the response
     * headers (Vary, Content-Encoding) and cleared the content length.
     *
     * @param request  The HTTP request
     * @param response The HTTP response
     *
     * @return {@code true} if compression should be used
     */
    public boolean useCompression(Request request, Response response) {
        return compressionConfig.useCompression(request, response);
    }


    /**
     * The maximum number of trailer headers allowed per request.
     */
    private int maxTrailerCount = 100;


    /**
     * Sets the maximum number of trailer headers allowed per request. A
     * negative value disables the limit.
     *
     * @param maxTrailerCount the maximum trailer count, or a negative value
     *                        for no limit
     */
    public void setMaxTrailerCount(int maxTrailerCount) {
        this.maxTrailerCount = maxTrailerCount;
    }


    /**
     * Returns the maximum number of trailer headers allowed per request.
     *
     * @return the maximum trailer count, or a negative value if unlimited
     */
    public int getMaxTrailerCount() {
        return maxTrailerCount;
    }


    /**
     * The maximum size of trailer headers in bytes.
     */
    private int maxTrailerSize = 8 * 1024;


    /**
     * Sets the maximum decoded size of trailer headers in bytes. A negative
     * value disables the decoded-size limit.
     * <p>
     * A trailer section is carried in a single HEADERS frame, and the
     * receiver still enforces the local 16 MiB per-frame buffering limit
     * ({@link Constants#MAX_FRAME_LENGTH}). A negative value therefore does
     * not allow a trailer section larger than that frame limit.
     *
     * @param maxTrailerSize the maximum decoded trailer size, or a negative
     *                       value for no decoded-size limit
     */
    public void setMaxTrailerSize(int maxTrailerSize) {
        this.maxTrailerSize = maxTrailerSize;
    }


    /**
     * Returns the maximum size of trailer headers in bytes.
     *
     * @return the maximum trailer size, or a negative value if unlimited
     */
    public int getMaxTrailerSize() {
        return maxTrailerSize;
    }


    // ------------------------------------------------ QuicProtocol

    @Override
    public QuicConnectionManager createQuicConnectionManager() {
        return new Http3ConnectionManager(this);
    }


    /**
     * {@inheritDoc}
     * <p>
     * Only the registered {@code h3} identifier is advertised. The
     * deprecated draft alias {@code h3-29} is deliberately not offered:
     * this implementation speaks RFC 9114 HTTP/3 and cannot serve the
     * draft-29 wire format, so advertising the alias would produce a
     * self-contradictory capability (the endpoint rejects connections that
     * negotiated a protocol outside this list).
     */
    @Override
    public String[] getAlpnIdentifiers() {
        return new String[] { ALPN_NAME };
    }


    @Override
    public long getDefaultStreamErrorCode() {
        return Http3Error.H3_INTERNAL_ERROR.getCode();
    }


    /**
     * {@inheritDoc}
     * <p>
     * Rejects connections the transport refuses while at connection
     * capacity with {@code H3_EXCESSIVE_LOAD} (RFC 9114 Section 8.1): the
     * server is too busy to handle the connection.
     */
    @Override
    public long getConnectionRejectErrorCode() {
        return Http3Error.H3_EXCESSIVE_LOAD.getCode();
    }


    /**
     * {@inheritDoc}
     * <p>
     * Rejects streams the transport refuses at the concurrent-stream limit
     * with {@code H3_REQUEST_REJECTED} (RFC 9114 Section 8.1): the request
     * was rejected before the server began processing it and the client may
     * retry it, mirroring HTTP/2's REFUSED_STREAM.
     */
    @Override
    public long getStreamRejectErrorCode() {
        return Http3Error.H3_REQUEST_REJECTED.getCode();
    }


    /**
     * {@inheritDoc}
     * <p>
     * Signals the endpoint's normal shutdown to live connections with
     * {@code H3_NO_ERROR} (RFC 9114 Section 8: "No error. Connections can be
     * closed as part of delayed shutdown"), after the GOAWAY frame the
     * endpoint sends as the graceful-shutdown mechanism of RFC 9114
     * Section 5.2.
     */
    @Override
    public long getGracefulShutdownErrorCode() {
        return Http3Error.H3_NO_ERROR.getCode();
    }


    // ------------------------------------------------ SSL Configuration

    public boolean isSSLEnabled() {
        return getEndpoint().isSSLEnabled();
    }


    public void setSSLEnabled(boolean SSLEnabled) {
        getEndpoint().setSSLEnabled(SSLEnabled);
    }


    // ------------------------------------------------ AbstractProtocol overrides

    private void configureProcessor(Http3Processor processor) {
        // Configure the processor's own (fallback) decoder: it is replaced
        // by the shared per-connection decoder during service(), which the
        // connection manager configures the same way.
        configureDecoder(processor.getQpackDecoder());
    }


    /*
     * The single application of this connector's header limits to a QPACK
     * decoder. Shared by every decoder construction site (the per-processor
     * fallback decoders created here and in Http3Processor.recycle(), and
     * the per-connection shared decoder created by
     * Http3ConnectionManager), so the limits of the decoders in use cannot
     * drift apart as the set of limits grows.
     * <p>
     * Note: these instance-level limits are not what enforces the limits on
     * a production decode. Every production field-section decode goes
     * through the four-argument
     * QpackDecoder.decodeHeaderBlock(ByteBuffer, HeaderEmitter, int, int)
     * overload (the trailer sections pass the connector's trailer limits),
     * which applies the per-call limits for the duration of the call and
     * then restores the instance values set here. The instance fields are
     * the limits seen only by the two-argument overload - used by the unit
     * tests - and the restore target of the four-argument one; keeping them
     * configured is about keeping that scaffolding consistent, not about
     * enforcing a limit.
     */
    void configureDecoder(QpackDecoder decoder) {
        decoder.setMaxHeaderCount(getMaxHeaderCount());
        decoder.setMaxHeaderSize(getMaxFieldSectionSizeInt());
    }


    @Override
    protected Processor createProcessor() {
        Http3Processor processor = new Http3Processor(this, getAdapter());
        configureProcessor(processor);
        return processor;
    }


    @Override
    protected UpgradeProtocol getNegotiatedProtocol(String name) {
        // HTTP/3 is not an upgrade of another protocol. The "h3" ALPN
        // identifier is negotiated by the QUIC endpoint (see
        // QuicOpenSSLEndpoint), which checks it against
        // getAlpnIdentifiers() and dispatches streams directly. There is
        // therefore no protocol to look up here, and stream socket
        // wrappers do not report a negotiated protocol.
        return null;
    }


    @Override
    protected UpgradeProtocol getUpgradeProtocol(String name) {
        return null;
    }


    /**
     * HTTP/3 does not support protocol upgrades. Each QUIC stream is served
     * by an HTTP/3 processor created by {@link #createProcessor()}; there is
     * no upgrade path from or to another protocol.
     *
     * @param socket       Ignored
     * @param upgradeToken Ignored
     *
     * @return never returns
     *
     * @throws IllegalStateException always
     */
    @Override
    protected Processor createUpgradeProcessor(SocketWrapperBase<?> socket,
            UpgradeToken upgradeToken) {
        // The token or its handler may in principle be unset; report them
        // without dereferencing so the documented always-IllegalStateException
        // contract holds for any argument state.
        HttpUpgradeHandler handler =
                upgradeToken == null ? null : upgradeToken.httpUpgradeHandler();
        throw new IllegalStateException(sm.getString("http3Protocol.noUpgradeHandler",
                handler == null ? "none" : handler.getClass().getName()));
    }


    private static final Log log =
            LogFactory.getLog(AbstractHttp3Protocol.class);


    @Override
    protected Log getLog() {
        return log;
    }


    @Override
    protected String getNamePrefix() {
        // QUIC always runs over TLS 1.3 (RFC 9001) and a non-TLS configuration
        // is rejected at bind time, so this endpoint is always secure.
        return "https-quic-" + getQuicImplementationShortName();
    }


    /**
     * Get the short name of the QUIC implementation this protocol selects,
     * used in the endpoint name (and therefore in JMX object names and
     * bind-time log lines).
     *
     * @return The short name of the QUIC implementation, e.g. {@code
     *         "quiche"} for the quiche endpoint or {@code "openssl"} for the
     *         OpenSSL endpoint
     */
    protected abstract String getQuicImplementationShortName();


    @Override
    protected String getProtocolName() {
        return "h3";
    }


    @Override
    public boolean isUdp() {
        return true;
    }


    // ------------------------------------------------ ProtocolHandler

    @Override
    public UpgradeProtocol[] findUpgradeProtocols() {
        // HTTP/3 is its own transport protocol. It neither upgrades from nor
        // to another protocol, and does not host nested upgrade protocols.
        return new UpgradeProtocol[0];
    }


    @Override
    public void addUpgradeProtocol(UpgradeProtocol upgradeProtocol) {
        // No-op: HTTP/3 doesn't support nested upgrade protocols
    }


    @Override
    public SSLHostConfig[] findSslHostConfigs() {
        return getEndpoint().findSslHostConfigs();
    }


    @Override
    public void addSslHostConfig(SSLHostConfig sslHostConfig) {
        getEndpoint().addSslHostConfig(sslHostConfig);
    }


    @Override
    public void addSslHostConfig(SSLHostConfig sslHostConfig, boolean replace) {
        getEndpoint().addSslHostConfig(sslHostConfig, replace);
    }


    /**
     * Matches the SNI host name with the host name from the protocol (the
     * {@code :authority} pseudo-header) if required (i.e. when
     * {@code strictSni} is enabled). Delegates to the endpoint, which applies
     * the same rules as the other protocols.
     *
     * @param sniHostName      The SNI host name sent by the client
     * @param protocolHostName The host name from the {@code :authority}
     *                         pseudo-header
     *
     * @return {@code true} if the names match (or the check is not
     *         required), {@code false} otherwise
     */
    public boolean checkSni(String sniHostName, String protocolHostName) {
        return getEndpoint().checkSni(sniHostName, protocolHostName);
    }
}

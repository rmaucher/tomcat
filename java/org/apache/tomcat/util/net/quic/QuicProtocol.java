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
package org.apache.tomcat.util.net.quic;

/**
 * The view the QUIC endpoint has of the application protocol it carries
 * (HTTP/3 in practice).
 * <p>
 * The QUIC transport must not depend on the protocol package it serves. The
 * protocol implements this interface and the endpoint consumes it through
 * here, so the dependency direction stays protocol-to-QUIC (e.g.
 * {@code org.apache.coyote.http3} depends on the interfaces in this
 * package, not the other way around).
 */
public interface QuicProtocol {

    /**
     * Returns the idle timeout to request for accepted connections
     * (RFC 9000 Section 10.1).
     *
     * @return The idle timeout in milliseconds; {@code 0} or less to leave
     *         the transport default in place
     */
    long getIdleTimeoutMs();


    /**
     * Returns the maximum number of concurrent application protocol streams
     * (for HTTP/3: concurrent client-initiated request streams) the endpoint
     * should allow per connection, as configured by the administrator.
     * <p>
     * Note: the QUIC transport advertises its own concurrency limit to the
     * peer in the {@code initial_max_streams_bidi} transport parameter. With
     * the OpenSSL QUIC implementation (OpenSSL 3.5 / 4.0) that parameter is
     * fixed and cannot be configured via the public API, so the endpoint
     * cannot advertise a value below the transport default. The endpoint
     * therefore uses the configured value for its own enforcement and warns
     * when it differs from the value the peer observes. With the quiche
     * implementation ({@code org.apache.tomcat.util.net.quic.quiche}) the
     * parameter is configurable, so the configured value is what the peer
     * observes; quiche's own default is zero, which allows no bidirectional
     * streams at all, so on that transport the "transport default" resolves
     * to the smallest HTTP/3-usable value (one stream).
     *
     * @return The configured maximum number of concurrent streams;
     *         {@code 0} or less to use the transport default
     */
    long getMaxConcurrentStreams();


    /**
     * Creates the connection manager that tracks the application protocol
     * state of a new QUIC connection. Called by the endpoint once per
     * accepted connection.
     *
     * @return A new connection manager instance for the protocol
     */
    QuicConnectionManager createQuicConnectionManager();


    /**
     * Returns the ALPN protocol identifiers this endpoint negotiates. The
     * first entry is the canonical identifier; later entries are additional
     * identifiers the application protocol can actually serve (for HTTP/3:
     * just the registered {@code "h3"} identifier — the draft alias
     * {@code "h3-29"} is not served by RFC 9114 implementations and must not
     * be advertised unless the draft wire format is supported).
     *
     * @return The accepted ALPN protocol identifiers, in preference order
     */
    String[] getAlpnIdentifiers();


    /**
     * Returns whether the given ALPN-negotiated protocol identifier (the
     * result of the TLS ALPN negotiation, RFC 9001 Section 7) is one the
     * application protocol can serve. A connection that negotiated no
     * protocol, or one the application protocol does not serve, must not
     * have protocol data dispatched to the connection; the transport tears
     * the connection down instead.
     *
     * @param negotiated The negotiated protocol name; may be {@code null}
     *                   when no protocol was negotiated
     *
     * @return {@code true} if the name is a supported
     *         {@link #getAlpnIdentifiers() identifier}
     */
    default boolean isServedIdentifier(String negotiated) {
        if (negotiated == null) {
            return false;
        }
        for (String identifier : getAlpnIdentifiers()) {
            if (identifier.equals(negotiated)) {
                return true;
            }
        }
        return false;
    }


    /**
     * Returns the application protocol error code the endpoint uses when it
     * resets a stream on its own (for HTTP/3:
     * {@code H3_INTERNAL_ERROR}, RFC 9114 Section 8.1).
     *
     * @return The default stream error code for the application protocol
     */
    long getDefaultStreamErrorCode();


    /**
     * Returns the application protocol error code the transport carries in
     * the {@code CONNECTION_CLOSE} (RFC 9000 Section 5.4.6) when it must
     * reject a connection on its own initiative, most commonly because the
     * server is at its connection capacity (for HTTP/3:
     * {@code H3_EXCESSIVE_LOAD}, RFC 9114 Section 8.1).
     *
     * @return The connection rejection error code for the application
     *         protocol
     */
    long getConnectionRejectErrorCode();


    /**
     * Returns the application protocol error code the transport carries in
     * the {@code RESET_STREAM} frame (RFC 9000 Section 19.4) when it refuses
     * a new client-initiated stream on its own initiative, most commonly
     * because the server is at its concurrent-stream limit (for HTTP/3:
     * {@code H3_REQUEST_REJECTED}, RFC 9114 Section 8.1 - the request was
     * rejected before processing began, the retryable analogue of HTTP/2's
     * REFUSED_STREAM).
     *
     * @return The stream rejection error code for the application protocol
     */
    long getStreamRejectErrorCode();


    /**
     * Returns the application protocol error code the transport carries in
     * the {@code CONNECTION_CLOSE} (RFC 9000 Section 5.4.6) it sends to live
     * connections when the endpoint shuts down normally, so the peer learns
     * about the shutdown immediately instead of waiting for the QUIC idle
     * timeout (for HTTP/3: {@code H3_NO_ERROR}, RFC 9114 Sections 5.2 and 8,
     * typically preceded by a GOAWAY frame).
     *
     * @return The graceful shutdown error code for the application protocol,
     *         or {@code 0} if the protocol defines none
     */
    default long getGracefulShutdownErrorCode() {
        return 0;
    }
}
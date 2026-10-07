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

import java.nio.ByteBuffer;

/**
 * Tracks the application protocol state of a single QUIC connection and
 * supplies the protocol-specific data the QUIC endpoint needs to drive the
 * connection.
 * <p>
 * The QUIC transport must not depend on the application protocol package it
 * serves. The protocol provides an implementation of this interface (created
 * via {@link QuicProtocol#createQuicConnectionManager()}) and the endpoint
 * consumes it through here, keeping the dependency direction
 * protocol-to-QUIC.
 */
public interface QuicConnectionManager {

    /**
     * Called when a new QUIC connection is established.
     *
     * @param connection The QUIC connection wrapper
     */
    void connectionOpen(QuicConnection connection);


    /**
     * Called when a QUIC connection is closed.
     *
     * @param connection The QUIC connection wrapper
     */
    void connectionClose(QuicConnection connection);


    /**
     * Processes data read from a client-initiated unidirectional stream.
     * The stream is identified by the protocol-specific stream type the
     * sender wrote at the start of the stream, not by its stream ID. For
     * HTTP/3 this covers the client control stream and the QPACK encoder
     * and decoder streams; data on streams of unknown type is consumed and
     * discarded.
     * <p>
     * Buffer contract: {@code data} is presented in <em>read (flipped)
     * mode</em> - the buffered bytes to process are {@code [position, limit)}
     * (position is zero on entry), and the bytes between {@code limit} and the
     * capacity are not part of the current input. The implementation consumes
     * the bytes it understands with relative {@code get} operations, advancing
     * {@code position} past them, and MUST return with the buffer still in read
     * mode - it must not call {@code flip()}, {@code clear()} or {@code
     * compact()}. Any bytes the implementation does not consume are left
     * unread at {@code [position, limit)}; the caller compacts them back to the
     * start (restoring put mode) so a partial frame or instruction is
     * re-assembled with the bytes read on the next call. This applies equally
     * on a normal return and when an exception is thrown.
     * <p>
     * Threading contract: the endpoint invokes this inline on its poll thread
     * (both the OpenSSL and the quiche transports do - the measured cost of
     * protocol-only parsing is too small to justify dedicating a separate
     * thread). The implementation must not assume it runs off the poll
     * thread, and MUST NOT touch the native QUIC connection or
     * the poll set - it may only manipulate protocol state and the
     * protocol-specific decoder/encoder (whose own monitor serialises them
     * against worker threads). Any side effect that reaches the wire (for
     * HTTP/3, emitting QPACK decoder instructions) is queued here and flushed
     * by the caller on the poll thread.
     *
     * @param connection The QUIC connection
     * @param streamId   The stream ID
     * @param data       The data buffer, in read mode; the unconsumed tail
     *                   {@code [position, limit)} is retained by the caller for
     *                   the next read
     *
     * @throws Exception If a connection-level protocol error occurred. The
     *         connection must be failed, using
     *         {@link #getProtocolErrorCode(Throwable)} to determine the
     *         connection error code.
     */
    void processClientUniStreamData(QuicConnection connection, long streamId, ByteBuffer data)
            throws Exception;


    /**
     * Returns the application protocol state for a connection.
     *
     * @param connection The QUIC connection for which the state is required
     *
     * @return The connection state for the given connection
     */
    ConnectionState getState(QuicConnection connection);


    /**
     * Returns the index of the next server-initiated unidirectional stream
     * the protocol wants the endpoint to open for this connection, or
     * {@code -1} when the protocol has none pending right now (for HTTP/3:
     * index 0 is the control stream, then - once the peer's SETTINGS have
     * arrived - the QPACK encoder and decoder streams). The endpoint calls
     * this after connection acceptance and whenever an outgoing-stream event
     * or new client stream data may have advanced the protocol state.
     *
     * @param connection The QUIC connection
     *
     * @return The next server unidirectional stream index to create, or
     *         {@code -1} if none is required at this time
     */
    int nextServerUniStream(QuicConnection connection);


    /**
     * Returns the data the endpoint must write as the first bytes of the
     * server-initiated unidirectional stream with the given index (for
     * HTTP/3: index 0 is the control stream type plus the SETTINGS frame,
     * index 1/2 the QPACK encoder/decoder stream type bytes).
     *
     * @param index The server unidirectional stream index as returned by
     *              {@link #nextServerUniStream(QuicConnection)}
     *
     * @return A buffer with the initialization data, or {@code null} if the
     *         stream carries none
     */
    ByteBuffer getServerUniStreamInitData(int index);


    /**
     * Notifies the protocol that the server-initiated unidirectional stream
     * with the given index has been created and registered, allowing the
     * protocol to store the stream handle it needs for later writes (for
     * HTTP/3: the QPACK decoder stream handle used to emit decoder
     * instructions).
     *
     * @param connection The QUIC connection
     * @param index      The server unidirectional stream index
     * @param stream     The wrapper of the created stream
     */
    void serverUniStreamCreated(QuicConnection connection, int index, QuicStream stream);


    /**
     * Generates the stream retirement notification (the HTTP/3 GOAWAY
     * frame, RFC 9114 Section 7.2.6) for the given connection and records
     * the identifier it carries on the connection state. The endpoint
     * writes it on server unidirectional stream index 0.
     * <p>
     * Per RFC 9114 Section 5.2 the frame carries the ID of the first
     * client-initiated bidirectional stream that may not have been
     * processed (the ID following the last processed one, as
     * client-initiated bidirectional stream IDs increase in steps of
     * four, RFC 9000 Section 2.1): requests with that ID or a greater one
     * are rejected by the sender of the GOAWAY, requests on stream IDs
     * less than it might have been processed. The identifier MUST NOT be
     * greater than the identifier of any GOAWAY previously sent on the
     * connection (RFC 9114 Section 5.2: a receiver treats a greater
     * identifier as a connection error of type H3_ID_ERROR), so it is
     * clamped to the identifier recorded in the connection state.
     *
     * @param state                 The connection state, used to record
     *                              and enforce monotonicity of the
     *                              identifiers sent on this connection
     * @param lastProcessedStreamId The ID of the last client-initiated
     *                              bidirectional stream processed by the
     *                              sender, or a negative value if none was
     *
     * @return A buffer containing the frame (type + length + payload)
     */
    ByteBuffer getStreamLimitFrame(ConnectionState state,
            long lastProcessedStreamId);


    /**
     * Emits any protocol data that has been queued for the connection and
     * is waiting to reach the peer on a server-initiated stream (for
     * HTTP/3: the pending QPACK decoder instructions). Intended to be
     * called periodically from the QUIC poll thread.
     *
     * @param connection The QUIC connection
     */
    void flushPendingProtocolData(QuicConnection connection);


    /**
     * Notifies the protocol that a stream was rejected by the transport at
     * accept time (for HTTP/3: reset with H3_REQUEST_REJECTED at the
     * concurrent-stream limit, before any processor read a byte of it).
     * The protocol may need to record the abandonment independently of the
     * stream never having been dispatched (for HTTP/3: a QPACK Stream
     * Cancellation, RFC 9204 Section 2.2.2.2, since the peer's encoder may
     * already reference dynamic table entries for the section the rejected
     * stream carried).
     *
     * @param connection The QUIC connection
     * @param streamId   The ID of the rejected stream
     */
    default void noteStreamRejected(QuicConnection connection, long streamId) {
        // NO-OP: protocols without per-stream abandonment bookkeeping need
        // no action.
    }


    /**
     * Returns the application protocol connection error code carried by the
     * given throwable, to be propagated into the QUIC CONNECTION_CLOSE
     * frame.
     *
     * @param t The throwable
     *
     * @return The protocol error code, or {@code 0} if the throwable does
     *         not carry one
     */
    long getProtocolErrorCode(Throwable t);


    /**
     * Application protocol state for a single QUIC connection.
     */
    interface ConnectionState {

        /**
         * Returns the QUIC connection this state belongs to.
         *
         * @return The QUIC connection
         */
        QuicConnection getConnection();


        /**
         * Returns whether the peer's initial settings have been received.
         *
         * @return {@code true} if the settings have been received
         */
        boolean isClientSettingsReceived();


        /**
         * Checks whether a new request stream can be accepted, i.e. the
         * concurrent stream limit has not been reached.
         *
         * @param streamId The stream ID of the new stream
         *
         * @return {@code true} if the stream can be accepted
         */
        boolean canAcceptStream(long streamId);


        /**
         * Sets the maximum number of concurrent application protocol streams
         * to enforce for this connection. The endpoint calls this once per
         * connection after the transport stream limits are known, with a
         * value derived from the configured application protocol limit that
         * does not exceed what the QUIC transport advertises to the peer
         * ({@code initial_max_streams_bidi}), so transport and application
         * protocol enforcement cannot diverge.
         *
         * @param max The maximum number of concurrent streams
         */
        void setMaxConcurrentStreams(long max);


        /**
         * Records that a new bidirectional stream was accepted.
         */
        void incrementActiveStreams();


        /**
         * Records that a bidirectional stream was closed.
         */
        void decrementActiveStreams();


        /**
         * Updates the last processed stream ID, used when generating the
         * stream retirement notification
         * ({@link #getStreamLimitFrame(ConnectionState, long)}).
         * <p>
         * Endpoints call this when a request stream is accepted, before
         * any processor has run a byte of it, so the recorded ID may name
         * a stream whose request has not completed (or will never
         * complete if the connection dies first). The resulting GOAWAY
         * identifier therefore means "may have been processed or might be
         * processed" (RFC 9114 Section 5.2), which is the most a
         * connector can promise at accept time.
         *
         * @param streamId The identifier of the last processed stream
         */
        void setLastProcessedStreamId(long streamId);


        /**
         * Returns the last processed stream ID.
         *
         * @return The last processed stream ID
         */
        long getLastProcessedStreamId();


        /**
         * Returns the identifier carried by the most recent stream
         * retirement notification ({@link #getStreamLimitFrame}) sent on
         * this connection, or -1 if none was sent. Subsequent
         * notifications MUST NOT carry a greater identifier
         * (RFC 9114 Section 5.2).
         *
         * @return The last GOAWAY identifier sent, or -1 if none
         */
        long getLastSentGoawayId();


        /**
         * Records the identifier carried by a stream retirement
         * notification sent on this connection.
         *
         * @param goawayId The identifier the frame carries
         */
        void setLastSentGoawayId(long goawayId);


        /**
         * Returns whether the given client-initiated unidirectional stream
         * has been identified as a stream whose closure is a connection
         * error (for HTTP/3 the control stream, RFC 9114 Section 6.2.1, and
         * the QPACK encoder and decoder streams, RFC 9204 Section 4.2).
         *
         * @param streamId The identifier of the client unidirectional stream
         *
         * @return {@code true} if the stream is protocol-critical and must
         *         stay open for the connection lifetime
         */
        boolean isCriticalClientUniStream(long streamId);


        /**
         * Returns the application protocol error code with which the
         * connection must be failed when a stream reported critical by
         * {@link #isCriticalClientUniStream(long)} is closed (for HTTP/3
         * {@code H3_CLOSED_CRITICAL_STREAM}, RFC 9114 Section 6.2.1,
         * RFC 9204 Section 4.2).
         *
         * @return The protocol error code
         */
        long getClosedCriticalStreamErrorCode();


        /**
         * Notifies the protocol that a client-initiated unidirectional
         * stream was closed or reset while the connection remains open
         * (clean close, reset or poll failure), allowing the protocol to
         * release any per-stream bookkeeping it retained for that stream
         * (for HTTP/3 the read-and-discard state of an unknown stream type,
         * RFC 9114 Section 9). Stream IDs are never reused (RFC 9000 Section
         * 2.1), so the notification fires at most once per ID. Implementations
         * must ignore IDs they do not know.
         *
         * @param streamId The identifier of the client unidirectional stream
         */
        void clientUniStreamClosed(long streamId);
    }
}
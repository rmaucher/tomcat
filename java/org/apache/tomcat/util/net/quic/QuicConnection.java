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
 * The QUIC transport view of a QUIC connection.
 * <p>
 * This interface is part of the QUIC abstraction in this package that the
 * application protocol implementation (HTTP/3 in practice) depends on. The
 * concrete transport implementation is provided in a separate package (the
 * OpenSSL QUIC implementation in
 * {@code org.apache.tomcat.util.net.quic.openssl} or the Cloudflare quiche
 * implementation in {@code org.apache.tomcat.util.net.quic.quiche}) and
 * must not be referenced by application protocol code.
 * <p>
 * Implementations must use identity semantics (must not override
 * {@code equals()} or {@code hashCode()}): one wrapper object represents one
 * QUIC connection for its whole lifetime, so the wrapper can be used as the
 * key of identity-based per-connection maps.
 */
public interface QuicConnection {

    /**
     * Returns the application protocol connection manager registered for
     * this connection. The application protocol registers its manager when
     * the transport accepts the connection, so it is available to all code
     * that operates on the connection afterwards.
     *
     * @return The connection manager for this connection, or {@code null} if
     *         none is registered
     */
    QuicConnectionManager getQuicConnectionManager();


    /**
     * Records whether this connection has protocol data pending emission that
     * the transport's periodic flush must pick up (for HTTP/3: QPACK decoder
     * instructions queued from worker/protocol threads, emitted on the
     * transport thread). Implementations that do not run a protocol-data
     * flush may keep the default no-op.
     *
     * @param pending {@code true} when data was queued, {@code false} once
     *                the flush has drained it
     */
    default void setProtocolDataPending(boolean pending) {
        // No pending-data tracking by default
    }


    /**
     * Returns whether protocol data is pending emission on this connection
     * (see {@link #setProtocolDataPending(boolean)}).
     *
     * @return {@code true} if a flush is pending
     */
    default boolean isProtocolDataPending() {
        return false;
    }


    /**
     * Returns the server name the peer requested for this connection
     * (TLS SNI, RFC 9001 Section 4). An empty string is returned both when
     * the peer sent no server name and when the value could not be obtained;
     * the two cases cannot be distinguished here, so callers must treat an
     * empty result as "no usable server name".
     *
     * @return The requested host name, or an empty string if none was sent
     *         or the value could not be determined; never {@code null}
     */
    String getSniHostName();


    /**
     * Signals a fatal connection error for this connection (RFC 9000
     * Section 5.4.6): the transport sends a {@code CONNECTION_CLOSE} frame
     * carrying the given error code and tears the connection down.
     * <p>
     * The native teardown performed by this explicit failure path must run
     * on the transport thread. Transports that are not called from their
     * transport thread hop the teardown there and may block the caller until
     * the hop completes (the SSL/Panama implementation waits for the poll
     * loop up to its hop timeout and then marks the connection closed), so
     * this method is not guaranteed to return immediately. Note that the
     * reachability-based fallback that releases the native connection when
     * the wrapper becomes unreachable without an explicit failure or close
     * is not hopped to the transport thread (unlike stream wrappers, whose
     * fallback frees are hopped to the poll thread); it is safe only because
     * the transport's connection book-keeping keeps the wrapper reachable
     * while the explicit teardown paths can still run against it.
     *
     * @param appErrorCode The application protocol error code carried in the
     *                     {@code CONNECTION_CLOSE} frame
     * @param reason       A diagnostic reason phrase
     */
    void failConnection(long appErrorCode, String reason);


    /**
     * Writes data on the given stream of this connection.
     * <p>
     * Must be called on the transport thread: writes to a native stream are
     * not thread-safe. The bytes to write are taken from {@code data}'s
     * current position to its limit; on return the position has advanced by
     * exactly the number of accepted bytes - the return value - which may
     * be a prefix of the buffer. A caller that retries must re-present the
     * remaining bytes unchanged (the accepted prefix is already in flight;
     * rebuilding the data from higher-level state would duplicate it).
     * <p>
     * A return value of {@code 0} means nothing was accepted and the write
     * should be retried later (e.g. once the peer's flow control allows it).
     * When the stream is in a terminal state that can never accept the
     * data, the transport consumes the buffer entirely and reports every
     * byte as accepted, so the caller drops its pending state instead of
     * retrying forever.
     *
     * @param stream The stream to write to
     * @param data   The data to write, in write mode; the position is
     *               advanced by the number of accepted bytes
     *
     * @return the number of bytes accepted by the stream
     */
    int writeToStream(QuicStream stream, ByteBuffer data);
}
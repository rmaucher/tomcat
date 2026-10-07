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
 * The QUIC transport view of a single QUIC stream.
 * <p>
 * QUIC multiplexes the data of an application protocol over one transport
 * connection, so the stream is the unit of I/O the application protocol
 * works with. Every stream belongs to a parent {@link QuicConnection} and
 * is either readable, writable or both, depending on how it was created and
 * by which peer (RFC 9000 Section 2).
 * <p>
 * This interface is part of the QUIC abstraction in this package that the
 * application protocol implementation (HTTP/3 in practice) depends on. The
 * concrete transport implementation is provided in a separate package (the
 * OpenSSL QUIC implementation in {@code org.apache.tomcat.util.net.quic.openssl}
 * or the Cloudflare quiche implementation in
 * {@code org.apache.tomcat.util.net.quic.quiche}) and must not be referenced
 * by application protocol code.
 * <p>
 * Implementations must use identity semantics (must not override
 * {@code equals()} or {@code hashCode()}) so a wrapper object can be stored
 * in identity-keyed maps for the lifetime of its stream.
 */
public interface QuicStream {

    /**
     * The state of the read side of a QUIC stream (RFC 9000 Section 2.4,
     * the receive part of the stream state machine).
     */
    enum ReadState {
        /**
         * The stream can be read from; more data may or may not be buffered.
         */
        OK,
        /**
         * All stream data has been received and the peer has signalled the
         * end of the stream.
         */
        FINISHED,
        /**
         * The read side was reset locally (e.g. the application aborted the
         * read direction); further data will never be delivered.
         */
        RESET_LOCAL,
        /**
         * The peer reset the read side; any data received before the reset
         * may still be available.
         */
        RESET_REMOTE,
        /**
         * The owning connection is closed, so the stream can never progress.
         */
        CONN_CLOSED
    }


    /**
     * Returns the QUIC stream identifier assigned by the transport
     * (RFC 9000 Section 2.1).
     *
     * @return The stream ID
     */
    long getStreamId();


    /**
     * Returns the connection this stream belongs to.
     *
     * @return The parent QUIC connection, or {@code null} if the stream was
     *         created without one
     */
    QuicConnection getConnection();


    /**
     * Returns the current state of the read side of the stream. The state is
     * updated by the transport as it observes state transitions.
     *
     * @return The current read state, never {@code null}
     */
    ReadState getReadState();


    /**
     * Returns whether the transport resources backing this stream have been
     * released. Operations against a freed stream are undefined; code paths
     * that may race with stream teardown must check this first and fail
     * fast.
     *
     * @return {@code true} if the stream's transport resources have been
     *         released
     */
    boolean isFreed();


    /**
     * Returns the data the transport has queued as pending to be written on
     * this stream, in write mode, or a buffer with nothing to write when no
     * data is pending. The buffer is owned by the transport; readers must
     * not modify it besides consuming it with relative get operations.
     *
     * @return The pending write data, may be {@code null}
     */
    ByteBuffer getWriteBuffer();
}
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

import org.apache.tomcat.util.net.AbstractEndpoint;

/**
 * A QUIC endpoint: an endpoint that binds to a datagram socket and serves
 * QUIC connections for a single application protocol.
 * <p>
 * The QUIC transport must not depend on the application protocol package it
 * serves. The application protocol (HTTP/3 in practice) creates an endpoint
 * implementation and registers itself as the {@link QuicProtocol} of the
 * endpoint; the endpoint then consumes the protocol only through that
 * interface, keeping the dependency direction protocol-to-QUIC.
 * <p>
 * Concrete implementations provide the transport binding (the OpenSSL QUIC
 * implementation in {@code org.apache.tomcat.util.net.quic.openssl} and the
 * Cloudflare quiche implementation in
 * {@code org.apache.tomcat.util.net.quic.quiche}) while everything the
 * application protocol layer needs is defined by this class and the QUIC
 * interfaces of this package.
 *
 * @param <U> The type of the listener socket handle the transport uses to
 *            accept connections
 */
public abstract class QuicEndpoint<U> extends AbstractEndpoint<QuicStream, U> {

    /**
     * The view the application protocol exposes to this endpoint. Configured
     * by the protocol during initialization, before the endpoint is started.
     */
    private volatile QuicProtocol quicProtocol;


    /**
     * Creates a new QUIC endpoint.
     */
    public QuicEndpoint() {
        super();
    }


    /**
     * Sets the application protocol this endpoint serves. Called by the
     * protocol (e.g. AbstractHttp3Protocol) during initialization.
     *
     * @param protocol The protocol instance that owns this endpoint
     */
    public void setQuicProtocol(QuicProtocol protocol) {
        this.quicProtocol = protocol;
    }


    /**
     * Returns the application protocol this endpoint serves.
     *
     * @return The configured protocol, or {@code null} if none is configured
     *         yet
     */
    public QuicProtocol getQuicProtocol() {
        return quicProtocol;
    }
}
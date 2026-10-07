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

/**
 * HTTP/3 protocol handler selecting the OpenSSL QUIC endpoint.
 * <p>
 * Configure an HTTP/3 connector with this class as its {@code protocol}
 * attribute to run on the OpenSSL QUIC implementation provided by the FFM
 * bindings. The endpoint class is instantiated reflectively by name (it
 * lives in the FFM gated compilation pass); if the build lacks that pass
 * the connector fails to create. An OpenSSL installation that provides the
 * QUIC APIs (OpenSSL 4.0 or later, loaded into the JVM via the FFM
 * bindings, see {@code OpenSSLLifecycleListener}) is required at run time;
 * an unusable OpenSSL fails the connector at bind time.
 */
public class Http3OpenSSLProtocol extends AbstractHttp3Protocol {

    /**
     * The class name of the OpenSSL QUIC endpoint implementation.
     */
    private static final String OPENSSL_QUIC_ENDPOINT_CLASS =
            "org.apache.tomcat.util.net.quic.openssl.QuicOpenSSLEndpoint";


    /**
     * Creates a new HTTP/3 protocol handler with an OpenSSL QUIC endpoint.
     */
    public Http3OpenSSLProtocol() {
        super(createQuicEndpoint(OPENSSL_QUIC_ENDPOINT_CLASS));
    }


    @Override
    protected String getQuicImplementationShortName() {
        return "openssl";
    }
}

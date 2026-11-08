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
 * HTTP/3 protocol handler selecting the ngtcp2 QUIC endpoint.
 * <p>
 * Configure an HTTP/3 connector with this class as its {@code protocol}
 * attribute to run on the ngtcp2 implementation provided by the FFM
 * bindings. The endpoint class is instantiated reflectively by name (it
 * lives in the FFM gated compilation pass); if the build lacks that pass
 * the connector fails to create. A loadable libngtcp2 (1.16.x or 1.26.x)
 * and libngtcp2_crypto_ossl, backed by the system OpenSSL 3.5+ TLS stack, are
 * required at run time; an unusable installation fails the connector at bind
 * time.
 */
public class Http3Ngtcp2Protocol extends AbstractHttp3Protocol {

    /**
     * The class name of the ngtcp2 QUIC endpoint implementation.
     */
    private static final String NGTCP2_QUIC_ENDPOINT_CLASS =
            "org.apache.tomcat.util.net.quic.ngtcp2.Ngtcp2Endpoint";


    /**
     * Creates a new HTTP/3 protocol handler with a ngtcp2 QUIC endpoint.
     */
    public Http3Ngtcp2Protocol() {
        super(createQuicEndpoint(NGTCP2_QUIC_ENDPOINT_CLASS));
    }


    @Override
    protected String getQuicImplementationShortName() {
        return "ngtcp2";
    }
}

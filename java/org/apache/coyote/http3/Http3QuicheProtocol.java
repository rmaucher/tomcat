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
 * HTTP/3 protocol handler selecting the Cloudflare quiche QUIC endpoint.
 * <p>
 * Configure an HTTP/3 connector with this class as its {@code protocol}
 * attribute to run on the quiche implementation provided by the FFM
 * bindings. The endpoint class is instantiated reflectively by name (it
 * lives in the FFM gated compilation pass); if the build lacks that pass
 * the connector fails to create. A loadable libquiche is required at run
 * time; an unusable libquiche fails the connector at bind time.
 */
public class Http3QuicheProtocol extends AbstractHttp3Protocol {

    /**
     * The class name of the quiche QUIC endpoint implementation.
     */
    private static final String QUICHE_QUIC_ENDPOINT_CLASS =
            "org.apache.tomcat.util.net.quic.quiche.QuicheEndpoint";


    /**
     * Creates a new HTTP/3 protocol handler with a quiche QUIC endpoint.
     */
    public Http3QuicheProtocol() {
        super(createQuicEndpoint(QUICHE_QUIC_ENDPOINT_CLASS));
    }


    @Override
    protected String getQuicImplementationShortName() {
        return "quiche";
    }
}

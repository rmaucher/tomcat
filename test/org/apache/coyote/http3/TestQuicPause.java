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
package org.apache.coyote.http3;

import java.util.Collections;

import org.junit.Assert;
import org.junit.Test;

import org.apache.coyote.AbstractProtocol;

/**
 * Tests that the QUIC endpoint honours the AbstractEndpoint pause contract:
 * a paused connector stops serving new connections.
 */
public class TestQuicPause extends Http3TestBase {

    @Test
    public void testPausedEndpointRefusesNewConnections() throws Exception {
        startHttp3Server();

        // Sanity check: new connections are served before the pause.
        validateStatus(get("/simple"), 200);

        connector.pause();
        Assert.assertTrue("endpoint should be paused",
                ((AbstractProtocol<?>) connector.getProtocolHandler())
                        .isPaused());

        // A paused endpoint accepts no new connections. The endpoint drains
        // the pending connection with a rejection, so the request never
        // receives a response (the connection is torn down before any
        // stream is served) and the client gives up with an error.
        ClientOutput output = runClient(clientCommand("get", "127.0.0.1",
                Integer.toString(port), "/simple", "--timeout", "5"),
                CLIENT_TIMEOUT_SECONDS, 1);

        Assert.assertEquals("Expected no response from a paused endpoint: "
                + output.getLines() + " / " + output.getStderr(),
                Collections.emptyList(), output.getResponses());
    }
}

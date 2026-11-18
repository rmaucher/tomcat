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
package org.apache.tomcat.util.net.quic.openssl;

import org.junit.Assert;
import org.junit.Test;


/**
 * Tests for endpoint-level poll masks that can be verified without a running
 * listener.
 */
public class TestQuicOpenSSLEndpoint {


    @Test
    public void testConnectionEventsExcludeOsb() {
        long events = QuicOpenSSLEndpoint.CONNECTION_POLL_EVENTS;

        // The endpoint never creates server-initiated bidirectional streams,
        // and a level-triggered OSB would spin the outgoing handler.
        Assert.assertEquals(0L,
                events & QuicPoll.SSL_POLL_EVENT_OSB);
        // The events the connection still needs must remain requested.
        Assert.assertNotEquals(0L,
                events & QuicPoll.SSL_POLL_EVENT_OSU);
        Assert.assertNotEquals(0L,
                events & QuicPoll.SSL_POLL_EVENT_ISB);
        Assert.assertNotEquals(0L,
                events & QuicPoll.SSL_POLL_EVENT_ISU);
        Assert.assertNotEquals(0L,
                events & QuicPoll.SSL_POLL_EVENT_EC);
        Assert.assertNotEquals(0L,
                events & QuicPoll.SSL_POLL_EVENT_ECD);
        Assert.assertNotEquals(0L,
                events & QuicPoll.SSL_POLL_EVENT_ER);
        Assert.assertNotEquals(0L,
                events & QuicPoll.SSL_POLL_EVENT_EW);
    }
}

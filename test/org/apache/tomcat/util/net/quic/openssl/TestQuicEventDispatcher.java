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
package org.apache.tomcat.util.net.quic.openssl;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.net.quic.openssl.QuicEventDispatcher.QuicEvent;

/**
 * Decision-table tests for {@link QuicEventDispatcher#classify(long, boolean)},
 * the pure {@code ERROR -> IN -> OUT} priority of the QUIC poll loop. They pin
 * the per-flag and cross-bucket priority against the exact revents combinations
 * the loop can see, and the progress accounting that drives the no-progress
 * backoff, without any OpenSSL or native call.
 */
public class TestQuicEventDispatcher {

    private static final long EL = QuicPoll.SSL_POLL_EVENT_EL;
    private static final long EC = QuicPoll.SSL_POLL_EVENT_EC;
    private static final long ECD = QuicPoll.SSL_POLL_EVENT_ECD;
    private static final long ER = QuicPoll.SSL_POLL_EVENT_ER;
    private static final long EW = QuicPoll.SSL_POLL_EVENT_EW;
    private static final long R = QuicPoll.SSL_POLL_EVENT_R;
    private static final long W = QuicPoll.SSL_POLL_EVENT_W;
    private static final long IC = QuicPoll.SSL_POLL_EVENT_IC;
    private static final long ISB = QuicPoll.SSL_POLL_EVENT_ISB;
    private static final long ISU = QuicPoll.SSL_POLL_EVENT_ISU;
    private static final long OSB = QuicPoll.SSL_POLL_EVENT_OSB;
    private static final long OSU = QuicPoll.SSL_POLL_EVENT_OSU;


    /**
     * A listener revents carrying EL maps to LISTENER_ERROR and, crucially,
     * must not count as progress: the level-triggered flag re-fires while the
     * condition lasts, so counting it would defeat the poll-loop backoff.
     */
    @Test
    public void listenerErrorIsNotProgress() {
        QuicEvent event = QuicEventDispatcher.classify(EL, true);
        Assert.assertEquals(QuicEvent.LISTENER_ERROR, event);
        Assert.assertFalse(event.countsAsProgress());
    }


    /**
     * An error bucket on a non-listener connection with a connection-close
     * flag (EC or ECD) is serviced as CONNECTION_CLOSE and does count as
     * progress.
     */
    @Test
    public void connectionCloseBeatsStreamError() {
        for (long cc : new long[] { EC, ECD }) {
            QuicEvent event = QuicEventDispatcher.classify(cc, false);
            Assert.assertEquals(QuicEvent.CONNECTION_CLOSE, event);
            Assert.assertTrue(event.countsAsProgress());
        }
        // EC wins over a co-present stream read/write error.
        Assert.assertEquals(QuicEvent.CONNECTION_CLOSE,
                QuicEventDispatcher.classify(EC | ER | EW, false));
    }


    /**
     * ER or EW alone (no connection-close flag) map to STREAM_ERROR.
     */
    @Test
    public void streamError() {
        Assert.assertEquals(QuicEvent.STREAM_ERROR,
                QuicEventDispatcher.classify(ER, false));
        Assert.assertEquals(QuicEvent.STREAM_ERROR,
                QuicEventDispatcher.classify(EW, false));
    }


    /**
     * An error bucket reached by a flag with no specific handler (a non-listener
     * EL, or EL alongside neither EC/ECD nor ER/EW) yields ERROR_OTHER, which
     * still counts as progress.
     */
    @Test
    public void errorBucketWithoutSpecificHandler() {
        QuicEvent event = QuicEventDispatcher.classify(EL, false);
        Assert.assertEquals(QuicEvent.ERROR_OTHER, event);
        Assert.assertTrue(event.countsAsProgress());
    }


    /**
     * Within the INBOUND bucket, IC beats IS beats R.
     */
    @Test
    public void inboundPriority() {
        Assert.assertEquals(QuicEvent.INCOMING_CONNECTION,
                QuicEventDispatcher.classify(IC, false));
        Assert.assertEquals(QuicEvent.INCOMING_CONNECTION,
                QuicEventDispatcher.classify(IC | ISB | R, false));
        Assert.assertEquals(QuicEvent.INCOMING_STREAM,
                QuicEventDispatcher.classify(ISB, false));
        Assert.assertEquals(QuicEvent.INCOMING_STREAM,
                QuicEventDispatcher.classify(ISU | R, false));
        Assert.assertEquals(QuicEvent.READABLE,
                QuicEventDispatcher.classify(R, false));
    }


    /**
     * Within the OUTBOUND bucket, OS beats W.
     */
    @Test
    public void outboundPriority() {
        Assert.assertEquals(QuicEvent.OUTGOING_STREAM,
                QuicEventDispatcher.classify(OSB, false));
        Assert.assertEquals(QuicEvent.OUTGOING_STREAM,
                QuicEventDispatcher.classify(OSU | W, false));
        Assert.assertEquals(QuicEvent.WRITABLE,
                QuicEventDispatcher.classify(W, false));
    }


    /**
     * Across buckets, ERROR beats IN beats OUT: an error flag suppresses any
     * co-present inbound or outbound flag for the same iteration.
     */
    @Test
    public void bucketPriorityErrorInThenOut() {
        // error beats inbound and outbound
        Assert.assertEquals(QuicEvent.STREAM_ERROR,
                QuicEventDispatcher.classify(ER | IC | W, false));
        Assert.assertEquals(QuicEvent.CONNECTION_CLOSE,
                QuicEventDispatcher.classify(ECD | R | W, false));
        // inbound beats outbound
        Assert.assertEquals(QuicEvent.READABLE,
                QuicEventDispatcher.classify(R | W, false));
        Assert.assertEquals(QuicEvent.INCOMING_CONNECTION,
                QuicEventDispatcher.classify(IC | OSB, false));
    }


    /**
     * A listener error flag wins even alongside inbound flags (the error
     * bucket is entered first, then the listener branch).
     */
    @Test
    public void listenerErrorWinsOverInbound() {
        Assert.assertEquals(QuicEvent.LISTENER_ERROR,
                QuicEventDispatcher.classify(EL | IC, true));
    }


    /**
     * A revents mask with no serviceable flag (zero) maps to NONE and does not
     * count as progress.
     */
    @Test
    public void noEvent() {
        QuicEvent event = QuicEventDispatcher.classify(0L, false);
        Assert.assertEquals(QuicEvent.NONE, event);
        Assert.assertFalse(event.countsAsProgress());
    }


    /**
     * F (SSL_poll failure) is handled - and the item evicted or retained - by
     * the endpoint before classification, so this decision is unreachable
     * through the poll loop; it is nonetheless frozen here: F is part of the
     * composite ERROR mask, so a revents mask still carrying it must fall
     * into the error bucket (ERROR_OTHER, counted as progress on a
     * non-listener; LISTENER_ERROR on a listener) rather than reaching an
     * IN/OUT handler of an item that could not be polled.
     */
    @Test
    public void pollFailureFlagClassifiesAsOtherError() {
        long f = QuicPoll.SSL_POLL_EVENT_F;
        QuicEvent event = QuicEventDispatcher.classify(f, false);
        Assert.assertEquals(QuicEvent.ERROR_OTHER, event);
        Assert.assertTrue(event.countsAsProgress());
        // F outranks co-present inbound/outbound flags like any error flag.
        Assert.assertEquals(QuicEvent.ERROR_OTHER,
                QuicEventDispatcher.classify(f | R | W, false));
        Assert.assertEquals(QuicEvent.LISTENER_ERROR,
                QuicEventDispatcher.classify(f, true));
    }
}

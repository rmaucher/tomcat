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

/**
 * The event-priority decision of the QUIC poll loop, kept free of native and
 * endpoint state so it can be reasoned about (and unit tested) as a pure
 * function of the {@code SSL_poll()} revents mask.
 * <p>
 * {@code SSL_poll()} reports an OR of event flags per item. The endpoint
 * services each item by handling the highest-priority bucket that has any flag
 * set, following the OpenSSL reference order {@code ERROR -> IN -> OUT}: within
 * a bucket exactly one handler runs, the buckets are mutually exclusive per
 * iteration, and handling a bucket counts as progress except where noted. A
 * poll-failure flag ({@code F}) is handled by the endpoint before classification
 * (it evicts a failing stream or connection; a failing listener is retained),
 * so it never reaches {@link #classify}.
 */
final class QuicEventDispatcher {

    private QuicEventDispatcher() {
    }

    // Composite masks mirroring SSL_poll(3): an item is serviced by the
    // highest-priority bucket whose mask intersects its revents.
    //
    // F is part of the ERROR composite even though the endpoint handles it
    // before calling classify(): per SSL_poll(3) it is one of the error
    // flags, so a revents mask that still carries F (unreachable through
    // the endpoint, whose poll loop evicts F first) deliberately falls into
    // the error bucket: on a non-listener item it yields ERROR_OTHER, which
    // counts as progress, rather than being routed to an IN/OUT handler of
    // an item SSL_poll() could not poll. Frozen by
    // TestQuicEventDispatcher#testPollFailureFlagClassifiesAsOtherError.
    private static final long SSL_POLL_ERROR = QuicPoll.SSL_POLL_EVENT_F |
            QuicPoll.SSL_POLL_EVENT_EL |
            QuicPoll.SSL_POLL_EVENT_EC |
            QuicPoll.SSL_POLL_EVENT_ECD |
            QuicPoll.SSL_POLL_EVENT_ER |
            QuicPoll.SSL_POLL_EVENT_EW;

    private static final long SSL_POLL_IN = QuicPoll.SSL_POLL_EVENT_IC |
            QuicPoll.SSL_POLL_EVENT_IS |
            QuicPoll.SSL_POLL_EVENT_R;

    private static final long SSL_POLL_OUT = QuicPoll.SSL_POLL_EVENT_OS |
            QuicPoll.SSL_POLL_EVENT_W;

    private static final long CONNECTION_CLOSE_MASK =
            QuicPoll.SSL_POLL_EVENT_EC | QuicPoll.SSL_POLL_EVENT_ECD;

    private static final long STREAM_ERROR_MASK =
            QuicPoll.SSL_POLL_EVENT_ER | QuicPoll.SSL_POLL_EVENT_EW;


    /**
     * The single event a poll-loop iteration should service for one item.
     * {@link #countsAsProgress()} reports whether servicing it counts as
     * forward progress for the no-progress backoff at the bottom of the poll
     * loop.
     */
    enum QuicEvent {
        /** EL on the listener: reported but not progress (level-triggered). */
        LISTENER_ERROR(false),
        /** A live connection reported a close (EC/ECD). */
        CONNECTION_CLOSE(true),
        /** A connection or stream reported a read/write error (ER/EW). */
        STREAM_ERROR(true),
        /**
         * An error bucket was hit that none of the specific handlers claims
         * (for example a non-listener EL with no EC/ECD/ER/EW). Nothing runs,
         * but the bucket was reached, which the endpoint counts as progress.
         */
        ERROR_OTHER(true),
        INCOMING_CONNECTION(true),
        INCOMING_STREAM(true),
        READABLE(true),
        OUTGOING_STREAM(true),
        WRITABLE(true),
        /** No serviceable bucket matched the revents. */
        NONE(false);

        private final boolean progress;

        QuicEvent(boolean progress) {
            this.progress = progress;
        }

        /**
         * @return {@code true} if servicing this event should count as progress
         *         for the poll loop's no-progress backoff
         */
        boolean countsAsProgress() {
            return progress;
        }
    }


    /**
     * Chooses the event to service for one item, following the
     * {@code ERROR -> IN -> OUT} priority. Assumes the poll-failure flag
     * ({@code F}) was already handled by the caller.
     *
     * @param revents   the item's {@code SSL_poll()} revents mask
     * @param isListener whether the item is the listening socket
     *
     * @return the highest-priority event to service, or {@link QuicEvent#NONE}
     */
    static QuicEvent classify(long revents, boolean isListener) {
        if ((revents & SSL_POLL_ERROR) != 0) {
            if (isListener) {
                return QuicEvent.LISTENER_ERROR;
            }
            if ((revents & CONNECTION_CLOSE_MASK) != 0) {
                return QuicEvent.CONNECTION_CLOSE;
            }
            if ((revents & STREAM_ERROR_MASK) != 0) {
                return QuicEvent.STREAM_ERROR;
            }
            return QuicEvent.ERROR_OTHER;
        }
        if ((revents & SSL_POLL_IN) != 0) {
            if ((revents & QuicPoll.SSL_POLL_EVENT_IC) != 0) {
                return QuicEvent.INCOMING_CONNECTION;
            }
            if ((revents & QuicPoll.SSL_POLL_EVENT_IS) != 0) {
                return QuicEvent.INCOMING_STREAM;
            }
            if ((revents & QuicPoll.SSL_POLL_EVENT_R) != 0) {
                return QuicEvent.READABLE;
            }
            return QuicEvent.NONE;
        }
        if ((revents & SSL_POLL_OUT) != 0) {
            if ((revents & QuicPoll.SSL_POLL_EVENT_OS) != 0) {
                return QuicEvent.OUTGOING_STREAM;
            }
            if ((revents & QuicPoll.SSL_POLL_EVENT_W) != 0) {
                return QuicEvent.WRITABLE;
            }
            return QuicEvent.NONE;
        }
        return QuicEvent.NONE;
    }
}

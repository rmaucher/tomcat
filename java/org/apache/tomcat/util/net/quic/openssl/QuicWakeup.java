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

import java.io.IOException;

import org.apache.tomcat.util.res.StringManager;


/**
 * The endpoint poll loop's blocking wait primitive.
 * <p>
 * {@code SSL_poll()} has no external wake hook, so the poll loop waits on the
 * UDP socket and a platform wake object together, then drives
 * {@code SSL_poll()} in non-blocking mode. This class preserves the endpoint's
 * existing {@code kick()}/{@code await()}/{@code consumeWake()}/{@code close()}
 * surface; the platform implementation owns the native wake primitive,
 * {@code poll} call and error handling.
 * <p>
 * {@link #kick()} may be called from any thread. {@link #await(long)},
 * {@link #consumeWake()} and {@link #close()} are called only from the poll
 * thread (close also from the stop path after the poll loop has stopped).
 */
final class QuicWakeup {

    private static final StringManager sm =
            StringManager.getManager(QuicOpenSSLEndpoint.class);

    /** The kick wake object became readable. */
    static final int EVENT_WAKE = QuicPlatformSupport.Wakeup.EVENT_WAKE;
    /** The UDP socket became readable (a QUIC packet may be pending). */
    static final int EVENT_SOCK = QuicPlatformSupport.Wakeup.EVENT_SOCK;

    private final QuicPlatformSupport.Wakeup delegate;


    /**
     * Creates the wake primitive for the given UDP socket.
     *
     * @param socket The endpoint's UDP socket handle
     *
     * @throws IOException If the platform wake object cannot be created
     */
    QuicWakeup(QuicPlatformSupport.SocketHandle socket) throws IOException {
        try {
            delegate = QuicPlatformSupport.get().createWakeup(socket);
        } catch (QuicPlatformSupport.QuicPlatformException e) {
            throw new IOException(sm.getString("quicEndpoint.wakeupCreateError"), e);
        }
    }


    /**
     * Signals the poll loop that mailbox work has been queued. Safe to call
     * from any thread, including after {@link #close()}: the platform wake
     * implementation makes the closed check and the kick atomic against close.
     */
    void kick() {
        delegate.kick();
    }


    /**
     * Waits for the UDP socket to become readable, for a {@link #kick()}, or
     * for the timeout to expire.
     *
     * @param timeoutMs Maximum time to wait; {@code 0} returns immediately and
     *                  a negative value waits without a deadline
     *
     * @return A bitmask of {@link #EVENT_WAKE} and {@link #EVENT_SOCK};
     *         {@code 0} means the wait timed out, a negative value means the
     *         wait failed
     */
    int await(long timeoutMs) {
        return delegate.await(timeoutMs);
    }


    /**
     * Drains the wake object. Called by the poll loop at the top of every
     * iteration, before the mailbox is drained, so a kick queued while the
     * drain runs still leaves the wake object set and the next
     * {@link #await(long)} returns immediately.
     */
    void consumeWake() {
        delegate.consume();
    }


    /**
     * Releases the platform wake object and its native scratch memory. Must be
     * called only once the poll loop has stopped.
     */
    void close() {
        delegate.close();
    }
}

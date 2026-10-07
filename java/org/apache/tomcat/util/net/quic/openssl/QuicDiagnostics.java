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

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import org.apache.tomcat.util.openssl.openssl_h;

/**
 * Low-level diagnostics for the OpenSSL QUIC bindings, kept out of the
 * endpoint so the poll loop and teardown paths are not interleaved with error
 * queue formatting. The helpers here are self-contained: they touch only the
 * OpenSSL error queue, never endpoint state. Payload dumps are deliberately
 * absent: transports log what happened (event, size), not the bytes, so
 * request data cannot leak into the log.
 */
final class QuicDiagnostics {

    /**
     * Upper bound on how many OpenSSL error-queue entries a single dump reads,
     * so a pathological queue cannot grow the dump without limit.
     */
    private static final int MAX_ERROR_QUEUE_ENTRIES = 16;

    private QuicDiagnostics() {
    }

    /**
     * Returns the OpenSSL error queue contents as a single string, then clears
     * the queue. Never throws: it is used on failure paths where a throw from
     * the diagnostics themselves would mask the real error.
     *
     * @return The rendered error queue, or {@code "<empty>"} when the queue is
     *         empty
     */
    static String dumpErrorQueue() {
        StringBuilder sb = new StringBuilder();
        try (Arena localArena = Arena.ofConfined()) {
            for (int i = 0; i < MAX_ERROR_QUEUE_ENTRIES; i++) {
                long code;
                try {
                    // ERR_get_error() takes AND removes the OLDEST queued
                    // code. Peeking with ERR_peek_last_error() while removing
                    // with ERR_get_error() logged the newest code once per
                    // queued entry, losing all earlier (often root-cause)
                    // errors.
                    code = openssl_h.ERR_get_error();
                } catch (Throwable t) {
                    break;
                }
                if (code == 0) {
                    break;
                }
                MemorySegment buf = localArena.allocate(256);
                try {
                    openssl_h.ERR_error_string_n(code, buf, 256);
                    sb.append(buf.getString(0)).append(' ');
                } catch (Throwable t) {
                    sb.append("0x").append(Long.toHexString(code)).append(' ');
                }
            }
        } catch (Throwable t) {
            // Ignore - diagnostics only
        }
        try {
            openssl_h.ERR_clear_error();
        } catch (Throwable t) {
            // Ignore
        }
        return sb.length() == 0 ? "<empty>" : sb.toString().trim();
    }
}

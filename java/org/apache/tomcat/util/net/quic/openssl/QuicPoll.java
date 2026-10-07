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
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;



/**
 * The OpenSSL QUIC polling building blocks: the {@code SSL_POLL_EVENT_*},
 * {@code SSL_STREAM_*} and {@code SSL_ACCEPT_STREAM_*} protocol constants, the
 * native {@code SSL_POLL_ITEM} / {@code BIO_POLL_DESCRIPTOR} struct layout
 * math, and the static {@code SSL_poll()} driver.
 * <p>
 * These are protocol/binding-level building blocks (they sit alongside
 * {@link QuicBindings}, which owns the downcall handles). They are kept out of
 * {@link QuicPollItem}, which is the per-item state wrapper. The C layout of the
 * structs the driver operates on is:
 * <pre>
 * typedef struct bio_poll_descriptor_st {
 *     uint32_t type;           // offset 0, 4 bytes
 *     union {                  // offset 8 (padded), 8 bytes
 *         int fd;
 *         void *custom;
 *         SSL *ssl;
 *     } value;
 * } BIO_POLL_DESCRIPTOR;       // total 16 bytes
 *
 * typedef struct ssl_poll_item_st {
 *     BIO_POLL_DESCRIPTOR desc;  // offset 0, 16 bytes
 *     uint64_t events;           // offset 16, 8 bytes
 *     uint64_t revents;          // offset 24, 8 bytes
 * } SSL_POLL_ITEM;               // total 32 bytes
 * </pre>
 */
public final class QuicPoll {

    private QuicPoll() {
        // Utility class - constants, layout and the SSL_poll() driver only.
    }

    // BIO_POLL_DESCRIPTOR type constants
    public static final int BIO_POLL_DESCRIPTOR_TYPE_SSL = 2;

    // SSL_POLL_EVENT constants - values of the SSL_POLL_EVENT_* enum in
    // OpenSSL's ssl.h (not exposed by the generated openssl_h bindings)
    // Failure: SSL_poll() failed to poll the item. SSL_poll() sets it on the
    // failing item, returns 0 and zeroes the revents of every item after it.
    // The endpoint must evict such items.
    public static final long SSL_POLL_EVENT_F = 1L << 0;       // Failure (item could not be polled)
    public static final long SSL_POLL_EVENT_EL = 1L << 1;      // Listener error
    public static final long SSL_POLL_EVENT_EC = 1L << 2;      // Connection close
    public static final long SSL_POLL_EVENT_ECD = 1L << 3;     // Connection closed
    public static final long SSL_POLL_EVENT_ER = 1L << 4;      // Stream read error
    public static final long SSL_POLL_EVENT_EW = 1L << 5;      // Stream write error
    public static final long SSL_POLL_EVENT_R = 1L << 6;       // Readable
    public static final long SSL_POLL_EVENT_W = 1L << 7;       // Writable
    public static final long SSL_POLL_EVENT_IC = 1L << 8;      // Incoming connection
    public static final long SSL_POLL_EVENT_ISB = 1L << 9;     // Incoming bidirectional stream
    public static final long SSL_POLL_EVENT_ISU = 1L << 10;    // Incoming unidirectional stream
    public static final long SSL_POLL_EVENT_OSB = 1L << 11;    // Outgoing bidirectional stream
    public static final long SSL_POLL_EVENT_OSU = 1L << 12;    // Outgoing unidirectional stream

    // Composite event masks
    // Flag: ssl.h SSL_POLL_FLAG_NO_HANDLE_EVENTS. SSL_poll() must not drive
    // the QUIC engine itself (no tick); the endpoint ticks explicitly with
    // SSL_handle_events() so ONE tick per loop iteration services the whole
    // shared engine (all connections of the listener ticked per OpenSSL 4.x
    // reactor model) instead of one full-engine tick per poll item.
    public static final long SSL_POLL_FLAG_NO_HANDLE_EVENTS = 1L << 0;
    public static final long SSL_POLL_EVENT_RE = SSL_POLL_EVENT_R | SSL_POLL_EVENT_ER;
    public static final long SSL_POLL_EVENT_WE = SSL_POLL_EVENT_W | SSL_POLL_EVENT_EW;
    public static final long SSL_POLL_EVENT_IS = SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU;
    public static final long SSL_POLL_EVENT_OS = SSL_POLL_EVENT_OSB | SSL_POLL_EVENT_OSU;
    public static final long SSL_POLL_EVENT_E =
            SSL_POLL_EVENT_EL | SSL_POLL_EVENT_EC | SSL_POLL_EVENT_ER | SSL_POLL_EVENT_EW;

    // SSL_STREAM constants
    public static final int SSL_STREAM_TYPE_READ = 1;
    public static final int SSL_STREAM_TYPE_WRITE = 2;
    public static final int SSL_STREAM_TYPE_BIDI = 3;

    public static final long SSL_STREAM_FLAG_UNI = 1L << 0;

    // SSL_accept_stream() flags (different from SSL_new_stream() flags)
    // OpenSSL ssl.h: SSL_ACCEPT_STREAM_UNI=2, SSL_ACCEPT_STREAM_BIDI=4.
    // The directional filter is OpenSSL 4.x-only: OpenSSL 3.5 defines only
    // SSL_ACCEPT_STREAM_NO_BLOCK and its ossl_quic_accept_stream() ignores
    // unknown flag bits, accepting the next pending stream of any direction.
    // Call sites must therefore route per-stream handling by the observed
    // SSL_get_stream_type(), not by the flag they passed.
    public static final long SSL_ACCEPT_STREAM_UNI = 2L;
    public static final long SSL_ACCEPT_STREAM_BIDI = 4L;

    // SSL_STREAM_STATE_* values from ssl.h; SSL_STREAM_STATE_NONE (0, the
    // "not a stream" sentinel) is never reported through the read/write
    // state getters and stays undefined.
    public static final int SSL_STREAM_STATE_OK = 1;
    public static final int SSL_STREAM_STATE_WRONG_DIR = 2;
    public static final int SSL_STREAM_STATE_FINISHED = 3;
    public static final int SSL_STREAM_STATE_RESET_LOCAL = 4;
    public static final int SSL_STREAM_STATE_RESET_REMOTE = 5;
    public static final int SSL_STREAM_STATE_CONN_CLOSED = 6;

    /**
     * Whether a stream write state means the write side is closed beyond any
     * recovery: reset (either direction) or the connection went away. A stream
     * in one of these states can never accept further bytes and never becomes
     * writable again.
     *
     * @param writeState A {@code SSL_get_stream_write_state()} value
     *
     * @return {@code true} for RESET_LOCAL, RESET_REMOTE or CONN_CLOSED
     */
    public static boolean isWriteStateClosed(int writeState) {
        return writeState == SSL_STREAM_STATE_RESET_LOCAL ||
                writeState == SSL_STREAM_STATE_RESET_REMOTE ||
                writeState == SSL_STREAM_STATE_CONN_CLOSED;
    }

    /**
     * Whether a stream write state is terminal for a write attempt: closed
     * (see {@link #isWriteStateClosed(int)}) or already FINISHED, which also
     * can never accept new bytes. Callers that treat a FINISHED stream
     * differently (for instance a retry that must not report a merely
     * concluded stream as failed) use {@link #isWriteStateClosed(int)}
     * instead.
     *
     * @param writeState A {@code SSL_get_stream_write_state()} value
     *
     * @return {@code true} for FINISHED plus the closed states
     */
    public static boolean isTerminalWriteState(int writeState) {
        return writeState == SSL_STREAM_STATE_FINISHED ||
                isWriteStateClosed(writeState);
    }

    // Struct layout definitions
    // BIO_POLL_DESCRIPTOR: uint32_t type + 4-byte padding + union{void* value} = 16 bytes
    // Use JAVA_INT as padding (4 bytes, 4-byte alignment) before ADDRESS (8-byte alignment)
    static final MemoryLayout BIO_POLL_DESCRIPTOR_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("type"),
            ValueLayout.JAVA_INT.withName("padding"),
            ValueLayout.ADDRESS.withName("value")
    ).withName("bio_poll_descriptor");

    // SSL_POLL_ITEM: BIO_POLL_DESCRIPTOR desc + uint64_t events + uint64_t revents = 32 bytes
    static final MemoryLayout SSL_POLL_ITEM_LAYOUT = MemoryLayout.structLayout(
            BIO_POLL_DESCRIPTOR_LAYOUT.withName("desc"),
            ValueLayout.JAVA_LONG.withName("events"),
            ValueLayout.JAVA_LONG.withName("revents")
    ).withName("ssl_poll_item");

    static final long SSL_POLL_ITEM_SIZE = SSL_POLL_ITEM_LAYOUT.byteSize();
    static final long STRIDE = (SSL_POLL_ITEM_SIZE % ValueLayout.ADDRESS.byteSize() != 0) ?
            ((SSL_POLL_ITEM_SIZE / ValueLayout.ADDRESS.byteSize() + 1) * ValueLayout.ADDRESS.byteSize()) :
            SSL_POLL_ITEM_SIZE;

    // Offsets within SSL_POLL_ITEM
    static final long DESC_TYPE_OFFSET =
            SSL_POLL_ITEM_LAYOUT.byteOffset(PathElement.groupElement("desc"), PathElement.groupElement("type"));
    static final long DESC_VALUE_OFFSET =
            SSL_POLL_ITEM_LAYOUT.byteOffset(PathElement.groupElement("desc"), PathElement.groupElement("value"));
    static final long EVENTS_OFFSET =
            SSL_POLL_ITEM_LAYOUT.byteOffset(PathElement.groupElement("events"));
    static final long REVENTS_OFFSET =
            SSL_POLL_ITEM_LAYOUT.byteOffset(PathElement.groupElement("revents"));

    // struct timeval - the single definition shared by every timeval site:
    // the SSL_poll() timeout built below and the SSL_get_event_timeout()
    // scratch the poll loop reads. time_t and suseconds_t are both 8 bytes on
    // the LP64 / _TIME_BITS=64 ABI that this Linux-only FFM endpoint targets.
    // A 32-bit or _TIME_BITS=32 build would need 4-byte fields here. The
    // offsets are derived from the layout so they stay consistent with the
    // field widths chosen below.
    static final MemoryLayout TIMEVAL_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.JAVA_LONG.withName("tv_sec"),
            ValueLayout.JAVA_LONG.withName("tv_usec"));
    static final long TV_SEC_OFFSET =
            TIMEVAL_LAYOUT.byteOffset(PathElement.groupElement("tv_sec"));
    static final long TV_USEC_OFFSET =
            TIMEVAL_LAYOUT.byteOffset(PathElement.groupElement("tv_usec"));

    /**
     * Invokes {@code SSL_poll()} on the given array of poll items.
     *
     * @param nativeArray The native array of SSL_POLL_ITEM structs
     * @param count       The number of items
     * @param timeoutMs   Timeout in milliseconds (0 = non-blocking, -1 = infinite)
     * @param flags       {@code SSL_POLL_*} flags, 0 or
     *                    {@link #SSL_POLL_FLAG_NO_HANDLE_EVENTS}
     * @param resultCount Output parameter for number of items with events
     *
     * @return Per {@code SSL_poll(3)} (OpenSSL 3.5+): return 1 with
     *         {@code resultCount == 0} means timeout; return 1 with
     *         {@code resultCount != 0} means events are available; return 0
     *         with {@code resultCount != 0} means at least one item has
     *         {@link #SSL_POLL_EVENT_F} (poll failure); return 0 with
     *         {@code resultCount == 0} indicates a basic usage error. There
     *         is no documented -1 return.
     */
    public static int poll(MemorySegment nativeArray, int count, long timeoutMs,
            long flags, MemorySegment resultCount) {
        // Build timeval on a confined arena; the native call copies the value before we return
        Arena localArena = Arena.ofConfined();
        MemorySegment timeoutPtr;
        if (timeoutMs < 0) {
            // Infinite timeout
            timeoutPtr = MemorySegment.NULL;
        } else {
            MemorySegment tv = localArena.allocate(TIMEVAL_LAYOUT);
            long secs = timeoutMs / 1000;
            long usecs = (timeoutMs % 1000) * 1000;
            tv.set(ValueLayout.JAVA_LONG, TV_SEC_OFFSET, secs);
            tv.set(ValueLayout.JAVA_LONG, TV_USEC_OFFSET, usecs);
            timeoutPtr = tv;
        }

        try {
            return QuicBindings.SSL_poll(
                    nativeArray,
                    (long) count,
                    STRIDE,
                    timeoutPtr,
                    flags,
                    resultCount);
        } finally {
            localArena.close();
        }
    }


    /**
     * Returns the byte size of a single SSL_POLL_ITEM struct.
     *
     * @return The struct size in bytes
     */
    public static long itemSize() {
        return SSL_POLL_ITEM_SIZE;
    }


    /**
     * Returns the aligned stride for an array of SSL_POLL_ITEM structs.
     *
     * @return The stride in bytes
     */
    public static long stride() {
        return STRIDE;
    }


    /**
     * Returns the byte offset of the revents field within the SSL_POLL_ITEM struct.
     * Used by {@link QuicPollSet} to sync revents from the native array.
     *
     * @return The revents field offset
     */
    public static long getReventsOffset() {
        return REVENTS_OFFSET;
    }
}

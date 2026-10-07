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
import java.lang.foreign.ValueLayout;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;


/**
 * Per-item state wrapper for one entry in the endpoint's {@code SSL_poll()}
 * set: the native {@code SSL_POLL_ITEM} struct and the want/revents
 * bookkeeping for a single listener, connection or stream.
 * <p>
 * The protocol constants, the native struct layout math and the
 * {@code SSL_poll()} driver are the binding-level building blocks and live in
 * {@link QuicPoll}; this class holds only per-item state.
 */
public class QuicPollItem {

    private static final Log log = LogFactory.getLog(QuicPollItem.class);
    private static final StringManager sm = StringManager.getManager(QuicPollItem.class);

    // SSL_as_poll_descriptor is an inline function; we construct the BIO_POLL_DESCRIPTOR directly
    // rather than calling the C inline.

    // ------------------------------------------ Instance fields

    /**
     * Native memory segment holding the SSL_POLL_ITEM struct.
     */
    private final MemorySegment segment;

    /**
     * Arena holding the native struct. Closed by {@link #dispose()} so the
     * struct memory is released as soon as the item leaves the poll set.
     * All access to this item (native struct and want_events) is confined
     * to the QUIC poll thread: worker-thread updates of interest are hopped
     * to the poll thread via submitPollTask(). The {@code arena != null}
     * checks guard only against a late-queued poll task touching an item
     * that has already been disposed.
     */
    private Arena arena;

    /**
     * The SSL* pointer associated with this poll item.
     */
    private MemorySegment ssl;

    /**
     * Slot (index in the poll set's native array) of this item while it is a
     * member of the set. Maintained by {@link QuicPollSet}.
     */
    private int slot;

    /**
     * Flag indicating the native struct changed (new item or updated
     * descriptor/events) and must be copied into the poll set's native array
     * by the next {@link QuicPollSet#rebuild()}.
     */
    private volatile boolean dirty;

    /**
     * Events we want to monitor. Read and written only on the endpoint's
     * poll thread: workers reach it through a submitted poll task (see
     * {@code QuicOpenSSLSocketWrapper.resumeInterest()}), so the read-
     * modify-write in setWantEvents() needs no synchronisation and the
     * field is deliberately not volatile - a cross-thread read is not
     * guaranteed to observe the latest mask and is acceptable only for
     * diagnostics.
     */
    private long wantEvents;

    /**
     * Events that occurred (set by SSL_poll).
     */
    private long revents;

    /**
     * Application data associated with this poll item.
     */
    private Object appData;


    /**
     * Creates a new poll item for the given SSL object. The native
     * {@code SSL_POLL_ITEM} struct is allocated on a private arena owned by
     * the item and released by {@link #dispose()} when the item leaves the
     * poll set.
     *
     * @param ssl    The SSL* pointer (listener, connection, or stream)
     * @param events The events to monitor
     * @param data   Application data associated with this item
     */
    public QuicPollItem(MemorySegment ssl, long events, Object data) {
        this.arena = Arena.ofShared();
        this.segment = arena.allocate(QuicPoll.SSL_POLL_ITEM_SIZE);
        this.ssl = ssl;
        this.wantEvents = events;
        this.revents = 0;
        this.appData = data;
        this.dirty = true;
        initDescriptor(ssl);
        segment.set(ValueLayout.JAVA_LONG, QuicPoll.EVENTS_OFFSET, events);
    }
    /**
     * Releases the native {@code SSL_POLL_ITEM} struct. Must only be called
     * once the item is no longer a member of the poll set (the poll set calls
     * this from its remove()/clear() paths). Safe to call more than once.
     */
    public void dispose() {
        Arena a = arena;
        if (a != null) {
            arena = null;
            try {
                a.close();
            } catch (Throwable t) {
                // The memory may already have been released; log for leak /
                // use-after-dispose diagnostics rather than swallowing silently.
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("quicPollItem.disposeError"), t);
                }
            }
        }
    }


    private void initDescriptor(MemorySegment ssl) {
        segment.set(ValueLayout.JAVA_INT, QuicPoll.DESC_TYPE_OFFSET, QuicPoll.BIO_POLL_DESCRIPTOR_TYPE_SSL);
        segment.set(ValueLayout.ADDRESS, QuicPoll.DESC_VALUE_OFFSET, ssl);
    }


    /**
     * Updates the SSL pointer in the native descriptor and marks the item
     * dirty so the next {@link QuicPollSet#rebuild()} re-copies the struct.
     *
     * @param ssl The new SSL* pointer
     */
    public void setSsl(MemorySegment ssl) {
        this.ssl = ssl;
        this.dirty = true;
        if (arena != null) {
            segment.set(ValueLayout.ADDRESS, QuicPoll.DESC_VALUE_OFFSET, ssl);
        }
    }


    /**
     * Updates the events to monitor and marks the item dirty so the next
     * {@link QuicPollSet#rebuild()} re-copies the struct.
     *
     * @param events The new event mask
     */
    public void setWantEvents(long events) {
        this.wantEvents = events;
        this.dirty = true;
        if (arena != null) {
            segment.set(ValueLayout.JAVA_LONG, QuicPoll.EVENTS_OFFSET, events);
        }
    }


    /**
     * Returns the slot (native array index) of this item within its poll
     * set. Maintained by {@link QuicPollSet}.
     *
     * @return The slot index
     */
    int getSlot() {
        return slot;
    }


    /**
     * Sets the slot (native array index) of this item within its poll set.
     *
     * @param slot The slot index
     */
    void setSlot(int slot) {
        this.slot = slot;
    }


    /**
     * Checks if the native struct must be (re-)copied into the poll set's
     * native array by the next {@link QuicPollSet#rebuild()}.
     *
     * @return {@code true} if the item is new or changed
     */
    boolean isDirty() {
        return dirty;
    }


    /**
     * Marks the item dirty so the next {@link QuicPollSet#rebuild()}
     * re-copies the struct.
     */
    void markDirty() {
        this.dirty = true;
    }


    /**
     * Clears the dirty flag after the struct has been copied into the poll
     * set's native array.
     */
    void clearDirty() {
        this.dirty = false;
    }


    /**
     * Returns the SSL* pointer for this poll item.
     *
     * @return The SSL* pointer
     */
    public MemorySegment getSsl() {
        return ssl;
    }


    /**
     * Returns the events we want to monitor.
     *
     * @return The want events mask
     */
    public long getWantEvents() {
        return wantEvents;
    }


    /**
     * Returns the events that occurred during the last SSL_poll call.
     *
     * @return The revents mask
     */
    public long getRevents() {
        return revents;
    }


    /**
     * Sets the revents field (used by QuicPollSet to sync from the native
     * array after SSL_poll returns). Only the Java field is updated:
     * SSL_poll() initialises the revents of every item in the native array
     * on each call, and {@link QuicPollSet#rebuild()} zeroes the struct's
     * revents field before copying the struct into the array.
     *
     * @param revents The revents value
     */
    public void setRevents(long revents) {
        this.revents = revents;
    }


    /**
     * Resets the revents field of the native struct before the next
     * SSL_poll call so stale event flags are not carried into the native
     * array.
     */
    public void resetRevents() {
        if (arena != null) {
            segment.set(ValueLayout.JAVA_LONG, QuicPoll.REVENTS_OFFSET, 0L);
        }
        this.revents = 0;
    }


    /**
     * Returns the application data associated with this poll item.
     *
     * @return The application data object
     */
    public Object getAppData() {
        return appData;
    }


    /**
     * Sets the application data associated with this poll item.
     *
     * @param data The application data object
     */
    public void setAppData(Object data) {
        this.appData = data;
    }


    /**
     * Returns the native memory segment for this poll item.
     *
     * @return The native SSL_POLL_ITEM segment
     */
    public MemorySegment getSegment() {
        return segment;
    }


    /**
     * Checks the poll failure flag (SSL_POLL_EVENT_F, OpenSSL 3.5+ / 4.0
     * {@code SSL_poll(3)}): SSL_poll() could not poll this item, returned 0
     * and zeroed the revents of every item after it in the array. The
     * endpoint evicts such items.
     *
     * @return {@code true} if SSL_POLL_EVENT_F is set
     */
    public boolean hasPollFailure() {
        return (revents & QuicPoll.SSL_POLL_EVENT_F) != 0;
    }


    /**
     * Checks if any error events occurred.
     *
     * @return {@code true} if an error event is set in revents
     */
    public boolean hasError() {
        return (revents & QuicPoll.SSL_POLL_EVENT_E) != 0;
    }


    /**
     * Checks if an incoming connection event occurred.
     *
     * @return {@code true} if SSL_POLL_EVENT_IC is set
     */
    public boolean hasIncomingConnection() {
        return (revents & QuicPoll.SSL_POLL_EVENT_IC) != 0;
    }


    /**
     * Checks if an incoming stream event occurred.
     *
     * @return {@code true} if SSL_POLL_EVENT_ISB or SSL_POLL_EVENT_ISU is set
     */
    public boolean hasIncomingStream() {
        return (revents & QuicPoll.SSL_POLL_EVENT_IS) != 0;
    }


    /**
     * Checks if an outgoing stream event occurred.
     *
     * @return {@code true} if SSL_POLL_EVENT_OSB or SSL_POLL_EVENT_OSU is set
     */
    public boolean hasOutgoingStream() {
        return (revents & QuicPoll.SSL_POLL_EVENT_OS) != 0;
    }


    /**
     * Checks if the stream is readable.
     *
     * @return {@code true} if SSL_POLL_EVENT_R is set
     */
    public boolean isReadable() {
        return (revents & QuicPoll.SSL_POLL_EVENT_R) != 0;
    }


    /**
     * Checks if the stream is writable.
     *
     * @return {@code true} if SSL_POLL_EVENT_W is set
     */
    public boolean isWritable() {
        return (revents & QuicPoll.SSL_POLL_EVENT_W) != 0;
    }


    /**
     * Checks if a connection close event occurred.
     *
     * @return {@code true} if SSL_POLL_EVENT_EC or SSL_POLL_EVENT_ECD is set
     */
    public boolean hasConnectionClose() {
        return (revents & (QuicPoll.SSL_POLL_EVENT_EC | QuicPoll.SSL_POLL_EVENT_ECD)) != 0;
    }



}

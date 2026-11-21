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

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;


/**
 * Per-item state wrapper for one entry in the endpoint's {@code SSL_poll()}
 * set. It represents one listener, connection or stream and holds that
 * item's want/revents bookkeeping; its {@code writeTo()} method materialises
 * the corresponding {@code SSL_POLL_ITEM} struct into the poll set's shared
 * native array (the item does not own a native struct itself).
 * <p>
 * The protocol constants, the native struct layout math and the
 * {@code SSL_poll()} driver are the binding-level building blocks and live in
 * {@link QuicPoll}; this class holds only per-item state.
 */
public class QuicPollItem {

    // SSL_as_poll_descriptor is an inline function; we construct the BIO_POLL_DESCRIPTOR directly
    // rather than calling the C inline.

    // ------------------------------------------ Instance fields

    /*
     * Deliberately no native SSL_POLL_ITEM allocation per item. A busy HTTP/3
     * connection can create one request stream per request, so an Arena plus a
     * native segment per stream made every accepted stream pay a SharedSession
     * acquire and native allocation (and a matching release on close) just to
     * describe one struct. The poll set has a contiguous native array already;
     * writePollItems() writes the struct for each selected item directly into
     * its compact-subset slot. All access to this item is confined to the QUIC
     * poll thread, as before.
     */

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
     * Whether this item has been disposed after leaving the poll set or
     * losing a duplicate-address add. Only a lifecycle marker: the native
     * struct is written on every poll pass while the item is selected, so no
     * pending-write state is needed.
     */
    private volatile boolean disposed;

    /**
     * Events we want to monitor. Read and written only on the endpoint's poll
     * thread: workers reach it through a submitted poll task (see
     * {@code QuicOpenSSLSocketWrapper.resumeInterest()}), so the
     * read-modify-write in setWantEvents() needs no synchronisation and the
     * field is deliberately not volatile. All call sites are poll-thread
     * confined; there is no cross-thread read of this field.
     */
    private long wantEvents;

    /**
     * Events that occurred (set by SSL_poll).
     */
    private long revents;

    /**
     * Whether this item is part of the current poll subset. Confined to the
     * poll thread and managed by {@link QuicPollSet#beginPoll()} /
     * {@link QuicPollSet#addPollItem(QuicPollItem)}.
     */
    private boolean pollActive;

    /**
     * Number of poll passes for which this stream item should remain in the
     * subset after its last event. A newly registered or connection-touched
     * stream can produce buffered read data on the next pass even though the
     * parent connection is no longer reported ready; the linger bounds that
     * follow-up without keeping quiescent streams polled forever.
     */
    private int pollLinger;

    /**
     * Application data associated with this poll item.
     */
    private Object appData;

    /**
     * One-shot notifier invoked when {@link #setWantEvents(long)} changes the
     * interest mask. The endpoint uses it to force the next poll pass even when
     * no packet, hop or timer would otherwise wake the loop. May be
     * {@code null} for standalone/test items.
     */
    private final Runnable interestChangeNotifier;


    /**
     * Creates a new poll item for the given SSL object. No native memory is
     * allocated here; {@link #writeTo(MemorySegment, long)} materialises the
     * struct into the poll set's native array when the item is selected.
     *
     * @param ssl    The SSL* pointer (listener, connection, or stream)
     * @param events The events to monitor
     * @param data   Application data associated with this item
     */
    public QuicPollItem(MemorySegment ssl, long events, Object data) {
        this(ssl, events, data, null);
    }


    /**
     * Creates a poll item with a notifier invoked whenever its interest mask
     * changes.
     *
     * @param ssl                   The SSL* pointer
     * @param events                The initial events mask
     * @param data                  Application data
     * @param interestChangeNotifier Notifier for interest changes, or
     *                              {@code null}
     */
    QuicPollItem(MemorySegment ssl, long events, Object data,
            Runnable interestChangeNotifier) {
        this.ssl = ssl;
        this.wantEvents = events;
        this.revents = 0;
        this.appData = data;
        this.interestChangeNotifier = interestChangeNotifier;
    }

    /**
     * Clears this item's lifecycle state when it leaves the poll set. The item
     * owns no native memory (see {@link #writeTo(MemorySegment, long)}); this
     * is the hook called by the poll set's remove()/clear() paths and is safe
     * to call more than once.
     */
    public void dispose() {
        disposed = true;
    }


    /**
     * Returns whether this item has been disposed by the poll set or by a
     * duplicate-address add.
     *
     * @return {@code true} if the item's lifecycle state was cleared
     */
    boolean isDisposed() {
        return disposed;
    }


    /**
     * Writes this item's SSL_POLL_ITEM struct into the poll set's native
     * array at the given byte offset, zeroing revents. Called by
     * {@link QuicPollSet#writePollItems()} for every selected item.
     *
     * @param array  The poll set's native array
     * @param offset Byte offset of this item's slot in the array
     */
    void writeTo(MemorySegment array, long offset) {
        array.set(ValueLayout.JAVA_INT, offset + QuicPoll.DESC_TYPE_OFFSET,
                QuicPoll.BIO_POLL_DESCRIPTOR_TYPE_SSL);
        array.set(ValueLayout.ADDRESS, offset + QuicPoll.DESC_VALUE_OFFSET, ssl);
        array.set(ValueLayout.JAVA_LONG, offset + QuicPoll.EVENTS_OFFSET,
                wantEvents);
        array.set(ValueLayout.JAVA_LONG, offset + QuicPoll.REVENTS_OFFSET, 0L);
    }


    /**
     * Updates the events to monitor. The next poll pass writes the new mask
     * into the native array through {@link QuicPollSet#writePollItems()}.
     *
     * @param events The new event mask
     */
    public void setWantEvents(long events) {
        this.wantEvents = events;
        if (interestChangeNotifier != null) {
            interestChangeNotifier.run();
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
     * Reports whether this item belongs to the current poll subset.
     *
     * @return {@code true} if the item is in the current poll subset
     */
    boolean isPollActive() {
        return pollActive;
    }


    /**
     * Sets whether this item belongs to the current poll subset.
     *
     * @param pollActive The new poll subset state
     */
    void setPollActive(boolean pollActive) {
        this.pollActive = pollActive;
    }


    /**
     * Returns the remaining linger passes for this stream item.
     *
     * @return The linger count; zero for non-lingering items
     */
    int getPollLinger() {
        return pollLinger;
    }


    /**
     * Sets the remaining linger passes for this stream item.
     *
     * @param pollLinger The linger count
     */
    void setPollLinger(int pollLinger) {
        this.pollLinger = pollLinger;
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
     * Sets the revents field (used by QuicPollSet.syncPollRevents() to copy
     * from the native array after SSL_poll returns). Only the Java field is
     * updated: SSL_poll() initialises the revents of every item in the
     * native array on each call.
     *
     * @param revents The revents value
     */
    public void setRevents(long revents) {
        this.revents = revents;
    }


    /**
     * Resets the revents field before the next SSL_poll call so stale event
     * flags are not carried into the native array. The array's revents field
     * is zeroed by {@link #writeTo(MemorySegment, long)} when the item is
     * written into the compact poll subset.
     */
    public void resetRevents() {
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
     * Checks the error events that form OpenSSL's {@code SSL_POLL_EVENT_E}
     * macro: listener error, connection close, stream read error and stream
     * write error. Connection-closed ({@code SSL_POLL_EVENT_ECD}) is reported
     * separately by {@link #hasConnectionClose()} and poll failure
     * ({@code SSL_POLL_EVENT_F}) by {@link #hasPollFailure()}; the mask here
     * intentionally mirrors OpenSSL's macro. Used only for trace formatting.
     *
     * @return {@code true} if an {@code SSL_POLL_EVENT_E} error event is set
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

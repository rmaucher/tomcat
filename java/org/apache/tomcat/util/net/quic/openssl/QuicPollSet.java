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
import java.util.concurrent.ConcurrentHashMap;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;

/**
 * Manages a dynamic set of {@link QuicPollItem} instances for use with
 * {@code SSL_poll()}. The poll set grows and shrinks as connections and
 * streams are added and removed.
 * <p>
 * This class maintains two representations of each poll item:
 * <ul>
 * <li>A Java {@link QuicPollItem} object tracked in a concurrent map keyed
 *     by the SSL pointer address</li>
 * <li>An {@code SSL_POLL_ITEM} struct in a contiguous native array passed
 *     to {@code SSL_poll()}</li>
 * </ul>
 * Each member occupies a slot (index) in the array while it is in the set.
 * Active members always occupy slots {@code 0} to {@code count - 1}. On
 * removal, the member at the last used slot is swapped into the vacated
 * slot, so both add and remove are O(1) and {@code SSL_poll()} always
 * receives a contiguous array of the active members.
 * <p>
 * The native array is kept on a dedicated {@link Arena} per generation:
 * when the set outgrows the current capacity a larger array is allocated on
 * a fresh arena and the previous arena is closed, so no superseded array is
 * retained. Each item's own struct is released by
 * {@link QuicPollItem#dispose()} when the item leaves the set.
 * <p>
 * Copies into the native array are incremental: an item's struct is copied
 * by {@link #rebuild()} only when the item is new or its descriptor/events
 * changed since the previous rebuild (per-item dirty flag, see
 * {@link QuicPollItem#setWantEvents(long)} and
 * {@link QuicPollItem#setSsl(MemorySegment)}). Per SSL_poll(3) (OpenSSL
 * 3.5+), SSL_poll() initialises the revents of all items in the input array
 * upon returning, so no other per-iteration maintenance of the array is
 * required. After {@code SSL_poll()} returns, revents are read back from
 * the array slot by slot via {@link #syncRevents()}.
 * <p>
 * All mutation of this class (add, remove, clear and the want_events
 * updates made through the items) happens on the QUIC poll thread:
 * {@code bind()} adds the listener item before the poll thread starts,
 * worker threads hop poll-set mutations to the poll thread, and
 * {@code stopInternal()} clears and closes the set only after the poll
 * thread has stopped. No internal locking is performed.
 */
public class QuicPollSet {

    private static final Log log = LogFactory.getLog(QuicPollSet.class);
    private static final StringManager sm = StringManager.getManager(QuicPollSet.class);

    private static final int INITIAL_CAPACITY = 64;
    private static final int GROWTH_INCREMENT = 32;

    private static final long ITEM_SIZE = QuicPoll.itemSize();
    private static final long STRIDE = QuicPoll.stride();

    /**
     * Arena holding the current native poll array. Replaced (and the
     * previous arena closed) each time the array grows.
     */
    private Arena arrayArena;

    /**
     * Native array of SSL_POLL_ITEM structs.
     */
    private MemorySegment nativeArray;

    /**
     * Current allocated capacity of the native array.
     */
    private int capacity;

    /**
     * Current number of active items. Active items always occupy slots
     * 0 to count-1.
     */
    private int count;

    /**
     * Map from SSL pointer address to QuicPollItem for O(1) lookup.
     */
    private final ConcurrentHashMap<Long, QuicPollItem> items = new ConcurrentHashMap<>();

    /**
     * Active items by slot. While the set has count members,
     * slots[0..count-1] are the current members; the remaining slots are
     * unused.
     */
    private QuicPollItem[] slots;

    /**
     * Arena for the result_count value passed to SSL_poll.
     */
    private final Arena resultCountArena;

    /**
     * Segment that holds the result_count value for SSL_poll.
     */
    private final MemorySegment resultCountSegment;


    /**
     * Creates a new poll set.
     */
    public QuicPollSet() {
        this.capacity = INITIAL_CAPACITY;
        this.count = 0;
        this.arrayArena = Arena.ofShared();
        this.nativeArray = arrayArena.allocate(ITEM_SIZE * capacity);
        this.slots = new QuicPollItem[capacity];
        this.resultCountArena = Arena.ofShared();
        this.resultCountSegment = resultCountArena.allocate(ValueLayout.JAVA_LONG);
    }


    /**
     * Adds a poll item to the set.
     *
     * @param item The poll item to add
     */
    public void add(QuicPollItem item) {
        long key = item.getSsl().address();
        QuicPollItem previous = items.putIfAbsent(key, item);
        if (previous != null) {
            // Already present - update in place. The passed-in item is not
            // used; release its native struct.
            // This path must not be taken for a live stream item: the
            // want-events mask is managed cooperatively by the endpoint
            // (dispatchStreamEvent strips R/W, the processor re-arms them), so
            // overwriting it with a freshly-constructed mask loses the current
            // interest, and disposing the caller's item leaves it with a null
            // arena so its later setWantEvents() calls silently no-op. No call
            // site is expected to re-add a tracked address, but the add is
            // still interpreted below (the previous item is updated in place),
            // so a regression on this path would not fail loudly - the warning
            // is the only signal that it happened.
            log.warn(sm.getString("quicPollSet.duplicateAdd",
                    Long.toHexString(key)));
            previous.setSsl(item.getSsl());
            previous.setWantEvents(item.getWantEvents());
            previous.setAppData(item.getAppData());
            item.dispose();
            return;
        }
        if (count == capacity) {
            grow();
        }
        slots[count] = item;
        item.setSlot(count);
        count++;
        item.markDirty();
    }


    /**
     * Removes a poll item by SSL pointer address. The item's native struct
     * is released.
     *
     * @param sslAddr The SSL pointer address
     *
     * @return The removed item, or {@code null} if not found
     */
    public QuicPollItem remove(long sslAddr) {
        QuicPollItem removed = items.remove(sslAddr);
        if (removed == null) {
            return null;
        }
        int slot = removed.getSlot();
        count--;
        if (slot < count) {
            QuicPollItem last = slots[count];
            slots[slot] = last;
            last.setSlot(slot);
            last.markDirty();
        }
        slots[count] = null;
        removed.dispose();
        return removed;
    }


    /**
     * Returns the poll item for the given SSL pointer address.
     *
     * @param sslAddr The SSL pointer address
     *
     * @return The poll item, or {@code null} if not found
     */
    public QuicPollItem get(long sslAddr) {
        return items.get(sslAddr);
    }


    /**
     * Returns the active item in the given slot. Valid for indices 0 to
     * {@link #size()} - 1.
     *
     * @param index The slot index
     *
     * @return The item in that slot
     */
    public QuicPollItem itemAt(int index) {
        if (index < 0 || index >= count) {
            // Fail loudly: the slots array is capacity-sized and may hold
            // trailing null slots, so an out-of-range (e.g. off-by-one) index
            // would otherwise return null rather than signal the bug.
            throw new IndexOutOfBoundsException(
                    "Index " + index + " out of bounds for poll set size " + count);
        }
        return slots[index];
    }


    /**
     * Copies the structs of new or changed items into the native array.
     * Must be called on the poll thread before every SSL_poll() call.
     * <p>
     * Per SSL_poll(3) (OpenSSL 3.5+), SSL_poll() initialises the revents
     * fields of all items in the input array upon returning, so only items
     * whose descriptor or events changed since the previous rebuild need
     * to be copied. The revents field of a copied struct is zeroed first
     * as a defence against stale event flags being handed to SSL_poll().
     */
    public void rebuild() {
        for (int i = 0; i < count; i++) {
            QuicPollItem item = slots[i];
            if (item.isDirty()) {
                item.resetRevents();
                MemorySegment.copy(item.getSegment(), 0, nativeArray,
                        (long) i * STRIDE, ITEM_SIZE);
                item.clearDirty();
            }
        }
    }


    /**
     * Syncs revents from the native array back to each item after
     * {@code SSL_poll()} returns. This must be called after a successful
     * poll and before processing events.
     * <p>
     * The native array index maps 1:1 to the items, so revents are mapped
     * directly to the items without any re-derivation of order.
     */
    public void syncRevents() {
        long reventsOffset = QuicPoll.getReventsOffset();
        for (int i = 0; i < count; i++) {
            QuicPollItem item = slots[i];
            long revents = nativeArray.get(ValueLayout.JAVA_LONG,
                    (long) i * STRIDE + reventsOffset);
            item.setRevents(revents);
        }
    }


    /**
     * Returns the number of active poll items.
     *
     * @return The item count
     */
    public int size() {
        return count;
    }



    /**
     * Returns the native array segment for passing to {@code SSL_poll()}.
     *
     * @return The native array
     */
    public MemorySegment getNativeArray() {
        return nativeArray;
    }


    /**
     * Returns the result count segment for {@code SSL_poll()}.
     *
     * @return The result count segment
     */
    public MemorySegment getResultCountSegment() {
        return resultCountSegment;
    }


    /**
     * Returns the number of items that had events after the last poll.
     *
     * @return The result count
     */
    public long getResultCount() {
        return resultCountSegment.get(ValueLayout.JAVA_LONG, 0);
    }


    /**
     * Resets the result count before the next poll.
     */
    public void resetResultCount() {
        resultCountSegment.set(ValueLayout.JAVA_LONG, 0, 0L);
    }


    /**
     * Removes all items from the poll set and releases their native
     * structs.
     */
    public void clear() {
        for (int i = 0; i < count; i++) {
            slots[i].dispose();
            slots[i] = null;
        }
        count = 0;
        items.clear();
    }


    /**
     * Releases the native resources held by this poll set (the native array
     * and the result_count segment). Call after the last SSL_poll() and
     * after {@link #clear()}.
     */
    public void close() {
        try {
            arrayArena.close();
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicPollSet.closeArenaError", "native array"), t);
            }
        }
        try {
            resultCountArena.close();
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicPollSet.closeArenaError", "result_count"), t);
            }
        }
    }


    /**
     * Grows the native array. The new array starts zeroed, so every active
     * item is marked dirty to force a re-copy on the next rebuild. The
     * previous array's arena is closed once the new array is in place.
     */
    private void grow() {
        int newCapacity = capacity + GROWTH_INCREMENT;
        Arena oldArena = arrayArena;
        arrayArena = Arena.ofShared();
        nativeArray = arrayArena.allocate(ITEM_SIZE * newCapacity);
        capacity = newCapacity;
        QuicPollItem[] newSlots = new QuicPollItem[capacity];
        System.arraycopy(slots, 0, newSlots, 0, count);
        slots = newSlots;
        for (int i = 0; i < count; i++) {
            slots[i].markDirty();
        }
        oldArena.close();
    }
}

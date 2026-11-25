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
import org.apache.tomcat.util.ExceptionUtils;
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
 * slot, so remove is O(1) and {@code SSL_poll()} always receives a
 * contiguous array of the active members. Add is amortized O(1): capacity
 * doubles on growth and halves when the set falls to a quarter of its
 * capacity, with the native array and slots array reallocated together.
 * <p>
 * The native array is kept on a dedicated {@link Arena} per generation:
 * when the set outgrows the current capacity a larger array is allocated on
 * a fresh arena and the previous arena is closed, so no superseded array is
 * retained. An item owns no native struct of its own: the poll loop's compact
 * subset is materialised into this array by {@link #writePollItems()} at the
 * start of every poll pass.
 * <p>
 * Per SSL_poll(3) (OpenSSL 3.5+), SSL_poll() initialises the revents of all
 * items in the input array upon returning, so no other per-iteration
 * maintenance of the array is required. After {@code SSL_poll()} returns,
 * revents are read back from the compact subset slots via
 * {@link #syncPollRevents()}.
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

    private static final long STRIDE = QuicPoll.stride();
    private static final QuicPlatformSupport.Abi ABI =
            QuicPlatformSupport.get().abi();

    /**
     * Arena holding the current native poll array. Replaced (and the
     * previous arena closed) whenever the array is resized, including on
     * growth and on the shrink path.
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
     * Set when the membership or order of the poll set changed since the last
     * {@link #consumeChanged()} call. The poll loop uses this one-shot flag to
     * force an engine tick and an {@code SSL_poll()} pass, because a slot
     * added by a handler after the previous poll may already be readable and
     * the normal tick-skip shortcut would not otherwise test it.
     */
    private boolean changed;

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
     * Items selected for the current poll pass. This is a compact subset of
     * the set and is rewritten into the beginning of the native array before
     * each {@code SSL_poll()} call. Poll-thread confined.
     */
    private QuicPollItem[] pollItems;

    /**
     * Number of items selected for the current poll pass.
     */
    private int pollCount;

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
        Arena arrayArenaLocal = Arena.ofShared();
        Arena resultCountArenaLocal = null;
        MemorySegment nativeArrayLocal = null;
        MemorySegment resultCountSegmentLocal = null;
        try {
            nativeArrayLocal = arrayArenaLocal.allocate(STRIDE * capacity);
            slots = new QuicPollItem[capacity];
            pollItems = new QuicPollItem[capacity];
            resultCountArenaLocal = Arena.ofShared();
            resultCountSegmentLocal = resultCountArenaLocal.allocate(ABI.sizeT());
        } catch (RuntimeException | Error e) {
            // An allocation failure after the shared arenas were created must
            // not leak the native memory they own. Close every arena that was
            // successfully created before rethrowing.
            closeQuietly(resultCountArenaLocal);
            closeQuietly(arrayArenaLocal);
            throw e;
        }
        this.arrayArena = arrayArenaLocal;
        this.nativeArray = nativeArrayLocal;
        this.resultCountArena = resultCountArenaLocal;
        this.resultCountSegment = resultCountSegmentLocal;
    }


    /**
     * Closes an arena while constructing or resizing, ignoring a close
     * failure: the original allocation error is the one that must propagate.
     *
     * @param arena The arena to close (may be {@code null})
     */
    private static void closeQuietly(Arena arena) {
        if (arena != null) {
            try {
                arena.close();
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                // Ignore - the allocation failure is the reportable error
            }
        }
    }


    /**
     * Adds a poll item to the set.
     *
     * @param item The poll item to add
     */
    public void add(QuicPollItem item) {
        if (item == null || item.isDisposed()) {
            return;
        }
        long key = item.getSsl().address();
        QuicPollItem previous = items.get(key);
        if (previous != null) {
            handleDuplicateAdd(item, previous);
            return;
        }
        if (count == capacity) {
            grow();
        }
        // Publish the item only after capacity growth succeeded, so an
        // allocation failure cannot leave the map referencing an item that
        // was never placed in the slots/native array.
        previous = items.putIfAbsent(key, item);
        if (previous != null) {
            handleDuplicateAdd(item, previous);
            return;
        }
        slots[count] = item;
        item.setSlot(count);
        count++;
        changed = true;
    }


    /**
     * Handles an address that is already tracked in the set. Re-adding a
     * tracked address is not supported: the existing item's want-events mask
     * is managed cooperatively by the endpoint (dispatchStreamEvent strips
     * R/W, the processor re-arms them). Overwriting that mask with the fresh
     * item's initial mask loses the current interest, and disposing the
     * caller's item can make its later setWantEvents() calls ineffective.
     * Report the regression and keep the existing item unchanged; re-adding
     * the same item itself still marks the set changed so the next poll pass
     * observes a want-events update made just before the call.
     *
     * @param item     The item being added
     * @param previous The item already tracked for the same SSL address
     */
    private void handleDuplicateAdd(QuicPollItem item, QuicPollItem previous) {
        log.warn(sm.getString("quicPollSet.duplicateAdd",
                Long.toHexString(item.getSsl().address())));
        if (previous != item) {
            item.dispose();
        } else {
            changed = true;
        }
    }


    /**
     * Removes a poll item by SSL pointer address. The item owns no native
     * memory; {@link QuicPollItem#dispose()} is still called as the lifecycle
     * hook.
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
        }
        slots[count] = null;
        removed.dispose();
        changed = true;
        if (capacity > INITIAL_CAPACITY && count <= capacity / 4) {
            shrink();
        }
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
     * Starts a new poll-subset pass. Clears the previous subset's membership
     * flags; the caller then selects items with {@link #addPollItem} and
     * writes the subset with {@link #writePollItems()}.
     */
    public void beginPoll() {
        for (int i = 0; i < pollCount; i++) {
            pollItems[i].setPollActive(false);
            // Drop the reference as well as the flag. A shrinking subset must
            // not keep removed/freed wrappers and their read buffers reachable
            // through the unused tail of the array.
            pollItems[i] = null;
        }
        pollCount = 0;
    }


    /**
     * Adds an item to the current poll subset. Duplicate additions are
     * ignored. The item must be a member of this set.
     *
     * @param item The item to poll
     */
    public void addPollItem(QuicPollItem item) {
        if (item == null || item.isDisposed() || item.isPollActive()) {
            return;
        }
        if (items.get(item.getSsl().address()) != item) {
            // The doc requires a member. Enforcing it also keeps pollCount
            // bounded by the membership capacity, so writePollItems() cannot
            // address beyond the native array.
            throw new IllegalArgumentException(
                    "Poll item is not a member of this set");
        }
        if (pollCount == pollItems.length) {
            // The set can grow during an iteration; preserve the subset that
            // was already selected.
            QuicPollItem[] newPollItems =
                    new QuicPollItem[Math.max(pollItems.length * 2, pollCount + 1)];
            System.arraycopy(pollItems, 0, newPollItems, 0, pollCount);
            pollItems = newPollItems;
        }
        pollItems[pollCount] = item;
        pollCount++;
        item.setPollActive(true);
    }


    /**
     * Returns the number of items in the current poll subset.
     *
     * @return The poll subset size
     */
    public int getPollCount() {
        return pollCount;
    }


    /**
     * Returns an item in the current poll subset.
     *
     * @param index The poll-subset index
     * @return The item
     */
    public QuicPollItem pollItemAt(int index) {
        if (index < 0 || index >= pollCount) {
            throw new IndexOutOfBoundsException(
                    "Index " + index + " out of bounds for poll subset size " + pollCount);
        }
        return pollItems[index];
    }


    /**
     * Copies the current poll subset's structs into the beginning of the
     * native array. Every selected item is written because its slot in the
     * native array no longer matches its membership slot.
     */
    public void writePollItems() {
        for (int i = 0; i < pollCount; i++) {
            QuicPollItem item = pollItems[i];
            item.resetRevents();
            item.writeTo(nativeArray, (long) i * STRIDE);
        }
    }


    /**
     * Syncs revents for the current poll subset from the beginning of the
     * native array after {@code SSL_poll()} returns.
     */
    public void syncPollRevents() {
        long reventsOffset = QuicPoll.getReventsOffset();
        for (int i = 0; i < pollCount; i++) {
            long revents = nativeArray.get(ValueLayout.JAVA_LONG,
                    (long) i * STRIDE + reventsOffset);
            pollItems[i].setRevents(revents);
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
     * Returns and clears the one-shot “membership/order changed” flag. The
     * poll loop calls this before deciding whether it may skip a tick and
     * {@code SSL_poll()} iteration.
     *
     * @return {@code true} if the set changed since the previous call
     */
    public boolean consumeChanged() {
        boolean result = changed;
        changed = false;
        return result;
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
        return ABI.getSizeT(resultCountSegment, 0);
    }


    /**
     * Resets the result count before the next poll.
     */
    public void resetResultCount() {
        ABI.setSizeT(resultCountSegment, 0, 0L);
    }


    /**
     * Removes all items from the poll set, clearing their Java state and the
     * lookup map.
     */
    public void clear() {
        for (int i = 0; i < pollCount; i++) {
            pollItems[i].setPollActive(false);
            // Release the references so a stopped endpoint does not retain
            // wrappers, streams and read buffers through the poll subset array.
            pollItems[i] = null;
        }
        pollCount = 0;
        for (int i = 0; i < count; i++) {
            slots[i].dispose();
            slots[i] = null;
        }
        count = 0;
        items.clear();
        changed = true;
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
            ExceptionUtils.handleThrowable(t);
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicPollSet.closeArenaError", "native array"), t);
            }
        }
        try {
            resultCountArena.close();
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicPollSet.closeArenaError", "result_count"), t);
            }
        }
    }


    /**
     * Doubles the array capacity.
     */
    private void grow() {
        int newCapacity = capacity > Integer.MAX_VALUE / 2
                ? Integer.MAX_VALUE : capacity * 2;
        if (newCapacity > capacity) {
            resize(newCapacity);
        }
    }


    /**
     * Halves the array capacity, not below the initial capacity.
     */
    private void shrink() {
        int newCapacity = Math.max(INITIAL_CAPACITY, capacity / 2);
        if (newCapacity < capacity) {
            resize(newCapacity);
        }
    }


    /**
     * Replaces the native and Java arrays with new arrays of the given
     * capacity. The new native array starts zeroed; writePollItems() writes
     * every selected item into it at the start of the next poll pass, so no
     * per-item re-copy marker is needed. The previous array's arena is closed
     * once the new state is in place; a failed allocation leaves the old
     * generation untouched.
     */
    private void resize(int newCapacity) {
        Arena oldArena = arrayArena;
        Arena newArena = Arena.ofShared();
        MemorySegment newArray;
        QuicPollItem[] newSlots;
        QuicPollItem[] newPollItems;
        int allocItems = Math.max(newCapacity, pollCount);
        try {
            newArray = newArena.allocate(STRIDE * allocItems);
            newSlots = new QuicPollItem[newCapacity];
            // A shrink during event handling can happen while the current
            // poll subset still references more items than the new capacity.
            newPollItems = new QuicPollItem[allocItems];
        } catch (Throwable t) {
            // Do not leave the new arena open or replace the current array
            // when the allocation failed; keep the old generation intact.
            try {
                newArena.close();
            } catch (Throwable closeFailure) {
                ExceptionUtils.handleThrowable(closeFailure);
                // Ignore - the original allocation failure is more useful.
            }
            throw t;
        }
        arrayArena = newArena;
        nativeArray = newArray;
        capacity = newCapacity;
        System.arraycopy(slots, 0, newSlots, 0, count);
        System.arraycopy(pollItems, 0, newPollItems, 0, pollCount);
        slots = newSlots;
        pollItems = newPollItems;
        try {
            oldArena.close();
        } catch (Throwable t) {
            ExceptionUtils.handleThrowable(t);
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("quicPollSet.closeArenaError", "old native array"), t);
            }
        }
    }
}

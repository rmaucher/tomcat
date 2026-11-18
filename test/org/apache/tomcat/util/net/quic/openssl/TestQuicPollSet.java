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

import java.lang.reflect.Constructor;

import org.junit.Assert;
import org.junit.Test;


/**
 * Tests for {@link QuicPollSet}'s slot management, growth and duplicate-add
 * behavior. Item creation uses reflection only because the test compilation
 * pass does not enable the foreign-memory preview API used by the main code.
 */
public class TestQuicPollSet {

    private static final long FIRST_ADDRESS = 0x10000L;
    private static final long EVENT_MASK =
            QuicPoll.SSL_POLL_EVENT_R | QuicPoll.SSL_POLL_EVENT_W;


    /**
     * Creates a poll item for a fake SSL address.
     *
     * @param address The fake SSL pointer address
     * @param data    The application data
     *
     * @return The poll item
     *
     * @throws Exception If reflection fails
     */
    private static QuicPollItem item(long address, Object data)
            throws Exception {
        Class<?> memorySegmentClass = Class.forName(
                "java.lang.foreign.MemorySegment");
        Object segment = memorySegmentClass.getMethod("ofAddress", long.class)
                .invoke(null, Long.valueOf(address));
        Constructor<QuicPollItem> constructor =
                QuicPollItem.class.getDeclaredConstructor(
                        memorySegmentClass, long.class, Object.class);
        return constructor.newInstance(segment, Long.valueOf(EVENT_MASK), data);
    }


    @Test
    public void testAddGrowAndSlotSwap() throws Exception {
        QuicPollSet set = new QuicPollSet();
        try {
            for (int i = 0; i < 65; i++) {
                set.add(item(FIRST_ADDRESS + i, Integer.valueOf(i)));
            }
            Assert.assertEquals(65, set.size());
            Assert.assertEquals(Integer.valueOf(64),
                    set.itemAt(64).getAppData());

            QuicPollItem removed = set.remove(FIRST_ADDRESS + 10);
            Assert.assertNotNull(removed);
            Assert.assertEquals(64, set.size());
            // The last item is swapped into the removed slot.
            Assert.assertEquals(Integer.valueOf(64),
                    set.itemAt(10).getAppData());
            Assert.assertNull(set.get(FIRST_ADDRESS + 10));

            QuicPollItem appended = item(FIRST_ADDRESS + 100,
                    Integer.valueOf(100));
            set.add(appended);
            Assert.assertSame(appended, set.itemAt(64));
            Assert.assertSame(appended, set.get(FIRST_ADDRESS + 100));
        } finally {
            set.clear();
            set.close();
        }
    }


    @Test
    public void testMoveToEnd() throws Exception {
        QuicPollSet set = new QuicPollSet();
        try {
            QuicPollItem first = item(FIRST_ADDRESS, Integer.valueOf(0));
            QuicPollItem second = item(FIRST_ADDRESS + 1, Integer.valueOf(1));
            set.add(first);
            set.add(second);

            set.moveToEnd(first);
            Assert.assertSame(second, set.itemAt(0));
            Assert.assertSame(first, set.itemAt(1));

            // Moving the already-last item is a no-op.
            set.moveToEnd(first);
            Assert.assertSame(first, set.itemAt(1));
        } finally {
            set.clear();
            set.close();
        }
    }


    @Test
    public void testDuplicateAddressKeepsExistingItem() throws Exception {
        QuicPollSet set = new QuicPollSet();
        try {
            QuicPollItem first = item(FIRST_ADDRESS, Integer.valueOf(0));
            QuicPollItem duplicate = item(FIRST_ADDRESS, Integer.valueOf(1));

            set.add(first);
            set.add(duplicate);

            Assert.assertEquals(1, set.size());
            Assert.assertSame(first, set.get(FIRST_ADDRESS));
            Assert.assertSame(first, set.itemAt(0));
            // The discarded item is disposed by the duplicate-add path.
            Assert.assertFalse(duplicate.isDirty());
        } finally {
            set.clear();
            set.close();
        }
    }


    @Test
    public void testClear() throws Exception {
        QuicPollSet set = new QuicPollSet();
        try {
            set.add(item(FIRST_ADDRESS, Integer.valueOf(0)));
            set.add(item(FIRST_ADDRESS + 1, Integer.valueOf(1)));
            set.clear();
            Assert.assertEquals(0, set.size());
            Assert.assertNull(set.get(FIRST_ADDRESS));
        } finally {
            set.clear();
            set.close();
        }
    }
}

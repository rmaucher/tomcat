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

import java.net.InetAddress;
import java.nio.ByteOrder;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;


/**
 * Tests for the Linux platform abstraction. These tests exercise the native
 * socket/wake-up layer directly; they skip cleanly when it is unavailable.
 */
public class TestQuicPlatformSupport {


    @Test
    public void testUnavailablePlatform() {
        QuicPlatformSupport platform = QuicPlatformSupport.selectForTest("unavailable");
        Assert.assertFalse(platform.isAvailable());
        Assert.assertNotNull(platform.unavailableReason());
        Assert.assertNotNull(platform.abi());
        Assert.assertFalse(platform.abi().isSupported());
    }


    @Test
    public void testLinuxAbi() {
        QuicPlatformSupport platform = QuicPlatformSupport.selectForTest("linux");
        Assume.assumeTrue(platform.isAvailable());
        QuicPlatformSupport.Abi abi = platform.abi();
        Assert.assertTrue(abi.isSupported());
        Assert.assertEquals(8L, abi.sizeTBytes());
        Assert.assertEquals(16L, abi.timeval().byteSize());
        Assert.assertEquals(8L, abi.pollFd().byteSize());
        Assert.assertEquals(32L, abi.sslPollItemStride());
        Assert.assertEquals(0L, abi.tvSecOffset());
        Assert.assertEquals(8L, abi.tvUsecOffset());
        Assert.assertEquals(0L, abi.descTypeOffset());
        Assert.assertEquals(8L, abi.descValueOffset());
        Assert.assertEquals(16L, abi.eventsOffset());
        Assert.assertEquals(24L, abi.reventsOffset());
    }


    @Test
    public void testAddressFamiliesAndPortDecode() {
        QuicPlatformSupport platform = QuicPlatformSupport.selectForTest("linux");
        Assume.assumeTrue(platform.isAvailable());
        Assert.assertTrue(platform.isIPv4Family(2));
        Assert.assertFalse(platform.isIPv4Family(10));
        Assert.assertTrue(platform.isIPv6Family(10));
        Assert.assertFalse(platform.isIPv6Family(2));
        if (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN) {
            Assert.assertEquals(0x1234, platform.decodePeerPort(0x3412));
        }
    }


    @Test
    public void testBindAndWakeup() throws Exception {
        QuicPlatformSupport platform = QuicPlatformSupport.selectForTest("linux");
        Assume.assumeTrue(platform.isAvailable());
        QuicPlatformSupport.BoundUdpSocket bound = platform.bindUdpSocket(
                InetAddress.getByName("127.0.0.1"), 0,
                new QuicPlatformSupport.UdpSocketOptions(0, 0, false));
        Assert.assertNotNull(bound);
        Assert.assertTrue(bound.boundPort() > 0);
        QuicPlatformSupport.Wakeup wakeup = platform.createWakeup(bound.socket());
        try {
            Assert.assertEquals(0, wakeup.await(0));
            wakeup.kick();
            int events = wakeup.await(1000);
            Assert.assertTrue((events & QuicPlatformSupport.Wakeup.EVENT_WAKE) != 0);
            wakeup.consume();
        } finally {
            wakeup.close();
            // Close twice to verify the handle's idempotent close contract.
            platform.close(bound.socket());
            platform.close(bound.socket());
        }
    }
}

/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http3;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

/**
 * Exercises the quiche endpoint's cmsg-gated UDP GRO receive split.
 *
 * <p>The split fires only on a read that arrives coalesced WITH the
 * segment-size cmsg. On the loopback hosts this endpoint is developed and
 * benchmarked on, separate datagrams never coalesce - ordinary suite and
 * benchmark traffic (however bursty) hands the endpoint only single-packet
 * reads - so the split path is otherwise unreachable from a test. The only
 * shape that produces a coalesced read here is a sender's own UDP_SEGMENT
 * (GSO) batch, which a {@code UDP_GRO}-enabled socket receives as one read
 * carrying the cmsg. This test injects exactly such a batch at the bound
 * port: {@code GSO_MAX_BATCH} equal-size short-header packets with an
 * unknown connection ID, which the endpoint must split back into datagrams
 * and demux-drop one by one, leaving serving untouched.</p>
 *
 * <p>The burst is built through the endpoint's own downcall wrappers
 * ({@code socket}, {@code fillSockaddr}, {@code sendSegmentedDatagram})
 * reached reflectively: the bindings live in the FFM compilation pass, a
 * release the test compilation cannot reference directly (the same
 * constraint that keeps the OpenSSL Panama tests reflective). Reusing the
 * wrappers rather than re-implementing sendmsg against
 * {@code java.lang.foreign} also keeps the injection byte-compatible with
 * the production GSO path by construction.</p>
 */
public class TestQuicGroSplit extends Http3TestBase {

    private static final String QUICHE_BINDINGS_CLASS =
            "org.apache.tomcat.util.net.quic.quiche.QuicheBindings";

    /*
     * Linux socket ABI constants (the values the bindings' package-private
     * equivalents hold; these are ABI, not tunables).
     */
    private static final int AF_INET = 2;
    private static final int AF_INET6 = 10;
    private static final int SOCK_DGRAM = 2;

    /*
     * Segment shape: a QUIC short header (fixed bit set, packet number
     * length field 2 bytes), a 16-byte all-0xAA connection ID (the
     * endpoint's fixed server CID length, so quiche_header_info parses it,
     * and no minted CID can be all-0xAA, so demux misses), then filler.
     * Every segment is the same size, as a GSO batch requires.
     */
    private static final int SEG_SIZE = 64;

    @Test
    public void testGsoBurstSplitsWithoutDisturbingServing() throws Exception {
        Assume.assumeTrue("The GRO receive split is quiche endpoint specific",
                endpointIsQuiche());

        Class<?> bindings;
        boolean groReceive;
        try {
            bindings = Class.forName(QUICHE_BINDINGS_CLASS);
            Field verdict = bindings.getDeclaredField("UDP_GRO_RECEIVE");
            verdict.setAccessible(true);
            groReceive = verdict.getBoolean(null);
        } catch (ReflectiveOperationException | LinkageError e) {
            Assume.assumeTrue("Quiche bindings not on the test classpath",
                    false);
            return;
        }
        Assume.assumeTrue("The class-init probe says this kernel hands up "
                + "coalesced reads without the segment cmsg - a read that "
                + "arrives merged could not be split, so the endpoint runs "
                + "with the receive option off", groReceive);

        startHttp3Server();

        validateStatus(get("/simple"), 200);

        long sent = sendGsoBurst(bindings, AF_INET, "127.0.0.1");
        Field maxBatch = bindings.getDeclaredField("GSO_MAX_BATCH");
        maxBatch.setAccessible(true);
        Assert.assertEquals("The GSO burst did not leave the client socket",
                (long) maxBatch.getInt(null) * SEG_SIZE, sent);

        // The endpoint normally binds the dual-stack wildcard, so the IPv4
        // burst above arrives v4-mapped. Send a copy aimed straight at the
        // IPv6 path too; best effort (nothing asserted) so an IPv4-only
        // wildcard fallback or a disabled IPv6 stack cannot fail the test.
        sendGsoBurst(bindings, AF_INET6, "::1");

        // The split segments are demux-dropped (unknown DCID) and the
        // endpoint must keep serving: fresh connections after the burst
        // complete normally.
        validateStatus(get("/simple"), 200);
        validateStatus(get("/simple"), 200);
    }


    /*
     * Sends one GSO batch (GSO_MAX_BATCH segments of SEG_SIZE bytes) from a
     * fresh unbound UDP socket to host:port, using the endpoint's own
     * downcall wrappers reflectively. Returns the sendmsg result (bytes
     * submitted) or -1 if the socket family is unavailable here.
     */
    private long sendGsoBurst(Class<?> bindings, int family, String host)
            throws Exception {
        Class<?> segmentClass =
                Class.forName("java.lang.foreign.MemorySegment");
        Class<?> arenaClass = Class.forName("java.lang.foreign.Arena");

        Method socket = declared(bindings, "socket", int.class, int.class,
                int.class);
        Method close = declared(bindings, "close", int.class);
        Method fillSockaddr = declared(bindings, "fillSockaddr", segmentClass,
                InetSocketAddress.class);
        Method sendSegmented = declared(bindings, "sendSegmentedDatagram",
                int.class, segmentClass, int[].class, int.class, int.class,
                int.class, segmentClass, int.class, segmentClass,
                segmentClass);

        Field maxBatchField = bindings.getDeclaredField("GSO_MAX_BATCH");
        maxBatchField.setAccessible(true);
        int count = maxBatchField.getInt(null);

        int fd = (int) socket.invoke(null, Integer.valueOf(family),
                Integer.valueOf(SOCK_DGRAM), Integer.valueOf(0));
        if (fd < 0) {
            // No IPv6 stack here (or any socket surprise): the caller
            // treats this path as best effort.
            return -1;
        }
        try {
            AutoCloseable arena = (AutoCloseable) arenaClass.getMethod(
                    "ofConfined").invoke(null);
            try {
                Method allocate = arenaClass.getMethod("allocate",
                        long.class);
                Object sockaddr = allocate.invoke(arena, 128L);
                Object data = allocate.invoke(arena,
                        Long.valueOf((long) count * SEG_SIZE));
                Field scratchSizeField =
                        bindings.getDeclaredField("BATCH_SCRATCH_SIZE");
                scratchSizeField.setAccessible(true);
                Object scratch = allocate.invoke(arena,
                        Long.valueOf(scratchSizeField.getLong(null)));

                byte[] burst = new byte[count * SEG_SIZE];
                for (int i = 0; i < count; i++) {
                    int o = i * SEG_SIZE;
                    burst[o] = 0x41;
                    Arrays.fill(burst, o + 1, o + 17, (byte) 0xAA);
                    Arrays.fill(burst, o + 17, o + SEG_SIZE, (byte) 0x55);
                }
                Method ofArray =
                        segmentClass.getMethod("ofArray", byte[].class);
                Method copy = segmentClass.getMethod("copy", segmentClass,
                        long.class, segmentClass, long.class, long.class);
                copy.invoke(null, ofArray.invoke(null, burst), Long.valueOf(0),
                        data, Long.valueOf(0),
                        Long.valueOf(burst.length));

                int toLen = (int) fillSockaddr.invoke(null, sockaddr,
                        new InetSocketAddress(host, port));

                int[] lens = new int[count];
                Arrays.fill(lens, SEG_SIZE);
                return ((Long) sendSegmented.invoke(null,
                        Integer.valueOf(fd), data, lens,
                        Integer.valueOf(count), Integer.valueOf(SEG_SIZE),
                        Integer.valueOf(SEG_SIZE), sockaddr,
                        Integer.valueOf(toLen), null, scratch)).longValue();
            } finally {
                arena.close();
            }
        } finally {
            close.invoke(null, Integer.valueOf(fd));
        }
    }


    private static Method declared(Class<?> type, String name,
            Class<?>... parameterTypes) throws NoSuchMethodException {
        Method method = type.getDeclaredMethod(name, parameterTypes);
        method.setAccessible(true);
        return method;
    }
}

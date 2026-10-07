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
package org.apache.tomcat.util.net.quic.quiche;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Cleaner;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.tomcat.util.net.quic.QuicConnection;
import org.apache.tomcat.util.net.quic.QuicConnectionManager;
import org.apache.tomcat.util.net.quic.QuicStream;

/**
 * Wraps a QUIC connection (a {@code quiche_conn *} between a client and the
 * server) and implements the QUIC transport view {@link QuicConnection} the
 * application protocol layer (HTTP/3) operates on.
 * <p>
 * Each connection manages its own set of {@link QuicheStreamWrapper}
 * instances. quiche has no per-stream native objects, so (unlike the OpenSSL
 * transport) there is no stream-before-connection free ordering: the single
 * native resource is the {@code quiche_conn} itself, freed exactly once
 * through the shared {@link #freed} CAS.
 * <p>
 * All native access runs on the endpoint's poll thread; worker calls hop
 * through the endpoint mailbox (see the individual methods).
 */
public class QuicheConnectionWrapper implements QuicConnection {

    private static final Cleaner cleaner = Cleaner.create();

    /**
     * The native quiche_conn* pointer for this connection.
     */
    private final MemorySegment conn;

    /**
     * Map of stream ID to stream wrapper.
     */
    private final ConcurrentHashMap<Long, QuicheStreamWrapper> streams =
            new ConcurrentHashMap<>();

    /**
     * The negotiated ALPN protocol (e.g., "h3").
     */
    private volatile String negotiatedProtocol;

    /**
     * The SNI host name sent by the client. Read once on the poll thread
     * during connection setup and cached so worker threads never make a
     * native call on the connection. {@code null} only if the setup-time
     * read has not (successfully) happened; an empty string means the client
     * sent no SNI.
     */
    private volatile String sniHostName;

    /**
     * Remote address (client).
     */
    private volatile InetSocketAddress remoteAddress;

    /**
     * Local address (server).
     */
    private volatile InetSocketAddress localAddress;

    /**
     * The application protocol connection manager registered for this
     * connection by the endpoint at connection accept.
     */
    private volatile QuicConnectionManager quicConnectionManager;

    /**
     * Whether the connection is closing (a CONNECTION_CLOSE was queued).
     */
    private volatile boolean closing;

    /**
     * Whether the connection has been fully closed.
     */
    private volatile boolean closed;

    /*
     * Poll-thread confined timer-deadline cache backing the endpoint's
     * timer heap: the deadline (absolute millis, Long.MAX_VALUE when no
     * timer is armed) and a stamp bumped on every refresh so heap entries
     * pushed for an earlier read are recognised as stale without a native
     * call. Only touched on the poll thread.
     */
    private long timerDeadlineMs = Long.MAX_VALUE;
    private int timerSeq;

    /**
     * ID of the most recently stream-limit-rejected client-initiated
     * bidirectional stream, or {@code -1}. Read and written only on the poll
     * thread (the readable sweep's rejection path); used to suppress the
     * repeated GOAWAY + shutdown that a client which keeps sending on an
     * already-rejected (never drained, never wrapped) stream would otherwise
     * trigger on each of its readable edges. Client stream IDs never repeat
     * on a connection, so a matching ID can only be a repeat of that same
     * rejection.
     */
    private long lastRejectedStreamId = -1;

    /**
     * Whether the native quiche_conn has been freed. Prevents double-free
     * from both explicit cleanup and the Cleaner. An {@link AtomicBoolean}
     * shared with the Cleaner's {@link State} so the State does not keep
     * this wrapper strongly reachable.
     */
    private final AtomicBoolean freed = new AtomicBoolean(false);

    /**
     * Number of executor worker threads currently executing the HTTP
     * handler for a stream on this connection. While greater than zero, the
     * native connection must NOT be freed, because a worker may still be
     * about to make a native call on the poll thread. The free is deferred
     * until this count reaches zero (see {@link #pendingFree}).
     */
    private final AtomicInteger activeHandlers = new AtomicInteger(0);

    /**
     * Set when the poll thread wants to free this connection but must wait
     * for {@link #activeHandlers} to reach zero. The worker that decrements
     * the count to zero clears this flag and schedules the free on the poll
     * thread.
     */
    private final AtomicBoolean pendingFree = new AtomicBoolean(false);

    /**
     * The server-initiated unidirectional streams of this connection, keyed
     * by the protocol-assigned stream index (index 0 is the primary stream
     * the endpoint uses for its own writes, e.g. the HTTP/3 control stream).
     */
    private final ConcurrentHashMap<Integer, QuicheStreamWrapper> serverUniStreams =
            new ConcurrentHashMap<>();

    /**
     * Streams whose {@code OPEN_READ} dispatch was dropped by the
     * claim-retry budget. The readable edge was already popped from
     * quiche's readable set when the dispatch was scheduled, so the event
     * has to be replayed by the endpoint's readable sweep once the
     * processing claim frees (see the endpoint's
     * rearmPendingReadDispatches). Entries are removed by the sweep when
     * they are replayed or the stream reaches a terminal state, and in
     * bulk by {@link #closeAllStreams()} when the connection goes away.
     */
    private final Set<QuicheStreamWrapper> pendingReadDispatches =
            ConcurrentHashMap.newKeySet();

    /**
     * Client-initiated unidirectional streams whose bounded drain stopped
     * with quiche still reporting readable data level-wise. The readable
     * edge was already popped from quiche's readable set, so the endpoint's
     * readable sweep has to re-drain these entries until the buffer is
     * empty (see the endpoint's rearmPendingUniStreamDrains). Entries are
     * removed by the sweep when the stream drains clean or reaches a
     * terminal state, and in bulk by {@link #closeAllStreams()} when the
     * connection goes away.
     */
    private final Set<QuicheStreamWrapper> pendingUniStreamDrains =
            ConcurrentHashMap.newKeySet();

    /**
     * Reference to the owning endpoint (for protocol-data accounting and
     * poll-thread hops).
     */
    private volatile QuicheEndpoint endpoint;

    /**
     * Whether protocol data (HTTP/3: QPACK decoder instructions) is queued
     * for emission on this connection. Set from worker threads via
     * {@link #setProtocolDataPending(boolean)} and cleared by the poll
     * thread when the flush drains the queue.
     */
    private final AtomicBoolean protocolDataPending = new AtomicBoolean();


    @Override
    public void setProtocolDataPending(boolean pending) {
        QuicheEndpoint ep = endpoint;
        if (ep != null) {
            ep.setConnectionProtocolDataPending(this, pending);
        } else {
            protocolDataPending.set(pending);
        }
    }


    @Override
    public boolean isProtocolDataPending() {
        return protocolDataPending.get();
    }


    /**
     * Applies a pending-state transition, reporting whether it actually
     * changed the flag. Package-private: the owning endpoint keeps its
     * endpoint-wide pending count consistent with the flag.
     *
     * @param pending The new pending state
     *
     * @return {@code true} if the state changed
     */
    boolean protocolDataPendingTransition(boolean pending) {
        return protocolDataPending.getAndSet(pending) != pending;
    }


    /**
     * Creates a new connection wrapper.
     *
     * @param conn The quiche_conn* pointer for the connection
     */
    public QuicheConnectionWrapper(MemorySegment conn) {
        this.conn = conn;
        // Pass the shared freed flag (not 'this') to the State so the
        // Cleaner does not keep this wrapper strongly reachable.
        State state = new State(conn, this.freed);
        cleaner.register(this, state);
    }


    /**
     * Returns the native quiche_conn* pointer for this connection.
     *
     * @return The quiche_conn* pointer
     */
    public MemorySegment getConn() {
        return conn;
    }


    /**
     * Returns the quiche_conn pointer address for use as a map key.
     *
     * @return The pointer address
     */
    public long getConnAddress() {
        return conn.address();
    }


    /**
     * Returns the negotiated ALPN protocol.
     *
     * @return The protocol string, or {@code null} if not yet negotiated
     */
    public String getNegotiatedProtocol() {
        return negotiatedProtocol;
    }


    /**
     * Sets the negotiated ALPN protocol.
     *
     * @param protocol The protocol string
     */
    public void setNegotiatedProtocol(String protocol) {
        this.negotiatedProtocol = protocol;
    }


    /**
     * Returns the SNI host name sent by the client.
     * <p>
     * The value is normally read on the poll thread during connection setup
     * and cached, so this method does not make a native call on the calling
     * (worker) thread. Only if the setup-time read did not populate the
     * cache is the native read hopped to the poll thread once and cached.
     * <p>
     * An empty string is returned both when the client sent no SNI and when
     * the value could not be obtained; callers must treat an empty result
     * as "no usable SNI".
     *
     * @return the SNI host name, or an empty string if none was sent or the
     *         value could not be determined; never {@code null}
     */
    @Override
    public String getSniHostName() {
        String result = sniHostName;
        if (result == null) {
            QuicheEndpoint endpoint = this.endpoint;
            if (endpoint == null || isClosed() || isFreed()) {
                // No poll thread to hop the native call to, or the native
                // connection is already gone. Calling into it here would
                // race the teardown. The SNI host name is not critical:
                // report "no SNI" and do not touch native memory.
                return "";
            }
            try {
                result = endpoint.callOnPollThread(this, this::readSniHostNameCached);
            } catch (Throwable t) {
                // The poll thread is not (or no longer) reachable: the SNI
                // host name is not critical, report "no SNI".
                result = "";
            }
        }
        return result;
    }


    /**
     * Reads the SNI host name from the native connection and caches it.
     * Must only be called on the QUIC poll thread.
     */
    private String readSniHostNameCached() {
        if (isClosed() || isFreed()) {
            // The connection was torn down between queueing this hop and its
            // execution (the free is poll-thread-confined too, so this check
            // is race-free). The native connection may already be freed;
            // report "no SNI" and do not touch it. Do not cache the result:
            // it means "unknown", not "the client sent no SNI".
            return "";
        }
        String value = readSniHostName();
        sniHostName = value;
        return value;
    }


    /**
     * Reads the SNI host name from the native connection. Must only be
     * called on the QUIC poll thread. The endpoint calls this during
     * connection accept; {@link #getSniHostName()} hops to the poll thread
     * lazily when the accept-time read did not populate the cache.
     *
     * @return the SNI host name, in lower case, or an empty string if the
     *         client sent no SNI or the read failed
     */
    public String readSniHostName() {
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment out = localArena.allocate(ValueLayout.ADDRESS);
            MemorySegment outLen = localArena.allocate(ValueLayout.JAVA_LONG);
            out.set(ValueLayout.ADDRESS, 0, MemorySegment.NULL);
            outLen.set(ValueLayout.JAVA_LONG, 0, 0L);
            QuicheBindings.quiche_conn_server_name(conn, out, outLen);
            MemorySegment data = out.get(ValueLayout.ADDRESS, 0);
            long len = outLen.get(ValueLayout.JAVA_LONG, 0);
            if (data.equals(MemorySegment.NULL) || len == 0) {
                return "";
            }
            byte[] bytes = data.reinterpret(len).toArray(ValueLayout.JAVA_BYTE);
            // Host names are case-insensitive and the endpoint's SSL host
            // config look-ups are keyed by lower-cased names.
            return new String(bytes, java.nio.charset.StandardCharsets.US_ASCII)
                    .toLowerCase(Locale.ENGLISH);
        }
    }


    /**
     * Caches the SNI host name. Called on the poll thread during connection
     * setup so that worker threads never need to read the value from the
     * native connection.
     *
     * @param sniHostName The SNI host name (empty string if none)
     */
    public void setSniHostName(String sniHostName) {
        this.sniHostName = sniHostName;
    }


    /**
     * Fails this QUIC connection with the given application protocol error
     * (for HTTP/3, RFC 9114 Section 8): the connection is terminated with a
     * QUIC {@code CONNECTION_CLOSE} frame carrying the error code.
     * <p>
     * The native teardown must run on the QUIC poll thread. When called
     * from a worker thread the teardown is hopped there. If the hop cannot
     * be completed in time, the connection is marked closed and the poll
     * loop tears down closed-but-not-yet-torn-down connections on its next
     * iteration, so the close always reclaims the connection's state.
     *
     * @param appErrorCode The application protocol error code for the
     *                     CONNECTION_CLOSE frame
     * @param reason       A short description of the error (for logging)
     */
    @Override
    public void failConnection(long appErrorCode, String reason) {
        QuicheEndpoint endpoint = this.endpoint;
        if (endpoint == null) {
            setClosed();
            return;
        }
        try {
            endpoint.callOnPollThread(this, () -> {
                endpoint.failConnection(this, appErrorCode, reason);
                return null;
            });
        } catch (Throwable t) {
            // The hop did not run (or did not complete in time). Mark the
            // close JVM-side and wake the loop: its teardown sweep picks up
            // closed connections that are still registered and releases
            // their state.
            setClosed();
            endpoint.kickPollLoop(this);
        }
    }


    /**
     * Returns the remote (client) address.
     *
     * @return The remote address
     */
    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }


    /**
     * Sets the remote (client) address.
     *
     * @param address The remote address
     */
    public void setRemoteAddress(InetSocketAddress address) {
        this.remoteAddress = address;
    }


    /**
     * Returns the local (server) address.
     *
     * @return The local address
     */
    public InetSocketAddress getLocalAddress() {
        return localAddress;
    }


    /**
     * Sets the local (server) address.
     *
     * @param address The local address
     */
    public void setLocalAddress(InetSocketAddress address) {
        this.localAddress = address;
    }


    /**
     * Checks if this connection is closing.
     *
     * @return {@code true} if a close has been initiated
     */
    public boolean isClosing() {
        return closing;
    }


    /**
     * Marks this connection as closing.
     */
    public void setClosing() {
        this.closing = true;
    }


    /**
     * Returns the ID of the most recently stream-limit-rejected client bidi
     * stream, or {@code -1}. Poll thread only.
     *
     * @return the last rejected stream ID
     */
    public long getLastRejectedStreamId() {
        return lastRejectedStreamId;
    }


    /**
     * Records the ID of a stream-limit-rejected client bidi stream. Poll
     * thread only.
     *
     * @param streamId The rejected stream ID
     */
    public void setLastRejectedStreamId(long streamId) {
        this.lastRejectedStreamId = streamId;
    }


    /**
     * Checks if this connection is fully closed.
     *
     * @return {@code true} if the connection is closed
     */
    public boolean isClosed() {
        return closed;
    }


    /**
     * Marks this connection as closed.
     */
    public void setClosed() {
        this.closed = true;
    }


    /**
     * Whether the endpoint's teardown for this connection has been claimed.
     * Claiming makes {@code teardownConnection} idempotent even when the
     * JVM-side {@link #closed} flag was set by a path that did not tear the
     * connection down (e.g. a failed worker-side failConnection hop): the
     * first caller runs the teardown, every later caller is a no-op.
     */
    private final AtomicBoolean teardownStarted = new AtomicBoolean(false);


    /**
     * Claims the teardown of this connection.
     *
     * @return {@code true} if the caller claimed it (and must perform the
     *         teardown), {@code false} if a teardown already ran
     */
    boolean markTeardownStarted() {
        return !teardownStarted.getAndSet(true);
    }


    /**
     * Checks if the native connection has been freed.
     *
     * @return {@code true} if the native connection has been freed
     */
    public boolean isFreed() {
        return freed.get();
    }


    /**
     * Frees the native quiche_conn exactly once, atomically. Both explicit
     * cleanup and the Cleaner call this, so the {@link AtomicBoolean}
     * guarantees {@code quiche_conn_free} runs at most once even if they
     * race.
     */
    public void freeConnOnce() {
        if (!freed.getAndSet(true)) {
            QuicheBindings.quiche_conn_free(conn);
        }
    }


    /**
     * Streams on which a worker is currently parked in a blocking read wait
     * ({@code awaitReadableData}). The readable re-arm
     * ({@code rearmReadWaiters}) walks this index instead of the connection's
     * full live-stream map, so the re-arm cost is O(interest) rather than
     * O(streams). Membership is bracketed exactly by the wait: every parked
     * reader registers its stream before the waiter slot becomes observable
     * and deregisters it, in a finally, after clearing that slot, so the set
     * is never missing a stream that still has a parked reader. A connection
     * carries at most one parked reader per stream at a time (the NIO2
     * machinery keeps a single read in flight per wrapper), so add / remove
     * are balanced per stream and the set holds no stale entries; a
     * deregistration racing the sweep can only over-register, which costs the
     * sweep a redundant (no-op) signal, never a lost one.
     */
    private final Set<QuicheStreamWrapper> readRearm =
            ConcurrentHashMap.newKeySet();

    /**
     * Per-stream count of poll-thread write interest: a parked blocking
     * writer ({@code awaitWritable}) plus a latched async write interest
     * ({@code registerWriteInterest}) are two independent producers, so a
     * stream that has both is counted twice and needs the write re-arm
     * ({@code rearmWriteWaiters}) until the last producer releases. The re-arm
     * walks the map's live key view (streams whose count is above zero)
     * instead of the full live-stream map, bounding the re-arm to O(interest)
     * rather than O(streams). Each producer transitions in through a
     * false→true latch / a pre-park registration that increments the count
     * before its interest becomes observable, and out through the matching
     * latch clear / post-unpark release that decrements it, so a stream stays
     * keyed while any producer is active and is dropped once none is. All
     * mutation runs through {@link ConcurrentHashMap}'s atomic
     * {@code merge} / {@code compute}, which is required because the latch
     * producers/clearers run on worker threads and the poll notify path
     * alike.
     */
    private final ConcurrentHashMap<QuicheStreamWrapper, Integer> writeRearm =
            new ConcurrentHashMap<>();

    /**
     * Packets that left quiche's send queue but met EAGAIN at the socket
     * (a GSO batch is atomic: when it fails, all of it is still unsent).
     * Drained by the next send flush, in order, before anything newer is
     * pulled from quiche, so wire order survives a full socket buffer.
     * Poll-thread confined (the send loop is the only toucher), so a plain
     * deque suffices. Bounded by {@link #MAX_PENDING_SENDS} with oldest-first
     * loss - the queue merely moves the kernel's drop point into the heap.
     */
    private final ArrayDeque<PendingSend> pendingSends = new ArrayDeque<>();

    /** Pending-send queue cap (packets). */
    static final int MAX_PENDING_SENDS = 64;


    /**
     * The connection's unsent-packet queue (see {@link #pendingSends}). The
     * returned deque is the live object; only the poll thread may mutate it.
     */
    ArrayDeque<PendingSend> pendingSends() {
        return pendingSends;
    }


    /**
     * One parked datagram: payload plus a snapshot of the destination (and
     * optional pinned source) quiche had recorded for it.
     */
    static final class PendingSend {
        final byte[] data;
        final byte[] to;
        final int toLen;
        final byte[] from;

        PendingSend(byte[] data, byte[] to, int toLen, byte[] from) {
            this.data = data;
            this.to = to;
            this.toLen = toLen;
            this.from = from;
        }
    }


    /**
     * Registers a stream that is about to park a blocking reader. Callers must
     * pair every call with a {@link #removeReadRearm(QuicheStreamWrapper)} in
     * a finally, and register before making the parked reader observable.
     */
    void addReadRearm(QuicheStreamWrapper stream) {
        readRearm.add(stream);
    }


    /**
     * Deregisters a stream whose blocking reader has finished waiting, after
     * its waiter slot has been cleared.
     */
    void removeReadRearm(QuicheStreamWrapper stream) {
        readRearm.remove(stream);
    }


    /**
     * Whether the readable re-arm has any stream to consider.
     *
     * @return {@code true} if at least one stream has a parked blocking reader
     */
    boolean hasReadRearm() {
        return !readRearm.isEmpty();
    }


    /**
     * The streams currently holding a parked blocking reader. The returned
     * view is the live (weakly consistent) set; the caller must not mutate it.
     */
    Set<QuicheStreamWrapper> readRearmStreams() {
        return readRearm;
    }


    /**
     * Records one unit of poll-thread write interest on a stream (a parked
     * blocking writer or a write-interest latch transition). Callers must pair
     * every call with a {@link #releaseWriteRearm(QuicheStreamWrapper)} and
     * register before the interest becomes observable.
     */
    void addWriteRearm(QuicheStreamWrapper stream) {
        writeRearm.merge(stream, Integer.valueOf(1), Integer::sum);
    }


    /**
     * Releases one unit of write interest recorded with
     * {@link #addWriteRearm(QuicheStreamWrapper)}, dropping the stream from
     * the index once its last producer has released.
     */
    void releaseWriteRearm(QuicheStreamWrapper stream) {
        writeRearm.compute(stream, (k, v) ->
                v == null || v.intValue() <= 1 ? null : Integer.valueOf(v.intValue() - 1));
    }


    /**
     * Whether the writable re-arm has any stream to consider.
     *
     * @return {@code true} if at least one stream has a parked blocking writer
     *         or a latched async write interest
     */
    boolean hasWriteRearm() {
        return !writeRearm.isEmpty();
    }


    /**
     * The streams currently holding poll-thread write interest, as a live
     * (weakly consistent) key view of the per-stream count. The caller must
     * not mutate the returned map.
     */
    Map<QuicheStreamWrapper, Integer> writeRearmStreams() {
        return writeRearm;
    }


    int getTimerSeq() {
        return timerSeq;
    }


    long getTimerDeadlineMs() {
        return timerDeadlineMs;
    }


    void setTimerDeadline(long deadlineMs) {
        timerDeadlineMs = deadlineMs;
        timerSeq++;
    }


    /**
     * Records that an executor worker is about to run the HTTP handler for a
     * stream on this connection.
     */
    public void incrActiveHandlers() {
        activeHandlers.incrementAndGet();
    }


    /**
     * Records that an executor worker finished running the HTTP handler.
     *
     * @return the remaining number of active handlers
     */
    public int decrActiveHandlers() {
        return activeHandlers.decrementAndGet();
    }


    /**
     * Checks whether any executor worker is currently running the HTTP
     * handler for a stream on this connection.
     *
     * @return {@code true} if at least one handler is active
     */
    public boolean hasActiveHandlers() {
        return activeHandlers.get() > 0;
    }


    /**
     * Marks this connection's free as pending, waiting for
     * {@link #activeHandlers} to reach zero.
     */
    public void setPendingFree() {
        pendingFree.set(true);
    }


    /**
     * Clears the pending-free flag if it is set.
     *
     * @return {@code true} if this caller cleared the flag and is therefore
     *         responsible for performing the deferred free
     */
    public boolean clearPendingFree() {
        return pendingFree.compareAndSet(true, false);
    }


    /**
     * Returns the wrapper of the server-initiated unidirectional stream with
     * the given protocol-assigned index, if it has been registered.
     *
     * @param index The protocol-assigned server unidirectional stream index
     *
     * @return The stream wrapper, or {@code null} if the stream has not been
     *         created yet
     */
    public QuicheStreamWrapper getServerUniStream(int index) {
        return serverUniStreams.get(Integer.valueOf(index));
    }


    /**
     * Returns the collection of the server-initiated unidirectional streams
     * created for this connection.
     *
     * @return The server unidirectional stream wrappers
     */
    public Collection<QuicheStreamWrapper> getServerUniStreams() {
        return serverUniStreams.values();
    }


    /**
     * Registers the wrapper of a server-initiated unidirectional stream.
     *
     * @param index  The protocol-assigned server unidirectional stream index
     * @param stream The stream wrapper
     */
    public void registerServerUniStream(int index, QuicheStreamWrapper stream) {
        serverUniStreams.put(Integer.valueOf(index), stream);
    }


    /**
     * Writes the remaining bytes of the given buffer to the provided stream
     * in one native {@code quiche_conn_stream_send()} call. Must be called
     * on the QUIC poll thread (quiche connections are not thread-safe).
     * <p>
     * As required by the {@link QuicConnection#writeToStream} contract, the
     * buffer's position is advanced by exactly the number of accepted bytes.
     * The write itself is atomic: the stream's writable capacity is checked
     * and the send is only attempted when the whole buffer fits, so in
     * practice the accepted count is either nothing (position unchanged, the
     * caller retries with the same bytes) or everything.
     *
     * @param stream The stream to write to
     * @param data   The data to write, from the buffer's current position to
     *               its limit; the position is advanced by the accepted count
     *
     * @return the number of bytes accepted by the stream - the whole buffer
     *         also when the stream is in a terminal state that can never
     *         accept the data (the bytes are dropped rather than retried
     *         forever)
     */
    @Override
    public int writeToStream(QuicStream stream, ByteBuffer data) {
        int startPos = data.position();
        byte[] bytes = new byte[data.remaining()];
        data.get(bytes);
        if (bytes.length == 0) {
            return 0;
        }
        QuicheStreamWrapper s = (QuicheStreamWrapper) stream;
        try (Arena localArena = Arena.ofConfined()) {
            MemorySegment dataSeg = localArena.allocate(bytes.length);
            dataSeg.asByteBuffer().put(bytes);
            long capacity = QuicheBindings.quiche_conn_stream_capacity(conn, s.getStreamId());
            if (capacity < 0) {
                // Any negative quiche_conn_stream_capacity - StreamStopped
                // (peer STOP_SENDING), InvalidStreamState (stream collected)
                // or any error a future quiche adds to the negative range -
                // means the stream can never accept these bytes: terminal
                // write state. The whole-negative-range rule is deliberately
                // the same one QuicheSocketWrapper.writeBytes() applies; when
                // a quiche update adds a capacity error, revisit both sites
                // together. Report the bytes as consumed so the caller drops
                // its pending state instead of re-attempting the write on
                // every poll iteration for the remaining lifetime of the
                // connection.
                data.position(startPos + bytes.length);
                return bytes.length;
            }
            if (capacity < bytes.length) {
                // Nothing accepted: leave the buffer for a retry with the
                // same bytes (per the interface contract).
                data.position(startPos);
                return 0;
            }
            MemorySegment errPtr = localArena.allocate(ValueLayout.JAVA_LONG);
            errPtr.set(ValueLayout.JAVA_LONG, 0, 0L);
            long written = QuicheBindings.quiche_conn_stream_send(conn, s.getStreamId(),
                    dataSeg, bytes.length, false, errPtr);
            if (written == QuicheBindings.QUICHE_ERR_STREAM_STOPPED ||
                    written == QuicheBindings.QUICHE_ERR_STREAM_RESET ||
                    written == QuicheBindings.QUICHE_ERR_INVALID_STREAM_STATE ||
                    written == QuicheBindings.QUICHE_ERR_FINAL_SIZE) {
                // Terminal send error: same drop-and-report semantics as the
                // terminal capacity path above.
                data.position(startPos + bytes.length);
                return bytes.length;
            }
            int accepted = written > 0 ? (int) Math.min(written, bytes.length) : 0;
            data.position(startPos + accepted);
            return accepted;
        }
    }


    /**
     * Returns the map of streams for this connection.
     *
     * @return The stream map
     */
    public ConcurrentHashMap<Long, QuicheStreamWrapper> getStreams() {
        return streams;
    }


    /**
     * Returns the set of streams with a dropped (claim-budget expired)
     * {@code OPEN_READ} dispatch awaiting replay by the readable sweep.
     *
     * @return The pending read-dispatch stream set
     */
    public Set<QuicheStreamWrapper> getPendingReadDispatches() {
        return pendingReadDispatches;
    }


    /**
     * Returns the set of client unidirectional streams whose bounded drain
     * stopped with data still buffered, awaiting the readable sweep's level
     * re-drain.
     *
     * @return The pending uni-stream drain set
     */
    public Set<QuicheStreamWrapper> getPendingUniStreamDrains() {
        return pendingUniStreamDrains;
    }


    /**
     * Returns the owning endpoint.
     *
     * @return The endpoint
     */
    public QuicheEndpoint getEndpoint() {
        return endpoint;
    }


    /**
     * Sets the owning endpoint.
     *
     * @param endpoint The endpoint
     */
    public void setEndpoint(QuicheEndpoint endpoint) {
        this.endpoint = endpoint;
    }


    /**
     * {@inheritDoc}
     * <p>
     * The manager is registered by the endpoint at connection accept.
     */
    @Override
    public QuicConnectionManager getQuicConnectionManager() {
        return quicConnectionManager;
    }


    /**
     * Sets the application protocol connection manager for this connection.
     *
     * @param quicConnectionManager The connection manager
     */
    public void setQuicConnectionManager(QuicConnectionManager quicConnectionManager) {
        this.quicConnectionManager = quicConnectionManager;
    }


    /**
     * Marks all streams of this connection deregistered and freed and clears
     * the connection's stream maps. quiche streams have no native handle, so
     * there is nothing to free beyond bookkeeping; a stream whose HTTP
     * handler is still running keeps its processing flag and finishes
     * against the (still alive) connection - the connection free itself is
     * deferred until all active handlers complete. Must run on the QUIC poll
     * thread.
     */
    public void closeAllStreams() {
        for (QuicheStreamWrapper stream : streams.values()) {
            stream.setDeregistered();
            stream.setFreed();
        }
        streams.clear();
        serverUniStreams.clear();
        pendingReadDispatches.clear();
        pendingUniStreamDrains.clear();
        readRearm.clear();
        writeRearm.clear();
        // Packets still queued for a dead connection: their destination
        // ceases to exist with it.
        pendingSends.clear();
    }


    @Override
    public String toString() {
        return "QuicConnection[conn=0x" + Long.toHexString(conn.address()) +
                ",streams=" + streams.size() +
                ",protocol=" + negotiatedProtocol + "]";
    }


    /**
     * State object for Cleaner-based native resource cleanup.
     */
    private static class State implements Runnable {
        private final MemorySegment conn;
        // Shared freed flag (NOT the wrapper) so this State does not keep the
        // QuicheConnectionWrapper strongly reachable from the static Cleaner.
        private final AtomicBoolean freed;

        State(MemorySegment conn, AtomicBoolean freed) {
            this.conn = conn;
            this.freed = freed;
        }

        @Override
        public void run() {
            // Free the native connection exactly once (races safely with
            // explicit cleanup via the shared AtomicBoolean). The endpoint's
            // bookkeeping keeps the wrapper strongly reachable while any
            // explicit teardown path can still run against the connection, so
            // reaching this point means the connection is already gone from
            // the endpoint's maps and no poll-loop iteration can touch it.
            if (!freed.getAndSet(true)) {
                QuicheBindings.quiche_conn_free(conn);
            }
        }
    }
}

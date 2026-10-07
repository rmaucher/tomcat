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
package org.apache.coyote.http3;

import java.nio.ByteBuffer;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;


/**
 * QPACK decoder per RFC 9204.
 * <p>
 * The decoder receives decoder instructions on the decoder stream and
 * decodes header blocks from request/response streams. Unlike HPACK,
 * QPACK uses out-of-band dynamic table management.
 */
public class QpackDecoder {

    private static final Log log = LogFactory.getLog(QpackDecoder.class);
    private static final StringManager sm = StringManager.getManager(QpackDecoder.class);

    private static final int INITIAL_RING_BUFFER_SIZE = 10;

    /**
     * Receives decoded headers.
     */
    public interface HeaderEmitter {
        void emitHeader(String name, String value) throws QpackException, Http3Exception;
    }


    /**
     * Dynamic table stored as a ring array indexed by absolute insert index
     * (RFC 9204 Section 3.2.4): the entry with absolute index {@code a} lives
     * at slot {@code a % dynamicTable.length}. Entries are inserted with a
     * strictly increasing absolute index and evicted oldest-first, so the
     * live entries always occupy a contiguous range of absolute indices and
     * their slots never collide while the array holds at least
     * {@link #dynamicTableSize} slots. A reference resolves in O(1) with no
     * per-reference copying (compare the former ArrayDeque-based lookup).
     */
    private Qpack.HeaderField[] dynamicTable = new Qpack.HeaderField[INITIAL_RING_BUFFER_SIZE];

    /**
     * Current memory size of the dynamic table.
     */
    private int currentTableSize = 0;

    /**
     * Maximum table size (soft limit, can be reduced by encoder).
     */
    private int maxTableSize;

    /**
     * Hard limit on table size.
     */
    private final int maxTableSizeHard;

    /**
     * Total number of entries inserted into the dynamic table so far
     * (never decremented on eviction). Per RFC 9204 Section 3.2.4, the
     * i-th inserted entry (0-based) has absolute index i. Volatile because
     * it may be read outside the decoder's monitor (e.g. by the processor
     * checking whether a blocked stream can be unblocked).
     */
    private volatile long totalInserts = 0;

    /**
     * Base value of the field section currently being decoded, in dynamic
     * table absolute index units (RFC 9204 Section 4.5.1.2). Long because
     * the absolute index space is unbounded over a connection's lifetime
     * (RFC 9204 Section 3.2.4: TotalNumberOfInserts never decreases, so
     * absolute indices grow past 2^31 on connections with more than 2^31
     * lifetime inserts).
     */
    private long currentBase;

    /**
     * Current size of dynamic table (number of entries).
     */
    private int dynamicTableSize = 0;

    /**
     * Maximum number of headers.
     */
    private int maxHeaderCount = 100;

    /**
     * Maximum total header size.
     */
    private int maxHeaderSize = 8 * 1024;

    private int headerCount = 0;
    private int headerSize = 0;

    /*
     * Whether the cookie header has been counted for the current field
     * section. Cookie field lines are split for compression efficiency
     * (RFC 9114 Section 4.2.1) and re-joined at the boundary, so only the
     * first occurrence is counted against maxHeaderCount - same accounting
     * as HTTP/2's HpackDecoder.
     */
    private boolean countedCookie = false;

    /**
     * Required Insert Count of the field section currently being decoded
     * (RFC 9204 Section 4.5.1), or -1 when not decoding a field section
     * (e.g. while processing encoder instructions). Used to enforce the
     * RFC 9204 Section 2.2.3 validation on dynamic table references. Long
     * for the same reason as {@link #currentBase}.
     */
    private long currentRic = -1;


    public QpackDecoder() {
        this(Qpack.DEFAULT_TABLE_SIZE, Qpack.DEFAULT_TABLE_SIZE);
    }


    /**
     * Creates a QPACK decoder with a configurable hard limit on the dynamic
     * table size.
     *
     * @param maxTableSize     The initial (soft) table capacity. May be
     *                         reduced by the peer's Set Dynamic Table
     *                         Capacity instruction (RFC 9204 Section 4.3.1).
     * @param maxTableSizeHard The hard limit on the table capacity. A Set
     *                         Dynamic Table Capacity instruction that
     *                         exceeds this limit is a connection error.
     *                         Typically the connector's
     *                         {@code qpackMaxTableCapacity} setting.
     */
    public QpackDecoder(int maxTableSize, int maxTableSizeHard) {
        this.maxTableSizeHard = maxTableSizeHard;
        this.maxTableSize = maxTableSize;
    }


    /**
     * Decodes a prefixed integer (iRP) per RFC 9204 Section 4.1.1 (the
     * RFC 7541 Section 5.1 format), narrowed to {@code int}. The top n bits
     * of the given first byte (i.e. the low n bits, for a mid-byte iRP
     * following earlier fields) hold the prefix. If the prefix is all ones,
     * the excess is encoded as 7-bit groups, least significant group first
     * (RFC 7541 Section 5.1 Figure 3), with the high bit as continuation
     * flag.
     * <p>
     * The {@code Int} name distinguishes this int-narrowing shim from the
     * identically named long-returning {@link Qpack#decodeIrp(ByteBuffer,
     * int, int)} it delegates to, which it otherwise shadows.
     *
     * @param buffer    Buffer to read continuation bytes from
     * @param n         Prefix size in bits (1-8)
     * @param firstByte First byte, already consumed from the buffer
     * @return The decoded integer, or -1 if more data is needed
     * @throws QpackException If the integer exceeds the maximum permitted value
     */
    private static int decodeIrpIntRest(ByteBuffer buffer, int n, int firstByte) throws QpackException {
        long value = Qpack.decodeIrp(buffer, n, firstByte);
        if (value == -1) {
            return -1;
        }
        if (value > Integer.MAX_VALUE) {
            // RFC 9204 Section 7.4 - see QpackValueTooLargeException.
            throw new QpackValueTooLargeException(
                    sm.getString("qpack.integerOverflow"));
        }
        return (int) value;
    }


    /**
     * Decodes a full-byte prefixed integer (iRP) per RFC 9204 Section 4.1.1
     * where the integer occupies the entire first byte, narrowed to
     * {@code int}; see {@link #decodeIrpIntRest(ByteBuffer, int, int)} for
     * the naming distinction from the long-returning {@code Qpack} static.
     *
     * @param buffer Buffer to read from
     * @param n      Prefix size in bits (1-8)
     * @return The decoded integer, or -1 if more data is needed
     * @throws QpackException If the integer exceeds the maximum permitted value
     */
    private static int decodeIrpInt(ByteBuffer buffer, int n) throws QpackException {
        if (buffer.remaining() == 0) {
            return -1;
        }
        int firstByte = buffer.get() & 0xFF;
        return decodeIrpIntRest(buffer, n, firstByte);
    }


    /**
     * Processes an encoder instruction from the encoder stream.
     * Per RFC 9204 Section 4.3, encoder instructions use prefixes:
     *   001 = Set Dynamic Table Capacity (Section 4.3.1)
     *   1   = Insert with Name Reference (Section 4.3.2)
     *   01  = Insert with Literal Name (Section 4.3.3)
     *   000 = Duplicate (Section 4.3.4)
     * <p>
     * This decoder instance is shared by all request streams of a QUIC
     * connection and may be invoked concurrently from different worker
     * threads, so instruction processing and header block decoding are
     * mutually exclusive.
     *
     * @param buffer The buffer containing the instruction
     * @throws QpackException If the instruction is invalid
     */
    public synchronized void processInstruction(ByteBuffer buffer) throws QpackException {
        if (buffer.remaining() < 1) {
            return;
        }

        int sp = buffer.position();
        int firstByte = buffer.get() & 0xFF;

        // RFC 9204 Section 4.3: Encoder Instructions. The branches test
        // disjoint masks, so the order of the checks carries no meaning;
        // the capacity instruction is simply tested first, mirroring the
        // RFC's enumeration order.
        if ((firstByte & 0xE0) == 0x20) {
            // 001xxxxx: Set Dynamic Table Capacity (Section 4.3.1)
            // 001 + iRP(m=5) capacity
            int capacity = decodeIrpIntRest(buffer, 5, firstByte);
            if (capacity == -1) {
                buffer.position(sp);
                return;
            }
            if (capacity > maxTableSizeHard) {
                throw new QpackException(sm.getString("qpackdecoder.tableSizeExceeded",
                        Integer.valueOf(capacity), Integer.valueOf(maxTableSizeHard)));
            }
            maxTableSize = capacity;
            evictToSize(capacity);
        } else if ((firstByte & 0x80) == 0x80) {
            // 1 T iRP(m=6): Insert with Name Reference (Section 4.3.2)
            // Bit 7=1 (type), bit 6=T, bits 5-0=Index (iRP m=6)
            boolean isStatic = (firstByte & 0x40) != 0;
            int nameIndex = decodeIrpIntRest(buffer, 6, firstByte);
            if (nameIndex == -1) {
                buffer.position(sp);
                return;
            }
            String value = Qpack.decodeString(buffer,
                    (int) Math.min(Integer.MAX_VALUE, encodedLiteralBudget(0)));
            if (value == null) {
                buffer.position(sp);
                return;
            }
            String name;
            if (isStatic) {
                if (nameIndex >= Qpack.STATIC_TABLE_LENGTH) {
                    // RFC 9204 Section 3.1: an invalid static table index
                    // received on the encoder stream is a distinct condition
                    // from an unknown instruction type.
                    throw new QpackException(sm.getString("qpackdecoder.invalidIndex", Integer.valueOf(nameIndex)));
                }
                name = Qpack.STATIC_TABLE[nameIndex].name;
            } else {
                // Per RFC 9204 Section 3.2.5, in encoder instructions a
                // relative index of 0 refers to the most recently inserted
                // entry: absolute = totalInserts - 1 - relativeIndex.
                long absoluteIndex = totalInserts - 1 - nameIndex;
                name = getDynamicEntryByAbsolute(absoluteIndex).name;
            }
            addToDynamicTable(name, value);
        } else if ((firstByte & 0xC0) == 0x40) {
            // 01xxxxxx: Insert with Literal Name (Section 4.3.3)
            // 01 H + 5-bit prefix name length, then name bytes, then value string
            // H is bit 5 of the byte (bit 2 in Figure 7)
            boolean huffman = (firstByte & 0x20) != 0;
            int nameLen = decodeIrpIntRest(buffer, 5, firstByte);
            if (nameLen == -1) {
                buffer.position(sp);
                return;
            }
            long nameBudget = encodedLiteralBudget(0);
            if (nameLen > nameBudget) {
                // The declared name alone can never be part of an entry
                // that fits the dynamic table (see encodedLiteralBudget()).
                // Fail the connection instead of retaining the partial
                // instruction across reads forever.
                throw new QpackException(sm.getString("qpack.stringTooLong",
                        Integer.valueOf(nameLen), Long.valueOf(nameBudget)));
            }
            if (buffer.remaining() < nameLen) {
                buffer.position(sp);
                return;
            }
            StringBuilder nameSb = new StringBuilder(nameLen);
            if (huffman) {
                QpackHuffman.decode(buffer, nameLen, nameSb);
            } else {
                Qpack.decodeRawLiteral(buffer, nameLen, nameSb);
            }
            String value = Qpack.decodeString(buffer,
                    (int) Math.min(Integer.MAX_VALUE,
                            encodedLiteralBudget(nameLen)));
            if (value == null) {
                buffer.position(sp);
                return;
            }
            addToDynamicTable(nameSb.toString(), value);
        } else if ((firstByte & 0xE0) == 0x00) {
            // 000xxxxx: Duplicate (Section 4.3.4)
            // 000 + iRP(m=5) relative index
            int relIndex = decodeIrpIntRest(buffer, 5, firstByte);
            if (relIndex == -1) {
                buffer.position(sp);
                return;
            }
            // Duplicate always references the dynamic table (RFC 9204 Section 4.3.4).
            // Per RFC 9204 Section 3.2.5, a relative index of 0 in encoder
            // instructions refers to the most recently inserted entry.
            long absoluteIndex = totalInserts - 1 - relIndex;
            Qpack.HeaderField entry = getDynamicEntryByAbsolute(absoluteIndex);
            addToDynamicTable(entry.name, entry.value);
        } else {
            throw new QpackException(sm.getString("qpackdecoder.unknownInstruction", Integer.valueOf(firstByte)));
        }
    }


    private void addToDynamicTable(String name, String value) throws QpackException {
        int entrySize = Qpack.entrySize(name, value);
        if (entrySize > maxTableSize) {
            // Per RFC 9204 Section 3.2.2, an entry larger than the dynamic
            // table capacity is a connection error of type
            // QPACK_ENCODER_STREAM_ERROR.
            throw new QpackException(sm.getString("qpackdecoder.entryTooLarge",
                    Integer.valueOf(entrySize), Integer.valueOf(maxTableSize)));
        }

        while (currentTableSize + entrySize > maxTableSize) {
            if (dynamicTableSize == 0) {
                break;
            }
            evictOldest();
        }

        ensureCapacity(dynamicTableSize + 1);
        Qpack.HeaderField entry = new Qpack.HeaderField(name, value);
        // The next insert takes absolute index totalInserts (RFC 9204
        // Section 3.2.4); its slot is fixed by the modulo once the array is
        // large enough to hold it alongside every live entry.
        dynamicTable[slot(totalInserts)] = entry;
        currentTableSize += entrySize;
        dynamicTableSize++;
        totalInserts++;
        // Wake any request stream blocked waiting for this insert
        // (RFC 9204 Section 2.1.2). The monitor is held by the caller
        // (processInstruction / decodeHeaderBlock are synchronized).
        notifyAll();
    }


    /*
     * Removes the oldest live entry (smallest absolute index, i.e. total
     * inserts minus the number of live entries). The caller must ensure at
     * least one entry is live.
     */
    private void evictOldest() {
        long oldestAbsolute = totalInserts - dynamicTableSize;
        int slot = slot(oldestAbsolute);
        Qpack.HeaderField removed = dynamicTable[slot];
        dynamicTable[slot] = null;
        currentTableSize -= Qpack.entrySize(removed.name, removed.value);
        dynamicTableSize--;
    }


    private void evictToSize(int maxSize) {
        while (currentTableSize > maxSize && dynamicTableSize > 0) {
            evictOldest();
        }
    }


    /*
     * Grows the ring array so it can hold at least minSlots live entries
     * without slot collisions. Because live entries occupy a contiguous
     * range of absolute indices, each is re-placed at its absolute index
     * modulo the new length.
     */
    private void ensureCapacity(int minSlots) {
        if (minSlots <= dynamicTable.length) {
            return;
        }
        int newLength = dynamicTable.length;
        while (newLength < minSlots) {
            newLength = newLength * 2;
        }
        Qpack.HeaderField[] newTable = new Qpack.HeaderField[newLength];
        long oldestAbsolute = totalInserts - dynamicTableSize;
        for (long absolute = oldestAbsolute; absolute < totalInserts; absolute++) {
            newTable[(int) (absolute % newLength)] = dynamicTable[(int) (absolute % dynamicTable.length)];
        }
        dynamicTable = newTable;
    }


    private int slot(long absoluteIndex) {
        return (int) (absoluteIndex % dynamicTable.length);
    }


    /*
     * The maximum combined encoded (wire) length of the name and value
     * string literals of an insert instruction that could still describe a
     * legal entry, minus the name's already-known encoded length. Encoder
     * instructions are re-assembled across stream reads, so a declared
     * length above this bound can never complete from the bytes the read
     * buffer retains and must fail the connection rather than stall the
     * stream. The bound is a superset of every legal entry: an entry's size
     * is 32 plus the UTF-8 byte length of name and value (RFC 9204 Section
     * 3.2.1); Huffman-decoded characters consume at most 30 bits each (the
     * longest code of the RFC 7541 Appendix B table, QpackHuffman), so N
     * decoded characters occupy at most 30N/8 = 15N/4 encoded bytes plus
     * one partial trailing byte per string, raw literals use exactly one
     * byte per character, and the UTF-8 byte length is never below the
     * character count, so a legal entry's combined encoded length is at
     * most 15/4 times the size budget plus a small padding allowance:
     * ceil(30N/8) + ceil(30M/8) <= (30(N+M) + 14) / 8 <= 15S/4 + 2 for
     * N+M <= S. Based on the hard (advertised) capacity, which is stable
     * across Set Dynamic Table Capacity rewinds of a partial instruction;
     * entries too large for the current (soft) capacity are still rejected
     * by addToDynamicTable once fully parsed.
     */
    private long encodedLiteralBudget(int nameEncodedLength) {
        long sizeBudget = (long) maxTableSizeHard - 32;
        if (sizeBudget <= 0) {
            // No literal can fit: only zero-length strings are even worth
            // completing, and the full parse still checks the real size.
            return 0;
        }
        return Math.max(0, sizeBudget * 15 / 4 + 2 - nameEncodedLength);
    }


    /**
     * Resolves a dynamic table absolute index (0-based insertion order,
     * RFC 9204 Section 3.2.4) to a table entry.
     *
     * @param absolute The absolute index of the entry
     * @return The referenced entry
     * @throws QpackBlockedException If the entry has not been inserted yet
     *         (RFC 9204 Section 2.2.1: the field section is blocked, this
     *         is not an error)
     * @throws QpackException If the reference is invalid (negative index or
     *         reference to an evicted entry)
     */
    private Qpack.HeaderField getDynamicEntryByAbsolute(long absolute) throws QpackException {
        if (absolute < 0) {
            // Per RFC 9204 Section 2.2.3, an invalid reference to the
            // dynamic table is a connection error of type
            // QPACK_DECOMPRESSION_FAILED (or QPACK_ENCODER_STREAM_ERROR
            // when the reference is in an encoder instruction).
            throw new QpackException(sm.getString("qpackdecoder.dynamicTableIndexInvalid"));
        }
        // Per RFC 9204 Section 2.2.3, a field line reference to a dynamic
        // table entry with an absolute index greater than or equal to the
        // declared Required Insert Count is a connection error of type
        // QPACK_DECOMPRESSION_FAILED.
        if (currentRic >= 0 && absolute >= currentRic) {
            throw new QpackException(sm.getString("qpackdecoder.dynamicTableIndexInvalid"));
        }
        if (absolute >= totalInserts) {
            // The entry has not been inserted yet. Per RFC 9204
            // Section 2.2.1, the stream is blocked until the entry is
            // inserted; this is not an error.
            throw new QpackBlockedException(absolute + 1L);
        }
        // The entry has been inserted. It is live unless its absolute index
        // precedes the oldest live entry (totalInserts minus the live count),
        // in which case it has been evicted. Per RFC 9204 Section 2.2.3 a
        // reference to an evicted entry is a connection error of type
        // QPACK_DECOMPRESSION_FAILED.
        if (absolute < totalInserts - dynamicTableSize) {
            throw new QpackException(sm.getString("qpackdecoder.dynamicTableIndexInvalid"));
        }
        // O(1) ring-array access: the live absolute index maps directly to its
        // slot. A null here would mean the live-range invariant was violated,
        // which the contiguous-range eviction/insert logic makes unreachable;
        // it is defended against to keep a bad reference an error, not an NPE.
        Qpack.HeaderField entry = dynamicTable[slot(absolute)];
        if (entry == null) {
            throw new QpackException(sm.getString("qpackdecoder.dynamicTableIndexInvalid"));
        }
        return entry;
    }


    /**
     * Decodes a header block from a request/response stream.
     * Per RFC 9204 Section 4.5, field line representations:
     *   1xxxxxxx = Indexed Field Line (Section 4.5.2)
     *   01xxxxxx = Literal Field Line with Name Reference (Section 4.5.4)
     *   001xxxxx = Literal Field Line with Literal Name (Section 4.5.6)
     *   0001xxxx = Indexed Field Line with Post-Base Index (Section 4.5.3)
     *   0000xxxx = Literal Field Line with Post-Base Name Reference (Section 4.5.5)
     *
     * This decoder instance is shared by all request streams of a QUIC
     * connection and may be invoked concurrently from different worker
     * threads, so header block decoding and instruction processing are
     * mutually exclusive. The transport thread that reads the client's
     * QPACK encoder stream acquires the same monitor (see
     * {@link #processInstruction(ByteBuffer)}), so a field section decode
     * (bounded by the configured max field section size) head-of-line
     * blocks instruction processing for its duration. This is a known,
     * bounded trade-off of processing encoder stream data inline on the
     * transport thread; enlarge the field section size limit only with
     * that in mind.
     *
     * <p>
     * Error handling contract (RFC 9204 Section 6):
     * </p>
     * <ul>
     * <li>{@link QpackBlockedException}: the field section requires dynamic
     * table entries that have not been inserted yet (RFC 9204
     * Section 2.2.1). This is not an error. A conformant decoder MAY block
     * the stream until {@link #getTotalInserts()} reaches or exceeds
     * {@link QpackBlockedException#getRequiredInsertCount()}; it fails the
     * connection with {@code H3_QPACK_DECOMPRESSION_FAILED} otherwise
     * (RFC 9204 Section 2.2.1). Blocking is opt-in via the
     * {@code qpackBlockedStreams} property of {@code AbstractHttp3Protocol} (which
     * also drives the advertised {@code QPACK_BLOCKED_STREAMS} value); with
     * the default of 0 the caller fails the connection.</li>
     * <li>{@link QpackException}: a fatal QPACK error (invalid reference,
     * invalid static table index, impossible Encoded Insert Count, Huffman
     * decode failure). Per RFC 9204 Sections 2.2.3, 3.1 and 4.5.1.1 the
     * caller MUST fail the whole connection with
     * {@code H3_QPACK_DECOMPRESSION_FAILED} (0x0200), not just the stream,
     * because this decoder is shared by all streams of the connection.</li>
     * <li>{@link QpackValueTooLargeException}: a value larger than this
     * implementation is able to decode (RFC 9204 Section 7.4). On a
     * request stream the caller MUST treat it as a stream error of type
     * {@code QPACK_DECOMPRESSION_FAILED}; on the encoder or decoder
     * stream it remains a connection error of the appropriate type.</li>
     * <li>{@link Http3Exception}: size-limit violations on the request
     * stream (decoded field section exceeds the advertised
     * {@code max_field_section_size} or header count; RFC 9114
     * Section 4.2.2 makes rejecting an oversized section optional without
     * mandating an error code, and this connector treats it as a
     * malformed message). The caller fails only the affected stream with
     * the error carried by the exception ({@code H3_MESSAGE_ERROR}),
     * matching the HTTP/2 connector's limit handling.</li>
     * </ul>
     *
     * <p>
     * The size/count limits applied are this instance's configured fields
     * (see {@link #setMaxHeaderCount(int)} / {@link #setMaxHeaderSize(int)}).
     * Production field-section decodes do not use this overload: they pass
     * per-section limits through the four-argument overload below, which
     * temporarily overrides (and then restores) the instance fields.
     *
     * @param buffer The buffer containing the header block
     * @param emitter The callback invoked for each decoded header field
     * @throws QpackException If decoding fails
     */
    public synchronized void decodeHeaderBlock(ByteBuffer buffer, HeaderEmitter emitter) throws QpackException, Http3Exception {
        decodeHeaderBlockInternal(buffer, emitter);
    }


    /**
     * Decodes a field section applying the given size/count limits for the
     * duration of this call only.
     * <p>
     * The decoder instance is shared by all streams of an HTTP/3 connection
     * and field sections are decoded concurrently on per-stream worker
     * threads. Limits that differ per field section (a trailer section is
     * checked against the connector's trailer limits, request headers
     * against the header limits) must therefore travel with the decode call
     * rather than be written to the shared instance from outside the monitor
     * (which would race with concurrent decodes). The limits are applied
     * under the decoder monitor and restored on exit, so a concurrent
     * decode either sees its own limits or waits for the monitor.
     *
     * @param buffer          The buffer containing the header block
     * @param emitter         The callback invoked for each decoded header
     *                        field
     * @param maxHeaderCount  Maximum header count for this field section, or
     *                        a negative value for no limit
     * @param maxHeaderSize   Maximum total header size for this field
     *                        section, or a negative value for no limit
     *
     * @throws QpackException If decoding fails
     * @throws Http3Exception If a size/count limit is exceeded
     */
    public synchronized void decodeHeaderBlock(ByteBuffer buffer, HeaderEmitter emitter,
            int maxHeaderCount, int maxHeaderSize) throws QpackException, Http3Exception {
        int savedHeaderCount = this.maxHeaderCount;
        int savedHeaderSize = this.maxHeaderSize;
        this.maxHeaderCount = maxHeaderCount;
        this.maxHeaderSize = maxHeaderSize;
        try {
            decodeHeaderBlockInternal(buffer, emitter);
        } finally {
            this.maxHeaderCount = savedHeaderCount;
            this.maxHeaderSize = savedHeaderSize;
        }
    }


    private void decodeHeaderBlockInternal(ByteBuffer buffer, HeaderEmitter emitter) throws QpackException, Http3Exception {
        headerCount = 0;
        headerSize = 0;
        countedCookie = false;

        int blockStart = buffer.position();

        // RFC 9204 Section 4.5.1: Encoded Field Section Prefix
        // Required Insert Count (iRP m=8), then Sign bit (S) + Delta Base (iRP m=7)
        int encodedInsertCount = decodeIrpInt(buffer, 8);
        if (encodedInsertCount == -1) {
            // The prefix was not decodable (e.g. an all-ones first byte
            // whose continuation bytes are missing). Rewind like the two
            // exits below so every incomplete-prefix case leaves the
            // whole block unconsumed: callers detect the truncation via
            // hasRemaining() and must not mistake a partially consumed
            // prefix for a complete field section.
            buffer.position(blockStart);
            return;
        }
        if (buffer.remaining() == 0) {
            buffer.position(blockStart);
            return;
        }
        int secondByte = buffer.get() & 0xFF;
        boolean sign = (secondByte & 0x80) != 0;
        int deltaBase = decodeIrpIntRest(buffer, 7, secondByte);
        if (deltaBase == -1) {
            buffer.position(blockStart);
            return;
        }

        // Reconstruct the Required Insert Count per RFC 9204 Section 4.5.1.1
        long requiredInsertCount = reconstructReqInsertCount(encodedInsertCount);
        if (requiredInsertCount < 0) {
            throw new QpackException(sm.getString("qpackdecoder.encodedInsertCountInvalid",
                    Integer.valueOf(encodedInsertCount)));
        }

        // Per RFC 9204 Section 4.5.1.2, a field block with a Sign bit of 1
        // is invalid if the Required Insert Count is less than or equal to
        // the Delta Base.
        if (sign && requiredInsertCount <= deltaBase) {
            throw new QpackException(sm.getString("qpackdecoder.invalidBase",
                    Long.valueOf(requiredInsertCount), Integer.valueOf(deltaBase)));
        }

        // Compute Base per RFC 9204 Section 4.5.1.2. The Base is expressed in
        // dynamic table absolute index units (RFC 9204 Section 3.2.4).
        long sectionBase;
        if (!sign) {
            sectionBase = requiredInsertCount + deltaBase;
        } else {
            sectionBase = requiredInsertCount - deltaBase - 1;
        }
        currentBase = sectionBase;
        currentRic = requiredInsertCount;

        // Reset the per-section state on every exit path - including the
        // blocked-stream signal below. The decoder is shared by all
        // streams of the connection: a stale RIC would otherwise make the
        // dynamic-reference guard reject a legal subsequent encoder stream
        // insert (RFC 9204 Sections 3.2.1, 4.5.1).
        try {
            // Per RFC 9204 Section 2.2.1, if the Required Insert Count
            // exceeds the number of entries inserted so far, the stream is
            // blocked (this is not an error).
            if (requiredInsertCount > totalInserts) {
                throw new QpackBlockedException(requiredInsertCount);
            }

            if (log.isDebugEnabled()) {
                log.debug("QPACK Header Block Prefix: RequiredInsertCount=" + requiredInsertCount
                        + ", Sign=" + sign + ", DeltaBase=" + deltaBase + ", Base=" + sectionBase);
            }

            decodeFieldLines(buffer, emitter);
        } finally {
            currentRic = -1;
            currentBase = -1;
        }
    }


    private void decodeFieldLines(ByteBuffer buffer, HeaderEmitter emitter) throws QpackException, Http3Exception {
        while (buffer.hasRemaining()) {
            int fieldStart = buffer.position();
            int b = buffer.get() & 0xFF;

            if ((b & 0x80) == 0x80) {
                // 1 T Index(6+): Indexed Field Line (RFC 9204 Section 4.5.2)
                boolean isStatic = (b & 0x40) != 0;
                int index = decodeIrpIntRest(buffer, 6, b);
                if (index == -1) {
                    buffer.position(fieldStart);
                    return;
                }
                emitIndexedEntry(index, isStatic, emitter);
            } else if ((b & 0xC0) == 0x40) {
                // 01 N T NameIndex(4+): Literal Field Line with Name Reference (Section 4.5.4)
                boolean isStatic = (b & 0x10) != 0;
                int index = decodeIrpIntRest(buffer, 4, b);
                if (index == -1) {
                    buffer.position(fieldStart);
                    return;
                }
                String value = Qpack.decodeString(buffer);
                if (value == null) {
                    buffer.position(fieldStart);
                    return;
                }
                emitNameRefEntry(index, isStatic, value, emitter);
            } else if ((b & 0xE0) == 0x20) {
                // 001 N H NameLen(3+): Literal Field Line with Literal Name (Section 4.5.6)
                // The name is a 4-bit prefix string literal: H flag (bit 3) + 3-bit prefix length.
                boolean huffman = (b & 0x08) != 0;
                int nameLen = decodeIrpIntRest(buffer, 3, b);
                if (nameLen == -1 || buffer.remaining() < nameLen) {
                    buffer.position(fieldStart);
                    return;
                }
                StringBuilder sb = new StringBuilder(nameLen);
                if (huffman) {
                    QpackHuffman.decode(buffer, nameLen, sb);
                } else {
                    Qpack.decodeRawLiteral(buffer, nameLen, sb);
                }
                String name = sb.toString();
                String value = Qpack.decodeString(buffer);
                if (value == null) {
                    buffer.position(fieldStart);
                    return;
                }
                emit(name, value, emitter);
            } else if ((b & 0xF0) == 0x10) {
                // 0001 Index(4+): Indexed Field Line with Post-Base Index (Section 4.5.3)
                int index = decodeIrpIntRest(buffer, 4, b);
                if (index == -1) {
                    buffer.position(fieldStart);
                    return;
                }
                emitPostBaseIndexedEntry(index, emitter);
            } else if ((b & 0xF0) == 0x00) {
                // 0000 N NameIdx(3+): Literal Field Line with Post-Base Name Reference (Section 4.5.5)
                int index = decodeIrpIntRest(buffer, 3, b);
                if (index == -1) {
                    buffer.position(fieldStart);
                    return;
                }
                String value = Qpack.decodeString(buffer);
                if (value == null) {
                    buffer.position(fieldStart);
                    return;
                }
                emitPostBaseNameRefEntry(index, value, emitter);
            } else {
                throw new QpackException(sm.getString("qpackdecoder.unknownInstruction", Integer.valueOf(b)));
            }
        }
    }


    /*
     * Resolves a field line table reference to its header field. Static
     * table indexes are bounds-checked (an out-of-range index is a QPACK
     * error, RFC 9204 Section 4.5.2). Dynamic references are relative to
     * Base: a relative index of 0 refers to the entry with absolute index
     * Base - 1 (RFC 9204 Section 3.2.5).
     */
    private Qpack.HeaderField resolveIndexedEntry(int index, boolean isStatic)
            throws QpackException {
        if (isStatic) {
            if (index >= Qpack.STATIC_TABLE_LENGTH) {
                throw new QpackException(sm.getString("qpackdecoder.invalidIndex", Integer.valueOf(index)));
            }
            return Qpack.STATIC_TABLE[index];
        }
        return getDynamicEntryByAbsolute(currentBase - 1 - index);
    }


    private void emitIndexedEntry(int index, boolean isStatic, HeaderEmitter emitter) throws QpackException, Http3Exception {
        Qpack.HeaderField entry = resolveIndexedEntry(index, isStatic);
        String name = entry.name;
        String value = entry.value != null ? entry.value : "";
        if (log.isDebugEnabled()) {
            log.debug("QPACK Indexed: name=" + name + " value=" + value);
        }
        emit(name, value, emitter);
    }


    private void emitNameRefEntry(int index, boolean isStatic, String value, HeaderEmitter emitter) throws QpackException, Http3Exception {
        String name = resolveIndexedEntry(index, isStatic).name;
        if (log.isDebugEnabled()) {
            log.debug("QPACK NameRef: name=" + name + " value=" + value);
        }
        emit(name, value, emitter);
    }


    /*
     * Resolves a post-base field line reference. Per RFC 9204
     * Section 3.2.6, a post-base index of 0 refers to the entry with
     * absolute index equal to Base.
     */
    private Qpack.HeaderField resolvePostBaseEntry(int postBaseIndex) throws QpackException {
        return getDynamicEntryByAbsolute(currentBase + postBaseIndex);
    }


    private void emitPostBaseIndexedEntry(int postBaseIndex, HeaderEmitter emitter) throws QpackException, Http3Exception {
        Qpack.HeaderField entry = resolvePostBaseEntry(postBaseIndex);
        String name = entry.name;
        String value = entry.value != null ? entry.value : "";
        if (log.isDebugEnabled()) {
            log.debug("QPACK PostBase Indexed: name=" + name + " value=" + value);
        }
        emit(name, value, emitter);
    }


    private void emitPostBaseNameRefEntry(int postBaseIndex, String value, HeaderEmitter emitter) throws QpackException, Http3Exception {
        String name = resolvePostBaseEntry(postBaseIndex).name;
        if (log.isDebugEnabled()) {
            log.debug("QPACK PostBase NameRef: name=" + name + " value=" + value);
        }
        emit(name, value, emitter);
    }


    private void emit(String name, String value, HeaderEmitter emitter) throws QpackException, Http3Exception {
        int inc = Qpack.entrySize(name, value);
        if ("cookie".equals(name)) {
            // Only count the cookie header once since HTTP/3 splits it into
            // multiple headers to aid compression
            if (!countedCookie) {
                headerCount++;
                countedCookie = true;
            }
        } else {
            headerCount++;
        }
        headerSize += inc;
        if (maxHeaderCount >= 0 && headerCount > maxHeaderCount) {
            throw new Http3Exception(sm.getString("qpackdecoder.headerCountExceeded",
                    Integer.valueOf(headerCount), Integer.valueOf(maxHeaderCount)),
                    Http3Error.H3_MESSAGE_ERROR);
        }
        if (maxHeaderSize >= 0 && headerSize > maxHeaderSize) {
            throw new Http3Exception(sm.getString("qpackdecoder.headerSizeExceeded",
                    Integer.valueOf(headerSize), Integer.valueOf(maxHeaderSize)),
                    Http3Error.H3_MESSAGE_ERROR);
        }
        if (log.isDebugEnabled()) {
            log.debug("QPACK emit: name=" + name + " value=" + value + " count=" + headerCount + " size=" + headerSize);
        }
        emitter.emitHeader(name, value);
    }


    /*
     * Synchronized: the limits are read by decodes running on other threads
     * under this decoder's monitor.
     */
    public synchronized void setMaxHeaderCount(int maxHeaderCount) {
        this.maxHeaderCount = maxHeaderCount;
    }


    public synchronized void setMaxHeaderSize(int maxHeaderSize) {
        this.maxHeaderSize = maxHeaderSize;
    }


    /**
     * Returns the total number of entries inserted into the dynamic table
     * so far (never decremented on eviction). A stream blocked by
     * {@link QpackBlockedException} can be unblocked once this value
     * reaches or exceeds
     * {@link QpackBlockedException#getRequiredInsertCount()}.
     *
     * @return The total number of inserts (RFC 9204 Section 3.2.4)
     */
    public long getTotalInserts() {
        return totalInserts;
    }


    /**
     * Reconstructs the Required Insert Count from its encoded value per
     * RFC 9204 Section 4.5.1.1.
     *
     * @param encoded The encoded insert count (iRP m=8 value)
     * @return The Required Insert Count, or -1 if the value could not have
     *         been produced by a conformant encoder. Long because the count
     *         lives in the unbounded absolute index space of RFC 9204
     *         Section 3.2.4 (TotalNumberOfInserts never decreases, so it
     *         grows past 2^31 on connections with more than 2^31 lifetime
     *         inserts).
     */
    private long reconstructReqInsertCount(int encoded) {
        if (encoded == 0) {
            return 0;
        }
        // Per RFC 9204 Section 4.5.1.1, MaxEntries is the maximum capacity
        // of the dynamic table as specified by the decoder (Section 3.2.3,
        // i.e. the hard limit advertised via
        // SETTINGS_QPACK_MAX_TABLE_CAPACITY) divided by 32. The current
        // (soft) capacity must not be used here because the encoder may
        // reduce it at any time via Set Dynamic Table Capacity (Section
        // 4.3.1) while the Required Insert Count encoding still uses the
        // maximum.
        int maxEntries = maxTableSizeHard / 32;
        if (maxEntries == 0) {
            return -1;
        }
        int fullRange = 2 * maxEntries;
        if (encoded > fullRange) {
            return -1;
        }
        long maxValue = totalInserts + maxEntries;
        // MaxWrapped is the largest possible value of ReqInsertCount that is
        // 0 mod 2 * MaxEntries
        long maxWrapped = (maxValue / fullRange) * fullRange;
        long ric = maxWrapped + encoded - 1;
        // If ReqInsertCount exceeds MaxValue, the encoder's value must have
        // wrapped one fewer time
        if (ric > maxValue) {
            if (ric <= fullRange) {
                return -1;
            }
            ric -= fullRange;
        }
        // A value of 0 must be encoded as 0
        if (ric == 0) {
            return -1;
        }
        return ric;
    }
}

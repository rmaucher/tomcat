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
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.http.parser.HttpParser;
import org.apache.tomcat.util.res.StringManager;


/**
 * QPACK encoder per RFC 9204.
 * <p>
 * Encodes header blocks for response streams.
 * <p>
 * Note: this server's encoder never inserts into a dynamic table. It emits
 * only static table references (RFC 9204 Appendix A) and literal
 * representations, so no encoder instructions are ever sent and every header
 * block is decodable with an empty dynamic table (RFC 9204 Section 4.4).
 * The dynamic-table forms of the {@code isStatic} parameter of
 * {@link #encodeIndexed} and {@link #encodeNameRefLiteral} are therefore
 * unreachable with the current encoding policy: they are deliberate
 * groundwork for a future dynamic-table encoder, not dead branches awaiting
 * cleanup.
 */
public class QpackEncoder {

    private static final Log log = LogFactory.getLog(QpackEncoder.class);
    private static final StringManager sm = StringManager.getManager(QpackEncoder.class);


    /**
     * Encoding state.
     */
    public enum State {
        COMPLETE,
        UNDERFLOW
    }


    private int headersIterator = -1;
    private boolean firstPass = true;
    private boolean prefixPending = false;
    private MimeHeaders currentHeaders;


    /**
     * Encodes response headers into the target buffer.
     *
     * @param headers The response headers to encode
     * @param target The output buffer
     * @return The encoding state
     */
    public State encode(MimeHeaders headers, ByteBuffer target) {
        return encode(headers, target, true);
    }


    /**
     * Abandons any in-progress (UNDERFLOW'd) header block encoding.
     * <p>
     * {@link #encode(MimeHeaders, ByteBuffer)} resumes an interrupted
     * encoding from {@code headersIterator} when the same
     * {@link MimeHeaders} instance is passed again. Callers that start a
     * fresh header block (a new response, an error response, early hints or
     * trailers) must call this first so stale partial state from an aborted
     * encoding cannot be applied to the new header set.
     */
    public void resetEncodingState() {
        headersIterator = -1;
        firstPass = true;
        prefixPending = false;
        currentHeaders = null;
    }


    public State encode(MimeHeaders headers, ByteBuffer target, boolean forceLowerCase) {
        int it = headersIterator;
        if (headersIterator == -1) {
            it = 0;
            currentHeaders = headers;
            prefixPending = true;
            // Debug: log all headers being encoded
            if (log.isDebugEnabled()) {
                StringBuilder sb = new StringBuilder("QPACK encode headers (");
                sb.append(headers.size()).append("): ");
                for (int i = 0; i < headers.size(); i++) {
                    sb.append('[').append(i).append("]").append(headers.getName(i).toString()).append("=").append(headers.getValue(i).toString()).append(" ");
                }
                log.debug(sb.toString());
            }
        } else if (headers != currentHeaders) {
            throw new IllegalStateException();
        }

        // Write QPACK header block prefix (RFC 9204 Section 4.5.1) before field representations.
        // Required Insert Count (iRP m=8) = 0: decoder doesn't need to wait for any
        // dynamic table entries before decoding this header block.
        // Sign/Delta Base (iRP m=7): Sign=0, Delta Base=0 -> 0x00
        // Base = Required Insert Count + Delta Base = 0 + 0 = 0 (RFC 9204 Section 4.5.1.2)
        if (prefixPending) {
            if (target.remaining() < 2) {
                headersIterator = it;
                return State.UNDERFLOW;
            }
            target.put((byte) 0x00); // Required Insert Count = 0
            target.put((byte) 0x00); // Sign=0, Delta Base=0
            prefixPending = false;
        }

        while (it < currentHeaders.size()) {
            String name = currentHeaders.getName(it).toString();
            if (forceLowerCase) {
                name = name.toLowerCase(Locale.US);
            }

            boolean skip = false;

            // Field names must be non-empty tokens (RFC 7230 Section 3.2,
            // RFC 9114 Section 4.2); pseudo-header fields are identified by
            // their leading ':' and are not tokens. Reject a name that
            // cannot carry either form before looking at its first
            // character (an empty name has none): the decode path
            // (emitHeader) rejects such fields on receipt, and dropping the
            // field here keeps a container-supplied invalid name (for
            // example an empty-named trailer built straight from the
            // servlet trailer map) from aborting the response mid-flight.
            boolean pseudo = !name.isEmpty() && name.charAt(0) == ':';
            if (!pseudo && !HttpParser.isToken(name)) {
                skip = true;
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("qpackEncoder.invalidNameSkipped",
                            name));
                }
            } else if (firstPass) {
                if (!pseudo) {
                    skip = true;
                }
            } else {
                if (pseudo) {
                    skip = true;
                }
            }

            if (!skip) {
                String value = currentHeaders.getValue(it).toString();

                // Header values are UTF-8 strings on the wire (RFC 9114
                // Section 4.2, RFC 9204 Section 4.1.2); sizes must be computed
                // in bytes, not chars.
                byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
                byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);

                StaticTableMatch match = lookupStaticTable(name, value);
                // Worst case per header: 2 byte field prefix + iRP continuation
                // bytes for the name index/name length/value length.
                int required = 22 + nameBytes.length + valueBytes.length;

                if (target.remaining() < required) {
                    headersIterator = it;
                    return State.UNDERFLOW;
                }

                if (log.isTraceEnabled()) {
                    log.trace(sm.getString("qpackEncoder.encodeHeader", name, value));
                }

                if (match.exact() >= 0 && shouldIndex(name, value)) {
                    // Indexed Field Line (RFC 9204 Section 4.5.2)
                    encodeIndexed(target, match.exact(), true);
                } else if (match.exact() < 0 && match.nameOnly() >= 0) {
                    // The name is in the table only as a name-only entry:
                    // Literal with name reference (RFC 9204 Section 4.5.4)
                    encodeNameRefLiteral(target, match.nameOnly(), true, valueBytes);
                } else if (match.firstName() >= 0) {
                    // An exact match is unavailable (value differs, or the pair
                    // must not be indexed): reference the name and carry the
                    // value literally (RFC 9204 Section 4.5.4)
                    encodeNameRefLiteral(target, match.firstName(), true, valueBytes);
                } else {
                    // Literal with literal name (RFC 9204 Section 4.5.6)
                    encodeNameValueLiteral(target, nameBytes, valueBytes);
                }

                // The encoder never inserts into a dynamic table and never
                // sends encoder instructions: only static table references
                // and literal representations are used, which ensures the
                // header block is decodable with an empty dynamic table.
            }

            if (++it == currentHeaders.size() && firstPass) {
                firstPass = false;
                it = 0;
            }
        }

        headersIterator = -1;
        firstPass = true;
        prefixPending = false;
        currentHeaders = null;
        return State.COMPLETE;
    }


    /**
     * Encodes an Indexed Field Line (RFC 9204 Section 4.5.2).
     * Format: 1 T Index(6+)
     * T=1 for static table, T=0 for dynamic table.
     *
     * @param target        Output buffer
     * @param index         Static table index or dynamic table relative index
     * @param isStatic      true for static table, false for dynamic table
     */
    private void encodeIndexed(ByteBuffer target, int index, boolean isStatic) {
        // Per RFC 9204 Section 4.5.2: 1 T iRP(m=6) Index
        Qpack.encodeIrp(target, 0x80 | (isStatic ? 0x40 : 0x00), 6, index);
    }


    /**
     * Encodes a Literal Field Line with Name Reference (RFC 9204 Section 4.5.4).
     * Format: 01 N T NameIndex(4+) Value
     * N=1 (never indexed - the encoder never inserts into a dynamic table),
     * T=1 for static, T=0 for dynamic.
     *
     * @param target        Output buffer
     * @param index         Static table index or dynamic table relative index
     * @param isStatic      true for static table, false for dynamic table
     * @param valueBytes    Literal value (UTF-8 encoded)
     */
    private void encodeNameRefLiteral(ByteBuffer target, int index, boolean isStatic, byte[] valueBytes) {
        // Per RFC 9204 Section 4.5.4: 01 N T iRP(m=4) Name Index
        int nBit = 1; // never indexed - encoder instructions may not reach client in time
        Qpack.encodeIrp(target, 0x40 | (nBit << 5) | (isStatic ? 0x10 : 0x00), 4, index);
        encodeString(target, valueBytes);
    }


    /**
     * Encodes a Literal Field Line with Literal Name (RFC 9204 Section 4.5.6).
     * Format: 001 N H NameLen(3+) Name Value
     * N=1 (never indexed - the encoder never inserts into a dynamic table),
     * H=0 (not Huffman for name).
     *
     * @param target    Output buffer
     * @param nameBytes Literal name (UTF-8 encoded)
     * @param valueBytes Literal value (UTF-8 encoded)
     */
    private void encodeNameValueLiteral(ByteBuffer target, byte[] nameBytes, byte[] valueBytes) {
        // Per RFC 9204 Section 4.5.6: 001 N H NameLen(3+) + Name + Value
        // The name is a 4-bit prefix string literal: H bit + 3-bit prefix length.
        int nBit = 1; // never indexed - encoder instructions may not reach client in time
        int hBit = 0; // not Huffman for name
        Qpack.encodeIrp(target, 0x20 | (nBit << 4) | (hBit << 3), 3, nameBytes.length);
        target.put(nameBytes);
        encodeString(target, valueBytes);
    }


    private void encodeString(ByteBuffer target, byte[] s) {
        // Per RFC 9204 Section 4.1.2: String Literal: H iRP(m=7) String Length
        // H = 0 (string is not Huffman-encoded). The length is the number of
        // UTF-8 bytes, not the number of Java chars.
        Qpack.encodeIrp(target, 0, 7, s.length);
        target.put(s);
    }


    private boolean shouldIndex(String name, String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        switch (name) {
            case "content-length":
            case "date":
            case "etag":
            case "authorization":
            case "set-cookie":
            case "cookie":
                return false;
            default:
                return true;
        }
    }


    /*
     * Usable static table representations (RFC 9204 Appendix A) of one
     * (name, value) pair, as found by lookupStaticTable(): the exact
     * (name, value) match, the first name-only entry carrying the name
     * (value {@code null}, e.g. :authority - referenceable by name with a
     * literal value) and the first entry carrying the name at all, each -1
     * when absent.
     */
    private record StaticTableMatch(int exact, int nameOnly, int firstName) {
    }


    /*
     * Scans the static table once for all three representations of
     * (name, value); the scan stops at the exact match, because the
     * name-reference candidates are only consulted when no exact match is
     * used.
     */
    private StaticTableMatch lookupStaticTable(String name, String value) {
        int exact = -1;
        int nameOnly = -1;
        int firstName = -1;
        for (int i = 0; i < Qpack.STATIC_TABLE_LENGTH; i++) {
            Qpack.HeaderField sf = Qpack.STATIC_TABLE[i];
            if (!sf.name.equals(name)) {
                continue;
            }
            if (firstName < 0) {
                firstName = i;
            }
            if (sf.value == null) {
                // Name-only entry (e.g., :authority). Remember it so a
                // Literal Field Line with Name Reference can be used.
                if (nameOnly < 0) {
                    nameOnly = i;
                }
            } else if (sf.value.equals(value)) {
                exact = i;
                break;
            }
        }

        return new StaticTableMatch(exact, nameOnly, firstName);
    }


}

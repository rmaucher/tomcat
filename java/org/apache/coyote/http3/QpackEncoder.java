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
     * <p>
     * The encoder may return {@link State#UNDERFLOW} when the target does not
     * have room for the complete block. Resuming an interrupted encoding
     * requires passing the SAME {@link MimeHeaders} instance and a target
     * buffer that still contains the bytes already written (the field-section
     * prefix and any field lines emitted before the underflow). Passing a
     * different headers instance throws {@link IllegalStateException}, and a
     * fresh target silently loses the prefix and earlier field lines. Call
     * {@link #resetEncodingState()} before starting an unrelated header block.
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


    /**
     * Encodes response headers into the target buffer, optionally forcing
     * field names to lower case.
     * <p>
     * {@code forceLowerCase=false} is intended only for tests or future
     * callers that know they already supply names in the exact form they
     * want. It can encode uppercase field names, which HTTP/3 requires to be
     * lowercase (RFC 9114 Section 4.2). Production response encoding uses the
     * two-argument overload, which forces lower case. The streaming/resume
     * contract is the same as for {@link #encode(MimeHeaders, ByteBuffer)}:
     * resume with the same headers instance and a target that retains the
     * bytes written before the underflow.
     *
     * @param headers The response headers to encode
     * @param target The output buffer
     * @param forceLowerCase Whether to lower-case field names before encoding
     * @return The encoding state
     */
    public State encode(MimeHeaders headers, ByteBuffer target, boolean forceLowerCase) {
        int it = headersIterator;
        if (headersIterator == -1) {
            it = 0;
            currentHeaders = headers;
            prefixPending = true;
            // Header values may contain credentials, cookies or tokens;
            // keep the dump at TRACE like HTTP/2's per-header logging.
            if (log.isTraceEnabled()) {
                StringBuilder sb = new StringBuilder("QPACK encode headers (");
                sb.append(headers.size()).append("): ");
                for (int i = 0; i < headers.size(); i++) {
                    sb.append('[').append(i).append(']').append(
                            Http3Log.printable(headers.getName(i).toString()))
                            .append("=").append(Http3Log.printable(
                                    headers.getValue(i).toString())).append(' ');
                }
                log.trace(sb.toString());
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

            boolean skip = false;

            // Field names must be non-empty tokens (RFC 7230 Section 3.2,
            // RFC 9114 Section 4.2); pseudo-header fields are identified by
            // their leading ':' and are not tokens. Validate the original
            // name before any case conversion: lower-casing first can fold a
            // non-ASCII character into a different ASCII name (for example
            // U+212A KELVIN SIGN becomes "k") and silently turn an invalid
            // name into a valid one. Reject a name that cannot carry either
            // form before looking at its first character (an empty name has
            // none): the decode path (emitHeader) rejects such fields on
            // receipt, and dropping the field here keeps a container-supplied
            // invalid name (for example an empty-named trailer built straight
            // from the servlet trailer map) from aborting the response
            // mid-flight.
            boolean pseudo = !name.isEmpty() && name.charAt(0) == ':';
            if (!pseudo && !HttpParser.isToken(name)) {
                skip = true;
                // The HTTP/2 response path logs a warning when it removes an
                // invalid header. Match that visibility here rather than
                // silently dropping an application-supplied field (which may
                // be a security header such as CSP or HSTS). The invalid
                // header is visited in both encoder passes, so warn only in
                // the first pass to avoid a duplicate diagnostic.
                if (firstPass) {
                    log.warn(sm.getString("qpackEncoder.invalidNameSkipped",
                            Http3Log.printable(name)));
                }
            } else {
                if (forceLowerCase) {
                    name = toLowerCase(name);
                }
                if (firstPass) {
                    if (!pseudo) {
                        skip = true;
                    }
                } else {
                    if (pseudo) {
                        skip = true;
                    }
                }
            }

            if (!skip) {
                String value = currentHeaders.getValue(it).toString();
                if (!isEncodableValue(value)) {
                    // A null value, a character above ISO-8859-1, or a
                    // forbidden control character cannot be emitted as a
                    // valid HTTP field value. Narrowing a wider character
                    // would change the value (for example U+010A would
                    // become LF), so drop the field rather than silently
                    // corrupting it or emitting an invalid field line. Log
                    // at warning level, as the HTTP/2 response path does for
                    // an invalid header, so an application-supplied security
                    // field is not lost without any diagnostic.
                    logInvalidValueSkipped(name);
                } else {
                    // HTTP field values are byte strings (RFC 9110 Section
                    // 5.5, obs-text). Tomcat stores them as ISO-8859-1
                    // characters, as HTTP/1.1 and HPACK do; encode one wire
                    // byte per char rather than re-encoding as UTF-8 (which
                    // would change the bytes and fail to round-trip through
                    // Qpack.decodeString()).
                    byte[] nameBytes = toFieldBytes(name);
                    byte[] valueBytes = toValueBytes(value);

                    StaticTableMatch match = lookupStaticTable(name, value);
                    // Worst case per header: 2 byte field prefix + iRP
                    // continuation bytes for the name index/name length/value
                    // length. 22 bytes of slack covers the widest current
                    // representation (a literal name plus an int-range value
                    // length: 1 representation byte, up to 2 index bytes and
                    // up to 10 length continuation bytes). Use long so two
                    // near-Integer.MAX_VALUE strings cannot overflow the sum
                    // into a negative value and bypass the capacity check.
                    // Revisit the slack if a representation with a larger
                    // fixed overhead is added.
                    long required = 22L + nameBytes.length + valueBytes.length;

                    if (target.remaining() < required) {
                        headersIterator = it;
                        return State.UNDERFLOW;
                    }

                    if (log.isTraceEnabled()) {
                        log.trace(sm.getString("qpackEncoder.encodeHeader",
                                Http3Log.printable(name),
                                Http3Log.printable(value)));
                    }

                    if (match.exact() >= 0 &&
                            shouldUseIndexedStaticRepresentation(name, value)) {
                        // Indexed Field Line (RFC 9204 Section 4.5.2)
                        encodeIndexed(target, match.exact(), true);
                    } else if (match.exact() < 0 && match.nameOnly() >= 0) {
                        // The table carries this name with an empty value:
                        // Literal with name reference (RFC 9204 Section 4.5.4)
                        encodeNameRefLiteral(target, match.nameOnly(), true,
                                valueBytes);
                    } else if (match.firstName() >= 0) {
                        // An exact match is unavailable (value differs, or the
                        // pair must not be indexed): reference the name and
                        // carry the value literally (RFC 9204 Section 4.5.4)
                        encodeNameRefLiteral(target, match.firstName(), true,
                                valueBytes);
                    } else {
                        // Literal with literal name (RFC 9204 Section 4.5.6)
                        encodeNameValueLiteral(target, nameBytes, valueBytes);
                    }

                    // The encoder never inserts into a dynamic table and never
                    // sends encoder instructions: only static table references
                    // and literal representations are used, which ensures the
                    // header block is decodable with an empty dynamic table.
                }
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
     * @param valueBytes    Literal value (ISO-8859-1, one byte per char)
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
     * @param nameBytes Literal name (ISO-8859-1, one byte per char)
     * @param valueBytes Literal value (ISO-8859-1, one byte per char)
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
        // wire bytes.
        Qpack.encodeIrp(target, 0, 7, s.length);
        target.put(s);
    }


    /*
     * Converts a field name or field value string to its one-byte-per-char
     * ISO-8859-1 wire form. HTTP/3 field names and values are byte strings
     * (RFC 9110 Sections 5.1 and 5.5); Tomcat stores them as ISO-8859-1
     * characters, matching HTTP/1.1 and HPACK, and UTF-8 re-encoding would
     * change non-ASCII values and make an HTTP/3 round trip produce a
     * different string from the request decode path. Names are validated as
     * tokens by encode(); the shared field-vchar check accepts every valid
     * token name. Values that encode() has already validated pass
     * {@code validate=false} to avoid a second scan.
     */
    private static byte[] toFieldBytes(String s, boolean validate) {
        if (validate && !isEncodableValue(s)) {
            throw new IllegalArgumentException(
                    sm.getString("qpackEncoder.invalidValue"));
        }
        byte[] bytes = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            bytes[i] = (byte) s.charAt(i);
        }
        return bytes;
    }


    private static byte[] toFieldBytes(String s) {
        return toFieldBytes(s, true);
    }


    private static byte[] toValueBytes(String s) {
        return toFieldBytes(s, false);
    }


    /*
     * Lower-cases only ASCII A-Z characters in a field name. Response header
     * names supplied by Tomcat are already lower case, so the common path
     * avoids the allocation. ASCII-only folding is deliberate: the HTTP/3
     * field-name grammar is ASCII (RFC 9114 Section 4.2), and a Unicode-aware
     * lower-case operation could change an invalid non-ASCII name into a
     * different valid ASCII name.
     */
    private static String toLowerCase(String name) {
        StringBuilder result = null;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                if (result == null) {
                    result = new StringBuilder(name);
                }
                result.setCharAt(i, (char) (c + ('a' - 'A')));
            }
        }
        return result == null ? name : result.toString();
    }


    /*
     * Whether a field can produce an encoded field line: a valid token name
     * and a valid field value. Used by the HTTP/3 processor to avoid writing
     * a HEADERS frame that contains only the QPACK prefix after peer-limit
     * reduction or value filtering has dropped every trailer field.
     */
    static boolean isEncodableField(String name, String value) {
        return name != null && HttpParser.isToken(name) &&
                isEncodableValue(value);
    }


    /*
     * Emits the diagnostic for an application-supplied field value that
     * cannot be represented on the wire. Shared by encode() and the trailer
     * send path: when every trailer value is filtered out, encode() is never
     * called, but the dropped fields must still produce the same warning.
     */
    static void logInvalidValueSkipped(String name) {
        log.warn(sm.getString("qpackEncoder.invalidValueSkipped",
                Http3Log.printable(name)));
    }


    /*
     * Whether a field name or field value string can be represented by one
     * wire byte per char and contains only characters permitted in an HTTP
     * field value (a valid token name is also a field-vchar string).
     * RFC 9110 Section 5.5 defines field-value as *field-content, where
     * field-content is field-vchar [ 1*( SP / HTAB / field-vchar ) field-vchar ]:
     * a value therefore has no leading or trailing whitespace. Values outside
     * this set are dropped by encode() (see the qpackEncoder.invalidValueSkipped
     * message): a non-Latin-1 value must not be silently narrowed, and emitting
     * a CTL as a raw field byte would let an HTTP/1.1 translation layer see a
     * header or message boundary that HTTP/3's length-prefixed framing did not
     * intend.
     */
    private static boolean isEncodableValue(String value) {
        if (value == null) {
            return false;
        }
        int length = value.length();
        for (int i = 0; i < length; i++) {
            char c = value.charAt(i);
            if (i == 0 || i == length - 1) {
                // The first and last character must be field-vchar (no leading
                // or trailing SP/HTAB).
                if (!HttpParser.isFieldVChar(c)) {
                    return false;
                }
            } else {
                if (!HttpParser.isFieldContent(c)) {
                    return false;
                }
            }
        }
        return true;
    }


    /**
     * Whether an exact static-table match may be emitted as an Indexed Field
     * Line (RFC 9204 Section 4.5.2) rather than as a Literal Field Line with
     * Name Reference (Section 4.5.4). This is only a choice between two
     * representations of the static table; the encoder never inserts into a
     * dynamic table. Connection framing metadata (content-length/date/etag)
     * and values likely to vary use the literal name-reference form. The
     * sensitive-name cases (authorization/set-cookie/cookie) are defensive:
     * their static entries have empty values, so they cannot produce the
     * non-null exact match that reaches this method.
     *
     * @param name  The (lower-cased) field name
     * @param value The field value
     *
     * @return {@code true} if the exact static match may be indexed
     */
    private boolean shouldUseIndexedStaticRepresentation(String name,
            String value) {
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
     * (name, value) match, the first entry carrying the name with an empty
     * value (value {@code null}, e.g. :authority - referenceable by name with
     * a literal value) and the first entry carrying the name at all, each -1
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
                // Entry carrying the name with an empty value (e.g.,
                // :authority). Remember it so a Literal Field Line with Name
                // Reference can be used.
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

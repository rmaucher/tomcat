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

import org.apache.coyote.http2.HPackHuffman;
import org.apache.coyote.http2.HpackException;


/**
 * Decoding of QPACK Huffman-coded string literals. Per RFC 9204
 * Section 4.1.2, QPACK uses the Huffman code defined in Appendix B of
 * RFC 7541 (the HPACK Huffman code) unmodified, so the decoding itself is
 * shared with HTTP/2's {@link HPackHuffman}. This class adapts the HTTP/2
 * exception type to the QPACK one.
 * <p>
 * Decode-only: a decoder must handle Huffman-coded input (it is optional
 * for a sender to use it), while this connector's response encoder always
 * emits non-Huffman literals ({@code QpackEncoder} writes the H bit as
 * {@code 0}), so no encoder is needed here.
 * </p>
 */
final class QpackHuffman {

    private QpackHuffman() {
        // Hide default constructor
    }


    /**
     * Decodes a QPACK Huffman-encoded string. Per RFC 9204 Section 4.1.2
     * this validates only the Huffman coding itself (EOS symbol, padding
     * and prefix errors are decompression failures). HTTP message-level
     * syntax of the decoded characters is deliberately not checked here:
     * field lines are classified as malformed messages (stream error of
     * type H3_MESSAGE_ERROR) by the message layer
     * ({@code Http3Processor.emitHeader}) independently of how the literal
     * was encoded, and RFC 9204 Section 3.2 places no character-level
     * restriction on dynamic table insertions.
     *
     * @param data The byte buffer
     * @param length The number of bytes to decode
     * @param target The target StringBuilder
     * @throws QpackException If the Huffman coding is invalid
     */
    public static void decode(ByteBuffer data, int length, StringBuilder target)
            throws QpackException {
        try {
            HPackHuffman.decode(data, length, target);
        } catch (HpackException e) {
            throw new QpackException(e.getMessage(), e);
        }
    }
}

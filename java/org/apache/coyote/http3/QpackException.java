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

import java.io.Serial;


/**
 * Thrown when a QPACK decoding or encoding error occurs.
 * <p>
 * Every {@code QpackException} other than {@link QpackBlockedException}
 * and {@link QpackValueTooLargeException} is a <em>fatal</em> QPACK
 * error: per RFC 9204 the affected <em>connection</em> (not just the
 * stream) MUST be failed, because the {@link QpackDecoder} is shared by
 * all streams of a connection:
 * </p>
 * <ul>
 * <li>Field section errors (invalid reference per Section 2.2.3, invalid
 * static table index per Section 3.1, impossible Encoded Insert Count per
 * Section 4.5.1.1, Huffman decode failures): connection error
 * {@code H3_QPACK_DECOMPRESSION_FAILED} (0x0200).</li>
 * <li>Encoder stream instruction errors: connection error
 * {@code H3_QPACK_ENCODER_STREAM_ERROR} (0x0201).</li>
 * <li>Decoder stream instruction errors: connection error
 * {@code H3_QPACK_DECODER_STREAM_ERROR} (0x0202).</li>
 * </ul>
 * <p>
 * The cases that are <em>not</em> fatal connection errors are signaled
 * differently:
 * </p>
 * <ul>
 * <li>Blocked streams (field section requires entries not yet inserted,
 * RFC 9204 Section 2.2.1): {@link QpackBlockedException} - not an error
 * at all; block the stream and re-decode later.</li>
 * <li>Oversize decode values (an integer or string larger than this
 * implementation can decode, RFC 9204 Section 7.4):
 * {@link QpackValueTooLargeException} - a <em>stream</em> error of type
 * {@code QPACK_DECOMPRESSION_FAILED} when met on a request stream, still
 * a connection error of the appropriate type on the encoder or decoder
 * stream.</li>
 * <li>Size-limit violations on a request stream (decoded field section
 * exceeds the advertised {@code max_field_section_size} or header
 * count, RFC 9114 Section 4.2.2): {@link Http3Exception} with
 * {@code H3_MESSAGE_ERROR} - fail only the affected stream.</li>
 * </ul>
 */
public class QpackException extends Exception {

    @Serial
    private static final long serialVersionUID = 1L;


    QpackException(String msg) {
        super(msg);
    }


    QpackException(String msg, Throwable cause) {
        super(msg, cause);
    }
}

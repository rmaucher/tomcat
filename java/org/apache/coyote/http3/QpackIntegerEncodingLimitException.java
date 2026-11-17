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
 * Signals that an encoded prefixed integer used more continuation octets
 * than this implementation accepts (RFC 9204 Section 7.4).
 * <p>
 * This is an implementation limit on the encoded length, not on the decoded
 * value: an encoder may represent a perfectly valid value with redundant
 * continuation groups. The decoder aborts on the length before it knows the
 * value, so the condition must not be classified as an invalid reference or
 * an impossible count. RFC 9204 Section 7.4 makes the encoded-length limit a
 * stream error of type {@code QPACK_DECOMPRESSION_FAILED} on a request
 * stream (and a connection error on the encoder or decoder stream, which is
 * where {@code Http3ConnectionManager} maps it).
 */
class QpackIntegerEncodingLimitException extends QpackValueTooLargeException {

    @Serial
    private static final long serialVersionUID = 1L;


    QpackIntegerEncodingLimitException(String msg) {
        super(msg);
    }
}

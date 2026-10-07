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
 * Signals that an encoded integer or string value was larger than this
 * implementation is able to decode (RFC 9204 Section 7.4).
 * <p>
 * RFC 9204 Section 7.4 scopes the failure by stream: met on a request
 * stream it MUST be treated as a <em>stream</em> error of type
 * {@code QPACK_DECOMPRESSION_FAILED} (only the affected stream is reset,
 * the connection and its other streams survive); met on the QPACK encoder
 * or decoder stream it is a connection error of the appropriate type.
 * Since the same decode primitives back both contexts, the distinction is
 * made by the consumer: {@code Http3Processor} resets the request stream,
 * while the {@code Http3ConnectionManager} QPACK stream handlers keep
 * treating it as a connection error via the {@link QpackException} catch.
 * </p>
 * <p>
 * Failing only the stream is safe for the shared {@link QpackDecoder}:
 * an oversize value is rejected before it can mutate any decoder state.
 * </p>
 */
class QpackValueTooLargeException extends QpackException {

    @Serial
    private static final long serialVersionUID = 1L;


    QpackValueTooLargeException(String msg) {
        super(msg);
    }
}

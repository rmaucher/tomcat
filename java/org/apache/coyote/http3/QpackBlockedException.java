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
 * Indicates that a field section references dynamic table entries that
 * have not been inserted yet (RFC 9204 Section 2.2.1).
 * <p>
 * Per the RFC this is not an error: a decoder that supports blocked
 * streams would block the stream and re-decode the field section once the
 * required entries have been inserted. Whether this implementation
 * supports blocked streams is configurable via the
 * {@code qpackBlockedStreams} property of {@code AbstractHttp3Protocol}, which
 * also drives the advertised {@code QPACK_BLOCKED_STREAMS} value. With a
 * positive value the caller blocks the stream until the required entries
 * have been inserted (or the wait times out); with the default value of
 * {@code 0} the caller fails the connection with
 * {@code H3_QPACK_DECOMPRESSION_FAILED} instead.
 */
public class QpackBlockedException extends QpackException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final long requiredInsertCount;


    QpackBlockedException(long requiredInsertCount) {
        super("QPACK field section blocked: required insert count " + requiredInsertCount);
        this.requiredInsertCount = requiredInsertCount;
    }


    /**
     * Returns the number of dynamic table entries that must have been
     * inserted (i.e. {@link QpackDecoder#getTotalInserts()}) before the
     * field section can be decoded (RFC 9204 Section 2.2.1).
     *
     * @return The required insert count
     */
    public long getRequiredInsertCount() {
        return requiredInsertCount;
    }
}

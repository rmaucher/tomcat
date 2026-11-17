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
 * Signals an HTTP/3 protocol error with its associated error code (RFC 9114
 * Section 8.1). The exception is part of the public QPACK decoder emitter
 * contract ({@link QpackDecoder.HeaderEmitter}); its constructors are public so
 * an external emitter implementation can signal the declared checked
 * exceptions. The concrete stream-scoped subclass remains an internal
 * implementation detail.
 */
public class Http3Exception extends Exception {

    @Serial
    private static final long serialVersionUID = 1L;

    private final Http3Error error;


    public Http3Exception(String msg, Http3Error error) {
        super(msg);
        this.error = error;
    }


    public Http3Exception(String msg, Http3Error error, Throwable cause) {
        super(msg, cause);
        this.error = error;
    }


    Http3Error getError() {
        return error;
    }


    /**
     * Returns the HTTP/3 error code carried by this exception (RFC 9114
     * Section 8.1).
     *
     * @return The HTTP/3 error code
     */
    public long getErrorCode() {
        return error.getCode();
    }
}

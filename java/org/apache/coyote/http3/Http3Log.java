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

import java.nio.charset.StandardCharsets;

import org.apache.tomcat.util.http.HeaderUtil;


/**
 * Log-value escaping for HTTP/3. Field names and values can contain arbitrary
 * bytes on the wire (QPACK strings are byte strings), including CR, LF and
 * other control characters. Logging them unescaped lets a peer forge log
 * records or split lines (CWE-117). This helper renders every non-printable
 * byte in {@code 0xNN} form, matching the HTTP/1.1
 * {@link HeaderUtil#toPrintableString(byte[], int, int)} representation.
 */
final class Http3Log {

    private Http3Log() {
        // Hide default constructor
    }


    /**
     * Returns a printable representation of the given value. Visible ASCII
     * characters are preserved; bytes outside 0x20-0x7E are rendered as
     * {@code 0xNN}. A null value is rendered as {@code null}.
     *
     * @param value The value to render
     *
     * @return The printable representation
     */
    static String printable(String value) {
        if (value == null) {
            return "null";
        }
        byte[] bytes = value.getBytes(StandardCharsets.ISO_8859_1);
        return HeaderUtil.toPrintableString(bytes, 0, bytes.length);
    }
}

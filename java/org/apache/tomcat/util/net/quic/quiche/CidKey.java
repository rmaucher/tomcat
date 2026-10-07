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
package org.apache.tomcat.util.net.quic.quiche;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;

/**
 * Immutable key for a QUIC connection ID, used for the endpoint's CID to
 * connection demux map. Wraps a defensive copy of the ID bytes so the key is
 * independent of the (reused) native packet-parse buffer the value is read
 * from.
 */
final class CidKey {

    private final byte[] cid;

    CidKey(byte[] cid) {
        this.cid = cid.clone();
    }

    CidKey(MemorySegment buffer, int length) {
        byte[] cid = new byte[length];
        MemorySegment.copy(buffer, ValueLayout.JAVA_BYTE, 0, cid, 0, length);
        this.cid = cid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof CidKey)) {
            return false;
        }
        return Arrays.equals(cid, ((CidKey) o).cid);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(cid);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(cid.length * 2);
        for (byte b : cid) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}

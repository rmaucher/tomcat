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
package org.apache.tomcat.util.net.quic.openssl;

import java.net.InetAddress;


/**
 * Fail-closed platform implementation used when no platform implementation is
 * available. The endpoint never binds with this instance; the reason is
 * reported to the operator instead.
 */
final class QuicPlatformUnavailable extends QuicPlatformSupport {

    private final String osName;
    private final String arch;
    private final String reason;

    QuicPlatformUnavailable(String osName, String arch, String reason) {
        this.osName = osName;
        this.arch = arch;
        this.reason = reason;
    }

    @Override
    PlatformId id() {
        return PlatformId.UNKNOWN;
    }

    @Override
    String name() {
        return "unavailable:" + osName + "/" + arch;
    }

    @Override
    boolean isAvailable() {
        return false;
    }

    @Override
    String unavailableReason() {
        return reason;
    }

    @Override
    Abi abi() {
        return Abi.placeholder();
    }

    @Override
    BoundUdpSocket bindUdpSocket(InetAddress address, int port,
            UdpSocketOptions options) throws QuicPlatformException {
        throw new QuicPlatformException("bindUdpSocket", 0, reason, false,
                false, false);
    }

    @Override
    void close(SocketHandle socket) {
        // No native state exists.
    }

    @Override
    int openSslFd(SocketHandle socket) throws QuicPlatformException {
        throw new QuicPlatformException("openSslFd", 0, reason, false,
                false, false);
    }

    @Override
    String describe(SocketHandle socket) {
        return "unavailable";
    }

    @Override
    boolean isIPv4Family(int nativeFamily) {
        return false;
    }

    @Override
    boolean isIPv6Family(int nativeFamily) {
        return false;
    }

    @Override
    int decodePeerPort(int rawPort) {
        return rawPort;
    }

    @Override
    Wakeup createWakeup(SocketHandle socket) throws QuicPlatformException {
        throw new QuicPlatformException("createWakeup", 0, reason, false,
                false, false);
    }
}

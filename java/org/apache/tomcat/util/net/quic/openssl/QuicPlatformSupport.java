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

import java.io.IOException;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetAddress;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;


/**
 * Operating-system abstraction for the OpenSSL QUIC endpoint.
 * <p>
 * All native socket, wake-up, address-family, error and ABI details are owned
 * by an implementation of this class. The endpoint and the other QUIC classes
 * use the semantic operations exposed here so that a new operating-system
 * implementation can be added without changing the HTTP/3 protocol code.
 * <p>
 * The OpenSSL QUIC endpoint is currently implemented only for Linux LP64. The
 * selector returns a {@link QuicPlatformUnavailable} implementation for every
 * other OS or ABI; the endpoint then reports why it is unavailable instead of
 * binding with a mismatched native ABI. An explicit operator override that is
 * not recognized (or an override class that cannot be loaded) also selects an
 * unavailable implementation: the selector fails closed instead of silently
 * falling back to automatic selection.
 * <p>
 * This class is package-private and is not a supported public API. The
 * package-private {@link #selectForTest(String)} hook exists for tests; the
 * production instance is selected once and cached in {@link #get()}.
 */
abstract class QuicPlatformSupport {

    private static final Log log = LogFactory.getLog(QuicPlatformSupport.class);
    private static final StringManager sm =
            StringManager.getManager(QuicOpenSSLEndpoint.class);

    private static final String PLATFORM_PROPERTY =
            "org.apache.tomcat.util.net.quic.openssl.platform";
    private static final String PLATFORM_CLASS_PROPERTY =
            "org.apache.tomcat.util.net.quic.openssl.platformClass";

    private static final QuicPlatformSupport INSTANCE = select();


    /**
     * Returns the selected platform implementation. Never returns null.
     *
     * @return The selected platform implementation
     */
    static QuicPlatformSupport get() {
        return INSTANCE;
    }


    private static QuicPlatformSupport select() {
        String override = System.getProperty(PLATFORM_PROPERTY);
        if (override != null && !override.trim().isEmpty() &&
                !"auto".equalsIgnoreCase(override.trim())) {
            return selectExplicit(override.trim());
        }

        String className = System.getProperty(PLATFORM_CLASS_PROPERTY);
        if (className != null && !className.trim().isEmpty()) {
            return selectClass(className.trim());
        }

        return selectAuto();
    }


    private static QuicPlatformSupport selectExplicit(String value) {
        if ("none".equalsIgnoreCase(value)) {
            return new QuicPlatformUnavailable(System.getProperty("os.name", ""),
                    System.getProperty("os.arch", ""),
                    sm.getString("quicPlatform.disabled"));
        }
        if ("linux".equalsIgnoreCase(value)) {
            return selectLinux();
        }
        // macOS/BSD/Windows implementations are future work. Keep the names
        // recognized so tests and diagnostics can force the unavailable path.
        if ("macos".equalsIgnoreCase(value) || "bsd".equalsIgnoreCase(value) ||
                "windows".equalsIgnoreCase(value)) {
            return new QuicPlatformUnavailable(value, System.getProperty("os.arch", ""),
                    sm.getString("quicPlatform.unsupportedOs", value));
        }
        // An invalid explicit override is a configuration error. Falling back
        // to automatic selection could silently enable QUIC when the operator
        // intended to disable or test it, so fail closed instead.
        String reason = sm.getString("quicPlatform.overrideInvalid",
                value);
        log.warn(reason);
        return new QuicPlatformUnavailable(value,
                System.getProperty("os.arch", ""), reason);
    }


    private static QuicPlatformSupport selectAuto() {
        String osName = System.getProperty("os.name", "").toLowerCase(Locale.ENGLISH);
        if (osName.startsWith("linux")) {
            return selectLinux();
        }
        return new QuicPlatformUnavailable(osName, System.getProperty("os.arch", ""),
                sm.getString("quicPlatform.unsupportedOs", osName));
    }


    private static QuicPlatformSupport selectLinux() {
        try {
            return initialize(new QuicLinuxPlatformSupport());
        } catch (Throwable t) {
            return new QuicPlatformUnavailable("linux",
                    System.getProperty("os.arch", ""), t.toString());
        }
    }


    private static QuicPlatformSupport selectClass(String className) {
        try {
            Class<?> clazz = Class.forName(className);
            if (!QuicPlatformSupport.class.isAssignableFrom(clazz)) {
                return new QuicPlatformUnavailable("", "", sm.getString(
                        "quicPlatform.overrideClassInvalid", className,
                        "class is not a QuicPlatformSupport subclass"));
            }
            QuicPlatformSupport candidate = (QuicPlatformSupport)
                    clazz.getDeclaredConstructor().newInstance();
            return initialize(candidate);
        } catch (Throwable t) {
            return new QuicPlatformUnavailable("", "", sm.getString(
                    "quicPlatform.overrideClassInvalid", className, t.toString()));
        }
    }


    private static QuicPlatformSupport initialize(QuicPlatformSupport candidate) {
        try {
            if (candidate.isAvailable()) {
                if (log.isDebugEnabled()) {
                    log.debug(sm.getString("quicPlatform.selected",
                            candidate.name(), candidate.abi().description()));
                }
                return candidate;
            }
            return new QuicPlatformUnavailable(candidate.id().name(),
                    System.getProperty("os.arch", ""),
                    candidate.unavailableReason());
        } catch (Throwable t) {
            return new QuicPlatformUnavailable(candidate.id().name(),
                    System.getProperty("os.arch", ""), t.toString());
        }
    }


    /**
     * Selects a platform explicitly for tests. Package-private; not used by
     * production code.
     *
     * @param id The platform id or {@code "unavailable"}
     * @return The selected implementation
     */
    static QuicPlatformSupport selectForTest(String id) {
        if ("linux".equalsIgnoreCase(id)) {
            return new QuicLinuxPlatformSupport();
        }
        return new QuicPlatformUnavailable(id, System.getProperty("os.arch", ""),
                "test-selected unavailable platform");
    }


    /**
     * Returns the platform id.
     *
     * @return The platform id
     */
    abstract PlatformId id();


    /**
     * Returns a descriptive name for diagnostics.
     *
     * @return The platform name
     */
    abstract String name();


    /**
     * Returns whether this platform implementation can be used.
     *
     * @return {@code true} when the implementation is available
     */
    abstract boolean isAvailable();


    /**
     * Returns the reason the platform is unavailable, or {@code null} when it
     * is available.
     *
     * @return The unavailable reason
     */
    abstract String unavailableReason();


    /**
     * Returns the ABI description used by the OpenSSL binding layer.
     * Implementations that are unavailable still return a non-null placeholder
     * so that class initialisation can complete; no native call is made with
     * that placeholder because {@code QUIC_AVAILABLE} is false.
     *
     * @return The ABI description
     */
    abstract Abi abi();


    /**
     * Creates and binds a UDP socket.
     *
     * @param address The address to bind
     * @param port    The port to bind; zero requests an ephemeral port
     * @param options The socket options
     * @return The bound socket and its actual port
     * @throws QuicPlatformException If the socket cannot be created or bound
     */
    abstract BoundUdpSocket bindUdpSocket(InetAddress address, int port,
            UdpSocketOptions options) throws QuicPlatformException;


    /**
     * Closes a socket handle. Must be idempotent.
     *
     * @param socket The socket handle
     */
    abstract void close(SocketHandle socket);


    /**
     * Returns the native file descriptor used by {@code SSL_set_fd()}.
     *
     * @param socket The socket handle
     * @return The native descriptor as a Java int
     * @throws QuicPlatformException If the handle cannot be represented
     */
    abstract int openSslFd(SocketHandle socket) throws QuicPlatformException;


    /**
     * Returns a safe diagnostic description of a socket handle.
     *
     * @param socket The socket handle
     * @return The description
     */
    abstract String describe(SocketHandle socket);


    /**
     * Returns whether an OpenSSL address-family value is IPv4.
     *
     * @param nativeFamily The native family value
     * @return {@code true} for IPv4
     */
    abstract boolean isIPv4Family(int nativeFamily);


    /**
     * Returns whether an OpenSSL address-family value is IPv6.
     *
     * @param nativeFamily The native family value
     * @return {@code true} for IPv6
     */
    abstract boolean isIPv6Family(int nativeFamily);


    /**
     * Decodes the raw port returned by {@code BIO_ADDR_rawport()}.
     *
     * @param rawPort The raw port value
     * @return The host-order port
     */
    abstract int decodePeerPort(int rawPort);


    /**
     * Creates the poll-loop wake-up object.
     *
     * @param socket The UDP socket handle
     * @return The wake-up object
     * @throws QuicPlatformException If the wake-up object cannot be created
     */
    abstract Wakeup createWakeup(SocketHandle socket) throws QuicPlatformException;


    /**
     * Platform identifiers.
     */
    enum PlatformId {
        LINUX,
        MACOS,
        BSD,
        WINDOWS,
        UNKNOWN
    }


    /**
     * Opaque native socket handle.
     */
    static final class SocketHandle {

        private final long value;
        private final boolean valid;
        private final AtomicBoolean closed = new AtomicBoolean();

        SocketHandle(long value) {
            this.value = value;
            this.valid = value >= 0;
        }

        long value() {
            return value;
        }

        boolean isValid() {
            return valid;
        }

        boolean markClosed() {
            return closed.compareAndSet(false, true);
        }
    }


    /**
     * Options applied while binding the UDP socket.
     *
     * @param receiveBufferSize The requested receive buffer size, or zero
     * @param sendBufferSize    The requested send buffer size, or zero
     * @param dualStack         Whether an IPv6 wildcard should accept IPv4
     */
    record UdpSocketOptions(int receiveBufferSize, int sendBufferSize,
            boolean dualStack) {
    }


    /**
     * A bound UDP socket and the port actually assigned by the OS.
     *
     * @param socket    The socket handle
     * @param boundPort The assigned port
     */
    record BoundUdpSocket(SocketHandle socket, int boundPort) {
    }


    /**
     * A classified platform failure. Native error codes are captured at the
     * call site and exposed only through semantic predicates.
     */
    static class QuicPlatformException extends IOException {

        private static final long serialVersionUID = 1L;

        private final boolean addressFamilyUnavailable;
        private final boolean addressNotAvailable;
        private final boolean permissionDenied;

        QuicPlatformException(String operation, int nativeCode,
                String nativeMessage, boolean addressFamilyUnavailable,
                boolean addressNotAvailable, boolean permissionDenied) {
            super(operation + " failed: " + nativeMessage +
                    " (error=[" + nativeCode + "])");
            this.addressFamilyUnavailable = addressFamilyUnavailable;
            this.addressNotAvailable = addressNotAvailable;
            this.permissionDenied = permissionDenied;
        }

        boolean isAddressFamilyUnavailable() {
            return addressFamilyUnavailable;
        }

        boolean isAddressNotAvailable() {
            return addressNotAvailable;
        }

        boolean isPermissionDenied() {
            return permissionDenied;
        }
    }


    /**
     * The ABI values and native layouts used by the QUIC socket, poll and
     * OpenSSL binding layers.
     *
     * @param sizeT                The C {@code size_t} layout
     * @param cLong                The C {@code long} layout
     * @param timeval              The {@code struct timeval} layout
     * @param tvSec                The {@code tv_sec} field layout
     * @param tvUsec               The {@code tv_usec} field layout
     * @param tvSecOffset          The {@code tv_sec} byte offset
     * @param tvUsecOffset         The {@code tv_usec} byte offset
     * @param pollFd               The {@code struct pollfd} layout
     * @param pollFdFd             The {@code pollfd.fd} layout
     * @param pollFdEvents         The {@code pollfd.events} layout
     * @param pollFdRevents        The {@code pollfd.revents} layout
     * @param pollFdEventsOffset   The {@code pollfd.events} byte offset
     * @param pollFdReventsOffset  The {@code pollfd.revents} byte offset
     * @param sslPollItem          The {@code SSL_POLL_ITEM} layout
     * @param sslPollItemStride    The {@code SSL_POLL_ITEM} array stride
     * @param descTypeOffset       The descriptor type byte offset
     * @param descValueOffset      The descriptor value byte offset
     * @param eventsOffset         The {@code events} byte offset
     * @param reventsOffset        The {@code revents} byte offset
     * @param supported            Whether this ABI can be used by the endpoint
     * @param description          A human-readable ABI description
     */
    record Abi(ValueLayout.OfLong sizeT, ValueLayout.OfLong cLong,
            MemoryLayout timeval, ValueLayout.OfLong tvSec,
            ValueLayout.OfLong tvUsec, long tvSecOffset, long tvUsecOffset,
            MemoryLayout pollFd, ValueLayout.OfInt pollFdFd,
            ValueLayout.OfShort pollFdEvents, ValueLayout.OfShort pollFdRevents,
            long pollFdEventsOffset, long pollFdReventsOffset,
            MemoryLayout sslPollItem, long sslPollItemStride,
            long descTypeOffset, long descValueOffset, long eventsOffset,
            long reventsOffset, boolean supported, String description) {

        boolean isSupported() {
            return supported;
        }

        long sizeTBytes() {
            return sizeT.byteSize();
        }

        void setSizeT(MemorySegment segment, long offset, long value) {
            segment.set(sizeT, offset, value);
        }

        long getSizeT(MemorySegment segment, long offset) {
            return segment.get(sizeT, offset);
        }

        void writeTimeval(MemorySegment segment, long seconds, long microseconds) {
            segment.set(tvSec, tvSecOffset, seconds);
            segment.set(tvUsec, tvUsecOffset, microseconds);
        }

        long readTimevalSeconds(MemorySegment segment) {
            return segment.get(tvSec, tvSecOffset);
        }

        long readTimevalMicroseconds(MemorySegment segment) {
            return segment.get(tvUsec, tvUsecOffset);
        }

        static Abi placeholder() {
            MemoryLayout tv = MemoryLayout.structLayout(
                    ValueLayout.JAVA_LONG.withName("tv_sec"),
                    ValueLayout.JAVA_LONG.withName("tv_usec"));
            MemoryLayout pollfd = MemoryLayout.structLayout(
                    ValueLayout.JAVA_INT.withName("fd"),
                    ValueLayout.JAVA_SHORT.withName("events"),
                    ValueLayout.JAVA_SHORT.withName("revents"));
            MemoryLayout desc = MemoryLayout.structLayout(
                    ValueLayout.JAVA_INT.withName("type"),
                    ValueLayout.JAVA_INT.withName("padding"),
                    ValueLayout.ADDRESS.withName("value"));
            MemoryLayout item = MemoryLayout.structLayout(
                    desc.withName("desc"),
                    ValueLayout.JAVA_LONG.withName("events"),
                    ValueLayout.JAVA_LONG.withName("revents"));
            return new Abi(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, tv,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, 0, 8,
                    pollfd, ValueLayout.JAVA_INT, ValueLayout.JAVA_SHORT,
                    ValueLayout.JAVA_SHORT, 4, 6, item, 32, 0, 8, 16, 24,
                    false, "unavailable placeholder ABI");
        }
    }


    /**
     * The poll-loop's wake primitive.
     */
    interface Wakeup extends AutoCloseable {

        int EVENT_WAKE = 1;
        int EVENT_SOCK = 2;

        void kick();

        int await(long timeoutMs);

        void consume();

        @Override
        void close();
    }


}

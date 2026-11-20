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

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteOrder;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;


/**
 * Linux LP64 implementation of {@link QuicPlatformSupport}.
 * <p>
 * This class is the only place in the OpenSSL QUIC package that knows Linux
 * libc symbol names, Linux socket constants or the Linux {@code sockaddr} and
 * ABI layouts. It supports glibc and musl on 64-bit Linux; other operating
 * systems and 32-bit ABIs are reported unavailable by the platform selector.
 */
final class QuicLinuxPlatformSupport extends QuicPlatformSupport {

    private static final Log log = LogFactory.getLog(QuicLinuxPlatformSupport.class);
    private static final StringManager sm =
            StringManager.getManager(QuicOpenSSLEndpoint.class);

    // Linux ABI constants. Keep all of them private: callers use semantic
    // methods and classified exceptions instead of numeric values.
    private static final int AF_INET = 2;
    private static final int AF_INET6 = 10;
    private static final int SOCK_DGRAM = 2;
    private static final int SOCK_NONBLOCK = 0x800;
    private static final int SOCK_CLOEXEC = 0x80000;
    private static final int SOL_SOCKET = 1;
    private static final int SO_RCVBUF = 8;
    private static final int SO_SNDBUF = 7;
    private static final int IPPROTO_IPV6 = 41;
    private static final int IPV6_V6ONLY = 26;
    private static final int EPERM = 1;
    private static final int EINTR = 4;
    private static final int EAFNOSUPPORT = 97;
    private static final int EADDRNOTAVAIL = 99;
    private static final short POLLIN = 0x0001;
    private static final short POLLERR = 0x0008;
    private static final short POLLHUP = 0x0010;
    private static final short POLLNVAL = 0x0020;
    private static final int EFD_NONBLOCK = 0x800;
    private static final int EFD_CLOEXEC = 0x80000;

    private static final MemoryLayout POLLFD_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("fd"),
            ValueLayout.JAVA_SHORT.withName("events"),
            ValueLayout.JAVA_SHORT.withName("revents")).withName("pollfd");
    private static final long POLLFD_SIZE = POLLFD_LAYOUT.byteSize();
    private static final long POLLFD_EVENTS_OFFSET =
            POLLFD_LAYOUT.byteOffset(PathElement.groupElement("events"));
    private static final long POLLFD_REVENTS_OFFSET =
            POLLFD_LAYOUT.byteOffset(PathElement.groupElement("revents"));

    private static final MemoryLayout BIO_POLL_DESCRIPTOR_LAYOUT =
            MemoryLayout.structLayout(
                    ValueLayout.JAVA_INT.withName("type"),
                    ValueLayout.JAVA_INT.withName("padding"),
                    ValueLayout.ADDRESS.withName("value"))
            .withName("bio_poll_descriptor");
    private static final MemoryLayout SSL_POLL_ITEM_LAYOUT =
            MemoryLayout.structLayout(
                    BIO_POLL_DESCRIPTOR_LAYOUT.withName("desc"),
                    ValueLayout.JAVA_LONG.withName("events"),
                    ValueLayout.JAVA_LONG.withName("revents"))
            .withName("ssl_poll_item");
    private static final long SSL_POLL_ITEM_SIZE = SSL_POLL_ITEM_LAYOUT.byteSize();
    private static final long SSL_POLL_ITEM_STRIDE = alignToPointer(SSL_POLL_ITEM_SIZE);
    private static final long DESC_TYPE_OFFSET = SSL_POLL_ITEM_LAYOUT.byteOffset(
            PathElement.groupElement("desc"), PathElement.groupElement("type"));
    private static final long DESC_VALUE_OFFSET = SSL_POLL_ITEM_LAYOUT.byteOffset(
            PathElement.groupElement("desc"), PathElement.groupElement("value"));
    private static final long SSL_POLL_EVENTS_OFFSET =
            SSL_POLL_ITEM_LAYOUT.byteOffset(PathElement.groupElement("events"));
    private static final long SSL_POLL_REVENTS_OFFSET =
            SSL_POLL_ITEM_LAYOUT.byteOffset(PathElement.groupElement("revents"));

    private static final MemoryLayout TIMEVAL_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.JAVA_LONG.withName("tv_sec"),
            ValueLayout.JAVA_LONG.withName("tv_usec"));
    private static final long TV_SEC_OFFSET =
            TIMEVAL_LAYOUT.byteOffset(PathElement.groupElement("tv_sec"));
    private static final long TV_USEC_OFFSET =
            TIMEVAL_LAYOUT.byteOffset(PathElement.groupElement("tv_usec"));

    private static final Abi ABI = new Abi(
            ValueLayout.JAVA_LONG,
            ValueLayout.JAVA_LONG,
            TIMEVAL_LAYOUT,
            ValueLayout.JAVA_LONG,
            ValueLayout.JAVA_LONG,
            TV_SEC_OFFSET,
            TV_USEC_OFFSET,
            POLLFD_LAYOUT,
            ValueLayout.JAVA_INT,
            ValueLayout.JAVA_SHORT,
            ValueLayout.JAVA_SHORT,
            POLLFD_EVENTS_OFFSET,
            POLLFD_REVENTS_OFFSET,
            SSL_POLL_ITEM_LAYOUT,
            SSL_POLL_ITEM_STRIDE,
            DESC_TYPE_OFFSET,
            DESC_VALUE_OFFSET,
            SSL_POLL_EVENTS_OFFSET,
            SSL_POLL_REVENTS_OFFSET,
            true,
            "linux-lp64");

    // -------------------------------------------------- libc handles

    private static final Set<String> MISSING_SYMBOLS = new LinkedHashSet<>();

    private static final MethodHandle socket$handle = libc("socket",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT));
    private static final MethodHandle bind$handle = libc("bind",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_INT));
    private static final MethodHandle getsockname$handle = libc("getsockname",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS));
    private static final MethodHandle close$handle = libc("close",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    private static final MethodHandle poll$handle = libc("poll",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT));
    private static final MethodHandle eventfd$handle = libc("eventfd",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    private static final MethodHandle read$handle = libc("read",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG));
    private static final MethodHandle write$handle = libc("write",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG,
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG));
    private static final MethodHandle setsockopt$handle = libc("setsockopt",
            FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                    ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_INT));
    private static final MethodHandle strerror$handle = libc("strerror",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    private static final MethodHandle errnoLocation$handle =
            libc("__errno_location", FunctionDescriptor.of(ValueLayout.ADDRESS));

    private static final Object STRERROR_LOCK = new Object();

    private static final boolean AVAILABLE;
    private static final String UNAVAILABLE_REASON;

    static {
        String reason = null;
        if (ValueLayout.ADDRESS.byteSize() != Long.BYTES) {
            reason = sm.getString("quicPlatform.unsupportedAbi",
                    String.valueOf(ValueLayout.ADDRESS.byteSize() * 8));
        } else if (!MISSING_SYMBOLS.isEmpty()) {
            reason = sm.getString("quicPlatform.missingSymbols",
                    String.join(", ", MISSING_SYMBOLS));
        } else if (TIMEVAL_LAYOUT.byteSize() != 16 ||
                POLLFD_SIZE != 8 || SSL_POLL_ITEM_SIZE != 32 ||
                SSL_POLL_ITEM_STRIDE != 32 || DESC_TYPE_OFFSET != 0 ||
                DESC_VALUE_OFFSET != 8 || SSL_POLL_EVENTS_OFFSET != 16 ||
                SSL_POLL_REVENTS_OFFSET != 24) {
            reason = sm.getString("quicPlatform.invalidLayout");
        }
        AVAILABLE = reason == null;
        UNAVAILABLE_REASON = reason;
        if (!AVAILABLE) {
            log.warn(UNAVAILABLE_REASON);
        }
    }


    private static MethodHandle libc(String symbol, FunctionDescriptor descriptor) {
        try {
            MemorySegment address = Linker.nativeLinker().defaultLookup().find(symbol)
                    .or(() -> SymbolLookup.loaderLookup().find(symbol))
                    .orElseThrow(() -> new UnsatisfiedLinkError(
                            "unresolved libc symbol: " + symbol));
            return Linker.nativeLinker().downcallHandle(address, descriptor);
        } catch (Throwable t) {
            MISSING_SYMBOLS.add(symbol);
            return null;
        }
    }


    private static long alignToPointer(long size) {
        long pointerSize = ValueLayout.ADDRESS.byteSize();
        long remainder = size % pointerSize;
        return remainder == 0 ? size : size + pointerSize - remainder;
    }


    @Override
    PlatformId id() {
        return PlatformId.LINUX;
    }


    @Override
    String name() {
        return "linux-" + System.getProperty("os.arch", "unknown") +
                (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN ?
                        "-le" : "-be");
    }


    @Override
    boolean isAvailable() {
        return AVAILABLE;
    }


    @Override
    String unavailableReason() {
        return UNAVAILABLE_REASON;
    }


    @Override
    Abi abi() {
        return ABI;
    }


    /**
     * Creates and binds a UDP socket.
     * <p>
     * An IPv6 scope identifier is not translated: only the 16 address bytes
     * are written and {@code sin6_scope_id} is left zero. Binding an IPv6
     * wildcard or a global address is unaffected; an explicit link-local
     * address with a scope fails rather than silently binding the wrong
     * interface.
     * <p>
     * {@code IPV6_V6ONLY} is set explicitly: 0 for the dual-stack wildcard
     * candidate, 1 for every other IPv6 bind, so an explicit IPv6 address
     * cannot inherit a system default that also accepts IPv4-mapped
     * connections.
     */
    @Override
    BoundUdpSocket bindUdpSocket(InetAddress address, int port,
            UdpSocketOptions options) throws QuicPlatformException {
        boolean ipv6 = address instanceof Inet6Address;
        int af = ipv6 ? AF_INET6 : AF_INET;
        int socketFd;
        int socketError;
        do {
            socketFd = invokeInt(socket$handle, "socket", af,
                    SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            socketError = socketFd < 0 ? errno() : 0;
        } while (socketFd < 0 && socketError == EINTR);
        if (socketFd < 0) {
            throw failure("socket", socketError,
                    options.dualStack() && ipv6 &&
                            isAddressFamilyError(socketError));
        }

        try (Arena arena = Arena.ofConfined()) {
            int rxBufSize = options.receiveBufferSize();
            if (rxBufSize > 0) {
                setIntOption(arena, socketFd, SOL_SOCKET, SO_RCVBUF,
                        rxBufSize, "SO_RCVBUF", false);
            }
            int txBufSize = options.sendBufferSize();
            if (txBufSize > 0) {
                setIntOption(arena, socketFd, SOL_SOCKET, SO_SNDBUF,
                        txBufSize, "SO_SNDBUF", false);
            }
            if (ipv6) {
                // The IPv6 wildcard default explicitly chooses dual-stack.
                // Every other IPv6 bind (including an explicit wildcard
                // address) is IPv6-only: leaving IPV6_V6ONLY at the system
                // default would let it accept IPv4-mapped connections on
                // systems whose default is 0.
                setIntOption(arena, socketFd, IPPROTO_IPV6, IPV6_V6ONLY,
                        options.dualStack() ? 0 : 1, "IPV6_V6ONLY", true);
            }

            MemorySegment sockaddr = ipv6 ? buildSockaddrIn6(arena, address, port) :
                    buildSockaddrIn4(arena, address, port);
            int addrlen = ipv6 ? 28 : 16;
            int rc;
            int bindError;
            do {
                rc = invokeInt(bind$handle, "bind", socketFd, sockaddr,
                        addrlen);
                bindError = rc != 0 ? errno() : 0;
            } while (rc != 0 && bindError == EINTR);
            if (rc != 0) {
                // Only EAFNOSUPPORT means the address family itself is
                // unavailable. EADDRNOTAVAIL/EPERM are classified by their
                // own predicates below and are still recognized by the
                // endpoint's dual-stack fallback policy.
                throw failure("bind", bindError,
                        options.dualStack() && ipv6 &&
                                isAddressFamilyError(bindError));
            }

            int actualPort = port;
            if (port == 0) {
                MemorySegment nameAddr = arena.allocate(ipv6 ? 28 : 16);
                MemorySegment nameLen = arena.allocate(ValueLayout.JAVA_INT);
                nameLen.set(ValueLayout.JAVA_INT, 0, addrlen);
                int nameRc;
                int nameError;
                do {
                    nameRc = invokeInt(getsockname$handle, "getsockname",
                            socketFd, nameAddr, nameLen);
                    nameError = nameRc != 0 ? errno() : 0;
                } while (nameRc != 0 && nameError == EINTR);
                if (nameRc != 0) {
                    throw failure("getsockname", nameError, false);
                }
                actualPort = ((nameAddr.get(ValueLayout.JAVA_BYTE, 2) & 0xFF) << 8) |
                        (nameAddr.get(ValueLayout.JAVA_BYTE, 3) & 0xFF);
            }
            return new BoundUdpSocket(new SocketHandle(socketFd), actualPort);
        } catch (QuicPlatformException | RuntimeException | Error e) {
            close(new SocketHandle(socketFd));
            throw e;
        }
    }


    private MemorySegment buildSockaddrIn6(Arena arena, InetAddress address, int port) {
        MemorySegment sockaddr = arena.allocate(28);
        sockaddr.set(ValueLayout.JAVA_SHORT, 0, (short) AF_INET6);
        sockaddr.set(ValueLayout.JAVA_BYTE, 2, (byte) (port >> 8));
        sockaddr.set(ValueLayout.JAVA_BYTE, 3, (byte) (port & 0xFF));
        byte[] bytes = address.getAddress();
        if (bytes != null && bytes.length == 16) {
            for (int i = 0; i < 16; i++) {
                sockaddr.set(ValueLayout.JAVA_BYTE, 8 + i, bytes[i]);
            }
        }
        return sockaddr;
    }


    private MemorySegment buildSockaddrIn4(Arena arena, InetAddress address, int port) {
        MemorySegment sockaddr = arena.allocate(16);
        sockaddr.set(ValueLayout.JAVA_SHORT, 0, (short) AF_INET);
        sockaddr.set(ValueLayout.JAVA_BYTE, 2, (byte) (port >> 8));
        sockaddr.set(ValueLayout.JAVA_BYTE, 3, (byte) (port & 0xFF));
        byte[] bytes = address.getAddress();
        if (bytes != null) {
            for (int i = 0; i < Math.min(4, bytes.length); i++) {
                sockaddr.set(ValueLayout.JAVA_BYTE, 4 + i, bytes[i]);
            }
        }
        return sockaddr;
    }


    private void setIntOption(Arena arena, int socketFd, int level, int option,
            int value, String name, boolean familyFailure)
            throws QuicPlatformException {
        MemorySegment valueSegment = arena.allocate(ValueLayout.JAVA_INT);
        valueSegment.set(ValueLayout.JAVA_INT, 0, value);
        int rc;
        int error;
        do {
            rc = invokeInt(setsockopt$handle, "setsockopt", socketFd, level,
                    option, valueSegment, 4);
            error = rc != 0 ? errno() : 0;
        } while (rc != 0 && error == EINTR);
        if (rc != 0) {
            // The caller's familyFailure flag only says that a family-related
            // error may be meaningful for this option. It must not turn an
            // unrelated errno (EINVAL/ENOPROTOOPT/ENOBUFS/...) into an
            // address-family failure.
            throw failure("setsockopt(" + name + ")", error,
                    familyFailure && isAddressFamilyError(error));
        }
    }


    private QuicPlatformException failure(String operation, int error,
            boolean addressFamilyUnavailable) {
        boolean addressNotAvailable = error == EADDRNOTAVAIL;
        boolean permissionDenied = error == EPERM;
        return new QuicPlatformException(operation, error, strerror(error),
                addressFamilyUnavailable, addressNotAvailable,
                permissionDenied);
    }


    private boolean isAddressFamilyError(int error) {
        return error == EAFNOSUPPORT;
    }


    @Override
    void close(SocketHandle socket) {
        if (socket == null || !socket.isValid() || close$handle == null) {
            return;
        }
        if (socket.markClosed()) {
            invokeInt(close$handle, "close", (int) socket.value());
        }
    }


    @Override
    int openSslFd(SocketHandle socket) throws QuicPlatformException {
        if (socket == null || !socket.isValid()) {
            throw new QuicPlatformException("openSslFd", 0,
                    "invalid socket handle", false, false, false);
        }
        long value = socket.value();
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw new QuicPlatformException("openSslFd", 0,
                    "socket handle does not fit in an int: " + value,
                    false, false, false);
        }
        return (int) value;
    }


    @Override
    String describe(SocketHandle socket) {
        return socket == null ? "null" : ("FD " + socket.value());
    }


    @Override
    boolean isIPv4Family(int nativeFamily) {
        return nativeFamily == AF_INET;
    }


    @Override
    boolean isIPv6Family(int nativeFamily) {
        return nativeFamily == AF_INET6;
    }


    @Override
    int decodePeerPort(int rawPort) {
        return ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN ?
                ((rawPort & 0xFF) << 8) | (rawPort >>> 8) : rawPort;
    }


    @Override
    Wakeup createWakeup(SocketHandle socket) throws QuicPlatformException {
        return new LinuxWakeup(socket);
    }


    private static int errno() {
        try {
            MemorySegment pointer = (MemorySegment) errnoLocation$handle.invokeExact();
            return pointer.reinterpret(Integer.BYTES).get(ValueLayout.JAVA_INT, 0);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }


    private static String strerror(int error) {
        synchronized (STRERROR_LOCK) {
            try {
                MemorySegment result = (MemorySegment) strerror$handle.invokeExact(error);
                if (result.equals(MemorySegment.NULL)) {
                    return "Unknown error " + error;
                }
                return result.getString(0);
            } catch (Throwable t) {
                throw new AssertionError("should not reach here", t);
            }
        }
    }


    private int invokeInt(MethodHandle handle, String operation, Object... args) {
        if (handle == null) {
            throw new IllegalStateException("libc symbol unavailable: " + operation);
        }
        try {
            return (int) handle.invokeWithArguments(args);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }


    /**
     * Linux eventfd/poll wake-up implementation.
     */
    private static final class LinuxWakeup implements Wakeup {

        private final Arena arena;
        private final int wakeFd;
        private boolean closed;
        private final MemorySegment pollfds;
        private final MemorySegment counter;

        LinuxWakeup(SocketHandle socket) throws QuicPlatformException {
            this.arena = Arena.ofShared();
            int fd;
            try {
                if (eventfd$handle == null) {
                    throw new IllegalStateException(
                            "libc symbol unavailable: eventfd");
                }
                fd = (int) eventfd$handle.invokeExact(0,
                        EFD_NONBLOCK | EFD_CLOEXEC);
            } catch (QuicPlatformException e) {
                throw e;
            } catch (Throwable t) {
                throw new AssertionError("should not reach here", t);
            }
            if (fd < 0) {
                int error = errno();
                arena.close();
                throw new QuicPlatformException("eventfd", error,
                        strerror(error), false, false, false);
            }
            this.wakeFd = fd;
            try {
                this.pollfds = arena.allocate(POLLFD_LAYOUT, 2);
                pollfds.set(ValueLayout.JAVA_INT, 0, (int) socket.value());
                pollfds.set(ValueLayout.JAVA_SHORT, POLLFD_EVENTS_OFFSET, POLLIN);
                pollfds.set(ValueLayout.JAVA_INT, POLLFD_SIZE, wakeFd);
                pollfds.set(ValueLayout.JAVA_SHORT,
                        POLLFD_SIZE + POLLFD_EVENTS_OFFSET, POLLIN);
                this.counter = arena.allocate(ValueLayout.JAVA_LONG);
                counter.set(ValueLayout.JAVA_LONG, 0, 1L);
            } catch (RuntimeException | Error t) {
                closeFd(fd);
                arena.close();
                throw t;
            }
        }

        @Override
        public void kick() {
            synchronized (this) {
                if (closed) {
                    return;
                }
                try {
                    long ignored = (long) write$handle.invokeExact(wakeFd,
                            counter, 8L);
                } catch (Throwable t) {
                    throw new AssertionError("should not reach here", t);
                }
            }
        }

        @Override
        public int await(long timeoutMs) {
            long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
            while (true) {
                long remainingMs = 0;
                boolean finite = timeoutMs >= 0;
                if (finite) {
                    remainingMs = (deadline - System.nanoTime() + 999_999) /
                            1_000_000;
                    if (remainingMs > Integer.MAX_VALUE) {
                        remainingMs = Integer.MAX_VALUE;
                    } else if (remainingMs < 0) {
                        return 0;
                    }
                }
                int rc;
                try {
                    rc = (int) poll$handle.invokeExact(pollfds, 2L,
                            finite ? (int) remainingMs : -1);
                } catch (Throwable t) {
                    throw new AssertionError("should not reach here", t);
                }
                if (rc < 0) {
                    int error = errno();
                    if (error == EINTR) {
                        if (!finite) {
                            continue;
                        }
                        if (System.nanoTime() - deadline >= 0) {
                            return 0;
                        }
                        continue;
                    }
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("quicEndpoint.wakeupPollError",
                                Integer.valueOf(error)));
                    }
                    return -1;
                }
                int events = 0;
                short wakeRevents = revents(1);
                short sockRevents = revents(0);
                if ((wakeRevents & POLLIN) != 0) {
                    events |= EVENT_WAKE;
                }
                if ((sockRevents & POLLIN) != 0) {
                    events |= EVENT_SOCK;
                }
                if (events == 0 && ((wakeRevents | sockRevents) &
                        (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                    if (log.isDebugEnabled()) {
                        log.debug(sm.getString("quicEndpoint.wakeupErrorEvents",
                                Integer.valueOf(wakeRevents & 0xFFFF),
                                Integer.valueOf(sockRevents & 0xFFFF)));
                    }
                    return -1;
                }
                return events;
            }
        }

        @Override
        public void consume() {
            try {
                long ignored = (long) read$handle.invokeExact(wakeFd,
                        counter, 8L);
            } catch (Throwable t) {
                throw new AssertionError("should not reach here", t);
            } finally {
                // eventfd read() overwrites the counter buffer with the
                // accumulated count. kick() writes that buffer as the next
                // increment, so leaving the observed count in place makes
                // batches of kicks multiply the kernel counter. Restore the
                // constant one used by every kick.
                counter.set(ValueLayout.JAVA_LONG, 0, 1L);
            }
        }

        @Override
        public void close() {
            synchronized (this) {
                if (closed) {
                    return;
                }
                closed = true;
                try {
                    closeFd(wakeFd);
                } finally {
                    try {
                        arena.close();
                    } catch (Throwable t) {
                        if (log.isDebugEnabled()) {
                            log.debug(sm.getString(
                                    "quicEndpoint.wakeupCloseError"), t);
                        }
                    }
                }
            }
        }

        private short revents(int slot) {
            return pollfds.get(ValueLayout.JAVA_SHORT,
                    slot * POLLFD_SIZE + POLLFD_REVENTS_OFFSET);
        }
    }


    private static void closeFd(int fd) {
        try {
            close$handle.invokeExact(fd);
        } catch (Throwable t) {
            // Ignore close failures on cleanup paths.
        }
    }
}

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
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.tomcat.util.openssl.openssl_h;


/**
 * FFM bindings for OpenSSL QUIC functions.
 * <p>
 * This class provides downcall handles for the QUIC-specific OpenSSL functions
 * needed by {@code QuicOpenSSLEndpoint}. All bindings follow the same pattern
 * as the existing bindings in {@code openssl_h}.
 * <p>
 * Functions bound here (OpenSSL manages QUIC I/O internally, so only the
 * symbols actually called by the endpoint are bound):
 * <ul>
 * <li>{@code OSSL_QUIC_server_method()}</li>
 * <li>{@code SSL_new_listener()}, {@code SSL_listen()}, {@code SSL_accept_connection()}</li>
 * <li>{@code SSL_new_stream()}, {@code SSL_accept_stream()}</li>
 * <li>{@code SSL_read_ex()}, {@code SSL_write_ex()}, {@code SSL_write_ex2()},
 *     {@code SSL_get_error()}</li>
 * <li>{@code SSL_poll()}, {@code SSL_handle_events()},
 *     {@code SSL_get_event_timeout()} (the poll loop's wait cap),
 *     {@code SSL_shutdown_ex()}</li>
 * <li>{@code SSL_set_blocking_mode()}, {@code SSL_set_fd()} (OpenSSL creates and
 *     manages the datagram BIO internally),
 *     {@code SSL_set_default_stream_mode()}, {@code SSL_set_incoming_stream_policy()}</li>
 * <li>{@code SSL_get_stream_id()}, {@code SSL_get_stream_type()},
 *     {@code SSL_stream_conclude()}, {@code SSL_stream_reset()},
 *     {@code SSL_get_stream_read_state()}, {@code SSL_get_stream_write_state()}</li>
 * <li>{@code SSL_get_value_uint()}, {@code SSL_set_value_uint()},
 *     {@code SSL_get_peer_addr()} (with the {@code BIO_ADDR_family()} /
 *     {@code BIO_ADDR_rawaddress()} / {@code BIO_ADDR_rawport()} accessors)</li>
 * <li>{@code SSL_get_servername()}, {@code SSL_get0_alpn_selected()},
 *     {@code SSL_use_certificate()}, {@code SSL_use_PrivateKey()},
 *     {@code X509_free()}, {@code EVP_PKEY_free()}</li>
 * <li>{@code SSL_CTX_ctrl()}, {@code SSL_ctrl()}, {@code SSL_CTX_callback_ctrl()}
 *     (used for the SNI callback and chain certificate management, which are
 *     macros in OpenSSL 4.0)</li>
 * <li>C libc helpers for the datagram socket: {@code socket()}, {@code bind()},
 *     {@code getsockname()}, {@code setsockopt()}, {@code fcntl()},
 *     {@code strerror_r()}, {@code close()}, {@code poll()},
 *     {@code read()}, {@code write()}, {@code eventfd()} and
 *     {@code __errno_location()} (the {@code errno} thread-local accessor
 *     used around the socket helpers; {@code read()}/{@code write()}/
 *     {@code eventfd()} drive the poll loop's wake eventfd)</li>
 * </ul>
 */
public class QuicBindings {

    private QuicBindings() {
        // Utility class - should not be instantiated
    }

    // -------------------------------------------------- QUIC availability check

    /**
     * Checks if QUIC support is available in the linked OpenSSL library.
     * The answer is computed (at the end of this class's static
     * initialisation, below) from the symbol failures recorded while the
     * downcall handles were being created: every symbol this class resolves
     * is probed by the very call that binds it, so the availability check
     * and the bound-symbol set can never drift apart. A partially-complete
     * library is rejected at startup instead of leaving individual handles
     * null and degrading specific features silently.
     */
    public static final boolean QUIC_AVAILABLE;

    /**
     * Symbols whose lookup or downcall binding failed during static
     * initialisation, populated by {@code createHandle()} and
     * {@code createLibcHandle()}. Empty means every symbol this class binds
     * is present in the linked library.
     */
    private static final Set<String> MISSING_SYMBOLS = new LinkedHashSet<>();

    // -------------------------------------------------- QUIC Server Method

    /**
     * {@code const SSL_METHOD *OSSL_QUIC_server_method()}
     */
    public static final MethodHandle OSSL_QUIC_server_method$handle =
            createHandle("OSSL_QUIC_server_method",
                    FunctionDescriptor.of(openssl_h.C_POINTER));

    /**
     * {@code const SSL_METHOD *OSSL_QUIC_server_method()}
     *
     * @return The QUIC server method to configure the server context with
     */
    public static MemorySegment OSSL_QUIC_server_method() {
        try {
            return (MemorySegment) OSSL_QUIC_server_method$handle.invokeExact();
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Listener

    /**
     * {@code SSL *SSL_new_listener(SSL_CTX *ctx, uint64_t flags)}
     */
    public static final MethodHandle SSL_new_listener$handle =
            createHandle("SSL_new_listener",
                    FunctionDescriptor.of(openssl_h.C_POINTER, openssl_h.C_POINTER, ValueLayout.JAVA_LONG));

    /**
     * {@code SSL *SSL_new_listener(SSL_CTX *ctx, uint64_t flags)}
     *
     * @param ctx   The SSL context configured for QUIC
     * @param flags Reserved for future use; must be {@code 0}
     * @return The new listener object, or {@code NULL} on failure
     */
    public static MemorySegment SSL_new_listener(MemorySegment ctx, long flags) {
        try {
            return (MemorySegment) SSL_new_listener$handle.invokeExact(ctx, flags);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_listen(SSL *ssl)}
     */
    public static final MethodHandle SSL_listen$handle =
            createHandle("SSL_listen",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER));

    /**
     * {@code int SSL_listen(SSL *ssl)}
     *
     * @param ssl The listener SSL object
     * @return One on success or zero on failure
     */
    public static int SSL_listen(MemorySegment ssl) {
        try {
            return (int) SSL_listen$handle.invokeExact(ssl);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Connection

    /**
     * {@code SSL *SSL_accept_connection(SSL *listener, uint64_t flags)}
     */
    public static final MethodHandle SSL_accept_connection$handle =
            createHandle("SSL_accept_connection",
                    FunctionDescriptor.of(openssl_h.C_POINTER, openssl_h.C_POINTER, ValueLayout.JAVA_LONG));

    /**
     * {@code SSL *SSL_accept_connection(SSL *listener, uint64_t flags)}
     *
     * @param listener The listener SSL object
     * @param flags    Reserved for future use; must be {@code 0}
     * @return The SSL object for the incoming connection, or {@code NULL} if none is pending
     */
    public static MemorySegment SSL_accept_connection(MemorySegment listener, long flags) {
        try {
            return (MemorySegment) SSL_accept_connection$handle.invokeExact(listener, flags);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Streams

    /**
     * {@code SSL *SSL_new_stream(SSL *conn, uint64_t flags)}
     */
    public static final MethodHandle SSL_new_stream$handle =
            createHandle("SSL_new_stream",
                    FunctionDescriptor.of(openssl_h.C_POINTER, openssl_h.C_POINTER, ValueLayout.JAVA_LONG));

    /**
     * {@code SSL *SSL_new_stream(SSL *conn, uint64_t flags)}
     *
     * @param conn  The SSL object for the QUIC connection
     * @param flags The stream type flags (bidirectional or unidirectional)
     * @return The SSL object for the new stream, or {@code NULL} on failure
     */
    public static MemorySegment SSL_new_stream(MemorySegment conn, long flags) {
        try {
            return (MemorySegment) SSL_new_stream$handle.invokeExact(conn, flags);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code SSL *SSL_accept_stream(SSL *conn, uint64_t flags)}
     */
    public static final MethodHandle SSL_accept_stream$handle =
            createHandle("SSL_accept_stream",
                    FunctionDescriptor.of(openssl_h.C_POINTER, openssl_h.C_POINTER, ValueLayout.JAVA_LONG));

    /**
     * {@code SSL *SSL_accept_stream(SSL *conn, uint64_t flags)}
     *
     * @param conn  The SSL object for the QUIC connection
     * @param flags Accepted stream-type filter (OpenSSL {@code
     *              SSL_ACCEPT_STREAM_*}): {@link QuicPoll#SSL_ACCEPT_STREAM_UNI}
     *              accepts only unidirectional streams, {@link
     *              QuicPoll#SSL_ACCEPT_STREAM_BIDI} only bidirectional ones,
     *              {@code 0} accepts whichever is pending next. ({@code
     *              SSL_ACCEPT_STREAM_NO_BLOCK} is not used here.) The
     *              directional filter is OpenSSL 4.x-only: an OpenSSL 3.5
     *              library defines no such flags and ignores them, accepting
     *              the next pending stream of any direction.
     * @return The SSL object for the accepted stream, or {@code NULL} if none is pending
     */
    public static MemorySegment SSL_accept_stream(MemorySegment conn, long flags) {
        try {
            return (MemorySegment) SSL_accept_stream$handle.invokeExact(conn, flags);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code uint64_t SSL_get_stream_id(SSL *s)}
     */
    public static final MethodHandle SSL_get_stream_id$handle =
            createHandle("SSL_get_stream_id",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, openssl_h.C_POINTER));

    /**
     * {@code uint64_t SSL_get_stream_id(SSL *s)}
     *
     * @param s The stream SSL object
     * @return The stream identifier
     */
    public static long SSL_get_stream_id(MemorySegment s) {
        try {
            return (long) SSL_get_stream_id$handle.invokeExact(s);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_get_stream_type(SSL *s)}
     */
    public static final MethodHandle SSL_get_stream_type$handle =
            createHandle("SSL_get_stream_type",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER));

    /**
     * {@code int SSL_get_stream_type(SSL *s)}
     *
     * @param s The stream SSL object
     * @return The stream type constant
     */
    public static int SSL_get_stream_type(MemorySegment s) {
        try {
            return (int) SSL_get_stream_type$handle.invokeExact(s);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_get_stream_read_state(SSL *ssl)}
     */
    public static final MethodHandle SSL_get_stream_read_state$handle =
            createHandle("SSL_get_stream_read_state",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER));

    /**
     * {@code int SSL_get_stream_read_state(SSL *ssl)}
     *
     * @param ssl The stream SSL object
     * @return The read state of the stream
     */
    public static int SSL_get_stream_read_state(MemorySegment ssl) {
        try {
            return (int) SSL_get_stream_read_state$handle.invokeExact(ssl);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_get_stream_write_state(SSL *ssl)}
     */
    public static final MethodHandle SSL_get_stream_write_state$handle =
            createHandle("SSL_get_stream_write_state",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER));

    /**
     * {@code int SSL_get_stream_write_state(SSL *ssl)}
     *
     * @param ssl The stream SSL object
     * @return The write state of the stream
     */
    public static int SSL_get_stream_write_state(MemorySegment ssl) {
        try {
            return (int) SSL_get_stream_write_state$handle.invokeExact(ssl);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_stream_conclude(SSL *ssl, uint64_t flags)}
     */
    public static final MethodHandle SSL_stream_conclude$handle =
            createHandle("SSL_stream_conclude",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER, ValueLayout.JAVA_LONG));

    /**
     * {@code int SSL_stream_conclude(SSL *ssl, uint64_t flags)}
     *
     * @param ssl   The stream SSL object
     * @param flags Reserved for future use; must be {@code 0}
     * @return One on success or zero on failure
     */
    public static int SSL_stream_conclude(MemorySegment ssl, long flags) {
        try {
            return (int) SSL_stream_conclude$handle.invokeExact(ssl, flags);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_stream_reset(SSL *ssl, const uint8_t *args, size_t args_len)}
     * Resets a QUIC stream with an error code.
     * The args parameter is the SSL_STREAM_RESET_ARGS structure: an 8-byte
     * native-endian {@code uint64_t} application error code, with
     * {@code args_len = 8}.
     */
    public static final MethodHandle SSL_stream_reset$handle =
            createHandle("SSL_stream_reset",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER, ValueLayout.JAVA_LONG));

    /**
     * {@code int SSL_stream_reset(SSL *ssl, const uint8_t *args, size_t args_len)}
     *
     * @param ssl     The stream SSL object
     * @param args    Pointer to the reset arguments structure, or {@code NULL}
     * @param argsLen The size of the structure referenced by {@code args}
     * @return One on success or zero on failure
     */
    public static int SSL_stream_reset(MemorySegment ssl, MemorySegment args, long argsLen) {
        try {
            return (int) SSL_stream_reset$handle.invokeExact(ssl, args, argsLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_set_incoming_stream_policy(SSL *s, int policy, uint64_t aec)}
     * Sets the policy for incoming streams.
     * Policy values: 0 = AUTO (default), 1 = ACCEPT, 2 = REJECT
     * The aec (additional error code) parameter is used when policy is REJECT.
     */
    public static final MethodHandle SSL_set_incoming_stream_policy$handle =
            createHandle("SSL_set_incoming_stream_policy",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER, openssl_h.C_INT, ValueLayout.JAVA_LONG));

    /**
     * {@code int SSL_set_incoming_stream_policy(SSL *s, int policy, uint64_t aec)}
     *
     * @param s      The connection SSL object
     * @param policy The policy to apply to peer-initiated streams
     * @param aec    The application error code to close the connection with if a stream is rejected
     * @return One on success or zero on failure
     */
    public static int SSL_set_incoming_stream_policy(MemorySegment s, int policy, long aec) {
        try {
            return (int) SSL_set_incoming_stream_policy$handle.invokeExact(s, policy, aec);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // Incoming stream policy constants
    /** Incoming stream policy: accept every incoming stream. */
    public static final int SSL_INCOMING_STREAM_POLICY_ACCEPT = 1;

    /**
     * {@code int SSL_handle_events(SSL *s)}
     * Handles internal QUIC events (timers, packet generation, etc.)
     * Required after SSL_poll to drive the QUIC state machine.
     * Returns 1 on success, 0 on error.
     */
    public static final MethodHandle SSL_handle_events$handle =
            createHandle("SSL_handle_events",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER));

    /**
     * {@code int SSL_handle_events(SSL *s)}
     *
     * @param s The SSL object to process
     * @return One on success or zero on failure
     */
    public static int SSL_handle_events(MemorySegment s) {
        try {
            return (int) SSL_handle_events$handle.invokeExact(s);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- I/O

    /**
     * {@code int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *readbytes)}
     */
    public static final MethodHandle SSL_read_ex$handle =
            createHandle("SSL_read_ex",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER, ValueLayout.JAVA_LONG, openssl_h.C_POINTER));

    /**
     * {@code int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *readbytes)}
     *
     * @param s         The stream SSL object
     * @param buf       The buffer that receives the data
     * @param num       The maximum number of bytes to read
     * @param readbytes Out parameter receiving the number of bytes read
     * @return One on success or zero if no data was read or on failure
     */
    public static int SSL_read_ex(MemorySegment s, MemorySegment buf, long num,
            MemorySegment readbytes) {
        try {
            return (int) SSL_read_ex$handle.invokeExact(s, buf, num, readbytes);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)}
     */
    public static final MethodHandle SSL_write_ex$handle =
            createHandle("SSL_write_ex",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER, ValueLayout.JAVA_LONG, openssl_h.C_POINTER));

    /**
     * {@code int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)}
     *
     * @param s       The stream SSL object
     * @param buf     The buffer containing the data to write
     * @param num     The number of bytes to write
     * @param written Out parameter receiving the number of bytes written
     * @return One on success or zero on failure
     */
    public static int SSL_write_ex(MemorySegment s, MemorySegment buf, long num,
            MemorySegment written) {
        try {
            return (int) SSL_write_ex$handle.invokeExact(s, buf, num, written);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_write_ex2(SSL *s, const void *buf, size_t num, uint64_t flags, size_t *written)}
     * Extended write with flags support. This endpoint writes with {@code flags = 0}
     * and concludes via the separate {@code SSL_stream_conclude()} step (see
     * QuicOpenSSLSocketWrapper.doWrite); the atomic SSL_WRITE_FLAG_CONCLUDE
     * variant is deliberately unused.
     */
    public static final MethodHandle SSL_write_ex2$handle =
            createHandle("SSL_write_ex2",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, openssl_h.C_POINTER));

    /**
     * {@code int SSL_write_ex2(SSL *s, const void *buf, size_t num, uint64_t
     * flags, size_t *written)}
     *
     * @param s       The stream SSL object
     * @param buf     The buffer containing the data to write
     * @param num     The number of bytes to write
     * @param flags   The write flags: the {@code SSL_WRITE_FLAG_*} values
     *                (none are used by this package; {@code 0} for a plain
     *                write)
     * @param written Out parameter receiving the number of bytes written
     * @return One on success or zero on failure
     */
    public static int SSL_write_ex2(MemorySegment s, MemorySegment buf, long num, long flags,
            MemorySegment written) {
        try {
            return (int) SSL_write_ex2$handle.invokeExact(s, buf, num, flags, written);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_get_error(const SSL *s, int ret_code)}
     */
    public static final MethodHandle SSL_get_error$handle =
            createHandle("SSL_get_error",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_INT));

    /**
     * {@code int SSL_get_error(const SSL *s, int ret_code)}
     *
     * @param s       The SSL object the failed operation was performed on
     * @param retCode The return value of the failed operation
     * @return The error code for the most recent operation
     */
    public static int SSL_get_error(MemorySegment s, int retCode) {
        try {
            return (int) SSL_get_error$handle.invokeExact(s, retCode);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code SSL_ERROR_WANT_READ}: the operation did not complete; the caller
     * must await read readiness and retry.
     */
    public static final int SSL_ERROR_WANT_READ = 2;

    /**
     * {@code SSL_ERROR_WANT_WRITE}: the operation did not complete; the caller
     * must await write readiness and retry.
     */
    public static final int SSL_ERROR_WANT_WRITE = 3;

    /**
     * {@code int SSL_shutdown_ex(SSL *ssl, uint64_t flags, const SSL_SHUTDOWN_EX_ARGS *args, size_t args_len)}
     * Extended shutdown with flags for rapid drain, no stream flush, etc.
     */
    public static final MethodHandle SSL_shutdown_ex$handle =
            createHandle("SSL_shutdown_ex",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER, ValueLayout.JAVA_LONG));

    /**
     * {@code int SSL_shutdown_ex(SSL *ssl, uint64_t flags, const
     * SSL_SHUTDOWN_EX_ARGS *args, size_t args_len)}
     *
     * @param ssl     The SSL object to shut down
     * @param flags   The shutdown flags
     * @param args    Pointer to the shutdown arguments structure, or {@code NULL}
     * @param argsLen The size of the structure referenced by {@code args}
     * @return One on success or zero on failure
     */
    public static int SSL_shutdown_ex(MemorySegment ssl, long flags, MemorySegment args,
            long argsLen) {
        try {
            return (int) SSL_shutdown_ex$handle.invokeExact(ssl, flags, args, argsLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_get_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t *v)}
     * Gets a QUIC value (e.g., available streams, idle timeout). The
     * uint32_t parameters are marshalled as C ints, which FFM sign-extends
     * correctly for values below 2^31 (all defined identifiers are).
     */
    public static final MethodHandle SSL_get_value_uint$handle =
            createHandle("SSL_get_value_uint",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_INT, openssl_h.C_INT, openssl_h.C_POINTER));

    /**
     * {@code int SSL_get_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t *v)}
     *
     * @param s          The SSL object
     * @param valueClass The object class to read the value from
     * @param id         The identifier of the value to read
     * @param v          Out parameter receiving the value
     * @return One on success or zero on failure
     */
    public static int SSL_get_value_uint(MemorySegment s, int valueClass, int id,
            MemorySegment v) {
        try {
            return (int) SSL_get_value_uint$handle.invokeExact(s, valueClass, id, v);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_set_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t v)}
     * Sets a QUIC value (e.g., idle timeout, stream write buffer size). The
     * uint32_t parameters are marshalled as C ints, which FFM sign-extends
     * correctly for values below 2^31 (all defined identifiers are).
     */
    public static final MethodHandle SSL_set_value_uint$handle =
            createHandle("SSL_set_value_uint",
                    FunctionDescriptor.of(openssl_h.C_INT,
                            openssl_h.C_POINTER,
                            openssl_h.C_INT,
                            openssl_h.C_INT,
                            openssl_h.C_LONG));

    /**
     * {@code int SSL_set_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t v)}
     *
     * @param s          The SSL object
     * @param valueClass The object class to write the value to
     * @param id         The identifier of the value to write
     * @param v          The value to set
     * @return One on success or zero on failure
     */
    public static int SSL_set_value_uint(MemorySegment s, int valueClass, int id, long v) {
        try {
            return (int) SSL_set_value_uint$handle.invokeExact(s, valueClass, id, v);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // SSL_shutdown_ex flags
    /**
     * {@code SSL_shutdown_ex()} flag: close immediately without waiting
     * for the peer to acknowledge the close.
     */
    public static final long SSL_SHUTDOWN_FLAG_RAPID = 1L << 0;
    /**
     * {@code SSL_shutdown_ex()} flag: do not block; return instead of
     * waiting for the close to complete.
     */
    public static final long SSL_SHUTDOWN_FLAG_NO_BLOCK = 1L << 2;

    // SSL value class IDs (uint32_t in C, hence int)
    /**
     * Value class for generic (non-feature) {@code SSL_*_value_uint()}
     * values.
     */
    public static final int SSL_VALUE_CLASS_GENERIC = 0;
    /** Value class for QUIC features requested by the local endpoint. */
    public static final int SSL_VALUE_CLASS_FEATURE_REQUEST = 1;

    // SSL value IDs
    // The *_AVAIL stream values are read-only in OpenSSL 3.5/4.0: they must
    // be queried with SSL_get_value_uint() and SSL_VALUE_CLASS_GENERIC (the
    // BIDI/UNI _REMOTE_AVAIL pair is the stream-count flow-control credit
    // left to the peer, i.e. the initial_max_streams_bidi/uni the local
    // endpoint advertised, less the streams the peer has already opened).
    // SSL_set_value_uint() only supports SSL_VALUE_QUIC_IDLE_TIMEOUT and
    // SSL_VALUE_EVENT_HANDLING_MODE, so the transport cannot be instructed to
    // advertise a configured concurrency limit.
    /** Stream ID: bidirectional-stream credit advertised to the peer. */
    public static final int SSL_VALUE_QUIC_STREAM_BIDI_REMOTE_AVAIL = 2;
    /** Stream ID: unidirectional-stream credit advertised to the peer. */
    public static final int SSL_VALUE_QUIC_STREAM_UNI_REMOTE_AVAIL = 4;
    /** QUIC idle timeout in milliseconds, connection-level (settable). */
    public static final int SSL_VALUE_QUIC_IDLE_TIMEOUT = 5;
    /** Stream ID: event handling mode for the object (settable). */
    public static final int SSL_VALUE_EVENT_HANDLING_MODE = 6;
    /** Event handling mode: inherit the mode of the parent object. */
    public static final int SSL_VALUE_EVENT_HANDLING_MODE_INHERIT = 0;
    /**
     * Event handling mode (the OpenSSL default, reached through the inherit
     * default): every API call on the object drives event handling
     * implicitly - for a QUIC object that means ticking the whole shared
     * engine reactor (one walk of every channel of the engine) per call.
     */
    public static final int SSL_VALUE_EVENT_HANDLING_MODE_IMPLICIT = 1;
    /**
     * Event handling mode: API calls do not drive event handling; only the
     * explicit {@code SSL_handle_events()} (and {@code SSL_poll()} without
     * {@code SSL_POLL_FLAG_NO_HANDLE_EVENTS}) tick the engine.
     */
    public static final int SSL_VALUE_EVENT_HANDLING_MODE_EXPLICIT = 2;

    /**
     * {@code SSL_OP_ALLOW_NO_DHE_KEX} (SSL_OP_BIT(10) in openssl/ssl.h). Not
     * yet in the jextract-generated openssl_h; it is listed in
     * res/openssl/openssl-tomcat.conf so the next binding regeneration moves
     * it there and this copy can go away.
     */
    public static final long SSL_OP_ALLOW_NO_DHE_KEX = 1L << 10;

    /**
     * {@code int SSL_get_peer_addr(SSL *ssl, BIO_ADDR *peer_addr)}
     * Gets the peer address of a QUIC connection.
     */
    public static final MethodHandle SSL_get_peer_addr$handle =
            createHandle("SSL_get_peer_addr",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER, openssl_h.C_POINTER));

    /**
     * {@code int SSL_get_peer_addr(SSL *ssl, BIO_ADDR *peer_addr)}
     *
     * @param ssl      The connection SSL object
     * @param peerAddr Out structure receiving the address of the peer
     * @return One on success or zero on failure
     */
    public static int SSL_get_peer_addr(MemorySegment ssl, MemorySegment peerAddr) {
        try {
            return (int) SSL_get_peer_addr$handle.invokeExact(ssl, peerAddr);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int BIO_ADDR_family(const BIO_ADDR *ap)}
     * Returns the address family of a BIO_ADDR using its documented accessor
     * (BIO_ADDR is an opaque union of sockaddr structs; the raw layout must
     * not be parsed directly).
     */
    public static final MethodHandle BIO_ADDR_family$handle =
            createHandle("BIO_ADDR_family",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER));

    /**
     * {@code int BIO_ADDR_family(const BIO_ADDR *ap)}
     *
     * @param ap The BIO_ADDR structure to query
     * @return The address family constant of the address
     */
    public static int BIO_ADDR_family(MemorySegment ap) {
        try {
            return (int) BIO_ADDR_family$handle.invokeExact(ap);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l)}
     * Copies the raw 4 (IPv4) / 16 (IPv6) address bytes of a BIO_ADDR into
     * {@code p} and writes the copied length into {@code l}.
     */
    public static final MethodHandle BIO_ADDR_rawaddress$handle =
            createHandle("BIO_ADDR_rawaddress",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER, openssl_h.C_POINTER));

    /**
     * {@code int BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l)}
     *
     * @param ap The BIO_ADDR structure to query
     * @param p  Buffer receiving the raw address, or {@code NULL} to query the length only
     * @param l  Out parameter receiving the length of the address
     * @return One on success or zero on failure
     */
    public static int BIO_ADDR_rawaddress(MemorySegment ap, MemorySegment p, MemorySegment l) {
        try {
            return (int) BIO_ADDR_rawaddress$handle.invokeExact(ap, p, l);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap)}
     * Returns the raw port of a BIO_ADDR as stored in the socket structure
     * (network byte order in memory), delivered in the low 16 bits: on a
     * little-endian host the returned 16-bit value is the byte-swapped port,
     * on a big-endian host it is the port itself (the caller must mask and,
     * on little-endian only, byteswap it).
     */
    public static final MethodHandle BIO_ADDR_rawport$handle =
            createHandle("BIO_ADDR_rawport",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER));

    /**
     * {@code unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap)}
     *
     * @param ap The BIO_ADDR structure to query
     * @return The raw port as stored in the socket structure (network byte
     *         order in memory), delivered in the low 16 bits of the result
     *         (the caller must mask it and byteswap only on little-endian
     *         hosts)
     */
    public static int BIO_ADDR_rawport(MemorySegment ap) {
        try {
            return (int) BIO_ADDR_rawport$handle.invokeExact(ap);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_set_default_stream_mode(SSL *s, uint32_t mode)}
     * Sets the default stream mode for a QUIC connection.
     * Mode values: 0=NONE (stream-aware), 1=AUTO_BIDI, 2=AUTO_UNI
     * For HTTP/3, mode must be NONE to disable legacy single-stream mode.
     */
    public static final MethodHandle SSL_set_default_stream_mode$handle =
            createHandle("SSL_set_default_stream_mode",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER, openssl_h.C_INT));

    /**
     * {@code int SSL_set_default_stream_mode(SSL *s, uint32_t mode)}
     *
     * @param s    The connection SSL object
     * @param mode The default stream mode to apply
     * @return One on success or zero on failure
     */
    public static int SSL_set_default_stream_mode(MemorySegment s, int mode) {
        try {
            return (int) SSL_set_default_stream_mode$handle.invokeExact(s, mode);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * Default stream mode per OpenSSL ssl.h: stream-aware application
     * (required for HTTP/3). The auto-create modes (AUTO_BIDI/AUTO_UNI)
     * bind the SSL object to a single stream and are not used here.
     */
    public static final int SSL_DEFAULT_STREAM_MODE_NONE = 0;

    // -------------------------------------------------- Socket

    /**
     * {@code int SSL_set_blocking_mode(SSL *s, int blocking)}
     */
    public static final MethodHandle SSL_set_blocking_mode$handle =
            createHandle("SSL_set_blocking_mode",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER, openssl_h.C_INT));

    /**
     * {@code int SSL_set_blocking_mode(SSL *s, int blocking)}
     *
     * @param s        The SSL object
     * @param blocking {@code 1} to enable blocking mode, {@code 0} to disable it
     * @return One on success or zero on failure
     */
    public static int SSL_set_blocking_mode(MemorySegment s, int blocking) {
        try {
            return (int) SSL_set_blocking_mode$handle.invokeExact(s, blocking);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_set_fd(SSL *s, int fd)}
     */
    public static final MethodHandle SSL_set_fd$handle =
            createHandle("SSL_set_fd",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER, openssl_h.C_INT));

    /**
     * {@code int SSL_set_fd(SSL *s, int fd)}
     *
     * @param s  The connection SSL object
     * @param fd The file descriptor of the datagram socket backing the connection
     * @return One on success or zero on failure
     */
    public static int SSL_set_fd(MemorySegment s, int fd) {
        try {
            return (int) SSL_set_fd$handle.invokeExact(s, fd);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Socket (libc)

    /**
     * {@code int socket(int domain, int type, int protocol)}
     */
    public static final MethodHandle socket$handle = createLibcHandle("socket",
            FunctionDescriptor.of(openssl_h.C_INT,
                    openssl_h.C_INT, openssl_h.C_INT, openssl_h.C_INT));

    /**
     * {@code int socket(int domain, int type, int protocol)}
     *
     * @param domain   The address family of the socket
     * @param type     The socket type
     * @param protocol The socket protocol
     * @return The file descriptor of the new socket
     */
    public static int socket(int domain, int type, int protocol) {
        try {
            return (int) socket$handle.invokeExact(domain, type, protocol);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)}
     * socklen_t is unsigned int (32-bit) on Linux.
     */
    public static final MethodHandle bind$handle = createLibcHandle("bind",
            FunctionDescriptor.of(openssl_h.C_INT,
                    openssl_h.C_INT, openssl_h.C_POINTER, openssl_h.C_INT));

    /**
     * {@code int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)}
     *
     * @param sockfd  The file descriptor of the socket to bind
     * @param addr    The address to bind the socket to
     * @param addrlen The size of the address structure
     * @return Zero on success or {@code -1} on failure
     */
    public static int bind(int sockfd, MemorySegment addr, int addrlen) {
        try {
            return (int) bind$handle.invokeExact(sockfd, addr, addrlen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)}
     * Returns the socket's bound address and port; used to resolve the
     * actually assigned port after an ephemeral (port 0) bind.
     * socklen_t is unsigned int (32-bit) on Linux and is passed by pointer.
     */
    public static final MethodHandle getsockname$handle = createLibcHandle("getsockname",
            FunctionDescriptor.of(openssl_h.C_INT,
                    openssl_h.C_INT, openssl_h.C_POINTER, openssl_h.C_POINTER));

    /**
     * {@code int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)}
     *
     * @param sockfd  The file descriptor of the socket to query
     * @param addr    Out structure receiving the socket address
     * @param addrlen In/out parameter holding the size of the address structure
     * @return Zero on success or {@code -1} on failure
     */
    public static int getsockname(int sockfd, MemorySegment addr, MemorySegment addrlen) {
        try {
            return (int) getsockname$handle.invokeExact(sockfd, addr, addrlen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int close(int fd)}
     */
    public static final MethodHandle close$handle = createLibcHandle("close",
            FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_INT));

    /**
     * {@code int close(int fd)}
     *
     * @param fd The file descriptor to close
     * @return Zero on success or {@code -1} on failure
     */
    public static int close(int fd) {
        try {
            return (int) close$handle.invokeExact(fd);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int fcntl(int fd, int cmd, int arg)}
     */
    public static final MethodHandle fcntl$handle = createLibcHandle("fcntl",
            FunctionDescriptor.of(openssl_h.C_INT,
                    openssl_h.C_INT, openssl_h.C_INT, openssl_h.C_INT));

    /**
     * {@code int fcntl(int fd, int cmd, int arg)}
     *
     * @param fd  The file descriptor to control
     * @param cmd The control command
     * @param arg The argument of the control command
     * @return The result of the control command
     */
    public static int fcntl(int fd, int cmd, int arg) {
        try {
            return (int) fcntl$handle.invokeExact(fd, cmd, arg);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code char *strerror_r(int errnum, char *buf, size_t buflen)} - the
     * glibc (GNU) variant, which the Linux/glibc ABI this endpoint binds
     * exposes under that symbol name.
     */
    public static final MethodHandle strerror_r$handle = createLibcHandle("strerror_r",
            FunctionDescriptor.of(openssl_h.C_POINTER, openssl_h.C_INT,
                    openssl_h.C_POINTER, openssl_h.C_LONG));

    /**
     * Thread-safe description of an {@code errno} value. The plain
     * {@code strerror()} returns a pointer into a process-wide static buffer,
     * so two threads formatting an error at once (bind on the start thread, a
     * socket-option failure on the stop path) can garble each other's
     * message. glibc's {@code strerror_r()} returns a pointer to a message
     * that is either the caller's buffer or a thread-local string, so
     * concurrent callers never share storage; the caller's buffer is supplied
     * here so the common short messages stay in caller memory.
     *
     * @param errnum The {@code errno} value to describe
     * @return The description of the error number
     */
    public static String strerror(int errnum) {
        final int buflen = 256;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buf = arena.allocate(buflen);
            MemorySegment res = (MemorySegment) strerror_r$handle.invokeExact(
                    errnum, buf, (long) buflen);
            return res.getString(0);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int errno} - accessed via __errno_location()
     */
    public static final MethodHandle errno_location$handle = createLibcHandle("__errno_location",
            FunctionDescriptor.of(openssl_h.C_POINTER));

    /**
     * {@code int *__errno_location()}
     *
     * @return A pointer to the calling thread's {@code errno} variable
     */
    public static MemorySegment errno_location() {
        try {
            return (MemorySegment) errno_location$handle.invokeExact();
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * Reads the current thread's {@code errno}. The returned pointer of
     * {@code __errno_location()} is bound through the
     * {@code openssl_h.C_POINTER} target layout, so it is already readable;
     * the reinterpret below is a bound-limiting defence (an int-sized view
     * of the thread-local), not a prerequisite for the read.
     *
     * @return The errno value
     */
    public static int errno() {
        return errno_location().reinterpret(Integer.BYTES).get(ValueLayout.JAVA_INT, 0);
    }

    /**
     * {@code int poll(struct pollfd *fds, nfds_t nfds, int timeout)}
     * Polls file descriptors for I/O events.
     */
    public static final MethodHandle poll$handle = createLibcHandle("poll",
            FunctionDescriptor.of(openssl_h.C_INT,
                    openssl_h.C_POINTER, openssl_h.C_LONG, openssl_h.C_INT));

    /**
     * {@code int poll(struct pollfd *fds, nfds_t nfds, int timeout)}
     *
     * @param fds     The array of file descriptors to wait on
     * @param nfds    The number of entries in the array
     * @param timeout The maximum wait in milliseconds, {@code -1} to wait indefinitely
     * @return The number of ready file descriptors
     */
    public static int poll(MemorySegment fds, long nfds, int timeout) {
        try {
            return (int) poll$handle.invokeExact(fds, nfds, timeout);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int eventfd(unsigned int initval, int flags)}
     * Creates a wakeup event counter. The endpoint uses this so that
     * threads other than the QUIC poll thread can interrupt the poll
     * thread's blocking wait: {@code SSL_poll()} has no external wake
     * hook, so the poll loop waits on the UDP socket and this counter
     * together with {@code poll()} and drives {@code SSL_poll()} in
     * non-blocking mode.
     */
    public static final MethodHandle eventfd$handle = createLibcHandle("eventfd",
            FunctionDescriptor.of(openssl_h.C_INT,
                    openssl_h.C_INT, openssl_h.C_INT));

    /**
     * {@code int eventfd(unsigned int initval, int flags)}
     *
     * @param initval The initial value of the event counter
     * @param flags   Flags controlling the behaviour of the file descriptor
     * @return The file descriptor of the new event object
     */
    public static int eventfd(int initval, int flags) {
        try {
            return (int) eventfd$handle.invokeExact(initval, flags);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t write(int fd, const void *buf, size_t count)}
     */
    public static final MethodHandle write$handle = createLibcHandle("write",
            FunctionDescriptor.of(openssl_h.C_LONG,
                    openssl_h.C_INT, openssl_h.C_POINTER, openssl_h.C_LONG));

    /**
     * {@code ssize_t write(int fd, const void *buf, size_t count)}
     *
     * @param fd    The file descriptor to write to
     * @param buf   The buffer containing the data to write
     * @param count The number of bytes to write
     * @return The number of bytes written
     */
    public static long write(int fd, MemorySegment buf, long count) {
        try {
            return (long) write$handle.invokeExact(fd, buf, count);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t read(int fd, void *buf, size_t count)}
     */
    public static final MethodHandle read$handle = createLibcHandle("read",
            FunctionDescriptor.of(openssl_h.C_LONG,
                    openssl_h.C_INT, openssl_h.C_POINTER, openssl_h.C_LONG));

    /**
     * {@code ssize_t read(int fd, void *buf, size_t count)}
     *
     * @param fd    The file descriptor to read from
     * @param buf   The buffer that receives the data
     * @param count The maximum number of bytes to read
     * @return The number of bytes read
     */
    public static long read(int fd, MemorySegment buf, long count) {
        try {
            return (long) read$handle.invokeExact(fd, buf, count);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)}
     */
    public static final MethodHandle setsockopt$handle = createLibcHandle("setsockopt",
            FunctionDescriptor.of(openssl_h.C_INT,
                    openssl_h.C_INT, openssl_h.C_INT, openssl_h.C_INT,
                    openssl_h.C_POINTER, openssl_h.C_INT));

    /**
     * {@code int setsockopt(int sockfd, int level, int optname, const void
     * *optval, socklen_t optlen)}
     *
     * @param sockfd  The file descriptor of the socket to configure
     * @param level   The socket option level
     * @param optname The socket option name
     * @param optval  The buffer holding the option value
     * @param optlen  The size of the option value buffer
     * @return Zero on success or {@code -1} on failure
     */
    public static int setsockopt(int sockfd, int level, int optname, MemorySegment optval,
            int optlen) {
        try {
            return (int) setsockopt$handle.invokeExact(sockfd, level, optname, optval, optlen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // AF_INET constant
    /** Address family: IPv4. */
    public static final int AF_INET = 2;

    // AF_INET6 constant
    /** Address family: IPv6. */
    public static final int AF_INET6 = 10;

    // SOCK_DGRAM constant
    /** Socket type: datagram (used for the QUIC UDP socket). */
    public static final int SOCK_DGRAM = 2;

    // fcntl commands
    /** {@code fcntl()} command: get the file status flags. */
    public static final int F_GETFL = 3;
    /** {@code fcntl()} command: set the file status flags. */
    public static final int F_SETFL = 4;
    /** File status flag: non-blocking I/O (octal 04000 on Linux). */
    public static final int O_NONBLOCK = 04000;  // Octal 04000 = 2048 decimal

    // Socket option levels
    /** Socket option level: the socket API itself. */
    public static final int SOL_SOCKET = 1;

    // Socket options
    /** Socket option: allow binding an address in TIME_WAIT. */
    public static final int SO_REUSEADDR = 2;

    // IPv6 option level / names (Linux values; IPV6_V6ONLY is 27 on
    // BSD/Darwin/FreeBSD, a different numbering on Windows)
    /** Socket option level: the IPv6 protocol. */
    public static final int IPPROTO_IPV6 = 41;
    /** IPv6 option: restrict the socket to IPv6 traffic only. */
    public static final int IPV6_V6ONLY = 26;

    // errno values (Linux ABI) used by the wildcard-bind fallback
    /** errno: operation not permitted. */
    public static final int EPERM = 1;
    /** errno: address family not supported by protocol. */
    public static final int EAFNOSUPPORT = 97;
    /** errno: cannot assign requested address. */
    public static final int EADDRNOTAVAIL = 99;
    // Linux values (BSD uses 0x1012/0x1011): SO_RCVBUF=8, SO_SNDBUF=7
    /** Socket option: receive buffer size. */
    public static final int SO_RCVBUF = 8;
    /** Socket option: send buffer size. */
    public static final int SO_SNDBUF = 7;

    // -------------------------------------------------- SNI / certificate selection

    /**
     * {@code TLSEXT_NAMETYPE_host_name}: the type of SNI entry that identifies
     * a host name (RFC 6066).
     */
    public static final int TLSEXT_NAMETYPE_HOST_NAME = 0;

    /**
     * Return values for the SNI (server name) callback. Values per OpenSSL 4.0
     * tls1.h.
     */
    public static final int SSL_TLSEXT_ERR_OK = 0;
    /** SNI callback result: continue the handshake but send a warning alert. */
    public static final int SSL_TLSEXT_ERR_ALERT_WARNING = 1;
    /** SNI callback result: send a fatal alert and abort the handshake. */
    public static final int SSL_TLSEXT_ERR_ALERT_FATAL = 2;
    /** SNI callback result: no acknowledgement of the server name. */
    public static final int SSL_TLSEXT_ERR_NOACK = 3;

    // SSL_CTRL command codes for SSL_CTX_ctrl()/SSL_ctrl(). Values per
    // OpenSSL 4.0 ssl.h. In OpenSSL 4.0 the
    // SSL_CTX_set_tlsext_servername_callback()/SSL_CTX_add1_chain_cert()/
    // SSL_add1_chain_cert() APIs are macros over these ctrl commands.
    /** {@code SSL_ctrl()} command: add an {@code SSL_MODE} bit. */
    public static final int SSL_CTRL_MODE = 33;
    /** {@code SSL_CTX_ctrl()} command: set the SNI callback. */
    public static final int SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = 53;
    /** {@code SSL_CTX_ctrl()} command: set the SNI callback argument. */
    public static final int SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54;
    /**
     * {@code SSL_set0_chain}/{@code SSL_clear_chain_certs} macro command.
     * With {@code larg = 0} and {@code parg = NULL} it frees the chain of
     * the SSL's current key entry ({@code ssl_cert_set0_chain}); with
     * {@code parg} a stack it replaces the chain with that stack. (The
     * context-level extra-chain list is not managed by this endpoint; the
     * {@code SSL_CTX_clear_extra_chain_certs} command it would need has no
     * {@code ssl3_ctrl} case at SSL level anyway - an {@code SSL_ctrl} call
     * with it returns 0 having done nothing.)
     */
    public static final int SSL_CTRL_CHAIN = 88;
    /**
     * Append-only: {@code SSL_add1_chain_cert(ssl, x)} macro command
     * (with {@code larg = 1}); pushes onto the current key entry's chain.
     */
    public static final int SSL_CTRL_CHAIN_CERT = 89;

    /**
     * {@code SSL_MODE} bit applied via {@code SSL_CTX_ctrl(SSL_CTRL_MODE)}.
     * The QUIC endpoint sets {@code SSL_MODE_ENABLE_PARTIAL_WRITE} on its SSL
     * context so stream writes are partial-accepting writers: without the
     * mode, {@code SSL_write_ex()} on a QUIC stream is an all-or-nothing
     * writer that arms an internal retry state demanding the very same
     * buffer address and length on the next call, which every fresh-buffer
     * staging write path in this package would violate once a peer's stream
     * credit accepts only a prefix.
     */
    public static final int SSL_MODE_ENABLE_PARTIAL_WRITE = 0x00000001;

    /**
     * {@code const char *SSL_get_servername(const SSL *s, int type)}
     * Returns the server name of the given type (e.g. the SNI host name) sent
     * by the peer, or NULL if no such server name was sent.
     */
    public static final MethodHandle SSL_get_servername$handle =
            createHandle("SSL_get_servername",
                    FunctionDescriptor.of(openssl_h.C_POINTER, openssl_h.C_POINTER,
                            openssl_h.C_INT));

    /**
     * {@code const char *SSL_get_servername(const SSL *s, int type)}
     *
     * @param s    The SSL object
     * @param type The type of name to retrieve
     * @return The server name, or {@code NULL} if none was indicated
     */
    public static MemorySegment SSL_get_servername(MemorySegment s, int type) {
        try {
            return (MemorySegment) SSL_get_servername$handle.invokeExact(s, type);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char
     * **data, unsigned int *len)}
     * Returns a pointer to the protocol negotiated by ALPN (or NPN) along
     * with its length. The memory is owned by the SSL object; it is valid
     * until the SSL object is freed. {@code *data} is set to NULL when no
     * protocol was negotiated.
     */
    public static final MethodHandle SSL_get0_alpn_selected$handle =
            createHandle("SSL_get0_alpn_selected",
                    FunctionDescriptor.ofVoid(openssl_h.C_POINTER,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char
     * **data, unsigned int *len)}
     *
     * @param ssl  The SSL object
     * @param data Out parameter receiving the selected protocol bytes
     * @param len  Out parameter receiving the length of the selected protocol
     */
    public static void SSL_get0_alpn_selected(MemorySegment ssl, MemorySegment data,
            MemorySegment len) {
        try {
            SSL_get0_alpn_selected$handle.invokeExact(ssl, data, len);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_use_certificate(SSL *ssl, X509 *x)}
     * Sets the certificate to be used by this specific SSL object, overriding
     * the SSL_CTX default for this connection only. Takes a reference on the
     * certificate.
     */
    public static final MethodHandle SSL_use_certificate$handle =
            createHandle("SSL_use_certificate",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER));

    /**
     * {@code int SSL_use_certificate(SSL *ssl, X509 *x)}
     *
     * @param ssl The SSL object
     * @param x   The certificate to use
     * @return One on success or zero on failure
     */
    public static int SSL_use_certificate(MemorySegment ssl, MemorySegment x) {
        try {
            return (int) SSL_use_certificate$handle.invokeExact(ssl, x);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *key)}
     * Sets the private key to be used by this specific SSL object, overriding
     * the SSL_CTX default for this connection only. Takes a reference on the
     * key.
     */
    public static final MethodHandle SSL_use_PrivateKey$handle =
            createHandle("SSL_use_PrivateKey",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER));

    /**
     * {@code int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *key)}
     *
     * @param ssl The SSL object
     * @param key The private key to use
     * @return One on success or zero on failure
     */
    public static int SSL_use_PrivateKey(MemorySegment ssl, MemorySegment key) {
        try {
            return (int) SSL_use_PrivateKey$handle.invokeExact(ssl, key);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void X509_free(X509 *a)}
     * Releases one reference to an X509 object allocated on the OpenSSL heap
     * (for example by the PEM/d2i loaders). {@code SSL_use_certificate()} and
     * {@code SSL_add1_chain_cert()} increment the object's own reference count,
     * so releasing the configuration's reference after applying a certificate
     * does not free an object that live connections still hold - the object
     * survives until those connections release it. See the endpoint's
     * {@code freeCertConfig()} / {@code swapCertConfig()} reload analysis.
     */
    public static final MethodHandle X509_free$handle =
            createHandle("X509_free",
                    FunctionDescriptor.ofVoid(openssl_h.C_POINTER));

    /**
     * {@code void X509_free(X509 *a)}
     *
     * @param a The certificate to free
     */
    public static void X509_free(MemorySegment a) {
        try {
            X509_free$handle.invokeExact(a);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void EVP_PKEY_free(EVP_PKEY *pkey)}
     * Releases one reference to an EVP_PKEY object allocated on the OpenSSL heap
     * (for example by {@code d2i_AutoPrivateKey}). {@code SSL_use_PrivateKey()}
     * increments the object's own reference count, so releasing the
     * configuration's reference after applying a key does not free a key that
     * live connections still hold - the key survives until those connections
     * release it. See the endpoint's {@code freeCertConfig()} /
     * {@code swapCertConfig()} reload analysis.
     */
    public static final MethodHandle EVP_PKEY_free$handle =
            createHandle("EVP_PKEY_free",
                    FunctionDescriptor.ofVoid(openssl_h.C_POINTER));

    /**
     * {@code void EVP_PKEY_free(EVP_PKEY *pkey)}
     *
     * @param pkey The private key to free
     */
    public static void EVP_PKEY_free(MemorySegment pkey) {
        try {
            EVP_PKEY_free$handle.invokeExact(pkey);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)}
     * Implements, amongst others, the OpenSSL 4.0 macros
     * {@code SSL_CTX_add1_chain_cert(ctx, x)} (cmd =
     * {@link #SSL_CTRL_CHAIN_CERT}, larg = 1).
     */
    public static final MethodHandle SSL_CTX_ctrl$handle =
            createHandle("SSL_CTX_ctrl",
                    FunctionDescriptor.of(openssl_h.C_LONG, openssl_h.C_POINTER,
                            openssl_h.C_INT, openssl_h.C_LONG, openssl_h.C_POINTER));

    /**
     * {@code long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)}
     *
     * @param ctx  The SSL context
     * @param cmd  The control command
     * @param larg The long argument of the control command
     * @param parg The pointer argument of the control command
     * @return The result of the control command
     */
    public static long SSL_CTX_ctrl(MemorySegment ctx, int cmd, long larg, MemorySegment parg) {
        try {
            return (long) SSL_CTX_ctrl$handle.invokeExact(ctx, cmd, larg, parg);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)}
     * Implements, amongst others, the OpenSSL 4.0 macros
     * {@code SSL_add1_chain_cert(ssl, x)} (cmd = {@link #SSL_CTRL_CHAIN_CERT},
     * larg = 1) and {@code SSL_clear_chain_certs(ssl)} (cmd =
     * {@link #SSL_CTRL_CHAIN}, larg = 0, parg = NULL). Note that
     * {@code SSL_clear_extra_chain_certs(ssl)} is an {@code SSL_CTX}-only
     * command in OpenSSL 4.x macros: an {@code SSL_ctrl} call with the
     * extra-chain-clear command returns 0 without any effect.
     */
    public static final MethodHandle SSL_ctrl$handle =
            createHandle("SSL_ctrl",
                    FunctionDescriptor.of(openssl_h.C_LONG, openssl_h.C_POINTER,
                            openssl_h.C_INT, openssl_h.C_LONG, openssl_h.C_POINTER));

    /**
     * {@code long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)}
     *
     * @param ssl  The SSL object
     * @param cmd  The control command
     * @param larg The long argument of the control command
     * @param parg The pointer argument of the control command
     * @return The result of the control command
     */
    public static long SSL_ctrl(MemorySegment ssl, int cmd, long larg, MemorySegment parg) {
        try {
            return (long) SSL_ctrl$handle.invokeExact(ssl, cmd, larg, parg);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code long SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp)(void))}
     * With cmd = {@link #SSL_CTRL_SET_TLSEXT_SERVERNAME_CB} this implements the
     * OpenSSL 4.0 macro {@code SSL_CTX_set_tlsext_servername_callback(ctx, cb)}
     * where the callback has the signature
     * {@code int callback(SSL *s, int *al, void *arg)}.
     */
    public static final MethodHandle SSL_CTX_callback_ctrl$handle =
            createHandle("SSL_CTX_callback_ctrl",
                    FunctionDescriptor.of(openssl_h.C_LONG, openssl_h.C_POINTER,
                            openssl_h.C_INT, openssl_h.C_POINTER));

    /**
     * {@code long SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp)(void))}
     *
     * @param ctx The SSL context
     * @param cmd The control command
     * @param fp  The callback function to install
     * @return The result of the control command
     */
    public static long SSL_CTX_callback_ctrl(MemorySegment ctx, int cmd, MemorySegment fp) {
        try {
            return (long) SSL_CTX_callback_ctrl$handle.invokeExact(ctx, cmd, fp);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Poll

    /**
     * {@code int SSL_poll(SSL_POLL_ITEM *items, size_t num_items, size_t stride,
     *                     const struct timeval *timeout, uint64_t flags, size_t *result_count)}
     */
    public static final MethodHandle SSL_poll$handle =
            createHandle("SSL_poll",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER));

    /**
     * {@code int SSL_poll(SSL_POLL_ITEM *items, size_t num_items, size_t stride,
     * const struct timeval *timeout, uint64_t flags, size_t *result_count)}
     *
     * @param items       The array of poll items to wait on
     * @param numItems    The number of items in the array
     * @param stride      The size of each item in the array
     * @param timeout     The maximum wait as a {@code struct timeval}:
     *                    {@code NULL} blocks indefinitely until a resource is
     *                    ready; a pointer to a zero-valued {@code timeval}
     *                    selects non-blocking mode (return immediately with
     *                    the readiness information); a non-zero value blocks
     *                    for at most that interval
     * @param flags       The poll behaviour flags
     * @param resultCount Out parameter receiving the number of ready items
     * @return One on success or zero on failure
     */
    public static int SSL_poll(MemorySegment items, long numItems, long stride,
            MemorySegment timeout, long flags, MemorySegment resultCount) {
        try {
            return (int) SSL_poll$handle.invokeExact(items, numItems, stride,
                    timeout, flags, resultCount);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int SSL_get_event_timeout(SSL *s, struct timeval *tv, int *is_infinite)}
     * Reports when QUIC internal processing next wants to run for this
     * object: the endpoint caps its poll wait by the earliest deadline so
     * timer-driven work (retransmission, close_notify) is not delayed by
     * the poll-loop cadence when {@code SSL_poll()} runs in non-blocking
     * mode.
     */
    public static final MethodHandle SSL_get_event_timeout$handle =
            createHandle("SSL_get_event_timeout",
                    FunctionDescriptor.of(openssl_h.C_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER, openssl_h.C_POINTER));

    /**
     * {@code int SSL_get_event_timeout(SSL *s, struct timeval *tv, int *is_infinite)}
     *
     * @param ssl   The SSL object
     * @param tv    Out structure receiving the next event deadline
     * @param isInf Out flag reporting whether the deadline is unbounded
     * @return One on success or zero on failure
     */
    public static int SSL_get_event_timeout(MemorySegment ssl, MemorySegment tv,
            MemorySegment isInf) {
        try {
            return (int) SSL_get_event_timeout$handle.invokeExact(ssl, tv, isInf);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Helpers

    private static MethodHandle createHandle(String symbol, FunctionDescriptor desc) {
        try {
            MemorySegment addr = openssl_h.SYMBOL_LOOKUP.find(symbol)
                    .orElseThrow(() -> new UnsatisfiedLinkError("unresolved QUIC symbol: " + symbol));
            return Linker.nativeLinker().downcallHandle(addr, desc);
        } catch (Throwable e) {
            // The bind attempt itself is the availability probe: record the
            // failure so QUIC_AVAILABLE turns false at the end of static
            // initialisation (see the field's javadoc).
            MISSING_SYMBOLS.add(symbol);
            return null;
        }
    }

    /**
     * Creates a downcall handle for a libc symbol.
     */
    private static MethodHandle createLibcHandle(String symbol, FunctionDescriptor desc) {
        try {
            // Use openssl_h's symbol lookup which works for libc symbols too
            // since they're all in the same process address space
            MemorySegment addr = openssl_h.SYMBOL_LOOKUP.find(symbol)
                    .orElseThrow(() -> new UnsatisfiedLinkError("unresolved libc symbol: " + symbol));
            return Linker.nativeLinker().downcallHandle(addr, desc);
        } catch (Throwable e) {
            // See createHandle(): the bind attempt is the availability probe.
            MISSING_SYMBOLS.add(symbol);
            return null;
        }
    }

    // Runs after every handle field above (static initialisers execute in
    // textual order): every symbol this class binds has now been probed by
    // its own createHandle()/createLibcHandle() call, so the availability
    // verdict is simply "nothing failed to bind". Consumers must not read
    // QUIC_AVAILABLE from a static context earlier in this class - there is
    // none, the handle initialisers deliberately bind unconditionally.
    static {
        QUIC_AVAILABLE = MISSING_SYMBOLS.isEmpty();
    }
}

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

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.res.StringManager;

/**
 * FFM bindings for the Cloudflare quiche QUIC library (the {@code quiche} C
 * API, quiche built with the {@code ffi} cargo feature) plus the libc
 * datagram-socket helpers the quiche endpoint needs.
 * <p>
 * All bindings are handwritten downcall handles, mirroring the pattern of
 * {@code org.apache.tomcat.util.net.quic.openssl.QuicBindings}. Signatures are pinned
 * against {@code quiche/include/quiche.h} and the struct layouts below are
 * Linux LP64. Those layouts were validated against the quiche 0.30 release
 * series only - the C FFI structs are not ABI-stable across quiche releases -
 * so the static initializer gates the loaded library to that series at
 * runtime (see {@link #QUICHE_ABI_SERIES}): a library outside the series is
 * reported as unavailable with a logged error instead of being used with
 * mismatched struct layouts (which would corrupt memory silently).
 * <p>
 * This class is entirely self-contained: it requires only {@code libquiche}
 * (which bundles its own TLS stack) and libc, never libssl.
 */
public final class QuicheBindings {

    private QuicheBindings() {
        // Utility class - should not be instantiated
    }

    private static final Log log = LogFactory.getLog(QuicheBindings.class);

    private static final StringManager sm = StringManager.getManager(QuicheBindings.class);

    // -------------------------------------------------- Availability check

    /**
     * The quiche version series whose C FFI struct layouts (in particular
     * {@code quiche_recv_info} and {@code quiche_send_info}) the descriptors
     * in this class were validated against. Re-validate the layouts against
     * {@code quiche/include/quiche.h} and bump this constant to adopt a newer
     * quiche series.
     */
    private static final String QUICHE_ABI_SERIES = "0.30";

    /**
     * Whether quiche (with the {@code ffi} feature symbols) could be loaded
     * and every symbol this class resolves is present. A quiche build without
     * the ffi feature exposes no C symbols at all and is rejected here,
     * exactly like the OpenSSL probe rejects a libssl without QUIC APIs.
     * Computed (at the end of this class's static initialisation, below)
     * from the symbol failures recorded while the downcall handles were
     * created: every symbol this class binds is probed by the very call that
     * binds it, so the availability check and the bound-symbol set can never
     * drift apart.
     */
    private static final boolean SYMBOLS_AVAILABLE;

    /**
     * Symbols whose lookup or downcall binding failed during static
     * initialisation, populated by {@code createHandle()} and
     * {@code createLibcHandle()}. Empty means every symbol this class binds
     * is present in the loaded library.
     */
    private static final Set<String> MISSING_SYMBOLS = new LinkedHashSet<>();

    /**
     * Whether the loaded library's {@code quiche_version()} matched the
     * {@link #QUICHE_ABI_SERIES} gate. Assigned by the version static
     * initialiser below; combined with {@code SYMBOLS_AVAILABLE} by the
     * final one.
     */
    private static final boolean ABI_COMPATIBLE;

    /**
     * Whether the quiche transport is usable: every symbol this class
     * resolves is present and the loaded library passed the ABI version gate
     * (see {@link #QUICHE_ABI_SERIES}).
     */
    static final boolean QUICHE_AVAILABLE;

    /**
     * The {@code quiche_version()} string, or {@code null} if unavailable.
     * Logged at bind time.
     */
    static final String QUICHE_VERSION;

    static final SymbolLookup QUICHE_LOOKUP;

    static {
        SymbolLookup lookup;
        try {
            System.loadLibrary("quiche");
            lookup = Linker.nativeLinker().defaultLookup().or(
                    SymbolLookup.loaderLookup());
        } catch (Throwable e) {
            lookup = null;
        }
        QUICHE_LOOKUP = lookup;
        // The symbol availability verdict is not computed here: it needs
        // every handle bound (the handle initialisers follow), and the
        // version string needs quiche_version$handle. Both are resolved by
        // the static initialisers below.
    }

    // -------------------------------------------------- quiche constants

    /** The current QUIC wire version ({@code QUICHE_PROTOCOL_VERSION}). */
    static final int QUICHE_PROTOCOL_VERSION = 0x00000001;

    /** The maximum length of a connection ID. */
    static final int QUICHE_MAX_CONN_ID_LEN = 20;

    // Error codes (quiche_error), negative range -1..-23. Values per
    // quiche.h (the full enum; only the codes the transport branches on
    // are referenced elsewhere).
    static final int QUICHE_ERR_DONE = -1;
    static final int QUICHE_ERR_BUFFER_TOO_SHORT = -2;
    static final int QUICHE_ERR_UNKNOWN_VERSION = -3;
    static final int QUICHE_ERR_INVALID_FRAME = -4;
    static final int QUICHE_ERR_INVALID_PACKET = -5;
    static final int QUICHE_ERR_INVALID_STATE = -6;
    static final int QUICHE_ERR_INVALID_STREAM_STATE = -7;
    static final int QUICHE_ERR_INVALID_TRANSPORT_PARAM = -8;
    static final int QUICHE_ERR_CRYPTO_FAIL = -9;
    static final int QUICHE_ERR_TLS_FAIL = -10;
    static final int QUICHE_ERR_FLOW_CONTROL = -11;
    static final int QUICHE_ERR_STREAM_LIMIT = -12;
    static final int QUICHE_ERR_FINAL_SIZE = -13;
    static final int QUICHE_ERR_CONGESTION_CONTROL = -14;
    static final int QUICHE_ERR_STREAM_STOPPED = -15;
    static final int QUICHE_ERR_STREAM_RESET = -16;
    static final int QUICHE_ERR_ID_LIMIT = -17;
    static final int QUICHE_ERR_OUT_OF_IDENTIFIERS = -18;
    static final int QUICHE_ERR_KEY_UPDATE = -19;
    static final int QUICHE_ERR_CRYPTO_BUFFER_EXCEEDED = -20;
    static final int QUICHE_ERR_INVALID_ACK_RANGE = -21;
    static final int QUICHE_ERR_OPTIMISTIC_ACK_DETECTED = -22;
    static final int QUICHE_ERR_INVALID_DCID_INITIALIZATION = -23;

    // quiche_header_info() packet-type values (quiche_ffi Type mapping:
    // Initial=1, Retry=2, Handshake=3, ZeroRTT=4, Short=5,
    // VersionNegotiation=6). Only the types the demultiplexer inspects are
    // bound; the full enum lives in quiche.h.
    static final int QUICHE_PACKET_TYPE_INITIAL = 1;
    static final int QUICHE_PACKET_TYPE_SHORT = 5;

    /** {@code QUICHE_SHUTDOWN_READ} (STOP_SENDING + drop the read side). */
    static final int QUICHE_SHUTDOWN_READ = 0;
    /** {@code QUICHE_SHUTDOWN_WRITE} (RESET_STREAM + drop the write side). */
    static final int QUICHE_SHUTDOWN_WRITE = 1;

    /**
     * QUIC transport error code CONNECTION_REFUSED (RFC 9000 Section 6.2),
     * used for server-side connection rejection before the handshake is
     * established (where an application error code cannot be carried).
     */
    static final long QUICHE_TRANSPORT_CONNECTION_REFUSED = 0x02;

    // -------------------------------------------------- Version

    /**
     * {@code const char *quiche_version(void)}
     */
    static final MethodHandle quiche_version$handle =
            createHandle("quiche_version", FunctionDescriptor.of(ValueLayout.ADDRESS));

    /**
     * {@code const char *quiche_version(void)}
     */
    static MemorySegment quiche_version() {
        try {
            return (MemorySegment) quiche_version$handle.invokeExact();
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    static {
        String version = null;
        if (quiche_version$handle != null) {
            try {
                // A NULL return comes back as the address-zero segment; reading
                // it would fault the JVM (an uncatchable SIGSEGV, so the catch
                // below would not help), so skip it and fail closed instead.
                MemorySegment p = quiche_version();
                if (!p.equals(MemorySegment.NULL)) {
                    version = p.reinterpret(64).getString(0);
                }
            } catch (Throwable t) {
                // Fail closed: an unreadable version cannot be confirmed
                // ABI-compatible.
                version = null;
            }
        }
        QUICHE_VERSION = version;
        boolean abiCompatible = version != null && (version.equals(QUICHE_ABI_SERIES)
                || version.startsWith(QUICHE_ABI_SERIES + "."));
        if (quiche_version$handle != null && !abiCompatible) {
            log.error(sm.getString("quicheBindings.abiMismatch",
                    String.valueOf(version), QUICHE_ABI_SERIES));
        }
        ABI_COMPATIBLE = abiCompatible;
    }

    // -------------------------------------------------- Config

    /**
     * {@code quiche_config *quiche_config_new(uint32_t version)}
     */
    static final MethodHandle quiche_config_new$handle =
            createHandle("quiche_config_new", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

    /**
     * {@code quiche_config *quiche_config_new(uint32_t version)}
     */
    static MemorySegment quiche_config_new(int version) {
        try {
            return (MemorySegment) quiche_config_new$handle.invokeExact(version);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_config_free(quiche_config *config)}
     */
    static final MethodHandle quiche_config_free$handle =
            createHandle("quiche_config_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    /**
     * {@code void quiche_config_free(quiche_config *config)}
     */
    static void quiche_config_free(MemorySegment config) {
        try {
            quiche_config_free$handle.invokeExact(config);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int quiche_config_load_cert_chain_from_pem_file(quiche_config
     * *config, const char *path)}
     */
    static final MethodHandle quiche_config_load_cert_chain_from_pem_file$handle =
            createHandle("quiche_config_load_cert_chain_from_pem_file",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code int quiche_config_load_cert_chain_from_pem_file(quiche_config
     * *config, const char *path)}
     */
    static int quiche_config_load_cert_chain_from_pem_file(MemorySegment config,
            MemorySegment path) {
        try {
            return (int) quiche_config_load_cert_chain_from_pem_file$handle.invokeExact(config, path);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int quiche_config_load_priv_key_from_pem_file(quiche_config
     * *config, const char *path)}
     */
    static final MethodHandle quiche_config_load_priv_key_from_pem_file$handle =
            createHandle("quiche_config_load_priv_key_from_pem_file",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code int quiche_config_load_priv_key_from_pem_file(quiche_config
     * *config, const char *path)}
     */
    static int quiche_config_load_priv_key_from_pem_file(MemorySegment config,
            MemorySegment path) {
        try {
            return (int) quiche_config_load_priv_key_from_pem_file$handle.invokeExact(config, path);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int quiche_config_set_application_protos(quiche_config *config,
     * const uint8_t *protos, size_t protos_len)}
     */
    static final MethodHandle quiche_config_set_application_protos$handle =
            createHandle("quiche_config_set_application_protos",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code int quiche_config_set_application_protos(quiche_config *config,
     * const uint8_t *protos, size_t protos_len)}
     */
    static int quiche_config_set_application_protos(MemorySegment config,
            MemorySegment protos, long protosLen) {
        try {
            return (int) quiche_config_set_application_protos$handle.invokeExact(config,
                    protos, protosLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_config_set_max_idle_timeout(quiche_config *config,
     * uint64_t v)}
     */
    static final MethodHandle quiche_config_set_max_idle_timeout$handle =
            createHandle("quiche_config_set_max_idle_timeout",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code void quiche_config_set_max_idle_timeout(quiche_config *config,
     * uint64_t v)}
     */
    static void quiche_config_set_max_idle_timeout(MemorySegment config, long v) {
        try {
            quiche_config_set_max_idle_timeout$handle.invokeExact(config, v);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // The per-packet UDP payload sizes are deliberately left at quiche's
    // config defaults: no quiche_config_set_max_recv/send_udp_payload_size
    // binding is kept here because nothing calls them. The effective send
    // cap comes from the SEND_BUFFER_SIZE clamp in the endpoint's sendLoop
    // (which also keeps the quiche_send BUFFER_TOO_SHORT path unreachable),
    // read back per connection via quiche_conn_max_send_udp_payload_size.

    /**
     * {@code void quiche_config_set_initial_max_data(quiche_config *config,
     * uint64_t v)}
     */
    static final MethodHandle quiche_config_set_initial_max_data$handle =
            createHandle("quiche_config_set_initial_max_data",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code void quiche_config_set_initial_max_data(quiche_config *config,
     * uint64_t v)}
     */
    static void quiche_config_set_initial_max_data(MemorySegment config, long v) {
        try {
            quiche_config_set_initial_max_data$handle.invokeExact(config, v);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_config_set_initial_max_stream_data_bidi_local
     * (quiche_config *config, uint64_t v)}
     */
    static final MethodHandle quiche_config_set_initial_max_stream_data_bidi_local$handle =
            createHandle("quiche_config_set_initial_max_stream_data_bidi_local",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code void quiche_config_set_initial_max_stream_data_bidi_local
     * (quiche_config *config, uint64_t v)}
     */
    static void quiche_config_set_initial_max_stream_data_bidi_local(
            MemorySegment config, long v) {
        try {
            quiche_config_set_initial_max_stream_data_bidi_local$handle.invokeExact(config, v);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_config_set_initial_max_stream_data_bidi_remote
     * (quiche_config *config, uint64_t v)}
     */
    static final MethodHandle quiche_config_set_initial_max_stream_data_bidi_remote$handle =
            createHandle("quiche_config_set_initial_max_stream_data_bidi_remote",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code void quiche_config_set_initial_max_stream_data_bidi_remote
     * (quiche_config *config, uint64_t v)}
     */
    static void quiche_config_set_initial_max_stream_data_bidi_remote(
            MemorySegment config, long v) {
        try {
            quiche_config_set_initial_max_stream_data_bidi_remote$handle.invokeExact(config, v);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_config_set_initial_max_stream_data_uni(quiche_config
     * *config, uint64_t v)}
     */
    static final MethodHandle quiche_config_set_initial_max_stream_data_uni$handle =
            createHandle("quiche_config_set_initial_max_stream_data_uni",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code void quiche_config_set_initial_max_stream_data_uni(quiche_config
     * *config, uint64_t v)}
     */
    static void quiche_config_set_initial_max_stream_data_uni(MemorySegment config,
            long v) {
        try {
            quiche_config_set_initial_max_stream_data_uni$handle.invokeExact(config, v);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_config_set_initial_max_streams_bidi(quiche_config
     * *config, uint64_t v)}
     */
    static final MethodHandle quiche_config_set_initial_max_streams_bidi$handle =
            createHandle("quiche_config_set_initial_max_streams_bidi",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code void quiche_config_set_initial_max_streams_bidi(quiche_config
     * *config, uint64_t v)}
     */
    static void quiche_config_set_initial_max_streams_bidi(MemorySegment config, long v) {
        try {
            quiche_config_set_initial_max_streams_bidi$handle.invokeExact(config, v);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_config_set_initial_max_streams_uni(quiche_config
     * *config, uint64_t v)}
     */
    static final MethodHandle quiche_config_set_initial_max_streams_uni$handle =
            createHandle("quiche_config_set_initial_max_streams_uni",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code void quiche_config_set_initial_max_streams_uni(quiche_config
     * *config, uint64_t v)}
     */
    static void quiche_config_set_initial_max_streams_uni(MemorySegment config, long v) {
        try {
            quiche_config_set_initial_max_streams_uni$handle.invokeExact(config, v);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Demux / version negotiation

    /**
     * {@code int quiche_header_info(const uint8_t *buf, size_t buf_len, size_t
     * dcil, uint32_t *version, uint8_t *type, uint8_t *scid, size_t *scid_len,
     * uint8_t *dcid, size_t *dcid_len, uint8_t *token, size_t *token_len)}
     */
    static final MethodHandle quiche_header_info$handle =
            createHandle("quiche_header_info",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code int quiche_header_info(const uint8_t *buf, size_t buf_len, size_t
     * dcil, uint32_t *version, uint8_t *type, uint8_t *scid, size_t *scid_len,
     * uint8_t *dcid, size_t *dcid_len, uint8_t *token, size_t *token_len)}
     */
    static int quiche_header_info(MemorySegment buf, long bufLen, long dcil,
            MemorySegment version, MemorySegment type, MemorySegment scid,
            MemorySegment scidLen, MemorySegment dcid, MemorySegment dcidLen,
            MemorySegment token, MemorySegment tokenLen) {
        try {
            return (int) quiche_header_info$handle.invokeExact(buf, bufLen, dcil,
                    version, type, scid, scidLen, dcid, dcidLen, token, tokenLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code bool quiche_version_is_supported(uint32_t version)}
     */
    static final MethodHandle quiche_version_is_supported$handle =
            createHandle("quiche_version_is_supported",
                    FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.JAVA_INT));

    /**
     * {@code bool quiche_version_is_supported(uint32_t version)}
     */
    static boolean quiche_version_is_supported(int version) {
        try {
            return (boolean) quiche_version_is_supported$handle.invokeExact(version);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t quiche_negotiate_version(const uint8_t *scid, size_t
     * scid_len, const uint8_t *dcid, size_t dcid_len, uint8_t *out, size_t
     * out_len)}
     */
    static final MethodHandle quiche_negotiate_version$handle =
            createHandle("quiche_negotiate_version",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code ssize_t quiche_negotiate_version(const uint8_t *scid, size_t
     * scid_len, const uint8_t *dcid, size_t dcid_len, uint8_t *out, size_t
     * out_len)}
     */
    static long quiche_negotiate_version(MemorySegment scid, long scidLen,
            MemorySegment dcid, long dcidLen, MemorySegment out, long outLen) {
        try {
            return (long) quiche_negotiate_version$handle.invokeExact(scid, scidLen,
                    dcid, dcidLen, out, outLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Connection lifecycle

    /**
     * {@code quiche_conn *quiche_accept(const uint8_t *scid, size_t scid_len,
     * const uint8_t *odcid, size_t odcid_len, const struct sockaddr *local,
     * socklen_t local_len, const struct sockaddr *peer, socklen_t peer_len,
     * quiche_config *config)}
     */
    static final MethodHandle quiche_accept$handle =
            createHandle("quiche_accept",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

    /**
     * {@code quiche_conn *quiche_accept(const uint8_t *scid, size_t scid_len,
     * const uint8_t *odcid, size_t odcid_len, const struct sockaddr *local,
     * socklen_t local_len, const struct sockaddr *peer, socklen_t peer_len,
     * quiche_config *config)}
     */
    static MemorySegment quiche_accept(MemorySegment scid, long scidLen,
            MemorySegment odcid, long odcidLen, MemorySegment local, int localLen,
            MemorySegment peer, int peerLen, MemorySegment config) {
        try {
            return (MemorySegment) quiche_accept$handle.invokeExact(scid, scidLen,
                    odcid, odcidLen, local, localLen, peer, peerLen, config);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_conn_free(quiche_conn *conn)}
     */
    static final MethodHandle quiche_conn_free$handle =
            createHandle("quiche_conn_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    /**
     * {@code void quiche_conn_free(quiche_conn *conn)}
     */
    static void quiche_conn_free(MemorySegment conn) {
        try {
            quiche_conn_free$handle.invokeExact(conn);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t quiche_conn_recv(quiche_conn *conn, uint8_t *buf, size_t
     * buf_len, const quiche_recv_info *info)}
     */
    static final MethodHandle quiche_conn_recv$handle =
            createHandle("quiche_conn_recv",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

    /**
     * {@code ssize_t quiche_conn_recv(quiche_conn *conn, uint8_t *buf, size_t
     * buf_len, const quiche_recv_info *info)}
     */
    static long quiche_conn_recv(MemorySegment conn, MemorySegment buf, long bufLen,
            MemorySegment info) {
        try {
            return (long) quiche_conn_recv$handle.invokeExact(conn, buf, bufLen, info);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t
     * out_len, quiche_send_info *out_info)}
     */
    static final MethodHandle quiche_conn_send$handle =
            createHandle("quiche_conn_send",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

    /**
     * {@code ssize_t quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t
     * out_len, quiche_send_info *out_info)}
     */
    static long quiche_conn_send(MemorySegment conn, MemorySegment out, long outLen,
            MemorySegment outInfo) {
        try {
            return (long) quiche_conn_send$handle.invokeExact(conn, out, outLen, outInfo);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code size_t quiche_conn_max_send_udp_payload_size(const quiche_conn
     * *conn)}
     */
    static final MethodHandle quiche_conn_max_send_udp_payload_size$handle =
            createHandle("quiche_conn_max_send_udp_payload_size",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

    /**
     * {@code size_t quiche_conn_max_send_udp_payload_size(const quiche_conn
     * *conn)}
     */
    static long quiche_conn_max_send_udp_payload_size(MemorySegment conn) {
        try {
            return (long) quiche_conn_max_send_udp_payload_size$handle.invokeExact(conn);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Connection state

    /**
     * {@code bool quiche_conn_is_established(const quiche_conn *conn)}
     */
    static final MethodHandle quiche_conn_is_established$handle =
            createHandle("quiche_conn_is_established",
                    FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));

    /**
     * {@code bool quiche_conn_is_established(const quiche_conn *conn)}
     */
    static boolean quiche_conn_is_established(MemorySegment conn) {
        try {
            return (boolean) quiche_conn_is_established$handle.invokeExact(conn);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code bool quiche_conn_is_closed(const quiche_conn *conn)}
     */
    static final MethodHandle quiche_conn_is_closed$handle =
            createHandle("quiche_conn_is_closed",
                    FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));

    /**
     * {@code bool quiche_conn_is_closed(const quiche_conn *conn)}
     */
    static boolean quiche_conn_is_closed(MemorySegment conn) {
        try {
            return (boolean) quiche_conn_is_closed$handle.invokeExact(conn);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code bool quiche_conn_is_draining(const quiche_conn *conn)}
     */
    static final MethodHandle quiche_conn_is_draining$handle =
            createHandle("quiche_conn_is_draining",
                    FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));

    /**
     * {@code bool quiche_conn_is_draining(const quiche_conn *conn)}
     */
    static boolean quiche_conn_is_draining(MemorySegment conn) {
        try {
            return (boolean) quiche_conn_is_draining$handle.invokeExact(conn);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code uint64_t quiche_conn_timeout_as_millis(const quiche_conn *conn)}
     * <p>
     * quiche returns {@code u64::MAX} - which arrives as {@code -1}
     * through the signed JAVA_LONG read - when the connection has no
     * timer armed. The negative value is that sentinel, not an error: a
     * timer-less connection has no deadline to honour, so it must not be
     * folded into a wait minimum.
     */
    static final MethodHandle quiche_conn_timeout_as_millis$handle =
            createHandle("quiche_conn_timeout_as_millis",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

    /**
     * {@code uint64_t quiche_conn_timeout_as_millis(const quiche_conn *conn)}
     * <p>
     * A negative result is the {@code u64::MAX} sentinel for a disarmed
     * timer, not an error.
     */
    static long quiche_conn_timeout_as_millis(MemorySegment conn) {
        try {
            return (long) quiche_conn_timeout_as_millis$handle.invokeExact(conn);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_conn_on_timeout(quiche_conn *conn)}
     */
    static final MethodHandle quiche_conn_on_timeout$handle =
            createHandle("quiche_conn_on_timeout", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    /**
     * {@code void quiche_conn_on_timeout(quiche_conn *conn)}
     */
    static void quiche_conn_on_timeout(MemorySegment conn) {
        try {
            quiche_conn_on_timeout$handle.invokeExact(conn);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int quiche_conn_close(quiche_conn *conn, bool app, uint64_t err,
     * const uint8_t *reason, size_t reason_len)}
     */
    static final MethodHandle quiche_conn_close$handle =
            createHandle("quiche_conn_close",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_BOOLEAN, ValueLayout.JAVA_LONG,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code int quiche_conn_close(quiche_conn *conn, bool app, uint64_t err,
     * const uint8_t *reason, size_t reason_len)}
     */
    static int quiche_conn_close(MemorySegment conn, boolean app, long err,
            MemorySegment reason, long reasonLen) {
        try {
            return (int) quiche_conn_close$handle.invokeExact(conn, app, err, reason,
                    reasonLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code bool quiche_conn_peer_error(const quiche_conn *conn, bool
     * *is_app, uint64_t *error_code, const uint8_t **reason, size_t
     * *reason_len)}
     */
    static final MethodHandle quiche_conn_peer_error$handle =
            createHandle("quiche_conn_peer_error",
                    FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code bool quiche_conn_peer_error(const quiche_conn *conn, bool
     * *is_app, uint64_t *error_code, const uint8_t **reason, size_t
     * *reason_len)}
     */
    static boolean quiche_conn_peer_error(MemorySegment conn, MemorySegment isApp,
            MemorySegment errorCode, MemorySegment reason, MemorySegment reasonLen) {
        try {
            return (boolean) quiche_conn_peer_error$handle.invokeExact(conn, isApp,
                    errorCode, reason, reasonLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code bool quiche_conn_local_error(const quiche_conn *conn, bool
     * *is_app, uint64_t *error_code, const uint8_t **reason, size_t
     * *reason_len)}
     */
    static final MethodHandle quiche_conn_local_error$handle =
            createHandle("quiche_conn_local_error",
                    FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code bool quiche_conn_local_error(const quiche_conn *conn, bool
     * *is_app, uint64_t *error_code, const uint8_t **reason, size_t
     * *reason_len)}
     */
    static boolean quiche_conn_local_error(MemorySegment conn, MemorySegment isApp,
            MemorySegment errorCode, MemorySegment reason, MemorySegment reasonLen) {
        try {
            return (boolean) quiche_conn_local_error$handle.invokeExact(conn, isApp,
                    errorCode, reason, reasonLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_conn_application_proto(const quiche_conn *conn, const
     * uint8_t **out, size_t *out_len)}
     */
    static final MethodHandle quiche_conn_application_proto$handle =
            createHandle("quiche_conn_application_proto",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code void quiche_conn_application_proto(const quiche_conn *conn, const
     * uint8_t **out, size_t *out_len)}
     */
    static void quiche_conn_application_proto(MemorySegment conn, MemorySegment out,
            MemorySegment outLen) {
        try {
            quiche_conn_application_proto$handle.invokeExact(conn, out, outLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code void quiche_conn_server_name(const quiche_conn *conn, const
     * uint8_t **out, size_t *out_len)}
     */
    static final MethodHandle quiche_conn_server_name$handle =
            createHandle("quiche_conn_server_name",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code void quiche_conn_server_name(const quiche_conn *conn, const
     * uint8_t **out, size_t *out_len)}
     */
    static void quiche_conn_server_name(MemorySegment conn, MemorySegment out,
            MemorySegment outLen) {
        try {
            quiche_conn_server_name$handle.invokeExact(conn, out, outLen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int quiche_conn_new_scid(quiche_conn *conn, const uint8_t *scid,
     * size_t scid_len, const uint8_t *reset_token, bool retire_if_needed,
     * uint64_t *scid_seq)}
     */
    static final MethodHandle quiche_conn_new_scid$handle =
            createHandle("quiche_conn_new_scid",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
                            ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));

    /**
     * {@code int quiche_conn_new_scid(quiche_conn *conn, const uint8_t *scid,
     * size_t scid_len, const uint8_t *reset_token, bool retire_if_needed,
     * uint64_t *scid_seq)}
     */
    static int quiche_conn_new_scid(MemorySegment conn, MemorySegment scid,
            long scidLen, MemorySegment resetToken, boolean retireIfNeeded,
            MemorySegment scidSeqOut) {
        try {
            return (int) quiche_conn_new_scid$handle.invokeExact(conn, scid, scidLen,
                    resetToken, retireIfNeeded, scidSeqOut);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Stream I/O

    /**
     * {@code ssize_t quiche_conn_stream_recv(quiche_conn *conn, uint64_t
     * stream_id, uint8_t *out, size_t buf_len, bool *fin, uint64_t
     * *out_error_code)}
     */
    static final MethodHandle quiche_conn_stream_recv$handle =
            createHandle("quiche_conn_stream_recv",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code ssize_t quiche_conn_stream_recv(quiche_conn *conn, uint64_t
     * stream_id, uint8_t *out, size_t buf_len, bool *fin, uint64_t
     * *out_error_code)}
     */
    static long quiche_conn_stream_recv(MemorySegment conn, long streamId,
            MemorySegment out, long bufLen, MemorySegment fin, MemorySegment errorCode) {
        try {
            return (long) quiche_conn_stream_recv$handle.invokeExact(conn, streamId,
                    out, bufLen, fin, errorCode);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t quiche_conn_stream_send(quiche_conn *conn, uint64_t
     * stream_id, const uint8_t *buf, size_t buf_len, bool fin, uint64_t
     * *out_error_code)}
     */
    static final MethodHandle quiche_conn_stream_send$handle =
            createHandle("quiche_conn_stream_send",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
                            ValueLayout.JAVA_LONG, ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS));

    /**
     * {@code ssize_t quiche_conn_stream_send(quiche_conn *conn, uint64_t
     * stream_id, const uint8_t *buf, size_t buf_len, bool fin, uint64_t
     * *out_error_code)}
     */
    static long quiche_conn_stream_send(MemorySegment conn, long streamId,
            MemorySegment buf, long bufLen, boolean fin, MemorySegment errorCode) {
        try {
            return (long) quiche_conn_stream_send$handle.invokeExact(conn, streamId,
                    buf, bufLen, fin, errorCode);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int quiche_conn_stream_shutdown(quiche_conn *conn, uint64_t
     * stream_id, enum quiche_shutdown direction, uint64_t err)}
     */
    static final MethodHandle quiche_conn_stream_shutdown$handle =
            createHandle("quiche_conn_stream_shutdown",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_LONG));

    /**
     * {@code int quiche_conn_stream_shutdown(quiche_conn *conn, uint64_t
     * stream_id, enum quiche_shutdown direction, uint64_t err)}
     */
    static int quiche_conn_stream_shutdown(MemorySegment conn, long streamId,
            int direction, long err) {
        try {
            return (int) quiche_conn_stream_shutdown$handle.invokeExact(conn, streamId,
                    direction, err);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t quiche_conn_stream_capacity(quiche_conn *conn, uint64_t
     * stream_id)}
     */
    static final MethodHandle quiche_conn_stream_capacity$handle =
            createHandle("quiche_conn_stream_capacity",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code ssize_t quiche_conn_stream_capacity(quiche_conn *conn, uint64_t
     * stream_id)}
     */
    static long quiche_conn_stream_capacity(MemorySegment conn, long streamId) {
        try {
            return (long) quiche_conn_stream_capacity$handle.invokeExact(conn, streamId);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code bool quiche_conn_stream_readable(const quiche_conn *conn,
     * uint64_t stream_id)}
     */
    static final MethodHandle quiche_conn_stream_readable$handle =
            createHandle("quiche_conn_stream_readable",
                    FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code bool quiche_conn_stream_readable(const quiche_conn *conn,
     * uint64_t stream_id)}
     */
    static boolean quiche_conn_stream_readable(MemorySegment conn, long streamId) {
        try {
            return (boolean) quiche_conn_stream_readable$handle.invokeExact(conn, streamId);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int64_t quiche_conn_stream_readable_next(quiche_conn *conn)}
     */
    static final MethodHandle quiche_conn_stream_readable_next$handle =
            createHandle("quiche_conn_stream_readable_next",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

    /**
     * {@code int64_t quiche_conn_stream_readable_next(quiche_conn *conn)}
     */
    static long quiche_conn_stream_readable_next(MemorySegment conn) {
        try {
            return (long) quiche_conn_stream_readable_next$handle.invokeExact(conn);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int64_t quiche_conn_stream_writable_next(quiche_conn *conn)}
     */
    static final MethodHandle quiche_conn_stream_writable_next$handle =
            createHandle("quiche_conn_stream_writable_next",
                    FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

    /**
     * {@code int64_t quiche_conn_stream_writable_next(quiche_conn *conn)}
     */
    static long quiche_conn_stream_writable_next(MemorySegment conn) {
        try {
            return (long) quiche_conn_stream_writable_next$handle.invokeExact(conn);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code bool quiche_conn_stream_finished(const quiche_conn *conn,
     * uint64_t stream_id)}
     */
    static final MethodHandle quiche_conn_stream_finished$handle =
            createHandle("quiche_conn_stream_finished",
                    FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code bool quiche_conn_stream_finished(const quiche_conn *conn,
     * uint64_t stream_id)}
     */
    static boolean quiche_conn_stream_finished(MemorySegment conn, long streamId) {
        try {
            return (boolean) quiche_conn_stream_finished$handle.invokeExact(conn, streamId);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Struct layouts

    /**
     * {@code quiche_recv_info}: {@code { sockaddr* from; socklen_t from_len;
     * sockaddr* to; socklen_t to_len; }}. Linux LP64: 32 bytes with 8-byte
     * alignment padding after each socklen_t.
     */
    static final MemoryLayout RECV_INFO_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.ADDRESS.withName("from"),
            ValueLayout.JAVA_INT.withName("from_len"),
            MemoryLayout.paddingLayout(4),
            ValueLayout.ADDRESS.withName("to"),
            ValueLayout.JAVA_INT.withName("to_len"),
            MemoryLayout.paddingLayout(4)).withName("quiche_recv_info");

    static final long RECV_INFO_SIZE = RECV_INFO_LAYOUT.byteSize();

    static final long RECV_INFO_FROM = RECV_INFO_LAYOUT.byteOffset(PathElement.groupElement("from"));
    static final long RECV_INFO_FROM_LEN = RECV_INFO_LAYOUT.byteOffset(PathElement.groupElement("from_len"));
    static final long RECV_INFO_TO = RECV_INFO_LAYOUT.byteOffset(PathElement.groupElement("to"));
    static final long RECV_INFO_TO_LEN = RECV_INFO_LAYOUT.byteOffset(PathElement.groupElement("to_len"));

    /**
     * {@code quiche_send_info}: {@code { struct sockaddr_storage from(128);
     * socklen_t from_len; struct sockaddr_storage to(128); socklen_t to_len;
     * struct timespec at; }}. Linux LP64: 288 bytes (from at 0, from_len at
     * 128, to at 136, to_len at 264, at at 272).
     */
    static final MemoryLayout SEND_INFO_LAYOUT = MemoryLayout.structLayout(
            MemoryLayout.sequenceLayout(128, ValueLayout.JAVA_BYTE).withName("from"),
            ValueLayout.JAVA_INT.withName("from_len"),
            MemoryLayout.paddingLayout(4),
            MemoryLayout.sequenceLayout(128, ValueLayout.JAVA_BYTE).withName("to"),
            ValueLayout.JAVA_INT.withName("to_len"),
            MemoryLayout.paddingLayout(4),
            MemoryLayout.structLayout(ValueLayout.JAVA_LONG.withName("tv_sec"),
                    ValueLayout.JAVA_LONG.withName("tv_nsec")).withName("at")).withName("quiche_send_info");

    static final long SEND_INFO_SIZE = SEND_INFO_LAYOUT.byteSize();

    static final long SEND_INFO_FROM = SEND_INFO_LAYOUT.byteOffset(PathElement.groupElement("from"));
    static final long SEND_INFO_FROM_LEN = SEND_INFO_LAYOUT.byteOffset(PathElement.groupElement("from_len"));
    static final long SEND_INFO_TO = SEND_INFO_LAYOUT.byteOffset(PathElement.groupElement("to"));
    static final long SEND_INFO_TO_LEN = SEND_INFO_LAYOUT.byteOffset(PathElement.groupElement("to_len"));

    /** Size of {@code struct sockaddr_storage} (Linux). */
    static final int SOCKADDR_STORAGE_SIZE = 128;

    /**
     * {@code struct msghdr} (Linux LP64, 56 bytes).
     */
    static final MemoryLayout MSGHDR_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.ADDRESS.withName("msg_name"),
            ValueLayout.JAVA_INT.withName("msg_namelen"),
            MemoryLayout.paddingLayout(4),
            ValueLayout.ADDRESS.withName("msg_iov"),
            ValueLayout.JAVA_LONG.withName("msg_iovlen"),
            ValueLayout.ADDRESS.withName("msg_control"),
            ValueLayout.JAVA_LONG.withName("msg_controllen"),
            ValueLayout.JAVA_INT.withName("msg_flags"),
            MemoryLayout.paddingLayout(4)).withName("msghdr");

    static final long MSGHDR_NAME = MSGHDR_LAYOUT.byteOffset(PathElement.groupElement("msg_name"));
    static final long MSGHDR_NAMELEN = MSGHDR_LAYOUT.byteOffset(PathElement.groupElement("msg_namelen"));
    static final long MSGHDR_IOV = MSGHDR_LAYOUT.byteOffset(PathElement.groupElement("msg_iov"));
    static final long MSGHDR_IOVLEN = MSGHDR_LAYOUT.byteOffset(PathElement.groupElement("msg_iovlen"));
    static final long MSGHDR_CONTROL = MSGHDR_LAYOUT.byteOffset(PathElement.groupElement("msg_control"));
    static final long MSGHDR_CONTROLLEN = MSGHDR_LAYOUT.byteOffset(PathElement.groupElement("msg_controllen"));
    static final long MSGHDR_FLAGS = MSGHDR_LAYOUT.byteOffset(PathElement.groupElement("msg_flags"));

    /**
     * {@code struct mmsghdr} (Linux LP64): a {@code struct msghdr} followed
     * by an {@code unsigned int msg_len}, into which {@code recvmmsg} stores
     * the received byte count of the slot's message, and padding to a
     * 64-byte boundary. A slot's message is the same content a single
     * {@code recvmsg} would deliver, GRO coalescing included, so the
     * {@code MSGHDR_*} offsets apply unchanged to a slot's leading bytes.
     */
    static final long MMSGHDR_SIZE = 64;
    static final long MMSGHDR_MSGLEN = 56;

    /**
     * {@code struct iovec} (Linux LP64, 16 bytes).
     */
    static final MemoryLayout IOVEC_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.ADDRESS.withName("iov_base"),
            ValueLayout.JAVA_LONG.withName("iov_len")).withName("iovec");

    static final long IOVEC_BASE = IOVEC_LAYOUT.byteOffset(PathElement.groupElement("iov_base"));
    static final long IOVEC_LEN = IOVEC_LAYOUT.byteOffset(PathElement.groupElement("iov_len"));

    /**
     * {@code struct cmsghdr} (Linux LP64: 8-byte len, then level and type,
     * payload at offset 16).
     */
    static final long CMSG_HEADER_SIZE = 16;
    static final long CMSG_DATA_OFFSET = 16;

    // Scratch block layout used by the datagram helpers below.
    static final long SCRATCH_MSGHDR = 0;
    static final long SCRATCH_IOV = 56;
    // Control-buffer capacity: sized for the control messages one receive
    // can carry with the socket options this endpoint enables
    // (IP_RECVPKTINFO/IPV6_RECVPKTINFO - one pktinfo cmsg per datagram,
    // even for v4 traffic on the dual-stack socket - plus the UDP_GRO
    // segment-size cmsg that rides the coalesced reads once that option is
    // enabled). The send side needs the same room for its PKTINFO +
    // UDP_SEGMENT cmsg pair. Enabling any further receive-side socket
    // option (DSTOPTS, ...) can put another control message into the same
    // receive, which this buffer would silently truncate: enlarge it (and
    // SCRATCH_SIZE) together with such an option.
    static final long CMSG_SPACE = 96;
    static final long SCRATCH_CMSG = 72;
    static final long SCRATCH_SIZE = 168;

    /**
     * Batch scratch layout for {@link #sendSegmentedDatagram}: msghdr, then
     * the iovec array (GSO_MAX_BATCH entries), then the control buffer.
     */
    static final long BATCH_IOVS = 56;
    static final long BATCH_CMSG = 184;
    static final long BATCH_SCRATCH_SIZE = BATCH_CMSG + CMSG_SPACE;

    /**
     * Largest number of packets the send loop batches into one segmented
     * {@code sendmsg} (one iovec per packet).
     */
    static final int GSO_MAX_BATCH = 8;

    /**
     * Returns the byte size a control message with the given payload
     * occupies in a control buffer (CMSG_SPACE, 8-byte aligned).
     *
     * @param dataLen The payload size
     *
     * @return The total space required, including alignment padding
     */
    static long cmsgSpace(long dataLen) {
        return (CMSG_HEADER_SIZE + dataLen + 7) & ~7L;
    }

    // -------------------------------------------------- Socket constants

    static final int AF_INET = 2;
    static final int AF_INET6 = 10;
    static final int SOCK_DGRAM = 2;
    static final int SOCK_NONBLOCK = 0x800;

    static final int MSG_DONTWAIT = 0x40;

    static final int SOL_SOCKET = 1;
    static final int SO_REUSEADDR = 2;
    // Linux values (BSD uses 0x1012/0x1011): SO_RCVBUF=8, SO_SNDBUF=7
    static final int SO_RCVBUF = 8;
    static final int SO_SNDBUF = 7;

    static final int IPPROTO_IP = 0;
    static final int IP_PKTINFO = 8;

    static final int IPPROTO_IPV6 = 41;
    static final int IPV6_RECVPKTINFO = 49;
    static final int IPV6_PKTINFO = 50;
    // Linux value. BSD/Darwin use 33, FreeBSD 27.
    static final int IPV6_V6ONLY = 26;

    // UDP socket options (SOL_UDP, <linux/udp.h>): UDP_SEGMENT (since 4.18)
    // turns one sendmsg into a GSO batch the kernel splits on the wire into
    // equal-size datagrams (last may be short); UDP_GRO (since 5.0) opts the
    // receive socket into taking GRO-coalesced runs as one read with a
    // segment-size cmsg telling the reader how to split them back up.
    static final int SOL_UDP = 17;
    static final int UDP_SEGMENT = 103;
    static final int UDP_GRO = 104;

    static final int EPERM = 1;
    static final int EINTR = 4;
    static final int EAGAIN = 11;
    static final int EAFNOSUPPORT = 97;
    static final int EADDRNOTAVAIL = 99;

    // eventfd flags: EFD_NONBLOCK == O_NONBLOCK == SOCK_NONBLOCK on Linux
    // (0x800 = 04000; eventfd(2) defines EFD_NONBLOCK as O_NONBLOCK),
    // EFD_CLOEXEC == O_CLOEXEC. The literals pin the ABI values, not the
    // header macros.
    static final int EFD_NONBLOCK = 0x800;
    static final int EFD_CLOEXEC = 02000000;

    // -------------------------------------------------- libc helpers

    /**
     * {@code int socket(int domain, int type, int protocol)}
     */
    static final MethodHandle socket$handle = createLibcHandle("socket",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

    /**
     * {@code int socket(int domain, int type, int protocol)}
     */
    static int socket(int domain, int type, int protocol) {
        try {
            return (int) socket$handle.invokeExact(domain, type, protocol);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int bind(int sockfd, const struct sockaddr *addr, socklen_t len)}
     */
    static final MethodHandle bind$handle = createLibcHandle("bind",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

    /**
     * {@code int bind(int sockfd, const struct sockaddr *addr, socklen_t len)}
     */
    static int bind(int sockfd, MemorySegment addr, int len) {
        try {
            return (int) bind$handle.invokeExact(sockfd, addr, len);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int getsockname(int sockfd, struct sockaddr *addr, socklen_t
     * *addrlen)}
     */
    static final MethodHandle getsockname$handle = createLibcHandle("getsockname",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    /**
     * {@code int getsockname(int sockfd, struct sockaddr *addr, socklen_t
     * *addrlen)}
     */
    static int getsockname(int sockfd, MemorySegment addr, MemorySegment addrlen) {
        try {
            return (int) getsockname$handle.invokeExact(sockfd, addr, addrlen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int setsockopt(int sockfd, int level, int optname, const void
     * *optval, socklen_t optlen)}
     */
    static final MethodHandle setsockopt$handle = createLibcHandle("setsockopt",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_INT));

    /**
     * {@code int setsockopt(int sockfd, int level, int optname, const void
     * *optval, socklen_t optlen)}
     */
    static int setsockopt(int sockfd, int level, int optname, MemorySegment optval,
            int optlen) {
        try {
            return (int) setsockopt$handle.invokeExact(sockfd, level, optname, optval, optlen);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int close(int fd)}
     */
    static final MethodHandle close$handle = createLibcHandle("close",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

    /**
     * {@code int close(int fd)}
     */
    static int close(int fd) {
        try {
            return (int) close$handle.invokeExact(fd);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int *__errno_location(void)}
     */
    static final MethodHandle errno_location$handle =
            createLibcHandle("__errno_location", FunctionDescriptor.of(ValueLayout.ADDRESS));

    /**
     * {@code int *__errno_location(void)}
     */
    static MemorySegment errno_location() {
        try {
            return (MemorySegment) errno_location$handle.invokeExact();
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * Reads the current thread's {@code errno}.
     *
     * @return The errno value
     */
    static int errno() {
        return errno_location().reinterpret(4).get(ValueLayout.JAVA_INT, 0);
    }

    /**
     * {@code char *strerror(int errnum)}
     */
    static final MethodHandle strerror$handle = createLibcHandle("strerror",
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

    /**
     * {@code char *strerror(int errnum)}
     */
    static String strerror(int errnum) {
        try {
            MemorySegment s = (MemorySegment) strerror$handle.invokeExact(errnum);
            return s.equals(MemorySegment.NULL) ? null : s.reinterpret(256).getString(0);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int poll(struct pollfd *fds, nfds_t nfds, int timeout)}
     */
    static final MethodHandle poll$handle = createLibcHandle("poll",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));

    /**
     * {@code int poll(struct pollfd *fds, nfds_t nfds, int timeout)}
     */
    static int poll(MemorySegment fds, long nfds, int timeout) {
        try {
            return (int) poll$handle.invokeExact(fds, nfds, timeout);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int eventfd(unsigned int initval, int flags)}
     */
    static final MethodHandle eventfd$handle = createLibcHandle("eventfd",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

    /**
     * {@code int eventfd(unsigned int initval, int flags)}
     */
    static int eventfd(int initval, int flags) {
        try {
            return (int) eventfd$handle.invokeExact(initval, flags);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t read(int fd, void *buf, size_t count)}
     */
    static final MethodHandle read$handle = createLibcHandle("read",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code ssize_t read(int fd, void *buf, size_t count)}
     */
    static long read(int fd, MemorySegment buf, long count) {
        try {
            return (long) read$handle.invokeExact(fd, buf, count);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t write(int fd, const void *buf, size_t count)}
     */
    static final MethodHandle write$handle = createLibcHandle("write",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));

    /**
     * {@code ssize_t write(int fd, const void *buf, size_t count)}
     */
    static long write(int fd, MemorySegment buf, long count) {
        try {
            return (long) write$handle.invokeExact(fd, buf, count);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)}
     */
    static final MethodHandle recvmsg$handle = createLibcHandle("recvmsg",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

    /**
     * {@code ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)}
     */
    static long recvmsg(int sockfd, MemorySegment msg, int flags) {
        try {
            return (long) recvmsg$handle.invokeExact(sockfd, msg, flags);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)}
     */
    static final MethodHandle sendmsg$handle = createLibcHandle("sendmsg",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

    /**
     * {@code ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)}
     */
    static long sendmsg(int sockfd, MemorySegment msg, int flags) {
        try {
            return (long) sendmsg$handle.invokeExact(sockfd, msg, flags);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    /**
     * {@code int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int
     * vlen, int flags, struct timespec *timeout)}
     */
    static final MethodHandle recvmmsg$handle = createLibcHandle("recvmmsg",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS));

    /**
     * True when {@code recvmmsg} linked (it is missing from some libcs);
     * the poll loop then receives with plain {@code recvmsg} instead.
     */
    static final boolean RECV_MMSG = recvmmsg$handle != null;

    /**
     * Receives up to {@code vlen} messages into consecutive {@code mmsghdr}
     * slots in one syscall. The timeout is {@code NULL}: on a
     * non-blocking socket the call takes what is queued (at least one
     * message, or {@code EAGAIN} when nothing is).
     *
     * @return Message count (1 to {@code vlen}), or -1 with errno set
     */
    static int recvmmsg(int sockfd, MemorySegment msgvec, int vlen, int flags) {
        try {
            return (int) recvmmsg$handle.invokeExact(sockfd, msgvec, vlen, flags,
                    MemorySegment.NULL);
        } catch (Throwable t) {
            throw new AssertionError("should not reach here", t);
        }
    }

    // -------------------------------------------------- Datagram helpers
    //
    // The scratch segment passed to the helpers must hold SCRATCH_SIZE
    // bytes (msghdr + iovec + control buffer). The from/to storage segments
    // must hold SOCKADDR_STORAGE_SIZE bytes each.

    /**
     * Receives one datagram, capturing the peer address and (via the
     * {@code IP_PKTINFO} / {@code IPV6_RECVPKTINFO} control message) the
     * local address it arrived on.
     *
     * @param fd        The UDP socket
     * @param buf       The receive buffer
     * @param bufLen    The receive buffer size
     * @param scratch   Confined scratch block (SCRATCH_SIZE bytes)
     * @param from      Storage for the peer sockaddr (128 bytes)
     * @param to        Storage for the local sockaddr written from the PKTINFO
     *                  cmsg (128 bytes; at most 28 written)
     * @param toLenOut  An int-sized segment receiving the written local
     *                  sockaddr length (0 when no cmsg was present)
     * @param groSegOut  {@code groSegOut[0]} receives the {@code UDP_GRO}
     *                  segment size of a coalesced read (0 when the read
     *                  carries no GRO cmsg, which - on a socket with the
     *                  option enabled - means one ordinary datagram)
     *
     * @return The number of bytes received, or {@code -1} with errno set
     *         (the caller checks EAGAIN/EINTR)
     */
    static long recvDatagram(int fd, MemorySegment buf, int bufLen,
            MemorySegment scratch, MemorySegment from, MemorySegment to,
            MemorySegment toLenOut, int[] groSegOut) {
        MemorySegment msg = scratch.asSlice(SCRATCH_MSGHDR, MSGHDR_LAYOUT.byteSize());
        MemorySegment iov = scratch.asSlice(SCRATCH_IOV, IOVEC_LAYOUT.byteSize());
        MemorySegment cbuf = scratch.asSlice(SCRATCH_CMSG, CMSG_SPACE);

        groSegOut[0] = 0;

        iov.set(ValueLayout.ADDRESS, IOVEC_BASE, buf);
        iov.set(ValueLayout.JAVA_LONG, IOVEC_LEN, bufLen);

        toLenOut.set(ValueLayout.JAVA_INT, 0, 0);

        msg.set(ValueLayout.ADDRESS, MSGHDR_NAME, from);
        msg.set(ValueLayout.JAVA_INT, MSGHDR_NAMELEN, SOCKADDR_STORAGE_SIZE);
        msg.set(ValueLayout.ADDRESS, MSGHDR_IOV, iov);
        msg.set(ValueLayout.JAVA_LONG, MSGHDR_IOVLEN, 1);
        msg.set(ValueLayout.ADDRESS, MSGHDR_CONTROL, cbuf);
        msg.set(ValueLayout.JAVA_LONG, MSGHDR_CONTROLLEN, CMSG_SPACE);
        msg.set(ValueLayout.JAVA_INT, MSGHDR_FLAGS, 0);

        long n = recvmsg(fd, msg, MSG_DONTWAIT);
        if (n < 0) {
            return n;
        }

        long controllen = Math.min(msg.get(ValueLayout.JAVA_LONG, MSGHDR_CONTROLLEN), CMSG_SPACE);
        parseRecvCmsgs(cbuf, controllen, to, toLenOut, groSegOut);
        return n;
    }

    /**
     * Parses the control buffer of one received datagram, taking it apart
     * exactly as {@link #recvDatagram} does: the {@code IP_PKTINFO} /
     * {@code IPV6_PKTINFO} entry is converted into a local sockaddr written
     * to {@code to} (its length reported through {@code toLenOut}), and a
     * {@code UDP_GRO} entry's segment size is stored in
     * {@code groSegOut[0]}. Shared with the {@code recvmmsg} batch path,
     * which reads one control buffer per slot.
     *
     * @param cbuf        The control buffer
     * @param controllen  Bytes of control data present (already clamped to
     *                    the buffer size)
     * @param to        Storage for the local sockaddr (128 bytes)
     * @param toLenOut  An int-sized segment receiving the written length
     *                  (0 when no packet-info cmsg was present)
     * @param groSegOut  {@code groSegOut[0]} receives the {@code UDP_GRO}
     *                  segment size, or 0; zeroed by this call
     */
    static void parseRecvCmsgs(MemorySegment cbuf, long controllen,
            MemorySegment to, MemorySegment toLenOut, int[] groSegOut) {
        groSegOut[0] = 0;
        toLenOut.set(ValueLayout.JAVA_INT, 0, 0);
        long off = 0;
        while (off + CMSG_HEADER_SIZE <= controllen) {
            long cmsgLen = cbuf.get(ValueLayout.JAVA_LONG, off);
            if (cmsgLen < CMSG_HEADER_SIZE || off + cmsgLen > controllen) {
                break;
            }
            int level = cbuf.get(ValueLayout.JAVA_INT, off + 8);
            int type = cbuf.get(ValueLayout.JAVA_INT, off + 12);
            if (level == IPPROTO_IP && type == IP_PKTINFO
                    && cmsgLen >= CMSG_HEADER_SIZE + 12) {
                // in_pktinfo: { uint ifindex; in_addr spec_dst; in_addr addr; }
                // Write a sockaddr_in for the local address (spec_dst).
                to.set(ValueLayout.JAVA_SHORT, 0, (short) AF_INET);
                to.set(ValueLayout.JAVA_SHORT, 2, (short) 0);
                MemorySegment.copy(cbuf, off + CMSG_DATA_OFFSET + 4, to, 4, 4);
                toLenOut.set(ValueLayout.JAVA_INT, 0, 16);
            } else if (level == IPPROTO_IPV6 && type == IPV6_PKTINFO
                    && cmsgLen >= CMSG_HEADER_SIZE + 20) {
                // in6_pktinfo: { in6_addr addr; uint ifindex; }
                to.set(ValueLayout.JAVA_SHORT, 0, (short) AF_INET6);
                to.set(ValueLayout.JAVA_SHORT, 2, (short) 0);
                MemorySegment.copy(cbuf, off + CMSG_DATA_OFFSET, to, 8, 16);
                // Preserve the arrival interface as sin6_scope_id: quiche
                // round-trips the sockaddr into send_info, and the send-side
                // PKTINFO cmsg recovers the ifindex from here (link-local
                // sources cannot be pinned without it).
                to.set(ValueLayout.JAVA_INT, 24,
                        cbuf.get(ValueLayout.JAVA_INT, off + CMSG_DATA_OFFSET + 16));
                toLenOut.set(ValueLayout.JAVA_INT, 0, 28);
            } else if (level == SOL_UDP && type == UDP_GRO
                    && cmsgLen >= CMSG_HEADER_SIZE + 2) {
                // Coalesced GRO read: every segment but the last has this
                // exact size; the read cannot be split without it.
                groSegOut[0] = cbuf.get(ValueLayout.JAVA_SHORT,
                        off + CMSG_DATA_OFFSET) & 0xFFFF;
            }
            off += (cmsgLen + 7) & ~7L;
        }
    }

    /**
     * Sends one datagram to {@code to}, optionally pinning the source
     * address via an {@code IP_PKTINFO} / {@code IPV6_PKTINFO} control
     * message when {@code from} is non-null.
     *
     * @param fd      The UDP socket
     * @param buf     The datagram bytes
     * @param bufLen  The number of bytes to send
     * @param to      Destination sockaddr
     * @param toLen   Destination sockaddr length
     * @param from    Source sockaddr, or {@code null} / NULL to let the
     *                kernel choose
     * @param scratch Confined scratch block (SCRATCH_SIZE bytes)
     *
     * @return The number of bytes sent, or {@code -1} with errno set
     */
    static long sendDatagram(int fd, MemorySegment buf, int bufLen,
            MemorySegment to, int toLen, MemorySegment from, MemorySegment scratch) {
        MemorySegment msg = scratch.asSlice(SCRATCH_MSGHDR, MSGHDR_LAYOUT.byteSize());
        MemorySegment iov = scratch.asSlice(SCRATCH_IOV, IOVEC_LAYOUT.byteSize());
        MemorySegment cbuf = scratch.asSlice(SCRATCH_CMSG, CMSG_SPACE);

        iov.set(ValueLayout.ADDRESS, IOVEC_BASE, buf);
        iov.set(ValueLayout.JAVA_LONG, IOVEC_LEN, bufLen);

        msg.fill((byte) 0);
        msg.set(ValueLayout.ADDRESS, MSGHDR_NAME, to);
        msg.set(ValueLayout.JAVA_INT, MSGHDR_NAMELEN, toLen);
        msg.set(ValueLayout.ADDRESS, MSGHDR_IOV, iov);
        msg.set(ValueLayout.JAVA_LONG, MSGHDR_IOVLEN, 1);
        msg.set(ValueLayout.ADDRESS, MSGHDR_CONTROL, MemorySegment.NULL);
        msg.set(ValueLayout.JAVA_LONG, MSGHDR_CONTROLLEN, 0);
        msg.set(ValueLayout.JAVA_INT, MSGHDR_FLAGS, 0);

        if (from != null && !from.equals(MemorySegment.NULL)) {
            long ctl = writePktinfoCmsg(cbuf, 0, from);
            if (ctl > 0) {
                msg.set(ValueLayout.ADDRESS, MSGHDR_CONTROL, cbuf);
                msg.set(ValueLayout.JAVA_LONG, MSGHDR_CONTROLLEN, ctl);
            }
        }
        return sendmsg(fd, msg, 0);
    }


    /**
     * Writes an {@code IP_PKTINFO} / {@code IPV6_PKTINFO} control message for
     * {@code from} at offset {@code off} of the control buffer (family picked
     * from the sockaddr).
     *
     * @param cbuf The control buffer
     * @param off  Offset at which to write the cmsg
     * @param from Source sockaddr
     *
     * @return The space consumed (CMSG_SPACE-aligned), or {@code 0} if the
     *         sockaddr family carries no pktinfo
     */
    private static long writePktinfoCmsg(MemorySegment cbuf, long off, MemorySegment from) {
        short family = from.get(ValueLayout.JAVA_SHORT, 0);
        if (family == AF_INET) {
            // in_pktinfo: ifindex=0, spec_dst=from address, addr=0
            cbuf.set(ValueLayout.JAVA_LONG, off, CMSG_HEADER_SIZE + 12);
            cbuf.set(ValueLayout.JAVA_INT, off + 8, IPPROTO_IP);
            cbuf.set(ValueLayout.JAVA_INT, off + 12, IP_PKTINFO);
            cbuf.set(ValueLayout.JAVA_INT, off + CMSG_DATA_OFFSET, 0);
            MemorySegment.copy(from, 4, cbuf, off + CMSG_DATA_OFFSET + 4, 4);
            cbuf.set(ValueLayout.JAVA_INT, off + CMSG_DATA_OFFSET + 8, 0);
            return cmsgSpace(12);
        }
        if (family == AF_INET6) {
            // in6_pktinfo: addr=from address, ifindex=from sin6_scope_id
            // (the egress interface; required to pin a link-local source,
            // harmless 0 for global addresses).
            cbuf.set(ValueLayout.JAVA_LONG, off, CMSG_HEADER_SIZE + 20);
            cbuf.set(ValueLayout.JAVA_INT, off + 8, IPPROTO_IPV6);
            cbuf.set(ValueLayout.JAVA_INT, off + 12, IPV6_PKTINFO);
            MemorySegment.copy(from, 8, cbuf, off + CMSG_DATA_OFFSET, 16);
            cbuf.set(ValueLayout.JAVA_INT, off + CMSG_DATA_OFFSET + 16,
                    from.get(ValueLayout.JAVA_INT, 24));
            return cmsgSpace(20);
        }
        return 0;
    }


    /**
     * Sends one segmented (UDP GSO) datagram: {@code count} packets stored at
     * fixed {@code stride}-byte slots starting at {@code base}, submitted as
     * a single {@code sendmsg} carrying an iovec per packet and a
     * {@code UDP_SEGMENT} cmsg. The kernel splits it on the wire into
     * equal-size {@code segSize} datagrams (the last may be short), so all
     * but the final packet must be exactly {@code segSize} bytes and the
     * destination (and optional pinned source) is shared by the whole batch.
     * A batch is also atomic: if the socket buffer cannot take all of it the
     * send fails whole with EAGAIN and nothing went out.
     *
     * @param fd       The UDP socket
     * @param base     Staging region holding the packets at slot offsets
     * @param lens     Per-packet lengths (first {@code count} entries)
     * @param count    Packets in the batch (at most GSO_MAX_BATCH)
     * @param stride   Slot stride within the staging region
     * @param segSize  The shared segment size (packet 0's length)
     * @param to       Destination sockaddr
     * @param toLen    Destination sockaddr length
     * @param from     Source sockaddr to pin, or {@code null}
     * @param scratch  Confined batch scratch block (BATCH_SCRATCH_SIZE bytes)
     *
     * @return The number of bytes sent, or {@code -1} with errno set
     */
    static long sendSegmentedDatagram(int fd, MemorySegment base, int[] lens,
            int count, int stride, int segSize, MemorySegment to, int toLen,
            MemorySegment from, MemorySegment scratch) {
        MemorySegment msg = scratch.asSlice(0, MSGHDR_LAYOUT.byteSize());
        MemorySegment iovs = scratch.asSlice(BATCH_IOVS,
                (long) GSO_MAX_BATCH * IOVEC_LAYOUT.byteSize());
        MemorySegment cbuf = scratch.asSlice(BATCH_CMSG, CMSG_SPACE);

        for (int i = 0; i < count; i++) {
            long slot = (long) i * stride;
            iovs.set(ValueLayout.ADDRESS, i * IOVEC_LAYOUT.byteSize() + IOVEC_BASE,
                    base.asSlice(slot));
            iovs.set(ValueLayout.JAVA_LONG, i * IOVEC_LAYOUT.byteSize() + IOVEC_LEN,
                    lens[i]);
        }

        msg.fill((byte) 0);
        msg.set(ValueLayout.ADDRESS, MSGHDR_NAME, to);
        msg.set(ValueLayout.JAVA_INT, MSGHDR_NAMELEN, toLen);
        msg.set(ValueLayout.ADDRESS, MSGHDR_IOV, iovs);
        msg.set(ValueLayout.JAVA_LONG, MSGHDR_IOVLEN, count);

        long ctl = 0;
        if (from != null && !from.equals(MemorySegment.NULL)) {
            ctl += writePktinfoCmsg(cbuf, ctl, from);
        }
        // UDP_SEGMENT cmsg: the kernel wants the segment size as a __u16 in
        // the cmsg payload (the setsockopt form is the int one - different
        // shapes, same option).
        cbuf.set(ValueLayout.JAVA_LONG, ctl, CMSG_HEADER_SIZE + 2);
        cbuf.set(ValueLayout.JAVA_INT, ctl + 8, SOL_UDP);
        cbuf.set(ValueLayout.JAVA_INT, ctl + 12, UDP_SEGMENT);
        cbuf.set(ValueLayout.JAVA_SHORT, ctl + CMSG_DATA_OFFSET, (short) segSize);
        ctl += cmsgSpace(2);
        msg.set(ValueLayout.ADDRESS, MSGHDR_CONTROL, cbuf);
        msg.set(ValueLayout.JAVA_LONG, MSGHDR_CONTROLLEN, ctl);

        return sendmsg(fd, msg, 0);
    }

    // -------------------------------------------------- Address conversion

    /**
     * Writes a Java address into a sockaddr storage as {@code sockaddr_in}
     * or {@code sockaddr_in6} (port in network byte order).
     *
     * @param sa    The storage (at least 28 bytes)
     * @param addr  The address to write
     *
     * @return The written sockaddr length (16 or 28)
     */
    static int fillSockaddr(MemorySegment sa, InetSocketAddress addr) {
        InetAddress a = addr.getAddress();
        int port = addr.getPort();
        short portBE = (short) (((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
        if (a instanceof Inet4Address) {
            sa.set(ValueLayout.JAVA_SHORT, 0, (short) AF_INET);
            sa.set(ValueLayout.JAVA_SHORT, 2, portBE);
            byte[] bytes = a.getAddress();
            for (int i = 0; i < 4; i++) {
                sa.set(ValueLayout.JAVA_BYTE, 4 + i, bytes[i]);
            }
            return 16;
        }
        sa.set(ValueLayout.JAVA_SHORT, 0, (short) AF_INET6);
        sa.set(ValueLayout.JAVA_SHORT, 2, portBE);
        sa.set(ValueLayout.JAVA_INT, 4, 0); // flowinfo
        byte[] bytes = a.getAddress();
        for (int i = 0; i < 16; i++) {
            sa.set(ValueLayout.JAVA_BYTE, 8 + i, bytes[i]);
        }
        // sin6_scope_id: the interface index of a scoped address (link-local
        // peers/sources and bind addresses carry %zone on the Inet6Address;
        // dropping it would make the kernel unable to route the sockaddr).
        int scopeId = (a instanceof Inet6Address) ? ((Inet6Address) a).getScopeId() : 0;
        sa.set(ValueLayout.JAVA_INT, 24, scopeId);
        return 28;
    }

    /**
     * Reads a {@code sockaddr_in} / {@code sockaddr_in6} into a Java
     * address.
     *
     * @param sa  The sockaddr
     * @param len The sockaddr length
     *
     * @return The address, or {@code null} if the family is unknown
     */
    static InetSocketAddress readSockaddr(MemorySegment sa, int len) {
        if (sa == null || sa.equals(MemorySegment.NULL) || len < 2) {
            return null;
        }
        short family = sa.get(ValueLayout.JAVA_SHORT, 0);
        short portBE = sa.get(ValueLayout.JAVA_SHORT, 2);
        int port = ((portBE & 0xFF) << 8) | ((portBE >> 8) & 0xFF);
        if (family == AF_INET && len >= 16) {
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                bytes[i] = sa.get(ValueLayout.JAVA_BYTE, 4 + i);
            }
            try {
                return new InetSocketAddress(InetAddress.getByAddress(bytes), port);
            } catch (IllegalArgumentException | UnknownHostException e) {
                return null;
            }
        }
        if (family == AF_INET6 && len >= 28) {
            byte[] bytes = new byte[16];
            for (int i = 0; i < 16; i++) {
                bytes[i] = sa.get(ValueLayout.JAVA_BYTE, 8 + i);
            }
            int scopeId = sa.get(ValueLayout.JAVA_INT, 24);
            try {
                InetAddress addr = (scopeId != 0)
                        ? Inet6Address.getByAddress(null, bytes, scopeId)
                        : InetAddress.getByAddress(bytes);
                return new InetSocketAddress(addr, port);
            } catch (UnknownHostException e) {
                // Scoped name lookup needs the interface to still exist; if it
                // vanished since recv, degrade to the scope-less address
                // (the behaviour before scope support).
                if (scopeId == 0) {
                    return null;
                }
                try {
                    return new InetSocketAddress(InetAddress.getByAddress(bytes), port);
                } catch (IllegalArgumentException | UnknownHostException e2) {
                    return null;
                }
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Converts an IPv4-mapped IPv6 address ({@code ::ffff/96}, RFC 9000
     * Section 2.2 / RFC 4291 Section 2.5.5.2) to the plain IPv4 address it
     * carries. A dual-stack wildcard bind delivers IPv4 datagrams with
     * v4-mapped sockaddrs; the java.net transports report the IPv4 form of
     * such peers, so the display paths (getRemoteAddr()/getLocalAddr(),
     * access logs, valves) unmap through this helper. Native sockaddr
     * consumers must keep the original value: the family has to match the
     * bound socket for sendmsg/recvmsg purposes.
     *
     * @param a The address to unmap, may be {@code null}
     *
     * @return the IPv4 address a v4-mapped IPv6 address carries, otherwise
     *         {@code a} unchanged
     */
    static InetSocketAddress unmapIpv4Mapped(InetSocketAddress a) {
        if (a == null) {
            return null;
        }
        InetAddress addr = a.getAddress();
        if (!(addr instanceof Inet6Address)) {
            return a;
        }
        byte[] b = addr.getAddress();
        // v4-mapped: ten leading zero bytes, then 0xffff, then the address.
        // (:: itself and ::1 fail the 0xffff test and stay untouched.)
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) {
                return a;
            }
        }
        if ((b[10] & 0xFF) != 0xFF || (b[11] & 0xFF) != 0xFF) {
            return a;
        }
        try {
            return new InetSocketAddress(
                    InetAddress.getByAddress(new byte[] { b[12], b[13], b[14], b[15] }),
                    a.getPort());
        } catch (UnknownHostException e) {
            return a;
        }
    }


    /**
     * Reads the sockaddr length implied by the family stored in the storage.
     *
     * @param sa The sockaddr
     *
     * @return 16 (IPv4), 28 (IPv6) or 0 (unknown)
     */
    static int sockaddrLength(MemorySegment sa) {
        short family = sa.get(ValueLayout.JAVA_SHORT, 0);
        if (family == AF_INET) {
            return 16;
        }
        if (family == AF_INET6) {
            return 28;
        }
        return 0;
    }

    /**
     * Enforces the sockaddr contract of every quiche entry point that takes
     * one: quiche's {@code std_addr_from_c} asserts the exact per-family
     * length (16 for {@code sockaddr_in}, 28 for {@code sockaddr_in6}) and
     * reaches {@code unimplemented!()} for any other family (quiche 0.30
     * src/ffi.rs) - a violation never returns from the native call, it
     * panics and aborts the JVM from the poll thread. Every sockaddr/length
     * pair crossing into a quiche call is checked here first so a future
     * producer regression (a partial length, a foreign family, a length
     * that no longer matches the stored family) surfaces as an ordinary
     * catchable Java exception instead of a dead process. The expected
     * length is re-derived from the stored family here - deliberately not
     * via {@link #sockaddrLength(MemorySegment)} - so a regression in that
     * helper cannot certify its own mistake.
     *
     * @param sa  The sockaddr about to be passed to quiche
     * @param len The length about to be passed alongside it
     *
     * @throws IllegalArgumentException If the pair would violate the quiche
     *         contract (a NULL address with a non-zero length, a foreign
     *         family, or a length that does not match the stored family)
     */
    static void requireSockaddrContract(MemorySegment sa, int len) {
        int expected;
        if (sa.equals(MemorySegment.NULL)) {
            // quiche maps a NULL sockaddr to "no address" before it ever
            // reaches the per-family assert; only the zero length belongs
            // with it.
            if (len != 0) {
                throw new IllegalArgumentException(
                        "NULL sockaddr paired with length " + len);
            }
            return;
        }
        short family = sa.get(ValueLayout.JAVA_SHORT, 0);
        if (family == AF_INET) {
            expected = 16;
        } else if (family == AF_INET6) {
            expected = 28;
        } else {
            throw new IllegalArgumentException(
                    "Address family " + family + " would abort the JVM in quiche's std_addr_from_c");
        }
        if (len != expected) {
            throw new IllegalArgumentException("sockaddr length " + len +
                    " does not match the exact length " + expected +
                    " quiche asserts for its stored family");
        }
    }

    // -------------------------------------------------- Helpers

    private static MethodHandle createHandle(String symbol, FunctionDescriptor desc) {
        try {
            MemorySegment addr = QUICHE_LOOKUP.find(symbol)
                    .orElseThrow(() -> new UnsatisfiedLinkError(
                            "unresolved quiche symbol: " + symbol));
            return Linker.nativeLinker().downcallHandle(addr, desc);
        } catch (Throwable e) {
            // The bind attempt itself is the availability probe: record the
            // failure so SYMBOLS_AVAILABLE turns false at the end of static
            // initialisation (see the field's javadoc). A failed library
            // load surfaces here too (QUICHE_LOOKUP is null).
            MISSING_SYMBOLS.add(symbol);
            return null;
        }
    }

    /**
     * Creates a downcall handle for a libc symbol.
     */
    private static MethodHandle createLibcHandle(String symbol, FunctionDescriptor desc) {
        try {
            // The default lookup covers the platform libraries (libc).
            MemorySegment addr = Linker.nativeLinker().defaultLookup().find(symbol)
                    .or(() -> QUICHE_LOOKUP.find(symbol))
                    .orElseThrow(() -> new UnsatisfiedLinkError(
                            "unresolved libc symbol: " + symbol));
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
    // verdict is simply "nothing failed to bind", gated by the ABI check.
    static {
        SYMBOLS_AVAILABLE = MISSING_SYMBOLS.isEmpty();
        QUICHE_AVAILABLE = SYMBOLS_AVAILABLE && ABI_COMPATIBLE;
    }

    /**
     * Scratch allocation helper: allocates a confined scratch block for the
     * datagram helpers.
     *
     * @param arena The arena to allocate from
     *
     * @return The scratch block
     */
    static MemorySegment allocateScratch(Arena arena) {
        return arena.allocate(SCRATCH_SIZE);
    }

    // -------------------------------------------------- UDP GSO/GRO probe
    //
    // The endpoint's UDP GSO/GRO support is capability-gated, never assumed:
    // UDP_GSO_SEND says a UDP_SEGMENT sendmsg is accepted AND a plain
    // (option-less) receive socket sees the batch correctly split into
    // per-datagram reads - the behaviour every normal peer relies on.
    // UDP_GRO_RECEIVE says more: this kernel answers a coalesced read on a
    // UDP_GRO-enabled socket WITH the segment-size cmsg, the only signal by
    // which a merged read can be split back into packets. A kernel that
    // coalesces WITHOUT the cmsg (observed for GSO-passthrough reads on
    // loopback) would hand the endpoint batches it cannot take apart, so
    // there the receive option stays off and the kernel's own per-datagram
    // segmentation of incoming GSO batches keeps working.
    //
    // Both verdicts come from one live round trip per socket on loopback,
    // run once at class-init: two ephemeral bound receive sockets, one
    // sender, two 1500-byte segments.

    static final boolean UDP_GSO_SEND;
    static final boolean UDP_GRO_RECEIVE;

    static {
        boolean gso = false;
        boolean gro = false;
        try (Arena a = Arena.ofConfined()) {
            int plain = -1;
            int groSock = -1;
            int tx = -1;
            try {
                plain = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                groSock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                tx = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                if (plain >= 0 && groSock >= 0 && tx >= 0) {
                    MemorySegment saPlain = a.allocate(SOCKADDR_STORAGE_SIZE);
                    MemorySegment saGro = a.allocate(SOCKADDR_STORAGE_SIZE);
                    fillSockaddr(saPlain, new InetSocketAddress("127.0.0.1", 0));
                    fillSockaddr(saGro, new InetSocketAddress("127.0.0.1", 0));
                    if (bind(plain, saPlain, 16) == 0 && bind(groSock, saGro, 16) == 0) {
                        // The ephemeral port arrives back only via
                        // getsockname(): an FFM downcall does not propagate
                        // bind(2)'s sockaddr write-back to the caller's
                        // segment, so reading the port off the bind argument
                        // would see 0 and every send to it EINVALs (exactly
                        // how this probe once mis-verdicted a GSO-capable
                        // host as incapable).
                        MemorySegment namelen = a.allocate(ValueLayout.JAVA_INT);
                        namelen.set(ValueLayout.JAVA_INT, 0, 16);
                        if (getsockname(plain, saPlain, namelen) != 0
                                || getsockname(groSock, saGro, namelen) != 0) {
                            throw new IllegalStateException("probe getsockname");
                        }
                        MemorySegment data = a.allocate(3000);
                        int[] lens = new int[] { 1500, 1500 };
                        MemorySegment bscratch = a.allocate(BATCH_SCRATCH_SIZE);
                        // GSO send + plain receive: the batch must arrive
                        // split, first read exactly one segment.
                        long s = sendSegmentedDatagram(tx, data, lens, 2, 1500,
                                1500, saPlain, 16, null, bscratch);
                        MemorySegment rbuf = a.allocate(4096);
                        MemorySegment scratch = allocateScratch(a);
                        MemorySegment from = a.allocate(SOCKADDR_STORAGE_SIZE);
                        MemorySegment to = a.allocate(SOCKADDR_STORAGE_SIZE);
                        MemorySegment toLen = a.allocate(ValueLayout.JAVA_INT);
                        int[] segOut = new int[1];
                        long r = recvDatagram(plain, rbuf, 4096, scratch, from,
                                to, toLen, segOut);
                        gso = s == 3000 && r == 1500;
                        // GSO send + UDP_GRO-enabled receive: a coalesced
                        // read must carry the cmsg. Any other outcome (no
                        // merge, silent merge, set failure) keeps the
                        // receive option off - safe by construction.
                        if (gso) {
                            MemorySegment one = a.allocate(ValueLayout.JAVA_INT);
                            one.set(ValueLayout.JAVA_INT, 0, 1);
                            if (setsockopt(groSock, SOL_UDP, UDP_GRO, one, 4) == 0) {
                                s = sendSegmentedDatagram(tx, data, lens, 2, 1500,
                                        1500, saGro, 16, null, bscratch);
                                r = recvDatagram(groSock, rbuf, 4096, scratch, from,
                                        to, toLen, segOut);
                                gro = s == 3000 && r == 3000 && segOut[0] == 1500;
                            }
                        }
                    }
                }
            } finally {
                if (plain >= 0) {
                    close(plain);
                }
                if (groSock >= 0) {
                    close(groSock);
                }
                if (tx >= 0) {
                    close(tx);
                }
            }
        } catch (Throwable t) {
            // Any probe surprise: both features off, every path behaves as
            // before they existed.
            gso = false;
            gro = false;
        }
        UDP_GSO_SEND = gso;
        UDP_GRO_RECEIVE = gro;
    }
}

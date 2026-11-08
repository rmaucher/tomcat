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
package org.apache.tomcat.util.net.quic.ngtcp2;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemoryLayout.PathElement;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.tomcat.util.net.quic.openssl.QuicBindings;
import org.apache.tomcat.util.openssl.openssl_h;

/**
 * FFM bindings for ngtcp2 plus a small transport facade modelled on the
 * operations the QUIC endpoint needs.
 * <p>
 * The endpoint control flow is shared with the quiche transport. This class
 * translates the quiche-like calls used by that code into ngtcp2 operations
 * and is the only place that knows about ngtcp2's callback-driven model and
 * native struct layouts.
 * <p>
 * Target ABI: ngtcp2 1.16.x and 1.26.x. The layout constants below were
 * generated from the installed 1.16 headers. The 1.26 structs only append
 * fields after the slices this binding passes to the versioned API
 * (CALLBACKS_V2 and SETTINGS_V3), so the 1.16 offsets and the V2/V3 struct
 * lengths remain valid; transport_params (V1) did not change size. The runtime
 * version is gated accordingly.
 */
public final class Ngtcp2Bindings {

    private Ngtcp2Bindings() {
    }

    private static final org.apache.juli.logging.Log log =
            org.apache.juli.logging.LogFactory.getLog(Ngtcp2Bindings.class);
    private static final org.apache.tomcat.util.res.StringManager sm =
            org.apache.tomcat.util.res.StringManager.getManager(Ngtcp2Bindings.class);

    static final int NGTCP2_MAX_CONN_ID_LEN = 20;
    static final int NGTCP2_MAX_UDP_PAYLOAD_SIZE = 1200;
    static final int NGTCP2_STATELESS_RESET_TOKENLEN = 16;

    // quiche-compatible facade return values used by the ported endpoint.
    static final long NGTCP2_ERR_DONE = -1;
    static final long NGTCP2_ERR_STREAM_RESET = -2;
    static final long NGTCP2_ERR_STREAM_STOPPED = -3;
    static final long NGTCP2_ERR_INVALID_STREAM_STATE = -4;
    static final long NGTCP2_ERR_FINAL_SIZE = -5;
    static final long NGTCP2_ERR_FLOW_CONTROL = -6;

    static final int NGTCP2_SHUTDOWN_READ = 0;
    static final int NGTCP2_SHUTDOWN_WRITE = 1;
    static final long NGTCP2_TRANSPORT_CONNECTION_REFUSED = 0x02L;

    // QUIC wire versions.
    private static final int QUIC_V1 = 1;
    private static final int QUIC_V2 = 0x6b3343cf;

    // Packet type values used by the endpoint's demux.
    static final int NGTCP2_PACKET_TYPE_INITIAL = 1;
    static final int NGTCP2_PACKET_TYPE_SHORT = 5;

    // Native error codes (ngtcp2 1.16).
    static final int NGTCP2_ERR_STREAM_ID_BLOCKED = -206;
    private static final int NGTCP2_ERR_STREAM_DATA_BLOCKED = -208;
    static final int NGTCP2_ERR_CRYPTO = -213;
    private static final int NGTCP2_ERR_STREAM_SHUT_WR = -219;
    private static final int NGTCP2_ERR_STREAM_NOT_FOUND = -220;
    static final int NGTCP2_ERR_CLOSING = -223;
    static final int NGTCP2_ERR_DRAINING = -224;
    static final int NGTCP2_ERR_RETRY = -231;
    static final int NGTCP2_ERR_DROP_CONN = -232;
    private static final int NGTCP2_ERR_IDLE_CLOSE = -238;
    private static final int NGTCP2_ERR_CALLBACK_FAILURE = -502;

    private static final int NGTCP2_SETTINGS_V3 = 3;
    private static final int NGTCP2_TRANSPORT_PARAMS_V1 = 1;
    private static final int NGTCP2_PKT_INFO_V1 = 1;
    private static final int NGTCP2_CALLBACKS_V2 = 2;

    private static final int NGTCP2_WRITE_STREAM_FLAG_NONE = 0;
    private static final int NGTCP2_WRITE_STREAM_FLAG_FIN = 0x02;

    // -------------------------------------------------- struct layouts

    // ngtcp2_cid: size_t datalen; uint8_t data[20]; (32 bytes on LP64)
    private static final long CID_DATALEN = 0;
    private static final long CID_DATA = 8;
    private static final long CID_SIZE = 32;

    // ngtcp2_vec: const uint8_t *base; size_t len; (16 bytes)
    private static final long VEC_BASE = 0;
    private static final long VEC_LEN = 8;
    private static final long VEC_SIZE = 16;

    private static final long PATH_SIZE = 40;
    private static final long PATH_LOCAL_ADDR = 0;
    private static final long PATH_LOCAL_LEN = 8;
    private static final long PATH_REMOTE_ADDR = 16;
    private static final long PATH_REMOTE_LEN = 24;

    private static final long SETTINGS_SIZE = 200;
    private static final long SETTINGS_INITIAL_TS = 16;
    private static final long SETTINGS_MAX_TX_UDP_PAYLOAD = 40;

    private static final long PARAMS_SIZE = 344;
    private static final long PARAMS_ORIGINAL_DCID = 96;
    private static final long PARAMS_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 192;
    private static final long PARAMS_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 200;
    private static final long PARAMS_INITIAL_MAX_STREAM_DATA_UNI = 208;
    private static final long PARAMS_INITIAL_MAX_DATA = 216;
    private static final long PARAMS_INITIAL_MAX_STREAMS_BIDI = 224;
    private static final long PARAMS_INITIAL_MAX_STREAMS_UNI = 232;
    private static final long PARAMS_MAX_IDLE_TIMEOUT = 240;
    private static final long PARAMS_ACTIVE_CONNECTION_ID_LIMIT = 256;
    private static final long PARAMS_ORIGINAL_DCID_PRESENT = 290;
    private static final long PARAMS_GREASE_QUIC_BIT = 310;

    private static final long CALLBACKS_SIZE = 328;
    private static final long CB_RECV_CLIENT_INITIAL = 8;
    private static final long CB_RECV_CRYPTO_DATA = 16;
    private static final long CB_HANDSHAKE_COMPLETED = 24;
    private static final long CB_ENCRYPT = 40;
    private static final long CB_DECRYPT = 48;
    private static final long CB_HP_MASK = 56;
    private static final long CB_RECV_STREAM_DATA = 64;
    private static final long CB_ACKED_STREAM_DATA = 72;
    private static final long CB_STREAM_OPEN = 80;
    private static final long CB_STREAM_CLOSE = 88;
    private static final long CB_RAND = 128;
    private static final long CB_GET_NEW_CONNECTION_ID = 136;
    private static final long CB_REMOVE_CONNECTION_ID = 144;
    private static final long CB_UPDATE_KEY = 152;
    private static final long CB_STREAM_RESET = 176;
    private static final long CB_DELETE_AEAD = 232;
    private static final long CB_DELETE_CIPHER = 240;
    private static final long CB_GET_PATH_CHALLENGE = 272;
    private static final long CB_STREAM_STOP_SENDING = 280;
    private static final long CB_VERSION_NEGOTIATION = 288;

    private static final long CCERR_SIZE = 40;
    private static final long CCERR_TYPE = 0;
    private static final long CCERR_ERROR_CODE = 8;
    private static final long CCERR_REASON = 24;
    private static final long CCERR_REASONLEN = 32;
    private static final int CCERR_TYPE_TRANSPORT = 0;
    private static final int CCERR_TYPE_APPLICATION = 1;

    private static final long CONN_REF_SIZE = 16;
    private static final long CONN_REF_GET_CONN = 0;
    private static final long CONN_REF_USER_DATA = 8;

    static final long VERSION_CID_SIZE = 40;
    private static final long VERSION_CID_VERSION = 0;
    private static final long VERSION_CID_DCID = 8;
    private static final long VERSION_CID_DCIDLEN = 16;
    private static final long VERSION_CID_SCID = 24;
    private static final long VERSION_CID_SCIDLEN = 32;

    // -------------------------------------------------- availability

    private static final Set<String> MISSING_SYMBOLS = new LinkedHashSet<>();
    private static final boolean SYMBOLS_AVAILABLE;
    static boolean NGTCP2_AVAILABLE;
    static final String NGTCP2_VERSION;
    private static final int NGTCP2_VERSION_NUM;
    private static SymbolLookup NGTCP2_LOOKUP;
    private static SymbolLookup CRYPTO_LOOKUP;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Arena CB_ARENA = Arena.ofShared();

    private static final Map<Long, ConnState> CONN_STATES = new ConcurrentHashMap<>();
    private static final Map<Long, ConnState> TOKEN_STATES = new ConcurrentHashMap<>();

    private static final MemorySegment CALLBACKS = CB_ARENA.allocate(CALLBACKS_SIZE);

    /*
     * The library lookup must be established before any of the MethodHandle
     * fields below initialise: static initialisers run in textual order.
     */
    static {
        SymbolLookup lookup = null;
        SymbolLookup crypto = null;
        try {
            System.loadLibrary("ngtcp2");
            lookup = Linker.nativeLinker().defaultLookup().or(SymbolLookup.loaderLookup());
        } catch (Throwable t) {
            MISSING_SYMBOLS.add("libngtcp2");
        }
        try {
            System.loadLibrary("ngtcp2_crypto_ossl");
        } catch (Throwable t) {
            try {
                crypto = SymbolLookup.libraryLookup("libngtcp2_crypto_ossl.so.0",
                        Arena.global());
            } catch (Throwable t2) {
                MISSING_SYMBOLS.add("libngtcp2_crypto_ossl");
            }
        }
        if (crypto == null && lookup != null) {
            crypto = SymbolLookup.loaderLookup().or(lookup);
        }
        NGTCP2_LOOKUP = lookup;
        CRYPTO_LOOKUP = crypto;
    }

    private static final MethodHandle sslSetExData$handle = createSslHandle(
            "SSL_set_ex_data",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER, ValueLayout.JAVA_INT,
                    openssl_h.C_POINTER));

    private static final MethodHandle ngtcp2SettingsDefault$handle = createHandle(
            "ngtcp2_settings_default_versioned",
            FunctionDescriptor.ofVoid(ValueLayout.JAVA_INT, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2TransportParamsDefault$handle = createHandle(
            "ngtcp2_transport_params_default_versioned",
            FunctionDescriptor.ofVoid(ValueLayout.JAVA_INT, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnServerNew$handle = createHandle(
            "ngtcp2_conn_server_new_versioned",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, openssl_h.C_POINTER, openssl_h.C_POINTER,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    ValueLayout.JAVA_INT, openssl_h.C_POINTER, ValueLayout.JAVA_INT,
                    openssl_h.C_POINTER, openssl_h.C_POINTER, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnDel$handle = createHandle(
            "ngtcp2_conn_del",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnReadPkt$handle = createHandle(
            "ngtcp2_conn_read_pkt_versioned",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnWritePkt$handle = createHandle(
            "ngtcp2_conn_write_pkt_versioned",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnWritevStream$handle = createHandle(
            "ngtcp2_conn_writev_stream_versioned",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnWriteClose$handle = createHandle(
            "ngtcp2_conn_write_connection_close_versioned",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                    ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnHandleExpiry$handle = createHandle(
            "ngtcp2_conn_handle_expiry",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnGetExpiry$handle = createHandle(
            "ngtcp2_conn_get_expiry",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnUpdatePktTxTime$handle = createHandle(
            "ngtcp2_conn_update_pkt_tx_time",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnOpenUni$handle = createHandle(
            "ngtcp2_conn_open_uni_stream",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnShutdownWrite$handle = createHandle(
            "ngtcp2_conn_shutdown_stream_write",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnShutdownRead$handle = createHandle(
            "ngtcp2_conn_shutdown_stream_read",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnMaxStreamDataLeft$handle = createHandle(
            "ngtcp2_conn_get_max_stream_data_left",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                    ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnMaxDataLeft$handle = createHandle(
            "ngtcp2_conn_get_max_data_left",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnMaxTxPayload$handle = createHandle(
            "ngtcp2_conn_get_max_tx_udp_payload_size",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnHandshakeCompleted$handle = createHandle(
            "ngtcp2_conn_get_handshake_completed",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnInClosing$handle = createHandle(
            "ngtcp2_conn_in_closing_period",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnInDraining$handle = createHandle(
            "ngtcp2_conn_in_draining_period",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnSetTlsNative$handle = createHandle(
            "ngtcp2_conn_set_tls_native_handle",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2ConnExtendMaxOffset$handle = createHandle(
            "ngtcp2_conn_extend_max_offset",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnExtendMaxStreamsBidi$handle = createHandle(
            "ngtcp2_conn_extend_max_streams_bidi",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2ConnExtendMaxStreamOffset$handle = createHandle(
            "ngtcp2_conn_extend_max_stream_offset",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2Version$handle = createHandle(
            "ngtcp2_version", FunctionDescriptor.of(openssl_h.C_POINTER, ValueLayout.JAVA_INT));
    private static final MethodHandle ngtcp2ErrInferTransport$handle = createHandle(
            "ngtcp2_err_infer_quic_transport_error_code",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));
    private static final MethodHandle ngtcp2Strerror$handle = createHandle(
            "ngtcp2_strerror", FunctionDescriptor.of(openssl_h.C_POINTER, ValueLayout.JAVA_INT));
    private static final MethodHandle ngtcp2PktDecodeVersionCid$handle = createHandle(
            "ngtcp2_pkt_decode_version_cid",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    openssl_h.C_POINTER, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2PktWriteVersionNegotiation$handle = createHandle(
            "ngtcp2_pkt_write_version_negotiation",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                    ValueLayout.JAVA_LONG, ValueLayout.JAVA_BYTE, openssl_h.C_POINTER,
                    ValueLayout.JAVA_LONG, openssl_h.C_POINTER, ValueLayout.JAVA_LONG,
                    openssl_h.C_POINTER, ValueLayout.JAVA_LONG));

    private static final MethodHandle ngtcp2ConnGetCcerr$handle = createHandle(
            "ngtcp2_conn_get_ccerr",
            FunctionDescriptor.of(openssl_h.C_POINTER, openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2CcerrDefault$handle = createHandle(
            "ngtcp2_ccerr_default",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER));
    private static final MethodHandle ngtcp2CcerrSetApp$handle = createHandle(
            "ngtcp2_ccerr_set_application_error",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER, ValueLayout.JAVA_LONG,
                    openssl_h.C_POINTER, ValueLayout.JAVA_LONG));
    private static final MethodHandle ngtcp2CcerrSetTransport$handle = createHandle(
            "ngtcp2_ccerr_set_transport_error",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER, ValueLayout.JAVA_LONG,
                    openssl_h.C_POINTER, ValueLayout.JAVA_LONG));

    private static final MethodHandle cryptoOsslInit$handle = createCryptoHandle(
            "ngtcp2_crypto_ossl_init", FunctionDescriptor.of(ValueLayout.JAVA_INT));
    private static final MethodHandle cryptoOsslCtxNew$handle = createCryptoHandle(
            "ngtcp2_crypto_ossl_ctx_new",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                    openssl_h.C_POINTER));
    private static final MethodHandle cryptoOsslCtxDel$handle = createCryptoHandle(
            "ngtcp2_crypto_ossl_ctx_del",
            FunctionDescriptor.ofVoid(openssl_h.C_POINTER));
    private static final MethodHandle cryptoOsslConfigureServer$handle = createCryptoHandle(
            "ngtcp2_crypto_ossl_configure_server_session",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER));

    private static final MemorySegment CB_RECV_CLIENT_INITIAL_ADDR =
            cryptoAddress("ngtcp2_crypto_recv_client_initial_cb");
    private static final MemorySegment CB_RECV_CRYPTO_DATA_ADDR =
            cryptoAddress("ngtcp2_crypto_recv_crypto_data_cb");
    private static final MemorySegment CB_ENCRYPT_ADDR =
            cryptoAddress("ngtcp2_crypto_encrypt_cb");
    private static final MemorySegment CB_DECRYPT_ADDR =
            cryptoAddress("ngtcp2_crypto_decrypt_cb");
    private static final MemorySegment CB_HP_MASK_ADDR =
            cryptoAddress("ngtcp2_crypto_hp_mask_cb");
    private static final MemorySegment CB_UPDATE_KEY_ADDR =
            cryptoAddress("ngtcp2_crypto_update_key_cb");
    private static final MemorySegment CB_DELETE_AEAD_ADDR =
            cryptoAddress("ngtcp2_crypto_delete_crypto_aead_ctx_cb");
    private static final MemorySegment CB_DELETE_CIPHER_ADDR =
            cryptoAddress("ngtcp2_crypto_delete_crypto_cipher_ctx_cb");
    private static final MemorySegment CB_GET_PATH_CHALLENGE_ADDR =
            cryptoAddress("ngtcp2_crypto_get_path_challenge_data_cb");
    private static final MemorySegment CB_VERSION_NEGOTIATION_ADDR =
            cryptoAddress("ngtcp2_crypto_version_negotiation_cb");

    private static final MemorySegment CB_RECV_STREAM_DATA_STUB;
    private static final MemorySegment CB_ACKED_STREAM_DATA_STUB;
    private static final MemorySegment CB_STREAM_OPEN_STUB;
    private static final MemorySegment CB_STREAM_CLOSE_STUB;
    private static final MemorySegment CB_RAND_STUB;
    private static final MemorySegment CB_STREAM_RESET_STUB;
    private static final MemorySegment CB_STREAM_STOP_SENDING_STUB;
    private static final MemorySegment CB_GET_CONN_STUB;
    private static final MemorySegment CB_GET_NEW_CONNECTION_ID_STUB;
    private static final MemorySegment CB_REMOVE_CONNECTION_ID_STUB;

    static {
        SymbolLookup lookup = NGTCP2_LOOKUP;
        SymbolLookup crypto = CRYPTO_LOOKUP;

        int versionNum = 0;
        String versionString = null;
        if (lookup != null && ngtcp2Version$handle != null) {
            try {
                MemorySegment info =
                        (MemorySegment) ngtcp2Version$handle.invokeExact(0x011000);
                if (!info.equals(MemorySegment.NULL)) {
                    info = info.reinterpret(24);
                    versionNum = info.get(ValueLayout.JAVA_INT, 4);
                    MemorySegment str = info.get(ValueLayout.ADDRESS, 8);
                    if (!str.equals(MemorySegment.NULL)) {
                        versionString = str.reinterpret(64).getString(0);
                    }
                } else {
                    MISSING_SYMBOLS.add("ngtcp2_version>=1.16");
                }
            } catch (Throwable t) {
                MISSING_SYMBOLS.add("ngtcp2_version");
            }
        }
        NGTCP2_VERSION_NUM = versionNum;
        NGTCP2_VERSION = versionString;

        try {
            CB_RECV_STREAM_DATA_STUB = upcall("recvStreamData",
                    MethodType.methodType(int.class, MemorySegment.class, int.class,
                            long.class, long.class, MemorySegment.class, long.class,
                            MemorySegment.class, MemorySegment.class),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                            ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                            openssl_h.C_POINTER));
            CB_ACKED_STREAM_DATA_STUB = upcall("ackedStreamData",
                    MethodType.methodType(int.class, MemorySegment.class, long.class,
                            long.class, long.class, MemorySegment.class,
                            MemorySegment.class),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                            openssl_h.C_POINTER));
            CB_STREAM_OPEN_STUB = upcall("streamOpen",
                    MethodType.methodType(int.class, MemorySegment.class, long.class,
                            MemorySegment.class),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER));
            CB_STREAM_CLOSE_STUB = upcall("streamClose",
                    MethodType.methodType(int.class, MemorySegment.class, int.class,
                            long.class, long.class, MemorySegment.class,
                            MemorySegment.class),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                            ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                            openssl_h.C_POINTER));
            CB_RAND_STUB = upcall("randBytes",
                    MethodType.methodType(void.class, MemorySegment.class, long.class,
                            MemorySegment.class),
                    FunctionDescriptor.ofVoid(openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER));
            CB_STREAM_RESET_STUB = upcall("streamReset",
                    MethodType.methodType(int.class, MemorySegment.class, long.class,
                            long.class, long.class, MemorySegment.class,
                            MemorySegment.class),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER,
                            openssl_h.C_POINTER));
            CB_STREAM_STOP_SENDING_STUB = upcall("streamStopSending",
                    MethodType.methodType(int.class, MemorySegment.class, long.class,
                            long.class, MemorySegment.class, MemorySegment.class),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                            openssl_h.C_POINTER, openssl_h.C_POINTER));
            CB_GET_CONN_STUB = upcall("getConn",
                    MethodType.methodType(MemorySegment.class, MemorySegment.class),
                    FunctionDescriptor.of(openssl_h.C_POINTER, openssl_h.C_POINTER));
            CB_GET_NEW_CONNECTION_ID_STUB = upcall("getNewConnectionId",
                    MethodType.methodType(int.class, MemorySegment.class,
                            MemorySegment.class, MemorySegment.class, long.class,
                            MemorySegment.class),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER, openssl_h.C_POINTER,
                            ValueLayout.JAVA_LONG, openssl_h.C_POINTER));
            CB_REMOVE_CONNECTION_ID_STUB = upcall("removeConnectionId",
                    MethodType.methodType(int.class, MemorySegment.class,
                            MemorySegment.class, MemorySegment.class),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, openssl_h.C_POINTER,
                            openssl_h.C_POINTER, openssl_h.C_POINTER));
        } catch (Throwable t) {
            throw new ExceptionInInitializerError(t);
        }

        CALLBACKS.set(openssl_h.C_POINTER, CB_RECV_CLIENT_INITIAL, CB_RECV_CLIENT_INITIAL_ADDR);
        CALLBACKS.set(openssl_h.C_POINTER, CB_RECV_CRYPTO_DATA, CB_RECV_CRYPTO_DATA_ADDR);
        CALLBACKS.set(openssl_h.C_POINTER, CB_ENCRYPT, CB_ENCRYPT_ADDR);
        CALLBACKS.set(openssl_h.C_POINTER, CB_DECRYPT, CB_DECRYPT_ADDR);
        CALLBACKS.set(openssl_h.C_POINTER, CB_HP_MASK, CB_HP_MASK_ADDR);
        CALLBACKS.set(openssl_h.C_POINTER, CB_RECV_STREAM_DATA, CB_RECV_STREAM_DATA_STUB);
        CALLBACKS.set(openssl_h.C_POINTER, CB_ACKED_STREAM_DATA, CB_ACKED_STREAM_DATA_STUB);
        CALLBACKS.set(openssl_h.C_POINTER, CB_STREAM_OPEN, CB_STREAM_OPEN_STUB);
        CALLBACKS.set(openssl_h.C_POINTER, CB_STREAM_CLOSE, CB_STREAM_CLOSE_STUB);
        CALLBACKS.set(openssl_h.C_POINTER, CB_RAND, CB_RAND_STUB);
        CALLBACKS.set(openssl_h.C_POINTER, CB_GET_NEW_CONNECTION_ID,
                CB_GET_NEW_CONNECTION_ID_STUB);
        CALLBACKS.set(openssl_h.C_POINTER, CB_REMOVE_CONNECTION_ID,
                CB_REMOVE_CONNECTION_ID_STUB);
        CALLBACKS.set(openssl_h.C_POINTER, CB_UPDATE_KEY, CB_UPDATE_KEY_ADDR);
        CALLBACKS.set(openssl_h.C_POINTER, CB_STREAM_RESET, CB_STREAM_RESET_STUB);
        CALLBACKS.set(openssl_h.C_POINTER, CB_DELETE_AEAD, CB_DELETE_AEAD_ADDR);
        CALLBACKS.set(openssl_h.C_POINTER, CB_DELETE_CIPHER, CB_DELETE_CIPHER_ADDR);
        CALLBACKS.set(openssl_h.C_POINTER, CB_GET_PATH_CHALLENGE,
                CB_GET_PATH_CHALLENGE_ADDR);
        CALLBACKS.set(openssl_h.C_POINTER, CB_STREAM_STOP_SENDING,
                CB_STREAM_STOP_SENDING_STUB);
        CALLBACKS.set(openssl_h.C_POINTER, CB_VERSION_NEGOTIATION,
                CB_VERSION_NEGOTIATION_ADDR);

        SYMBOLS_AVAILABLE = MISSING_SYMBOLS.isEmpty();
        // The fixed layouts were validated against 1.16 and 1.26. Both pass
        // the old versioned slices (CALLBACKS_V2, SETTINGS_V3,
        // TRANSPORT_PARAMS_V1), so the 1.26 struct growth (callbacks 328->384,
        // settings 200->216) happens after the bytes we allocate and the
        // library reads/copies only the requested slice length. Do not widen
        // this to arbitrary later minors without re-validating those layouts.
        boolean abi = (versionNum >= 0x011000 && versionNum < 0x011100) ||
                (versionNum >= 0x011a00 && versionNum < 0x011b00);
        // The fixed LP64 layout, socket constants and libc downcalls below are
        // Linux-specific (see the class constants). Without this gate a
        // non-Linux installation with libngtcp2 present would report the
        // transport available and then fail in eventfd/errno or with a wrong
        // numeric socket option at bind time.
        boolean linux = System.getProperty("os.name", "").startsWith("Linux");
        NGTCP2_AVAILABLE = SYMBOLS_AVAILABLE && abi && CRYPTO_LOOKUP != null &&
                linux;
        if (!linux) {
            log.warn(sm.getString("ngtcp2Bindings.unsupportedPlatform",
                    System.getProperty("os.name", "unknown")));
        }
        if (!abi && versionNum != 0) {
            log.warn(sm.getString("ngtcp2Bindings.abiMismatch",
                    versionString != null ? versionString :
                            "0x" + Integer.toHexString(versionNum),
                    "1.16.x/1.26.x"));
        }
        if (NGTCP2_AVAILABLE) {
            cryptoOsslInit();
        }
    }

    // -------------------------------------------------- connection state

    static final class ConnState {
        final MemorySegment conn;
        final MemorySegment ssl;
        final MemorySegment osslCtx;
        final MemorySegment connRef;
        final MemorySegment token;
        final MemorySegment localSockaddr;
        final MemorySegment remoteSockaddr;
        final int localSockaddrLen;
        final int remoteSockaddrLen;
        final MemorySegment path;
        final Arena arena;

        /*
         * Per-connection scratch for the send path. The poll thread (and,
         * during a graceful stop, the stop thread after the poll loop has
         * exited) is the only caller, so the buffers can be reused for every
         * packet instead of allocating a fresh Arena per call.
         */
        final MemorySegment sendVecs;
        final MemorySegment datalenSeg;
        final MemorySegment ccerr;

        final Map<Long, StreamState> streams = new ConcurrentHashMap<>();

        /*
         * Ready work sets. Scanning the stream map for every packet and
         * sweep made the hot path O(live + completed streams), and the map
         * accumulates one entry per request, so a long-lived connection
         * degraded linearly. The queues carry exactly the streams that have
         * work and are only touched by the poll thread.
         */
        final PriorityQueue<StreamState> readableQueue =
                new PriorityQueue<>(Comparator.comparingLong(ss -> ss.id));
        final ArrayDeque<StreamState> sendQueue = new ArrayDeque<>();
        /** No packet could be produced in the last send pass (credit/CC). */
        boolean sendBlocked;

        /*
         * Weak: the static CONN_STATES map must not keep the wrapper alive.
         * The wrapper owns the Cleaner that is the last-resort free path for
         * connections which escape the explicit teardown paths; a strong
         * reference here would make the Cleaner unreachable forever.
         */
        volatile java.lang.ref.WeakReference<Ngtcp2ConnectionWrapper> wrapper;
        volatile boolean closed;
        volatile boolean draining;
        volatile boolean closeQueued;
        volatile boolean closeApp;
        volatile long closeError;
        volatile String closeReason;
        volatile boolean lastErrorSet;
        volatile long lastErrorCode;
        volatile String lastErrorReason;
        volatile boolean peerErrorSet;
        volatile boolean peerErrorApp;
        volatile long peerErrorCode;
        volatile String peerErrorReason;

        MemorySegment alpnData = MemorySegment.NULL;
        MemorySegment sniData = MemorySegment.NULL;
        MemorySegment errorReasonData = MemorySegment.NULL;
        MemorySegment peerReasonData = MemorySegment.NULL;

        /** Thread the connection state is confined to (the poll thread). */
        final Thread ownerThread;

        ConnState(MemorySegment conn, MemorySegment ssl, MemorySegment osslCtx,
                MemorySegment connRef, MemorySegment token, Arena arena,
                MemorySegment local, int localLen, MemorySegment remote, int remoteLen,
                MemorySegment path) {
            this.conn = conn;
            this.ssl = ssl;
            this.osslCtx = osslCtx;
            this.connRef = connRef;
            this.token = token;
            this.arena = arena;
            this.localSockaddr = local;
            this.localSockaddrLen = localLen;
            this.remoteSockaddr = remote;
            this.remoteSockaddrLen = remoteLen;
            this.path = path;
            this.ownerThread = Thread.currentThread();
            this.sendVecs = arena.allocate(64L * VEC_SIZE);
            this.datalenSeg = arena.allocate(ValueLayout.JAVA_LONG);
            this.ccerr = arena.allocate(CCERR_SIZE);
        }

        StreamState stream(long id) {
            return streams.computeIfAbsent(Long.valueOf(id), StreamState::new);
        }
    }

    static final class StreamState {
        final long id;
        final ArrayDeque<ReadChunk> reads = new ArrayDeque<>();
        final ArrayList<SendChunk> sends = new ArrayList<>();
        /** Index of the first chunk not fully handed to ngtcp2. */
        int sendVecIndex;
        /** Index of the first chunk not fully acknowledged by the peer. */
        int ackIndex;
        boolean inReadQueue;
        boolean inSendQueue;
        long queuedOffset;
        long sentOffset;
        long ackedOffset;
        boolean finQueued;
        boolean finReceived;
        boolean finDelivered;
        boolean resetRemote;
        boolean resetRemoteDelivered;
        boolean resetLocal;
        boolean closed;
        boolean nativeOpen;
        boolean readReported;

        StreamState(long id) {
            this.id = id;
        }

        boolean readable() {
            return !reads.isEmpty() || (finReceived && !finDelivered) ||
                    (resetRemote && !resetRemoteDelivered);
        }

        boolean hasWritable() {
            return !closed && !resetLocal &&
                    ((finQueued && sentOffset >= queuedOffset) || sentOffset < queuedOffset);
        }
    }

    static final class ReadChunk {
        final byte[] data;
        int off;
        final boolean fin;

        ReadChunk(byte[] data, boolean fin) {
            this.data = data;
            this.fin = fin;
        }
    }

    static final class SendChunk {
        final Arena arena;
        final MemorySegment segment;
        final long start;
        final int len;
        final Thread owner;
        final boolean shared;

        SendChunk(Arena arena, MemorySegment segment, long start, int len,
                Thread owner, boolean shared) {
            this.arena = arena;
            this.segment = segment;
            this.start = start;
            this.len = len;
            this.owner = owner;
            this.shared = shared;
        }
    }

    /*
     * Closes a send chunk's arena. A confined arena may only be closed by the
     * thread that created it; if teardown runs on the stop/start/cleaner
     * thread the close is deferred to the arena's Cleaner instead of throwing
     * WrongThreadException. This keeps the hot path on confined arenas (a
     * shared arena's close costs a VM-wide thread handshake, which dominated
     * the poll thread) while cross-thread teardown remains safe.
     */
    private static void closeSendChunk(SendChunk c) {
        if (!c.shared && Thread.currentThread() != c.owner) {
            return;
        }
        try {
            c.arena.close();
        } catch (Throwable t) {
            // Ignore: a chunk that cannot be closed here is still reclaimed
            // by the arena Cleaner once it becomes unreachable.
        }
    }

    static MemorySegment ngtcp2_conn_get_ssl(MemorySegment conn) {
        ConnState st = state(conn);
        return st == null ? MemorySegment.NULL : st.ssl;
    }

    static void bindConnection(Ngtcp2ConnectionWrapper wrapper, MemorySegment conn) {
        ConnState state = CONN_STATES.get(Long.valueOf(conn.address()));
        if (state != null) {
            state.wrapper = new java.lang.ref.WeakReference<>(wrapper);
            TOKEN_STATES.put(Long.valueOf(state.token.address()), state);
        }
    }

    private static Ngtcp2ConnectionWrapper wrapper(ConnState st) {
        java.lang.ref.WeakReference<Ngtcp2ConnectionWrapper> ref =
                st == null ? null : st.wrapper;
        return ref == null ? null : ref.get();
    }

    private static ConnState state(MemorySegment conn) {
        return conn == null ? null : CONN_STATES.get(Long.valueOf(conn.address()));
    }

    private static ConnState stateFromUserData(MemorySegment userData) {
        return userData == null || userData.equals(MemorySegment.NULL) ? null :
                TOKEN_STATES.get(Long.valueOf(userData.address()));
    }

    private static long now() {
        return System.nanoTime();
    }

    private static void queueRead(ConnState st, StreamState ss) {
        if (!ss.inReadQueue && ss.readable()) {
            ss.inReadQueue = true;
            st.readableQueue.add(ss);
        }
    }

    private static void queueSend(ConnState st, StreamState ss) {
        if (!ss.inSendQueue && ss.hasWritable()) {
            ss.inSendQueue = true;
            st.sendQueue.addLast(ss);
        }
    }

    /*
     * Drops a fully closed and drained stream from the map. ngtcp2 calls
     * stream_close only after all receive data was consumed by the
     * application and all transmitted data (including the FIN) was
     * acknowledged, so the common request path reclaims immediately here;
     * the residual predicates cover reset/early-close paths and defer
     * reclamation to the later callback that removes the last state.
     */
    private static void tryReclaim(ConnState st, StreamState ss) {
        if (!ss.closed || !ss.reads.isEmpty() || !ss.sends.isEmpty() ||
                ss.inReadQueue || ss.inSendQueue) {
            return;
        }
        if (ss.finReceived && !ss.finDelivered) {
            return;
        }
        if (ss.resetRemote && !ss.resetRemoteDelivered) {
            return;
        }
        st.streams.remove(Long.valueOf(ss.id));
    }

    /**
     * Discards the binding-side receive state for a stream whose endpoint
     * wrapper has gone away (handler close, rejection at the
     * concurrent-stream limit, unidirectional terminal path). Without this
     * the buffered {@link ReadChunk}s survive until the whole connection is
     * freed, because no endpoint wrapper is left to call
     * {@code ngtcp2_conn_stream_recv()}.
     * <p>
     * Only the receive side is dropped: a bidi stream may still have queued
     * response bytes in {@code sends} that have to reach the peer, and the
     * stream's send state is reclaimed by the ACK/stream_close callbacks as
     * usual.
     *
     * @param conn The connection
     * @param id   The stream identifier
     */
    static void ngtcp2_conn_discard_stream(MemorySegment conn, long id) {
        ConnState st = state(conn);
        if (st == null) {
            return;
        }
        StreamState ss = st.streams.get(Long.valueOf(id));
        if (ss == null) {
            return;
        }
        dropBufferedReads(st, ss);
        ss.finReceived = true;
        ss.finDelivered = true;
        ss.resetRemoteDelivered = true;
        ss.readReported = false;
        if (ss.inReadQueue) {
            st.readableQueue.remove(ss);
            ss.inReadQueue = false;
        }
        tryReclaim(st, ss);
    }

    private static void writeCid(MemorySegment cid, long offset, MemorySegment data,
            long len) {
        cid.set(ValueLayout.JAVA_LONG, offset + CID_DATALEN, (long) len);
        if (len > 0) {
            MemorySegment.copy(data, 0, cid, offset + CID_DATA, len);
        }
    }

    private static void writeCid(MemorySegment cid, long offset, byte[] data, int len) {
        cid.set(ValueLayout.JAVA_LONG, offset + CID_DATALEN, (long) len);
        if (len > 0) {
            cid.asSlice(offset + CID_DATA, len).asByteBuffer().put(data, 0, len);
        }
    }

    private static int cryptoOsslInit() {
        try {
            return (int) cryptoOsslInit$handle.invokeExact();
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    /**
     * Maps an internal ngtcp2 error to the QUIC transport error code that
     * should be reported to the peer.
     *
     * @param rc The internal ngtcp2 error code
     *
     * @return The QUIC transport error code
     */
    static long ngtcp2_infer_transport_error_code(int rc) {
        try {
            return (long) ngtcp2ErrInferTransport$handle.invokeExact(rc);
        } catch (Throwable t) {
            return 0;
        }
    }

    private static String ngtcp2Strerror(int rc) {
        try {
            MemorySegment p = (MemorySegment) ngtcp2Strerror$handle.invokeExact(rc);
            return p.equals(MemorySegment.NULL) ? "ngtcp2 error " + rc :
                    p.reinterpret(256).getString(0);
        } catch (Throwable t) {
            return "ngtcp2 error " + rc;
        }
    }

    // -------------------------------------------------- accept / recv / send

    static MemorySegment ngtcp2_accept(MemorySegment serverScid, int serverScidLen,
            MemorySegment originalDcid, int originalDcidLen,
            MemorySegment clientScid, int clientScidLen, int version,
            long maxStreams, long idleTimeoutMs,
            MemorySegment localSockaddr, int localSockaddrLen,
            MemorySegment peerSockaddr, int peerSockaddrLen,
            MemorySegment sslCtx) {
        // Shared because the stop path flushes GOAWAY/close packets from the
        // thread that stops the connector, not only from the poll thread.
        Arena arena = Arena.ofShared();
        try {
            MemorySegment connPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment dcid = arena.allocate(CID_SIZE);
            MemorySegment scid = arena.allocate(CID_SIZE);
            writeCid(dcid, 0, clientScid, clientScidLen);
            writeCid(scid, 0, serverScid, serverScidLen);

            MemorySegment local = arena.allocate(localSockaddrLen);
            MemorySegment remote = arena.allocate(peerSockaddrLen);
            MemorySegment.copy(localSockaddr, 0, local, 0, localSockaddrLen);
            MemorySegment.copy(peerSockaddr, 0, remote, 0, peerSockaddrLen);

            MemorySegment path = arena.allocate(PATH_SIZE);
            path.set(openssl_h.C_POINTER, PATH_LOCAL_ADDR, local);
            path.set(ValueLayout.JAVA_INT, PATH_LOCAL_LEN, localSockaddrLen);
            path.set(openssl_h.C_POINTER, PATH_REMOTE_ADDR, remote);
            path.set(ValueLayout.JAVA_INT, PATH_REMOTE_LEN, peerSockaddrLen);

            MemorySegment settings = arena.allocate(SETTINGS_SIZE);
            ngtcp2SettingsDefault(NGTCP2_SETTINGS_V3, settings);
            settings.set(ValueLayout.JAVA_LONG, SETTINGS_INITIAL_TS, now());
            settings.set(ValueLayout.JAVA_LONG, SETTINGS_MAX_TX_UDP_PAYLOAD,
                    NGTCP2_MAX_UDP_PAYLOAD_SIZE);

            MemorySegment params = arena.allocate(PARAMS_SIZE);
            ngtcp2TransportParamsDefault(NGTCP2_TRANSPORT_PARAMS_V1, params);
            params.set(ValueLayout.JAVA_LONG,
                    PARAMS_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 32L * 1024 * 1024);
            params.set(ValueLayout.JAVA_LONG,
                    PARAMS_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 32L * 1024 * 1024);
            params.set(ValueLayout.JAVA_LONG, PARAMS_INITIAL_MAX_STREAM_DATA_UNI,
                    32L * 1024 * 1024);
            params.set(ValueLayout.JAVA_LONG, PARAMS_INITIAL_MAX_DATA,
                    32L * 1024 * 1024);
            params.set(ValueLayout.JAVA_LONG, PARAMS_INITIAL_MAX_STREAMS_BIDI,
                    maxStreams > 0 ? maxStreams : 1);
            params.set(ValueLayout.JAVA_LONG, PARAMS_INITIAL_MAX_STREAMS_UNI, 128);
            params.set(ValueLayout.JAVA_LONG, PARAMS_MAX_IDLE_TIMEOUT,
                    (idleTimeoutMs > 0 ? idleTimeoutMs : 30000) * 1_000_000L);
            params.set(ValueLayout.JAVA_LONG, PARAMS_ACTIVE_CONNECTION_ID_LIMIT, 4);
            params.set(ValueLayout.JAVA_BYTE, PARAMS_GREASE_QUIC_BIT, (byte) 1);
            writeCid(params, PARAMS_ORIGINAL_DCID, originalDcid, originalDcidLen);
            params.set(ValueLayout.JAVA_BYTE, PARAMS_ORIGINAL_DCID_PRESENT, (byte) 1);

            MemorySegment token = arena.allocate(1);
            int rc = ngtcp2ConnServerNew(connPtr, dcid, scid, path, version,
                    settings, params, token);
            if (rc != 0) {
                arena.close();
                return MemorySegment.NULL;
            }
            MemorySegment conn = connPtr.get(openssl_h.C_POINTER, 0);
            if (conn.equals(MemorySegment.NULL)) {
                arena.close();
                return MemorySegment.NULL;
            }

            MemorySegment ssl = openssl_h.SSL_new(sslCtx);
            if (ssl.equals(MemorySegment.NULL)) {
                ngtcp2ConnDel(conn);
                arena.close();
                return MemorySegment.NULL;
            }
            MemorySegment osslPtr = arena.allocate(ValueLayout.ADDRESS);
            if ((int) cryptoOsslCtxNew$handle.invokeExact(osslPtr, ssl) != 0) {
                openssl_h.SSL_free(ssl);
                ngtcp2ConnDel(conn);
                arena.close();
                return MemorySegment.NULL;
            }
            MemorySegment osslCtx = osslPtr.get(openssl_h.C_POINTER, 0);
            if ((int) cryptoOsslConfigureServer$handle.invokeExact(ssl) != 0) {
                cryptoOsslCtxDel(osslCtx);
                openssl_h.SSL_free(ssl);
                ngtcp2ConnDel(conn);
                arena.close();
                return MemorySegment.NULL;
            }

            MemorySegment connRef = arena.allocate(CONN_REF_SIZE);
            connRef.set(openssl_h.C_POINTER, CONN_REF_GET_CONN, CB_GET_CONN_STUB);
            connRef.set(openssl_h.C_POINTER, CONN_REF_USER_DATA, conn);
            sslSetExData(ssl, 0, connRef);
            openssl_h.SSL_set_accept_state(ssl);
            ngtcp2ConnSetTlsNative(conn, osslCtx);

            ConnState state = new ConnState(conn, ssl, osslCtx, connRef, token, arena,
                    local, localSockaddrLen, remote, peerSockaddrLen, path);
            CONN_STATES.put(Long.valueOf(conn.address()), state);
            return conn;
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("ngtcp2_accept failed", t);
            }
            arena.close();
            return MemorySegment.NULL;
        }
    }

    static int ngtcp2_header_info(MemorySegment pkt, long len, int scidBufLen,
            MemorySegment versionOut, MemorySegment typeOut, MemorySegment scidOut,
            MemorySegment scidLenInOut, MemorySegment dcidOut,
            MemorySegment dcidLenInOut, MemorySegment tokenOut, MemorySegment tokenLenInOut,
            MemorySegment vcScratch) {
        try {
            MemorySegment vc = vcScratch;
            int rc = (int) ngtcp2PktDecodeVersionCid$handle.invokeExact(vc, pkt, len,
                    (long) scidBufLen);
            if (rc != 0) {
                return -1;
            }
            int version = vc.get(ValueLayout.JAVA_INT, VERSION_CID_VERSION);
            MemorySegment dcid = vc.get(openssl_h.C_POINTER, VERSION_CID_DCID);
            long dcidLen = vc.get(ValueLayout.JAVA_LONG, VERSION_CID_DCIDLEN);
            MemorySegment scid = vc.get(openssl_h.C_POINTER, VERSION_CID_SCID);
            long scidLen = vc.get(ValueLayout.JAVA_LONG, VERSION_CID_SCIDLEN);
            long dcidCap = dcidLenInOut.get(ValueLayout.JAVA_LONG, 0);
            long scidCap = scidLenInOut.get(ValueLayout.JAVA_LONG, 0);
            if (dcidLen > dcidCap || scidLen > scidCap) {
                return -1;
            }
            if (dcidLen > 0) {
                MemorySegment.copy(dcid, 0, dcidOut, 0, dcidLen);
            }
            if (scidLen > 0) {
                MemorySegment.copy(scid, 0, scidOut, 0, scidLen);
            }
            dcidLenInOut.set(ValueLayout.JAVA_LONG, 0, dcidLen);
            scidLenInOut.set(ValueLayout.JAVA_LONG, 0, scidLen);
            versionOut.set(ValueLayout.JAVA_INT, 0, version);

            int first = pkt.get(ValueLayout.JAVA_BYTE, 0) & 0xFF;
            int type;
            if ((first & 0xC0) == 0xC0) {
                int longType = (first & 0x30) >> 4;
                if (version == QUIC_V2) {
                    // RFC 9369: 0=Retry, 1=Initial, 2=0-RTT, 3=Handshake.
                    type = longType == 1 ? NGTCP2_PACKET_TYPE_INITIAL :
                            longType == 3 ? 4 : 2;
                } else {
                    // RFC 9000: 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry.
                    type = longType == 0 ? NGTCP2_PACKET_TYPE_INITIAL :
                            longType == 3 ? 4 : 2;
                }
            } else {
                type = NGTCP2_PACKET_TYPE_SHORT;
            }
            typeOut.set(ValueLayout.JAVA_BYTE, 0, (byte) type);
            if (tokenLenInOut != null) {
                tokenLenInOut.set(ValueLayout.JAVA_LONG, 0, 0L);
            }
            return 0;
        } catch (Throwable t) {
            return -1;
        }
    }

    /**
     * The QUIC versions this endpoint advertises. ngtcp2 1.16 supports both
     * v1 and v2 ({@code ngtcp2_is_supported_version()} returns true for
     * {@code 0x6b3343cf}) and {@link #ngtcp2_header_info()} already maps the
     * v2 long-header type table; restricting the endpoint to v1 is a
     * deliberate deployment policy, not a library limitation.
     */
    static boolean ngtcp2_version_is_supported(int version) {
        return version == QUIC_V1;
    }

    static long ngtcp2_negotiate_version(MemorySegment dcid, long dcidLen,
            MemorySegment scid, long scidLen, MemorySegment dest, long destLen) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment versions = arena.allocate(ValueLayout.JAVA_INT);
            versions.set(ValueLayout.JAVA_INT, 0, 1);
            return (long) ngtcp2PktWriteVersionNegotiation$handle.invokeExact(
                    dest, destLen, (byte) (RANDOM.nextInt() & 0x3F), dcid, dcidLen,
                    scid, scidLen, versions, 1L);
        } catch (Throwable t) {
            return -1;
        }
    }

    static long ngtcp2_conn_recv(MemorySegment conn, MemorySegment buf, int len,
            MemorySegment recvInfo) {
        ConnState st = state(conn);
        if (st == null) {
            return -1;
        }
        try {
            MemorySegment from = recvInfo.get(openssl_h.C_POINTER, RECV_INFO_FROM);
            int fromLen = recvInfo.get(ValueLayout.JAVA_INT, RECV_INFO_FROM_LEN);
            MemorySegment to = recvInfo.get(openssl_h.C_POINTER, RECV_INFO_TO);
            int toLen = recvInfo.get(ValueLayout.JAVA_INT, RECV_INFO_TO_LEN);
            // ngtcp2 copies the addresses into its own path storage during
            // the call, so the per-connection path can be reused for every
            // datagram instead of allocating a fresh one per receive.
            st.path.set(openssl_h.C_POINTER, PATH_LOCAL_ADDR, to);
            st.path.set(ValueLayout.JAVA_INT, PATH_LOCAL_LEN, toLen);
            st.path.set(openssl_h.C_POINTER, PATH_REMOTE_ADDR, from);
            st.path.set(ValueLayout.JAVA_INT, PATH_REMOTE_LEN, fromLen);
            int rc = (int) ngtcp2ConnReadPkt$handle.invokeExact(conn, st.path,
                    NGTCP2_PKT_INFO_V1, MemorySegment.NULL, buf, (long) len, now());
            if (rc != 0) {
                noteError(st, rc);
                return rc;
            }
            st.sendBlocked = false;
            return len;
        } catch (Throwable t) {
            return -1;
        }
    }

    static long ngtcp2_conn_send(MemorySegment conn, MemorySegment dest, long destLen,
            MemorySegment sendInfo) {
        ConnState st = state(conn);
        if (st == null) {
            return NGTCP2_ERR_DONE;
        }
        if (st.closed) {
            return NGTCP2_ERR_DONE;
        }
        try {
            if (st.closeQueued) {
                try (Arena arena = Arena.ofConfined()) {
                    ngtcp2CcerrDefault(st.ccerr);
                    byte[] reason = st.closeReason == null ? null :
                            st.closeReason.getBytes(StandardCharsets.UTF_8);
                    MemorySegment reasonSeg = reason == null ? MemorySegment.NULL :
                            arena.allocate(reason.length);
                    if (reason != null && reason.length > 0) {
                        reasonSeg.asByteBuffer().put(reason);
                    }
                    if (st.closeApp) {
                        ngtcp2CcerrSetApp(st.ccerr, st.closeError,
                                reasonSeg, reason == null ? 0 : reason.length);
                    } else {
                        ngtcp2CcerrSetTransport(st.ccerr, st.closeError,
                                reasonSeg, reason == null ? 0 : reason.length);
                    }
                    long n = (long) ngtcp2ConnWriteClose$handle.invokeExact(conn,
                            st.path, NGTCP2_PKT_INFO_V1, MemorySegment.NULL, dest,
                            destLen, st.ccerr, now());
                    if (n > 0) {
                        st.closeQueued = false;
                        st.closed = true;
                        updatePktTxTime(st.conn);
                        fillSendInfo(st, sendInfo);
                        return n;
                    }
                    if (n == 0 && (st.closed || connInClosing(conn) ||
                            connInDraining(conn))) {
                        // ngtcp2 reports 0 when it is already CLOSING/DRAINING
                        // and cannot emit another close packet. Drop the queued
                        // close so has_pending_send()/the retry sweep does not
                        // spin on a frame that can never be written.
                        st.closeQueued = false;
                        return NGTCP2_ERR_DONE;
                    }
                    if (n < 0) {
                        noteError(st, (int) n);
                        return n;
                    }
                    return NGTCP2_ERR_DONE;
                }
            }

            // Try stream data first. Only streams with queued output are
            // visited, and each candidate is tried once per call so a
            // flow-control-blocked head cannot mask a sendable stream.
            if (!st.sendQueue.isEmpty()) {
                int candidates = st.sendQueue.size();
                for (int i = 0; i < candidates; i++) {
                    StreamState ss = st.sendQueue.pollFirst();
                    if (ss == null) {
                        break;
                    }
                    ss.inSendQueue = false;
                    if (!ss.hasWritable()) {
                        continue;
                    }
                    long capacity = capacity(st, ss);
                    if (capacity <= 0) {
                        queueSend(st, ss);
                        continue;
                    }
                    long remaining = ss.queuedOffset - ss.sentOffset;
                    int maxVec = (int) Math.min(64, (remaining + 1023) / 1024 + 1);
                    long cursor = ss.sentOffset;
                    int vi = 0;
                    int idx = ss.sendVecIndex;
                    while (idx < ss.sends.size() && vi < maxVec) {
                        SendChunk c = ss.sends.get(idx);
                        long cend = c.start + c.len;
                        if (cend <= cursor) {
                            idx++;
                            continue;
                        }
                        int off = (int) Math.max(0, cursor - c.start);
                        int n = c.len - off;
                        if (n <= 0) {
                            idx++;
                            continue;
                        }
                        st.sendVecs.set(openssl_h.C_POINTER, vi * VEC_SIZE + VEC_BASE,
                                c.segment.asSlice(off, n));
                        st.sendVecs.set(ValueLayout.JAVA_LONG, vi * VEC_SIZE + VEC_LEN, n);
                        vi++;
                        cursor += n;
                        idx++;
                    }
                    st.datalenSeg.set(ValueLayout.JAVA_LONG, 0, -1L);
                    int flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
                    boolean fin = ss.finQueued && ss.sentOffset >= ss.queuedOffset;
                    if (fin) {
                        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                    }
                    long n = (long) ngtcp2ConnWritevStream$handle.invokeExact(conn,
                            st.path, NGTCP2_PKT_INFO_V1, MemorySegment.NULL, dest,
                            destLen, st.datalenSeg, flags, ss.id, st.sendVecs,
                            (long) vi, now());
                    if (n > 0) {
                        long accepted = st.datalenSeg.get(ValueLayout.JAVA_LONG, 0);
                        if (accepted >= 0) {
                            ss.sentOffset += accepted;
                            if (fin && ss.sentOffset >= ss.queuedOffset) {
                                ss.finQueued = false;
                            }
                            while (ss.sendVecIndex < ss.sends.size()) {
                                SendChunk c = ss.sends.get(ss.sendVecIndex);
                                if (c.start + c.len > ss.sentOffset) {
                                    break;
                                }
                                ss.sendVecIndex++;
                            }
                        }
                        st.sendBlocked = false;
                        queueSend(st, ss);
                        updatePktTxTime(st.conn);
                        fillSendInfo(st, sendInfo);
                        return n;
                    }
                    if (n == 0) {
                        // No packet can be produced right now. ACKs for
                        // received data may still be pending, so fall
                        // through to the control-packet write before
                        // declaring the send pass done.
                        st.sendBlocked = true;
                        queueSend(st, ss);
                        break;
                    }
                    if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
                            n == NGTCP2_ERR_STREAM_NOT_FOUND) {
                        st.sendBlocked = true;
                        queueSend(st, ss);
                        continue;
                    }
                    if (n == NGTCP2_ERR_STREAM_SHUT_WR) {
                        ss.resetLocal = true;
                        continue;
                    }
                    noteError(st, (int) n);
                    return n;
                }
                if (st.sendQueue.isEmpty()) {
                    st.sendBlocked = false;
                }
            }

            // Control/handshake/ACK traffic.
            try {
                long n = (long) ngtcp2ConnWritePkt$handle.invokeExact(conn, st.path,
                        NGTCP2_PKT_INFO_V1, MemorySegment.NULL, dest, destLen, now());
                if (n > 0) {
                    updatePktTxTime(st.conn);
                    fillSendInfo(st, sendInfo);
                    return n;
                }
                if (n == 0) {
                    return NGTCP2_ERR_DONE;
                }
                // A negative write_pkt result is a real send-side failure
                // (crypto, protocol, internal state). Surface it instead of
                // collapsing it into DONE, or the connection would silently
                // stay live with output that can never be produced.
                noteError(st, (int) n);
                return n;
            } catch (Throwable t) {
                noteError(st, NGTCP2_ERR_CALLBACK_FAILURE);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        } catch (Throwable t) {
            noteError(st, NGTCP2_ERR_CALLBACK_FAILURE);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    private static long capacity(ConnState st, StreamState ss) {
        if (ss.resetLocal || ss.closed) {
            return -1;
        }
        if (!ss.nativeOpen) {
            return 65536;
        }
        long streamLeft = connMaxStreamDataLeft(st.conn, ss.id);
        long connLeft = connMaxDataLeft(st.conn);
        return Math.min(streamLeft, connLeft);
    }

    private static void fillSendInfo(ConnState st, MemorySegment sendInfo) {
        if (sendInfo == null || sendInfo.equals(MemorySegment.NULL)) {
            return;
        }
        // ngtcp2's write functions copy the connection's *current* path into
        // the path struct supplied to them (st.path), so use that rather than
        // the addresses captured at accept time: after client migration or a
        // path rebind the packets must go to the new peer address.
        MemorySegment local = st.path.get(openssl_h.C_POINTER, PATH_LOCAL_ADDR);
        int localLen = st.path.get(ValueLayout.JAVA_INT, PATH_LOCAL_LEN);
        MemorySegment remote = st.path.get(openssl_h.C_POINTER, PATH_REMOTE_ADDR);
        int remoteLen = st.path.get(ValueLayout.JAVA_INT, PATH_REMOTE_LEN);
        if (local == null || local.equals(MemorySegment.NULL) || localLen <= 0) {
            local = st.localSockaddr;
            localLen = st.localSockaddrLen;
        }
        if (remote == null || remote.equals(MemorySegment.NULL) || remoteLen <= 0) {
            remote = st.remoteSockaddr;
            remoteLen = st.remoteSockaddrLen;
        }
        MemorySegment.copy(local, 0, sendInfo, SEND_INFO_FROM, localLen);
        MemorySegment.copy(remote, 0, sendInfo, SEND_INFO_TO, remoteLen);
        sendInfo.set(ValueLayout.JAVA_INT, SEND_INFO_FROM_LEN, localLen);
        sendInfo.set(ValueLayout.JAVA_INT, SEND_INFO_TO_LEN, remoteLen);
    }

    static long ngtcp2_conn_stream_recv(MemorySegment conn, long id,
            MemorySegment dest, int destLen, MemorySegment finOut,
            MemorySegment errOut) {
        ConnState st = state(conn);
        if (st == null) {
            return NGTCP2_ERR_DONE;
        }
        StreamState ss = st.streams.get(Long.valueOf(id));
        if (ss == null) {
            return NGTCP2_ERR_DONE;
        }
        if (ss.resetRemote && !ss.resetRemoteDelivered) {
            // Once the reset has been surfaced the receiver is gone for this
            // direction; the buffered data can never be consumed and must not
            // keep the StreamState alive.
            dropBufferedReads(st, ss);
            ss.finReceived = true;
            ss.finDelivered = true;
            ss.resetRemoteDelivered = true;
            ss.readReported = false;
            tryReclaim(st, ss);
            return NGTCP2_ERR_STREAM_RESET;
        }
        if (ss.reads.isEmpty()) {
            if (ss.finReceived && !ss.finDelivered) {
                ss.finDelivered = true;
                ss.readReported = false;
                finOut.set(ValueLayout.JAVA_BOOLEAN, 0, true);
                return 0;
            }
            return NGTCP2_ERR_DONE;
        }
        ReadChunk chunk = ss.reads.peekFirst();
        int available = chunk.data.length - chunk.off;
        int n = Math.min(available, destLen);
        if (n > 0) {
            dest.asSlice(0, n).asByteBuffer().put(chunk.data, chunk.off, n);
            chunk.off += n;
        }
        boolean fin = false;
        if (chunk.off >= chunk.data.length) {
            ss.reads.pollFirst();
            if (chunk.fin) {
                fin = true;
                ss.finReceived = true;
                ss.finDelivered = true;
            }
        }
        if (ss.reads.isEmpty() && !(ss.finReceived && !ss.finDelivered)) {
            ss.readReported = false;
        }
        finOut.set(ValueLayout.JAVA_BOOLEAN, 0, fin);
        if (n > 0) {
            extendFlowControl(st, id, n);
        }
        if (ss.reads.isEmpty()) {
            tryReclaim(st, ss);
        }
        return n;
    }

    /**
     * Queues application bytes for a stream. The bytes are copied into a
     * transport-owned chunk that lives until the peer acknowledges them; the
     * caller's array is not retained, so callers on the poll thread do not
     * need an intermediate native copy.
     *
     * @param conn   The connection
     * @param id     The stream identifier
     * @param data   The source bytes (may be {@code null} when {@code len} is 0)
     * @param off    Offset of the first byte in {@code data}
     * @param len    Number of bytes to queue
     * @param fin    Whether this write concludes the stream
     * @param errOut Optional scratch for the native stream error code
     *
     * @return The number of bytes accepted, or a negative ngtcp2 error
     */
    static long ngtcp2_conn_stream_send(MemorySegment conn, long id,
            byte[] data, int off, int len, boolean fin, MemorySegment errOut) {
        ConnState st = state(conn);
        if (st == null) {
            return NGTCP2_ERR_STREAM_NOT_FOUND;
        }
        StreamState ss = st.streams.computeIfAbsent(Long.valueOf(id), StreamState::new);
        if (!ss.nativeOpen && (id & 3) == 3) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment out = arena.allocate(ValueLayout.JAVA_LONG);
                int rc = (int) ngtcp2ConnOpenUni$handle.invokeExact(st.conn, out,
                        MemorySegment.NULL);
                if (rc != 0) {
                    return rc;
                }
                long opened = out.get(ValueLayout.JAVA_LONG, 0);
                if (opened != id) {
                    // The endpoint's stream bookkeeping is keyed by the
                    // assumed id (3 + 4*index). Do not send data on a
                    // different native stream: record the opened stream so a
                    // retry does not open yet another one, then fail clearly.
                    st.streams.computeIfAbsent(Long.valueOf(opened),
                            StreamState::new).nativeOpen = true;
                    return NGTCP2_ERR_INVALID_STREAM_STATE;
                }
                ss = st.streams.computeIfAbsent(Long.valueOf(opened), StreamState::new);
                ss.nativeOpen = true;
            } catch (Throwable t) {
                return NGTCP2_ERR_INVALID_STREAM_STATE;
            }
        }
        if (ss.closed || ss.resetLocal) {
            return NGTCP2_ERR_STREAM_SHUT_WR;
        }
        if (len > 0) {
            try {
                // The normal send path runs on the poll thread, where a
                // confined arena avoids the per-close VM-wide thread
                // handshake that a shared arena incurs. Chunks created by the
                // stop-path drain on another thread use a shared arena so
                // they can be closed from any thread.
                Thread current = Thread.currentThread();
                boolean shared = current != st.ownerThread;
                Arena arena = shared ? Arena.ofShared() : Arena.ofConfined();
                MemorySegment seg = arena.allocate(len);
                seg.asByteBuffer().put(data, off, len);
                ss.sends.add(new SendChunk(arena, seg, ss.queuedOffset, len,
                        current, shared));
                ss.queuedOffset += len;
            } catch (Throwable t) {
                return NGTCP2_ERR_INVALID_STREAM_STATE;
            }
        }
        if (fin) {
            ss.finQueued = true;
        }
        st.sendBlocked = false;
        queueSend(st, ss);
        if (errOut != null && !errOut.equals(MemorySegment.NULL)) {
            errOut.set(ValueLayout.JAVA_LONG, 0, 0L);
        }
        return len;
    }

    /**
     * Convenience overload for the common write path, which does not need the
     * native stream error code.
     */
    static long ngtcp2_conn_stream_send(MemorySegment conn, long id,
            byte[] data, int off, int len, boolean fin) {
        return ngtcp2_conn_stream_send(conn, id, data, off, len, fin,
                MemorySegment.NULL);
    }

    static boolean ngtcp2_conn_has_pending_send(MemorySegment conn) {
        ConnState st = state(conn);
        return st != null && !st.closed &&
                (st.closeQueued || (!st.sendBlocked && !st.sendQueue.isEmpty()));
    }

    static long ngtcp2_conn_stream_capacity(MemorySegment conn, long id) {
        ConnState st = state(conn);
        if (st == null) {
            return -1;
        }
        StreamState ss = st.streams.computeIfAbsent(Long.valueOf(id), StreamState::new);
        return capacity(st, ss);
    }

    static boolean ngtcp2_conn_stream_finished(MemorySegment conn, long id) {
        ConnState st = state(conn);
        if (st == null) {
            return true;
        }
        StreamState ss = st.streams.get(Long.valueOf(id));
        return ss == null || (ss.reads.isEmpty() && ss.finDelivered);
    }

    static boolean ngtcp2_conn_stream_readable(MemorySegment conn, long id) {
        ConnState st = state(conn);
        if (st == null) {
            return false;
        }
        StreamState ss = st.streams.get(Long.valueOf(id));
        return ss != null && ss.readable();
    }

    static long ngtcp2_conn_stream_readable_next(MemorySegment conn) {
        ConnState st = state(conn);
        if (st == null) {
            return -1;
        }
        while (!st.readableQueue.isEmpty()) {
            StreamState ss = st.readableQueue.poll();
            ss.inReadQueue = false;
            if (ss.readReported || !ss.readable()) {
                tryReclaim(st, ss);
                continue;
            }
            ss.readReported = true;
            return ss.id;
        }
        return -1;
    }

    static int ngtcp2_conn_stream_shutdown(MemorySegment conn, long id,
            int direction, long errorCode) {
        ConnState st = state(conn);
        if (st == null) {
            return -1;
        }
        try {
            if (direction == NGTCP2_SHUTDOWN_READ) {
                // A READ shutdown (STOP_SENDING) closes only the receive
                // direction. It must not mark the write side terminal: the
                // response handler shuts the read direction down after it has
                // queued the final response bytes/FIN, and treating that as a
                // write reset would strand the FIN (the peer then waits for
                // the end of the response forever).
                return (int) ngtcp2ConnShutdownRead$handle.invokeExact(conn, 0, id,
                        errorCode);
            }
            StreamState ss = st.streams.get(Long.valueOf(id));
            if (ss != null) {
                ss.resetLocal = true;
                ss.inSendQueue = false;
                if (ss.closed) {
                    return 0;
                }
            }
            return (int) ngtcp2ConnShutdownWrite$handle.invokeExact(conn, 0, id,
                    errorCode);
        } catch (Throwable t) {
            return -1;
        }
    }

    /**
     * Re-points the connection's send path at the sockaddr copies owned by its
     * own connection arena.
     * <p>
     * {@code ngtcp2_conn_recv()} points {@code ConnState.path} at the
     * endpoint's loop-arena scratch (saFrom/saTo or a receive-batch slot), and
     * ngtcp2 copies the current path back into that struct during writes.
     * {@code unbind()} closes the loop arena, so a connection retained across a
     * stop/start (its handler outlived the stop) would otherwise keep dangling
     * local/remote address pointers and hand them to the next send pass. The
     * accept-time sockaddr copies live in the connection's own arena and stay
     * valid for its lifetime.
     *
     * @param conn The ngtcp2 connection
     */
    static void ngtcp2_conn_reset_path(MemorySegment conn) {
        ConnState st = state(conn);
        if (st == null) {
            return;
        }
        st.path.set(openssl_h.C_POINTER, PATH_LOCAL_ADDR, st.localSockaddr);
        st.path.set(ValueLayout.JAVA_INT, PATH_LOCAL_LEN, st.localSockaddrLen);
        st.path.set(openssl_h.C_POINTER, PATH_REMOTE_ADDR, st.remoteSockaddr);
        st.path.set(ValueLayout.JAVA_INT, PATH_REMOTE_LEN, st.remoteSockaddrLen);
    }

    static long ngtcp2_conn_timeout_as_millis(MemorySegment conn) {
        ConnState st = state(conn);
        if (st == null || st.closed) {
            return 0;
        }
        long expiry = connGetExpiry(conn);
        if (expiry == -1L) {
            return Long.MAX_VALUE;
        }
        long delta = expiry - now();
        return delta <= 0 ? 0 : delta / 1_000_000L;
    }

    static void ngtcp2_conn_on_timeout(MemorySegment conn) {
        ConnState st = state(conn);
        if (st == null || st.closed) {
            return;
        }
        try {
            int rc = (int) ngtcp2ConnHandleExpiry$handle.invokeExact(conn, now());
            st.sendBlocked = false;
            if (rc != 0) {
                noteError(st, rc);
            }
        } catch (Throwable t) {
            st.closed = true;
        }
    }

    static boolean ngtcp2_conn_is_established(MemorySegment conn) {
        ConnState st = state(conn);
        return st != null && connHandshakeCompleted(conn);
    }

    static boolean ngtcp2_conn_is_closed(MemorySegment conn) {
        ConnState st = state(conn);
        if (st != null && !st.peerErrorSet && !st.closeQueued &&
                (st.closed || connInClosing(conn))) {
            capturePeerError(st);
        }
        return st == null || st.closed || connInClosing(conn);
    }

    /**
     * Captures the peer's CONNECTION_CLOSE details on demand. Close detection
     * calls this through {@code ngtcp2_conn_is_closed()}, but a receive error
     * that puts ngtcp2 straight into DRAINING/CLOSING ({@code read_pkt}
     * returns {@code NGTCP2_ERR_DRAINING}) never reaches that path; the
     * endpoint calls this before reporting/tearing the connection down so the
     * peer's diagnostic code and reason are available.
     *
     * @param conn The ngtcp2 connection
     */
    static void ngtcp2_conn_capture_peer_error(MemorySegment conn) {
        ConnState st = state(conn);
        if (st != null && !st.peerErrorSet) {
            capturePeerError(st);
        }
    }

    private static void capturePeerError(ConnState st) {
        try {
            MemorySegment ccerr = (MemorySegment) ngtcp2ConnGetCcerr$handle
                    .invokeExact(st.conn);
            if (ccerr.equals(MemorySegment.NULL)) {
                return;
            }
            int type = ccerr.get(ValueLayout.JAVA_INT, CCERR_TYPE);
            if (type != CCERR_TYPE_TRANSPORT &&
                    type != CCERR_TYPE_APPLICATION) {
                return;
            }
            st.peerErrorApp = type == CCERR_TYPE_APPLICATION;
            st.peerErrorCode = ccerr.get(ValueLayout.JAVA_LONG, CCERR_ERROR_CODE);
            MemorySegment reason = ccerr.get(openssl_h.C_POINTER, CCERR_REASON);
            long len = ccerr.get(ValueLayout.JAVA_LONG, CCERR_REASONLEN);
            st.peerErrorReason = reason.equals(MemorySegment.NULL) || len <= 0 ?
                    null : reason.reinterpret(len).getString(0,
                            StandardCharsets.UTF_8);
            st.peerErrorSet = true;
        } catch (Throwable t) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to read ngtcp2 peer close error", t);
            }
        }
    }

    static boolean ngtcp2_conn_is_draining(MemorySegment conn) {
        ConnState st = state(conn);
        return st != null && (st.draining || connInDraining(conn));
    }

    static void ngtcp2_conn_close(MemorySegment conn, boolean app, long errorCode,
            MemorySegment reason, long reasonLen) {
        ConnState st = state(conn);
        if (st == null) {
            return;
        }
        st.closeQueued = true;
        st.closeApp = app;
        st.closeError = errorCode;
        if (reason != null && !reason.equals(MemorySegment.NULL) && reasonLen > 0) {
            st.closeReason = reason.reinterpret(reasonLen)
                    .getString(0, StandardCharsets.UTF_8);
        }
    }

    static long ngtcp2_conn_max_send_udp_payload_size(MemorySegment conn) {
        try {
            return connMaxTxPayload(conn);
        } catch (Throwable t) {
            return NGTCP2_MAX_UDP_PAYLOAD_SIZE;
        }
    }

    static void ngtcp2_conn_application_proto(MemorySegment conn, MemorySegment out,
            MemorySegment outLen) {
        ConnState st = state(conn);
        if (st == null) {
            out.set(openssl_h.C_POINTER, 0, MemorySegment.NULL);
            outLen.set(ValueLayout.JAVA_LONG, 0, 0L);
            return;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment len = arena.allocate(ValueLayout.JAVA_INT);
            QuicBindings.SSL_get0_alpn_selected(st.ssl, data, len);
            MemorySegment p = data.get(openssl_h.C_POINTER, 0);
            int n = len.get(ValueLayout.JAVA_INT, 0);
            if (p.equals(MemorySegment.NULL) || n == 0) {
                out.set(openssl_h.C_POINTER, 0, MemorySegment.NULL);
                outLen.set(ValueLayout.JAVA_LONG, 0, 0L);
                return;
            }
            byte[] bytes = p.reinterpret(n).toArray(ValueLayout.JAVA_BYTE);
            st.alpnData = st.arena.allocateFrom(new String(bytes,
                    StandardCharsets.US_ASCII));
            out.set(openssl_h.C_POINTER, 0, st.alpnData);
            outLen.set(ValueLayout.JAVA_LONG, 0, bytes.length);
        }
    }

    static void ngtcp2_conn_server_name(MemorySegment conn, MemorySegment out,
            MemorySegment outLen) {
        ConnState st = state(conn);
        if (st == null) {
            out.set(openssl_h.C_POINTER, 0, MemorySegment.NULL);
            outLen.set(ValueLayout.JAVA_LONG, 0, 0L);
            return;
        }
        MemorySegment p = QuicBindings.SSL_get_servername(st.ssl, 0);
        if (p.equals(MemorySegment.NULL)) {
            out.set(openssl_h.C_POINTER, 0, MemorySegment.NULL);
            outLen.set(ValueLayout.JAVA_LONG, 0, 0L);
            return;
        }
        String name = p.reinterpret(256).getString(0);
        st.sniData = st.arena.allocateFrom(name, StandardCharsets.US_ASCII);
        out.set(openssl_h.C_POINTER, 0, st.sniData);
        outLen.set(ValueLayout.JAVA_LONG, 0, name.length());
    }

    static boolean ngtcp2_conn_local_error(MemorySegment conn, MemorySegment isAppOut,
            MemorySegment codeOut, MemorySegment reasonOut,
            MemorySegment reasonLenOut) {
        ConnState st = state(conn);
        if (st == null || !st.lastErrorSet) {
            isAppOut.set(ValueLayout.JAVA_BOOLEAN, 0, false);
            return false;
        }
        isAppOut.set(ValueLayout.JAVA_BOOLEAN, 0, false);
        codeOut.set(ValueLayout.JAVA_LONG, 0, st.lastErrorCode);
        if (st.lastErrorReason != null) {
            st.errorReasonData = st.arena.allocateFrom(st.lastErrorReason,
                    StandardCharsets.UTF_8);
            reasonOut.set(openssl_h.C_POINTER, 0, st.errorReasonData);
            reasonLenOut.set(ValueLayout.JAVA_LONG, 0,
                    st.lastErrorReason.getBytes(StandardCharsets.UTF_8).length);
        } else {
            reasonOut.set(openssl_h.C_POINTER, 0, MemorySegment.NULL);
            reasonLenOut.set(ValueLayout.JAVA_LONG, 0, 0L);
        }
        return true;
    }

    static boolean ngtcp2_conn_peer_error(MemorySegment conn, MemorySegment isAppOut,
            MemorySegment codeOut, MemorySegment reasonOut,
            MemorySegment reasonLenOut) {
        ConnState st = state(conn);
        if (st == null || !st.peerErrorSet) {
            isAppOut.set(ValueLayout.JAVA_BOOLEAN, 0, false);
            return false;
        }
        isAppOut.set(ValueLayout.JAVA_BOOLEAN, 0, st.peerErrorApp);
        codeOut.set(ValueLayout.JAVA_LONG, 0, st.peerErrorCode);
        if (st.peerErrorReason != null) {
            st.peerReasonData = st.arena.allocateFrom(st.peerErrorReason,
                    StandardCharsets.UTF_8);
            reasonOut.set(openssl_h.C_POINTER, 0, st.peerReasonData);
            reasonLenOut.set(ValueLayout.JAVA_LONG, 0,
                    st.peerErrorReason.getBytes(StandardCharsets.UTF_8).length);
        } else {
            reasonOut.set(openssl_h.C_POINTER, 0, MemorySegment.NULL);
            reasonLenOut.set(ValueLayout.JAVA_LONG, 0, 0L);
        }
        return true;
    }

    static void ngtcp2_conn_free(MemorySegment conn) {
        ConnState st = state(conn);
        if (st == null) {
            return;
        }
        CONN_STATES.remove(Long.valueOf(conn.address()));
        TOKEN_STATES.remove(Long.valueOf(st.token.address()));
        for (StreamState ss : st.streams.values()) {
            for (SendChunk c : ss.sends) {
                closeSendChunk(c);
            }
        }
        try {
            sslSetExData(st.ssl, 0, MemorySegment.NULL);
            cryptoOsslCtxDel(st.osslCtx);
            openssl_h.SSL_free(st.ssl);
            ngtcp2ConnDel(conn);
        } finally {
            try {
                st.arena.close();
            } catch (Throwable t) {
                // Ignore
            }
        }
    }

    private static void extendMaxStreamsBidi(MemorySegment conn) {
        try {
            ngtcp2ConnExtendMaxStreamsBidi$handle.invokeExact(conn, 1L);
        } catch (Throwable t) {
            // Ignore: the peer will simply reopen after the next close.
        }
    }

    private static void extendFlowControl(ConnState st, long id, int n) {
        try {
            // The stream handle returns int; invokeExact must see that exact
            // return type or it throws WrongMethodTypeException (which the
            // old statement-form call did on every read, silently skipping
            // the stream-window extension).
            int rc = (int) ngtcp2ConnExtendMaxStreamOffset$handle.invokeExact(
                    st.conn, id, (long) n);
            if (rc != 0) {
                return;
            }
            ngtcp2ConnExtendMaxOffset$handle.invokeExact(st.conn, (long) n);
        } catch (Throwable t) {
            // Ignore: flow-control extension is best-effort here.
        }
    }


    /**
     * Drops the binding-side receive copy of a stream and returns its bytes to
     * the connection-level flow-control window.
     * <p>
     * Data queued in {@link StreamState#reads} has already been handed to the
     * application callback. ngtcp2's own stream close only compensates for
     * data still inside the native receive buffer
     * ({@code rx.last_offset - rx_offset}), so without this the peer's
     * {@code initial_max_data} credit for every Java-buffered byte would be
     * consumed permanently. Only the connection window is extended: the stream
     * is going away (discarded, rejected or reset), so stream-level credit
     * would be meaningless, and ngtcp2_conn_extend_max_stream_offset() can
     * fail for a stream already removed from the native map.
     *
     * @param st The connection state
     * @param ss The stream state whose buffered receive data is dropped
     */
    private static void dropBufferedReads(ConnState st, StreamState ss) {
        long unread = 0;
        for (ReadChunk chunk : ss.reads) {
            unread += chunk.data.length - chunk.off;
        }
        ss.reads.clear();
        if (unread > 0) {
            try {
                ngtcp2ConnExtendMaxOffset$handle.invokeExact(st.conn, unread);
            } catch (Throwable t) {
                // Ignore: flow-control extension is best-effort here.
            }
        }
    }

    private static void noteError(ConnState st, int rc) {
        st.lastErrorSet = true;
        st.lastErrorCode = rc;
        st.lastErrorReason = ngtcp2Strerror(rc);
        switch (rc) {
            case NGTCP2_ERR_DRAINING:
                st.draining = true;
                st.closed = true;
                break;
            case NGTCP2_ERR_CLOSING:
            case NGTCP2_ERR_DROP_CONN:
            case NGTCP2_ERR_IDLE_CLOSE:
            case NGTCP2_ERR_RETRY:
                st.closed = true;
                break;
            default:
                break;
        }
    }

    // -------------------------------------------------- callbacks

    private static MemorySegment upcall(String name, MethodType type,
            FunctionDescriptor descriptor) throws Exception {
        MethodHandle mh = MethodHandles.lookup().findStatic(Ngtcp2Bindings.class,
                name, type);
        return Linker.nativeLinker().upcallStub(mh, descriptor, CB_ARENA);
    }

    /*
     * Every upcall below is invoked from native code. A Throwable escaping
     * an FFM upcall terminates the JVM, so each body is wrapped and reports
     * NGTCP2_ERR_CALLBACK_FAILURE instead. Diagnostics are debug-level to keep
     * a remote-triggered failure from flooding the log.
     */
    private static int callbackFailure(String name, Throwable t) {
        if (log.isDebugEnabled()) {
            log.debug("ngtcp2 " + name + " callback failed", t);
        }
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    private static int recvStreamData(MemorySegment conn, int flags, long id,
            long offset, MemorySegment data, long datalen, MemorySegment userData,
            MemorySegment streamUserData) {
        try {
            ConnState st = stateFromUserData(userData);
            if (st == null) {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            StreamState ss = st.stream(Long.valueOf(id));
            ss.nativeOpen = true;
            byte[] bytes = datalen == 0 ? new byte[0] :
                    data.reinterpret(datalen).toArray(ValueLayout.JAVA_BYTE);
            boolean fin = (flags & 1) != 0;
            ss.reads.addLast(new ReadChunk(bytes, fin));
            ss.readReported = false;
            if (fin) {
                ss.finReceived = true;
            }
            queueRead(st, ss);
            return 0;
        } catch (Throwable t) {
            return callbackFailure("recvStreamData", t);
        }
    }

    private static int ackedStreamData(MemorySegment conn, long id, long offset,
            long datalen, MemorySegment userData, MemorySegment streamUserData) {
        try {
            ConnState st = stateFromUserData(userData);
            if (st == null) {
                return 0;
            }
            StreamState ss = st.stream(Long.valueOf(id));
            ss.ackedOffset = Math.max(ss.ackedOffset, offset + datalen);
            while (ss.ackIndex < ss.sends.size()) {
                SendChunk c = ss.sends.get(ss.ackIndex);
                if (c.start + c.len > ss.ackedOffset) {
                    break;
                }
                closeSendChunk(c);
                ss.ackIndex++;
            }
            if (ss.ackIndex > 0 &&
                    (ss.ackIndex >= 256 || ss.ackIndex >= ss.sends.size())) {
                ss.sends.subList(0, ss.ackIndex).clear();
                ss.sendVecIndex -= ss.ackIndex;
                ss.ackIndex = 0;
            }
            tryReclaim(st, ss);
            return 0;
        } catch (Throwable t) {
            return callbackFailure("ackedStreamData", t);
        }
    }

    private static int streamOpen(MemorySegment conn, long id,
            MemorySegment userData) {
        try {
            ConnState st = stateFromUserData(userData);
            if (st != null) {
                st.stream(Long.valueOf(id)).nativeOpen = true;
            }
            return 0;
        } catch (Throwable t) {
            return callbackFailure("streamOpen", t);
        }
    }

    private static int streamClose(MemorySegment conn, int flags, long id,
            long appErrorCode, MemorySegment userData, MemorySegment streamUserData) {
        try {
            ConnState st = stateFromUserData(userData);
            if (st != null) {
                StreamState ss = st.stream(Long.valueOf(id));
                ss.closed = true;
                if ((id & 0x03) == 0) {
                    // Recycle the client-initiated bidirectional stream credit.
                    // Without this the peer stops after initial_max_streams_bidi
                    // sequential requests (the default is 100), which looks like
                    // a connection stall at exactly the configured stream cap.
                    extendMaxStreamsBidi(conn);
                }
                // NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET only says that
                // an application error code was supplied - a locally generated
                // RESET_STREAM or STOP_SENDING sets it as well. A remote reset
                // is reported by the stream_reset callback, so never infer
                // resetRemote from the flags (or resurrect a reset that was
                // already delivered). The stream is fully closed here (both
                // directions), so make sure the receive side reports a
                // terminal edge: re-arm the FIN exactly once so a parked
                // reader or stream wrapper observes EOF and can complete,
                // instead of being left to wait for an event that will never
                // come. A remote reset keeps its own terminal path.
                if (!ss.resetRemote) {
                    ss.finReceived = true;
                    ss.finDelivered = false;
                }
                for (SendChunk c : ss.sends) {
                    closeSendChunk(c);
                }
                ss.sends.clear();
                ss.sendVecIndex = 0;
                ss.ackIndex = 0;
                ss.inSendQueue = false;
                if (ss.readable()) {
                    queueRead(st, ss);
                }
                tryReclaim(st, ss);
            }
            return 0;
        } catch (Throwable t) {
            return callbackFailure("streamClose", t);
        }
    }

    private static int streamReset(MemorySegment conn, long id, long finalSize,
            long appErrorCode, MemorySegment userData, MemorySegment streamUserData) {
        try {
            ConnState st = stateFromUserData(userData);
            if (st != null) {
                StreamState ss = st.stream(Long.valueOf(id));
                ss.resetRemote = true;
                ss.resetRemoteDelivered = false;
                ss.readReported = false;
                queueRead(st, ss);
            }
            return 0;
        } catch (Throwable t) {
            return callbackFailure("streamReset", t);
        }
    }

    private static int streamStopSending(MemorySegment conn, long id,
            long appErrorCode, MemorySegment userData, MemorySegment streamUserData) {
        try {
            // This callback reports a *local* read shutdown (ngtcp2 invokes it
            // when it emits STOP_SENDING), not a peer reset of our send side.
            // The write side is independent: a bidirectional stream whose
            // handler shut the read direction down may still have response
            // bytes/FIN queued in ss.sends, and marking resetLocal here would
            // make capacity()/hasWritable() reject them and truncate the
            // response. The receive copy is discarded separately by
            // ngtcp2_conn_discard_stream() (with the connection-level flow
            // control credit returned there), so this callback has nothing to
            // do.
            return 0;
        } catch (Throwable t) {
            return callbackFailure("streamStopSending", t);
        }
    }

    private static void randBytes(MemorySegment dest, long destlen,
            MemorySegment randCtx) {
        try {
            if (destlen <= 0 || dest.equals(MemorySegment.NULL)) {
                return;
            }
            // Fill the whole requested buffer (the contract has no upper
            // bound); chunk the generation so a future larger request cannot
            // allocate an unbounded temporary array.
            long off = 0;
            while (off < destlen) {
                int n = (int) Math.min(destlen - off, 1088L);
                byte[] bytes = new byte[n];
                RANDOM.nextBytes(bytes);
                dest.asSlice(off, n).asByteBuffer().put(bytes);
                off += n;
            }
        } catch (Throwable t) {
            // A void upcall cannot report failure; never let it escape.
            callbackFailure("randBytes", t);
        }
    }

    private static int getNewConnectionId(MemorySegment conn, MemorySegment cid,
            MemorySegment token, long cidlen, MemorySegment userData) {
        try {
            if (cidlen <= 0 || cidlen > NGTCP2_MAX_CONN_ID_LEN) {
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            byte[] id = new byte[(int) cidlen];
            byte[] reset = new byte[NGTCP2_STATELESS_RESET_TOKENLEN];
            RANDOM.nextBytes(id);
            RANDOM.nextBytes(reset);
            cid.set(ValueLayout.JAVA_LONG, 0, cidlen);
            cid.asSlice(CID_DATA, cidlen).asByteBuffer().put(id);
            token.reinterpret(NGTCP2_STATELESS_RESET_TOKENLEN).asByteBuffer().put(reset);
            Ngtcp2ConnectionWrapper wrapper = wrapper(stateFromUserData(userData));
            if (wrapper != null && wrapper.getEndpoint() != null) {
                wrapper.getEndpoint().registerCid(id, wrapper);
            }
            return 0;
        } catch (Throwable t) {
            return callbackFailure("getNewConnectionId", t);
        }
    }

    private static int removeConnectionId(MemorySegment conn, MemorySegment cid,
            MemorySegment userData) {
        try {
            Ngtcp2ConnectionWrapper wrapper = wrapper(stateFromUserData(userData));
            if (wrapper != null && wrapper.getEndpoint() != null) {
                long len = cid.get(ValueLayout.JAVA_LONG, CID_DATALEN);
                if (len > 0 && len <= NGTCP2_MAX_CONN_ID_LEN) {
                    byte[] id = cid.asSlice(CID_DATA, len).toArray(ValueLayout.JAVA_BYTE);
                    wrapper.getEndpoint().removeCid(id);
                }
            }
            return 0;
        } catch (Throwable t) {
            return callbackFailure("removeConnectionId", t);
        }
    }

    private static MemorySegment getConn(MemorySegment connRef) {
        try {
            return connRef.get(openssl_h.C_POINTER, CONN_REF_USER_DATA);
        } catch (Throwable t) {
            callbackFailure("getConn", t);
            return MemorySegment.NULL;
        }
    }

    // -------------------------------------------------- native wrappers

    private static void ngtcp2SettingsDefault(int version, MemorySegment settings) {
        try {
            ngtcp2SettingsDefault$handle.invokeExact(version, settings);
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    private static void ngtcp2TransportParamsDefault(int version, MemorySegment params) {
        try {
            ngtcp2TransportParamsDefault$handle.invokeExact(version, params);
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    private static int ngtcp2ConnServerNew(MemorySegment out, MemorySegment dcid,
            MemorySegment scid, MemorySegment path, int version,
            MemorySegment settings, MemorySegment params, MemorySegment token) {
        try {
            return (int) ngtcp2ConnServerNew$handle.invokeExact(out, dcid, scid, path,
                    version, NGTCP2_CALLBACKS_V2, CALLBACKS,
                    NGTCP2_SETTINGS_V3, settings,
                    NGTCP2_TRANSPORT_PARAMS_V1, params,
                    MemorySegment.NULL, token);
        } catch (Throwable t) {
            return -1;
        }
    }

    private static void ngtcp2ConnDel(MemorySegment conn) {
        try {
            ngtcp2ConnDel$handle.invokeExact(conn);
        } catch (Throwable t) {
            // Ignore
        }
    }

    private static void ngtcp2ConnSetTlsNative(MemorySegment conn,
            MemorySegment osslCtx) {
        try {
            ngtcp2ConnSetTlsNative$handle.invokeExact(conn, osslCtx);
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    private static void cryptoOsslCtxDel(MemorySegment ctx) {
        try {
            cryptoOsslCtxDel$handle.invokeExact(ctx);
        } catch (Throwable t) {
            // Ignore
        }
    }

    private static void sslSetExData(MemorySegment ssl, int idx, MemorySegment data) {
        try {
            sslSetExData$handle.invokeExact(ssl, idx, data);
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    private static void updatePktTxTime(MemorySegment conn) {
        try {
            ngtcp2ConnUpdatePktTxTime$handle.invokeExact(conn, now());
        } catch (Throwable t) {
            // Ignore: pacing is an optimisation; timers are still driven by
            // ngtcp2_conn_get_expiry.
        }
    }

    private static long connGetExpiry(MemorySegment conn) {
        try {
            long v = (long) ngtcp2ConnGetExpiry$handle.invokeExact(conn);
            return v == -1L ? -1L : v;
        } catch (Throwable t) {
            return -1L;
        }
    }

    private static long connMaxStreamDataLeft(MemorySegment conn, long id) {
        try {
            return (long) ngtcp2ConnMaxStreamDataLeft$handle.invokeExact(conn, id);
        } catch (Throwable t) {
            return 0;
        }
    }

    private static long connMaxDataLeft(MemorySegment conn) {
        try {
            return (long) ngtcp2ConnMaxDataLeft$handle.invokeExact(conn);
        } catch (Throwable t) {
            return 0;
        }
    }

    private static long connMaxTxPayload(MemorySegment conn) {
        try {
            return (long) ngtcp2ConnMaxTxPayload$handle.invokeExact(conn);
        } catch (Throwable t) {
            return NGTCP2_MAX_UDP_PAYLOAD_SIZE;
        }
    }

    private static boolean connHandshakeCompleted(MemorySegment conn) {
        try {
            return (int) ngtcp2ConnHandshakeCompleted$handle.invokeExact(conn) != 0;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean connInClosing(MemorySegment conn) {
        try {
            return (int) ngtcp2ConnInClosing$handle.invokeExact(conn) != 0;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean connInDraining(MemorySegment conn) {
        try {
            return (int) ngtcp2ConnInDraining$handle.invokeExact(conn) != 0;
        } catch (Throwable t) {
            return false;
        }
    }

    private static void ngtcp2CcerrDefault(MemorySegment ccerr) {
        try {
            ngtcp2CcerrDefault$handle.invokeExact(ccerr);
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    private static void ngtcp2CcerrSetApp(MemorySegment ccerr, long code,
            MemorySegment reason, long reasonLen) {
        try {
            ngtcp2CcerrSetApp$handle.invokeExact(ccerr, code, reason, reasonLen);
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    private static void ngtcp2CcerrSetTransport(MemorySegment ccerr, long code,
            MemorySegment reason, long reasonLen) {
        try {
            ngtcp2CcerrSetTransport$handle.invokeExact(ccerr, code, reason, reasonLen);
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    // -------------------------------------------------- symbol helpers

    private static MethodHandle createHandle(String symbol, FunctionDescriptor desc) {
        try {
            if (NGTCP2_LOOKUP == null) {
                throw new UnsatisfiedLinkError("libngtcp2 not loaded");
            }
            MemorySegment addr = NGTCP2_LOOKUP.find(symbol)
                    .orElseThrow(() -> new UnsatisfiedLinkError(
                            "unresolved ngtcp2 symbol: " + symbol));
            return Linker.nativeLinker().downcallHandle(addr, desc);
        } catch (Throwable e) {
            MISSING_SYMBOLS.add(symbol);
            return null;
        }
    }

    private static MethodHandle createCryptoHandle(String symbol, FunctionDescriptor desc) {
        try {
            if (CRYPTO_LOOKUP == null) {
                throw new UnsatisfiedLinkError("libngtcp2_crypto_ossl not loaded");
            }
            MemorySegment addr = CRYPTO_LOOKUP.find(symbol)
                    .orElseThrow(() -> new UnsatisfiedLinkError(
                            "unresolved ngtcp2 crypto symbol: " + symbol));
            return Linker.nativeLinker().downcallHandle(addr, desc);
        } catch (Throwable e) {
            MISSING_SYMBOLS.add(symbol);
            return null;
        }
    }

    private static MethodHandle createSslHandle(String symbol, FunctionDescriptor desc) {
        try {
            MemorySegment addr = openssl_h.SYMBOL_LOOKUP.find(symbol)
                    .orElseThrow(() -> new UnsatisfiedLinkError(
                            "unresolved OpenSSL symbol: " + symbol));
            return Linker.nativeLinker().downcallHandle(addr, desc);
        } catch (Throwable e) {
            MISSING_SYMBOLS.add(symbol);
            return null;
        }
    }

    private static MemorySegment cryptoAddress(String symbol) {
        try {
            if (CRYPTO_LOOKUP == null) {
                throw new UnsatisfiedLinkError("libngtcp2_crypto_ossl not loaded");
            }
            return CRYPTO_LOOKUP.find(symbol).orElseThrow(
                    () -> new UnsatisfiedLinkError("unresolved crypto symbol: " + symbol));
        } catch (Throwable e) {
            MISSING_SYMBOLS.add(symbol);
            return MemorySegment.NULL;
        }
    }


    // -------------------------------------------------- Struct layouts

    /**
     * Internal receive-path helper layout for this binding's
     * {@code ngtcp2_conn_recv} wrapper:
     * {@code { sockaddr* from; socklen_t from_len; sockaddr* to; socklen_t
     * to_len; }}. It is not a public ngtcp2 1.16 type (1.16 uses
     * {@code ngtcp2_path} with inline storage); Linux LP64: 32 bytes with
     * 8-byte alignment padding after each socklen_t.
     */
    static final MemoryLayout RECV_INFO_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.ADDRESS.withName("from"),
            ValueLayout.JAVA_INT.withName("from_len"),
            MemoryLayout.paddingLayout(4),
            ValueLayout.ADDRESS.withName("to"),
            ValueLayout.JAVA_INT.withName("to_len"),
            MemoryLayout.paddingLayout(4)).withName("ngtcp2_recv_info");

    static final long RECV_INFO_SIZE = RECV_INFO_LAYOUT.byteSize();

    static final long RECV_INFO_FROM = RECV_INFO_LAYOUT.byteOffset(PathElement.groupElement("from"));
    static final long RECV_INFO_FROM_LEN = RECV_INFO_LAYOUT.byteOffset(PathElement.groupElement("from_len"));
    static final long RECV_INFO_TO = RECV_INFO_LAYOUT.byteOffset(PathElement.groupElement("to"));
    static final long RECV_INFO_TO_LEN = RECV_INFO_LAYOUT.byteOffset(PathElement.groupElement("to_len"));

    /**
     * Internal send-path helper layout for this binding's
     * {@code ngtcp2_conn_send} wrapper: {@code { struct sockaddr_storage
     * from(128); socklen_t from_len; struct sockaddr_storage to(128); socklen_t
     * to_len; struct timespec at; }}. It is not a public ngtcp2 1.16 type.
     * Linux LP64: 288 bytes (from at 0, from_len at 128, to at 136, to_len at
     * 264, at at 272).
     */
    static final MemoryLayout SEND_INFO_LAYOUT = MemoryLayout.structLayout(
            MemoryLayout.sequenceLayout(128, ValueLayout.JAVA_BYTE).withName("from"),
            ValueLayout.JAVA_INT.withName("from_len"),
            MemoryLayout.paddingLayout(4),
            MemoryLayout.sequenceLayout(128, ValueLayout.JAVA_BYTE).withName("to"),
            ValueLayout.JAVA_INT.withName("to_len"),
            MemoryLayout.paddingLayout(4),
            MemoryLayout.structLayout(ValueLayout.JAVA_LONG.withName("tv_sec"),
                    ValueLayout.JAVA_LONG.withName("tv_nsec")).withName("at")).withName("ngtcp2_send_info");

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
    // Linux SOCK_CLOEXEC == O_CLOEXEC. Every UDP socket is created with it so
    // an exec() in the JVM cannot inherit the QUIC listener (the eventfd is
    // already created with EFD_CLOEXEC).
    static final int SOCK_CLOEXEC = 0x80000;

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
    static final MethodHandle recvmmsg$handle = createOptionalLibcHandle("recvmmsg",
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
                // Preserve the arrival interface as sin6_scope_id: ngtcp2
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
     * Enforces the sockaddr contract of every ngtcp2 entry point that takes
     * one: ngtcp2's {@code std_addr_from_c} asserts the exact per-family
     * length (16 for {@code sockaddr_in}, 28 for {@code sockaddr_in6}) and
     * reaches {@code unimplemented!()} for any other family (ngtcp2 1.16
     * src/ffi.rs) - a violation never returns from the native call, it
     * panics and aborts the JVM from the poll thread. Every sockaddr/length
     * pair crossing into a ngtcp2 call is checked here first so a future
     * producer regression (a partial length, a foreign family, a length
     * that no longer matches the stored family) surfaces as an ordinary
     * catchable Java exception instead of a dead process. The expected
     * length is re-derived from the stored family here - deliberately not
     * via {@link #sockaddrLength(MemorySegment)} - so a regression in that
     * helper cannot certify its own mistake.
     *
     * @param sa  The sockaddr about to be passed to ngtcp2
     * @param len The length about to be passed alongside it
     *
     * @throws IllegalArgumentException If the pair would violate the ngtcp2
     *         contract (a NULL address with a non-zero length, a foreign
     *         family, or a length that does not match the stored family)
     */
    static void requireSockaddrContract(MemorySegment sa, int len) {
        int expected;
        if (sa.equals(MemorySegment.NULL)) {
            // ngtcp2 maps a NULL sockaddr to "no address" before it ever
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
                    "Address family " + family + " would abort the JVM in ngtcp2's std_addr_from_c");
        }
        if (len != expected) {
            throw new IllegalArgumentException("sockaddr length " + len +
                    " does not match the exact length " + expected +
                    " ngtcp2 asserts for its stored family");
        }
    }


    /**
     * Creates a downcall handle for a libc symbol.
     */
    private static MethodHandle createLibcHandle(String symbol, FunctionDescriptor desc) {
        try {
            MemorySegment addr = Linker.nativeLinker().defaultLookup().find(symbol)
                    .or(() -> NGTCP2_LOOKUP == null ? java.util.Optional.empty() :
                            NGTCP2_LOOKUP.find(symbol))
                    .orElseThrow(() -> new UnsatisfiedLinkError(
                            "unresolved libc symbol: " + symbol));
            return Linker.nativeLinker().downcallHandle(addr, desc);
        } catch (Throwable e) {
            MISSING_SYMBOLS.add(symbol);
            return null;
        }
    }


    /**
     * Like {@link #createLibcHandle(String, FunctionDescriptor)} but for
     * optional symbols (e.g. {@code recvmmsg}, absent on some libcs): a
     * missing symbol yields a {@code null} handle and the caller uses its
     * documented fallback instead of disabling the whole transport.
     */
    private static MethodHandle createOptionalLibcHandle(String symbol,
            FunctionDescriptor desc) {
        try {
            MemorySegment addr = Linker.nativeLinker().defaultLookup().find(symbol)
                    .or(() -> NGTCP2_LOOKUP == null ? java.util.Optional.empty() :
                            NGTCP2_LOOKUP.find(symbol))
                    .orElseThrow(() -> new UnsatisfiedLinkError(
                            "unresolved libc symbol: " + symbol));
            return Linker.nativeLinker().downcallHandle(addr, desc);
        } catch (Throwable e) {
            return null;
        }
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


    /**
     * Receives a probe datagram, polling the socket for readability between
     * attempts. A single non-blocking {@code recvmsg()} immediately after the
     * send can race the loopback delivery and report {@code EAGAIN}, which
     * would permanently disable an otherwise supported GSO/GRO path for the
     * whole JVM. The bounded poll loop (10 x 50 ms) makes the probe verdict
     * reliable without delaying class initialisation when the datagram
     * arrives immediately.
     *
     * @return The received length, or {@code -1} if no datagram arrived
     */
    private static long recvProbeDatagram(Arena arena, int fd, MemorySegment rbuf,
            int len, MemorySegment scratch, MemorySegment from, MemorySegment to,
            MemorySegment toLen, int[] segOut) {
        // struct pollfd { int fd; short events; short revents; } on Linux LP64.
        MemorySegment pfd = arena.allocate(8);
        for (int attempt = 0; attempt < 10; attempt++) {
            long r = recvDatagram(fd, rbuf, len, scratch, from, to, toLen, segOut);
            if (r >= 0) {
                return r;
            }
            if (errno() != EAGAIN) {
                return r;
            }
            pfd.set(ValueLayout.JAVA_INT, 0, fd);
            pfd.set(ValueLayout.JAVA_SHORT, 4, (short) 1);
            pfd.set(ValueLayout.JAVA_SHORT, 6, (short) 0);
            int p = poll(pfd, 1, 50);
            if (p < 0 && errno() != EINTR) {
                return r;
            }
        }
        return -1;
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
                plain = socket(AF_INET,
                        SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                groSock = socket(AF_INET,
                        SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                tx = socket(AF_INET,
                        SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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
                        long r = recvProbeDatagram(a, plain, rbuf, 4096, scratch,
                                from, to, toLen, segOut);
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
                                r = recvProbeDatagram(a, groSock, rbuf, 4096,
                                        scratch, from, to, toLen, segOut);
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


    /*
     * The required libc downcalls (socket/bind/sendmsg/recvmsg/close, errno,
     * eventfd, poll, ...) are created after the early availability decision
     * above. A missing one is added to MISSING_SYMBOLS by createLibcHandle();
     * re-check here, after every handle has been resolved, so the transport
     * reports unavailable instead of failing later with an AssertionError or
     * NPE in the poll loop / bind path.
     */
    static {
        if (NGTCP2_AVAILABLE && !MISSING_SYMBOLS.isEmpty()) {
            NGTCP2_AVAILABLE = false;
        }
    }
}

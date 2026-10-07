/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http3;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Assume;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;

/**
 * Base class for HTTP/3 tests.
 *
 * <p>HTTP/3 (RFC 9114) runs over QUIC (RFC 9000) on UDP, unlike HTTP/2 which
 * runs over TCP. A raw socket test client, such as the one used by
 * {@code org.apache.coyote.http2.Http2TestBase}, is not an option because a
 * full QUIC implementation is required on the client side. Instead, these
 * tests drive an external client: the aioquic (Python) based
 * {@code http3_client.py} script is started as a subprocess and its
 * machine readable output is asserted on.
 *
 * <p>The tests are skipped (via {@link Assume}) unless the environment
 * provides an OpenSSL that offers the QUIC APIs (see
 * {@link #isQuicSupported()}) and the test certificate. Tests that use the
 * aioquic probe client additionally skip unless {@code python3} on the PATH
 * (override with the {@code http3.python} system property), the
 * {@code aioquic} Python package and the client script (override with the
 * {@code http3.client.script} system property) are available; that check is
 * made when the client is invoked, so tests using another client (e.g. the
 * JDK 26 HttpClient, see {@code TestHttp3JdkHttpClient}) run without
 * aioquic.</p>
 */
public abstract class Http3TestBase extends TomcatBaseTest {

    /**
     * The Python interpreter used to run the client script.
     */
    protected static final String PYTHON = System.getProperty("http3.python",
            "python3");

    /**
     * The aioquic based client script.
     */
    protected static final String CLIENT_SCRIPT = System.getProperty(
            "http3.client.script",
            "test/org/apache/coyote/http3/http3_client.py");

    /**
     * A PKCS12 keystore that holds the standard test certificate. The QUIC
     * endpoint can also load PEM files (key and chain supplied separately)
     * and Java keystores; this default uses PKCS12 because the client script
     * consumes the same file.
     */
    protected static final String KEYSTORE = System.getProperty("http3.keystore",
            "test/org/apache/coyote/http3/localhost-rsa.p12");

    protected static final String KEYSTORE_PASSWORD = "changeit";

    /*
     * Whether the OpenSSL library linked into this JVM provides the QUIC
     * APIs. Evaluated the same way as the OPENSSL4 flag of the
     * openssl_h_Compatibility class: the linked OpenSSL must export the
     * QUIC specific OSSL_QUIC_method symbol. Read reflectively because the
     * FFM based bindings live in a separate compilation pass and may be
     * absent from the test classpath.
     */
    private static final boolean QUIC_AVAILABLE = isOpensslQuicAvailable();

    /*
     * The HTTP/3 protocol class selected for the tests with the
     * tomcat.test.http3.protocol property (set by the build when running
     * the quiche flavour of the suite; see the test.quiche flag). The
     * OpenSSL protocol is the default.
     */
    private static final String OPENSSL_PROTOCOL_CLASS =
            Http3OpenSSLProtocol.class.getName();

    private static final String QUICHE_PROTOCOL_CLASS =
            Http3QuicheProtocol.class.getName();

    private static final String PROTOCOL_CLASS = System.getProperty(
            "tomcat.test.http3.protocol", OPENSSL_PROTOCOL_CLASS);

    private static final boolean QUICHE_SELECTED =
            QUICHE_PROTOCOL_CLASS.equals(PROTOCOL_CLASS);

    /*
     * Whether the quiche FFM bindings compiled and found a loadable
     * libquiche with the required symbols. Evaluated reflectively via the
     * endpoint's isAvailable() convention for the same reason as
     * QUIC_AVAILABLE above.
     */
    private static final boolean QUICHE_AVAILABLE = checkQuicheAvailable();

    private static boolean checkQuicheAvailable() {
        try {
            return (boolean) Class.forName(
                            "org.apache.tomcat.util.net.quic.quiche.QuicheEndpoint")
                    .getMethod("isAvailable").invoke(null);
        } catch (ReflectiveOperationException | LinkageError e) {
            // FFM bindings not compiled or no libquiche available
            return false;
        }
    }

    /*
     * PEM files used as the default host certificate when the quiche
     * endpoint is in use: the quiche phase-1 configuration is PEM file
     * based (keystore sources are a later phase).
     */
    protected static final String QUICHE_TEST_CERT_FILE = System.getProperty(
            "http3.quiche.cert",
            "test/org/apache/coyote/http3/quic-default-cert.pem");

    protected static final String QUICHE_TEST_KEY_FILE = System.getProperty(
            "http3.quiche.key",
            "test/org/apache/coyote/http3/quic-default-key.pem");

    /**
     * HTTP/3 error codes (RFC 9114 Section 8.1, RFC 9204 Section 8.3).
     */
    protected static final int H3_NO_ERROR = 0x100;
    protected static final int H3_STREAM_CREATION_ERROR = 0x103;
    protected static final int H3_CLOSED_CRITICAL_STREAM = 0x104;
    protected static final int H3_FRAME_UNEXPECTED = 0x105;
    protected static final int H3_FRAME_ERROR = 0x106;
    protected static final int H3_EXCESSIVE_LOAD = 0x107;
    protected static final int H3_ID_ERROR = 0x108;
    protected static final int H3_SETTINGS_ERROR = 0x109;
    protected static final int H3_REQUEST_REJECTED = 0x10B;
    protected static final int H3_REQUEST_INCOMPLETE = 0x10D;
    protected static final int H3_MESSAGE_ERROR = 0x10E;
    protected static final int H3_QPACK_DECOMPRESSION_FAILED = 0x200;
    protected static final int H3_QPACK_ENCODER_STREAM_ERROR = 0x201;
    protected static final int H3_QPACK_DECODER_STREAM_ERROR = 0x202;

    /**
     * Default timeout, in seconds, for a single client invocation.
     */
    protected static final long CLIENT_TIMEOUT_SECONDS = 30;

    /**
     * The UDP port that the HTTP/3 connector is listening on.
     */
    protected int port;

    /**
     * The started HTTP/3 connector.
     */
    protected Connector connector;


    /**
     * Start an HTTP/3 connector on the embedded Tomcat instance and deploy
     * the standard test servlets.
     *
     * @return the started connector
     *
     * @throws Exception if the server fails to start
     */
    protected Connector startHttp3Server() throws Exception {
        return startHttp3Server(defaultTestHostConfig());
    }


    /**
     * Start an HTTP/3 connector on the embedded Tomcat instance with the
     * given SSL host configurations and deploy the standard test servlets.
     *
     * @param sslHostConfigs the SSL host configurations to use
     * @return the started connector
     *
     * @throws Exception if the server fails to start
     */
    protected Connector startHttp3Server(SSLHostConfig... sslHostConfigs)
            throws Exception {
        return startHttp3Server(null, sslHostConfigs);
    }


    /**
     * Start an HTTP/3 connector on the embedded Tomcat instance, secured
     * with the standard test keystore, and deploy the standard test
     * servlets.
     *
     * @param servletConfigurer a callback that can register additional
     *            servlets (and mappings) on the root context after the
     *            standard test servlets have been registered and before the
     *            server is started; may be {@code null}
     * @return the started connector
     *
     * @throws Exception if the server fails to start
     */
    protected Connector startHttp3Server(Consumer<Context> servletConfigurer)
            throws Exception {
        return startHttp3Server(servletConfigurer, defaultTestHostConfig());
    }


    /**
     * Start an HTTP/3 connector on the embedded Tomcat instance with the
     * given SSL host configurations and deploy the standard test servlets.
     *
     * @param servletConfigurer a callback that can register additional
     *            servlets (and mappings) on the root context after the
     *            standard test servlets have been registered and before the
     *            server is started; may be {@code null}
     * @param sslHostConfigs the SSL host configurations to use
     * @return the started connector
     *
     * @throws Exception if the server fails to start
     */
    protected Connector startHttp3Server(Consumer<Context> servletConfigurer,
            SSLHostConfig... sslHostConfigs) throws Exception {
        // The probe client requirement is checked when it is actually
        // invoked (see runClient), so tests using another client can start
        // the server without aioquic.
        assumeQuicEndpointAvailable();

        Tomcat tomcat = getTomcatInstance();

        // The QUIC endpoint does not (yet) support ephemeral ports, so pick
        // a free UDP port explicitly.
        port = findFreeUdpPort();

        connector = newHttp3Connector(port, sslHostConfigs);

        tomcat.setConnector(connector);

        Context ctxt = getProgrammaticRootContext();
        Tomcat.addServlet(ctxt, "simple", new SimpleServlet());
        ctxt.addServletMapping("/simple", "simple");
        Tomcat.addServlet(ctxt, "echo", new EchoServlet());
        ctxt.addServletMapping("/echo", "echo");
        Tomcat.addServlet(ctxt, "echoMethod", new EchoMethodServlet());
        ctxt.addServletMapping("/echoMethod", "echoMethod");
        Tomcat.addServlet(ctxt, "remote", new RemoteAddrServlet());
        ctxt.addServletMapping("/remote", "remote");
        Tomcat.addServlet(ctxt, "large", new LargeServlet());
        ctxt.addServletMapping("/large", "large");
        Tomcat.addServlet(ctxt, "trailers", new TrailersServlet());
        ctxt.addServletMapping("/trailers", "trailers");
        Tomcat.addServlet(ctxt, "trailersInvalid", new TrailersInvalidServlet());
        ctxt.addServletMapping("/trailersInvalid", "trailersInvalid");
        Tomcat.addServlet(ctxt, "earlyHints", new EarlyHintsServlet());
        ctxt.addServletMapping("/earlyHints", "earlyHints");
        Tomcat.addServlet(ctxt, "sleep", new SleepServlet());
        ctxt.addServletMapping("/sleep", "sleep");

        if (servletConfigurer != null) {
            servletConfigurer.accept(ctxt);
        }

        tomcat.start();
        return connector;
    }


    /**
     * Checks whether the OpenSSL library linked into this JVM provides the
     * QUIC APIs, using the availability flag maintained by the
     * openssl_h_Compatibility class.
     *
     * @return  {@code true} if OpenSSL QUIC support is available, otherwise
     *          {@code false}
     */
    private static boolean isOpensslQuicAvailable() {
        try {
            return Class.forName(
                    "org.apache.tomcat.util.openssl.openssl_h_Compatibility")
                    .getField("OPENSSL4").getBoolean(null);
        } catch (ReflectiveOperationException | LinkageError e) {
            // FFM bindings not compiled or no OpenSSL library available
            return false;
        }
    }


    /**
     * Checks whether the QUIC transport selected for this test run (see
     * {@link #PROTOCOL_CLASS}) is usable: the OpenSSL QUIC endpoint for the
     * OpenSSL protocol, the quiche endpoint for the quiche protocol.
     *
     * @return  {@code true} if QUIC support is available, otherwise
     *          {@code false}
     */
    protected static boolean isQuicSupported() {
        if (QUICHE_SELECTED) {
            // No cross-transport fallback: tests skip when the selected
            // quiche endpoint is not usable, even if OpenSSL QUIC would be.
            return QUICHE_AVAILABLE;
        }
        return QUIC_AVAILABLE;
    }


    /**
     * Whether the QUIC transport that the connector will use is the quiche
     * endpoint: the case when the quiche protocol class is selected with the
     * {@code tomcat.test.http3.protocol} property. Tests that depend on
     * OpenSSL endpoint specifics (SNI/multi-certificate hosts, keystore
     * sources) use this to skip.
     *
     * @return {@code true} if the quiche endpoint is in use
     */
    protected static boolean endpointIsQuiche() {
        return QUICHE_SELECTED;
    }


    /**
     * Creates an instance of the HTTP/3 protocol class selected for this
     * test run, for tests that exercise the protocol without a connector.
     *
     * @return The new protocol instance
     */
    protected static AbstractHttp3Protocol newHttp3Protocol() {
        if (QUICHE_SELECTED) {
            return new Http3QuicheProtocol();
        }
        return new Http3OpenSSLProtocol();
    }


    /**
     * Whether the endpoint in use supports per-SNI hosts and
     * multi-certificate default hosts. The quiche phase-1 configuration
     * carries a single default-host PEM certificate.
     *
     * @return {@code true} if SNI and multi-certificate hosts are supported
     */
    protected static boolean endpointSupportsSni() {
        return !endpointIsQuiche();
    }


    /**
     * SSLHostConfig for the default host carrying the standard test
     * certificate: the PKCS12 keystore for the OpenSSL endpoint, the PEM
     * leaf/key pair for the quiche endpoint (whose phase-1 configuration
     * loads credentials from PEM files only).
     *
     * @return the default host SSLHostConfig
     */
    private SSLHostConfig defaultTestHostConfig() {
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setSslProtocol("tls");
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(
                sslHostConfig, SSLHostConfigCertificate.Type.UNDEFINED);
        if (endpointIsQuiche()) {
            certificate.setCertificateFile(
                    new File(QUICHE_TEST_CERT_FILE).getAbsolutePath());
            certificate.setCertificateKeyFile(
                    new File(QUICHE_TEST_KEY_FILE).getAbsolutePath());
        } else {
            certificate.setCertificateKeystoreFile(
                    new File(KEYSTORE).getAbsolutePath());
            certificate.setCertificateKeystorePassword(KEYSTORE_PASSWORD);
        }
        sslHostConfig.addCertificate(certificate);
        return sslHostConfig;
    }


    /**
     * Skip the current test unless the QUIC test environment is complete:
     * a usable QUIC endpoint, the test certificate and the aioquic probe
     * client.
     *
     * <p>Extracted from
     * {@link #startHttp3Server(Consumer, SSLHostConfig...)} for tests that
     * exercise server start-up failures (or other paths that do not use the
     * standard started-server fixtures) but must still honour the same
     * environment prerequisites.</p>
     */
    protected static void assumeQuicEnvironmentAvailable() {
        assumeQuicEndpointAvailable();
        assumeProbeClientAvailable();
    }


    /**
     * Skip the current test unless the QUIC endpoint can run a server: a
     * usable QUIC transport and the test certificate files.
     */
    protected static void assumeQuicEndpointAvailable() {
        // The QUIC transport requires either an OpenSSL with the QUIC APIs
        // or a loadable libquiche (see isQuicSupported()).
        Assume.assumeTrue(
                "No QUIC endpoint available (OpenSSL QUIC and quiche both "
                        + "unusable)",
                isQuicSupported());
        if (endpointIsQuiche()) {
            Assume.assumeTrue("quiche PEM test certificate not found: "
                    + QUICHE_TEST_CERT_FILE,
                    new File(QUICHE_TEST_CERT_FILE).isFile()
                            && new File(QUICHE_TEST_KEY_FILE).isFile());
        } else {
            Assume.assumeTrue("PKCS12 keystore not found: " + KEYSTORE,
                    new File(KEYSTORE).isFile());
        }
    }


    /**
     * Skip the current test unless the aioquic probe client can be run.
     */
    protected static void assumeProbeClientAvailable() {
        Assume.assumeTrue("python3 not available",
                isCommandAvailable(PYTHON, "-V"));
        Assume.assumeTrue("aioquic not available",
                isCommandAvailable(PYTHON, "-c", "import aioquic"));
        Assume.assumeTrue("HTTP/3 client script not found: " + CLIENT_SCRIPT,
                new File(CLIENT_SCRIPT).isFile());
    }


    /**
     * Build (but do not configure into a server, and do not start) an
     * HTTP/3 connector secured with the standard test keystore, bound to
     * the given UDP port.
     *
     * @param port           the UDP port to bind to
     * @param sslHostConfigs the SSL host configurations to use
     *
     * @return the configured connector
     */
    protected Connector newHttp3Connector(int port,
            SSLHostConfig... sslHostConfigs) {
        Connector connector = new Connector(PROTOCOL_CLASS);
        connector.setPort(port);
        connector.setSecure(true);
        Assert.assertTrue(connector.setProperty("SSLEnabled", "true"));
        if (sslHostConfigs.length == 0) {
            connector.addSslHostConfig(defaultTestHostConfig());
        } else {
            for (SSLHostConfig sslHostConfig : sslHostConfigs) {
                connector.addSslHostConfig(sslHostConfig);
            }
        }
        return connector;
    }


    /**
     * Send an HTTP/3 GET request to the server.
     *
     * @param path
     *            The request path
     * @param extraHeaders
     *            Additional request headers as
     *            {@code name, value, name, value, ...}
     * @return The response
     */
    protected Http3Response get(String path, String... extraHeaders) {
        List<String> command = clientCommand("get", "127.0.0.1",
                Integer.toString(port), path, extraHeaders);
        ClientOutput output = runClient(command, CLIENT_TIMEOUT_SECONDS);
        return new Http3Response(output);
    }


    /**
     * Send an HTTP/3 GET request to the server and cancel (reset) the
     * request stream once at least the given number of response body bytes
     * have been received. The client resets the stream with
     * {@code H3_REQUEST_CANCELLED} (RFC 9114 Section 4.2), the equivalent
     * of the HTTP/2 client cancelling a request stream with a CANCEL
     * RST_STREAM frame.
     *
     * @param path
     *            The request path
     * @param cancelAfterBytes
     *            The number of response body bytes after which the request
     *            stream is reset
     * @return The client output, which includes the partial response
     */
    protected ClientOutput getCancelled(String path, int cancelAfterBytes) {
        List<String> command = clientCommand("get", "127.0.0.1",
                Integer.toString(port), path);
        command.add("--cancel-after");
        command.add(Integer.toString(cancelAfterBytes));
        return runClient(command, CLIENT_TIMEOUT_SECONDS);
    }


    /**
     * Send an HTTP/3 request to the server.
     *
     * @param method
     *            The request method
     * @param path
     *            The request path
     * @param body
     *            The request body or {@code null}
     * @param trailers
     *            Request trailers as {@code name, value, name, value, ...}
     * @param extraHeaders
     *            Additional request headers as
     *            {@code name, value, name, value, ...}
     * @return The response
     */
    protected Http3Response request(String method, String path, byte[] body,
            String[] trailers, String... extraHeaders) {
        List<String> command = clientCommand("get", "127.0.0.1",
                Integer.toString(port), path, extraHeaders);
        command.add("--method");
        command.add(method);
        if (body != null) {
            command.add("--body");
            command.add(Base64.getEncoder().encodeToString(body));
        }
        for (int i = 0; i + 1 < (trailers == null ? 0 : trailers.length);
                i += 2) {
            command.add("--trailer");
            command.add(trailers[i] + ": " + trailers[i + 1]);
        }
        ClientOutput output = runClient(command, CLIENT_TIMEOUT_SECONDS);
        return new Http3Response(output);
    }


    /**
     * Build the base command for the client script.
     *
     * @param subCommand
     *            The client sub-command ({@code get} or {@code raw})
     * @param args
     *            Additional arguments for the sub-command
     * @return The command
     */
    protected List<String> clientCommand(String subCommand, String... args) {
        List<String> command = new ArrayList<>();
        command.add(PYTHON);
        command.add(CLIENT_SCRIPT);
        command.add(subCommand);
        command.addAll(Arrays.asList(args));
        return command;
    }


    /**
     * Build the base command for a {@code get} request with extra headers.
     */
    private List<String> clientCommand(String subCommand, String host,
            String port, String path, String[] extraHeaders) {
        List<String> command = clientCommand(subCommand, host, port, path);
        for (int i = 0; i + 1 < extraHeaders.length; i += 2) {
            command.add("--header");
            command.add(extraHeaders[i] + ": " + extraHeaders[i + 1]);
        }
        return command;
    }


    /**
     * Build the base command for a raw mode client connection.
     *
     * @return The base command; raw mode options are appended by the caller
     */
    protected List<String> rawCommand() {
        return clientCommand("raw", "127.0.0.1", Integer.toString(port));
    }


    /**
     * Build a raw mode client command with the given extra options.
     *
     * @param extra
     *            The extra options, e.g. {@code "--headers", <b64>}
     * @return The command
     */
    protected List<String> rawCommandWith(String... extra) {
        List<String> command = rawCommand();
        command.addAll(Arrays.asList(extra));
        return command;
    }


    /**
     * Build a QPACK encoded field section using the production QPACK
     * encoder. This mirrors the way the HTTP/2 tests use the production
     * HPACK encoder to build the payloads of their raw frames.
     *
     * @param headers
     *            The field section contents as
     *            {@code name, value, name, value, ...}
     * @return The base64 encoded field section
     */
    protected String buildFieldSection(String... headers) {
        MimeHeaders mimeHeaders = new MimeHeaders();
        for (int i = 0; i + 1 < headers.length; i += 2) {
            mimeHeaders.addValue(headers[i]).setString(headers[i + 1]);
        }
        QpackEncoder encoder = new QpackEncoder();
        ByteBuffer buffer = ByteBuffer.allocate(65536);
        while (encoder.encode(mimeHeaders, buffer)
                == QpackEncoder.State.UNDERFLOW) {
            ByteBuffer larger = ByteBuffer.allocate(buffer.capacity() * 2);
            buffer.flip();
            larger.put(buffer);
            buffer = larger;
        }
        byte[] result = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(result);
        return Base64.getEncoder().encodeToString(result);
    }


    /**
     * Send a raw mode request with the given field section contents.
     *
     * @param headers
     *            The request field section contents as
     *            {@code name, value, name, value, ...}
     * @return The client output
     */
    protected ClientOutput rawRequest(String... headers) {
        return runClient(rawCommandWith("--headers", buildFieldSection(headers)),
                CLIENT_TIMEOUT_SECONDS);
    }


    /**
     * Encode a QUIC variable length integer (RFC 9000 Section 16).
     *
     * @param value
     *            The value to encode
     * @return The encoded bytes
     */
    protected static byte[] encodeVarint(long value) {
        if (value < 0x40) {
            return new byte[] {(byte) value};
        }
        if (value < 0x1000) {
            return new byte[] {(byte) (0x40 | (value >> 8)),
                    (byte) (value & 0xFF)};
        }
        if (value < 0x40000000L) {
            return new byte[] {(byte) (0x80 | (value >> 24)),
                    (byte) ((value >> 16) & 0xFF),
                    (byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF)};
        }
        return new byte[] {(byte) (0xC0 | (value >> 56)),
                (byte) (value >> 48), (byte) (value >> 40),
                (byte) (value >> 32), (byte) (value >> 24),
                (byte) (value >> 16), (byte) (value >> 8), (byte) value};
    }


    /**
     * Build an HTTP/3 frame (RFC 9114 Section 7.2) and base64 encode it.
     *
     * @param frameType
     *            The frame type
     * @param payload
     *            The frame payload (may be empty)
     * @return The base64 encoded frame
     */
    protected static String buildFrameB64(int frameType, byte[] payload) {
        byte[] type = encodeVarint(frameType);
        byte[] length = encodeVarint(payload.length);
        byte[] frame = new byte[type.length + length.length + payload.length];
        System.arraycopy(type, 0, frame, 0, type.length);
        System.arraycopy(length, 0, frame, type.length, length.length);
        System.arraycopy(payload, 0, frame, type.length + length.length,
                payload.length);
        return Base64.getEncoder().encodeToString(frame);
    }


    /**
     * Build a SETTINGS frame (RFC 9114 Section 7.2.4) from setting
     * identifier/value pairs and base64 encode it.
     *
     * @param idValuePairs
     *            The settings as {@code id, value, id, value, ...}
     * @return The base64 encoded SETTINGS frame
     */
    protected static String buildSettingsFrameB64(long... idValuePairs) {
        byte[] payload = new byte[idValuePairs.length * 8];
        int offset = 0;
        for (int i = 0; i < idValuePairs.length; i += 2) {
            byte[] id = encodeVarint(idValuePairs[i]);
            byte[] value = encodeVarint(idValuePairs[i + 1]);
            System.arraycopy(id, 0, payload, offset, id.length);
            offset += id.length;
            System.arraycopy(value, 0, payload, offset, value.length);
            offset += value.length;
        }
        payload = Arrays.copyOf(payload, offset);
        return buildFrameB64(0x04, payload);
    }


    /**
     * Open a raw mode connection that sends the given control stream
     * payload (without the stream type varint) and no request stream.
     * Used to probe the server's handling of the client control stream.
     *
     * @param control
     *            The base64 encoded control stream payload
     * @return The client output
     */
    protected ClientOutput rawControlOnly(String control) {
        return runClient(
                rawCommandWith("--control", control, "--no-request"),
                CLIENT_TIMEOUT_SECONDS);
    }


    /**
     * Build the field section contents of a simple GET request to the given
     * path.
     *
     * @param path
     *            The request path
     * @return The field section contents as
     *         {@code name, value, name, value, ...}
     */
    protected String[] simpleGetHeaders(String path) {
        return new String[] { ":method", "GET", ":scheme", "https",
                ":authority", "127.0.0.1:" + port, ":path", path };
    }


    /**
     * Concatenate base64 encoded payloads and return the result base64
     * encoded. Used to build control stream payloads that consist of
     * several frames.
     *
     * @param base64Payloads
     *            The base64 encoded payloads to concatenate
     * @return The base64 encoded concatenation
     */
    protected static String buildFramesB64(String... base64Payloads) {
        int length = 0;
        for (String base64Payload : base64Payloads) {
            length += Base64.getDecoder().decode(base64Payload).length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (String base64Payload : base64Payloads) {
            byte[] payload = Base64.getDecoder().decode(base64Payload);
            System.arraycopy(payload, 0, result, offset, payload.length);
            offset += payload.length;
        }
        return Base64.getEncoder().encodeToString(result);
    }


    /**
     * Assert that the request stream was reset with the given HTTP/3 error
     * code and that no response was received.
     *
     * @param output
     *            The client output to check
     * @param expectedError
     *            The expected HTTP/3 error code
     */
    protected void assertStreamError(ClientOutput output, int expectedError) {
        Assert.assertTrue("Expected no response: "
                + output.getResponses().size(),
                output.getResponses().isEmpty());
        Assert.assertEquals("Expected stream error " + expectedError
                + " but got " + output.getStreamError(),
                Integer.valueOf(expectedError), output.getStreamError());
        Assert.assertNull("Expected no connection error",
                output.getConnectionError());
    }


    /**
     * Assert that the QUIC connection was terminated with a
     * {@code CONNECTION_CLOSE} frame carrying the given HTTP/3 connection
     * error code (RFC 9114 Section 8) and that no response was received.
     *
     * @param output
     *            The client output to check
     * @param expectedError
     *            The expected HTTP/3 error code
     */
    protected void assertConnectionError(ClientOutput output, int expectedError) {
        Assert.assertTrue("Expected no response: "
                + output.getResponses().size(),
                output.getResponses().isEmpty());
        Assert.assertNull("Expected no stream error",
                output.getStreamError());
        Assert.assertEquals("Expected connection error " + expectedError
                + " but got " + output.getConnectionError(),
                Integer.valueOf(expectedError), output.getConnectionError());
    }


    /**
     * Assert that the server terminated the connection without sending any
     * HTTP/3 error (the client sees no response and no error markers).
     *
     * @param output
     *            The client output to check
     */
    protected void assertNoResponseOrError(ClientOutput output) {
        Assert.assertTrue("Expected no response: "
                + output.getResponses().size(),
                output.getResponses().isEmpty());
        Assert.assertNull("Expected no stream error",
                output.getStreamError());
        Assert.assertNull("Expected no connection error",
                output.getConnectionError());
        Assert.assertFalse("Expected the connection to not be closed",
                output.isConnectionClosed());
    }


    /**
     * A raw mode GET request to the given path with the given extra headers.
     *
     * @param path
     *            The request path
     * @param extraHeaders
     *            The extra headers as {@code name, value, ...}
     * @return The client output
     */
    protected ClientOutput rawGet(String path, String... extraHeaders) {
        String[] all = new String[8 + extraHeaders.length];
        all[0] = ":method";
        all[1] = "GET";
        all[2] = ":scheme";
        all[3] = "https";
        all[4] = ":authority";
        all[5] = "127.0.0.1:" + port;
        all[6] = ":path";
        all[7] = path;
        System.arraycopy(extraHeaders, 0, all, 8, extraHeaders.length);
        return rawRequest(all);
    }


    /**
     * Run the client script with the given command and return its output.
     *
     * @param command
     *            The command to run
     * @param timeoutSeconds
     *            The maximum time to wait for the client to finish
     * @return The client output
     */
    protected ClientOutput runClient(List<String> command, long timeoutSeconds) {
        return runClient(command, timeoutSeconds, 0);
    }


    /**
     * Run the client script with the given command and return its output.
     *
     * @param command
     *            The command to run
     * @param timeoutSeconds
     *            The maximum time to wait for the client to finish
     * @param expectedExitCode
     *            The expected client exit code
     * @return The client output
     */
    protected ClientOutput runClient(List<String> command, long timeoutSeconds,
            int expectedExitCode) {
        return runClient(command, timeoutSeconds, expectedExitCode, null);
    }


    /**
     * Run the client script with the given command and return its output.
     *
     * @param command
     *            The command to run
     * @param timeoutSeconds
     *            The maximum time to wait for the client to finish
     * @param expectedExitCode
     *            The expected client exit code
     * @param midRun
     *            An optional hook executed once the client process has
     *            started, before waiting for it to finish (for observations
     *            that must be taken while the client is still running, e.g.
     *            server-side heap sampling during a slow drip)
     * @return The client output
     */
    protected ClientOutput runClient(List<String> command, long timeoutSeconds,
            int expectedExitCode, Runnable midRun) {
        assumeProbeClientAvailable();
        try {
            Process process = new ProcessBuilder(command).start();
            List<String> lines = new ArrayList<>();
            Thread reader = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(process.getInputStream(),
                                StandardCharsets.ISO_8859_1))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        synchronized (lines) {
                            lines.add(line);
                        }
                    }
                } catch (IOException e) {
                    // The process exited; the output is complete.
                }
            });
            reader.setDaemon(true);
            reader.start();

            if (midRun != null) {
                midRun.run();
            }

            boolean finished = process.waitFor(timeoutSeconds,
                    TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                Assert.fail("The aioquic client timed out after "
                        + timeoutSeconds + " seconds: " + command);
            }
            reader.join(TimeUnit.SECONDS.toMillis(5));
            int exit = process.exitValue();
            String stderr = readAll(process.getErrorStream());
            Assert.assertEquals("aioquic client failed (exit code " + exit
                    + "): " + stderr, expectedExitCode, exit);
            return new ClientOutput(exit, lines, stderr);
        } catch (Exception e) {
            Assert.fail("Failed to run the aioquic client: " + e);
            return null;
        }
    }


    /**
     * Assert that the response has the expected status code.
     *
     * @param response
     *            The response to check
     * @param expectedStatus
     *            The expected status code
     */
    protected void validateStatus(Http3Response response, int expectedStatus) {
        Assert.assertEquals("Unexpected response status", expectedStatus,
                response.getStatus());
    }


    protected static int findFreeUdpPort() throws IOException {
        try (DatagramSocket socket = new DatagramSocket(0)) {
            return socket.getLocalPort();
        }
    }


    protected static boolean isCommandAvailable(String... command) {
        try {
            Process process = new ProcessBuilder(command).redirectErrorStream(
                    true).start();
            readAll(process.getInputStream());
            return process.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }


    protected static String readAll(InputStream inputStream)
            throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = inputStream.read(buffer)) != -1) {
            result.write(buffer, 0, n);
        }
        return result.toString(StandardCharsets.ISO_8859_1);
    }


    /**
     * The raw output of a client invocation.
     */
    protected static class ClientOutput {

        private final int exitCode;
        private final List<String> lines;
        private final String stderr;
        private final Map<String, String> settings = new LinkedHashMap<>();
        private final Map<String, String> ctrlSettings = new LinkedHashMap<>();
        private final List<String> ctrlGoaway = new ArrayList<>();
        private final List<String> ctrlFrames = new ArrayList<>();
        private final Map<String, Integer> streamResets =
                new LinkedHashMap<>();
        private Integer streamError;
        private Integer connectionError;
        private boolean connectionClosed;
        private final List<Http3Response> responses = new ArrayList<>();
        private final List<Integer> decoderAcks = new ArrayList<>();
        private final List<Integer> decoderCancellations =
                new ArrayList<>();
        private final List<Integer> decoderInsertIncrements =
                new ArrayList<>();

        private int currentResponse = -1;
        private int currentStatus = -1;
        private final List<Integer> currentStatuses = new ArrayList<>();
        private final Map<String, String> currentHeaders =
                new LinkedHashMap<>();
        private final Map<String, String> currentTrailers =
                new LinkedHashMap<>();
        private final List<String> currentBodies = new ArrayList<>();


        ClientOutput(int exitCode, List<String> lines, String stderr) {
            this.exitCode = exitCode;
            this.lines = new ArrayList<>(lines);
            this.stderr = stderr;
            parse();
        }


        private boolean responseStarted = false;


        private void parse() {
            for (String line : lines) {
                if (line.startsWith("SETTINGS:")) {
                    int idx = line.indexOf('=');
                    settings.put(line.substring("SETTINGS:".length(), idx),
                            line.substring(idx + 1));
                } else if (line.startsWith("CTRL:SETTINGS:")) {
                    int idx = line.indexOf('=');
                    ctrlSettings.put(
                            line.substring("CTRL:SETTINGS:".length(), idx),
                            line.substring(idx + 1));
                } else if (line.startsWith("CTRL:GOAWAY=")) {
                    ctrlGoaway.add(line.substring("CTRL:GOAWAY=".length()));
                } else if (line.startsWith("CTRL:FRAME=")) {
                    ctrlFrames.add(line.substring("CTRL:FRAME=".length()));
                } else if (line.startsWith("STREAM_ERROR=")) {
                    streamError = Integer.decode(
                            line.substring("STREAM_ERROR=".length()));
                } else if (line.startsWith("STREAM_RESET=")) {
                    String rest = line.substring("STREAM_RESET=".length());
                    int idx = rest.indexOf('=');
                    streamResets.put(rest.substring(0, idx),
                            Integer.decode(rest.substring(idx + 1)));
                } else if (line.startsWith("CONNECTION_ERROR=")) {
                    connectionError = Integer.decode(
                            line.substring("CONNECTION_ERROR=".length()));
                } else if (line.startsWith("DEC_ACK=")) {
                    decoderAcks.add(Integer.valueOf(Integer.parseInt(
                            line.substring("DEC_ACK=".length()))));
                } else if (line.startsWith("DEC_CANC=")) {
                    decoderCancellations.add(Integer.valueOf(Integer.parseInt(
                            line.substring("DEC_CANC=".length()))));
                } else if (line.startsWith("DEC_RIC=")) {
                    decoderInsertIncrements.add(
                            Integer.valueOf(Integer.parseInt(
                                    line.substring("DEC_RIC=".length()))));
                } else if (line.equals("CONNECTION_CLOSED")) {
                    connectionClosed = true;
                } else if (line.startsWith("RESPONSE index=")) {
                    flushResponse();
                    currentResponse++;
                    responseStarted = true;
                } else if (line.startsWith("STATUS=")) {
                    responseStarted = true;
                    currentStatus = Integer.parseInt(
                            line.substring("STATUS=".length()));
                    currentStatuses.add(currentStatus);
                } else if (line.startsWith("HEADER:")) {
                    responseStarted = true;
                    int idx = line.indexOf('=');
                    currentHeaders.put(line.substring(7, idx),
                            line.substring(idx + 1));
                } else if (line.startsWith("TRAILER:")) {
                    responseStarted = true;
                    int idx = line.indexOf('=');
                    currentTrailers.put(line.substring(8, idx),
                            line.substring(idx + 1));
                } else if (line.startsWith("BODY=")) {
                    responseStarted = true;
                    currentBodies.add(line.substring("BODY=".length()));
                }
            }
            flushResponse();
        }


        private void flushResponse() {
            if (responseStarted) {
                byte[] body = new byte[0];
                for (String b64 : currentBodies) {
                    byte[] part = Base64.getDecoder().decode(b64);
                    byte[] combined = new byte[body.length + part.length];
                    System.arraycopy(body, 0, combined, 0, body.length);
                    System.arraycopy(part, 0, combined, body.length,
                            part.length);
                    body = combined;
                }
                // Copy the maps: the current* fields are reused for the
                // next response and cleared below.
                responses.add(new Http3Response(new ArrayList<>(
                        currentStatuses),
                        new LinkedHashMap<>(currentHeaders),
                        new LinkedHashMap<>(currentTrailers), body));
            }
            currentStatus = -1;
            currentStatuses.clear();
            currentHeaders.clear();
            currentTrailers.clear();
            currentBodies.clear();
            responseStarted = false;
        }


        public int getExitCode() {
            return exitCode;
        }


        public List<String> getLines() {
            return lines;
        }


        public String getStderr() {
            return stderr;
        }


        /**
         * The values of the server SETTINGS frames as
         * {@code settingId -> value}.
         *
         * @return the server SETTINGS values
         */
        public Map<String, String> getSettings() {
            return settings;
        }


        /**
         * The value of a server SETTINGS frame, or {@code null}.
         *
         * @param settingId the numeric setting ID
         * @return the setting value or {@code null}
         */
        public String getSetting(int settingId) {
            return settings.get(Integer.toString(settingId));
        }


        /**
         * The value of a server SETTINGS frame as an integer, or
         * {@code null} if the setting is not present.
         *
         * @param settingId the numeric setting ID
         * @return the setting value or {@code null}
         */
        public Integer getSettingAsInt(int settingId) {
            String value = getSetting(settingId);
            if (value == null) {
                return null;
            }
            return Integer.decode(value);
        }


        /**
         * The value of a frame on the server control stream, or
         * {@code null}.
         *
         * @param settingId the numeric setting ID
         * @return the setting value or {@code null}
         */
        public String getCtrlSetting(int settingId) {
            return ctrlSettings.get(Integer.toString(settingId));
        }


        /**
         * The value of a frame on the server control stream as an integer,
         * or {@code null} if the frame is not present.
         *
         * @param settingId the numeric setting ID
         * @return the setting value or {@code null}
         */
        public Integer getCtrlSettingAsInt(int settingId) {
            String value = getCtrlSetting(settingId);
            if (value == null) {
                return null;
            }
            return Integer.decode(value);
        }


        public Map<String, String> getCtrlSettings() {
            return ctrlSettings;
        }


        public List<String> getCtrlGoaway() {
            return ctrlGoaway;
        }


        public List<String> getCtrlFrames() {
            return ctrlFrames;
        }


        /**
         * The HTTP/3 error code of the request stream reset, or
         * {@code null} if the request stream was not reset.
         *
         * @return the error code or {@code null}
         */
        public Integer getStreamError() {
            return streamError;
        }


        public Map<String, Integer> getStreamResets() {
            return streamResets;
        }


        /**
         * The HTTP/3 error code of the connection close, or {@code null} if
         * the connection was not closed with an error.
         *
         * @return the error code or {@code null}
         */
        public Integer getConnectionError() {
            return connectionError;
        }


        public boolean isConnectionClosed() {
            return connectionClosed;
        }


        /**
         * The Section Acknowledgment instructions the server wrote to the
         * client QPACK decoder stream, as the acknowledged stream IDs
         * (RFC 9204 Section 4.4.1).
         *
         * @return the acknowledged stream IDs
         */
        public List<Integer> getDecoderAcks() {
            return decoderAcks;
        }


        /**
         * The Stream Cancellation instructions the server wrote to the
         * client QPACK decoder stream, as the cancelled stream IDs
         * (RFC 9204 Section 4.4.2).
         *
         * @return the cancelled stream IDs
         */
        public List<Integer> getDecoderCancellations() {
            return decoderCancellations;
        }


        /**
         * The Insert Count Increment instructions the server wrote to the
         * client QPACK decoder stream (RFC 9204 Section 4.4.3).
         *
         * @return the increments
         */
        public List<Integer> getDecoderInsertIncrements() {
            return decoderInsertIncrements;
        }


        /**
         * The responses received. There is one entry per request.
         *
         * @return the responses
         */
        public List<Http3Response> getResponses() {
            return responses;
        }


        /**
         * The (single) response received.
         *
         * @return the response
         * @throws AssertionError if there was not exactly one response
         */
        public Http3Response getResponse() {
            Assert.assertEquals("Expected exactly one response", 1,
                    responses.size());
            return responses.get(0);
        }
    }


    /**
     * The result of an HTTP/3 request.
     */
    protected static class Http3Response {

        private final List<Integer> statuses;
        private final Map<String, String> headers;
        private final Map<String, String> trailers;
        private final byte[] body;


        Http3Response(List<Integer> statuses, Map<String, String> headers,
                Map<String, String> trailers, byte[] body) {
            this.statuses = statuses;
            this.headers = headers;
            this.trailers = trailers;
            this.body = body;
        }


        Http3Response(ClientOutput output) {
            if (!output.responses.isEmpty()) {
                Http3Response first = output.responses.get(0);
                this.statuses = first.statuses;
                this.headers = first.headers;
                this.trailers = first.trailers;
                this.body = first.body;
            } else {
                this.statuses = new ArrayList<>();
                this.headers = new LinkedHashMap<>();
                this.trailers = new LinkedHashMap<>();
                this.body = new byte[0];
            }
        }


        /**
         * The status codes of all responses received on the stream,
         * including interim (1xx) responses. The last entry is the final
         * response status.
         *
         * @return the status codes
         */
        public List<Integer> getStatuses() {
            return statuses;
        }


        /**
         * The final response status code, or -1 if no response was
         * received.
         *
         * @return the final status code, or -1
         */
        public int getStatus() {
            if (statuses.isEmpty()) {
                return -1;
            }
            return statuses.get(statuses.size() - 1);
        }


        /**
         * Get a response header. The lookup is case insensitive.
         *
         * @param name
         *            The header name
         * @return The header value or {@code null} if the header is not
         *         present
         */
        public String getHeader(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }


        public Map<String, String> getHeaders() {
            return headers;
        }


        /**
         * Get a response trailer. The lookup is case insensitive.
         *
         * @param name
         *            The trailer name
         * @return The trailer value or {@code null} if the trailer is not
         *         present
         */
        public String getTrailer(String name) {
            return trailers.get(name.toLowerCase(Locale.ROOT));
        }


        public Map<String, String> getTrailers() {
            return trailers;
        }


        public byte[] getBody() {
            return body;
        }


        public String getBodyAsString() {
            return new String(body, StandardCharsets.ISO_8859_1);
        }
    }


    private static class SimpleServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            resp.getWriter().print("Hello over HTTP/3");
        }
    }


    private static class EchoServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            echo(req, resp);
        }

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            echo(req, resp);
        }

        @Override
        protected void doPut(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            echo(req, resp);
        }

        private void echo(HttpServletRequest req, HttpServletResponse resp)
                throws IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            StringBuilder sb = new StringBuilder();
            sb.append("METHOD: ").append(req.getMethod()).append("\n");
            sb.append("QUERY: ").append(req.getQueryString() == null ? ""
                    : req.getQueryString()).append("\n");
            Enumeration<String> names = req.getHeaderNames();
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                sb.append(name).append(": ").append(req.getHeader(name))
                        .append("\n");
            }
            byte[] body = req.getInputStream().readAllBytes();
            sb.append("BODY: ").append(body.length).append(":")
                    .append(new String(body, StandardCharsets.ISO_8859_1));
            resp.getWriter().print(sb.toString());
        }
    }


    private static class EchoMethodServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            resp.getWriter().print(req.getMethod());
        }
    }


    private static class RemoteAddrServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            resp.getWriter().print(req.getRemoteAddr() + ":" + req.getRemotePort());
        }
    }


    private static final int LARGE_BODY_SIZE = 256 * 1024;


    private static class LargeServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            resp.setContentLength(LARGE_BODY_SIZE);
            byte[] pattern = new byte[1024];
            for (int i = 0; i < pattern.length; i++) {
                pattern[i] = (byte) (i % 251);
            }
            ServletOutputStream out = resp.getOutputStream();
            for (int i = 0; i < LARGE_BODY_SIZE / pattern.length; i++) {
                out.write(pattern);
            }
            out.flush();
        }
    }


    private static class TrailersServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            resp.setTrailerFields(
                    () -> java.util.Map.of("x-test-trailer", "test"));
            resp.getWriter().print("body");
            resp.flushBuffer();
        }
    }


    /*
     * Supplies a trailer map that mixes a valid field with names that are
     * not valid HTTP field names (empty, contains a space). The servlet-API
     * trailer path (setTrailerFields, unlike addHeader) applies no name
     * validation, so these reach the protocol layer.
     */
    private static class TrailersInvalidServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            java.util.Map<String,String> trailers = new java.util.HashMap<>();
            trailers.put("", "empty-name");
            trailers.put("not a token", "space-in-name");
            trailers.put("x-valid-trailer", "valid");
            resp.setTrailerFields(() -> trailers);
            resp.getWriter().print("body");
            resp.flushBuffer();
        }
    }


    private static class EarlyHintsServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.addHeader("Link", "</large>; rel=preload");
            resp.sendEarlyHints();
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            resp.getWriter().print("Hello over HTTP/3");
        }
    }


    private static class SleepServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            long sleep = Long.parseLong(
                    req.getParameter("ms") == null ? "5000"
                            : req.getParameter("ms"));
            try {
                Thread.sleep(sleep);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.ISO_8859_1.name());
            resp.getWriter().print("done");
        }
    }
}

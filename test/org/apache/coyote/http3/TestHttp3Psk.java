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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigPreSharedKey;

/**
 * Tests TLS 1.3 pre-shared key authentication on the OpenSSL QUIC endpoint.
 * <p>
 * The client is {@code openssl s_client} with its {@code -quic} transport
 * (OpenSSL 4.x): it completes the real TLS 1.3 handshake over QUIC, which is
 * what these tests assert; request-level HTTP/3 behaviour over pre-shared key
 * connections is covered by the regular suites via the certificate path. The
 * s_client is skipped when no QUIC-capable OpenSSL binary is available (see
 * {@link #OPENSSL}).
 */
public class TestHttp3Psk extends Http3TestBase {

    /**
     * Path of the OpenSSL command line tool used as the QUIC test client.
     * Must be a build that supports {@code s_client -quic} (OpenSSL 4.x).
     */
    private static final String OPENSSL = System.getProperty(
            "http3.openssl.client",
            "/home/opencode/openssl-master/apps/openssl");

    private static final String PSK_IDENTITY = "tomcat-psk-test";
    private static final String PSK_KEY =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static final long CLIENT_TIMEOUT_SECONDS = 15;


    @Override
    public void setUp() throws Exception {
        super.setUp();
        // Pre-shared key support is implemented on the OpenSSL QUIC endpoint
        // only; the quiche endpoint has its own TLS stack.
        Assume.assumeFalse("PSK is an OpenSSL QUIC endpoint feature",
                endpointIsQuiche());
        Assume.assumeTrue("QUIC-capable openssl client not found: " + OPENSSL,
                isQuicClientAvailable());
    }


    private static boolean isQuicClientAvailable() {
        try {
            Process process = new ProcessBuilder(OPENSSL, "s_client", "-help")
                    .redirectErrorStream(true).start();
            String output = readOutput(process);
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return false;
            }
            return process.exitValue() == 0
                    && output.contains("-quic") && output.contains("-psk");
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }


    @Test
    public void testCertlessPskHandshake() throws Exception {
        startHttp3Server(pskOnlyHostConfig());

        ClientResult result = runSClient("-psk", PSK_KEY,
                "-psk_identity", PSK_IDENTITY,
                "-ciphersuites", "TLS_AES_128_GCM_SHA256");

        Assert.assertTrue("PSK handshake failed, output:\n" + result.output,
                result.succeeded());
        Assert.assertTrue("Handshake did not negotiate TLS 1.3, output:\n"
                + result.output, result.output.contains("TLSv1.3"));
        // The connector has no certificate at all: a completed handshake can
        // only have been authenticated with the pre-shared key.
    }


    @Test
    public void testMixedPskHandshakeSkipsCertificate() throws Exception {
        startHttp3Server(mixedHostConfig());

        ClientResult pskRun = runSClient("-psk", PSK_KEY,
                "-psk_identity", PSK_IDENTITY,
                "-ciphersuites", "TLS_AES_128_GCM_SHA256");

        Assert.assertTrue("PSK handshake failed, output:\n" + pskRun.output,
                pskRun.succeeded());
        Assert.assertTrue("A resolved PSK identity should produce a PSK "
                + "handshake without a server certificate, output:\n"
                + pskRun.output, !containsServerCertificate(pskRun.output));
    }


    @Test
    public void testMixedPlainHandshakeUsesCertificate() throws Exception {
        startHttp3Server(mixedHostConfig());

        ClientResult plainRun = runSClient();

        Assert.assertTrue("Certificate handshake failed, output:\n"
                + plainRun.output, plainRun.succeeded());
        Assert.assertTrue("A client that offers no PSK identity should get the "
                + "certificate handshake, output:\n" + plainRun.output,
                containsServerCertificate(plainRun.output));
    }


    @Test
    public void testMixedUnknownIdentityFallsBackToCertificate()
            throws Exception {
        startHttp3Server(mixedHostConfig());

        ClientResult result = runSClient("-psk", PSK_KEY,
                "-psk_identity", "unknown-identity");

        Assert.assertTrue("Unknown identity should fall through to the "
                + "certificate handshake, output:\n" + result.output,
                result.succeeded());
        Assert.assertTrue("Unknown identity should not produce a PSK "
                + "handshake, output:\n" + result.output,
                containsServerCertificate(result.output));
    }


    @Test
    public void testCertlessPlainHandshakeFails() throws Exception {
        startHttp3Server(pskOnlyHostConfig());

        ClientResult result = runSClient();

        // The connector has no certificate; a client that does not offer the
        // configured identity cannot complete the handshake.
        Assert.assertFalse("Handshake without a PSK should have failed, "
                + "output:\n" + result.output, result.succeeded());
    }


    // ------------------------------------------------------------- fixtures


    private SSLHostConfig pskOnlyHostConfig() {
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setSslProtocol("tls");
        addPsk(sslHostConfig);
        return sslHostConfig;
    }


    private SSLHostConfig mixedHostConfig() {
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setSslProtocol("tls");
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(
                sslHostConfig, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateKeystoreFile(
                new File(KEYSTORE).getAbsolutePath());
        certificate.setCertificateKeystorePassword(KEYSTORE_PASSWORD);
        sslHostConfig.addCertificate(certificate);
        addPsk(sslHostConfig);
        return sslHostConfig;
    }


    private void addPsk(SSLHostConfig sslHostConfig) {
        SSLHostConfigPreSharedKey psk =
                new SSLHostConfigPreSharedKey(sslHostConfig);
        psk.setIdentity(PSK_IDENTITY);
        psk.setKey(PSK_KEY);
        psk.setDigest("SHA256");
        sslHostConfig.addPreSharedKey(psk);
    }


    /**
     * Starts {@code openssl s_client} against the running HTTP/3 connector
     * with the given extra arguments and waits for it to finish.
     *
     * @param args additional s_client arguments
     *
     * @return the client result (exit code and combined output)
     */
    private ClientResult runSClient(String... args) throws Exception {
        String[] command = new String[args.length + 8];
        int i = 0;
        command[i++] = OPENSSL;
        command[i++] = "s_client";
        command[i++] = "-quic";
        command[i++] = "-connect";
        command[i++] = "127.0.0.1:" + port;
        command[i++] = "-alpn";
        command[i++] = "h3";
        command[i++] = "-trace";
        System.arraycopy(args, 0, command, i, args.length);

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        process.getOutputStream().close();

        String output = readOutput(process);
        if (!process.waitFor(CLIENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            Assert.fail("s_client timed out, output:\n" + output);
        }
        return new ClientResult(process.exitValue(), output);
    }


    private static String readOutput(Process process) throws IOException {
        try (InputStream in = process.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }


    /**
     * Whether the s_client output shows that a server certificate was
     * received: {@code -brief} reports one as a "Peer certificate" line, the
     * non-brief output prints a "Server certificate" section.
     */
    private static boolean containsServerCertificate(String output) {
        return output.contains("Peer certificate")
                || output.contains("Server certificate");
    }


    private static final class ClientResult {

        private final int exitCode;
        private final String output;

        ClientResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }

        boolean succeeded() {
            return exitCode == 0;
        }
    }
}

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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;

/**
 * Tests for the QUIC endpoint certificate capabilities: SNI based
 * certificate selection, multiple key types per host, PEM / PKCS#12 / JKS
 * certificate loading, chain files and live certificate reload.
 *
 * <p>The tests drive the aioquic based {@code http3_cert_client.py} script
 * which reports the certificate presented by the server.
 */
public class TestQuicCertificates extends Http3TestBase {

    /**
     * The aioquic based certificate inspection client script.
     */
    protected static final String CERT_CLIENT_SCRIPT = System.getProperty(
            "http3.cert.client.script",
            "test/org/apache/coyote/http3/http3_cert_client.py");

    private static final String CERT_DIR =
            "test/org/apache/coyote/http3/";


    @Override
    public void setUp() throws Exception {
        super.setUp();
        Assume.assumeTrue("OpenSSL QUIC support not available",
                isQuicSupported());
        Assume.assumeTrue("python3 not available",
                isCommandAvailable(PYTHON, "-V"));
        Assume.assumeTrue("aioquic not available",
                isCommandAvailable(PYTHON, "-c", "import aioquic"));
        Assume.assumeTrue("HTTP/3 certificate client script not found: "
                + CERT_CLIENT_SCRIPT,
                new File(CERT_CLIENT_SCRIPT).isFile());
    }


    /*
     * The quiche phase-1 configuration is a single default-host PEM
     * certificate: SNI hosts, multi-certificate-type default hosts, keystore
     * / PKCS#12 sources and encrypted private keys are not supported yet, so
     * the tests that exercise them skip when the quiche endpoint is in use.
     */
    private void assumeAdvancedCertificates() {
        Assume.assumeTrue(
                "The quiche endpoint (phase 1) serves a single default-host "
                        + "PEM certificate; SNI, multi-type, keystore and "
                        + "encrypted-key cases are skipped",
                endpointSupportsSni());
    }


    @Test
    public void testSniSelection() throws Exception {
        assumeAdvancedCertificates();
        startHttp3Server(
                pemHost(null, "quic-default-cert.pem", "quic-default-key.pem"),
                pemHost("quic-sni.test", "quic-sni-ec-cert.pem",
                        "quic-sni-ec-key.pem"),
                keystoreHost("quic-p12.test", "quic-p12.p12", "changeit",
                        "PKCS12", null));

        // SNI matching the EC host
        CertClientResult result = certGet("/simple", "quic-sni.test", null,
                null, null);
        Assert.assertEquals("CN=quic-sni", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("ECPublicKey", result.fields.get("PEER_PUBKEY"));
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // SNI matching the PKCS#12 host
        result = certGet("/simple", "quic-p12.test", null, null, null);
        Assert.assertEquals("CN=quic-p12", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("ECPublicKey", result.fields.get("PEER_PUBKEY"));
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // SNI matching no configured host -> default certificate
        result = certGet("/simple", "unknown.example", null, null, null);
        Assert.assertEquals("CN=localhost", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("RSAPublicKey", result.fields.get("PEER_PUBKEY"));
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // No SNI -> default certificate
        result = certGet("/simple", null, null, null, null);
        Assert.assertEquals("CN=localhost", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("RSAPublicKey", result.fields.get("PEER_PUBKEY"));
        Assert.assertEquals("200", result.fields.get("STATUS"));
    }


    @Test
    public void testMultiKeyType() throws Exception {
        assumeAdvancedCertificates();
        SSLHostConfig defaultHost =
                pemHost(null, "quic-default-cert.pem", "quic-default-key.pem");
        SSLHostConfig sniHost = new SSLHostConfig();
        sniHost.setHostName("quic-sni.test");
        sniHost.setSslProtocol("tls");
        sniHost.addCertificate(pemCertificate(sniHost, "quic-sni-ec-cert.pem",
                "quic-sni-ec-key.pem", SSLHostConfigCertificate.Type.EC));
        sniHost.addCertificate(pemCertificate(sniHost, "quic-sni-rsa-cert.pem",
                "quic-sni-rsa-key.pem", SSLHostConfigCertificate.Type.RSA));
        startHttp3Server(defaultHost, sniHost);

        // Client preferring ECDSA gets the EC certificate
        CertClientResult result = certGet("/simple", "quic-sni.test", null,
                null, "ec");
        Assert.assertEquals("CN=quic-sni", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("ECPublicKey", result.fields.get("PEER_PUBKEY"));
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // Client preferring RSA gets the RSA certificate
        result = certGet("/simple", "quic-sni.test", null, null, "rsa");
        Assert.assertEquals("CN=quic-sni-rsa", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("RSAPublicKey", result.fields.get("PEER_PUBKEY"));
        Assert.assertEquals("200", result.fields.get("STATUS"));
    }


    @Test
    public void testChainFile() throws Exception {
        startHttp3Server(
                pemHost(null, "quic-leaf-cert.pem", "quic-leaf-key.pem",
                        "quic-leaf-chain.pem"));

        // Verifying client: full chain is served and validates
        CertClientResult result = certGet("/simple", null, null,
                CERT_DIR + "quic-ca-cert.pem", null);
        Assert.assertEquals("CN=localhost", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("2", result.fields.get("PEER_CERT_COUNT"));
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // Verifying client with the wrong CA must fail the handshake
        CertClientResult failed = certGet("/simple", null, null,
                CERT_DIR + "quic-default-cert.pem", null);
        Assert.assertFalse("Handshake with wrong CA must fail",
                failed.exitCode == 0 && failed.fields.containsKey("STATUS"));
    }


    @Test
    public void testCombinedPemChain() throws Exception {
        // Intermediates appended to the certificate file after the leaf are
        // part of the served chain, not only the separately configured
        // certificateChainFile.
        String combined = combinedPem();

        SSLHostConfig host = new SSLHostConfig();
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(host,
                        SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateFile(combined);
        certificate.setCertificateKeyFile(
                new File(CERT_DIR + "quic-leaf-key.pem").getAbsolutePath());
        host.addCertificate(certificate);
        startHttp3Server(host);

        CertClientResult result = certGet("/simple", null, null,
                CERT_DIR + "quic-ca-cert.pem", null);
        Assert.assertEquals("CN=localhost", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("leaf + intermediate must both be presented",
                "2", result.fields.get("PEER_CERT_COUNT"));
        Assert.assertEquals("200", result.fields.get("STATUS"));
    }


    @Test
    public void testPkcs12BundleChain() throws Exception {
        assumeAdvancedCertificates();
        // A PKCS#12 bundle holding [leaf, intermediate] must present both
        // certificates; PKCS12_parse's ca parameter must not be discarded.
        String bundle = pkcs12BundleWithChain();

        SSLHostConfig host = new SSLHostConfig();
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(host,
                        SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateFile(bundle);
        certificate.setCertificateKeyPassword("changeit");
        host.addCertificate(certificate);
        startHttp3Server(host);

        CertClientResult result = certGet("/simple", null, null,
                CERT_DIR + "quic-ca-cert.pem", null);
        Assert.assertEquals("CN=localhost", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("leaf + intermediate must both be presented",
                "2", result.fields.get("PEER_CERT_COUNT"));
        Assert.assertEquals("200", result.fields.get("STATUS"));
    }


    @Test
    public void testEncryptedPemPrivateKey() throws Exception {
        assumeAdvancedCertificates();
        // An encrypted PEM private key must load with its configured
        // passphrase: the pem_password_cb must report the password length
        // excluding the NUL terminator (OpenSSL feeds the returned length
        // straight into the key derivation).
        SSLHostConfig host = new SSLHostConfig();
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(host,
                        SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateFile(
                new File(CERT_DIR + "quic-leaf-cert.pem").getAbsolutePath());
        certificate.setCertificateKeyFile(
                new File(CERT_DIR + "quic-leaf-key-enc.pem").getAbsolutePath());
        certificate.setCertificateKeyPassword("changeit");
        host.addCertificate(certificate);
        startHttp3Server(host);

        CertClientResult result = certGet("/simple", null, null,
                CERT_DIR + "quic-ca-cert.pem", null);
        Assert.assertEquals("CN=localhost", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("200", result.fields.get("STATUS"));
    }


    @Test
    public void testEncryptedPemPrivateKeyWrongPassword() throws Exception {
        assumeAdvancedCertificates();
        // The same encrypted key with a wrong passphrase must fail the load
        // (logged, host dropped); the default host has no other certificate
        // so no request may succeed.
        SSLHostConfig host = new SSLHostConfig();
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(host,
                        SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateFile(
                new File(CERT_DIR + "quic-leaf-cert.pem").getAbsolutePath());
        certificate.setCertificateKeyFile(
                new File(CERT_DIR + "quic-leaf-key-enc.pem").getAbsolutePath());
        certificate.setCertificateKeyPassword("wrong-password");
        host.addCertificate(certificate);

        startHttp3Server(host);

        CertClientResult result = certGet("/simple", null, null, null, null);
        Assert.assertFalse("Handshake without a usable private key must fail",
                result.exitCode == 0 && result.fields.containsKey("STATUS"));
    }


    @Test
    public void testStrictSni() throws Exception {
        assumeAdvancedCertificates();
        Connector connector = startHttp3Server(
                pemHost(null, "quic-default-cert.pem", "quic-default-key.pem"),
                pemHost("quic-sni.test", "quic-sni-ec-cert.pem",
                        "quic-sni-ec-key.pem"));
        Assert.assertTrue(connector.setProperty("strictSni", "true"));

        String portText = Integer.toString(port);

        // SNI and :authority match -> OK
        CertClientResult result = certGet("/simple", "quic-sni.test",
                "quic-sni.test:" + portText, null, null);
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // SNI matches one host, :authority matches another -> stream
        // reset with H3_MESSAGE_ERROR
        result = certGet("/simple", "quic-sni.test",
                "localhost:" + portText, null, null);
        Assert.assertEquals(Integer.toString(H3_MESSAGE_ERROR),
                result.fields.get("STREAM_ERROR"));
        Assert.assertNull(result.fields.get("STATUS"));

        // SNI and :authority match the default host -> OK
        result = certGet("/simple", "localhost", "localhost:" + portText,
                null, null);
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // No SNI, :authority matches the default host -> OK
        result = certGet("/simple", null, "localhost:" + portText, null,
                null);
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // No SNI, :authority matches a non-default host -> stream reset
        // with H3_MESSAGE_ERROR
        result = certGet("/simple", null, "quic-sni.test:" + portText, null,
                null);
        Assert.assertEquals(Integer.toString(H3_MESSAGE_ERROR),
                result.fields.get("STREAM_ERROR"));
        Assert.assertNull(result.fields.get("STATUS"));
    }


    @Test
    public void testKeystoreJks() throws Exception {
        assumeAdvancedCertificates();
        startHttp3Server(
                pemHost(null, "quic-default-cert.pem", "quic-default-key.pem"),
                keystoreHost("quic-jks.test", "quic-jks.jks", "changeit",
                        "JKS", "quic-jks"));

        CertClientResult result = certGet("/simple", "quic-jks.test", null,
                null, null);
        Assert.assertEquals("CN=quic-jks", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("RSAPublicKey", result.fields.get("PEER_PUBKEY"));
        Assert.assertEquals("200", result.fields.get("STATUS"));
    }


    @Test
    public void testPkcs12CertificateFile() throws Exception {
        assumeAdvancedCertificates();
        // A certificateFile with the .pkcs12 extension is loaded through
        // the PKCS#12 bundle reader (a file handed to OpenSSL directly),
        // not through the Java key-store loader.
        SSLHostConfig host = new SSLHostConfig();
        host.setHostName("quic-pkcs12.test");
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(
                host, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateFile(
                new File(CERT_DIR + "quic-pkcs12.pkcs12").getAbsolutePath());
        certificate.setCertificateKeyPassword("changeit");
        host.addCertificate(certificate);

        startHttp3Server(
                pemHost(null, "quic-default-cert.pem", "quic-default-key.pem"),
                host);

        CertClientResult result = certGet("/simple", "quic-pkcs12.test", null,
                null, null);
        Assert.assertEquals("CN=quic-p12", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("200", result.fields.get("STATUS"));
    }


    @Test
    public void testPkcs12CertificateFileWrongPassword() throws Exception {
        assumeAdvancedCertificates();
        // A wrong PKCS#12 password must fail the load cleanly (logged,
        // host config dropped); the connector must still come up with the
        // remaining hosts and refuse the unknown SNI host.
        SSLHostConfig host = new SSLHostConfig();
        host.setHostName("quic-pkcs12.test");
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(
                host, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateFile(
                new File(CERT_DIR + "quic-pkcs12.pkcs12").getAbsolutePath());
        certificate.setCertificateKeyPassword("wrong-password");
        host.addCertificate(certificate);

        startHttp3Server(
                pemHost(null, "quic-default-cert.pem", "quic-default-key.pem"),
                host);

        // The default host still serves.
        CertClientResult result = certGet("/simple", null, null, null, null);
        Assert.assertEquals("CN=localhost", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // A configured host whose certificate failed to load must not
        // silently present the default host's identity: the handshake for
        // that SNI name must fail instead of serving a name-mismatched
        // certificate.
        CertClientResult mismatch = certGet("/simple", "quic-pkcs12.test",
                null, null, null);
        Assert.assertFalse("SNI for a host without loadable certificates "
                        + "must fail the handshake, not present the default "
                        + "certificate",
                mismatch.exitCode == 0 && mismatch.fields.containsKey("STATUS"));
    }


    @Test
    public void testReload() throws Exception {
        assumeAdvancedCertificates();
        SSLHostConfig defaultHost =
                pemHost(null, "quic-default-cert.pem", "quic-default-key.pem");
        SSLHostConfig sniHost = new SSLHostConfig();
        sniHost.setHostName("quic-sni.test");
        sniHost.setSslProtocol("tls");
        sniHost.addCertificate(pemCertificate(sniHost, "quic-sni-ec-cert.pem",
                "quic-sni-ec-key.pem"));
        Connector connector = startHttp3Server(defaultHost, sniHost);

        // Initial certificate
        CertClientResult result = certGet("/simple", "quic-sni.test", null,
                null, null);
        Assert.assertEquals("CN=quic-sni", result.fields.get("PEER_SUBJECT"));
        Assert.assertEquals("200", result.fields.get("STATUS"));

        // Replace the host configuration with the second certificate
        SSLHostConfig replacement = new SSLHostConfig();
        replacement.setHostName("quic-sni.test");
        replacement.setSslProtocol("tls");
        replacement.addCertificate(pemCertificate(replacement,
                "quic-sni-ec-v2-cert.pem", "quic-sni-ec-v2-key.pem"));
        connector.getProtocolHandler().addSslHostConfig(replacement, true);

        // The swap happens on the poll thread; retry briefly until the new
        // certificate is served
        String subject = null;
        for (int i = 0; i < 100; i++) {
            result = certGet("/simple", "quic-sni.test", null, null, null);
            subject = result.fields.get("PEER_SUBJECT");
            if ("CN=quic-sni-v2".equals(subject)) {
                break;
            }
            Thread.sleep(100);
        }
        Assert.assertEquals("CN=quic-sni-v2", subject);
        Assert.assertEquals("200", result.fields.get("STATUS"));
    }


    @Test
    public void testDefaultHostCertificateFailureFailsStartup() throws Exception {
        assumeAdvancedCertificates();
        // The default host's certificate cannot be loaded (wrong password)
        // while another host's certificate loads successfully. The build
        // must fail the startup explicitly; the entries loaded for the
        // other host are freed on this failure path (they live on the
        // OpenSSL heap, so closing the arena alone would leak them).
        SSLHostConfig defaultHost = keystoreHost(null, "quic-p12.p12",
                "wrong-password", "PKCS12", null);
        SSLHostConfig sniHost = pemHost("quic-sni.test",
                "quic-sni-ec-cert.pem", "quic-sni-ec-key.pem");

        // StandardService logs and swallows a connector start failure, so
        // tomcat.start() returns normally; the connector itself must not be
        // running.
        Connector started = startHttp3Server(defaultHost, sniHost);
        Assert.assertFalse("The connector must not be running when the"
                + " default host has no loadable certificate",
                started.getState().isAvailable());
    }


    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------


    /**
     * Builds a combined PEM certificate file in the test temp directory:
     * the leaf followed by the CA certificate (the common
     * "leaf + intermediates in one file" deployment style).
     *
     * @return the absolute path of the combined file
     */
    private String combinedPem() throws Exception {
        java.nio.file.Path combined = java.nio.file.Files.write(
                tempFile("quic-leaf-combined", ".pem"),
                java.nio.file.Files.readAllBytes(
                        new File(CERT_DIR + "quic-leaf-cert.pem").toPath()));
        java.nio.file.Files.write(combined, java.nio.file.Files.readAllBytes(
                new File(CERT_DIR + "quic-leaf-chain.pem").toPath()),
                java.nio.file.StandardOpenOption.APPEND);
        return combined.toAbsolutePath().toString();
    }


    /**
     * Builds a PKCS#12 bundle in the test temp directory containing the
     * leaf private key with a [leaf, CA] certificate chain.
     *
     * @return the absolute path of the bundle
     */
    private String pkcs12BundleWithChain() throws Exception {
        java.security.PrivateKey key = null;
        for (String algorithm : new String[] { "EC", "RSA" }) {
            try {
                key = readPkcs8PrivateKey(algorithm);
                break;
            } catch (java.security.GeneralSecurityException e) {
                // Not this key type; try the next candidate algorithm
            }
        }
        Assert.assertNotNull("leaf private key must be parseable", key);

        java.security.cert.CertificateFactory factory =
                java.security.cert.CertificateFactory.getInstance("X.509");
        java.security.cert.Certificate leaf;
        try (InputStream is = new FileInputStream(
                CERT_DIR + "quic-leaf-cert.pem")) {
            leaf = factory.generateCertificate(is);
        }
        java.security.cert.Certificate ca;
        try (InputStream is = new FileInputStream(
                CERT_DIR + "quic-ca-cert.pem")) {
            ca = factory.generateCertificate(is);
        }

        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("leaf", key, "changeit".toCharArray(),
                new java.security.cert.Certificate[] { leaf, ca });

        java.nio.file.Path bundle = tempFile("quic-leaf-chain", ".pkcs12");
        try (OutputStream os = new FileOutputStream(bundle.toFile())) {
            ks.store(os, "changeit".toCharArray());
        }
        return bundle.toAbsolutePath().toString();
    }


    private java.nio.file.Path tempFile(String prefix, String suffix)
            throws Exception {
        java.nio.file.Path tempDir = java.nio.file.Paths.get(
                System.getProperty("tomcat.test.temp"));
        java.nio.file.Files.createDirectories(tempDir);
        return java.nio.file.Files.createTempFile(tempDir, prefix, suffix);
    }


    private java.security.PrivateKey readPkcs8PrivateKey(String algorithm)
            throws java.security.GeneralSecurityException, java.io.IOException {
        byte[] pem = java.nio.file.Files.readAllBytes(
                new File(CERT_DIR + "quic-leaf-key.pem").toPath());
        String text = new String(pem, StandardCharsets.US_ASCII);
        String base64 = text.replaceAll("-----[A-Z ]+-----", "")
                .replaceAll("\\s", "");
        byte[] der = java.util.Base64.getMimeDecoder().decode(base64);
        return java.security.KeyFactory.getInstance(algorithm).generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(der));
    }


    /**
     * Runs the certificate client.
     *
     * @param path      the request path
     * @param sni       the SNI host name, or {@code null} to send no SNI
     * @param authority the value for the :authority pseudo-header, or
     *                  {@code null} for the default ({@code <sni>:<port>})
     * @param caFile    the CA file for verification, or {@code null} to
     *                  disable verification
     * @param sigpref   the preferred key type ("ec" or "rsa"), or
     *                  {@code null} for the default order
     * @return the parsed client output
     */
    private CertClientResult certGet(String path, String sni, String authority,
            String caFile, String sigpref) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(PYTHON);
        command.add(CERT_CLIENT_SCRIPT);
        command.add("get");
        command.add("127.0.0.1");
        command.add(Integer.toString(port));
        command.add(path);
        command.add("--sni");
        command.add(sni != null ? sni : "");
        if (authority != null) {
            command.add("--authority");
            command.add(authority);
        }
        if (caFile != null) {
            command.add("--ca");
            command.add(new File(caFile).getAbsolutePath());
        }
        if (sigpref != null) {
            command.add("--sigpref");
            command.add(sigpref);
        }

        Process process = new ProcessBuilder(command).start();
        CertClientResult result = new CertClientResult();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(),
                        StandardCharsets.ISO_8859_1))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int idx = line.indexOf('=');
                if (idx > 0) {
                    result.fields.put(line.substring(0, idx),
                            line.substring(idx + 1));
                }
            }
        }
        result.exitCode = process.waitFor();
        if (result.exitCode != 0) {
            result.stderr = readAll(process.getErrorStream());
        }
        return result;
    }


    private static SSLHostConfig pemHost(String hostName, String certFile,
            String keyFile) {
        return pemHost(hostName, certFile, keyFile, null);
    }


    private static SSLHostConfig pemHost(String hostName, String certFile,
            String keyFile, String chainFile) {
        SSLHostConfig host = new SSLHostConfig();
        if (hostName != null) {
            host.setHostName(hostName);
        }
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate =
                pemCertificate(host, certFile, keyFile);
        if (chainFile != null) {
            certificate.setCertificateChainFile(
                    new File(CERT_DIR + chainFile).getAbsolutePath());
        }
        host.addCertificate(certificate);
        return host;
    }


    private static SSLHostConfig keystoreHost(String hostName,
            String storeFile, String password, String storeType,
            String alias) {
        SSLHostConfig host = new SSLHostConfig();
        if (hostName != null) {
            host.setHostName(hostName);
        }
        host.setSslProtocol("tls");
        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(host, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateKeystoreFile(
                new File(CERT_DIR + storeFile).getAbsolutePath());
        certificate.setCertificateKeystorePassword(password);
        certificate.setCertificateKeystoreType(storeType);
        certificate.setCertificateKeyAlias(alias);
        host.addCertificate(certificate);
        return host;
    }


    private static SSLHostConfigCertificate pemCertificate(
            SSLHostConfig host, String certFile, String keyFile) {
        return pemCertificate(host, certFile, keyFile,
                SSLHostConfigCertificate.Type.UNDEFINED);
    }


    private static SSLHostConfigCertificate pemCertificate(
            SSLHostConfig host, String certFile, String keyFile,
            SSLHostConfigCertificate.Type type) {
        SSLHostConfigCertificate certificate =
                new SSLHostConfigCertificate(host, type);
        certificate.setCertificateFile(
                new File(CERT_DIR + certFile).getAbsolutePath());
        certificate.setCertificateKeyFile(
                new File(CERT_DIR + keyFile).getAbsolutePath());
        return certificate;
    }


    /**
     * The result of running the certificate client.
     */
    private static class CertClientResult {

        final Map<String, String> fields = new LinkedHashMap<>();
        int exitCode;
        String stderr;
    }
}

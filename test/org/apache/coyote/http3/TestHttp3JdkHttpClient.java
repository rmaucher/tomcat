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

import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

/**
 * Interoperability tests against the JDK HttpClient's independent HTTP/3
 * stack (JEP 517, JDK 26): ALPN negotiation, the request/response exchange,
 * header, query and body paths, including a large request body that spans
 * several DATA frames and flow control credit windows.
 *
 * <p>The tests are skipped when the JDK does not provide HTTP/3 support in
 * the HttpClient (older than JDK 26).</p>
 */
public class TestHttp3JdkHttpClient extends Http3TestBase {

    /*
     * JDK 26 (JEP 517) added HTTP/3 to the HttpClient API. The tests are
     * compiled against the Java 21 API, so everything HTTP/3 specific - the
     * HTTP_3 version constant, the (new in 26) HttpOption type, its
     * H3_DISCOVERY option and HTTP_3_URI_ONLY mode, and the (new in 26)
     * Builder.setOption method - is resolved at run time. They are null on
     * older JDKs, where the tests skip.
     */
    private static final HttpClient.Version HTTP_3 = resolveHttp3Version();

    private static final Object H3_DISCOVERY = resolveH3DiscoveryOption();

    private static final Object HTTP_3_URI_ONLY = resolveUriOnlyMode();

    private static final Method SET_OPTION = resolveSetOption();

    private static final int LARGE_BODY_LENGTH = 1024 * 1024;


    private static HttpClient.Version resolveHttp3Version() {
        try {
            return HttpClient.Version.valueOf("HTTP_3");
        } catch (IllegalArgumentException e) {
            // JDK older than 26
            return null;
        }
    }


    private static Object resolveH3DiscoveryOption() {
        try {
            return Class.forName("java.net.http.HttpOption")
                    .getField("H3_DISCOVERY").get(null);
        } catch (ReflectiveOperationException e) {
            // JDK older than 26
            return null;
        }
    }


    private static Object resolveUriOnlyMode() {
        try {
            Class<?> modeClass = Class.forName(
                    "java.net.http.HttpOption$Http3DiscoveryMode");
            for (Object constant : modeClass.getEnumConstants()) {
                if ("HTTP_3_URI_ONLY".equals(((Enum<?>) constant).name())) {
                    return constant;
                }
            }
        } catch (ClassNotFoundException e) {
            // JDK older than 26
        }
        return null;
    }


    private static Method resolveSetOption() {
        try {
            return HttpRequest.Builder.class.getMethod("setOption",
                    Class.forName("java.net.http.HttpOption"), Object.class);
        } catch (ReflectiveOperationException e) {
            // JDK older than 26
            return null;
        }
    }


    /*
     * The JDK QUIC stack only accepts the SunJSSE trust manager
     * implementation: HttpClientImpl rejects any SSLContext whose trust
     * manager is not a sun.security.ssl.X509TrustManagerImpl with
     * "HTTP3 is not supported", so a custom (e.g. trust-all) trust manager
     * is not an option. Obtain an X509TrustManagerImpl the supported way
     * instead: a TrustManagerFactory initialised with a trust store that
     * contains the server's self-signed test certificate. Endpoint
     * identification stays on (the test certificate covers 127.0.0.1).
     */
    private SSLContext clientSslContext() throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("server", serverCertificate());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        return sslContext;
    }


    /*
     * The certificate the server presents for the endpoint in use: the leaf
     * of the PKCS12 test keystore for the OpenSSL endpoint, the PEM leaf
     * for the quiche one (see Http3TestBase.defaultTestHostConfig()).
     */
    private X509Certificate serverCertificate() throws Exception {
        if (endpointIsQuiche()) {
            CertificateFactory factory = CertificateFactory.getInstance(
                    "X.509");
            try (InputStream in = Files.newInputStream(
                    Path.of(QUICHE_TEST_CERT_FILE))) {
                return (X509Certificate) factory.generateCertificate(in);
            }
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(Path.of(KEYSTORE))) {
            keyStore.load(in, KEYSTORE_PASSWORD.toCharArray());
        }
        for (String alias : Collections.list(keyStore.aliases())) {
            Certificate certificate = keyStore.getCertificate(alias);
            if (certificate instanceof X509Certificate x509) {
                return x509;
            }
        }
        throw new IllegalStateException(
                "No X.509 certificate found in " + KEYSTORE);
    }


    /**
     * A client that prefers HTTP/3, skipping the test when the JDK does not
     * support it.
     */
    private HttpClient newHttp3Client() throws Exception {
        Assume.assumeTrue(
                "HttpClient HTTP/3 support (JEP 517) requires JDK 26 or "
                        + "later",
                HTTP_3 != null && H3_DISCOVERY != null
                        && HTTP_3_URI_ONLY != null && SET_OPTION != null);
        return HttpClient.newBuilder()
                .sslContext(clientSslContext())
                .version(HTTP_3)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }


    /**
     * A request builder pinned to HTTP/3 for the given path: the
     * {@code HTTP_3_URI_ONLY} discovery mode fails the request instead of
     * downgrading to HTTP/2 or HTTP/1.1, the equivalent of curl's
     * {@code --http3-only}.
     */
    private HttpRequest.Builder newRequest(String path) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(
                URI.create("https://127.0.0.1:" + port + path))
                .timeout(Duration.ofSeconds(CLIENT_TIMEOUT_SECONDS));
        try {
            SET_OPTION.invoke(builder, H3_DISCOVERY, HTTP_3_URI_ONLY);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to apply the "
                    + "H3_DISCOVERY request option", e);
        }
        return builder;
    }


    @Test
    public void testGetOverHttp3() throws Exception {
        startHttp3Server();

        HttpResponse<byte[]> response = newHttp3Client().send(
                newRequest("/echo?msg=jdk")
                        .header("x-jdk-test", "hello-jdk")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofByteArray());

        // The client negotiated h3 over ALPN and the request reached the
        // servlet.
        Assert.assertEquals("unexpected status", 200, response.statusCode());
        Assert.assertEquals("client did not use HTTP/3", HTTP_3,
                response.version());
        String body = new String(response.body(),
                StandardCharsets.ISO_8859_1);
        Assert.assertTrue("method not GET: " + body,
                body.contains("METHOD: GET"));
        Assert.assertTrue("servlet did not see the request header: " + body,
                body.contains("x-jdk-test: hello-jdk"));
        Assert.assertTrue("servlet did not see the query: " + body,
                body.contains("QUERY: msg=jdk"));
    }


    @Test
    public void testResponseBodyOverHttp3() throws Exception {
        startHttp3Server();

        HttpResponse<byte[]> response = newHttp3Client().send(
                newRequest("/simple").GET().build(),
                HttpResponse.BodyHandlers.ofByteArray());

        Assert.assertEquals("unexpected status", 200, response.statusCode());
        Assert.assertEquals("client did not use HTTP/3", HTTP_3,
                response.version());
        Assert.assertEquals("Hello over HTTP/3",
                new String(response.body(), StandardCharsets.ISO_8859_1));
    }


    @Test
    public void testPutOverHttp3() throws Exception {
        startHttp3Server();

        byte[] body = "jdk-put-body".getBytes(StandardCharsets.ISO_8859_1);
        HttpResponse<byte[]> response = newHttp3Client().send(
                newRequest("/echo")
                        .PUT(HttpRequest.BodyPublishers.ofByteArray(body))
                        .build(),
                HttpResponse.BodyHandlers.ofByteArray());

        // PUT body arrives intact through the HTTP/3 DATA frames.
        Assert.assertEquals("unexpected status", 200, response.statusCode());
        Assert.assertEquals("client did not use HTTP/3", HTTP_3,
                response.version());
        String echoed = new String(response.body(),
                StandardCharsets.ISO_8859_1);
        Assert.assertTrue("method not PUT: " + echoed,
                echoed.contains("METHOD: PUT"));
        Assert.assertTrue("PUT body missing: " + echoed,
                echoed.contains("BODY: 12:jdk-put-body"));
    }


    /*
     * A one MiB request body, well beyond a single HTTP/3 DATA frame and
     * one round of flow control credit, to exercise request body reassembly
     * across frames and windows.
     */
    @Test
    public void testPutLargeBodyOverHttp3() throws Exception {
        startHttp3Server();

        byte[] body = new byte[LARGE_BODY_LENGTH];
        for (int i = 0; i < body.length; i++) {
            body[i] = (byte) (i % 251);
        }

        HttpResponse<byte[]> response = newHttp3Client().send(
                newRequest("/echo")
                        .PUT(HttpRequest.BodyPublishers.ofByteArray(body))
                        .build(),
                HttpResponse.BodyHandlers.ofByteArray());

        Assert.assertEquals("unexpected status", 200, response.statusCode());
        Assert.assertEquals("client did not use HTTP/3", HTTP_3,
                response.version());
        String echoed = new String(response.body(),
                StandardCharsets.ISO_8859_1);
        Assert.assertTrue("method not PUT", echoed.contains("METHOD: PUT"));
        Assert.assertTrue("large PUT body not received intact", echoed
                .contains("BODY: " + body.length + ":" + new String(body,
                        StandardCharsets.ISO_8859_1)));
    }
}

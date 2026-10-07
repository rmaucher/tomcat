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

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.net.SSLSupport;

/**
 * End-to-end coverage of the QUIC TLS request attributes served by
 * {@code QuicOpenSSLSocketWrapper.QuicSSLSupport}: reading any TLS request
 * attribute in a servlet triggers the population of all of them from the
 * SSLSupport of the stream's socket wrapper (cipher suite, TLS version,
 * session id, peer certificate chain and the negotiated ALPN protocol). A
 * second request on the same connection exercises the per-connection
 * caches shared by the streams of a connection.
 */
public class TestQuicSslAttributes extends Http3TestBase {

    public static class SslAttributeServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req,
                HttpServletResponse resp) throws IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding("UTF-8");
            PrintWriter writer = resp.getWriter();
            dumpAttr(writer, req, "secure_protocol", SSLSupport.SECURE_PROTOCOL_KEY);
            dumpAttr(writer, req, "cipher_suite", SSLSupport.CIPHER_SUITE_KEY);
            dumpAttr(writer, req, "ssl_session_id", SSLSupport.SESSION_ID_KEY);
            dumpAttr(writer, req, "key_size", SSLSupport.KEY_SIZE_KEY);
            dumpAttr(writer, req, "negotiated",
                    SSLSupport.REQUESTED_PROTOCOL_VERSIONS_KEY);
            dump(writer, "session_mgr", req.getAttribute(SSLSupport.SESSION_MGR));
            Object chain = req.getAttribute(SSLSupport.CERTIFICATE_KEY);
            writer.println("cert_chain_len=" + (chain == null ? "null"
                    : Integer.toString(((X509Certificate[]) chain).length)));
        }


        private void dumpAttr(PrintWriter writer, HttpServletRequest req,
                String label, String attrName) {
            dump(writer, label, req.getAttribute(attrName));
        }


        private void dump(PrintWriter writer, String label, Object value) {
            writer.println(label + "=" +
                    (value == null ? "null" : value.toString()));
        }
    }


    private static Map<String,String> parseDump(String body) {
        Map<String,String> result = new HashMap<>();
        for (String line : body.split("\n")) {
            int index = line.indexOf('=');
            if (index > 0) {
                result.put(line.substring(0, index), line.substring(index + 1));
            }
        }
        return result;
    }


    @Test
    public void testSslRequestAttributes() throws Exception {
        // The quiche phase-1 transport does not expose the negotiated TLS
        // cipher suite, so the cipher-sensitive attribute assertions below
        // are OpenSSL-endpoint only.
        Assume.assumeTrue(endpointSupportsSni());
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "sslinfo", new SslAttributeServlet());
            ctxt.addServletMapping("/sslinfo", "sslinfo");
        });

        Http3Response response = get("/sslinfo");
        validateStatus(response, 200);
        Map<String,String> attributes = parseDump(response.getBodyAsString());

        // QUIC runs on TLS 1.3; version and cipher suite are resolved via
        // the poll-thread hop into OpenSSL.
        Assert.assertEquals("unexpected secure_protocol: " + attributes,
                "TLSv1.3", attributes.get("secure_protocol"));
        String cipher = attributes.get("cipher_suite");
        Assert.assertNotNull("cipher_suite must be resolved: " + attributes,
                cipher);
        Assert.assertTrue("unexpected cipher suite " + cipher,
                cipher.startsWith("TLS_"));
        // TLS 1.3 / QUIC sessions carry no legacy session identifier: an
        // empty string is a valid resolution (null would mean the
        // attribute was never populated).
        Assert.assertNotNull("ssl_session_id must be populated: " + attributes,
                attributes.get("ssl_session_id"));

        // ALPN: the negotiated protocol of the QUIC connection.
        Assert.assertEquals("unexpected negotiated protocol: " + attributes,
                "h3", attributes.get("negotiated"));

        // The SSLSupport instance itself is exposed to the application.
        Assert.assertNotEquals("ssl_session_mgr must be present: " + attributes,
                "null", attributes.get("session_mgr"));

        // No client authentication is requested: the peer chain is
        // resolved (empty) rather than left unparsed.
        Assert.assertEquals("unexpected peer chain: " + attributes,
                "0", attributes.get("cert_chain_len"));

        // Known gap: the OpenSSL QUIC bindings do not expose the key size.
        Assert.assertEquals("key_size is expected to be unavailable: " +
                        attributes,
                "null", attributes.get("key_size"));
    }


    @Test
    public void testSslRequestAttributesCachedPerConnection()
            throws Exception {
        // As above: the per-connection cipher/session caching assertions
        // require the endpoint to expose the negotiated cipher suite, which
        // the quiche phase-1 transport does not.
        Assume.assumeTrue(endpointSupportsSni());
        startHttp3Server(ctxt -> {
            Tomcat.addServlet(ctxt, "sslinfo", new SslAttributeServlet());
            ctxt.addServletMapping("/sslinfo", "sslinfo");
        });

        // Two requests on one connection: the cipher suite and session id
        // are cached on the connection once the first stream resolves
        // them, so the second dump must match without a poll-thread hop.
        ClientOutput output = runClient(clientCommand("get", "127.0.0.1",
                Integer.toString(port), "/sslinfo", "--requests", "2"),
                CLIENT_TIMEOUT_SECONDS);

        int bodies = 0;
        Map<String,String> first = null;
        Map<String,String> last = null;
        for (String line : output.getLines()) {
            if (!line.startsWith("BODY=")) {
                continue;
            }
            String body = new String(Base64.getDecoder().decode(
                    line.substring("BODY=".length())), StandardCharsets.UTF_8);
            Map<String,String> dump = parseDump(body);
            // Attribute lines only appear in the servlet output.
            if (!dump.containsKey("secure_protocol")) {
                continue;
            }
            bodies++;
            if (first == null) {
                first = dump;
            }
            last = dump;
        }

        Assert.assertEquals("Expected two servlet dispatches on one " +
                "connection", 2, bodies);
        Assert.assertNotNull(first);
        Assert.assertNotEquals("Cipher suite must be resolved, not null",
                "null", last.get("cipher_suite"));
        Assert.assertEquals("Cipher suite must match across the connection's " +
                        "streams",
                first.get("cipher_suite"), last.get("cipher_suite"));
        Assert.assertEquals("Session id must match across the connection's " +
                        "streams",
                first.get("ssl_session_id"), last.get("ssl_session_id"));
        Assert.assertEquals("Negotiated protocol must match across the " +
                        "connection's streams",
                first.get("negotiated"), last.get("negotiated"));
    }
}

#!/usr/bin/env python3
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
HTTP/3 certificate test client for the Tomcat test suite, based on aioquic.

Connects to a QUIC server, reports the certificate presented by the server
(subject, SPKI fingerprint, public key type, number of certificates in the
chain) and optionally performs an HTTP/3 GET request, reporting the status
or the HTTP/3 stream error code if the stream is reset.

Machine readable output (one field per line):

    PEER_SUBJECT=<RFC 4514 subject>
    PEER_FP=<SHA-256 of the DER encoded peer certificate>
    PEER_PUBKEY=<public key type, e.g. RSAPublicKey>
    PEER_CERT_COUNT=<number of certificates in the chain>
    STATUS=<response status>            (if the request completed)
    STREAM_ERROR=<HTTP/3 error code>    (if the stream was reset)
    OK

Commands:

    get HOST PORT PATH [--sni NAME] [--authority NAME] [--ca FILE]
                       [--sigpref ec|rsa]
        Connect (using NAME as the SNI host name, defaulting to HOST),
        report the peer certificate and perform a GET request using NAME
        (or --authority) in the :authority pseudo-header.
        --ca FILE verifies the peer certificate chain against FILE.
        --sigpref reorders the offered signature algorithms so the server
        is forced to present an EC or an RSA certificate when it holds
        both.

Exit code is 0 when the connection was established and the requested
information was collected (a stream reset is reported, not an error),
1 otherwise (details on stderr).

Requires: Python >= 3.9 and aioquic (pip install aioquic).
"""

import argparse
import asyncio
import hashlib
import ssl
import sys

from cryptography.hazmat.primitives import serialization

import aioquic.h3.connection
import aioquic.h3.events
import aioquic.quic.configuration
import aioquic.quic.events
from aioquic.asyncio import QuicConnectionProtocol, connect

TIMEOUT = 10.0


class StreamResetError(Exception):
    """Raised when the remote peer resets the request stream."""

    def __init__(self, error_code):
        super().__init__(f"stream reset with error code {error_code}")
        self.error_code = error_code


class H3CertClientProtocol(QuicConnectionProtocol):
    """QUIC protocol subclass that speaks HTTP/3 and inspects the
    peer certificate."""

    def __init__(self, quic, stream_handler=None, authority=b"localhost:443"):
        super().__init__(quic, stream_handler)
        self._h3 = aioquic.h3.connection.H3Connection(quic)
        self._authority = authority
        self._responses = {}

    def request_get(self, path):
        stream_id = self._quic.get_next_available_stream_id()
        future = asyncio.get_running_loop().create_future()
        self._responses[stream_id] = {
            "headers": None,
            "data": bytearray(),
            "future": future,
        }
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", self._authority),
            (b":path", path.encode("ascii")),
        ]
        self._h3.send_headers(stream_id=stream_id, headers=headers,
                              end_stream=True)
        self.transmit()
        return future

    def quic_event_received(self, event):
        # Note: super().quic_event_received() is deliberately NOT called
        # (see http3_client.py).
        if isinstance(event, aioquic.quic.events.ConnectionTerminated):
            for response in self._responses.values():
                if not response["future"].done():
                    response["future"].set_exception(
                        ConnectionError("QUIC connection terminated"))
            return
        if isinstance(event, aioquic.quic.events.StreamReset):
            response = self._responses.get(event.stream_id)
            if response is not None and not response["future"].done():
                response["future"].set_exception(
                    StreamResetError(event.error_code))
            return
        for h3_event in self._h3.handle_event(event):
            response = self._responses.get(h3_event.stream_id)
            if response is None:
                continue
            if isinstance(h3_event, aioquic.h3.events.HeadersReceived):
                response["headers"] = h3_event.headers
                if h3_event.stream_ended:
                    self._complete(response)
            elif isinstance(h3_event, aioquic.h3.events.DataReceived):
                response["data"].extend(h3_event.data)
                if h3_event.stream_ended:
                    self._complete(response)

    def _complete(self, response):
        future = response["future"]
        if not future.done():
            future.set_result((response["headers"], bytes(response["data"])))


def _make_client_protocol(authority):
    def factory(quic, stream_handler=None):
        return H3CertClientProtocol(quic, stream_handler, authority)
    return factory


def _reorder_signature_algorithms(pref):
    import aioquic.tls as aioquic_tls
    original = aioquic_tls.Context.__init__

    def patched(self, *args, **kwargs):
        original(self, *args, **kwargs)
        sa = aioquic_tls.SignatureAlgorithm
        ec = [sa.ECDSA_SECP256R1_SHA256, sa.ECDSA_SECP384R1_SHA384]
        rsa = [sa.RSA_PSS_RSAE_SHA256, sa.RSA_PKCS1_SHA256,
               sa.RSA_PSS_RSAE_SHA384, sa.RSA_PKCS1_SHA384, sa.RSA_PKCS1_SHA1]
        other = [a for a in self._signature_algorithms
                 if a not in ec and a not in rsa]
        if pref == "rsa":
            self._signature_algorithms = rsa + ec + other
        else:
            self._signature_algorithms = ec + rsa + other

    aioquic_tls.Context.__init__ = patched


async def h3_get(host, port, path, sni, authority, ca_file, sigpref):
    configuration = aioquic.quic.configuration.QuicConfiguration(is_client=True)
    configuration.alpn_protocols = ["h3"]
    # A None server name means no SNI extension is sent
    configuration.server_name = sni
    if ca_file:
        configuration.verify_mode = ssl.CERT_REQUIRED
        configuration.cafile = ca_file
    else:
        configuration.verify_mode = ssl.CERT_NONE
    if sigpref:
        _reorder_signature_algorithms(sigpref)

    async with connect(host, port, configuration=configuration,
                       create_protocol=_make_client_protocol(
                           authority.encode("ascii"))) as client:
        quic = client._quic
        # Wait for the TLS handshake so the peer certificate is available
        for _ in range(int(TIMEOUT / 0.1)):
            if quic._handshake_complete:
                break
            await asyncio.sleep(0.1)
        else:
            raise ConnectionError("TLS handshake did not complete")

        tls = quic.tls
        cert = tls._peer_certificate
        if cert is None:
            raise ConnectionError("no peer certificate available")
        pub = cert.public_key()
        der = cert.public_bytes(serialization.Encoding.DER)
        # _peer_certificate_chain holds the chain as sent by the peer
        # excluding the leaf certificate itself
        chain = getattr(tls, "_peer_certificate_chain", None)
        peer_cert_count = 1 + (len(chain) if chain else 0)
        print(f"PEER_SUBJECT={cert.subject.rfc4514_string()}")
        print(f"PEER_FP={hashlib.sha256(der).hexdigest()}")
        print(f"PEER_PUBKEY={type(pub).__name__}")
        print(f"PEER_CERT_COUNT={peer_cert_count}")

        try:
            headers, body = await asyncio.wait_for(
                client.request_get(path), TIMEOUT)
        except StreamResetError as exc:
            print(f"STREAM_ERROR={exc.error_code}")
            client.close()
            return
        status = None
        for name, value in headers:
            if name == b":status":
                status = value.decode("ascii")
        print(f"STATUS={status}")
        client.close()


def cmd_get(args):
    # --sni defaults to the host argument; pass an empty value to send no SNI
    sni = args.sni if args.sni is not None else args.host
    if sni == "":
        sni = None
    authority = args.authority if args.authority else f"{sni or args.host}:{args.port}"
    try:
        asyncio.run(asyncio.wait_for(
            h3_get(args.host, args.port, args.path, sni, authority,
                   args.ca, args.sigpref), 2 * TIMEOUT))
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print("OK")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="HTTP/3 certificate test client for the Tomcat test suite "
                    "(aioquic)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_get = sub.add_parser("get",
                           help="inspect the peer certificate and perform a GET")
    p_get.add_argument("host")
    p_get.add_argument("port", type=int)
    p_get.add_argument("path")
    p_get.add_argument("--sni", default=None,
                       help="SNI host name (defaults to the host argument)")
    p_get.add_argument("--authority", default=None,
                       help="value for the :authority pseudo-header "
                            "(defaults to <sni>:<port>)")
    p_get.add_argument("--ca", default=None,
                       help="CA file to verify the peer certificate chain")
    p_get.add_argument("--sigpref", choices=["ec", "rsa"], default=None,
                       help="preferred certificate key type")

    args = parser.parse_args()
    if args.command == "get":
        return cmd_get(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
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
HTTP/3 test client for the Tomcat test suite, based on aioquic.

The client speaks HTTP/3 (RFC 9114) over QUIC (RFC 9000) and prints a
machine readable result that JUnit tests can assert on.

Two client modes are provided:

1. The normal mode ("get") uses the full aioquic HTTP/3 stack. It is used
   for functional tests.

2. The raw mode ("raw") uses only the aioquic QUIC/TLS layers and manages
   the HTTP/3 streams (control stream, QPACK streams, request streams)
   manually. It is used for specification conformance tests where
   ill-formed frames, field sections and stream types need to be sent.
   Raw payloads are supplied base64 encoded.

Machine readable output lines:

    STATUS=<code>                  response status
    HEADER:name=value              response header
    TRAILER:name=value             response trailer
    BODY=<base64>                  response body
    SETTINGS:<id>=<value>          server SETTINGS frame values
    CTRL:SETTINGS:<id>=<value>     frame on the server control stream
    CTRL:GOAWAY=<id>               GOAWAY frame on the server control stream
    CTRL:FRAME=<hex>:<hex>         other frames on the server control stream
    STREAM_ERROR=<code>            the (single) request stream was reset
    STREAM_RESET=<stream>=<code>   another stream (or, with --streams N,
                                   a request stream) was reset
    RESPONSE index=<i>             with --streams N, groups the response
                                   lines per request stream
    CONNECTION_ERROR=<code>        the connection was closed with an error
    CONNECTION_CLOSED              the connection was closed cleanly
    DEC_ACK=<stream>               Section Acknowledgment on the client
                                   QPACK decoder stream (raw mode)
    DEC_CANC=<stream>              Stream Cancellation on the client QPACK
                                   decoder stream (raw mode)
    DEC_RIC=<inc>                  Insert Count Increment on the client
                                   QPACK decoder stream (raw mode)
    CLOSED_WITH_ERROR=<code>       raw mode with --close-error
    ABANDONED                      raw mode with --abandon (abrupt exit)
    OK                             the request completed

Exit code is 0 unless the client itself fails (details on stderr).

Commands:

    get HOST PORT PATH [--method M] [--header "Name: value"]...
        [--trailer "Name: value"]... [--body <b64>] [--requests N]
        [--cancel-after BYTES] [--authority NAME] [--sni NAME]
        [--ca FILE] [--timeout SECS]
        Perform HTTP/3 requests. With --cancel-after the request stream is
        reset (H3_REQUEST_CANCELLED) once at least BYTES response body bytes
        have been received and the partial response is reported.

    raw HOST PORT [--control <b64>] [--fin-control] [--no-control]
        [--no-qpack-streams] [--decoder <b64>]
        [--uni "TYPE[,data_b64][,1]"]...
        [--headers <b64>] [--data <b64>] [--frame <b64>]...
        [--frame-after-data <b64>]...
        [--trailers <b64>] [--streams N] [--no-request] [--no-fin]
        [--frames-after-wait <b64>]... [--wait SECS]
        [--close-error CODE] [--abandon]
        [--authority NAME] [--sni NAME] [--ca FILE] [--timeout SECS]
        Manually managed HTTP/3 connection. With --streams N the request
        payload is sent on N concurrent bidirectional streams. With
        --close-error the connection is closed with a CONNECTION_CLOSE
        frame carrying the given transport error code; with --abandon the
        process dies without sending a CONNECTION_CLOSE.

    selftest
        Start an in-process aioquic HTTP/3 echo server on 127.0.0.1 and
        verify the client against it. No Tomcat server required.

Requires: Python >= 3.9 and aioquic (pip install aioquic).
"""

import argparse
import asyncio
import base64
import datetime
import ipaddress
import os
import socket
import ssl
import sys
import tempfile

import aioquic.h3.connection
import aioquic.h3.events
import aioquic.quic.events
from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import stream_is_unidirectional
from aioquic.quic.configuration import QuicConfiguration
import pylsqpack

DEFAULT_TIMEOUT = 10.0

# HTTP/3 frame types (RFC 9114 Section 7.2, Table 2)
H3_DATA = 0x00
H3_HEADERS = 0x01
H3_CANCEL_PUSH = 0x03
H3_SETTINGS = 0x04
H3_PUSH_PROMISE = 0x05
H3_GOAWAY = 0x07
H3_MAX_PUSH_ID = 0x0D

# HTTP/3 stream types (RFC 9114 Section 6.2, Table 3)
STREAM_TYPE_CONTROL = 0x00
STREAM_TYPE_QPACK_ENCODER = 0x02
STREAM_TYPE_QPACK_DECODER = 0x03


def encode_varint(value):
    """Encode a QUIC variable length integer (RFC 9000 Section 16)."""
    if value < 0x40:
        return bytes([value])
    if value < 0x1000:
        return bytes([0x40 | (value >> 8), value & 0xFF])
    if value < 0x40000000:
        return bytes([0x80 | (value >> 24), (value >> 16) & 0xFF,
                      (value >> 8) & 0xFF, value & 0xFF])
    return (b"\xc0" + value.to_bytes(7, byteorder="big"))


def decode_varint(data, offset):
    """Decode a QUIC variable length integer. Returns (value, new offset)."""
    first = data[offset]
    length = 1 << (first >> 6)
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[offset + i]
    return value, offset + length


def encode_h3_frame(frame_type, payload):
    """Encode an HTTP/3 frame: type (varint) + length (varint) + payload."""
    return encode_varint(frame_type) + encode_varint(len(payload)) + payload


def parse_h3_frames(data):
    """Parse HTTP/3 frames. Returns a list of (frame_type, payload)."""
    frames = []
    offset = 0
    while offset < len(data):
        frame_type, offset = decode_varint(data, offset)
        length, offset = decode_varint(data, offset)
        if offset + length > len(data):
            break
        frames.append((frame_type, data[offset:offset + length]))
        offset += length
    return frames


def parse_settings(payload):
    """Parse a SETTINGS frame payload. Returns {setting_id: value}."""
    settings = {}
    offset = 0
    while offset < len(payload):
        setting_id, offset = decode_varint(payload, offset)
        value, offset = decode_varint(payload, offset)
        settings[setting_id] = value
    return settings


def parse_goaway(payload):
    """Parse a GOAWAY frame payload. Returns the last stream ID."""
    if not payload:
        return None
    value, _ = decode_varint(payload, 0)
    return value


def b64d(text):
    return base64.b64decode(text) if text else b""


def make_configuration(host, port, authority, sni, ca):
    configuration = QuicConfiguration(is_client=True)
    configuration.alpn_protocols = ["h3"]
    configuration.server_name = sni if sni is not None else None
    if ca is not None:
        configuration.verify_mode = ssl.CERT_REQUIRED
        configuration.load_verify_locations(ca)
    else:
        # Tests run against a self-signed cert by default.
        configuration.verify_mode = ssl.CERT_NONE
    return configuration


# ---------------------------------------------------------------------------
# Normal mode: full aioquic HTTP/3 stack
# ---------------------------------------------------------------------------

class H3ClientProtocol(QuicConnectionProtocol):
    """QUIC protocol subclass that speaks HTTP/3 on top."""

    def __init__(self, quic, stream_handler=None, authority=b"localhost:443"):
        super().__init__(quic, stream_handler)
        self._h3 = aioquic.h3.connection.H3Connection(quic)
        self._authority = authority
        # stream_id -> response state
        self._responses = {}
        self.stream_error = None
        self.connection_error = None

    def request(self, method, path, extra_headers=None, body=None,
                extra_trailers=None, cancel_after=None):
        """
        Send an HTTP/3 request.

        Returns a Future that resolves to (header_blocks, body) when the
        response stream is complete, or raises if the connection is
        terminated. header_blocks is the list of all HEADERS frames
        received on the stream (interim responses, final response,
        trailers). When cancel_after is set the request stream is reset
        with H3_REQUEST_CANCELLED (RFC 9114 Section 4.2) once at least
        that many response body bytes have been received and the Future
        resolves with the partial body.
        """
        stream_id = self._quic.get_next_available_stream_id()
        future = asyncio.get_running_loop().create_future()
        self._responses[stream_id] = {
            "blocks": [],
            "data": bytearray(),
            "future": future,
            "cancel_after": cancel_after,
            "cancelled": False,
        }
        headers = [
            (b":method", method.encode("ascii")),
            (b":scheme", b"https"),
            (b":authority", self._authority),
            (b":path", path.encode("ascii")),
        ]
        for name, value in (extra_headers or []):
            headers.append((name.encode("ascii"), value.encode("ascii")))
        if body is None:
            if extra_trailers:
                # Send headers first, trailers after the (empty) body.
                self._h3.send_headers(stream_id=stream_id, headers=headers)
                self.transmit()
                self._h3.send_headers(stream_id=stream_id,
                                      headers=[(n.encode("ascii"),
                                                v.encode("ascii"))
                                               for n, v in extra_trailers],
                                      end_stream=True)
            else:
                self._h3.send_headers(stream_id=stream_id, headers=headers,
                                      end_stream=True)
            self.transmit()
        else:
            self._h3.send_headers(stream_id=stream_id, headers=headers)
            self._h3.send_data(stream_id=stream_id, data=body,
                               end_stream=not extra_trailers)
            if extra_trailers:
                self._h3.send_headers(stream_id=stream_id,
                                      headers=[(n.encode("ascii"),
                                                v.encode("ascii"))
                                               for n, v in extra_trailers],
                                      end_stream=True)
            self.transmit()
        return future

    def quic_event_received(self, event):
        # Note: super().quic_event_received() is deliberately NOT called.
        # The base class implementation creates asyncio stream wrappers for
        # every received QUIC stream; when such a wrapper is closed (or
        # garbage collected) it sends a FIN on the stream, which would
        # corrupt the HTTP/3 response stream. The H3 layer below consumes
        # the stream data instead.
        if isinstance(event, aioquic.quic.events.ConnectionTerminated):
            self.connection_error = event.error_code
            for response in self._responses.values():
                if not response["future"].done():
                    response["future"].set_exception(
                        ConnectionError("QUIC connection terminated"))
            return
        if isinstance(event, aioquic.quic.events.StreamReset):
            if event.stream_id in self._responses:
                self.stream_error = (event.stream_id, event.error_code)
                response = self._responses[event.stream_id]
                if not response["future"].done():
                    response["future"].set_exception(
                        StreamResetError(event.error_code))
            return
        for h3_event in self._h3.handle_event(event):
            response = self._responses.get(h3_event.stream_id)
            if response is None:
                continue
            if isinstance(h3_event, aioquic.h3.events.HeadersReceived):
                response["blocks"].append(h3_event.headers)
                if h3_event.stream_ended:
                    self._complete(response)
            elif isinstance(h3_event, aioquic.h3.events.DataReceived):
                response["data"].extend(h3_event.data)
                if (response["cancel_after"] is not None and
                        not response["cancelled"] and
                        len(response["data"]) >= response["cancel_after"]):
                    response["cancelled"] = True
                    # Client cancels the request (RFC 9114 Section 4.2).
                    self._quic.reset_stream(h3_event.stream_id, 0x109)
                    self.transmit()
                    self._complete(response)
                if h3_event.stream_ended:
                    self._complete(response)

    def _complete(self, response):
        future = response["future"]
        if not future.done():
            future.set_result((response["blocks"], bytes(response["data"])))


class StreamResetError(Exception):
    def __init__(self, error_code):
        super().__init__(f"stream reset with error code {error_code}")
        self.error_code = error_code


def _make_client_protocol(authority):
    def factory(quic, stream_handler=None):
        return H3ClientProtocol(quic, stream_handler, authority)
    return factory


async def h3_requests(host, port, path, method, extra_headers, body,
                      extra_trailers, count, timeout, sni, ca,
                      cancel_after=None):
    """
    Connect to host:port (QUIC/UDP), send HTTP/3 requests and return a
    list of (headers, trailers, body) plus protocol level error markers.
    """
    configuration = make_configuration(host, port, None, sni, ca)

    async with connect(host, port, configuration=configuration,
                       create_protocol=_make_client_protocol(
                           f"{host}:{port}".encode("ascii"))) as client:
        futures = [client.request(method, path, extra_headers, body,
                                  extra_trailers, cancel_after)
                   for _ in range(count)]
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*futures, return_exceptions=True), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"timed out after {timeout} seconds")
        return results, client.stream_error, client.connection_error, \
            client._h3.received_settings


def _print_response(blocks, body, index=None):
    if index is not None:
        print(f"RESPONSE index={index}")
    # Blocks that carry a :status pseudo header are responses (including
    # interim 1xx responses); the final block without a :status carries
    # the trailers.
    for headers in blocks:
        status = None
        for name, value in headers:
            if name == b":status":
                status = value.decode("ascii")
        if status is not None:
            print(f"STATUS={status}")
            for name, value in headers:
                if not name.startswith(b":"):
                    print(f"HEADER:{name.decode('ascii')}"
                          f"={value.decode('latin-1')}")
        else:
            for name, value in headers:
                if not name.startswith(b":"):
                    print(f"TRAILER:{name.decode('ascii')}"
                          f"={value.decode('latin-1')}")
    print(f"BODY={base64.b64encode(body).decode('ascii')}")


def cmd_get(args):
    extra = []
    for header in args.header:
        name, _, value = header.partition(":")
        extra.append((name.strip(), value.strip()))
    trailers = []
    for trailer in args.trailer:
        name, _, value = trailer.partition(":")
        trailers.append((name.strip(), value.strip()))
    body = b64d(args.body) if args.body else None
    try:
        (results, stream_error, connection_error,
         server_settings) = asyncio.run(
              asyncio.wait_for(h3_requests(
                  args.host, args.port, args.path, args.method, extra,
                  body, trailers or None, args.requests, args.timeout,
                  args.sni, args.ca, args.cancel_after),
              timeout=2 * args.timeout))
    except TimeoutError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if server_settings:
        for setting_id, value in sorted(server_settings.items()):
            print(f"SETTINGS:{setting_id}={value}")
    if stream_error is not None:
        print(f"STREAM_ERROR={stream_error[1]}")
    if connection_error is not None:
        print(f"CONNECTION_ERROR={connection_error}")
    # Protocol level errors (stream resets, connection closes) are reported
    # via the markers above, not via the exit code. The exit code only
    # reflects the outcome of the client itself.
    single = args.requests == 1
    for index, result in enumerate(results):
        if isinstance(result, Exception):
            if isinstance(result, StreamResetError):
                print(f"STREAM_ERROR={result.error_code}")
            elif connection_error is not None:
                pass
            else:
                print(f"FAIL: {result}", file=sys.stderr)
                return 1
            continue
        blocks, body_data = result
        if single:
            _print_response(blocks, body_data)
        else:
            _print_response(blocks, body_data, index=index)
    print("OK")
    return 0


# ---------------------------------------------------------------------------
# Raw mode: manual HTTP/3 stream management over aioquic QUIC/TLS
# ---------------------------------------------------------------------------

class RawH3Protocol(QuicConnectionProtocol):
    """
    QUIC protocol subclass that manages the HTTP/3 streams manually.

    Data received on all streams (bidirectional and unidirectional) is
    buffered and reported. No HTTP/3 semantics are applied by aioquic.
    """

    def __init__(self, quic, stream_handler=None):
        super().__init__(quic, stream_handler)
        # stream_id -> bytearray of received data
        self._data = {}
        self._eof = set()
        self.stream_errors = {}
        self.connection_error = None
        self.closed_cleanly = False

    def send(self, stream_id, data=b"", fin=False):
        self._quic.send_stream_data(stream_id, data, end_stream=fin)
        self.transmit()

    def open_stream(self, is_unidirectional):
        return self._quic.get_next_available_stream_id(
            is_unidirectional=is_unidirectional)

    def quic_event_received(self, event):
        # Note: super().quic_event_received() is deliberately NOT called;
        # see H3ClientProtocol for the explanation.
        if isinstance(event, aioquic.quic.events.ConnectionTerminated):
            if event.error_code:
                self.connection_error = event.error_code
            else:
                self.closed_cleanly = True
        elif isinstance(event, aioquic.quic.events.StreamReset):
            self.stream_errors[event.stream_id] = event.error_code
        elif isinstance(event, aioquic.quic.events.StreamDataReceived):
            self._data.setdefault(event.stream_id, bytearray()).extend(
                event.data)
            if event.end_stream:
                self._eof.add(event.stream_id)


def _print_control_stream(data):
    """Print the frames received on the server control stream."""
    for frame_type, payload in parse_h3_frames(data):
        if frame_type == H3_SETTINGS:
            for setting_id, value in sorted(parse_settings(payload).items()):
                print(f"CTRL:SETTINGS:{setting_id}={value}")
        elif frame_type == H3_GOAWAY:
            last_id = parse_goaway(payload)
            print(f"CTRL:GOAWAY={last_id}")
        else:
            print(f"CTRL:FRAME={frame_type:02X}:{payload.hex()}")


def decode_prefix_int(data, offset, n):
    """
    Decode a prefixed integer (RFC 7541 Section 5.1) occupying the low n
    bits of the byte at offset. Returns (value, new offset) or (None,
    offset) when more data is needed.
    """
    if offset >= len(data):
        return None, offset
    first = data[offset]
    max_inline = (1 << n) - 1
    value = first & max_inline
    offset += 1
    if value < max_inline:
        return value, offset
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        value += (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return value, offset
    return None, offset


def _print_decoder_stream(data):
    """
    Print the QPACK decoder instructions received on the client's decoder
    stream (the server acting as decoder): Section Acknowledgment
    (1 + iRP(m=7) stream ID), Stream Cancellation (01 + iRP(m=6) stream
    ID) and Insert Count Increment (00 + iRP(m=6) increment), per RFC 9204
    Section 4.4.
    """
    offset = 0
    while offset < len(data):
        first = data[offset]
        if first & 0x80:
            value, new_offset = decode_prefix_int(data, offset, 7)
            kind = "DEC_ACK"
        elif first & 0xC0 == 0x40:
            value, new_offset = decode_prefix_int(data, offset, 6)
            kind = "DEC_CANC"
        else:
            value, new_offset = decode_prefix_int(data, offset, 6)
            kind = "DEC_RIC"
        if value is None:
            break    # partial instruction at the end of the stream
        print(f"{kind}={value}")
        offset = new_offset


def _print_request_stream(stream_id, data, decoder):
    """Print the response received on a request stream."""
    header_block = 0
    for frame_type, payload in parse_h3_frames(data):
        if frame_type == H3_HEADERS:
            # Use a distinct ID per header block so that the decoder does
            # not confuse the response headers with the trailers.
            try:
                _, headers = decoder.feed_header(stream_id + 1000 *
                                                 header_block, payload)
            except Exception as exc:
                print(f"HEADER_DECODE_ERROR={type(exc).__name__}")
                continue
            header_block += 1
            is_response = any(name == b":status" for name, _ in headers)
            for name, value in headers:
                if name == b":status":
                    print(f"STATUS={value.decode('ascii')}")
                elif not name.startswith(b":"):
                    prefix = "HEADER" if is_response else "TRAILER"
                    print(f"{prefix}:{name.decode('ascii')}"
                          f"={value.decode('latin-1')}")
        elif frame_type == H3_DATA:
            print(f"BODY={base64.b64encode(payload).decode('ascii')}")


async def raw_connection(args):
    configuration = make_configuration(args.host, args.port, None, args.sni,
                                       args.ca)
    host = args.host
    port = args.port

    async with connect(host, port, configuration=configuration,
                       create_protocol=RawH3Protocol) as client:
        # Client control stream (first unidirectional stream, ID 2).
        if not args.no_control:
            stream_id = client.open_stream(is_unidirectional=True)
            control_payload = b64d(args.control) if args.control else \
                encode_h3_frame(H3_SETTINGS, b"")
            client.send(stream_id, encode_varint(STREAM_TYPE_CONTROL) +
                        control_payload, fin=args.fin_control)
        # Client QPACK streams unless disabled.
        deferred_encoder = None
        if not args.no_qpack_streams:
            encoder_id = client.open_stream(is_unidirectional=True)
            # The first encoder instruction MUST be a Set Dynamic Table
            # Capacity instruction (RFC 9204 Section 4.3.1). Capacity 0
            # (byte 0x20 = 001 + iRP(m=5) 0): this client never inserts
            # into the dynamic table. Override with --encoder for probes
            # that send other capacity values or instructions.
            encoder_payload = b64d(args.encoder) if args.encoder else \
                b"\x20"
            if args.encoder_after_request > 0:
                # Open the stream now (send the type varint) but hold the
                # instructions until after the request, so the server
                # receives a field section whose Required Insert Count is
                # not yet satisfied: a blocked stream (RFC 9204
                # Section 2.2.1). The connector must accept blocked
                # streams (qpackBlockedStreams) or it fails the connection
                # with H3_QPACK_DECOMPRESSION_FAILED, as advertised.
                client.send(encoder_id,
                            encode_varint(STREAM_TYPE_QPACK_ENCODER))
                deferred_encoder = (encoder_id, encoder_payload)
            else:
                client.send(encoder_id,
                            encode_varint(STREAM_TYPE_QPACK_ENCODER) +
                            encoder_payload)
            decoder_id = client.open_stream(is_unidirectional=True)
            decoder_payload = b64d(args.decoder) if args.decoder else b""
            client.send(decoder_id,
                        encode_varint(STREAM_TYPE_QPACK_DECODER) +
                        decoder_payload)

        # Give the server a chance to process the encoder stream
        # instructions before the request (with its dynamic references)
        # arrives: QUIC gives no ordering between streams, and the server
        # advertises no blocked-stream capacity by default.
        if args.encoder_delay:
            await asyncio.sleep(args.encoder_delay)
        # Additional unidirectional streams: "TYPE[,data_b64][,fin]".
        for spec in args.uni:
            parts = spec.split(",")
            stream_type = int(parts[0])
            data = b64d(parts[1]) if len(parts) > 1 and parts[1] else b""
            fin = len(parts) > 2 and parts[2] == "1"
            stream_id = client.open_stream(is_unidirectional=True)
            client.send(stream_id, encode_varint(stream_type) + data,
                        fin=fin)
        # Request stream(s): the first N bidirectional streams, IDs 0, 4, ...
        # Note: the stream ID counter only advances once a stream has been
        # written to, so each stream must be opened and written to before
        # the next one is opened.
        decoder = pylsqpack.Decoder(4096, 16)
        request_stream_ids = []
        if not args.no_request:
            for _ in range(max(1, args.streams)):
                stream_id = client.open_stream(is_unidirectional=False)
                request_stream_ids.append(stream_id)
                if args.declared_frame:
                    spec = args.declared_frame.split(",")
                    ftype = int(spec[0], 0)
                    declared = int(spec[1])
                    sent = int(spec[2])
                    client.send(stream_id,
                                encode_varint(ftype) + encode_varint(declared)
                                + b"\0" * sent)
                    # Deliver the declared remainder only after the delay, so
                    # the server sits mid-frame with the frame incomplete.
                    await asyncio.sleep(args.frame_delay)
                    client.send(stream_id, b"\0" * (declared - sent))
                if args.frame:
                    for frame in args.frame:
                        client.send(stream_id, b64d(frame))
                if args.headers is not None:
                    client.send(stream_id,
                                encode_h3_frame(H3_HEADERS,
                                                b64d(args.headers)))
                if args.data is not None:
                    client.send(stream_id,
                                encode_h3_frame(H3_DATA, b64d(args.data)))
                if args.frame_after_data:
                    for frame in args.frame_after_data:
                        client.send(stream_id, b64d(frame))
                if args.trailers is not None:
                    client.send(stream_id,
                                encode_h3_frame(H3_HEADERS,
                                                b64d(args.trailers)),
                                fin=not args.no_fin)
                elif not args.no_fin:
                    client.send(stream_id, b"", fin=True)
                elif args.streams > 1:
                    # No payload at all: still write zero bytes so that the
                    # stream ID counter advances for the next stream.
                    client.send(stream_id, b"", fin=False)

        if deferred_encoder is not None:
            await asyncio.sleep(args.encoder_after_request)
            try:
                client.send(deferred_encoder[0], deferred_encoder[1])
            except Exception:
                # The connection is gone: the server failed it (e.g. the
                # blocked-stream wait timed out) while the instructions
                # were being held back.
                pass

        # Optionally reset the first request stream after the delay, so the
        # server observes a stream reset while the request body (sent with
        # --no-fin) is still incomplete (RFC 9000 Section 2.4,
        # RESET_STREAM). This is the HTTP/3 equivalent of the HTTP/2 tests
        # resetting a request stream with RST_STREAM mid-body.
        if args.reset_request is not None and request_stream_ids:
            await asyncio.sleep(args.reset_request)
            try:
                client._quic.reset_stream(request_stream_ids[0], 0x109)
                client.transmit()
            except Exception:
                # The connection is gone; nothing left to reset.
                pass

        # Wait for the responses and for the connection to settle.
        deadline = args.timeout + (args.wait if args.wait else 0.5)
        start = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start < deadline:
            streams_done = bool(request_stream_ids) and all(
                stream_id in client._eof or
                stream_id in client.stream_errors
                for stream_id in request_stream_ids)
            done = (client.connection_error is not None or
                    client.closed_cleanly or streams_done)
            if done:
                # Allow a short grace period for more data to arrive. Keep it
                # well above the QUIC packet exchange time under load so
                # trailing stream data / the CONNECTION_CLOSE are not missed
                # when the host is busy (test suites share the machine with
                # the server under test).
                await asyncio.sleep(0.5)
                break
            await asyncio.sleep(0.05)

        # Optional second phase: send extra frames on the first request
        # stream after the response completed (e.g. a second HEADERS frame
        # to verify that a concluded stream ignores further data).
        if args.frames_after_wait and request_stream_ids:
            for frame in args.frames_after_wait:
                client.send(request_stream_ids[0], b64d(frame))
            await asyncio.sleep(0.5)

        # Report what was received.
        for stream_id in sorted(client._data):
            if stream_is_unidirectional(stream_id):
                data = bytes(client._data[stream_id])
                if not data:
                    continue
                # The first varint of every unidirectional stream is the
                # stream type (RFC 9114 Section 6.2, RFC 9204 Section 4.2);
                # everything after it is stream-type specific.
                stream_type, offset = decode_varint(data, 0)
                if stream_type == STREAM_TYPE_CONTROL:
                    _print_control_stream(data[offset:])
                elif stream_type == STREAM_TYPE_QPACK_DECODER:
                    # QPACK decoder instructions written by the server
                    # (its Section Acks / Stream Cancellations / Insert
                    # Count Increments, RFC 9204 Section 4.4).
                    _print_decoder_stream(data[offset:])
            elif request_stream_ids and len(request_stream_ids) > 1:
                # Multiple request streams: report per stream, indexed in
                # the order the streams were opened.
                index = request_stream_ids.index(stream_id)
                print(f"RESPONSE index={index}")
                _print_request_stream(stream_id,
                                      bytes(client._data[stream_id]),
                                      decoder)
            else:
                _print_request_stream(stream_id,
                                      bytes(client._data[stream_id]),
                                      decoder)
        for stream_id, error_code in sorted(client.stream_errors.items()):
            # The (single) request stream is reported as STREAM_ERROR to
            # stay compatible with the original output format.
            if len(request_stream_ids) == 1 and \
                    stream_id == request_stream_ids[0]:
                print(f"STREAM_ERROR={error_code}")
            else:
                print(f"STREAM_RESET={stream_id}={error_code}")
        if client.connection_error is not None:
            print(f"CONNECTION_ERROR={client.connection_error}")
        elif client.closed_cleanly:
            print("CONNECTION_CLOSED")

        # Failure-injection modes for server resilience tests.
        if args.close_error is not None:
            # Close the connection with a CONNECTION_CLOSE frame carrying
            # the given transport error code (RFC 9000 Section 10.2.3).
            client._quic.close(error_code=args.close_error)
            client.transmit()
            await asyncio.sleep(0.3)
            print(f"CLOSED_WITH_ERROR={args.close_error}")
        if args.abandon:
            # Die without sending a CONNECTION_CLOSE: the server only
            # notices through its own timers (RFC 9000 Section 10.1).
            print("ABANDONED")
            sys.stdout.flush()
            os._exit(0)
        print("OK")
        return 0


def cmd_raw(args):
    try:
        return asyncio.run(asyncio.wait_for(
            raw_connection(args), timeout=2 * args.timeout + 5))
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Selftest: in-process aioquic HTTP/3 echo server
# ---------------------------------------------------------------------------

class H3ServerProtocol(QuicConnectionProtocol):
    """Minimal in-process HTTP/3 server used by the selftest command."""

    def __init__(self, quic, stream_handler=None):
        super().__init__(quic, stream_handler)
        self._h3 = aioquic.h3.connection.H3Connection(quic)

    def quic_event_received(self, event):
        # As for the client: do not call super() (see H3ClientProtocol).
        for h3_event in self._h3.handle_event(event):
            if isinstance(h3_event, aioquic.h3.events.HeadersReceived):
                self._handle_request(h3_event)

    def _handle_request(self, event):
        headers = dict(event.headers)
        method = headers.get(b":method", b"?").decode("ascii")
        path = headers.get(b":path", b"?").decode("ascii")
        body = f"echo {method} {path}".encode("ascii")
        self._h3.send_headers(
            event.stream_id,
            headers=[(b":status", b"200"), (b"content-type", b"text/plain")])
        self._h3.send_data(event.stream_id, data=body, end_stream=True)
        self.transmit()


def _make_self_signed_cert(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256()))
    key_file = f"{directory}/key.pem"
    cert_file = f"{directory}/cert.pem"
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_file, key_file


def cmd_selftest(_args):
    """
    Prove the client code path works without Tomcat: start an aioquic H3
    echo server in-process and run the client against it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        cert_file, key_file = _make_self_signed_cert(tmp)

        # Find a free UDP port
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        configuration = QuicConfiguration(is_client=False)
        configuration.alpn_protocols = ["h3"]
        configuration.load_cert_chain(cert_file, key_file)

        async def run():
            server = await serve("127.0.0.1", port,
                                  configuration=configuration,
                                  create_protocol=H3ServerProtocol)
            try:
                (results, _, _, _) = await h3_requests(
                    "127.0.0.1", port, "/selftest", "GET", None, None,
                    None, 1, DEFAULT_TIMEOUT, None, None)
            finally:
                server.close()

            blocks, body = results[0]
            status = None
            for headers in blocks:
                for name, value in headers:
                    if name == b":status":
                        status = value.decode("ascii")
            expected = b"echo GET /selftest"
            if status != "200" or body != expected:
                raise AssertionError(
                    f"unexpected response: status={status}, body={body!r}")
            print("SELFTEST-OK")

        try:
            asyncio.run(asyncio.wait_for(run(), timeout=2 * DEFAULT_TIMEOUT))
        except Exception as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="HTTP/3 test client for the Tomcat test suite (aioquic)")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p, with_authority=True):
        if with_authority:
            p.add_argument("--authority", default=None, metavar="NAME",
                           help="value of the :authority pseudo header "
                                "(default HOST:PORT)")
        p.add_argument("--sni", default=None, metavar="NAME",
                       help="TLS server name (default HOST; empty string "
                            "sends no SNI)")
        p.add_argument("--ca", default=None, metavar="FILE",
                       help="CA file; when set the certificate is verified")
        p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                       metavar="SECS", help="operation timeout in seconds")

    p_get = sub.add_parser("get", help="perform HTTP/3 request(s)")
    p_get.add_argument("host")
    p_get.add_argument("port", type=int)
    p_get.add_argument("path")
    p_get.add_argument("--method", default="GET")
    p_get.add_argument("--header", action="append", default=[],
                       metavar="NAME:VALUE",
                       help="extra request header (repeatable)")
    p_get.add_argument("--trailer", action="append", default=[],
                       metavar="NAME:VALUE",
                       help="request trailer (repeatable)")
    p_get.add_argument("--body", default=None, metavar="B64",
                       help="base64 encoded request body")
    p_get.add_argument("--requests", type=int, default=1, metavar="N",
                       help="number of concurrent requests")
    p_get.add_argument("--cancel-after", type=int, default=None,
                       metavar="BYTES",
                       help="reset the request stream "
                            "(H3_REQUEST_CANCELLED) once at least BYTES "
                            "response body bytes have been received")
    add_common(p_get)

    p_raw = sub.add_parser("raw",
                           help="manually managed HTTP/3 connection")
    p_raw.add_argument("host")
    p_raw.add_argument("port", type=int)
    p_raw.add_argument("--control", default=None, metavar="B64",
                       help="base64 payload for the client control stream "
                            "(after the stream type varint); default is a "
                            "valid empty SETTINGS frame")
    p_raw.add_argument("--fin-control", action="store_true",
                       help="FIN the client control stream immediately")
    p_raw.add_argument("--no-control", action="store_true",
                       help="do not open the client control stream")
    p_raw.add_argument("--no-qpack-streams", action="store_true",
                       help="do not open the client QPACK streams")
    p_raw.add_argument("--decoder", default=None, metavar="B64",
                       help="base64 payload appended to the client QPACK "
                            "decoder stream after the stream type varint "
                            "(QPACK decoder instructions)")
    p_raw.add_argument("--encoder", default=None, metavar="B64",
                       help="base64 payload appended to the client QPACK "
                            "encoder stream after the stream type varint, "
                            "replacing the default Set Dynamic Table "
                            "Capacity 0 instruction")
    p_raw.add_argument("--encoder-delay", type=float, default=0.0,
                       metavar="SECS",
                       help="pause this long after sending the QPACK "
                            "encoder instructions, before opening the "
                            "request stream(s), so the server processes "
                            "the instructions first")
    p_raw.add_argument("--encoder-after-request", type=float, default=0.0,
                       metavar="SECS",
                       help="open the QPACK encoder stream at connect time "
                            "but send its instructions only this long after "
                            "the request stream(s), so the server sees a "
                            "blocked stream (requires a connector with "
                            "qpackBlockedStreams set)")
    p_raw.add_argument("--uni", action="append", default=[],
                       metavar="TYPE[,DATA_B64][,FIN]",
                       help="open an additional unidirectional stream "
                            "(repeatable)")
    p_raw.add_argument("--headers", default=None, metavar="B64",
                       help="base64 encoded QPACK field section for the "
                            "request HEADERS frame")
    p_raw.add_argument("--data", default=None, metavar="B64",
                       help="base64 encoded payload for a DATA frame on the "
                            "request stream")
    p_raw.add_argument("--frame", action="append", default=[],
                       metavar="B64",
                       help="base64 encoded raw HTTP/3 frame for the request "
                            "stream (repeatable)")
    p_raw.add_argument("--frame-after-data", action="append", default=[],
                       metavar="B64",
                       help="base64 encoded raw HTTP/3 frame sent on the "
                            "request stream after the --data payload "
                            "(repeatable)")
    p_raw.add_argument("--trailers", default=None, metavar="B64",
                       help="base64 encoded QPACK field section for request "
                            "trailers (second HEADERS frame)")
    p_raw.add_argument("--streams", type=int, default=1, metavar="N",
                       help="open N concurrent bidirectional request "
                            "streams with the same request payload")
    p_raw.add_argument("--no-request", action="store_true",
                       help="do not open the request stream")
    p_raw.add_argument("--no-fin", action="store_true",
                       help="do not FIN the request stream")
    p_raw.add_argument("--declared-frame", default=None,
                       metavar="TYPE,DECLARED,SENT",
                       help="raw frame on the request stream whose header "
                            "declares DECLARED payload bytes but sends only "
                            "SENT now (synthetic zero payload); the remainder "
                            "follows after --frame-delay")
    p_raw.add_argument("--frame-delay", type=float, default=1.0,
                       metavar="SECS",
                       help="delay before delivering the remainder of a "
                            "--declared-frame payload (lets the server sit "
                            "mid-frame with the declared frame incomplete)")
    p_raw.add_argument("--reset-request", type=float, default=None,
                       metavar="SECS",
                       help="reset the first request stream after the given "
                            "delay (RESET_STREAM, RFC 9000 Section 2.4)")


    p_raw.add_argument("--frames-after-wait", action="append", default=[],
                       metavar="B64",
                       help="base64 encoded frames to send on the first "
                            "request stream after the response completed "
                            "(repeatable)")
    p_raw.add_argument("--wait", type=float, default=0.0, metavar="SECS",
                       help="extra time to keep the connection open")
    p_raw.add_argument("--close-error", type=int, default=None,
                       metavar="CODE",
                       help="after the response, close the connection with "
                            "a CONNECTION_CLOSE frame carrying transport "
                            "error CODE")
    p_raw.add_argument("--abandon", action="store_true",
                       help="exit the process abruptly (no CONNECTION_CLOSE) "
                            "after the connection settles")
    add_common(p_raw)

    sub.add_parser("selftest",
                   help="in-process aioquic H3 server + client round trip")

    args = parser.parse_args()
    if args.command == "get":
        return cmd_get(args)
    if args.command == "raw":
        return cmd_raw(args)
    return cmd_selftest(args)


if __name__ == "__main__":
    sys.exit(main())

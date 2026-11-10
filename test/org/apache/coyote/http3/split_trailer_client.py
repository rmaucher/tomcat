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
Send a POST with a small Content-Length body and a trailer section that is
delivered in two chunks. The split forces the connector to stage a partial
trailer section after the body has already been completed; the servlet then
asks for the trailer fields.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import http3_client as h
import pylsqpack
from aioquic.asyncio import connect


async def run(port):
    authority = ("127.0.0.1:" + str(port)).encode("ascii")
    configuration = h.make_configuration("127.0.0.1", port, authority,
                                         "127.0.0.1", None)
    async with connect("127.0.0.1", port, configuration=configuration,
                       create_protocol=h.RawH3Protocol) as client:
        ctrl = client.open_stream(is_unidirectional=True)
        client.send(ctrl, h.encode_varint(h.STREAM_TYPE_CONTROL) +
                    h.encode_h3_frame(h.H3_SETTINGS, b""))
        enc_id = client.open_stream(is_unidirectional=True)
        client.send(enc_id, h.encode_varint(h.STREAM_TYPE_QPACK_ENCODER))
        dec_id = client.open_stream(is_unidirectional=True)
        client.send(dec_id, h.encode_varint(h.STREAM_TYPE_QPACK_DECODER))

        encoder = pylsqpack.Encoder()
        request_stream = client.open_stream(is_unidirectional=False)
        encoder_data, request_block = encoder.encode(request_stream, [
            (b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", authority), (b":path", b"/trailerready"),
            (b"content-length", b"5")])
        client.send(request_stream,
                    h.encode_h3_frame(h.H3_HEADERS, request_block))
        if encoder_data:
            client.send(enc_id, encoder_data)
        client.send(request_stream, h.encode_h3_frame(h.H3_DATA, b"body!"))

        encoder_data, trailer_block = encoder.encode(request_stream, [
            (b"x-checksum", b"abc123")])
        frame = h.encode_varint(h.H3_HEADERS) + \
            h.encode_varint(len(trailer_block)) + trailer_block
        split = max(1, len(frame) // 2)
        client.send(request_stream, frame[:split])
        await asyncio.sleep(0.1)
        client.send(request_stream, frame[split:], fin=True)

        deadline = asyncio.get_event_loop().time() + 5
        while asyncio.get_event_loop().time() < deadline:
            if request_stream in client._eof or \
                    request_stream in client.stream_errors:
                break
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.1)
        data = bytes(client._data.get(request_stream, b""))
        decoder = pylsqpack.Decoder(4096, 16)
        h._print_request_stream(request_stream, data, decoder)
        if client.connection_error is not None:
            print("CONNECTION_ERROR=" + str(client.connection_error))
        elif client.closed_cleanly:
            print("CONNECTION_CLOSED")
        print("OK")


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(run(int(sys.argv[1])), 10))

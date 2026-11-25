# WebSocket over HTTP/3 (RFC 9220) - implementation plan

Status: draft plan, not implemented.

## 1. Summary

This document analyses the feasibility of implementing
[RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.txt)
("Bootstrapping WebSockets with HTTP/3") in Tomcat's HTTP/3 connector and
drafts an implementation plan.

The goal is that a normal Jakarta WebSocket application (`@ServerEndpoint`,
`ServerEndpointConfig`, `WsServerContainer`, the standard endpoint/session
API) works unchanged over HTTP/3, using the same server-side
`WsHttpUpgradeHandler` / `InternalHttpUpgradeHandler` machinery that the
HTTP/1.1 WebSocket implementation already uses. RFC 9220 itself is a small
document: it reuses all of the semantics of
[RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.txt) and only adapts them
to HTTP/3. The real work is in the Tomcat plumbing:

* accepting and routing Extended CONNECT requests in the Servlet container,
* performing the RFC 8441/9220 opening handshake (no `Upgrade`/`Connection`
  headers, no `Sec-WebSocket-Key`/`Sec-WebSocket-Accept`, `200` response),
* handing an HTTP/3 request stream to the WebSocket implementation while
  keeping HTTP/3 DATA-frame framing,
* closing the stream with FIN for orderly WebSocket closure and with
  `H3_REQUEST_CANCELLED` for abnormal closure.

The QUIC/OpenSSL transport itself does not need to change. The HTTP/3
processor already contains most of the protocol pieces needed for RFC 9220
(SETTINGS_ENABLE_CONNECT_PROTOCOL, `:protocol` validation, CONNECT DATA
frame classification), and the WebSocket implementation is transport-coupled
in only two classes (`WsFrameServer` and `WsRemoteEndpointImplServer`), which
can be refactored behind a small I/O abstraction without changing HTTP/1.1
behaviour.

The WebSocket transport target is deliberately the internal upgrade path,
not the Servlet API upgrade path. Tomcat's WebSocket server uses
`InternalHttpUpgradeHandler` because its suspend/resume, callback
scheduling, blocking close, write-timeout and deadlock requirements do not
fit the Servlet API thread model cleanly, and maintaining a second
Servlet-stream WebSocket implementation is not resourced. HTTP/3 therefore
provides an `UpgradeTransport` for internal handlers rather than requiring
WebSocket to run over Servlet upgrade streams.

Overall feasibility: **high**. The main risks are lifecycle integration
between the HTTP/3 processor and a long-lived upgraded stream, the
suspension/async behaviour of the WebSocket stack, and the absence of an
HTTP/3 WebSocket client in Tomcat (client-side support is out of scope for
the first phase).

## 2. Scope and non-goals

In scope:

* Server-side RFC 9220 WebSocket support over the existing HTTP/3 connector
  (`Http3OpenSSLProtocol`, and by construction the quiche/ngtcp2 transports).
* Standard Jakarta WebSocket server API: annotated and programmatic
  endpoints, subprotocols, extensions (`permessage-deflate`), origin checks,
  session close handshakes, blocking and asynchronous sends.
* `HttpServletRequest.upgrade()` with an `InternalHttpUpgradeHandler`,
  because that is the mechanism the WebSocket implementation uses.
* Existing HTTP/1.1 WebSocket behaviour must remain bit-for-bit compatible.

Out of scope for phase 1:

* Client-side RFC 9220 WebSocket support in `WsWebSocketContainer`. The
  current WebSocket client is built directly on
  `AsynchronousSocketChannel` and TLS and has no HTTP/3 client stack and no
  Extended CONNECT support.
* RFC 8441 WebSocket support over HTTP/2. The transport abstraction proposed
  here is protocol-neutral and could be reused later, but HTTP/2 Extended
  CONNECT is not implemented in this tree.
* Generic external (Servlet-stream based) `HttpUpgradeHandler` support over
  HTTP/3. Tomcat's WebSocket implementation deliberately uses
  `InternalHttpUpgradeHandler` and direct transport I/O. The pure Servlet API
  upgrade path proved unsuitable for several WebSocket usage patterns
  (Servlet API thread model, read suspend/resume and scheduling, blocking
  close semantics, write-timeout control and deadlock avoidance), and
  maintaining both an internal and a Servlet-stream WebSocket path was not
  resourced. RFC 9220 WebSocket support therefore targets
  `InternalHttpUpgradeHandler` + `UpgradeTransport`. Generic external
  upgrade streams are a separate HTTP/3 capability if ever needed; they are
  not a dependency of this plan and not part of the WebSocket definition of
  done.
* WebTransport (RFC 9297 HTTP datagrams). RFC 9220 tunnels use ordinary
  HTTP/3 DATA frames; WebTransport is a separate protocol.

## 3. Normative requirements checklist

RFC 9220 Section 3 says the pseudo-header and setting semantics are identical
to RFC 8441, with the HTTP/3 setting registered separately. The applicable
requirements are therefore:

1. The server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) with value
   `1` before a client may use Extended CONNECT (RFC 8441 Section 3,
   RFC 9220 Section 3/5).
2. A WebSocket bootstrap request is an Extended CONNECT:
   * `:method = CONNECT`
   * `:protocol = websocket`
   * `:scheme = https` (for `wss`) or `http` (for `ws`)
   * `:path = <WebSocket resource>`
   * `:authority = <host>` interpreted as a normal request authority, not as
     a tunnel target (RFC 8441 Section 4).
3. The request MUST NOT contain `Connection` or `Upgrade` (RFC 8441
   Section 5). HTTP/3 already treats these as malformed connection-specific
   fields (RFC 9114 Section 4.2).
4. The `Sec-WebSocket-Key`/`Sec-WebSocket-Accept` exchange of RFC 6455 is
   **not performed** (RFC 8441 Section 5); `:protocol` supersedes it.
5. `Origin`, `Sec-WebSocket-Version`, `Sec-WebSocket-Protocol` and
   `Sec-WebSocket-Extensions` keep their RFC 6455 meaning.
6. The successful response is a `2xx` status (normally `200`), not `101`
   (RFC 8441 Section 5, RFC 9110 Section 9.3.6). A `2xx` response to CONNECT
   MUST NOT carry `Content-Length` or `Transfer-Encoding`.
7. An Extended CONNECT whose `:protocol` is unknown or unsupported SHOULD
   receive `501 Not Implemented` (RFC 9220 Section 3).
8. Once the handshake completes, WebSocket bytes travel in HTTP/3 DATA
   frames on the same bidirectional request stream (RFC 9114 Section 4.4,
   RFC 9220 Section 3). Only DATA frames (and extension frames that
   explicitly permit themselves) may follow a completed CONNECT.
9. Orderly closure is a stream FIN; abrupt closure is a stream reset with
   `H3_REQUEST_CANCELLED` (RFC 9220 Section 3).
10. `SETTINGS_ENABLE_CONNECT_PROTOCOL` must be 0 or 1; any other value is a
    connection error of type `H3_SETTINGS_ERROR` (RFC 8441 Section 3,
    RFC 9114 Section 7.2.4). This is already implemented.

## 4. Current implementation inventory

### 4.1 QUIC transport / OpenSSL endpoint

`org.apache.tomcat.util.net.quic.QuicStream` and
`org.apache.tomcat.util.net.quic.QuicSocketWrapper` already expose
everything RFC 9220 needs at the transport level:

* bidirectional request streams (`SSL_STREAM_TYPE_BIDI`),
* read state (`OK`, `FINISHED`, `RESET_LOCAL`, `RESET_REMOTE`,
  `CONN_CLOSED`),
* `concludeStream()` (FIN),
* `resetStream(appErrorCode)` (RESET_STREAM),
* event-driven read/write wake-ups and write-interest registration,
* flow-control-aware non-blocking and blocking writes.

`QuicOpenSSLSocketWrapper` implements these on top of the OpenSSL QUIC API.
Its `hasAsyncIO()` returns `false`, so the WebSocket implementation will use
its non-blocking (not vectored/async-IO) write path. That path is already
exercised by HTTP/3 response writes and works.

The quiche and ngtcp2 endpoints implement the same `QuicSocketWrapper`
contract, so RFC 9220 support added in the HTTP/3 protocol layer should work
on all three transports. The OpenSSL endpoint is the reference transport.

**No changes are expected in the native QUIC endpoint, the FFM bindings, or
the QUIC stream interfaces.**

Important transport observation: on a request-stream handler returning
`SocketState.CLOSED` or `SocketState.SUSPENDED`, all three QUIC endpoints
call `wrapper.close()` and release the stream. This matters for the
WebSocket suspension mapping (see Section 8.7).

### 4.2 HTTP/3 protocol implementation

The HTTP/3 layer is implemented by
`org.apache.coyote.http3.AbstractHttp3Protocol` and
`org.apache.coyote.http3.Http3Processor` (about 9k lines), with
`Http3ConnectionManager`, `Http3Settings` and QPACK support.

Already present and directly reusable:

* `SETTINGS_ENABLE_CONNECT_PROTOCOL` encoding in `Http3Settings.encode()`.
* Per-connection snapshot `enableConnectProtocol` in
  `Http3ConnectionManager.ConnectionState`.
* Connector properties `enableConnectProtocol` and `connectProtocols` on
  `AbstractHttp3Protocol` (defaults: disabled / empty).
* Extended CONNECT request validation in
  `Http3Processor.validateHeadersInternal()`:
  * `:protocol` only allowed on CONNECT,
  * Extended CONNECT requires `:scheme` and `:path`,
  * Extended CONNECT requires `:authority` and interprets it as a normal
    request authority,
  * `:protocol` requires the server to have advertised the setting,
  * `:protocol` must be a token,
  * unknown methods and non-token methods handled per RFC 9110/9114.
* Storage of the `:protocol` value in the request attribute
  `Constants.ATTR_EXTENDED_CONNECT_PROTOCOL`
  (`org.apache.coyote.http3.protocol`).
* Rejection of unsupported Extended CONNECT protocols with `501` in
  `Http3Processor.isUnsupportedExtendedConnect()`.
* CONNECT DATA-frame classification:
  `classifyBodyFrame()` treats DATA as tunnel/body bytes and a HEADERS frame
  after CONNECT as a connection error, per RFC 9114 Section 4.4.
* Successful CONNECT response handling in
  `sendResponseHeadersInternal()`: `2xx` CONNECT responses clear
  `Content-Length`, `Transfer-Encoding`, `Content-Type`,
  `Content-Language` and `Content-Encoding`, skip compression and skip
  response trailers, per RFC 9110 Section 9.3.6 and RFC 9114 Section 4.4.
* A 101 response is already rejected (replaced with 500), per RFC 9114
  Section 4.5.
* Request-body reading (`Http3InputBuffer`) and response-body writing
  (`Http3OutputBuffer`) already parse/write HTTP/3 DATA frames, handle
  partial frames, ignore unknown frames, enforce Content-Length where
  applicable, and implement non-blocking response queues.

Current gaps in the HTTP/3 layer:

* `CoyoteAdapter` rejects **every** CONNECT request with `501` before request
  mapping, so an Extended CONNECT never reaches `WsFilter`.
* `Http3Processor` does not implement HTTP upgrade:
  * `AbstractProcessor.doHttpUpgrade()` throws `UnsupportedOperationException`.
  * `AbstractHttp3Protocol.createUpgradeProcessor()` throws
    `IllegalStateException` and documents that HTTP/3 has no upgrade.
* `Http3Processor` has no upgrade state, no upgrade dispatch path, and no way
  to keep a request stream alive after `service()` returns.
* There is no HTTP/3 equivalent of `UpgradeProcessorInternal` that can hand
  the stream to an `InternalHttpUpgradeHandler`.
* The processor always finishes the response and concludes the stream after
  `adapter.service()` returns; for WebSocket the stream must stay open and
  tunnel bytes must be framed as DATA frames.
* `Http3InputBuffer.doRead()` is blocking-oriented; the WebSocket frame
  reader needs a non-blocking "read what is available now" method.
* `Http3OutputBuffer.doWrite()` chooses blocking/non-blocking mode from the
  Servlet `WriteListener`; a WebSocket tunnel needs explicit
  blocking/non-blocking tunnel writes plus message-level queue batching.

### 4.3 WebSocket implementation

Server-side WebSocket is in `org.apache.tomcat.websocket` and
`org.apache.tomcat.websocket.server`.

The relevant path today:

* `WsFilter` (registered for `/*` by `WsServerContainer`) detects HTTP/1.1
  WebSocket upgrade requests via
  `UpgradeUtil.isWebSocketUpgradeRequest()` and looks up the endpoint mapping.
* `UpgradeUtil.doUpgrade()` performs the RFC 6455 handshake and calls
  `HttpServletRequest.upgrade(WsHttpUpgradeHandler.class)`.
* `Request.upgrade()` creates the handler and fires
  `ActionCode.UPGRADE`; the protocol processor stores an `UpgradeToken`.
* On HTTP/1.1, `Http11Processor` returns `SocketState.UPGRADING`; the
  connection handler creates `UpgradeProcessorInternal`, calls
  `WsHttpUpgradeHandler.init(WebConnection)`, and the handler drives the
  upgraded connection with `upgradeDispatch(SocketEvent)`.
* `WsHttpUpgradeHandler` creates:
  * `WsRemoteEndpointImplServer`, which writes WebSocket frames directly to
    `SocketWrapperBase`,
  * `WsFrameServer`, which reads WebSocket frames directly from
    `SocketWrapperBase` and drives `WsSession`/endpoint callbacks.
* `WsFrameBase` (transport-neutral) parses WebSocket frames; only
  `WsFrameServer` knows about `SocketWrapperBase`.
* `WsRemoteEndpointImplServer` handles blocking and non-blocking sends,
  write timeouts, and a deadlock-avoidance path that temporarily releases the
  socket wrapper lock.

Current gaps in the WebSocket layer:

* `WsFilter` / `UpgradeUtil` only recognise HTTP/1.1 requests with
  `Upgrade: websocket` and `Connection: upgrade`.
* `UpgradeUtil.doUpgrade()` unconditionally validates `Sec-WebSocket-Key`,
  emits `Upgrade`, `Connection` and `Sec-WebSocket-Accept`, and expects
  `HTTP/1.1`. None of that is valid for RFC 8441/9220 Extended CONNECT.
* `Request.upgrade()` always sets the response status to `101`.
* The WebSocket data path is hard-coded to `SocketWrapperBase`:
  `WsFrameServer` calls `socketWrapper.read()` and
  `WsRemoteEndpointImplServer` calls `socketWrapper.write()`/`flush()`.
  For HTTP/3 these must be DATA-frame-aware operations, not raw stream I/O.
* The WebSocket client (`WsWebSocketContainer`) is HTTP/1.1-only.

## 5. Gap analysis

| Area | Existing | Needed |
|---|---|---|
| SETTINGS advertisement | Implemented (`Http3Settings`, `AbstractHttp3Protocol`) | Configure/enable `enableConnectProtocol` and register `websocket` in `connectProtocols` |
| Extended CONNECT validation | Implemented | No change (maybe expose protocol attribute constant centrally) |
| Extended CONNECT routing | Rejected by `CoyoteAdapter` | Allow Extended CONNECT through mapping/filter chain; keep plain CONNECT 501 |
| Handshake detection | HTTP/1.1 `Upgrade` header only | Detect HTTP/3 Extended CONNECT `:protocol=websocket` |
| Handshake semantics | RFC 6455 key/accept + 101 | RFC 8441/9220 variant: no key/accept, no Upgrade/Connection, 200 response |
| `Request.upgrade` | Always 101 | 2xx for Extended CONNECT, 101 for HTTP/1.1 |
| Upgrade lifecycle | HTTP/1.1 `UpgradeProcessorInternal` | HTTP/3 in-place upgrade dispatch (recommended) |
| WebSocket I/O | `SocketWrapperBase` directly | Transport abstraction with DATA-frame-aware HTTP/3 implementation |
| Tunnel input | HTTP/3 body read | Non-blocking tunnel read that delivers DATA payload bytes |
| Tunnel output | HTTP/3 response body write | Tunnel DATA-frame writer with blocking/non-blocking support |
| Closure | Socket close | FIN for orderly close, `H3_REQUEST_CANCELLED` for abort |
| Suspension | `SocketState.SUSPENDED` (HTTP/1.1) | QUIC endpoints close on SUSPENDED; map to `ASYNC_IO` |
| Client | HTTP/1.1 client only | Out of scope for phase 1 |
| Tests | HTTP/3 GET/body tests, HTTP/1.1 WebSocket tests | HTTP/3 WebSocket handshake/tunnel tests |

## 6. Feasibility assessment

### 6.1 Protocol/transport layer: no blockers

QUIC request streams are bidirectional, support half-close (FIN) and
RESET_STREAM, and the HTTP/3 processor already treats CONNECT DATA frames as
tunnel bytes. The OpenSSL endpoint needs no native changes. The existing
non-blocking write path (`hasAsyncIO() == false`; `write(false, ...)`,
`flush(false)`, `isReadyForWrite()`, write-interest registration) is
sufficient for WebSocket asynchronous sends, provided the HTTP/3 tunnel
writer maps them to DATA frames.

### 6.2 HTTP/3 processor lifecycle: feasible with in-place upgrade

The HTTP/3 processor is a pooled `AbstractProcessor` whose input buffer,
frame parser state, QPACK state, output queue and stream-reset bookkeeping
are all per-stream fields. Moving that state to a separate
`Http3UpgradeProcessor` after the handshake would be error-prone: the
processor can have partially consumed DATA frames, buffered WebSocket bytes,
a partial frame header, an in-flight ignored-frame skip, and a response
output queue. Keeping the same `Http3Processor` alive and adding an
in-place upgrade dispatch path avoids transferring that state.

`AbstractProtocol.ConnectionHandler` already supports
`SocketState.UPGRADED` and `SocketState.ASYNC_IO`; the only missing piece is
a dispatch hook for processors that set an upgrade token. This can be added
to `AbstractProcessor` with a small, protocol-neutral change, without
touching the HTTP/1.1 upgrade flow.

The main lifecycle risk is recycling: an upgraded HTTP/3 processor must not
be returned to the shared processor pool while non-container WebSocket
threads may still hold its request/response/transport. This is handled by
marking it non-reusable and giving it a dedicated upgrade cleanup path in
`recycle()`.

### 6.3 WebSocket I/O abstraction: feasible, moderate refactor

`WsFrameServer` uses exactly one socket method (`read(false, ByteBuffer)`),
one close check, and one `processSocket()` call. `WsRemoteEndpointImplServer`
uses about a dozen socket methods (write, flush, readiness, lock, execute,
write timeout, close, current-processor handoff). A small interface covering
that subset, with an HTTP/1.1 adapter that delegates to `SocketWrapperBase`,
preserves existing behaviour. The HTTP/1.1 NIO2 vectored-I/O branch can keep
using the underlying `SocketWrapperBase` directly because QUIC reports
`hasAsyncIO() == false`.

### 6.4 Container handshake: feasible with small changes

The only container-level blocker is the blanket CONNECT rejection in
`CoyoteAdapter`. Permitting Extended CONNECT through the normal mapping path
lets the existing `WsFilter`/security/valve machinery handle it. The
handshake variant itself is a localized change in `UpgradeUtil` and
`Request.upgrade`.

### 6.5 Testability: feasible, requires an HTTP/3 WebSocket client

The existing HTTP/3 test suite already drives an aioquic Python client that
can send arbitrary headers and DATA frames, and has raw HTTP/3 frame helpers.
Adding a `websocket` client mode is straightforward. A JUnit integration test
can then assert the RFC 9220 handshake and echo frames end-to-end.

## 7. Architecture decisions

### 7.1 Recommended: in-place HTTP/3 upgrade (Option A)

Keep the `Http3Processor` associated with the stream after the handshake.
The processor:

1. Detects `isUpgrade()` after `adapter.service()` returns.
2. Sends the WebSocket handshake response headers (200 + `Sec-WebSocket-*`
   headers) as a normal HTTP/3 response HEADERS frame.
3. Creates an HTTP/3 tunnel connection/transport backed by the same
   processor buffers.
4. Initializes the `InternalHttpUpgradeHandler`.
5. Returns `SocketState.UPGRADED` (or `ASYNC_IO` if the handler reports
   async I/O).
6. Routes subsequent socket events to the handler via a new
   `AbstractProcessor.dispatchUpgrade(SocketEvent)` hook.

Advantages:

* No transfer of frame-parser/buffer state.
* Reuses the existing HTTP/3 DATA frame reader and writer.
* Reuses `ConnectionHandler`'s existing `UPGRADED`/`ASYNC_IO` handling.
* The processor is never pooled while upgraded.

Disadvantages:

* `Http3Processor` gains upgrade-specific fields, lifecycle and cleanup code.
* `Processor.dispatch()` must delegate to an upgrade hook.
* `Http3Processor.recycle()` needs an explicit non-pooled upgrade path.

### 7.2 Rejected alternative: dedicated `Http3UpgradeProcessor` (Option B)

Return `SocketState.UPGRADING`, let `ConnectionHandler` create a separate
upgrade processor, and transfer the tunnel state into it. This fits the
HTTP/1.1 model but requires copying:

* the remaining `Http3Processor.inputBuffer` bytes,
* `inputBufferHasData`, `pendingFrameType/Length/Read/Payload`,
* `Http3InputBuffer` pre-buffered DATA payload, `partialDataRemaining`,
  `pendingSkipRemaining`, `streamClosed`/`streamAborted`/`trailersReceived`,
* `totalDataReceived`, `requestContentLength`,
* QPACK/stream-cancellation bookkeeping,
* the output queue and stream reset/fin bookkeeping.

The transfer is fragile and duplicates parser invariants. It is not
recommended for WebSocket support. It might become attractive only if HTTP/3
later needs a fully separate generic external `HttpUpgradeHandler` stream
capability or a reusable upgrade processor abstraction.

### 7.3 Transport abstraction

Introduce a small protocol-neutral upgrade transport interface, for example:

```java
package org.apache.coyote;

public interface UpgradeTransport {
    int read(boolean block, ByteBuffer to) throws IOException;
    void write(boolean block, ByteBuffer from) throws IOException;
    boolean flush(boolean block) throws IOException;
    boolean isReadyForWrite();
    boolean isClosed();
    void registerReadInterest();
    void registerWriteInterest();
    void processSocket(SocketEvent event, boolean dispatch);
    void execute(Runnable runnable);
    ReentrantLock getLock();
    boolean hasAsyncIO();
    void setWriteTimeout(long timeoutMs);
    void setCurrentProcessor(Object currentProcessor);
    Object takeCurrentProcessor();
    SocketWrapperBase<?> getSocketWrapper();
    default void startWriteBatch() { }
    default void endWriteBatch() { }
    void close() throws IOException;
    void abort() throws IOException;
}
```

`UpgradeTransportAware` (or a default method on `InternalHttpUpgradeHandler`)
lets a protocol processor inject the transport before `init()`:

```java
public interface UpgradeTransportAware {
    void setUpgradeTransport(UpgradeTransport transport);
}
```

Implementations:

* `SocketWrapperUpgradeTransport` (WebSocket server package): delegates to
  `SocketWrapperBase`; preserves HTTP/1.1 semantics exactly.
* `Http3TunnelTransport` (inner class of `Http3Processor`): reads HTTP/3
  DATA frame payloads and writes HTTP/3 DATA frames.
* Future HTTP/2 RFC 8441 transport.

Place the interface in a protocol-neutral package (suggest
`org.apache.coyote`) rather than `org.apache.coyote.http3` or
`org.apache.coyote.http11`, so both HTTP/2 and HTTP/3 can implement it
without a protocol-layer dependency.

### 7.4 Rejected: Servlet-only upgrade path for WebSocket

A second architectural option was to make HTTP/3 expose only the Servlet
async I/O API and the generic Servlet upgrade mechanism (a `WebConnection`
with `ServletInputStream`/`ServletOutputStream`), and to have WebSocket use
that path exclusively. This has clean layering, but it was rejected for
WebSocket for these reasons:

* Tomcat's WebSocket server implementation is deliberately an
  `InternalHttpUpgradeHandler`. It uses direct transport I/O because the
  Servlet API upgrade stream path could not cleanly express several required
  WebSocket usage patterns: async read suspend/resume, callback scheduling,
  blocking close with deadlock avoidance, write timeouts, and message-level
  write batching.
* The Servlet API thread model and listener contract add indirection and
  scheduling constraints that are a poor fit for the WebSocket frame/remote
  endpoint state machines. The original Servlet-stream WebSocket path had
  design issues and was not retained.
* Maintaining both an internal WebSocket path and a Servlet-stream WebSocket
  path would double the surface area for async, close, error and timeout
  semantics, with insufficient resources to support both.
* Even a Servlet-only WebSocket backend would need Tomcat-specific hooks for
  resume/scheduling/locking, so the Servlet boundary would not actually
  eliminate the need for a protocol-neutral internal contract.

Consequence for this plan: HTTP/3 must support
`InternalHttpUpgradeHandler` directly through `UpgradeTransport`. Generic
external `HttpUpgradeHandler` streams are a separate protocol capability, not
a prerequisite for WebSocket and not a second WebSocket implementation.

## 8. Detailed design

### 8.1 Connector configuration and SETTINGS

The existing HTTP/3 connector attributes are sufficient:

```xml
<Connector port="8444"
           protocol="org.apache.coyote.http3.Http3OpenSSLProtocol"
           SSLEnabled="true"
           enableConnectProtocol="true"
           connectProtocols="websocket">
    <SSLHostConfig>
        <Certificate .../>
    </SSLHostConfig>
</Connector>
```

Recommendation: keep `enableConnectProtocol` default `false` (the RFC default
for the setting is 0 and changing the default would affect existing HTTP/3
tests/behaviour). Document that RFC 9220 WebSocket requires it to be enabled
and `websocket` registered. Optionally, an `altService="h3"` TCP connector can
advertise HTTP/3 to browsers via `Alt-Svc`.

No settings encoding change is needed; `SETTINGS_ENABLE_CONNECT_PROTOCOL`
(0x08) is already emitted when enabled.

### 8.2 Request routing and validation

1. **Promote the Extended CONNECT attribute constant.** Move/alias
   `org.apache.coyote.http3.Constants.ATTR_EXTENDED_CONNECT_PROTOCOL` to a
   protocol-neutral constant (suggest `org.apache.coyote.Constants`) with the
   same string value, so Catalina, WebSocket and HTTP/3 code can use it
   without depending on the HTTP/3 package. Keep the HTTP/3 constant as an
   alias for existing tests.

2. **Allow Extended CONNECT through `CoyoteAdapter`.** In
   `CoyoteAdapter.postParseRequest()`, replace the blanket CONNECT rejection
   with:

   ```java
   if (Method.CONNECT.equals(req.getMethod()) &&
           req.getAttribute(Constants.ATTR_EXTENDED_CONNECT_PROTOCOL) == null) {
       response.sendError(501, ...);
   } else {
       // normal URI decoding, normalization and mapping
   }
   ```

   An Extended CONNECT has a `:path` and behaves like a normal request for
   mapping purposes. Plain CONNECT (no `:protocol`) remains rejected with
   `501`.

   Note: `Http3Processor` already answers unsupported `:protocol` values with
   `501` before dispatch, so `CoyoteAdapter` only sees protocols the
   connector registered.

3. **`WsFilter` detection.** `UpgradeUtil.isWebSocketUpgradeRequest()` gains
   an HTTP/3 branch:

   ```java
   if ("HTTP/3.0".equals(request.getProtocol())) {
       return Method.CONNECT.equals(request.getMethod()) &&
              "websocket".equalsIgnoreCase(
                  (String) request.getAttribute(EXTENDED_CONNECT_PROTOCOL));
   }
   ```

   (Optionally support `HTTP/2.0` in the same predicate when RFC 8441 lands.)

4. **Mapping and filters.** Because `:path` is mapped normally, the existing
   `WsFilter`, security constraints, valves and filter chain run as for an
   HTTP/1.1 WebSocket request. No new filter registration is needed.

### 8.3 WebSocket handshake

Refactor `UpgradeUtil` into two handshake modes:

* HTTP/1.1 RFC 6455 mode (existing behaviour),
* RFC 8441/9220 Extended CONNECT mode.

Extended CONNECT mode:

1. Require `:protocol = websocket` (case-insensitive), `CONNECT`, HTTP/3
  (and later HTTP/2), and the `:scheme`/`:path`/`:authority` validation
  already done by the HTTP/3 processor.
2. Do **not** require or validate `Sec-WebSocket-Key`; do **not** compute
  `Sec-WebSocket-Accept`.
3. Do **not** require `Connection`/`Upgrade`; HTTP/3 already rejects them.
4. Validate `Origin` via the configured `ServerEndpointConfigurator`.
5. Require `Sec-WebSocket-Version: 13`. If missing/invalid, return `400`
   rather than the HTTP/1.1 `426` path, because a `426` response would
   require an `Upgrade` header that HTTP/3 forbids.
6. Negotiate subprotocols and extensions exactly as today.
7. Set the response status to `200` and add `Sec-WebSocket-Protocol` /
   `Sec-WebSocket-Extensions` response headers. Do not add `Upgrade`,
   `Connection` or `Sec-WebSocket-Accept`. If an application configurator
   adds `Sec-WebSocket-Accept`, remove it for the Extended CONNECT response;
   HTTP/3 already strips `Upgrade`/`Connection` on output.
8. Call `req.upgrade(WsHttpUpgradeHandler.class)` and `preInit()` exactly as
   today.

`Request.upgrade()` changes:

```java
coyoteRequest.action(ActionCode.UPGRADE, upgradeToken);
upgradeRequested = true;

if (coyoteRequest.getAttribute(Constants.ATTR_EXTENDED_CONNECT_PROTOCOL) != null) {
    // RFC 8441/9220: successful Extended CONNECT is a 2xx response.
    if (response.getStatus() < 200 || response.getStatus() > 299) {
        response.setStatus(HttpServletResponse.SC_OK);
    }
} else {
    response.setStatus(HttpServletResponse.SC_SWITCHING_PROTOCOLS);
}
```

Note that QUIC always uses TLS, and the HTTP/3 processor's default
`allowSchemeMismatch=false` check requires `:scheme=https` (the `wss` case).
An RFC 9220 Extended CONNECT with `:scheme=http` (the `ws` case) is rejected
as an inconsistent scheme unless the connector is explicitly configured with
`allowSchemeMismatch=true` (for example behind a trusted TLS-terminating
proxy). This matches the existing HTTP/3 scheme-consistency policy.

`getUpgradeProtocolName()` should return the `:protocol` value
(`websocket`) for an Extended CONNECT, so `UpgradeInfo`/JMX grouping uses
the protocol name instead of the handler class name.

### 8.4 HTTP/3 upgrade lifecycle

Add to `Http3Processor`:

```java
private UpgradeToken upgradeToken;      // null unless req.upgrade() was called
private boolean upgradeMode;            // set in doHttpUpgrade()
private boolean upgradeHandlerInitialized;
private boolean tunnelActive;
private Http3TunnelTransport tunnelTransport;
```

Implement/override:

* `doHttpUpgrade(UpgradeToken token)`: validate that the handler is an
  `InternalHttpUpgradeHandler` that implements `UpgradeTransportAware`
  (phase 1; otherwise throw `UnsupportedOperationException` before the
  handshake response is committed), store the token, set
  `upgradeMode = true`, and make sure any further Servlet response body
  writes are discarded.
* `getUpgradeToken()`: return token.
* `isUpgrade()`: return `upgradeToken != null`.
* `dispatchUpgrade(SocketEvent status)`: delegate to the
  `InternalHttpUpgradeHandler`, map states for QUIC (see 8.7), and terminate
  the stream on CLOSED/error. Normal `OPEN_READ`/`OPEN_WRITE` states are
  `UPGRADED` (or `ASYNC_IO` for read suspension); `STOP` maps to an orderly
  close (FIN) after the handler's GOING_AWAY close; `TIMEOUT` and `ERROR`
  map to an abort (`H3_REQUEST_CANCELLED`) unless the handler already
  concluded or reset the stream.
* `timeoutAsync(long now)`: if upgraded, delegate to the handler's
  `timeoutAsync`; else existing async timeout.
* `recycle()`: if `upgradeMode`, mark the processor non-reusable, clear upgrade
  fields, ensure the stream is concluded/reset if the handler did not do so,
  unregister from priority/timeout tracking, detach the wrapper, and return
  without returning the processor to the pool.

In `service()`, after `adapter.service()` returns and after the existing
error/body-frame checks, insert:

```java
if (isUpgrade()) {
    return processHttpUpgrade(socketWrapper);
}
```

`processHttpUpgrade()`:

1. Validate the response status is `2xx`; otherwise reset/close and return
   `CLOSED`.
2. Ensure the handshake response headers were sent (they normally are sent
   during `Response.finishResponse()`, which commits the response; call
   `sendResponseHeadersInternal()` defensively if not). Drain any pending
   handshake output queue blocking, so no handshake HEADERS frame can be
   overtaken by later tunnel DATA frames.
3. Ensure no response body DATA frames were emitted; `upgradeMode` makes
   `Http3OutputBuffer.doWrite()` discard Servlet response bytes, while
   `writeFrame()` still allows the handshake HEADERS frame. If
   `outputBuffer.getBytesWritten()` is non-zero (an application wrote and
   flushed a response body before calling `upgrade()`), reject the upgrade
   and reset the stream rather than mixing response DATA with tunnel DATA.
4. Create the `Http3TunnelConnection` (implements `WebConnection` and
   `UpgradeTransportAware`) and its `Http3TunnelTransport`.
5. If the handler is an `InternalHttpUpgradeHandler`:
   * call `setSocketWrapper(socketWrapper)`,
   * call `setSslSupport(socketWrapper.getSslSupport())` if needed,
   * call `setUpgradeTransport(transport)` if it implements
     `UpgradeTransportAware`,
   * call `init(connection)` with the context class loader bound as
     `ConnectionHandler` does for internal handlers.
6. If the handler is not an `InternalHttpUpgradeHandler` (or not
   transport-aware), reject: reset the stream and return `CLOSED`. Generic
   Servlet-stream external upgrade is a separate HTTP/3 capability, not a
   second WebSocket implementation and not required for RFC 9220 WebSocket
   support.
7. Set `upgradeHandlerInitialized = true` and `tunnelActive = true`.
   Until initialization completes, `dispatchUpgrade()` must be a no-op that
   returns `UPGRADED` (not `CLOSED`), so a write-interest event generated by
   `onOpen()` cannot tear the session down while `init()` is still running.
   The QUIC endpoint normally serializes dispatches per stream, but this
   guard keeps the lifecycle correct regardless.
8. If there are already-buffered tunnel bytes (from the pre-dispatch body
   read or from bytes read together with the request HEADERS), run one
   inline `dispatchUpgrade(OPEN_READ)` to feed them to the handler before
   returning. This is required because `longPoll()` only arms *future*
   transport reads; bytes already in Java buffers will not generate a new
   QUIC read event.
9. Return `SocketState.UPGRADED`, or `SocketState.ASYNC_IO` if the handler
   reports async I/O.

### 8.5 HTTP/3 tunnel input

Add a non-blocking tunnel read method to `Http3InputBuffer` (or a small
dedicated reader that shares the same buffers/state):

```java
int readTunnel(ByteBuffer dst) throws IOException {
    // under inputReadLock:
    // 1. drain dataBuffers (pre-buffered DATA payload)
    // 2. if no data, call readMoreData(socketWrapper, dst, pump=false)
    // 3. map CLEAN FIN -> -1
    //    map RESET_REMOTE / CONN_CLOSED / local abort -> IOException
    //    map would-block -> 0
    // 4. if bodyFrameError != null, fail the HTTP/3 connection
}
```

Key points:

* The pre-dispatch `readRequestBody()` may already have consumed DATA frames
  into `Http3InputBuffer.dataBuffers` and may have set
  `partialDataRemaining`/`pendingSkipRemaining`. Those must be consumed
  before parsing new frame headers.
* `readMoreData()` already enforces the frame sequence rules:
  * DATA frames are delivered as body/tunnel bytes,
  * ignored/unknown frames are skipped,
  * a HEADERS frame after CONNECT is recorded as
    `H3_FRAME_UNEXPECTED` (a connection error per RFC 9114 Section 4.4),
  * a truncated final frame on a clean FIN is `H3_FRAME_ERROR`.
* `readMoreData()` must gain a `pump` parameter so the tunnel's non-blocking
  read does not park a container thread. The existing blocking `doRead()`
  path keeps `pump=true`; the tunnel path uses `pump=false`.
* A peer FIN maps to WebSocket EOF (abnormal close if no WebSocket Close
  frame was received; the WebSocket layer handles that).
* A peer RESET_STREAM maps to an `IOException` in the WebSocket reader
  (abnormal close).
* Large DATA frames: `readMoreData()` currently rejects DATA frames above
  `Http3Processor.MAX_FRAME_LENGTH` (16 MiB) and tracks a partially delivered
  frame with an `int`. For phase 1, document the 16 MiB HTTP/3 DATA frame
  limit; large WebSocket messages can be split by the client into multiple
  DATA frames. Phase 5 can add a tunnel-specific mode that streams DATA
  payloads of any length with a `long` remainder.

`Http3TunnelTransport.read(boolean block, ByteBuffer to)`:

* `block == false`: call `readTunnel(to)` once; return 0 on would-block,
  -1 on clean FIN, or throw on reset/abort/connection error.
* `block == true`: loop with `pump=true` until data or EOF. WebSocket uses
  non-blocking reads; the blocking variant is only needed if a separate
  generic external `HttpUpgradeHandler` stream capability is ever added.

`Http3TunnelTransport.isClosed()` should report true when the transport
wrapper is closed, or when the stream has been reset/aborted/connection
closed. It must **not** report true merely because the local write side was
concluded with FIN; the read side may still be open.

Reading interest: `registerReadInterest()` delegates to the QUIC wrapper.
After an `OPEN_READ` dispatch, the handler reads until `readTunnel` returns
0; `ConnectionHandler` then re-arms read interest while the state is
`UPGRADED`.

### 8.6 HTTP/3 tunnel output

Reuse `Http3OutputBuffer`'s DATA-frame encoder and non-blocking queue, but
add tunnel-specific entry points:

```java
int writeTunnel(boolean block, ByteBuffer chunk) throws IOException;
boolean flushTunnel(boolean block) throws IOException;
boolean isTunnelReadyForWrite();
```

Implementation notes:

* `emitData()` is refactored to take an explicit
  `boolean nonBlocking` mode (instead of deriving it only from the Servlet
  `WriteListener`) and a `boolean inWriteBatch` flag. Existing response
  callers pass the current listener mode and `false`; tunnel callers pass
  `!block` and the current message-batch state. While a WebSocket message
  batch is active, every DATA frame of that message (including the small
  WebSocket frame header buffers and the potentially large payload buffers)
  is appended as part of the same logical batch and is exempt from the
  aggregate queue limit. This fixes the case where the small frame header
  fills the queue first and a large payload write behind it would otherwise
  be rejected.
* Blocking tunnel writes (`block == true`) first drain any pending
  non-blocking queue (`flushBlocking()`) so a close frame or other blocking
  message cannot overtake DATA frames queued by an earlier asynchronous send,
  then write DATA frames directly to the QUIC wrapper
  (`wrapper.write(true, frame)`); the WebSocket blocking path calls
  `flush(true)`.
* Non-blocking tunnel writes (`block == false`) queue DATA frames in the
  existing ordered queue and call `flushNonBlocking()`. The queue's
  `WRITE_QUEUE_HARD_LIMIT` (256 KiB) is too small for a single large
  WebSocket frame whose header and payload arrive as separate write calls.
  Add a message-level write batch:
  * `UpgradeTransport.startWriteBatch()` / `endWriteBatch()` (no-ops for
    HTTP/1.1),
  * `WsRemoteEndpointImplServer` starts a batch when it accepts a message
    part and ends it when `clearHandlerInternal()` completes the part,
  * `Http3TunnelTransport` delegates to
    `Http3OutputBuffer.startOversizedBatch()`/`finishOversizedBatch()` (or a
    tunnel-specific equivalent) so all DATA frames of one WebSocket message
    are accepted as one logical batch while the aggregate limit still applies
    to later messages. The batch size is bounded by the WebSocket message size
    limits configured on the session/endpoint; a future hard upper bound can
    be added if required.
* `Http3OutputBuffer.doWrite()` (the Servlet response path) returns/discards
  bytes without framing when `upgradeMode` is set, so a Servlet response
  body cannot leak into the tunnel. `writeTunnel()` bypasses that check.
* `flushTunnel(false)` drains queued frames and wrapper staging buffers and
  registers write interest when data remains. `isTunnelReadyForWrite()`
  returns false while the queue or wrapper staging buffer has data and, as a
  safety net, registers write interest before reporting false so a missed
  registration cannot stall the WebSocket write.
* `close()`: flush pending tunnel frames (blocking), then
  `Http3Processor.concludeStream()` (FIN). Do not call
  `SocketWrapperBase.close()` first: the QUIC wrapper's close path frees the
  stream and may emit a neutral error code instead of the RFC 9220 FIN/RST.
* `abort()`: `Http3Processor.resetStream(H3_REQUEST_CANCELLED)`. Do not send
  FIN afterwards. If the peer already reset the stream, avoid a redundant
  reset.

`Http3TunnelConnection` (the `WebConnection` passed to `init()`):

* `getInputStream()`/`getOutputStream()`: not used by the WebSocket internal
  upgrade path. They may throw `UnsupportedOperationException`. A separate
  generic external `HttpUpgradeHandler` feature could later provide tunnel
  `ServletInputStream`/`ServletOutputStream`, but it is not part of this
  plan and does not affect WebSocket support.
* `close()`: idempotently close/abort the tunnel transport.
* implements `UpgradeTransportAware` returning the `Http3TunnelTransport`.

### 8.7 WebSocket transport refactor

Introduce `WsServerTransport` (or reuse `UpgradeTransport`) and adapt
`WsFrameServer` / `WsRemoteEndpointImplServer`:

* `WsFrameServer` constructor takes the transport instead of a raw
  `SocketWrapperBase`:
  * `transport.read(false, inputBuffer)`,
  * `transport.isClosed()`,
  * `transport.processSocket(OPEN_READ, true)` for `resumeProcessing()`.
* `WsRemoteEndpointImplServer` constructor takes the transport (plus the
  underlying `SocketWrapperBase` for the HTTP/1.1 NIO2 vectored-I/O branch):
  * `transport.hasAsyncIO()` controls whether the existing vectored
    completion-handler path is used,
  * blocking writes use `transport.write(true, buffer)` /
    `transport.flush(true)`,
  * non-blocking writes use `transport.write(false, buffer)` /
    `transport.flush(false)` / `transport.isReadyForWrite()`,
  * deadlock avoidance uses `transport.getLock()`,
    `transport.setCurrentProcessor()`, `transport.takeCurrentProcessor()`,
  * callbacks use `transport.execute()`,
  * close uses `transport.close()`, abort uses `transport.abort()`,
  * write timeout uses `transport.setWriteTimeout()`.
* Add `SocketWrapperUpgradeTransport` implementing the interface by direct
  delegation to `SocketWrapperBase`. For the HTTP/1.1 adapter,
  `setCurrentProcessor(connection)` can keep delegating because the
  `WebConnection` is the `UpgradeProcessor` (a `Processor`). For the HTTP/3
  transport, `setCurrentProcessor()` must set the `Http3Processor` (which is
  a `Processor`) rather than the `WebConnection`, otherwise
  `ConnectionHandler` would later cast a `WebConnection` to `Processor`.
* `WsHttpUpgradeHandler` implements `UpgradeTransportAware`, stores the
  transport, and in `init()` uses it if set; otherwise creates the
  `SocketWrapperUpgradeTransport` fallback for HTTP/1.1.
* On abnormal close (`CloseReason.CloseCodes.CLOSED_ABNORMALLY`), the
  handler calls `transport.abort()` so RFC 9220 uses
  `H3_REQUEST_CANCELLED` instead of FIN. Normal close continues to use
  `transport.close()` (FIN).
* `WsHttpUpgradeHandler.upgradeDispatch()` must return a state that reflects
  read suspension. Add `WsFrameServer.isReadSuspended()` and return
  `SocketState.SUSPENDED` when the WebSocket read state is suspended and the
  session is not closed. This fixes a latent HTTP/1.1 issue and is required
  for HTTP/3 because all three QUIC endpoints close the stream wrapper on
  `SocketState.SUSPENDED`. The HTTP/3 `dispatchUpgrade()` maps
  `SUSPENDED` to `SocketState.ASYNC_IO`.

HTTP/1.1 compatibility is preserved by running the existing WebSocket test
suite, including the async/NIO2 paths and the deadlock test.

### 8.8 Closure and error semantics

| Event | HTTP/3 stream action | WebSocket result |
|---|---|---|
| Normal WebSocket Close handshake completes | FIN (`concludeStream`) | Normal closure |
| Application calls `Session.close()` | Close frame + FIN | Normal closure |
| Peer sends WebSocket Close | Server Close response + FIN | Normal closure |
| Peer sends FIN without Close | Peer FIN already ended read; server aborts write | Abnormal closure (1006) |
| Peer sends RESET_STREAM | Read fails; server does not send FIN | Abnormal closure (1006) |
| WebSocket protocol error (bad frame, unmasked frame, bad UTF-8) | Send Close (best effort), then `RESET_STREAM(H3_REQUEST_CANCELLED)` | Abnormal closure |
| I/O error / write timeout / transport error | `RESET_STREAM(H3_REQUEST_CANCELLED)` (if stream still writable) | Abnormal closure |
| HTTP/3 frame sequence violation (e.g. HEADERS after CONNECT) | Connection error `H3_FRAME_UNEXPECTED` | Connection fails |
| Truncated final HTTP/3 frame on clean FIN | Connection error `H3_FRAME_ERROR` | Connection fails |
| Server stop | Close frame + FIN (best effort) | GOING_AWAY closure |

Notes:

* RFC 9220 only distinguishes orderly FIN vs RST exceptions. Sending a
  WebSocket Close frame followed by FIN is an orderly stream closure.
  Protocol/transport failures use `H3_REQUEST_CANCELLED`. The WebSocket
  write-timeout and protocol-error paths should call `transport.abort()`
  rather than `transport.close()` when the close reason is
  `CLOSED_ABNORMALLY`, so the HTTP/3 transport sends RST instead of FIN.
* `Http3Processor.resetStream()` must not send FIN afterwards; its
  `streamReset`/`finSent` flags already enforce this.
* A peer reset must not cause a local `RESET_STREAM` to be sent if the stream
  is already reset.
* If a write has been concluded (FIN sent) and a later error occurs, do not
  reset the stream just to signal an error after a complete response; the
  WebSocket layer will already have closed the session.

### 8.9 Statistics and JMX

* `WsHttpUpgradeHandler` creates an `UpgradeInfo`; HTTP/3 can use it for
  WebSocket message/byte counters. If desired, add an `UpgradeGroupInfo`
  registry to `AbstractHttp3Protocol` analogous to
  `AbstractHttp11Protocol.getUpgradeGroupInfo()`, and register the
  `UpgradeInfo` from the tunnel connection.
* The HTTP request itself is counted once by `Http3Processor`'s `finally`
  block (the handshake response), and access-logged by `CoyoteAdapter`.
  WebSocket message traffic is tracked by `UpgradeInfo`, not by
  `Request.updateCounters()`.
* `ServletConnection`/`getProtocolRequestId()` continue to report the QUIC
  stream ID during the handshake.

## 9. File-by-file change list

Core interfaces and processor:

* `java/org/apache/coyote/AbstractProcessor.java`
  * add a `dispatchUpgrade(SocketEvent)` hook and short-circuit in
    `dispatch()` when `isUpgrade()` is true.
* `java/org/apache/coyote/Constants.java`
  * add the protocol-neutral Extended CONNECT attribute constant.
* New `java/org/apache/coyote/UpgradeTransport.java`
  * transport abstraction.
* New `java/org/apache/coyote/UpgradeTransportAware.java`
  * handler hook.
* `java/org/apache/coyote/http3/Http3Processor.java`
  * upgrade fields, `doHttpUpgrade`, `getUpgradeToken`, `isUpgrade`,
    `dispatchUpgrade`, `processHttpUpgrade`, `timeoutAsync`, `recycle`
    upgrade path, `finishResponse` upgrade early-return.
  * `Http3InputBuffer.readTunnel()` and `readMoreData(..., pump)` changes.
  * `Http3OutputBuffer` tunnel write/flush/readiness/batch and
    `doWrite()` upgrade discard.
  * `Http3TunnelTransport` and `Http3TunnelConnection` inner classes.
* `java/org/apache/coyote/http3/Constants.java`
  * alias the attribute constant to the protocol-neutral one.
* `java/org/apache/coyote/http3/AbstractHttp3Protocol.java`
  * optional upgrade stats/JMX support; no protocol logic change required.

Container:

* `java/org/apache/catalina/connector/CoyoteAdapter.java`
  * allow Extended CONNECT (attribute present) through CONNECT filtering.
* `java/org/apache/catalina/connector/Request.java`
  * Extended CONNECT status handling, protocol name for `UpgradeToken`.

WebSocket:

* New `java/org/apache/tomcat/websocket/server/SocketWrapperUpgradeTransport.java`.
* `java/org/apache/tomcat/websocket/server/WsFrameServer.java`
  * read via transport; add `isReadSuspended()`.
* `java/org/apache/tomcat/websocket/server/WsRemoteEndpointImplServer.java`
  * write/flush/readiness/lock/execute/timeout/close via transport; keep the
    HTTP/1.1 NIO2 vectored path using the underlying socket wrapper.
* `java/org/apache/tomcat/websocket/server/WsHttpUpgradeHandler.java`
  * transport-aware init; abnormal-close abort; suspension state return.
* `java/org/apache/tomcat/websocket/server/UpgradeUtil.java`
  * RFC 8441/9220 Extended CONNECT handshake variant.
* `java/org/apache/tomcat/websocket/server/WsFilter.java`
  * detect HTTP/3 Extended CONNECT via `UpgradeUtil`.
* `java/org/apache/coyote/http3/LocalStrings.properties`
  * new upgrade/error messages.
* `java/org/apache/tomcat/websocket/server/LocalStrings.properties`
  * new handshake messages if needed.

Docs:

* `webapps/docs/config/http3.xml`
  * document RFC 9220 support and required connector configuration.
* `webapps/docs/web-socket-howto.xml`
  * document HTTP/3 WebSocket support and server-side/client-side scope.
* This architecture document.

Tests:

* `test/org/apache/coyote/http3/TestHttp3Functional.java`
  * Extended CONNECT routing/upgrade unit tests with
    `ControlledQuicSocketWrapper`.
* New `test/org/apache/coyote/http3/TestHttp3WebSocket.java`
  * end-to-end handshake/echo/close tests via the Python client.
* `test/org/apache/coyote/http3/http3_client.py`
  * new `websocket` client mode: Extended CONNECT, WS framing, DATA
    frames, FIN/RST assertion.
* Existing WebSocket tests:
  * `TestUpgrade`, `TestUpgradeInternalHandler`,
  * `TestWsRemoteEndpointImplServerDeadlock`,
  * `TestAsyncMessagesPerformance`,
  * `TestWebSocketFrameClient`,
  * `TestPerMessageDeflate`, `TestWsSubprotocols`, `TestClose`,
  * all should pass unchanged.

## 10. Implementation phases

### Phase 1 - WebSocket transport abstraction (HTTP/1.1 behaviour unchanged)

* Add `UpgradeTransport`/`UpgradeTransportAware`.
* Add `SocketWrapperUpgradeTransport`.
* Refactor `WsFrameServer`, `WsRemoteEndpointImplServer`,
  `WsHttpUpgradeHandler` to use the transport.
* Add `WsFrameServer.isReadSuspended()` and the suspension return state.
* Run the full existing WebSocket test suite.

Exit criteria: all existing HTTP/1.1 WebSocket tests pass; no connector
configuration or API changes.

### Phase 2 - HTTP/3 upgrade plumbing

* Add the `AbstractProcessor.dispatchUpgrade()` hook.
* Add upgrade lifecycle fields and `processHttpUpgrade()` to
  `Http3Processor`.
* Implement `Http3TunnelTransport`/`Http3TunnelConnection`.
* Add tunnel read/write methods to the HTTP/3 buffers.
* Add the upgrade `recycle()` path and stream termination.
* Add `finishResponse()` and `Http3OutputBuffer.doWrite()` upgrade guards.
* Unit tests with `ControlledQuicSocketWrapper`:
  * handshake 200 response headers, no Upgrade/Connection/Accept,
  * DATA frame in/out, split frames, pre-buffered bytes,
  * FIN/RST mapping, non-blocking backpressure,
  * suspension maps to `ASYNC_IO`.

Exit criteria: an Extended CONNECT request with a registered `websocket`
protocol can be upgraded in unit tests and tunnel bytes flow correctly.

### Phase 3 - Container routing and handshake

* Promote the Extended CONNECT attribute constant.
* Allow Extended CONNECT in `CoyoteAdapter`.
* Update `Request.upgrade()` status/protocol-name handling.
* Implement the RFC 8441/9220 handshake variant in `UpgradeUtil`/`WsFilter`.
* Add unit tests for the handshake detection and status/headers.

Exit criteria: an HTTP/3 Extended CONNECT for a deployed `@ServerEndpoint`
passes security/mapping/filter processing, calls `req.upgrade()`, and gets a
200 handshake response with the negotiated WebSocket headers.

### Phase 4 - End-to-end integration

* Add the `websocket` mode to `http3_client.py`.
* `TestHttp3WebSocket` (handshake, text/binary echo, subprotocol,
  permessage-deflate, orderly close, peer FIN, peer RST,
  large message across multiple DATA frames, multiple concurrent WebSocket
  streams, mixed WebSocket + normal HTTP/3 requests, and an endpoint that
  suspends/resumes message processing to exercise the
  `SUSPENDED` -> `ASYNC_IO` mapping).
* Optional manual interop with Chrome/Firefox over `Alt-Svc`.

Exit criteria: end-to-end tests pass on the OpenSSL QUIC transport; run the
same tests on quiche/ngtcp2 if available.

### Phase 5 - Hardening and optional extensions

* Large HTTP/3 DATA frame support for tunnel reads (stream payload with a
  `long` remainder, or a documented/configurable limit).
* UpgradeInfo/JMX group registration.
* Idle-timeout guidance (`idleTimeoutMs` vs WebSocket ping/keepalive).
* RFC 8441 HTTP/2 reuse (separate project; transport abstraction is ready).
* Security review of handshake routing and error mapping.
* Final documentation.

Generic external `HttpUpgradeHandler` tunnel Servlet streams are not part of
this WebSocket plan. If that capability is ever needed for non-WebSocket
upgrade protocols, it should be a separate HTTP/3 feature built on the same
upgrade lifecycle, not a second WebSocket implementation.

### Definition of done

A WebSocket application deployed unchanged to a web application on an
HTTP/3 connector configured with `enableConnectProtocol="true"` and
`connectProtocols="websocket"` can:

* complete an Extended CONNECT handshake with `:protocol=websocket` and
  receive a 200 response with the negotiated WebSocket headers,
* exchange text/binary messages, pings/pongs and permessage-deflate frames,
* use blocking and asynchronous sends and normal Jakarta WebSocket session
  APIs,
* close the session with a proper WebSocket Close handshake followed by a
  stream FIN, or observe an abnormal closure with `H3_REQUEST_CANCELLED` on
  protocol/I/O failure,
while HTTP/1.1 WebSocket and all existing HTTP/3 tests continue to pass.

## 11. Test plan

### Unit tests

1. Extended CONNECT validation (existing tests extended):
   * `:protocol=websocket` with `enableConnectProtocol=true` and
     `connectProtocols=websocket` dispatches; unregistered value is 501.
   * plain CONNECT remains 501.
   * `:path`, `:scheme`, `:authority` validation unchanged.
2. Upgrade lifecycle:
   * fake adapter calls `req.action(UPGRADE, token)`; assert 200 HEADERS,
     no `upgrade`/`connection`/`sec-websocket-accept`, no
     `content-length`, `UpgradeInfo` state.
   * assert `SocketState.UPGRADED` and `isUpgrade()`.
3. Tunnel I/O:
   * read pre-buffered DATA payload, split DATA frames, concatenated WS
     frames in one DATA frame.
   * write WS bytes; decode captured DATA frames and verify payload.
   * non-blocking queue/batch/backpressure and write-interest registration.
   * FIN maps to EOF; RESET maps to IOException / H3_REQUEST_CANCELLED.
   * HEADERS after CONNECT fails connection with H3_FRAME_UNEXPECTED.
4. Handshake predicates:
   * HTTP/1.1 requests still detected exactly as before.
   * HTTP/3 Extended CONNECT detected; plain HTTP/3 CONNECT not detected.
   * missing key accepted; wrong version rejected; origin/subprotocol/
     extension handling.
5. HTTP/1.1 regression:
   * `Request.upgrade()` still sets 101 for HTTP/1.1.

### Integration tests (aioquic Python client)

* `websocket` command:
  * send Extended CONNECT with `:protocol=websocket`,
    `sec-websocket-version=13`, optional subprotocol/extensions/origin.
  * assert `STATUS=200`, negotiated headers, absence of
    `sec-websocket-accept`, `upgrade`, `connection`.
  * send masked WS text/binary frames as HTTP/3 DATA payload; assert echo.
  * split a WS frame across multiple DATA frames; assert.
  * send multiple WS frames in one DATA frame; assert.
  * send WS Close, read server Close, assert clean FIN.
  * send FIN without Close; assert server abnormal closure.
  * reset the stream; assert server does not send FIN and handles the
    abnormal close (`H3_REQUEST_CANCELLED` if it chooses to respond).
  * send HEADERS after CONNECT; assert connection error.
  * unsupported `:protocol`; assert 501.
  * `enableConnectProtocol` disabled; assert H3_MESSAGE_ERROR.
* Run with `enableConnectProtocol=true`,
  `connectProtocols=websocket`, a deployed `TesterEchoServer.Config` and a
  normal HTTP/3 servlet on the same connection to verify multiplexing.

### Browser interop (optional)

Chrome supports WebSocket over HTTP/3 via Alt-Svc/`SETTINGS_ENABLE_CONNECT_PROTOCOL`
depending on version; Firefox support varies. Validate with a real browser
and a trusted test CA per `HTTP3_TESTING_HOWTO.md`. This is a manual
interop check, not a CI requirement.

### Security tests

* Plain CONNECT is never dispatched/upgraded.
* Extended CONNECT to a path with no WebSocket endpoint does not upgrade.
* Origin check rejects cross-origin handshakes.
* `Sec-WebSocket-Key` does not affect acceptance (no key required), but the
  CONNECT method and pseudo-header restrictions remain (RFC 8441 security
  considerations).
* A malformed HTTP/3 frame sequence after CONNECT fails the connection, not
  just the stream.
* A peer cannot use padding/zero-length DATA frames to keep a worker busy
  indefinitely (existing non-body frame budgets).
* No response body/content headers on the 2xx CONNECT handshake.

## 12. Risks and mitigations

| Risk | Mitigation |
|---|---|
| State transfer if a separate upgrade processor is used | Avoid it; implement in-place upgrade (Option A) |
| Upgraded processor returned to the pool while WebSocket threads still use it | Mark non-reusable, dedicated `recycle()` path, destroy handler before release |
| QUIC endpoints close the stream on `SocketState.SUSPENDED` | Map WebSocket read suspension to `ASYNC_IO`; return `SUSPENDED` only to HTTP/1.1 and map in the HTTP/3 dispatcher |
| Response committed before upgrade branch sends handshake headers | The handshake headers are committed during `Response.finishResponse()`; `processHttpUpgrade()` defensively sends them if not started and validates 2xx |
| Servlet response body leaks into the tunnel | `upgradeMode` discards `Http3OutputBuffer.doWrite()` bytes; tunnel uses a separate `writeTunnel()` path |
| Large WebSocket frame rejected by the 256 KiB output queue | Message-level write batch (`startWriteBatch`/`endWriteBatch`) maps to the existing oversized-batch queue logic |
| Large HTTP/3 DATA frame >16 MiB rejected | Document phase 1 limit; phase 5 tunnel streaming with a `long` remainder |
| Peer FIN without WebSocket Close treated incorrectly | Peer FIN maps to EOF; WebSocket layer reports abnormal closure (1006) |
| Peer RST causes FIN or silence | Tunnel read throws; abnormal close calls `abort()` -> `H3_REQUEST_CANCELLED`; no FIN after reset |
| `setCurrentProcessor(WebConnection)` corrupts the QUIC wrapper's processor association | HTTP/3 transport sets the `Http3Processor`, not the `WebConnection` |
| WebSocket close initiated from a non-container thread leaves the stream registered | `transport.close()`/`abort()` triggers a STOP dispatch (`processSocket(STOP, true)`) when not on the request thread |
| Existing HTTP/1.1 WebSocket regressions from the transport refactor | Adapter delegates one-to-one; keep the NIO2 vectored path on the raw wrapper; run the full existing WebSocket suite |
| No client-side HTTP/3 WebSocket support | Explicit non-goal; document; server-side tests use aioquic |
| Idle timeout closes long-lived WebSocket sessions | Document `idleTimeoutMs`; WebSocket ping/keepalive or a larger timeout for WebSocket-heavy connectors |
| HTTP/2 and HTTP/3 code diverge | Keep the transport abstraction and handshake predicate protocol-neutral; RFC 8441 can reuse them later |

## 13. Open questions

1. Should `enableConnectProtocol` default to `true` when
   `connectProtocols` contains `websocket`, or remain explicitly opt-in?
   Recommendation: remain opt-in; document the required configuration.
2. Should `websocket` be automatically registered in `connectProtocols`
   when the WebSocket implementation is present? The connector has no
   webapp/WebSocket-container awareness; explicit configuration is cleaner.
3. Should the successful handshake status be exactly `200`, or any `2xx`?
   Recommendation: `200` for the WebSocket handshake; accept any `2xx` if
   an application/Valve sets one.
4. Should an invalid/missing `Sec-WebSocket-Version` over RFC 9220 return
   `400` (recommended) or `426` without the forbidden `Upgrade` header?
5. Should a separate generic external `HttpUpgradeHandler` stream capability
   be added for non-WebSocket protocols? It is explicitly not required for
   WebSocket and not part of this plan's definition of done. If wanted, it
   should use the same HTTP/3 upgrade lifecycle and be designed separately
   from the WebSocket internal path.
6. How should `WsSession` close timeouts and server-initiated close map to
   FIN vs `H3_REQUEST_CANCELLED`? Recommendation: FIN after a Close frame
   (orderly WebSocket close); RST for protocol/I/O failures and peer resets.
7. Do we need a tunnel-specific `MAX_FRAME_LENGTH`/streaming reader in
   phase 1, or is the existing 16 MiB DATA frame limit acceptable initially?
8. Should the `Http3Processor` expose an `UpgradeInfo` group via JMX in
   phase 1, or defer metrics integration?

## 14. Documentation plan

* `webapps/docs/config/http3.xml`:
  * update `connectProtocols`/`enableConnectProtocol` descriptions to state
    that `websocket` is a supported value,
  * add a "WebSocket over HTTP/3" section with a connector example,
  * document the server-side-only scope and idle-timeout guidance.
* `webapps/docs/web-socket-howto.xml`:
  * add HTTP/3 support, requirements and limitations.
* This architecture document:
  * keep updated as implementation progresses.
* Changelog entry when implemented.
* Security model note: RFC 9220 handshakes pass through the normal request
  mapping/security/filter chain, and the CONNECT method/pseudo-header rules
  provide the RFC 8441 security properties. See `SECURITY.md` and the
  Tomcat security model for the project's threat model and scope.

## 15. Future work: WebTransport (separate project, not part of this plan)

WebTransport has real browser adoption by 2026 (Baseline "newly available"
since March 2026: Chrome 97+, Edge 97/98+, Firefox 114+, Safari 26.4+), while
RFC 9220 WebSocket over HTTP/3 has no production browser implementation
(Chromium is at "Intent to Prototype"/experimental, Firefox and Safari have
no implementation announced). This does not make WebTransport a substitute
for this plan, for the following reasons:

* WebTransport over HTTP/3 is still an IETF Internet-Draft
  (`draft-ietf-webtrans-http3`, as of mid-2026) and the W3C API is a
  Candidate Recommendation Snapshot, not a final Recommendation. RFC 9220 is
  a stable Proposed Standard.
* There is no Jakarta WebTransport API. Jakarta WebSocket 2.3 (Jakarta EE 12)
  does not add WebTransport support; the Jakarta EE 12 roadmap mentions
  general HTTP/3 requirements, not a WebTransport specification. Tomcat core
  would either need a new standard API or a proprietary Tomcat extension.
* WebTransport is not just "Extended CONNECT + DATA frames". It requires:
  * QUIC DATAGRAM frames (RFC 9221) and `max_datagram_frame_size`
    negotiation,
  * HTTP Datagrams and the Capsule Protocol (RFC 9297) and
    `SETTINGS_H3_DATAGRAM`,
  * WebTransport-over-HTTP/3 session and stream mapping,
  * the `RESET_STREAM_AT` QUIC extension,
  * server-initiated unidirectional and bidirectional streams,
  * a new application API for sessions, streams, datagrams, backpressure and
    origin/protocol validation.

The current HTTP/3 implementation explicitly does not negotiate
`max_datagram_frame_size` (see `Http3Processor.processFrame()`), so
datagram-based protocols cannot run over this connector today. Adding
WebTransport would therefore touch all QUIC transports (OpenSSL, quiche,
ngtcp2), the HTTP/3 connection manager, settings, datagram framing, stream
scheduling and the API layer. It is a separate, much larger project.

Strategy:

* Finish RFC 9220 WebSocket support first. It is a stable RFC, fits the
  existing Jakarta WebSocket API, requires no new application API, and is
  opt-in via `enableConnectProtocol`/`connectProtocols`, so the lack of
  browser production adoption is low-risk.
* Treat WebTransport as future work. A separate design plan is maintained in
  `webtransport-plan.md`. Re-evaluate when the IETF WebTransport over HTTP/3
  specification and the W3C API are final, a Jakarta WebTransport API exists
  (or Tomcat decides to publish a proprietary extension), and the chosen QUIC
  transports expose QUIC DATAGRAM and `RESET_STREAM_AT` support.
* A framework-level WebTransport sidecar (as some projects do) is an
  alternative in the meantime, but it is not part of the Tomcat HTTP/3
  connector plan.

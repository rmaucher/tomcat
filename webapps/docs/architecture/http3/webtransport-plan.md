# WebTransport over HTTP/3 in Tomcat - design plan

Status: draft, separate design plan. Not implemented.

This plan is intentionally separate from the RFC 9220 WebSocket plan. WebTransport
is not a WebSocket variant: it is a connection-scoped protocol with sessions,
multiple streams and unreliable datagrams, and it requires a new application API.
It should not be folded into the WebSocket implementation.

## 1. Summary

The goal is browser-compatible **WebTransport over HTTP/3** on Tomcat's QUIC
connectors, with application code using a hypothetical future **Jakarta EE
WebTransport API** (for example a `jakarta.webtransport` specification). Tomcat
would implement that API in a container analogous to the existing Jakarta
WebSocket implementation.

This is a much larger project than RFC 9220 WebSocket support. It requires:

* QUIC transport support for DATAGRAM frames, server-initiated bidirectional
  and unidirectional streams, and reliable stream reset (`RESET_STREAM_AT`).
* HTTP/3 support for `SETTINGS_H3_DATAGRAM`, `SETTINGS_WT_ENABLED`, WebTransport
  flow-control settings and capsules.
* A connection-level WebTransport session manager that multiplexes sessions,
  WebTransport streams and datagrams on one HTTP/3 connection.
* A new Jakarta (or provisional Tomcat) API and container for sessions, streams,
  datagrams, protocol negotiation, origin checks and lifecycle.
* Browser/aioquic interoperability testing.

As of 2026 WebTransport has real browser adoption (Baseline since March 2026:
Chrome 97+, Edge 97/98+, Firefox 114+, Safari 26.4+), but the server protocol is
still an IETF Internet-Draft (`draft-ietf-webtrans-http3`) and the W3C API is a
Candidate Recommendation. There is **no Jakarta WebTransport API** yet. This
plan therefore assumes a hypothetical Jakarta API and treats the exact API
shape, draft version and transport capability matrix as explicit project
prerequisites.

## 2. Scope and non-goals

In scope:

* The browser/native `webtransport-h3` variant of WebTransport over HTTP/3.
* HTTP/3 sessions established by Extended CONNECT.
* Bidirectional and unidirectional WebTransport streams, both client- and
  server-initiated.
* Unreliable HTTP Datagrams over QUIC DATAGRAM frames.
* Session flow control (WebTransport stream/data limits and capsules).
* Session close, drain and HTTP/3 GOAWAY interaction.
* A hypothetical Jakarta EE WebTransport API as the application API.
* Tomcat container integration: endpoint mapping, configurator, origin check,
  protocol negotiation, instance lifecycle, security integration.
* Browser and aioquic interoperability tests.

Out of scope for the first implementation:

* The capsule-based single-stream WebTransport variant over HTTP/3
  (`webtransport` token / WebTransport over HTTP/2-style capsule protocol).
  It may be useful for intermediaries or non-browser clients later.
* WebTransport over HTTP/2.
* A WebTransport client API in Tomcat.
* Peer-to-peer WebTransport.
* QUIC 0-RTT session establishment: WebTransport CONNECT is not safe for 0-RTT;
  settings caching/0-RTT support is outside this plan.
* Implementing a new Jakarta specification inside Tomcat. Tomcat implements
  the hypothetical API; creating the API is a separate standards effort.
* Support on a QUIC transport that lacks QUIC DATAGRAM and `RESET_STREAM_AT`.
  Such a transport must be reported as not WebTransport-capable.
* Full intermediary/proxy WebTransport translation.

RFC 9220 WebSocket support and this plan share some HTTP/3 plumbing (Extended
CONNECT routing, SETTINGS, connection-level stream handling), but they must not
be conflated.

## 3. Protocol snapshot (2026)

The current WebTransport over HTTP/3 design (draft-ietf-webtrans-http3-16/17)
uses:

* Extended CONNECT with `:protocol = webtransport-h3` (newer drafts; older
  drafts and some clients may still use `webtransport`).
* `:scheme = https`, `:authority` and `:path` identifying the WebTransport
  resource.
* Optional `Origin` header, which a browser client sends and the server must
  verify.
* `WT-Available-Protocols` request header and `WT-Protocol` response header for
  application protocol negotiation (Structured Fields).
* A `2xx` response to accept the session; `405` if the resource does not
  support WebTransport; `403` for an Origin failure.
* The CONNECT stream ID (a client-initiated bidirectional stream, divisible by
  4) is the WebTransport **Session ID**.
* The CONNECT stream carries the Capsule Protocol after the `2xx` response.
* WebTransport streams:
  * unidirectional stream type `0x54`, followed by the session ID as a QUIC
    varint and the application payload;
  * bidirectional streams with the first QUIC varint `0x41` (`WT_STREAM`),
    followed by the session ID and the application payload. This applies to
    both client-initiated and server-initiated bidirectional streams.
* Datagrams use HTTP Datagrams over QUIC DATAGRAM frames:
  * QUIC DATAGRAM frame payload begins with the HTTP/3 Datagram Quarter Stream
    ID (session ID / 4), followed by the WebTransport datagram payload.
* Required settings/transport parameters for a WebTransport-capable HTTP/3
  connection:
  * `SETTINGS_WT_ENABLED` = 1 (draft-specific codepoint; see Section 4).
  * `SETTINGS_ENABLE_CONNECT_PROTOCOL` = 1.
  * `SETTINGS_H3_DATAGRAM` (0x33) = 1.
  * QUIC `max_datagram_frame_size` > 0.
  * QUIC `reset_stream_at` transport parameter present.
* Flow control uses WebTransport settings and capsules:
  * `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` (0x2b64) and
    `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` (0x2b65);
  * `SETTINGS_WT_INITIAL_MAX_DATA` (0x2b61);
  * `WT_MAX_STREAMS` capsules (0x190B4D3F and 0x190B4D40), `WT_STREAMS_BLOCKED`
    (0x190B4D43/44), `WT_MAX_DATA` (0x190B4D3D), `WT_DATA_BLOCKED` (0x190B4D41).
* Session termination:
  * CONNECT stream FIN or reset terminates the session;
  * `WT_CLOSE_SESSION` capsule (0x2843) with a 32-bit application error code and
    a UTF-8 reason (max 1024 bytes), followed by FIN on the CONNECT stream;
  * `WT_DRAIN_SESSION` capsule (0x78ae) requests graceful drain;
  * HTTP/3 GOAWAY is a signal to drain all WebTransport sessions.
* WebTransport error codes:
  * `H3_DATAGRAM_ERROR` = 0x33;
  * `WT_BUFFERED_STREAM_REJECTED` = 0x3994bd84;
  * `WT_SESSION_GONE` = 0x170d7b68;
  * `WT_FLOW_CONTROL_ERROR` = 0x045d4487;
  * `WT_ALPN_ERROR` = 0x0817b3dd;
  * `WT_REQUIREMENTS_NOT_MET` = 0x212c0d48;
  * `WT_APPLICATION_ERROR` range 0x52e4a40fa8db..0x52e5ac983162, excluding the
    reserved `0x1f*N+0x21` codepoints.

Draft versioning is a first-class problem:

* `SETTINGS_WT_ENABLED` has draft-specific codepoints. Draft-16/17 uses
  `0x2c7cf000`; older drafts used other values.
* The upgrade token changed from `webtransport` to `webtransport-h3` in newer
  drafts.
* Browsers may implement different draft versions. A server implementation
  must be version-aware or pin itself to the browser versions it targets.

## 4. Architecture overview

```text
Jakarta WebTransport application
    @ServerWebTransportEndpoint / WebTransportConfigurator / listeners
            |
            v
WebTransportServerContainer (webapp, endpoint registry, lifecycle, security)
            |
            v
WebTransportSession (per CONNECT stream)
    streams, datagrams, flow control, close/drain
            |
            v
WebTransportConnectionManager (per QUIC connection)
    session map, pending stream/datagram buffers, stream routing
            |
            v
HTTP/3 connection layer
    SETTINGS, H3 datagrams, capsules, stream classification
            |
            v
QUIC transport
    streams (bidi/uni, local/remote), DATAGRAM frames, RESET_STREAM_AT
```

Key architectural decision: **WebTransport must be a connection-level subsystem,
not a single-stream HTTP upgrade.** The CONNECT stream is the session control
stream; data streams and datagrams are sibling QUIC streams/connection-level
datagrams. A per-request `Http3Processor` cannot own the whole protocol alone.

The CONNECT request still passes through the normal Servlet mapping/filter chain
so that URL mapping, security constraints, authentication, cookies and Origin
checks work as usual. A `WebTransportFilter` recognises the WebTransport
Extended CONNECT, resolves the endpoint, performs the handshake, asks the
WebTransport container to create a session, and tells the HTTP/3 layer to accept
and register it.

## 5. Hypothetical Jakarta EE WebTransport API

This plan assumes a future Jakarta specification (illustrative, not existing):

Package `jakarta.webtransport` and `jakarta.webtransport.server`.

### 5.1 Server endpoint model

```java
@ServerWebTransportEndpoint("/wt")
public class EchoEndpoint {
    @OnWebTransportSession
    public void open(WebTransportSession session) { ... }

    @OnWebTransportStream
    public void stream(WebTransportStream stream) { ... }

    @OnWebTransportDatagram
    public void datagram(WebTransportDatagram datagram) { ... }

    @OnWebTransportClose
    public void close(WebTransportSession session, int errorCode, String reason) { ... }

    @OnWebTransportError
    public void error(WebTransportSession session, Throwable t) { ... }
}
```

Programmatic equivalent:

```java
ServerWebTransportConfig config = ServerWebTransportConfig.builder(EchoEndpoint.class)
        .path("/wt")
        .subprotocols("echo", "chat")
        .configurator(new MyConfigurator())
        .build();
WebTransportServerContainer container = ...;
container.addEndpoint(config);
```

### 5.2 Container

```java
public interface WebTransportServerContainer {
    void addEndpoint(ServerWebTransportConfig config) throws DeploymentException;
    void removeEndpoint(...);
    Set<WebTransportSession> getOpenSessions();
    WebTransportConfigurator getDefaultConfigurator();
    ...
}
```

The container is per `ServletContext` (like `WsServerContainer`) and is
initialised by a `ServletContainerInitializer`/`ServletContextListener`.

### 5.3 Configurator / handshake

```java
public interface WebTransportConfigurator {
    boolean checkOrigin(String origin);

    String getNegotiatedSubprotocol(List<String> supported,
            List<String> requested);

    void modifyHandshake(ServerWebTransportConfig config,
            WebTransportHandshakeRequest request,
            WebTransportHandshakeResponse response);
}
```

`WebTransportHandshakeRequest` exposes the normal HTTP request data:
request URI, path parameters, query string, headers, Origin, cookies,
`HttpSession`, user principal, secure flag, local/remote address and the
Servlet request attributes. `WebTransportHandshakeResponse` allows application
response headers and selected subprotocol.

### 5.4 Session

```java
public interface WebTransportSession extends AutoCloseable {
    String getSessionId();
    URI getRequestURI();
    String getProtocol();                 // negotiated WT-Protocol
    Map<String,List<String>> getRequestHeaders();
    Principal getUserPrincipal();
    HttpSession getHttpSession();
    boolean isSecure();

    WebTransportBidirectionalStream createBidirectionalStream()
            throws IOException;
    WebTransportUnidirectionalStream createUnidirectionalStream()
            throws IOException;

    WebTransportDatagramChannel getDatagramChannel();

    void setStreamListener(WebTransportStreamListener listener);
    void setDatagramListener(WebTransportDatagramListener listener);

    void drain();
    boolean isDraining();

    void close(int applicationErrorCode, String reason);
    int getApplicationErrorCode();
    String getApplicationErrorReason();
}
```

### 5.5 Streams

```java
public interface WebTransportStream extends AutoCloseable {
    long getStreamId();
    boolean isBidirectional();
    boolean isUnidirectional();
    boolean isLocalInitiated();

    InputStream getInputStream() throws IOException;       // blocking or non-blocking
    OutputStream getOutputStream() throws IOException;

    void setReadListener(WebTransportReadListener listener);
    void setWriteListener(WebTransportWriteListener listener);

    void reset(int applicationErrorCode);
    void stopSending(int applicationErrorCode);

    void close() throws IOException;
}
```

Blocking and non-blocking access should follow the Jakarta Servlet async I/O
style: listeners, `isReady`, `onDataAvailable`, `onWritePossible`, `onError`,
`onAllDataRead`. The exact API is part of the hypothetical Jakarta specification;
Tomcat only implements it.

### 5.6 Datagrams

```java
public interface WebTransportDatagramChannel {
    int getMaxDatagramSize();
    void send(ByteBuffer datagram) throws IOException;   // unreliable, may drop
    void setListener(WebTransportDatagramListener listener);
}

public interface WebTransportDatagramListener {
    void onDatagram(WebTransportDatagram datagram);
    void onError(Throwable t);
}
```

Datagrams are unreliable: a send may be dropped when the QUIC send queue, path
MTU or configured queue limit requires it. The API must document this and expose
statistics/drop counters.

### 5.7 Threading and lifecycle

* The session endpoint instance is created through the container's
  `InstanceManager` and receives CDI/injection where applicable.
* `onOpen`/`onClose`/`onError` run on container threads.
* Stream and datagram callbacks run on container threads; blocking operations
  must be allowed only where the API defines a blocking mode.
* The API must define backpressure: when a stream/datagram queue is full, writes
  block, fail with an IOException, or return a "would block" result according to
  the Jakarta contract.
* Sessions are registered with the container for `getOpenSessions`,
  close-timeout processing and shutdown.
* Endpoint configurators may add response headers, negotiate subprotocols, and
  reject the handshake.

## 6. Additions to the QUIC transport layer

The current QUIC abstraction is HTTP/3-stream oriented. WebTransport needs
connection-level datagrams and arbitrary server-initiated streams.

### 6.1 `QuicConnection`

Add:

```java
boolean isDatagramSupported();
int getMaxDatagramFrameSize();       // local advertised limit
int getPeerMaxDatagramFrameSize();   // peer's advertised limit, or 0

/**
 * Sends one unreliable datagram. May drop or fail when the send queue,
 * path MTU or peer limit does not permit it. Must be called on the
 * transport thread or hop there.
 */
boolean sendDatagram(ByteBuffer data) throws IOException;

/**
 * Opens a server-initiated stream. The first bytes (stream type/session ID)
 * are written atomically before application data.
 */
QuicStream openStream(boolean bidirectional) throws IOException;
```

Add stream reset variants:

```java
boolean resetStreamAt(QuicStream stream, long appErrorCode,
        long reliableSize) throws IOException;

void stopSending(QuicStream stream, long appErrorCode) throws IOException;
```

`QuicStream` additions:

```java
boolean isBidirectional();
boolean isLocalInitiated();
long getStreamId();
// existing read state and write buffer accessors remain
```

### 6.2 `QuicConnectionManager`

Add:

```java
/** Local max_datagram_frame_size advertised in transport parameters. */
int getMaxDatagramFrameSize();

/** Receive a QUIC DATAGRAM frame (on the poll thread). */
void processDatagram(QuicConnection connection, ByteBuffer datagram)
        throws Exception;

/**
 * Classify a newly accepted client-initiated bidirectional stream from its
 * first bytes. Return a WebTransport stream routing decision or "HTTP request".
 */
StreamClassification classifyClientStream(QuicConnection connection,
        long streamId, ByteBuffer firstBytes);

/** A server-initiated stream request; may carry initial header bytes. */
QuicStream openServerStream(QuicConnection connection,
        boolean bidirectional, ByteBuffer initialData) throws Exception;
```

The existing `nextServerUniStream`/`getServerUniStreamInitData` fixed-index API
(for HTTP/3 control and QPACK streams) remains, but it is not sufficient for
WebTransport: WebTransport can create arbitrarily many server uni/bidi streams
with per-session header bytes. Add a generic outgoing-stream queue alongside it.

### 6.3 `QuicProtocol`

Add capability/configuration methods:

```java
boolean isWebTransportSupported();
int getMaxDatagramFrameSize();
boolean isResetStreamAtSupported();
long getWebTransportRequirementsErrorCode();  // WT_REQUIREMENTS_NOT_MET
```

The connector must refuse `webTransportEnabled=true` on a transport that cannot
negotiate QUIC DATAGRAM and `RESET_STREAM_AT`.

### 6.4 Transport implementations

#### OpenSSL QUIC

Current state:

* `SSL_new_stream()` is used only for server unidirectional streams.
* The endpoint explicitly never creates bidirectional streams.
* The bindings expose `SSL_stream_reset()` (RESET_STREAM), not
  `RESET_STREAM_AT`.
* The endpoint does not negotiate `max_datagram_frame_size`.
* The OpenSSL 4.x QUIC API documentation does not expose application-level
  QUIC DATAGRAM frame send/receive.

Additions required:

* Native bindings and endpoint support for QUIC DATAGRAM receive/send, if the
  chosen OpenSSL version exposes it. If not, the OpenSSL transport cannot
  support browser WebTransport and must report `webTransportEnabled` as
  unavailable.
* Transport parameter `max_datagram_frame_size` (QUIC codepoint 0x20)
  configuration and validation.
* Transport parameter `reset_stream_at` (draft codepoint 0x1d) and
  `RESET_STREAM_AT` support, if available.
* `SSL_new_stream()` with bidirectional flags (default flags, not
  `SSL_STREAM_FLAG_UNI`) and a generic server stream creation queue.
* Incoming bidirectional stream classification: pre-read the first varint before
  dispatching to the HTTP/3 processor; route WebTransport streams to the session
  manager.
* Poll-loop delivery of inbound DATAGRAM frames to the protocol connection
  manager.
* Stream reset/stop-sending plumbing for `RESET_STREAM_AT` and `STOP_SENDING`.
* Free/lifecycle ordering for server-created bidi streams (stream SSLs before
  connection SSL, same as existing server uni streams).

If OpenSSL lacks DATAGRAM/RESET_STREAM_AT support, mark OpenSSL as not
WebTransport-capable and target quiche/ngtcp2 first.

#### quiche

Additions required:

* Bind and configure `quiche_config_enable_dgram()` (receive/send queue limits).
* Bind `quiche_conn_dgram_recv()` / `quiche_conn_dgram_send()` and deliver
  inbound datagrams to the connection manager.
* Set/validate `max_datagram_frame_size`.
* Create server-initiated bidirectional/unidirectional streams
  (`quiche_conn_stream_open`).
* `RESET_STREAM_AT` support is version-dependent; verify the pinned quiche
  version. If absent, quiche is not WebTransport-capable for browser clients.
* Classify incoming bidi streams before HTTP/3 dispatch.
* Expose effective datagram payload size (`dgram_max_writable_len`).

#### ngtcp2

Additions required:

* Set `max_datagram_frame_size` in transport parameters.
* Bind `ngtcp2_conn_writev_datagram()` and the receive-datagram callback.
* Create server-initiated streams (`ngtcp2_conn_open_bidi_stream`,
  `ngtcp2_conn_open_uni_stream`).
* `RESET_STREAM_AT` support is version-dependent; verify.
* Classify incoming bidi streams before HTTP/3 dispatch.
* Handle datagram queue limits and loss semantics.

### 6.5 Capability matrix

The connector exposes a per-transport capability report:

| Capability | OpenSSL 4.x | quiche 0.30 | ngtcp2 1.16/1.26 |
|---|---|---|---|
| QUIC DATAGRAM | To verify; likely absent in current API | Available (`enable_dgram`) | Available |
| `max_datagram_frame_size` | To add/verify | To bind | To add |
| `RESET_STREAM_AT` | To verify; likely absent | Version-dependent | Version-dependent |
| Server bidi streams | API supports; endpoint to add | To bind | To add |
| Server uni streams | Existing | To bind | To add |
| WebTransport-capable | Gate on capabilities | Gate on capabilities | Gate on capabilities |

This matrix must be resolved before implementation. Browser WebTransport is not
possible without QUIC DATAGRAM and `RESET_STREAM_AT`.

## 7. Additions to the HTTP/3 layer

### 7.1 Constants and settings

Add to `org.apache.coyote.http3.Constants`:

* `H3_SETTINGS_H3_DATAGRAM = 0x33`.
* `H3_SETTINGS_WT_ENABLED` (draft-specific; use a version table, draft-16/17:
  `0x2c7cf000`).
* `H3_SETTINGS_WT_INITIAL_MAX_STREAMS_UNI = 0x2b64`.
* `H3_SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI = 0x2b65`.
* `H3_SETTINGS_WT_INITIAL_MAX_DATA = 0x2b61`.
* `H3_FRAME_WT_STREAM = 0x41`.
* `H3_STREAM_TYPE_WEBTRANSPORT = 0x54`.
* Capsule types:
  * `DATAGRAM_CAPSULE = 0x00` (RFC 9297, optional fallback),
  * `WT_CLOSE_SESSION_CAPSULE = 0x2843`,
  * `WT_DRAIN_SESSION_CAPSULE = 0x78ae`,
  * `WT_MAX_STREAMS_CAPSULE_BIDI = 0x190B4D3F`,
  * `WT_MAX_STREAMS_CAPSULE_UNI = 0x190B4D40`,
  * `WT_STREAMS_BLOCKED_CAPSULE_BIDI = 0x190B4D43`,
  * `WT_STREAMS_BLOCKED_CAPSULE_UNI = 0x190B4D44`,
  * `WT_MAX_DATA_CAPSULE = 0x190B4D3D`,
  * `WT_DATA_BLOCKED_CAPSULE = 0x190B4D41`.
* Header names/values:
  * `WT-Available-Protocols`, `WT-Protocol`,
  * `webtransport-h3` (and legacy `webtransport` for older drafts).

`Http3Error` additions:

* `H3_DATAGRAM_ERROR = 0x33`.
* WebTransport error codes or a separate `WebTransportError` with the
  WT-specific codes and the `WT_APPLICATION_ERROR` mapping helpers.

`Http3Settings` additions:

* Parse and retain peer `SETTINGS_H3_DATAGRAM`, `SETTINGS_WT_ENABLED` and WT flow
  control settings (currently only `SETTINGS_MAX_FIELD_SECTION_SIZE` is
  retained).
* Validate `SETTINGS_H3_DATAGRAM` is 0 or 1; invalid -> H3_SETTINGS_ERROR.
* Validate `SETTINGS_WT_ENABLED` values (draft-specific allowed values; >1 or
  unknown version -> H3_SETTINGS_ERROR or reject WebTransport).
* Validate WT flow-control settings are non-negative varints and within
  implementation bounds.
* Advertise local settings in `Http3Settings.encode()`:
  * `SETTINGS_H3_DATAGRAM=1` when datagram support is enabled,
  * `SETTINGS_WT_ENABLED=1` when WebTransport is enabled,
  * `SETTINGS_WT_INITIAL_MAX_*` values from connector configuration,
  * `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` already handled by existing config.

`Http3ConnectionManager.ConnectionState` additions:

* Snapshot peer settings for H3 datagram/WebTransport.
* Track `webTransportRequiredSettingsMet` (peer + local settings/transport
  parameters).
* Track max sessions/streams/data limits and pending buffers.
* Expose `WebTransportConnectionState`/`WebTransportConnectionManager`.

### 7.2 Extended CONNECT and session establishment

`Http3Processor` (or a new connection-level handshake handler) must:

* Recognise `:protocol = webtransport-h3` (and legacy `webtransport` if
  supported).
* Validate `:scheme=https`, `:authority`, `:path`, optional `Origin`.
* Reject if the connection has not negotiated `SETTINGS_WT_ENABLED`,
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`, `SETTINGS_H3_DATAGRAM`,
  `max_datagram_frame_size > 0` and `reset_stream_at`;
  close with `WT_REQUIREMENTS_NOT_MET` if the client attempted WebTransport
  without the prerequisites.
* For draft versions, the server MUST NOT process an incoming WebTransport
  request until the client's SETTINGS have been received. Buffer/reject until
  then rather than dispatching a session prematurely.
* Dispatch the CONNECT request through the normal Servlet mapping/filter chain so
  that security constraints, authentication and path mapping apply.
* `WebTransportFilter` (new) resolves the `WebTransportServerContainer`
  endpoint for the path.
* `405` if no endpoint/resource supports WebTransport; `403` if Origin fails.
* Negotiate `WT-Available-Protocols` -> `WT-Protocol` through the container
  configurator.
* On acceptance, send a `2xx` response (normally `200`) with any application
  headers and `WT-Protocol`, then register the session in the connection-level
  manager.
* Reuse the existing successful-CONNECT response rules: no `Content-Length`,
  `Transfer-Encoding`, `Content-Type`, `Content-Language` or `Content-Encoding`,
  no compression and no response trailers (RFC 9110 Section 9.3.6, RFC 9114
  Section 4.4).
* The CONNECT stream remains open and switches to Capsule Protocol. No ordinary
  HTTP content/frames are expected after the `2xx` response.

Because WebTransport is connection-scoped, a plain Servlet `HttpUpgradeHandler`
is not enough. The HTTP/3 layer needs a Tomcat-internal bridge that hands the
CONNECT stream, session ID, connection handle and negotiated settings to the
WebTransport session manager after the container has accepted the session.

Any capsule bytes already pre-read by `Http3Processor` (for example from the
same QUIC packet as the CONNECT HEADERS) must be transferred to the session's
capsule reader. The processor must stop treating the stream as an HTTP request
body after the handoff.

### 7.3 Capsule Protocol

Implement a reusable capsule codec for the CONNECT stream:

```java
Capsule readCapsule(ByteBuffer in) throws IOException;
void writeCapsule(ByteBuffer out, long type, ByteBuffer value) throws IOException;
```

Requirements:

* Capsule = varint type + varint length + value. Unknown capsule types are
  skipped (but bounded).
* Capsules are carried in HTTP/3 DATA frames on the CONNECT stream; their bytes
  are the data stream, not HTTP message content.
* Do not buffer a whole capsule of arbitrary length before processing; stream
  capsule payloads incrementally where possible, especially DATAGRAM capsules.
* Truncated capsule on a clean FIN -> malformed message / H3_MESSAGE_ERROR.
* Capsule Protocol is only in use after a 2xx response.
* `Capsule-Protocol` header is not required by WebTransport; it may be omitted.
* Validate capsule-specific lengths and UTF-8:
  * `WT_CLOSE_SESSION`: 32-bit app error code + UTF-8 reason <= 1024 bytes;
    invalid length/UTF-8 -> H3_MESSAGE_ERROR.
  * `WT_DRAIN_SESSION`: length 0.
  * Flow-control capsules: one varint value; reject malformed/oversized values.
  * DATAGRAM capsule: bounded payload; discard if too large.
* A receiver should not wait for `WT_DATA_BLOCKED`/`WT_STREAMS_BLOCKED` before
  sending credit; send `WT_MAX_DATA`/`WT_MAX_STREAMS` proactively.

### 7.4 WebTransport streams

#### Client-initiated bidirectional streams

* All client-initiated bidirectional QUIC streams are normally HTTP request
  streams. WebTransport reuses them: after the WebTransport settings are
  negotiated, a client may start a bidi stream with first varint `0x41`
  (`WT_STREAM`) + session ID.
* The HTTP/3 endpoint must classify such a stream **before** dispatching it to
  `Http3Processor` as an HTTP request. A WebTransport stream must not be parsed
  as HTTP/3 HEADERS/DATA frames.
* Classification can be done by the QUIC endpoint/connection manager from the
  pre-read bytes:
  * parse the first QUIC varint;
  * if it is `0x41`, parse the session ID, validate it is a client-initiated
    bidi stream ID divisible by 4 and belongs to an existing/pending session;
  * hand the stream to the session manager;
  * otherwise dispatch it as a normal HTTP/3 request stream.
  Alternatively, the HTTP/3 processor can detect `0x41` as the first frame
  before any HEADERS and hand the stream off to the WebTransport manager.
  Prefer endpoint/connection-manager classification so WebTransport streams never
  enter the HTTP request processor; the processor fallback is useful if the
  endpoint cannot peek the first bytes without delaying normal request dispatch.
* If a WebTransport stream arrives before the session is established, buffer it
  (bounded) or reject it with `WT_BUFFERED_STREAM_REJECTED`. After the session is
  closed, reset with `WT_SESSION_GONE`.
* Invalid session ID type -> `H3_ID_ERROR` connection error.
* The stream header bytes must be retained for `RESET_STREAM_AT` reliable size.

#### Client-initiated unidirectional streams

* The standard HTTP/3 unidirectional stream type parser handles the first
  varint. Add `0x54` as WebTransport stream type:
  * parse session ID varint;
  * validate/buffer/route as above;
  * rest of stream is application data.
* Unknown uni stream types continue to be discarded with the existing bounded
  handling.

#### Server-initiated streams

* Add generic server stream creation in the QUIC transport.
* For a bidirectional stream: write first varint `0x41` + session ID, then hand
  the stream to the application API.
* For a unidirectional stream: write stream type `0x54` + session ID, then hand
  the stream to the application.
* Respect QUIC stream limits and WebTransport per-session `WT_MAX_STREAMS`;
  block or fail new stream creation accordingly.
* Stream creation should be non-blocking or expose readiness; the API must define
  backpressure.

#### Stream reset/stop-sending

* WebTransport application error codes are 32-bit and must be mapped into the
  `WT_APPLICATION_ERROR` range, skipping reserved HTTP/3 codepoints. The draft
  gives the mapping (illustratively):

  ```text
  first = 0x52e4a40fa8db
  last  = 0x52e5ac983162

  toHttp(appCode) = first + appCode + floor(appCode / 0x1e)
  toApp(httpCode) = (httpCode - first) - floor((httpCode - first) / 0x1f)
  ```
* Reset a WebTransport data stream with `RESET_STREAM_AT` and a reliable size of
  at least the header length (varint `0x41` + session ID for bidi; `0x54` +
  session ID for uni). This is mandatory so the peer can associate the stream
  with its session even when data is reset early.
* `STOP_SENDING` must propagate to the peer and be exposed to the application.
* Receiving RESET_STREAM/STOP_SENDING outside the WT application error range
  still resets the stream, but no application error code is delivered.
* Session close resets all associated streams with `WT_SESSION_GONE`.

### 7.5 HTTP Datagrams

* The QUIC endpoint must deliver inbound QUIC DATAGRAM frames to the protocol
  connection manager.
* HTTP/3 Datagram decoding:
  * parse the Quarter Stream ID varint;
  * session ID = quarterStreamID * 4;
  * validate it is a client-initiated bidi stream ID;
  * route the remaining payload to the corresponding session's datagram queue.
* Invalid/too-short datagram -> `H3_DATAGRAM_ERROR`.
* Quarter Stream ID > 2^60-1 -> `H3_DATAGRAM_ERROR` connection error.
* A datagram for an unknown session:
  * buffer it briefly (bounded) while the session is being established, or drop
    it;
  * after the session is closed, drop silently.
* A datagram for a non-WebTransport stream -> terminate that request with
  `H3_DATAGRAM_ERROR`.
* Do not send datagrams unless both `SETTINGS_H3_DATAGRAM=1` and
  `max_datagram_frame_size>0` are negotiated.
* Do not send datagrams after the session's CONNECT send side is closed.
* Datagram send:
  * encode Quarter Stream ID + payload;
  * pass to the QUIC transport, which may drop/queue according to path MTU,
    flow control and send queue limits;
  * expose effective max payload size and drop statistics;
  * enforce a configured queue/packet limit and drop when full (unreliable
    semantics) rather than blocking the whole connection.
* Optional fallback: DATAGRAM Capsule (`0x00`) for a single-stream capsule
  variant. Not required for the browser `webtransport-h3` variant.

### 7.6 WebTransport flow control

Implement per-session flow control as defined by the draft:

* Initial limits from `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI`,
  `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI`, `SETTINGS_WT_INITIAL_MAX_DATA`.
* Defaults are zero: a peer may not create streams/send data until the server
  sends `WT_MAX_STREAMS`/`WT_MAX_DATA` capsules (or advertises non-zero
  settings). Decide connector defaults; for browser interoperability, consider
  advertising non-zero initial values.
* Track:
  * current max bidi/uni streams per session,
  * current max session data (stream body data; stream headers, capsules and
    datagram payloads are not counted),
  * data consumed/streams closed,
  * blocked senders.
* Send flow-control capsules as credits are consumed/streams closed:
  * `WT_MAX_STREAMS` (bidi/uni),
  * `WT_MAX_DATA`.
* Receive:
  * enforce peer-advertised limits on new streams and data sent;
  * update maxima only monotonically;
  * malformed/oversized values or protocol violations -> `WT_FLOW_CONTROL_ERROR`.
* Send `WT_STREAMS_BLOCKED`/`WT_DATA_BLOCKED` when the sender is blocked, but do
  not wait for them before sending credit.
* Enforce QUIC transport stream/data limits as well; the effective limit is the
  minimum of QUIC and WebTransport limits.
* Flow control is per session, not per connection. Intermediary translation is
  out of scope for a direct origin server, but the receive rules must be
  correct.

### 7.7 Session lifecycle

* Session ID = CONNECT stream ID; validate divisibility by 4 and
  client-initiated bidi type.
* States: `PENDING` (CONNECT received, app handshaking), `OPEN` (2xx sent),
  `DRAINING`, `CLOSING`, `CLOSED`.
* A session is established once the server sends `2xx`.
* The client MAY optimistically create streams/send datagrams before receiving
  the `2xx`; the server MAY create streams/send datagrams as soon as it receives
  the CONNECT request. Buffer bounded streams/datagrams until acceptance or
  discard them if the session is rejected.
* Client data may arrive before the `2xx`; buffer bounded streams/datagrams and
  process them after acceptance, or discard if the session is rejected.
* CONNECT stream FIN/reset -> terminate the session:
  * reset all session streams with `WT_SESSION_GONE`;
  * stop sending/receiving datagrams;
  * notify the application with an appropriate close reason;
  * release session state.
* `WT_CLOSE_SESSION`: parse app code/reason, send FIN on CONNECT, reset all
  session streams with `WT_SESSION_GONE`, notify app; peer may STOP_SENDING.
* Clean FIN on CONNECT without `WT_CLOSE_SESSION` is equivalent to app code 0
  and empty reason.
* `WT_DRAIN_SESSION`: notify app to drain; session may continue to open streams
  and send datagrams until closed.
* HTTP/3 GOAWAY: initiate drain for all sessions; no new sessions on the
  connection.
* Connection close: close all sessions with an abnormal reason; reset/cleanup
  streams.
* Session limits:
  * maximum sessions per connection (configured),
  * maximum buffered streams/datagrams before session establishment,
  * reject extra sessions with a 2xx-compatible error? Use `503`/`429` with a
    Retry-After/rate-limit policy according to local policy; document.
* Application close error code mapping:
  * 32-bit app code -> `WT_APPLICATION_ERROR` range,
  * reason <= 1024 UTF-8 bytes,
  * invalid/oversized reason -> truncate at UTF-8 boundary or reset with
    `H3_MESSAGE_ERROR` (decide policy; draft requires receiver reset for invalid
    input).

## 8. Container and Servlet integration

### 8.1 WebTransport container

Add a webapp-scoped container analogous to `WsServerContainer`:

* `WebTransportServerContainer` implementation of the hypothetical Jakarta
  container interface.
* Endpoint registry and exact/template path mapping (reuse/extend the WebSocket
  `UriTemplate` logic if appropriate, but keep a separate implementation to
  avoid coupling).
* `WebTransportFilter` registered for `/*` by a `ServletContainerInitializer`
  / `WebTransportContextListener`, similar to `WsFilter`/`WsSci`.
* The filter detects `CONNECT` with `:protocol=webtransport-h3`, maps the path,
  and calls the container handshake.
* The filter must not intercept ordinary CONNECT or other Extended CONNECT
  protocols.
* Security constraints, authentication valves and application filters run
  before the WebTransport filter (same normal Servlet pipeline as WebSocket).
* Endpoint instances are created through `InstanceManager`; support
  `@ServerWebTransportEndpoint`, programmatic configs and POJO endpoints.
* Container session registry supports `getOpenSessions`, close timeouts,
  shutdown.

### 8.2 Handshake bridge to HTTP/3

The container handshake needs access to the HTTP/3 session context:

* `Http3Processor` sets an internal request attribute with a
  `WebTransportHandshakeContext` (connection handle, session ID/stream ID,
  settings snapshot, CONNECT stream handle, negotiated limits).
* `WebTransportFilter`/container reads it, performs the handshake and calls a
  Tomcat-internal `WebTransportProtocol.acceptSession(context, endpointConfig,
  responseHeaders)`.
* The HTTP/3 layer sends the `2xx`, registers the session in the
  `WebTransportConnectionManager`, and starts capsule processing.
* The application-facing `WebTransportSession` is created by the container and
  linked to the internal session object.

This avoids pretending WebTransport is a single-stream `HttpUpgradeHandler` and
keeps the Servlet request/security model intact.

### 8.3 Session callbacks and threading

* The container invokes `onOpen` after the session is accepted/registered.
* Stream and datagram callbacks are dispatched on container threads when events
  arrive from the QUIC poll thread/connection manager.
* The API defines blocking/non-blocking stream modes and readiness callbacks.
  Tomcat should implement non-blocking stream callbacks via container executor
  dispatch and provide blocking stream views for simple applications.
* Ordering: per-stream events are serialized; datagram delivery order is
  whatever the transport provides (unreliable/possibly reordered).
* Backpressure: do not accumulate unbounded data per session/stream/datagram
  queue; enforce configured limits and surface errors/drop counters.
* Session close/drain callbacks are delivered once; endpoint instances released
  through `InstanceManager`.

## 9. Connector configuration

Add HTTP/3 connector attributes (names illustrative):

* `webTransportEnabled` (default false).
* `webTransportDraftVersion` or accepted upgrade tokens/settings codepoints
  (for browser compatibility).
* `webTransportMaxSessions` per connection.
* `webTransportMaxBidirectionalStreams` and
  `webTransportMaxUnidirectionalStreams` per session.
* `webTransportMaxData` per session.
* `webTransportInitialMaxBidirectionalStreams`,
  `webTransportInitialMaxUnidirectionalStreams`,
  `webTransportInitialMaxData` (advertised SETTINGS).
* `webTransportMaxDatagramSize` (advertised/limit; QUIC recommends 65535 for
  max_datagram_frame_size).
* `webTransportBufferStreams` / `webTransportBufferDatagrams` (pre-session
  buffering bounds).
* `webTransportSendQueueLimit` / `webTransportDatagramQueueLimit`.
* `webTransportRequireResetStreamAt` (default true; fail connector if the
  transport cannot provide it).
* `webTransportOriginCheck` or container-level configurator (likely
  container/app-level, analogous to WebSocket).
* `connectProtocols` must include `webtransport-h3` (and optionally legacy
  `webtransport`); `enableConnectProtocol=true` is required.
* `altService="h3"` for browser discovery via Alt-Svc (existing HTTP/3 feature).
* `idleTimeoutMs`: long-lived WebTransport sessions are subject to the QUIC
  connection idle timeout; document keepalive/PING requirements or use a larger
  timeout for WebTransport-heavy connectors.
* `maxConcurrentStreams` interplay: WebTransport streams consume QUIC stream
  credit; configure sufficient limits.

Binding-time capability check: if `webTransportEnabled=true` and the selected
transport lacks QUIC DATAGRAM or `RESET_STREAM_AT`, fail with a clear message
rather than starting a partially broken connector.

## 10. Metrics, JMX and access logging

Add per-connector/connection/session statistics:

* active WebTransport sessions,
* rejected sessions (limits, settings, Origin, API),
* WebTransport streams opened/closed/reset (bidi/uni, local/remote),
* datagrams sent/received/dropped (queue/MTU/closed),
* bytes sent/received per session,
* flow-control blocked events and credit updates,
* capsule parse errors, ALPN failures, draines/close codes.
* `UpgradeInfo`-like per-session stats or a `WebTransportGroupInfo` JMX view.
* Access log for the CONNECT request (the handshake response is an HTTP request
  that should be logged; subsequent streams/datagrams are WebTransport stats,
  not HTTP requests).

## 11. File-by-file addition list

QUIC interfaces and transports:

* `java/org/apache/tomcat/util/net/quic/QuicConnection.java`
  * datagram capability/send, server stream open, reset-at/stop-sending.
* `java/org/apache/tomcat/util/net/quic/QuicStream.java`
  * stream type/initiator/bidirectional accessors.
* `java/org/apache/tomcat/util/net/quic/QuicSocketWrapper.java`
  * any connection-level datagram/stream helpers needed.
* `java/org/apache/tomcat/util/net/quic/QuicConnectionManager.java`
  * datagram receive, client stream classification, server stream creation,
    stream/datagram close notifications.
* `java/org/apache/tomcat/util/net/quic/QuicProtocol.java`
  * WebTransport capability/config methods.
* Transport implementations:
  * `org/apache/tomcat/util/net/quic/openssl/QuicBindings.java`,
    `QuicOpenSSLEndpoint.java`, `QuicOpenSSLSocketWrapper.java`,
    `QuicStreamWrapper.java`, `QuicPoll.java`.
  * `org/apache/tomcat/util/net/quic/quiche/QuicheBindings.java`,
    `QuicheEndpoint.java`, `QuicheConnectionWrapper.java`, `QuicheStreamWrapper.java`.
  * `org/apache/tomcat/util/net/quic/ngtcp2/Ngtcp2Bindings.java`,
    `Ngtcp2Endpoint.java`, corresponding connection/stream wrappers.
* Native/FFM bindings for DATAGRAM send/receive, `max_datagram_frame_size`,
  `reset_stream_at`/`RESET_STREAM_AT`, server bidi/uni stream creation,
  `STOP_SENDING`, and datagram queue/size introspection.

HTTP/3:

* `java/org/apache/coyote/http3/Constants.java`
  * settings/capsule/stream/frame/header constants and draft-version table.
* `java/org/apache/coyote/http3/Http3Error.java`
  * H3_DATAGRAM_ERROR and WebTransport error codes/mapping helpers.
* `java/org/apache/coyote/http3/Http3Settings.java`
  * parse/validate/encode H3_DATAGRAM, WT_ENABLED, WT flow-control settings.
* `java/org/apache/coyote/http3/Http3ConnectionManager.java`
  * WebTransport connection state, session registry, datagram/stream routing,
    pending buffers, GOAWAY drain.
* `java/org/apache/coyote/http3/Http3Processor.java`
  * WebTransport CONNECT handshake, capsule handling, no ordinary body after
    session acceptance.
* New classes:
  * `WebTransportConnectionManager.java`,
  * `WebTransportSession.java`/`WebTransportConnectionState.java`,
  * `WebTransportCapsuleCodec.java`,
  * `HttpDatagramCodec.java`,
  * `WebTransportFlowController.java`,
  * `WebTransportStreamRouter.java`,
  * `WebTransportErrors.java`,
  * `WebTransportSettings.java`.
* `java/org/apache/coyote/http3/AbstractHttp3Protocol.java`
  * connector config/capabilities; WebTransport settings advertisement.

Catalina/container:

* `java/org/apache/catalina/connector/CoyoteAdapter.java`
  * Extended CONNECT routing already needed for RFC 9220; ensure
    `webtransport-h3` passes through.
* New `WebTransportFilter.java`, `WebTransportServerContainer.java`,
  `WebTransportContextListener.java`, `WebTransportServerContainerProvider.java`,
  `WebTransportEndpointConfig.java`, `WebTransportHandshakeRequest/Response`.
* `Request`/`RequestFacade` only if the hypothetical Jakarta API requires
  standard request attributes; otherwise none.
* Container SCI registration (`META-INF/services/jakarta.servlet.ServletContainerInitializer`)
  and webapp listener.
* Security/valve integration tests.
* `webapps/docs/config/http3.xml`, new WebTransport docs, `webapps/docs/changelog.xml`.

API implementation:

* New `org.apache.tomcat.webtransport` package implementing the hypothetical
  `jakarta.webtransport` interfaces (or a Tomcat-specific provisional API until
  Jakarta standardizes one).
* Session/stream/datagram implementations, listener dispatch, endpoint
  lifecycle, configurator invocation, Origin/subprotocol validation, flow
  control integration, close handling.

Tests:

* New `test/org/apache/coyote/http3/WebTransportTestBase.java`,
  `TestHttp3WebTransportProtocol.java`, `TestWebTransportSettings.java`,
  `TestWebTransportCapsules.java`, `TestWebTransportStreams.java`,
  `TestWebTransportDatagrams.java`, `TestWebTransportFlowControl.java`,
  `TestWebTransportLifecycle.java`.
* Transport tests for datagrams/server streams/reset-at, skipped when the
  transport lacks capabilities.
* New `test/org/apache/tomcat/webtransport/` container/API tests,
  endpoint mapping, configurator, Origin, instance manager, callbacks.
* aioquic WebTransport client mode or dedicated Python client tests.
* Chrome/Firefox/Safari WebTransport JS interop tests (manual/CI optional).
* Performance/backpressure/queue-limit tests.
* Security tests: Origin, auth, session/stream/datagram limits, malformed
  capsules, datagram bombs, stream header resets.

## 12. Implementation phases

### Phase 0 - Prerequisites and prototype

* Confirm that the HTTP/3 connector is available in the target Tomcat branch
  and release vehicle; WebTransport depends on it.
* Confirm the Extended CONNECT routing change (currently the blanket CONNECT
  `501` in `CoyoteAdapter`) from the RFC 9220 plan, or add an equivalent
  prerequisite.
* Confirm the hypothetical Jakarta API scope/name, or decide on a provisional
  Tomcat API.
* Pin the target IETF draft version(s) and browser versions; build a version
  compatibility table (upgrade token, `SETTINGS_WT_ENABLED` codepoints, capsule
  formats, flow-control behavior).
* Build a capability matrix for OpenSSL/quiche/ngtcp2: QUIC DATAGRAM,
  `max_datagram_frame_size`, `RESET_STREAM_AT`, server bidi/uni streams.
* Prototype with aioquic/Chrome on a capable transport to validate framing and
  settings.
* Decide whether to support legacy `webtransport` token/draft versions.

Exit criteria: a written compatibility/capability decision and a working
non-Tomcat/aioquic prototype path (or proof that a required transport capability
is unavailable, with a plan to gate it).

### Phase 1 - QUIC transport primitives

* Implement datagram send/receive and queue limits in the transport interfaces.
* Implement `max_datagram_frame_size` advertisement/validation.
* Implement server-initiated bidi/uni streams and generic outgoing stream queues.
* Implement `RESET_STREAM_AT`/`STOP_SENDING` where supported; gate WebTransport
  on transports that lack them.
* Implement client stream classification hooks for WebTransport headers.
* Add capability detection and fail-fast connector configuration.
* Unit/integration tests per transport.

Exit criteria: a capable QUIC transport can send/receive datagrams, open server
streams, classify client streams, and reset-at; connector reports unsupported
transports clearly.

### Phase 2 - HTTP/3 protocol core

* Add settings, error codes, constants and draft-version table.
* Implement WebTransport session manager and connection state.
* Implement Extended CONNECT handshake, 405/403/2xx, `WT-Available-Protocols`.
* Implement Capsule Protocol and flow-control capsules.
* Implement stream routing (client bidi/uni, server bidi/uni) and session
  buffering.
* Implement HTTP Datagram codec/demux and datagram send/receive.
* Implement session close/drain/GOAWAY and stream resets/error mapping.
* Implement per-session flow control.
* Raw protocol tests with aioquic/custom clients.

Exit criteria: protocol-level session, streams, datagrams, flow control, close
and drain work against a test client on a capable transport.

### Phase 3 - Hypothetical Jakarta API/container

* Implement the Tomcat container and endpoint registry for the hypothetical
  Jakarta API.
* Implement `WebTransportFilter`/SCI, mapping, configurator, Origin and
  subprotocol negotiation.
* Implement `WebTransportSession`, stream and datagram API objects, listener
  dispatch, instance manager lifecycle, security integration.
* Implement session limits, buffering bounds, metrics.
* Container/API unit tests.

Exit criteria: a webapp endpoint can accept a WebTransport session through the
normal Servlet mapping/security/filter chain and exchange streams/datagrams via
the Jakarta-like API.

### Phase 4 - Browser/aioquic interop

* Browser tests (Chrome/Firefox/Safari) for `WebTransport` sessions, bidi/uni
  streams, datagrams, close/drain.
* aioquic/custom client tests for edge cases and draft variants. Note that
  aioquic's current WebTransport support may use an older `webtransport` token
  and older settings/capsule forms; verify the installed version and target the
  compatible draft.
* Mixed HTTP/3 and WebTransport traffic on one connection.
* Origin/auth/subprotocol tests.
* Performance and backpressure tests.

Exit criteria: browser WebTransport interop on at least one supported transport;
no regression to HTTP/3/WebSocket.

### Phase 5 - Hardening and optional variants

* Capsule-based single-stream `webtransport`/WebTransport-over-HTTP/2-style
  variant (optional).
* Intermediary translation support (optional; likely out of scope).
* Session pooling (optional).
* Additional flow-control edge cases and performance tuning.
* JMX/metrics, docs, changelog, security review.

## 13. Test plan

### Protocol/unit tests

* Settings:
  * H3_DATAGRAM validation (0/1, invalid -> H3_SETTINGS_ERROR).
  * WT_ENABLED versions/codepoints, unknown/invalid -> reject/error.
  * WT flow-control settings parsing/encoding.
  * Missing mandatory settings/transport parameters -> WT_REQUIREMENTS_NOT_MET
    or no session.
* Extended CONNECT:
  * valid WebTransport CONNECT -> 2xx; invalid scheme/path/authority -> error.
  * unsupported resource -> 405; bad Origin -> 403.
  * missing WT settings -> reject/no session.
  * WT-Available-Protocols/WT-Protocol negotiation and errors (WT_ALPN_ERROR).
* Capsules:
  * WT_CLOSE_SESSION parsing/validation/UTF-8/length; FIN after capsule.
  * WT_DRAIN_SESSION.
  * WT_MAX_STREAMS/BLOCKED, WT_MAX_DATA/BLOCKED.
  * unknown capsules skipped; truncated capsule on FIN malformed.
  * DATAGRAM capsule optional fallback.
* Streams:
  * client bidi `0x41` + session ID routing; invalid session ID -> H3_ID_ERROR.
  * client uni `0x54` + session ID.
  * server bidi/uni creation and headers.
  * unknown session buffering/rejection (`WT_BUFFERED_STREAM_REJECTED`).
  * session close resets streams with `WT_SESSION_GONE`.
  * stream reset/STOP_SENDING/error mapping; RESET_STREAM_AT reliable size.
* Datagrams:
  * HTTP/3 datagram Quarter Stream ID encode/decode.
  * too-short -> H3_DATAGRAM_ERROR; wrong stream -> H3_DATAGRAM_ERROR.
  * unknown session buffering/drop; closed session drop.
  * before settings -> connection error/no send.
  * max size/queue/drop behavior.
* Flow control:
  * initial settings and capsules; stream/data limits; blocked senders; credit
    updates; violations -> WT_FLOW_CONTROL_ERROR.
  * interaction with QUIC stream/data limits.
* Lifecycle:
  * CONNECT FIN/reset; WT_CLOSE_SESSION; WT_DRAIN_SESSION; GOAWAY; connection
    close.
  * callback ordering and cleanup.

### Transport tests

* Datagram send/receive on quiche/ngtcp2 (and OpenSSL if capable).
* `max_datagram_frame_size` negotiation and oversize behavior.
* Server-initiated bidi/uni streams (OpenSSL/quiche/ngtcp2).
* RESET_STREAM_AT/STOP_SENDING behavior; skip on incapable transports.
* Stream classification/pre-read for client bidi streams.
* Queue limits, flow-control integration, concurrent sessions/streams.

### API/container tests

* Endpoint mapping (exact/template), `@ServerWebTransportEndpoint`.
* Configurator: Origin check, subprotocol negotiation, response headers.
* Security constraints/auth/session/cookies available in handshake request.
* Instance manager lifecycle, injection, POJO endpoints.
* Session close/drain callbacks, open sessions registry, shutdown.
* Stream/datagram API read/write/blocking/non-blocking/listeners/backpressure.
* Error callbacks and close reasons.

### Browser/aioquic integration

* Chrome, Firefox, Safari WebTransport JS client:
  * session ready, bidi stream echo, uni stream, datagram echo.
  * close/drain/connection close.
  * Origin/auth/custom headers/subprotocol.
  * multiple sessions and regular HTTP/3 requests multiplexed.
* aioquic WebTransport client for deterministic edge cases and older draft
  variants.
* Alt-Svc discovery if applicable.

### Security tests

* Origin validation; cross-origin rejection.
* Secure context/TLS only (QUIC always TLS).
* Session/path authorization and security constraints.
* Session/stream/datagram limits and buffering bounds; memory/DoS.
* Malformed frames/capsules/settings/stream headers; connection vs stream errors.
* No arbitrary `:authority` tunnel/proxy behavior.
* Resource exhaustion via many streams/datagrams/sessions; rate limits.
* API backpressure behavior.

## 14. Security considerations

* WebTransport is browser-exposed: `Origin` MUST be verified; endpoints must be
  explicitly registered and authorized. Do not allow arbitrary Extended CONNECT
  `:protocol` or path to reach a WebTransport session without mapping/security.
* The CONNECT request passes through the Servlet security pipeline; preserve
  auth/session/cookie semantics.
* Enforce session limits per connection and overall.
* Bound pending streams/datagrams before session establishment; reject with
  `WT_BUFFERED_STREAM_REJECTED`/drop datagrams.
* Bound capsule sizes/types; never allocate a full attacker-declared capsule
  length before data arrives.
* Enforce max datagram sizes; drop oversize rather than fragmenting/blocking.
* Enforce flow-control limits; `WT_FLOW_CONTROL_ERROR` on violations.
* Enforce stream header sizes/valid session IDs; `H3_ID_ERROR` for invalid
  session ID types.
* No generic CONNECT proxy behavior; Tomcat terminates WebTransport at an
  application resource, not an arbitrary host.
* Session close/GOAWAY must reset all associated streams and stop datagrams.
* Protect against many small streams/datagrams/sessions and slowloris-style
  stalls; use timeouts/queue limits.
* TLS 1.3/QUIC transport security is inherited from the HTTP/3 connector.

## 15. Risks and blockers

| Risk/blocker | Impact | Mitigation |
|---|---|---|
| No Jakarta WebTransport API | Cannot deliver standard portable app API | Wait for Jakarta spec; optionally prototype a Tomcat-specific provisional API; design container behind an abstraction layer |
| IETF WebTransport draft not final | Wire format/codepoints/flow control may change | Pin draft version(s); version table; browser compatibility testing; avoid hardcoding final values |
| Browser draft versions differ | Chrome/Firefox/Safari may use different tokens/settings/capsules | Support multiple draft versions or explicitly target tested browser versions; negotiate WT_ENABLED codepoints/tokens |
| OpenSSL QUIC API lacks QUIC DATAGRAM/RESET_STREAM_AT | Browser WebTransport impossible on OpenSSL transport | Gate WebTransport on capable transports; target quiche/ngtcp2 first; wait for OpenSSL API support |
| quiche/ngtcp2 RESET_STREAM_AT support uncertain | Cannot conform to required reliable stream header reset | Capability matrix; upgrade libraries; gate WebTransport; interop tests |
| QUIC DATAGRAM loss/size/MTU | App-visible drops/limits | API drop semantics, stats, effective max size, queue limits |
| WebTransport flow control complexity | Deadlocks/stalls/memory growth | Dedicated flow-controller, tests, conservative defaults, bounded queues |
| Connection-level session management | Harder than request-scoped WebSocket upgrade | Dedicated WebTransportConnectionManager; clear state machine |
| Server-initiated streams | Requires generic stream API and lifecycle ordering | Implement in QUIC interface/transports; tests |
| Buffering before session establishment | DoS/memory risk | Bounded buffers; reject/drop; limits |
| Browser H3 Datagram requirement | Browser clients may refuse sessions without H3_DATAGRAM | Ensure settings/TP negotiation; capability check |
| Session pooling/rate limits | Browser may limit/pool sessions | Document; support per-connection session limits; optional pooling |
| QUIC idle timeout | Long-lived sessions can be closed on idle | Document keepalive/PING or larger `idleTimeoutMs`; test browser behavior |
| Servlet/container integration | CONNECT mapping/security and connection binding | Normal Servlet mapping/filter; internal handshake bridge; tests |
| Performance | Extra streams/datagrams/flow control overhead | Benchmarks; non-blocking paths; queue tuning |

## 16. Open questions

1. Which Jakarta EE release/API shape should be targeted? Is there a Jakarta
   WebTransport specification effort, or should Tomcat publish a provisional
   proprietary API first?
2. Which IETF draft version(s) and browser versions are the compatibility
   targets? Does Tomcat need to support the legacy `webtransport` token and
   older `SETTINGS_WT_ENABLED` codepoints?
3. Will OpenSSL expose QUIC DATAGRAM and `RESET_STREAM_AT`? If not, is
   WebTransport initially limited to quiche/ngtcp2?
4. Does the chosen quiche/ngtcp2 version support `RESET_STREAM_AT`? If not,
   browser interop may be impossible until the library is upgraded.
5. Should Tomcat support the capsule-based single-stream `webtransport` variant
   in addition to `webtransport-h3`? It is useful for non-browser clients and
   intermediaries but not the browser path.
6. What is the API threading model: blocking streams, non-blocking listeners,
   or both? How should backpressure and datagram drops be exposed?
7. Should the Jakarta API expose connection statistics and TLS keying-material
   export (`exportKeyingMaterial`) similar to the W3C WebTransport API?
8. What are sensible default flow-control values (initial max streams/data) and
   session limits for browser interoperability?
9. How should session rejection (limits, Origin, auth) be mapped to HTTP status
   codes and `WT-Protocol`/rate-limit headers?
10. Is intermediary/proxy WebTransport translation in scope? Likely not for a
    Tomcat origin server.
11. Should WebTransport support be enabled by default when the connector and
    transport are capable, or strictly opt-in?

## 17. Definition of done

A browser WebTransport application (`new WebTransport(url)`) can connect to a
Tomcat HTTP/3 connector on a WebTransport-capable QUIC transport and use the
hypothetical Jakarta WebTransport API to:

* establish a session through Extended CONNECT with `:protocol=webtransport-h3`
  and a `2xx` response,
* exchange reliable bidirectional and unidirectional streams (client- and
  server-initiated),
* send and receive unreliable datagrams with documented drop/queue behavior,
* negotiate an application protocol (`WT-Available-Protocols`/`WT-Protocol`),
* pass Origin/auth/security checks through the normal Servlet pipeline,
* apply WebTransport flow control correctly,
* close/drain the session with correct error/reason propagation and stream
  resets,
* coexist with regular HTTP/3 requests and other WebTransport sessions on one
  connection,
while HTTP/3, RFC 9220 WebSocket, and all existing WebSocket/HTTP tests continue
to pass.

## 18. Documentation plan

* `webapps/docs/config/http3.xml`: WebTransport configuration attributes,
  capability requirements and transport matrix.
* New `webapps/docs/webtransport-howto.xml`: application API, endpoint example,
  stream/datagram examples, close/drain, security.
* This design document: keep updated as the protocol draft and Jakarta API
  evolve.
* Changelog entry when implementation starts/lands.
* Security model note: WebTransport is a browser-facing protocol; Origin,
  mapping, authentication and resource limits are mandatory.

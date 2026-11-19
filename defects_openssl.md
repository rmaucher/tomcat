# Review of `org.apache.tomcat.util.net.quic.openssl`

Scope: all Java sources in `java/org/apache/tomcat/util/net/quic/openssl/`
(17 files, ~17.5 kLOC), with cross-checks against callers in
`org.apache.tomcat.util.net.quic`, `org.apache.coyote.http3`, the sibling
quiche/ngtcp2 transports, and the OpenSSL headers/man pages where semantics
matter. The confirmed defects and verified documentation issues found during
this review have been fixed and committed. The sections below record the
remaining non-defect observations (maintainability and security notes) that
were intentionally not changed by the fix series.

## Duplicated code / maintainability observations

* `QuicOpenSSLEndpoint` repeats the "accept UNI then BIDI, then promote
  pending streams" sequence in `bootstrapIncomingStreams()`,
  `handleIncomingStream()` and `acceptPendingStreams()`; the variants
  differ in whether they add pending streams and re-arm interest, which is
  exactly where future behavioural drift is likely.
* Stream teardown logic is spread over `closeStream()`,
  `closeStreamByHandler()`, `deregisterStream()`,
  `deregisterAndReleaseStream()`, `cleanupAcceptedStream()`,
  `rejectAcceptedStream()`, `freeIdleStreams()`,
  `reclaimRetainedConnection()`, and the stream-free loop in `stopInternal()`.
  The claim/free/drain ordering has already diverged once (the connection-free
  ordering race fixed during this review); a single "release stream" primitive
  would remove the risk.
* `QuicPlatformSupport.select()`, `selectAuto()` and the `"linux"` branch of
  `selectExplicit()` contain the same Linux selection block.
* `QuicOpenSSLSocketWrapper` duplicates the blocking read loop between the
  `byte[]` and `ByteBuffer` overloads and duplicates the wait/pump pattern
  between `awaitReadableData()` and `awaitWritable()`.
* `QuicPollItem.hasPollFailure()` is used only in trace formatting in
  `handlePollItemEvents()`, but F is always consumed before that method is
  called, so the trace branch is dead code.

## Security / resource-exhaustion notes

* **UNI-stream read-buffer amplification.** `processAcceptedStream()`
  allocates a full `readBufferSize` (default 16 KiB) per accepted stream,
  including client unidirectional streams. The configured
  `maxConcurrentStreams` check applies only to BIDI request streams; UNI
  streams are bounded only by OpenSSL's fixed `initial_max_streams_uni`
  (OpenSSL default 100). With the default
  `maxConnections` of 8192, a client can force large per-connection and
  endpoint-wide allocations with UNI streams that HTTP/3 then discards as
  unknown (RFC 9114 permits ignoring unknown types). Consider a small/lazy
  buffer for unidentified UNI streams or a concurrent-UNI cap. Severity is
  environment-dependent; no in-tree limit currently prevents it.
* **Protocol deviation on ALPN rejection.** `NO_APPLICATION_PROTOCOL_ERROR`
  (`209`) is documented as being sent in the application error code field
  because OpenSSL exposes no transport-error API. A peer expecting the
  RFC 9001 transport code `0x0178` sees an application code instead. The
  code documents this, but it is an interoperability/security-signalling gap,
  not a hidden bug.
* **Error-path teardown.** `teardownConnection()` marks the teardown started
  before doing its work; if a later step throws, subsequent
  `teardownConnection()` calls are no-ops and the connection can remain
  unreclaimed/untracked (the method catches most steps, but a throw in the
  final maps/free block is not recoverable). Related: `closeAllStreams()` can
  throw after freeing only some streams and `freeIdleStreams()` does not
  deregister poll items, so a failed teardown can leave poll-set entries for
  freed SSLs. These are low-probability (FFM `SSL_free` failures) but should
  be considered in hardening.

## Items checked and found not defective (to avoid false positives)

* All `SSL_POLL_EVENT_*`, `SSL_VALUE_QUIC_*`, `SSL_STREAM_STATE_*`,
  `SSL_ACCEPT_STREAM_*`, `SSL_STREAM_TYPE_*`, `SSL_SHUTDOWN_FLAG_*`,
  `SSL_MODE_*` and control-command constants match OpenSSL's current
  `ssl.h`/`bio.h`.
* `BIO_ADDR_rawport()` is network byte order; `decodePeerPort()` correctly
  byteswaps on little-endian only.
* `SSL_get_event_timeout()` returns a relative timeval; the deadline
  computation in `earlierQuicDeadline()` is correct.
* `SSL_poll()` ignores unknown event bits; the `-1L` masks used for the
  listener/connection want-events are not rejected by OpenSSL.
* `SSL_CTX_callback_ctrl(SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, ...)` returns 1
  on success, so the SNI installation check is correct.
* `SSL_CTRL_CHAIN` with `larg=0, parg=NULL` is the supported
  `SSL_clear_chain_certs()` form and returns 1; the per-certificate chain
  replace logic is correct.
* The OpenSSL error queue is a fixed 16-entry per-thread ring; the review's
  diagnostics finding concerned overwriting root causes, not unbounded memory
  growth, and the relevant paths now clear the queue.

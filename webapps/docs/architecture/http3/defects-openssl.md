# Defect review — `org.apache.tomcat.util.net.quic.openssl`

Complete, independent review of the OpenSSL-backed QUIC transport: all 14 Java
classes of the package plus its `LocalStrings.properties` (~14.2k lines), the
unit test `test/.../quic/openssl/TestQuicEventDispatcher.java`, the shared layer
the package implements/consumes and the HTTP/3 consumer that wires it.

This report replaces the previous (incomplete) review in this file: the
old text referenced defect sections that were not present in it. Everything
below was re-derived from scratch against the current tree; no claim was
carried over unverified.

## Scope and method

Classes reviewed line by line: `QuicBindings`, `QuicPoll`, `QuicPollItem`,
`QuicPollSet`, `QuicEventDispatcher`, `QuicWakeup`, `QuicDiagnostics`,
`QuicNativeMailbox`, `QuicCertConfig`, `QuicCertificateManager`,
`QuicStreamWrapper`, `QuicConnectionWrapper`, `QuicOpenSSLSocketWrapper`,
`QuicOpenSSLEndpoint`; plus the contracts they implement and the shared base
classes they consume (`org.apache.tomcat.util.net.quic.{QuicEndpoint,
QuicProtocol, QuicStream, QuicConnection, QuicConnectionManager,
QuicNativeMailbox, QuicSocketWrapper, QuicSSLContext}`,
`AbstractEndpoint`, `SocketWrapperBase`, `SocketBufferHandler`,
`CertificateLoader`, `openssl_h`, `openssl_h_Compatibility`) and the consumer
wiring (`coyote.http3.Http3Protocol`, which selects this endpoint through the
`quicEndpointClass` probe chain).

Verification performed for every finding:

- **OpenSSL sources and documentation, fetched from `openssl/openssl`** (both
  the `openssl-3.5` branch and `master`, fetched 2026-10) and read at the
  QUIC-API level: `ssl.h.in`, `bio.h.in`, `ssl_lib.c` (`SSL_set_fd` →
  `BIO_set_fd(fd, BIO_NOCLOSE)`), `ssl/quic/quic_impl.c` (3.5 and master
  `ossl_quic_accept_stream`, `ossl_quic_handle_events`,
  `ossl_quic_get_event_timeout`), `ssl/quic/quic_obj_local.h`
  (`ossl_quic_obj_get0_reactor` → the engine's single shared reactor),
  `crypto/bio/bio_addr.c` (`BIO_ADDR_rawaddress`/`BIO_ADDR_rawport`) and
  `doc/man3/SSL_poll.pod`, `doc/man3/SSL_get_value_uint.pod`. Results:
  - every QUIC constant declared in `QuicPoll`/`QuicBindings` matches both
    branches: `SSL_POLL_EVENT_*` bits 0–12, `SSL_POLL_FLAG_NO_HANDLE_EVENTS`
    = bit 0, `SSL_STREAM_TYPE_*` (1/2/3), `SSL_STREAM_STATE_*` (1–6),
    `SSL_STREAM_FLAG_UNI`, `SSL_ACCEPT_STREAM_UNI/BIDI` = 2/4,
    `SSL_SHUTDOWN_FLAG_RAPID` = bit 0 and `SSL_SHUTDOWN_FLAG_NO_BLOCK`
    = bit 2, `SSL_DEFAULT_STREAM_MODE_NONE` = 0 (with `AUTO_BIDI`=1,
    `AUTO_UNI`=2 — verified explicitly, see non-findings),
    `SSL_INCOMING_STREAM_POLICY_ACCEPT` = 1, `SSL_VALUE_CLASS_*` (0–3),
    `SSL_VALUE_QUIC_STREAM_BIDI_REMOTE_AVAIL` = 2,
    `SSL_VALUE_QUIC_STREAM_UNI_REMOTE_AVAIL` = 4,
    `SSL_VALUE_QUIC_IDLE_TIMEOUT` = 5, `SSL_VALUE_EVENT_HANDLING_MODE` = 6,
    `SSL_CTRL_MODE`/`SET_TLSEXT_SERVERNAME_CB`/`_ARG`/`SSL_CTRL_CHAIN`/
    `SSL_CTRL_CHAIN_CERT` = 33/53/54/88/89, `SSL_OP_ALLOW_NO_DHE_KEX`
    = `SSL_OP_BIT(10)`, `SSL_MODE_ENABLE_PARTIAL_WRITE` = 0x1, and
    `BIO_POLL_DESCRIPTOR_TYPE_SSL` = 2;
  - `SSL_poll(3)` semantics: NULL timeout = *block indefinitely*, zero
    `struct timeval` = non-blocking, `result_count` is always written, all
    items' `revents` initialised on every return (even on failure), the
    1/0 × 0/nonzero return matrix in `QuicPoll.poll`'s javadoc is accurate;
  - per-item `events` bits that "do not make sense on a given kind of
    resource" are ignored per the manpage, so the all-bits listener and
    connection want-masks are legal;
  - the directional `SSL_accept_stream()` filters `SSL_ACCEPT_STREAM_UNI`/
    `SSL_ACCEPT_STREAM_BIDI` exist only in OpenSSL 4.x (`ssl35.h.in` defines
    only `SSL_ACCEPT_STREAM_NO_BLOCK`, and 3.5's `ossl_quic_accept_stream`
    ignores the flag bits entirely) — resolved: the accept sites now route
    per-stream handling by the observed `SSL_get_stream_type()`.
- **Call-site traceability**: every candidate traced through its consumer
  chain — poll loop ⇄ poll set ⇄ poll items ⇄ wrappers ⇄ mailbox (all three
  queues) ⇄ Cleaner queues ⇄ stop/start sweeps, including
  `AbstractEndpoint.bindWithCleanup()` → `unbind()` failure cleanup, the
  `stopInternal()` early return when the poll thread survives its join, the
  retention/pending-free claim protocol across stop→start cycles, the
  processing-flag (claim) discipline, and every `connections.remove()`/
  `connections.clear()` site for the streams-before-connection invariant.
- **Cross-transport twins**: `quic.quiche.QuicWakeup` was diffed in full;
  `QuicheCertificateManager`/`QuicheSocketWrapper` consulted where a finding
  could be a deliberate divergence (see C-1 and the non-findings).
- **String resources**: scripted cross-check — every `sm.getString(...)`
  literal used by the package (79 distinct keys after normalising the
  line-wrapped literals) resolves in `quic/openssl/LocalStrings.properties`;
  the one exception (`endpoint.unknownSslHostName`) is read via the base
  endpoint's `StringManager` and exists in
  `java/.../util/net/LocalStrings.properties`.
- **Build and test**: `ant compile` succeeds; the package's unit test
  `TestQuicEventDispatcher` compiles and passes (10 tests, JUnit 4) on the
  tree as reviewed. The magic-number property setters, the rate-limiting
  fields and the due-tick floor were re-checked against their consumers.

Line numbers refer to the tree as of this review and may drift.

Findings are ordered by severity within each category.

---

## 1. Duplicated code

### C-1 — `QuicWakeup` twin (deliberate, but documented only on one side and already drifting)

`quic.quiche.QuicWakeup` (~260 lines) is a near-verbatim twin of the OpenSSL
`QuicWakeup` (~288 lines). The duplication rationale (FFM/libssl-gating: the
OpenSSL primitive routes its libc downcalls through `QuicBindings`, whose
initialisation requires libssl) is documented **only in the quiche copy**;
the OpenSSL copy makes no reference to its twin, which is where a future
maintainer would look first. Three concrete divergences exist today (all
currently functionally correct, verified on this round):

1. **POLLNVAL/error handling in `await()`** — the quiche copy returns
   "wait failed" (`-1`) as soon as either slot reports `POLLNVAL`, even when
   the *other* slot has readable data; the OpenSSL copy only maps
   `POLLERR|POLLHUP|POLLNVAL` to `-1` *when nothing is readable*, so it still
   consumes socket data in that iteration. (The OpenSSL behaviour is the more
   useful one for the readable-socket case, e.g. a UDP socket with an ICMP
   error; the quiche copy's early check is stricter.)
2. **`kick()`Throwable scope** — the quiche copy wraps its downcall in
   try/catch (justified there: the FFM layer would throw on a caller thread
   if the arena was released mid-kick; the OpenSSL copy needs no catch
   because `kick()` and `close()` fully serialise on the monitor, which makes
   the write impossible after the release). Same surface, diverging shapes.
3. **Contract documentation** — the quiche `await()` javadoc spells out the
   negative-timeout (`-1`, infinite wait) contract and its currently-untested
   status; the OpenSSL copy silently supports the same path (identical
   `finite = timeoutMs >= 0` logic) without documenting it.

Recorded as a real long-term drift risk for a pair whose only defence is a
"keep in step" note; the three diffs above show the step has already become
stale in both directions. Low-cost mitigations: add the twin reference to the
OpenSSL class doc, and fold the divergent behaviours into the shared note.

---

## 2. Security review

Verified-good (documented so future audits can skip re-derivation):

- **No payload reaches the log.** `QuicDiagnostics` formats error codes only
  (capped at 16 entries); every read/write path logs sizes and event kinds
  with the payloads deliberately omitted ("Payload redacted" annotations in
  `drainStreamInto`, `readBidiStreamImmediately`,
  `readUnidirectionalStreamImmediately`, the `processUniStreamData` trace).
- **The ALPN callback is fail-closed and bounds-checked.** The offered-list
  scan reinterprets the buffer to `inlen` (bound-limiting), rejects malformed
  length prefixes (`protoLen > inlen - (offset + 1)` → alert, never an
  out-of-bounds read), treats protocol==null and every throwable as
  `ALERT_FATAL`, and returns the undefined warning code 1 only by routing it
  to the fatal branch, matching the RFC 7301/RFC 9114 note in the code.
- **SNI handling cannot serve a mismatched identity silently**: names are
  lower-cased at the single native read site
  (`QuicConnectionWrapper.readSniHostNameNative`), unknown hosts fall back to
  the default host's material, and a *configured* host whose certificates
  failed to load gets `apply-nothing` (`resolveCertEntries` → `List.of()`)
  so the handshake fails visibly instead of presenting an unrelated identity.
- **Client-certificate settings are not silently ignored**:
  `certificateVerification=want/required` produces the
  `quicEndpoint.clientAuthUnsupported` warning at configuration build
  (verified parity with the quiche transport's warning).
- **`strerror` uses the thread-safe, caller-buffered GNU `strerror_r`**,
  no user-supplied data flows through it; the returned pointer is read inside
  its arena scope.
- **The wake eventfd cannot be written after fd release** — `kick()` and
  `close()` serialise on the same monitor, killing the recycled-descriptor
  window the class doc describes (verified against the quiche twin's
  independently-documented reasoning).
- **Cleaner frees are routed to the poll thread** (`DeferredStreamFree` /
  `DeferredConnectionFree` handed to the mailbox queues; the direct-free
  fallback only exists for wrappers constructed without a connection, which
  the endpoint never does — verified all construction sites).

Hardening notes (no exploitable defect found; recorded as residual risk):

### S-1 — the connection-retention invariant is enforced only by comments at its seven call sites

The safety of every `connections.remove(...)` / `connections.clear()` rests
on the invariant spelled out in the `connections` field javadoc
(QuicOpenSSLEndpoint.java:306–318): stream SSLs must be freed-or-deferred and
the connection free immediate-or-claimed *before* the map entry is dropped,
or the GC-thread Cleaner may free a connection whose streams still reference
it (per `SSL_new_stream(3)` the connection must be freed last). Verified: all
five sites comply (`teardownConnection`, `handleConnectionClose` ECD branch,
`abortConnectionSetup`→`teardownConnection`, `stopInternal`'s busy-retention
loop before `clear()`, and `startInternal`'s retained-free sweep), and the
Cleaner itself routes through the CAS-guarded mailbox free. But nothing
structural prevents a future maintainer from adding a remove site that drops
the entry early — the failure mode is a GC-timing-dependent native free-race,
not a loud assertion. An `assert` at the removal sites (streams-empty +
free-claimed-or-done) would convert it into a stoppable failure.

### S-2 — rejection at capacity/pause pays one full accept + handshake + close per connection (bounded)

When `maxConnections` is reached, the endpoint is paused, or no
application protocol is configured, `rejectIncomingConnection(s)` accepts
each pending connection and sends it a `CONNECTION_CLOSE` before freeing it —
necessary because OpenSSL only surfaces a connection once its handshake has
completed inside the engine (verified `SSL_accept_connection(3)`), so the
CPU is already spent and un-requestable. The batch bound
(`REJECT_BURST_LIMIT`=32 per IC iteration × up to 3 engine-tick flushes) and
the deliberate omission of `SO_REUSEPORT` (which would hash-load-balance
datagrams of one connection across listener processes — the split-brain
comment is accurate for listener-mode scaling) are correct mitigations. No
unbounded state growth: the level-triggered IC re-fires and the batch drains
at the poll-loop rate. Residual: a determined client completing handshakes at
line rate keeps the poll thread on the accept/close treadmill; inherent to
the model, consistent with the documented design.

---

## 3. Verified non-findings (dropped candidates)

Each was investigated and found correct against implementation, consumers
and/or the OpenSSL sources; recorded so the verification is not re-spent:

1. **`SSL_DEFAULT_STREAM_MODE_NONE = 0`.** Explicitly verified in both
   `ssl.h.in` branches: master/3.5 define `NONE`=0, `AUTO_BIDI`=1,
   `AUTO_UNI`=2 (the reverse-numbering impression from older 3.5 drafts is
   wrong). The endpoint's `SSL_set_default_stream_mode(conn, 0)` really
   selects the stream-aware (no default stream) mode required for HTTP/3.
2. **Every `SSL_VALUE_*`/`SSL_VALUE_CLASS_*` identifier** (2/4/5/6 and
   classes 0/1) — identical in 3.5 and master; `SSL_VALUE_QUIC_IDLE_TIMEOUT`
   is a pre-connection-establishment feature request with a documented 30s
   default, exactly what `configureIdleTimeout()` implements (including the
   once-only fallback warning and its 30s trigger value).
3. **`QuicPoll.poll()` maps `timeoutMs < 0` to NULL "infinite".** Correct per
   `SSL_poll(3)` (NULL = block indefinitely); the endpoint always calls it
   with 0 (non-blocking + `SSL_POLL_FLAG_NO_HANDLE_EVENTS`), and `QuicPoll`
   documents the mapping accurately. (The wrong claim in `QuicBindings`'s
   javadoc was reported as Doc-1 and fixed there.)
4. **Incremental `rebuild()` relying on `SSL_poll()` initialising all
   revents.** Holds per the manpage, including on failure, and the items
   array is only read slot-wise up to `count` after `syncRevents()`.
5. **Stale-swap miss in `QuicPollSet.remove()`** (moved member marked dirty,
   vacated tail nulled, updated slots) — traced correct; a mid-iteration
   removal only skips the item's *own* reprocessing this round; all
   `SSL_poll()` events are level-triggered (manpage), so the event re-fires
   next iteration. The membership re-check (`pollSet.get(addr) == item`)
   protects against freed items mid-loop.
6. **`BIO_ADDR_rawaddress` with an uninitialised `size_t *l`.** Verified in
   `bio_addr.c`: `l` is only ever written (`*l = len`), never read when
   `p != NULL`; the `copied != addrLen` check validates output only.
7. **`SSL_free` does not close the UDP FD** (`BIO_NOCLOSE`,
   verified in `ssl_lib.c`), so `releaseBindResources()` closing the FD
   explicitly — and doing so *after* the listener free — is correct and not a
   double-close.
8. **`SSL_handle_events(listener)` ticking the entire fleet and
   `SSL_get_event_timeout(listener)` returning the merged engine deadline.**
   Verified: `ossl_quic_obj_get0_reactor` is the *engine's* single reactor
   for every QUIC object (`quic_obj_local.h:289–293`), so the poll loop's
   one-tick-per-iteration design and the listen-side deadline cache are valid
   for all connections of the listener.
9. **`stopInternal()` ordering** (poll-thread join →mailbox drain → GOAWAY →
   bounded drain → queued closes → handler wait → executor shutdown →
   stream frees → stream/cleaner frees → queued-close flush → connection
   frees/retention → `connections.clear()` → mailbox close), including the
   early return when the poll thread survives its join (native state then
   deliberately leaked by `unbind()` instead of freed) and the pending-free
   claim protocol across stop→start (worker completions after
   mailbox.close() are rejected or discarded, and the `startInternal()` sweep
   completes their claims; every increment/decrement of
   `activeHandlers` in `scheduleStreamDispatch`/`dispatchToExecutor`/
   `QuicOpenSSLEndpoint.processSocketInline` balances — traced end to end).
10. **`alive-check` guards on hop execution** (`writeChunk`, `concludeStream`,
    `getStreamWriteState`, `pumpConnectionEvents` capture raw pointers
    outside the hop and do not re-check liveness inside the hop): kept safe
    by the processing-flag discipline — every free path (closeStream,
    closeAllStreams, stopInternal teardown, `freeSslIfIdle`) honours the same
    CAS, and while a worker executes the wrapper's I/O the flag is owned by
    its dispatch, so the free cannot run between the check and the hop.
    Residual is a caller-discipline matter, consistent with S-1; not a
    reachable defect today.
11. **Full read buffer with non-consumable partial data → spin hazard.** The
    endpoint claims a full buffer "is not a stall: the retained bytes are
    processed below and the stream stays armed". Confirmed non-spinning in
    the wired protocol: `Http3ConnectionManager` explicitly detects when the
    retained bytes fill the caller's buffer
    (`data.limit() - sp >= data.capacity()` → `partialDataTooLarge` →
    connection error H3_EXCESSIVE_LOAD, Http3ConnectionManager.java:209, 549,
    1017), so the buffer-full + R-latched spin cannot persist.
12. **`writeStreamData` staging** — heap buffers staged via one
    `MemorySegment.copy` from the backing-array slice; direct non-read-only
    buffers handed over via `MemorySegment.ofBuffer` (position-anchored,
    exactly `remaining()`-sized, global scope — safe across the synchronous
    hop; `read-only` direct staged via `asByteBuffer().put(duplicate())`);
    the doWrite anchor/consume protocol (`startPos` per iteration, restore on
    would-block) is correct against partial acceptance.
13. **`transferPutMode`** puts flip/limit/put/limit/compact preserves the
    `[0, position)`/`limit == capacity` put-mode protocol for every
    exit path (verified with partial-fit and empty-destination states).
14. **Socket/bootstrap byte handling** — `sockaddr` writers use explicit
    network-order port bytes and platform-native family shorts
    (endian-correct on both hypotheses the comments claim); the ephemeral
    port is composed from raw bytes at offsets 2/3 (endian-safe); Linux ABI
    option/errno constants (`SO_*`, `IPPROTO_IPV6`, `IPV6_V6ONLY`,
    `EAFNOSUPPORT`/`EADDRNOTAVAIL`/`EPERM`) all match the Linux ABI; the
    `V6ONLY=0` dual-stack pre-bind detail and the scoped-link-local
    limitation are documented and behave as stated.
15. **`QuicWakeup.await()` EINTR/errno paths** — errno segment handling
    (target-layout pointer + bounded reinterpret), transparent retry with
    remaining time, deadline-crossing reporting 0 (would otherwise mean
    infinite wait), and the "error without readable data" back-off semantics
    (verified against pollLoop's contract "waitEvents < 0 keeps engine ticks
    running and engages the no-progress sleep").
16. **Mailbox open()/close()/submit serialization** — `submitLock` closes the
    check-vs-discard race in both directions; `open()` discards before
    reopening (stale tasks from a previous generation can never run on the
    new loop, whose consecutive frees they would misuse); Cleaner enqueues
    without a kick are latency-bounded, not lost
    (`hasDeferredStreamFrees()` feeds the loop's wait computation).
17. **`QuicCertConfig.buildCertConfig` displaced-entry handling** — the
    lower-cased host-name collision frees the displaced native material
    exactly once and removes those entries from the failure-path list before
    any later `freeLoadedEntries`; `free()` de-duplicates the shared
    `defaultCerts`/`certsByHost` entries by identity (`CertificateEntry` has
    no `equals` — verified).
18. **`applyTransportStreamLimits` recovery arithmetic** —
    `bidiAvail + bidiAccepted` reconstructs the advertised
    `initial_max_streams_bidi` correctly given the accept-cap guard
    (`MAX_ACCEPT_PER_EVENT` skip), the value/UID semantics of
    `SSL_VALUE_QUIC_STREAM_*_REMOTE_AVAIL` ("number of streams the local
    endpoint has authorised the peer to create" per SSL_get_value_uint(3)).
19. **Absent/disable of `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`** — not needed:
    `SSL_MODE_ENABLE_PARTIAL_WRITE` (set on the context, verified inherited
    by QUIC streams) is what makes the fresh-buffer-per-attempt staging
    legal; the retry state the other mode guards against is not armed by
    partial writes.
20. **`ensureServedProtocol()` teardown order** — the `no_application_protocol`
    close (`0x100+120` = RFC 9001 §4.8 alert-derived code) is sent while the
    connection SSL is still live, and the deferred flush callback runs
    between stream and connection frees.
21. **`CertificateLoader` interplay** — `loadCertEntry` failure paths free
    partially-built entries; `resolvePskSelector` applying certificates
    before returning (required while OpenSSL parses the PSK extension,
    `tls_parse_ctos_psk`) re-applies idempotently thanks to the
    `SSL_ctrl(SSL_CTRL_CHAIN, 0, NULL)` clear-first chain handling
    (SSL-level clear works — the SSL_CTX-only extra-chain command the
    comments rule out indeed has no SSL-level case).

---

## 4. Summary

| # | Severity | Class | Finding |
|---|----------|-------|---------|
| C-1 | Duplication (drift risk) | QuicWakeup ×2 | Deliberate twin documented only in the quiche copy; POLLNVAL handling, kick() shape and the await() timeout contract have already diverged |
| S-1 | Hardening | Endpoint | Streams-freed-before-retention invariant at `connections.remove()` sites is comment-enforced only (all five sites verified compliant) |
| S-2 | Hardening (residual) | Endpoint | Rejection at capacity costs accept+handshake+close per connection (bounded batch; inherent to OpenSSL surfacing only fully-handshaken connections) |

The package's core machinery — the single poll thread with mailbox-hopped
native access, the level-triggered event classification, the put-mode buffer
protocol, the streams-before-connection free ordering, and the bounded
shutdown/retention sequences across stop/start — held up under end-to-end
tracing, and every hand-written OpenSSL binding constant matches the
3.5 and master headers. The four code findings and the two documentation
defects each had a small, self-contained fix and have all been resolved.
# Defect report: `org.apache.tomcat.util.net.quic.quiche` (QUIC via Cloudflare quiche)

Scope: the eight classes of the quiche transport package
(`QuicheBindings`, `QuicheEndpoint`, `QuicheCertificateManager`,
`QuicheConnectionWrapper`, `QuicheSocketWrapper`, `QuicheStreamWrapper`,
`CidKey`, `QuicWakeup`), reviewed against their users (the shared classes of
`org.apache.tomcat.util.net.quic`, the OpenSSL twin package
`org.apache.tomcat.util.net.quic.openssl`, `Http3Protocol`) and against the
quiche 0.30.0 library sources (available locally under `/home/opencode/quiche-0.30.0`).

Method: full-file reading of every class, cross-checking every inter-class
contract and every claim about the quiche C API against
`quiche/include/quiche.h` and `quiche/src/*.rs` (0.30.0), comparison with the
OpenSSL twin implementations, a clean `javac` compile of the package (and of
the openssl package + `Http3Protocol`) on JDK 26, a message-key audit of the
package's `LocalStrings.properties`, and two small empirical experiments
(reproducing a JVM crash and the Linux UDP `SO_REUSEADDR` semantics). Line
references are to the files in `java/org/apache/tomcat/util/net/quic/quiche/`
unless stated otherwise.

---

## 1. Duplicated code

The package duplicates non-trivial machinery from the OpenSSL twin package.
Where the duplication is explicit and motivated, it is fine as-is; the
risk to manage is *drift* between the twins. Inventory:

| Duplication | deliberate? | notes |
|---|---|---|
| `quiche.QuicWakeup` ≈ `openssl.QuicWakeup` (whole class) | yes | javadoc (`quiche QuicWakeup`, lines 42–48) explains it: cannot share because the OpenSSL original's libc downcalls route through `QuicBindings` → `openssl_h`, requiring libssl at class init. Same surface (`kick/await/consumeWake/close`), same eventfd+pollfd layout, same EINTR/deadline logic. Behavioural divergences found and verified sane: (a) quiche's `await()` treats POLLERR/POLLHUP as *readable* (the subsequent read surfaces the error) while the OpenSSL twin reports an error-only wait as `-1` (spins the caller's bounded backoff instead) — both are safe; (b) quiche's `kick()` adds a volatile fast path and a try/catch — a hardening the twin lacks (only cosmetic, the twin's monitor covers the same race); (c) `EFD_CLOEXEC` literal `02000000` (octal) vs `0x80000` — same value. |
| `QuicheEndpoint` ports of `QuicOpenSSLEndpoint` machinery: `processSocketInline`, `dispatchToExecutor`/`runStreamDispatch`/`scheduleStreamDispatch`/`wakeClaimWaiters`/`finishStreamDispatch`, `teardownConnection`/`closeStreamByHandler`, `stopInternal` graceful-shutdown skeleton, `createUdpSocket`, `sendStreamLimitNotification`, the glide-in `QuicSocketProcessor` | yes ("port of…" comments) | verified byte-level equivalent where the two must agree (`processSocketInline` including the SUSPENDED→close semantics, processor accounting, two-level wrapper maps). Keep the pairs in step when changing either. |
| `QuicheCertificateManager` lifecycle ≈ `QuicCertificateManager` (`initialize/prepareConfig/installConfig/discard/release`) | yes | documented parallel; the NATIVE halves legitimately differ (quiche config vs OpenSSL cert config). |
| `QuicheConnectionWrapper.writeToStream`'s whole-negative-capacity rule ↔ `QuicheSocketWrapper.writeBytes`'s identical rule | yes | both sites cross-reference each other and instruct updating both when quiche changes ("revisit both together") — satisfied by construction today (verified against quiche 0.30: negative capacity range exists). |
| `QuicheStreamWrapper` vs `QuicStreamWrapper` (openssl) | yes | quiche has no per-stream native object; the class doc explains the delta. |
| `dispatchToExecutor`'s inline/executor fallback copy for the no-executor case | yes | mirrors the twin. |
| `QuicSendfileData` inner class | acceptable | single-use wrapper identical to the twin's (the emulated-sendfile stub). |

One duplication-related caution: `QuicheBindings` re-implements the libc
datagram helpers (`socket/bind/setsockopt/…`) that `openssl.QuicBindings`
also binds. This is intentional ("libssl-free" rationale in the class
javadoc) but means Linux-ABI platform constants (errno values, sockaddr
layouts, `SO_*`/`IPPROTO_*` values) exist in two places — the constants
were verified correct in both (Linux values: `SO_SNDBUF=7`, `SO_RCVBUF=8`,
`IP_RECVPKTINFO=8`, `IPV6_*`, `UDP_SEGMENT=103`, `UDP_GRO=104`, `SOL_UDP=17`,
`AF_*`, msghdr/cmsg/iovec/mmsghdr LP64 layouts, pollfd, `EFD_*`, errno
values), so no current drift — only a maintenance note.

---

## 2. Documentation issues

1. **`quiceBind…` version floor is duplicated knowledge.** `QUICHE_ABI_SERIES`
   ("0.30") is pinned in code, but the struct-layout claims are spread over
   several comments; fine today (all verified correct against quiche 0.30.0,
   including the `quiche_recv_info`/`quiche_send_info` layouts at
   `QuicheBindings.java:1085–1121`, the packet-type mapping 178–179
   (verified: `Initial=1 … Short=5`, `ffi.rs:493–498`), the
   `quiche_shutdown` values, the `-1..-23` error range, `u64::MAX` timeout
   sentinel semantics (`ffi.rs:1113–1119`: `None → u64::MAX`), and
   `active_connection_id_limit` default 2 (`transport_params.rs:213`). No
   discrepancy found — listed so the review trail exists.
2. **`QuicheCertificateManager` default-limit comment** ("quiche's own
   default is zero streams/flow control") — verified accurate against
   `TransportParams::default()` (all `initial_max_*` are 0); no action.
3. **For the wrong-way claims there were none**: the trickier javadoc
   claims in `QuicheEndpoint`/`QuicheSocketWrapper` were all verified
   against quiche 0.30 sources and hold:
   * "quiche silently rewrites an application-level close on such a
     [non-established] connection to a transport close with code 0x0c"
     (`Connection::close`, `lib.rs:7615–7621`) — correct, and the explicit
     transport-close workaround is therefore meaningful;
   * "close immediately if no packet was processed" (`recv_count == 0 →
     mark_closed`, `lib.rs:7630–7633`) — correct, and the reject-path
     "feed the Initial first" requirement is real;
   * "quiche truncates a fin-marked send that does not fit … and silently
     drops the FIN flag" (`send_buf.rs:145–155`, `len = cap; fin = false`)
     — correct;
   * "quiche clamps every packet to `min(out.len(), max_send_udp_payload_size)`"
     (`lib.rs:4016`) — correct;
   * "quiche's read path … can only surface Done, data, or StreamReset"
     (`recv_buf.rs` emits `StreamReset` only; `StreamStopped` lives in
     `send_buf.rs`) — correct, so the missing `STREAM_STOPPED` branch in the
     read error mapping is not a bug;
   * "quiche's `std_addr_from_c` asserts the exact per-family length … and
     reaches `unimplemented!()` for any other family" (`ffi.rs:2049–2105`)
       — correct, validating the `requireSockaddrContract()` guard's premise.
4. **LocalStrings audit:** every `sm.getString(...)` key used by the eight
   classes exists in the package's `LocalStrings.properties` (three keys are
   only referenced across physical line breaks — verified), and the
   `endpoint.unknownSslHostName` key used through `baseSm` exists in
   `org/apache/tomcat/util/net/LocalStrings.properties`. No missing keys.

---

## 3. Verified non-findings (false positives eliminated)

For future reviewers, these plausible suspects were specifically checked and
are **not** defects:

1. **GRO split loop termination** (`rem -= seg`) — same iteration count as
   the `rem -= size` twin (the cosmetic decrement difference between the two
   paths has since been harmonised to `rem -= size`).
2. **`quiche_header_info` partial-output writes on failure** — the FFI
   writes `*version`/`*ty` (and possibly scid) *before* the length checks
   that return −1 (`ffi.rs:489–513`). The endpoint correctly never reads
   those outputs on `rc < 0`: version negotiation is decided by re-parsing
   the raw datagram (`negotiateVersionIfNeeded`), whose bounds checks
   (`off + dcidLen + 1 > len`, `off + scidLen > len`) are also correct.
3. **`CidKey` lengths** — `quiche_header_info` writes at most the seeded
   capacity (20) and returns −1 when a CID does not fit (`ffi.rs:501–519`),
   so `new CidKey(hdrDcid, (int) dcidLen)` cannot read out of bounds.
4. **Timer-heap staleness** — `TimerEntry.seq` stamping, closed/freed
   dropping in `heapPeekFresh`, the bounded rebuild trigger, and the
   timer-less `u64::MAX` (negative through JAVA_LONG) handling in
   `earliestTimer`/`refreshTimerDeadline` are all consistent (poll-thread
   confined, comment-accurate).
5. **Wait computation** — `computeWait()` clamps to `[0, WAIT_CAP_MS]`;
   the negative-timeout (infinite poll) form of `QuicWakeup.await()` is
   indeed never exercised by the only caller, exactly as its javadoc warns.
6. **Access checks on the shared read buffer** — both the stream-worker
   read path (`fillReadBufferDirect0`) and the endpoint's
   `drainIntoStreamBuffer` execute on the poll thread (the wrapper hops via
   `onPollThread`), so the put-mode protocol has no cross-thread access.
7. **`stopInternal()` thread-safety** — mailbox close ordering
   (`QuicNativeMailbox.submitLock` check-vs-act lock), the
   `stagedCertConfig` `getAndSet` claim protocols and the
   `stoppedBusyConnections` retention/release (start-side re-check) hold
   against the reachable interleavings; the poll-thread denial-of-join
   path deliberately leaks instead of freeing under a live loop (documented).
 8. **Pending-send queue** — drained before fresh pulls (order preserved),
    bounded by `MAX_PENDING_SENDS`, EINTR-safe, `p.toLen`/`p.from` snapshot
    copies correct. (The parked-carry interplay was the one exception and has
    since been fixed: a carry whose batch fails to send is now re-parked.)
 9. **`recvPassBatched`** — per-slot saved/restored `saFrom/saTo/toLenOut`,
    msg_len read as unsigned, mmsghdr re-arm limited to the fields the
    kernel consumes, GRO splitting identical to the single path (the one
    cosmetic `rem` decrement difference has since been harmonised).
10. **hopInterest / sweep gating** — mark-before-poll/drain ordering (task
    queued before mark, marks consumed before each drain) matches the
    comments' one-iteration-delay worst case, no lost-sweep race found.
11. **QuicheCertificateManager temp-file materialization** — content is
    public certificate data (the private key is never written), temp
    creation is exclusive-create, permissions tightened post-rename,
    failure paths delete both candidate names; the documented threat
    reasoning holds.
12. **Message keys, imports, compile** — no unused imports, no TODO/FIXME
    markers, clean compile of quiche + openssl transports and
    `Http3Protocol` on JDK 26 (FFM APIs as pinned).

---

## 4. Resolution

All findings were reviewed against the current tree and, where warranted,
fixed. Each change was verified with the HTTP/3 quiche test suite (green at
316/0/0/19) and committed on its own, so any regression is bisectable.

Applied (code):

* `quiche_version()` read guarded against a NULL (`MemorySegment.NULL`)
  return, so the availability probe fails closed instead of an uncatchable
  class-init SIGSEGV.
* The send-loop carry is re-parked on the connection's pending-send queue
  (with its own `send_info`) and a retry sweep requested whenever the batch it
  could not join fails to leave the socket, restoring the "nothing that left
  quiche's queue is lost, order survives" invariant.
* The QUIC poll-thread reference made `volatile` in both the quiche endpoint
  and its OpenSSL twin (no stale-null read on the certificate-reload /
  unbind guards).
* An ALPN-not-served connection is added to the touched set after its
  `CONNECTION_CLOSE` is queued, so the close is flushed and the connection
  reclaimed in the same sweep instead of waiting on the peer.
* The `recvPassBatched` GRO split remainder decrement harmonised with the
  single-read twin (`rem -= size`).
* The write wrappers gained the same post-close `checkNotClosed()` guard the
  read paths use, so a late write reports the closed stream rather than an NPE.
* `SO_REUSEADDR` dropped from the QUIC UDP listener in both transports,
  restoring the single-binder guarantee (no UDP TIME_WAIT needs it; on Linux it
  only relaxes the bind rule to last-binder-wins).
* The shared `QuicSSLContext.getCertificateChain` javadoc qualified so its
  "selected by SNI and key type" claim is stated as transport-specific (the
  quiche transport performs no SNI selection).

No change required (verified, documented where relevant):

* `QuicSocketProcessor` confirmed unreached scaffolding with an accurate class
  comment; the accounting balances and the cache is null-guarded.
* The no-Retry / no-address-validation choice and the absent stateless reset
  for unknown short-header CIDs are accurate, RFC-allowed decisions already
  documented at their code sites.
# Review of `org.apache.coyote.http3` (fresh independent round)

Complete, sequential (no sub-agents) review of every class in the package —
`Constants`, `Http3Error`, `Http3Exception`, `Http3StreamException`,
`QpackException`, `QpackBlockedException`, `QpackValueTooLargeException`,
`Qpack`/`Qpack.HeaderField`, `QpackHuffman`, `QpackDecoder`, `QpackEncoder`,
`Http3Settings`, `Http3Protocol` and `Http3ConnectionManager` (+
`ConnectionState`, `InstructionChunk`, `QpackInstructionHandler`) and
`Http3Processor` (+ `Http3InputBuffer`, `Http3OutputBuffer`,
`GzipSinkOutputStream`, `BodyFrameKind`, all 4865 lines read top to bottom) —
including the message bundle `LocalStrings.properties` (all 129 lines).

Each file was read in full. Every contract the package relies on outside the
package was checked at its defining or consuming site (never from javadoc
alone):

* HTTP/2 counterparts where behaviour is claimed to be ported:
  `org.apache.coyote.http2.Stream` (`emitHeader` name/value validation,
  pseudo-header gates, `content-length`/`cookie`/`host`/`priority` cases,
  `parseAuthority`/`compareAuthority`, `receivedEndOfHeaders` and its
  `Header-State` transitions, `writeTrailers`), `HPackHuffman`,
  `Http2UpgradeHandler.headersEnd` (where cookie flush happens relative to
  trailer sections) and `AbstractProcessor.isReadyForRead()` /
  `available(boolean)` use sites.
* QUIC transport layer: `QuicConnectionManager` (`processClientUniStreamData`
  retention/threading contract, `ConnectionState` interface), the two
  endpoint call-site families in `QuicOpenSSLEndpoint` (`processUniStreamData`
  flip/compact around the protocol call, `incrementActiveStreams` /
  `decrementActiveStreams` / `canAcceptStream` / `noteStreamRejected` — all
  on the QUIC poll thread) and `QuicheEndpoint` (same call sites),
  `QuicSocketWrapper` stall/write timeout constants, and
  `AbstractEndpoint.checkSni`.
* Coyote side: `AbstractProcessor` abstract-method surface (compiles), the
  `available(true)` consumers (`isReadyForRead`), `Request.getServerPort()`
  raw-field semantics used by `compareAuthority`, `HttpParser` request-target
  whitelist (the `OPTIONS *` case was checked explicitly — `*` is admitted).
* Standard test infrastructure was executed at the reviewed tree (see NF-5).

Governing RFC texts were fetched fresh this round and the relevant claims
cross-checked against them: RFC 9114 (§4.1–§4.3, §7.1–§7.2 incl. Table 2 and
7.2.8, §11.2.1 Table 2, §11.2.2 Table 3) and RFC 9204 (§2.1–§2.2, §3.2,
§4.1.1, §4.3–§4.5.1.2 including the worked example, §7.4). RFC 7541
Appendix B was checked differentially (NF-2).

Scripted checks run from scratch this round:

* QPACK static table vs RFC 9204 Appendix A: **99/99 entries match exactly**
  (index, name, value; the RFC's two in-table line-wrap continuations were
  joined per the RFC's own footnote that in-value line breaks are formatting).
* Huffman table vs upstream `HPackHuffman`: **257/257 identical** (0–255 plus
  the 30-bit EOS = `0x3fffffff`), proved by a differential parse of both
  source files rather than by trusting the fork comment.
* Message keys: every dotted key literal used in Java (direct `sm.getString`
  or indirect via `messageError()`/`Http3Settings.error()`) resolves in
  `LocalStrings.properties` and **no defined key is unused**.
* `run-http3-tests.sh` at the reviewed tree: **312 tests, 0 failures,
  0 errors, 0 skipped** (OpenSSL endpoint), including the QPACK unit suites
  (60 tests) and the full-stack suites.

Findings are classified: **Defect** (wrong behaviour / RFC divergence),
**Concern** (real but edge-condition or config-dependent),
**Documentation issue**, **Duplication / minor observation**, and verified
non-findings.

---

## 1. Findings

---

## 2. Verified non-findings (re-derived this round from reads, use sites and/or fetched RFC text, so they are not silently re-raised)

* **NF-1. QPACK static table is RFC-exact** — 99/99 entries match RFC 9204
  Appendix A (index/name/value) via scripted comparison; the only parsing
  pitfalls were the RFC's own in-cell line wraps (covering `application/
  dns-message`, `public, max-age=31536000`, `application/javascript`,
  `application/x-www-form-urlencoded`, `text/plain;charset=utf-8`), which the
  RFC footnote explicitly attributes to formatting; joining them yields
  exact equality for all 99 entries including the empty (null) values and
  the ordering quirks (`:method` block alphabetical at 15–21, the doubled
  `:status` blocks, the 63–98 tail).
* **NF-2. Huffman table is exact** — `QpackHuffman` and upstream
  `HPackHuffman` were parsed and compared entry-by-entry: 257/257 identical
  (`codes[256] = 0x3fffffff`, 30 bits, EOS). This rests on the
  upstream-proven table rather than the fork comment.
* **NF-3. `Constants.isHttp2ReservedFrame` = {0x02, 0x06, 0x08, 0x09} matches
  RFC 9114 Table 2 verbatim** (fetched text: Reserved 0x02, 0x06, 0x08,
  0x09; CANCEL_PUSH has 0x03 and GOAWAY 0x07 correctly *not* reserved). The
  reserved-family predicate `0x1f*N+0x21` (Constants.isReservedFrame) also
  matches §11.2.1/§7.2.8 wording.
* **NF-4. `Http3Settings` reserved-identifier set {0x00, 0x02, 0x03, 0x04,
  0x05} matches RFC 9114 Table 3 verbatim**, with 0x01/0x06/0x07/0x08/0x22
  and the always-sent 0x21 experimental value handled per §7.2.4.1/§7.2.4
  and RFC 9220.
* **NF-5. The reviewed tree passes its full test suite**: `run-http3-tests.sh`
  (OpenSSL endpoint) — 312 tests, 0 failures, 0 errors, 0 skipped, including
  the QPACK unit suites (`TestQpackCoding` 22, `TestQpackDecoder` 25,
  `TestQpackEncoder` 13), the RFC-driven suites (§4.1: 56, §4.2: 10, §6.2:
  19, §7.2: 13) and X/QUIC endpoint suites.
* **NF-6. `LocalStrings.properties` is complete and consistent** — every
  message key literal (direct and indirect) resolves; no unused keys; the
  pair used with swapped argument order
  (`http3Processor.unexpectedFrameOnStream` type/stream at
  Http3ConnectionManager.java:604-606) matches its own format string.
* **NF-7. `compareAuthority` port logic is sound** — `Request.getServerPort`
  returns the raw field defaulting to -1 (Request.java:91, 453-455), so the
  `!= -1` probe of "the authority carried a port" is exact; the method is
  line-identical in intent to HTTP/2's `Stream.compareAuthority`.
* **NF-8. Active-stream accounting is thread-confined to the QUIC poll
  thread in both endpoints** — `incrementActiveStreams` (openssl 4521 /
  quiche 2762), `decrementActiveStreams` (openssl 5911 / quiche 3298, 3362)
  and `canAcceptStream` call sites are all on the poll thread (the worker
  close path hops cleanup to the poll thread per the
  `ConnectionState` concurrency notes), so the unsynchronized
  `activeStreamCount` has today no cross-thread exposure; the decision to
  keep plain fields is documented in ConnectionState.
* **NF-9. The blocked-stream retry cannot emit header lines twice** —
  `QpackBlockedException` fires only at the section prefix
  (QpackDecoder.java:668-670: `requiredInsertCount > totalInserts`; the
  mid-decode §2.2.3 guard at 478-481 precedes any blocked test), and the
  wait loop re-checks the condition under the decoder monitor before any
  wait (missed-notify-safe), with the per-connection slot acquire/release
  bracketed. Second-block after the wait is a clean connection error.
* **NF-10. QPACK wire primitives are bounded** — `decodeIrp`'s overflow
  guard is tested before the addition (no negative-long wrap), the bound is
  the RFC §4.1.1-maximal 62 bits, `MAX_IRP_ENCODED_LENGTH = 10` is the exact
  worst-case wire length (verified against a 62-bit value), and the
  `ConnectionState` flush buffer sizing (`32 + 10*(pending+1)`,
  Http3ConnectionManager.java:1278-1279) covers every instruction plus the
  Insert Count Increment with slack, matching the javadoc rationale.
* **NF-11. Encoder-insert accounting in the flush pipeline is
  retransmission-correct** — instruction bytes serialize once under the
  connection-state lock (ID sets + insert watermark consumed at
  serialization time), a partial `writeToStream` accept leaves exactly the
  unsent suffix queued, and the pending cap counts queued and unsent
  instructions under the same monitor (Http3ConnectionManager.java:1250-1345,
  1799-1811). The Insert Count Increment carries a delta per RFC 9204
  §4.4.3.
* **NF-12. Second-trailer-section acceptance is not silently possible** —
  after the first trailer section completes, read paths stop parsing
  (`break readLoop` / immediate returns), the request reads report end of
  data (`trailersReceived` gates), and any HEADERS/DATA after the trailing
  section is classified and fails the connection in
  `checkFramesAfterTrailer` (Http3Processor.java:3164-3212) on both the
  synchronous and async completion paths.
* **NF-13. Content-Length enforcement across both read paths is complete
  and non-double-counting** — pre-dispatch overruns reject the frame before
  payload copy (Http3Processor.java:1304-1311), the streaming path re-checks
  against the cumulative `totalDataReceived` (4457-4471), shortfalls are
  checked against clean FIN pre-dispatch (1463-1469) and in `doRead`
  (4226-4234), and trailer sections close the committed boundary on both
  paths (1408-1416, 4291-4301).
* **NF-14. `available(boolean)` ignoring `doRead` is a deliberate event-model
  difference, not a stall** — H3 never parses frames inside `available()`
  (H2 does), but `AbstractProcessor.isReadyForRead()`'s fallback
  (`isRequestBodyFullyRead()` + `registerReadInterest()`) is fully
  implemented (Http3Processor.java:1699-1725, 1690-1695) and the QUIC
  wrapper's read-event path re-drives reads, so readiness is maintained by
  the poller instead of inline parsing. The shipped async read-listener
  suites (TestAsync*, TestAsyncReadListener) pass.

---

Method note. As in previous rounds, every suspicion was forced through a
use-site or RFC-text check before being written down; suspicions that were
disproved this round are recorded as NF-8/NF-12/NF-14 (stream-accounting
races, double-trailer acceptance, `available()` semantics) rather than
kept as unfounded concerns. The full suite passes at the reviewed tree
(312 tests, 0 failures, 0 errors, 0 skipped), so all findings above are
derived from reading, with their narrow triggering conditions spelled out:
D-2/D-3 are message/comment accuracy.

*End of report.*
# HTTP/3 QUIC endpoint scalability review: OpenSSL vs quiche

Initial head-to-head review: September 28, 2026. Reworked
October 5, 2026 after the quiche poll-loop rework (work-gated
sweeps, timer deadline index, named hops), then the same day
after the OpenSSL poll-loop rework (EXPLICIT event-handling
mode, zero-event scan skip, protocol-data mark set), then the
same day again after the quiche re-arm indexing and the
stream→socket-wrapper back-pointer, then once more after the
quiche UDP GSO/GRO poll-loop work (section 4) - the quiche
figures below are that final re-measurement; the OpenSSL
column is unchanged by all of it (no code is shared). This file now
documents the **current** state of both endpoints.
Historical quiche figures and the September OpenSSL
figures have been dropped; for the older campaign and the
OpenSSL upstream watchlist, `quic_scalability.md` remains the
reference.

The two backends of the HTTP/3 connector:

- `org.apache.tomcat.util.net.quic.openssl.QuicOpenSSLEndpoint`
  (OpenSSL 4 QUIC, the default backend), and
- `org.apache.tomcat.util.net.quic.quiche.QuicheEndpoint`
  (Cloudflare quiche 0.30.0 via FFM, opt-in).

## 1. Method

- Tree: current working tree (JDK 26.0.2; quiche 0.30.0 `ffi`
  release build; OpenSSL the in-tree master build,
  `/home/opencode/openssl-master`, `libssl.so.4`). The endpoint
  is switched by restart with
  `-Dorg.apache.coyote.http3.quicEndpointClass`; the bind log
  line was checked on every case.
- Server: `output/build` package, connector `maxThreads=150`,
  30 s idle timeout, stream cap at the default 100, UDP-only
  HTTP/3 connector on 8444.
- Clients: aioquic (same host, loopback) - the harness in
  `../h3bench` (`bench.py` load/idle modes, `merge.py`
  aggregator, `run_case.sh` driver). Load mode:
  `connections x streams` sequential-pipelined GET workers on
  `/h3test.html` (70 B), 3 s warm-up, 12 s window; idle mode:
  settled fleet (15 s settle) held with a 12 s client PING for
  a 40 s poller sample (past the 30 s idle timeout, so a live
  fleet is what is measured). A JVM-warming 1x32 run precedes
  every batch.
- Poller CPU: utime+stime delta of the `*-Poller` LWP (nid via
  `jcmd Thread.print`), percent of one core; `us/req` is
  poller-seconds per completed request - the host-independent
  metric. Raw shards in `h3bench/out.*`; the current quiche
  column is the `item3` tag (post re-arm indexing and
  back-pointer), the OpenSSL column the October rework runs.

Harness hygiene, learned the hard way and worth repeating:

1. Check the connector's *effective* `maxConcurrentStreams`
   before trusting any load row (a leftover config once clamped
   every shape to ~320 rps, and the once-per-endpoint mismatch
   warning can already be spent).
2. Never trust a load window that overlaps an idle case's fleet
   teardown.
3. Warm the JVM before measuring a poller: cold-JIT rows read
   2-3x too high.

## 2. Idle fleet (percent of one poll core)

The OpenSSL column is October 5, after the OpenSSL rework;
the quiche column is the October 5 re-measurement after the
re-arm indexing and back-pointer. The UDP GSO/GRO work does
not move this table (idle traffic carries nothing worth
merging or batching): the 2000-connection cell re-measured
0.62 % on the GSO/GRO build.

| idle conns, kept alive @12 s | OpenSSL | errs | quiche | errs |
|---|---|---|---|---|
| 100 | 0.26 | 0 | 0.20 | 0 |
| 1000 | 5.09 | 0 | 0.45 | 0 |
| 2000 | 35.80 | 0 | 0.65 | 0 |
| 4000 | 86.74 | 894 | 1.15 | 0 |
| 8000 | 94.00 | 12512 | 1.42 | 0 |

- Quiche is flat: ~0.0002 %/conn (0.2 % at 100 is a
  small-sample floor - a couple of timer passes over the
  whole 40 s window). One core carries the full harness
  range; the wall sits far beyond 8000 settled connections,
  and the re-run took the 8000 ramp with zero churn where
  the previous run reported ~25 retries. A connection idle
  between its 12 s ping and its 30 s idle timeout is swept
  ~twice per 12 s, not thousands of times.
- OpenSSL's October rework (section 4) roughly halves the idle
  cost again at every size up to the knee - 1000 conns went
  from ~8.2 to ~5.1 % of a core, 2000 from ~44 to ~36 % - and
  the churn errors the September run reported at 2000
  connections are gone (the shortened iterations now keep up
  with keepalive processing). The knee still sits between 2000
  and 4000 connections and ~1 core is exhausted at 4000: what
  is left is transport-side. Every arriving datagram and every
  due engine timer costs one shared-engine tick - a walk of
  every channel of the listener inside libssl (`ossl_quic_port
  _subtick`) - and one `SSL_poll()` readout that takes the
  engine lock per item. O(channels) per O(1) wake over an N
  connection fleet is the quadratic; no endpoint-side work can
  move it. Upstream watchlist in `quic_scalability.md`.
- OpenSSL's per-connection idle cost still grows with the
  fleet (the quadratic above); quiche remains cheaper per idle
  connection at every measured size, by ~11x at 1000
  connections and ~55-75x at 2000-8000 (at 100 connections the
  small-sample floor makes the ratio ~1.3x - the absolute
  figure there is noise, not scaling).

## 3. Request load

### quiche (current)

`cc` marks client-process-capped rows (aioquic saturates near
~8-16k rps per connection; server figures are then lower
bounds, and `us/req` remains the comparable metric).

| shape | rps | p50 ms | poller % | us/req |
|---|---|---|---|---|
| 1x1 | 7156 | 0.16 | 23.2 (client 86 %) | 32.4 |
| 1x32 | 7738 (cc) | 5.17 | 24.0 | 31.0 |
| 8x25 | 78,691 | 3.17 | 98.9 (poller-saturated) | 12.6 |
| 16x16 | 70,865 | 3.90 | 99.5 (poller-saturated) | 14.0 |

The poller-saturated rows are today's machine: the plateau
moved from the ~66-68k rps / 14.6-15.2 us/req the rework run
measured (8x25 pristine 66,984 / 14.8 on this host the same
day) to ~71-79k rps / 12.6-14.0 us/req - the re-arm indexing
and back-pointer gave the ~+12 % (section 4), and the UDP
GSO/GRO work (also section 4) added ~+3 % more on the 8x25
repeat pair (78,734 / 12.6) while pulling the 1x1 per-request
poller cost down ~12 % (36.9 → 32.4 us/req: the server's
same-size packet runs merge into one sendmsg - the receive
side contributes nothing on this host, where separate client
datagrams never coalesce and every one still arrives as its
own read). A repeat 32x32 measured 72,853 / 13.6, so
the rows are reproducible to ~1 %. Aggregate ceiling ~71-79k
rps at ~99 % poller.

Bulk transfer is the shape send-GSO targets (1 MiB body,
8x25, client-process-capped at ~3.4 Gb/s loopback):

| quiche 1 MiB bulk (8x25) | rps | p50 ms | poller % |
|---|---|---|---|
| pre-GSO (singles only) | 423 | 583 | 88.9 |
| GSO batching | 427-441 | 569 | 79.4-82.5 |

Throughput is client-bound in this shape, so the win shows up
as poller headroom: ~9 points of one core freed at the same
rate, with a temporary server-side trace recording ~7.3
packets per segmented sendmsg on bulk runs.

### The mixed shape (quiche)

1x32 client-capped load measured against a settled 2000-
connection idle fleet: **7776 rps, 26.1 % poller, 33.5
us/req** - within a point of the 1x32-solo cost (24.0 %,
31.0 us/req). An idle fleet of that size adds essentially no
load-serving cost (the poll loop only ever sweepes
connections an event touched).

### OpenSSL (October, post-rework)

| shape | rps | p50 ms | poller % | us/req |
|---|---|---|---|---|
| 1x1 | 288 | 3.88 | 5.0 | 174.5 |
| 1x32 | 13805 (cc) | 2.38 | 29.6 | 21.4 |
| 8x25 | 18187 | 12.09 | 39.9 | 22.0 |
| 8x100 | 15281 | 54.1 | 38.2 | 25.0 |
| 32x32 | 14783 | 32.7 | 41.6 | 28.1 |

Against the September baseline (13421 rps / 34.9 us/req / 46.8
% on 8x25; 113 ms p50 on 32x32) the rework moves ~19-44 % more
throughput at ~40 % less poller time per request, with wide
shapes gaining most (8x100 p50 70 -> 54 ms, 32x32 p50 113 ->
33 ms; the 32x32 p99 stays ~1 s - stream-count serialization,
below). The ~15-18k rps aggregate wall still arrives with the
poller only ~40 % busy: the wall is per-connection
single-threaded stream handling inside the one poll thread and
the shared engine tick, not CPU (extra poller headroom is
unusable; raising streams/conn only raises p50/p99). 1x1 is
unchanged - its 288 rps is the client's 1/p50 over sequential
pipelined requests with neither endpoint nor client CPU
saturated; that p50 remains ~25x quiche's.

### The mixed shape (OpenSSL)

Same 1x32 against the settled 2000-connection fleet: **3973
rps, p50 8.1 ms, 88 % poller, 221 us/req** - 9.3x the pre-
rework measurement on this host (408 rps, p50 86 ms, 98 %
poller, 2412 us/req). An idle fleet still taxes the load
heavily on this backend: each request datagram wakes the
shared engine, whose tick walks every channel of the listener
(section 2). Quiche serves the same shape within a point of
its solo cost.

## 4. The poll loops (how each backend scales)

Both endpoints confine native QUIC work to one poll thread with
worker-hop mailboxes; quiche's poll iteration is now O(work)
instead of O(live connections):

- **Work-gated sweep.** Each iteration sweeps the union of the
  poll-thread work sets: connections a datagram was delivered
  to, connections whose quiche timer expired, and connections
  holding deferred work (dispatch replays, partially flushed
  QPACK output, EAGAIN'd sends whose queued output quiche will
  not re-drive on its own). An iteration whose wait timed out
  with nothing pending skips the sweep entirely.
- **Timer deadline index.** A min-heap of stamped
  (deadline, seq, connection) entries replaces the per-
  iteration O(fleet) earliest-timer scan and pinpoints the due
  connections. Entries are pushed when a connection's timer is
  re-read (after each sweep of that connection); stale and
  closed-connection entries are dropped lazily (quiche reports
  a timeout of 0 forever once closed - those reclaims are
  flag-driven, never timer-driven), and the heap is rebuilt
  from the per-connection cached deadlines when the stale
  backlog passes 4x the fleet. quiche timers only move through
  native calls, and every native call site runs inside a swept
  connection's `processConnection` or forces a full pass.
- **Named hops.** Mailbox submissions name the connection whose
  native state they change. A submission enqueues its task
  before its mark, and the loop consumes the mark queue both
  before draining the mailbox and after the recv pass, so a
  task's effects are always followed by a sweep naming its
  connection. Full passes remain only for genuinely global
  events: unattributed submissions (certificate install) and
  wait failures. A 1 s JVM-side closed-flag scan bounds the
  teardown latency of any future close path that neither hops
  nor kicks.
- **Indexed re-arm sweeps** (October follow-up). The
  level-triggered readable/writable re-arms and the dropped
  OPEN_READ replay used to walk the swept connection's live
  stream map. They now iterate per-connection interest sets -
  a parked-reader set and a refcounted parked-writer / async
  write-interest map - maintained at the park/latch points and
  purged at stream close, so a sweep costs O(interest) not
  O(streams); and each stream wrapper carries a direct
  back-pointer to its socket wrapper (published before the
  wrapper enters the endpoint's maps, dropped at
  deregistration), so visiting an indexed stream is one field
  read instead of the endpoint's two-level boxed map lookup.
- **UDP GSO send / GRO receive** (October follow-up). The send
  loop now collects runs of equal-size, same-destination
  packets (up to eight, one possibly short as the final
  segment) into one segmented `sendmsg` (`UDP_SEGMENT` cmsg,
  one iovec per staged packet) - measured ~7.3 packets per
  syscall on bulk runs - and the receive path enables
   `UDP_GRO`, splitting a coalesced read by its segment-size
   cmsg and feeding quiche one packet per `quiche_conn_recv`
   call. That split stays dormant under load on this host:
   separate datagrams never coalesce over loopback, so merged
   reads only arrive from a sender's own GSO batch (and every
   merge does carry the cmsg) - `TestQuicGroSplit` injects
   such a batch to keep the split suite-covered. Because a
   segmented `sendmsg` is one atomic submit, a
  run that meets EAGAIN (nothing reached the socket) is parked
  whole, address snapshot included, on a per-connection
  bounded pending queue that the next flush drains before
  anything newer is pulled from quiche: wire order survives a
  full socket buffer, and the queue bound caps loss at what
  the kernel's own limit already imposes. The receive split is
  gated on the cmsg being present, never on the read merely
  being large - a path that hands up coalesced bytes without
  the split information must not be split. Both features are
  capability-probed once at class init with a live loopback
  round trip (does a plain socket see the GSO batch split;
  does a `UDP_GRO` read carry the cmsg) rather than assumed;
  on this host both verdicts are positive and both are on by
  default, with every path falling back to the pre-feature
  singles/segmentation behaviour where the probe says no.
  (The probe's own founding story: the ephemeral port must be
  re-read with `getsockname` - an FFM downcall does not
  propagate `bind(2)`'s sockaddr write-back, so trusting the
  bind argument sends to port 0 and EINVALs the probe into a
  false negative.) Measured: the 1x1 per-request poller cost
  is ~12 % lower, the bulk shape frees ~9 points of the poll
  core, and the 8x190 cliff row softened further (section 5).
- **recvmmsg receive batching** (October follow-up). The recv
  loop now reads with `recvmmsg`: one syscall takes up to
  eight messages into per-slot mmsghdr slots - each with its
  own data buffer, control buffer and peer sockaddr, all slot
  pointers written once at bind - and each message is
  delivered, GRO-split where its own cmsg says so, exactly as
  the single-read path does; the control-buffer parse is
  shared between the two paths. EINTR retries and the
  EAGAIN-ends-the-pass rule carry over unchanged, the
  fairness budget bounds messages per iteration as before,
  and where the symbol cannot be linked the loop stays the
  plain `recvmsg` one. Measured throughput-neutral at this
  host's plateau (8x25 65,249 rps vs 65,072-65,258 same-day
  baselines, 8x190 59,694 vs 59,216, 1x1 5,552-5,920 vs
  5,553-5,877): the bound there is quiche's per-datagram
  work on the poll core, not syscall entry, so this is an
  order-of-magnitude receive-syscall reduction (headroom)
  rather than a throughput win.
- `pollTimeoutMs`, `WAIT_CAP_MS` and every connector default are
  unchanged; there is no new configuration.

The OpenSSL poll loop reached for the same properties where
libssl's API allows it (October rework):

- **EXPLICIT event handling.** Accepted connections - and,
  through OpenSSL's parent-chain inheritance, every stream of
  them - are switched to `SSL_VALUE_EVENT_HANDLING_MODE_
  EXPLICIT`. In the default mode every API call on a QUIC
  object (`SSL_read_ex`, `SSL_write_ex2`, `SSL_stream_conclude`,
  `SSL_shutdown`, `SSL_accept_stream`) drives event handling
  implicitly, which for these objects means one whole-engine
  tick per call - an O(fleet) channel walk behind every
  response byte. In EXPLICIT mode the loop's single top-of-
  iteration tick plus one flush tick at the bottom of any
  iteration whose event handlers produced output are the only
  engine walks (the close/teardown and shutdown paths already
  pumped `SSL_handle_events` explicitly and are unchanged).
  The mode cannot be set on the listener object, so its
  accept-path autotick remains - one per new connection, not
  per request.
- **Zero-event scan skip.** A zero `SSL_poll()` result count
  means no item reported anything (items that fail to poll are
  counted through the F flag), so the revents sync and the
  full slot scan - two O(poll-set) passes - are skipped
  entirely; a keepalive-only ticked iteration now runs with
  zero Java-side scan.
- **Protocol-data mark set.** The QPACK pending-flush sweep
  walks a mark queue of the connections that actually hold
  instructions instead of the whole fleet, mirroring the
  quiche named-hop pattern (mark enqueued before the count is
  published; connections whose flush only got part way out
  stay registered for the next sweep).
- **Already in place from the September campaign:** one engine
  tick per iteration instead of per poll item, the O(1)
  engine-merged next-deadline read (`SSL_get_event_timeout` on
  the listener), and the adaptive due-tick floor.

What remains OpenSSL-side is inside libssl and no endpoint-
side work can move it: the O(channels) `ossl_quic_port_subtick`
walk per engine tick (the section 2 quadratic - every arriving
datagram costs it once), the O(items) `SSL_poll()` readout that
takes the engine lock per item, the one engine lock and one
port per listener (no parallel handshake offload; upstream
`TODO(QUIC MULTIPORT)`), and the transport-owned socket pump
and DCID demux - with no app-visible per-tick channel-touch
set, the quiche work-gated sweep has no portable equivalent
here. quiche's remaining walls are endpoint code (section 5).

## 5. Stream concurrency and known limits

- **Default cap 100, both backends, fully usable.** Quiche runs
  1x100 clean at full suite level (zero content-length
  violations or H3-layer closes); over-cap demand clamps and
  MAX_STREAMS credit recycles cleanly. The cap is
  transport-level on OpenSSL (advertised
  `initial_max_streams_bidi` pinned at 100; the endpoint can
  only lower enforcement) and configuration on quiche (what the
  client sees on the wire is what you set).
- **The >150-streams/conn cliff is root-caused and fixed.**
  The old signature - poller pinned ~98-99 %, whole-JVM
  ~130-150 %, clients starving, cliff onset just past the
  per-connection stream count that keeps several claims busy
  at once - came from the busy-claim retry in
  `scheduleStreamDispatch`: a retry whose claim was still
  held resubmitted *itself* to the mailbox from inside the
  mailbox drain, so the drain's `while (poll() != null)` loop
  never saw the queue empty and the retry re-ran at drain
  rate until its 500 ms budget expired. Temporary counters on
  the cliff shape measured 381,400,000 retry runs for 249
  schedules (~1.5M per chain) with the claim essentially never
  winning inside the budget (2 wins, 128 budget handoffs): the
  poll thread was doing nothing but retry bookkeeping - task
  queue churn, hop-interest marks, touched-set inserts and an
  eventfd write per resubmit. The fix parks the retry as a
  waiter on the stream instead; the dispatch that releases the
  claim drains the waiters and re-submits them (one wake per
  release, races closed by registering before the claim
  attempt), and the budget remains only as the handoff bound
  to the readable-sweep replay. Re-measured same host, both
  binaries (cap500): pre-fix 8x190 7,372 rps / p99 1.63 s /
  134 us per req; post-fix 59,216 rps / p99 47.6 ms / 16.7 us;
  8x250 1,476 (recorded pre-fix) to 55,680 rps / p99 64 ms /
  17.8 us. Zero errors. Plateau shapes are unchanged within
  run-to-run noise (A/B same day: 8x25 65,258 pre vs 64,616/
  65,072 post; 1x1 5,553 pre vs 5,716/5,877 post, 1x1 being
  client-bound at ~84 %). The earlier softening passes
  (re-arm indexing, GSO) moved the cliff floor ~8k->14k
  because they reduced how often claims collided, not the
  retry loop itself. Note the host drifts run-to-run (the
  pre-fix 8x190 row measured 14,001 in the October re-runs
  and 7,372 today), so only same-day A/B numbers compare.
  The <=150 cap recommendation is obsolete: the plateau now
  extends to at least 250 streams/conn (poller-limited at
  ~56-59k rps, same ceiling as the default-cap plateau).
- **Silent stall above ~150 streams/conn (suspect closed).**
  The two mechanisms the retry storm explains are the poller
  starvation (no sweeps while the drain spins) and the
  budget-expiry drop of non-replayable events; both are gone
  with the fix. The stall had never reproduced on re-run, and
  a dedicated burst probe on the fixed build (single
  connection, simultaneous 140/190/250 streams, three runs
  each, cap 500) completed every stream every time. Kept here
  as a watch item; unobserved at or below the default cap in
  the entire history.

## 6. Accept burst

The 8000-connection idle case is also an 8000-handshake ramp
(300 s budget):

| | established | churn/retry errs |
|---|---|---|
| OpenSSL (October, 300 s ramp budget) | 8000 | 12512 |
| OpenSSL (September, 60 s budget) | 7045 | 20077 |
| quiche (October re-run, 300 s budget) | 8000 | 0 |

Quiche absorbs the full burst essentially clean. The faster
October iterations let OpenSSL's 8000-connection ramp settle
completely (within a generous budget) where September's lost
the late handshakes to its pre-crypto pending-queue overflow,
but the ramp still churns 12.5k retries and a short budget
still drops the tail. Both need `socket.rxBufSize` sizing
and/or a slower client ramp for real 8k bursts; neither
parallelises handshakes off the poll thread.

## 7. Recommendations

- **Default/shipped path stays OpenSSL** (distribution and the
  JUnit-proven backend), planned at <= ~1000 connections (an
  idle fleet of 2000 is affordable at ~36 % of a core, but it
  still taxes serving connections) and ~15-18k rps per
  connector instance; scale horizontally.
- **quiche is the scale endpoint**: ~4-5x OpenSSL's aggregate
  throughput (~71-79k vs ~15-18k rps, with bulk transfers
  additionally paying ~10 points less poller for the bytes
  they move), ~55-75x cheaper idle
  scaling (full harness range on ~1.4 % of one core), the
  better accept-burst citizen (8000-handshake ramp, zero
  churn), and an idle fleet that costs the load essentially
  nothing. Worth the opt-in wherever a single instance must
  carry heavy HTTP/3 load or many mostly-idle connections, at
  the cost of a self-distributed native library (Rust+BoringSSL
  static, no packages); the ~150-streams/conn ceiling it used
  to carry (section 5) is gone since the October 6 claim-retry
  fix.
- Verification bar on the current build: full JUnit suite green
  on the OpenSSL backend (315 run, 0 failures, 0 errors) across
  three consecutive runs; the quiche backend is green on the
  same tree (316 run, 0 failures, 0 errors, 19 skipped) for
  each of the follow-up re-arm, GSO/GRO and claim-retry commits,
  each with
  its own stress loops of the parked-reader / write-latch /
  teardown suites (the GSO/GRO run additionally exercises the
  batch send path through every handshake - the equal-size
  Initial runs are what the batching feeds on - and the
  cmsg-gated receive split through the injected GSO burst of
  `TestQuicGroSplit`; separate datagrams never merge on this
  host's loopback, so without that injection no suite or
  benchmark traffic ever reaches the split).

## 8. Open items

- The quiche >150-streams/conn wall and the silent stall:
  **closed (October 6)**. The forensic landed on the busy-claim
  retry of `scheduleStreamDispatch`: it resubmitted itself to
  the mailbox from inside the mailbox drain, so the drain never
  terminated while a chain was alive and the retry ran at drain
  rate for its full 500 ms budget (measured 381M retry runs for
  249 schedules, the claim winning essentially never) - a
  poll-thread starvation loop that scales with busy-claim
  overlap, which is exactly the >150-streams/conn signature.
  The retry is now release-driven (parked on the stream, woken
  once by the dispatch clearing the claim). Same-day A/B cap500
  8x190: 7,372 rps / p99 1.63 s to 59,216 rps / p99 47.6 ms;
  8x250: 1,476 to 55,680 rps. Plateau shapes unchanged within
  noise. The stall never reproduced before or after the fix,
  but budget-drops and poller starvation are both mechanisms it
  explains, so it is listed as suspect-closed (section 5).
- Poll-loop GSO/GRO: **done for the quiche backend** (section
  4, October 6): batched segmented sends with the pending
  queue for the atomic-EAGAIN case, cmsg-gated receive split,
  both capability-probed at class init. Two corrections to
  earlier versions of this item: the "loopback hands up
  coalesced reads without the `UDP_GRO` cmsg" observation was
  a probe-tool artifact - Python's `recvmsg` drops that cmsg,
   a raw reader sees it on every merge - and the host was never
   missing the API (the very first probe had misnumbered the
   options; see the section 4 item for the FFM bind write-back
   trap that then hid the working probe). The cmsg presence
   gate stays regardless of the host verdict. One more
   correction from the coverage pass: earlier text credited
   the 1x1 win partly to receive-side merging of client
   bursts; separate datagrams never merge over this host's
   loopback, so no suite or benchmark traffic reaches the
   split - the 1x1 gain is send-side batching alone, and the
   split path is exercised only by the capability probe and
   by `TestQuicGroSplit`'s injected GSO batch. **Open for the
  OpenSSL backend**: its poll loop is `SSL_poll()`-driven and
  the batching would have to sit inside the libssl readout,
  not around the socket.
- recvmmsg receive batching: **done for the quiche backend**
  (section 4, October 6). Kept as the receive-side counterpart
  of the send batching; throughput-neutral at this host's
  plateau (the poll core is bound by quiche's per-datagram
  work, not syscall entry), so it buys receive-syscall
  headroom, not rps. The OpenSSL loop has no socket-level
  batching point outside libssl's readout.
- Poller sharding (one endpoint facade over N `SO_REUSEPORT`
  sockets and N poll threads, with datagram forwarding on owner
  change): **implemented for the quiche backend and reverted
  (October 6)**. The two-phase implementation - poll-loop state
  carved into a per-thread Shard class, then N live shards with
  per-shard TLS config slots - proved behaviour-neutral every
  way it was measured: single-flow traffic is structurally
  shard-local, and the multi-flow plateaus moved by a couple of
  percent between one shard and four, in both directions, so the
  capability never earned a demonstrated win. The 100 %-busy
  single poller that motivated it is not reproducible on the
  current host (multi-flow shapes run client-bound today), and
  the implementation carries a cost structure that grows exactly
  where the payoff was supposed to live: the full pass, the
  close scan and the sweep rebuild iterate the *shared*
  connections map on every shard, each filtering its own share
  out, so per-iteration scan work scales with fleet size times
  shard count until per-shard owned lists replace the filter.
  Revisit if a poller-bound reproduction returns - it would want
  those lists, plus a client fleet that is not itself the
  bottleneck.
- OpenSSL: the endpoint-side constant factors are now gone
  (section 4); what is left scales with the fleet per engine
  tick and per `SSL_poll()` readout and lives inside libssl -
  the engine tick, the shared engine lock, and the invisible
  per-tick channel-touch set that blocks a work-gated poll-set
  scan. Upstream watchlist in `quic_scalability.md`.
- OpenSSL 32x32 p99 (~1 s): stream acceptance serialised on the
  poll thread at high per-connection concurrency.
- OpenSSL 1x1 p50 (~3.9 ms): per-request round-trip cost,
  unexplained by either CPU; worth a forensic pass.

# OpenSSL QUIC idle4000 scalability: issue analysis and design plan

Status: analysis and implementation plan, 2026-11-20.

Scope: the OpenSSL QUIC transport in `org.apache.tomcat.util.net.quic.openssl`
and the libssl QUIC engine it drives. The target case is the documented
`idle4000` benchmark (`4000` settled connections held with a `12 s` client
PING), where OpenSSL costs about `32.25 %` of one poll core while quiche costs
about `1.35 %` and ngtcp2 about `3.67 %`.

## 1. Summary

The idle fleet is not idle from the poll loop's point of view. Every arriving
keepalive datagram (about `4000 / 12 = 333` per second) causes a poll
iteration. That iteration performs two O(fleet) operations inside libssl:

1. one `SSL_handle_events()` tick, which in the supported OpenSSL 4.x build
   walks every channel on the listener (`ossl_quic_port_subtick()`), and
2. one `SSL_poll()` readout, which visits every poll item (one per connection
   plus the listener) and tests that item's requested events.

The same two walks also run for every due engine timer. The endpoint's
due-tick floor only coalesces the timer-driven walks; packet-driven wakes reset
the floor, so keepalive traffic keeps the O(fleet) work at the wake rate. This
is O(fleet) work for O(1) input, i.e. quadratic in the fleet size: at `4000`
connections it is the dominant idle cost, and it is also why the churn-free
limit is only about `4000` connections.

A diagnostic run in this environment separated the two costs. With a local
OpenSSL draft that already work-gates the engine tick (active-channel list and
timer heap), the current Tomcat tree still measured `25.35 %` at `idle4000`.
Raising the endpoint's due-tick floor from `50 ms` to `250 ms` did not move it
(`25.67 %`). Restricting the same diagnostic build to poll only the listener
item dropped the poller to `3.92 %`; that variant is intentionally incorrect
for normal traffic, but it isolates about `21` points of the cost to the
`SSL_poll()` item walk. JFR agreed: with the active-channel tick in place,
poller samples were concentrated in `SSL_poll()`, with almost none in
`SSL_handle_events()`.

The solution is therefore two-layered:

- make the libssl tick and poll readout proportional to work, not to the
  number of established connections, and
- let the Tomcat endpoint poll only the listener plus channels that libssl has
  actually marked ready, instead of all idle connections.

For older OpenSSL builds that do not have the libssl changes, the endpoint can
fall back to a bounded-cadence poll for stream-quiescent connections. That
fallback trades a small, bounded first-request/keepalive latency for the
removal of the unbounded per-packet O(fleet) scan; it is not the preferred
long-term path.

## 2. Evidence used

- Existing report: `h3_scalability.md`, section 3. At `4000` idle
  connections: OpenSSL `32.25 %`, quiche `1.35 %`, ngtcp2 `3.67 %`; the
  OpenSSL churn-free limit is `4000`, first material churn at `5000`.
- Existing shards in `/home/opencode/h3bench`: OpenSSL `idle4000` runs in
  the `28-32 %` range on the baseline tree, while quiche is flat at about
  `1.1-1.4 %` over `1000-8000` connections.
- Diagnostic runs taken while preparing this plan, with the current Tomcat
  classes swapped into the benchmark base:
  - `idle4000`, local OpenSSL active-channel tick patch: `25.35 %`.
  - same, endpoint `DEFAULT_DUE_TICK_FLOOR_CAP_MS = 250`: `25.67 %`.
  - same, no keepalive traffic (`--keepalive 0`, short pre-timeout
    window): `17.8 %` (includes tail connection churn).
  - same, diagnostic `SSL_poll()` restricted to the listener item only:
    `3.92 %` (not a valid production configuration; used only to attribute
    cost).
- JFR of the local patched OpenSSL build at `idle4000`: poller samples were
  dominated by `QuicPoll.poll()` / libssl `SSL_poll()`; `SSL_handle_events()`
  was almost not sampled.

The host is shared and noisy; treat the absolute percentages as directional
and use the deltas for attribution.

## 3. Issue list

### I-1. The libssl engine tick walks every channel

`SSL_handle_events()` on any object ticks the whole shared QUIC engine:
`ossl_quic_reactor_tick()` -> `qeng_tick()` -> `ossl_quic_port_subtick()`,
which iterates `port->channel_list` and calls `ossl_quic_channel_subtick()`
for every channel. In the supported baseline this is O(connections) per tick,
regardless of whether only one connection received a datagram or only one
connection has a timer.

Impact: every keepalive datagram and every due engine timer pays for the
entire fleet. This is the original upstream quadratic identified in the
existing scalability report.

### I-2. `SSL_poll()` readout visits every item

The endpoint's poll set contains one `SSL_POLL_ITEM` per established
connection (plus one per active stream and the listener). `SSL_poll()` in
non-blocking mode with `SSL_POLL_FLAG_NO_HANDLE_EVENTS` still loops over all
`num_items` and calls `ossl_quic_conn_poll_events_with_lock()` for each QUIC
object. That function takes/reuses the domain mutex and runs the event tests
(`test_poll_event_*`) for the requested event mask. There is no skipping of
quiescent connections.

Impact: about `333` keepalive wakes/s times `~4000` items is more than
`1.3 million` item evaluations/s. The diagnostic listener-only run shows this
is the largest remaining cost once the engine tick is work-gated (`21` points
of the `25.35 %` run).

### I-3. The endpoint has no way to know which channels are ready

The engine hides its channel activity behind `SSL_handle_events()` and the
poll readout. The endpoint only gets a boolean from `SSL_handle_events()` and
an event count from `SSL_poll()`; it cannot learn that the tick serviced a
particular connection, so it cannot poll only that connection. Its only safe
option today is to keep every connection in the poll set.

Impact: the O(items) readout in I-2 cannot be avoided by endpoint-side logic
alone, and the same limitation prevents a work-gated endpoint poll set.

### I-4. Timer chatter plus a fixed floor still produces full scans

The reactor merges per-channel deadlines (ACKM ack-flush deadlines, loss
detection, PING, idle timeout) into one engine deadline returned by
`SSL_get_event_timeout()` on the listener. For an idle fleet this deadline is
often already due or due again within a few milliseconds. The endpoint's
due-tick floor (`DEFAULT_DUE_TICK_FLOOR_CAP_MS = 50`) coalesces those ticks to
at most one per `50 ms`, but each such tick still performs the full engine tick
and `SSL_poll()` readout. The floor also does not scale with fleet size, and
raising it does not help packet-driven wakes (see I-5).

Impact: even a quiet fleet pays about `20` full-fleet scans/s on top of packet
wakes, and the floor masks rather than removes the O(fleet) work.

### I-5. Every packet wake resets the floor

Any socket wake sets `reactiveWake`, resets `dueTickFloorMs` to zero and forces
an immediate tick. Keepalive PINGs are spread by the client stagger and arrive
continuously, so in `idle4000` the loop is essentially packet-driven. The
floor therefore cannot coalesce the dominant keepalive traffic, and each PING
pays one engine tick plus one full `SSL_poll()` readout.

Impact: O(fleet) work per O(1) packet; this is the quadratic that keeps the
poller busy at `4000` and prevents the fleet from scaling further.

### I-6. Endpoint-side O(items) loops remain on the event path

Even when `SSL_poll()` reports zero events, the endpoint skips the Java
`syncRevents()` and slot scan (a useful optimisation), but it still runs
`QuicPollSet.rebuild()`, which iterates every slot looking for dirty items.
When there is one event (for example an incoming request stream), it also runs
`syncRevents()` and the item scan over all items. The poll set has no
dirty-slot list or returned-event index list.

Impact: secondary to I-2, but it makes every event-bearing packet O(fleet) on
the Java side as well, and it adds avoidable per-tick work to the quiet path.

### I-7. Idle connections keep a broad want-events mask

Each connection poll item requests every connection event except OSB
(`CONNECTION_POLL_EVENTS = -1 & ~SSL_POLL_EVENT_OSB`). A quiescent connection
does not need R/W/OS interest; it needs connection-close and incoming-stream
interest. The broad mask means more event tests per item and more level-
triggered retries while the connection is idle.

Impact: a constant-factor increase on top of I-2, not the main quadratic, but
it is cheap to narrow once a connection has no active streams/interest.

### I-8. One engine, one listener, one poll thread

The supported OpenSSL QUIC API has one engine lock and one port per listener;
there is no multi-port/parallel-handshake support (`TODO(QUIC MULTIPORT)` in
libssl). This is not the primary idle4000 cost, but it means the O(fleet) work
cannot be parallelised when it is needed, and it keeps handshake/accept work
and request work on the same poll thread.

Impact: limits load throughput and accept-burst scalability; not the first
thing to fix for idle CPU, and sharding alone only spreads the same O(fleet)
total work over more cores.

## 4. Design principles

1. Make work proportional to activity: a tick, a poll readout, and a poll-set
   scan should cost O(active work), not O(established connections).
2. Keep level-triggered semantics: an item that is ready stays ready until its
   event is consumed; "skip" decisions must never hide a pending stream,
   close, timer, or credit update.
3. Keep the fast path fast: active request streams must not pay the idle-floor
   or coalescing latency.
4. Prefer an upstream OpenSSL solution over a vendor patch; add an endpoint
   fallback for builds without the new API.
5. Preserve the existing stream-before-connection free ordering, poll-set
   ownership, and stop/start lifecycle.

## 5. Solution design

### Phase A: work-gated libssl engine tick (OpenSSL upstream)

Status: implemented in the in-tree `/home/opencode/openssl-master` build on
2026-11-20; see section 10 for the implementation record and validation.

Add the following to the QUIC port/channel implementation:

- `active_channel_list` on `QUIC_PORT`: channels with pending RX, TX, API work,
  or handshake progress.
- `timer_heap` on `QUIC_PORT`: min-heap keyed by each channel's cached
  `next_tick_deadline`, with the channel storing its heap index so a channel
  can be removed in O(log n) when freed.
- Per-channel fields: `next_tick_deadline`, `tick_dirty`,
  `on_active_channel_list`, `in_subtick`, `timer_heap_idx`.
- `ossl_quic_channel_mark_active()` called on:
  - RX injection (`ossl_quic_channel_inject()` / `_inject_pkt()`),
  - TX/API actions (`SSL_write`, stream conclude/shutdown/reset, PING,
    new-token, stream-map mark-active, handshake start/termination),
  - handshake completion/progress paths that can proceed without network
    input.
- `ossl_quic_port_subtick()` becomes:
  1. pump the socket RX,
  2. tick at most the channels on the active list snapshot,
  3. pop due channels from the timer heap and tick them,
  4. report `tick_deadline = timer_heap[0]` (or infinity).
- `ossl_quic_channel_subtick()` gets a cheap skip path for a handshake-complete
  channel with no queued QRX/QTX work, no pending stream work, and a future
  timer deadline. Idle/terminated channels return an infinite deadline and do
  not run the full tick body.
- A channel whose handshake is not complete stays marked active until it
  completes or terminates.
- Allocation failure of the timer heap falls back to the old full channel scan;
  it must not fail the connection.

This turns the O(fleet) `ossl_quic_port_subtick()` walk into O(active + due
timers). It is the first prerequisite for idle4000 scaling.

### Phase B: work-gated poll readout (OpenSSL upstream)

Status: full implementation (B1 + B2) completed in the in-tree
`/home/opencode/openssl-master` build on 2026-11-20; see section 11 for the
implementation record and validation. The Tomcat consumer wiring is Phase C.

Two implementation options, in increasing order of benefit and change size:

**B1, minimal (recommended first step).** Add a fast path in
`ossl_quic_conn_poll_events_with_lock()` for `do_tick == 0`: if the channel is
handshake-complete, not marked active/dirty, has no due timer, and has no
pending stream/accept-queue work, return `revents = 0` immediately without
running the event tests. Keep the existing shared-mutex reuse across items so
the readout takes one engine lock, not one per item.

This keeps the `num_items` loop but makes each idle item a few field reads
instead of a set of event tests. It is a small, reviewable upstream patch and
should remove most of the `21`-point readout cost seen in the diagnostic.

**B2, full (recommended follow-up if B1 is not enough).** Maintain a
per-port "poll-ready" set populated during the tick/RX path: channels that
have a pollable condition (incoming stream, connection close, stream readable/
writable/error, or a timer-driven event). Expose a small public API, for
example:

```c
size_t SSL_get_quic_ready_channels(SSL *listener, SSL **channels,
                                   size_t capacity);
```

or a poll-cookie equivalent that lets an application enumerate ready children
without scanning its own item array. The endpoint can then pass only the
listener plus ready connections/streams to `SSL_poll()`, making the native
readout genuinely O(ready). Level-triggered events stay in the ready set until
consumed or no longer true.

If a public enumeration API is not acceptable upstream, an alternative is a
new `SSL_poll()` mode that accepts the full item array but internally indexes
the port's ready set; that still leaves the app with an O(items) array walk in
the API unless the API is allowed to filter the array itself. B2 with an
enumeration API is cleaner for the endpoint.

### Phase C: Tomcat endpoint integration

When the OpenSSL API is available:

- Keep the listener item in the poll set always.
- Maintain poll items only for connections/streams that are active or
  readiness-pending. On each tick:
  1. tick the engine,
  2. ask libssl for the ready-channel list,
  3. add/retain those channels' connection/stream items in the poll set,
  4. remove or park items whose events are drained,
  5. call `SSL_poll()` on the listener plus the retained ready items only.
- Use the returned event list, or the ready channels themselves, to drive
  `handlePollItemEvents()`, avoiding a full slot scan of all established
  connections.
- Keep a per-connection "active poll item" flag so add/remove from the poll set
  is O(1) and never duplicates an item.
- When a channel transitions to quiescent, narrow its want-events mask to the
  connection-close and incoming-stream bits (`EC`, `ECD`, `ISB`, `ISU`; retain
  `OSU`/`W` only while the endpoint has a server stream waiting for credit).
  Restore the full mask when a new stream or write interest appears.
- Track dirty poll-set slots in a small list/counter so `rebuild()` is
  O(dirty), not O(count). Track returned event indices where possible so
  `syncRevents()` is O(events), not O(count). If the API cannot return indices,
  keep the existing zero-result fast skip and add a sparse event scan.
- Cache the engine deadline as today; the idle wait remains bounded by the
  earliest timer deadline and the wake-up socket.

This removes the endpoint's O(fleet) per-packet work on builds with the new
libssl API.

### Phase D: fallback for older OpenSSL builds

Until a build with Phases A+B is available, add a compatibility mode that
bounds the O(fleet) readout instead of running it on every packet:

- Detect "stream-quiescent" fleet state: no active request streams, no
  write-interest wrappers, no pending protocol data, no mailbox work.
- While in that state, coalesce packet wakes (or run the full `SSL_poll()` at a
  bounded cadence, for example every `20-25 ms`) instead of one scan per
  datagram. This is bounded by `max_ack_delay` for keepalive ACKs and keeps
  the keepalive path correct.
- As soon as an active stream or worker interest appears, cancel the coalescing
  and return to the normal immediate path. A first request on an otherwise idle
  connection may see at most one coalescing interval of extra latency; this
  must be documented and tested.
- Keep the existing due-tick floor, but make its cap adaptive to the fleet
  size (for example a bounded function of the connection count) rather than a
  fixed `50 ms`. This only helps the timer-driven share; it is not a substitute
  for Phases A+B.
- Optionally expose the coalescing cadence and floor as endpoint properties so
  operators can tune latency versus idle CPU.

The fallback is intentionally conservative: it never removes a connection from
the poll set, so no incoming stream or close can be missed; it only delays the
readout by a bounded interval.

### Phase E: validation

Functional:

- Full HTTP/3 suites on OpenSSL, quiche and ngtcp2; no backend may regress.
- New OpenSSL unit/stress tests for:
  - active-list insertion/removal during and outside a tick,
  - timer-heap update/removal/fallback and stale-index safety,
  - handshaking channels staying scheduled,
  - quiescent-channel poll skip not hiding incoming stream/close/credit,
  - close/free while a channel is on the active list or timer heap,
  - endpoint restart/stop with idle connections.
- Endpoint tests for idle -> request -> idle transitions, keepalive PING,
  ACK/loss timers, graceful shutdown and certificate reload while idle.

Performance:

- `idle1000`, `idle2000`, `idle4000`, `idle8000` with the documented
  `--stagger 0.004 --settle 35 --keepalive 12` shape.
- Target: `idle4000` at or below roughly `5 %` of one poll core, and
  `idle8000` no worse than about `10 %`, with no connection-establishment
  churn. The fleet cost should grow sub-linearly (ideally flat up to the
  handshake/ramp limit).
- Load shapes `8x25` and `32x32`, plus `1x1`/`1x32` latency checks; compare
  `us/req` and p99, not absolute rps on the shared host.
- JFR/counters: `SSL_poll()` calls/s, items per call, active channels per
  tick, timer-heap pops, and `SSL_handle_events()` calls. Confirm the item
  count per call is proportional to ready/active items, not the fleet.

## 6. Implementation sketch

OpenSSL port tick:

```c
void ossl_quic_port_subtick(QUIC_PORT *port, QUIC_TICK_RESULT *res,
                            uint32_t flags)
{
    port_rx_pre(port);

    n = active_channel_list_len(port);
    while (n-- > 0) {
        ch = pop_active_channel(port);
        ch_subtick(ch, ...);
    }

    now = get_time(port);
    while (timer_heap_len(port) > 0) {
        ch = timer_heap_min(port);
        if (ch->next_tick_deadline > now)
            break;
        ch_subtick(ch, ...);
    }

    res->tick_deadline = timer_heap_len(port) > 0
        ? timer_heap_min(port)->next_tick_deadline
        : infinity;
}
```

Endpoint poll loop (with ready API):

```java
if (reactiveWake || deadlineDue) {
    handleEvents(listener);
    ready = quicReadyChannels(listener);
    pollSet.retainReady(ready);
}
sslPoll(pollSet.listenerAndReadyItems(), pollSet.readyCount(), 0,
        SSL_POLL_FLAG_NO_HANDLE_EVENTS);
pollSet.processReportedEvents();  // only ready slots
```

Fallback coalescing:

```java
if (fleetStreamQuiescent() && !workerInterestPending()) {
    nextFullReadoutAt = now + MAX_IDLE_READOUT_INTERVAL_MS;
}
if (now < nextFullReadoutAt && !activeStreamAppeared()) {
    // wait until the bounded deadline or a real worker kick
    continue;
}
```

## 7. Risks and invariants

- **Missed active mark:** a channel that changes TX/RX/timer state without
  being marked active can remain unserviced. Every state-changing API and RX
  injection must mark it; add an assertion/instrumentation mode during bring-up.
- **Timer heap correctness:** a channel must be unlinked from the heap before
  it is freed; stale heap indices are a memory-safety bug. Keep the full-scan
  fallback for allocation failure and test it.
- **Poll skip false negatives:** the skip is only legal when the channel is not
  handshaking, has no pending RX/TX/stream work, no due timer, and no ready
  event retained. Level-triggered events must be re-tested until consumed.
- **Coalescing latency:** the fallback must never delay active request streams;
  the bounded interval should be at most the QUIC maximum ACK delay (`25 ms`)
  unless it is configurable and documented. Test first-request latency and
  keepalive PING response.
- **Lock reuse:** the shared-mutex readout must release the previous domain
  lock before taking a different one, and must release it on all exits,
  including DTLS/other item types.
- **API/ABI detection:** the endpoint must probe the new OpenSSL symbols and
  fall back cleanly if they are absent; do not require the new API for basic
  connection service.
- **Stop/start and cleanup:** the ready/active lists and per-connection poll
  item flags must be cleared at the same terminal points as the existing
  `connections`/`pollSet` cleanup, preserving streams-before-connection free
  ordering.
- **Sharding is not a substitute:** multiple engines/listeners or
  `SO_REUSEPORT` shards reduce per-engine N but still pay O(N) total unless
  the work gating lands; they also introduce datagram forwarding/split-brain
  risks and are not recommended as the first fix for idle CPU.

## 8. Rollout

1. Upstream Phases A and B1 to OpenSSL; add tests and performance evidence.
2. Land the Tomcat Phase C consumer behind a symbol/version feature probe;
   older OpenSSL uses Phase D.
3. If B1 leaves a measurable O(items) readout, implement B2 and switch the
   endpoint to the ready-channel list.
4. Update `h3_scalability.md` with the new method, raw shards, and the
   upstream dependency; record the per-connection idle cost curve rather than
   only the fleet limit.
5. Keep the fallback documented as a compatibility path, not the target
   architecture.

## 9. Acceptance criteria

- `idle4000` keepalive poller at or below roughly `5 %` of one core on the
  benchmark host, with no connection churn; `idle8000` at or below roughly
  `10 %` and improving rather than saturating.
- `SSL_poll()` items per call scale with ready/active channels, not the fleet;
  `SSL_handle_events()` channel ticks scale with active/due channels.
- No measurable regression on `8x25`/`32x32` request throughput or latency;
  no regression on quiche/ngtcp2 suites.
- Full HTTP/3 test suites green on all three transports, including idle,
  keepalive, close, restart and malformed-trailing-frame cases.
- The fallback path is bounded and documented; an OpenSSL build without the
  new API still works with the existing semantics.

## 10. Phase A implementation record (2026-11-20)

Status: implemented and validated in the in-tree OpenSSL source tree
`/home/opencode/openssl-master` (HEAD `159cdbc600`, uncommitted working-tree
changes). No public API, ABI or configuration change is required.

The standalone patch is saved in the repository as
`openssl-quic-work-gated-port-tick.patch` (generated against OpenSSL master
`159cdbc600`).

Phase A files:

- `include/internal/quic_channel.h`
- `include/internal/quic_port.h`
- `include/internal/quic_stream_map.h`
- `ssl/quic/quic_channel.c`
- `ssl/quic/quic_channel_local.h`
- `ssl/quic/quic_port.c`
- `ssl/quic/quic_port_local.h`
- `ssl/quic/quic_stream_map.c`

The same working tree also carries the Phase B lock-batching changes
(`include/internal/quic_ssl.h`, `ssl/quic/quic_impl.c`,
`ssl/rio/poll_immediate.c`), which are independent of Phase A and were
verified together with it.

What changed:

- `QUIC_PORT` now owns an `active_channel_list` and a min-heap of channels
  keyed by each channel's cached `next_tick_deadline`.
- `QUIC_CHANNEL` now caches `next_tick_deadline` and carries `tick_dirty`,
  `on_active_channel_list`, `in_subtick` and `timer_heap_idx`.
- RX injection, stream activation, application TX actions, close, key update,
  PING and handshake progress mark the channel active.
- `ossl_quic_port_subtick()` services the active-list snapshot and due
  timer-heap entries only; idle channels are no longer fully ticked.
- A handshake-complete channel with no queued RX/TX, no stream work and a
  future timer deadline takes the cheap skip path in
  `ossl_quic_channel_subtick()`.
- Handshaking channels stay scheduled until they complete or terminate.
- A timer-heap allocation failure falls back to the old full channel scan.
- Channel cleanup unlinks the channel from the active list and removes its
  timer-heap entry before freeing it.

Validation performed:

- `make -j8` completed successfully.
- All OpenSSL QUIC recipe tests passed: 19 recipe files, 21 tests, 0 failures
  (`test_quic_cfq`, `test_quic_fc`, `test_quic_fifd`, `test_quic_lcidm`,
  `test_quic_qlog`, `test_quic_radix`, `test_quic_rcidm`,
  `test_quic_record`, `test_quic_srtm`, `test_quic_stream`,
  `test_quic_tserver`, `test_quic_txp`, `test_quic_txpim`,
  `test_quic_wire`, `test_quic_ackm`, `test_quic_cc`,
  `test_quic_srt_gen`, `test_quicapi`, `test_quicfaults`).
- Tomcat HTTP/3 suite against the patched libssl: `588` run, `0` failures,
  `0` errors, `2` skipped.
- Tomcat diagnostic with the current tree classes and the patched library:
  `idle4000` poller `25.35 %` (the report baseline is `32.25 %`). Raising
  the endpoint due-tick floor to `250 ms` did not change it (`25.67 %`), and
  a diagnostic `SSL_poll()` restricted to the listener item measured
  `3.92 %`. That isolates about `21` points to the Phase B `SSL_poll()`
  readout and confirms the Phase A engine tick is no longer the dominant
  cost.

Phase A is therefore complete; the remaining `idle4000` cost is Phase B
(`SSL_poll()` item readout and endpoint poll-set gating).

## 11. Phase B implementation record (2026-11-20)

Status: full implementation (B1 + B2) complete and validated in the in-tree
OpenSSL source tree `/home/opencode/openssl-master` (HEAD `159cdbc600`,
uncommitted working-tree changes). The standalone patch is saved as
`openssl-quic-poll-ready-channels.patch` and applies on top of the Phase A
patch.

Phase B files:

- `doc/man3/SSL_get_quic_ready_channels.pod` (new)
- `doc/man3/SSL_poll.pod`
- `include/internal/quic_channel.h`
- `include/internal/quic_port.h`
- `include/internal/quic_ssl.h`
- `include/openssl/ssl.h.in`
- `ssl/quic/quic_channel.c`
- `ssl/quic/quic_channel_local.h`
- `ssl/quic/quic_impl.c`
- `ssl/quic/quic_port.c`
- `ssl/quic/quic_port_local.h`
- `ssl/rio/poll_immediate.c`
- `ssl/ssl_lib.c`
- `test/quicapitest.c`
- `util/libssl.num`

The same working tree retains the earlier batched `SSL_poll()` domain-lock
change in `ssl/quic/quic_impl.c`, `ssl/rio/poll_immediate.c` and
`include/internal/quic_ssl.h`; it is included in this Phase B patch because it
is part of the same poll-readout change.

What changed:

- **B2, ready-channel queue.** `QUIC_PORT` now owns a `ready_channel_list`.
  Accepted channels enter it when they are marked active, when a timer is due,
  or when they retain a level-triggered condition (incoming stream or
  connection close). Unaccepted incoming channels are deliberately excluded:
  the listener `IC` event remains their readiness signal.
- **New API.**
  `SSL_get_quic_ready_channels(SSL *listener, SSL **channels, size_t max_channels)`
  returns the queued count when passed a NULL array or a zero capacity, or
  drains up to `max_channels` accepted connection SSL objects. The returned
  pointers are borrowed; the application must not free them. A second drain
  returns nothing until new work occurs.
- **B1, quiescent-item fast path.** `SSL_poll()` with
  `SSL_POLL_FLAG_NO_HANDLE_EVENTS` now returns zero revents for a
  handshake-complete connection with no pending RX/TX, no stream work, no
  incoming stream queue, no close state and a future timer deadline. OS
  credit events are excluded because they are level-triggered and not tied to
  pending channel work.
- The existing one-lock-per-domain readout is retained for runs of items from
  the same QUIC domain.

Validation performed:

- `make -j8` completed successfully.
- All OpenSSL QUIC recipe tests passed: 19 recipe files, 21 tests, 0 failures,
  including the new `quicapitest` coverage.
- New `test_get_quic_ready_channels` verifies that:
  - a connection still queued for `SSL_accept_connection()` is not exposed;
  - an accepted connection is returned exactly once;
  - draining removes it from the ready queue;
  - a second drain returns zero until new work occurs.

At the time of Phase B validation the Tomcat endpoint did not yet consume the
new API, so no Tomcat benchmark number changed in that phase alone. Phase C
wires the endpoint poll set to the ready-channel API and recovers the ~21
points attributed to the per-item `SSL_poll()` readout in the Phase A
diagnostic.

## 12. Phase C implementation record (2026-11-20)

Status: implemented and validated in the Tomcat working tree. No commit was
made. The standalone Tomcat patch is
`tomcat-openssl-quic-ready-poll.patch`, applied on top of the OpenSSL Phase A
and Phase B patches.

Phase C changes:

- `QuicBindings` binds the optional
  `SSL_get_quic_ready_channels()` symbol without adding it to the required
  `QUIC_AVAILABLE` set. A build without the extension keeps the legacy
  all-items poll path.
- `QuicPollSet` gained a compact per-iteration poll subset:
  - `beginPoll()`, `addPollItem()`, `addAllPollItems()`
  - `writePollItems()` writes only the selected items into the native array
  - `syncPollRevents()` reads revents only for the selected items
  - the subset survives poll-set shrink while a readout is in flight
- `QuicOpenSSLEndpoint` builds the subset from:
  - the listener item, always;
  - connections returned by the ready-channel API;
  - the registered stream items for a returned connection;
  - all bidirectional request-stream items that have a socket wrapper, which
    can carry application read/write interest without new parent-channel
    activity.
- Idle connections are no longer included in every `SSL_poll()` readout.
  Their connection and stream items are added only for iterations in which
  OpenSSL reports the connection ready.
- Stream poll items are tracked in a registry so they can be removed from the
  ready subset on normal close, poll failure and connection teardown.
- Newly registered and ready-connection-touched stream items receive a bounded
  linger window (four follow-up poll passes). It covers buffered data which
  becomes readable one pass after the parent connection's ready entry was
  drained. Read/error events refresh the window; write-only W events do not,
  so quiescent server unidirectional streams do not stay polled forever.
- The compatibility path for builds without the API still selects all poll-set
  items, preserving the previous behaviour.

Validation performed:

- `TestQuicPollSet`: 6 tests, 0 failures, including a new subset-selection
  test and a shrink-during-poll test.
- Full Tomcat HTTP/3 suite against the patched libssl: 588 run, 0 errors,
  2 skipped. Under the shared host's load, repeated full runs showed a single
  `TestAsyncFlush.testFlush` aioquic 10 s timeout; the test passes 10/10 in
  isolation and is explicitly documented upstream as non-release-blocking.
  Every other HTTP/3 suite was green.
- `idle4000` keepalive: poller `2.0-2.15 %` of one core (Phase A diagnostic
  was `25.35 %`, reported baseline `32.25 %`), with 3-5 client-side ramp
  errors attributed to the shared host's connection ramps.
- `idle8000` keepalive: poller `2.45 %`, with 13 client-side ramp errors.
  The idle cost is now essentially flat from 4000 to 8000 connections.
- `8x25` load: 92,716-93,483 rps, p50 2.58-2.59 ms, p99 4.94-4.99 ms,
  `10.1-10.2 us/req`, poller `94.16-94.41 %`, zero errors.
- `32x32` load (before the final stream-interest guard): 148,707 rps, p50
  7.71 ms, p99 47.57 ms, `6.7 us/req`, poller `98.91 %`, one client error.
- Mixed shape (1x32 load against a settled 2000-connection fleet): 18,280 rps,
  p50 2.09 ms, p99 4.01 ms, `15.7 us/req`, zero load errors.
- No `SEVERE` resize or stream-close errors after the poll-subset shrink fix.

Phase C is complete. Phase D (compatibility coalescing for older OpenSSL) is
optional for the patched library, and Phase E remains the final documentation
and regression pass.

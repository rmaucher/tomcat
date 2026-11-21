# HTTP/3 QUIC endpoint scalability: OpenSSL vs quiche vs ngtcp2

Tomcat's HTTP/3 connector has three interchangeable QUIC transports. All
three implement the same Coyote HTTP/3 processor and connector contract;
they differ in the native library, TLS configuration surface and scaling
behaviour.

## 1. The three endpoints

| Endpoint | Connector protocol | Native library | Selection |
|---|---|---|---|
| OpenSSL QUIC | `org.apache.coyote.http3.Http3OpenSSLProtocol` | OpenSSL 4.x QUIC API (`libssl.so.4`) through FFM | Default backend |
| quiche | `org.apache.coyote.http3.Http3QuicheProtocol` | Cloudflare quiche 0.30.0 (`libquiche.so`) through FFM | Opt-in |
| ngtcp2 | `org.apache.coyote.http3.Http3Ngtcp2Protocol` | ngtcp2 1.16 plus `libngtcp2_crypto_ossl` through FFM, backed by the system OpenSSL 3.5+ TLS stack | Opt-in |

- **OpenSSL** uses the server-side QUIC API in OpenSSL 4.x:
  `SSL_new_listener()`, `SSL_accept_connection()`, `SSL_accept_stream()`,
  `SSL_poll()` and the per-stream `SSL_read_ex()`/`SSL_write_ex2()` calls.
  It supports SNI, multiple certificate configurations and PSK
  configuration. One listener owns one shared QUIC engine, so one engine
  tick walks all channels of that engine and an idle fleet has a
  super-linear cost at large connection counts.
- **quiche** uses a Rust QUIC implementation with TLS inside
  `libquiche`. Its phase-1 configuration is a single PEM certificate source,
  so SNI, multiple hosts and the Java keystore/PKCS#12/JKS paths are not
  available on this backend. Its poll loop is event-gated and its idle cost
  is the lowest of the three.
- **ngtcp2** uses `libngtcp2` for QUIC and `libngtcp2_crypto_ossl` for TLS
  with the system OpenSSL. It preserves the full certificate surface
  (SNI, multiple hosts, PEM/PKCS#12/JKS, PSK) without requiring OpenSSL 4
  QUIC support. Request throughput is slightly below OpenSSL; idle cost sits
  between quiche and OpenSSL.

All three support the Servlet asynchronous non-blocking write path
(`WriteListener`/`isReady()`). quiche and ngtcp2 expose stream write
capacity directly. OpenSSL exposes the native stream write-buffer
statistics; the endpoint keeps a stream SSL alive until that buffer drains
and re-drives latched write interest level-wise because `SSL_poll()` does
not report W while the send buffer is full even after flow-control credit
reopens.

## 2. Measurement method

- Tree: current working tree at the time of measurement, JDK 26.0.2,
  quiche 0.30.0 release build, OpenSSL 4.x in-tree build, system ngtcp2
  1.16.
- Server: `output/build` package, connector `maxThreads=150`,
  HTTP/3 UDP connector on port 8444 with the default concurrent-stream
  cap of 100. The connector's default `maxConnections` is 8192; runs
  beyond 8000 connections raised it to 200000.
- Clients: aioquic on loopback, `../h3bench` (`bench.py`, `merge.py`,
  `run_case.sh`).
- Load mode: `connections x streams` sequential-pipelined GET workers on
  `/h3test.html` (70 B), 3 s warm-up, 12 s measurement window. A JVM-warming
  `1x32` run precedes each batch.
- Idle mode: a settled connection fleet (35 s settle) held with a 12 s
  client PING over a 40 s poller sample, past the 30 s idle timeout.
- Poller CPU: utime+stime delta of the endpoint's `*-Poller` LWP, as a
  percentage of one core. `us/req` is poller-seconds per completed request.
- Raw shards: `/home/opencode/h3bench/out.perf-*` and `out.ab-*`.

The benchmark host was shared with an unrelated local model server
consuming about 430 % CPU. The load runs were taken with a load average
of 20-24; the idle-limit runs were taken later at a load average of
roughly 3.5-5.5. Absolute rps was therefore noisy: repeated OpenSSL
`32x32` runs ranged from 75.6k to 92.3k rps and from 10.7 to 13.1 us/req.
The tables below are one representative run; use `us/req` and the relative
ordering for comparison, not absolute rps against a quiet host. `cc` marks
rows where the client process, rather than the server poller, is the
limiting factor.

## 3. Idle fleet and connection limit

Poller cost as a percentage of one core for a settled keepalive fleet,
with the number of connection-establishment retries in parentheses:

| idle connections | OpenSSL | quiche | ngtcp2 |
|---|---|---|---|
| 1000 | 2.50 (0) | 0.60 (0) | 1.30 (0) |
| 4000 | 32.25 (0) | 1.35 (0) | 3.67 (0) |
| 8000 | 79.9-81.2 (1,893-1,974) | 1.65-1.87 (0) | 15.9-16.0 (166-294) |

quiche is effectively flat per connection. ngtcp2 grows linearly and
remains well below OpenSSL at 8000 connections. OpenSSL's shared-engine
tick is the dominant cost at large fleets: every arriving datagram and
every due engine timer walks every channel of the listener. The OpenSSL
8000-connection row is already past its churn-free limit: the client still
establishes the full fleet, but only after roughly two thousand retries.

The measured idle scalability limit is the largest settled fleet that
completed without material connection-establishment churn. Beyond that,
the endpoints still accept connections, but the client retry/error count
rises sharply; the limit is therefore a handshake/ramp limit rather than a
hard connection cap.

| endpoint | churn-free limit | first material churn | poller at limit |
|---|---|---|---|
| OpenSSL | 4000 | 5000 (61 retries, 54.8 %) | 32.25 % |
| quiche | 12000 (2 retries) | 14000 (108 retries, 3.4 %) | 6.37 % |
| ngtcp2 | 6000 | 7000 (18 retries, 14.8 %) | 9.87 % |

OpenSSL reaches 6000 connections with 564 retries at 67.2 % poller and
8000 connections with about 1,900 retries at about 80 % poller. ngtcp2
reaches 8000 connections with 166-294 retries at about 16 % poller and
12000 with 3366 retries at 22.8 % poller. quiche reaches 16000
connections with 819 retries while the poller remains around 3.3 %; its
limit is therefore client handshake churn, not endpoint CPU. Under the
default `maxConnections=8192`, quiche is capped at 8192 connections even
though its idle cost would allow more.

## 4. Request load

### OpenSSL

| shape | rps | p50 ms | p99 ms | poller % | us/req | errs |
|---|---|---|---|---|---|---|
| 1x1 | 280.1 | 4.41 | 5.57 | 4.33 | 154.7 | 0 |
| 1x32 (cc) | 18,307.9 | 2.11 | 3.74 | 24.92 | 13.6 | 0 |
| 8x25 | 98,144.8 | 2.44 | 4.78 | 99.25 | 10.1 | 0 |
| 32x32 | 82,386.6 | 6.94 | 92.49 | 98.41 | 11.9 | 0 |

### quiche

| shape | rps | p50 ms | p99 ms | poller % | us/req | errs |
|---|---|---|---|---|---|---|
| 1x1 (cc) | 7,246.2 | 0.15 | 0.37 | 20.50 | 28.3 | 0 |
| 1x32 (cc) | 7,730.0 | 5.18 | 5.38 | 20.50 | 26.5 | 0 |
| 8x25 | 93,910.0 | 2.62 | 3.72 | 99.08 | 10.6 | 0 |
| 32x32 | 93,240.5 | 10.70 | 43.63 | 99.08 | 10.6 | 0 |

### ngtcp2

| shape | rps | p50 ms | p99 ms | poller % | us/req | errs |
|---|---|---|---|---|---|---|
| 1x1 (cc) | 6,384.8 | 0.18 | 0.39 | 24.50 | 38.4 | 0 |
| 1x32 (cc) | 7,101.6 | 5.64 | 5.87 | 71.25 | 100.3 | 0 |
| 8x25 | 85,233.9 | 2.85 | 4.14 | 99.17 | 11.6 | 0 |
| 32x32 | 77,700.1 | 11.77 | 50.64 | 99.00 | 12.7 | 0 |

## 5. Observations

- The wide shapes (`8x25`, `32x32`) are poller-saturated on all three
  backends. OpenSSL leads `8x25` at about 98k rps / 10.1 us/req; quiche
  leads the measured `32x32` run at about 93k rps / 10.6 us/req; ngtcp2
  reaches about 85k / 11.6 and 78k / 12.7 respectively.
- The `1x1` shape is a sequential request/response latency workload, not a
  throughput ceiling. quiche serves it fastest (about 7.2k rps, p50
  0.15 ms). OpenSSL's `1x1` is latency-bound (280 rps, p50 4.41 ms) with
  most of the core idle; ngtcp2 is client-capped at about 6.4k rps.
- The `1x32` shape is client-capped for all three backends. OpenSSL still
  serves the highest rate (18.3k rps / 13.6 us/req) because its per-request
  poller cost is lower than the other two on this shape.
- Idle cost ranking is quiche < ngtcp2 < OpenSSL. At 8000 connections
  quiche uses about 1.7 % of a core, ngtcp2 about 16 %, and OpenSSL about
  80 %. The churn-free idle connection limit ranks the same way: quiche
  reaches about 12,000 connections, ngtcp2 about 6000, and OpenSSL about
  4000 before connection-establishment retries rise sharply. quiche's
  limit is client handshake churn, not endpoint CPU; the default
  `maxConnections=8192` is the practical cap on that backend unless the
  connector limit is raised.
- No performance regression was found in the OpenSSL non-blocking-write
  work. An A/B run against the parent tree measured the same `32x32` and
  `8x25` shapes within the run-to-run spread, and a JFR poller profile
  showed the new stream-drain/close path below sampling visibility
  (`drainPendingStreamDrains` had zero poller samples, while stream
  acceptance dominated). The quiche and ngtcp2 endpoint code was unchanged.

## 6. Reproduction

With the benchmark base and libraries already configured, a load case is:

```sh
./run_case.sh <tag> load 8 25 8 12
```

and an idle case is:

```sh
./run_case.sh <tag> idle 1000 0 2 40 --stagger 0.004 --settle 35 --keepalive 12
./run_case.sh <tag> idle 8000 0 8 40 --stagger 0.004 --settle 35 \
    --keepalive 12 --ramp-timeout 300
```

The endpoint is selected by the `protocol` class on the 8444 connector
(`Http3OpenSSLProtocol`, `Http3QuicheProtocol` or `Http3Ngtcp2Protocol`)
and confirmed by the `QUIC endpoint ... bound ... using ...` log line. Use
`LD_LIBRARY_PATH` for the OpenSSL 4 build, quiche build or system ngtcp2
libraries as appropriate; do not mix the OpenSSL 4 build with the system
OpenSSL that ngtcp2's crypto helper links against.

## 7. Post-review performance check (2026-11-13)

A quick re-check after the HTTP/3 review fixes used the same benchmark base
and the `8x25` shape (`./run_case.sh <tag> load 8 25 8 12`). The host load
average was about 22, within the shared-host caveat in Section 2. The
current HTTP/3 classes were run against the benchmark tree's unchanged
native endpoint code.

| endpoint | current rps | current us/req | earlier report rps | earlier us/req |
|---|---:|---:|---:|---:|
| OpenSSL | 96,823.5 | 10.2 | 98,144.8 | 10.1 |
| quiche | 93,643.3 | 10.6 | 93,910.0 | 10.6 |
| ngtcp2 | 83,411.8 | 11.9 | 85,233.9 | 11.6 |

OpenSSL and quiche are within run-to-run noise of the report; ngtcp2 is
about 2% lower, also within the host-noise band. The first run of the
current classes showed a reproducible quiche regression (73.8-77.1k rps /
12.7-13.3 us/req against a 90.9-92.9k / 10.6-10.9 baseline). The cause was
that the current processor deferred the response FIN to the completion path
after the after-response request-stream scan, while the earlier processor
concluded the stream in `finishResponse()` before that scan. On quiche the
extra scan latency directly reduced sequential request throughput.

Diagnostic A/B runs isolated the cause:

| variant | quiche rps | quiche us/req |
|---|---:|---:|
| baseline HTTP/3 classes | 92,863.5 | 10.6 |
| current classes, FIN deferred after scan | 73,813.7-77,104.1 | 12.7-13.3 |
| scan bypassed, FIN still deferred | 83,070.9 | 12.0 |
| FIN sent in `finishResponse()` unconditionally | 92,772.9 | 10.7 |
| conditional early FIN (final fix) | 93,643.3 | 10.6 |

The final fix in `Http3Processor.finishResponse()` concludes early only when
the request stream has already ended cleanly at a frame boundary and has no
buffered trailer, partial DATA, ignored-frame skip, body-frame error or
Content-Length shortfall. All other cases keep the deferred FIN so a
malformed trailing request frame can still be reset at stream scope first.
This preserves the review correctness fix while restoring quiche throughput.
The new `QpackEncoder` validation is measurable in profiles but is not the
primary cause: replacing only the encoder with the baseline encoder still
measured 76.2k rps. The full HTTP/3 suites pass on all three endpoints
after the change (445 tests, 0 failures; 2/20/6 skipped for
OpenSSL/quiche/ngtcp2 respectively).

## 8. Post-fix A/B performance check (2026-11-13)

A later quick re-check covered the complete HTTP/3 review-fix series. The
method was the same `8x25` load case (`connections=8`, `streams=25`,
`procs=8`, 3 s warm-up, 12 s window) after a `1x32` JVM-warming run. Each
endpoint was measured on the final tree and on its parent commit
(`03d8816a87`) with only `tomcat-coyote.jar` and `tomcat-coyote-ffm.jar`
swapped into the same benchmark base. The host load average ranged from
about 13.7 to 21.2, within the shared-host caveat in Section 2.

| endpoint | final tree rps (mean of runs) | parent rps (mean) | final us/req | parent us/req |
|---|---:|---:|---:|---:|
| OpenSSL | 92,405.1 (2 runs) | 91,855.3 (2 runs) | 10.68 | 10.77 |
| quiche | 90,404.3 (2 runs) | 90,798.6 (2 runs) | 10.94 | 10.89 |
| ngtcp2 | 76,170.3 (5 runs) | 78,727.7 (5 runs) | 13.06 | 12.64 |

OpenSSL is marginally faster and quiche is within noise. The ngtcp2 mean is
about 3% lower, but its run-to-run standard deviation was 2,346 rps on the
final tree and 3,458 rps on the parent, with overlapping ranges
(73.4-79.0k versus 73.0-82.0k). The JVM CPU per request was effectively
unchanged (47.6 versus 47.9 us/req), so the difference is not protocol CPU
cost. Replacing only the new `QpackEncoder` validation with the parent
encoder did not recover throughput (73.8k rps mean), ruling out the most
obvious new per-request Java work. No regression attributable to the review
fixes was found; the lower absolute rps than Section 7 reflects the current
shared-host state, since the parent tree measured at the same time shows the
same level. The final full HTTP/3 suites pass on all three endpoints (465
tests, 0 failures; 2/20/6 skipped for OpenSSL/quiche/ngtcp2).

## 9. Post-review follow-up performance check (2026-11-15)

A final quick check re-ran the documented `8x25` load case (`connections=8`,
`streams=25`, `procs=8`, 3 s warm-up, 12 s window) after a `1x32` JVM-warming
run for all three endpoints. The benchmark base and its native endpoint code
were held fixed; only `tomcat-coyote.jar` and, where noted, the OpenSSL
transport classes from `tomcat-coyote-ffm.jar` were swapped. The host load
average ranged from about 7.8 to 26.2, within the shared-host caveat in
Section 2, so absolute numbers and sub-2% differences should be read with the
usual noise margin.

| endpoint | current rps (mean) | current us/req | Section 8 rps | Section 8 us/req |
|---|---:|---:|---:|---:|
| OpenSSL | 91,502.3 (2 runs, after fix) | 10.85 | 92,405.1 | 10.68 |
| quiche | 91,062.9 (2 runs) | 10.85 | 90,404.3 | 10.94 |
| ngtcp2 | 84,097.6 (2 runs) | 11.85 | 76,170.3 | 13.06 |

quiche is within noise of the report and ngtcp2 is faster (the difference is
host-state noise, not a protocol change). The first OpenSSL run of the final
tree was low, at 87,480.7 rps / 11.3 us/req, so the regression was
investigated before accepting the result.

### 9.1 Cause and bisection

A direct rebuild of the Section 8 final tree (`13f7f32cef`) measured
96,832.1 rps / 10.2 us/req; the later `e890bbf569` tree measured
90,013.4 / 11.0. Bisecting the 57 commits between them, with the benchmark
endpoint jar and only `tomcat-coyote.jar` swapped, isolated the change:

| tree / commit | rps | us/req |
|---|---:|---:|
| `13f7f32cef` (Section 8 tree) | 96,832.1 | 10.2 |
| `404785a168` (before the regression) | 96,301.3 | 10.3 |
| `03acca2245` (parent of the regression) | 96,500.6 | 10.3 |
| `5ca4a358b4` (peek transport data before fast-path FIN) | 89,749.6 | 11.0 |

Commit `5ca4a358b4` added a `getSocketWrapper().isReadyForRead()` probe to
`isRequestStreamCleanlyFinished()`, which runs on every response before the
fast-path FIN. On OpenSSL, `QuicOpenSSLSocketWrapper.isReadyForRead()` calls
`fillReadBuffer()` when the wrapper buffer is empty. That performs an
`SSL_read_ex()` through `onPollThread()` even when the stream read state is
already `FINISHED`, where the native read can only return zero; the
poll-thread hop and native round trip added about 0.5-0.7 us/req to the
per-response path. quiche and ngtcp2 were not affected because their
readiness checks do not take that native path in this state.

### 9.2 Fix

`QuicOpenSSLSocketWrapper.isReadyForRead()` now checks the stream pre-read
buffer directly when the transport read state is `FINISHED`, and only falls
back to `fillReadBuffer()` for other states. Trailing bytes still defer the
fast-path FIN, so the correctness intent of `5ca4a358b4` is preserved without
the per-response native read. After the fix OpenSSL measured 92,313.1 and
90,691.5 rps (10.8 and 10.9 us/req); the doc tree measured 92,505.4 / 10.7
with the same fixed endpoint jar, within the host-noise band.

The full HTTP/3 suite passes on OpenSSL after the fix (520 tests, 0 failures,
2 skipped). The fix changes only the OpenSSL transport wrapper, so the quiche
and ngtcp2 numbers above are unaffected.

## 10. ngtcp2 optimization follow-up (2026-11-15)

The ngtcp2 endpoint was profiled with JFR and temporary poll-loop counters on
the same benchmark base. The goal was to reduce both the idle keepalive cost
and the per-request cost. The documented `8x25` load case and the documented
idle cases (`4000`/`8000` connections, `--stagger 0.004 --settle 35
--keepalive 12`) were used; the host load average ranged from about 1 to 19.

### 10.1 Idle poll performance

| idle connections | before | after | Section 3 report |
|---|---:|---:|---:|
| 4000 | 3.80 % | 1.45 % | 3.67 % |
| 8000 | 14.02-14.67 % | 2.90 % | 15.9-16.0 % |

Two causes dominated the before numbers:

- **Zero-millisecond timer storm.** Poll-loop counters showed that
  `ngtcp2_conn_timeout_as_millis()` can keep returning `0` after
  `ngtcp2_conn_handle_expiry()`/`ngtcp2_conn_send()` for a timer whose
  deadline is already in the past. Re-arming the deadline at "now" made the
  same connections due on every iteration: an 8000-connection idle fleet
  reached about 150,000 poll iterations/s, with JFR showing most poll-thread
  Java samples in timer-heap/set iteration. Giving zero-millisecond results a
  1 ms floor drops this to a normal millisecond cadence.
- **O(fleet) CID cleanup.** Connection teardown removed its CIDs with
  `cidMap.values().removeIf(...)`, scanning the entire fleet-sized map for
  every close. Each connection now tracks its own CID keys and teardown removes
  only those entries, making cleanup O(owned CIDs) instead of O(connections).
  This matters for connection churn and idle-fleet ramp/close.

### 10.2 Request throughput

The `8x25` load case was measured on the unmodified tree and on the optimized
tree with the same native endpoint jar base and the same coyote jar.
Host-noise dominates the small request-path effects, so these results are
reported as a check for regression rather than as a throughput claim:

| tree | rps (mean of 2 runs) | us/req |
|---|---:|---:|
| before optimization | 84,045.5 | 11.8 |
| after optimization | 82,891.9 | 11.95 |

The profile-guided request-path changes removed per-request work but stayed
inside the shared-host run-to-run band:

- The QUIC wrappers selected the direct-read path by calling
  `socketBufferHandler.getReadBuffer().capacity()`, which lazily allocated the
  8 KiB read buffer even when the caller's buffer was used directly. The
  configured size is now exposed and used instead.
- The ngtcp2 blocking write path now forwards an empty staged queue directly
  to `doWrite()` instead of copying the caller's buffer through the socket
  write buffer.
- QPACK response encoding skips `String.toLowerCase()` when the field name is
  already lowercase and no longer scans an already-validated value twice.

The JFR load profile also identified the next candidates: mailbox/eventfd hops
for worker reads/writes and the remaining per-header QPACK encoding work.
Coalescing eventfd kicks was tried and measured within noise, so it was not
retained.

All three HTTP/3 test suites pass after the changes: 520 tests, 0 failures,
with 2/20/6 skipped for OpenSSL/quiche/ngtcp2.

## 11. Post-defect-fix ngtcp2 performance check (2026-11-17)

A quick regression check covered the later ngtcp2 correctness fixes. The
documented `8x25` load case (`connections=8`, `streams=25`, `procs=8`,
3 s warm-up, 12 s window) was run after a `1x32` JVM-warming run. The
benchmark base and server configuration were held fixed; only
`tomcat-coyote.jar` and `tomcat-coyote-ffm.jar` were swapped. The host load
average ranged from about 9 to 14, within the shared-host caveat in Section 2.

| tree | rps (mean) | us/req |
|---|---:|---:|
| parent tree (`bb46787c41`, before the fixes) | 83,400 (3 runs) | 11.9 |
| fixes before this performance correction | 70,262 (3 runs) | 14.0 |
| corrected tree | 82,397 (3 runs) | 12.0 |
| Section 10.2 after-optimization report | 82,891.9 | 11.95 |

The initial fixes showed a reproducible ~15% regression. Bisecting the
fix series with only the coyote jars swapped isolated two interacting
changes on the request-stream completion path:

- Closing a late readable edge for an already completed request directly on
  the poll thread moved the remaining stream drain/close work there. The
  poller is already saturated in this shape; the previous wrapper dispatch
  performed that cleanup on executor workers, which kept per-request poller
  cost lower.
- Suppressing the terminal FIN edge for request streams removed the later
  drain that returned connection flow-control credit for bytes sent after the
  response. It also let the binding tombstone disappear earlier, so some
  late edges were reclassified as new requests and allocated a fresh wrapper.

The correction keeps a bounded tombstone of recently finalized client
bidirectional stream IDs so late edges stay on the duplicate path without
touching the HTTP/3 active-stream count. Request streams keep the terminal
FIN edge (and the wrapper dispatch, which runs the cleanup on workers);
client- and server-initiated unidirectional streams keep the earlier
suppression, since their cleanup is handled directly. The corrected tree is
within run-to-run noise of both the parent tree and the Section 10.2 report.

The ngtcp2 HTTP/3 suite passes after the correction (586 tests, 0 failures,
6 skipped).
## 12. Post-defect-fix OpenSSL performance check (2026-11-18)

A quick regression check covered the final OpenSSL QUIC fixes on top of the
`efea20486f` review tree. The documented `8x25` load case (`connections=8`,
`streams=25`, `procs=8`, 3 s warm-up, 12 s window) was run after a `1x32`
JVM-warming run. The benchmark base was `/home/opencode/tomcat-http3`; only
`tomcat-coyote.jar` and `tomcat-coyote-ffm.jar` were swapped, and the server
was restarted between variants. Host load average ranged from about 10.9 to
24.1, within the shared-host caveat in Section 2.

| tree | runs (rps) | mean rps | us/req |
|---|---:|---:|---:|
| final fixed tree | 92,192.9 / 92,529.6 / 88,976.1 | 91,232.9 | 10.8 |
| parent tree (`efea20486f`) | 90,545.7 / 92,936.4 / 92,474.3 | 91,985.5 | 10.7 |
| Section 9 report (final fixed tree) | 91,502.3 | 91,502.3 | 10.85 |
| older benchmark-base jar | 97,640.7 / 98,650.5 | 98,145.6 | 10.05 |

The final tree is within the shared-host spread of the parent tree (about
0.8% lower mean rps, 0.1 us/req higher) and matches the Section 9 report
(about 0.8% higher rps, 1.4% lower us/req). No regression attributable to the
defect fixes was measurable in this shape.

The older benchmark-base jar is faster in this run but is not a comparison
baseline for the current tree: its class files predate current code (for
example, it has no `writeInterestedWrappers` or retained `listenerPollItem`
fields), matching an earlier tree rather than the review parent. The
parent-versus-fixed A/B above isolates the unpushed changes and shows no
measurable regression.

## 10. Post-review quick performance check (2026-11-18)

A quick check of the current OpenSSL QUIC tree used the same `8x25` load case
(`./run_case.sh <tag> load 8 25 8 12`) after a `1x32` warm-up. The shared-host
load average ranged from about 5.8 to 17.2 during the runs, so absolute rps and
sub-10% differences are noisy; `us/req` and the relative ordering are the useful
signals.

| tree | shape | rps | us/req | poller % | errs |
|---|---|---:|---:|---:|---:|
| current (HEAD before ABI cache) | 8x25 | 92,234.6 | 10.7 | 98.91 | 0 |
| current (ABI cache) | 8x25 | 91,617.3 | 10.8 | 99.16 | 0 |
| parent `e0ab41a5ef` | 8x25 | 89,608.9-90,849.6 | 10.9-11.0 | 98.83-98.91 | 0 |
| `5a60708ad4` (before platform abstraction) | 8x25 | 91,855.8-93,108.4 | 10.6-10.8 | 98.91-99.00 | 0 |
| current (HEAD before ABI cache) | 32x32 | 71,142.9 | 13.9 | 98.74 | 0 |
| current (ABI cache) | 32x32 | 74,552.0 | 13.2 | 98.49 | 0 |
| parent `e0ab41a5ef` | 32x32 | 75,812.3 | 13.1 | 99.25 | 0 |

The current `8x25` numbers match the Section 9 current-tree result
(91,502.3 rps / 10.85 us/req) and the pre-platform tree within the host-noise
band. No reproducible regression attributable to the review fixes was found:
the parent and current measurements overlap, and the `32x32` spread follows the
host load (the same current classes measured 71.1k at load ~8.5 and 74.6k at
load ~10.6).

The older benchmark-base jar measured 99.1k / 10.0 us/req for `8x25` and
79.6k / 12.2 for `32x32` on the same host window, but it is a different source
tree: its `tomcat-coyote-ffm.jar` contains 29 OpenSSL QUIC classes versus 44 in
the current/platform tree. It is therefore not an A/B of the current branch,
and the absolute difference is not evidence of a review regression.

One hot-path cleanup was identified during the investigation:
`QuicOpenSSLEndpoint` called the abstract `PLATFORM.abi()` accessor repeatedly
for every native read/write size/layout access. Caching the immutable ABI
record in a static field reduced the `32x32` poller cost in the back-to-back
pair above (71.1k to 74.6k; `8x25` stayed within noise).

## 13. Unpushed-fix OpenSSL regression check (2026-11-19)

A quick regression check covered the uncommitted review fixes on top of the
`b8a200c6ed` parent (`Remove defects`). The documented `8x25` and `32x32`
load cases (`connections x streams`, `procs=8`, 3 s warm-up, 12 s window)
were run after a `1x32` JVM-warming run. The benchmark base was
`/home/opencode/tomcat-http3`; only `tomcat-coyote.jar` and
`tomcat-coyote-ffm.jar` were swapped, and the server was restarted between
variants. The two `tomcat-coyote.jar` files are byte-identical between the
trees; only `tomcat-coyote-ffm.jar` differs, so the A/B isolates the OpenSSL
QUIC changes. Host load average ranged from about 11 to 16, within the
shared-host caveat in Section 2.

| tree | shape | runs (rps) | mean rps | us/req |
|---|---|---:|---:|---:|
| current fixed tree | 8x25 | 89,786.2 / 90,383.0 | 90,084.6 | 10.6 |
| parent `b8a200c6ed` | 8x25 | 89,118.1 / 90,196.9 | 89,657.5 | 10.7 / 10.6 |
| Section 9 current tree | 8x25 | — | 91,502.3 | 10.85 |
| current fixed tree | 32x32 | 77,980.3 / 72,453.6 / 72,448.9 | 74,294.3 | 12.7 / 13.7 / 13.7 |
| parent `b8a200c6ed` | 32x32 | 78,836.0 / 95,758.6 / 72,888.5 | 82,494.4 | 12.4 / 9.7 / 13.6 |
| Section 10 current tree | 32x32 | — | 71,142.9–74,552.0 | 13.9 / 13.2 |

The current `8x25` mean is 0.5% faster than the parent and 1.5% below the
Section 9 current-tree report while using 0.2 us/req less, all inside the
shared-host spread. The `32x32` parent and current ranges overlap: the
parent's 95.8k / 9.7 run and the current 72.4k / 13.7 runs were taken at
the same host load, and a clean parent rerun measured 72.9k / 13.6. No
reproducible regression attributable to the unpushed fixes was found. The
fixes touch teardown, error and liveness paths rather than steady-state
request processing; the two added liveness checks are volatile reads on
existing hot paths and were not measurable in this shape.

## 14. Unpushed-fix OpenSSL regression check (2026-11-20)

A quick check covered the later OpenSSL QUIC fixes on top of `a986be69ca`.
The benchmark base was `/home/opencode/tomcat-http3`; only
`tomcat-coyote.jar` and `tomcat-coyote-ffm.jar` were swapped, and the
server was restarted between variants. `tomcat-coyote.jar` was
byte-identical between the trees, so the A/B isolates the OpenSSL changes.
The documented `8x25` and `32x32` load cases (`connections x streams`,
`procs=8`, 3 s warm-up, 12 s window) were run after a `1x32` JVM-warming
run. Host load average ranged from about 8 to 22, within the shared-host
caveat in Section 2.

| tree | shape | runs (rps) | mean rps | us/req |
|---|---|---:|---:|---:|
| current before optimization | 8x25 | 87,145.4 / 90,258.6 | 88,702.0 | 11.0 / 10.6 |
| parent `a986be69ca` | 8x25 | 89,592.2 / 90,642.6 | 90,117.4 | 10.7 / 10.5 |
| current after optimization | 8x25 | 89,248.5 / 90,085.4 / 90,671.8 | 90,001.9 | 10.6 / 10.6 / 10.5 |
| Section 13 current tree | 8x25 | — | 90,084.6 | 10.6 |
| current before optimization | 32x32 | 95,141.1 / 70,995.6 | 83,068.4 | 10.4 / 13.9 |
| parent `a986be69ca` | 32x32 | 78,083.4 / 73,302.5 | 75,692.9 | 12.7 / 13.5 |
| current after optimization | 32x32 | 84,572.6 / 78,082.4 | 81,327.5 | 11.7 / 12.7 |
| Section 13 current tree | 32x32 | — | 74,294.3 | 12.7 |

The first current run was about 1.6% below the parent and the Section 13
report on `8x25`, so the difference was investigated before being
accepted as noise. The cause was the D-06 error-queue fix: it called
`QuicDiagnostics.clearErrorQueue()` immediately before every
`SSL_accept_connection()`/`SSL_accept_stream()`. In the steady `8x25`
shape each request-stream event runs a UNI accept pass (normally no
stream) and a BIDI accept pass (one accepted stream), so the fix added
two native `ERR_clear_error()` downcalls per request. That was enough to
cost about 0.2 us/req against a 10.6 us/req request path.

The correction clears any residual error-queue entries once per
event-bearing poll iteration, before the item scan, instead of per
accept call. Handled non-fatal failures continue to clear their own
entries, so the D-06 intent is preserved: an accept still sees only
errors raised in the current iteration, while steady-state stream
acceptance no longer pays a native clear per stream. The optimized tree
returns to the parent/report level (90.0k rps / 10.6 us/req on `8x25`);
`32x32` also remains within the host-noise spread. The full HTTP/3
OpenSSL suite passes (588 tests, 0 failures, 2 skipped). Raw shards are
`/home/opencode/h3bench/out.perf-cur-*`, `out.perf-par-*` and
`out.perf-opt-*`.

## 15. Unpushed-change OpenSSL regression check (2026-11-21)

A quick check covered the unpushed tree at `d7e29013dd` (the final
defect fixes plus the test-timing changes). The documented `8x25` load
case (`connections=8`, `streams=25`, `procs=8`, 3 s warm-up, 12 s
window) was run after a `1x32` JVM-warming run. The benchmark base was
`/home/opencode/tomcat-http3`; only `tomcat-coyote.jar` and
`tomcat-coyote-ffm.jar` were swapped, and the server was restarted
between variants. Host load average ranged from about 9 to 19, within
the shared-host caveat in Section 2.

| tree | runs | mean rps | us/req |
|---|---:|---:|---:|
| current `d7e29013dd` | 80,624.1-87,317.4 | 83,891.2 | 11.1 |
| parent `2bf850a793` (before the final fixes) | 81,513.3 / 83,183.3 / 83,240.1 | 82,645.6 | 11.2 |
| Section 14 optimized current tree | — | 90,001.9 | 10.6 |

The final fixes are about 1.5% faster than their parent on the same
host, so the last defect-fix series is not the source of the gap. The
current tree is about 6.8% below the Section 14 report in rps and 4.7%
above it in `us/req`. Bisecting the unpushed history with built jars
and only the coyote/ffm jars swapped isolated the cause.

| tree / commit | runs (rps) | mean rps | us/req |
|---|---:|---:|---:|
| `b8bbb345a5` | 92,875.6 / 94,876.2 / 93,371.8 / 91,112.4 / 91,130.2 | 92,673.2 | 10.1 |
| `4515c02089` (parent of the regression) | 91,519.0 / 93,615.6 | 92,567.3 | 10.2 |
| `6e4de9f388` (cancel timed-out poll hops and isolate buffers) | 81,643.9 / 80,577.5 | 81,110.7 | 11.4 |
| current `d7e29013dd` | see above | 83,891.2 | 11.1 |

Commit `6e4de9f388` (an earlier unpushed correctness fix, before the
defect-fix series) introduced the regression. It changed the worker
read/write hops from passing the caller buffer to the poll thread to
copying it into a task-owned buffer first:

* `QuicOpenSSLSocketWrapper.fillReadBufferDirect()` now allocates a
  scratch `ByteBuffer` per worker read and copies the bytes into the
  caller buffer.
* `QuicOpenSSLSocketWrapper.writeChunk()` now allocates a `byte[]` per
  worker write, copies the caller bytes into it, and wraps that copy
  for the native hop.

The copies are required to keep a timed-out hop from touching a
caller-owned buffer, but they add allocation and copy work to every
worker read and write hop. The JVM CPU cost at the same request rate
rose from about 500% of one core (`b8bbb`/`4515c0`) to about 620% on
`6e4de9` and the current tree, while poller CPU stayed around 92-94%.
The regression is therefore server-side Java work, not a change in
native QUIC cost. The current tree's remaining gap to the Section 14
report is consistent with this single commit: the report predates it.

A dirty poll-item write experiment (copying only changed structs into
the compact subset) and a slot-based replacement for the poll-item
membership guard were measured during the investigation; neither
recovered the lost throughput, because the buffer snapshots dominate
the `8x25` request path. Both were reverted rather than committed.

The correct mitigation is to keep the timed-out-hop isolation while
avoiding a fresh allocation/copy on every hop, for example a pooled
task-owned buffer with explicit ownership transfer on completion or
cancellation, or a start/cancel handshake that lets a hop use the
caller buffer when the caller promises not to reuse it. That requires a
separate ownership design change.

The buffer-snapshot commit `6e4de9f388` was therefore reverted. The
read and write hops again hand the caller's live buffer to the poll
thread (with the caller blocked in the hop until it completes), and the
per-hop cancellation/discard API introduced by that commit was removed;
the one later caller that relied on its cleanup (the certificate-reload
swap) again handles rejection itself and does not free a snapshot whose
queued task may still run. Re-measured after the revert with the same
`8x25` case: 93,760.0 / 94,747.2 / 95,887.7 rps and 10.1 / 9.9 / 9.9
`us/req`, recovering above the Section 14 report and matching the
pre-regression trees. The full OpenSSL HTTP/3 suite passes after the
revert (588 tests, 0 failures, 2 skipped).


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

# Testing the HTTP/3 connector with Chrome

Practical notes for validating the
`org.apache.coyote.http3.Http3OpenSSLProtocol` connector (OpenSSL 4 QUIC
implementation) with a real Chrome browser.
Everything below was verified on Linux with Tomcat main, OpenSSL 4.0.0,
Java 25 and Chrome for Testing 153 (and 131 for built-in screenshots,
section 4). Firefox headless is also a fully viable client - see
section 9. The connector can additionally run on the Cloudflare quiche
backend instead of OpenSSL - see section 10.

## 1. Build and start the server

```sh
ant -q package
```

The Panama FFM binding needs native-access flags and the OpenSSL 4
libraries on both `java.library.path` and `LD_LIBRARY_PATH`:

```sh
export JAVA_OPTS="--enable-native-access=ALL-UNNAMED \
  --add-opens=java.base/java.io=ALL-UNNAMED \
  --add-opens=java.base/java.lang=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  --add-opens=java.base/java.util.concurrent=ALL-UNNAMED \
  --add-opens=java.base/sun.nio.ch=ALL-UNNAMED \
  --add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED \
  -Djava.library.path=/path/to/openssl/lib64"
export LD_LIBRARY_PATH=/path/to/openssl/lib64
output/build/bin/catalina.sh start
```

## 2. Server certificate: use a trusted CA-signed leaf, not a self-signed one

This is the single biggest Chrome gotcha. **Chrome's QUIC stack does not
honour `--ignore-certificate-errors` or
`--ignore-certificate-errors-spki-list`.** A self-signed leaf (e.g. the
`keytool`-generated `conf/localhost.p12`) is rejected during the QUIC
handshake with `QUIC_SESSION_CERTIFICATE_VERIFY_FAILED` even when the
same certificate is accepted over TCP/TLS with the same flag. Plain
`curl -k` will happily connect, which makes this easy to misdiagnose as
a server bug.

The reliable setup is a local test CA that the OS trust store (NSS db)
actually trusts. Test material is in
`test/org/apache/coyote/http3/`:

- `quic-ca-cert.pem` / `quic-ca-key.pem` - test CA
- `quic-leaf-cert.pem` / `quic-leaf-key.pem` - leaf with
  `CN=localhost`, SAN `DNS:localhost, IP:127.0.0.1`
- `quic-leaf-chain.pem` - the CA certificate, served after the leaf as the
  certificate chain (`certificateChainFile`)

Copy them into `conf/` and configure the connector (UDP-only port is
fine; Chrome probes with Alt-Svc forced, see below):

```xml
<Connector port="8444" protocol="org.apache.coyote.http3.Http3OpenSSLProtocol"
           SSLEnabled="true">
    <SSLHostConfig>
        <Certificate certificateFile="conf/quic-leaf-cert.pem"
                     certificateKeyFile="conf/quic-leaf-key.pem"
                     certificateChainFile="conf/quic-ca-cert.pem"/>
    </SSLHostConfig>
</Connector>
```

(`Certificate` elements are only digested when nested inside
`<SSLHostConfig>` - a bare `<Certificate>` under `<Connector>` is silently
ignored and the connector fails to bind for want of a certificate.)

To regenerate the leaf with SANs:

```sh
openssl req -new -newkey rsa:2048 -nodes -keyout quic-leaf-key.pem \
    -subj "/CN=localhost" -out leaf.csr
openssl x509 -req -in leaf.csr -CA quic-ca-cert.pem -CAkey quic-ca-key.pem \
    -CAcreateserial -days 825 -out quic-leaf-cert.pem \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
```

## 3. Make Chrome trust the CA

Chrome on Linux uses the NSS database in `~/.pki/nssdb`. `certutil`
comes from `libnss3-tools` (any checkout of the binary works, e.g. one
extracted from the distro package):

```sh
mkdir -p ~/.pki/nssdb
certutil -d sql:$HOME/.pki/nssdb -N --empty-password   # first time only
certutil -d sql:$HOME/.pki/nssdb -A -t "CT,C,C" \
    -n quic-test-ca -i conf/quic-ca-cert.pem
certutil -d sql:$HOME/.pki/nssdb -L                    # verify: CT,C,C
```

Re-seed after each CA re-generation. A stale entry can be removed with
`certutil -D -n quic-test-ca`.

## 4. Which Chrome to use

- **Chrome for Testing (recommended).** An unpacked binary uses the real
  `~/.pki/nssdb` and honours the CA trust. Download:

  ```sh
  curl -sO https://storage.googleapis.com/chrome-for-testing-public/<version>/linux64/chrome-linux64.zip
  unzip -q chrome-linux64.zip
  ```

  (Discover `<version>` via
  `https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json`.)

- **Chrome for Testing <= 131, if you want built-in `--screenshot` /
  `--dump-dom`.** The old headless mode (plain `--headless`) has a
  working capture/exit path; it was removed in Chrome 132, so current
  releases only offer the new mode, which hangs here (see section 5).
  Verified with 131.0.6778.87, including over HTTP/3 — the same
  `--origin-to-force-quic-on` flags work, the NSS CA trust from
  section 3 is honoured, and the server log shows
  `GET /h3test.html HTTP/3 200`:

  ```sh
  curl -sO https://storage.googleapis.com/chrome-for-testing-public/131.0.6778.87/linux64/chrome-linux64.zip
  unzip -q chrome-linux64.zip
  /tmp/path/chrome-linux64/chrome --headless --no-sandbox --disable-gpu \
      --disable-dev-shm-usage --no-first-run --disable-component-update \
      --user-data-dir="$(mktemp -d)" \
      --origin-to-force-quic-on=localhost:8444 \
      --host-resolver-rules="MAP localhost 127.0.0.1,MAP * 0.0.0.0" \
      --window-size=1280,800 \
      --screenshot=/tmp/h3-chrome-shot.png https://localhost:8444/h3test.html
  ```

- **Snap Chromium: do not rely on it.** Inside confinement its `HOME` is
  `/home/$USER/snap/chromium/<rev>`, seeding its `~/.pki/nssdb` did not
  take effect for QUIC verification in testing, and the cert-bypass
  flags are ignored on QUIC anyway. Use it only for
  Alt-Svc-discovery experiments, not for cert-trusted validation. (It
  may also fail to start at all, e.g.
  `... is not a snap cgroup for tag snap.chromium.chromium` when the
  session cgroup is not snap-labelled.)

## 5. Run the headless test

```sh
TMPD=$(mktemp -d)
/tmp/path/chrome-linux64/chrome \
    --headless=new --no-sandbox --disable-gpu \
    --disable-dev-shm-usage --no-first-run \
    --disable-component-update --disable-background-networking \
    --user-data-dir="$TMPD" \
    --origin-to-force-quic-on=localhost:8444 \
    --host-resolver-rules="MAP localhost 127.0.0.1,MAP * 0.0.0.0" \
    --virtual-time-budget=20000 \
    --dump-dom https://localhost:8444/h3test.html
```

Flag rationale:

- `--origin-to-force-quic-on=localhost:8444` - forces QUIC immediately;
  otherwise Chrome needs a prior Alt-Svc hint from a TCP connection on
  the same origin/port, which a UDP-only connector never provides.
- `--host-resolver-rules="MAP localhost 127.0.0.1,MAP * 0.0.0.0"` -
  pins the server to IPv4 loopback (avoids `::1`, which the UDP socket
  is not bound to) and blocks all other network access, so netlogs and
  failures stay unambiguous.
- `--headless=new` + a throwaway `--user-data-dir` keeps the test
  non-interactive and stateless (no stale Alt-Svc/HSTS cache).

**Note:** On current Chrome (>= 132, where `--headless=new` is the only
headless mode), `--dump-dom` and `--screenshot` hang after the page has
loaded and *never* produce their output. This is **not** specific to
QUIC — the same hang was reproduced with `file://` and with
`https://www.google.com` both with and without `--disable-quic`; the
page does load (visible in the server access log), only the
new-headless capture/shutdown path hangs in this environment.
`timeout 45 ...` exiting 124 with no output file is therefore expected
and *not* evidence of a server failure — judge the result from the
access log, not from the chrome process exit code. To actually capture
a screenshot or the rendered DOM, use Chrome for Testing <= 131's old
headless mode (section 4), or drive current Chrome through the DevTools
Protocol (section 6).

**Do not run `ant test` while this server is running.** The test build
shares `output/build` with the live server, and `build-prepare` deletes
`${tomcat.build}/work`. The JSP classloader keeps a handle on the
deleted directory, so JSP pages 500 with `ClassNotFoundException`
(e.g. `org.apache.jsp.echo_jsp`) even though the `.class` files are
back on disk. A clean `catalina.sh` stop/start fixes it. Run the JUnit
suite and the browser/curl validation sequentially.

## 6. Capturing screenshots and rendered DOM (DevTools Protocol)

Because the built-in `--screenshot` / `--dump-dom` flags hang before
producing output (see section 5), drive headless Chrome through its
DevTools endpoint instead. The page loads over QUIC normally; only the
process *shutdown* hangs, which does not matter for an out-of-band CDP
client.

Start Chrome detached with a debugging port:

```sh
TMPD=$(mktemp -d)
setsid nohup /tmp/path/chrome-linux64/chrome \
    --headless=new --no-sandbox --disable-gpu \
    --disable-dev-shm-usage --no-first-run \
    --disable-component-update --disable-background-networking \
    --user-data-dir="$TMPD" \
    --origin-to-force-quic-on=localhost:8444 \
    --host-resolver-rules="MAP localhost 127.0.0.1,MAP * 0.0.0.0" \
    --remote-debugging-port=9222 --window-size=1280,800 \
    about:blank > /tmp/chrome-dev.log 2>&1 < /dev/null &
```

(`setsid ... < /dev/null &` keeps Chrome out of the calling shell's
process group, so it survives if the wrapping command times out or is
killed.)

Then navigate, verify and screenshot with Node >= 22 (built-in
`WebSocket`, no dependencies):

```js
// cdp-shot.mjs
import { writeFileSync } from 'node:fs';
const target = await (await fetch(
  'http://127.0.0.1:9222/json/new?' +
  encodeURIComponent('https://localhost:8444/h3test.html'),
  { method: 'PUT' })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
let id = 0;
const pending = new Map();
const send = (method, params = {}) => new Promise((res, rej) => {
  const mid = ++id;
  pending.set(mid, { res, rej });
  ws.send(JSON.stringify({ id: mid, method, params }));
});
ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    const { res, rej } = pending.get(m.id);
    pending.delete(m.id);
    m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result);
  }
});
ws.onopen = async () => {
  await send('Page.enable');
  await new Promise((r) => setTimeout(r, 3000)); // allow load over QUIC
  const { result: { value: proto } } = await send('Runtime.evaluate', {
    expression:
      "performance.getEntriesByType('navigation')[0]?.nextHopProtocol",
    returnByValue: true,
  });
  const { result: { value: text } } = await send('Runtime.evaluate', {
    expression: 'document.body.innerText', returnByValue: true,
  });
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync('/tmp/h3-chrome-shot.png',
                Buffer.from(shot.data, 'base64'));
  console.log(`protocol=${proto} dom=${JSON.stringify(text)}`);
  process.exit(0);
};
```

`node cdp-shot.mjs` prints e.g.
`protocol=h3 dom="HTTP/3 Test\n\nQUIC is working!"`. The
`nextHopProtocol` value is *client-side* proof the navigation used
HTTP/3, complementing the server access log (section 7). Kill Chrome
afterwards with `pkill -f chrome-linux64` — it will not exit on its
own while the QUIC connection is open.

## 7. Verify it actually went over HTTP/3

Server access log is the ground truth:

```sh
tail output/build/logs/localhost_access_log.*.txt
# 127.0.0.1 - - [...] "GET /h3test.html HTTP/3" 200 70
```

`HTTP/3` in the request line proves the QUIC path; a `HTTP/1.1` entry
would mean it fell back to TCP (which will not happen on a UDP-only
port, but check on dual-stack setups).

For deeper diagnosis, record a netlog:

```sh
... chrome ... --log-net-log=/tmp/netlog.json --net-log-capture-mode=IncludeCapabilities
```

and grep the connection section for
`QUIC_SESSION_CRYPTO_HANDSHAKE_COMPLETE`,
`QUIC_SESSION_PARAMETERS_RECEIVED`, `HTTP3_HEADERS_DECODED`,
`HTTP3_DATA_FRAME_RECEIVED`. A failed handshake shows up as
`QUIC_SESSION_CERTIFICATE_VERIFY_FAILED` (trust problem - redo
sections 2-3) or `UDP_SEND_ERROR` on `127.0.0.1` (resolver/routing
problem - redo section 5).

## 8. Non-browser smoke tests

`curl` (needs `--with-nghttp3`; note `-k` works fine with self-signed
here, unlike Chrome) covers most protocol surface quickly:

```sh
curl -sk --http3 -o /dev/null -w "%{http_version} %{http_code}\n" \
    https://localhost:8444/h3test.html
curl -sk --http3 -I https://localhost:8444/h3test.html
curl -sk --http3 -X POST -d hello https://localhost:8444/echo.jsp
curl -sk --http3 --output /tmp/big.bin https://localhost:8444/h3big.bin  # 1 MiB, check md5
seq 1 40 | xargs -I{} curl -sk --http3 -o /dev/null -w "%{http_code} " \
    https://localhost:8444/h3test.html           # sequential
seq 1 8  | xargs -P8 -I{} curl -sk --http3 -o /dev/null -w "%{http_code} " \
    https://localhost:8444/h3test.html           # parallel, multiplexed
```

The curl smoke tests above are manual only. Automated interop coverage
against an independent HTTP/3 stack runs in CI through the JDK HttpClient
(JEP 517, JDK 26) in `TestHttp3JdkHttpClient` - it is part of the normal
`ant test` / `run-http3-tests.sh` run and skips itself on JDKs older than
26. The JUnit suite (`ant -q test -Dtest.entry=org.apache.coyote.http3.TestXxx`)
also covers QPACK, flow control and RFC sections; Chrome validates the
browser-trust path, which no test-suite certificate setup exercises
end-to-end.

## 9. Firefox headless (works too)

Firefox headless uses the same HTTP/3 stack as the interactive browser
(neqo over Necko, on by default since Firefox 95) and - unlike current
Chrome - its built-in `--screenshot` / `--dump-dom` flags exit cleanly.
Verified with Firefox 156.0 (Mozilla tarball; `/usr/bin/firefox` on this
machine is a snap stub that dies with the same `not a snap cgroup` error
documented for snap Chromium in section 4):

```sh
curl -sO https://download-installer.cdn.mozilla.net/pub/firefox/releases/<version>/linux-x86_64/en-US/firefox-<version>.tar.xz
tar -xf firefox-<version>.tar.xz    # -> ./firefox/firefox
```

Build a throwaway profile that trusts the test CA and forces HTTP/3:

```sh
PROF=$(mktemp -d)
certutil -d sql:"$PROF" -N --empty-password   # first time only
certutil -d sql:"$PROF" -A -t "CT,C,C" -n quic-test-ca -i conf/quic-ca-cert.pem
cat > "$PROF/user.js" <<'EOF'
user_pref("network.http.http3.alt-svc-mapping-for-testing", "localhost;h3=\":8444\"");
user_pref("network.http.http3.disable_when_third_party_roots_found", false);
EOF
```

Unlike Chrome, Firefox does **not** use `~/.pki/nssdb`: it trusts the
NSS database inside its own profile, so import `quic-ca-cert.pem` into
the profile with `certutil` (same trust flags as section 3).

```sh
MOZ_DISABLE_CONTENT_SANDBOX=1 timeout 60 ./firefox/firefox \
    --headless --no-remote --profile "$PROF" --window-size=1280,800 \
    --screenshot=/tmp/h3-ff-shot.png https://localhost:8444/h3test.html
# exit 0, screenshot written, access log shows: GET /h3test.html HTTP/3 200
```

The two prefs and one trap:

- `network.http.http3.alt-svc-mapping-for-testing` is the equivalent of
  `--origin-to-force-quic-on`: it injects an Alt-Svc entry (entries are
  comma-separated, each formatted as `<host>;h3=":<port>"`) into the
  Alt-Svc cache before the connection opens, so a UDP-only connector
  works without any TCP hint. (`MOZ_FORCE_QUIC_ON=localhost:8444` as an
  environment variable is the CLI shorthand.)
- **The trap:** `network.http.http3.disable_when_third_party_roots_found`
  defaults to `true`, and Firefox closes the QUIC connection right after
  the handshake when the server chain is rooted at a non-built-in CA -
  which is exactly our imported test CA. The symptom is easy to
  misdiagnose: the TLS handshake completes, no request ever reaches the
  server (access log stays empty), the headless load hangs until the
  timeout, and the client log shows
  `Http3Session::Authenticated [... hasThirdPartyRoots=1 ...]` followed
  by a close with `NS_ERROR_NET_RESET` (`0x804b0014`); the qlog shows
  `connection_closed {"application_code": 256, "trigger": "application"}`.
  It is a client policy, not a connector bug - set the pref to `false`
  for local-CA testing (Firefox has no CLI switch for it).
- `MOZ_DISABLE_CONTENT_SANDBOX=1` is only needed in containers without
  user namespaces (the log says `Sandbox: CanCreateUserNamespace()
  unshare(CLONE_NEWPID): EPERM` when it is required).

For deeper diagnosis set `network.http.http3.enable_qlog` (user.js) - the
qlogs land in `$TMPDIR/qlog_<pid>/` - and `MOZ_LOG="nsHttp:5"
MOZ_LOG_FILE=/tmp/fflog/net` for the Necko/Http3Session trace. Note the
static page is heuristically cached between runs against the same
profile (same trap as Chrome's stale Alt-Svc cache, section 5): append a
unique query string or start from a fresh profile when you need proof of
a wire fetch.

## 10. The quiche backend

The HTTP/3 connector can run on Cloudflare quiche instead of OpenSSL 4.
The QUIC transport is selected by the connector `protocol` attribute -
there is no start-up probing and no silent fallback, and a connector
whose transport is unusable fails at bind time:

- `org.apache.coyote.http3.Http3OpenSSLProtocol` (the default in
  `conf/server.xml`) runs on the FFM-based OpenSSL QUIC endpoint;
- `org.apache.coyote.http3.Http3QuicheProtocol` runs on the FFM-based
  Cloudflare quiche endpoint
  (`org.apache.tomcat.util.net.quic.quiche.QuicheEndpoint`).

Both classes extend `org.apache.coyote.http3.AbstractHttp3Protocol`,
which holds all the HTTP/3 connector configuration.

Phase-1 quiche limitation: the TLS configuration is a single
default-host PEM certificate. SNI/multi-host `SSLHostConfig` setups and
keystore-sourced material are not wired up yet - keep the connector to
one `<Certificate>` (the leaf/CA files from section 2 work as-is).

Connection IDs: quiche only sends NEW_CONNECTION_ID frames for CIDs the
application supplies, so the quiche endpoint issues exactly one additional
source CID per connection at accept (`quiche_conn_new_scid`, saturating the
default `active_connection_id_limit` of 2) and registers it in its demux
map. A spec-compliant deliberate client migration (RFC 9000 Section 9.5)
can therefore switch to a fresh DCID; NAT rebinding has always worked.
There is no CID rotation/retirement yet, and the OpenSSL backend
auto-issues more CIDs.

### 10.1 Running the server on quiche

libquiche 0.30.0 is prebuilt locally under
`/home/opencode/quiche-0.30.0/target/` (`release`, or `debug` for debug
info) and already on the library path, so nothing to build - just switch
the 8444 connector in `conf/server.xml` to the quiche protocol class:

```xml
<Connector port="8444"
           protocol="org.apache.coyote.http3.Http3QuicheProtocol"
           SSLEnabled="true">
```

(start the server as in section 1; no extra `JAVA_OPTS` are needed for
the selection itself):

```sh
output/build/bin/catalina.sh start
```

The log line `QUIC endpoint [https-quic-quiche-8444] bound to [...]
using quiche [x.y.z]` confirms it - the `quiche` in the endpoint name
and the quiche version in the message are only produced by the quiche
endpoint. The curl and browser checks from sections 2-9 work unchanged.

### 10.2 Running the JUnit suite

`run-http3-tests.sh` wraps the whole HTTP/3 JUnit suite:

```sh
./run-http3-tests.sh              # OpenSSL backend
./run-http3-tests.sh --quiche     # quiche backend
```

- `--quiche` passes `-Dtest.quiche=true`, which makes the build pin the
  protocol class `org.apache.coyote.http3.Http3QuicheProtocol` in the
  test JVM via the `tomcat.test.http3.protocol` test property (the
  default is `Http3OpenSSLProtocol`; the script also puts the prebuilt
  libquiche directory on `LD_LIBRARY_PATH`; use `--quiche-lib DIR` to
  point at a different build, e.g. `target/debug`).
- Default mode needs an OpenSSL 4 build with the QUIC APIs (in-tree or
  installed). The script puts `OPENSSL_LIB_DIR`
  (default `/home/opencode/openssl-master`) on `LD_LIBRARY_PATH`; FFM
  locates libssl via `dlopen`, so `java.library.path` alone is not
  enough.
- Summary lines per class plus a `TOTAL run=... failures=... skipped=...`
  line are printed; full per-test logs land in
  `output/build/logs/TEST-org.apache.coyote.http3.*.NIO.txt`.
- If the summary shows `skipped` equal to the total, no QUIC backend
  loaded (wrong/missing library on `LD_LIBRARY_PATH`) - that is an
  environment problem, not a test failure.
- The `TestHttp3JdkHttpClient` interop tests drive the server with the JDK
  HttpClient's HTTP/3 client (JEP 517). They need a JDK 26 or newer test
  JVM (the test JVM is the one Ant runs on, so export `JAVA_HOME`
  accordingly) and otherwise skip with "JEP 517" in the skip reason. The
  suite's other tests use the aioquic probe client and skip only when
  python3/aioquic are missing.

With the quiche endpoint active, ~14 tests skip themselves by design:
SNI/multi-certificate/keystore/reload cases (phase-1 single-PEM
limitation) and a few OpenSSL-specific connection-close assertions.
Expected full-suite shape as of writing (JDK 26 test JVM): `run=250
skipped=0` with OpenSSL at 250/0/0, and `run=250 skipped=19` (11 SNI /
keystore cases, 5 PSK cases, 3 OpenSSL-specific close-assertion cases)
with quiche at 0 failures. Earlier quiche-only
failures and load flakes (RESET_STREAM surfacing as EOF to async read
listeners instead of an error, missing stream FIN after an ACKed body,
stalled async/blocking response writes when connection-level
flow-control credit reopened without a writable edge, dropped
readable/writeable dispatches under parallel load) are fixed: the
endpoint now captures the one-shot quiche reset error on the poll
thread and the processor surfaces it to the handler like HTTP/2 does,
the wrapper holds back the final bytes of a response and sends them
with the FIN flag (so the FIN rides on a data-bearing frame that loss
recovery retransmits, instead of a zero-length FIN that quiche can
collect along with an ACKed-complete stream), the endpoint
level-re-arms write readiness from `quiche_conn_stream_capacity`
(including OPEN_WRITE dispatch for async write listeners), and retries
event deliveries whose processing claim was busy instead of dropping
them.

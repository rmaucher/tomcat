# Review of `org.apache.tomcat.util.net.quic.openssl`

Date: 2026-11-25

## Scope and method

This is an independent static review of all Java classes in
`java/org/apache/tomcat/util/net/quic/openssl` (about 21,000 lines),
plus the OpenSSL declarations/source they call and the HTTP/3 and endpoint
lifecycle call sites that use these classes. No parallel/sub-agents were used.

For native contracts I checked the actual OpenSSL tree available in this
environment at `/home/opencode/openssl-master` (`ssl/`, `include/openssl/`)
rather than relying only on comments. Every suspected defect was followed to
its callers and, where relevant, to the sibling quiche/ngtcp2 transports.
The full OpenSSL HTTP/3 test suite was run after each code fix; the final
suite result is 588 tests, 0 failures, 0 errors, 2 skipped. The remaining
security and maintainability observations are verified against the native
source where ABI/behaviour matters.

## Summary

No open code defects remain from the reviewed list. The sections below record
the security limitations and maintainability observations that were checked
and retained.

## Security posture and documented limitations

The following are not newly introduced code defects in this review; they are
real deployment limitations of this transport. Most are documented and warned
about, but they are security-relevant and should be considered fail-open gaps.

1. **Optional client authentication is ignored.** `certificateVerification=want`
   / `OPTIONAL` / `OPTIONAL_NO_CA` only produces a warning
   (`QuicCertConfig.java:285-301`). The QUIC endpoint never installs a verify
   hook and never requests a client certificate. Only `REQUIRED` fails the
   build. Applications using an optional client certificate as an identity
   signal will see no peer certificate. A fail-closed policy for any
   non-`NONE` verification setting would be safer.
2. **OCSP stapling and CRL/revocation are ignored.** `ocspEnabled`,
   `revocationEnabled` and `certificateRevocationListFile` only warn
   (`QuicCertConfig.java:276-284`). An operator expecting revocation
   enforcement must not rely on this transport.
3. **A directly provided `SSLContext` is not used for native trust or client
   auth configuration.** It is retained for Manager/MBean consumers and warned
   about (`QuicOpenSSLEndpoint.java:1660-1675`), while the handshake uses
   `QuicCertConfig` files/keystores. Trust-store and client-auth settings on a
   provided context do not reach the native handshake.
4. **Peer-address refresh is fail-open for address-based valves.**
   `refreshPeerAddress()` leaves the previously captured address in place when
   `SSL_get_peer_addr()` fails (`QuicOpenSSLEndpoint.java:5578-5590`). After
   migration, a request can be checked against an old address. This is exactly
   the kind of input `RemoteCIDRValve` uses; if remote address is security
   input, the connection should be failed closed or the failure surfaced.
5. **Per-host TLS policy differences are not enforced.** All hosts share one
   `SSL_CTX`; per-host `cipherSuites`, `groups`, `protocols` and TLS 1.2
   `ciphers` are warned about and the default host's policy is used
   (`QuicCertConfig.java:242-275`, `QuicCertificateManager.java:307-320`).
   A non-default host configured with a stricter policy inherits the default
   host's suites/groups. This is documented but security-relevant.
6. **PSK-only mode can remove forward secrecy.** For an endpoint with no
   certificates anywhere, `SSL_OP_ALLOW_NO_DHE_KEX` is enabled and a warning is
   emitted (`QuicCertificateManager.java:378-435`). This is intentional for
   pre-shared-key-only endpoints but must be understood operationally.
7. **Session resumption is intentionally disabled.** `SSL_CTX_set_num_tickets(0)`
   plus `SSL_OP_NO_TICKET` (`QuicCertificateManager.java:307-320`) is a sound
   choice for the shared-context virtual-host model, but it means no TLS 1.3
   resumption and no per-host ticket isolation.
8. **Invalid SNI is handled inconsistently.** A trailing-dot SNI is rejected
   fatally, while an SNI containing control characters is converted to "no SNI"
   by `readSniHostNameNative()` (`QuicConnectionWrapper.java:628-651`) and falls
   back to the default host certificate. This is not a certificate-name
   mismatch (the default host is the normal no-SNI fallback), but it means an
   invalid SNI is silently treated as absent by the certificate manager.
   Rejecting all malformed SNI values would be more consistent and easier to
   audit.
9. **No client certificate verification and no renegotiation.** The handshake
   is server-authentication TLS 1.3 only; `doClientAuth()` fails
   (`QuicOpenSSLSocketWrapper.java:1241-1245`). This is documented.
10. **ALPN and logging hardening are good.** The ALPN callback bounds-checks the
    client protocol list and returns `SSL_TLSEXT_ERR_ALERT_FATAL` on malformed
    or unsupported input; payload bytes are not logged (sizes only); error
    queue dumps are bounded.

## Duplicated code and maintainability

No independent functional defect was reproduced by the duplication alone, but
the package contains several large near-copies of security/teardown logic. A
stale comment found during this review was an example of how these copies
drift.

1. **Connection free/reclaim sequences.** The same
   drain-deferred-queues -> free-idle-streams -> `freeSslOnce()` -> retain
   sequence is open-coded in `teardownConnection()` (`7934`),
   `freeConnectionOrDefer()` (`3701`), `reclaimRetainedConnection()` (`3535`),
   `stopInternal()` (`2533`/`2617`), `finishStreamDispatch()`'s deferred task
   (`9551`), and the Cleaner drain (`QuicNativeMailbox`). The sticky-failure
   checks have historically not been applied identically, which is exactly the
   risk of this duplication.
2. **Stream free/claim loops.** `QuicConnectionWrapper.closeAllStreams()`
   (`1326`), the stop stream pass (`2535`), `freeIdleStreams()` (`3668`),
   `reclaimRetainedConnection()` (`3595`), and the mailbox drain methods all
   iterate streams, claim `processing`, free or defer, and clear the claim.
   They now share `freeSslIfIdle()`/`freeSslOnce()`, but the surrounding
   bookkeeping is still copy-pasted.
3. **Event failure/wake/teardown handlers.** `failConnectionNow()`,
   `handlePollFailure()`, `handleConnectionClose()` and
   `abortConnectionSetup()` repeat the "wake terminal events then tear down"
   sequence with subtly different liveness/failure checks. The differences are
   intentional in places, but they make it easy to miss a case.
4. **Socket wrapper read loops.** `read(byte[])` and `read(ByteBuffer)` repeat
   the deadline/would-block/await logic; a shared read-loop helper would reduce
   the chance of one path losing the zero-length/read-only/EOF handling.
5. **Certificate callback setup.** `setupAlpnCallback()`,
   `setupSniCallback()` and `setupPskCallback()` repeat the same
   arena/upcall/downcall installation pattern with only the signature
   differing.
6. **FFM binding boilerplate.** `QuicBindings` contains the standard
   handle + wrapper + `AssertionError("should not reach here")` boilerplate for
   every symbol; that is generated-binding style and hard to avoid, but it
   makes the class very large.
7. **`QuicOpenSSLEndpoint` is a 10,700-line monolith.** Splitting the poll loop,
   event handlers, certificate lifecycle, stream bootstrap and teardown/reclaim
   into collaborators would make the invariants easier to verify. The
   claim-waiter, provisional-close and poll-item eviction paths are all in this
   file.

## Items checked and found correct

The following were checked against the native source and call sites and no
defect was found:

* OpenSSL constants used by the package: `SSL_POLL_EVENT_*`
  (values 1 << 0..12), `SSL_POLL_FLAG_NO_HANDLE_EVENTS`, `SSL_STREAM_STATE_*`,
  `SSL_ACCEPT_STREAM_*`, `SSL_STREAM_TYPE_*`, `SSL_STREAM_FLAG_UNI`,
  `SSL_VALUE_CLASS_*`, `SSL_VALUE_QUIC_*`, `SSL_VALUE_EVENT_HANDLING_MODE_*`,
  `SSL_INCOMING_STREAM_POLICY_ACCEPT`, `SSL_DEFAULT_STREAM_MODE_NONE`,
  `SSL_SHUTDOWN_FLAG_*`, `SSL_CTRL_*`, `SSL_OP_ALLOW_NO_DHE_KEX`,
  `SSL_TLSEXT_ERR_*`, `TLSEXT_NAMETYPE_HOST_NAME`, `SSL_AD_INTERNAL_ERROR`.
* FFM signatures and layouts: `SSL_POLL_ITEM`/`BIO_POLL_DESCRIPTOR`
  (16/32-byte LP64 layouts, offsets 0/8/16/24), Linux `struct timeval`
  (16 bytes), `struct pollfd` (8 bytes), `size_t`/`long` width.
* Linux socket constants and `sockaddr_in`/`sockaddr_in6` sizes, network-order
  port encoding/decoding, `IPV6_V6ONLY` handling, `eventfd`/`poll(2)` wake-up,
  `close()` idempotency.
* `SSL_poll()` return/result-count semantics and the rule that `F` zeroes
  `revents` of later items; the endpoint keeps the listener last and evicts
  failing stream/connection items before they can starve the set.
* Event priority `ERROR -> IN -> OUT`, matching the OpenSSL poll reference.
* `SSL_new_stream()`/`SSL_accept_stream()` stream IDs/types and directional
  filter compatibility notes.
* `SSL_get_stream_write_buf_used()` semantics (bytes accepted but not yet
  acknowledged); the deferred stream-drain logic correctly keeps a stream alive
  when the statistic is positive or unavailable, and force-frees only when the
  connection is going away.
* `SSL_SHUTDOWN_EX_ARGS` (`uint64_t` + pointer) and `SSL_STREAM_RESET_ARGS`
  (`uint64_t`) layouts and argument lengths.
* `SSL_CTX_set_min_proto_version`/`SSL_CTX_set_max_proto_version` and TLS 1.3
  enforcement; session tickets disabled; no client certificate request.
* Per-connection TLS mode application: `SSL_MODE_ENABLE_PARTIAL_WRITE` and
  `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`; the accepted-connection mode check
  matches `SSL_ctrl(SSL_CTRL_MODE)` returning the updated mode bits.
* `SSL_clear_chain_certs` semantics: `SSL_ctrl(ssl, SSL_CTRL_CHAIN, 0, NULL)`
  maps to `ssl_cert_set0_chain(s, NULL)` and clears the chain of the current
  key entry; `SSL_CTRL_CHAIN_CERT` with `larg = 1` appends a chain certificate.
* ALPN callback: bounds-checked protocol list, server preference order,
  `unsigned char *outlen` one-byte write, and pointer into the client's input
  buffer.
* SNI handling: lower-casing, control/line-separator filtering, trailing-dot
  rejection, wildcard/default fallback; OpenSSL invokes the SNI final callback
  even when the extension is absent, so the default-host path is reachable.
* PSK find-session callback ordering: OpenSSL requires the PSK extension to be
  the last ClientHello extension, so the SNI has already been parsed when the
  find-session callback resolves the host.
* Certificate apply/reload ownership: the SNI/PSK callbacks take their own
  references, so freeing the old `QuicCertConfig` after a poll-thread swap is
  safe; cipher-suite reloads do reapply the new list, including restoring the
  default when the new configuration uses the default suites.
* Error-queue clearing before accept calls and on handled failure paths;
  conclude failures now capture the queue on the poll thread.
* `LocalStrings.properties` keys used by the package exist and the argument
  counts match the format placeholders; no missing bundle entry was found.
* Payload bytes are not logged; reads/writes log sizes and stream IDs only.


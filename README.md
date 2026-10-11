# reqtime

`httpstat` for Rust: times one HTTP(S) request and breaks it down into
DNS lookup, TCP connect, TLS handshake, server processing, and content
transfer — with an ASCII waterfall, the same idea as the classic Go
`httpstat` or `curl -w`'s timing variables. Rust has excellent HTTP
*client libraries* but no real equivalent of this specific
"one-shot, show me where the time went" diagnostic tool — and this one
needs no `libcurl` bindings, Go, or Python: DNS, TCP, and TLS timing
are all measured directly against `std::net` and `rustls`.

## Usage

```bash
reqtime https://github.com
reqtime github.com                    # missing scheme defaults to http://
reqtime -L http://github.com          # follow redirects, one waterfall per hop
reqtime -v https://api.example.com/x  # also print response headers
reqtime --width 60 https://example.com
```

```
$ reqtime https://github.com
200 OK (https://github.com/)
  connected to [64:ff9b::14cf:4952]:443
  574659 byte(s) body

  DNS Lookup         [██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  39.1ms
  TCP Connect        [░░███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  57.5ms
  TLS Handshake      [░░░░░███████████░░░░░░░░░░░░░░░░░░░░░░░░]  222.2ms
  Server Processing  [░░░░░░░░░░░░░░░░██████░░░░░░░░░░░░░░░░░░]  133.6ms
  Content Transfer   [░░░░░░░░░░░░░░░░░░░░░░██████████████████]  360.2ms
  Total               812.6ms
```

Each bar shows *when* a phase happens within the total timeline (a
waterfall), not just its own duration in isolation — durations shown
on the right are cumulative from the request's start, the same
convention `curl -w`'s `time_connect`/`time_starttransfer`/`time_total`
variables use, not deltas between phases.

## How it works

No `libcurl`, no async runtime — one blocking request, timed by hand
at each layer:

1. **DNS** (`src/resolve.rs`): `std`'s own resolver
   (`ToSocketAddrs`), timed around the call itself.
2. **TCP** (`src/connect.rs`): `TcpStream::connect_timeout`, trying
   every resolved address in turn (same fallback a browser uses for
   multi-A-record hosts).
3. **TLS** (`src/tls.rs`, `https` only): a real `rustls`
   `ClientConnection` against Mozilla's public root list
   (`webpki-roots`) — genuine certificate validation, not skipped,
   since this tool is timing a normal request rather than inspecting
   a cert. The handshake is driven directly via `complete_io()` so the
   timer stops exactly when the handshake finishes, not whenever some
   later incidental read/write happens to trigger it lazily.
4. **HTTP/1.1** (`src/httpio.rs`): a hand-written request writer and
   response reader — status line, headers, and a body reader that
   respects `Transfer-Encoding: chunked` first, then
   `Content-Length`, then falls back to read-until-close. First-byte
   (TTFB) timing is captured by a small `Read` wrapper that records
   the instant of its first non-empty `read()` call, placed *beneath*
   the buffered reader used for convenient line parsing so it's
   measuring the real first byte off the wire, not whatever a
   buffer's internal fill size happens to be.
5. **Redirects** (`src/timing.rs`): each hop is a completely fresh
   connection with its own full breakdown — real per-hop numbers, not
   one figure amortized across a whole chain.

## Status: built and verified against real internet endpoints, including two real bugs caught along the way

- **35 unit and integration tests**. Real sockets throughout, not
  mocks: `connect.rs`'s tests bind a real local listener and a real
  closed port (`127.0.0.1:1`) for the fallback/failure paths;
  `tls.rs`'s tests run a real local `rustls` server and do a genuine
  handshake three ways — trusted-and-succeeds, untrusted-and-fails,
  wrong-hostname-and-fails — the same live-handshake pattern this
  workspace's `localcert` tool established; `timing.rs`'s tests run a
  real local HTTP server for a full request/response cycle and a
  3-hop redirect chain. `httpio.rs`'s chunked/`Content-Length`/
  read-to-close body-parsing logic is tested deterministically against
  in-memory byte buffers (no socket needed for that part, since the
  interesting behavior is pure parsing).
- **Live-verified against real internet endpoints** covering every
  code path at once: a real HTTPS request to `github.com` (full
  5-phase waterfall, real TLS handshake, real ~575KB body); a real
  HTTP→HTTPS redirect chain (`http://github.com` → `https://github.com/`),
  checked both without `-L` (shows the redirect, doesn't follow) and
  with `-L` (follows, prints both hops' independent breakdowns); a
  real 404 with `-v` showing real response headers; a real
  `Transfer-Encoding: chunked` response (`httpbin.org/stream/3`)
  decoded correctly end to end; a genuinely unresolvable hostname and
  a genuinely refused connection (`127.0.0.1:1`), both failing cleanly
  with a specific message and exit code `1`, not a panic; the
  scheme-optional convenience (`reqtime github.com`) and `--width`
  both confirmed working.
- **A real bug caught by the test suite itself, not live traffic**:
  the redirect-chain integration tests were intermittently failing
  with "Connection reset by peer" — reproducible even running a
  single test in complete isolation, roughly 40% of the time. Root
  cause: the test server's one-shot `read()` call to drain each
  request didn't guarantee capturing every byte the client wrote; if
  bytes were still unread in the kernel receive buffer when the
  server closed the socket for the next hop, TCP sent a **RST**
  instead of a clean FIN, and that stale connection state then broke
  the *next* sequential connection reusing the same ephemeral port.
  (An initial theory — that this was inter-test parallelism stress —
  was tested directly with a serializing `Mutex` and **did not** fix
  it, which is what pointed at the real, sequential-within-one-test
  cause instead.) Fixed by having the test server actually drain until
  it sees the end of the request's headers, not just one arbitrary
  `read()` call; stable across 20 repeated full-suite runs afterward.
- **A real lint catch, not just a style nit**: `clippy` flagged two
  test calls doing `reader.read(&mut buf).unwrap()` without checking
  the returned byte count (`unused_io_amount`) — a real correctness
  footgun in general (`read()` is never guaranteed to fill the whole
  buffer), fixed by switching those specific calls to `read_exact`.

**Deliberate scope limits, stated plainly**: GET requests only in this
v1 — no custom method or request body support; HTTP/1.1 only (no
HTTP/2, which real `curl`/browsers negotiate via ALPN for most modern
HTTPS sites — this tool doesn't offer ALPN's `h2` and always gets
HTTP/1.1 back); no persistent-connection reuse across requests (every
hop, redirect or not, is a fresh connection, which is what makes a
clean per-hop breakdown possible but means this isn't measuring
keep-alive-warmed request latency).

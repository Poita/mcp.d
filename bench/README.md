# Streamable HTTP throughput benchmark

A minimal local throughput benchmark for the mcp.d **Streamable HTTP** client +
server. It drives a trivial `tools/call` (`add(a, b)`) in a tight loop and reports
calls/sec and mean round-trip latency, with both processes on `127.0.0.1`.

## What it measures

The handler does essentially no work (`a + b`), so the number reflects the
**transport + JSON-RPC round-trip cost**, not handler compute.

Note the transport shape: the modern Streamable HTTP client sends each POST over a
**fresh TCP connection** with `Connection: close`
(`source/mcp/client/http_transport.d`). This is deliberate — a tool handler may
open a server→client request (sampling / elicitation / roots) as an SSE event on
the POST's own response stream, which a pooled/keep-alive reader cannot deliver
promptly. So every tool call pays a full `connect → request → response → close`
cycle. This benchmark therefore measures connection-per-call throughput, which is
the real cost of a synchronous tool call today.

## Build

```bash
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"   # macOS
ulimit -n 65536
dub build -c server -b release
dub build -c client -b release
```

## Run

```bash
# Terminal 1 — start the server
./bench-server --port 8550

# Terminal 2 — synchronous baseline (one connection, calls are serial)
./bench-client --url http://127.0.0.1:8550/mcp --calls 20000 --concurrency 1

# Find max throughput — run N independent clients in parallel
./bench-client --url http://127.0.0.1:8550/mcp --calls 30000 --concurrency 16
```

Client options: `--url`, `--calls` (total timed calls), `--concurrency` (parallel
connections), `--warmup` (per-client warmup calls before timing).

## Results

Measured on an Apple-silicon laptop (macOS, loopback), release build, server and
client each a single vibe.d event-loop thread:

| Concurrency | Throughput (calls/sec) | Mean latency / connection |
| ----------: | ---------------------: | ------------------------: |
| 1           | ~5,900                 | 0.17 ms                   |
| 2           | ~9,600                 | 0.21 ms                   |
| 4           | ~12,700                | 0.31 ms                   |
| 8           | ~13,100                | 0.61 ms                   |
| 12          | ~16,500                | —                         |
| **16**      | **~17,300 (peak)**     | 1.0 ms                    |
| 32          | ~15,000                | 2.1 ms                    |

**Max throughput ≈ 17,000 synchronous tool calls/sec**, reached around
concurrency 12–16. A single synchronous caller sees ~5,900 calls/sec (~0.17 ms per
round-trip).

### Why it plateaus / chokes at high concurrency

Because each call opens and closes its own TCP connection, a sustained run mints
thousands of short-lived sockets that linger in `TIME_WAIT` (2×MSL ≈ 30 s on
macOS). Past concurrency ~16 the client exhausts the ephemeral port range
(`49152–65535`, ~16k ports) faster than sockets drain, and new `connectTCP` calls
block — throughput collapses rather than climbing. The CPU-bound ceiling (~17k/s)
is hit before that point; both server and client saturate one core.

The single biggest lever to raise this number would be HTTP keep-alive / connection
reuse for the request/response path (falling back to a dedicated connection only
when a handler actually initiates a server→client request) — but that is a transport
design change, not a benchmark tuning knob.

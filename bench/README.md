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
# Terminal 1 — start the server (single event-loop thread = one core)
./bench-server --port 8550

# Terminal 2 — synchronous baseline (one connection, calls are serial)
./bench-client --url http://127.0.0.1:8550/mcp --calls 20000 --concurrency 1

# Find max throughput — run N independent clients in parallel
./bench-client --url http://127.0.0.1:8550/mcp --calls 30000 --concurrency 16
```

Client options: `--url`, `--calls` (total timed calls), `--concurrency` (parallel
connections), `--warmup` (per-client warmup calls before timing).

Server options: `--port`, `--host`, `--threads N`. With `--threads N` the server
runs N independent event-loop threads, each with its own `McpServer` + router, all
binding the same port via `SO_REUSEPORT` so the kernel load-balances connections
across them — i.e. N cores instead of one.

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
macOS). Mid-run `netstat` shows ~16,182 `TIME_WAIT` sockets on the endpoint — the
*entire* ephemeral port range (`49152–65535`, ~16k ports). Once the pool is
exhausted, new `connectTCP` calls **block indefinitely** (there is no free local
port), so throughput collapses rather than climbing. The CPU-bound ceiling
(~17k/s) is hit before that point; both server and client saturate one core.

This also makes the loopback ephemeral pool the binding constraint for *any*
multi-process load test: all clients on `127.0.0.1` share one ~16k-port pool, and
a poisoned pool needs ~30 s to drain, so back-to-back high-rate runs must pause
between them (the scripts here drain `TIME_WAIT` before each run).

### Multi-threaded server (`--threads`)

`--threads N` was added to test multi-core scaling, but on a single loopback host
the offered load is hard to push past one server core: each single-threaded client
process maxes ~8–9k calls/sec, and the connection-per-call churn exhausts the
shared ephemeral pool before enough client processes can be added. Two parallel
clients (≈17k/sec aggregate) barely saturate one server core, so extra server
threads add little:

| Server threads | Aggregate (2 parallel clients) |
| -------------: | -----------------------------: |
| 1              | ~17,200 calls/sec              |
| 2              | ~19,000 calls/sec              |
| 4              | ~17,700 calls/sec              |

The flag is correct (N `SO_REUSEPORT` listeners, kernel-balanced); demonstrating
real multi-core scaling needs a load generator that does NOT churn a connection per
call (HTTP keep-alive) or a second host / a widened ephemeral range.

### The real fix

The single biggest lever for both throughput and the `TIME_WAIT` storm is HTTP
keep-alive / connection reuse for the request/response path — falling back to a
dedicated `Connection: close` socket only when a handler actually initiates a
server→client request (sampling / elicitation / roots). That is a transport design
change, not a benchmark tuning knob. A secondary, cheaper improvement: bound the
client `connectTCP` with a timeout so ephemeral-port exhaustion surfaces as a clear
error instead of an indefinite hang.

# Deploying an mcp.d server in a container

A worked, copy-paste reference for packaging an mcp.d server into a Docker image
and running it on a PaaS (the examples use [fly.io](https://fly.io)). The
[`Dockerfile`](Dockerfile) in this directory is a generic multi-stage build for
any mcp.d executable.

## System dependencies

mcp.d links against OpenSSL and zlib through vibe-d, and LDC has its own runtime
needs. A from-scratch image (e.g. `ubuntu:24.04`) must install:

| Package | Stage | Why |
|---|---|---|
| `build-essential` | build | gcc **and `libc6-dev`** — the linker needs libc's `rt`/`dl`/`pthread`/`m` stubs. Bare `gcc` under `--no-install-recommends` omits them. |
| `libssl-dev` | build | OpenSSL headers for `vibe-d:tls` (HTTPS transport, OAuth 2.1, webhook delivery). |
| `zlib1g-dev` | build | vibe-d links zlib. |
| `libxml2` | build | LDC runtime dependency — `ldc2` won't start without it. |
| `pkg-config` | build | lets dub locate OpenSSL. |
| `curl xz-utils gnupg` | build | for the official D install script. |
| `git ca-certificates` | build | to fetch git/registry dub dependencies over TLS. |
| `libssl3` | runtime | TLS at run time (inbound HTTPS + outbound calls). |
| `ca-certificates` | runtime | verify TLS peers. |

(On a developer machine `dub build` "just works" because these are already
present; a minimal container is where the full list bites.)

## Toolchain: install LDC from the official releases

Pin LDC via [`dlang.org/install.sh`](https://dlang.org/install.sh), which pulls
from the official [ldc-developers](https://github.com/ldc-developers/ldc)
releases:

```dockerfile
ARG LDC_VERSION=1.41.0
RUN curl -fsS https://dlang.org/install.sh | bash -s ldc-${LDC_VERSION} -p /opt/dlang
ENV PATH="/opt/dlang/ldc-${LDC_VERSION}/bin:${PATH}"
ENV DC=ldc2
```

Two things that will otherwise cost you a build cycle each:

- **Match the SDK's compiler.** Pin to the version CI builds with (`ldc-latest`),
  and at minimum the floor declared in this repo's `dub.json`
  `toolchainRequirements`. Too old an LDC fails with a confusing frontend error
  deep in the SDK, not a clear "compiler too old" message.
- **`ENV DC=ldc2`.** Some dub dependencies (e.g. `openssl`) reference `$DC` in
  their build commands and fail with `Invalid variable: DC` without it.

> **Why not a prebuilt D image?** The community `dlang2/*` images
> (`dlang2/ldc-ubuntu`, …) are built from
> [wilzbach/dlang-docker](https://github.com/wilzbach/dlang-docker) and **stopped
> publishing in mid-2021** when their CI pipeline broke — `:latest` still ships
> LDC 1.26, well below what this SDK needs. Installing from `install.sh` tracks
> the real LDC releases and never goes stale.

## Build

Commit `dub.selections.json` for reproducible dependency versions, then:

```bash
docker build --build-arg APP=<your dub targetName> -t my-server .
```

`APP` is the executable `dub build` produces (your `dub.json` `targetName`). The
[`Dockerfile`](Dockerfile) copies that binary into a slim runtime image.

## Server-side requirements

For the container to be reachable on a PaaS, the server must:

1. **Listen on `0.0.0.0:$PORT`.** fly.io (and most platforms) inject `$PORT`.

   ```d
   import mcp.transport.streamable_http : runStreamableHttp, StreamableHttpOptions;
   StreamableHttpOptions o;
   o.port = environment.get("PORT", "8080").to!ushort;
   o.bindAddresses = ["0.0.0.0"];
   ```

2. **Allow the public Host header.** The Streamable HTTP transport's
   DNS-rebinding guard rejects any `Host` that isn't localhost — a public request
   gets `403 Forbidden: Host not allowed`. Add your deployment hostname:

   ```d
   o.allowedHosts = ["my-app.fly.dev"];   // e.g. from an ALLOWED_HOSTS env var
   ```

   (Leave the guard on and allow-list the host; only disable
   `validateOrigin` if you front the server with a trusted proxy.)

## fly.io

A minimal `fly.toml`. The key choice is **keeping a machine running**: if your
server holds long-lived state or connections (e.g. an in-memory subscription
store, or a feed it relays), it must not be auto-stopped when idle of inbound
HTTP.

```toml
app = "my-app"
primary_region = "iad"

[build]
  dockerfile = "deploy/Dockerfile"

[env]
  PORT = "8080"
  ALLOWED_HOSTS = "my-app.fly.dev"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "off"
  auto_start_machines = false
  min_machines_running = 1

[[vm]]
  size = "shared-cpu-1x"
  memory = "512mb"
```

The `[build]` section can't pass `--build-arg`, so either bake `APP` as a default
in your copy of the Dockerfile or drop the `ARG APP` indirection and hard-code the
binary name.

```bash
fly launch --no-deploy   # choose a unique app name; keep this fly.toml/Dockerfile
fly deploy
```

**Cost note:** a single always-on `shared-cpu-1x`/512 MB machine is roughly
$3/month. Inbound bandwidth is free, so relaying even a high-volume upstream feed
adds nothing; you only pay egress on what your server sends out.

**If `fly deploy` stalls** on the remote builder, build and push the image
yourself and release by reference:

```bash
docker build --build-arg APP=<app> --platform linux/amd64 -t registry.fly.io/<app>:v1 .
TOKEN=$(fly tokens create deploy -a <app>)
echo "$TOKEN" | docker login registry.fly.io -u x --password-stdin
docker push registry.fly.io/<app>:v1
fly deploy --image registry.fly.io/<app>:v1 -a <app> -t "$TOKEN"
```

# Reference multi-stage Dockerfile for an mcp.d server.
#
# Copy this into your project, set the APP build-arg to your dub `targetName`,
# and `docker build --build-arg APP=<your-app> -t my-server .`
#
# Why install the toolchain from scratch instead of a prebuilt D image: the
# community `dlang2/*` Docker images stopped publishing in 2021 (their CI
# pipeline broke) and ship an LDC far older than this SDK needs. Installing LDC
# from the official ldc-developers releases via dlang.org/install.sh always
# tracks a current compiler. See deploy/README.md for the full rationale.

# ---- build stage ---------------------------------------------------------
FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive

# Build + link dependencies for an mcp.d binary. Each is load-bearing:
#   build-essential   gcc + libc6-dev — the linker needs libc's rt/dl/pthread/m
#                     stubs; bare `gcc` under --no-install-recommends omits them.
#   libssl-dev        OpenSSL, for vibe-d:tls (HTTPS transport, OAuth 2.1, and
#                     outbound webhook delivery).
#   zlib1g-dev        vibe-d links zlib.
#   libxml2           an LDC runtime dependency (ldc2 won't start without it).
#   pkg-config        lets dub locate OpenSSL.
#   curl xz-utils gnupg   for the official dlang.org install script.
#   git ca-certificates   to fetch git/registry dub dependencies over TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev zlib1g-dev libxml2 pkg-config \
    curl xz-utils gnupg git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pin LDC to a version this SDK compiles on. Match the SDK's CI compiler
# (ldc-latest) — and at minimum the floor in the SDK's dub.json
# `toolchainRequirements`. Too old an LDC fails with confusing frontend errors
# rather than a clear "compiler too old" message.
ARG LDC_VERSION=1.41.0
RUN curl -fsS https://dlang.org/install.sh | bash -s ldc-${LDC_VERSION} -p /opt/dlang
ENV PATH="/opt/dlang/ldc-${LDC_VERSION}/bin:${PATH}"
# Some dub packages (e.g. openssl) reference $DC in their build commands.
ENV DC=ldc2

WORKDIR /src
# Copy the manifest first for layer caching. Commit dub.selections.json for
# reproducible dependency versions (remove it from this line if you don't have
# one).
COPY dub.json dub.selections.json ./
COPY source ./source

# Your dub `targetName` — the executable `dub build` produces. Required.
ARG APP
RUN test -n "$APP" || { echo "ERROR: pass --build-arg APP=<your dub targetName>"; exit 1; }
RUN dub build --build=release --compiler=ldc2 && cp "./${APP}" /out

# ---- runtime stage -------------------------------------------------------
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# Runtime libs: libssl3 for TLS (inbound HTTPS + outbound calls),
# ca-certificates to verify peers. (libxml2/zlib are only needed at build time.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out /usr/local/bin/app

# Listen on 0.0.0.0:$PORT in your server — most PaaS (incl. fly.io) set $PORT.
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/app"]

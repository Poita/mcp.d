# examples/auth — Authorization (OAuth 2.1)

A self-contained example of an **MCP server protected as an OAuth 2.1 Resource
Server** over Streamable HTTP, plus a client that authenticates with a bearer
token and **doubles as an end-to-end regression test**.

It is its own dub package with a path dependency on the root `mcp` SDK; it does
not modify the root `dub.json`.

## Transport: HTTP only (and why)

This example is **HTTP only** — there is no stdio mode. OAuth 2.1
resource-server protection is inherently an HTTP concern: the `401` +
`WWW-Authenticate` challenge, the RFC 9728 Protected Resource Metadata document
served at a well-known URL, and RFC 8707 audience binding all live in the HTTP
layer. A stdio variant would have nothing to demonstrate. The server therefore
parses its `--port` / `--host` surface with the scaffold's HTTP-only
`parseHttpServerArgs` and always serves over `runStreamableHttp`; the client
connects with `--url`.

## What it teaches

The single server-side auth entry point is **`jwtVerifier`**, plugged into
`ResourceServerConfig.validator`. From there the Streamable HTTP transport does
everything else automatically:

- **401 + `WWW-Authenticate`** when no/invalid token is presented — the
  challenge carries `resource_metadata="…"` and a `scope="mcp:read"` hint
  (RFC 6750 §3, RFC 9728 §5.1).
- **Protected Resource Metadata** served at
  `/.well-known/oauth-protected-resource` (RFC 9728) advertising `resource`,
  `authorization_servers`, and `scopes_supported`.
- **RFC 8707 audience binding** — a token whose `aud` does not name this server
  is rejected (`401 invalid_token`).
- **Server-wide scope enforcement** — a request whose token lacks the required
  `mcp:read` scope gets `403 insufficient_scope`.
- **`RequestContext.auth`** — the validated `TokenInfo` (subject, scopes,
  audience, claims) is handed to tool handlers, which the `whoami` tool reports
  and the `secret_note` tool uses for a **finer-grained per-tool `mcp:write`
  check**.

### Typed APIs

The tools are declared in the ergonomic **UDA style** (`@tool` methods on an
`AuthApi` class, registered in one call via `registerHandlers`) and lean on the
SDK's typed APIs rather than hand-built `Json`:

- **`whoami` returns a typed `WhoamiResult` struct.** The reflection layer
  derives the tool's output schema (via `jsonSchemaOf`) and fills in the
  `structuredContent` of the result automatically — the handler never touches
  `Json`. On the client side the result is decoded straight back into a typed
  struct with **`CallToolResult.structuredContentAs!WhoamiResult`** (SDK #464),
  so the assertions read real `.subject` / `.scopes` fields instead of poking at
  raw `structuredContent["..."]` Json.
- **`secret_note` returns a `CallToolResult`** because it must set `isError` on
  the per-tool scope-denied path; its content is built with the typed
  `Content.makeText` helper.

### High-level OAuth client surface

The client also demonstrates the SDK's real OAuth consumer API (SDK #471)
alongside the low-level wire checks:

- **`OAuthClient.probeUnauthorized(endpoint)`** POSTs an unauthenticated
  `initialize` and returns the `WWW-Authenticate` header.
- **`parseWwwAuthenticate(header)`** turns that header into a typed
  `WwwAuthenticate{scheme, resourceMetadata, scope_}`.
- **`OAuthClient.discoverProtectedResource(endpoint, header)`** follows the
  challenge's `resource_metadata` URL (or the RFC 9728 well-known fallbacks) and
  returns a typed `ProtectedResourceMetadata{resource, authorizationServers,
  scopesSupported}`.

Each high-level pass is paired with a low-level pass that asserts the exact wire
shape (raw 401 header substrings, raw PRM JSON), so the example pins both the
ergonomic API and the protocol bytes.

### Tokens / keys

In production the verifier fetches the authorization server's keys from a JWKS
endpoint (`JwtVerifierConfig.jwksUri`). To keep this example offline, the
server **pins the AS public key** (`staticPublicKeysPem`) and the client stands
in for the authorization server with the matching private key.

For the happy path the client drives the SDK's real **token-acquisition
surface** (#504): it stands up a tiny in-process AS **token endpoint** that
mints the ES256 JWT, then calls **`OAuthClient.clientCredentials`** against it —
the cleanest automated grant — and feeds the returned `TokenSet.accessToken` to
`setBearerToken`, instead of ONLY hand-minting the JWT inline. The discovery and
wire-shape assertions are kept. The negative-path tokens (read-only,
wrong-audience, missing-scope) are still hand-minted directly, since each needs
a bespoke claim set. The keypair here is a throwaway used only for this demo;
never ship a private key in a real client.

## Scaffold (examples/common)

The client uses the shared **`examples_common`** scaffold (#505): `runClient`
drives the vibe event loop and maps a thrown assertion to a non-zero exit,
`check` / `checkEq` are the assertion primitives, and `connectFromArgs` selects
the HTTP transport from `--url`. On the server side the scaffold's HTTP-only
`parseHttpServerArgs` parses `--port` / `--host` (folding the host into
`StreamableHttpOptions.bindAddresses`) and hands back the resolved host/port so
`main` can derive the RFC 8707 resource audience from the actual socket; `main`
then sets `StreamableHttpOptions.auth` and calls `runStreamableHttp(server,
port, opts)` directly. There is deliberately no stdio fallback: an OAuth
resource server must never silently degrade to an unauthenticated transport.

## Run it (two terminals / CI two-step)

```sh
dub build -c server
dub build -c client

# terminal 1 — start the protected server
./auth-server --port 8742

# terminal 2 — run the client e2e against it
./auth-client --url http://127.0.0.1:8742/mcp ; echo "exit=$?"
```

(`--port` / `--host` on the client are a convenience to build the default URL
`http://127.0.0.1:8742/mcp`; prefer `--url` to point at any endpoint.)

The client prints `OK: …` and exits `0` when every assertion passes; on any
mismatch it prints what differed and exits non-zero. This is exactly how CI runs
it: start `server.d` in the background, then run `client.d` and check the exit
code.

## What the client asserts

1. **First contact (no token)** → HTTP `401` with a `Bearer` challenge carrying
   `resource_metadata` and `scope="mcp:read"`. Verified twice: once through the
   high-level `OAuthClient.probeUnauthorized` + `parseWwwAuthenticate` typed
   surface, and once against the raw header substrings.
2. **PRM document** → `resource`, `authorization_servers`, `scopes_supported`
   match what the server configured. Verified through the typed
   `OAuthClient.discoverProtectedResource` API and against the raw well-known
   JSON.
3. **Full-scope token** (`mcp:read mcp:write`), **acquired via the SDK OAuth
   client-credentials surface** (`OAuthClient.clientCredentials`, #504) →
   `initialize` succeeds, `tools/list` contains `whoami` + `secret_note`,
   `whoami` reports the token subject (`user-42`) and granted scopes, decoded
   with `structuredContentAs!WhoamiResult`, and `secret_note` returns the
   privileged payload.
4. **Read-only token** (`mcp:read`) → `whoami` still works (subject `reader`),
   but `secret_note` returns an `isError` tool result naming the missing
   `mcp:write` scope.
5. **Wrong audience** (RFC 8707) → a token issued for another resource is
   rejected.
6. **Missing required scope** → a token without `mcp:read` gets HTTP `403`
   `insufficient_scope`.

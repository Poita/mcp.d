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
stays on `runStreamableHttp`; its getopt surface is just `--port` / `--host`,
and the client connects with `--url`.

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
  `Json`. The client asserts the inferred `structuredContent.subject` /
  `.scopes`.
- **`secret_note` returns a `CallToolResult`** because it must set `isError` on
  the per-tool scope-denied path; its content is built with the typed
  `Content.makeText` helper.

### Tokens / keys

In production the verifier fetches the authorization server's keys from a JWKS
endpoint (`JwtVerifierConfig.jwksUri`). To keep this example offline, the
server **pins the AS public key** (`staticPublicKeysPem`) and the client mints
its own ES256 JWTs with the matching private key — standing in for the AS. The
keypair here is a throwaway used only for this demo; never ship a private key in
a real client.

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
   `resource_metadata` and `scope="mcp:read"`.
2. **PRM document** → `resource`, `authorization_servers`, `scopes_supported`
   match what the server configured.
3. **Full-scope token** (`mcp:read mcp:write`) → `initialize` succeeds,
   `tools/list` contains `whoami` + `secret_note`, `whoami` reports the token
   subject (`user-42`) and granted scopes in its **typed `structuredContent`**
   (inferred from the server's `WhoamiResult` struct), and `secret_note`
   returns the privileged payload.
4. **Read-only token** (`mcp:read`) → `whoami` still works (subject `reader`),
   but `secret_note` returns an `isError` tool result naming the missing
   `mcp:write` scope.
5. **Wrong audience** (RFC 8707) → a token issued for another resource is
   rejected.
6. **Missing required scope** → a token without `mcp:read` gets HTTP `403`
   `insufficient_scope`.

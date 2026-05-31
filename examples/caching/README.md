# Caching (`CacheableResult`) example

A focused, self-contained example showing the draft MCP **`CacheableResult`**
freshness hints (`ttlMs` / `cacheScope`) from *both* sides — a server that
attaches them and a client that reads them — over the **Streamable HTTP**
transport.

It is its own dub package (depends on the root `mcp` via a path dependency) and
does **not** modify the root `dub.json`.

## What it teaches

Cache hints let a server tell clients and intermediaries how long a result may
be reused and by whom (`public` shared cache vs `private` per-client cache).
They are **draft-only** (protocol `2026-07-28`): the server only emits the
fields when the negotiated protocol is the stateless draft.

- **Per-resource hint** — `server.d` passes a `CacheHint` as the optional third
  argument of `registerResource(descriptor, reader, cacheHint)`. It rides on
  that resource's `resources/read` result.
  ```d
  server.registerResource(config, &readConfig,
      nullable(CacheHint(60_000, CacheScope.private_)));
  ```
- **Per-list hint** — `server.d` calls
  `server.setListCacheHint("resources/list", CacheHint(5_000, CacheScope.public_))`.
  It rides on the `resources/list` result. (Valid list methods: `tools/list`,
  `resources/list`, `resources/templates/list`, `prompts/list`.)
- **Consumer's-eye view** — `client.d` enables draft mode
  (`client.enableDraft()`), then reads `list.cache.ttlMs` / `cacheScope` and
  `readResource(uri).cache.ttlMs` / `cacheScope`.

A third resource (`status://live`) is registered with **no** hint, and the
client asserts that its read carries **no** cache hint — proving the absence is
reported faithfully.

## Self-verifying e2e test

`client.d` is also an end-to-end regression test. It asserts the concrete
values that `server.d` set:

| Surface                       | `ttlMs` | `cacheScope` |
| ----------------------------- | ------- | ------------ |
| `resources/list`              | 5000    | `public`     |
| `resources/read config://app` | 60000   | `private`    |
| `resources/read status://live`| (none)  | (none)       |

On success it prints `OK: ...` and exits `0`; on any mismatch it prints what
differed and exits non-zero.

## Running it

This is an HTTP example, so it runs in two steps (two terminals, or background
the server). Start the server, then run the client against it:

```sh
# terminal 1 — start the server (serves http://127.0.0.1:8531/mcp)
dub run -c server

# terminal 2 — run the self-verifying client
dub run -c client
echo "exit code: $?"   # 0 = all assertions passed
```

One-shot equivalent (what CI does):

```sh
dub build -c server && dub build -c client
./caching-server &        # background the server
SERVER_PID=$!
sleep 2
./caching-client          # exits 0 on success, non-zero on any mismatch
RESULT=$?
kill $SERVER_PID
exit $RESULT
```

The server port can be changed with `--port`; point the client at it with
`--url http://127.0.0.1:<port>/mcp`.

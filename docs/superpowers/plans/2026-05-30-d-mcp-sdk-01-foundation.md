# dlang-mcp-sdk — Plan 1: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the project scaffold and the protocol bedrock — version negotiation, JSON-RPC 2.0 framing, and typed errors — all under TDD.

**Architecture:** A `dub` library named `mcp` built on vibe-d. JSON is represented with `vibe.data.json.Json` everywhere for seamless transport/HTTP interop. This plan delivers three leaf modules with zero transport/HTTP dependencies, so they compile and test fast: `mcp.protocol.versions`, `mcp.protocol.errors`, `mcp.protocol.jsonrpc`.

**Tech Stack:** D (ldc2 1.41+), dub 1.40+, vibe-d (`vibe-d:data`, `vibe-d:http`), native `unittest` blocks via `dub test`.

**Plan series:** This is Plan 1 of a multi-plan build (see `docs/superpowers/specs/2026-05-30-d-mcp-sdk-design.md`, "Build sequence"). Subsequent plans (types/capabilities, server core + tools, resources/prompts/etc., transports, client, server→client features, UDA layer, auth, conformance) are written just-in-time before their execution so their code reflects what actually compiled here.

**Conventions for every task:** Run `ulimit -n 65536` before any `dub` command (ghostty's default unlimited breaks dub). Put each test in its own `unittest` block. Commit after each green task.

---

### Task 1: Project scaffold (dub, git ignores, tooling configs)

**Files:**
- Create: `dub.json`
- Create: `.gitignore`
- Create: `dfmt.json`
- Create: `dscanner.ini`
- Create: `source/mcp/package.d`
- Create: `LICENSE`

- [ ] **Step 1: Write `dub.json`**

```json
{
	"name": "mcp",
	"description": "Production-grade Model Context Protocol SDK for D",
	"license": "MIT",
	"authors": ["Peter Alexander"],
	"targetType": "library",
	"dependencies": {
		"vibe-d:data": "~>0.9.8",
		"vibe-d:http": "~>0.9.8"
	},
	"configurations": [
		{
			"name": "library",
			"targetType": "library"
		},
		{
			"name": "unittest",
			"targetType": "executable"
		}
	]
}
```

- [ ] **Step 2: Write `.gitignore`**

```
.dub/
docs/superpowers/plans/*.html
*.o
*.obj
*.a
*.lib
mcp
mcp-test-library
__test__*__
dub.selections.json
conformance-results/
```

- [ ] **Step 3: Write `dfmt.json`**

```json
{
	"dfmt_brace_style": "allman",
	"dfmt_indent_style": "tab",
	"end_of_line": "lf",
	"max_line_length": 100,
	"dfmt_soft_max_line_length": 90,
	"dfmt_split_operator_at_line_end": false
}
```

- [ ] **Step 4: Write `dscanner.ini`** (relaxed defaults; we lint style, not block on every hint)

```ini
[analysis.config.StaticAnalysisConfig]
style_check="enabled"
enum_array_literal_check="enabled"
exception_check="enabled"
delete_check="enabled"
float_operator_check="enabled"
number_style_check="enabled"
object_const_check="enabled"
backwards_range_check="enabled"
if_else_same_check="enabled"
constructor_check="enabled"
unused_variable_check="enabled"
unused_label_check="enabled"
undocumented_declaration_check="disabled"
```

- [ ] **Step 5: Write `source/mcp/package.d`** (public re-export hub; grows over the series)

```d
/**
 * mcp — a production-grade Model Context Protocol SDK for D.
 *
 * Public entry point. Importing `mcp` re-exports the stable public API.
 */
module mcp;

public import mcp.protocol.versions;
public import mcp.protocol.errors;
public import mcp.protocol.jsonrpc;
```

- [ ] **Step 6: Write `LICENSE`** (MIT, holder "Peter Alexander", year 2026)

Create a standard MIT license text with copyright line `Copyright (c) 2026 Peter Alexander`.

- [ ] **Step 7: Verify it builds**

Run: `ulimit -n 65536 && dub build 2>&1 | tail -20`
Expected: builds with no errors (an empty library links cleanly). vibe-d fetches on first run.

- [ ] **Step 8: Commit**

```bash
git add dub.json .gitignore dfmt.json dscanner.ini source/mcp/package.d LICENSE
git commit -m "feat: project scaffold (dub, vibe-d deps, tooling configs)"
```

---

### Task 2: Protocol versions + negotiation

**Files:**
- Create: `source/mcp/protocol/versions.d`

The MCP `protocolVersion` is a date string. Supported, oldest→newest: `2024-11-05`,
`2025-03-26`, `2025-06-18`, `2025-11-25`, plus `draft`. Negotiation rule (per spec): the
server responds with the client's requested version if it supports it; otherwise it
responds with its own latest supported version and the client decides whether to proceed.

- [ ] **Step 1: Write the failing tests**

Append to `source/mcp/protocol/versions.d`:

```d
module mcp.protocol.versions;

@safe:

/// A supported MCP protocol version, ordered oldest to newest.
enum ProtocolVersion
{
	v2024_11_05,
	v2025_03_26,
	v2025_06_18,
	v2025_11_25,
	draft
}

/// The newest stable (non-draft) version this SDK speaks.
enum ProtocolVersion latestStable = ProtocolVersion.v2025_11_25;

/// All versions this SDK can speak, oldest to newest (draft last).
immutable ProtocolVersion[] supportedVersions = [
	ProtocolVersion.v2024_11_05,
	ProtocolVersion.v2025_03_26,
	ProtocolVersion.v2025_06_18,
	ProtocolVersion.v2025_11_25,
	ProtocolVersion.draft
];

unittest // wire string round-trips for every version
{
	import std.exception : assertThrown;

	assert(ProtocolVersion.v2024_11_05.toWire == "2024-11-05");
	assert(ProtocolVersion.draft.toWire == "draft");
	assert("2025-06-18".parseVersion == ProtocolVersion.v2025_06_18);
	assert("draft".parseVersion == ProtocolVersion.draft);
	assertThrown("1999-01-01".parseVersion);
}

unittest // tryParseVersion does not throw on unknown
{
	ProtocolVersion v;
	assert("2025-03-26".tryParseVersion(v));
	assert(v == ProtocolVersion.v2025_03_26);
	assert(!"nope".tryParseVersion(v));
}

unittest // negotiation: client version supported -> echo it back
{
	assert(negotiate("2025-06-18") == ProtocolVersion.v2025_06_18);
}

unittest // negotiation: client version unknown/newer -> fall back to latest stable
{
	assert(negotiate("2099-01-01") == latestStable);
	assert(negotiate("garbage") == latestStable);
}

unittest // feature gating: elicitation introduced in 2025-06-18
{
	assert(!ProtocolVersion.v2025_03_26.supportsElicitation);
	assert(ProtocolVersion.v2025_06_18.supportsElicitation);
	assert(ProtocolVersion.draft.supportsElicitation);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ulimit -n 65536 && dub test 2>&1 | tail -25`
Expected: FAIL — `toWire`, `parseVersion`, `tryParseVersion`, `negotiate`, `supportsElicitation` are undefined.

- [ ] **Step 3: Implement the functions**

Add below the declarations in `source/mcp/protocol/versions.d`:

```d
/// Convert a version to its on-the-wire date string.
string toWire(ProtocolVersion v) pure nothrow
{
	final switch (v)
	{
	case ProtocolVersion.v2024_11_05:
		return "2024-11-05";
	case ProtocolVersion.v2025_03_26:
		return "2025-03-26";
	case ProtocolVersion.v2025_06_18:
		return "2025-06-18";
	case ProtocolVersion.v2025_11_25:
		return "2025-11-25";
	case ProtocolVersion.draft:
		return "draft";
	}
}

/// Parse a wire string into a ProtocolVersion, or throw if unknown.
ProtocolVersion parseVersion(string s) pure
{
	ProtocolVersion v;
	if (!tryParseVersion(s, v))
		throw new Exception("Unknown MCP protocol version: " ~ s);
	return v;
}

/// Parse a wire string; returns false (without throwing) if unknown.
bool tryParseVersion(string s, out ProtocolVersion v) pure nothrow
{
	foreach (candidate; supportedVersions)
	{
		if (candidate.toWire == s)
		{
			v = candidate;
			return true;
		}
	}
	return false;
}

/// Server-side negotiation: accept the client's version if supported,
/// otherwise offer our latest stable version.
ProtocolVersion negotiate(string clientRequested) pure nothrow
{
	ProtocolVersion v;
	return tryParseVersion(clientRequested, v) ? v : latestStable;
}

/// Whether elicitation (client feature) is available at this version.
bool supportsElicitation(ProtocolVersion v) pure nothrow
{
	return v >= ProtocolVersion.v2025_06_18;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `ulimit -n 65536 && dub test 2>&1 | tail -15`
Expected: PASS — all `mcp.protocol.versions` unittests succeed.

- [ ] **Step 5: Commit**

```bash
git add source/mcp/protocol/versions.d
git commit -m "feat(protocol): version enum, wire parsing, negotiation, feature gating"
```

---

### Task 3: JSON-RPC error codes + typed exceptions

**Files:**
- Create: `source/mcp/protocol/errors.d`

- [ ] **Step 1: Write the failing tests**

Create `source/mcp/protocol/errors.d`:

```d
module mcp.protocol.errors;

import vibe.data.json : Json;

@safe:

/// Standard JSON-RPC 2.0 + MCP error codes.
enum ErrorCode : int
{
	parseError = -32700,
	invalidRequest = -32600,
	methodNotFound = -32601,
	invalidParams = -32602,
	internalError = -32603,
	// MCP-specific
	resourceNotFound = -32002,
	requestCancelled = -32800
}

/// An error that maps onto a JSON-RPC error object.
class McpException : Exception
{
	int code;
	Json data; /// optional structured payload; `Json.undefined` if none

	this(int code, string message, Json data = Json.undefined,
		string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
	{
		super(message, file, line);
		this.code = code;
		this.data = data;
	}
}

unittest // McpException carries code and message
{
	auto e = new McpException(ErrorCode.invalidParams, "bad arg");
	assert(e.code == -32602);
	assert(e.msg == "bad arg");
}

unittest // convenience constructors set the right code
{
	assert(methodNotFound("nope").code == ErrorCode.methodNotFound);
	assert(invalidParams("x").code == ErrorCode.invalidParams);
	assert(resourceNotFound("file:///x").code == ErrorCode.resourceNotFound);
}

unittest // toErrorJson produces a JSON-RPC error object
{
	auto e = new McpException(ErrorCode.internalError, "boom");
	auto j = e.toErrorJson();
	assert(j["code"].get!int == -32603);
	assert(j["message"].get!string == "boom");
	assert("data" !in j); // undefined data omitted
}

unittest // toErrorJson includes data when present
{
	auto e = new McpException(ErrorCode.invalidParams, "bad", Json(["field": Json("name")]));
	auto j = e.toErrorJson();
	assert(j["data"]["field"].get!string == "name");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ulimit -n 65536 && dub test 2>&1 | tail -25`
Expected: FAIL — `methodNotFound`, `invalidParams`, `resourceNotFound`, `toErrorJson` undefined.

- [ ] **Step 3: Implement helpers + serialization**

Append to `source/mcp/protocol/errors.d`:

```d
/// Build the JSON-RPC error object `{code, message, data?}`.
Json toErrorJson(const McpException e) @safe
{
	Json j = Json.emptyObject;
	j["code"] = e.code;
	j["message"] = e.msg;
	if (e.data.type != Json.Type.undefined)
		j["data"] = e.data;
	return j;
}

McpException parseError(string message, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.parseError, message, data);
}

McpException invalidRequest(string message, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.invalidRequest, message, data);
}

McpException methodNotFound(string method, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.methodNotFound, "Method not found: " ~ method, data);
}

McpException invalidParams(string message, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.invalidParams, message, data);
}

McpException internalError(string message, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.internalError, message, data);
}

McpException resourceNotFound(string uri, Json data = Json.undefined) @safe pure nothrow
{
	return new McpException(ErrorCode.resourceNotFound, "Resource not found: " ~ uri, data);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `ulimit -n 65536 && dub test 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add source/mcp/protocol/errors.d
git commit -m "feat(protocol): JSON-RPC/MCP error codes and typed exceptions"
```

---

### Task 4: JSON-RPC 2.0 message framing + batching

**Files:**
- Create: `source/mcp/protocol/jsonrpc.d`

JSON-RPC 2.0: a message is a Request (has `id` + `method`), a Notification (has `method`,
no `id`), or a Response (has `id` + either `result` or `error`). The `id` may be a string
or integer. A batch is a JSON array of messages. We model a message as a parsed `Json`
plus classification helpers, and provide builders for outgoing messages.

- [ ] **Step 1: Write the failing tests**

Create `source/mcp/protocol/jsonrpc.d`:

```d
module mcp.protocol.jsonrpc;

import vibe.data.json : Json, parseJsonString;
import mcp.protocol.errors;

@safe:

unittest // classify a request
{
	auto m = parseMessage(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
	assert(m.kind == MessageKind.request);
	assert(m.method == "ping");
	assert(m.id == Json(1));
}

unittest // classify a notification (no id)
{
	auto m = parseMessage(`{"jsonrpc":"2.0","method":"notifications/initialized"}`);
	assert(m.kind == MessageKind.notification);
	assert(m.method == "notifications/initialized");
}

unittest // classify a success response
{
	auto m = parseMessage(`{"jsonrpc":"2.0","id":"abc","result":{"ok":true}}`);
	assert(m.kind == MessageKind.response);
	assert(m.id == Json("abc"));
	assert(m.result["ok"].get!bool);
}

unittest // classify an error response
{
	auto m = parseMessage(`{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"x"}}`);
	assert(m.kind == MessageKind.errorResponse);
	assert(m.error["code"].get!int == -32601);
}

unittest // reject wrong jsonrpc version
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{"jsonrpc":"1.0","id":1,"method":"x"}`));
}

unittest // reject malformed json with a parse error
{
	import std.exception : assertThrown;

	assertThrown!McpException(parseMessage(`{not json`));
}

unittest // builders produce spec-shaped objects
{
	auto req = makeRequest(Json(7), "tools/list", Json(["cursor": Json("c1")]));
	assert(req["jsonrpc"].get!string == "2.0");
	assert(req["id"].get!int == 7);
	assert(req["method"].get!string == "tools/list");
	assert(req["params"]["cursor"].get!string == "c1");

	auto note = makeNotification("notifications/cancelled", Json(["requestId": Json(7)]));
	assert("id" !in note);
	assert(note["method"].get!string == "notifications/cancelled");

	auto ok = makeResponse(Json(7), Json(["tools": Json.emptyArray]));
	assert(ok["result"]["tools"].length == 0);

	auto err = makeErrorResponse(Json(7), new McpException(ErrorCode.methodNotFound, "no"));
	assert(err["error"]["code"].get!int == -32601);
	assert("result" !in err);
}

unittest // batch parsing: array of messages
{
	auto batch = parseBatch(`[{"jsonrpc":"2.0","id":1,"method":"ping"},
		{"jsonrpc":"2.0","method":"notifications/initialized"}]`);
	assert(batch.length == 2);
	assert(batch[0].kind == MessageKind.request);
	assert(batch[1].kind == MessageKind.notification);
}

unittest // parseAny distinguishes single vs batch
{
	auto single = parseAny(`{"jsonrpc":"2.0","id":1,"method":"ping"}`);
	assert(!single.isBatch && single.messages.length == 1);

	auto many = parseAny(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`);
	assert(many.isBatch && many.messages.length == 1);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `ulimit -n 65536 && dub test 2>&1 | tail -25`
Expected: FAIL — `parseMessage`, `MessageKind`, builders, `parseBatch`, `parseAny` undefined.

- [ ] **Step 3: Implement framing + builders**

Append to `source/mcp/protocol/jsonrpc.d`:

```d
/// What a JSON-RPC message represents.
enum MessageKind
{
	request,
	notification,
	response,
	errorResponse
}

/// A classified JSON-RPC message wrapping its raw Json.
struct Message
{
	Json raw;

	MessageKind kind() const @safe
	{
		const hasId = "id" in raw && raw["id"].type != Json.Type.undefined
			&& raw["id"].type != Json.Type.null_;
		const hasMethod = "method" in raw;
		if (hasMethod)
			return hasId ? MessageKind.request : MessageKind.notification;
		if ("error" in raw)
			return MessageKind.errorResponse;
		return MessageKind.response;
	}

	string method() const @safe
	{
		return ("method" in raw) ? raw["method"].get!string : null;
	}

	Json id() const @safe
	{
		return ("id" in raw) ? raw["id"] : Json(null);
	}

	Json params() const @safe
	{
		return ("params" in raw) ? raw["params"] : Json.emptyObject;
	}

	Json result() const @safe
	{
		return ("result" in raw) ? raw["result"] : Json.undefined;
	}

	Json error() const @safe
	{
		return ("error" in raw) ? raw["error"] : Json.undefined;
	}
}

private void validateEnvelope(Json j) @safe
{
	if (j.type != Json.Type.object)
		throw invalidRequest("JSON-RPC message must be an object");
	if (("jsonrpc" !in j) || j["jsonrpc"].get!string != "2.0")
		throw invalidRequest("Missing or invalid jsonrpc version (expected \"2.0\")");
}

/// Parse and classify a single JSON-RPC message from text.
Message parseMessage(string text) @safe
{
	Json j;
	try
		j = parseJsonString(text);
	catch (Exception e)
		throw parseError("Invalid JSON: " ~ e.msg);
	validateEnvelope(j);
	return Message(j);
}

/// Parse a JSON-RPC batch (array) from text.
Message[] parseBatch(string text) @safe
{
	Json arr;
	try
		arr = parseJsonString(text);
	catch (Exception e)
		throw parseError("Invalid JSON: " ~ e.msg);
	if (arr.type != Json.Type.array)
		throw invalidRequest("Batch must be a JSON array");
	if (arr.length == 0)
		throw invalidRequest("Batch must not be empty");
	Message[] msgs;
	foreach (item; arr)
	{
		validateEnvelope(item);
		msgs ~= Message(item);
	}
	return msgs;
}

/// Result of `parseAny`: a single message or a batch, normalized to a list.
struct ParsedInput
{
	bool isBatch;
	Message[] messages;
}

/// Parse text that may be either a single message or a batch array.
ParsedInput parseAny(string text) @safe
{
	import std.string : strip, startsWith;

	if (text.strip.startsWith("["))
		return ParsedInput(true, parseBatch(text));
	return ParsedInput(false, [parseMessage(text)]);
}

/// Build a request object.
Json makeRequest(Json id, string method, Json params = Json.undefined) @safe
{
	Json j = Json.emptyObject;
	j["jsonrpc"] = "2.0";
	j["id"] = id;
	j["method"] = method;
	if (params.type != Json.Type.undefined)
		j["params"] = params;
	return j;
}

/// Build a notification object (no id).
Json makeNotification(string method, Json params = Json.undefined) @safe
{
	Json j = Json.emptyObject;
	j["jsonrpc"] = "2.0";
	j["method"] = method;
	if (params.type != Json.Type.undefined)
		j["params"] = params;
	return j;
}

/// Build a success response object.
Json makeResponse(Json id, Json result) @safe
{
	Json j = Json.emptyObject;
	j["jsonrpc"] = "2.0";
	j["id"] = id;
	j["result"] = result;
	return j;
}

/// Build an error response object from an McpException.
Json makeErrorResponse(Json id, const McpException e) @safe
{
	Json j = Json.emptyObject;
	j["jsonrpc"] = "2.0";
	j["id"] = id;
	j["error"] = toErrorJson(e);
	return j;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `ulimit -n 65536 && dub test 2>&1 | tail -15`
Expected: PASS — all jsonrpc unittests succeed.

- [ ] **Step 5: Commit**

```bash
git add source/mcp/protocol/jsonrpc.d
git commit -m "feat(protocol): JSON-RPC 2.0 framing, classification, builders, batching"
```

---

### Task 5: Format, lint, and README touch-up

**Files:**
- Modify: all `source/mcp/protocol/*.d` (formatting only)
- Modify: `README.md`

- [ ] **Step 1: Format with dfmt**

Run: `ulimit -n 65536 && dub run dfmt -- --config dfmt.json source/`
Expected: files reformatted in place (no errors).

- [ ] **Step 2: Lint with dscanner**

Run: `ulimit -n 65536 && dub run dscanner -- --styleCheck source/ 2>&1 | tail -30`
Expected: no errors (warnings acceptable; fix anything trivial like unused imports).

- [ ] **Step 3: Re-run tests after formatting**

Run: `ulimit -n 65536 && dub test 2>&1 | tail -10`
Expected: PASS (formatting must not change behavior).

- [ ] **Step 4: Update README with a build/test section**

Replace `README.md` body with a short intro plus:

````markdown
## Status

Under active development. Foundation (protocol versioning, JSON-RPC framing, errors) is in place.

## Build & test

```bash
ulimit -n 65536   # required: dub misbehaves under `ulimit -n unlimited`
dub build
dub test
```
````

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: format, lint, README build/test instructions"
```

---

## Self-Review

**Spec coverage (this plan's slice):**
- Versioning + negotiation + feature gating → Task 2. ✓
- JSON-RPC 2.0 framing + batching → Task 4. ✓
- Typed errors / error codes → Task 3. ✓
- Tooling (dub, dfmt, dscanner, vibe-d deps, MIT license) → Task 1, Task 5. ✓
- `types`, `capabilities`, transports, server, client, UDA layer, auth, conformance →
  **deferred to later plans** (by design; this is Plan 1 of N).

**Placeholder scan:** No TBD/TODO; every code step shows complete code; every run step has
an exact command and expected outcome.

**Type consistency:** `ProtocolVersion`, `McpException`, `ErrorCode`, `Message`,
`MessageKind`, and the `make*`/`parse*` free functions are referenced consistently across
tasks and re-exported from `mcp.package`. `Json` is `vibe.data.json.Json` throughout.

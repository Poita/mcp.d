/// MCP Tools example server — dual-transport (stdio + Streamable HTTP).
///
/// Demonstrates, from the server side, the `@tool` reflection surface of the D
/// MCP SDK:
///   - typed arguments: scalars, an `enum` parameter, a `Nullable!` optional,
///     and a `struct` argument (mapped into the inferred input JSON Schema);
///   - inferred output schema + `structuredContent` from a `struct` return;
///   - the behavioral marker UDAs `@readOnly` and `@destructive`
///     (plus `@idempotent`) that populate `ToolAnnotations`;
///   - `@describeParam` argument documentation;
///   - returning a typed `CallToolResult` built with the typed `Content.make*`
///     factories (`Content.makeText`, `Content.makeResourceLink`) — no
///     hand-built content Json;
///   - `registerModule` to register module-level `@tool` free functions in one
///     call (no class instance required).
///
/// The SAME binary speaks MCP over EITHER transport, selected at runtime by the
/// shared `runServerFromArgs` scaffold helper (examples/common): stdio by
/// default (the deployable shape) or Streamable HTTP under `--http` (with
/// `--port`/`--host`).
///
/// The matching `client.d` is a self-verifying e2e that drives this server over
/// BOTH transports with the same transport-agnostic assertions.
module tools_server;

import std.typecons : Nullable, nullable;

import examples_common : runServerFromArgs;

import mcp.api.attributes;
import mcp.api.reflection : registerModule;
import mcp.protocol.types : CallToolResult, Content;
import mcp.server.server : McpServer;

/// The example's default HTTP port. The client uses the same default URL, and
/// the README documents starting the server with `--http --port 8530`.
enum ushort DefaultPort = 8530;

/// An enum argument — the SDK emits a JSON Schema `enum` of its members.
enum Op
{
	add,
	sub,
	mul
}

/// A struct argument — mapped to an object sub-schema in the tool's inputSchema,
/// and (when returned) to the tool's inferred outputSchema + structuredContent.
struct Vec2
{
	double x;
	double y;
}

/// A struct return — its fields become the tool's structured output.
struct CalcResult
{
	Op op;
	double result;
}

/// A read-only tool over typed scalars, an enum, and an optional Nullable arg.
/// `@readOnly` + `@idempotent` set the corresponding `ToolAnnotations` hints.
/// Returns a struct, so the SDK infers an outputSchema and emits
/// `structuredContent`.
@tool("calc", "Apply an arithmetic operation to two numbers")
@readOnly @idempotent @hintTitle("Calculator")
@describeParam("op", "the operation to apply")
@describeParam("a", "left operand")
@describeParam("b", "right operand")
@describeParam("round", "optional rounding to N decimals")
CalcResult calc(Op op, double a, double b, Nullable!int round) @safe
{
	double r;
	final switch (op)
	{
	case Op.add:
		r = a + b;
		break;
	case Op.sub:
		r = a - b;
		break;
	case Op.mul:
		r = a * b;
		break;
	}
	if (!round.isNull)
	{
		import std.math : pow, lround;

		const factor = pow(10.0, round.get);
		r = lround(r * factor) / factor;
	}
	return CalcResult(op, r);
}

/// A tool taking a struct argument and returning a scalar. Scalar returns are
/// wrapped under a `result` key in structuredContent.
@tool("magnitude", "Euclidean length of a 2D vector")
@readOnly @describeParam("v", "the vector")
double magnitude(Vec2 v) @safe
{
	import std.math : sqrt;

	return sqrt(v.x * v.x + v.y * v.y);
}

/// A string-returning tool — produces plain text content, no structuredContent.
@tool("greet", "Greet someone by name")
@readOnly @describeParam("name", "who to greet")
string greet(string name) @safe
{
	return "Hello, " ~ name ~ "!";
}

/// A `@destructive` tool — its presence sets `destructiveHint:true`. The body is
/// a no-op stand-in for a real side effect; it just confirms the request.
@tool("erase", "Erase a record by id (destructive)")
@destructive @describeParam("id", "record id")
string erase(string id) @safe
{
	return "erased " ~ id;
}

/// A tool that returns a typed `CallToolResult` assembled with the typed
/// `Content.make*` factories — `Content.makeText` for a human-readable line and
/// `Content.makeResourceLink` for a pointer to a related resource. This shows
/// building multi-block tool content WITHOUT hand-writing any content Json.
@tool("describe_doc", "Return a text note plus a resource link for a document id")
@readOnly @describeParam("id", "document id")
CallToolResult describeDoc(string id) @safe
{
	CallToolResult r;
	r.content = [
		Content.makeText("Document " ~ id ~ " is available."),
		Content.makeResourceLink("doc://" ~ id, "Document " ~ id, "text/plain"),
	];
	return r;
}

void main(string[] args) @safe
{
	auto server = new McpServer("tools-example", "1.0.0");
	// Register every @tool free function in this module in one call.
	registerModule!(tools_server)(server);

	// The shared scaffold picks the transport from argv: stdio by default, or
	// Streamable HTTP under `--http` on `--port`/`--host` (default 8530).
	runServerFromArgs(server, args, DefaultPort);
}

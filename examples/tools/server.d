/// MCP Tools example server (#348).
///
/// Demonstrates, from the server side, the `@tool` reflection surface of the D
/// MCP SDK:
///   - typed arguments: scalars, an `enum` parameter, a `Nullable!` optional,
///     and a `struct` argument (mapped into the inferred input JSON Schema);
///   - inferred output schema + `structuredContent` from a `struct` return;
///   - the behavioral marker UDAs `@readOnly` and `@destructive`
///     (plus `@idempotent`) that populate `ToolAnnotations`;
///   - `@describe` argument documentation;
///   - `registerModule` to register module-level `@tool` free functions in one
///     call (no class instance required).
///
/// The server speaks MCP over stdio (`runStdio`), which is the deployable shape:
/// the matching `client.d` spawns this very binary and drives it end-to-end.
module tools_server;

import std.typecons : Nullable, nullable;

import mcp.api.attributes;
import mcp.api.reflection : registerModule;
import mcp.server.server : McpServer;
import mcp.transport.stdio : runStdio;

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
@readOnly
@idempotent
@hintTitle("Calculator")
CalcResult calc(
	@describe("the operation to apply") Op op,
	@describe("left operand") double a,
	@describe("right operand") double b,
	@describe("optional rounding to N decimals") Nullable!int round) @safe
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
@readOnly
double magnitude(@describe("the vector") Vec2 v) @safe
{
	import std.math : sqrt;

	return sqrt(v.x * v.x + v.y * v.y);
}

/// A string-returning tool — produces plain text content, no structuredContent.
@tool("greet", "Greet someone by name")
@readOnly
string greet(@describe("who to greet") string name) @safe
{
	return "Hello, " ~ name ~ "!";
}

/// A `@destructive` tool — its presence sets `destructiveHint:true`. The body is
/// a no-op stand-in for a real side effect; it just confirms the request.
@tool("erase", "Erase a record by id (destructive)")
@destructive
string erase(@describe("record id") string id) @safe
{
	return "erased " ~ id;
}

void main() @safe
{
	auto server = new McpServer("tools-example", "1.0.0");
	// Register every @tool free function in this module in one call.
	registerModule!(tools_server)(server);
	runStdio(server);
}

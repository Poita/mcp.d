/**
 * examples/elicitation — server.d (dual-transport, typed APIs)
 *
 * Demonstrates the SERVER side of **2025-era blocking elicitation** (issue #355)
 * written in the ergonomic UDA style: the tool is an annotated typed method on a
 * class, registered in one call with `registerHandlers`.
 *
 * The `plan_trip` tool needs more information than its single `destination`
 * argument carries, so mid-handler it opens a server->client
 * `elicitation/create` request via the BLOCKING typed `ctx.elicit!TripDetails(message)`.
 * The call BLOCKS until the client's `onElicitation` handler answers; the SDK
 * delivers the answer back as a typed `ElicitResult` (issue #436). The handler
 * branches on the user's `action` (accept / decline / cancel) and returns a
 * structured result the client can assert against.
 *
 * Typed-API adoption (closes the example half of #436/#437, plus #465):
 *   - the requestedSchema is DERIVED ENTIRELY from the flat struct `TripDetails`:
 *     the rich facets (integer bounds, field titles, the enum/boolean defaults)
 *     live as field UDAs (`@minimum`/`@maximum`/`@title`/`@schemaDefault`, #465)
 *     that `jsonSchemaOf!TripDetails` now emits, so the typed
 *     `ctx.elicit!TripDetails(message)` (#436) sends the whole SEP-1034/1330
 *     restricted schema with NO hand-built Json;
 *   - `ctx.elicit!T` returns a typed `ElicitResult`; on `accept` the collected
 *     values are decoded with `result.contentAs!TripDetails` instead of
 *     hand-reading the `content` Json;
 *   - the tool returns a `TripPlan` struct so the SDK infers the output schema
 *     and emits `structuredContent`.
 *
 * Transport selection is delegated to the shared `examples/common` scaffold's
 * `runServerFromArgs` (#505): one binary, either transport —
 *   stdio (default):  ./elicitation-server                       # JSON-RPC on stdio
 *   http:             ./elicitation-server --http --port 9355     # http://127.0.0.1:9355/mcp
 *
 * The blocking server->client elicitation completes over BOTH transports: stdio
 * answers the request inline on the same channel; the Streamable HTTP deadlock
 * was fixed in #377.
 */
module elicitation_server;

import std.conv : to;
import std.typecons : nullable;

import mcp;
import examples_common : runServerFromArgs;
import vibe.data.serialization : optional;

import mcp.api.attributes : minimum, maximum, title, schemaDefault;

/// The fixed HTTP port the example binds, kept in one place so server.d,
/// client.d (and the README) agree.
enum ushort defaultPort = 9355;

void main(string[] args) @safe
{
	// This tool calls ctx.elicit (a server->client request). Over
	// HTTP that requires a session, so the server runs in STATEFUL mode (works
	// over stdio too — single implicit session).
	auto server = McpServer.stateful("elicitation-example", "1.0.0",
			nullable("2025-era blocking elicitation demo (stdio + Streamable HTTP)."));
	// Register every @tool method on the API object in one call; each tool's
	// input schema and argument marshalling are derived from the method signature.
	registerHandlers(server, new TripApi);

	// The scaffold picks the transport from argv: `--http` (+ `--port`/`--host`)
	// serves Streamable HTTP, otherwise stdio (the default). Over stdio a tool
	// that calls ctx.elicit is answered inline on the same channel (#448/#449),
	// so the blocking round-trip completes; over HTTP the reply rides the SSE
	// channel (deadlock fixed in #377).
	runServerFromArgs(server, args, defaultPort);
}

/// The flat elicitation form the server gathers from the client. Its scalar
/// fields satisfy the elicitation schema restriction (SEP-1034/1330), and the
/// rich facets the demo wants the client to see — field titles, the `travelers`
/// integer bounds, and the `cabin`/`insurance` defaults — are declared inline as
/// field UDAs (`@title`/`@minimum`/`@maximum`/`@schemaDefault`, #465). That lets
/// `ctx.elicit!TripDetails(message)` derive the ENTIRE `requestedSchema` from
/// this one struct (object type, the `required` set, the `cabin` enum members,
/// and every facet) with no hand-built Json, and `result.contentAs!TripDetails`
/// decodes the accepted answer. The D field initializers double as the values
/// applied when the user omits an optional field.
/// Cabin class — a D `enum`, so jsonSchemaOf derives the three enum members
/// (["economy","premium","business"]) into the requestedSchema automatically.
enum Cabin
{
	economy,
	premium,
	business,
}

struct TripDetails
{
	/// required: number of travelers, with display title + integer bounds.
	@title("Number of travelers") @minimum(1) @maximum(9) int travelers;
	/// enum (members derived) + display title + an "economy" default; the field
	/// initializer keeps it out of `required` and is the applied fallback.
	@optional @title("Cabin class") @schemaDefault(Cabin.economy) Cabin cabin = Cabin.economy;
	/// boolean with a display title + a `false` default (and matching fallback).
	@optional @title("Add travel insurance") @schemaDefault(false) bool insurance = false;
}

/// The structured result `plan_trip` returns. Its fields become the tool's
/// inferred output JSON Schema + `structuredContent`, so the client can assert
/// concrete values (decoded via `result.structuredContentAs!TripPlan`).
struct TripPlan
{
	string status; /// "booked" | "declined" | "cancelled"
	string destination;
	int travelers;
	string cabin;
	bool insurance;
	string summary;
}

/// The annotated MCP tool surface for this example.
final class TripApi
{
	/// `plan_trip`: takes only a `destination`, then BLOCKS on the typed
	/// `ctx.elicit!TripDetails` to gather the remaining trip details. The whole
	/// rich requestedSchema (an integer with bounds, an enum with a default, and a
	/// boolean with a default) is derived from `TripDetails`' field UDAs — no
	/// hand-built schema Json.
	///
	/// `ctx` is auto-injected and omitted from the tool's inputSchema. The method
	/// returns a `TripPlan` struct so the SDK infers the output schema and emits
	/// `structuredContent`.
	@tool("plan_trip",
			"Plan a trip to a destination; elicits traveler count, cabin class and insurance.")
	@describe("the destination city")
	TripPlan planTrip(string destination, RequestContext ctx) @safe
	{
		// BLOCKING server->client elicitation. The requestedSchema is derived
		// wholesale from `TripDetails` (object type + required + the cabin enum
		// members + the @title/@minimum/@maximum/@schemaDefault facets), so this is
		// a single typed call with no hand-built Json. Returns once the client's
		// onElicitation answers (the round-trip fixed for HTTP in #377, and
		// inline-answered over stdio). Yields a typed `ElicitResult` (#436).
		ElicitResult result = ctx.elicit!TripDetails(
				"Please provide trip details for " ~ destination);

		final switch (result.action)
		{
		case ElicitAction.decline:
			return TripPlan("declined", destination, 0, "",
					false, "User declined to provide trip details for " ~ destination ~ ".");
		case ElicitAction.cancel:
			return TripPlan("cancelled", destination, 0,
					"", false, "Trip planning for " ~ destination ~ " was cancelled.");
		case ElicitAction.accept:
			break;
		}

		// action == accept: decode the collected values into the typed struct.
		// Fields the user omitted keep TripDetails' defaults ("economy" / false),
		// which mirror the schema defaults declared via @schemaDefault.
		TripDetails details = result.contentAs!TripDetails;
		const cabinName = details.cabin.to!string;

		const summary = "Booked " ~ destination ~ " for " ~ details.travelers.to!string
			~ " traveler(s) in " ~ cabinName ~ " class" ~ (details.insurance
					? " with insurance." : " without insurance.");
		return TripPlan("booked", destination, details.travelers, cabinName,
				details.insurance, summary);
	}
}

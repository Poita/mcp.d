/**
 * examples/elicitation — server.d (dual-transport, typed APIs)
 *
 * Demonstrates the SERVER side of **2025-era blocking elicitation** (issue #355)
 * written in the ergonomic UDA style: the tool is an annotated typed method on a
 * class, registered in one call with `registerHandlers`.
 *
 * The `plan_trip` tool needs more information than its single `destination`
 * argument carries, so mid-handler it opens a server->client
 * `elicitation/create` request via the BLOCKING `ctx.elicit(message, schema)`.
 * The call BLOCKS until the client's `onElicitation` handler answers; the SDK
 * delivers the answer back as a typed `ElicitResult` (issue #436). The handler
 * branches on the user's `action` (accept / decline / cancel) and returns a
 * structured result the client can assert against.
 *
 * Typed-API adoption (closes the example half of #436/#437):
 *   - the requestedSchema is DERIVED from the flat struct `TripDetails` via
 *     `jsonSchemaOf!TripDetails` (then enriched with the rich facets — integer
 *     bounds, an enum default, a boolean default — that `jsonSchemaOf` cannot
 *     express on its own; SEP-1034/1330 permits them);
 *   - `ctx.elicit` returns a typed `ElicitResult`; on `accept` the collected
 *     values are decoded with `result.contentAs!TripDetails` instead of
 *     hand-reading the `content` Json;
 *   - the tool returns a `TripPlan` struct so the SDK infers the output schema
 *     and emits `structuredContent`.
 *
 * Dual transport — ONE binary, either transport:
 *   stdio (default):  ./elicitation-server                       # JSON-RPC on stdio
 *   http:             ./elicitation-server --http --port 9355     # http://127.0.0.1:9355/mcp
 *
 * The blocking server->client elicitation completes over BOTH transports: stdio
 * answers the request inline on the same channel; the Streamable HTTP deadlock
 * was fixed in #377.
 */
module elicitation_server;

import std.conv : to;
import std.getopt : getopt;
import std.stdio : stderr;
import std.typecons : nullable;

import vibe.data.json : Json;
import vibe.data.serialization : optional;

import mcp;
import mcp.api.schema : jsonSchemaOf;
import mcp.transport : StreamableHttpOptions, runStreamableHttp, runStdio;

/// The fixed HTTP port the example binds, kept in one place so server.d,
/// client.d (and the README) agree.
enum ushort defaultPort = 9355;

void main(string[] args)
{
	bool http;
	ushort port = defaultPort;
	string host = "127.0.0.1";
	getopt(args, "http", "Serve over Streamable HTTP instead of stdio", &http, "port|p",
			"HTTP port to listen on (default 9355)",
			&port, "host|h", "HTTP address to bind (default 127.0.0.1)", &host);

	auto server = new McpServer("elicitation-example", "1.0.0",
			nullable("2025-era blocking elicitation demo (stdio + Streamable HTTP)."));
	// Register every @tool method on the API object in one call; each tool's
	// input schema and argument marshalling are derived from the method signature.
	registerHandlers(server, new TripApi);

	if (http)
	{
		StreamableHttpOptions opts;
		opts.bindAddresses = [host];
		() @trusted {
			stderr.writefln("elicitation-server listening on http://%s:%d/mcp", host, port);
		}();
		runStreamableHttp(server, port, opts);
	}
	else
	{
		// stdio (default): a tool that calls ctx.elicit is answered inline on the
		// same stdio channel (#448/#449), so the blocking round-trip completes.
		runStdio(server);
	}
}

/// The flat elicitation form the server gathers from the client. Its scalar
/// fields satisfy the elicitation schema restriction (SEP-1034/1330), so
/// `jsonSchemaOf!TripDetails` derives the base `requestedSchema` and
/// `ElicitResult.contentAs!TripDetails` decodes the accepted answer. The field
/// defaults double as the values applied when the user omits an optional field.
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
	int travelers; /// required: number of travelers (bounds added to the schema)
	@optional Cabin cabin = Cabin.economy; /// enum (members derived) + a default (added to the schema)
	@optional bool insurance = false; /// boolean with a default (added to the schema)
}

/// The structured result `plan_trip` returns. Its fields become the tool's
/// inferred output JSON Schema + `structuredContent`, so the client can assert
/// concrete values.
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
	/// `plan_trip`: takes only a `destination`, then BLOCKS on `ctx.elicit` to
	/// gather the remaining trip details with a rich requestedSchema (an integer
	/// with bounds, an enum with a default, and a boolean with a default).
	///
	/// `ctx` is auto-injected and omitted from the tool's inputSchema. The method
	/// returns a `TripPlan` struct so the SDK infers the output schema and emits
	/// `structuredContent`.
	@tool("plan_trip",
			"Plan a trip to a destination; elicits traveler count, cabin class and insurance.")
	@describe("the destination city")
	TripPlan planTrip(string destination, RequestContext ctx) @safe
	{
		// Start from the schema DERIVED from the TripDetails struct via
		// jsonSchemaOf (object type + required + the cabin enum members), then
		// enrich it with the rich facets jsonSchemaOf cannot express: titles,
		// integer bounds, an enum default and a boolean default (all permitted by
		// the SEP-1034/1330 restricted schema).
		Json schema = jsonSchemaOf!TripDetails;
		Json props = schema["properties"];

		props["travelers"]["title"] = "Number of travelers";
		props["travelers"]["minimum"] = 1;
		props["travelers"]["maximum"] = 9;

		props["cabin"]["title"] = "Cabin class";
		props["cabin"]["default"] = "economy";

		props["insurance"]["title"] = "Add travel insurance";
		props["insurance"]["default"] = false;

		// Only `travelers` is required; `cabin` and `insurance` are optional and
		// fall back to the defaults above when the user omits them. (jsonSchemaOf
		// cannot tell a `false` boolean default from bool.init, so set this
		// explicitly to keep the requestedSchema consistent with the demo.)
		Json required = Json.emptyArray;
		required ~= Json("travelers");
		schema["required"] = required;

		// BLOCKING server->client elicitation. Returns once the client's
		// onElicitation answers (the round-trip fixed for HTTP in #377, and
		// inline-answered over stdio). `ctx.elicit` returns a typed `ElicitResult`
		// (#436).
		ElicitResult result = ctx.elicit("Please provide trip details for " ~ destination, schema);

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
		// which mirror the schema defaults.
		TripDetails details = result.contentAs!TripDetails;
		const cabinName = details.cabin.to!string;

		const summary = "Booked " ~ destination ~ " for " ~ details.travelers.to!string
			~ " traveler(s) in " ~ cabinName ~ " class" ~ (details.insurance
					? " with insurance." : " without insurance.");
		return TripPlan("booked", destination, details.travelers, cabinName,
				details.insurance, summary);
	}
}

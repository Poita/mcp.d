/**
 * examples/elicitation — server.d
 *
 * Demonstrates the SERVER side of **2025-era blocking elicitation** (issue #355)
 * over the Streamable HTTP transport, written in the ergonomic UDA style: the
 * tool is an annotated typed method on a class, registered in one call with
 * `registerHandlers`.
 *
 * The `plan_trip` tool needs more information than its single `destination`
 * argument carries, so mid-handler it opens a server->client
 * `elicitation/create` request via the BLOCKING `ctx.elicit(message, schema)`.
 * It hands the client a rich `requestedSchema` exercising the
 * SEP-1034/1330 surface:
 *   - a `string` field (`travelers` -> actually an integer; see below),
 *   - an `integer` field with `minimum`/`maximum`,
 *   - an `enum` field (`cabin`) with a `default`, and
 *   - a `boolean` field with a `default`.
 * The call BLOCKS until the client's `onElicitation` handler answers; the SDK
 * delivers the answer back as the `ctx.elicit` return value (an `ElicitResult`
 * as JSON). The handler then branches on the user's `action`
 * (accept / decline / cancel) and returns a structured result the client can
 * assert against.
 *
 * Contrast with MRTR (examples/mrtr): MRTR is the *stateless draft* input flow
 * where the tool ENDS the call with `ToolResponse.inputRequired(...)` and the
 * client resubmits a fresh `tools/call`. Here, on the 2025 released protocol,
 * the elicitation is a genuine blocking server->client round-trip inside one
 * `tools/call` — no resubmission, no opaque `requestState`. The server->client
 * blocking deadlock over Streamable HTTP was fixed in #377, so this completes.
 *
 * Run standalone:
 *   dub build -c server
 *   ./elicitation-server --port 9355        # serves http://127.0.0.1:9355/mcp
 */
module elicitation_server;

import std.conv : to;
import std.getopt : getopt;
import std.stdio : stderr;
import std.typecons : nullable;

import vibe.data.json : Json;

import mcp;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;

/// The fixed port the example binds, kept in one place so server.d, client.d
/// (and the README) agree.
enum ushort defaultPort = 9355;

void main(string[] args)
{
	ushort port = defaultPort;
	string host = "127.0.0.1";
	getopt(args, "port|p", "Port to listen on (default 9355)", &port,
			"host|h", "Address to bind (default 127.0.0.1)", &host);

	auto server = new McpServer("elicitation-example", "1.0.0",
			nullable("2025-era blocking elicitation demo over Streamable HTTP."));
	// Register every @tool method on the API object in one call; each tool's
	// input schema and argument marshalling are derived from the method signature.
	registerHandlers(server, new TripApi);

	StreamableHttpOptions opts;
	opts.bindAddresses = [host];
	() @trusted {
		stderr.writefln("elicitation-server listening on http://%s:%d/mcp", host, port);
	}();
	runStreamableHttp(server, port, opts);
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
		// Build the restricted requestedSchema (SEP-1034/1330): only flat objects
		// of primitive fields, optionally with enum / default / min / max.
		Json schema = Json.emptyObject;
		schema["type"] = "object";

		Json props = Json.emptyObject;

		// integer field with bounds.
		Json travelers = Json.emptyObject;
		travelers["type"] = "integer";
		travelers["title"] = "Number of travelers";
		travelers["minimum"] = 1;
		travelers["maximum"] = 9;
		props["travelers"] = travelers;

		// enum field with a default.
		Json cabin = Json.emptyObject;
		cabin["type"] = "string";
		cabin["title"] = "Cabin class";
		Json cabinEnum = Json.emptyArray;
		cabinEnum ~= Json("economy");
		cabinEnum ~= Json("premium");
		cabinEnum ~= Json("business");
		cabin["enum"] = cabinEnum;
		cabin["default"] = "economy";
		props["cabin"] = cabin;

		// boolean field with a default.
		Json insurance = Json.emptyObject;
		insurance["type"] = "boolean";
		insurance["title"] = "Add travel insurance";
		insurance["default"] = false;
		props["insurance"] = insurance;

		schema["properties"] = props;

		Json required = Json.emptyArray;
		required ~= Json("travelers");
		schema["required"] = required;

		// BLOCKING server->client elicitation. Returns once the client's
		// onElicitation answers (this is the round-trip fixed for HTTP in #377).
		// `ctx.elicit` returns a typed `ElicitResult` (#436).
		auto result = ctx.elicit("Please provide trip details for " ~ destination, schema);

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

		// action == accept: read the collected values, applying the schema's
		// defaults for any optional field the user left out.
		auto content = result.content;
		int travelersN = 1;
		if (content.type == Json.Type.object && "travelers" in content)
			travelersN = content["travelers"].get!int;

		string cabinClass = "economy";
		if (content.type == Json.Type.object && "cabin" in content
				&& content["cabin"].type == Json.Type.string)
			cabinClass = content["cabin"].get!string;

		bool wantsInsurance = false;
		if (content.type == Json.Type.object && "insurance" in content
				&& content["insurance"].type == Json.Type.bool_)
			wantsInsurance = content["insurance"].get!bool;

		const summary = "Booked " ~ destination ~ " for " ~ travelersN.to!string
			~ " traveler(s) in " ~ cabinClass ~ " class" ~ (wantsInsurance
					? " with insurance." : " without insurance.");
		return TripPlan("booked", destination, travelersN, cabinClass, wantsInsurance, summary);
	}
}

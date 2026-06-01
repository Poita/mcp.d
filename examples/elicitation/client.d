/**
 * examples/elicitation — client.d (dual-transport, self-verifying e2e test)
 *
 * Exercises the **2025-era blocking elicitation** flow (issue #355) from the
 * consumer's eye view over BOTH transports the example supports. It is NOT just
 * a demo: every observation is asserted against the value the server promises,
 * and the process exits NON-ZERO on any mismatch, so CI can run it as an
 * end-to-end regression test on either transport.
 *
 * Transport selection + event-loop wiring are delegated to the shared
 * `examples/common` scaffold (#505):
 *   - `connectFromArgs(args, "elicitation-server")` picks the transport from
 *     argv: `--http <url>` -> `McpClient.http(url)`, otherwise
 *     `McpClient.spawnSibling("elicitation-server")` which launches the built
 *     server binary next to this client and owns its stdio JSON-RPC channel
 *     (`client.close()` runs the shutdown sequence, #470);
 *   - `runClient(scenario)` drives the vibe event loop uniformly so the SAME
 *     scenario body completes over BOTH the synchronous stdio transport and the
 *     HTTP transport (whose blocking server->client elicitation rides the
 *     Streamable HTTP SSE channel and needs a loop), mapping any thrown failure
 *     to a non-zero exit.
 *
 * Two-step run (see README):
 *   stdio:  dub run -c client                                   # spawns the server
 *   http:   dub run -c server -- --http --port 9355   (term 1)
 *           dub run -c client -- --http http://127.0.0.1:9355/mcp  (term 2)
 *
 * Typed-API adoption (#466 / #464 / #468 / #470):
 *   - stdio spawns the server via the scaffold's `spawnSibling` +
 *     `scope(exit) close()`, replacing the hand-rolled ServerProcess /
 *     ProcessPipes plumbing (#470);
 *   - the `accept` handler returns `ElicitResult.accept(AcceptForm(3))` — the
 *     struct's fields become the collected `{name: value}` content map (#466) —
 *     instead of hand-building a Json object;
 *   - the `plan_trip` arguments are passed as the typed `PlanArgs(destination)`
 *     struct (#468), not a hand-built Json;
 *   - the structured result is decoded once with `result.structuredContentAs!
 *     TripPlan` (#464) and the assertions read its typed fields;
 *   - installing `onElicitation` alone advertises form elicitation — the inbound
 *     gate now honours effectiveCapabilities() (#463), so the redundant raw
 *     `client.capabilities.elicitation*` flag-setting is gone.
 *
 * What it verifies, in order, on whichever transport is selected:
 *   A. DISCOVERY — `listTools()` contains `plan_trip` (with `destination` as a
 *      required arg and the injected `ctx` correctly omitted from the schema).
 *   B. ACCEPT (with defaults) — a client whose `onElicitation` returns
 *      `accept(AcceptForm(3))` (omitting cabin + insurance) drives a `plan_trip`
 *      call. The client asserts the elicitation request carried the rich
 *      requestedSchema (the `cabin` enum with 3 members + its `"economy"`
 *      default, the `travelers` integer bounds, the `insurance` boolean default),
 *      and that the final TripPlan is
 *      `{status:"booked", travelers:3, cabin:"economy", insurance:false}` —
 *      proving the server applied the schema defaults for the omitted fields and
 *      the accepted value flowed through the blocking round-trip.
 *   C. DECLINE — a fresh client whose `onElicitation` returns `decline()` gets
 *      `status:"declined"` back from the same tool.
 *   D. CANCEL — a fresh client whose `onElicitation` returns `cancel()` gets
 *      `status:"cancelled"`.
 *   E. UNSUPPORTED — a client that installs NO `onElicitation` handler (so it
 *      never advertises the elicitation capability) makes the tool fail: the
 *      server refuses to send an elicitation to a non-elicitation client, which
 *      surfaces as a tool error.
 */
module elicitation_client;

import std.algorithm : canFind, map;
import std.array : array;
import std.stdio : writeln;

import vibe.data.json : Json;

import mcp;
import examples_common : check, checkEq, runClient, connectFromArgs;
import mcp.protocol.errors : McpException;
import mcp.protocol.types : asNumber;

/// Typed arguments for the `plan_trip` tool (#468): passed to `callTool` as a
/// struct so the client never hand-builds the arguments Json.
struct PlanArgs
{
	string destination;
}

/// The `accept` form the client submits (#466): only `travelers` is supplied, so
/// `ElicitResult.accept(AcceptForm(3))` produces the `{travelers: 3}` content
/// map and the server applies its schema defaults for the omitted cabin +
/// insurance fields.
struct AcceptForm
{
	int travelers;
}

/// Mirrors the server's `TripPlan` structured output so the client can decode it
/// with `result.structuredContentAs!TripPlan` (#464) and assert typed fields
/// instead of hand-reading raw `structuredContent` Json.
struct TripPlan
{
	string status;
	string destination;
	int travelers;
	string cabin;
	bool insurance;
	string summary;
}

int main(string[] args) @safe
{
	// `runClient` drives the vibe loop uniformly for both transports and maps any
	// thrown assertion to a non-zero exit. A fresh client per scenario: stdio
	// spawns a new sibling server subprocess (owned by the returned client,
	// terminated by its close()); HTTP opens a new connection to the same URL.
	// Returning a transport-agnostic `McpClient` keeps the assertion body
	// identical for both transports.
	return runClient(() @safe {
		McpClient makeClient() @safe
		{
			return connectFromArgs(args, "elicitation-server");
		}

		return run(&makeClient);
	});
}

/// The transport-agnostic e2e body. `makeClient` yields a fresh connected-but-
/// not-yet-initialized client each call (a new spawned stdio subprocess or a new
/// HTTP connection); every assertion is identical across transports. Each client
/// is closed on scope exit so a spawned stdio server is reaped (#470).
private int run(McpClient delegate() @safe makeClient) @safe
{
	// ---- A. DISCOVERY -----------------------------------------------------
	{
		auto client = makeClient();
		scope (exit)
			client.close();
		auto init = client.initialize();
		checkEq(init.serverInfo.name, "elicitation-example", "server name");

		auto tools = client.listTools().tools;
		auto names = tools.map!(t => t.name).array;
		check(names.canFind("plan_trip"), "tools/list missing 'plan_trip'");

		Tool planTrip;
		foreach (t; tools)
			if (t.name == "plan_trip")
				planTrip = t;
		auto props = planTrip.inputSchema["properties"];
		check(("destination" in props) !is null, "plan_trip.inputSchema missing 'destination'");
		// The auto-injected RequestContext must NOT leak into the input schema.
		check(("ctx" in props) is null, "plan_trip.inputSchema must not expose the injected 'ctx'");
	}

	// ---- B. ACCEPT (server applies schema defaults for omitted fields) ----
	{
		// Captured so we can assert the requestedSchema the server sent.
		ElicitParams seen;
		bool sawElicit;

		auto client = makeClient();
		scope (exit)
			client.close();
		// Installing onElicitation alone advertises form elicitation; the inbound
		// gate now honours effectiveCapabilities() (#463), so no raw capability
		// flags are needed.
		client.onElicitation = (ElicitParams p) @safe {
			seen = p;
			sawElicit = true;
			// Accept, supplying only `travelers` via the typed AcceptForm (#466);
			// leave cabin + insurance to the server's schema defaults
			// ("economy" / false).
			return ElicitResult.accept(AcceptForm(3));
		};
		client.initialize();

		auto r = client.callTool("plan_trip", PlanArgs("Kyoto"));

		check(!r.isError, "plan_trip (accept) should not be an error");
		check(sawElicit, "client should have received an elicitation/create request");

		// The blocking elicitation prompt carries the destination.
		check(seen.message.canFind("Kyoto"),
				"elicitation message should mention the destination, got: " ~ seen.message);

		// The rich requestedSchema flowed through to the client.
		check(seen.requestedSchema.type == Json.Type.object,
				"elicitation requestedSchema should be an object");
		auto sprops = seen.requestedSchema["properties"];
		// enum + default on `cabin` (enum members derived from the struct,
		// default declared via @schemaDefault).
		auto cabin = sprops["cabin"];
		checkEq(cabin["enum"].length, 3UL, "cabin enum member count");
		checkEq(cabin["default"].get!string, "economy", "cabin default");
		// bounds on `travelers` (declared via @minimum/@maximum).
		auto travelers = sprops["travelers"];
		check(asNumber(travelers["minimum"]) == 1 && asNumber(travelers["maximum"]) == 9,
				"travelers should have minimum 1 / maximum 9");
		// default on `insurance` (declared via @schemaDefault(false)).
		checkEq(sprops["insurance"]["default"].get!bool, false, "insurance default");

		// The accepted value + applied defaults appear in the structured result,
		// decoded once into the typed TripPlan (#464).
		auto plan = r.structuredContentAs!TripPlan;
		checkEq(plan.status, "booked", "accept status");
		checkEq(plan.destination, "Kyoto", "destination");
		checkEq(plan.travelers, 3, "travelers (the accepted value)");
		checkEq(plan.cabin, "economy", "cabin should default when omitted");
		checkEq(plan.insurance, false, "insurance should default when omitted");
	}

	// ---- C. DECLINE -------------------------------------------------------
	{
		auto client = makeClient();
		scope (exit)
			client.close();
		client.onElicitation = (ElicitParams p) @safe {
			return ElicitResult.decline();
		};
		client.initialize();

		auto r = client.callTool("plan_trip", PlanArgs("Oslo"));
		check(!r.isError, "plan_trip (decline) should not be a tool error");
		auto plan = r.structuredContentAs!TripPlan;
		checkEq(plan.status, "declined", "decline status");
	}

	// ---- D. CANCEL --------------------------------------------------------
	{
		auto client = makeClient();
		scope (exit)
			client.close();
		client.onElicitation = (ElicitParams p) @safe {
			return ElicitResult.cancel();
		};
		client.initialize();

		auto r = client.callTool("plan_trip", PlanArgs("Lima"));
		check(!r.isError, "plan_trip (cancel) should not be a tool error");
		auto plan = r.structuredContentAs!TripPlan;
		checkEq(plan.status, "cancelled", "cancel status");
	}

	// ---- E. UNSUPPORTED (no onElicitation -> server refuses to elicit) ----
	{
		auto client = makeClient();
		scope (exit)
			client.close();
		// Deliberately install NO onElicitation handler, so this client does not
		// advertise the elicitation capability. The server's ctx.elicit then
		// refuses to send to a non-elicitation client, and the tool fails.
		client.initialize();

		bool failed;
		try
		{
			auto r = client.callTool("plan_trip", PlanArgs("Cairo"));
			// Over some transports the refusal surfaces as a tool error result
			// rather than a JSON-RPC error; accept either as the expected failure.
			failed = r.isError;
		}
		catch (McpException e)
			failed = true;
		check(failed, "plan_trip should fail (server refuses to elicit) when the client "
				~ "does not support elicitation");
	}

	writeln("OK: elicitation example e2e passed — blocking ctx.elicit!T, ",
			"rich requestedSchema (enum+default, integer bounds, boolean default) seen by ",
			"the client, accept applies server defaults (decoded via structuredContentAs!T), ",
			"decline/cancel branch, and a non-elicitation client makes the tool error.");
	return 0;
}

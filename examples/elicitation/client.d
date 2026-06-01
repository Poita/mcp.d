/**
 * examples/elicitation — client.d (self-verifying e2e test)
 *
 * Connects to `elicitation-server` over Streamable HTTP and exercises the
 * **2025-era blocking elicitation** flow (issue #355) from the consumer's eye
 * view. It is NOT just a demo: every observation is asserted against the value
 * the server promises, and the process exits NON-ZERO on any mismatch, so CI
 * can run it as an end-to-end regression test.
 *
 * Two-step run (see README):
 *   terminal 1:  dub run -c server
 *   terminal 2:  dub run -c client          # exits 0 on OK, non-zero on mismatch
 *
 * What it verifies, in order:
 *   A. DISCOVERY — `listTools()` contains `plan_trip` (with `destination` as a
 *      required arg and `ctx` correctly omitted from the input schema).
 *   B. ACCEPT (with defaults) — a client whose `onElicitation` returns
 *      `accept{travelers:3}` (omitting cabin + insurance) drives a `plan_trip`
 *      call. The client asserts:
 *        - the elicitation request it received carried the rich requestedSchema
 *          (the `cabin` enum with 3 members + its `"economy"` default, the
 *          `travelers` integer bounds, the `insurance` boolean default), and
 *        - the final result's structuredContent is
 *          `{status:"booked", travelers:3, cabin:"economy", insurance:false}` —
 *          proving the server applied the schema defaults for the omitted fields
 *          and the accepted value flowed through the blocking round-trip.
 *   C. DECLINE — a fresh client whose `onElicitation` returns `decline()` gets
 *      `status:"declined"` back from the same tool.
 *   D. CANCEL — a fresh client whose `onElicitation` returns `cancel()` gets
 *      `status:"cancelled"`.
 *   E. UNSUPPORTED — a client that installs NO `onElicitation` handler (so it
 *      never advertises the elicitation capability) makes the tool fail: the
 *      server refuses to send an elicitation to a non-elicitation client, which
 *      surfaces as a tool error (`isError == true`).
 *
 * Contrast with examples/mrtr: there the same shape is achieved statelessly by
 * resubmitting `tools/call` with `inputResponses`; here it is one blocking
 * `tools/call` with a genuine server->client `elicitation/create` in the middle.
 */
module elicitation_client;

import std.algorithm : startsWith, canFind, map;
import std.array : array;
import std.stdio : stderr, writeln;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.data.json : Json;

import mcp;
import mcp.protocol.errors : McpException;

enum string defaultUrl = "http://127.0.0.1:9355/mcp";

int main(string[] args)
{
	string url = defaultUrl;
	foreach (a; args[1 .. $])
		if (a.startsWith("http://") || a.startsWith("https://"))
			url = a;

	int rc;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			rc = run(url);
		catch (Throwable t) // AssertError and exceptions both fail the e2e
		{
			try
				stderr.writeln("FAIL: ", t.msg);
			catch (Exception)
			{
			}
			rc = 1;
		}
	});
	runEventLoop();
	return rc;
}

/// A tiny assert helper that throws (caught in main -> exit 1) with a clear
/// message describing what differed.
private void check(bool cond, lazy string msg) @safe
{
	if (!cond)
		throw new Exception(msg);
}

/// Read a JSON number as an int, tolerating either integral or double encoding.
private int asInt(Json j) @safe
{
	if (j.type == Json.Type.float_)
		return cast(int) j.get!double;
	return j.get!int;
}

private int run(string url) @safe
{
	// ---- A. DISCOVERY -----------------------------------------------------
	{
		auto client = McpClient.http(url);
		auto init = client.initialize();
		check(init.serverInfo.name == "elicitation-example",
			"server name: expected 'elicitation-example', got '" ~ init.serverInfo.name ~ "'");

		auto tools = client.listTools().tools;
		auto names = tools.map!(t => t.name).array;
		check(names.canFind("plan_trip"), "tools/list missing 'plan_trip'");

		Tool planTrip;
		foreach (t; tools)
			if (t.name == "plan_trip")
				planTrip = t;
		auto props = planTrip.inputSchema["properties"];
		check(("destination" in props) !is null,
			"plan_trip.inputSchema missing 'destination'");
		// The auto-injected RequestContext must NOT leak into the input schema.
		check(("ctx" in props) is null,
			"plan_trip.inputSchema must not expose the injected 'ctx'");
	}

	// ---- B. ACCEPT (server applies schema defaults for omitted fields) ----
	{
		// Captured so we can assert the requestedSchema the server sent.
		ElicitParams seen;
		bool sawElicit;

		auto client = McpClient.http(url);
		// Declare form-mode elicitation explicitly so the inbound dispatcher accepts
		// the server's `elicitation/create` (the inbound check reads the raw
		// `capabilities`, not the auto-advertised set).
		client.capabilities.elicitation = true;
		client.capabilities.elicitationForm = true;
		client.onElicitation = (ElicitParams p) @safe {
			seen = p;
			sawElicit = true;
			// Accept, supplying only `travelers`; leave cabin + insurance to the
			// server's schema defaults ("economy" / false).
			Json content = Json.emptyObject;
			content["travelers"] = 3;
			return ElicitResult.accept(content);
		};
		client.initialize();

		Json a = Json.emptyObject;
		a["destination"] = "Kyoto";
		auto r = client.callTool("plan_trip", a);

		check(!r.isError, "plan_trip (accept) should not be an error");
		check(sawElicit, "client should have received an elicitation/create request");

		// The blocking elicitation prompt carries the destination.
		check(seen.message.canFind("Kyoto"),
			"elicitation message should mention the destination, got: " ~ seen.message);

		// The rich requestedSchema flowed through to the client.
		check(seen.requestedSchema.type == Json.Type.object,
			"elicitation requestedSchema should be an object");
		auto sprops = seen.requestedSchema["properties"];
		// enum + default on `cabin`.
		auto cabin = sprops["cabin"];
		check(cabin["enum"].length == 3,
			"cabin enum should have 3 members");
		check(cabin["default"].get!string == "economy",
			"cabin default should be 'economy'");
		// bounds on `travelers`.
		auto travelers = sprops["travelers"];
		check(asInt(travelers["minimum"]) == 1 && asInt(travelers["maximum"]) == 9,
			"travelers should have minimum 1 / maximum 9");
		// default on `insurance`.
		check(sprops["insurance"]["default"].get!bool == false,
			"insurance default should be false");

		// The accepted value + applied defaults appear in the structured result.
		auto sc = r.structuredContent;
		check(sc["status"].get!string == "booked",
			"accept status should be 'booked', got: " ~ sc["status"].get!string);
		check(sc["destination"].get!string == "Kyoto",
			"destination should be 'Kyoto'");
		check(asInt(sc["travelers"]) == 3,
			"travelers should be 3 (the accepted value)");
		check(sc["cabin"].get!string == "economy",
			"cabin should default to 'economy' when omitted");
		check(sc["insurance"].get!bool == false,
			"insurance should default to false when omitted");
	}

	// ---- C. DECLINE -------------------------------------------------------
	{
		auto client = McpClient.http(url);
		// Declare form-mode elicitation explicitly so the inbound dispatcher accepts
		// the server's `elicitation/create` (the inbound check reads the raw
		// `capabilities`, not the auto-advertised set).
		client.capabilities.elicitation = true;
		client.capabilities.elicitationForm = true;
		client.onElicitation = (ElicitParams p) @safe {
			return ElicitResult.decline();
		};
		client.initialize();

		Json a = Json.emptyObject;
		a["destination"] = "Oslo";
		auto r = client.callTool("plan_trip", a);
		check(!r.isError, "plan_trip (decline) should not be a tool error");
		check(r.structuredContent["status"].get!string == "declined",
			"decline status should be 'declined', got: "
			~ r.structuredContent["status"].get!string);
	}

	// ---- D. CANCEL --------------------------------------------------------
	{
		auto client = McpClient.http(url);
		// Declare form-mode elicitation explicitly so the inbound dispatcher accepts
		// the server's `elicitation/create` (the inbound check reads the raw
		// `capabilities`, not the auto-advertised set).
		client.capabilities.elicitation = true;
		client.capabilities.elicitationForm = true;
		client.onElicitation = (ElicitParams p) @safe {
			return ElicitResult.cancel();
		};
		client.initialize();

		Json a = Json.emptyObject;
		a["destination"] = "Lima";
		auto r = client.callTool("plan_trip", a);
		check(!r.isError, "plan_trip (cancel) should not be a tool error");
		check(r.structuredContent["status"].get!string == "cancelled",
			"cancel status should be 'cancelled', got: "
			~ r.structuredContent["status"].get!string);
	}

	// ---- E. UNSUPPORTED (no onElicitation -> server refuses to elicit) ----
	{
		auto client = McpClient.http(url);
		// Deliberately install NO onElicitation handler, so this client does not
		// advertise the elicitation capability. The server's ctx.elicit then
		// refuses to send to a non-elicitation client, and the tool fails.
		client.initialize();

		Json a = Json.emptyObject;
		a["destination"] = "Cairo";
		bool threw;
		try
			client.callTool("plan_trip", a);
		catch (McpException e)
			threw = true;
		check(threw,
			"plan_trip should fail (server refuses to elicit) when the client "
			~ "does not support elicitation");
	}

	writeln("OK: elicitation example e2e passed — blocking ctx.elicit over HTTP, ",
		"rich requestedSchema (enum+default, integer bounds, boolean default) seen by ",
		"the client, accept applies server defaults, decline/cancel branch, and a ",
		"non-elicitation client makes the tool error.");
	return 0;
}

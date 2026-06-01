/**
 * examples/elicitation — client.d (dual-transport, self-verifying e2e test)
 *
 * Exercises the **2025-era blocking elicitation** flow (issue #355) from the
 * consumer's eye view over BOTH transports the example supports. It is NOT just
 * a demo: every observation is asserted against the value the server promises,
 * and the process exits NON-ZERO on any mismatch, so CI can run it as an
 * end-to-end regression test on either transport.
 *
 * Transport selection (transport-agnostic assertions — the SAME `run` verifies
 * both):
 *   STDIO (default): no `--http` -> spawn the built `elicitation-server` binary
 *     (without --http) and talk to it over its stdin/stdout via
 *     `McpClient.stdio(&proc.readLine, &proc.writeLine)`. The blocking
 *     elicitation is answered inline on the same channel, so this needs no event
 *     loop.
 *   HTTP: `--http <url>` -> `McpClient.http(url)`. The blocking server->client
 *     elicitation rides the Streamable HTTP SSE channel, which requires a vibe
 *     event loop, so the HTTP run is wrapped in `runTask`/`runEventLoop`.
 *
 * Two-step run (see README):
 *   stdio:  dub run -c client                                   # spawns the server
 *   http:   dub run -c server -- --http --port 9355   (term 1)
 *           dub run -c client -- --http http://127.0.0.1:9355/mcp  (term 2)
 *
 * What it verifies, in order, on whichever transport is selected:
 *   A. DISCOVERY — `listTools()` contains `plan_trip` (with `destination` as a
 *      required arg and the injected `ctx` correctly omitted from the schema).
 *   B. ACCEPT (with defaults) — a client whose `onElicitation` returns
 *      `accept{travelers:3}` (omitting cabin + insurance) drives a `plan_trip`
 *      call. The client asserts the elicitation request carried the rich
 *      requestedSchema (the `cabin` enum with 3 members + its `"economy"`
 *      default, the `travelers` integer bounds, the `insurance` boolean default),
 *      and that the final structuredContent is
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

import std.algorithm : startsWith, canFind, map;
import std.array : array;
import std.getopt : getopt;
import std.process : ProcessPipes, pipeProcess, Redirect, wait;
import std.stdio : stderr, writeln;
import std.string : stripRight;

import vibe.data.json : Json;

import mcp;
import mcp.protocol.errors : McpException;

/// Owns one server subprocess and exposes the newline-delimited JSON-RPC channel
/// `McpClient.stdio` expects. Holding `ProcessPipes` in a class field keeps the
/// stdin/stdout `File` handles alive for the client's lifetime (mirrors the
/// pattern in examples/tools/client.d).
final class ServerProcess
{
	private ProcessPipes pipes;

	this(string[] command) @trusted
	{
		pipes = pipeProcess(command, Redirect.stdin | Redirect.stdout);
	}

	/// Read one response line (terminator stripped), or null at EOF.
	string readLine() @trusted
	{
		auto f = pipes.stdout;
		if (f.eof)
			return null;
		auto ln = f.readln();
		if (ln.length == 0 && f.eof)
			return null;
		return ln.stripRight("\r\n");
	}

	/// Write one request line (the channel appends the terminator).
	void writeLine(string s) @trusted
	{
		pipes.stdin.writeln(s);
		pipes.stdin.flush();
	}

	/// Close stdin and reap the child.
	void shutdown() @trusted
	{
		try
			pipes.stdin.close();
		catch (Exception)
		{
		}
		wait(pipes.pid);
	}
}

/// Absolute path to the `elicitation-server` binary, resolved next to this
/// client binary (dub writes both into the package root), independent of cwd.
private string serverBinaryPath() @safe
{
	import std.file : thisExePath;
	import std.path : dirName, buildPath;

	return buildPath(dirName(thisExePath()), "elicitation-server");
}

int main(string[] args)
{
	string url;
	getopt(args, "http", "Connect over Streamable HTTP to this MCP URL (otherwise stdio)", &url);
	// Tolerate a bare positional URL too (e.g. `-- http://...`), matching the
	// older invocation style.
	if (url.length == 0)
		foreach (a; args[1 .. $])
			if (a.startsWith("http://") || a.startsWith("https://"))
				url = a;

	const useHttp = url.length != 0;

	// Track every spawned stdio server so we can reap them on exit. For HTTP the
	// list stays empty.
	ServerProcess[] procs;
	scope (exit)
		foreach (p; procs)
			p.shutdown();

	// A fresh client per scenario: stdio spawns a new server subprocess; HTTP
	// opens a new connection to the same URL. Returning a transport-agnostic
	// `McpClient` keeps the assertion body identical for both transports.
	McpClient makeClient() @trusted
	{
		if (useHttp)
			return McpClient.http(url);
		auto proc = new ServerProcess([serverBinaryPath()]);
		procs ~= proc;
		return McpClient.stdio(&proc.readLine, &proc.writeLine);
	}

	int rc;
	if (useHttp)
	{
		// HTTP: the blocking elicitation rides the SSE channel and needs an event
		// loop, so drive the whole scenario from inside one vibe task.
		import vibe.core.core : runTask, runEventLoop, exitEventLoop;

		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
				rc = run(&makeClient);
			catch (Throwable t) // AssertError + exceptions both fail the e2e
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
	}
	else
	{
		// stdio: synchronous; the elicitation reply is written inline to the
		// child's stdin, so no event loop is required.
		try
			rc = run(&makeClient);
		catch (Throwable t)
		{
			try
				stderr.writeln("FAIL: ", t.msg);
			catch (Exception)
			{
			}
			rc = 1;
		}
	}
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

/// The transport-agnostic e2e body. `makeClient` yields a fresh connected-but-
/// not-yet-initialized client each call (a new stdio subprocess or a new HTTP
/// connection); every assertion is identical across transports.
private int run(McpClient delegate() @safe makeClient) @safe
{
	// ---- A. DISCOVERY -----------------------------------------------------
	{
		auto client = makeClient();
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
		// enum + default on `cabin` (enum members derived from the struct,
		// default added by the server).
		auto cabin = sprops["cabin"];
		check(cabin["enum"].length == 3, "cabin enum should have 3 members");
		check(cabin["default"].get!string == "economy", "cabin default should be 'economy'");
		// bounds on `travelers`.
		auto travelers = sprops["travelers"];
		check(asInt(travelers["minimum"]) == 1 && asInt(travelers["maximum"]) == 9,
				"travelers should have minimum 1 / maximum 9");
		// default on `insurance`.
		check(sprops["insurance"]["default"].get!bool == false, "insurance default should be false");

		// The accepted value + applied defaults appear in the structured result.
		auto sc = r.structuredContent;
		check(sc["status"].get!string == "booked",
				"accept status should be 'booked', got: " ~ sc["status"].get!string);
		check(sc["destination"].get!string == "Kyoto", "destination should be 'Kyoto'");
		check(asInt(sc["travelers"]) == 3, "travelers should be 3 (the accepted value)");
		check(sc["cabin"].get!string == "economy", "cabin should default to 'economy' when omitted");
		check(sc["insurance"].get!bool == false, "insurance should default to false when omitted");
	}

	// ---- C. DECLINE -------------------------------------------------------
	{
		auto client = makeClient();
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
		auto client = makeClient();
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
		auto client = makeClient();
		// Deliberately install NO onElicitation handler, so this client does not
		// advertise the elicitation capability. The server's ctx.elicit then
		// refuses to send to a non-elicitation client, and the tool fails.
		client.initialize();

		Json a = Json.emptyObject;
		a["destination"] = "Cairo";
		bool failed;
		try
		{
			auto r = client.callTool("plan_trip", a);
			// Over some transports the refusal surfaces as a tool error result
			// rather than a JSON-RPC error; accept either as the expected failure.
			failed = r.isError;
		}
		catch (McpException e)
			failed = true;
		check(failed, "plan_trip should fail (server refuses to elicit) when the client "
				~ "does not support elicitation");
	}

	writeln("OK: elicitation example e2e passed — blocking ctx.elicit, ",
			"rich requestedSchema (enum+default, integer bounds, boolean default) seen by ",
			"the client, accept applies server defaults (decoded via contentAs!T), ",
			"decline/cancel branch, and a non-elicitation client makes the tool error.");
	return 0;
}

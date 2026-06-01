/**
 * examples/sampling — client.d (self-verifying e2e test, dual-transport)
 *
 * Exercises MCP **Sampling** from the consumer's eye view over EITHER transport:
 *
 *   - STDIO (default): spawns the built `sampling-server` binary (no `--http`)
 *     and drives it over the bidirectional stdio channel, exactly like
 *     examples/tools/client.d (ProcessPipes + `McpClient.stdio`).
 *   - HTTP (`--http <url>`): connects to a running `sampling-server --http`
 *     instance via `McpClient.http(url)`.
 *
 * It is NOT just a demo: every observation is asserted against the value the
 * mock model produced, and the process exits NON-ZERO on any mismatch, so CI can
 * run it as an end-to-end regression test over each transport.
 *
 * The client installs an `onSampling` handler — a DETERMINISTIC mock "model".
 * When the server calls `ctx.sample(...)` the SDK routes the
 * `sampling/createMessage` request back to this handler; its reply travels back
 * to the server and surfaces in the tool's structured result. Because the mock
 * is deterministic, the client knows exactly what the server's result must be
 * and asserts it precisely — proving the value flowed server→client→server. The
 * assertions are transport-agnostic, so the SAME run() verifies both transports.
 *
 * Run (see README):
 *   STDIO:  dub run -c client                                   # spawns the server
 *   HTTP:   dub run -c server -- --http --port 9354 &           # in another shell
 *           dub run -c client -- --http http://127.0.0.1:9354/mcp
 *
 * What it verifies, in order:
 *   - `listTools()` contains `summarize` and `model_name`.
 *   - The `onSampling` handler is actually INVOKED (the server reached back).
 *   - The handler received a system prompt and the user text the server sent.
 *   - `summarize` returns `{summary, model, stopReason}` exactly matching the
 *     mock model's reply — i.e. the mocked sampling value flowed through.
 *   - `model_name` returns the mock model's `model` identifier.
 */
module sampling_client;

import std.algorithm : canFind, map;
import std.array : array;
import std.conv : to;
import std.getopt : getopt;
import std.process : ProcessPipes, pipeProcess, Redirect, wait;
import std.stdio : stderr, writeln;
import std.string : stripRight;

import vibe.data.json : Json;

import mcp;

/// The fixed identifier our mock "model" reports. The server echoes this back in
/// its structured result, so the client can assert it round-tripped.
enum string mockModelId = "mock-summarizer-v1";

/// The mock model's deterministic completion. Captured by the server in the
/// `summarize` structured result.
enum string fixedSummary = "A terse one-line summary.";

/// Owns the server subprocess and exposes the newline-delimited JSON-RPC channel
/// expected by `McpClient.stdio`. Holding `ProcessPipes` in a class field keeps
/// the stdin/stdout `File` handles alive for the lifetime of the client.
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
		pipes.stdin.close();
		wait(pipes.pid);
	}
}

int main(string[] args)
{
	string url; // empty => stdio
	getopt(args, "http", "Connect over Streamable HTTP to this URL instead of spawning over stdio", &url);

	if (url.length)
	{
		// HTTP: sampling is a server->client request mid-tool-call, so the client
		// must run an event loop to dispatch the inbound sampling/createMessage.
		import vibe.core.core : runTask, runEventLoop, exitEventLoop;

		int rc;
		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
				rc = run(McpClient.http(url), null);
			catch (Throwable t) // AssertError + exceptions both fail the e2e
			{
				logFail(t.msg);
				rc = 1;
			}
		});
		runEventLoop();
		return rc;
	}

	// STDIO: spawn the built server binary (no --http) and drive it synchronously.
	// Server->client sampling replies are written inline on the same channel, so
	// no event loop is required (same model as examples/tools/client.d).
	auto proc = new ServerProcess([serverBinaryPath()]);
	scope (exit)
		proc.shutdown();
	try
		return run(McpClient.stdio(&proc.readLine, &proc.writeLine), proc);
	catch (Throwable t)
	{
		logFail(t.msg);
		return 1;
	}
}

/// Transport-agnostic e2e: drives `client` and asserts the mocked sampling value
/// flows server→client→server. `proc` is non-null only for stdio (so we can keep
/// it referenced); the assertions never look at the transport.
private int run(McpClient client, Object proc) @safe
{
	scope (exit)
		client.close();

	// --- the mock model -----------------------------------------------------
	// Records what it was asked and answers deterministically. Captured by
	// reference so post-call assertions can inspect what the server requested.
	bool handlerInvoked;
	string seenSystemPrompt;
	string seenUserText;

	client.onSampling = (CreateMessageRequest request) @safe {
		handlerInvoked = true;
		if (!request.systemPrompt.isNull)
			seenSystemPrompt = request.systemPrompt.get;
		// The server sends a single user message with one text block.
		if (request.messages.length)
			seenUserText = request.messages[0].content.text;

		CreateMessageResult r;
		r.role = "assistant";
		r.content = Content.makeText(fixedSummary);
		r.model = mockModelId;
		r.stopReason = "endTurn";
		return r;
	};

	// Pin a stable (2025-era) version so the BLOCKING sampling path is exercised.
	// (The draft revision would route sampling through MRTR / inputRequired
	// instead of the synchronous server->client request this example demos.)
	client.initialize("2025-11-25");

	// --- tools/list ---------------------------------------------------------
	auto tools = client.listTools().tools;
	auto names = tools.map!(t => t.name).array;
	foreach (want; ["summarize", "model_name"])
		check(names.canFind(want), "tools/list missing tool: " ~ want);

	// --- summarize: the mocked sampling value must flow through -------------
	const longText = "MCP sampling lets a server borrow the client's LLM. "
		~ "The server sends sampling/createMessage; the client answers with a completion.";
	Json sArgs = Json.emptyObject;
	sArgs["text"] = longText;
	auto sres = client.callTool("summarize", sArgs);

	check(!sres.isError, "summarize must not be an error");
	check(sres.structuredContent.type == Json.Type.object,
			"summarize must return structuredContent");
	check(sres.structuredContent["summary"].get!string == fixedSummary,
			"summarize.summary should be the mock model's reply '" ~ fixedSummary
			~ "', got '" ~ sres.structuredContent["summary"].to!string ~ "'");
	check(sres.structuredContent["model"].get!string == mockModelId,
			"summarize.model should be '" ~ mockModelId ~ "', got '"
			~ sres.structuredContent["model"].to!string ~ "'");
	check(sres.structuredContent["stopReason"].get!string == "endTurn",
			"summarize.stopReason should be 'endTurn'");

	// The server must actually have reached back into our handler...
	check(handlerInvoked, "onSampling handler was never invoked (server did not call ctx.sample)");
	// ...and what it asked for must match what the server built.
	check(seenSystemPrompt.length > 0, "onSampling should have received a systemPrompt");
	check(seenUserText.canFind(longText),
			"onSampling user message should contain the text we sent to summarize");

	// --- model_name: the client's model id flows back to the server ---------
	auto mres = client.callTool("model_name");
	check(mres.structuredContent.type == Json.Type.object,
			"model_name must return structuredContent");
	check(mres.structuredContent["model"].get!string == mockModelId,
			"model_name.model should be '" ~ mockModelId ~ "', got '"
			~ mres.structuredContent["model"].to!string ~ "'");

	logOk("sampling example e2e passed — server reached back via ctx.sample, "
			~ "onSampling mock answered (system prompt + user text observed), and the "
			~ "mocked summary/model/stopReason flowed through summarize + model_name.");
	return 0;
}

/// Assertion helper: throws (failing the e2e with a clear message) when `cond`
/// is false.
private void check(bool cond, lazy string msg) @safe
{
	if (!cond)
		throw new Exception(msg);
}

/// Absolute path to the `sampling-server` binary, resolved next to this client
/// binary (dub writes both into the package root), independent of cwd.
private string serverBinaryPath() @safe
{
	import std.file : thisExePath;
	import std.path : dirName, buildPath;

	return buildPath(dirName(thisExePath()), "sampling-server");
}

private void logOk(string msg) @trusted
{
	writeln("OK: ", msg);
}

private void logFail(string msg) @trusted nothrow
{
	try
		stderr.writeln("FAIL: ", msg);
	catch (Exception)
	{
	}
}

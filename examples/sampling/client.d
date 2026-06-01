/**
 * examples/sampling — client.d (self-verifying e2e test, dual-transport)
 *
 * Exercises MCP **Sampling** from the consumer's eye view over EITHER transport:
 *
 *   - STDIO (default): spawns the built `sampling-server` binary (no `--http`)
 *     and drives it over the bidirectional stdio channel.
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
 *     mock model's reply — read via the typed `structuredContentAs!T`.
 *   - `model_name` returns the mock model's `model` identifier.
 */
module sampling_client;

import std.algorithm : canFind, map;
import std.array : array;
import std.getopt : getopt;
import std.stdio : stderr, writeln;

import mcp;

/// The fixed identifier our mock "model" reports. The server echoes this back in
/// its structured result, so the client can assert it round-tripped.
enum string mockModelId = "mock-summarizer-v1";

/// The mock model's deterministic completion. Captured by the server in the
/// `summarize` structured result.
enum string fixedSummary = "A terse one-line summary.";

/// Typed arguments for the `summarize` tool — passed to the typed
/// `callTool(name, T)` overload (#468) so the SDK serializes them (no hand-built
/// Json argument object).
struct SummarizeArgs
{
	string text;
}

/// Mirror of the server's `summarize` structured output, decoded with
/// `CallToolResult.structuredContentAs!T` (#464) instead of reading raw Json
/// fields one by one.
struct SummaryResult
{
	string summary;
	string model;
	string stopReason;
}

/// Mirror of the server's `model_name` structured output (read via
/// `structuredContentAs!T`).
struct ModelResult
{
	string model;
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
				rc = run(McpClient.http(url));
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
	// `McpClient.spawn` owns the subprocess pipes and its `close()` runs the MCP
	// stdio shutdown sequence (SIGTERM->SIGKILL). Server->client sampling replies
	// are written inline on the same channel, so no event loop is required (same
	// model as examples/tools/client.d).
	try
		return run(McpClient.spawn([serverBinaryPath()]));
	catch (Throwable t)
	{
		logFail(t.msg);
		return 1;
	}
}

/// Transport-agnostic e2e: drives `client` and asserts the mocked sampling value
/// flows server→client→server. The assertions never look at the transport, so the
/// SAME run() verifies both. For stdio, `client.close()` runs the MCP stdio
/// shutdown sequence on the spawned subprocess; for HTTP it stops background streams.
private int run(McpClient client) @safe
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

		// One-line assistant reply with our mock model id — built with the
		// `CreateMessageResult.text` helper (#467) instead of setting
		// role/content/model/stopReason by hand (stopReason defaults to "endTurn").
		return CreateMessageResult.text(mockModelId, fixedSummary);
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
	// Typed args (#468): pass a struct; the SDK serializes it to the arguments
	// object, so the example no longer hand-builds Json here.
	auto sres = client.callTool("summarize", SummarizeArgs(longText));

	check(!sres.isError, "summarize must not be an error");
	// Typed structured output (#464): decode the whole result in one step instead
	// of reading `structuredContent["x"].get!...` field by field.
	auto summary = sres.structuredContentAs!SummaryResult;
	check(summary.summary == fixedSummary,
			"summarize.summary should be the mock model's reply '" ~ fixedSummary
			~ "', got '" ~ summary.summary ~ "'");
	check(summary.model == mockModelId,
			"summarize.model should be '" ~ mockModelId ~ "', got '" ~ summary.model ~ "'");
	check(summary.stopReason == "endTurn",
			"summarize.stopReason should be 'endTurn', got '" ~ summary.stopReason ~ "'");

	// The server must actually have reached back into our handler...
	check(handlerInvoked, "onSampling handler was never invoked (server did not call ctx.sample)");
	// ...and what it asked for must match what the server built.
	check(seenSystemPrompt.length > 0, "onSampling should have received a systemPrompt");
	check(seenUserText.canFind(longText),
			"onSampling user message should contain the text we sent to summarize");

	// --- model_name: the client's model id flows back to the server ---------
	auto mres = client.callTool("model_name");
	auto modelName = mres.structuredContentAs!ModelResult;
	check(modelName.model == mockModelId,
			"model_name.model should be '" ~ mockModelId ~ "', got '" ~ modelName.model ~ "'");

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

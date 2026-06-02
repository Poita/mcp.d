/**
 * examples/sampling — client.d (self-verifying e2e test, dual-transport)
 *
 * Exercises MCP **Sampling** from the consumer's eye view over EITHER transport,
 * selected by the shared `examples/common` scaffold's `connectFromArgs`:
 *
 *   - STDIO (default): spawns the sibling `sampling-server` binary (no `--http`)
 *     via `McpClient.spawnSibling` and drives it over the bidirectional stdio
 *     channel.
 *   - HTTP (`--http <url>`): connects to a running `sampling-server --http`
 *     instance via `McpClient.http(url)`.
 *
 * It is NOT just a demo: every observation is asserted (with the scaffold's
 * `check`) against the value the mock model produced, and the process exits
 * NON-ZERO on any mismatch, so CI can run it as an end-to-end regression test
 * over each transport. The event-loop wiring that lets the SAME scenario work
 * over both transports is provided by the scaffold's `runClient`.
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

import mcp;
import examples_common : check, runClient, connectFromArgs;

/// The fixed identifier our mock "model" reports. The server echoes this back in
/// its structured result, so the client can assert it round-tripped.
enum string mockModelId = "mock-summarizer-v1";

/// The mock model's deterministic completion. Captured by the server in the
/// `summarize` structured result.
enum string fixedSummary = "A terse one-line summary.";

/// Typed arguments for the `summarize` tool — passed to the typed
/// `callTool(name, T)` overload so the SDK serializes them (no hand-built
/// Json argument object).
struct SummarizeArgs
{
	string text;
}

/// Mirror of the server's `summarize` structured output, decoded with
/// `CallToolResult.structuredContentAs!T`.
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

int main(string[] args) @safe
{
	// Scaffold `runClient` drives the vibe event loop uniformly so the SAME
	// scenario body works over BOTH a spawned-sibling stdio transport and an HTTP
	// transport (sampling is a server->client request mid-tool-call, so even the
	// stdio path needs the loop to dispatch the inbound sampling/createMessage).
	return runClient(() @safe {
		// Transport from argv: `--http <url>` -> HTTP, else spawn the sibling
		// `sampling-server` binary over stdio. Returned client is not initialized.
		auto client = connectFromArgs(args, "sampling-server");
		scope (exit)
			client.close();
		return run(client);
	});
}

/// Transport-agnostic e2e: drives `client` and asserts the mocked sampling value
/// flows server→client→server. The assertions never look at the transport, so the
/// SAME run() verifies both.
private int run(McpClient client) @safe
{
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
		// `CreateMessageResult.text` helper (stopReason defaults to "endTurn").
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
	// Typed args: pass a struct; the SDK serializes it to the arguments object.
	auto sres = client.callTool("summarize", SummarizeArgs(longText));

	check(!sres.isError, "summarize must not be an error");
	// Typed structured output: decode the whole result in one step.
	auto summary = sres.structuredContentAs!SummaryResult;
	check(summary.summary == fixedSummary, "summarize.summary should be the mock model's reply '"
			~ fixedSummary ~ "', got '" ~ summary.summary ~ "'");
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

private void logOk(string msg) @trusted
{
	import std.stdio : writeln;

	writeln("OK: ", msg);
}

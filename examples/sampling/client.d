/**
 * examples/sampling — client.d (self-verifying e2e test)
 *
 * Connects to `sampling-server` over Streamable HTTP and exercises MCP
 * **Sampling** from the consumer's eye view. It is NOT just a demo: every
 * observation is asserted against the value the mock model produced, and the
 * process exits NON-ZERO on any mismatch, so CI can run it as an end-to-end
 * regression test.
 *
 * The client installs an `onSampling` handler — a DETERMINISTIC mock "model".
 * When the server calls `ctx.sample(...)` the SDK routes the
 * `sampling/createMessage` request back to this handler; its reply travels back
 * to the server and surfaces in the tool's structured result. Because the mock
 * is deterministic, the client knows exactly what the server's result must be
 * and asserts it precisely — proving the value flowed server→client→server.
 *
 * Two-step run (see README):
 *   terminal 1:  dub run -c server
 *   terminal 2:  dub run -c client          # exits 0 on OK, non-zero on mismatch
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

import std.algorithm : startsWith, canFind, map;
import std.array : array;
import std.conv : to;
import std.stdio : stderr, writeln;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.data.json : Json;

import mcp;

enum string defaultUrl = "http://127.0.0.1:9354/mcp";

/// The fixed identifier our mock "model" reports. The server echoes this back in
/// its structured result, so the client can assert it round-tripped.
enum string mockModelId = "mock-summarizer-v1";

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

private int run(string url) @safe
{
	auto client = McpClient.http(url);
	scope (exit)
		client.close();

	// --- the mock model -----------------------------------------------------
	// Records what it was asked and answers deterministically. Captured by
	// reference so post-call assertions can inspect what the server requested.
	bool handlerInvoked;
	string seenSystemPrompt;
	string seenUserText;
	const string fixedSummary = "A terse one-line summary.";

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

	() @trusted {
		writeln("OK: sampling example e2e passed — server reached back via ctx.sample, ",
				"onSampling mock answered (system prompt + user text observed), and the ",
				"mocked summary/model/stopReason flowed through summarize + model_name.");
	}();
	return 0;
}

/// Assertion helper: throws (failing the e2e with a clear message) when `cond`
/// is false.
private void check(bool cond, lazy string msg) @safe
{
	if (!cond)
		throw new Exception(msg);
}

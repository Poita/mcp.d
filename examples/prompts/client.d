/// Prompts + completion example — CLIENT (self-verifying e2e test, dual-transport).
///
/// Drives the prompts + completion surface and ASSERTS concrete expected values.
/// On any mismatch it prints what differed and exits non-zero; on success it
/// prints an "OK:" summary and exits 0. Running this client IS the whole e2e
/// test — and the SAME assertions run over BOTH transports. Transport selection
/// and the event-loop wiring are delegated to the shared `examples_common`
/// scaffold:
///
///   * STDIO (default): `connectFromArgs` spawns the sibling `prompts-server`
///     binary (WITHOUT --http) via `McpClient.spawnSibling("prompts-server")`,
///     which owns the subprocess and drives it over stdin/stdout; `client.close()`
///     runs the stdio shutdown sequence (SIGTERM -> SIGKILL).
///   * HTTP (`--http <url>`): `connectFromArgs` connects to an already-running
///     server over Streamable HTTP via `McpClient.http(url)`.
///
/// What it verifies (transport-agnostic):
///   * `prompts/list` contains exactly the two prompts the server registers,
///     with their titles and argument descriptors.
///   * `prompts/get greet` renders the `name` argument (built as a JSON object,
///     the untyped client request surface) into a text message.
///   * `prompts/get code_review` returns an embedded-resource content block,
///     decoded via the typed `Content.embeddedResource()` (uri + mimeType + text).
///   * `completion/complete` for the `language` argument prefix-matches the
///     server's known-language list (context-aware shape).
///   * an unknown prompt name yields a JSON-RPC invalidParams (-32602) error.
module prompts_client;

import std.algorithm : map, canFind, sort;
import std.array : array;

import mcp.client.client : McpClient, byName;
import mcp.protocol.types : ContentKind, CompletionReference, CompleteResult,
	ListPromptsResult, GetPromptResult, Prompt, ResourceContents;
import mcp.protocol.errors : McpException, ErrorCode;
import vibe.data.json : Json;

import examples_common : check, checkEq, runClient, connectFromArgs;

/// `greet` prompt arguments as a JSON object (`{ "name": name }`). The client
/// request surface is untyped — see the repo-root `DESIGN.md`.
private Json greetArgs(string name) @safe
{
	Json j = Json.emptyObject;
	j["name"] = name;
	return j;
}

/// `code_review` prompt arguments as a JSON object (`{ "language": language }`).
private Json codeReviewArgs(string language) @safe
{
	Json j = Json.emptyObject;
	j["language"] = language;
	return j;
}

int main(string[] args) @safe
{
	return runClient(() @safe {
		auto client = connectFromArgs(args, "prompts-server");
		scope (exit)
			client.close();
		return run(client);
	});
}

/// The actual e2e: run every assertion against an initialized client. The body
/// is transport-agnostic, so the SAME checks verify stdio and HTTP.
int run(McpClient client) @safe
{
	client.initialize();

	// --- 1. prompts/list: exact names, titles, and argument descriptors. ---
	ListPromptsResult listed = client.listPrompts();
	auto names = listed.prompts.map!(p => p.name).array;
	names.sort();
	checkEq(names, ["code_review", "greet"], "prompts/list names");

	// greet: title + one required, described argument.
	auto greet = listed.prompts.canFindAndGet("greet");
	check(!greet.title.isNull && greet.title.get == "Greeting", "greet title is 'Greeting'");
	checkEq(greet.arguments.length, 1UL, "greet argument count");
	checkEq(greet.arguments[0].name, "name", "greet arg name");
	check(greet.arguments[0].required, "greet arg 'name' is required");
	check(!greet.arguments[0].description.isNull
			&& greet.arguments[0].description.get == "the person to greet", "greet arg description");

	// code_review: title + one argument (language).
	auto review = listed.prompts.canFindAndGet("code_review");
	check(!review.title.isNull && review.title.get == "Code Review", "code_review title");
	auto reviewArgNames = review.arguments.map!(a => a.name).array;
	checkEq(reviewArgNames, ["language"], "code_review arg order");

	// --- 2. prompts/get greet: the arg flows into the message text. ---
	// Build the prompt arguments as a JSON object (the untyped client request
	// surface).
	GetPromptResult greetResult = client.getPrompt("greet", greetArgs("Ada"));
	checkEq(greetResult.messages.length, 1UL, "greet message count");
	checkEq(greetResult.messages[0].role, "user", "greet message role");
	checkEq(greetResult.messages[0].content.kind, ContentKind.text, "greet message content kind");
	check(greetResult.messages[0].content.text.canFind("Ada"),
			"greet message mentions 'Ada' (arg flowed through)");

	// --- 3. prompts/get code_review: embedded-resource content block. ---
	GetPromptResult cr = client.getPrompt("code_review", codeReviewArgs("d"));
	checkEq(cr.messages.length, 2UL, "code_review message count");
	checkEq(cr.messages[0].content.kind, ContentKind.text, "code_review first message is text");
	// Second message: embedded resource carrying the snippet. Decode it with the
	// typed `Content.embeddedResource()` -> ResourceContents (uri/mimeType/text)
	// instead of poking at raw `resource["..."]` Json.
	checkEq(cr.messages[1].content.kind, ContentKind.embeddedResource,
			"code_review second message is an embedded resource");
	ResourceContents res = cr.messages[1].content.embeddedResource();
	checkEq(res.uri, "snippet://review.d", "embedded resource uri");
	checkEq(res.mimeType, "text/x-dlang", "embedded resource mimeType");
	checkEq(res.text, "void main() { int x; }", "embedded resource text == sample d snippet");

	// --- 4. completion/complete: prefix match on the language argument. ---
	auto comp = client.complete(CompletionReference.forPrompt("code_review"), "language", "ru");
	checkEq(comp.values, ["rust"], "completion for 'ru' -> [rust]");
	check(!comp.total.isNull && comp.total.get == 1, "completion total for 'ru' is 1");

	auto compP = client.complete(CompletionReference.forPrompt("code_review"), "language", "p");
	checkEq(compP.values, ["python"], "completion for 'p' -> [python]");

	// Empty prefix returns the full known-language list (9 entries).
	auto compAll = client.complete(CompletionReference.forPrompt("code_review"), "language", "");
	checkEq(compAll.values.length, 9UL, "completion for '' returns all 9 languages");

	// --- 5. error path: unknown prompt -> invalidParams (-32602). ---
	bool threw = false;
	try
		client.getPrompt("does_not_exist", Json.emptyObject);
	catch (McpException e)
	{
		threw = true;
		checkEq(cast(int) e.code, cast(int) ErrorCode.invalidParams,
				"unknown prompt error code is invalidParams (-32602)");
	}
	check(threw, "unknown prompt must raise an McpException");

	import std.stdio : writeln;

	() @trusted {
		writeln("OK: prompts/list (2), greet arg render, ",
				"code_review embedded resource, completion prefix-match ",
				"(ru->rust, p->python, ''->9), unknown-prompt -> -32602. All assertions passed.");
	}();
	return 0;
}

/// Small helper: find a prompt by name in a slice (asserts presence). Delegates
/// the scan to the SDK's `byName` accessor and unwraps, throwing when absent.
Prompt canFindAndGet(Prompt[] prompts, string name) @safe
{
	auto p = prompts.byName(name);
	if (p.isNull)
		throw new Exception("expected prompt not present: " ~ name);
	return p.get;
}

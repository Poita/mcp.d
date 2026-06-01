/// Prompts + completion example — CLIENT (self-verifying e2e test, dual-transport).
///
/// Drives the prompts + completion surface and ASSERTS concrete expected values.
/// On any mismatch it prints what differed and exits non-zero; on success it
/// prints an "OK:" summary and exits 0. Running this client IS the whole e2e
/// test — and the SAME assertions run over BOTH transports:
///
///   * STDIO (default): spawns the built `prompts-server` binary (WITHOUT --http)
///     and drives it over its stdin/stdout via `McpClient.stdio`, exactly like
///     examples/tools/client.d.
///   * HTTP (`--http <url>`): connects to an already-running server over
///     Streamable HTTP via `McpClient.http(url)`.
///
/// What it verifies (transport-agnostic):
///   * `prompts/list` contains exactly the two prompts the server registers,
///     with their titles and typed-argument descriptors.
///   * `prompts/get greet` renders the typed `name` argument into a text message.
///   * `prompts/get code_review` returns an embedded-resource content block
///     (uri + mimeType + text) carrying the snippet.
///   * `completion/complete` for the `language` argument prefix-matches the
///     server's known-language list (context-aware shape).
///   * an unknown prompt name yields a JSON-RPC invalidParams (-32602) error.
module prompts_client;

import std.algorithm : map, canFind, sort;
import std.array : array;
import std.format : format;
import std.getopt : getopt;
import std.path : dirName, buildPath;
import std.process : pipeProcess, ProcessPipes, Redirect, wait;
import std.stdio : writeln, stderr;
import std.string : stripRight;
import std.file : exists, thisExePath;

import mcp.client.client : McpClient;
import mcp.protocol.types : ContentKind, CompletionReference, CompleteResult,
	ListPromptsResult, GetPromptResult;
import mcp.protocol.errors : McpException, ErrorCode;
import vibe.data.json : Json;

/// Assert helper: print a clear diff and throw on failure.
void check(bool ok, lazy string what) @safe
{
	if (!ok)
		throw new Exception("ASSERTION FAILED: " ~ what);
}

void checkEq(T)(T actual, T expected, string what) @safe
{
	if (actual != expected)
		throw new Exception(format!"ASSERTION FAILED: %s — expected %s, got %s"(
				what, expected, actual));
}

/// Locate the built server binary. dub places sibling config target binaries in
/// the package directory; the client runs from there too, so look next to us.
string serverBinaryPath() @safe
{
	const dir = dirName(thisExePath);
	foreach (name; ["prompts-server", "prompts-server.exe"])
	{
		const p = buildPath(dir, name);
		if (exists(p))
			return p;
	}
	// Fallback: assume it is on PATH / same dir name.
	return buildPath(dir, "prompts-server");
}

int main(string[] args)
{
	string httpUrl;
	getopt(args, "http", "Connect over Streamable HTTP at this URL "
			~ "(e.g. http://127.0.0.1:8533/mcp); if omitted, spawn the server over stdio",
			&httpUrl);

	// --- Build the transport-specific client; everything after is identical. ---
	McpClient client;
	ProcessPipes* pipes; // non-null only on the stdio path (owns the subprocess)

	if (httpUrl.length)
	{
		// HTTP: connect to an already-running `prompts-server --http`.
		client = McpClient.http(httpUrl);
	}
	else
	{
		// STDIO: spawn the built server binary (WITHOUT --http) and drive it,
		// exactly like examples/tools/client.d. We heap-box the ProcessPipes so the
		// read/write closures and the cleanup path share one long-lived handle (a
		// stack-local ProcessPipes whose closures outlive its scope would have its
		// File handles refcounted to zero and closed).
		const serverBin = serverBinaryPath();
		if (!exists(serverBin))
		{
			() @trusted {
				stderr.writeln("FAIL: server binary not found at ", serverBin,
					" — build it first: dub build -c server");
			}();
			return 2;
		}
		pipes = new ProcessPipes;
		() @trusted {
			*pipes = pipeProcess([serverBin], Redirect.stdin | Redirect.stdout);
		}();
		client = McpClient.stdio(() @trusted {
			if (pipes.stdout.eof)
				return cast(string) null;
			auto ln = pipes.stdout.readln();
			if (ln.length == 0 && pipes.stdout.eof)
				return cast(string) null;
			return ln.stripRight("\r\n");
		}, (string s) @trusted { pipes.stdin.writeln(s); pipes.stdin.flush(); });
	}

	scope (exit)
		() @trusted {
			if (pipes !is null)
			{
				try
					pipes.stdin.close();
				catch (Exception) {}
				wait(pipes.pid);
			}
			else
				client.close();
		}();

	try
	{
		return run(client, httpUrl.length ? "http" : "stdio");
	}
	catch (Exception e)
	{
		() @trusted { stderr.writeln("FAIL: ", e.msg); }();
		return 1;
	}
}

/// The actual e2e: run every assertion against an initialized client. The body
/// is transport-agnostic, so the SAME checks verify stdio and HTTP.
int run(McpClient client, string transport) @safe
{
	client.initialize();

	// --- 1. prompts/list: exact names, titles, and argument descriptors. ---
	ListPromptsResult listed = client.listPrompts();
	auto names = listed.prompts.map!(p => p.name).array;
	names.sort();
	checkEq(names, ["code_review", "greet"], "prompts/list names");

	// greet: title + one required, described argument.
	auto greet = listed.prompts.canFindAndGet("greet");
	check(!greet.title.isNull && greet.title.get == "Greeting",
		"greet title is 'Greeting'");
	checkEq(greet.arguments.length, 1UL, "greet argument count");
	checkEq(greet.arguments[0].name, "name", "greet arg name");
	check(greet.arguments[0].required, "greet arg 'name' is required");
	check(!greet.arguments[0].description.isNull
		&& greet.arguments[0].description.get == "the person to greet",
		"greet arg description");

	// code_review: title + one argument (language).
	auto review = listed.prompts.canFindAndGet("code_review");
	check(!review.title.isNull && review.title.get == "Code Review",
		"code_review title");
	auto reviewArgNames = review.arguments.map!(a => a.name).array;
	checkEq(reviewArgNames, ["language"], "code_review arg order");

	// --- 2. prompts/get greet: typed arg flows into the message text. ---
	Json greetArgs = Json.emptyObject;
	greetArgs["name"] = "Ada";
	GetPromptResult greetResult = client.getPrompt("greet", greetArgs);
	checkEq(greetResult.messages.length, 1UL, "greet message count");
	checkEq(greetResult.messages[0].role, "user", "greet message role");
	checkEq(greetResult.messages[0].content.kind, ContentKind.text,
		"greet message content kind");
	check(greetResult.messages[0].content.text.canFind("Ada"),
		"greet message mentions 'Ada' (typed arg flowed through)");

	// --- 3. prompts/get code_review: embedded-resource content block. ---
	Json crArgs = Json.emptyObject;
	crArgs["language"] = "d";
	GetPromptResult cr = client.getPrompt("code_review", crArgs);
	checkEq(cr.messages.length, 2UL, "code_review message count");
	checkEq(cr.messages[0].content.kind, ContentKind.text,
		"code_review first message is text");
	// Second message: embedded resource carrying the snippet.
	auto embedded = cr.messages[1].content;
	checkEq(embedded.kind, ContentKind.embeddedResource,
		"code_review second message is an embedded resource");
	Json res = embedded.resource;
	checkEq(res["uri"].get!string, "snippet://review.d",
		"embedded resource uri");
	checkEq(res["mimeType"].get!string, "text/x-dlang",
		"embedded resource mimeType");
	checkEq(res["text"].get!string, "void main() { int x; }",
		"embedded resource text == sample d snippet");

	// --- 4. completion/complete: prefix match on the language argument. ---
	auto comp = client.complete(
		CompletionReference.forPrompt("code_review"), "language", "ru");
	checkEq(comp.values, ["rust"], "completion for 'ru' -> [rust]");
	check(!comp.total.isNull && comp.total.get == 1,
		"completion total for 'ru' is 1");

	auto compP = client.complete(
		CompletionReference.forPrompt("code_review"), "language", "p");
	checkEq(compP.values, ["python"], "completion for 'p' -> [python]");

	// Empty prefix returns the full known-language list (9 entries).
	auto compAll = client.complete(
		CompletionReference.forPrompt("code_review"), "language", "");
	checkEq(compAll.values.length, 9UL,
		"completion for '' returns all 9 languages");

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

	writeln("OK [", transport, "]: prompts/list (2), greet typed-arg render, ",
		"code_review embedded resource, completion prefix-match ",
		"(ru->rust, p->python, ''->9), unknown-prompt -> -32602. All assertions passed.");
	return 0;
}

/// Small helper: find a prompt by name in a slice (asserts presence).
auto canFindAndGet(P)(P[] prompts, string name) @safe
{
	foreach (p; prompts)
		if (p.name == name)
			return p;
	throw new Exception("expected prompt not present: " ~ name);
}

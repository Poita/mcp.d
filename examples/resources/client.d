/**
 * MCP Resources example — CLIENT + self-verifying E2E test (dual transport).
 *
 * The SAME client verifies the resources server over BOTH transports; the
 * assertions are transport-agnostic:
 *
 *   - stdio (default): spawn the built `resources-server` binary (no `--http`)
 *     and drive it over its stdin/stdout via `McpClient.stdio`, exactly like
 *     examples/tools/client.d.
 *   - http (`--http <url>`): connect with `McpClient.http(url)`.
 *
 * It speaks the stateless draft protocol (`enableDraft`) for two reasons: the
 * `CacheableResult` freshness hint rides inline on every `resources/read`, and a
 * `subscriptions/listen` stream is the ONE push mechanism the SDK supports over
 * both transports (the legacy standalone GET SSE stream is HTTP-only).
 *
 * What it verifies (identical over stdio and http):
 *   1. resources/list contains the static `config://app` resource.
 *   2. resources/templates/list contains the `note:///{id}` template.
 *   3. resources/read of `config://app` returns the expected JSON text.
 *   4. resources/read of `note:///welcome` (template expansion) returns the
 *      seeded body, with mimeType text/plain.
 *   5. resources/read of an unknown URI fails with an error (the draft aligns
 *      this to invalidParams -32602; stable revisions used -32002).
 *   6. the draft read of `config://app` surfaces the server's CacheableResult
 *      freshness hint (ttlMs == 60000, cacheScope == public).
 *   7. after subscriptions/listen, calling `set_note` delivers a
 *      notifications/resources/updated for the subscribed URI AND a
 *      notifications/resources/list_changed for the newly-created note resource;
 *      the new note then reads back its pushed body. The tool's typed
 *      `structuredContent` (uri + created) is asserted too.
 *
 * On success it prints a single "OK: ..." line and exits 0; on ANY mismatch it
 * prints what differed and exits non-zero, so CI can run it as a regression test.
 *
 * Run:
 *   stdio: dub run -c client                         # spawns the server itself
 *   http:  dub run -c server -- --http --port 8349   # terminal 1
 *          dub run -c client -- --http http://127.0.0.1:8349/mcp   # terminal 2
 */
module client;

import std.getopt : getopt;
import std.stdio : writeln, stderr;
import std.format : format;
import std.path : dirName, buildPath;
import std.file : exists, thisExePath;
import std.process : pipeProcess, ProcessPipes, Redirect, wait;
import std.string : stripRight;
import core.time : msecs, MonoTime;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep, yield;
import vibe.data.json : Json;

import mcp.client.client : McpClient;
import mcp.client.subscription : SubscriptionFilter, SubscriptionStream;
import mcp.protocol.draft : CacheScope;
import mcp.protocol.errors : ErrorCode, McpException;

// Expected contract — must match server.d.
enum string expectedConfig = `{"name":"resources-example","featureFlags":["resources","subscribe"]}`;
enum long expectedTtlMs = 60_000;

private int failures;

private void fail(string msg) @trusted
{
	stderr.writeln("FAIL: ", msg);
	failures++;
}

private void check(bool cond, lazy string msg) @safe
{
	if (!cond)
		fail(msg);
}

/// Locate the built server binary next to this client binary (dub writes both
/// into the package root), independent of the current working directory.
private string serverBinaryPath() @safe
{
	const dir = dirName(thisExePath);
	foreach (name; ["resources-server", "resources-server.exe"])
	{
		const p = buildPath(dir, name);
		if (exists(p))
			return p;
	}
	return buildPath(dir, "resources-server");
}

int main(string[] args)
{
	string httpUrl;
	getopt(args, "http", "Connect over Streamable HTTP to this MCP URL "
			~ "(e.g. http://127.0.0.1:8349/mcp); omit for stdio", &httpUrl);

	int rc;
	// The SDK transport does its I/O on the vibe event loop, so run the e2e
	// inside a runTask and exit the loop when done. This also lets the HTTP
	// `subscriptions/listen` background stream task be pumped.
	runTask(() nothrow {
		scope (exit)
			exitEventLoop();
		try
			rc = run(httpUrl);
		catch (Exception e)
		{
			try
				stderr.writeln("FAIL (exception): ", e.msg);
			catch (Exception)
			{
			}
			rc = 1;
		}
	});
	runEventLoop();
	return rc;
}

int run(string httpUrl) @safe
{
	const overHttp = httpUrl.length != 0;

	// --- connect over the selected transport --------------------------------
	McpClient client;
	// stdio only: the spawned server subprocess pipes, kept alive for the run.
	ProcessPipes* pipes;

	if (overHttp)
	{
		client = McpClient.http(httpUrl);
	}
	else
	{
		const serverBin = serverBinaryPath();
		if (!exists(serverBin))
		{
			fail("server binary not found at " ~ serverBin
					~ " — build it first: dub build -c server");
			return 2;
		}
		// Heap-box the ProcessPipes so the read/write closures and the cleanup
		// path share one long-lived handle (a stack-local would have its File
		// handles refcounted to zero when this helper returns).
		pipes = () @trusted { return new ProcessPipes; }();
		() @trusted { *pipes = pipeProcess([serverBin], Redirect.stdin | Redirect.stdout); }();
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
		if (pipes !is null)
			() @trusted {
				try
					pipes.stdin.close();
				catch (Exception)
				{
				}
				wait(pipes.pid);
			}();

	// Speak the stateless draft: cache hints ride inline on resources/read, and
	// subscriptions/listen is the cross-transport push mechanism.
	client.enableDraft();
	auto disc = client.discover();
	check(disc.serverInfo.name == "resources-example",
			format("discover serverInfo.name = %s (want resources-example)",
				disc.serverInfo.name));

	// (1) resources/list contains the static resource.
	auto list = client.listResources();
	bool hasConfig;
	foreach (r; list.resources)
		if (r.uri == "config://app")
			hasConfig = true;
	check(hasConfig, "resources/list missing config://app");

	// (2) templates/list contains the note template.
	auto tmpls = client.listResourceTemplates();
	bool hasTmpl;
	foreach (t; tmpls.resourceTemplates)
		if (t.uriTemplate == "note:///{id}")
			hasTmpl = true;
	check(hasTmpl, "templates/list missing note:///{id}");

	// (3) read the static resource.
	auto cfg = client.readResource("config://app");
	check(cfg.contents.length == 1, "config read: expected 1 content block");
	const cfgText = cfg.contents.length ? cfg.contents[0].text : "";
	check(cfgText == expectedConfig, format("config text mismatch: got %s", cfgText));

	// (6) draft read surfaces the CacheableResult freshness hint (inline).
	check(!cfg.cache.isNull, "draft read: expected a cache hint on config://app");
	if (!cfg.cache.isNull)
	{
		check(cfg.cache.get.ttlMs == expectedTtlMs,
				format("cache ttlMs mismatch: got %d", cfg.cache.get.ttlMs));
		check(cfg.cache.get.cacheScope == CacheScope.public_,
				"cache scope mismatch: expected public");
	}

	// (4) read a template-expanded resource.
	auto note = client.readResource("note:///welcome");
	check(note.contents.length == 1, "note read: expected 1 content block");
	check(note.contents.length && note.contents[0].text == "Hello from the resources example.",
			"note:///welcome text mismatch");
	check(note.contents.length && note.contents[0].mimeType == "text/plain",
			"note:///welcome mimeType mismatch");

	// (5) unknown resource read raises an error. NOTE: the draft protocol aligns
	// the resources/read not-found code to invalidParams (-32602); the stable
	// revisions used resourceNotFound (-32002). We speak draft (for the inline
	// cache hint above), so we expect -32602. Pick a URI that matches neither the
	// direct resource nor the note template.
	bool threw;
	try
		client.readResource("other:///x");
	catch (McpException e)
	{
		threw = true;
		check(e.code == ErrorCode.invalidParams,
				format("unknown read: expected -32602 (draft not-found), got %d", e.code));
	}
	check(threw, "unknown resource read did not raise an error");

	// (7) subscribe via subscriptions/listen + observe push notifications.
	int updated;
	int listChanged;
	string updatedUri;
	client.onNotification = (string method, Json params) @safe nothrow {
		if (method == "notifications/resources/updated")
		{
			updated++;
			try
				updatedUri = params["uri"].get!string;
			catch (Exception)
			{
			}
		}
		else if (method == "notifications/resources/list_changed")
			listChanged++;
	};

	const targetUri = "note:///e2e";
	SubscriptionFilter filter = {
		resourcesListChanged: true,
		resourceSubscriptions: [targetUri],
	};
	auto stream = client.subscriptionsListen(filter);
	scope (exit)
		stream.close();
	// Let the listen stream attach (HTTP opens a background SSE task; stdio
	// shares the single channel and needs no settle time, but a couple of yields
	// are harmless).
	sleep(200.msecs);

	// Mutate the subscribed note via the tool; the server pushes
	// resources/updated (subscribed) + resources/list_changed (new resource).
	Json toolArgs = Json.emptyObject;
	toolArgs["id"] = "e2e";
	toolArgs["body"] = "pushed body";
	auto callRes = client.callTool("set_note", toolArgs);
	check(!callRes.isError, "set_note should not be an error");
	check(callRes.structuredContent["uri"].get!string == targetUri,
			"set_note structuredContent.uri mismatch");
	check(callRes.structuredContent["created"].get!bool == true,
			"set_note should report created=true for a new note");

	// Wait for the notifications. Over stdio they interleave on the single
	// channel during the readResource await below; over http they arrive on the
	// background listen task. Yield + poll covers both.
	const deadline = MonoTime.currTime + 5000.msecs;
	while (MonoTime.currTime < deadline && (updated == 0 || listChanged == 0))
	{
		() @trusted { yield(); }();
		sleep(50.msecs);
		// On stdio, notifications only drain while the client is reading a
		// response, so issue a cheap request to pump the channel.
		if (updated == 0 || listChanged == 0)
			client.ping();
	}

	check(updated >= 1, "did not receive notifications/resources/updated");
	check(updatedUri == targetUri,
			format("updated notification uri mismatch: got %s", updatedUri));
	check(listChanged >= 1, "did not receive notifications/resources/list_changed");

	// The newly-created note is now a direct resource and reads back.
	auto pushed = client.readResource(targetUri);
	check(pushed.contents.length && pushed.contents[0].text == "pushed body",
			"new note resource did not read back the pushed body");

	if (failures)
	{
		() @trusted {
			stderr.writeln(format("FAIL: %d assertion(s) failed over %s",
					failures, overHttp ? "http" : "stdio"));
		}();
		return 1;
	}
	writeln("OK [", overHttp ? "http" : "stdio", "]: list+templates+read+template-expand"
			~ "+notfound(-32602 draft)+draft-cache(ttl=60000,public)+subscribe/updated+list_changed"
			~ " verified");
	return 0;
}

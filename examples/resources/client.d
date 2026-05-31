/**
 * MCP Resources example — CLIENT + self-verifying E2E test (Streamable HTTP).
 *
 * Connects to the resources server (default http://127.0.0.1:8349/mcp) and
 * asserts its Resources behaviour end-to-end. On success it prints a single
 * "OK: ..." line and exits 0; on ANY mismatch it prints what differed and
 * exits non-zero, so CI can run it as a regression test.
 *
 * What it verifies:
 *   1. resources/list contains the static `config://app` resource.
 *   2. resources/templates/list contains the `note:///{id}` template.
 *   3. resources/read of `config://app` returns the expected JSON text.
 *   4. resources/read of `note:///welcome` (template expansion) returns the
 *      seeded body, with mimeType text/plain.
 *   5. resources/read of an unknown URI fails with the resourceNotFound
 *      (-32002) error code.
 *   6. A draft-protocol read of `config://app` surfaces the server's
 *      CacheableResult freshness hint (ttlMs == 60000, cacheScope == public).
 *   7. After resources/subscribe + opening the server->client stream, calling
 *      the `set_note` tool delivers a notifications/resources/updated for the
 *      subscribed URI, AND a notifications/resources/list_changed for the
 *      newly-created note resource.
 *
 * Run:  (terminal 1) dub run -c server
 *       (terminal 2) dub run -c client
 *   The client exits 0 iff every assertion held.
 */
module client;

import mcp;
import mcp.protocol.draft : CacheScope;
import mcp.protocol.errors : ErrorCode, McpException;

import std.stdio : writeln, stderr;
import std.format : format;
import core.time : msecs, MonoTime;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.data.json : Json;

enum string serverUrl = "http://127.0.0.1:8349/mcp";

// Exit code threaded out of the event-loop task. The vibe event loop is
// single-threaded here, so a plain module global is fine.
int exitCode = 0;

void fail(string msg) @trusted
{
	stderr.writeln("FAIL: ", msg);
	exitCode = 1;
}

void check(bool cond, string msg) @trusted
{
	if (!cond)
		fail(msg);
}

void main()
{
	runTask(() nothrow {
		scope (exit)
			exitEventLoop();
		try
			runChecks();
		catch (Exception e)
		{
			try
				stderr.writeln("FAIL (exception): ", e.msg);
			catch (Exception)
			{
			}
			exitCode = 1;
		}
	});
	runEventLoop();

	import core.stdc.stdlib : exit;

	exit(exitCode);
}

void runChecks() @trusted
{
	auto client = McpClient.http(serverUrl);
	client.initialize();

	// (1) resources/list contains the static resource.
	auto list = client.listResources();
	bool hasConfig = false;
	foreach (r; list.resources)
		if (r.uri == "config://app")
			hasConfig = true;
	check(hasConfig, "resources/list missing config://app");

	// (2) templates/list contains the note template.
	auto tmpls = client.listResourceTemplates();
	bool hasTmpl = false;
	foreach (t; tmpls.resourceTemplates)
		if (t.uriTemplate == "note:///{id}")
			hasTmpl = true;
	check(hasTmpl, "templates/list missing note:///{id}");

	// (3) read the static resource.
	auto cfg = client.readResource("config://app");
	check(cfg.contents.length == 1, "config read: expected 1 content block");
	const cfgText = cfg.contents.length ? cfg.contents[0].text : "";
	const expectedCfg = `{"name":"resources-example","featureFlags":["resources","subscribe"]}`;
	check(cfgText == expectedCfg,
		format("config text mismatch: got %s", cfgText));

	// (4) read a template-expanded resource.
	auto note = client.readResource("note:///welcome");
	check(note.contents.length == 1, "note read: expected 1 content block");
	check(note.contents.length && note.contents[0].text == "Hello from the resources example.",
		"note:///welcome text mismatch");
	check(note.contents.length && note.contents[0].mimeType == "text/plain",
		"note:///welcome mimeType mismatch");

	// (5) unknown resource -> resourceNotFound (-32002).
	bool threw = false;
	try
		client.readResource("note:///does-not-exist-as-direct/../nope:bad");
	catch (McpException e)
	{
		threw = true;
		check(e.code == ErrorCode.resourceNotFound,
			format("unknown read: expected -32002, got %d", e.code));
	}
	// Note: an unmatched template still routes to not-found; pick a URI that
	// matches neither the direct resource nor the note template.
	if (!threw)
	{
		try
			client.readResource("other:///x");
		catch (McpException e)
		{
			threw = true;
			check(e.code == ErrorCode.resourceNotFound,
				format("unknown read: expected -32002, got %d", e.code));
		}
	}
	check(threw, "unknown resource read did not raise an error");

	// (6) draft read surfaces the CacheableResult freshness hint.
	auto draft = McpClient.http(serverUrl);
	draft.enableDraft();
	auto dcfg = draft.readResource("config://app");
	check(!dcfg.cache.isNull, "draft read: expected a cache hint");
	if (!dcfg.cache.isNull)
	{
		check(dcfg.cache.get.ttlMs == 60_000,
			format("cache ttlMs mismatch: got %d", dcfg.cache.get.ttlMs));
		check(dcfg.cache.get.cacheScope == CacheScope.public_,
			"cache scope mismatch: expected public");
	}

	// (7) subscribe + receive push notifications on the server->client stream.
	int updated = 0;
	int listChanged = 0;
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
	client.subscribe(targetUri);
	client.startServerStream(); // open the standalone GET SSE stream
	sleep(200.msecs); // let the stream attach

	// Mutate the subscribed note via the tool; the server pushes
	// resources/updated (subscribed) + resources/list_changed (new resource).
	Json args = Json.emptyObject;
	args["id"] = "e2e";
	args["body"] = "pushed body";
	auto callRes = client.callTool("set_note", args);
	check(callRes.structuredContent["uri"].get!string == targetUri,
		"set_note result uri mismatch");
	check(callRes.structuredContent["created"].get!bool == true,
		"set_note should report created=true for a new note");

	// Wait for the notifications to arrive on the SSE stream.
	const deadline = MonoTime.currTime + 5000.msecs;
	while (MonoTime.currTime < deadline && (updated == 0 || listChanged == 0))
		sleep(50.msecs);

	check(updated >= 1, "did not receive notifications/resources/updated");
	check(updatedUri == targetUri,
		format("updated notification uri mismatch: got %s", updatedUri));
	check(listChanged >= 1, "did not receive notifications/resources/list_changed");

	// The newly-created note is now a direct resource and reads back.
	auto pushed = client.readResource(targetUri);
	check(pushed.contents.length && pushed.contents[0].text == "pushed body",
		"new note resource did not read back the pushed body");

	if (exitCode == 0)
		writeln("OK: list+templates+read+template-expand+notfound(-32002)+draft-cache(ttl=60000,public)"
			~ " +subscribe/updated+list_changed verified");
}

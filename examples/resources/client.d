/**
 * MCP Resources example — CLIENT + self-verifying E2E test (dual transport).
 *
 * The SAME client verifies the resources server over BOTH transports; the
 * assertions are transport-agnostic. Transport selection and event-loop wiring
 * are delegated to the shared `examples_common` scaffold:
 *
 *   - stdio (default): `connectFromArgs` spawns the sibling `resources-server`
 *     binary (resolved next to this client) over stdio.
 *   - http (`--http <url>` / `--url <url>`): `connectFromArgs` connects with
 *     `McpClient.http(url)`.
 *
 * It speaks the stateless draft protocol (`enableModern`) for two reasons: the
 * `CacheableResult` freshness hint rides inline on every `resources/read`, and a
 * `subscriptions/listen` stream is the ONE push mechanism the SDK supports over
 * both transports (the standalone GET SSE stream is HTTP-only).
 *
 * What it verifies (identical over stdio and http):
 *   1. resources/list contains the static `config://app` resource.
 *   2. resources/templates/list contains the `note:///{id}` template.
 *   3. resources/read of `config://app` returns the expected JSON text.
 *   4. resources/read of `note:///welcome` (template expansion) returns the
 *      seeded body, with mimeType text/plain.
 *   5. resources/read of an unknown URI fails with an error (the draft maps
 *      not-found to invalidParams -32602).
 *   6. the draft read of `config://app` surfaces the server's CacheableResult
 *      freshness hint (ttl == 60.seconds, wire ttlMs == 60000, cacheScope == public).
 *   7. after subscriptions/listen, calling `set_note` delivers a
 *      notifications/resources/updated for the subscribed URI AND a
 *      notifications/resources/list_changed for the newly-created note resource;
 *      the new note then reads back its pushed body. The tool is invoked with a
 *      typed args struct and its typed `structuredContent` is decoded with
 *      `structuredContentAs!SetNoteResult` (uri + created) before asserting. The
 *      resources/updated notification is parsed with
 *      `ResourceUpdatedNotification.fromJson` rather than raw `params["uri"]`.
 *
 * On success it prints a single "OK: ..." line and exits 0; on ANY mismatch it
 * throws (via the shared `check`) so `runClient` maps it to a non-zero exit.
 *
 * Run:
 *   stdio: dub run -c client                         # spawns the server itself
 *   http:  dub run -c server -- --http --port 8349   # terminal 1
 *          dub run -c client -- --http http://127.0.0.1:8349/mcp   # terminal 2
 */
module client;

import std.stdio : writeln;
import std.format : format;
import core.time : msecs, seconds, Duration, MonoTime;

import vibe.core.core : sleep, yield;
import vibe.data.json : Json;

import mcp.client.client : McpClient;
import mcp.client.subscription : SubscriptionFilter, SubscriptionStream;
import mcp.protocol.modern : CacheScope;
import mcp.protocol.errors : ErrorCode, McpException;
import mcp.protocol.types : ResourceUpdatedNotification;

import examples_common;

// Expected contract — must match server.d.
enum string expectedConfig = `{"name":"resources-example","featureFlags":["resources","subscribe"]}`;
enum Duration expectedTtl = 60.seconds;

/// Typed arguments for the `set_note` tool. Passing this struct to the typed
/// `callTool(name, T args)` overload lets the SDK serialize the wire arguments
/// for a fixed-shape call.
struct SetNoteArgs
{
	string id;
	string body;
}

/// Mirrors the server's typed `SetNoteResult`. Decoding the tool's
/// `structuredContent` with `structuredContentAs!SetNoteResult` yields these
/// fields directly, so the client asserts on typed values instead of raw Json.
struct SetNoteResult
{
	string uri;
	bool created;
}

int main(string[] args) @safe
{
	return runClient(() @safe { return run(args); });
}

int run(string[] args) @safe
{
	// The push phase (subscriptions/listen + notifications/resources/updated)
	// runs over BOTH transports. subscriptions/listen is a DRAFT RPC and the draft is
	// stateless-only, so it works on this STATELESS server: the POST opens one
	// long-lived SSE stream and set_note -> notifyResourceUpdated streams
	// notifications/resources/updated (+ resources/list_changed) down THAT same
	// stream, in-process — no session, no second correlated HTTP call. stdio behaves
	// identically (the only difference being the subscriptionId tagging).

	// --- connect over the selected transport (stdio sibling / http url) -----
	auto client = connectFromArgs(args, "resources-server");
	// Both transports release cleanly via close() (stdio terminates the
	// subprocess; http stops any background streams).
	scope (exit)
		client.close();

	// Speak the stateless draft: cache hints ride inline on resources/read, and
	// subscriptions/listen is the cross-transport push mechanism.
	client.enableModern();
	auto disc = client.discover();
	checkEq(disc.serverInfo.name, "resources-example", "discover serverInfo.name");

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
	checkEq(cfg.contents.length, cast(size_t) 1, "config read: content block count");
	const cfgText = cfg.contents.length ? cfg.contents[0].text : "";
	checkEq(cfgText, expectedConfig, "config text");

	// (6) draft read surfaces the CacheableResult freshness hint (inline).
	check(!cfg.cache.isNull, "draft read: expected a cache hint on config://app");
	if (!cfg.cache.isNull)
	{
		checkEq(cfg.cache.get.ttl, expectedTtl, "cache ttl");
		check(cfg.cache.get.cacheScope == CacheScope.public_,
				"cache scope mismatch: expected public");
	}

	// (4) read a template-expanded resource.
	auto note = client.readResource("note:///welcome");
	checkEq(note.contents.length, cast(size_t) 1, "note read: content block count");
	check(note.contents.length && note.contents[0].text == "Hello from the resources example.",
			"note:///welcome text mismatch");
	check(note.contents.length && note.contents[0].mimeType == "text/plain",
			"note:///welcome mimeType mismatch");

	// (5) unknown resource read raises an error. The draft protocol maps the
	// resources/read not-found code to invalidParams (-32602). Pick a URI that
	// matches neither the direct resource nor the note template.
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
	// This runs over BOTH transports. subscriptions/listen opens a single
	// self-contained long-lived stream; set_note -> notifyResourceUpdated streams
	// resources/updated (subscribed URI) + resources/list_changed (new resource) down
	// THAT stream — in-process on this stateless server, no second correlated call.
	int updated;
	int listChanged;
	string updatedUri;
	client.onNotification = (string method, Json params) @safe nothrow{
		if (method == ResourceUpdatedNotification.methodName)
		{
			updated++;
			// Parse the typed notification payload instead of reading raw
			// `params["uri"]`. `fromJson` is `@safe` but not `nothrow`, and the
			// notification sink must be `nothrow`, so guard it.
			try
				updatedUri = ResourceUpdatedNotification.fromJson(params).uri;
			catch (Exception)
			{
			}
		}
		else if (method == "notifications/resources/list_changed")
			listChanged++;
	};

	const targetUri = "note:///e2e";
	SubscriptionFilter filter = {
		resourcesListChanged: true, resourceSubscriptions: [targetUri],
	};
	auto stream = client.subscriptionsListen(filter);
	scope (exit)
		stream.close();
	// Let the listen stream attach (stdio shares the single channel and needs no
	// settle time, but a couple of yields are harmless).
	sleep(200.msecs);

	// Mutate the subscribed note via the tool; the server pushes
	// resources/updated (subscribed) + resources/list_changed (new resource).
	// The args have a fixed shape, so pass a typed struct to the typed callTool
	// overload rather than hand-building a Json object.
	auto callRes = client.callTool("set_note", SetNoteArgs("e2e", "pushed body"));
	check(!callRes.isError, "set_note should not be an error");
	// Decode the tool's typed structuredContent in one step instead of reading
	// raw Json fields, then assert on the typed values.
	auto setResult = callRes.structuredContentAs!SetNoteResult;
	checkEq(setResult.uri, targetUri, "set_note structuredContent.uri");
	check(setResult.created == true, "set_note should report created=true for a new note");

	// Wait for the notifications. Over stdio they interleave on the single
	// channel during the readResource await below. Yield + poll covers it.
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
	checkEq(updatedUri, targetUri, "updated notification uri");
	check(listChanged >= 1, "did not receive notifications/resources/list_changed");

	// The newly-created note is now a direct resource and reads back.
	auto pushed = client.readResource(targetUri);
	check(pushed.contents.length && pushed.contents[0].text == "pushed body",
			"new note resource did not read back the pushed body");

	writeln("OK [resources]: list+templates+read+template-expand"
			~ "+notfound(-32602 draft)+draft-cache(ttl=60000,public)+subscribe/updated+list_changed"
			~ " verified");
	return 0;
}

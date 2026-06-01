/**
 * Caching (CacheableResult) example — client side AND self-verifying e2e test,
 * over BOTH stdio and Streamable HTTP.
 *
 * Connects to the caching server (draft / stateless), then asserts the server's
 * cache behavior matches exactly what server.d set:
 *
 *   1. resources/list carries the PER-LIST hint (ttlMs=5000, scope=public)
 *      and lists both registered resources.
 *   2. reading config://app carries the PER-RESOURCE hint
 *      (ttlMs=60000, scope=private) and the expected body.
 *   3. reading status://live (no hint) carries NO cache hint.
 *
 * Transport selection (same assertions either way):
 *   - default (no --http): spawn the built `caching-server` binary over stdio
 *     and drive it via McpClient.stdio(&proc.readLine, &proc.writeLine)
 *     (exactly the pattern in examples/tools/client.d).
 *   - `--http <url>`: connect to a running HTTP server via McpClient.http(url).
 *
 * On success it prints "OK: ..." and exits 0. On ANY mismatch it prints what
 * differed and exits non-zero, so CI can run it as a behavioral regression test.
 *
 * Run:
 *   # stdio: the client spawns the server for you
 *   dub run -c client
 *
 *   # http: start the server first, then point the client at it
 *   dub run -c server -- --http --port 8531
 *   dub run -c client -- --http http://127.0.0.1:8531/mcp
 */
module caching_client;

import std.getopt : getopt;
import std.stdio : writeln, stderr;
import std.algorithm : map, canFind;
import std.array : array;
import std.format : format;
import std.process : ProcessPipes, pipeProcess, Redirect, wait;
import std.string : stripRight;

import mcp;
import mcp.client.client : McpClient;
import mcp.protocol.draft : CacheScope;

// Expected contract — must match the enums/values in server.d.
enum long ExpectConfigTtlMs = 60_000;
enum long ExpectListTtlMs = 5_000;

/// Owns the server subprocess and exposes the newline-delimited JSON-RPC channel
/// expected by `McpClient.stdio`. Holding `ProcessPipes` in a class field keeps
/// the stdin/stdout `File` handles alive for the lifetime of the client (a stack
/// value would be destructed when the spawning helper returns).
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

/// Absolute path to the `caching-server` binary, resolved next to this client
/// binary (dub writes both into the package root), independent of cwd.
private string serverBinaryPath() @safe
{
	import std.file : thisExePath;
	import std.path : dirName, buildPath;

	return buildPath(dirName(thisExePath()), "caching-server");
}

int main(string[] args)
{
	string url; // empty -> stdio (spawn the server); set -> HTTP
	getopt(args, "http", "Connect to a running HTTP server at this MCP endpoint "
			~ "(e.g. http://127.0.0.1:8531/mcp); omit for stdio", &url);

	string[] failures;
	void check(bool cond, lazy string msg) @safe
	{
		if (!cond)
			failures ~= msg;
	}

	// --- transport selection ------------------------------------------------
	McpClient client;
	ServerProcess proc;
	scope (exit)
		if (proc !is null)
			proc.shutdown();

	if (url.length)
	{
		client = McpClient.http(url);
	}
	else
	{
		proc = new ServerProcess([serverBinaryPath()]);
		client = McpClient.stdio(&proc.readLine, &proc.writeLine);
	}

	// Cache hints are a draft-only feature: speak the stateless draft protocol.
	// Transport-agnostic — the same call works over stdio and HTTP.
	client.enableDraft();

	// --- 1. resources/list carries the per-list cache hint --------------------
	auto list = client.listResources();
	auto names = list.resources.map!(r => r.uri).array;
	check(names.canFind("config://app"),
		format("resources/list missing config://app; got %s", names));
	check(names.canFind("status://live"),
		format("resources/list missing status://live; got %s", names));

	check(!list.cache.isNull, "resources/list result carried NO cache hint (expected one)");
	if (!list.cache.isNull)
	{
		check(list.cache.get.ttlMs == ExpectListTtlMs,
			format("resources/list ttlMs = %d, expected %d",
				list.cache.get.ttlMs, ExpectListTtlMs));
		check(list.cache.get.cacheScope == CacheScope.public_,
			format("resources/list cacheScope = %s, expected public",
				cast(string) list.cache.get.cacheScope));
	}

	// --- 2. reading config://app carries the per-resource cache hint ----------
	auto cfg = client.readResource("config://app");
	check(cfg.contents.length == 1,
		format("config://app returned %d content blocks, expected 1", cfg.contents.length));
	if (cfg.contents.length >= 1)
	{
		check(cfg.contents[0].text == `{"theme":"dark","retries":3}`,
			format("config://app body = %s", cfg.contents[0].text));
	}
	check(!cfg.cache.isNull, "config://app read carried NO cache hint (expected one)");
	if (!cfg.cache.isNull)
	{
		check(cfg.cache.get.ttlMs == ExpectConfigTtlMs,
			format("config://app ttlMs = %d, expected %d",
				cfg.cache.get.ttlMs, ExpectConfigTtlMs));
		check(cfg.cache.get.cacheScope == CacheScope.private_,
			format("config://app cacheScope = %s, expected private",
				cast(string) cfg.cache.get.cacheScope));
	}

	// --- 3. reading status://live carries NO cache hint -----------------------
	auto st = client.readResource("status://live");
	check(st.cache.isNull,
		"status://live read carried a cache hint, but the server set none");

	if (failures.length)
	{
		stderr.writeln("FAIL: caching example assertions did not hold:");
		foreach (f; failures)
			stderr.writeln("  - ", f);
		return 1;
	}

	writeln(format(
		"OK: [%s] list hint ttlMs=%d/public, config://app hint ttlMs=%d/private, status://live uncached",
		url.length ? "http" : "stdio", ExpectListTtlMs, ExpectConfigTtlMs));
	return 0;
}

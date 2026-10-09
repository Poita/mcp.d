/// Minimal standalone MCP client for `server.d`: connects over stdio by
/// spawning the sibling `hello-server` binary, or over Streamable HTTP with
/// `--http <url>`, then calls `greet` and checks the reply.
module hello_client;

import std.getopt : getopt;
import std.stdio : writeln;

import mcp;

int main(string[] args)
{
	string url;
	getopt(args, "http", "Streamable HTTP endpoint, e.g. http://127.0.0.1:8540/mcp.", &url);

	const text = runWithEventLoop(() @safe {
		auto client = url.length ? McpClient.http(url) : McpClient.spawnSibling("hello-server");
		scope (exit)
			client.close();
		client.connect();

		auto result = client.callTool("greet", parseJsonString(`{"name": "Ada"}`));
		return result.content[0].text;
	});

	writeln(text);
	return text == "Hello, Ada!" ? 0 : 1;
}

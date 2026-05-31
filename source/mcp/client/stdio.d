module mcp.client.stdio;

import std.typecons : Nullable;

import vibe.data.json : Json, parseJsonString;

import mcp.protocol.jsonrpc;
import mcp.protocol.errors;
import mcp.protocol.versions;
import mcp.protocol.capabilities;
import mcp.protocol.types;
import mcp.client.client : resolveNegotiatedVersion;

@safe:

/// A Model Context Protocol client over the **stdio** transport.
///
/// Per the MCP stdio transport, the host launches the MCP server as a
/// subprocess and exchanges newline-delimited JSON-RPC messages over its
/// `stdin`/`stdout`; only valid MCP messages are written to the server's
/// `stdin` (newlines are never embedded in a message), and `stderr` is used by
/// the server for logging.
///
/// This class is transport-pure: it is constructed with a `readLine`/`writeLine`
/// pair (symmetric to `mcp.transport.stdio.serveStdio` on the server side) and
/// drives the lifecycle (`initialize` + `notifications/initialized`) and the
/// server features (tools, resources, prompts, logging, subscriptions) with
/// auto-pagination. Use `spawnStdioClient` for the common case of launching a
/// child process and wiring this to its pipes.
final class StdioClient
{
    private string delegate() @safe readLine;
    private void delegate(string) @safe writeLine;
    private ProtocolVersion negotiated = latestStable;
    private bool didInitialize;
    private long nextId = 1;

    /// Capabilities this client advertises at initialize.
    ClientCapabilities capabilities;
    /// This client's identity.
    Implementation clientInfo;

    /// Observer for inbound notifications received while awaiting a response
    /// (progress, message, resource updates).
    void delegate(string method, Json params) @safe onNotification;

    /// Construct over a newline-delimited JSON-RPC channel. `readLine` returns
    /// the next line from the server (without its terminator) or `null` at
    /// end-of-input; `writeLine` emits one request/notification line to the
    /// server (the sink appends the terminator).
    this(string delegate() @safe readLine, void delegate(string) @safe writeLine,
            Implementation clientInfo = Implementation("dlang-mcp-client", "0.1.0")) @safe
    {
        this.readLine = readLine;
        this.writeLine = writeLine;
        this.clientInfo = clientInfo;
    }

    /// The protocol version negotiated with the server (valid after initialize).
    ProtocolVersion protocolVersion() const @safe
    {
        return negotiated;
    }

    /// Perform the initialize handshake and send `notifications/initialized`.
    InitializeResult initialize(string requestedVersion = latestStable.toWire) @safe
    {
        InitializeParams params;
        params.protocolVersion = requestedVersion;
        params.capabilities = capabilities;
        params.clientInfo = clientInfo;

        auto result = rpc("initialize", params.toJson());
        auto init = InitializeResult.fromJson(result);
        // Per the Lifecycle / Version Negotiation rules: if the client does not
        // support the version in the server's response it SHOULD disconnect.
        negotiated = resolveNegotiatedVersion(init.protocolVersion);
        didInitialize = true;
        notify("notifications/initialized", Json.emptyObject);
        return init;
    }

    /// `ping` — returns when the server acknowledges.
    void ping() @safe
    {
        rpc("ping", Json.emptyObject);
    }

    /// `tools/list`, following pagination cursors to completion.
    Tool[] listTools() @safe
    {
        Tool[] all;
        Nullable!string cursor;
        do
        {
            Json p = Json.emptyObject;
            if (!cursor.isNull)
                p["cursor"] = cursor.get;
            auto res = ListToolsResult.fromJson(rpc("tools/list", p));
            all ~= res.tools;
            cursor = res.nextCursor;
        }
        while (!cursor.isNull);
        return all;
    }

    /// `tools/call`.
    CallToolResult callTool(string name, Json arguments = Json.emptyObject) @safe
    {
        Json p = Json.emptyObject;
        p["name"] = name;
        p["arguments"] = arguments;
        return CallToolResult.fromJson(rpc("tools/call", p));
    }

    /// `resources/list`, auto-paginated.
    Resource[] listResources() @safe
    {
        Resource[] all;
        Nullable!string cursor;
        do
        {
            Json p = Json.emptyObject;
            if (!cursor.isNull)
                p["cursor"] = cursor.get;
            auto res = ListResourcesResult.fromJson(rpc("resources/list", p));
            all ~= res.resources;
            cursor = res.nextCursor;
        }
        while (!cursor.isNull);
        return all;
    }

    /// `resources/read`.
    ReadResourceResult readResource(string uri) @safe
    {
        Json p = Json.emptyObject;
        p["uri"] = uri;
        return ReadResourceResult.fromJson(rpc("resources/read", p));
    }

    /// `prompts/list`, auto-paginated.
    Prompt[] listPrompts() @safe
    {
        Prompt[] all;
        Nullable!string cursor;
        do
        {
            Json p = Json.emptyObject;
            if (!cursor.isNull)
                p["cursor"] = cursor.get;
            auto res = ListPromptsResult.fromJson(rpc("prompts/list", p));
            all ~= res.prompts;
            cursor = res.nextCursor;
        }
        while (!cursor.isNull);
        return all;
    }

    /// `prompts/get`.
    GetPromptResult getPrompt(string name, Json arguments = Json.emptyObject) @safe
    {
        Json p = Json.emptyObject;
        p["name"] = name;
        p["arguments"] = arguments;
        return GetPromptResult.fromJson(rpc("prompts/get", p));
    }

    /// `resources/subscribe` / `resources/unsubscribe`.
    void subscribe(string uri) @safe
    {
        Json p = Json.emptyObject;
        p["uri"] = uri;
        rpc("resources/subscribe", p);
    }

    void unsubscribe(string uri) @safe
    {
        Json p = Json.emptyObject;
        p["uri"] = uri;
        rpc("resources/unsubscribe", p);
    }

    /// `logging/setLevel`.
    void setLogLevel(string level) @safe
    {
        Json p = Json.emptyObject;
        p["level"] = level;
        rpc("logging/setLevel", p);
    }

    // --- transport internals -------------------------------------------------

    /// Send a request and return its result (or throw `McpException`). Inbound
    /// notifications and server->client requests received while waiting are
    /// dispatched until the correlated response (`id`) arrives.
    private Json rpc(string method, Json params) @safe
    {
        const id = nextId++;
        send(makeRequest(Json(id), method, params));
        return await(id);
    }

    /// Send a notification (no reply expected).
    private void notify(string method, Json params) @safe
    {
        send(makeNotification(method, params));
    }

    /// Serialize a single message and write it as one newline-delimited line.
    /// `Json.toString` never emits a raw newline, so the line framing holds and
    /// only a valid MCP message is written to the server's stdin.
    private void send(Json message) @safe
    {
        writeLine(message.toString());
    }

    /// Read lines until the response correlated with `expectId` arrives,
    /// dispatching notifications (and ignoring stray server messages) along the
    /// way. Throws on end-of-input before the response or on a JSON-RPC error.
    private Json await(long expectId) @safe
    {
        for (;;)
        {
            auto line = readLine();
            if (line is null)
                throw internalError(
                        "Server closed stdout before responding to request " ~ idStr(expectId));
            if (line.length == 0)
                continue; // blank line, ignore

            Message msg;
            try
                msg = parseMessage(line);
            catch (Exception)
                continue; // not a JSON-RPC message (e.g. stray stdout); ignore

            final switch (msg.kind)
            {
            case MessageKind.response:
                if (msg.id.type == Json.Type.int_
                        && msg.id.get!long == expectId)
                    return msg.result;
                break;
            case MessageKind.errorResponse:
                if (msg.id.type == Json.Type.int_
                        && msg.id.get!long == expectId)
                    throw errorFrom(msg.error);
                break;
            case MessageKind.notification:
                if (onNotification !is null)
                    onNotification(msg.method, msg.params);
                break;
            case MessageKind.request:
                // The server initiated a request (e.g. ping). Reply to a `ping`
                // so the channel stays healthy; refuse anything else.
                replyToServerRequest(msg);
                break;
            }
        }
    }

    /// Answer a server->client request. Only `ping` is supported out of the box
    /// (sampling / elicitation / roots over stdio would need a richer host loop);
    /// anything else gets a `Method not found` error response.
    private void replyToServerRequest(Message msg) @safe
    {
        Json response;
        if (msg.method == "ping")
            response = makeResponse(msg.id, Json.emptyObject);
        else
            response = makeErrorResponse(msg.id, methodNotFound(msg.method));
        send(response);
    }

    private static McpException errorFrom(Json error) @safe
    {
        const code = ("code" in error) ? error["code"].get!int : ErrorCode.internalError;
        const m = ("message" in error) ? error["message"].get!string : "server error";
        return new McpException(code, m, error);
    }

    private static string idStr(long id) @safe
    {
        import std.conv : to;

        return id.to!string;
    }
}

/// Owns a spawned MCP server subprocess and the `StdioClient` driving it over
/// the child's `stdin`/`stdout`. The child's `stderr` is left attached to this
/// process's `stderr` for logging, per the MCP stdio transport.
///
/// Call `close()` (or rely on `scope(exit)`) to perform the MCP stdio shutdown
/// sequence: close the child's stdin, then escalate to `SIGTERM` and finally
/// `SIGKILL` if the server does not exit within the grace periods.
final class StdioClientProcess
{
    import std.process : ProcessPipes;
    import core.time : Duration, seconds, msecs;

    private ProcessPipes pipes;
    /// The MCP client speaking to the subprocess.
    StdioClient client;

    private this(ProcessPipes pipes, StdioClient client) @safe
    {
        this.pipes = pipes;
        this.client = client;
    }

    /// Shut the child down per the MCP stdio Shutdown sequence
    /// (basic/lifecycle §Shutdown -> stdio):
    ///
    /// 1. close the child's stdin (signal end-of-input),
    /// 2. wait up to `termGrace` for the server to exit, then send `SIGTERM`,
    /// 3. wait up to `killGrace` for the server to exit, then send `SIGKILL`.
    ///
    /// Returns the child's exit status (a process killed by signal reports a
    /// negative status per `std.process.wait`). Safe to call once.
    int close(Duration termGrace = 5.seconds, Duration killGrace = 5.seconds) @safe
    {
        () @trusted { pipes.stdin.close(); }();

        // Step 1+2: wait for a clean exit, escalating to SIGTERM on timeout.
        auto status = waitUntil(termGrace);
        if (!status.isNull)
            return status.get;

        version (Posix)
        {
            import std.process : kill;
            import core.sys.posix.signal : SIGTERM, SIGKILL;

            () @trusted { kill(pipes.pid, SIGTERM); }();
            status = waitUntil(killGrace);
            if (!status.isNull)
                return status.get;

            // Step 3: still alive after SIGTERM -- force kill and reap.
            () @trusted { kill(pipes.pid, SIGKILL); }();
        }
        else
        {
            import std.process : kill;

            // On Windows there is no SIGTERM/SIGKILL distinction; TerminateProcess
            // is the forceful equivalent of SIGKILL.
            () @trusted { kill(pipes.pid); }();
        }

        import std.process : wait;

        return () @trusted { return wait(pipes.pid); }();
    }

    /// Poll `tryWait` until the child exits or `grace` elapses. Returns the exit
    /// status if it exited within the deadline, or null if it is still running.
    private Nullable!int waitUntil(Duration grace) @safe
    {
        import std.process : tryWait;
        import std.datetime.stopwatch : StopWatch, AutoStart;
        import core.thread : Thread;

        auto sw = StopWatch(AutoStart.yes);
        for (;;)
        {
            auto r = () @trusted { return tryWait(pipes.pid); }();
            if (r.terminated)
                return Nullable!int(r.status);
            if (sw.peek >= grace)
                return Nullable!int.init;
            () @trusted { Thread.sleep(10.msecs); }();
        }
    }
}

/// Launch an MCP server as a subprocess and return a `StdioClientProcess` whose
/// `.client` speaks JSON-RPC over the child's stdin/stdout.
///
/// `args` is the command line (`args[0]` is the executable). Newline-delimited
/// JSON-RPC requests are written to the child's stdin and responses are read
/// from its stdout; the child's stderr is inherited for logging. The returned
/// `StdioClient` is NOT yet initialized — call `.client.initialize()` (or
/// `.client.ping()` for a stateless probe) yourself.
StdioClientProcess spawnStdioClient(string[] args,
        Implementation clientInfo = Implementation("dlang-mcp-client", "0.1.0")) @safe
{
    import std.process : pipeProcess, Redirect, Config;
    import std.string : stripRight;

    // Redirect stdin and stdout (frame the JSON-RPC channel); leave stderr
    // attached to ours so the server's logging is visible.
    auto pipes = () @trusted {
        return pipeProcess(args, Redirect.stdin | Redirect.stdout);
    }();

    auto client = new StdioClient(() @trusted {
        auto f = pipes.stdout;
        if (f.eof)
            return cast(string) null;
        auto ln = f.readln();
        if (ln.length == 0 && f.eof)
            return cast(string) null;
        return ln.stripRight("\r\n");
    }, (string s) @trusted { pipes.stdin.writeln(s); pipes.stdin.flush(); }, clientInfo);

    return new StdioClientProcess(pipes, client);
}

version (unittest)
{
    import mcp.server.server : MCPServer;
}

unittest  // StdioClient drives an in-process server over a paired channel (initialize + tools)
{
    // Wire a StdioClient to an MCPServer through two queues, pumping the server
    // synchronously: every request the client writes is handled immediately and
    // its response queued for the client to read back.
    auto server = new MCPServer("stdio-client-srv", "1.0");
    Tool echo = {name: "echo"};
    server.registerTool(echo, (Json args) @safe {
        CallToolResult r;
        r.content = [Content.makeText("ok")];
        return r;
    });

    string[] toServer; // lines written by the client, awaiting the server
    string[] toClient; // response lines queued for the client to read

    auto client = new StdioClient(() @safe {
        // Drain pending server work so a response is available before we read.
        while (toClient.length == 0 && toServer.length)
        {
            auto req = toServer[0];
            toServer = toServer[1 .. $];
            auto resp = server.handleRaw(req);
            if (resp.length)
                toClient ~= resp;
        }
        if (toClient.length == 0)
            return cast(string) null;
        auto line = toClient[0];
        toClient = toClient[1 .. $];
        return line;
    }, (string s) @safe { toServer ~= s; });

    auto init = client.initialize();
    assert(init.serverInfo.name == "stdio-client-srv");

    auto tools = client.listTools();
    assert(tools.length == 1);
    assert(tools[0].name == "echo");

    auto res = client.callTool("echo");
    assert(res.content[0].text == "ok");
}

unittest  // StdioClient surfaces a correlated server error response as an McpException
{
    // The server answers our request (id 1) with a JSON-RPC error carrying the
    // matching id; the client must raise it as an McpException with that code.
    string[] toClient = [
        `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`,
    ];

    auto client = new StdioClient(() @safe {
        if (toClient.length == 0)
            return cast(string) null;
        auto line = toClient[0];
        toClient = toClient[1 .. $];
        return line;
    }, (string) @safe {});

    int code;
    bool threw;
    try
        client.ping();
    catch (McpException e)
    {
        threw = true;
        code = e.code;
    }
    assert(threw);
    assert(code == ErrorCode.methodNotFound);
}

unittest  // StdioClient throws when the server closes stdout before responding
{
    auto client = new StdioClient(() @safe { return cast(string) null; }, (string) @safe {
    });
    bool threw;
    try
        client.ping();
    catch (McpException)
        threw = true;
    assert(threw);
}

unittest  // StdioClient dispatches inbound notifications while awaiting a response
{
    string[] toClient = [
        `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`,
        `{"jsonrpc":"2.0","id":1,"result":{}}`,
    ];
    string[] gotMethods;

    auto client = new StdioClient(() @safe {
        if (toClient.length == 0)
            return cast(string) null;
        auto line = toClient[0];
        toClient = toClient[1 .. $];
        return line;
    }, (string) @safe {});
    client.onNotification = (string method, Json params) @safe {
        gotMethods ~= method;
    };

    client.ping(); // id 1; the notification precedes the response
    assert(gotMethods == ["notifications/message"]);
}

unittest  // StdioClient answers a server-initiated ping while awaiting its own response
{
    string[] toServer;
    string[] toClient = [
        `{"jsonrpc":"2.0","id":100,"method":"ping"}`, // server pings us first
        `{"jsonrpc":"2.0","id":1,"result":{}}`, // then answers our request
    ];

    auto client = new StdioClient(() @safe {
        if (toClient.length == 0)
            return cast(string) null;
        auto line = toClient[0];
        toClient = toClient[1 .. $];
        return line;
    }, (string s) @safe { toServer ~= s; });

    client.ping();
    // We should have replied to the server's ping (id 100) in addition to
    // sending our own request (id 1).
    assert(toServer.length == 2);
    bool repliedToPing;
    foreach (line; toServer)
    {
        auto m = parseJsonString(line);
        if ("id" in m && m["id"].get!int == 100 && "result" in m)
            repliedToPing = true;
    }
    assert(repliedToPing);
}

version (Posix) unittest  // close() escalates to SIGTERM when the child ignores stdin EOF
{
    import std.process : pipeProcess, Redirect, wait;
    import std.datetime.stopwatch : StopWatch, AutoStart;
    import core.time : seconds, msecs;
    import core.sys.posix.signal : SIGTERM;

    // `sleep 30` does not exit when its stdin is closed, so closing stdin alone
    // would hang forever; the escalating shutdown must SIGTERM it.
    auto pipes = () @trusted {
        return pipeProcess(["sh", "-c", "sleep 30"], Redirect.stdin | Redirect.stdout);
    }();
    auto proc = new StdioClientProcess(pipes, null);

    auto sw = StopWatch(AutoStart.yes);
    auto status = proc.close(200.msecs, 2.seconds);
    // Must return well before the 30s sleep would have finished.
    assert(sw.peek < 5.seconds);
    // Killed by SIGTERM => negative status reporting the signal.
    assert(status == -SIGTERM);
}

version (Posix) unittest  // close() escalates to SIGKILL when the child also ignores SIGTERM
{
    import std.process : pipeProcess, Redirect;
    import std.datetime.stopwatch : StopWatch, AutoStart;
    import core.time : seconds, msecs;
    import core.sys.posix.signal : SIGKILL;

    // Trap (ignore) SIGTERM, then sleep; only SIGKILL can stop this child.
    auto pipes = () @trusted {
        return pipeProcess(["sh", "-c", "trap '' TERM; sleep 30"], Redirect.stdin | Redirect.stdout);
    }();
    auto proc = new StdioClientProcess(pipes, null);

    auto sw = StopWatch(AutoStart.yes);
    auto status = proc.close(200.msecs, 200.msecs);
    assert(sw.peek < 5.seconds);
    // SIGTERM was ignored, so the kill must have come from SIGKILL.
    assert(status == -SIGKILL);
}

version (Posix) unittest  // close() returns the child's clean exit status when it exits on stdin EOF
{
    import std.process : pipeProcess, Redirect;
    import core.time : seconds;

    // `cat` exits 0 once its stdin reaches EOF, so step 1 (close stdin) suffices.
    auto pipes = () @trusted {
        return pipeProcess(["cat"], Redirect.stdin | Redirect.stdout);
    }();
    auto proc = new StdioClientProcess(pipes, null);

    auto status = proc.close(5.seconds, 5.seconds);
    assert(status == 0);
}

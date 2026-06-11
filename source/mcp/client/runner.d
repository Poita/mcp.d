/**
 * `runWithEventLoop` — a scoped entry affordance for driving `McpClient` work
 * from a process that is not otherwise vibe-based.
 *
 * $(B Positioning.) The mcp.d client leans into vibe's event loop. `McpClient`
 * verbs are $(I fiber-blocking), not thread-blocking: a call yields its fiber
 * back to the loop until the reply arrives (the Go-SDK model — blocking calls on
 * cheap green threads, concurrency by spawning more tasks — not the Java-SDK
 * model of an async surface plus a blocking sync facade). That means the loop
 * stays live $(I during) a call, so progress notifications and server→client
 * handlers (sampling / elicitation) still dispatch mid-call.
 *
 * Because every verb must run inside a task under a running event loop, a
 * process that is not already vibe-based needs a loop to run on. `runWithEventLoop`
 * is that affordance: it spins up the loop, runs your `scenario` inside a
 * `runTask`, exits the loop when the scenario returns, and hands back the
 * scenario's value (rethrowing any exception it threw on the caller's side).
 *
 * Use it when:
 * $(UL
 *   $(LI your process is $(B not) otherwise vibe-based, $(B and))
 *   $(LI its MCP work has a scoped lifetime — CLI tools, batch jobs, tests.)
 * )
 *
 * Do $(B not) reach for it when:
 * $(UL
 *   $(LI you are writing a vibe-native app — there is already a loop; just call
 *        `McpClient` from any task.)
 *   $(LI you have a long-lived non-vibe host (a GUI, a game loop, a server in
 *        another framework) — run your MCP integration on the loop on its own
 *        thread and hand results to the rest of the app over your own channel,
 *        rather than entering and exiting the loop per call.)
 * )
 *
 * $(B No cross-thread sync wrapper, by design.) There is deliberately no
 * blocking cross-thread synchronous `McpClient` facade, no callback-async verb
 * variants, and no "sync client" wrapper. Tool calls can run for minutes;
 * parking a host thread on one is a foot-gun. Fiber-blocking already delivers the
 * Go model on the loop's own thread, and long-running work is addressed at the
 * MCP level by `RequestOptions.onProgress` and the Tasks extension (`@task` /
 * `awaitTask`). Reach for those, not a thread bridge.
 */
module mcp.client.runner;

/**
 * Run `scenario` to completion inside a fresh vibe event loop and return its
 * value.
 *
 * The scenario body is executed inside a `runTask` under `runEventLoop()`; the
 * loop is exited as soon as the scenario returns (or throws). This is what lets
 * fiber-blocking `McpClient` verbs work from a non-vibe process: the blocking
 * stdio request/response completes inside the loop, and any HTTP background
 * streams get a loop to run on.
 *
 * Exceptions are propagated $(B by rethrow): a `Throwable` escaping the scenario
 * is captured inside the task and re-thrown on the caller's side after the loop
 * has exited — the exact same object the scenario threw, not a return-code
 * mapping. `T == void` scenarios are supported.
 *
 * Params:
 *   scenario = the work to run on the loop; its return value is forwarded.
 *
 * Returns: the value returned by `scenario` (nothing when `T == void`).
 *
 * Throws: whatever `scenario` throws, rethrown on the caller's side.
 */
T runWithEventLoop(T)(scope T delegate() @safe scenario) @trusted
{
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;

	// Captured across the loop boundary: the scenario runs in a task on the
	// loop's thread, and we rethrow/return on the caller's thread once the loop
	// exits. The task is `nothrow` (vibe requires it), so a Throwable must be
	// stashed and re-raised here rather than allowed to escape the task.
	Throwable captured;
	static if (is(T == void))
	{
		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
				scenario();
			catch (Throwable t)
				captured = t;
		});
		runEventLoop();
		if (captured !is null)
			throw captured;
	}
	else
	{
		T result;
		runTask(() nothrow{
			scope (exit)
				exitEventLoop();
			try
				result = scenario();
			catch (Throwable t)
				captured = t;
		});
		runEventLoop();
		if (captured !is null)
			throw captured;
		return result;
	}
}

@safe unittest
{
	// A value-returning scenario's result is forwarded to the caller.
	auto n = runWithEventLoop(() @safe => 42);
	assert(n == 42);
}

@safe unittest
{
	// Non-trivial return types are forwarded intact.
	auto s = runWithEventLoop(() @safe => "hello");
	assert(s == "hello");
}

@safe unittest
{
	// A `void` scenario is supported and its side effects are observed.
	int ran;
	runWithEventLoop(() @safe { ran = 1; });
	assert(ran == 1);
}

@safe unittest
{
	// An exception thrown by the scenario is rethrown on the caller's side —
	// and it is the SAME object, carrying the SAME message.
	auto thrown = new Exception("boom");
	Exception caught;
	try
		runWithEventLoop(() @safe { throw thrown; });
	catch (Exception e)
		caught = e;
	assert(caught is thrown);
	assert(caught.msg == "boom");
}

@safe unittest
{
	// Rethrow works for a `void` scenario too.
	bool caught;
	try
		runWithEventLoop(() @safe { throw new Exception("void-boom"); });
	catch (Exception e)
		caught = (e.msg == "void-boom");
	assert(caught);
}

@safe unittest
{
	// Nested / smoke use without any McpClient: the scenario can itself do
	// ordinary work and yield a computed value back through the loop.
	auto total = runWithEventLoop(() @safe {
		int acc;
		foreach (i; 0 .. 5)
			acc += i;
		return acc;
	});
	assert(total == 10);
}

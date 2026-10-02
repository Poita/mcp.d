# MCP Tasks example (server + client e2e), dual-transport

A self-contained example of the **`io.modelcontextprotocol/tasks`** extension
(SEP-2663) in the D MCP SDK ([mcp.d](https://github.com/Poita/mcp.d)): a
`@taskTool` method becomes a tool whose `tools/call` returns a task handle
immediately, runs asynchronously, and delivers its typed return value as the
task's final result. It is its own dub package with path dependencies on the
root `mcp-d` library and the shared `examples/common` scaffold, so it never
touches the root `dub.json`.

Tasks is a modern-only extension (2026-07-28), so the client enables the modern
protocol before negotiation. The single server binary speaks **stdio or
Streamable HTTP**, and the single client binary is a **self-verifying e2e test**
that runs the same assertions over either transport.

## What it teaches

**Server side (`server.d`)** — three `@taskTool` methods on `TasksApi`, wired by one
`registerHandlers` call after `server.enableTasks()`:

- **`word_count`** — a plain async task that reports progress with
  `TaskContext.progress` and returns a typed `WordCountResult`.
- **`slow_reverse`** — reverses its input one character at a time, polling
  `TaskContext.cancelRequested` between characters so `tasks/cancel` stops it
  promptly.
- **`labeled_count`** — needs input mid-execution: with no answer yet it returns
  `tc.requireInput([elicitationRequest!LabelChoice(...)])`, which suspends the
  task into `input_required`. Once the client answers via `tasks/update`, the
  executor runs again and reads the answer with `tc.inputAs!ElicitResult`.
- **`@taskTtl` / `@taskPollInterval`** set each task's lifetime and suggested
  poll interval.
- The injected `TaskContext` is omitted from the input schema, and the other
  parameters are reconstituted from the task's durable input on every dispatch,
  so the same handler works in-process or re-dispatched on another node. The
  comment in `main` sketches a Redis-backed `TaskStore` and a queue-backed
  `TaskDispatcher` for that deployment.

**Client side (`client.d`)** calls `enableModern()` and `enableTasks()`, declares
form elicitation, and asserts:

1. `server/discover` advertises the tasks extension (`tasksExtensionKey`) and
   `connect()` negotiates 2026-07-28.
2. `callToolAwait("word_count", ...)` polls `tasks/get` to completion and
   returns 9 words / 43 characters.
3. `callToolAwait("slow_reverse", ...)` returns `"olleh"`, not cancelled.
4. **Persist and resume** — plain `callTool` returns the task handle
   (`isTask`, `task.taskId`); `awaitTask(taskId)` drives it to completion from
   the bare id, as a client would after a restart.
5. **Mid-task input** — `callToolAwait("labeled_count", ...)` surfaces the
   `label` elicitation through its `onInputRequired` callback; the client answers
   with `respondTaskInput` and the task completes with that label.
6. `McpClient.isTaskResult` distinguishes a `resultType: "task"` object from
   ordinary results.

On success it prints `OK: ...` and exits `0`; any failed assertion prints what
differed and exits non-zero.

## Running it

```sh
# from this directory (examples/tasks)
dub build -c server      # produces ./tasks-server
dub build -c client      # produces ./tasks-client
```

### Over stdio (default)

```sh
./tasks-client           # spawns ./tasks-server and runs the e2e (exit 0 == pass)
```

### Over Streamable HTTP

```sh
# terminal 1
./tasks-server --http --port 8643

# terminal 2
./tasks-client --http http://127.0.0.1:8643/mcp
```

See the [MCP Tasks](../../README.md#mcp-tasks-asynchronous-execution) section of
the root README for durable stores and dispatchers.

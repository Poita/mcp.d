/**
 * macOS-only custom unittest runner that exits cleanly after the summary.
 *
 * On macOS, vibe.d/eventcore selects the CFRunLoop process driver. Its
 * process-reaper thread (`PosixEventDriverProcesses.waitForProcesses`) can
 * still be alive and busy-spinning when `main` returns from the unittest
 * binary. druntime's shutdown (`rt_term` -> `thread_joinAll`) then blocks
 * forever trying to join that thread, so the test binary spins at ~100% CPU
 * and never exits even though every unit test has already finished.
 *
 * To make `dub test` deterministic on macOS, this runner takes over module
 * unit testing via `Runtime.extendedModuleUnitTester`, runs all module unit
 * tests, prints the standard pass/fail summary, then hard-exits the process
 * with the correct status code via libc `exit`, bypassing the `rt_term`
 * thread-join that hangs on the lingering eventcore thread.
 *
 * This is `version(unittest)` + `version(OSX)` only, so it never affects
 * production binaries, and it leaves Linux (and its coverage flush) on the
 * default runner. Exit-code semantics are preserved: any failing unit test
 * still produces a non-zero exit so CI detects failures.
 */
module mcp.internal.unittest_runner;

version (unittest)
{
	version (OSX)
	{
		import core.runtime : Runtime, UnitTestResult;

		shared static this()
		{
			Runtime.extendedModuleUnitTester = &runAllUnitTests;
		}

		/// Run every module's unit tests, print the summary, and hard-exit with
		/// the status code reflecting whether any test failed.
		private UnitTestResult runAllUnitTests() @system
		{
			import core.exception : AssertError;

			UnitTestResult result;
			foreach (m; ModuleInfo)
			{
				if (!m)
					continue;
				auto fp = m.unitTest;
				if (!fp)
					continue;

				++result.executed;
				try
				{
					fp();
					++result.passed;
				}
				catch (Throwable t)
				{
					// Print the failure the same way druntime's default runner
					// does: a concise location line for in-module assert
					// failures, otherwise the full throwable.
					if (typeid(t) == typeid(AssertError) && originatesIn(m.name, t.file))
					{
						import core.stdc.stdio : printf;

						printf("%.*s(%llu): [unittest] %.*s\n", cast(int) t.file.length,
								t.file.ptr, cast(ulong) t.line,
								cast(int) t.message.length, t.message.ptr);
					}
					else
					{
						printThrowable(t);
					}
				}
			}

			summarizeAndExit(result);

			// Unreachable: summarizeAndExit never returns. runMain stays false so
			// the binary would not run main even in the impossible case of a
			// return.
			result.runMain = false;
			return result;
		}

		/// Treat an assert as in-module when the failing file is the module's
		/// own source: its dotted name as a path ending in `.d` or
		/// `/package.d`, at the start of `file` or right after a `/`.
		private bool originatesIn(string moduleName, string file) @safe nothrow @nogc
		{
			static immutable string[2] suffixes = [".d", "/package.d"];
			if (moduleName.length == 0)
				return false;
			foreach (suffix; suffixes)
			{
				immutable total = moduleName.length + suffix.length;
				if (file.length < total || file[$ - suffix.length .. $] != suffix)
					continue;
				immutable start = file.length - total;
				if (start != 0 && file[start - 1] != '/')
					continue;
				bool same = true;
				foreach (i, c; moduleName)
				{
					immutable f = file[start + i];
					if (c == '.' ? f != '/' : f != c)
					{
						same = false;
						break;
					}
				}
				if (same)
					return true;
			}
			return false;
		}

		@safe unittest
		{
			assert(originatesIn("mcp.internal.unittest_runner",
					"source/mcp/internal/unittest_runner.d"));
		}

		@safe unittest
		{
			assert(originatesIn("mcp.transport", "source/mcp/transport/package.d"));
		}

		@safe unittest
		{
			assert(!originatesIn("mcp.transport", "source/mcp/transport/stdio.d"));
			assert(!originatesIn("mcp.server.server", "source/mcp/server/server_test.d"));
			assert(!originatesIn("", "source/mcp/server/server.d"));
		}

		private extern (C) void _d_print_throwable(Throwable t) nothrow;

		/// Print a throwable using druntime's standard formatter.
		private void printThrowable(Throwable t) @trusted nothrow
		{
			_d_print_throwable(t);
		}

		/// Print the standard pass/fail summary, then hard-exit with the matching
		/// status code, bypassing `rt_term`/`thread_joinAll`.
		private void summarizeAndExit(UnitTestResult result) @trusted nothrow @nogc
		{
			import core.stdc.stdio : printf, fflush, stdout;
			import core.stdc.stdlib : exit;

			// Keep druntime's exact summary wording that CI and local greps rely
			// on: "<N> modules passed unittests" on success and
			// "<failed>/<executed> modules FAILED unittests" otherwise.
			immutable anyFailed = result.passed != result.executed;
			if (anyFailed)
				printf("%llu/%llu modules FAILED unittests\n",
						cast(ulong)(result.executed - result.passed), cast(ulong) result.executed);
			else
				printf("%llu modules passed unittests\n", cast(ulong) result.passed);
			fflush(stdout);
			exit(anyFailed ? 1 : 0);
		}
	}
}

/**
 * Stop control shared between a periodic background loop and its owner.
 */
module mcp.internal.background_loop;

import core.time : Duration;
import vibe.core.task : Task;

/// Owned by a runtime that starts a periodic loop: the loop checks `stopped`
/// on every pass and waits between passes with `pause`. `stop` interrupts the
/// loop's fiber only while it waits in `pause`, so a pass in progress finishes
/// its work (including any I/O) and the loop ends at its next check.
final class BackgroundLoop
{
	bool stopped; /// set by `stop`; the loop exits at its next check
	Task task; /// the loop's fiber, when it runs in one
	private bool pausing_;

	/// Ask the loop to end.
	void stop() @safe nothrow
	{
		stopped = true;
		if (pausing_ && task && Task.getThis() != task)
			task.interrupt();
	}

	/// Wait `interval` before the next pass. Returns whether the loop should
	/// continue: false once stopped, or when the wait is interrupted (by
	/// `stop`, or the event loop shutting down).
	bool pause(Duration interval) @safe nothrow
	{
		import vibe.core.core : sleep;

		if (stopped)
			return false;
		pausing_ = true;
		scope (exit)
			pausing_ = false;
		try
			sleep(interval);
		catch (Exception)
			return false;
		return !stopped;
	}
}

unittest  // stop during a pass lets the pass finish its I/O uninterrupted
{
	import core.time : msecs;
	import vibe.core.core : runTask, exitEventLoop, runEventLoop, sleep;

	auto loop = new BackgroundLoop;
	bool passFinished, loopEnded;
	loop.task = runTask(() nothrow @safe {
		try
		{
			sleep(20.msecs); // I/O inside a pass
			passFinished = true;
		}
		catch (Exception)
		{
		}
		loopEnded = loop.stopped;
	});
	runTask(() nothrow @safe {
		try
		{
			sleep(5.msecs);
			loop.stop();
			sleep(40.msecs);
		}
		catch (Exception)
		{
		}
		exitEventLoop();
	});
	runEventLoop();
	assert(passFinished, "stop interrupted the pass's I/O");
	assert(loopEnded);
}

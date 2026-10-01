/**
 * Stop control shared between a periodic background loop and its owner.
 */
module mcp.internal.background_loop;

import vibe.core.task : Task;

/// Owned by a runtime that starts a periodic loop: the loop checks `stopped`
/// on every pass, and `stop` also interrupts the loop's fiber (when it runs in
/// one) so a loop sleeping between passes ends promptly.
final class BackgroundLoop
{
	bool stopped; /// set by `stop`; the loop exits at its next check
	Task task; /// the loop's fiber, when it runs in one

	/// Ask the loop to end.
	void stop() @safe nothrow
	{
		stopped = true;
		if (task && Task.getThis() != task)
			task.interrupt();
	}
}

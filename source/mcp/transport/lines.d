module mcp.transport.lines;

import vibe.data.json : Json;

@safe:

/// Newline-delimited line assembly over a byte source, shared by both ends of the
/// stdio transport (the server reading its stdin, the client reading a spawned
/// server's stdout).
///
/// Bytes are read in 64 KiB chunks into a small persistent buffer rather than one
/// read + fiber suspend/resume per byte: `next` scans the filled region for '\n',
/// returns the line up to it, and retains the bytes after the newline for the
/// next call.
package(mcp) struct LineReader
{
	private size_t maxLineBytes;
	private enum size_t chunk = 64 * 1024;
	private ubyte[] storage; // fixed chunk-sized backing buffer that every read fills
	private ubyte[] buf; // the filled prefix of `storage` from the latest read
	private size_t bufPos; // index of the next unconsumed byte in `buf`
	private enum size_t idScanBytes = 4096;
	private bool oversized_; // an over-long line was dropped since the last takeOversized
	private FrameHead oversizedHead_; // what the dropped line's first bytes reveal

	this(size_t maxLineBytes) @safe
	{
		this.maxLineBytes = maxLineBytes;
	}

	// Refill `buf` through `read` (which fills the slice it is given and returns
	// the byte count, 0 at end-of-input): return false at end-of-input with `buf`
	// cleared, else true with `buf` set to the bytes read and `bufPos` reset to 0.
	private bool refillFrom(scope size_t delegate(ubyte[]) @safe read) @safe
	{
		if (storage is null)
			storage = new ubyte[chunk];
		bufPos = 0;
		const n = read(storage);
		if (n == 0)
		{
			buf = null;
			return false;
		}
		buf = storage[0 .. n];
		return true;
	}

	/// Return the next line read through `read` (without its '\n', stripping a
	/// trailing '\r'), or null at end-of-input. `read` fills the slice it is
	/// given and returns the byte count, 0 at end-of-input. A final line left
	/// unterminated at end-of-input is returned before the null. An over-long line
	/// (> maxLineBytes) is dropped — `next` returns "" and `takeOversized` reports
	/// it so the caller can answer the peer — and reading resumes after the next
	/// newline.
	string next(scope size_t delegate(ubyte[]) @safe read) @safe
	{
		return nextWith(() @safe => refillFrom(read));
	}

	// Whether an over-long line was dropped since the last call; if so `head` is
	// what its first bytes reveal (its id is null when not found there).
	bool takeOversized(out FrameHead head) @safe
	{
		if (!oversized_)
			return false;
		oversized_ = false;
		head = oversizedHead_;
		return true;
	}

	private void markOversized(const(ubyte)[] prefix) @safe
	{
		oversized_ = true;
		oversizedHead_ = scanFrameHead(prefix);
	}

	// The pure line-assembly state machine, parameterised on the buffer-refill
	// source so the CR-strip and over-long-drop paths are unit-testable with a fake
	// refill (no real eventcore pipe I/O). `refillFn` fills `buf`/`bufPos` and
	// returns false at EOF, exactly as `refill` does.
	package string nextWith(scope bool delegate() @safe refillFn) @safe
	{
		ubyte[] acc;
		bool dropping; // true once `acc` exceeded maxLineBytes: skip to next '\n'
		for (;;)
		{
			if (bufPos >= buf.length)
			{
				// Refill from the pipe. At EOF a final unterminated line is still a
				// complete message; the next call then reports EOF.
				if (!refillFn())
				{
					if (dropping)
						return null;
					if (acc.length && acc[$ - 1] == '\r')
						acc = acc[0 .. $ - 1];
					return acc.length ? () @trusted {
						return cast(string) acc.idup;
					}() : null;
				}
			}

			// Scan the filled region for a newline.
			const rest = buf[bufPos .. $];
			size_t nl = size_t.max;
			foreach (i, b; rest)
				if (b == '\n')
				{
					nl = i;
					break;
				}

			if (nl == size_t.max)
			{
				// No newline yet: accumulate (unless dropping) and refill.
				if (!dropping)
				{
					acc ~= rest;
					if (acc.length > maxLineBytes)
					{
						markOversized(acc[0 .. $ < idScanBytes ? $ : idScanBytes]);
						acc = null;
						dropping = true;
					}
				}
				bufPos = buf.length;
				continue;
			}

			// Found a newline at rest[nl]; consume through it.
			if (!dropping)
				acc ~= rest[0 .. nl];
			bufPos += nl + 1;
			// Enforce the size cap here too: when the line and its newline land in the
			// same chunk the no-newline accumulation path above never runs, so the cap
			// must also be checked on the newline-found path. An over-long line (already
			// dropping, or only now over the cap) is discarded and a fresh one started.
			if (dropping || acc.length > maxLineBytes)
			{
				if (!dropping)
					markOversized(acc[0 .. $ < idScanBytes ? $ : idScanBytes]);
				return "";
			}
			if (acc.length && acc[$ - 1] == '\r')
				acc = acc[0 .. $ - 1];
			// A blank line is "" rather than null, which the read loop takes as EOF.
			if (!acc.length)
				return "";
			return () @trusted { return cast(string) acc.idup; }();
		}
	}
}

/// What the first bytes of a JSON-RPC object reveal about it: its top-level
/// `"id"` and whether a top-level `"method"` or `"result"`/`"error"` key appears.
package(mcp) struct FrameHead
{
	Json id; /// a number or string id, or JSON null when none is found
	bool hasMethod; /// a top-level `"method"` key: a request or notification
	bool hasResult; /// a top-level `"result"` or `"error"` key: a response
}

/// Scan a (possibly truncated) prefix of a JSON-RPC object's text for its
/// top-level keys, skipping nested objects/arrays and string contents.
package(mcp) FrameHead scanFrameHead(const(ubyte)[] text) @safe
{
	import std.conv : to, ConvException;
	import vibe.data.json : parseJsonString, JSONException;

	FrameHead head;
	head.id = Json(null);
	size_t i;
	int depth;
	bool expectValueForId;
	bool afterKey; // the last depth-1 string was a key whose ':' is pending
	string lastKey;

	// Scan one JSON string starting at text[i] == '"'; returns its raw contents
	// (escapes left as-is) and leaves i after the closing quote, or null if cut off.
	string scanString() @safe
	{
		const start = ++i;
		while (i < text.length)
		{
			if (text[i] == '\\')
				i += 2;
			else if (text[i] == '"')
				return () @trusted { return cast(string) text[start .. i++]; }();
			else
				i++;
		}
		return null;
	}

	while (i < text.length)
	{
		const c = text[i];
		if (c == '"')
		{
			const startQuote = i;
			auto str = scanString();
			if (str is null)
				break;
			if (expectValueForId)
			{
				expectValueForId = false;
				try
					head.id = parseJsonString(() @trusted {
						return cast(string) text[startQuote .. i];
					}());
				catch (JSONException)
				{
				}
				continue;
			}
			if (depth == 1)
			{
				lastKey = str;
				afterKey = true;
			}
			continue;
		}
		if (expectValueForId && (c == '-' || (c >= '0' && c <= '9')))
		{
			expectValueForId = false;
			const start = i;
			while (i < text.length && (text[i] == '-' || text[i] == '+'
					|| text[i] == '.' || text[i] == 'e' || text[i] == 'E'
					|| (text[i] >= '0' && text[i] <= '9')))
				i++;
			if (i >= text.length)
				break; // cut off mid-number
			try
				head.id = Json(() @trusted { return cast(string) text[start .. i]; }().to!long);
			catch (ConvException)
			{
			}
			continue;
		}
		if (c == ':' && depth == 1 && afterKey)
		{
			expectValueForId = lastKey == "id";
			if (lastKey == "method")
				head.hasMethod = true;
			else if (lastKey == "result" || lastKey == "error")
				head.hasResult = true;
			afterKey = false;
		}
		else if (c == '{' || c == '[')
		{
			expectValueForId = false; // an object or array is not a valid id
			depth++;
		}
		else if (c == '}' || c == ']')
			depth--;
		else if (c == ',' && depth == 1)
			expectValueForId = false;
		else if (expectValueForId && c > ' ')
			expectValueForId = false; // true/false/null are not valid ids
		i++;
	}
	return head;
}

version (unittest)
{
	// Drive LineReader.nextWith over an in-memory byte feed: each refill hands the
	// reader the next pre-chunked slice, and returns false (EOF) once the chunks
	// are exhausted, exactly as refillFrom does. Lets the line-assembly edge cases
	// be unit-tested.
	private string[] drainLineReader(size_t maxLineBytes, ubyte[][] chunks, ref Json[] oversizedIds) @safe
	{
		auto reader = LineReader(maxLineBytes);
		size_t ci;
		bool refill() @safe
		{
			if (ci >= chunks.length)
			{
				reader.buf = null;
				reader.bufPos = 0;
				return false;
			}
			reader.buf = chunks[ci++];
			reader.bufPos = 0;
			return true;
		}

		string[] lines;
		for (;;)
		{
			auto s = reader.nextWith(&refill);
			FrameHead head;
			if (reader.takeOversized(head))
				oversizedIds ~= head.id;
			if (s is null)
				break;
			if (s.length)
				lines ~= s;
		}
		return lines;
	}

	private string[] drainLineReader(size_t maxLineBytes, ubyte[][] chunks) @safe
	{
		Json[] ignored;
		return drainLineReader(maxLineBytes, chunks, ignored);
	}
}

unittest  // LineReader refills into one fixed backing buffer across short reads
{
	auto reader = LineReader.init;
	size_t readThree(ubyte[] dst) @safe
	{
		dst[0 .. 3] = cast(const(ubyte)[]) "ab\n";
		return 3;
	}

	assert(reader.refillFrom(&readThree));
	const first = &reader.buf[0];
	assert(reader.buf == cast(const(ubyte)[]) "ab\n");
	assert(reader.refillFrom(&readThree));
	assert(&reader.buf[0] is first, "a short read must not force a reallocation");
	assert(reader.buf == cast(const(ubyte)[]) "ab\n");
}

unittest  // LineReader strips a trailing CR on a CRLF-terminated line
{
	auto lines = drainLineReader(64, [cast(ubyte[]) "ok\r\n".dup]);
	assert(lines.length == 1);
	assert(lines[0] == "ok", "trailing CR must be stripped");
}

unittest  // LineReader drops an over-long line and resumes reading after the next newline
{
	// maxLineBytes = 8. The middle line's bytes arrive newline-free across refills so
	// the accumulator crosses maxLineBytes (the over-long drop path) before its
	// terminating newline; the surrounding short lines still come through. The drop is
	// triggered while accumulating without a newline, mirroring a real chunked pipe.
	auto lines = drainLineReader(8, [
		cast(ubyte[]) "a\n11111".dup, cast(ubyte[]) "1111".dup,
		cast(ubyte[]) "1111\ntail\n".dup
	]);
	assert(lines == ["a", "tail"], "over-long line dropped, reading resumes after its newline");
}

unittest  // LineReader drops an over-long line whose terminating newline shares its chunk
{
	// maxLineBytes = 8. The over-long line and its newline arrive in the SAME chunk,
	// so the no-newline accumulation path (which enforces the cap) is never taken.
	// The size cap must still be enforced on the newline-found path: the over-long
	// line is dropped and the following short line still comes through.
	auto lines = drainLineReader(8, [cast(ubyte[]) "aaaaaaaaaaaa\ntail\n".dup]);
	assert(lines == ["tail"], "over-long line with same-chunk newline must still be dropped");
}

unittest  // LineReader reassembles a line split across two refills
{
	auto lines = drainLineReader(64, [
		cast(ubyte[]) "hel".dup, cast(ubyte[]) "lo\nworld\n".dup
	]);
	assert(lines == ["hello", "world"], "a line spanning two refills is reassembled");
}

unittest  // LineReader returns a final unterminated line at EOF
{
	auto lines = drainLineReader(64, [cast(ubyte[]) "first\nlast\r".dup]);
	assert(lines == ["first", "last"], "a final line without a newline must still be processed");
}

unittest  // LineReader returns a blank line as an empty, non-null string
{
	auto lines = drainLineReader(64, [cast(ubyte[]) "a\n\n\r\nb\n".dup]);
	assert(lines == ["a", "b"], "blank lines must not be reported as end-of-input");
}

unittest  // LineReader reports an over-long line with its top-level id
{
	Json[] ids;
	auto lines = drainLineReader(24,
			[
				cast(ubyte[]) `{"params":{"id":9,"x":"aaaaaaaaaaaaaaaa"},"id":42,"method":"m"}`.dup,
				cast(ubyte[]) "\ntail\n".dup
	], ids);
	assert(lines == ["tail"]);
	assert(ids.length == 1);
	assert(ids[0].type == Json.Type.int_ && ids[0].get!long == 42,
			"the reported id is the request's own, not a nested params id");
}

unittest  // LineReader reports an over-long line whose id is unknown as null
{
	Json[] ids;
	drainLineReader(8, [cast(ubyte[]) "aaaaaaaaaaaa\ntail\n".dup], ids);
	assert(ids.length == 1);
	assert(ids[0].type == Json.Type.null_);
}

unittest  // LineReader reports an over-long line cut off by EOF
{
	Json[] ids;
	drainLineReader(8, [cast(ubyte[]) `{"id":"abc","method":"xxxxxxxx"`.dup], ids);
	assert(ids.length == 1);
	assert(ids[0].get!string == "abc");
}

unittest  // scanFrameHead tells a request, a response and a notification apart by their top-level keys
{
	auto req = scanFrameHead(cast(
			const(ubyte)[]) `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"x`);
	assert(req.id.get!long == 7 && req.hasMethod && !req.hasResult);

	auto res = scanFrameHead(cast(
			const(ubyte)[]) `{"jsonrpc":"2.0","result":{"method":"m","id":3},"id":"s-1"`);
	assert(res.id.get!string == "s-1" && res.hasResult && !res.hasMethod,
			"keys nested in the result do not count as top-level");

	auto err = scanFrameHead(cast(const(ubyte)[]) `{"id":4,"error":{"code":1,"message":"aaaa`);
	assert(err.id.get!long == 4 && err.hasResult);

	auto note = scanFrameHead(
			cast(const(ubyte)[]) `{"method":"notifications/progress","params":{"id":2,`);
	assert(note.id.type == Json.Type.null_ && note.hasMethod && !note.hasResult);
}

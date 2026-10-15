module mcp.transport.lines;

import vibe.data.json : Json;

@safe:

/// How many leading bytes of a dropped over-long line a reader that does not
/// stream it through a `FrameHeadScanner` keeps for `scanFrameHead`.
package(mcp) enum size_t frameHeadScanBytes = 4096;

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
	private bool oversized_; // an over-long line was dropped since the last takeOversized
	private FrameHead oversizedHead_; // what the dropped line reveals
	private FrameHeadScanner scanner_; // scans the line being dropped
	private bool reported_; // onOversized already ran for the line being dropped

	/// Called once per over-long line with its `FrameHead`: as soon as the bytes
	/// read so far reveal both its id and its kind, so a caller can act on it while
	/// a peer is still sending it, else when the line ends. Optional;
	/// `takeOversized` reports the line once `next` returns.
	void delegate(FrameHead) @safe onOversized;

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
	// what the line reveals (its id is null when it has none).
	bool takeOversized(out FrameHead head) @safe
	{
		if (!oversized_)
			return false;
		oversized_ = false;
		head = oversizedHead_;
		return true;
	}

	// Start dropping an over-long line whose bytes so far are `seen`.
	private void beginOversized(const(ubyte)[] seen) @safe
	{
		scanner_ = FrameHeadScanner.init;
		reported_ = false;
		scanOversized(seen);
	}

	// Scan more of the line being dropped, reporting it once its head is decided.
	private void scanOversized(const(ubyte)[] bytes) @safe
	{
		scanner_.feed(bytes);
		if (!reported_ && scanner_.decided)
		{
			reported_ = true;
			if (onOversized !is null)
				onOversized(scanner_.head);
		}
	}

	// The line being dropped has ended.
	private void endOversized() @safe
	{
		oversized_ = true;
		oversizedHead_ = scanner_.head;
		if (!reported_ && onOversized !is null)
			onOversized(oversizedHead_);
		reported_ = true;
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
					{
						endOversized();
						return null;
					}
					if (acc.length && acc[$ - 1] == '\r')
						acc = acc[0 .. $ - 1];
					return acc.length ? (() @trusted => cast(string) acc)() : null;
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
				if (dropping)
					scanOversized(rest);
				else
				{
					acc ~= rest;
					if (acc.length > maxLineBytes)
					{
						beginOversized(acc);
						acc = null;
						dropping = true;
					}
				}
				bufPos = buf.length;
				continue;
			}

			// Found a newline at rest[nl]; consume through it. A line held whole in
			// `buf` is sliced, not accumulated, so it is copied only once on return.
			const(ubyte)[] line;
			bool owned; // `line` is `acc`, which no one else references
			if (!dropping)
			{
				if (acc.length)
				{
					acc ~= rest[0 .. nl];
					line = acc;
					owned = true;
				}
				else
					line = rest[0 .. nl];
			}
			bufPos += nl + 1;
			// Enforce the size cap here too: when the line and its newline land in the
			// same chunk the no-newline accumulation path above never runs, so the cap
			// must also be checked on the newline-found path. An over-long line (already
			// dropping, or only now over the cap) is discarded and a fresh one started.
			if (dropping || line.length > maxLineBytes)
			{
				if (dropping)
					scanOversized(rest[0 .. nl]);
				else
					beginOversized(line);
				endOversized();
				return "";
			}
			if (line.length && line[$ - 1] == '\r')
				line = line[0 .. $ - 1];
			// A blank line is "" rather than null, which the read loop takes as EOF.
			if (!line.length)
				return "";
			return owned ? (() @trusted => cast(string) line)() : cast(string) line.idup;
		}
	}
}

/// What the text of a JSON-RPC object reveals about it: its top-level
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
	FrameHeadScanner scanner;
	scanner.feed(text);
	return scanner.head;
}

/// Incremental form of `scanFrameHead`: `feed` takes a JSON-RPC object's text in
/// any number of pieces, so the whole of an over-long line can be scanned as its
/// bytes stream past without being kept. Only nesting depth, string/number state
/// and the last top-level key are carried between pieces.
package(mcp) struct FrameHeadScanner
{
	// Longest top-level key or string id kept; anything longer matches no key
	// and is not taken as an id.
	private enum size_t maxCapture = 256;

	private FrameHead head_;
	private int depth;
	private bool inString, escaped, capturing, captureOverflow, stringIsId;
	private ubyte[] captured;
	private bool inNumber;
	private ubyte[] number;
	private bool expectValueForId;
	private bool afterKey; // the last depth-1 string was a key whose ':' is pending
	private string lastKey;

	/// Scan the next piece of the object's text.
	void feed(const(ubyte)[] text) @safe
	{
		foreach (c; text)
			step(c);
	}

	/// What the text fed so far reveals. A number or string still open at the
	/// end of it may be cut off, so it is not taken as the id.
	FrameHead head() const @safe
	{
		FrameHead h;
		h.id = head_.id.type == Json.Type.undefined ? Json(null) : head_.id;
		h.hasMethod = head_.hasMethod;
		h.hasResult = head_.hasResult;
		return h;
	}

	/// Whether both the id and the kind (request or response) are known, so
	/// the rest of the text cannot change what matters about the frame.
	bool decided() const @safe
	{
		return head_.id.type != Json.Type.undefined && (head_.hasMethod || head_.hasResult);
	}

	private void step(ubyte c) @safe
	{
		if (inString)
		{
			if (escaped)
				escaped = false;
			else if (c == '\\')
				escaped = true;
			else if (c == '"')
			{
				inString = false;
				endString();
				return;
			}
			if (capturing)
			{
				if (captured.length < maxCapture)
					captured ~= c;
				else
					captureOverflow = true;
			}
			return;
		}
		if (inNumber)
		{
			if (c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' || (c >= '0' && c <= '9'))
			{
				if (number.length < maxCapture)
					number ~= c;
				return;
			}
			inNumber = false;
			endNumber();
		}
		if (c == '"')
		{
			inString = true;
			stringIsId = expectValueForId;
			expectValueForId = false;
			capturing = stringIsId || depth == 1;
			captured = null;
			captureOverflow = false;
			return;
		}
		if (expectValueForId && (c == '-' || (c >= '0' && c <= '9')))
		{
			expectValueForId = false;
			inNumber = true;
			number = [c];
			return;
		}
		if (c == ':' && depth == 1 && afterKey)
		{
			expectValueForId = lastKey == "id";
			if (lastKey == "method")
				head_.hasMethod = true;
			else if (lastKey == "result" || lastKey == "error")
				head_.hasResult = true;
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
	}

	private void endString() @safe
	{
		import vibe.data.json : parseJsonString, JSONException;

		if (stringIsId)
		{
			if (captureOverflow)
				return;
			try
				head_.id = parseJsonString(`"` ~ (() @trusted => cast(string) captured)() ~ `"`);
			catch (JSONException)
			{
			}
			return;
		}
		if (depth == 1)
		{
			lastKey = captureOverflow ? null : cast(string) captured.idup;
			afterKey = true;
		}
	}

	private void endNumber() @safe
	{
		import std.conv : to, ConvException;

		try
			head_.id = Json((() @trusted => cast(string) number)().to!long);
		catch (ConvException)
		{
		}
	}
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

	// Bytes the GC has allocated on this thread so far.
	private ulong allocatedBytes() @trusted nothrow
	{
		import core.memory : GC;

		return GC.allocatedInCurrentThread;
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

unittest  // LineReader copies a line that arrives within one chunk only once
{
	enum size_t len = 1024 * 1024;
	auto chunk = new ubyte[len + 1];
	chunk[0 .. len] = 'x';
	chunk[len] = '\n';
	auto reader = LineReader(2 * len);
	bool fed;
	bool refill() @safe
	{
		if (fed)
			return false;
		fed = true;
		reader.buf = chunk;
		reader.bufPos = 0;
		return true;
	}

	const before = allocatedBytes();
	auto line = reader.nextWith(&refill);
	const allocated = allocatedBytes() - before;
	assert(line.length == len);
	assert(allocated < len + len / 2, "the line must be copied out of the buffer once");
}

unittest  // LineReader does not re-copy a line assembled across chunks
{
	enum size_t half = 512 * 1024;
	auto first = new ubyte[half];
	first[] = 'x';
	auto second = new ubyte[half + 1];
	second[0 .. half] = 'y';
	second[half] = '\n';
	auto reader = LineReader(4 * half);
	ubyte[][] chunks = [first, second];
	bool refill() @safe
	{
		if (chunks.length == 0)
			return false;
		reader.buf = chunks[0];
		chunks = chunks[1 .. $];
		reader.bufPos = 0;
		return true;
	}

	const before = allocatedBytes();
	auto line = reader.nextWith(&refill);
	const allocated = allocatedBytes() - before;
	assert(line.length == 2 * half && line[0] == 'x' && line[$ - 1] == 'y');
	assert(allocated < 5 * half, "the assembled line must not be duplicated again");
}

unittest  // LineReader finds the id of an over-long request that follows its large params
{
	import std.array : replicate;

	Json[] ids;
	const big = "a".replicate(3 * frameHeadScanBytes);
	auto text = `{"jsonrpc":"2.0","method":"tools/call","params":{"x":"` ~ big ~ `"},"id":7}`;
	auto lines = drainLineReader(64, [
		cast(ubyte[]) text[0 .. 100].dup, cast(ubyte[]) text[100 .. 5000].dup,
		cast(ubyte[]) text[5000 .. $ - 3].dup,
		cast(ubyte[])(text[$ - 3 .. $] ~ "\ntail\n").dup
	], ids);
	assert(lines == ["tail"]);
	assert(ids.length == 1);
	assert(ids[0].type == Json.Type.int_ && ids[0].get!long == 7,
			"the id after the params is found in the dropped bytes");
}

unittest  // LineReader finds a late id when the over-long line and its newline share a chunk
{
	import std.array : replicate;

	Json[] ids;
	const big = "b".replicate(2 * frameHeadScanBytes);
	auto text = `{"method":"m","params":{"x":"` ~ big ~ `"},"id":"req-9"}` ~ "\n";
	drainLineReader(64, [cast(ubyte[]) text.dup], ids);
	assert(ids.length == 1 && ids[0].get!string == "req-9");
}

unittest  // FrameHeadScanner resumes across a split key, string and number
{
	FrameHeadScanner s;
	s.feed(cast(const(ubyte)[]) `{"me`);
	s.feed(cast(const(ubyte)[]) `thod":"x","params":{"id":1,"s":"a\`);
	s.feed(cast(const(ubyte)[]) `"b"},"i`);
	s.feed(cast(const(ubyte)[]) `d":12`);
	s.feed(cast(const(ubyte)[]) `34}`);
	auto head = s.head;
	assert(head.hasMethod && !head.hasResult);
	assert(head.id.get!long == 1234);
}

unittest  // FrameHeadScanner ignores a number cut off by the end of the input
{
	FrameHeadScanner s;
	s.feed(cast(const(ubyte)[]) `{"result":{},"id":12`);
	assert(s.head.id.type == Json.Type.null_);
}

unittest  // LineReader reports an over-long line early once its id and kind are known
{
	import std.array : replicate;

	auto reader = LineReader(16);
	FrameHead early;
	bool fired;
	reader.onOversized = (FrameHead h) @safe { fired = true; early = h; };
	auto first = cast(ubyte[])(`{"id":3,"result":{"x":"` ~ "c".replicate(64)).dup;
	bool firstFed;
	bool refill() @safe
	{
		if (firstFed)
		{
			assert(fired, "reported before the rest of the line is read");
			return false;
		}
		firstFed = true;
		reader.buf = first;
		reader.bufPos = 0;
		return true;
	}

	reader.nextWith(&refill);
	assert(fired && early.id.get!long == 3 && early.hasResult);
}

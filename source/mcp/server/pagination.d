/// Opaque pagination cursor codec for the `*/list` methods
/// (server/utilities/pagination). The server hands the client an opaque
/// `nextCursor` and the client passes it back as `params.cursor`; per spec
/// clients MUST treat cursors as opaque tokens, so the encoding here is an
/// implementation detail (base64url of the list method and the last-seen item's
/// sort key).
module mcp.server.pagination;

import std.typecons : Nullable;

import vibe.data.json : Json;

import mcp.protocol.errors : invalidParams;

@safe:

/// Prefix marking a cursor this server issued, so arbitrary base64 is rejected.
private enum cursorPrefix = "k:";

/// Separates the list method from the sort key; no method name contains it.
private enum methodSeparator = '\x1f';

/// Encode the list `method` and the sort key of the last item on a page into the
/// opaque cursor handed to the client. Keying on the item rather than its offset
/// keeps the next page anchored after that item even when earlier items are
/// added or removed; carrying the method stops a cursor from one list being
/// replayed against another.
package string encodeCursor(string method, string lastKey) @safe
{
	import std.string : representation;
	import mcp.auth.oauth : base64UrlNoPad;

	return base64UrlNoPad((cursorPrefix ~ method ~ methodSeparator ~ lastKey).representation);
}

/// Decode a pagination cursor previously produced by `encodeCursor` for `method`
/// back into the last-seen sort key. Throws `invalidParams` (-32602) for a
/// malformed cursor or one issued by a different list method, per the
/// pagination spec ("If the cursor is invalid ... SHOULD return ... Invalid
/// params").
package string decodeCursor(string method, string cursor) @safe
{
	import std.algorithm : startsWith;
	import std.base64 : Base64URLNoPadding, Base64Exception;
	import std.utf : validate, UTFException;

	string decoded;
	try
	{
		decoded = () @trusted {
			return cast(string) Base64URLNoPadding.decode(cursor);
		}();
		validate(decoded);
	}
	catch (Base64Exception)
		throw invalidParams("Invalid pagination cursor");
	catch (UTFException)
		throw invalidParams("Invalid pagination cursor");
	if (!decoded.startsWith(cursorPrefix))
		throw invalidParams("Invalid pagination cursor");
	const 
	body = decoded[cursorPrefix.length .. $];
	if (!body.startsWith(method ~ methodSeparator))
		throw invalidParams("Invalid pagination cursor: not issued by " ~ method);
	return
	body[method.length + 1 .. $];
}

/// Compute the slice `[begin, end)` of `keys` (the strictly ascending sort keys
/// of the items `method` lists) for the page requested by `params.cursor`, honouring
/// `pageSize`. The page starts at the first key after the cursor's last-seen
/// key. When more items remain after `end`, `next` is set to the cursor for the
/// following page (otherwise left null). With pagination disabled
/// (`pageSize == 0`) the whole list is returned and `next` stays null. Throws
/// `invalidParams` for a malformed or non-string cursor, or one issued by a
/// different list method; an explicit `null` cursor is read as absent.
package void pageBounds(string method, Json params, const(string)[] keys,
		size_t pageSize, out size_t begin, out size_t end, out Nullable!string next) @safe
{
	import std.range : assumeSorted;

	begin = 0;
	const cursor = (params.type == Json.Type.object && "cursor" in params) ? params["cursor"]
		: Json.undefined;
	if (cursor.type != Json.Type.undefined && cursor.type != Json.Type.null_)
	{
		if (cursor.type != Json.Type.string)
			throw invalidParams("Invalid pagination cursor");
		const lastKey = decodeCursor(method, cursor.get!string);
		begin = keys.length - keys.assumeSorted.upperBound(lastKey).length;
	}

	// Compared as `pageSize >= remaining` so a huge page size cannot overflow.
	if (pageSize == 0 || pageSize >= keys.length - begin)
	{
		end = keys.length;
	}
	else
	{
		end = begin + pageSize;
		next = encodeCursor(method, keys[end - 1]);
	}
}

unittest  // a non-string cursor is rejected with -32602
{
	import std.exception : collectException;
	import mcp.protocol.errors : McpException, ErrorCode;

	foreach (bad; [Json(5), Json.emptyObject, Json(true)])
	{
		size_t b, e;
		Nullable!string next;
		auto ex = cast(McpException) collectException(pageBounds("tools/list",
				Json(["cursor": bad]), ["a", "b", "c"], 2, b, e, next));
		assert(ex !is null && ex.code == ErrorCode.invalidParams, bad.toString());
	}
}

unittest  // an explicit null cursor is treated as absent (first page)
{
	size_t b, e;
	Nullable!string next;
	pageBounds("tools/list", Json(["cursor": Json(null)]), ["a", "b", "c", "d"], 3, b, e, next);
	assert(b == 0 && e == 3 && !next.isNull);
}

unittest  // a cursor resumes after its key even when that key is gone
{
	size_t b, e;
	Nullable!string next;
	pageBounds("tools/list", Json.emptyObject, ["a", "b", "c", "d"], 2, b, e, next);
	assert(b == 0 && e == 2);
	pageBounds("tools/list", Json(["cursor": Json(next.get)]), ["a", "c", "d"], 2, b, e, next);
	assert(b == 1 && e == 3 && next.isNull);
}

unittest  // a page size of size_t.max after a cursor returns the rest of the list
{
	size_t b, e;
	Nullable!string next;
	pageBounds("tools/list", Json([
		"cursor": Json(encodeCursor("tools/list", "a"))
	]), ["a", "b", "c"], size_t.max, b, e, next);
	assert(b == 1 && e == 3 && next.isNull);
}

unittest  // a well-formed base64 cursor the server never issued is rejected
{
	import std.exception : collectException;
	import std.string : representation;
	import mcp.auth.oauth : base64UrlNoPad;
	import mcp.protocol.errors : McpException, ErrorCode;

	size_t b, e;
	Nullable!string next;
	auto ex = cast(McpException) collectException(pageBounds("tools/list",
			Json(["cursor": Json(base64UrlNoPad("999".representation))]), ["a"], 1, b, e, next));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
}

unittest  // a cursor issued by one list method is rejected by another
{
	import std.exception : collectException;
	import mcp.protocol.errors : McpException, ErrorCode;

	size_t b, e;
	Nullable!string next;
	pageBounds("tools/list", Json.emptyObject, ["a", "b", "c"], 1, b, e, next);
	auto ex = cast(McpException) collectException(pageBounds("prompts/list",
			Json(["cursor": Json(next.get)]), ["a", "b", "c"], 1, b, e, next));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
}

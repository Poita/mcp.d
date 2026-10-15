/// Opaque pagination cursor codec for the `*/list` methods
/// (server/utilities/pagination). The server hands the client an opaque
/// `nextCursor` and the client passes it back as `params.cursor`; per spec
/// clients MUST treat cursors as opaque tokens, so the encoding here is an
/// implementation detail (base64url of the last-seen item's sort key).
module mcp.server.pagination;

import std.typecons : Nullable;

import vibe.data.json : Json;

import mcp.protocol.errors : invalidParams;

@safe:

/// Prefix marking a cursor this server issued, so arbitrary base64 is rejected.
private enum cursorPrefix = "k:";

/// Encode the sort key of the last item on a page into the opaque cursor handed
/// to the client. Keying on the item rather than its offset keeps the next page
/// anchored after that item even when earlier items are added or removed.
package string encodeCursor(string lastKey) @safe
{
	import std.string : representation;
	import mcp.auth.oauth : base64UrlNoPad;

	return base64UrlNoPad((cursorPrefix ~ lastKey).representation);
}

/// Decode a pagination cursor previously produced by `encodeCursor` back into
/// the last-seen sort key. Throws `invalidParams` (-32602) for a malformed
/// cursor, per the pagination spec ("If the cursor is invalid ... SHOULD
/// return ... Invalid params").
package string decodeCursor(string cursor) @safe
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
	return decoded[cursorPrefix.length .. $];
}

/// Compute the slice `[begin, end)` of `keys` (the strictly ascending sort keys
/// of the listed items) for the page requested by `params.cursor`, honouring
/// `pageSize`. The page starts at the first key after the cursor's last-seen
/// key. When more items remain after `end`, `next` is set to the cursor for the
/// following page (otherwise left null). With pagination disabled
/// (`pageSize == 0`) the whole list is returned and `next` stays null. Throws
/// `invalidParams` for a malformed or non-string cursor; an explicit `null`
/// cursor is read as absent.
package void pageBounds(Json params, const(string)[] keys, size_t pageSize,
		out size_t begin, out size_t end, out Nullable!string next) @safe
{
	import std.range : assumeSorted;

	begin = 0;
	const cursor = (params.type == Json.Type.object && "cursor" in params) ? params["cursor"]
		: Json.undefined;
	if (cursor.type != Json.Type.undefined && cursor.type != Json.Type.null_)
	{
		if (cursor.type != Json.Type.string)
			throw invalidParams("Invalid pagination cursor");
		const lastKey = decodeCursor(cursor.get!string);
		begin = keys.length - keys.assumeSorted.upperBound(lastKey).length;
	}

	if (pageSize == 0 || begin + pageSize >= keys.length)
	{
		end = keys.length;
	}
	else
	{
		end = begin + pageSize;
		next = encodeCursor(keys[end - 1]);
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
		auto ex = cast(McpException) collectException(pageBounds(Json([
			"cursor": bad
		]), ["a", "b", "c"], 2, b, e, next));
		assert(ex !is null && ex.code == ErrorCode.invalidParams, bad.toString());
	}
}

unittest  // an explicit null cursor is treated as absent (first page)
{
	size_t b, e;
	Nullable!string next;
	pageBounds(Json(["cursor": Json(null)]), ["a", "b", "c", "d"], 3, b, e, next);
	assert(b == 0 && e == 3 && !next.isNull);
}

unittest  // a cursor resumes after its key even when that key is gone
{
	size_t b, e;
	Nullable!string next;
	pageBounds(Json.emptyObject, ["a", "b", "c", "d"], 2, b, e, next);
	assert(b == 0 && e == 2);
	pageBounds(Json(["cursor": Json(next.get)]), ["a", "c", "d"], 2, b, e, next);
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
	auto ex = cast(McpException) collectException(pageBounds(Json(
			["cursor": Json(base64UrlNoPad("999".representation))]), ["a"], 1, b, e, next));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
}

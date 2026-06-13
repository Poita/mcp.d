/// Opaque pagination cursor codec for the `*/list` methods
/// (server/utilities/pagination). The server hands the client an opaque
/// `nextCursor` and the client passes it back as `params.cursor`; per spec
/// clients MUST treat cursors as opaque tokens, so the encoding here is an
/// implementation detail (base64url of the decimal offset).
module mcp.server.pagination;

import std.typecons : Nullable;

import vibe.data.json : Json;

import mcp.protocol.errors : invalidParams;

@safe:

/// Encode an offset into the opaque pagination cursor handed to the client.
/// The format is intentionally opaque per spec ("Clients MUST treat cursors
/// as opaque tokens"); we base64url-encode the decimal offset.
package string encodeCursor(size_t offset) @safe
{
	import std.conv : to;
	import std.string : representation;
	import mcp.auth.oauth : base64UrlNoPad;

	return base64UrlNoPad(offset.to!string.representation);
}

/// Decode a pagination cursor previously produced by `encodeCursor`. Throws
/// `invalidParams` (-32602) for a malformed cursor, per the pagination spec
/// ("If the cursor is invalid ... SHOULD return ... Invalid params").
package size_t decodeCursor(string cursor) @safe
{
	import std.base64 : Base64URLNoPadding, Base64Exception;
	import std.conv : to, ConvException;

	try
	{
		auto decoded = () @trusted {
			return cast(string) Base64URLNoPadding.decode(cursor);
		}();
		return decoded.to!size_t;
	}
	catch (Base64Exception)
		throw invalidParams("Invalid pagination cursor");
	catch (ConvException)
		throw invalidParams("Invalid pagination cursor");
}

/// Compute the slice `[begin, end)` of a sorted list of `total` items for the
/// page requested by `params.cursor`, honouring `pageSize`. When more items
/// remain after `end`, `next` is set to the cursor for the following page
/// (otherwise left null). With pagination disabled (`pageSize == 0`) the whole
/// list is returned and `next` stays null. Throws `invalidParams` for a
/// malformed or out-of-range cursor.
package void pageBounds(Json params, size_t total, size_t pageSize,
		out size_t begin, out size_t end, out Nullable!string next) @safe
{
	begin = 0;
	if (params.type == Json.Type.object && "cursor" in params
			&& params["cursor"].type == Json.Type.string)
	{
		begin = decodeCursor(params["cursor"].get!string);
		// A cursor pointing past the end of the (now possibly shorter) list
		// is invalid rather than silently returning an empty final page.
		if (begin > total)
			throw invalidParams("Invalid pagination cursor");
	}

	if (pageSize == 0 || begin + pageSize >= total)
	{
		end = total;
	}
	else
	{
		end = begin + pageSize;
		next = encodeCursor(end);
	}
}

/// JSON Schema derivation and JSON → D argument binding for the reflection
/// layer, kept in one module so the two always agree.
///
/// `schemaOf!T` describes `T` the way vibe serializes it, and `bindJson!T` converts
/// an inbound JSON value into `T` following the same optionality rules the
/// reflected input schema advertises: a struct field is required unless it is
/// `Nullable`, carries vibe's `@optional`, or has a declared default (a
/// `@schemaDefault` UDA or an initializer differing from its type's `.init`). An
/// omitted optional field keeps its default. Struct fields are keyed by their
/// serialized name (vibe's `@name`, else the field name with one trailing
/// underscore stripped), and `@ignore`d fields are skipped. Enums are read by
/// member name at any depth.
module mcp.api.binding;

import std.traits;
import std.typecons : Nullable;

import jsonschema.node : JsonNode;
import vibe.data.json : Json;

@safe:

/// Thrown by `bindJson` when a value cannot be bound to the target type. The
/// message names the offending field path relative to the bound value.
final class BindException : Exception
{
	this(string msg, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe
	{
		super(msg, file, line);
	}
}

/// Whether struct `T` is bound field by field. Structs vibe serializes in a
/// custom form (`std.datetime` types, `toJson`/`fromJson`, `toString`/
/// `fromString`, `toRepresentation`/`fromRepresentation`) and the `Nullable` /
/// `SumType` / `Json` wrappers are handled elsewhere.
package(mcp) template isFieldwiseStruct(T)
{
	import std.datetime.date : Date, DateTime, TimeOfDay;
	import std.datetime.systime : SysTime;
	import std.sumtype : isSumType;

	static if (!is(T == struct) || is(T == Json) || isInstanceOf!(Nullable, T)
			|| isSumType!T || is(T == SysTime) || is(T == DateTime)
			|| is(T == Date) || is(T == TimeOfDay))
		enum isFieldwiseStruct = false;
	else
		enum isFieldwiseStruct = !hasCustomRepresentation!T;
}

private enum hasCustomRepresentation(T) = __traits(hasMember, T, "fromJson")
	|| __traits(hasMember, T, "fromString") || __traits(hasMember, T, "fromRepresentation");

/// Whether field `field` of struct `T` takes part in (de)serialization: a
/// public, non-`@ignore`d instance field.
package(mcp) template isBoundField(T, string field)
{
	import vibe.data.serialization : IgnoreAttribute;

	enum visibility = __traits(getVisibility, __traits(getMember, T, field));
	static if (visibility != "public" && visibility != "export")
		enum isBoundField = false;
	else
		enum isBoundField = !hasUDA!(__traits(getMember, T, field), IgnoreAttribute);
}

/// The JSON key field `field` of struct `T` is serialized under: vibe's `@name`
/// when present, else the field name with a single trailing underscore stripped
/// (vibe's convention for fields named after D keywords).
package(mcp) template wireFieldName(T, string field)
{
	import vibe.data.serialization : NameAttribute;

	static if (hasUDA!(__traits(getMember, T, field), NameAttribute))
		enum wireFieldName = getUDAs!(__traits(getMember, T, field), NameAttribute)[0].name;
	else static if (field.length > 1 && field[$ - 1] == '_')
		enum wireFieldName = field[0 .. $ - 1];
	else
		enum wireFieldName = field;
}

/// Whether field `field` of struct `T` must be present in its JSON object: it is
/// not `Nullable`, not vibe-`@optional`, and has no declared default (a
/// `@schemaDefault` UDA, or an initializer that differs from its type's `.init`).
package(mcp) template isRequiredField(T, string field)
{
	import jsonschema.attributes : SchemaDefault;
	import vibe.data.serialization : OptionalAttribute;

	alias member = __traits(getMember, T, field);
	alias FT = typeof(member);

	static if (isInstanceOf!(Nullable, FT) || hasUDA!(member,
			OptionalAttribute) || hasUDA!(member, SchemaDefault))
		enum isRequiredField = false;
	else static if (hasCtInitializer!(T, field))
		enum isRequiredField = __traits(getMember, T.init, field) == FT.init;
	else
		enum isRequiredField = true;
}

/// Whether the declared initializer of field `field` of `T` is readable at
/// compile time (so it can be compared against its type's `.init`).
private enum hasCtInitializer(T, string field) = __traits(compiles,
			ctValue!(__traits(getMember, T.init, field)));

private enum ctValue(alias v) = v;

/// The JSON Schema for `T` as vibe (de)serializes it, fully inlined. Struct
/// fields are keyed by `wireFieldName`, listed in `required` per
/// `isRequiredField`, and carry their `@fieldDescription` and facet UDAs. With
/// `omitNull` a `Nullable!U` is described by the bare schema of `U` (an input
/// models optionality through `required`); otherwise it is `anyOf: [U, null]`.
/// Scalars, enums, and custom-serialized types come from the `jsonschema`
/// generator.
package(mcp) Json schemaOf(T, bool omitNull)()
{
	import jsonschema.vibejson : nodeToVibeJson;

	return nodeToVibeJson(schemaNode!(T, omitNull)());
}

/// `schemaOf` in the `jsonschema` IR, so facet UDAs can be folded onto the
/// result before rendering. `Ancestors` are the enclosing struct types, used to
/// reject recursive types, which an inlined schema cannot describe.
package(mcp) JsonNode schemaNode(T, bool omitNull, Ancestors...)()
{
	import std.meta : staticIndexOf;
	import std.sumtype : isSumType;

	static if (is(T == Json))
		return JsonNode.emptyObject();
	else static if (isInstanceOf!(Nullable, T))
	{
		auto inner = schemaNode!(TemplateArgsOf!T[0], omitNull, Ancestors)();
		static if (omitNull)
			return inner;
		else
			return anyOfNode(inner, typeNode("null"));
	}
	else static if (isSumType!T)
	{
		JsonNode[] members;
		static foreach (V; TemplateArgsOf!T)
			members ~= schemaNode!(V, omitNull, Ancestors)();
		return anyOfNode(members);
	}
	else static if (isFieldwiseStruct!T)
	{
		import jsonschema : applyUdaFacets, fieldDescription;

		static assert(staticIndexOf!(T, Ancestors) < 0,
				"cannot derive an inline JSON Schema for the recursive type " ~ T.stringof);
		auto s = typeNode("object");
		auto props = JsonNode.emptyObject();
		auto required = JsonNode.emptyArray();
		static foreach (field; FieldNameTuple!T)
		{
			static if (isBoundField!(T, field))
			{
				{
					alias member = __traits(getMember, T, field);
					auto prop = schemaNode!(typeof(member), omitNull, Ancestors, T)();
					static if (hasUDA!(member, fieldDescription))
						prop.set("description", JsonNode(getUDAs!(member,
								fieldDescription)[0].value));
					applyUdaFacets!(__traits(getAttributes, member))(prop);
					props.set(wireFieldName!(T, field), prop);
					static if (isRequiredField!(T, field))
						required.append(JsonNode(wireFieldName!(T, field)));
				}
			}
		}
		s.set("properties", props);
		if (required.array_.length)
			s.set("required", required);
		return s;
	}
	else static if (isArray!T && !isSomeString!T)
	{
		auto s = typeNode("array");
		s.set("items", schemaNode!(typeof(T.init[0]), omitNull, Ancestors)());
		return s;
	}
	else static if (isAssociativeArray!T && isSomeString!(KeyType!T))
	{
		auto s = typeNode("object");
		s.set("additionalProperties", schemaNode!(ValueType!T, omitNull, Ancestors)());
		return s;
	}
	else
	{
		import jsonschema : generate = jsonSchemaOf, GeneratorSettings;

		// (emitSchemaKeyword: false, inlineSubschemas: true, nullableOmitsNull)
		enum settings = GeneratorSettings(false, true, omitNull);
		return generate!(T, settings)();
	}
}

private JsonNode typeNode(string type) pure
{
	auto s = JsonNode.emptyObject();
	s.set("type", JsonNode(type));
	return s;
}

private JsonNode anyOfNode(JsonNode[] members...) pure
{
	auto anyOf = JsonNode.emptyArray();
	foreach (m; members)
		anyOf.append(m);
	auto s = JsonNode.emptyObject();
	s.set("anyOf", anyOf);
	return s;
}

/// Bind the JSON value `v` to `T`. `path` is the location of `v` relative to the
/// top-level value (empty at the top) and prefixes error messages. Throws
/// `BindException` for a shape or value that does not fit `T`.
package(mcp) T bindJson(T)(Json v, string path = "")
{
	import std.conv : to;
	import std.sumtype : isSumType;

	static if (is(T == Json))
		return v;
	else static if (isInstanceOf!(Nullable, T))
	{
		if (v.type == Json.Type.null_ || v.type == Json.Type.undefined)
			return T.init;
		return T(bindJson!(TemplateArgsOf!T[0])(v, path));
	}
	else static if (isSumType!T)
	{
		static foreach (V; TemplateArgsOf!T)
		{
			try
				return T(bindJson!V(v, path));
			catch (BindException)
			{
			}
		}
		throw new BindException(located(path, "matches none of the types in " ~ T.stringof));
	}
	else static if (isFieldwiseStruct!T)
	{
		if (v.type != Json.Type.object)
			throw new BindException(located(path, "expected a JSON object"));
		T result = T.init;
		static foreach (field; FieldNameTuple!T)
		{
			static if (isBoundField!(T, field))
			{
				{
					alias FT = typeof(__traits(getMember, T, field));
					enum key = wireFieldName!(T, field);
					const fieldPath = path.length ? path ~ "." ~ key : key;
					auto p = key in v;
					if (isPresent!FT(p))
						setBound(__traits(getMember, result, field), bindJson!FT(*p, fieldPath));
					else static if (isRequiredField!(T, field))
						throw new BindException("missing required field '" ~ fieldPath ~ "'");
				}
			}
		}
		return result;
	}
	else static if (isArray!T && !isSomeString!T)
	{
		if (v.type != Json.Type.array)
			throw new BindException(located(path, "expected a JSON array"));
		alias E = typeof(T.init[0]);
		static if (isStaticArray!T)
		{
			if (v.length != T.length)
				throw new BindException(located(path,
						"expected " ~ T.length.to!string ~ " elements, got " ~ v.length.to!string));
			T result;
		}
		else
			auto result = new E[v.length];
		foreach (idx; 0 .. v.length)
			result[idx] = bindJson!E(v[idx], path ~ "[" ~ idx.to!string ~ "]");
		return result;
	}
	else static if (isAssociativeArray!T && isSomeString!(KeyType!T))
	{
		if (v.type != Json.Type.object)
			throw new BindException(located(path, "expected a JSON object"));
		T result;
		foreach (kv; v.byKeyValue)
		{
			const entryPath = path.length ? path ~ "." ~ kv.key : kv.key;
			result[kv.key.to!(KeyType!T)] = bindJson!(ValueType!T)(kv.value, entryPath);
		}
		return result;
	}
	else
		return bindLeaf!T(v, path);
}

/// Assign a freshly bound `value` into `dst`, a default-initialized slot being
/// filled. Some types' assignment is `@system` (a `SumType` over types with
/// indirections, and aggregates containing one) because overwriting a live value
/// could leave a dangling reference into it; a default-initialized slot has no
/// such references, so the assignment is trusted when it is not already `@safe`.
package(mcp) void setBound(X)(ref X dst, X value)
{
	static if (__traits(compiles, ()@safe { dst = value; }))
		dst = value;
	else
		() @trusted { dst = value; }();
}

/// Whether a struct member's JSON value `p` counts as supplied. JSON `null`
/// means absent except for a `Json` field, which binds `null` verbatim.
private bool isPresent(FT)(const(Json)* p)
{
	if (p is null || p.type == Json.Type.undefined)
		return false;
	static if (is(FT == Json))
		return true;
	else
		return p.type != Json.Type.null_;
}

/// Bind a string-typed wire value — a `prompts/get` argument or a captured URI
/// template variable — to `T`. Strings pass through; enums (by member name),
/// integers, floating-point numbers, and booleans are parsed with `std.conv.to`;
/// `Nullable!U` binds `U`; `std.datetime` and other string-serialized types are
/// read from the string itself; structs, arrays, associative arrays, and
/// `SumType`s are read from the string as a JSON document. Throws
/// `BindException` when the string does not parse as `T`.
package(mcp) T bindString(T)(string raw, string path = "")
{
	import std.conv : to;
	import std.sumtype : isSumType;
	import vibe.data.json : parseJsonString;

	static if (isSomeString!T)
		return raw.to!T;
	else static if (isInstanceOf!(Nullable, T))
		return T(bindString!(TemplateArgsOf!T[0])(raw, path));
	else static if (is(T == Json))
		return Json(raw);
	else static if (is(T == enum) || isIntegral!T || isFloatingPoint!T || is(T == bool))
	{
		try
			return raw.to!T;
		catch (Exception e)
			throw new BindException(located(path, "cannot parse '" ~ raw ~ "' as " ~ T.stringof));
	}
	else static if (isFieldwiseStruct!T || isSumType!T || isArray!T || isAssociativeArray!T)
	{
		Json doc;
		try
			doc = parseJsonString(raw);
		catch (Exception e)
			throw new BindException(located(path, "expected a JSON document for " ~ T.stringof));
		return bindJson!T(doc, path);
	}
	else
		return bindJson!T(Json(raw), path);
}

/// Bind a scalar, enum, or vibe-custom-serialized value through vibe with enums
/// read by member name.
private T bindLeaf(T)(Json v, string path)
{
	import mcp.api.reflection : EnumByNamePolicy;
	import vibe.data.json : JsonSerializer;
	import vibe.data.serialization : deserializeWithPolicy;

	try
		return () @trusted {
		return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, T)(v);
	}();
	catch (Exception e)
		throw new BindException(located(path, e.msg));
}

private string located(string path, string msg) pure nothrow
{
	return path.length ? "field '" ~ path ~ "': " ~ msg : msg;
}

unittest  // bindJson fills omitted defaulted and Nullable fields from the struct's defaults
{
	import vibe.data.json : parseJsonString;

	static struct S
	{
		string q;
		int limit = 10;
		Nullable!int offset;
	}

	auto s = bindJson!S(parseJsonString(`{"q":"x"}`));
	assert(s.q == "x" && s.limit == 10 && s.offset.isNull);
}

unittest  // bindString parses scalars from their string forms
{
	assert(bindString!int("42") == 42);
	assert(bindString!bool("false") == false);
	assert(bindString!(Nullable!double)("1.5").get == 1.5);
	assert(bindString!string("5") == "5");
}

unittest  // bindString rejects a string that does not parse as the target type
{
	import std.exception : assertThrown;

	assertThrown!BindException(bindString!int("abc"));
	assertThrown!BindException(bindString!bool("yes"));
}

unittest  // bindJson binds a SumType to the first member type the value fits
{
	import std.sumtype : SumType, match;

	alias U = SumType!(int, string);
	assert(bindJson!U(Json(3)).match!((int n) => n == 3, (string _) => false));
	assert(bindJson!U(Json("a")).match!((int _) => false, (string t) => t == "a"));
}

unittest  // bindJson reports the dotted path of a missing nested field
{
	import std.exception : collectException;
	import vibe.data.json : parseJsonString;

	static struct Inner
	{
		int n;
	}

	static struct Outer
	{
		Inner[] items;
	}

	auto e = collectException!BindException(
			bindJson!Outer(parseJsonString(`{"items":[{"n":1},{}]}`)));
	assert(e !is null);
	assert(e.msg == "missing required field 'items[1].n'", e.msg);
}

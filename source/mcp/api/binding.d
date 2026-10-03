/// JSON Schema derivation and JSON → D argument binding for the reflection
/// layer, kept in one module so the two always agree.
///
/// `schemaOf!T` describes `T` the way vibe serializes it, and `bindJson!T` converts
/// an inbound JSON value into `T` following the same optionality rules the
/// reflected input schema advertises: a struct field is required unless it is
/// `Nullable`, carries vibe's `@optional`, has a declared default (a
/// `@schemaDefault` UDA or an initializer differing from its type's `.init`), or
/// belongs to an `@allOptional` struct. An omitted optional field takes its
/// `@schemaDefault` value, else keeps its initializer. Struct fields are keyed by their serialized name (vibe's `@name`,
/// else the field name with one trailing underscore stripped), and `@ignore`d
/// fields are skipped. Enums are read by member name at any depth.
module mcp.api.binding;

import std.traits;
import std.typecons : Nullable;

import jsonschema.node : JsonNode;
import vibe.data.json : Json;
import mcp.protocol.jsonhelpers : isFieldwiseStruct;

@safe:

/// Thrown by `bindJson` when a value cannot be bound to the target type. The
/// message names the offending field path relative to the bound value and is
/// written for the caller that sent the value (it reaches an MCP client as a
/// tool error), so it carries no D-side advice. A field the client should be
/// able to omit is made optional by declaring it `Nullable`, marking it vibe's
/// `@optional`, giving it a default, or marking its struct `@allOptional`.
final class BindException : Exception
{
	this(string msg, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe
	{
		super(msg, file, line);
	}
}

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
	else
		enum wireFieldName = wireName!field;
}

/// The JSON key for the D identifier `name` — a struct field without `@name`,
/// or a handler parameter: `name` with a single trailing underscore stripped, so
/// one named after a D keyword (`version_`, `body_`) appears as the keyword.
package(mcp) enum wireName(string name) = name.length > 1 && name[$ - 1] == '_' ? name[0 .. $ - 1]
		: name;

/// Whether field `field` of struct `T` must be present in its JSON object: `T`
/// is not `@allOptional`, and the field is not `Nullable`, not vibe-`@optional`,
/// and has no declared default (a `@schemaDefault` UDA, or an initializer that
/// differs from its type's `.init`).
package(mcp) template isRequiredField(T, string field)
{
	import jsonschema.attributes : SchemaDefault;
	import mcp.api.attributes : allOptional;
	import vibe.data.serialization : OptionalAttribute;

	alias member = __traits(getMember, T, field);
	alias FT = typeof(member);

	static if (hasUDA!(T, allOptional) || isInstanceOf!(Nullable, FT)
			|| hasUDA!(member, OptionalAttribute) || hasUDA!(member, SchemaDefault))
		enum isRequiredField = false;
	else static if (hasCtInitializer!(T, field))
		enum isRequiredField = isInitValue(__traits(getMember, T.init, field));
	else
		enum isRequiredField = true;
}

/// Whether `v` equals `reference`, by default its type's `.init`. Floating-point
/// values are compared bitwise so a `.init` of NaN matches itself, and fieldwise
/// structs and static arrays are compared member by member against the matching
/// member of `reference` so a NaN inside them does too.
private bool isInitValue(V)(const V v, const V reference = V.init)
{
	static if (isFloatingPoint!V)
		return v is reference;
	else static if (isStaticArray!V)
	{
		foreach (i, ref e; v)
			if (!isInitValue(e, reference[i]))
				return false;
		return true;
	}
	else static if (isFieldwiseStruct!V)
	{
		static foreach (i; 0 .. V.tupleof.length)
			if (!isInitValue(v.tupleof[i], reference.tupleof[i]))
				return false;
		return true;
	}
	else
		return v == reference;
}

/// Whether the declared initializer of field `field` of `T` is readable at
/// compile time (so it can be compared against its type's `.init`).
private enum hasCtInitializer(T, string field) = __traits(compiles,
			ctValue!(__traits(getMember, T.init, field)));

private enum ctValue(alias v) = v;

/// Which side of a tool a derived schema describes.
package(mcp) enum SchemaUse
{
	/// A tool's arguments, which `bindJson` reads.
	input,
	/// A tool's structured result, as vibe serializes it.
	output,
}

/// The JSON Schema for `T` as vibe (de)serializes it, fully inlined. Struct
/// fields are keyed by `wireFieldName`, listed in `required` per
/// `isRequiredField`, and carry their `@fieldDescription` and facet UDAs. For
/// an input a `Nullable!U` is the schema of `U` widened in place to admit
/// `null` (see `admitNull`), since `bindJson` reads `null` as an unset value;
/// for an output it is `anyOf: [U, null]`. `TimeOfDay` and `DateTime` are
/// strings constrained by a pattern. Other scalars, enums, and
/// custom-serialized types come from the `jsonschema` generator.
package(mcp) Json schemaOf(T, SchemaUse use)()
{
	import jsonschema.vibejson : nodeToVibeJson;

	return nodeToVibeJson(schemaNode!(T, use)());
}

/// `schemaOf` in the `jsonschema` IR, so facet UDAs can be folded onto the
/// result before rendering. `Ancestors` are the enclosing struct types, used to
/// reject recursive types, which an inlined schema cannot describe.
package(mcp) JsonNode schemaNode(T, SchemaUse use, Ancestors...)()
{
	import std.datetime.date : DateTime, TimeOfDay;
	import std.meta : staticIndexOf;
	import std.sumtype : isSumType;

	static if (is(T == Json))
		return JsonNode.emptyObject();
	else static if (is(T == TimeOfDay))
		return patternNode(timeOfDayPattern);
	else static if (is(T == DateTime))
		return patternNode(
				`^-?[0-9]{4,}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T` ~ timeOfDayPattern[1 .. $]);
	else static if (isInstanceOf!(Nullable, T))
	{
		auto inner = schemaNode!(TemplateArgsOf!T[0], use, Ancestors)();
		static if (use == SchemaUse.input)
			return admitNull(inner);
		else
			return anyOfNode(inner, typeNode("null"));
	}
	else static if (isSumType!T)
	{
		JsonNode[] members;
		static foreach (V; TemplateArgsOf!T)
			members ~= schemaNode!(V, use, Ancestors)();
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
					auto prop = schemaNode!(typeof(member), use, Ancestors, T)();
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
	else static if (isArray!T && !isSomeString!T && !is(T == enum))
	{
		auto s = typeNode("array");
		s.set("items", schemaNode!(typeof(T.init[0]), use, Ancestors)());
		static if (isStaticArray!T)
		{
			s.set("minItems", JsonNode(long(T.length)));
			s.set("maxItems", JsonNode(long(T.length)));
		}
		return s;
	}
	else static if (isAssociativeArray!T && isSomeString!(KeyType!T))
	{
		auto s = typeNode("object");
		s.set("additionalProperties", schemaNode!(ValueType!T, use, Ancestors)());
		return s;
	}
	else
	{
		import jsonschema : generate = jsonSchemaOf, GeneratorSettings;

		// (emitSchemaKeyword: false, inlineSubschemas: true, nullableOmitsNull)
		enum settings = GeneratorSettings(false, true, use == SchemaUse.input);
		auto s = generate!(T, settings)();
		// Binding rejects a value outside an integer type's range, so a type
		// narrower than `int`, and `uint`, advertise that range. `int` and the
		// 64-bit types are left as a plain integer.
		static if (isIntegral!T && !is(T == enum) && (T.sizeof < 4 || is(T == uint)))
		{
			s.set("minimum", JsonNode(long(T.min)));
			s.set("maximum", JsonNode(long(T.max)));
		}
		// vibe writes a NaN — such as an unset field's `.init` — as `null`, so
		// a floating-point output may be `null`.
		static if (isFloatingPoint!T && use == SchemaUse.output)
			return admitNull(s);
		else
			return s;
	}
}

/// Why `T` cannot be described by `schemaOf` and bound from JSON (`use` is
/// `input`) or written as JSON (`output`), or `null` when it can. The reason
/// starts with the offending type, which may be nested anywhere inside `T` (a
/// struct field, an array element, a `Nullable` or `SumType` member), so a
/// handler can be rejected with a diagnostic naming it. `Ancestors` are the
/// enclosing struct types; a recursive type is left to `schemaNode` to reject.
package(mcp) string unsupportedTypeReason(T, SchemaUse use, Ancestors...)()
{
	import std.datetime.date : DateTime, TimeOfDay;
	import std.meta : staticIndexOf;
	import std.sumtype : isSumType;
	import std.typecons : Tuple;

	static if (is(T == Json) || is(T == TimeOfDay) || is(T == DateTime)
			|| staticIndexOf!(T, Ancestors) >= 0)
		return null;
	else static if (isInstanceOf!(Tuple, T))
		return T.stringof ~ ": a Tuple has no JSON Schema; use a struct with named fields";
	else static if (isInstanceOf!(Nullable, T))
		return unsupportedTypeReason!(TemplateArgsOf!T[0], use, Ancestors)();
	else static if (isSumType!T)
	{
		static foreach (V; TemplateArgsOf!T)
			if (auto r = unsupportedTypeReason!(V, use, Ancestors)())
				return r;
		return null;
	}
	else static if (isFieldwiseStruct!T)
	{
		import jsonschema.attributes : SchemaDefault;

		static foreach (field; FieldNameTuple!T)
		{
			static if (isBoundField!(T, field))
			{
				static foreach (d; getUDAs!(__traits(getMember, T, field), SchemaDefault))
					static if (!isDefaultFor!(typeof(__traits(getMember, T,
							field)), typeof(d.value)))
						return T.stringof ~ "." ~ field
							~ ": its @schemaDefault value of type " ~ typeof(d.value)
								.stringof ~ " does not convert to " ~ typeof(__traits(getMember,
										T, field)).stringof;
				if (auto r = facetMismatch!(typeof(__traits(getMember, T, field)),
						__traits(getAttributes, __traits(getMember, T, field)))())
					return T.stringof ~ "." ~ field ~ ": " ~ r;
				if (auto r = unsupportedTypeReason!(typeof(__traits(getMember,
						T, field)), use, Ancestors, T)())
					return r;
			}
		}
		return null;
	}
	else static if (is(T == enum) || is(T == bool) || isIntegral!T || isSomeString!T)
		return null;
	else static if (isFloatingPoint!T)
		return use == SchemaUse.input && is(Unqual!T == real)
			? T.stringof ~ ": a real argument cannot be read from JSON; use double" : null;
	else static if (isArray!T)
		return unsupportedTypeReason!(typeof(T.init[0]), use, Ancestors)();
	else static if (isAssociativeArray!T)
	{
		static if (!isSomeString!(KeyType!T))
			return T.stringof ~ ": JSON object keys are strings, so the key type must be a string";
		else
			return unsupportedTypeReason!(ValueType!T, use, Ancestors)();
	}
	else static if (is(T == struct))
		return null; // custom-serialized, such as SysTime or Date
	else
		return T.stringof ~ ": the type has no JSON representation";
}

/// The first JSON Schema facet among `udas` that cannot constrain a `T`, as
/// `@name`, or `null` when every facet fits: a string facet (`@minLength`,
/// `@maxLength`, `@pattern`, `@schemaFormat`) needs a value written as a JSON
/// string, `@minItems` / `@maxItems` an array, and `@minimum` / `@maximum` a
/// number. A `Nullable` is judged by the type it wraps; `Json` and `SumType`
/// values may take any shape, so every facet fits them.
package(mcp) string facetMismatch(T, udas...)()
{
	import jsonschema.attributes : Maximum, Minimum, format, maxItems,
		maxLength, minItems, minLength, pattern;
	import std.datetime.date : Date, DateTime, TimeOfDay;
	import std.datetime.systime : SysTime;
	import std.sumtype : isSumType;

	static if (isInstanceOf!(Nullable, T))
		return facetMismatch!(TemplateArgsOf!T[0], udas)();
	else static if (is(T == Json) || isSumType!T)
		return null;
	else
	{
		enum isString = isSomeString!T || is(T == enum) || is(T == SysTime)
			|| is(T == Date) || is(T == DateTime) || is(T == TimeOfDay);
		enum isList = isArray!T && !isString;
		enum isNumber = (isIntegral!T || isFloatingPoint!T) && !is(T == enum);
		static foreach (uda; udas)
		{
			static if (!is(uda))
			{
				static if (is(typeof(uda) == minLength)
						|| is(typeof(uda) == maxLength)
						|| is(typeof(uda) == pattern) || is(typeof(uda) == format))
				{
					if (!isString)
						return "@" ~ typeof(uda).stringof ~ " applies only to a string";
				}
				else static if (is(typeof(uda) == minItems) || is(typeof(uda) == maxItems))
				{
					if (!isList)
						return "@" ~ typeof(uda).stringof ~ " applies only to an array";
				}
				else static if (isInstanceOf!(Minimum, typeof(uda))
						|| isInstanceOf!(Maximum, typeof(uda)))
				{
					if (!isNumber)
						return "@" ~ (isInstanceOf!(Minimum, typeof(uda))
								? "minimum" : "maximum") ~ " applies only to a number";
				}
			}
		}
		return null;
	}
}

/// Whether a `@schemaDefault` value of type `V` can be the default of a `P`: it
/// converts to `P` (or, for a `Nullable`, to the type it wraps) without losing
/// a fractional part to an integer.
package(mcp) template isDefaultFor(P, V)
{
	static if (isInstanceOf!(Nullable, P))
		alias Target = TemplateArgsOf!P[0];
	else
		alias Target = P;
	enum isDefaultFor = is(typeof(cast(P) V.init)) && !(isFloatingPoint!V
				&& !isFloatingPoint!Target);
}

/// The value of the `@schemaDefault` UDA `uda` as a `P`, rejected at compile
/// time when it does not convert (see `isDefaultFor`).
package(mcp) P defaultAs(P, alias uda)()
{
	alias V = typeof(uda.value);
	static assert(isDefaultFor!(P, V),
			"a @schemaDefault value of type " ~ V.stringof ~ " does not convert to " ~ P.stringof);
	static if (isDefaultFor!(P, V))
		return cast(P) uda.value;
	else
		return P.init;
}

/// The `HH:MM:SS` form vibe reads and writes a `TimeOfDay` in. `TimeOfDay` and
/// `DateTime` carry no UTC offset, so they are described by patterns rather
/// than the RFC 3339 `time` / `date-time` formats, which require one.
private enum timeOfDayPattern = `^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$`;

private JsonNode patternNode(string pattern) pure
{
	auto s = typeNode("string");
	s.set("pattern", JsonNode(pattern));
	return s;
}

private JsonNode typeNode(string type) pure
{
	auto s = JsonNode.emptyObject();
	s.set("type", JsonNode(type));
	return s;
}

/// `s` widened to also accept JSON `null`, kept a single flat node so a client
/// still sees the plain shape of the value: a `type` gains `"null"` (becoming
/// `[type, "null"]`) and an `enum` gains a `null` member; a schema with no
/// `type` but an `anyOf` (a `SumType`) gains a `{"type": "null"}` member; a
/// schema constraining neither (`Json`) already admits `null`.
private JsonNode admitNull(JsonNode s) pure
{
	if (auto t = s.get("type"))
	{
		if (t.isString)
		{
			auto types = JsonNode.emptyArray();
			types.append(*t);
			types.append(JsonNode("null"));
			*t = types;
		}
		else if (t.isArray && !containsNode(*t, JsonNode("null")))
			t.append(JsonNode("null"));
		if (auto e = s.get("enum"))
			if (!containsNode(*e, JsonNode(null)))
				e.append(JsonNode(null));
	}
	else if (auto a = s.get("anyOf"))
		a.append(typeNode("null"));
	return s;
}

private bool containsNode(const JsonNode array, const JsonNode member) pure nothrow
{
	import jsonschema.node : jsonEquals;

	foreach (ref e; array.array_)
		if (jsonEquals(e, member))
			return true;
	return false;
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
	import jsonschema.attributes : SchemaDefault;
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
		// A member the JSON value is natively written as wins over an earlier one
		// that would merely convert it (an integer binds to `int`, not `double`);
		// failing that, the first member that accepts the value does.
		static foreach (V; TemplateArgsOf!T)
		{
			if (isNativeJsonType!V(v.type))
			{
				try
					return T(bindJson!V(v, path));
				catch (BindException)
				{
				}
			}
		}
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
					else static if (hasUDA!(__traits(getMember, T, field), SchemaDefault))
						setBound(__traits(getMember, result, field), defaultAs!(FT,
								getUDAs!(__traits(getMember, T, field), SchemaDefault)[0])());
					else static if (isRequiredField!(T, field))
						throw new BindException("missing required field '" ~ fieldPath ~ "'");
				}
			}
		}
		return result;
	}
	else static if (isArray!T && !isSomeString!T && !is(T == enum))
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

/// Whether vibe serializes a `V` as a JSON value of type `t`, so a value of
/// that type binds to `V` without conversion.
private bool isNativeJsonType(V)(Json.Type t) pure nothrow
{
	static if (isInstanceOf!(Nullable, V))
		return t == Json.Type.null_ || isNativeJsonType!(TemplateArgsOf!V[0])(t);
	else static if (is(V == bool))
		return t == Json.Type.bool_;
	else static if (is(V == enum) || isSomeString!V)
		return t == Json.Type.string;
	else static if (isIntegral!V)
		return t == Json.Type.int_ || t == Json.Type.bigInt;
	else static if (isFloatingPoint!V)
		return t == Json.Type.float_;
	else static if (isArray!V)
		return t == Json.Type.array;
	else static if (isFieldwiseStruct!V || isAssociativeArray!V)
		return t == Json.Type.object;
	else
		return false;
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
/// read by member name. A value of the wrong JSON type, an enum name that is
/// not a member, and an integer outside `T`'s range are reported in JSON terms.
/// An integer also binds from a JSON number with no fractional part (`2.0`),
/// which JSON Schema's `integer` admits and some clients send.
private T bindLeaf(T)(Json v, string path)
{
	import mcp.protocol.schema : EnumByNamePolicy;
	import std.conv : to;
	import vibe.data.json : JsonSerializer;
	import vibe.data.serialization : deserializeWithPolicy;

	static if (is(T == enum))
	{
		if (v.type != Json.Type.string)
			throw new BindException(located(path, "expected a string, got " ~ jsonTypeName(v)));
		static foreach (m; __traits(allMembers, T))
			if (v.get!string == m)
				return __traits(getMember, T, m);
		string names;
		static foreach (i, m; __traits(allMembers, T))
			names ~= (i ? ", " : "") ~ `"` ~ m ~ `"`;
		throw new BindException(located(path, "expected one of " ~ names ~ ", got " ~ v.toString));
	}
	else static if (is(T == bool))
	{
		if (v.type != Json.Type.bool_)
			throw new BindException(located(path, "expected a boolean, got " ~ jsonTypeName(v)));
	}
	else static if (isSomeString!T)
	{
		if (v.type != Json.Type.string)
			throw new BindException(located(path, "expected a string, got " ~ jsonTypeName(v)));
	}
	else static if (isFloatingPoint!T)
	{
		if (v.type != Json.Type.int_ && v.type != Json.Type.bigInt && v.type != Json.Type.float_)
			throw new BindException(located(path, "expected a number, got " ~ jsonTypeName(v)));
	}
	else static if (isIntegral!T)
	{
		import std.math : isFinite, trunc;

		enum outOfRange = "expected an integer from " ~ T.min.to!string
			~ " to " ~ T.max.to!string ~ ", got ";
		if (v.type == Json.Type.float_)
		{
			const d = v.get!double;
			if (!isFinite(d) || d != trunc(d))
				throw new BindException(located(path,
						"expected an integer, got a number with a fractional part"));
			// The bounds are powers of two, exact as doubles, so a whole `d`
			// strictly inside them converts to `T` without overflow.
			enum double limit = 2.0 ^^ (T.sizeof * 8 - (isSigned!T ? 1 : 0));
			if (d >= limit || d < (isSigned!T ? -limit : 0))
				throw new BindException(located(path, outOfRange ~ v.toString));
			return cast(T) d;
		}
		if (v.type == Json.Type.int_)
		{
			const n = v.get!long;
			static if (T.sizeof < 8)
			{
				if (n < T.min || n > T.max)
					throw new BindException(located(path, outOfRange ~ v.toString));
			}
			else static if (isUnsigned!T)
			{
				if (n < 0)
					throw new BindException(located(path, outOfRange ~ v.toString));
			}
			return cast(T) n;
		}
		if (v.type != Json.Type.bigInt)
			throw new BindException(located(path, "expected an integer, got " ~ jsonTypeName(v)));
		{
			import std.bigint : BigInt;

			const b = v.get!BigInt;
			if (b < T.min || b > T.max)
				throw new BindException(located(path, outOfRange ~ v.toString));
		}
	}

	try
		return () @trusted {
		return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, T)(v);
	}();
	catch (Exception e)
		throw new BindException(located(path, e.msg));
}

/// How a JSON value's type reads in an error message: "a string", "an array".
private string jsonTypeName(const Json v)
{
	final switch (v.type)
	{
	case Json.Type.undefined:
	case Json.Type.null_:
		return "null";
	case Json.Type.bool_:
		return "a boolean";
	case Json.Type.int_:
	case Json.Type.bigInt:
	case Json.Type.float_:
		return "a number";
	case Json.Type.string:
		return "a string";
	case Json.Type.array:
		return "an array";
	case Json.Type.object:
		return "an object";
	}
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
	import std.algorithm.searching : startsWith;
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
	assert(e.msg.startsWith("missing required field 'items[1].n'"), e.msg);
}

unittest  // an undefaulted floating-point field is required, and a defaulted one is optional
{
	static struct S
	{
		double x;
		float y;
		double z = 2.5;
	}

	static assert(isRequiredField!(S, "x"));
	static assert(isRequiredField!(S, "y"));
	static assert(!isRequiredField!(S, "z"));
}

unittest  // an undefaulted struct field holding floating-point members is required
{
	static struct Vec2
	{
		double x;
		double y;
	}

	static struct S
	{
		Vec2 v;
		Vec2 w = Vec2(1, 2);
	}

	static assert(isRequiredField!(S, "v"));
	static assert(!isRequiredField!(S, "w"));
}

unittest  // bindJson rejects an object missing an undefaulted floating-point field
{
	import std.exception : assertThrown;
	import vibe.data.json : parseJsonString;

	static struct S
	{
		double x;
	}

	assertThrown!BindException(bindJson!S(parseJsonString(`{}`)));
}

unittest  // a bounded integer schema carries its type's minimum and maximum
{
	auto u8 = schemaOf!(ubyte, SchemaUse.input)();
	assert(u8["minimum"].get!long == 0 && u8["maximum"].get!long == 255, u8.toString);
	auto u16 = schemaOf!(ushort, SchemaUse.input)();
	assert(u16["maximum"].get!long == ushort.max, u16.toString);
	auto i8 = schemaOf!(byte, SchemaUse.input)();
	assert(i8["minimum"].get!long == -128 && i8["maximum"].get!long == 127, i8.toString);
	auto i16 = schemaOf!(short, SchemaUse.input)();
	assert(i16["minimum"].get!long == short.min
			&& i16["maximum"].get!long == short.max, i16.toString);
	auto u32 = schemaOf!(uint, SchemaUse.input)();
	assert(u32["maximum"].get!long == uint.max, u32.toString);
}

unittest  // a value outside a bounded integer type's range does not bind
{
	import std.exception : assertThrown;

	assertThrown!BindException(bindJson!ubyte(Json(256)));
	assertThrown!BindException(bindJson!byte(Json(-129)));
}

unittest  // a static array schema pins its length with minItems and maxItems
{
	auto s = schemaOf!(int[3], SchemaUse.input)();
	assert(s["type"].get!string == "array");
	assert(s["minItems"].get!long == 3, s.toString);
	assert(s["maxItems"].get!long == 3, s.toString);
	assert("minItems" !in schemaOf!(int[], SchemaUse.input)());
}

unittest  // an undefaulted struct field whose struct type has a defaulted member is required
{
	static struct Inner
	{
		int a;
		string b = "x";
	}

	static struct Outer
	{
		Inner inner;
		Inner[2] pair;
		Inner changed = Inner(0, "y");
	}

	static assert(isRequiredField!(Outer, "inner"));
	static assert(isRequiredField!(Outer, "pair"));
	static assert(!isRequiredField!(Outer, "changed"));
}

unittest  // a missing required field's error names only the field, for the client
{
	import std.exception : collectException;
	import vibe.data.json : parseJsonString;

	static struct S
	{
		bool verbose = false;
	}

	auto e = collectException!BindException(bindJson!S(parseJsonString(`{}`)));
	assert(e !is null);
	assert(e.msg == "missing required field 'verbose'", e.msg);
}

unittest  // every field of an @allOptional struct is optional and keeps its default when omitted
{
	import mcp.api.attributes : allOptional;
	import vibe.data.json : parseJsonString;

	@allOptional static struct S
	{
		bool verbose = false;
		int depth;
		string name = "x";
	}

	static assert(!isRequiredField!(S, "verbose"));
	static assert(!isRequiredField!(S, "depth"));
	auto s = bindJson!S(parseJsonString(`{"depth":2}`));
	assert(!s.verbose && s.depth == 2 && s.name == "x");
	assert("required" !in schemaOf!(S, SchemaUse.input)());
}

unittest  // bindJson binds a SumType to the member matching the JSON value's own type first
{
	import std.sumtype : SumType, has, match;

	alias N = SumType!(double, int);
	assert(bindJson!N(Json(3)).has!int);
	assert(bindJson!N(Json(1.5)).has!double);

	alias S = SumType!(string, bool);
	assert(bindJson!S(Json(true)).match!((string _) => false, (bool b) => b));
}

unittest  // bindJson falls back to a converting SumType member when none matches exactly
{
	import std.sumtype : SumType, match;

	alias N = SumType!(string, double);
	assert(bindJson!N(Json(3)).match!((string _) => false, (double d) => d == 3));
}

version (unittest) private enum Shade : string
{
	light = "L",
	dark = "D",
}

unittest  // a string-based enum field is described by member name
{
	static struct S
	{
		Shade shade;
	}

	auto s = schemaOf!(S, SchemaUse.input)();
	auto p = s["properties"]["shade"];
	assert(p["type"].get!string == "string", s.toString);
	assert(p["enum"].length == 2 && p["enum"][0].get!string == "light", s.toString);
}

unittest  // a string-based enum field binds from its member name
{
	import std.exception : assertThrown;
	import vibe.data.json : parseJsonString;

	static struct S
	{
		Shade shade;
	}

	assert(bindJson!S(parseJsonString(`{"shade":"dark"}`)).shade == Shade.dark);
	assertThrown!BindException(bindJson!S(parseJsonString(`{"shade":"D"}`)));
}

unittest  // an omitted @schemaDefault field binds to the advertised default
{
	import jsonschema : schemaDefault;
	import vibe.data.json : parseJsonString;

	static struct S
	{
		@schemaDefault(10) int limit;
		@schemaDefault(Shade.dark) Shade shade;
	}

	auto s = bindJson!S(parseJsonString(`{}`));
	assert(s.limit == 10 && s.shade == Shade.dark);
	assert(bindJson!S(parseJsonString(`{"limit":3}`)).limit == 3);
}

unittest  // bindString reads a string-based enum by member name
{
	assert(bindString!Shade("light") == Shade.light);
}

version (unittest) private class NotJson
{
}

unittest  // a type with no JSON form is reported as unsupported, naming the offending type
{
	import std.typecons : Tuple;

	static struct HoldsClass
	{
		NotJson c;
	}

	static assert(unsupportedTypeReason!(NotJson, SchemaUse.input)().length);
	static assert(unsupportedTypeReason!(int*, SchemaUse.input)().length);
	static assert(unsupportedTypeReason!(void delegate(), SchemaUse.input)().length);
	static assert(unsupportedTypeReason!(char, SchemaUse.input)().length);
	static assert(unsupportedTypeReason!(Tuple!(int, string), SchemaUse.output)().length);
	static assert(unsupportedTypeReason!(real, SchemaUse.input)().length);
	static assert(unsupportedTypeReason!(int[int], SchemaUse.input)().length);
	static assert(unsupportedTypeReason!(Nullable!(char)[], SchemaUse.input)().length);
	enum nested = unsupportedTypeReason!(HoldsClass, SchemaUse.input)();
	static assert(nested.length && nested[0 .. NotJson.stringof.length] == NotJson.stringof, nested);
}

unittest  // a type with a JSON form is not reported as unsupported
{
	import std.datetime.systime : SysTime;
	import std.sumtype : SumType;

	static struct Rec
	{
		int a;
		string[] b;
		Nullable!double c;
		SumType!(int, string) d;
		SysTime when;
		Json raw;
		Shade shade;
	}

	static assert(unsupportedTypeReason!(Rec, SchemaUse.input)() is null);
	static assert(unsupportedTypeReason!(int[string], SchemaUse.input)() is null);
	static assert(unsupportedTypeReason!(real, SchemaUse.output)() is null);
	static assert(unsupportedTypeReason!(string, SchemaUse.input)() is null);
}

unittest  // a struct field whose @schemaDefault does not convert to its type is reported
{
	import jsonschema : schemaDefault;

	static struct S
	{
		@schemaDefault("abc") int n;
	}

	static assert(unsupportedTypeReason!(S, SchemaUse.input)().length);
	static assert(isDefaultFor!(Nullable!int, int));
	static assert(isDefaultFor!(double, int));
	static assert(!isDefaultFor!(int, double));
	static assert(!isDefaultFor!(int, string));
}

unittest  // an integer binds from a JSON number with no fractional part
{
	assert(bindJson!int(Json(2.0)) == 2);
	assert(bindJson!long(Json(-7.0)) == -7);
	assert(bindJson!ubyte(Json(255.0)) == 255);
}

unittest  // an integer rejects a fractional or out-of-range JSON number, in JSON terms
{
	import std.exception : collectException;

	auto frac = collectException!BindException(bindJson!int(Json(2.5)));
	assert(frac !is null
			&& frac.msg == "expected an integer, got a number with a fractional part", frac.msg);
	auto big = collectException!BindException(bindJson!ubyte(Json(256.0)));
	assert(big !is null && big.msg == "expected an integer from 0 to 255, got 256", big.msg);
	auto over = collectException!BindException(bindJson!ubyte(Json(256)));
	assert(over !is null && over.msg == "expected an integer from 0 to 255, got 256", over.msg);
}

unittest  // a scalar of the wrong JSON type is reported in JSON terms
{
	import std.exception : collectException;
	import vibe.data.json : parseJsonString;

	auto e1 = collectException!BindException(bindJson!string(parseJsonString(`[1]`)));
	assert(e1 !is null && e1.msg == "expected a string, got an array", e1.msg);
	auto e2 = collectException!BindException(bindJson!int(Json("3")));
	assert(e2 !is null && e2.msg == "expected an integer, got a string", e2.msg);
	auto e3 = collectException!BindException(bindJson!bool(Json(1)));
	assert(e3 !is null && e3.msg == "expected a boolean, got a number", e3.msg);
	auto e4 = collectException!BindException(bindJson!double(Json.emptyObject));
	assert(e4 !is null && e4.msg == "expected a number, got an object", e4.msg);
	auto e5 = collectException!BindException(bindJson!Shade(Json(1)));
	assert(e5 !is null && e5.msg == "expected a string, got a number", e5.msg);
}

unittest  // an enum names its members when the value is not one of them
{
	import std.exception : collectException;

	auto e = collectException!BindException(bindJson!Shade(Json("D")));
	assert(e !is null && e.msg == `expected one of "light", "dark", got "D"`, e.msg);
}

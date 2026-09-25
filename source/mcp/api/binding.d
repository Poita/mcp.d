/// JSON Schema derivation and JSON → D argument binding for the reflection
/// layer, kept in one module so the two always agree.
///
/// `schemaOf!T` describes `T` the way vibe serializes it, and `bindJson!T` converts an inbound JSON value into `T` following the same
/// optionality rules the reflected input schema advertises: a struct field is
/// required unless it is `Nullable`, carries vibe's `@optional`, or has a
/// declared default (a `@schemaDefault` UDA or an initializer differing from its
/// type's `.init`). An omitted optional field keeps its default. Struct fields
/// are keyed by their serialized name (vibe's `@name`, else the field name with
/// one trailing underscore stripped), and `@ignore`d fields are skipped. Enums
/// are read by member name at any depth.
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
		enum isFieldwiseStruct = !__traits(hasMember, T, "fromJson") && !__traits(hasMember,
					T, "fromString") && !__traits(hasMember, T, "fromRepresentation");
}

/// Whether field `field` of struct `T` takes part in (de)serialization: a
/// public, non-`@ignore`d instance field.
package(mcp) template isBoundField(T, string field)
{
	import vibe.data.serialization : IgnoreAttribute;

	static if (__traits(getVisibility, __traits(getMember, T, field)) != "public"
			&& __traits(getVisibility, __traits(getMember, T, field)) != "export")
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

	alias FT = typeof(__traits(getMember, T, field));
	enum i = staticIndexOfField!(T, field);

	static if (isInstanceOf!(Nullable, FT) || hasUDA!(__traits(getMember, T,
			field), OptionalAttribute) || hasUDA!(__traits(getMember, T, field), SchemaDefault))
		enum isRequiredField = false;
	else static if (__traits(compiles, { enum d = T.init.tupleof[i]; }))
				enum isRequiredField = T.init.tupleof[i] == FT.init;
	else
				enum isRequiredField = true;
				}

		private template staticIndexOfField(T, string field)
		{
			import std.meta : staticIndexOf;

			enum staticIndexOfField = staticIndexOf!(field, FieldNameTuple!T);
		}

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
					{
					auto anyOf = JsonNode.emptyArray();
					anyOf.append(inner);
					anyOf.append(typeNode("null"));
					auto s = JsonNode.emptyObject();
					s.set("anyOf", anyOf);
					return s;
				}
			}
			else static if (isSumType!T)
				{
				auto anyOf = JsonNode.emptyArray();
				static foreach (V; TemplateArgsOf!T)
					anyOf.append(schemaNode!(V, omitNull, Ancestors)());
				auto s = JsonNode.emptyObject();
				s.set("anyOf", anyOf);
				return s;
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

				enum GeneratorSettings settings = {
					inlineSubschemas: true,
					nullableOmitsNull: omitNull
					};
					return generate!(T, settings)();
				}
			}

			private JsonNode typeNode(string type) pure
			{
				auto s = JsonNode.emptyObject();
				s.set("type", JsonNode(type));
				return s;
			}

			/// Bind the JSON value `v` to `T`. `path` is the location of `v` relative to the
			/// top-level value (empty at the top) and prefixes error messages. Throws
			/// `BindException` for a shape or value that does not fit `T`.
			package(mcp) T bindJson(T)(Json v, string path = "")
			{
				import std.sumtype : isSumType;

				static if (is(T == Json))
					return v;
				else static if (isInstanceOf!(Nullable, T))
					{
					if (v.type == Json.Type.null_ || v.type == Json.Type.undefined)
						return T.init;
					return T(bindJson!(TemplateArgsOf!T[0])(v, path));
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
								static if (is(FT == Json))
									const present = p !is null && p.type != Json.Type.undefined;
								else
									const present = p !is null && p.type != Json.Type.null_
										&& p.type != Json.Type.undefined;
								if (present)
									__traits(getMember, result, field) = bindJson!FT(*p, fieldPath);
								else static if (isRequiredField!(T, field))
									throw new BindException(
										"missing required field '" ~ fieldPath ~ "'");
							}
						}
					}
					return result;
				}
				else static if (isArray!T && !isSomeString!T)
					{
					import std.conv : to;

					if (v.type != Json.Type.array)
						throw new BindException(located(path, "expected a JSON array"));
					alias E = typeof(T.init[0]);
					static if (isStaticArray!T)
						{
						if (v.length != T.length)
							throw new BindException(located(path, "expected "
								~ T.length.to!string ~ " elements, got " ~ v.length.to!string));
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
					import std.conv : to;

					T result;
					foreach (kv; v.byKeyValue)
						result[kv.key.to!(KeyType!T)] = bindJson!(ValueType!T)(kv.value,
							path.length ? path ~ "." ~ kv.key : kv.key);
					return result;
				}
				else
					return bindLeaf!T(v, path);
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

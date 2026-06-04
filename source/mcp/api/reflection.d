module mcp.api.reflection;

import std.traits;
import std.typecons : Tuple, Nullable, nullable;
import std.meta : AliasSeq;

import vibe.data.json : Json, serializeToJson, deserializeJson, JsonSerializer;
import vibe.data.serialization : serializeWithPolicy, deserializeWithPolicy;

import mcp.protocol.types;
import mcp.protocol.capabilities : Icon;
import mcp.protocol.draft : CacheHint, CacheScope;
import mcp.server.server : McpServer, ToolResponse;
import mcp.server.context;
import mcp.api.attributes;
import mcp.api.schema;

@safe:

/// vibe.data serialization policy that maps any `enum` leaf to / from its
/// member *name* (string), rather than vibe's default numeric base value.
///
/// The reflection layer emits enum schemas as `{type:"string", enum:[names…]}`
/// (see `jsonSchemaOf`), so both directions of marshalling must agree: struct
/// params/returns and bare-enum values are (de)serialized by-name. The policy
/// only defines `toRepresentation`/`fromRepresentation` for enums, so vibe's
/// `isPolicySerializable` is false for every other type and the default
/// behaviour is preserved (it still recurses into nested struct/array fields,
/// applying this rule to any enum found at any depth).
template EnumByNamePolicy(T) if (is(T == enum))
{
	import std.conv : to;

	static string toRepresentation(T v) @safe
	{
		return v.to!string;
	}

	static T fromRepresentation(string s) @safe
	{
		return s.to!T;
	}
}

/// Register every `@tool` / `@prompt` / `@resource` / `@resourceTemplate`
/// annotated method of `obj` on `server`, deriving JSON schemas and argument
/// marshalling from the method signatures (FastMCP-style ergonomics).
void registerHandlers(T)(McpServer server, T obj) @safe
{
	registerAnnotatedMembers!(T, obj)(server);
}

/// Register every `@tool` / `@prompt` / `@resource` / `@resourceTemplate`
/// annotated **free function** in module `mod` on `server`, mirroring
/// `registerHandlers` but targeting module-scope symbols rather than the
/// methods of an instance (FastMCP-style module decoration).
///
/// Free functions cannot receive a `RequestContext` via `this`, so a context
/// must be taken as an explicit parameter (exactly as opt-in methods do).
/// Non-function members and functions without a recognized UDA are skipped.
void registerModule(alias mod)(McpServer server) @safe
{
	registerAnnotatedMembers!(mod, mod)(server);
}

/// Walk every overload of every member of `root` and dispatch each recognized
/// handler UDA to the matching register method. `root` supplies the member set;
/// `parent` is the symbol member calls resolve against — `(T, obj)` for an
/// instance, `(mod, mod)` for a module's free functions. Members without a
/// recognized UDA are skipped.
private void registerAnnotatedMembers(alias root, alias parent)(McpServer server) @safe
{
	static foreach (memberName; __traits(allMembers, root))
	{
		static if (__traits(compiles, __traits(getOverloads, root, memberName)))
		{
			static foreach (overload; __traits(getOverloads, root, memberName))
			{
				static foreach (attr; __traits(getAttributes, overload))
				{
					static if (is(typeof(attr) == tool))
						registerToolMethod!(memberName, overload, parent)(server, attr);
					else static if (is(typeof(attr) == prompt))
						registerPromptMethod!(memberName, overload, parent)(server, attr);
					else static if (is(typeof(attr) == resource))
						registerResourceMethod!(memberName, overload, parent)(server, attr);
					else static if (is(typeof(attr) == resourceTemplate))
						registerTemplateMethod!(memberName, overload, parent)(server, attr);
				}
			}
		}
	}
}

/// Convenience variadic form of `registerModule`: register the annotated free
/// functions of several modules in one call.
void registerModules(mods...)(McpServer server) @safe
{
	static foreach (mod; mods)
		registerModule!mod(server);
}

/// Resolve the documentation string for parameter `i` (named `pname`) of `func`
/// from the `@describe` UDA layer, or `""` when none applies.
///
/// Two spellings are honored:
///  * parameter-level `@describe(...)` attached directly to the parameter. The
///    single-string form `@describe("text")` (which fills the struct's first
///    field, `parameter`) is treated as the description; the explicit
///    `@describe(name, text)` form on a parameter uses `description`.
///  * method-level `@describe(name, text)` whose `parameter` matches `pname`,
///    documenting an argument from the function's own UDA list.
private string describeFor(alias func, size_t i, string pname)() @safe
{
	alias types = Parameters!func;
	string desc;
	// Parameter-level @describe.
	static foreach (attr; __traits(getAttributes, types[i .. i + 1]))
		static if (is(typeof(attr) == describe))
			{
			if (attr.description.length)
				desc = attr.description;
			else if (attr.parameter.length)
				desc = attr.parameter;
		}
	// Method-level @describe(name, text) naming this parameter.
	static foreach (attr; __traits(getAttributes, func))
		static if (is(typeof(attr) == describe))
			{
			if (attr.parameter == pname && attr.description.length)
				desc = attr.description;
		}
	return desc;
}

/// Whether `P` is an admissible `@mcpHeader` parameter type: one whose
/// `jsonSchemaOf` yields a draft primitive header type (integer/string/boolean).
/// `Nullable!T` is unwrapped to its inner type. Mirrors the runtime check
/// `draft.isPrimitiveHeaderType` so detection is symmetric at compile time.
private template isPrimitiveHeaderParam(P)
{
	import std.traits : isIntegral;

	static if (isInstanceOf!(Nullable, P))
		enum isPrimitiveHeaderParam = isPrimitiveHeaderParam!(TemplateArgsOf!P[0]);
	else
		enum isPrimitiveHeaderParam = is(P == bool) || is(P == enum)
			|| isIntegral!P || isSomeString!P;
}

/// Build the `{type:object, properties, required}` schema for a method's
/// parameters, skipping any `RequestContext` parameter.
private Json parametersSchema(alias func)() @safe
{
	import mcp.protocol.draft : validateHeaderName;
	import std.traits : ParameterDefaultValueTuple;

	alias names = ParameterIdentifierTuple!func;
	alias types = Parameters!func;
	// ParameterDefaultValueTuple yields `void` for a parameter with no declared
	// D-level default and the default value's type otherwise.
	alias defs = ParameterDefaultValueTuple!func;

	Json props = Json.emptyObject;
	Json required = Json.emptyArray;
	static foreach (i, P; types)
	{
		static if (!is(P : RequestContext))
		{
			{
				Json ps = jsonSchemaOf!P;
				// Draft x-mcp-header: a parameter tagged @mcpHeader is mirrored
				// into an `Mcp-Param-<name>` request header; emit the extension
				// property so the transport can validate it (see draft.paramHeaders).
				// The header name and parameter type are checked against the draft
				// `x-mcp-header` constraints at compile time: the value MUST be a
				// valid HTTP token (non-empty, 1*tchar, no CR/LF) and the parameter
				// MUST be a primitive type (string/integral/bool); `number`
				// (floating point) is NOT permitted.
				static foreach (attr; __traits(getAttributes, types[i .. i + 1]))
					static if (is(typeof(attr) == mcpHeader))
						{
						static assert(validateHeaderName(attr.name) is null,
								"@mcpHeader(\"" ~ attr.name ~ "\") is not a valid x-mcp-header value: "
								~ validateHeaderName(attr.name));
						// The draft permits only primitive x-mcp-header value types
						// (integer/string/boolean). Whitelist exactly those (plus the
						// `Nullable` thereof) so a struct/array/AA/`number` parameter is
						// rejected at the registration site rather than per-request via
						// the transport's `headerMismatch` (see draft.isPrimitiveHeaderType).
						static assert(isPrimitiveHeaderParam!P, "@mcpHeader cannot be applied to parameter '" ~ names[i] ~ "' of type " ~ P
								.stringof ~ "; x-mcp-header permits only integer/string/boolean (or Nullable thereof)");
						ps["x-mcp-header"] = attr.name;
					}
				// Fold the @describe UDA into the property's JSON Schema
				// `description` (a standard annotation keyword, valid in every
				// protocol version).
				{
					enum d = describeFor!(func, i, names[i]);
					static if (d.length)
						ps["description"] = d;
				}
				props[names[i]] = ps;
			}
			// A parameter is required only when it is neither Nullable nor carries a
			// declared D-level default value. ParameterDefaultValueTuple gives
			// `void` for params without a default.
			static if (!isInstanceOf!(Nullable, P) && is(defs[i] == void))
				required ~= Json(names[i]);
		}
	}
	Json s = Json.emptyObject;
	s["type"] = "object";
	s["properties"] = props;
	if (required.length > 0)
		s["required"] = required;
	return s;
}

/// Whether argument `name` is meaningfully present in `args`: keyed, and neither
/// JSON `null` nor `undefined`. The canonical absent/null/undefined predicate
/// shared by the defaulting and Nullable marshalling paths.
private bool argPresent(Json args, string name) @safe
{
	return (name in args) !is null && args[name].type != Json.Type.null_
		&& args[name].type != Json.Type.undefined;
}

/// Convert one JSON argument value into the parameter type `P`, falling back to
/// the parameter's declared D-level default `def` when the argument is absent.
/// `def` is the value from `ParameterDefaultValueTuple` for this slot.
private P marshalArgDefault(P, alias def)(Json args, string name) @safe
{
	static if (is(P : RequestContext))
	{
		assert(false, "context parameters are injected, not marshalled");
	}
	else
	{
		if (!argPresent(args, name))
			return def;
		return marshalArg!P(args, name);
	}
}

/// Convert one JSON argument value into the parameter type `P`.
private P marshalArg(P)(Json args, string name) @safe
{
	static if (is(P : RequestContext))
	{
		assert(false, "context parameters are injected, not marshalled");
	}
	else static if (isInstanceOf!(Nullable, P))
	{
		alias Inner = TemplateArgsOf!P[0];
		if (argPresent(args, name))
			return P(marshalScalar!Inner(args[name]));
		return P.init;
	}
	else
	{
		if (name in args)
			return marshalScalar!P(args[name]);
		return P.init;
	}
}

/// Convert a captured resource-template URI variable (always a string) into the
/// declared parameter type `P`. Enums are parsed by member name, other scalars
/// via `std.conv.to`; conversion failure throws (caller maps it to InvalidParams).
private P marshalTemplateVar(P)(string raw) @safe
{
	import std.conv : to;

	static if (is(P == string))
		return raw;
	else static if (is(P == enum) || isIntegral!P || isFloatingPoint!P || is(P == bool))
		return to!P(raw);
	else
	{
		// Aggregate / Nullable etc.: interpret the captured string as a JSON
		// document and deserialize through the enum-aware policy.
		import vibe.data.json : parseJsonString;

		return marshalScalar!P(parseJsonString(raw));
	}
}

private P marshalScalar(P)(Json v) @safe
{
	// Deserialize through EnumByNamePolicy so any enum — whether `P` itself or
	// an enum field nested inside a struct/array — is read from its schema-
	// declared string member name rather than vibe's default integer base
	// value. Non-enum types are unaffected by the policy.
	return () @trusted {
		return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, P)(v);
	}();
}

/// Deserialize a dynamic handler's raw wire `arguments` into a typed value `T`.
///
/// The UDA-driven registration overloads marshal each argument from the method
/// signature for you, but the dynamic `registerDynamicTool`/`registerDynamicPrompt`
/// overloads hand the handler the raw `Json arguments`. This is the inbound
/// counterpart of the client's `callTool!T`: it deserializes `arguments` through
/// the same enum-by-name policy the UDA layer uses (so any `enum` leaf is read
/// from its schema-declared member name, at any nesting depth) and maps a vibe
/// conversion failure to `invalidParams` (-32602), matching how the reflection
/// layer reports a malformed argument. A handler can then write
/// `auto a = argsAs!MyArgs(arguments);` instead of hand-rolling
/// `arguments["x"].get!int` with manual presence/type checks.
T argsAs(T)(Json arguments) @safe
{
	import mcp.protocol.errors : McpException, invalidParams;

	try
		return marshalScalar!T(arguments);
	catch (McpException e)
		throw e;
	catch (Exception e)
		throw invalidParams("arguments: " ~ e.msg);
}

/// The JSON Schema describing a tool's structured output, derived from its
/// return type — or `Json.undefined` when the tool produces unstructured text
/// (a `string`) or supplies its own `CallToolResult`. Aggregate (`struct`)
/// returns map to their object schema directly; scalar/array/enum returns are
/// wrapped under a `result` property so `structuredContent` is always an object.
private Json outputSchemaOf(R)() @safe
{
	static if (is(R == CallToolResult) || is(R == ToolResponse) || isSomeString!R || is(R == void))
		return Json.undefined;
	else static if (is(R == struct))
		return jsonSchemaOf!R;
	else
	{
		Json s = Json.emptyObject;
		s["type"] = "object";
		Json props = Json.emptyObject;
		props["result"] = jsonSchemaOf!R;
		s["properties"] = props;
		s["required"] = Json([Json("result")]);
		return s;
	}
}

/// Wrap a tool method's return value into a `CallToolResult`. The structured
/// result mirrors `outputSchemaOf!R`: structs serialize to an object; scalars,
/// arrays, and enums are wrapped under a `result` key; strings become text
/// content with no structured output.
private CallToolResult toToolResult(R)(R ret) @safe if (!is(R == void))
{
	static if (is(R == CallToolResult))
		return ret;
	else static if (isSomeString!R)
	{
		CallToolResult r;
		r.content = [Content.makeText(ret)];
		return r;
	}
	else
	{
		CallToolResult r;
		// Serialize through EnumByNamePolicy so enum leaves (the value itself, or
		// enums nested in structs/arrays) emit their schema-declared string member
		// name, matching the tool's outputSchema instead of an integer base value.
		static if (is(R == struct))
			auto structured = () @trusted {
				return serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(ret);
			}();
		else
		{
			Json structured = Json.emptyObject;
			structured["result"] = () @trusted {
				return serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(ret);
			}();
		}
		r.structuredContent = structured;
		r.content = [Content.makeText(structured.toString())];
		return r;
	}
}

/// Collect every `@icon` UDA on a method into the descriptor `Icon[]` shape.
private Icon[] collectIcons(alias overload)() @safe
{
	Icon[] icons;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == icon))
		{
			{
				Icon ic;
				ic.src = a.src;
				if (a.mimeType.length)
					ic.mimeType = nullable(a.mimeType);
				ic.sizes = a.sizes;
				icons ~= ic;
			}
		}
	}
	return icons;
}

/// Collect a `@meta` UDA's object into a descriptor `_meta` Json (undefined when
/// absent or when the supplied value is not an object).
private Json collectMeta(alias overload)() @safe
{
	Json m = Json.undefined;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == meta))
		{
			if (a.value.type == Json.Type.object)
				m = a.value;
		}
	}
	return m;
}

/// Fold a method's `@icon` UDAs into `descriptor.icons` and its `@meta` UDA into
/// `descriptor.meta`. Generic over any descriptor exposing those members (Tool,
/// Prompt, Resource, ResourceTemplate).
private void applyIconsAndMeta(alias overload, D)(ref D descriptor) @safe
{
	descriptor.icons = collectIcons!overload();
	auto m = collectMeta!overload();
	if (m.type == Json.Type.object)
		descriptor.meta = m;
}

/// Fold a resource/template method's value UDAs into `descriptor`: the
/// `@audience` / `@priority` / `@lastModified` annotations plus the shared
/// `@icon` / `@meta` metadata. Generic over Resource and ResourceTemplate, which
/// share the `annotations` / `icons` / `meta` members. Absent UDAs leave the
/// corresponding field unset (omitted from the wire form).
private void applyResourceMetadata(alias overload, D)(ref D descriptor) @safe
{
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == audience))
			descriptor.annotations.audience = a.roles;
		else static if (is(typeof(a) == priority))
			descriptor.annotations.priority = a.value;
		else static if (is(typeof(a) == lastModified))
			descriptor.annotations.lastModified = a.value;
	}
	applyIconsAndMeta!overload(descriptor);
}

/// Collect a `@cache` UDA into a `Nullable!CacheHint` for resource/template
/// registration; null when absent.
private Nullable!CacheHint collectCache(alias overload)() @safe
{
	Nullable!CacheHint hint;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == cache))
		{
			{
				CacheHint h;
				h.ttlMs = a.ttlMs;
				h.cacheScope = (a.scope_ == "private") ? CacheScope.private_ : CacheScope.public_;
				hint = h;
			}
		}
	}
	return hint;
}

private void registerToolMethod(string memberName, alias overload, alias parent)(
		McpServer server, tool attr) @safe
{
	import std.traits : ReturnType;

	Tool descriptor;
	descriptor.name = attr.name;
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	if (attr.title.length)
		descriptor.title = nullable(attr.title);
	descriptor.inputSchema = parametersSchema!overload();
	auto outSchema = outputSchemaOf!(ReturnType!overload)();
	if (outSchema.type == Json.Type.object)
		descriptor.outputSchema = outSchema;

	// Fold every method UDA in a single pass: the marker hint UDAs (@readOnly /
	// @destructive / @idempotent / @openWorld) and the @hintTitle value UDA into
	// typed ToolAnnotations, and @toolExecution into the descriptor's `execution`
	// field (2025-11-25 per-tool task-augmented execution negotiation). A single
	// loop keeps every UDA handled in one place so a new UDA cannot land in only
	// one pass. A marker's presence sets the corresponding hint to true; absence
	// leaves it unset (omitted from the wire form).
	ToolAnnotations anns;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (__traits(isSame, a, readOnly))
			anns.readOnlyHint = true;
		else static if (__traits(isSame, a, destructive))
			anns.destructiveHint = true;
		else static if (__traits(isSame, a, idempotent))
			anns.idempotentHint = true;
		else static if (__traits(isSame, a, openWorld))
			anns.openWorldHint = true;
		else static if (is(typeof(a) == hintTitle))
		{
			if (a.value.length)
				anns.title = a.value;
		}
		else static if (is(typeof(a) == toolExecution))
		{
			static assert(a.taskSupport == "forbidden"
					|| a.taskSupport == "optional" || a.taskSupport == "required",
					"@toolExecution requires one of forbidden/optional/required, got \""
					~ a.taskSupport ~ "\"");
			if (a.taskSupport.length)
				descriptor.execution = ToolExecution(nullable(a.taskSupport));
		}
	}
	if (!anns.empty)
		descriptor.annotations = anns.toJson();

	applyIconsAndMeta!overload(descriptor);

	server.registerDynamicTool(descriptor, (Json args, RequestContext ctx) @safe {
		import mcp.protocol.errors : McpException;

		alias names = ParameterIdentifierTuple!overload;
		alias defs = ParameterDefaultValueTuple!overload;
		// A malformed argument that the coarse input-schema check admits (e.g. when
		// schema validation is disabled, or a conversion the type-check cannot rule
		// out) must surface as a clean, attributed tool-execution error rather than
		// a raw std.conv/vibe exception string. This SDK classifies tool input
		// failures as `isError:true` results (not -32602), so the marshalling
		// failure is returned as an error CallToolResult, wrapped to the handler's
		// return type. Protocol errors thrown by the marshaller are re-thrown so an
		// inner McpException is not swallowed (mirrors the prompt path's pass-through).
		static CallToolResult marshalError(string argName, string msg) @safe
		{
			return CallToolResult.error("argument '" ~ argName ~ "': " ~ msg);
		}

		Tuple!(Parameters!overload) argv;
		static foreach (i, P; Parameters!overload)
		{
			static if (is(P : RequestContext))
				argv[i] = ctx;
			else
			{
				// A required parameter (neither Nullable nor carrying a D-level
				// default) must be present even when input-schema validation is
				// disabled; a missing one is a tool input error, not a silently
				// default-constructed value.
				static if (is(defs[i] == void) && !isInstanceOf!(Nullable, P))
				{
					if (!argPresent(args, names[i]))
					{
						static if (is(ReturnType!overload == ToolResponse))
							return ToolResponse.complete(marshalError(names[i],
								"required argument is missing"));
						else
							return marshalError(names[i], "required argument is missing");
					}
				}
				try
				{
					static if (is(defs[i] == void))
						argv[i] = marshalArg!P(args, names[i]);
					else
						argv[i] = marshalArgDefault!(P, defs[i])(args, names[i]);
				}
				catch (McpException e)
					throw e;
				catch (Exception e)
				{
					static if (is(ReturnType!overload == ToolResponse))
						return ToolResponse.complete(marshalError(names[i], e.msg));
					else
						return marshalError(names[i], e.msg);
				}
			}
		}
		// An MRTR-capable tool returns a ToolResponse directly, so it may answer
		// `inputRequired` (stateless elicitation) as well as `complete`; any other
		// return type is wrapped into a CallToolResult.
		static if (is(ReturnType!overload == ToolResponse))
			return __traits(getMember, parent, memberName)(argv.expand);
		else static if (is(ReturnType!overload == void))
		{
			__traits(getMember, parent, memberName)(argv.expand);
			CallToolResult empty;
			return empty;
		}
		else
			return toToolResult(__traits(getMember, parent, memberName)(argv.expand));
	});
}

/// Wrap a prompt method's return value into a `GetPromptResult`.
private GetPromptResult toPromptResult(R)(R ret) @safe
{
	static if (is(R == GetPromptResult))
		return ret;
	else static if (is(R == PromptMessage[]))
	{
		GetPromptResult r;
		r.messages = ret;
		return r;
	}
	else static if (isSomeString!R)
	{
		GetPromptResult r;
		r.messages = [PromptMessage("user", Content.makeText(ret))];
		return r;
	}
	else
		static assert(false,
				"@prompt method must return GetPromptResult, PromptMessage[], or string");
}

private void registerPromptMethod(string memberName, alias overload, alias parent)(
		McpServer server, prompt attr) @safe
{
	Prompt descriptor;
	descriptor.name = attr.name;
	if (attr.title.length)
		descriptor.title = nullable(attr.title);
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	alias names = ParameterIdentifierTuple!overload;
	alias defs = ParameterDefaultValueTuple!overload;
	static foreach (i, P; Parameters!overload)
	{
		static if (!is(P : RequestContext))
		{
			// Populate PromptArgument.description from the @describe UDA.
			enum d = describeFor!(overload, i, names[i]);
			// A prompt argument is required only when it is neither Nullable nor
			// carries a declared D-level default, matching the tool path.
			descriptor.arguments ~= PromptArgument(names[i], d.length
					? nullable(d) : Nullable!string.init,
					!isInstanceOf!(Nullable, P) && is(defs[i] == void));
		}
	}

	applyIconsAndMeta!overload(descriptor);

	server.registerDynamicPrompt(descriptor, (Json args) @safe {
		import mcp.protocol.errors : McpException, invalidParams;

		Tuple!(Parameters!overload) argv;
		static foreach (i, P; Parameters!overload)
		{
			static if (is(P : RequestContext))
				argv[i] = new NullContext;
			else static if (is(defs[i] == void))
			{
				// A malformed argument (e.g. an out-of-range enum member or a
				// non-numeric integer) must surface as InvalidParams (-32602)
				// rather than escaping as an internal error (-32603), mirroring
				// the resource-template path. Protocol errors thrown by the
				// marshaller are passed through unchanged so an inner
				// invalidParams is not double-wrapped.
				try
					argv[i] = marshalArg!P(args, names[i]);
				catch (McpException e)
					throw e;
				catch (Exception e)
					throw invalidParams("argument '" ~ names[i] ~ "': " ~ e.msg);
			}
			else
			{
				try
					argv[i] = marshalArgDefault!(P, defs[i])(args, names[i]);
				catch (McpException e)
					throw e;
				catch (Exception e)
					throw invalidParams("argument '" ~ names[i] ~ "': " ~ e.msg);
			}
		}
		return toPromptResult(__traits(getMember, parent, memberName)(argv.expand));
	});
}

private ResourceContents toResourceContents(R)(R ret, string uri, string mimeType) @safe
{
	static if (is(R == ResourceContents))
		return ret;
	else static if (isSomeString!R)
		return ResourceContents.makeText(uri, mimeType, ret);
	else
		static assert(false, "@resource method must return ResourceContents or string");
}

private void registerResourceMethod(string memberName, alias overload, alias parent)(
		McpServer server, resource attr) @safe
{
	Resource descriptor;
	descriptor.uri = attr.uri;
	descriptor.name = attr.name;
	if (attr.mimeType.length)
		descriptor.mimeType = nullable(attr.mimeType);

	applyResourceMetadata!overload(descriptor);

	server.registerResource(descriptor, () @safe {
		return toResourceContents(__traits(getMember, parent, memberName)(),
			attr.uri, attr.mimeType);
	}, collectCache!overload());
}

private void registerTemplateMethod(string memberName, alias overload, alias parent)(
		McpServer server, resourceTemplate attr) @safe
{
	ResourceTemplate descriptor;
	descriptor.uriTemplate = attr.uriTemplate;
	descriptor.name = attr.name;
	if (attr.mimeType.length)
		descriptor.mimeType = nullable(attr.mimeType);

	applyResourceMetadata!overload(descriptor);

	server.registerResourceTemplate(descriptor, (string uri, string[string] params) @safe {
		import mcp.protocol.errors : invalidParams;

		alias names = ParameterIdentifierTuple!overload;
		Tuple!(Parameters!overload) argv;
		static foreach (i, P; Parameters!overload)
		{
			static if (is(P : RequestContext))
				argv[i] = new NullContext;
			else static if (is(P == string))
				argv[i] = (names[i] in params) ? params[names[i]] : "";
			else
			{
				// A captured URI variable is always a string; convert it into the
				// declared parameter type instead of silently defaulting it to
				// `P.init`. Surface a conversion failure as InvalidParams
				// rather than throwing a raw exception.
				if (auto pv = names[i] in params)
				{
					try
						argv[i] = marshalTemplateVar!P(*pv);
					catch (Exception e)
						throw invalidParams("resource template parameter '" ~ names[i]
							~ "' could not be parsed as " ~ P.stringof ~ ": " ~ e.msg);
				}
				else
					argv[i] = P.init;
			}
		}
		auto ret = __traits(getMember, parent, memberName)(argv.expand);
		return toResourceContents(ret, uri, attr.mimeType);
	}, collectCache!overload());
}

version (unittest)
{
	private enum Priority
	{
		low,
		high
	}

	private struct Stats
	{
		int count;
		double total;
	}

	private final class DemoApi
	{
		@tool("add", "Add two integers")
		int add(int a, int b) @safe
		{
			return a + b;
		}

		@tool("stats", "Summarize a list of integers")
		Stats stats(int[] values) @safe
		{
			Stats s;
			foreach (v; values)
			{
				s.count++;
				s.total += v;
			}
			return s;
		}

		@tool("greet", "Greet someone")
		string greet(string name) @safe
		{
			return "Hello, " ~ name ~ "!";
		}

		@tool("classify", "Classify with an enum + optional note")
		string classify(Priority p, Nullable!string note) @safe
		{
			return note.isNull ? "p" : "n";
		}

		@tool("erase", "Erase a record", "Erase Record")
		@destructive @idempotent string erase(string id) @safe
		{
			return "erased " ~ id;
		}

		@tool("render", "Render a long report")
		@toolExecution("optional") string render(string spec) @safe
		{
			return "rendered " ~ spec;
		}

		@resource("test://doc", "Doc", "text/plain")
		string doc() @safe
		{
			return "document body";
		}

		@resource("test://readme", "Readme", "text/markdown")
		@priority(0.9) @audience("user") string readme() @safe
		{
			return "readme body";
		}

		@tool("query", "Query a region")
		string query(@mcpHeader("Region") string region, int limit)@safe
		{
			return region;
		}

		@tool("annotate", "Tool with described parameters")
		string annotate(@describe("the document id") string id,
				@describe("count", "how many copies") int count)@safe
		{
			return id;
		}

		@prompt("describedPrompt", "Prompt with a described argument")
		string describedPrompt(@describe("the subject to write about") string topic)@safe
		{
			return "Tell me about " ~ topic;
		}

		@prompt("intro", "Intro prompt")
		string intro(string topic) @safe
		{
			return "Tell me about " ~ topic;
		}

		@prompt("summary", "Summary prompt", "Summarize Text")
		string summary(string topic) @safe
		{
			return "Summarize " ~ topic;
		}

		@prompt("byPriority", "Prompt taking an enum argument")
		string byPriority(Priority p) @safe
		{
			return "priority " ~ (p == Priority.high ? "high" : "low");
		}

		@prompt("repeat", "Prompt taking an integer argument")
		string repeat(int count) @safe
		{
			return "count " ~ (count > 0 ? "pos" : "nonpos");
		}
	}

	import vibe.data.json : parseJsonString;
	import mcp.server.server : ToolResponse;
	import mcp.protocol.draft : InputRequest;

	// Fixture exercising icons, _meta, annotation title, per-resource cache
	// hint, and MRTR (ToolResponse) tools.
	private final class ExtApi
	{
		@tool("draw", "Draw something")
		@icon("https://example.com/draw.png", "image/png", ["48x48"])
		@meta(parseJsonString(`{"category":"art"}`))
		@readOnly @hintTitle("Draw Tool") string draw(string spec) @safe
		{
			return "drew " ~ spec;
		}

		@tool("ask", "MRTR tool that may ask for more input")
		ToolResponse ask(string seed) @safe
		{
			if (seed.length == 0)
				return ToolResponse.inputRequired([
				InputRequest("req1", "elicitation", Json.emptyObject)
			]);
			CallToolResult r;
			r.content = [Content.makeText("seeded " ~ seed)];
			return ToolResponse.complete(r);
		}

		@resource("ext://cached", "Cached", "application/json")
		@icon("https://example.com/res.svg")
		@meta(parseJsonString(`{"origin":"db"}`))
		@cache(5000, "private")
		string cached() @safe
		{
			return "{}";
		}

		@prompt("greeting", "A greeting prompt")
		@icon("https://example.com/prompt.png", "image/png", ["32x32"])
		@meta(parseJsonString(`{"audience":"all"}`))
		string greeting() @safe
		{
			return "hello";
		}
	}
}

unittest  // @tool reflection: schema derivation + typed dispatch
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json lp = Json.emptyObject;
	auto list = s.handle(Message(makeRequest(Json(1), "tools/list", lp))).get;
	assert(list["result"]["tools"].length == 8);

	// add -> scalar return wrapped under `result`, with an inferred outputSchema.
	Json p = Json.emptyObject;
	p["name"] = "add";
	p["arguments"] = Json(["a": Json(4), "b": Json(5)]);
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["result"].get!int == 9);
}

unittest  // @tool reflection: outputSchema is inferred from the return type
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json addSchema, statsSchema, greetTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "add")
			addSchema = tools[i]["outputSchema"];
		else if (name == "stats")
			statsSchema = tools[i]["outputSchema"];
		else if (name == "greet")
			greetTool = tools[i];
	}

	// Scalar return -> object schema wrapping the value under `result`.
	assert(addSchema["type"].get!string == "object");
	assert(addSchema["properties"]["result"]["type"].get!string == "integer");

	// Struct return -> the struct's object schema directly.
	assert(statsSchema["type"].get!string == "object");
	assert(statsSchema["properties"]["count"]["type"].get!string == "integer");
	assert(statsSchema["properties"]["total"]["type"].get!string == "number");

	// String return -> unstructured text, no outputSchema.
	assert("outputSchema" !in greetTool);
}

unittest  // @tool reflection: struct return produces matching structuredContent
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	Json p = Json.emptyObject;
	p["name"] = "stats";
	p["arguments"] = Json(["values": Json([Json(2), Json(3), Json(5)])]);
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["count"].get!int == 3);
	// `total` (a double) serializes as a JSON number; just confirm it's present
	// and numeric (int/float representation is vibe's choice for whole values).
	auto total = r["result"]["structuredContent"]["total"];
	assert(total.type == Json.Type.float_ || total.type == Json.Type.int_);
}

unittest  // @tool reflection: string return becomes text content
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	Json p = Json.emptyObject;
	p["name"] = "greet";
	p["arguments"] = Json(["name": Json("Sam")]);
	auto r = s.handle(Message(makeRequest(Json(3), "tools/call", p))).get;
	assert(r["result"]["content"][0]["text"].get!string == "Hello, Sam!");
}

unittest  // @tool reflection: a void-returning tool compiles, registers, and dispatches
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	static final class VoidApi
	{
		string lastCommand;

		@tool("doThing", "Perform a side-effecting command")
		void doThing(string what) @safe
		{
			lastCommand = what;
		}
	}

	auto api = new VoidApi;
	auto s = new McpServer("t", "1");
	registerHandlers(s, api);

	// The void tool is registered like any other.
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	assert(tools.length == 1);
	assert(tools[0]["name"].get!string == "doThing");

	// Dispatching invokes the method and returns an empty, non-error result.
	Json p = Json.emptyObject;
	p["name"] = "doThing";
	p["arguments"] = Json(["what": Json("erase")]);
	auto r = s.handle(Message(makeRequest(Json(7), "tools/call", p))).get;
	assert(api.lastCommand == "erase");
	assert(("error" in r) is null);
	assert(r["result"]["content"].length == 0);
	assert(("structuredContent" in r["result"]) is null);
}

unittest  // @tool reflection: a void-returning tool advertises no outputSchema
{
	static final class VoidSchemaApi
	{
		@tool("noop", "Does nothing observable")
		void noop() @safe
		{
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new VoidSchemaApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	assert(tools.length == 1);
	assert(("outputSchema" in tools[0]) is null);
}

unittest  // @tool reflection: enum param schema + optional Nullable param
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	// find classify
	bool found;
	foreach (i; 0 .. tools.length)
	{
		if (tools[i]["name"].get!string == "classify")
		{
			found = true;
			auto schema = tools[i]["inputSchema"];
			assert(schema["properties"]["p"]["type"].get!string == "string");
			assert(schema["properties"]["p"]["enum"].length == 2);
			// only p is required (note is Nullable)
			assert(schema["required"].length == 1);
		}
	}
	assert(found);
}

unittest  // @resource and @prompt reflection register and dispatch
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json rp = Json.emptyObject;
	rp["uri"] = "test://doc";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "document body");

	Json pp = Json.emptyObject;
	pp["name"] = "intro";
	pp["arguments"] = Json(["topic": Json("MCP")]);
	auto pr = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
	assert(pr["result"]["messages"][0]["content"]["text"].get!string == "Tell me about MCP");
}

unittest  // @prompt enum arg given an invalid member -> InvalidParams (-32602)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.errors : ErrorCode;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json pp = Json.emptyObject;
	pp["name"] = "byPriority";
	pp["arguments"] = Json(["p": Json("urgent")]); // not a Priority member
	auto resp = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
	assert("error" in resp, "expected an error for an invalid enum prompt argument");
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams,
			"invalid enum prompt arg must map to -32602, not -32603");
}

unittest  // @prompt integer arg given a non-numeric string -> InvalidParams (-32602)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.errors : ErrorCode;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json pp = Json.emptyObject;
	pp["name"] = "repeat";
	pp["arguments"] = Json(["count": Json("abc")]); // not an integer
	auto resp = s.handle(Message(makeRequest(Json(3), "prompts/get", pp))).get;
	assert("error" in resp, "expected an error for a non-numeric integer prompt argument");
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams,
			"non-numeric integer prompt arg must map to -32602, not -32603");
}

unittest  // @prompt reflection: optional title is emitted in prompts/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];

	bool foundIntro, foundSummary;
	foreach (i; 0 .. prompts.length)
	{
		auto name = prompts[i]["name"].get!string;
		if (name == "intro")
		{
			foundIntro = true;
			// A prompt without a title carries none on the wire.
			assert("title" !in prompts[i]);
		}
		else if (name == "summary")
		{
			foundSummary = true;
			assert(prompts[i]["title"].get!string == "Summarize Text");
		}
	}
	assert(foundIntro && foundSummary);
}

unittest  // @audience/@priority value UDAs: annotations appear in resources/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	bool foundReadme, foundDoc;
	foreach (i; 0 .. res.length)
	{
		auto uri = res[i]["uri"].get!string;
		if (uri == "test://readme")
		{
			foundReadme = true;
			assert(res[i]["annotations"]["audience"][0].get!string == "user");
			assert(res[i]["annotations"]["priority"].get!double == 0.9);
		}
		else if (uri == "test://doc")
		{
			foundDoc = true;
			// A resource without annotation UDAs carries no annotations.
			assert("annotations" !in res[i]);
		}
	}
	assert(foundReadme && foundDoc);
}

unittest  // @audience value UDA: multiple roles round-trip into annotations
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	@safe final class MultiAudienceApi
	{
		@resource("test://both", "Both", "text/plain")
		@audience("user", "assistant") @priority(0.5)
		string both() @safe
		{
			return "both";
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new MultiAudienceApi);
	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	Json bothRes;
	foreach (i; 0 .. res.length)
		if (res[i]["uri"].get!string == "test://both")
			bothRes = res[i];
	assert(bothRes.type == Json.Type.object);
	auto anns = bothRes["annotations"];
	assert(anns["audience"].length == 2);
	assert(anns["audience"][0].get!string == "user");
	assert(anns["audience"][1].get!string == "assistant");
	assert(anns["priority"].get!double == 0.5);
	// lastModified was not set, so it is omitted.
	assert("lastModified" !in anns);
}

unittest  // @tool reflection: optional title is emitted in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json eraseTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "erase")
			eraseTool = tools[i];
	assert(eraseTool.type == Json.Type.object);
	assert(eraseTool["title"].get!string == "Erase Record");
}

unittest  // marker hint UDAs: hints are serialized into annotations
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json eraseTool, addTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "erase")
			eraseTool = tools[i];
		else if (name == "add")
			addTool = tools[i];
	}

	auto anns = eraseTool["annotations"];
	assert(anns["destructiveHint"].get!bool == true);
	assert(anns["idempotentHint"].get!bool == true);
	// Unset hints are omitted entirely.
	assert("readOnlyHint" !in anns);
	assert("openWorldHint" !in anns);

	// A tool without any hint UDA carries no annotations object.
	assert("annotations" !in addTool);
}

unittest  // marker-UDA hints: @readOnly + @hintTitle produce the wire shape
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	@safe final class ReadOnlyApi
	{
		@tool("peek", "Read-only peek")
		@readOnly @hintTitle("Peek")
		string peek() @safe
		{
			return "peek";
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ReadOnlyApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json peekTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "peek")
			peekTool = tools[i];
	assert(peekTool.type == Json.Type.object);
	auto anns = peekTool["annotations"];
	// The @readOnly marker sets readOnlyHint=true; @hintTitle sets the title.
	assert(anns["readOnlyHint"].get!bool == true);
	assert(anns["title"].get!string == "Peek");
	// The unset markers are omitted entirely.
	assert("destructiveHint" !in anns);
	assert("idempotentHint" !in anns);
	assert("openWorldHint" !in anns);
}

unittest  // @toolExecution reflection: execution.taskSupport appears in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json renderTool, addTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "render")
			renderTool = tools[i];
		else if (name == "add")
			addTool = tools[i];
	}

	assert(renderTool.type == Json.Type.object);
	assert(renderTool["execution"]["taskSupport"].get!string == "optional");
	// A tool without @toolExecution carries no execution object.
	assert("execution" !in addTool);
}

version (unittest) private class ValidExecutionApi
{
	@tool("render", "Render")
	@toolExecution("required")
	string render(string spec) @safe
	{
		return spec;
	}
}

version (unittest) private class InvalidExecutionApi
{
	@tool("render", "Render")
	@toolExecution("optionl")
	string render(string spec) @safe
	{
		return spec;
	}
}

unittest  // @toolExecution: a valid taskSupport value reflects, an invalid one fails to compile
{
	auto s = new McpServer("t", "1");
	assert(__traits(compiles, registerHandlers(s, new ValidExecutionApi)));
	assert(!__traits(compiles, registerHandlers(s, new InvalidExecutionApi)));
}

version (unittest) private struct HeaderPayload
{
	string id;
}

version (unittest) private class StructHeaderApi
{
	@tool("agg", "Aggregate header")
	string agg(@mcpHeader("X-Payload") HeaderPayload p)@safe
	{
		return p.id;
	}
}

version (unittest) private class ArrayHeaderApi
{
	@tool("arr", "Array header")
	string arr(@mcpHeader("X-Tags") string[] tags)@safe
	{
		return tags.length ? tags[0] : "";
	}
}

version (unittest) private class NullableHeaderApi
{
	@tool("opt", "Optional primitive header")
	string opt(@mcpHeader("X-Region") Nullable!int region)@safe
	{
		return region.isNull ? "" : "set";
	}
}

unittest  // @mcpHeader: a struct-typed parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new StructHeaderApi)));
}

unittest  // @mcpHeader: an array-typed parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new ArrayHeaderApi)));
}

unittest  // @mcpHeader: a Nullable-of-primitive parameter is accepted at compile time
{
	auto s = new McpServer("t", "1");
	assert(__traits(compiles, registerHandlers(s, new NullableHeaderApi)));
}

unittest  // @mcpHeader reflection: x-mcp-header is emitted into the param schema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.draft : paramHeaderMap;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json queryTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "query")
			queryTool = tools[i];
	assert(queryTool.type == Json.Type.object);

	auto schema = queryTool["inputSchema"];
	// The annotated parameter carries the x-mcp-header property.
	assert(schema["properties"]["region"]["x-mcp-header"].get!string == "Region");
	// The non-annotated parameter does not.
	assert("x-mcp-header" !in schema["properties"]["limit"]);

	// The consumer side (draft.paramHeaderMap) now reads it from the UDA-driven schema.
	auto m = paramHeaderMap(schema);
	assert(m["region"] == "Mcp-Param-Region");
}

unittest  // @tool dispatch: a malformed arg (validation off) yields a clean attributed message
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import std.algorithm.searching : canFind;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	// With schema validation off the coarse pre-dispatch check is bypassed, so the
	// marshaller sees the malformed value and must report a clean, attributed error.
	s.disableInputSchemaValidation();

	Json cp = Json.emptyObject;
	cp["name"] = "query";
	cp["arguments"] = Json(["region": Json("us"), "limit": Json("abc")]);
	auto resp = s.handle(Message(makeRequest(Json(4), "tools/call", cp))).get;
	// Tool input failures are classified as isError:true results, not -32602.
	assert("result" in resp, "malformed tool arg must be an isError result, not a protocol error");
	assert(resp["result"]["isError"].get!bool);
	auto text = resp["result"]["content"][0]["text"].get!string;
	assert(text.canFind("argument 'limit'"),
			"the error text must attribute the failure to the named argument: " ~ text);
}

unittest  // @describe UDA: parameter descriptions appear in tool inputSchema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json annotateTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "annotate")
			annotateTool = tools[i];
	assert(annotateTool.type == Json.Type.object);

	auto props = annotateTool["inputSchema"]["properties"];
	// Parameter-level @describe with a single argument documents the property.
	assert(props["id"]["description"].get!string == "the document id");
	// Parameter-level @describe naming itself documents the property.
	assert(props["count"]["description"].get!string == "how many copies");
}

unittest  // @describe UDA: prompt argument descriptions appear in prompts/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];

	Json described;
	foreach (i; 0 .. prompts.length)
		if (prompts[i]["name"].get!string == "describedPrompt")
			described = prompts[i];
	assert(described.type == Json.Type.object);

	auto args = described["arguments"];
	assert(args.length == 1);
	assert(args[0]["name"].get!string == "topic");
	assert(args[0]["description"].get!string == "the subject to write about");

	// A prompt argument without @describe carries no description on the wire.
	Json intro;
	foreach (i; 0 .. prompts.length)
		if (prompts[i]["name"].get!string == "intro")
			intro = prompts[i];
	assert("description" !in intro["arguments"][0]);
}

unittest  // ToolAnnotations: typed struct round-trips through JSON
{
	ToolAnnotations a;
	a.title = "Display";
	a.readOnlyHint = true;
	a.openWorldHint = false;
	auto j = a.toJson();
	auto b = ToolAnnotations.fromJson(j);
	assert(b.title.get == "Display");
	assert(b.readOnlyHint.get == true);
	assert(b.openWorldHint.get == false);
	assert(b.destructiveHint.isNull);
}

unittest  // ToolAnnotations: empty struct produces an empty object
{
	ToolAnnotations a;
	assert(a.empty);
	assert(a.toJson().length == 0);
}

version (unittest) private auto MakeListMessage()
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	return Message(makeRequest(Json(99), "tools/list", Json.emptyObject));
}

unittest  // @icon UDA: tool icons appear in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json drawTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "draw")
			drawTool = tools[i];
	assert(drawTool.type == Json.Type.object);
	assert(drawTool["icons"].length == 1);
	assert(drawTool["icons"][0]["src"].get!string == "https://example.com/draw.png");
	assert(drawTool["icons"][0]["mimeType"].get!string == "image/png");
	assert(drawTool["icons"][0]["sizes"][0].get!string == "48x48");
}

unittest  // @meta UDA: tool descriptor `_meta` appears in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json drawTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "draw")
			drawTool = tools[i];
	assert(drawTool["_meta"]["category"].get!string == "art");
}

unittest  // @hintTitle: annotation-level title appears in annotations
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json drawTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "draw")
			drawTool = tools[i];
	// The annotation-level title is distinct from tool.title and lives under annotations.
	assert(drawTool["annotations"]["title"].get!string == "Draw Tool");
	assert(drawTool["annotations"]["readOnlyHint"].get!bool == true);
}

unittest  // MRTR UDA tool: returning ToolResponse.inputRequired surfaces inputRequests
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.draft : MetaKey;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	// Empty seed -> the tool asks for more input (MRTR InputRequiredResult). MRTR
	// exists only on the draft (stateless) protocol, so the request must negotiate
	// the draft version via `_meta`; otherwise the projection layer rejects an
	// input-required result for a non-MRTR peer.
	Json p = Json.emptyObject;
	p["name"] = "ask";
	p["arguments"] = Json(["seed": Json("")]);
	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientCapabilities] = Json(["elicitation": Json.emptyObject]);
	p["_meta"] = meta;
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	// An InputRequiredResult carries `inputRequests` (a map keyed by id), not content.
	assert(r["result"]["inputRequests"].type == Json.Type.object);
	assert(r["result"]["inputRequests"]["req1"]["method"].get!string == "elicitation/create");
}

unittest  // MRTR on a non-draft session: an input-required result is rejected, not emitted off-schema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.errors : ErrorCode;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	// No draft `_meta.protocolVersion` -> the session is non-draft (no MRTR). A
	// handler that nonetheless returns ToolResponse.inputRequired would emit the
	// draft-only `{inputRequests}` shape (no `content`) to a peer whose
	// CallToolResult schema requires content; the projection layer rejects this
	// programming error with an internal error rather than letting it reach the wire.
	Json p = Json.emptyObject;
	p["name"] = "ask";
	p["arguments"] = Json(["seed": Json("")]);
	auto r = s.handle(Message(makeRequest(Json(4), "tools/call", p))).get;
	assert(r["error"]["code"].get!int == ErrorCode.internalError);
}

unittest  // argsAs deserializes a typed struct through the enum-by-name policy
{
	enum Color
	{
		red,
		green
	}

	struct Args
	{
		int n;
		Color c;
	}

	Json j = Json(["n": Json(3), "c": Json("green")]);
	auto a = argsAs!Args(j);
	assert(a.n == 3);
	assert(a.c == Color.green);
}

unittest  // argsAs maps a conversion failure to invalidParams (-32602)
{
	import mcp.protocol.errors : McpException, ErrorCode;

	struct Args
	{
		int n;
	}

	// `n` is a string, not an int -> vibe conversion fails -> invalidParams.
	Json j = Json(["n": Json("not-a-number")]);
	bool threw;
	try
		cast(void) argsAs!Args(j);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
	}
	assert(threw, "argsAs must surface a conversion failure as invalidParams");
}

unittest  // MRTR UDA tool: returning ToolResponse.complete produces a normal result
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	Json p = Json.emptyObject;
	p["name"] = "ask";
	p["arguments"] = Json(["seed": Json("X")]);
	auto r = s.handle(Message(makeRequest(Json(3), "tools/call", p))).get;
	assert("inputRequests" !in r["result"]);
	assert(r["result"]["content"][0]["text"].get!string == "seeded X");
}

unittest  // @icon / @meta UDA on a resource: appear in resources/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	Json cachedRes;
	foreach (i; 0 .. res.length)
		if (res[i]["uri"].get!string == "ext://cached")
			cachedRes = res[i];
	assert(cachedRes.type == Json.Type.object);
	assert(cachedRes["icons"][0]["src"].get!string == "https://example.com/res.svg");
	assert(cachedRes["_meta"]["origin"].get!string == "db");
}

unittest  // @icon UDA on a @prompt: icons appear in prompts/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];

	Json greeting;
	foreach (i; 0 .. prompts.length)
		if (prompts[i]["name"].get!string == "greeting")
			greeting = prompts[i];
	assert(greeting.type == Json.Type.object);
	assert(greeting["icons"].length == 1);
	assert(greeting["icons"][0]["src"].get!string == "https://example.com/prompt.png");
	assert(greeting["icons"][0]["mimeType"].get!string == "image/png");
	assert(greeting["icons"][0]["sizes"][0].get!string == "32x32");
}

unittest  // @meta UDA on a @prompt: descriptor `_meta` appears in prompts/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];

	Json greeting;
	foreach (i; 0 .. prompts.length)
		if (prompts[i]["name"].get!string == "greeting")
			greeting = prompts[i];
	assert(greeting.type == Json.Type.object);
	assert(greeting["_meta"]["audience"].get!string == "all");
}

version (unittest) private auto draftRead(string uri) @safe
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.draft : MetaKey;

	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientInfo] = Json(["name": Json("c"), "version": Json("1")]);
	meta[MetaKey.clientCapabilities] = Json.emptyObject;
	Json params = Json.emptyObject;
	params["uri"] = uri;
	params["_meta"] = meta;
	return Message(makeRequest(Json(1), "resources/read", params));
}

unittest  // @cache UDA on a resource: draft resources/read carries CacheableResult fields
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	// A draft request (carrying the protocol-version _meta) gets cache fields.
	auto rr = s.handle(draftRead("ext://cached")).get;
	assert(rr["result"]["ttlMs"].get!long == 5000);
	assert(rr["result"]["cacheScope"].get!string == "private");
}

unittest  // @cache UDA: pre-draft resources/read has NO cache fields (no wire regression)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	// A plain (non-draft) request must NOT carry any cache fields.
	Json rp = Json.emptyObject;
	rp["uri"] = "ext://cached";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert("ttlMs" !in rr["result"]);
	assert("cacheScope" !in rr["result"]);
}

version (unittest)
{
	private enum Color
	{
		red,
		green,
		blue
	}

	private struct ColorBox
	{
		Color e;
	}

	private struct Palette
	{
		Color[] colors;
	}

	// Fixtures for enum (de)serialization, default values, and resource-template
	// typed parameters.
	private final class EnumApi
	{
		// Returning a struct holding an enum must emit the enum's string name.
		@tool("box", "Return a struct holding a color")
		ColorBox box(Color c) @safe
		{
			return ColorBox(c);
		}

		// Bare enum return is wrapped under `result` as a string.
		@tool("pick", "Return a bare color")
		Color pick() @safe
		{
			return Color.blue;
		}

		// Array of enums nested in a struct.
		@tool("palette", "Return a palette")
		Palette palette() @safe
		{
			return Palette([Color.red, Color.green]);
		}

		// A struct param containing an enum supplied by name.
		@tool("name", "Name the color in a box")
		string name(ColorBox b) @safe
		{
			import std.conv : to;

			return b.e.to!string;
		}

		// A parameter with a D-level default.
		@tool("limited", "Tool with a defaulted parameter")
		int limited(int n, int limit = 7) @safe
		{
			return n + limit;
		}

		@resourceTemplate("widget://{id}", "Widget", "text/plain")
		string widget(int id) @safe
		{
			import std.conv : to;

			return "widget-" ~ id.to!string;
		}

		@resourceTemplate("hue://{shade}", "Hue", "text/plain")
		string hue(Color shade) @safe
		{
			import std.conv : to;

			return "hue-" ~ shade.to!string;
		}
	}
}

unittest  // enum field in a returned struct serializes by member name
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "box";
	p["arguments"] = Json(["c": Json("green")]);
	auto r = s.handle(Message(makeRequest(Json(1), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["e"].get!string == "green");
}

unittest  // bare enum return is wrapped under `result` as its string name
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "pick";
	p["arguments"] = Json.emptyObject;
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["result"].get!string == "blue");
}

unittest  // array of enums inside a struct serializes by name
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "palette";
	p["arguments"] = Json.emptyObject;
	auto r = s.handle(Message(makeRequest(Json(3), "tools/call", p))).get;
	auto colors = r["result"]["structuredContent"]["colors"];
	assert(colors[0].get!string == "red");
	assert(colors[1].get!string == "green");
}

unittest  // enum output passes the tool's own outputSchema validation
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.enableOutputSchemaValidation();
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "box";
	p["arguments"] = Json(["c": Json("red")]);
	auto r = s.handle(Message(makeRequest(Json(4), "tools/call", p))).get;
	// The server must not reject its own structured output as schema-invalid.
	assert("error" !in r);
	assert(r["result"]["structuredContent"]["e"].get!string == "red");
}

unittest  // enum nested in a struct param is supplied as its schema string
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "name";
	Json box = Json.emptyObject;
	box["e"] = "blue";
	p["arguments"] = Json(["b": box]);
	auto r = s.handle(Message(makeRequest(Json(5), "tools/call", p))).get;
	assert(r["result"]["content"][0]["text"].get!string == "blue");
}

unittest  // a defaulted parameter is absent from inputSchema required
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json limited;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "limited")
			limited = tools[i];
	assert(limited.type == Json.Type.object);
	auto req = limited["inputSchema"]["required"];
	bool hasLimit;
	foreach (i; 0 .. req.length)
		if (req[i].get!string == "limit")
			hasLimit = true;
	assert(!hasLimit);
	// `n` (no default) is still required.
	bool hasN;
	foreach (i; 0 .. req.length)
		if (req[i].get!string == "n")
			hasN = true;
	assert(hasN);
}

unittest  // omitting a defaulted arg passes the declared default, not P.init
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "limited";
	p["arguments"] = Json(["n": Json(3)]);
	auto r = s.handle(Message(makeRequest(Json(6), "tools/call", p))).get;
	// limit defaults to 7, so 3 + 7 = 10 (not 3 + 0 = 3 from int.init).
	assert(r["result"]["structuredContent"]["result"].get!int == 10);
}

unittest  // a required tool arg missing (schema validation disabled) is an isError, not a default value
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.disableInputSchemaValidation();
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "limited";
	p["arguments"] = Json.emptyObject; // omit the required 'n'
	auto r = s.handle(Message(makeRequest(Json(7), "tools/call", p))).get;
	assert(r["result"]["isError"].get!bool);
}

unittest  // resource-template int param receives the captured value, not T.init
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json rp = Json.emptyObject;
	rp["uri"] = "widget://42";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "widget-42");
}

unittest  // resource-template enum param is parsed by member name
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json rp = Json.emptyObject;
	rp["uri"] = "hue://green";
	auto rr = s.handle(Message(makeRequest(Json(2), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "hue-green");
}

unittest  // resource-template invalid scalar yields an InvalidParams error
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json rp = Json.emptyObject;
	rp["uri"] = "widget://not-a-number";
	auto rr = s.handle(Message(makeRequest(Json(3), "resources/read", rp))).get;
	assert("error" in rr);
	assert(rr["error"]["code"].get!int == -32602);
}

module mcp.api.reflection;

import std.traits;
import std.typecons : Tuple, Nullable, nullable;
import std.meta : AliasSeq, staticMap;

import vibe.data.json : Json, serializeToJson, deserializeJson, JsonSerializer;
import vibe.data.serialization : serializeWithPolicy, deserializeWithPolicy;

import mcp.protocol.types;
import mcp.protocol.capabilities : Icon;
import mcp.protocol.modern : CacheHint, CacheScope;
import mcp.server.server : McpServer, TaskToolOptions;
import mcp.server.responses : ToolResponse;
import mcp.server.context;
import mcp.server.task_context : TaskContext;
import mcp.server.task_runtime : TaskOptions;
import mcp.server.event_context : EventContext, EventResult, Event, EventBatch, FetchContext;
import mcp.server.events_runtime : EventRegistration, EventCheck;
import mcp.api.attributes;
import mcp.api.apps : UiToolMeta, setUiToolMeta;
import mcp.api.skills : Skill, isValidSkillPath, registerSkill;
import mcp.api.binding : bindJson, bindString, defaultAs, schemaNode, schemaOf,
	SchemaUse, setBound, wireName;
import mcp.protocol.schema;
import mcp.protocol.jsonhelpers : isFieldwiseStruct;

@safe:

/// Register every `@tool` / `@prompt` / `@resource` / `@resourceTemplate`
/// annotated method of `obj` on `server`, deriving JSON schemas and argument
/// marshalling from the method signatures (FastMCP-style ergonomics).
///
/// `obj` is a class instance, an interface, or a pointer to a struct: the
/// registered handlers call its methods for the server's lifetime, so a struct
/// passed by value is rejected — they would act on a copy.
///
/// An override (or interface implementation) without UDAs of its own takes the
/// handler UDAs of the declaration it overrides, and calls dispatch virtually to
/// the override.
void registerHandlers(T)(McpServer server, T obj) @safe
{
	static if (is(T == U*, U) && is(U == struct))
		registerAnnotatedMembers!(U, obj)(server);
	else
	{
		static assert(is(T == class) || is(T == interface),
				"registerHandlers needs a class instance or a pointer to a struct, not "
				~ T.stringof ~ "; a struct passed by value is copied, so its handlers would not "
				~ "see or update the original (allocate it with new and pass the pointer)");
		registerAnnotatedMembers!(T, obj)(server);
	}
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
		static if (__traits(compiles, __traits(getOverloads, root, memberName, true)))
		{
			// Templates are included so a templated handler is rejected rather
			// than silently left unregistered: its parameter types, and so its
			// schema, are unknown until it is instantiated.
			static foreach (overload; __traits(getOverloads, root, memberName, true))
			{
				static if (__traits(isTemplate, overload))
				{
					static foreach (attr; __traits(getAttributes, overload))
						static assert(!isHandlerAttribute!attr, "handler '" ~ memberName
								~ "' is a template; a handler's parameter types must be fixed "
								~ "to derive its schema, so declare it without template parameters");
				}
				else
					registerOverload!(memberName, AnnotatedDecl!(root,
							memberName, overload), parent)(server);
			}
		}
	}
}

/// The declaration whose UDAs describe `overload`, a member `memberName` of
/// `root`: `overload` itself when it carries a handler UDA or `root` is not a
/// class, else the nearest declaration it overrides or implements, in a base
/// class or an interface, that does. An override does not inherit its base
/// declaration's UDAs, so the handler's metadata is read from that declaration
/// while the call still dispatches virtually to the override.
private template AnnotatedDecl(alias root, string memberName, alias overload)
{
	static if (!is(root == class) || hasHandlerUda!overload())
		alias AnnotatedDecl = overload;
	else
	{
		import std.meta : Filter;

		template declsIn(S)
		{
			static if (__traits(hasMember, S, memberName))
				alias declsIn = AliasSeq!(__traits(getOverloads, S, memberName));
			else
				alias declsIn = AliasSeq!();
		}

		enum isAnnotatedMatch(alias d) = is(Parameters!d == Parameters!overload)
			&& hasHandlerUda!d();
		alias matches = Filter!(isAnnotatedMatch, staticMap!(declsIn,
				BaseClassesTuple!root, InterfacesTuple!root));
		static if (matches.length)
			alias AnnotatedDecl = matches[0];
		else
			alias AnnotatedDecl = overload;
	}
}

/// Validate the handler UDAs on `overload` (member `memberName`) and register
/// each one on `server`, dispatching calls through `parent`.
private void registerOverload(string memberName, alias overload, alias parent)(McpServer server) @safe
{
	static if (hasHandlerUda!overload())
	{
		checkHandlerSafety!(memberName, overload)();
		checkMethodFacets!(memberName, overload)();
		checkUdaPlacement!(memberName, overload)();
	}
	static foreach (attr; __traits(getAttributes, overload))
	{
		static if (is(attr))
			static assert(!isHandlerUda!attr,
					"@" ~ attr.stringof ~ " on '" ~ memberName ~ "' is missing its argument list (e.g. "
					~ handlerUdaExample!attr ~ "); a bare @" ~ attr.stringof
					~ " attaches the type, not a value, and registers nothing");
		else static if (is(typeof(attr) == tool))
		{
			static assert(attr.name.length, "@tool on '" ~ memberName ~ "' has an empty name");
			registerToolMethod!(memberName, overload, parent)(server, attr);
		}
		else static if (is(typeof(attr) == taskTool))
		{
			static assert(attr.name.length, "@taskTool on '" ~ memberName ~ "' has an empty name");
			registerTaskMethod!(memberName, overload, parent)(server, attr);
		}
		else static if (is(typeof(attr) == event))
		{
			static assert(attr.name.length, "@event on '" ~ memberName ~ "' has an empty name");
			registerEventMethod!(memberName, overload, parent)(server, attr);
		}
		else static if (is(typeof(attr) == prompt))
		{
			static assert(attr.name.length, "@prompt on '" ~ memberName ~ "' has an empty name");
			registerPromptMethod!(memberName, overload, parent)(server, attr);
		}
		else static if (is(typeof(attr) == resource))
			registerResourceMethod!(memberName, overload, parent)(server, attr);
		else static if (is(typeof(attr) == resourceTemplate))
			registerTemplateMethod!(memberName, overload, parent, attr)(server);
		else static if (is(typeof(attr) == skill))
		{
			static assert(isValidSkillPath(attr.path),
					"@skill on '" ~ memberName ~ "' has the invalid skill path \""
					~ attr.path ~ "\"; its final segment must be lowercase alphanumeric "
					~ "with single hyphens (1..64 chars), after optional "
					~ "non-empty prefix segments");
			registerSkillMethod!(memberName, overload, parent)(server, attr);
		}
		else static if (is(typeof(attr) == skillDir))
		{
			static assert(attr.path.length == 0 || isValidSkillPath(attr.path),
					"@skillDir on '" ~ memberName ~ "' has the invalid skill path \""
					~ attr.path ~ "\"; its final segment must be lowercase alphanumeric "
					~ "with single hyphens (1..64 chars), after optional "
					~ "non-empty prefix segments");
			registerSkillDirMethod!(memberName, overload, parent)(server, attr);
		}
	}
}

/// Whether `f` carries a handler UDA value (`@tool(...)`, `@prompt(...)`, ...).
private bool hasHandlerUda(alias f)()
{
	bool found;
	static foreach (a; __traits(getAttributes, f))
		static if (!is(a) && isHandlerUda!(typeof(a)))
			found = true;
	return found;
}

/// Reject a handler that is not `@safe` (or `@trusted`): the registered
/// callbacks are `@safe`, so calling it would otherwise fail deep inside a
/// generated lambda instead of at the annotated method.
private void checkHandlerSafety(string memberName, alias f)()
{
	static assert(isSafe!f, "handler '" ~ memberName ~ "' must be @safe (or @trusted); "
			~ "annotate it, e.g. `string " ~ memberName ~ "(...) @safe { ... }`");
}

/// Whether the type `A` is one of the handler UDAs that must be applied with an
/// argument list; a bare `@tool` attaches the type itself rather than a value.
private enum isHandlerUda(A) = is(A == tool) || is(A == taskTool)
	|| is(A == event) || is(A == prompt) || is(A == resource)
	|| is(A == resourceTemplate) || is(A == skill) || is(A == skillDir);

/// Whether the attribute `a` is a handler UDA, applied (`@tool(...)`) or bare
/// (`@tool`).
private template isHandlerAttribute(alias a)
{
	static if (is(a))
		enum isHandlerAttribute = isHandlerUda!a;
	else
		enum isHandlerAttribute = isHandlerUda!(typeof(a));
}

/// An applied form of the handler UDA `A` with placeholder arguments, shown when
/// `A` is attached bare.
private template handlerUdaExample(A)
{
	static if (is(A == resource))
		enum handlerUdaExample = `@resource("uri", "name")`;
	else static if (is(A == resourceTemplate))
		enum handlerUdaExample = `@resourceTemplate("uriTemplate", "name")`;
	else static if (is(A == skill))
		enum handlerUdaExample = `@skill("path", "description")`;
	else static if (is(A == skillDir))
		enum handlerUdaExample = `@skillDir("path") or @skillDir()`;
	else
		enum handlerUdaExample = "@" ~ A.stringof ~ `("name", "description")`;
}

/// Convenience variadic form of `registerModule`: register the annotated free
/// functions of several modules in one call.
void registerModules(mods...)(McpServer server) @safe
{
	static foreach (mod; mods)
		registerModule!mod(server);
}

/// The parameter types of `func` with top-level qualifiers removed, so an `in`,
/// `const`, or `immutable` parameter's argument can be bound into a mutable slot
/// before the call.
private alias BoundParameters(alias func) = staticMap!(Unqual, Parameters!func);

/// The UDAs attached to parameter `i` of `func`. The compiler reports the
/// attributes of a parameter that carries any prefixed by those of `func`
/// itself, so that prefix is dropped.
private template ParamAttributes(alias func, size_t i)
{
	alias all = AliasSeq!(__traits(getAttributes, Parameters!func[i .. i + 1]));
	alias own = AliasSeq!(__traits(getAttributes, func));
	static if (own.length && all.length > own.length
			&& AliasSeq!(all[0 .. own.length]).stringof == own.stringof)
		alias ParamAttributes = all[own.length .. $];
	else
		alias ParamAttributes = all;
}

/// The `@schemaDefault` UDAs attached to parameter `i` of `func`.
private template ParamSchemaDefaults(alias func, size_t i)
{
	import jsonschema.attributes : SchemaDefault;
	import std.meta : Filter;

	enum isDefault(alias a) = !is(a) && isInstanceOf!(SchemaDefault, typeof(a));
	alias ParamSchemaDefaults = Filter!(isDefault, ParamAttributes!(func, i));
}

/// Whether `A` is one of the `jsonschema` facet UDA types, which describe a
/// parameter or struct field.
private template isSchemaFacet(A)
{
	import jsonschema.attributes : Maximum, Minimum, SchemaDefault, fieldDescription,
		format, maxItems, maxLength, minItems, minLength, pattern, title;

	enum isSchemaFacet = isInstanceOf!(Minimum, A) || isInstanceOf!(Maximum, A)
		|| isInstanceOf!(SchemaDefault, A) || is(A == fieldDescription)
		|| is(A == format) || is(A == maxItems) || is(A == maxLength)
		|| is(A == minItems) || is(A == minLength) || is(A == pattern) || is(A == title);
}

/// Reject a JSON Schema facet UDA attached to the handler method `f` itself:
/// facets describe a parameter or struct field, and on a method they would
/// match nothing.
private void checkMethodFacets(string memberName, alias f)()
{
	static foreach (attr; __traits(getAttributes, f))
		static if (!is(attr))
			static assert(!isSchemaFacet!(typeof(attr)),
					"@" ~ attr.stringof ~ " on '" ~ memberName
					~ "' is a JSON Schema facet, which applies to a parameter "
					~ "or struct field, not a method; attach it to the parameter (for a "
					~ "display title use @tool's title argument or @hintTitle)");
}

/// Reject a method-level MCP UDA on `f` that none of its handler kinds reads,
/// so a misplaced one (`@cacheable` on a `@tool`, `@readOnly` on a `@prompt`)
/// is an error rather than silently ignored.
private void checkUdaPlacement(string memberName, alias f)()
{
	enum onTool = hasUDA!(f, tool) || hasUDA!(f, taskTool);
	enum onTask = hasUDA!(f, taskTool);
	enum onPrompt = hasUDA!(f, prompt);
	enum onResource = hasUDA!(f, resource) || hasUDA!(f, resourceTemplate);
	enum onEvent = hasUDA!(f, event);

	static foreach (attr; __traits(getAttributes, f))
	{
		static if (__traits(isSame, attr, readOnly) || __traits(isSame, attr,
				destructive) || __traits(isSame, attr, idempotent) || __traits(isSame,
				attr, openWorld) || __traits(isSame, attr, strictArgs))
			static assert(onTool, "@" ~ attr.stringof ~ " on '" ~ memberName
					~ "' applies only to a @tool or @taskTool method");
		else static if (!is(attr))
		{
			static if (is(typeof(attr) == hintTitle)
					|| is(typeof(attr) == mcpHeader) || is(typeof(attr) == ui))
				static assert(onTool, "@" ~ typeof(attr)
						.stringof ~ " on '" ~ memberName
						~ "' applies only to a @tool or @taskTool method");
			else static if (is(typeof(attr) == taskTtl) || is(typeof(attr) == taskPollInterval))
				static assert(onTask, "@" ~ typeof(attr)
						.stringof ~ " on '" ~ memberName ~ "' applies only to a @taskTool method");
			else static if (is(typeof(attr) == describeParam))
				static assert(onTool || onPrompt, "@describeParam on '" ~ memberName
						~ "' applies only to a @tool, @taskTool, or @prompt method");
			else static if (is(typeof(attr) == audience)
					|| is(typeof(attr) == priority)
					|| is(typeof(attr) == lastModified) || is(typeof(attr) == cacheable))
				static assert(onResource, "@" ~ typeof(attr).stringof ~ " on '" ~ memberName
						~ "' applies only to a @resource or @resourceTemplate method");
			else static if (is(typeof(attr) == icon) || is(typeof(attr) == meta))
				static assert(onTool || onPrompt || onResource, "@" ~ typeof(attr)
						.stringof ~ " on '" ~ memberName
						~ "' applies only to a @tool, @taskTool, @prompt, @resource, or "
						~ "@resourceTemplate method");
			else static if (is(typeof(attr) == eventPollInterval))
				static assert(onEvent,
						"@eventPollInterval on '" ~ memberName
						~ "' applies only to an @event method");
		}
	}
}

/// The wire names of `func`'s parameters, in order: each identifier with one
/// trailing underscore dropped (see `wireName`), the names the input schema,
/// prompt arguments, and URI template variables use.
private alias ParamWireNames(alias func) = staticMap!(wireName, ParameterIdentifierTuple!func);

/// Reject a parameter of `func` with no name unless it is an injected context:
/// every other parameter is an argument whose name is its wire name, and D
/// gives an unnamed one an internal `__param_N` identifier. Also reject two
/// arguments sharing a wire name (`limit` and `limit_`).
private void checkParamNames(alias func)()
{
	import std.algorithm.searching : startsWith;
	import std.conv : to;

	alias ids = ParameterIdentifierTuple!func;
	alias names = ParamWireNames!func;
	alias types = BoundParameters!func;
	enum isArgument(size_t i) = !is(types[i] : RequestContext) && !is(types[i] == TaskContext);
	static foreach (i, P; types)
	{
		static if (isArgument!i)
		{
			static assert(ids[i].length && !ids[i].startsWith("__param_"),
					"parameter #" ~ (i + 1)
						.to!string ~ " (" ~ P.stringof ~ ") of '" ~ __traits(identifier,
							func) ~ "' has no name; name it, since its name is the argument's name");
			static foreach (j; 0 .. i)
				static if (isArgument!j)
					static assert(names[j] != names[i],
							"parameters '" ~ ids[j] ~ "' and '" ~ ids[i] ~ "' of '" ~ __traits(identifier,
								func) ~ "' share the argument name '" ~ names[i] ~ "'");
		}
	}
}

/// Reject an argument parameter of `func` whose type cannot be bound from JSON,
/// or whose `@schemaDefault` value does not convert to its type, with a
/// diagnostic naming the handler, the parameter, and the offending type rather
/// than an error from deep inside schema generation or binding.
private void checkParamTypes(alias func)()
{
	import mcp.api.binding : facetMismatch, isDefaultFor, unsupportedTypeReason;

	alias ids = ParameterIdentifierTuple!func;
	static foreach (i, P; BoundParameters!func)
	{
		static if (!is(P : RequestContext) && !is(P == TaskContext))
		{
			static assert(unsupportedTypeReason!(P, SchemaUse.input)() is null,
					"parameter '" ~ ids[i] ~ "' of '" ~ __traits(identifier,
						func) ~ "' has type " ~ P.stringof ~ ", which cannot be bound from JSON ("
					~ unsupportedTypeReason!(P, SchemaUse.input)() ~ ")");
			static assert(facetMismatch!(P, ParamAttributes!(func, i))() is null,
					"parameter '" ~ ids[i] ~ "' of '" ~ __traits(identifier,
						func) ~ "' has type " ~ P.stringof ~ ", but " ~ facetMismatch!(P,
						ParamAttributes!(func, i))());
			static foreach (d; ParamSchemaDefaults!(func, i))
				static assert(isDefaultFor!(P, typeof(d.value)),
						"the @schemaDefault value of type " ~ typeof(d.value)
							.stringof ~ " on parameter '" ~ ids[i] ~ "' of '" ~ __traits(identifier,
								func) ~ "' does not convert to its type " ~ P.stringof);
		}
	}
}

/// Reject a tool method `func` whose return type cannot be written as
/// structured JSON, naming the handler and the offending type.
private void checkToolReturnType(alias func)()
{
	import mcp.api.binding : unsupportedTypeReason;

	alias R = ReturnType!func;
	static if (!isUnstructuredReturn!R)
		static assert(unsupportedTypeReason!(R, SchemaUse.output)() is null,
				"tool '" ~ __traits(identifier,
					func) ~ "' returns " ~ R.stringof ~ ", which cannot be written as JSON ("
				~ unsupportedTypeReason!(R, SchemaUse.output)() ~ ")");
}

/// Reject any method-level `@describeParam` or `@mcpHeader` UDA whose
/// `parameter` does not name a schema parameter of `func`. A parameter that is
/// not declared at all, or one that is an injected context parameter (a trailing
/// `RequestContext` / `TaskContext`, which is excluded from the input schema and
/// has no property to annotate), is always a programmer error: the annotation
/// would silently match nothing. Reject it at compile time with a clear
/// diagnostic instead.
private void validateParamUdas(alias func)()
{
	alias names = ParamWireNames!func;
	alias types = BoundParameters!func;

	// Whether `pname` names a parameter of `func` that appears in the input
	// schema (declared, and not an injected RequestContext / TaskContext).
	static bool namesSchemaParam(string pname)()
	{
		bool found;
		static foreach (i, P; types)
			static if (!is(P : RequestContext) && !is(P == TaskContext))
				if (names[i] == pname)
					found = true;
		return found;
	}

	static foreach (attr; __traits(getAttributes, func))
	{
		static if (is(typeof(attr) == describeParam))
			static assert(namesSchemaParam!(attr.parameter)(), "@describeParam(\""
					~ attr.parameter ~ "\", ...) names no schema parameter of this method "
					~ "(an injected RequestContext/TaskContext has no schema property).");
		else static if (is(typeof(attr) == mcpHeader))
			static assert(namesSchemaParam!(attr.parameter)(), "@mcpHeader(\""
					~ attr.parameter ~ "\", ...) names no schema parameter of this method "
					~ "(an injected RequestContext/TaskContext has no schema property).");
	}
}

/// Resolve the documentation string for the parameter named `pname` of `func`
/// from the method-level `@describeParam` UDA layer, or `""` when none applies.
private string describeFor(alias func, string pname)() @safe
{
	string desc;
	static foreach (attr; __traits(getAttributes, func))
		static if (is(typeof(attr) == describeParam))
			if (attr.parameter == pname && attr.description.length)
				desc = attr.description;
	return desc;
}

/// The header name a method-level `@mcpHeader` UDA on `func` assigns to the
/// parameter named `pname`, or `""` when none does.
private string headerFor(alias func, string pname)() @safe
{
	string header;
	static foreach (attr; __traits(getAttributes, func))
		static if (is(typeof(attr) == mcpHeader))
			if (attr.parameter == pname)
				header = attr.name;
	return header;
}

/// Whether `P` is an admissible `@mcpHeader` parameter type: one whose
/// `jsonSchemaOf` yields a modern primitive header type (integer/string/boolean).
/// `Nullable!T` is unwrapped to its inner type. Mirrors the runtime check
/// `modern.isPrimitiveHeaderType` so detection is symmetric at compile time.
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
	import mcp.protocol.mrtr : validateHeaderName;
	import std.traits : ParameterDefaultValueTuple;

	checkParamNames!func();
	checkParamTypes!func();
	validateParamUdas!func();

	alias names = ParamWireNames!func;
	alias types = BoundParameters!func;
	// ParameterDefaultValueTuple yields `void` for a parameter with no declared
	// D-level default and the default value's type otherwise.
	alias defs = ParameterDefaultValueTuple!func;

	Json props = Json.emptyObject;
	Json required = Json.emptyArray;
	static foreach (i, P; types)
	{
		static if (!is(P : RequestContext) && !is(P == TaskContext))
		{
			{
				// Generate the parameter's schema and fold in the facet UDAs
				// (@minimum, @maximum, @title, @format, @minLength, @maxLength,
				// @pattern, @minItems, @maxItems, @schemaDefault) attached directly
				// to the parameter, in the jsonschema JsonNode IR; render to vibe
				// Json once the facets are applied, then layer the MCP-specific
				// extensions (x-mcp-header, description) on below.
				//
				// A `Nullable!T` parameter is optional (absent from `required`)
				// and its schema also admits an explicit `null`, which binds as
				// unset. An x-mcp-header parameter keeps the bare primitive `type`
				// the header extension requires.
				import jsonschema : applyUdaFacets;
				import jsonschema.vibejson : nodeToVibeJson;

				static if (isInstanceOf!(Nullable, P) && headerFor!(func, names[i]).length)
					auto psNode = schemaNode!(TemplateArgsOf!P[0], SchemaUse.input)();
				else
					auto psNode = schemaNode!(P, SchemaUse.input)();
				applyUdaFacets!(ParamAttributes!(func, i))(psNode);
				Json ps = nodeToVibeJson(psNode);
				// Modern x-mcp-header: a method-level @mcpHeader(parameter, name)
				// naming this parameter mirrors it into an `Mcp-Param-<name>`
				// request header; emit the extension property so the transport can
				// validate it (see modern.paramHeaders). The header name and the
				// named parameter's type are checked against 2026-07-28
				// `x-mcp-header` constraints at compile time: the value MUST be a
				// valid HTTP token (non-empty, 1*tchar, no CR/LF) and the parameter
				// MUST be a primitive type (string/integral/bool); `number`
				// (floating point) is NOT permitted.
				static foreach (attr; __traits(getAttributes, func))
					static if (is(typeof(attr) == mcpHeader))
						if (attr.parameter == names[i])
							{
							static assert(validateHeaderName(attr.name) is null,
									"@mcpHeader(\"" ~ attr.parameter ~ "\", \"" ~ attr.name
									~ "\") is not a valid x-mcp-header value: " ~ validateHeaderName(
										attr.name));
							// The modern permits only primitive x-mcp-header value
							// types (integer/string/boolean). Whitelist exactly those
							// (plus the `Nullable` thereof) so a struct/array/AA/
							// `number` parameter is rejected at the registration site
							// rather than per-request via the transport's
							// `headerMismatch` (see modern.isPrimitiveHeaderType).
							static assert(isPrimitiveHeaderParam!P, "@mcpHeader cannot be applied to parameter '" ~ names[i] ~ "' of type " ~ P
									.stringof ~ "; x-mcp-header permits only integer/string/boolean (or Nullable thereof)");
							ps["x-mcp-header"] = attr.name;
						}
				// Fold the parameter's @fieldDescription, then the method's
				// @describeParam for it (which takes precedence), into the
				// property's JSON Schema `description` (a standard annotation
				// keyword, valid in every protocol version).
				static foreach (attr; ParamAttributes!(func, i))
				{
					static if (is(typeof(attr) == fieldDescription))
						ps["description"] = attr.value;
				}
				{
					enum d = describeFor!(func, names[i]);
					static if (d.length)
						ps["description"] = d;
				}
				// A declared D-level default is advertised as the JSON Schema
				// `default` unless an explicit @schemaDefault already set one.
				static if (!is(defs[i] == void))
					if ("default" !in ps)
						{
						auto d = () @trusted {
							return serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(
									cast(P) defs[i]);
						}();
						if (d.type != Json.Type.null_ && d.type != Json.Type.undefined)
							ps["default"] = d;
					}
				props[names[i]] = ps;
			}
			// A parameter is required only when it is not Nullable and has neither
			// a declared D-level default value nor a @schemaDefault.
			// ParameterDefaultValueTuple gives `void` for params without a default.
			static if (!isInstanceOf!(Nullable, P) && is(defs[i] == void)
					&& !ParamSchemaDefaults!(func, i).length)
				required ~= Json(names[i]);
		}
	}
	Json s = Json.emptyObject;
	s["type"] = "object";
	s["properties"] = props;
	if (required.length > 0)
		s["required"] = required;
	static if (hasUDA!(func, strictArgs))
		s["additionalProperties"] = false;
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

/// Whether argument `name` of a `P` parameter is an explicit JSON `null` that
/// binds as unset: `P` is `Nullable`, so `null` is a value of its own rather
/// than an omission that takes the parameter's default.
private bool isExplicitNull(P)(Json args, string name) @safe
{
	static if (isInstanceOf!(Nullable, P))
		return (name in args) !is null && args[name].type == Json.Type.null_;
	else
		return false;
}

/// Convert one JSON argument value into the parameter type `P`, falling back to
/// the parameter's declared D-level default `def` when the argument is absent
/// (an explicit `null` for a `Nullable` binds as unset).
/// `def` is the value from `ParameterDefaultValueTuple` for this slot.
private P marshalArgDefault(P, alias def, bool stringArgs = false)(Json args, string name) @safe
{
	static if (is(P : RequestContext))
	{
		assert(false, "context parameters are injected, not marshalled");
	}
	else
	{
		if (isExplicitNull!P(args, name))
			return P.init;
		if (!argPresent(args, name))
			return def;
		return marshalArg!(P, stringArgs)(args, name);
	}
}

/// Convert one JSON argument value into the parameter type `P`; an absent
/// argument yields `P.init`. With `stringArgs` (prompt arguments, which the
/// protocol types as strings) a JSON string is parsed into `P` from its text.
private P marshalArg(P, bool stringArgs = false)(Json args, string name) @safe
{
	static if (is(P : RequestContext))
	{
		assert(false, "context parameters are injected, not marshalled");
	}
	else
	{
		if (!argPresent(args, name))
			return P.init;
		static if (stringArgs)
			if (args[name].type == Json.Type.string)
				return bindString!P(args[name].get!string);
		return bindJson!P(args[name]);
	}
}

/// Deserialize a dynamic handler's raw wire `arguments` into a typed value `T`.
///
/// The UDA-driven registration overloads marshal each argument from the method
/// signature for you, but the dynamic `registerTool`/`registerPrompt`
/// overloads hand the handler the raw `Json arguments`. `argsAs` deserializes
/// `arguments` through the same enum-by-name policy the UDA layer uses (so any `enum` leaf is read
/// from its schema-declared member name, at any nesting depth) and maps a
/// conversion failure to a `ToolError`, so a dynamic tool reports a malformed
/// argument as an `isError` result, exactly as a `@tool` method's does. A
/// handler can then write `auto a = argsAs!MyArgs(arguments);` instead of
/// hand-rolling `arguments["x"].get!int` with manual presence/type checks.
///
/// In a dynamic prompt handler, where a malformed argument is a JSON-RPC
/// `invalidParams` (-32602) error, catch the `ToolError` and rethrow it as
/// `invalidParams(e.msg)`.
T argsAs(T)(Json arguments) @safe
{
	import mcp.protocol.errors : McpException;
	import mcp.server.responses : ToolError;

	try
		return bindJson!T(arguments);
	catch (McpException e)
		throw e;
	catch (Exception e)
		throw new ToolError("arguments: " ~ e.msg);
}

/// The JSON Schema describing a tool's structured output, derived from its
/// return type — or `Json.undefined` when the tool produces unstructured
/// content (a `string`, `Content`, or `Content[]`) or supplies its own
/// `CallToolResult`. Fieldwise-serialized
/// structs map to their object schema directly; every other return (scalars,
/// arrays, enums, `Nullable`, `Json`, `SumType`, and custom-serialized structs
/// such as `SysTime`) is wrapped under a `result` property so
/// `structuredContent` is always an object.
private Json outputSchemaOf(R)() @safe
{
	static if (isUnstructuredReturn!R)
		return Json.undefined;
	else static if (isFieldwiseStruct!R)
		return schemaOf!(R, SchemaUse.output);
	else
	{
		Json s = Json.emptyObject;
		s["type"] = "object";
		Json props = Json.emptyObject;
		props["result"] = schemaOf!(R, SchemaUse.output);
		s["properties"] = props;
		s["required"] = Json([Json("result")]);
		return s;
	}
}

/// Whether a tool returning `R` produces no structured output: it returns
/// text, `Content`, or nothing, or builds its own result.
private enum isUnstructuredReturn(R) = is(R == CallToolResult) || is(R == ToolResponse)
	|| isSomeString!R || is(R == void) || is(R == Content) || is(R == Content[]);

/// Wrap a tool method's return value into a `CallToolResult`. The structured
/// result mirrors `outputSchemaOf!R`: fieldwise structs serialize to an object;
/// every other value is wrapped under a `result` key; strings become text
/// content and `Content` / `Content[]` become the content itself, with no
/// structured output.
private CallToolResult toToolResult(R)(R ret) @safe if (!is(R == void))
{
	static if (is(R == CallToolResult))
		return ret;
	else static if (is(R == Content) || is(R == Content[]))
	{
		CallToolResult r;
		static if (is(R == Content))
			r.content = [ret];
		else
			r.content = ret;
		return r;
	}
	else static if (isSomeString!R)
	{
		import std.conv : to;

		CallToolResult r;
		r.content = [Content.makeText(ret.to!string)];
		return r;
	}
	else
		return CallToolResult.structured(ret);
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
				if (a.theme.length)
					ic.theme = nullable(a.theme);
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
		{
			static assert(a.value >= 0.0 && a.value <= 1.0,
					"@priority value must be in [0.0, 1.0], got " ~ a.value.stringof);
			descriptor.annotations.priority = a.value;
		}
		else static if (is(typeof(a) == lastModified))
			descriptor.annotations.lastModified = a.value;
	}
	applyIconsAndMeta!overload(descriptor);
}

/// Collect a `@cacheable` UDA into a `Nullable!CacheHint` for resource/template
/// registration; null when absent.
private Nullable!CacheHint collectCache(alias overload)() @safe
{
	Nullable!CacheHint hint;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == cacheable))
		{
			{
				CacheHint h;
				h.ttl = a.ttl;
				h.cacheScope = a.scope_;
				hint = h;
			}
		}
	}
	return hint;
}

/// Bind every non-injected parameter of the tool or task method `overload`
/// from the call's `args` into `argv`, leaving injected context slots untouched.
/// Returns `null` on success, or an attributed message for a required argument
/// that is missing or, for a `@strictArgs` method, an argument it does not
/// declare (both checked even when input-schema validation is disabled), or a
/// value that cannot be converted; the caller reports it as an `isError` result,
/// the classification this SDK uses for tool input failures. An `McpException`
/// raised while binding propagates unchanged.
private string bindToolArgs(alias overload)(Json args, ref Tuple!(BoundParameters!overload) argv) @safe
{
	import mcp.protocol.errors : McpException;

	alias names = ParamWireNames!overload;
	alias defs = ParameterDefaultValueTuple!overload;
	static if (hasUDA!(overload, strictArgs))
	{
		if (args.type == Json.Type.object)
			foreach (kv; args.byKeyValue)
			{
				bool declared;
				static foreach (i, P; BoundParameters!overload)
					static if (!is(P : RequestContext) && !is(P == TaskContext))
						declared |= kv.key == names[i];
				if (!declared)
					return "argument '" ~ kv.key ~ "': unknown argument";
			}
	}
	static foreach (i, P; BoundParameters!overload)
	{
		static if (!is(P : RequestContext) && !is(P == TaskContext))
		{
			static if (is(defs[i] == void) && !isInstanceOf!(Nullable, P)
					&& !ParamSchemaDefaults!(overload, i).length)
				if (!argPresent(args, names[i]))
					return "argument '" ~ names[i] ~ "': required argument is missing";
			try
			{
				// An omitted argument takes its advertised default: a @schemaDefault
				// when present, else the D default.
				static if (ParamSchemaDefaults!(overload, i).length)
				{
					if (argPresent(args, names[i]))
						setBound(argv[i], marshalArg!P(args, names[i]));
					else if (!isExplicitNull!P(args, names[i]))
						setBound(argv[i], defaultAs!(P, ParamSchemaDefaults!(overload, i)[0])());
				}
				else static if (is(defs[i] == void))
					setBound(argv[i], marshalArg!P(args, names[i]));
				else
					setBound(argv[i], marshalArgDefault!(P, defs[i])(args, names[i]));
			}
			catch (McpException e)
				throw e;
			catch (Exception e)
				return "argument '" ~ names[i] ~ "': " ~ e.msg;
		}
	}
	return null;
}

/// The `Tool` descriptor for the method `overload` annotated with `attr`, its
/// `@tool` or `@taskTool`: the name, description, and title from `attr`, the
/// input schema from the parameters, output schema from the return type, the
/// hint UDAs (`@readOnly` / `@destructive` / `@idempotent` / `@openWorld`) and
/// `@hintTitle` as annotations, `@icon` / `@meta`, and `@ui` merged into
/// `_meta.ui`. A hint marker's presence sets its hint to true; absence leaves it
/// unset (omitted from the wire form).
private Tool toolDescriptor(alias overload, A)(A attr) @safe
		if (is(A == tool) || is(A == taskTool))
{
	import std.traits : ReturnType;

	Tool descriptor;
	descriptor.name = attr.name;
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	if (attr.title.length)
		descriptor.title = nullable(attr.title);
	checkToolReturnType!overload();
	descriptor.inputSchema = parametersSchema!overload();
	auto outSchema = outputSchemaOf!(ReturnType!overload)();
	if (outSchema.type == Json.Type.object)
		descriptor.outputSchema = outSchema;

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
	}
	if (!anns.empty)
		descriptor.annotations = anns.toJson();

	applyIconsAndMeta!overload(descriptor);
	// @ui merges into the _meta that @meta set.
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == ui))
		{
			static assert(a.resourceUri.length > 5 && a.resourceUri[0 .. 5] == "ui://",
					"@ui resourceUri must be a ui:// URI, got: \"" ~ a.resourceUri ~ "\"");
			static foreach (v; a.visibility)
				static assert(v == "model" || v == "app",
						"@ui visibility must be \"model\" or \"app\", got: \"" ~ v ~ "\"");
			setUiToolMeta(descriptor, UiToolMeta(a.resourceUri, a.visibility));
		}
	}
	return descriptor;
}

private void registerToolMethod(string memberName, alias overload, alias parent)(
		McpServer server, tool attr) @safe
{
	import std.traits : ReturnType;

	static foreach (P; BoundParameters!overload)
	{
		static assert(!is(P == TaskContext), "@tool method '" ~ memberName
				~ "' must not take a TaskContext; declare it with @taskTool to run as a task.");
		static assert(!is(P == EventContext), "@tool method '" ~ memberName
				~ "' must not take an EventContext; only event handlers receive one.");
	}

	auto descriptor = toolDescriptor!overload(attr);

	server.registerTool(descriptor, (Json args, RequestContext ctx) @safe {
		Tuple!(BoundParameters!overload) argv;
		static foreach (i, P; BoundParameters!overload)
			static if (is(P : RequestContext))
				argv[i] = ctx;
		if (auto failure = bindToolArgs!overload(args, argv))
		{
			static if (is(ReturnType!overload == ToolResponse))
				return ToolResponse.complete(CallToolResult.error(failure));
			else
				return CallToolResult.error(failure);
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

private void registerTaskMethod(string memberName, alias overload, alias parent)(
		McpServer server, taskTool attr) @safe
{
	import std.traits : ReturnType;

	// A task executor runs asynchronously, after the originating request has
	// already returned a task handle — there is no live RequestContext to inject.
	// Task methods observe progress/cancellation/input through a TaskContext.
	static foreach (P; BoundParameters!overload)
	{
		static assert(!is(P : RequestContext),
				"@taskTool method '" ~ memberName ~ "' must not take a RequestContext "
				~ "(the request has already returned); take a TaskContext instead.");
		static assert(!is(P == EventContext), "@taskTool method '" ~ memberName
				~ "' must not take an EventContext; only event handlers receive one.");
	}
	static assert(!is(ReturnType!overload == ToolResponse),
			"@taskTool method '" ~ memberName ~ "' must return a value (or void), not ToolResponse");

	auto descriptor = toolDescriptor!overload(attr);

	// Per-task timing from @taskTtl / @taskPollInterval; an absent UDA inherits the
	// corresponding server default.
	import core.time : Duration;

	TaskToolOptions opts;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == taskTtl))
			opts.create.ttl = a.value;
		else static if (is(typeof(a) == taskPollInterval))
			opts.create.pollInterval = a.value;
	}

	// The executor runs on each dispatch: it reconstitutes the typed arguments
	// from the task's durable input, injects the TaskContext, invokes the method,
	// and wraps the return value into a CallToolResult-shaped result JSON. A
	// missing or malformed argument completes the task with an `isError` result,
	// as the same input would for a plain tool call; a thrown exception
	// propagates to runTaskExecutor, which fails the task; a
	// `tc.requireInput(...)` suspends it.
	server.registerTaskTool(descriptor, (TaskContext tc) @safe {
		Tuple!(BoundParameters!overload) argv;
		static foreach (i, P; BoundParameters!overload)
			static if (is(P == TaskContext))
				argv[i] = tc;
		if (auto failure = bindToolArgs!overload(tc.inputJson(), argv))
			return CallToolResult.error(failure).toJson();
		static if (is(ReturnType!overload == void))
		{
			__traits(getMember, parent, memberName)(argv.expand);
			CallToolResult empty;
			return empty.toJson();
		}
		else
			return toToolResult(__traits(getMember, parent, memberName)(argv.expand)).toJson();
	}, opts);
}

/// Register a typed `@event` pull/fetch type. The method must have the shape
/// `EventBatch!P fetch(A args, FetchContext ctx)`: `A` derives the subscription
/// `inputSchema`, `P` the `payloadSchema`, and the method becomes the type's fetch
/// handler (backing poll directly, stream/webhook via the runtime's loop) through
/// `EventsRuntime.define!(A,P).onFetch`. `@eventPollInterval` sets the cadence.
/// Push-only event types use the builder (`server.events.define!(A,P)(...)` +
/// `publish`) directly rather than `@event`. Requires `enableEvents()` first.
private void registerEventMethod(string memberName, alias overload, alias parent)(
		McpServer server, event attr) @safe
{
	import std.traits : Parameters, ReturnType;
	import mcp.protocol.errors : internalError;

	static assert(Parameters!overload.length == 2,
			"@event method '" ~ memberName ~ "' must take (Args, FetchContext)");
	static assert(is(Parameters!overload[1] == FetchContext),
			"@event method '" ~ memberName ~ "' must take FetchContext as its second parameter");

	static if (is(ReturnType!overload == EventBatch!EP, EP))
	{
		alias A = Parameters!overload[0];

		if (server.events is null)
			throw internalError("@event requires enableEvents() before registerHandlers");

		auto ev = server.events.define!(A, EP)(attr.name, attr.description, attr.title);
		ev.onFetch((A args, scope FetchContext ctx) @safe => __traits(getMember,
				parent, memberName)(args, ctx));
		static foreach (a; __traits(getAttributes, overload))
			static if (is(typeof(a) == eventPollInterval))
				ev.pollInterval(a.value);
	}
	else
		static assert(false, "@event method '" ~ memberName
				~ "' must return EventBatch!P (its payload type P derives the payloadSchema)");
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
		import std.conv : to;

		GetPromptResult r;
		r.messages = [PromptMessage("user", Content.makeText(ret.to!string))];
		return r;
	}
	else
		static assert(false,
				"@prompt method must return GetPromptResult, PromptMessage[], or string");
}

/// Whether an empty string given for a prompt argument of type `P` stands for an
/// omitted argument: prompt arguments travel as strings, so a client sends `""`
/// for a field left blank, and that is a value only for a string (or `Json`)
/// parameter, or a `Nullable` of one.
private template emptyMeansAbsent(P)
{
	static if (isInstanceOf!(Nullable, P))
		enum emptyMeansAbsent = emptyMeansAbsent!(TemplateArgsOf!P[0]);
	else
		enum emptyMeansAbsent = !isSomeString!P && !is(P == Json);
}

/// The prompt `arguments` of `func` with every empty-string value of a
/// parameter whose type `emptyMeansAbsent` dropped, so it binds as omitted.
private Json omitEmptyPromptArgs(alias func)(Json args) @safe
{
	if (args.type != Json.Type.object)
		return args;
	alias names = ParamWireNames!func;
	Json kept = Json.emptyObject;
	foreach (kv; args.byKeyValue)
	{
		bool blank;
		static foreach (i, P; BoundParameters!func)
			static if (!is(P : RequestContext) && emptyMeansAbsent!P)
				blank |= kv.key == names[i] && kv.value.type == Json.Type.string
					&& kv.value.get!string.length == 0;
		if (!blank)
			kept[kv.key] = kv.value;
	}
	return kept;
}

private void registerPromptMethod(string memberName, alias overload, alias parent)(
		McpServer server, prompt attr) @safe
{
	static foreach (P; BoundParameters!overload)
		static assert(!is(P == TaskContext) && !is(P == EventContext)
				&& !is(P == FetchContext),
				"@prompt method '" ~ memberName ~ "' must not take a " ~ P.stringof
				~ "; a prompt may take only a RequestContext besides its arguments");
	checkParamNames!overload();
	checkParamTypes!overload();
	validateParamUdas!overload();

	Prompt descriptor;
	descriptor.name = attr.name;
	if (attr.title.length)
		descriptor.title = nullable(attr.title);
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	alias names = ParamWireNames!overload;
	alias defs = ParameterDefaultValueTuple!overload;
	static foreach (i, P; BoundParameters!overload)
	{
		static if (!is(P : RequestContext))
		{
			{
				// Populate PromptArgument.description from the @describeParam UDA.
				enum d = describeFor!(overload, names[i]);
				// A prompt argument is required only when it is neither Nullable nor
				// carries a declared default (D-level or @schemaDefault), matching
				// the tool path.
				descriptor.arguments ~= PromptArgument(names[i], d.length
						? nullable(d) : Nullable!string.init, !isInstanceOf!(Nullable, P)
						&& is(defs[i] == void) && !ParamSchemaDefaults!(overload, i).length);
			}
		}
	}

	applyIconsAndMeta!overload(descriptor);

	server.registerPrompt(descriptor, (Json rawArgs, RequestContext ctx) @safe {
		import mcp.protocol.errors : McpException, invalidParams;
		import mcp.server.responses : PromptResponse;

		Json args = omitEmptyPromptArgs!overload(rawArgs);
		Tuple!(BoundParameters!overload) argv;
		static foreach (i, P; BoundParameters!overload)
		{
			// A declared RequestContext parameter binds to the real per-request
			// context so context-dependent features (logging, cancellation,
			// elicitation) work from prompts, exactly as the tool path does.
			static if (is(P : RequestContext))
				argv[i] = ctx;
			else static if (ParamSchemaDefaults!(overload, i).length)
			{
				// An omitted argument takes its advertised @schemaDefault.
				if (argPresent(args, names[i]))
				{
					try
						setBound(argv[i], marshalArg!(P, true)(args, names[i]));
					catch (McpException e)
						throw e;
					catch (Exception e)
						throw invalidParams("argument '" ~ names[i] ~ "': " ~ e.msg);
				}
				else if (!isExplicitNull!P(args, names[i]))
					setBound(argv[i], defaultAs!(P, ParamSchemaDefaults!(overload, i)[0])());
			}
			else static if (is(defs[i] == void))
			{
				// A malformed argument (e.g. an out-of-range enum member or a
				// non-numeric integer) must surface as InvalidParams (-32602)
				// rather than escaping as an internal error (-32603), mirroring
				// the resource-template path. Protocol errors thrown by the
				// marshaller are passed through unchanged so an inner
				// invalidParams is not double-wrapped.
				static if (!isInstanceOf!(Nullable, P))
					if (!argPresent(args, names[i]))
						throw invalidParams(
							"Missing required argument '" ~ names[i] ~ "' for prompt: " ~ attr.name);
				try
					setBound(argv[i], marshalArg!(P, true)(args, names[i]));
				catch (McpException e)
					throw e;
				catch (Exception e)
					throw invalidParams("argument '" ~ names[i] ~ "': " ~ e.msg);
			}
			else
			{
				try
					setBound(argv[i], marshalArgDefault!(P, defs[i], true)(args, names[i]));
				catch (McpException e)
					throw e;
				catch (Exception e)
					throw invalidParams("argument '" ~ names[i] ~ "': " ~ e.msg);
			}
		}
		return PromptResponse.complete(toPromptResult(__traits(getMember,
			parent, memberName)(argv.expand)));
	});
}

private ResourceContents toResourceContents(R)(R ret, string uri, string mimeType) @safe
{
	static if (is(R == ResourceContents))
		return ret;
	else static if (isSomeString!R)
	{
		import std.conv : to;

		return ResourceContents.makeText(uri, mimeType, ret.to!string);
	}
	else
		static assert(false, "@resource method must return ResourceContents or string");
}

private void registerResourceMethod(string memberName, alias overload, alias parent)(
		McpServer server, resource attr) @safe
{
	enum takesContext = Parameters!overload.length == 1
		&& is(Parameters!overload[0] : RequestContext);
	static assert(Parameters!overload.length == 0 || takesContext,
			"@resource method '" ~ memberName ~ "' may take only a RequestContext parameter; "
			~ "use @resourceTemplate to read values from a URI with variables.");

	Resource descriptor;
	descriptor.uri = attr.uri;
	descriptor.name = attr.name;
	if (attr.mimeType.length)
		descriptor.mimeType = nullable(attr.mimeType);
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	if (attr.title.length)
		descriptor.title = nullable(attr.title);

	applyResourceMetadata!overload(descriptor);

	server.registerResource(descriptor, (RequestContext ctx) @safe {
		static if (takesContext)
			auto ret = __traits(getMember, parent, memberName)(ctx);
		else
			auto ret = __traits(getMember, parent, memberName)();
		return toResourceContents(ret, attr.uri, attr.mimeType);
	}, collectCache!overload());
}

/// The variable names of an RFC 6570 URI template, in order, with expression
/// operators (`+#./;?&`) and value modifiers (`*`, `:N`) removed.
private string[] uriTemplateVars(string tmpl) @safe pure
{
	import std.algorithm.iteration : splitter;
	import std.string : indexOf;

	string[] vars;
	while (true)
	{
		immutable open = tmpl.indexOf('{');
		if (open < 0)
			break;
		immutable close = tmpl[open .. $].indexOf('}');
		if (close < 0)
			break;
		auto expr = tmpl[open + 1 .. open + close];
		tmpl = tmpl[open + close + 1 .. $];
		if (expr.length && "+#./;?&".indexOf(expr[0]) >= 0)
			expr = expr[1 .. $];
		foreach (spec; expr.splitter(','))
		{
			immutable colon = spec.indexOf(':');
			if (colon >= 0)
				spec = spec[0 .. colon];
			if (spec.length && spec[$ - 1] == '*')
				spec = spec[0 .. $ - 1];
			if (spec.length)
				vars ~= spec;
		}
	}
	return vars;
}

private void registerTemplateMethod(string memberName, alias overload,
		alias parent, resourceTemplate attr)(McpServer server) @safe
{
	import std.algorithm.searching : canFind;

	ResourceTemplate descriptor;
	descriptor.uriTemplate = attr.uriTemplate;
	descriptor.name = attr.name;
	if (attr.mimeType.length)
		descriptor.mimeType = nullable(attr.mimeType);
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	if (attr.title.length)
		descriptor.title = nullable(attr.title);

	static foreach (P; BoundParameters!overload)
		static assert(!is(P == TaskContext) && !is(P == EventContext) && !is(P == FetchContext),
				"@resourceTemplate method '" ~ memberName ~ "' must not take a " ~ P.stringof
				~ "; a resource template may take only a RequestContext besides its variables");
	checkParamNames!overload();
	checkParamTypes!overload();
	// Every bound parameter must name a template variable; any other name would
	// silently receive an empty or default value on every read.
	static foreach (i, P; BoundParameters!overload)
	{
		static if (!is(P : RequestContext))
		{
			static assert(canFind(uriTemplateVars(attr.uriTemplate), ParamWireNames!overload[i]),
					"@resourceTemplate method '" ~ memberName ~ "' parameter '"
					~ ParamWireNames!overload[i]
					~ "' does not appear in URI template \"" ~ attr.uriTemplate ~ "\"");
		}
	}

	applyResourceMetadata!overload(descriptor);

	server.registerResourceTemplate(descriptor, (string uri,
			string[string] params, RequestContext ctx) @safe {
		import mcp.protocol.errors : invalidParams;

		alias names = ParamWireNames!overload;
		alias defs = ParameterDefaultValueTuple!overload;
		Tuple!(BoundParameters!overload) argv;
		static foreach (i, P; BoundParameters!overload)
		{
			// A declared RequestContext parameter binds to the real per-request
			// context so context-dependent features work from resource templates,
			// exactly as the tool path does.
			static if (is(P : RequestContext))
				argv[i] = ctx;
			else
			{
				// A captured URI variable is always a string; parse it into the
				// declared parameter type and surface a conversion failure as
				// InvalidParams. A variable the URI does not supply binds the
				// parameter's declared default, or `P.init` when it has none.
				if (auto pv = names[i] in params)
				{
					try
						setBound(argv[i], bindString!P(*pv));
					catch (Exception e)
						throw invalidParams("resource template parameter '" ~ names[i]
							~ "' could not be parsed as " ~ P.stringof ~ ": " ~ e.msg);
				}
				else static if (!is(defs[i] == void))
					setBound!P(argv[i], defs[i]);
			}
		}
		auto ret = __traits(getMember, parent, memberName)(argv.expand);
		return toResourceContents(ret, uri, attr.mimeType);
	}, collectCache!overload());
}

private void registerSkillMethod(string memberName, alias overload, alias parent)(
		McpServer server, skill attr) @safe
{
	import std.traits : ReturnType;

	// A skill method declares the SKILL.md instructions: it takes no arguments
	// and returns the body as a string. The frontmatter is synthesized from the
	// @skill name/description, so the method body need only be the instructions.
	static assert(Parameters!overload.length == 0, "@skill method '" ~ memberName
			~ "' must take no parameters; it returns the " ~ "SKILL.md instructions as a string");
	static assert(is(ReturnType!overload : string),
			"@skill method '" ~ memberName ~ "' must return the SKILL.md instructions as a string");

	Skill sk;
	sk.path = attr.path;
	sk.description = attr.description;
	sk.instructions = __traits(getMember, parent, memberName)();
	registerSkill(server, sk);
}

private void registerSkillDirMethod(string memberName, alias overload, alias parent)(
		McpServer server, skillDir attr) @safe
{
	import std.traits : ReturnType;
	import mcp.api.skill_dir : registerSkillDir, SkillDirOptions;

	// A @skillDir method names a local directory: it takes no arguments and
	// returns the directory path as a string. The directory's SKILL.md and files
	// are served by registerSkillDir.
	static assert(Parameters!overload.length == 0, "@skillDir method '" ~ memberName
			~ "' must take no parameters; it returns the local skill directory path");
	static assert(is(ReturnType!overload : string),
			"@skillDir method '" ~ memberName
			~ "' must return the local skill directory path as a string");

	SkillDirOptions options;
	options.path = attr.path;
	registerSkillDir(server, __traits(getMember, parent, memberName)(), options);
}

version (unittest)
{
	import core.time : seconds;

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
		@mcpHeader("region", "Region")
		string query(string region, int limit) @safe
		{
			return region;
		}

		@tool("annotate", "Tool with described parameters")
		@describeParam("id", "the document id")
		@describeParam("count", "how many copies")
		string annotate(string id, int count) @safe
		{
			return id;
		}

		@prompt("describedPrompt", "Prompt with a described argument")
		@describeParam("topic", "the subject to write about")
		string describedPrompt(string topic) @safe
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
	import mcp.server.responses : ToolResponse;
	import mcp.protocol.mrtr : InputRequest;

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
		@cacheable(5.seconds, CacheScope.private_)
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
	assert(list["result"]["tools"].length == 7);

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
	assert(statsSchema["properties"]["total"]["type"] == Json([
		Json("number"), Json("null")
	]));

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

unittest  // @skill reflection: registerHandlers serves SKILL.md and lists the skill
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.api.skills : skillUri, skillMimeType;

	@safe final class SkillApi
	{
		@skill("git-workflow", "Follow Git conventions")
		string gitWorkflow() @safe
		{
			return "# Git Workflow\n\n1. Branch from main.\n";
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new SkillApi);

	// The @skill method is served as a skill:// markdown resource with synthesized
	// frontmatter wrapping the returned instructions body.
	Json rp = Json.emptyObject;
	rp["uri"] = skillUri("git-workflow");
	auto contents = s.handle(Message(makeRequest(Json(1), "resources/read",
			rp))).get["result"]["contents"][0];
	assert(contents["mimeType"].get!string == skillMimeType);
	const md = contents["text"].get!string;
	import std.algorithm : canFind;

	assert(md.canFind("name: git-workflow"));
	assert(md.canFind("# Git Workflow"));

	// The skill is listed by skills/list.
	auto result = s.handle(Message(makeRequest(Json(2), "skills/list",
			Json.emptyObject))).get["result"];
	assert(result["skills"].length == 1);
	assert(result["skills"][0]["frontmatter"]["name"].get!string == "git-workflow");
	assert(result["skills"][0]["uri"].get!string == skillUri("git-workflow"));
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

unittest  // @prompt integer arg given its wire-form string is parsed into the D type
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json pp = Json.emptyObject;
	pp["name"] = "repeat";
	pp["arguments"] = Json(["count": Json("5")]);
	auto resp = s.handle(Message(makeRequest(Json(3), "prompts/get", pp))).get;
	assert("error" !in resp, resp.toString);
	assert(resp["result"]["messages"][0]["content"]["text"].get!string == "count pos");
}

unittest  // @prompt bool, floating-point, and Nullable args are parsed from their string forms
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	@safe final class TypedPromptApi
	{
		@prompt("typed", "Prompt with several typed arguments")
		string typed(bool loud, double ratio, Nullable!long limit) @safe
		{
			import std.conv : to;

			return loud.to!string ~ " " ~ ratio.to!string ~ " " ~ limit.get.to!string;
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new TypedPromptApi);
	Json pp = Json.emptyObject;
	pp["name"] = "typed";
	pp["arguments"] = Json([
		"loud": Json("true"),
		"ratio": Json("0.5"),
		"limit": Json("7")
	]);
	auto resp = s.handle(Message(makeRequest(Json(3), "prompts/get", pp))).get;
	assert("error" !in resp, resp.toString);
	assert(resp["result"]["messages"][0]["content"]["text"].get!string == "true 0.5 7");
}

unittest  // a @prompt parameter with @schemaDefault is optional and takes that default
{
	import jsonschema : schemaDefault;
	import mcp.protocol.jsonrpc : Message, makeRequest;

	@safe final class DefaultedPromptApi
	{
		@prompt("page", "Prompt with a defaulted argument")
		string page(string topic, @schemaDefault(3) int count)@safe
		{
			import std.conv : to;

			return topic ~ " x" ~ count.to!string;
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DefaultedPromptApi);
	auto list = s.handle(Message(makeRequest(Json(1), "prompts/list", Json.emptyObject))).get;
	auto args = list["result"]["prompts"][0]["arguments"];
	foreach (i; 0 .. args.length)
		if (args[i]["name"].get!string == "count")
			assert(!("required" in args[i] && args[i]["required"].get!bool));

	Json pp = Json.emptyObject;
	pp["name"] = "page";
	pp["arguments"] = Json(["topic": Json("d")]);
	auto resp = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
	assert("error" !in resp, resp.toString);
	assert(resp["result"]["messages"][0]["content"]["text"].get!string == "d x3");

	pp["arguments"] = Json(["topic": Json("d"), "count": Json("5")]);
	auto given = s.handle(Message(makeRequest(Json(3), "prompts/get", pp))).get;
	assert(given["result"]["messages"][0]["content"]["text"].get!string == "d x5");
}

unittest  // @prompt string arg given JSON null -> clean InvalidParams, not vibe deserialization error
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.errors : ErrorCode;
	import std.algorithm : canFind;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json pp = Json.emptyObject;
	pp["name"] = "intro";
	pp["arguments"] = Json(["topic": Json(null)]); // null for required string arg
	auto resp = s.handle(Message(makeRequest(Json(4), "prompts/get", pp))).get;
	assert("error" in resp, "expected an error for a null required prompt argument");
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams,
			"null required prompt arg must map to -32602, not -32603");
	// The clean error path treats null as absent and reports a missing-required diagnostic.
	// The indirect path (vibe deserialization) produces an "argument 'topic': ..." prefix.
	const msg = resp["error"]["message"].get!string;
	assert(msg.canFind("Missing required argument") || msg.canFind("required argument is missing"),
			"expected a clean missing-required diagnostic, got: " ~ msg);
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

unittest  // method-level marker UDAs coexist with a @describeParam'd parameter
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	// Method-level marker UDAs (`@readOnly`/`@idempotent`) and `@describeParam`
	// live side by side on the declaration. The schema builder must fold the
	// description into the named property without the markers adding spurious
	// facet keys, and the markers must still populate ToolAnnotations.
	@safe final class MarkedParamApi
	{
		@tool("calc", "Read-only calc with a described parameter")
		@readOnly @idempotent @describeParam("a", "the left operand")
		int calc(int a, int b) @safe
		{
			return a + b;
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new MarkedParamApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json calcTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "calc")
			calcTool = tools[i];
	assert(calcTool.type == Json.Type.object);

	// The described parameter keeps its description; the leaked markers add no
	// spurious facet keys to its schema.
	auto aSchema = calcTool["inputSchema"]["properties"]["a"];
	assert(aSchema["description"].get!string == "the left operand");
	assert("minimum" !in aSchema);
	assert("maximum" !in aSchema);

	// The method-level markers still set the behavioral hints.
	auto anns = calcTool["annotations"];
	assert(anns["readOnlyHint"].get!bool == true);
	assert(anns["idempotentHint"].get!bool == true);
}

version (unittest) private struct HeaderPayload
{
	string id;
}

version (unittest) private class StructHeaderApi
{
	@tool("agg", "Aggregate header")
	@mcpHeader("p", "X-Payload")
	string agg(HeaderPayload p) @safe
	{
		return p.id;
	}
}

version (unittest) private class ArrayHeaderApi
{
	@tool("arr", "Array header")
	@mcpHeader("tags", "X-Tags")
	string arr(string[] tags) @safe
	{
		return tags.length ? tags[0] : "";
	}
}

version (unittest) private class NullableHeaderApi
{
	@tool("opt", "Optional primitive header")
	@mcpHeader("region", "X-Region")
	string opt(Nullable!int region) @safe
	{
		return region.isNull ? "" : "set";
	}
}

version (unittest) private class UnknownHeaderParamApi
{
	@tool("q", "Header naming a missing parameter")
	@mcpHeader("nope", "X-Region")
	string q(string region) @safe
	{
		return region;
	}
}

version (unittest) private class CtxHeaderParamApi
{
	@tool("q", "Header naming an injected context parameter")
	@mcpHeader("ctx", "X-Region")
	string q(string region, RequestContext ctx) @safe
	{
		return region;
	}
}

version (unittest)
{
	private class BareToolApi
	{
		@tool string f() @safe
		{
			return "";
		}
	}

	private class BarePromptApi
	{
		@prompt string f() @safe
		{
			return "";
		}
	}

	private class BareResourceApi
	{
		@resource string f() @safe
		{
			return "";
		}
	}

	private class EmptyToolNameApi
	{
		@tool("", "Nameless")
		string f() @safe
		{
			return "";
		}
	}

	private class EmptyPromptNameApi
	{
		@prompt("", "Nameless")
		string f() @safe
		{
			return "";
		}
	}
}

version (unittest) private class UnknownTemplateParamApi
{
	@resourceTemplate("item://{id}", "Item", "text/plain")
	string item(string id, string idd) @safe
	{
		return id ~ idd;
	}
}

version (unittest) private class OperatorTemplateApi
{
	@resourceTemplate("doc://{+path}/v{.ext}{/seg*}{?q,limit:3}{&extra}{#frag}",
			"Doc", "text/plain")
	string doc(string path, string ext, string seg, string q, int limit,
			string extra, string frag, RequestContext ctx) @safe
	{
		return path;
	}
}

unittest  // uriTemplateVars extracts variable names, stripping operators and modifiers
{
	static assert(uriTemplateVars("a://{x}/{+y}{?p,q*}{&r:4}") == [
		"x", "y", "p", "q", "r"
	]);
	static assert(uriTemplateVars("plain://no/vars").length == 0);
}

unittest  // a @resourceTemplate parameter not named in the URI template is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new UnknownTemplateParamApi)));
}

unittest  // @resourceTemplate parameters may bind any operator-prefixed or modified template variable
{
	auto s = new McpServer("t", "1");
	assert(__traits(compiles, registerHandlers(s, new OperatorTemplateApi)));
}

unittest  // the bare-UDA diagnostic shows each handler UDA's own argument list
{
	static assert(handlerUdaExample!tool == `@tool("name", "description")`);
	static assert(handlerUdaExample!prompt == `@prompt("name", "description")`);
	static assert(handlerUdaExample!resource == `@resource("uri", "name")`);
	static assert(handlerUdaExample!resourceTemplate == `@resourceTemplate("uriTemplate", "name")`);
	static assert(handlerUdaExample!skill == `@skill("path", "description")`);
	static assert(handlerUdaExample!skillDir == `@skillDir("path") or @skillDir()`);
}

unittest  // a bare @tool (without its argument list) is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new BareToolApi)));
}

unittest  // a bare @prompt (without its argument list) is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new BarePromptApi)));
}

unittest  // a bare @resource (without its argument list) is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new BareResourceApi)));
}

unittest  // a @tool with an empty name is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new EmptyToolNameApi)));
}

unittest  // a @prompt with an empty name is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new EmptyPromptNameApi)));
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

unittest  // @mcpHeader: naming a non-existent parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new UnknownHeaderParamApi)));
}

unittest  // @mcpHeader: naming an injected context parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new CtxHeaderParamApi)));
}

unittest  // @mcpHeader reflection: x-mcp-header is emitted into the param schema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.mrtr : paramHeaders;

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

	// paramHeaders surfaces top-level annotations; filter to path.length == 1 for the flat map.
	string[string] m;
	foreach (ph; paramHeaders(schema))
		if (ph.path.length == 1)
			m[ph.path[0]] = ph.header;
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

unittest  // @describeParam UDA: parameter descriptions appear in tool inputSchema
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
	// Each method-level @describeParam documents the named property.
	assert(props["id"]["description"].get!string == "the document id");
	assert(props["count"]["description"].get!string == "how many copies");
}

unittest  // @describeParam UDA: prompt argument descriptions appear in prompts/list
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

	// A prompt argument without @describeParam carries no description on the wire.
	Json intro;
	foreach (i; 0 .. prompts.length)
		if (prompts[i]["name"].get!string == "intro")
			intro = prompts[i];
	assert("description" !in intro["arguments"][0]);
}

unittest  // @prompt with several non-context parameters registers and dispatches
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	@safe final class TwoArgPromptApi
	{
		@prompt("pair", "Prompt taking two arguments")
		@describeParam("left", "the first word")
		string pair(string left, string right, RequestContext ctx) @safe
		{
			return left ~ "+" ~ right;
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new TwoArgPromptApi);

	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];
	assert(prompts[0]["arguments"].length == 2);
	assert(prompts[0]["arguments"][0]["description"].get!string == "the first word");
	assert("description" !in prompts[0]["arguments"][1]);

	Json pp = Json.emptyObject;
	pp["name"] = "pair";
	pp["arguments"] = Json(["left": Json("a"), "right": Json("b")]);
	auto pr = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
	assert(pr["result"]["messages"][0]["content"]["text"].get!string == "a+b");
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
	import mcp.protocol.mrtr : MetaKey;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	// Empty seed -> the tool asks for more input (MRTR InputRequiredResult). MRTR
	// exists only on the modern (stateless) protocol, so the request must negotiate
	// the modern version via `_meta`; otherwise the projection layer rejects an
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

unittest  // MRTR on a legacy session: an input-required result is rejected, not emitted off-schema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.errors : ErrorCode;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	// No modern `_meta.protocolVersion` -> the session is legacy (no MRTR). A
	// handler that nonetheless returns ToolResponse.inputRequired would emit the
	// modern-only `{inputRequests}` shape (no `content`) to a peer whose
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

unittest  // argsAs maps a conversion failure to a ToolError
{
	import mcp.server.responses : ToolError;

	struct Args
	{
		int n;
	}

	// `n` is a string, not an int -> vibe conversion fails -> ToolError.
	Json j = Json(["n": Json("not-a-number")]);
	bool threw;
	try
		cast(void) argsAs!Args(j);
	catch (ToolError e)
		threw = true;
	assert(threw, "argsAs must surface a conversion failure as a ToolError");
}

unittest  // a dynamic tool's malformed arguments read via argsAs yield an isError result
{
	import std.algorithm.searching : canFind;

	static struct Args
	{
		int n;
	}

	auto s = new McpServer("t", "1");
	Tool t;
	t.name = "dyn";
	t.inputSchema = parseJsonString(`{"type":"object"}`);
	s.registerTool(t, (Json arguments, RequestContext ctx) @safe {
		cast(void) argsAs!Args(arguments);
		return CallToolResult.text("ok");
	});
	auto r = callToolArgs(s, "dyn", `{"n":"not-a-number"}`);
	assert(r["isError"].get!bool, r.toString);
	assert(r["content"][0]["text"].get!string.canFind("arguments"), r.toString);
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

version (unittest) private final class ThemedIconApi
{
	@tool("night", "A tool with a dark-theme icon")
	@icon("https://example.com/night.png", "image/png", ["48x48"], "dark")
	string night(string x) @safe
	{
		return x;
	}
}

unittest  // @icon UDA: theme field propagates through collectIcons to tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ThemedIconApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	assert(tools.length == 1);
	assert(tools[0]["icons"].length == 1);
	assert(tools[0]["icons"][0]["src"].get!string == "https://example.com/night.png");
	assert(tools[0]["icons"][0]["theme"].get!string == "dark");
}

version (unittest) private auto modernRead(string uri) @safe
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.mrtr : MetaKey;

	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientInfo] = Json(["name": Json("c"), "version": Json("1")]);
	meta[MetaKey.clientCapabilities] = Json.emptyObject;
	Json params = Json.emptyObject;
	params["uri"] = uri;
	params["_meta"] = meta;
	return Message(makeRequest(Json(1), "resources/read", params));
}

unittest  // @cacheable UDA on a resource: modern resources/read carries CacheableResult fields
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	// A modern request (carrying the protocol-version _meta) gets cache fields.
	auto rr = s.handle(modernRead("ext://cached")).get;
	assert(rr["result"]["ttlMs"].get!long == 5000);
	assert(rr["result"]["cacheScope"].get!string == "private");
}

unittest  // @cacheable UDA: legacy resources/read has NO cache fields (no wire regression)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	// A plain (legacy) request must NOT carry any cache fields.
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

version (unittest)
{
	private struct PagedQuery
	{
		string q;
		int limit = 10;
		Nullable!int offset;
	}

	private final class PagedApi
	{
		@tool("page", "Tool taking a struct with defaulted and Nullable fields")
		string page(PagedQuery o) @safe
		{
			import std.conv : to;

			return o.q ~ ":" ~ o.limit.to!string ~ ":" ~ (o.offset.isNull
					? "none" : o.offset.get.to!string);
		}
	}

	private Json callPage(Json arguments) @safe
	{
		import mcp.protocol.jsonrpc : Message, makeRequest;

		auto s = new McpServer("t", "1");
		s.disableInputSchemaValidation();
		registerHandlers(s, new PagedApi);
		Json p = Json.emptyObject;
		p["name"] = "page";
		p["arguments"] = arguments;
		return s.handle(Message(makeRequest(Json(1), "tools/call", p))).get["result"];
	}
}

unittest  // struct param fields the schema marks optional bind to their defaults when omitted
{
	auto r = callPage(parseJsonString(`{"o":{"q":"x"}}`));
	assert("isError" !in r, r.toString);
	assert(r["content"][0]["text"].get!string == "x:10:none");
}

unittest  // struct param defaulted and Nullable fields bind supplied values
{
	auto r = callPage(parseJsonString(`{"o":{"q":"x","limit":3,"offset":4}}`));
	assert(r["content"][0]["text"].get!string == "x:3:4");
}

unittest  // struct param missing a required field names the field without serializer internals
{
	import std.algorithm : canFind;

	auto r = callPage(parseJsonString(`{"o":{"limit":3}}`));
	assert(r["isError"].get!bool);
	const msg = r["content"][0]["text"].get!string;
	assert(msg.canFind("'q'"), msg);
	assert(!msg.canFind("Policy"), msg);
}

version (unittest)
{
	import vibe.data.serialization : vibeName = name, vibeOptional = optional;

	private struct Renamed
	{
		@vibeName("type") string type_;
		@vibeOptional int opt;
		string class_;
	}

	private final class RenamedApi
	{
		@tool("renamed", "Tool whose struct param uses vibe field UDAs")
		string renamed(Renamed o) @safe
		{
			return o.type_ ~ "/" ~ o.class_;
		}

		@tool("echoRenamed", "Tool returning a struct that uses vibe field UDAs")
		Renamed echoRenamed() @safe
		{
			return Renamed("t", 1, "c");
		}
	}

	private Json renamedTool(string toolName) @safe
	{
		auto s = new McpServer("t", "1");
		registerHandlers(s, new RenamedApi);
		auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
		foreach (i; 0 .. tools.length)
			if (tools[i]["name"].get!string == toolName)
				return tools[i];
		assert(false, "tool not listed: " ~ toolName);
	}
}

unittest  // struct param schema keys fields by their serialized name
{
	auto props = renamedTool("renamed")["inputSchema"]["properties"]["o"]["properties"];
	assert("type" in props && "type_" !in props, props.toString);
	assert("class" in props && "class_" !in props, props.toString);
}

unittest  // struct param schema does not require an @optional field
{
	auto req = renamedTool("renamed")["inputSchema"]["properties"]["o"]["required"];
	assert(req == Json([Json("type"), Json("class")]), req.toString);
}

unittest  // a struct param using vibe field UDAs is callable under input-schema validation
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new RenamedApi);
	Json p = Json.emptyObject;
	p["name"] = "renamed";
	p["arguments"] = parseJsonString(`{"o":{"type":"x","class":"y"}}`);
	auto r = s.handle(Message(makeRequest(Json(1), "tools/call", p))).get["result"];
	assert("isError" !in r, r.toString);
	assert(r["content"][0]["text"].get!string == "x/y");
}

unittest  // a struct return using vibe field UDAs passes its own outputSchema validation
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.enableOutputSchemaValidation();
	registerHandlers(s, new RenamedApi);
	Json p = Json.emptyObject;
	p["name"] = "echoRenamed";
	p["arguments"] = Json.emptyObject;
	auto r = s.handle(Message(makeRequest(Json(1), "tools/call", p))).get;
	assert("error" !in r, r.toString);
	assert(r["result"]["structuredContent"]["type"].get!string == "t");
}

version (unittest)
{
	private struct Envelope
	{
		string kind;
		Json body_;
	}

	private final class JsonParamApi
	{
		@tool("raw", "Tool taking an arbitrary JSON parameter")
		string raw(Json payload) @safe
		{
			return payload.toString();
		}

		@tool("wrap", "Tool taking and returning a struct with a Json field")
		Envelope wrap(Envelope e) @safe
		{
			return e;
		}
	}
}

unittest  // a Json parameter or struct field is described by the empty (any-value) schema
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new JsonParamApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	Json raw, wrap;
	foreach (i; 0 .. tools.length)
	{
		if (tools[i]["name"].get!string == "raw")
			raw = tools[i];
		else if (tools[i]["name"].get!string == "wrap")
			wrap = tools[i];
	}
	assert(raw["inputSchema"]["properties"]["payload"] == Json.emptyObject);
	assert(wrap["inputSchema"]["properties"]["e"]["properties"]["body"] == Json.emptyObject);
	assert(wrap["outputSchema"]["properties"]["body"] == Json.emptyObject);
}

unittest  // Json parameters and struct fields bind the argument value verbatim
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.enableOutputSchemaValidation();
	registerHandlers(s, new JsonParamApi);

	Json p = Json.emptyObject;
	p["name"] = "raw";
	p["arguments"] = parseJsonString(`{"payload":{"a":[1,2]}}`);
	auto r = s.handle(Message(makeRequest(Json(1), "tools/call", p))).get["result"];
	assert(parseJsonString(r["content"][0]["text"].get!string) == parseJsonString(`{"a":[1,2]}`));

	p["name"] = "wrap";
	p["arguments"] = parseJsonString(`{"e":{"kind":"k","body":[true,null]}}`);
	auto w = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert("error" !in w, w.toString);
	assert(w["result"]["structuredContent"]["body"] == parseJsonString(`[true,null]`));
}

version (unittest)
{
	import std.sumtype : SumType;

	private alias IntOrText = SumType!(int, string);

	private struct Tagged
	{
		IntOrText value;
	}

	private final class SumTypeApi
	{
		@tool("either", "Tool taking a SumType parameter")
		string either(IntOrText v) @safe
		{
			import std.sumtype : match;

			return v.match!((int n) => "int", (string s) => "string:" ~ s);
		}

		@tool("tagged", "Tool taking a struct with a SumType field")
		string tagged(Tagged t) @safe
		{
			import std.sumtype : match;

			return t.value.match!((int n) => "int", (string s) => "string:" ~ s);
		}
	}

	private string callSumType(string tool, string args) @safe
	{
		import mcp.protocol.jsonrpc : Message, makeRequest;

		auto s = new McpServer("t", "1");
		registerHandlers(s, new SumTypeApi);
		Json p = Json.emptyObject;
		p["name"] = tool;
		p["arguments"] = parseJsonString(args);
		auto r = s.handle(Message(makeRequest(Json(1), "tools/call", p))).get["result"];
		assert("isError" !in r, r.toString);
		return r["content"][0]["text"].get!string;
	}
}

unittest  // a SumType parameter is described by anyOf over its members
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new SumTypeApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	auto v = tools[0]["inputSchema"]["properties"]["v"];
	assert(v["anyOf"].length == 2, v.toString);
}

unittest  // a SumType parameter binds whichever member the argument matches
{
	assert(callSumType("either", `{"v":5}`) == "int");
	assert(callSumType("either", `{"v":"x"}`) == "string:x");
}

unittest  // a SumType struct field binds whichever member the value matches
{
	assert(callSumType("tagged", `{"t":{"value":7}}`) == "int");
	assert(callSumType("tagged", `{"t":{"value":"y"}}`) == "string:y");
}

version (unittest)
{
	import std.datetime.date : DateTime, TimeOfDay;

	private struct Slot
	{
		TimeOfDay at;
		DateTime when;
	}

	private final class ClockApi
	{
		@tool("slot", "Tool taking and returning local times")
		Slot slot(TimeOfDay at, DateTime when) @safe
		{
			return Slot(at, when);
		}
	}
}

unittest  // TimeOfDay/DateTime schemas describe the offset-less form they bind, not RFC 3339 formats
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new ClockApi);
	auto props = s.handle(MakeListMessage()).get["result"]["tools"][0]["inputSchema"]["properties"];
	assert("format" !in props["at"] && "pattern" in props["at"], props.toString);
	assert("format" !in props["when"] && "pattern" in props["when"], props.toString);
}

unittest  // TimeOfDay/DateTime values round-trip under input and output schema validation
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.enableOutputSchemaValidation();
	registerHandlers(s, new ClockApi);
	Json p = Json.emptyObject;
	p["name"] = "slot";
	p["arguments"] = parseJsonString(`{"at":"10:00:00","when":"2026-09-25T10:00:00"}`);
	auto r = s.handle(Message(makeRequest(Json(1), "tools/call", p))).get;
	assert("error" !in r && "isError" !in r["result"], r.toString);
	assert(r["result"]["structuredContent"]["at"].get!string == "10:00:00");

	p["arguments"] = parseJsonString(`{"at":"10:00","when":"2026-09-25T10:00:00"}`);
	auto bad = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(bad["result"]["isError"].get!bool, bad.toString);
}

unittest  // argsAs honours struct field defaults and Nullable fields
{
	auto a = argsAs!PagedQuery(parseJsonString(`{"q":"x"}`));
	assert(a.q == "x" && a.limit == 10 && a.offset.isNull);
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

unittest  // resource-template Nullable!string param receives the plain captured value
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	@safe final class NullableTemplateApi
	{
		@resourceTemplate("opt://{x}", "Opt", "text/plain")
		string opt(Nullable!string x) @safe
		{
			return x.isNull ? "null" : "got " ~ x.get;
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new NullableTemplateApi);
	Json rp = Json.emptyObject;
	rp["uri"] = "opt://hello";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert("error" !in rr, rr.toString);
	assert(rr["result"]["contents"][0]["text"].get!string == "got hello");
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

version (unittest)
{
	import mcp.protocol.capabilities : ClientCapability;

	/// A context that advertises elicitation, so a handler receiving the real
	/// context observes a capability a `NullContext` (which reports no
	/// capabilities) never would.
	private final class ContextProbe : BaseRequestContext
	{
		override bool clientSupports(ClientCapability cap) @safe
		{
			return cap == ClientCapability.elicitationForm;
		}
	}

	private final class ContextPromptApi
	{
		@prompt("ctxPrompt", "Prompt exercising the request context")
		string ctxPrompt(string topic, RequestContext ctx) @safe
		{
			return ctx.clientSupports(ClientCapability.elicitationForm)
				? "elicit-capable: " ~ topic : "no-elicit: " ~ topic;
		}
	}

	private final class ContextTemplateApi
	{
		@resourceTemplate("ctx://{topic}", "ctxTpl", "text/plain")
		string ctxTpl(string topic, RequestContext ctx) @safe
		{
			return ctx.clientSupports(ClientCapability.elicitationForm)
				? "elicit-capable: " ~ topic : "no-elicit: " ~ topic;
		}
	}
}

unittest  // @prompt RequestContext parameter binds to the real request context
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ContextPromptApi);

	auto probe = new ContextProbe;
	Json pp = Json.emptyObject;
	pp["name"] = "ctxPrompt";
	pp["arguments"] = Json(["topic": Json("MCP")]);
	auto pr = s.handle(Message(makeRequest(Json(1), "prompts/get", pp)), probe).get;

	// The handler observed the real context's capabilities; a dummy NullContext
	// would report no capabilities and yield "no-elicit".
	assert(pr["result"]["messages"][0]["content"]["text"].get!string == "elicit-capable: MCP");
}

unittest  // @resourceTemplate RequestContext parameter binds to the real request context
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ContextTemplateApi);

	auto probe = new ContextProbe;
	Json rp = Json.emptyObject;
	rp["uri"] = "ctx://MCP";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp)), probe).get;

	// The handler observed the real context's capabilities; a dummy NullContext
	// would report no capabilities and yield "no-elicit".
	assert(rr["result"]["contents"][0]["text"].get!string == "elicit-capable: MCP");
}

version (unittest) private final class DescribedResourceApi
{
	@resource("res://described", "Described", "text/plain",
			"A human-readable description", "Display Title")
	string described() @safe
	{
		return "body";
	}

	@resource("res://bare", "Bare", "text/plain")
	string bare() @safe
	{
		return "bare body";
	}

	@resourceTemplate("tmpl://{id}", "DescribedTmpl", "text/plain",
			"Template description", "Template Title")
	string describedTmpl(string id) @safe
	{
		return "tmpl " ~ id;
	}

	@resourceTemplate("tmpl2://{id}", "BareTmpl", "text/plain")
	string bareTmpl(string id) @safe
	{
		return "bare tmpl " ~ id;
	}
}

unittest  // @resource description and title fields are emitted in resources/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DescribedResourceApi);
	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	Json described, bare;
	foreach (i; 0 .. res.length)
	{
		auto uri = res[i]["uri"].get!string;
		if (uri == "res://described")
			described = res[i];
		else if (uri == "res://bare")
			bare = res[i];
	}

	assert(described.type == Json.Type.object);
	assert(described["description"].get!string == "A human-readable description");
	assert(described["title"].get!string == "Display Title");

	assert(bare.type == Json.Type.object);
	// A resource without description or title carries neither on the wire.
	assert("description" !in bare);
	assert("title" !in bare);
}

unittest  // @resourceTemplate description and title fields are emitted in resources/templates/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DescribedResourceApi);
	auto tmpl = s.handle(Message(makeRequest(Json(1), "resources/templates/list",
			Json.emptyObject))).get["result"]["resourceTemplates"];

	Json described, bare;
	foreach (i; 0 .. tmpl.length)
	{
		auto ut = tmpl[i]["uriTemplate"].get!string;
		if (ut == "tmpl://{id}")
			described = tmpl[i];
		else if (ut == "tmpl2://{id}")
			bare = tmpl[i];
	}

	assert(described.type == Json.Type.object);
	assert(described["description"].get!string == "Template description");
	assert(described["title"].get!string == "Template Title");

	assert(bare.type == Json.Type.object);
	// A template without description or title carries neither on the wire.
	assert("description" !in bare);
	assert("title" !in bare);
}

// A @describeParam naming a parameter the method does not declare matches
// nothing and silently documents no argument: a programmer error rejected at
// compile time.
version (unittest) private final class DescribeUnknownParamApi
{
	@tool("ping", "Ping tool")
	@describeParam("nope", "names no parameter of ping")
	string ping(string msg) @safe
	{
		return msg;
	}
}

// A @describeParam naming an injected context parameter (excluded from the
// input schema) has no property to document: also a compile-time error.
version (unittest) private final class DescribeCtxParamApi
{
	@tool("ping", "Ping tool")
	@describeParam("ctx", "names the injected context parameter")
	string ping(string msg, RequestContext ctx) @safe
	{
		return msg;
	}
}

unittest  // @describeParam naming an unknown parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new DescribeUnknownParamApi)));
}

unittest  // @describeParam naming an injected context parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new DescribeCtxParamApi)));
}

version (unittest) private final class FacetParamApi
{
	@tool("clamp", "Clamp a value to a range")
	int clamp(@minimum(0) @maximum(100) int value)@safe
	{
		return value < 0 ? 0 : value > 100 ? 100 : value;
	}

	@tool("email", "Send to an email address")
	string email(@schemaFormat("email") string address)@safe
	{
		return address;
	}
}

unittest  // facet UDAs on bare tool parameters are emitted into inputSchema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new FacetParamApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json clampTool, emailTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "clamp")
			clampTool = tools[i];
		else if (name == "email")
			emailTool = tools[i];
	}

	// @minimum and @maximum on a bare int parameter must appear in its schema.
	// A whole-number facet is emitted as a JSON integer (`0`, not `0.0`), so read
	// the bound as an integer rather than asserting a float storage type.
	auto valueProp = clampTool["inputSchema"]["properties"]["value"];
	assert(valueProp["type"].get!string == "integer");
	assert(valueProp["minimum"].get!long == 0);
	assert(valueProp["maximum"].get!long == 100);

	// @format on a bare string parameter must appear in its schema.
	auto addrProp = emailTool["inputSchema"]["properties"]["address"];
	assert(addrProp["type"].get!string == "string");
	assert(addrProp["format"].get!string == "email");
}

version (unittest) private final class OptionalParamApi
{
	enum Unique
	{
		cards,
		art,
		prints
	}

	// All-optional parameters: a plain Nullable, an optional enum, and a
	// Nullable carrying a @schemaDefault.
	@tool("opt", "Optional params")
	string opt(Nullable!string order, Nullable!Unique unique, @schemaDefault(1) Nullable!int page)@safe
	{
		return "ok";
	}

	// A parameter facet (@schemaDefault/@minimum) AND a method-level marker
	// (@readOnly/@openWorld) on the same function.
	@tool("search", "Search")
	@readOnly @openWorld string search(string query, @schemaDefault(1) @minimum(1) int page = 1)@safe
	{
		return query;
	}
}

version (unittest) private Json optToolSchema() @safe
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new OptionalParamApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "opt")
			return tools[i]["inputSchema"];
	assert(false, "opt tool not found");
}

unittest  // a parameter facet + a method-level marker on the same tool compiles (#1263)
{
	// Registration must compile: applyUdaFacets has to ignore the bare-type
	// markers (@readOnly/@openWorld) mixed into the parameter's attribute set.
	auto s = new McpServer("t", "1");
	registerHandlers(s, new OptionalParamApi);
}

unittest  // a Nullable!T parameter is an optional flat type admitting null, absent from required
{
	auto schema = optToolSchema();
	auto order = schema["properties"]["order"];
	assert(order["type"] == Json([Json("string"), Json("null")]), order.toString);
	assert("anyOf" !in order);
	// All parameters are optional, so the schema carries no `required` array.
	assert("required" !in schema);
}

unittest  // an optional enum parameter keeps its enum constraint inline, with null as a member
{
	auto schema = optToolSchema();
	auto unique = schema["properties"]["unique"];
	assert(unique["type"] == Json([Json("string"), Json("null")]), unique.toString);
	assert("anyOf" !in unique);
	assert(unique["enum"].length == 4);
	assert(unique["enum"][3].type == Json.Type.null_);
}

unittest  // @schemaDefault on a Nullable parameter emits `default`
{
	auto schema = optToolSchema();
	auto page = schema["properties"]["page"];
	assert(page["type"] == Json([Json("integer"), Json("null")]), page.toString);
	assert("anyOf" !in page);
	assert(page["default"].get!long == 1);
}

version (unittest) private final class TaskUdaApi
{
	import mcp.server.task_context : TaskContext;
	import mcp.protocol.mrtr : InputRequest;
	import core.time : msecs;

	struct Doubled
	{
		int value;
	}

	struct Approved
	{
		string topic;
		bool approved;
	}

	/// A plain async task: returns a typed result the framework wraps. The
	/// @taskTtl / @taskPollInterval set this task's TTL and poll cadence.
	@taskTool("async_double", "Double a number asynchronously")
	@taskTtl(12_345.msecs) @taskPollInterval(250.msecs)
	@readOnly Doubled asyncDouble(int n, TaskContext tc) @safe
	{
		tc.progress("doubling");
		return Doubled(n * 2);
	}

	/// A task that elicits mid-execution before finishing (re-entrant model).
	@taskTool("approve", "Ask for approval, then finish")
	Approved approve(string topic, TaskContext tc) @safe
	{
		if (!tc.hasInput("ok"))
			return tc.requireInput([
			InputRequest.elicitation("ok", "Approve " ~ topic ~ "?")
		]);
		return Approved(topic, tc.input("ok").get!bool);
	}
}

version (unittest) private Json modernMeta() @safe
{
	import mcp.protocol.capabilities : tasksExtensionKey;
	import mcp.protocol.mrtr : MetaKey;

	// A client that declared the Tasks extension: the @taskTool tests exercise the
	// task surface, which the server serves only to such a client.
	Json ext = Json.emptyObject;
	ext[tasksExtensionKey] = Json.emptyObject;
	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientCapabilities] = Json(["extensions": ext]);
	return meta;
}

unittest  // @taskTool UDA: tool is listed with an input schema derived from its params
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.server.task_context : SyncTaskDispatcher;

	auto s = new McpServer("t", "1");
	TaskOptions taskOpts;
	taskOpts.dispatcher = new SyncTaskDispatcher();
	s.enableTasks(taskOpts);
	registerHandlers(s, new TaskUdaApi);

	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];
	Json dbl;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "async_double")
			dbl = tools[i];
	assert(dbl.type == Json.Type.object);
	// The TaskContext parameter is injected and omitted from the schema; `n` is.
	assert(("n" in dbl["inputSchema"]["properties"]) !is null);
	assert("tc" !in dbl["inputSchema"]["properties"]);
	assert(dbl["annotations"]["readOnlyHint"].get!bool);
}

unittest  // @taskTool UDA: tools/call returns a task the executor completes
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.server.task_context : SyncTaskDispatcher;

	auto s = new McpServer("t", "1");
	s.enableTasks(TaskOptions(null, new SyncTaskDispatcher()));
	registerHandlers(s, new TaskUdaApi);

	Json p = Json.emptyObject;
	p["name"] = "async_double";
	p["arguments"] = Json(["n": Json(21)]);
	p["_meta"] = modernMeta();
	auto call = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(call["result"]["resultType"].get!string == "task");
	const id = call["result"]["taskId"].get!string;
	// @taskTtl(12_345.msecs) / @taskPollInterval(250.msecs) seed the task timing.
	assert(call["result"]["ttlMs"].get!long == 12_345);
	assert(call["result"]["pollIntervalMs"].get!long == 250);

	Json gp = Json(["taskId": Json(id)]);
	gp["_meta"] = modernMeta();
	auto got = s.handle(Message(makeRequest(Json(3), "tasks/get", gp))).get;
	assert(got["result"]["status"].get!string == "completed");
	assert(got["result"]["result"]["structuredContent"]["value"].get!int == 42);
	assert(got["result"]["pollIntervalMs"].get!long == 250);
}

unittest  // @taskTool UDA: a missing required argument (schema validation off) completes as an isError result
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.server.task_context : SyncTaskDispatcher;
	import std.algorithm : canFind;

	auto s = new McpServer("t", "1");
	s.disableInputSchemaValidation();
	s.enableTasks(TaskOptions(null, new SyncTaskDispatcher()));
	registerHandlers(s, new TaskUdaApi);

	Json p = Json.emptyObject;
	p["name"] = "async_double";
	p["arguments"] = Json.emptyObject;
	p["_meta"] = modernMeta();
	auto call = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	const id = call["result"]["taskId"].get!string;

	Json gp = Json(["taskId": Json(id)]);
	gp["_meta"] = modernMeta();
	auto got = s.handle(Message(makeRequest(Json(3), "tasks/get", gp))).get["result"];
	assert(got["status"].get!string == "completed", got.toString);
	assert(got["result"]["isError"].get!bool, got.toString);
	assert(got["result"]["content"][0]["text"].get!string.canFind("'n'"));
}

unittest  // @taskTool UDA: a mid-task elicitation suspends and resumes via tasks/update
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.server.task_context : SyncTaskDispatcher;

	auto s = new McpServer("t", "1");
	s.enableTasks(TaskOptions(null, new SyncTaskDispatcher()));
	registerHandlers(s, new TaskUdaApi);

	Json p = Json.emptyObject;
	p["name"] = "approve";
	p["arguments"] = Json(["topic": Json("deploy")]);
	p["_meta"] = modernMeta();
	auto call = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	const id = call["result"]["taskId"].get!string;

	Json gp = Json(["taskId": Json(id)]);
	gp["_meta"] = modernMeta();
	auto blocked = s.handle(Message(makeRequest(Json(3), "tasks/get", gp))).get;
	assert(blocked["result"]["status"].get!string == "input_required");
	assert(blocked["result"]["inputRequests"]["ok"]["method"].get!string == "elicitation/create");

	Json up = Json([
		"taskId": Json(id),
		"inputResponses": Json(["ok": Json(true)])
	]);
	up["_meta"] = modernMeta();
	auto ack = s.handle(Message(makeRequest(Json(4), "tasks/update", up))).get;
	assert("error" !in ack);

	auto done = s.handle(Message(makeRequest(Json(5), "tasks/get", gp))).get;
	assert(done["result"]["status"].get!string == "completed");
	assert(done["result"]["result"]["structuredContent"]["topic"].get!string == "deploy");
	assert(done["result"]["result"]["structuredContent"]["approved"].get!bool);
}

version (unittest)
{
	private struct EmailArgs
	{
		string from;
	}

	private struct Email
	{
		string messageId;
		string from;
	}

	// A typed @event pull/fetch type: EventBatch!Email fetch(EmailArgs, FetchContext).
	private class EventUdaApi
	{
		@event("email.received", "A new email arrives", "New Email")
		EventBatch!Email checkEmail(EmailArgs args, FetchContext ctx) @safe
		{
			if (ctx.isBootstrap())
				return EventBatch!Email.empty("c0");
			return EventBatch!Email.of([
				Event!Email(Email("e1", args.from), "c1")
			], "c1");
		}
	}
}

unittest  // @event derives input + payload schemas from its typed signature
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.enableEvents();
	registerHandlers(s, new EventUdaApi);

	Json params = Json.emptyObject;
	params["_meta"] = modernMeta();
	auto events = s.handle(Message(makeRequest(Json(1), "events/list",
			params))).get["result"]["events"];
	Json email;
	foreach (i; 0 .. events.length)
		if (events[i]["name"].get!string == "email.received")
			email = events[i];
	assert(email.type == Json.Type.object);
	assert(("from" in email["inputSchema"]["properties"]) !is null); // from EmailArgs
	assert(email["payloadSchema"].type == Json.Type.object);
	assert(("messageId" in email["payloadSchema"]["properties"]) !is null); // from Email
}

unittest  // @event carries its title through to events/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.enableEvents();
	registerHandlers(s, new EventUdaApi);

	Json params = Json.emptyObject;
	params["_meta"] = modernMeta();
	auto events = s.handle(Message(makeRequest(Json(1), "events/list",
			params))).get["result"]["events"];
	Json email;
	foreach (i; 0 .. events.length)
		if (events[i]["name"].get!string == "email.received")
			email = events[i];
	assert(email["title"].get!string == "New Email");
}

unittest  // @event fetch handler backs events/poll: bootstrap then deliver typed payload
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.enableEvents();
	registerHandlers(s, new EventUdaApi);

	Json boot = Json.emptyObject;
	boot["name"] = "email.received";
	boot["arguments"] = Json(["from": Json("a@b.com")]);
	boot["_meta"] = modernMeta();
	auto b = s.handle(Message(makeRequest(Json(1), "events/poll", boot))).get;
	assert(b["result"]["events"].length == 0 && b["result"]["cursor"].get!string == "c0");

	Json next = Json.emptyObject;
	next["name"] = "email.received";
	next["arguments"] = Json(["from": Json("a@b.com")]);
	next["cursor"] = "c0";
	next["_meta"] = modernMeta();
	auto n = s.handle(Message(makeRequest(Json(2), "events/poll", next))).get;
	assert(n["result"]["events"].length == 1);
	assert(n["result"]["events"][0]["data"]["from"].get!string == "a@b.com");
	assert(n["result"]["events"][0]["data"]["messageId"].get!string == "e1");
}

unittest  // the typed builder defines a push type whose publish() feeds events/poll
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	auto rt = s.enableEvents();
	auto ev = rt.define!(EmailArgs, Email)("mail.pushed", "pushed mail");

	Json boot = Json.emptyObject;
	boot["name"] = "mail.pushed";
	boot["_meta"] = modernMeta();
	auto b = s.handle(Message(makeRequest(Json(1), "events/poll", boot))).get;
	auto cursor = b["result"]["cursor"];

	ev.publish(Email("m1", "x@y.com"));

	Json next = Json.emptyObject;
	next["name"] = "mail.pushed";
	next["cursor"] = cursor;
	next["_meta"] = modernMeta();
	auto n = s.handle(Message(makeRequest(Json(2), "events/poll", next))).get;
	assert(n["result"]["events"].length == 1);
	assert(n["result"]["events"][0]["data"]["messageId"].get!string == "m1");
}

version (unittest) private final class TaskCtxToolApi
{
	@tool("t", "A plain tool that wrongly takes a TaskContext")
	string t(string msg, TaskContext tc) @safe
	{
		return msg;
	}
}

version (unittest) private final class EventCtxToolApi
{
	@tool("t", "A plain tool that wrongly takes an EventContext")
	string t(string msg, EventContext ec) @safe
	{
		return msg;
	}
}

version (unittest) private final class EventCtxTaskApi
{
	@taskTool("t", "A task that wrongly takes an EventContext")
	string t(string msg, EventContext ec) @safe
	{
		return msg;
	}
}

unittest  // a @tool method taking a TaskContext is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new TaskCtxToolApi)));
}

unittest  // a @tool method taking an EventContext is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new EventCtxToolApi)));
}

unittest  // a @taskTool method taking an EventContext is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new EventCtxTaskApi)));
}

unittest  // a Nullable return is wrapped under `result` in an object output schema
{
	auto s = outputSchemaOf!(Nullable!int)();
	assert(s["type"].get!string == "object", s.toString());
	assert("result" in s["properties"]);

	auto r = toToolResult(Nullable!int(3));
	assert(r.structuredContent.type == Json.Type.object);
	assert(r.structuredContent["result"].get!long == 3);
}

unittest  // a null Nullable return still yields an object structuredContent
{
	auto r = toToolResult(Nullable!int.init);
	assert(r.structuredContent.type == Json.Type.object);
	assert(r.structuredContent["result"].type == Json.Type.null_);
}

unittest  // a SysTime return is wrapped under `result` in an object output schema
{
	import std.datetime.systime : SysTime;
	import std.datetime.timezone : UTC;
	import std.datetime.date : DateTime;

	auto s = outputSchemaOf!SysTime();
	assert(s["type"].get!string == "object", s.toString());
	assert("result" in s["properties"]);

	auto r = toToolResult(SysTime(DateTime(2026, 1, 2, 3, 4, 5), UTC()));
	assert(r.structuredContent.type == Json.Type.object);
	assert(r.structuredContent["result"].type == Json.Type.string);
}

unittest  // a Json return is wrapped under `result` so structuredContent is an object
{
	auto r = toToolResult(Json(5));
	assert(r.structuredContent.type == Json.Type.object);
	assert(r.structuredContent["result"].get!long == 5);
	assert("result" in outputSchemaOf!Json()["properties"]);
}

version (unittest) private final class SystemToolApi
{
	@tool("t", "A tool whose method is not @safe")
	string t(string msg) @system
	{
		return msg;
	}
}

unittest  // a non-@safe handler method is rejected with a diagnostic naming it
{
	static assert(!__traits(compiles, checkHandlerSafety!("t", SystemToolApi.t)()));
	static assert(__traits(compiles, checkHandlerSafety!("echo", EchoSafeApi.echo)()));
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new SystemToolApi)));
}

version (unittest) private final class EchoSafeApi
{
	@tool("echo", "Echo")
	string echo(string msg) @safe
	{
		return msg;
	}
}

version (unittest) private final class ContentToolApi
{
	@tool("one", "Return a single content block")
	Content one() @safe
	{
		return Content.makeText("hi");
	}

	@tool("many", "Return several content blocks")
	Content[] many() @safe
	{
		return [Content.makeText("a"), Content.makeText("b")];
	}
}

unittest  // a Content return becomes the result's content with no structured output
{
	assert(outputSchemaOf!Content().type == Json.Type.undefined);
	auto r = toToolResult(Content.makeText("hi"));
	assert(r.content.length == 1);
	assert(r.structuredContent.type == Json.Type.undefined);
}

unittest  // a Content[] return becomes the result's content with no structured output
{
	assert(outputSchemaOf!(Content[])().type == Json.Type.undefined);
	auto r = toToolResult([Content.makeText("a"), Content.makeText("b")]);
	assert(r.content.length == 2);
	assert(r.structuredContent.type == Json.Type.undefined);
}

unittest  // @tool methods returning Content and Content[] register
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new ContentToolApi);
}

version (unittest) private final class DefaultParamApi
{
	enum Order
	{
		asc,
		desc
	}

	@tool("list", "List with defaults")
	string list(string q, int page = 1, Order order = Order.desc, @schemaDefault(5) int limit = 7)@safe
	{
		return q;
	}
}

unittest  // a D default parameter value is emitted as the property's JSON Schema default
{
	auto s = parametersSchema!(DefaultParamApi.list)();
	auto props = s["properties"];
	assert("default" !in props["q"]);
	assert(props["page"]["default"].get!long == 1, s.toString());
	assert(props["order"]["default"].get!string == "desc", s.toString());
}

unittest  // an explicit @schemaDefault wins over the D default value
{
	auto s = parametersSchema!(DefaultParamApi.list)();
	assert(s["properties"]["limit"]["default"].get!long == 5, s.toString());
}

version (unittest) private final class NullDefaultParamApi
{
	@tool("f", "Nullable parameter with a null default")
	string f(Nullable!int n = Nullable!int.init) @safe
	{
		return "";
	}
}

unittest  // a default that serializes to null emits no JSON Schema default
{
	auto s = parametersSchema!(NullDefaultParamApi.f)();
	assert("default" !in s["properties"]["n"], s.toString());
}

version (unittest) private final class ParamResourceApi
{
	@resource("file:///x", "X")
	string x(string id) @safe
	{
		return id;
	}
}

unittest  // a @resource method that takes parameters is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new ParamResourceApi)));
}

version (unittest) private final class QualifiedParamApi
{
	@tool("repeat", "Repeat a string")
	string repeat(in string s, const int n, immutable bool loud) @safe
	{
		import std.array : replicate;

		return loud ? s.replicate(n) ~ "!" : s.replicate(n);
	}

	@prompt("greet", "Greet someone")
	string greet(in string name, const int times) @safe
	{
		import std.conv : to;

		return name ~ times.to!string;
	}

	@resourceTemplate("q://{id}", "Q", "text/plain")
	string q(const int id, const RequestContext ctx) @safe
	{
		import std.conv : to;

		return "q-" ~ id.to!string;
	}
}

version (unittest) private final class DefaultTemplateParamApi
{
	@resourceTemplate("item://{id}{?fmt,n}", "Item", "text/plain")
	string item(string id, string fmt = "json", int n = 3) @safe
	{
		import std.conv : to;

		return id ~ "/" ~ fmt ~ "/" ~ n.to!string;
	}
}

unittest  // a @resourceTemplate parameter absent from the URI binds its declared default
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DefaultTemplateParamApi);

	Json rp = Json.emptyObject;
	rp["uri"] = "item://42";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "42/json/3", rr.toString);

	rp["uri"] = "item://42?fmt=xml&n=5";
	rr = s.handle(Message(makeRequest(Json(2), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "42/xml/5", rr.toString);
}

unittest  // handlers with in/const/immutable parameters register and dispatch
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new QualifiedParamApi);

	Json tp = Json.emptyObject;
	tp["name"] = "repeat";
	tp["arguments"] = parseJsonString(`{"s":"ab","n":2,"loud":true}`);
	auto tr = s.handle(Message(makeRequest(Json(1), "tools/call", tp))).get;
	assert(tr["result"]["content"][0]["text"].get!string == "abab!", tr.toString);

	Json pp = Json.emptyObject;
	pp["name"] = "greet";
	pp["arguments"] = parseJsonString(`{"name":"Sam","times":"3"}`);
	auto pr = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
	assert(pr["result"]["messages"][0]["content"]["text"].get!string == "Sam3", pr.toString);

	Json rp = Json.emptyObject;
	rp["uri"] = "q://7";
	auto rr = s.handle(Message(makeRequest(Json(3), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "q-7", rr.toString);
}

version (unittest) private Json callToolArgs(McpServer s, string name, string arguments) @safe
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	Json p = Json.emptyObject;
	p["name"] = name;
	p["arguments"] = parseJsonString(arguments);
	return s.handle(Message(makeRequest(Json(1), "tools/call", p))).get["result"];
}

version (unittest) private final class NullInputApi
{
	static struct Filter
	{
		string q;
		Nullable!int limit;
	}

	@tool("nul", "Nullable inputs")
	string nul(Nullable!int limit, Nullable!int[] slots,
			Nullable!(OptionalParamApi.Unique) unique, Filter filter) @safe
	{
		import std.conv : to;

		return (limit.isNull ? "-" : limit.get.to!string) ~ ":" ~ slots.length.to!string ~ ":" ~ (
				unique.isNull ? "-" : "u") ~ ":" ~ (filter.limit.isNull ? "-" : "l");
	}
}

unittest  // explicit null for a Nullable parameter passes input validation and binds as null
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new NullInputApi);
	auto r = callToolArgs(s, "nul", `{"limit":null,"slots":[],"filter":{"q":"x"}}`);
	assert("isError" !in r, r.toString);
	assert(r["content"][0]["text"].get!string == "-:0:-:-", r.toString);
}

unittest  // a null element of a Nullable!T[] parameter passes input validation
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new NullInputApi);
	auto r = callToolArgs(s, "nul", `{"slots":[1,null],"filter":{"q":"x"}}`);
	assert("isError" !in r, r.toString);
	assert(r["content"][0]["text"].get!string == "-:2:-:-", r.toString);
}

unittest  // explicit null for a Nullable enum parameter passes input validation
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new NullInputApi);
	auto r = callToolArgs(s, "nul", `{"unique":null,"slots":[],"filter":{"q":"x"}}`);
	assert("isError" !in r, r.toString);
}

unittest  // explicit null for a Nullable struct field passes input validation
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new NullInputApi);
	auto r = callToolArgs(s, "nul", `{"slots":[],"filter":{"q":"x","limit":null}}`);
	assert("isError" !in r, r.toString);
}

unittest  // a Nullable @mcpHeader parameter keeps the bare primitive type x-mcp-header requires
{
	import mcp.protocol.mrtr : paramHeaders;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new NullableHeaderApi);
	auto schema = s.handle(MakeListMessage()).get["result"]["tools"][0]["inputSchema"];
	assert(schema["properties"]["region"]["type"].get!string == "integer", schema.toString);
	assert(paramHeaders(schema).length == 1);
}

version (unittest) private final class UnsetFloatApi
{
	static struct Reading
	{
		string sensor;
		double value;
		float[] samples;
	}

	@tool("read", "Return a reading whose floating-point members are unset")
	Reading read() @safe
	{
		Reading r;
		r.sensor = "s";
		r.samples = [float.init];
		return r;
	}

	@tool("ratio", "Return an unset double")
	double ratio() @safe
	{
		return double.init;
	}
}

unittest  // an unset floating-point result, as sent on the wire, conforms to the tool's outputSchema
{
	import mcp.protocol.schema : validateAgainstSchema;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new UnsetFloatApi);
	Json[string] schemas;
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	foreach (i; 0 .. tools.length)
		schemas[tools[i]["name"].get!string] = tools[i]["outputSchema"];
	foreach (name; ["read", "ratio"])
	{
		// The wire form: vibe writes a NaN as `null`.
		auto wire = parseJsonString(callToolArgs(s, name, `{}`).toString);
		const err = validateAgainstSchema(wire["structuredContent"], schemas[name]);
		assert(err.length == 0, name ~ ": " ~ err ~ " in " ~ wire.toString);
	}
}

unittest  // a floating-point output schema admits the null an unset value serializes as
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new UnsetFloatApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "read")
			assert(tools[i]["outputSchema"]["properties"]["value"]["type"] == Json(
					[Json("number"), Json("null")]), tools[i].toString);
}

version (unittest) private final class KeywordParamApi
{
	@tool("fetch", "Parameters named after D keywords")
	@describeParam("version", "the version to fetch")
	@mcpHeader("version", "Version")
	string fetch(string version_, string body_) @safe
	{
		return version_ ~ "/" ~ body_;
	}

	@prompt("release", "Prompt with a keyword-named argument")
	string release(string version_) @safe
	{
		return "release " ~ version_;
	}

	@resourceTemplate("pkg://{version}", "Package")
	string pkg(string version_) @safe
	{
		return "pkg " ~ version_;
	}
}

unittest  // a tool parameter's wire name drops one trailing underscore, as a struct field's does
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new KeywordParamApi);
	auto schema = s.handle(MakeListMessage()).get["result"]["tools"][0]["inputSchema"];
	assert("version" in schema["properties"] && "body" in schema["properties"], schema.toString);
	assert(schema["required"] == Json([Json("version"), Json("body")]), schema.toString);
	assert(schema["properties"]["version"]["description"].get!string == "the version to fetch");
	assert(schema["properties"]["version"]["x-mcp-header"].get!string == "Version");
	auto r = callToolArgs(s, "fetch", `{"version":"1.2","body":"b"}`);
	assert("isError" !in r, r.toString);
	assert(r["content"][0]["text"].get!string == "1.2/b", r.toString);
}

unittest  // a prompt argument's wire name drops one trailing underscore
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new KeywordParamApi);
	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];
	assert(prompts[0]["arguments"][0]["name"].get!string == "version", prompts.toString);
	Json pp = Json.emptyObject;
	pp["name"] = "release";
	pp["arguments"] = parseJsonString(`{"version":"2"}`);
	auto pr = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
	assert(pr["result"]["messages"][0]["content"]["text"].get!string == "release 2", pr.toString);
}

unittest  // a resource template parameter matches its URI variable without the trailing underscore
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new KeywordParamApi);
	Json rp = Json.emptyObject;
	rp["uri"] = "pkg://3";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "pkg 3", rr.toString);
}

version (unittest) private final class ContextResourceApi
{
	@resource("ctx://doc", "Doc")
	string doc(RequestContext ctx) @safe
	{
		return ctx is null ? "no context" : "with context";
	}
}

version (unittest) private final class ArgResourceApi
{
	@resource("arg://doc", "Doc")
	string doc(string id) @safe
	{
		return id;
	}
}

unittest  // a @resource method may take the per-request RequestContext
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ContextResourceApi);
	Json rp = Json.emptyObject;
	rp["uri"] = "ctx://doc";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "with context", rr.toString);
}

unittest  // a @resource method taking a non-context parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new ArgResourceApi)));
}

version (unittest) private final class UnnamedToolParamApi
{
	@tool("anon", "A tool with an unnamed parameter")
	string anon(int) @safe
	{
		return "";
	}
}

version (unittest) private final class UnnamedPromptParamApi
{
	@prompt("anon", "A prompt with an unnamed parameter")
	string anon(string) @safe
	{
		return "";
	}
}

version (unittest) private final class UnnamedContextParamApi
{
	@tool("ctx", "A tool whose unnamed parameter is the injected context")
	string ctx(int n, RequestContext) @safe
	{
		return "";
	}
}

unittest  // a tool with an unnamed schema parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new UnnamedToolParamApi)));
}

unittest  // a prompt with an unnamed argument parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new UnnamedPromptParamApi)));
}

unittest  // an unnamed injected context parameter needs no name
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new UnnamedContextParamApi);
}

version (unittest) private final class StrictArgsApi
{
	@tool("strict", "Rejects unknown arguments")
	@strictArgs string strict(string q, int limit = 1) @safe
	{
		return q;
	}

	@tool("lenient", "Ignores unknown arguments")
	string lenient(string q) @safe
	{
		return q;
	}
}

version (unittest) private Json strictToolSchema(string name) @safe
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new StrictArgsApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == name)
			return tools[i]["inputSchema"];
	assert(false, name ~ " not found");
}

unittest  // a @strictArgs tool's input schema closes its properties
{
	auto schema = strictToolSchema("strict");
	assert(schema["additionalProperties"].type == Json.Type.bool_, schema.toString);
	assert(!schema["additionalProperties"].get!bool);
	assert("additionalProperties" !in strictToolSchema("lenient"));
}

unittest  // a @strictArgs tool rejects an unknown argument
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new StrictArgsApi);
	auto r = callToolArgs(s, "strict", `{"q":"x","limt":5}`);
	assert(r["isError"].get!bool, r.toString);
}

unittest  // a @strictArgs tool rejects an unknown argument with input validation off
{
	import std.algorithm.searching : canFind;

	auto s = new McpServer("t", "1");
	s.disableInputSchemaValidation();
	registerHandlers(s, new StrictArgsApi);
	auto r = callToolArgs(s, "strict", `{"q":"x","limt":5}`);
	assert(r["isError"].get!bool, r.toString);
	assert(r["content"][0]["text"].get!string.canFind("'limt'"), r.toString);
	assert("isError" !in callToolArgs(s, "strict", `{"q":"x","limit":5}`));
}

unittest  // a tool without @strictArgs ignores an unknown argument
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new StrictArgsApi);
	auto r = callToolArgs(s, "lenient", `{"q":"x","extra":true}`);
	assert("isError" !in r, r.toString);
}

version (unittest) private struct CounterApi
{
	int calls;

	@tool("bump", "Count a call")
	int bump() @safe
	{
		return ++calls;
	}
}

unittest  // registerHandlers rejects a struct value, whose handlers would mutate a copy
{
	auto s = new McpServer("t", "1");
	CounterApi api;
	static assert(!__traits(compiles, registerHandlers(s, api)));
}

unittest  // registerHandlers with a pointer to a struct dispatches to that struct
{
	auto s = new McpServer("t", "1");
	auto api = new CounterApi;
	registerHandlers(s, api);
	callToolArgs(s, "bump", `{}`);
	callToolArgs(s, "bump", `{}`);
	assert(api.calls == 2);
}

version (unittest) private final class SharedWireNameApi
{
	@tool("dup", "Two parameters with one wire name")
	string dup(int limit, int limit_) @safe
	{
		return "";
	}
}

unittest  // parameters whose names differ only by a trailing underscore are rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new SharedWireNameApi)));
}

version (unittest) private enum Tone : string
{
	soft = "s",
	loud = "l",
}

version (unittest) private final class StringEnumApi
{
	@tool("speak", "Speak in a tone")
	string speak(Tone tone, Tone fallback = Tone.soft) @safe
	{
		import std.conv : to;

		return tone.to!string ~ "/" ~ fallback.to!string;
	}
}

unittest  // a string-based enum parameter is advertised and bound by member name
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new StringEnumApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	auto props = tools[0]["inputSchema"]["properties"];
	assert(props["tone"]["enum"][1].get!string == "loud", props.toString);
	assert(props["fallback"]["default"].get!string == "soft", props.toString);
	auto r = callToolArgs(s, "speak", `{"tone":"loud"}`);
	assert(r["content"][0]["text"].get!string == "loud/soft", r.toString);
}

version (unittest) private final class MethodUdaParamApi
{
	@tool("f", "f")
	@hintTitle("Nice") @describeParam("y", "why") @readOnly string f(@minimum(1) int x, int y)@safe
	{
		return "";
	}
}

unittest  // a parameter's attributes exclude the attributes of its function
{
	alias f = MethodUdaParamApi.f;
	static assert(ParamAttributes!(f, 0).length == 1);
	static assert(is(typeof(ParamAttributes!(f, 0)[0]) == typeof(minimum(1))));
	static assert(ParamAttributes!(f, 1).length == 0);
	auto props = parametersSchema!f()["properties"];
	assert(props["x"].length == 2 && props["x"]["minimum"].get!long == 1, props.toString);
}

version (unittest) private final class MethodTitleApi
{
	@tool("f", "f") @title("Nice")
	string f(int x) @safe
	{
		return "";
	}
}

version (unittest) private final class SchemaDefaultParamApi
{
	@tool("sum", "Sum with a schema-defaulted addend")
	int sum(int n, @schemaDefault(7) int x, @schemaDefault(5) int y = 2)@safe
	{
		return n + x + y;
	}
}

unittest  // a @schemaDefault parameter is optional in the input schema
{
	auto s = parametersSchema!(SchemaDefaultParamApi.sum)();
	assert(s["required"] == Json([Json("n")]), s.toString);
	assert(s["properties"]["x"]["default"].get!long == 7, s.toString);
}

unittest  // an omitted @schemaDefault argument binds to the advertised default
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new SchemaDefaultParamApi);
	auto r = callToolArgs(s, "sum", `{"n":1}`);
	assert(r["structuredContent"]["result"].get!int == 13, r.toString);
	r = callToolArgs(s, "sum", `{"n":1,"x":0,"y":0}`);
	assert(r["structuredContent"]["result"].get!int == 1, r.toString);
}

version (unittest) private final class FieldDescriptionParamApi
{
	@tool("find", "Find things")
	@describeParam("limit", "page size")
	string find(@fieldDescription("search text") string q, @fieldDescription("ignored") int limit)@safe
	{
		return q;
	}
}

unittest  // @fieldDescription on a parameter is its description, and @describeParam wins over it
{
	auto props = parametersSchema!(FieldDescriptionParamApi.find)()["properties"];
	assert(props["q"]["description"].get!string == "search text", props.toString);
	assert(props["limit"]["description"].get!string == "page size", props.toString);
}

version (unittest) private final class UiTaskApi
{
	@taskTool("render_later", "Render a widget as a task")
	@ui("ui://demo/widget", "model")
	string renderLater(string spec, TaskContext tc) @safe
	{
		return spec;
	}
}

unittest  // @ui on a @taskTool attaches _meta.ui to its descriptor
{
	import mcp.server.task_context : SyncTaskDispatcher;

	auto s = new McpServer("t", "1");
	s.enableTasks(TaskOptions(null, new SyncTaskDispatcher()));
	registerHandlers(s, new UiTaskApi);
	auto t = s.handle(MakeListMessage()).get["result"]["tools"][0];
	assert(t["_meta"]["ui"]["resourceUri"].get!string == "ui://demo/widget", t.toString);
	assert(t["_meta"]["ui"]["visibility"] == Json([Json("model")]), t.toString);
}

version (unittest) private final class UiBadSchemeApi
{
	@tool("f", "f") @ui("https://example.com/widget")
	string f() @safe
	{
		return "";
	}
}

version (unittest) private final class UiBadVisibilityApi
{
	@tool("f", "f") @ui("ui://demo/widget", "user")
	string f() @safe
	{
		return "";
	}
}

unittest  // a @ui resourceUri outside the ui:// scheme is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new UiBadSchemeApi)));
}

unittest  // a @ui visibility other than "model" or "app" is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new UiBadVisibilityApi)));
}

unittest  // a JSON Schema facet on a handler method is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new MethodTitleApi)));
}

version (unittest) private Json callToolResult(McpServer s, string name, Json arguments) @safe
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	Json p = Json.emptyObject;
	p["name"] = name;
	p["arguments"] = arguments;
	return s.handle(Message(makeRequest(Json(1), "tools/call", p))).get["result"];
}

version (unittest) private struct SumHolder
{
	import std.sumtype : SumType;

	string label;
	SumType!(int, string) value;
}

version (unittest) private final class SumTypeResultApi
{
	import std.sumtype : SumType;

	@tool("pick", "Return a number or a word")
	SumType!(int, string) pick(bool word) @safe
	{
		alias R = SumType!(int, string);
		return word ? R("seven") : R(7);
	}

	@tool("tagged", "Return a struct holding a SumType")
	SumHolder tagged() @safe
	{
		return SumHolder("x", typeof(SumHolder.value)("held"));
	}
}

unittest  // a SumType tool result serializes as the value it holds
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new SumTypeResultApi);
	auto n = callToolResult(s, "pick", Json(["word": Json(false)]));
	assert(n["structuredContent"]["result"] == Json(7), n.toString);
	auto w = callToolResult(s, "pick", Json(["word": Json(true)]));
	assert(w["structuredContent"]["result"] == Json("seven"), w.toString);
}

unittest  // a SumType field of a struct tool result serializes as the value it holds
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new SumTypeResultApi);
	auto r = callToolResult(s, "tagged", Json.emptyObject);
	assert(r["structuredContent"]["value"] == Json("held"), r.toString);
	assert(r["structuredContent"]["label"] == Json("x"), r.toString);
}

version (unittest) private final class RealParamApi
{
	@tool("f", "f")
	string f(real x) @safe
	{
		return "";
	}
}

version (unittest) private final class TupleReturnApi
{
	@tool("f", "f")
	Tuple!(int, string) f() @safe
	{
		return typeof(return)(1, "a");
	}
}

version (unittest) private final class ClassParamApi
{
	@tool("f", "f")
	string f(RealParamApi other) @safe
	{
		return "";
	}
}

version (unittest) private final class MismatchedDefaultApi
{
	import jsonschema : schemaDefault;

	@tool("f", "f")
	string f(@schemaDefault("abc") int x)@safe
	{
		return "";
	}
}

version (unittest) private final class FractionalIntDefaultApi
{
	import jsonschema : schemaDefault;

	@tool("f", "f")
	string f(@schemaDefault(2.5) int x)@safe
	{
		return "";
	}
}

unittest  // a real parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new RealParamApi)));
}

unittest  // a Tuple return is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new TupleReturnApi)));
}

unittest  // a class parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new ClassParamApi)));
}

unittest  // a @schemaDefault whose value does not convert to the parameter type is rejected
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new MismatchedDefaultApi)));
	static assert(!__traits(compiles, registerHandlers(s, new FractionalIntDefaultApi)));
}

version (unittest) private final class TaskTtlOnToolApi
{
	@tool("f", "f") @taskTtl(1.seconds)
	string f() @safe
	{
		return "";
	}
}

version (unittest) private final class CacheableOnToolApi
{
	@tool("f", "f") @cacheable(1.seconds)
	string f() @safe
	{
		return "";
	}
}

version (unittest) private final class UiOnResourceApi
{
	@resource("test://r", "r") @ui("ui://demo/widget")
	string r() @safe
	{
		return "";
	}
}

version (unittest) private final class ReadOnlyOnPromptApi
{
	@prompt("p", "p") @readOnly string p() @safe
	{
		return "";
	}
}

version (unittest) private final class StrictArgsOnPromptApi
{
	@prompt("p", "p") @strictArgs string p(string topic) @safe
	{
		return topic;
	}
}

version (unittest) private final class McpHeaderOnPromptApi
{
	@prompt("p", "p") @mcpHeader("topic", "Topic")
	string p(string topic) @safe
	{
		return topic;
	}
}

version (unittest) private final class DescribeParamOnTemplateApi
{
	@resourceTemplate("test://{id}", "t") @describeParam("nope", "missing")
	string t(string id) @safe
	{
		return id;
	}
}

version (unittest) private final class MinLengthOnIntApi
{
	@tool("f", "f")
	string f(@minLength(2) int n)@safe
	{
		return "";
	}
}

version (unittest) private final class MinimumOnStringApi
{
	@tool("f", "f")
	string f(@minimum(2) string s)@safe
	{
		return s;
	}
}

version (unittest) private struct MinItemsOnScalar
{
	@minItems(1) int n;
}

version (unittest) private final class MinItemsOnFieldApi
{
	@tool("f", "f")
	string f(MinItemsOnScalar arg) @safe
	{
		return "";
	}
}

version (unittest) private final class TaskContextPromptApi
{
	@prompt("p", "p")
	string p(string topic, TaskContext tc) @safe
	{
		return topic;
	}
}

version (unittest) private final class EventPollOnToolApi
{
	@tool("f", "f") @eventPollInterval(1.seconds)
	string f() @safe
	{
		return "";
	}
}

version (unittest) private final class FittingUdasApi
{
	@prompt("p", "p") @icon("https://example.com/p.png") @describeParam("topic", "what")
	string p(@minLength(1) string topic)@safe
	{
		return topic;
	}

	@resourceTemplate("test://{id}", "t") @cacheable(1.seconds) @priority(0.5)
	string t(string id) @safe
	{
		return id;
	}
}

unittest  // @taskTtl on a plain @tool is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new TaskTtlOnToolApi)));
}

unittest  // @cacheable on a @tool is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new CacheableOnToolApi)));
}

unittest  // @ui on a @resource is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new UiOnResourceApi)));
}

unittest  // tool-only UDAs on a @prompt are rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new ReadOnlyOnPromptApi)));
	static assert(!__traits(compiles, registerHandlers(s, new StrictArgsOnPromptApi)));
	static assert(!__traits(compiles, registerHandlers(s, new McpHeaderOnPromptApi)));
}

unittest  // @describeParam on a @resourceTemplate is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new DescribeParamOnTemplateApi)));
}

unittest  // a facet that does not fit its parameter or field type is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new MinLengthOnIntApi)));
	static assert(!__traits(compiles, registerHandlers(s, new MinimumOnStringApi)));
	static assert(!__traits(compiles, registerHandlers(s, new MinItemsOnFieldApi)));
}

unittest  // a TaskContext parameter on a @prompt is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new TaskContextPromptApi)));
}

unittest  // @eventPollInterval on a @tool is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new EventPollOnToolApi)));
}

unittest  // UDAs that fit their handler kind and parameter types still register
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new FittingUdasApi);
}

version (unittest) private final class TemplatedToolApi
{
	@tool("f", "f")
	string f(T)(T x) @safe
	{
		return "";
	}
}

version (unittest) private final class TemplatedHelperApi
{
	@tool("g", "g")
	string g(string s) @safe
	{
		return helper(s);
	}

	string helper(T)(T x) @safe
	{
		return x;
	}
}

unittest  // a templated method carrying a handler UDA is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new TemplatedToolApi)));
}

unittest  // a templated method without a handler UDA is skipped
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new TemplatedHelperApi);
}

version (unittest) private final class MutableStringApi
{
	@tool("chars", "Return a mutable char array")
	char[] chars() @safe
	{
		return "abc".dup;
	}

	@tool("wide", "Return a wstring")
	wstring wide() @safe
	{
		return "wide"w;
	}

	@prompt("p", "Return a const char slice")
	const(char)[] p() @safe
	{
		return "prompt text";
	}

	@resource("test://chars", "chars", "text/plain")
	char[] r() @safe
	{
		return "resource text".dup;
	}
}

unittest  // a tool, prompt, or resource returning a non-immutable or wide string serves it as text
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new MutableStringApi);
	auto t = callToolResult(s, "chars", Json.emptyObject);
	assert(t["content"][0]["text"] == Json("abc"), t.toString);
	auto w = callToolResult(s, "wide", Json.emptyObject);
	assert(w["content"][0]["text"] == Json("wide"), w.toString);

	Json pp = Json.emptyObject;
	pp["name"] = "p";
	auto pr = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get["result"];
	assert(pr["messages"][0]["content"]["text"] == Json("prompt text"), pr.toString);

	Json rp = Json.emptyObject;
	rp["uri"] = "test://chars";
	auto rr = s.handle(Message(makeRequest(Json(3), "resources/read", rp))).get["result"];
	assert(rr["contents"][0]["text"] == Json("resource text"), rr.toString);
}

/// A `priority` built without its constructor's range check, standing in for
/// one constructed where that check is compiled out.
version (unittest) private priority uncheckedPriority(double v) @safe
{
	priority p;
	p.value = v;
	return p;
}

version (unittest) private final class OutOfRangePriorityApi
{
	@resource("test://p", "p") @uncheckedPriority(5.0)
	string r() @safe
	{
		return "";
	}
}

unittest  // an out-of-range @priority is rejected at registration even without contracts
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new OutOfRangePriorityApi)));
}

version (unittest) private final class NullableDefaultApi
{
	import jsonschema : schemaDefault;

	@tool("viaUda", "Nullable with a @schemaDefault")
	string viaUda(@schemaDefault(5) Nullable!int n)@safe
	{
		import std.conv : to;

		return n.isNull ? "unset" : n.get.to!string;
	}

	@tool("viaD", "Nullable with a D default")
	string viaD(Nullable!int n = 5) @safe
	{
		import std.conv : to;

		return n.isNull ? "unset" : n.get.to!string;
	}

	@prompt("p", "Nullable prompt argument with a @schemaDefault")
	string p(@schemaDefault("x") Nullable!string topic)@safe
	{
		return topic.isNull ? "unset" : topic.get;
	}
}

unittest  // an explicit null for a defaulted Nullable parameter binds as unset
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new NullableDefaultApi);
	Json nullArg = Json(["n": Json(null)]);
	assert(callToolResult(s, "viaUda", nullArg)["content"][0]["text"] == Json("unset"));
	assert(callToolResult(s, "viaD", nullArg)["content"][0]["text"] == Json("unset"));
	assert(callToolResult(s, "viaUda", Json.emptyObject)["content"][0]["text"] == Json("5"));
	assert(callToolResult(s, "viaD", Json.emptyObject)["content"][0]["text"] == Json("5"));
}

unittest  // an explicit null for a defaulted Nullable prompt argument binds as unset
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new NullableDefaultApi);
	Json pp = Json.emptyObject;
	pp["name"] = "p";
	pp["arguments"] = Json(["topic": Json(null)]);
	auto r = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get["result"];
	assert(r["messages"][0]["content"]["text"] == Json("unset"), r.toString);
}

version (unittest) private final class InvalidSkillPathApi
{
	@skill("Not A Name", "An invalid skill path")
	string instructions() @safe
	{
		return "# Body\n";
	}
}

version (unittest) private final class InvalidSkillDirPathApi
{
	@skillDir("office//pdf-forms")
	string dir() @safe
	{
		return "skills/pdf-forms";
	}
}

unittest  // an invalid @skill path is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new InvalidSkillPathApi)));
}

unittest  // an invalid non-empty @skillDir path is rejected at compile time
{
	auto s = new McpServer("t", "1");
	static assert(!__traits(compiles, registerHandlers(s, new InvalidSkillDirPathApi)));
}

version (unittest) private class AnnotatedBaseApi
{
	@tool("who", "Report which class handles the call")
	string who() @safe
	{
		return "base";
	}
}

version (unittest) private class OverridingApi : AnnotatedBaseApi
{
	override string who() @safe
	{
		return "derived";
	}
}

version (unittest) private class FurtherOverridingApi : OverridingApi
{
	override string who() @safe
	{
		return "further";
	}
}

unittest  // an override of an annotated base method registers with the base UDAs and dispatches virtually
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new OverridingApi);
	auto r = callToolArgs(s, "who", `{}`);
	assert(r["content"][0]["text"].get!string == "derived", r.toString);
}

unittest  // an override two levels below the annotated declaration is still registered
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new FurtherOverridingApi);
	auto r = callToolArgs(s, "who", `{}`);
	assert(r["content"][0]["text"].get!string == "further", r.toString);
}

version (unittest) private interface AnnotatedInterfaceApi
{
	@tool("ping", "Answer a ping")
	string ping(string from) @safe;
}

version (unittest) private final class InterfaceImplApi : AnnotatedInterfaceApi
{
	string ping(string from) @safe
	{
		return "pong " ~ from;
	}
}

unittest  // a class implementing an annotated interface method registers that tool
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new InterfaceImplApi);
	auto r = callToolArgs(s, "ping", `{"from":"a"}`);
	assert(r["content"][0]["text"].get!string == "pong a", r.toString);
}

version (unittest) private final class EmptyPromptArgApi
{
	@prompt("page", "Prompt with optional typed arguments")
	string page(Nullable!int limit, int count = 3, string note = "n") @safe
	{
		import std.conv : to;

		return (limit.isNull ? "unset" : limit.get.to!string) ~ " "
			~ count.to!string ~ " [" ~ note ~ "]";
	}

	@prompt("need", "Prompt with a required integer argument")
	string need(int count) @safe
	{
		import std.conv : to;

		return count.to!string;
	}
}

unittest  // an empty string for an optional non-string prompt argument binds as omitted
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EmptyPromptArgApi);
	Json pp = Json.emptyObject;
	pp["name"] = "page";
	pp["arguments"] = Json([
		"limit": Json(""),
		"count": Json(""),
		"note": Json("")
	]);
	auto resp = s.handle(Message(makeRequest(Json(1), "prompts/get", pp))).get;
	assert("error" !in resp, resp.toString);
	assert(resp["result"]["messages"][0]["content"]["text"].get!string == "unset 3 []",
			resp.toString);
}

unittest  // an empty string for a required non-string prompt argument is a missing argument
{
	import std.algorithm.searching : canFind;
	import mcp.protocol.errors : ErrorCode;
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EmptyPromptArgApi);
	Json pp = Json.emptyObject;
	pp["name"] = "need";
	pp["arguments"] = Json(["count": Json("")]);
	auto resp = s.handle(Message(makeRequest(Json(1), "prompts/get", pp))).get;
	assert("error" in resp, resp.toString);
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams);
	assert(resp["error"]["message"].get!string.canFind("Missing required argument 'count'"),
			resp.toString);
}

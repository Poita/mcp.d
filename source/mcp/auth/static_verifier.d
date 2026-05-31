/// A trivial bearer-token verifier built from an in-memory map of token string →
/// `TokenInfo`, for local development and tests. It is the D analogue of
/// FastMCP's `StaticTokenVerifier`.
///
/// WARNING: this verifier performs NO cryptographic validation, expiry checking,
/// or revocation — it simply looks the presented token up in a fixed table. It is
/// intended ONLY for local dev and automated tests. Do NOT use it in production;
/// use `jwtVerifier` (RFC 7519 / JWKS) or `introspectionVerifier` (RFC 7662)
/// instead.
module mcp.auth.static_verifier;

import mcp.auth.resource_server : TokenInfo, TokenValidator;

@safe:

/// Build a `TokenValidator` that resolves a presented bearer token against a
/// fixed in-memory table. A token present in `tokens` returns its associated
/// `TokenInfo` (with `valid` forced true so callers cannot accidentally register
/// a "valid" entry that fails authorization); any unknown token returns
/// `TokenInfo.invalid()`.
///
/// NOT for production — see the module docs.
TokenValidator staticVerifier(TokenInfo[string] tokens) @safe
{
    // Copy the table so later mutation by the caller cannot change behavior.
    TokenInfo[string] table;
    foreach (k, v; tokens)
    {
        auto info = v;
        info.valid = true;
        table[k] = info;
    }

    return (string token) @safe {
        if (auto p = token in table)
            return *p;
        return TokenInfo.invalid();
    };
}

unittest  // a known token returns its TokenInfo
{
    TokenInfo alice;
    alice.subject = "alice";
    alice.scopes = ["mcp:read", "mcp:write"];
    alice.audience = ["https://mcp.example.com/mcp"];

    auto verify = staticVerifier(["tok-alice": alice]);

    auto got = verify("tok-alice");
    assert(got.valid);
    assert(got.subject == "alice");
    assert(got.hasScope("mcp:read"));
    assert(got.hasScope("mcp:write"));
    assert(got.hasAudience("https://mcp.example.com/mcp"));
}

unittest  // an unknown token returns TokenInfo.invalid()
{
    TokenInfo alice;
    alice.subject = "alice";
    auto verify = staticVerifier(["tok-alice": alice]);

    auto got = verify("nope");
    assert(!got.valid);
    assert(got.subject == "");
    assert(got.scopes.length == 0);
}

unittest  // an empty table rejects every token
{
    TokenInfo[string] none;
    auto verify = staticVerifier(none);
    assert(!verify("anything").valid);
    assert(!verify("").valid);
}

unittest  // registered entries are forced valid even if built with valid=false
{
    auto info = TokenInfo.invalid(); // valid == false
    info.subject = "bob";
    auto verify = staticVerifier(["tok-bob": info]);

    auto got = verify("tok-bob");
    assert(got.valid);
    assert(got.subject == "bob");
}

unittest  // mutating the caller's map after construction does not change results
{
    TokenInfo[string] tokens;
    TokenInfo alice;
    alice.subject = "alice";
    tokens["tok-alice"] = alice;

    auto verify = staticVerifier(tokens);

    // Caller adds a token after the verifier was built.
    TokenInfo mallory;
    mallory.subject = "mallory";
    tokens["tok-mallory"] = mallory;

    assert(verify("tok-alice").valid);
    assert(!verify("tok-mallory").valid); // not captured by the snapshot
}

unittest  // the result plugs into authorize() as a TokenValidator
{
    import mcp.auth.resource_server : ResourceServerConfig, AuthFailure, authorize;

    TokenInfo alice;
    alice.subject = "alice";
    alice.scopes = ["mcp:read"];

    ResourceServerConfig cfg;
    cfg.validator = staticVerifier(["tok-alice": alice]);

    TokenInfo info;
    assert(authorize(cfg, "Bearer tok-alice", info) == AuthFailure.none);
    assert(info.subject == "alice");
    assert(authorize(cfg, "Bearer bad", info) == AuthFailure.invalidToken);
}

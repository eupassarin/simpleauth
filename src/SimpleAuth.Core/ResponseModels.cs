using System.Text.Json.Serialization;

namespace SimpleAuth;

/// <summary>Successful token endpoint response per RFC 6749 §5.1 / OAuth 2.1.</summary>
public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn)
{
    /// <summary>Refresh token (present only when <c>offline_access</c> was granted).</summary>
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    /// <summary>Granted scope when it differs from the requested scope.</summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    /// <summary>ID token (present only for OIDC requests).</summary>
    [JsonPropertyName("id_token")]
    public string? IdToken { get; init; }
}

/// <summary>OAuth 2.x error response per RFC 6749 §5.2.</summary>
public sealed record ErrorResponse(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string? ErrorDescription = null);

/// <summary>OIDC discovery document per OpenID Connect Discovery 1.0 §3.</summary>
public sealed record DiscoveryDocument
{
    /// <summary>Issuer identifier URL.</summary>
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    /// <summary>Authorization endpoint URL.</summary>
    [JsonPropertyName("authorization_endpoint")]
    public required string AuthorizationEndpoint { get; init; }

    /// <summary>Token endpoint URL.</summary>
    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; init; }

    /// <summary>UserInfo endpoint URL.</summary>
    [JsonPropertyName("userinfo_endpoint")]
    public string? UserInfoEndpoint { get; init; }

    /// <summary>JWKS endpoint URL.</summary>
    [JsonPropertyName("jwks_uri")]
    public required string JwksUri { get; init; }

    /// <summary>End session endpoint URL.</summary>
    [JsonPropertyName("end_session_endpoint")]
    public string? EndSessionEndpoint { get; init; }

    /// <summary>Introspection endpoint URL.</summary>
    [JsonPropertyName("introspection_endpoint")]
    public string? IntrospectionEndpoint { get; init; }

    /// <summary>Revocation endpoint URL.</summary>
    [JsonPropertyName("revocation_endpoint")]
    public string? RevocationEndpoint { get; init; }

    /// <summary>Supported response types.</summary>
    [JsonPropertyName("response_types_supported")]
    public required IReadOnlyList<string> ResponseTypesSupported { get; init; }

    /// <summary>Supported response modes.</summary>
    [JsonPropertyName("response_modes_supported")]
    public IReadOnlyList<string>? ResponseModesSupported { get; init; }

    /// <summary>Supported grant types.</summary>
    [JsonPropertyName("grant_types_supported")]
    public IReadOnlyList<string>? GrantTypesSupported { get; init; }

    /// <summary>Supported subject types.</summary>
    [JsonPropertyName("subject_types_supported")]
    public required IReadOnlyList<string> SubjectTypesSupported { get; init; }

    /// <summary>Supported ID token signing algorithms.</summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public required IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; }

    /// <summary>Supported scopes.</summary>
    [JsonPropertyName("scopes_supported")]
    public IReadOnlyList<string>? ScopesSupported { get; init; }

    /// <summary>Supported token endpoint auth methods.</summary>
    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public IReadOnlyList<string>? TokenEndpointAuthMethodsSupported { get; init; }

    /// <summary>Supported claims.</summary>
    [JsonPropertyName("claims_supported")]
    public IReadOnlyList<string>? ClaimsSupported { get; init; }

    /// <summary>Whether PKCE S256 is required.</summary>
    [JsonPropertyName("code_challenge_methods_supported")]
    public IReadOnlyList<string>? CodeChallengeMethodsSupported { get; init; }

    /// <summary>Supported request object signing algorithms (for PAR).</summary>
    [JsonPropertyName("request_object_signing_alg_values_supported")]
    public IReadOnlyList<string>? RequestObjectSigningAlgValuesSupported { get; init; }

    /// <summary>PAR endpoint (RFC 9126).</summary>
    [JsonPropertyName("pushed_authorization_request_endpoint")]
    public string? PushedAuthorizationRequestEndpoint { get; init; }

    /// <summary>Whether PAR is required for all clients.</summary>
    [JsonPropertyName("require_pushed_authorization_requests")]
    public bool? RequirePushedAuthorizationRequests { get; init; }

    /// <summary>DPoP signing algorithms supported (RFC 9449).</summary>
    [JsonPropertyName("dpop_signing_alg_values_supported")]
    public IReadOnlyList<string>? DPopSigningAlgValuesSupported { get; init; }
}

/// <summary>UserInfo endpoint response per OIDC Core §5.3.</summary>
public sealed class UserInfoResponse : Dictionary<string, object?>
{
    /// <summary>Initializes an empty UserInfo response.</summary>
    public UserInfoResponse() : base(StringComparer.Ordinal) { }
}

/// <summary>Token introspection response per RFC 7662 §2.2.</summary>
public sealed record IntrospectionResponse
{
    /// <summary>Whether the token is currently active.</summary>
    [JsonPropertyName("active")]
    public required bool Active { get; init; }

    /// <summary>Space-separated list of scopes.</summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    /// <summary>Client ID the token was issued to.</summary>
    [JsonPropertyName("client_id")]
    public string? ClientId { get; init; }

    /// <summary>Subject (end-user) identifier.</summary>
    [JsonPropertyName("sub")]
    public string? Sub { get; init; }

    /// <summary>Token expiration (Unix timestamp).</summary>
    [JsonPropertyName("exp")]
    public long? Exp { get; init; }

    /// <summary>Token issued-at (Unix timestamp).</summary>
    [JsonPropertyName("iat")]
    public long? Iat { get; init; }

    /// <summary>Token not-before (Unix timestamp).</summary>
    [JsonPropertyName("nbf")]
    public long? Nbf { get; init; }

    /// <summary>JWT ID (token unique identifier).</summary>
    [JsonPropertyName("jti")]
    public string? Jti { get; init; }

    /// <summary>Issuer.</summary>
    [JsonPropertyName("iss")]
    public string? Iss { get; init; }

    /// <summary>Audience.</summary>
    [JsonPropertyName("aud")]
    public string? Aud { get; init; }

    /// <summary>Token type hint.</summary>
    [JsonPropertyName("token_type")]
    public string? TokenType { get; init; }
}

/// <summary>Pushed Authorization Request response per RFC 9126 §2.2.</summary>
public sealed record ParResponse(
    [property: JsonPropertyName("request_uri")] string RequestUri,
    [property: JsonPropertyName("expires_in")] int ExpiresIn);

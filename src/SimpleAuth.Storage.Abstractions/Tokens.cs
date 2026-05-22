namespace SimpleAuth;

/// <summary>
/// Possible outcomes when consuming an authorization code.
/// </summary>
public enum CodeConsumeStatus
{
    /// <summary>Code was valid and has been consumed successfully.</summary>
    Success,

    /// <summary>
    /// Code was already consumed by a previous request — replay/reuse attack detected.
    /// Per RFC 6749 §4.1.2 the server SHOULD revoke all tokens previously issued for this code.
    /// <see cref="CodeConsumeResult.SubjectId"/> and <see cref="CodeConsumeResult.ClientId"/> are available for revocation.
    /// </summary>
    Reused,

    /// <summary>Code was not found, was never issued, or has already expired.</summary>
    Invalid,
}

/// <summary>Result of an authorization code consume operation.</summary>
public sealed class CodeConsumeResult
{
    /// <summary>Code was not found, never issued, or expired. No revocation needed.</summary>
    public static CodeConsumeResult Invalid { get; } = new(CodeConsumeStatus.Invalid, null, null, null);

    private CodeConsumeResult(CodeConsumeStatus status, AuthorizationCode? code, string? subjectId, string? clientId)
    {
        Status = status;
        Code = code;
        SubjectId = subjectId;
        ClientId = clientId;
    }

    /// <summary>Outcome of the consume attempt.</summary>
    public CodeConsumeStatus Status { get; }

    /// <summary>The consumed authorization code. Non-null only when <see cref="Status"/> is <see cref="CodeConsumeStatus.Success"/>.</summary>
    public AuthorizationCode? Code { get; }

    /// <summary>Subject identifier from the original grant. Non-null when <see cref="Status"/> is <see cref="CodeConsumeStatus.Reused"/>.</summary>
    public string? SubjectId { get; }

    /// <summary>Client identifier from the original grant. Non-null when <see cref="Status"/> is <see cref="CodeConsumeStatus.Reused"/>.</summary>
    public string? ClientId { get; }

    /// <summary>Creates a successful consume result.</summary>
    public static CodeConsumeResult Success(AuthorizationCode code) =>
        new(CodeConsumeStatus.Success, code, null, null);

    /// <summary>Creates a reuse-detected result with subject/client for token revocation.</summary>
    public static CodeConsumeResult Reused(string subjectId, string clientId) =>
        new(CodeConsumeStatus.Reused, null, subjectId, clientId);
}

/// <summary>
/// An authorization code issued at the end of the authorize endpoint redirect.
/// Codes are single-use — consuming the same code twice revokes all tokens in the grant (RFC 9700 §2.10).
/// </summary>
public sealed class AuthorizationCode
{
    /// <summary>Opaque handle sent to the client. SHA-256 hashed before storage.</summary>
    public required string Code { get; init; }

    /// <summary>Client this code was issued to.</summary>
    public required string ClientId { get; init; }

    /// <summary>Subject (user) identifier.</summary>
    public required string SubjectId { get; init; }

    /// <summary>Redirect URI used in the original authorization request.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>SHA-256 PKCE code challenge (RFC 7636 §4.2). <c>null</c> when client does not require PKCE.</summary>
    public string? CodeChallenge { get; init; }

    /// <summary>Scopes granted at the authorization endpoint.</summary>
    public required IReadOnlyList<string> GrantedScopes { get; init; }

    /// <summary>UTC time this code was created.</summary>
    public required DateTime CreatedAt { get; init; }

    /// <summary>UTC time this code expires. Typically 5 minutes from creation.</summary>
    public required DateTime ExpiresAt { get; init; }

    /// <summary>Nonce from the authorization request, included in the ID token.</summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// Unix timestamp (seconds) of when the End-User was authenticated.
    /// Populated when the authorization request included <c>max_age</c>.
    /// OIDC Core §3.1.2.1: <c>auth_time</c> MUST appear in the ID token when <c>max_age</c> was used.
    /// </summary>
    public long? AuthTime { get; init; }

    /// <summary>
    /// Authentication Context Class Reference value to include in the ID token.
    /// Set from the first value of the <c>acr_values</c> request parameter (OIDC Core §3.1.2.1).
    /// </summary>
    public string? AcrValue { get; init; }

    /// <summary>Session identifier from the user's authentication session.</summary>
    public string? SessionId { get; init; }

    /// <summary>
    /// Claim names explicitly requested via the OIDC <c>claims</c> request parameter (§5.5)
    /// for the userinfo endpoint. Populated from <c>claims.userinfo</c> in the authorization request.
    /// Empty when the parameter was not used.
    /// </summary>
    public IReadOnlyList<string> RequestedUserInfoClaims { get; init; } = [];

    /// <summary>Whether this code has been consumed. Used for replay detection.</summary>
    public bool IsConsumed { get; init; }
}

/// <summary>
/// An opaque refresh token reference.
/// Only reference tokens are supported — JWTs as refresh tokens are not issued.
/// The <see cref="Handle"/> is SHA-256 hashed before storage.
/// </summary>
public sealed class RefreshToken
{
    /// <summary>Opaque handle. SHA-256 hashed in the store.</summary>
    public required string Handle { get; init; }

    /// <summary>Client this refresh token was issued to.</summary>
    public required string ClientId { get; init; }

    /// <summary>Subject (user) identifier.</summary>
    public required string SubjectId { get; init; }

    /// <summary>Scopes granted to this refresh token. Cannot exceed the original grant.</summary>
    public required IReadOnlyList<string> GrantedScopes { get; init; }

    /// <summary>UTC creation time.</summary>
    public required DateTime CreatedAt { get; init; }

    /// <summary>UTC absolute expiry.</summary>
    public required DateTime ExpiresAt { get; init; }

    /// <summary>Sliding lifetime extension per refresh. Null when using absolute expiration.</summary>
    public DateTime? SlidingExpiresAt { get; init; }

    /// <summary>Session identifier linked to this token family.</summary>
    public string? SessionId { get; init; }

    /// <summary>Whether this refresh token has been revoked.</summary>
    public bool IsRevoked { get; init; }

    /// <summary>Generation counter for token family (used to detect replay within a family).</summary>
    public int Generation { get; init; }

    /// <summary>
    /// JWK thumbprint (RFC 7638) of the DPoP public key bound to this refresh token.
    /// Non-null when the original grant used DPoP (RFC 9449 §10.1).
    /// On refresh, the server MUST require a DPoP proof with a matching thumbprint.
    /// </summary>
    public string? DPopJkt { get; init; }
}

/// <summary>
/// A record of an issued access token, used for revocation and introspection.
/// Stored by reference handle; the JWT itself is not persisted.
/// </summary>
public sealed class IssuedToken
{
    /// <summary>Opaque reference handle. SHA-256 hashed in the store.</summary>
    public required string Handle { get; init; }

    /// <summary>Client this token was issued to.</summary>
    public required string ClientId { get; init; }

    /// <summary>Subject identifier. Null for client credentials tokens.</summary>
    public string? SubjectId { get; init; }

    /// <summary>Granted scopes in this token.</summary>
    public required IReadOnlyList<string> GrantedScopes { get; init; }

    /// <summary>UTC creation time.</summary>
    public required DateTime CreatedAt { get; init; }

    /// <summary>UTC expiry time.</summary>
    public required DateTime ExpiresAt { get; init; }

    /// <summary>Whether this token has been revoked.</summary>
    public bool IsRevoked { get; init; }

    /// <summary>
    /// Handle of the refresh token this access token was issued alongside.
    /// Null if issued via client credentials or if no refresh token was issued.
    /// </summary>
    public string? RefreshTokenHandle { get; init; }

    /// <summary>
    /// Handle of the authorization code that caused this token to be issued.
    /// Null if issued via client credentials or refresh token grant.
    /// Used for code-reuse revocation (RFC 6749 §4.1.2): when a code is used twice,
    /// all tokens bearing this handle MUST be revoked.
    /// </summary>
    public string? AuthorizationCodeHandle { get; init; }

    /// <summary>
    /// JWK thumbprint (RFC 7638) of the DPoP public key bound to this token.
    /// Non-null only when the token was issued with a <c>DPoP</c> header (RFC 9449).
    /// When set, resource endpoints MUST require a matching DPoP proof.
    /// </summary>
    public string? JktThumbprint { get; init; }

    /// <summary>
    /// Claim names explicitly requested via the OIDC <c>claims</c> request parameter (§5.5)
    /// for the userinfo endpoint. Carried forward from the authorization code so the UserInfo
    /// endpoint can return those claims even when the corresponding scope was not requested.
    /// </summary>
    public IReadOnlyList<string> RequestedUserInfoClaims { get; init; } = [];
}

/// <summary>
/// A recorded user consent decision for a specific client and scope set.
/// Enables skipping the consent screen on repeated visits.
/// </summary>
public sealed class UserConsent
{
    /// <summary>Subject (user) identifier.</summary>
    public required string SubjectId { get; init; }

    /// <summary>Client identifier.</summary>
    public required string ClientId { get; init; }

    /// <summary>Scopes the user approved.</summary>
    public required IReadOnlyList<string> GrantedScopes { get; init; }

    /// <summary>UTC time this consent was given.</summary>
    public required DateTime CreatedAt { get; init; }

    /// <summary>UTC time this consent expires. Null means no expiry.</summary>
    public DateTime? ExpiresAt { get; init; }
}

/// <summary>
/// A pushed authorization request (RFC 9126).
/// Stores the full authorize request parameters, keyed by a short-lived <see cref="RequestUri"/>.
/// </summary>
public sealed class ParEntry
{
    /// <summary>
    /// Unique request URI in the form <c>urn:ietf:params:oauth:request-uri:{handle}</c>.
    /// Used as the lookup key; handle is not hashed (short-lived, no secret value).
    /// </summary>
    public required string RequestUri { get; init; }

    /// <summary>Client that submitted this PAR request (already authenticated).</summary>
    public required string ClientId { get; init; }

    /// <summary>Redirect URI from the PAR request.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>Space-separated scope string from the PAR request.</summary>
    public required string Scope { get; init; }

    /// <summary>PKCE code challenge (S256 is the only supported method). Null when PKCE is not used.</summary>
    public string? CodeChallenge { get; init; }

    /// <summary>PKCE code challenge method — "S256" or null when PKCE is not used.</summary>
    public string? CodeChallengeMethod { get; init; }

    /// <summary>response_type from the PAR request. Should always be "code".</summary>
    public required string ResponseType { get; init; }

    /// <summary>Optional opaque state forwarded to the redirect URI.</summary>
    public string? State { get; init; }

    /// <summary>Optional nonce bound to the ID token.</summary>
    public string? Nonce { get; init; }

    /// <summary>Optional response_mode (e.g., "query", "form_post").</summary>
    public string? ResponseMode { get; init; }

    /// <summary>UTC time this PAR entry was created.</summary>
    public required DateTime CreatedAt { get; init; }

    /// <summary>UTC time this PAR entry expires. RFC 9126 recommends ≤ 90 s.</summary>
    public required DateTime ExpiresAt { get; init; }
}

/// <summary>Metadata for a signing key managed by <c>ISigningKeyStore</c>.</summary>
public sealed class SigningKeyInfo
{
    /// <summary>
    /// Key identifier. Format: <c>{alg}-{yyyyMMddHHmmss}-{4hex}</c>
    /// (e.g., <c>ec-20260120-a3f2</c>).
    /// </summary>
    public required string KeyId { get; init; }

    /// <summary>Signing algorithm (e.g., <c>"ES256"</c>, <c>"RS256"</c>).</summary>
    public required string Algorithm { get; init; }

    /// <summary>PEM-encoded private key. Stored encrypted at rest.</summary>
    public required string PrivateKeyPem { get; init; }

    /// <summary>UTC time this key was created.</summary>
    public required DateTime CreatedAt { get; init; }

    /// <summary>UTC time after which this key should no longer sign new tokens.</summary>
    public required DateTime RetireAt { get; init; }

    /// <summary>UTC time after which this key should be removed from JWKS.</summary>
    public required DateTime RemoveAt { get; init; }

    /// <summary>Whether this key is the current (primary) signing key.</summary>
    public bool IsPrimary { get; init; }
}

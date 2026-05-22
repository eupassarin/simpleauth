using System.Security.Claims;

namespace SimpleAuth;

/// <summary>
/// Context passed to each <see cref="IClaimsEnricher"/> during token and UserInfo issuance.
/// </summary>
/// <remarks>
/// Enrichers should only add identity claims (e.g., <c>name</c>, <c>email</c>).
/// Protocol claims (<c>sub</c>, <c>iss</c>, <c>aud</c>, <c>exp</c>, <c>iat</c>, <c>scope</c>) are
/// managed exclusively by the server and are ignored if added here.
/// </remarks>
public sealed class ClaimsEnrichmentContext
{
    /// <summary>Subject (user) identifier — always present for user-bound tokens.</summary>
    public required string SubjectId { get; init; }

    /// <summary>OAuth client identifier that originated the request.</summary>
    public required string ClientId { get; init; }

    /// <summary>Scopes that were granted to this request.</summary>
    public required IReadOnlyList<string> GrantedScopes { get; init; }

    /// <summary>
    /// Claim names explicitly requested via the OIDC <c>claims</c> request parameter (§5.5).
    /// These claims SHOULD be returned in the UserInfo response even if their scope was not requested.
    /// Empty when the <c>claims</c> parameter was not used.
    /// </summary>
    public IReadOnlyList<string> RequestedClaims { get; init; } = [];

    /// <summary>
    /// Claims produced by this enrichment run.
    /// Populate this collection to include additional claims in the ID token and UserInfo response.
    /// </summary>
    public ICollection<Claim> Claims { get; } = new List<Claim>();
}

/// <summary>
/// Enriches identity claims for ID tokens and UserInfo responses.
/// </summary>
/// <remarks>
/// Register one or more implementations via the standard DI container:
/// <code>services.AddScoped&lt;IClaimsEnricher, MyProfileEnricher&gt;();</code>
/// All registered enrichers are invoked in registration order before token issuance.
/// Enrichers are <em>not</em> called for machine-to-machine (client credentials) tokens.
/// </remarks>
public interface IClaimsEnricher
{
    /// <summary>
    /// Adds identity claims to <paramref name="context"/>.<see cref="ClaimsEnrichmentContext.Claims"/>.
    /// </summary>
    ValueTask EnrichAsync(ClaimsEnrichmentContext context, CancellationToken cancellationToken = default);
}

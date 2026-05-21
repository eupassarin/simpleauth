using System.Text.Json.Serialization;
using SimpleAuth.Crypto;

namespace SimpleAuth.Serialization;

/// <summary>
/// Source-generated JSON context for all SimpleAuth HTTP response types.
/// Native AOT-safe — no reflection used at runtime.
/// </summary>
[JsonSerializable(typeof(JwksDocument))]
[JsonSerializable(typeof(DiscoveryDocument))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(UserInfoResponse))]
[JsonSerializable(typeof(IntrospectionResponse))]
[JsonSerializable(typeof(ParResponse))]
[JsonSerializable(typeof(Dictionary<string, string?>))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
internal sealed partial class AuthJsonContext : JsonSerializerContext;

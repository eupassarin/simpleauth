using System.Security.Cryptography;
using System.Text;

namespace SimpleAuth.Crypto;

/// <summary>
/// PKCE code verifier and challenge validator per RFC 7636.
/// Only <c>S256</c> is accepted — <c>plain</c> is permanently rejected.
/// </summary>
internal static class PkceValidator
{
    private const int MinVerifierLength = 43;
    private const int MaxVerifierLength = 128;

    /// <summary>
    /// Validates a PKCE code verifier against the stored challenge.
    /// Returns <see langword="true"/> only when the verifier is structurally valid
    /// and its S256 challenge matches.
    /// </summary>
    internal static bool Validate(string codeVerifier, string codeChallenge)
    {
        if (!IsVerifierValid(codeVerifier))
        {
            return false;
        }

        // challenge = BASE64URL(SHA256(ASCII(verifier))) — RFC 7636 §4.6
        Span<byte> hash = stackalloc byte[32];
        int written = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier), hash);

        if (written != 32)
        {
            return false;
        }

        // Constant-time comparison to prevent timing attacks
        string computed = Base64UrlEncode(hash);
        if (computed.Length != codeChallenge.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(computed),
            Encoding.UTF8.GetBytes(codeChallenge));
    }

    /// <summary>
    /// Validates that a <c>code_challenge_method</c> value is accepted.
    /// <c>plain</c> is always rejected per OAuth 2.1 §7.6.
    /// </summary>
    internal static bool IsMethodAllowed(string? method) =>
        string.Equals(method, "S256", StringComparison.Ordinal);

    private static bool IsVerifierValid(string verifier)
    {
        if (verifier.Length is < MinVerifierLength or > MaxVerifierLength)
        {
            return false;
        }

        // RFC 7636 §4.1: ALPHA / DIGIT / "-" / "." / "_" / "~"
        foreach (char c in verifier)
        {
            if (!IsUnreservedChar(c))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsUnreservedChar(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
            or '-' or '.' or '_' or '~';

    private static string Base64UrlEncode(ReadOnlySpan<byte> input)
    {
        // stackalloc enough for base64 of 32 bytes = 44 chars (43 without padding)
        Span<char> buffer = stackalloc char[44];
        bool ok = Convert.TryToBase64Chars(input, buffer, out int charsWritten);

        if (!ok)
        {
            return string.Empty;
        }

        // Convert standard Base64 to Base64Url and strip padding
        for (int i = 0; i < charsWritten; i++)
        {
            buffer[i] = buffer[i] switch
            {
                '+' => '-',
                '/' => '_',
                _ => buffer[i],
            };
        }

        // Strip trailing '=' padding
        while (charsWritten > 0 && buffer[charsWritten - 1] == '=')
        {
            charsWritten--;
        }

        return new string(buffer[..charsWritten]);
    }
}

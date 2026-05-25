using System.Security.Cryptography;
using System.Text;

namespace SimpleAuth.Admin;

/// <summary>Configuration for the SimpleAuth admin GUI.</summary>
public sealed class SimpleAuthGuiConfiguration
{
    /// <summary>Admin username. Default: "admin".</summary>
    public string AdminUsername { get; set; } = "admin";

    /// <summary>PBKDF2-hashed admin password.</summary>
    public string? AdminPasswordHash { get; internal set; }

    /// <summary>URL path prefix for the admin GUI. Default: "/admin".</summary>
    public string PathPrefix { get; set; } = "/admin";

    /// <summary>Cookie authentication scheme name for admin sessions.</summary>
    public string CookieScheme { get; set; } = "SimpleAuth.Admin.Cookie";

    /// <summary>Admin session cookie name.</summary>
    public string CookieName { get; set; } = ".SimpleAuth.Admin";

    /// <summary>Admin session lifetime. Default: 4 hours.</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromHours(4);

    /// <summary>Sets the admin password (hashes it with PBKDF2).</summary>
    public void SetPassword(string plainTextPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plainTextPassword);
        AdminPasswordHash = HashPassword(plainTextPassword);
    }

    /// <summary>Verifies a password against the stored hash.</summary>
    internal bool VerifyPassword(string plainTextPassword)
    {
        if (string.IsNullOrEmpty(AdminPasswordHash))
        {
            return false;
        }

        return VerifyPasswordHash(plainTextPassword, AdminPasswordHash);
    }

    private static string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations: 100_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);

        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    private static bool VerifyPasswordHash(string password, string storedHash)
    {
        string[] parts = storedHash.Split(':');
        if (parts.Length != 2)
        {
            return false;
        }

        byte[] salt = Convert.FromBase64String(parts[0]);
        byte[] expectedHash = Convert.FromBase64String(parts[1]);
        byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations: 100_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);

        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }
}

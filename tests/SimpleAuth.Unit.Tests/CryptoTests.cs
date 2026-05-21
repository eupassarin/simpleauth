using SimpleAuth.Crypto;
using Xunit;

namespace SimpleAuth;

public sealed class CryptoTests
{
    [Fact]
    public void SecretHasher_RoundTrips()
    {
        string hash = SecretHasher.Hash("super-secret-value");

        Assert.True(SecretHasher.Verify("super-secret-value", hash));
        Assert.False(SecretHasher.Verify("wrong-value", hash));
    }

    [Fact]
    public void PkceValidator_ValidatesS256Challenge()
    {
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        Assert.True(PkceValidator.IsMethodAllowed("S256"));
        Assert.True(PkceValidator.Validate(verifier, challenge));
        Assert.False(PkceValidator.IsMethodAllowed("plain"));
    }
}

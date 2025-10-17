using System.Security.Cryptography;

using NUnit.Framework;

using StringPair = System.Collections.Generic.KeyValuePair<string, string>;

namespace SecureRemotePassword.Tests; 
/// <summary>
/// <see cref="SrpServer"/> tests.
///</summary>
[TestFixture]
public class SrpUtilityTests {
    private static Dictionary<int, StringPair> Primes { get; } = new Dictionary<int, StringPair>
    {
        [1024] = new StringPair(SrpConstants.SafePrime1024, SrpConstants.Generator1024),
        [1536] = new StringPair(SrpConstants.SafePrime1536, SrpConstants.Generator1536),
        [2048] = new StringPair(SrpConstants.SafePrime2048, SrpConstants.Generator2048),
        [3072] = new StringPair(SrpConstants.SafePrime3072, SrpConstants.Generator3072),
        [4096] = new StringPair(SrpConstants.SafePrime4096, SrpConstants.Generator4096),
        [6144] = new StringPair(SrpConstants.SafePrime6144, SrpConstants.Generator6144),
        [8192] = new StringPair(SrpConstants.SafePrime8192, SrpConstants.Generator8192),
    };

    [TestCase(1024)]
    [TestCase(1536)]
    [TestCase(2048)]
    [TestCase(3072)]
    [TestCase(4096)]
    [TestCase(6144)]
    [TestCase(8192)]
    public void SrpImplementationGeneratesValidSaltAndVerifier(int bits) {
        StringPair primes = Primes[bits];
        string prime = primes.Key;
        string generator = primes.Value;

        SrpImplementationGeneratesValidSaltAndVerifier<MD5>(prime, generator);
        SrpImplementationGeneratesValidSaltAndVerifier<SHA1>(prime, generator);
        SrpImplementationGeneratesValidSaltAndVerifier<SHA256>(prime, generator);
        SrpImplementationGeneratesValidSaltAndVerifier<SHA384>(prime, generator);
        SrpImplementationGeneratesValidSaltAndVerifier<SHA512>(prime, generator);
    }

    private static void SrpImplementationGeneratesValidSaltAndVerifier<T>(string prime, string generator)
        where T : HashAlgorithm {
        // generate values
        SrpParameters parameters = SrpParameters.Create<T>(prime, generator);
        SrpClient client = new(parameters);
        string salt = client.GenerateSalt();
        string privateKey = client.DerivePrivateKey(salt, "root", "123");
        string verifier = client.DeriveVerifier(privateKey);

        // verify generated values
        Assert.That(parameters.IsValidSalt(salt), Is.True);
        Assert.That(parameters.IsValidVerifier(verifier), Is.True);
    }

    [Test]
    public void InvalidSaltAndVerifierAreReported() {
        SrpClient client = new();
        SrpServer server = new();
        SrpParameters parameters = server.Parameters;
        string salt = client.GenerateSalt();
        string privateKey = client.DerivePrivateKey(salt, "root", "123");
        string verifier = client.DeriveVerifier(privateKey);

        // valid examples
        Assert.That(parameters.IsValidSalt(salt), Is.True);
        Assert.That(parameters.IsValidVerifier(verifier), Is.True);

        // invalid examples
        Assert.That(parameters.IsValidSalt(null!), Is.False);
        Assert.That(parameters.IsValidVerifier(null!), Is.False);
        Assert.That(parameters.IsValidSalt("123"), Is.False);
        Assert.That(parameters.IsValidVerifier("123"), Is.False);
        Assert.That(parameters.IsValidSalt(salt + "01"), Is.False);
        Assert.That(parameters.IsValidVerifier(verifier + "01"), Is.False);
        Assert.That(parameters.IsValidSalt(salt[2..]), Is.False);
        Assert.That(parameters.IsValidVerifier(verifier[2..]), Is.False);
        Assert.That(parameters.IsValidSalt(salt.Replace(salt[0], 'g')), Is.False);
        Assert.That(parameters.IsValidVerifier(verifier.Replace(salt[0], 'h')), Is.False);
        Assert.That(parameters.IsValidSalt(verifier), Is.False);
        Assert.That(parameters.IsValidVerifier(salt), Is.False);
    }
}

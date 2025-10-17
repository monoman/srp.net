using System.Security.Cryptography;

using NUnit.Framework;

namespace SecureRemotePassword.Tests; 
using H = SrpParameters.SrpHashFunction;

/// <summary>
/// <see cref="SrpHash"/> tests.
/// </summary>
[TestFixture]
public class SrpHashTests {
    [Test]
    public void CreateHasherTests() {
        HashAlgorithm sha1 = SrpHash<SHA1>.CreateHasher();
        Assert.That(sha1, Is.Not.Null);

        HashAlgorithm sha256 = SrpHash<SHA256>.CreateHasher();
        Assert.That(sha256, Is.Not.Null);

        HashAlgorithm sha384 = SrpHash<SHA384>.CreateHasher();
        Assert.That(sha384, Is.Not.Null);

        HashAlgorithm sha512 = SrpHash<SHA512>.CreateHasher();
        Assert.That(sha512, Is.Not.Null);
    }

    [Test]
    public void CreateHasherByNameTests() {
        HashAlgorithm sha1 = SrpHash.CreateHasher("sha1");
        Assert.That(sha1, Is.Not.Null);

        HashAlgorithm sha256 = SrpHash.CreateHasher("sha256");
        Assert.That(sha256, Is.Not.Null);

        HashAlgorithm sha384 = SrpHash.CreateHasher("sha384");
        Assert.That(sha384, Is.Not.Null);

        HashAlgorithm sha512 = SrpHash.CreateHasher("sha512");
        Assert.That(sha512, Is.Not.Null);
    }

    [Test]
    public void SrpHashComputesValidStringHashes() {
        string[] parts = ["D4C7F8A2B32", "C11B8FBA9581EC4BA4F1B0421", string.Empty, "5642EF7355E37C0FC0443EF7", "56EA2C6B8EEB755A1C72302", "7663CAA265EF785B8FF6A9B35227A52D86633DBDFCA43"];
        string sample = string.Concat(parts);
        SrpInteger srpint = SrpInteger.FromHex(sample);

        H md5 = new SrpHash<MD5>().ComputeHash;
        SrpInteger hashmd5 = SrpInteger.FromHex("34ada39bbabfa6e663f1aad3d7814121");
        Assert.That(hashmd5, Is.EqualTo(md5(srpint.ToHex().ToUpperInvariant())));
        Assert.That(hashmd5, Is.EqualTo(md5(sample)));
        Assert.That(hashmd5, Is.EqualTo(md5(parts)));
        Assert.That(16, Is.EqualTo(new SrpHash<MD5>().HashSizeBytes));

        H sha256 = new SrpHash<SHA256>().ComputeHash;
        SrpInteger hash256 = SrpInteger.FromHex("1767fe8c94508ad3514b8332493fab5396757fe347023fc9d1fef6d26c3a70d3");
        Assert.That(hash256, Is.EqualTo(sha256(srpint.ToHex().ToUpperInvariant())));
        Assert.That(hash256, Is.EqualTo(sha256(sample)));
        Assert.That(hash256, Is.EqualTo(sha256(parts)));
        Assert.That(256 / 8, Is.EqualTo(new SrpHash<SHA256>().HashSizeBytes));

        H sha512 = new SrpHash<SHA512>().ComputeHash;
        SrpInteger hash512 = SrpInteger.FromHex("f2406fd4b33b15a6b47ff78ccac7cd80eec7944092425b640d740e7dc695fdd42f583a9b4a4b98ffa5409680181999bfe319f2a3b50ddb111e8405019a8c552a");
        Assert.That(hash512, Is.EqualTo(sha512(srpint.ToHex().ToUpperInvariant())));
        Assert.That(hash512, Is.EqualTo(sha512(sample)));
        Assert.That(hash512, Is.EqualTo(sha512(parts)));
        Assert.That(512 / 8, Is.EqualTo(new SrpHash<SHA512>().HashSizeBytes));
    }

    [Test]
    public void SrpHashComputesValidSrpIntegerHashes() {
        string[] parts = ["Hello", " ", "world!"];
        string sample = string.Concat(parts);
        SrpInteger srpint = SrpInteger.FromHex("48 65 6C 6C 6F 20 77 6F 72 6c 64 21");

        H md5 = new SrpHash<MD5>().ComputeHash;
        SrpInteger hashmd5 = SrpInteger.FromHex("86FB269D190D2C85F6E0468CECA42A20");
        Assert.That(hashmd5, Is.EqualTo(md5(srpint)));
        Assert.That(hashmd5, Is.EqualTo(md5(sample)));
        Assert.That(hashmd5, Is.EqualTo(md5(parts)));
        Assert.That(16, Is.EqualTo(new SrpHash<MD5>().HashSizeBytes));

        H sha256 = new SrpHash<SHA256>().ComputeHash;
        SrpInteger hash256 = SrpInteger.FromHex("C0535E4BE2B79FFD93291305436BF889314E4A3FAEC05ECFFCBB7DF31AD9E51A");
        Assert.That(hash256, Is.EqualTo(sha256(srpint)));
        Assert.That(hash256, Is.EqualTo(sha256(sample)));
        Assert.That(hash256, Is.EqualTo(sha256(parts)));
        Assert.That(256 / 8, Is.EqualTo(new SrpHash<SHA256>().HashSizeBytes));

        H sha512 = new SrpHash<SHA512>().ComputeHash;
        SrpInteger hash512 = SrpInteger.FromHex("F6CDE2A0F819314CDDE55FC227D8D7DAE3D28CC556222A0A8AD66D91CCAD4AAD6094F517A2182360C9AACF6A3DC323162CB6FD8CDFFEDB0FE038F55E85FFB5B6");
        Assert.That(hash512, Is.EqualTo(sha512(srpint)));
        Assert.That(hash512, Is.EqualTo(sha512(sample)));
        Assert.That(hash512, Is.EqualTo(sha512(parts)));
        Assert.That(512 / 8, Is.EqualTo(new SrpHash<SHA512>().HashSizeBytes));
    }

    [Test]
    public void SrpHashMiscTests() {
        SrpHash hash = new(() => MD5.Create());
        Assert.That(hash.AlgorithmName, Is.Not.Empty);

        SrpInteger tmp = hash.ComputeHash(null!, null!, null!);
    }
}

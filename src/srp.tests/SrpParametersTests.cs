using System.Security.Cryptography;

using NUnit.Framework;

namespace SecureRemotePassword.Tests; 
[TestFixture]
public class SrpParametersTests {
    [Test]
    public void SrpParameterDefaultsAreReasonable() {
        SrpParameters parameters = new();
        Assert.That(parameters.Prime, Is.Not.Null);
        Assert.That(parameters.Generator, Is.Not.Null);
        Assert.That(32, Is.EqualTo(parameters.HashSizeBytes));
        Assert.That(512, Is.EqualTo(parameters.PaddedLength));
    }

    [Test]
    public void SrpParametersCanUseCustomHashAlgorithm() {
        SrpParameters parameters = new(MD5.Create);
        Assert.That(parameters.Prime, Is.Not.Null);
        Assert.That(parameters.Generator, Is.Not.Null);
        Assert.That(16, Is.EqualTo(parameters.HashSizeBytes));
        Assert.That(512, Is.EqualTo(parameters.PaddedLength));
    }

    [Test]
    public void SrpParametersUsePadding() {
        SrpInteger value = SrpInteger.FromHex("1234");
        SrpParameters parameters = new(paddedLength: 10);
        Assert.That("0000001234", Is.EqualTo(parameters.Pad(value).ToHex()));
    }

    [Test]
    public void SrpParametersCanOverridePaddedLength() {
        SrpParameters parameters = SrpParameters.Create<SHA1>(SrpConstants.SafePrime1024, SrpConstants.Generator1024, 1000);
        Assert.That(1000, Is.EqualTo(parameters.PaddedLength));
        Assert.That(parameters.ToString(), Is.Not.Empty);
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Services;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xunit;
using BouncyCastleCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// Offline unit tests for the key length and hash algorithm a renewal inherits from the
/// certificate being renewed.
/// </summary>
public class RenewalKeyAndHashTests
{
    private static X509Certificate2 CreateRsaCert(int keyLength, HashAlgorithmName hashAlgorithm)
    {
        using RSA rsa = RSA.Create(keyLength);
        CertificateRequest request = new(
            "CN=renewal-test",
            rsa,
            hashAlgorithm,
            RSASignaturePadding.Pkcs1
        );
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1)
        );
    }

    private static X509Certificate2 CreateEcdsaCert(ECCurve curve, HashAlgorithmName hashAlgorithm)
    {
        using ECDsa ecdsa = ECDsa.Create(curve);
        CertificateRequest request = new("CN=renewal-test", ecdsa, hashAlgorithm);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1)
        );
    }

    private static X509Certificate2 CreateSha1SignedCert()
    {
        RsaKeyPairGenerator keyPairGenerator = new();
        keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

        X509Name subject = new("CN=renewal-test");
        X509V3CertificateGenerator certGenerator = new();
        certGenerator.SetSerialNumber(BigInteger.One);
        certGenerator.SetIssuerDN(subject);
        certGenerator.SetSubjectDN(subject);
        certGenerator.SetNotBefore(DateTimeOffset.UtcNow.AddDays(-1).UtcDateTime);
        certGenerator.SetNotAfter(DateTimeOffset.UtcNow.AddYears(1).UtcDateTime);
        certGenerator.SetPublicKey(keyPair.Public);

        BouncyCastleCertificate generated = certGenerator.Generate(
            new Asn1SignatureFactory("SHA1WITHRSA", keyPair.Private)
        );
        return X509CertificateLoader.LoadCertificate(generated.GetEncoded());
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void GetKeyLength_Returns_Rsa_Key_Length(int keyLength)
    {
        using X509Certificate2 cert = CreateRsaCert(keyLength, HashAlgorithmName.SHA256);
        Assert.Equal(keyLength, CertUtils.GetKeyLength(cert));
    }

    [Fact]
    public void GetKeyLength_Returns_Ecdsa_Key_Length()
    {
        using X509Certificate2 cert = CreateEcdsaCert(
            ECCurve.NamedCurves.nistP384,
            HashAlgorithmName.SHA384
        );
        Assert.Equal(384, CertUtils.GetKeyLength(cert));
    }

    [Theory]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void GetHashAlgorithm_Returns_Rsa_Signature_Hash(string hashName)
    {
        HashAlgorithmName hashAlgorithm = new(hashName);
        using X509Certificate2 cert = CreateRsaCert(2048, hashAlgorithm);
        Assert.Equal(hashAlgorithm, CertUtils.GetHashAlgorithm(cert));
    }

    [Theory]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void GetHashAlgorithm_Returns_Ecdsa_Signature_Hash(string hashName)
    {
        HashAlgorithmName hashAlgorithm = new(hashName);
        using X509Certificate2 cert = CreateEcdsaCert(ECCurve.NamedCurves.nistP256, hashAlgorithm);
        Assert.Equal(hashAlgorithm, CertUtils.GetHashAlgorithm(cert));
    }

    [Fact]
    public void GetHashAlgorithm_Falls_Back_To_Sha256_For_Weak_Hashes()
    {
        using X509Certificate2 cert = CreateSha1SignedCert();
        Assert.Equal(HashAlgorithmName.SHA256, CertUtils.GetHashAlgorithm(cert));
    }

    [Theory]
    [InlineData("SHA256", "1.2.840.113549.1.1.11")]
    [InlineData("SHA384", "1.2.840.113549.1.1.12")]
    [InlineData("SHA512", "1.2.840.113549.1.1.13")]
    public void CreateCSR_Uses_Requested_Key_Length_And_Hash(
        string hashName,
        string expectedSignatureOid
    )
    {
        UnifiedCertStoreService certStoreService = new(new UnifiedStoreService());
        string csrPem = certStoreService.CreateCSR(
            "CN=renewal-test",
            ["renewal-test"],
            2048,
            false,
            [],
            string.Empty,
            null,
            false,
            new HashAlgorithmName(hashName)
        );

        Pkcs10CertificationRequest csr = (Pkcs10CertificationRequest)
            new PemReader(new StringReader(csrPem)).ReadObject();
        Assert.Equal(expectedSignatureOid, csr.SignatureAlgorithm.Algorithm.Id);
        Assert.True(csr.Verify());
        Assert.Equal(2048, ((RsaKeyParameters)csr.GetPublicKey()).Modulus.BitLength);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void GetReusableRsaKeyLength_Reuses_Strong_Rsa_Keys(int keyLength)
    {
        using X509Certificate2 cert = CreateRsaCert(keyLength, HashAlgorithmName.SHA256);
        Assert.Equal(keyLength, CertUtils.GetReusableRsaKeyLength(cert));
    }

    [Fact]
    public void GetReusableRsaKeyLength_Rejects_Weak_Rsa_Keys()
    {
        using X509Certificate2 cert = CreateRsaCert(1024, HashAlgorithmName.SHA256);
        Assert.Null(CertUtils.GetReusableRsaKeyLength(cert));
    }

    [Fact]
    public void GetReusableRsaKeyLength_Rejects_Ecdsa_Keys()
    {
        // An EC key size is not an RSA key size: reusing 256 or 384 here would either fail to
        // create a key or quietly request a breakable RSA key
        using X509Certificate2 p256 = CreateEcdsaCert(
            ECCurve.NamedCurves.nistP256,
            HashAlgorithmName.SHA256
        );
        using X509Certificate2 p384 = CreateEcdsaCert(
            ECCurve.NamedCurves.nistP384,
            HashAlgorithmName.SHA384
        );
        Assert.Null(CertUtils.GetReusableRsaKeyLength(p256));
        Assert.Null(CertUtils.GetReusableRsaKeyLength(p384));
    }

    [Fact]
    public void AddPrivateKeyToCertificate_Reports_Unsupported_Key_Type()
    {
        UnifiedCertStoreService certStoreService = new(new UnifiedStoreService());
        certStoreService.CreateCSR(
            "CN=renewal-test",
            ["renewal-test"],
            256,
            false,
            [],
            string.Empty,
            null,
            false,
            HashAlgorithmName.SHA256
        );
        using X509Certificate2 issued = CreateEcdsaCert(
            ECCurve.NamedCurves.nistP256,
            HashAlgorithmName.SHA256
        );

        Assert.Throws<InvalidOperationException>(() =>
            certStoreService.AddPrivateKeyToCertificate(issued, false)
        );
    }
}

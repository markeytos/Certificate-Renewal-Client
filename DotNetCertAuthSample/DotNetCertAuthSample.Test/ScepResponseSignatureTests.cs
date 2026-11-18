using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Managers;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// Offline unit tests for the trust decision made on a SCEP response. The
/// response may be signed by the issuing CA itself or by an RA certificate the
/// server ships with the response, and in the latter case the signer only counts
/// when it chains to a certificate the GetCACert operation published.
/// </summary>
public class ScepResponseSignatureTests
{
    private static X509Certificate2 CreateRootCa(string commonName)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(
            $"CN={commonName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false)
        );
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(10)
        );
    }

    private static X509Certificate2 CreateSubordinateCa(string commonName, X509Certificate2 issuer)
    {
        RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(
            $"CN={commonName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false)
        );
        X509Certificate2 issued = request.Create(
            issuer,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5),
            RandomNumberGenerator.GetBytes(8)
        );
        return issued.CopyWithPrivateKey(rsa);
    }

    /// <summary>
    /// Creates an end entity certificate that can sign a CMS message, i.e. one
    /// that keeps its private key.
    /// </summary>
    private static X509Certificate2 CreateSigningCertificate(
        string commonName,
        X509Certificate2 issuer
    )
    {
        RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(
            $"CN={commonName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true)
        );
        X509Certificate2 issued = request.Create(
            issuer,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1),
            RandomNumberGenerator.GetBytes(8)
        );
        return issued.CopyWithPrivateKey(rsa);
    }

    /// <summary>
    /// Builds a signed response the way a SCEP server does: a CMS signed over
    /// some payload, encoded and decoded again so that only what travels on the
    /// wire is available to the verification.
    /// </summary>
    private static SignedCms CreateSignedResponse(
        X509Certificate2 signer,
        X509IncludeOption includeOption
    )
    {
        ContentInfo content = new([0x01, 0x02, 0x03, 0x04]);
        SignedCms signedCms = new(content);
        CmsSigner cmsSigner = new(signer) { IncludeOption = includeOption };
        signedCms.ComputeSignature(cmsSigner);
        SignedCms decoded = new();
        decoded.Decode(signedCms.Encode());
        return decoded;
    }

    [Fact]
    public void VerifyScepResponseSignature_SignedByPublishedIssuingCa_Succeeds()
    {
        using X509Certificate2 root = CreateRootCa("Signed By CA Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("Signed By CA Issuing CA", root);
        SignedCms response = CreateSignedResponse(issuingCa, X509IncludeOption.EndCertOnly);
        X509Certificate2Collection published = [root, issuingCa];

        CertificateManager.VerifyScepResponseSignature(response, published);
    }

    [Fact]
    public void VerifyScepResponseSignature_SignerNotSentWithResponse_Succeeds()
    {
        // The server signs with the published CA but does not ship the
        // certificate, so it can only be resolved from the GetCACert response.
        using X509Certificate2 root = CreateRootCa("Not Sent Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("Not Sent Issuing CA", root);
        SignedCms response = CreateSignedResponse(issuingCa, X509IncludeOption.None);
        X509Certificate2Collection published = [root, issuingCa];

        CertificateManager.VerifyScepResponseSignature(response, published);
    }

    [Fact]
    public void VerifyScepResponseSignature_RaSignerIssuedByPublishedCa_Succeeds()
    {
        using X509Certificate2 root = CreateRootCa("RA Signer Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("RA Signer Issuing CA", root);
        using X509Certificate2 raSigner = CreateSigningCertificate("RA Signer", issuingCa);
        SignedCms response = CreateSignedResponse(raSigner, X509IncludeOption.EndCertOnly);
        X509Certificate2Collection published = [root, issuingCa];

        CertificateManager.VerifyScepResponseSignature(response, published);
    }

    [Fact]
    public void VerifyScepResponseSignature_SignerFromAnotherPki_Throws()
    {
        // The response is correctly signed, but by a certificate that has
        // nothing to do with the CA the SCEP server published.
        using X509Certificate2 root = CreateRootCa("Foreign Signer Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("Foreign Signer Issuing CA", root);
        using X509Certificate2 rogueRoot = CreateRootCa("Rogue Root");
        using X509Certificate2 rogueSigner = CreateSigningCertificate("Rogue Signer", rogueRoot);
        SignedCms response = CreateSignedResponse(rogueSigner, X509IncludeOption.ExcludeRoot);
        X509Certificate2Collection published = [root, issuingCa];

        Exception ex = Assert.ThrowsAny<Exception>(() =>
            CertificateManager.VerifyScepResponseSignature(response, published)
        );
        Assert.Contains("does not chain to", ex.Message);
    }

    [Fact]
    public void VerifyScepResponseSignature_ImpostorCaSentWithResponse_Throws()
    {
        // A CA certificate that travels with the response must not be able to
        // vouch for itself.
        using X509Certificate2 root = CreateRootCa("Impostor Scenario Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("Impostor Scenario CA", root);
        using X509Certificate2 impostorRoot = CreateRootCa("Impostor Root");
        using X509Certificate2 impostor = CreateSubordinateCa("Impostor CA", impostorRoot);
        SignedCms response = CreateSignedResponse(impostor, X509IncludeOption.EndCertOnly);
        X509Certificate2Collection published = [root, issuingCa];

        Assert.ThrowsAny<Exception>(() =>
            CertificateManager.VerifyScepResponseSignature(response, published)
        );
    }

    [Fact]
    public void VerifyScepResponseSignature_UnsignedResponse_Throws()
    {
        using X509Certificate2 root = CreateRootCa("Unsigned Root");
        SignedCms response = new(new ContentInfo([0x01, 0x02]));
        X509Certificate2Collection published = [root];

        Exception ex = Assert.ThrowsAny<Exception>(() =>
            CertificateManager.VerifyScepResponseSignature(response, published)
        );
        Assert.Contains("not signed", ex.Message);
    }
}

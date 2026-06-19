using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DotNetCertAuthSample.Managers;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// Offline unit tests for the SCEP GetCACert response handling. The server can
/// return the CA certificate either as a single (DER or PEM) certificate or as a
/// PKCS#7 bundle containing the issuing CA together with its parent(s). These
/// tests verify both encodings are parsed and that the correct issuing CA is
/// selected out of a bundle regardless of ordering.
/// </summary>
public class ScepCaCertificateParsingTests
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
        // Keep the private key on the returned certificate so it can sign children.
        X509Certificate2 issued = request.Create(
            issuer,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5),
            RandomNumberGenerator.GetBytes(8)
        );
        return issued.CopyWithPrivateKey(rsa);
    }

    [Fact]
    public void ParseCaCertificateResponse_SingleDerCertificate_ReturnsSingleCert()
    {
        using X509Certificate2 root = CreateRootCa("Single DER Root");
        byte[] der = root.Export(X509ContentType.Cert);

        X509Certificate2Collection certs = CertificateManager.ParseCaCertificateResponse(der);

        Assert.Single(certs);
        Assert.Equal(root.Thumbprint, certs[0].Thumbprint);
    }

    [Fact]
    public void ParseCaCertificateResponse_SinglePemCertificate_ReturnsSingleCert()
    {
        using X509Certificate2 root = CreateRootCa("Single PEM Root");
        byte[] pem = Encoding.UTF8.GetBytes(root.ExportCertificatePem());

        X509Certificate2Collection certs = CertificateManager.ParseCaCertificateResponse(pem);

        Assert.Single(certs);
        Assert.Equal(root.Thumbprint, certs[0].Thumbprint);
    }

    [Fact]
    public void ParseCaCertificateResponse_Pkcs7DerBundle_ReturnsAllCerts()
    {
        using X509Certificate2 root = CreateRootCa("Bundle Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("Bundle Issuing CA", root);
        X509Certificate2Collection bundle = [issuingCa, root];
        byte[] pkcs7 = bundle.Export(X509ContentType.Pkcs7)!;

        X509Certificate2Collection certs = CertificateManager.ParseCaCertificateResponse(pkcs7);

        Assert.Equal(2, certs.Count);
    }

    [Fact]
    public void ParseCaCertificateResponse_Pkcs7PemBundle_ReturnsAllCerts()
    {
        using X509Certificate2 root = CreateRootCa("Pem Bundle Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("Pem Bundle Issuing CA", root);
        X509Certificate2Collection bundle = [issuingCa, root];
        byte[] pkcs7Der = bundle.Export(X509ContentType.Pkcs7)!;
        byte[] pkcs7Pem = Encoding.UTF8.GetBytes(PemEncoding.WriteString("PKCS7", pkcs7Der));

        X509Certificate2Collection certs = CertificateManager.ParseCaCertificateResponse(pkcs7Pem);

        Assert.Equal(2, certs.Count);
    }

    [Fact]
    public void ParseCaCertificateResponse_InvalidData_Throws()
    {
        byte[] garbage = [0x01, 0x02, 0x03, 0x04];

        Assert.ThrowsAny<Exception>(() => CertificateManager.ParseCaCertificateResponse(garbage));
    }

    [Fact]
    public void SelectIssuingCaCertificate_SingleCertificate_ReturnsThatCertificate()
    {
        using X509Certificate2 root = CreateRootCa("Lonely Root");
        X509Certificate2Collection certs = [root];

        X509Certificate2 selected = CertificateManager.SelectIssuingCaCertificate(certs);

        Assert.Equal(root.Thumbprint, selected.Thumbprint);
    }

    [Fact]
    public void SelectIssuingCaCertificate_Bundle_ReturnsIssuingCaNotRoot()
    {
        using X509Certificate2 root = CreateRootCa("Select Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("Select Issuing CA", root);
        X509Certificate2Collection certs = [issuingCa, root];

        X509Certificate2 selected = CertificateManager.SelectIssuingCaCertificate(certs);

        Assert.Equal(issuingCa.Thumbprint, selected.Thumbprint);
        Assert.NotEqual(root.Thumbprint, selected.Thumbprint);
    }

    [Fact]
    public void SelectIssuingCaCertificate_BundleRootFirst_StillReturnsIssuingCa()
    {
        using X509Certificate2 root = CreateRootCa("Order Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("Order Issuing CA", root);
        // Root listed first to prove selection does not depend on ordering.
        X509Certificate2Collection certs = [root, issuingCa];

        X509Certificate2 selected = CertificateManager.SelectIssuingCaCertificate(certs);

        Assert.Equal(issuingCa.Thumbprint, selected.Thumbprint);
    }

    [Fact]
    public void SelectIssuingCaCertificate_ThreeTierChain_ReturnsBottomMostCa()
    {
        using X509Certificate2 root = CreateRootCa("Three Tier Root");
        using X509Certificate2 intermediate = CreateSubordinateCa("Three Tier Intermediate", root);
        using X509Certificate2 issuingCa = CreateSubordinateCa("Three Tier Issuing CA", intermediate);
        X509Certificate2Collection certs = [root, intermediate, issuingCa];

        X509Certificate2 selected = CertificateManager.SelectIssuingCaCertificate(certs);

        Assert.Equal(issuingCa.Thumbprint, selected.Thumbprint);
    }

    [Fact]
    public void ParseAndSelect_Pkcs7Bundle_RoundTripsToIssuingCa()
    {
        // End-to-end of the two helpers as GetScepCA chains them: bytes -> parse -> select.
        using X509Certificate2 root = CreateRootCa("RoundTrip Root");
        using X509Certificate2 issuingCa = CreateSubordinateCa("RoundTrip Issuing CA", root);
        X509Certificate2Collection bundle = [issuingCa, root];
        byte[] pkcs7 = bundle.Export(X509ContentType.Pkcs7)!;

        X509Certificate2Collection parsed = CertificateManager.ParseCaCertificateResponse(pkcs7);
        X509Certificate2 selected = CertificateManager.SelectIssuingCaCertificate(parsed);

        Assert.Equal(issuingCa.Thumbprint, selected.Thumbprint);
    }
}

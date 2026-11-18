using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Services;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// The Linux and macOS certificate request path. It builds requests with BouncyCastle rather than
/// CertEnroll, so the Subject Alternative Name types and the SCEP challenge attribute have to be
/// covered here as well as on Windows.
/// </summary>
public class UnifiedCertStoreServiceCsrTests
{
    /// <summary>
    /// Building a request touches no store, so the tests do not need a real one.
    /// </summary>
    private sealed class UnusedStoreService : IStoreService
    {
        public X509Certificate2Collection FindCertificatesBySubject(
            string subjectName,
            bool localStore,
            string? password = null
        ) => throw new NotSupportedException();

        public X509Certificate2Collection GetAllCertificatesInStore(
            bool localStore,
            string? password = null
        ) => throw new NotSupportedException();

        public X509Certificate2Collection FindCertificatesByTemplate(
            string templateName,
            bool localStore,
            string? password = null
        ) => throw new NotSupportedException();

        public X509Certificate2Collection FindCertificatesByIssuer(
            string issuerName,
            bool localStore,
            string? password = null
        ) => throw new NotSupportedException();

        public void WriteCertificateWithPrivateKeyToStore(
            X509Certificate2 certificate,
            bool localStore,
            string? password = null
        ) => throw new NotSupportedException();
    }

    private static Pkcs10CertificationRequest BuildRequest(
        List<string> sans,
        string? challengePassword = null
    )
    {
        UnifiedCertStoreService service = new(new UnusedStoreService());
        string pem = service.CreateCSR(
            "CN=host.contoso.com",
            sans,
            2048,
            localStore: false,
            ekus: ["1.3.6.1.5.5.7.3.2"],
            challengePassword: challengePassword
        );
        return new Pkcs10CertificationRequest(
            DotNetCertAuthSample.Managers.CertificateManager.PemToDer(pem)
        );
    }

    private static GeneralNames? GetSubjectAlternativeNames(Pkcs10CertificationRequest request)
    {
        Asn1Set attributes = request.GetCertificationRequestInfo().Attributes;
        foreach (Asn1Encodable encodable in attributes)
        {
            AttributePkcs attribute = AttributePkcs.GetInstance(encodable);
            if (!attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
            {
                continue;
            }

            X509Extensions extensions = X509Extensions.GetInstance(attribute.AttrValues[0]);
            Org.BouncyCastle.Asn1.X509.X509Extension? san = extensions.GetExtension(
                X509Extensions.SubjectAlternativeName
            );
            return san == null ? null : GeneralNames.GetInstance(san.GetParsedValue());
        }

        return null;
    }

    [Fact]
    public void A_Request_Is_Signed_By_Its_Own_Key()
    {
        Assert.True(BuildRequest(["host.contoso.com"]).Verify());
    }

    [Fact]
    public void Plain_Names_Are_Still_Dns_Names()
    {
        GeneralNames? sans = GetSubjectAlternativeNames(
            BuildRequest(["host.contoso.com", "alias.contoso.com"])
        );

        Assert.NotNull(sans);
        Assert.Equal(2, sans!.GetNames().Length);
        Assert.All(sans.GetNames(), name => Assert.Equal(GeneralName.DnsName, name.TagNo));
    }

    [Fact]
    public void A_Sid_Is_Carried_As_The_Microsoft_Sid_Uri()
    {
        GeneralNames? sans = GetSubjectAlternativeNames(
            BuildRequest(["host.contoso.com", "SID=S-1-5-21-1-2-3-1000"])
        );

        GeneralName sid = Assert.Single(
            sans!.GetNames(),
            name => name.TagNo == GeneralName.UniformResourceIdentifier
        );
        Assert.Equal(
            SubjectAlternativeNameParser.SidUriPrefix + "S-1-5-21-1-2-3-1000",
            sid.Name.ToString()
        );
    }

    [Fact]
    public void A_Upn_Is_Carried_As_An_OtherName()
    {
        GeneralNames? sans = GetSubjectAlternativeNames(
            BuildRequest(["host.contoso.com", "UPN=host$@contoso.com"])
        );

        Assert.Single(sans!.GetNames(), name => name.TagNo == GeneralName.OtherName);
    }

    [Fact]
    public void An_Ip_Address_Is_Carried_As_An_Ip_Address()
    {
        GeneralNames? sans = GetSubjectAlternativeNames(
            BuildRequest(["host.contoso.com", "IP=10.0.0.5"])
        );

        Assert.Single(sans!.GetNames(), name => name.TagNo == GeneralName.IPAddress);
    }

    [Fact]
    public void The_Scep_Challenge_Is_A_Signed_Attribute_Of_The_Request()
    {
        Pkcs10CertificationRequest request = BuildRequest(
            ["host.contoso.com"],
            challengePassword: "a-static-scep-password"
        );

        Asn1Set attributes = request.GetCertificationRequestInfo().Attributes;
        AttributePkcs challenge = Assert.Single(
            attributes.Cast<Asn1Encodable>().Select(AttributePkcs.GetInstance),
            attribute => attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtChallengePassword)
        );

        Assert.Equal(
            "a-static-scep-password",
            DerPrintableString.GetInstance(challenge.AttrValues[0]).GetString()
        );
        // The challenge only means anything because the request key signed it.
        Assert.True(request.Verify());
    }

    [Fact]
    public void No_Challenge_Password_Leaves_The_Attribute_Out()
    {
        Pkcs10CertificationRequest request = BuildRequest(["host.contoso.com"]);

        Assert.DoesNotContain(
            request.GetCertificationRequestInfo().Attributes.Cast<Asn1Encodable>(),
            encodable =>
                AttributePkcs
                    .GetInstance(encodable)
                    .AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtChallengePassword)
        );
    }
}

#if WINDOWS
using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Managers;
using DotNetCertAuthSample.Services;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// The Windows CertEnroll Subject Alternative Name mapping. This is the only way to check it:
/// CertEnroll builds the ASN.1 itself, so the encoding has to be read back out of a request it
/// actually produced. In particular it settles whether InitializeFromOtherName's ToBeWrapped
/// argument makes CertEnroll add the [0] EXPLICIT tag around a UPN, or double-wraps it.
///
/// These create a real key in the current user's store, so they only run on Windows.
/// </summary>
[Collection("WindowsCertEnroll")]
public class WindowsCertEnrollSanTests
{
    private static GeneralNames BuildAndReadSans(List<string> sans)
    {
        WindowsCertService service = new(new UnifiedStoreService());
        try
        {
            return ReadSans(service, sans);
        }
        finally
        {
            // Building the request persists a key container, and nothing installs a response
            // here, so each test would otherwise leave one behind.
            service.DiscardPendingRequest();
        }
    }

    private static GeneralNames ReadSans(WindowsCertService service, List<string> sans)
    {
        string pem = service.CreateCSR(
            "CN=host.contoso.com",
            sans,
            2048,
            localStore: false,
            ekus: ["1.3.6.1.5.5.7.3.2"],
            KeyProviders.SoftwareKeyStorage
        );
        Pkcs10CertificationRequest request = new(CertificateManager.PemToDer(pem));
        Assert.True(request.Verify());

        foreach (Asn1Encodable encodable in request.GetCertificationRequestInfo().Attributes)
        {
            AttributePkcs attribute = AttributePkcs.GetInstance(encodable);
            if (!attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest))
            {
                continue;
            }

            X509Extensions extensions = X509Extensions.GetInstance(attribute.AttrValues[0]);
            Org.BouncyCastle.Asn1.X509.X509Extension subjectAltName = extensions.GetExtension(
                X509Extensions.SubjectAlternativeName
            );
            Assert.NotNull(subjectAltName);
            return GeneralNames.GetInstance(subjectAltName.GetParsedValue());
        }

        throw new InvalidOperationException("The request carried no extension request attribute.");
    }

    [Fact]
    public void A_Upn_Is_An_OtherName_Carrying_A_Single_Utf8String()
    {
        GeneralNames sans = BuildAndReadSans(["host.contoso.com", "UPN=host$@contoso.com"]);

        GeneralName upn = Assert.Single(
            sans.GetNames(),
            name => name.TagNo == GeneralName.OtherName
        );
        Asn1Sequence otherName = Asn1Sequence.GetInstance(upn.Name);
        Assert.Equal(
            SubjectAlternativeNameParser.UpnOid,
            DerObjectIdentifier.GetInstance(otherName[0]).Id
        );

        // The value must be [0] EXPLICIT UTF8String. A double wrap would put another tagged
        // object or an OCTET STRING here instead, and Windows would not read the UPN back.
        Asn1TaggedObject tagged = Asn1TaggedObject.GetInstance(otherName[1]);
        Assert.Equal(0, tagged.TagNo);
        DerUtf8String value = DerUtf8String.GetInstance(tagged.GetObject());
        Assert.Equal("host$@contoso.com", value.GetString());
    }

    [Fact]
    public void A_Sid_Is_A_Uri_Carrying_The_Microsoft_Sid_Form()
    {
        GeneralNames sans = BuildAndReadSans(
            ["host.contoso.com", "SID=S-1-5-21-1-2-3-1000"]
        );

        GeneralName sid = Assert.Single(
            sans.GetNames(),
            name => name.TagNo == GeneralName.UniformResourceIdentifier
        );
        Assert.Equal(
            SubjectAlternativeNameParser.SidUriPrefix + "S-1-5-21-1-2-3-1000",
            DerIA5String.GetInstance(sid.Name).GetString()
        );
    }

    [Fact]
    public void An_Ip_Address_Is_Four_Raw_Octets()
    {
        GeneralNames sans = BuildAndReadSans(["host.contoso.com", "IP=10.0.0.5"]);

        GeneralName ip = Assert.Single(
            sans.GetNames(),
            name => name.TagNo == GeneralName.IPAddress
        );
        Assert.Equal(
            new byte[] { 10, 0, 0, 5 },
            Asn1OctetString.GetInstance(ip.Name).GetOctets()
        );
    }

    [Fact]
    public void An_Email_Is_An_Rfc822_Name_And_Dns_Names_Still_Work()
    {
        GeneralNames sans = BuildAndReadSans(
            ["host.contoso.com", "EMAIL=device@contoso.com"]
        );

        Assert.Single(sans.GetNames(), name => name.TagNo == GeneralName.Rfc822Name);
        GeneralName dns = Assert.Single(
            sans.GetNames(),
            name => name.TagNo == GeneralName.DnsName
        );
        Assert.Equal("host.contoso.com", DerIA5String.GetInstance(dns.Name).GetString());
    }

    [Fact]
    public void The_Scep_Challenge_Is_A_Signed_Attribute_Of_The_Request()
    {
        WindowsCertService service = new(new UnifiedStoreService());
        string pem;
        try
        {
            pem = service.CreateCSR(
                "CN=host.contoso.com",
                ["host.contoso.com"],
                2048,
                localStore: false,
                ekus: ["1.3.6.1.5.5.7.3.2"],
                KeyProviders.SoftwareKeyStorage,
                challengePassword: "a-static-scep-password"
            );
        }
        finally
        {
            service.DiscardPendingRequest();
        }

        Pkcs10CertificationRequest request = new(CertificateManager.PemToDer(pem));

        AttributePkcs challenge = Assert.Single(
            request
                .GetCertificationRequestInfo()
                .Attributes.Cast<Asn1Encodable>()
                .Select(AttributePkcs.GetInstance),
            attribute => attribute.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtChallengePassword)
        );

        Assert.Equal(
            "a-static-scep-password",
            ((IAsn1String)challenge.AttrValues[0]).GetString()
        );
        Assert.True(request.Verify());
    }
}
#endif

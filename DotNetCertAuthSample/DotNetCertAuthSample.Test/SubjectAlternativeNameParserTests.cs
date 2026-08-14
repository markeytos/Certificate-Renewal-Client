using System.Net;
using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Services;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// Offline unit tests for the --SubjectAltNames parsing used by the SCEPCertificate command.
/// Names without a type prefix stay DNS names (the original behavior), while a prefix such as
/// UPN=, IP=, RFC822=, URI= or SID= requests that specific Subject Alternative Name type.
/// </summary>
public class SubjectAlternativeNameParserTests
{
    [Theory]
    [InlineData("server1.contoso.com")]
    [InlineData("DNS=server1.contoso.com")]
    [InlineData("dns=server1.contoso.com")]
    [InlineData(" DNS = server1.contoso.com ")]
    public void Parse_Returns_DnsName(string input)
    {
        GeneralName name = Assert.Single(SubjectAlternativeNameParser.Parse(input));

        Assert.Equal(GeneralName.DnsName, name.TagNo);
        Assert.Equal("server1.contoso.com", name.Name.ToString());
    }

    [Fact]
    public void Parse_Without_Prefix_Keeps_All_Names_As_Dns()
    {
        GeneralName[] names = SubjectAlternativeNameParser.Parse(
            "one.contoso.com,two.contoso.com,three.contoso.com"
        );

        Assert.Equal(
            new[] { GeneralName.DnsName, GeneralName.DnsName, GeneralName.DnsName },
            names.Select(name => name.TagNo).ToArray()
        );
        Assert.Equal(
            new[] { "one.contoso.com", "two.contoso.com", "three.contoso.com" },
            names.Select(name => name.Name.ToString()).ToArray()
        );
    }

    [Fact]
    public void Parse_Upn_Creates_OtherName_With_Upn_Oid()
    {
        GeneralName name = Assert.Single(SubjectAlternativeNameParser.Parse("UPN=aaron@keytos.io"));

        Assert.Equal(GeneralName.OtherName, name.TagNo);
        Asn1Sequence otherName = Asn1Sequence.GetInstance(name.Name);
        Assert.Equal(
            SubjectAlternativeNameParser.UpnOid,
            DerObjectIdentifier.GetInstance(otherName[0]).Id
        );
        DerUtf8String upn = DerUtf8String.GetInstance(
            Asn1TaggedObject.GetInstance(otherName[1]).GetBaseObject()
        );
        Assert.Equal("aaron@keytos.io", upn.GetString());
    }

    [Theory]
    [InlineData("IP=10.0.0.5", "10.0.0.5")]
    [InlineData("IPAddress=10.0.0.5", "10.0.0.5")]
    [InlineData("IP=2001:db8::1", "2001:db8::1")]
    public void Parse_IpAddress_Encodes_Address_Octets(string input, string expected)
    {
        GeneralName name = Assert.Single(SubjectAlternativeNameParser.Parse(input));

        Assert.Equal(GeneralName.IPAddress, name.TagNo);
        byte[] octets = ((DerOctetString)name.Name).GetOctets();
        Assert.Equal(IPAddress.Parse(expected).GetAddressBytes(), octets);
    }

    [Theory]
    [InlineData("IP=not-an-ip")]
    [InlineData("IP=10.0.0.256")]
    public void Parse_Invalid_IpAddress_Throws(string input)
    {
        Assert.Throws<ArgumentException>(() => SubjectAlternativeNameParser.Parse(input));
    }

    [Theory]
    [InlineData("RFC822=aaron@keytos.io")]
    [InlineData("Rfc822Name=aaron@keytos.io")]
    [InlineData("EMAIL=aaron@keytos.io")]
    public void Parse_Rfc822_Returns_Rfc822Name(string input)
    {
        GeneralName name = Assert.Single(SubjectAlternativeNameParser.Parse(input));

        Assert.Equal(GeneralName.Rfc822Name, name.TagNo);
        Assert.Equal("aaron@keytos.io", name.Name.ToString());
    }

    [Theory]
    [InlineData("URI=https://contoso.com/app")]
    [InlineData("URL=https://contoso.com/app")]
    public void Parse_Uri_Returns_UniformResourceIdentifier(string input)
    {
        GeneralName name = Assert.Single(SubjectAlternativeNameParser.Parse(input));

        Assert.Equal(GeneralName.UniformResourceIdentifier, name.TagNo);
        Assert.Equal("https://contoso.com/app", name.Name.ToString());
    }

    [Theory]
    [InlineData("SID=S-1-5-21-1004336348-1177238915-682003330-512")]
    [InlineData(
        "SID=tag:microsoft.com\\,2022-09-14:sid:S-1-5-21-1004336348-1177238915-682003330-512"
    )]
    [InlineData(
        "URI=tag:microsoft.com\\,2022-09-14:sid:S-1-5-21-1004336348-1177238915-682003330-512"
    )]
    public void Parse_Sid_Returns_Microsoft_Sid_Uri(string input)
    {
        GeneralName name = Assert.Single(SubjectAlternativeNameParser.Parse(input));

        Assert.Equal(GeneralName.UniformResourceIdentifier, name.TagNo);
        Assert.Equal(
            "tag:microsoft.com,2022-09-14:sid:S-1-5-21-1004336348-1177238915-682003330-512",
            name.Name.ToString()
        );
    }

    [Fact]
    public void Parse_Mixed_Types_Keeps_Order_And_Types()
    {
        GeneralName[] names = SubjectAlternativeNameParser.Parse(
            "server1.contoso.com, UPN=aaron@keytos.io ,IP=10.0.0.5,EMAIL=aaron@keytos.io,URI=https://contoso.com"
        );

        Assert.Equal(
            new[]
            {
                GeneralName.DnsName,
                GeneralName.OtherName,
                GeneralName.IPAddress,
                GeneralName.Rfc822Name,
                GeneralName.UniformResourceIdentifier,
            },
            names.Select(name => name.TagNo).ToArray()
        );
    }

    [Fact]
    public void Parse_Unknown_Type_Throws()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            SubjectAlternativeNameParser.Parse("SPN=host/server1.contoso.com")
        );

        Assert.Contains("SPN", exception.Message);
    }

    [Fact]
    public void Parse_Value_With_Equals_Sign_Is_Not_Treated_As_A_Type()
    {
        GeneralName name = Assert.Single(
            SubjectAlternativeNameParser.Parse("URI=https://contoso.com/app?key=value")
        );

        Assert.Equal(GeneralName.UniformResourceIdentifier, name.TagNo);
        Assert.Equal("https://contoso.com/app?key=value", name.Name.ToString());
    }

    [Fact]
    public void Parse_Missing_Value_Throws()
    {
        Assert.Throws<ArgumentException>(() => SubjectAlternativeNameParser.Parse("UPN="));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(",")]
    public void Parse_Empty_Input_Throws(string input)
    {
        Assert.Throws<ArgumentException>(() => SubjectAlternativeNameParser.Parse(input));
    }

    [Fact]
    public void Parsed_Names_Produce_An_Extension_DotNet_Can_Read()
    {
        GeneralNames generalNames = new(
            SubjectAlternativeNameParser.Parse(
                "server1.contoso.com,UPN=aaron@keytos.io,IP=10.0.0.5,EMAIL=aaron@keytos.io"
            )
        );

        X509SubjectAlternativeNameExtension extension = new(
            generalNames.GetDerEncoded(),
            critical: false
        );

        // The UPN is an otherName, so it must not come back as a DNS name.
        string dnsName = Assert.Single(extension.EnumerateDnsNames());
        Assert.Equal("server1.contoso.com", dnsName);
        IPAddress ipAddress = Assert.Single(extension.EnumerateIPAddresses());
        Assert.Equal(IPAddress.Parse("10.0.0.5"), ipAddress);
    }
}

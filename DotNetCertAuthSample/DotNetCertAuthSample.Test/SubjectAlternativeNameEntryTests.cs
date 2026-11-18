using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// The entry form of the parser, which is what lets the Windows CertEnroll request carry the same
/// Subject Alternative Name types the BouncyCastle request on Linux and macOS already could.
/// </summary>
public class SubjectAlternativeNameEntryTests
{
    [Fact]
    public void Entries_Without_A_Prefix_Are_Dns_Names()
    {
        List<SubjectAlternativeNameEntry> entries = SubjectAlternativeNameParser.ParseEntries(
            "server1.contoso.com,server2.contoso.com"
        );

        Assert.Equal(2, entries.Count);
        Assert.All(entries, entry => Assert.Equal(SANTypes.DNSName, entry.Type));
        Assert.Equal("server1.contoso.com", entries[0].Value);
    }

    [Fact]
    public void A_Upn_Becomes_An_OtherName_Carrying_The_Microsoft_Oid()
    {
        SubjectAlternativeNameEntry entry = Assert.Single(
            SubjectAlternativeNameParser.ParseEntries("UPN=aaron@keytos.io")
        );

        Assert.Equal(SANTypes.OtherName, entry.Type);
        Assert.Equal(SubjectAlternativeNameParser.UpnOid, entry.OtherNameOid);
        Assert.Equal("aaron@keytos.io", entry.Value);
    }

    [Fact]
    public void A_Sid_Becomes_The_Microsoft_Sid_Uri()
    {
        SubjectAlternativeNameEntry entry = Assert.Single(
            SubjectAlternativeNameParser.ParseEntries("SID=S-1-5-21-1-2-3-1000")
        );

        // This is the URI form, which is what the SID= prefix produces. It is not the whole of
        // strong mapping: a domain controller enforcing KB5014754 reads the SID out of the
        // 1.3.6.1.4.1.311.25.2 extension, which only the issuing CA can assert. A certificate
        // meant for strong mapping needs both, and the extension is the CA's to add.
        Assert.Equal(SANTypes.URI, entry.Type);
        Assert.Equal(
            SubjectAlternativeNameParser.SidUriPrefix + "S-1-5-21-1-2-3-1000",
            entry.Value
        );
    }

    [Fact]
    public void A_Sid_That_Is_Already_A_Uri_Is_Not_Prefixed_Twice()
    {
        string alreadyPrefixed = SubjectAlternativeNameParser.SidUriPrefix + "S-1-5-21-9";

        SubjectAlternativeNameEntry entry = Assert.Single(
            SubjectAlternativeNameParser.ParseEntries([alreadyPrefixed])
        );

        Assert.Equal(alreadyPrefixed, entry.Value);
    }

    [Theory]
    [InlineData("IP=10.0.0.5", 4)]
    [InlineData("IP=2001:db8::1", 16)]
    public void An_Ip_Address_Keeps_Its_Octets(string input, int expectedLength)
    {
        SubjectAlternativeNameEntry entry = Assert.Single(
            SubjectAlternativeNameParser.ParseEntries(input)
        );

        Assert.Equal(SANTypes.IPAddress, entry.Type);
        Assert.NotNull(entry.IPAddressOctets);
        Assert.Equal(expectedLength, entry.IPAddressOctets!.Length);
    }

    [Fact]
    public void An_Email_Becomes_An_Rfc822_Name()
    {
        SubjectAlternativeNameEntry entry = Assert.Single(
            SubjectAlternativeNameParser.ParseEntries("EMAIL=aaron@keytos.io")
        );

        Assert.Equal(SANTypes.Rfc822Name, entry.Type);
    }

    [Fact]
    public void Entries_Already_Split_Are_Not_Split_Again()
    {
        // The SID URI contains a comma. Splitting it a second time would cut it in half.
        string sidUri = SubjectAlternativeNameParser.SidUriPrefix + "S-1-5-21-1-2-3-1000";

        List<SubjectAlternativeNameEntry> entries = SubjectAlternativeNameParser.ParseEntries(
            ["host.contoso.com", "URI=" + sidUri]
        );

        Assert.Equal(2, entries.Count);
        Assert.Equal(sidUri, entries[1].Value);
    }

    [Fact]
    public void Split_Honors_An_Escaped_Comma()
    {
        List<string> parts = SubjectAlternativeNameParser.Split(
            @"host.contoso.com,SID=tag:microsoft.com\,2022-09-14:sid:S-1-5-21-7"
        );

        Assert.Equal(2, parts.Count);
        Assert.Equal("SID=tag:microsoft.com,2022-09-14:sid:S-1-5-21-7", parts[1]);
    }

    [Fact]
    public void Split_Then_Parse_Round_Trips_A_Value_Containing_A_Comma()
    {
        // This is the path the SCEP command now takes: split once, then hand the entries to the
        // certificate store, which parses them without splitting again.
        const string input = @"host.contoso.com,SID=S-1-5-21-1-2-3-1000,UPN=host$@contoso.com";

        List<SubjectAlternativeNameEntry> entries = SubjectAlternativeNameParser.ParseEntries(
            SubjectAlternativeNameParser.Split(input)
        );

        Assert.Equal(3, entries.Count);
        Assert.Equal(SANTypes.DNSName, entries[0].Type);
        Assert.Equal(SANTypes.URI, entries[1].Type);
        Assert.Equal(SANTypes.OtherName, entries[2].Type);
    }

    [Fact]
    public void An_Unknown_Type_Is_Rejected_By_Name()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            SubjectAlternativeNameParser.ParseEntries("SPN=host/server1.contoso.com")
        );

        Assert.Contains("SPN", exception.Message);
    }
}

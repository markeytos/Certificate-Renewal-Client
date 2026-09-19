#if WINDOWS
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Services;
using EZCAClient.Models;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// Offline unit tests for the IIS binding selection. IIS is only touched when a site
/// is named on the command line, so these cover the cases that decide whether the
/// client does anything at all.
/// </summary>
public class IISBindingMatchingTests
{
    /// <summary>
    /// No --IISSite means IIS was never asked for, so the call has to be a no-op even
    /// on a machine that does not run IIS at all.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SetIISCertificate_IsANoOpWithoutASiteName(string? siteName)
    {
        WindowsSystemInfoService service = new();
        APIResultModel result = service.SetIISCertificate(new string('A', 40), siteName);
        Assert.True(result.Success);
        Assert.Empty(result.Message);
    }

    /// <summary>
    /// renewAll calls into IIS for every renewed certificate, so a machine without IIS
    /// has to be reported as "nothing to do" rather than failing the renewal.
    /// </summary>
    [Fact]
    public void CheckIfIISCertAndRenew_IsANoOpWhenIISIsNotInstalled()
    {
        if (IsIISInstalled())
        {
            return;
        }

        WindowsSystemInfoService service = new();
        APIResultModel result = service.CheckIfIISCertAndRenew(
            new string('A', 40),
            new string('B', 40)
        );
        Assert.True(result.Success);
        Assert.Empty(result.Message);
    }

    [Fact]
    public void SetIISCertificate_ReportsWhenIISIsNotInstalled()
    {
        if (IsIISInstalled())
        {
            return;
        }

        WindowsSystemInfoService service = new();
        APIResultModel result = service.SetIISCertificate(new string('A', 40), "Default Web Site");
        Assert.False(result.Success);
        Assert.Contains("IIS is not installed", result.Message);
    }

    [Theory]
    // the name the certificate was issued for
    [InlineData("www.contoso.com", "www.contoso.com", true)]
    [InlineData("www.contoso.com", "WWW.Contoso.COM", true)]
    // a second hostname sharing the same IIS site must not be repointed at this cert
    [InlineData("www.contoso.com", "legacy.fabrikam.com", false)]
    [InlineData("www.contoso.com", "contoso.com", false)]
    // a wildcard stands in for exactly one label
    [InlineData("*.contoso.com", "www.contoso.com", true)]
    [InlineData("*.contoso.com", "a.b.contoso.com", false)]
    [InlineData("*.contoso.com", "contoso.com", false)]
    [InlineData("*.contoso.com", ".contoso.com", false)]
    [InlineData("*.contoso.com", "www.fabrikam.com", false)]
    // a suffix match is not a subdomain match
    [InlineData("*.contoso.com", "evilcontoso.com", false)]
    public void CoversHost_MatchesOnlyTheNamesTheCertificateCanServe(
        string certificateName,
        string host,
        bool expected
    )
    {
        Assert.Equal(expected, WindowsSystemInfoService.CoversHost([certificateName], host));
    }

    [Fact]
    public void CoversHost_MatchesNothingWhenTheCertificateHasNoNames()
    {
        Assert.False(WindowsSystemInfoService.CoversHost([], "www.contoso.com"));
    }

    [Fact]
    public void GetCertificateNames_ReadsTheDnsSubjectAlternativeNames()
    {
        using X509Certificate2 certificate = CreateCertificate(
            "CN=www.contoso.com",
            "www.contoso.com",
            "contoso.com"
        );

        List<string> names = WindowsSystemInfoService.GetCertificateNames(certificate);

        Assert.Equal(2, names.Count);
        Assert.Contains("www.contoso.com", names);
        Assert.Contains("contoso.com", names);
    }

    /// <summary>
    /// A certificate issued without a SAN extension still has to resolve to a name, or
    /// every binding on the site would look like someone else's.
    /// </summary>
    [Fact]
    public void GetCertificateNames_FallsBackToTheCommonName()
    {
        using X509Certificate2 certificate = CreateCertificate("CN=legacy.contoso.com");

        Assert.Equal(
            ["legacy.contoso.com"],
            WindowsSystemInfoService.GetCertificateNames(certificate)
        );
    }

    private static X509Certificate2 CreateCertificate(string subject, params string[] dnsNames)
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new(
            subject,
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
        if (dnsNames.Length > 0)
        {
            SubjectAlternativeNameBuilder sanBuilder = new();
            foreach (string dnsName in dnsNames)
            {
                sanBuilder.AddDnsName(dnsName);
            }
            request.CertificateExtensions.Add(sanBuilder.Build());
        }
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1)
        );
    }

    private static bool IsIISInstalled()
    {
        return File.Exists(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "inetsrv",
                "config",
                "applicationHost.config"
            )
        );
    }
}
#endif

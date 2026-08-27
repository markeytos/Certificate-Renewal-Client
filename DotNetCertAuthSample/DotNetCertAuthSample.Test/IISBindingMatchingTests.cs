#if WINDOWS
using DotNetCertAuthSample.Services;
using EZCAClient.Models;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// Offline unit tests for the IIS binding selection. When no site is named on the
/// command line the client only rebinds the https bindings whose host name the
/// certificate actually covers, so this matching decides which sites are touched.
/// </summary>
public class IISBindingMatchingTests
{
    [Theory]
    [InlineData("www.contoso.com", "www.contoso.com")]
    [InlineData("WWW.CONTOSO.COM", "www.contoso.com")]
    [InlineData("www.contoso.com", "WWW.CONTOSO.COM")]
    public void CertificateCoversHost_MatchesExactNameIgnoringCase(
        string certificateName,
        string host
    )
    {
        Assert.True(WindowsSystemInfoService.CertificateCoversHost([certificateName], host));
    }

    [Theory]
    [InlineData("*.contoso.com", "www.contoso.com")]
    [InlineData("*.contoso.com", "api.contoso.com")]
    public void CertificateCoversHost_MatchesSingleLabelUnderWildcard(
        string certificateName,
        string host
    )
    {
        Assert.True(WindowsSystemInfoService.CertificateCoversHost([certificateName], host));
    }

    [Theory]
    [InlineData("*.contoso.com", "a.b.contoso.com")] // wildcards only cover one label
    [InlineData("*.contoso.com", "contoso.com")]
    [InlineData("www.contoso.com", "www.fabrikam.com")]
    [InlineData("www.contoso.com", "notwww.contoso.com")]
    public void CertificateCoversHost_RejectsNamesOutsideTheCertificate(
        string certificateName,
        string host
    )
    {
        Assert.False(WindowsSystemInfoService.CertificateCoversHost([certificateName], host));
    }

    [Fact]
    public void CertificateCoversHost_MatchesAnyOfTheCertificateNames()
    {
        string[] names = ["contoso.com", "www.contoso.com", "*.dev.contoso.com"];
        Assert.True(WindowsSystemInfoService.CertificateCoversHost(names, "www.contoso.com"));
        Assert.True(WindowsSystemInfoService.CertificateCoversHost(names, "api.dev.contoso.com"));
        Assert.False(WindowsSystemInfoService.CertificateCoversHost(names, "www.fabrikam.com"));
    }

    /// <summary>
    /// A binding with no host name answers every request that reaches its ip and port,
    /// so it is never picked up by name matching. Those need an explicit --IISSite.
    /// </summary>
    [Fact]
    public void CertificateCoversHost_DoesNotMatchCatchAllBinding()
    {
        Assert.False(WindowsSystemInfoService.CertificateCoversHost(["www.contoso.com"], ""));
    }

    [Fact]
    public void CertificateCoversHost_IgnoresEmptyCertificateNames()
    {
        Assert.False(WindowsSystemInfoService.CertificateCoversHost(["", "  "], "www.contoso.com"));
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
        APIResultModel result = service.SetIISCertificate(
            new string('A', 40),
            null,
            ["www.contoso.com"]
        );
        Assert.False(result.Success);
        Assert.Contains("IIS is not installed", result.Message);
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

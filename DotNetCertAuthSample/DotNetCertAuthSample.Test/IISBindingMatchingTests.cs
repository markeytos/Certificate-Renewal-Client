#if WINDOWS
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

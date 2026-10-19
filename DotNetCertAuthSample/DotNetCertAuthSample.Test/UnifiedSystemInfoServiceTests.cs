using DotNetCertAuthSample.Services;
using EZCAClient.Models;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// IIS does not exist outside Windows, so the unified service has to report that as a
/// result instead of throwing, and stay quiet when IIS was never asked for.
/// </summary>
public class UnifiedSystemInfoServiceTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SetIISCertificate_IsANoOpWithoutASiteName(string? siteName)
    {
        UnifiedSystemInfoService service = new();
        APIResultModel result = service.SetIISCertificate(new string('A', 40), siteName);
        Assert.True(result.Success);
        Assert.Empty(result.Message);
    }

    [Fact]
    public void SetIISCertificate_ReportsThatIISIsWindowsOnly()
    {
        UnifiedSystemInfoService service = new();
        APIResultModel result = service.SetIISCertificate(new string('A', 40), "Default Web Site");
        Assert.False(result.Success);
        Assert.Contains("only available on Windows", result.Message);
    }

    [Fact]
    public void CheckIfIISCertAndRenew_IsANoOp()
    {
        UnifiedSystemInfoService service = new();
        APIResultModel result = service.CheckIfIISCertAndRenew(
            new string('A', 40),
            new string('B', 40)
        );
        Assert.True(result.Success);
        Assert.Empty(result.Message);
    }
}

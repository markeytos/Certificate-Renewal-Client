using DotNetCertAuthSample.Services;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// Offline unit tests for how long renewAll remembers a certificate it already renewed.
/// </summary>
public class RotationRecordRetentionTests
{
    private static readonly DateTime UtcNow = new(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData(10, true)]
    [InlineData(3, true)]
    [InlineData(0, true)]
    [InlineData(-6, true)]
    [InlineData(-7, false)]
    [InlineData(-8, false)]
    public void ShouldKeepRotationRecord_Keeps_Record_Until_A_Week_After_Expiry(
        int daysUntilExpiry,
        bool keep
    )
    {
        DateTime expiry = UtcNow.AddDays(daysUntilExpiry);
        Assert.Equal(keep, SettingsService.ShouldKeepRotationRecord(expiry, UtcNow));
    }
}

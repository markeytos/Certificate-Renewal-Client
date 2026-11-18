using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Managers;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// Covers the failure modes a skeptic review found in the first cut of device enrollment: a
/// subject that is not a distinguished name, a challenge URL built from the wrong segment, and the
/// state the next run needs to find its certificate.
/// </summary>
public class SubjectDistinguishedNameTests
{
    [Theory]
    [InlineData("host.contoso.com", "CN=host.contoso.com")]
    [InlineData("  host.contoso.com  ", "CN=host.contoso.com")]
    public void A_Bare_Name_Becomes_A_Distinguished_Name(string input, string expected)
    {
        // A machine with no Active Directory computer object reports a bare FQDN, and both CSR
        // builders hand the subject to a parser that rejects a value with no attribute.
        Assert.Equal(expected, CertUtils.EnsureDistinguishedName(input));
    }

    [Theory]
    [InlineData("CN=host.contoso.com")]
    [InlineData("cn=host.contoso.com")]
    [InlineData("CN =host.contoso.com")]
    [InlineData("CN=host,OU=Workstations,DC=contoso,DC=com")]
    public void An_Existing_Distinguished_Name_Is_Left_Alone(string input)
    {
        Assert.Equal(input.Trim(), CertUtils.EnsureDistinguishedName(input));
    }

    [Fact]
    public void A_Bare_Name_Now_Builds_A_Real_Request_On_The_Unified_Path()
    {
        // Before the fix this threw "badly formatted directory string" on Linux and macOS.
        UnifiedCertStoreService service = new(new NoStoreService());

        string pem = service.CreateCSR(
            CertUtils.EnsureDistinguishedName("host.contoso.com"),
            ["host.contoso.com"],
            2048,
            localStore: false,
            ekus: ["1.3.6.1.5.5.7.3.2"]
        );

        Assert.Contains("CERTIFICATE REQUEST", pem);
    }

    private sealed class NoStoreService : IStoreService
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
}

public class ChallengeUrlTests
{
    private const string Ids =
        "11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222";
    private const string ProfileId = "33333333-3333-3333-3333-333333333333";

    [Fact]
    public void The_Challenge_Replaces_The_Profile_Segment()
    {
        // The challenge belongs to the CA, one level above the profile.
        Assert.Equal(
            $"https://portal.ezca.io/api/enroll/device/{Ids}/challenge",
            DeviceEnrollmentClient
                .BuildChallengeUrl(
                    new Uri($"https://portal.ezca.io/api/enroll/device/{Ids}/{ProfileId}")
                )
                .AbsoluteUri
        );
    }

    [Fact]
    public void A_Trailing_Slash_Does_Not_Change_It()
    {
        Assert.Equal(
            $"https://portal.ezca.io/api/enroll/device/{Ids}/challenge",
            DeviceEnrollmentClient
                .BuildChallengeUrl(
                    new Uri($"https://portal.ezca.io/api/enroll/device/{Ids}/{ProfileId}/")
                )
                .AbsoluteUri
        );
    }

    [Fact]
    public void An_Address_With_A_Path_Keeps_It()
    {
        Assert.Equal(
            $"https://ezca.contoso.com/pki/api/enroll/device/{Ids}/challenge",
            DeviceEnrollmentClient
                .BuildChallengeUrl(
                    new Uri($"https://ezca.contoso.com/pki/api/enroll/device/{Ids}/{ProfileId}")
                )
                .AbsoluteUri
        );
    }

    [Fact]
    public void Upper_Case_Ids_Are_Accepted()
    {
        Assert.True(
            DeviceEnrollmentClient.IsProfileEnrollmentUrl(
                new Uri(
                    $"https://portal.ezca.io/api/enroll/device/{Ids.ToUpperInvariant()}/{ProfileId}"
                )
            )
        );
    }

    [Theory]
    [InlineData("https://portal.ezca.io/api/enroll/device/abc")]
    [InlineData(
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222"
    )]
    [InlineData("https://portal.ezca.io/")]
    // The device signs the URL and EZCA checks it against the URL it handed out, which has none
    // of these, so each would fail every enrollment.
    [InlineData(
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333?ref=portal"
    )]
    [InlineData(
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333#top"
    )]
    [InlineData(
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333//"
    )]
    [InlineData(
        "https://portal.ezca.io/api//enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333"
    )]
    [InlineData(
        "https://portal.ezca.io/api/enroll/device/{11111111-1111-1111-1111-111111111111}/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333"
    )]
    public void A_Url_Without_The_Profile_Is_Refused(string enrollmentUrl)
    {
        // An enrollment URL from before profiles existed, or a CA's own URL, would otherwise send
        // the challenge request somewhere it can't be answered.
        Assert.False(DeviceEnrollmentClient.IsProfileEnrollmentUrl(new Uri(enrollmentUrl)));
        Assert.Throws<ArgumentException>(() =>
            DeviceEnrollmentClient.BuildChallengeUrl(new Uri(enrollmentUrl))
        );
    }
}

public class EnrollmentStateTests
{
    [Fact]
    public void The_Issued_Thumbprint_Survives_A_Round_Trip()
    {
        // The next run finds its certificate by this thumbprint, because EZCA and not the client
        // chooses the subject, so there is no name the client could search for.
        string path = Path.Combine(Path.GetTempPath(), $"ezca-state-{Guid.NewGuid():N}.json");
        EnrollmentConfigService service = new();
        try
        {
            EnrollmentConfig saved = new()
            {
                Url = "https://portal.ezca.io/api/enroll/device/a/b/c",
                LastIssuedThumbprint = "AABBCCDDEEFF00112233445566778899AABBCCDD",
                LastIssuedSubject = "CN=ws123.contoso.com",
            };
            service.Save(saved, path, NullLogger.Instance);

            EnrollmentConfig loaded = service.Load(path, NullLogger.Instance);

            Assert.Equal(saved.LastIssuedThumbprint, loaded.LastIssuedThumbprint);
            Assert.Equal(saved.LastIssuedSubject, loaded.LastIssuedSubject);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

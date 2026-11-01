using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Managers;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// Covers the failure modes a skeptic review found in the first cut of device enrollment: a
/// subject that is not a distinguished name, an attestation that is not bound to its request, a
/// challenge that carries no nonce, and a plaintext enrollment URL.
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
    [Fact]
    public void The_Challenge_Segment_Is_Appended_To_The_Path()
    {
        Assert.Equal(
            "https://portal.ezca.io/api/enroll/device/abc/challenge",
            DeviceEnrollmentClient
                .BuildChallengeUrl(new Uri("https://portal.ezca.io/api/enroll/device/abc"))
                .AbsoluteUri
        );
    }

    [Fact]
    public void A_Trailing_Slash_Does_Not_Double_Up()
    {
        Assert.Equal(
            "https://portal.ezca.io/api/enroll/device/abc/challenge",
            DeviceEnrollmentClient
                .BuildChallengeUrl(new Uri("https://portal.ezca.io/api/enroll/device/abc/"))
                .AbsoluteUri
        );
    }

    [Fact]
    public void A_Query_String_Stays_A_Query_String()
    {
        // String concatenation put the appended segment behind the query, producing a path of
        // "/enroll?ca=x/challenge".
        Uri challengeUrl = DeviceEnrollmentClient.BuildChallengeUrl(
            new Uri("https://portal.ezca.io/api/enroll?ca=abc")
        );

        Assert.Equal("/api/enroll/challenge", challengeUrl.AbsolutePath);
        Assert.Equal("?ca=abc", challengeUrl.Query);
    }
}

public class KerberosChallengeRequirementTests
{
    [Fact]
    public async Task Kerberos_Attestation_Refuses_To_Run_Without_A_Challenge()
    {
        // It declares RequiresChallenge, so accepting a missing nonce would silently drop the
        // replay protection the binding exists for. Entra already refused this.
        KerberosDeviceAttestor attestor = new(NullLogger.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            attestor.AttestAsync(
                new Uri("https://portal.ezca.io/api/enroll/device/abc"),
                [1, 2, 3],
                challenge: null,
                CancellationToken.None
            )
        );
    }

    [Fact]
    public async Task Kerberos_Attestation_Refuses_An_Empty_Nonce()
    {
        KerberosDeviceAttestor attestor = new(NullLogger.Instance);
        DeviceEnrollmentChallenge emptyChallenge = new() { ChallengeId = "abc", Nonce = "" };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            attestor.AttestAsync(
                new Uri("https://portal.ezca.io/api/enroll/device/abc"),
                [1, 2, 3],
                emptyChallenge,
                CancellationToken.None
            )
        );
    }

    [Fact]
    public async Task Both_Attestations_Refuse_A_Missing_Challenge_The_Same_Way()
    {
        foreach (
            IDeviceAttestor attestor in new IDeviceAttestor[]
            {
                new KerberosDeviceAttestor(NullLogger.Instance),
                new EntraDeviceAttestor(NullLogger.Instance),
            }
        )
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                attestor.AttestAsync(
                    new Uri("https://portal.ezca.io/api/enroll/device/abc"),
                    [1, 2, 3],
                    challenge: null,
                    CancellationToken.None
                )
            );
        }
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
                Url = "https://portal.ezca.io/api/enroll/device/abc",
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

using DotNetCertAuthSample.Managers;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DotNetCertAuthSample.Test;

public class ScepUrlNormalizationTests
{
    [Theory]
    [InlineData(
        "https://portal.ezca.io/api/SCEP/PKCS7/Static/sub/ca/usa/cgi-bin",
        "https://portal.ezca.io/api/SCEP/Static/sub/ca/usa/cgi-bin"
    )]
    [InlineData(
        "https://portal.ezca.io/api/scep/pkcs7/static/sub/ca/usa/cgi-bin",
        "https://portal.ezca.io/api/SCEP/Static/sub/ca/usa/cgi-bin"
    )]
    public void Normalize_Rewrites_The_Pkcs7_Static_Endpoint(string input, string expected)
    {
        Assert.Equal(expected, CertificateManager.NormalizeScepUrl(input));
    }

    [Theory]
    [InlineData("https://portal.ezca.io/api/SCEP/Static/sub/ca/usa/cgi-bin")]
    [InlineData("https://portal.ezca.io/api/SCEP/Dynamic/sub/ca/usa/cgi-bin")]
    [InlineData("https://scep.contoso.com/cgi-bin")]
    public void Normalize_Leaves_Other_Urls_Alone(string input)
    {
        Assert.Equal(input, CertificateManager.NormalizeScepUrl(input));
    }

    [Fact]
    public void Normalize_Only_Rewrites_The_Path()
    {
        // A query string carrying the same text is not an endpoint spelling, and rewriting it
        // would corrupt the request.
        const string url =
            "https://portal.ezca.io/api/SCEP/Static/cgi-bin?next=/api/SCEP/PKCS7/Static/x";

        Assert.Equal(url, CertificateManager.NormalizeScepUrl(url));
    }

    [Fact]
    public void Normalize_Leaves_A_Host_That_Reads_Like_The_Segment_Alone()
    {
        const string url = "https://scep-pkcs7-static.contoso.com/api/SCEP/Static/cgi-bin";

        Assert.Equal(url, CertificateManager.NormalizeScepUrl(url));
    }
}

public class PemToDerTests
{
    [Fact]
    public void PemToDer_Strips_Armor_And_Line_Breaks()
    {
        byte[] expected = [1, 2, 3, 4, 5];
        string pem =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\r\n"
            + Convert.ToBase64String(expected)
            + "\r\n-----END NEW CERTIFICATE REQUEST-----\r\n";

        Assert.Equal(expected, CertificateManager.PemToDer(pem));
    }

    [Fact]
    public void A_Re_Armored_Request_Carries_The_Standard_Label_And_The_Same_Bytes()
    {
        // What is sent and what the attestation hashes have to be the same DER, and CertEnroll's
        // own "NEW CERTIFICATE REQUEST" label is not what the contract promises.
        byte[] der = Enumerable.Range(0, 64).Select(value => (byte)value).ToArray();

        string pem = CertificateManager.ToStandardCsrPem(der);

        Assert.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", pem);
        Assert.Contains("-----END CERTIFICATE REQUEST-----", pem);
        Assert.DoesNotContain("NEW CERTIFICATE REQUEST", pem);
        Assert.Equal(der, CertificateManager.PemToDer(pem));
    }

    [Fact]
    public void A_CertEnroll_Armored_Request_Round_Trips_Through_Re_Armoring()
    {
        byte[] der = [1, 2, 3, 4, 5, 6, 7, 8];
        string certEnrollArmor = string.Join(
            (char)10,
            "-----BEGIN NEW CERTIFICATE REQUEST-----",
            Convert.ToBase64String(der),
            "-----END NEW CERTIFICATE REQUEST-----"
        );

        byte[] roundTripped = CertificateManager.PemToDer(
            CertificateManager.ToStandardCsrPem(CertificateManager.PemToDer(certEnrollArmor))
        );

        Assert.Equal(der, roundTripped);
    }

    [Fact]
    public void PemToDer_Reads_A_Body_Split_Over_Several_Lines()
    {
        byte[] expected = Enumerable.Range(0, 200).Select(value => (byte)value).ToArray();
        string body = Convert.ToBase64String(expected, Base64FormattingOptions.InsertLineBreaks);
        string pem = $"-----BEGIN CERTIFICATE REQUEST-----\n{body}\n-----END CERTIFICATE REQUEST-----";

        Assert.Equal(expected, CertificateManager.PemToDer(pem));
    }
}

public class KeyProvidersTests
{
    [Fact]
    public void Device_Certificates_Default_To_The_Tpm_On_Windows_Only()
    {
        string provider = KeyProviders.DefaultForDeviceCertificate();

        if (OperatingSystem.IsWindows())
        {
            Assert.Equal(KeyProviders.PlatformCrypto, provider);
        }
        else
        {
            // Linux and macOS build the request with BouncyCastle, which has no provider name.
            Assert.Equal(string.Empty, provider);
        }
    }

    [Fact]
    public void A_Provider_The_Caller_Named_Never_Falls_Back()
    {
        Assert.Null(KeyProviders.FallbackFor(KeyProviders.PlatformCrypto, true));
    }

    [Fact]
    public void Only_The_Tpm_Default_Falls_Back()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Null(KeyProviders.FallbackFor(KeyProviders.PlatformCrypto, false));
            return;
        }

        Assert.Equal(
            KeyProviders.SoftwareKeyStorage,
            KeyProviders.FallbackFor(KeyProviders.PlatformCrypto, false)
        );
        Assert.Null(KeyProviders.FallbackFor(KeyProviders.SoftwareKeyStorage, false));
        Assert.Null(KeyProviders.FallbackFor(KeyProviders.LegacyCsp, false));
    }
}

public class EnrollmentConfigServiceTests
{
    [Fact]
    public void Config_Path_Is_Machine_Wide_For_This_Platform()
    {
        string path = new EnrollmentConfigService().ResolvePath(null);

        Assert.EndsWith("enrollment.json", path);
        if (OperatingSystem.IsWindows())
        {
            Assert.Contains("Keytos", path);
        }
        else if (OperatingSystem.IsMacOS())
        {
            Assert.StartsWith("/Library", path);
        }
        else
        {
            // The scheduled job runs as root, so the file does not belong in a user profile.
            Assert.StartsWith("/etc", path);
        }
    }

    [Fact]
    public void An_Explicit_Path_Wins_Over_The_Default()
    {
        string requested = Path.Combine(Path.GetTempPath(), "ezca-enrollment-test.json");

        Assert.Equal(
            Path.GetFullPath(requested),
            new EnrollmentConfigService().ResolvePath(requested)
        );
    }

    [Fact]
    public void Saved_Settings_Survive_A_Round_Trip()
    {
        string path = Path.Combine(
            Path.GetTempPath(),
            $"ezca-enrollment-{Guid.NewGuid():N}.json"
        );
        EnrollmentConfigService service = new();
        try
        {
            service.Save(
                new EnrollmentConfig
                {
                    Url = "https://portal.ezca.io/api/enroll/device/abc",
                    Mode = "kerberos",
                    Spn = "HTTP/enroll.ezca.io",
                },
                path,
                NullLogger.Instance
            );

            EnrollmentConfig loaded = service.Load(path, NullLogger.Instance);

            Assert.Equal("https://portal.ezca.io/api/enroll/device/abc", loaded.Url);
            Assert.Equal("kerberos", loaded.Mode);
            Assert.Equal("HTTP/enroll.ezca.io", loaded.Spn);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void A_Missing_File_Reads_As_Empty_Rather_Than_Throwing()
    {
        EnrollmentConfig loaded = new EnrollmentConfigService().Load(
            Path.Combine(Path.GetTempPath(), $"ezca-missing-{Guid.NewGuid():N}.json"),
            NullLogger.Instance
        );

        Assert.Null(loaded.Url);
    }

    [Fact]
    public void Command_Line_Arguments_Win_Over_The_Saved_Configuration()
    {
        EnrollArgModel values = new()
        {
            Url = "https://from-command-line.example.com",
            Mode = AttestationMode.Entra,
            Spn = "HTTP/from-command-line",
        };

        EnrollmentConfigService.ApplyTo(
            values,
            new EnrollmentConfig
            {
                Url = "https://from-file.example.com",
                Mode = "kerberos",
                Spn = "HTTP/from-file",
            }
        );

        Assert.Equal("https://from-command-line.example.com", values.Url);
        Assert.Equal(AttestationMode.Entra, values.Mode);
        Assert.Equal("HTTP/from-command-line", values.Spn);
    }

    [Fact]
    public void The_Saved_Configuration_Fills_In_What_Was_Not_Passed()
    {
        EnrollArgModel values = new();

        EnrollmentConfigService.ApplyTo(
            values,
            new EnrollmentConfig
            {
                Url = "https://from-file.example.com",
                Mode = "kerberos",
                Spn = "HTTP/from-file",
            }
        );

        Assert.Equal("https://from-file.example.com", values.Url);
        Assert.Equal(AttestationMode.Kerberos, values.Mode);
        Assert.Equal("HTTP/from-file", values.Spn);
    }

    [Fact]
    public void An_Unreadable_Mode_In_The_File_Leaves_Auto_Alone()
    {
        EnrollArgModel values = new();

        EnrollmentConfigService.ApplyTo(values, new EnrollmentConfig { Mode = "smartcard" });

        Assert.Equal(AttestationMode.Auto, values.Mode);
    }
}

public class DeviceAttestorTests
{
    [Fact]
    public void Both_Attestations_Need_A_Challenge_From_The_Server()
    {
        // The challenge is what stops a captured attestation being redeemed a second time, so
        // neither attestor is allowed to skip it.
        Assert.True(new KerberosDeviceAttestor(NullLogger.Instance).RequiresChallenge);
        Assert.True(new EntraDeviceAttestor(NullLogger.Instance).RequiresChallenge);
    }

    [Fact]
    public async Task Entra_Attestation_Refuses_To_Run_Without_A_Challenge()
    {
        EntraDeviceAttestor attestor = new(NullLogger.Instance);

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
    public void An_Unavailable_Attestation_Explains_Itself()
    {
        // Whichever of these is unavailable on the machine running the tests, the reason has to be
        // something an administrator reading a scheduled task log can act on.
        foreach (
            IDeviceAttestor attestor in new IDeviceAttestor[]
            {
                new KerberosDeviceAttestor(NullLogger.Instance),
                new EntraDeviceAttestor(NullLogger.Instance),
            }
        )
        {
            bool isAvailable = attestor.IsAvailable(out string reason);

            // Exactly one of these has to hold whatever this machine is, so the test asserts on
            // every run rather than quietly passing on a machine where both are available.
            Assert.True(
                isAvailable ^ !string.IsNullOrWhiteSpace(reason),
                $"{attestor.Name} returned availability {isAvailable} with reason '{reason}'"
            );
        }
    }

    [Fact]
    public void Entra_Attestation_Is_Never_Offered_Off_Windows()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Assert.False(new EntraDeviceAttestor(NullLogger.Instance).IsAvailable(out string reason));
        Assert.Contains("Entra", reason);
    }
}

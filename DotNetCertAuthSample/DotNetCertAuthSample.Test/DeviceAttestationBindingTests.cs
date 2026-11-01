using System.Security.Cryptography;
using System.Text;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// The bytes both attestations sign. A server verifies a signature over exactly these, so the
/// layout is a wire format: these tests pin it down byte for byte rather than only checking that
/// it changes when the inputs change.
/// </summary>
public class DeviceAttestationBindingTests
{
    private static readonly Uri EnrollmentUrl = new(
        "https://portal.ezca.io/api/enroll/device/abc"
    );

    private static DeviceEnrollmentChallenge Challenge(
        string challengeId = "01HQ",
        string nonce = "AAECAw=="
    )
    {
        return new DeviceEnrollmentChallenge { ChallengeId = challengeId, Nonce = nonce };
    }

    private static byte[] Expected(
        string scheme,
        Uri url,
        DeviceEnrollmentChallenge challenge,
        byte[] csrDer
    )
    {
        using MemoryStream expected = new();
        foreach (
            byte[] field in new[]
            {
                Encoding.UTF8.GetBytes(DeviceAttestationBinding.Context),
                Encoding.UTF8.GetBytes(scheme),
                Encoding.UTF8.GetBytes(url.AbsoluteUri),
                Encoding.UTF8.GetBytes(challenge.ChallengeId),
                Convert.FromBase64String(challenge.Nonce),
                SHA256.HashData(csrDer),
            }
        )
        {
            // Little-endian length, independent of the machine running the test.
            expected.Write(
                [
                    (byte)(field.Length & 0xFF),
                    (byte)((field.Length >> 8) & 0xFF),
                    (byte)((field.Length >> 16) & 0xFF),
                    (byte)((field.Length >> 24) & 0xFF),
                ]
            );
            expected.Write(field);
        }

        return expected.ToArray();
    }

    [Fact]
    public void The_Context_String_Is_The_Documented_One()
    {
        // Written out rather than read from the code under test: this value is the agreement with
        // the server, so a rename has to break a test rather than quietly ship.
        Assert.Equal("EZCA-DEVICE-ENROLL-v1", DeviceAttestationBinding.Context);
    }

    [Fact]
    public void The_Binding_Is_Exactly_The_Documented_Byte_Layout()
    {
        byte[] csrDer = [9, 8, 7];
        DeviceEnrollmentChallenge challenge = Challenge();

        byte[] binding = DeviceAttestationBinding.Build(
            "Negotiate",
            EnrollmentUrl,
            challenge,
            csrDer
        );

        Assert.Equal(Expected("Negotiate", EnrollmentUrl, challenge, csrDer), binding);
    }

    [Fact]
    public void The_Length_Prefix_Is_Little_Endian()
    {
        // The context string is the first field, so its length prefix is the first four bytes.
        byte[] binding = DeviceAttestationBinding.Build(
            "Negotiate",
            EnrollmentUrl,
            Challenge(),
            [1]
        );

        Assert.Equal((byte)DeviceAttestationBinding.Context.Length, binding[0]);
        Assert.Equal(0, binding[1]);
        Assert.Equal(0, binding[2]);
        Assert.Equal(0, binding[3]);
    }

    [Fact]
    public void The_Two_Attestation_Schemes_Produce_Different_Bytes()
    {
        // Without this a MIC made for Kerberos would be a valid signature input for Entra.
        byte[] csrDer = [1, 2, 3];
        DeviceEnrollmentChallenge challenge = Challenge();

        Assert.NotEqual(
            DeviceAttestationBinding.Build("Negotiate", EnrollmentUrl, challenge, csrDer),
            DeviceAttestationBinding.Build("EntraDevice", EnrollmentUrl, challenge, csrDer)
        );
    }

    [Fact]
    public void A_Different_Enrollment_Url_Produces_Different_Bytes()
    {
        byte[] csrDer = [1, 2, 3];
        DeviceEnrollmentChallenge challenge = Challenge();

        Assert.NotEqual(
            DeviceAttestationBinding.Build("Negotiate", EnrollmentUrl, challenge, csrDer),
            DeviceAttestationBinding.Build(
                "Negotiate",
                new Uri("https://evil.example.com/api/enroll/device/abc"),
                challenge,
                csrDer
            )
        );
    }

    [Fact]
    public void Fields_Cannot_Be_Shifted_Between_Each_Other()
    {
        // The length prefixes exist so that moving a character from one field to the next cannot
        // produce the same byte string.
        byte[] csrDer = [1];

        Assert.NotEqual(
            DeviceAttestationBinding.Build(
                "Negotiate",
                EnrollmentUrl,
                Challenge(challengeId: "AB", nonce: "AAEC"),
                csrDer
            ),
            DeviceAttestationBinding.Build(
                "Negotiate",
                EnrollmentUrl,
                Challenge(challengeId: "A", nonce: "QgABAg=="),
                csrDer
            )
        );
    }

    [Fact]
    public void A_Different_Csr_Produces_Different_Bytes()
    {
        DeviceEnrollmentChallenge challenge = Challenge();

        Assert.NotEqual(
            DeviceAttestationBinding.Build("Negotiate", EnrollmentUrl, challenge, [1, 2, 3]),
            DeviceAttestationBinding.Build("Negotiate", EnrollmentUrl, challenge, [1, 2, 4])
        );
    }

    [Theory]
    [InlineData("", "AAECAw==")]
    [InlineData("   ", "AAECAw==")]
    [InlineData("01HQ", "")]
    [InlineData("01HQ", "   ")]
    public void A_Challenge_Missing_Either_Half_Is_Refused(string challengeId, string nonce)
    {
        Assert.Throws<ArgumentException>(() =>
            DeviceAttestationBinding.Build(
                "Negotiate",
                EnrollmentUrl,
                Challenge(challengeId, nonce),
                [1]
            )
        );
    }
}

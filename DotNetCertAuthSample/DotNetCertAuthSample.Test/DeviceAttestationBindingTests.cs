using System.Security.Cryptography;
using System.Text;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// The bytes the device signs. EZCA verifies a signature over exactly these, so the
/// layout is a wire format: these tests pin it down byte for byte rather than only checking that
/// it changes when the inputs change.
/// </summary>
public class DeviceAttestationBindingTests
{
    private static readonly Uri EnrollmentUrl = new(
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/"
            + "22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333"
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
            "EntraDevice",
            EnrollmentUrl,
            challenge,
            csrDer
        );

        Assert.Equal(Expected("EntraDevice", EnrollmentUrl, challenge, csrDer), binding);
    }

    [Fact]
    public void The_Length_Prefix_Is_Little_Endian()
    {
        // The context string is the first field, so its length prefix is the first four bytes.
        byte[] binding = DeviceAttestationBinding.Build(
            "EntraDevice",
            EnrollmentUrl,
            Challenge(),
            [1]
        );

        Assert.Equal((byte)DeviceAttestationBinding.Context.Length, binding[0]);
        Assert.Equal(0, binding[1]);
        Assert.Equal(0, binding[2]);
        Assert.Equal(0, binding[3]);
    }

    // EZCA writes the URL it checks the signature against with a lower-case host, no default
    // port and no trailing slash, and also tries it with one trailing slash. This pins the
    // client's spelling to that literally, rather than through Uri.AbsoluteUri again.
    [Theory]
    [InlineData(
        "HTTPS://Portal.EZCA.io:443/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333",
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333"
    )]
    [InlineData(
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333/",
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333/"
    )]
    [InlineData(
        "https://ezca.contoso.com:8443/pki/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333",
        "https://ezca.contoso.com:8443/pki/api/enroll/device/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333"
    )]
    public void The_Url_Is_Signed_The_Way_EZCA_Spells_It(string configured, string signed)
    {
        byte[] binding = DeviceAttestationBinding.Build(
            "EntraDevice",
            new Uri(configured),
            Challenge(),
            [1]
        );

        Assert.Equal(signed, Encoding.UTF8.GetString(ReadField(binding, 2)));
    }

    // The fields are counted from zero: the context string is field 0.
    private static byte[] ReadField(byte[] binding, int index)
    {
        int offset = 0;
        for (int field = 0; ; field++)
        {
            int length =
                binding[offset]
                | (binding[offset + 1] << 8)
                | (binding[offset + 2] << 16)
                | (binding[offset + 3] << 24);
            offset += 4;
            if (field == index)
            {
                return binding[offset..(offset + length)];
            }

            offset += length;
        }
    }

    [Fact]
    public void The_Scheme_Is_Bound()
    {
        // So a signature made for this scheme can't be presented under another one.
        byte[] csrDer = [1, 2, 3];
        DeviceEnrollmentChallenge challenge = Challenge();

        Assert.NotEqual(
            DeviceAttestationBinding.Build("EntraDevice", EnrollmentUrl, challenge, csrDer),
            DeviceAttestationBinding.Build("OtherScheme", EnrollmentUrl, challenge, csrDer)
        );
    }

    [Fact]
    public void A_Different_Enrollment_Url_Produces_Different_Bytes()
    {
        byte[] csrDer = [1, 2, 3];
        DeviceEnrollmentChallenge challenge = Challenge();

        Assert.NotEqual(
            DeviceAttestationBinding.Build("EntraDevice", EnrollmentUrl, challenge, csrDer),
            DeviceAttestationBinding.Build(
                "EntraDevice",
                new Uri("https://evil.example.com/api/enroll/device/a/b/c"),
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
                "EntraDevice",
                EnrollmentUrl,
                Challenge(challengeId: "AB", nonce: "AAEC"),
                csrDer
            ),
            DeviceAttestationBinding.Build(
                "EntraDevice",
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
            DeviceAttestationBinding.Build("EntraDevice", EnrollmentUrl, challenge, [1, 2, 3]),
            DeviceAttestationBinding.Build("EntraDevice", EnrollmentUrl, challenge, [1, 2, 4])
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
                "EntraDevice",
                EnrollmentUrl,
                Challenge(challengeId, nonce),
                [1]
            )
        );
    }
}

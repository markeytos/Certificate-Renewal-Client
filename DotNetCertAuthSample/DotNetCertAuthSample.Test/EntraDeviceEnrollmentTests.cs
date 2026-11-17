using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// What the Entra attestation sends: the device registration certificate itself as the
/// credential, and a signature with its key over the binding for this enrollment.
/// </summary>
public class EntraDeviceAttestorSigningTests
{
    private const string DeviceId = "8c2f1d4e-5a6b-4c7d-8e9f-0a1b2c3d4e5f";

    private static readonly Uri EnrollmentUrl = new(
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/"
            + "22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333"
    );

    private static X509Certificate2 CreateDeviceCertificate(RSA key, string commonName)
    {
        CertificateRequest request = new(
            "CN=" + commonName,
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1)
        );
    }

    [Fact]
    public async Task The_Credential_Is_The_Device_Certificate_And_The_Binding_Is_Signed_With_Its_Key()
    {
        using RSA deviceKey = RSA.Create(2048);
        using X509Certificate2 deviceCertificate = CreateDeviceCertificate(deviceKey, DeviceId);
        EntraDeviceAttestor attestor = new(
            NullLogger.Instance,
            () => CreateDeviceCertificate(deviceKey, DeviceId)
        );
        DeviceEnrollmentChallenge challenge = new()
        {
            ChallengeId = Guid.NewGuid().ToString(),
            Nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        };
        byte[] csrDer = [1, 2, 3, 4];

        DeviceAttestationResult attestation = await attestor.AttestAsync(
            EnrollmentUrl,
            csrDer,
            challenge,
            CancellationToken.None
        );

        Assert.Equal("EntraDevice", attestation.Scheme);
        X509Certificate2 sent = X509CertificateLoader.LoadCertificate(
            Convert.FromBase64String(attestation.Token)
        );
        using (sent)
        {
            Assert.Equal(
                deviceCertificate.PublicKey.EncodedKeyValue.RawData,
                sent.PublicKey.EncodedKeyValue.RawData
            );
            Assert.Equal(DeviceId, sent.GetNameInfo(X509NameType.SimpleName, false));
        }

        Assert.Equal(DeviceId, attestation.DeviceId);
        byte[] binding = DeviceAttestationBinding.Build(
            "EntraDevice",
            EnrollmentUrl,
            challenge,
            csrDer
        );
        Assert.True(
            deviceKey.VerifyData(
                binding,
                Convert.FromBase64String(attestation.RequestBinding),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            )
        );
    }

    [Fact]
    public async Task The_Device_Id_Is_Spelled_One_Way()
    {
        using RSA deviceKey = RSA.Create(2048);
        EntraDeviceAttestor attestor = new(
            NullLogger.Instance,
            () => CreateDeviceCertificate(deviceKey, DeviceId.ToUpperInvariant())
        );

        DeviceAttestationResult attestation = await attestor.AttestAsync(
            EnrollmentUrl,
            [1],
            new DeviceEnrollmentChallenge { ChallengeId = "c", Nonce = "AAEC" },
            CancellationToken.None
        );

        Assert.Equal(DeviceId, attestation.DeviceId);
    }

    [Fact]
    public async Task A_Certificate_That_Names_No_Device_Is_Refused()
    {
        using RSA deviceKey = RSA.Create(2048);
        EntraDeviceAttestor attestor = new(
            NullLogger.Instance,
            () => CreateDeviceCertificate(deviceKey, "not-a-device")
        );

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            attestor.AttestAsync(
                EnrollmentUrl,
                [1],
                new DeviceEnrollmentChallenge { ChallengeId = "c", Nonce = "AAEC" },
                CancellationToken.None
            )
        );
    }
}

/// <summary>
/// The exchange with EZCA: a challenge from the CA's URL, the post to the profile's URL, and
/// another attempt with a fresh challenge when EZCA is busy or can't reach Entra ID.
/// </summary>
public class DeviceEnrollmentClientTests
{
    private const string CaUrl =
        "https://portal.ezca.io/api/enroll/device/11111111-1111-1111-1111-111111111111/"
        + "22222222-2222-2222-2222-222222222222";

    private static readonly Uri EnrollmentUrl = new(
        CaUrl + "/33333333-3333-3333-3333-333333333333"
    );

    private sealed class FakeAttestor : IDeviceAttestor
    {
        public List<string> ChallengeIds { get; } = [];

        public string Name => "fake";

        public bool IsAvailable(out string reason)
        {
            reason = string.Empty;
            return true;
        }

        public Task<DeviceAttestationResult> AttestAsync(
            Uri enrollmentUrl,
            byte[] csrDer,
            DeviceEnrollmentChallenge challenge,
            CancellationToken cancellationToken
        )
        {
            ChallengeIds.Add(challenge.ChallengeId);
            return Task.FromResult(
                new DeviceAttestationResult
                {
                    Scheme = "EntraDevice",
                    Token = "Q0VSVA==",
                    RequestBinding = "U0lH",
                    DeviceId = "device",
                }
            );
        }
    }

    private sealed class ScriptedHandler(
        Queue<Func<HttpRequestMessage, HttpResponseMessage>> script
    ) : HttpMessageHandler
    {
        public List<(
            HttpMethod Method,
            Uri Uri,
            AuthenticationHeaderValue? Authorization,
            string Body
        )> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken
        )
        {
            string body =
                request.Content == null
                    ? string.Empty
                    : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add(
                (request.Method, request.RequestUri!, request.Headers.Authorization, body)
            );
            return script.Dequeue()(request);
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, object value)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(value),
                Encoding.UTF8,
                "application/json"
            ),
        };
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> Challenge(string id)
    {
        return _ => Json(HttpStatusCode.OK, new { challengeId = id, nonce = "AAECAw==" });
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> Status(
        HttpStatusCode status,
        TimeSpan? retryAfter = null
    )
    {
        return _ =>
        {
            HttpResponseMessage response = Json(
                status,
                new { error = "x", message = "Error [E1]: answered " + (int)status }
            );
            if (retryAfter != null)
            {
                response.Headers.RetryAfter = new RetryConditionHeaderValue(retryAfter.Value);
            }

            return response;
        };
    }

    private static Func<HttpRequestMessage, HttpResponseMessage> Issued()
    {
        return _ =>
            Json(
                HttpStatusCode.OK,
                new { certificate = "-----BEGIN CERTIFICATE-----", attestationSource = "entra" }
            );
    }

    private static (
        DeviceEnrollmentClient Client,
        ScriptedHandler Handler,
        List<TimeSpan> Waits
    ) Build(params Func<HttpRequestMessage, HttpResponseMessage>[] script)
    {
        ScriptedHandler handler = new(
            new Queue<Func<HttpRequestMessage, HttpResponseMessage>>(script)
        );
        List<TimeSpan> waits = [];
        DeviceEnrollmentClient client = new(
            new HttpClient(handler),
            NullLogger.Instance,
            (delay, _) =>
            {
                waits.Add(delay);
                return Task.CompletedTask;
            }
        );
        return (client, handler, waits);
    }

    [Fact]
    public async Task The_Challenge_Comes_From_The_CA_And_The_Request_Goes_To_The_Profile()
    {
        (DeviceEnrollmentClient client, ScriptedHandler handler, _) = Build(
            Challenge("c1"),
            Issued()
        );

        DeviceEnrollmentResponse response = await client.EnrollAsync(
            EnrollmentUrl,
            new FakeAttestor(),
            [1],
            "CSR",
            "ws1"
        );

        Assert.Equal("entra", response.AttestationSource);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
        Assert.Equal(CaUrl + "/challenge", handler.Requests[0].Uri.AbsoluteUri);
        Assert.Equal(HttpMethod.Post, handler.Requests[1].Method);
        Assert.Equal(EnrollmentUrl, handler.Requests[1].Uri);
        Assert.Equal("EntraDevice", handler.Requests[1].Authorization?.Scheme);
        Assert.Equal("Q0VSVA==", handler.Requests[1].Authorization?.Parameter);
        using JsonDocument posted = JsonDocument.Parse(handler.Requests[1].Body);
        Assert.Equal("c1", posted.RootElement.GetProperty("challengeId").GetString());
        Assert.Equal("U0lH", posted.RootElement.GetProperty("requestBinding").GetString());
        Assert.Equal("CSR", posted.RootElement.GetProperty("csr").GetString());
    }

    [Fact]
    public async Task A_Busy_Answer_Is_Retried_With_A_New_Challenge()
    {
        FakeAttestor attestor = new();
        (DeviceEnrollmentClient client, _, List<TimeSpan> waits) = Build(
            Challenge("c1"),
            Status(HttpStatusCode.TooManyRequests),
            Challenge("c2"),
            Issued()
        );

        await client.EnrollAsync(EnrollmentUrl, attestor, [1], "CSR", null);

        // EZCA spends a challenge as soon as a request names it, so the retry needs a new one.
        Assert.Equal(["c1", "c2"], attestor.ChallengeIds);
        Assert.Single(waits);
    }

    [Fact]
    public async Task A_Busy_Challenge_Endpoint_Is_Retried()
    {
        FakeAttestor attestor = new();
        (DeviceEnrollmentClient client, _, List<TimeSpan> waits) = Build(
            Status(HttpStatusCode.TooManyRequests),
            Challenge("c1"),
            Issued()
        );

        await client.EnrollAsync(EnrollmentUrl, attestor, [1], "CSR", null);

        Assert.Equal(["c1"], attestor.ChallengeIds);
        Assert.Single(waits);
    }

    [Fact]
    public async Task Retry_After_Is_Honored_Up_To_The_Cap()
    {
        (DeviceEnrollmentClient client, _, List<TimeSpan> waits) = Build(
            Challenge("c1"),
            Status(HttpStatusCode.TooManyRequests, TimeSpan.FromSeconds(7)),
            Challenge("c2"),
            Status(HttpStatusCode.TooManyRequests, TimeSpan.FromHours(1)),
            Challenge("c3"),
            Issued()
        );

        await client.EnrollAsync(EnrollmentUrl, new FakeAttestor(), [1], "CSR", null);

        Assert.Equal([TimeSpan.FromSeconds(7), DeviceEnrollmentClient.MaxRetryDelay], waits);
    }

    [Fact]
    public async Task It_Gives_Up_After_The_Last_Attempt_And_Says_Why()
    {
        (DeviceEnrollmentClient client, ScriptedHandler handler, List<TimeSpan> waits) = Build(
            Challenge("c1"),
            Status(HttpStatusCode.TooManyRequests),
            Challenge("c2"),
            Status(HttpStatusCode.TooManyRequests),
            Challenge("c3"),
            Status(HttpStatusCode.TooManyRequests)
        );

        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () =>
                client.EnrollAsync(EnrollmentUrl, new FakeAttestor(), [1], "CSR", null)
        );

        Assert.Equal(DeviceEnrollmentClient.MaxAttempts * 2, handler.Requests.Count);
        Assert.Equal(DeviceEnrollmentClient.MaxAttempts - 1, waits.Count);
        Assert.Contains("429", failure.Message);
        Assert.Contains("Error [E1]", failure.Message);
    }

    [Fact]
    public async Task Entra_ID_Being_Unreachable_Is_Left_To_The_Next_Run()
    {
        // EZCA turns the device away for several minutes after a 503, so retrying a minute later
        // would only replace the real error with a 429.
        (DeviceEnrollmentClient client, ScriptedHandler handler, List<TimeSpan> waits) = Build(
            Challenge("c1"),
            Status(HttpStatusCode.ServiceUnavailable)
        );

        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () =>
                client.EnrollAsync(EnrollmentUrl, new FakeAttestor(), [1], "CSR", null)
        );

        Assert.Equal(2, handler.Requests.Count);
        Assert.Empty(waits);
        Assert.Contains("503", failure.Message);
        Assert.Contains("next scheduled run", failure.Message);
    }

    [Fact]
    public async Task A_Refusal_Is_Not_Retried()
    {
        (DeviceEnrollmentClient client, ScriptedHandler handler, List<TimeSpan> waits) = Build(
            Challenge("c1"),
            Status(HttpStatusCode.Forbidden)
        );

        await Assert.ThrowsAsync<EnrollmentForbiddenException>(() =>
            client.EnrollAsync(EnrollmentUrl, new FakeAttestor(), [1], "CSR", null)
        );

        Assert.Equal(2, handler.Requests.Count);
        Assert.Empty(waits);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "dsregcmd")]
    [InlineData(HttpStatusCode.NotFound, "Keytos portal")]
    public async Task A_Credential_Or_Url_Problem_Names_The_Fix(HttpStatusCode status, string hint)
    {
        (DeviceEnrollmentClient client, _, List<TimeSpan> waits) = Build(
            Challenge("c1"),
            Status(status)
        );

        InvalidOperationException failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () =>
                client.EnrollAsync(EnrollmentUrl, new FakeAttestor(), [1], "CSR", null)
        );

        Assert.Contains(hint, failure.Message);
        Assert.Empty(waits);
    }

    [Fact]
    public async Task A_Url_Without_The_Profile_Is_Refused_Before_Anything_Is_Sent()
    {
        (DeviceEnrollmentClient client, ScriptedHandler handler, _) = Build();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.EnrollAsync(new Uri(CaUrl), new FakeAttestor(), [1], "CSR", null)
        );

        Assert.Empty(handler.Requests);
    }
}

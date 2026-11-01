using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using DotNetCertAuthSample.Models;
using Microsoft.Extensions.Logging;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Raised when the enrollment endpoint issued a certificate for a request that carried no proof
/// this machine produced it. It is its own type so that trying a different attestation, which is
/// the right answer to a credential this machine cannot produce, is not the answer to this.
/// </summary>
public class UnboundEnrollmentResponseException(string message) : Exception(message) { }

/// <summary>
/// Raised when EZCA authenticated the machine and then refused to issue to it. This is a decision
/// about the identity that was proved, not a problem with proving it, so it must not be retried
/// with a different credential: doing so would let a machine removed from the allowed Active
/// Directory group enrol anyway through its Entra identity.
/// </summary>
public class EnrollmentForbiddenException(string message) : Exception(message) { }

/// <summary>
/// Talks to the EZCA device enrollment endpoint: fetches a challenge, attests, and posts the CSR.
/// The certificate that comes back is issued against the attested identity, so nothing this client
/// puts in the CSR subject decides what the certificate says.
/// </summary>
public class DeviceEnrollmentClient(HttpClient httpClient, ILogger logger)
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public async Task<DeviceEnrollmentResponse> EnrollAsync(
        Uri enrollmentUrl,
        IDeviceAttestor attestor,
        byte[] csrDer,
        string csrPem,
        string? clientReportedName,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(enrollmentUrl);
        ArgumentNullException.ThrowIfNull(attestor);

        DeviceEnrollmentChallenge? challenge = attestor.RequiresChallenge
            ? await GetChallengeAsync(enrollmentUrl, cancellationToken)
            : null;

        using DeviceAttestationResult attestation = await attestor.AttestAsync(
            enrollmentUrl,
            csrDer,
            challenge,
            cancellationToken
        );

        DeviceEnrollmentRequest request = new()
        {
            Csr = csrPem,
            ChallengeId = challenge?.ChallengeId,
            RequestBinding = attestation.RequestBinding,
            DeviceId = attestation.DeviceId,
            ClientReportedName = clientReportedName,
        };

        HttpResponseMessage response = await PostAsync(
            enrollmentUrl,
            request,
            attestation,
            cancellationToken
        );

        // A multi leg handshake answers the first post with a challenge of its own.
        if (
            response.StatusCode == HttpStatusCode.Unauthorized
            && attestation.Continue != null
            && TryGetServerToken(response, attestation.Scheme, out string serverToken)
        )
        {
            logger.LogInformation("Continuing the authentication handshake with the enrollment endpoint");
            using DeviceAttestationResult next = attestation.Continue(serverToken);
            request.RequestBinding = next.RequestBinding;
            response.Dispose();
            response = await PostAsync(enrollmentUrl, request, next, cancellationToken);
        }

        using (response)
        {
            string body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                throw new EnrollmentForbiddenException(
                    DescribeFailure(response.StatusCode, body)
                );
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(DescribeFailure(response.StatusCode, body));
            }

            // A server that issues against an attestation we never bound to this certificate
            // request is not one we can trust the answer from, so a success without a binding is
            // refused here rather than installed.
            if (attestor.RequiresChallenge && string.IsNullOrWhiteSpace(request.RequestBinding))
            {
                throw new UnboundEnrollmentResponseException(
                    "The enrollment endpoint issued a certificate for a request that carried no "
                        + "proof this machine produced it. The certificate was not installed."
                );
            }

            DeviceEnrollmentResponse? enrollment = JsonSerializer.Deserialize<DeviceEnrollmentResponse>(
                body,
                SerializerOptions
            );
            if (enrollment == null || string.IsNullOrWhiteSpace(enrollment.Certificate))
            {
                throw new InvalidOperationException(
                    "The enrollment endpoint returned no certificate."
                );
            }

            return enrollment;
        }
    }

    private async Task<DeviceEnrollmentChallenge> GetChallengeAsync(
        Uri enrollmentUrl,
        CancellationToken cancellationToken
    )
    {
        Uri challengeUrl = BuildChallengeUrl(enrollmentUrl);
        using HttpResponseMessage response = await httpClient.GetAsync(
            challengeUrl,
            cancellationToken
        );
        string body = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Could not get an enrollment challenge from {challengeUrl}: "
                    + DescribeFailure(response.StatusCode, body)
            );
        }

        DeviceEnrollmentChallenge? challenge = JsonSerializer.Deserialize<DeviceEnrollmentChallenge>(
            body,
            SerializerOptions
        );
        if (
            challenge == null
            || string.IsNullOrWhiteSpace(challenge.ChallengeId)
            || string.IsNullOrWhiteSpace(challenge.Nonce)
        )
        {
            throw new InvalidOperationException(
                $"{challengeUrl} did not return a usable enrollment challenge. Without a nonce "
                    + "there is nothing tying an attestation to this enrollment."
            );
        }

        if (!IsBase64(challenge.Nonce))
        {
            throw new InvalidOperationException(
                $"{challengeUrl} returned a nonce that is not base64."
            );
        }

        return challenge;
    }

    /// <summary>
    /// Appends the challenge segment to the enrollment path, keeping any query string, which
    /// string concatenation would have pushed behind the appended segment.
    /// </summary>
    internal static Uri BuildChallengeUrl(Uri enrollmentUrl)
    {
        ArgumentNullException.ThrowIfNull(enrollmentUrl);
        UriBuilder challengeUrl = new(enrollmentUrl)
        {
            Path = enrollmentUrl.AbsolutePath.TrimEnd('/') + "/challenge",
        };
        return challengeUrl.Uri;
    }

    private static bool IsBase64(string value)
    {
        return Convert.TryFromBase64String(value, new byte[value.Length], out _);
    }

    private async Task<HttpResponseMessage> PostAsync(
        Uri enrollmentUrl,
        DeviceEnrollmentRequest request,
        DeviceAttestationResult attestation,
        CancellationToken cancellationToken
    )
    {
        using HttpRequestMessage message = new(HttpMethod.Post, enrollmentUrl)
        {
            Content = JsonContent.Create(request),
        };
        message.Headers.Authorization = new AuthenticationHeaderValue(
            attestation.Scheme,
            attestation.Token
        );
        return await httpClient.SendAsync(message, cancellationToken);
    }

    private static bool TryGetServerToken(
        HttpResponseMessage response,
        string scheme,
        out string token
    )
    {
        foreach (AuthenticationHeaderValue header in response.Headers.WwwAuthenticate)
        {
            if (
                header.Scheme.Equals(scheme, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(header.Parameter)
            )
            {
                token = header.Parameter;
                return true;
            }
        }

        token = string.Empty;
        return false;
    }

    /// <summary>
    /// Turns a failed enrollment into something an administrator reading a scheduled task log can
    /// act on, since the usual causes each need a different fix.
    /// </summary>
    private static string DescribeFailure(HttpStatusCode statusCode, string body)
    {
        string detail = body;
        try
        {
            DeviceEnrollmentError? error = JsonSerializer.Deserialize<DeviceEnrollmentError>(
                body,
                SerializerOptions
            );
            if (!string.IsNullOrWhiteSpace(error?.Message))
            {
                detail = error.Message!;
            }
        }
        catch (JsonException)
        {
            // Not every error body is ours; fall back to what was sent.
        }

        string hint = statusCode switch
        {
            HttpStatusCode.Unauthorized =>
                " EZCA did not accept this machine's credential. Check that the enrollment account's "
                + "key in EZCA is current, since it has to be rotated, and that this machine's clock "
                + "is within five minutes of the domain's.",
            HttpStatusCode.Forbidden =>
                " This machine authenticated but is not allowed to enroll. Check that its computer "
                + "object is in the group the enrollment policy allows.",
            HttpStatusCode.NotFound =>
                " Check that the enrollment URL is the one from the Keytos portal.",
            _ => string.Empty,
        };

        return $"{(int)statusCode} {statusCode}: {detail}{hint}";
    }
}

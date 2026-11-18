using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using DotNetCertAuthSample.Models;
using Microsoft.Extensions.Logging;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Raised when EZCA proved who the device is and then refused to issue to it, for example because
/// the device is disabled or not in a group the profile allows. Retrying does not change that
/// answer, so it is reported as it is.
/// </summary>
public class EnrollmentForbiddenException(string message) : Exception(message) { }

/// <summary>
/// Talks to the EZCA device enrollment endpoint: fetches a challenge, attests, and posts the CSR.
/// The certificate that comes back is issued against the attested identity, so nothing this client
/// puts in the CSR subject decides what the certificate says.
/// </summary>
public class DeviceEnrollmentClient
{
    /// <summary>
    /// Attempts per enrollment when EZCA answers that it is receiving too many requests (429).
    /// Each attempt starts with a new challenge, since EZCA spends a challenge as soon as a request
    /// names it. A 503 (EZCA couldn't reach Entra ID) is not retried here: EZCA then turns the
    /// device away for several minutes, so an attempt a minute later would only get a 429 that
    /// hides the original error. The next scheduled run tries again.
    /// </summary>
    internal const int MaxAttempts = 3;

    /// <summary>The longest this client waits between attempts, whatever EZCA asks for.</summary>
    internal static readonly TimeSpan MaxRetryDelay = TimeSpan.FromMinutes(5);

    private static readonly TimeSpan DefaultRetryDelay = TimeSpan.FromSeconds(60);

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public DeviceEnrollmentClient(HttpClient httpClient, ILogger logger)
        : this(httpClient, logger, null) { }

    /// <param name="delay">How to wait between attempts. Defaults to Task.Delay; tests pass their own.</param>
    public DeviceEnrollmentClient(
        HttpClient httpClient,
        ILogger logger,
        Func<TimeSpan, CancellationToken, Task>? delay
    )
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(logger);
        _httpClient = httpClient;
        _logger = logger;
        _delay = delay ?? Task.Delay;
    }

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
        ArgumentNullException.ThrowIfNull(csrDer);
        Uri challengeUrl = BuildChallengeUrl(enrollmentUrl);

        for (int attempt = 1; ; attempt++)
        {
            using HttpResponseMessage challengeResponse = await _httpClient.GetAsync(
                challengeUrl,
                cancellationToken
            );
            string challengeBody = await challengeResponse.Content.ReadAsStringAsync(
                cancellationToken
            );
            if (await WaitIfTransientAsync(challengeResponse, attempt, cancellationToken))
            {
                continue;
            }

            DeviceEnrollmentChallenge challenge = ReadChallenge(
                challengeUrl,
                challengeResponse,
                challengeBody
            );
            DeviceAttestationResult attestation = await attestor.AttestAsync(
                enrollmentUrl,
                csrDer,
                challenge,
                cancellationToken
            );
            if (string.IsNullOrWhiteSpace(attestation.RequestBinding))
            {
                throw new InvalidOperationException(
                    "The attestation carried no proof that this device produced the certificate "
                        + "request, so it was not sent."
                );
            }

            DeviceEnrollmentRequest request = new()
            {
                Csr = csrPem,
                ChallengeId = challenge.ChallengeId,
                RequestBinding = attestation.RequestBinding,
                DeviceId = attestation.DeviceId,
                ClientReportedName = clientReportedName,
            };
            using HttpResponseMessage response = await PostAsync(
                enrollmentUrl,
                request,
                attestation,
                cancellationToken
            );
            string body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (await WaitIfTransientAsync(response, attempt, cancellationToken))
            {
                continue;
            }

            if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                throw new EnrollmentForbiddenException(DescribeFailure(response.StatusCode, body));
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(DescribeFailure(response.StatusCode, body));
            }

            DeviceEnrollmentResponse? enrollment =
                JsonSerializer.Deserialize<DeviceEnrollmentResponse>(body, SerializerOptions);
            if (enrollment == null || string.IsNullOrWhiteSpace(enrollment.Certificate))
            {
                throw new InvalidOperationException(
                    "The enrollment endpoint returned no certificate."
                );
            }

            return enrollment;
        }
    }

    /// <summary>
    /// The challenge belongs to the certificate authority, not the profile: the profile's
    /// enrollment URL is <c>.../{tenant}/{ca}/{profile}</c> and its challenge is
    /// <c>.../{tenant}/{ca}/challenge</c>. The profile segment is replaced rather than appended
    /// to.
    /// </summary>
    internal static Uri BuildChallengeUrl(Uri enrollmentUrl)
    {
        ArgumentNullException.ThrowIfNull(enrollmentUrl);
        if (!IsProfileEnrollmentUrl(enrollmentUrl))
        {
            throw new ArgumentException(
                $"'{enrollmentUrl}' is not an Entra profile's enrollment URL. Copy the enrollment "
                    + "URL the Keytos portal shows for the profile; it ends in the tenant, CA and "
                    + "profile IDs.",
                nameof(enrollmentUrl)
            );
        }

        string path = enrollmentUrl.AbsolutePath.TrimEnd('/');
        UriBuilder challengeUrl = new(enrollmentUrl)
        {
            Path = path[..path.LastIndexOf('/')] + "/challenge",
        };
        return challengeUrl.Uri;
    }

    /// <summary>
    /// Whether the URL is an Entra profile's enrollment URL as the portal shows it: it ends in the
    /// tenant, CA and profile IDs, with at most one trailing slash, and carries no query string or
    /// fragment. Anything before the IDs is the address EZCA is reached at, which may carry a
    /// path. The device signs the URL, and EZCA checks the signature against the URL it handed
    /// out, so any other spelling would fail on every enrollment.
    /// </summary>
    public static bool IsProfileEnrollmentUrl(Uri enrollmentUrl)
    {
        ArgumentNullException.ThrowIfNull(enrollmentUrl);
        if (
            !enrollmentUrl.IsAbsoluteUri
            || !string.IsNullOrEmpty(enrollmentUrl.Query)
            || !string.IsNullOrEmpty(enrollmentUrl.Fragment)
        )
        {
            return false;
        }

        string path = enrollmentUrl.AbsolutePath;
        if (path.EndsWith('/'))
        {
            path = path[..^1];
        }

        string[] segments = path.Split('/');
        // The first segment is the empty one before the leading slash.
        return segments.Length >= 4
            && segments[1..].All(segment => segment.Length > 0)
            && segments[^3..].All(segment => Guid.TryParseExact(segment, "D", out _));
    }

    private static DeviceEnrollmentChallenge ReadChallenge(
        Uri challengeUrl,
        HttpResponseMessage response,
        string body
    )
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Could not get an enrollment challenge from {challengeUrl}: "
                    + DescribeFailure(response.StatusCode, body)
            );
        }

        DeviceEnrollmentChallenge? challenge;
        try
        {
            challenge = JsonSerializer.Deserialize<DeviceEnrollmentChallenge>(
                body,
                SerializerOptions
            );
        }
        catch (JsonException)
        {
            challenge = null;
        }

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
    /// Waits before the next attempt when EZCA answered 429 and attempts are left, and says
    /// whether it did. The last attempt's answer is left for the caller to report.
    /// </summary>
    private async Task<bool> WaitIfTransientAsync(
        HttpResponseMessage response,
        int attempt,
        CancellationToken cancellationToken
    )
    {
        if (response.StatusCode != HttpStatusCode.TooManyRequests || attempt >= MaxAttempts)
        {
            return false;
        }

        TimeSpan delay = ReadRetryDelay(response, attempt);
        _logger.LogWarning(
            "EZCA answered {StatusCode}; trying again in {DelaySeconds} seconds (attempt {Attempt} of {MaxAttempts})",
            (int)response.StatusCode,
            (int)delay.TotalSeconds,
            attempt + 1,
            MaxAttempts
        );
        await _delay(delay, cancellationToken);
        return true;
    }

    /// <summary>
    /// Retry-After when EZCA sends one, otherwise a minute per attempt so far, never more than
    /// <see cref="MaxRetryDelay"/>.
    /// </summary>
    internal static TimeSpan ReadRetryDelay(HttpResponseMessage response, int attempt)
    {
        TimeSpan delay = DefaultRetryDelay * attempt;
        RetryConditionHeaderValue? retryAfter = response.Headers.RetryAfter;
        if (retryAfter?.Delta is TimeSpan retryDelta)
        {
            delay = retryDelta;
        }
        else if (retryAfter?.Date is DateTimeOffset retryAt)
        {
            delay = retryAt - DateTimeOffset.UtcNow;
        }

        if (delay < TimeSpan.Zero)
        {
            delay = TimeSpan.Zero;
        }

        return delay > MaxRetryDelay ? MaxRetryDelay : delay;
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
        return await _httpClient.SendAsync(message, cancellationToken);
    }

    /// <summary>
    /// Turns a failed enrollment into something an administrator reading a scheduled task log can
    /// act on, since the usual causes each need a different fix.
    /// </summary>
    internal static string DescribeFailure(HttpStatusCode statusCode, string body)
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
                " EZCA did not accept this device's Entra registration. Run 'dsregcmd /status' to "
                    + "check that the device is Entra joined or hybrid joined to the tenant the CA "
                    + "belongs to, and that this command runs as SYSTEM.",
            HttpStatusCode.Forbidden =>
                " This device proved who it is but EZCA won't issue to it. The message says why: "
                    + "usually the device is disabled in Entra ID or outside the profile's groups, "
                    + "but the CA's subscription or its IP restrictions can refuse it too.",
            HttpStatusCode.NotFound =>
                " Check that the enrollment URL is the one the Keytos portal shows for the profile, "
                    + "and that the profile is enabled.",
            HttpStatusCode.TooManyRequests =>
                " EZCA is receiving too many requests, or Entra ID didn't vouch for this device a "
                    + "few minutes ago; the next scheduled run will try again.",
            HttpStatusCode.ServiceUnavailable =>
                " EZCA couldn't check this device with Entra ID just now; the next scheduled run "
                    + "will try again.",
            _ => string.Empty,
        };

        return $"{(int)statusCode} {statusCode}: {detail}{hint}";
    }
}

using System.Text.Json.Serialization;

namespace DotNetCertAuthSample.Models;

/// <summary>
/// The nonce EZCA hands out before an enrollment. It ties one attestation to one request so a
/// captured attestation cannot be redeemed a second time.
/// </summary>
public class DeviceEnrollmentChallenge
{
    [JsonPropertyName("challengeId")]
    public string ChallengeId { get; set; } = string.Empty;

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;
}

/// <summary>
/// What the client posts to the EZCA device enrollment endpoint. The attestation itself travels in
/// the Authorization header; this is the part of the request the attestation is bound to.
/// </summary>
public class DeviceEnrollmentRequest
{
    [JsonPropertyName("csr")]
    public string Csr { get; set; } = string.Empty;

    [JsonPropertyName("challengeId")]
    public string? ChallengeId { get; set; }

    /// <summary>
    /// Proof that the machine that produced the attestation is the one that produced this CSR,
    /// computed over the challenge nonce and the CSR. Kerberos uses a MAC under the Kerberos
    /// session key; Entra uses a signature from the device registration key.
    /// </summary>
    [JsonPropertyName("requestBinding")]
    public string? RequestBinding { get; set; }

    /// <summary>
    /// Only set for Entra attestation, where the identity is not carried by the Authorization
    /// token itself.
    /// </summary>
    [JsonPropertyName("deviceId")]
    public string? DeviceId { get; set; }

    /// <summary>
    /// What the client believes its own name is. EZCA uses it for diagnostics only: the subject
    /// and SANs of the issued certificate come from the attested identity, never from here.
    /// </summary>
    [JsonPropertyName("clientReportedName")]
    public string? ClientReportedName { get; set; }
}

public class DeviceEnrollmentResponse
{
    /// <summary>The issued certificate, PEM encoded.</summary>
    [JsonPropertyName("certificate")]
    public string Certificate { get; set; } = string.Empty;

    /// <summary>The subject EZCA chose from the attested identity.</summary>
    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    /// <summary>Which attestation EZCA accepted, echoed back so the log records it.</summary>
    [JsonPropertyName("attestationSource")]
    public string? AttestationSource { get; set; }
}

public class DeviceEnrollmentError
{
    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }
}

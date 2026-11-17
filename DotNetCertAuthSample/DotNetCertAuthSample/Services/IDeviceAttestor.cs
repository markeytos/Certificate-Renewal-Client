using DotNetCertAuthSample.Models;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Proves to EZCA which device is asking for a certificate, using a credential the device already
/// has rather than a secret an administrator had to distribute.
/// </summary>
public interface IDeviceAttestor
{
    /// <summary>Name of this attestation, as it appears in logs.</summary>
    string Name { get; }

    /// <summary>
    /// Whether this device can produce this attestation at all. <paramref name="reason"/>
    /// explains a false, and is what the user sees.
    /// </summary>
    bool IsAvailable(out string reason);

    /// <summary>
    /// Produces the attestation for one enrollment. The enrollment URL, the challenge and
    /// <paramref name="csrDer"/> are bound into it, so the result cannot be replayed against a
    /// different request, certificate authority or profile.
    /// </summary>
    Task<DeviceAttestationResult> AttestAsync(
        Uri enrollmentUrl,
        byte[] csrDer,
        DeviceEnrollmentChallenge challenge,
        CancellationToken cancellationToken
    );
}

public class DeviceAttestationResult
{
    /// <summary>Authorization scheme, for example EntraDevice.</summary>
    public string Scheme { get; init; } = string.Empty;

    /// <summary>Authorization parameter, base64 encoded.</summary>
    public string Token { get; init; } = string.Empty;

    /// <summary>
    /// Proof that the attested device produced this CSR for this enrollment. Travels in the
    /// request body rather than the header because it covers the body.
    /// </summary>
    public string RequestBinding { get; init; } = string.Empty;

    /// <summary>
    /// The device ID the attestation names. EZCA reads the identity from the token and only
    /// checks this against it.
    /// </summary>
    public string? DeviceId { get; init; }
}

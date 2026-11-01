using DotNetCertAuthSample.Models;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Proves to EZCA which machine is asking for a certificate, using a credential the machine
/// already has rather than a secret an administrator had to distribute.
/// </summary>
public interface IDeviceAttestor
{
    /// <summary>Name of this attestation, as it appears in the Authorization header and in logs.</summary>
    string Name { get; }

    /// <summary>
    /// Whether this machine can produce this attestation at all. <paramref name="reason"/>
    /// explains a false, and is what the user sees when nothing is available.
    /// </summary>
    bool IsAvailable(out string reason);

    /// <summary>
    /// Produces the attestation for one enrollment. <paramref name="csrDer"/> and the challenge
    /// nonce are bound into it, so the result cannot be replayed against a different request.
    /// </summary>
    Task<DeviceAttestationResult> AttestAsync(
        Uri enrollmentUrl,
        byte[] csrDer,
        DeviceEnrollmentChallenge? challenge,
        CancellationToken cancellationToken
    );

    /// <summary>
    /// Whether this attestation needs a challenge from the server before it can be produced.
    /// </summary>
    bool RequiresChallenge { get; }
}

public class DeviceAttestationResult : IDisposable
{
    /// <summary>
    /// A security context the attestation holds open for the length of the exchange, because
    /// <see cref="Continue"/> and the request binding both need it after this object is built.
    /// </summary>
    public IDisposable? Disposable { get; init; }

    public void Dispose()
    {
        Disposable?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>Authorization scheme, for example Negotiate.</summary>
    public string Scheme { get; init; } = string.Empty;

    /// <summary>Authorization parameter, base64 encoded.</summary>
    public string Token { get; init; } = string.Empty;

    /// <summary>
    /// Proof that the attested machine produced this CSR. Travels in the request body rather than
    /// the header because it covers the body.
    /// </summary>
    public string? RequestBinding { get; init; }

    /// <summary>Set only by attestations that do not carry the identity inside the token.</summary>
    public string? DeviceId { get; init; }

    /// <summary>
    /// Called with the server's challenge blob when the server answers 401 and wants another leg
    /// of the handshake. Throws when the handshake cannot continue.
    /// </summary>
    public Func<string, DeviceAttestationResult>? Continue { get; init; }
}

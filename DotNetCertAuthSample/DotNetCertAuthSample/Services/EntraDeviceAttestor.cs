using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Models;
using Microsoft.Extensions.Logging;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Proves the machine's identity with the key behind its Entra device registration certificate.
/// A device that is Entra joined or hybrid joined holds that key in its TPM and Entra holds the
/// matching public key against the device object, so EZCA can check the signature without the
/// machine ever having been given a secret.
/// </summary>
public class EntraDeviceAttestor(ILogger logger) : IDeviceAttestor
{
    public const string AuthenticationScheme = "EntraDevice";

    /// <summary>
    /// Issuer of the certificate the device registration service leaves in the machine store.
    /// </summary>
    public const string DeviceCertificateIssuer = "MS-Organization-Access";

    public string Name => "entra";

    public bool RequiresChallenge => true;

    public bool IsAvailable(out string reason)
    {
        if (!OperatingSystem.IsWindows())
        {
            reason =
                "Entra device attestation needs the device registration certificate Windows "
                + "creates when a machine is Entra joined or hybrid joined";
            return false;
        }

        if (FindDeviceCertificate() == null)
        {
            reason =
                "this machine has no Entra device registration certificate, so it is not Entra "
                + "joined or hybrid joined. Run 'dsregcmd /status' to check its join state";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    public Task<DeviceAttestationResult> AttestAsync(
        Uri enrollmentUrl,
        byte[] csrDer,
        DeviceEnrollmentChallenge? challenge,
        CancellationToken cancellationToken
    )
    {
        ArgumentNullException.ThrowIfNull(csrDer);
        if (challenge == null || string.IsNullOrWhiteSpace(challenge.Nonce))
        {
            throw new InvalidOperationException(
                "Entra device attestation needs a challenge from the enrollment endpoint."
            );
        }

        using X509Certificate2 deviceCertificate =
            FindDeviceCertificate()
            ?? throw new InvalidOperationException(
                "This machine has no Entra device registration certificate."
            );

        string deviceId = GetDeviceId(deviceCertificate);
        logger.LogInformation("Attesting as Entra device {DeviceId}", deviceId);

        using RSA? privateKey = deviceCertificate.GetRSAPrivateKey();
        if (privateKey == null)
        {
            throw new InvalidOperationException(
                "The Entra device registration certificate has no usable private key. This "
                    + "command has to run as SYSTEM or as an administrator to reach it."
            );
        }

        byte[] signed = DeviceAttestationBinding.Build(
            AuthenticationScheme,
            enrollmentUrl,
            challenge,
            csrDer
        );
        byte[] signature = privateKey.SignData(
            signed,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        return Task.FromResult(
            new DeviceAttestationResult
            {
                Scheme = AuthenticationScheme,
                // The token names the device; the signature in the body is what proves it.
                Token = Convert.ToBase64String(
                    System.Text.Encoding.UTF8.GetBytes(deviceId)
                ),
                RequestBinding = Convert.ToBase64String(signature),
                DeviceId = deviceId,
            }
        );
    }

    /// <summary>
    /// The device registration certificate carries the Entra device id as its common name.
    /// </summary>
    private static string GetDeviceId(X509Certificate2 deviceCertificate)
    {
        string commonName = deviceCertificate.GetNameInfo(X509NameType.SimpleName, false);
        if (string.IsNullOrWhiteSpace(commonName))
        {
            throw new InvalidOperationException(
                "Could not read the device id from the Entra device registration certificate."
            );
        }

        return commonName;
    }

    private X509Certificate2? FindDeviceCertificate()
    {
        try
        {
            using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            return store
                .Certificates.Where(certificate =>
                    certificate.Issuer.Contains(
                        DeviceCertificateIssuer,
                        StringComparison.OrdinalIgnoreCase
                    )
                )
                .Where(certificate =>
                    new DateTimeOffset(certificate.NotAfter) > DateTimeOffset.Now
                )
                .OrderByDescending(certificate => certificate.NotAfter)
                .FirstOrDefault();
        }
        catch (CryptographicException ex)
        {
            // A machine store that cannot be opened is the same as one with nothing in it, but it
            // is worth saying so: the usual cause is not running elevated.
            logger.LogDebug(ex, "Could not read the machine certificate store");
            return null;
        }
    }
}

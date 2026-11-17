using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Models;
using Microsoft.Extensions.Logging;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Proves the device's identity with its Entra device registration certificate and the key behind
/// it. Windows creates that certificate when the device is Entra joined or hybrid joined, and
/// normally keeps its key in the TPM. EZCA checks that the certificate chains to the Entra device
/// registration service, that the signature over this enrollment verifies with its key, and that
/// Entra ID lists it as the current registration of an enabled device in the CA's own tenant, so
/// the device never needs a secret from an administrator.
/// </summary>
public class EntraDeviceAttestor : IDeviceAttestor
{
    public const string AuthenticationScheme = "EntraDevice";

    /// <summary>
    /// Issuer of the certificate the device registration service leaves in the machine store.
    /// </summary>
    public const string DeviceCertificateIssuer = "MS-Organization-Access";

    private readonly ILogger _logger;
    private readonly Func<X509Certificate2?> _findDeviceCertificate;

    public EntraDeviceAttestor(ILogger logger)
        : this(logger, null) { }

    /// <param name="findDeviceCertificate">
    /// Finds the device registration certificate, with its private key. Defaults to searching the
    /// machine store; tests pass their own.
    /// </param>
    public EntraDeviceAttestor(ILogger logger, Func<X509Certificate2?>? findDeviceCertificate)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
        _findDeviceCertificate = findDeviceCertificate ?? FindDeviceCertificateInMachineStore;
    }

    public string Name => "Entra device";

    public bool IsAvailable(out string reason)
    {
        if (!OperatingSystem.IsWindows())
        {
            reason =
                "Entra device enrollment needs the device registration certificate Windows creates "
                + "when a device is Entra joined or hybrid joined";
            return false;
        }

        using X509Certificate2? deviceCertificate = _findDeviceCertificate();
        if (deviceCertificate == null)
        {
            reason =
                "this device has no Entra device registration certificate, so it is not Entra "
                + "joined or hybrid joined, or the command is not running as SYSTEM or an "
                + "administrator. Run 'dsregcmd /status' to check its join state";
            return false;
        }

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
        ArgumentNullException.ThrowIfNull(enrollmentUrl);
        ArgumentNullException.ThrowIfNull(csrDer);
        ArgumentNullException.ThrowIfNull(challenge);

        using X509Certificate2 deviceCertificate =
            _findDeviceCertificate()
            ?? throw new InvalidOperationException(
                "This device has no Entra device registration certificate."
            );

        string deviceId = GetDeviceId(deviceCertificate);
        _logger.LogInformation("Attesting as Entra device {DeviceId}", deviceId);

        using RSA? privateKey = deviceCertificate.GetRSAPrivateKey();
        if (privateKey == null)
        {
            throw new InvalidOperationException(
                "The Entra device registration certificate has no usable RSA private key. This "
                    + "command has to run as SYSTEM or as an administrator to reach it."
            );
        }

        byte[] binding = DeviceAttestationBinding.Build(
            AuthenticationScheme,
            enrollmentUrl,
            challenge,
            csrDer
        );
        byte[] signature = privateKey.SignData(
            binding,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        return Task.FromResult(
            new DeviceAttestationResult
            {
                Scheme = AuthenticationScheme,
                // The whole certificate, DER encoded: Entra keeps only its thumbprint against the
                // device, so EZCA needs the certificate itself to check the chain and the
                // signature. The certificate is not secret; the signature is what proves the
                // device holds its key.
                Token = Convert.ToBase64String(deviceCertificate.RawData),
                RequestBinding = Convert.ToBase64String(signature),
                DeviceId = deviceId,
            }
        );
    }

    /// <summary>
    /// The device registration certificate carries the Entra device ID, a GUID, as its common
    /// name. Read the way EZCA reads it, so a name EZCA would refuse is refused here first, with a
    /// clearer error.
    /// </summary>
    internal static string GetDeviceId(X509Certificate2 deviceCertificate)
    {
        string commonName = deviceCertificate.GetNameInfo(X509NameType.SimpleName, false);
        if (!Guid.TryParseExact(commonName, "D", out Guid deviceGuid) || deviceGuid == Guid.Empty)
        {
            throw new InvalidOperationException(
                "The Entra device registration certificate does not name a device ID."
            );
        }

        return deviceGuid.ToString("D");
    }

    private X509Certificate2? FindDeviceCertificateInMachineStore()
    {
        try
        {
            using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = store.Certificates;
            X509Certificate2? chosen = null;
            bool isHandedOver = false;
            try
            {
                DateTime now = DateTime.Now;
                foreach (X509Certificate2 certificate in certificates)
                {
                    bool isCandidate =
                        certificate.Issuer.Contains(
                            DeviceCertificateIssuer,
                            StringComparison.OrdinalIgnoreCase
                        )
                        && certificate.NotBefore <= now
                        && certificate.NotAfter > now
                        && certificate.HasPrivateKey
                        && (chosen == null || certificate.NotAfter > chosen.NotAfter);
                    if (isCandidate)
                    {
                        chosen = certificate;
                    }
                }

                isHandedOver = true;
                return chosen;
            }
            finally
            {
                // The caller disposes the one it was handed; every other one is disposed here,
                // the chosen one too if the search stopped with an error.
                foreach (X509Certificate2 certificate in certificates)
                {
                    if (!isHandedOver || !ReferenceEquals(certificate, chosen))
                    {
                        certificate.Dispose();
                    }
                }
            }
        }
        catch (CryptographicException ex)
        {
            // A machine store that cannot be opened is the same as one with nothing in it, but it
            // is worth saying so: the usual cause is not running elevated.
            _logger.LogDebug(ex, "Could not read the machine certificate store");
            return null;
        }
    }
}

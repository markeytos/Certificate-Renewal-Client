using System.Buffers;
using System.Net.Security;
using System.Security.Cryptography;
using DotNetCertAuthSample.Models;
using Microsoft.Extensions.Logging;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Proves the machine's identity with a Kerberos service ticket for the EZCA enrollment SPN.
/// Running as the machine account, the ticket the domain controller issues names this machine and
/// no other, so the subject of the certificate stops being something the caller can choose.
/// </summary>
public class KerberosDeviceAttestor(
    ILogger logger,
    ISystemInfoService? systemInfoService = null,
    string? servicePrincipalName = null
) : IDeviceAttestor
{
    public const string AuthenticationScheme = "Negotiate";

    private readonly string? _servicePrincipalName = servicePrincipalName;

    public string Name => "kerberos";

    public bool RequiresChallenge => true;

    /// <summary>
    /// Whether this machine might have a Kerberos machine credential. No cheap local check can
    /// tell an Active Directory member from a machine that merely has a DNS suffix, so this is
    /// deliberately permissive: the caller falls back to another attestation when the ticket
    /// request itself fails.
    /// </summary>
    public bool IsAvailable(out string reason)
    {
        if (HasActiveDirectoryComputerObject() || SystemInfoUtils.HasDomainSuffix())
        {
            reason = string.Empty;
            return true;
        }

        reason =
            "this machine is not joined to an Active Directory domain, so it has no Kerberos "
            + "machine credential to authenticate with";
        return false;
    }

    public Task<DeviceAttestationResult> AttestAsync(
        Uri enrollmentUrl,
        byte[] csrDer,
        DeviceEnrollmentChallenge? challenge,
        CancellationToken cancellationToken
    )
    {
        ArgumentNullException.ThrowIfNull(enrollmentUrl);
        ArgumentNullException.ThrowIfNull(csrDer);
        if (challenge == null || string.IsNullOrWhiteSpace(challenge.Nonce))
        {
            throw new InvalidOperationException(
                "Kerberos attestation needs a challenge from the enrollment endpoint: without the "
                    + "nonce there is nothing tying this ticket to this enrollment."
            );
        }

        string spn = ResolveSpn(enrollmentUrl);
        logger.LogInformation("Requesting a Kerberos service ticket for {Spn}", spn);

        NegotiateAuthenticationClientOptions options = new()
        {
            // Kerberos rather than Negotiate: an NTLM fallback would not carry the PAC EZCA needs
            // and would silently weaken the identity the certificate is issued against.
            Package = "Kerberos",
            TargetName = spn,
            RequiredProtectionLevel = ProtectionLevel.Sign,
            RequireMutualAuthentication = false,
        };

        NegotiateAuthentication authentication = new(options);
        try
        {
            string? token = authentication.GetOutgoingBlob(
                (string?)null,
                out NegotiateAuthenticationStatusCode status
            );
            if (
                status
                is not (
                    NegotiateAuthenticationStatusCode.Completed
                    or NegotiateAuthenticationStatusCode.ContinueNeeded
                )
                || string.IsNullOrEmpty(token)
            )
            {
                throw new InvalidOperationException(
                    $"Could not get a Kerberos ticket for {spn}: {status}. Check that the EZCA "
                        + "enrollment account exists in this domain with that service principal name, that this "
                        + "machine can reach a domain controller, and that its clock is within five minutes of the domain's."
                );
            }

            byte[] bindingInput = DeviceAttestationBinding.Build(
                AuthenticationScheme,
                enrollmentUrl,
                challenge,
                csrDer
            );
            return Task.FromResult(BuildResult(authentication, token, bindingInput, status));
        }
        catch
        {
            authentication.Dispose();
            throw;
        }
    }

    private DeviceAttestationResult BuildResult(
        NegotiateAuthentication authentication,
        string token,
        byte[] bindingInput,
        NegotiateAuthenticationStatusCode status
    )
    {
        bool isComplete = status == NegotiateAuthenticationStatusCode.Completed;
        return new DeviceAttestationResult
        {
            Scheme = AuthenticationScheme,
            Token = token,
            RequestBinding = isComplete ? ComputeBinding(authentication, bindingInput) : null,
            Disposable = authentication,
            // Only offered while the context still has a leg to go. A finished context produces
            // no further token, and asking it for one would replace the server's own explanation
            // of a 401 with a misleading handshake error.
            Continue = isComplete
                ? null
                : incomingBlob =>
                {
                    string? nextToken = authentication.GetOutgoingBlob(
                        incomingBlob,
                        out NegotiateAuthenticationStatusCode continueStatus
                    );
                    if (string.IsNullOrEmpty(nextToken))
                    {
                        throw new InvalidOperationException(
                            $"The Kerberos handshake with the enrollment endpoint failed: {continueStatus}"
                        );
                    }

                    return new DeviceAttestationResult
                    {
                        Scheme = AuthenticationScheme,
                        Token = nextToken,
                        RequestBinding =
                            continueStatus == NegotiateAuthenticationStatusCode.Completed
                                ? ComputeBinding(authentication, bindingInput)
                                : null,
                    };
                },
        };
    }

    /// <summary>
    /// MACs the challenge and CSR under the Kerberos session key. Only the machine that holds the
    /// ticket and the service that can decrypt it share that key, so this is what stops a captured
    /// Authorization header from being replayed with somebody else's CSR. A failure here is fatal:
    /// an enrollment sent without it would be a ticket with nothing tying it to this request.
    /// </summary>
    private string ComputeBinding(
        NegotiateAuthentication authentication,
        byte[] bindingInput
    )
    {
        if (!authentication.IsAuthenticated)
        {
            throw new InvalidOperationException(
                "The Kerberos context reported success but is not authenticated, so this request "
                    + "cannot be bound to its certificate request."
            );
        }

        try
        {
            ArrayBufferWriter<byte> signature = new();
            authentication.ComputeIntegrityCheck(bindingInput, signature);
            return Convert.ToBase64String(signature.WrittenSpan);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "Could not bind the Kerberos ticket to this certificate request, so the "
                    + "enrollment was not sent.",
                ex
            );
        }
    }

    private bool HasActiveDirectoryComputerObject()
    {
        if (systemInfoService == null)
        {
            return false;
        }

        try
        {
            return !string.IsNullOrWhiteSpace(
                systemInfoService.GetComputerDistinguishedName(Environment.MachineName)
            );
        }
        catch (Exception ex)
        {
            logger.LogDebug(
                ex,
                "Could not read this machine's Active Directory computer object"
            );
            return false;
        }
    }

    private string ResolveSpn(Uri enrollmentUrl)
    {
        if (string.IsNullOrWhiteSpace(_servicePrincipalName))
        {
            return $"HTTP/{enrollmentUrl.Host}";
        }

        return _servicePrincipalName;
    }
}

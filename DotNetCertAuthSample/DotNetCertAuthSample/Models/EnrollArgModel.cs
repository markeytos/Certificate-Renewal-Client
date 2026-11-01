using CommandLine;
using EZCAClient.Models;

namespace DotNetCertAuthSample.Models;

/// <summary>
/// How the machine proves which machine it is when it asks EZCA for a device certificate.
/// </summary>
public enum AttestationMode
{
    /// <summary>Pick whichever the machine can actually produce, Kerberos first.</summary>
    Auto,

    /// <summary>A Kerberos service ticket for the EZCA enrollment SPN, issued by the machine's own domain controller.</summary>
    Kerberos,

    /// <summary>A signature from the key behind the machine's Entra device registration certificate.</summary>
    Entra,
}

[Verb(
    "enroll",
    HelpText = "Requests a device certificate from EZCA, proving the machine's identity with its "
        + "Active Directory or Entra device credentials instead of a shared secret"
)]
public class EnrollArgModel
{
    [Option(
        'u',
        "Url",
        Required = false,
        HelpText = "EZCA device enrollment URL. Falls back to the machine enrollment configuration file when omitted."
    )]
    public string? Url { get; set; }

    [Option(
        "Mode",
        Required = false,
        Default = AttestationMode.Auto,
        HelpText = "How to prove this machine's identity: Auto, Kerberos or Entra. Auto tries Kerberos first and falls back to Entra."
    )]
    public AttestationMode Mode { get; set; } = AttestationMode.Auto;

    [Option(
        "Spn",
        Required = false,
        HelpText = "Service principal name of the EZCA enrollment account. Defaults to HTTP/<host of --Url>."
    )]
    public string? Spn { get; set; }

    [Option(
        "LocalStore",
        Required = false,
        Default = true,
        HelpText = "If the certificate should be stored in the computer's local store. A device certificate belongs to the machine, so this defaults to true."
    )]
    public bool LocalCertStore { get; set; } = true;

    [Option(
        "KeyProvider",
        Required = false,
        HelpText = "Windows key storage provider for the new key. Defaults to the TPM ('Microsoft Platform Crypto Provider'), "
            + "falling back to a software key when the TPM cannot create one. Ignored on Linux and macOS."
    )]
    public string? KeyProvider { get; set; }

    [Option(
        'k',
        "KeyLength",
        Required = false,
        Default = 2048,
        HelpText = "Certificate key length. Defaults to 2048 because most TPMs cannot create a 4096 bit RSA key."
    )]
    public int KeyLength { get; set; } = 2048;

    [Option(
        "EKUs",
        Required = false,
        HelpText = "EKUs requested for the certificate. Defaults to Client Authentication, which is what a device certificate needs for EAP-TLS."
    )]
    public string? EKUsInputs { get; set; }

    public List<string> EKUs { get; set; } = [EZCAConstants.ClientAuthenticationEKU];

    [Option(
        "RenewalPercentage",
        Required = false,
        Default = 20,
        HelpText = "Renew when this percentage or less of the certificate's lifetime is left. The command does nothing when a valid certificate is already present."
    )]
    public int RenewalPercentage { get; set; } = 20;

    [Option(
        "Force",
        Required = false,
        Default = false,
        HelpText = "Enroll even when the machine already has a certificate that is not due for renewal."
    )]
    public bool Force { get; set; }

    [Option(
        "ConfigFile",
        Required = false,
        HelpText = "Path to the machine enrollment configuration file. Defaults to the machine-wide location for this platform."
    )]
    public string? ConfigFile { get; set; }

    [Option(
        "SaveConfig",
        Required = false,
        Default = false,
        HelpText = "Writes the URL and mode used by this run to the machine enrollment configuration file, replacing what is already recorded. A first enrollment records its URL either way, so later runs need no arguments; this flag is how an already-configured machine is repointed."
    )]
    public bool SaveConfig { get; set; }

    [Option(
        "Path",
        Required = false,
        HelpText = "Certificate will also be saved to the specified file. A pfx or p12 path needs an exportable key, so it turns off TPM key storage."
    )]
    public string? Path { get; set; }

    [Option(
        "Password",
        Required = false,
        HelpText = "Password for the certificate file."
    )]
    public string? Password { get; set; }

    [Option(
        "AppInsights",
        Required = false,
        HelpText = "Azure Application Insights connection string to send logs to"
    )]
    public string? AppInsightsKey { get; set; }
}

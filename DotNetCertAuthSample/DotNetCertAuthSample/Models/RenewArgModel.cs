using CommandLine;

namespace DotNetCertAuthSample.Models;

[Verb("renew", HelpText = "Renews an existing certificate")]
public class RenewArgModel
{
    [Option(
        'r',
        "RDP",
        Required = false,
        Default = false,
        HelpText = "whether this certificate should be added as the computer's RDP certificate"
    )]
    public bool RDPCert { get; set; }

    [Option(
        's',
        "SubjectName",
        Required = false,
        HelpText = "SubjectName for the certificate you want to renew. Required unless --SourceFile is provided."
    )]
    public string? Domain { get; set; }

    [Option(
        "SourceFile",
        Required = false,
        HelpText = "Path to an existing certificate file (PEM or PFX/P12) to use as the source for renewal instead of the certificate store. If the file is a PFX, --Password is required to decrypt it."
    )]
    public string? SourceFile { get; set; }

    [Option(
        "AppInsights",
        Required = false,
        HelpText = "Azure Application Insights connection string to send logs to"
    )]
    public string? AppInsightsKey { get; set; }

    [Option(
        'e',
        "EZCAInstance",
        Required = false,
        Default = "https://portal.ezca.io/",
        HelpText = "EZCA instance url"
    )]
    public string url { get; set; } = "https://portal.ezca.io/";

    [Option(
        "LocalStore",
        Required = false,
        Default = false,
        HelpText = "If the certificate should be stored in the computers Local Store. If false certificate will be stored in the user store"
    )]
    public bool LocalCertStore { get; set; }

    [Option(
        't',
        "Template",
        Required = false,
        Default = "",
        HelpText = "Certificate Template Name"
    )]
    public string template { get; set; } = "";

    [Option('i', "Issuer", Required = false, Default = "", HelpText = "Certificate Issuer Name")]
    public string issuer { get; set; } = "";

    [Option('k', "KeyLength", HelpText = "Certificate Key Length", Default = 4096)]
    public int KeyLength { get; set; } = 4096;

    [Option(
        'p',
        "KeyProvider",
        Required = false,
        Default = "Microsoft Enhanced Cryptographic Provider v1.0",
        HelpText = "Certificate Key Provider (Default: Microsoft Enhanced Cryptographic Provider v1.0)"
    )]
    public string KeyProvider { get; set; } = "Microsoft Enhanced Cryptographic Provider v1.0";

    [Option(
        "Path",
        Required = false,
        HelpText = "Certificate will be saved to the specified file. If specified with pfx or p12 ending, the private key will be saved in the file and the file will be password-protected."
    )]
    public string? Path { get; set; }

    [Option(
        "Password",
        Required = false,
        HelpText = "Password for the certificate file. Required to decrypt a PFX/P12 source file (--SourceFile). On Linux without --SourceFile, this must be the password of the existing certificate in the store. If not provided when saving a PFX output, a random password will be generated and saved to {filename}_password.txt in the same directory as the certificate file."
    )]
    public string? Password { get; set; }
}

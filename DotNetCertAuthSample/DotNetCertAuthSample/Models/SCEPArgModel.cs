using CommandLine;
using EZCAClient.Models;

namespace DotNetCertAuthSample.Models;

[Verb(
    "SCEPCertificate",
    HelpText = "Creates a new SCEP certificate using SCEP Static Challenge protocol"
)]
public class SCEPArgModel
{
    [Option(
        "LocalStore",
        Required = false,
        Default = false,
        HelpText = "If the certificate should be stored in the computers Local Store. If false certificate will be stored in the user store"
    )]
    public bool LocalCertStore { get; set; }

    [Option(
        "EKUs",
        Required = false,
        Default = "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1",
        HelpText = "EKUs requested for the certificate"
    )]
    public string? EKUsInputs { get; set; }
    public List<string> EKUs { get; set; } =
    [EZCAConstants.ClientAuthenticationEKU, EZCAConstants.ServerAuthenticationEKU];

    [Option('k', "KeyLength", HelpText = "Certificate Key Length", Default = 4096)]
    public int KeyLength { get; set; } = 4096;

    [Option(
        "AppInsights",
        Required = false,
        HelpText = "Azure Application Insights connection string to send logs to"
    )]
    public string? AppInsightsKey { get; set; }

    [Option('u', "URL", Required = true, HelpText = "SCEP URL from your EZCA CA")]
    public string? url { get; set; }

    [Option(
        's',
        "SubjectName",
        Required = false,
        HelpText = "Subject Name for this certificate for example: CN=server1.contoso.com OU=Domain Controllers DC=contoso DC=com"
    )]
    public string? SubjectName { get; set; }

    [Option('p', "SCEPPassword", Required = true, HelpText = "SCEP Password for Static Challenge")]
    public string? SCEPPassword { get; set; }

    [Option(
        "SubjectAltNames",
        Required = false,
        HelpText = "Subject Alternate Names for this certificate for example (comma separate multiple): server1.constoso.com,server2.contoso.com"
    )]
    public string? SubjectAltNames { get; set; }

    [Option(
        "Path",
        Required = false,
        HelpText = "Certificate will be saved to the specified file. If specified with pfx or p12 ending, the private key will be saved in the file and the file will be password-protected."
    )]
    public string? Path { get; set; }

    [Option(
        "Password",
        Required = false,
        HelpText = "Password for certificate file. If not provided, a random password will be generated. The password will be written to a file."
    )]
    public string? Password { get; set; }
}

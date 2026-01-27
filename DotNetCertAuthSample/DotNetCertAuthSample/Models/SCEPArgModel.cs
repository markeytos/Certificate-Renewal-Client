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
        Default = true,
        HelpText = "If the certificate should be stored in the computers Local Store. If false certificate will be stored in the user store"
    )]
    public bool LocalCertStore { get; set; } = true;

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
        'o',
        "OutputPath",
        Required = false,
        HelpText = "Optional file or directory path to save the certificate as a PFX file. If a directory is specified, the file will be named {CN}.pfx"
    )]
    public string? OutputPath { get; set; }

    [Option(
        "OutputPassword",
        Required = false,
        HelpText = "Optional password to protect the PFX file. If not specified, the PFX will not be password protected"
    )]
    public string? OutputPassword { get; set; }
}

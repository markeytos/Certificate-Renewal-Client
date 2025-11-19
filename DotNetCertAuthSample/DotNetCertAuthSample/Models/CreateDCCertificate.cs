using CommandLine;
using EZCAClient.Models;

namespace DotNetCertAuthSample.Models;

[Verb(
    "createDC",
    HelpText = "Creates a new Domain Controller certificate. Note: this must be run from a PKI Administrator Account"
)]
public class CreateDCCertificate
{
    [Option('d', "DNS", HelpText = "DNS Entry for this Domain Controller")]
    public string? Domain { get; set; }

    [Option(
        's',
        "SubjectName",
        HelpText = "Subject Name for this certificate for example: CN=server1.contoso.com OU=Domain Controllers DC=contoso DC=com"
    )]
    public string? SubjectName { get; set; }

    [Option(
        "caid",
        Required = true,
        HelpText = "CA ID of the CA you want to request the certificate from"
    )]
    public string caID { get; set; } = "";

    [Option(
        "TemplateID",
        Required = true,
        HelpText = "Template ID of the template you want to request the certificate from (Note: Only SCEP templates are supported)"
    )]
    public string TemplateID { get; set; } = "";

    [Option('v', "Validity", Required = true, HelpText = "Certificate validity in days")]
    public int Validity { get; set; }

    [Option(
        'g',
        "DCGUID",
        Required = false,
        HelpText = "Domain Controller GUID. This is only required if SMTP replication is used in your domain. Learn more: https://learn.microsoft.com/en-US/troubleshoot/windows-server/windows-security/requirements-domain-controller#how-to-determine-the-domain-controller-guid"
    )]
    public string DCGUID { get; set; } = "";

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
        "EKUs",
        Required = false,
        Default = "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.2.3.5",
        HelpText = "EKUs requested for the certificate"
    )]
    public string? EKUsInputs { get; set; }
    public List<string> EKUs { get; set; } = EZCAConstants.DomainControllerDefaultEKUs;

    [Option(
        "AzureCLI",
        Required = false,
        Default = false,
        HelpText = "Use Azure CLI as authentication method"
    )]
    public bool AzureCLI { get; set; } = false;

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
        "SubjectAltNames",
        Required = false,
        HelpText = "Subject Alternate Names for this certificate for example (comma separate multiple): server1.contoso.com,server2.contoso.com"
    )]
    public string? SubjectAltNames { get; set; }
}

using CommandLine;

namespace DotNetCertAuthSample.Models;

[Verb("renewAll", HelpText = "Renews all existing certificates issued by a list of CAs")]
public class RenewAllArgModel
{
    
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
        'a',
        "authoritySubjectKeys",
        Required = true,
        HelpText = "Authority Subject Keys of the issuing CAs of the certificates you want to renew. This can be found in the certificate details of the CA certificate. If you want to include multiple CAs, separate the values with a comma"
    )]
    public string authoritySubjectKeys { get; set; } = string.Empty;
    [Option(
        "LocalStore",
        Required = false,
        Default = false,
        HelpText = "If the certificate should be stored in the computers Local Store. If false certificate will be stored in the user store"
    )]
    public bool LocalCertStore { get; set; }
    
    [Option(
        "RenewalPercentage",
        Required = false,
        Default = 20,
        HelpText = "Remaining percentage of lifetime of the certificate before renewal is attempted. For example, if set to 20, certificates will be renewed when they have 20% or less of their lifetime remaining"
    )]
    public int RenewalPercentage { get; set; } =20;

}
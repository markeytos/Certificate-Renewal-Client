using CommandLine;

namespace DotNetCertAuthSample.Models
{
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
            Required = true,
            HelpText = "SubjectName for the certificate you want to renew"
        )]
        public string? Domain { get; set; }

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

        [Option(
            'i',
            "Issuer",
            Required = false,
            Default = "",
            HelpText = "Certificate Issuer Name"
        )]
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
    }
}

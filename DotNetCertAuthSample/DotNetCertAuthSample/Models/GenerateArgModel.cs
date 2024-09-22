using CommandLine;

namespace DotNetCertAuthSample.Models
{
    [Verb("create", HelpText = "Creates a new certificate")]
    public class GenerateArgModel
    {
        [Option(
            'r',
            "RDP",
            Required = false,
            Default = false,
            HelpText = "whether this certificate should be added as the computer's RDP certificate"
        )]
        public bool RDPCert { get; set; }

        [Option('d', "Domain", HelpText = "Domain for the certificate you want to create")]
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
            "caid",
            Required = true,
            HelpText = "CA ID of the CA you want to request the certificate from"
        )]
        public string caID { get; set; } = "";

        [Option(
            "LocalStore",
            Required = false,
            Default = false,
            HelpText = "If the certificate should be stored in the computers Local Store. If false certificate will be stored in the user store"
        )]
        public bool LocalCertStore { get; set; }

        [Option('v', "Validity", Required = true, HelpText = "Certificate validity in days")]
        public int Validity { get; set; }

        [Option(
            "AzTenantID",
            Required = false,
            HelpText = "Optional If you want to authenticate with an Azure application you must pass "
                + "you Azure TenantID, the Application ID and the Application Secret"
        )]
        public string TenantID { get; set; } = "";

        [Option(
            "AzAppID",
            Required = false,
            HelpText = "Optional If you want to authenticate with an Azure application you must pass "
                + "you Azure TenantID, the Application ID and the Application Secret"
        )]
        public string ClientID { get; set; } = "";

        [Option(
            "AzAppSecret",
            Required = false,
            HelpText = "Optional If you want to authenticate with an Azure application you must pass "
                + "you Azure TenantID, the Application ID and the Application Secret"
        )]
        public string ClientSecret { get; set; } = "";

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

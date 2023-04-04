using CommandLine.Text;
using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetCertAuthSample.Models
{
    [Verb("renew", HelpText = "Renews an existing certificate")]
    public class RenewArgModel
    {
        [Option('r',"RDP", Required = false, Default = false,
            HelpText = "whether this certificate should be added as the computer's RDP certificate")]
        public bool RDPCert { get; set; }

        [Option('s', "SubjectName", Required = true,
            HelpText = "SubjectName for the certificate you want to renew")]
        public string? Domain { get; set; }
        [Option("AppInsights", Required = false,
            HelpText = "Azure Application Insights connection string to send logs to")]
        public string? AppInsightsKey { get; set; }
        [Option('e', "EZCAInstance", Required = false, Default = "https://portal.ezca.io/",
           HelpText = "EZCA instance url")]
        public string url { get; set; } = "https://portal.ezca.io/";
        [Option("LocalStore", Required = false, Default = false,
            HelpText = "If the certificate should be stored in the computers Local Store. If false certificate will be stored in the user store")]
        public bool LocalCertStore { get; set; }
        
    }
}

using CommandLine.Text;
using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNetCertAuthSample.Models
{
    [Verb("register", HelpText = "Registers a domain in EZCA and creates a new certificate")]
    public class RegisterArgModel
    {

        [Option('d', "Domain", Required = true,
            HelpText = "Domain for the certificate you want to create")]
        public string? Domain { get; set; }
        [Option("AppInsights", Required = false,
            HelpText = "Azure Application Insights connection string to send logs to")]
        public string? AppInsightsKey { get; set; }
        [Option('e', "EZCAInstance", Required = false, Default = "https://portal.ezca.io/",
           HelpText = "EZCA instance url")]
        public string url { get; set; } = "https://portal.ezca.io/";
        [Option( "caid", Required = true,
           HelpText = "CA ID of the CA you want to request the certificate from")]
        public string caID { get; set; } = "";
        
    }
}

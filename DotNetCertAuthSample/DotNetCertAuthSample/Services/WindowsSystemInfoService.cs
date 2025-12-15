#if WINDOWS
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Net;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

namespace DotNetCertAuthSample.Services
{
    public class WindowsSystemInfoService : ISystemInfoService
    {
        public string GetFQDN(string computerName = "")
        {
            // Get the host entry for the local computer.
            if (string.IsNullOrWhiteSpace(computerName))
            {
                computerName = Dns.GetHostName();
            }
            var hostEntry = Dns.GetHostEntry(computerName);

            // Return the first DNS name assigned to this address (should be the FQDN).
            return hostEntry.HostName;
        }

        public string? GetComputerDistinguishedName(string computerName)
        {
            // set up domain context
            try
            {
                var context = new PrincipalContext(ContextType.Domain);

                // find computer
                var computer = ComputerPrincipal.FindByIdentity(context, computerName);

                if (computer != null)
                {
                    // get the Distinguished Name
                    return computer.DistinguishedName;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error getting computer distinguished name " + e.Message);
            }
            return null;
        }

        public string GetComputerSubjectName()
        {
            string computerName = Dns.GetHostName();
            string? distinguishedName = GetComputerDistinguishedName(computerName);
            if (!string.IsNullOrWhiteSpace(distinguishedName))
            {
                return distinguishedName;
            }
            return GetFQDN(computerName);
        }

        public void SetRDPCertificate(string thumbprint)
        {
            string namespaceValue = @"root\cimv2\TerminalServices";
            string queryDialect = "WQL";
            string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
            string thumbprintProperty = "SSLCertificateSHA1Hash";
            var dComOpts = new DComSessionOptions()
            {
                Culture = CultureInfo.CurrentCulture,
                UICulture = CultureInfo.CurrentUICulture,
                PacketIntegrity = true,
                PacketPrivacy = true,
                Timeout = new TimeSpan(0)
            };
            CimSession cimSession = CimSession.Create("localhost", dComOpts);
            CimInstance? instance = cimSession
                .QueryInstances(namespaceValue, queryDialect, query)
                .ToArray()
                .FirstOrDefault();
            if (instance == null)
            {
                throw new Exception("Error getting RDP service");
            }
            var check = !instance.CimInstanceProperties[thumbprintProperty].Value.Equals(thumbprint);
            if (check)
            {
                var prop = instance.CimInstanceProperties[thumbprintProperty];
                prop.Value = thumbprint;
                cimSession.ModifyInstance(instance);
            }
        }
    }
}
#endif

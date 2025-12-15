using System.Net;

namespace DotNetCertAuthSample.Services
{
    public class LinuxSystemInfoService : ISystemInfoService
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
            // Linux doesn't have Active Directory by default
            // Return null to indicate that DN is not available
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
            // RDP is not applicable on Linux
            // This is a no-op on Linux
            Console.WriteLine("RDP certificate configuration is not supported on Linux");
        }
    }
}

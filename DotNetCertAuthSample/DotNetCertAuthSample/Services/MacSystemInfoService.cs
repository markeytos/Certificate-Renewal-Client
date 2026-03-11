using System.Net;

namespace DotNetCertAuthSample.Services;

public class MacSystemInfoService : ISystemInfoService
{
    public string? GetComputerDistinguishedName(string computerName)
    {
        return null;
    }

    public string GetComputerSubjectName()
    {
        string computerName = Dns.GetHostName();
        return GetFQDN(computerName);
    }

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

    public void SetRDPCertificate(string thumbprint)
    {
        throw new NotImplementedException("RDP is not availalbe on macOS");
    }
}

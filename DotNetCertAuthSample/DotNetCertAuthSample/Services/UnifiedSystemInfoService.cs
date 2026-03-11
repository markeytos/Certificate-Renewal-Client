using System.Net;

namespace DotNetCertAuthSample.Services;

public class UnifiedSystemInfoService : ISystemInfoService
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
        if (string.IsNullOrWhiteSpace(computerName))
        {
            computerName = Dns.GetHostName();
        }
        IPHostEntry hostEntry = Dns.GetHostEntry(computerName);
        return hostEntry.HostName;
    }

    public void SetRDPCertificate(string thumbprint)
    {
        throw new NotSupportedException("RDP is only available on Windows");
    }
}


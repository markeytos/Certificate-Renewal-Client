using System.Net;

namespace DotNetCertAuthSample.Services;

public class LinuxSystemInfoService : ISystemInfoService
{
    public string GetFQDN(string computerName = "")
    {
        if (string.IsNullOrWhiteSpace(computerName))
        {
            computerName = Dns.GetHostName();
        }
        IPHostEntry hostEntry = Dns.GetHostEntry(computerName);

        return hostEntry.HostName;
    }

    public string? GetComputerDistinguishedName(string computerName)
    {
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

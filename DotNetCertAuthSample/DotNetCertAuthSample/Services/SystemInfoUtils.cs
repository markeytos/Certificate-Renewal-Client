using System.Net;

namespace DotNetCertAuthSample.Services;

public static class SystemInfoUtils
{
    public static string GetFQDN(string computerName = "")
    {
        if (string.IsNullOrWhiteSpace(computerName))
        {
            computerName = Dns.GetHostName();
        }
        IPHostEntry hostEntry = Dns.GetHostEntry(computerName);
        return hostEntry.HostName;
    }

    public static string GetComputerSubjectName(ISystemInfoService systemInfoService)
    {
        string computerName = Dns.GetHostName();
        string? distinguishedName = systemInfoService.GetComputerDistinguishedName(computerName);
        if (!string.IsNullOrWhiteSpace(distinguishedName))
        {
            return distinguishedName;
        }
        return GetFQDN(computerName);
    }
}


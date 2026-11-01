using System.Net;
using System.Net.NetworkInformation;

namespace DotNetCertAuthSample.Services;

public static class SystemInfoUtils
{
    /// <summary>
    /// Whether this machine has a DNS domain suffix. This is NOT a domain membership test — DHCP
    /// hands a suffix to machines that are not joined to Active Directory — it only rules out a
    /// machine that plainly has no domain at all. Callers that need to know whether a Kerberos
    /// credential really exists have to try to use one.
    /// </summary>
    public static bool HasDomainSuffix()
    {
        try
        {
            return !string.IsNullOrWhiteSpace(
                IPGlobalProperties.GetIPGlobalProperties().DomainName
            );
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }

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

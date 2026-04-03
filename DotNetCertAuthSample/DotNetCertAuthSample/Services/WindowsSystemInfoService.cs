#if WINDOWS
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Net;
using EZCAClient.Models;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;

namespace DotNetCertAuthSample.Services;

public class WindowsSystemInfoService : ISystemInfoService
{
    public string? GetComputerDistinguishedName(string computerName)
    {
        try
        {
            PrincipalContext context = new(ContextType.Domain);
            var computer = ComputerPrincipal.FindByIdentity(context, computerName);
            if (computer != null)
            {
                return computer.DistinguishedName;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Error getting computer distinguished name " + e.Message);
        }
        return null;
    }

    public void SetRDPCertificate(string thumbprint)
    {
        string namespaceValue = @"root\cimv2\TerminalServices";
        string queryDialect = "WQL";
        string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
        string thumbprintProperty = "SSLCertificateSHA1Hash";
        DComSessionOptions dComOpts = new()
        {
            Culture = CultureInfo.CurrentCulture,
            UICulture = CultureInfo.CurrentUICulture,
            PacketIntegrity = true,
            PacketPrivacy = true,
            Timeout = new TimeSpan(0),
        };
        using CimSession cimSession = CimSession.Create("localhost", dComOpts);
        CimInstance? instance = cimSession
            .QueryInstances(namespaceValue, queryDialect, query)
            .ToArray()
            .FirstOrDefault();
        if (instance == null)
        {
            throw new Exception("Error getting RDP service");
        }
        bool check = !instance.CimInstanceProperties[thumbprintProperty].Value.Equals(thumbprint);
        if (check)
        {
            CimProperty? prop = instance.CimInstanceProperties[thumbprintProperty];
            prop.Value = thumbprint;
            cimSession.ModifyInstance(instance);
        }
    }

    public APIResultModel CheckIfRDPCertAndRenew(string oldCertThumbprint, string newCertThumbprint)
    {
        string namespaceValue = @"root\cimv2\TerminalServices";
        string queryDialect = "WQL";
        string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
        string thumbprintProperty = "SSLCertificateSHA1Hash";
        DComSessionOptions dComOpts = new()
        {
            Culture = CultureInfo.CurrentCulture,
            UICulture = CultureInfo.CurrentUICulture,
            PacketIntegrity = true,
            PacketPrivacy = true,
            Timeout = new TimeSpan(0),
        };
        using CimSession cimSession = CimSession.Create("localhost", dComOpts);
        CimInstance? instance = cimSession
            .QueryInstances(namespaceValue, queryDialect, query)
            .ToArray()
            .FirstOrDefault();
        if (instance == null)
        {
            return new(false, "Error getting RDP service");
        }
        string currentThumbprint = NormalizeThumbprint(
            instance.CimInstanceProperties[thumbprintProperty].Value?.ToString()
        );
        if (currentThumbprint != NormalizeThumbprint(oldCertThumbprint))
        {
            return new(true, "");
        }
        CimProperty? prop = instance.CimInstanceProperties[thumbprintProperty];
        prop.Value = newCertThumbprint;
        cimSession.ModifyInstance(instance);
        return new(true, "RDP certificate updated successfully");
    }

    private static string NormalizeThumbprint(string? thumbprint) =>
        (thumbprint ?? string.Empty).Replace(" ", string.Empty).Trim().ToUpperInvariant();
}
#endif

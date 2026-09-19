using EZCAClient.Models;

namespace DotNetCertAuthSample.Services;

public class UnifiedSystemInfoService : ISystemInfoService
{
    public string? GetComputerDistinguishedName(string computerName)
    {
        return null;
    }

    public void SetRDPCertificate(string thumbprint)
    {
        throw new NotSupportedException("RDP is only available on Windows");
    }

    public APIResultModel CheckIfRDPCertAndRenew(string oldCertThumbprint, string newCertThumbprint)
    {
        throw new NotSupportedException("RDP is only available on Windows");
    }

    public APIResultModel SetIISCertificate(string thumbprint, string? siteName)
    {
        if (string.IsNullOrWhiteSpace(siteName))
        {
            return new(true, "");
        }

        return new(false, "IIS is only available on Windows");
    }

    public APIResultModel CheckIfIISCertAndRenew(string oldCertThumbprint, string newCertThumbprint)
    {
        // nothing to renew, this machine cannot be running IIS
        return new(true, "");
    }
}

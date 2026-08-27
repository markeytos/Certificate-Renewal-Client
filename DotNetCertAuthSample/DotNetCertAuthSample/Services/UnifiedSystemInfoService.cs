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

    public APIResultModel SetIISCertificate(
        string thumbprint,
        string? siteName,
        IReadOnlyList<string> certificateHostNames
    )
    {
        throw new NotSupportedException("IIS is only available on Windows");
    }

    public APIResultModel CheckIfIISCertAndRenew(string oldCertThumbprint, string newCertThumbprint)
    {
        throw new NotSupportedException("IIS is only available on Windows");
    }
}

using EZCAClient.Models;

namespace DotNetCertAuthSample.Services;

public interface ISystemInfoService
{
    string? GetComputerDistinguishedName(string computerName);

    void SetRDPCertificate(string thumbprint);
    APIResultModel CheckIfRDPCertAndRenew(string oldCertThumbprint, string newCertThumbprint);

    /// <summary>
    /// Binds the certificate to every https binding of the named IIS site. An empty
    /// site name means IIS was not requested, so nothing is done.
    /// </summary>
    APIResultModel SetIISCertificate(string thumbprint, string? siteName);

    /// <summary>
    /// Updates every IIS https binding that is currently using the old certificate so
    /// that it uses the renewed one. Bindings using other certificates are left alone.
    /// </summary>
    APIResultModel CheckIfIISCertAndRenew(string oldCertThumbprint, string newCertThumbprint);
}

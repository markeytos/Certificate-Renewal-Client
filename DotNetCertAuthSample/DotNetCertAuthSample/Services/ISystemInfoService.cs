using EZCAClient.Models;

namespace DotNetCertAuthSample.Services;

public interface ISystemInfoService
{
    string? GetComputerDistinguishedName(string computerName);

    void SetRDPCertificate(string thumbprint);
    APIResultModel CheckIfRDPCertAndRenew(string oldCertThumbprint, string newCertThumbprint);

    /// <summary>
    /// Binds the certificate to the machine's IIS https bindings. When a site name is
    /// given every https binding of that site is updated, otherwise only the bindings
    /// whose host name is covered by the certificate are updated.
    /// </summary>
    APIResultModel SetIISCertificate(
        string thumbprint,
        string? siteName,
        IReadOnlyList<string> certificateHostNames
    );

    /// <summary>
    /// Updates every IIS https binding that is currently using the old certificate so
    /// that it uses the renewed one. Bindings using other certificates are left alone.
    /// </summary>
    APIResultModel CheckIfIISCertAndRenew(string oldCertThumbprint, string newCertThumbprint);
}

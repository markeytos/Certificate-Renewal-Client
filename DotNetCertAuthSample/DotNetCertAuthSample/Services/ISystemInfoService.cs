namespace DotNetCertAuthSample.Services;

public interface ISystemInfoService
{
    string? GetComputerDistinguishedName(string computerName);

    void SetRDPCertificate(string thumbprint);
}

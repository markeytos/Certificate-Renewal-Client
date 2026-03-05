namespace DotNetCertAuthSample.Services;

public class MacSystemInfoService : ISystemInfoService
{
    public string? GetComputerDistinguishedName(string computerName)
    {
        throw new NotImplementedException();
    }

    public string GetComputerSubjectName()
    {
        throw new NotImplementedException();
    }

    public string GetFQDN(string computerName = "")
    {
        throw new NotImplementedException();
    }

    public void SetRDPCertificate(string thumbprint)
    {
        throw new NotImplementedException();
    }
}

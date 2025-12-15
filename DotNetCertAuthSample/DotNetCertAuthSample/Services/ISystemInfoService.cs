namespace DotNetCertAuthSample.Services
{
    public interface ISystemInfoService
    {
        string GetFQDN(string computerName = "");
        
        string? GetComputerDistinguishedName(string computerName);
        
        string GetComputerSubjectName();
        
        void SetRDPCertificate(string thumbprint);
    }
}

using System.Security.Cryptography.X509Certificates;

namespace DotNetCertAuthSample.Services;

public class MacCertStoreService : ICertStoreService
{
    public CsrData CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string keyProvider = "Microsoft Enhanced Cryptographic Provider v1.0"
    )
    {
        throw new NotImplementedException();
    }

    public X509Certificate2 GetCertFromStoreBySubject(
        string subjectName,
        bool localStore,
        string issuerName = "",
        string templateName = ""
    )
    {
        throw new NotImplementedException();
    }

    public X509Certificate2? GetCertFromStoreByThumbprint(string thumbprint)
    {
        throw new NotImplementedException();
    }

    public void InstallCertificate(string cert, CsrData csrData)
    {
        throw new NotImplementedException();
    }

    public void InstallFullCertificate(X509Certificate2 certificate, bool localStore)
    {
        throw new NotImplementedException();
    }
}

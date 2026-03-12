using System.Security.Cryptography.X509Certificates;

namespace DotNetCertAuthSample.Services;

public interface ICertStoreService
{
    CsrData CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string keyProvider = "",
        X509KeyUsageFlags? keyUsageFlags = null
    );

    void InstallCertificate(string cert, CsrData csrData, bool localStore, string? password = null);

    void InstallCertificateWithPrivateKey(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    );
}

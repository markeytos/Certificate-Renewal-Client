using System.Security.Cryptography.X509Certificates;

namespace DotNetCertAuthSample.Services;

public interface ICertStoreService
{
    X509Certificate2 GetCertFromStoreBySubject(
        string subjectName,
        bool localStore,
        string issuerName = "",
        string templateName = ""
    );

    X509Certificate2? GetCertFromStoreByThumbprint(string thumbprint);

    CsrData CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string keyProvider = "Microsoft Enhanced Cryptographic Provider v1.0",
        List<X509KeyUsageFlags>? keyUsageFlags = null
    );

    void InstallCertificate(string cert, CsrData csrData, bool localStore);

    void InstallCertificateWithPrivateKey(X509Certificate2 certificate, bool localStore);
}

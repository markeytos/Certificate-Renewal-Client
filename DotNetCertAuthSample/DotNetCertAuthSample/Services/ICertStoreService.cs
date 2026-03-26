using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Parameters;

namespace DotNetCertAuthSample.Services;

public interface ICertStoreService
{
    string CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string keyProvider = "",
        X509KeyUsageFlags? keyUsageFlags = null,
        bool makePrivateKeyExportable = false
    );

    RSA ConvertToDotnetRSA(RsaPrivateCrtKeyParameters rsaParams);

    void InstallCertificate(X509Certificate2 cert, bool localStore, string? password = null);

    void InstallCertificateWithPrivateKey(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    );

    X509Certificate2 GetCertFromStore(
        string subjectName,
        bool localStore,
        string issuerName = "",
        string templateName = "",
        string? password = null
    );

    List<X509Certificate2> GetCertificatesIssuedByCaSki(string caSki, bool localStore);

    X509Certificate2 AddPrivateKeyToCertificate(X509Certificate2 certificate, bool localStore);
}

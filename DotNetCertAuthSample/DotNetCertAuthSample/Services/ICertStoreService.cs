using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Parameters;

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

    RSA ConvertToDotnetRSA(RsaPrivateCrtKeyParameters rsaParams);

    // on windows, returns a CX509Enrollment
    object? InstallCertificate(
        string cert,
        CsrData csrData,
        bool localStore,
        string? password = null
    );

    void InstallCertificateWithPrivateKey(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    );

    public X509Certificate2 GetCertFromStore(
        string subjectName,
        bool localStore,
        string issuerName = "",
        string templateName = "",
        string? password = null
    );

    byte[] ExportCertificate(
        string certificatePEM,
        CsrData csrData,
        object? enrollmentContext,
        bool withPrivateKey = false,
        string? password = null
    );
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Parameters;

namespace DotNetCertAuthSample.Services;

public interface ICertStoreService
{
    /// <summary>
    /// Creates a certificate request and the key behind it. Each entry of <paramref name="sans"/>
    /// may carry a type prefix (DNS=, UPN=, IP=, RFC822=, URI=, SID=); an entry without one is a
    /// DNS name. <paramref name="challengePassword"/> adds the PKCS#9 challengePassword attribute
    /// SCEP uses, signed by the request key, and is left out when null.
    /// </summary>
    string CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string keyProvider = "",
        X509KeyUsageFlags? keyUsageFlags = null,
        bool makePrivateKeyExportable = false,
        HashAlgorithmName? hashAlgorithm = null,
        string? challengePassword = null
    );

    RSA ConvertToDotnetRSA(RsaPrivateCrtKeyParameters rsaParams);

    /// <summary>
    /// Deletes the key created for a certificate request that is never going to be answered.
    /// Creating the request persists a key container on Windows, so without this a command that
    /// runs on a schedule leaves one behind on every failed attempt.
    /// </summary>
    void DiscardPendingRequest();

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

    /// <summary>
    /// The certificate with this thumbprint, or null when the store does not hold it. Looking a
    /// certificate up by thumbprint is exact, unlike looking it up by subject. The password is
    /// required on Linux, where the store is a directory of password protected files.
    /// </summary>
    X509Certificate2? GetCertificateByThumbprint(
        string thumbprint,
        bool localStore,
        string? password = null
    );

    X509Certificate2 AddPrivateKeyToCertificate(X509Certificate2 certificate, bool localStore);
}

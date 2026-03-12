using System.Security.Cryptography.X509Certificates;

namespace DotNetCertAuthSample.Services;

public interface IStoreService
{
    X509Certificate2Collection FindCertificatesBySubject(
        string subjectName,
        bool localStore,
        string? password = null
    );

    X509Certificate2Collection GetAllCertificatesInStore(bool localStore, string? password = null);

    X509Certificate2Collection FindCertificatesByTemplate(
        string templateName,
        bool localStore,
        string? password = null
    );

    X509Certificate2Collection FindCertificatesByIssuer(
        string issuerName,
        bool localStore,
        string? password = null
    );

    void WriteCertificateWithPrivateKeyToStore(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    );
}


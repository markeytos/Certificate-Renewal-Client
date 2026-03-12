using System.Security.Cryptography.X509Certificates;

namespace DotNetCertAuthSample.Services;

public class UnifiedStoreService : IStoreService
{
    public X509Certificate2Collection FindCertificatesByIssuer(
        string issuerName,
        bool localStore,
        string? password = null
    )
    {
        X509Store store = GetCertStore(localStore);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection certs = store.Certificates.Find(
            X509FindType.FindByIssuerName,
            issuerName,
            true
        );
        store.Close();
        return certs;
    }

    public X509Certificate2Collection FindCertificatesBySubject(
        string subjectName,
        bool localStore,
        string? password = null
    )
    {
        X509Store store = GetCertStore(localStore);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection certs = store.Certificates.Find(
            X509FindType.FindBySubjectName,
            subjectName,
            true
        );
        store.Close();
        return certs;
    }

    public X509Certificate2Collection FindCertificatesByTemplate(
        string templateName,
        bool localStore,
        string? password = null
    )
    {
        X509Store store = GetCertStore(localStore);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection certs = store.Certificates.Find(
            X509FindType.FindByTemplateName,
            templateName,
            true
        );
        store.Close();
        return certs;
    }

    public X509Certificate2Collection GetAllCertificatesInStore(
        bool localStore,
        string? password = null
    )
    {
        X509Store store = GetCertStore(localStore);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection certs = store.Certificates;
        store.Close();
        return certs;
    }

    public void WriteCertificateWithPrivateKeyToStore(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    )
    {
        if (!certificate.HasPrivateKey)
        {
            throw new Exception("Certificate does not have private key");
        }
        X509Store store = GetCertStore(localStore);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
        store.Close();
    }

    public static X509Store GetCertStore(bool localStore)
    {
        return new X509Store(
            StoreName.My,
            localStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser
        );
    }
}

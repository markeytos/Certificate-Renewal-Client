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
        X509Certificate2Collection certsSearch1 = store.Certificates.Find(
            X509FindType.FindByIssuerName,
            issuerName,
            true
        );
        X509Certificate2Collection certsSearch2 = store.Certificates.Find(
            X509FindType.FindByIssuerDistinguishedName,
            issuerName,
            true
        );
        X509Certificate2Collection certsSearch3 = FindByIssuerDistinguishedName(store, issuerName);
        store.Close();
        X509Certificate2[] allCerts = certsSearch1
            .Cast<X509Certificate2>()
            .Concat(certsSearch2.Cast<X509Certificate2>())
            .Concat(certsSearch3.Cast<X509Certificate2>())
            .DistinctBy(c => c.Thumbprint)
            .ToArray();
        return new X509Certificate2Collection(allCerts);
    }

    public X509Certificate2Collection FindCertificatesBySubject(
        string subjectName,
        bool localStore,
        string? password = null
    )
    {
        X509Store store = GetCertStore(localStore);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection certsSearch1 = store.Certificates.Find(
            X509FindType.FindBySubjectName,
            subjectName,
            true
        );
        X509Certificate2Collection certsSearch2 = store.Certificates.Find(
            X509FindType.FindBySubjectDistinguishedName,
            subjectName,
            true
        );
        X509Certificate2Collection certsSearch3 = FindBySubjectDistinguishedName(
            store,
            subjectName
        );
        store.Close();
        X509Certificate2[] allCerts = certsSearch1
            .Cast<X509Certificate2>()
            .Concat(certsSearch2.Cast<X509Certificate2>())
            .Concat(certsSearch3.Cast<X509Certificate2>())
            .DistinctBy(c => c.Thumbprint)
            .ToArray();
        return new X509Certificate2Collection(allCerts);
    }

    private static X509Certificate2Collection FindBySubjectDistinguishedName(
        X509Store store,
        string subjectName
    )
    {
        X509Certificate2Collection allCerts = store.Certificates;
        List<X509Certificate2> matchingCerts = allCerts
            .Where((cert) => CertUtils.MatchesSubjectDistinguishedName(cert, subjectName))
            .ToList();
        return new X509Certificate2Collection(matchingCerts.ToArray());
    }

    private static X509Certificate2Collection FindByIssuerDistinguishedName(
        X509Store store,
        string issuerName
    )
    {
        X509Certificate2Collection allCerts = store.Certificates;
        List<X509Certificate2> matchingCerts = allCerts
            .Where((cert) => CertUtils.MatchesIssuerDistinguishedName(cert, issuerName))
            .ToList();
        return new X509Certificate2Collection(matchingCerts.ToArray());
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
        return new X509Store(localStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
    }
}

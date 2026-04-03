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
        X509Store store = CertUtils.GetCertStore(localStore);
        X509Certificate2[] allCerts = [];
        store.Open(OpenFlags.ReadOnly);
        try
        {
            allCerts = FindCertificatesByIssuer(issuerName, store);
        }
        finally
        {
            store.Close();
        }
        return new X509Certificate2Collection(allCerts);
    }

    private static X509Certificate2[] FindCertificatesByIssuer(string issuerName, X509Store store)
    {
        X509Certificate2[] allCerts;
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
        allCerts = certsSearch1
            .Cast<X509Certificate2>()
            .Concat(certsSearch2.Cast<X509Certificate2>())
            .Concat(certsSearch3.Cast<X509Certificate2>())
            .DistinctBy(c => c.Thumbprint)
            .ToArray();
        return allCerts;
    }

    public List<X509Certificate2> GetUserCertificatesIssuedByCaSki(string caSki, bool localStore)
    {
        if (string.IsNullOrWhiteSpace(caSki))
            throw new ArgumentException("CA SKI cannot be null or empty.", nameof(caSki));

        string normalizedTargetSki = CertUtils.NormalizeHex(caSki);

        using X509Store store = CertUtils.GetCertStore(localStore);
        store.Open(OpenFlags.ReadOnly);

        List<X509Certificate2> certificates = store
            .Certificates.Cast<X509Certificate2>()
            .Where(cert =>
            {
                string authorityKeyId = CertUtils.GetAuthorityKeyIdentifier(cert);
                return !string.IsNullOrWhiteSpace(authorityKeyId)
                    && CertUtils.NormalizeHex(authorityKeyId) == normalizedTargetSki;
            })
            .ToList();
        store.Close();
        return certificates;
    }

    public X509Certificate2Collection FindCertificatesBySubject(
        string subjectName,
        bool localStore,
        string? password = null
    )
    {
        X509Store store = CertUtils.GetCertStore(localStore);
        X509Certificate2[] allCerts = [];
        store.Open(OpenFlags.ReadOnly);
        try
        {
            allCerts = FindCertificatesBySubject(subjectName, store);
        }
        finally
        {
            store.Close();
        }
        return new X509Certificate2Collection(allCerts);
    }

    private static X509Certificate2[] FindCertificatesBySubject(string subjectName, X509Store store)
    {
        X509Certificate2[] allCerts;
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
        allCerts = certsSearch1
            .Cast<X509Certificate2>()
            .Concat(certsSearch2.Cast<X509Certificate2>())
            .Concat(certsSearch3.Cast<X509Certificate2>())
            .DistinctBy(c => c.Thumbprint)
            .ToArray();
        return allCerts;
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
        X509Store store = CertUtils.GetCertStore(localStore);
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
        X509Store store = CertUtils.GetCertStore(localStore);
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
        X509Store store = CertUtils.GetCertStore(localStore);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
        store.Close();
    }
}

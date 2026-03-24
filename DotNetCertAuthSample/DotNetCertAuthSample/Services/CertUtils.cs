using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DotNetCertAuthSample.Services;

public static class CertUtils
{
    public static string GetOrGeneratePasswordForCert(string? password = null)
    {
        if (!string.IsNullOrWhiteSpace(password))
        {
            return password;
        }

        const string alphanumericCharacters =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        return RandomNumberGenerator.GetString(alphanumericCharacters, 30);
    }

    public static X509Certificate2 GetCertFromStore(
        IStoreService storeService,
        string subjectName,
        bool localStore,
        string issuerName = "",
        string templateName = "",
        string? password = null
    )
    {
        X509Certificate2Collection certs = storeService.FindCertificatesBySubject(
            subjectName,
            localStore,
            password
        );
        X509Certificate2? cert = null;
        if (certs.Count > 0)
        {
            if (!string.IsNullOrWhiteSpace(templateName))
            {
                cert = storeService
                    .FindCertificatesByTemplate(templateName, localStore, password)
                    .FirstOrDefault();
            }
            else if (!string.IsNullOrWhiteSpace(issuerName))
            {
                cert = storeService
                    .FindCertificatesByIssuer(issuerName, localStore, password)
                    .FirstOrDefault();
            }
            cert ??=
                certs
                    .OrderByDescending(x => x.NotAfter)
                    .FirstOrDefault(i => i.SubjectName.Name == subjectName)
                ?? certs.OrderByDescending(x => x.NotAfter).First();
        }
        else
        {
            List<X509Certificate2> matchingCertificates = [];
            X509Certificate2Collection allStoreCertificates =
                storeService.GetAllCertificatesInStore(localStore, password);
            foreach (
                X509Certificate2 storeCert in allStoreCertificates.OrderByDescending(i =>
                    i.NotAfter
                )
            )
            {
                if (
                    CheckCertificateTemplate(storeCert, templateName)
                    && CheckCertificateIssuer(storeCert, issuerName)
                    && storeCert.Subject.Contains(subjectName)
                )
                {
                    matchingCertificates.Add(storeCert);
                }
            }
            if (matchingCertificates.Count == 1)
            {
                cert = matchingCertificates[0];
            }
            else if (matchingCertificates.Count > 1)
            {
                cert =
                    matchingCertificates
                        .OrderByDescending(x => x.NotAfter)
                        .FirstOrDefault(i => i.SubjectName.Name == subjectName)
                    ?? matchingCertificates.OrderByDescending(x => x.NotAfter).First();
            }
        }
        if (cert == null)
        {
            throw new FileNotFoundException(
                $"Could not find certificate for domain {subjectName} in {StoreString(localStore)}"
            );
        }
        return cert;
    }

    public static string StoreString(bool localStore)
    {
        if (localStore)
        {
            return "local store";
        }
        return "user store";
    }

    public static bool CheckCertificateTemplate(X509Certificate2 cert, string templateName)
    {
        if (string.IsNullOrWhiteSpace(templateName))
        {
            return true;
        }
        string? certTemplateName = GetCertificateTemplateName(cert);
        return templateName.Equals(certTemplateName?.Trim());
    }

    public static bool CheckCertificateIssuer(X509Certificate2 cert, string issuerName)
    {
        if (string.IsNullOrWhiteSpace(issuerName))
        {
            return true;
        }
        return cert.Issuer.Contains(issuerName);
    }

    private static string? GetCertificateTemplateName(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value == "1.3.6.1.4.1.311.20.2")
            {
                AsnEncodedData asnData = new(extension.Oid, extension.RawData);
                return asnData.Format(true);
            }
        }
        return null;
    }
}

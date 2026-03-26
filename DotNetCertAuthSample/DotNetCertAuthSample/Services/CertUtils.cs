using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

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

    public static int GetKeyLength(X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);

        // RSA
        using RSA? rsa = cert.GetRSAPublicKey();
        if (rsa != null)
        {
            return rsa.KeySize;
        }

        // ECDSA
        using ECDsa? ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null)
            return ecdsa.KeySize;

        throw new ArgumentException("Certificate Key not supported");
    }

    public static int GetPercentageOfLifetimeLeft(X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        double totalLifetime = (cert.NotAfter - cert.NotBefore).TotalDays;
        double remainingLifetime = (cert.NotAfter - DateTime.UtcNow).TotalDays;
        if (totalLifetime <= 0)
        {
            return 0;
        }

        if (remainingLifetime <= 0)
        {
            return 0;
        }
        return (int)((remainingLifetime / totalLifetime) * 100);
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
                    .FirstOrDefault(i => MatchesSubjectDistinguishedName(i, subjectName))
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
                        .FirstOrDefault(i => MatchesSubjectDistinguishedName(i, subjectName))
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

    public static X509Store GetCertStore(bool localStore)
    {
        return new X509Store(localStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
    }

    public static string GetAuthorityKeyIdentifier(X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        try
        {
            X509Extension? extension = cert.Extensions["2.5.29.35"];
            if (extension is null || extension.RawData.Length == 0)
            {
                return string.Empty;
            }

            AsnReader reader = new(extension.RawData, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            Asn1Tag tag = sequence.PeekTag();

            // AuthorityKeyIdentifier ::= SEQUENCE {
            //   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
            //   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
            //   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
            // }
            //
            // We want [0], which is the keyIdentifier.
            if (tag is { TagClass: TagClass.ContextSpecific, TagValue: 0 })
            {
                byte[] keyIdentifier = sequence.ReadOctetString(
                    new Asn1Tag(TagClass.ContextSpecific, 0)
                );
                return Convert.ToHexString(keyIdentifier).ToLowerInvariant();
            }
        }
        catch 
        {
        }
       
        return string.Empty;
    }

    public static string NormalizeHex(string value) =>
        value
            .Replace(":", "", StringComparison.Ordinal)
            .Replace(" ", "", StringComparison.Ordinal)
            .Trim()
            .ToUpperInvariant();

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

    public static bool MatchesSubjectDistinguishedName(X509Certificate2 cert, string subjectName)
    {
        try
        {
            X509Name certSubjectDN = new(cert.Subject);
            X509Name inputSubjectDN = new(subjectName);
            if (!certSubjectDN.Equivalent(inputSubjectDN))
            {
                throw new Exception();
            }
            return true;
        }
        catch
        {
            string commonName = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.Equals(
                commonName,
                subjectName.Replace("CN=", "").Trim(),
                StringComparison.OrdinalIgnoreCase
            );
        }
    }

    public static bool MatchesIssuerDistinguishedName(X509Certificate2 cert, string issuerName)
    {
        try
        {
            X509Name certIssuerDN = new(cert.Issuer);
            X509Name inputIssuerDN = new(issuerName);
            if (!certIssuerDN.Equivalent(inputIssuerDN))
            {
                throw new Exception();
            }
            return true;
        }
        catch
        {
            string commonName = cert.GetNameInfo(X509NameType.SimpleName, true);
            return string.Equals(
                commonName,
                issuerName.Replace("CN=", "").Trim(),
                StringComparison.OrdinalIgnoreCase
            );
        }
    }
}

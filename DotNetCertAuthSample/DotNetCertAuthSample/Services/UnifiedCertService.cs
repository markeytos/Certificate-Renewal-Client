using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EZCAClient.Services;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DotNetCertAuthSample.Services;

public class UnifiedCertService(IStoreService storeService) : ICertStoreService
{
    public CsrData CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string keyProvider = "",
        X509KeyUsageFlags? keyUsage = null
    )
    {
        CryptoApiRandomGenerator randomGenerator = new();
        SecureRandom random = new(randomGenerator);
        KeyGenerationParameters keyGenerationParameters = new(random, keylength);
        RsaKeyPairGenerator keyPairGenerator = new();
        keyPairGenerator.Init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

        X509Name x509Name = new(subjectName);

        X509KeyUsage usage = ConvertKeyUsages(keyUsage);

        Pkcs10CertificationRequest pkcs10 = new(
            "SHA256WITHRSA",
            x509Name,
            keyPair.Public,
            CreateAttributes(sans, ekus, usage),
            keyPair.Private
        );

        StringBuilder csrPemBuilder = new();
        using (StringWriter stringWriter = new(csrPemBuilder))
        {
            PemWriter pemWriter = new(stringWriter);
            pemWriter.WriteObject(pkcs10);
        }

        return new CsrData { CsrPem = csrPemBuilder.ToString(), PrivateKeyContext = keyPair };
    }

    public static X509Certificate2 CopyPrivateKeyFromCsr(string cert, CsrData csrData)
    {
        if (csrData.PrivateKeyContext is not AsymmetricCipherKeyPair keyPair)
        {
            throw new ArgumentException("Invalid CSR context for Linux certificate installation");
        }

        X509Certificate2 certificate = CryptoStaticService.ImportCertFromPEMString(cert);

        RsaPrivateCrtKeyParameters rsaParams = (RsaPrivateCrtKeyParameters)keyPair.Private;
        RSA rsa = ConvertToDotnetRSA(rsaParams);

        X509Certificate2 certWithKey = certificate.CopyWithPrivateKey(rsa);
        return certWithKey;
    }

    public static void CreateDirectoryIfNotExists(string path)
    {
        if (!Directory.Exists(path))
        {
            Directory.CreateDirectory(path);
        }
    }

    public static string GetOrGeneratePasswordForCert(string? password)
    {
        if (!string.IsNullOrWhiteSpace(password))
        {
            return password;
        }

        const string alphanumericCharacters =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        return RandomNumberGenerator.GetString(alphanumericCharacters, 30);
    }

    private static X509KeyUsage ConvertKeyUsages(X509KeyUsageFlags? keyUsage)
    {
        if (keyUsage is null)
        {
            return new(X509KeyUsage.DigitalSignature | X509KeyUsage.KeyEncipherment);
        }
        int bitMask = 0;
        if (keyUsage.Value.HasFlag(X509KeyUsageFlags.DigitalSignature))
        {
            bitMask |= X509KeyUsage.DigitalSignature;
        }
        if (keyUsage.Value.HasFlag(X509KeyUsageFlags.KeyEncipherment))
        {
            bitMask |= X509KeyUsage.KeyEncipherment;
        }
        if (keyUsage.Value.HasFlag(X509KeyUsageFlags.KeyAgreement))
        {
            bitMask |= X509KeyUsage.KeyAgreement;
        }
        if (keyUsage.Value.HasFlag(X509KeyUsageFlags.DataEncipherment))
        {
            bitMask |= X509KeyUsage.DataEncipherment;
        }
        if (keyUsage.Value.HasFlag(X509KeyUsageFlags.KeyCertSign))
        {
            bitMask |= X509KeyUsage.KeyCertSign;
        }
        if (keyUsage.Value.HasFlag(X509KeyUsageFlags.CrlSign))
        {
            bitMask |= X509KeyUsage.CrlSign;
        }
        if (keyUsage.Value.HasFlag(X509KeyUsageFlags.EncipherOnly))
        {
            bitMask |= X509KeyUsage.EncipherOnly;
        }
        if (keyUsage.Value.HasFlag(X509KeyUsageFlags.DecipherOnly))
        {
            bitMask |= X509KeyUsage.DecipherOnly;
        }
        if (keyUsage.Value.HasFlag(X509KeyUsageFlags.NonRepudiation))
        {
            bitMask |= X509KeyUsage.NonRepudiation;
        }

        return new(bitMask);
    }

    public static AsymmetricCipherKeyPair GenerateKeyPair(int keylength)
    {
        CryptoApiRandomGenerator randomGenerator = new();
        SecureRandom random = new(randomGenerator);
        KeyGenerationParameters keyGenerationParameters = new(random, keylength);
        RsaKeyPairGenerator keyPairGenerator = new();
        keyPairGenerator.Init(keyGenerationParameters);
        return keyPairGenerator.GenerateKeyPair();
    }

    public static RSA ConvertToDotnetRSA(RsaPrivateCrtKeyParameters key)
    {
        RSAParameters rsaParams = new()
        {
            Modulus = key.Modulus.ToByteArrayUnsigned(),
            Exponent = key.PublicExponent.ToByteArrayUnsigned(),
            D = key.Exponent.ToByteArrayUnsigned(),
            P = key.P.ToByteArrayUnsigned(),
            Q = key.Q.ToByteArrayUnsigned(),
            DP = key.DP.ToByteArrayUnsigned(),
            DQ = key.DQ.ToByteArrayUnsigned(),
            InverseQ = key.QInv.ToByteArrayUnsigned(),
        };

        RSA rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);
        return rsa;
    }

    public void InstallCertificate(
        string cert,
        CsrData csrData,
        bool localStore,
        string? password = null
    )
    {
        X509Certificate2 certificate = CopyPrivateKeyFromCsr(cert, csrData);
        storeService.WriteCertificateWithPrivateKeyToStore(certificate, localStore, password);
    }

    public void InstallCertificateWithPrivateKey(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    )
    {
        storeService.WriteCertificateWithPrivateKeyToStore(certificate, localStore, password);
    }

    public static X509Certificate2 GetCertFromStoreBySubject(
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
                    .FindCertificatesByIssuer(templateName, localStore, password)
                    .FirstOrDefault();
            }
            cert ??=
                certs
                    .OrderByDescending(x => x.NotAfter)
                    .FirstOrDefault(i => i.SubjectName.Name == $"CN={subjectName}")
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
                        .FirstOrDefault(i => i.SubjectName.Name == $"CN={subjectName}")
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

    private static string StoreString(bool localStore)
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
                AsnEncodedData asnData = new AsnEncodedData(extension.Oid, extension.RawData);
                return asnData.Format(true);
            }
        }
        return null;
    }

    private static DerSet CreateAttributes(
        List<string> sans,
        List<string> ekus,
        X509KeyUsage keyUsage
    )
    {
        var attributes = new List<AttributePkcs>();

        if (sans.Count == 0)
        {
            return new DerSet(attributes.ToArray());
        }
        GeneralName[] generalNames = sans.Select(san => new GeneralName(GeneralName.DnsName, san))
            .ToArray();

        GeneralNames subjectAlternativeNames = new(generalNames);
        X509ExtensionsGenerator extensionsGenerator = new();
        extensionsGenerator.AddExtension(
            X509Extensions.SubjectAlternativeName,
            false,
            subjectAlternativeNames
        );

        if (ekus.Count > 0)
        {
            var ekuOids = ekus.Select(oid => new DerObjectIdentifier(oid)).ToArray();
            var extendedKeyUsage = new ExtendedKeyUsage(ekuOids);
            extensionsGenerator.AddExtension(
                X509Extensions.ExtendedKeyUsage,
                false,
                extendedKeyUsage
            );
        }

        extensionsGenerator.AddExtension(X509Extensions.KeyUsage, true, keyUsage);

        X509Extensions extensions = extensionsGenerator.Generate();
        AttributePkcs extensionRequest = new(
            PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
            new DerSet(extensions)
        );
        attributes.Add(extensionRequest);

        return new DerSet(attributes.ToArray());
    }
}

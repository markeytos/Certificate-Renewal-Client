using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

public class UnifiedCertStoreService(IStoreService storeService) : ICertStoreService
{
    private AsymmetricCipherKeyPair? _keyPair;

    public string CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string keyProvider = "",
        X509KeyUsageFlags? keyUsage = null,
        bool makePrivateKeyExportable = false
    )
    {
        AsymmetricCipherKeyPair keyPair = GenerateKeyPair(keylength);
        X509Name x509Name = new(subjectName);
        X509KeyUsage usage = ConvertDotnetKeyUsagesToBouncy(keyUsage);
        Pkcs10CertificationRequest pkcs10 = new(
            "SHA256WITHRSA",
            x509Name,
            keyPair.Public,
            CreateAttributes(sans, ekus, usage),
            keyPair.Private
        );

        string csrPem = ExportCSRToPem(pkcs10);
        _keyPair = keyPair;
        return csrPem;
    }

    public void InstallCertificate(X509Certificate2 cert, bool localStore, string? password = null)
    {
        X509Certificate2 certWithKey = AddPrivateKeyToCertificate(cert, localStore);
        InstallCertificateWithPrivateKey(certWithKey, localStore, password);
    }

    public void InstallCertificateWithPrivateKey(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    )
    {
        storeService.WriteCertificateWithPrivateKeyToStore(certificate, localStore, password);
    }

    public X509Certificate2 GetCertFromStore(
        string subjectName,
        bool localStore,
        string issuerName = "",
        string templateName = "",
        string? password = null
    )
    {
        return CertUtils.GetCertFromStore(
            storeService,
            subjectName,
            localStore,
            issuerName,
            templateName,
            password
        );
    }

    public List<X509Certificate2> GetUserCertificatesIssuedByCaSki(string caSki, bool localStore)
    {
        throw new NotImplementedException();
    }

    public RSA ConvertToDotnetRSA(RsaPrivateCrtKeyParameters key)
    {
        RSAParameters rsaParams = new()
        {
            Modulus = key.Modulus?.ToByteArrayUnsigned(),
            Exponent = key.PublicExponent?.ToByteArrayUnsigned(),
            D = key.Exponent?.ToByteArrayUnsigned(),
            P = key.P?.ToByteArrayUnsigned(),
            Q = key.Q.ToByteArrayUnsigned(),
            DP = key.DP.ToByteArrayUnsigned(),
            DQ = key.DQ.ToByteArrayUnsigned(),
            InverseQ = key.QInv.ToByteArrayUnsigned(),
        };

        RSA rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);
        return rsa;
    }

    public X509Certificate2 AddPrivateKeyToCertificate(
        X509Certificate2 certificate,
        bool localStore
    )
    {
        if (_keyPair is null)
        {
            throw new InvalidOperationException(
                "No key pair available for exporting certificate with private key"
            );
        }

        RsaPrivateCrtKeyParameters rsaParams = (RsaPrivateCrtKeyParameters)_keyPair.Private;
        RSA rsa = ConvertToDotnetRSA(rsaParams);
        return certificate.CopyWithPrivateKey(rsa);
    }

    private static string ExportCSRToPem(Pkcs10CertificationRequest pkcs10)
    {
        StringBuilder csrPemBuilder = new();
        using (StringWriter stringWriter = new(csrPemBuilder))
        {
            PemWriter pemWriter = new(stringWriter);
            pemWriter.WriteObject(pkcs10);
        }

        return csrPemBuilder.ToString();
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair(int keyLength)
    {
        CryptoApiRandomGenerator randomGenerator = new();
        SecureRandom random = new(randomGenerator);
        KeyGenerationParameters keyGenerationParameters = new(random, keyLength);
        if(keyLength >= 2048)
        {
            RsaKeyPairGenerator keyPairGenerator = new();
            keyPairGenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            return keyPair;
        }
        else
        {
            ECKeyPairGenerator ecKeyPairGenerator = new();
            ecKeyPairGenerator.Init(keyGenerationParameters);
            AsymmetricCipherKeyPair keyPair = ecKeyPairGenerator.GenerateKeyPair();
            return keyPair;
        }
    }

    private static X509KeyUsage ConvertDotnetKeyUsagesToBouncy(X509KeyUsageFlags? keyUsage)
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

    private static DerSet CreateAttributes(
        List<string> sans,
        List<string> ekus,
        X509KeyUsage keyUsage
    )
    {
        List<AttributePkcs> attributes = [];
        X509ExtensionsGenerator extensionsGenerator = new();

        if (sans.Count > 0)
        {
            AddSubjectAlternativeNames(extensionsGenerator, sans);
        }

        if (ekus.Count > 0)
        {
            AddEKUs(ekus, extensionsGenerator);
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

    private static void AddEKUs(List<string> ekus, X509ExtensionsGenerator extensionsGenerator)
    {
        DerObjectIdentifier[] ekuOids = ekus.Select(oid => new DerObjectIdentifier(oid)).ToArray();
        ExtendedKeyUsage extendedKeyUsage = new(ekuOids);
        extensionsGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, extendedKeyUsage);
    }

    private static void AddSubjectAlternativeNames(
        X509ExtensionsGenerator extensionsGenerator,
        List<string> sans
    )
    {
        GeneralName[] generalNames = sans.Select(san => new GeneralName(GeneralName.DnsName, san))
            .ToArray();

        GeneralNames subjectAlternativeNames = new(generalNames);

        extensionsGenerator.AddExtension(
            X509Extensions.SubjectAlternativeName,
            false,
            subjectAlternativeNames
        );
    }
}

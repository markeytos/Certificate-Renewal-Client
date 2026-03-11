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
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace DotNetCertAuthSample.Services;

public class MacCertStoreService : ICertStoreService
{
    public CsrData CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string keyProvider = "Microsoft Enhanced Cryptographic Provider v1.0",
        List<X509KeyUsageFlags>? keyUsageFlags = null
    )
    {
        // TODO: combine with Linux because same

        // Generate RSA key pair using BouncyCastle
        var randomGenerator = new Org.BouncyCastle.Crypto.Prng.CryptoApiRandomGenerator();
        var random = new SecureRandom(randomGenerator);
        var keyGenerationParameters = new KeyGenerationParameters(random, keylength);
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(keyGenerationParameters);
        var keyPair = keyPairGenerator.GenerateKeyPair();

        // Create X509Name from subject
        var x509Name = new X509Name(subjectName);

        // Create CSR
        var pkcs10 = new Pkcs10CertificationRequest(
            "SHA256WITHRSA",
            x509Name,
            keyPair.Public,
            CreateAttributes(sans, ekus),
            keyPair.Private
        );

        // Convert to PEM format
        StringBuilder csrPemBuilder = new();
        using (StringWriter stringWriter = new(csrPemBuilder))
        {
            PemWriter pemWriter = new(stringWriter);
            pemWriter.WriteObject(pkcs10);
        }

        return new CsrData { CsrPem = csrPemBuilder.ToString(), PrivateKeyContext = keyPair };
    }

    public X509Certificate2 GetCertFromStoreBySubject(
        string subjectName,
        bool localStore,
        string issuerName = "",
        string templateName = ""
    )
    {
        X509Store store = GetCertStore(localStore);
        try
        {
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2? certificate = store
                .Certificates.Find(X509FindType.FindBySubjectName, subjectName, validOnly: false)
                .OfType<X509Certificate2>()
                .FirstOrDefault(c =>
                    c.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase)
                );
            return certificate
                ?? throw new Exception(
                    $"Certificate with subject name '{subjectName}' not found in the store."
                );
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error opening certificate store: {ex.Message}");
            throw;
        }
    }

    public X509Certificate2 GetCertFromStoreByThumbprint(string thumbprint)
    {
        X509Store store = new(StoreName.My, StoreLocation.CurrentUser);
        try
        {
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2? certificate = store
                .Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .FirstOrDefault();
            return certificate
                ?? throw new Exception(
                    $"Certificate with thumbprint '{thumbprint}' not found in the store."
                );
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error opening certificate store: {ex.Message}");
            throw;
        }
    }

    public void InstallCertificate(string cert, CsrData csrData, bool localStore)
    {
        // TODO: combine with Linux because same
        if (csrData.PrivateKeyContext is not AsymmetricCipherKeyPair keyPair)
        {
            throw new ArgumentException("Invalid CSR context for Linux certificate installation");
        }
        X509Certificate2 certificate = CryptoStaticService.ImportCertFromPEMString(cert);
        RsaPrivateCrtKeyParameters rsaParams = (RsaPrivateCrtKeyParameters)keyPair.Private;
        RSA rsa = ConvertToRSA(rsaParams);

        var certWithKey = certificate.CopyWithPrivateKey(rsa);
        InstallCertificateWithPrivateKey(certWithKey, localStore);
    }

    public static RSA ConvertToRSA(RsaPrivateCrtKeyParameters key)
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

    public void InstallCertificateWithPrivateKey(X509Certificate2 certificate, bool localStore)
    {
        // TODO: combine with Linux because same
        X509Store store = GetCertStore(localStore);
        AssertCanWriteToStore(localStore);
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
        store.Close();
    }

    private static void AssertCanWriteToStore(bool localStore)
    {
        if (localStore && !IsRunningAsRoot())
        {
            throw new Exception(
                "Insufficient permissions to write to the local machine store. Please run the application with elevated permissions (i.e. 'sudo')"
            );
        }
    }

    private static bool IsRunningAsRoot()
    {
        return string.Equals(Environment.UserName, "root", StringComparison.OrdinalIgnoreCase);
    }

    private static X509Store GetCertStore(bool localStore)
    {
        return new X509Store(
            StoreName.My,
            localStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser
        );
    }

    private static DerSet CreateAttributes(List<string> sans, List<string> ekus)
    {
        // TODO: combine with Linux because same
        var attributes = new List<AttributePkcs>();

        // Add Subject Alternative Names extension
        if (sans.Any())
        {
            var generalNames = sans.Select(san => new GeneralName(GeneralName.DnsName, san))
                .ToArray();

            var subjectAlternativeNames = new GeneralNames(generalNames);
            var extensionsGenerator = new X509ExtensionsGenerator();
            extensionsGenerator.AddExtension(
                X509Extensions.SubjectAlternativeName,
                false,
                subjectAlternativeNames
            );

            // Add EKUs if specified
            if (ekus.Any())
            {
                var ekuOids = ekus.Select(oid => new DerObjectIdentifier(oid)).ToArray();
                var extendedKeyUsage = new ExtendedKeyUsage(ekuOids);
                extensionsGenerator.AddExtension(
                    X509Extensions.ExtendedKeyUsage,
                    false,
                    extendedKeyUsage
                );
            }

            // Add Key Usage
            extensionsGenerator.AddExtension(
                X509Extensions.KeyUsage,
                true,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment)
            );

            var extensions = extensionsGenerator.Generate();
            var extensionRequest = new AttributePkcs(
                PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                new DerSet(extensions)
            );
            attributes.Add(extensionRequest);
        }

        return new DerSet(attributes.ToArray());
    }

    private static void PrintCertificatesInStore(X509Store store)
    {
        Console.WriteLine($"Certificates in {store.Name} ({store.Location}) store:");
        try
        {
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in store.Certificates)
            {
                Console.WriteLine($"\t- Subject: {cert.Subject}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"Error accessing {store.Name} ({store.Location}) store: {ex.Message}"
            );
        }
    }
}

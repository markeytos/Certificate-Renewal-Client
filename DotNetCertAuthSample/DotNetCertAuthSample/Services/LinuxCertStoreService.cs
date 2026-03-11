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
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace DotNetCertAuthSample.Services;

public class LinuxCertStoreService : ICertStoreService
{
    private readonly string _userStorePath;
    private readonly string _machineStorePath = "/etc/keytos/certs";
    private readonly string _certEnding = "pfx";

    public LinuxCertStoreService()
    {
        string homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _userStorePath = Path.Combine(homeDir, ".local", "share", "keytos", "certs");

        CreateDirectoryIfNotExists(_userStorePath);
    }

    public X509Certificate2 GetCertFromStoreBySubject(
        string subjectName,
        bool localStore,
        string issuerName = "",
        string templateName = ""
    )
    {
        string storePath = GetStorePath(localStore);

        if (!Directory.Exists(storePath))
        {
            throw new FileNotFoundException(
                $"Could not find certificate for domain {subjectName} - store directory does not exist"
            );
        }

        List<X509Certificate2> matchingCerts = [];

        foreach (string certFile in Directory.GetFiles(storePath, $"*.{_certEnding}"))
        {
            try
            {
                X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile(
                    certFile,
                    "password"
                );

                if (
                    cert.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase)
                    || cert.SubjectName.Name.Contains(
                        subjectName,
                        StringComparison.OrdinalIgnoreCase
                    )
                )
                {
                    if (
                        !string.IsNullOrWhiteSpace(issuerName)
                        && !cert.Issuer.Contains(issuerName, StringComparison.OrdinalIgnoreCase)
                    )
                    {
                        continue;
                    }

                    matchingCerts.Add(cert);
                }
            }
            catch (Exception e)
            {
                // Skip invalid certificates
                Console.WriteLine(
                    $"Warning: Failed to load certificate from {certFile}. Exception: {e.Message}"
                );
                continue;
            }
        }

        if (matchingCerts.Count == 0)
        {
            throw new FileNotFoundException(
                $"Could not find certificate for domain {subjectName} in the {(localStore ? "machine" : "user")} store"
            );
        }

        // Return the most recent certificate
        return matchingCerts.OrderByDescending(c => c.NotAfter).First();
    }

    public X509Certificate2? GetCertFromStoreByThumbprint(string thumbprint)
    {
        List<bool> localStoreOptions = [true, false];
        foreach (bool localStore in localStoreOptions)
        {
            X509Certificate2? cert = GetCertFromStoreByThumbprint(thumbprint, localStore);
            if (cert is not null)
            {
                return cert;
            }
        }

        return null;
    }

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
        AsymmetricCipherKeyPair keyPair = GenerateKeyPair(keylength);
        X509Name x509Name = new(subjectName);

        // Create CSR
        Pkcs10CertificationRequest pkcs10 = new(
            "SHA256WITHRSA",
            x509Name,
            keyPair.Public,
            CreateAttributes(sans, ekus),
            keyPair.Private
        );

        // Convert to PEM format
        StringBuilder csrPemBuilder = new();
        using (var stringWriter = new StringWriter(csrPemBuilder))
        {
            var pemWriter = new PemWriter(stringWriter);
            pemWriter.WriteObject(pkcs10);
        }

        return new CsrData { CsrPem = csrPemBuilder.ToString(), PrivateKeyContext = keyPair };
    }

    public void InstallCertificate(string cert, CsrData csrData, bool localStore)
    {
        if (csrData.PrivateKeyContext is not AsymmetricCipherKeyPair keyPair)
        {
            throw new ArgumentException("Invalid CSR context for Linux certificate installation");
        }

        // Parse the certificate
        X509Certificate2 certificate = CryptoStaticService.ImportCertFromPEMString(cert);

        // Convert private key to RSA
        RsaPrivateCrtKeyParameters rsaParams = (RsaPrivateCrtKeyParameters)keyPair.Private;
        RSA rsa = ConvertToRSA(rsaParams);

        // Combine certificate with private key
        var certWithKey = certificate.CopyWithPrivateKey(rsa);
        InstallCertificateWithPrivateKey(certWithKey, localStore);
    }

    public void InstallCertificateWithPrivateKey(X509Certificate2 certificate, bool localStore)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must have a private key for installation");
        }

        string storePath = GetStorePath(localStore);
        CreateDirectoryIfNotExists(storePath);

        string filename = GetFileNameFromCertificate(certificate);
        string certPath = Path.Combine(storePath, filename);

        string password = "password";
        byte[] certBytes = certificate.Export(X509ContentType.Pfx, password);

        File.WriteAllBytes(certPath, certBytes);

        try
        {
            UnixFileMode fileInfo = new();
            fileInfo = UnixFileMode.UserRead | UnixFileMode.UserWrite;
#pragma warning disable CA1416 // Validate platform compatibility
            File.SetUnixFileMode(certPath, fileInfo);
#pragma warning restore CA1416 // Validate platform compatibility
        }
        catch (Exception e)
        {
            Console.WriteLine(
                $"Warning: Failed to set file permissions on {certPath}. Exception: {e.Message}"
            );
        }
    }

    private string GetFileNameFromCertificate(X509Certificate2 certificate)
    {
        return $"{SanitizeFilename(certificate.Subject)}_{certificate.Thumbprint}.{_certEnding}";
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

    private X509Certificate2? GetCertFromStoreByThumbprint(string thumbprint, bool localStore)
    {
        string storePath = GetStorePath(localStore);

        if (!Directory.Exists(storePath))
        {
            return null;
        }

        foreach (string certFile in Directory.GetFiles(storePath, $"*.{_certEnding}"))
        {
            try
            {
                X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(certFile);
                if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    return cert;
                }
            }
            catch
            {
                continue;
            }
        }

        return null;
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair(int keylength)
    {
        CryptoApiRandomGenerator randomGenerator = new();
        SecureRandom random = new(randomGenerator);
        KeyGenerationParameters keyGenerationParameters = new(random, keylength);
        RsaKeyPairGenerator keyPairGenerator = new();
        keyPairGenerator.Init(keyGenerationParameters);
        return keyPairGenerator.GenerateKeyPair();
    }

    private string GetStorePath(bool localStore)
    {
        if (localStore)
        {
            return _machineStorePath;
        }
        else
        {
            return _userStorePath;
        }
    }

    private static string SanitizeFilename(string filename)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var sanitized = new string(filename.Where(c => !invalidChars.Contains(c)).ToArray());
        return sanitized.Replace(" ", "_").Replace(",", "").Replace("CN=", "");
    }

    private static DerSet CreateAttributes(List<string> sans, List<string> ekus)
    {
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

    private static void CreateDirectoryIfNotExists(string path)
    {
        if (!Directory.Exists(path))
        {
            Directory.CreateDirectory(path);
        }
    }
}

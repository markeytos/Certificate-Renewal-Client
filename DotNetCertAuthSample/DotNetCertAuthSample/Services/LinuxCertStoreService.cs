using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace DotNetCertAuthSample.Services
{
    public class LinuxCertStoreService : ICertStoreService
    {
        private readonly string _certStorePath;

        public LinuxCertStoreService()
        {
            // Use standard Linux certificate store paths
            string homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            _certStorePath = Path.Combine(homeDir, ".ezca", "certs");
            
            // Create directory if it doesn't exist
            if (!Directory.Exists(_certStorePath))
            {
                Directory.CreateDirectory(_certStorePath);
            }
        }

        public X509Certificate2 GetCertFromStoreBySubject(
            string subjectName,
            bool localStore,
            string issuerName = "",
            string templateName = ""
        )
        {
            // On Linux, we'll search for certificates in our custom store
            string storePath = GetStorePath(localStore);
            
            if (!Directory.Exists(storePath))
            {
                throw new FileNotFoundException(
                    $"Could not find certificate for domain {subjectName} - store directory does not exist"
                );
            }

            var matchingCerts = new List<X509Certificate2>();

            foreach (var certFile in Directory.GetFiles(storePath, "*.pem"))
            {
                try
                {
                    var cert = new X509Certificate2(certFile);
                    
                    // Check if subject matches
                    if (cert.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase) ||
                        cert.SubjectName.Name.Contains(subjectName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Check issuer if specified
                        if (!string.IsNullOrWhiteSpace(issuerName) && 
                            !cert.Issuer.Contains(issuerName, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }
                        
                        matchingCerts.Add(cert);
                    }
                }
                catch
                {
                    // Skip invalid certificates
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
            foreach (var localStore in new[] { true, false })
            {
                string storePath = GetStorePath(localStore);
                
                if (!Directory.Exists(storePath))
                {
                    continue;
                }

                foreach (var certFile in Directory.GetFiles(storePath, "*.pem"))
                {
                    try
                    {
                        var cert = new X509Certificate2(certFile);
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
            }

            return null;
        }

        public CsrData CreateCSR(
            string subjectName,
            List<string> sans,
            int keylength,
            bool localStore,
            List<string> ekus,
            string keyProvider = "Microsoft Enhanced Cryptographic Provider v1.0"
        )
        {
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
            StringBuilder csrPemBuilder = new StringBuilder();
            using (var stringWriter = new StringWriter(csrPemBuilder))
            {
                var pemWriter = new PemWriter(stringWriter);
                pemWriter.WriteObject(pkcs10);
            }

            return new CsrData
            {
                CsrPem = csrPemBuilder.ToString(),
                PrivateKeyContext = keyPair
            };
        }

        public void InstallCertificate(string cert, CsrData csrData)
        {
            if (csrData.PrivateKeyContext is not AsymmetricCipherKeyPair keyPair)
            {
                throw new ArgumentException("Invalid CSR context for Linux certificate installation");
            }

            // Parse the certificate
            var certParser = new X509CertificateParser();
            byte[] certBytes = Encoding.UTF8.GetBytes(cert);
            X509Certificate bcCert = certParser.ReadCertificate(certBytes);

            // Convert BouncyCastle certificate to X509Certificate2
            var dotNetCert = new X509Certificate2(bcCert.GetEncoded());

            // Convert private key to RSA
            var rsaParams = (RsaPrivateCrtKeyParameters)keyPair.Private;
#pragma warning disable CA1416
            RSA rsa = DotNetUtilities.ToRSA(rsaParams);
#pragma warning restore CA1416

            // Combine certificate with private key
            var certWithKey = dotNetCert.CopyWithPrivateKey(rsa);

            // Determine if this should be stored in local (machine) or user store
            // For Linux, we'll use our custom file-based store
            bool localStore = true; // Default to machine store
            
            // Install the certificate
            InstallFullCertificate(certWithKey, localStore);
        }

        public void InstallFullCertificate(X509Certificate2 certificate, bool localStore)
        {
            string storePath = GetStorePath(localStore);
            
            // Create directory if it doesn't exist
            if (!Directory.Exists(storePath))
            {
                Directory.CreateDirectory(storePath);
            }

            // Generate filename from certificate subject and thumbprint
            string filename = SanitizeFilename(certificate.Subject) + "_" + certificate.Thumbprint + ".pem";
            string certPath = Path.Combine(storePath, filename);

            // Export certificate with private key
            byte[] certBytes = certificate.Export(X509ContentType.Pfx);
            
            // Save as PFX file
            File.WriteAllBytes(certPath, certBytes);

            // Set appropriate permissions on Linux
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                try
                {
                    // Set file permissions to 600 (owner read/write only)
                    var fileInfo = new UnixFileMode();
                    fileInfo = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                    File.SetUnixFileMode(certPath, fileInfo);
                }
                catch
                {
                    // Ignore if setting permissions fails
                }
            }
        }

        private string GetStorePath(bool localStore)
        {
            if (localStore)
            {
                // Machine-wide store
                return "/etc/ezca/certs";
            }
            else
            {
                // User store
                return _certStorePath;
            }
        }

        private static string SanitizeFilename(string filename)
        {
            // Remove invalid filename characters
            var invalidChars = Path.GetInvalidFileNameChars();
            var sanitized = new string(filename
                .Where(c => !invalidChars.Contains(c))
                .ToArray());
            return sanitized.Replace(" ", "_").Replace(",", "");
        }

        private static DerSet CreateAttributes(List<string> sans, List<string> ekus)
        {
            var attributes = new List<AttributePkcs>();

            // Add Subject Alternative Names extension
            if (sans.Any())
            {
                var generalNames = sans
                    .Select(san => new GeneralName(GeneralName.DnsName, san))
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
    }
}

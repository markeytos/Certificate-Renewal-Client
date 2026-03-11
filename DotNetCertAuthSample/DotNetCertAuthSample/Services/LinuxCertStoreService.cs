using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EZCAClient.Services;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

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
        string keyProvider = "",
        X509KeyUsageFlags? keyUsage = null
    )
    {
        return UnifiedCertService.CreateCSR(subjectName, sans, keylength, ekus, keyUsage);
    }

    public void InstallCertificate(string cert, CsrData csrData, bool localStore)
    {
        if (csrData.PrivateKeyContext is not AsymmetricCipherKeyPair keyPair)
        {
            throw new ArgumentException("Invalid CSR context for Linux certificate installation");
        }

        X509Certificate2 certificate = CryptoStaticService.ImportCertFromPEMString(cert);

        RsaPrivateCrtKeyParameters rsaParams = (RsaPrivateCrtKeyParameters)keyPair.Private;
        RSA rsa = UnifiedCertService.ConvertToDotnetRSA(rsaParams);

        X509Certificate2 certWithKey = certificate.CopyWithPrivateKey(rsa);
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

    private string GetStorePath(bool localStore)
    {
        return localStore ? _machineStorePath : _userStorePath;
    }

    private static string SanitizeFilename(string filename)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var sanitized = new string(filename.Where(c => !invalidChars.Contains(c)).ToArray());
        return sanitized.Replace(" ", "_").Replace(",", "").Replace("CN=", "");
    }

    private static void CreateDirectoryIfNotExists(string path)
    {
        if (!Directory.Exists(path))
        {
            Directory.CreateDirectory(path);
        }
    }
}

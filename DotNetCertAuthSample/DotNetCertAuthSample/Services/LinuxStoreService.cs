using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DotNetCertAuthSample.Services;

public class LinuxStoreService : IStoreService
{
    private readonly string _userStorePath;
    private readonly string _machineStorePath = "/etc/keytos/certs";
    private readonly string _certEnding = "pfx";

    public LinuxStoreService()
    {
        string homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _userStorePath = Path.Combine(homeDir, ".local", "share", "keytos", "certs");

        UnifiedCertService.CreateDirectoryIfNotExists(_userStorePath);
    }

    public X509Certificate2Collection FindCertificatesBySubject(
        string subjectName,
        bool localStore,
        string? password = null
    )
    {
        ValidatePassword(password);
        string storePath = ValidateAndGetStorePath(localStore);

        return FindCertificates(
            storePath,
            password!,
            cert =>
                cert.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase)
                || cert.SubjectName.Name.Contains(subjectName, StringComparison.OrdinalIgnoreCase)
        );
    }

    public X509Certificate2Collection FindCertificatesByTemplate(
        string templateName,
        bool localStore,
        string? password = null
    )
    {
        ValidatePassword(password);
        string storePath = ValidateAndGetStorePath(localStore);

        return FindCertificates(
            storePath,
            password!,
            cert =>
                cert.Extensions.FirstOrDefault(ext =>
                    ext.Oid != null
                    && (
                        ext.Oid.Value == "1.3.6.1.4.1.311.20.2"
                        || ext.Oid.Value == "1.3.6.1.4.1.311.21.7"
                    )
                ) != null
        );
    }

    public X509Certificate2Collection FindCertificatesByIssuer(
        string issuerName,
        bool localStore,
        string? password = null
    )
    {
        ValidatePassword(password);
        string storePath = ValidateAndGetStorePath(localStore);

        return FindCertificates(
            storePath,
            password!,
            cert =>
                cert.Issuer.Contains(issuerName, StringComparison.OrdinalIgnoreCase)
                || cert.IssuerName.Name.Contains(issuerName, StringComparison.OrdinalIgnoreCase)
        );
    }

    public X509Certificate2Collection GetAllCertificatesInStore(
        bool localStore,
        string? password = null
    )
    {
        string storePath = ValidateAndGetStorePath(localStore);
        ValidatePassword(password);
        return FindCertificates(storePath, password!, cert => true);
    }

    private static void ValidatePassword(string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException(
                "Password must be provided for template-based searches on Linux store"
            );
        }
    }

    private X509Certificate2Collection FindCertificates(
        string storePath,
        string password,
        Func<X509Certificate2, bool> matchFunc
    )
    {
        X509Certificate2Collection matchingCerts = [];
        foreach (string certFile in Directory.GetFiles(storePath, $"*.{_certEnding}"))
        {
            try
            {
                X509Certificate2 cert = X509CertificateLoader.LoadPkcs12FromFile(
                    certFile,
                    password
                );

                if (matchFunc(cert))
                {
                    matchingCerts.Add(cert);
                }
            }
            catch
            {
                continue;
            }
        }
        return matchingCerts;
    }

    public void WriteCertificateWithPrivateKeyToStore(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    )
    {
        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must have a private key for installation");
        }

        string storePath = GetStorePath(localStore);
        UnifiedCertService.CreateDirectoryIfNotExists(storePath);

        string certFilename = GetFileNameFromCertificate(certificate);
        string certPath = Path.Combine(storePath, certFilename);

        string passwordFileName = GetPasswordFileNameFromCertificate(certificate);
        string passwordPath = Path.Combine(storePath, passwordFileName);

        password = UnifiedCertService.GetOrGeneratePasswordForCert(password);
        byte[] certBytes = certificate.Export(X509ContentType.Pfx, password);

        File.WriteAllBytes(certPath, certBytes);
        File.WriteAllText(passwordPath, password);

        Console.WriteLine(
            $"Certificate installed at {certPath} with password stored at {passwordPath}"
        );

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
        return $"{certificate.Thumbprint}.{_certEnding}";
    }

    private static string GetPasswordFileNameFromCertificate(X509Certificate2 certificate)
    {
        return $"{certificate.Thumbprint}_password.txt";
    }

    private string GetStorePath(bool localStore)
    {
        return localStore ? _machineStorePath : _userStorePath;
    }

    private string ValidateAndGetStorePath(bool localStore)
    {
        string storePath = GetStorePath(localStore);

        if (!Directory.Exists(storePath))
        {
            throw new FileNotFoundException(
                $"Could not find {StoreString(localStore)} for searching - store directory does not exist"
            );
        }
        return storePath;
    }

    private static string StoreString(bool localStore)
    {
        if (localStore)
        {
            return "local store";
        }
        return "user store";
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EZCAClient.Services;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace DotNetCertAuthSample.Services;

public class MacCertStoreService : ICertStoreService
{
    public CsrData CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string keyProvider = "",
        X509KeyUsage? keyUsage = null
    )
    {
        return UnifiedCertService.CreateCSR(subjectName, sans, keylength, ekus, keyUsage);
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

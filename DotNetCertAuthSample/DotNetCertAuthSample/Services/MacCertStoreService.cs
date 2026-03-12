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
        X509KeyUsageFlags? keyUsages = null
    )
    {
        return UnifiedCertService.CreateCSR(subjectName, sans, keylength, ekus, keyUsages);
    }

    public X509Certificate2 GetCertFromStoreBySubject(
        string subjectName,
        bool localStore,
        string issuerName = "",
        string templateName = ""
    )
    {
        return UnifiedCertService.GetCertFromStoreBySubject(
            subjectName,
            localStore,
            issuerName,
            templateName
        );
    }

    public X509Certificate2 GetCertFromStoreByThumbprint(string thumbprint)
    {
        return UnifiedCertService.GetCertFromStoreByThumbprint(thumbprint);
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
        X509Store store = UnifiedCertService.GetCertStore(localStore);
        AssertCanWriteToStore(localStore);
        UnifiedCertService.WriteCertificateToStore(store, certificate);
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

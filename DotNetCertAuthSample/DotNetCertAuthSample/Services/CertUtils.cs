using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EZCAClient.Services;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace DotNetCertAuthSample.Services;

public static class CertUtils
{
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

    public static RSA ConvertToDotnetRSA(RsaPrivateCrtKeyParameters key)
    {
        RSAParameters rsaParams = new()
        {
            Modulus = key.Modulus?.ToByteArrayUnsigned(),
            Exponent = key.PublicExponent?.ToByteArrayUnsigned(),
            D = key.Exponent?.ToByteArrayUnsigned(),
        };

        if (key.P != null)
            rsaParams.P = key.P.ToByteArrayUnsigned();
        if (key.Q != null)
            rsaParams.Q = key.Q.ToByteArrayUnsigned();
        if (key.DP != null)
            rsaParams.DP = key.DP.ToByteArrayUnsigned();
        if (key.DQ != null)
            rsaParams.DQ = key.DQ.ToByteArrayUnsigned();
        if (key.QInv != null)
            rsaParams.InverseQ = key.QInv.ToByteArrayUnsigned();

        RSA rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);
        return rsa;
    }
}

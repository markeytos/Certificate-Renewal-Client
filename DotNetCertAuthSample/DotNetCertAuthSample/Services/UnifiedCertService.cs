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

public class UnifiedCertService
{
    public static CsrData CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        List<string> ekus,
        X509KeyUsage? keyUsage = null
    )
    {
        CryptoApiRandomGenerator randomGenerator = new();
        SecureRandom random = new(randomGenerator);
        KeyGenerationParameters keyGenerationParameters = new(random, keylength);
        RsaKeyPairGenerator keyPairGenerator = new();
        keyPairGenerator.Init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

        X509Name x509Name = new(subjectName);

        X509KeyUsage usage =
            keyUsage ?? new(X509KeyUsage.DigitalSignature | X509KeyUsage.KeyEncipherment);

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


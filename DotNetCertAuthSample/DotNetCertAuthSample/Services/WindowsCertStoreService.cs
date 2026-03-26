#if WINDOWS
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CERTENROLLLib;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using X509KeyUsageFlags = System.Security.Cryptography.X509Certificates.X509KeyUsageFlags;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using EZCAClient.Services;

namespace DotNetCertAuthSample.Services;

public class WindowsCertService(IStoreService storeService) : ICertStoreService
{
    private CX509CertificateRequestPkcs10? _certRequest;
    private CX509Enrollment? _objEnroll;

    public string CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string KeyProvider = "Microsoft Enhanced Cryptographic Provider v1.0",
        X509KeyUsageFlags? keyUsageFlags = null,
        bool makePrivateKeyExportable = false
    )
    {
        CX509CertificateRequestPkcs10 certRequest = new();
        certRequest.Initialize(
            localStore
                ? X509CertificateEnrollmentContext.ContextMachine
                : X509CertificateEnrollmentContext.ContextUser
        );
        if (makePrivateKeyExportable)
        {
            certRequest.PrivateKey.ExportPolicy =
                X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG
                | X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        }
        else
        {
            certRequest.PrivateKey.ExportPolicy =
                X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_NONE;
        }
        certRequest.PrivateKey.Length = keylength;
        certRequest.PrivateKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
        certRequest.PrivateKey.KeySpec = X509KeySpec.XCN_AT_NONE;
        certRequest.PrivateKey.MachineContext = localStore;
        certRequest.PrivateKey.ProviderName = KeyProvider;
        certRequest.PrivateKey.Create();
        CX500DistinguishedName objDN = new();
        certRequest.X509Extensions.Add((CX509Extension)CreateSans(sans));
        objDN.Encode(subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);
        certRequest.Subject = objDN;
        // Key Usage Extension
        CX509ExtensionKeyUsage extensionKeyUsage = new CX509ExtensionKeyUsage();
        // Use provided key usage flags or default to DigitalSignature and KeyEncipherment
        CERTENROLLLib.X509KeyUsageFlags usageFlags = ConvertKeyUsageFlags(keyUsageFlags);
        extensionKeyUsage.InitializeEncode(usageFlags);

        certRequest.X509Extensions.Add((CX509Extension)extensionKeyUsage);

        // Enhanced Key Usage Extension
        CObjectIds objectIds = new();
        if (ekus.Any())
        {
            CX509ExtensionEnhancedKeyUsage x509ExtensionEnhancedKeyUsage = new();
            foreach (string eku in ekus)
            {
                CObjectId ekuObjectId = new();
                ekuObjectId.InitializeFromValue(eku);
                objectIds.Add(ekuObjectId);
            }
            x509ExtensionEnhancedKeyUsage.InitializeEncode(objectIds);
            certRequest.X509Extensions.Add((CX509Extension)x509ExtensionEnhancedKeyUsage);
        }

        certRequest.Encode();
        _certRequest = certRequest;
        return certRequest.RawData[EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER];
    }

    public List<X509Certificate2> GetCertificatesIssuedByCaSki(string caSki, bool localStore)
    {
        return  CertUtils.GetCACertificates(caSki, localStore);
    }

    public void InstallCertificate(X509Certificate2 cert, bool localStore, string? password = null)
    {
        if (_certRequest is null)
        {
            throw new InvalidOperationException(
                "CSR must be created before installing a certificate."
            );
        }
        string pem = CryptoStaticService.ExportToPEM(cert);
        CX509Enrollment objEnroll = new();
        objEnroll.InitializeFromRequest(_certRequest);
        objEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);
        objEnroll.InstallResponse(
            InstallResponseRestrictionFlags.AllowUntrustedRoot,
            pem,
            EncodingType.XCN_CRYPT_STRING_BASE64HEADER,
            null
        );
        _objEnroll = objEnroll;
    }

    public void InstallCertificateWithPrivateKey(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    )
    {
        string tempPassword = CertUtils.GetOrGeneratePasswordForCert();
        byte[] pfx = certificate.Export(X509ContentType.Pfx, tempPassword);
        X509KeyStorageFlags flags = localStore
            ? X509KeyStorageFlags.MachineKeySet
            : X509KeyStorageFlags.UserKeySet;
        certificate = X509CertificateLoader.LoadPkcs12(pfx, tempPassword, flags);
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

    public X509Certificate2 AddPrivateKeyToCertificate(
        X509Certificate2 certificate,
        bool localStore
    )
    {
        if (_objEnroll is null)
        {
            throw new InvalidOperationException(
                "CSR must be created before adding a private key to a certificate."
            );
        }
        string password = CertUtils.GetOrGeneratePasswordForCert();
        string pfxBase64 = _objEnroll.CreatePFX(
            password,
            PFXExportOptions.PFXExportChainWithRoot,
            EncodingType.XCN_CRYPT_STRING_BASE64
        );
        byte[] pfxBytes = Convert.FromBase64String(pfxBase64);
        X509Certificate2 certWithKey = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            password,
            X509KeyStorageFlags.Exportable
        );
        return certWithKey;
    }

    public RSA ConvertToDotnetRSA(RsaPrivateCrtKeyParameters rsaParams)
    {
        return DotNetUtilities.ToRSA(rsaParams);
    }

    private static CX509ExtensionAlternativeNames CreateSans(List<string> sans)
    {
        CAlternativeNames objAlternativeNames = new();
        CX509ExtensionAlternativeNames objExtensionAlternativeNames = new();

        foreach (string sanSTR in sans)
        {
            CAlternativeName san = new();
            san.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME, sanSTR);
            objAlternativeNames.Add(san);
        }
        objExtensionAlternativeNames.InitializeEncode(objAlternativeNames);
        return objExtensionAlternativeNames;
    }

    public static CERTENROLLLib.X509KeyUsageFlags? GetKeyUsages(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.15") // Key Usage OID
            {
                if (extension is not X509KeyUsageExtension keyUsageExt)
                {
                    continue;
                }

                return ConvertKeyUsage(keyUsageExt.KeyUsages);
            }
        }
        return null;
    }

    private static CERTENROLLLib.X509KeyUsageFlags ConvertKeyUsage(X509KeyUsageFlags keyUsageFlags)
    {
        CERTENROLLLib.X509KeyUsageFlags flags = 0;

        if (keyUsageFlags.HasFlag(X509KeyUsageFlags.DigitalSignature))
        {
            flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE;
        }
        if (keyUsageFlags.HasFlag(X509KeyUsageFlags.NonRepudiation))
        {
            flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_NON_REPUDIATION_KEY_USAGE;
        }
        if (keyUsageFlags.HasFlag(X509KeyUsageFlags.KeyEncipherment))
        {
            flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE;
        }
        if (keyUsageFlags.HasFlag(X509KeyUsageFlags.DataEncipherment))
        {
            flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE;
        }
        if (keyUsageFlags.HasFlag(X509KeyUsageFlags.KeyAgreement))
        {
            flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_AGREEMENT_KEY_USAGE;
        }
        if (keyUsageFlags.HasFlag(X509KeyUsageFlags.KeyCertSign))
        {
            flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE;
        }
        if (keyUsageFlags.HasFlag(X509KeyUsageFlags.CrlSign))
        {
            flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE;
        }
        if (keyUsageFlags.HasFlag(X509KeyUsageFlags.EncipherOnly))
        {
            flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_ENCIPHER_ONLY_KEY_USAGE;
        }
        if (keyUsageFlags.HasFlag(X509KeyUsageFlags.DecipherOnly))
        {
            flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DECIPHER_ONLY_KEY_USAGE;
        }

        return flags;
    }

    private CERTENROLLLib.X509KeyUsageFlags ConvertKeyUsageFlags(X509KeyUsageFlags? keyUsageFlags)
    {
        if (keyUsageFlags == null)
        {
            return CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE
                | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE;
        }

        return ConvertKeyUsage((X509KeyUsageFlags)keyUsageFlags);
    }
}
#endif

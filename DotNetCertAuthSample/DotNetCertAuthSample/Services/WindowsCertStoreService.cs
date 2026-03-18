#if WINDOWS
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CERTENROLLLib;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using X509KeyUsageFlags = System.Security.Cryptography.X509Certificates.X509KeyUsageFlags;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace DotNetCertAuthSample.Services;

public class WindowsCertService(IStoreService storeService) : ICertStoreService
{
    public CsrData CreateCSR(
        string subjectName,
        List<string> sans,
        int keylength,
        bool localStore,
        List<string> ekus,
        string KeyProvider = "Microsoft Enhanced Cryptographic Provider v1.0",
        X509KeyUsageFlags? keyUsageFlags = null
    )
    {
        CX509CertificateRequestPkcs10 certRequest = new();
        certRequest.Initialize(
            localStore
                ? X509CertificateEnrollmentContext.ContextMachine
                : X509CertificateEnrollmentContext.ContextUser
        );
        certRequest.PrivateKey.ExportPolicy =
            X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_NONE;
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

        return new CsrData
        {
            CsrPem = certRequest.RawData[EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER],
            PrivateKeyContext = certRequest,
        };
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

    public void InstallCertificate(
        string cert,
        CsrData csrData,
        bool localStore,
        string? password = null
    )
    {
        if (csrData.PrivateKeyContext is not CX509CertificateRequestPkcs10 certRequest)
        {
            throw new ArgumentException("Invalid CSR context for Windows certificate installation");
        }

        CX509Enrollment objEnroll = new();
        objEnroll.InitializeFromRequest(certRequest);
        objEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);
        objEnroll.InstallResponse(
            InstallResponseRestrictionFlags.AllowUntrustedRoot,
            cert,
            EncodingType.XCN_CRYPT_STRING_BASE64HEADER,
            null
        );
    }

    public void InstallCertificateWithPrivateKey(
        X509Certificate2 certificate,
        bool localStore,
        string? password = null
    )
    {
        certificate = LoadPrivateKeyToStore(certificate, localStore);
        storeService.WriteCertificateWithPrivateKeyToStore(certificate, localStore, password);
    }

    public RSA ConvertToDotnetRSA(RsaPrivateCrtKeyParameters rsaParams)
    {
        return DotNetUtilities.ToRSA(rsaParams);
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

    private static X509Certificate2 LoadPrivateKeyToStore(
        X509Certificate2 certificate,
        bool localStore
    )
    {
        // Generate a random password for temporary PFX export/import
        string tempPassword = CertUtils.GetOrGeneratePasswordForCert();
        byte[] pfx = certificate.Export(X509ContentType.Pfx, tempPassword);
        X509KeyStorageFlags flags = localStore
            ? X509KeyStorageFlags.MachineKeySet
            : X509KeyStorageFlags.UserKeySet;
        certificate = X509CertificateLoader.LoadPkcs12(pfx, tempPassword, flags);
        return certificate;
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
}
#endif

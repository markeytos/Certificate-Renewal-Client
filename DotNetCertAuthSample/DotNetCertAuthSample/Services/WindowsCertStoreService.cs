using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CERTENROLLLib;
using X509KeyUsageFlags = System.Security.Cryptography.X509Certificates.X509KeyUsageFlags;

namespace DotNetCertAuthSample.Services
{
    public static class WindowsCertStoreService
    {
        public static X509Certificate2 GetCertFromWinStoreBySubject(
            string subjectName,
            bool localStore,
            string issuerName = "",
            string templateName = ""
        )
        {
            X509Store store;
            if (localStore)
            {
                store = new(StoreLocation.LocalMachine);
            }
            else
            {
                store = new(StoreLocation.CurrentUser);
            }
            X509Certificate2? cert = null;
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(
                X509FindType.FindBySubjectName,
                subjectName,
                true
            );
            if (certs.Count > 0)
            {
                if (!string.IsNullOrWhiteSpace(templateName))
                {
                    cert = certs
                        .Find(X509FindType.FindByTemplateName, templateName, true)
                        .FirstOrDefault();
                }
                else if (!string.IsNullOrWhiteSpace(issuerName))
                {
                    cert = certs
                        .Find(X509FindType.FindByIssuerName, issuerName, true)
                        .FirstOrDefault();
                }
                cert ??=
                    certs
                        .OrderByDescending(x => x.NotAfter)
                        .FirstOrDefault(i => i.SubjectName.Name == $"CN={subjectName}")
                    ?? certs.OrderByDescending(x => x.NotAfter).First();
            }
            else
            {
                List<X509Certificate2> matchingCertificates = new();
                X509Certificate2Collection allStoreCertificates = store.Certificates;
                foreach (
                    X509Certificate2 storeCert in allStoreCertificates.OrderByDescending(i =>
                        i.NotAfter
                    )
                )
                {
                    if (
                        CheckCertificateTemplate(storeCert, templateName)
                        && CheckCertificateIssuer(storeCert, issuerName)
                        && storeCert.Subject.Contains(subjectName)
                    )
                    {
                        matchingCertificates.Add(storeCert);
                    }
                }
                if (matchingCertificates.Count == 1)
                {
                    cert = matchingCertificates[0];
                }
                else if (matchingCertificates.Count > 1)
                {
                    cert =
                        matchingCertificates
                            .OrderByDescending(x => x.NotAfter)
                            .FirstOrDefault(i => i.SubjectName.Name == $"CN={subjectName}")
                        ?? matchingCertificates.OrderByDescending(x => x.NotAfter).First();
                }
            }
            if (cert == null)
            {
                throw new FileNotFoundException(
                    $"Could not find certificate for domain {subjectName} "
                        + $"in the {StoreString(localStore)}"
                );
            }
            return cert;
        }

        public static X509Certificate2? GetCertFromWinStoreBythumbprint(string thumbprint)
        {
            //not recommended since it breaks with auto rotation
            X509Store store = new(StoreLocation.CurrentUser);
            X509Certificate2? cert = null;
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                thumbprint,
                true
            );
            if (certs.Count > 0)
            {
                cert = certs[0];
            }
            return cert;
        }

        public static CX509CertificateRequestPkcs10 CreateCSR(
            string subjectName,
            List<string> sans,
            int keylength,
            bool localStore,
            List<string> ekus,
            string KeyProvider = "Microsoft Enhanced Cryptographic Provider v1.0",
            CERTENROLLLib.X509KeyUsageFlags? keyUsageFlags = null
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
            var objDN = new CX500DistinguishedName();
            certRequest.X509Extensions.Add((CX509Extension)CreateSans(sans));
            objDN.Encode(subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            certRequest.Subject = objDN;
            // Key Usage Extension
            CX509ExtensionKeyUsage extensionKeyUsage = new CX509ExtensionKeyUsage();
            // Use provided key usage flags or default to DigitalSignature and KeyEncipherment
            CERTENROLLLib.X509KeyUsageFlags usageFlags = keyUsageFlags ??
                (CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE
                    | CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE);
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
            return certRequest;
        }

        public static void InstallCertificate(
            string cert,
            CX509CertificateRequestPkcs10 certRequest
        )
        {
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

        public static void InstallFullCertificate(X509Certificate2 certificate, bool localStore)
        {
            X509Store store =
                new(localStore ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Add(certificate);
            store.Close();
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

        private static string StoreString(bool localStore)
        {
            if (localStore)
            {
                return "local store";
            }
            return "user store";
        }

        private static bool CheckCertificateTemplate(X509Certificate2 cert, string templateName)
        {
            if (string.IsNullOrWhiteSpace(templateName))
            {
                return true;
            }
            string? certTemplateName = GetCertificateTemplateName(cert);
            return templateName.Equals(certTemplateName?.Trim());
        }

        private static bool CheckCertificateIssuer(X509Certificate2 cert, string issuerName)
        {
            if (string.IsNullOrWhiteSpace(issuerName))
            {
                return true;
            }
            return cert.Issuer.Contains(issuerName);
        }

        private static string? GetCertificateTemplateName(X509Certificate2 certificate)
        {
            foreach (var extension in certificate.Extensions)
            {
                if (extension.Oid?.Value == "1.3.6.1.4.1.311.20.2")
                {
                    AsnEncodedData asnData = new AsnEncodedData(extension.Oid, extension.RawData);
                    return asnData.Format(true);
                }
            }
            return null;
        }

        public static CERTENROLLLib.X509KeyUsageFlags? GetKeyUsages(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            foreach (var extension in certificate.Extensions)
            {
                if (extension.Oid?.Value == "2.5.29.15") // Key Usage OID
                {
                    if (extension is not X509KeyUsageExtension keyUsageExt)
                    {
                        continue;
                    }
                    
                    CERTENROLLLib.X509KeyUsageFlags flags = 0;

                    if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
                    {
                        flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE;
                    }
                    if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation))
                    {
                        flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_NON_REPUDIATION_KEY_USAGE;
                    }
                    if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment))
                    {
                        flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE;
                    }
                    if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.DataEncipherment))
                    {
                        flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE;
                    }
                    if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.KeyAgreement))
                    {
                        flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_AGREEMENT_KEY_USAGE;
                    }
                    if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
                    {
                        flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE;
                    }
                    if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign))
                    {
                        flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_CRL_SIGN_KEY_USAGE;
                    }
                    if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.EncipherOnly))
                    {
                        flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_ENCIPHER_ONLY_KEY_USAGE;
                    }
                    if (keyUsageExt.KeyUsages.HasFlag(X509KeyUsageFlags.DecipherOnly))
                    {
                        flags |= CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DECIPHER_ONLY_KEY_USAGE;
                    }

                    return flags;
                }
            }
            return null;
        }
    }
}

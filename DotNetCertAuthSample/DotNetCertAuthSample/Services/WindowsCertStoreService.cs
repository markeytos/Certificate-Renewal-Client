using CERTENROLLLib;
using System.Security.Cryptography.X509Certificates;

namespace DotNetCertAuthSample.Services
{
    public static class WindowsCertStoreService
    {
        public static X509Certificate2 GetCertFromWinStoreBySubject(string subjectName, bool localStore)
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
                X509FindType.FindBySubjectName, subjectName, true);
            if (certs.Count > 0)
            {
                cert = certs.OrderByDescending(i => i.NotAfter).First();
            }
            else
            {
                X509Certificate2Collection allStoreCertificates = store.Certificates;
                foreach (X509Certificate2 storeCert in allStoreCertificates.OrderByDescending(i => i.NotAfter))
                {
                    if (storeCert.Subject.Contains(subjectName))
                    {
                        cert = storeCert;
                        break;
                    }
                }
            }
            if (cert == null)
            {
                throw new FileNotFoundException($"Could not find certificate for domain {subjectName} " +
                    $"in the {StoreString(localStore)}");
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
                X509FindType.FindByThumbprint, thumbprint, true);
            if (certs.Count > 0)
            {
                cert = certs[0];
            }
            return cert;
        }

        public static CX509CertificateRequestPkcs10 CreateCSR(string subjectName, 
            List<string> sans, int keylength, bool localStore, List<string> ekus)
        {
            CX509CertificateRequestPkcs10 certRequest = new ();
            if(localStore)
            {
                certRequest.Initialize(X509CertificateEnrollmentContext.ContextMachine);
            }
            else
            {
                certRequest.Initialize(X509CertificateEnrollmentContext.ContextUser);
            }
            certRequest.PrivateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_NONE;
            certRequest.PrivateKey.Length = keylength;
            certRequest.PrivateKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
            certRequest.PrivateKey.KeySpec = X509KeySpec.XCN_AT_NONE;
            certRequest.PrivateKey.MachineContext = localStore;
            certRequest.PrivateKey.Create();
            var objDN = new CX500DistinguishedName();
            certRequest.X509Extensions.Add((CX509Extension)CreateSans(sans));
            objDN.Encode(subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            certRequest.Subject = objDN;
            // Key Usage Extension 
            CX509ExtensionKeyUsage extensionKeyUsage = new CX509ExtensionKeyUsage();
            extensionKeyUsage.InitializeEncode(
                CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
                CERTENROLLLib.X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE 
            );

            certRequest.X509Extensions.Add((CX509Extension)extensionKeyUsage);

            // Enhanced Key Usage Extension
            CObjectIds objectIds = new ();
            if(ekus.Any())
            {
                CX509ExtensionEnhancedKeyUsage x509ExtensionEnhancedKeyUsage = new();
                foreach(string eku in ekus)
                {
                    CObjectId ekuObjectId = new ();
                    ekuObjectId.InitializeFromValue(eku);
                    objectIds.Add(ekuObjectId);
                }
                x509ExtensionEnhancedKeyUsage.InitializeEncode(objectIds);
                certRequest.X509Extensions.Add((CX509Extension)x509ExtensionEnhancedKeyUsage);
            }
            certRequest.Encode();
            return certRequest;
        }

        public static void InstallCertificate(string cert, CX509CertificateRequestPkcs10 certRequest)
        {
            CX509Enrollment objEnroll = new ();
            objEnroll.InitializeFromRequest(certRequest);
            objEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);
            objEnroll.InstallResponse(
                InstallResponseRestrictionFlags.AllowUntrustedRoot,
                cert,
                EncodingType.XCN_CRYPT_STRING_BASE64HEADER,
                null
            );
        }

        private static CX509ExtensionAlternativeNames CreateSans(List<string> sans)
        {
            CAlternativeNames objAlternativeNames = new ();
            CX509ExtensionAlternativeNames objExtensionAlternativeNames = new();

            foreach (string sanSTR in sans)
            {
                CAlternativeName san = new ();
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
    }
}

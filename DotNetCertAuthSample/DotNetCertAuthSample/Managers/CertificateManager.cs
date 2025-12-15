using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using CommandLine;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using EZCAClient.Managers;
using EZCAClient.Models;
using EZCAClient.Services;
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using ContentInfo = System.Security.Cryptography.Pkcs.ContentInfo;
using SignerInfo = System.Security.Cryptography.Pkcs.SignerInfo;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace DotNetCertAuthSample.Managers;

public class CertificateManager
{
    private ILogger? _logger;
    private RenewArgModel? _renewArgModel;
    private GenerateArgModel? _generateArgModel;
    private RegisterArgModel? _registerArgModel;
    private CreateDCCertificate? _createDCCertArgModel;
    private SCEPArgModel? _scepArgModel;
    private HttpClient _httpClient = new();
    private TelemetryClient? _telemetryClient;
    private readonly ICertStoreService _certStoreService;
    private readonly ISystemInfoService _systemInfoService;

    public CertificateManager(ICertStoreService certStoreService, ISystemInfoService systemInfoService)
    {
        _certStoreService = certStoreService;
        _systemInfoService = systemInfoService;
    }

    public int InitializeManager(RenewArgModel values)
    {
        _logger = CreateLogger(values.AppInsightsKey);
        _renewArgModel = values;
        return 0;
    }

    public int InitializeManager(GenerateArgModel values)
    {
        _logger = CreateLogger(values.AppInsightsKey);
        _generateArgModel = values;
        return 0;
    }

    public int InitializeManager(RegisterArgModel values)
    {
        _logger = CreateLogger(values.AppInsightsKey);
        _registerArgModel = values;
        return 0;
    }

    public int InitializeManager(CreateDCCertificate values)
    {
        _logger = CreateLogger(values.AppInsightsKey);
        if (!string.IsNullOrWhiteSpace(values.EKUsInputs))
        {
            values.EKUs = values.EKUsInputs.Split(',').ToList();
        }
        _createDCCertArgModel = values;
        return 0;
    }

    public int InitializeManager(SCEPArgModel values)
    {
        _logger = CreateLogger(values.AppInsightsKey);
        if (!string.IsNullOrWhiteSpace(values.EKUsInputs))
        {
            values.EKUs = values.EKUsInputs.Split(',').ToList();
        }
        _scepArgModel = values;
        return 0;
    }

    public int ProcessError(IEnumerable<Error> errs)
    {
        return 1;
    }

    public async Task<int> CallCertActionAsync()
    {
        int response = -1;
        if (_renewArgModel != null)
        {
            response = await RenewAsync(_renewArgModel);
        }
        else if (_generateArgModel != null)
        {
            response = await CreateCertAsync(_generateArgModel);
        }
        else if (_registerArgModel != null)
        {
            response = await RegisterAndCreateCertAsync(_registerArgModel);
        }
        else if (_createDCCertArgModel != null)
        {
            response = await CreateDCCertAsync(_createDCCertArgModel);
        }
        else if (_scepArgModel != null)
        {
            response = await CreateSCEPCertificate(_scepArgModel);
        }
        if (_telemetryClient != null)
        {
            await _telemetryClient.FlushAsync(CancellationToken.None);
            Thread.Sleep(5000);
        }
        return response;
    }

    private async Task<int> RenewAsync(RenewArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }
        try
        {
            _logger.LogInformation("Renewing certificate for {Domain}", values.Domain);
            if (values is { RDPCert: true, LocalCertStore: false })
            {
                throw new ArgumentException(
                    "If certificate will be used for RDP it must be stored in the local store"
                );
            }
            if (string.IsNullOrWhiteSpace(values.Domain))
            {
                throw new ArgumentNullException(nameof(values.Domain));
            }
            if (values.KeyLength != 2048 && values.KeyLength != 4096)
            {
                throw new ArgumentException("Key length must be 2048 or 4096");
            }
            X509Certificate2 cert = _certStoreService.GetCertFromStoreBySubject(
                values.Domain.Replace("CN=", "").Trim(),
                values.LocalCertStore,
                values.issuer,
                values.template
            );
            CsrData csrData = _certStoreService.CreateCSR(
                cert.SubjectName.Name,
                GetSubjectAlternativeNames(cert)
                    .Where(i => i.Type == SANTypes.DNSName)
                    .Select(i => i.Value)
                    .ToList(),
                values.KeyLength,
                values.LocalCertStore,
                new(),
                values.KeyProvider
            );
            string csr = csrData.CsrPem;
            _logger.LogInformation($"Renewing certificate");
            Console.WriteLine($"Renewing certificate");
            IEZCAClient ezcaClient = new EZCAClientClass(new HttpClient(), _logger, values.url);
            string createdCert = await ezcaClient.RenewCertificateAsync(cert, csr);
            _certStoreService.InstallCertificate(createdCert, csrData);
            _logger.LogInformation($"certificate {values.Domain} was renewed successfully");
            Console.WriteLine($"certificate {values.Domain} was renewed successfully");
            if (values.RDPCert)
            {
                SetRDPCertificate(
                    CryptoStaticService.ImportCertFromPEMString(createdCert).Thumbprint
                );
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Error renewing certificate {values.Domain}");
            Console.WriteLine(ex.Message);
            return 1;
        }
        return 0;
    }

    private async Task<int> CreateCertAsync(GenerateArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }
        try
        {
            if (values is { RDPCert: true, LocalCertStore: false })
            {
                throw new ArgumentException(
                    "If certificate will be used for RDP it must be stored in the local store"
                );
            }
            if (!IsGuid(values.caID))
            {
                throw new ArgumentException("Please enter a valid CA ID Guid");
            }
            if (string.IsNullOrWhiteSpace(values.Domain))
            {
                values.Domain = GetFQDN();
                if (string.IsNullOrWhiteSpace(values.Domain))
                {
                    throw new ArgumentNullException(nameof(values.Domain));
                }
            }
            if (values.KeyLength != 2048 && values.KeyLength != 4096)
            {
                throw new ArgumentException("Key length must be 2048 or 4096");
            }
            IEZCAClient ezcaClient = new EZCAClientClass(
                new HttpClient(),
                _logger,
                values.url,
                CreateTokenCredential(values.ClientID, values.ClientSecret, values.TenantID)
            );
            _logger.LogInformation("Getting available CAs");
            Console.WriteLine("Getting available CAs");
            AvailableCAModel selectedCA = await GetCAAsync(values.caID, ezcaClient);
            List<string> ekus =
            [
                EZCAConstants.ServerAuthenticationEKU,
                EZCAConstants.ClientAuthenticationEKU
            ];
            X509Certificate2 createdCertificate = await CreateCertificateAsync(
                values.Domain,
                values.Domain,
                values.LocalCertStore,
                selectedCA,
                values.Validity,
                ezcaClient,
                false,
                ekus,
                values.KeyLength,
                "",
                values.KeyProvider
            );
            if (values.RDPCert)
            {
                SetRDPCertificate(createdCertificate.Thumbprint);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error creating certificate: " + ex.Message);
            _logger.LogError(ex, "Error creating certificate");
            return 1;
        }
        return 0;
    }

    private async Task<int> CreateDCCertAsync(CreateDCCertificate values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }
        try
        {
            if (!IsGuid(values.caID))
            {
                throw new ArgumentException("Please enter a valid CA ID Guid");
            }
            if (!IsGuid(values.TemplateID))
            {
                throw new ArgumentException("Please enter a valid Template ID Guid");
            }
            if (string.IsNullOrWhiteSpace(values.Domain))
            {
                values.Domain = GetFQDN();
                if (string.IsNullOrWhiteSpace(values.Domain))
                {
                    throw new ArgumentNullException(nameof(values.Domain));
                }
            }
            if (string.IsNullOrWhiteSpace(values.SubjectName))
            {
                values.SubjectName = GetComputerSubjectName();
                if (string.IsNullOrWhiteSpace(values.SubjectName))
                {
                    throw new ArgumentNullException(
                        nameof(values.SubjectName),
                        "Please enter a valid Subject Name"
                    );
                }
            }
            if (values.EKUs == null || values.EKUs.Any() == false)
            {
                values.EKUs = EZCAConstants.DomainControllerDefaultEKUs;
            }
            IEZCAClient ezcaClient = new EZCAClientClass(
                new HttpClient(),
                _logger,
                values.url,
                CreateTokenCredential(values.AzureCLI)
            );
            if (values.KeyLength != 2048 && values.KeyLength != 4096)
            {
                throw new ArgumentException("Key length must be 2048 or 4096");
            }
            
            // Process additional SubjectAltNames if provided
            List<string>? additionalSANs = null;
            if (!string.IsNullOrWhiteSpace(values.SubjectAltNames))
            {
                additionalSANs = values
                    .SubjectAltNames.Split(',')
                    .Select(san => san.Trim())
                    .Where(san => !string.IsNullOrWhiteSpace(san))
                    .ToList();
            }
            
            AvailableCAModel selectedCA =
                new() { CAID = values.caID, TemplateID = values.TemplateID, };
            X509Certificate2 createdCertificate = await CreateCertificateAsync(
                values.Domain,
                values.SubjectName,
                true,
                selectedCA,
                values.Validity,
                ezcaClient,
                true,
                values.EKUs,
                values.KeyLength,
                values.DCGUID,
                values.KeyProvider,
                additionalSANs
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating domain controller certificate");
            Console.WriteLine("Error creating certificate: " + ex.Message);
            return 1;
        }
        return 0;
    }

    private async Task<int> CreateSCEPCertificate(SCEPArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }
        try
        {
            if (string.IsNullOrWhiteSpace(values.SubjectAltNames))
            {
                values.SubjectAltNames = GetFQDN();
                if (string.IsNullOrWhiteSpace(values.SubjectAltNames))
                {
                    throw new ArgumentNullException(nameof(values.SubjectAltNames));
                }
            }
            if (string.IsNullOrWhiteSpace(values.SubjectName))
            {
                values.SubjectName = GetComputerSubjectName();
                if (string.IsNullOrWhiteSpace(values.SubjectName))
                {
                    throw new ArgumentNullException(
                        nameof(values.SubjectName),
                        "Please enter a valid Subject Name"
                    );
                }
            }
            if (values.EKUs is null or { Count: 0 })
            {
                values.EKUs =
                [
                    EZCAConstants.ClientAuthenticationEKU,
                    EZCAConstants.ServerAuthenticationEKU
                ];
            }
            if (values.KeyLength != 2048 && values.KeyLength != 4096)
            {
                throw new ArgumentException("Key length must be 2048 or 4096");
            }
            if (string.IsNullOrWhiteSpace(values.url))
            {
                throw new ArgumentNullException(nameof(values.url));
            }
            //TIP: you can hardcode the password here or use a secure secret manager to avoid having the password in the Script
            // values.SCEPPassword = "YourPassword";
            if (string.IsNullOrWhiteSpace(values.SCEPPassword))
            {
                throw new ArgumentNullException(nameof(values.SCEPPassword));
            }
            _logger.LogInformation(
                "Creating SCEP certificate for {SubjectName}",
                values.SubjectName
            );
            Console.WriteLine("Creating SCEP certificate for " + values.SubjectName);
            X509Certificate2 caCert = await GetScepCA(values.url);
            AsymmetricCipherKeyPair rsaKeyPair = CreateKeyPair($"RSA {values.KeyLength}");
            Pkcs10CertificationRequest request = CreateCSRForScep(
                values,
                values.SCEPPassword,
                rsaKeyPair
            );
            return await RequestSCEPCertificateAsync(caCert, rsaKeyPair, request, values);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating SCEP certificate");
            Console.WriteLine("Error creating certificate: " + ex.Message);
            return 1;
        }
    }

    private async Task<int> RequestSCEPCertificateAsync(
        X509Certificate2 caCertificate,
        AsymmetricCipherKeyPair rsaKeyPair,
        Pkcs10CertificationRequest request,
        SCEPArgModel values
    )
    {
        try
        {
            X509Certificate bouncyCastleCACert = DotNetUtilities.FromX509Certificate(caCertificate);
            CmsEnvelopedDataGenerator envelopedDataGenerator = new();
            envelopedDataGenerator.AddKeyTransRecipient(bouncyCastleCACert);
            CmsProcessable req = new CmsProcessableByteArray(request.GetDerEncoded());
            CmsEnvelopedData encryptedEnvelope = envelopedDataGenerator.Generate(
                req,
                CmsEnvelopedGenerator.Aes256Cbc
            );
            byte[] encryptedBytes = encryptedEnvelope.GetEncoded();
            //create Signing Key
            AsymmetricCipherKeyPair signingKeyPair = CreateKeyPair($"RSA {values.KeyLength}");
            X509Certificate2 cert = GenerateSelfSignedCertificate(signingKeyPair, "TempCert");
            CmsSigner signer = new(cert);
            var messageType = new AsnEncodedData(
                "2.16.840.1.113733.1.9.2",
                DerEncoding.EncodePrintableString("19")
            );
            signer.SignedAttributes.Add(messageType);
            var transactionID = new Pkcs9AttributeObject(
                "2.16.840.1.113733.1.9.7",
                DerEncoding.EncodePrintableString(
                    Convert.ToBase64String(SHA512.HashData(cert.GetPublicKey()))
                )
            );
            signer.SignedAttributes.Add(transactionID);
            SecureRandom random = new();
            byte[] nonceBytes = new byte[16]; // Typically a 16-byte nonce
            random.NextBytes(nonceBytes);
            var nonce = new Pkcs9AttributeObject(
                "2.16.840.1.113733.1.9.5",
                DerEncoding.EncodeOctet(nonceBytes)
            );
            signer.SignedAttributes.Add(nonce);
            ContentInfo signedContent = new(encryptedBytes);
            SignedCms signedMessage = new(signedContent);
            signedMessage.ComputeSignature(signer);
            byte[] signedBytes = signedMessage.Encode();
            ByteArrayContent content = new(signedBytes);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(
                "application/x-pki-message"
            );
            HttpResponseMessage response = await _httpClient.PostAsync(values.url, content);
            if (!response.IsSuccessStatusCode)
            {
                throw new Exception(
                    $"Failed to request SCEP certificate: {response.StatusCode} "
                        + await response.Content.ReadAsStringAsync()
                );
            }
            byte[] responseBytes = await response.Content.ReadAsByteArrayAsync();
            return DecodeAndInstallSCEPCertificate(
                responseBytes,
                rsaKeyPair,
                caCertificate,
                nonceBytes,
                cert,
                values.LocalCertStore
            );
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Error Requesting SCEP certificate");
            Console.WriteLine("Error Requesting SCEP certificate: " + ex.Message);
            return 1;
        }
    }

    private int DecodeAndInstallSCEPCertificate(
        byte[] responseBytes,
        AsymmetricCipherKeyPair rsaKeyPair,
        X509Certificate2 caCertificate,
        byte[] nonce,
        X509Certificate2 signingCert,
        bool localStore
    )
    {
        var signedResponse = new SignedCms();
        signedResponse.Decode(responseBytes);
        X509Certificate2Collection caCerts = [caCertificate];
        signedResponse.CheckSignature(caCerts, true);
        var attributes = signedResponse
            .SignerInfos.Cast<SignerInfo>()
            .SelectMany(si => si.SignedAttributes.Cast<CryptographicAttributeObject>());
        var recipientNonce = attributes.FirstOrDefault(a =>
            a.Oid.Value == "2.16.840.1.113733.1.9.6"
        );
        if (recipientNonce == null)
        {
            throw new Exception("Recipient nonce not found in response");
        }
        if (!nonce.SequenceEqual(recipientNonce.Values[0].RawData[2..]))
        {
            throw new Exception("Recipient nonce does not match");
        }
        var certBytes = signedResponse.ContentInfo.Content;
        var cmsResponse = new EnvelopedCms();
        cmsResponse.Decode(signedResponse.ContentInfo.Content);
        cmsResponse.Decrypt(new X509Certificate2Collection(signingCert));
        X509Certificate2Collection certCollection = new X509Certificate2Collection();
        certCollection.Import(cmsResponse.ContentInfo.Content);
        X509Certificate2 cert = certCollection.OrderBy(x => x.NotBefore).Last();
#pragma warning disable CA1416
        RSA rsaPrivateKey = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)rsaKeyPair.Private);
#pragma warning restore CA1416
        cert = cert.CopyWithPrivateKey(rsaPrivateKey);
        _certStoreService.InstallFullCertificate(cert, localStore);
        return 0;
    }

    private static X509Certificate2 GenerateSelfSignedCertificate(
        AsymmetricCipherKeyPair keyPair,
        string subjectName,
        int validDays = 2
    )
    {
        // Create the certificate generator
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        // Set certificate subject and issuer (self-signed so issuer is the same as the subject)
        X509Name issuerName = new X509Name($"CN={subjectName}");
        certGen.SetIssuerDN(issuerName);
        certGen.SetSubjectDN(issuerName);

        // Set the certificate's serial number
        BigInteger serialNumber = BigInteger.ProbablePrime(120, new SecureRandom());
        certGen.SetSerialNumber(serialNumber);

        // Set the certificate's validity period
        DateTime notBefore = DateTime.UtcNow.Date;
        DateTime notAfter = notBefore.AddDays(validDays);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);

        // Set the public key for the certificate
        certGen.SetPublicKey(keyPair.Public);

        // Optionally add extensions (like Basic Constraints, Key Usage, etc.)
        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true)); // Cert is allowed to act as a CA

        // Sign the certificate with the private key
        ISignatureFactory signatureFactory = new Asn1SignatureFactory(
            "SHA256WITHRSA",
            keyPair.Private
        );
        X509Certificate bouncyCastleCert = certGen.Generate(signatureFactory);
        X509Certificate2 cert = new X509Certificate2(bouncyCastleCert.GetEncoded());
#pragma warning disable CA1416
        RSA rsaPrivateKey = DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private);
#pragma warning restore CA1416
        cert = cert.CopyWithPrivateKey(rsaPrivateKey);
        return cert;
    }

    private Pkcs10CertificationRequest CreateCSRForScep(
        SCEPArgModel values,
        string challengePassword,
        AsymmetricCipherKeyPair rsaKeyPair
    )
    {
        AttributePkcs scepPassword = new AttributePkcs(
            PkcsObjectIdentifiers.Pkcs9AtChallengePassword,
            new DerSet(new DerPrintableString(challengePassword))
        );
        X509ExtensionsGenerator extensions = new X509ExtensionsGenerator();
        if (!string.IsNullOrWhiteSpace(values.SubjectAltNames))
        {
            GeneralNames subjectAlternateNames = new GeneralNames(
                values
                    .SubjectAltNames.Split(',')
                    .Select(dnsName => new GeneralName(GeneralName.DnsName, dnsName))
                    .ToArray()
            );
            extensions.AddExtension(
                X509Extensions.SubjectAlternativeName,
                false,
                subjectAlternateNames
            );
        }
        Asn1Encodable ekus = new ExtendedKeyUsage(
            values.EKUs.Select(oid => new DerObjectIdentifier(oid)).ToArray()
        );
        extensions.AddExtension(X509Extensions.ExtendedKeyUsage, false, ekus);
        //key usage
        extensions.AddExtension(
            X509Extensions.KeyUsage,
            true,
            (new KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature)).ToAsn1Object()
        );
        AttributePkcs extensionRequest = new AttributePkcs(
            PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
            new DerSet(extensions.Generate())
        );
        Pkcs10CertificationRequest request = new Pkcs10CertificationRequest(
            "SHA256WITHRSA",
            new X509Name(values.SubjectName),
            rsaKeyPair.Public,
            new DerSet(extensionRequest, scepPassword),
            rsaKeyPair.Private
        );
        return request;
    }

    private static AsymmetricCipherKeyPair CreateKeyPair(string keyAlgo)
    {
        var randomGenerator = new CryptoApiRandomGenerator();
        var random = new SecureRandom(randomGenerator);
        if (keyAlgo.Contains("RSA", StringComparison.OrdinalIgnoreCase))
        {
            int strength = Int32.Parse(keyAlgo.Split(" ")[1]);
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }
        if (keyAlgo.Contains("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var ecKeyPairGenerator = new ECKeyPairGenerator();
            ECKeyGenerationParameters ecKeyGenParams;
            if (keyAlgo.Contains("256"))
            {
                ecKeyGenParams = new(SecObjectIdentifiers.SecP256r1, new SecureRandom());
            }
            else if (keyAlgo.Contains("384"))
            {
                ecKeyGenParams = new(SecObjectIdentifiers.SecP384r1, new SecureRandom());
            }
            else
            {
                throw new NotImplementedException($"Algorithm {keyAlgo} not supported");
            }
            ecKeyPairGenerator.Init(ecKeyGenParams);
            return ecKeyPairGenerator.GenerateKeyPair();
        }
        throw new NotImplementedException($"Algorithm {keyAlgo} not supported");
    }

    private async Task<X509Certificate2> GetScepCA(string scepURL)
    {
        HttpResponseMessage caResponse = await _httpClient.GetAsync(
            string.Concat(scepURL, "?operation=GetCACert&message=ca")
        );
        if (caResponse.IsSuccessStatusCode)
        {
            byte[] caCertData = await caResponse.Content.ReadAsByteArrayAsync();
            X509Certificate2 caCert = new(caCertData);
            // Validate the chain to ensure we trust the CA
            X509Chain chain = new();
            if (chain.Build(caCert))
            {
                return caCert;
            }
            throw new Exception(
                "Error building chain for SCEP CA certificate: "
                    + chain.ChainStatus[0].StatusInformation
            );
        }
        throw new Exception(
            "Error getting SCEP CA certificate: " + await caResponse.Content.ReadAsStringAsync()
        );
    }

    private string GetComputerSubjectName()
    {
        return _systemInfoService.GetComputerSubjectName();
    }

    private string? GetComputerDistinguishedName(string computerName)
    {
        return _systemInfoService.GetComputerDistinguishedName(computerName);
    }

    private string GetFQDN(string computerName = "")
    {
        return _systemInfoService.GetFQDN(computerName);
    }

    private async Task<int> RegisterAndCreateCertAsync(RegisterArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }
        try
        {
            if (!IsGuid(values.caID))
            {
                throw new ArgumentException("Please enter a valid CA ID Guid");
            }
            if (string.IsNullOrWhiteSpace(values.Domain))
            {
                values.Domain = GetFQDN();
                if (string.IsNullOrWhiteSpace(values.Domain))
                {
                    throw new ArgumentNullException(nameof(values.Domain));
                }
            }
            IEZCAClient ezcaClient = new EZCAClientClass(new HttpClient(), _logger, values.url);
            _logger.LogInformation("Getting available CAs");
            Console.WriteLine("Getting available CAs");
            AvailableCAModel selectedCA = await GetCAAsync(values.caID, ezcaClient);
            APIResultModel registrationResult = await ezcaClient.RegisterDomainAsync(
                selectedCA,
                values.Domain
            );
            _logger.LogInformation($"Registering domain: {values.Domain}");
            Console.WriteLine($"Registering domain: {values.Domain}");
            if (!registrationResult.Success)
            {
                throw new InvalidOperationException(
                    $"Could not register new domain in EZCA {registrationResult.Message}"
                );
            }
            _logger.LogInformation($"Successfully registered domain: {values.Domain}");
            Console.WriteLine($"Successfully registered domain: {values.Domain}");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error registering domain: " + ex.Message);
            _logger.LogError(ex, "Error registering domain");
            return 1;
        }
        return 0;
    }

    private void SetRDPCertificate(string thumbprint)
    {
        _systemInfoService.SetRDPCertificate(thumbprint);
    }

    private async Task<X509Certificate2> CreateCertificateAsync(
        string domain,
        string subjectName,
        bool localStore,
        AvailableCAModel selectedCA,
        int validity,
        IEZCAClient ezcaClient,
        bool dcCertificate,
        List<string> ekus,
        int keyLength,
        string dcGUID = "",
        string keyProvider = "Microsoft Enhanced Cryptographic Provider v1.0",
        List<string>? additionalSubjectAltNames = null
    )
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }
        if (validity <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(validity),
                "Error certificate validity has to be greater than 0"
            );
        }
        if (keyLength != 2048 && keyLength != 4096)
        {
            throw new ArgumentException("Key length must be 2048 or 4096");
        }
        // Start with domain as first SAN
        List<string> subjectAltNames = [domain];
        
        // Add additional SANs if provided, with deduplication
        if (additionalSubjectAltNames?.Count > 0)
        {
            var newSans = additionalSubjectAltNames
                .Where(san => !subjectAltNames.Contains(san, StringComparer.OrdinalIgnoreCase))
                .ToList();
            subjectAltNames.AddRange(newSans);
        }
        
        if (
            !subjectName.StartsWith("CN=", StringComparison.InvariantCultureIgnoreCase)
            && !subjectName.StartsWith("CN =", StringComparison.InvariantCultureIgnoreCase)
        )
        {
            subjectName = "CN=" + subjectName;
        }
        CsrData csrData = _certStoreService.CreateCSR(
            subjectName,
            subjectAltNames,
            keyLength,
            localStore,
            ekus,
            keyProvider
        );
        string csr = csrData.CsrPem;
        X509Certificate2? windowsCert;
        if (dcCertificate)
        {
            _logger.LogInformation($"Getting Domain Controller certificate for {domain}");
            Console.WriteLine($"Getting Domain Controller certificate for {domain}");
            windowsCert = await ezcaClient.RequestDCCertificateAsync(
                selectedCA,
                csr,
                subjectName,
                domain,
                validity,
                ekus,
                dcGUID
            );
        }
        else
        {
            _logger.LogInformation($"Getting Windows certificate for {domain}");
            Console.WriteLine($"Getting Windows certificate for {domain}");
            windowsCert = await ezcaClient.RequestCertificateAsync(
                selectedCA,
                csr,
                domain,
                validity
            );
        }

        if (windowsCert != null)
        {
            _logger.LogInformation(
                $"Installing Windows Certificate for "
                    + $"{domain} with thumbprint {windowsCert.Thumbprint}"
            );
            Console.WriteLine(
                $"Installing Windows Certificate for "
                    + $"{domain} with thumbprint {windowsCert.Thumbprint}"
            );
            _certStoreService.InstallCertificate(
                CryptoStaticService.ExportToPEM(windowsCert),
                csrData
            );
            _logger.LogInformation(
                $"Successfully created certificate for "
                    + $"{domain} with thumbprint {windowsCert.Thumbprint}"
            );
            Console.WriteLine(
                $"Successfully created certificate for "
                    + $"{domain} with thumbprint {windowsCert.Thumbprint}"
            );
            return windowsCert;
        }
        throw new CryptographicException($"Error requesting EZCA certificate for {domain}");
    }

    private static async Task<AvailableCAModel> GetCAAsync(string caID, IEZCAClient ezcaClient)
    {
        AvailableCAModel[]? availableCAs = await ezcaClient.GetAvailableCAsAsync();
        if (availableCAs == null || availableCAs.Any() == false)
        {
            throw new NullReferenceException("Could not find any available CAs in EZCA");
        }
        AvailableCAModel? selectedCA = availableCAs.FirstOrDefault(i => i.CAID == caID);
        if (selectedCA == null)
        {
            throw new ArgumentOutOfRangeException(
                $"No CA with CA ID {caID} was found, make sure you have access to request from this CA"
            );
        }
        return selectedCA;
    }

    private static TokenCredential CreateTokenCredential(
        string clientID,
        string clientSecret,
        string tenantID
    )
    {
        if (
            string.IsNullOrWhiteSpace(clientID)
            || string.IsNullOrWhiteSpace(clientSecret)
            || string.IsNullOrWhiteSpace(tenantID)
        )
        {
            return new DefaultAzureCredential(includeInteractiveCredentials: true);
        }
        return new ClientSecretCredential(tenantID, clientID, clientSecret);
    }

    private static TokenCredential CreateTokenCredential(bool azureCLI)
    {
        if (azureCLI)
        {
            return new AzureCliCredential();
        }
        return new DefaultAzureCredential(includeInteractiveCredentials: true);
    }

    private ILogger CreateLogger(string? appInsightsKey)
    {
        IServiceCollection services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Information);
            if (!string.IsNullOrWhiteSpace(appInsightsKey))
            {
                builder.AddApplicationInsights(
                    configureTelemetryConfiguration: (config) =>
                        config.ConnectionString = appInsightsKey,
                    configureApplicationInsightsLoggerOptions: (_) => { }
                );
            }
#pragma warning disable CA1416
            builder.AddEventLog();
#pragma warning restore CA1416
        });
        if (!string.IsNullOrWhiteSpace(appInsightsKey))
        {
            services.AddSingleton<TelemetryClient>();
        }
        IServiceProvider serviceProvider = services.BuildServiceProvider();
        if (!string.IsNullOrWhiteSpace(appInsightsKey))
        {
            _telemetryClient = serviceProvider.GetRequiredService<TelemetryClient>();
        }
        return serviceProvider.GetRequiredService<ILogger<Program>>();
    }

    private static bool IsGuid(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }
        return Guid.TryParse(value, out _);
    }

    private static List<X509SubjectAlternativeName> GetSubjectAlternativeNames(
        X509Certificate2 certificate
    )
    {
        var subjectAlternativeNames = new List<X509SubjectAlternativeName>();

        // Convert X509Certificate2 to Bouncy Castle X509Certificate
        var parser = new X509CertificateParser();
        var bcCert = parser.ReadCertificate(certificate.RawData);

        // Get the SubjectAlternativeNames extension
        var sanExtension = bcCert.GetExtensionValue(X509Extensions.SubjectAlternativeName);

        if (sanExtension != null)
        {
            var asn1Object = X509ExtensionUtilities.FromExtensionValue(sanExtension);
            var generalNames = GeneralNames.GetInstance(asn1Object);

            foreach (var generalName in generalNames.GetNames())
            {
                X509SubjectAlternativeName x509SubjectAlternativeName = new();
                switch (generalName.TagNo)
                {
                    case GeneralName.Rfc822Name:
                        x509SubjectAlternativeName.Type = SANTypes.Rfc822Name;
                        x509SubjectAlternativeName.Value = generalName.Name.ToString() ?? "";
                        break;
                    case GeneralName.DnsName:
                        x509SubjectAlternativeName.Type = SANTypes.DNSName;
                        x509SubjectAlternativeName.Value = generalName.Name.ToString() ?? "";
                        break;
                    case GeneralName.UniformResourceIdentifier:
                        x509SubjectAlternativeName.Type = SANTypes.URI;
                        x509SubjectAlternativeName.Value = generalName.Name.ToString() ?? "";
                        break;
                    case GeneralName.DirectoryName:
                        x509SubjectAlternativeName.Type = SANTypes.DirectoryName;
                        x509SubjectAlternativeName.Value = ((X509Name)generalName.Name).ToString();
                        break;
                    case GeneralName.IPAddress:
                        x509SubjectAlternativeName.Type = SANTypes.IPAddress;
                        x509SubjectAlternativeName.Value = string.Join(
                            ".",
                            ((DerOctetString)generalName.Name).GetOctets()
                        );
                        break;
                    case GeneralName.OtherName:
                        x509SubjectAlternativeName.Type = SANTypes.OtherName;
                        var sequence = Asn1Sequence.GetInstance(generalName.Name);
                        var oid = DerObjectIdentifier.GetInstance(sequence[0]);
                        if (oid.Id == "1.3.6.1.4.1.311.20.2.3") // OID for UPN
                        {
                            var upn = DerUtf8String.GetInstance(
                                Asn1TaggedObject.GetInstance(sequence[1]).GetBaseObject()
                            );
                            x509SubjectAlternativeName.Value = upn.GetString();
                        }
                        else
                        {
                            x509SubjectAlternativeName.Value = generalName.Name.ToString() ?? "";
                        }
                        break;
                    default:
                        x509SubjectAlternativeName.Type = SANTypes.Unknown;
                        x509SubjectAlternativeName.Value = generalName.Name.ToString() ?? "";
                        break;
                }

                subjectAlternativeNames.Add(x509SubjectAlternativeName);
            }
        }

        return subjectAlternativeNames;
    }
}

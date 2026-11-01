using System.Runtime.InteropServices;
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
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace DotNetCertAuthSample.Managers;

public class CertificateManager(
    ICertStoreService certStoreService,
    ISystemInfoService systemInfoService,
    ISettingsService settingsService
)
{
    private ILogger? _logger;
    private RenewArgModel? _renewArgModel;
    private RenewAllArgModel? _renewAllArgModel;
    private GenerateArgModel? _generateArgModel;
    private RegisterArgModel? _registerArgModel;
    private CreateDCCertificate? _createDCCertArgModel;
    private SCEPArgModel? _scepArgModel;
    private EnrollArgModel? _enrollArgModel;
    private readonly HttpClient _httpClient = new();
    private TelemetryClient? _telemetryClient;

    public int InitializeManager(RenewArgModel values)
    {
        _logger = CreateLogger(values.AppInsightsKey);
        _renewArgModel = values;
        return 0;
    }

    public int InitializeManager(RenewAllArgModel values)
    {
        _logger = CreateLogger(values.AppInsightsKey);
        _renewAllArgModel = values;
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

    public int InitializeManager(EnrollArgModel values)
    {
        _logger = CreateLogger(values.AppInsightsKey);
        if (!string.IsNullOrWhiteSpace(values.EKUsInputs))
        {
            values.EKUs = values.EKUsInputs.Split(',').ToList();
        }

        _enrollArgModel = values;
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
            response = await RegisterDomainAsync(_registerArgModel);
        }
        else if (_createDCCertArgModel != null)
        {
            response = await CreateDCCertAsync(_createDCCertArgModel);
        }
        else if (_scepArgModel != null)
        {
            response = await CreateSCEPCertificate(_scepArgModel);
        }
        else if (_renewAllArgModel != null)
        {
            response = await RenewAllCertificatesAsync(_renewAllArgModel);
        }
        else if (_enrollArgModel != null)
        {
            response = await EnrollDeviceAsync(_enrollArgModel);
        }

        if (_telemetryClient != null)
        {
            await _telemetryClient.FlushAsync(CancellationToken.None);
            Thread.Sleep(5000);
        }

        return response;
    }

    private async Task<int> RenewAllCertificatesAsync(RenewAllArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }
        ArgumentException.ThrowIfNullOrWhiteSpace(values.authoritySubjectKeys);
        if (values.RenewalPercentage <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(values.RenewalPercentage));
        }
        int result = 0;
        try
        {
            LogInformation($"Renewing certificate for {values.authoritySubjectKeys}");
            LogInformation(
                $"Getting certificate from {CertUtils.StoreString(values.LocalCertStore)}"
            );
            List<X509Certificate2> certs = new();
            foreach (string ski in values.authoritySubjectKeys.Split(','))
            {
                certs.AddRange(
                    certStoreService.GetCertificatesIssuedByCaSki(ski, values.LocalCertStore)
                );
            }
            if (certs.Count == 0)
            {
                LogInformation($"No certificate found for {values.authoritySubjectKeys}");
                return 0;
            }
            LogInformation($"Retrieved  {certs.Count} certificates");
            SettingsModel settings = settingsService.GetSettings(_logger);
            foreach (X509Certificate2 cert in certs)
            {
                LogInformation(
                    $"Analyzing certificate for {cert.Subject} with thumbprint  {cert.Thumbprint}"
                );
                if (CertUtils.GetPercentageOfLifetimeLeft(cert) <= values.RenewalPercentage)
                {
                    if (
                        settings.RotatedCertificates.Any(x =>
                            x.Thumbprint.Equals(
                                cert.Thumbprint,
                                StringComparison.InvariantCultureIgnoreCase
                            )
                        )
                    )
                    {
                        LogInformation(
                            "Skipping certificate with thumbprint "
                                + cert.Thumbprint
                                + " since it has already been rotated"
                        );
                    }
                    else
                    {
                        result += await RenewCertificatesAsync(cert, values, settings);
                    }
                }
                else
                {
                    LogInformation(
                        $"Skipping certificate for {cert.Subject} with thumbprint  {cert.Thumbprint} since its lifetime is longer than  {values.RenewalPercentage}%"
                    );
                }
            }
        }
        catch (Exception ex)
        {
            LogError(ex, $"Error renewing certificates for {values.authoritySubjectKeys}");
            return 1;
        }
        return result;
    }

    private async Task<int> RenewCertificatesAsync(
        X509Certificate2 cert,
        RenewAllArgModel values,
        SettingsModel settings
    )
    {
        try
        {
            LogInformation(
                $"Found certificate with thumbprint {cert.Thumbprint} and subject {cert.Subject} expiring on {cert.NotAfter}"
            );
            string csr = CreateRenewalCSR(
                cert,
                values.LocalCertStore,
                string.Empty,
                makePrivateKeyExportable: false
            );
            LogInformation("Renewing certificate");
            EZCAClientClass ezcaClient = new(_httpClient, _logger, values.url);
            string createdCert = await ezcaClient.RenewCertificateAsync(cert, csr);
            X509Certificate2 certReturned = CryptoStaticService.ImportCertFromPEMString(
                createdCert
            );
            certStoreService.InstallCertificate(certReturned, values.LocalCertStore);
            LogInformation(
                $"Certificate {cert.SubjectName} with thumbprint {cert.Thumbprint} was renewed successfully"
            );
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                APIResultModel rdpResult = systemInfoService.CheckIfRDPCertAndRenew(
                    cert.Thumbprint,
                    certReturned.Thumbprint
                );
                if (rdpResult.Success && !string.IsNullOrWhiteSpace(rdpResult.Message))
                {
                    LogInformation(rdpResult.Message);
                }
                else if (!rdpResult.Success)
                {
                    LogError(new(rdpResult.Message));
                }

                APIResultModel iisResult = systemInfoService.CheckIfIISCertAndRenew(
                    cert.Thumbprint,
                    certReturned.Thumbprint
                );
                if (iisResult.Success && !string.IsNullOrWhiteSpace(iisResult.Message))
                {
                    LogInformation(iisResult.Message);
                }
                else if (!iisResult.Success)
                {
                    LogError(new(iisResult.Message));
                }
            }
            settings.RotatedCertificates.Add(new(cert.Thumbprint, cert.NotAfter));
            settingsService.SaveSettings(settings, _logger);
        }
        catch (Exception ex)
        {
            // renewall loops over every matching certificate, so without this one unreachable CA
            // leaves an orphaned key container per certificate per run.
            certStoreService.DiscardPendingRequest();
            LogError(
                ex,
                $"Error renewing certificate {cert.SubjectName} with thumbprint {cert.Thumbprint} {ex.Message}"
            );
            return 1;
        }

        return 0;
    }

    private async Task<int> RenewAsync(RenewArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }

        try
        {
            AssertCorrectRenewArgModel(values);

            X509Certificate2? cert;
            if (!string.IsNullOrWhiteSpace(values.SourceFile))
            {
                LogInformation($"Loading certificate from file {values.SourceFile}");
                cert = LoadCertFromFile(values.SourceFile, values.Password);
                if (cert == null)
                {
                    return 1;
                }
            }
            else
            {
                LogInformation(
                    $"Getting certificate from {CertUtils.StoreString(values.LocalCertStore)}"
                );
                cert = certStoreService.GetCertFromStore(
                    values.Domain!.Trim(),
                    values.LocalCertStore,
                    values.issuer,
                    values.template,
                    values.Password
                );
            }

            LogInformation(
                $"Renewing certificate for {(string.IsNullOrWhiteSpace(values.Domain) ? cert.Subject : values.Domain)}"
            );
            LogInformation(
                $"Found certificate with thumbprint {cert.Thumbprint} and subject {cert.Subject} expiring on {cert.NotAfter}"
            );

            string csr = CreateRenewalCSR(
                cert,
                values.LocalCertStore,
                values.KeyProvider,
                ShouldMakePrivateKeyExportable(values.Path),
                values.KeyLength
            );
            LogInformation($"Renewing certificate");
            EZCAClientClass ezcaClient = new(_httpClient, _logger, values.url);
            string createdCert = await ezcaClient.RenewCertificateAsync(cert, csr);
            X509Certificate2 certReturned = CryptoStaticService.ImportCertFromPEMString(
                createdCert
            );
            certStoreService.InstallCertificate(
                certReturned,
                values.LocalCertStore,
                values.Password
            );
            LogInformation($"Certificate {cert.Subject} was renewed successfully");
            if (values.RDPCert)
            {
                LogInformation($"Setting RDP certificate");
                SetRDPCertificate(
                    CryptoStaticService.ImportCertFromPEMString(createdCert).Thumbprint
                );
            }

            await CheckAndSaveCertificateToPathAsync(
                certReturned,
                values.LocalCertStore,
                values.Path,
                values.Password
            );

            if (!string.IsNullOrWhiteSpace(values.IISSite))
            {
                LogInformation($"Setting IIS certificate");
                SetIISCertificate(certReturned, values.IISSite);
            }
        }
        catch (Exception ex)
        {
            certStoreService.DiscardPendingRequest();
            LogError(ex, $"Error renewing certificate for {values.Domain}");
            return 1;
        }

        return 0;
    }

    private string CreateRenewalCSR(
        X509Certificate2 cert,
        bool localStore,
        string keyProvider,
        bool makePrivateKeyExportable,
        int? keyLengthOverride = null
    )
    {
        X509KeyUsageFlags? keyUsages = null;
        foreach (X509Extension ext in cert.Extensions)
        {
            if (ext is X509KeyUsageExtension keyUsage)
            {
                keyUsages = keyUsage.KeyUsages;
                break;
            }
        }

        int keyLength = keyLengthOverride ?? GetReusableKeyLength(cert);
        HashAlgorithmName hashAlgorithm = CertUtils.GetHashAlgorithm(cert);
        LogInformation(
            $"Creating CSR for certificate with a {keyLength} bit key and {hashAlgorithm.Name}"
        );
        return certStoreService.CreateCSR(
            cert.SubjectName.Name,
            GetSubjectAlternativeNames(cert)
                .Where(i => i.Type == SANTypes.DNSName)
                .Select(i => i.Value)
                .ToList(),
            keyLength,
            localStore,
            [],
            keyProvider,
            keyUsages,
            makePrivateKeyExportable,
            hashAlgorithm
        );
    }

    /// <summary>
    /// Key length to request when renewing <paramref name="cert"/> without an explicit --KeyLength.
    /// Only an RSA key of at least <see cref="CertUtils.MinimumRsaKeyLength"/> bits can be reused:
    /// CSRs are always created with an RSA key, so reusing the size of an EC key (256, 384, 521)
    /// would ask for an unusably weak RSA key, and reusing a legacy RSA size would downgrade the
    /// certificate.
    /// </summary>
    private int GetReusableKeyLength(X509Certificate2 cert)
    {
        int? reusableKeyLength = CertUtils.GetReusableRsaKeyLength(cert);
        if (reusableKeyLength.HasValue)
        {
            return reusableKeyLength.Value;
        }

        LogWarning(
            $"The certificate being renewed does not have an RSA key of at least {CertUtils.MinimumRsaKeyLength} bits, "
                + $"requesting a new {CertUtils.DefaultRsaKeyLength} bit RSA key instead"
        );
        return CertUtils.DefaultRsaKeyLength;
    }

    private bool ShouldMakePrivateKeyExportable(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        path = ParseAndCreateCertificatePath(path);
        return ShouldIncludePrivateKey(path);
    }

    private async Task CheckAndSaveCertificateWithPrivateKeyToPathAsync(
        X509Certificate2 createdCert,
        string? path,
        string? password
    )
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        path = ParseAndCreateCertificatePath(path);
        bool inBinaryForm = IsBinaryCertificateFormat(path);
        bool includePrivateKey = ShouldIncludePrivateKey(path);

        if (includePrivateKey && !createdCert.HasPrivateKey)
        {
            throw new ArgumentException(
                "The certificate does not have a private key to export, but the file extension indicates that the private key should be included."
            );
        }

        await WriteCertificateToFileAsync(
            createdCert,
            path,
            password,
            GetPasswordPathFromCertificatePath(path),
            inBinaryForm,
            includePrivateKey
        );
    }

    private X509Certificate2? LoadCertFromFile(string path, string? password)
    {
        try
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext is ".pfx" or ".p12")
            {
                return X509CertificateLoader.LoadPkcs12FromFile(
                    path,
                    password,
                    X509KeyStorageFlags.Exportable
                );
            }
            return X509Certificate2.CreateFromPemFile(path);
        }
        catch (Exception ex)
        {
            LogError(ex, $"Error loading certificate from file {path}");
            return null;
        }
    }

    private static string GetPasswordPathFromCertificatePath(string path)
    {
        return Path.Join(
            Path.GetDirectoryName(path),
            Path.GetFileNameWithoutExtension(path) + "_password.txt"
        );
    }

    private async Task CheckAndSaveCertificateToPathAsync(
        X509Certificate2 cert,
        bool localStore,
        string? path,
        string? password
    )
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        path = ParseAndCreateCertificatePath(path);
        bool inBinaryForm = IsBinaryCertificateFormat(path);
        bool includePrivateKey = ShouldIncludePrivateKey(path);

        X509Certificate2 certToExport = cert;
        if (includePrivateKey)
        {
            certToExport = certStoreService.AddPrivateKeyToCertificate(cert, localStore);
        }

        await WriteCertificateToFileAsync(
            certToExport,
            path,
            password,
            GetPasswordPathFromCertificatePath(path),
            inBinaryForm,
            includePrivateKey
        );
    }

    private async Task WriteCertificateToFileAsync(
        X509Certificate2 certToExport,
        string path,
        string? password,
        string passwordPath,
        bool inBinaryForm,
        bool includePrivateKey
    )
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }

        LogInformation($"Saving certificate to path {path}");
        if (inBinaryForm)
        {
            byte[] certBytes;
            if (includePrivateKey)
            {
                bool passwordWasProvided = !string.IsNullOrWhiteSpace(password);
                password = CertUtils.GetOrGeneratePasswordForCert(password);
                certBytes = certToExport.Export(X509ContentType.Pfx, password);
                if (!passwordWasProvided)
                {
                    await File.WriteAllTextAsync(passwordPath, password);
                    LogInformation($"Certificate private key password saved to {passwordPath}");
                }
            }
            else
            {
                certBytes = certToExport.Export(X509ContentType.Cert);
            }

            await File.WriteAllBytesAsync(path, certBytes);
        }
        else
        {
            string pem = CryptoStaticService.ExportToPEM(certToExport);
            await File.WriteAllTextAsync(path, pem);
        }

        LogInformation($"Certificate saved to {path}");
    }

    private static string ParseAndCreateCertificatePath(string path)
    {
        if (string.IsNullOrWhiteSpace(Path.GetExtension(path)))
        {
            path += ".pfx";
        }

        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        return path;
    }

    private static bool IsBinaryCertificateFormat(string path)
    {
        return Path.GetExtension(path).ToLower() switch
        {
            ".pfx" => true,
            ".p12" => true,
            ".der" => true,
            _ => false,
        };
    }

    private static bool ShouldIncludePrivateKey(string path)
    {
        return Path.GetExtension(path).ToLower() switch
        {
            ".pfx" => true,
            ".p12" => true,
            _ => false,
        };
    }

    private static bool IsValidCertificatePathExtension(string path)
    {
        return Path.GetExtension(path).ToLower() switch
        {
            ".pem" => true,
            ".pfx" => true,
            ".p12" => true,
            ".cer" => true,
            ".crt" => true,
            ".der" => true,
            _ => false,
        };
    }

    private void AssertCorrectRenewArgModel(RenewArgModel values)
    {
        AssertRdpSupported(values.RDPCert, values.LocalCertStore);
        AssertIisSupported(values.IISSite, values.LocalCertStore);
        AssertLocalStoreProperties(values.LocalCertStore);

        if (
            string.IsNullOrWhiteSpace(values.Domain) && string.IsNullOrWhiteSpace(values.SourceFile)
        )
        {
            throw new ArgumentException("Either --SubjectName or --SourceFile must be provided.");
        }

        if (!string.IsNullOrWhiteSpace(values.SourceFile) && !File.Exists(values.SourceFile))
        {
            throw new FileNotFoundException(
                $"Source certificate file not found: {values.SourceFile}"
            );
        }

        if (values.KeyLength.HasValue && values.KeyLength != 2048 && values.KeyLength != 4096)
        {
            throw new ArgumentException("Key length must be 2048 or 4096");
        }
    }

    private static void AssertRdpSupported(bool rdpCert, bool localCertStore)
    {
        if (!OperatingSystem.IsWindows() && rdpCert)
        {
            throw new ArgumentException("RDP certificates are only supported on Windows");
        }

        if (rdpCert && !localCertStore)
        {
            throw new ArgumentException(
                "If certificate will be used for RDP it must be stored in the local store"
            );
        }
    }

    private static void AssertIisSupported(string? iisSite, bool localCertStore)
    {
        if (string.IsNullOrWhiteSpace(iisSite))
        {
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new ArgumentException("IIS certificates are only supported on Windows");
        }

        if (!localCertStore)
        {
            throw new ArgumentException(
                "If certificate will be used for IIS it must be stored in the local store"
            );
        }
    }

    private async Task<int> CreateCertAsync(GenerateArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }

        try
        {
            ValidateGenerateArgModel(values);
            IEZCAClient ezcaClient = new EZCAClientClass(
                _httpClient,
                _logger,
                values.url,
                CreateTokenCredential(values.ClientID, values.ClientSecret, values.TenantID)
            );
            LogInformation($"Getting available CAs");
            AvailableCAModel selectedCA = await GetCAAsync(values.caID, ezcaClient);
            List<string> ekus =
            [
                EZCAConstants.ServerAuthenticationEKU,
                EZCAConstants.ClientAuthenticationEKU,
            ];
            X509Certificate2 createdCertificate = await CreateCertificateAsync(
                values.Domain!,
                values.Domain!,
                values.LocalCertStore,
                selectedCA,
                values.Validity,
                ezcaClient,
                false,
                ekus,
                values.KeyLength,
                "",
                values.KeyProvider,
                null,
                values.Path,
                values.Password
            );
            if (values.RDPCert)
            {
                SetRDPCertificate(createdCertificate.Thumbprint);
            }

            if (!string.IsNullOrWhiteSpace(values.IISSite))
            {
                LogInformation($"Setting IIS certificate");
                SetIISCertificate(createdCertificate, values.IISSite);
            }
        }
        catch (Exception ex)
        {
            certStoreService.DiscardPendingRequest();
            LogError(ex, "Error creating certificate for " + values.Domain);
            return 1;
        }

        return 0;
    }

    private void ValidateGenerateArgModel(GenerateArgModel values)
    {
        AssertRdpSupported(values.RDPCert, values.LocalCertStore);
        AssertIisSupported(values.IISSite, values.LocalCertStore);
        AssertLocalStoreProperties(values.LocalCertStore);
        AssertCertificatePathProperties(values.Path);
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
    }

    private void AssertCertificatePathProperties(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        Path.GetFullPath(path);
        if (string.IsNullOrWhiteSpace(Path.GetExtension(path)))
        {
            path += ".pfx";
        }

        if (!IsValidCertificatePathExtension(path))
        {
            throw new ArgumentException(
                "Invalid certificate file extension, valid extensions are (.pem, .pfx, .p12, .cer, .crt, .der)"
            );
        }
    }

    private static void AssertCanWriteToStore(bool localStore)
    {
        if (localStore && !IsRunningAsRoot() && OperatingSystem.IsLinux())
        {
            string message = "To write to the local store, run the CLI with 'sudo -E'";
            throw new Exception(message);
        }

        if (!localStore && IsRunningAsRoot() && OperatingSystem.IsLinux())
        {
            string message = "To write to the user store, do not run the CLI with sudo";
            throw new Exception(message);
        }

        if (localStore && !IsRunningAsRoot() && OperatingSystem.IsMacOS())
        {
            string message = "To write to the local store, run the CLI with 'sudo'";
            throw new Exception(message);
        }
    }

    private void CheckPreservedUserCredentials()
    {
        string? dbus = Environment.GetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS");
        if (string.IsNullOrWhiteSpace(dbus) && _logger != null)
        {
            LogWarning(
                "Run 'sudo -E' to preserve user credentials while running as root, proceeding without user credentials"
            );
        }
    }

    private static bool IsRunningAsRoot()
    {
        return string.Equals(Environment.UserName, "root", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<int> CreateDCCertAsync(CreateDCCertificate values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }

        try
        {
            bool localStore = true;
            AssertLocalStoreProperties(localStore);
            ValidateCreateDCCertificateModel(values);
            IEZCAClient ezcaClient = new EZCAClientClass(
                _httpClient,
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
                // The escape-aware split, so the documented '\,' works here too: the SID URI
                // this verb is most likely to be given contains a comma.
                additionalSANs = SubjectAlternativeNameParser.Split(values.SubjectAltNames);
            }

            AvailableCAModel selectedCA = new()
            {
                CAID = values.caID,
                TemplateID = values.TemplateID,
            };
            X509Certificate2 createdCertificate = await CreateCertificateAsync(
                values.Domain!,
                values.SubjectName!,
                localStore,
                selectedCA,
                values.Validity,
                ezcaClient,
                true,
                values.EKUs,
                values.KeyLength,
                values.DCGUID,
                values.KeyProvider,
                additionalSANs,
                values.Path,
                values.Password,
                values.DCSid
            );
        }
        catch (Exception ex)
        {
            certStoreService.DiscardPendingRequest();
            _logger.LogError(ex, "Error creating domain controller certificate");
            Console.WriteLine("Error creating certificate: " + ex.Message);
            return 1;
        }

        return 0;
    }

    private void ValidateCreateDCCertificateModel(CreateDCCertificate values)
    {
        AssertCertificatePathProperties(values.Path);
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

        if (values.EKUs.Count == 0)
        {
            values.EKUs = EZCAConstants.DomainControllerDefaultEKUs;
        }
    }

    /// <summary>
    /// Requests a device certificate from EZCA, proving which machine is asking with a credential
    /// the machine already holds. Nothing secret is distributed to get this far, and the subject of
    /// the certificate is decided by EZCA from the attested identity rather than by this client.
    /// </summary>
    private async Task<int> EnrollDeviceAsync(EnrollArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }

        try
        {
            EnrollmentConfigService configService = new();
            EnrollmentConfig config = configService.Load(values.ConfigFile, _logger);
            EnrollmentConfigService.ApplyTo(values, config);
            ValidateEnrollArgModel(values);
            Uri enrollmentUrl = new(values.Url!);

            if (values.SaveConfig)
            {
                // Saved before enrolling rather than after: the URL is just as valid when this run
                // cannot reach EZCA, and the installer wants the scheduled task to be able to
                // retry on a machine that was offline while it was being set up.
                config.Url = values.Url;
                config.Mode =
                    values.Mode == AttestationMode.Auto
                        ? null
                        : values.Mode.ToString().ToLowerInvariant();
                config.Spn = values.Spn;
                configService.Save(config, values.ConfigFile, _logger);
            }

            if (!values.Force && HasCertificateThatIsNotDue(values, config))
            {
                return 0;
            }

            bool exportable = ShouldMakePrivateKeyExportable(values.Path);
            // EZCA builds the subject from the attested identity, so this one only ever reaches
            // the CSR, which the server reads for its public key.
            string subjectName = CertUtils.EnsureDistinguishedName(GetComputerSubjectName());
            List<string> sans = [GetFQDN()];
            LogInformation(
                $"Creating a {values.KeyLength} bit key and certificate request for {subjectName}"
            );
            string csrPem = CreateCsrWithKeyProviderFallback(
                subjectName,
                sans,
                values.KeyLength,
                values.LocalCertStore,
                values.EKUs,
                values.KeyProvider,
                exportable,
                challengePassword: null
            );

            byte[] csrDer = PemToDer(csrPem);
            DeviceEnrollmentClient enrollmentClient = new(_httpClient, _logger);
            DeviceEnrollmentResponse enrollment = await AttestAndEnrollAsync(
                enrollmentClient,
                values,
                enrollmentUrl,
                csrDer,
                ToStandardCsrPem(csrDer),
                subjectName
            );

            X509Certificate2 certificate = CryptoStaticService.ImportCertFromPEMString(
                enrollment.Certificate
            );
            LogInformation(
                $"EZCA issued {certificate.Subject} against the {enrollment.AttestationSource ?? "attested"} identity of this machine"
            );
            certStoreService.InstallCertificate(
                certificate,
                values.LocalCertStore,
                values.Password
            );
            LogInformation(
                $"Certificate installed in {CertUtils.StoreString(values.LocalCertStore)} with thumbprint {certificate.Thumbprint}"
            );
            // Recorded as soon as the certificate is in the store, before anything that can still
            // fail: a later failure must not leave the machine holding a certificate that the
            // next run does not know about, or it enrolls again every day.
            RecordIssuedCertificate(configService, values, config, certificate);
            await SaveIssuedCertificateToPathAsync(
                certificate,
                values.LocalCertStore,
                values.Path,
                values.Password
            );

            return 0;
        }
        catch (Exception ex)
        {
            certStoreService.DiscardPendingRequest();
            LogError(ex, "Error enrolling this machine");
            Console.WriteLine("Error enrolling this machine: " + ex.Message);
            return 1;
        }
    }

    /// <summary>
    /// Records which certificate this enrollment installed, so the next run knows whether there is
    /// anything to do. This is written whether or not --SaveConfig was passed, because it is
    /// operational state rather than configuration; failing to write it costs a needless
    /// enrollment on the next run, which is not worth failing the command for.
    /// </summary>
    private void RecordIssuedCertificate(
        EnrollmentConfigService configService,
        EnrollArgModel values,
        EnrollmentConfig config,
        X509Certificate2 certificate
    )
    {
        config.LastIssuedThumbprint = certificate.Thumbprint;
        config.LastIssuedSubject = certificate.Subject;
        if (string.IsNullOrWhiteSpace(config.Url))
        {
            // Filled in only when nothing is recorded yet, never overwritten. A machine that was
            // enrolled by hand still has to be able to renew unattended, but an ad-hoc run
            // against a test endpoint must not repoint a machine that is already configured.
            config.Url = values.Url;
        }

        try
        {
            configService.Save(config, values.ConfigFile, _logger);
        }
        catch (Exception ex)
        {
            LogWarning(
                "The certificate was issued and installed, but the enrollment state could not be "
                    + $"saved, so the next run will enroll again instead of checking this certificate: {ex.Message}"
            );
        }
    }

    private void ValidateEnrollArgModel(EnrollArgModel values)
    {
        AssertLocalStoreProperties(values.LocalCertStore);
        AssertCertificatePathProperties(values.Path);
        if (string.IsNullOrWhiteSpace(values.Url))
        {
            throw new ArgumentException(
                "An enrollment URL is required. Pass --Url, or run once with --Url and --SaveConfig "
                    + "so later runs can read it from the machine enrollment configuration."
            );
        }

        if (!Uri.TryCreate(values.Url, UriKind.Absolute, out Uri? parsed) || !parsed.IsAbsoluteUri)
        {
            throw new ArgumentException($"'{values.Url}' is not a valid enrollment URL.");
        }

        // The attestation token, the request binding and the issued certificate all travel over
        // this URL, so plaintext is refused outside a local development endpoint.
        bool isPlainHttpToLoopback = parsed.Scheme == Uri.UriSchemeHttp && parsed.IsLoopback;
        if (parsed.Scheme != Uri.UriSchemeHttps && !isPlainHttpToLoopback)
        {
            throw new ArgumentException(
                $"The enrollment URL must use https, but '{values.Url}' uses {parsed.Scheme}. "
                    + "Only a loopback address may use plain http, for local development."
            );
        }

        if (values.KeyLength != 2048 && values.KeyLength != 4096)
        {
            throw new ArgumentException("Key length must be 2048 or 4096");
        }

        if (OperatingSystem.IsLinux() && string.IsNullOrWhiteSpace(values.Password))
        {
            // The Linux store is a directory of password protected files and refuses to be
            // searched without one, for the user store as well as the machine store. Without a
            // password this command could install a certificate and then never find it again, so
            // it would enrol afresh on every run.
            throw new ArgumentException(
                "--Password is required on Linux, because the certificate store cannot be read "
                    + "back without it."
            );
        }

        if (values.EKUs is null or { Count: 0 })
        {
            values.EKUs = [EZCAConstants.ClientAuthenticationEKU];
        }

        if (values.RenewalPercentage is <= 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(values.RenewalPercentage),
                "Renewal percentage must be between 1 and 100"
            );
        }
    }

    /// <summary>
    /// Tries each attestation this machine might be able to produce, in order, and enrolls with
    /// the first that works. In Auto, Kerberos comes first: every hybrid joined machine is also
    /// domain joined, and the Kerberos identity carries the machine SID, so it is the stronger of
    /// the two wherever both are available.
    ///
    /// Falling back on failure and not only on availability matters because no cheap local check
    /// can tell an Active Directory member from a machine that merely has a DNS suffix, so
    /// Kerberos can look available on a machine that cannot actually get a ticket.
    /// </summary>
    private async Task<DeviceEnrollmentResponse> AttestAndEnrollAsync(
        DeviceEnrollmentClient enrollmentClient,
        EnrollArgModel values,
        Uri enrollmentUrl,
        byte[] csrDer,
        string csrPem,
        string clientReportedName
    )
    {
        List<IDeviceAttestor> candidates = values.Mode switch
        {
            AttestationMode.Kerberos =>
            [
                new KerberosDeviceAttestor(_logger!, systemInfoService, values.Spn),
            ],
            AttestationMode.Entra => [new EntraDeviceAttestor(_logger!)],
            _ =>
            [
                new KerberosDeviceAttestor(_logger!, systemInfoService, values.Spn),
                new EntraDeviceAttestor(_logger!),
            ],
        };

        List<string> rejected = [];
        Exception? lastFailure = null;
        foreach (IDeviceAttestor candidate in candidates)
        {
            if (!candidate.IsAvailable(out string reason))
            {
                rejected.Add($"{candidate.Name} ({reason})");
                continue;
            }

            LogInformation($"Proving this machine's identity with {candidate.Name}");
            try
            {
                return await enrollmentClient.EnrollAsync(
                    enrollmentUrl,
                    candidate,
                    csrDer,
                    csrPem,
                    clientReportedName
                );
            }
            // Only a failure to produce or use a credential is worth retrying with another one.
            // A response we could not bind to our own request, and an explicit refusal to issue
            // to the identity we proved, are decisions rather than credential problems, and
            // retrying either would be working around the answer. A timeout is neither: nothing
            // threads a cancellation token into this call, so the only cancellation reachable
            // here is an HttpClient timeout, which is exactly the transient failure the fallback
            // exists for. Thread a token in and this needs revisiting.
            catch (Exception ex)
                when (ex is not UnboundEnrollmentResponseException
                    && ex is not EnrollmentForbiddenException
                )
            {
                // Every candidate's failure is collected, the last one included, so the error the
                // administrator reads names each attestation that was tried and why it failed
                // rather than only whichever happened to be last.
                LogWarning($"Could not enroll with {candidate.Name}: {ex.Message}");
                rejected.Add($"{candidate.Name} ({ex.Message})");
                lastFailure = ex;
            }
        }

        throw new InvalidOperationException(
            "This machine could not prove its identity to EZCA: " + string.Join("; ", rejected),
            lastFailure
        );
    }

    /// <summary>
    /// Whether the certificate this machine enrolled for last time still has enough lifetime left
    /// that there is nothing to do. The scheduled task runs daily, so most runs end here.
    ///
    /// It is found by the thumbprint recorded at enrollment rather than by subject, because EZCA
    /// and not this client chooses the subject: searching by name would both match certificates
    /// this command never issued and miss the one it did.
    /// </summary>
    private bool HasCertificateThatIsNotDue(EnrollArgModel values, EnrollmentConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.LastIssuedThumbprint))
        {
            return false;
        }

        X509Certificate2? existing = FindCertificateByThumbprint(
            config.LastIssuedThumbprint,
            values.LocalCertStore,
            values.Password
        );
        if (existing == null)
        {
            LogInformation(
                "The certificate recorded for this machine is no longer in the store, so a new one is needed"
            );
            return false;
        }

        if (!existing.HasPrivateKey)
        {
            // A certificate whose key is gone cannot authenticate anything, so it does not count
            // as being enrolled however much lifetime it has left.
            LogWarning(
                $"Certificate {existing.Thumbprint} is in the store but its private key is not, so a new one is needed"
            );
            return false;
        }

        int remaining = CertUtils.GetPercentageOfLifetimeLeft(existing);
        if (remaining > values.RenewalPercentage)
        {
            LogInformation(
                $"Certificate {existing.Thumbprint} expires on {existing.NotAfter} with {remaining}% of its "
                    + $"lifetime left, which is more than the {values.RenewalPercentage}% renewal threshold. Nothing to do."
            );
            return true;
        }

        LogInformation(
            $"Certificate {existing.Thumbprint} has {remaining}% of its lifetime left, so it is due for renewal"
        );
        return false;
    }

    private X509Certificate2? FindCertificateByThumbprint(
        string thumbprint,
        bool localStore,
        string? password
    )
    {
        try
        {
            return certStoreService.GetCertificateByThumbprint(
                thumbprint,
                localStore,
                password
            );
        }
        catch (Exception ex)
        {
            LogWarning(
                $"Could not read {CertUtils.StoreString(localStore)} to look for the current certificate: {ex.Message}"
            );
            return null;
        }
    }

    /// <summary>
    /// Creates the request and its key, preferring a TPM key when the caller did not name a
    /// provider. A TPM key cannot be exported, which is the point: the certificate stops being a
    /// portable network credential. Most TPMs cannot create a 4096 bit RSA key, so a TPM that
    /// refuses falls back to a software key of the requested size rather than silently shortening
    /// the key.
    /// </summary>
    private string CreateCsrWithKeyProviderFallback(
        string subjectName,
        List<string> sans,
        int keyLength,
        bool localStore,
        List<string> ekus,
        string? requestedKeyProvider,
        bool makePrivateKeyExportable,
        string? challengePassword
    )
    {
        bool callerSupplied = !string.IsNullOrWhiteSpace(requestedKeyProvider);
        string keyProvider = callerSupplied
            ? requestedKeyProvider!
            : makePrivateKeyExportable
                ? KeyProviders.SoftwareKeyStorage
                : KeyProviders.DefaultForDeviceCertificate();

        while (true)
        {
            try
            {
                return certStoreService.CreateCSR(
                    subjectName,
                    sans,
                    keyLength,
                    localStore,
                    ekus,
                    keyProvider,
                    null,
                    makePrivateKeyExportable,
                    null,
                    challengePassword
                );
            }
            catch (Exception ex)
            {
                // The failed attempt may already have created its key container, and the retry
                // below replaces the pending request that owns it, so it has to be released here
                // or nothing can reach it afterwards.
                certStoreService.DiscardPendingRequest();
                string? fallback = KeyProviders.FallbackFor(keyProvider, callerSupplied);
                if (fallback == null)
                {
                    throw;
                }

                LogWarning(
                    $"Could not create a {keyLength} bit key with '{keyProvider}': {ex.Message}. "
                        + $"Falling back to '{fallback}'. Most TPMs only support 2048 bit RSA keys, so pass "
                        + "-k 2048 if you want the key to stay in the TPM."
                );
                keyProvider = fallback;
                // Only fall back once, so a failure of the fallback is reported rather than looped.
                callerSupplied = true;
            }
        }
    }

    /// <summary>
    /// Writes the issued certificate to --Path when one was given. The private key is only pulled
    /// out of the store for the file formats that carry one.
    /// </summary>
    private async Task SaveIssuedCertificateToPathAsync(
        X509Certificate2 certificate,
        bool localStore,
        string? path,
        string? password
    )
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        X509Certificate2 toSave = ShouldMakePrivateKeyExportable(path)
            ? certStoreService.AddPrivateKeyToCertificate(certificate, localStore)
            : certificate;
        await CheckAndSaveCertificateWithPrivateKeyToPathAsync(toSave, path, password);
    }

    /// <summary>
    /// Re-armors a certificate request as standard PEM. CertEnroll hands back
    /// "BEGIN NEW CERTIFICATE REQUEST", which is Microsoft's own label: a server decoding by label
    /// would reject it, or re-armor it and then hash different bytes than the ones the attestation
    /// is bound to.
    /// </summary>
    internal static string ToStandardCsrPem(byte[] csrDer)
    {
        ArgumentNullException.ThrowIfNull(csrDer);
        return new string(PemEncoding.Write("CERTIFICATE REQUEST", csrDer));
    }

    /// <summary>
    /// Strips the PEM armor from a certificate request. CertEnroll and BouncyCastle both hand
    /// back PEM, and the SCEP envelope and the attestation binding are both over the DER.
    /// </summary>
    internal static byte[] PemToDer(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        string base64 = string.Concat(
            pem.Split('\n', '\r')
                .Select(line => line.Trim())
                .Where(line => line.Length > 0 && !line.StartsWith("-----"))
        );
        return Convert.FromBase64String(base64);
    }

    private async Task<int> CreateSCEPCertificate(SCEPArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }

        try
        {
            ValidateSCEPArgModel(values);
            string url = NormalizeScepUrl(values.url!);
            string password = values.SCEPPassword!;
            LogInformation($"Creating SCEP certificate for {values.SubjectName}");
            X509Certificate2Collection caCertificates = await GetScepCA(url);
            // The request and its key are built by the platform's certificate store rather than in
            // process, so on Windows the key can be created in the TPM and never exported.
            string csrPem = CreateCsrWithKeyProviderFallback(
                CertUtils.EnsureDistinguishedName(values.SubjectName!),
                SubjectAlternativeNameParser.Split(values.SubjectAltNames!),
                values.KeyLength,
                values.LocalCertStore,
                values.EKUs,
                values.KeyProvider,
                ShouldMakePrivateKeyExportable(values.Path),
                password
            );
            int scepResult = await RequestSCEPCertificateAsync(
                caCertificates,
                PemToDer(csrPem),
                values,
                url
            );
            if (scepResult != 0)
            {
                // The request steps report failure by return code rather than by throwing, so the
                // key they left behind is cleaned up here as well as in the catch below.
                certStoreService.DiscardPendingRequest();
            }

            return scepResult;
        }
        catch (Exception ex)
        {
            certStoreService.DiscardPendingRequest();
            _logger.LogError(ex, "Error creating SCEP certificate");
            Console.WriteLine("Error creating certificate: " + ex.Message);
            return 1;
        }
    }

    private void ValidateSCEPArgModel(SCEPArgModel values)
    {
        AssertLocalStoreProperties(values.LocalCertStore);
        AssertCertificatePathProperties(values.Path);
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
                EZCAConstants.ServerAuthenticationEKU,
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

        if (string.IsNullOrWhiteSpace(values.SCEPPassword))
        {
            values.SCEPPassword = Environment.GetEnvironmentVariable("EZCA_SCEP_PASSWORD");
        }
        if (string.IsNullOrWhiteSpace(values.SCEPPassword))
        {
            throw new ArgumentException(
                "SCEP password is required. Provide it via -p / --SCEPPassword or set the EZCA_SCEP_PASSWORD environment variable."
            );
        }
    }

    private void AssertLocalStoreProperties(bool localStore)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            AssertCanWriteToStore(localStore);
        }

        if (localStore && OperatingSystem.IsLinux())
        {
            CheckPreservedUserCredentials();
        }
    }

    /// <summary>
    /// The portal hands out the PKCS7 form of the static SCEP URL, which this client cannot use:
    /// enrolling against it fails with "Cannot find the original signer". The /Static/ endpoint
    /// issues from the same CA with the same password, so the URL is corrected here rather than by
    /// hand in every Group Policy Object that calls the client.
    /// </summary>
    internal static string NormalizeScepUrl(string url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        const string pkcs7Segment = "/SCEP/PKCS7/Static/";
        const string staticSegment = "/SCEP/Static/";
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed))
        {
            return url;
        }

        int index = parsed.AbsolutePath.IndexOf(
            pkcs7Segment,
            StringComparison.OrdinalIgnoreCase
        );
        if (index < 0)
        {
            return url;
        }

        // Only the path is rewritten: a host or a query string that happens to contain the same
        // text is not an endpoint spelling and must be left alone.
        UriBuilder corrected = new(parsed)
        {
            Path = parsed.AbsolutePath[..index]
                + staticSegment
                + parsed.AbsolutePath[(index + pkcs7Segment.Length)..],
        };
        return corrected.Uri.AbsoluteUri;
    }

    private async Task<int> RequestSCEPCertificateAsync(
        X509Certificate2Collection caCertificates,
        byte[] csrDer,
        SCEPArgModel values,
        string url
    )
    {
        try
        {
            X509Certificate2 encryptionCertificate = SelectEncryptionCertificate(caCertificates);
            LogInformation($"Encrypting the SCEP request for {encryptionCertificate.Subject}");
            X509Certificate bouncyCastleCACert = DotNetUtilities.FromX509Certificate(
                encryptionCertificate
            );
            CmsEnvelopedDataGenerator envelopedDataGenerator = new();
            envelopedDataGenerator.AddKeyTransRecipient(bouncyCastleCACert);
            CmsProcessable req = new CmsProcessableByteArray(csrDer);
            CmsEnvelopedData encryptedEnvelope = envelopedDataGenerator.Generate(
                req,
                CmsEnvelopedGenerator.Aes256Cbc
            );
            byte[] encryptedBytes = encryptedEnvelope.GetEncoded();
            //create Signing Key
            AsymmetricCipherKeyPair signingKeyPair = CreateKeyPair($"RSA {values.KeyLength}");
            X509Certificate2 cert = GenerateSelfSignedCertificate(signingKeyPair, "TempCert");
            CmsSigner signer = new(cert);
            AsnEncodedData messageType = new(
                "2.16.840.1.113733.1.9.2",
                DerEncoding.EncodePrintableString("19")
            );
            signer.SignedAttributes.Add(messageType);
            Pkcs9AttributeObject transactionID = new Pkcs9AttributeObject(
                "2.16.840.1.113733.1.9.7",
                DerEncoding.EncodePrintableString(
                    Convert.ToBase64String(SHA512.HashData(cert.GetPublicKey()))
                )
            );
            signer.SignedAttributes.Add(transactionID);
            SecureRandom random = new();
            byte[] nonceBytes = new byte[16]; // Typically a 16-byte nonce
            random.NextBytes(nonceBytes);
            Pkcs9AttributeObject nonce = new Pkcs9AttributeObject(
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
            HttpResponseMessage response = await _httpClient.PostAsync(url, content);
            if (!response.IsSuccessStatusCode)
            {
                throw new Exception(
                    $"Failed to request SCEP certificate: {response.StatusCode} "
                        + await response.Content.ReadAsStringAsync()
                );
            }

            byte[] responseBytes = await response.Content.ReadAsByteArrayAsync();
            return await DecodeAndInstallSCEPCertificate(
                responseBytes,
                csrDer,
                caCertificates,
                nonceBytes,
                cert,
                values.LocalCertStore,
                values.Path,
                values.Password
            );
        }
        catch (Exception ex)
        {
            LogError(ex, "Error Requesting SCEP certificate");
            return 1;
        }
    }

    private async Task<int> DecodeAndInstallSCEPCertificate(
        byte[] responseBytes,
        byte[] csrDer,
        X509Certificate2Collection caCertificates,
        byte[] nonce,
        X509Certificate2 signingCert,
        bool localStore,
        string? path = null,
        string? password = null
    )
    {
        SignedCms signedResponse = new();
        signedResponse.Decode(responseBytes);
        VerifyScepResponseSignature(signedResponse, caCertificates);
        List<CryptographicAttributeObject> attributes = signedResponse
            .SignerInfos.Cast<SignerInfo>()
            .SelectMany(si => si.SignedAttributes.Cast<CryptographicAttributeObject>())
            .ToList();
        CryptographicAttributeObject recipientNonce =
            attributes.FirstOrDefault(a => a.Oid.Value == "2.16.840.1.113733.1.9.6")
            ?? throw new Exception("Recipient nonce not found in response");
        if (!nonce.SequenceEqual(recipientNonce.Values[0].RawData.AsSpan()[2..]))
        {
            throw new Exception("Recipient nonce does not match");
        }

        EnvelopedCms cmsResponse = new();
        cmsResponse.Decode(signedResponse.ContentInfo.Content);
        cmsResponse.Decrypt(new X509Certificate2Collection(signingCert));
        X509Certificate2Collection certCollection = [];
        certCollection.Import(cmsResponse.ContentInfo.Content);
        Pkcs10CertificationRequest request = new(csrDer);
        X509Certificate2? cert = SelectIssuedCertificate(certCollection, request.GetPublicKey());
        if (cert == null)
        {
            Exception ex = new("No end-entity certificate found in the SCEP response");
            LogError(ex);
            return 1;
        }

        LogInformation(
            $"Installing certificate with subject {cert.Subject} to {CertUtils.StoreString(localStore)}"
        );
        // The key was created by the certificate store when the request was built, so installing
        // the response is what binds the two. Nothing here ever holds the private key, which is
        // what lets it stay in the TPM.
        certStoreService.InstallCertificate(cert, localStore, password);
        LogInformation(
            $"Certificate installed successfully in {CertUtils.StoreString(localStore)} with thumbprint {cert.Thumbprint}"
        );
        await SaveIssuedCertificateToPathAsync(cert, localStore, path, password);
        return 0;
    }

    private static bool IsCACertificate(X509Certificate2 cert)
    {
        X509BasicConstraintsExtension? basicConstraints = (X509BasicConstraintsExtension?)
            cert.Extensions["2.5.29.19"];
        bool isCA = basicConstraints != null && basicConstraints.CertificateAuthority;
        return isCA;
    }

    private X509Certificate2 GenerateSelfSignedCertificate(
        AsymmetricCipherKeyPair keyPair,
        string subjectName,
        int validDays = 2
    )
    {
        // Create the certificate generator
        X509V3CertificateGenerator certGen = new();

        // Set certificate subject and issuer (self-signed so issuer is the same as the subject)
        X509Name issuerName = new($"CN={subjectName}");
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
        X509Certificate2 cert = X509CertificateLoader.LoadCertificate(
            bouncyCastleCert.GetEncoded()
        );
        RSA rsaPrivateKey = certStoreService.ConvertToDotnetRSA(
            (RsaPrivateCrtKeyParameters)keyPair.Private
        );
        cert = cert.CopyWithPrivateKey(rsaPrivateKey);
        return cert;
    }

    private static AsymmetricCipherKeyPair CreateKeyPair(string keyAlgo)
    {
        CryptoApiRandomGenerator randomGenerator = new();
        SecureRandom random = new(randomGenerator);
        if (keyAlgo.Contains("RSA", StringComparison.OrdinalIgnoreCase))
        {
            int strength = int.Parse(keyAlgo.Split(" ")[1]);
            KeyGenerationParameters keyGenerationParameters = new(random, strength);
            RsaKeyPairGenerator keyPairGenerator = new();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        if (keyAlgo.Contains("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            ECKeyPairGenerator ecKeyPairGenerator = new();
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

    /// <summary>
    /// Downloads the certificates the SCEP server publishes through GetCACert.
    /// The whole response is kept, since the certificate the request has to be
    /// encrypted to and the certificate the response is signed with are not
    /// necessarily the same one.
    /// </summary>
    private async Task<X509Certificate2Collection> GetScepCA(string scepURL)
    {
        HttpResponseMessage caResponse = await _httpClient.GetAsync(
            string.Concat(scepURL, "?operation=GetCACert&message=ca")
        );
        if (!caResponse.IsSuccessStatusCode)
        {
            throw new Exception(
                "Error getting SCEP CA certificate: " + await caResponse.Content.ReadAsStringAsync()
            );
        }

        byte[] caCertData = await caResponse.Content.ReadAsByteArrayAsync();
        X509Certificate2Collection certs = ParseCaCertificateResponse(caCertData);
        X509Certificate2 caCert = SelectIssuingCaCertificate(certs);
        // Validate the chain to ensure we trust the CA
        X509Chain chain = new();
        if (certs.Count > 1)
        {
            // Allow the chain to use the other certs in the bundle (e.g. the root)
            // to build the path even if they are not yet in the system store.
            chain.ChainPolicy.ExtraStore.AddRange(certs);
        }

        if (chain.Build(caCert))
        {
            return certs;
        }

        throw new Exception(
            "Error building chain for SCEP CA certificate: "
                + chain.ChainStatus[0].StatusInformation
        );
    }

    /// <summary>
    /// Parses the body of a SCEP GetCACert response. The body can be either a
    /// single DER- or PEM-encoded certificate (application/x-x509-ca-cert) or a
    /// PKCS#7 bundle containing the issuing CA and its parents
    /// (application/x-x509-ca-ra-cert). Import() transparently handles all of
    /// these encodings.
    /// </summary>
    internal static X509Certificate2Collection ParseCaCertificateResponse(byte[] caCertData)
    {
        X509Certificate2Collection certs = [];
        certs.Import(caCertData);
        if (certs.Count == 0)
        {
            throw new Exception("No certificate found in the SCEP GetCACert response");
        }

        return certs;
    }

    /// <summary>
    /// Selects the issuing CA certificate from a GetCACert response. When the
    /// response is a PKCS#7 bundle it contains the issuing CA plus its parents,
    /// and possibly an RA certificate, which is not a CA and therefore never the
    /// issuer. The issuing CA is the CA certificate at the bottom of the
    /// hierarchy, i.e. the one whose subject is not the issuer of any other CA
    /// certificate in the bundle.
    /// </summary>
    internal static X509Certificate2 SelectIssuingCaCertificate(X509Certificate2Collection certs)
    {
        if (certs.Count == 1)
        {
            return certs[0];
        }

        List<X509Certificate2> candidates = certs.Where(IsCACertificate).ToList();
        if (candidates.Count == 0)
        {
            candidates = [.. certs];
        }

        foreach (X509Certificate2 candidate in candidates)
        {
            bool issuesAnotherCert = candidates.Any(other =>
                !ReferenceEquals(other, candidate)
                && other.IssuerName.RawData.SequenceEqual(candidate.SubjectName.RawData)
            );
            if (!issuesAnotherCert)
            {
                return candidate;
            }
        }

        return candidates[0];
    }

    /// <summary>
    /// Selects the certificate the CSR is encrypted to. A GetCACert response may
    /// carry an RA certificate next to the CA chain; when it does, the request is
    /// encrypted to the RA key encipherment certificate, otherwise it is
    /// encrypted to the issuing CA itself, which is what a plain CA endpoint
    /// returns.
    /// </summary>
    internal static X509Certificate2 SelectEncryptionCertificate(X509Certificate2Collection certs)
    {
        if (certs.Count == 1)
        {
            return certs[0];
        }

        X509Certificate2? raCertificate = certs
            .Where(cert => !IsCACertificate(cert) && SupportsKeyEncipherment(cert))
            .OrderByDescending(cert => cert.NotBefore)
            .FirstOrDefault();
        if (raCertificate != null)
        {
            return raCertificate;
        }

        X509Certificate2 issuingCa = SelectIssuingCaCertificate(certs);
        if (SupportsKeyEncipherment(issuingCa))
        {
            return issuingCa;
        }

        return certs.FirstOrDefault(SupportsKeyEncipherment) ?? issuingCa;
    }

    /// <summary>
    /// True when the certificate can be used as a key transport recipient, that
    /// is when it declares the key encipherment usage or declares no key usage at
    /// all, in which case every usage is allowed.
    /// </summary>
    private static bool SupportsKeyEncipherment(X509Certificate2 cert)
    {
        X509KeyUsageExtension? keyUsage = cert
            .Extensions.OfType<X509KeyUsageExtension>()
            .FirstOrDefault();
        return keyUsage == null
            || keyUsage.KeyUsages == X509KeyUsageFlags.None
            || keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment);
    }

    /// <summary>
    /// Verifies the signature of a SCEP response. The response can be signed by
    /// the issuing CA or by an RA certificate, so every certificate GetCACert
    /// returned is offered as a possible signer on top of the ones the response
    /// carries itself. A response that carries its own signer is only accepted
    /// when that signer chains to one of the certificates GetCACert published,
    /// so a certificate shipped with the response cannot vouch for itself.
    /// </summary>
    internal static void VerifyScepResponseSignature(
        SignedCms signedResponse,
        X509Certificate2Collection caCertificates
    )
    {
        if (signedResponse.SignerInfos.Count == 0)
        {
            throw new Exception("The SCEP response is not signed");
        }

        try
        {
            signedResponse.CheckSignature(caCertificates, true);
        }
        catch (CryptographicException ex)
        {
            throw new Exception(
                "Could not verify the signature of the SCEP response: it was signed by a "
                    + "certificate that is neither included in the response nor published by the "
                    + "GetCACert operation of this SCEP URL ("
                    + DescribeCertificates(caCertificates)
                    + "). Make sure the SCEP URL points to the endpoint that issues the certificates.",
                ex
            );
        }

        foreach (SignerInfo signer in signedResponse.SignerInfos)
        {
            // A signer that is not shipped with the response was resolved by
            // CheckSignature out of the GetCACert certificates, so it is already
            // one of them and needs no further anchoring.
            if (signer.Certificate != null)
            {
                AssertSignerIsAnchoredToCA(
                    signer.Certificate,
                    caCertificates,
                    signedResponse.Certificates
                );
            }
        }
    }

    /// <summary>
    /// Makes sure the certificate that signed a SCEP response is one that
    /// GetCACert published, or chains up to one of them. GetScepCA has already
    /// validated the published issuing CA against the machine trust store, so
    /// the published certificates are the trust anchor here and an unknown root
    /// below them is not accepted on its own.
    /// </summary>
    private static void AssertSignerIsAnchoredToCA(
        X509Certificate2 signerCertificate,
        X509Certificate2Collection caCertificates,
        X509Certificate2Collection responseCertificates
    )
    {
        if (caCertificates.Any(caCert => caCert.RawData.SequenceEqual(signerCertificate.RawData)))
        {
            return;
        }

        using X509Chain chain = new();
        chain.ChainPolicy.ExtraStore.AddRange(caCertificates);
        chain.ChainPolicy.ExtraStore.AddRange(responseCertificates);
        // The published certificates are the anchor, not the machine store, and
        // their revocation status was checked when they were downloaded.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.AllowUnknownCertificateAuthority;
        bool chainIsValid = chain.Build(signerCertificate);
        bool anchoredToPublishedCA = chain.ChainElements.Any(element =>
            caCertificates.Any(caCert => caCert.RawData.SequenceEqual(element.Certificate.RawData))
        );
        if (chainIsValid && anchoredToPublishedCA)
        {
            return;
        }

        throw new Exception(
            $"The SCEP response was signed by {signerCertificate.Subject}, which does not chain to "
                + "any of the certificates published by the GetCACert operation of this SCEP URL ("
                + DescribeCertificates(caCertificates)
                + "). Refusing the response."
        );
    }

    private static string DescribeCertificates(X509Certificate2Collection certs)
    {
        return string.Join(", ", certs.Select(cert => cert.Subject));
    }

    /// <summary>
    /// Finds the certificate that was issued for our request in a SCEP response.
    /// The response is a degenerate PKCS#7 that may carry the full chain, and on
    /// an RA based endpoint other end entity certificates as well, so the issued
    /// certificate is identified by the public key that was sent in the CSR.
    /// </summary>
    internal static X509Certificate2? SelectIssuedCertificate(
        X509Certificate2Collection certs,
        AsymmetricKeyParameter requestPublicKey
    )
    {
        byte[] requestedKey = SubjectPublicKeyInfoFactory
            .CreateSubjectPublicKeyInfo(requestPublicKey)
            .GetDerEncoded();
        X509Certificate2? issuedCert = certs.FirstOrDefault(cert =>
            cert.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(requestedKey)
        );
        return issuedCert
            ?? certs.OrderBy(cert => cert.NotBefore).LastOrDefault(cert => !IsCACertificate(cert));
    }

    private string GetComputerSubjectName()
    {
        return SystemInfoUtils.GetComputerSubjectName(systemInfoService);
    }

    private static string GetFQDN(string computerName = "")
    {
        return SystemInfoUtils.GetFQDN(computerName);
    }

    private async Task<int> RegisterDomainAsync(RegisterArgModel values)
    {
        if (_logger == null)
        {
            throw new ArgumentNullException(nameof(_logger));
        }

        try
        {
            ValidateRegisterArgModel(values);
            EZCAClientClass ezcaClient = new(_httpClient, _logger, values.url);
            LogInformation("Getting available CAs");
            AvailableCAModel selectedCA = await GetCAAsync(values.caID, ezcaClient);
            LogInformation($"Registering domain: {values.Domain}");
            APIResultModel registrationResult = await ezcaClient.RegisterDomainAsync(
                selectedCA,
                values.Domain!
            );
            if (!registrationResult.Success)
            {
                throw new InvalidOperationException(
                    $"Could not register new domain in EZCA {registrationResult.Message}"
                );
            }

            LogInformation($"Successfully registered domain: {values.Domain}");
        }
        catch (Exception ex)
        {
            LogError(ex, "Error registering domain");
            return 1;
        }

        return 0;
    }

    private void ValidateRegisterArgModel(RegisterArgModel values)
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
    }

    private void SetRDPCertificate(string thumbprint)
    {
        systemInfoService.SetRDPCertificate(thumbprint);
    }

    private void SetIISCertificate(X509Certificate2 certificate, string? siteName)
    {
        if (string.IsNullOrWhiteSpace(siteName))
        {
            return;
        }

        APIResultModel result = systemInfoService.SetIISCertificate(
            certificate.Thumbprint,
            siteName
        );
        if (!result.Success)
        {
            throw new InvalidOperationException(result.Message);
        }

        LogInformation(result.Message);
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
        List<string>? additionalSubjectAltNames = null,
        string? path = "",
        string? password = null,
        string sid = ""
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
            List<string> newSans = additionalSubjectAltNames
                .Where(san => !subjectAltNames.Contains(san, StringComparer.OrdinalIgnoreCase))
                .ToList();
            subjectAltNames.AddRange(newSans);
        }

        subjectName = CertUtils.EnsureDistinguishedName(subjectName);

        LogInformation($"Creating CSR with subject name {subjectName}");
        bool makePrivateKeyExportable = ShouldMakePrivateKeyExportable(path);
        string csr = certStoreService.CreateCSR(
            subjectName,
            subjectAltNames,
            keyLength,
            localStore,
            ekus,
            keyProvider,
            null,
            makePrivateKeyExportable
        );
        X509Certificate2? cert;
        if (dcCertificate)
        {
            LogInformation($"Getting Domain Controller certificate for {domain}");
            cert = await ezcaClient.RequestDCCertificateAsync(
                selectedCA,
                csr,
                subjectName,
                domain,
                validity,
                ekus,
                dcGUID,
                sid
            );
        }
        else
        {
            LogInformation($"Getting certificate for {domain}");
            cert = await ezcaClient.RequestCertificateAsync(selectedCA, csr, domain, validity);
        }

        if (cert != null)
        {
            LogInformation(
                $"Installing Certificate for {domain} with thumbprint {cert.Thumbprint}"
            );
            certStoreService.InstallCertificate(cert, localStore, password);
            LogInformation(
                $"Successfully created certificate for {domain} with thumbprint {cert.Thumbprint}"
            );
            await CheckAndSaveCertificateToPathAsync(cert, localStore, path, password);
            return cert;
        }

        throw new CryptographicException($"Error requesting EZCA certificate for {domain}");
    }

    private static async Task<AvailableCAModel> GetCAAsync(string caID, IEZCAClient ezcaClient)
    {
        AvailableCAModel[]? availableCAs = await ezcaClient.GetAvailableCAsAsync();
        if (availableCAs == null || availableCAs.Length == 0)
        {
            throw new NullReferenceException("Could not find any available CAs in EZCA");
        }

        AvailableCAModel? selectedCA = availableCAs.FirstOrDefault(i => i.CAID == caID);
        if (selectedCA != null)
        {
            return selectedCA;
        }

        throw new ArgumentOutOfRangeException(
            $"No CA with CA ID {caID} was found, make sure you have access to request from this CA"
        );
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

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                builder.AddEventLog();
            }
            else
            {
                builder.AddConsole();
            }
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
        List<X509SubjectAlternativeName> subjectAlternativeNames = new();

        // Convert X509Certificate2 to Bouncy Castle X509Certificate
        X509CertificateParser parser = new();
        X509Certificate bcCert = parser.ReadCertificate(certificate.RawData);

        // Get the SubjectAlternativeNames extension
        Asn1OctetString sanExtension = bcCert.GetExtensionValue(
            X509Extensions.SubjectAlternativeName
        );

        if (sanExtension != null)
        {
            Asn1Object asn1Object = X509ExtensionUtilities.FromExtensionValue(sanExtension);
            GeneralNames generalNames = GeneralNames.GetInstance(asn1Object);

            foreach (GeneralName generalName in generalNames.GetNames())
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
                        Asn1Sequence sequence = Asn1Sequence.GetInstance(generalName.Name);
                        DerObjectIdentifier oid = DerObjectIdentifier.GetInstance(sequence[0]);
                        if (oid.Id == "1.3.6.1.4.1.311.20.2.3") // OID for UPN
                        {
                            DerUtf8String upn = DerUtf8String.GetInstance(
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

    private void LogInformation(string message)
    {
        ArgumentNullException.ThrowIfNull(_logger);
        _logger.LogInformation(message);
        Console.WriteLine(message);
    }

    private void LogWarning(string message)
    {
        ArgumentNullException.ThrowIfNull(_logger);
        _logger.LogWarning(message);
        Console.WriteLine(message);
    }

    private void LogError(Exception ex, string? message = null)
    {
        ArgumentNullException.ThrowIfNull(_logger);
        if (string.IsNullOrWhiteSpace(message))
        {
            message = ex.Message;
        }

        _logger.LogError(ex, message);
        Console.WriteLine($"{message}: {ex}");
    }
}

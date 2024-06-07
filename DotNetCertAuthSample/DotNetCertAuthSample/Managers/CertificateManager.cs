using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using CERTENROLLLib;
using CommandLine;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using EZCAClient.Managers;
using EZCAClient.Models;
using EZCAClient.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace DotNetCertAuthSample.Managers;

public class CertificateManager
{
    private ILogger? _logger;
    private RenewArgModel? _renewArgModel;
    private GenerateArgModel? _generateArgModel;
    private RegisterArgModel? _registerArgModel;
    private CreateDCCertificate? _createDCCertArgModel;

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

    public int ProcessError(IEnumerable<Error> errs)
    {
        return 1;
    }

    public async Task<int> CallCertActionAsync()
    {
        if (_renewArgModel != null)
        {
            return await RenewAsync(_renewArgModel);
        }
        if (_generateArgModel != null)
        {
            return await CreateCertAsync(_generateArgModel);
        }
        if (_registerArgModel != null)
        {
            return await RegisterAndCreateCertAsync(_registerArgModel);
        }
        if (_createDCCertArgModel != null)
        {
            return await CreateDCCertAsync(_createDCCertArgModel);
        }
        return -1;
    }

    private async Task<int> RenewAsync(RenewArgModel values)
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
            if (string.IsNullOrWhiteSpace(values.Domain))
            {
                throw new ArgumentNullException(nameof(values.Domain));
            }
            X509Certificate2 cert = WindowsCertStoreService.GetCertFromWinStoreBySubject(
                values.Domain.Replace("CN=", "").Trim(),
                values.LocalCertStore,
                values.issuer,
                values.template
            );
            CX509CertificateRequestPkcs10 certRequest = WindowsCertStoreService.CreateCSR(
                cert.SubjectName.Name,
                GetSubjectAlternativeNames(cert)
                    .Where(i => i.Type == SANTypes.DNSName)
                    .Select(i => i.Value)
                    .ToList(),
                4096,
                values.LocalCertStore,
                new()
            );
            string csr = certRequest.RawData[EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER];
            _logger.LogInformation($"Renewing certificate");
            Console.WriteLine($"Renewing certificate");
            IEZCAClient ezcaClient = new EZCAClientClass(new HttpClient(), _logger, values.url);
            string createdCert = await ezcaClient.RenewCertificateAsync(cert, csr);
            WindowsCertStoreService.InstallCertificate(createdCert, certRequest);
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
            if (values.RDPCert && values.LocalCertStore == false)
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
                ekus
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
                values.DCGUID
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

    private string GetComputerSubjectName()
    {
        string computerName = Dns.GetHostName();
        string? distinguishedName = GetComputerDistinguishedName(computerName);
        if (!string.IsNullOrWhiteSpace(distinguishedName))
        {
            return distinguishedName;
        }
        return GetFQDN(computerName);
    }

    private string? GetComputerDistinguishedName(string computerName)
    {
        // set up domain context
        try
        {
            var context = new PrincipalContext(ContextType.Domain);

            // find computer
            var computer = ComputerPrincipal.FindByIdentity(context, computerName);

            if (computer != null)
            {
                // get the Distinguished Name
                return computer.DistinguishedName;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Error getting computer distinguished name " + e.Message);
            _logger?.LogError(e, "Error getting computer distinguished name");
        }
        return null;
    }

    private static string GetFQDN(string computerName = "")
    {
        // Get the host entry for the local computer.
        if (string.IsNullOrWhiteSpace(computerName))
        {
            computerName = Dns.GetHostName();
        }
        var hostEntry = Dns.GetHostEntry(computerName);

        // Return the first DNS name assigned to this address (should be the FQDN).
        return hostEntry.HostName;
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
        string namespaceValue = @"root\cimv2\TerminalServices";
        string queryDialect = "WQL";
        string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
        string thumbprintProperty = "SSLCertificateSHA1Hash";
        var dComOpts = new DComSessionOptions()
        {
            Culture = CultureInfo.CurrentCulture,
            UICulture = CultureInfo.CurrentUICulture,
            PacketIntegrity = true,
            PacketPrivacy = true,
            Timeout = new TimeSpan(0)
        };
        CimSession cimSession = CimSession.Create("localhost", dComOpts);
        CimInstance? instance = cimSession
            .QueryInstances(namespaceValue, queryDialect, query)
            .ToArray()
            .FirstOrDefault();
        if (instance == null)
        {
            throw new Exception("Error getting RDP service");
        }
        var check = !instance.CimInstanceProperties[thumbprintProperty].Value.Equals(thumbprint);
        if (check)
        {
            var prop = instance.CimInstanceProperties[thumbprintProperty];
            prop.Value = thumbprint;
            cimSession.ModifyInstance(instance);
        }
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
        string dcGUID = ""
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
        List<string> subjectAltNames = [domain];
        if (
            !subjectName.StartsWith("CN=", StringComparison.InvariantCultureIgnoreCase)
            && !subjectName.StartsWith("CN =", StringComparison.InvariantCultureIgnoreCase)
        )
        {
            subjectName = "CN=" + subjectName;
        }
        CX509CertificateRequestPkcs10 certRequest = WindowsCertStoreService.CreateCSR(
            subjectName,
            subjectAltNames,
            4096,
            localStore,
            ekus
        );
        string csr = certRequest.RawData[EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER];
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
            WindowsCertStoreService.InstallCertificate(
                CryptoStaticService.ExportToPEM(windowsCert),
                certRequest
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

    private static ILogger CreateLogger(string? appInsightsKey)
    {
        IServiceCollection services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            if (!string.IsNullOrWhiteSpace(appInsightsKey))
            {
                builder.AddApplicationInsights(
                    configureTelemetryConfiguration: (config) =>
                        config.ConnectionString = appInsightsKey,
                    configureApplicationInsightsLoggerOptions: (options) => { }
                );
            }
            builder.AddEventLog();
        });
        IServiceProvider serviceProvider = services.BuildServiceProvider();
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

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DotNetCertAuthSample.Managers;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;
using Xunit;

namespace DotNetCertAuthSample.Test;

public class CertificateManagerTests
{
    private static CertificateManager CreateManager()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
#if WINDOWS
            IStoreService storeService = new UnifiedStoreService();
            ICertStoreService certStoreService = new WindowsCertService(storeService);
            ISystemInfoService systemInfoService = new WindowsSystemInfoService();
            return new CertificateManager(certStoreService, systemInfoService);
#else
            throw new Exception("Windows-specific services not available in this build.");
#endif
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            IStoreService storeService = new LinuxStoreService();
            ICertStoreService certStoreService = new UnifiedCertStoreService(storeService);
            ISystemInfoService systemInfoService = new UnifiedSystemInfoService();
            return new CertificateManager(certStoreService, systemInfoService);
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            IStoreService storeService = new UnifiedStoreService();
            ICertStoreService certStoreService = new UnifiedCertStoreService(storeService);
            ISystemInfoService systemInfoService = new UnifiedSystemInfoService();
            return new CertificateManager(certStoreService, systemInfoService);
        }

        throw new Exception("Unsupported operating system for tests.");
    }

    private static string NewDomain() => Guid.NewGuid().ToString("N")[..8] + ".com";

    [Fact]
    [Trait("Privilege", "User")]
    public async Task Register_Domain()
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();

        RegisterArgModel registerArgs = new() { Domain = domainUser, caID = TestConfig.SslCaId };

        manager.InitializeManager(registerArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    public async Task Register_Domain_EU_Instance_WithAppInsights()
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();

        RegisterArgModel registerArgs = new()
        {
            Domain = domainUser,
            caID = TestConfig.SslCaId,
            url = "https://eu.ezca.io",
            AppInsightsKey = TestConfig.AppInsights,
        };

        manager.InitializeManager(registerArgs);
        int result = await manager.CallCertActionAsync(); // ca does not exist in eu
        Assert.Equal(1, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    public async Task Create_User_Certificate_UserStore()
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();

        GenerateArgModel createUserArgs = new()
        {
            Domain = domainUser,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(createUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    private static string GetRandomPassword()
    {
        const string alphanumericCharacters =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        return RandomNumberGenerator.GetString(alphanumericCharacters, 30);
    }

    [Theory]
    [Trait("Privilege", "User")]
    [InlineData("./my-cert", "./my-cert.pfx", true)]
    [InlineData("./my-cert.pfx", "./my-cert.pfx", true)]
    [InlineData("./my-cert.p12", "./my-cert.p12", true)]
    [InlineData("./my-cert.pem", "./my-cert.pem", false)]
    [InlineData("./my-cert.cer", "./my-cert.cer", false)]
    [InlineData("./my-cert.crt", "./my-cert.crt", false)]
    public async Task Create_User_Certificate_UserStore_Save_To_Path(
        string path,
        string expectedPath,
        bool includePrivateKey
    )
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();
        string password = GetRandomPassword();

        GenerateArgModel createUserArgs = new()
        {
            Domain = domainUser,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = false,
            Path = path,
            Password = password,
        };
        manager.InitializeManager(createUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
        AssertCorrectCertificateFile(expectedPath, includePrivateKey, password);
        DeleteCertificateFiles(path);
    }

    private static void AssertCorrectCertificateFile(
        string expectedFilePath,
        bool includePrivateKey,
        string? password
    )
    {
        Assert.True(File.Exists(expectedFilePath));
        X509Certificate2? cert;
        if (includePrivateKey)
        {
            cert = X509CertificateLoader.LoadPkcs12FromFile(expectedFilePath, password);
            Assert.True(cert.HasPrivateKey);
        }
        else
        {
            cert = X509CertificateLoader.LoadCertificateFromFile(expectedFilePath);
            Assert.False(cert.HasPrivateKey);
        }
    }

    private static void DeleteCertificateFiles(string path)
    {
        string[] files = Directory.GetFiles(
            Path.GetDirectoryName(path) ?? ".",
            $"{Path.GetFileNameWithoutExtension(path)}*"
        );
        foreach (string file in files)
        {
            try
            {
                File.Delete(file);
            }
            catch
            {
                continue;
            }
        }
    }

    [Fact]
    [Trait("Privilege", "Root")]
    public async Task Create_Machine_Certificate_LocalStore()
    {
        CertificateManager manager = CreateManager();
        string domainMachine = NewDomain();

        GenerateArgModel createMachineArgs = new()
        {
            Domain = domainMachine,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = true,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(createMachineArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    public async Task Renew_User_Certificate_UserStore()
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();

        GenerateArgModel createUserArgs = new()
        {
            Domain = domainUser,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(createUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);

        RenewArgModel renewUserArgs = new()
        {
            Domain = domainUser,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(renewUserArgs);
        result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "Root")]
    public async Task Renew_Machine_Certificate_LocalStore()
    {
        CertificateManager manager = CreateManager();
        string domainMachine = NewDomain();

        GenerateArgModel createMachineArgs = new()
        {
            Domain = domainMachine,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = true,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(createMachineArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);

        RenewArgModel renewMachineArgs = new()
        {
            Domain = domainMachine,
            LocalCertStore = true,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(renewMachineArgs);
        result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    public async Task Renew_User_Certificate_Search_By_Issuer_UserStore()
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();

        GenerateArgModel createUserArgs = new()
        {
            Domain = domainUser,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(createUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);

        RenewArgModel renewUserArgs = new()
        {
            Domain = domainUser,
            issuer = TestConfig.SslCaIssuer,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(renewUserArgs);
        result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "Root")]
    public async Task Renew_Machine_Certificate_Search_By_Issuer_LocalStore()
    {
        CertificateManager manager = CreateManager();
        string domainMachine = NewDomain();

        GenerateArgModel createMachineArgs = new()
        {
            Domain = domainMachine,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = true,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(createMachineArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);

        RenewArgModel renewMachineArgs = new()
        {
            Domain = domainMachine,
            issuer = TestConfig.SslCaIssuer,
            LocalCertStore = true,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(renewMachineArgs);
        result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "Root")]
    public async Task Create_DomainController_Certificate_LocalStore()
    {
        CertificateManager manager = CreateManager();
        const string dnsName = "dc.cert.contoso.com";
        string dcSubject = dnsName;

        CreateDCCertificate createDcArgs = new()
        {
            Domain = dnsName,
            SubjectName = dcSubject,
            caID = TestConfig.ScepCaId,
            TemplateID = TestConfig.ScepTemplateId,
            Validity = 30,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(createDcArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "Root")]
    public async Task Create_DomainController_Certificate_EKUs_LocalStore()
    {
        CertificateManager manager = CreateManager();
        const string dnsName = "dc.cert.contoso.com";
        string dcSubject = dnsName;
        List<string> ekus = ["1.3.6.1.5.5.7.3.5"];

        CreateDCCertificate createDcArgs = new()
        {
            Domain = dnsName,
            SubjectName = dcSubject,
            caID = TestConfig.ScepCaId,
            TemplateID = TestConfig.ScepTemplateId,
            Validity = 30,
            Password = TestConfig.CertPassword,
            EKUs = ekus,
        };
        manager.InitializeManager(createDcArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "Root")]
    public async Task Create_DomainController_Certificate_SubjectAltNames_LocalStore()
    {
        CertificateManager manager = CreateManager();
        const string dnsName = "dc.cert.contoso.com";
        string dcSubject = dnsName;
        string subjectAltNames = "one.contoso.com,two.contoso.com,three.contoso.com";

        CreateDCCertificate createDcArgs = new()
        {
            SubjectName = dcSubject,
            caID = TestConfig.ScepCaId,
            TemplateID = TestConfig.ScepTemplateId,
            Validity = 30,
            Password = TestConfig.CertPassword,
            SubjectAltNames = subjectAltNames,
        };
        manager.InitializeManager(createDcArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    public async Task Request_Scep_User_Certificate_UserStore()
    {
        CertificateManager manager = CreateManager();
        const string scepSubjectUser = "CN=user.scep.contoso.com";
        const string scepSans = "machine.contoso.com,machine2.contoso.com";

        SCEPArgModel scepUserArgs = new()
        {
            url = TestConfig.ScepUrl,
            SubjectName = scepSubjectUser,
            SCEPPassword = TestConfig.ScepPassword,
            SubjectAltNames = scepSans,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(scepUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "Root")]
    public async Task Request_Scep_Machine_Certificate_LocalStore()
    {
        CertificateManager manager = CreateManager();
        const string scepSubjectMachine = "CN=machine.scep.contoso.com";
        const string scepSans = "machine.contoso.com,machine2.contoso.com";

        SCEPArgModel scepMachineArgs = new()
        {
            url = TestConfig.ScepUrl,
            SubjectName = scepSubjectMachine,
            SCEPPassword = TestConfig.ScepPassword,
            SubjectAltNames = scepSans,
            LocalCertStore = true,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(scepMachineArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    public async Task Renew_Scep_User_Certificate_UserStore()
    {
        CertificateManager manager = CreateManager();
        const string scepSubjectUser = "CN=user.scep.contoso.com";
        const string scepSans = "machine.contoso.com,machine2.contoso.com";

        SCEPArgModel scepUserArgs = new()
        {
            url = TestConfig.ScepUrl,
            SubjectName = scepSubjectUser,
            SCEPPassword = TestConfig.ScepPassword,
            SubjectAltNames = scepSans,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(scepUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);

        RenewArgModel renewScepUserArgs = new()
        {
            Domain = scepSubjectUser,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(renewScepUserArgs);
        result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    public async Task Renew_Scep_User_Certificate_Long_Subject_Name_UserStore()
    {
        CertificateManager manager = CreateManager();
        const string scepSubjectUser = "CN=user.scep.contoso.com,OU=test,O=testing,C=USA";
        const string scepSans = "machine.contoso.com,machine2.contoso.com";

        SCEPArgModel scepUserArgs = new()
        {
            url = TestConfig.ScepUrl,
            SubjectName = scepSubjectUser,
            SCEPPassword = TestConfig.ScepPassword,
            SubjectAltNames = scepSans,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(scepUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);

        RenewArgModel renewScepUserArgs = new()
        {
            Domain = scepSubjectUser,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(renewScepUserArgs);
        result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "Root")]
    public async Task Renew_Scep_Machine_Certificate_LocalStore()
    {
        CertificateManager manager = CreateManager();
        const string scepSubjectMachine = "CN=machine.scep.contoso.com";
        const string scepSans = "machine.contoso.com,machine2.contoso.com";

        SCEPArgModel scepMachineArgs = new()
        {
            url = TestConfig.ScepUrl,
            SubjectName = scepSubjectMachine,
            SCEPPassword = TestConfig.ScepPassword,
            SubjectAltNames = scepSans,
            LocalCertStore = true,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(scepMachineArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);

        RenewArgModel renewScepMachineArgs = new()
        {
            Domain = scepSubjectMachine,
            LocalCertStore = true,
            Password = TestConfig.CertPassword,
        };
        manager.InitializeManager(renewScepMachineArgs);
        result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    public async Task Create_User_Certificate_UserStore_KeyLength()
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();

        GenerateArgModel createUserArgs = new()
        {
            Domain = domainUser,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
            KeyLength = 2048,
        };
        manager.InitializeManager(createUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    [Trait("OS", "Windows")]
    public async Task Create_User_Certificate_UserStore_SoftwareKeyProvider()
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();

        GenerateArgModel createUserArgs = new()
        {
            Domain = domainUser,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
            KeyProvider = "Microsoft Software Key Storage Provider",
        };
        manager.InitializeManager(createUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    [Trait("OS", "Windows")]
    public async Task Create_User_Certificate_UserStore_CryptoKeyProvider()
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();

        GenerateArgModel createUserArgs = new()
        {
            Domain = domainUser,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
            KeyProvider = "Microsoft Enhanced Cryptographic Provider v1.0",
        };
        manager.InitializeManager(createUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }

    [Fact]
    [Trait("Privilege", "User")]
    [Trait("OS", "Windows")]
    public async Task Create_User_Certificate_UserStore_RDP()
    {
        CertificateManager manager = CreateManager();
        string domainUser = NewDomain();

        GenerateArgModel createUserArgs = new()
        {
            Domain = domainUser,
            caID = TestConfig.SslCaId,
            Validity = 30,
            LocalCertStore = false,
            Password = TestConfig.CertPassword,
            RDPCert = true,
        };
        manager.InitializeManager(createUserArgs);
        int result = await manager.CallCertActionAsync();
        Assert.Equal(0, result);
    }
}

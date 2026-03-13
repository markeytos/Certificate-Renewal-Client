using System.Runtime.InteropServices;
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
}

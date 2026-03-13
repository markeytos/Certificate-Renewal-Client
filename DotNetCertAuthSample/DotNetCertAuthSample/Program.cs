using System.Runtime.InteropServices;
using CommandLine;
using DotNetCertAuthSample.Managers;
using DotNetCertAuthSample.Models;
using DotNetCertAuthSample.Services;

namespace DotNetCertAuthSample;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        // Determine platform and create appropriate services
        ICertStoreService certStoreService;
        ISystemInfoService systemInfoService;
        IStoreService storeService;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
#if WINDOWS
            storeService = new UnifiedStoreService();
            certStoreService = new WindowsCertService(storeService);
            systemInfoService = new WindowsSystemInfoService();
#else
            Console.WriteLine("Windows-specific services not available");
            return 1;
#endif
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            storeService = new LinuxStoreService();
            certStoreService = new UnifiedCertStoreService(storeService);
            systemInfoService = new UnifiedSystemInfoService();
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            storeService = new UnifiedStoreService();
            certStoreService = new UnifiedCertStoreService(storeService);
            systemInfoService = new UnifiedSystemInfoService();
        }
        else
        {
            Console.WriteLine("Unsupported operating system");
            return 1;
        }

        CertificateManager certificateManager = new(
            certStoreService,
            systemInfoService,
            storeService
        );
        int result = Parser
            .Default.ParseArguments<
                RenewArgModel,
                GenerateArgModel,
                RegisterArgModel,
                CreateDCCertificate,
                SCEPArgModel,
                TestModel
            >(args)
            .MapResult(
                (RenewArgModel operation) => certificateManager.InitializeManager(operation),
                (GenerateArgModel operation) => certificateManager.InitializeManager(operation),
                (RegisterArgModel operation) => certificateManager.InitializeManager(operation),
                (CreateDCCertificate operation) => certificateManager.InitializeManager(operation),
                (SCEPArgModel operation) => certificateManager.InitializeManager(operation),
                (TestModel operation) => certificateManager.InitializeManager(operation),
                errs => certificateManager.ProcessError(errs)
            );
        if (result == 0)
        {
            result = await certificateManager.CallCertActionAsync();
        }
        return result;
    }
}

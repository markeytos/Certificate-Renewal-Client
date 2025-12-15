using System.Net;
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

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
#if WINDOWS
            certStoreService = new WindowsCertStoreService();
            systemInfoService = new WindowsSystemInfoService();
#else
            Console.WriteLine("Windows-specific services not available");
            return 1;
#endif
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            certStoreService = new LinuxCertStoreService();
            systemInfoService = new LinuxSystemInfoService();
        }
        else
        {
            Console.WriteLine("Unsupported operating system");
            return 1;
        }

        CertificateManager certificateManager = new(certStoreService, systemInfoService);
        int result = Parser
            .Default.ParseArguments<
                RenewArgModel,
                GenerateArgModel,
                RegisterArgModel,
                CreateDCCertificate,
                SCEPArgModel
            >(args)
            .MapResult(
                (RenewArgModel operation) => certificateManager.InitializeManager(operation),
                (GenerateArgModel operation) => certificateManager.InitializeManager(operation),
                (RegisterArgModel operation) => certificateManager.InitializeManager(operation),
                (CreateDCCertificate operation) => certificateManager.InitializeManager(operation),
                (SCEPArgModel operation) => certificateManager.InitializeManager(operation),
                errs => certificateManager.ProcessError(errs)
            );
        if (result == 0)
        {
            result = await certificateManager.CallCertActionAsync();
        }
        return result;
    }
}

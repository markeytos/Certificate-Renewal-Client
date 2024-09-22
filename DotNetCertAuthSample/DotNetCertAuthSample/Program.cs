using System.Net;
using CommandLine;
using DotNetCertAuthSample.Managers;
using DotNetCertAuthSample.Models;

namespace DotNetCertAuthSample;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        CertificateManager certificateManager = new();
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

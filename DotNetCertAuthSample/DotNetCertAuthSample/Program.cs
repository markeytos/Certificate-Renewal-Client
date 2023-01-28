using System;
using System.Collections.Generic;
using System.Linq;
using DotNetCertAuthSample.Services;
using DotNetCertAuthSample.Models;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CERTENROLLLib;
using CommandLine;
using Microsoft.Extensions.Logging;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.Extensions.DependencyInjection;
using DotNetCertAuthSample.Managers;

namespace DotNetCertAuthSample
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            CertificateManager certificateManager = new ();
            int result = Parser.Default.ParseArguments<
                RenewArgModel, GenerateArgModel, RegisterArgModel>(args)
                .MapResult(
                 (RenewArgModel operation) => certificateManager.InitializeManager(operation),
                 (GenerateArgModel operation) => certificateManager.InitializeManager(operation),
                 (RegisterArgModel operation) => certificateManager.InitializeManager(operation),
                (IEnumerable<Error> errs) => certificateManager.ProcessError(errs));
            if(result == 0)
            {
                await certificateManager.CallCertActionAsync();
            }
        }


    }
}
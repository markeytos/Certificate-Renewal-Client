using System;
using System.Collections.Generic;
using System.Linq;
using DotNetCertAuthSample.Services;
using DotNetCertAuthSample.Models;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CERTENROLLLib;

namespace DotNetCertAuthSample
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            HttpClient _httpClient = new ();
            HTTPService _httpService = new(_httpClient);
            string subjectName = "CN=keytos.io";
            List<string> subjectAltNames = new List<string>
            {
                "keytos.io"
            };
            await CreateCertFromWindowsAsync(_httpService, subjectName, subjectAltNames);
            return;
        }

        private static async Task CreateCertFromWindowsAsync(HTTPService httpService, string subjectName,
            List<string> subjectAltNames)
        {
            //preferred option subject name based
            X509Certificate2? cert = WindowsCertStoreService.GetCertFromWinStoreBySubject("keytos.io");
            //thumbprint option (not recommended)
            //cert = WindowsCertStoreService.GetCertFromWinStoreBythumbprint("49e9968c7ffc83710c01adbc422106fa294b839d");
            
            CX509CertificateRequestPkcs10 certRequest = WindowsCertStoreService.CreateCSR(subjectName, subjectAltNames, 4096);
            string csr = certRequest.RawData[EncodingType.XCN_CRYPT_STRING_BASE64REQUESTHEADER];
            CertRenewReqModel certReq = new(csr, 20);
            if (cert == null)
            {
                Console.WriteLine("Could not find certificate");
                return;
            }
            string base64Cert = await GetCertFromCAAsync(httpService, certReq, cert);
            WindowsCertStoreService.InstallCertificate(base64Cert, certRequest);
        }

        private static async Task<string> GetCertFromCAAsync(HTTPService httpService,
            CertRenewReqModel certReq, X509Certificate2 cert)
        {
            APIResultModel result = await httpService.SendPostAsync(
                "https://localhost:5001/api/Certificates/RenewCertificate"
                , cert, JsonSerializer.Serialize(certReq));
            if (result.Success)
            {
                APIResultModel serverResponse = JsonSerializer.Deserialize<APIResultModel>(result.Message);
                if (serverResponse.Success)
                {
                    return serverResponse.Message;
                }
                else
                {
                    throw new Exception(serverResponse.Message);
                }
            }
            else
            {
                throw new Exception(result.Message);
            }
        }


    }
}
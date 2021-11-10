using System;
using System.Collections.Generic;
using System.Linq;
using DotNetCertAuthSample.Services;
using DotNetCertAuthSample.Models;
using System.Security.Cryptography.X509Certificates;

namespace DotNetCertAuthSample
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            HttpClient _httpClient = new ();
            HTTPService _httpService = new(_httpClient);
            //prefered option subject name based
            X509Certificate2? cert = GetCertFromWinStoreBySubject("keytos.io");
            //thumbprint option
            cert = GetCertFromWinStoreBythumbprint("e00cee63cadf08c80de33e7bc44c89027c164aeb");
            if(cert == null)
            {
                Console.WriteLine("Could not find certificate");
                return;
            }
            APIResultModel result = await _httpService.SendGetAsync(
                "https://localhost:5001/api/Certificates/RenewCertificate"
                , cert);
            return;
        }

        private static X509Certificate2 GetCertFromWinStoreBySubject(string subjectName)
        {
            X509Store store = new (StoreLocation.CurrentUser);
            X509Certificate2? cert = null;
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(
                X509FindType.FindBySubjectName, subjectName, true);
            if(certs.Count > 0)
            {
                cert = certs[0];
            }
            return cert;
        }

        private static X509Certificate2 GetCertFromWinStoreBythumbprint(string thumbprint)
        {
            //not recommended since it breaks with auto rotation
            X509Store store = new (StoreLocation.CurrentUser);
            X509Certificate2? cert = null;
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(
                X509FindType.FindByThumbprint, thumbprint, true);
            if (certs.Count > 0)
            {
                cert = certs[0];
            }
            return cert;
        }
    }
}
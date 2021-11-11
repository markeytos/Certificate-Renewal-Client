using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DotNetCertAuthSample.Models
{
    public class CertRenewReqModel
    {
        public CertRenewReqModel(string csr, int validity)
        {
            CSR = csr;
            ValidityInDays = validity;
        }

        [JsonPropertyName("CSR")]
        public string CSR { get; set; }

        [JsonPropertyName("ValidityInDays")]
        public int ValidityInDays { get; set; }
    }
}

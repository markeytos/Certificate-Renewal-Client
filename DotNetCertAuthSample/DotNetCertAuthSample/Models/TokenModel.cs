using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DotNetCertAuthSample.Models
{
    public class TokenModel
    {
        public TokenModel ()
        {
            NotBefore = DateTime.UtcNow;
            ExpiresOn = DateTime.UtcNow.AddMinutes(30);
            AccessToken = string.Empty;
        }

        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }
        [JsonPropertyName("not_before")]
        public DateTimeOffset NotBefore { get; set; }
        [JsonPropertyName("expires_on")]
        public DateTimeOffset ExpiresOn { get; set; }
    }
}

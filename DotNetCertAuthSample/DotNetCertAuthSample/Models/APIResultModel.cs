using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DotNetCertAuthSample.Models
{
    public class APIResultModel
    {
        public APIResultModel(bool success, string message)
        {
            Success = success;
            Message = message;
        }
        public APIResultModel()
        {
            Message = string.Empty;
            Success = false;
        }
        public APIResultModel(bool success)
        {
            Success = success;
            Message = string.Empty;
        }

        [JsonPropertyName("Success")]
        public bool Success { get; set; }
        [JsonPropertyName("Message")]
        public string Message { get; set; }
    }
}

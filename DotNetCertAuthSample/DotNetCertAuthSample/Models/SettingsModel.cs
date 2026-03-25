using System.Text.Json.Serialization;

namespace DotNetCertAuthSample.Models;

public class SettingsModel
{
    [JsonPropertyName("RotatedCertificates")]
    public List<string> RotatedCertificates { get; set; } = new();

    
}
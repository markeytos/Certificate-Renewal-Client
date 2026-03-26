using System.Text.Json.Serialization;

namespace DotNetCertAuthSample.Models;

public class SettingsModel
{
    [JsonPropertyName("RotatedCertificates")]
    public List<RotatedCertificate> RotatedCertificates { get; set; } = new();
}


public class RotatedCertificate
{

    public RotatedCertificate()
    {
        Thumbprint = string.Empty;
        ExpiryDate = DateTime.MinValue;
    }
    
    public RotatedCertificate(string thumbprint, DateTime expiryDate)
    {
        Thumbprint = thumbprint;
        ExpiryDate = expiryDate;
    }
    [JsonPropertyName("Thumbprint")]
    
    public string Thumbprint { get; set; }
    [JsonPropertyName("ExpiryDate")]
    
    public DateTime ExpiryDate { get; set; }
}
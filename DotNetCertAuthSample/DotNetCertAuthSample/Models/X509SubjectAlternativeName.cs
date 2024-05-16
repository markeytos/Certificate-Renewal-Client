namespace DotNetCertAuthSample.Models;


public class X509SubjectAlternativeName
{
    public SANTypes Type { get; set; }
    public string Value { get; set; }
}

public enum SANTypes
{
    OtherName,
    Rfc822Name,
    DNSName,
    DirectoryName,
    IPAddress,
    URI,
    Unknown
}

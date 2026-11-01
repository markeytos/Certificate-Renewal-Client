namespace DotNetCertAuthSample.Models;

/// <summary>
/// A Subject Alternative Name after parsing, in a shape both certificate request builders can
/// consume: BouncyCastle on Linux and macOS, CertEnroll on Windows.
/// </summary>
public class SubjectAlternativeNameEntry
{
    public SANTypes Type { get; init; }

    /// <summary>
    /// The textual value, already normalized. A SID is the full Microsoft SID URI rather than the
    /// bare SID the caller typed.
    /// </summary>
    public string Value { get; init; } = string.Empty;

    /// <summary>OID of the otherName. Set only when <see cref="Type"/> is OtherName.</summary>
    public string? OtherNameOid { get; init; }

    /// <summary>Address octets. Set only when <see cref="Type"/> is IPAddress.</summary>
    public byte[]? IPAddressOctets { get; init; }
}

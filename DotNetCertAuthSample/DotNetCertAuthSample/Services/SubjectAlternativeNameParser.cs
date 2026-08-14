using System.Net;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Parses the comma separated --SubjectAltNames value into ASN.1 Subject Alternative Names.
/// Each entry may declare its type with a prefix (DNS=, UPN=, IP=, RFC822=, URI=, SID=).
/// Entries without a prefix are treated as DNS names so existing commands keep working.
/// A comma inside a value can be escaped with a backslash (for example URI=tag:example.com\,2022:foo).
/// </summary>
public static class SubjectAlternativeNameParser
{
    /// <summary>OID for the Microsoft User Principal Name otherName SAN.</summary>
    public const string UpnOid = "1.3.6.1.4.1.311.20.2.3";

    /// <summary>
    /// Prefix of the URI SAN Microsoft uses to carry an account SID (see KB5014754).
    /// </summary>
    public const string SidUriPrefix = "tag:microsoft.com,2022-09-14:sid:";

    public static GeneralName[] Parse(string subjectAltNames)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectAltNames);
        List<string> entries = SplitEntries(subjectAltNames);
        if (entries.Count == 0)
        {
            throw new ArgumentException(
                $"'{subjectAltNames}' does not contain any Subject Alternative Names."
            );
        }

        return entries.Select(ParseEntry).ToArray();
    }

    private static GeneralName ParseEntry(string entry)
    {
        (string? type, string value) = SplitTypeAndValue(entry);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                $"Subject Alternative Name '{entry}' does not have a value."
            );
        }

        // No prefix means the caller is using the original syntax, where every value is a DNS name.
        if (type == null)
        {
            return new GeneralName(GeneralName.DnsName, value);
        }

        switch (type.ToUpperInvariant())
        {
            case "DNS":
            case "DNSNAME":
                return new GeneralName(GeneralName.DnsName, value);
            case "UPN":
                return CreateUpnName(value);
            case "IP":
            case "IPADDRESS":
                return CreateIPAddressName(value);
            case "RFC822":
            case "RFC822NAME":
            case "EMAIL":
                return new GeneralName(GeneralName.Rfc822Name, value);
            case "URI":
            case "URL":
                return new GeneralName(GeneralName.UniformResourceIdentifier, value);
            case "SID":
                return new GeneralName(
                    GeneralName.UniformResourceIdentifier,
                    value.StartsWith(SidUriPrefix, StringComparison.OrdinalIgnoreCase)
                        ? value
                        : SidUriPrefix + value
                );
            default:
                throw new ArgumentException(
                    $"'{type}' is not a supported Subject Alternative Name type. "
                        + "Supported types are DNS, UPN, IP, RFC822 (or EMAIL), URI (or URL) and SID."
                );
        }
    }

    private static GeneralName CreateUpnName(string value)
    {
        // otherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT UTF8String }
        DerSequence otherName = new(
            new DerObjectIdentifier(UpnOid),
            new DerTaggedObject(true, 0, new DerUtf8String(value))
        );
        return new GeneralName(GeneralName.OtherName, otherName);
    }

    private static GeneralName CreateIPAddressName(string value)
    {
        if (
            !IPAddress.TryParse(value, out IPAddress? ipAddress)
            || ipAddress.AddressFamily
                is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
        )
        {
            throw new ArgumentException($"'{value}' is not a valid IP address.");
        }

        return new GeneralName(
            GeneralName.IPAddress,
            new DerOctetString(ipAddress.GetAddressBytes())
        );
    }

    /// <summary>
    /// Returns the type prefix of an entry, or null when the entry has no prefix. Only a bare
    /// alphanumeric token before the first '=' counts as a prefix, so values such as
    /// https://contoso.com/path?key=value are not mistaken for a type declaration.
    /// </summary>
    private static (string? Type, string Value) SplitTypeAndValue(string entry)
    {
        int separator = entry.IndexOf('=');
        if (separator <= 0)
        {
            return (null, entry.Trim());
        }

        string prefix = entry[..separator].Trim();
        if (prefix.Length == 0 || !prefix.All(char.IsAsciiLetterOrDigit))
        {
            return (null, entry.Trim());
        }

        return (prefix, entry[(separator + 1)..].Trim());
    }

    /// <summary>
    /// Splits on commas, honoring backslash escaped commas so values that contain a comma
    /// (such as the Microsoft SID URI) can be passed as a single entry.
    /// </summary>
    private static List<string> SplitEntries(string subjectAltNames)
    {
        List<string> entries = [];
        StringBuilder current = new();
        for (int i = 0; i < subjectAltNames.Length; i++)
        {
            char character = subjectAltNames[i];
            if (
                character == '\\'
                && i + 1 < subjectAltNames.Length
                && subjectAltNames[i + 1] == ','
            )
            {
                current.Append(',');
                i++;
                continue;
            }

            if (character == ',')
            {
                AddEntry(entries, current);
                continue;
            }

            current.Append(character);
        }

        AddEntry(entries, current);
        return entries;
    }

    private static void AddEntry(List<string> entries, StringBuilder current)
    {
        string entry = current.ToString().Trim();
        current.Clear();
        if (entry.Length > 0)
        {
            entries.Add(entry);
        }
    }
}

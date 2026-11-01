using System.Net;
using System.Net.Sockets;
using System.Text;
using DotNetCertAuthSample.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Parses the comma separated --SubjectAltNames value into Subject Alternative Names.
/// Each entry may declare its type with a prefix (DNS=, UPN=, IP=, RFC822=, URI=, SID=).
/// Entries without a prefix are treated as DNS names so existing commands keep working.
/// A comma inside a value can be escaped with a backslash.
/// </summary>
public static class SubjectAlternativeNameParser
{
    /// <summary>OID for the Microsoft User Principal Name otherName SAN.</summary>
    public const string UpnOid = "1.3.6.1.4.1.311.20.2.3";

    /// <summary>
    /// Prefix of the URI SAN Microsoft uses to carry an account SID. This is the form a requester
    /// can ask for; a domain controller enforcing KB5014754 reads the SID out of the
    /// 1.3.6.1.4.1.311.25.2 extension instead, which only the issuing CA can assert and which no
    /// CSR can self-declare meaningfully.
    /// </summary>
    public const string SidUriPrefix = "tag:microsoft.com,2022-09-14:sid:";

    public static GeneralName[] Parse(string subjectAltNames)
    {
        return ParseEntries(subjectAltNames).Select(ToGeneralName).ToArray();
    }

    /// <summary>
    /// Parses the value into entries that are independent of the certificate request builder.
    /// Windows builds its request through CertEnroll and cannot use a BouncyCastle GeneralName,
    /// so both platforms share this parser and map the result themselves.
    /// </summary>
    public static List<SubjectAlternativeNameEntry> ParseEntries(string subjectAltNames)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectAltNames);
        List<string> entries = SplitEntries(subjectAltNames);
        if (entries.Count == 0)
        {
            throw new ArgumentException(
                $"'{subjectAltNames}' does not contain any Subject Alternative Names."
            );
        }

        return entries.Select(ParseEntry).ToList();
    }

    /// <summary>
    /// Parses values that were already split, so a value containing a comma does not have to be
    /// escaped a second time when it reaches this parser as its own string.
    /// </summary>
    public static List<SubjectAlternativeNameEntry> ParseEntries(
        IEnumerable<string> subjectAltNames
    )
    {
        ArgumentNullException.ThrowIfNull(subjectAltNames);
        return subjectAltNames
            .Where(entry => !string.IsNullOrWhiteSpace(entry))
            .Select(entry => ParseEntry(entry.Trim()))
            .ToList();
    }

    /// <summary>
    /// Splits the comma separated value into entries without parsing them, for callers that pass
    /// the entries on to something that parses them itself.
    /// </summary>
    public static List<string> Split(string subjectAltNames)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectAltNames);
        return SplitEntries(subjectAltNames);
    }

    public static GeneralName ToGeneralName(SubjectAlternativeNameEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        switch (entry.Type)
        {
            case SANTypes.DNSName:
                return new GeneralName(GeneralName.DnsName, entry.Value);
            case SANTypes.Rfc822Name:
                return new GeneralName(GeneralName.Rfc822Name, entry.Value);
            case SANTypes.URI:
                return new GeneralName(GeneralName.UniformResourceIdentifier, entry.Value);
            case SANTypes.IPAddress:
                return new GeneralName(
                    GeneralName.IPAddress,
                    new DerOctetString(entry.IPAddressOctets ?? [])
                );
            case SANTypes.OtherName:
                // otherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT UTF8String }
                DerSequence otherName = new(
                    new DerObjectIdentifier(entry.OtherNameOid ?? UpnOid),
                    new DerTaggedObject(true, 0, new DerUtf8String(entry.Value))
                );
                return new GeneralName(GeneralName.OtherName, otherName);
            default:
                throw new ArgumentException(
                    $"'{entry.Type}' is not a supported Subject Alternative Name type."
                );
        }
    }

    private static SubjectAlternativeNameEntry ParseEntry(string entry)
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
            return new() { Type = SANTypes.DNSName, Value = value };
        }

        switch (type.ToUpperInvariant())
        {
            case "DNS":
            case "DNSNAME":
                return new() { Type = SANTypes.DNSName, Value = value };
            case "UPN":
                return new()
                {
                    Type = SANTypes.OtherName,
                    Value = value,
                    OtherNameOid = UpnOid,
                };
            case "IP":
            case "IPADDRESS":
                return CreateIPAddressEntry(value);
            case "RFC822":
            case "RFC822NAME":
            case "EMAIL":
                return new() { Type = SANTypes.Rfc822Name, Value = value };
            case "URI":
            case "URL":
                return new() { Type = SANTypes.URI, Value = value };
            case "SID":
                // A pasted full SID URI contains a comma, so it arrives here already cut in half
                // unless it was escaped. Prefixing the fragment would produce a plausible-looking
                // but wrong SAN, and the other half would silently become a DNS name, so a value
                // that looks like a severed URI is refused instead.
                if (
                    !value.StartsWith(SidUriPrefix, StringComparison.OrdinalIgnoreCase)
                    && value.StartsWith("tag:microsoft.com", StringComparison.OrdinalIgnoreCase)
                )
                {
                    throw new ArgumentException(
                        $"'{value}' looks like a Microsoft SID URI that was split on its comma. "
                            + @"Escape the comma as '\,' to pass the whole URI, or pass just the SID."
                    );
                }

                return new()
                {
                    Type = SANTypes.URI,
                    Value = value.StartsWith(SidUriPrefix, StringComparison.OrdinalIgnoreCase)
                        ? value
                        : SidUriPrefix + value,
                };
            default:
                throw new ArgumentException(
                    $"'{type}' is not a supported Subject Alternative Name type. "
                        + "Supported types are DNS, UPN, IP, RFC822 (or EMAIL), URI (or URL) and SID."
                );
        }
    }

    private static SubjectAlternativeNameEntry CreateIPAddressEntry(string value)
    {
        if (
            !IPAddress.TryParse(value, out IPAddress? ipAddress)
            || ipAddress.AddressFamily
                is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
        )
        {
            throw new ArgumentException($"'{value}' is not a valid IP address.");
        }

        return new()
        {
            Type = SANTypes.IPAddress,
            Value = ipAddress.ToString(),
            IPAddressOctets = ipAddress.GetAddressBytes(),
        };
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

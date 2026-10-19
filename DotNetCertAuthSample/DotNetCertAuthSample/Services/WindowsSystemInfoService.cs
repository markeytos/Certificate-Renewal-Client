#if WINDOWS
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EZCAClient.Models;
using Microsoft.Management.Infrastructure;
using Microsoft.Management.Infrastructure.Options;
using Microsoft.Web.Administration;

namespace DotNetCertAuthSample.Services;

public class WindowsSystemInfoService : ISystemInfoService
{
    private const string DefaultCertificateStoreName = "MY";
    private const string HttpsProtocol = "https";
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    public string? GetComputerDistinguishedName(string computerName)
    {
        try
        {
            PrincipalContext context = new(ContextType.Domain);
            var computer = ComputerPrincipal.FindByIdentity(context, computerName);
            if (computer != null)
            {
                return computer.DistinguishedName;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine("Error getting computer distinguished name " + e.Message);
        }
        return null;
    }

    public void SetRDPCertificate(string thumbprint)
    {
        string namespaceValue = @"root\cimv2\TerminalServices";
        string queryDialect = "WQL";
        string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
        string thumbprintProperty = "SSLCertificateSHA1Hash";
        DComSessionOptions dComOpts = new()
        {
            Culture = CultureInfo.CurrentCulture,
            UICulture = CultureInfo.CurrentUICulture,
            PacketIntegrity = true,
            PacketPrivacy = true,
            Timeout = new TimeSpan(0),
        };
        using CimSession cimSession = CimSession.Create("localhost", dComOpts);
        CimInstance? instance = cimSession
            .QueryInstances(namespaceValue, queryDialect, query)
            .ToArray()
            .FirstOrDefault();
        if (instance == null)
        {
            throw new Exception("Error getting RDP service");
        }
        bool check = !instance.CimInstanceProperties[thumbprintProperty].Value.Equals(thumbprint);
        if (check)
        {
            CimProperty? prop = instance.CimInstanceProperties[thumbprintProperty];
            prop.Value = thumbprint;
            cimSession.ModifyInstance(instance);
        }
    }

    public APIResultModel CheckIfRDPCertAndRenew(string oldCertThumbprint, string newCertThumbprint)
    {
        string namespaceValue = @"root\cimv2\TerminalServices";
        string queryDialect = "WQL";
        string query = "SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = 'RDP-Tcp'";
        string thumbprintProperty = "SSLCertificateSHA1Hash";
        DComSessionOptions dComOpts = new()
        {
            Culture = CultureInfo.CurrentCulture,
            UICulture = CultureInfo.CurrentUICulture,
            PacketIntegrity = true,
            PacketPrivacy = true,
            Timeout = new TimeSpan(0),
        };
        using CimSession cimSession = CimSession.Create("localhost", dComOpts);
        CimInstance? instance = cimSession
            .QueryInstances(namespaceValue, queryDialect, query)
            .ToArray()
            .FirstOrDefault();
        if (instance == null)
        {
            return new(false, "Error getting RDP service");
        }
        string currentThumbprint = NormalizeThumbprint(
            instance.CimInstanceProperties[thumbprintProperty].Value?.ToString()
        );
        if (currentThumbprint != NormalizeThumbprint(oldCertThumbprint))
        {
            return new(true, "");
        }
        CimProperty? prop = instance.CimInstanceProperties[thumbprintProperty];
        prop.Value = newCertThumbprint;
        cimSession.ModifyInstance(instance);
        return new(true, "RDP certificate updated successfully");
    }

    public APIResultModel SetIISCertificate(string thumbprint, string? siteName)
    {
        if (string.IsNullOrWhiteSpace(siteName))
        {
            // no site was asked for, so IIS is not part of this request
            return new(true, "");
        }
        if (!IsIISInstalled())
        {
            return new(false, "IIS is not installed on this machine");
        }
        thumbprint = NormalizeThumbprint(thumbprint);
        try
        {
            using ServerManager manager = new();
            Site? site = manager.Sites.FirstOrDefault(candidate =>
                candidate.Name.Equals(siteName, StringComparison.OrdinalIgnoreCase)
            );
            if (site == null)
            {
                return new(
                    false,
                    $"IIS site '{siteName}' was not found. {DescribeAvailableBindings(manager)}"
                );
            }
            StoreLookup lookup = FindInStore(DefaultCertificateStoreName, thumbprint);
            if (lookup.Failed)
            {
                return new(false, $"Error setting IIS certificate: {lookup.Error}");
            }
            if (lookup.Certificate == null)
            {
                return new(
                    false,
                    $"Certificate {thumbprint} was not found in LocalMachine\\{DefaultCertificateStoreName}. "
                        + "Issue it with --LocalStore so that IIS can read it"
                );
            }
            using X509Certificate2 certificate = lookup.Certificate;
            List<string> certificateNames = GetCertificateNames(certificate);
            List<BindingTarget> targets = [];
            List<string> centralCertStoreBindings = [];
            List<string> foreignNameBindings = [];
            foreach (Binding binding in site.Bindings)
            {
                if (!IsHttpsBinding(binding))
                {
                    continue;
                }
                if (UsesCentralCertificateStore(binding))
                {
                    centralCertStoreBindings.Add(Describe(site, binding));
                    continue;
                }
                string host = binding.Host ?? string.Empty;
                // a binding with no host name serves whatever reaches the site, and the
                // site was named on the command line, so it is taken. A binding that does
                // name a host the certificate cannot serve belongs to someone else and is
                // left alone rather than broken
                if (host.Length > 0 && !CoversHost(certificateNames, host))
                {
                    foreignNameBindings.Add($"{Describe(site, binding)} serving {host}");
                    continue;
                }
                targets.Add(new(site, binding));
            }
            if (targets.Count == 0)
            {
                return new(
                    false,
                    NoBindingMessage(
                        siteName,
                        certificateNames,
                        centralCertStoreBindings,
                        foreignNameBindings
                    )
                );
            }
            APIResultModel storeCheck = EnsureCertificateIsInBindingStores(targets, thumbprint);
            if (!storeCheck.Success)
            {
                return new(
                    false,
                    $"Could not bind the certificate to IIS site '{siteName}': {storeCheck.Message}"
                );
            }
            foreach (BindingTarget target in targets)
            {
                ApplyCertificateToBinding(target.Binding, thumbprint);
            }
            manager.CommitChanges();
            return new(
                true,
                $"IIS certificate set successfully for {DescribeAll(targets)}"
                    + DescribeSkipped(centralCertStoreBindings, foreignNameBindings)
            );
        }
        catch (Exception ex)
        {
            return new(false, $"Error setting IIS certificate: {ex.Message}");
        }
    }

    public APIResultModel CheckIfIISCertAndRenew(string oldCertThumbprint, string newCertThumbprint)
    {
        if (!IsIISInstalled())
        {
            return new(true, "");
        }
        oldCertThumbprint = NormalizeThumbprint(oldCertThumbprint);
        newCertThumbprint = NormalizeThumbprint(newCertThumbprint);
        try
        {
            using ServerManager manager = new();
            List<BindingTarget> targets = [];
            foreach (Site site in manager.Sites)
            {
                foreach (Binding binding in site.Bindings)
                {
                    if (!IsHttpsBinding(binding) || UsesCentralCertificateStore(binding))
                    {
                        continue;
                    }
                    if (GetBindingThumbprint(binding) == oldCertThumbprint)
                    {
                        targets.Add(new(site, binding));
                    }
                }
            }
            if (targets.Count == 0)
            {
                return new(true, "");
            }
            // a binding whose store cannot be made to hold the renewed certificate would
            // be left pointing at nothing, so it is reported instead of being updated
            List<BindingTarget> updatable = [];
            List<string> unavailable = [];
            foreach (BindingTarget target in targets)
            {
                string? error = EnsureCertificateInBindingStore(
                    GetBindingStoreName(target.Binding),
                    newCertThumbprint
                );
                if (error == null)
                {
                    updatable.Add(target);
                }
                else
                {
                    unavailable.Add($"{Describe(target.Site, target.Binding)}: {error}");
                }
            }
            if (updatable.Count == 0)
            {
                return new(
                    false,
                    "Could not move any IIS binding onto the renewed certificate. "
                        + string.Join("; ", unavailable)
                );
            }
            foreach (BindingTarget target in updatable)
            {
                ApplyCertificateToBinding(target.Binding, newCertThumbprint);
            }
            manager.CommitChanges();
            return new(
                true,
                $"IIS certificate updated successfully for {DescribeAll(updatable)}"
                    + (
                        unavailable.Count > 0
                            ? $". Left unchanged: {string.Join("; ", unavailable)}"
                            : string.Empty
                    )
            );
        }
        catch (Exception ex)
        {
            return new(false, $"Error updating IIS certificate: {ex.Message}");
        }
    }

    private static bool IsIISInstalled()
    {
        string configPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "inetsrv",
            "config",
            "applicationHost.config"
        );
        return File.Exists(configPath);
    }

    private static bool IsHttpsBinding(Binding binding) =>
        HttpsProtocol.Equals(binding.Protocol, StringComparison.OrdinalIgnoreCase);

    private static bool UsesCentralCertificateStore(Binding binding) =>
        binding.SslFlags.HasFlag(SslFlags.CentralCertStore);

    private static string GetBindingStoreName(Binding binding) =>
        string.IsNullOrWhiteSpace(binding.CertificateStoreName)
            ? DefaultCertificateStoreName
            : binding.CertificateStoreName;

    private static string GetBindingThumbprint(Binding binding)
    {
        byte[]? hash = binding.CertificateHash;
        return hash is null or { Length: 0 } ? string.Empty : Convert.ToHexString(hash);
    }

    private static void ApplyCertificateToBinding(Binding binding, string thumbprint)
    {
        // the store name has to be written before the hash, otherwise IIS drops it
        binding.CertificateStoreName = GetBindingStoreName(binding);
        binding.CertificateHash = Convert.FromHexString(thumbprint);
    }

    /// <summary>
    /// The DNS names the certificate can serve: its SANs, plus the common name so that a
    /// certificate issued without a SAN extension still resolves to something.
    /// </summary>
    internal static List<string> GetCertificateNames(X509Certificate2 certificate)
    {
        List<string> names = [];
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != SubjectAlternativeNameOid)
            {
                continue;
            }
            X509SubjectAlternativeNameExtension san = new(extension.RawData, extension.Critical);
            names.AddRange(san.EnumerateDnsNames());
        }
        string commonName = certificate.GetNameInfo(X509NameType.DnsName, false);
        if (!string.IsNullOrWhiteSpace(commonName))
        {
            names.Add(commonName);
        }
        return [.. names.Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    internal static bool CoversHost(List<string> certificateNames, string host) =>
        certificateNames.Any(name => NameCoversHost(name, host));

    /// <summary>
    /// A wildcard in a certificate only ever stands in for a single label, so
    /// *.contoso.com covers www.contoso.com but neither a.b.contoso.com nor contoso.com.
    /// </summary>
    private static bool NameCoversHost(string name, string host)
    {
        if (name.Equals(host, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (!name.StartsWith("*.", StringComparison.Ordinal))
        {
            return false;
        }
        string suffix = name[1..];
        if (!host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        string label = host[..^suffix.Length];
        return label.Length > 0 && !label.Contains('.');
    }

    private static APIResultModel EnsureCertificateIsInBindingStores(
        List<BindingTarget> targets,
        string thumbprint
    )
    {
        foreach (
            string storeName in targets
                .Select(target => GetBindingStoreName(target.Binding))
                .Distinct(StringComparer.OrdinalIgnoreCase)
        )
        {
            string? error = EnsureCertificateInBindingStore(storeName, thumbprint);
            if (error != null)
            {
                return new(false, error);
            }
        }
        return new(true, "");
    }

    /// <summary>
    /// Makes the certificate readable from the store an IIS binding reads from, returning
    /// null on success and the reason otherwise. This client only ever installs into
    /// LocalMachine\MY, so a binding on another store (a WebHosting binding, typically)
    /// gets a copy of the certificate rather than being refused. The binding keeps its own
    /// store name, which is what IIS Manager does when a certificate is picked by hand.
    /// </summary>
    private static string? EnsureCertificateInBindingStore(string storeName, string thumbprint)
    {
        StoreLookup bindingStore = FindInStore(storeName, thumbprint);
        if (bindingStore.Failed)
        {
            return bindingStore.Error;
        }
        if (bindingStore.Certificate != null)
        {
            bindingStore.Certificate.Dispose();
            return null;
        }
        if (storeName.Equals(DefaultCertificateStoreName, StringComparison.OrdinalIgnoreCase))
        {
            return $"certificate {thumbprint} is not in LocalMachine\\{storeName}, which is the store "
                + "the binding reads from. Issue it with --LocalStore";
        }
        StoreLookup source = FindInStore(DefaultCertificateStoreName, thumbprint);
        if (source.Failed)
        {
            return source.Error;
        }
        if (source.Certificate == null)
        {
            return $"certificate {thumbprint} is in neither LocalMachine\\{storeName}, which is the "
                + $"store the binding reads from, nor LocalMachine\\{DefaultCertificateStoreName}. "
                + "Issue it with --LocalStore";
        }
        using X509Certificate2 certificate = source.Certificate;
        try
        {
            using X509Store store = new(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(certificate);
            return null;
        }
        catch (Exception ex) when (IsStoreAccessFailure(ex))
        {
            return $"certificate {thumbprint} could not be copied from LocalMachine\\"
                + $"{DefaultCertificateStoreName} into LocalMachine\\{storeName}, which is the store "
                + $"the binding reads from: {ex.Message}";
        }
    }

    /// <summary>
    /// A store that cannot be read is not the same thing as a store that does not hold the
    /// certificate, and the two call for different advice, so they are kept apart.
    /// </summary>
    private static StoreLookup FindInStore(string storeName, string thumbprint)
    {
        try
        {
            using X509Store store = new(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            return new(
                store.Certificates.FirstOrDefault(certificate =>
                    NormalizeThumbprint(certificate.Thumbprint) == thumbprint
                ),
                null
            );
        }
        catch (Exception ex) when (IsStoreAccessFailure(ex))
        {
            return new(
                null,
                $"LocalMachine\\{storeName} could not be read, so whether it holds certificate "
                    + $"{thumbprint} is unknown: {ex.Message}. This client has to run elevated"
            );
        }
    }

    private static bool IsStoreAccessFailure(Exception ex) =>
        ex
            is CryptographicException
                or SecurityException
                or UnauthorizedAccessException
                or IOException;

    private static string NoBindingMessage(
        string? siteName,
        List<string> certificateNames,
        List<string> centralCertStoreBindings,
        List<string> foreignNameBindings
    )
    {
        if (foreignNameBindings.Count > 0)
        {
            return $"The https binding(s) of IIS site '{siteName}' serve names this certificate does "
                + $"not cover: {string.Join(", ", foreignNameBindings)}. The certificate covers "
                + $"{DescribeNames(certificateNames)}";
        }
        return centralCertStoreBindings.Count > 0
            ? $"The IIS site '{siteName}' only has https bindings that use the Central Certificate Store, "
                + "those are managed by the store itself and cannot be bound to a thumbprint"
            : $"The IIS site '{siteName}' does not have any https bindings";
    }

    private static string DescribeNames(List<string> certificateNames) =>
        certificateNames.Count == 0 ? "no DNS names" : string.Join(", ", certificateNames);

    private static string DescribeSkipped(
        List<string> centralCertStoreBindings,
        List<string> foreignNameBindings
    )
    {
        List<string> skipped = [];
        if (foreignNameBindings.Count > 0)
        {
            skipped.Add(
                $"{string.Join(", ", foreignNameBindings)} because the certificate does not cover those names"
            );
        }
        if (centralCertStoreBindings.Count > 0)
        {
            skipped.Add(
                $"{string.Join(", ", centralCertStoreBindings)} because they use the IIS Central Certificate Store"
            );
        }
        return skipped.Count > 0 ? $". Skipped {string.Join("; ", skipped)}" : string.Empty;
    }

    private static string DescribeAvailableBindings(ServerManager manager)
    {
        List<string> bindings = manager
            .Sites.SelectMany(site =>
                site.Bindings.Where(IsHttpsBinding).Select(binding => Describe(site, binding))
            )
            .ToList();
        return bindings.Count == 0
            ? "This machine does not have any IIS https bindings"
            : $"Available https bindings: {string.Join(", ", bindings)}";
    }

    private static string DescribeAll(List<BindingTarget> targets) =>
        string.Join(", ", targets.Select(target => Describe(target.Site, target.Binding)));

    private static string Describe(Site site, Binding binding) =>
        $"'{site.Name}' ({binding.BindingInformation})";

    private static string NormalizeThumbprint(string? thumbprint) =>
        (thumbprint ?? string.Empty).Replace(" ", string.Empty).Trim().ToUpperInvariant();

    private readonly record struct BindingTarget(Site Site, Binding Binding);

    private readonly record struct StoreLookup(X509Certificate2? Certificate, string? Error)
    {
        public bool Failed => Error != null;
    }
}
#endif

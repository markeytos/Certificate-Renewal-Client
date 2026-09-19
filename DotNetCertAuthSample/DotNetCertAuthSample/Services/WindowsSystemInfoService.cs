#if WINDOWS
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.Net;
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
            List<BindingTarget> targets = [];
            List<string> centralCertStoreBindings = [];
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
                targets.Add(new(site, binding));
            }
            if (targets.Count == 0)
            {
                return new(false, NoBindingMessage(siteName, centralCertStoreBindings));
            }
            APIResultModel storeCheck = CheckCertificateIsInStores(targets, thumbprint);
            if (!storeCheck.Success)
            {
                return storeCheck;
            }
            foreach (BindingTarget target in targets)
            {
                ApplyCertificateToBinding(target.Binding, thumbprint);
            }
            manager.CommitChanges();
            string message =
                $"IIS certificate set successfully for {DescribeAll(targets)}"
                + (
                    centralCertStoreBindings.Count > 0
                        ? $". Skipped {string.Join(", ", centralCertStoreBindings)} because they use the IIS Central Certificate Store"
                        : string.Empty
                );
            return new(true, message);
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
            // a binding whose store does not hold the renewed certificate would be left
            // pointing at nothing, so it is reported instead of being updated
            List<BindingTarget> updatable = [];
            List<string> unavailable = [];
            foreach (BindingTarget target in targets)
            {
                if (IsCertificateInStore(GetBindingStoreName(target.Binding), newCertThumbprint))
                {
                    updatable.Add(target);
                }
                else
                {
                    unavailable.Add(
                        $"{Describe(target.Site, target.Binding)} (LocalMachine\\{GetBindingStoreName(target.Binding)})"
                    );
                }
            }
            if (updatable.Count == 0)
            {
                return new(
                    false,
                    $"Could not update the IIS binding(s) {string.Join(", ", unavailable)} because the renewed "
                        + $"certificate {newCertThumbprint} is not in the store those bindings read from"
                );
            }
            foreach (BindingTarget target in updatable)
            {
                ApplyCertificateToBinding(target.Binding, newCertThumbprint);
            }
            manager.CommitChanges();
            if (unavailable.Count > 0)
            {
                return new(
                    false,
                    $"IIS certificate updated successfully for {DescribeAll(updatable)}, but the binding(s) "
                        + $"{string.Join(", ", unavailable)} were left unchanged because the renewed certificate "
                        + $"{newCertThumbprint} is not in the store those bindings read from"
                );
            }
            return new(true, $"IIS certificate updated successfully for {DescribeAll(updatable)}");
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

    private static APIResultModel CheckCertificateIsInStores(
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
            if (!IsCertificateInStore(storeName, thumbprint))
            {
                return new(
                    false,
                    $"Certificate {thumbprint} was not found in LocalMachine\\{storeName}, which is the store "
                        + "the IIS binding(s) read from. Make sure the certificate is created with --LocalStore"
                );
            }
        }
        return new(true, "");
    }

    private static bool IsCertificateInStore(string storeName, string thumbprint)
    {
        try
        {
            using X509Store store = new(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            return store.Certificates.Any(certificate =>
                NormalizeThumbprint(certificate.Thumbprint) == thumbprint
            );
        }
        catch
        {
            return false;
        }
    }

    private static string NoBindingMessage(
        string? siteName,
        List<string> centralCertStoreBindings
    ) =>
        centralCertStoreBindings.Count > 0
            ? $"The IIS site '{siteName}' only has https bindings that use the Central Certificate Store, "
                + "those are managed by the store itself and cannot be bound to a thumbprint"
            : $"The IIS site '{siteName}' does not have any https bindings";

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
}
#endif

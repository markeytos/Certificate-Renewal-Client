using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using DotNetCertAuthSample.Models;
using Microsoft.Extensions.Logging;

namespace DotNetCertAuthSample.Services;

/// <summary>
/// Raised when the enrollment configuration could have been written by someone who is not an
/// administrator. It is deliberately not caught and turned into an empty configuration: carrying
/// on would mean enrolling against whatever that file says.
/// </summary>
public class UntrustedEnrollmentConfigException(string message) : Exception(message) { }

/// <summary>
/// Where the machine keeps its enrollment settings. Group Policy passes a command line that every
/// authenticated user in the domain can read out of SYSVOL, so the less that command line has to
/// carry the better; with this file in place it carries nothing but the verb.
/// </summary>
public class EnrollmentConfig
{
    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("mode")]
    public string? Mode { get; set; }

    [JsonPropertyName("spn")]
    public string? Spn { get; set; }

    /// <summary>
    /// Thumbprint of the certificate the last successful enrollment installed. This is how a
    /// later run finds the certificate it issued: EZCA chooses the subject, so there is no name
    /// the client can search for reliably.
    /// </summary>
    [JsonPropertyName("lastIssuedThumbprint")]
    public string? LastIssuedThumbprint { get; set; }

    [JsonPropertyName("lastIssuedSubject")]
    public string? LastIssuedSubject { get; set; }
}

public interface IEnrollmentConfigService
{
    EnrollmentConfig Load(string? path, ILogger? logger);
    void Save(EnrollmentConfig config, string? path, ILogger? logger);
    string ResolvePath(string? path);
}

public class EnrollmentConfigService : IEnrollmentConfigService
{
    private const string FileName = "enrollment.json";

    public EnrollmentConfig Load(string? path, ILogger? logger)
    {
        string resolved = ResolvePath(path);
        try
        {
            if (!File.Exists(resolved))
            {
                return new EnrollmentConfig();
            }

            // Decided by which file this is, not by how it was named. This recognises the
            // canonical spelling and anything under the shared data root; an exotic spelling of
            // the same file (an 8.3 short name, an extended-length prefix, a subst drive) is treated as a
            // caller-chosen path, which is what --ConfigFile already is.
            if (IsMachineWidePath(resolved))
            {
                AssertConfigurationIsTrustworthy(resolved);
            }

            string contents = File.ReadAllText(resolved);
            return JsonSerializer.Deserialize<EnrollmentConfig>(contents) ?? new EnrollmentConfig();
        }
        catch (UntrustedEnrollmentConfigException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "Could not read the enrollment configuration at {Path}", resolved);
            return new EnrollmentConfig();
        }
    }

    public void Save(EnrollmentConfig config, string? path, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(config);
        string resolved = ResolvePath(path);
        try
        {
            string? directory = Path.GetDirectoryName(resolved);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                CreateDirectoryChain(directory, resolved, logger);
            }

            File.WriteAllText(
                resolved,
                JsonSerializer.Serialize(
                    config,
                    new JsonSerializerOptions { WriteIndented = true }
                )
            );
            if (IsMachineWidePath(resolved))
            {
                // The machine-wide file gets its permissions set rather than inherited, so that it
                // passes the check on the next run whoever wrote it. Inheriting from %ProgramData%
                // would give its creator full control, and an administrator's own account is not
                // an administrative principal as far as that check is concerned.
                RestrictToAdministrators(resolved, logger);
            }

            logger?.LogInformation("Saved the enrollment configuration to {Path}", resolved);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Could not write the enrollment configuration to {Path}", resolved);
            throw;
        }
    }

    /// <summary>
    /// Creates the directories down to the configuration file and hardens the ones this product
    /// owns, refusing to write into a chain an unprivileged account could control.
    ///
    /// This cannot be left to inheritance: %ProgramData% carries a container-inherited ACE
    /// granting Users write, and gives CREATOR OWNER full control of what they create, so a
    /// directory created and left alone fails the very check this file's next load performs.
    /// </summary>
    private static void CreateDirectoryChain(string directory, string resolvedFile, ILogger? logger)
    {
        if (!IsMachineWidePath(resolvedFile))
        {
            Directory.CreateDirectory(directory);
            return;
        }

        AssertCanProtectMachineWidePaths();
        List<DirectoryInfo> levels = LevelsBelowSharedRoot(directory, SharedDataRoot());

        foreach (DirectoryInfo level in Enumerable.Reverse(levels))
        {
            if (level.Exists)
            {
                AdoptOrRefuseExistingLevel(level, logger);
                continue;
            }

            Directory.CreateDirectory(level.FullName);
        }

        // Hardened only once every level exists and the file has somewhere to go. Hardening a
        // level at the moment it is created removes the creator's own permission to put anything
        // inside it, which locks the very run that made it out of its own directory.
        foreach (DirectoryInfo level in levels)
        {
            RestrictToAdministrators(level.FullName, logger);
        }
    }

    /// <summary>
    /// Takes over a directory that already exists but is not restricted to administrators, or
    /// refuses it when that cannot be done safely.
    ///
    /// Taking it over matters because %ProgramData% lets any user create a directory there: were
    /// this only ever a refusal, one `mkdir` by any logged-in account would stop the machine
    /// enrolling for good, and the same account could repeat it after every cleanup. An elevated
    /// run can simply take ownership and replace the permissions, which leaves whoever planted it
    /// with nothing.
    /// </summary>
    private static void AdoptOrRefuseExistingLevel(DirectoryInfo level, ILogger? logger)
    {
        try
        {
            AssertPathIsTrustworthy(level.FullName);
            return;
        }
        catch (UntrustedEnrollmentConfigException ex)
        {
            // A reparse point is not adopted at any privilege: its target is chosen by whoever
            // created it, so taking ownership and writing through it would be writing wherever
            // they pointed it.
            if (level.LinkTarget != null)
            {
                throw new UntrustedEnrollmentConfigException(
                    $"{level.FullName} is a link rather than a directory, so the enrollment "
                        + "configuration was not written. Delete it and run this again."
                );
            }

            logger?.LogWarning(
                "{Path} already existed without administrator-only permissions. Taking ownership "
                    + "of it and replacing them",
                level.FullName
            );
            RestrictToAdministrators(level.FullName, logger);

            try
            {
                AssertPathIsTrustworthy(level.FullName);
            }
            catch (UntrustedEnrollmentConfigException)
            {
                throw new UntrustedEnrollmentConfigException(
                    $"{level.FullName} already exists, is not restricted to administrators, and "
                        + "could not be taken over, so the enrollment configuration was not written: an "
                        + $"unattended run would refuse it. Delete that directory and run this again as an "
                        + $"administrator. ({ex.Message})"
                );
            }
        }
    }

    /// <summary>
    /// Refuses a machine-wide write that cannot possibly produce a trustworthy result. Without
    /// this, an ordinary user's run creates the directories, fails to make them administrator
    /// owned, and leaves a chain behind that every later run — including elevated ones — refuses.
    /// </summary>
    private static void AssertCanProtectMachineWidePaths()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw new UntrustedEnrollmentConfigException(
                "The machine-wide enrollment configuration can only be written by an "
                    + "administrator, because it has to be protected from everyone else. Run this "
                    + "elevated, or pass --ConfigFile to write somewhere this account owns."
            );
        }
    }

    /// <summary>
    /// The directories from <paramref name="directory"/> up to, but not including, the shared
    /// data root, deepest first.
    /// </summary>
    internal static List<DirectoryInfo> LevelsBelowSharedRoot(
        string directory,
        string sharedDataRoot
    )
    {
        string root = Path.GetFullPath(sharedDataRoot).TrimEnd(Path.DirectorySeparatorChar);
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        List<DirectoryInfo> levels = [];
        for (
            DirectoryInfo? level = new(Path.GetFullPath(directory));
            level != null
                && !string.Equals(
                    level.FullName.TrimEnd(Path.DirectorySeparatorChar),
                    root,
                    comparison
                );
            level = level.Parent
        )
        {
            levels.Add(level);
        }

        return levels;
    }

    /// <summary>
    /// Replaces a file or directory's inherited permissions with ones only administrators can
    /// write.
    /// </summary>
    internal static void RestrictToAdministrators(string path, ILogger? logger = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            UnixFileMode mode =
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead;
            if (Directory.Exists(path))
            {
                mode |= UnixFileMode.UserExecute
                    | UnixFileMode.GroupExecute
                    | UnixFileMode.OtherExecute;
            }

            File.SetUnixFileMode(path, mode);
            return;
        }

        RestrictWindowsPathToAdministrators(path, logger);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void RestrictWindowsPathToAdministrators(string path, ILogger? logger)
    {
        SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        bool isDirectory = Directory.Exists(path);
        FileSystemSecurity permissions = BuildAdministratorsOnlySecurity(isDirectory);

        // The permissions are written first and on their own. Owner and DACL travel in one
        // SetAccessControl call once SetOwner has marked the owner dirty, so combining them would
        // mean a rejected owner write also discards the permissions — which are the part that
        // must land.
        ApplySecurity(path, permissions, isDirectory);

        try
        {
            FileSystemSecurity ownership = isDirectory
                ? new DirectorySecurity()
                : new FileSecurity();
            ownership.SetOwner(administrators);
            ApplySecurity(path, ownership, isDirectory);
        }
        catch (Exception ex)
            when (ex is InvalidOperationException
                or UnauthorizedAccessException
                or PrivilegeNotHeldException
            )
        {
            // Taking ownership for a group the caller is not acting as needs SeRestorePrivilege.
            // SYSTEM and an elevated administrator both have it; without it the next run refuses
            // this file, so it is said now rather than only discovered then.
            logger?.LogWarning(
                ex,
                "Could not set the owner of {Path} to the Administrators group. Later runs will "
                    + "refuse this enrollment configuration until its owner is corrected",
                path
            );
        }
    }

    /// <summary>
    /// The permissions this product writes on its own files and directories. Exposed so a test
    /// can put what Save writes through what Load demands, which is the property that matters and
    /// which a hand-built descriptor in a test cannot vouch for.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static FileSystemSecurity BuildAdministratorsOnlySecurity(bool isDirectory)
    {
        SecurityIdentifier system = new(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        SecurityIdentifier users = new(WellKnownSidType.BuiltinUsersSid, null);
        FileSystemSecurity permissions = isDirectory
            ? new DirectorySecurity()
            : new FileSecurity();
        permissions.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (
            (SecurityIdentifier identity, FileSystemRights rights) in new[]
            {
                (system, FileSystemRights.FullControl),
                (administrators, FileSystemRights.FullControl),
                (users, FileSystemRights.ReadAndExecute),
            }
        )
        {
            permissions.AddAccessRule(
                isDirectory
                    ? new FileSystemAccessRule(
                        identity,
                        rights,
                        InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
                        PropagationFlags.None,
                        AccessControlType.Allow
                    )
                    : new FileSystemAccessRule(identity, rights, AccessControlType.Allow)
            );
        }

        return permissions;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void ApplySecurity(
        string path,
        FileSystemSecurity security,
        bool isDirectory
    )
    {
        if (isDirectory)
        {
            new DirectoryInfo(path).SetAccessControl((DirectorySecurity)security);
            return;
        }

        new FileInfo(path).SetAccessControl((FileSecurity)security);
    }

    /// <summary>
    /// Whether this is the file an unattended run reads when it is given no arguments, which is
    /// the one whose permissions have to be right.
    /// </summary>
    internal static bool IsMachineWidePath(string resolvedPath)
    {
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (
            string.Equals(
                resolvedPath.TrimEnd(Path.DirectorySeparatorChar),
                new EnrollmentConfigService()
                    .ResolvePath(null)
                    .TrimEnd(Path.DirectorySeparatorChar),
                comparison
            )
        )
        {
            return true;
        }

        // Anything inside the shared data root counts too. Comparing one exact path would let a
        // different spelling of the same file be written without its permissions and then be
        // refused by the very check that spelling skipped.
        string root = Path.GetFullPath(SharedDataRoot())
            .TrimEnd(Path.DirectorySeparatorChar);
        return resolvedPath.StartsWith(root + Path.DirectorySeparatorChar, comparison);
    }

    internal static void AssertConfigurationIsTrustworthy(string path)
    {
        AssertPathIsTrustworthy(path);
        foreach (string directory in AncestorsToCheck(path))
        {
            AssertPathIsTrustworthy(directory);
        }
    }

    internal static void AssertPathIsTrustworthy(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            AssertWindowsPathIsTrustworthy(path);
            return;
        }

        AssertUnixPathIsTrustworthy(path, Directory.Exists(path));
    }

    /// <summary>
    /// The directories between the file and the platform's shared data root. They are checked too
    /// because owning a directory is enough to replace what is inside it: the root itself is not
    /// checked, since it is the operating system's and is writable by design.
    /// </summary>
    private static IEnumerable<string> AncestorsToCheck(string path)
    {
        return AncestorsToCheck(path, SharedDataRoot());
    }

    /// <summary>
    /// The root is a parameter so the walk can be exercised without writing into the real shared
    /// data directory, which a test process cannot do.
    /// </summary>
    internal static IEnumerable<string> AncestorsToCheck(string path, string sharedDataRoot)
    {
        string root = Path.GetFullPath(sharedDataRoot);
        string fullPath = Path.GetFullPath(path);
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (
            !fullPath.StartsWith(
                root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                comparison
            )
        )
        {
            // A file outside the shared data root has no ancestors this check owns an opinion
            // about, and walking to the volume root would judge directories the operating system
            // or the user legitimately controls.
            yield break;
        }

        DirectoryInfo? directory = new FileInfo(fullPath).Directory;
        while (
            directory != null
            && !string.Equals(
                directory.FullName.TrimEnd(Path.DirectorySeparatorChar),
                root.TrimEnd(Path.DirectorySeparatorChar),
                comparison
            )
        )
        {
            yield return directory.FullName;
            directory = directory.Parent;
        }
    }

    private static string SharedDataRoot()
    {
        if (OperatingSystem.IsWindows())
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        }

        return OperatingSystem.IsMacOS() ? "/Library/Application Support" : "/etc";
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void AssertUnixPathIsTrustworthy(string path, bool isDirectory)
    {
        UnixFileMode mode = isDirectory
            ? File.GetUnixFileMode(new DirectoryInfo(path).FullName)
            : File.GetUnixFileMode(path);
        if (mode.HasFlag(UnixFileMode.GroupWrite) || mode.HasFlag(UnixFileMode.OtherWrite))
        {
            throw new UntrustedEnrollmentConfigException(
                $"{path} is writable by users other than its owner, so the enrollment "
                    + "configuration is not trusted. Run 'chmod go-w' on it."
            );
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void AssertWindowsPathIsTrustworthy(string path)
    {
        FileSystemSecurity security = Directory.Exists(path)
            ? new DirectoryInfo(path).GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner
            )
            : new FileInfo(path).GetAccessControl(
                AccessControlSections.Access | AccessControlSections.Owner
            );
        AssertSecurityIsTrustworthy(security, path);
    }

    /// <summary>
    /// The decision itself, separated from reading it off disk so it can be exercised against a
    /// constructed descriptor: setting a real file's owner needs a privilege a test process does
    /// not have.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    internal static void AssertSecurityIsTrustworthy(FileSystemSecurity security, string path)
    {
        // The owner is checked as well as the permissions: on NTFS an owner holds WRITE_DAC
        // implicitly, so whoever owns this can grant themselves write access whatever the
        // permissions currently say.
        IdentityReference? owner = security.GetOwner(typeof(SecurityIdentifier));
        if (owner is not SecurityIdentifier ownerSid || !IsAdministrativeIdentity(ownerSid))
        {
            if (owner is not SecurityIdentifier unknownOwner)
            {
                // An owner we cannot read is the one case the DACL alone cannot speak for, so it
                // is refused rather than waved through.
                throw new UntrustedEnrollmentConfigException(
                    $"The owner of {path} could not be read, so the enrollment configuration is "
                        + "not trusted."
                );
            }

            ownerSid = unknownOwner;
            throw new UntrustedEnrollmentConfigException(
                $"{path} is owned by {DescribeIdentity(ownerSid)}, which is not an administrative "
                    + "account, so the enrollment configuration is not trusted. Its owner can grant themselves "
                    + "write access at any time regardless of its permissions."
            );
        }

        foreach (
            FileSystemAccessRule rule in security.GetAccessRules(
                true,
                true,
                typeof(SecurityIdentifier)
            )
        )
        {
            if (rule.AccessControlType != AccessControlType.Allow)
            {
                continue;
            }

            if ((rule.FileSystemRights & WriteRights()) == 0)
            {
                continue;
            }

            SecurityIdentifier identity = (SecurityIdentifier)rule.IdentityReference;
            if (IsAdministrativeIdentity(identity))
            {
                continue;
            }

            throw new UntrustedEnrollmentConfigException(
                $"{path} can be written by {DescribeIdentity(identity)}, which is not an "
                    + "administrative account, so the enrollment configuration is not trusted. Remove that "
                    + "permission, or delete it and reinstall so it is created with the right permissions."
            );
        }
    }

    /// <summary>
    /// Rights that let the holder change what this file says, directly or by first changing who
    /// may write it. Declared inside a Windows-only method because these constants do not exist
    /// on the other platforms this client builds for.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static FileSystemRights WriteRights()
    {
        return FileSystemRights.WriteData
            | FileSystemRights.AppendData
            | FileSystemRights.ChangePermissions
            | FileSystemRights.TakeOwnership
            | FileSystemRights.Delete;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool IsAdministrativeIdentity(SecurityIdentifier identity)
    {
        // TrustedInstaller has no WellKnownSidType, so it is matched by its fixed SID.
        if (identity.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
        {
            return true;
        }

        return identity.IsWellKnown(WellKnownSidType.LocalSystemSid)
            || identity.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
            || identity.IsWellKnown(WellKnownSidType.AccountDomainAdminsSid)
            || identity.IsWellKnown(WellKnownSidType.AccountEnterpriseAdminsSid);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string DescribeIdentity(SecurityIdentifier identity)
    {
        try
        {
            return identity.Translate(typeof(NTAccount)).Value;
        }
        catch (IdentityNotMappedException)
        {
            return identity.Value;
        }
    }

    /// <summary>
    /// The machine wide location for this platform. The file describes the machine rather than
    /// whoever is running the command, and the scheduled task that renews the certificate runs as
    /// SYSTEM or root, so it does not belong in a user profile.
    /// </summary>
    public string ResolvePath(string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            return Path.GetFullPath(path);
        }

        if (OperatingSystem.IsWindows())
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Keytos",
                "EZCACertManager",
                FileName
            );
        }

        if (OperatingSystem.IsMacOS())
        {
            return Path.Combine(
                "/Library",
                "Application Support",
                "Keytos",
                "EZCACertManager",
                FileName
            );
        }

        return Path.Combine("/etc", "keytos", "ezcacertmanager", FileName);
    }

    /// <summary>
    /// Applies the saved settings to the arguments, letting anything passed on the command line
    /// win over what is on disk.
    /// </summary>
    public static void ApplyTo(EnrollArgModel values, EnrollmentConfig config)
    {
        ArgumentNullException.ThrowIfNull(values);
        ArgumentNullException.ThrowIfNull(config);
        if (string.IsNullOrWhiteSpace(values.Url))
        {
            values.Url = config.Url;
        }

        if (string.IsNullOrWhiteSpace(values.Spn))
        {
            values.Spn = config.Spn;
        }

        if (
            values.Mode == AttestationMode.Auto
            && !string.IsNullOrWhiteSpace(config.Mode)
            && Enum.TryParse(config.Mode, true, out AttestationMode savedMode)
        )
        {
            values.Mode = savedMode;
        }
    }
}

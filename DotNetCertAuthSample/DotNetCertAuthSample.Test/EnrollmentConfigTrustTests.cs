using System.Security.AccessControl;
using System.Security.Principal;
using DotNetCertAuthSample.Services;
using System.Runtime.Versioning;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// The check that stops an unattended SYSTEM run from taking its enrollment URL, or its "already
/// enrolled" thumbprint, out of a file an ordinary user could have written.
///
/// The Windows cases are built against a constructed security descriptor rather than a real file,
/// because setting a file's owner to the Administrators group needs a privilege a test process
/// does not hold — and owner is half of what is being tested.
/// </summary>
public class EnrollmentConfigTrustTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"ezca-trust-{Guid.NewGuid():N}"
    );

    private string CreateConfigFile()
    {
        Directory.CreateDirectory(_directory);
        string path = Path.Combine(_directory, "enrollment.json");
        File.WriteAllText(path, "{}");
        return path;
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
        catch (IOException)
        {
            // A temp directory that will not delete is not a test failure.
        }

        GC.SuppressFinalize(this);
    }

    [SupportedOSPlatform("windows")]
    private static FileSecurity SecurityOwnedByAdministrators()
    {
        FileSecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow
            )
        );
        security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow
            )
        );
        security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.Read,
                AccessControlType.Allow
            )
        );
        return security;
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void A_Descriptor_Restricted_To_Administrators_Is_Accepted()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        EnrollmentConfigService.AssertSecurityIsTrustworthy(
            SecurityOwnedByAdministrators(),
            "enrollment.json"
        );
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Write_Access_For_Ordinary_Users_Is_Refused()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        FileSecurity security = SecurityOwnedByAdministrators();
        security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.WriteData,
                AccessControlType.Allow
            )
        );

        UntrustedEnrollmentConfigException refusal =
            Assert.Throws<UntrustedEnrollmentConfigException>(() =>
                EnrollmentConfigService.AssertSecurityIsTrustworthy(security, "enrollment.json")
            );
        Assert.Contains("not trusted", refusal.Message);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Permission_To_Change_Permissions_Counts_As_Write_Access()
    {
        // The holder can grant themselves write whenever they like, so it is the same thing.
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        FileSecurity security = SecurityOwnedByAdministrators();
        security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ChangePermissions,
                AccessControlType.Allow
            )
        );

        Assert.Throws<UntrustedEnrollmentConfigException>(() =>
            EnrollmentConfigService.AssertSecurityIsTrustworthy(security, "enrollment.json")
        );
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void A_Non_Administrative_Owner_Is_Refused_Even_With_A_Clean_Dacl()
    {
        // An owner holds WRITE_DAC implicitly, so a tidy DACL says nothing if the wrong account
        // can rewrite it at will. This is the bypass the permission loop alone does not catch.
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        FileSecurity security = SecurityOwnedByAdministrators();
        security.SetOwner(
            new SecurityIdentifier(WellKnownSidType.BuiltinGuestsSid, null)
        );

        UntrustedEnrollmentConfigException refusal =
            Assert.Throws<UntrustedEnrollmentConfigException>(() =>
                EnrollmentConfigService.AssertSecurityIsTrustworthy(security, "enrollment.json")
            );
        Assert.Contains("owned by", refusal.Message);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void A_Denied_Rule_Does_Not_Count_As_Write_Access()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        FileSecurity security = SecurityOwnedByAdministrators();
        security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.WriteData,
                AccessControlType.Deny
            )
        );

        EnrollmentConfigService.AssertSecurityIsTrustworthy(security, "enrollment.json");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [SupportedOSPlatform("windows")]
    public void What_Save_Writes_Passes_What_Load_Demands(bool isDirectory)
    {
        // The property that matters, and the one a hand-built descriptor cannot vouch for: the
        // permissions the product actually applies have to satisfy the check the next run runs.
        // Asserted for the directory form too, which carries inheritance flags the file form
        // does not.
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        FileSystemSecurity written = EnrollmentConfigService.BuildAdministratorsOnlySecurity(
            isDirectory
        );
        written.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));

        EnrollmentConfigService.AssertSecurityIsTrustworthy(
            written,
            isDirectory ? "EZCACertManager" : "enrollment.json"
        );
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void The_Permissions_Written_Grant_Ordinary_Users_No_Write_Access()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        FileSystemSecurity written = EnrollmentConfigService.BuildAdministratorsOnlySecurity(
            isDirectory: true
        );

        FileSystemAccessRule usersRule = Assert.Single(
            written.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(),
            rule =>
                ((SecurityIdentifier)rule.IdentityReference).IsWellKnown(
                    WellKnownSidType.BuiltinUsersSid
                )
        );
        Assert.Equal(AccessControlType.Allow, usersRule.AccessControlType);

        // Not an equality check: the framework folds Synchronize into every rule. What has to
        // hold is that none of the rights the trust check treats as write access is granted.
        const FileSystemRights writeRights =
            FileSystemRights.WriteData
            | FileSystemRights.AppendData
            | FileSystemRights.ChangePermissions
            | FileSystemRights.TakeOwnership
            | FileSystemRights.Delete;
        Assert.Equal((FileSystemRights)0, usersRule.FileSystemRights & writeRights);
        Assert.True(usersRule.FileSystemRights.HasFlag(FileSystemRights.ReadAndExecute));
        Assert.True(written.AreAccessRulesProtected);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void An_Owner_That_Cannot_Be_Read_Is_Refused()
    {
        // The one case a DACL cannot speak for, so it must not fall through to the rule loop.
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        FileSecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(
            new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow
            )
        );

        UntrustedEnrollmentConfigException refusal =
            Assert.Throws<UntrustedEnrollmentConfigException>(() =>
                EnrollmentConfigService.AssertSecurityIsTrustworthy(security, "enrollment.json")
            );
        Assert.Contains("could not be read", refusal.Message);
    }

    [Fact]
    public void A_World_Writable_File_Is_Refused()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string path = CreateConfigFile();
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead
                | UnixFileMode.OtherWrite
        );

        Assert.Throws<UntrustedEnrollmentConfigException>(() =>
            EnrollmentConfigService.AssertConfigurationIsTrustworthy(path)
        );
    }

    [Fact]
    public void A_Group_Writable_File_Is_Refused()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string path = CreateConfigFile();
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead
                | UnixFileMode.GroupWrite
                | UnixFileMode.OtherRead
        );

        Assert.Throws<UntrustedEnrollmentConfigException>(() =>
            EnrollmentConfigService.AssertConfigurationIsTrustworthy(path)
        );
    }

    [Fact]
    public void An_Owner_Only_Writable_File_Is_Accepted()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string path = CreateConfigFile();
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead
        );

        EnrollmentConfigService.AssertConfigurationIsTrustworthy(path);
    }
}

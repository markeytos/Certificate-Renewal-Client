using DotNetCertAuthSample.Services;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// The walk up from the configuration file to the shared data root. It exists because owning a
/// directory is enough to replace what is inside it, so locking only the file would leave the
/// same hole open one level up.
/// </summary>
public class EnrollmentConfigAncestorTests
{
    private static string Root => Path.Combine(Path.GetTempPath(), "ezca-root-test");

    private static List<string> Ancestors(string relativeFilePath)
    {
        return EnrollmentConfigService
            .AncestorsToCheck(Path.Combine(Root, relativeFilePath), Root)
            .ToList();
    }

    [Fact]
    public void Every_Directory_Between_The_File_And_The_Root_Is_Returned()
    {
        List<string> ancestors = Ancestors(Path.Combine("Keytos", "EZCACertManager", "enrollment.json"));

        Assert.Equal(
            [
                Path.Combine(Root, "Keytos", "EZCACertManager"),
                Path.Combine(Root, "Keytos"),
            ],
            ancestors
        );
    }

    [Fact]
    public void The_Root_Itself_Is_Not_Returned()
    {
        // The shared data root belongs to the operating system and is writable by design; it is
        // the directories this product creates inside it that have to be locked down.
        List<string> ancestors = Ancestors(Path.Combine("Keytos", "enrollment.json"));

        Assert.Equal([Path.Combine(Root, "Keytos")], ancestors);
        Assert.DoesNotContain(Root, ancestors);
    }

    [Fact]
    public void A_File_Outside_The_Root_Has_No_Ancestors_To_Judge()
    {
        // Walking to the volume root would start judging directories the operating system or the
        // user legitimately controls.
        List<string> ancestors = EnrollmentConfigService
            .AncestorsToCheck(
                Path.Combine(Path.GetTempPath(), "somewhere-else", "enrollment.json"),
                Root
            )
            .ToList();

        Assert.Empty(ancestors);
    }

    [Fact]
    public void A_Path_That_Merely_Starts_With_The_Root_Name_Is_Outside_It()
    {
        // "…\ezca-root-test-other" is not inside "…\ezca-root-test".
        List<string> ancestors = EnrollmentConfigService
            .AncestorsToCheck(Root + "-other" + Path.DirectorySeparatorChar + "enrollment.json", Root)
            .ToList();

        Assert.Empty(ancestors);
    }

    [Fact]
    public void A_File_Directly_In_The_Root_Has_No_Ancestors()
    {
        Assert.Empty(Ancestors("enrollment.json"));
    }
}

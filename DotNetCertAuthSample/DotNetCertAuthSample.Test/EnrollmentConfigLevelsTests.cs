using DotNetCertAuthSample.Services;
using Xunit;

namespace DotNetCertAuthSample.Test;

/// <summary>
/// The directory levels the configuration writer creates and hardens. The order it works in has
/// produced two separate lock-outs, so it is pinned here rather than reasoned about: levels have
/// to be reported deepest first, and nothing above the shared data root may appear.
/// </summary>
public class EnrollmentConfigLevelsTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"ezca-levels-{Guid.NewGuid():N}"
    );

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (IOException)
        {
            // A temp directory that will not delete is not a test failure.
        }

        GC.SuppressFinalize(this);
    }

    private List<string> Levels(params string[] relativeSegments)
    {
        string directory = Path.Combine([_root, .. relativeSegments]);
        return EnrollmentConfigService
            .LevelsBelowSharedRoot(directory, _root)
            .Select(level => level.FullName)
            .ToList();
    }

    [Fact]
    public void Levels_Are_Reported_Deepest_First()
    {
        // The caller creates in reverse of this and hardens in this order, so the direction is
        // load-bearing: hardening a parent before its child exists locks the run out of it.
        Assert.Equal(
            [
                Path.Combine(_root, "Keytos", "EZCACertManager"),
                Path.Combine(_root, "Keytos"),
            ],
            Levels("Keytos", "EZCACertManager")
        );
    }

    [Fact]
    public void The_Shared_Root_Is_Never_A_Level()
    {
        // %ProgramData% and /etc belong to the operating system; taking them over would be wrong
        // and would fail anyway.
        Assert.DoesNotContain(_root, Levels("Keytos", "EZCACertManager"));
        Assert.DoesNotContain(_root, Levels("Keytos"));
    }

    [Fact]
    public void A_Directory_That_Is_The_Root_Has_No_Levels()
    {
        Assert.Empty(EnrollmentConfigService.LevelsBelowSharedRoot(_root, _root));
    }

    [Fact]
    public void A_Directory_Outside_The_Root_Still_Walks_Only_To_The_Root()
    {
        // A sibling whose name merely starts with the root's name is not inside it, so the walk
        // must not stop early and silently treat its parent as the root.
        string sibling = _root + "-other";
        List<string> levels = EnrollmentConfigService
            .LevelsBelowSharedRoot(Path.Combine(sibling, "Keytos"), _root)
            .Select(level => level.FullName)
            .ToList();

        Assert.Contains(Path.Combine(sibling, "Keytos"), levels);
        Assert.Contains(sibling, levels);
    }

    [Fact]
    public void Trailing_Separators_Do_Not_Produce_A_Duplicate_Level()
    {
        List<string> withSeparator = EnrollmentConfigService
            .LevelsBelowSharedRoot(
                Path.Combine(_root, "Keytos") + Path.DirectorySeparatorChar,
                _root + Path.DirectorySeparatorChar
            )
            .Select(level => level.FullName)
            .ToList();

        Assert.Single(withSeparator);
    }
}

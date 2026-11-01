using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using DotNetCertAuthSample.Models;
using Microsoft.Extensions.Logging;

namespace DotNetCertAuthSample.Services;

public interface ISettingsService
{
    SettingsModel GetSettings(ILogger logger);
    void SaveSettings(SettingsModel settings, ILogger? logger);
}

public class SettingsService : ISettingsService
{
    public SettingsModel GetSettings(ILogger? logger)
    {
        string settingsFolder = "certClient";
        string path = CreateFilePath("certClientSettings.json", settingsFolder);
        string settingsString = GetFullFile(path, logger, true);
        SettingsModel result;
        if (string.IsNullOrWhiteSpace(settingsString))
        {
            result = new();
            SaveSettings(result, logger);
        }
        else
        {
            result = JsonSerializer.Deserialize<SettingsModel>(settingsString) ?? new();
        }
        return result;
    }

    public void SaveSettings(SettingsModel settings, ILogger? logger)
    {
        string settingsFolder = "certClient";
        string path = CreateFilePath("certClientSettings.json", settingsFolder);
        DateTime utcNow = DateTime.UtcNow;
        settings.RotatedCertificates = settings
            .RotatedCertificates.Where(rc => ShouldKeepRotationRecord(rc.ExpiryDate, utcNow))
            .ToList();
        string settingsString = JsonSerializer.Serialize(settings);
        WriteToFile(path, settingsString, logger, settingsFolder);
    }

    /// <summary>
    /// renewAll records the old certificate's thumbprint so the next run does not renew it again.
    /// That certificate stays in the store, so the record has to outlive its expiry. Drop it a week
    /// after it expires, once a daily run has had time to move on.
    /// </summary>
    internal static bool ShouldKeepRotationRecord(DateTime expiryDate, DateTime utcNow)
    {
        return expiryDate > utcNow.AddDays(-7);
    }

    private static void WriteToFile(string path, string content, ILogger? logger, string folder)
    {
        path = CreateFilePath(path, folder);
        try
        {
            using (FileStream fs = File.Create(path))
            {
                byte[] info = new UTF8Encoding(true).GetBytes(content);
                fs.Write(info, 0, info.Length);
            }
        }
        catch (Exception ex)
        {
            if (logger != null)
            {
                logger.LogError(ex, "Failed to write to file");
            }
        }
    }

    private static string GetFullFile(string filepath, ILogger? logger, bool suppressError = false)
    {
        string content = string.Empty;
        try
        {
            content = File.ReadAllText(filepath, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            if (!suppressError && logger != null)
            {
                logger.LogError(ex, "Failed to read file");
            }
        }
        return content;
    }

    private static string CreateFilePath(string fileName, string folder)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new ArgumentException("fileName cannot be null or empty", nameof(fileName));
        }

        // If it's already an absolute path, just return it
        if (Path.IsPathRooted(fileName))
        {
            return fileName;
        }

        string basePath;

        if (OperatingSystem.IsWindows())
        {
            basePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                folder
            );
        }
        else if (OperatingSystem.IsMacOS())
        {
            basePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library",
                folder
            );
        }
        else
        {
            // Linux / others
            basePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                folder
            );
        }

        Directory.CreateDirectory(basePath);

        return Path.Combine(basePath, fileName);
    }
}

namespace DotNetCertAuthSample.Services;

/// <summary>
/// The Windows key storage providers the client asks for by name. Only Windows builds certificate
/// requests through CertEnroll, so on Linux and macOS the provider name is ignored and these
/// values never reach a key.
/// </summary>
public static class KeyProviders
{
    /// <summary>
    /// TPM backed keys. A key created here cannot be exported, so a certificate issued against it
    /// stays on the machine it was issued to.
    /// </summary>
    public const string PlatformCrypto = "Microsoft Platform Crypto Provider";

    /// <summary>Software CNG keys. The fallback when the machine has no usable TPM.</summary>
    public const string SoftwareKeyStorage = "Microsoft Software Key Storage Provider";

    /// <summary>
    /// The legacy CSP the client used before TPM keys. Still the default for the commands that
    /// issue server certificates, where the key often has to be exported or backed up.
    /// </summary>
    public const string LegacyCsp = "Microsoft Enhanced Cryptographic Provider v1.0";

    /// <summary>
    /// The provider a device certificate should use when the caller did not name one. Device
    /// certificates identify the machine itself, so they default to the TPM and fall back to a
    /// software key only when the TPM cannot produce one.
    /// </summary>
    public static string DefaultForDeviceCertificate()
    {
        return OperatingSystem.IsWindows() ? PlatformCrypto : string.Empty;
    }

    /// <summary>
    /// The provider to retry with after <paramref name="keyProvider"/> failed, or null when there
    /// is nothing sensible left to try. Only the TPM default falls back: a provider the caller
    /// asked for by name is honored or the command fails, since silently using a weaker key than
    /// the one that was requested is worse than stopping.
    /// </summary>
    public static string? FallbackFor(string keyProvider, bool callerSuppliedProvider)
    {
        if (callerSuppliedProvider || !OperatingSystem.IsWindows())
        {
            return null;
        }

        return keyProvider == PlatformCrypto ? SoftwareKeyStorage : null;
    }
}

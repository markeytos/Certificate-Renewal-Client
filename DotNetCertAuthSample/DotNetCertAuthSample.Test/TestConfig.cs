namespace DotNetCertAuthSample.Test;

internal static class TestConfig
{
    public static string SslCaId => GetRequired("EZCA_SSL_CA_ID");

    public static string ScepCaId => GetRequired("EZCA_SCEP_CA_ID");

    public static string ScepTemplateId => GetRequired("EZCA_SCEP_TEMPLATE_ID");

    public static string ScepUrl => GetRequired("EZCA_SCEP_URL");

    public static string ScepPassword => GetRequired("EZCA_SCEP_PASSWORD");

    public static string? CertPassword => GetOptional("CERT_PASSWORD");

    public static string? AppInsights => GetOptional("APP_INSIGHTS_INSTRUMENTATION_KEY");

    private static string GetRequired(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new Exception($"Environment variable {name} must be provided");
        }
        return value;
    }

    private static string? GetOptional(string name)
    {
        return Environment.GetEnvironmentVariable(name);
    }
}

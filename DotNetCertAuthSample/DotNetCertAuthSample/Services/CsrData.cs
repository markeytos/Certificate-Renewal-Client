namespace DotNetCertAuthSample.Services
{
    /// <summary>
    /// Platform-independent representation of a CSR along with its associated private key context
    /// </summary>
    public class CsrData
    {
        /// <summary>
        /// The CSR in PEM format (Base64 encoded with headers)
        /// </summary>
        public string CsrPem { get; set; } = string.Empty;
        
        /// <summary>
        /// Platform-specific private key context (e.g., CX509CertificateRequestPkcs10 on Windows, RSA on Linux)
        /// </summary>
        public object? PrivateKeyContext { get; set; }
    }
}

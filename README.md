# Certificate Renewal Client

At Keytos, our goal is to make EZCA, our [cloud PKI service](https://www.keytos.io/azure-pki), easy-to-use for every person in the world. One way to make this a reality is by removing humans as much as possible from the equation. To help companies achieve this goal, we have created a sample C# console application for Windows and Linux that can:

- [Register a new domain in EZCA](https://www.keytos.io/docs/azure-pki/pki-tooling/ezca-cert-renewal-client/#register-a-new-domain-in-ezca)
- [Create a new certificate](https://www.keytos.io/docs/azure-pki/pki-tooling/ezca-cert-renewal-client/#create-a-new-certificate)
- [Renew an existing certificate](https://www.keytos.io/docs/azure-pki/pki-tooling/ezca-cert-renewal-client/#renew-an-existing-certificate)
- [Create a Domain Controller Certificate](https://www.keytos.io/docs/azure-pki/pki-tooling/ezca-cert-renewal-client/#create-a-domain-controller-certificate)
- [Create SCEP Certificates for Unmanaged Devices](https://www.keytos.io/docs/azure-pki/pki-tooling/ezca-cert-renewal-client/#create-scep-certificates-for-unmanaged-devices)

This application can be used in combination with Windows Task Scheduler or Linux cron jobs to automatically renew certificates before they expire, ensuring that your systems remain secure and compliant without manual intervention.

## Platform Support

This application supports **Windows**, **Mac**, **Linux** platforms:

- **Windows**: Uses Windows Certificate Store and Windows-specific APIs (CertEnroll, Active Directory, RDP configuration)
- **Linux**: Uses file-based certificate storage in `~/.local/share/keytos/certs` (user store) or `/etc/keytos/certs` (machine store)
- **Mac**: Uses Mac Keychain Access

**Note**: Some features are Windows-specific:
- RDP certificate configuration (requires Windows)
- Domain Controller certificate features (requires Active Directory)
- Windows Certificate Store integration

## Installation

1. Navigate to the **Releases** section.
    <img width="1562" height="787" alt="image" src="https://github.com/user-attachments/assets/cc6dbf42-0625-48be-9a8f-348e3967e1b3" />
1. Download the latest executable for your operating system.
  <img width="1396" height="552" alt="image" src="https://github.com/user-attachments/assets/60d6c1ea-0577-4b68-8ced-539bbfac60b4" />

### Windows

1. Download `EZCACertManager.exe` from the [latest release](../../releases/latest).
2. Open **PowerShell** or **Command Prompt** and navigate to the download location.
3. Run the executable directly:
   ```powershell
   .\EZCACertManager.exe --help
   ```
4. *(Optional)* Add the directory to your `PATH` so you can run it from anywhere:
   ```powershell
   $env:PATH += ";C:\path\to\EZCACertManager"
   ```
   To make this permanent, add it via **System Properties → Environment Variables**.

### MacOS

1. Download `EZCACertManager` (macOS binary) from the [latest release](../../releases/latest).
1. Open **Terminal** and navigate to the download location.
1. Make the binary executable:
   ```bash
   chmod +x ./EZCACertManager
   ```
1. Run it:
   ```bash
   ./EZCACertManager --help
   ```
1. *(Optional)* Move it to a directory on your `PATH`:
   ```bash
   sudo mv ./EZCACertManager /usr/local/bin/EZCACertManager
   ```
   Then run from anywhere:
   ```bash
   EZCACertManager --help
   ```

### Linux

1. Download `EZCACertManager.deb` (Linux binary) from the [latest release](../../releases/latest).
1. Open a **terminal** and navigate to the download location.
1. Install it:
   ```bash
   sudo apt install ./EZCACertManager.deb
   ```
1. Run it:
   ```bash
   EZCACertManager --help
   ```


## Documentation

Please refer to the [Keytos documentation](https://www.keytos.io/docs/azure-pki/pki-tooling/ezca-cert-renewal-client/#how-to-manage-your-ezca-resources-with-the-ezca-certificate-renewal-client) for instructions on how to use the tool and example commands!

## Development 
If you want to contribute or customize the application, you can clone the repository and build it using .NET 10 SDK. Make sure to have the necessary dependencies installed and follow the coKeytos code best practices for contributions. 

### Testing 
We have included unit tests for the core functionalities of the application. To run the tests, use the following command in the project directory
#### Windows 
First you have to add the environment variables for your tests (Fill in the values for your environment, if you are a Keytos Engineer ask Grayson or Igal for the internal values):
```powershell
$env:EZCA_SSL_CA_ID=""
$env:EZCA_SSL_CA_ISSUER=""
$env:TEMPLATE_NAME=""
$env:EZCA_SCEP_CA_ID=""
$env:EZCA_SCEP_TEMPLATE_ID=""
$env:EZCA_SCEP_URL=""
$env:EZCA_SCEP_PASSWORD=""
$env:APP_INSIGHTS_INSTRUMENTATION_KEY=""
$env:CA_SUBJECT_KEY_IDENTIFIER=""
```
For windows, since we have certenroll and other windows specific dependencies, we must build it using the msbuild command instead of dotnet build, to ensure the correct target framework is used. 
```powershell
MSBuild.exe  .\DotNetCertAuthSample\DotNetCertAuthSample.Test\DotNetCertAuthSample.Test.csproj   /t:Build   /p:Configuration=Debug    /p:TargetFramework=net10.0-windows
```
If you can't find the msbuild command, it is probably here: `C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe` (path may vary based on your Visual Studio version and edition but this is 2026).

Then you can run the tests using the following command:
```powershell
$vsTest = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\TestWindow\vstest.console.exe"  
& $vsTest  .\DotNetCertAuthSample\DotNetCertAuthSample.Test\bin\Debug\net10.0-windows\DotNetCertAuthSample.Test.dll
```


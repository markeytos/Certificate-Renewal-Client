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

- **Windows**: Uses Windows Certificate Store and Windows-specific APIs (CertEnroll, Active Directory, RDP configuration, IIS bindings)
- **Linux**: Uses file-based certificate storage in `~/.local/share/keytos/certs` (user store) or `/etc/keytos/certs` (machine store)
- **Mac**: Uses Mac Keychain Access

**Note**: Some features are Windows-specific:
- RDP certificate configuration (requires Windows)
- IIS binding configuration (requires Windows with IIS installed)
- Domain Controller certificate features (requires Active Directory)
- Windows Certificate Store integration

### IIS bindings

`create` and `renew` accept `--IISSite "<site name>"` to bind the new certificate to the https bindings of that IIS site. The certificate has to go to the machine store, so `--LocalStore` is required. Without `--IISSite` nothing in IIS is touched.

```powershell
.\EZCACertManager.exe renew -s "www.contoso.com" --LocalStore --IISSite "Default Web Site"
```

Within the named site, a binding is only rebound when the certificate can actually serve it:

- A binding whose host name the certificate covers is rebound. Names come from the certificate's DNS SANs, falling back to its common name, and a wildcard stands in for exactly one label, so `*.contoso.com` covers `www.contoso.com` but not `a.b.contoso.com` or `contoso.com`.
- A binding with no host name (`*:443:`) is rebound, since it serves whatever reaches the site and the site was named explicitly.
- A binding serving some other host name is left alone and named in the output, so a second site name sharing the same IIS site does not get pointed at a certificate that cannot serve it.
- If nothing in the site matches, the command fails and lists what it found rather than guessing.

`renewAll` needs no flag. Every IIS https binding pointing at a certificate it renews is moved to the renewed certificate automatically, the same way RDP bindings are. Bindings that use the IIS Central Certificate Store are left alone, since those are managed by the store itself rather than by thumbprint.

Bindings keep whichever store they already read from. Certificates are issued into `LocalMachine\MY`, so a binding on another store (`WebHosting`, typically) gets a copy of the certificate placed in that store rather than being moved to `MY` or refused.

All of these need to run elevated, and IIS binding changes are written to `applicationHost.config`.

## Device enrollment for Entra joined devices (`enroll`)

`enroll` asks EZCA for a device certificate for an Entra joined or hybrid joined Windows device, and
proves which device is asking with the device's own Entra registration, so nothing secret has to be
distributed to get a device its first certificate.

Domain joined machines don't need this client: they get their certificates from Windows
autoenrollment, which EZCA serves directly once its enrollment policy server is set in Group Policy.

Copy the enrollment URL the Keytos portal shows for the Entra profile, exactly as shown. It ends in
the tenant, CA and profile IDs, each profile has its own, and the device signs it, so a URL with
anything added (a query string, say) fails every enrollment and is refused up front:

```powershell
.\EZCACertManager.exe enroll --Url "https://portal.ezca.io/api/enroll/device/<tenant>/<ca>/<profile>" --SaveConfig
```

With `--SaveConfig` the URL is written to a machine wide configuration file, and later runs need no
arguments at all:

```powershell
.\EZCACertManager.exe enroll
```

The configuration file lives in `%ProgramData%\Keytos\EZCACertManager\`. Run `enroll` as SYSTEM,
as the installer's scheduled task does: the device registration certificate and its key are in the
machine store.

### How the device proves who it is

When a Windows device joins Entra (or is hybrid joined), the Entra device registration service
issues it a certificate whose subject is the Entra device ID, and Windows normally keeps its key in
the TPM. `enroll` sends that certificate and signs the enrollment with its key. EZCA then checks
that:

- the certificate chains to the Entra device registration service;
- the signature verifies with the certificate's key, over this enrollment's challenge, URL and
  certificate request;
- Entra ID, in the CA's own tenant, lists this certificate as the current registration of an
  enabled, Entra joined or hybrid joined device, in a group the profile allows.

The issued certificate names the device by its Entra device ID (`EntraDeviceId://<device ID>`) and
whatever else the profile's formats say, never by anything the device puts in its request. A hybrid
joined device can also hold a certificate from Windows autoenrollment; the two are expected to
coexist, for example while moving off Active Directory.

`enroll` is also the renewal path: it checks the certificate it already has and does nothing unless
that certificate is within `--RenewalPercentage` of expiry. Renewing therefore re-proves the
device's identity, so a device that has been disabled or deleted in Entra ID stops getting
certificates rather than renewing on the strength of the certificate it already has. Run it from a
scheduled task at startup and daily; the installer below sets that up.

### The enrollment exchange

`<url>` is the profile's enrollment URL, `.../api/enroll/device/<tenant>/<ca>/<profile>`.

`GET .../api/enroll/device/<tenant>/<ca>/challenge` (the challenge belongs to the CA, so the profile
segment is replaced):

```json
{ "challengeId": "<GUID>", "nonce": "<base64>" }
```

`POST <url>` with `Authorization: EntraDevice <base64 DER of the device registration certificate>`
and body:

```json
{
  "csr": "<PEM certificate request>",
  "challengeId": "<GUID>",
  "requestBinding": "<base64 signature>",
  "deviceId": "<Entra device ID>",
  "clientReportedName": "CN=device.contoso.com"
}
```

Answering `200`:

```json
{ "certificate": "<PEM>", "subject": "CN=...", "attestationSource": "entra" }
```

`requestBinding` is an RSA PKCS#1 v1.5 SHA-256 signature, by the device registration key, over a
byte string built from these fields, each written with its length as a little-endian `uint32` in
front of it so no two different sets of values can produce the same bytes:

| Order | Field |
|---|---|
| 1 | the ASCII context string `EZCA-DEVICE-ENROLL-v1` |
| 2 | the Authorization scheme, `EntraDevice` |
| 3 | the absolute enrollment URL, as `Uri.AbsoluteUri` writes it |
| 4 | `challengeId` |
| 5 | the raw nonce, base64-decoded |
| 6 | `SHA256(csr DER)` |

The URL names the tenant, the CA and the profile, so a signature made for one of them can't be
presented to another, and the challenge is spent on its first use, so a captured request can't be
replayed. `deviceId` is only checked against the certificate and `clientReportedName` is only
logged; the identity comes from the certificate.

Refusals come back as `{ "error": "<kind>", "message": "Error [E....]: ..." }`:

| Status | Meaning | What the client does |
|---|---|---|
| `401` | EZCA didn't accept the device's registration (another tenant's, not its current one, or the signature didn't verify) | Fails, pointing at `dsregcmd /status` |
| `403` | The device proved who it is but may not enroll (disabled, not in an allowed group, or a registered rather than joined device) | Fails |
| `404` | The CA or profile doesn't offer device enrollment | Fails, pointing at the portal's URL |
| `429` | EZCA is receiving too many requests, or Entra ID didn't vouch for this device a few minutes ago | Tries again with a new challenge, up to 3 attempts, waiting for `Retry-After` or a minute per attempt (at most 5 minutes) |
| `503` | EZCA couldn't check the device with Entra ID just now | Fails; the next scheduled run tries again. EZCA turns the device away for a few minutes after this, so retrying sooner would only get a `429` |

### Key storage

On Windows, `enroll` creates the key in the TPM (`Microsoft Platform Crypto Provider`) and it is not
exportable, so the certificate cannot be copied off the machine it was issued to. Two things change
that:

- Most TPMs cannot create a 4096 bit RSA key. `enroll` therefore defaults to 2048. If a TPM refuses
  the requested size the client logs a warning and falls back to a software key of that size rather
  than silently shortening the key.
- A `--Path` ending in `.pfx` or `.p12` needs an exportable key, so it turns TPM storage off.

`SCEPCertificate` keeps its existing default of `Microsoft Enhanced Cryptographic Provider v1.0`,
because changing the provider under a command that is already deployed would change the kind of key
container every existing caller gets. To put a SCEP key in the TPM, ask for it, and lower the key
length, since the default 4096 is more than a TPM will do:

```powershell
.\EZCACertManager.exe SCEPCertificate --LocalStore -k 2048 --KeyProvider "Microsoft Platform Crypto Provider" ...
```

A provider you name is used or the command fails; only the default falls back. For
`SCEPCertificate` on Linux and macOS the key is created by BouncyCastle and the provider name is
ignored.

### Deploying it

The Windows release includes `EZCACertManager.msi`, which installs the client to
`C:\Program Files\Keytos\EZCACertManager\` and registers a scheduled task that runs `enroll` as
SYSTEM at startup and daily. Deploy it per device as a line-of-business app through Intune, or
install it silently:

```powershell
msiexec /i EZCACertManager.msi /qn ENROLLURL="https://portal.ezca.io/api/enroll/device/<tenant>/<ca>/<profile>"
```

`ENROLLURL` is written to the configuration file before the first enrollment is attempted, so a
device that was offline during the install, or hadn't finished joining Entra, still enrolls when
the scheduled task next runs. The
install directory is fixed, because a scheduled task definition is not formatted by Windows
Installer and so has to name the executable by path.

### How a run knows whether there is anything to do

`enroll` records the thumbprint of the certificate it installed in the same configuration file and
looks for that thumbprint on the next run. It does not search by subject, because EZCA and not the
client chooses the subject: a name search would both match certificates this command never issued
(reporting success without enrolling) and miss the one it did (enrolling again every day). The
thumbprint is written whether or not `--SaveConfig` was passed, since it is state rather than
configuration.

### Protecting the configuration

The machine-wide configuration decides which endpoint an unattended SYSTEM run enrols against, so
the client refuses to read one that an account without administrative rights could have written.
It checks the file and every directory between it and the shared data root, for both permissions
and ownership, and refuses to *write* into a directory chain that would fail that check rather
than reporting success and failing on every later run.

Two things about this are worth knowing before a release:

- **Verify a silent install end to end, once, before any release.** Two things depend on install
  ordering and on behaviour of the WiX util extension that cannot be proved from this repository,
  and both fail silently because the enrollment custom action returns `ignore`:

  ```powershell
  msiexec /i EZCACertManager.msi /qn ENROLLURL="https://portal.ezca.io/api/enroll/device/<tenant>/<ca>/<profile>"
  icacls "C:\ProgramData\Keytos"
  Test-Path "C:\ProgramData\Keytos\EZCACertManager\enrollment.json"
  ```

  `icacls` must show no `BUILTIN\Users` entry granting `(WD,AD)` and no entries marked `(I)` — the
  directories must carry a *protected* DACL, because `%ProgramData%` grants `Users` write through
  a container-inherited ACE and the client refuses to write into a chain in that state.
  `Test-Path` must return `True`: the client writes the configuration during the install, and it
  has to run after the extension applies those permissions. If the file is missing, the scheduled
  task has no URL and the device never enrols, on every device in the fleet.

### Known limitation

A renewed device certificate is added to the store next to the one it replaces; superseded
certificates are not deleted. Windows picks the one with the longest remaining validity for EAP-TLS,
so this is cosmetic, but a long lived machine accumulates expired certificates in its store.

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
If you want to contribute or customize the application, you can clone the repository and build it using .NET 10 SDK. Make sure to have the necessary dependencies installed and follow the Keytos code best practices for contributions. 

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


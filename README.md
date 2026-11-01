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

## Device enrollment for domain joined and Entra joined machines (`enroll`)

`enroll` asks EZCA for a device certificate and proves which machine is asking with a credential the
machine already holds, so nothing secret has to be distributed to get a machine its first
certificate.

```powershell
.\EZCACertManager.exe enroll --Url "https://portal.ezca.io/api/enroll/device/<subscription>/<ca>" --SaveConfig
```

With `--SaveConfig` the URL is written to a machine wide configuration file, and later runs need no
arguments at all:

```powershell
.\EZCACertManager.exe enroll
```

That matters for Group Policy. A Group Policy Preferences scheduled task stores its whole command
line in SYSVOL, which every authenticated user in the domain can read, so the less the command line
carries the better. The configuration file lives in `%ProgramData%\Keytos\EZCACertManager\` on
Windows, `/etc/keytos/ezcacertmanager/` on Linux and `/Library/Application Support/Keytos/EZCACertManager/`
on macOS.

### How the machine proves who it is

| `--Mode` | Credential | Needs |
| --- | --- | --- |
| `Kerberos` | A Kerberos service ticket for the EZCA enrollment SPN | The machine is joined to Active Directory and can reach a domain controller |
| `Entra` | A signature from the key behind the Entra device registration certificate | The machine is Entra joined or hybrid joined (Windows only) |
| `Auto` (default) | Kerberos first, then Entra | — |

Auto prefers Kerberos because every hybrid joined machine is also domain joined, and the Kerberos
identity carries the machine SID.

`enroll` is also the renewal path: it checks the certificate it already has and does nothing unless
that certificate is within `--RenewalPercentage` of expiry. Renewing therefore re-proves the
machine's identity, so a computer account that has been disabled or deleted stops getting
certificates rather than renewing on the strength of the certificate it already has. Run it from a
scheduled task at startup and daily.

### What the enrollment endpoint has to implement

The client talks to two endpoints. `<url>` is the value of `--Url`.

`GET <url>/challenge`

```json
{ "challengeId": "01HQ...", "nonce": "<base64>" }
```

`POST <url>` with `Authorization: Negotiate <base64 token>` for Kerberos, or
`Authorization: EntraDevice <base64 utf8 device id>` for Entra, and body:

> The Kerberos token is a **raw GSS-API Kerberos AP-REQ** (mech OID `1.2.840.113554.1.2.2`), not a
> SPNEGO-wrapped one, even though it travels under the `Negotiate` scheme. The client asks for the
> Kerberos package by name rather than Negotiate so that it can never fall back to NTLM, which
> would carry no PAC and so no verifiable machine identity. SSPI and GSSAPI acceptors take both
> forms; a strict SPNEGO-only decoder will not.

```json
{
  "csr": "<PEM certificate request>",
  "challengeId": "01HQ...",
  "requestBinding": "<base64>",
  "deviceId": "<Entra device id, Entra mode only>",
  "clientReportedName": "CN=machine.contoso.com"
}
```

Answering `200`:

```json
{ "certificate": "<PEM>", "subject": "CN=machine.contoso.com", "attestationSource": "kerberos" }
```

`requestBinding` is what ties one attestation to one certificate request. It is computed over a
byte string built from these fields, each written with its length as a little-endian `uint32` in
front of it so no two different sets of values can produce the same bytes:

| Order | Field |
|---|---|
| 1 | the ASCII context string `EZCA-DEVICE-ENROLL-v1` |
| 2 | the Authorization scheme (`Negotiate` or `EntraDevice`) |
| 3 | the absolute enrollment URL |
| 4 | `challengeId` |
| 5 | the raw nonce, base64-decoded |
| 6 | `SHA256(csr DER)` |

- **Kerberos** — the GSS integrity check (MIC) over those bytes under the Kerberos session key. The
  server derives the same key when it accepts the AP-REQ, so a captured `Authorization` header
  cannot be redeemed with a different key.
- **Entra** — an RSA PKCS#1 v1.5 SHA-256 signature over those bytes by the device registration key,
  verified against the public key Entra holds for that device object.

> **The Entra attestation is specified here but not implemented server-side.** The client can
> produce it; EZCA cannot yet check it. Two things are known about finishing it, and one is not:
>
> - **Entra does not hand back the device's public key.** The device object's
>   `alternativeSecurityIds` holds `X509:<SHA1-TP-PUBKEY>[thumbprint]+[publickeyhash]` — a SHA-1
>   thumbprint and a base64 SHA-256 hash — so there is nothing to verify a signature against
>   unless the request carries the key itself. The fix is on this side: the client must send its
>   whole `MS-Organization-Access` certificate, DER encoded, alongside the signature. The server
>   then matches SHA-1 over the certificate against the thumbprint, which is unambiguous, and
>   checks the key hash as a second test. Sending only the public key would not do: MS-DVRE
>   describes the hashed value as "the X.509 certificate public key", which reads as either the
>   SubjectPublicKeyInfo DER or the raw `subjectPublicKey` bits, and nothing settles which.
>   The attribute is multi-valued for key rollover, so any entry may match, and Microsoft
>   documents it as "for internal use only".
> - **What such a certificate could assert is an open design question, not a detail.** This
>   feature exists for KB5014754 strong mapping, and what makes the certificate worth issuing is
>   the machine SID. A cloud-only Entra joined device has no Active Directory SID to carry.
>   Hybrid joined devices do — and they are domain joined, so the Kerberos path already covers
>   them. The population an Entra path would uniquely serve is therefore the one for which this
>   feature's premise does not hold. Deciding what an Entra-only device certificate asserts, and
>   whether the RADIUS side will accept it, comes before building any of the above.
> - **Unproven:** that the `MS-Organization-Access` certificate's public key is the key whose hash
>   `alternativeSecurityIds` holds. It should be — that is the registration key — but it is an
>   inference. One test against a real Entra joined device settles it and the encoding question
>   together.

The scheme and the URL are in there so a binding made for one kind of attestation, or for one CA,
cannot be presented as another. The URL is the absolute URL **the client was configured with**, so
the server must verify against its own configured canonical enrollment URL and not against the URL
it observes on the request: behind a TLS-terminating proxy the request arrives with a different
scheme, host or port, and comparing against that would fail every verification with nothing to
diagnose from. Nothing outside this list may influence issuance: in particular the
EKUs come from the CSR's own extension request, which the hash covers, and not from a separate
field in the body, which nothing signs.

Two rules the server side has to keep, because the client deliberately does not:

1. **The subject and SANs of the issued certificate come from the attested identity, never from the
   CSR.** `clientReportedName` is for diagnostics. The CSR is read for its public key and its
   requested EKUs.
   **Carry the SID twice.** Put it in the `tag:microsoft.com,2022-09-14:sid:<sid>` URI SAN *and*
   in the `1.3.6.1.4.1.311.25.2` extension. A domain controller enforcing KB5014754 reads the
   extension, which is what the SCEP certificates this replaces already carry; the URI SAN is what
   Entra certificate-based authentication and Intune-issued certificates use. Only the issuing CA
   can assert either, so neither comes from the request.
2. **Burn the challenge on first use** and reject an expired one.
3. **Key the Kerberos replay cache only on authenticated fields.** A ticket's service name and
   realm travel outside its encrypted part (RFC 4120 §5.3), so a caller can rewrite them. A replay
   cache keyed on anything taken from there — the service name, for instance — can be stepped past
   by replaying the same AP-REQ with one letter's case changed. Key it on what the decrypted
   authenticator and ticket actually attest to.
4. **Refuse a ticket that carries delegation information.** A service trusted for constrained
   delegation can obtain a ticket to the enrollment account *in another machine's name*, and it
   holds the session key, so it can produce a request binding that verifies. Every other check
   passes and it enrols a certificate for a machine it does not own. The PAC says when a ticket
   arrived this way; reject it.
5. **Do not let the policy allow the Any or KDC Authentication EKUs.** A device enrollment policy
   that permits them lets a machine ask for a certificate that stands in for a domain controller.
   The requested EKUs come from the CSR, which the binding covers, so the only place to stop this
   is the policy.

The URL the server verifies (field 3 of the binding) is configuration, not something read off the
request — see above. It has to be byte-identical to the URL the machines are given, so whoever
configures the endpoint should set both. A mismatch fails every binding and reports it as a `401`,
which reads as the machine's credential being rejected rather than as a server misconfiguration.

The client reports `401` and `403` differently, so return `401` when the credential itself was not
accepted and `403` when the machine authenticated but is not allowed to enroll.

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

A provider you name is used or the command fails; only the default falls back. On Linux and macOS
the key is created by BouncyCastle and the provider name is ignored.

### Deploying it with Group Policy

The Windows release includes `EZCACertManager.msi`, which installs the client to
`C:\Program Files\Keytos\EZCACertManager\` and registers a scheduled task that runs `enroll` as
SYSTEM at startup and daily. Deploy it per machine through Group Policy software installation, or
install it silently:

```powershell
msiexec /i EZCACertManager.msi /qn ENROLLURL="https://portal.ezca.io/api/enroll/device/<subscription>/<ca>"
```

`ENROLLURL` is written to the configuration file before the first enrollment is attempted, so a
machine that was offline during the install still enrolls when the scheduled task next runs. The
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
  msiexec /i EZCACertManager.msi /qn ENROLLURL="https://portal.ezca.io/api/enroll/device/<sub>/<ca>"
  icacls "C:\ProgramData\Keytos"
  Test-Path "C:\ProgramData\Keytos\EZCACertManager\enrollment.json"
  ```

  `icacls` must show no `BUILTIN\Users` entry granting `(WD,AD)` and no entries marked `(I)` — the
  directories must carry a *protected* DACL, because `%ProgramData%` grants `Users` write through
  a container-inherited ACE and the client refuses to write into a chain in that state.
  `Test-Path` must return `True`: the client writes the configuration during the install, and it
  has to run after the extension applies those permissions. If the file is missing, the scheduled
  task has no URL and the machine never enrols, on every machine in the fleet.
- **The Linux and macOS check does not look at ownership.** It refuses a group- or world-writable
  file or directory, which is all the platform APIs available here expose. On Linux the shared
  root is `/etc`, which only root can write, so the gap is unreachable. On macOS
  `/Library/Application Support` is group-writable by `admin`, so a member of that group can
  create the directory chain and own it, and this check will accept it. The installer and the
  scheduled task target Windows, so no shipped unattended path is affected.

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


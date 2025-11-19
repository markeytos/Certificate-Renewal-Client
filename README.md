# Certificate Renewal Client

At Keytos, our goal is to make EZCA, our [cloud PKI service](https://www.keytos.io/azure-pki), easy-to-use for every person in the world. One way to make this a reality is by removing humans as much as possible from the equation. To help companies achieve this goal, we have created a sample C# console application for Windows that can:

- [Register a new domain in EZCA](#register-a-new-domain-in-ezca)
- [Create a new certificate](#create-a-new-certificate)
- [Renew an existing certificate](#renew-an-existing-certificate)
- [Create a Domain Controller Certificate](#create-a-domain-controller-certificate)
- [Create SCEP Certificates for Non-Managed Windows Devices](#create-scep-certificates-for-non-managed-windows-devices)

This application can be used in combination with Windows Task Scheduler to automatically renew certificates before they expire, ensuring that your systems remain secure and compliant without manual intervention.

## Download Signed Binary

https://download.keytos.io/Downloads/CertificateManager/EZCACertManager.exe 

## Commands

The application supports the following commands:

### Register a new domain in EZCA

This will use a [DefaultAzureCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet) to authenticate to EZCA and register the domain

> **NOTE: the identity must be a human identity, MSI or Application will fail since applications cannot be domain owners**.

> **WARNING: This command should only be called once, after the domain is registered in EZCA this command will fail.**

```powershell
EZCACertManager.exe register --help

  -d, --Domain          Required. Domain for the certificate you want to create

  --AppInsights         Azure Application Insights connection string to send logs to

  -e, --EZCAInstance    (Default: https://portal.ezca.io/) EZCA instance url

  --caid                Required. CA ID of the CA you want to request the certificate from

  --help                Display this help screen.

  --version             Display version information.
```

Sample call:

```powershell
.\EZCACertManager.exe register -d MYDOMAIN.LOCAL -caid "MY CAID From EZCA Certificate Authority Details"
```

### Create a new certificate

If your domain is already registered in EZCA (either by calling the register function mentioned above, or by [registering a domain in the EZCA portal](https://docs.keytos.io/azure-pki/registering-a-domain/registering_new_domain/)), you should use the ```create``` option. This option will use a [DefaultAzureCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet) to authenticate to EZCA and request a certificate. Please ensure that the identity being used to authenticate is registered as a requester for this domain. **Note: unlike with register this can be run by machine identities**

```powershell
EZCACertManager.exe create --help

  -r, --RDP             (Default: false) whether this certificate should be added as the computer's RDP certificate

  -d, --Domain          Domain for the certificate you want to create

  --AppInsights         Azure Application Insights connection string to send logs to

  -e, --EZCAInstance    (Default: https://portal.ezca.io/) EZCA instance url

  --caid                Required. CA ID of the CA you want to request the certificate from

  --LocalStore          (Default: false) If the certificate should be stored in the computers Local Store. If false
                        certificate will be stored in the user store

  -v, --Validity        Required. Certificate validity in days

  --AzTenantID          Optional If you want to authenticate with an Azure application you must pass you Azure TenantID,
                        the Application ID and the Application Secret

  --AzAppID             Optional If you want to authenticate with an Azure application you must pass you Azure TenantID,
                        the Application ID and the Application Secret

  --AzAppSecret         Optional If you want to authenticate with an Azure application you must pass you Azure TenantID,
                        the Application ID and the Application Secret

  -k, --KeyLength       (Default: 4096) Certificate Key Length

  -p, --KeyProvider     (Default: Microsoft Enhanced Cryptographic Provider v1.0) Certificate Key Provider (Default:
                        Microsoft Enhanced Cryptographic Provider v1.0)

  --help                Display this help screen.

  --version             Display version information.
```

Sample call:

```powershell
.\EZCACertManager.exe create -d MYDOMAIN.LOCAL --caid "MY CAID From EZCA Certificate Authority Details" -v 30
```

If you want to use this certificate for RDP we must add `--LocalStore -r` to the command:

```powershell
.\EZCACertManager.exe create -d MYDOMAIN.LOCAL --caid "MY CAID From EZCA Certificate Authority Details" -v 30 --LocalStore -r
```

### Renew an existing certificate

Once a certificate has been created and is in your Windows store, we recommend setting a scheduled task running this binary with the renew function to automatically renew your certificate. This uses the existing certificate to authenticate so no need for an AAD identity. For this one the only required option is the ```-d``` with the subject name of the certificate, the console application will use that information to get the certificate from the store you specify and renew it in EZCA.

```powershell
EZCACertManager.exe renew --help

  -r, --RDP             (Default: false) whether this certificate should be added as the computer's RDP certificate

  -s, --SubjectName     Required. SubjectName for the certificate you want to renew

  --AppInsights         Azure Application Insights connection string to send logs to

  -e, --EZCAInstance    (Default: https://portal.ezca.io/) EZCA instance url

  --LocalStore          (Default: false) If the certificate should be stored in the computers Local Store. If false
                        certificate will be stored in the user store

  -t, --Template        (Default: ) Certificate Template Name

  -i, --Issuer          (Default: ) Certificate Issuer Name

  -k, --KeyLength       (Default: 4096) Certificate Key Length

  -p, --KeyProvider     (Default: Microsoft Enhanced Cryptographic Provider v1.0) Certificate Key Provider (Default:
                        Microsoft Enhanced Cryptographic Provider v1.0)

  --help                Display this help screen.

  --version             Display version information.
```

Sample call:

```powershell
.\EZCACertManager.exe renew -s mydomain.com
```

Same as the other commands, if you want to serve this certificate when a computer tries to RDP to this endpoint, we must add `--LocalStore -r`:

```powershell
.\EZCACertManager.exe renew -s mydomain.com --LocalStore -r
```

### Create a Domain Controller Certificate

If you are trying to go passwordless with [hello for business hybrid key trust deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-hybrid-key-trust), you can use this application to [request the domain controller certificate](https://docs.keytos.io/azure-pki/intune-certificate-authority/domain-controller-certificates-for-windows-hello-hybrid/#using-the-application).
The following options are available for this command:

```powershell
EZCACertManager.exe createDC --help

 -d, --DNS             DNS Entry for this Domain Controller

  -s, --SubjectName     Subject Name for this certificate for example: CN=server1.contoso.com OU=Domain Controllers
                        DC=contoso DC=com

  --caid                Required. CA ID of the CA you want to request the certificate from

  --TemplateID          Required. Template ID of the template you want to request the certificate from (Note: Only SCEP
                        templates are supported)

  -v, --Validity        Required. Certificate validity in days

  -g, --DCGUID          Domain Controller GUID. This is only required if SMTP replication is used in your domain. Learn
                        more: https://learn.microsoft.com/en-US/troubleshoot/windows-server/windows-security/requirements-doma
                        in-controller#how-to-determine-the-domain-controller-guid

  --AppInsights         Azure Application Insights connection string to send logs to

  -e, --EZCAInstance    (Default: https://portal.ezca.io/) EZCA instance url

  --EKUs                (Default: 1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.2.3.5) EKUs
                        requested for the certificate

  --AzureCLI            (Default: false) Use Azure CLI as authentication method

  -k, --KeyLength       (Default: 4096) Certificate Key Length

  -p, --KeyProvider     (Default: Microsoft Enhanced Cryptographic Provider v1.0) Certificate Key Provider (Default:
                        Microsoft Enhanced Cryptographic Provider v1.0)

  --SubjectAltNames     A comma-separate list of additional Subject Alternate Names to be added to this certificate,
                        in addition to the Domain name. When not specified, only the Domain name is added as a SAN.
                        For example: server1.contoso.com,server2.contoso.com

  --help                Display this help screen.

  --version             Display version information.
```

Sample command:

```powershell
.\EZCACertManager.exe createDC  -s \"CN=server1.contoso.com OU=Domain Controllers, DC=contoso DC=com\" -d your.fqdn --caid yourCAIDFromThePortal --TemplateID YourTemplateIDFromThePortal -v 20
```


### Create SCEP Certificates for Non-Managed Windows Devices

If you are migrating to the cloud but not all of your devices are cloud managed or MDM managed, you can use this client to request certificates from EZCA using static SCEP for those devices. To Request a Static SCEP certificate, you will need your Static SCEP URL from EZCA, and the Static Challenge, you can find this information in the EZCA portal under the Certificate Authority details.
![How To Enable Static SCEP](https://github.com/user-attachments/assets/671f54bc-0669-40ab-a1e0-977fce493d22)

```powershell
EZCACertManager.exe SCEPCertificate --help

   --LocalStore          (Default: true) If the certificate should be stored in the computers Local Store. If false
                        certificate will be stored in the user store

  --EKUs                (Default: 1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1) EKUs requested for the certificate

  -k, --KeyLength       (Default: 4096) Certificate Key Length

  --AppInsights         Azure Application Insights connection string to send logs to

  -u, --URL             Required. SCEP URL from your EZCA CA

  -s, --SubjectName     Subject Name for this certificate for example: CN=server1.contoso.com OU=Domain Controllers
                        DC=contoso DC=com (If left empty it will use the computer name in your domain)

  -p, --SCEPPassword    Required. SCEP Password for Static Challenge

  --SubjectAltNames     Subject Alternate Names for this certificate for example (comma separate multiple):
                        server1.constoso.com,server2.contoso.com (If left empty it will use the computer name in your domain)
```

Sample call:

```powershell
.\EZCACertManager.exe SCEPCertificate  -u https://portal.ezca.io/api/SCEP/Static/1c3c6cea-fcbd-4681-85e1-74fb74b6863e/d2e20719-090c-40c9-88a0-d1955ed74f73/eastus/cgi-bin -s "CN=server3.contoso.com" -p YOURPASSWORD  --SubjectAltNames machine.contoso.com,machine2.contoso.com 
```


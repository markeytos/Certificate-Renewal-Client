# Certificate Renewal Client
In Keytos our goal is to make our [PKI services](https://www.keytos.io/AZURE-PKI.html) as easy to use for every person in the world. One way to make this a reality is by removing humans as much as possible from the equation. To help companies achieve this goal, we have created a sample C# console application for Windows that can:

## Register a new domain in EZCA
This will use a [DefaultAzureCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet) to authenticate to EZCA and register the domain **Note: the identity must be a human identity, MSI or Application will fail since applications cannot be domain owners**.
**WARNING: This command should only be called once, after the domain is registered in EZCA this command will fail.**
```
  -d, --Domain          Required. Domain for the certificate you want to create

  --AppInsights         Azure Application Insights connection string to send logs to

  -e, --EZCAInstance    (Default: https://portal.ezca.io/) EZCA instance url

  --caid                Required. CA ID of the CA you want to request the certificate from

  --help                Display this help screen.

  --version             Display version information.
```
Sample call:
```.\EZCACertManager.exe register -d MYDOMAIN.LOCAL -caid "MY CAID From EZCA Certificate Authority Details" ```

## Create a new certificate

If your domain is already registered in EZCA (either by calling the register function mentioned above, or by [registering a domain in the EZCA portal](https://docs.keytos.io/azure-pki/registering-a-domain/registering_new_domain/)), you should use the ```create``` option. This option will use a [DefaultAzureCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet) to authenticate to EZCA and request a certificate. Please ensure that the identity being used to authenticate is registered as a requester for this domain. **Note: unlike with register this can be run by machine identities**
```
-r, --RDP             (Default: false) whether this certificate should be added as the computer's RDP certificate

  -d, --Domain          Required. Domain for the certificate you want to create

  --AppInsights         Azure Application Insights connection string to send logs to

  -e, --EZCAInstance    (Default: https://portal.ezca.io/) EZCA instance url

  --caid                Required. CA ID of the CA you want to request the certificate from

  --LocalStore          (Default: false) If the certificate should be stored in the computers Local Store. If false certificate will be stored in the user store

  -v, --Validity        Required. Certificate validity in days

  --AzTenantID          Optional If you want to authenticate with an Azure application you must pass you Azure TenantID, the Application ID and the Application Secret

  --AzAppID             Optional If you want to authenticate with an Azure application you must pass you Azure TenantID, the Application ID and the Application Secret

  --AzAppSecret         Optional If you want to authenticate with an Azure application you must pass you Azure TenantID, the Application ID and the Application Secret

  --help                Display this help screen.

  --version             Display version information.
```
Sample call:
```.\EZCACertManager.exe create -d MYDOMAIN.LOCAL -caid "MY CAID From EZCA Certificate Authority Details" -v 30```
Once again if you want to use this certificate for RDP we must add ```--LocalStore -r```:
```.\EZCACertManager.exe create -d MYDOMAIN.LOCAL -caid "MY CAID From EZCA Certificate Authority Details" -v 30 --LocalStore -r```
## Create a Domain Controller Certificate
If you are trying to go passwordless with [hello for business hybrid key trust deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-hybrid-key-trust), you can use this application to [request the domain controller certificate](https://docs.keytos.io/azure-pki/intune-certificate-authority/domain-controller-certificates-for-windows-hello-hybrid/#using-the-application).
The following options are available for this command:
```
   -d, --DNS             Required. DNS Entry for this Domain Controller

  -s, --SubjectName     Required. Subject Name for this certificate for example: CN=server1.contoso.com OU=Domain
                        Controllers DC=contoso DC=com

  --caid                Required. CA ID of the CA you want to request the certificate from

  --TemplateID          Required. Template ID of the template you want to request the certificate from (Note: Only SCEP
                        templates are supported)

  -v, --Validity        Required. Certificate validity in days

  -g, --DCGUID          Domain Controller GUID. This is only required if SMTP replication is used in your domain. Learn
                        more:
                        https://learn.microsoft.com/en-US/troubleshoot/windows-server/windows-security/requirements-doma                        in-controller#how-to-determine-the-domain-controller-guid

  --AppInsights         Azure Application Insights connection string to send logs to

  -e, --EZCAInstance    (Default: https://portal.ezca.io/) EZCA instance url

  --EKUs                (Default: 1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.2.3.5) EKUs
                        requested for the certificate

  --AzureCLI            (Default: false) Use Azure CLI as authentication method
```
sample command:
``` 
.\EZCACertManager.exe createDC  -s \"CN=server1.contoso.com OU=Domain Controllers, DC=contoso DC=com\" -d your.fqdn --caid yourCAIDFromThePortal --TemplateID YourTemplateIDFromThePortal -v 20
```

## Renew an existing certificate
Once a certificate has been created and is in your Windows store, we recommend setting a scheduled task running this binary with the renew function to automatically renew your certificate. This uses the existing certificate to authenticate so no need for an AAD identity. For this one the only required option is the ```-d``` with the subject name of the certificate, the console application will use that information to get the certificate from the store you specify and renew it in EZCA.
```
 -r, --RDP             (Default: false) whether this certificate should be added as the computer's RDP certificate

  -d, --Domain          Required. Domain for the certificate you want to create

  --AppInsights         Azure Application Insights connection string to send logs to

  -e, --EZCAInstance    (Default: https://portal.ezca.io/) EZCA instance url

  --LocalStore          (Default: false) If the certificate should be stored in the computers Local Store. If false certificate will be stored in the user store

  --help                Display this help screen.

  --version             Display version information.
```
Sample call:
```.\EZCACertManager.exe renew -d mydomain.com```
Same as the other commands, if you want to serve this certificate when a computer tries to RDP to this endpoint, we must add ```--LocalStore -r```:
```.\EZCACertManager.exe renew -d mydomain.com --LocalStore -r```

## Download Signed Binary 
https://www.keytos.io/Downloads/CertificateManager/EZCACertManager.exe 
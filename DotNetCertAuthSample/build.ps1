param (
    [string] $signingCertName = "globalsign",
    [string] $signingAKV = "https://codesigningkeytos.vault.azure.net/",
    [string] $version = "1.0.0"
)

$ErrorActionPreference = "Stop"

$rids = @("win-x64", "win-arm64")

$akvToken = az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

foreach ($rid in $rids) {
    msbuild .\DotNetCertAuthSample\DotNetCertAuthSample\DotNetCertAuthSample.csproj /restore /t:publish /p:Configuration=Release /p:SelfContained=True /p:RuntimeIdentifier=$rid /p:PublishSingleFile=true /p:TargetFramework=net10.0-windows /p:Version=$version
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    azuresigntool sign --azure-key-vault-url $signingAKV -kvc $signingCertName --azure-key-vault-accesstoken $akvToken -tr http://timestamp.digicert.com .\DotNetCertAuthSample\DotNetCertAuthSample\bin\Release\net10.0-windows\$rid\publish\*.exe
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    # The MSI wraps the signed executable, so it is built after signing and signed itself. It is
    # what Group Policy software installation deploys, instead of every workstation downloading the
    # executable from github.com at boot.
    $publishDir = Resolve-Path ".\DotNetCertAuthSample\DotNetCertAuthSample\bin\Release\net10.0-windows\$rid\publish"
    $msiArch = if ($rid -eq "win-arm64") { "arm64" } else { "x64" }
    $msiPath = Join-Path $publishDir "EZCACertManager.msi"
    wix build .\DotNetCertAuthSample\Installer\EZCACertManager.wxs `
        -arch $msiArch `
        -ext WixToolset.Util.wixext `
        -d Version=$version `
        -d ClientExe=(Join-Path $publishDir "EZCACertManager.exe") `
        -d TaskXml=(Resolve-Path ".\DotNetCertAuthSample\Installer\EnrollmentTask.xml") `
        -o $msiPath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    azuresigntool sign --azure-key-vault-url $signingAKV -kvc $signingCertName --azure-key-vault-accesstoken $akvToken -tr http://timestamp.digicert.com $msiPath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

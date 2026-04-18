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
}

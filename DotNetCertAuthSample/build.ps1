param (
    [string] $signingCertName = "globalsign",
    [string] $signingAKV = "https://codesigningkeytos.vault.azure.net/",
    [string] $version = "1.0.0"
)

$rids = @("win-x64", "win-arm64")

$akvToken = az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv

foreach ($rid in $rids) {
    msbuild .\DotNetCertAuthSample\DotNetCertAuthSample\DotNetCertAuthSample.csproj /restore /t:publish /p:Configuration=Release /p:SelfContained=True /p:RuntimeIdentifier=$rid /p:PublishSingleFile=true /p:TargetFramework=net10.0-windows /p:Version=$version
    azuresigntool sign --azure-key-vault-url $signingAKV -kvc $signingCertName --azure-key-vault-accesstoken $akvToken -tr http://timestamp.digicert.com .\DotNetCertAuthSample\DotNetCertAuthSample\bin\Release\net10.0-windows\$rid\publish\*.exe
}

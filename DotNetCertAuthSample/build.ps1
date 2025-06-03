param (
    [string] $signingCertName = "globalsign",
    [string] $signingAKV = "https://codesigningkeytos.vault.azure.net/"
)

msbuild .\DotNetCertAuthSample\DotNetCertAuthSample\DotNetCertAuthSample.csproj /restore /t:publish  /p:Configuration=Release /p:SelfContained=True  /p:RuntimeIdentifier=win-x64 /p:PublishSingleFile=true
$akvToken = (az account get-access-token  --resource https://vault.azure.net --query "accessToken").Replace('"','')
azuresigntool sign --azure-key-vault-url $signingAKV -kvc $signingCertName --azure-key-vault-accesstoken $akvToken -tr http://timestamp.digicert.com .\DotNetCertAuthSample\bin\Release\net8.0-windows\win-x64\publish\*.exe

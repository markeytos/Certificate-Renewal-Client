$env:Path += ";C:\Program Files\Microsoft Visual Studio\2022\Preview\Msbuild\Current\Bin" 
$env:Path += ";C:\Program Files (x86)\Windows Kits\10\App Certification Kit"
msbuild /restore /t:publish  /p:Configuration=Release /p:SelfContained=True  /p:RuntimeIdentifier=win-x64 /p:PublishSingleFile=true
SignTool sign /fd SHA256 /a /t http://timestamp.digicert.com  /n "Keytos LLC" .\DotNetCertAuthSample\bin\Release\net7.0-windows\win-x64\publish\*.exe
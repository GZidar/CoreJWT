@echo off
set config=Release
set platform=AnyCPU
set warnings=1591,1572,1573,1570,1000,1587

set buildargs=/p:Configuration="%config%" /p:Platform="%platform%" /p:NoWarn="%warnings%" /v:minimal 
set buildargsTests=/p:Configuration="Debug" /p:Platform="%platform%" /p:NoWarn="%warnings%" /v:minimal 

echo Building CoreJWT...

msbuild src/CoreJWT.csproj %buildargs%

echo Creating Nuget Packages...

nuget pack CoreJWT.nuspec

xcopy *.nupkg packages\*.* /Y
del *.nupkg

echo All done.
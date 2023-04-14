@echo off
REM
REM SETBUILD.CMD - Set the build environment for various compilers.
REM Written by Alan Klietz
REM
REM This script is for building and signing the software
REM package for public download at https://u-tools.com/msls
REM and is not likely to be helpful to you.
REM
if "%LOCALAPPDATA%"=="" ( set VC8Settings=%USERPROFILE%\Local Settings\Application Data\Microsoft\VisualStudio\8.0\
set VC9Settings=%USERPROFILE%\Local Settings\Application Data\Microsoft\VisualStudio\9.0\
set VC10Settings=%USERPROFILE%\Local Settings\Application Data\Microsoft\MSBuild\v4.0\
set VC12Settings=%USERPROFILE%\Local Settings\Application Data\Microsoft\MSBuild\v4.0\
set VC14Settings=%USERPROFILE%\Local Settings\Application Data\Microsoft\MSBuild\v4.0\
set VC141Settings=%USERPROFILE%\Local Settings\Application Data\Microsoft\MSBuild\v4.0\
) else ( set VC8Settings=%LOCALAPPDATA%\Microsoft\VisualStudio\8.0\
set VC9Settings=%LOCALAPPDATA%\Microsoft\VisualStudio\9.0\
set VC10Settings=%LOCALAPPDATA%\Microsoft\MSBuild\v4.0\
set VC12Settings=%LOCALAPPDATA%\Microsoft\MSBuild\v4.0\
set VC14Settings=%LOCALAPPDATA%\Microsoft\MSBuild\v4.0\
set VC141Settings=%LOCALAPPDATA%\Microsoft\MSBuild\v4.0\
Rem Note: VC14 has strongly deprecated per-user project sheets.  See
Rem the Help topic 'Working with Project Properties' in Help 2.3.
)

set DevDrive=E:& set VS6=E:\DevStudio
if /i "%COMPUTERNAME%"=="HUMMER64" set DevDrive=H:& set VS6=G:\DevStudio
if /i "%COMPUTERNAME%"=="QUAD" set DevDrive=H:& set VS6=G:\DevStudio
if /i "%COMPUTERNAME%"=="SNAP" set DevDrive=C:& set VS6=C:\DevStudio

rem Required for vc8-vc9 fallthru
set VCSettings=%VC9Settings%

set HomeVC8Settings=E:\home\alan\doc\Visual Studio 2005\Settings\
set HomeVC9Settings=E:\home\alan\doc\Visual Studio 2008\Settings\
set HomeVC10Settings=E:\home\alan\doc\Visual Studio 2010\Settings\
set HomeVC12Settings=E:\home\alan\doc\Visual Studio 2013\Settings\
set HomeVC14Settings=E:\home\alan\doc\Visual Studio 2015\Settings\

rem Required for vc8-vc9 fallthru
set HomeVCSettings=%HomeVC9Settings%

rem Required for vc8-vc9 fallthru
set VCName=VS2008
set VCVersion=9.0
set VCLib=E:\ae\libvc96

set FrameworkVersion=v3.5
set FrameworkSDKDir=%DevDrive%\VS2008\SDK\v3.5\

if "%AE_UCRTVER%" == "" set AE_UCRTVER=10.0.20348.0 & echo Defaulting to AE_UCRTVER 10.0.20348.0
if "%AE_VCTOOLS%" == "" set AE_VCTOOLS=14.31.31103 & echo Defaulting to AE_VCTOOLS 14.31.31103

if not "%ProgramFiles(x86)%"=="" ( set REG32=%SystemRoot%\SysWOW64\reg.exe
) else ( set REG32=%SystemRoot%\System32\reg.exe
)

if "%~1"=="/silent" (
	shift /1
	set silent=yes
)
if "%~1"=="/force" (
	shift /1
	set force=yes
)
rem
if "%1"=="restore" goto restore
if "%1"=="%BUILDTOOL%" goto done
set BUILDTOOL=%1
rem
if not "%basepath%"=="" goto nosave
rem
rem Basepath is empty. Save the basepath for later restore
rem
set basepath=%PATH%
set baseinclude=%INCLUDE%
set baselib=%LIB%
:nosave
rem
set PATH=C:\Perl64\bin;%basepath%
set INCLUDE=%baseinclude%
set LIB=%baselib%
set VCVARS_ARE_SET=1
rem
if "%1"=="msvc16" goto m16
if "%1"=="vc6" goto vc6
if "%1"=="vc8" goto vc8
if "%1"=="vc9" goto vc9
if "%1"=="vc8x64" goto vc8x64
if "%1"=="vc9x64" goto vc9x64
if "%1"=="vc86" goto vc86
if "%1"=="vc96" goto vc96
if "%1"=="vc86x64" goto vc86x64
if "%1"=="vc96x64" goto vc96x64
if "%1"=="vc10" goto vc10
if "%1"=="vc10x64" goto vc10x64
if "%1"=="vc10net35" goto vc10net35
if "%1"=="vc10net35x64" goto vc10net35x64
if "%1"=="vc10net4" goto vc10net4
if "%1"=="vc10net4x64" goto vc10net4x64
if "%1"=="vc106x64" goto vc106x64
if "%1"=="vc12" goto vc12
if "%1"=="vc12x64" goto vc12x64
Rem Note: vc126x64 is no longer used
if "%1"=="vc126x64" goto vc126x64
if "%1"=="vc14" goto vc14
if "%1"=="vc14x64" goto vc14x64
if "%1"=="vc141" goto vc141
if "%1"=="vc141x64" goto vc141x64
if "%1"=="vc142" goto vc142
if "%1"=="vc142x64" goto vc142x64
if "%1"=="vc143" goto vc143
if "%1"=="vc143x64" goto vc143x64
echo Usage: setbuild [vc6,vc8,vc9,vc10,vc12,vc14,vc141,vc142,vc143,vc8x64,vc9x64,vc10x64,vc12x64,vc14x64,vc141x64,vc142x64,vc143x64,vc86,vc96,vc86x64,vc96x64,vc106x64,vc10net35,vc10net35x64,vc10net4,vc10net4x64,vc126x64,restore]
goto done
:restore
if "%basepath%"=="" goto norestore
rem
rem Restore the PATH from the basepath
rem
set BUILDTOOL=
set toolrootdir=
set PATH=%basepath%
set basepath=
set INCLUDE=%baseinclude%
set baseinclude=
set LIB=%baselib%
set baselib=
set AMD64=
rem
set Framework35Version=
set FrameworkDir=
set FrameworkDir32=
set FrameworkDir64=
set FrameworkVersion=
set FrameworkVersion64=
set FrameworkSDKDir=
set Platform=
set VSInstallDir=
set VCInstallDir=
set WindowsSdkDir=
set WindowsSdkDir06=
set DevEnvDir=
set LIBPATH=
set UCRTVersion=
set VS170COMNTOOLS=
set VCVARS_ARE_SET=
:norestore
goto done
:m16
set toolrootdir=E:\msvc16
set path=%toolrootdir%\bin;%path%
set include=%toolrootdir%\include;%toolrootdir%\mfc\include
set lib=%toolrootdir%\lib;%toolrootdir%\mfc\lib
if not "%silent%"=="yes" echo Environment variables set for 16-bit Visual C++.
goto done
rem --------------------------------------------------------------------------
:vc6
rem FrameworkXxx is required to use msbuild4 with vc6
rem BUG: MSBuild4 passes too many incompatible args via the CL task. Cant use it
set Framework35Version=v3.5
set FrameworkSDKDir=
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir32=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir64=
set WindowsSdkDir=%DevDrive%\MSSDK06\
set WindowsSdkDir06=
set DevEnvDir=
set Platform=
set AMD64=
set VSInstallDir=%VS6%\
set VCInstallDir=%VSInstallDir%VC98\
set PATH=%WindowsSdkDir%bin;%WindowsSdkDir%bin\winnt;%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%PATH%;%VSInstallDir%Common\MSDev98\Bin;%VSInstallDir%Common\Tools;%VCInstallDir%bin
set LIB=%WindowsSdkDir%lib;%DevDrive%\DDK\7100\lib\atl\i386;%VCInstallDir%mfc\lib;%VCInstallDir%lib;%LIB%;%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%
rem set LIB=%LIB%;E:\ae\libvc96;%DevDrive%\MSSDK09\lib;%FrameworkSDKDir%lib;%DevDrive%\DDK\7100\lib\atl\i386;%DevDrive%\DDK\7100\lib\mfc\i386;%DevDrive%\DDK\7100\lib\crt\i386;%DevDrive%\DDK\7100\lib\atl\i386
set LIBPATH=%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%
set INCLUDE=%WindowsSdkDir%include;%WindowsSdkDir%include\atl;%WindowsSdkDir%include\mfc;%WindowsSdkDir%include\crt;%INCLUDE%
rem set INCLUDE=%WindowsSdkDir%include;%INCLUDE%;%VCInstallDir%atl\include;%VCInstallDir%mfc\include;%VCInstallDir%include
set StudioDir=
rem
if not "%silent%"=="yes" echo Environment varibles set for Visual Studio 6.
goto done
rem --------------------------------------------------------------------------
:vc8
set VCSettings=%VC8Settings%
set HomeVCSettings=%HomeVC8Settings%
set VCName=VS2005
set VCVersion=8.0
set FrameworkVersion=v2.0.50727
set FrameworkSDKDir=%DevDrive%\VS2005\SDK\v2.0\
:vc9
set WindowsSdkDir=%DevDrive%\MSSDK09\
set VCLib=
set AMD64=
REM
REM Set the build environment for Visual Studio 200x (VC9), target 32-bit x86
REM
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
REM
REM Need path %FrameworkDir%%FrameworkVersion% for gac, caspol, ilasm, regasm
REM
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set PATH=%WindowsSdkDir%bin;%FrameworkSDKDir%Bin;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%VSInstallDir%Common7\IDE;%VCInstallDir%vcpackages;%FrameworkDir%%FrameworkVersion%;%PATH%
REM Use x64 versions of tools if running on x64
if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\X64;%PATH%
set LIB=%LIB%;%WindowsSdkDir%lib;%FrameworkSDKDir%lib;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib
set LIBPATH=%FrameworkDir%;%FrameworkDir%%FrameworkVersion%;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib
set INCLUDE=%INCLUDE%;%WindowsSdkDir%include;%FrameworkSDKDir%include;%VCInstallDir%include;%VCInstallDir%atlmfc\include
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%DevDrive%\%VCName%\VC\crt\src\;%DevDrive%\%VCName%\VC\atlmfc\src\mfc\;%DevDrive%\%VCName%\VC\atlmfc\src\atl\;%DevDrive%\%VCNAME%\VC\atlmfc\include\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc9
cmp -s "%VCSettings%VCComponents_Alan_vc9.dat" "%VCSettings%VCComponents.dat"
if %ERRORLEVEL% EQU 0 goto done
:force_vc9
cp "%VCSettings%VCComponents_Alan_vc9.dat" "%VCSettings%VCComponents.dat"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc9.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x86.
goto done
rem --------------------------------------------------------------------------
:vc8x64
set VCSettings=%VC8Settings%
set HomeVCSettings=%HomeVC8Settings%
set VCName=VS2005
set VCVersion=8.0
set FrameworkVersion=v2.0.50727
set FrameworkSDKDir=%DevDrive%\VS2005\SDK\v2.0\
:vc9x64
set WindowsSdkDir=%DevDrive%\MSSDK09\
set VCLib=
set AMD64=1
REM
REM Set the build environment for VC9, target AMD64/EMT64 (x64), use VC9 DLLs
REM
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework64\
REM
REM Need path %FrameworkDir%%FrameworkVersion% for gac, caspol, ilasm, regasm
REM
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set PATH=%WindowsSdkDir%bin;%FrameworkSDKDir%Bin;%VCInstallDir%bin\x86_amd64;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%VSInstallDir%Common7\IDE;%VCInstallDir%vcpackages;%FrameworkDir%%FrameworkVersion%;%PATH%
REM Use x64 versions of tools if running on x64
if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\X64;%PATH%
set LIB=%WindowsSdkDir%lib\x64;%FrameworkSDKDir%lib\amd64;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64
set LIBPATH=%FrameworkDir%;%FrameworkDir%%FrameworkVersion%;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64
set INCLUDE=%WindowsSdkDir%include;%FrameworkSDKDir%include;%VCInstallDir%include;%VCInstallDir%atlmfc\include;%INCLUDE%
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%DevDrive%\%VCName%\VC\crt\src\;%DevDrive%\%VCName%\VC\atlmfc\src\mfc\;%DevDrive%\%VCName%\VC\atlmfc\src\atl\;%DevDrive%\%VCNAME%\VC\atlmfc\include\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc8x64
cmp -s "%VCSettings%VCComponents_Alan_vc9.dat" "%VCSettings%VCComponents.dat"
if %ERRORLEVEL% EQU 0 goto done
:force_vc8x64
cp "%VCSettings%VCComponents_Alan_vc9.dat" "%VCSettings%VCComponents.dat"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc9.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64
goto done
rem --------------------------------------------------------------------------
:vc86
set VCSettings=%VC8Settings%
set HomeVCSettings=%HomeVC8Settings%
set VCName=VS2005
set VCVersion=8.0
set VCLib=E:\ae\libvc86
set FrameworkVersion=v2.0.50727
set FrameworkSDKDir=%DevDrive%\VS2005\SDK\v2.0\
:vc96
set WindowsSdkDir=%DevDrive%\MSSDK09\
set AMD64=
REM
REM Set the build environment for Visual Studio 200x (VC9), target 32-bit x86
REM Use backward-compatible DLLs (MFC42, MSVCRT)
REM
REM Uses Visual Studio 200x (VC9) compiler, but with VC6 includes and libraries.
REM The VC6 Includes were updated for 32/64-bit in \DDK\7100\
REM
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
REM
REM Need path %FrameworkDir%%FrameworkVersion% for gac, caspol, ilasm, regasm
REM
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set PATH=%WindowsSdkDir%bin;%FrameworkSDKDir%Bin;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%VSInstallDir%Common7\IDE;%VCInstallDir%vcpackages;%FrameworkDir%%FrameworkVersion%;%PATH%
if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\X64;%WindowsSdkDir%bin\win64\X64;%PATH%
rem
set StudioDir=%VS6%
set LIB=%LIB%;%VCLib%;%WindowsSdkDir%lib;%FrameworkSDKDir%lib;%DevDrive%\DDK\7100\lib\atl\i386;%StudioDir%\VC98\mfc\lib;%StudioDir%\VC98\lib
rem Cannot use the following - missing %DevDrive%\DDK\7100\bin\msvcrtd.dll
rem set LIB=%LIB%;%VCLib%;%WindowsSdkDir%lib;%FrameworkSDKDir%lib;%DevDrive%\DDK\7100\lib\crt\i386;%DevDrive%\DDK\7100\lib\atl\i386;%DevDrive%\DDK\7100\lib\mfc\i386
set LIBPATH=%FrameworkDir%%FrameworkVersion%
set INCLUDE=E:\ae\atl30;%WindowsSdkDir%include;%DevDrive%\DDK\7100\inc\crt;%DevDrive%\DDK\7100\inc\mfc42;%DevDrive%\DDK\7100\inc\api\crt\stl60;%FrameworkSDKDir%include;%INCLUDE%
set StudioDir=
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "E:\ae\atl30\;%VS6%\VC98\crt\src\;%VS6%\VC98\mfc\src\;%DevDrive%\DDK\7100\inc\mfc42\;%DevDrive%\DDK\7100\inc\api\crt\stl60\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc86
cmp -s "%VCSettings%VCComponents_Alan_vc96.dat" "%VCSettings%VCComponents.dat"
if %ERRORLEVEL% EQU 0 goto done
:force_vc86
cp "%VCSettings%VCComponents_Alan_vc96.dat" "%VCSettings%VCComponents.dat"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc96.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
if not "%silent%"=="yes" echo Environment varibles set for %VCNAME% w/VC6 include and lib
goto done
rem --------------------------------------------------------------------------
:vc86x64
REM
REM Set the build environment for VC8 DevEnv.exe and vcbuild.exe, but
REM target backward-compatible 64-bit x64 (W2K3 x64 and XP x64).
REM
REM Uses the March 2006 Platform SDK cross-compiler
REM %DevDrive%\MSSDK06\bin\win64\x86\AMD64\cl.exe (version 14.00.40310) with
REM the VC6 includes and MSSDK06 libs.  The VC6 includes are updated
REM for 32/64-bit in \DDK\7100\.
REM
set VCSettings=%VC8Settings%
set HomeVCSettings=%HomeVC8Settings%
set VCName=VS2005
set VCVersion=8.0
set FrameworkVersion=v2.0.50727
set FrameworkSDKDir=%DevDrive%\VS2005\SDK\v2.0\
:vc96x64
REM
REM Set the build environment for VC9 DevEnv.exe and vcbuild.exe, but
REM target backward-compatible 64-bit x64 (W2K3 x64 and XP x64).
REM
REM Uses the March 2006 Platform SDK cross-compiler
REM %DevDrive%\MSSDK06\bin\win64\x86\AMD64\cl.exe (version 14.00.40310) with
REM the VC6 includes and MSSDK06 libs.  The VC6 includes are updated
REM for 32/64-bit in \DDK\7100\.
REM
set WindowsSdkDir06=%DevDrive%\MSSDK06\
set WindowsSdkDir=%DevDrive%\MSSDK09\
set VCLib=
set AMD64=1
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework64\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set PATH=%WindowsSdkDir06%bin;%FrameworkSDKDir%Bin;%WindowsSdkDir06%bin\win64\x86\AMD64;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%VSInstallDir%Common7\IDE;%VCInstallDir%vcpackages;%FrameworkDir%%FrameworkVersion%;%PATH%
rem Cannot use the VS200x compiler because it generates unref symbols
rem set PATH=%WindowsSdkDir%bin;%FrameworkSDKDir%Bin;%VCInstallDir%bin\x86_amd64;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%VSInstallDir%Common7\IDE;%VCInstallDir%vcpackages;%FrameworkDir%%FrameworkVersion%;%PATH%
REM Use x64 versions of tools if running on x64
if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\X64;%PATH%
rem
set LIB=%WindowsSdkDir06%lib\amd64;%FrameworkSDKDir%lib\amd64;%WindowsSdkDir06%lib\amd64\atlmfc
rem Cannot use the following - missing %DevDrive%\DDK\7100\bin\amd64\msvcrtd.dll
rem set LIB=%LIB%;%VCLib%;%WindowsSdkDir%lib;%FrameworkSDKDir%lib;%DevDrive%\DDK\7100\lib\crt\amd64;%DevDrive%\DDK\7100\lib\atl\amd64;%DevDrive%\DDK\7100\lib\mfc\amd64
set LIBPATH=%FrameworkDir%%FrameworkVersion%
set INCLUDE=%WindowsSdkDir%include;%WindowsSdkDir06%include\mfc;%WindowsSdkDir06%include\atl;%WindowsSdkDir06%include\crt;%FrameworkSDKDir%include;%INCLUDE%
rem Cannot use the following
rem set INCLUDE=E:\ae\atl30;%WindowsSdkDir%include;%DevDrive%\DDK\7100\inc\crt;%DevDrive%\DDK\7100\inc\mfc42;%DevDrive%\DDK\7100\inc\api\crt\stl60;%FrameworkSDKDir%include;%INCLUDE%
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%WindowsSdkDir06%src\crt\;%WindowsSdkDir06%src\mfc\;%WindowsSdkDir06%include\crt\;%WindowsSdkDir06%include\mfc\;%WindowsSdkDir06%include\atl\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc96x64
cmp -s "%VCSettings%VCComponents_Alan_vc96.dat" "%VCSettings%VCComponents.dat"
if %ERRORLEVEL% EQU 0 goto done
:force_vc96x64
cp "%VCSettings%VCComponents_Alan_vc96.dat" "%VCSettings%VCComponents.dat"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc96.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64, with MSVCRT.DLL compiler and libs
goto done
rem --------------------------------------------------------------------------
:vc10net4
REM
REM Set the build environment for .NET 4 on x86 (vc10net4)
REM
set VCSettings=%VC10Settings%
set HomeVCSettings=%HomeVC10Settings%
set VCName=VS2010
set VCVersion=10.0
set VCLib=
set AMD64=
set Framework35Version=v3.5
set FrameworkSDKDir=
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir32=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir64=
rem set WindowsSdkDir=C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\
set WindowsSdkDir=%DevDrive%\MSSDK10\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
rem
set PATH=%VSInstallDir%VSTSDB\Deploy;%DevEnvDir%;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%VCInstallDir%VCPackages;%VSInstallDir%Team Tools\Performance Tools;%WindowsSdkDir%bin\NETFX 4.0 Tools;%WindowsSdkDir%bin;%PATH%
REM Use x64 versions of tools if running on x64
REM BUG: The MSBUILD4 Tracker requires x86, else TRK0002 error.
rem if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\x64;%WindowsSdkDir%bin\NETFX 4.0 Tools\x64;%PATH%
set LIB=%LIB%;%WindowsSdkDir%lib;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib
set LIBPATH=%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib;C:\Program Files (x86)\Microsoft ASP.NET\ASP.NET Web Pages\v2.0\Assemblies;C:\Program Files (x86)\Microsoft ASP.NET\ASP.NET MVC 4\Assemblies
set INCLUDE=%INCLUDE%;%WindowsSdkDir%include;%VCInstallDir%include;%VCInstallDir%atlmfc\include
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%VCInstallDir%crt\src\;%VCInstallDir%atlmfc\src\mfc\;%VCInstallDir%atlmfc\src\mfcm\;%VCInstallDir%atlmfc\src\atl\;%VCInstallDir%atlmfc\include\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc10net4
cmp -s "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc10Net4.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc10net4
cp "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc10Net4.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
if not "%silent%"=="yes" echo Environment varibles set for %VCName% .NET 4, target x86.
goto done
rem --------------------------------------------------------------------------
:vc10net4x64
REM
REM Set the build environment for .NET 4 on x64 (vc10net4x64)
REM
set VCSettings=%VC10Settings%
set HomeVCSettings=%HomeVC10Settings%
set VCName=VS2010
set VCVersion=10.0
set VCLib=
set Framework35Version=v3.5
set FrameworkSDKDir=
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=v4.0.30319
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework64\
set FrameworkDir32=
set FrameworkDir64=%SystemRoot%\Microsoft.NET\Framework64\
rem set WindowsSdkDir=C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\
set WindowsSdkDir=%DevDrive%\MSSDK10\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set Platform=X64
rem
set PATH=%VCInstallDir%bin\amd64;%VSInstallDir%VSTSDB\Deploy;%DevEnvDir%;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%VCInstallDir%VCPackages;%VSInstallDir%Team Tools\Performance Tools\x64;%VSInstallDir%Team Tools\Performance Tools;%WindowsSdkDir%bin\NETFX 4.0 Tools\x64;%WindowsSdkDir%bin\x64;%WindowsSdkDir%bin;%PATH%
set LIB=%LIB%;%WindowsSdkDir%lib\x64;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64
set LIBPATH=%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64;C:\Program Files (x86)\Microsoft ASP.NET\ASP.NET Web Pages\v2.0\Assemblies;C:\Program Files (x86)\Microsoft ASP.NET\ASP.NET MVC 4\Assemblies
set INCLUDE=%INCLUDE%;%WindowsSdkDir%include;%VCInstallDir%include;%VCInstallDir%atlmfc\include
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%VCInstallDir%crt\src\;%VCInstallDir%atlmfc\src\mfc\;%VCInstallDir%atlmfc\src\mfcm\;%VCInstallDir%atlmfc\src\atl\;%VCInstallDir%atlmfc\include\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc10net4x64
cmp -s "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc10Net4.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc10net4x64
cp "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc10Net4.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if not "%silent%"=="yes" echo Environment varibles set for %VCName% .NET 4, target x64.
goto done
rem --------------------------------------------------------------------------
:vc10net35
REM
REM Set the build environment for .NET 3.5 on x86 (vc10net35)
REM
set VCSettings=%VC10Settings%
set HomeVCSettings=%HomeVC10Settings%
set VCName=VS2010
set VCVersion=10.0
set VCLib=
set AMD64=
set Framework35Version=
set FrameworkSDKDir=
set FrameworkVersion=v3.5
set FrameworkVersion64=
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir32=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir64=
rem set WindowsSdkDir=C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\
set WindowsSdkDir=%DevDrive%\MSSDK10\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
rem
set PATH=%VSInstallDir%VSTSDB\Deploy;%DevEnvDir%;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%FrameworkDir%%FrameworkVersion%;%VCInstallDir%VCPackages;%VSInstallDir%Team Tools\Performance Tools;%WindowsSdkDir%bin;%PATH%
REM Use x64 versions of tools if running on x64
REM BUG: The MSBUILD4 Tracker requires x86, else TRK0002 error.
rem if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\x64;%PATH%
set LIB=%LIB%;%WindowsSdkDir%lib;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib
set LIBPATH=%FrameworkDir%%FrameworkVersion%;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib
set INCLUDE=%INCLUDE%;%WindowsSdkDir%include;%VCInstallDir%include;%VCInstallDir%atlmfc\include
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%VCInstallDir%crt\src\;%VCInstallDir%atlmfc\src\mfc\;%VCInstallDir%atlmfc\src\mfcm\;%VCInstallDir%atlmfc\src\atl\;%VCInstallDir%atlmfc\include\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc10net35
cmp -s "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc10Net35.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc10net35
cp "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc10Net35.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
if not "%silent%"=="yes" echo Environment varibles set for %VCName% .NET 3.5, target x86.
goto done
rem --------------------------------------------------------------------------
:vc10net35x64
REM
REM Set the build environment for .NET 3.5 on x64 (vc10net35x64)
REM
set VCSettings=%VC10Settings%
set HomeVCSettings=%HomeVC10Settings%
set VCName=VS2010
set VCVersion=10.0
set VCLib=
set Framework35Version=
set FrameworkSDKDir=
set FrameworkVersion=v3.5
set FrameworkVersion64=v3.5
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework64\
set FrameworkDir32=
set FrameworkDir64=%SystemRoot%\Microsoft.NET\Framework64\
rem set WindowsSdkDir=C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\
set WindowsSdkDir=%DevDrive%\MSSDK10\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set Platform=X64
rem
set PATH=%VCInstallDir%bin\amd64;%VSInstallDir%VSTSDB\Deploy;%DevEnvDir%;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%FrameworkDir%%FrameworkVersion%;%VCInstallDir%VCPackages;%VSInstallDir%Team Tools\Performance Tools\x64;%VSInstallDir%Team Tools\Performance Tools;%WindowsSdkDir%bin\x64;%WindowsSdkDir%bin;%PATH%
set LIB=%LIB%;%WindowsSdkDir%lib\x64;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64
set LIBPATH=%FrameworkDir%%FrameworkVersion%;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64
set INCLUDE=%INCLUDE%;%WindowsSdkDir%include;%VCInstallDir%include;%VCInstallDir%atlmfc\include
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%VCInstallDir%crt\src\;%VCInstallDir%atlmfc\src\mfc\;%VCInstallDir%atlmfc\src\mfcm\;%VCInstallDir%atlmfc\src\atl\;%VCInstallDir%atlmfc\include\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc10net35x64
cmp -s "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc10Net35.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc10net4x64
cp "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc10Net35.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if not "%silent%"=="yes" echo Environment varibles set for %VCName% .NET 3.5, target x64.
goto done
rem --------------------------------------------------------------------------
:vc10
if /i "%COMPUTERNAME%"=="TANK" echo Error: vc10 is not installed on %COMPUTERNAME%& goto done
if /i "%COMPUTERNAME%"=="LUMP" echo Error: vc10 is not installed on %COMPUTERNAME%& goto done
if /i "%COMPUTERNAME%"=="SNAP" echo Error: vc10 is not installed on %COMPUTERNAME%& goto done
REM
REM Set the build environment for VC10 on x86
REM
set VCSettings=%VC10Settings%
set HomeVCSettings=%HomeVC10Settings%
set VCName=VS2010
set VCVersion=10.0
set VCLib=
set AMD64=
set Framework35Version=v3.5
set FrameworkSDKDir=
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir32=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir64=
set WindowsSdkDir=%DevDrive%\MSSDK10\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
rem
set PATH=%VSInstallDir%VSTSDB\Deploy;%DevEnvDir%;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%VCInstallDir%VCPackages;%VSInstallDir%Team Tools\Performance Tools;%WindowsSdkDir%bin\NETFX 4.0 Tools;%WindowsSdkDir%bin;%PATH%
REM Use x64 versions of tools if running on x64
REM BUG: The MSBUILD4 Tracker requires x86, else TRK0002 error.
rem if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\x64;%WindowsSdkDir%bin\NETFX 4.0 Tools\x64;%PATH%
set LIB=%LIB%;%WindowsSdkDir%lib;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib
set LIBPATH=%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib
set INCLUDE=%INCLUDE%;%WindowsSdkDir%include;%VCInstallDir%include;%VCInstallDir%atlmfc\include
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%VCInstallDir%crt\src\;%VCInstallDir%atlmfc\src\mfc\;%VCInstallDir%atlmfc\src\mfcm\;%VCInstallDir%atlmfc\src\atl\;%VCInstallDir%atlmfc\include\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc10
cmp -s "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc10.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc10
cp "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc10.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc10.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
rem See C:\lbin\OLD\SpliceSettings.py -- Good example of XML parsing in Python
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x86.
goto done
rem --------------------------------------------------------------------------
:vc10x64
if /i "%COMPUTERNAME%"=="TANK" echo Error: vc10x64 is not installed on %COMPUTERNAME%& goto done
if /i "%COMPUTERNAME%"=="LUMP" echo Error: vc10x64 is not installed on %COMPUTERNAME%&goto done
if /i "%COMPUTERNAME%"=="SNAP" echo Error: vc10x64 is not installed on %COMPUTERNAME%& goto done
REM
REM Set the build environment for VC10 on x64
REM
set VCSettings=%VC10Settings%
set HomeVCSettings=%HomeVC10Settings%
set VCName=VS2010
set VCVersion=10.0
set VCLib=
set Framework35Version=v3.5
set FrameworkSDKDir=
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=v4.0.30319
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework64\
set FrameworkDir32=
set FrameworkDir64=%SystemRoot%\Microsoft.NET\Framework64\
set WindowsSdkDir=%DevDrive%\MSSDK10\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set Platform=X64
rem
set PATH=%VCInstallDir%bin\amd64;%VSInstallDir%VSTSDB\Deploy;%DevEnvDir%;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%VCInstallDir%VCPackages;%VSInstallDir%Team Tools\Performance Tools\x64;%VSInstallDir%Team Tools\Performance Tools;%WindowsSdkDir%bin\NETFX 4.0 Tools\x64;%WindowsSdkDir%bin\x64;%WindowsSdkDir%bin;%PATH%
set LIB=%LIB%;%WindowsSdkDir%lib\x64;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64
set LIBPATH=%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64
set INCLUDE=%INCLUDE%;%WindowsSdkDir%include;%VCInstallDir%include;%VCInstallDir%atlmfc\include
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%VCInstallDir%crt\src\;%VCInstallDir%atlmfc\src\mfc\;%VCInstallDir%atlmfc\src\mfcm\;%VCInstallDir%atlmfc\src\atl\;%VCInstallDir%atlmfc\include\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc10x64
cmp -s "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc10.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc10x64
cp "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc10.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64.
goto done
rem --------------------------------------------------------------------------
:vc106x64
REM
REM Set the build environment for VC10 DevEnv.exe and msbuild.exe, but
REM target backward-compatible 64-bit x64 (W2K3 x64 and XP x64).
REM
REM Uses the March 2006 Platform SDK cross-compiler
REM %DevDrive%\MSSDK06\bin\win64\x86\AMD64\cl.exe (version 14.00.40310) with
REM the VC6 includes and MSSDK06 libs.
REM
REM The VC6 includes are updated for 32/64-bit in \DDK\7100\.
REM We use %DevDrive%\MSSDK10 includes because they still work.  When a newer SDK fails
REM fall back to \DDK\7100 includes (might need work).
REM
set VCSettings=%VC10Settings%
set HomeVCSettings=%HomeVC10Settings%
set VCName=VS2010
set VCVersion=10.0
set VCLib=
set Framework35Version=v3.5
set FrameworkSDKDir=
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=v4.0.30319
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir32=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir64=
set WindowsSdkDir06=%DevDrive%\MSSDK06\
rem We want to use \MSSDK10 to pick up Vista/Win7 Includes.
set WindowsSdkDir=%DevDrive%\MSSDK10\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set Platform=X64
set PATH=%WindowsSdkDir06%bin;%WindowsSdkDir06%bin\win64\x86\AMD64;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%DevEnvDir%;%VCInstallDir%vcpackages;%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%PATH%
REM BUG: MSSDK06 does not have a native x64 compiler. MSBuild4 requires
REM that all tools be consistently 32-bit or consistently 64-bit.
REM if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\X64;%PATH%
rem Cannot use the VS2010 x64 compiler because it generates unref symbols.
rem set PATH=%WindowsSdkDir%bin;%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%;%VCInstallDir%bin\amd64;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%VSInstallDir%Common7\IDE;%VCInstallDir%vcpackages;%PATH%
rem
set LIB=%WindowsSdkDir06%lib\amd64;%WindowsSdkDir06%lib\amd64\atlmfc
rem Cannot use the following - missing %DevDrive%\DDK\7100\bin\amd64\msvcrtd.dll
rem set LIB=%LIB%;%VCLib%;%WindowsSdkDir%lib;%FrameworkSDKDir%lib;%DevDrive%\DDK\7100\lib\crt\amd64;%DevDrive%\DDK\7100\lib\atl\amd64;%DevDrive%\DDK\7100\lib\mfc\amd64
set LIBPATH=%FrameworkDir%%FrameworkVersion%;%FrameworkDir%%Framework35Version%
set INCLUDE=%WindowsSdkDir%include;%WindowsSdkDir06%include\mfc;%WindowsSdkDir06%include\atl;%WindowsSdkDir06%include\crt;%INCLUDE%
rem Cannot use the following
rem set INCLUDE=E:\ae\atl30;%WindowsSdkDir%include;%DevDrive%\DDK\7100\inc\crt;%DevDrive%\DDK\7100\inc\mfc42;%DevDrive%\DDK\7100\inc\api\crt\stl60;%INCLUDE%
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%WindowsSdkDir06%src\crt\;%WindowsSdkDir06%src\mfc\;%WindowsSdkDir06%include\crt\;%WindowsSdkDir06%include\mfc\;%WindowsSdkDir06%include\atl\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc106x64
cmp -s "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc106.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc106x64
cp "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc106.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64, with MSVCRT.DLL compiler and libs
goto done
rem --------------------------------------------------------------------------
:vc12
REM
REM Set the build environment for VC12 on x86
REM
set VCSettings=%VC12Settings%
set HomeVCSettings=%HomeVC12Settings%
set VCName=VS2013
set VCVersion=12.0
set VCLib=
set AMD64=
set FrameworkSDKDir=
set FrameworkVersion=
Rem E:\MSSDK14 is a symlink to C:\Program Files (x86)\Windows Kits\8.1
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\8.1\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set NETFXTools=C:\Program Files (x86)\Windows Kits\8.1A\bin\NETFX 4.5.1 Tools\
rem
set PATH=%VSInstallDir%VC\bin;%WindowsSdkDir%bin\x86;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Program Files (x86)\MSBuild\12.0\bin;C:\Windows\Microsoft.NET\Framework\v4.0.30319;%PATH%
REM Use x64 versions of tools if running on x64
REM BUG: The MSBUILD4 Tracker requires x86, else TRK0002 error.
rem if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\x64;%NETFXToolsx64;%PATH%
set LIB=%LIB%;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib;%WindowsSdkDir%lib\winv6.3\um\x86
rem LIBPATH is not needed in .NET 4.5.1
set LIBPATH=
set INCLUDE=%INCLUDE%;%VCInstallDir%include;%VCInstallDir%atlmfc\include;%WindowsSdkDir%include\um;%WindowsSdkDir%include\shared;%WindowsSdkDir%include\winrt
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%VCInstallDir%crt\src;%VCInstallDir%crt\src\vccorlib;%VCInstallDir%atlmfc\src\mfc;%VCInstallDir%atlmfc\src\mfcm;%VCInstallDir%atlmfc\src\atl;%VCInstallDir%atlmfc\include" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc12
cmp -s "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc12.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc12
cp "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc12.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc12.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
rem See C:\lbin\OLD\SpliceSettings.py -- Good example of XML parsing in Python
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x86.
goto done
rem --------------------------------------------------------------------------
:vc12x64
REM
REM Set the build environment for VC12 on x64
REM
set VCSettings=%VC12Settings%
set HomeVCSettings=%HomeVC12Settings%
set VCName=VS2013
set VCVersion=12.0
set VCLib=
set AMD64=1
set FrameworkSDKDir=
set FrameworkVersion=
Rem E:\MSSDK14 is a symlink to C:\Program Files (x86)\Windows Kits\8.1
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\8.1\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set NETFXTools=C:\Program Files (x86)\Windows Kits\8.1A\bin\NETFX 4.5.1 Tools\
rem
rem Note: Use x86 SDK bins because the x64 SignTool is buggy, per MSDN
rem Note: Use x86 .NET and NETFX Tools because the default x64 config does
set PATH=%VSInstallDir%VC\bin\x86_amd64;%VSInstallDir%VC\bin;%WindowsSdkDir%bin\x86;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Program Files (x86)\MSBuild\12.0\bin;C:\Windows\Microsoft.NET\Framework\v4.0.30319;%PATH%
REM Use x64 versions of tools if running on x64
REM BUG: The MSBUILD4 Tracker requires x86, else TRK0002 error.
rem if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\x64;%NETFXToolsx64;%PATH%
set LIB=%LIB%;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64;%WindowsSdkDir%lib\winv6.3\um\x64
rem LIBPATH is not needed in .NET 4.5.1
set LIBPATH=
set INCLUDE=%INCLUDE%;%VCInstallDir%include;%VCInstallDir%atlmfc\include;%WindowsSdkDir%include\um;%WindowsSdkDir%include\shared;%WindowsSdkDir%include\winrt
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%VCInstallDir%crt\src;%VCInstallDir%crt\src\vccorlib;%VCInstallDir%atlmfc\src\mfc;%VCInstallDir%atlmfc\src\mfcm;%VCInstallDir%atlmfc\src\atl;%VCInstallDir%atlmfc\include" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc12x64
cmp -s "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc12.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc12x64
cp "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc12.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc12.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
rem See C:\lbin\OLD\SpliceSettings.py -- Good example of XML parsing in Python
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64.
goto done
rem --------------------------------------------------------------------------
:vc126x64
REM
REM Set the build environment for VC12 DevEnv.exe and msbuild.exe, but
REM target backward-compatible 64-bit x64 (W2K3 x64 and XP x64).
REM
REM Uses the March 2006 Platform SDK cross-compiler
REM %DevDrive%\MSSDK06\bin\win64\x86\AMD64\cl.exe (version 14.00.40310) with
REM the VC6 includes and MSSDK06 libs.
REM
REM The VC6 includes are updated for 32/64-bit in \DDK\7100\.
REM We use %DevDrive%\MSSDK10 includes because they still work.  When a newer SDK fails
REM fall back to \DDK\7100 includes (might need work).
REM
REM Not used -- does not work for Debug builds
REM
set VCSettings=%VC12Settings%
set HomeVCSettings=%HomeVC12Settings%
set VCName=VS2013
set VCVersion=12.0
set VCLib=
set AMD64=1
set WindowsSdkDir06=%DevDrive%\MSSDK06\
rem We want to use \MSSDK10 to pick up Vista/Win7 Includes.
set WindowsSdkDir=%DevDrive%\MSSDK10\
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set Platform=X64
rem Note: Use x86 .NET and NETFX Tools because the default x64 config does
rem Note: Use x86 for %VCInstallDir%bin for misc tools
set PATH=%WindowsSdkDir06%bin;%WindowsSdkDir06%bin\win64\x86\AMD64;%VCInstallDir%bin;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Program Files (x86)\MSBuild\12.0\bin;C:\Windows\Microsoft.NET\Framework\v4.0.30319;%PATH%
REM Use x64 versions of tools if running on x64
REM BUG: The MSBUILD4 Tracker requires x86, else TRK0002 error.
rem if not "%ProgramFiles(x86)%"=="" set PATH=%WindowsSdkDir%bin\x64;%NETFXToolsx64;%PATH%
set LIB=%WindowsSdkDir06%lib\amd64;%WindowsSdkDir06%lib\amd64\atlmfc
rem LIBPATH is not needed in .NET 4.5.1
set LIBPATH=
set INCLUDE=%WindowsSdkDir%include;%WindowsSdkDir06%include\mfc;%WindowsSdkDir06%include\atl;%WindowsSdkDir06%include\crt;%INCLUDE%
rem Cannot use the following
rem set INCLUDE=E:\ae\atl30;%WindowsSdkDir%include;%DevDrive%\DDK\7100\inc\crt;%DevDrive%\DDK\7100\inc\mfc42;%DevDrive%\DDK\7100\inc\api\crt\stl60;%INCLUDE%
REM
%REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "%WindowsSdkDir06%src\crt\;%WindowsSdkDir06%src\mfc\;%WindowsSdkDir06%include\crt\;%WindowsSdkDir06%include\mfc\;%WindowsSdkDir06%include\atl\\" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc126x64
cmp -s "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc126.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc126x64
cp "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc126.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc12.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
rem See C:\lbin\OLD\SpliceSettings.py -- Good example of XML parsing in Python
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64. with MSVCRT.DLL compiler and libs
goto done
rem --------------------------------------------------------------------------
:vc14
REM
REM Set the build environment for VC14 on x86
REM
set VCSettings=%VC14Settings%
set HomeVCSettings=%HomeVC14Settings%
set VCName=VS2015
set VCVersion=14.0
set VCLib=
set AMD64=
rem These env vars are required for msbuild /p:useenv=true
Rem E:\MSSDK15 is a symlink to C:\Program Files (x86)\Windows Kits\10
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10\
set FrameworkVersion=v4.6
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkSDKDir=%WindowsSdkDir%
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set NETFXTools=C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6 Tools\
set NETFXSDK=C:\Program Files (x86)\Windows Kits\NETFXSDK\4.6\
rem
set PATH=%VSInstallDir%VC\bin;%WindowsSdkDir%bin\x86;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Program Files (x86)\MSBuild\14.0\bin;C:\Windows\Microsoft.NET\Framework\v4.0.30319;%PATH%
set LIB=%LIB%;%VCInstallDir%lib;%VCInstallDir%atlmfc\lib;%WindowsSdkDir%lib\%AE_UCRTVER%\ucrt\x86;%WindowsSdkDir%lib\%AE_UCRTVER%\um\x86;%NETFXSDK%Lib\um\x86
rem LIBPATH is not needed in .NET 4.6
set LIBPATH=
set INCLUDE=%INCLUDE%;%VCInstallDir%include;%VCInstallDir%atlmfc\include;%WindowsSdkDir%Include\%AE_UCRTVER%\ucrt;%WindowsSdkDir%include\%AE_UCRTVER%\um;%WindowsSdkDir%include\%AE_UCRTVER%\shared;%WindowsSdkDir%include\%AE_UCRTVER%\winrt
REM
REM The regval was extracted from a virgin install of VS2015.
REM Static -- no need to change
rem %REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "E:\VS2015\VC\include\;E:\VS2015\VC\include\cvt\;E:\VS2015\VC\include\msclr\;E:\VS2015\VC\include\sys\;E:\VS2015\VC\include\sys\;E:\VS2015\VC\include\thr\;E:\VS2015\VC\crt\src\;E:\VS2015\VC\crt\src\amd64\;E:\VS2015\VC\crt\src\arm\;E:\VS2015\VC\crt\src\concrt\;E:\VS2015\VC\crt\src\i386\;E:\VS2015\VC\crt\src\linkopts\;E:\VS2015\VC\crt\src\stl\;E:\VS2015\VC\crt\src\vccorlib\;E:\VS2015\VC\crt\src\vcruntime\;E:\VS2015\VC\atlmfc\src\mfc\;E:\VS2015" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc14
cmp -s "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc14.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc14
cp "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc14.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc14.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
rem See C:\lbin\OLD\SpliceSettings.py -- Good example of XML parsing in Python
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x86.
goto done
rem --------------------------------------------------------------------------
:vc14x64
REM
REM Set the build environment for VC14 on x64
REM
set VCSettings=%VC14Settings%
set HomeVCSettings=%HomeVC14Settings%
set VCName=VS2015
set VCVersion=14.0
set VCLib=
set AMD64=1
rem These env vars are required for msbuild /p:useenv=true
Rem E:\MSSDK15 is a symlink to C:\Program Files (x86)\Windows Kits\10
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10\
set FrameworkVersion=v4.6
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkSDKDir=%WindowsSdkDir%
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set NETFXTools=C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6 Tools\
set NETFXSDK=C:\Program Files (x86)\Windows Kits\NETFXSDK\4.6\
rem
rem Note: Use x86 SDK bins because the x64 SignTool is buggy, per MSDN
rem Note: Use x86 .NET and NETFX Tools because the default x64 config does
set PATH=%VSInstallDir%VC\bin\x86_amd64;%VSInstallDir%VC\bin;%WindowsSdkDir%bin\x86;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Program Files (x86)\MSBuild\14.0\bin;C:\Windows\Microsoft.NET\Framework\v4.0.30319;%PATH%
set LIB=%LIB%;%VCInstallDir%lib\amd64;%VCInstallDir%atlmfc\lib\amd64;%WindowsSdkDir%lib\%AE_UCRTVER%\ucrt\x64;%WindowsSdkDir%lib\%AE_UCRTVER%\um\x64;%NETFXSDK%Lib\um\x64
rem LIBPATH is not needed in .NET 4.6
set LIBPATH=
set INCLUDE=%INCLUDE%;%VCInstallDir%include;%VCInstallDir%atlmfc\include;%WindowsSdkDir%Include\%AE_UCRTVER%\ucrt;%WindowsSdkDir%include\%AE_UCRTVER%\um;%WindowsSdkDir%include\%AE_UCRTVER%\shared;%WindowsSdkDir%include\%AE_UCRTVER%\winrt
REM
REM The regval was extracted from a virgin install of VS2015.
REM Static -- no need to change
rem %REG32% ADD "HKLM\Software\Microsoft\VisualStudio\%VCVersion%" /v "Source Directories" /d "E:\VS2015\VC\include\;E:\VS2015\VC\include\cvt\;E:\VS2015\VC\include\msclr\;E:\VS2015\VC\include\sys\;E:\VS2015\VC\include\sys\;E:\VS2015\VC\include\thr\;E:\VS2015\VC\crt\src\;E:\VS2015\VC\crt\src\amd64\;E:\VS2015\VC\crt\src\arm\;E:\VS2015\VC\crt\src\concrt\;E:\VS2015\VC\crt\src\i386\;E:\VS2015\VC\crt\src\linkopts\;E:\VS2015\VC\crt\src\stl\;E:\VS2015\VC\crt\src\vccorlib\;E:\VS2015\VC\crt\src\vcruntime\;E:\VS2015\VC\atlmfc\src\mfc\;E:\VS2015" /f | %SystemRoot%\System32\find.exe /V "successfully"
if "%force%"=="yes" goto force_vc14x64
cmp -s "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc14.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc14x64
cp "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc14.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
rem BUG: Race condition causes Exit to occur before /ResetSettings
rem start /wait devenv.exe /ResetSettings "%HomeVCSettings%Alan_vc14.vssettings" /Command Exit
rem python "%HomeVCSettings%SpliceSettings.py" %1
rem See C:\lbin\OLD\SpliceSettings.py -- Good example of XML parsing in Python
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64.
goto done
rem --------------------------------------------------------------------------
:vc141
set AE_UCRTVER=10.0.17763.0
set AE_VCREDIST=14.16.27012
set AE_VCTOOLS=14.16.27023
set AE_VCVER=vc141
REM
REM Set the build environment for VC141 (Visual Studio 2017) on x86
REM
set UCRTVersion=%AE_UCRTVER%
set VCSettings=%VC141Settings%
set VCName=VS2017
set VCVersion=15.0
set VCLib=
set VS150COMNTOOLS=E:\VS2017\Common7\Tools\
set AMD64=
rem These env vars are required for msbuild /p:useenv=true
Rem E:\MSSDK15 is a symlink to C:\Program Files (x86)\Windows Kits\10
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10\
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=v4.0.30319
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkSDKDir=
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\Tools\MSVC\%AE_VCTOOLS%\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set NETFXTools=C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6.1 Tools\
set NETFXSDK=C:\Program Files (x86)\Windows Kits\NETFXSDK\4.6.1\
rem
set PATH=%VCInstallDir%bin\Hostx86\x86;%DevEnvDir%VC\VCPackages;%VSInstallDir%MSBuild\15.0\Bin\Roslyn;%VSInstallDir%MSBuild\15.0\Bin;%WindowsSdkDir%bin\%AE_UCRTVER%\x86;%WindowsSdkDir%bin\x86;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Windows\Microsoft.NET\Framework\v4.0.30319;%PATH%
set LIB=%LIB%;%VCInstallDir%atlmfc\lib\x86;%VCInstallDir%lib\x86;%WindowsSdkDir%lib\%AE_UCRTVER%\ucrt\x86;%WindowsSdkDir%lib\%AE_UCRTVER%\um\x86;%NETFXSDK%Lib\um\x86
set LIBPATH=%VCInstallDir%atlmfc\lib\x86;%VCInstallDir%lib\x86;%WindowsSdkDir%UnionMetadata\%AE_UCRTVER%;%WindowsSdkDir%References\%AE_UCRTVER%;%FrameworkDir%%FrameworkVersion%
set IFCPATH=%VCInstallDir%ifc\x86
set INCLUDE=%INCLUDE%;%VCInstallDir%atlmfc\include;%VCInstallDir%include;%NETFXSDK%include\um;%WindowsSdkDir%Include\%AE_UCRTVER%\ucrt;%WindowsSdkDir%include\%AE_UCRTVER%\um;%WindowsSdkDir%include\%AE_UCRTVER%\shared;%WindowsSdkDir%include\%AE_UCRTVER%\winrt
REM
rem if "%force%"=="yes" goto force_vc141
cmp -s "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc141.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc141
cp "%VCSettings%Microsoft.Cpp.Win32.user_Alan_vc141.props" "%VCSettings%Microsoft.Cpp.Win32.user.props"
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x86.
goto done
rem --------------------------------------------------------------------------
:vc141x64
set AE_UCRTVER=10.0.17763.0
set AE_VCREDIST=14.16.27012
set AE_VCTOOLS=14.16.27023
set AE_VCVER=vc141
REM
REM Set the build environment for VC141 (Visual Studio 2017) on x64
REM
set UCRTVersion=%AE_UCRTVER%
set VCSettings=%VC141Settings%
set VCName=VS2017
set VCVersion=15.0
set VCLib=
set VS150COMNTOOLS=E:\VS2017\Common7\Tools\
set AMD64=1
rem These env vars are required for msbuild /p:useenv=true
Rem E:\MSSDK15 is a symlink to C:\Program Files (x86)\Windows Kits\10
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10\
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=v4.0.30319
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework64\
set FrameworkSDKDir=
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\Tools\MSVC\%AE_VCTOOLS%\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set NETFXTools=C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6.1 Tools\
set NETFXSDK=C:\Program Files (x86)\Windows Kits\NETFXSDK\4.6.1\
rem
rem Note: Use x64 .NET and NETFX Tools because the default x64 config now does
set PATH=%VCInstallDir%bin\Hostx64\x64;%DevEnvDir%VC\VCPackages;%VSInstallDir%MSBuild\15.0\Bin\Roslyn;%VSInstallDir%MSBuild\15.0\Bin;;%WindowsSdkDir%bin\%AE_UCRTVER%\x64;%WindowsSdkDir%bin\x64;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Windows\Microsoft.NET\Framework64\v4.0.30319;%PATH%
set LIB=%LIB%;%VCInstallDir%atlmfc\lib\x64;%VCInstallDir%lib\x64;%WindowsSdkDir%lib\%AE_UCRTVER%\ucrt\x64;%WindowsSdkDir%lib\%AE_UCRTVER%\um\x64;%NETFXSDK%Lib\um\x64
set LIBPATH=%VCInstallDir%atlmfc\lib\x64;%VCInstallDir%lib\x64;%WindowsSdkDir%UnionMetadata\%AE_UCRTVER%;%WindowsSdkDir%References\%AE_UCRTVER%;%FrameworkDir%%FrameworkVersion%
set IFCPATH=%VCInstallDir%ifc\x64
set INCLUDE=%INCLUDE%;%VCInstallDir%atlmfc\include;%VCInstallDir%include;%NETFXSDK%include\um;%WindowsSdkDir%Include\%AE_UCRTVER%\ucrt;%WindowsSdkDir%include\%AE_UCRTVER%\um;%WindowsSdkDir%include\%AE_UCRTVER%\shared;%WindowsSdkDir%include\%AE_UCRTVER%\winrt
REM
if "%force%"=="yes" goto force_vc141x64
cmp -s "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc141.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if %ERRORLEVEL% EQU 0 goto done
:force_vc141x64
cp "%VCSettings%Microsoft.Cpp.x64.user_Alan_vc141.props" "%VCSettings%Microsoft.Cpp.x64.user.props"
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64.
goto done
rem --------------------------------------------------------------------------
:vc142
REM
REM Set the build environment for VC142 (Visual Studio 2019) on x86
REM
REM To view official settings: vsdevcmd -arch=x86 -host_arch=x86 -app_platform=Desktop
REM
set UCRTVersion=%AE_UCRTVER%
set VCName=VS2019
set VCVersion=16.0
set VCLib=
set VS160COMNTOOLS=E:\VS2019\Common7\Tools\
set AMD64=
rem These env vars are required for msbuild /p:useenv=true
Rem E:\MSSDK15 is a symlink to C:\Program Files (x86)\Windows Kits\10
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10\
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=v4.0.30319
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkSDKDir=
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\Tools\MSVC\%AE_VCTOOLS%\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set NETFXTools=C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\
set NETFXSDK=C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\
rem
set PATH=%VSInstallDir%MSBuild\Current\Bin\Roslyn;%VSInstallDir%MSBuild\Current\Bin;%VCInstallDir%bin\Hostx86\x86;%DevEnvDir%VC\VCPackages;%WindowsSdkDir%bin\%AE_UCRTVER%\x86;%WindowsSdkDir%bin\x86;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Windows\Microsoft.NET\Framework\%FrameworkVersion%;%PATH%;%DevEnvDir%\CommonExtensions\Microsoft\CMake\CMake\bin;%DevEnvDir%\CommonExtensions\Microsoft\CMake\Ninja
set LIB=%LIB%;%VCInstallDir%atlmfc\lib\x86;%VCInstallDir%lib\x86;%WindowsSdkDir%lib\%AE_UCRTVER%\ucrt\x86;%WindowsSdkDir%lib\%AE_UCRTVER%\um\x86;%NETFXSDK%Lib\um\x86
set LIBPATH=%VCInstallDir%atlmfc\lib\x86;%VCInstallDir%lib\x86;%WindowsSdkDir%UnionMetadata\%AE_UCRTVER%;%WindowsSdkDir%References\%AE_UCRTVER%;%FrameworkDir%%FrameworkVersion%
set INCLUDE=%INCLUDE%;%VCInstallDir%atlmfc\include;%VCInstallDir%include;%NETFXSDK%include\um;%WindowsSdkDir%Include\%AE_UCRTVER%\ucrt;%WindowsSdkDir%include\%AE_UCRTVER%\um;%WindowsSdkDir%include\%AE_UCRTVER%\shared;%WindowsSdkDir%include\%AE_UCRTVER%\winrt;%WindowsSdkDir%include\%AE_UCRTVER%\cppwinrt
REM
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x86.
goto done
rem --------------------------------------------------------------------------
:vc142x64
REM
REM Set the build environment for VC142 (Visual Studio 2019) on x64
REM
REM To view official settings: vsdevcmd -arch=amd64 -host_arch=amd64 -app_platform=Desktop
REM
set UCRTVersion=%AE_UCRTVER%
set VCName=VS2019
set VCVersion=16.0
set VCLib=
set VS160COMNTOOLS=E:\VS2019\Common7\Tools\
set AMD64=1
rem These env vars are required for msbuild /p:useenv=true
Rem E:\MSSDK15 is a symlink to C:\Program Files (x86)\Windows Kits\10
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10\
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=v4.0.30319
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework64\
set FrameworkSDKDir=
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\Tools\MSVC\%AE_VCTOOLS%\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set NETFXTools=C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\
set NETFXSDK=C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\
rem
rem Note: Use x64 .NET and NETFX Tools because the default x64 config now does
set PATH=%VSInstallDir%MSBuild\Current\Bin\Roslyn;%VSInstallDir%MSBuild\Current\Bin;%VCInstallDir%bin\Hostx64\x64;%DevEnvDir%VC\VCPackages;%WindowsSdkDir%bin\%AE_UCRTVER%\x64;%WindowsSdkDir%bin\x64;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Windows\Microsoft.NET\Framework64\%FrameworkVersion64%;%PATH%;%DevEnvDir%\CommonExtensions\Microsoft\CMake\CMake\bin;%DevEnvDir%\CommonExtensions\Microsoft\CMake\Ninja
set LIB=%LIB%;%VCInstallDir%atlmfc\lib\x64;%VCInstallDir%lib\x64;%WindowsSdkDir%lib\%AE_UCRTVER%\ucrt\x64;%WindowsSdkDir%lib\%AE_UCRTVER%\um\x64;%NETFXSDK%Lib\um\x64
set LIBPATH=%VCInstallDir%atlmfc\lib\x64;%VCInstallDir%lib\x64;%WindowsSdkDir%UnionMetadata\%AE_UCRTVER%;%WindowsSdkDir%References\%AE_UCRTVER%;%FrameworkDir%%FrameworkVersion%
set INCLUDE=%INCLUDE%;%VCInstallDir%atlmfc\include;%VCInstallDir%include;%NETFXSDK%include\um;%WindowsSdkDir%Include\%AE_UCRTVER%\ucrt;%WindowsSdkDir%include\%AE_UCRTVER%\um;%WindowsSdkDir%include\%AE_UCRTVER%\shared;%WindowsSdkDir%include\%AE_UCRTVER%\winrt;%WindowsSdkDir%include\%AE_UCRTVER%\cppwinrt
REM
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64.
goto done
rem --------------------------------------------------------------------------
:vc143
REM
REM Set the build environment for VC143 (Visual Studio 2022) on x86
REM
REM To view official settings: \VS2022\Common7\Tools\vsdevcmd -arch=x86 -host_arch=amd64 -app_platform=Desktop
REM
set UCRTVersion=%AE_UCRTVER%
set VCName=VS2022
set VCVersion=17.0
set VCLib=
set VS170COMNTOOLS=E:\VS2022\Common7\Tools\
set AMD64=
rem These env vars are required for msbuild /p:useenv=true
Rem E:\MSSDK15 is a symlink to C:\Program Files (x86)\Windows Kits\10
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10\
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=v4.0.30319
rem Use x64 tools to build for x86
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework64\
set FrameworkDir32=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir64=%SystemRoot%\Microsoft.NET\Framework64\
set FrameworkSDKDir=
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\Tools\MSVC\%AE_VCTOOLS%\
set DevEnvDir=%VSInstallDir%Common7\IDE\
Rem Use x64 tools to build for x86
set NETFXTools=C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\x64
set NETFXSDKDir=C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\
rem
Rem Use x64 tools to build for x86
set PATH=%VSInstallDir%MSBuild\Current\Bin\Roslyn;%VSInstallDir%MSBuild\Current\Bin\amd64;%VCInstallDir%bin\Hostx64\x86;%VCInstallDir%bin\Hostx64\x64;%DevEnvDir%VC\VCPackages;%WindowsSdkDir%bin\%AE_UCRTVER%\x64;%WindowsSdkDir%bin\x64;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Windows\Microsoft.NET\Framework\%FrameworkVersion%;%PATH%;%DevEnvDir%\CommonExtensions\Microsoft\CMake\CMake\bin;%DevEnvDir%\CommonExtensions\Microsoft\CMake\Ninja
set LIB=%LIB%;%VCInstallDir%atlmfc\lib\x86;%VCInstallDir%lib\x86;%WindowsSdkDir%lib\%AE_UCRTVER%\ucrt\x86;%WindowsSdkDir%lib\%AE_UCRTVER%\um\x86;%NETFXSDKDir%Lib\um\x86
set LIBPATH=%VCInstallDir%atlmfc\lib\x86;%VCInstallDir%lib\x86;%WindowsSdkDir%UnionMetadata\%AE_UCRTVER%;%WindowsSdkDir%References\%AE_UCRTVER%;%FrameworkDir%%FrameworkVersion%;%VCInstallDir%lib\x86\store\references
set INCLUDE=%INCLUDE%;%VCInstallDir%atlmfc\include;%VCInstallDir%include;%WindowsSdkDir%Include\%AE_UCRTVER%\ucrt;%WindowsSdkDir%include\%AE_UCRTVER%\um;%WindowsSdkDir%include\%AE_UCRTVER%\shared;%WindowsSdkDir%include\%AE_UCRTVER%\winrt;%WindowsSdkDir%include\%AE_UCRTVER%\cppwinrt;%NETFXSDKDir%include\um
REM
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x86.
goto done
rem --------------------------------------------------------------------------
:vc143x64
REM
REM Set the build environment for VC143 (Visual Studio 2022) on x64
REM
REM To view official settings: \VS2022\Common7\Tools\vsdevcmd -arch=amd64 -host_arch=amd64 -app_platform=Desktop
REM
set UCRTVersion=%AE_UCRTVER%
set VCName=VS2022
set VCVersion=17.0
set VCLib=
set VS170COMNTOOLS=E:\VS2022\Common7\Tools\
set AMD64=1
rem These env vars are required for msbuild /p:useenv=true
Rem E:\MSSDK15 is a symlink to C:\Program Files (x86)\Windows Kits\10
set WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10\
set FrameworkVersion=v4.0.30319
set FrameworkVersion64=v4.0.30319
set FrameworkDir=%SystemRoot%\Microsoft.NET\Framework64\
set FrameworkDir32=%SystemRoot%\Microsoft.NET\Framework\
set FrameworkDir64=%SystemRoot%\Microsoft.NET\Framework64\
set FrameworkSDKDir=
set VSInstallDir=%DevDrive%\%VCName%\
set VCInstallDir=%VSInstallDir%VC\Tools\MSVC\%AE_VCTOOLS%\
set DevEnvDir=%VSInstallDir%Common7\IDE\
set NETFXTools=C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\x64
set NETFXSDKDir=C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\
rem
rem Note: Use x64 .NET and NETFX Tools because the default x64 config now does
set PATH=%VSInstallDir%MSBuild\Current\Bin\Roslyn;%VSInstallDir%MSBuild\Current\Bin\amd64;%VCInstallDir%bin\Hostx64\x64;%DevEnvDir%VC\VCPackages;%WindowsSdkDir%bin\%AE_UCRTVER%\x64;%WindowsSdkDir%bin\x64;%NETFXTools%;%VSInstallDir%Common7\Tools;%DevEnvDir%;C:\Windows\Microsoft.NET\Framework64\%FrameworkVersion64%;%PATH%;%DevEnvDir%\CommonExtensions\Microsoft\CMake\CMake\bin;%DevEnvDir%\CommonExtensions\Microsoft\CMake\Ninja
set LIB=%LIB%;%VCInstallDir%atlmfc\lib\x64;%VCInstallDir%lib\x64;%WindowsSdkDir%lib\%AE_UCRTVER%\ucrt\x64;%WindowsSdkDir%lib\%AE_UCRTVER%\um\x64;%NETFXSDKDir%Lib\um\x64
set LIBPATH=%VCInstallDir%atlmfc\lib\x64;%VCInstallDir%lib\x64;%WindowsSdkDir%UnionMetadata\%AE_UCRTVER%;%WindowsSdkDir%References\%AE_UCRTVER%;%FrameworkDir%%FrameworkVersion64%;%VCInstallDir%lib\x64\store\references
set INCLUDE=%INCLUDE%;%VCInstallDir%atlmfc\include;%VCInstallDir%include;%WindowsSdkDir%Include\%AE_UCRTVER%\ucrt;%WindowsSdkDir%include\%AE_UCRTVER%\um;%WindowsSdkDir%include\%AE_UCRTVER%\shared;%WindowsSdkDir%include\%AE_UCRTVER%\winrt;%WindowsSdkDir%include\%AE_UCRTVER%\cppwinrt;%NETFXSDKDir%include\um
REM
if not "%silent%"=="yes" echo Environment varibles set for %VCName%, target x64.
goto done
rem --------------------------------------------------------------------------
:done
set VC8Settings=
set VC9Settings=
set VC10Settings=
set VC12Settings=
set VC14Settings=
set VC141Settings=
set VCSettings=
set HomeVC8Settings=
set HomeVC9Settings=
set HomeVC10Settings=
set HomeVC12Settings=
set HomeVC14Settings=
set HomeVCSettings=
set WindowsSdkDir06=
rem set WindowsSdkDir=
set DevEnvDir=
set NETFXTools=
set NETFXSDK=
set NETFXSDKDir=
set VCName=
set VCVersion=
set VCLib=
rem set VS140COMNTOOLS=
rem set VS150COMNTOOLS=
rem set VS160COMNTOOLS=
rem set VS170COMNTOOLS=
set IFCPATH=
set REG32=
set DevDrive=
set VS6=
set silent=
set force=
exit /b 0

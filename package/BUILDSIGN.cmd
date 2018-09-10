@setlocal enableextensions
@echo off
set PACKAGE=msls
rem
REM
REM BUILDSIGN.CMD - Build and sign msls for public release
REM Written by Alan Klietz
REM
REM This script is for building and signing the software
REM package for public download at https://u-tools.com/msls.
REM It is not likely to be helpful to you.
REM
choice /C DR /N /M "[D]ebug or [R]elease? "
if errorlevel 2 set BLDTYPE=Release& set TARGET=release
if errorlevel 1 set BLDTYPE=Debug& set TARGET=debug
call SETBUILD.CMD vc6
if errorlevel 1 goto done
set OUTDIR_LS=..\ls\#build\%target%.(cl@1200)
set OUTDIR_DIRCOLORS=..\dircolors\#build\%target%.(cl@1200)
cd ..\ls
call build.bat clean CFG="%TARGET%"
if errorlevel 1 ( cd .. & goto done )
cd ..\dircolors
call build.bat clean CFG="%TARGET%"
if errorlevel 1 ( cd .. & goto done )
cd ..\dbin
if "%BLDTYPE%"=="Release" C:\Python32\python.exe .\BumpVersion.py
cd ..\ls
call build.bat CFG="%TARGET%"
if errorlevel 1 ( cd .. & goto done )
cd ..\dircolors
call build.bat CFG="%TARGET%"
if errorlevel 1 ( cd .. & goto done )
cd ..\package
if "%BLDTYPE%"=="Release" goto release
goto done
:release
rem
copy /Y %OUTDIR_DIRCOLORS%\dircolors.exe c:\lbin\dircolors.exe
rem
copy /Y ..\DOC\msls.htm c:\inetpub\wwwroot\utools\msls.htm
copy /Y ..\DOC\msls.css c:\inetpub\wwwroot\utools\msls.css
rem
rem
choice /C YN /M "Build Distribution "
if errorlevel 2 goto done
rem
set URL="https://u-tools.com/msls"
rem
rem Authenticode certificate
rem
rem BUG: XP and W2K3R2 prior to 2009/03/19 Crypt32.dll 5.131.2600.5779
rem do not support SHA256.  Chktrust fails with 'Unknown publisher'.
rem Ditto sigcheck -a -h -i  (Lies about cert path.)
rem
rem It is likely that _no_ version of XP/W2K3 supports SHA-2.   See
rem Microsoft Security Advisory 2949927, 'Availability of SHA-2 Hashing
rem Algorithm for Windows 7 and Windows Server 2008 R2'.
rem
rem Microsoft pushed a patch in 2014/10 for Win7/W2K8R2 for SHA-2.  Win8+
rem has it built-in.  They specifically did _not_ patch Vista- or W2K8-.
rem
rem WORKAROUND: Double-sign all .EXEs with SHA-1 (primary) and SHA-2 (secondary)
rem
call E:\ae\certvars.bat
if errorlevel 1 exit /b 1
SET TITLE="ls for Windows"
rem
set /P PASSPHRASE=Enter the passphrase?
%SIGNTOOL% sign /v /f %CERTCODEPFX% /fd sha1 /t "http://timestamp.verisign.com/scripts/timestamp.dll" /d %TITLE% /p %PASSPHRASE% /ac %CERTCODEAC% /du %URL% %OUTDIR_LS%\ls.exe
if errorlevel 1 goto done
sleep 3
%SIGNTOOL% sign /v /as /f %CERTCODEPFX% /fd sha256 /tr "http://sha256timestamp.ws.symantec.com/sha256/timestamp" /td sha256 /d %TITLE% /p %PASSPHRASE% /ac %CERTCODEAC% /du %URL% %OUTDIR_LS%\ls.exe
if errorlevel 1 goto done
copy /Y %OUTDIR_LS%\ls.exe c:\lbin\ls.exe
copy /Y %OUTDIR_LS%\ls.exe c:\vmshared\ls.exe
rem
rem Make DISTRIB for distribution
rem
rm -rf ..\DISTRIB_EXE
mkdir ..\DISTRIB_EXE
copy %OUTDIR_LS%\ls.exe ..\DISTRIB_EXE
copy %OUTDIR_DIRCOLORS%\dircolors.exe ..\DISTRIB_EXE
copy ..\README.mkd ..\DISTRIB_EXE
copy ..\LICENSE.txt ..\DISTRIB_EXE
copy ..\DOC\* ..\DISTRIB_EXE
copy C:\lbin\grep.exe ..\DISTRIB_EXE
rem
rem Make DISTRIB_SRC for distribution
rem
rm -rf ..\DISTRIB_SRC
mkdir ..\DISTRIB_SRC
mkdir ..\DISTRIB_SRC\ls
copy ..\README.mkd ..\DISTRIB_SRC\README.mkd
copy ..\LICENSE.txt ..\DISTRIB_SRC\LICENSE.txt
copy ..\build.bat ..\DISTRIB_SRC\build.bat
copy ..\Makefile.nmake.core ..\DISTRIB_SRC\Makefile.nmake.core
copy ..\ls\*.h ..\DISTRIB_SRC\ls
copy ..\ls\*.c ..\DISTRIB_SRC\ls
copy ..\ls\*.cpp ..\DISTRIB_SRC\ls
copy ..\ls\*.bat ..\DISTRIB_SRC\ls
copy ..\ls\*.rc ..\DISTRIB_SRC\ls
copy ..\ls\*.manifest ..\DISTRIB_SRC\ls
copy ..\Makefile.nmake ..\DISTRIB_SRC\ls\Makefile.nmake
mkdir ..\DISTRIB_SRC\dircolors
copy ..\dircolors\*.h?? ..\DISTRIB_SRC\dircolors
copy ..\dircolors\*.c ..\DISTRIB_SRC\dircolors
copy ..\dircolors\build.bat ..\DISTRIB_SRC\dircolors\build.bat
copy ..\dircolors\Makefile.nmake ..\DISTRIB_SRC\dircolors\Makefile.nmake
rem
rem Build zip packages
rem
rm -rf ..\DISTRIB_ZIP
mkdir ..\DISTRIB_ZIP
cd ..\DISTRIB_EXE
zip.exe -9 -v -o -r ..\DISTRIB_ZIP\%PACKAGE%.zip *
cd ..\DISTRIB_SRC
zip.exe -9 -v -o -r ..\DISTRIB_ZIP\%PACKAGE%_src.zip *
cd ..\DISTRIB_ZIP
if NOT "%ProgramFiles(x86)%"=="" goto 64bit
set WZIPSE="%ProgramFiles%\wzipse\winzipse.exe"
goto cont
:64bit
set WZIPSE="%ProgramFiles(x86)%\wzipse\winzipse.exe"
:cont
%WZIPSE% %PACKAGE%.zip @..\package\winzipse.inp
rem
rem Sign the self-extracting .EXE with Authenticode Certificate
rem
sleep 3
%SIGNTOOL% sign /v /f %CERTCODEPFX% /t "http://timestamp.verisign.com/scripts/timestamp.dll" /d %TITLE% /p %PASSPHRASE% /ac %CERTCODEAC% /du %URL% %PACKAGE%.exe
if errorlevel 1 goto done
sleep 3
%SIGNTOOL% sign /v /as /f %CERTCODEPFX% /fd sha256 /tr "http://sha256timestamp.ws.symantec.com/sha256/timestamp" /td sha256 /d %TITLE% /p %PASSPHRASE% /ac %CERTCODEAC% /du %URL% %PACKAGE%.exe
if errorlevel 1 goto done
cd ..\ls
call build.bat clean CFG="%TARGET%"
cd ..\dircolors
call build.bat clean CFG="%TARGET%"
cd ..\package
echo Build complete in DISTRIB_ZIP.
echo To publish run \Releases\msls\PublishRelease.cmd
:done
endlocal

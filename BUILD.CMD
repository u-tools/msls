@echo off
setlocal
set PACKAGE=msls
rem
REM
REM BUILD.CMD - Build and install msls
REM
REM $Id: BUILD.CMD,v 1.13 2017/11/29 00:03:46 cvsalan Exp $
REM
choice /C DR /N /M "[D]ebug or [R]elease? "
if errorlevel 2 set BLDTYPE=Release
if errorlevel 1 set BLDTYPE=Debug
call SETBUILD.CMD vc6
nmake /nologo clean CFG="%PACKAGE% - Win32 %BLDTYPE%"
if errorlevel 1 goto done
if "%BLDTYPE%"=="Release" C:\Python32\python.exe BumpVersion.py
nmake /nologo CFG="%PACKAGE% - Win32 %BLDTYPE%" 
if errorlevel 1 goto done
cd dircolors
nmake /nologo CFG="dircolors - Win32 %BLDTYPE%" 
if errorlevel 1 ( cd .. & goto done )
cd ..
if "%BLDTYPE%"=="Release" goto release
goto done
:release
rem 
rem Install into final location.  This path will vary depending
rem on your folder layout.
rem
copy /Y Release\ls.exe c:\lbin\ls.exe
copy /Y Release\ls.exe c:\vmshared\ls.exe
copy /Y dircolors\Release\dircolors.exe c:\lbin\dircolors.exe
rem
copy /Y DOC\msls.htm c:\inetpub\wwwroot\utools\msls.htm
copy /Y DOC\msls.css c:\inetpub\wwwroot\utools\msls.css
rem
rem
choice /C YN /M "Build Distribution "
if errorlevel 2 goto done
rem The remainder of this file is for packaging the distribution
rem and is not likely to be helpful to you
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
%SIGNTOOL% sign /v /f %CERTCODEPFX% /fd sha1 /t "http://timestamp.verisign.com/scripts/timestamp.dll" /d %TITLE% /p %PASSPHRASE% /ac %CERTCODEAC% /du %URL% Release\ls.exe
if errorlevel 1 goto done
sleep 3
%SIGNTOOL% sign /v /as /f %CERTCODEPFX% /fd sha256 /tr "http://sha256timestamp.ws.symantec.com/sha256/timestamp" /td sha256 /d %TITLE% /p %PASSPHRASE% /ac %CERTCODEAC% /du %URL% Release\ls.exe
if errorlevel 1 goto done
copy /Y Release\ls.exe c:\lbin\ls.exe
copy /Y Release\ls.exe c:\vmshared\ls.exe
rem
rem Make DISTRIB for distribution
rem
rm -rf DISTRIB_EXE
mkdir DISTRIB_EXE
copy Release\ls.exe DISTRIB_EXE
copy dircolors\Release\dircolors.exe DISTRIB_EXE
copy README.TXT DISTRIB_EXE
copy COPYING DISTRIB_EXE
copy DOC\* DISTRIB_EXE
copy C:\lbin\grep.exe DISTRIB_EXE
rem
rem Make DISTRIB_SRC for distribution
rem
rm -rf DISTRIB_SRC
mkdir DISTRIB_SRC
copy README.TXT DISTRIB_SRC\README.TXT
copy COPYING DISTRIB_SRC\COPYING
copy *.h DISTRIB_SRC
copy *.c DISTRIB_SRC
copy *.cpp DISTRIB_SRC
copy *.cmd DISTRIB_SRC
copy *.rc DISTRIB_SRC
copy *.manifest DISTRIB_SRC
copy Makefile DISTRIB_SRC\Makefile
mkdir DISTRIB_SRC\dircolors
copy dircolors\*.h?? DISTRIB_SRC\dircolors
copy dircolors\*.c DISTRIB_SRC\dircolors
copy dircolors\Makefile DISTRIB_SRC\dircolors\Makefile
rem
rem Build zip packages
rem
rm -rf DISTRIB_ZIP
mkdir DISTRIB_ZIP
cd DISTRIB_EXE
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
%WZIPSE% %PACKAGE%.zip @..\winzipse.inp
rem
rem Sign the self-extracting .EXE with Authenticode Certificate
rem
sleep 3
%SIGNTOOL% sign /v /f %CERTCODEPFX% /t "http://timestamp.verisign.com/scripts/timestamp.dll" /d %TITLE% /p %PASSPHRASE% /ac %CERTCODEAC% /du %URL% %PACKAGE%.exe
if errorlevel 1 goto done
sleep 3
%SIGNTOOL% sign /v /as /f %CERTCODEPFX% /fd sha256 /tr "http://sha256timestamp.ws.symantec.com/sha256/timestamp" /td sha256 /d %TITLE% /p %PASSPHRASE% /ac %CERTCODEAC% /du %URL% %PACKAGE%.exe
if errorlevel 1 goto done
cd ..
echo Build complete in DISTRIB_ZIP.
echo To publish run \Releases\msls\PublishRelease.cmd
:done
endlocal

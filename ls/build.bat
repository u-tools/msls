@echo off
setlocal enableextensions
cd "%~dp0"
set "RANDOM=" &:: clear any prior storage use of %RANDOM%
set "BUILD_RANDOM=%RANDOM%"
set "BUILD_HELP_ALIAS=%~nx0"
nmake /nologo /f Makefile.nmake %*
endlocal

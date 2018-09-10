@setlocal enableextensions
@echo off

rem
rem Build script for msls
rem Written by Roy Ivy III (https://github.com/rivy)
rem

:: ::

set "projects=dircolors ls"

:: ::

cd "%~dp0"
set __dp0=%~dp0

set CC=cl
set _FIND=%SystemRoot%\System32\find.EXE

set "build_dir_default=#build"

if NOT DEFINED BUILD_DIR ( set "BUILD_DIR=%__dp0%%build_dir_default%" )

set "BUILD_DIR_present="
if EXIST "%BUILD_DIR%" ( set "BUILD_DIR_present=true" )

( endlocal
setlocal
:: call sub-builds with clean environment
if /I "%CC%"=="cl" if NOT DEFINED VCVARS_ARE_SET if EXIST "%__dp0%dbin\VCvars.BAT" ( call "%__dp0%dbin\VCvars.BAT" ) else ( call VCVars 2>NUL )
call %CC% >NUL 2>NUL && (
    for /D %%d in (%projects%) DO @(
        if /i NOT "%%d" == "%build_dir_default%" ( if /i NOT "%%d" == "%BUILD_DIR%" (
            echo [%%d @ "%__dp0%%%d"]
            cd "%__dp0%%%d"
            set "BUILD_DIR=%BUILD_DIR%\%%d"
            call echo INFO: building into "%%BUILD_DIR%%"
            call build %*
        ))
    )
    :: regenerate any needed environment
    cd "%__dp0%"
    set __dp0=%__dp0%
    set BUILD_DIR=%BUILD_DIR%
    set BUILD_DIR_present=%BUILD_DIR_present%
    set _FIND=%_FIND%
) || (
    echo ERR!: missing required compiler ^(`%CC%`^) >&2
    goto _undefined_ 2>NUL || "%COMSPEC%" /d/c exit 1
)
)

:: cleanup an empty BUILD_DIR
if EXIST "%BUILD_DIR%" (
    for /f %%g in ('dir /a/b "%BUILD_DIR%" 2^>NUL ^| "%_FIND%" /C /V ""') do @(
        if /I "%%g"=="0" (
            rmdir /q "%BUILD_DIR%" && if DEFINED BUILD_DIR_present ( echo "%BUILD_DIR%" removed )
        ))
)

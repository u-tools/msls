@setlocal enableextensions &:: required for %CD%
@echo off

:: style inspector ~ whitespace: test for nonconforming files in repository

:: Copyright (C) 2016-2018 ~ Roy Ivy III
:: License: GPLv3 (see https://opensource.org/licenses/GPL-3.0 @@ http://archive.is/id3YT)
:: * this software is provided for free, WITHOUT ANY EXPRESS OR IMPLIED WARRANTY (see the license for details)

:config
set "_exclude_dir=(?i)[_.#]build|\.git|\.gpg|vendor"
set "_exclude=(?i)\.dll$|\.exe$|\.zip$"
:config_done

set _dp0=%~dp0.
set _nx0=%~nx0
set _ME=%~n0
set dirs=%*
if NOT DEFINED dirs if EXIST "%CD%\repo" ( set dirs="%CD%\repo" )
if NOT DEFINED dirs if EXIST "%_dp0%\..\..\repo\dbin\%_nx0%" ( set dirs="%_dp0%\.." )
if NOT DEFINED dirs ( set "dirs=." )

set PCREGREP=pcregrep
if EXIST "%_dp0%\bin\pcregrep.EXE" ( set "PCREGREP=%_dp0%\bin\pcregrep.EXE" )
if EXIST "%_dp0%\pcregrep.EXE" ( set "PCREGREP=%_dp0%\pcregrep.EXE" )
"%PCREGREP%" --version >NUL 2>NUL || ( echo ERR!: Missing required `pcregrep` [try `scoop install pcregrep`] 1>&2 & goto _undefined_ 2>NUL || "%COMSPEC%" /d/c exit 1 )

echo # %_ME%: testing [ %dirs% ]

if /i "%LC_CTYPE%"=="posix" (set "LC_CTYPE=C") &:: `pcregrep` doesn't understand the common "POSIX", replace with the equivalent "C"

set "ERRORLEVEL="
set "ERROR="
:: 1. Test for TABs within leading whitespace (additional Makefile, Makefile.* exclusions)
"%PCREGREP%" -I --exclude-dir "%_exclude_dir%" --exclude "%_exclude%" --exclude "[Mm]akefile(\..*)?" --count --files-with-matches --recursive "^\s*\t" %dirs%
if NOT "%ERRORLEVEL%" == "1" ( set ERROR=1 & echo ERR!: files found with TABs within leading whitespace [file:#lines_matched] 1>&2 )

:: 1a. Test Makefiles for TABs after non-TAB whitespace within leading whitespace
"%PCREGREP%" -I --exclude-dir "%_exclude_dir%" --include "[Mm]akefile(\..*)?" --count --files-with-matches --recursive "^[^\S\t]+\t" %dirs%
if NOT "%ERRORLEVEL%" == "1" ( set ERROR=1 & echo ERR!: Makefiles found with TABs after non-TAB whitespace within leading whitespace [file:#lines_matched] 1>&2 )

:: 2. test for internal TABs after leading whitespace (ignore 'dbin' directory which may have some file which require literal TABs within code)
"%PCREGREP%" -I --exclude-dir "%_exclude_dir%" --exclude "%_exclude%" --count --files-with-matches --recursive "^[^\t]+\t" %dirs%
if NOT "%ERRORLEVEL%" == "1" ( set ERROR=1 & echo ERR!: files found with TABs internal to text ^(and AFTER leading whitespace^) [file:#lines_matched] 1>&2 )

:: 3. Test for non-LF line endings
set "HAVE_NONLF_ERROR="
"%PCREGREP%" --buffer-size=1M -I --exclude-dir "%_exclude_dir%" --exclude "%_exclude%" -NLF --files-with-matches --multiline --recursive "\r[^\n]" %dirs%
if NOT "%ERRORLEVEL%" == "1" ( set HAVE_NONLF_ERROR=1 & echo ## files found with CR line endings)
"%PCREGREP%" --buffer-size=1M -I --exclude-dir "%_exclude_dir%" --exclude "%_exclude%" --exclude "(?i)\.bat$|\.cmd$" -NLF --files-with-matches --multiline --recursive "\r\n" %dirs%
if NOT "%ERRORLEVEL%" == "1" ( set HAVE_NONLF_ERROR=1 & echo ## files found with CRLF line endings)
if DEFINED HAVE_NONLF_ERROR ( set ERROR=1 & echo ERR!: files found with non-LF line endings 1>&2 )

:: 4. Test for files without trailing newline
:: "%PCREGREP%" -I --exclude-dir "%_exclude_dir%" --exclude "%_exclude%" --files-without-match --multiline --recursive "\r?[\r\n]\z" %dirs%
"%PCREGREP%" -I --exclude-dir "%_exclude_dir%" --exclude "%_exclude%" --files-with-matches --multiline --recursive "\z" %dirs%
if NOT "%ERRORLEVEL%" == "1" ( set ERROR=1 & echo ERR!: files found without trailing newline 1>&2 )

:: 5. Test for files with lines having trailing whitespace
"%PCREGREP%" -I --exclude-dir "%_exclude_dir%" --exclude "%_exclude%" --recursive --line-number "\s$" %dirs%
if NOT "%ERRORLEVEL%" == "1" ( set ERROR=1 & echo ERR!: files found with lines having trailing whitespace [file:line_number] 1>&2 )

:: 6. Test for files with BOM
"%PCREGREP%" -I --exclude-dir "%_exclude_dir%" --exclude "%_exclude%" --files-with-matches --multiline --recursive "\A[\xEF][\xBB][\xBF]" %dirs%
if NOT "%ERRORLEVEL%" == "1" ( set ERROR=1 & echo ERR!: files found with leading BOM 1>&2 )

:script_done
if NOT DEFINED ERROR (
    echo success: no file errors found
    goto __nonexistent_label_to_shift_into_command_line_context__ 2>NUL || %COMSPEC% /c exit 0
    ) else (
    goto __nonexistent_label_to_shift_into_command_line_context__ 2>NUL || %COMSPEC% /c exit -1
    )

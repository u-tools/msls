:: setup Visual C/C++ command line build environment

:: Copyright (C) 2016-2018 ~ Roy Ivy III
:: License: GPLv3 (see https://opensource.org/licenses/GPL-3.0 @@ http://archive.is/id3YT)
:: * this software is provided for free, WITHOUT ANY EXPRESS OR IMPLIED WARRANTY (see the license for details)

:: ToDO: add support for `vswhere` for versions >= 2016 (VC15+); eg, `vswhere -property installationPath`

@setlocal
@echo off
set "__dp0=%~dp0"
set "__ME=%~n0"
cd "%~dp0"
goto :_START

:$usage
echo %~nx0 [OPTIONS] [VCVERSION ^| PATH] [VCVARSARGS]
echo:
echo OPTIONS
echo help/usage :: -?, -h, --help, --usage
echo echo       :: --echo
echo force      :: --force
echo prior      :: --or-prior, --prior
echo show-all   :: --list, --list-all, --show, --show-all
echo quiet      :: --quiet
echo:
echo VCVERSION = latest
echo             6 ^| 6min ^| 7 ^| 8 ^| 9 ^| 10 ^| 11 ^| 12 ^| 14 ^| 15
echo             vc6 ^| vc6min ^| vc7 ^| vc8 ^| vc9 ^| vc10 ^| vc11 ^| vc12 ^| vc14 ^| vc15 ^| vc2017
echo             vs6 ^| vs6min ^| vs7 ^| vs8 ^| vs9 ^| vs10 ^| vs11 ^| vs12 ^| vs14 ^| vs15 ^| vc2017
echo             1998 ^| 2002 ^| 2003 ^| 2005 ^| 2010 ^| 2012 ^| 2013 ^| 2015 ^| 2016 ^| 2017
echo             CL1200 ^| CL1300 ^| CL1310 ^| CL1400 ^| CL1500 ^| CL1600 ^| CL1700 ^| CL1800 ^| CL1900 ^| CL1911
echo:
echo NOTE: 1998 == CL1200 == VC6; 2002 == CL1300 == VC7; 2003 == CL1310 == VC7.1; 2005 == CL1400 == VC8
echo   ... 2008 == CL1500 == VC9; 2010 == CL1600 == VC10; 2012 == CL1700 == VC11; 2013 == CL1800 == VC12
echo   ... 2015 == CL1900 == VC14; 2016 == VC15; 2017 == CL1911 == VC2017
echo:
echo VCVARSARGS = x86 ^| x64 ^| amd64 ^| ia64 ^| x86_amd64 ^| x86_ia64
echo:
echo NOTE: PATH == path to directory containing VCvarsALL.bat, VCvars32.BAT, bin\VCvars32.BAT or path to the specific VCvars setup file
goto :EOF

:: NOTE: produces no ENV variable echo if there is an error

:: NOTE: VC9/2008 bug: vcvarsall incorrectly locates the batch files for x86_amd and x86_ia64.
::   ... WORKAROUND: After normal VC9 installation, copy the batch files vcvarsx86_amd64.bat and vcvarsx86_ia64.bat from the <VC9>\VC\bin directory into the <VC9>\VC\bin\x86_amd and <VC9>\VC\bin\x86_ia64 subdirectories, respectively.

:: TODO: deal with XP64, Vista64, 764
::      1) WOW6432node (eg, 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\6.0\Setup\Microsoft Visual C++' translates to  'HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\6.0\Setup\Microsoft Visual C++')
::      2) installation to 'Program Files (x86)'

::NOT! == USE {PATH}
:: %VCVARS == [INPUT:optional]
::         # full path to Visual C/C++ environment setup batch file (usually either vcvarsall.bat or vcvars32.bat) [NO surrounding quotes]
::         # use VCVARS to skip lookup and specify desired C/C++ environment setup; generally used when multiple versions of VC are installed [or a version without registry entries installed in non-default location]

:: REFERENCES
:: VCVARSALL.bat (for 32- or 64-bit command-line builds): URLref: [How to: Enable a 64-Bit Visual C++ Toolset at the Command Line] http://msdn.microsoft.com/en-us/library/x4d2c09s(VS.80).aspx @@ https://archive.is/J0MGG
:: VCVARS32.bat  (for 32-bit command-line builds): URLref: [Setting the Path and Environment Variables for Command-Line Builds] http://msdn.microsoft.com/en-us/library/f2ccy3wt(VS.80).aspx @@ https://archive.is/tsGjd

:_START
call :$$echo_DEBUG [ %~nx0 ]

:: parse options
:parse_options
::
set "__help="
set "__echo="
set "__force="
set "__prior="
set "__showall="
set "__quiet="
::
set "arg="
set "args="
set "arg_list="
::
set args=%*
call :$transform_slash_question args &:: transform all isolated '/?' with '-?'; NOTE: ignores surrounding quoting; needed to avoid possible `call ... /? ...`, which fails
if NOT DEFINED args ( goto :parse_options_DONE )
call :$$create_list_with_NULLs arg_list %args%
call :$$echo_DEBUG arg_list = "%arg_list%"
::
if DEFINED arg_list call :$$first_list_match __help "-?;-h;--help;--usage" "%arg_list%"
if DEFINED __help ( call :$usage & exit /b 1 )
:: (sorted by estimated descending probability of occurance)
if DEFINED arg_list call :$$first_list_match __showall "--list;--list-all;--show;--show-all" "%arg_list%"
if DEFINED __showall ( call :$$remove_from_list arg_list "%__showall%" "%arg_list%" )
if DEFINED arg_list call :$$first_list_match __force "--force" "%arg_list%"
if DEFINED __force ( call :$$remove_from_list arg_list "%__force%" "%arg_list%" )
if DEFINED arg_list call :$$first_list_match __echo "--echo" "%arg_list%"
if DEFINED __echo ( call :$$remove_from_list arg_list "%__echo%" "%arg_list%" )
if DEFINED arg_list call :$$first_list_match __prior "--or-prior;--prior" "%arg_list%"
if DEFINED __prior ( call :$$remove_from_list arg_list "%__prior%" "%arg_list%" )
if DEFINED arg_list call :$$first_list_match __quiet "--quiet" "%arg_list%"
if DEFINED __quiet ( call :$$remove_from_list arg_list "%__quiet%" "%arg_list%" )
call :$$list_to_items args "%arg_list%"
::
:parse_options_DONE

:: parse VCVAR argument
call :$$first_of arg "%arg_list%"

call :$$echo_DEBUG VCVARS_ARE_SET = "%VCVARS_ARE_SET%"
call :$$echo_DEBUG VCVARS = "%VCVARS%"
call :$$echo_DEBUG __echo = "%__echo%"
call :$$echo_DEBUG __force = "%__force%"
call :$$echo_DEBUG __prior = "%__prior%"
call :$$echo_DEBUG __showall = "%__showall%"
call :$$echo_DEBUG __quiet = "%__quiet%"
call :$$echo_DEBUG arg = "%arg%"
call :$$echo_DEBUG args = "%args%"
call :$$echo_DEBUG arg_list = "%arg_list%"

rem if DEFINED VCVARS_ARE_SET if NOT DEFINED __force ( goto :VCVARS_env )

:VCVARS_DO

:: KB ~ MSVC install paths
:: verified against Boost-Build [SVN Revision 52578 Fri Apr 24 17:45:34 MSD 2009]
:: ref: https://github.com/boostorg/build/search?utf8=%E2%9C%93&q=vcvarsall
::  ... https://github.com/boostorg/build/blob/ffcd9824851ef362d79d99f3de0d76055070ebbc/src/engine/guess_toolset.bat
::  ... https://github.com/boostorg/build/blob/5377199473f8d9858773ebb7daae69c772e6b3c5/src/engine/config_toolset.bat
::  ... https://github.com/boostorg/build/blob/ffcd9824851ef362d79d99f3de0d76055070ebbc/src/engine/vswhere_usability_wrapper.cmd
:: * names of registry keys containing the MSVC install path
:: v6.0 = "HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\6.0\\Setup\\Microsoft Visual C++"
:: v7.0= "HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\7.0\\Setup\\VC"
:: v7.1 = "HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\7.1\\Setup\\VC"
:: v8.0 = "HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\8.0\\Setup\\VC"
:: v8.0.express = "HKLM\\SOFTWARE\\Microsoft\\VCExpress\\8.0\\Setup\\VC"
:: v9.0 = "HKLM\\SOFTWARE\\Microsoft\\VisualStudio\\9.0\\Setup\\VC"
:: v9.0.express = "HKLM\\SOFTWARE\\Microsoft\\VCExpress\\9.0\\Setup\\VC"
::
:: NOTE: Visual C++ Toolkit 2003 (MSVC v7.1.toolkit) does not store its installation path in the registry...
::   ... * the environment variable 'VCToolkitInstallDir' and the default installation path are checked instead.

set "_check_single_version="
set "_csv_val=true"
if DEFINED __prior set "_csv_val="
if /i [%arg%]==[latest] ( call :$shift_args args %args% & goto :VCVARS_find )
::
if /i [%arg%]==[6]      ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_6 )
if /i [%arg%]==[vc6]    ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_6 )
if /i [%arg%]==[vs6]    ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_6 )
if /i [%arg%]==[1998]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_6 )
if /i [%arg%]==[CL1200] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_6 )
if /i [%arg%]==[6min]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_6min )
if /i [%arg%]==[vc6min] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_6min )
if /i [%arg%]==[vs6min] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_6min )
if /i [%arg%]==[7]      ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_7 )
if /i [%arg%]==[vc7]    ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_7 )
if /i [%arg%]==[vs7]    ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_7 )
if /i [%arg%]==[2002]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_7 )
if /i [%arg%]==[2003]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_7 )
if /i [%arg%]==[CL1300] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_7 )
if /i [%arg%]==[CL1310] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_7 )
if /i [%arg%]==[8]      ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_8 )
if /i [%arg%]==[vc8]    ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_8 )
if /i [%arg%]==[vs8]    ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_8 )
if /i [%arg%]==[2005]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_8 )
if /i [%arg%]==[CL1400] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_8 )
if /i [%arg%]==[9]      ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_9 )
if /i [%arg%]==[vc9]    ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_9 )
if /i [%arg%]==[vs9]    ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_9 )
if /i [%arg%]==[2008]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_9 )
if /i [%arg%]==[CL1500] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_9 )
if /i [%arg%]==[10]     ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_10 )
if /i [%arg%]==[vc10]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_10 )
if /i [%arg%]==[vs10]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_10 )
if /i [%arg%]==[2010]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_10 )
if /i [%arg%]==[CL1600] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_10 )
if /i [%arg%]==[11]     ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_11 )
if /i [%arg%]==[vc11]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_11 )
if /i [%arg%]==[vs11]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_11 )
if /i [%arg%]==[2012]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_11 )
if /i [%arg%]==[CL1700] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_11 )
if /i [%arg%]==[12]     ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_12 )
if /i [%arg%]==[vc12]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_12 )
if /i [%arg%]==[vs12]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_12 )
if /i [%arg%]==[2013]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_12 )
if /i [%arg%]==[CL1800] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_12 )
if /i [%arg%]==[14]     ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_14 )
if /i [%arg%]==[vc14]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_14 )
if /i [%arg%]==[vs14]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_14 )
if /i [%arg%]==[2015]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_14 )
if /i [%arg%]==[CL1900] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_14 )
if /i [%arg%]==[2016]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_15_0 )
if /i [%arg%]==[15]     ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_15 )
if /i [%arg%]==[vc15]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_15 )
if /i [%arg%]==[vs15]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_15 )
if /i [%arg%]==[15_3]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_15_3 )
if /i [%arg%]==[2017]   ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_2017 )
if /i [%arg%]==[vc2017] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_2017 )
if /i [%arg%]==[vs2017] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_2017 )
if /i [%arg%]==[CL1911] ( set "_check_single_version=%_csv_val%" & call :$shift_args args %args% & goto :VCVARS_find_2017 )
::
if EXIST "%arg%" ( set "VCVARS=%arg%" & call :$shift_args args %args% & goto :VCVARS_file_find_DONE ) else (
    if DEFINED arg (
        echo ERR!: "%arg%" is not known VCVERSION or a PATH 1>&2
        call :$usage & exit /b -1
    ))

:: VCVARS_find
:VCVARS_find
:VCVARS_find_15
:VCVARS_find_15_3
:VCVARS_find_2017
set VCVARS_version=VC2017
set "base_path=%ProgramFiles(x86)%\Microsoft Visual Studio\2017"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Enterprise\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Professional\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Community\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\BuildTools\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Common7\IDE\VC"
:VCVARS_find_2017_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo %VCVARS_version% ["%VCVARS%"] & goto VCVARS_find_15_0 )
if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
if DEFINED VCVARS goto :VCVARS_find_DONE
:VCVARS_find_15_0
set VCVARS_version=VC15
set "base_path=%ProgramFiles(x86)%\Microsoft Visual Studio\VS15"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Enterprise\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Professional\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Community\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\BuildTools\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Common7\IDE\VC"
set "base_path=%ProgramFiles(x86)%\Microsoft Visual Studio\VS15Preview"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Enterprise\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Professional\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Community\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\BuildTools\VC\Auxiliary\Build"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%base_path%\Common7\IDE\VC"
:VCVARS_find_15_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo %VCVARS_version% ["%VCVARS%"] & goto VCVARS_find_14 )
if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:VCVARS_find_14
set VCVARS_version=VC14
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\14.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc14 ["%VCVARS%"]& goto VCVARS_find_12 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
        SET "VC_VERSION=14"
    )
:VCVARS_find_14_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc14 ["%VCVARS%"]& goto VCVARS_find_12 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VCExpress\14.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc14 ["%VCVARS%"]& goto VCVARS_find_12 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VCExpress\14.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
:VCVARS_find_14e_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc14 ["%VCVARS%"]& goto VCVARS_find_12 )
if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:VCVARS_find_12
set VCVARS_version=VC12
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\12.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc12 ["%VCVARS%"]& goto VCVARS_find_11 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\12.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
        SET "VC_VERSION=12"
    )
:VCVARS_find_12_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc12 ["%VCVARS%"]& goto VCVARS_find_11 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VCExpress\12.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc12 ["%VCVARS%"]& goto VCVARS_find_11 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VCExpress\12.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
:VCVARS_find_12e_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc12 ["%VCVARS%"]& goto VCVARS_find_11 )
if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:VCVARS_find_11
set VCVARS_version=VC11
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\11.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc11 ["%VCVARS%"]& goto VCVARS_find_10 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\11.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
        SET "VC_VERSION=11"
    )
:VCVARS_find_11_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc11 ["%VCVARS%"]& goto VCVARS_find_10 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VCExpress\11.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc11 ["%VCVARS%"]& goto VCVARS_find_10 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VCExpress\11.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
:VCVARS_find_11e_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc11 ["%VCVARS%"]& goto VCVARS_find_10 )
if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:VCVARS_find_10
set VCVARS_version=VC10
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\10.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc10 ["%VCVARS%"]& goto VCVARS_find_9 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\10.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
        SET "VC_VERSION=10"
    )
:VCVARS_find_10_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc10 ["%VCVARS%"]& goto VCVARS_find_9 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VCExpress\10.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc10 ["%VCVARS%"]& goto VCVARS_find_9 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VCExpress\10.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
:VCVARS_find_10e_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc10 ["%VCVARS%"]& goto VCVARS_find_9 )
if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:VCVARS_find_9
set VCVARS_version=VC9
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\9.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc9 ["%VCVARS%"]& goto VCVARS_find_8 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\9.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
        SET "VC_VERSION=9"
    )
:VCVARS_find_9_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc9 ["%VCVARS%"]& goto VCVARS_find_8 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VCExpress\9.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc9 ["%VCVARS%"]& goto VCVARS_find_8 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VCExpress\9.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
:VCVARS_find_9e_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc9 ["%VCVARS%"]& goto VCVARS_find_8 )
if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:VCVARS_find_8
set VCVARS_version=VC8
call :$$echo_DEBUG [ testing VCVARS_version=%VCVARS_version%; VCVARS=%VCVARS% ]
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%ProgramFiles%\Microsoft Visual Studio 8\VC"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%ProgramFiles(x86)%\Microsoft Visual Studio 8\VC"
call :$$echo_DEBUG [ VCVARS=%VCVARS%]
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc8 ["%VCVARS%"]& goto VCVARS_find_7 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\8.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc8 ["%VCVARS%"]& goto VCVARS_find_7 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\8.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
:VCVARS_find_8_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc8 ["%VCVARS%"]& goto VCVARS_find_7 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VCExpress\8.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc8 ["%VCVARS%"]& goto VCVARS_find_7 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VCExpress\8.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
:VCVARS_find_8e_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc8 ["%VCVARS%"]& goto VCVARS_find_7 )
if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:VCVARS_find_7
set VCVARS_version=VC7
call :$$echo_DEBUG [ testing VCVARS_version=%VCVARS_version%; VCVARS=%VCVARS% ]
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\7.1\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc7 ["%VCVARS%"]& goto VCVARS_find_6 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\7.1\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
:VCVARS_find_7_1_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
call :$$echo_DEBUG [ testing VCVARS_version=%VCVARS_version% PATHs]
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%VCToolkitInstallDir%"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%ProgramFiles%\Microsoft Visual C++ Toolkit 2003"
call :$$echo_DEBUG [ VCVARS=%VCVARS%]
:VCVARS_find_7_1t_DONE
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc7 ["%VCVARS%"]& goto VCVARS_find_6 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
call :$$echo_DEBUG [ testing VCVARS_version=%VCVARS_version% 7.1t; VCVARS=%VCVARS% ]
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\7.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc7 ["%VCVARS%"]& goto VCVARS_find_6 )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\7.0\Setup\VC" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
:VCVARS_find_7_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc7 ["%VCVARS%"]& goto VCVARS_find_6 )
if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:VCVARS_find_6
set VCVARS_version=VC6
call :$$echo_DEBUG [ testing VCVARS_version=%VCVARS_version% ]
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\6.0\Setup\Microsoft Visual C++" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc6 ["%VCVARS%"]& goto VCVARS_find_6_DONE)
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
set _cmd="%SystemRoot%\system32\reg" query "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\6.0\Setup\Microsoft Visual C++" /v "ProductDir" 2^> nul
:: CMD needs surrounding quotes
set _cmd="%_cmd%"
for /f "tokens=1,2*" %%A in (
    '%_cmd%'
    ) do (
::      echo set "VCVARS=%%C"
        SET "VCVARS=%%C"
    )
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc6 ["%VCVARS%"]& goto VCVARS_find_6_DONE)
if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:: ALTERNATE/minimal installation of Visual C++ 6 (VC6min)
:: search common installation paths: %LocalAppData%\scoop\apps\msvc\6\VC6; %LocalAppData%\MSVC-portable\VC6; %SystemDrive%\VC6; %ProgramFiles%\VC6; %ProgramFiles%\VisualC; %ProgramFiles%\VisualC6
:VCVARS_find_6min
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%LocalAppData%\scoop\apps\msvc\6\VC6\bin\vcvars32.BAT"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%LocalAppData%\scoop\apps\msvc\6.0\VC6\bin\vcvars32.BAT"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%LocalAppData%\MSVC-portable\VC6\bin\vcvars32.BAT"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%SystemDrive%\VC6\bin\vcvars32.BAT"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%ProgramFiles%\VC6\bin\vcvars32.BAT"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%ProgramFiles%\VisualC\bin\vcvars32.BAT"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%ProgramFiles%\VisualC6\bin\vcvars32.BAT"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%ProgramFiles(x86)%\VC6\bin\vcvars32.BAT"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%ProgramFiles(x86)%\VisualC\bin\vcvars32.BAT"
if NOT DEFINED VCVARS call :$VARS_file_path VCVARS "%ProgramFiles(x86)%\VisualC6\bin\vcvars32.BAT"
:VCVARS_find_6min_DONE
:VCVARS_find_6_DONE
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED __showall if DEFINED VCVARS ( set "VCVARS=" & echo vc6 ["%VCVARS%"])
:: if DEFINED _check_single_version ( goto :VCVARS_find_DONE )
:: if NOT "%VCVARS%"=="" goto :VCVARS_find_DONE
:VCVARS_find_DONE

if DEFINED __showall exit /b 0
if NOT DEFINED VCVARS (
    echo %__ME%: ERROR: cannot find location of Visual C installation
    exit /b -1
    )

:VCVARS_file_find
if DEFINED VCVARS call :$VARS_file_path VCVARS "%VCVARS%"
if DEFINED VCVARS ( goto :VCVARS_file_find_DONE )
echo %__ME%: ERROR: cannot find vcvarsall.bat, vcvars32.bat, or bin\vcvars32.bat [in "%VCVARS%"]
exit /b -1
:VCVARS_file_find_DONE

if NOT DEFINED VCVARS (
    echo %__ME%: ERROR: cannot find location of Visual C installation
    exit /b -1
    )
if NOT EXIST "%VCVARS%" (
    echo %__ME%: ERROR: "%VCVARS%" does not exist
    exit /b -1
    )

:VCVARS_env
if NOT DEFINED VCVARS_version (
    if NOT "%VCVARS_ARE_SET%" == "1" (
        set VCVARS_version=%VCVARS_ARE_SET%
    ) else set VCVARS_version=VC?
)
if NOT DEFINED VCVARS ( goto :VCVARS_no_call )
:: skip the call if VCVARS_ARE_SET unless FORCE
if NOT DEFINED VCVARS_ARE_SET ( goto :VCVARS_call )
if DEFINED __force ( goto :VCVARS_call )
:VCVARS_no_call
call :$$echo_DEBUG no VCVARS call
( endlocal
    set __VCVARS_message=no changes
    set __VCvars_ME=%__ME%
    set __VCvars_echo=%__echo%
    set __VCvars_quiet=%__quiet%
    set __VCVARS_version=%VCVARS_ARE_SET%
    )
goto :VCVARS_env_DONE

:VCVARS_call
:: bugfix for VC14 bug (`rc` missing / not on PATH)
:: ref: https://stackoverflow.com/questions/14372706/visual-studio-cant-build-due-to-rc-exe/46166632#46166632 @@ https://archive.is/6HPIG#19.25%
:: ref: https://stackoverflow.com/questions/43847542/rc-exe-no-longer-found-in-vs-2015-command-prompt/45319119 @@ https://archive.is/GuODI
if "%VCVARS_version%"=="VC14" if NOT DEFINED args ( set "args=x86 8.1" )
if "%VCVARS_version%"=="VC14" if "%args%"=="x86" ( set "args=%args% 8.1" )
if "%VCVARS_version%"=="VC14" if "%args%"=="amd64" ( set "args=%args% 8.1" )
::
if NOT DEFINED args ( set "args=x86" )
call :$$echo_DEBUG call "%VCVARS%" %args%
( endlocal
    pushd .
    call "%VCVARS%" %args% >NUL
    popd
    set __VCVARS_message=setup complete
    set __VCvars_ME=%__ME%
    set __VCvars_echo=%__echo%
    set __VCvars_quiet=%__quiet%
    set __VCVARS_version=%VCVARS_version%
    )

:: increase compatibility between VC6 and later version environment variables
if NOT DEFINED MSVCDir          (set "MSVCDir=%VCINSTALLDIR%")
if NOT DEFINED VCINSTALLDIR     (set "VCINSTALLDIR=%MSVCDir%")

:VCVARS_env_DONE
( setlocal
    set __ME=%__VCvars_ME%
    call :$$echo_DEBUG MAKE = "%MAKE%"
    call :$$echo_DEBUG MSVCDir = "%MSVCDir%"
    call :$$echo_DEBUG VCINSTALLDIR = "%VCINSTALLDIR%"
endlocal
)

:: check setup for correctness
set "__CL_exe="
call :_path_of_file_in_PATH __CL_exe cl ".exe"
if NOT DEFINED __CL_exe (
    echo %__VCvars_ME%: ERROR: unable to find `cl.exe` [VCINSTALLDIR="%VCINSTALLDIR%"]
    set __VCVARS_message=setup completed [but with ERRORS]
    set __VCvars_exit=-1
    goto :DONE
    )
:: check setup for correctness
set "__RC_exe="
call :_path_of_file_in_PATH __RC_exe rc ".exe"
if NOT DEFINED __RC_exe (
    echo %__VCvars_ME%: ERROR: unable to find `rc.exe` [VCINSTALLDIR="%VCINSTALLDIR%"]
    set __VCVARS_message=setup completed [but with ERRORS]
    set __VCvars_exit=-1
    goto :DONE
    )
:: find `nmake` [using default PATHEXT order {ref: https://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/ntcmds_shelloverview.mspx @@ https://archive.is/BzbHM }]
set "__NMAKE_exe="
call :_path_of_file_in_PATH __NMAKE_exe nmake ".com;.exe;.bat;.cmd"
if NOT DEFINED __NMAKE_exe (
    echo %__VCvars_ME%: ERROR: unable to find `nmake` [VCINSTALLDIR="%VCINSTALLDIR%"]
    set __VCVARS_message=setup completed [but with ERRORS]
    set __VCvars_exit=-1
    goto :DONE
    )
set "__NMAKE_exe="

:: set confirmation environment variable
if %ERRORLEVEL% EQU 0 (
    set VCVARS_ARE_SET=%__VCVARS_version%
    if NOT DEFINED VCVARS_ARE_SET (set VCVARS_ARE_SET=1)
    )

:: ECHO
if NOT defined __VCvars_echo ( goto :ECHO_DONE )
:: each version of MSVS changes the variables that are setup, so just echo ALL variables
:: [2012-03-15] MSVS 10: vars == DevEnvDir; Framework35Version; FrameworkDir; FrameworkDIR32; FrameworkVersion; FrameworkVersion32; FSHARPINSTALLDIR; INCLUDE; LIB; LIBPATH; MAKE; MSVCDir; PATH; VCINSTALLDIR; VCVARS_ARE_SET; VSINSTALLDIR; WindowsSdkDir;
( setlocal
set "__VCvars_ME="
set "__VCvars_echo="
set "__VCvars_exit="
set "__VCVARS_version="
set "__VCVARS_message="
set
endlocal
)
:ECHO_DONE

:DONE
::# MAINT:* [2016-02] current algorithm works for `cl` v12 (as "1200"; aka VS6/VC6/1998) through v19 (as "1900" and "1911", aka VS14/VC14/2015 and 2017); dependent on output of `cl`, which *has* changed between versions
for /f "tokens=6-10" %%g in ('cl 2^>^&1 ^| findstr /I /C:"Version"') do (
    if /I "%%g"=="Version" (
        set VCvars_CL_version=%%h
        set VCvars_CL_target_cpu=%%j
    ) else if /I "%%h"=="Version" (
        set VCvars_CL_version=%%i
        set VCvars_CL_target_cpu=%%k
    ) else (
        set VCvars_CL_version=19.0+
        set VCvars_CL_target_cpu=?
    )
    )
if /I "%VCvars_CL_target_cpu%"=="80x86" ( set "VCvars_CL_target_cpu=x86") &:: standardize
for /f "tokens=6-10 delims=. " %%g in ('cl 2^>^&1 ^| findstr /I /C:"Version"') do (
    if /I "%%g"=="Version" (
        set VCvars_CL_VER=%%h%%i
    ) else if /I "%%h"=="Version" (
        set VCvars_CL_VER=%%i%%j
    ) else set VCvars_CL_VER=19.11+
    )
if NOT DEFINED __VCvars_quiet ( echo %__VCvars_ME%: %__VCVARS_message% ^(%__VCvars_version%; cl-%VCvars_CL_version%/%VCvars_CL_target_cpu%^) )
if NOT DEFINED __VCvars_exit (set __VCvars_exit=0)
set "__VCvars_ME="
set "__VCvars_echo="
set "__VCvars_quiet="
set "__VCVARS_version="
set "__VCVARS_message="
set "__VCvars_CL_version="
set "__VCvars_exit=" & goto _undefined_ 2>NUL || "%COMSPEC%" /d/c exit %__VCvars_exit%

goto :EOF
::
:: LOCAL FUNCTIONS
::

::
:$VARS_file_path ( ref_RETURN PATH )
:: return path to any VCvarsall.BAT (preferred) or VCvars32.BAT associated with PATH
::
setlocal
set "__DEBUG_KEY=1"
set "__MEfn=VARS_file_path"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
REM set "_RETval="
set "_RETvar=%~1"
set "_path=%~2"
set "fname=%~nx2"
::
if NOT EXIST "%_path%" ( set "_path=" & goto :$VARS_file_path_DONE )
if /I "%fname%"=="vcvarsall.BAT" ( goto :$VARS_file_path_DONE )
if /I "%fname%"=="vcvars32.BAT" ( goto :$VARS_file_path_DONE )
call :$is_dir is_dir "%_path%"
if NOT DEFINED is_dir ( set "_path=" & goto :$VARS_file_path_DONE )
if EXIST "%_path%\vcvarsall.BAT" (
    set "_path=%_path%\vcvarsall.BAT"
    goto :$VARS_file_path_DONE
    )
if EXIST "%_path%\vcvars32.BAT" (
    set "_path=%_path%\vcvars32.BAT"
    goto :$VARS_file_path_DONE
    )
if EXIST "%_path%\bin\vcvars32.BAT" (
    set "_path=%_path%\bin\vcvars32.BAT"
    goto :$VARS_file_path_DONE
    )
set "_path="
rem echo %__ME%: ERROR: cannot find vcvarsall.bat, vcvars32.bat, or bin\vcvars32.bat [in "%VCVARS%"]
rem exit /b -1
:$VARS_file_path_DONE
:$VARS_file_path_RETURN
REM call :_echo_DEBUG_KEY [ %__MEfn% :: _RETvar=%_RETvar% ]
REM call :_echo_DEBUG_KEY [ %__MEfn% :: _path=%_path% ]
endlocal & set %_RETvar%^=%_path%
goto :EOF
::

::
:$shift_args ( ref_RETURN ARGS )
::
setlocal
set "_RETval="
set "_RETvar=%~1"
::
set "args="
set "arg_list="
set line=%*
if NOT DEFINED line ( goto :$shift_args_DONE )
call :$$create_list_with_NULLs arg_list %*
call :$$remove_first arg_list "%arg_list%"
call :$$remove_first arg_list "%arg_list%"
if NOT DEFINED arg_list ( goto :$shift_args_DONE )
call :$$list_to_items _RETval "%arg_list%"
:$shift_args_DONE
:$shift_args_RETURN
endlocal & set %_RETVAR%^=%_RETVAL%
goto :EOF
::

::
:$transform_slash_question ( ref_VARNAME )
::
setlocal enabledelayedexpansion
set _RETval=!%1!
set "_RETvar=%~1"
::
if NOT DEFINED _RETval ( goto :$transform_slash_question_DONE )
if "!_RETval!"=="/?" ( set "_RETval=-?" )
:$transform_slash_question_loop
set t=%_RETval: /? = -? %
if NOT "!t!"=="!_RETval!" (
    set _RETval=%t%
    goto :$transform_slash_question_loop
)
:$transform_slash_question_loop_DONE
set t=%_RETval:~0,3%
if "!t!"=="/? " (
    set _RETval=-? %_RETval:~3%
)
set t=%_RETval:~-3%
if "!t!"==" /?" (
    set args=%_RETval:~0,-3% -?
)
:$transform_slash_question_DONE
:$transform_slash_question_RETURN
endlocal & set %_RETVAR%^=%_RETVAL%
goto :EOF
::

@::::
@:: FUNCTIONS (library:rev76)
@call %*
@goto :EOF
::

:: Copyright (C) 2011-2018 ~ Roy Ivy III
:: License: GPLv3 (see https://opensource.org/licenses/GPL-3.0 @@ http://archive.is/id3YT)
:: * this software is provided for free, WITHOUT ANY EXPRESS OR IMPLIED WARRANTY (see the license for details)

:: NOTE: ToDO: as a notation signal, function labels are annotated with $; library functions will be annotated with $$ or $_ to avoid clashes with other SUBs/functions

:: NOTE: ToDO: add noLF versions to all $$echo... functions

:: NOTE: ToDO: add ability to store/use/rerturn double-quotes and semicolons (? using character replacements)
:: #.... use ref: https://sbjh.wordpress.com/2013/02/08/generate-any-control-character @@ https://archive.is/QYqgh

:: NOTE: fix bug working with ampersand (&) characters; any problems with redirection characters, etc?

:: NOTE: for use with TCC, _MUST_ have TCMD.INI "CMDVariables=Yes"; this, plus all the WAD ("works as designed") bugs & the interminably slow execution of large batch files makes the case for completely removing TCC compatibility

:: NOTE: BAT/CMD script files require PC (CRLF) line endings for correct function; ASCII/UTF-8 encoding should also be used

:: NOTES
:: DEFINITIONS
:: ITEMs are character strings which may contain no internal double quotes (and no characters outside the usual non-graphical, printable set [ ord(ch) > 31, ord(ch) < 128 ]
:: LISTs are a ';' seperated list of ITEMs
:: SETs or PATHLISTs are LISTs which contain unique individual ITEMs (and don't accept duplicate additions)
:: PATHLISTs don't accept NULL ITEM additions
:: PATHLISTs normalize all added ITEMs as PATHs (which removes any trailing backslashes [DOS/Win path dividers])
:: BOOLEAN values are defined as FALSE == NULL, TRUE == any non-NULL value (generally "1" or "true", but can be any non-NULL, including "0")
:: :: this makes testing for truth easy... if DEFINED foo ( echo true ) else ( echo false )
::
:: LISTs may contain NULL values, and are all defined as "" in the special case of containing a single NULL value
:: NULL valued ITEMs within LISTs may be either encoded as either "" or NULL, but will be returned as NULL when using functions returning individual elements within LISTs
::
:: NOTE: Don't use '(set %RETvar%=%RETval%)' for return values as internal close parenthesis in RETval will cause errors. Use 'set "%RETvar%=%RETval%"' instead.
:: NOTE: ... if RETval may contain double quotes, must use 'endlocal & set %RETvar%=%RETval%', as surrounding aa double quote with double quotes won't work.

:: ToDO: add new function "get_output( REF_VARNAME COMMAND )" that runs COMMAND & stores the last line output into VARNAME (initial plan is to use a temporary file)

:: ToDO: ( endlocal ... ) block and variations to bypass setlocal/endlocal walls
:: ToDO: BLOG needed parens for ifs in end ( endlocal ... ) block o/w only 1st if is evaluated

:: URLref: Use of $ as subroutine sigil @@ http://www.webcitation.org/5z4F3V9yk @ 2011-05-30.0754

:: ToDO: rethink returning values (using jeb's techinique @ http://www.dostips.com/forum/viewtopic.php?p=6930#p6930 @@ http://www.webcitation.org/6ADfeDSrJ)

:: ToDO: rethink PATH functions in reference to the following notes:
::     : [How-TO check if directory is within PATH] "http://stackoverflow.com/questions/141344/how-to-check-if-directory-exists-in-path/8046515#8046515"
::     : [How-TO split PATH on ';' - initial correct answer] http://stackoverflow.com/questions/5471556/pretty-print-windows-path-variable-how-to-split-on-in-cmd-shell/5472168#5472168
::     : [How-TO split PATH on ';' - slightly improved answer] http://stackoverflow.com/a/7940444/43774

:: ToDO: look at [DOS Function Collection] http://www.dostips.com/DtCodeFunctions.php @@ http://www.webcitation.org/6ADg2siao

:: ToDO: look at [Date Math] http://www.robvanderwoude.com/datetimentmath.php @@ http://www.webcitation.org/6Ei47MYcp AND http://www.powercram.com/2010/07/get-yesterdays-date-in-ms-dos-batch.html @@ http://www.webcitation.org/6ADgoDmWV

:: DONE: add is_dir [see http://stackoverflow.com/questions/8909355/how-to-check-if-target-of-path-is-a-directory]

:: ToDO: rethink PREinitialize ... currently, doesn't work as portrayed; %0 %* is NOT the main script and it's arguments; so, the script can't be re-run as written; additionally, environment variables and path changes are lost when returning from the subshell, so it's not correct; calling the script directly doesn't change the parse/comspec misalignment
::          :: possible, changing comspec and recalling directly after PREinitialize might work
::      NOTE: the only culprit known right now is Perl with a TCC shell and an empty Perl5SHELL environment variable
::          :: this is one Perl fix: `perl -e "if (not defined $ENV{PERL5SHELL}) {$ENV{COMSPEC}=q{c:\windows\system32\cmd.exe}}; system(q{gccvars perl});"`

:: ToDO: ?? change API function names to use sigil sign ($)?

:: NOTE: Use DEFINED and NOT DEFINED instead of comparison of vars to "" when possible to avoid quoting issues as much as possible
:: NOTE: "%_RETvar%" == "" comparision @ function RETURN is necessary because of endlocal which undefines _RETvar after the %% instantiation

:: DONE::ToDO: update API changes :: _echo_no_LF => _echo_noLF ; _path_of_first => _path_of_file
:: ToDO: !! change path_of_item_in_pathlist to either NOTE NULL item will be found in first existing path OR return NULL
:: ToDO: !! copy updated library to all other BATs
:: ToDO: update library documentation with a list of functions & short, one line explanations as a summary section

:: URLref: [CMD Syntax: Escape characters, delimiters, & quotes] http://ss64.com/nt/syntax-esc.html @@ http://archive.is/V92JZ
:: URLref: [CMD parsing (at command line & at batch file level)] http://stackoverflow.com/questions/4094699/how-does-the-windows-command-interpreter-cmd-exe-parse-scripts/4095133#4095133

:: URLref: [dbenham HOME - CharLib.BAT] https://sites.google.com/site/dbenhamfiles/home @@ http://archive.is/8KAbT
:: URLref: [BUG SOLVED! - Return any string across ENDLOCAL boundary; using %%2 ... in FOR] http://www.dostips.com/forum/viewtopic.php?f=3&t=1839 @@ http://archive.is/0QuYk

::
::
:#exit_with_ERRORLEVEL
:: exits with %ERRORLEVEL%, *correctly* setting both ERRORLEVEL and the process exit code (no matter how called)
:: NOTE: NOT a subroutine; ONLY execute this code directly by using GOTO
:: VARS: GLOBAL::ERRORLEVEL; must be pinned [via "set ERRORLEVEL=..."] prior to execution; INT == batch + process exit value
:: example: `if NOT "%ERRORLEVEL%" == "0" ( set ERRORLEVEL=%ERRORLEVEL% & goto #exit_with_ERRORLEVEL )`
:: ref: <http://stackoverflow.com/questions/4864670/how-to-exit-a-cmd-file-and-the-shell-at-the-same-time#4876381>[`@`](https://archive.is/X2mkm#29%)
:: ref: @dbenham's comment on the answer <http://stackoverflow.com/questions/23327304/my-goto-redirect-is-not-working-but-works-with-echo/23327977#23327977>[`@`](http://archive.is/6CgpF#39.25%)
::
:: release pinned ERRORLEVEL & shift into command line context & die/exit (setting both ERRORLEVEL + process exit code)
set "ERRORLEVEL=" & goto _undefined_label_ 2>NUL || "%COMSPEC%" /d /c exit %ERRORLEVEL%
::echo "NEVER EXECUTE" code has been executed!!! 1>&2
goto :EOF &:: should NEVER be executed
::

::
:__exec_self_as_BTM
:: NOTE: should NOT be called as a subroutine; ONLY use directly, with a guarded GOTO (eg, "if 1.0 == 01 if /i "%~x0" neq ".BTM" goto :__exec_self_as_BTM")
:: VARS: GLOBAL::__exec_self_as_BTM_localize; must be set prior to execution; BOOLEAN == is current script localized within SETlocal/ENDlocal block?; required to set up balanced SETlocal/ENDlocal blocks within newly incarnated BTM
:: VARS: GLOBAL::__ME, __ME_dir, __ME_fullpath; REQUIRED; these are passed on through to the new BTM script as pointers to the context of the original script
:: NOTE: Prior failed attempts at TCC speedup:
:: * @if 1.0 == 1 ( loadbtm on 1> nul 2> nul & cd . ) &:: only works for TCC (not TCC/LE) and DOESN'T work well at all, timing seems just as slow!! (Maybe this is because of the call's to subroutines?)
:: * @if 1.0 == 1 ( option //UpdateTitle=No ) &:: ToDO: TEST by timing -- speeds up TCC execution by disabling window title updates? -- NO, initial testing shows no differences
if NOT 01 == 1.0 ( echo %__ME%:__exec_self_as_BTM: ERROR: Console interpreter is NOT TCC/4NT; unable to execute script as BTM 1>&2 & @echo %__ME_echo% & @exit /B -1 )
if NOT defined __ME ( echo %__ME%:__exec_self_as_BTM: ERROR: __ME must be defined prior to call; unable to execute script as BTM 1>&2 & @echo %__ME_echo% & @exit /B -1 )
if NOT defined __ME_dir ( echo %__ME%:__exec_self_as_BTM: ERROR: __ME_dir must be defined prior to call; unable to execute script as BTM 1>&2 & @echo %__ME_echo% & @exit /B -1 )
if NOT defined __ME_fullpath ( echo %__ME%:__exec_self_as_BTM: ERROR: __ME_fullpath must be defined prior to call; unable to execute script as BTM 1>&2 & @echo %__ME_echo% & @exit /B -1 )
call :_tempfile __exec_self_as_BTM_TEMPFILE "%__ME_fullpath%" .BTM
if NOT exist "%__exec_self_as_BTM_TEMPFILE%" ( echo %__ME%:__exec_self_as_BTM: ERROR: unable to open temporary file for BTM creation 1>&2 & @echo %__ME_echo% & @exit /B -1 )
if DEFINED __exec_self_as_BTM_localize echo @setlocal>> "%__exec_self_as_BTM_TEMPFILE%"
echo @:: [dynamic BTM, created from "%__ME_fullpath%"]>> "%__exec_self_as_BTM_TEMPFILE%"
echo @set __exec_self_as_BTM_TEMPFILE=>> "%__exec_self_as_BTM_TEMPFILE%"
echo set __ME=%__ME%>> "%__exec_self_as_BTM_TEMPFILE%"
echo set __ME_dir=%__ME_dir%>> "%__exec_self_as_BTM_TEMPFILE%"
echo set __ME_fullpath=%__ME_fullpath%>> "%__exec_self_as_BTM_TEMPFILE%"
echo @goto :__BTM_ENTRY >> "%__exec_self_as_BTM_TEMPFILE%"
::type "%~dpnx0" >> "%__exec_self_as_BTM_TEMPFILE%"
::type "%~f0" >> "%__exec_self_as_BTM_TEMPFILE%"
type "%__ME_fullpath%" >> "%__exec_self_as_BTM_TEMPFILE%"
:: correct setlocal/endlocal imbalance
if NOT DEFINED __exec_self_as_BTM_localize goto :__exec_self_as_BTM_call
endlocal & set __exec_self_as_BTM_TEMPFILE=%__exec_self_as_BTM_TEMPFILE%
:__exec_self_as_BTM_call
:: call new BTM incarnation
call "%__exec_self_as_BTM_TEMPFILE%" %*
:__exec_self_as_BTM_END
:: clean up temporaries
if EXIST "%__exec_self_as_BTM_TEMPFILE%" erase "%__exec_self_as_BTM_TEMPFILE%" >NUL
set __exec_self_as_BTM_TEMPFILE=
goto :EOF
::

::
:$$echo_state ( ref_RETURN )
:$echo_state ( ref_RETURN )
:_echo_state ( ref_RETURN )
:: determine and return the current echo state [ON/OFF]
:: RETURN == ON _or_ OFF [corresponding to the current echo state and usable as "echo %RETval%"]
:: NOTE: subs generally expect echo ON/OFF to be set prior to call for debugging so don't use any subroutine calls
@setlocal
@set "__DEBUG_KEY=@"
@set "__MEfn=_echo_state"
@set "_RETval=OFF"
@set "_RETvar=%~1"
@if NOT DEFINED temp ( set "temp=%tmp%" )
@if NOT EXIST "%temp%" ( set "temp=%tmp%" )
@if NOT EXIST "%temp%" ( set "temp=%LocalAppData%\Temp" )
@if NOT EXIST "%temp%" ( set "temp=%SystemRoot%\Temp" )
@if NOT EXIST "%temp%" ( set "temp=." )
:_echo_state_find_unique_temp
@set "tempfile=%temp%\%~nx0.echo_state.%RANDOM%.%RANDOM%.txt"
@if EXIST %tempfile% ( @goto :_echo_state_find_unique_temp )
@echo > "%tempfile%"
@type "%tempfile%" | "%SystemRoot%\System32\findstr" /i /r " [(]*on[)]*\.$" >nul 2>&1
@if "%ERRORLEVEL%"=="0" ( set _RETval=ON )
::@erase "%tempfile%" /Q > nul 2>&1
@endlocal & @set %_RETvar%^=%_RETval%
@if NOT 01 == 1.0 (@exit /b 0) else (@quit 0)
::

::
:$$tempfile ( ref_RETURN [PREFIX [EXTENSION]])
:$tempfile ( ref_RETURN [PREFIX [EXTENSION]])
:_tempfile ( ref_RETURN [PREFIX [EXTENSION]])
:: open a unique temporary file
:: RETURN == full pathname of temporary file (with given PREFIX and EXTENSION) [NOTE: has NO surrounding quotes]
:: PREFIX == optional filename prefix for temporary file
:: EXTENSION == optional extension (including leading '.') for temporary file [default == '.bat']
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_tempfile"
set "_RETval="
set "_RETvar=%~1"
set "prefix=%~nx2"
set "extension=%~3"
if NOT DEFINED extension ( set "extension=.txt")
:: attempt to find a temp directory
:: NOTE: see [How-TO check for directory-only existence] http://stackoverflow.com/a/12037613/43774
if NOT DEFINED temp ( set "temp=%tmp%" )
if NOT EXIST "%temp%" ( set "temp=%tmp%" )
if NOT EXIST "%temp%" ( set "temp=%LocalAppData%\Temp" )
if NOT EXIST "%temp%" ( set "temp=%SystemRoot%\Temp" )
if NOT EXIST "%temp%" ( goto :_tempfile_RETURN )    &:: undefined TEMP, RETURN (with NULL filename)
:_tempfile_find_unique_temp
set "_RETval=%temp%\%prefix%.TEMPFILE.%RANDOM%.%RANDOM%%extension%"
if EXIST %_RETval% ( goto :_tempfile_find_unique_temp )
:: instantiate tempfile [NOTE: this is an unavoidable race condition]
if NOT 01 == 1.0 (
    echo|set /p _OUTPUT="" >"%_RETval%" 2>nul
    ) else (
    echos >"%_RETval%" 2>nul
    )
if NOT EXIST "%_RETval%" (
    echo %__ME%:%__MEfn%: ERROR: unable to open tempfile [%_RETval%] 1>&2
    set "_RETval="
    )
:_tempfile_find_unique_temp_DONE
:_tempfile_RETURN
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:__PREinitialize ( [ ref_RETURN ] )
:: RETURN == COMSPEC name ('cmd', 'tcc')
::
:: BAT/CMD preinitialization for alternative shell compatibility [TCC/4NT, etc]
:: get COMSPEC filename and determine shell parsing type
:: NOTE: COMSPEC and parsing shell could be different if, for example, this BAT is executed from perl (perl defaults to using 'cmd' for system commands despite %COMSPEC% [see PERL5SHELL references in URLrefs: http://perldoc.perl.org/perlwin32.html#Usage-Hints-for-Perl-on-Win32 , http://perldoc.perl.org/perlrun.html#ENVIRONMENT])
:: NOTE: MINIMIZE subroutine calls within __PREinitialize (and any called subroutines) to allow quick transition to BTM for TCC (especially, comment out "call :_echo_DEBUG_KEY ..." calls unless/until needed)
setlocal
set "__DEBUG_KEY=@@"
set "__MEfn=__PREinitialize"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
:__PREinitialize_CMDVARIABLES_CHECK
::TCC/4NT; expect "CMDVariables=Yes" in TCMD.ini to maximize compatibility
if NOT 01 == 1.0 ( goto :__PREinitialize_CMDVARIABLES_CHECK_DONE )
(set _TEMP=)
(set _TEMP(x86)=1)
set _TEMP=%_TEMP(x86)%
if "%_TEMP%" == "1" ( goto :__PREinitialize_CMDVARIABLES_CHECK_DONE )
echo %__ME%:%__MEfn%: ERROR: "CMDVariables=No" in TCMD.ini; make "CMDVariables=Yes" in TCMD.ini for CMD compatibility 1>&2
if 01 == 1.0 ( @echo %__ME_echo% & @quit -1 ) else ( @echo %__ME_echo% & @exit /B -1 ) &::TCC drops/ignores exit ERRORLEVEL from subroutines [so, use "quit" instead]
:__PREinitialize_CMDVARIABLES_CHECK_DONE
::check shell PARSE type vs COMSPEC
call :_filename_of _COMSPECNAME "%ComSpec%"
set "_PARSETYPE=%_COMSPECNAME%"
:: known parsers (CMD & TCC)
if 01 == 1.0 ( set "_PARSETYPE=tcc" ) else ( set "_PARSETYPE=cmd" )
REM call :_echo_DEBUG_KEY _COMSPECNAME="%_COMSPECNAME%"
REM call :_echo_DEBUG_KEY _PARSETYPE="%_PARSETYPE%"
:: if same, then assume user wants the current shell and continue
if /i [%_COMSPECNAME%]==[%_PARSETYPE%] ( goto :__PREinitialize_RETURN )
:: NOTE: this doesn't work ...
:: :: otherwise, restart using known COMSPEC with CMD.exe fallback (if found)
:: :: ?? use /d to avoid AutoRun for TCC and/or CMD shell execution
::if /i "%_COMSPECNAME%"=="tcc" (
::  "%ComSpec%" /x/c %0 %*
::  exit /B %ERRORLEVEL%
::  )
::set ComSpec=%SystemRoot%\\System32\\cmd.exe
::if EXIST "%ComSpec%" (
::  "%ComSpec%" /x/c %0 %*
::  exit /B %ERRORLEVEL%
::  )
:: echo %__ME%:%__MEfn%: ERROR: unmatched batch file parser and COMSPEC [unrecognized current COMSPEC and unable to find CMD.exe (at "%ComSpec%")]
:: exit /B -1
::
::
:__PREinitialize_RETURN
if /i NOT [%_COMSPECNAME%]==[%_PARSETYPE%] (
    echo %__ME%:%__MEfn%: ERROR: unmatched batch file parser and COMSPEC 1>&2
    if 01 == 1.0 ( @echo %__ME_echo% & @quit -1 ) else ( @echo %__ME_echo% & @exit /B -1 ) &::TCC drops/ignores exit ERRORLEVEL from subroutines [so, use "quit" instead]
    )
set "_RETval=%_COMSPECNAME%"
REM call :_echo_DEBUG_KEY _COMSPECNAME="%_COMSPECNAME%"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$filename_of ( ref_RETURN PATH )
:$filename_of ( ref_RETURN PATH )
:_filename_of ( ref_RETURN PATH )
:: RETURN == filename of PATH
:: NOTE: special processing to deal correctly with the case of "<DRIVE>:" ("<DRIVE>:" == "<DRIVE>:." == ".")
:: NOTE: _filename_of("") == ""
:: NOTE: _filename_of("\\") == _filename_of("\") == _filename_of("c:\") == _filename_of("c:\.") == ""
:: NOTE: _filename_of("c:") == _filename_of("c:.") == _filename_of(".")
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_filename_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "_path=%~2"
if NOT DEFINED _path ( goto :_filename_of_RETURN )
if "%_path%" == "\\" ( set "_path=\" )
::?:call :_drive_of drive "%~1"
::?:if /i "%drive%" == "%~1" ( set "_RETval=" & goto :_filename_of_RETURN )
::?:if /i "%drive%\" == "%~1" ( set "_RETval=" & goto :_filename_of_RETURN )
call :_rewrite_path_to_FQ_local _path _ "%_path%"
REM call :_echo_DEBUG_KEY _path="%_path%"
REM call :_echo_DEBUG_KEY _="%_%"
call :_param_tilde_N _RETval "%_path%"
:: remove trailing backslashes
call :_rtrim _RETval "%_RETval%" "\"
:_filename_of_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$rewrite_path_to_FQ_local ( ref_RETURN_path ref_RETURN_drive PATH )
:$rewrite_path_to_FQ_local ( ref_RETURN_path ref_RETURN_drive PATH )
:_rewrite_path_to_FQ_local ( ref_RETURN_path ref_RETURN_drive PATH )
:: RETURN_path == PATH, rewritten in a fully qualified (semi-canonical) form: removing extraneous trailing "\" or "\." and changing path to point to current drive (if a drive is specified)
:: RETURN_drive == original drive of PATH, "" if no drive was specified
:: NOTE:: changing PATH to refer to a similar "false" PATH on the local drive (for CMD and/or TCC) speeds up calculations for UNC network paths (avoiding network timeouts)
:: NOTE:: special processing is needed to deal with the fact that TCC acts out with almost unsuppressible errors for inaccessible and UNC PATHs [which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
:: NOTE:: changing PATH to refer to a local drive for TCC [avoids a loud & nasty TCC bug [URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://webcitation.org/63ua1bpOk]]
:: NOTE: assumes PATH has leading "X:", "\\...\...", "\...", or is a relative path (without leading "\")
:: NOTE: _rewrite_path_to_FQ_local("") => ("", "")
:: NOTE: _rewrite_path_to_FQ_local("\\") == _rewrite_path_to_FQ_local("\")
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_rewrite_path_to_FQ_local"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETvar_drive=%~2"
set "_RETval=%~3"
set "drive="
REM call :_echo_DEBUG_KEY PATH="%_RETval%"
if NOT DEFINED _RETval ( goto :_rewrite_path_to_FQ_local_RETURN )
set "_path=%_RETval%"
if "%_path%" == "." ( goto :_rewrite_path_to_FQ_local_RETURN )
set local_drive=
call :_split_drive_path_of drive _path "%_path%"
if NOT DEFINED _path ( set "_path=." )
REM call :_echo_DEBUG_KEY drive="%drive%"
REM call :_echo_DEBUG_KEY _path="%_path%"
:_rewrite_path_to_FQ_local_LOOP
if NOT DEFINED _path ( goto :_rewrite_path_to_FQ_local_LOOP_DONE )
if "%_path%" == "\\" ( set "_path=\" )
if "%_path%" == "\." ( set "_path=\" )
if "%_path%" == "\" ( goto :_rewrite_path_to_FQ_local_LOOP_DONE )
:: TCC doesn't handle trailing "\." or "\" correctly, so remove them
REM call :_echo_DEBUG_KEY 2_path="%_path%"
:_rewrite_path_to_FQ_local_LOOP_test_1
if NOT "%_path:~-2,2%" == "\." ( goto :_rewrite_path_to_FQ_local_LOOP_test_2 )
set "_path=%_path:~0,-2%"
goto :_rewrite_path_to_FQ_local_LOOP
:_rewrite_path_to_FQ_local_LOOP_test_2
REM call :_echo_DEBUG_KEY 3_path="%_path%"
if NOT "%_path:~-1,1%" == "\" ( goto :_rewrite_path_to_FQ_local_LOOP_test_3 )
set "_path=%_path:~0,-1%"
goto :_rewrite_path_to_FQ_local_LOOP
:_rewrite_path_to_FQ_local_LOOP_test_3
if NOT "%_path:~0,2%" == "\\" ( goto :_rewrite_path_to_FQ_local_LOOP_test_DONE )
set "_RETval=%_path:~1%"
:_rewrite_path_to_FQ_local_LOOP_test_DONE
:_rewrite_path_to_FQ_local_LOOP_DONE
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
if NOT DEFINED drive ( goto :_rewrite_path_to_FQ_local_DONE )
if NOT DEFINED local_drive ( set "local_drive=%SYSTEMDRIVE%" )
if NOT DEFINED local_drive ( set "local_drive=%SYSTEMROOT:~0,2%" )
if NOT DEFINED local_drive ( set "local_drive=%~d0" )
REM call :_echo_DEBUG_KEY local_drive="%local_drive%"
set "_RETval=%local_drive%%_path%"
:_rewrite_path_to_FQ_local_DONE
:_rewrite_path_to_FQ_local_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set "%_RETvar%=%_RETval%" & set "%_RETvar_drive%=%drive%"
goto :EOF
::

::
:$$drive_of ( ref_RETURN PATH )
:$drive_of ( ref_RETURN PATH )
:_drive_of ( ref_RETURN PATH )
:: RETURN == drive of PATH
:: NOTE: assumes PATH has leading "X:", "\\SERVER"; PATHs without a drive indicator return NULL
:: NOTE: drive_of("") == ""; drive_of("\\SERVER\PATH") == "\\SERVER"
:: NOTE: special UNC paths: drive_of("\\?\UNC\PATH") => drive_of("\\PATH"); drive_of("\\?\PATH") == drive_of("\\.\PATH") => drive_of("PATH")
:: URLref: [Naming Files, Paths, and Namespaces - MSDN] http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx @@ http://archive.is/EcTrM @@ http://webcitation.org/6IwYVd1Cn
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_drive_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "_path=%~2"
call :_split_drive_path_of _RETval _ "%_path%"
::if NOT DEFINED _RETval ( set "_RETval=%~d2" ) &:: causes TCC errors for non-existant PATHs
:_drive_of_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$FQ_drive_of ( ref_RETURN PATH )
:$FQ_drive_of ( ref_RETURN PATH )
:_FQ_drive_of ( ref_RETURN PATH )
:: RETURN == fully qualified (canonical) directory of PATH
:: NOTE: _FQ_drive_of("") == ""
:: NOTE: _FQ_drive_of("\\") == _FQ_drive_of("\") == _FQ_drive_of("\.")
:: NOTE: _FQ_drive_of("c:") == _FQ_drive_of("c:.")
:: NOTE: _FQ_drive_of("c:\") == _FQ_drive_of("c:\.") == "c:\"
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_FQ_drive_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: avoid TCC path parsing errors for null strings
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_FQ_drive_of_RETURN )
call :_rewrite_path_to_FQ_local _ drive "%_RETval%"
if NOT DEFINED drive ( goto :_FQ_drive_of_DONE )
:_FQ_drive_of_DONE
if NOT DEFINED drive ( set "drive=%SYSTEMDRIVE%" )
if NOT DEFINED drive ( set "drive=%SYSTEMROOT:~0,2%" )
if NOT DEFINED drive ( set "drive=%~d0" )
REM call :_echo_DEBUG_KEY drive="%drive%"
:_FQ_drive_of_DONE
set "_RETval=%drive%"
:_FQ_drive_of_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$split_drive_path_of ( ref_RETURN_DRIVE ref_RETURN_PATH PATH )
:$split_drive_path_of ( ref_RETURN_DRIVE ref_RETURN_PATH PATH )
:_split_drive_path_of ( ref_RETURN_DRIVE ref_RETURN_PATH PATH )
:: RETURN_DRIVE == drive of PATH
:: RETURN_PATH == PATH with drive prefix removed
:: NOTE: assumes PATH has leading "X:", "\\", "\...", or is a relative path (without leading "\")
:: NOTE: drive_of("") == ""; drive_of("\\SERVER\PATH") == "\\SERVER"
:: NOTE: special UNC paths: drive_of("\\?\UNC\PATH") => drive_of("\\PATH"); drive_of("\\?\PATH") => drive_of("PATH"); drive_of("\\.\DEVICE\PATH") => "\\.\DEVICE"
:: URLref: [Naming Files, Paths, and Namespaces - MSDN] http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx @@ http://archive.is/EcTrM @@ http://webcitation.org/6IwYVd1Cn
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_split_drive_path_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval_drive="
set "_RETvar_drive=%~1"
set "_RETvar_path=%~2"
set "_path=%~3"
:_split_drive_path_of_START
if NOT DEFINED _path ( goto :_split_drive_path_of_RETURN )
if "%_path%" == "\\" ( goto :_split_drive_path_of_RETURN )
if NOT "%_path:~0,2%" == "\\" ( goto :_split_drive_path_of_NONUNC )
set "_RETval_drive=\\"
set "_path=%_path:~2%"
:_split_drive_path_of_TEST_1
if NOT "%_path:~0,6%" == "?\UNC\" ( goto :_split_drive_path_of_TEST_2 )
set "_path=\\%_path:~6%"
goto :_split_drive_path_of_UNC_LOOP
:_split_drive_path_of_TEST_2
if NOT "%_path:~0,2%" == "?\" ( goto :_split_drive_path_of_TEST_3 )
set "_path=%_path:~2%"
goto :_split_drive_path_of_START
:_split_drive_path_of_TEST_3
if NOT "%_path:~0,2%" == ".\" ( goto :_split_drive_path_of_TEST_4 )
set "_RETval_drive=\\.\"
set "_path=%_path:~2%"
:_split_drive_path_of_TEST_4
:_split_drive_path_of_UNC_LOOP
if NOT DEFINED _path ( goto :_split_drive_path_of_UNC_LOOP_DONE )
if "%_path:~0,1%" == "\" ( goto :_split_drive_path_of_UNC_LOOP_DONE )
set "_RETval_drive=%_RETval_drive%%_path:~0,1%"
set "_path=%_path:~1%"
goto :_split_drive_path_of_UNC_LOOP
:_split_drive_path_of_UNC_LOOP_DONE
goto :_split_drive_path_of_RETURN
:_split_drive_path_of_NONUNC
if NOT "%_path:~1,1%" == ":" ( goto :_split_drive_path_of_TEST_6 )
set "_RETval_drive=%_path:~0,2%"
set "_path=%_path:~2%"
goto :_split_drive_path_of_RETURN
:_split_drive_path_of_TEST_6
::set "_RETval_drive=%~d3"
:_split_drive_path_of_RETURN
REM call :_echo_DEBUG_KEY _RETvar_drive="%_RETvar_drive%"
REM call :_echo_DEBUG_KEY _RETval_drive="%_RETval_drive%"
REM call :_echo_DEBUG_KEY _RETvar_path="%_RETvar_path%"
REM call :_echo_DEBUG_KEY _RETval_path="%_path%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
:: return values via a single line with surrounding double-quotes; this is fine here, given double-quotes are illegal in NTFS filenames
endlocal & set "%_RETvar_drive%=%_RETval_drive%" & set "%_RETvar_path%=%_path%"
goto :EOF
::

::
:$$rtrim ( ref_RETURN ITEM [CHARSET] )
:$rtrim ( ref_RETURN ITEM [CHARSET] )
:_rtrim ( ref_RETURN ITEM [CHARSET] )
:: trim characters in CHARSET from right-side of ITEM
:: RETURN = ITEM with rightmost CHARSET characters removed
:: NOTE: CHARSET defaults to "<SPACE>" if NULL/missing
:: URLrefs: [Variable editing] http://ss64.com/nt/syntax-substring.html, [How to trim whitespace from a string] http://www.experts-exchange.com/OS/Microsoft_Operating_Systems/MS_DOS/Q_23816304.html
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_rtrim"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "item=%~2"
if 1.0 == 01 (
    set item=%@unquotes[%2]
    )
set "charset=%~3"
if 1.0 == 01 (
    set charset=%@unquotes[%3]
    )
if NOT DEFINED charset ( set "charset= " )
REM call :_echo_DEBUG_KEY item="%item%"
REM call :_echo_DEBUG_KEY charset="%charset%"
:: change any internal double quotes to chr(255) (avoids syntax errors during the character comparison and removal process) [ NOTE: may have internal double quotes, so no outer quotes for set; this also creates a problem with internal ()'s if the set is enclosed in a block, so use a goto around it as needed]
if NOT DEFINED item ( goto :_rtrim_LOOP_ch )
set "item=%item:"=¸%"
set "charset=%charset:"=¸%"
set "chars=%charset%"
:_rtrim_LOOP_ch
REM call :_echo_DEBUG_KEY LOOP.item="%item%"
REM call :_echo_DEBUG_KEY charset="%charset%"
REM call :_echo_DEBUG_KEY LOOP.chars="%chars%"
set "ch="
if DEFINED chars ( set "ch=%chars:~0,1%" & set "chars=%chars:~1%" )
if NOT DEFINED ch ( goto :_rtrim_LOOP_DONE )
:_rtrim_LOOP_removal
if NOT DEFINED item ( goto :_rtrim_LOOP_DONE )
set "last_ch="
if DEFINED item ( set "last_ch=%item:~-1%" )
REM call :_echo_DEBUG_KEY item="%item%"
REM call :_echo_DEBUG_KEY ch="%ch%"
REM call :_echo_DEBUG_KEY last_ch="%last_ch%"
if /i "%last_ch%" == "%ch%" (
    set "item=%item:~0,-1%"
    set "chars=%charset%"
    goto :_rtrim_LOOP_removal
    )
goto :_rtrim_LOOP_ch
:_rtrim_LOOP_DONE
:_rtrim_RETURN
if NOT DEFINED item ( goto :_rtrim_RETURN_translate_DONE )
:: return any double quotes to ITEM
set item=%item:¸=^"%
:: " [balance double quote for editor parsing]
:_rtrim_RETURN_translate_DONE
set _RETval=%item%
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$param_tilde_N ( ref_RETURN PATH )
:$param_tilde_N ( ref_RETURN PATH )
:_param_tilde_N ( ref_RETURN PATH )
:: NOTE: for TCC, assume that PATH is on (or has been forced onto) an accessible drive and not a UNC pathname [necessary to avoid unsupressable TCC parsing errors; which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
:: RETURN == name of PATH
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_param_tilde_N"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
if NOT DEFINED _RETval ( goto :_param_tilde_N_RETURN )
set "_RETval=%~n2"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
:_param_tilde_N_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$echo_DEBUG ( [ TEXT ... ] )
:$echo_DEBUG ( [ TEXT ... ] )
:_echo_DEBUG ( [ TEXT ... ] )
:: used to help avoid the CMD/TCC BUG which causes a script breaking error if ()'s (more specifically, closed parens) are found within an IF() block
:: NOTE: __DEBUG is GLOBAL to this function (and MUST be, because the shift command doesn't change subsequent %* uses {so, there is no way to pass vars into the function with arbitrary following TEXT})
if NOT DEFINED __DEBUG ( goto :_echo_DEBUG_RETURN )
if NOT DEFINED __MEfn ( goto :_echo_DEBUG_NO_MEFN )
echo %__ME%:%__MEfn%: {{DEBUG}} %*
goto :_echo_DEBUG_RETURN
:_echo_DEBUG_NO_MEFN
echo %__ME%: {{DEBUG}} %*
goto :_echo_DEBUG_RETURN
:_echo_DEBUG_RETURN
goto :EOF
::

::
:$$echo_DEBUG_KEY ( [ TEXT ... ] )
:$echo_DEBUG_KEY ( [ TEXT ... ] )
:_echo_DEBUG_KEY ( [ TEXT ... ] )
:: used to help avoid the CMD/TCC BUG which causes a script breaking error if ()'s (more specifically, closed parens) are found within an IF() block
:: NOTE: __DEBUG and __DEBUG_KEY are GLOBAL to this function (and MUST be, because the shift command doesn't change subsequent %* uses {so, there is no way to pass vars into the function with arbitrary following TEXT})
if NOT DEFINED __DEBUG ( goto :_echo_DEBUG_KEY_RETURN )
if NOT "%__DEBUG%" == "%__DEBUG_KEY%" ( goto :_echo_DEBUG_KEY_RETURN )
if NOT DEFINED __MEfn ( goto :_echo_DEBUG_KEY_NO_MEFN )
echo %__ME%:%__MEfn%: {{DEBUG: %__DEBUG%}} %*
goto :_echo_DEBUG_KEY_RETURN
:_echo_DEBUG_KEY_NO_MEFN
echo %__ME%: {{DEBUG: %__DEBUG%}} %*
goto :_echo_DEBUG_KEY_RETURN
:_echo_DEBUG_KEY_RETURN
goto :EOF
::

::
:$$echo_item_DEBUG_KEY ( DEBUG DEBUG_KEY ME MEfn ITEM )
:$echo_item_DEBUG_KEY ( DEBUG DEBUG_KEY ME MEfn ITEM )
:_echo_item_DEBUG_KEY ( DEBUG DEBUG_KEY ME MEfn ITEM )
:: used to help avoid the CMD/TCC BUG which causes a script breaking error if ()'s (more specifically, closed parens) are found within an IF() block
:: NOTE: using a single echo'd item allows passage of other vars into the function
setlocal
set __DEBUG=%~1
set __DEBUG_KEY=%~2
set __ME=%~3
set __MEfn=%~4
set item=%~5
@call :_echo_DEBUG_KEY %item%
:_echo_item_DEBUG_KEY_RETURN
endlocal
goto :EOF
::

:::: [ end of __PREinitialize section (contains all required function dependencies) ]

::
:$$is_same_command ( ref_RETURN FILENAME1 FILENAME2 )
:$is_same_command ( ref_RETURN FILENAME1 FILENAME2 )
:_is_same_command ( ref_RETURN FILENAME1 FILENAME2 )
:: determine if FILENAME1 is the same as FILENAME2
:: RETURN == (BOOLEAN as undef/1) whether FILENAMEs are the same
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_same_command"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
:: more than 3 ARGS implies multiple parts for FILENAME1 and/or FILENAME2 (therefore, NOT testable and defined as NOT the same)
REM call :_echo_DEBUG_KEY 4thARG?="%~4"
if NOT "%~4"=="" ( goto :_is_same_command_RETURN )
:: deal with NULL extensions (if both NULL, leave alone; otherwise, use the non-NULL extension for both)
set "_f2=%~2"
set "_f3=%~3"
if "%~x2"=="" ( call :_path_of_file_in_PATH _p2 "%_f2%" "%PATHEXT%" ) else ( call :_path_in_PATH _p2 "%_f2%" )
if "%~x3"=="" ( call :_path_of_file_in_PATH _p3 "%_f3%" "%PATHEXT%" ) else ( call :_path_in_PATH _p3 "%_f3%" )
REM call :_echo_DEBUG_KEY p2="%_p2%"
REM call :_echo_DEBUG_KEY p3="%_p3%"
if /i "%_p2%"=="%_p3%" ( set "_RETval=1" )
:_is_same_command_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%~1"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
endlocal & set "%~1=%_RETval%"
goto :EOF
::

::
:$$is_similar_command ( ref_RETURN FILENAME1 FILENAME2 )
:$is_similar_command ( ref_RETURN FILENAME1 FILENAME2 )
:_is_similar_command ( ref_RETURN FILENAME1 FILENAME2 )
:: determine if FILENAME1 is similar to FILENAME2
:: RETURN == (BOOLEAN as undef/1) whether FILENAMEs are similar
:: NOTE: not _is_SAME_command; that entails parsing PATHEXT and concatenating each EXT for any argument with a NULL extension
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_similar_command"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
:: more than 3 ARGS implies multiple parts for FILENAME1 and/or FILENAME2 (therefore, NOT testable and defined as NOT the same)
if NOT "%~4"=="" ( goto :_is_similar_command_RETURN )
:: deal with NULL extensions (if both NULL, leave alone; otherwise, use the non-NULL extension for both)
set _EXT_2=%~x2
set _EXT_3=%~x3
if NOT "%_EXT_2%"=="%_EXT_3%" if "%_EXT_2%"=="" (
    call :_is_similar_command _RETval "%~2%_EXT_3%" "%~3"
    goto :_is_similar_command_RETURN
    )
if NOT "%_EXT_2%"=="%_EXT_3%" if "%_EXT_3%"=="" (
    call :_is_similar_command _RETval "%~2" "%~3%_EXT_2%"
    goto :_is_similar_command_RETURN
    )
::if /i "%~dnpx2"=="%~dnpx3" ( set "_RETval=1" )  &:: FAILS for shells executed with non-fully qualified paths (eg, subshells called with 'cmd.exe' or 'tcc')
if /i "%~$PATH:2"=="%~$PATH:3" ( set "_RETval=1" )
:_is_similar_command_RETURN
endlocal & set "%~1=%_RETval%"
goto :EOF
::

::
:$$is_exec_from_console ( ref_RETURN )
:$is_exec_from_console ( ref_RETURN )
:_is_exec_from_console ( ref_RETURN )
:: determine if script is being executed directly from the console window (rather than from an explorer)
:: RETURN == (BOOLEAN as undef/1) whether script is executed from console
:: NOTE: if %cmdcmdline% has multiple parts, the script is NOT under direct console execution [!! except for elevate or run `cmd /k ...`]
:: NOTE: ToDO: check for ...\CMD.exe or ...\CMD.exe /k [elevate or run] vs ...\CMD.exe /c [explorer or run]
:: NOTE:   ... elevate.x32.exe uses C:\Windows\SysWOW64\CMD.exe on 64-bit systems; deal with C:\Windows\System32\CMD.exe and C:\Windows\SysWOW64\CMD.exe
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_exec_from_console"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval=0"
set _RETvar=%~1
call :_is_same_command _RETval "%COMSPEC%" %cmdcmdline%
:_is_exec_from_console_RETURN
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_transient_shell ( ref_RETURN )
:$is_transient_shell ( ref_RETURN )
:_is_transient_shell ( ref_RETURN )
:: determine if script is being executed in a transient shell console window
:: RETURN == (BOOLEAN as undef/1) whether script is executed from console
:: NOTE: known possibilities: `...\CMD.exe`, `...\CMD.exe /k` [via elevate or run], `...\CMD.exe /c` [via explorer or run]
:: NOTE: 32-bit commands (eg, elevate.x32.exe) may see `C:\Windows\SysWOW64\CMD.exe` on 64-bit systems; deal with `C:\Windows\System32\CMD.exe` and `C:\Windows\SysWOW64\CMD.exe`
:: [CMD/TCC] /C == transient shell carries out the command specified by string and then terminates
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=$is_transient_console"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval=0"
set _RETvar=%~1
call :_create_list ccl_token_list %cmdcmdline%
call :_is_in_list _RETval "/c" "%ccl_token_list%"
:_is_transient_shell_RETURN
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_elevated ( ref_RETURN )
:$is_elevated ( ref_RETURN )
:_is_elevated ( ref_RETURN )
:: determine if script is operating under privilege elevation
:: RETURN == (BOOLEAN as undef/1) whether script has elevated permissions
:: NOTE: pre-VISTA OS do not have UAC limited permissions and are therefore always considered "elevated"
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_elevated"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set _RETvar=%~1
shift
::
set _RETval=1
call :_win_os_version _version_name _version_N
IF /i %_version_N% LSS 6 ( goto :_is_elevated_RETURN )
call :_is_UAC_elevated _RETval
::
:_is_elevated_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_UAC_elevated ( ref_RETURN )
:$is_UAC_elevated ( ref_RETURN )
:_is_UAC_elevated ( ref_RETURN )
:: elevation check
:: ref: <http://blogs.technet.com/jhoward/archive/2008/11/19/how-to-detect-uac-elevation-from-vbscript.aspx>[`@`](https://archive.is/nS90V)
:: ref: <http://stackoverflow.com/questions/7985755/how-to-detect-if-cmd-is-running-as-administrator-has-elevated-privileges>[`@`](https://archive.is/5uENM)
:: ref: <https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights>[`@`](https://archive.is/M1tFE)
:: RETURN == (BOOLEAN as undef/1) whether script has UAC elevated permissions
:: if VISTA+, run %SystemRoot%/System32/whoami.exe /groups and check for "Mandatory Label\High Mandatory Level" - if missing -> NOT elevated
:: using "net session" instead as a more robust method of detection
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_UAC_elevated"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set _RETvar=%~1
call :_win_os_version _version_name _version_N
IF /i %_version_N% LSS 6 ( goto :_is_UAC_elevated_RETURN )
set "ERRORLEVEL="
:: call `net session` twice to avoid corner case where `at` has been called previously
call "%SystemRoot%\\System32\\net" session >nul 2>&1
call "%SystemRoot%\\System32\\net" session >nul 2>&1
IF %ERRORLEVEL% EQU 0 ( SET "_RETval=true" )
:_is_UAC_elevated_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_devmode ( ref_RETURN )
:$is_devmode ( ref_RETURN )
:_is_devmode ( ref_RETURN )
:: Win10+ Developer Mode
:: ref: <https://stackoverflow.com/questions/41231586/how-to-detect-if-developer-mode-is-active-on-windows-10>[`@`](https://archive.is/63txT)
:: RETURN == (BOOLEAN as undef/1) whether Win10 Developer Mode is enabled
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_devmode"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set _RETvar=%~1
:: ? is check for Win10 needed?
call :_win_os_version _version_name _version_N
IF /i %_version_N% LSS 10 ( goto :_is_devmode_RETURN )
::
set "ERRORLEVEL="
for /F "tokens=1,2,3" %%g in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowDevelopmentWithoutDevLicense') do (
    if /i "%%g" == "AllowDevelopmentWithoutDevLicense" ( set "devmode=%%i" )
    )
IF %ERRORLEVEL% EQU 0 IF DEFINED devmode IF /i NOT "%devmode%"=="0x0" ( SET "_RETval=true" )
:_is_devmode_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$has_privilege ( ref_RETURN PRIV_NAME )
:$has_privilege ( ref_RETURN PRIV_NAME )
:_has_privilege ( ref_RETURN PRIV_NAME )
:: privilege check
:: URLref: http://stackoverflow.com/questions/11607389/how-to-view-user-privileges-using-windows-cmd
:: URLref: https://social.technet.microsoft.com/Forums/windowsserver/en-US/e24a35b3-fb72-4918-8e51-562e2ad8d8f5/what-is-the-state-column-returned-by-whoami-priv?forum=winserversecurity @@ https://archive.today/uZMlX
:: RETURN == (BOOLEAN as undef/1) whether script has privilege by the name PRIV_NAME
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_has_privilege"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set _RETvar=%~1
set priv_name=%~2 &:: privilege name to search
::call :_win_os_version _version_name _version_N
::IF /i %_version_N% LSS 6 ( goto :_is_UAC_elevated_RETURN )
set "ERRORLEVEL="
call "%SystemRoot%\\System32\\whoami" /priv | call "%SystemRoot%\\System32\\FINDSTR" /IL /C:"%priv_name%" > NUL
IF %ERRORLEVEL% EQU 0 ( SET "_RETval=true" )
:_has_privilege_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_exit_pause_needed ( ref_PAUSE_FLAG [in/out] )
:$is_exit_pause_needed ( ref_PAUSE_FLAG [in/out] )
:_is_exit_pause_needed ( ref_PAUSE_FLAG [in/out] )
:: determine if a pause is needed before script exit (if called from explorer via a transient shell, etc)
:: PAUSE_FLAG may be preset to a value (0==false/non-0==true) prior to calling this function is called to allow executor control of pause on exit, overriding normal logic as noted here
:: %PAUSE_FLAG% == not defined :: normal logic, PAUSE needed if script executed in a transient console shell
:: %PAUSE_FLAG% == 0 :: override, no PAUSE needed
:: %PAUSE_FLAG% == "1, will pause at top level", no PAUSE needed in current or called scripts
:: %PAUSE_FLAG% == 1 or <OTHER> :: override, PAUSE needed, but set return value to signal value ("1, will pause at top level")
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_exit_pause_needed"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval=1, will pause at top level"
set _RETvar=%~1
call set _INPUT_PAUSE=%%%_RETvar%%%
if DEFINED _INPUT_PAUSE ( if /I "%_INPUT_PAUSE%"=="0" ( set "_RETval=0" & goto :_is_exit_pause_needed_RETURN ) )
if DEFINED _INPUT_PAUSE ( if /I "%_INPUT_PAUSE%"=="1, will pause at top level" ( set "_RETval=0" & goto :_is_exit_pause_needed_RETURN ) )
if DEFINED _INPUT_PAUSE ( goto :_is_exit_pause_needed_RETURN )
call :_is_transient_shell _TRANSIENT
if NOT DEFINED _TRANSIENT ( set "_RETval=0" )
:_is_exit_pause_needed_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY "%_RETvar%"="%_INPUT_PAUSE%"
REM call :_echo_DEBUG_KEY _TRANSIENT="%_TRANSIENT%"
REM call :_echo_DEBUG_KEY _is_exit_pause_needed="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$win_os_version ( ref_RETURN_NAME ref_RETURN_N [ [ [ [ [ref_RETURN_V] ref_RETURN_V_Major ] ref_RETURN_V_minor ] ref_RETURN_V_build ] ref_RETURN_arch ] )
:$win_os_version ( ref_RETURN_NAME ref_RETURN_N [ [ [ [ [ref_RETURN_V] ref_RETURN_V_Major ] ref_RETURN_V_minor ] ref_RETURN_V_build ] ref_RETURN_arch ] )
:_win_os_version ( ref_RETURN_NAME ref_RETURN_N [ [ [ [ [ref_RETURN_V] ref_RETURN_V_Major ] ref_RETURN_V_minor ] ref_RETURN_V_build ] ref_RETURN_arch ] )
:: ToDO: add notes about continuing maintainence needs for increasing Windows versions
:: ToDO: make more robust: 1) check for existence of used EXEs; 2) check for earlier versions
:: ToDO: ? change "XP.x64" to "XP" with N_bit == "64"
:: ToDO: add _ARCH, _V, _V_b, _V_Mm as optional return values
:: find Windows OS version (for Windows versions from Windows 2000 on)
:: RETURN_NAME == current OS name ["7", "2008.R2", "2008", "Vista", "2003", "XP.x64", "XP", NULL]
:: RETURN_N == current OS version [ 0 == unknown ]
:: URLref: http://serverfault.com/questions/124848/using-systeminfo-to-get-the-os-name
:: URLref: http://stackoverflow.com/questions/1792740/how-to-tell-what-version-of-windows-and-or-cmd-exe-a-batch-file-is-running-on
:: URLref: http://pario.no/2011/06/19/list-installed-windows-updates-using-wmic @@ http://www.webcitation.org/66a7J58OK
:: URLref: http://tech-wreckblog.blogspot.com/2009/11/wmic-command-line-kung-fu.html @@ http://www.webcitation.org/66a7MbiGf
:: URLref: http://roddotnet.blogspot.com/2008/08/how-to-detect-windows-vista-in-batch.html
:: URLref: [MS Windows Version Numbers] http://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx @@ http://www.webcitation.org/66FzghSQU
:: URLref: http://malektips.com/xp_dos_0025.html @@ http://www.webcitation.org/66G00alzC
:: URLref: http://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions @@ https://archive.today/JtQ5J
:: NOTE: "systeminfo 2> nul" is used to avoid spurious progress output from systeminfo
:: ToDO: investigate use of "%SystemRoot%\System32\cmd.exe" /x/d/c "VER instead
:: ToDO: investigate improved efficiency if VER and systeminfo could be executed just once with value saved into a variable with "ECHO %VAR% | findstr ..."
:: ToDO: DONE: change to use wmic
:: NOTE: not using FOR ... in order to use this same function in Autorun :: might be able to use for ('cmd /d ...')
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_win_os_version"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval_NAME="
set _RETval_N=0
set _RETvar=%~1
shift
set _RETvar_N=%~1
shift
set _RETvar_V=%~1
shift
set _RETvar_V_Major=%~1
shift
set _RETvar_V_minor=%~1
shift
set _RETvar_V_build=%~1
shift
set _RETvar_ARCH=%~1
:: get temp file
call :_tempfile _win_os_version_TEMPFILE "%__MEfn%" .txt
::*::
:: URLref: http://serverfault.com/questions/124848/using-systeminfo-to-get-the-os-name
:: URLref: http://stackoverflow.com/questions/1792740/how-to-tell-what-version-of-windows-and-or-cmd-exe-a-batch-file-is-running-on
:: URLref: http://pario.no/2011/06/19/list-installed-windows-updates-using-wmic @@ http://www.webcitation.org/66a7J58OK
:: URLref: http://tech-wreckblog.blogspot.com/2009/11/wmic-command-line-kung-fu.html @@ http://www.webcitation.org/66a7MbiGf
::
:: default values for unknown windows version: version=NULL
SET _win_os_version=
SET _win_os_version_ARCH=32
SET _win_os_version_N=0
SET _win_os_version_FIND=%SystemRoot%\\System32\\FINDSTR
SET _win_os_version_INFO=%SystemRoot%\\System32\\WBEM\\wmic
"%SystemRoot%\System32\cmd.exe" /x/d/c "echo. | call "%_win_os_version_INFO%" os get osarchitecture /format:value 2> NUL | call "%_win_os_version_FIND%" /IR /C:"OSArchitecture=64.*" > NUL"
IF "%ERRORLEVEL%" == "0" (
    SET "_win_os_version_ARCH=64"
    )
"%SystemRoot%\System32\cmd.exe" /x/d/c "VER | call "%_win_os_version_FIND%" /IR /C:"Version *" > "%_win_os_version_TEMPFILE%""
set /p _win_os_version_CMDver= < "%_win_os_version_TEMPFILE%" > NUL
for /f "usebackq tokens=2 delims=[]" %%G in ('%_win_os_version_CMDver%') do set _win_os_version_V=%%G
set _win_os_version_V=%_win_os_version_V:Version =%
for /f "usebackq tokens=1,2,3* delims=." %%G in ('%_win_os_version_V%') do (
        set _win_os_version_N=%%G
        set _win_os_version_V_Mm=%%G.%%H
        set _win_os_version_V_Major=%%G
        set _win_os_version_V_minor=%%H
        set _win_os_version_V_build=%%I
        )
:_win_os_version_check_5_0
if NOT "%_win_os_version_V_Mm%" == "5.0" ( goto :_win_os_version_check_5_0_DONE )
:: : Windows 2000
SET "_win_os_version=2000"
goto :_win_os_version_FOUND
:_win_os_version_check_5_0_DONE
:_win_os_version_check_5_1
if NOT "%_win_os_version_V_Mm%" == "5.1" ( goto :_win_os_version_check_5_1_DONE )
:: : Windows XP
SET "_win_os_version=XP"
goto :_win_os_version_FOUND
:_win_os_version_check_5_1_DONE
:_win_os_version_check_5_2
if NOT "%_win_os_version_V_Mm%" == "5.2" ( goto :_win_os_version_check_5_2_DONE )
:: : Windows Server 2003 & Windows XP 64-bit
SET "_win_os_version=2003"
"%SystemRoot%\System32\cmd.exe" /x/d/c "echo. | call "%_win_os_version_INFO%" os get caption /format:value 2> NUL | call "%_win_os_version_FIND%" /IR /C:"Caption=.*Windows.XP.*" > NUL"
IF "%ERRORLEVEL%" == "0" (
    SET "_win_os_version=XP.x64"
    )
goto :_win_os_version_FOUND
:_win_os_version_check_5_2_DONE
:_win_os_version_check_6_0
if NOT "%_win_os_version_V_Mm%" == "6.0" ( goto :_win_os_version_check_6_0_DONE )
:: : Windows Vista & Windows Server 2008
SET "_win_os_version=Vista"
"%SystemRoot%\System32\cmd.exe" /x/d/c "echo. | call "%_win_os_version_INFO%" os get caption /format:value 2> NUL | call "%_win_os_version_FIND%" /IR /C:"Caption=.*Server.*" > NUL"
IF "%ERRORLEVEL%" == "0" (
    SET "_win_os_version=2008"
    )
goto :_win_os_version_FOUND
:_win_os_version_check_6_0_DONE
:_win_os_version_check_6_1
if NOT "%_win_os_version_V_Mm%" == "6.1" ( goto :_win_os_version_check_6_1_DONE )
:: : Windows 7 & Windows Server 2008 R2
SET "_win_os_version=7"
"%SystemRoot%\System32\cmd.exe" /x/d/c "echo. | call "%_win_os_version_INFO%" os get caption /format:value 2> NUL | call "%_win_os_version_FIND%" /IR /C:"Caption=.*Server.*" > NUL"
IF "%ERRORLEVEL%" == "0" (
    SET "_win_os_version=2008.R2"
    )
goto :_win_os_version_FOUND
:_win_os_version_check_6_1_DONE
:_win_os_version_check_6_2
if NOT "%_win_os_version_V_Mm%" == "6.2" ( goto :_win_os_version_check_6_2_DONE )
:: : Windows 8 & Windows Server 2012
SET "_win_os_version=8"
"%SystemRoot%\System32\cmd.exe" /x/d/c "echo. | call "%_win_os_version_INFO%" os get caption /format:value 2> NUL | call "%_win_os_version_FIND%" /IR /C:"Caption=.*Server.*" > NUL"
IF "%ERRORLEVEL%" == "0" (
    SET "_win_os_version=2012"
    )
goto :_win_os_version_FOUND
:_win_os_version_check_6_2_DONE
:_win_os_version_check_6_3
if NOT "%_win_os_version_V_Mm%" == "6.3" ( goto :_win_os_version_check_6_3_DONE )
:: : Windows 8.1 & Windows Server 2012 R2
SET "_win_os_version=8.1"
"%SystemRoot%\System32\cmd.exe" /x/d/c "echo. | call "%_win_os_version_INFO%" os get caption /format:value 2> NUL | call "%_win_os_version_FIND%" /IR /C:"Caption=.*Server.2008.R2.*" > NUL"
IF "%ERRORLEVEL%" == "0" (
    SET "_win_os_version=2012.R2"
    )
goto :_win_os_version_FOUND
:_win_os_version_check_6_3_DONE
:_win_os_version_check_6_4
if NOT "%_win_os_version_V_Mm%" == "6.4" ( goto :_win_os_version_check_6_4_DONE )
:: : Windows 10
SET "_win_os_version=10"
goto :_win_os_version_FOUND
:_win_os_version_check_6_4_DONE
:_win_os_version_check_10
if NOT "%_win_os_version_V_Mm%" == "10.0" ( goto :_win_os_version_check_10_0_DONE )
:: : Windows 10
SET "_win_os_version=10"
goto :_win_os_version_FOUND
:_win_os_version_check_10_0_DONE
:_win_os_version_check_11+
:: : Windows 11+
SET "_win_os_version=11+"
goto :_win_os_version_FOUND
:_win_os_version_check_11+_DONE
:_win_os_version_FIND_DONE
:_win_os_version_FOUND
::*::
:_win_os_version_RETURN
if EXIST "%_win_os_version_TEMPFILE%" ( erase "%_win_os_version_TEMPFILE%" > NUL )
REM call :_echo_DEBUG_KEY _win_os_version="%_win_os_version%"
REM call :_echo_DEBUG_KEY _win_os_version_N="%_win_os_version_N%"
::( endlocal
::  ( if NOT 1.0 == 1 (set "%_RETvar%=%_win_os_version%" & set "%_RETvar_N%=%_win_os_version_N%"
::          ) else (set "%_RETvar=%_win_os_version" & set "%_RETvar_N=%_win_os_version_N"
::              )
::      )
::@rem :::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
( endlocal
set %_RETvar%^=%_win_os_version%
set %_RETvar_N%^=%_win_os_version_N%
if NOT "%_RETvar_V%"=="" (set %_RETvar_V%^=%_win_os_version_V%)
if NOT "%_RETvar_V_Major%"=="" (set %_RETvar_V_Major%^=%_win_os_version_V_Major%)
if NOT "%_RETvar_V_minor%"=="" (set %_RETvar_V_minor%^=%_win_os_version_V_minor%)
if NOT "%_RETvar_V_build%"=="" (set %_RETvar_V_build%^=%_win_os_version_V_build%)
if NOT "%_RETvar_ARCH%"=="" (set %_RETvar_arch%^=%_win_os_version_ARCH%)
)
goto :EOF
::

::
:$$echo_noLF ( [ TEXT ] )
:$echo_noLF ( [ TEXT ] )
:_echo_noLF ( [ TEXT ] )
setlocal
if 01 == 1.0 ( goto :_echo_noLF_TCC )
:_echo_noLF_CMD
echo|set /p OUTPUT=%*
goto :_echo_noLF_RETURN
:_echo_noLF_TCC
echos %*
goto :_echo_noLF_RETURN
:_echo_noLF_RETURN
endlocal
goto :EOF
::

::
:$$echo_VERBOSE ( [ TEXT ... ] )
:: NOTE: __VERBOSE is GLOBAL to this function (and MUST be, because the shift command doesn't change subsequent %* uses {so, there is no way to pass vars into the function with arbitrary following TEXT})
if NOT DEFINED __VERBOSE ( goto :_echo_VERBOSE_RETURN )
echo %__ME%: %*
goto :_echo_VERBOSE_RETURN
:_echo_VERBOSE_RETURN
goto :EOF
::

::
:$$simple_dequote ( ref_RETURN ITEM )
:$simple_dequote ( ref_RETURN ITEM )
:_simple_dequote ( ref_RETURN ITEM )
:: strip outer double quotes from ITEM (NO attempt to check for or remove balanced quotes)
:: RETURN = dequoted ITEM
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_simple_dequote"
set "_RETvar=%~1"
set "_RETval=%~2"
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$length_of ( ref_RETURN ITEM )
:$length_of ( ref_RETURN ITEM )
:_length_of ( ref_RETURN ITEM )
:: determine length of ITEM
:: RETURN = length of ITEM
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_length_of"
set "_RETvar=%~1"
set "item=%~2"
set length=0
:_length_of_LOOP
if DEFINED item (
    set item=%item:~1%
    set /a length += 1
    goto :_length_of_LOOP
)
:_length_of_RETURN
set "_RETval=%length%"
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$trim ( ref_RETURN ITEM CHARSET )
:$trim ( ref_RETURN ITEM CHARSET )
:_trim ( ref_RETURN ITEM CHARSET )
:: trim characters from ITEM
:: RETURN == ITEM with CHARSET characters removed (from both sides)
:: NOTE: CHARSET defaults to "<SPACE>" if NULL/missing
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_trim"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
if 1.0 == 01 (
    set _RETval=%@unquotes[%2]
    )
set "charset=%~3"
if 1.0 == 01 (
    set charset=%@unquotes[%3]
    )
if NOT DEFINED charset ( set "charset= " )
REM call :_echo_DEBUG_KEY _RETVal/item="%_RETval%"
REM call :_echo_DEBUG_KEY charset="%charset%"
call :_ltrim _RETval "%_RETval%" "%charset%"
call :_rtrim _RETval "%_RETval%" "%charset%"
:_trim_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$ltrim ( ref_RETURN ITEM [CHARSET] )
:$ltrim ( ref_RETURN ITEM [CHARSET] )
:_ltrim ( ref_RETURN ITEM [CHARSET] )
:: trim characters in CHARSET from left-side of ITEM
:: RETURN = ITEM with leftmost CHARSET characters removed
:: NOTE: CHARSET defaults to "<SPACE>" if NULL/missing
:: URLrefs: [Variable editing] http://ss64.com/nt/syntax-substring.html, [How to trim whitespace from a string] http://www.experts-exchange.com/OS/Microsoft_Operating_Systems/MS_DOS/Q_23816304.html
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_ltrim"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "item=%~2"
if 1.0 == 01 (
    set item=%@unquotes[%2]
    )
set "charset=%~3"
if 1.0 == 01 (
    set charset=%@unquotes[%3]
    )
if NOT DEFINED charset ( set "charset= " )
REM call :_echo_DEBUG_KEY *={%*}
REM call :_echo_DEBUG_KEY item="%item%"
REM call :_echo_DEBUG_KEY charset="%charset%"
:: change any internal double quotes to chr(255) (avoids syntax errors during the character comparison and removal process) [ NOTE: may have internal double quotes, so no outer quotes for set; this also creates a problem with internal ()'s if the set is enclosed in a block, so use a goto around it as needed]
if NOT DEFINED item ( goto :_ltrim_LOOP_ch )
set "item=%item:"=¸%"
set "charset=%charset:"=¸%"
set "chars=%charset%"
REM call :_echo_DEBUG_KEY LOOP.item="%item%"
REM call :_echo_DEBUG_KEY charset="%charset%"
REM call :_echo_DEBUG_KEY LOOP.chars="%chars%"
:_ltrim_LOOP_ch
set "ch="
if DEFINED chars ( set "ch=%chars:~0,1%" & set "chars=%chars:~1%" )
if NOT DEFINED ch ( goto :_ltrim_LOOP_DONE )
:_ltrim_LOOP_removal
if NOT DEFINED item ( goto :_ltrim_LOOP_DONE )
set "first_ch="
if DEFINED item (
    set "first_ch=%item:~0,1%"
    )
REM call :_echo_DEBUG_KEY LOOP.item="%item%"
REM call :_echo_DEBUG_KEY LOOP.item.first_ch="%first_ch%"
if /i "%first_ch%" == "%ch%" (
    set "item=%item:~1%"
    set "chars=%charset%"
    goto :_ltrim_LOOP_removal
    )
goto :_ltrim_LOOP_ch
:_ltrim_LOOP_DONE
:_ltrim_RETURN
if NOT DEFINED item ( goto :_ltrim_RETURN_translate_DONE )
:: return any double quotes to ITEM
set item=%item:¸=^"%
:_ltrim_RETURN_translate_DONE
set _RETval=%item%
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$translate_charset ( ref_RETURN ITEM CHARSET TRANS )
:$translate_charset ( ref_RETURN ITEM CHARSET TRANS )
:_translate_charset ( ref_RETURN ITEM CHARSET TRANS )
:: change all CHARSET characters to TRANS in ITEM
:: RETURN = ITEM with all characters in CHARSET changed to TRANS
:: NOTE: ITEM should have no internal double quotes; if present, double quotes are translated to single quotes(? TRUE, ?needed for CMD or TCC?) for the RETURN value
setlocal
set "__DEBUG_KEY=@1"
set "__MEfn=translate_charset"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "item=%~2"
set "charset_init=%~3"
set "trans=%~4"
REM call :_echo_DEBUG_KEY item="%item%"
REM call :_echo_DEBUG_KEY charset="%charset%"
REM call :_echo_DEBUG_KEY trans="%trans%"
:: change any internal double quotes to chr(255) (avoids syntax errors during the character comparison and removal process) [ NOTE: may have internal double quotes, so no outer quotes for set; this also creates a problem with internal ()'s if the set is enclosed in a block, so use a goto around it as needed]
if NOT DEFINED item ( goto :_translate_charset_LOOP_ch )
set "item=%item:^"=¸%"
::
:translate_charset_LOOP
set "item_dest="
:_translate_charset_LOOP_item
if NOT DEFINED item ( goto :_translate_charset_LOOP_item_DONE )
set "first_ch=%item:~0,1%"
set "item=%item:~1%"
set "charset=%charset_init%"
REM call :_echo_DEBUG_KEY charset="%charset%"
REM call :_echo_DEBUG_KEY first_ch="%first_ch%"
:_translate_charset_LOOP_ch
set "ch="
if DEFINED charset ( set "ch=%charset:~0,1%" & set "charset=%charset:~1%" )
if NOT DEFINED ch ( goto :_translate_charset_LOOP_ch_DONE )
REM call :_echo_DEBUG_KEY charset="%charset%"
REM call :_echo_DEBUG_KEY ch="%ch%"
:_translate_charset_LOOP_change
if NOT "%first_ch%" == "%ch%" ( goto :_translate_charset_LOOP_ch )
set "item_dest=%item_dest%%trans%"
goto :_translate_charset_LOOP_item
:_translate_charset_LOOP_ch_DONE
set "item_dest=%item_dest%%first_ch%"
goto :_translate_charset_LOOP_item
:_translate_charset_LOOP_item_DONE
set "item=%item_dest%"
REM call :_echo_DEBUG_KEY item="%item%"
:_translate_charset_LOOP_DONE
::
:_translate_charset_RETURN
:: return any double quotes to ITEM
set "item=%item:¸=^"%"
set "_RETval=%item%"
REM call :_echo_DEBUG_KEY _RETVAL="%_RETVAL%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$translate_charset_nocase ( ref_RETURN ITEM CHARSET TRANS )
:$translate_charset_nocase ( ref_RETURN ITEM CHARSET TRANS )
:_translate_charset_nocase ( ref_RETURN ITEM CHARSET TRANS )
:: change all CHARSET characters to TRANS in ITEM
:: RETURN = ITEM with all characters in CHARSET changed to TRANS
:: NOTE: ITEM should have no internal double quotes; if present, double quotes are translated to single quotes(? TRUE, ?needed for CMD or TCC?) for the RETURN value
setlocal
set "__DEBUG_KEY=@1"
set "__MEfn=translate_charset_nocase"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "item=%~2"
set "charset_init=%~3"
set "trans=%~4"
REM call :_echo_DEBUG_KEY item="%item%"
REM call :_echo_DEBUG_KEY charset="%charset%"
REM call :_echo_DEBUG_KEY trans="%trans%"
:: change any internal double quotes to chr(255) (avoids syntax errors during the character comparison and removal process) [ NOTE: may have internal double quotes, so no outer quotes for set; this also creates a problem with internal ()'s if the set is enclosed in a block, so use a goto around it as needed]
if NOT DEFINED item ( goto :_translate_charset_nocase_LOOP_ch )
set "item=%item:^"=¸%"
::
:translate_charset_LOOP
set "item_dest="
:_translate_charset_nocase_LOOP_item
if NOT DEFINED item ( goto :_translate_charset_nocase_LOOP_item_DONE )
set "first_ch=%item:~0,1%"
set "item=%item:~1%"
set "charset=%charset_init%"
REM call :_echo_DEBUG_KEY charset="%charset%"
REM call :_echo_DEBUG_KEY first_ch="%first_ch%"
:_translate_charset_nocase_LOOP_ch
set "ch="
if DEFINED charset ( set "ch=%charset:~0,1%" & set "charset=%charset:~1%" )
if NOT DEFINED ch ( goto :_translate_charset_nocase_LOOP_ch_DONE )
REM call :_echo_DEBUG_KEY charset="%charset%"
REM call :_echo_DEBUG_KEY ch="%ch%"
:_translate_charset_nocase_LOOP_change
if /i "%first_ch%" NEQ "%ch%" ( goto :_translate_charset_nocase_LOOP_ch )
set "item_dest=%item_dest%%trans%"
goto :_translate_charset_nocase_LOOP_item
:_translate_charset_nocase_LOOP_ch_DONE
set "item_dest=%item_dest%%first_ch%"
goto :_translate_charset_nocase_LOOP_item
:_translate_charset_nocase_LOOP_item_DONE
set "item=%item_dest%"
REM call :_echo_DEBUG_KEY item="%item%"
:_translate_charset_nocase_LOOP_DONE
::
:_translate_charset_nocase_RETURN
:: return any double quotes to ITEM
set "item=%item:¸=^"%"
set "_RETval=%item%"
REM call :_echo_DEBUG_KEY _RETVAL="%_RETVAL%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_matching_item ( ref_RETURN ITEM_X [ ITEMs ... ] )
:$is_matching_item ( ref_RETURN ITEM_X [ ITEMs ... ] )
:_is_matching_item ( ref_RETURN ITEM_X [ ITEMs ... ] )
:: determine if ITEM_X matched any of the ITEMs
:: RETURN == false/true (aka ITEM# [1+]) [ false == NULL, true == 1+ ]
:: NOTE: NULL items as "" or """" are supported
:: NOTE: ITEM comparisons are case-independent
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_matching_item"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
shift
set "item_x=%~1"
if "%item_x%" EQU """" ( set "item_x=" )
set "item_n=0"
REM call :_echo_DEBUG_KEY item_n="%item_n%"
:_is_matching_item_LOOP
shift
set item_raw=%1
REM call :_echo_DEBUG_KEY item_raw='%item_raw%'
if NOT DEFINED item_raw ( set "item_n=" & goto :_is_matching_item_LOOP_DONE )
set "item=%~1"
if "%item%" EQU """" ( set "item=" )
set /a item_n += 1 > nul
REM call :_echo_DEBUG_KEY item="%item%"
REM call :_echo_DEBUG_KEY item_n="%item_n%"
if DEFINED item_raw ( if /I "%item%" NEQ "%item_x%" ( goto :_is_matching_item_LOOP ) )
:_is_matching_item_LOOP_DONE
:_is_matching_item_RETURN
set "_RETval=%item_n%"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: done ]
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$remove_matching_item ( ref_RETURN ITEM_X [ ITEMs ... ] )
:$remove_matching_item ( ref_RETURN ITEM_X [ ITEMs ... ] )
:_remove_matching_item ( ref_RETURN ITEM_X [ ITEMs ... ] )
:: remove ITEM_X from list of ITEMs
:: RETURN == SET of ITEMs with ITEM_X removed (all occurances)
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_remove_matching_item"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
shift
set "item_x=%~1"
if "%item_x%" EQU """" ( set "item_x=" )
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
REM call :_echo_DEBUG_KEY item_x="%item_x%"
:_remove_matching_item_LOOP
shift
set item_raw=%1
REM call :_echo_DEBUG_KEY item_raw="%item_raw%"
if NOT DEFINED item_raw ( goto :_remove_matching_item_LOOP_DONE )
set "item=%~1"
if "%item%" EQU """" ( set "item=" )
REM call :_echo_DEBUG_KEY item="%item%"
if /I "%item%" NEQ "%item_x%" ( call :_append_to_list _RETval "%item%" "%_RETval%" )
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
goto :_remove_matching_item_LOOP
:_remove_matching_item_LOOP_DONE
:_remove_matching_item_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$create_list_without_NULLs ( ref_RETURN [ ITEMs ... ] )
:$$create_list ( ref_RETURN [ ITEMs ... ] )
:$create_list ( ref_RETURN [ ITEMs ... ] )
:_create_list ( ref_RETURN [ ITEMs ... ] )
:: RETURN == LIST of ITEMs
setlocal
set "__DEBUG_KEY=@c"
set "__MEfn=_create_list"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:_create_list_LOOP
shift
set item_raw=%1
if NOT DEFINED item_raw ( goto :_create_list_LOOP_DONE )
set item=%~1
if "%item%" EQU """" ( set "item=" )
REM call :_echo_DEBUG_KEY item_N="%item%"
if NOT DEFINED _RETval (
    set "_RETval=%item%"
    ) else (
    set "_RETval=%_RETval%;%item%"
    )
goto :_create_list_LOOP
:_create_list_LOOP_DONE
:_create_list_RETURN
if NOT DEFINED _RETval ( set "_RETval=""" )
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$create_list_with_NULLs ( ref_RETURN [ ITEMs ... ] )
:$create_list_with_NULLs ( ref_RETURN [ ITEMs ... ] )
:_create_list_with_NULLs ( ref_RETURN [ ITEMs ... ] )
:: RETURN == LIST of ITEMs
setlocal
set "__DEBUG_KEY=@c"
set "__MEfn=_create_list_with_NULLs"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "last_item_NULL="
:_create_list_with_NULLs_LOOP
shift
set item_raw=%1
if NOT DEFINED item_raw ( goto :_create_list_with_NULLs_LOOP_DONE )
set "item=%~1"
if "%item%" EQU """" ( set "item=" )
REM call :_echo_DEBUG_KEY item_N="%item%"
if NOT DEFINED _RETval (
    if DEFINED last_item_NULL (
        set "_RETval=%_RETval%;%item%"
        ) else (
        set "_RETval=%item%"
        )
    ) else (
    set "_RETval=%_RETval%;%item%"
    )
set "last_item_NULL="
if NOT DEFINED item ( set "last_item_NULL=1" )
goto :_create_list_with_NULLs_LOOP
:_create_list_with_NULLs_LOOP_DONE
:_create_list_with_NULLs_RETURN
if NOT DEFINED _RETval ( set "_RETval=""" )
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$list_to_items ( ref_RETURN LIST )
:: return separated LIST elements
:: RETURN == separated LIST ITEM elements
setlocal
set "_RETval="
set "_RETvar=%~1"
set "list=%~2"
if NOT DEFINED list ( goto :_list_to_items_DONE )
call :_first_of arg "%list%"
call :_remove_first list "%list%"
call :$$count_of_items N %arg%
if NOT "%N%"=="1" set arg="%arg%"
set _RETval=%arg%
:_list_to_items_LOOP
if NOT DEFINED list ( goto :_list_to_items_DONE )
call :_first_of arg "%list%"
call :_remove_first list "%list%"
call :$$count_of_items N %arg%
if NOT "%N%"=="1" set arg="%arg%"
set _RETval=%_RETval% %arg%
goto :_list_to_items_LOOP
:_list_to_items_DONE
:_list_to_items_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$count_of ( ref_RETURN [ LIST ] )
:: return number of ITEMs within LIST
:: RETURN == number of ITEM(s) within LIST
setlocal
set "_RETval=0"
set "_RETvar=%~1"
set "list=%~2"
call :$$count_of_items _RETval "%list:;=" "%"
:$$count_of_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$count_of_items ( ref_RETURN [ ITEMs ... ] )
:: return separated LIST elements
:: RETURN == number of ITEM(s)
setlocal
set "_RETval=0"
set "_RETvar=%~1"
:$$count_of_items_LOOP
shift
set item_raw=%1
if NOT DEFINED item_raw ( goto :$$count_of_items_LOOP_DONE )
set /a _RETval += 1
goto :$$count_of_items_LOOP
:$$count_of_items_LOOP_DONE
:$$count_of_items_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_in_list ( ref_RETURN ITEM LIST )
:$is_in_list ( ref_RETURN ITEM LIST )
:_is_in_list ( ref_RETURN ITEM LIST )
:: determine if ITEM is within LIST
:: RETURN == (BOOLEAN: undef/1+ (ITEM# [1+])) whether ITEM is contained within the LIST
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_in_list"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set _RETvar=%~1
set "list=%~3"
set "item=%~2"
REM call :_echo_DEBUG_KEY list="%list%"
REM call :_echo_DEBUG_KEY item="%item%"
if DEFINED list ( call :_is_matching_item _RETval "%item%" "%list:;=" "%" )
:_is_in_list_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$prepend_to_list ( ref_RETURN ITEM LIST )
:$prepend_to_list ( ref_RETURN ITEM LIST )
:_prepend_to_list ( ref_RETURN ITEM LIST )
:: RETURN == LIST with ITEM prepended
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_prepend_to_list"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set _RETvar=%~1
set list=%~3
set item=%~2
if "%item%" EQU """" ( set "item=" )
set "_RETval=%item%"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
REM call :_echo_DEBUG_KEY list="%list%"
REM call :_echo_DEBUG_KEY item="%item%"
if NOT DEFINED list ( goto :_prepend_to_list_RETURN )
if "%list%" EQU """" ( set "list=" )
set "_RETval=%item%;%list%"
REM call :_echo_DEBUG_KEY 2
:_prepend_to_list_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
if NOT DEFINED _RETval ( set "_RETval=""" )
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$append_to_list ( ref_RETURN ITEM LIST )
:$append_to_list ( ref_RETURN ITEM LIST )
:_append_to_list ( ref_RETURN ITEM LIST )
:: RETURN == LIST with ITEM appended
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_append_to_list"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set _RETvar=%~1
set "list=%~3"
set "item=%~2"
if "%item%" EQU """" ( set "item=" )
set "_RETval=%item%"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY list="%list%"
REM call :_echo_DEBUG_KEY item="%item%"
if NOT DEFINED list ( goto :_append_to_list_RETURN )
if "%list%" EQU """" ( set "list=" )
set "_RETval=%list%;%item%"
:_append_to_list_RETURN
if NOT DEFINED _RETval ( set "_RETval=""" )
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$prepend_to_set ( ref_RETURN ITEM SET )
:$prepend_to_set ( ref_RETURN ITEM SET )
:_prepend_to_set ( ref_RETURN ITEM SET )
:: RETURN == SET/LIST with ITEM prepended (if not already in SET/LIST)
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_prepend_to_set"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set _RETvar=%~1
set list=%~3
set item=%~2
set _RETval=%list%
REM call :_echo_DEBUG_KEY list="%list%"
REM call :_echo_DEBUG_KEY item="%item%"
call :_is_in_list IN_list "%item%" "%list%"
REM call :_echo_DEBUG_KEY 1
if NOT DEFINED IN_list ( call :_prepend_to_list _RETval "%item%" "%list%" )
:_prepend_to_set_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$append_to_set ( ref_RETURN ITEM SET )
:$append_to_set ( ref_RETURN ITEM SET )
:_append_to_set ( ref_RETURN ITEM SET )
:: RETURN == SET/LIST with ITEM appended (if not already in SET/LIST)
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_append_to_set"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set _RETvar=%~1
set "list=%~3"
set "item=%~2"
set "_RETval=%list%"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY list="%list%"
REM call :_echo_DEBUG_KEY item="%item%"
call :_is_in_list IN_list "%item%" "%list%"
REM call :_echo_DEBUG_KEY IN_list="%IN_list%"
if NOT DEFINED IN_list ( call :_append_to_list _RETval "%item%" "%list%" )
:_append_to_set_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$prepend_to_pathlist ( ref_RETURN ITEM PATHLIST )
:$prepend_to_pathlist ( ref_RETURN ITEM PATHLIST )
:_prepend_to_pathlist ( ref_RETURN ITEM PATHLIST )
:: NOTE: PATHLIST is treated as a SET of PATHs
:: RETURN == PATHLIST with ITEM prepended (if not already in PATHLIST)
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_prepend_to_pathlist"
set _RETvar=%~1
set list=%~3
set item=%~2
if "%item%" EQU """" ( set "item=" )
call :_rtrim item "%item%" "\"
set _RETval=%list%
if DEFINED item ( call :_prepend_to_set _RETval "%item%" "%list%" )
:_prepend_to_pathlist_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$append_to_pathlist ( ref_RETURN ITEM PATHLIST )
:$append_to_pathlist ( ref_RETURN ITEM PATHLIST )
:_append_to_pathlist ( ref_RETURN ITEM PATHLIST )
:: NOTE: PATHLIST is treated as a SET of PATHs
:: RETURN == PATHLIST with ITEM appended (if not already in PATHLIST)
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_append_to_pathlist"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set _RETvar=%~1
set "list=%~3"
set "item=%~2"
if "%item%" EQU """" ( set "item=" )
call :_rtrim item "%item%" "\"
set "_RETval=%list%"
REM call :_echo_DEBUG_KEY item="%item%"
REM call :_echo_DEBUG_KEY list="%list%"
if DEFINED item ( call :_append_to_set _RETval "%item%" "%list%" )
:_append_to_pathlist_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$remove_from_list ( ref_RETURN ITEM LIST )
:$remove_from_list ( ref_RETURN ITEM LIST )
:_remove_from_list ( ref_RETURN ITEM LIST )
:: RETURN == LIST with ITEM removed (all occurances)
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_remove_from_list"
set "_RETval="
set _RETvar=%~1
set "list=%~3"
set "item=%~2"
if DEFINED list ( call :_remove_matching_item _RETval "%item%" "%list:;=" "%" )
:_remove_from_list_RETURN
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$create_pathlist ( ref_RETURN [ ITEMs ... ] )
:$create_pathlist ( ref_RETURN [ ITEMs ... ] )
:_create_pathlist ( ref_RETURN [ ITEMs ... ] )
:: NOTE: PATHLIST is a SET of PATHs (no NULL PATHs; PATHs are normalized ITEMs [no trailing backslashes] )
:: RETURN == PATHLIST of PATHs
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_create_pathlist"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval="
:_create_pathlist_LOOP
shift
set item_raw=%1
if NOT DEFINED item_raw ( goto :_create_pathlist_LOOP_DONE )
set "item=%~1"
if "%item%" EQU """" ( set "item=" )
call :_rtrim item "%item%" "\"
call :_append_to_pathlist _RETval "%item%" "%_RETval%"
goto :_create_pathlist_LOOP
:_create_pathlist_LOOP_DONE
:_create_pathlist_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$create_set ( ref_RETURN [ ITEMs ... ] )
:$create_set ( ref_RETURN [ ITEMs ... ] )
:_create_set ( ref_RETURN [ ITEMs ... ] )
:: NOTE: SET is a LIST of ITEMs (with no repeated ITEMs)
:: RETURN == SET of ITEMs
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_create_set"
set "_RETvar=%~1"
set "_RETval="
:_create_set_LOOP
shift
set item_raw=%1
if NOT DEFINED item_raw ( goto :_create_set_LOOP_DONE )
set "item=%~1"
if "%item%" EQU """" ( set "item=" )
call :_append_to_set _RETval "%item%" "%_RETval%"
goto :_create_set_LOOP
:_create_set_LOOP_DONE
:_create_set_RETURN
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$first_of ( ref_RETURN LIST )
:$first_of ( ref_RETURN LIST )
:_first_of ( ref_RETURN LIST )
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_first_of"
set "_RETval="
set _RETvar=%~1
set "list=%~2"
if DEFINED list ( call :_first_of_items _RETval "%list:;=" "%" )
:_first_of_RETURN
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$first_of_items ( ref_RETURN [ ITEMs ... ] )
:$first_of_items ( ref_RETURN [ ITEMs ... ] )
:_first_of_items ( ref_RETURN [ ITEMs ... ] )
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_first_of_items"
set _RETvar=%~1
set "item=%~2"
if "%item%" == """" ( set "item=" )
:_first_of_items_RETURN
set "_RETval=%item%"
::endlocal & if NOT 01 == 1.0 (set "%_RETvar%=%_RETval%") else (set "%_RETvar=%_RETval")
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$remove_first_item ( ref_RETURN [ ITEMs ... ] )
:$remove_first_item ( ref_RETURN [ ITEMs ... ] )
:_remove_first_item ( ref_RETURN [ ITEMs ... ] )
:: RETURN == LIST of all ITEMs excepting the initial ITEM
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_remove_first_item"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
shift
:_remove_first_item_LOOP
shift
set item_raw=%1
REM call :_echo_DEBUG_KEY item_raw="%item_raw%"
if NOT DEFINED item_raw ( goto :_remove_first_item_LOOP_DONE )
set "item=%~1"
if "%item%" EQU """" ( set "item=" )
REM call :_echo_DEBUG_KEY item="%item%"
call :_append_to_list _RETval "%item%" "%_RETval%"
goto :_remove_first_item_LOOP
:_remove_first_item_LOOP_DONE
:_remove_first_item_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$remove_first ( ref_RETURN LIST )
:$remove_first ( ref_RETURN LIST )
:_remove_first ( ref_RETURN LIST )
:: RETURN == LIST with first ITEM removed
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_remove_first"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "list=%~2"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY list="%list%"
if DEFINED list ( call :_remove_first_item _RETval "%list:;=" "%" )
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$first_list_match ( ref_RETURN LIST1 LIST2 )
:$first_list_match ( ref_RETURN LIST1 LIST2 )
:_first_list_match ( ref_RETURN LIST1 LIST2 )
:: RETURN == first ITEM in LIST1 which is also contained in LIST2
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_first_list_match"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "list1=%~2"
set "list2=%~3"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY list1="%list1%"
REM call :_echo_DEBUG_KEY list2="%list2%"
:_first_list_match_LOOP
if NOT DEFINED list1 ( goto :_first_list_match_RETURN )
call :_first_of item "%list1%"
call :_remove_first list1 "%list1%"
REM call :_echo_DEBUG_KEY item="%item%"
REM call :_echo_DEBUG_KEY list="%list%"
call :_is_in_list IS_match "%item%" "%list2%"
if NOT DEFINED IS_match ( goto :_first_list_match_LOOP )
set "_RETval=%item%"
:_first_list_match_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$path_in_pathlist ( ref_RETURN FILENAME PATHLIST )
:$path_in_pathlist ( ref_RETURN FILENAME PATHLIST )
:_path_in_pathlist ( ref_RETURN FILENAME PATHLIST )
:: NOTE: FILENAME should be a simple filename, not a directory or filename with leading directory prefix. CMD will match these more complex paths, but TCC will not.
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_path_in_pathlist"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "pathlist=%~3"
set "PATH=%pathlist%"
REM call :_echo_DEBUG_KEY ref_RETURN="%~1"
REM call :_echo_DEBUG_KEY filename="%~2"
REM call :_echo_DEBUG_KEY pathlist="%pathlist%"
::call :_path_of_file_in_paths _RETval "%~2" "%pathlist:;=" "%"
set "_RETval=%~$PATH:2"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
:_path_in_pathlist_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$path_in_PATH ( ref_RETURN FILENAME )
:$path_in_PATH ( ref_RETURN FILENAME )
:_path_in_PATH ( ref_RETURN FILENAME )
:: NOTE: FILENAME should be a simple filename, not a directory or filename with leading directory prefix. CMD will match these more complex paths, but TCC will not.
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_path_in_PATH"
set "_RETvar=%~1"
call :_path_in_pathlist _RETval "%~2" ".;%PATH%"  &:: the current working directory is implied in %PATH% (and searched 1st); make this explicit for this search
:_path_in_PATH_RETURN
endlocal & set "%~1=%_RETval%"
goto :EOF
::

::
:$$path_of_file_in_pathlist ( ref_RETURN FILENAME PATHLIST [EXTENSIONLIST] )
:$path_of_file_in_pathlist ( ref_RETURN FILENAME PATHLIST [EXTENSIONLIST] )
:_path_of_file_in_pathlist ( ref_RETURN FILENAME PATHLIST [EXTENSIONLIST] )
:: NOTE: FILENAME should be a simple filename, not a directory or filename with leading directory prefix. CMD will match these more complex paths, but TCC will not.
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_path_of_file_in_pathlist"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
set "extensionList=%~4"
REM call :_echo_DEBUG_KEY _RETvar="%~1"
REM call :_echo_DEBUG_KEY filename="%~2"
REM call :_echo_DEBUG_KEY pathlist="%~3"
REM call :_echo_DEBUG_KEY extensionList="%extensionList%"
if NOT DEFINED extensionList ( goto :_path_of_file_in_pathlist_EXTS_NULL )
:_path_of_file_in_pathlist_EXTS
call :_path_of_file_in_pathlist_with_extensions _RETval "%~2" "%~3" "%extensionList:;=" "%"
goto :_path_of_file_in_pathlist_DONE
:_path_of_file_in_pathlist_EXTS_NULL
call :_path_in_pathlist _RETval "%~2" "%~3"
:_path_of_file_in_pathlist_DONE
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
:_path_of_file_in_pathlist_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$path_of_file_in_pathlist_with_extensions ( ref_RETURN FILENAME PATHLIST [[EXTENSION1] [EXTENSION2] ...]  )
:$path_of_file_in_pathlist_with_extensions ( ref_RETURN FILENAME PATHLIST [[EXTENSION1] [EXTENSION2] ...]  )
:_path_of_file_in_pathlist_with_extensions ( ref_RETURN FILENAME PATHLIST [[EXTENSION1] [EXTENSION2] ...]  )
:: NOTE: FILENAME should be a simple filename, not a directory or filename with leading directory prefix. CMD will match these more complex paths, but TCC will not.
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_path_of_file_in_pathlist_with_extensions"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set _RETvar=%~1
shift
set "_f=%~1"
shift
set "pathlist=%~1"
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY filename="%_f%"
REM call :_echo_DEBUG_KEY pathlist="%pathlist%"
set "_RETval_level="
:_path_of_file_in_pathlist_with_extensions_LOOP
shift
REM call :_echo_DEBUG_KEY ext_N="%~1"
if "%~1" == "" ( goto :_path_of_file_in_pathlist_with_extensions_RETURN )
call :_path_in_pathlist _f_path "%_f%%~1" "%pathlist%"
if "%_f_path%" EQU "" ( goto :_path_of_file_in_pathlist_with_extensions_LOOP )
REM call :_echo_DEBUG_KEY _f_path="%_f_path%"
call :_dir_of _f_dir "%_f_path%"
REM call :_echo_DEBUG_KEY _f_path="%_f_path%"
call :_is_in_list _f_level "%_f_dir%" "%pathlist%"
::if DEFINED _f_level ( if "%_RETval_level%" EQU "" ( set "_RETval_level=%_f_level%" & set "_RETval=%_f_path%" ) )
::if DEFINED _f_level ( if %_f_level%0 LSS %_RETval_level%0 ( set "_RETval_level=%_f_level%" & set "_RETval=%_f_path%" ) )
if NOT defined _RETval_level ( set "_RETval_level=%_f_level%" & set "_RETval=%_f_path%" )
if %_f_level%0 LSS %_RETval_level%0 ( set "_RETval_level=%_f_level%" & set "_RETval=%_f_path%" )
REM call :_echo_DEBUG_KEY _f_level="%_f_level%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
REM call :_echo_DEBUG_KEY _RETval_level="%_RETval_level%"
goto :_path_of_file_in_pathlist_with_extensions_LOOP
:_path_of_file_in_pathlist_with_extensions_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$path_of_file_in_PATH ( ref_RETURN FILENAME EXTENSIONLIST )
:$path_of_file_in_PATH ( ref_RETURN FILENAME EXTENSIONLIST )
:_path_of_file_in_PATH ( ref_RETURN FILENAME EXTENSIONLIST )
:: NOTE: FILENAME should be a simple filename, not a directory or filename with leading directory prefix. CMD will match these more complex paths, but TCC will not.
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_path_of_file_in_PATH"
call :_path_of_file_in_pathlist _RETval "%~2" "%PATH%" "%~3"
:_path_of_file_in_PATH_RETURN
endlocal & set "%~1=%_RETval%"
goto :EOF
::

::
:$$path_of_item_in_pathlist ( ref_RETURN ITEMNAME PATHLIST )
:$path_of_item_in_pathlist ( ref_RETURN ITEMNAME PATHLIST )
:_path_of_item_in_pathlist ( ref_RETURN ITEMNAME PATHLIST )
:: RETURN == PATH of first ITEMNAME found within PATHLIST (NULL if not found)
:: NOTE: ITEMNAME can be a simple filename, a path, or filename with leading prefix
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_path_of_item_in_pathlist"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "item=%~2"
set "pathlist=%~3"
set "_RETval="
REM call :_echo_DEBUG_KEY ref_RETURN="%_RETvar%"
REM call :_echo_DEBUG_KEY itemname="%item%"
call :_path_of_item_in_paths _RETval "%item%" "%pathlist:;=" "%"
:_path_of_file_in_paths_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$path_of_item_in_paths ( ref_RETURN ITEMNAME PATH1 [[PATH2] ...] )
:$path_of_item_in_paths ( ref_RETURN ITEMNAME PATH1 [[PATH2] ...] )
:_path_of_item_in_paths ( ref_RETURN ITEMNAME PATH1 [[PATH2] ...] )
:: RETURN == PATH of ITEMNAME from within PATHs (NULL if not found)
:: NOTE: ITEMNAME can be a simple filename, a path, or filename with leading partial prefix
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_path_of_item_in_paths"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
shift
set "item=%~1"
set "_RETval="
REM call :_echo_DEBUG_KEY ref_RETURN="%_RETvar%"
REM call :_echo_DEBUG_KEY itemname="%item%"
:_path_of_item_in_paths_LOOP
shift
REM call :_echo_DEBUG_KEY path_N="%~1"
if "%~1" == "" ( goto :_path_of_item_in_paths_RETURN )
if EXIST "%~1\%item%" ( set "_RETval=%~1\%item%" & goto :_path_of_item_in_paths_RETURN )
goto :_path_of_item_in_paths_LOOP
:_path_of_item_in_paths_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$fullname_of ( ref_RETURN PATH )
:$fullname_of ( ref_RETURN PATH )
:_fullname_of ( ref_RETURN PATH )
:$$FQ_name_of
:$$FQ_fullname_of
:$$fully_qualified_form_of
:$FQ_name_of
:$FQ_fullname_of
:$fully_qualified_form_of
:_FQ_name_of
:_FQ_fullname_of
:_fully_qualified_form_of
:: RETURN == fully qualified name of PATH
:: ToDO: ? pull out _fullname_of to seperate function in keeping with _drive_of / _FQ_drive_of and _dir_of / _FQ_dir_of
:: NOTE: special processing to deal correctly with the case of "<DRIVE>:" ("<DRIVE>:" == "<DRIVE>:" == "<DRIVE>:.", NOT "<DRIVE>:.")
:: NOTE: _fullname_of("") == ""
:: NOTE: _fullname_of("\\") == _fullname_of("\") == _fullname_of("\.") == "<CURRENTDRIVE>:\"
:: NOTE: _fullname_of("c:") == _fullname_of("c:.")
:: NOTE: special processing is needed to deal with the fact that TCC acts out with almost unsuppressible errors for inaccessible and UNC PATHs [which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_fullname_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
REM call :_echo_DEBUG_KEY 2="%~2"
:: avoid TCC path parsing errors for null strings
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_fullname_of_RETURN )
if "%_RETval%" == "\\" ( set "_RETval=\" )
::
::?:call :_drive_of drive "%~2"
REM call :_echo_DEBUG_KEY drive="%drive%"
::?:if /i "%drive%" == "%~2" ( set "_RETval=%~2" & goto :_fullname_of_RETURN )
call :_rewrite_path_to_FQ_local _RETval drive "%_RETval%"
if NOT DEFINED drive ( set "drive=%SYSTEMDRIVE%" )
if NOT DEFINED drive ( set "drive=%SYSTEMROOT:~0,2%" )
if NOT DEFINED drive ( set "drive=%~d0" )
REM call :_echo_DEBUG_KEY drive="%drive%"
REM call :_echo_DEBUG_KEY _RETval_local="%_RETval%"
call :_param_tilde_PNX _RETval "%_RETval%"
REM call :_echo_DEBUG_KEY _RETval_PNX="%_RETval%"
set "_RETval=%drive%%_RETval%"
REM call :_echo_DEBUG_KEY _RETval_DR="%_RETval%"
::?:call :_rtrim _RETval "%_RETval%" "\\"
:_fullname_of_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$shortname_of ( ref_RETURN PATH )
:$shortname_of ( ref_RETURN PATH )
:_shortname_of ( ref_RETURN PATH )
:: RETURN == fully qualified short name of PATH
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_shortname_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set _RETvar=%~1
call :_param_tilde_SF _RETval "%~2"
call :_FQ_fullname_of _RETval "%_RETval%"
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$dir_of ( ref_RETURN PATH )
:$dir_of ( ref_RETURN PATH )
:_dir_of ( ref_RETURN PATH )
:: RETURN == directory of PATH
:: NOTE: uses the PATH as is without changing it to fully qualified form
:: NOTE: special processing to deal correctly with the case of "<DRIVE>:" ("<DRIVE>:" == "<DRIVE>:."; "DRIVE:\" == "<DRIVE>:\.")
:: NOTE: _dir_of("") == ""
:: NOTE: _dir_of("\\") == _dir_of("\") == "\"
:: NOTE: _dir_of("c:") == _dir_of("c:.")
:: NOTE: _dir_of("c:\") == _dir_of("c:\.") == "\"
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_dir_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: avoid TCC path parsing errors for null strings
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_dir_of_RETURN )
if "%_RETval%" == "\\" ( set "_RETval=\" )
::
::?:call :_drive_of drive "%~2"
::?:call :_echo_DEBUG_KEY drive="%drive%"
::?:if /i "%drive%" == "%~2" ( set "_RETval=%~2" & goto :_dir_of_RETURN )
call :_rewrite_path_to_FQ_local _path drive "%_RETval%"
call :_param_tilde_P _RETval "%_path%"
::?:call :_param_tilde_N NAME "%_path%"
REM call :_echo_DEBUG_KEY _P="%_RETval%"
call :_rtrim _RETval "%_RETval%" "\"
::?:if NOT DEFINED _RETval if DEFINED NAME (set _RETval=\)
if NOT DEFINED _RETval (set _RETval=\)
::set "_RETval=%drive%%_RETval%"
:_dir_of_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$FQ_dir_of ( ref_RETURN PATH )
:$FQ_dir_of ( ref_RETURN PATH )
:_FQ_dir_of ( ref_RETURN PATH )
:: RETURN == fully qualified directory of PATH
:: NOTE: _FQ_dir_of("") == ""
:: NOTE: _FQ_dir_of("\\") == _FQ_dir_of("\")
:: NOTE: _FQ_dir_of("c:") == _FQ_dir_of("c:.")
:: NOTE: _FQ_dir_of("c:\") == _FQ_dir_of("c:\.") == "c:\"
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_FQ_dir_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: avoid TCC path parsing errors for null strings
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_FQ_dir_of_RETURN )
if "%_RETval%" == "\\" ( set "_RETval=\" )
call :_rewrite_path_to_FQ_local _RETval drive "%_RETval%"
::?:call :_dir_of _RETval "%_RETval%"
if NOT DEFINED _RETval ( goto :_FQ_dir_of_RETURN )
call :_param_tilde_P _RETval "%_RETval%"
REM call :_echo_DEBUG_KEY _P="%_RETval%"
call :_rtrim _RETval "%_RETval%" "\"
if NOT DEFINED _RETval ( set "_RETval=\" )
:_FQ_dir_of_DONE
if NOT DEFINED drive ( set "drive=%SYSTEMDRIVE%" )
if NOT DEFINED drive ( set "drive=%SYSTEMROOT:~0,2%" )
if NOT DEFINED drive ( set "drive=%~d0" )
REM call :_echo_DEBUG_KEY drive="%drive%"
set "_RETval=%drive%%_RETval%"
:_FQ_dir_of_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$extension_of ( ref_RETURN PATH )
:$extension_of ( ref_RETURN PATH )
:_extension_of ( ref_RETURN PATH )
:: RETURN == extension of PATH
:: NOTE: _extension_of "" == "" ; _extension_of "c:" == "" ; _extension_of "\\" == "" _extension_of "\" == ""
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_extension_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: avoid TCC path parsing errors for null strings
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_extension_of_RETURN )
::
call :_rewrite_path_to_FQ_local _RETval _ "%_RETval%"
call :_param_tilde_X _RETval "%_RETval%"
call :_rtrim _RETval "%_RETval%" "\"
:_extension_of_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$param_tilde_PNX ( ref_RETURN PATH )
:$param_tilde_PNX ( ref_RETURN PATH )
:_param_tilde_PNX ( ref_RETURN PATH )
:: NOTE: for TCC, assume that PATH is on (or has been forced onto) an accessible drive and not a UNC pathname [necessary to avoid unsupressable TCC parsing errors; which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
:: RETURN == path, name, and extension of PATH
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_param_tilde_PNX"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_param_tilde_PNX_RETURN )
set "_RETval=%~pnx2"
:_param_tilde_PNX_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$param_tilde_P ( ref_RETURN PATH )
:$param_tilde_P ( ref_RETURN PATH )
:_param_tilde_P ( ref_RETURN PATH )
:: NOTE: for TCC, assume that PATH is on (or has been forced onto) an accessible drive and not a UNC pathname [necessary to avoid unsupressable TCC parsing errors; which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
:: RETURN == directory of PATH
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_param_tilde_P"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_param_tilde_P_RETURN )
set "_RETval=%~p2"
REM call :_echo_DEBUG_KEY 1="%~1"
REM call :_echo_DEBUG_KEY 2="%~2"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
:_param_tilde_P_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$param_tilde_NX ( ref_RETURN PATH )
:$param_tilde_NX ( ref_RETURN PATH )
:_param_tilde_NX ( ref_RETURN PATH )
:: NOTE: for TCC, assume that PATH is on an accessible drive and not a UNC pathname [necessary to avoid unsupressable TCC parsing errors; which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
:: RETURN == name & extension of PATH
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_param_tilde_NX"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_param_tilde_NX_RETURN )
set "_RETval=%~nx2"
:_param_tilde_NX_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$param_tilde_X ( ref_RETURN PATH )
:$param_tilde_X ( ref_RETURN PATH )
:_param_tilde_X ( ref_RETURN PATH )
:: NOTE: for TCC, assume that PATH is on an accessible drive and not a UNC pathname [necessary to avoid unsupressable TCC parsing errors; which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
:: RETURN == extension of PATH
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_param_tilde_X"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_param_tilde_X_RETURN )
set "_RETval=%~x2"
:_param_tilde_X_RETURN
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$param_tilde_SF ( ref_RETURN PATH )
:$param_tilde_SF ( ref_RETURN PATH )
:_param_tilde_SF ( ref_RETURN PATH )
:: NOTE: for TCC, assume that PATH is on (or has been forced onto) an accessible drive and not a UNC pathname [necessary to avoid unsupressable TCC parsing errors; which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
:: RETURN == short full name of PATH [ PATH is either absolute or assumed to be relative to %CD%]
:: URLref: [Bug and workaround in %~sf0 ] https://groups.google.com/d/topic/alt.msdos.batch.nt/CrLJbBzgdkk/discussion
:: URLref: [Discussion of bug in %~s0 syntax ] https://groups.google.com/d/topic/alt.msdos.batch.nt/TkUsCQuL_bg/discussion
:: URLref: [CMD percent-tilde Syntax] http://ss64.com/nt/syntax-args.html @@ http://www.webcitation.org/67qH4Ri09
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_param_tilde_SF"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_param_tilde_SF_RETURN )
set "_RETval=%~sf2"
:_param_tilde_SF_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$param_tilde_A ( ref_RETURN PATH )
:$param_tilde_A ( ref_RETURN PATH )
:_param_tilde_A ( ref_RETURN PATH )
:: NOTE: for TCC, assume that PATH is on (or has been forced onto) an accessible drive and not a UNC pathname [necessary to avoid unsupressable TCC parsing errors; which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
:: RETURN == attributes of full name of PATH [ PATH is either absolute or assumed to be relative to %CD%]
:: URLref: [CMD percent-tilde Syntax] http://ss64.com/nt/syntax-args.html @@ http://www.webcitation.org/67qH4Ri09
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_param_tilde_A"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_param_tilde_SF_RETURN )
set "_RETval=%~a2"
:_param_tilde_A_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$param_tilde_DPNX ( ref_RETURN PATH )
:$param_tilde_DPNX ( ref_RETURN PATH )
:_param_tilde_DPNX ( ref_RETURN PATH )
:: NOTE: for TCC, assume that PATH is on (or has been forced onto) an accessible drive and not a UNC pathname [necessary to avoid unsupressable TCC parsing errors; which is "WAD" per developer [meh, see URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://www.webcitation.org/63ua1bpOk]]
:: RETURN == drive, path, name, and extension of PATH
setlocal
set "_RETvar=%~1"
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_param_tilde_PNX_RETURN )
set "_RETval=%~dpnx2"
:_param_tilde_PNX_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$attributes_of ( ref_RETURN PATH )
:$attributes_of ( ref_RETURN PATH )
:_attributes_of ( ref_RETURN PATH )
:: RETURN == attribute string for PATH ("", if PATH not accessible)
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_attributes_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set _RETvar=%~1
:: TCC can't handle nonexistant PATHs (especially non-existant drives)
if NOT EXIST "%~2" ( goto :_attributes_of_RETURN )
set "_RETval=%~a2"
:_attributes_of_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$size_of ( ref_RETURN FILE )
:$size_of ( ref_RETURN FILE )
:_size_of ( ref_RETURN FILE )
:: RETURN == size of FILE
:: NOTE: _size_of(FILE; FILE not accessible) == ""
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_size_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: TCC can't handle nonexistant PATHs (especially non-existant drives)
if NOT EXIST "%~2" ( goto :_size_of_RETURN )
set "_RETval=%~z2"
:_size_of_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$filetime_of ( ref_RETURN FILE )
:$filetime_of ( ref_RETURN FILE )
:_filetime_of ( ref_RETURN FILE )
:: RETURN == file time of FILE ("", if FILE is missing)
:: NOTE: file time is returned in "YYYY-MM-DD.HHmm" format [this format is comparable using usual string comparisons for time ordering; and has no illegal file characters, allowing use in a filename]
:: NOTE: _filetime_of(PATH; PATH not accessible) == ""
:: ToDO: check assumptions regarding leading zeros in "~tN" substitution for all time sections
:: ToDO: FIX: time changes by 60 minutes with change in DST ... leave this as LOCAL time ... create _filetime_GMT_of()
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_filetime_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
if NOT EXIST "%~2" ( goto :_filetime_of_RETURN )
set "_RETval=%~t2"
if NOT DEFINED _RETval ( goto :_filetime_of_RETURN )
:: transform to comparable strings
if 1.0 == 1 ( goto :_filetime_of_TCC_transform ) &:: TCC uses a different format for ~tN time/date values
:_filetime_of_CMD_transform
set "year=%_RETval:~6,4%"
set "month=%_RETval:~0,2%"
set "day=%_RETval:~3,2%"
set "hour=%_RETval:~11,2%"
set "minute=%_RETval:~14,2%"
set "ampm=%_RETval:~17,1%"
if "%hour%" == "12" ( set "hour=00" )
if /i "%ampm%" == "p" (
    set /a hour += 12
    )
goto :_filetime_of_SET_RETval
:_filetime_of_TCC_transform
set _RETval=%@filedate["%~2",w,4] %@filetime["%~2"]
set "year=%_RETval:~0,4%"
set "month=%_RETval:~5,2%"
set "day=%_RETval:~8,2%"
set "hour=%_RETval:~11,2%"
set "minute=%_RETval:~14,2%"
if "%hour%" == "12" ( set "hour=00" )
goto :_filetime_of_SET_RETval
:_filetime_of_SET_RETval
set "_RETval=%year%-%month%-%day%.%hour%%minute%"
:_filetime_of_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
REM call :_echo_DEBUG_KEY ~t2="%~t2"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_archive ( ref_RETURN PATH )
:$is_archive ( ref_RETURN PATH )
:_is_archive ( ref_RETURN PATH )
:: RETURN == (BOOLEAN as undef/1) whether PATH is a directory
:: NOTE: URLref: http://stackoverflow.com/a/3728742/43774 from http://stackoverflow.com/questions/138981/how-do-i-test-if-a-file-is-a-directory-in-a-batch-script
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_archive"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: TCC can't handle nonexistant PATHs (especially non-existant drives)
if NOT EXIST "%~2" ( goto :_is_archive_RETURN )
set "attr=%~a2"
set "attr_bit=%attr:~2,1%"
if /i "%attr_bit%"=="a" (set "_RETval=1")
:_is_archive_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_dir ( ref_RETURN PATH )
:$is_dir ( ref_RETURN PATH )
:_is_dir ( ref_RETURN PATH )
:: RETURN == (BOOLEAN as undef/1) whether PATH is a directory
:: NOTE: URLref: http://stackoverflow.com/a/3728742/43774 from http://stackoverflow.com/questions/138981/how-do-i-test-if-a-file-is-a-directory-in-a-batch-script
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_dir"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: TCC can't handle nonexistant PATHs (especially non-existant drives)
if NOT EXIST "%~2" ( goto :_is_dir_RETURN )
set "attr=%~a2"
set "attr_bit=%attr:~0,1%"
if /i "%attr_bit%"=="d" (set "_RETval=1")
:_is_dir_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_file ( ref_RETURN PATH )
:$is_file ( ref_RETURN PATH )
:_is_file ( ref_RETURN PATH )
:: RETURN == (BOOLEAN as undef/1) whether PATH is a directory
:: NOTE: URLref: http://stackoverflow.com/a/3728742/43774 from http://stackoverflow.com/questions/138981/how-do-i-test-if-a-file-is-a-directory-in-a-batch-script
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_file"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: TCC can't handle nonexistant PATHs (especially non-existant drives)
if NOT EXIST "%~2" ( goto :_is_file_RETURN )
set "attr=%~a2"
set "attr_bit=%attr:~0,1%"
if /i "%attr_bit%"=="-" (set "_RETval=1")
:_is_file_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_hidden ( ref_RETURN PATH )
:$is_hidden ( ref_RETURN PATH )
:_is_hidden ( ref_RETURN PATH )
:: RETURN == (BOOLEAN as undef/1) whether PATH is hidden
:: NOTE: URLref: http://stackoverflow.com/a/3728742/43774 from http://stackoverflow.com/questions/138981/how-do-i-test-if-a-file-is-a-directory-in-a-batch-script
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_hidden"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: TCC can't handle nonexistant PATHs (especially non-existant drives)
if NOT EXIST "%~2" ( goto :_is_hidden_RETURN )
set "attr=%~a2"
set "attr_bit=%attr:~3,1%"
if /i "%attr_bit%"=="h" (set "_RETval=1")
:_is_hidden_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_readonly ( ref_RETURN PATH )
:$is_readonly ( ref_RETURN PATH )
:_is_readonly ( ref_RETURN PATH )
:: RETURN == (BOOLEAN as undef/1) whether PATH is readonly (locked)
:: NOTE: URLref: http://stackoverflow.com/a/3728742/43774 from http://stackoverflow.com/questions/138981/how-do-i-test-if-a-file-is-a-directory-in-a-batch-script
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_readonly"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: TCC can't handle nonexistant PATHs (especially non-existant drives)
if NOT EXIST "%~2" ( goto :_is_readonly_RETURN )
set "attr=%~a2"
set "attr_bit=%attr:~1,1%"
if /i "%attr_bit%"=="r" (set "_RETval=1")
:_is_readonly_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_system ( ref_RETURN PATH )
:$is_system ( ref_RETURN PATH )
:_is_system ( ref_RETURN PATH )
:: RETURN == (BOOLEAN as undef/1) whether PATH is a directory
:: NOTE: URLref: http://stackoverflow.com/a/3728742/43774 from http://stackoverflow.com/questions/138981/how-do-i-test-if-a-file-is-a-directory-in-a-batch-script
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_is_system"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETval="
set "_RETvar=%~1"
:: TCC can't handle nonexistant PATHs (especially non-existant drives)
if NOT EXIST "%~2" ( goto :_is_system_RETURN )
set "attr=%~a2"
set "attr_bit=%attr:~4,1%"
if /i "%attr_bit%"=="s" (set "_RETval=1")
:_is_system_RETURN
REM call :_echo_DEBUG_KEY _RETvar="%_RETvar%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
::( endlocal
::  ( if "%_RETvar%" NEQ "" ( if NOT 01 == 1.0 (
::      set "%_RETvar%=%_RETval%"
::      ) else (
::      set %_RETvar=%_RETval
::      ))
::call :_echo_item_DEBUG_KEY "%__DEBUG%" "%__DEBUG_KEY%" "%__ME%" "%__MEfn%" "[ %__MEfn% :: done ]"
::)
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_link ( ref_RETURN PATH )
:$is_link ( ref_RETURN PATH )
:_is_link ( ref_RETURN PATH )
:: RETURN == (BOOLEAN as undef/1) whether PATH is a link (symbolic link, includes junctions)
:: NOTE: TCC attibute expansion is bugged, and doesn't display the link attribute correctly
setlocal
set "_RETval="
set "_RETvar=%~1"
if NOT EXIST "%~2" ( goto :_is_link_RETURN )
set "attr=%~a2"
set "attr_bit=%attr:~-1,1%"
:: NOTE: TCC ~aN is no longer compatible with CMD (does not show the link attribute)
if NOT 01 == 1.0 ( goto :_is_link_TEST )
set "attr_bit=-"
set "attr=%@lower[%@attrib[%~2]]"
if %@wild[%attr%,*l*] == 1 (
    set "attr_bit=l"
    )
:_is_link_TEST
if /i "%attr_bit%"=="l" (set "_RETval=1")
:_is_link_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$is_junction ( ref_RETURN PATH )
:$is_junction ( ref_RETURN PATH )
:_is_junction ( ref_RETURN PATH )
:: RETURN == (BOOLEAN as undef/1) whether PATH is a junction
setlocal
set "_RETval="
set "_RETvar=%~1"
if NOT EXIST "%~2" ( goto :_is_junction_RETURN )
call :_is_link is_link "%~2"
if NOT DEFINED is_link ( goto :_is_junction_RETURN )
set path_basename=%~nx2
set path_abs=%~dpnx2
:: use ...* to avoid searching within a directory (also, works fine for files)
:: only need 1st match
set "DIRCMD=" &:: remove DIRCMD as it could interfere
:: NOTE: TCC dir formats time as 24 hour (HH:mm) vs CMD 12 hour (HH:mm A/PM)
if 01 == 1.0 ( goto :_readsymlink_TCC )
:_is_junction_CMD
FOR /F "tokens=1,2,3,4*" %%G IN ('dir /A:L "%path_abs%*" ^| "%SystemRoot%\system32\findstr.EXE" "<JUNCTION"') DO (
    set "_dir_entry=%%K"
    goto :_is_junction_DIR_DONE
    )
:_is_junction_TCC
FOR /F "tokens=1,2,3*" %%G IN ('dir /A:L "%path_abs%*" ^| "%SystemRoot%\system32\findstr.EXE" "<JUNCTION"') DO (
    set "_dir_entry=%%J"
    goto :_is_junction_DIR_DONE
    )
:_is_junction_DIR_DONE
if NOT DEFINED _dir_entry ( goto :_is_junction_RETURN )
:: find symlink portion and pull it off the entry, then match pathnames
call set symlink=%%_dir_entry:*%path_basename% [=%%
set symlink= [%symlink%
call set path_name=%%_dir_entry:%symlink%=%%
if "%path_basename%" == "%path_name%" ( set _RETval=1 )
:_is_junction_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$readsymlink_of ( ref_RETURN PATH )
:$readsymlink_of ( ref_RETURN PATH )
:_readsymlink_of ( ref_RETURN PATH )
:: RETURN == target path of PATH (in raw, non-fully-qualified / non-canonicalized form); NULL if PATH is not a link/junction
:: NOTE: only follows a single link (if present)
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_readsymlink_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_readsymlink_of_RETURN )
set path_basename=%~nx2
set path_abs=%~dpnx2
call :_is_link is_link "%~2"
REM call :_echo_DEBUG_KEY path_basename="%path_basename%"
if NOT DEFINED is_link ( set "_RETval=" & goto :_readsymlink_of_FOUND )
:: use ...* to avoid searching within a directory (also, works fine for files)
:: the 1st match is correct, take it and stop looking (avoids collisions with similar link names)
:: NOTE: TCC dir formats time as 24 hour (HH:mm) vs CMD 12 hour (HH:mm A/PM)
if 01 == 1.0 ( goto :_readsymlink_TCC )
:_readsymlink_CMD
FOR /F "tokens=1,2,3,4*" %%G IN ('dir /A:L "%path_abs%*" ^| "%SystemRoot%\system32\findstr.EXE" "<SYMLINK <JUNCTION"') DO (
    set "_dir_entry=%%K"
    goto :_readsymlink_of_DIR_DONE
    )
:_readsymlink_TCC
FOR /F "tokens=1,2,3*" %%G IN ('dir /A:L "%path_abs%*" ^| "%SystemRoot%\system32\findstr.EXE" "<SYMLINK <JUNCTION"') DO (
    set "_dir_entry=%%J"
    goto :_readsymlink_of_DIR_DONE
    )
:_readsymlink_of_DIR_DONE
call set _RETval=%%_dir_entry:*%path_basename% [=%%
set _RETval=%_RETval:~0,-1%
:_readsymlink_of_FOUND
:_readsymlink_of_DONE
:_readsymlink_of_RETURN
REM call :_echo_DEBUG_KEY _RETval=%_RETVal%
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$readlink_of ( ref_RETURN PATH )
:$readlink_of ( ref_RETURN PATH )
:_readlink_of ( ref_RETURN PATH )
:: RETURN == fully qualified target path of PATH; NULL if PATH is not a link/junction
:: NOTE: only follows a single link (if present)
:: NOTE: using _fq_fullname for full qualification to deal with difficult special cases (and nasty TCC drive/UNC bugs [URLref: http://jpsoft.com/forums/threads/using-dp1-for-paths-with-unavailable-drives.3450 @@ http://webcitation.org/63ua1bpOk])
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_readlink_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
if NOT DEFINED _RETval ( goto :_readlink_of_RETURN )
call :_readsymlink_of _RETval "%_RETval%"
if NOT DEFINED _RETval ( goto :_readlink_of_RETURN )
::call :_split_drive_path_of _drive _path "%_RETval%"
::if DEFINED _drive ( goto :_readlink_of_FOUND )
::if NOT "%_path:~0,1%" == "\" ( set "_RETval=%~dp2%_path%" )
:_readlink_of_FOUND
call :_FQ_fullname_of _RETval "%_RETval%"
:_readlink_of_DONE
:_readlink_of_RETURN
REM call :_echo_DEBUG_KEY _RETval=%_RETVal%
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$realpath_of ( ref_RETURN PATH [MAX_DEPTH] )
:$realpath_of ( ref_RETURN PATH [MAX_DEPTH] )
:_realpath_of ( ref_RETURN PATH [MAX_DEPTH] )
:: RETURN == fully qualified & canonical real/final path of PATH (to MAX_DEPTH level [default=9]; NULL if still not at final, non-link/junction PATH by MAX_DEPTH)
:: NOTE: MAX_DEPTH is used to avoid an infinite loop for circular link references
:: NOTE: similar to "realpath" or "readlink -f"
:: NOTE: ToDO: research changing all parent directories into real paths (for a true canonical real_path); currently, symbolic links in PARENTs are not dereferenced
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=_realpath_of"
REM call :_echo_DEBUG_KEY [ %__MEfn% :: start ]
set "_RETvar=%~1"
set "_RETval=%~2"
set "max_depth=%~3"
if NOT DEFINED max_depth ( set max_depth=9 )
REM call :_echo_DEBUG_KEY _RETvar=%_RETvar%
REM call :_echo_DEBUG_KEY _RETval=%_RETval%
REM call :_echo_DEBUG_KEY max_depth=%max_depth%
:_realpath_of_LOOP
call :_is_link is_link "%_RETval%"
if NOT DEFINED is_link ( goto :_realpath_of_FOUND )
if NOT %max_depth% GTR 0 ( set "_RETval=" & goto :_realpath_of_DONE )
call :_readlink_of _RETval "%_RETval%"
REM call :_echo_DEBUG_KEY _RETval="%_RETval%"
set /a max_depth -= 1
goto :_realpath_of_LOOP
:_realpath_of_FOUND
call :_FQ_fullname_of _RETval "%_RETval%"
:_realpath_of_DONE
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

::
:$$ascii_chr ( ref_RETURN [ ASCII_CODEs ... ] )
:: RETURN == ASCII character correspondong to the provided ASCII code point
:: ASCII_CODE == desired ASCII character code
:: ref: <https://stackoverflow.com/a/49959194/43774> @@ <https://archive.is/zRRJt#29%>
:: ref: <https://www.dostips.com/forum/viewtopic.php?f=3&t=5326&start=105> @@ <https://archive.is/FnTRi>
setlocal
set "__DEBUG_KEY=@"
set "__MEfn=$ascii_chr"
set "_RETval="
set "_RETvar=%~1"
call :$tempfile tempfile "$library"
:_ascii_chr_LOOP
shift
set "ascii_code=%~1"
if NOT DEFINED ascii_code goto :_ascii_chr_DONE
echo|set /p _OUTPUT="" >"%tempfile%" 2>nul
"C:\WINDOWS\System32\makecab.EXE" /d compress=off /d reservePerDataBlockSize=0 /d reservePerFolderSize=%ascii_code% "%tempfile%" "%tempfile%" >nul
<"%tempfile%" ((for /L %%g in (1,1,38) do pause>nul)&set /p "ch=") >nul
set "ch=%ch:~0,1%"
set "_RETval=%_RETval%%ch%"
goto :_ascii_chr_LOOP
:_ascii_chr_DONE
:_ascii_chr_RETURN
endlocal & set %_RETvar%^=%_RETval%
goto :EOF
::

:: end :: FUNCTIONS (library:rev76)

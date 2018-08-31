#
# msls - GNU ls for Microsoft Windows
# Ported to Microsoft Windows by Alan Klietz
#
# Based on GNU FileUtils 4.1
#
# Windows Extensions copyright (c) 2010-2018, U-Tools Software LLC
# Distributed under GNU General Public License version 2.
#


#
# To build run SETBUILD.CMD to configure your environment.  You
# will need to adjust the file paths to match your build environment.
#
# To compile run BUILD.CMD.
#

#
# Compiling with Visual Studio 6 C++
# ----------------------------------
#
# By default msls is compiled using Visual Studio 6.  It uses either the
# April 2005 Platform SDK ("MSSDK05") or the March 2006 Platform SDK
# ("MSSDK06"). The Platform SDK is necessary to pick up the new features
# for XP.  (The new features for Vista are hand-rolled into the
# msls header files.)
#
# The original purpose of MSSDK0x was to port legacy apps to compile
# for 64-bit Windows.  It includes a free 64-bit C++ compiler.
# By fortunate happenstance it is also 95% compatible for building
# 32-bit apps for legacy operating systems.
#
# There are a few inadvertent quirks in MSSDK0x that break
# compatibility with VS6.  Some libraries accidentally include the VS2005
# PDB debug symbols, which the VS6 linker chokes on.  So you will need
# to scrounge for a Visual Studio 2005 (or 2008) linker to link the
# DEBUG version with the VS6 object files.
#

#
# Note for Visual Studio 6
# ------------------------
#
# Visual Studio 6 was withdrawn by Microsoft in response to a
# lawsuit by Sun Microsystems regarding J++ (Microsoft's Java implementation),
# which Microsoft then withdrew by removing VS6 from the market.  This means
# that Visual Studio 6 is no longer available for sale anywhere.
#

#
# Compiling with Visual Studio 2005/2008/2010/2013/2015 C++
# ----------------------------------------------------------
#
# Alternately you can use the Visual Studio 2005/2008/2010/2013/2015
# C++ compiler.  Full backward compatibility all the way back to Windows 95
# is possible with 2005/2008.  2010 or later will limit execution to newer
# operating systems.
#
# Full backward compatibility requires the Windows Software Development Kit
# Update for Windows Vista, dated February 2007 ("MSSDK07").
#
# Unfortunately MSSDK07 omits the legacy 32-bit MSVCRT.LIB, which
# is necessary to link apps for pre-XP operating systems.
# MSSDK07 only includes the 64-bit legacy MSVCRT.LIB.  VS2005/8 only
# includes MSVCRT.LIB for MSVCR80.DLL/MSVCR90.DLL.
#
# To use VC2005/8 C++ for 100% backward compatibility you will need to
# scrounge for MSVCRT.LIB from a Visual Studio 6 installation.
# Preferrably one patched to VS6 Service Pack 6
# (file MSVCRT.LIB dated August 23 2000).  For debugging you will
# need MSVCRTD.LIB.
#
# And you will need to splice in some missing .OBJ files:
# __alloca_probe_16.obj, __aulldvrm.obj, and __ftol2.obj.
# Use lib.exe to extract them from VS2005/8's MSVCRT.LIB.
#
# To compile with VS2005 or later, comment-out USE_VS6 below.  Also
# change "SETBUILD.CMD vc6" in BUILD.CMD as follows:
#
# setbuild vc6 --> Use VS6 compiler + VS6 libs
# setbuild vc86 --> Use VS2005 compiler (VC8) + VS6 libs
# setbuild vc8 --> Use VS2005 compiler (VC8) + VS2005 libs (MSVCR80.DLL)
# setbuild vc96 --> Use VS2008 compiler (VC9) + VS6 libs
# setbuild vc9 --> Use VS2008 compiler (VC9) + VS2008 libs (MSVCR90.DLL)
# setbuild vc106 --> Use VS2010 compiler (VC10) + VS6 libs
# setbuild vc10 --> Use VS2010 compiler (VC10) + VS2010 libs (MSVCR100.DLL)
# setbuild vc12 --> Use VS2013 compiler (VC12) + VS2012 libs (MSVCR120.DLL)
# setbuild vc14 --> Use VS2015 compiler (VC14) + VS2015 libs
#
# Apps compiled with Visual Studio 2010 (VC10) or later will not run on
# Windows 2000 because VC10 dropped support for Windows 2000.  Ditto W9x,
# NT, XP SP1, and W2K3 SP0.
#
# WARNING: The linker (link.exe) in Visual Studio 2008/2010/2013 (VC9/VC10/VC12)
# will hard-wire the .EXE header to Version 5 or 5.01.  This will prevent
# execution on Windows 2000, Windows NT (Version 5.0)
# or Windows 9x (Version 4).  To run on 2000/NT/Win9x you must build with
# VS2005 or with VS6.
# Visual Studio 2015 will limit execution to Windows Vista or later.
#
USE_VS6=1

#
# To build without BUILD.CMD type
#    nmake CFG="msls - Win32 Release"
# or nmake CFG="msls - Win32 Debug"
#    as applicable.
#

!IF "$(CFG)" == ""
CFG=msls - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to msls - Win32 Debug.
!ENDIF

!IF "$(CFG)" != "msls - Win32 Release" && "$(CFG)" != "msls - Win32 Debug"
!MESSAGE
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE
!MESSAGE nmake CFG="msls - Win32 Debug"
!MESSAGE
!MESSAGE Possible choices for configuration are:
!MESSAGE
!MESSAGE "msls - Win32 Release"
!MESSAGE "msls - Win32 Debug"
!MESSAGE
!ERROR An invalid configuration is specified.
!ENDIF

!IFDEF USE_VS6
# VS2005/VS2008 root for the linker to use with VS6
#VISUAL_STUDIO_20XX_ROOT=C:\Program Files\Microsoft Visual Studio 2005
VISUAL_STUDIO_20XX_ROOT=E:\VS2008
!ENDIF

CPP=cl

RSC=rc.exe

DEFS=/D HAVE_CONFIG_H /D _CONSOLE /D WIN32 /D _WIN32_WINNT=0x0500 \
	 /DSTRICT /D _MBCS /D _CRT_SECURE_NO_WARNINGS
INCLUDES=/I.

DELAYIMPLIB=delayimp.lib
LD=link.exe

!IF "$(CFG)" == "msls - Win32 Debug"
!IFDEF USE_VS6
# Specify path to mspdbXX.dll for VS2005/VS2008/VS2010/VS2013 link.exe
PATH=$(PATH);$(VISUAL_STUDIO_20XX_ROOT)\Common7\IDE
# Need VS20XX delayimp.lib for MSSDK0x
DELAYIMPLIB=$(VISUAL_STUDIO_20XX_ROOT)\VC\lib\delayimp.lib
# Need VS20XX linker for MSSDK0x libs
LD=$(VISUAL_STUDIO_20XX_ROOT)\VC\bin\link.exe
!ENDIF
!ENDIF

LIBS=kernel32.lib advapi32.lib user32.lib ole32.lib shell32.lib netapi32.lib \
	rpcrt4.lib $(DELAYIMPLIB) /delay:nobind \
	/delayload:ole32.dll /delayload:shell32.dll /delayload:netapi32.dll \
	/delayload:rpcrt4.dll

###############################################################################
!IF "$(CFG)" == "msls - Win32 Debug"

INTDIR=.\Debug
OUTDIR=.\Debug

!IFDEF USE_VS6
COPTS=/nologo /MDd /W4 /Zi /Od /D _DEBUG /Gm- /GZ
!ELSE
COPTS=/nologo /MDd /W4 /Zi /Od /D _DEBUG /Gm- /GZ
!ENDIF

CFLAGS=$(COPTS) \
	   $(DEFS) $(INCLUDES) \
	   /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /c

RSC_PROJ=/l 0x409 /d _DEBUG /fo"$(INTDIR)\ls.res"

!IFDEF USE_VS6
#LDOPTS=/opt:nowin98 /subsystem:console
LDOPTS=/subsystem:console
!ELSE
#
# BUG: The Visual C++ 2008 (VC9) linker inserts version 5.0 into the
# PE header (MajorOperatingSystemVersion=5).  There is no linker
# option to change it to 4.0.
#
# /version:4.00 sets MajorImageVersion=4, and /subsystem:console,4.00
# sets MajorSubsystemVersion=4.  However to run on Win9x/NT we also
# need to set a 3rd value, MajorOperatingSystemVersion=4.
#
# The VC9 linker does not provide an option to change
# MajorOperatingSystemVersion to 4.
#
# This prevents msls from running on Win9x or NT if linked with VC9.
#
#LDOPTS=/opt:nowin98 /version:4.00 /subsystem:console,4.00
LDOPTS=/version:4.00 /subsystem:console,4.00
!ENDIF

LDFLAGS=$(LIBS) /nologo /incremental:no /base:"0x20000000" \
	/machine:I386 /out:"$(OUTDIR)\ls.exe" /debug /release \
	/pdb:"$(OUTDIR)\ls.pdb" \
	$(LDOPTS) /map:"$(OUTDIR)\ls.map"


###############################################################################
!ELSEIF "$(CFG)" == "msls - Win32 Release"

INTDIR=.\Release
OUTDIR=.\Release

!IFDEF USE_VS6
COPTS=/nologo /MD /W4 /Zd /Og /Os /Ob1 /Gy /D NDEBUG /Gm- /GF
!ELSE
COPTS=/nologo /MD /W4 /O2 /Ot /Ob1 /Gy /D NDEBUG /Gm- /GF /GS-
!ENDIF

CFLAGS=$(COPTS) \
	   $(DEFS) $(INCLUDES) \
	   /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /c

RSC_PROJ=/l 0x409 /d NDEBUG /fo"$(INTDIR)\ls.res"

!IFDEF USE_VS6
#LDOPTS=/opt:ref,icf,nowin98 /subsystem:console
LDOPTS=/opt:ref,icf /subsystem:console
!ELSE
LDOPTS=/opt:ref,icf,nowin98 /version:4.00 /subsystem:console,4.00
!ENDIF

LDFLAGS=$(LIBS) /nologo /incremental:no /base:"0x20000000" \
	/machine:I386 /out:"$(OUTDIR)\ls.exe" /release \
	$(LDOPTS) /map:"$(OUTDIR)\ls.map"

!ENDIF
###############################################################################


OBJS="$(INTDIR)\xmalloc.obj" "$(INTDIR)\xstrdup.obj" \
	 "$(INTDIR)\xstrtol.obj" "$(INTDIR)\xstrtoul.obj" \
	 "$(INTDIR)\FindFiles.obj" \
	 "$(INTDIR)\version-etc.obj" \
	 "$(INTDIR)\quotearg.obj" "$(INTDIR)\mbswidth.obj" \
	 "$(INTDIR)\path-concat.obj" "$(INTDIR)\obstack.obj" \
	 "$(INTDIR)\human.obj" \
	 "$(INTDIR)\fnmatch.obj" "$(INTDIR)\argmatch.obj" \
	 "$(INTDIR)\strncasecmp.obj" "$(INTDIR)\filemode.obj" \
	 "$(INTDIR)\error.obj" \
	 "$(INTDIR)\closeout.obj" "$(INTDIR)\basename.obj" \
	 "$(INTDIR)\getopt1.obj" "$(INTDIR)\getopt.obj" \
	 "$(INTDIR)\dirent.obj" "$(INTDIR)\xmbrtowc.obj" \
	 "$(INTDIR)\glob.obj" "$(INTDIR)\windows-support.obj" \
	 "$(INTDIR)\more.obj" "$(INTDIR)\Streams.obj" \
	 "$(INTDIR)\Reparse.obj" "$(INTDIR)\Shortcut.obj" \
	 "$(INTDIR)\ObjectId.obj" \
	 "$(INTDIR)\CStr.obj" \
	 "$(INTDIR)\Hash.obj" \
	 "$(INTDIR)\Registry.obj" \
	 "$(INTDIR)\Security.obj" \
	 "$(INTDIR)\ViewAs.obj" \
	 "$(INTDIR)\Token.obj" \
	 "$(INTDIR)\ls.obj" \
	 "$(INTDIR)\ls.res"

all: "$(OUTDIR)\ls.exe"

#
# Force creation of INTDIR
#
"$(INTDIR)\xmalloc.obj": "$(INTDIR)" xmalloc.c

!IFDEF UNDEFINED   # Not used anymore
#
# Arrange to keep FPO (Frame Pointer Omission) debug data in the .EXE
# file, so stack trace by Dr. Watson works correctly.
#
# Use rebase.exe to strip symbols into a .DBG file, leaving only FPO debug
# data left behind in the executable.
#
# ** BUG **
# Current versions of rebase -x will *copy*, not *move*, debug symbols
# from the .EXE file!
#
# To move symbols to the .DBG file, you need to obtain the old version
# of rebase.exe from an old MSSDK CD-ROM from circa 1998.
#
"$(OUTDIR)\ls.exe": $(OBJS)
		$(LD) $(LDFLAGS) $(OBJS)
		rebase -b 20000000 -x "$(OUTDIR)" "$(OUTDIR)\ls.exe"
!ELSE
"$(OUTDIR)\ls.exe": $(OBJS)
		$(LD) $(LDFLAGS) $(OBJS)
!ENDIF

"$(INTDIR)\ls.res": ls.rc
	$(RSC) $(RSC_PROJ) ls.rc

clean:
	rm -rf Debug Release

"$(INTDIR)" :
	if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

.c{$(INTDIR)}.obj:
	$(CPP) $(CFLAGS) $<

.cpp{$(INTDIR)}.obj:
	$(CPP) $(CFLAGS) $<

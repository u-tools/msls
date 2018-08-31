#
# Based on GNU FileUtils 4.1, from MSYS source tree (1/04)
#
# Must be run under the VC6 environment!
#
# setbuild vc6
# nmake CFG="dircolors - Win32 Release"
#
#######################################################################

!IF "$(CFG)" == ""
CFG=dircolors - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to dircolors - Win32 Debug.
!ENDIF

!IF "$(CFG)" != "dircolors - Win32 Release" && "$(CFG)" != "dircolors - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE
!MESSAGE NMAKE /f "Makefile.w32" CFG="dircolors - Win32 Debug"
!MESSAGE
!MESSAGE Possible choices for configuration are:
!MESSAGE
!MESSAGE "dircolors - Win32 Release"
!MESSAGE "dircolors - Win32 Debug"
!MESSAGE
!ERROR An invalid configuration is specified.
!ENDIF

CPP=cl

DEFS=/D HAVE_CONFIG_H /D _CONSOLE /D WIN32 /D _WIN32_WINNT=0x0500 \
	 /DSTRICT /D _MBCS /D _CRT_SECURE_NO_WARNINGS
INCLUDES=/I. /I..\. /I..\ls\.

LD=link
LIBS=kernel32.lib advapi32.lib shell32.lib

!IF "$(CFG)" == "dircolors - Win32 Debug"

INTDIR=.\Debug
OUTDIR=.\Debug

CFLAGS=/nologo /MDd /W4 /GX /Zi /Od /D _DEBUG /Gm- /GZ \
	   $(DEFS) $(INCLUDES) \
	   /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /c

LDFLAGS=$(LIBS) /nologo /subsystem:console /incremental:no /base:"0x20000000" \
	/machine:I386 /out:"$(OUTDIR)\dircolors.exe" /debug /release \
	/pdb:"$(OUTDIR)\dircolors.pdb" \
	/opt:nowin98 /map:"$(OUTDIR)\dircolors.map"

!ELSEIF "$(CFG)" == "dircolors - Win32 Release"

INTDIR=.\Release
OUTDIR=.\Release

CFLAGS=/nologo /MD /W4 /GX /Zd /Og /Os /Ob1 /Gy /D NDEBUG /Gm- /GF \
	   $(DEFS) $(INCLUDES) \
	   /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /c

LDFLAGS=$(LIBS) /nologo /subsystem:console /incremental:no /base:"0x20000000" \
	/machine:I386 /out:"$(OUTDIR)\dircolors.exe" /debug /release \
	/pdb:none \
	/opt:ref,icf,nowin98 /map:"$(OUTDIR)\dircolors.map" /mapinfo:lines

!ENDIF

OBJS= \
	 "$(INTDIR)\quote.obj" \
	 "$(INTDIR)\quotearg.obj" \
	 "$(INTDIR)\xmalloc.obj" \
	 "$(INTDIR)\xmbrtowc.obj" \
	 "$(INTDIR)\strndup.obj" \
	 "$(INTDIR)\strnlen.obj" \
	 "$(INTDIR)\closeout.obj" \
	 "$(INTDIR)\getline.obj" \
	 "$(INTDIR)\version-etc.obj" \
	 "$(INTDIR)\basename.obj" \
	 "$(INTDIR)\obstack.obj" \
	 "$(INTDIR)\error.obj" \
	 "$(INTDIR)\getstr.obj" \
	 "$(INTDIR)\getopt1.obj" "$(INTDIR)\getopt.obj" \
	 "$(INTDIR)\dircolors.obj"

all: "$(OUTDIR)\dircolors.exe"

#
# Force creation of INTDIR
#
"$(INTDIR)\quote.obj": "$(INTDIR)" quote.c

#
# Use rebase to strip symbols into a .DBG file, leaving only FPO debug data
# in the executable.
#

"$(OUTDIR)\dircolors.exe": $(OBJS)
		$(LD) $(LDFLAGS) $(OBJS)
		rebase -b 20000000 -x "$(OUTDIR)" "$(OUTDIR)\dircolors.exe"

clean:
	rm -rf Debug Release

"$(INTDIR)" :
	if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

.c{$(INTDIR)}.obj::
	$(CPP) $(CFLAGS) $<

.cpp{$(INTDIR)}.obj::
	$(CPP) $(CFLAGS) $<

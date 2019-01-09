//
// Wrap stdio for more-style pagination
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

//
// This is a built-in paginator ("Press any key to continue..")
//
// It is required because piping 'ls | more' does not
// work for colors.   This is because of the way that colors are displayed
// in console mode.  Colors are set not by ANSI escape codes embedded in
// the text stream, but rather they are set by doing direct hardware
// pokes on the console framebuffer via WriteConsole().
//
// Thus the paginator needs to be 'aware' of colors outside the context
// of the byte stream.   Piping 'ls | more' cannot work.
//
// If not running in a console window, the paginator falls back to the
// Unix-style escape codes.  Thus it works correctly both in console mode
// and in a 'real' GUI shell (e.g., Emacs and rxvt).
//
// This module depends on complex initialization gymnastics to
// work properly between OEM (console mode) and ANSI (GUI) character sets.
// See the comments in ls.c surrounding setlocale()
//
#include "config.h"

#ifdef WIN32
#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
// For VC6, disable warnings from various standard Windows headers
// NOTE: #pragma warning(push) ... #pragma warning(pop) is broken/unusable for MSVC 6 (re-enables multiple other warnings)
#pragma warning(disable: 4068)  // DISABLE: unknown pragma warning
#pragma warning(disable: 4035)  // DISABLE: no return value warning
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
#pragma warning(default: 4068)  // RESET: unknown pragma warning
#pragma warning(default: 4035)  // RESET: no return value warning
#endif
#endif

#include <stdio.h>
// BUG: (for some MSVC 1900 versions) putc() is defined incorrectly when _CRT_DISABLE_PERFCRIT_LOCKS is defined
#if defined(_CRT_DISABLE_PERFCRIT_LOCKS) && defined(_MSC_VER) && (_MSC_VER >= 1900) && (_MSC_VER < 2000)
#undef putc
#define putc(_Ch, _Stream) _fputc_nolock(_Ch, _Stream)
#endif

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <io.h> // for _isatty()

#include <mbstring.h>

#ifdef WIN32
#include <conio.h> // for getch
#endif

#include "xalloc.h"
#include "more.h"
#include "error.h"
#include "windows-support.h"
#include "tabsize.h"
// #include "ls.h" // for tabsize


#define STDMORE_BUFSIZ 16384

#ifdef WIN32
//
// By default Win32 console programs use the apallingly slow thread-safe
// version of putc() in MSVCRT.DLL for locking multi-threaded writes.
// Use the macro instead since we know we are single-threaded.
//
// (Also use setvbuf() to get the best speedup.)
//
// Visual Studio 2015's UCRT hides FILE as an opaque type so this optimization
// is no longer possible.  Instead we define _CRT_DISABLE_PERFCRIT_LOCKS
// in config.h.
//
#if defined (_MSC_VER) && (_MSC_VER < 1900) // If pre-Visual Studio 2015
#undef putc
#define putc(_c,_stream)  (--(_stream)->_cnt >= 0 \
    ? 0xff & (*(_stream)->_ptr++ = (char)(_c)) :  _flsbuf((_c),(_stream)))
#endif
#endif

static int more_enabled;

static char morebuf[STDMORE_BUFSIZ+10];
static struct more _stdmore_dat = { morebuf, STDMORE_BUFSIZ, morebuf,
    0, STDMORE_BUFSIZ, NULL, -1, 0 };
struct more* stdmore = &_stdmore_dat;

#define STDMORE_ERR_BUFSIZ 1
static char err_morebuf[STDMORE_ERR_BUFSIZ+3];
static struct more _stdmore_err_dat = { err_morebuf, STDMORE_ERR_BUFSIZ,
    err_morebuf, 0, STDMORE_ERR_BUFSIZ, NULL, -1, 0 };
struct more* stdmore_err = &_stdmore_err_dat;

static int _more_paginate(struct more* m, int n);

//
// BUG: MSVCRT.DLL in Windows 8 (and possibly as early as Windows Vista)
// forces write() to send 1 character at a time if the output is a tty.
// It is doing some hairy MBCS translations through code page tables.
//
// Slloooowww...
//
// MSVCRT.DLL does two system calls (GetConsoleMode and WriteConsole) for
// every output character, which makes the output crawl even on a fast PC.
//
// It generates only one character at a time, with complex checks for
// double-byte MBCS characters, deep inside of write().
//
// What is happening is that MSVCRT.DLL under Windows 8 was modified
// to handle the situation where the MBCS codepage is not the same as the
// console codepage.  It is a pessimization, as it performs an unnecessary
// double-conversion on each individual character:  MBCS -> Unicode ->
// ConsoleCP, even when the MBCS codepage and the ConsoleCP are the same
// (which is always the case for msls.)
//
// Note that Windows does *not* support writing pure Unicode to a console
// handle via WriteFile.  (The displayed output is gibberish, even with
// the Lucida Console font.) NtWriteFile() to a console handle must always
// use MBCS.  It is mapped to Unicode in the kernel using the code page set
// by SetConsoleOutputCP.
//
// To write pure Unicode to a console you must use WriteConsoleW() explicitly,
// and the console font has to support TrueType to render any Unicode glyphs
// that cannot be directly represented in the code page.   The kernel still
// does the double-conversion (Unicode -> MBCS -> Unicode), so in fact the
// full path is this:
//
// MBCS (User's codepage) -> Unicode (in MSVCRT.DLL write) ->
// MBCS (Console's codepage, also in write) -> Unicode (ditto)
// -> WriteConsoleW (call into kernel) -> console's codepage -> NtWriteFile
//
// That is seven conversions. Small wonder console output is so slow.
// (This might get fixed in Windows 10.)
//
// WORKAROUND: We temporarily change the console's codepage to match
// the user's default codepage, so the multi-step conversion is not necessary.
// It hugely speeds up writes to the console.  Or it ought to.  However,
// the CRT does not check if the MBCS codepage matches the console codepage,
// so it still insists on doing the double-conversion in user mode.
// Even if we generated pure Unicode (or even UTF-8), it still does the
// tedious Unicode-to-console_codepage conversion. This is because,
// by design, the console does _not_ accept Unicode characters in WriteFile()
// -- they display as gibberish (even on Windows 8).  So all Unicode output
// must go through WriteConsoleW() and not WriteFile(), as the former
// correctly translates the string to the console MBCS codepage to display it.
//
// The operating system does the MBCS-to-Unicode conversion
// (inside of NtWriteFile), even if the console font is a TrueType font
// that can display Unicode directly (e.g., Lucida Console).
//
// WORKAROUND #2: During output, intercept calls to _isatty() and lie about
// stdout or stderr being a tty.  This will trick MSVCRT.DLL into using
// WriteFile to write to the console (and invoke only one syscall for the
// entire output buffer).  The performance speedup is dramatic.
//
// write() will still correctly do FTEXT (\n to \r\n) conversions properly on
// a non-tty, so our spoofing isatty() won't break it.
//

typedef BOOL (WINAPI *PFNVIRTUALPROTECT)(
    IN  PVOID lpAddress,
    IN  SIZE_T dwSize,
    IN  DWORD flNewProtect,
    OUT PDWORD lpflOldProtect
);
static PFNVIRTUALPROTECT pfnVirtualProtect;

// 0=stdin, 1=stdout, 2=stderr
#define ISATTY_CACHE_LEN 3
static int isatty_cache[ISATTY_CACHE_LEN] = {1, 1, 1};

static BOOL intercepting_isatty;

static int _my_isatty(int fh)
{
    if (intercepting_isatty) {
        if (fh >= 0 && fh < ISATTY_CACHE_LEN) {
            return 0; // lie
        }
    }
    if (fh >= 0 && fh < ISATTY_CACHE_LEN) {
        return isatty_cache[fh];
    }
    return 0; // assume not a tty
}

static void InitInterceptIsatty()
{
    DWORD dwPrevProtect = 0;
    DWORD dwDummy = 0;
    PBYTE pbIsatty = NULL;

    typedef int (*PFN_ISATTY)(int);
    static PFN_ISATTY pfnIsatty;
#ifdef _DLL
# ifdef _DEBUG
#  if _MSC_VER < 1300 // if VC6
#   define MSVCRT "MSVCRTD.DLL"
#  else
#   error Need to change MSVCRTD.DLL to MSVCR1xxD.DLL (VC7-12) or UCRTBASED.DLL (VC14+)
#  endif
# else // !_DEBUG
#  if _MSC_VER < 1300 // if VC6
#   define MSVCRT "MSVCRT.DLL"
#  else
#   error Need to change to MSVCR1xx.DLL (VC7-12) or UCRTBASE.DLL (VC14+)
#  endif
# endif
    if (!DynaLoad(MSVCRT, "_isatty", (PPFN)&pfnIsatty)) {
        error(EXIT_FAILURE, 0, "Cannot find _isatty.");
        return; /*NOTREACHED*/
    }
#else // statically link with LIBCMT.LIB
    pfnIsatty = _isatty;
#endif

    pbIsatty = (PBYTE)(*(void **)(&pfnIsatty));
    //
    // Cache the real isatty property for stdin, stdout, and stderr
    //
    isatty_cache[0] = _isatty(0);
    isatty_cache[1] = _isatty(1);
    isatty_cache[2] = _isatty(2);

    // Not available on Win9x
    if (!DynaLoad("KERNEL32.DLL", "VirtualProtect",
            (PPFN)&pfnVirtualProtect)) {
        error(EXIT_FAILURE, 0, "Cannot find VirtualProtect.");
        return; /*NOTREACHED*/
    }

#ifdef _WIN64
# define PATCH_INSN_LEN 17
#else
# define PATCH_INSN_LEN 5
#endif

    if (!(*pfnVirtualProtect)(*(void **)(&pfnIsatty), PATCH_INSN_LEN, PAGE_WRITECOPY, &dwPrevProtect)) {
        error(EXIT_FAILURE, 0, "Cannot change protection on _isatty().");
        return; /*NOTREACHED*/
    }

#pragma warning(push)
#pragma warning(disable: 4054)
#ifdef _WIN64
    //
    // Patch _isatty() to jump indirectly to our function
    //
    // BUG: The Intel Optimization Guide urges avoiding placing the indirect
    // jump address immediately following the indirect JMP. This is because
    // the CPU micro-decoder will try to speculatively decode the jump address
    // data as instructions and cause a massive slowdown.
    //
    // WORKAROUND: Insert a PAUSE instruction (F3 90) after the indirect JMP.
    // This tells the CPU micro-decoder to not attempt speculative execution.
    //
    // 3E               ; no-track prefix for control-flow enforcement
    // FF 25 00000002   ; Relative offset from next insn to an absolute address
    // F3 90            ; PAUSE insn to stop decoding insns
    // xx xx xx xx xx xx xx xx ; absolute address of function _my_isatty
    //
    //
    pbIsatty[0] = 0x3E; // jmp/call no-track prefix for control-flow enforcement
    pbIsatty[1] = 0xFF;
    pbIsatty[2] = 0x25;  // Indirect JMP
    // Not aligned
    *(PDWORD)(pbIsatty + 3) = 2; // indirect addr
    pbIsatty[7] = 0xF3;  // PAUSE instruction
    psIsatty[8] = 0x90;
    *(PQWORD)(pbIsatty + 9) = (QWORD)_my_isatty;
#else
    //
    // Patch _isatty() to jump to _my_isatty().
    //
    // E9 xx xx xx xx   ; jmp relative to next insn
    //
    // Note: VC12 uses an indirect call: FF 15 xxxxxxxx -> xxxxxxxx -> _isatty()
    //
    *pbIsatty = 0xE9;
    // Not aligned
    *(PDWORD)(pbIsatty + 1) = (DWORD)((PBYTE)_my_isatty - (pbIsatty + 5));
#endif // x86
#pragma warning(pop)
    // Restore protection
    if (!(*pfnVirtualProtect)(*(void **)(&pfnIsatty), PATCH_INSN_LEN, dwPrevProtect, &dwDummy)) {
        error(EXIT_FAILURE, 0, "Cannot restore protection on _isatty().");
        return; /*NOTREACHED*/
    }
    return;
}

static void InterceptIsatty(BOOL bEnable)
{
    intercepting_isatty = bEnable;
}

int more_enable(int enable)
{
    int oldval = more_enabled;
    more_enabled = enable;
    return oldval;
}

int more_fflush(struct more *m)
{
    int n;

    if (m->err) return EOF;

    n = m->ptr - m->base;
    m->ptr = m->base;
    m->cnt = m->bufsiz;

    if (n == 0) {
        return 0;
    }

    m->nflushed += n;  // total bytes flushed
    //
    // Feed out n bytes
    //
    if (_more_paginate(m, n) == EOF) {
        m->ptr = m->base; m->cnt = 0; m->err =  1;
        return EOF;
    }
    return 0;
}


int _more_flushbuf(char ch, struct more *m)
{
    if (more_fflush(m) == EOF) {
        return EOF;
    }
    return more_putc(ch, m);
}

int more_fputs(const char *s, struct more* m)
{
    int n;

    for (n = (int)strlen(s); n > 0; --n) {
        if (more_putc(*s, m) == EOF) {
            return EOF;
        }
        ++s; // do _not_ increment in more_putc - macro!
    }
    return 0;
}

size_t more_fwrite(const char *s, int siz, int len, struct more* m)
{
    int  n = siz * len, i;

    for (i=0; i < n; ++i) {
        if (more_putc(*s, m) == EOF) {
            return (size_t)i;
        }
        ++s; // do _not_ increment in more_putc - macro!
    }
    return (size_t)n;
}

int
_more_doprintf(struct more* m, const char *fmt, va_list args)
{
    int ret;
    char buf[2048];

    ret = _vsnprintf(buf, sizeof(buf)-1, fmt, args);

    if (ret <= 0) { // too big
        return ret;
    }

    if (more_fwrite(buf, 1, ret, m) != (size_t)ret) {
        return -1;
    }

    return ret;
}

int
more_fprintf(struct more *m, const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = _more_doprintf(m, fmt, args);
    va_end(args);

    return ret;
}

int
more_vfprintf(struct more *m, const char *fmt, va_list args)
{
    return _more_doprintf(m, fmt, args);
}

int
more_printf(const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = _more_doprintf(stdmore, fmt, args);
    va_end(args);

    return ret;
}

////////////////////////////////////////////////////////////////////////

int _send_output(FILE *f, char *s, int n)
{
    if (fwrite(s, 1, n, f) != (size_t)n) {
        return EOF;
    }
    return fflush(f);
}

#define TABSIZE tabsize // from ls.c

static int rows=40, cols=80; // defaults
static int currow=0, curcol=0;

//
// Feed out m->base, n bytes
//
static int __more_paginate(struct more* m, int n)
{
    static int init = 0;
    static int bHasTerm;
#ifdef WIN32
    static HANDLE hConsole;
    static CONSOLE_SCREEN_BUFFER_INFO csbi;
#endif
    char *s, ch;

    if (init == 0) {
        init = 1;
#ifdef WIN32
        if ((hConsole = GetStdHandle(STD_ERROR_HANDLE)) == INVALID_HANDLE_VALUE) {
            bHasTerm = 0;
        } else if (GetConsoleScreenBufferInfo(hConsole, &csbi) == 0) {
            bHasTerm = 0;
        } else {
            rows = (csbi.srWindow.Bottom - csbi.srWindow.Top) + 1;
            cols = (csbi.srWindow.Right - csbi.srWindow.Left) + 1;
            bHasTerm = 1;
        }
#else
# ifdef TIOCGWINSZ
        {
            struct winsize ws;

            if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) != -1 && ws.ws_col != 0) {
              rows = ws.ws_row;
              cols = ws.ws_col;
              bHasTerm = 1;
            } else {
              bHasTerm = 0;
            }
        }
# else
#warning Missing TIOCGWINSZ - cannot determine # of rows and cols
        bHasTerm = 0;
# endif
#endif
    } // init

    if (m->istty == -1) { // dunno if we are a tty
        if (m->file == NULL) {
            if (m == stdmore) {
                m->file = stdout;
            } else if (m == stdmore_err) {
                m->file = stderr;
            }
        }
        if (!bHasTerm) {
            m->istty = 0;
        } else {
            // Determine if we really are using a true TTY (no intercept)
            InterceptIsatty(FALSE);
            m->istty = isatty(fileno(m->file));
            InterceptIsatty(TRUE);
        }
    }

    if (n <= 0) {
        return 0;
    }

    if (n > 100000) { // sanity check
        return EOF;
    }

    if (!more_enabled || !m->istty) { // not a tty, just output as-is
        return _send_output(m->file, m->base, n);
    }

    /////////////////////////////////////////////////////////////////
    //
    // Send output, pausing on full screen
    //
    for (s = m->base; n > 0; --n) {
        ch = *s++;
        if (putc(ch, m->file) == EOF) {
            return EOF;
        }
        //
        // _ismbblead(ch): Leading byte is in range 0x81-0x9F or 0xE0-0xFC.
        // The trailing byte is guaranteed to be in range 0x40-0xFC (not 0x7F).
        // See _ismbclegal.  Used for Katakana, Kanji, and other
        // Asian language code pages.
        //
        if (_ismbblead(ch)) {
            //
            // Try to output the second byte if available
            //
            if (n-1 > 0) {
                if (putc(*s, m->file) == EOF) {
                    return EOF;
                }
                ++s; --n;
            } else {
                //
                // BUG: A multibyte char was split at the buffer edge.
                // This will throw the count off if the trailing byte
                // is in 0x81-0x7E,0x80-0x9F,0xE0-0xFC.
                //
                // Since it will always overestimate, it will never
                // overscroll (only underscroll) so it should be safe to
                // ignore.
                //
                // You can reduce occurences of this bug by making
                // STDMORE_BUFSIZ bigger.
                //
            }
        }

        if (ch == '\n') {
            ++currow;
            curcol = 0;
        } else if (ch == '\r') {
            // ignore
        } else if (ch == '\t') {
#ifdef _DEBUG
            if (TABSIZE == 0) {
                fputs("\n\nTried to print tab with -T0 -- aborting (DEBUG)\n", stderr);
                fflush(stderr);
                *(int *)0 = 0; // boom
            }
#endif
            curcol += (TABSIZE == 0 ? 8 : TABSIZE) - curcol % (TABSIZE == 0 ? 8 : TABSIZE);
        } else if (ch >= 32) { // if not a control char
            ++curcol;
        }

        // Wrap on right
        if (curcol >= cols) {
            curcol=0;
            ++currow;
        }

        if (currow >= rows-1-(1/*lines of previous screen to keep*/)) {
            currow = curcol = 0;
            if (fflush(m->file) == EOF) {
                return EOF;
            }
            fputs("Press any key to continue . . .", stderr);
            fflush(stderr);
            //
            // Use raw-mode getch
            //
            // For Unix set raw mode here
            //
            ch = (char)getch(); // (700 line function, ugh..)
            fputs("\r                               \r", stderr);
            //      "Press any key to continue . . ."
            fflush(stderr);
            //
            // BUG: Control-C does not trigger the signal handler
            // when using getch()!
            //
            if (ch == '\003') { // if we see ^C, bail immediately
                exit(1);
            }
        }
    }

    return fflush(m->file);
}


static int _more_paginate(struct more* m, int n)
{
    int ret;
    static int intercept_isatty = 0;
    static int bInPaginator;

    //
    // Intercept _isatty() on Vista or later
    //
    if (!intercept_isatty && IsVista) {
        InitInterceptIsatty();
        intercept_isatty = 1;
    }

    InterceptIsatty(TRUE);

    if (bInPaginator) {
        //
        // Oops, we recursed somehow (prob via error())
        //
        ret = _send_output(m->file, m->base, n);
    } else {
        bInPaginator = 1;
        ret = __more_paginate(m, n);
        bInPaginator = 0;
    }

    InterceptIsatty(FALSE);

    return ret;
}

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

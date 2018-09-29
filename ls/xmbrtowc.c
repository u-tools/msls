//
// Microsoft implemented _mbrtowc() in MSVCRT.DLL but they
// forgot to export it from the DLL (oops).
//
// So we roll own _mbrtowc() here.  This is sui-genris implementation
// w/o reference to the MSVCRT code.  Since I was doing it from scratch
// I decided to add UTF-8 support as an exercise.
//
// Copyright (c) 2004-2018 U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wchar.h>
#include <tchar.h>
#include <mbctype.h>
#include <locale.h>

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
// For VC6, disable warnings from various standard Windows headers
// NOTE: #pragma warning(push) ... #pragma warning(pop) is broken/unusable for MSVC 6 (re-enables multiple other warnings)
#pragma warning(disable: 4068)  // DISABLE: unknown pragma warning
#pragma warning(disable: 4035)  // DISABLE: no return value warning
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <errno.h>

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
#pragma warning(default: 4068)  // RESET: unknown pragma warning
#pragma warning(default: 4035)  // RESET: no return value warning
#endif

#include "error.h"

#include "windows-support.h"
#include "xmbrtowc.h"
#include "ls.h"

extern int _HasConsole();

#if WCHAR_MAX != 0xFFFF  // If MSSDK05 or earlier
//
// BUG: MSSDK05 and VS6 forgot to define mbsinit outside of __cplusplus.
//
int mbsinit(const mbstate_t *mbs)
{
    // Return TRUE if mbstate_t is still in the initial state
    return (mbs==NULL || *mbs == 0);
}
#endif

//
// Get the user current default OEM/ANSI code page
//
// Use OEM if outputting to a console window, otherwise use ANSI
//
int get_codepage()
{
    //
    // BUG: The XP MUI version of Windows is based on the English
    // version with the MUI languages layered on top of it.
    //
    // However GetACP/GetOEMCP are insensitive to the MUI language.
    // In MUI XP, for example, GetACP always is 1252 and GetOEMCP is 437
    // regardless of the MUI language.   This means that CP_ACP
    // and CP_OEM cannot be used with a MUI edition of Windows.
    // Only 100% pure Unicode apps will work correctly!
    //

    return (int) (gbOemCp ? GetOEMCP() : GetACP());

#ifdef UNDEFINED
    if (_HasConsole() && isatty(STDOUT_FILENO)) {
        //
        // msls is running under a console.  Use the console's current
        // output codepage.
        //
        // BUG: If the user's current locale (LCID) does not support a
        // console codepage, this function punts and returns CP_OEMCP,
        // which the system maps to the ANSI code page.  If the ANSI
        // code page also does not exist (e.g., Arabic languages), the
        // actual console codepage is 437 (United States OEM).  This means
        // that displaying Arabic file names in a console window using
        // MBCS is impossible.  The only workaround is to re-write all of
        // msls using Unicode, which is too hard.
        //
        // BUG: If redirecting output to a file, msls uses the ANSI codepage.
        // This allows the file to be viewed correctly in Notepad or Word.
        // However it screws up parsing argv[] command-line input,
        // and error messages to stderr will be wrong.
        //
        _codepage = GetConsoleOutputCP();
        return;
    }

    int lcidCountry = GetThreadLocale();
    char szCodePage[8];
    szCodePage[0] = _T('\0');

    int lcidCountry = GetUserDefaultLCID();
    int info = /*LOCALE_IDEFAULTCODEPAGE -- OEM*/
                 LOCALE_IDEFAULTANSICODEPAGE /* -- ANSI*/;

    //
    // Note: If the requested OEM/ACP codepage for the user user's
    // current local LCID does not exist, GetLocalInfo punts and returns
    // CP_OEM (1) or, failing that CP_ACP (0).
    //
    // For example, Arabic languages do not work on a console.
    //
    if (!GetLocaleInfo(lcidCountry,
            info,
            szCodePage, sizeof(szCodePage)) ||
            ((_codepage = (int)atol(szCodePage)) == 0
                && szCodePage[0] != '0')) {
        error(EXIT_FAILURE, 0, "Unable to get locale info.");
    }
#endif
}

static UINT guiOriginalConsoleCP;
static UINT guiOriginalConsoleOutputCP;

typedef BOOL (WINAPI *PFNSETCONSOLECP)(
    IN UINT wCodePageID
);
static PFNSETCONSOLECP pfnSetConsoleCP;

typedef BOOL (WINAPI *PFNSETCONSOLEOUTPUTCP)(
    IN UINT wCodePageID
);
static PFNSETCONSOLEOUTPUTCP pfnSetConsoleOutputCP;

typedef UINT (WINAPI *PFNGETCONSOLECP)(VOID);
static PFNGETCONSOLECP pfnGetConsoleCP;

typedef UINT (WINAPI *PFNGETCONSOLEOUTPUTCP)(VOID);
static PFNGETCONSOLEOUTPUTCP pfnGetConsoleOutputCP;

//
// Set the codepage for console output
//
// Requires HasConsole() to be TRUE, otherwise it aborts.
//
void SetConsoleCodePage(int cp)
{
    //
    // BUG: We must explicitly set the _input_ code page for MSVCRT.DLL on
    // Windows 8.1 (and maybe earlier), because it attempts to convert the
    // MBCS to Unicode manually just before calling WriteFile() in _write().
    //
    if (DynaLoad("KERNEL32.DLL", "SetConsoleCP", // Sets the input codepage
            (PPFN)&pfnSetConsoleCP)) { // Not avail on Win95
        if (guiOriginalConsoleCP == 0) {
            guiOriginalConsoleCP = GetConsoleCP(); // available on Win95
        }
        // Note: Might fail for Arabic or Hindu languages that have a codepage
        // that cannot be displayed on a console.
        if (!(*pfnSetConsoleCP)((UINT)cp)) {
#ifdef _DEBUG
            error(EXIT_FAILURE, 0, "Unable to set the codepage for the console.");
#endif
        }
    }
    //
    // BUG: We must call both SetConsoleCP() _and_ SetConsoleOutputCP(),
    // otherwise the MSVCRT MBCS-to-Unicode output functions go wonky.
    //
    if (DynaLoad("KERNEL32.DLL", "SetConsoleOutputCP",
            (PPFN)&pfnSetConsoleOutputCP)) { // Not avail on Win95
        if (guiOriginalConsoleOutputCP == 0) {
            guiOriginalConsoleOutputCP = GetConsoleOutputCP(); // avail on Win95
        }
        // Note: Might fail for Arabic or Hindu languages that have a codepage
        // that cannot be displayed on a console.
        if (!(*pfnSetConsoleOutputCP)((UINT)cp)) {
#ifdef _DEBUG
            error(EXIT_FAILURE, 0, "Unable to set the codepage for console output.");
#endif
        }
    }
    return;
}

//
// Restore the console codepage at exit
//
void RestoreConsoleCodePage()
{
    if (guiOriginalConsoleCP && pfnSetConsoleCP
            && (PFN)pfnSetConsoleCP != LOAD_FAIL) {
        (*pfnSetConsoleCP)(guiOriginalConsoleCP);
    }
    if (guiOriginalConsoleOutputCP && pfnSetConsoleOutputCP
            && (PFN)pfnSetConsoleOutputCP != LOAD_FAIL) {
        (*pfnSetConsoleOutputCP)(guiOriginalConsoleOutputCP);
    }
    return;
}

//
// Set the codepage for kernel file APIs and CRT functions
//
void SetCodePage(int bAnsi)
{
    //
    // BUG: We have to use the system-wide codepage (CP_ACP or CP_OEM)
    // to stay in sync with SetFileApisToANSI() and SetFileApisToOEM(),
    // which both only use CP_ACP or CP_OEM (Win95 doesn't have CP_THREAD_CP).
    //
    // This is required because we use ANSI file APIs (GetFileAttributesA),
    // and the kernel uses CP_ACP implicitly, even on Windows 10.
    //
    // We must use ANSI, not Unicode, because the Unicode APIs are not
    // available on Win95.
    //
    // The proper way to do this is to dynaload the Unicode file
    // APIs:  (*pfnGetFileAttributesW)(...), (*pfnFindFirstFileW)(...)
    // and explicitly translate using WideCharToMultiByte(get_codepage(),...).
    // Ditto the registry APIs.  Then we can use CP_THREAD_ACP (and
    // fall back to CP_ACP on Win9x.)
    //
    // The problem is that Win9x doesn't have Unicode so we have to
    // dynaload every Unicode file API, which is a pain.  TODO
    //

    // ".1252", ".437"
    TCHAR szCodePage[80];
    _sntprintf(szCodePage, sizeof(szCodePage)/sizeof(TCHAR),
        _T(".%d"), (bAnsi ? GetACP() : GetOEMCP()));

    if (bAnsi) {
        //
        // Use the ANSI charset for FindFirstFile/FindNextFile
        //
        SetFileApisToANSI(); // hard coded to use system-wide GetACP()
        //
        // Arrange for CRT locale-sensitive string functions to use the
        // per-user ANSI codepage instead of the "C" locale.
        //
        // DESIGN BUG: This does _not_ change the USER32.DLL codepage for
        // wsprintfA() (which uses the per-user codepage),
        // nor does it change the ANSI file APIs (e.g., GetFileAttributesA),
        // which always use the system-wide CP_ACP or CP_OEM.
        //
        // Do not try to change the USER32 codepage with SetLocalInfo().
        // It is sticky, and it *permanently* changes the locale in the
        // Control Panel! Do not use.
        //
        // Use the ANSI codepage.  (Instead of "C" codepage)
        setlocale(LC_ALL, szCodePage); // ".1252"
        //setlocale(LC_ALL, ".ACP"); // WRONG -- uses per-user ACP, not GetACP()
    } else { // OEM
        //
        // Arrange to have CreateFile() and FindFirstFile() use the OEM
        // character set for input and output instead of the ANSI character set.
        //
        SetFileApisToOEM(); // hard coded to use system-wide GetOEMCP()
        //
        // Arrange for CRT locale-sensitive string functions to use the OEM
        // codepage instead of the the ANSI codepage.
        //
        setlocale(LC_ALL, szCodePage); // ".437"
        //setlocale(LC_ALL, ".OCP"); // WRONG -- uses per-user OEMCP, not GetOEMCP()
    }
    //
    // *Must* set the multibyte code page after changing the locale,
    // otherwise MBCS string functions will continue to use the
    // "C" code page!
    //
    if (_setmbcp(_MB_CP_LOCALE) < 0) { // set to ANSI
      error(EXIT_FAILURE, 0, "_setmbcp: unable to set code page");
    }
    return;
}

//
// Determine UTF byte length.
//
// Note: Since mbstate_t is defined as int we cannot
// handle 5 or 6 byte chars.
//
static size_t _utf8_len(const char *s)
{
    unsigned char c = (unsigned char)*s;

    if (c < 0xC0) return 1;
    if (0xC0 <= c && c <= 0xDF) return 2;
    if (0xE0 <= c && c <= 0xEF) return 3;
    if (0xF0 <= c && c <= 0xF7) return 4;
    if (0xF8 <= c && c <= 0xFB) return (size_t)-1; // 5 bytes unsupported
    if (0xF8 <= c && c <= 0xFD) return (size_t)-1; // 6 bytes unsupported
    return (size_t)-1; // Unicode endian markers 0xFE and 0xFF unsupported
}


#if defined(_MSC_VER) && (_MSC_VER < 1900) // If pre-UCRT
//
// Implement mbrtowc per Standard ANSI C using MultiByteToWideChar
// and the user default current code page.
//
// This works with all codepages: Latin, Asian, and CP_UTF8.
//
size_t __cdecl
xmbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *pst)
{
    static mbstate_t mbst = 0;
    size_t bytelen = MB_CUR_MAX;
    int bLead;
    int _codepage = get_codepage();

    if (pst == NULL) {
        pst = &mbst; // note: not thread-safe
    }
    if (s == NULL) {
        pwc = NULL;
        s = "";
    }
    if ( s == NULL || n == 0 ) {
        return 0;
    }
    if ( *s == '\0') {
        if (pwc) {
            *pwc = L'\0';
        }
        return 0;
    }

    if (*pst != 0) { // if continuation of partial multibyte char
        //
        // Determine length of char.
        //
        // Note: MB_CUR_MAX is really a locale-dependent variable,
        // __mb_cur_max, set by setlocale().
        //
        bytelen = (_codepage == CP_UTF8 ? _utf8_len((char*)pst) : MB_CUR_MAX);

        if (bytelen == (size_t)-1 || ++n < bytelen) {
            //
            // Still partial after 2 tries (or garbage in *pst),
            // punt.  Note: This is not strictly ANSI C compliant but
            // it would require extra state which does not fit in an int.
            //
            *pst = 0;
            errno = EILSEQ;
            return (size_t)-1;
        }

        if (n > bytelen) n = bytelen;

        // splice in the remainder of the char
        memcpy(((char*)pst)+1, s, n-1);

        if ((MultiByteToWideChar(_codepage,
                MB_PRECOMPOSED|MB_ERR_INVALID_CHARS,
                (char *)pst, n, pwc, (pwc) ? 1 : 0) == 0)) {  // failed
            *pst = 0;
            errno = EILSEQ;
            return (size_t)-1;
        }
        *pst = 0;
        return bytelen;
    }
    if (_codepage == CP_UTF8) {
        if ((bytelen = _utf8_len(s)) == (size_t)-1) { // if bad UTF char
            *pst = 0;
            errno = EILSEQ;
            return (size_t)-1;
        }
        bLead = (bytelen > 1);
    } else {
        bytelen = MB_CUR_MAX;
        bLead = isleadbyte((unsigned char)*s);
    }
    if (bLead) {
        //
        // 1st byte of multibyte char
        //
        if (n < bytelen) { // if input is truncated
            //
            // Tried to convert a partial multibyte char w/o rest of bytes
            //
            ((char *)pst)[0] = *s;
            return (size_t)-2; // indicate partial

        } else {
            //
            // Convert multibyte char to Unicode-16
            //
            if (MultiByteToWideChar(_codepage,
                    MB_PRECOMPOSED | MB_ERR_INVALID_CHARS,
                    s, bytelen, pwc, (pwc) ? 1 : 0) == 0) {
                //
                // Failed
                //
                *pst = 0;
                errno = EILSEQ;
                return (size_t)-1;
            }
        }
        return bytelen;
    }
    //
    // Single byte char - expansion still possible so do it
    //
    if (MultiByteToWideChar(_codepage,
          MB_PRECOMPOSED|MB_ERR_INVALID_CHARS, s, 1, pwc,
          (pwc) ? 1 : 0) == 0 ) { // failed
        errno = EILSEQ;
        return (size_t)-1;
    }

    return 1; // single byte
}
#endif

////////////////////////////////////////////////////////////////////////////
//
// Return non-zero if the console is using a TrueType (TT) font.
//
// Requires Vista or later.
//

typedef struct _CONSOLE_FONT_INFOEX_VISTA {
    ULONG cbSize;
    DWORD nFont;
    COORD dwFontSize;
    UINT FontFamily;
    UINT FontWeight;
    WCHAR FaceName[LF_FACESIZE/*32*/];
} CONSOLE_FONT_INFOEX_VISTA, *PCONSOLE_FONT_INFOEX_VISTA;

typedef BOOL (WINAPI *PFNGETCURRENTCONSOLEFONTEX)(
    HANDLE hConsoleOutput,
    BOOL bMaximumWindow,
    PCONSOLE_FONT_INFOEX_VISTA lpConsoleCurrentFontEx
);
static PFNGETCURRENTCONSOLEFONTEX pfnGetCurrentConsoleFontEx;


typedef int (WINAPI *PFNENUMFONTFAMILIESEXW)(
    HDC hdc,
    LPLOGFONTW lpLogfont,
    FONTENUMPROCW lpProc,
    LPARAM lParam,
    DWORD dwFlags
);
static PFNENUMFONTFAMILIESEXW pfnEnumFontFamiliesExW;

////

static BOOL bIsConsoleFontTrueType;

// Is the given font a TrueType font?
static int CALLBACK EnumFontFamiliesExProcW(ENUMLOGFONTEXW *pelfe,
    NEWTEXTMETRICEXW *pntme, DWORD dwFontType, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(pelfe);
    UNREFERENCED_PARAMETER(dwFontType);
    UNREFERENCED_PARAMETER(lParam);

    if ((pntme->ntmTm.tmPitchAndFamily & TMPF_TRUETYPE) != 0) {
        bIsConsoleFontTrueType = TRUE;
        return 0; // stop searching
    }
    return 1; // keep searching
}

/////////////////////////////////////////////////////////////////////////////
//
// Return non-zero if the console is using a TrueType (TT) font.
//
// Requires Vista or later.
//
int IsConsoleFontTrueType()
{
    HANDLE hConsole;
    CONSOLE_FONT_INFOEX_VISTA cfix;
    LOGFONTW lf;
    HDC hDC;

    if (!DynaLoad("KERNEL32.DLL", "GetCurrentConsoleFontEx", // Vista or later
            (PPFN)&pfnGetCurrentConsoleFontEx)) {
        return FALSE;
    }
    if (!DynaLoad("GDI32.DLL", "EnumFontFamiliesExW", // Not Unicode on Win9x
            (PPFN)&pfnEnumFontFamiliesExW)) {
        return FALSE;
    }

    hConsole = GetStdHandle(STD_ERROR_HANDLE);
    memset(&cfix, 0, sizeof(cfix));
    cfix.cbSize = sizeof(cfix);

    if (!(*pfnGetCurrentConsoleFontEx)(hConsole, FALSE, &cfix)) {
        return FALSE; // might not have a console
    }

    if ((hDC = GetDC(NULL/*desktop*/)) == NULL) {
        return FALSE; // no display
    }


    memset(&lf, 0, sizeof(lf));
    lf.lfCharSet = DEFAULT_CHARSET/*1*/; // required
    memcpy(lf.lfFaceName, cfix.FaceName, LF_FACESIZE*sizeof(WCHAR));

    bIsConsoleFontTrueType = 0;

    (*pfnEnumFontFamiliesExW)(hDC, &lf, (FONTENUMPROCW)EnumFontFamiliesExProcW, 0, 0);

    return bIsConsoleFontTrueType;
}

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

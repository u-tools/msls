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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <wchar.h>

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

#include "xmbrtowc.h"

//extern int _HasConsole();
#define _HasConsole() 1

static void _init_codepage();

static int _codepage = -1;

#if WCHAR_MAX != 0xFFFF // If MSSDK05 or earlier
//
// BUG: VC6 forgot to define mbsinit outside of __cplusplus.
//
int mbsinit(const mbstate_t *mbs)
{
    // Return TRUE if mbstate_t is still in the initial state
    return (mbs==NULL || *mbs == 0);
}
#endif

int get_codepage()
{
    //
    // Initialize the codepage if not already
    //
    if (_codepage == -1) {
        _init_codepage();
    }
    return _codepage;
}

//
// Get the user current default OEM/ANSI code page
//
// Use OEM if console window, otherwise use ANSI
//
static void _init_codepage()
{
    char szCodePage[8];

    int lcidCountry = GetUserDefaultLCID();
    int info = _HasConsole() ? LOCALE_IDEFAULTCODEPAGE :
        LOCALE_IDEFAULTANSICODEPAGE;

    if (!GetLocaleInfo(lcidCountry,
            info,
            szCodePage, sizeof(szCodePage)) ||
            ((_codepage = (int)atol(szCodePage)) == 0)) {
        error(EXIT_FAILURE, 0, "Unable to get locale info.");
    }
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


#if defined(_MSC_VER) && (_MSC_VER < 1900)
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
    //
    // Initialize the codepage if not already
    //
    if (_codepage == -1) {
        _init_codepage();
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

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

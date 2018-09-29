//////////////////////////////////////////////////////////////////////////
//
// Shortcut.cpp - Query the shortcut .LNK for the target path
//
// Used by stat()
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
// For VC6, disable warnings from various standard Windows headers
// NOTE: #pragma warning(push) ... #pragma warning(pop) is broken/unusable for MSVC 6 (re-enables multiple other warnings)
#pragma warning(disable: 4068)  // DISABLE: unknown pragma warning
#pragma warning(disable: 4035)  // DISABLE: no return value warning
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ole2.h>
#include <shlobj.h> // IShellLink

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
#pragma warning(default: 4068)  // RESET: unknown pragma warning
#pragma warning(default: 4035)  // RESET: no return value warning
#endif

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>

#include <errno.h>
#ifndef errno
extern int errno;
#endif

#include <string.h>
#include <wchar.h>
#include <tchar.h>
//#include <mbstring.h>

extern "C" {
#include "dirent.h"
#include "xmbrtowc.h" // for get_codepage()
#include "more.h"
#include "ls.h"
}


//
// Query the shortcut .LNK for the target path
//
extern "C" char *
_GetShortcutTarget(struct cache_entry *ce, char *szPath)
{
    HRESULT hr;
    IShellLink *psl=NULL;
    IPersistFile* ppf=NULL;
    wchar_t wszPath[FILENAME_MAX];
    DWORD dwFlags;
    LPITEMIDLIST/*PIDLIST_ABSOLUTE*/ pidl = NULL;

    szPath[0] = '\0';

    //
    // Initialize COM
    //
    if (!gbComInitialized) {
        gbComInitialized = TRUE;
        if (FAILED(CoInitialize(NULL))) {
            more_fputs("Unable to initialize COM\n", stdmore_err);
            exit(1);
        }
    }

    //
    // Convert the path name to Unicode
    //
    if (MultiByteToWideChar(get_codepage(), 0, ce->ce_abspath, -1,
            wszPath, FILENAME_MAX) == 0) {
        goto fail;
    }

    //
    // Create an IShellLink object
    //
    hr = CoCreateInstance(CLSID_ShellLink/*ref*/, NULL,
        CLSCTX_INPROC_SERVER, IID_IShellLink/*ref*/, (LPVOID*)&psl);

    if (FAILED(hr)) goto fail;

    //
    // Query IShellLink for the IPersistFile interface
    //
    hr = psl->QueryInterface(IID_IPersistFile/*ref*/, (LPVOID*)&ppf);

    if (FAILED(hr)) goto fail;

#ifdef _DEBUG
//more_printf("Shortcut Load(\"%ws\")\n", wszPath);
#endif

    //
    // Load the .LNK file
    //
    hr = ppf->Load(wszPath, STGM_READ);

    if (FAILED(hr)) goto fail;

    //
    // Resolve the shortcut.  Disable GUI (SLR_NO_UI) if not found,
    // Do not try exhaustive file search (SLR_NOSEARCH).
    // Do not update the shortcut (SLR_NOUPDATE).
    //
    // Query the Distributed Link Tracking Service iff --slow
    //
    dwFlags = SLR_NO_UI|SLR_NOSEARCH|SLR_NOUPDATE;
    if (run_fast) {
        dwFlags |= SLR_NOTRACK; // no Distributed Link Tracking
    }

    //dwFlags |= SLR_ANY_MATCH; // UNDOCUMENTED (not needed for MSI?)

    dwFlags |= SLR_INVOKE_MSI; // Required for MSI 'Darwin' link resolution

    hr = psl->Resolve(NULL, dwFlags);

    //if (FAILED(hr)) goto fail; // ignore failure to get orphan link

    //
    // Get the target path.  This should always succeed even for
    // orphan links.
    //

    //
    // We must use PIDLs to resolve MSI 'Darwin' style advertised
    // shortcuts.
    //
    // Get the PIDL list
    hr = psl->GetIDList(&pidl);

    //
    // First try to resolve an MSI 'Darwin' encoded/advertised shortcut
    //
    if (FAILED(hr) || !::SHGetPathFromIDList(pidl, szPath)) {
        //
        // Fall back to using IShellLink::GetPath
        //
        // Note: A shortcut to a non-file resource will return
        // a zero-length string and S_FALSE (and succeed).
        //
        hr = psl->GetPath(szPath, FILENAME_MAX, NULL, /*SLGP_RAWPATH*/0);
    }

    if (szPath[0] == '\0' || hr == S_FALSE || FAILED(hr)) { // unable to query path
        //
        // We have to return something, so punt
        //
        lstrcpyn(szPath, "[Non-file link]", FILENAME_MAX);
    }

    ppf->Release();
    psl->Release();

    return szPath;

fail:
    if (ppf) ppf->Release();
    if (psl) psl->Release();

    return NULL;
}
/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

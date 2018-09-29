//////////////////////////////////////////////////////////////////////////
//
// Query the reparse point for the target.
// Also queries Vista-style symbolic links (mklink MyLink RealFile)
//

//
// Used by stat()
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

#pragma warning(disable: 4305)  // truncated cast ok basetsd.h POINTER_64 - AEK

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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <errno.h>

#include <string.h>
#include <wchar.h>
#include <tchar.h>
//#include <mbstring.h>

#pragma warning(disable: 4201) // ignore nameless union/structs in winioctl.h

#include <winioctl.h>

#define NEED_DIRENT_H
#include "windows-support.h"
#include "xmbrtowc.h" // for get_codepage()
#include "more.h"

#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)       // winnt
#endif

#ifndef IO_REPARSE_TAG_DFS
#define IO_REPARSE_TAG_DFS                      (0x8000000AL)       // winnt
#endif

#ifndef IO_REPARSE_TAG_DFSR
#define IO_REPARSE_TAG_DFSR                     (0x80000012L)       // winnt
#endif

#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK                  (0xA000000CL)       // winnt
#endif

//
// Note: IO_REPARSE_TAG_SYMLINK is identical except it appends a DWORD
// for flags immediately before szPathBuffer.  See ::CreateSymbolicLink()
// on Vista.
//

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)       // unnamed struct

#define SYMLINK_FLAG_RELATIVE   1 // dwFlags

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  dwReparseTag;
    USHORT wReparseDataLength;
    USHORT wReserved0;
    union {
        struct {
            USHORT wPhysicalNameOffset;
            USHORT wPhysicalNameLength;
            USHORT wDisplayNameOffset;
            USHORT wDisplayNameLength;
            ULONG dwFlags;
            WCHAR wszPathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT wPhysicalNameOffset;
            USHORT wPhysicalNameLength;
            USHORT wDisplayNameOffset;
            USHORT wDisplayNameLength;
            WCHAR wszPathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    };
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning( default : 4201 )
#endif


//
// Query the reparse point for the target path, using
// FSCTL_GET_REPARSE_POINT.
//
// Note: The format of the output of FSCTL_GET_REPARSE_POINT
// is undocumented.
//
char *
_GetReparseTarget(struct cache_entry *ce, char *szPath)
{
    HANDLE hFile;
    char szBuf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    PREPARSE_DATA_BUFFER rdb = (PREPARSE_DATA_BUFFER)szBuf;
    DWORD dwBytesReturned=0;
    LPWSTR wszPathBuffer = NULL;
    USHORT wPhysicalNameLength = 0;
    char *sz;

#ifdef _DEBUG
more_printf("CreateFile(\"%s\") with FILE_FLAG_OPEN_REPARSE_POINT\n", ce->ce_abspath);
#endif

    //
    // DESIGN BUG: GENERIC_READ fails to open "super-hidden" reparse points
    // on Vista, e.g., C:\ProgramData\Templates
    //
    // WORKAROUND: Use SYNCHRONIZE|FILE_READ_ATTRIBUTES|FILE_READ_EA
    //
    // UNDOCUMENTED: FILE_FLAG_BACKUP_SEMANTICS is silently ignored
    // if not an elevated admin user
    //
    if ((hFile = CreateFile(ce->ce_abspath,
            /*GENERIC_READ*/SYNCHRONIZE|FILE_READ_ATTRIBUTES,
            0, 0, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, 0)) ==
                INVALID_HANDLE_VALUE)  {
#ifdef _DEBUG
more_printf("CreateFile failed\n");
#endif
        return NULL;
    }

    memset(szBuf, 0, sizeof(szBuf));

    if (!DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0,
            (LPVOID)rdb, MAXIMUM_REPARSE_DATA_BUFFER_SIZE/*16KB*/,
            &dwBytesReturned, 0)) {
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile); hFile = NULL;

    switch (rdb->dwReparseTag) {
        case IO_REPARSE_TAG_MOUNT_POINT:
        case IO_REPARSE_TAG_DFS:
        case IO_REPARSE_TAG_DFSR:
            wPhysicalNameLength = rdb->MountPointReparseBuffer.wPhysicalNameLength;
            wszPathBuffer = rdb->MountPointReparseBuffer.wszPathBuffer;
            break;

        case IO_REPARSE_TAG_SYMLINK:
            wPhysicalNameLength = rdb->SymbolicLinkReparseBuffer.wPhysicalNameLength;
            wszPathBuffer = rdb->SymbolicLinkReparseBuffer.wszPathBuffer;
            break;
    }

    if (wPhysicalNameLength > (FILENAME_MAX-20)*sizeof(WCHAR)) {
        wPhysicalNameLength = (FILENAME_MAX-20)*sizeof(WCHAR);
    }

    if (wszPathBuffer != NULL) {
        // NUL-terminate
        wszPathBuffer[wPhysicalNameLength/sizeof(WCHAR)] = L'\0';

        switch (rdb->dwReparseTag) {
            case IO_REPARSE_TAG_DFS:
                wcscat(wszPathBuffer, L" (DFS)");
                break;
            case IO_REPARSE_TAG_DFSR:
                wcscat(wszPathBuffer, L" (DFSR)");
                break;
        }
    } else {
        //
        // We only handle mount points, not HSM, SIS, etc
        //
        // Undocumented: The tag is also returned in the field
        // dwReserved0 in WIN32_FIND_DATA from FindFirstFile/FindNextFile.
        //
        // This can be used to quickly filter out unwanted reparse points.
        //
        wszPathBuffer = L"(Unknown)";
    }

    memset(szPath, 0, FILENAME_MAX); // required!

    if (!WideCharToMultiByte(get_codepage(), 0,
            wszPathBuffer, -1, szPath, FILENAME_MAX, NULL, NULL)) {
        return NULL;
    }

    if (strncmp(szPath, "\\??\\", 4) == 0) {
        //
        // \??\ is the kernel-mode prefix for DosDevice symlinks.  These
        // are represented as \\?\ in user-mode.
        //
        // Note: Do not confuse with \\.\pipe syntax.
        //
        // The syntax is the same as for the \??\object syntax
        // inside the kernel for creating kernel symbolic links.
        // Kernel symbolc links expose \device\foo as \\.\baz in user mode.
        //
        sz = &szPath[4]; // skip leading \??\...
    } else {
        sz = szPath;
    }

    return sz;
}

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

//////////////////////////////////////////////////////////////////////////
//
// Display the 48-byte Object ID for the file, if any.
//
// Object IDs are used to track the movement of files around
// the computer (and around the network) via the Distributed Link Tracking
// service.
//
// Object IDs are used when the Shell resolves an orphan link, to try to
// locate the actual file.
//
// Object IDs are used by the NT File Replication Service (NTFRS) when
// synchronizing files in SYSVOL.
//

//
// Copyright (c) 2007-2018, U-Tools Software LLC
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
#include <rpc.h> // for UuidString

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

//
// Display the file's object ID, using FSCTL_GET_OBJECT_ID
//
void print_objectid(struct cache_entry *ce)
{
    HANDLE hFile;
    FILE_OBJECTID_BUFFER objId;
    DWORD dwBytesReturned=0;
    DWORD l,i;
    unsigned char *szUuid=NULL;
    unsigned char *szGuidZero = (unsigned char*)"00000000-0000-0000-0000-000000000000";

    //
    // DESIGN BUG: GENERIC_READ fails to open files that have
    // FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_SYSTEM.
    //
    // WORKAROUND #1: Use FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM for arg 6.
    //
    // WORKAROUND #2: Use SYNCHRONIZE|FILE_READ_ATTRIBUTES
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
more_printf("CreateFile failed, err=%u\n", GetLastError());
#endif
        return;
    }

    memset(&objId, 0, sizeof(objId));

    if (!DeviceIoControl(hFile, FSCTL_GET_OBJECT_ID, NULL, 0,
            (LPVOID)&objId, sizeof(objId),
            &dwBytesReturned, 0)) {
#ifdef _DEBUG
if (GetLastError() != ERROR_FILE_NOT_FOUND)
more_printf("DeviceIoControl(FSCTL_GET_OBJECT_ID) failed, err=%u\n", GetLastError());
#endif
        CloseHandle(hFile);
        return;
    }

    CloseHandle(hFile); hFile = NULL;

    for (l=0; l < sizeof(objId); l += 16) {
        more_fputs(l == 0 ? "     Object ID: " : "                ", stdmore);
        for (i=0; i < 16; ++i) {
            more_printf("%02.2x ", ((PBYTE)(&objId))[l+i]);
        }
        more_putc('\n', stdmore);
    }

    UuidToString((UUID*)&objId.ObjectId, &szUuid);
    more_printf("      ObjectID: {%s}\n", szUuid);
    RpcStringFree(&szUuid); szUuid = NULL;

    UuidToString((UUID*)&objId.BirthVolumeId[0], &szUuid);
    if (strcmp((LPSTR)szUuid, (LPSTR)szGuidZero) != 0) {
        more_printf(" BirthVolumeID: {%s}\n", szUuid);
    }
    RpcStringFree(&szUuid); szUuid = NULL;

    UuidToString((UUID*)&objId.BirthObjectId[0], &szUuid);
    if (strcmp((LPSTR)szUuid, (LPSTR)szGuidZero) != 0) {
        more_printf(" BirthObjectID: {%s}\n", szUuid);
    }
    RpcStringFree(&szUuid); szUuid = NULL;

    UuidToString((UUID*)&objId.DomainId[0], &szUuid);
    if (strcmp((LPSTR)szUuid, (LPSTR)szGuidZero) != 0) {
        more_printf("      DomainID: {%s}\n", szUuid);
    }
    RpcStringFree(&szUuid); szUuid = NULL;

    more_putc('\n', stdmore);

    return;
}

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

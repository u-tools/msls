//////////////////////////////////////////////////////////////////////////
//
// FindFiles.cpp
//
// Copyright (c) 2007-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

// _aefindfirsti64() and _aefindnexti64()

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

#include <ole2.h>

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <mbstring.h>
#include <time.h>

#include <errno.h>
#include <io.h> // for _finddatai64_t
#include <system.h> // for alloca()

//
// Stupid MSVC doesn't define __STDC__
//
#ifndef __STDC__
# define __STDC__ 1
#endif

#include "more.h"

#define NEED_DIRENT_H
#include "windows-support.h"
#include "xalloc.h"
#include "xmbrtowc.h" // for get_codepage()
#include "ls.h"
#include "FindFiles.h"

#undef strrchr
#define strrchr _mbsrchr // use the multibyte version of strrchr

#pragma warning(disable: 4057) // ignore unsigned char* vs char*

//
// BUG: _tfindfirsti64() wrongly uses FileSystemToLocalFileTime, which
// does not handle DST correctly when the filedate is standard time
// and the current time is daylight-savings time, or vice versa.
//
// It ought to use SystemTimeToTzSpecificLocalTime if running
// on NT or later.
//
// The bug is fixed on Windows Vista.  (Yes, Microsoft modified the legacy
// MSVCRT.DLL even though they promised they wouldn't change it on Vista.)
// So we have to check if we are running on Vista.
//
// The reverse function (TzSpecificLocalTimeToSystemTime) requires
// Windows XP or later.
//
// WORKAROUND: Convert from FILETIME to time_t directly, without
// involving DST.
//
// DESIGN BUG: FAT filesystems store dates as UTC-5 during CDT and UTC-6
// during CST.  This is because FAT filesystems store the local time on disk,
// not the UTC time.
//
// DESIGN BUG: FileTimeToLocalFileTime uses today's CDT/CST, not the date's
// CDT/CST.
//
// SystemTimeToTzSpecificLocalTime subtracts UTC by -5 if the date is in CDT
// and by -6 if date is in CST.  Thus it always shows the correct local time
// for NTFS (and for all stored UTC dates in general).
//
// Note: SystemTimeToTzSpecificLocalTime is not available on Win9x.
//
extern "C" time_t ConvertFileTimeToTimeT(PFILETIME pft)
{
    LARGE_INTEGER llFileDate, ll1970;

    static BOOL gbInitDst, gbIsDst;
    static TIME_ZONE_INFORMATION tzi;

    typedef BOOL (WINAPI *PFNSYSTEMTIMETOTZSPECIFICLOCALTIME)(
        IN     LPTIME_ZONE_INFORMATION lpTimeZoneInformation,
        IN     LPSYSTEMTIME lpUniversalTime,
        OUT    LPSYSTEMTIME lpLocalTime
    );

    static PFNSYSTEMTIMETOTZSPECIFICLOCALTIME pfnSystemTimeToTzSpecificLocalTime;

    time_t timFail = (time_t)-1;

    if (!gbInitDst) {
        gbInitDst = TRUE;
        gbIsDst = (GetTimeZoneInformation(&tzi) == TIME_ZONE_ID_DAYLIGHT);
    }


    if (pft->dwLowDateTime == 0 && pft->dwHighDateTime == 0) {
        return timFail;
    }

    llFileDate.LowPart = pft->dwLowDateTime;
    llFileDate.HighPart = pft->dwHighDateTime;

    //
    // 100ns intervals between Jan 1 1600 and Jan 1 1970
    //
    ll1970.LowPart = 0xD53E8000;
    ll1970.HighPart = 0x019DB1DE;

    if (llFileDate.QuadPart < ll1970.QuadPart) { // if before Jan 1 1970
        return timFail;
    }

    //
    // Convert from 100ns intervals since Jan 1 1600
    // to 100ns intervals since Jan 1 1970
    //
    llFileDate.QuadPart -= ll1970.QuadPart;
    //
    // Convert from 100ns intervals to seconds
    //
    llFileDate.QuadPart /= 10000000;

    //
    // BUG: localtime() wrongly uses the current DST, not the DST of
    // the timestamp.
    //
    // WORKAROUND:
    // Use SystemTimeToTzSpecificLocalTime to adjust for DST.  Not available
    // on Win9x.
    //
    // Bug is fixed on Vista.
    //
    // Note: While SystemTimeToTzSpecificLocalTime is available on NT/W2K,
    // TzSpecificLocalTimeToSystemTime is only available on XP or later.
    //
    if (!IsVista) { // UNDOCUMENTED: localtime is fixed in MSVCRT.DLL in Vista

      if (DynaLoad("KERNEL32.DLL", "SystemTimeToTzSpecificLocalTime",
            (PPFN)&pfnSystemTimeToTzSpecificLocalTime)) {
        //
        // Convert the UTC FILETIME to UTC SYSTEMTIME
        //
        SYSTEMTIME stmUTC, stmDate1, stmDate2;
        FileTimeToSystemTime(pft, &stmUTC);
        //
        // See if the file time is in DST by converting it twice,
        // once using the normal DST rules, and once using a bogus
        // "no DST" rule.
        //
        TIME_ZONE_INFORMATION tzNoDst;
        memset(&tzNoDst, 0, sizeof(tzNoDst));
        tzNoDst.Bias = tzi.Bias; // non-DST bias only

        (*pfnSystemTimeToTzSpecificLocalTime)(NULL, &stmUTC, &stmDate1);
        (*pfnSystemTimeToTzSpecificLocalTime)(&tzNoDst, &stmUTC, &stmDate2);

        //
        // Note: Some countries shift by 1/2 hour, so check both hours and
        // minutes.
        //
        BOOL bFileDst = (stmDate1.wHour != stmDate2.wHour
            || stmDate1.wMinute != stmDate2.wMinute);

        //
        // BUG: This is wrong if the country uses a 1/2 hour bias,
        // e.g., Afghanistan.
        //
        if (!bFileDst && gbIsDst) {
            //
            // The file date is not in DST, and the current time is in DST.
            //
            // stftime wrongly uses DST: Add 1 hour to compensate
            //
            llFileDate.QuadPart += 3600;
        } else if (bFileDst && !gbIsDst) {
            //
            // The file date is in DST, and the current time is not in DST.
            //
            // localtime wrongly uses non-DST: Subtract 1 hour to compensate
            //
            llFileDate.QuadPart -= 3600;
        }
      }
    }

    //
    // BUG: In the year 2038 we need to use __time64_t instead of time_t.
    //
    // There is no MSVCRT support for __time64_t in legacy operating
    // systems.  Coding it ourselves is too hard, so we punt.
    //
    // Hopefully by 2038 nobody will be running Win9x/NT/W2K, and we
    // can use the native __time64_t.
    //
    // TODO: Return (__time64_t)llFileDate.QuadPart;
    //
    return (time_t)llFileDate.QuadPart;
}


long _aefindfirsti64(const char* szWild,
    struct _finddatai64_t * pfd)
{
    HANDLE hFile;
    DWORD dwError;
    WIN32_FIND_DATA wfd;

    if ((hFile = FindFirstFile(szWild, &wfd)) == INVALID_HANDLE_VALUE) {
        switch (dwError = GetLastError()) {
            case ERROR_FILE_NOT_FOUND:
            case ERROR_PATH_NOT_FOUND:
            case ERROR_NO_MORE_FILES:
                errno = ENOENT;
                break;

            case ERROR_NOT_ENOUGH_MEMORY:
                errno = ENOMEM;
                break;

            default:
                errno = EINVAL;
                break;
        }
        return -1;
    }

    pfd->attrib = (wfd.dwFileAttributes == FILE_ATTRIBUTE_NORMAL)
                      ? 0 : wfd.dwFileAttributes;

#ifdef UNDEFINED
printf("low=%08X, high=%08X, file=%s\n",
wfd.ftLastWriteTime.dwLowDateTime,
wfd.ftLastWriteTime.dwHighDateTime, szWild);
#endif

    pfd->time_create  = ConvertFileTimeToTimeT(&wfd.ftCreationTime);
    pfd->time_access  = ConvertFileTimeToTimeT(&wfd.ftLastAccessTime);
    pfd->time_write   = ConvertFileTimeToTimeT(&wfd.ftLastWriteTime);

    pfd->size = ((__int64)(wfd.nFileSizeHigh)) * (0x100000000i64) +
                 (__int64)(wfd.nFileSizeLow);

    strcpy(pfd->name, wfd.cFileName);

    return (long)hFile;
}


int _aefindnexti64(long hFile, struct _finddatai64_t * pfd)
{
    WIN32_FIND_DATA wfd;
    DWORD dwError;

    if (!FindNextFile((HANDLE)hFile, &wfd)) {
        switch (dwError = GetLastError()) {
            case ERROR_FILE_NOT_FOUND:
            case ERROR_PATH_NOT_FOUND:
            case ERROR_NO_MORE_FILES:
                errno = ENOENT;
                break;

            case ERROR_NOT_ENOUGH_MEMORY:
                errno = ENOMEM;
                break;

            default:
                errno = EINVAL;
                break;
        }
        return -1;
    }

    pfd->attrib = (wfd.dwFileAttributes == FILE_ATTRIBUTE_NORMAL)
                      ? 0 : wfd.dwFileAttributes;

    pfd->time_create  = ConvertFileTimeToTimeT(&wfd.ftCreationTime);
    pfd->time_access  = ConvertFileTimeToTimeT(&wfd.ftLastAccessTime);
    pfd->time_write   = ConvertFileTimeToTimeT(&wfd.ftLastWriteTime);

    pfd->size = ((__int64)(wfd.nFileSizeHigh)) * (0x100000000i64) +
                 (__int64)(wfd.nFileSizeLow);

    strcpy(pfd->name, wfd.cFileName);

    return 0;
}

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

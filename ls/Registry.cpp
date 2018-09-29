//////////////////////////////////////////////////////////////////////////
//
// Registryc.pp - Registry layer for Win32
//
// Copyright (c) 2007-2018, U-Tools Software LLC
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

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
#pragma warning(default: 4068)  // RESET: unknown pragma warning
#pragma warning(default: 4035)  // RESET: no return value warning
#endif

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
#include "Registry.h"

#ifndef HKEY_CURRENT_USER_LOCAL_SETTINGS // Win7
#define HKEY_CURRENT_USER_LOCAL_SETTINGS ((HKEY)(ULONG_PTR)((LONG)0x80000007))
#endif


typedef LONG (WINAPI *PFNREGLOADMUISTRINGW) (
    HKEY       hKey,
    LPCWSTR    pszValue,
    LPWSTR     pszOutBuf,
    DWORD      cbOutBuf,
    LPDWORD    pcbData,
    DWORD      Flags,
    LPCWSTR    pszDirectory
);
static PFNREGLOADMUISTRINGW pfnRegLoadMUIStringW;


// Defined in Token.cpp
extern BOOL SetVirtualView(BOOL bEnable, BOOL bVerify);

#ifndef FILE_ATTRIBUTE_VIRTUAL
# define FILE_ATTRIBUTE_VIRTUAL 0x00010000
#endif

/////////////////////////////////////////////////////////////////////////////
//
// From Vista ntddk.h
//
// BUG: MSDN documentation has the wrong order!
// (Corrected in MSDN circa Aug 2008)
//
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation, // XP
    KeyFlagsInformation, // XP 1st ULONG only, Vista 3 ULONGs
    KeyVirtualizationInformation, // Vista
    MaxKeyInfoClass  // MaxKeyInfoClass should always be the last enum
} KEY_INFORMATION_CLASS;

//
// ControlFlags
//
#define     REG_KEY_DONT_JOURNAL        1 // ?
#define     REG_KEY_DONT_VIRTUALIZE     2 // When --virtual same as (VirtualizationCandidate==1 && VirtualizationEnabled==0)
#define     REG_KEY_DONT_SILENT_FAIL    4
#define     REG_KEY_RECURSE_FLAG        8

typedef struct _KEY_FLAGS_INFORMATION {
    ULONG   Wow64Flags;         // XP, formerly UserFlags
    /// Added by Vista
    ULONG   KeyFlags;           // LSB bit set --> Key is Volatile
                                // second to LSB bit set --> Key is symlink
    /// Added by Vista
    ULONG   ControlFlags;       // REG_KEY_xxx flags
} KEY_FLAGS_INFORMATION, *PKEY_FLAGS_INFORMATION;

typedef struct _KEY_VIRTUALIZATION_INFORMATION {
    //
    // VirtualizationCandidate == 1 iff
    //  - Running in virtual mode.
    //  - Key is under HKLM\Software.
    //  - Key does _not_ have a mirror yet.
    //    Note: Includes exempt keys such as HKLM\Software\Microsoft\Windows
    //
    ULONG   VirtualizationCandidate : 1; // MSDN: "Tells whether the key is part of the virtualization namespace scope (only HKLM\Software for now)"
    //
    // Indicates if a key is exempt under HKLM\Software
    //   (VirtualizationCandidate==1 && VirtualizationEnabled==0)
    //
    //  Default exempt keys:
    //      HKLM\Software\Microsoft\Windows
    //      HKLM\Software\Microsoft\Windows NT
    //      HKLM\Software\ODBC\ODBC.INI
    //
    ULONG   VirtualizationEnabled   : 1; // MSDN: "Tells whether virtualization is enabled on this key. Can be 1 only if above flag is 1."
    //
    // VirtualTarget == 1 iff
    //  - VirtualStore==1
    //  - Key exists only on mirror not on main branch
    //
    ULONG   VirtualTarget           : 1; // MDSN: "Tells if the key is a virtual key. Can be 1 only if above 2 are 0. Valid only on the virtual store key handles."
    //
    // VirtualStore == 1 iff
    //  - Running in virtual mode
    //  - Key is mirrored in HKCU\Software\Classes\VirtualStore\MACHINE\Software
    //
    ULONG   VirtualStore            : 1; // MSDN: "Tells if the key is a part of the virtual store path. Valid only on the virtual store key handles."
    //
    // VirtualSource == 1 iff
    //  - Not running in virtual mode
    //  - and the key has had a virtual mirror in HKCU\Software\VirtualStore
    //    at any point in its history.
    //
    // BUG: MSDN DDK comment below is wrong.
    //
    ULONG   VirtualSource           : 1; // MSDN: "Tells if the key has ever been virtualized, Can be 1 only if VirtualizationCandidate is 1"
    ULONG   Reserved                : 27;
} KEY_VIRTUALIZATION_INFORMATION, *PKEY_VIRTUALIZATION_INFORMATION;

// NtQueryKey
typedef NTSTATUS (WINAPI *PFNNTQUERYKEY)(
    IN HANDLE KeyHandle,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID KeyInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
);
static PFNNTQUERYKEY pfnNtQueryKey;

//////////////////////////////////////////////////////////////// end ntddk.h

#undef strrchr
#define strrchr _mbsrchr // use the multibyte version of strrchr

#pragma warning(disable: 4057) // ignore unsigned char* vs char*

typedef const unsigned char *PCUSTR;
typedef unsigned char *PUSTR;

//
// \HKEY_LOCAL_MACHINE\xxx -> \HKLM\xxx
// \HKEY_CURRENT_USER\xxx -> \HKCU\xxx
// \HKEY_USERS\xxx -> \HKU\xxx
// \HKEY_CLASSES_ROOT\xxx -> \HKCR\xxx
// \HKEY_CURRENT_CONFIG\xxx -> \HKCC\xxx
// \HKEY_CURRENT_USER_LOCAL_SETTINGS -> \HKCULS\xxx (Win7)
//

#define FR_MAGIC 0x99887766

struct find_reg {
    DWORD fr_magic;
    BOOL fr_bRootKeys;
    HKEY fr_hRoot;
    LPSTR fr_szKey;
    LPSTR fr_szValue;
    LPSTR fr_szClass;
    HKEY fr_hKey; // for enumeration
    DWORD fr_dwIndex; // next index for enumeration
    BOOL fr_bReturnedDot; // TRUE after we returned dot
    BOOL fr_bEnumValues; // enumerating keys or values
    BOOL fr_bFailed;
    BOOL fr_bEof;
    struct _finddatai64_t fr_fd;
};


static time_t
_cached_now()
{
    static BOOL bInit;
    static time_t now;

    if (!bInit) {
        bInit = TRUE;
        time(&now);
    }
    return now;
}


static BOOL
_PrepReg(const char *szPath, struct find_reg *fr, DWORD dwType)
{
    char szBuf[FILENAME_MAX];
    LPSTR sz, szRoot, szKey=NULL;
    DWORD dwLen;

    if (szPath == NULL || szPath[0] != '\\') {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    //
    // "\*"
    // "\hklm\foo\*"
    // "\hklm\foo\baz", Use dwType to determine
    //
    if (_mbsicmp((PCUSTR)szPath, (PCUSTR)"\\*") == 0) { // "\*"
        fr->fr_bRootKeys = TRUE;
        return TRUE;
    }
    if (szPath[1] == '\0') { // "\"
        fr->fr_bRootKeys = TRUE;
        fr->fr_bEof = TRUE; // singleton
        return TRUE;
    }

    dwLen = strlen(szPath);
    if (dwLen >= FILENAME_MAX) {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return FALSE;
    }

    lstrcpyn(szBuf, szPath, FILENAME_MAX);

    if (szPath[dwLen-2] == '\\' && szPath[dwLen-1] == '*') { // "\foo\*"
        //
        // Truncate to "\foo"
        //
        szBuf[dwLen-2] = '\0';
        dwLen -= 2;
    } else if (szPath[dwLen-2] == '\\' && szPath[dwLen-1] == '.') { // "\foo\."
        //
        // Truncate to "\foo", singleton
        //
        szBuf[dwLen-2] = '\0';
        dwLen -= 2;
        fr->fr_bEof = TRUE; // singleton
    } else {
        fr->fr_bEof = TRUE; // singleton
    }

    szRoot = szBuf+1;
    if ((sz = (char*)_mbschr((PCUSTR)szRoot, '\\')) != NULL) {
        *sz = '\0';
        szKey = sz+1;
    }

    if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKLM") == 0) {
        fr->fr_hRoot = HKEY_LOCAL_MACHINE;
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKEY_LOCAL_MACHINE") == 0) {
        fr->fr_hRoot = HKEY_LOCAL_MACHINE;
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKCU") == 0) {
        fr->fr_hRoot = HKEY_CURRENT_USER;
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKEY_CURRENT_USER") == 0) {
        fr->fr_hRoot = HKEY_CURRENT_USER;
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKU") == 0) {
        fr->fr_hRoot = HKEY_USERS;
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKEY_USERS") == 0) {
        fr->fr_hRoot = HKEY_USERS;
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKCR") == 0) {
        fr->fr_hRoot = HKEY_CLASSES_ROOT;
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKEY_CLASSES_ROOT") == 0) {
        fr->fr_hRoot = HKEY_CLASSES_ROOT;
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKCC") == 0) {
        fr->fr_hRoot = HKEY_CURRENT_CONFIG;
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKEY_CURRENT_CONFIG") == 0) {
        fr->fr_hRoot = HKEY_CURRENT_CONFIG;
    // HKEY_CURRENT_USER_LOCAL_SETTINGS
    // For non-roaming registry settings.
    // The settings do in HKCULS do _not_ overlay HKCU.
    // Apps must explicitly open HKEY_CURRENT_USER_LOCAL_SETTINGS to gain
    // access to the non-roaming regvals (instead of HKEY_CURRENT_USER).
    //
    // Alias for HKCU\Software\Classes\Local Settings (Win7 or later),
    // (\Users\MyUserName\AppData\Local\Microsoft\Windows\UsrClass.dat)
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKCULS") == 0) {
        fr->fr_hRoot = HKEY_CURRENT_USER_LOCAL_SETTINGS; // Win7
    } else if (_mbsicmp((PCUSTR)szRoot, (PCUSTR)"HKEY_CURRENT_USER_LOCAL_SETTINGS") == 0) {
        fr->fr_hRoot = HKEY_CURRENT_USER_LOCAL_SETTINGS; // Win7
    } else {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    strcpy(fr->fr_fd.name, szRoot);

    if (dwType == DT_REG) { // path is to a value, not a key
        fr->fr_bEof = TRUE; // singleton
        if ((sz = (LPSTR)strrchr((PCUSTR)szKey, '\\')) == NULL) {
            // Single value, no key
            fr->fr_szValue = xstrdup(szKey);
        } else {
            *sz = '\0';
            fr->fr_szKey = xstrdup(szKey);
            fr->fr_szValue = xstrdup(sz+1);
        }
        return TRUE;
    }
    if (szKey) {
        fr->fr_szKey = xstrdup(szKey);
    }
    return TRUE;
}

static BOOL
_LookupReg(struct find_reg *fr, struct _finddatai64_t *pfd)
{
    char szClass[128];
    DWORD dwClassLen = 128;
    DWORD lErrCode;
    DWORD dwSize=0;
    DWORD dwLen=0, dwGotType=0;
    FILETIME ftWrite;

    pfd->attrib = 0;
    pfd->time_create = -1L;
    pfd->time_access = _cached_now();
    pfd->time_write = -1L;
    pfd->size = 0;

    if (fr->fr_bRootKeys) {
        //
        // Enumerate root keys.  Must do by hand
        //
        pfd->attrib = FILE_ATTRIBUTE_DIRECTORY;

        if (fr->fr_bEof) {  // if singleton
            strcpy(pfd->name, "\\"); // synthetic root
            return TRUE;
        }

        switch (fr->fr_dwIndex) {
            case 0:
                strcpy(pfd->name, "HKLM");
                break;
            case 1:
                strcpy(pfd->name, "HKCU");
                break;
            case 2:
                strcpy(pfd->name, "HKU");
                break;
#ifdef UNDEFINED // dont walk by default because it is so huge
            case 3:
                strcpy(pfd->name, "HKCR");
                break;
#endif
            default:
                fr->fr_bEof = TRUE;
                ::SetLastError(ERROR_NO_MORE_FILES);
                return FALSE;
        }
        fr->fr_dwIndex++;
        return TRUE;
    }

    if (fr->fr_hKey == NULL) { // if first time
        if (fr->fr_szKey == NULL) { // if no intermediate key
            fr->fr_hKey = fr->fr_hRoot; // use root
        } else { // open intermediate key
            DWORD dwAccess = KEY_READ;
            if (gbIsWindowsWOW64 && !gb32bit) {
                // Allow access to 64 bit keys
                dwAccess |= 0x0100; // KEY_WOW64_64KEY
            }
            if (_EnableSecurityPrivilege()) {
                dwAccess |= ACCESS_SYSTEM_SECURITY;
            }
            if ((lErrCode = ::RegOpenKeyExA(fr->fr_hRoot, fr->fr_szKey, 0,
                    dwAccess, &fr->fr_hKey)) != ERROR_SUCCESS) {
                ::SetLastError((DWORD)lErrCode);
                return FALSE;
            }
        }
        //
        // Get last-write time and class name
        //
        if ((lErrCode = ::RegQueryInfoKeyA(fr->fr_hKey, szClass, &dwClassLen,
                NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                &ftWrite)) != 0) {
            ::SetLastError((DWORD)lErrCode);
            return FALSE;
        }
        if (dwClassLen > 0) {
            fr->fr_szClass = xstrdup(szClass);
        }
        fr->fr_fd.attrib = FILE_ATTRIBUTE_DIRECTORY;
        fr->fr_fd.time_write = ConvertFileTimeToTimeT(&ftWrite);
        fr->fr_fd.time_create = fr->fr_fd.time_write;
        fr->fr_fd.time_access = _cached_now();
        fr->fr_fd.size = 0;
        if (fr->fr_szKey != NULL) {
            //
            // strip to last component for returned name
            //
            LPCSTR sz;
            if ((sz = (char *)strrchr((unsigned char *)fr->fr_szKey, '\\')) != NULL) {
                ++sz;
            } else {
                sz = fr->fr_szKey;
            }
            strcpy(fr->fr_fd.name, sz);
        } // otherwise use the original fd.name from PrepReg()

        // Note: Use "REG.EXE FLAGS hklm\software\XXX" to view ControlFlags

//#ifdef UNDEFINED
        NTSTATUS Status;

        if (IsWindowsXP) {
            if (DynaLoad("NTDLL.DLL", "NtQueryKey", (PPFN)&pfnNtQueryKey)) {
                //
                // Query the key flags
                // Available on Vista, possibly XP
                //
                // ControlFlags = REG_KEY_xxx
                //
                KEY_FLAGS_INFORMATION kfi;
                ULONG ulResultLen = sizeof(kfi);
                memset(&kfi, 0, sizeof(kfi));
                Status = (*pfnNtQueryKey)(fr->fr_hKey,
                    KeyFlagsInformation,
                    &kfi, sizeof(kfi), &ulResultLen);

#ifdef _DEBUG
if (fr->fr_szKey != NULL) {
more_printf("%s\n", fr->fr_szKey);
}
#endif
                if (NT_SUCCESS(Status)) {
#ifdef _DEBUG
more_printf("Wow64Flags=%08X, KeyFlags=%08X, ControlFlags=%08X\n",
kfi.Wow64Flags, kfi.KeyFlags, kfi.ControlFlags);
#endif
                }
                if (IsVista) {
                    //
                    // BUG: KeyVirtualizationInformation returns
                    // all zeros for every key on Vista if not running
                    // in virtual mode.
                    //
                    KEY_VIRTUALIZATION_INFORMATION kvi;
                    ulResultLen = sizeof(kvi);
                    memset(&kvi, 0, sizeof(kvi));
                    Status = (*pfnNtQueryKey)(fr->fr_hKey,
                        KeyVirtualizationInformation,
                        &kvi, sizeof(kvi), &ulResultLen);
                    if (NT_SUCCESS(Status)) {
                        if (kvi.VirtualStore) {
                            //
                            // The key is mirrored.  Only when --virtual
                            //
                            fr->fr_fd.attrib |= FILE_ATTRIBUTE_VIRTUAL;
                        }
#ifdef _DEBUG
more_printf("VirtualizationCandidate=%u, VirtualizationEnabled=%u\n",
    kvi.VirtualizationCandidate, kvi.VirtualizationEnabled);
more_printf("VirtualTarget=%u, VirtualStore=%u, VirtualSource=%u\n",
    kvi.VirtualTarget, kvi.VirtualStore, kvi.VirtualSource);
more_printf("Reserved=%08X\n", kvi.Reserved);
#endif
                    }
                } // IsVista
#ifdef _DEBUG
more_printf("\n");
#endif
            }
        } // IsWindowsXP
//#endif // UNDEFINED
    } // if first time

    *pfd = fr->fr_fd; // struct copy

    LPCSTR szValue = fr->fr_szValue;

    if (szValue != NULL) {
        if (strcmp(szValue, "[default]") == 0) {
            szValue = "";
        }
        //
        // Query a single value - just check existance and get size
        //
        if ((lErrCode = ::RegQueryValueExA(fr->fr_hKey, szValue, 0,
                &dwGotType, NULL, &dwSize)) != ERROR_SUCCESS) {
            ::SetLastError((DWORD)lErrCode);
            return FALSE;
        }
        pfd->size = dwSize; // 64 bit
        pfd->attrib &= ~FILE_ATTRIBUTE_DIRECTORY;
        strcpy(pfd->name, szValue);
        return TRUE;
    }
    if (fr->fr_bEof) {
        //
        // Query a single key - already did above, so quit
        //
        return TRUE;
    }
    if (!fr->fr_bReturnedDot) {
        //
        // Return a synthetic dot "."
        // Required by dirent()
        //
        fr->fr_bReturnedDot = TRUE;
        strcpy(pfd->name, ".");
        pfd->attrib |= FILE_ATTRIBUTE_DIRECTORY;
        pfd->time_write = _cached_now();
        pfd->time_create = _cached_now();
        pfd->time_access = _cached_now();
        pfd->size = 0;
        return TRUE;
    }
    if (!fr->fr_bEnumValues) {
        //
        // Enumerate subkeys first
        //
Again:
        dwLen = FILENAME_MAX;
        if ((lErrCode = ::RegEnumKeyExA(fr->fr_hKey, fr->fr_dwIndex,
            pfd->name, &dwLen, NULL, NULL, NULL, &ftWrite)) != ERROR_SUCCESS) {
            if (lErrCode == ERROR_NO_MORE_ITEMS) {
                fr->fr_bEnumValues = TRUE;
                fr->fr_dwIndex = 0;
                goto enum_values;
            }
            ::SetLastError((DWORD)lErrCode);
            return FALSE;
        }
        if (_stricmp(pfd->name, "Wow6432Node") == 0) {
            //
            // BUG: We must never follow or return Wow6432Node. Otherwise
            // we might create a bogus subkey under it.
            //
            // WORKAROUND: Ignore it
            //
            fr->fr_dwIndex++;
            goto Again;
        }
        pfd->attrib |= FILE_ATTRIBUTE_DIRECTORY;
        //
        // The recursive call to _LookupReg() will determine the virtual status.
        //
        pfd->attrib &= ~FILE_ATTRIBUTE_VIRTUAL;
        pfd->time_write = ConvertFileTimeToTimeT(&ftWrite);
        pfd->time_create = fr->fr_fd.time_write;
        pfd->time_access = _cached_now();
        pfd->size = 0;
        fr->fr_dwIndex++;
        return TRUE;
    }

enum_values:
    //
    // Enumerate values second
    //
    dwLen = FILENAME_MAX;
    dwSize = 0;
    if ((lErrCode = ::RegEnumValueA(fr->fr_hKey, fr->fr_dwIndex, pfd->name,
                &dwLen, NULL, NULL, NULL, &dwSize)) != ERROR_SUCCESS) {
        if (lErrCode == ERROR_NO_MORE_ITEMS) {
            fr->fr_bEof = TRUE;
            lErrCode = ERROR_NO_MORE_FILES; // expected by caller
        }
        if (lErrCode != ERROR_MORE_DATA) { // ok, because no data buf
            ::SetLastError(lErrCode);
            return FALSE;
        }
    }

    pfd->attrib &= ~FILE_ATTRIBUTE_VIRTUAL;

    if (virtual_view && fr->fr_szKey != NULL && (fr->fr_fd.attrib & FILE_ATTRIBUTE_VIRTUAL)) {
        //
        // Query the virtual store to determine if the registry value is
        // really mirrored
        //
        // Open HKCU\Software\Classes\VirtualStore\Machine\SOFTWARE\xxx
        //
        LPSTR szVirtStore = (LPSTR)alloca(strlen(fr->fr_szKey) + 80);
        strcpy(szVirtStore, "Software\\Classes\\VirtualStore\\MACHINE\\");
        strcat(szVirtStore, fr->fr_szKey);

        HKEY hVirtKey= (HKEY)INVALID_HANDLE_VALUE;
        DWORD dwAccess = KEY_READ;

        if (gbIsWindowsWOW64 && !gb32bit) {
            // Allow access to 64 bit keys
            dwAccess |= 0x0100; // KEY_WOW64_64KEY
        }

        //
        // DESIGN BUG: Querying HKCU\Classes\VirtualStore returns the merged
        // view when --virtual!
        //
        // WORKAROUND: Temporarily turn off virtual mode so we can inspect
        // the actual HKCU\Classes\VirtualStore.
        //
        SetVirtualView(FALSE/*bEnable*/, FALSE/*bVerify*/);

        if ((lErrCode = ::RegOpenKeyExA(HKEY_CURRENT_USER, szVirtStore, 0,
                dwAccess, &hVirtKey)) == ERROR_SUCCESS) {
            DWORD dwValueLen=0;
            if (::RegQueryValueExA(hVirtKey, pfd->name, 0, NULL, NULL, &dwValueLen) == ERROR_SUCCESS) {
                //
                // Found the value in the VirtualStore
                //
                pfd->attrib |= FILE_ATTRIBUTE_VIRTUAL;
            }
            ::RegCloseKey(hVirtKey);
        }
        //
        // Turn virtual mode back on
        //
        SetVirtualView(TRUE/*bEnable*/, FALSE/*bVerify*/);
    }

    if (pfd->name[0] == '\0') {
        strcpy(pfd->name, "[default]");
    }
    pfd->size = fr->fr_fd.size = dwSize;
    pfd->attrib &= ~FILE_ATTRIBUTE_DIRECTORY;
    // Use the key's timestamp for the value's timestamp
    pfd->time_create = fr->fr_fd.time_create;
    pfd->time_access = fr->fr_fd.time_access;
    pfd->time_write = fr->fr_fd.time_write;
    //fr->fr_fd.size = 0;

    fr->fr_dwIndex++;
    return TRUE;
}

extern "C"
{

//
// Called by Security.cpp to report the key's security descriptor
//
BOOL _GetRegSecurity(LPCSTR szPath, struct cache_entry *ce,
    DWORD dwFlags, PSECURITY_DESCRIPTOR psd, DWORD dwSdLen,
    PDWORD pdwNeededSdLen)
{
    struct find_reg *fr;
    struct _finddatai64_t fd;
    DWORD dwError;
    DWORD dwType;

    fr = (struct find_reg*)xmalloc(sizeof(*fr));
    memset(fr, 0, sizeof(*fr));
    fr->fr_magic = FR_MAGIC;

    if (ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        dwType = DT_DIR;
    } else {
        dwType = DT_REG;
    }

    if (!_PrepReg(szPath, fr, dwType)) {
        _RegFindClose((long)fr);
        return FALSE;
    }

    if (!_LookupReg(fr, &fd)) {
        _RegFindClose((long)fr);
        return FALSE;
    }

    if (fr->fr_hKey == NULL) { // ls -d -K /
        _RegFindClose((long)fr);
        ::SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Always fails on Win9x
    dwError = (DWORD)::RegGetKeySecurity(fr->fr_hKey, dwFlags,
        psd, &dwSdLen);

    if (dwError == ERROR_MORE_DATA) {
        *pdwNeededSdLen = dwSdLen; // indicate required size
    }
    _RegFindClose((long)fr);

    return (dwError == ERROR_SUCCESS);
}


long _RegFindFirst(const char *szPath, struct _finddatai64_t *pfd,
    DWORD dwType)
{
    struct find_reg *fr;

    fr = (struct find_reg*)xmalloc(sizeof(*fr));
    memset(fr, 0, sizeof(*fr));

    fr->fr_magic = FR_MAGIC;

    if (!_PrepReg(szPath, fr, dwType)) {
        _RegFindClose((long)fr);
        return -1;
    }

    if (!_LookupReg(fr, pfd)) {
        _RegFindClose((long)fr);
        return -1;
    }

    return (long)fr;
}

int _RegFindNext(long handle, struct _finddatai64_t *pfd)
{
    struct find_reg *fr;

    if (handle == -1) { // prev failure
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    fr = (struct find_reg *)handle;

    if (fr->fr_magic != FR_MAGIC) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    if (fr->fr_bEof) { // normal exit
        SetLastError(ERROR_NO_MORE_FILES);
        return -1;
    }

    if (fr->fr_bFailed) { // if prev failure
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    if (!_LookupReg(fr, pfd)) {
        fr->fr_bFailed = TRUE;
        return -1;
    }

    return 0;
}

int _RegFindClose(long handle)
{
    struct find_reg *fr;
    DWORD dwError = ::GetLastError();

    if (handle == -1) { // prev failure
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    fr = (struct find_reg *)handle;

    if (fr->fr_magic != FR_MAGIC) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }
    if (fr->fr_szKey != NULL) {
        free(fr->fr_szKey); fr->fr_szKey = NULL;
    }
    if (fr->fr_szValue != NULL) {
        free(fr->fr_szValue); fr->fr_szValue = NULL;
    }
    if (fr->fr_szClass != NULL) {
        free(fr->fr_szClass); fr->fr_szClass = NULL;
    }
    if (fr->fr_hKey != NULL) {
        if (fr->fr_hKey != fr->fr_hRoot) {
            ::RegCloseKey(fr->fr_hKey); fr->fr_hKey = NULL;
        }
    }
    memset(fr, 0, sizeof(*fr)); // scrub
    free(fr);

    ::SetLastError(dwError); // restore original error code

    return 0;
}

///////////////////////////////////////////////////////////////////////////

BOOL
print_registry_value(struct cache_entry *ce)
{
    struct find_reg *fr;
    struct _finddatai64_t fd;
    wchar_t wszName[FILENAME_MAX];
    DWORD dwSize=0;
    DWORD dwType;
    DWORD dwGotType=0;
    LONG lErrCode;

    typedef LONG (WINAPI *PFNREGQUERYREFLECTIONKEY)(
        HKEY hBase,
        BOOL *pbIsReflectionDisabled  // BUG in MSDN doc: BOOL
    );
    static PFNREGQUERYREFLECTIONKEY pfnRegQueryReflectionKey;

    fr = (struct find_reg*)xmalloc(sizeof(*fr));
    memset(fr, 0, sizeof(*fr));
    fr->fr_magic = FR_MAGIC;

    if (ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        dwType = DT_DIR;
    } else {
        dwType = DT_REG;
    }

    if (!_PrepReg(ce->ce_abspath, fr, dwType)) {
        _RegFindClose((long)fr);
        return FALSE;
    }

    if (!_LookupReg(fr, &fd)) {
        _RegFindClose((long)fr);
        return FALSE;
    }

    if (dwType == DT_DIR) {
        //
        // Reg key: show the class name if any.
        //
        if (fr->fr_szClass != NULL) {
            more_printf("            Class Name: \"%s\"\n", fr->fr_szClass);
        }
        //
        // Reg key: report if 64-bit <-> 32-bit reflection is enabled.
        //
        // The reflection is between HKLM\Software and
        // HKLM\Software\Wow6432Node.
        //
        if (gbIsWindowsWOW64) {
          if (DynaLoad("ADVAPI32.DLL", "RegQueryReflectionKey",
                (PPFN)&pfnRegQueryReflectionKey)) {
            //
            // BUG: Documented as bReflectionEnabled but really
            // is bReflectionDisabled!
            //
            // Note: Always FALSE if !gbIsWindowsWOW64
            //
            // See http://www.codeproject.com/system/Reflection.asp
            //
            BOOL bReflectionDisabled = FALSE; // BUG: Reversed
            if ((*pfnRegQueryReflectionKey)(fr->fr_hKey, &bReflectionDisabled) == ERROR_SUCCESS) {
                if (!IsWindows7) { // Windows 7 disables all reflection always
                    if (bReflectionDisabled) { // BUG: Reversed
                        more_printf("            Reflection is disabled.\n");
                    }
                }
            }
          }
        }
        _RegFindClose((long)fr);
        return TRUE;
    }

    //
    // Show the reg value
    //

    if (fr->fr_szValue == NULL) {
        _RegFindClose((long)fr);
        return FALSE;
    }

    //
    // Query a single value - just check existance and get size
    //
    // BUG: Must use Unicode as the RegA functions wrongly
    // use the Ansi code page.
    if (::MultiByteToWideChar(get_codepage(), 0, fr->fr_szValue, -1,
            wszName, FILENAME_MAX) == 0) {
        _RegFindClose((long)fr);
        return FALSE;
    }

    if (wcscmp(wszName, L"[default]") == 0) {
        wszName[0] = L'\0';
    }

    dwSize = (DWORD)(fd.size);

    dwSize = (dwSize + 10) * sizeof(WCHAR);

    BOOL bUnicode = TRUE;
    PBYTE pbData = (PBYTE) alloca(dwSize);
    memset(pbData, 0, dwSize);

    //
    // Note: RegQueryValueExW will fail on Win9x
    //
    if ((lErrCode = ::RegQueryValueExW(fr->fr_hKey, wszName, 0,
            &dwGotType, pbData, &dwSize)) != ERROR_SUCCESS) {
        if (lErrCode != ERROR_NOT_SUPPORTED && lErrCode != ERROR_CALL_NOT_IMPLEMENTED) {
            ::SetLastError((DWORD)lErrCode);
            _RegFindClose((long)fr);
            return FALSE;
        }
        //
        // Win9x: Try again using the ANSI version.
        // Note that this will wrongly convert OEM chars.
        //
        if ((lErrCode = ::RegQueryValueExA(fr->fr_hKey, fr->fr_szValue, 0,
                &dwGotType, pbData, &dwSize)) != ERROR_SUCCESS) {
            ::SetLastError((DWORD)lErrCode);
            _RegFindClose((long)fr);
            return FALSE;
        }
        bUnicode = FALSE;
    }

    BOOL bExpandedMui = FALSE;

    if (IsVista && gbExpandMui) {
        if ((dwGotType == REG_SZ || dwGotType == REG_EXPAND_SZ || dwGotType == REG_MULTI_SZ)
            && dwSize >= sizeof(WCHAR) && ((LPCWSTR)pbData)[0] == L'@'
            && DynaLoad("ADVAPI32.DLL", "RegLoadMUIStringW", (PPFN)&pfnRegLoadMUIStringW)) {
            PBYTE pbMuiData = NULL;
            //
            // Get the required buffer size for the expanded MUI string
            //
            DWORD dwMuiLen = 0; // byte len
            WCHAR wszDummy[4]; // dummy buffer
            wszDummy[0] = L'\0';
            if ((lErrCode = (*pfnRegLoadMUIStringW)(fr->fr_hKey, wszName,
                    wszDummy, 0, &dwMuiLen, 0, NULL)) != ERROR_MORE_DATA) {
                goto NoMui; // Use the @-string as-is
            }

            pbMuiData = (PBYTE) alloca(dwMuiLen+8);

            //
            // Now read the data for real
            //
            // dwMuiLen will be overwritten with the actual length
            //
            if ((lErrCode = (*pfnRegLoadMUIStringW)(fr->fr_hKey, wszName,
                    (LPWSTR)pbMuiData, dwMuiLen, &dwMuiLen, 0, NULL)) != ERROR_SUCCESS) {
                goto NoMui; // Use the @-string as-is
            }
            //
            // Replace pbData with the expanded MUI data
            //
            pbData = pbMuiData;
            dwSize = dwMuiLen;

            bExpandedMui = TRUE;
        }
    }

NoMui:

    fd.size = dwSize;
    _RegFindClose((long)fr);

    switch (dwGotType) {

        case REG_SZ:
        case REG_EXPAND_SZ:
        {
            DWORD dwLen, dwStrLen=0;
            LPSTR szBuf;

            more_fputs((dwGotType == REG_SZ ?
                "            REG_SZ=\"" : "            REG_EXPAND_SZ=\""), stdmore);
            if (!bUnicode) {
                more_fputs((LPCSTR)pbData, stdmore);
                dwLen = dwSize;
                dwStrLen = strlen((LPCSTR)pbData) + 1;
            } else {
                dwLen = dwSize+10;
                szBuf = (LPSTR)alloca(dwLen);
                if ((dwLen = ::WideCharToMultiByte(get_codepage(), 0,
                        (LPCWSTR)pbData, dwSize/2, szBuf, dwLen, NULL, NULL)) == 0) {
                    more_fputs("???", stdmore);
                } else {
                    more_fputs(szBuf, stdmore);
                    dwStrLen = strlen(szBuf) + 1;
                }
            }
            more_fputs("\"\n", stdmore);
            if (dwLen != dwStrLen) {
                //
                // Warn if the string length does not match the registry
                // buffer size.  Could indicate hidden data after \0
                //
                more_printf("            *** String length with \\0 (%u) <> registry length (%u) ***\n",
                    dwStrLen, dwLen);
            }
            break;
        }

        case REG_NONE:
        case REG_BINARY:
        case REG_LINK:
        case REG_MULTI_SZ:
        case REG_RESOURCE_LIST:
        case REG_FULL_RESOURCE_DESCRIPTOR:
        case REG_RESOURCE_REQUIREMENTS_LIST:
        default:
        {
            DWORD dwBytes, i;
            char ch;

            switch (dwGotType) {
                case REG_NONE:
                    more_printf("            REG_NONE  (%u bytes)\n", dwSize);
                    break;
                case REG_BINARY:
                    more_printf("            REG_BINARY  (%u bytes)\n", dwSize);
                    break;
                case REG_LINK:
                    more_printf("            REG_LINK  (%u bytes)\n", dwSize);
                    break;
                case REG_MULTI_SZ:
                    more_printf("            REG_MULTI_SZ  (%u bytes)\n", dwSize);
                    break;
                case REG_RESOURCE_LIST:
                    more_printf("            REG_RESOURCE_LIST  (%u bytes)\n", dwSize);
                    break;
                case REG_FULL_RESOURCE_DESCRIPTOR:
                    more_printf("            REG_FULL_RESOURCE_DESCRIPTOR  (%u bytes)\n", dwSize);
                    break;
                case REG_RESOURCE_REQUIREMENTS_LIST:
                    more_printf("            REG_RESOURCE_REQUIREMENTS_LIST  (%u bytes)\n", dwSize);
                    break;
                default:
                    more_printf("            Unknown type (%u), size %u bytes.\n",
                        dwGotType, dwSize);
                    break;
            }

            for (unsigned long l=0; l < dwSize; l += 16) {
                more_printf("%8x: ", l);
                dwBytes = ((dwSize - l < 16) ? (dwSize - l) : 16);
                for (i=0; i < dwBytes; ++i) {
                    more_printf("%02.2x ", pbData[l+i]);
                }
                for (; i < 16; ++i) {
                    more_fputs("   ", stdmore);
                }
                more_fputs("  ", stdmore);

                for (i=0; i < dwBytes; ++i) {
                    if ((ch = pbData[l+i]) < 040 || ch > 0176) {
                        ch = '.';
                    }
                    more_putc(ch, stdmore);
                }

                for (; i < 16; ++i) {
                    more_putc(' ', stdmore);
                }
                more_putc('\n', stdmore);
            }
            break;
        }

        case REG_DWORD:
            more_printf("            REG_DWORD=%u (0x%08X)\n",
                *(PDWORD)pbData, *(PDWORD)pbData);
            if (dwSize != sizeof(DWORD)) {
                more_printf("            *** DWORD length (%u) is not standard. ***\n",
                    dwSize);
            }
            break;

        case REG_QWORD:
            more_printf("            REG_QWORD=%I64u (0x%I64X)\n",
                *(unsigned __int64 *)pbData, *(unsigned __int64 *)pbData);
            if (dwSize != sizeof(unsigned __int64)) {
                more_printf("            *** QWORD length (%u) is not standard. ***\n",
                    dwSize);
            }
            break;
    }

    if (bExpandedMui) {
            more_printf("                Expanded MUI string.\n");
    }

    return TRUE;
}

//
// Query a symbolic registry link
//
// Also do --regsetval and --regdelval
//
char *
_GetRegistryLink(struct cache_entry *ce, char *szPath)
{
    struct find_reg *fr;

    if ((ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return NULL; // regval
    }

    fr = (struct find_reg*)xmalloc(sizeof(*fr));
    memset(fr, 0, sizeof(*fr));
    fr->fr_magic = FR_MAGIC;

    DWORD dwType = DT_DIR;

    if (!_PrepReg(ce->ce_abspath, fr, dwType) || fr->fr_szKey == NULL) {
        _RegFindClose((long)fr);
        return NULL;
    }

    wchar_t wszPath[FILENAME_MAX+1];

    //
    // Convert the registry path to Unicode
    //
    if (MultiByteToWideChar(get_codepage(), 0, fr->fr_szKey, -1,
            wszPath, FILENAME_MAX) == 0) {
        _RegFindClose((long)fr);
        return NULL;
    }

    LONG lErrCode;
    DWORD dwDisposition = 0;
    HKEY hkLink = NULL;

    DWORD dwAccess = KEY_READ;
    if (gbRegDelVal || gbRegSetVal) {
        dwAccess |= KEY_WRITE;
    }

    if (gbIsWindowsWOW64 && !gb32bit) {
        // Allow access to 64 bit keys
        dwAccess |= 0x0100; // KEY_WOW64_64KEY
    }

    //
    // Must use RegCreateKeyExW to pass REG_OPTION_OPEN_LINK
    //
    lErrCode = RegCreateKeyExW(fr->fr_hRoot,
        wszPath,
        0, NULL/*wszClass*/,
        REG_OPTION_OPEN_LINK,
        dwAccess, NULL, &hkLink, &dwDisposition);

    if (lErrCode != 0) {
        _RegFindClose((long)fr);
        return NULL;
    }

    dwType = 0;
    WCHAR wszData[FILENAME_MAX+1];
    DWORD dwLen = FILENAME_MAX*sizeof(WCHAR);

    wszData[0] = L'\0';

    lErrCode = RegQueryValueExW(hkLink, L"SymbolicLinkValue", NULL, &dwType,
        (PBYTE)wszData, &dwLen);

    if (gbRegDelVal) {
        //
        // --regdelval   Delete a test value for exploring registry reflection
        // and registry redirection.
        //
        ::RegDeleteValueW(hkLink, L"TestValue");
    }

    if (gbRegSetVal) {
        //
        // --regsetval   Set a test value for exploring registry reflection
        // and registry redirection.
        //
        DWORD dwVal = 1;
        ::RegSetValueExW(hkLink, L"TestValue", 0, REG_DWORD,
            (PBYTE)&dwVal, sizeof(dwVal));
    }

    RegCloseKey(hkLink); hkLink = NULL;

    //
    // Sanity check: If we somehow created a new key accidentally
    // via RegCreateKeyEx, bail immediately!
    //
    if (dwDisposition == REG_CREATED_NEW_KEY) {
        more_printf("Error: Created new key by mistake: %s\n",
            fr->fr_szKey);
        _RegFindClose((long)fr);
        exit(1);
    }

    _RegFindClose((long)fr);

    if (lErrCode != 0) {
        return NULL;
    }

    wszData[dwLen/2] = L'\0'; // BUG: Not NULL terminated

    //
    // Convert from wchar_t to multibyte string
    //
    if (!WideCharToMultiByte(get_codepage(), 0,
            wszData, -1,
            szPath, FILENAME_MAX-1, NULL, NULL)) {
        return NULL;
    }

    return szPath;
}

} // end extern "C"

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

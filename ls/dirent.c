//////////////////////////////////////////////////////////////////////////
//
// opendir/readdir/stat translation layer for WIN32 - with caching
//
// Copyright (c) 2007-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

//
// Implement a stat cache to reduce number of round-trips to the file system.
// This is especially important for network folders.
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <io.h> // for _findfirsti64/_findnexti64

#include <errno.h>

#include <string.h>
#include <wchar.h>
#include <mbstring.h>

#include <time.h>

#define NEED_DIRENT_H
#include "windows-support.h"
#include "xalloc.h"
#include "more.h"
//#include "xmbrtowc.h" // for get_codepage()
#include "ls.h" // for enum show_streams and gbReg

extern int print_inode;
extern int phys_size;
extern int short_names;

#undef strrchr
#define strrchr _mbsrchr // use the multibyte version of strrchr

#pragma warning(disable: 4057) // ignore unsigned char* vs char*

//
// Cache for opendir()
//
static struct cache_dir *_dir_first, *_dir_last;
static struct cache_dir *_dir_nocache; // current non-cached dir

//
// Partial cache for stat()
//
static struct cache_entry *_stat_first, *_stat_last;


//
// Map GetLastError() WIN32 error codes to Posix error codes
//
struct win32_err_table {
    DWORD dwWin32Error; // GetLastError() code
    int errno_code; // Posix code
};

//
// Win32 -> Posix error mappings.
// Same as CRT mappings for functional compatibility.
//
static struct win32_err_table err_table[] = {
 {  ERROR_INVALID_FUNCTION,       EINVAL    },
 {  ERROR_FILE_NOT_FOUND,         ENOENT    },
 {  ERROR_PATH_NOT_FOUND,         ENOENT    },
 {  ERROR_TOO_MANY_OPEN_FILES,    EMFILE    },
 {  ERROR_ACCESS_DENIED,          EACCES    },
 {  ERROR_INVALID_HANDLE,         EBADF     },
 {  ERROR_ARENA_TRASHED,          ENOMEM    },
 {  ERROR_NOT_ENOUGH_MEMORY,      ENOMEM    },
 {  ERROR_INVALID_BLOCK,          ENOMEM    },
 {  ERROR_BAD_ENVIRONMENT,        E2BIG     },
 {  ERROR_BAD_FORMAT,             ENOEXEC   },
 {  ERROR_INVALID_ACCESS,         EINVAL    },
 {  ERROR_INVALID_DATA,           EINVAL    },
 {  ERROR_INVALID_DRIVE,          ENOENT    },
 {  ERROR_CURRENT_DIRECTORY,      EACCES    },
 {  ERROR_NOT_SAME_DEVICE,        EXDEV     },
 {  ERROR_NO_MORE_FILES,          ENOENT    },
 {  ERROR_LOCK_VIOLATION,         EACCES    },
 {  ERROR_BAD_NETPATH,            ENOENT    },
 {  ERROR_NETWORK_ACCESS_DENIED,  EACCES    },
 {  ERROR_BAD_NET_NAME,           ENOENT    },
 {  ERROR_FILE_EXISTS,            EEXIST    },
 {  ERROR_CANNOT_MAKE,            EACCES    },
 {  ERROR_FAIL_I24,               EACCES    },
 {  ERROR_INVALID_PARAMETER,      EINVAL    },
 {  ERROR_NO_PROC_SLOTS,          EAGAIN    },
 {  ERROR_DRIVE_LOCKED,           EACCES    },
 {  ERROR_BROKEN_PIPE,            EPIPE     },
 {  ERROR_DISK_FULL,              ENOSPC    },
 {  ERROR_INVALID_TARGET_HANDLE,  EBADF     },
 {  ERROR_INVALID_HANDLE,         EINVAL    },
 {  ERROR_WAIT_NO_CHILDREN,       ECHILD    },
 {  ERROR_CHILD_NOT_COMPLETE,     ECHILD    },
 {  ERROR_DIRECT_ACCESS_HANDLE,   EBADF     },
 {  ERROR_NEGATIVE_SEEK,          EINVAL    },
 {  ERROR_SEEK_ON_DEVICE,         EACCES    },
 {  ERROR_DIR_NOT_EMPTY,          ENOTEMPTY },
 {  ERROR_NOT_LOCKED,             EACCES    },
 {  ERROR_BAD_PATHNAME,           ENOENT    },
 {  ERROR_MAX_THRDS_REACHED,      EAGAIN    },
 {  ERROR_LOCK_FAILED,            EACCES    },
 {  ERROR_ALREADY_EXISTS,         EEXIST    },
 {  ERROR_FILENAME_EXCED_RANGE,   ENAMETOOLONG },
 {  ERROR_NESTING_NOT_ALLOWED,    EAGAIN    },
 {  ERROR_NOT_ENOUGH_QUOTA,       ENOMEM    },
 {  ERROR_BUFFER_OVERFLOW,        ENAMETOOLONG }
};

// Range of errors for CreateProcess errors (ENOEXEC)
#define MIN_EXEC_ERROR ERROR_INVALID_STARTING_CODESEG
#define MAX_EXEC_ERROR ERROR_INFLOOP_IN_RELOC_CHAIN

// Range of errors for Access Denied (EACCESS)
#define MIN_EACCES_ERROR ERROR_WRITE_PROTECT
#define MAX_EACCES_ERROR ERROR_SHARING_BUFFER_EXCEEDED

static struct cache_entry *
_follow_symlink(struct cache_entry *);

static int
_get_full_file_info(char *szPath, struct cache_entry *ce);

//
// Get the physical size of the file.  Returns smaller
// size for compressed or sparse files.
//
static uintmax_t
_get_phys_size(char *szPath, uintmax_t ui64DefaultSize)
{
    DWORD dwLow, dwHigh=0;

    typedef DWORD (WINAPI *PFNGETCOMPRESSEDFILESIZE)(
        LPCTSTR lpFileName,
        LPDWORD lpFileSizeHigh
    );
    static PFNGETCOMPRESSEDFILESIZE pfnGetCompressedFileSize;

    if (gbReg) {
        return ui64DefaultSize;
    }
    if (!DynaLoad("KERNEL32.DLL", "GetCompressedFileSizeA", &pfnGetCompressedFileSize)) {
        return ui64DefaultSize; // Win9x
    }

    //
    // Is this a stream name?
    //
    if (szPath[0] != '\0' && szPath[1] != '\0' && _mbschr(szPath+2,':') != NULL) {
        return ui64DefaultSize; // already computed at lower level (streams.c)
    }

    dwLow = (*pfnGetCompressedFileSize)(szPath, &dwHigh);

    if (dwLow == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
        return ui64DefaultSize; // failed
    }

    return _to_unsigned_int64(dwLow, dwHigh);
}


static void
_get_short_path(char *szPath)
{
    if (gbReg) {
        return;
    }
    GetShortPathName(szPath, szPath, FILENAME_MAX);
}

//
// Map and assign the Win32 GetLastError() return value to POSIX errno
//
void
MapWin32ErrorToPosixErrno()
{
    DWORD dwWin32Error;
    int i;

    dwWin32Error = GetLastError();

    //
    // Set the "operating system" errno global in the MSVC runtime
    //
    _doserrno = dwWin32Error;

    for (i = 0; i < sizeof(err_table)/sizeof(err_table[0]); ++i) {
        if (dwWin32Error == err_table[i].dwWin32Error) {
                errno = err_table[i].errno_code;
            return;
        }
    }

    //
    // Heuristic check for other error codes
    //
    if (dwWin32Error >= MIN_EACCES_ERROR && dwWin32Error <= MAX_EACCES_ERROR) {
        errno = EACCES; // some sort of permission problem
    } else if (dwWin32Error >= MIN_EXEC_ERROR && dwWin32Error <= MAX_EXEC_ERROR) {
        errno = ENOEXEC;
    } else  {
        errno = EINVAL; // punt
    }
    return;
}

////////////////////////////////////////////////////////////////////////
//
// Switch to the "real" 64-bit filesystem view so we can view the
// real \WINDOWS\SYSTEM32 and not get redirected to \WINDOWS\SysWOW64
//

typedef BOOL (WINAPI *PFNISWOW64PROCESS)(HANDLE hProcess, PBOOL bWow64Process);
static PFNISWOW64PROCESS gpfnIsWow64Process;

typedef BOOL (WINAPI *PFNWOW64DISABLEWOW64FSREDIRECTION)(PVOID *OldValue);
static PFNWOW64DISABLEWOW64FSREDIRECTION gpfnWow64DisableWow64FsRedirection;

typedef BOOL (WINAPI *PFNWOW64REVERTWOW64FSREDIRECTION)(PVOID OldValue);
static PFNWOW64REVERTWOW64FSREDIRECTION gpfnWow64RevertWow64FsRedirection;

#define WOW64_UNKNOWN 0x12345566

static DWORD bIsWindowsWOW64 = WOW64_UNKNOWN;

PVOID _push_64bitfs()
{
    PVOID pOldState = (PVOID)WOW64_UNKNOWN;

    if (bIsWindowsWOW64 == WOW64_UNKNOWN) {
        if (DynaLoad("KERNEL32.DLL", "IsWow64Process",
                &gpfnIsWow64Process)) {
            bIsWindowsWOW64 = 0; // in case sizeof(BOOL) changed to 1
            (*gpfnIsWow64Process)(GetCurrentProcess(), (PBOOL)&bIsWindowsWOW64);
        } else {
            bIsWindowsWOW64 = FALSE;
        }
    }

    if (!bIsWindowsWOW64 || gb32bit) {
        return NULL;
    }

    if (!DynaLoad("KERNEL32.DLL", "Wow64DisableWow64FsRedirection",
            &gpfnWow64DisableWow64FsRedirection)) {
        return pOldState; // indicate failure
    }

    if (!(*gpfnWow64DisableWow64FsRedirection)(&pOldState)) {
        pOldState = (PVOID)WOW64_UNKNOWN; // indicate failure
        return pOldState;
    }
    return pOldState;
}

void _pop_64bitfs(PVOID pOldState)
{
    if (!bIsWindowsWOW64 || pOldState == (PVOID)WOW64_UNKNOWN || gb32bit) {
        return;
    }

    if (!DynaLoad("KERNEL32.DLL", "Wow64RevertWow64FsRedirection",
            &gpfnWow64RevertWow64FsRedirection)) {
        return;
    }
    (*gpfnWow64RevertWow64FsRedirection)(pOldState);
    return;
}

//////////////////////////////////////////////////////


//
// Return 1 if the path is to a server root, eg "\\server\share"
//
// Note: Assumes the path is already clean
// (no embedded double-slashes, dots, or dot-dots)
//
static int _IsServerRootPath(char *szPath)
{
    char *sz;

    if (gbReg) {
        return 0;
    }

    if (szPath[0] != '\\' || szPath[1] != '\\') { // <\\>server...
        return 0;
    }

    sz = &szPath[2];

    if ((sz = _mbschr(sz, '\\')) == NULL) {  // \\server<\>...
        return 1; // \\server pseudo-path (from glob)
    }

    if ((sz = _mbschr(++sz, '\\')) == NULL) {
        return 1; // found \\server\share or \\server\ pseudo-path
    }

    return (*(sz+1) == '\0'); // found \\server\share\...
}

//
// Work around a BUG in FindFirst.
//
// Expand "C:foo" to "C:/lbin/foo"
//
// Necessary because FindFirst("C:*") fails if the current dir
// is C:\.  Ditto FindFirst(".\*")
//
// Also to discover UNC paths "." -> \\server\share
//
static int
_ExpandPath(char *szPath, char *szBuf, size_t dwBufLen)
{
    char *szFilePart=NULL; // unused
    size_t n;

    n = strlen(szPath) + 1;
    if (n > dwBufLen) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (gbReg) {
        //n = GetRegistryPathName(szPath, dwBufLen, szBuf);
        lstrcpyn(szBuf, szPath, dwBufLen); // use as-is
    } else {
        char *szStream = NULL;
        //
        // BUG: GetFullPathName(".:secret:$DATA") is wrongly expanded
        // to ".:\secret:$DATA".  Probably because GetFullPathName gets
        // confused and thinks that ".:" is a drive letter.
        //
        // WORKAROUND: Temporarily chop the stream suffix
        //
        if ((n = strlen(szPath)) >= 7
                && _mbsicmp(szPath+n-6, ":$DATA") == 0) {
            //
            // Find the second ':' going backwards
            //
            szPath[n-6] = '\0'; // temporarily hide the ":$DATA" suffix
            if ((szStream = strrchr(szPath, ':')) != NULL) {
                *szStream = '\0'; // temporarily hide the second ':'
            }
            szPath[n-6] = ':';
        }

        n = GetFullPathName(szPath, dwBufLen, szBuf, &szFilePart);

        if (szStream) {
            size_t nLenStream;

            *szStream = ':'; // restore the second ':'
            nLenStream = strlen(szStream);
            n += nLenStream;
            if (n+1 <= dwBufLen) {
                strcat(szBuf, szStream);
            }
        }
    }

    if (n+1 > dwBufLen) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (n == 0) {
        MapWin32ErrorToPosixErrno();
        return -1;
    }

#ifdef UNDEFINED
    //
    // Convert to forward slashes
    //
    for (sz = szBuf; *sz; ++sz) {
        if (*sz == '\\') {
            *sz = '/';
        }
    }
#endif

    return 0;
}


//
// Get the absolute file path
//
int _GetAbsolutePath(char *szFile, char *szFullPath, DWORD dwFullPathLen,
    BOOL* pbFixedDrive)
{
    CHAR *sz;
    //
    // Expand the path to smoke out the C: or UNC path.
    // Also collapses redundant dot-dots and dots.
    //
    if (_ExpandPath(szFile, szFullPath, dwFullPathLen) == -1) {
        return -1; // errno already set
    }

    //
    // BUG: FindFirst("\\server\share") fails!  Must append
    // a backslash, "\\server\share\"
    //
    if (_IsServerRootPath(szFullPath)) {
        sz = szFullPath + strlen(szFullPath) - 1;
        if (*sz != '\\') {
            *++sz = '\\';
            *++sz = '\0';
        }
    }

    //
    // See if we should get full info
    //
    if (pbFixedDrive != NULL) { // do we care about full info?
        if (gbReg) {
            // Registry is always assumed to be local (fast)
            *pbFixedDrive = TRUE;
        } else {
            *pbFixedDrive = FALSE;
            if (szFullPath[1] == ':') { // not a UNC path
                char szDrive[4];
                //
                // If C:\ is a local drive, get full info
                //
                szDrive[0] = szFullPath[0];
                szDrive[1] = szFullPath[1];
                szDrive[2] = '\\';
                szDrive[3] = '\0';
                if (GetDriveType(szDrive) == DRIVE_FIXED) {
                    //
                    // We want full info (local disks only unless already set)
                    //
                    *pbFixedDrive = TRUE;
                }
            }
        }
    }

    return 0;
}

//////////////////////////////////////////////////////

unsigned long _MapMode(struct cache_entry *ce)
{
    DWORD dwAttribs;
    unsigned long m;
    char *sz;

    dwAttribs = ce->dwFileAttributes;

    if (dwAttribs & (FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)) {
        m = 0444;  // -r--r--r--
    } else {
        m = 0666;  // -rw-rw-rw-
    }

    if (dwAttribs & FILE_ATTRIBUTE_DIRECTORY) {
        m &= ~S_IFMT; m |= S_IFDIR;
        m |= 0111;
    } else if (dwAttribs & FILE_ATTRIBUTE_DEVICE) {
        m &= ~S_IFMT; m |= S_IFCHR;
    } else {
        m &= ~S_IFMT; m |= S_IFREG; // regular file
    }

    if (ce->ce_bIsSymlink) {
        m &= ~S_IFMT; m |= S_IFLNK; // symbolic link
    }

    if (dwAttribs & FILE_ATTRIBUTE_COMPRESSED) {
        m |= S_COMPR; // compressed
    }
    if (dwAttribs & FILE_ATTRIBUTE_STREAMS) { // pseudo-attrib
        //
        // The file has child streams (or is a stream)
        //
        m |= S_STREAM;
    }

    if ((sz = strrchr(ce->ce_filename, '.')) != NULL) {
        //
        // Heuristic: Assume executable if these types.
        //
        if (_mbsicmp(sz, ".exe") == 0 || _mbsicmp(sz, ".com") == 0 ||
            _mbsicmp(sz, ".bat") == 0 || _mbsicmp(sz, ".cmd") == 0) {
                m |= 0111;  // ---x--x--x-
        }
    }

    return m;
}

unsigned long _MapType(struct cache_entry *ce)
{
    DWORD dwAttribs;
    unsigned long t = DT_UNKNOWN;

    dwAttribs = ce->dwFileAttributes;

    if (dwAttribs & FILE_ATTRIBUTE_DIRECTORY) {
        t = DT_DIR;
    } else if (dwAttribs & FILE_ATTRIBUTE_DEVICE) {
        t = DT_CHR;
    } else {
        t = DT_REG; // regular file
    }
    if (ce->ce_bIsSymlink) {
        t = DT_LNK; // symbolic link
    }
    return t;
}

//
// Do a DOS-style wildcard pattern match.
//
static BOOL _DosPatternMatch(LPCSTR szPattern, LPCSTR szFile)
{
    register LPCSTR p, q;
    unsigned int mbc;

    p = szPattern;
    q = szFile;
    for (;;) {
      //
      // DOC BUG: _mbsnextc() returns the _current_ multi-byte char
      //
      switch (mbc = _mbsnextc(p), p = _mbsinc(p), mbc) {
        case '\0':
            goto done;
        case '?':
            if (*q == '\0')
                return FALSE;
            q = _mbsinc(q);
            break;
        case '*':
            //
            // DOC BUG: _mbsnextc() returns the _current_ multi-byte char
            //
            mbc = _mbsnextc(p);
            if (mbc != '?' && mbc != '*') {
                mbc = _mbctolower(mbc);
                while (_mbctolower(*q) != mbc) {
                    if (*q == '\0') {
                        return mbc == '\0' ? TRUE : FALSE;
                    }
                    q = _mbsinc(q);
                }
            }
            do {
                if (_DosPatternMatch(p, q)) // recurse
                    return TRUE;
                mbc = _mbsnextc(q); // current char, not "next"
                q = _mbsinc(q);
            } while (mbc != '\0');
            return FALSE;
        default:
            if (_mbctolower(*q) != _mbctolower(mbc)) {
                return FALSE;
            }
            q = _mbsinc(q);
            break;
      }
    }
done:
    return (*q == '\0') ? TRUE : FALSE;
}

static BOOL
_match_dir(struct cache_dir *cd, BOOL bFile,
    LPCSTR szPath, LPCSTR szPat)
{
    if (_mbsicmp(cd->cd_dirname, szPath) == 0) {
        if (!bFile) {
            //
            // Matching against another pattern - must be exact match
            //
            if (_mbsicmp(szPat, cd->cd_pat) == 0) {
                return TRUE;
            }
        } else if (_DosPatternMatch(cd->cd_pat, szPat/*file*/)) {
            //
            // Matching against a file name - use pattern match
            //
            return TRUE;
        }
    }
    return FALSE;
}

struct cache_dir *
_find_cache_dir(LPCSTR szPath, LPCSTR szPat)
{
    struct cache_dir *cd;
    BOOL bFile;

    bFile = (_mbspbrk(szPath, "?*") == NULL);

    //
    // First match against the current non-cached dir
    //
    if ((cd = _dir_nocache) != NULL) {
        if (_match_dir(cd, bFile, szPath, szPat)) {
            return cd;
        }
    }
    //
    // Second search the dir cache list
    //
    for (cd = _dir_first; cd; cd = cd->cd_next) {
        if (_match_dir(cd, bFile, szPath, szPat)) {
            return cd;
        }
    }
    return NULL;
}

//////////////////////////////////////////////////////

static void _delete_dir(struct cache_dir *cd);

//
// Replacement for opendir()
//
// Called by ls.c
//

static DIR*
__opendir_with_pat(const char* szPath, const char* szPat, BOOL bCache);

DIR*
opendir(const char* szPath)
{
    return opendir_with_pat(szPath, "*", TRUE/*bCache*/);
}

DIR*
opendir_with_pat(const char* szPath, const char* szPat, BOOL bCache)
{
    PVOID pOldState;
    DIR* pResult;

    pOldState = _push_64bitfs();
    pResult = __opendir_with_pat(szPath, szPat, bCache);
    _pop_64bitfs(pOldState);
    return pResult;
}

//
// Opendir with wildcard pattern, for network speedup
//
// Called by glob.c
//
static DIR*
__opendir_with_pat(const char* szPath, const char* szPat, BOOL bCache)
{
    char szBuf[FILENAME_MAX];
    char szFullDirPath[FILENAME_MAX];
    char szPatBuf[FILENAME_MAX+10];
    char* sz;
    struct cache_dir *cd;
    struct cache_entry *ce;
    DIR* pDir;
    long hFind;
    struct _finddatai64_t fd;
    BOOL bShowStreams = (show_streams == yes_arg);
    BOOL bFixedDisk = FALSE;
    BOOL bGetFullFileInfoOk = TRUE;

    //
    // Delete the previous non-cached dir, if any
    //
    if (_dir_nocache != NULL) {
        _delete_dir(_dir_nocache);
        _dir_nocache = NULL;
    }

    lstrcpyn(szBuf, szPath, sizeof(szBuf));
    //
    // Change forward slashes to backward slashes
    //
    for (sz = szBuf; *sz; ++sz) {
        if (*sz == '/') {
            *sz = '\\';
        }
    }
    //
    // Strip trailing backslashes
    //
    for (--sz; sz > szBuf; --sz) {
        if (*sz != '\\') {
            break;
        }
        if (sz == szBuf+2 && szBuf[1] == ':') {
            break; // stop if C:\ found
        }
        *sz = '\0';
    }

    if (!gbReg) {
        //
        // See if the pattern contains any UNIX-style glob chars
        // other than *?
        //
        // Note that '!' is legal in an NTFS file name.
        //
        // Note that all glob chars are legal in registry names.
        //
        if (_mbspbrk(szPat, "[]+@") != NULL) {
            szPat = "*"; // punt
        }
    }

    //
    // Return cached dir if available
    //
    if ((cd = _find_cache_dir(szBuf, szPat)) != NULL) {
        pDir = xmalloc(sizeof(DIR));
        memset(pDir, 0, sizeof(pDir));
        pDir->dd_cd = cd;
        pDir->dd_next_entry = cd->cd_entry_first;
        return pDir;
    }

    //
    // Get the absolute path of the directory for FindFirst
    //
    if (_GetAbsolutePath(szBuf, szFullDirPath, FILENAME_MAX, &bFixedDisk) < 0) {
        return NULL;
    }

    //
    // Do not show streams if --fast on a non-fixed disk
    //
    if (run_fast && !bFixedDisk) {
        bShowStreams = FALSE;
    }

    //
    // See if the resulting path is too long
    //
    if (strlen(szBuf) + strlen(szPat) + 2 > sizeof(szBuf)) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    //
    // Create a new directory node
    //
    cd = (struct cache_dir *)xmalloc(sizeof(struct cache_dir));
    memset(cd, 0, sizeof(*cd));
    cd->cd_dirname = xstrdup(szBuf); // *not* abs path - must match for caching
    cd->cd_pat = xstrdup(szPat);

    //
    // Append search pattern for FindFirstFile.
    // Use absolute path to make sure it works w/UNC
    //
    strcpy(szPatBuf, szFullDirPath);
    if (*right(szPatBuf, 1) != '\\') { // if not already
        strcat(szPatBuf, "\\");
    }
    strcat(szPatBuf, szPat);

#ifdef UNDEFINED
    //
    // BUG: FindFirst("\\server\share") fails!  Must append
    // a backslash, "\\server\share\"
    //
    if (_IsServerRootPath(szPatBuf)) {
        sz = szPatBuf + strlen(szPatBuf) - 1;
        if (*sz != '\\') {
            *++sz = '\\';
            *++sz = '\0';
        }
    }
#endif

#ifdef _DEBUG
#define DEBUG_FINDFIRST
#endif
#ifdef DEBUG_FINDFIRST
more_printf("opendir: findfirst on \"%s\"\n", szPatBuf);
more_fflush(stdmore);
#endif

    //
    // Always guaranteed to return at least "." and "..", otherwise
    // not a directory or not found.
    //
    if ((hFind = _xfindfirsti64(szPatBuf, &fd, bShowStreams, DT_DIR))
            == (long)INVALID_HANDLE_VALUE) {
        MapWin32ErrorToPosixErrno();
        free(cd->cd_dirname);
        free(cd->cd_pat);
        free(cd);
        return NULL;
    }

    if (bCache) {
        //
        // Append new directory to the dir cache list
        //
        if (_dir_first == NULL) {
            _dir_first = _dir_last = cd;
        } else {
            _dir_last->cd_next = cd;
            _dir_last = cd;
        }
        _dir_nocache = NULL;
    } else {
        //
        // Save as non-cached
        //
        _dir_nocache = cd;
    }

    do {
        //
        // Append each file entry to the dir
        //
        ce = (struct cache_entry *)xmalloc(sizeof(*ce));
        memset(ce, 0, sizeof(*ce));
        if (cd->cd_entry_first == NULL) {
            cd->cd_entry_first = cd->cd_entry_last = ce;
        } else {
            cd->cd_entry_last->ce_next = ce;
            cd->cd_entry_last = ce;
        }
        ce->ce_filename = (char *)xstrdup(fd.name);
        ce->ce_size = fd.size;
        ce->ce_ino = 1; // requires GetFileInformationByHandle - uintmax_t
        ce->dwFileAttributes = fd.attrib; // FILE_ATTRIBUTE_NORMAL maps to 0
        ce->ce_atime = fd.time_access;
        ce->ce_mtime = fd.time_write;
        ce->ce_ctime = fd.time_create;
        ce->nNumberOfLinks = 1;

        if (bFixedDisk) {
            ce->dwFileAttributes |= FILE_ATTRIBUTE_FIXED_DISK;
        }

        // Flag reparse points and .LNK shortcuts as symbolic links
        if ((ce->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                _mbsicmp(right(fd.name, 4), ".lnk") == 0) {
            ce->ce_bIsSymlink = TRUE;
        }

        //
        // If we are reparse point, or need full info,
        // or phys size, or short names, or ls -l
        //
        if ((ce->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                || gbReg || !run_fast || bFixedDisk || print_inode
                || phys_size || short_names) {
            char szBuf2[FILENAME_MAX], szBuf3[FILENAME_MAX];
            //
            // Build dir\file
            //
            if (strlen(szFullDirPath) + strlen(fd.name) + 2 < sizeof(szBuf2)) {
                strcpy(szBuf2, szFullDirPath); // directory path
                if (*right(szBuf2, 1) != '\\') { // if not already
                    strcat(szBuf2, "\\");
                }
                strcat(szBuf2, fd.name);
                //
                // Get the absolute path
                //
                if (_GetAbsolutePath(szBuf2, szBuf3, FILENAME_MAX, NULL) >= 0) {
                    //
                    // Squirrel away our abs path for later lookup by security.cpp
                    //
                    ce->ce_abspath = xstrdup(szBuf3);

                    if (gbReg && (ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        // For registry keys we must test each regkey explicitly
                        _follow_symlink(ce);
                    }

                    if ((!run_fast || bFixedDisk || print_inode) &&
                            bGetFullFileInfoOk) {
                        //
                        // Get inode and hardlink info
                        // (requires absolute path)
                        //
                        bGetFullFileInfoOk = (_get_full_file_info(szBuf3, ce) == 0);
                    }
                }
                //
                // Get the physical size too if requested
                //
                if (phys_size) {
                    ce->ce_size = _get_phys_size(szBuf2, ce->ce_size);
                }

                if (short_names) {
                    //
                    // Get the short path, then extract the rightmost
                    // component and stuff it into ce->ce_filename
                    //
                    _get_short_path(szBuf2);
                    if ((sz = strrchr(szBuf2, '\\')) != NULL) {
                        ++sz;
                        free(ce->ce_filename);
                        ce->ce_filename = (char *)xstrdup(sz);
                    }
                }

            }
        }
    } while (_xfindnexti64(hFind, &fd, bShowStreams) != -1);

    if (GetLastError() != ERROR_NO_MORE_FILES) { // network fail during walk
        DWORD dwError = GetLastError();
        _xfindclose(hFind, bShowStreams);
        SetLastError(dwError);
        MapWin32ErrorToPosixErrno();
        return NULL;
    }

    if (_xfindclose(hFind, bShowStreams) == -1) {
        MapWin32ErrorToPosixErrno();
        return NULL;
    }

    //
    // Build and return DIR
    //
    pDir = xmalloc(sizeof(DIR));
    memset(pDir, 0, sizeof(pDir));
    pDir->dd_cd = cd;
    pDir->dd_next_entry = cd->cd_entry_first;
    return pDir;
}

struct dirent*
readdir(DIR* pDir)
{
    struct cache_entry *ce;
    size_t n;

    if ((ce = pDir->dd_next_entry) == NULL) { // if no more files
        return NULL;
    }

    pDir->dd_dir.d_ino = ce->ce_ino; // might be 0
    pDir->dd_dir.d_reclen = 0; // unused
    pDir->dd_dir.d_type = _MapType(ce);
    n = strlen(ce->ce_filename);
    pDir->dd_dir.d_namlen = (unsigned short)n;
    memcpy(pDir->dd_dir.d_name, ce->ce_filename, n+1);
    pDir->dd_dir.d_ce = ce;

    // Bump to next
    pDir->dd_next_entry = ce->ce_next;

    return &pDir->dd_dir;
}


int closedir(DIR* pDir)
{
    memset(pDir, 0, sizeof(*pDir));
    free(pDir);
    return 0;
}

static void _delete_dir(struct cache_dir *cd)
{
    struct cache_entry *ce, *ce2, *ce3;

    for (ce = cd->cd_entry_first; ce; ce = ce2) {
        ce2 = ce->ce_next;
again:
        if (ce->ce_filename != NULL) {
            free(ce->ce_filename); ce->ce_filename = NULL;
        }
        if (ce->ce_abspath != NULL) {
            free(ce->ce_abspath); ce->ce_abspath = NULL;
        }
        // Also free any symlinks
        if ((ce3 = ce->ce_symlink) != NULL) {
            free(ce);
            ce = ce3;
            goto again;
        }
        free(ce);
    }
    cd->cd_entry_first = cd->cd_entry_last = NULL;
    if (cd->cd_dirname != NULL) {
        free(cd->cd_dirname); cd->cd_dirname = NULL;
    }
    if (cd->cd_pat != NULL) {
        free(cd->cd_pat); cd->cd_pat = NULL;
    }
    free(cd);
    return;
}

//////////////////////////////////////////////////////////////////////

static int _xstat(const char *szPath, struct xstat *st,
    unsigned long dwType, BOOL bCache, BOOL bFollowSymlink);

static int __xstat(const char *szPath, struct xstat *st,
    unsigned long dwType, BOOL bCache, BOOL bFollowSymlink);

//
// Replacement for stat().  Called by glob.c and ls.c
//
int
xstat(const char *szPath, struct xstat *st)
{
    return _xstat(szPath, st, DT_UNKNOWN,
        TRUE/*bCache*/, TRUE/*bFollowSymlink*/);
}

//
// Ditto without caching
//
int
stat_nocache(const char *szPath, struct xstat *st, unsigned long dwType)
{
    return _xstat(szPath, st, dwType,
        FALSE/*bCache*/, TRUE/*bFollowSymlink*/);
}

//
// Replacement for lstat().  Called by glob.c and ls.c
//
int
xlstat(const char *szPath, struct xstat *st)
{
    return _xstat(szPath, st, DT_UNKNOWN,
        TRUE/*bCache*/, FALSE/*bFollowSymlink*/);
}

//
// Ditto without caching
//
int
lstat_nocache(const char *szPath, struct xstat *st, unsigned long dwType)
{
    return _xstat(szPath, st, dwType,
        FALSE/*bCache*/, FALSE/*bFollowSymlink*/);
}


static int
_xstat(const char *szPath, struct xstat *st,
    unsigned long dwType, BOOL bCache, BOOL bFollowSymlink)
{
    PVOID pOldState;
    int iResult;

    pOldState = _push_64bitfs();
    iResult = __xstat(szPath, st, dwType, bCache, bFollowSymlink);
    _pop_64bitfs(pOldState);
    return iResult;
}

static int
__xstat(const char *szPath, struct xstat *st,
    unsigned long dwType, BOOL bCache, BOOL bFollowSymlink)
{
    char szFullPath[FILENAME_MAX], szBuf[FILENAME_MAX];
    char szDirBuf[FILENAME_MAX];
    char *sz, *szDir, *szFile;
    struct cache_dir *cd;
    struct cache_entry *ce;
    long hFind;
    struct _finddatai64_t fd;
    BOOL bShowStreams = (show_streams == yes_arg);
    BOOL bFixedDisk = FALSE;

    lstrcpyn(szFullPath, szPath, FILENAME_MAX);
    //
    // Change forward slashes to backward slashes
    //
    for (sz = szFullPath; *sz; ++sz) {
        if (*sz == '/') {
            *sz = '\\';
        }
    }
    //
    // Strip trailing backslashes
    //
    for (--sz; sz > szFullPath; --sz) {
        if (*sz != '\\') {
            break;
        }
        if (sz == szFullPath+2 && szFullPath[1] == ':') {
            break; // stop if C:\ found
        }
        *sz = '\0';
    }

    //
    // No FindFile wildcards allowed at this point
    //
    if (_mbspbrk(szFullPath, "?*") != NULL) {
        errno = ENOENT;
        return -1;
    }

    //
    // Break off dir and file components
    //
    strcpy(szBuf, szFullPath);

    if ((sz = strrchr(szBuf, '\\')) == NULL) {
        if (szBuf[1] == ':') {
            if (szBuf[2] == '\0') {
                // ls C:
                szDir = szBuf; // C:
                szFile = ".";
            } else {
                // ls C:foo
                szDirBuf[0] = szBuf[0];
                szDirBuf[1] = szBuf[1];
                szDirBuf[2] = '\0';
                szDir = szDirBuf; // C:
                szFile = szBuf+2; // foo
            }
        } else {
            // ls foo
            szDir = ".";
            szFile = szBuf;
        }
    } else {
        // ls dir\foo
        szFile = sz+1;
        //
        // Strip trailing backslashes from the dir component
        //
        strcpy(szDirBuf, szBuf); // copy to avoid stomping on szFile
        szDir = szDirBuf;
        sz = szDir + (sz-szBuf);
        *(sz+1) = '\0'; // ensure termination
        for (; *sz == '\\' && sz > szDirBuf; --sz) {
            if (sz == szDirBuf+2 && szDirBuf[1] == ':') {
                break; // stop if C:\ found
            }
            *sz = '\0';
        }
    }

    if ((cd = _find_cache_dir(szDir, szFile)) != NULL) {
        //
        // Found hit from previous opendir()/readdir()
        //
        for (ce = cd->cd_entry_first; ce; ce = ce->ce_next) {
            if (ce->ce_filename[0] == szFile[0] &&
                    _mbsicmp(ce->ce_filename, szFile) == 0) {
                //
                // Found file
                //
                goto cache_hit;
            }
        }
        errno = ENOENT;  // not in cache dir
        return -1;
    }

    //
    // Get the canonical path for use in security.cpp
    //
    if (_GetAbsolutePath(szFullPath, szBuf, FILENAME_MAX, &bFixedDisk) < 0) {
        return -1;
    }

    strcpy(szFullPath, szBuf);

    //
    // Check the partial stat cache against the abs path
    //
    for (ce = _stat_first; ce; ce = ce->ce_next) {
        if (ce->ce_abspath && _mbsicmp(ce->ce_abspath, szFullPath) == 0) {
            goto cache_hit;
        }
    }

    //
    // Do not show streams if --fast on a non-fixed disk
    //
    if (run_fast && !bFixedDisk) {
        bShowStreams = FALSE;
    }

#ifdef DEBUG_FINDFIRST
more_printf("stat: findfirst on \"%s\"\n", szFullPath);
more_fflush(stdmore);
#endif

    //
    // Do a singleton FindFirst to get WIN32_FILE_DATA
    //
    if ((hFind = _xfindfirsti64(szFullPath, &fd, bShowStreams, dwType))
            != (long)INVALID_HANDLE_VALUE) {
        // Succeeded
        if (_xfindclose(hFind, bShowStreams) == -1) {
            MapWin32ErrorToPosixErrno();
            return -1;
        }
    } else {
        //
        // FindFirst failed.  This is a normal (sic) error for root folders
        // e.g., C:\ and sometimes \\server\share\...
        //
        if ((szFullPath[1] == ':' && szFullPath[2] == '\\' && szFullPath[3] == '\0') ||
                _IsServerRootPath(szFullPath)) {
            //
            // Fake an entry for the root folder
            //
            time_t t;
            memset(&fd, 0, sizeof(fd));
            t = time(0);
            fd.attrib = FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_SYSTEM;
            strcpy(fd.name, "\\");
            fd.time_access = t;
            fd.time_write = t;
            fd.time_create = t;
        } else {
            MapWin32ErrorToPosixErrno();
            return -1;
        }
    }

    ce = (struct cache_entry *)xmalloc(sizeof(*ce));
    memset(ce, 0, sizeof(*ce));

    if (bCache) {
        //
        // Put on the partial stat cache
        //
        if (_stat_first == NULL) {
            _stat_first = _stat_last = ce;
        } else {
            _stat_last->ce_next = ce;
            _stat_last = ce;
        }
    }

    if (short_names) {
        _get_short_path(szFullPath); // update in place
    }
    ce->ce_filename = (char *)xstrdup(fd.name); // last component only
    ce->ce_size = fd.size;
    ce->ce_ino = 1; // requires GetFileInformationByHandle - uintmax_t
    ce->dwFileAttributes = fd.attrib; // FILE_ATTRIBUTE_NORMAL maps to 0
    ce->ce_atime = fd.time_access;
    ce->ce_mtime = fd.time_write;
    ce->ce_ctime = fd.time_create;
    ce->nNumberOfLinks = 1;
    if (bFixedDisk) {
        ce->dwFileAttributes |= FILE_ATTRIBUTE_FIXED_DISK;
    }

    //
    // Squirrel away the canonical path
    //
    ce->ce_abspath = xstrdup(szFullPath);

    // Flag reparse points and .LNK shortcuts as symbolic links
    if ((ce->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            _mbsicmp(right(fd.name, 4), ".lnk") == 0) {
        ce->ce_bIsSymlink = TRUE;
    }

    if (phys_size) {
        ce->ce_size = _get_phys_size(szFullPath, ce->ce_size);
    }
    if (!run_fast || bFixedDisk || print_inode) {
        //
        // Get inode and hardlink info
        //
        _get_full_file_info(szFullPath, ce);
    }

cache_hit:
    if (bFollowSymlink) {
        ce = _follow_symlink(ce);
    }
    memset(st, 0, sizeof(*st));
    st->st_ino = ce->ce_ino;
    st->st_size = ce->ce_size;
    st->st_atime = ce->ce_atime;
    st->st_mtime = ce->ce_mtime;
    st->st_ctime = ce->ce_ctime;
    st->st_nlink = (short)ce->nNumberOfLinks;
    st->st_mode = _MapMode(ce);
    st->st_ce = ce;

    return 0;
}

//////////////////////////////////////////////////

//
// Wrapper for readlink()
//
// Read the target path of the symbolic link
//
// Called by ls.c
//
int _xreadlink(struct stat *pst, char *szBuf, int iBufLen)
{
    struct cache_entry *ce;
    char *sz;

    ce = pst->st_ce;
    if (ce == NULL) { // should never happen
        errno = ENOENT;
        return -1;
    }

    if (!gbReg && !ce->ce_bIsSymlink) {
        errno = EINVAL; // not a symbolic link
        return -1;
    }

    _follow_symlink(ce); // trigger reading the symlink if not already

    if (ce->ce_symlink == NULL) {
        errno = EXDEV; // "Improper link"
        return -1;
    }

    ce = ce->ce_symlink;

    if (ce->ce_filename == NULL || ce->ce_filename[0] == '\0') {
        // cannot figure out symlink name..
        errno = EXDEV; // "Improper link"
        return -1;
    }

    lstrcpyn(szBuf, ce->ce_filename, iBufLen);

    //
    // Convert to forward slashes
    //
    for (sz = szBuf; *sz; ++sz) {
        if (*sz == '\\') {
            *sz = '/';
        }
    }

    return strlen(szBuf);
}

//////////////////////////////////////////////////

//
// Return the symlink if followable, otherwise return the current
// node again
//
static struct cache_entry *
_follow_symlink(struct cache_entry *ce)
{
    char *sz, *szFullPath;
    char szPath[FILENAME_MAX+10];
    struct cache_entry *symce;
    long hFind;
    struct _finddatai64_t fd;
    BOOL bFixedDisk = FALSE;

    if (!gbReg && !ce->ce_bIsSymlink) {
        // not a symlink
        return ce;
    }

    if (ce->ce_symlink != NULL) {
        return ce->ce_symlink; // return whatever we got earlier
    }

    if (ce->ce_bBadSymlink) {
        //
        // Already tried and failed
        //
        return ce;
    }

    ce->ce_bBadSymlink = TRUE; // provisionally mark as bad

    if (ce->ce_abspath == NULL) { // if earlier _ExpandPath failed
        return ce; // bail
    }

    if (gbReg) {
        if ((sz = _GetRegistryLink(ce, szPath)) == NULL) {
            return ce; // bail
        }
    } else if ((ce->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        //
        // Query the reparse point
        //
        if ((sz = _GetReparseTarget(ce, szPath)) == NULL) {
            return ce; // bail
        }
    } else {
        //
        // Query the .LNK shortcut
        //
        if ((sz = _GetShortcutTarget(ce, szPath)) == NULL) {
            return ce; // bail
        }
    }

    if (!gbReg && short_names) {
        _get_short_path(sz); // update in place
    }

    //
    // Build the symbolic link cache_entry
    //
    symce = (struct cache_entry *)xmalloc(sizeof(*symce));
    memset(symce, 0, sizeof(*symce));
    //
    // Store relative path for later readlink() (not just last component)
    //
    symce->ce_filename = (char *)xstrdup(sz);
    ce->ce_symlink = symce; // point to symlink
    ce->ce_bIsSymlink = TRUE;
    symce->ce_ino = 1; // requires GetFileInformationByHandle - uintmax_t
    symce->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY; // we know this..
    symce->nNumberOfLinks = 1;

    //
    // Errors after this point are not very important.  At worst
    // we might lose st_mode, st_size and st_time info.
    //

    ce->ce_bBadSymlink = FALSE; // link is ok


    //
    // Get the absolute path
    //
    if (_GetAbsolutePath(symce->ce_filename, szPath, FILENAME_MAX, &bFixedDisk) < 0) {
        return symce; // bail
    }

    //
    // Squirrel away the absolute path for security.cpp
    //

    symce->ce_abspath = xstrdup(szPath);

    if (gbReg) {
        return symce; // done
    }

    szFullPath = szPath;

#ifdef DEBUG_FINDFIRST
more_printf("_follow_symlink: findfirst on \"%s\"\n", szFullPath);
more_fflush(stdmore);
#endif

    //
    // Do a singleton FindFirst to get WIN32_FILE_DATA
    //
    if ((hFind = _xfindfirsti64(szFullPath, &fd,
            FALSE/*bShowStreams*/, DT_UNKNOWN)) != (long)INVALID_HANDLE_VALUE) {
        // Suceeded
        if (_xfindclose(hFind, FALSE/*bShowStreams*/) == -1) {
            MapWin32ErrorToPosixErrno();
            return symce; // bail
        }
    } else {
        //
        // FindFirst failed.  This is a normal error (sic) for root folders
        // e.g., C:\ and sometimes \\server\share\...
        //
        if ((szFullPath[1] == ':' && szFullPath[2] == '\\' && szFullPath[3] == '\0') ||
                _IsServerRootPath(szFullPath)) {
            //
            // Fake an entry for the root folder
            //
            time_t t;
            memset(&fd, 0, sizeof(fd));
            t = time(0);
            fd.attrib = FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_SYSTEM;
            strcpy(fd.name, "\\");
            fd.time_access = t;
            fd.time_write = t;
            fd.time_create = t;
        } else {
            MapWin32ErrorToPosixErrno();
            return symce;
        }
    }

    //
    // Fill in more data for the symlink target
    //
    symce->ce_size = fd.size;
    symce->dwFileAttributes = fd.attrib; // FILE_ATTRIBUTE_NORMAL maps to 0
    symce->ce_atime = fd.time_access;
    symce->ce_mtime = fd.time_write;
    symce->ce_ctime = fd.time_create;

    if (bFixedDisk) {
        symce->dwFileAttributes |= FILE_ATTRIBUTE_FIXED_DISK;
    }

    // Flag reparse points and .LNK shortcuts as symbolic links
    if ((symce->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            _mbsicmp(right(fd.name, 4), ".lnk") == 0) {
        symce->ce_bIsSymlink = TRUE; // symlink pointing to a symlink (rare)
    }

    if (phys_size) {
        symce->ce_size = _get_phys_size(szFullPath, symce->ce_size);
    }

    //
    // Tah dah!
    //
    ce->ce_bBadSymlink = FALSE;

    return symce;
}


//
// Get exhaustive info on the file.  Slow on network disks (avoid).
//
// Requires full canonical path (for UNC)
//
static int
_get_full_file_info(char *szFullPath, struct cache_entry *ce)
{
    HANDLE hFile;
    BY_HANDLE_FILE_INFORMATION bhfi;

    if (ce->ce_bGotFullInfo) {
        return 0;
    }

    ce->ce_bGotFullInfo = TRUE;

    if (gbReg) { // registry keys have no additional info
        return 0;
    }

    //
    // Open file with 0 access rights.
    //
    // FILE_FLAG_BACKUP_SEMANTICS is required to open directories
    // (not supported on Win9x)
    //
    if ((hFile = CreateFile(szFullPath,
            /*STANDARD_RIGHTS_READ | SYNCHRONIZE*/0,
            0, 0, OPEN_EXISTING,
            ((ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ?
                FILE_FLAG_BACKUP_SEMANTICS : 0),
            0)) == INVALID_HANDLE_VALUE)  {
#ifdef DEBUG_FINDFIRST
more_printf("_get_full_file_info: CreateFile(%s) failed\n", szFullPath);
more_fflush(stdmore);
#endif
        MapWin32ErrorToPosixErrno();
        return -1;
    }

    memset(&bhfi, 0, sizeof(bhfi));

    if (!GetFileInformationByHandle(hFile, &bhfi)) {
        MapWin32ErrorToPosixErrno();
        CloseHandle(hFile);
        return -1;
    }

    CloseHandle(hFile);

    ce->dwVolumeSerialNumber = bhfi.dwVolumeSerialNumber;
    ce->nNumberOfLinks = bhfi.nNumberOfLinks;
    ce->ce_ino = _to_unsigned_int64(bhfi.nFileIndexLow, bhfi.nFileIndexHigh);

    return 0;
}

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

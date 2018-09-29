//////////////////////////////////////////////////////////////////////////
//
// Query for embedded file streams:  "foo.txt:mystream:$Type"
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

//
// Streams are a barely documented feature to create information forks within
// files.  They are like the 'data fork' and 'resource fork' on the Macintosh.
//
// To create a stream, simply append ':foo' to the file name.
//
// Example:  ECHO "sooper seekret hidden data" > foo:secret1
//
// The secret data does not show up in the file size.  It is
// completely hidden unless you know the name of the stream.
//
// You can view the secret data with  MORE < foo:secret1
//
// Streams with suffixes other than ":$DATA" apparently can be created
// with undocumented APIs.
//
// I made file streams very visible in this program so they
// aren't 'sooper seekret' anymore.  Streams are always checked on local
// disks.  They are also checked on network folders if --slow is added.
// (Because enumerating streams is slow over a network.)
//
// Files that contain streams are flagged with a distinctive color
// and type symbol ($).  $ was chosen because the dollar sign is
// already used to indicate secret file shares (e.g., C$), and because
// the stream type suffix (":$DATA") has a dollar sign.
//
// My approach is to make a stream look like a regular file that just happens
// to have ":" appended to its name.  Thus 'ls foo:*' works as expected.
//
// Streams are probably an attempt to create a "Structured File System"
// analogous to OLE Structured Storage, using the kernel filesystem
// driver instead of OLE32.DLL.  This was part of the long
// delayed (and now abandoned) "Cairo" project, to create an Object Oriented
// file system for Windows.
//
// Streams are a Very Bad Thing, IMHO.  It breaks the simple relationship
// of file = array of bytes.  Streams cannot be copied or backed
// without special handling.  And they are a hiding places for malware
// or viruses.
//
// Support within Windows for streams is incomplete at best.  For example
// 'TYPE foo:secret1' does not work.
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
#include <string.h>
#include <wchar.h>
#include <mbstring.h>

#include <errno.h>

#define NEED_DIRENT_H
#include "windows-support.h"
#include "xalloc.h"
#include "xmbrtowc.h" // for get_codepage()
#include "more.h"
#include "Registry.h"
#include "FindFiles.h"
#include "ls.h"

#undef strrchr
#define strrchr _mbsrchr // use the multibyte version of strrchr - AEK

#pragma warning(disable: 4057) // ignore unsigned char* vs char*

extern int phys_size;

#define FILE_INFORMATION_CLASS int
#define FileStreamInformation 22  // FILE_INFORMATION_CLASS

typedef struct {
    NTSTATUS Status;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

//
// Stream IOCTL buffer
//
typedef struct { // Information Class 22
    ULONG NextEntryOffset;
    ULONG StreamNameLength;
    LARGE_INTEGER EndOfStream;
    LARGE_INTEGER AllocationSize;
    WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;


///////////////////////////////////////////////////////////////////////////
#ifdef QUERY_EXTENDED_ATTRIBUTES // EA's are obsolete OS/2 cruft
//
// Extended Attributes (EA)
//

//
// Extended Attributes are a vestige of OS/2.  Used only
// on FAT16 and HFS.  Not supported on FAT32.
//
// Not supported on NTFS (not officially anyway).
//
// Extended Attributes are part of the OS/2 subsystem and HFS.
// The OS/2 subsystem was dropped from XP.
//

//
// Query to see if the file has any EA bytes at all
// Retval of 0 means dont bother with FileFullEaInformation
//
typedef struct { // Information Class 7
    ULONG EaInformationLength;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

#define FileEaInformation 7


//
// Get pairs of EA name=value pairs.
//
typedef struct { // Information Class 15
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1]; // *not* Unicode
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

#define FileFullEaInformation 15 // FILE_INFORMATION_CLASS

#endif // QUERY_EXTENDED_ATTRIBUTES
///////////////////////////////////////////////////////////////////////////


// NtQueryInformationFile
typedef NTSTATUS (WINAPI *PFNNTQUERYINFORMATIONFILE)(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
);
static PFNNTQUERYINFORMATIONFILE pfnNtQueryInformationFile;

#ifdef UNDEFINED
// NtSetInformationFile
typedef NTSTATUS (WINAPI *PFNNTSETINFORMATIONFILE)(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
);
static PFNNTSETINFORMATIONFILE pfnNtSetInformationFile;
#endif


// RtlNtStatusToDosError
typedef ULONG (WINAPI *PFNRTLNTSTATUSTODOSERROR)(
    NTSTATUS Status
);
static PFNRTLNTSTATUSTODOSERROR pfnRtlNtStatusToDosError;

/////////////////////////////////////////////////////////////////////////
//
// Map NTSTATUS code to Win32 error code
//
DWORD
MapNtStatusToWin32Error(NTSTATUS Status)
{
    DWORD dwError = ERROR_INVALID_PARAMETER; // default

    if (DynaLoad("NTDLL.DLL","RtlNtStatusToDosError", &pfnRtlNtStatusToDosError)) {
        // returns ERROR_MR_MID_NOT_FOUND if cannot map to Win32 error code
        dwError = (*pfnRtlNtStatusToDosError)(Status);
    }
    SetLastError(dwError);
    return dwError;
}

/////////////////////////////////////////////////////////////////////////

struct stream_info {
    char *si_szName;
    __int64 si_size;
    __int64 si_phys_size;
    struct stream_info *si_next;
};

struct find_stream {
    long fs_handle; // original FindFirst handle
    char *fs_szStrippedPath;
    struct _finddatai64_t fs_fd; // main file's fd
    char *fs_szStreamPat; // pattern to match
    struct stream_info *fs_list_stream_info; // list head
    struct stream_info *fs_next_stream_info; // next in list to return
    BOOL fs_bFailed;
    BOOL fs_bEof;
};

#define FAIL ((long)INVALID_HANDLE_VALUE)

static BOOL
_LookupStream(BOOL bFirst,
    struct find_stream *fs, char *szStreamPat, struct _finddatai64_t *pfd);


static LPCSTR aszPrivs[] = {"SeBackupPrivilege"};

//
//
// Wrapper around _aefindfirsti64() to report streams
//
// Note: This implementation requires abs paths (always do _ExpandPath first)
//
long _xfindfirsti64(const char *szPath, struct _finddatai64_t *pfd,
    BOOL bShowStreams, DWORD dwType)
{
    char szStrippedPathBuf[FILENAME_MAX];
    const char *szStrippedPath;
    char *szStreamPat;
    char *sz;
    long handle;
    struct find_stream *fs;
    static BOOL bSetPriv;

    if (gbReg) {
        return _RegFindFirst(szPath, pfd, dwType);
    }

    if (!bShowStreams) {
        return _aefindfirsti64(szPath, pfd);
    }

    //
    // Split into szStrippedPath, szStreamPat
    //
    if (szPath[0] == '\0' || szPath[1] == '\0' || (sz = _mbschr(szPath+2, ':')) == NULL) {
        szStrippedPath = szPath;
        szStreamPat = NULL;
    } else {
        szStreamPat = sz; // ":mystream"
        lstrcpyn(szStrippedPathBuf, szPath, FILENAME_MAX);
        szStrippedPathBuf[szStreamPat-szPath] = '\0'; // chop stream
        szStrippedPath = szStrippedPathBuf;
    }

    //
    // Query the file propper via the stripped path
    //
    if ((handle = _aefindfirsti64(szStrippedPath, pfd)) == FAIL) {
        return FAIL;
    }

    fs = (struct find_stream*)xmalloc(sizeof(*fs));
    memset(fs, 0, sizeof(*fs));
    fs->fs_handle = handle;
    fs->fs_szStrippedPath = xstrdup(szStrippedPath);
    fs->fs_szStreamPat = szStreamPat ? xstrdup(szStreamPat) : NULL;

    if (!bSetPriv) {
        bSetPriv = TRUE;
#ifdef UNDEFINED // not needed
        //
        // Enable SeBackupPrivilege
        //
        _SetPrivileges(1, aszPrivs, TRUE); // ignore errors
#endif
    }

    if (!_LookupStream(TRUE/*bFirst*/, fs, szStreamPat/*to match*/, pfd)) {
        _xfindclose((long)fs, bShowStreams); // free and close
        return FAIL; // bail
    }

    return (long)fs;
}



//
// Wrapper around _aefindnexti64() to report streams
//
int _xfindnexti64(long handle, struct _finddatai64_t *pfd,
    BOOL bShowStreams)
{
    struct find_stream *fs;

    if (gbReg) {
        return _RegFindNext(handle, pfd);
    }

    if (!bShowStreams) {
        return _aefindnexti64(handle, pfd);
    }

    if (handle == FAIL) { // prev failure
        SetLastError(ERROR_INVALID_PARAMETER);
        return FAIL;
    }

    fs = (struct find_stream *)handle;
    handle = fs->fs_handle;

    if (fs->fs_bEof) { // normal exit
        SetLastError(ERROR_NO_MORE_FILES);
        return FAIL;
    }

    if (fs->fs_bFailed) { // if prev failure
        SetLastError(ERROR_INVALID_PARAMETER);
        return FAIL;
    }

    if (!_LookupStream(FALSE/*bFirst*/, fs, fs->fs_szStreamPat, pfd)) {
        fs->fs_bFailed = TRUE;
        return -1;
    }
    return 0;
}


//
// Wrapper around _findclose()
//
int _xfindclose(long handle, BOOL bShowStreams)
{
    struct find_stream *fs;
    struct stream_info *si;

    if (gbReg) {
        return _RegFindClose(handle);
    }

    if (!bShowStreams) {
        return _findclose(handle);
    }

    if (handle == FAIL) { // prev failure
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    fs = (struct find_stream *)handle;
    handle = fs->fs_handle;

    //
    // Free everything
    //
    if (fs->fs_szStrippedPath) {
        free(fs->fs_szStrippedPath);
    }
    if (fs->fs_szStreamPat) {
        free(fs->fs_szStreamPat);
    }
    //
    // Free stream_info list
    //
    while ((si = fs->fs_list_stream_info) != NULL) {
        fs->fs_list_stream_info = si->si_next;
        if (si->si_szName) {
            free(si->si_szName);
        }
        memset(si, 0, sizeof(*si)); // scrub
        free(si);
    }
    memset(fs, 0, sizeof(*fs)); // scrub
    free(fs);

    return _findclose(handle);
}

////////////////////////////////////////////////////////////////////

#ifdef QUERY_EXTENDED_ATTRIBUTES
#define EA_BUFSIZE 4096
static BYTE abEaInfo[EA_BUFSIZE];
#endif

#define STREAM_BUFSIZE 16384
static BYTE abStreamInfo[STREAM_BUFSIZE];

//
// We do the actual digging into NTFS here
//
static BOOL
_LookupStream(BOOL bFirst,
    struct find_stream *fs,
    char *szStreamMatch,
    struct _finddatai64_t *pfd)
{
    char szBuf[FILENAME_MAX*2];
    char *sz;
    HANDLE hFile;
#ifdef QUERY_EXTENDED_ATTRIBUTES
    PFILE_EA_INFORMATION pEaInfo = (PFILE_EA_INFORMATION) abEaInfo;
    //PFILE_FULL_EA_INFORMATION pFullEaInfo = (PFILE_FULL_EA_INFORMATION) abEaInfo;
#endif
    PFILE_STREAM_INFORMATION pStreamInfo = (PFILE_STREAM_INFORMATION) abStreamInfo;
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    struct stream_info *si, **psiPrev;

    if (fs->fs_next_stream_info != NULL) {
        goto next_si_entry;
    }

next_fs_entry:

    if (!bFirst) { // if _xfindnexti64()
        //
        // Get next file in list
        //
        if (_aefindnexti64(fs->fs_handle, pfd) < 0) {
            if (GetLastError() == ERROR_NO_MORE_FILES) {
                fs->fs_bEof = TRUE;
            }
            return FALSE; // splat
        }
    }

    //
    // pfd is loaded with real file data at this point
    //

    fs->fs_fd = *pfd; // get main file info - struct copy

    if ((pfd->attrib & (FILE_ATTRIBUTE_DEVICE|FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        return TRUE; // no streams for devices or reparse-points
    }

    if (!DynaLoad("NTDLL.DLL", "NtQueryInformationFile", &pfnNtQueryInformationFile)) {
        goto done;
    }

#ifdef UNDEFINED
    if (!DynaLoad("NTDLL.DLL", "NtSetInformationFile", &pfnNtSetInformationFile)) {
        goto done;
    }
#endif

    //
    // Build path from fs->fs_szStrippedPath minus rightmost chunk
    // + '\\' + pfd->name
    //
    lstrcpyn(szBuf, fs->fs_szStrippedPath, FILENAME_MAX);
    if ((sz = strrchr(szBuf, '\\')) == NULL) {
        lstrcpyn(szBuf, pfd->name, FILENAME_MAX); // should never happen
    } else {
        lstrcpyn(sz+1, pfd->name, FILENAME_MAX);
    }

    //
    // Open the file with Backup semantics.
    //
    // UNDOCUMENTED: CreateFile does *not* require the
    // SeBackupPrivilege if the mode flags are 0!
    //
    // In all other cases FILE_FLAG_BACKUP_SEMANTICS requires
    // the SeBackupPrivilege.
    //
    if ((hFile = CreateFile(szBuf,
                0, // required - undocumented
                FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, 0)) == INVALID_HANDLE_VALUE) {
        goto done;
    }

#ifdef QUERY_EXTENDED_ATTRIBUTES
    //
    // First query for Extended Attributes
    //
    Status = (*pfnNtQueryInformationFile)(hFile, &IoStatus, pEaInfo,
        EA_BUFSIZE, FileEaInformation/*7*/);

    if (NT_SUCCESS(Status) && pEaInfo->EaInformationLength != 0) {
        //
        // File has Extended Attributes
        //
        fd.Attribs |= FILE_ATTRIBUTE_EA;
    }
#endif

    //
    // Now query for streams
    //
    Status = (*pfnNtQueryInformationFile)(hFile, &IoStatus, pStreamInfo,
        STREAM_BUFSIZE, FileStreamInformation/*22*/);

    if (!NT_SUCCESS(Status)) {
        CloseHandle(hFile);
        MapNtStatusToWin32Error(Status);
        goto done;
    }

    if (IoStatus.Information == 0) { // pending??
        CloseHandle(hFile);
        SetLastError(ERROR_IO_PENDING); // should never happen
        goto done;
    }

    CloseHandle(hFile);

    //
    // BUG: We cannot enumerate streams for "." because it looks too
    // much like a drive letter (".:foo").
    //
    // It triggers bugs in FILESYSTEM_PREFIX_LEN, glob.c, basename.c,
    // and many other places that check for szPath[1] == ':'.
    //
    if (strcmp(pfd->name, ".") == 0) {
        //
        // Indicate that dot has streams
        //
        pfd->attrib |= FILE_ATTRIBUTE_STREAMS;
        //
        // But do not enumerate them
        //
        goto done;
    }

    psiPrev = &fs->fs_list_stream_info;
    *psiPrev = NULL;

    for (;;) {
        char szPath[FILENAME_MAX];

        memset(szPath, 0, FILENAME_MAX); // required!

        //
        // Convert from wchar_t to multibyte string
        //
        if (!WideCharToMultiByte(get_codepage(), 0,
                pStreamInfo->StreamName,
                pStreamInfo->StreamNameLength / sizeof(WCHAR),
                szPath, FILENAME_MAX, NULL, NULL)) {
            break; // rare, ignore
        }

        if (stricmp(szPath, "::$DATA") != 0) { // skip default data stream
            //
            // Create a new stream_info obj
            //
            si = (struct stream_info *)xmalloc(sizeof(*si));
            memset(si, 0, sizeof(*si));
            si->si_szName = xstrdup(szPath);
            si->si_size = pStreamInfo->EndOfStream.QuadPart;
            si->si_phys_size = pStreamInfo->AllocationSize.QuadPart;

            // append to list
            *psiPrev = si; psiPrev = &si->si_next;
        }

        //
        // Bump to next FILE_STREAM_INFORMATION struct
        //
        if (pStreamInfo->NextEntryOffset == 0) { // end of chain
            *psiPrev = NULL;
            break;
        }
        pStreamInfo = (PFILE_STREAM_INFORMATION)
            (((char *)pStreamInfo) + pStreamInfo->NextEntryOffset);
    }

    // rewind to start
    fs->fs_next_stream_info = fs->fs_list_stream_info;

    if (fs->fs_list_stream_info != NULL) {
        //
        // Mark the file as having streams
        //
        pfd->attrib |= FILE_ATTRIBUTE_STREAMS;
        fs->fs_fd.attrib |= FILE_ATTRIBUTE_STREAMS; // mark children too
    }

    if (szStreamMatch == NULL) { // if want main file info
        return TRUE; // return of main file info
    }

    // fall through and return a matching stream

next_si_entry:

    if (fs->fs_next_stream_info == NULL) {
        goto next_fs_entry;
    }

    // pop next si entry
    si = fs->fs_next_stream_info;
    fs->fs_next_stream_info = si->si_next;

    *pfd = fs->fs_fd; // get main file info - struct copy

    //
    // Turn off the directory attribute - a stream is not a directory
    // (although a directory can have streams)
    //
    pfd->attrib &= ~FILE_ATTRIBUTE_DIRECTORY;

    //
    // See if stream does not match pattern
    //
    // Only match on direct match or '*'
    //
    if (szStreamMatch != NULL &&
        ((szStreamMatch[0] != ':' || szStreamMatch[1] != '*' || szStreamMatch[2] != '\0') &&
            _mbsicmp(szStreamMatch, si->si_szName) != 0)) {
        // stream does not match pattern
        goto next_si_entry;
    }

    if (strlen(pfd->name) + strlen(si->si_szName) + 1 > sizeof(pfd->name)) {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        goto done;
    }

    strcat(pfd->name, si->si_szName); // concat ":stream"

    if (phys_size) {
        pfd->size = si->si_phys_size;
    } else {
        pfd->size = si->si_size;
    }

done:
    return TRUE; // return of stream info (or main file info)
}


/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

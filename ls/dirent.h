//////////////////////////////////////////////////////////////////////////
//
// opendir/readdir/stat translation layer for WIN32
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

//
// Use caching to reduce number of round-trips to the file system.
// This is especially important for network folders.
//

#ifndef _XDIRENT_H_
#define _XDIRENT_H_

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

#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>  // for _finddatai64_t

#ifdef __cplusplus
extern "C" {
#endif

//
// Caches queries for speedup, esp on network folders.
//

//
// Dir cache
//
struct cache_dir {
    struct cache_dir *cd_next;
    struct cache_entry *cd_entry_first;
    struct cache_entry *cd_entry_last;
    char *cd_dirname;
    char *cd_pat;
};

//
// Entry cache
//
struct cache_entry {
    struct cache_entry *ce_next;
    char *ce_filename;
    uintmax_t ce_size;
    uintmax_t ce_ino; // dirent->d_ino  inode #
    ///////////////////////////////////////////////////
    //
    // FindFirstFile/FindNextFile WIN32_FIND_DATA
    //
    DWORD dwFileAttributes;
    //FILETIME ftCreationTime;
    //FILETIME ftLastAccessTime;
    //FILETIME ftLastWriteTime;
    time_t ce_atime;
    time_t ce_mtime;
    time_t ce_ctime;
    DWORD dwReserved0; // reparse tag from FindFileFirst - not in findfirst
    DWORD dwReserved1; // ??? from FindFileFirst - not in findfirst

    // Requires real Win32 FindFirst
    CHAR cAlternateFileName[14]; // not in findfirst

    BOOL ce_bGotFullInfo; // did GetFileInformationByHandle()
    BOOL ce_bIsSymlink; // Reparse point or .LNK file

    // These require extra query with GetFileInformationByHandle
    DWORD dwVolumeSerialNumber;
    DWORD nNumberOfLinks;
    //DWORD nFileIndexHigh; // map to ce_ino
    //DWORD nFileIndexLow;

    ////////////////////////
    //
    // Child for target of symlink (if we are a reparse point)
    //
    char *ce_abspath; // our full path
    struct cache_entry *ce_symlink;
    BOOL ce_bBadSymlink; // TRUE if already tried to follow symlink & failed

    ////////////////////////
    //
    // Registry info
    //
    DWORD ce_dwRegType; // REG_SZ, etc
};

#define REG_KEY 255  // synthetic type to mark a registry key

//////////////////////////////////////////////////////////////////


struct dirent
{
    uintmax_t       d_ino;      // note size!
    unsigned short  d_reclen;   // Always zero. */
    unsigned short  d_namlen;   // Length of name in d_name.
    unsigned long   d_type;     // DT_xxx type
    char            d_name[FILENAME_MAX];   // 260 chars max
    ///////////////////////////
    // Extra info (cached)
    struct cache_entry *d_ce;
};

/*
 * This is an internal data structure. Good programmers will not use it
 * except as an argument to one of the functions below.
 * dd_stat field is now int (was short in older versions).
 */
typedef struct
{
    /* disk transfer area for this dir */
    //struct _finddata_t    dd_dta;
    struct cache_dir *dd_cd;  // cache dir
    struct cache_entry *dd_next_entry; // next cache entry

    /* dirent struct to return from dir (NOTE: this makes this thread
     * safe as long as only one thread uses a particular DIR struct at
     * a time) */
    struct dirent dd_dir;

} DIR;

PVOID _push_64bitfs();
void _pop_64bitfs(PVOID pOldState);

DIR* __cdecl opendir (const char*);
// Variant of opendir that includes the wildcard pattern - for speedup (AEK)
DIR* __cdecl opendir_with_pat (const char*, const char*, BOOL bCache);
struct dirent* __cdecl readdir (DIR*);
int __cdecl closedir (DIR*);
void __cdecl rewinddir (DIR*);
long __cdecl telldir (DIR*);
void __cdecl seekdir (DIR*, long);


////////////////////////////////////////////////////////////////////////
//
// xstat - stat with caching of Win32 info
//

#undef S_IFMT
#define S_IFMT   00770000  // need extra bits in mask for symlink - AEK
//      S_IFMT   00170000  // file type mask (real stat.h)
//      S_IFDIR  00040000  // directory
//      S_IFCHR  00020000  // character special
//      S_IFIFO  00010000  // pipe
//      S_IFREG  00100000  // regular file
#define S_IFLNK  00400000  // file is a reparse point (aka symbolic link)
#define S_RECENT 01000000  // file was changed recently
#define S_COMPR  02000000  // file is compressed
#define S_STREAM 04000000  // file has streams

#define S_ISSTREAM(mode) (mode & S_STREAM)

#ifndef FILE_ATTRIBUTE_DEVICE // BUG: Missing from VS6 winnt.h
# define FILE_ATTRIBUTE_DEVICE    0x00000040 // File is a device object
#endif

#undef FILE_ATTRIBUTE_ENCRYPTED
#define FILE_ATTRIBUTE_ENCRYPTED  0x00004000 // BUG: VS6 winnt.h uses 0x40

#ifndef FILE_ATTRIBUTE_EA
# define FILE_ATTRIBUTE_EA        0x00040000 // extended attributes are present
#endif

#define FILE_ATTRIBUTE_FIXED_DISK 0x01000000 // pseudo-attrib for fixed disk
#define FILE_ATTRIBUTE_STREAMS    0x02000000 // pseudo-attrib for file w/streams


#define DTTOIF(d) (1 << ((d)+11))  // Convert DT_xxx to S_IFMT file-type mask

#define DT_UNKNOWN 0
#define DT_FIFO 1 // unused
#define DT_CHR 2
#define DT_BLK DT_CHR // same as DT_CHR
#define DT_DIR 3
#define DT_REG 4
#define DT_SOCK 5 // unused
#define DT_LNK 6


struct xstat {
    _dev_t st_dev;
    uintmax_t st_ino; // note size!
    unsigned long st_mode;
    short st_nlink;
    short st_uid; // unused
    short st_gid; // unused
    _dev_t st_rdev; // unused
    uintmax_t st_size; // note size!
    time_t st_atime;
    time_t st_mtime;
    time_t st_ctime;
    ///////////////////////////
    // Extra info (cached)
    struct cache_entry *st_ce; // might be null
};

//
// Return the target of the reparse-point
//
extern int xstat(const char *, struct xstat *);
extern int stat_nocache(const char*, struct xstat *, unsigned long);

//
// Always return the current object (regardless of whether
// it is a reparse point or not)
//
extern int xlstat(const char *, struct xstat *);
extern int lstat_nocache(const char*, struct xstat *, unsigned long);

//
// Read the target of the symbolic link
//
extern int _xreadlink(struct xstat *, char *, int);

#undef stat
#define stat xstat

#undef lstat
#define lstat xlstat

void PreFilterPath(char* szPath/*inout*/);

//
// Map and assign the Win32 GetLastError() return value to POSIX errno
//
void
MapWin32ErrorToPosixErrno();

/////////////////////////////////////////////////////////////////////////
//
// Security API
//

//
// Translate the owner SID
//
extern char *xgetuser(struct cache_entry *ce, int bGroup);

extern void print_encrypted_file(struct cache_entry *ce);
extern void print_objectid(struct cache_entry *ce);
extern void print_long_acl(struct cache_entry *ce);
extern BOOL view_file_security(struct cache_entry *ce);
extern void win32_mode_string(struct stat *st, char *szMode);

extern BOOL _GetRegSecurity(LPCSTR szPath, struct cache_entry *ce,
    DWORD dwFlags, PSECURITY_DESCRIPTOR psd, DWORD dwSdLen,
    PDWORD pdwNeededSdLen);
extern BOOL print_registry_value(struct cache_entry* ce);

extern int DumpToken();
extern BOOL VirtualView();

//
// COM support
//
extern BOOL gbComInitialized;

#ifdef  __cplusplus
}
#endif

#endif  /* Not _XDIRENT_H_ */

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

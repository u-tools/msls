/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define if you have the Andrew File System. */
/* #undef AFS */

/* Define to the function xargmatch calls on failures. */
#define ARGMATCH_DIE usage (1)

/* Define to the declaration of the xargmatch failure function. */
#define ARGMATCH_DIE_DECL extern void usage ()

/* Define if the `closedir' function returns void instead of `int'. */
/* #undef CLOSEDIR_VOID */

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Define if using `alloca.c'. */
/* #undef C_ALLOCA */

/* Define if using `getloadavg.c'. */
#define C_GETLOADAVG 1

/* Define for DGUX with <sys/dg_sys_info.h>. */
/* #undef DGUX */

/* Define if there is a member named d_ino in the struct describing directory
   headers. */
#define D_INO_IN_DIRENT 1

/* Define if there is a member named d_type in the struct describing directory
   headers. */
#define D_TYPE_IN_DIRENT 1
#define _DIRENT_HAVE_D_TYPE 1

// Define _CRTIMP (used for __mb_cur_max to avoid incompatible redefinition) // RIVY
// from ctype.h
#ifndef _CRTIMP
#ifdef  _DLL
#define _CRTIMP __declspec(dllimport)
#else   /* ndef _DLL */
#define _CRTIMP
#endif  /* _DLL */
#endif  /* _CRTIMP */

#ifdef WIN32
# undef MB_CUR_MAX
# define MB_CUR_MAX __mb_cur_max // AEK fix MSSDK05 ctype.h 32-bit MSVCRT.DLL
_CRTIMP extern int __mb_cur_max; // AEK
# undef __PCTYPE_FUNC
# define __PCTYPE_FUNC _pctype  // AEK fix MSSDK05 ctype.h 32-bit MSVCRT.DLL
#endif

/* Define to 1 if NLS is requested. */
// #define ENABLE_NLS 1 // AEK

/* Define on systems for which file names may have a so-called `drive letter'
   prefix, define this to compute the length of that prefix, including the
   colon. */
//#define FILESYSTEM_ACCEPTS_DRIVE_LETTER_PREFIX 0
#define FILESYSTEM_ACCEPTS_DRIVE_LETTER_PREFIX 2 // AEK

/* Define if the backslash character may also serve as a file name component
   separator. */
//#define FILESYSTEM_BACKSLASH_IS_FILE_NAME_SEPARATOR 0
#define FILESYSTEM_BACKSLASH_IS_FILE_NAME_SEPARATOR 1 // AEK

#if FILESYSTEM_ACCEPTS_DRIVE_LETTER_PREFIX
# define FILESYSTEM_PREFIX_LEN(Filename) \
  ((Filename)[0] && (Filename)[1] == ':' ? 2 : 0)
#else
# define FILESYSTEM_PREFIX_LEN(Filename) 0
#endif

/* Define to the type of elements in the array set by `getgroups'. Usually
   this is either `int' or `gid_t'. */
#define GETGROUPS_T int

/* Define if the `getloadavg' function needs to be run setuid or setgid. */
/* #undef GETLOADAVG_PRIVILEGED */

/* The concatenation of the strings `GNU ', and PACKAGE. */
#define GNU_PACKAGE "GNU fileutils"

/* Define if TIOCGWINSZ requires sys/ioctl.h */
/* #undef GWINSZ_IN_SYS_IOCTL */

/* Define if you have the `acl' function. */
/* #undef HAVE_ACL */

/* Define if you have the `alarm' function. */
/* #undef HAVE_ALARM */

/* Define if you have `alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define if you have <alloca.h> and it should be used (not on Ultrix). */
/* #undef HAVE_ALLOCA_H */

/* Define if you have the <argz.h> header file. */
/* #undef HAVE_ARGZ_H */

/* Define if you have the <arpa/inet.h> header file. */
/* #undef HAVE_ARPA_INET_H */

/* Define if you have the `atexit' function. */
#define HAVE_ATEXIT 1

/* Define if you have the `bcopy' function. */
/* #undef HAVE_BCOPY */

/* Define if you have the <bp-sym.h> header file. */
/* #undef HAVE_BP_SYM_H */

/* Define if you have the `btowc' function. */
/* #undef HAVE_BTOWC */

/* Define if you have the `bzero' function. */
/* #undef HAVE_BZERO */

/* Define as 1 if you have catgets and don't want to use GNU gettext. */
/* #undef HAVE_CATGETS */

/* Define if you have the `chsize' function. */
#define HAVE_CHSIZE 1

/* Define if you have the `clock_gettime' function. */
/* #undef HAVE_CLOCK_GETTIME */

/* Define if backslash-a works in C strings. */
#define HAVE_C_BACKSLASH_A 1

/* Define if you have the `dcgettext' function. */
/* #undef HAVE_DCGETTEXT */

/* Define to 1 if you have the declaration of `clearerr_unlocked', and to 0 if
   you don't. */
#define HAVE_DECL_CLEARERR_UNLOCKED 0

/* Define to 1 if you have the declaration of `feof_unlocked', and to 0 if you
   don't. */
#define HAVE_DECL_FEOF_UNLOCKED 0

/* Define to 1 if you have the declaration of `ferror_unlocked', and to 0 if
   you don't. */
#define HAVE_DECL_FERROR_UNLOCKED 0

/* Define to 1 if you have the declaration of `fflush_unlocked', and to 0 if
   you don't. */
#define HAVE_DECL_FFLUSH_UNLOCKED 0

/* Define to 1 if you have the declaration of `fputc_unlocked', and to 0 if
   you don't. */
#define HAVE_DECL_FPUTC_UNLOCKED 0

/* Define to 1 if you have the declaration of `fread_unlocked', and to 0 if
   you don't. */
#define HAVE_DECL_FREAD_UNLOCKED 0

/* Define to 1 if you have the declaration of `free', and to 0 if you don't.
   */
#define HAVE_DECL_FREE 1

/* Define to 1 if you have the declaration of `fwrite_unlocked', and to 0 if
   you don't. */
#define HAVE_DECL_FWRITE_UNLOCKED 0

/* Define to 1 if you have the declaration of `getchar_unlocked', and to 0 if
   you don't. */
#define HAVE_DECL_GETCHAR_UNLOCKED 0

/* Define to 1 if you have the declaration of `getc_unlocked', and to 0 if you
   don't. */
#define HAVE_DECL_GETC_UNLOCKED 0

/* Define to 1 if you have the declaration of `getenv', and to 0 if you don't.
   */
#define HAVE_DECL_GETENV 1

/* Define to 1 if you have the declaration of `geteuid', and to 0 if you
   don't. */
#define HAVE_DECL_GETEUID 0

/* Define to 1 if you have the declaration of `getgrgid', and to 0 if you
   don't. */
#define HAVE_DECL_GETGRGID 0

/* Define to 1 if you have the declaration of `getlogin', and to 0 if you
   don't. */
#define HAVE_DECL_GETLOGIN 0

/* Define to 1 if you have the declaration of `getpwuid', and to 0 if you
   don't. */
#define HAVE_DECL_GETPWUID 0

/* Define to 1 if you have the declaration of `getuid', and to 0 if you don't.
   */
#define HAVE_DECL_GETUID 0

/* Define to 1 if you have the declaration of `getutent', and to 0 if you
   don't. */
#define HAVE_DECL_GETUTENT 0

/* Define to 1 if you have the declaration of `lseek', and to 0 if you don't.
   */
#define HAVE_DECL_LSEEK 1

/* Define to 1 if you have the declaration of `malloc', and to 0 if you don't.
   */
#define HAVE_DECL_MALLOC 1

/* Define to 1 if you have the declaration of `memchr', and to 0 if you don't.
   */
#define HAVE_DECL_MEMCHR 1

/* Define to 1 if you have the declaration of `memrchr', and to 0 if you
   don't. */
#define HAVE_DECL_MEMRCHR 0

/* Define to 1 if you have the declaration of `nanosleep', and to 0 if you
   don't. */
#define HAVE_DECL_NANOSLEEP 0

/* Define to 1 if you have the declaration of `putchar_unlocked', and to 0 if
   you don't. */
#define HAVE_DECL_PUTCHAR_UNLOCKED 0

/* Define to 1 if you have the declaration of `putc_unlocked', and to 0 if you
   don't. */
#define HAVE_DECL_PUTC_UNLOCKED 0

/* Define to 1 if you have the declaration of `realloc', and to 0 if you
   don't. */
#define HAVE_DECL_REALLOC 1

/* Define to 1 if you have the declaration of `stpcpy', and to 0 if you don't.
   */
#define HAVE_DECL_STPCPY 0

/* Define to 1 if you have the declaration of `strerror_r', and to 0 if you
   don't. */
#define HAVE_DECL_STRERROR_R 0

/* Define to 1 if you have the declaration of `strndup', and to 0 if you
   don't. */
#define HAVE_DECL_STRNDUP 0

/* Define to 1 if you have the declaration of `strnlen', and to 0 if you
   don't. */
#if defined(_MSC_VER) && (_MSC_VER < 1900)
#define HAVE_DECL_STRNLEN 0
#else
#define HAVE_DECL_STRNLEN 1
#endif

/* Define to 1 if you have the declaration of `strstr', and to 0 if you don't.
   */
#define HAVE_DECL_STRSTR 1

/* Define to 1 if you have the declaration of `strtoul', and to 0 if you
   don't. */
#define HAVE_DECL_STRTOUL 1

/* Define to 1 if you have the declaration of `strtoull', and to 0 if you
   don't. */
//#define HAVE_DECL_STRTOULL 1
#undef HAVE_DECL_STRTOULL // AEK

/* Define to 1 if you have the declaration of `ttyname', and to 0 if you
   don't. */
#define HAVE_DECL_TTYNAME 0

/* Define to 1 if you have the declaration of `wcwidth', and to 0 if you
   don't. */
#define HAVE_DECL_WCWIDTH 0

/* Define if you have the <dirent.h> header file, and it defines `DIR'. */
#define HAVE_DIRENT_H 1

/* Define if the malloc check has been performed. */
#define HAVE_DONE_WORKING_MALLOC_CHECK 1

/* Define if the realloc check has been performed. */
#define HAVE_DONE_WORKING_REALLOC_CHECK 1

/* Define if you don't have `vprintf' but do have `_doprnt.' */
/* #undef HAVE_DOPRNT */

/* Define if you have the `dup2' function. */
#define HAVE_DUP2 1

/* Define if you have the `endgrent' function. */
/* #undef HAVE_ENDGRENT */

/* Define if you have the `endpwent' function. */
/* #undef HAVE_ENDPWENT */

/* Define if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define if you have the `euidaccess' function. */
/* #undef HAVE_EUIDACCESS */

/* Define if you have the `fchdir' function. */
/* #undef HAVE_FCHDIR */

/* Define if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define if you have the `fdatasync' function. */
/* #undef HAVE_FDATASYNC */

/* Define if you have the <fenv.h> header file. */
//#define HAVE_FENV_H 1 // AEK

/* Define if you have the `fesetround' function. */
//#define HAVE_FESETROUND 1 // AEK

/* Define if you have the <float.h> header file. */
#define HAVE_FLOAT_H 1

/* Define if you have the `floor' function. */
#define HAVE_FLOOR 1

/* Define if your system has a working `fnmatch' function. */
/* #undef HAVE_FNMATCH */

/* Define if you have the `fseeko' function. */
/* #undef HAVE_FSEEKO */

/* Define if you have the <fs_info.h> header file. */
/* #undef HAVE_FS_INFO_H */

/* Define if you have the `fs_stat_dev' function. */
/* #undef HAVE_FS_STAT_DEV */

/* Define if you have the `ftime' function. */
//#define HAVE_FTIME 1 // AEK

/* Define if you have the `ftruncate' function. */
/* #undef HAVE_FTRUNCATE */

/* Define if struct statfs has the f_fstypename member. */
/* #undef HAVE_F_FSTYPENAME_IN_STATFS */

/* Define if you have the `getcwd' function. */
#define HAVE_GETCWD 1

/* Define if you have the `getdelim' function. */
/* #undef HAVE_GETDELIM */

/* Define if you have the `getgroups' function. */
/* #undef HAVE_GETGROUPS */

/* Define if you have the `gethostbyaddr' function. */
/* #undef HAVE_GETHOSTBYADDR */

/* Define if you have the `gethostbyname' function. */
/* #undef HAVE_GETHOSTBYNAME */

/* Define if you have the `gethostname' function. */
/* #undef HAVE_GETHOSTNAME */

/* Define if you have the `gethrtime' function. */
/* #undef HAVE_GETHRTIME */

/* Define if you have the `getloadavg' function. */
/* #undef HAVE_GETLOADAVG */

/* Define if you have the `getmntent' function. */
/* #undef HAVE_GETMNTENT */

/* Define if you have the `getmntinfo' function. */
/* #undef HAVE_GETMNTINFO */

/* Define if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define if you have the `getpass' function. */
/* #undef HAVE_GETPASS */

/* Define if you have the `getspnam' function. */
/* #undef HAVE_GETSPNAM */

/* Define to 1 if you have gettext and don't want to use GNU gettext. */
/* #undef HAVE_GETTEXT */

/* Define if you have the `gettimeofday' function. */
/* #undef HAVE_GETTIMEOFDAY */

/* Define if you have the `getusershell' function. */
/* #undef HAVE_GETUSERSHELL */

/* Define if you have the <grp.h> header file. */
/* #undef HAVE_GRP_H */

/* Define if you have the `hasmntopt' function. */
/* #undef HAVE_HASMNTOPT */

/* Define if you have the iconv() function. */
/* #undef HAVE_ICONV */

/* Define if you have the `inet_ntoa' function. */
/* #undef HAVE_INET_NTOA */

/* Define if <inttypes.h> exists, doesn't clash with <sys/types.h>, and
   declares uintmax_t. */
//#define HAVE_INTTYPES_H 1 // AEK

/* Define if you have the `isascii' function. */
#define HAVE_ISASCII 1

/* Define if you have the `iswprint' function. */
#define HAVE_ISWPRINT 1

/* Define if you have <langinfo.h> and nl_langinfo(CODESET). */
/* #undef HAVE_LANGINFO_CODESET */

/* Define if you have the <langinfo.h> header file. */
/* #undef HAVE_LANGINFO_H */

/* Define if you have the `lchown' function. */
/* #undef HAVE_LCHOWN */

/* Define if your locale.h file contains LC_MESSAGES. */
/* #undef HAVE_LC_MESSAGES */

/* Define if you have the `dgc' library (-ldgc). */
/* #undef HAVE_LIBDGC */

/* Define if you have the `i' library (-li). */
/* #undef HAVE_LIBI */

/* Define if you have the `intl' library (-lintl). */
/* #undef HAVE_LIBINTL */

/* Define if you have the <libintl.h> header file. */
/* #undef HAVE_LIBINTL_H */

/* Define if you have the `kstat' library (-lkstat). */
/* #undef HAVE_LIBKSTAT */

/* Define if you have the `ldgc' library (-lldgc). */
/* #undef HAVE_LIBLDGC */

/* Define if you have the `ypsec' library (-lypsec). */
/* #undef HAVE_LIBYPSEC */

/* Define if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define if you have the `listmntent' function. */
/* #undef HAVE_LISTMNTENT */

/* Define if you have the `localeconv' function. */
#define HAVE_LOCALECONV 1

/* Define if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define if you have the `localtime_r' function. */
/* #undef HAVE_LOCALTIME_R */

/* Define if the `long double' type works. */
#define HAVE_LONG_DOUBLE 1

/* Define if you support file names longer than 14 characters. */
#define HAVE_LONG_FILE_NAMES 1

/* Define if lstat has the bug that it succeeds when given the zero-length
   file name argument. The lstat from SunOS4.1.4 and the Hurd as of
   1998-11-01) do this. */
/* #undef HAVE_LSTAT_EMPTY_STRING_BUG */
#define HAVE_LSTAT 1 // AEK

/* Define if you have the <mach/mach.h> header file. */
/* #undef HAVE_MACH_MACH_H */

/* Define if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define if you have the `mblen' function. */
#define HAVE_MBLEN 1

/* Define if you have the `mbrlen' function. */
/* #undef HAVE_MBRLEN */
#define HAVE_MBRLEN 1 // AEK

/* Define to 1 if mbrtowc and mbstate_t are properly declared. */
/* #undef HAVE_MBRTOWC */
#define HAVE_MBRTOWC 1 // AEK - implemented as xmbrtowc

/* Define if you have the `memchr' function. */
#define HAVE_MEMCHR 1

/* Define if you have the `memcmp' function. */
#define HAVE_MEMCMP 1

/* Define if you have the `memcpy' function. */
#define HAVE_MEMCPY 1

/* Define if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define if you have the `mempcpy' function. */
/* #undef HAVE_MEMPCPY */

/* Define if you have the `memrchr' function. */
/* #undef HAVE_MEMRCHR */

/* Define if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define if you have the `mkfifo' function. */
/* #undef HAVE_MKFIFO */

/* Define if you have the `mkstemp' function. */
/* #undef HAVE_MKSTEMP */

/* Define if you have a working `mmap' system call. */
/* #undef HAVE_MMAP */

/* Define if you have the <mntent.h> header file. */
/* #undef HAVE_MNTENT_H */

/* Define if you have the <mnttab.h> header file. */
/* #undef HAVE_MNTTAB_H */

/* Define if you have the `modf' function. */
#define HAVE_MODF 1

/* Define if you have the `munmap' function. */
/* #undef HAVE_MUNMAP */

/* Define if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define if you have the <netdb.h> header file. */
/* #undef HAVE_NETDB_H */

/* Define if you have the <netinet/in.h> header file. */
/* #undef HAVE_NETINET_IN_H */

/* Define if you have the `next_dev' function. */
/* #undef HAVE_NEXT_DEV */

/* Define if you have the <nlist.h> header file. */
/* #undef HAVE_NLIST_H */

/* Define if you have the `nl_langinfo' function. */
/* #undef HAVE_NL_LANGINFO */

/* Define if you have the <nl_types.h> header file. */
/* #undef HAVE_NL_TYPES_H */

/* Define if libc includes obstacks */
/* #undef HAVE_OBSTACK */

/* Define if you have the <OS.h> header file. */
/* #undef HAVE_OS_H */

/* Define if you have the `pathconf' function. */
/* #undef HAVE_PATHCONF */

/* Define if you have the <paths.h> header file. */
/* #undef HAVE_PATHS_H */

/* Define if you have the `pow' function. */
/* #undef HAVE_POW */

/* Define if your system has the /proc/uptime special file. */
/* #undef HAVE_PROC_UPTIME */

/* Define if you have the `pstat_getdynamic' function. */
/* #undef HAVE_PSTAT_GETDYNAMIC */

/* Define if you have the `putenv' function. */
/* #undef HAVE_PUTENV */

/* Define if you have the <pwd.h> header file. */
/* #undef HAVE_PWD_H */

/* Define if you have the `realpath' function. */
/* #undef HAVE_REALPATH */

/* Define if you have the `resolvepath' function. */
/* #undef HAVE_RESOLVEPATH */

/* Define if you have the `rint' function. */
#define HAVE_RINT 1

/* Define if you have the `rmdir' function. */
#define HAVE_RMDIR 1

/* Define if you have the `rpmatch' function. */
/* #undef HAVE_RPMATCH */

/* Define if you have the `setenv' function. */
/* #undef HAVE_SETENV */

/* Define if you have the `sethostname' function. */
/* #undef HAVE_SETHOSTNAME */

/* Define if you have the `setlocale' function. */
#define HAVE_SETLOCALE 1

/* Define if you have the <shadow.h> header file. */
/* #undef HAVE_SHADOW_H */

/* Define if you have the `sqrt' function. */
#define HAVE_SQRT 1

/* Define if stat has the bug that it succeeds when given the zero-length file
   name argument. The stat from SunOS4.1.4 and the Hurd as of 1998-11-01) do
   this. */
/* #undef HAVE_STAT_EMPTY_STRING_BUG */

/* Define if you have the <stdbool.h> header file. */
//#define HAVE_STDBOOL_H 1 // AEK

/* Define if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define if you have the <stdint.h> header file. */
//#define HAVE_STDINT_H 1 // AEK

/* Define if you have the <stdio_ext.h> header file. */
/* #undef HAVE_STDIO_EXT_H */

/* Define if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define if you have the `stime' function. */
/* #undef HAVE_STIME */

/* Define to 1 if you have the stpcpy function. */
/* #undef HAVE_STPCPY */

/* Define if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1
#define strcasecmp stricmp // AEK

/* Define if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define if you have the `strcspn' function. */
#define HAVE_STRCSPN 1

/* Define if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define if you have the `strerror_r' function. */
/* #undef HAVE_STRERROR_R */

/* Define if you have the `strftime' function. */
#define HAVE_STRFTIME 1

/* Define if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if you have the `strncasecmp' function. */
//#define HAVE_STRNCASECMP 1 // AEK

/* Define if you have the `strndup' function. */
/* #undef HAVE_STRNDUP */

/* Define if you have the `strnlen' function. */
/* #undef HAVE_STRNLEN */

/* Define if you have the `strpbrk' function. */
#define HAVE_STRPBRK 1

/* Define if you have the `strrchr' function. */
#define HAVE_STRRCHR 1

/* Define if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define if you have the `strtoul' function. */
#define HAVE_STRTOUL 1

/* Define if you have the `strtoull' function. */
/* #undef HAVE_STRTOULL */

/* Define if you have the `strtoumax' function. */
#define HAVE_STRTOUMAX 1

/* Define if `n_un.n_name' is member of `struct nlist'. */
/* #undef HAVE_STRUCT_NLIST_N_UN_N_NAME */

/* Define if `sp_pwdp' is member of `struct spwd'. */
/* #undef HAVE_STRUCT_SPWD_SP_PWDP */

/* Define if `st_blksize' is member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_BLKSIZE */

/* Define if `st_blocks' is member of `struct stat'. */
/* #undef HAVE_STRUCT_STAT_ST_BLOCKS */

/* Define if struct timespec is declared in <time.h>. */
/* #undef HAVE_STRUCT_TIMESPEC */

/* Define if `tm_zone' is member of `struct tm'. */
/* #undef HAVE_STRUCT_TM_TM_ZONE */

/* Define if struct utimbuf is declared -- usually in <utime.h>. Some systems
   have utime.h but don't declare the struct anywhere. */
#define HAVE_STRUCT_UTIMBUF 1

/* Define if `ut_name' is member of `struct utmpx'. */
/* #undef HAVE_STRUCT_UTMPX_UT_NAME */

/* Define if `ut_user' is member of `struct utmpx'. */
/* #undef HAVE_STRUCT_UTMPX_UT_USER */

/* Define if `ut_name' is member of `struct utmp'. */
/* #undef HAVE_STRUCT_UTMP_UT_NAME */

/* Define if `ut_user' is member of `struct utmp'. */
/* #undef HAVE_STRUCT_UTMP_UT_USER */

/* Define if you have the `strverscmp' function. */
/* #undef HAVE_STRVERSCMP */

/* Define if your `struct stat' has `st_blocks'. Deprecated, use
   `HAVE_STRUCT_STAT_ST_BLOCKS' instead. */
/* #undef HAVE_ST_BLOCKS */

/* Define if struct stat has an st_dm_mode member. */
/* #undef HAVE_ST_DM_MODE */

/* Define if you have the `sysinfo' function. */
/* #undef HAVE_SYSINFO */

/* Define if you have the <syslog.h> header file. */
/* #undef HAVE_SYSLOG_H */

/* Define if you have the <sys/acl.h> header file. */
/* #undef HAVE_SYS_ACL_H */

/* Define if you have the <sys/dir.h> header file, and it defines `DIR'. */
/* #undef HAVE_SYS_DIR_H */

/* Define if you have the <sys/filsys.h> header file. */
/* #undef HAVE_SYS_FILSYS_H */

/* Define if you have the <sys/fstyp.h> header file. */
/* #undef HAVE_SYS_FSTYP_H */

/* Define if you have the <sys/fs/s5param.h> header file. */
/* #undef HAVE_SYS_FS_S5PARAM_H */

/* Define if you have the <sys/fs_types.h> header file. */
/* #undef HAVE_SYS_FS_TYPES_H */

/* Define if you have the <sys/ioctl.h> header file. */
/* #undef HAVE_SYS_IOCTL_H */

/* Define if you have the <sys/mntent.h> header file. */
/* #undef HAVE_SYS_MNTENT_H */

/* Define if you have the <sys/mount.h> header file. */
/* #undef HAVE_SYS_MOUNT_H */

/* Define if you have the <sys/ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_SYS_NDIR_H */

/* Define if you have the <sys/param.h> header file. */
//#define HAVE_SYS_PARAM_H 1 // AEK

/* Define if you have the <sys/resource.h> header file. */
/* #undef HAVE_SYS_RESOURCE_H */

/* Define if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define if you have the <sys/statfs.h> header file. */
/* #undef HAVE_SYS_STATFS_H */

/* Define if you have the <sys/statvfs.h> header file. */
/* #undef HAVE_SYS_STATVFS_H */

/* Define if you have the <sys/systeminfo.h> header file. */
/* #undef HAVE_SYS_SYSTEMINFO_H */

/* Define if you have the <sys/timeb.h> header file. */
#define HAVE_SYS_TIMEB_H 1

/* Define if you have the <sys/time.h> header file. */
//#define HAVE_SYS_TIME_H 1 // AEK

/* Define if you have the <sys/vfs.h> header file. */
/* #undef HAVE_SYS_VFS_H */

/* Define if you have the <sys/wait.h> header file. */
/* #undef HAVE_SYS_WAIT_H */

/* Define if you have the <termios.h> header file. */
/* #undef HAVE_TERMIOS_H */

/* Define if struct tm has the tm_gmtoff member. */
/* #undef HAVE_TM_GMTOFF */

/* Define if your `struct tm' has `tm_zone'. Deprecated, use
   `HAVE_STRUCT_TM_TM_ZONE' instead. */
/* #undef HAVE_TM_ZONE */

/* Define if you don't have `tm_zone' but do have the external array `tzname'.
   */
/* #undef HAVE_TZNAME */
#define HAVE_TZNAME 1 // AEK

/* Define if you have the `tzset' function. */
#define HAVE_TZSET 1

/* Define if you have the <unistd.h> header file. */
//#define HAVE_UNISTD_H 1 // AEK

/* Define if you have the unsigned long long type. */
//#define HAVE_UNSIGNED_LONG_LONG 1 // AEK

/* Define if you have the `utime' function. */
/* #undef HAVE_UTIME */
#define HAVE_UTIME 1 // AEK

/* Define if utimes accepts a null argument */
/* #undef HAVE_UTIMES_NULL */

/* Define if you have the <utime.h> header file. */
#define HAVE_UTIME_H 1

/* Define if `utime(file, NULL)' sets file's timestamp to the present. */
#define HAVE_UTIME_NULL 1

/* Define if you have the `utmpname' function. */
/* #undef HAVE_UTMPNAME */

/* Define if you have the `utmpxname' function. */
/* #undef HAVE_UTMPXNAME */

/* Define if you have the <utmpx.h> header file. */
/* #undef HAVE_UTMPX_H */

/* Define if you have the <utmp.h> header file. */
/* #undef HAVE_UTMP_H */

/* Define if you have the <values.h> header file. */
//#define HAVE_VALUES_H 1 // AEK

/* Define if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Define if you have the <wchar.h> header file. */
#define HAVE_WCHAR_H 1

/* Define if you have the `wcrtomb' function. */
/* #undef HAVE_WCRTOMB */
#define HAVE_WCRTOMB 1 // AEK

/* Define if you have the <wctype.h> header file. */
#define HAVE_WCTYPE_H 1

/* Define if you have the `wcwidth' function. */
/* #undef HAVE_WCWIDTH */

/* Define if readdir is found to work properly in some unusual cases. */
/* #undef HAVE_WORKING_READDIR */

/* Define to 1 if `strerror_r' returns a string. */
/* #undef HAVE_WORKING_STRERROR_R */

/* Define if you have the `__argz_count' function. */
/* #undef HAVE___ARGZ_COUNT */

/* Define if you have the `__argz_next' function. */
/* #undef HAVE___ARGZ_NEXT */

/* Define if you have the `__argz_stringify' function. */
/* #undef HAVE___ARGZ_STRINGIFY */

/* Define if you have the `__secure_getenv' function. */
/* #undef HAVE___SECURE_GETENV */

/* Define as const if the declaration of iconv() needs const. */
/* #undef ICONV_CONST */

#if FILESYSTEM_BACKSLASH_IS_FILE_NAME_SEPARATOR
# define ISSLASH(C) ((C) == '/' || (C) == '\\')
#else
# define ISSLASH(C) ((C) == '/')
#endif

/* Define if `link(2)' dereferences symbolic links. */
/* #undef LINK_FOLLOWS_SYMLINKS */

/* Define if `lstat' dereferences a symlink specified with a trailing slash.
   */
#define LSTAT_FOLLOWS_SLASHED_SYMLINK 1 // AEK

/* Define if `major', `minor', and `makedev' are declared in <mkdev.h>. */
/* #undef MAJOR_IN_MKDEV */

/* Define if `major', `minor', and `makedev' are declared in <sysmacros.h>. */
/* #undef MAJOR_IN_SYSMACROS */

/* Define if there is no specific function for reading the list of mounted
   filesystems. fread will be used to read /etc/mnttab. (SVR2) */
/* #undef MOUNTED_FREAD */

/* Define if (like SVR2) there is no specific function for reading the list of
   mounted filesystems, and your system has these header files: <sys/fstyp.h>
   and <sys/statfs.h>. (SVR3) */
/* #undef MOUNTED_FREAD_FSTYP */

/* Define if there are functions named next_dev and fs_stat_dev for reading
   the list of mounted filesystems. (BeOS) */
/* #undef MOUNTED_FS_STAT_DEV */

/* Define if there is a function named getfsstat for reading the list of
   mounted filesystems. (DEC Alpha running OSF/1) */
/* #undef MOUNTED_GETFSSTAT */

/* Define if there is a function named getmnt for reading the list of mounted
   filesystems. (Ultrix) */
/* #undef MOUNTED_GETMNT */

/* Define if there is a function named getmntent for reading the list of
   mounted filesystems, and that function takes a single argument. (4.3BSD,
   SunOS, HP-UX, Dynix, Irix) */
/* #undef MOUNTED_GETMNTENT1 */

/* Define if there is a function named getmntent for reading the list of
   mounted filesystems, and that function takes two arguments. (SVR4) */
/* #undef MOUNTED_GETMNTENT2 */

/* Define if there is a function named getmntinfo for reading the list of
   mounted filesystems. (4.4BSD) */
/* #undef MOUNTED_GETMNTINFO */

/* Define if there is a function named listmntent that can be used to list all
   mounted filesystems. (UNICOS) */
/* #undef MOUNTED_LISTMNTENT */

/* Define if there is a function named mntctl that can be used to read the
   list of mounted filesystems, and there is a system header file that
   declares `struct vmount.' (AIX) */
/* #undef MOUNTED_VMOUNT */

/* Define to 1 if assertions should be disabled. */
/* #undef NDEBUG */

/* Define if your `struct nlist' has an `n_un' member. Obsolete, depend on
   `HAVE_STRUCT_NLIST_N_UN_N_NAME */
/* #undef NLIST_NAME_UNION */

/* Name of package */
#define PACKAGE "fileutils"

/* the number of pending output bytes on stream `fp' */
#define PENDING_OUTPUT_N_BYTES fp->_ptr - fp->_base

/* Define if compiler has function prototypes */
#define PROTOTYPES 1

/* Define if rename does not work for source paths with a trailing slash, like
   the one from SunOS 4.1.1_U1. */
/* #undef RENAME_TRAILING_SLASH_BUG */

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* the value to which errno is set when rmdir fails on a nonempty directory */
#define RMDIR_ERRNO_NOT_EMPTY 41

/* Define if the `setvbuf' function takes the buffering type as its second
   argument and the buffer pointer as the third, as on System V before release
   3. */
/* #undef SETVBUF_REVERSED */

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at run-time.
        STACK_DIRECTION > 0 => grows toward higher addresses
        STACK_DIRECTION < 0 => grows toward lower addresses
        STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define if the block counts reported by statfs may be truncated to 2GB and
   the correct values may be stored in the f_spare array. (SunOS 4.1.2, 4.1.3,
   and 4.1.3_U1 are reported to have this problem. SunOS 4.1.1 seems not to be
   affected.) */
/* #undef STATFS_TRUNCATES_BLOCK_COUNTS */

/* Define if the `S_IS*' macros in <sys/stat.h> do not work properly. */
/* #undef STAT_MACROS_BROKEN */
#define STAT_MACROS_BROKEN 1 // AEK

/* Define if there is no specific function for reading filesystems usage
   information and you have the <sys/filsys.h> header file. (SVR2) */
/* #undef STAT_READ_FILSYS */

/* Define if statfs takes 2 args and struct statfs has a field named f_bsize.
   (4.3BSD, SunOS 4, HP-UX, AIX PS/2) */
/* #undef STAT_STATFS2_BSIZE */

/* Define if statfs takes 2 args and struct statfs has a field named f_fsize.
   (4.4BSD, NetBSD) */
/* #undef STAT_STATFS2_FSIZE */

/* Define if statfs takes 2 args and the second argument has type struct
   fs_data. (Ultrix) */
/* #undef STAT_STATFS2_FS_DATA */

/* Define if statfs takes 3 args. (DEC Alpha running OSF/1) */
/* #undef STAT_STATFS3_OSF1 */

/* Define if statfs takes 4 args. (SVR3, Dynix, Irix, Dolphin) */
/* #undef STAT_STATFS4 */

/* Define if there is a function named statvfs. (SVR4) */
/* #undef STAT_STATVFS */

/* Define if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to be the nanoseconds member of struct stat's st_mtim, if it exists.
   */
/* #undef ST_MTIM_NSEC */

/* Define on System V Release 4. */
/* #undef SVR4 */

/* Define if you can safely include both <sys/time.h> and <time.h>. */
//#define TIME_WITH_SYS_TIME 1 // AEK

/* Define if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Define for Encore UMAX. */
/* #undef UMAX */

/* Define for Encore UMAX 4.3 that has <inq_status/cpustats.h> instead of
   <sys/cpustats.h>. */
/* #undef UMAX4_3 */

/* Version number of package */
#define VERSION "4.8.350 2023/05"

/* Define if your system defines `struct winsize' in sys/ptem.h. */
/* #undef WINSIZE_IN_PTEM */

/* Define if your processor stores words with the most significant byte first
   (like Motorola and SPARC, unlike Intel and VAX). */
/* #undef WORDS_BIGENDIAN */

/* Define if on AIX 3.
   System headers sometimes define this.
   We just want to avoid a redefinition error message.  */
#ifndef _ALL_SOURCE
/* # undef _ALL_SOURCE */
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define if on MINIX. */
/* #undef _MINIX */

/* Define if the system does not provide POSIX.1 features except with this
   defined. */
/* #undef _POSIX_1_SOURCE */

/* Define if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define to rpl_chown if the replacement function should be used. */
#define chown rpl_chown

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to rpl_fnmatch if the replacement function should be used. */
#define fnmatch rpl_fnmatch

/* Define as rpl_getgroups if getgroups doesn't work right. */
/* #undef getgroups */

/* Define to `int' if <sys/types.h> doesn't define. */
#define gid_t int

/* Define as `__inline' if that's what the C compiler calls it, or to nothing
   if it is not supported. */
/* #undef inline */

/* Define to `unsigned long' if <sys/types.h> does not define. */
/* #undef ino_t */

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to a type if <wchar.h> does not define. */
/* #undef mbstate_t */

/* Define to rpl_memcmp if the replacement function should be used. */
/* #undef memcmp */

/* Define to rpl_mktime if the replacement function should be used. */
/* #undef mktime */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef mode_t */
#define mode_t int // AEK

/* Define to rpl_nanosleep if the replacement function should be used. */
#define nanosleep rpl_nanosleep

/* Define to `long' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to rpl_putenv if the replacement function should be used. */
#define putenv rpl_putenv

/* Define to rpl_realloc if the replacement function should be used. */
/* #undef realloc */

/* Define to `unsigned' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef ssize_t */

/* Define to gnu_strftime if the replacement function should be used. */
//#define strftime gnu_strftime // AEK

/* Define to `int' if <sys/types.h> doesn't define. */
#define uid_t int

/* Define to unsigned long or unsigned long long if <inttypes.h> doesn't
   define. */
/* #undef uintmax_t */
typedef unsigned __int64 uintmax_t; // AEK

/* Define to empty if the keyword `volatile' does not work. Warning: valid
   code using `volatile' can become incorrect without. Disable with care. */
/* #undef volatile */

////////////
//
// Added by AEK
//
#pragma warning(disable: 4127)  // constant exprs ok - AEK
#pragma warning(disable: 4001)  // single-line comments ok - AEK
#pragma warning(disable: 4305)  // truncated cast ok basetsd.h POINTER_64 - AEK

#if defined(_MSC_VER) && (_MSC_VER < 1300) // RIVY
// For VC6, disable warnings from various standard Windows headers
#pragma warning(disable: 4068) // DISABLE: unknown pragma warnings (in WinGDI.h)
#pragma warning(disable: 4035) // DISABLE: no return value warnings (in WinNT.h)
#endif

#pragma warning(disable: 4996)  // DISABLE: POSIX deprecated warnings

#define _CRT_DISABLE_PERFCRIT_LOCKS // Big perf win -- ls is single-threaded
/*
vim:tabstop=2:shiftwidth=2:expandtab
*/

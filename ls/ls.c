/* `dir', `vdir' and `ls' directory listing programs for GNU.
   Copyright (C) 85, 88, 90, 91, 1995-2001 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* If ls_mode is LS_MULTI_COL,
   the multi-column format is the default regardless
   of the type of output device.
   This is for the `dir' program.

   If ls_mode is LS_LONG_FORMAT,
   the long format is the default regardless of the
   type of output device.
   This is for the `vdir' program.

   If ls_mode is LS_LS,
   the output format depends on whether the output
   device is a terminal.
   This is for the `ls' program. */

/* Written by Richard Stallman and David MacKenzie.  */

/* Color support by Peter Anvin <Peter.Anvin@linux.org> and Dennis
   Flaherty <dennisf@denix.elk.miles.com> based on original patches by
   Greg Lee <lee@uhunix.uhcc.hawaii.edu>.  */

/* Microsoft Windows modifications copyright (c) 2004-2018, U-Tools Software LLC
   Written by Alan Klietz.  Distributed under
   GNU General Public License version 2. */

#ifdef _AIX
 #pragma alloca
#endif

#include <config.h>
#include <sys/types.h>

#if HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#if HAVE_TERMIOS_H
# include <termios.h>
#endif

#ifdef GWINSZ_IN_SYS_IOCTL
# include <sys/ioctl.h>
#endif

#ifdef WINSIZE_IN_PTEM
# include <sys/stream.h>
# include <sys/ptem.h>
#endif

#if HAVE_SYS_ACL_H
# include <sys/acl.h>
#endif

#include <stdio.h>
#include <assert.h>
#ifndef WIN32 // AEK
#include <grp.h>
#include <pwd.h>
#endif
#include <getopt.h>

/* Get MB_CUR_MAX.  */
#if HAVE_STDLIB_H
# include <stdlib.h>
#endif

#include <time.h> // AEK
#include <signal.h> // AEK
#ifdef WIN32
#include <crtdbg.h> // AEK
#endif

/* Get mbstate_t, mbrtowc(), mbsinit(), wcwidth().  */
#if HAVE_WCHAR_H
# include <wchar.h>
#endif

#include <mbstring.h> // AEK - multibyte character set (MBCS) string functions
//#include <mbctype.h>

/* Get iswprint().  */
#if HAVE_WCTYPE_H
# include <wctype.h>
#endif
#if !defined iswprint && !HAVE_ISWPRINT
# define iswprint(wc) 1
#endif

#ifndef HAVE_DECL_WCWIDTH
"this configure-time declaration test was not run"
#endif
#if !HAVE_DECL_WCWIDTH
int wcwidth ();
#endif

/* If wcwidth() doesn't exist, assume all printable characters have
   width 1.  */
#ifndef wcwidth
# if !HAVE_WCWIDTH
#  define wcwidth(wc) ((wc) == 0 ? 0 : iswprint (wc) ? 1 : -1)
# endif
#endif

#include "system.h"
#include <fnmatch.h>

#include "argmatch.h"
#include "error.h"
#include "human.h"
#include "filemode.h"
#include "ls.h"
#include "mbswidth.h"
#include "obstack.h"
#include "path-concat.h"
#include "quotearg.h"
#include "strverscmp.h"
#include "xstrtol.h"
#include "xmbrtowc.h" // AEK
#include "FindFiles.h" // AEK, for __time64_t
#include "glob.h" // AEK
#include "more.h" // AEK

extern void InitVersion(); // AEK

#undef strrchr
#define strrchr _mbsrchr  // use multi-byte version of strrchr - AEK

#ifdef WIN32
#undef strcoll
#define strcoll _mbsicoll // use multi-byte case-insensitive collation order
//
// Win32 BUG: strcoll() and _mbscoll() are wrongly case sensitive!
//
#endif

#pragma warning(disable: 4244) // ignore loss of precision int-to-char // AEK
#pragma warning(disable: 4245) // ignore signed/unsigned mismatch
#pragma warning(disable: 4057) // ignore unsigned char* vs char*
#pragma warning(disable: 4706) // ignore assignment within conditional expr

/* Use access control lists only under all the following conditions.
   Some systems (OSF4, Irix5, Irix6) have the acl function, but not
   sys/acl.h or don't define the GETACLCNT macro.  */
#if HAVE_SYS_ACL_H && HAVE_ACL && defined GETACLCNT
# define USE_ACL 1
#endif

static int ls_mode = LS_LS;

#define PROGRAM_NAME (ls_mode == LS_LS ? "ls" \
              : (ls_mode == LS_MULTI_COL \
             ? "dir" : "vdir"))

#define AUTHORS "Richard Stallman and David MacKenzie" \
  "\nMicrosoft Windows extensions by Alan Klietz"

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

/* Return an int indicating the result of comparing two integers.
   Subtracting doesn't always work, due to overflow.  */
#define longdiff(a, b) ((a) < (b) ? -1 : (a) > (b))

/* The field width for inode numbers.  On some hosts inode numbers are
   64 bits, so columns won't line up exactly when a huge inode number
   is encountered, but in practice 7 digits is usually enough.  */
#ifndef INODE_DIGITS
# define INODE_DIGITS 7
#endif

#ifdef S_ISLNK
# define HAVE_SYMLINKS 1
#else
# define HAVE_SYMLINKS 0
#endif

/* If any of the S_* macros are undefined, define them here so each
   use doesn't have to be guarded with e.g., #ifdef S_ISLNK.  */
#ifndef S_ISLNK
# define S_ISLNK(Mode) 0
#endif

#ifndef S_ISFIFO
# define S_ISFIFO(Mode) 0
#endif

#ifndef S_ISSOCK
# define S_ISSOCK(Mode) 0
#endif

#ifndef S_ISCHR
# define S_ISCHR(Mode) 0
#endif

#ifndef S_ISBLK
# define S_ISBLK(Mode) 0
#endif

#ifndef S_ISDOOR
# define S_ISDOOR(Mode) 0
#endif

#ifndef S_ISSTREAM
# define S_ISSTREAM(Mode) 0
#endif

/* Arrange to make lstat calls go through the wrapper function
   on systems with an lstat function that does not dereference symlinks
   that are specified with a trailing slash.  */
#if ! LSTAT_FOLLOWS_SLASHED_SYMLINK
int rpl_lstat PARAMS((const char *, struct stat *));
# undef lstat
# define lstat(Name, Stat_buf) rpl_lstat(Name, Stat_buf)
#endif

#if defined _DIRENT_HAVE_D_TYPE || defined DTTOIF
# define HAVE_STRUCT_DIRENT_D_TYPE 1
# define DT_INIT(Val) = Val
#else
# define HAVE_STRUCT_DIRENT_D_TYPE 0
# define DT_INIT(Val) /* empty */
#endif

#ifdef ST_MTIM_NSEC
# define TIMESPEC_NS(timespec) ((timespec).ST_MTIM_NSEC)
#else
# define TIMESPEC_NS(timespec) 0
#endif

//
// if --recent=n, then st_mtime within n minutes is considered
// to be 'recent' and is flagged with a different color.
//
#define DEFAULT_RECENT_FILE_MOD 60  // default 60 minutes - AEK

#ifdef WIN32
//
// Because Win32 paths often contain a colon (C:\),
// do not quote with an escape to \: - looks ugly.
//
#define quotearg_colon(n) (n)
#endif

enum filetype
  {
    unknown DT_INIT (DT_UNKNOWN),
    fifo DT_INIT (DT_FIFO),
    chardev DT_INIT (DT_CHR),
    directory DT_INIT (DT_DIR),
    blockdev DT_INIT (DT_BLK),
    normal DT_INIT (DT_REG),
    symbolic_link DT_INIT (DT_LNK),
    sock DT_INIT (DT_SOCK),
    arg_directory DT_INIT (2 * (DT_UNKNOWN | DT_FIFO | DT_CHR | DT_DIR | DT_BLK
                | DT_REG | DT_LNK | DT_SOCK))
  };

struct fileinfo
  {
    /* The file name. */
    char *name;

    struct stat stat;

    /* For symbolic link, name of the file linked to, otherwise zero. */
    char *linkname;

    /* For symbolic link and long listing, st_mode of file linked to, otherwise
       zero. */
    unsigned int linkmode;

    /* For symbolic link and color printing, 1 if linked-to file
       exists, otherwise 0.  */
    int linkok;

    enum filetype filetype;

#if USE_ACL
    /* For long listings, nonzero if the file has an access control list,
       otherwise zero.  */
    int have_acl;
#endif
  };

#if USE_ACL
# define FILE_HAS_ACL(F) ((F)->have_acl)
#else
# define FILE_HAS_ACL(F) 0
#endif

#define LEN_STR_PAIR(s) sizeof (s) - 1, s

/* Null is a valid character in a color indicator (think about Epson
   printers, for example) so we have to use a length/buffer string
   type.  */

struct bin_str
  {
    int len;                /* Number of bytes */
    const char *string;     /* Pointer to the same */
  };

#ifndef STDC_HEADERS
time_t time ();
#endif

char *getgroup () { return "group"; }; // AEK

#define MSLS_PREFIX "MSLS" // AEK
#define LS_PREFIX "LS"

static size_t quote_name PARAMS ((MORE *out, const char *name,
                  struct quoting_options const *options));
static char *make_link_path PARAMS ((const char *path, const char *linkname));
static void mark_if_file_changed_recently PARAMS ((struct stat *pst)); // AEK
static int compare_atime PARAMS ((const struct fileinfo *file1,
                  const struct fileinfo *file2));
static int rev_cmp_atime PARAMS ((const struct fileinfo *file2,
                  const struct fileinfo *file1));
static int compare_ctime PARAMS ((const struct fileinfo *file1,
                  const struct fileinfo *file2));
static int rev_cmp_ctime PARAMS ((const struct fileinfo *file2,
                  const struct fileinfo *file1));
static int compare_mtime PARAMS ((const struct fileinfo *file1,
                  const struct fileinfo *file2));
static int rev_cmp_mtime PARAMS ((const struct fileinfo *file2,
                  const struct fileinfo *file1));
static int compare_size PARAMS ((const struct fileinfo *file1,
                 const struct fileinfo *file2));
static int rev_cmp_size PARAMS ((const struct fileinfo *file2,
                 const struct fileinfo *file1));
static int compare_name PARAMS ((const struct fileinfo *file1,
                 const struct fileinfo *file2));
static int rev_cmp_name PARAMS ((const struct fileinfo *file2,
                 const struct fileinfo *file1));
static int compare_extension PARAMS ((const struct fileinfo *file1,
                      const struct fileinfo *file2));
static int rev_cmp_extension PARAMS ((const struct fileinfo *file2,
                      const struct fileinfo *file1));
static int compare_version PARAMS ((const struct fileinfo *file1,
                    const struct fileinfo *file2));
static int rev_cmp_version PARAMS ((const struct fileinfo *file2,
                    const struct fileinfo *file1));
// AEK
static int compare_case_sensitive PARAMS ((const struct fileinfo *file1,
                 const struct fileinfo *file2));
static int rev_cmp_case_sensitive PARAMS ((const struct fileinfo *file2,
                 const struct fileinfo *file1));
static int decode_switches PARAMS ((int argc, char **argv));
static int file_interesting PARAMS ((const struct dirent *next));
static uintmax_t gobble_file PARAMS ((const char *name, enum filetype type,
                      int explicit_arg, const char *dirname));
static void print_color_indicator PARAMS ((const char *name, unsigned int mode,
                       int linkok));
static void put_indicator PARAMS ((const struct bin_str *ind));
static int length_of_file_name_and_frills PARAMS ((const struct fileinfo *f));
static void add_ignore_pattern PARAMS ((const char *pattern));
static void attach PARAMS ((char *dest, const char *dirname, const char *name));
static void clear_files PARAMS ((void));
static void extract_dirs_from_files PARAMS ((const char *dirname,
                         int recursive));
static void get_link_name PARAMS ((const char *filename, struct fileinfo *f));
static void indent PARAMS ((int from, int to));
static void init_column_info PARAMS ((void));
static void print_current_files PARAMS ((void));
static void print_dir PARAMS ((const char *name, const char *realname));
static void print_file_name_and_frills PARAMS ((const struct fileinfo *f));
static void print_horizontal PARAMS ((void));
static void print_long_format PARAMS ((const struct fileinfo *f));
static void print_many_per_line PARAMS ((void));
static void print_name_with_quoting PARAMS ((const char *p, unsigned int mode,
                         int linkok,
                         struct obstack *stack));
static void prep_non_filename_text PARAMS ((void));
//static void print_type_indicator PARAMS ((unsigned int mode));
static void print_type_indicator PARAMS ((struct stat *pst,
    unsigned int mode)); // AEK
static void print_with_commas PARAMS ((void));
static void queue_directory PARAMS ((const char *name, const char *realname));
static void sort_files PARAMS ((void));
static void parse_ls_color PARAMS ((void));
void usage PARAMS ((int status));

/* The name the program was run with, stripped of any leading path. */
char *program_name;

/* The table of files in the current directory:

   `files' points to a vector of `struct fileinfo', one per file.
   `nfiles' is the number of elements space has been allocated for.
   `files_index' is the number actually in use.  */

/* Address of block containing the files that are described.  */
static struct fileinfo *files;  /* FIXME: rename this to e.g. cwd_file */

/* Length of block that `files' points to, measured in files.  */
static int nfiles;  /* FIXME: rename this to e.g. cwd_n_alloc */

/* Index of first unused in `files'.  */
static int files_index;  /* FIXME: rename this to e.g. cwd_n_used */

/* When nonzero, in a color listing, color each symlink name according to the
   type of file it points to.  Otherwise, color them according to the `ln'
   directive in LS_COLORS.  Dangling (orphan) symlinks are treated specially,
   regardless.  This is set when `ln=target' appears in LS_COLORS.  */

static int color_symlink_as_referent;

/* mode of appropriate file for colorization */
#define FILE_OR_LINK_MODE(File) \
    ((color_symlink_as_referent && (File)->linkok) \
     ? (File)->linkmode : (File)->stat.st_mode)


/* Record of one pending directory waiting to be listed.  */

struct pending
  {
    char *name;
    /* If the directory is actually the file pointed to by a symbolic link we
       were told to list, `realname' will contain the name of the symbolic
       link, otherwise zero. */
    char *realname;
    struct pending *next;
  };

static struct pending *pending_dirs;

/* Current time in seconds and nanoseconds since 1970, updated as
   needed when deciding whether a file is recent.  */

static time_t current_time = TYPE_MINIMUM (time_t);
static int current_time_ns = -1;

/* The number of digits to use for block sizes.
   4, or more if needed for bigger numbers.  */

static int block_size_size;

// Ditto for -l output  AEK
static int long_block_size_size;

/* Option flags */

/* long_format for lots of info, one per line.
   one_per_line for just names, one per line.
   many_per_line for just names, many per line, sorted vertically.
   horizontal for just names, many per line, sorted horizontally.
   with_commas for just names, many per line, separated by commas.

   -l, -1, -C, -x and -m control this parameter.  */

enum format format; // make global for security.cpp and dirent.c - AEK

/* `full-iso' uses full ISO-style dates and times.  `long-iso' uses longer
   ISO-style time stamps, though shorter than `full-iso'.  `iso' uses shorter
   ISO-style time stamps.  `locale' uses locale-dependent time stamps.  */
enum time_style
  {
    full_iso_time_style,    /* --time-style=full-iso */
    long_iso_time_style,    /* --time-style=long-iso */
    iso_time_style,         /* --time-style=iso */
    locale_time_style       /* --time-style=locale */
  };

static char const *const time_style_args[] =
{
  "full-iso", "long-iso", "iso", "locale", NULL
};
static enum time_style const time_style_types[] =
{
  full_iso_time_style, long_iso_time_style, iso_time_style,
  locale_time_style
};

int run_fast = 1; // default, implicitly turned off sometimes unless..
static int explicit_run_fast_or_slow; // explicit --fast or --slow

int phys_size; // --phys_size

int short_names; // --short-names

int color_compressed; // --compressed

static int command_line; // LS_OPTIONS vs command line arg

static char const *const yes_no_args[] =
{
  "always", "yes", "y",
  "never", "none", "no", "n",
  0
};

static enum yes_no_type const yes_no_types[] =
{
  yes_arg, yes_arg, yes_arg,
  no_arg, no_arg, no_arg, no_arg
};

enum yes_no_type show_streams = no_arg; // AEK

#ifdef WIN32
BOOL gbReg; // AEK show registry via -K
BOOL gb32bit; // AEK show 32-bit view of files and registry (--32)

BOOL gbRegDelVal; // AEK delete registry test-value
BOOL gbRegSetVal; // AEK set registry test-value

BOOL gbOemCp; // AEK are we using the OEM console codepage?

BOOL gbExpandMui; // AEK expand MUI registry strings

extern BOOL IsVista;
#endif

/* Type of time to print or sort by.  Controlled by -c and -u.  */

enum time_type
  {
    time_mtime,         /* default */
    time_ctime,         /* -c */
    time_atime          /* -u */
  };

static enum time_type time_type;

/* print the full time, otherwise the standard unix heuristics. */

static int full_time;

/* The file characteristic to sort by.  Controlled by -t, -S, -U, -X, -v. */

enum sort_type
  {
    sort_none,          /* -U */
    sort_name,          /* default */
    sort_extension,     /* -X */
    sort_time,          /* -t */
    sort_size,          /* -S */
    sort_version,       /* -v */
    sort_case           /* -sort=case */  /* AEK */
  };

static enum sort_type sort_type;

/* Direction of sort.
   0 means highest first if numeric,
   lowest first if alphabetic;
   these are the defaults.
   1 means the opposite order in each case.  -r  */

static int sort_reverse;

/* Nonzero means to NOT display group information.  -G  */

#ifdef WIN32
static int inhibit_group = 1;  // inhibit groups by default on Win32 - AEK
#else
static int inhibit_group;
#endif

/* Nonzero means print the user and group id's as numbers rather
   than as names.  -n  */

int numeric_ids; // make global - AEK

/* Nonzero means mention the size in blocks of each file.  -s  */

static int print_block_size;

/* If positive, the units to use when printing sizes;
   if negative, the human-readable base.  */
static int output_block_size;

/* Precede each line of long output (per file) with a string like `m,n:'
   where M is the number of characters after the `:' and before the
   filename and N is the length of the filename.  Using this format,
   Emacs' dired mode starts up twice as fast, and can handle all
   strange characters in file names.  */
static int dired;

/* `none' means don't mention the type of files.
   `classify' means mention file types and mark executables.
   `file_type' means mention only file types.

   Controlled by -F, -p, and --indicator-style.  */

enum indicator_style
  {
    none,       /*     --indicator-style=none */
    classify,   /* -F, --indicator-style=classify */
    file_type   /* -p, --indicator-style=file-type */
  };

static enum indicator_style indicator_style;

/* Names of indicator styles.  */
static char const *const indicator_style_args[] =
{
  "none", "classify", "file-type", 0
};

static enum indicator_style const indicator_style_types[]=
{
  none, classify, file_type
};

/* Nonzero means use colors to mark types.  Also define the different
   colors as well as the stuff for the LS_COLORS environment variable.
   The LS_COLORS variable is now in a termcap-like format.  */

static int print_with_color;

enum color_type
  {
    color_never,        /* 0: default or --color=never */
    color_always,       /* 1: --color=always */
    color_if_tty        /* 2: --color=tty */
  };

enum indicator_no
  {
    C_LEFT, C_RIGHT, C_END, C_NORM, C_FILE, C_DIR, C_LINK, C_FIFO, C_SOCK,
    C_BLK, C_CHR, C_MISSING, C_ORPHAN, C_EXEC, C_DOOR,
    C_RECENT,
    C_COMPRESSED,
    C_STREAMS,
    // additional *nix compatible keywords
    C_RESET, C_MULTIHARDLINK, C_SETUID, C_SETGID, C_CAPABILITY,
    C_STICKY_OTHER_WRITABLE, C_OTHER_WRITABLE, C_STICKY
  };

static const char *const indicator_name[]=
  {
    "lc", "rc", "ec", "no", "fi", "di", "ln", "pi", "so",
    "bd", "cd", "mi", "or", "ex", "do",
    "re", // AEK C_RECENT
    "co", // AEK C_COMPRESSED
    "xs",
    "rs", "mh", "su", "sg", "ca",
    "tw", "ow", "st",
    NULL
  };

struct color_ext_type
  {
    struct bin_str ext;             /* The extension we're looking for */
    struct bin_str seq;             /* The sequence to output when we do */
    struct color_ext_type *next;    /* Next in list */
  };

static struct bin_str color_indicator[] =
  {
    { LEN_STR_PAIR ("\033[") },     /* lc: Left of color sequence */
    { LEN_STR_PAIR ("m") },         /* rc: Right of color sequence */
    { 0, NULL },                    /* ec: End color (replaces lc+no+rc) */
    { LEN_STR_PAIR ("0") },         /* no: Normal */
    { LEN_STR_PAIR ("0") },         /* fi: File: default */
    { LEN_STR_PAIR ("01;32") },     /* di: Directory: bright green */
    { LEN_STR_PAIR ("01;34") },     /* ln: Symlink: bright blue */
    { LEN_STR_PAIR ("33") },        /* pi: Pipe: yellow/brown */
    { LEN_STR_PAIR ("01;35") },     /* so: Socket: bright magenta */
    { LEN_STR_PAIR ("33") },        /* bd: Block device: brown */
    { LEN_STR_PAIR ("33") },        /* cd: Char device: bright yellow */
    { LEN_STR_PAIR ("01;31") },     /* mi: Missing symlink target: bright red */
    { LEN_STR_PAIR ("01;31") },     /* or: Orphaned symlink source: bright red */
    { LEN_STR_PAIR ("01;33") },     /* ex: Executable: bright yellow */
    { LEN_STR_PAIR ("01;35") },     /* do: Door: bright magenta */
    { LEN_STR_PAIR (";04") },       /* re: Recent: underscore - AEK */
    { LEN_STR_PAIR (";01;36") },    /* co: Compressed: bright cyan - AEK */
    { LEN_STR_PAIR (";01;34") },    /* xs: Streams: bright blue - AEK */
    { LEN_STR_PAIR ("0") },         /* rs: Reset */
    { LEN_STR_PAIR ("0") },         /* mh: Multihardlink: normal */
    { LEN_STR_PAIR (";37;41") },    /* su: SetUID: white on red */
    { LEN_STR_PAIR (";30;43") },    /* sg: SetGID: black on yellow */
    { LEN_STR_PAIR (";30;41") },    /* ca: Capability: black on red */
    { LEN_STR_PAIR (";30;42") },    /* tw: Sticky, other-writable: black on green */
    { LEN_STR_PAIR (";01;33;42") }, /* ow: Other-writable: bold yellow on green */
    { LEN_STR_PAIR (";37;44") },    /* st: Sticky: bright blue */
  };

//
// Default colors for popular file extensions.  String generated
// from the dircolors utility - AEK
//
#define MSLS_COLORS_DEFAULT "*.cmd=01;33:*.bat=01;33:*.exe=01;33:*.com=01;33:*.tar=01;36:*.tgz=01;36:*.arj=01;36:*.taz=01;36:*.lzh=01;36:*.zip=01;36:*.z=01;36:*.Z=01;36:*.gz=01;36:*.bz2=01;36:*.deb=01;36:*.rpm=01;36:*.jpg=01;35:*.png=01;35:*.gif=01;35:*.bmp=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.cdr=01;35:*.mpg=01;35:*.wmv=01;35:*.avi=01;35:*.fli=01;35:*.gl=01;35:*.dl=01;35"

/* FIXME: comment  */
static struct color_ext_type *color_ext_list = NULL;

/* Buffer for color sequences */
static char *color_buf;

/* Nonzero means to check for orphaned symbolic link, for displaying
   colors.  */

static int check_symlink_color;

/* Nonzero means mention the inode number of each file.  -i  */

int print_inode; // make global for dirent.c - AEK

/* Nonzero means use the built-in more paginator -M  (AEK) */

static int use_more; // AEK

/* Nonzero means when a symbolic link is found, display info on
   the file linked to.  -L  */

static int trace_links;

/* Nonzero means when a directory is found, display info on its
   contents.  -R  */

static int trace_dirs;

/* Nonzero means when an argument is a directory name, display info
   on it itself.  -d  */

static int immediate_dirs;

/* Nonzero means don't omit files whose names start with `.'.  -A */

static int all_files;

/* Nonzero means don't omit files `.' and `..'
   This flag implies `all_files'.  -a  */

static int really_all_files;

/* A linked list of shell-style globbing patterns.  If a non-argument
   file name matches any of these patterns, it is omitted.
   Controlled by -I.  Multiple -I options accumulate.
   The -B option adds `*~' and `.*~' to this list.  */

struct ignore_pattern
  {
    const char *pattern;
    struct ignore_pattern *next;
  };

static struct ignore_pattern *ignore_patterns;

/* Nonzero means output nongraphic chars in file names as `?'.
   (-q, --hide-control-chars)
   qmark_funny_chars and the quoting style (-Q, --quoting-style=WORD) are
   independent.  The algorithm is: first, obey the quoting style to get a
   string representing the file name;  then, if qmark_funny_chars is set,
   replace all nonprintable chars in that string with `?'.  It's necessary
   to replace nonprintable chars even in quoted strings, because we don't
   want to mess up the terminal if control chars get sent to it, and some
   quoting methods pass through control chars as-is.  */
static int qmark_funny_chars;

/* Quoting options for file and dir name output.  */

static struct quoting_options *filename_quoting_options;
static struct quoting_options *dirname_quoting_options;

/* The number of chars per hardware tab stop.  Setting this to zero
   inhibits the use of TAB characters for separating columns.  -T */
int tabsize;

/* Nonzero means we are listing the working directory because no
   non-option arguments were given. */

static int dir_defaulted;

/* Nonzero means print each directory name before listing it. */

static int print_dir_name;

/* The line length to use for breaking lines in many-per-line format.
   Can be set with -w.  */

static int line_length;

/* If nonzero, the file listing format requires that stat be called on
   each file. */

static int format_needs_stat;

/* Similar to `format_needs_stat', but set if only the file type is
   needed.  */

static int format_needs_type;

/* strftime formats for non-recent and recent files, respectively, in
   -l output.  */

static char const *long_time_format[2];

/* The exit status to use if we don't get any fatal errors. */

static int exit_status;

/* For long options that have no equivalent short option, use a
   non-character as a pseudo short option, starting with CHAR_MAX + 1.  */
enum
{
  BIT32_OPTION = CHAR_MAX + 1, // AEK
  BIT64_OPTION, // AEK
  BLOCK_SIZE_OPTION,
  COLOR_OPTION,
  FORMAT_OPTION,
  FULL_TIME_OPTION,
  INDICATOR_STYLE_OPTION,
  QUOTING_STYLE_OPTION,
  SHOW_CONTROL_CHARS_OPTION,
  SI_OPTION,
  SORT_OPTION,
  TIME_OPTION,
  TIME_STYLE_OPTION,
#ifdef WIN32
  FAST_OPTION, // AEK
  SLOW_OPTION, // AEK
  RECENT_OPTION, // AEK
  PHYS_SIZE_OPTION, // AEK
  SHORT_NAMES_OPTION, // AEK
  COMPRESSED_OPTION, // AEK
  SHOW_STREAMS_OPTION, // AEK
  SIDS_OPTION, // AEK
  GIDS_OPTION, // AEK
  ACLS_OPTION, // AEK
  ENCRYPTION_OPTION, // AEK
  OBJECTID_OPTION, // AEK
  USER_OPTION, // AEK
  VIEW_SECURITY_OPTION, // AEK
  REGSETVAL_OPTION, // AEK
  REGDELVAL_OPTION,
  TOKEN_OPTION, // AEK
  VIRTUAL_OPTION, // AEK
  ANSICP_OPTION, // AEK
  OEMCP_OPTION, // AEK
  EXPANDMUI_OPTION, // AEK
#endif
  COMMAND_LINE_OPTION, // AEK
};

// Mark the end of LS_OPTIONS and the start of real command line args - AEK
#define COMMAND_LINE_OPTION_MARKER "\001\001\001"

static struct option const long_options[] =
{
#ifdef WIN32
  {"32", no_argument, 0, BIT32_OPTION},
  {"64", no_argument, 0, BIT64_OPTION},
#endif
  {"all", no_argument, 0, 'a'},
  {"escape", no_argument, 0, 'b'},
  {"directory", no_argument, 0, 'd'},
  {"dired", no_argument, 0, 'D'},
  {"full-time", no_argument, 0, FULL_TIME_OPTION},
  {"human-readable", no_argument, 0, 'h'},
  {"inode", no_argument, 0, 'i'},
  {"kilobytes", no_argument, 0, 'k'},
#ifdef WIN32
  {"registry", no_argument, 0, 'K'}, // AEK
#endif
  {"numeric-uid-gid", no_argument, 0, 'n'},
  {"no-group", no_argument, 0, 'G'}, // backward compatbility; undoc
  {"groups", optional_argument, 0, 'g'},  // AEK
  {"hide-control-chars", no_argument, 0, 'q'},
  {"reverse", no_argument, 0, 'r'},
  {"size", no_argument, 0, 's'},
  {"width", required_argument, 0, 'w'},
  {"almost-all", no_argument, 0, 'A'},
  {"ignore-backups", no_argument, 0, 'B'},
  {"classify", no_argument, 0, 'F'},
  {"file-type", no_argument, 0, 'p'},
  {"si", no_argument, 0, SI_OPTION},
  {"ignore", required_argument, 0, 'I'},
  {"indicator-style", required_argument, 0, INDICATOR_STYLE_OPTION},
  {"dereference", no_argument, 0, 'L'},
  {"literal", no_argument, 0, 'N'},
  {"quote-name", no_argument, 0, 'Q'},
  {"quoting-style", required_argument, 0, QUOTING_STYLE_OPTION},
  {"recursive", no_argument, 0, 'R'},
  {"format", required_argument, 0, FORMAT_OPTION},
  {"show-control-chars", no_argument, 0, SHOW_CONTROL_CHARS_OPTION},
  {"sort", required_argument, 0, SORT_OPTION},
  {"tabsize", required_argument, 0, 'T'},
  {"time", required_argument, 0, TIME_OPTION},
  {"color", optional_argument, 0, COLOR_OPTION},
  {"block-size", required_argument, 0, BLOCK_SIZE_OPTION},
  {"time-style", required_argument, 0, TIME_STYLE_OPTION},
#ifdef WIN32
  {"fast", no_argument, 0, FAST_OPTION}, // AEK
  {"slow", no_argument, 0, SLOW_OPTION}, // AEK
  {"recent", optional_argument, 0, RECENT_OPTION}, // AEK
  {"more", no_argument, 0, 'M'}, // AEK
  {"phys-size", no_argument, 0, PHYS_SIZE_OPTION}, // AEK
  {"short-names", no_argument, 0, SHORT_NAMES_OPTION}, // AEK
  {"compressed", no_argument, 0, COMPRESSED_OPTION}, // AEK
  {"streams", optional_argument, 0, SHOW_STREAMS_OPTION}, // AEK
  {"sids", optional_argument, 0, SIDS_OPTION}, // AEK
  {"gids", optional_argument, 0, GIDS_OPTION}, // AEK
  {"acls", optional_argument, 0, ACLS_OPTION}, // AEK
  {"encryption-users", no_argument, 0, ENCRYPTION_OPTION}, // AEK
  {"object-id", no_argument, 0, OBJECTID_OPTION}, // AEK
  {"user", required_argument, 0, USER_OPTION}, // AEK
  {"view-security", no_argument, 0, VIEW_SECURITY_OPTION}, // AEK
  {"regsetval", no_argument, 0, REGSETVAL_OPTION}, // AEK
  {"regdelval", no_argument, 0, REGDELVAL_OPTION}, // AEK
  {"tokens", no_argument, 0, TOKEN_OPTION}, // AEK
  {"virtual", no_argument, 0, VIRTUAL_OPTION}, // AEK
  {"ansi-cp", no_argument, 0, ANSICP_OPTION}, // AEK
  {"oem-cp", no_argument, 0, OEMCP_OPTION}, // AEK
  {"expandmui", no_argument, 0, EXPANDMUI_OPTION}, // AEK
#endif
  // Mark the end of LS_OPTIONS and the start of real command line args - AEK
  {COMMAND_LINE_OPTION_MARKER, no_argument, 0, COMMAND_LINE_OPTION}, // AEK
  {GETOPT_HELP_OPTION_DECL},
  {GETOPT_VERSION_OPTION_DECL},
  {NULL, 0, NULL, 0}
};

static char const *const format_args[] =
{
  "verbose", "long", "commas", "horizontal", "across",
  "vertical", "single-column", 0
};

static enum format const format_types[] =
{
  long_format, long_format, with_commas, horizontal, horizontal,
  many_per_line, one_per_line
};

static char const *const sort_args[] =
{
  "none", "time", "size", "extension", "version",
  "case", // AE
  0
};

static enum sort_type const sort_types[] =
{
  sort_none, sort_time, sort_size, sort_extension, sort_version,
  sort_case // AEK
};

static char const *const time_args[] =
{
  "atime", "access", "use",
  "ctime",
#ifndef WIN32
  "status",
#endif
  "mtime", "modify",
  0
};

static enum time_type const time_types[] =
{
  time_atime, time_atime, time_atime,
  time_ctime,
#ifndef WIN32
  time_ctime,
#endif
  time_mtime, time_mtime
};

static char const *const color_args[] =
{
  /* force and none are for compatibility with another color-ls version */
  "always", "yes", "force",
  "never", "no", "none",
  "auto", "tty", "if-tty", 0
};

static enum color_type const color_types[] =
{
  color_always, color_always, color_always,
  color_never, color_never, color_never,
  color_if_tty, color_if_tty, color_if_tty
};

static int recent_file_mod; // AEK

static char const *const sids_args[] =
{
  "long", "yes", "always",
  "none", "no", "never",
  "short",
  0
};

enum sids_format const sids_formats[] =
{
  sids_long, sids_long, sids_long,
  sids_none, sids_none, sids_none,
  sids_short,
};

enum sids_format sids_format = sids_short; // AEK

//
// Note: On Win32 POSIX groups have no effect on the security policy
// outside of the POSIX subsystem.  Since Win32 by definition
// runs outside of POSIX, it makes gids pretty much worthless.
//
#ifdef WIN32
enum sids_format gids_format = sids_none; // AEK
#else
enum sids_format gids_format = sids_short; // AEK
#endif


enum acls_format const acls_formats[] =
{
  acls_long, acls_long, acls_long,
  acls_none, acls_none, acls_none,
  acls_short,
  acls_very_long,
  acls_exhaustive
};

static char const *const acls_args[] =
{
  "long", "yes", "always",
  "none", "no", "never",
  "short",
  "very-long", "exhaustive",
  0
};

enum acls_format acls_format = acls_short; // AEK


static int encrypted_files; // AEK
static int show_objectid; // AEK

char *view_as; // AEK

static int view_security; // AEK
static int show_token; // AEK
int virtual_view; // AEK

/* Information about filling a column.  */
struct column_info
{
  int valid_len;
  int line_len;
  int *col_arr;
};

/* Array with information about column filledness.  */
static struct column_info *column_info;

/* Maximum number of columns ever possible for this display.  */
static int max_idx;

/* The minimum width of a colum is 3: 1 character for the name and 2
   for the separating white space.  */
#define MIN_COLUMN_WIDTH    3


/* This zero-based index is used solely with the --dired option.
   When that option is in effect, this counter is incremented for each
   character of output generated by this program so that the beginning
   and ending indices (in that output) of every file name can be recorded
   and later output themselves.  */
static size_t dired_pos;

//
// Use more-paginator - AEK
//

static char stdout_buf[4096]; // setvbuf buffer

#define DIRED_PUTCHAR(c) do {more_putchar ((c)); ++dired_pos;} while (0)

/* Write S to STREAM and increment DIRED_POS by S_LEN.  */
#define DIRED_FPUTS(s, stream, s_len) \
    do {more_fputs ((s), (stream)); dired_pos += s_len;} while (0)

/* Like DIRED_FPUTS, but for use when S is a literal string.  */
#define DIRED_FPUTS_LITERAL(s, stream) \
    do {more_fputs ((s), (stream)); dired_pos += sizeof((s)) - 1;} while (0)

#define DIRED_INDENT()                                          \
    do                                                          \
      {                                                         \
    /* FIXME: remove the `&& format == long_format' clause.  */ \
    if (dired && format == long_format)                         \
      DIRED_FPUTS_LITERAL ("  ", stdmore);                      \
      }                                                         \
    while (0)

/* With --dired, store pairs of beginning and ending indices of filenames.  */
static struct obstack dired_obstack;

/* With --dired, store pairs of beginning and ending indices of any
   directory names that appear as headers (just before `total' line)
   for lists of directory entries.  Such directory names are seen when
   listing hierarchies using -R and when a directory is listed with at
   least one other command line argument.  */
static struct obstack subdired_obstack;

/* Save the current index on the specified obstack, OBS.  */
#define PUSH_CURRENT_DIRED_POS(obs)                                 \
  do                                                                \
    {                                                               \
      /* FIXME: remove the `&& format == long_format' clause.  */   \
      if (dired && format == long_format)                           \
    obstack_grow ((obs), &dired_pos, sizeof (dired_pos));           \
    }                                                               \
  while (0)


/* Write to standard output PREFIX, followed by the quoting style and
   a space-separated list of the integers stored in OS all on one line.  */

static void
dired_dump_obstack (const char *prefix, struct obstack *os)
{
  int n_pos;

  n_pos = obstack_object_size (os) / sizeof (dired_pos);
  if (n_pos > 0)
    {
      int i;
      size_t *pos;

      pos = (size_t *) obstack_finish (os);
      fputs (prefix, stdout);
      for (i = 0; i < n_pos; i++)
        printf (" %d", (int) pos[i]);
      fputs ("\n", stdout);
    }
}

static volatile int bFreezeColors; // AEK

#ifdef WIN32 // AEK
static HANDLE hStdOut; // console handle for stdout
static WORD wDefaultColors;

//
// Return true/false if the process has a console.
//
// There is no surefire portable way to do this under both
// W2K/NT and W98/W95.   We use the heuristic of checking
// if the underlying WIN32 STD_ERROR_HANDLE is a console.
//
// Note that fd=2 (stderr) is irrelevant here as nothing can redirect
// the underlying console STD_ERROR_HANDLE.  So this heuristic works
// regardless if stderr is redirected (e.g., shells, perl scripts).
//
int _HasConsole()
{
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  static int _bHasConsole = -1;

  if (_bHasConsole != -1) {
    return _bHasConsole;
  }

  hStdOut = GetStdHandle(STD_ERROR_HANDLE);

  if (hStdOut == INVALID_HANDLE_VALUE) {
    _bHasConsole = 0;
    return 0;
  }

  if (GetConsoleScreenBufferInfo(hStdOut, &csbi) == 0) {
    _bHasConsole = 0;
    return 0;
  }

  //
  // Remember default colors for later restore
  //
  wDefaultColors = csbi.wAttributes;

  _bHasConsole = 1;
  return 1;
}

void
exit_ls(void)
{
  //
  // Restore the default colors if interrupted
  //
  bFreezeColors = TRUE; // Prevent races with the main thread

  if (_HasConsole()) { // AEK

    // Restore the console default color
    SetConsoleTextAttribute(hStdOut, wDefaultColors);

    // Restore the console's original codepage
    RestoreConsoleCodePage();

  } else if (print_with_color) { // AEK
    //
    // Restore the console color for rxvt/emacs
    //
    fflush(stdout);
    // atomic: stdout interlocks
    fwrite(color_indicator[C_LEFT].string, sizeof(char), color_indicator[C_LEFT].len, stdout);
    fwrite(color_indicator[C_NORM].string, sizeof(char), color_indicator[C_NORM].len, stdout);
    fwrite(color_indicator[C_RIGHT].string, sizeof(char), color_indicator[C_RIGHT].len, stdout);
    fflush(stdout);
  }

  close_stdout();
}

void signal_ls(int signo)
{
  UNREFERENCED_PARAMETER(signo);
  // calls exit_ls to restore the console
  exit(EXIT_FAILURE);
}
#endif // WIN32 - AEK

int
main (int argc, char **argv)
{
  register int i;
  register struct pending *thispend;
  unsigned int n_files;

  program_name = argv[0];

#if defined(WIN32) && defined(_DEBUG)
  {
    //
    // Check for malloc/free errors - AEK
    //
    int nOldState = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
    _CrtSetDbgFlag(nOldState | _CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF);
  }
#endif

#ifndef WIN32 // AEK
  setlocale (LC_ALL, "");
#else
  InitVersion(); // Query for Windows version
  //
  // Set the locale to the default OEM or ANSI codepage
  // depending on whether or not we are inside a console window
  // and are writing to it (not ls > foo.txt).
  //
  // BUG: If writing to a file the command-line will be parsed
  // using ANSI instead of OEM.
  //
  if (_HasConsole() && isatty(STDOUT_FILENO)) { // AEK
    //
    // By default we use the OEM codepage, unless the console is
    // using a TrueType (TT) font.
    //
    gbOemCp = !IsConsoleFontTrueType();
  }

  if (gbOemCp) {
    //
    // Process has a console.  Set the codepage to OEM so that
    // extended Latin and Asian charsets are parsed and displayed correctly.
    //
    SetCodePage(FALSE/*bAnsi*/);

  } else { // ANSI code page, or the process does not have a console

    SetCodePage(TRUE/*bAnsi*/);

  }
  //
  // If we have a console allocated to us, set the console codepage to what
  // we want - ANSI or OEM.
  //
  if (_HasConsole()) {
    SetConsoleCodePage(get_codepage());
  }

#endif // _WIN32

#if WIN32
  //
  // Arrange to restore console colors on exit - AEK
  //
  atexit (exit_ls);
  signal(SIGINT, signal_ls); // restore console colors on ^C
  signal(SIGBREAK, signal_ls); // restore console colors on BREAK
#else
  atexit (close_stdout);
#endif

  //
  // BUG: On WIN32 stdout is *never* buffered for console output!
  //
  // On Unix stdout is normally line buffered if isatty()
  // and block buffered otherwise.  (Stderr is always
  // single-character buffered so that error messages
  // can appear immediately.)
  //
  // Making stdout block-buffered is a *huge* performance win.   Something
  // like 1000% faster.
  //
  // BUGFIX: Manually set buffering via setvbuf().
  //
#ifdef SETVBUF_REVERSED // if Unix SVR2 bug, swap args
  setvbuf(stdout, _IOFBF, stdout_buf, sizeof(stdout_buf));
#else
  if (setvbuf(stdout, stdout_buf, _IOFBF, sizeof(stdout_buf)) < 0) {
    error(EXIT_FAILURE, 0, "setvbuf failed");
  }
#endif

  more_enable(1); // paginate --help or usage output if tty  AEK

#if ENABLE_NLS // AEK - not supported in Win32 yet.. TODO
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif

#define N_ENTRIES(Array) (sizeof Array / sizeof *(Array))
  assert (N_ENTRIES (color_indicator) + 1 == N_ENTRIES (indicator_name));

  exit_status = 0;
  dir_defaulted = 1;
  print_dir_name = 1;
  pending_dirs = 0;

#ifdef WIN32
  glob_ignore_case = 1; // AEK - Use case-insensitive globbing on Win32
#endif

  //
  // Parse options from the LS_OPTIONS environment variable - AEK
  //
  {
   char *s, *p;
   if ((p = getenv(MSLS_PREFIX "_OPTIONS")) == NULL && // AEK
       (p = getenv(LS_PREFIX "_OPTIONS")) == NULL) {
     command_line = 1;
   } else {
#define N_LS_ARGS 30 // max # of LS_OPTIONS args that we recognize
    int _ls_argc=0;
    char **_ls_argv = (char **)alloca((sizeof(char*))*(N_LS_ARGS+1));

    s = (char *)alloca(strlen(p)+1);
    strcpy(s, p);

    for (;;) {
      while (*s == ' ' || *s == '\t') { // skip leading spaces
    ++s;
      }
      if (*s == '\0') {
    break;
      }
      for (p=s; *p; ++p) { // copy arg until whitespace
    if (*p == ' ' || *p == '\t') {
      break;
    }
      }
      _ls_argv[_ls_argc++] = s;
      if (*p == '\0') {
    break;
      }
      *p++ = '\0';
      s = p;
      if (_ls_argc >= N_LS_ARGS-1) {
    break;
      }

    }

    // mark the end of LS_OPTIONS and start of real command line args
    _ls_argv[_ls_argc++] = "--" COMMAND_LINE_OPTION_MARKER;

    //
    // Merge _ls_argv with argv
    //
    {
      int _tmp_argc = 1;
      char** _tmp_argv = (char **)xmalloc((sizeof(char*))*(_ls_argc+argc+1));
      _tmp_argv[0] = argv[0]; // program name
      for (i=0; i < _ls_argc; ++i) {
    _tmp_argv[_tmp_argc++] = _ls_argv[i];
      }
      for (i=1; i < argc; ++i) {
    _tmp_argv[_tmp_argc++] = argv[i];
      }
      assert (_tmp_argc == _ls_argc+argc);
      argc = _tmp_argc;
      argv = _tmp_argv;
      argv[argc] = NULL;
    }
   }
  } // end AEK

  i = decode_switches (argc, argv);

  if (print_with_color)
    {
      parse_ls_color ();
      prep_non_filename_text ();
      /* Avoid following symbolic links when possible.  */
      if (color_indicator[C_ORPHAN].string != NULL
      || (color_indicator[C_MISSING].string != NULL
          && format == long_format))
    check_symlink_color = 1;
    }

  format_needs_stat = sort_type == sort_time || sort_type == sort_size
    || format == long_format
    || trace_links || trace_dirs || print_block_size || print_inode;
  format_needs_type = (format_needs_stat == 0
               && (print_with_color || indicator_style != none));

#ifdef WIN32
  if (virtual_view) {
    VirtualView();
  }
#endif

  if (dired && format == long_format)
    {
      obstack_init (&dired_obstack);
      obstack_init (&subdired_obstack);
    }

  nfiles = 100;
  files = (struct fileinfo *) xmalloc (sizeof (struct fileinfo) * nfiles);
  files_index = 0;

  clear_files ();

  n_files = argc - i;
  if (0 < n_files)
    dir_defaulted = 0;

  for (; i < argc; i++)
    {
#ifndef WIN32
      gobble_file (argv[i], unknown, 1, "");
#else
      // begin AEK
      //
      // Do manual globbing on Win32.  SETARGV.OBJ is not helpful
      // as it does only primitive globbing of *?.  Using it would
      // interfere with glob.c globbing.  (And it is buggy anyways.)
      //
      // By doing our own globbing we can take advantage of our
      // caching-stat() wrapper for a 50% reduction in the total number
      // of stat() calls.
      //
      char **glob_argv, *s;
      char szPath[FILENAME_MAX];
      int j;

      //
      // BUG: CMD.EXE mangles the command line args from the OEM code page
      // to the ANSI code page, breaking console output.
      // The BUG still exists as of Vista.
      //
      // Example:
      //
      // FOO.EXE "ALT+130" (OEM e-accent) on keyboard input to CMD.EXE
      // comes out as argv "ALT+0233" (ANSI e-accent)
      //
      // As a test to prove that argv is mangled I wrote a trivial console
      // program that puts(argv[1]).  With keyboard input ALT+130 (OEM)
      // -- showing a nice e-accent on the console for the command line --
      // it instead prints ALT+0233 (ANSI), which looks like junk on stdout.
      //
      // This is due to a BUG in CMD.EXE, probably due to failure to
      // call SetFileApisToOem() before invoking CreateProcess("FOO.EXE",argv)
      // to create the console process.   It ought to check the SUBSYSTEM
      // bytes in the executable header and then set the code page
      // appropriately.
      //
      // BUGFIX: De-mangle the argv strings in-place from ANSI back to OEM.
      //
      // Microsoft's own command-line fileutils (XCOPY.EXE, ATTRIB.EXE, etc)
      // use the undocumented ULIB.DLL to work around the CMD.EXE bug.  ULIB
      // knows how to de-mangle argv from ANSI back to the original OEM.
      // It knows how to correct the OEM Locale and MBCP mode (see above).
      //
      // ** A plea to Microsoft: Please document ULIB.DLL.  It would be
      // extremely helpful for 3rd party developers who need to create
      // console-mode utilities that support international languages. **
      //
      if (gbOemCp) {
        CharToOem(argv[i], argv[i]);
      }

      if (!gbReg) {
    lstrcpyn(szPath, argv[i], FILENAME_MAX);
      } else {
    //
    // All registry paths are assumed to be absolute, so
    // prepend '/' if missing
    //
    if (argv[i][0] != '/' && argv[i][0] != '\\') {
      szPath[0] = '/';
      lstrcpyn(szPath+1, argv[i], FILENAME_MAX-1);
    } else {
      lstrcpyn(szPath, argv[i], FILENAME_MAX);
    }
      }

      //
      // Change backslashes to forward slashes for glob
      //
      for (s = szPath; *s; ++s) {
    if (*s == '\\') {
      *s = '/';
     }
      }

      glob_argv = glob_filename(szPath);

      if (glob_argv == NULL) {
    error(EXIT_FAILURE,0,"Out of memory");
      }
      if (glob_argv == &glob_error_return) {
    error (0, errno, "%s", quotearg_colon (argv[i]));
    exit_status = 1;
    continue;
      }
      if (glob_argv[0] == NULL) {
    error (0, errno, "%s", quotearg_colon (argv[i]));
    exit_status = 1;
    continue;
      }
      for (j=0; glob_argv[j] != NULL; ++j) {
        gobble_file(glob_argv[j], unknown, 1, "");
        free(glob_argv[j]);
      }
      free(glob_argv);
      // end AEK
#endif
    }

    //
    // Bail if glob errors on all args - AEK
    //
    if (files_index == 0 && exit_status != 0) {
      exit(exit_status);
    }

  if (dir_defaulted)
    {
#ifdef WIN32 // AEK
      if (gbReg) {
    error(EXIT_FAILURE, 0, "-K requires a registry path");
      }
#endif
      if (immediate_dirs)
    gobble_file (".", directory, 1, "");
      else
    queue_directory (".", 0);
    }

  if (files_index)
    {
      sort_files ();
      if (!immediate_dirs)
    extract_dirs_from_files ("", 0);
      /* `files_index' might be zero now.  */
    }

  if (view_security) { // AEK
    if (files_index > 1) {
      error(EXIT_FAILURE, 0, "Too many files.\nYou must specify a single file or directory with --view-security");
    } else {
#ifdef WIN32
      if (files_index == 1) {
        exit_status = (view_file_security(files[0].stat.st_ce) != 0);
      }
#else
      error(EXIT_FAILURE, 0, "--view-security not supported");
#endif
    }
    exit(exit_status);
  }

#ifdef WIN32
  if (show_token) { // AEK
    exit_status = (DumpToken());
    exit(exit_status);
  }
#endif

  if (files_index)
    {
      print_current_files ();
      if (pending_dirs)
    DIRED_PUTCHAR ('\n');
    }
  else if (n_files <= 1 && pending_dirs && pending_dirs->next == 0)
    print_dir_name = 0;

  while (pending_dirs)
    {
      thispend = pending_dirs;
      pending_dirs = pending_dirs->next;
      print_dir (thispend->name, thispend->realname);
      free (thispend->name);
      if (thispend->realname)
    free (thispend->realname);
      free (thispend);
      print_dir_name = 1;
    }

  if (dired && format == long_format)
    {
      /* No need to free these since we're about to exit.  */
      dired_dump_obstack ("//DIRED//", &dired_obstack);
      dired_dump_obstack ("//SUBDIRED//", &subdired_obstack);
      printf ("//DIRED-OPTIONS// --quoting-style=%s\n",
          // BUG: Need to add '*' to filename_quoting_options - AEK
          //ARGMATCH_TO_ARGUMENT (filename_quoting_options,
          ARGMATCH_TO_ARGUMENT (*filename_quoting_options,
              quoting_style_args, quoting_style_vals));
    }

  exit (exit_status);
}

/* Set all the option flags according to the switches specified.
   Return the index of the first non-option argument.  */

static int
decode_switches (int argc, char **argv)
{
  register char const *p;
  int c;
  int i;
  long int tmp_long;
  char *time_style_option = NULL;

  /* Record whether there is an option specifying sort type.  */
  int sort_type_specified = 0;

  qmark_funny_chars = 0;

  /* initialize all switches to default settings */

  switch (ls_mode)
    {
    case LS_MULTI_COL:
      /* This is for the `dir' program.  */
      format = many_per_line;
      set_quoting_style (NULL, escape_quoting_style);
      break;

    case LS_LONG_FORMAT:
      /* This is for the `vdir' program.  */
      format = long_format;
      set_quoting_style (NULL, escape_quoting_style);
      break;

    case LS_LS:
      /* This is for the `ls' program.  */
      // Uses the default literal_quoting style (0)
      if (isatty (STDOUT_FILENO))
    {
      format = many_per_line;
      /* See description of qmark_funny_chars, above.  */
      qmark_funny_chars = 1;
    }
      else
    {
      format = one_per_line;
      qmark_funny_chars = 0;
    }
      break;

    default:
      abort ();
    }

  time_type = time_mtime;
  full_time = 0;
  sort_type = sort_name;
  sort_reverse = 0;
  numeric_ids = 0;
  print_block_size = 0;
  indicator_style = none;
  print_inode = 0;
  trace_links = 0;
  trace_dirs = 0;
  immediate_dirs = 0;
  all_files = 0;
  really_all_files = 0;
  ignore_patterns = 0;

  /* FIXME: Shouldn't we complain on wrong values? */
  if ((p = getenv ("QUOTING_STYLE"))
      && 0 <= (i = ARGCASEMATCH (p, quoting_style_args, quoting_style_vals)))
    set_quoting_style (NULL, quoting_style_vals[i]);

  human_block_size (((p = getenv (MSLS_PREFIX "_BLOCK_SIZE")) != NULL ? p :
    getenv (LS_PREFIX "_BLOCK_SIZE")), 0, &output_block_size); // AEK

  line_length = 80;
  if ((p = getenv ("COLUMNS")) && *p)
    {
      if (xstrtol (p, NULL, 0, &tmp_long, NULL) == LONGINT_OK
      && 0 < tmp_long && tmp_long <= INT_MAX)
    {
      line_length = (int) tmp_long;
    }
      else
    {
      error (0, 0,
           _("ignoring invalid width in environment variable COLUMNS: %s"),
         quotearg (p));
    }
    }

#ifdef TIOCGWINSZ
  {
    struct winsize ws;

    if (ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws) != -1 && ws.ws_col != 0)
      line_length = ws.ws_col;
  }
#endif

  /* Using the TABSIZE environment variable is not POSIX-approved.
     Ignore it when POSIXLY_CORRECT is set.  */
  tabsize = 8;
  if (!getenv ("POSIXLY_CORRECT") && (p = getenv ("TABSIZE")))
    {
      if (xstrtol (p, NULL, 0, &tmp_long, NULL) == LONGINT_OK
      && 0 <= tmp_long && tmp_long <= INT_MAX)
    {
      tabsize = (int) tmp_long;
    }
      else
    {
      error (0, 0,
       _("ignoring invalid tab size in environment variable TABSIZE: %s"),
         quotearg (p));
    }
    }

  while ((c = getopt_long (argc, argv,
               //"abcdfghiklmnopqrstuvw:xABCDFGHI:LNQRST:UX1",
               "abcdfghiklmnopqrstuvw:xABCDFGHI:KLMNQRST:UX1",// AEK
               long_options, NULL)) != -1)
    {
      switch (c)
    {
    case 0:
      break;

    case 'a':
      all_files = 1;
      really_all_files = 1;
      break;

    case 'b':
      set_quoting_style (NULL, escape_quoting_style);
      break;

    case 'c':
      time_type = time_ctime;
      break;

    case 'd':
      immediate_dirs = 1;
      break;

    case 'f':
      /* Same as enabling -a -U and disabling -l -s.  */
      all_files = 1;
      really_all_files = 1;
      sort_type = sort_none;
      sort_type_specified = 1;
      /* disable -l */
      if (format == long_format)
        format = (isatty (STDOUT_FILENO) ? many_per_line : one_per_line);
      print_block_size = 0; /* disable -s */
      print_with_color = 0; /* disable --color */
      break;

    case 'g': // AEK
      if (optarg)
        inhibit_group = !XARGMATCH ("--groups", optarg,
          yes_no_args, yes_no_types);
      else
        inhibit_group = no_arg; // show groups if -g
      if (!inhibit_group && gids_format == sids_none) {
        gids_format = sids_short; // GIDs format if unspecified
      }
      break;

    case 'h':
      output_block_size = -1024;
      break;

    case 'H':
#ifdef UNDEFINED
      error (0, 0,
         _("\
Warning: the meaning of `-H' will change in the future to conform to POSIX.\n\
Use `--si' for the old meaning."));
      /* Fall through.  */
#else // AEK
    output_block_size = -1024;
    break;
#endif
    case SI_OPTION:
      output_block_size = -1000;
      break;

    case 'i':
      print_inode = 1;
      break;

    case 'k':
      output_block_size = 1024;
      break;

#ifdef WIN32
    case 'K':
      gbReg = TRUE; // AEK show registry via -K
      break;
#endif

    case 'l':
      format = long_format;
      break;

    case 'm':
      format = with_commas;
      break;

    case 'M':
      use_more = 1;
      break;

    case 'n':
      numeric_ids = 1;
      break;

    case 'o':  /* Just like -l, but don't display group info.  */
      format = long_format;
      inhibit_group = 1;
      break;

    case 'p':
      indicator_style = file_type;
      break;

    case 'q':
      qmark_funny_chars = 1;
      break;

    case 'r':
      sort_reverse = 1;
      break;

    case 's':
      print_block_size = 1;
      break;

    case 't':
      sort_type = sort_time;
      sort_type_specified = 1;
      break;

    case 'u':
      time_type = time_atime;
      break;

    case 'v':
      sort_type = sort_version;
      sort_type_specified = 1;
      break;

    case 'w':
      if (xstrtol (optarg, NULL, 0, &tmp_long, NULL) != LONGINT_OK
          || tmp_long <= 0 || tmp_long > INT_MAX)
        error (EXIT_FAILURE, 0, _("invalid line width: %s"),
           quotearg (optarg));
      line_length = (int) tmp_long;
      break;

    case 'x':
      format = horizontal;
      break;

    case 'A':
      really_all_files = 0;
      all_files = 1;
      break;

    case 'B':
      add_ignore_pattern ("*~");
      add_ignore_pattern (".*~");
      break;

    case 'C':
      format = many_per_line;
      break;

    case 'D':
      dired = 1;
      break;

    case 'F':
      indicator_style = classify;
      break;

    case 'G':       /* inhibit display of group info */
      inhibit_group = 1;
      break;

    case 'I':
      add_ignore_pattern (optarg);
      break;

    case 'L':
      trace_links = 1;
      break;

    case 'N':
      set_quoting_style (NULL, literal_quoting_style);
      break;

    case 'Q':
      set_quoting_style (NULL, c_quoting_style);
      break;

    case 'R':
      trace_dirs = 1;
      break;

    case 'S':
      sort_type = sort_size;
      sort_type_specified = 1;
      break;

    case 'T':
      if (xstrtol (optarg, NULL, 0, &tmp_long, NULL) != LONGINT_OK
          || tmp_long < 0 || tmp_long > INT_MAX)
        error (EXIT_FAILURE, 0, _("invalid tab size: %s"),
           quotearg (optarg));
      tabsize = (int) tmp_long;
      break;

    case 'U':
      sort_type = sort_none;
      sort_type_specified = 1;
      break;

    case 'X':
      sort_type = sort_extension;
      sort_type_specified = 1;
      break;

    case '1':
      /* -1 has no effect after -l.  */
      if (format != long_format)
        format = one_per_line;
      break;

#ifdef WIN32 // AEK
    case BIT32_OPTION:
      gb32bit = TRUE;
      break;

    case BIT64_OPTION:
      gb32bit = FALSE;
      break;

    case ANSICP_OPTION:
      gbOemCp = FALSE;

      SetCodePage(TRUE/*bAnsi*/);

      if (_HasConsole()) {
        //
        // Set the console codepage to ANSI.
        //
        SetConsoleCodePage(get_codepage());
      }

      break;

    case OEMCP_OPTION:
      gbOemCp = TRUE;

      SetCodePage(FALSE/*bAnsi*/);

      if (_HasConsole()) {
        //
        // Set the console codepage to OEM.
        //
        SetConsoleCodePage(get_codepage());
      }

      break;
#endif

    case SORT_OPTION:
      sort_type = XARGMATCH ("--sort", optarg, sort_args, sort_types);
      sort_type_specified = 1;
      break;

    case TIME_OPTION:
      time_type = XARGMATCH ("--time", optarg, time_args, time_types);
      break;

    case FORMAT_OPTION:
      format = XARGMATCH ("--format", optarg, format_args, format_types);
      break;

    case FULL_TIME_OPTION:
      format = long_format;
      full_time = 1;
      time_style_option = "full-iso";
      break;

    case COLOR_OPTION:
      if (optarg)
        i = XARGMATCH ("--color", optarg, color_args, color_types);
      else
        /* Using --color with no argument is equivalent to using
           --color=always.  */
        i = color_always;

      print_with_color = (i == color_always
                  || (i == color_if_tty
                  && isatty (STDOUT_FILENO)));

      if (print_with_color)
        {
          /* Don't use TAB characters in output.  Some terminal
         emulators can't handle the combination of tabs and
         color codes on the same line.  */
          tabsize = 0;
        }
      break;

    case INDICATOR_STYLE_OPTION:
      indicator_style = XARGMATCH ("--indicator-style", optarg,
                       indicator_style_args,
                       indicator_style_types);
      break;

    case QUOTING_STYLE_OPTION:
      set_quoting_style (NULL,
                 XARGMATCH ("--quoting-style", optarg,
                    quoting_style_args,
                    quoting_style_vals));
      break;

    case TIME_STYLE_OPTION:
      time_style_option = optarg;
      break;

    case SHOW_CONTROL_CHARS_OPTION:
      qmark_funny_chars = 0;
      break;

    case BLOCK_SIZE_OPTION:
      human_block_size (optarg, 1, &output_block_size);
      break;

    case FAST_OPTION: // AEK
      run_fast = 1;
      explicit_run_fast_or_slow = 1;
      break;

    case SLOW_OPTION: // AEK
      run_fast = 0;
      explicit_run_fast_or_slow = 1;
      break;

    case RECENT_OPTION: // AEK
      if (optarg) { // --recent[=n], n is minutes
        if (xstrtol (optarg, NULL, 0, &tmp_long, NULL) != LONGINT_OK
        || tmp_long < 0 || tmp_long > INT_MAX)
          error (EXIT_FAILURE, 0, _("invalid --recent size: %s"),
             quotearg (optarg));
      } else {
        /* Using --recent with no argument is equivalent to using
           --recent=60. */
        recent_file_mod = DEFAULT_RECENT_FILE_MOD;
      }
      if (command_line && recent_file_mod != 0) {
        // specified on command line
        if (print_with_color == color_never) {
          print_with_color = color_always; // implies --color=always
        }
      }
      break;

#ifdef WIN32
    case PHYS_SIZE_OPTION: // AEK
      phys_size = 1;
      break;

    case SHORT_NAMES_OPTION: // AEK
      short_names = 1;
      break;

    case COMPRESSED_OPTION: // AEK
      color_compressed = 1;
      break;

    case SHOW_STREAMS_OPTION: // AEK
      if (optarg)
        show_streams = XARGMATCH ("--streams", optarg,
          yes_no_args, yes_no_types);
      else
        show_streams = yes_arg;
      if (command_line && show_streams == yes_arg) {
        // specified on command line
        if (!explicit_run_fast_or_slow) run_fast = 0;
      }
      break;

    case SIDS_OPTION: // AEK
      if (!optarg) {
        sids_format = sids_short;
      } else {
        sids_format = XARGMATCH ("--sids", optarg, sids_args, sids_formats);
      }
      if (command_line && sids_format != sids_none) {
        // specified on command line
        format = long_format; // implies -l
        if (!explicit_run_fast_or_slow) run_fast = 0;
      }
      break;

    case GIDS_OPTION: // AEK
      if (!optarg) {
       gids_format = sids_short;
      } else {
       gids_format = XARGMATCH ("--gids", optarg, sids_args, sids_formats);
      }
      if (command_line && gids_format != sids_none) {
        // specified on command line
        format = long_format; // implies -l
        inhibit_group = 0; // turns off -G
        if (!explicit_run_fast_or_slow) run_fast = 0;
      }
      break;

    case ACLS_OPTION: // AEK
      if (!optarg) {
        acls_format = acls_short;
      } else {
        acls_format = XARGMATCH ("--acls", optarg, acls_args, acls_formats);
      }
      if (command_line && acls_format != acls_none) {
        // specified on command line
        format = long_format; // implies -l
        if (!explicit_run_fast_or_slow) run_fast = 0;
      }
      break;

    case ENCRYPTION_OPTION: // AEK
      encrypted_files = 1;
      if (command_line) {
        // specified on command line
        format = long_format; // implies -l
        if (!explicit_run_fast_or_slow) run_fast = 0;
      }
      break;

    case OBJECTID_OPTION: // AEK
      show_objectid = 1;
      if (command_line) {
        // specified on command line
        format = long_format; // implies -l
        if (!explicit_run_fast_or_slow) run_fast = 0;
      }
      break;

    case USER_OPTION: // AEK
      view_as = optarg;
      break;

    case VIEW_SECURITY_OPTION: // AEK
      view_security = 1;
      immediate_dirs = 1; // implies -d
      if (command_line) {
        // specified on command line
        if (!explicit_run_fast_or_slow) run_fast = 0;
      }
      break;

    case TOKEN_OPTION: // AEK
      show_token = 1;
      break;

    case VIRTUAL_OPTION: // AEK
      if (IsVista) {
            virtual_view = 1;
      }
      break;

    case REGSETVAL_OPTION: // AEK
      gbRegSetVal = 1;
      break;

    case REGDELVAL_OPTION: // AEK
      gbRegDelVal = 1;
      break;

    case EXPANDMUI_OPTION: // AEK
      if (IsVista) {
        gbExpandMui = TRUE;
      }
      break;

#endif // WIN32 AEK

    case COMMAND_LINE_OPTION: // AEK
      // Indicate that the remaining args are from the real command line
      // and not from LS_OPTIONS
      command_line = 1;
      break;

    case_GETOPT_HELP_CHAR;

    case_GETOPT_VERSION_CHAR (PROGRAM_NAME, AUTHORS);

    default:
      usage (EXIT_FAILURE);
    }
    }

  if (format != long_format) { // if not -l   - AEK
    sids_format = sids_none;
    gids_format = sids_none;
    acls_format = acls_none;
  }

  more_enable(use_more); // set pagination mode - AEK

  filename_quoting_options = clone_quoting_options (NULL);
#ifndef WIN32 // dont escape embedded spaces in file names on WIN32 - AEK
  if (get_quoting_style (filename_quoting_options) == escape_quoting_style)
    set_char_quoting (filename_quoting_options, ' ', 1);
#endif
  if (indicator_style != none)
    for (p = "*=@|" + (int) indicator_style - 1;  *p;  p++)
      set_char_quoting (filename_quoting_options, *p, 1);

  dirname_quoting_options = clone_quoting_options (NULL);
  set_char_quoting (dirname_quoting_options, ':', 1);

#ifdef WIN32 // don't escape '@' characters on Win32
  set_char_quoting (filename_quoting_options, '@', 0);
  set_char_quoting (dirname_quoting_options, '@', 0);
#endif

  /* If -c or -u is specified and not -l (or any other option that implies -l),
     and no sort-type was specified, then sort by the ctime (-c) or atime (-u).
     The behavior of ls when using either -c or -u but with neither -l nor -t
     appears to be unspecified by POSIX.  So, with GNU ls, `-u' alone means
     sort by atime (this is the one that's not specified by the POSIX spec),
     -lu means show atime and sort by name, -lut means show atime and sort
     by atime.  */

  if ((time_type == time_ctime || time_type == time_atime)
      && !sort_type_specified && format != long_format)
    {
      sort_type = sort_time;
    }

#ifdef WIN32
# define TIME_SEP_CHAR '!'
#else
# define TIME_SEP_CHAR '\n'
#endif
  if (format == long_format)
    {
      char *style = time_style_option;
      static char const posix_prefix[] = "posix-";

      if (! style)
    if (! (style = getenv ("TIME_STYLE")))
      style = "locale";

      while (strncmp (style, posix_prefix, sizeof posix_prefix - 1) == 0)
    {
#ifndef WIN32
      if (! hard_locale (LC_TIME))
        return optind;
#endif
      style += sizeof posix_prefix - 1;
    }

      if (*style == '+')
    {
      char *p0 = style + 1;
      char *p1 = strchr (p0, TIME_SEP_CHAR);
      if (! p1)
        p1 = p0;
      else
        {
          if (strchr (p1 + 1, TIME_SEP_CHAR))
        error (0, 0, _("invalid time style format '%s'"),
               p0);
          *p1++ = '\0';
        }
      long_time_format[0] = p0;
      long_time_format[1] = p1;
    }
      else
    switch (XARGMATCH ("time style", style,
               time_style_args,
               time_style_types))
      {
      case full_iso_time_style:
        long_time_format[0] = long_time_format[1] =
#ifdef WIN32 // Win32 strftime does not support %N.  %z = "Central Daylight Time", not -0600
          "%Y-%m-%d %H:%M:%S";
#else
          "%Y-%m-%d %H:%M:%S.%N %z";
#endif
        break;

      case long_iso_time_style:
#ifndef WIN32
      case_long_iso_time_style:
#endif
        long_time_format[0] = long_time_format[1] = "%Y-%m-%d %H:%M";
        break;

      case iso_time_style:
        long_time_format[0] = "%Y-%m-%d ";
        long_time_format[1] = "%m-%d %H:%M";
        break;

      case locale_time_style:
#ifdef WIN32
      // BUG: Win32 strftime() does not support '%e', so use '%d' - AEK
      long_time_format[0] = dcgettext (NULL, "%b %d  %Y", LC_TIME); // AEK
      long_time_format[1] = dcgettext (NULL, "%b %d %H:%M", LC_TIME); // AEK
#else
        if (hard_locale (LC_TIME))
          {
        /* Ensure that the locale has translations for both
           formats.  If not, fall back on long-iso format.  */
        int i;
        for (i = 0; i < 2; i++)
          {
            char const *locale_format =
              dcgettext (NULL, long_time_format[i], LC_TIME);
            if (locale_format == long_time_format[i])
              goto case_long_iso_time_style;
            long_time_format[i] = locale_format;
          }
          }
#endif
      }
    }


  return optind;
}

/* Parse a string as part of the LS_COLORS variable; this may involve
   decoding all kinds of escape characters.  If equals_end is set an
   unescaped equal sign ends the string, otherwise only a : or \0
   does.  Returns the number of characters output, or -1 on failure.

   The resulting string is *not* null-terminated, but may contain
   embedded nulls.

   Note that both dest and src are char **; on return they point to
   the first free byte after the array and the character that ended
   the input string, respectively.  */

static int
get_funky_string (char **dest, const char **src, int equals_end)
{
  int num;              /* For numerical codes */
  int count;            /* Something to count with */
  enum {
    ST_GND, ST_BACKSLASH, ST_OCTAL, ST_HEX, ST_CARET, ST_END, ST_ERROR
  } state;
  const char *p;
  char *q;

  p = *src;             /* We don't want to double-indirect */
  q = *dest;            /* the whole darn time.  */

  count = 0;            /* No characters counted in yet.  */
  num = 0;

  state = ST_GND;       /* Start in ground state.  */
  while (state < ST_END)
    {
      switch (state)
    {
    case ST_GND:        /* Ground state (no escapes) */
      switch (*p)
        {
        case ':':
        case '\0':
          state = ST_END;   /* End of string */
          break;
        case '\\':
          state = ST_BACKSLASH; /* Backslash scape sequence */
          ++p;
          break;
        case '^':
          state = ST_CARET; /* Caret escape */
          ++p;
          break;
        case '=':
          if (equals_end)
        {
          state = ST_END; /* End */
          break;
        }
          /* else fall through */
        default:
          *(q++) = *(p++);
          ++count;
          break;
        }
      break;

    case ST_BACKSLASH:  /* Backslash escaped character */
      switch (*p)
        {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
          state = ST_OCTAL; /* Octal sequence */
          num = *p - '0';
          break;
        case 'x':
        case 'X':
          state = ST_HEX;   /* Hex sequence */
          num = 0;
          break;
        case 'a':       /* Bell */
          num = 7;      /* Not all C compilers know what \a means */
          break;
        case 'b':       /* Backspace */
          num = '\b';
          break;
        case 'e':       /* Escape */
          num = 27;
          break;
        case 'f':       /* Form feed */
          num = '\f';
          break;
        case 'n':       /* Newline */
          num = '\n';
          break;
        case 'r':       /* Carriage return */
          num = '\r';
          break;
        case 't':       /* Tab */
          num = '\t';
          break;
        case 'v':       /* Vtab */
          num = '\v';
          break;
        case '?':       /* Delete */
              num = 127;
          break;
        case '_':       /* Space */
          num = ' ';
          break;
        case '\0':      /* End of string */
          state = ST_ERROR; /* Error! */
          break;
        default:        /* Escaped character like \ ^ : = */
          num = *p;
          break;
        }
      if (state == ST_BACKSLASH)
        {
          *(q++) = num;
          ++count;
          state = ST_GND;
        }
      ++p;
      break;

    case ST_OCTAL:      /* Octal sequence */
      if (*p < '0' || *p > '7')
        {
          *(q++) = num;
          ++count;
          state = ST_GND;
        }
      else
        num = (num << 3) + (*(p++) - '0');
      break;

    case ST_HEX:        /* Hex sequence */
      switch (*p)
        {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
          num = (num << 4) + (*(p++) - '0');
          break;
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
          num = (num << 4) + (*(p++) - 'a') + 10;
          break;
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
          num = (num << 4) + (*(p++) - 'A') + 10;
          break;
        default:
          *(q++) = num;
          ++count;
          state = ST_GND;
          break;
        }
      break;

    case ST_CARET:      /* Caret escape */
      state = ST_GND;   /* Should be the next state... */
      if (*p >= '@' && *p <= '~')
        {
          *(q++) = *(p++) & 037;
          ++count;
        }
      else if (*p == '?')
        {
          *(q++) = 127;
          ++count;
        }
      else
        state = ST_ERROR;
      break;

    default:
      abort ();
    }
    }

  *dest = q;
  *src = p;

  return state == ST_ERROR ? -1 : count;
}

static void
parse_ls_color (void)
{
  const char *p;        /* Pointer to character being parsed */
  char *buf;            /* color_buf buffer pointer */
  int state;            /* State of parser */
  int ind_no;           /* Indicator number */
  char label[3];        /* Indicator label */
  struct color_ext_type *ext;   /* Extension we are working on */

  if (((p = getenv (MSLS_PREFIX "_COLORS"/*AEK*/)) == NULL &&
      (p = getenv (LS_PREFIX "_COLORS")) == NULL) || *p == '\0') {
    p = MSLS_COLORS_DEFAULT; // AEK
  }

  ext = NULL;
  strcpy (label, "??");

  /* This is an overly conservative estimate, but any possible
     LS_COLORS string will *not* generate a color_buf longer than
     itself, so it is a safe way of allocating a buffer in
     advance.  */
  buf = color_buf = xstrdup (p);

  state = 1;
  while (state > 0)
    {
      switch (state)
    {
    case 1:     /* First label character */
      switch (*p)
        {
        case ':':
          ++p;
          break;

        case '*':
          /* Allocate new extension block and add to head of
         linked list (this way a later definition will
         override an earlier one, which can be useful for
         having terminal-specific defs override global).  */

          ext = (struct color_ext_type *)
                xmalloc (sizeof (struct color_ext_type));
          ext->next = color_ext_list;
          color_ext_list = ext;

          ++p;
          ext->ext.string = buf;

          state = (ext->ext.len =
                get_funky_string (&buf, &p, 1)) < 0 ? -1 : 4;
          break;

        case '\0':
          state = 0;    /* Done! */
          break;

        default:    /* Assume it is file type label */
          label[0] = *(p++);
          state = 2;
          break;
        }
      break;

    case 2:     /* Second label character */
      if (*p)
        {
          label[1] = *(p++);
          state = 3;
        }
      else
        state = -1; /* Error */
      break;

    case 3:     /* Equal sign after indicator label */
      state = -1;   /* Assume failure... */
      if (*(p++) == '=')/* It *should* be... */
        {
          for (ind_no = 0; indicator_name[ind_no] != NULL; ++ind_no)
        {
          if (STREQ (label, indicator_name[ind_no]))
            {
              color_indicator[ind_no].string = buf;
              state = ((color_indicator[ind_no].len =
                get_funky_string (&buf, &p, 0)) < 0 ? -1 : 1);
              break;
            }
        }
          if (state == -1)
        error (0, 0, _("unrecognized prefix: %s"), quotearg (label));
        }
     break;

    case 4:     /* Equal sign after *.ext */
      if (*(p++) == '=')
        {
          ext->seq.string = buf;
          state = (ext->seq.len =
               get_funky_string (&buf, &p, 0)) < 0 ? -1 : 1;
        }
      else
        state = -1;
      break;
    }
    }

  if (state < 0)
    {
      struct color_ext_type *e;
      struct color_ext_type *e2;

      error (0, 0,
         _("unparsable value for " LS_PREFIX "_COLORS environment variable")); // AEK
      free (color_buf);
      for (e = color_ext_list; e != NULL; /* empty */)
    {
      e2 = e;
      e = e->next;
      free (e2);
    }
      print_with_color = 0;
    }

  if (color_indicator[C_LINK].len == 6
      && !strncmp (color_indicator[C_LINK].string, "target", 6))
    color_symlink_as_referent = 1;
}

/* Request that the directory named `name' have its contents listed later.
   If `realname' is nonzero, it will be used instead of `name' when the
   directory name is printed.  This allows symbolic links to directories
   to be treated as regular directories but still be listed under their
   real names. */

static void
queue_directory (const char *name, const char *realname)
{
  struct pending *new;

  new = (struct pending *) xmalloc (sizeof (struct pending));
  new->next = pending_dirs;
  pending_dirs = new;
  new->name = xstrdup (name);
  if (realname)
    new->realname = xstrdup (realname);
  else
    new->realname = 0;
}

/* Read directory `name', and list the files in it.
   If `realname' is nonzero, print its name instead of `name';
   this is used for symbolic links to directories. */

static void
print_dir (const char *name, const char *realname)
{
  register DIR *reading;
  register struct dirent *next;
  register uintmax_t total_blocks = 0;

  errno = 0;
#ifdef WIN32
  reading = opendir_with_pat (name, "*", FALSE/*bCache*/);
#else
  reading = opendir (name);
#endif
  if (!reading)
    {
      error (0, errno, "%s", quotearg_colon (name));
      exit_status = 1;
      return;
    }

  /* Read the directory entries, and insert the subfiles into the `files'
     table.  */

  clear_files ();

  while ((next = readdir (reading)) != NULL)
    if (file_interesting (next))
      {
    enum filetype type = unknown;

#if HAVE_STRUCT_DIRENT_D_TYPE
    if (next->d_type == DT_DIR || next->d_type == DT_CHR
        || next->d_type == DT_BLK || next->d_type == DT_SOCK
        || next->d_type == DT_FIFO)
      type = next->d_type;
#endif
    total_blocks += gobble_file (next->d_name, type, 0, name);
      }

  if (CLOSEDIR (reading))
    {
      error (0, errno, "%s", quotearg_colon (name));
      exit_status = 1;
      /* Don't return; print whatever we got. */
    }

  /* Sort the directory contents.  */
  sort_files ();

  /* If any member files are subdirectories, perhaps they should have their
     contents listed rather than being mentioned here as files.  */

  if (trace_dirs)
    extract_dirs_from_files (name, 1);

  if (trace_dirs || print_dir_name)
    {
      DIRED_INDENT ();
      PUSH_CURRENT_DIRED_POS (&subdired_obstack);
      dired_pos += quote_name (stdmore, realname ? realname : name,
                   dirname_quoting_options);
      PUSH_CURRENT_DIRED_POS (&subdired_obstack);
      DIRED_FPUTS_LITERAL (":\n", stdmore);
    }

  if (format == long_format || print_block_size)
    {
      const char *p;
      char buf[LONGEST_HUMAN_READABLE + 1];

      DIRED_INDENT ();
      p = _("total");
      DIRED_FPUTS (p, stdmore, strlen (p));
      DIRED_PUTCHAR (' ');
      p = human_readable_inexact (total_blocks, buf, ST_NBLOCKSIZE,
                  output_block_size, human_ceiling);
      DIRED_FPUTS (p, stdmore, strlen (p));
      DIRED_PUTCHAR ('\n');
    }

  if (files_index)
    print_current_files ();

  if (pending_dirs)
    DIRED_PUTCHAR ('\n');
}

/* Add `pattern' to the list of patterns for which files that match are
   not listed.  */

static void
add_ignore_pattern (const char *pattern)
{
  register struct ignore_pattern *ignore;

  ignore = (struct ignore_pattern *) xmalloc (sizeof (struct ignore_pattern));
  ignore->pattern = pattern;
  /* Add it to the head of the linked list. */
  ignore->next = ignore_patterns;
  ignore_patterns = ignore;
}

/* Return nonzero if the file in `next' should be listed. */

static int
file_interesting (const struct dirent *next)
{
  register struct ignore_pattern *ignore;

  for (ignore = ignore_patterns; ignore; ignore = ignore->next)
    if (fnmatch (ignore->pattern, next->d_name, FNM_PERIOD) == 0)
      return 0;

  if (next->d_name[0] == '.' && next->d_name[1] == '\0') return really_all_files;
  if (next->d_name[0] == '.' && next->d_name[1] == '.' && next->d_name[2] == '\0') return really_all_files;

  if (all_files) return 1;

  if (next->d_name[0] == '.') return 0;
  if (next->d_name[0] == '_') return 0;
  {
    unsigned long attribs = next->d_ce->dwFileAttributes;
    if (attribs & FILE_ATTRIBUTE_HIDDEN) return 0;
  }

  return 1;
}

/* Enter and remove entries in the table `files'.  */

/* Empty the table of files. */

static void
clear_files (void)
{
  register int i;

  for (i = 0; i < files_index; i++)
    {
      free (files[i].name);
      if (files[i].linkname)
    free (files[i].linkname);
    }

  files_index = 0;
  block_size_size = 4;
  long_block_size_size = 4; // AEK
}

/* Add a file to the current table of files.
   Verify that the file exists, and print an error message if it does not.
   Return the number of blocks that the file occupies.  */

static uintmax_t
gobble_file (const char *name, enum filetype type, int explicit_arg,
         const char *dirname)
{
  register uintmax_t blocks;
  register char *path;

  if (files_index == nfiles)
    {
      nfiles *= 2;
      files = (struct fileinfo *) xrealloc ((char *) files,
                        sizeof (*files) * nfiles);
    }

  files[files_index].linkname = 0;
  files[files_index].linkmode = 0;
  files[files_index].linkok = 0;

  /* FIXME: this use of ls: `mkdir a; touch a/{b,c,d}; ls -R a'
     shouldn't require that ls stat b, c, and d -- at least
     not on systems with usable d_type.  The problem is that
     format_needs_stat is set, because of the -R.  */
  if (explicit_arg || format_needs_stat
      || (format_needs_type && type == unknown))
    {
      /* `path' is the absolute pathname of this file. */
      int val;

      if (name[0] == '/' || dirname[0] == 0
#ifdef WIN32
    // C:xxx - dont concat
    || (name[0] != '\0' && name[1] == ':')
#endif
    )
    path = (char *) name;
      else
    {
      path = (char *) alloca (strlen (name) + strlen (dirname) + 2);
      attach (path, dirname, name);
    }

#ifdef WIN32
      val = (trace_links
         ? stat_nocache (path, &files[files_index].stat, (unsigned long)type)
         : lstat_nocache (path, &files[files_index].stat, (unsigned long)type));
#else
      val = (trace_links
         ? stat (path, &files[files_index].stat)
         : lstat (path, &files[files_index].stat));
#endif

      mark_if_file_changed_recently(&files[files_index].stat); // AEK

      if (val < 0)
    {
      error (0, errno, "%s", quotearg_colon (path));
      exit_status = 1;
      return 0;
    }

#if USE_ACL
      if (format == long_format)
    files[files_index].have_acl =
      (! S_ISLNK (files[files_index].stat.st_mode)
       && 4 < acl (path, GETACLCNT, 0, NULL));
#endif

#if HAVE_SYMLINKS // AEK
      if (S_ISLNK (files[files_index].stat.st_mode)
      && (explicit_arg || format == long_format || check_symlink_color))
    {
      char *linkpath;
      struct stat linkstats;

      get_link_name (path, &files[files_index]);
      linkpath = make_link_path (path, files[files_index].linkname);

      /* Avoid following symbolic links when possible, ie, when
         they won't be traced and when no indicator is needed. */
      if (linkpath
          && ((explicit_arg && format != long_format)
          || indicator_style != none
          || check_symlink_color)
          && stat (linkpath, &linkstats) == 0)
        {
          files[files_index].linkok = 1;

          mark_if_file_changed_recently(&linkstats); // AEK

          /* Symbolic links to directories that are mentioned on the
             command line are automatically traced if not being
             listed as files.  */
          if (explicit_arg && format != long_format
          && S_ISDIR (linkstats.st_mode))
        {
          /* Substitute the linked-to directory's name, but
             save the real name in `linkname' for printing.  */
          if (!immediate_dirs)
            {
              const char *tempname = name;
              name = linkpath;
              linkpath = files[files_index].linkname;
              //
              // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
              // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
              // BUG: Must include a strdup - otherwise
              // we later free garbage memory and trash
              // the arena!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
              // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
              //
              tempname = xstrdup(tempname); // BUFGIX - AEK
              files[files_index].linkname = (char *) tempname;
            }
          files[files_index].stat = linkstats;
        }
          else
        {
          /* Get the linked-to file's mode for the filetype indicator
             in long listings.  */
          files[files_index].linkmode = linkstats.st_mode;
          files[files_index].linkok = 1;
        }
        }
      if (linkpath)
        free (linkpath);
    }
#endif // HAVE_SYMLINKS - AEK

      if (S_ISLNK (files[files_index].stat.st_mode))
    files[files_index].filetype = symbolic_link;
      else if (S_ISDIR (files[files_index].stat.st_mode))
    {
      if (explicit_arg && !immediate_dirs)
        files[files_index].filetype = arg_directory;
      else
        files[files_index].filetype = directory;
    }
      else
    files[files_index].filetype = normal;

      blocks = ST_NBLOCKS (files[files_index].stat);
      {
    char buf[LONGEST_HUMAN_READABLE + 1];
    int len = strlen (human_readable_inexact (blocks, buf, ST_NBLOCKSIZE,
                          output_block_size,
                          human_ceiling));
    if (block_size_size < len)
#ifdef UNDEFINED
      block_size_size = len < 7 ? len : 7;
#else
      block_size_size = len; // AEK make columns thin as possible
#endif
    //
    // Get max size for long format (which is exact if requested)
    //
    if (format == long_format) { // AEK
        len = strlen(human_readable(files[files_index].stat.st_size,
            buf, 1, output_block_size < 0 ? output_block_size : 1));
      if (long_block_size_size < len) {
        long_block_size_size = len;
      }
    }
      }
    }
  else
    {
      files[files_index].filetype = type;
#if HAVE_STRUCT_DIRENT_D_TYPE
      files[files_index].stat.st_mode = DTTOIF (type);
#endif
      blocks = 0;
    }

  files[files_index].name = xstrdup (name);
  files_index++;

  return blocks;
}

#if HAVE_SYMLINKS

/* Put the name of the file that `filename' is a symbolic link to
   into the `linkname' field of `f'. */

static void
get_link_name (const char *filename, struct fileinfo *f)
{
  char *linkbuf;
  register int linksize;

  linkbuf = (char *) alloca (PATH_MAX + 2);
  /* Some automounters give incorrect st_size for mount points.
     I can't think of a good workaround for it, though.  */
#ifndef WIN32
  linksize = readlink (filename, linkbuf, PATH_MAX + 1);
#else
  linksize = _xreadlink (&f->stat, linkbuf, PATH_MAX + 1); // AEK
#endif
  if (linksize < 0)
    {
      error (0, errno, "%s", quotearg_colon (filename));
      exit_status = 1;
    }
  else
    {
      linkbuf[linksize] = '\0';
      f->linkname = xstrdup (linkbuf);
    }
}

/* If `linkname' is a relative path and `path' contains one or more
   leading directories, return `linkname' with those directories
   prepended; otherwise, return a copy of `linkname'.
   If `linkname' is zero, return zero. */

static char *
make_link_path (const char *path, const char *linkname)
{
  char *linkbuf;
  int bufsiz;

  if (linkname == 0)
    return 0;

  if (*linkname == '/')
    return xstrdup (linkname);

#ifdef WIN32
  if (linkname[1] == ':')
    return xstrdup (linkname); // C:xxx - dont concat
#endif

  /* The link is to a relative path.  Prepend any leading path
     in `path' to the link name. */
  linkbuf = strrchr (path, '/');
  if (linkbuf == 0)
    return xstrdup (linkname);

  bufsiz = linkbuf - path + 1;
  linkbuf = xmalloc (bufsiz + strlen (linkname) + 1);
  strncpy (linkbuf, path, bufsiz);
  strcpy (linkbuf + bufsiz, linkname);
  return linkbuf;
}

#endif

// begin AEK
static time_t _current_time;

static void
mark_if_file_changed_recently(struct stat *pst)
{
#ifndef S_RECENT
  return;
#else
  if (recent_file_mod == 0) {
    return;
  }
  if (_current_time == 0) {
    time(&_current_time);
  }
  if ((_current_time - pst->st_mtime) < recent_file_mod * 60) {
    pst->st_mode |= S_RECENT;
  }
#endif
}
// end AEK


/* Return nonzero if base_name (NAME) ends in `.' or `..'
   This is so we don't try to recurse on `././././. ...' */

static int
basename_is_dot_or_dotdot (const char *name)
{
  char *base = base_name (name);
  return DOT_OR_DOTDOT (base);
}

/* Remove any entries from `files' that are for directories,
   and queue them to be listed as directories instead.
   `dirname' is the prefix to prepend to each dirname
   to make it correct relative to ls's working dir.
   `recursive' is nonzero if we should not treat `.' and `..' as dirs.
   This is desirable when processing directories recursively.  */

static void
extract_dirs_from_files (const char *dirname, int recursive)
{
  register int i, j;

  /* Queue the directories last one first, because queueing reverses the
     order.  */
  for (i = files_index - 1; i >= 0; i--)
    if ((files[i].filetype == directory || files[i].filetype == arg_directory)
    && (!recursive || !basename_is_dot_or_dotdot (files[i].name)))
      {
    if (files[i].name[0] == '/' || dirname[0] == 0
#ifdef WIN32
      || files[i].name[1] == ':'// C:xxx - dont concat
#endif
      )
      {
        queue_directory (files[i].name, files[i].linkname);
      }
    else
      {
        char *path = path_concat (dirname, files[i].name, NULL);
        queue_directory (path, files[i].linkname);
        free (path);
      }
    if (files[i].filetype == arg_directory)
      free (files[i].name);
      }

  /* Now delete the directories from the table, compacting all the remaining
     entries.  */

  for (i = 0, j = 0; i < files_index; i++)
    if (files[i].filetype != arg_directory)
      files[j++] = files[i];
  files_index = j;
}

/* Sort the files now in the table.  */

static void
sort_files (void)
{
  typedef int (*qsort_compare_t)( const void *, const void * );
  qsort_compare_t func = NULL;

  switch (sort_type)
    {
    case sort_none:
      return;
    case sort_time:
      switch (time_type)
    {
    case time_ctime:
      func = sort_reverse ? rev_cmp_ctime : compare_ctime;
      break;
    case time_mtime:
      func = sort_reverse ? rev_cmp_mtime : compare_mtime;
      break;
    case time_atime:
      func = sort_reverse ? rev_cmp_atime : compare_atime;
      break;
    default:
      abort ();
    }
      break;
    case sort_name:
      func = sort_reverse ? rev_cmp_name : compare_name;
      break;
    case sort_extension:
      func = sort_reverse ? rev_cmp_extension : compare_extension;
      break;
    case sort_size:
      func = sort_reverse ? rev_cmp_size : compare_size;
      break;
    case sort_version:
      func = sort_reverse ? rev_cmp_version : compare_version;
      break;
    case sort_case: // AEK
      func = sort_reverse ? rev_cmp_case_sensitive : compare_case_sensitive;
      break;
    default:
      abort ();
    }

  qsort ( (void *)files, (size_t)files_index, (size_t)sizeof (struct fileinfo), func); // RIVY
}

/* Comparison routines for sorting the files. */

static int
compare_ctime (const struct fileinfo *file1, const struct fileinfo *file2)
{
  int diff = CTIME_CMP (file2->stat, file1->stat);
  if (diff == 0)
    diff = strcoll (file1->name, file2->name);
  return diff;
}

static int
rev_cmp_ctime (const struct fileinfo *file2, const struct fileinfo *file1)
{
  int diff = CTIME_CMP (file2->stat, file1->stat);
  if (diff == 0)
    diff = strcoll (file1->name, file2->name);
  return diff;
}

static int
compare_mtime (const struct fileinfo *file1, const struct fileinfo *file2)
{
  int diff = MTIME_CMP (file2->stat, file1->stat);
  if (diff == 0)
    diff = strcoll (file1->name, file2->name);
  return diff;
}

static int
rev_cmp_mtime (const struct fileinfo *file2, const struct fileinfo *file1)
{
  int diff = MTIME_CMP (file2->stat, file1->stat);
  if (diff == 0)
    diff = strcoll (file1->name, file2->name);
  return diff;
}

static int
compare_atime (const struct fileinfo *file1, const struct fileinfo *file2)
{
  int diff = ATIME_CMP (file2->stat, file1->stat);
  if (diff == 0)
    diff = strcoll (file1->name, file2->name);
  return diff;
}

static int
rev_cmp_atime (const struct fileinfo *file2, const struct fileinfo *file1)
{
  int diff = ATIME_CMP (file2->stat, file1->stat);
  if (diff == 0)
    diff = strcoll (file1->name, file2->name);
  return diff;
}

static int
compare_size (const struct fileinfo *file1, const struct fileinfo *file2)
{
  int diff = longdiff (file2->stat.st_size, file1->stat.st_size);
  if (diff == 0)
    diff = strcoll (file1->name, file2->name);
  return diff;
}

static int
rev_cmp_size (const struct fileinfo *file2, const struct fileinfo *file1)
{
  int diff = longdiff (file2->stat.st_size, file1->stat.st_size);
  if (diff == 0)
    diff = strcoll (file1->name, file2->name);
  return diff;
}

static int
compare_version (const struct fileinfo *file1, const struct fileinfo *file2)
{
  return strverscmp (file1->name, file2->name);
}

static int
rev_cmp_version (const struct fileinfo *file2, const struct fileinfo *file1)
{
  return strverscmp (file1->name, file2->name);
}

static int
compare_name (const struct fileinfo *file1, const struct fileinfo *file2)
{
  return strcoll (file1->name, file2->name);
}

static int
rev_cmp_name (const struct fileinfo *file2, const struct fileinfo *file1)
{
  return strcoll (file1->name, file2->name);
}

//
// Case-sensitive comparison  --sort=case
//
// For Unix afficanados who like "Makefile" first.
//
static int
compare_case_sensitive (const struct fileinfo *file1, const struct fileinfo *file2)
{
#ifdef WIN32
  //
  // Win32 BUG: _mbscoll wrongly acts like _mbsicoll!
  //
  // Re-implement _mbscoll manually.
  //
  unsigned char *s1 = (unsigned char *)file1->name;
  unsigned char *s2 = (unsigned char *)file2->name;

  int mbch1, mbch2;
  for (; *s1 && *s2; s1 = _mbsinc(s1), s2 = _mbsinc(s2)) {
    mbch1 = _mbsnextc(s1);
    mbch2 = _mbsnextc(s2);
    if (_ismbcupper(mbch1) && !_ismbcupper(mbch2)) {
      return -1; // upper case < lower case
    }
    if (!_ismbcupper(mbch1) && _ismbcupper(mbch2)) {
      return 1; // lower case > upper case
    }
    if (mbch1 != mbch2) {
      break;
    }
  }
  // No case-only differences at this point
  return _mbsicoll(file1->name, file2->name);
#else
  return _mbscoll(file1->name, file2->name);
#endif
}

static int
rev_cmp_case_sensitive (const struct fileinfo *file2, const struct fileinfo *file1)
{
  return compare_case_sensitive (file1, file2);
}

/* Compare file extensions.  Files with no extension are `smallest'.
   If extensions are the same, compare by filenames instead. */

static int
compare_extension (const struct fileinfo *file1, const struct fileinfo *file2)
{
  register char *base1, *base2;
  register int cmp;

  base1 = strrchr (file1->name, '.');
  base2 = strrchr (file2->name, '.');
  if (base1 == 0 && base2 == 0)
    return strcoll (file1->name, file2->name);
  if (base1 == 0)
    return -1;
  if (base2 == 0)
    return 1;
  cmp = strcoll (base1, base2);
  if (cmp == 0)
    return strcoll (file1->name, file2->name);
  return cmp;
}

static int
rev_cmp_extension (const struct fileinfo *file2, const struct fileinfo *file1)
{
  register char *base1, *base2;
  register int cmp;

  base1 = strrchr (file1->name, '.');
  base2 = strrchr (file2->name, '.');
  if (base1 == 0 && base2 == 0)
    return strcoll (file1->name, file2->name);
  if (base1 == 0)
    return -1;
  if (base2 == 0)
    return 1;
  cmp = strcoll (base1, base2);
  if (cmp == 0)
    return strcoll (file1->name, file2->name);
  return cmp;
}

/* List all the files now in the table.  */

static void
print_current_files (void)
{
  register int i;

  switch (format)
    {
    case one_per_line:
      for (i = 0; i < files_index; i++)
    {
      print_file_name_and_frills (files + i);
      more_putchar ('\n');
    }
      break;

    case many_per_line:
      init_column_info ();
      print_many_per_line ();
      break;

    case horizontal:
      init_column_info ();
      print_horizontal ();
      break;

    case with_commas:
      print_with_commas ();
      break;

    case long_format:
      for (i = 0; i < files_index; i++)
    {
#ifdef WIN32
      size_t count;
#endif
      print_long_format (files + i);
      DIRED_PUTCHAR ('\n');
#ifdef WIN32
      count = MORE_COUNT(stdmore); // get output odometer
      //
      // Print the long ACL
      //
      if (gbReg) {
        print_registry_value(files[i].stat.st_ce);
      }
      if (acls_format == acls_long || acls_format == acls_very_long
            || acls_format == acls_exhaustive) {
        print_long_acl(files[i].stat.st_ce);
      }
      //
      // Print the name(s) of principals with encryption credentails
      // for the file
      //
      if (encrypted_files) {
        print_encrypted_file(files[i].stat.st_ce);
      }
      if (show_objectid) {
        print_objectid(files[i].stat.st_ce);
      }
      //
      // Bump the EMACS dired_pos by the total number of chars output
      //
      dired_pos += (MORE_COUNT(stdmore) - count);
#endif
    }
      break;
    }
}

/* Return the expected number of columns in a long-format time stamp,
   or zero if it cannot be calculated.  */

static int
long_time_expected_width (void)
{
  static int width = -1;

  if (width < 0)
    {
      time_t epoch = 0;
      struct tm const *tm = localtime (&epoch);
      char const *fmt = long_time_format[0];
      char initbuf[100];
      char *buf = initbuf;
      size_t bufsize = sizeof initbuf;
      size_t len;

      for (;;)
    {
      *buf = '\1';
      len = strftime (buf, bufsize, fmt, tm);
      if (len || ! *buf)
        break;
      buf = alloca (bufsize *= 2);
    }

      width = mbsnwidth (buf, len, 0);
      if (width < 0)
    width = 0;
    }

  return width;
}

/* Get the current time.  */

static void
get_current_time (void)
{
#if HAVE_CLOCK_GETTIME && defined CLOCK_REALTIME
  {
    struct timespec timespec;
    if (clock_gettime (CLOCK_REALTIME, &timespec) == 0)
      {
    current_time = timespec.tv_sec;
    current_time_ns = timespec.tv_nsec;
    return;
      }
  }
#endif

  /* The clock does not have nanosecond resolution, so get the maximum
     possible value for the current time that is consistent with the
     reported clock.  That way, files are not considered to be in the
     future merely because their time stamps have higher resolution
     than the clock resolution.  */

#if HAVE_GETTIMEOFDAY
  {
    struct timeval timeval;
    if (gettimeofday (&timeval, NULL) == 0)
      {
    current_time = timeval.tv_sec;
    current_time_ns = timeval.tv_usec * 1000 + 999;
    return;
      }
  }
#endif

  current_time = time (NULL);
  current_time_ns = 999999999;
}

static void
print_long_format (const struct fileinfo *f)
{
  char modebuf[12];

  /* 7 fields that may require LONGEST_HUMAN_READABLE bytes,
     1 10-byte mode string,
     1 24-byte time string (may be longer in some locales -- see below)
       or LONGEST_HUMAN_READABLE integer,
     9 spaces, one following each of these fields, and
     1 trailing NUL byte.  */
  char init_bigbuf[7 * LONGEST_HUMAN_READABLE + 10
           + (LONGEST_HUMAN_READABLE < 24 ? 24 : LONGEST_HUMAN_READABLE)
           + 9 + 1
#ifdef WIN32
           + 128 // longer user + group names
#endif
  ];
  char *buf = init_bigbuf;
  size_t bufsize = sizeof (init_bigbuf);
  size_t s;
  char *p;
  time_t when;
  //int when_ns IF_LINT (= 0);
  int when_ns = 0; // AEK
  struct tm *when_local;
  char *user_name;

#if HAVE_ST_DM_MODE
  /* Cray DMF: look at the file's migrated, not real, status */
  mode_string (f->stat.st_dm_mode, modebuf);
#else
# ifdef WIN32 // AEK
  win32_mode_string (&((struct fileinfo *)f)->stat, modebuf); // fancy ACL check    // RIVY
# else
  mode_string (f->stat.st_mode, modebuf);
# endif
#endif

#ifdef WIN32 // AEK
  {
    unsigned long attribs = f->stat.st_ce->dwFileAttributes;

#ifndef FILE_ATTRIBUTE_VIRTUAL
# define FILE_ATTRIBUTE_VIRTUAL 0x00010000
#endif

    if (attribs & FILE_ATTRIBUTE_COMPRESSED) {
      if ((attribs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        modebuf[0] = 'c';  // crw-rw-rw-
      }
    }
    if (attribs & FILE_ATTRIBUTE_SPARSE_FILE) {
      modebuf[0] = 'S';  // Srw-rw-rw-
    }
    if (attribs & FILE_ATTRIBUTE_SYSTEM) {
      modebuf[3] = 's'; // -rws-rw-rw-
    }
    if (attribs & FILE_ATTRIBUTE_HIDDEN) {
      modebuf[6] = 'h'; // -rw-rwh-rw-
    }
    if (attribs & FILE_ATTRIBUTE_ARCHIVE) {
      modebuf[9] = 'a'; // -rw-rw-rwa
    }
    if (attribs & FILE_ATTRIBUTE_ENCRYPTED) {
      // Note: An NTFS file cannot have system+encrypt attribs at same time
      modebuf[3] = 'E'; // -rwE-rw-rw-
    }
    if (attribs & FILE_ATTRIBUTE_TEMPORARY) {
      modebuf[6] = 'T';  // -rw-rwTrw-  (input arg only - never seen?)
    }
    if (attribs & FILE_ATTRIBUTE_OFFLINE) {
      modebuf[9] = 'O'; // -rw-rw-rwO
    }
    if (attribs & FILE_ATTRIBUTE_VIRTUAL) {
      modebuf[9] = 'V'; // -rw-rw-rwV
    }
  }
#endif

#ifdef WIN32
  // Mark if the file has embedded data streams
  modebuf[10] = ((f->stat.st_mode & S_STREAM) ? '$' : ' ');
#else
  modebuf[10] = (FILE_HAS_ACL (f) ? '+' : ' ');
#endif
  modebuf[11] = '\0';

  switch (time_type)
    {
    case time_ctime:
      when = f->stat.st_ctime;
      when_ns = TIMESPEC_NS (f->stat.st_ctim);
      break;
    case time_mtime:
      when = f->stat.st_mtime;
      when_ns = TIMESPEC_NS (f->stat.st_mtim);
      break;
    case time_atime:
      when = f->stat.st_atime;
      when_ns = TIMESPEC_NS (f->stat.st_atim);
      break;
    }

  p = buf;

  if (print_inode)
    {
      char hbuf[LONGEST_HUMAN_READABLE + 1];
      sprintf (p, "%*s ", INODE_DIGITS,
           human_readable ((uintmax_t) f->stat.st_ino, hbuf, 1, 1));
      p += strlen (p);
    }

  if (print_block_size)
    {
      char hbuf[LONGEST_HUMAN_READABLE + 1];
      sprintf (p, "%*s ", block_size_size,
           human_readable_inexact ((uintmax_t) ST_NBLOCKS (f->stat), hbuf,
                       ST_NBLOCKSIZE, output_block_size,
                       human_ceiling));
      p += strlen (p);
    }

  /* The last byte of the mode string is the POSIX
     "optional alternate access method flag".  */
#ifdef WIN32
  sprintf (p, "%s %1u ", modebuf, (unsigned int) f->stat.st_nlink);
#else
  sprintf (p, "%s %3u ", modebuf, (unsigned int) f->stat.st_nlink);
#endif
  p += strlen (p);

#ifdef WIN32 // AEK
  user_name = xgetuser(f->stat.st_ce, FALSE/*bGroup*/); // translate owner SID
  if (user_name == NULL) user_name = "???";
  if (strcmp(user_name, "0") == 0) {
    //
    // We return "0" to keep the number of columns the same.
    //
    // Needed for perl scripts that expect exactly 9 columns in the output
    //
    sprintf (p, "%-1.1s ", user_name); // keep short
  } else if (sids_format == sids_long) {
    sprintf (p, "%-17s ", user_name);
  } else { // sids_short, and chopped [domain\]users
    sprintf (p, "%-16.16s ", user_name); // sizeof("Administradators") == 16
  }

#else
  user_name = (numeric_ids ? NULL : getuser (f->stat.st_uid));
  if (user_name)
    sprintf (p, "%-8.8s ", user_name);
  else
    sprintf (p, "%-8u ", (unsigned int) f->stat.st_uid);
#endif
  p += strlen (p);

  if (!inhibit_group)
    {
#ifdef WIN32
      char *group_name = xgetuser(f->stat.st_ce, TRUE/*bGroup*/);
      if (group_name == NULL) group_name = "???";
      if (strcmp(group_name, "0") == 0) {
        //
        // We return "0" to keep the number of columns the same.
    //
    // Needed for perl scripts that expect exactly 9 columns in the output
    //
        // To turn off gids entirely use -G or -o.
        //
        sprintf (p, "%-1.1s ", group_name); // keep short
      } else if (gids_format == sids_long) {
        sprintf (p, "%-17s ", group_name);
      } else {
        sprintf (p, "%-8.8s ", group_name);
      }
#else
      char *group_name = (numeric_ids ? NULL : getgroup (f->stat.st_gid));
      if (group_name)
    sprintf (p, "%-8.8s ", group_name);
      else
    sprintf (p, "%-8u ", (unsigned int) f->stat.st_gid);
#endif
      p += strlen (p);
    }

  if (S_ISCHR (f->stat.st_mode) || S_ISBLK (f->stat.st_mode))
    sprintf (p, "%3u, %3u ", (unsigned) major (f->stat.st_rdev),
         (unsigned) minor (f->stat.st_rdev));
  else
    {
      char hbuf[LONGEST_HUMAN_READABLE + 1];
      //sprintf (p, "%8s ",
      sprintf (p, "%*s ", long_block_size_size, // AEK
           human_readable ((uintmax_t) f->stat.st_size, hbuf, 1,
                   output_block_size < 0 ? output_block_size : 1));
    }

  p += strlen (p);

  if ((when_local = localtime (&when)))
    {
      time_t six_months_ago;
      int recent;
      char const *fmt;

      /* If the file appears to be in the future, update the current
     time, in case the file happens to have been modified since
     the last time we checked the clock.  */
      if (current_time < when
      || (current_time == when && current_time_ns < when_ns))
    get_current_time ();

      /* Consider a time to be recent if it is within the past six
     months.  A Gregorian year has 365.2425 * 24 * 60 * 60 ==
     31556952 seconds on the average.  Write this value as an
     integer constant to avoid floating point hassles.  */
      six_months_ago = current_time - 31556952 / 2;
      recent = (six_months_ago <= when
        && (when < current_time
            || (when == current_time && when_ns <= current_time_ns)));
      fmt = long_time_format[recent];

      for (;;)
    {
      char *newbuf;
      *p = '\1';
      s = strftime (p, buf + bufsize - p - 1, fmt, when_local);
      if (s || ! *p)
        break;
      newbuf = alloca (bufsize *= 2);
      memcpy (newbuf, buf, p - buf);
      p = newbuf + (p - buf);
      buf = newbuf;
    }

      {
    //
    // Manually chop the leading zero from day-of-month.  This is needed
    // because Win32 strftime does not have "%e" format - AEK
    //
    char *sz;
    if ((sz = _mbschr(p, '0')) != NULL) {
      if (sz[-1] == ' ' && sz[2] == ' ') {
        *sz = ' ';
      }
    }
      }

      p += s;
      *p++ = ' ';

      /* NUL-terminate the string -- fputs (via DIRED_FPUTS) requires it.  */
      *p = '\0';
    }
  else
    {
      /* The time cannot be represented as a local time;
     print it as a huge integer number of seconds.  */
      char hbuf[LONGEST_HUMAN_READABLE + 1];
      int width = long_time_expected_width ();

      if (when < 0)
    {
      // BUG: use signed __int64 - AEK
      //const char *num = human_readable (- (uintmax_t) when, hbuf, 1, 1);
      const char *num = human_readable (- (__int64) when, hbuf, 1, 1);
      int sign_width = width - strlen (num);
      sprintf (p, "%*s%s ", sign_width < 0 ? 0 : sign_width, "-", num);
    }
      else
    sprintf (p, "%*s ", width,
         human_readable ((uintmax_t) when, hbuf, 1, 1));

      p += strlen (p);
    }

  DIRED_INDENT ();
  DIRED_FPUTS (buf, stdmore, p - buf);
  print_name_with_quoting (f->name, FILE_OR_LINK_MODE (f), f->linkok,
               &dired_obstack);

  if (f->filetype == symbolic_link)
    {
      if (f->linkname)
    {
      DIRED_FPUTS_LITERAL (" -> ", stdmore);
      print_name_with_quoting (f->linkname, f->linkmode, f->linkok - 1,
                   NULL);
      if (indicator_style != none)
            print_type_indicator (&((struct fileinfo *)f)->stat, f->linkmode);  // RIVY
    }
    }
  else if (indicator_style != none)
    print_type_indicator (&((struct fileinfo *)f)->stat, f->stat.st_mode);     // RIVY
}

/* Output to OUT a quoted representation of the file name NAME,
   using OPTIONS to control quoting.  Produce no output if OUT is NULL.
   Return the number of screen columns occupied by NAME's quoted
   representation.  */

static size_t
quote_name (MORE *out, const char *name, struct quoting_options const *options)
{
  char smallbuf[BUFSIZ];
  size_t len = quotearg_buffer (smallbuf, sizeof smallbuf, name, -1, options);
  char *buf;
  int displayed_width;

  if (len < sizeof smallbuf)
    buf = smallbuf;
  else
    {
      buf = (char *) alloca (len + 1);
      quotearg_buffer (buf, len + 1, name, -1, options);
    }

  if (qmark_funny_chars)
    {
#if HAVE_MBRTOWC
      if (MB_CUR_MAX > 1)
    {
      const char *p = buf;
      char *plimit = buf + len;
      char *q = buf;
      displayed_width = 0;

      while (p < plimit)
        switch (*p)
          {
        case ' ': case '!': case '"': case '#': case '%':
        case '&': case '\'': case '(': case ')': case '*':
        case '+': case ',': case '-': case '.': case '/':
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        case ':': case ';': case '<': case '=': case '>':
        case '?':
        case 'A': case 'B': case 'C': case 'D': case 'E':
        case 'F': case 'G': case 'H': case 'I': case 'J':
        case 'K': case 'L': case 'M': case 'N': case 'O':
        case 'P': case 'Q': case 'R': case 'S': case 'T':
        case 'U': case 'V': case 'W': case 'X': case 'Y':
        case 'Z':
        case '[': case '\\': case ']': case '^': case '_':
        case 'a': case 'b': case 'c': case 'd': case 'e':
        case 'f': case 'g': case 'h': case 'i': case 'j':
        case 'k': case 'l': case 'm': case 'n': case 'o':
        case 'p': case 'q': case 'r': case 's': case 't':
        case 'u': case 'v': case 'w': case 'x': case 'y':
        case 'z': case '{': case '|': case '}': case '~':
          /* These characters are printable ASCII characters.  */
          *q++ = *p++;
          displayed_width += 1;
          break;
        default:
          /* If we have a multibyte sequence, copy it until we
             reach its end, replacing each non-printable multibyte
             character with a single question mark.  */
          {
            mbstate_t mbstate;
            memset (&mbstate, 0, sizeof mbstate);
            do
              {
            wchar_t wc;
            size_t bytes;
            int w;

            bytes = mbrtowc (&wc, p, plimit - p, &mbstate);

            if (bytes == (size_t) -1)
              {
                /* An invalid multibyte sequence was
                   encountered.  Skip one input byte, and
                   put a question mark.  */
                p++;
                *q++ = '?';
                displayed_width += 1;
                break;
              }

            if (bytes == (size_t) -2)
              {
                /* An incomplete multibyte character
                   at the end.  Replace it entirely with
                   a question mark.  */
                p = plimit;
                *q++ = '?';
                displayed_width += 1;
                break;
              }

            if (bytes == 0)
              /* A null wide character was encountered.  */
              bytes = 1;

            w = wcwidth (wc);
            if (w >= 0)
              {
                /* A printable multibyte character.
                   Keep it.  */
                for (; bytes > 0; --bytes)
                  *q++ = *p++;
                displayed_width += w;
              }
            else
              {
                /* An unprintable multibyte character.
                   Replace it entirely with a question
                   mark.  */
                p += bytes;
                *q++ = '?';
                displayed_width += 1;
              }
              }
            while (! mbsinit (&mbstate));
          }
          break;
          }

      /* The buffer may have shrunk.  */
      len = q - buf;
    }
      else
#endif
    {
      char *p = buf;
      char *plimit = buf + len;

      while (p < plimit)
        {
          if (! ISPRINT ((unsigned char) *p))
        *p = '?';
          p++;
        }
      displayed_width = len;
    }
    }
  else
    {
      /* Assume unprintable characters have a displayed_width of 1.  */
#if HAVE_MBRTOWC
      if (MB_CUR_MAX > 1)
    displayed_width = mbsnwidth (buf, len,
                     (MBSW_ACCEPT_INVALID
                      | MBSW_ACCEPT_UNPRINTABLE));
      else
#endif
    displayed_width = len;
    }

#ifdef WIN32
  {
    //
    // Change forward slashes to backslashes on WIN32 - AEK
    //
    char *sz;
    for (sz = _mbschr(buf, '/'); sz; sz = _mbschr(sz+1, '/')) {
      *sz = '\\';
    }
  }
#endif

  if (out != NULL)
    more_fwrite (buf, 1, len, out); // AEK
  return displayed_width;
}

static void
print_name_with_quoting (const char *p, unsigned int mode, int linkok,
             struct obstack *stack)
{
  if (print_with_color)
    print_color_indicator (p, mode, linkok);

  if (stack)
    PUSH_CURRENT_DIRED_POS (stack);

  dired_pos += quote_name (stdmore, p, filename_quoting_options);

  if (stack)
    PUSH_CURRENT_DIRED_POS (stack);

  if (print_with_color)
    prep_non_filename_text ();
}

static void
prep_non_filename_text (void)
{
  if (color_indicator[C_END].string != NULL)
    put_indicator (&color_indicator[C_END]);
  else
    {
      put_indicator (&color_indicator[C_LEFT]);
      put_indicator (&color_indicator[C_NORM]);
      put_indicator (&color_indicator[C_RIGHT]);
    }
}

/* Print the file name of `f' with appropriate quoting.
   Also print file size, inode number, and filetype indicator character,
   as requested by switches.  */

static void
print_file_name_and_frills (const struct fileinfo *f)
{
  char buf[LONGEST_HUMAN_READABLE + 1];

  if (print_inode)
    more_printf ("%*s ", INODE_DIGITS,
        human_readable ((uintmax_t) f->stat.st_ino, buf, 1, 1));

  if (print_block_size)
    more_printf ("%*s ", block_size_size,
        human_readable_inexact ((uintmax_t) ST_NBLOCKS (f->stat), buf,
                    ST_NBLOCKSIZE, output_block_size,
                    human_ceiling));

  print_name_with_quoting (f->name, FILE_OR_LINK_MODE (f), f->linkok, NULL);

  if (indicator_style != none)
    print_type_indicator (&((struct fileinfo *)f)->stat, f->stat.st_mode);     // RIVY
}

static void
//print_type_indicator (unsigned int mode)
print_type_indicator (struct stat *pst, unsigned int mode)  // AEK
{
  int c=0; // AEK

  if (S_ISREG (mode))
    {
      if (indicator_style == classify && (mode & S_IXUGO))
    c ='*';
#ifdef WIN32 // AEK
      else if (S_ISSTREAM (mode)) {
    struct cache_entry *ce = pst->st_ce;
    char *s = ce->ce_abspath;
    if (s == NULL || _mbschr(s+2, ':') == NULL) {
      c = '$'; // indicate that the file contains streams
    }
      }
#endif
      else
    c = 0;
    }
  else
    {
      if (S_ISDIR (mode))
#if WIN32
    c = '\\';
#else
    c = '/';
#endif
      else if (S_ISLNK (mode))
    c = '@';
      else if (S_ISFIFO (mode))
    c = '|';
      else if (S_ISSOCK (mode))
    c = '=';
      else if (S_ISDOOR (mode))
    c = '>';
      else
    c = 0;
    }

  if (c)
    DIRED_PUTCHAR ((char)c);
}

static void
print_color_indicator (const char *name, unsigned int mode, int linkok)
{
  int type = C_FILE;
  int recent=0, compressed=0, streams=0; // AEK
  struct color_ext_type *ext;   /* Color extension */
  size_t len;           /* Length of name */

  /* Is this a nonexistent file?  If so, linkok == -1.  */

  if (linkok == -1 && color_indicator[C_MISSING].string != NULL)
    {
      ext = NULL;
      type = C_MISSING;
    }
  else
    {
      if (S_ISDIR (mode))
    type = C_DIR;
      else if (S_ISLNK (mode))
    type = ((!linkok && color_indicator[C_ORPHAN].string)
        ? C_ORPHAN : C_LINK);
      else if (S_ISFIFO (mode))
    type = C_FIFO;
      else if (S_ISSOCK (mode))
    type = C_SOCK;
      else if (S_ISBLK (mode))
    type = C_BLK;
      else if (S_ISCHR (mode))
    type = C_CHR;
      else if (S_ISDOOR (mode))
    type = C_DOOR;

      if (type == C_FILE && (mode & S_IXUGO) != 0)
    type = C_EXEC;

      /* Check the file's suffix only if still classified as C_FILE.  */
      ext = NULL;
      if (type == C_FILE)
    {
      /* Test if NAME has a recognized suffix.  */

      len = strlen (name);
      name += len;      /* Pointer to final \0.  */
      for (ext = color_ext_list; ext != NULL; ext = ext->next)
        {
          if ((size_t) ext->ext.len <= len
        // was strncmp -- AEK
          && _strnicmp (name - ext->ext.len, ext->ext.string,
                  ext->ext.len) == 0)
        break;
        }
    }
    }

    recent = ((type == C_FILE || type == C_EXEC) && ((mode & S_RECENT) != 0));
    if (color_indicator[C_RECENT].len == 0) {
      recent = 0;
    }

    if (color_compressed) {
      compressed = (((mode & S_COMPR) != 0) && !S_ISDIR(mode));
      if (color_indicator[C_COMPRESSED].len == 0) {
    compressed = 0;
      }
    }

    streams = ((mode & S_STREAM) != 0);
    if (color_indicator[C_STREAMS].len == 0) {
      streams = 0;
    }

#ifdef S_RECENT // AEK
  if (!recent && !compressed && !streams) {
    put_indicator (&color_indicator[C_LEFT]);
    put_indicator (ext ? &(ext->seq) : &color_indicator[type]);
    put_indicator (&color_indicator[C_RIGHT]);
  } else {
    //
    // Concatenate the 'recent' color modifier to the color string
    // (typically an undercore)
    //
    // Ditto 'compressed' and 'streams'
    //
    struct bin_str tmp_str, *str;
    int pos;

    str = (ext ? &(ext->seq) : &color_indicator[type]);
    tmp_str.len = str->len;
    if (streams) {
      tmp_str.len += color_indicator[C_STREAMS].len;
      compressed = 0; // streams overrides compress
      recent = 0; // streams overrides recent
    }
    if (recent) {
      tmp_str.len += color_indicator[C_RECENT].len;
      compressed = 0; // recent overrides compressed
    }
    if (compressed) {
      tmp_str.len += color_indicator[C_COMPRESSED].len;
    }
    tmp_str.string = (char*) alloca(tmp_str.len+1);
    strncpy((char *)tmp_str.string, str->string, str->len);
    pos = str->len;
    if (recent) {
      strncpy((char *)tmp_str.string+pos, color_indicator[C_RECENT].string,
      color_indicator[C_RECENT].len);
      pos += color_indicator[C_RECENT].len;
    }
    if (compressed) {
      strncpy((char *)tmp_str.string+pos, color_indicator[C_COMPRESSED].string,
      color_indicator[C_COMPRESSED].len);
    }
    if (streams) {
      strncpy((char *)tmp_str.string+pos, color_indicator[C_STREAMS].string,
      color_indicator[C_STREAMS].len);
    }

    put_indicator (&color_indicator[C_LEFT]);
    put_indicator (&tmp_str);
    put_indicator (&color_indicator[C_RIGHT]);
  }
#else
  put_indicator (&color_indicator[C_LEFT]);
  put_indicator (ext ? &(ext->seq) : &color_indicator[type]);
  put_indicator (&color_indicator[C_RIGHT]);
#endif

}


#ifdef WIN32 // AEK
//
// Map color escape codes to Win32 console text attributes.
//
static int bConsoleOut = -1;

static int bBold, bUnderscore, bReverse;

//
// Use a heuristic mapping from dircolors colors (MSLS_COLORS)
// to Windows console-mode colors.
//
// The mapping is based on my opinion of aesthetically pleasing
// colors under Win32 console mode.  In particular, some colors
// are intensified to look correct. (Example: red looks brownish w/o intensity)
//
static WORD
_MapColor(DWORD wColor, unsigned long u)
{
  switch (u) {
    case 1:
      bBold = 1;
      break;
    case 4:
      bUnderscore = 1;
      break;
    case 7:
      bReverse = 1;
      break;
    case 30: /* black */
      return (wColor & 0xFFF0);
    case 31: /* red */
      return (wColor & 0XFFF0) | FOREGROUND_RED;
    case 32: /* green */
      return (wColor & 0XFFF0) | FOREGROUND_GREEN;
    case 33: /* yellow */
      return (wColor & 0XFFF0) | FOREGROUND_GREEN | FOREGROUND_RED;
    case 34: /* blue */
      return (wColor & 0XFFF0) | FOREGROUND_BLUE;
    case 35: /* magenta */
      return (wColor & 0XFFF0) | FOREGROUND_BLUE | FOREGROUND_RED;
    case 36: /* cyan */
      return (wColor & 0XFFF0) | FOREGROUND_BLUE | FOREGROUND_GREEN;
    case 37: /* white */
      return (wColor & 0XFFF0) | FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;
    case 40: /* black */
      return (wColor & 0xFF0F);
    case 41: /* red */
      return (wColor & 0XFF0F) | BACKGROUND_RED;
    case 42: /* green */
      return (wColor & 0XFF0F) | BACKGROUND_GREEN;
    case 43: /* yellow */
      return (wColor & 0XFF0F) | BACKGROUND_GREEN | BACKGROUND_RED;
    case 44: /* blue */
      return (wColor & 0XFF0F) | BACKGROUND_BLUE;
    case 45: /* magenta */
      return (wColor & 0XFF0F) | BACKGROUND_BLUE | BACKGROUND_RED;
    case 46: /* cyan */
      return (wColor & 0XFF0F) | BACKGROUND_BLUE | BACKGROUND_GREEN;
    case 47: /* white */
      return (wColor & 0XFF0F) | BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED;
    case 90: /* black */
      return (wColor & 0xFFF0) | FOREGROUND_INTENSITY;
    case 91: /* red */
      return (wColor & 0XFFF0) | FOREGROUND_RED | FOREGROUND_INTENSITY;
    case 92: /* green */
      return (wColor & 0XFFF0) | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case 93: /* yellow */
      return (wColor & 0XFFF0) | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;
    case 94: /* blue */
      return (wColor & 0XFFF0) | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    case 95: /* magenta */
      return (wColor & 0XFFF0) | FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY;
    case 96: /* cyan */
      return (wColor & 0XFFF0) | FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case 97: /* white */
      return (wColor & 0XFFF0) | FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;
    case 100: /* black */
      return (wColor & 0xFF0F) | BACKGROUND_INTENSITY;
    case 101: /* red */
      return (wColor & 0XFF0F) | BACKGROUND_RED | BACKGROUND_INTENSITY;
    case 102: /* green */
      return (wColor & 0XFF0F) | BACKGROUND_GREEN | BACKGROUND_INTENSITY;
    case 103: /* yellow */
      return (wColor & 0XFF0F) | BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_INTENSITY;
    case 104: /* blue */
      return (wColor & 0XFF0F) | BACKGROUND_BLUE | BACKGROUND_INTENSITY;
    case 105: /* magenta */
      return (wColor & 0XFF0F) | BACKGROUND_BLUE | BACKGROUND_RED | BACKGROUND_INTENSITY;
    case 106: /* cyan */
      return (wColor & 0XFF0F) | BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_INTENSITY;
    case 107: /* white */
      return (wColor & 0XFF0F) | BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_INTENSITY;
    }
    return wColor;
}

#define BAD_ESCAPE (unsigned int)(-1)

static unsigned int _ParseEscape(const char **p, const char **p2)
{
  unsigned int ret=0;

  if (**p2 == ';') {
    *p = ++*p2;
    *p2 = *p; errno = 0; ret = strtol(*p, (char **)p2, 10/*base*/);     // RIVY
    if (*p2 == *p || errno != 0) {
      return BAD_ESCAPE;
    }
  }
  return ret;
}


/* Output a color indicator (which may contain nulls).  */
static void
put_indicator (const struct bin_str *ind)
{
  register int i;
  char szBuf[12];
  const char *p, *p2;
  unsigned long u1=0, u2=0, u3=0, u4=0, u5=0;
  WORD wColor;

  p = ind->string;

  if (bConsoleOut == -1) {
    bConsoleOut = _HasConsole() && isatty(STDOUT_FILENO);
  }

  //
  // If shutting down, dont change colors to prevent races with
  // the signal thread.
  //
  if (bFreezeColors) {
    return;
  }

  if (!bConsoleOut) {
    //
    // Output escape sequences a la Unix.  Only do this if we
    // are running under a GUI, e.g., under Emacs or rxvt.
    //
    for (i = ind->len; i > 0; --i)
      more_putchar (*(p++));
    return;
  }

  //
  // NUL-terminate the string in a temp buf
  //
  i = ind->len;
  if (i >= sizeof(szBuf)) {
    i = sizeof(szBuf)-1;
  }
  lstrcpyn(szBuf, p, i+1);
  p = szBuf;

  //
  // Set console color via SetConsoleTextAtttribute()
  //
  // Parse MSLS_COLORS escape codes.
  //
  // Format: ll;mm;nn;oo;pp (any order, ';...' optional)
  //
  // ll = Attribute codes:
  //    00=none, 01=bold, 04=underscore, 05=blink, 07=reverse, 08=concealed
  //
  // nn = Foregroud color codes:
  //    30=black, 31=red, 32=green, 33=yellow, 34=blue, 35=magenta,
  //    36=cyan, 37=white
  //
  // nn = Background color codes:
  //    40=black, 41=red, 42=green, 43=yellow, 44=blue, 45=magenta,
  //    46=cyan, 47=white
  //
  if (*p == 'm') { // ignore C_RIGHT
    return;
  }

  if (!(*p >= '0' && *p <= '9')) {
    return; // ignore
  }

  p2 = p; errno = 0; u1 = strtoul(p, &(char *)p2, 10/*base*/);  // RIVY
  if (p2 == p || errno != 0) {
    return; // not a number
  }

  if ((u2 = _ParseEscape(&p, &p2)) == BAD_ESCAPE) return;
  if ((u3 = _ParseEscape(&p, &p2)) == BAD_ESCAPE) return;
  if ((u4 = _ParseEscape(&p, &p2)) == BAD_ESCAPE) return;
  if ((u5 = _ParseEscape(&p, &p2)) == BAD_ESCAPE) return;

  bBold = 0;
  bReverse = 0;
  bUnderscore = 0;
  wColor = wDefaultColors;
  //
  // Apply color mappings
  //
  wColor = _MapColor(wColor, u1);
  wColor = _MapColor(wColor, u2);
  wColor = _MapColor(wColor, u3);
  wColor = _MapColor(wColor, u4);

  //
  // Underscores are typically used to flag files with recent changes.
  // Because Win32 consoles do not have real underscores, use heuristic color
  // changes instead.
  //
  if (bUnderscore) {
    if ((wColor & 0x7) != (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)) {
      //
      // Use reverse to simulate underscore for non-white chars
      //
      bReverse = 1;
    }
  }
  if (bReverse) {
    wColor = ((wColor << 4) & 0xF0) | ((wColor >> 4) & 0xF);
    wColor &= ~BACKGROUND_INTENSITY;
    if ((wColor & 0xF) == 0/*black foreground*/) {
      wColor &= ~FOREGROUND_INTENSITY; // blacker
    } else {
      wColor |= FOREGROUND_INTENSITY; // brighter
    }
  } else {
    if (bUnderscore) {
      if ((wColor & 0xF) == (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)) {
    //
    // Use highlight to simulate underscore for white chars
    //
    wColor |= FOREGROUND_INTENSITY;
      }
    }
    if (bBold) {
      wColor |= FOREGROUND_INTENSITY;
    }
  }

  more_fflush(stdmore);
  //fflush(stdout);

  // Check again in case of races -- fflush can be slow
  if (bFreezeColors) {
    return;
  }

  SetConsoleTextAttribute(hStdOut, wColor);

  return;
}

#else // !WIN32

/* Output a color indicator (which may contain nulls).  */
static void
put_indicator (const struct bin_str *ind)
{
  register int i;
  register const char *p;

  p = ind->string;

  for (i = ind->len; i > 0; --i)
    more_putchar (*(p++));
}
#endif // !WIN32

static int
length_of_file_name_and_frills (const struct fileinfo *f)
{
  register int len = 0;

  if (print_inode)
    len += INODE_DIGITS + 1;

  if (print_block_size)
    len += 1 + block_size_size;

  len += quote_name (NULL, f->name, filename_quoting_options);

  if (indicator_style != none)
    {
      unsigned filetype = f->stat.st_mode;

      if (S_ISREG (filetype))
    {
      if (indicator_style == classify
          && (f->stat.st_mode & S_IXUGO))
        len += 1;
#ifdef WIN32 // AEK
      else if (S_ISSTREAM (filetype)) {
        struct cache_entry *ce = f->stat.st_ce;
        char *s = ce->ce_abspath;
        if (s == NULL || _mbschr(s+2, ':') == NULL) { // not stream itself
        len += 1; // space for '$' suffix
        }
      }
#endif
    }
      else if (S_ISDIR (filetype)
           || S_ISLNK (filetype)
           || S_ISFIFO (filetype)
           || S_ISSOCK (filetype)
           || S_ISDOOR (filetype)
           )
    len += 1;
    }

  return len;
}

static void
print_many_per_line (void)
{
  struct column_info *line_fmt;
  int filesno;          /* Index into files. */
  int row;              /* Current row. */
  int max_name_length;  /* Length of longest file name + frills. */
  int name_length;      /* Length of each file name + frills. */
  int pos;              /* Current character column. */
  int cols;             /* Number of files across. */
  int rows;             /* Maximum number of files down. */
  int max_cols;

  /* Normally the maximum number of columns is determined by the
     screen width.  But if few files are available this might limit it
     as well.  */
  max_cols = max_idx > files_index ? files_index : max_idx;

  /* Compute the maximum number of possible columns.  */
  for (filesno = 0; filesno < files_index; ++filesno)
    {
      int i;

      name_length = length_of_file_name_and_frills (files + filesno);

      for (i = 0; i < max_cols; ++i)
    {
      if (column_info[i].valid_len)
        {
          int idx = filesno / ((files_index + i) / (i + 1));
          int real_length = name_length + (idx == i ? 0 : 2);

          if (real_length > column_info[i].col_arr[idx])
        {
          column_info[i].line_len += (real_length
                       - column_info[i].col_arr[idx]);
          column_info[i].col_arr[idx] = real_length;
          column_info[i].valid_len = column_info[i].line_len < line_length;
        }
        }
    }
    }

  /* Find maximum allowed columns.  */
  for (cols = max_cols; cols > 1; --cols)
    {
      if (column_info[cols - 1].valid_len)
    break;
    }

  line_fmt = &column_info[cols - 1];

  /* Calculate the number of rows that will be in each column except possibly
     for a short column on the right. */
  rows = files_index / cols + (files_index % cols != 0);

  for (row = 0; row < rows; row++)
    {
      int col = 0;
      filesno = row;
      pos = 0;
      /* Print the next row.  */
      while (1)
    {
      print_file_name_and_frills (files + filesno);
      name_length = length_of_file_name_and_frills (files + filesno);
      max_name_length = line_fmt->col_arr[col++];

      filesno += rows;
      if (filesno >= files_index)
        break;

      indent (pos + name_length, pos + max_name_length);
      pos += max_name_length;
    }
      more_putchar ('\n');
    }
}

static void
print_horizontal (void)
{
  struct column_info *line_fmt;
  int filesno;
  int max_name_length;
  int name_length;
  int cols;
  int pos;
  int max_cols;

  /* Normally the maximum number of columns is determined by the
     screen width.  But if few files are available this might limit it
     as well.  */
  max_cols = max_idx > files_index ? files_index : max_idx;

  /* Compute the maximum file name length.  */
  max_name_length = 0;
  for (filesno = 0; filesno < files_index; ++filesno)
    {
      int i;

      name_length = length_of_file_name_and_frills (files + filesno);

      for (i = 0; i < max_cols; ++i)
    {
      if (column_info[i].valid_len)
        {
          int idx = filesno % (i + 1);
          int real_length = name_length + (idx == i ? 0 : 2);

          if (real_length > column_info[i].col_arr[idx])
        {
          column_info[i].line_len += (real_length
                       - column_info[i].col_arr[idx]);
          column_info[i].col_arr[idx] = real_length;
          column_info[i].valid_len = column_info[i].line_len < line_length;
        }
        }
    }
    }

  /* Find maximum allowed columns.  */
  for (cols = max_cols; cols > 1; --cols)
    {
      if (column_info[cols - 1].valid_len)
    break;
    }

  line_fmt = &column_info[cols - 1];

  pos = 0;

  /* Print first entry.  */
  print_file_name_and_frills (files);
  name_length = length_of_file_name_and_frills (files);
  max_name_length = line_fmt->col_arr[0];

  /* Now the rest.  */
  for (filesno = 1; filesno < files_index; ++filesno)
    {
      int col = filesno % cols;

      if (col == 0)
    {
      more_putchar ('\n');
      pos = 0;
    }
      else
    {
      indent (pos + name_length, pos + max_name_length);
      pos += max_name_length;
    }

      print_file_name_and_frills (files + filesno);

      name_length = length_of_file_name_and_frills (files + filesno);
      max_name_length = line_fmt->col_arr[col];
    }
  more_putchar ('\n');
}

static void
print_with_commas (void)
{
  int filesno;
  int pos, old_pos;

  pos = 0;

  for (filesno = 0; filesno < files_index; filesno++)
    {
      old_pos = pos;

      pos += length_of_file_name_and_frills (files + filesno);
      if (filesno + 1 < files_index)
    pos += 2;       /* For the comma and space */

      if (old_pos != 0 && pos >= line_length)
    {
      more_putchar ('\n');
      pos -= old_pos;
    }

      print_file_name_and_frills (files + filesno);
      if (filesno + 1 < files_index)
    {
      more_putchar (',');
      more_putchar (' ');
    }
    }
  more_putchar ('\n');
}

/* Assuming cursor is at position FROM, indent up to position TO.
   Use a TAB character instead of two or more spaces whenever possible.  */

static void
indent (int from, int to)
{
  while (from < to)
    {
      if (tabsize > 0 && to / tabsize > (from + 1) / tabsize)
    {
      more_putchar ('\t');
      from += tabsize - from % tabsize;
    }
      else
    {
      more_putchar (' ');
      from++;
    }
    }
}

/* Put DIRNAME/NAME into DEST, handling `.' and `/' properly. */
/* FIXME: maybe remove this function someday.  See about using a
   non-malloc'ing version of path_concat.  */

static void
attach (char *dest, const char *dirname, const char *name)
{
  const char *dirnamep = dirname;

  /* Copy dirname if it is not ".". */
  if (dirname[0] != '.' || dirname[1] != 0)
    {
      while (*dirnamep)
    *dest++ = *dirnamep++;
      /* Add '/' if `dirname' doesn't already end with it. */
      if (dirnamep > dirname && dirnamep[-1] != '/')
#ifdef WIN32 // AEK
       //
       // "C:" + "foo" -> "C:foo"
       //
       if (dirname[0] == '\0' || dirname[1] != ':' || dirname[2] != '\0')
#endif
    *dest++ = '/';
    }
  while (*name)
    *dest++ = *name++;
  *dest = 0;
}

static void
init_column_info (void)
{
  int i;
  int allocate = 0;

  max_idx = line_length / MIN_COLUMN_WIDTH;
  if (max_idx == 0)
    max_idx = 1;

  if (column_info == NULL)
    {
      column_info = (struct column_info *) xmalloc (max_idx
                            * sizeof (struct column_info));
      allocate = 1;
    }

  for (i = 0; i < max_idx; ++i)
    {
      int j;

      column_info[i].valid_len = 1;
      column_info[i].line_len = (i + 1) * MIN_COLUMN_WIDTH;

      if (allocate)
    column_info[i].col_arr = (int *) xmalloc ((i + 1) * sizeof (int));

      for (j = 0; j <= i; ++j)
    column_info[i].col_arr[j] = MIN_COLUMN_WIDTH;
    }
}

void
usage (int status)
{
  if (status != 0)
    more_fprintf (stdmore_err, _("Try `%s --help' for more information.\n"),
         program_name);
  else
    {
      more_printf (_("Usage: %s [OPTION]... [FILE]...\n"), program_name);
      more_printf (_("\
List information about the FILEs (the current directory by default).\n"));
      more_printf (_("\n\
%s version %s for Microsoft Windows.\n"), program_name, VERSION); // AEK
      more_printf (_("\
Microsoft Windows extensions by Alan Klietz\n\
Get the latest version at https://u-tools.com/msls\n")); // AEK
      more_printf (_("\n\
  -a, --all                  do not hide entries starting with .\n\
  -A, --almost-all           do not list implied . and ..\n\
      --acls[=STYLE]         show the file Access Control Lists (ACL):\n\
                               STYLE may be `none', `short', `long',\n\
                               `very-long', or `exhaustive'\n\
      --ansi-cp              use the ANSI code page for output\n\
  -b, --escape               print octal escapes for nongraphic characters\n\
      --block-size=SIZE      use SIZE-byte blocks.  See -s\n\
  -B, --ignore-backups       do not list implied entries ending with ~\n\
  -c                         with -lt: sort by, and show, ctime (time of file\n\
                               creation instead of modification)\n\
                               with -l: show ctime and sort by name\n\
                               otherwise: sort by ctime\n\
  -C                         list entries by columns\n\
      --color[=WHEN]         control whether color is used to distinguish file\n\
                               types.  WHEN may be `never', `always', or `auto'\n\
      --compressed           indicate compressed files with distinct color\n\
                               (requires --color)\n\
  -d, --directory            list directory entries instead of contents\n\
  -D, --dired                generate output designed for Emacs' dired mode\n\
      --encryption-users     show names of users with encryption keys for file\n\
  -f                         do not sort, enable -aU, disable -lst\n\
  -F, --classify             append indicator (one of *\\@$) to entries\n"));

      more_printf (_("\
      --fast                 do not get extended information from slow media\n\
                               such as networks, diskettes, or CD-ROMs\n\
      --format=WORD          across -x, commas -m, horizontal -x, long -l,\n\
                               single-column -1, verbose -l, vertical -C\n\
      --full-time            list both full date and full time\n\
  -g, --groups[=y/n]         show POSIX group information\n\
  -G                         do not show POSIX group information\n\
      --gids[=STYLE]         show POSIX group security identifiers:\n\
                               STYLE may be `long', `short', or `none'\n\
  -h, -H, --human-readable   print sizes in human readable format (1K 234M 2G)\n\
      --si                   likewise, but use powers of 1000 not 1024\n\
  -i, --inode                print index number of each file\n\
  -I, --ignore=PATTERN       do not list implied entries matching shell PATTERN\n\
      --indicator-style=WORD append indicator with style WORD to entry names:\n\
                               none (default), classify (-F), file-type (-p)\n"));
      more_printf (_("\
  -k, --kilobytes            like --block-size=1024\n\
  -K, --registry             show registry keys: hklm, hkcu, hku, hkcr\n\
  -l                         use a long listing format\n\
  -L, --dereference          list entries pointed to by symbolic links\n\
  -m                         fill width with a comma separated list of entries\n\
  -M, --more                 Pause output to the console between each screenful\n\
  -n, --numeric-uid-gid      list numeric UIDs and GIDs instead of names and\n\
                               show Security Identifiers (SIDs) in raw form\n\
  -N, --literal              print raw entry names (don't treat e.g. control\n\
                               characters specially)\n\
  -o                         use long listing format without POSIX group info\n\
      --object-id            show the object ID for the file (if any)\n\
      --oem-cp               use the OEM code page for output\n\
  -p, --file-type            append indicator (one of \\@$) to entries\n\
      --phys-size            report the physical size if the file is\n\
                               compressed or sparse\n"));
      more_printf (_("\
  -q, --hide-control-chars   print ? instead of non graphic characters\n\
      --show-control-chars   show non graphic characters as-is (default\n\
                             unless program is `ls' and output is a terminal)\n\
  -Q, --quote-name           enclose entry names in double quotes\n\
      --quoting-style=WORD   use quoting style WORD for entry names:\n\
                               literal, locale, shell, shell-always, c, escape\n\
  -r, --reverse              reverse order while sorting\n\
  -R, --recursive            list subdirectories recursively\n\
      --recent[=#]           highlight files changed in the last # minutes\n\
                               using a distinctive color\n"));
      more_printf (_("\
      --short-names          show short 8.3 letter file names, a la MS-DOS\n\
      --sids[=STYLE]         show file owner Security Identifiers (SIDs):\n\
                               STYLE may be `long', `short', or `none'.  See -n\n\
  -s, --size                 print size of each file in blocks\n"));
      more_printf (_("\
  -S                         sort by file size\n\
      --slow                 get extended information from slow media such as\n\
                               networks, diskettes, or CD-ROMs (see --fast)\n\
      --sort=WORD            sort by: none -U, size -S, time -t,\n\
                               version -v, extension -X, case\n\
                               status -c, time -t, atime -u, access -u, use -u\n\
      --streams[=y/n]        report files containing streams (-F -p --color)\n\
                               with -l: print the names of the streams\n\
      --time=WORD            show time as WORD instead of modification time:\n\
                               atime, access, use, or ctime (creation time)\n\
                               specified time is sort key if --sort=time\n"));

      more_printf (_("\
      --time-style=STYLE     with -l, show times using style STYLE:\n\
                               full-iso, long-iso, iso, +FORMAT.\n\
                               FORMAT is based on strftime; if FORMAT is\n\
                               FORMAT1!FORMAT2, FORMAT1 applies to\n\
                               non-recent files and FORMAT2 to recent files\n\
"));
      more_printf (_("\
  -t                         sort by modification time\n\
  -T, --tabsize=COLS         assume tab stops at each COLS instead of 8\n\
      --token                show the process token\n\
  -u                         with -lt: sort by, and show, access time\n\
                               with -l: show access time and sort by name\n\
                               otherwise: sort by access time\n\
  -U                         do not sort; list entries in directory order\n\
      --user=NAME            report permissions from the viewpoint of user NAME\n\
  -v                         sort by version\n\
      --view-security        view the file's security, a la Windows Explorer\n\
      --virtual              show the virtual view of files and the registry\n\
                               as seen by pre-Vista legacy applications\n"));
      more_printf (_("\
  -w, --width=COLS           assume screen width instead of current value\n\
  -x                         list entries by lines instead of by columns\n\
  -X                         sort alphabetically by entry extension\n\
  -1                         list one file per line\n\
      --32                   show 32-bit view of files and the registry\n\
      --64                   show 64-bit view of files and the registry\n\
                               (default is --64 on 64-bit operating systems)\n\
      --help                 display this help and exit\n\
      --version              output version information and exit\n\
\n\
By default, color is not used to distinguish types of files.  This is\n\
equivalent to using --color=none.  Using the --color option without an\n\
argument is equivalent to --color=always.  When using --color=auto, color\n\
codes are generated only if the output is a display console.\n\
\n\
Use the environment variable " LS_PREFIX "_OPTIONS to set default options.\n\
Example: -bhAC --more --color=auto --recent --streams\n\
"));
      //more_printf (_("\nReport bugs to <bug-fileutils@gnu.org>."));
    }
  exit (status);
}
/*
vim:tabstop=2:shiftwidth=2:expandtab
*/

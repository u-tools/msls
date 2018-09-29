//
// ls.h
//
#ifdef __cplusplus
extern "C" {
#endif

/* This is for the `ls' program.  */
#define LS_LS 1

/* This is for the `dir' program.  */
#define LS_MULTI_COL 2

/* This is for the `vdir' program.  */
#define LS_LONG_FORMAT 3

enum format
  {
    long_format,        /* -l */
    one_per_line,       /* -1 */
    many_per_line,      /* -C */
    horizontal,         /* -x */
    with_commas         /* -m */
  };

extern enum format format; // make global for dirent.c - AEK

extern int tabsize;

extern int numeric_ids;

extern int run_fast;

///////////////////////////////////////////////////////////////////

enum yes_no_type
{
    no_arg=0,
    yes_arg
};

extern enum yes_no_type show_streams; // AEK

#ifdef WIN32
extern BOOL gbReg; // AEK show registry via -K
extern BOOL gb32bit;  // AEK show 32-bit view of files and registry

extern BOOL gbRegDelVal; // AEK delete registry test-value
extern BOOL gbRegSetVal; // AEK set registry test-value

extern BOOL gbOemCp; // AEK are we using the OEM console codepage?

extern int virtual_view; // --virtual

extern BOOL gbExpandMui; // AEK --expandmui
#endif

///////////////////////////////////////////////////////////////////

enum sids_format
{
  sids_none=0, sids_short, sids_long
};
typedef enum sids_format SIDS_FORMAT, *PSIDS_FORMAT;

extern SIDS_FORMAT sids_format; // AEK
extern SIDS_FORMAT gids_format; // AEK

///////////////////////////////////////////////////////////////////

enum acls_format
{
 acls_none=0, acls_short, acls_long, acls_very_long, acls_exhaustive
};
typedef enum acls_format ACLS_FORMAT, *PACLS_FORMAT;

extern ACLS_FORMAT acls_format; // AEK

///////////////////////////////////////////////////////////////////

extern char *view_as;

#ifdef __cplusplus
}
#endif
/*
vim:tabstop=2:shiftwidth=2:expandtab
*/

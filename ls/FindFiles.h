//
// FindFiles.h
//

#pragma once

#ifndef _FINDFILES_H_
#define _FINDFILES_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef UNDEFINED // not yet, maybe someday..
//////////////////////////////////////////////////////////////////////////
//
// __time64_t replacement functions.  These are included msvcr80.dll
//
#ifndef _TIME64_T_DEFINED
typedef __int64 __time64_t;     /* 64-bit time value */
#define _TIME64_T_DEFINED
#endif

extern struct tm * _localtime64(const __time64_t * _Time);

extern size_t _strftime64(char * _Buf, size_t _SizeInBytes,
    const char * _Format, const struct tm * _Tm);

//////////////////////////////////////////////////////////////////////////
//
// Like _finddatai64_t except use __time64_t
//
struct _aefinddatai64_t {
    unsigned    attrib;
    __time64_t  time_create;    /* -1 for FAT file systems */
    __time64_t  time_access;    /* -1 for FAT file systems */
    __time64_t  time_write;
    __int64     size;
    char        name[260];
};
#endif // UNDEFINED

extern long _aefindfirsti64(const char* szWild, struct _finddatai64_t * pfd);

extern int _aefindnexti64(long hFile, struct _finddatai64_t * pfd);

#ifdef __cplusplus
}
#endif

#endif // _FINDFILES_H_

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

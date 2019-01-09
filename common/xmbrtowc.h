#ifdef WIN32
//
// Implementation of _mbrtowc()
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

#ifdef __cplusplus
extern "C" {
#endif


#if defined(_MSC_VER) && (_MSC_VER < 1900) // If pre-UCRT
extern size_t __cdecl
xmbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *pst);
#define mbrtowc(pwc,s,n,pst) xmbrtowc(pwc,s,n,pst)
#endif

#ifndef __cplusplus
//
// wchar.h forgot to define mbsinit() outside of __cplusplus.
// It is wrong anyway.
//
extern int mbsinit(const mbstate_t *mbs);
#endif

//
// Return the current effective codepage
//
extern int get_codepage();

//
// Set the codepage for console output
//
void SetConsoleCodePage(int cp);
void RestoreConsoleCodePage(); // called at exit
void SetCodePage(int bAnsi);

//
// Return non-zero if the console is using a TrueType (TT) font
//
int IsConsoleFontTrueType();

#ifdef __cplusplus
}
#endif

#endif // WIN32

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

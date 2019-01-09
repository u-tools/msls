//
// Support routines for MS Windows and NTFS
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

#ifdef NEED_DIRENT_H
#include "dirent.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern BOOL IsWindowsNT;
extern BOOL IsWindowsXP;
extern BOOL IsVista;
extern BOOL IsWindows7;

// Like VB Right$()
extern const char *
right(const char *sz, int len);

//
// Some Win32 structs have big-endian DWORD order (highpart,lowpart),
// so we must flip them to create an __int64, which is little-endian
// on x86 architectures.
//
unsigned __int64
_to_unsigned_int64(DWORD dwLowPart, DWORD dwHighPart);

/////////////////////////////////////////////////////////////////////
//
// From the Windows DDK and from "Windows NT/2000 Native API Reference"
// by Gary Nebbett
//
#ifndef NTSTATUS
#define NTSTATUS int
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

//
// Dynamically load a DLL function.
//
// pfn = A *static* pointer-to-function-pointer
typedef int (WINAPI *PFN)();
typedef PFN *PPFN;

#define LOAD_FAIL ((PFN)0xFFFFFFFF) // bad-pfn marker

extern BOOL
DynaLoad(LPSTR szDll, LPSTR szProc, PPFN ppfn/*inout*/);

extern DWORD MapNtStatusToWin32Error(NTSTATUS Status);

///// Wow64

extern DWORD gbIsWindowsWOW64; // not BOOL

/////

//
// Set process privileges (not on Win9x)
//
// Example:
//      LPCSTR aszPrivs[] = {"SeDebugPrivilege", "SeTCBPrivilege"};
//      _SetPrivileges(2, aszPrivs, TRUE);
//
extern BOOL _SetPrivileges(int nPrivs, LPCSTR *ppszPrivilege, BOOL bEnable);
extern BOOL _EnableSecurityPrivilege(); // Enable SeSecurityPrivilege

#ifdef NEED_DIRENT_H
//
// Wrappers for _findfirsti64/_findnexti64/_findclose
//
extern long _xfindfirsti64(const char *szPath, struct _finddatai64_t *pfd,
    BOOL bShowStreams, DWORD dwType);
extern int _xfindnexti64(long handle, struct _finddatai64_t *pfd,
    BOOL bShowStreams);
extern int _xfindclose(long handle, BOOL bShowStreams);

//
// Other helpers
//

extern char *
_GetReparseTarget(struct cache_entry *ce, char *szPath);

extern char *
_GetShortcutTarget(struct cache_entry *ce, char *szPath);

extern char *
_GetRegistryLink(struct cache_entry *ce, char *szPath);

extern BOOL
_GetViewAs(char* szViewAs, PSID pUserSid, DWORD cbSid,
    PTOKEN_GROUPS pTokenGroups, DWORD cbGroups, PDWORD pdwGroupsSize);

time_t ConvertFileTimeToTimeT(PFILETIME pft);

#endif // NEED_DIRENT_H

#ifdef __cplusplus
}
#endif

///////////////////////////////////////////////////////////////////////////
//
// C++ support.  Needed mainly for hash templates taken from the
// U-Tools proprietary AELIB.DLL
//
#ifdef __cplusplus

// non-DLL version
#define EXPORT /**/

#pragma warning(disable: 4127) // constant exprs for TRACE/ASSERT

//
// Standalone ASSERT() and VERIFY()
//
#ifdef _DEBUG
# ifndef ASSERT
#  define ASSERT(x) _ASSERT(x)  // use C lib macro
# endif
# define VERIFY(x) _ASSERT(x)
#else
# ifndef ASSERT
#  define ASSERT(x)
# endif
# define VERIFY(x) ((void)(x))
#endif

#define DLL_ENTRY /**/ // non-DLL version

#undef TRACE
#define TRACE AeTrace
#undef TRACE0
#define TRACE0(sz) AeTrace(_T("%s"), _T(sz))
#undef TRACE1
#define TRACE1(sz,p1) AeTrace(_T(sz),p1)
#undef TRACE2
#define TRACE2(sz,p1,p2) AeTrace(_T(sz),p1,p2)
#undef TRACE3
#define TRACE3(sz,p1,p2,p3) AeTrace(_T(sz),p1,p2,p3)

extern "C" extern void AeTrace(LPCTSTR szFormat, ...);

#define AfxIsMemoryBlock(pData, nBytes) _CrtIsMemoryBlock(pData, nBytes, NULL, NULL, NULL)

#define UNUSED_ALWAYS(x) x

#ifndef __AFX_H__
//
// Abstract iteration position
//
struct __POSITION {};
typedef __POSITION* POSITION;
#define BEFORE_START_POSITION ((POSITION)-1L)
#endif __AFX_H__


#ifdef NEED_CSTR_H
#include <crtdbg.h>
#include <tchar.h>
#include "CStr.h" // CString functions
#endif

#ifdef NEED_HASH_H
#include "Hash.h"

#pragma warning(push)
#pragma warning(disable: 4231) // non-standard extension: extern template

//
// "template<class T> MyClass { T Doit(const T& t); ...};" declares
// a template class.
//
// "template<class T> MyClass<T>::Doit(const T& t) { ... };" defines
// a templated member function.
//

//
// "template<> vector<char>::copy() { ... };" declares a special
// type-specific implementation in order to optimize a frequently used
// type.  This is called explicit specialization or user specialization.
//
// BUG: Microsoft wrongly allows you to omit "template<>" from the
// specialization.
//

//
// "template MyClass<int>;" forces instantiation of all code in the current
// translation unit.
//
// "MyClass<int> v;" instantiates the specialization, but does not necessarily
// create the code (might be merged with dups in other .obj files).
//

//
// MICROSOFT SPECIFIC: Must declare as "extern" all template code that is
// imported from a DLL.  Use explicit instantiation with "extern" and "EXPORT":
// extern template class __declspec(dllimport) MyClass<int>;
//

//
// Declare the instantiation, but do not generate code ("extern" is a MS hack)
//
// CHData<CString> was already instantiated inline by hash.h
//extern template class EXPORT CHData<CString>;
//
// DOCUMENTED BUG: Microsoft STL containers _cannot_ be exported
// w/o compiler errors (except vector<>).  See KB Q168958.
//
// DOCUMENTED BUG: STL containers instantiated in a DLL _cannot_ be
// manipulated in another DLL/EXE (again except for vector<>)
// without causing a GPF, because of a static data member for _Nil.
// See KB Q172396.
// Note: fixed with XTREE patch from http://www.dinkumware.com/vc_fixes.html
//

//
// DOCUMENTED BUG: Microsoft C++ VS6 does not support partial specialization.
// However VS 2005 fixed it for the most typical cases.
//

// DONT USE TEMPLATES BEYOND HASH.H -- IMPOSSIBLE IN VS6 W/O SPECIAL HANDLING.

#pragma warning(pop)

#endif // NEED_HASH_H

#endif // __cplusplus
/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

//////////////////////////////////////////////////////////////////////////
//
// Microsoft Windows support functions
//
// Copyright (c) 2004-2017, U-Tools Software LLC
// Written by Alan Klietz 
// Distributed under GNU General Public License version 2.
//
// $Id: windows-support.c,v 1.8 2016/12/29 22:20:22 cvsalan Exp $
//

#pragma warning(disable: 4305)  // truncated cast ok basetsd.h POINTER_64 - AEK

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "windows-support.h"
#include "xalloc.h"


BOOL IsWindowsNT;
BOOL IsWindowsXP;
BOOL IsVista;
BOOL IsWindows7;

DWORD gbIsWindowsWOW64; // DWORD not BOOL

typedef BOOL (WINAPI *PFNISWOW64PROCESS)(HANDLE hProcess, PBOOL bWow64Process);
static PFNISWOW64PROCESS gpfnIsWow64Process;


void
InitVersion() // also declared in ls.c
{
	OSVERSIONINFOEX OSVersionInfoEx;

	OSVersionInfoEx.dwOSVersionInfoSize = sizeof(OSVersionInfoEx);
	if (!GetVersionEx((OSVERSIONINFO*)&OSVersionInfoEx)) {
		//
		// Fails with larger size under NT pre-SP6; retry with smaller size
		//
		OSVersionInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		GetVersionEx((OSVERSIONINFO*)&OSVersionInfoEx);
	}
	
	IsWindowsNT = (OSVersionInfoEx.dwPlatformId == VER_PLATFORM_WIN32_NT);
	IsWindowsXP = IsWindowsNT &&
		((OSVersionInfoEx.dwMajorVersion == 5 
		 	&& OSVersionInfoEx.dwMinorVersion >= 1) 
		|| OSVersionInfoEx.dwMajorVersion > 5);
	IsVista = IsWindowsNT && OSVersionInfoEx.dwMajorVersion >= 6;
	IsWindows7 = IsVista &&
		((OSVersionInfoEx.dwMajorVersion == 6 
		 	&& OSVersionInfoEx.dwMinorVersion >= 1) 
		|| OSVersionInfoEx.dwMajorVersion > 6);

	//
	// Determine if running in Wow64 mode
	//
	if (DynaLoad("KERNEL32.DLL", "IsWow64Process",
			(PPFN)&gpfnIsWow64Process)) {
		gbIsWindowsWOW64 = 0; // in case sizeof(BOOL) changed to 1
		(*gpfnIsWow64Process)(GetCurrentProcess(), (PBOOL)&gbIsWindowsWOW64);
	} else {
		gbIsWindowsWOW64 = FALSE;
	}

	return;
}


//////////////////////////////////////////////////////////////////////////
//
// Like VB Right$() for comparisons of file suffixes (e.g., ".LNK")
//
const char *
right(const char *sz, int len)
{
	int n;

	n = (int)strlen(sz) - len;
	if (len < 0) {
		return "";
	}
	return &sz[n];
}

//////////////////////////////////////////////////////////////////////////
//
// Stupid WIN32_FIND_DATA has big-endian DWORD order (highpart,lowpart),
// so we must flip the 32-bit high/low pairs to create an __int64.
//
unsigned __int64
_to_unsigned_int64(DWORD dwLowPart, DWORD dwHighPart)
{
	ULARGE_INTEGER ull;

	ull.LowPart = dwLowPart;
	ull.HighPart = dwHighPart;
	return ull.QuadPart;
}

//////////////////////////////////////////////////////////////////////////

//
// Dynamically load a DLL function.
//
// Note: pfn must be a *static* pointer-to-function-pointer for this to work!
//
BOOL DynaLoad(LPSTR szDll, LPSTR szProc, PPFN ppfn/*inout*/)
{
	HANDLE hModule;

	if (*ppfn == LOAD_FAIL) {
		return FALSE; // failed previously
	}
	if (*ppfn != NULL) {
		return TRUE; // worked previously
	}
	//
	// First time: Locate and load the module
	//
	if ((hModule = GetModuleHandle(szDll)) == NULL) {
		//
		// Not loaded; do it now
		//
		if ((hModule = LoadLibrary(szDll)) == NULL) {
			*ppfn = LOAD_FAIL;
			return FALSE;
		}
	}

	if ((*ppfn = (PFN) GetProcAddress(hModule, szProc)) == NULL) {
		*ppfn = LOAD_FAIL;
		return FALSE;
	}
	// Never calls FreeLibrary
	return TRUE;
}

////////////////////////////////////////////////////////////////////////////
//
// Enable/disable process privileges.
//
// Example:
//		LPCSTR aszPrivs[] = {"SeDebugPrivilege", "SeTCBPrivilege"};
//		bOk = _SetPrivileges(2, aszPrivs, TRUE/*enable*/);
//
BOOL _SetPrivileges(int nPrivs, LPCTSTR *ppszPrivilege, BOOL bEnable) 
{
	HANDLE hToken; 
	TOKEN_PRIVILEGES *ptp;
	DWORD dwLen;
	int i;

	if (nPrivs <= 0) {
		return TRUE;
	}

	//
	// Grovel for the privilege LUIDs based on their text names.
	//
	dwLen = sizeof(DWORD) + (sizeof(LUID_AND_ATTRIBUTES)*nPrivs);
	ptp = (PTOKEN_PRIVILEGES) xmalloc(dwLen);
	memset(ptp, 0, dwLen);

	ptp->PrivilegeCount = nPrivs;

	for (i=0; i < nPrivs; ++i) {
		//
		// get the luid for each privilege string
		//
		if (!LookupPrivilegeValue(NULL, ppszPrivilege[i],
				&ptp->Privileges[i].Luid)) {
		    return FALSE;
		}
		if (bEnable) {
			ptp->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;    
		} else {
			ptp->Privileges[i].Attributes &= ~SE_PRIVILEGE_ENABLED;    
		}
	}

	//
	// Obtain the process token
	//
	if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)) {
		free(ptp);
		return FALSE;
	}
	//
	// Finally, enable or disable the privileges
	//
	if (!AdjustTokenPrivileges(hToken, FALSE, ptp, 0,
				(PTOKEN_PRIVILEGES)NULL, NULL) || GetLastError() != 0) {
		DWORD dwError = GetLastError();
		CloseHandle(hToken);
		free(ptp);
		SetLastError(dwError);
		return FALSE;
	}
	CloseHandle(hToken);
	free(ptp);
	//
	// Easy! :-)
	//
	return TRUE;
}

//////////////////////////////////////////////////////////////////

static LPCSTR aszSecurityPrivs[] = { "SeSecurityPrivilege" };

//
// Enable SeSecurityPrivilege for reading SACLs
// Typically requires Administrators group
//
BOOL _EnableSecurityPrivilege()
{
	static int priv_status = -1; // 0, 1, or -1 (unknown)

	if (priv_status != -1) { // if previously attempted
		return (priv_status == 1); // return previous result
	}
	priv_status = _SetPrivileges(1, aszSecurityPrivs, TRUE);
	return priv_status;
}

//////////////////////////////////////////////////////////////////

//
// Handler for TRACE macros
//
void AeTrace(LPCTSTR szFormat, ...)
{
#ifndef _DEBUG
	UNREFERENCED_PARAMETER(szFormat);
	return;
#else
	TCHAR szText[1024+4]; // wvprintf limited to 1024 bytes
	int iLen;

	va_list args;
	va_start(args, szFormat);
	iLen = wvsprintf(szText, szFormat, args);
	va_end(args);

	if (iLen <= 0) {
		return;
	}

	OutputDebugString(szText);
#endif // _DEBUG
}

/*
vim:tabstop=4:shiftwidth=4:noexpandtab
*/

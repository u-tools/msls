//
// Stand-alone mini-CString
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
// For VC6, disable warnings from various standard Windows headers
// NOTE: #pragma warning(push) ... #pragma warning(pop) is broken/unusable for MSVC 6 (re-enables multiple other warnings)
#pragma warning(disable: 4068)  // DISABLE: unknown pragma warning
#pragma warning(disable: 4035)  // DISABLE: no return value warning
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <crtdbg.h>

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
#pragma warning(default: 4068)  // RESET: unknown pragma warning
#pragma warning(default: 4035)  // RESET: no return value warning
#endif

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>

#define NEED_CSTR_H
#include "windows-support.h"

EXPORT CString::CString(const CString& strSrc) {
    *this = strSrc.GetData(); // invokes CString::operator=(LPCTSTR sz)
}

EXPORT CString::CString(LPCSTR sz)
{
    int iLen = (sz == NULL ? 0 : (int)strlen(sz));
    if (iLen == 0) {
        m_szBuf = NULL;
        m_iLen = 0;
    } else {
        _alloc(iLen);
        memcpy(m_szBuf, sz, iLen);
    }
}

void CString::_alloc(int iLen)
{
    if (iLen <= 0) {
        m_szBuf = NULL;
        m_iLen = 0 ;
    } else {
        m_iLen = iLen;
        m_szBuf = new char[iLen+1]; // add space for terminating \0
        m_szBuf[iLen] = '\0';
    }
}

EXPORT CString::~CString()
{
    if (m_szBuf == NULL) return;
    delete [] m_szBuf; m_szBuf = NULL;
}

EXPORT CString& CString::operator=(const CString& stringSrc)
{
    if (m_szBuf != stringSrc.GetData()) {
        if (m_szBuf != NULL) {
            delete [] m_szBuf; m_szBuf = NULL;
        }
        int nSrcLen = stringSrc.GetLength();
        _alloc(nSrcLen);
        if (nSrcLen > 0) {
            memcpy(m_szBuf, stringSrc.GetData(), nSrcLen);
        }
    }
    return *this;
}

EXPORT CString& CString::operator=(LPCSTR sz)
{
    int nSrcLen = (sz == NULL ? 0 : strlen(sz));
    _alloc(nSrcLen);
    if (nSrcLen > 0) {
        memcpy(m_szBuf, sz, nSrcLen);
    }
    return *this;
}

EXPORT BOOL operator==(const CString& s1, const CString& s2)
    { return s1.Equal(s2) == 0; }
EXPORT BOOL operator!=(const CString& s1, const CString& s2)
    { return s1.Equal(s2) != 0; }
/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

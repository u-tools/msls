//
// cstr.h - Stand-alone mini-CString
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

///////////////////////////////////////////////////////////////////////////////

class EXPORT CString
{
public:
    CString() { m_szBuf = NULL; };
    CString(const CString& stringSrc);
    CString(LPCSTR psz);
    ~CString();

    // cast to LPCTSTR
    operator LPCTSTR() const { return m_szBuf == NULL ? "" : m_szBuf; };

    // assignment
    CString& operator=(const CString& stringSrc);
    CString& operator=(LPCSTR sz);

    LPCTSTR GetData() const { return m_szBuf; };
    int GetLength() const { return m_iLen; };

    int Equal(LPCTSTR sz) const { return _tcscmp(m_szBuf == NULL ? "" : m_szBuf, sz); };

    BOOL IsEmpty() const { return m_iLen == 0; };

private:
    void _alloc(int iLen);

private:
    LPTSTR m_szBuf;
    int m_iLen;
};

EXPORT extern BOOL operator==(const CString& s1, const CString& s2);
EXPORT extern BOOL operator!=(const CString& s1, const CString& s2);

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

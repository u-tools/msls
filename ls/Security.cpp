//////////////////////////////////////////////////////////////////////////
//
// Security.cpp - Security translation layer for WIN32
//
// Copyright (c) 2007-2018, U-Tools Software LLC
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
#include <ole2.h>

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
#pragma warning(default: 4068)  // RESET: unknown pragma warning
#pragma warning(default: 4035)  // RESET: no return value warning
#endif

#include <wincrypt.h> // prereq for winefs.h
#include <winefs.h>  // for QueryUsersOnEncryptedFile
#include <aclapi.h> // for Trustee
#include <sddl.h> // for SDDL_REVISION_1
#include <aclui.h> // for EditSecurity dialog

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <mbstring.h>

#include <errno.h>

#include <system.h> // for alloca()

#ifndef LABEL_SECURITY_INFORMATION
# define LABEL_SECURITY_INFORMATION (0x10)   // Return S-1-16-xxxx ACEs in SACL
#endif

//
// Stupid MSVC doesn't define __STDC__
//
#ifndef __STDC__
# define __STDC__ 1
#endif

#include "filemode.h"
#include "error.h"
#include "more.h"

#define NEED_DIRENT_H
#define NEED_CSTR_H
#define NEED_HASH_H
#include "windows-support.h"
#include "xalloc.h"
#include "xmbrtowc.h" // for get_codepage()
#include "ls.h" // for sids_format, gids_format

#ifndef SYSTEM_MANDATORY_LABEL_ACE_TYPE
# define SYSTEM_MANDATORY_LABEL_ACE_TYPE 0x11 // Vista Integrity ACE in SACL
#endif

#ifndef SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
# define SYSTEM_MANDATORY_LABEL_NO_WRITE_UP 0x1
#endif
#ifndef SYSTEM_MANDATORY_LABEL_NO_READ_UP
# define SYSTEM_MANDATORY_LABEL_NO_READ_UP 0x2
#endif
#ifndef SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
# define SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP 0x4
#endif

#undef strrchr
#define strrchr _mbsrchr // use the multibyte version of strrchr

BOOL gbComInitialized; // CoInitialize has been called

static DWORD gdwSdSerial = 1;  // next SD serial # to allocate

#pragma warning(disable: 4057) // ignore unsigned char* vs char*

/*
   Security on Windows is difficult to understand.  The best way
   to master it is to follow it historically.
   Each layer is backward compatible.  Start with Windows NT,
   then study Windows 2000, XP, Vista, and Win7/Win10 in that order.

   Some of the cruft can be ignored.  For example, object ACEs
   are used only for Active Directory and are not applicable
   to files or registry keys.

   The complexity means it is easy to blunder when enforcing
   your security policy.  You need to understand innumerable rules
   and special cases, many of which are barely documented or outright
   undocumented.

   The whole thing should be scrapped and redesigned.
*/

/*
    A SID is a Security Identifier that uniquely identifies a
    security principal.  A security principal is a person, a computer,
    or some other entity that can modify a secured object.

    The SID format is S-R-I-S-S...

    S identifies the series of digits as a SID (literally 'S'),
    R is the revision level (always '1'),
    I is the identifier-authority value (48 bits, but see below),
    S is subauthority value(s) (32 bits for each).

    An SID could be written in this notation as follows:
    S-1-5-32-544

    In this example,
      The SID has a revision level of 1,
      an identifier-authority value of 5,
      a first subauthority value of 32,
      and a second subauthority value of 544.

    In this example S-1-5-32-544 is the local Administrators group.
    The SID prefix is S-1-5-32 and the Relative Identifier (RID)
    is 544.  The RID is always the last subauthority value.

    When displayed the SID string will take one of two forms.  If the
    IdentifierAuthority value is not greater than 2^32, then the SID
    will be in the form:

    S-1-5-21-2127521184-1604012920-1887927527-19009
      ^ ^ ^^ ^^^^^^^^^^ ^^^^^^^^^^ ^^^^^^^^^^ ^^^^^
      | | |      |          |          |        |
      +-+-+------+----------+----------+--------+--- Decimal

    This is true for 99%+ of all SIDs.

    In _very_ rare cases a SID will take the form:

    S-1-0x206C277C6666-21-2127521184-1604012920-1887927527-19009
      ^ ^^^^^^^^^^^^^^ ^^ ^^^^^^^^^^ ^^^^^^^^^^ ^^^^^^^^^^ ^^^^^
      |       |        |      |          |          |        |
      |   Hexadecimal  |      |          |          |        |
      +----------------+------+----------+----------+--------+--- Decimal

    This exposes the fact that the SID authority is technically 48 bits.
    The byte order is big-endian, unlike the rest of Windows.
    To the best of my knowledge the 'large' format SID has never been used
    on a real computer in production use.

    99%+ of the time the IdentifierAuthority is 1, 3, 5, 16, or 80.

    1 = (S-1-1-0 Everyone), 3 = (S-1-3-0 CREATOR OWNER),
    5 = (S-1-5-.. User/Group/Computer), 16 = (S-1-16 Vista mandatory ACE)
    80 = (S-1-80 Service SID, mapped from service name text)
*/

/////////////////////////////////////////////////////////////////////////////
//
// SID class that supports assignment (required for hash.h)
//
#define SID AESID  // avoid clash with winnt.h's SID struct
class SID {

public:
    SID() { m_pSid = NULL; };
    SID(PSID pSid) { m_pSid = NULL; _CloneSid(pSid); };
    SID(const SID& SidSrc) { m_pSid = NULL; _CloneSid(SidSrc.GetSid()); };

    ~SID() { _CloneSid(NULL); };

    PSID GetSid() const { return m_pSid; };

    SID& operator=(const SID& SidSrc) {
        PSID pSidSrc = SidSrc.GetSid();
        _CloneSid(pSidSrc);
        return *this;
    };

    BOOL Equal(PSID pSid) const {
        if (pSid == NULL && m_pSid == NULL) return TRUE;
        if (pSid == NULL || m_pSid == NULL) return FALSE;
        if (!::IsValidSid(pSid) || !::IsValidSid(m_pSid)) {
            return FALSE; // corrupt SIDs are never equal
        }
        return ::EqualSid(pSid, m_pSid);
    };

private:
    void _CloneSid(PSID pSid) {
        if (m_pSid == pSid) return; // important!
        if (m_pSid) { delete [] (PBYTE)m_pSid; m_pSid = NULL; }
        if (pSid == NULL || !::IsValidSid(pSid))  return;
        DWORD dwLen = ::GetLengthSid(pSid);
        m_pSid = (PSID) new BYTE[dwLen];
        memcpy(m_pSid, pSid, dwLen);
    };

    PSID m_pSid; // really PVOID
};

BOOL operator==(const SID& sid1, const SID& sid2) {
    return sid1.Equal(sid2.GetSid());
}
BOOL operator!=(const SID& sid1, const SID& sid2) {
    return !sid1.Equal(sid2.GetSid());
}

//
// CHData<SID> explicit template specialization of SID as a hashable data type
//

//
// Hash the SID
//
template<> inline LONG CHData<SID>::HashVal(const SID& sid)
{
    PSID pSid = sid.GetSid();
    if (pSid == NULL) {
        return 12345678; // arb fixed hash for NULL or bogus sid
    }
    if (!::IsValidSid(pSid)) {
        return 78901234; // arb fixed hash for corrupt sid
    }
    int iLen = ::GetLengthSid(pSid);
    register const unsigned char* p = (const unsigned char*)pSid;
    register LONG x;
    x = *p << 7;
    for (register int i=iLen; --i >= 0;) {
        x = (1000003*x) ^ *p++;
    }
    x ^= iLen;
    if (x == 0 || x == -1) {
        x = -2;
    }
    return x;
}
template<> inline BOOL CHData<SID>::Equal(const SID& sid1, const SID& sid2)
{
    return sid1.Equal(sid2.GetSid());
}
#ifdef _DEBUG
template<> inline void CHData<SID>::Trace(const SID& sid)
{
    UNREFERENCED_PARAMETER(&sid);
    TRACE0(_T("<sid>"));
}
#endif

/////////////////////////////////////////////////////////////////////////////
//
// SECURITY_DESCRIPTOR class that supports assignment (required for hash.h)
//
class SD {

public:
    SD() { m_pSd = NULL; };
    SD(PSECURITY_DESCRIPTOR pSd) { m_pSd = NULL; _CloneSd(pSd); };
    SD(const SD& SdSrc) { m_pSd = NULL; _CloneSd(SdSrc.GetSd()); };

    ~SD() { _CloneSd(NULL); };

    PSECURITY_DESCRIPTOR GetSd() const { return m_pSd; };

    void SetSd(PSECURITY_DESCRIPTOR psd) {
        _CloneSd(psd);
    }

    SD& operator=(const SD& SdSrc) {
        PSECURITY_DESCRIPTOR pSdSrc = SdSrc.GetSd();
        _CloneSd(pSdSrc);
        return *this;
    };

    BOOL Equal(PSECURITY_DESCRIPTOR pSd) const {
        if (pSd == NULL && m_pSd == NULL) return TRUE;
        if (pSd == NULL || m_pSd == NULL) return FALSE;
        if (!::IsValidSecurityDescriptor(pSd) || !::IsValidSecurityDescriptor(m_pSd)) {
            return FALSE; // corrupt SDs are never equal
        }
        DWORD dwLen = ::GetSecurityDescriptorLength(pSd);
        if (dwLen != ::GetSecurityDescriptorLength(m_pSd)) {
            return FALSE; // different lengths
        }
        return (memcmp(pSd, m_pSd, dwLen) == 0);
    };

private:
    void _CloneSd(PSECURITY_DESCRIPTOR pSd) {
        if (m_pSd == pSd) return; // important!
        if (m_pSd) { delete [] (PBYTE)m_pSd; m_pSd = NULL; }
        if (pSd == NULL || !::IsValidSecurityDescriptor(pSd))  return;
        DWORD dwLen = ::GetSecurityDescriptorLength(pSd);

        SECURITY_DESCRIPTOR_CONTROL sdc;
        DWORD dwRevision=0;

        if (::GetSecurityDescriptorControl(pSd, &sdc, &dwRevision)) {
            if ((sdc & SE_SELF_RELATIVE) == 0) {
                error(EXIT_FAILURE, 0, "Tried to encapsulate a non-relative security descriptor.");
                /*NOTREACHED*/
            }
        }

        m_pSd = (PSECURITY_DESCRIPTOR) new BYTE[dwLen];

        memcpy(m_pSd, pSd, dwLen);
    };

    PSECURITY_DESCRIPTOR m_pSd; // really PVOID
};

BOOL operator==(const SD& sd1, const SD& sd2) {
    return sd1.Equal(sd2.GetSd());
}
BOOL operator!=(const SD& sd1, const SD& sd2) {
    return !sd1.Equal(sd2.GetSd());
}

//
// CHData<SD> explicit template specialization of SD as a hashable data type
//

//
// Hash the SD
//
template<> inline LONG CHData<SD>::HashVal(const SD& sd)
{
    PSECURITY_DESCRIPTOR pSd = sd.GetSd();
    if (pSd == NULL) {
        return 12345678; // arb fixed hash for NULL or bogus sd
    }
    if (!::IsValidSecurityDescriptor(pSd)) {
        return 78901234; // arb fixed hash for corrupt sd
    }
    int iLen = ::GetSecurityDescriptorLength(pSd);
    register const unsigned char* p = (const unsigned char*)pSd;
    register LONG x;
    x = *p << 7;
    for (register int i=iLen; --i >= 0;) {
        x = (1000003*x) ^ *p++;
    }
    x ^= iLen;
    if (x == 0 || x == -1) {
        x = -2;
    }
    return x;
}
template<> inline BOOL CHData<SD>::Equal(const SD& sd1, const SD& sd2)
{
    return sd1.Equal(sd2.GetSd());
}
#ifdef _DEBUG
template<> inline void CHData<SD>::Trace(const SD& sd)
{
    UNREFERENCED_PARAMETER(&sd);
    TRACE0(_T("<security descriptor>"));
}
#endif

/////////////////////////////////////////////////////////////////////////////
//
// Hash sids -> user names
//
static CHash<CHData<SID>, CHData<CString> > gMapSidToName;

//
// Hash absolute file paths -> security descriptor serial #
//
static CHash<CHData<CString>, CHData<DWORD> > gMapAbsPathToSdSerial;

//
// Hash security descriptor serial # -> security descriptor
// Must be bidirectional to share SDs
//
static CHash<CHData<DWORD>, CHData<SD> > gMapSdSerialToSd;
static CHash<CHData<SD>, CHData<DWORD> > gMapSdToSdSerial;

///////////////////////////////////////////////////////////////////
//
// Get the NETBIOS security domain for this computer.  Return
// the local computer name if not joined to a domain
//
// Since we dont care about spoofing, just query %USERDOMAIN%.
// No need to futz with the NetXxx APIs here.  (Which is a good
// thing because on Win9x it requires a thunk to a 16-bit DLL).
//
static char *_GetSecurityDomain(void)
{
    static BOOL bInit;
    static char szDomain[64];
    if (bInit) {
        return szDomain;
    }
    bInit = TRUE;

    //
    // Note: Must use _wgetenv because getenv() returns ANSI not OEM
    //
    // BUG: GetEnvironmentStrings returns in OEM,
    // but GetEnvironmentVariable returns ANSI!
    //

    wchar_t *wsz = _wgetenv(L"USERDOMAIN");

    if (wsz != NULL) {
        ::WideCharToMultiByte(get_codepage(), 0,
            wsz, -1,
            szDomain, sizeof(szDomain), NULL, NULL);
    }
    return szDomain;
}

/////////////////////////////////////////////////////////////////////////////
//
// Translate the pSid to text sid "S-1-5-x-y-z-rid"
//
// Note: ConvertSidToStringSid is not available on NT.
//
static BOOL _GetTextualSid(PSID pSid, char *szSidBuf,
    DWORD dwSidBufLen, SIDS_FORMAT eFormat)
{
    PSID_IDENTIFIER_AUTHORITY pSia;
    DWORD dwSubAuthorities;
    DWORD dwSidLen;

    if (!::IsValidSid(pSid)) return FALSE;

    pSia = ::GetSidIdentifierAuthority(pSid);

    dwSubAuthorities = *::GetSidSubAuthorityCount(pSid);

    //
    // Compute the approximate text buffer length
    // S-SID_REVISION- + identifierauthority- + subauthorities- + NULL
    //
    dwSidLen = (15 + 12 + (12 * dwSubAuthorities) + 1) * sizeof(TCHAR);

    if(dwSidBufLen < dwSidLen) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    //
    // Prepare S-SID_REVISION-
    //
    dwSidLen = wsprintf(szSidBuf, _T("S-%lu-"), SID_REVISION );

    //
    // Format SID_IDENTIFIER_AUTHORITY  (BYTE Value[6])
    //
    // SID_IDENTIFIER_AUTHORITY is 6 bytes *big endian*
    //
    // In practice it is always a small integer (1,3,5, or 16).
    // I yet to see a valid SID with any other authority value.
    //
    if ( (pSia->Value[0] != 0) || (pSia->Value[1] != 0) ) {
        //
        // SIA is longer than 4 bytes.  Probably indicates a corrupt SID.
        //
        dwSidLen += wsprintf(szSidBuf + dwSidLen,
                    _T("0x%02hx%02hx%02hx%02hx%02hx%02hx"),
                    (USHORT)pSia->Value[0],
                    (USHORT)pSia->Value[1],
                    (USHORT)pSia->Value[2],
                    (USHORT)pSia->Value[3],
                    (USHORT)pSia->Value[4],
                    (USHORT)pSia->Value[5]);
    } else {
        //
        // SIA fits in a DWORD.  Byte-flip and print it.
        //
        dwSidLen += wsprintf(szSidBuf + dwSidLen,
                    _T("%lu"),
                    (ULONG)(pSia->Value[5]) + // most significant byte=(S-1-*x*)
                    (ULONG)(pSia->Value[4] <<  8)   + // usually 0
                    (ULONG)(pSia->Value[3] << 16)   + // usually 0
                    (ULONG)(pSia->Value[2] << 24)   ); // usually 0
    }

    if (eFormat != sids_long) { // short or none
        //
        // "S-1-5-...-512"
        //
        dwSidLen += wsprintf(szSidBuf + dwSidLen, _T("-...-%lu"),
                *GetSidSubAuthority(pSid, dwSubAuthorities-1));
    } else {
        //
        // "S-1-5-12345678-98765432-31415926-512"
        //
        DWORD i;
        for(i = 0 ; i < dwSubAuthorities ; i++) {
            dwSidLen += wsprintf(szSidBuf + dwSidLen, _T("-%lu"),
                *GetSidSubAuthority(pSid, i));
        }
    }
    return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
//
// Map the SID to a domain and name.
//
// If fails, use a table of well-known SIDS
//
static BOOL _LookupAccountSid(PSID pSid,
    LPSTR szNameBuf, PDWORD pdwLenName,
    LPSTR szDomainBuf, PDWORD pdwLenDomain,
    PSID_NAME_USE peSidNameUse/*out*/)
{
    //
    // First query the system, as we prefer the local language name.
    //
    if (::LookupAccountSid(NULL, pSid,
            szNameBuf, pdwLenName,
            szDomainBuf, pdwLenDomain,
            peSidNameUse/*out ign*/)) {
        return TRUE;
    }

    ///////////////////////////////////////////////////////////////////
    //
    // Lookup failed.  Use our built-in table of well-known SIDs
    //
    struct _aWellKnownSids {
        LPCSTR  m_szSid;
        LPCSTR  m_szDomain;
        LPCSTR  m_szName;
        enum _SID_NAME_USE m_eSidNameUse;
    } aWellKnownSids[] = {
        {
            //
            // UNDOCUMENTED:
            // ::LookupAccountSids() on S-1-5-18 works on XP/Vista,
            // does not work on NT, and possibly works on W2K.
            //
            "S-1-5-18",
            "NT AUTHORITY", "SYSTEM",
            SidTypeUser
        },
        {
            "S-1-5-19",
            "NT AUTHORITY", "LOCAL SERVICE",
            SidTypeUser
        },
        {
            "S-1-5-20",
            "NT AUTHORITY", "NETWORK SERVICE",
            SidTypeUser
        },
        {
            //
            // Used in IO inherited ACEs. Substituted with actual SID
            // upon object creation.
            //
            "S-1-3-0",
            "", "CREATOR OWNER",
            SidTypeUser
        },
        {
            //
            // Vista hack for an ACE to take away WRITE_DACL|READ_CONTROL
            // rights from the object owner.  Usually indicates READ_CONTROL,
            // which therefore denies WRITE_DACL.
            //
            // Changing ownership implicitly strips this ACE from the ACL.
            // Therefore to bypass this ACE, change ownership to another
            // user then claim it back.   Fiddle as needed. Finally recreate
            // the ACE.
            //
            "S-1-3-4",
            "", "OWNER RIGHTS",
            SidTypeUser
        },
        {
            //
            // S-1-5-80-w-x-y-z is a per-service SID,
            // constructed textually (w-x-y-z) from the service name.
            //
            // Used for display when multi-booting XP
            // and looking at Vista files from XP.
            //
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            "NT SERVICE", "TrustedInstaller",
            SidTypeUser
        },
        //
        // SACL label ACEs
        //
        // Uses same text as icacls.exe
        //
        {
            "S-1-16-0",  // Defined in WinNT.h but never seen
            "Mandatory Label","Untrusted Mandatory Level",
            (SID_NAME_USE)10 // SidTypeLabel
        },
        {
            "S-1-16-4096",
            "Mandatory Label","Low Mandatory Level",
            (SID_NAME_USE)10 // SidTypeLabel
        },
        {
            "S-1-16-8192",
            "Mandatory Label","Medium Mandatory Level",
            (SID_NAME_USE)10 // SidTypeLabel
        },
        {
            "S-1-16-8448",  // Defined in WinNT for Win7 SDK, never seen
            "Mandatory Label","MediumPlus Mandatory Level",
            (SID_NAME_USE)10 // SidTypeLabel
        },
        {
            "S-1-16-12288",
            "Mandatory Label","High Mandatory Level",
            (SID_NAME_USE)10 // SidTypeLabel
        },
        {
            "S-1-16-16834",
            "Mandatory Label","System Mandatory Level",
            (SID_NAME_USE)10 // SidTypeLabel
        },
        {
            "S-1-16-20480",
            "Mandatory Label","ProtectedProcess Mandatory Level",
            (SID_NAME_USE)10 // SidTypeLabel
        },
        { NULL, NULL, NULL, SidTypeUser }
    };

    char szSidBuf[128];

    if (!_GetTextualSid(pSid, szSidBuf, 128, sids_long)) {
        return FALSE;
    }

    for (int i=0; aWellKnownSids[i].m_szName != NULL; ++i) {
        if (stricmp(aWellKnownSids[i].m_szSid, szSidBuf) == 0) {

            lstrcpyn(szDomainBuf, aWellKnownSids[i].m_szDomain, *pdwLenDomain);
            *pdwLenDomain = strlen(szDomainBuf);

            lstrcpyn(szNameBuf, aWellKnownSids[i].m_szName, *pdwLenName);
            *pdwLenName = strlen(szNameBuf);

            *peSidNameUse = aWellKnownSids[i].m_eSidNameUse;
            return TRUE;
        }
    }
    return FALSE;
}

/////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////
//
// Map the SID to a user name.  Fall back to a text SID if necessary.
//
// Will always succeed unless insufficient buffer or corrupt sid
//
// Declared also in Token.cpp
//
BOOL LookupSidName(PSID pSid, LPTSTR szBuf, DWORD dwBufLen,
    SIDS_FORMAT eFormat)
{
    char szName[128], szDomain[128];
    DWORD dwLenName, dwLenDomain;
    SID_NAME_USE eSidNameUse;
    //SIDS_FORMAT eFormat = (bGroup ? gids_format : sids_format);

    if (!::IsValidSid(pSid)) return FALSE;

    //
    // Look up the SID in the hash table first
    //
    SID sid(pSid);
    CString strName;
    if (gMapSidToName.Lookup(sid, strName)) {
        //
        // Found a hit
        //
        lstrcpyn(szBuf, (LPCTSTR)strName, dwBufLen);
        return TRUE;
    }

    dwLenDomain = sizeof(szDomain);
    dwLenName = sizeof(szName);

    //
    // Query the LSA for the account name.  Will check the local SAM first.
    // If not found it will pass it up to the domain controller.
    //
    // BUG: No way to specify a shorter timeout if the
    // domain controller is unavailable.  (The default timeout
    // is too long for our purposes.)
    //
    // WORKAROUND (not implemented): If the first lookup fails for
    // a given SID prefix, cache this fact and skip checks on future
    // SIDs with the same prefix.
    //
    if (numeric_ids || !_LookupAccountSid(pSid,
        szName, &dwLenName,
        szDomain, &dwLenDomain,
        &eSidNameUse/*out ign*/)) {

        //
        // Fall back to the textual SID
        //
        if (!_GetTextualSid(pSid, szBuf, dwBufLen, eFormat)) {
            //
            // The SID is corrupt
            //
            return FALSE;
        } else {
            //
            // Add to hash table
            //
            strName = szBuf;
            gMapSidToName.SetAt(sid, strName);
            return TRUE; // found
        }
    }

    if (eFormat != sids_long) {
        //
        // Do not include szDomain if it matches the local computer name
        // (not in a domain) or the default domain (in a domain)
        //
        // Ditto BUILTIN or NT AUTHORITY
        //
        if (_mbsicmp((unsigned char*)szDomain, (unsigned char*)_GetSecurityDomain()) == 0) {
            szDomain[0] = '\0';
        } else if (_stricmp(szDomain,"BUILTIN") == 0) {
            szDomain[0] = '\0';
        } else if (_stricmp(szDomain, "NT AUTHORITY") == 0) {
            szDomain[0] = '\0';
        } else if (_stricmp(szDomain, "Mandatory Label") == 0) {
            szDomain[0] = '\0';
        } else if (_stricmp(szDomain, "NT SERVICE") == 0) {
            // e.g., NT SERVICE\Trusted Installer
            szDomain[0] = '\0';
        } else if (_stricmp(szDomain, "APPLICATION PACKAGE AUTHORITY") == 0) {
            // WinRT app (The RID is typically ALL APPLICATION PACKAGES)
            szDomain[0] = '\0';
        }
    }

    //
    // Build "domain\name"
    //
    if (szDomain[0] == '\0') {
        lstrcpyn(szBuf, szName, dwBufLen);
    } else {
        _snprintf(szBuf, dwBufLen, "%s\\%s", szDomain, szName);
    }

    //
    // Add to hash table
    //
    strName = szBuf;
    gMapSidToName.SetAt(sid, strName);

    return TRUE; // found
}


////////////////////////////////////////////////////////////////////////

BOOL
_LoadSecurityDescriptor(struct cache_entry *ce, SD& rsd)
{
    if (ce->ce_abspath == NULL) {
        //
        // Path is unknown
        //
        return FALSE;
    }

    //
    // Return hardcoded value if --fast and not a fixed disk
    //
    if (run_fast &&
          (ce->dwFileAttributes & FILE_ATTRIBUTE_FIXED_DISK) == 0) {
        //
        // --fast and not a fixed disk
        //
        return FALSE;
    }

    DWORD dwSdSerial=0;
    if (gMapAbsPathToSdSerial.Lookup(ce->ce_abspath, dwSdSerial/*out*/)) {
        if (gMapSdSerialToSd.Lookup(dwSdSerial, rsd)) {
            //
            // Found cache hit
            //
            return TRUE;  // Use psd = sd.GetSd() to extract the psd
        }
    }

    DWORD dwSdLen = 1024; // initial size
    DWORD dwNeededSdLen;
    DWORD dwFlags;
    PSECURITY_DESCRIPTOR psd;
    BOOL bSuccess;

    dwFlags = OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION;

    if (_EnableSecurityPrivilege()) { // if we have SeSecurityPrivilege
        dwFlags |= SACL_SECURITY_INFORMATION; // get SACL too
        if (IsVista) {
            //
            // UNDOCUMENTED: Required to get S-1-16-xxxx SACL ACEs for
            // mandatory integrity labels
            //
            dwFlags |= LABEL_SECURITY_INFORMATION; // get integrity labels too
        }
    }

    do {
        dwNeededSdLen = 0;

        psd = (PSECURITY_DESCRIPTOR) alloca(dwSdLen);

        ///////////////////////////////////////////////////////////////////
        //
        // Get the file's security description
        //
        // WARNING: This call is incredibly *slow* over a network, especially
        // when querying all the files in a directory (ls -l)
        //
        // Thus the reason for the --fast switch, to avoid this call
        // on network files.
        //
        // DESIGN BUG: Microsoft really should provide a way to batch
        // these calls over the wire to avoid the excessive rounds-trips.
        // Perhaps start pre-fetching if there are repeated calls within
        // the same folder?
        //
        ///////////////////////////////////////////////////////////////////

        if (gbReg) {
            bSuccess = _GetRegSecurity(ce->ce_abspath, ce,
               dwFlags, psd, dwSdLen, &dwNeededSdLen);
        } else {
            PVOID pOldState = _push_64bitfs();
            bSuccess = ::GetFileSecurity(ce->ce_abspath,
               dwFlags, psd, dwSdLen, &dwNeededSdLen);
            _pop_64bitfs(pOldState);
        }

        if (bSuccess) {
            //
            // Cache the hit so we will never again
            // GetFileSecurity on this file.
            //
            rsd.SetSd(psd); // return the descriptor in sd (does heap copy)
            //
            // Map abspath -> serial # -> psd
            //
            // This technique saves memory by sharing SDs that are identical
            //
            dwSdSerial=0;
            if (gMapSdToSdSerial.Lookup(rsd, dwSdSerial/*out*/)) {
                gMapAbsPathToSdSerial.SetAt(ce->ce_abspath, dwSdSerial);
            } else {
                gMapAbsPathToSdSerial.SetAt(ce->ce_abspath, gdwSdSerial);
                gMapSdSerialToSd.SetAt(gdwSdSerial, rsd);
                gMapSdToSdSerial.SetAt(rsd, gdwSdSerial);
                ++gdwSdSerial;
            }
        } else {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && dwNeededSdLen < 65536 && dwSdLen < 65536) {
                //
                // Grow size and try again
                //
                if (dwNeededSdLen) {
                    dwSdLen = dwNeededSdLen + 32;
                } else {
                    dwSdLen += 1024;
                }
            } else {
                return FALSE; // Fail; possibly due to Win9x stub
            }
        }
    } while (!bSuccess);
    //
    // Got psd ok
    //
    return TRUE;
}

////////////////////////////////////////////////////////////////////////

//
// Get the name of the owner (or group) for the file
//
static BOOL
_GetOwnerName(struct cache_entry *ce, char *szUserBuf, DWORD dwUserBufLen,
    BOOL bGroup)
{
    SIDS_FORMAT eFormat = (bGroup ? gids_format : sids_format);
    SD sd;
    BOOL bDefaulted = FALSE;
    BOOL bSuccess;

    if (eFormat == sids_none || !_LoadSecurityDescriptor(ce, sd)) {
        //
        // We return "0" to keep the number of columns the same.
        //
        // Needed for perl scripts that expect exactly 9 columns in the output
        // Ditto Emacs.
        //
        lstrcpyn(szUserBuf, "0", dwUserBufLen);
        return TRUE;
    }

    //
    // Got psd
    //
    PSECURITY_DESCRIPTOR psd = sd.GetSd();


    //
    // Dig out the owner or group SID
    //
    PSID pSid;
    if (!bGroup) {
        bSuccess = ::GetSecurityDescriptorOwner(psd, &pSid, &bDefaulted);
    } else {
        bSuccess = ::GetSecurityDescriptorGroup(psd, &pSid, &bDefaulted);
    }
    if (!bSuccess) {
        return FALSE;
    }

    //
    // Convert SID to name
    //
    bSuccess = LookupSidName(pSid, szUserBuf, dwUserBufLen, eFormat);
    return bSuccess;
}

///////////////////////////////////////////////////////
//
// Return the user name or POSIX group name of the file.
//
extern "C" char *
xgetuser(struct cache_entry *ce, int bGroup)
{
    static char szOwnerBuf[128]; // not thread safe

    if (!_GetOwnerName(ce, szOwnerBuf, 128, bGroup/*gid*/)) {
        return NULL;
    }
    return szOwnerBuf;
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
//
// Define a COM object to implement the callbacks
// ISecurityInformation and IEffectivePermission.
//
// EditSecurity() interrogates these interfaces
// in order to display the file's security using
// a fancy property sheet.
//

class CComDialogInfo : // COM object
        public ISecurityInformation,
        public IEffectivePermission
#ifdef UNDEFINED
        , public ISecurityInformation2
#endif
{
public:
    CComDialogInfo(struct cache_entry *ce, PSECURITY_DESCRIPTOR psd) :
            m_sd(psd), m_sdOrig(psd) {
        m_cRef = 0;
        m_ce = ce;
        m_psd = m_sd.GetSd();
        m_psdOrig = m_sdOrig.GetSd();
        if (m_psd == NULL || m_psdOrig == NULL) {
            error(EXIT_FAILURE, 0, "Bad security descriptor.");
            /*NOTREACHED*/
        }
    }

    //
    // DESIGN BUG: A quirk of C++ is that the destructor in a derived class
    // should *always* be virtual.
    //
    // Otherwise the derived class destructor is never called if the object
    // is deleted through its base pointer, meaning that the derived member
    // objects are never deleted!
    //
    // (Assignment operators in a derived class should also be virtual for
    // similar reasons.)
    //

    virtual ~CComDialogInfo() { } // implicitly destructs member objects m_sd, etc.

    ////////////////////////////////////////////////////////////////////////
    //
    // Implement IUnknown
    //
    STDMETHODIMP QueryInterface(REFIID r,void **p) {
        if (r == IID_IUnknown) {
            //
            // COM hack: For IID_IUnknown return a static_cast to the
            // left-most most-derived interface (e.g., ISecurityInformation)
            // that contains the requested interface (IID_IUnknown).
            //
            // Do *not* cast directly to IUnknown!  It is ambiguous
            // due to multiple-inheritance and will cause compilation
            // error C2594.
            //
            // The memory layout of CComDialogInfo:
            //
            //  1. vptr for CComDialogInfo and ISecurityInformation(shorter)
            //  2. vptr for IEffectivePermission (2nd inherited interface)
            //  3. vptr for ISecurityInformation2 (3rd interited interface)
            //  4. volatile long m_cRef
            //  5. struct cache_entry *m_ce, and other data members
            //
            // The vptr 1. points to a table of functions when called
            // directly from CComDialogInfo, or from a pointer that was
            // cast to ISecurityInformation*:
            //
            //      a. IUnknown::QueryInterface
            //      b. IUnknown::AddRef
            //      c. IUnknown::Release
            //      d. ISecurityInformation::GetObjectInformation
            //      e. ISecurityInformation::GetSecurity
            //      f. ISecurityInformation::SetSecurity
            //      g. ISecurityInformation::MapGeneric
            //      h. ISecurityInformation::GetAccessRights
            //      i. ISecurityInformation::GetInheritTypes
            //      (Logically stops here when cast to ISecurityInformation*)
            //      j. IEffectivePermission::GetEffectivePermission
            //      k. ISecurityInformation2::IsDaclCanonical
            //
            // The vptr 2. points to a table of thunks when called by a pointer
            // that was cast to to IEffectivePermission*:
            //
            //      a. IUnknown::QueryInterface (thunk subtracts 4 from ECX)
            //      b. IUnknown::AddRef (thunk subtracts 4 from ECX)
            //      c. IUnknown::Release (thunk subtracts 4 from ECX)
            //      d. IEffectivePermission::GetEffectivePermission (ditto)
            //
            // The vptr 3. points to a table of thunks when called by a
            // pointer that was cast to ISecurityInformation2*:
            //
            //      a. IUnknown::QueryInterface (thunk subtracts 8 from ECX)
            //      b. IUnknown::AddRef (thunk subtracts 8 from ECX)
            //      c. IUnknown::Release (thunk subtracts 8 from ECX)
            //      d. ISecurityInformation2::IsDaclCanonical (ditto)
            //
            // If the vptr is leftmost (1.) then its vtable will call the
            // function directly.
            //
            // If the vptr is at a later address (2. or 3.) then its vtable
            // will point to a thunk that adjusts ECX and then calls the derived
            // virtual function.
            //
            // This is necessary to adjust the "this" pointer (register ECX)
            // to point to the derived object (and not to the base object)
            // when calling the derived virtual function.
            //
            // To understand these quirks of C++ see the book "Inside COM"
            // by Dale Rogerson (1997).  For a more in-depth discussion
            // see the book "Essential COM" by Don Box (1999).
            //
            *p = static_cast<ISecurityInformation*>(this);
        } else if (r == IID_ISecurityInformation) {
            *p = static_cast<ISecurityInformation*>(this);
        } else if (r == IID_IEffectivePermission) {
            *p = static_cast<IEffectivePermission*>(this);
#ifdef UNDEFINED
        } else if (r == IID_ISecurityInformation2) {
            *p = static_cast<ISecurityInformation2*>(this);
#endif
        } else {
            *p = NULL;
            return E_NOINTERFACE;
        }
        this->AddRef(); // required!
        return S_OK;
    }

    STDMETHODIMP_(ULONG) AddRef() {
        return ::InterlockedIncrement(&m_cRef);
    }

    STDMETHODIMP_(ULONG) Release() {
        if (::InterlockedDecrement(&m_cRef) == 0) {
            m_cRef = 1; // Rogerson says to do this, but I'm not sure why.
            delete this;
            return 0;
        }
        return m_cRef;
    }

private:
    volatile long m_cRef; // COM reference count

public:

    ////////////////////////////////////////////////////////////////////////
    //
    // Implement ISecurityInformation
    //

    //
    // Return some basic info about the kind of dialog we want to display
    //
    STDMETHOD(GetObjectInformation) (THIS_ PSI_OBJECT_INFO pObjectInfo ) {
        SECURITY_DESCRIPTOR_CONTROL sdc;
        DWORD dwRevision=0;

        /////////////////////////////////////////////////////////////////
        //
        // BUG: Clearing pObjectInfo->guidObjectType will corrupt the
        // stack on Windows NT!!!!!
        //
        /////////////////////////////////////////////////////////////////

        //memset(pObjectInfo, 0, sizeof(*pObjectInfo));  // BUG AVOID

        if (!::GetSecurityDescriptorControl(m_psd, &sdc, &dwRevision)) {
            return E_FAIL;
        }
        //
        // This is a read-only implementation
        //
        // DESIGN BUG: Does not make the Owner page read-only!
        // Need SI_OWNER_READONLY for that.
        //
        // Note: NT/W2K pops up an annoying message box, "You only have
        // permission to view the current security information
        // on xxx."  Blah.  Gone in XP and W2K3.
        //
        pObjectInfo->dwFlags = SI_READONLY;

        pObjectInfo->dwFlags |= SI_ADVANCED;

        pObjectInfo->dwFlags |= SI_EDIT_PERMS; // show permissions tab

        pObjectInfo->dwFlags |= SI_EDIT_OWNER; // show owner tab

        //
        // SI_OWNER_READONLY pops up an annoying warning message box.
        // A bad design choice IMHO.  (Should not pop up if
        // SI_READONLY as it already makes it abundantly obvious that we
        // arent allowing changes)
        //

        // Do not set SI_OWNER_READONLY because it pops up an annoying msgbox
        //pObjectInfo->dwFlags |= SI_OWNER_READONLY

        pObjectInfo->dwFlags |= SI_EDIT_AUDITS; // show audits tab

        pObjectInfo->dwFlags |= SI_EDIT_EFFECTIVE; // show effective tab

        if (m_ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            pObjectInfo->dwFlags |= SI_CONTAINER; // indicate a directory
        }

        pObjectInfo->dwFlags |= SI_PAGE_TITLE;

        //pObjectInfo->dwFlags |= SI_EDIT_PROPERTIES; // Active Directory only
        //pObjectInfo->dwFlags |= SI_OBJECT_GUID; // Active Directory only

        pObjectInfo->hInstance = NULL; // for LoadString - not used

        pObjectInfo->pszServerName = NULL; // use default domain controller

        //
        // Note: Use the ANSI code page (CP_ACP), not OEM (get_codepage)!
        //
        if (::MultiByteToWideChar(CP_ACP, 0, m_ce->ce_filename, -1,
                m_wszName, FILENAME_MAX) == 0) {
            return E_FAIL;
        }

        //
        // Titlebar name
        //
        pObjectInfo->pszObjectName = m_wszName;

        //
        // Tab name
        //
        if (m_ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            pObjectInfo->pszPageTitle = gbReg ? L"Registry Permissions" : L"Folder Permissions";
        } else {
            pObjectInfo->pszPageTitle = gbReg ? L"Registry Permissions" : L"File Permissions";
        }

        return S_OK;
    }

    //
    // Get the Security Descriptor.  Called during initialization of the page
    // or when pressing the Defaults button.
    //
    // fDefault = reload the original security descriptor (user changed
    // his mind).  Not strictly necessary in a read-only implementation.
    //
    STDMETHOD(GetSecurity) (THIS_ SECURITY_INFORMATION RequestedInformation,
                            PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
                            BOOL fDefault ) {
        SECURITY_DESCRIPTOR_CONTROL sdc;
        DWORD dwRevision=0;
        PSECURITY_DESCRIPTOR psdSrc, psdDst;
        DWORD dwLen;

        // Determine what parts of our SD are valid
        if (!::GetSecurityDescriptorControl(m_psdOrig, &sdc, &dwRevision)) {
            return E_FAIL;
        }

        if ((sdc & SE_SELF_RELATIVE) == 0) {
            return E_FAIL; // cannot copy an absolute descriptor
        }

        if (RequestedInformation & (SACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION)) {
            if ((sdc & SE_SACL_PRESENT) == 0) {
                return E_ACCESSDENIED; // sorry no SACL info
            }
        }

        //
        // Clone the security descriptor into LocalAlloc memory.
        //
        // The GUI will later free it with LocalFree
        //

        psdSrc = fDefault ? m_psdOrig : m_psd;
        dwLen = ::GetSecurityDescriptorLength(psdSrc);
        psdDst = ::LocalAlloc(LPTR, dwLen);

        if (psdDst == NULL) {
            return E_FAIL;
        }

        memcpy(psdDst, psdSrc, dwLen);

        *ppSecurityDescriptor = psdDst;

        return S_OK;
    }

    //
    // Set security on the object (triggered by pressing Ok or Apply buttons
    // on a dirty page)
    //
    // We are a read-only implementation so flag an error
    //
    STDMETHOD(SetSecurity) (THIS_ SECURITY_INFORMATION SecurityInformation,
                            PSECURITY_DESCRIPTOR pSecurityDescriptor ) {
        UNREFERENCED_PARAMETER(SecurityInformation);
        UNREFERENCED_PARAMETER(pSecurityDescriptor);

        return E_NOTIMPL; // readonly
    }

    //
    // Turn off all GENERIC_xxx flags, mapping them to the equivalent
    // file-specific flags (FILE_xxx).
    //
    STDMETHOD(MapGeneric) (THIS_ const GUID *pguidObjectType/*ignored*/,
                           UCHAR *pAceFlags,
                           ACCESS_MASK *pMask) {

        // Describe the mapping from GENERIC_xxx to specific registry rights
        static GENERIC_MAPPING _reg_generic_mapping = {
            /*GenericRead = */KEY_READ,
            /*GenericWrite = */KEY_WRITE,
            /*GenericExecute = */KEY_EXECUTE,
            /*GenericAll = */KEY_ALL_ACCESS
        };

        // Describe the mapping from GENERIC_xxx to specific file rights
        static GENERIC_MAPPING _file_generic_mapping = {
            /*GenericRead = */FILE_GENERIC_READ,
            /*GenericWrite = */FILE_GENERIC_WRITE,
            /*GenericExecute = */FILE_GENERIC_EXECUTE,
            /*GenericAll = */FILE_ALL_ACCESS
        };

        UNREFERENCED_PARAMETER(pAceFlags);
        UNREFERENCED_PARAMETER(pguidObjectType);
        //
        // Just use the equivalent Win32 MapGenericMask function
        //
        if (gbReg) {
            ::MapGenericMask(pMask/*inout*/, &_reg_generic_mapping);
        } else {
            ::MapGenericMask(pMask/*inout*/, &_file_generic_mapping);
        }
        return S_OK;
    }

    //
    // Map various combinations of the ACE mask bits to their
    // text descriptions.
    //
    // Assumes that the GENERIC_xxx mask bits have already been mapped
    // to their FILE_xxx equivalents.  (See MapGeneric)
    //
    STDMETHOD(GetAccessRights) (THIS_ const GUID* pguidObjectType,
                                DWORD dwFlags, // SI_EDIT_AUDITS, SI_EDIT_PROPERTIES
                                PSI_ACCESS *ppAccess,
                                ULONG *pcAccesses,
                                ULONG *piDefaultAccess ) {
        UNREFERENCED_PARAMETER(pguidObjectType);
        UNREFERENCED_PARAMETER(dwFlags);

        //
        // dwFlags is one of the following combinations:
        //
        // 0                          -- show basic rights
        // SI_ADVANCED                -- show specific rights
        // SI_ADVANCED|SI_EDIT_AUDITS -- show SACL rights
        //

        //
        // The display selectors are a combination of the following:
        //
        // SI_ACCESS_GENERAL = appear on basic page
        // SI_ACCESS_SPECIFIC = appear on advanced page (ditto SACL page)
        // SI_ACCESS_CONTAINER = appear only on container object
        //
        // In addition these flags can be set.
        // Ignored on a non-container object.
        //
        // CONTAINER_INHERIT_ACE = match if CI set in ACE
        // INHERIT_ONLY_ACE = match if IO set in ACE
        // OBJECT_INHERIT_ACE = match if OI set in ACE
        //
        // The output mask (2nd arg) must *not* contain GENERIC_xxx flags.
        //

        static SI_ACCESS _file_oAccesses[] =
        {
            ///////////////////////////////////////////////////
            //
            // Basic permissions page (SI_ACCESS_GENERAL)
            //

            // Full Control = 0x1F01FF (FILE_ALL_ACCESS)
            { &GUID_NULL, FILE_ALL_ACCESS,
                L"Full Control",
                    SI_ACCESS_GENERAL \
                    | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            },

            // Modify = 0x1301BF (FILE_R|W|E_ACCESS)
            // Note: Omits FILE_DELETE_CHILD 0x000040
            // FILE_DELETE_CHILD means 'can ignore missing DELETE bit in child'
            { &GUID_NULL, FILE_GENERIC_READ|FILE_GENERIC_WRITE|FILE_GENERIC_EXECUTE,
                L"Modify", SI_ACCESS_GENERAL \
                    | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            },

            // Read & Execute = 0x1200A9
            { &GUID_NULL, FILE_GENERIC_READ|FILE_GENERIC_EXECUTE,
                L"Read & Execute",
                    SI_ACCESS_GENERAL \
                    | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            },

            // List Folder Contents = 0x1200A9 (FILE_GENERIC_READ)
            // same except no OBJECT_INHERIT_ACE
            { &GUID_NULL, FILE_GENERIC_READ,
                L"List Folder Contents",
                    SI_ACCESS_GENERAL \
                    | SI_ACCESS_CONTAINER /*folders only*/ \
                    | CONTAINER_INHERIT_ACE
            },

            // Read = 0x120089 (FILE_GENERIC_READ)
            { &GUID_NULL, FILE_GENERIC_READ,
                L"Read",
                    SI_ACCESS_GENERAL \
                    | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            },

            // Write = 0x10036 (FILE_GENERIC_WRITE)
            { &GUID_NULL, FILE_GENERIC_WRITE,
                L"Write",
                    SI_ACCESS_GENERAL
                    | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            },

            ///////////////////////////////////////////////////////////////
            //
            // Advanced permissions page (SI_ACCESS_SPECIFIC)
            //

            // Full Control = 0x1F01FF (FILE_ALL_ACCESS)
            { &GUID_NULL, FILE_ALL_ACCESS,
                L"Full Control",
                    SI_ACCESS_SPECIFIC \
                    | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            },

            // Traverse Folder / Execute File = 0x000020
            { &GUID_NULL, FILE_TRAVERSE/*=FILE_EXECUTE*/,
                L"Traverse Folder / Execute File",
                    SI_ACCESS_SPECIFIC \
                    | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            },

            // List Folder Contents / Read Data = 0x000001 (FILE_LIST_DIRECTORY)
            { &GUID_NULL, FILE_LIST_DIRECTORY/*=FILE_READ_DATA*/,
                L"List Folder / Read Data",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Read Attributes = 0x000080 (FILE_READ_ATTRIBUTES)
            { &GUID_NULL, FILE_READ_ATTRIBUTES,
                L"Read Attributes",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Read Extended Attributes = 0x000008 (FILE_READ_EA)
            { &GUID_NULL, FILE_READ_EA,
                L"Read Extended Attributes",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Create Files / Write Data = 0x000002 (FILE_ADD_FILE)
            { &GUID_NULL, FILE_ADD_FILE/*=FILE_WRITE_DATA*/,
                L"Create Files / Write Data",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Create Folders / Append Data = 0x000004 (FILE_ADD_SUBDIRECTORY)
            { &GUID_NULL, FILE_ADD_SUBDIRECTORY/*=FILE_APPEND_DATA*/,
                L"Create Subfolders / Append Data",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Write Attributes = 0x000100 (FILE_WRITE_ATTRIBUTES)
            { &GUID_NULL, FILE_WRITE_ATTRIBUTES,
                L"Write Attributes",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Write Extended Attributes = 0x000010 (FILE_WRITE_EA)
            { &GUID_NULL, FILE_WRITE_EA,
                L"Write Extended Attributes",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Delete Subfolders and Files = 0x000040 (FILE_DELETE_CHILD)
            { &GUID_NULL, FILE_DELETE_CHILD,
                L"Delete Subfolders and Files",
                    SI_ACCESS_SPECIFIC \
                    | SI_ACCESS_CONTAINER /*folders only*/ \
                    | CONTAINER_INHERIT_ACE
            },

            // Delete = 0x010000 (DELETE)
            { &GUID_NULL, DELETE,
                L"Delete",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Read Permissions = 0x020000 (READ_CONTROL)
            { &GUID_NULL, READ_CONTROL,
                L"Read Permissions",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Change Permissions = 0x040000 (WRITE_DAC)
            { &GUID_NULL, WRITE_DAC,
                L"Write Permissions",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Take Ownership = 0x080000 (WRITE_OWNER)
            { &GUID_NULL, WRITE_OWNER,
                L"Take Ownership",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },
        };

        /////////////////////////////////////////////////////////////////////
        //
        // Registry ACL map
        //
        static SI_ACCESS _reg_oAccesses[] =
        {
            ///////////////////////////////////////////////////
            //
            // Basic permissions page (SI_ACCESS_GENERAL)
            //

            // Full Control = KEY_ACCESS_ACCESS
            { &GUID_NULL, KEY_ALL_ACCESS,
                L"Full Control",
                    SI_ACCESS_GENERAL \
                    | CONTAINER_INHERIT_ACE
            },

            // Read = KEY_READ
            { &GUID_NULL, KEY_READ,
                L"Read",
                    SI_ACCESS_GENERAL \
                    | CONTAINER_INHERIT_ACE
            },

            // Write = KEY_WRITE
            { &GUID_NULL, KEY_WRITE,
                L"Write",
                    SI_ACCESS_GENERAL
                    | CONTAINER_INHERIT_ACE
            },

            ///////////////////////////////////////////////////////////////
            //
            // Advanced permissions page (SI_ACCESS_SPECIFIC)
            //

            // Full Control = KEY_ALL_ACCESS
            { &GUID_NULL, KEY_ALL_ACCESS,
                L"Full Control",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Query Value
            { &GUID_NULL, KEY_QUERY_VALUE,
                L"Query Value",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Set Value
            { &GUID_NULL, KEY_SET_VALUE,
                L"Set Value",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Create Subkey
            { &GUID_NULL, KEY_CREATE_SUB_KEY,
                L"Create Subkey",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Enumerate Subkeys
            { &GUID_NULL, KEY_ENUMERATE_SUB_KEYS,
                L"Enumerate Subkeys",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Notify
            { &GUID_NULL, KEY_NOTIFY,
                L"Notify",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Create Link
            { &GUID_NULL, KEY_CREATE_LINK,
                L"Create Link",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Delete
            { &GUID_NULL, DELETE,
                L"Delete",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Read Permissions = 0x020000 (READ_CONTROL)
            { &GUID_NULL, READ_CONTROL,
                L"Read Permissions",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Change Permissions = 0x040000 (WRITE_DAC)
            { &GUID_NULL, WRITE_DAC,
                L"Write Permissions",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },

            // Take Ownership = 0x080000 (WRITE_OWNER)
            { &GUID_NULL, WRITE_OWNER,
                L"Take Ownership",
                    SI_ACCESS_SPECIFIC \
                    | CONTAINER_INHERIT_ACE
            },
        };

        if (gbReg) {
            *ppAccess = _reg_oAccesses;
            *pcAccesses = sizeof(_reg_oAccesses)/sizeof(_reg_oAccesses[0]);
        } else {
            *ppAccess = _file_oAccesses;
            *pcAccesses = sizeof(_file_oAccesses)/sizeof(_file_oAccesses[0]);
        }

        *piDefaultAccess = 0; // default is first

        if ((m_ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            //
            // BUG: SI_CONTAINER (returned by GetObjectInformation)
            // is ignored by the property sheet.
            //
            // Workaround:
            // Zero the entries that have SI_ACCESS_CONTAINER
            // so they do not appear in the dialog.
            //
            // This hack depends on EditSecurity being called only once.
            //
            for (unsigned i=0; i < *pcAccesses; ++i) {
                if ((*ppAccess)[i].dwFlags & SI_ACCESS_CONTAINER) {
                    (*ppAccess)[i].dwFlags = 0;
                }
            }
        }

        return S_OK;
    }

    //
    // Map various combinations of the CI/OI/IO flags to their
    // text descriptions.
    //
    STDMETHOD(GetInheritTypes) (THIS_ PSI_INHERIT_TYPE *ppInheritTypes,
                                ULONG *pcInheritTypes ) {

        static SI_INHERIT_TYPE _reg_objInheritTypes[] =
        {
            &GUID_NULL, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                L"This key and subkeys",
            &GUID_NULL, CONTAINER_INHERIT_ACE,
                L"This key and subkeys",
            &GUID_NULL, OBJECT_INHERIT_ACE,
                L"This key and subkeys",
            &GUID_NULL, INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                L"Subkeys only",
            &GUID_NULL, INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE,
                L"Subkeys only",
            &GUID_NULL, INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE,
                L"Subkeys only",
            &GUID_NULL, INHERIT_ONLY_ACE, // bogus
                L"Never",
            &GUID_NULL, 0,
                L"This key only",
        };

        static SI_INHERIT_TYPE _file_objInheritTypes[] =
        {
            &GUID_NULL, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                L"This folder, subfolders and files",
            &GUID_NULL, CONTAINER_INHERIT_ACE,
                L"This folder and subfolders",
            &GUID_NULL, OBJECT_INHERIT_ACE,
                L"Files only",
            &GUID_NULL, INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                L"Subfolders and files only",
            &GUID_NULL, INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE,
                L"Subfolders only",
            &GUID_NULL, INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE,
                L"Files only",
            &GUID_NULL, INHERIT_ONLY_ACE, // bogus
                L"Never",
            &GUID_NULL, 0,
                L"This folder only",
        };

        if (gbReg) {
            *ppInheritTypes = _reg_objInheritTypes;
            *pcInheritTypes = sizeof(_reg_objInheritTypes)/sizeof(_reg_objInheritTypes[0]);
        } else {
            *ppInheritTypes = _file_objInheritTypes;
            *pcInheritTypes = sizeof(_file_objInheritTypes)/sizeof(_file_objInheritTypes[0]);
        }

        return S_OK;
    }

    STDMETHOD(PropertySheetPageCallback)(THIS_ HWND hWnd, UINT uMsg, SI_PAGE_TYPE uPage ) {
        UNREFERENCED_PARAMETER(hWnd);
        UNREFERENCED_PARAMETER(uMsg);
        UNREFERENCED_PARAMETER(uPage);
        return S_OK;
    }

    ////////////////////////////////////////////////////////////////////////
    //
    // Implement IEffectivePermission
    //

    //
    // Do a security check of the security principal pUserSid against
    // a hypothetical security descriptor pSD
    //
    STDMETHOD(GetEffectivePermission) (  THIS_ const GUID* pguidObjectType,
                                         PSID pUserSid,
                                         LPCWSTR pszServerName,
                                         PSECURITY_DESCRIPTOR pSD,
                                         POBJECT_TYPE_LIST *ppObjectTypeList,
                                         ULONG *pcObjectTypeListLength,
                                         PACCESS_MASK *ppGrantedAccessList,
                                         ULONG *pcGrantedAccessListLength)
    {
        BOOL bPresent = FALSE, bDefaulted = FALSE;
        PACL pAcl = NULL;
        TRUSTEE trustee;

        static OBJECT_TYPE_LIST _DefaultOTL [] = {
            {0, 0, (LPGUID)&GUID_NULL},
        }; // used in AD only - create dummy OTL here

        typedef DWORD (WINAPI *PFNGETEFFECTIVERIGHTSFROMACLA)(
            IN PACL pAcl,
            IN PTRUSTEE_A pTrustee,
            OUT PACCESS_MASK pAccessRights
        );
        static PFNGETEFFECTIVERIGHTSFROMACLA pfnGetEffectiveRightsFromAclA;

        UNREFERENCED_PARAMETER(pguidObjectType); // AD object type

        UNREFERENCED_PARAMETER(pszServerName); // used when??

        *ppObjectTypeList = _DefaultOTL; // dummy
        *pcObjectTypeListLength = 1;

        if (!::GetSecurityDescriptorDacl(pSD, &bPresent, &pAcl, &bDefaulted)) {
            return E_ACCESSDENIED; // fail, punt
        }

        PACCESS_MASK pMask = (PACCESS_MASK) ::LocalAlloc(LPTR, sizeof(ACCESS_MASK));
        *pMask = 0;

        //
        // BUG: When querying a FAT file system, bPresent != 0 but pAcl == NULL
        //

        if (!bPresent || pAcl == NULL) { // no DACL means allow everything
            *pMask = FILE_ALL_ACCESS;
            *ppGrantedAccessList = pMask;
            *pcGrantedAccessListLength = 1;
            return S_OK;
        }

        memset(&trustee, 0, sizeof(trustee));
        trustee.pMultipleTrustee = NULL;
        trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        trustee.TrusteeForm = TRUSTEE_IS_SID;
        trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
        trustee.ptstrName = (LPTSTR) pUserSid;

        //
        // Use GetEffectiveRightsFromAcl to do the dirty work.
        //
        // This API call can be very slow if Universal Groups are
        // enabled.  This is because it attempts
        // to cobble together a pseduo-token containing all of the
        // security principal's groups.  It basically has to chase down
        // and query domain controllers in each and every domain in
        // the AD forest.
        //
        // Windows Server 2003 speeds up this operation by caching every
        // security principal's group membership in the Glocal Cache.
        // (Requires running in Windows Server 2003 native mode.)
        // (This API is *not* documented [yet])
        //

        //
        // DESIGN BUG: Does not know about owner-overrides (i.e., the
        // file owner always has WRITE_OWNER permission regardless
        // of the ACL).  Ditto users with SeTakeOwnershipPrivilege.
        //

        if (!DynaLoad("ADVAPI32.DLL", "GetEffectiveRightsFromAclA",
                (PPFN)&pfnGetEffectiveRightsFromAclA)) { // not avail on Win95
            return E_ACCESSDENIED; // fail, punt
        }
        if ((*pfnGetEffectiveRightsFromAclA)(pAcl, &trustee, pMask) != ERROR_SUCCESS) {
            return E_ACCESSDENIED; // fail, punt
        }

        *ppGrantedAccessList = pMask;
        *pcGrantedAccessListLength = 1;

        return S_OK;
    }

#ifdef UNDEFINED
    ////////////////////////////////////////////////////////////////////////
    //
    // Implement ISecurityInformation2
    //
    STDMETHOD_(BOOL,IsDaclCanonical) (THIS_ IN PACL pDacl) {
        UNREFERENCED_PARAMETER(pDacl);
        //
        // Return FALSE is the given DACL is not in canonical order.
        // Required only when editing - pops up a warning box.
        //
        return TRUE; // note: not an HRESULT
    }

    STDMETHOD(LookupSids) (THIS_ IN ULONG cSids, IN PSID *rgpSids, OUT LPDATAOBJECT *ppdo) {
        //
        // Allows intercept of SID-to-name lookups
        // to prettify or change the name(s)
        //
        return E_NOTIMPL;
    }
#endif

private:
    struct cache_entry* m_ce;

    SD m_sd; // security descriptor (allocated on the heap)
    PSECURITY_DESCRIPTOR m_psd; // point to the above

    SD m_sdOrig; // original SD before modification
    PSECURITY_DESCRIPTOR m_psdOrig; // point to the above

    WCHAR m_wszName[FILENAME_MAX]; // name of file for title bar
};


///////////////////////////////////////////////////////////////////////////


typedef BOOL (WINAPI *PFNEDITSECURITY)(
    HWND hwndOwner,
    LPSECURITYINFO psi
);
static PFNEDITSECURITY pfnEditSecurity;


/////////////////////////////////////////////////////////////////
//
// Show the EditSecurity property sheet.  W2K or later
//
BOOL
view_file_security(struct cache_entry *ce)
{
    SD sd;

    if (!_LoadSecurityDescriptor(ce, sd)) {
        error(0, 0, "%s: Unable to load the security descriptor",
            ce->ce_filename);
        return FALSE;
    }

    //
    // Got psd
    //
    PSECURITY_DESCRIPTOR psd = sd.GetSd();

    //
    // Initialize COM
    //
    if (!gbComInitialized) {
        gbComInitialized = TRUE;
        if (FAILED(CoInitialize(NULL))) {
            error(EXIT_FAILURE, 0, "Unable to initialize COM");
            return FALSE; /*NOTREACHED*/
        }
    }

    if (!DynaLoad("ACLUI.DLL", "EditSecurity",
            (PPFN)&pfnEditSecurity)) {
        error(0, 0, "This version of Windows does not support the Security Property Sheet.");
        return FALSE;
    }

    //
    // Build the COM object to implement ISecurityInformation
    // and IEffectivePermissions
    //
    CComDialogInfo *pComDialogInfo = new CComDialogInfo(ce, psd);
    pComDialogInfo->AddRef();

    // Get the base pointer to ISecurityInformation
    ISecurityInformation* psi;

    if (FAILED(pComDialogInfo->QueryInterface(IID_ISecurityInformation, (void**)&psi))) {
        pComDialogInfo->Release();
        return FALSE;
    }

    //
    // Show the security propsheet, passing in ISecurityInformation.  The GUI
    // will QueryInterface() to get the other interface pointers.
    //
    // Progress blocks here until dialog is closed.
    //
    if (!(*pfnEditSecurity)(NULL/*hwndOwner*/, psi)) {
        MapWin32ErrorToPosixErrno();
        error(0, errno, "EditSecurity failed with error %d", GetLastError());
        psi->Release();
        pComDialogInfo->Release();
        return FALSE;
    }

    psi->Release();
    pComDialogInfo->Release();
    return TRUE;
}

////////////////////////////////////////////////////////////////////////

extern "C"
{

///////////////////////////////////////////////////////////////////
//
// Show very-long-format ACL
//

static void
_print_ace(PACCESS_ALLOWED_ACE pAce, BOOL bDirectory)
{
    PSID pSid;
    char szUserBuf[128];
    BOOL bComma = FALSE;
    BOOL bSpecial = FALSE;
    // indent for special perms
    const char * const szIndent = "                      ";
    // indent for CI/OI/IO bits
    const char * const szIndentBits
                                = "                     "; // one char less

    pSid = (PSID)&((PACCESS_ALLOWED_ACE)pAce)->SidStart;

    if (!LookupSidName(pSid, szUserBuf, sizeof(szUserBuf)-1, sids_format)) {
        // should never happen
        error(0, 0, "Error looking up SID");
        return;
    }
    strcat(szUserBuf, ":");
    more_printf("    %-17s ", szUserBuf);

    if (pAce->Header.AceFlags & OBJECT_INHERIT_ACE) {
        //
        // ACE is applicable to files also, so show it as such.
        //
        bDirectory = FALSE;
    }

    if (pAce->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
        //
        // Vista Integrity level S-1-16-4096,8192,12288,16384
        //
        more_fputs("Integrity Level", stdmore);
    } else {
     if (gbReg) {
      switch (pAce->Mask) {
        case KEY_ALL_ACCESS:
        case GENERIC_ALL:
            more_fputs("Full", stdmore);
            break;

        case KEY_WRITE:
        case GENERIC_WRITE:
            more_fputs("Write", stdmore);
            break;

        case KEY_READ:
        case GENERIC_READ:
            more_fputs("Read", stdmore);
            break;

        default:
            //
            // GENERIC_ALL means all bits are set virtually
            // so we can skip displaying the special bits
            //
            if (pAce->Mask & GENERIC_ALL) {
                more_fputs("Full", stdmore);
            } else {
                //more_fputs("Special:", stdmore);
                bSpecial = TRUE;
            }
            break;
      }
     } else {
      switch (pAce->Mask) {
        //
        // Note: All of the FILE_GENERIC_xxx flags include
        // include SYNCHRONIZE (0x100000) except FILE_GENERIC_WRITE
        //
        case FILE_ALL_ACCESS: // 0x1F01FF
        case GENERIC_ALL: // 0x10000000
            more_fputs("Full", stdmore);
            break;
        case FILE_GENERIC_READ|FILE_GENERIC_WRITE|FILE_GENERIC_EXECUTE:
            // 0x1301BF - Note: Omits FILE_DELETE_CHILD 0x000040
            // FILE_DELETE_CHILD means 'can ignore missing DELETE bit in child'
        case GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE: // 0xE0000000
            more_fputs("Modify", stdmore);
            break;
        case FILE_GENERIC_READ: // 0x120089
        case GENERIC_READ: // 0x80000000
            more_fputs(bDirectory ? "List Contents" : "Read", stdmore);
            break;
        case FILE_GENERIC_READ|FILE_GENERIC_EXECUTE: // 0x1200A9
        case GENERIC_READ|GENERIC_EXECUTE: // 0xA0000000
            more_fputs(bDirectory ? "List Contents + Traverse Folder" : "Read + Execute",
                stdmore);
            break;
        case FILE_GENERIC_EXECUTE: // 0x1200A0
        case GENERIC_EXECUTE: // 0x20000000
            more_fputs(bDirectory ? "Traverse Folder" : "Execute", stdmore);
            break;
        case FILE_GENERIC_WRITE: // 0x010036
        case GENERIC_WRITE: // 0x40000000
            more_fputs(bDirectory ? "Add Files or Subfolders" : "Write", stdmore);
            break;
        default:
            //
            // GENERIC_ALL means all bits are set virtually
            // so we can skip displaying the special bits
            //
            if (pAce->Mask & GENERIC_ALL) {
                more_fputs("Full", stdmore);
            } else {
                //more_fputs("Special:", stdmore);
                bSpecial = TRUE;
            }
            break;
      }
     }
    }

    more_putchar('\n');

    if (pAce->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
        //
        // Vista Integrity levels.  Used in SACLs
        //
        if (pAce->Mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP/*0x1*/) {
            more_printf("%s%s\n", szIndent, "No-Write-Up");
        }
        if (pAce->Mask & SYSTEM_MANDATORY_LABEL_NO_READ_UP/*0x2*/) {
            more_printf("%s%s\n", szIndent, "No-Read-Up");
        }
        if (pAce->Mask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP/*0x4*/) {
            more_printf("%s%s\n", szIndent, "No-Execute-Up");
        }
    } else {
      if (bSpecial && gbReg) {
        //
        // Break out the individual mask bits specially
        //

        //
        // Show generic flags broken out
        //
        if (pAce->Mask & (GENERIC_READ|KEY_QUERY_VALUE)) {
            more_printf("%s%s\n", szIndent, "Query Value");
        }
        if (pAce->Mask & (GENERIC_READ|KEY_ENUMERATE_SUB_KEYS)) {
            more_printf("%s%s\n", szIndent, "Enumerate Subkeys");
        }
        if (pAce->Mask & (GENERIC_READ|KEY_NOTIFY)) {
            more_printf("%s%s\n", szIndent, "Notify");
        }
        if (pAce->Mask & (GENERIC_WRITE|KEY_SET_VALUE)) {
            more_printf("%s%s\n", szIndent, "Set Value");
        }
        if (pAce->Mask & (GENERIC_WRITE|KEY_CREATE_SUB_KEY)) {
            more_printf("%s%s\n", szIndent, "Create Subkey");
        }
        //
        // Show file flags that don't match GENERIC_xxx broken out
        //
        if (pAce->Mask & KEY_CREATE_LINK) {
            more_printf("%s%s\n", szIndent, "Create Link");
        }
        //
        // Show control flags broken out
        //
        if (pAce->Mask & DELETE) { // 0x010000
            more_printf("%s%s\n", szIndent, "Delete");
        }
        if (pAce->Mask & READ_CONTROL) { // 0x02000
            more_printf("%sRead Permissions\n", szIndent);
        }
        if (pAce->Mask & WRITE_DAC) { // 0x040000
            more_printf("%sWrite Permissions\n", szIndent);
        }
        if (pAce->Mask & WRITE_OWNER) { // 0x080000
            more_printf("%sTake Ownership\n", szIndent);
        }
        if ((pAce->Mask & (GENERIC_READ|GENERIC_EXECUTE)) == 0) {
            //
            // SYNCHRONIZE not already implicitly specified -
            // show it explicitly
            //
            if (pAce->Mask & SYNCHRONIZE) {
                more_printf("%sSynchronize\n", szIndent);
            }
        }
      }

      if (bSpecial && !gbReg) {
        //
        // Break out the individual mask bits specially
        //

        //
        // Show generic flags broken out
        //
        if (pAce->Mask & (GENERIC_READ|FILE_READ_DATA/*=FILE_LIST_DIRECTORY*/)) {
            more_printf("%s%s\n", szIndent, bDirectory ? "List Contents" : "Read");
        }
        if (pAce->Mask & (GENERIC_WRITE|FILE_WRITE_DATA/*=FILE_ADD_FILE*/)) {
            more_printf("%s%s\n", szIndent, bDirectory ? "Add Files or Subfolders" : "Write");
        }
        if (pAce->Mask & (GENERIC_EXECUTE|FILE_EXECUTE/*=FILE_TRAVERSE*/)) {
            more_printf("%s%s\n", szIndent, bDirectory ? "Traverse Folder" : "Execute");
        }
        //
        // Show file flags that don't match GENERIC_xxx broken out
        //
        if (pAce->Mask & FILE_APPEND_DATA/*=FILE_ADD_SUBDIRECTORY*/) { // 0x000004
            more_printf("%s%s\n", szIndent, bDirectory ? "Create Subfolders" : "Append Data");
        }
        if (pAce->Mask & FILE_DELETE_CHILD) { // 0x000040
            // FILE_DELETE_CHILD means 'can ignore missing DELETE bit in child'
            more_printf("%sAlways Delete Files and Subfolders\n", szIndent);
        }
        if (pAce->Mask & FILE_READ_ATTRIBUTES) { // 0x000080
            more_printf("%sRead Attributes\n", szIndent);
        }
#ifdef UNDEFINED // Extended Attribs haven't been used on NTFS since OS/2
        if (pAce->Mask & FILE_READ_EA) { // 0x000008
            more_printf("%sRead Extended Attributes\n", szIndent);
        }
#endif
        if (pAce->Mask & FILE_WRITE_ATTRIBUTES) { // 0x000100
            more_printf("%sWrite Attributes\n", szIndent);
        }
#ifdef UNDEFINED // Extended Attribs haven't been used on NTFS since OS/2
        if (pAce->Mask & FILE_WRITE_EA) { // 0x000010
            more_printf("%sWrite Extended Attributes\n", szIndent);
        }
#endif
        //
        // Show control flags broken out
        //
        if (pAce->Mask & DELETE) { // 0x010000
            more_printf("%s%s\n", szIndent, bDirectory ? "Delete this folder" : "Delete");
        }
        if (pAce->Mask & READ_CONTROL) { // 0x02000
            more_printf("%sRead Permissions\n", szIndent);
        }
        if (pAce->Mask & WRITE_DAC) { // 0x040000
            more_printf("%sWrite Permissions\n", szIndent);
        }
        if (pAce->Mask & WRITE_OWNER) { // 0x080000
            more_printf("%sTake Ownership\n", szIndent);
        }
        if ((pAce->Mask & (GENERIC_READ|GENERIC_EXECUTE)) == 0) {
            //
            // SYNCHRONIZE not already implicitly specified -
            // show it explicitly
            //
            if (pAce->Mask & SYNCHRONIZE) {
                more_printf("%sSynchronize\n", szIndent);
            }
        }
      }
    }

    //
    // Special ACE types
    //
    if (pAce->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
        if (bComma) more_putchar(','); else more_fputs(szIndentBits, stdmore);
        more_fputs(" Deny Access", stdmore);
        bComma = TRUE;
    }
#ifdef UNDEFINED
    //
    // Vista Integrity level S-1-16-4096,8192,12288,16384
    //
    if (pAce->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
        if (bComma) more_putchar(','); else more_fputs(szIndentBits, stdmore);
        more_fputs(" Integity Level", stdmore);
        bComma = TRUE;
    }
#endif

    if (pAce->Header.AceFlags & CONTAINER_INHERIT_ACE) {
        if (bComma) more_putchar(','); else more_fputs(szIndentBits, stdmore);
        more_fputs(gbReg ? " Keys Inherit" : " Folders Inherit", stdmore); // Containers Inherit
        bComma = TRUE;
    }
    if (pAce->Header.AceFlags & OBJECT_INHERIT_ACE) {
        if (bComma) more_putchar(','); else more_fputs(szIndentBits, stdmore);
        more_fputs(" Files Inherit", stdmore); // Objects Inherit
        bComma = TRUE;
    }
    if (pAce->Header.AceFlags & INHERIT_ONLY_ACE) {
        if (bComma) more_putchar(','); else more_fputs(szIndentBits, stdmore);
        more_fputs(" Inherit Only", stdmore);
        bComma = TRUE;
    }
    if (pAce->Header.AceFlags & NO_PROPAGATE_INHERIT_ACE) {
        if (bComma) more_putchar(','); else more_fputs(szIndentBits, stdmore);
        more_fputs(" Propagate One Level Only", stdmore);
        bComma = TRUE;
    }
    if ((pAce->Header.AceFlags & INHERITED_ACE) == 0) { // *not* inherited
        if (bComma) more_putchar(','); else more_fputs(szIndentBits, stdmore);
        more_fputs(" Not Inherited", stdmore);
        bComma = TRUE;
    }
    if (pAce->Header.AceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) {
        if (bComma) more_putchar(','); else more_fputs(szIndentBits, stdmore);
        more_fputs(" Audit on Success", stdmore);
        bComma = TRUE;
    }
    if (pAce->Header.AceFlags & FAILED_ACCESS_ACE_FLAG) {
        if (bComma) more_putchar(','); else more_fputs(szIndentBits, stdmore);
        more_fputs(" Audit on Failure", stdmore);
        bComma = TRUE;
    }
    if (bComma) {
        more_putchar('\n');
    }
    return;
}

static void
_print_very_long_acl(PSECURITY_DESCRIPTOR psd, BOOL bDirectory)
{
    SECURITY_DESCRIPTOR_CONTROL sdc;
    DWORD dwRevision=0;
    BOOL bPresent, bDefaulted;
    PACL pDacl, pSacl;
    ULONG i;
    PACCESS_ALLOWED_ACE pAce; // same as PACCESS_DENIED_ACE

    BOOL bExhaustive = (acls_format == acls_exhaustive);

#ifdef UNDEFINED // BUG: Broken - returns garbage for DACL and SACL
    //
    // Q: Why is this still broken in XP in the year 2004???
    // It was first reported broken in NT 4 in 1997!
    //
    if (::LookupSecurityDescriptorParts(&pOwner, &pGroup,
            &nDaclAces, &peaDacl, &nSaclAces, &peaSacl, psd) != ERROR_SUCCESS) {
        MapWin32ErrorToPosixErrno();
        error(0, errno, "Unable to crack the security descriptor");
        return;
    }
#endif

    //
    // Do it the hard way (sigh)
    //

    //
    // Grovel for the DACL
    //
    pDacl = NULL; bPresent = 0; bDefaulted = 0; // required
    if (!::GetSecurityDescriptorDacl(psd, &bPresent, &pDacl, &bDefaulted)) {
        error(0, 0, "Unable to get DACL");
        pDacl = NULL;
    } else if (!bPresent || pDacl == NULL) {
        pDacl = NULL;
        more_puts(" Missing DACL - allow all access.");
    }
    if (bExhaustive && !bPresent) {
        more_puts(" DACL is not present.");
    }
    if (bExhaustive && bDefaulted) {
        more_puts(" DACL was created from the user's default DACL.");
    }

    //
    // Grovel for the SACL
    //
    pSacl = NULL; bPresent = 0; bDefaulted = 0; // required
    if (!::GetSecurityDescriptorSacl(psd, &bPresent, &pSacl, &bDefaulted)) {
        error(0, 0, "Unable to get SACL");
        pSacl = NULL;
    } else if (!bPresent || pSacl == NULL) {
        pSacl = NULL;
    }
    if (bExhaustive) {
        if (bPresent) {
            more_puts(" SACL is present.");
        } else {
            more_puts(" SACL is not present.");
        }
    }
    if (bExhaustive && bDefaulted) {
        more_puts(" The SACL was created from the user's default SACL.");
    }

    //
    // Report top-level flags from the control word
    //
    if (::GetSecurityDescriptorControl(psd, &sdc, &dwRevision)) {
        if (pDacl != NULL && (sdc & SE_DACL_PROTECTED)) {
            more_puts(" DACL protected from clobbering by parent.");
        }
        if ((bExhaustive || pSacl != NULL) && (sdc & SE_SACL_PROTECTED)) {
            more_puts(" SACL protected from clobbering by parent.");
        }
        if (pDacl != NULL && (sdc & (SE_DACL_PROTECTED|SE_DACL_AUTO_INHERITED)) == 0) {
            //
            // Rare: Neither Protected nor Auto_inherited.  Most likely
            // this was created by NT4.
            //
            // NTMARTA.DLL will set SE_DACL_PROTECTED the first time it is used.
            //
            // BUG:
            //  Many custom-created folders (outside of NTMARTA)
            //  that dont want inheritance from the parent
            //  have SE_DACL_PROTECTED=0 and
            //  SE_DACL_AUTO_INHERITED=0.  Not just legacy NT!
            //
            //more_puts(" DACL protected from clobbering by parent (NT4 legacy).");
            more_puts(" DACL is not inherited (but not protected).");
        }
        if ((bExhaustive || pSacl != NULL) && (sdc & (SE_SACL_PROTECTED|SE_SACL_AUTO_INHERITED)) == 0) {
            //
            // Rare: Neither Protected nor Auto_inherited.  Most likely
            // this was created by NT4, or modified by the low-level API.
            //
            // NTMARTA.DLL will set SE_SACL_PROTECTED the first time it is used
            // if the ACL contains only non-inherited ACEs.  This prevents
            // any future inheritance.
            //
            // BUG:
            //  Many custom-created folders (outside of NTMARTA)
            //  that dont want inheritance from the parent
            //  have SE_DACL_PROTECTED=0 and
            //  SE_DACL_AUTO_INHERITED=0.  Not just legacy NT!
            //
            //more_puts(" SACL protected from clobbering by parent (NT4 legacy).");
            more_puts(" SACL is not inherited (but not protected).");
        }
        if (bDirectory) {
            //
            // Actually, SE_DACL_AUTO_INHERITED is merely an optimization
            // that tells ::ConvertToAutoInheritPrivateObjectSecurity to
            // do (mostly) nothing.
            //
            if (pDacl != NULL && (sdc & SE_DACL_AUTO_INHERITED)) {
                more_puts(" Changes in DACL will propagate to existing descendants.");
            }
            //
            // Actually, SE_DACL_AUTO_INHERITED is merely an optimization
            // that tells ::ConvertToAutoInheritPrivateObjectSecurity to
            // do (mostly) nothing.
            //
            if ((bExhaustive || pSacl != NULL) && (sdc & SE_SACL_AUTO_INHERITED)) {
                more_puts(" Changes in SACL will propagate to existing descendants.");
            }
        }
    }

    // No - Requires VS2005 exception handling lib
    //__try { // in case of memory access violations due to garbage ACLs

        if (pDacl) {
            pAce = (PACCESS_ALLOWED_ACE)(pDacl+1);
            for (i=0; i < pDacl->AceCount; ++i, pAce = (PACCESS_ALLOWED_ACE)((PBYTE)pAce+pAce->Header.AceSize)) {
                _print_ace(pAce, bDirectory);
                //if (i != pDacl->AceCount-1) more_putchar('\n');
            }
        }
        if (pSacl) {
            pAce = (PACCESS_ALLOWED_ACE)(pSacl+1); // all file ACEs have same format
            more_puts("System Access Control List:");
            for (i=0; i < pSacl->AceCount; ++i, pAce = (PACCESS_ALLOWED_ACE)((PBYTE)pAce+pAce->Header.AceSize)) {
                _print_ace(pAce, bDirectory);
                //if (i != pSacl->AceCount-1) more_putchar('\n');
            }
        }

    //} __except(EXCEPTION_EXECUTE_HANDLER) {
    //  error(0, 0, "Garbage ACL detected.");
    //}

    return;
}

///////////////////////////////////////////////////////////////////
//
// Show long-format ACL
//

// Trivia: This is the longest name in the Win32 API.
typedef BOOL (WINAPI *PFNCONVERTSECURITYDESCRIPTORTOSTRINGSECURITYDESCRIPTOR)(
    PSECURITY_DESCRIPTOR sd,
    DWORD dwRequestedStringSDRevision,
    SECURITY_INFORMATION SecurityInformation,
    LPTSTR* szStringBuf, // Allocated; use LocalFree to free
    PULONG dwStringBufLen
);
static PFNCONVERTSECURITYDESCRIPTORTOSTRINGSECURITYDESCRIPTOR
    pfnConvertSecurityDescriptorToStringSecurityDescriptor;

typedef BOOL (WINAPI *PFNCONVERTSTRINGSIDTOSID)(
    LPCTSTR szSid,
    PSID* ppsid
);
static PFNCONVERTSTRINGSIDTOSID pfnConvertStringSidToSid;

//
// Print the ACL in long form (W2K or later)
//
void
print_long_acl(struct cache_entry *ce)
{
    SD sd;
    LPTSTR szStringBuf = NULL;

    errno = 0;
    SetLastError(0);

    //
    // Bail if not --acls=long or --acls=very-long or --acls=exhaustive
    //
    if ((acls_format != acls_long && acls_format != acls_very_long
            && acls_format != acls_exhaustive)) {
        return;
    }

    if (gbReg && (ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        // dont show security on reg values, only keys
        return;
    }

    if (!_LoadSecurityDescriptor(ce, sd)) {
        return;
    }

    //
    // Got psd
    //
    PSECURITY_DESCRIPTOR psd = sd.GetSd();

    if (acls_format == acls_very_long || acls_format == acls_exhaustive) {
        _print_very_long_acl(psd, ((ce->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0));
        return;
    }

    //
    // Load the API (W2K or later)
    //
    if (!DynaLoad("ADVAPI32.DLL", "ConvertSecurityDescriptorToStringSecurityDescriptorA",
            (PPFN)&pfnConvertSecurityDescriptorToStringSecurityDescriptor)) {
        errno = EINVAL;
        return;
    }
    DWORD dwFlags = DACL_SECURITY_INFORMATION;
    if (_EnableSecurityPrivilege()) {
        dwFlags |= SACL_SECURITY_INFORMATION; // get SACL too
        if (IsVista) {
            //
            // UNDOCUMENTED: Required to get S-1-16-xxxx SACL ACEs for
            // mandatory integrity labels
            //
            dwFlags |= LABEL_SECURITY_INFORMATION; // get integrity labels too
        }
    }

    if (!(*pfnConvertSecurityDescriptorToStringSecurityDescriptor)(psd,
            SDDL_REVISION_1, dwFlags, &szStringBuf, NULL)) {
        //
        // This can happen on FAT "C:\"
        //
        more_puts("Missing or bad Security Descriptor.\n"); // garbage SD?
    }


    if (szStringBuf != NULL) {
        char *s, *s2, ch;
        char szUserBuf[128];
        PSID pSid;

        for (s = szStringBuf; *s; ++s) {
            if (numeric_ids) { // if -n
                more_putchar(*s); // print as-is
                continue;
            }
            //
            // Prettify the ACL string to make it more readable
            //
            if (s[0] != 'S' || s[1] != '-' || s[2] != '1' || s[3] != '-') {
                // Not S-1-...
                if (s[0] != '0' || s[1] != 'x' || s[2] != '1') {
                    // Not 0x1...
                    if (s[0] != 'F' || s[1] != 'A' || s[2] != ';') {
                        // Not FA;...
                        more_putchar(*s); // punt
                        continue;
                    }
                    //
                    // "FA;" -> "Full;"
                    //
                    more_fputs("Full", stdmore);
                    ++s;
                    continue;
                }
                //
                // 0x1...
                //
                // Show common mask combinations as names
                // a la the EditSecurity dialog
                //
                DWORD dwMask = strtoul(s, &s2, 0);
                switch (dwMask) {
                    case 0x1F01FF:
                        more_fputs("All", stdmore);
                        break;

                    case 0x1301BF:
                        more_fputs("Modify", stdmore);
                        break;

                    case 0x1200A9:
                        more_fputs("Read+Exec", stdmore);
                        break;

                    case 0x120089:
                        more_fputs("Read", stdmore);
                        break;

                    case 0x010036:
                        more_fputs("Write", stdmore);
                        break;

                    default: // punt
                        more_putchar(*s);
                        continue;
                }
                s = s2-1;
                continue;
            }
            //
            // Found start of SID "S-1..". Find end at ')'
            //
            if ((s2 = strchr(s, ')')) == NULL) { // should never happen
                more_putchar(*s);
                continue; // punt
            }
            ch = *s2; *s2 = '\0';
            //
            // Convert SID from text to binary
            //
            if (!DynaLoad("ADVAPI32.DLL", "ConvertStringSidToSidA",
                    (PPFN)&pfnConvertStringSidToSid)) {
                *s2 = ch; // restore
                more_putchar(*s);
                continue; // punt
            }
            pSid = NULL;
            if (!(*pfnConvertStringSidToSid)(s, &pSid)) {
                *s2 = ch; // restore
                more_putchar(*s); // punt
                continue;
            }
            //
            // Convert SID to name
            //
            if (!LookupSidName(pSid, szUserBuf, sizeof(szUserBuf), sids_format)) {
                ::LocalFree(pSid);
                *s2 = ch; // restore
                more_putchar(*s); // punt
                continue;
            }
            ::LocalFree(pSid);
            more_fputs(szUserBuf, stdmore); // show name
            *s2 = ch; // restore
            s = s2-1;
        }
        more_putchar('\n');

        ::LocalFree(szStringBuf);
    }

    return;
}

///////////////////////////////////////////////////////////////////
//
// Print the names of users with encryption certificates for this
// file.  Requires FILE_ATTRIBUTE_ENCRYPTED_FILE (W2K or later)
//

typedef DWORD (WINAPI *PFNQUERYUSERSONENCRYPTEDFILE)(
     IN LPCWSTR lpFileName,
     OUT PENCRYPTION_CERTIFICATE_HASH_LIST * pUsers
);
static PFNQUERYUSERSONENCRYPTEDFILE pfnQueryUsersOnEncryptedFile;

typedef DWORD (WINAPI *PFNQUERYRECOVERYAGENTSONENCRYPTEDFILE)(
     IN LPCWSTR lpFileName,
     OUT PENCRYPTION_CERTIFICATE_HASH_LIST * pRecoveryAgents
);
static PFNQUERYRECOVERYAGENTSONENCRYPTEDFILE pfnQueryRecoveryAgentsOnEncryptedFile;

typedef VOID (WINAPI *PFNFREEENCRYPTIONCERTIFICATEHASHLIST)(
    IN PENCRYPTION_CERTIFICATE_HASH_LIST pHashes
);
static PFNFREEENCRYPTIONCERTIFICATEHASHLIST pfnFreeEncryptionCertificateHashList;

//
// Print the names of principals and of recovery agents on the encrypted file
//
void
print_encrypted_file(struct cache_entry *ce)
{
    wchar_t wszPath[FILENAME_MAX];
    DWORD dwError;
    DWORD i;
    PENCRYPTION_CERTIFICATE_HASH_LIST pHashes=NULL;

    errno = 0;
    SetLastError(0);

    if ((ce->dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED) == 0) {
        return; // not encrypted
    }

    if (ce->ce_abspath == NULL) {
        errno = ENOENT;  // GetFullPathName() failed earlier in dirent.c
        return;
    }
    //
    // Dynamically load the EFS API.  Not available on NT or W9x
    //
    if (!DynaLoad("ADVAPI32.DLL", "QueryUsersOnEncryptedFile",
            (PPFN)&pfnQueryUsersOnEncryptedFile)) {
        errno = EINVAL;
        return;
    }
    if (!DynaLoad("ADVAPI32.DLL", "QueryRecoveryAgentsOnEncryptedFile",
            (PPFN)&pfnQueryRecoveryAgentsOnEncryptedFile)) {
        errno = EINVAL;
        return;
    }
    if (!DynaLoad("ADVAPI32.DLL", "FreeEncryptionCertificateHashList",
            (PPFN)&pfnFreeEncryptionCertificateHashList)) {
        errno = EINVAL;
        return;
    }

    //
    // Convert the path name to Unicode for QueryUsersOnEncryptedFile
    //
    if (MultiByteToWideChar(get_codepage(), 0, ce->ce_abspath, -1,
            wszPath, FILENAME_MAX) == 0) {
        error(0, 0,
            "Cannot convert file name to UNICODE: \"%s\"\n", ce->ce_abspath);
        errno = ENOENT;
        return;
    }

    //
    // Print the names of the encryption principals
    // (NTFS limits to max 4 per file)
    //
    if ((dwError = (*pfnQueryUsersOnEncryptedFile)(wszPath, &pHashes)) != ERROR_SUCCESS) {
        SetLastError(dwError);
        MapWin32ErrorToPosixErrno();
        return;
    }
    if (pHashes->nCert_Hash > 0) {
        for (i=0; i < pHashes->nCert_Hash; ++i) {
            // Do _not_ use tabs (not allowed if -T0)
            more_printf("              Encryption key: %ws\n", pHashes->pUsers[i]->lpDisplayInformation);
        }
    }
    (*pfnFreeEncryptionCertificateHashList)(pHashes);  pHashes = NULL;

    //
    // Print the name of the recovery agents (max 4)
    //
    if ((dwError = (*pfnQueryRecoveryAgentsOnEncryptedFile)(wszPath, &pHashes)) != ERROR_SUCCESS) {
        SetLastError(dwError);
        MapWin32ErrorToPosixErrno();
        return;
    }
    if (pHashes->nCert_Hash > 0) {
        for (i=0; i < pHashes->nCert_Hash; ++i) {
            // Do _not_ use tabs (not allowed if -T0)
            more_printf("              Recovery agent: %ws\n", pHashes->pUsers[i]->lpDisplayInformation);
        }
    }
    (*pfnFreeEncryptionCertificateHashList)(pHashes);  pHashes = NULL;
    return;
}

///////////////////////////////////////////////////////////////////

//
// Note: Do *not* use the Win32 GetEffectiveRightsFromAcl!
//
// This API call can be very slow if Universal Groups are
// enabled.  This is because it attempts
// to cobble together a pseduo-token containing all of the
// security principal's groups.  It basically has to chase down
// and query domain controllers in each and every domain in
// the AD forest.
//
// Windows Server 2003 speeds up this operation by caching every
// security principal's group membership in the Glocal Cache.
// (Requires running in Windows Server 2003 native mode.)
// (This API is *not* documented [yet])
//

//
// Check the SID directly against the ACL
//
static void
_GetEffectiveRightsFromAcl(struct cache_entry* ce, PACL pAcl, PSID pSid,
    DWORD dwAttributes, PACCESS_MASK pMask/*merged*/)
{
    UINT i;
    PACCESS_ALLOWED_ACE pAce;
    ACCESS_MASK MaskDeny = 0;
    PSID pAceSid;

    UNREFERENCED_PARAMETER(ce);

    if ((dwAttributes & SE_GROUP_ENABLED) == 0) {
        //
        // UNDOCUMENTED: A non-elevated admin token on Vista
        // has group Administrators set to SE_GROUP_USE_DENY_ONLY=1
        // and SE_GROUP_ENABLED=0.
        //
        // Dont skip a non-enabled group if its use is deny-only.
        //
        if ((dwAttributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0) {
            return; // skip
        }
    }

    // No - Requires VS2005 exception handling lib
    //__try { // in case of memory access violations due to garbage ACLs

        pAce = (PACCESS_ALLOWED_ACE)(pAcl+1);

        for (i=0; i < pAcl->AceCount; ++i, pAce = (PACCESS_ALLOWED_ACE)((PBYTE)pAce+pAce->Header.AceSize)) {
            if (pAce->Header.AceFlags & INHERIT_ONLY_ACE) {
                continue; // Skip inherit-only ACEs
            }
            if (pAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
                if ((dwAttributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0) {
                    pAceSid = (PSID)&pAce->SidStart;
                    if (::EqualSid(pSid, pAceSid)) {
                        *pMask |= pAce->Mask;
                    }
                }
            } else if (pAce->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
                pAceSid = (PSID)&((PACCESS_DENIED_ACE)pAce)->SidStart;
                if (::EqualSid(pSid, pAceSid)) {
                    MaskDeny |= pAce->Mask;
                }
            }
            // Audit ACE or unknown ACE, ignore
        }

        //
        // The Deny bits always override the Allow bits
        //
        *pMask &= ~MaskDeny;

    //} __except(EXCEPTION_EXECUTE_HANDLER) {
    //  error(0, 0, "Garbage ACL detected in %s", ce->ce_abspath);
    //}
    return;
}

//
// Like mode_string() in filemode.c except use NTFS-style checks
//
// Assumes szMode is pre-allocated with 10 bytes for -rwxrwxrwx
//
void
win32_mode_string(struct stat *st, char *szMode)
{
    struct cache_entry *ce;
    SD sd;
    PSECURITY_DESCRIPTOR psd;
    BOOL bPresent = FALSE, bDefaulted = FALSE;
    DWORD dwBufferSize;
    PACL pAcl;
    ACCESS_MASK mask, appMask;
    PSID pGroupSid;
    BOOL bBinaryExecutable;
    UINT i;

#ifndef SECURITY_APP_PACKAGE_AUTHORITY
# define SECURITY_APP_PACKAGE_AUTHORITY {0,0,0,0,0,15}
# define SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT (2L)
# define SECURITY_APP_PACKAGE_BASE_RID  (0x00000002L)
# define SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE   (0x00000001L)
#endif
    static HANDLE hToken; // cached
    static BYTE UserBuffer[80]; // cached
    static PSID pUserSid; // cached
    static BYTE GroupsBuffer[16384]; // cached
    static PTOKEN_GROUPS pTokenGroups; // cached
    static SID_IDENTIFIER_AUTHORITY siaWorldAuthority = SECURITY_WORLD_SID_AUTHORITY;
    static SID_IDENTIFIER_AUTHORITY siaNtAuthority = SECURITY_NT_AUTHORITY;
    static SID_IDENTIFIER_AUTHORITY siaAppPackageAuthority = SECURITY_APP_PACKAGE_AUTHORITY;
    static PSID pSidEveryone, pSidUsers, pSidAuthenticatedUsers, pSidAllApplicationPackages;
    static BYTE SidEveryoneBuffer[32], SidUsersBuffer[32];
    static BYTE SidAuthenticatedUsersBuffer[32];
    static BYTE SidAllApplicationPackagesBuffer[32];

    ce = st->st_ce;

    //
    // Fill in defaults per Unix
    //
    // In particular fill szMode[0] with the file-type byte
    //
    mode_string(st->st_mode, szMode);

    if (acls_format == acls_none) {
        goto check_attribs; // punt
    }

    if (!_LoadSecurityDescriptor(ce, sd)) {
        //
        // run_fast on network drive, or
        // Windows 9x or FAT filesystem.
        //
        goto check_attribs; // punt
    }

    //
    // Got psd
    //
    psd = sd.GetSd();

    //
    // Dig out the DACL from the file SD
    //
    if (!::GetSecurityDescriptorDacl(psd, &bPresent, &pAcl, &bDefaulted)) {
        goto check_attribs; // punt
    }

    //
    // BUG: When querying a FAT file system, bPresent != 0 but pAcl == NULL
    //

    if (!bPresent || pAcl == NULL) { // no DACL means allow everything
        goto check_attribs;
    }

    if (hToken == INVALID_HANDLE_VALUE) { // failed previously
        goto check_attribs;
    }

    if (pSidEveryone == NULL) { // if first time
        //
        // First time - get the user and groups SIDs
        //
        if (view_as == NULL) {
            //
            // Get user and groups SIDs from the process token
            //

            //
            // Note: If somehow we are running under an Impersonation Token
            // this will still return correct info.
            //
            if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                hToken = INVALID_HANDLE_VALUE;
                goto check_attribs; // punt
            }

            if (!::GetTokenInformation(hToken, ::TokenUser, UserBuffer, sizeof(UserBuffer), &dwBufferSize)) {
                ::CloseHandle(hToken);
                hToken = INVALID_HANDLE_VALUE;
                goto check_attribs; // punt
            }
            pUserSid = ((PTOKEN_USER)UserBuffer)->User.Sid;

            if (!::GetTokenInformation(hToken, ::TokenGroups, GroupsBuffer, sizeof(GroupsBuffer), &dwBufferSize)) {
                ::CloseHandle(hToken);
                hToken = INVALID_HANDLE_VALUE;
                goto check_attribs; // punt
            }
            pTokenGroups = (PTOKEN_GROUPS)GroupsBuffer;
            ::CloseHandle(hToken);

        } else { // view_as
            //
            // Get user and groups SIDs from the view_as user
            //
            // Used by --user=name to get effective permissions
            //
            pUserSid = (PSID)UserBuffer;
            pTokenGroups = (PTOKEN_GROUPS)GroupsBuffer;

            //
            // Mimic GetTokenInformation
            //
            if (!_GetViewAs(view_as, pUserSid, sizeof(UserBuffer),
                    pTokenGroups, sizeof(GroupsBuffer), &dwBufferSize)) {
                hToken = INVALID_HANDLE_VALUE;
                goto check_attribs; // punt
            }
        }

        //
        // Users S-1-5-32-545
        // Includes all users except NULL logon and SYSTEM.
        //
        // Note: A user in group Administrators is _not_ necessarily
        // a member of this group (e.g, SYSTEM).
        //
        pSidUsers = (PSID) SidUsersBuffer;
        ::InitializeSid(pSidUsers, &siaNtAuthority, 2/*nSubauthorities*/);
        *::GetSidSubAuthority(pSidUsers, 0) = SECURITY_BUILTIN_DOMAIN_RID;
        *::GetSidSubAuthority(pSidUsers, 1) = DOMAIN_ALIAS_RID_USERS;

        //
        // Everyone = S-1-1-0
        // Includes all users.
        // Exception: It excludes NULL logon if via network (XP or later).
        //
        pSidEveryone = (PSID) SidEveryoneBuffer;
        ::InitializeSid(pSidEveryone, &siaWorldAuthority, 1/*nSubauthorities*/);
        *GetSidSubAuthority(pSidEveryone, 0) = SECURITY_WORLD_RID;

        //
        // Authenticated Users S-1-5-32-11
        // Includes all users except NULL logon
        //
        // Note: *Does* include Guests and IUSR_xxx.  Includes SYSTEM.
        //
        // Heuristic: This group is used to set the 'group' mode bytes.
        //
        pSidAuthenticatedUsers = (PSID) SidAuthenticatedUsersBuffer;
        ::InitializeSid(pSidAuthenticatedUsers, &siaNtAuthority, 2/*nSubauthorities*/);
        *::GetSidSubAuthority(pSidAuthenticatedUsers, 0) = SECURITY_BUILTIN_DOMAIN_RID;
        *::GetSidSubAuthority(pSidAuthenticatedUsers, 1) = SECURITY_AUTHENTICATED_USER_RID;

        //
        // APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES (WinRT)
        // S-1-15-2-1
        //
        pSidAllApplicationPackages = (PSID) SidAllApplicationPackagesBuffer;
        ::InitializeSid(pSidAllApplicationPackages, &siaAppPackageAuthority, SECURITY_BUILTIN_APP_PACKAGE_RID_COUNT/*nSubauthorities=2*/);
        *::GetSidSubAuthority(pSidAllApplicationPackages, 0) = SECURITY_APP_PACKAGE_BASE_RID; // 2
        *::GetSidSubAuthority(pSidAllApplicationPackages, 1) = SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE; // 1

        //
        // Heuristic: Everyone and Authenticated Users are used to
        // set the 'other' mode bytes.
        //
        // The interpreted meaning is "absolutely everybody"
        //
    }

    //
    // Clear all flags
    //
    memset(&szMode[1], '-', 9); // ----------

    //
    // Heuristic: Assume a binary executable if not .BAT or .CMD
    // (See also dirent.c)
    //
    bBinaryExecutable = (st->st_mode & S_IXUSR) &&
        !(_stricmp(right(ce->ce_abspath,4),".bat") == 0 ||
        _stricmp(right(ce->ce_abspath,4),".cmd") == 0);

    //////////////////////////////////////////////////////////
    //
    // Check user token against the ACL
    //
    mask = 0;

    _GetEffectiveRightsFromAcl(ce, pAcl, pUserSid, SE_GROUP_ENABLED, &mask);

    for (i=0; i < pTokenGroups->GroupCount; ++i) {
        pGroupSid = pTokenGroups->Groups[i].Sid;
        ULONG dwAttr = pTokenGroups->Groups[i].Attributes;
        _GetEffectiveRightsFromAcl(ce, pAcl, pGroupSid, dwAttr, &mask);
    }

    /////// Set owner mode chars
    if (gbReg) {
        if (mask & KEY_QUERY_VALUE) {
            szMode[1]='r';
        }
        if (mask & KEY_SET_VALUE) {
            szMode[2]='w';
        } else if (mask & KEY_CREATE_SUB_KEY) {
            szMode[2] = 'a';  // rare --a------- // keys but not values
        }
        if (mask & KEY_ENUMERATE_SUB_KEYS) {
            szMode[3] = 'x';
        }
    } else {
        if (mask & FILE_READ_DATA/*=FILE_LIST_DIRECTORY*/) {
            szMode[1]='r';
            if (!bBinaryExecutable && (st->st_mode & S_IXUSR)) { // .CMD or .BAT
                szMode[3] = 'x';
            }
        }
        if (mask & FILE_WRITE_DATA/*=FILE_ADD_FILE*/) {
            szMode[2]='w';
        } else if (mask & FILE_APPEND_DATA) {
            szMode[2] = 'a';  // rare --a-------
        }
        if (bBinaryExecutable && (mask & FILE_EXECUTE)) {
            szMode[3] = 'x';
        }
    }


    //////////////////////////////////////////////////////////
    //
    // Set the group rw mode bytes based on Users
    // and Authenticated Users (merged)
    //

    mask = 0;

    _GetEffectiveRightsFromAcl(ce, pAcl, pSidUsers, SE_GROUP_ENABLED, &mask);
    _GetEffectiveRightsFromAcl(ce, pAcl, pSidAuthenticatedUsers, SE_GROUP_ENABLED, &mask);

    /////// Set group mode chars
    if (gbReg) {
        if (mask & KEY_QUERY_VALUE) {
            szMode[4]='r';
        }
        if (mask & KEY_SET_VALUE) {
            szMode[5]='w';
        } else if (mask & KEY_CREATE_SUB_KEY) {
            szMode[5] = 'a';  // rare --a------- // keys but not values
        }
        if (mask & KEY_ENUMERATE_SUB_KEYS) {
            szMode[6] = 'x';
        }
    } else {
        if (mask & FILE_READ_DATA/*=FILE_LIST_DIRECTORY*/) {
            szMode[4]='r';
            if (!bBinaryExecutable && (st->st_mode & S_IXUSR)) { // .CMD or .BAT
                szMode[6] = 'x';
            }
        }
        if (mask & FILE_WRITE_DATA/*=FILE_ADD_FILE*/) {
            szMode[5]='w';
        } else if (mask & FILE_APPEND_DATA) {
            szMode[5] = 'a';  // rare -----a----
        }
        if (bBinaryExecutable && (mask & FILE_EXECUTE)) {
            szMode[6] = 'x';
        }
    }

    /////////////////////////////////////////////////////////
    //
    // Set the other rw mode bytes based on Everyone
    // and Authenticated Users
    //

    mask = 0; appMask = 0;

    _GetEffectiveRightsFromAcl(ce, pAcl, pSidEveryone, SE_GROUP_ENABLED, &mask);
    _GetEffectiveRightsFromAcl(ce, pAcl, pSidAuthenticatedUsers, SE_GROUP_ENABLED, &mask);
    _GetEffectiveRightsFromAcl(ce, pAcl, pSidAllApplicationPackages, SE_GROUP_ENABLED, &appMask);

    /// other mode chars
    if (gbReg) {
        if (mask & KEY_QUERY_VALUE) {
            szMode[7]='r';
        }
        if (mask & KEY_SET_VALUE) {
            szMode[8]='w';
        } else if (mask & KEY_CREATE_SUB_KEY) {
            szMode[8] = 'a';  // rare --a------- // keys but not values
        }
        if (mask & KEY_ENUMERATE_SUB_KEYS) {
            szMode[9] = 'x';
        }
    } else {
        if (mask & FILE_READ_DATA/*=FILE_LIST_DIRECTORY*/) {
            szMode[7]='r';
            if (!bBinaryExecutable && (st->st_mode & S_IXUSR)) { // .CMD or .BAT
                szMode[9] = 'x';
            }
        }
        if (mask & FILE_WRITE_DATA/*=FILE_ADD_FILE*/) {
            szMode[8]='w';
        } else if (mask & FILE_APPEND_DATA) {
            szMode[8] = 'a';  // rare --------a-
        }
        if (bBinaryExecutable && (mask & FILE_EXECUTE)) {
            szMode[9] = 'x';
        }
    }

    // All Application Packages
    if (gbReg) {
        if (appMask & KEY_QUERY_VALUE) {
            szMode[7]='R';
        }
        if (appMask & KEY_SET_VALUE) {
            szMode[8]='W';
        } else if (appMask & KEY_CREATE_SUB_KEY) {
            szMode[8] = 'A';  // rare --a------- // keys but not values
        }
        if (appMask & KEY_ENUMERATE_SUB_KEYS) {
            szMode[9] = 'X';
        }
    } else {
        if (appMask & FILE_READ_DATA/*=FILE_LIST_DIRECTORY*/) {
            szMode[7]='R';
            if (!bBinaryExecutable && (st->st_mode & S_IXUSR)) { // .CMD or .BAT
                szMode[9] = 'X';
            }
        }
        if (appMask & FILE_WRITE_DATA/*=FILE_ADD_FILE*/) {
            szMode[8]='W';
        } else if (appMask & FILE_APPEND_DATA) {
            szMode[8] = 'A';  // rare --------a-
        }
        if (bBinaryExecutable && (appMask & FILE_EXECUTE)) {
            szMode[9] = 'X';
        }
    }

check_attribs:
    //
    // Set mode chars based on the file attributes
    //
    //
    // Finally, if the file has the Readonly, System or Hidden attributes, clear
    // all write bits.
    //

    if (ce->dwFileAttributes & (FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN)) {
        szMode[2] = '-';
        szMode[5] = '-';
        szMode[8] = '-';
    }

    //
    // Emphasize the read-only attribute with 'R', but only if we can
    // read the file in the first place.
    //
    if (ce->dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
        if (szMode[1] == 'r') {
            szMode[1] = 'R';
        }
#ifdef UNDEFINED
        if (szMode[4] == 'r') {
            szMode[4] = 'R';
        }
        if (szMode[7] == 'r') {
            szMode[7] = 'R';
        }
#endif
    }

    return;
}
///////////////////////////////////////////////////////////////////

} // end extern "C"

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

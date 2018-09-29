//////////////////////////////////////////////////////////////////////////
//
// ViewAs.cpp - View effective permissions for another user.  (--user=name)
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
//
// Distributed under GNU General Public License version 2.
//

//
// Build a pseudo-token by interrogating the various domain controllers
// and cobbling together a list of all direct and indirect groups in
// which the named user is a member, relative to the local computer.
// Then apply it the against the file ACL to build the effective
// permission mask.
//
// Note: Universal groups seem to be handled properly in Windows Server 2003.
// It chases down all the domains in the forest to cobble together the
// final group list.  It does *not* appear to work on Windows 2000 Server,
// however. (Possibly because only W2K3 puts Universal Group membership into
// the Global Cache.)
//

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
// For VC6, disable warnings from various standard Windows headers
// NOTE: #pragma warning(push) ... #pragma warning(pop) is broken/unusable for MSVC 6 (re-enables multiple other warnings)
#pragma warning(disable: 4068)  // DISABLE: unknown pragma warning
#pragma warning(disable: 4035)  // DISABLE: no return value warning
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <lm.h>  // for NetXxx

#if defined(_MSC_VER) && (_MSC_VER < 1300)  // RIVY
#pragma warning(default: 4068)  // RESET: unknown pragma warning
#pragma warning(default: 4035)  // RESET: no return value warning
#endif

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

//
// Stupid MSVC doesn't define __STDC__
//
#ifndef __STDC__
# define __STDC__ 1
#endif

#include "error.h"
#include "more.h"

#define NEED_DIRENT_H
#define NEED_CSTR_H
#define NEED_HASH_H
#include "windows-support.h"
#include "xalloc.h"
#include "xmbrtowc.h" // for get_codepage()
#include "ls.h" // for sids_format, gids_format

#undef strrchr
#define strrchr _mbsrchr // use the multibyte version of strrchr

#define MAX_SID_LEN 32  // real max is 28

//
// Grovel for groups
//
// wszServer = \\DOMAINNAME or \\COMPUTERNAME
//
static BOOL
_GetGroups(LPWSTR wszServer, LPWSTR wszUser, PTOKEN_GROUPS pTokenGroups,
    PSID* ppGroupSid)
{
    LPWSTR wsz;
    PGROUP_USERS_INFO_0 pgrui0 = NULL;
    NET_API_STATUS nas;
    DWORD nGroups=0, nTotal=0, i;
    WCHAR wszUserDomain[80];
    DWORD cbSid, ccDomain;
    LPWSTR wszGroup;
    SID_NAME_USE eSidNameType; // unused
    //
    // "global" groups, such as Domain Users and Domain Admins
    //
    // These have meaning across the whole domain
    //
    // Group members are stored in the SAM with long SIDs.
    //
    // Groups can have nested groups as members (typically local groups
    // like Administrators)
    //
    // Global groups are not intended to be installed in the SAM
    // on standalone computers, but have been seen in rare cases
    // (e.g. with Commerce Server).  NetUserGetGroups
    // always fails on standalone computers.   Instead we depend on
    // global groups containing only local groups (which will be picked up
    // by LG_INCLUDE_INDIRECT when we enumerate local groups later.)
    //
    // NetUserGetGroups requires wszUser *not* wszDomUser.
    //
    // No domain prefix allowed for this call!!
    //

    if ((wsz = wcschr(wszUser, L'\\')) != 0) { // if domain\user
        wszUser = wsz+1;  // strip domain\  (required)
    }

    nas = ::NetUserGetGroups(wszServer, wszUser,
        0, (LPBYTE*)&pgrui0, 1048576, &nGroups, &nTotal);

    if (nas != NERR_Success && nas != ERROR_MORE_DATA) {
        //
        // This is a normal error when the user's SID prefix does
        // not match the SAM server's SID prefix.
        //
        // e.g., looking up a domain user on the local member computer,
        // or looking up a local user on the domain controller computer.
        //
#ifdef _DEBUG
        error(0, 0, "Unable to get groups on %ws for %ws (%d) - ignore",
            wszServer, wszUser, nas);
#endif
        return TRUE; // not an error
    }

    for (i=0; i < nGroups; ++i) {
        wszGroup = pgrui0[i].grui0_name;
        cbSid = MAX_SID_LEN;
        ccDomain = sizeof(wszUserDomain) / sizeof(WCHAR);
        if (!::LookupAccountNameW(wszServer+2, wszGroup,
                *ppGroupSid, &cbSid,
                wszUserDomain, &ccDomain, &eSidNameType)) {
            error(0, 0, "Unable to look up SID on %ws for group %ws.",
                wszServer+2, wszGroup);
        } else {
            if ((PBYTE)*ppGroupSid - (PBYTE)pTokenGroups < sizeof(TOKEN_GROUPS)) {
                error(0, 0, "Too many groups for buffer.");
                ::NetApiBufferFree(pgrui0);
                return FALSE;
            }
#ifdef _DEBUG
            more_printf("Is member of group %ws (SID %u) on %ws\n",
                wszGroup, *::GetSidSubAuthority(*ppGroupSid, 1), wszServer);
#endif
            pTokenGroups->Groups[pTokenGroups->GroupCount].Sid = *ppGroupSid;
            pTokenGroups->Groups[pTokenGroups->GroupCount].Attributes = SE_GROUP_ENABLED;
            pTokenGroups->GroupCount++;
            //
            // Bump next sid backwards (started at top)
            //
            *ppGroupSid = (PSID)(((PBYTE)*ppGroupSid) - MAX_SID_LEN);
        }
    }
    if (pgrui0 != NULL) {
        ::NetApiBufferFree(pgrui0);  pgrui0 = NULL;
    }
    return TRUE;
}


//
// Grovel for local groups
//
// wszServer = \\DOMAINNAME or \\COMPUTERNAME
//
static BOOL
_GetLocalGroups(LPWSTR wszServer, LPWSTR wszUser, PTOKEN_GROUPS pTokenGroups,
    PSID* ppGroupSid)
{
    PLOCALGROUP_USERS_INFO_0 plgrui0 = NULL;
    NET_API_STATUS nas;
    DWORD nLocalGroups=0, nLocalTotal=0, i;
    WCHAR wszUserDomain[80];
    DWORD cbSid, ccDomain;
    LPWSTR wszGroup;
    SID_NAME_USE eSidNameType; // unused

    //
    // "local" groups, such as Administrators and Users
    //
    // These have meaning on the local computer only.  When stored
    // on a DC they have meaning among the DCs only.
    //
    // Local Group members are stored in the SAM with the only the RID.
    //
    // LG_INCLUDE_INDIRECT = include additional local groups
    // in which the user is indirectly a member (that is, the
    // user has membership in a global group that is itself a
    // member of one or more local groups).
    //

    nas = ::NetUserGetLocalGroups(wszServer, wszUser,
        0, LG_INCLUDE_INDIRECT, (LPBYTE*)&plgrui0, 1048576,
        &nLocalGroups, &nLocalTotal);

    if (nas != NERR_Success && nas != ERROR_MORE_DATA) {
        //
        // This is a normal error if looking up on the wrong server
        //
#ifdef _DEBUG
        error(0, 0, "Unable to get local groups on %ws for %ws (%d) - ignore",
            wszServer, wszUser, nas);
#endif
        return TRUE; // not an error
    }

    for (i=0; i < nLocalGroups; ++i) {
        wszGroup = plgrui0[i].lgrui0_name;
        cbSid = MAX_SID_LEN;
        ccDomain = sizeof(wszUserDomain) / sizeof(WCHAR);
        if (!::LookupAccountNameW(wszServer+2, wszGroup,
                *ppGroupSid, &cbSid,
                wszUserDomain, &ccDomain, &eSidNameType)) {
            error(0, 0, "Unable to look up SID on %ws for group %ws.",
                wszServer+2, wszGroup);
        } else {
            if ((PBYTE)*ppGroupSid - (PBYTE)pTokenGroups < sizeof(TOKEN_GROUPS)) {
                error(0, 0, "Too many groups for buffer.");
                ::NetApiBufferFree(plgrui0);
                return FALSE;
            }
#ifdef _DEBUG
            more_printf("Is member of local group %ws (SID %u) on %ws\n",
                wszGroup, *::GetSidSubAuthority(*ppGroupSid, 1), wszServer);
#endif
            pTokenGroups->Groups[pTokenGroups->GroupCount].Sid = *ppGroupSid;
            pTokenGroups->Groups[pTokenGroups->GroupCount].Attributes = SE_GROUP_ENABLED;
            pTokenGroups->GroupCount++;
            //
            // Bump next sid backwards (started at top)
            //
            *ppGroupSid = (PSID)(((PBYTE)*ppGroupSid) - MAX_SID_LEN);
        }
    }
    if (plgrui0 != NULL) {
        ::NetApiBufferFree(plgrui0);  plgrui0 = NULL;
    }
    return TRUE;
}


//
// Mimic ::GetTokenInformation to get all of the user's group SIDs.
//
// Used by --user to view security from the viewpoint of the named user.
//
BOOL
_GetViewAs(char* szViewAs, PSID pUserSid, DWORD cbSid,
    PTOKEN_GROUPS pTokenGroups, DWORD cbGroups, PDWORD pdwGroupsSize)
{
    LPWSTR wszComputerName; // from environment
    WCHAR wszServer[80];
    WCHAR wszUserDomain[80];
    WCHAR wszSamDomain[80]; // computer's SAM domain
    PUSER_MODALS_INFO_2 pumi2 = NULL;
    NET_API_STATUS nas;
    DWORD ccDomain = sizeof(wszUserDomain) / sizeof(WCHAR);
    SID_NAME_USE eSidNameType; // unused
    WCHAR wszUser[80], wszDomUser[80];
    PSID pGroupSid;
    static PPFN pfnDummy;

    pTokenGroups->GroupCount = 0;

    //
    // Point to end of buffer - MAX_SID_LEN
    //
    pGroupSid = (PSID)(((PBYTE)pTokenGroups) + cbGroups - MAX_SID_LEN);

    if (stricmp(szViewAs, "System") == 0) {
        //
        // Optimize: Change "System" -> "NT AUTHORITY\SYSTEM" to
        // avoid scanning all the domain controllers.
        //
        szViewAs = "NT AUTHORITY\\SYSTEM";
    } else if (stricmp(szViewAs, "Local Service") == 0) {
        szViewAs = "NT AUTHORITY\\Local Service";
    } else if (stricmp(szViewAs, "Network Service") == 0) {
        szViewAs = "NT AUTHORITY\\Network Service";
    }

    //
    // Convert szViewAs to wszUser
    //
    if (!::MultiByteToWideChar(get_codepage(), 0, szViewAs, -1,
            wszUser, sizeof(wszUser)/sizeof(WCHAR))) {
        error(EXIT_FAILURE, 0, "Cannot convert user name to wide char.");
        /*NOTREACHED*/
        return FALSE;
    }

    //
    // Test to see if we have NETAPI32.DLL.
    // (Actual calls use /DELAYLOAD)
    //
    if (!DynaLoad("NETAPI32.DLL", "NetUserGetGroups",
            (PPFN)&pfnDummy)) {
        //
        // Fail on Windows 9x.  I could (I suppose) use a 16-bit thunk DLL
        // to the 16-bit NETAPI.DLL but it's too much work..
        //
        error(EXIT_FAILURE, 0, "This operating system does not support user name lookup.");
        /*NOTREACHED*/
        return FALSE;
    }

    //
    // Get the computer's "primary domain" (sic) name via NetUserModalsGet
    //
    // For a domain controller, this is the name of the domain that
    // the controller is a member of.  For non-DCs, this is the
    // name of the local computer -- even if it is a member of a domain.
    //
    // (Really the domain name of the local SAM.)
    //
    // Name does _not_ have \\ prefixed.
    //
    nas = ::NetUserModalsGet(NULL/*local*/, 2, (PBYTE*)&pumi2);
    if (nas != NERR_Success) {
        error(EXIT_FAILURE, 0, "Unable to get primary domain for computer (%d).", nas);
        /*NOTREACHED*/
        return FALSE;
    }
    wcscpy(wszSamDomain, pumi2->usrmod2_domain_name);
    ::NetApiBufferFree(pumi2);

#ifdef _DEBUG
    //more_printf("This computer's SAM domain is %ws\n", wszSamDomain);
#endif

    //
    // Look up the user name -> SID.
    //
    // The local computer will kick the query upstairs to a DC if it
    // cannot resolve it locally
    //

    //cbSid passed in from caller
    ccDomain = sizeof(wszUserDomain) / sizeof(WCHAR);

    if (!::LookupAccountNameW(NULL, wszUser, pUserSid, &cbSid,
            wszUserDomain, &ccDomain, &eSidNameType)) {
        // always fails on Win9x
        error(EXIT_FAILURE, 0, "User name not found: %ws", wszUser);
        /*NOTREACHED*/
        return FALSE;
    }

    //
    // Build Domain\User
    //
    if (wcschr(wszUser, L'\\') != 0) { // if already domain\user
        wcscpy(wszDomUser, wszUser); // use as-is
    } else {
        _snwprintf(wszDomUser, sizeof(wszDomUser)/sizeof(WCHAR),
            L"%ws\\%ws", wszUserDomain, wszUser);
    }

#ifdef _DEBUG
    more_printf("User %ws found in domain %ws\n", wszDomUser, wszUserDomain);
#endif

    wszComputerName = _wgetenv(L"COMPUTERNAME");

    if (wszComputerName == NULL) { // should always be non-null
        error(0, 0, "%%COMPUTERNAME%% not found.");
        return FALSE;
    }

    //
    // Phase 1: Scan the user's domain for groups and localgroups
    //
    // (Might be contacting a foreign domain controller here.)
    //
    // BUG: If the real user is logged on with a local account we cannot
    // interrogate the list of users/groups on the DC for the viewed user.
    //

    // Build \\DOMAINNAME from user's account domain
    _snwprintf(wszServer, sizeof(wszServer)/sizeof(WCHAR),
        L"\\\\%ws", wszUserDomain);

    // NetUserGetGroups does not grok domain\user
    _GetGroups(wszServer, wszUser/*not wszDomUser!*/,
        pTokenGroups, &pGroupSid);

    //
    // Get local groups only if  wszUserDomain == local SAM domain
    // i.e., logged on with a local account.
    //
    // Might still be a DC, in which case we will get getting groups
    // redundantly with below.
    //
    if (wcsicmp(wszUserDomain, wszSamDomain) == 0) {
        // NetUserGetLocalGroups *does* grok domain\user
        _GetLocalGroups(wszServer, wszDomUser,
            pTokenGroups, &pGroupSid);
    }

    if (wcsicmp(wszUserDomain, wszComputerName) != 0) { // if logged on with a domain account
        //
        // Phase 2: Scan the local computer for groups and localgroups
        //

        // Build \\COMPUTERNAME from %COMPUTERNAME%
        _snwprintf(wszServer, sizeof(wszServer)/sizeof(WCHAR),
            L"\\\\%ws", wszComputerName);

        // NetUserGetGroups does not grok domain\user
        _GetGroups(wszServer, wszUser/*not wszDomUser!*/,
            pTokenGroups, &pGroupSid);

        // NetUserGetLocalGroups *does* grok domain\user
        _GetLocalGroups(wszServer, wszDomUser,
            pTokenGroups, &pGroupSid);
    }

    *pdwGroupsSize = cbGroups;

    return TRUE;
}
/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

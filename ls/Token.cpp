//////////////////////////////////////////////////////////////////////////
//
// Token.cpp - Dump the process token
//
// Copyright (c) 2007-2018, U-Tools Software LLC
// Written by Alan Klietz
//
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

//#include <system.h> // for alloca()

//
// Stupid MSVC doesn't define __STDC__
//
#ifndef __STDC__
# define __STDC__ 1
#endif

#include "error.h"
#include "more.h"

#define NEED_CSTR_H
#include "windows-support.h"
#include "xalloc.h"
#include "xmbrtowc.h" // for get_codepage()
#include "ls.h" // for sids_format, gids_format

#undef strrchr
#define strrchr _mbsrchr // use the multibyte version of strrchr

#define MAX_SID_LEN 32  // real max is 28

//
// Vista
//
#ifndef SE_GROUP_INTEGRITY
# define SE_GROUP_INTEGRITY 0x20
#endif

#ifndef SE_GROUP_INTEGRITY_ENABLED
# define SE_GROUP_INTEGRITY_ENABLED 0x40
#endif

/////////////////////////////////////////////////////////////////////////////
#ifndef TOKEN_MANDATORY_POLICY_NO_WRITE_UP
# define TokenElevationType ((TOKEN_INFORMATION_CLASS)18)
# define TokenLinkedToken ((TOKEN_INFORMATION_CLASS)19)
# define TokenElevation ((TOKEN_INFORMATION_CLASS)20)
# define TokenHasRestrictions ((TOKEN_INFORMATION_CLASS)21)
// TokenAccessInformation
# define TokenVirtualizationAllowed ((TOKEN_INFORMATION_CLASS)23)
# define TokenVirtualizationEnabled ((TOKEN_INFORMATION_CLASS)24)
# define TokenIntegrityLevel ((TOKEN_INFORMATION_CLASS)25)
# define TokenUIAccess ((TOKEN_INFORMATION_CLASS)26)
# define TokenMandatoryPolicy ((TOKEN_INFORMATION_CLASS)27)
# define TokenLogonSid ((TOKEN_INFORMATION_CLASS)28)

//
// Token elevation values describe the relative strength of a given token.
// A full token is a token with all groups and privileges to which the principal
// is authorized.  A limited token is one with some groups or privileges
// removed.
//

typedef enum _TOKEN_ELEVATION_TYPE {
    TokenElevationTypeDefault = 1,
    TokenElevationTypeFull,
    TokenElevationTypeLimited,
} TOKEN_ELEVATION_TYPE, *PTOKEN_ELEVATION_TYPE;


typedef struct _TOKEN_LINKED_TOKEN {
    HANDLE LinkedToken;
} TOKEN_LINKED_TOKEN, *PTOKEN_LINKED_TOKEN;

typedef struct _TOKEN_ELEVATION {
    DWORD TokenIsElevated;
} TOKEN_ELEVATION, *PTOKEN_ELEVATION;

typedef struct _TOKEN_MANDATORY_LABEL {
    SID_AND_ATTRIBUTES Label;
} TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;

#define TOKEN_MANDATORY_POLICY_OFF             0x0
#define TOKEN_MANDATORY_POLICY_NO_WRITE_UP     0x1
#define TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN 0x2

#define TOKEN_MANDATORY_POLICY_VALID_MASK      (TOKEN_MANDATORY_POLICY_NO_WRITE_UP | \
                                                TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN)

typedef struct _TOKEN_MANDATORY_POLICY {
    DWORD Policy;
} TOKEN_MANDATORY_POLICY, *PTOKEN_MANDATORY_POLICY;

#endif // MaxTokenInfoClass <= 18
/////////////////////////////////////////////////////////////////////////////

//
// Security.cpp
//
extern BOOL LookupSidName(PSID pSid, LPTSTR szBuf, DWORD dwBufLen,
    SIDS_FORMAT eFormat);

static void
_DumpPrivileges(PTOKEN_PRIVILEGES pPrivileges)
{
    DWORD i;
    DWORD dwAttrib;
    BOOL bOr;
    char szBuf[128];
    DWORD dwBufLen;

    for (i=0; i < pPrivileges->PrivilegeCount; ++i) {

        dwBufLen = sizeof(szBuf);

        if (!::LookupPrivilegeName(NULL, &pPrivileges->Privileges[i].Luid,
                szBuf, &dwBufLen)) {
            strcpy(szBuf, "???");
        }

        more_printf("%-32s ", szBuf);

        //
        // Display privilege flags
        //
        bOr = FALSE;
        dwAttrib = pPrivileges->Privileges[i].Attributes;

        if (dwAttrib & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
            if (bOr) more_putchar('|');
            more_fputs("ENABLED_BY_DEFAULT", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_PRIVILEGE_ENABLED) {
            if (bOr) more_putchar('|');
            more_fputs("ENABLED", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_PRIVILEGE_REMOVED) {
            if (bOr) more_putchar('|');
            more_fputs("REMOVED", stdmore);
            bOr = TRUE;
        }
        more_putchar('\n');
    }
    return;
}

static void
_DumpGroups(PTOKEN_GROUPS pGroups)
{
    DWORD i;
    DWORD dwAttrib;
    BOOL bOr;
    char szBuf[128];
    DWORD dwBufLen;

    for (i=0; i < pGroups->GroupCount; ++i) {

        dwBufLen = sizeof(szBuf);

        if (!LookupSidName(pGroups->Groups[i].Sid, szBuf, sizeof(szBuf),
                sids_format)) {
            strcpy(szBuf, "???");
        }
        more_printf("%-33s ", szBuf);

        //
        // Display attrib flags
        //
        bOr = FALSE;
        dwAttrib = pGroups->Groups[i].Attributes;

        if (dwAttrib & SE_GROUP_MANDATORY) {
            if (bOr) more_putchar('|');
            more_fputs("MANDATORY", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_GROUP_ENABLED_BY_DEFAULT) {
            if (bOr) more_putchar('|');
            more_fputs("ENABLED_BY_DEFAULT", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_GROUP_ENABLED) {
            if (bOr) more_putchar('|');
            more_fputs("ENABLED", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_GROUP_OWNER) {
            if (bOr) more_putchar('|');
            more_fputs("OWNER", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_GROUP_USE_FOR_DENY_ONLY) {
            if (bOr) more_putchar('|');
            more_fputs("USE_FOR_DENY_ONLY", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_GROUP_INTEGRITY) {
            if (bOr) more_putchar('|');
            more_fputs("INTEGRITY", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_GROUP_INTEGRITY_ENABLED) {
            if (bOr) more_putchar('|');
            more_fputs("INTEGRITY_ENABLED", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_GROUP_LOGON_ID) {
            if (bOr) more_putchar('|');
            more_fputs("LOGON_ID", stdmore);
            bOr = TRUE;
        }

        if (dwAttrib & SE_GROUP_RESOURCE) {
            if (bOr) more_putchar('|');
            more_fputs("RESOURCE", stdmore);
            bOr = TRUE;
        }

        more_putchar('\n');
    }
    return;
}

static int _DumpToken(HANDLE hToken, BOOL bRecurseOk)
{
    DWORD dwError;
    DWORD dwBufferSize=0;
    BYTE PrivBuffer[2048];
    PTOKEN_PRIVILEGES pPrivileges;
    BYTE UserBuffer[80];
    PSID pUserSid;
    BYTE Buffer[32768];
    PTOKEN_GROUPS pTokenGroups;
    PTOKEN_SOURCE pTokenSource;
    PTOKEN_STATISTICS pTokenStatistics;
    PTOKEN_ORIGIN pTokenOrigin;
    PTOKEN_ELEVATION_TYPE pTokenElevationType;
    PTOKEN_LINKED_TOKEN pTokenLinkedToken;
    char szBuf[128];

    //DWORD i;

    //
    // Get privileges
    //
    if (!::GetTokenInformation(hToken, TokenPrivileges, PrivBuffer, sizeof(PrivBuffer), &dwBufferSize)) {
        error(EXIT_FAILURE, 0, "Unable to query the token user.  Error %d",
            GetLastError());
    }
    pPrivileges = (PTOKEN_PRIVILEGES)PrivBuffer;
    more_printf("\nToken Privileges:\n");
    _DumpPrivileges(pPrivileges);

    //
    // Get group SIDs
    //
    if (!::GetTokenInformation(hToken, TokenGroups, Buffer, sizeof(Buffer), &dwBufferSize)) {
        error(EXIT_FAILURE, 0, "Unable to query the token groups.  Error %d",
            GetLastError());
    }
    pTokenGroups = (PTOKEN_GROUPS)Buffer;
    more_printf("\nToken Groups:\n");
    _DumpGroups(pTokenGroups);

    if (::IsTokenRestricted(hToken)) {
        more_printf("\nThe token is restricted.\n");
    }

    //
    // Get restricted group SIDs (if any)
    //
    // This is used by service apps to adjust an impersonation token
    // to further restrict the impersonation token by removing certain groups
    // (esp Administrators).
    //
    // During a security check an object must pass an ACL check of _both_
    // the token's group list _and_ the token's restricted group list.  The
    // restricted token group list typically changes Administrators from
    // SE_GROUP_ENABLED to SE_GROUP_USE_FOR_DENY_ONLY.
    //
    // Used by Safer.
    //
    if (!::GetTokenInformation(hToken, TokenRestrictedSids, Buffer, sizeof(Buffer), &dwBufferSize)) {
        error(EXIT_FAILURE, 0, "Unable to query restricted SIDs.  Error %d",
            GetLastError());
    }
    pTokenGroups = (PTOKEN_GROUPS)Buffer;
    if (pTokenGroups->GroupCount != 0) {
        more_printf("\nRestricted SIDs:\n");
        _DumpGroups(pTokenGroups);
    }

    //
    // Get user SID
    //
    if (!::GetTokenInformation(hToken, TokenUser, UserBuffer, sizeof(UserBuffer), &dwBufferSize)) {
        error(EXIT_FAILURE, 0, "Unable to query the token user.  Error %d",
            GetLastError());
    }
    pUserSid = ((PTOKEN_USER)UserBuffer)->User.Sid;
    if (!LookupSidName(pUserSid, szBuf, sizeof(szBuf), sids_format)) {
        strcpy(szBuf, "???");
    }
    more_printf("\nToken User: ");
    more_printf("%-33s\n", szBuf);

    //
    // Get the token source
    //
    if (!::GetTokenInformation(hToken, TokenSource, Buffer, sizeof(Buffer), &dwBufferSize)) {
        error(EXIT_FAILURE, 0, "Unable to query the token source.  Error %d",
            GetLastError());
    }
    pTokenSource = (PTOKEN_SOURCE)Buffer;
    more_printf("Token Source: ");
    more_printf("0x%08X%08X  %-8.8s\n", pTokenSource->SourceIdentifier.HighPart,
        pTokenSource->SourceIdentifier.LowPart, pTokenSource->SourceName);

    //
    // Get the token origin LUID.
    //
    // A non-zero LUID incidates that the token has some sort of associated
    // network credentials (not just a naked token created via NtCreateToken).
    //
    // Fails with ERROR_INVALID_PARAMETER under the W2K SYSTEM account.
    //
    if (::GetTokenInformation(hToken, TokenOrigin, Buffer, sizeof(Buffer), &dwBufferSize)) {
        pTokenOrigin = (PTOKEN_ORIGIN)Buffer;
        DWORD dwLow = pTokenOrigin->OriginatingLogonSession.LowPart;
        DWORD dwHigh = (DWORD)pTokenOrigin->OriginatingLogonSession.HighPart;
        BOOL bFound = FALSE;

        if (dwLow != 0 || dwHigh != 0) {
            more_printf("Token Origin: ");
            if (dwHigh == 0) {
                switch (dwLow) {
                    //
                    // Logged on with an explicit password. The pw hash
                    // is assumed available for outgoing network access.
                    // e.g., logged on with LOGON32_LOGON_INTERACTIVE but
                    // not LOGON32_LOGON_NETWORK or AcceptSecurityContext().
                    //
                    case 0x3e7: // SYSTEM_LUID 999
                        bFound = TRUE;
                        // Inconsistent, dont use
                        //more_fputs("SYSTEM (created using an explicit password)\n", stdmore);
                        more_fputs("SYSTEM\n", stdmore);
                        break;
                    //
                    // Anonymous NULL network logon
                    // (NET USE Z: \\machine\share /USER:"")
                    //
                    // Generally disallowed on XP or later.
                    //
                    // _Not_ the Guest account (which uses SYSTEM_LUID).
                    //
                    case 0x3e6: // ANONYMOUS_LOGON_LUID 998
                        bFound = TRUE;
                        more_fputs("Anonymous Logon\n", stdmore);
                        break;
                    //
                    // Local Service account.  Created by Service Manager
                    // w/o password.  Services use a blank pw.
                    // No network credentials (except for self-identification
                    // when accepting incoming connections).
                    //
                    // XP or later.
                    //
                    case 0x3e5: // 997 LOCALSERVICE_LUID
                        bFound = TRUE;
                        more_fputs("LocalService\n", stdmore);
                        break;
                    //
                    // Network Service account.  Created by Service Manager
                    // w/o password.  Services use a blank password.
                    //
                    // The network credentials are those of
                    // the machine account and the machine pw hash.
                    //
                    // XP or later.
                    //
                    case 0x3e4: // 996 NETWORKSERVICE_LUID
                        bFound = TRUE; // machine acct
                        more_fputs("NetworkService\n", stdmore);
                        break;
                    //
                    // IUSER.  Created via IIS for the IIS worker process.
                    // No password associated.  No network credentials.
                    //
                    // Vista or later.
                    //
                    case 0x3e3: // 995 IUSER_LUID
                        bFound = TRUE;
                        more_fputs("IUser\n", stdmore);
                        break;
                    default:
                        break;
                }
            }
            if (!bFound) {
                //
                // Unknown LUID
                //
                more_printf("0x%08X%08X\n", dwHigh, dwLow);
            }
        }
    }

    //
    // Get the token's LUIDs
    //
    if (::GetTokenInformation(hToken, TokenStatistics, Buffer, sizeof(Buffer), &dwBufferSize)) {
        pTokenStatistics = (PTOKEN_STATISTICS)Buffer;
        //
        // The TokenId is unique per token.
        //
        more_printf("Token LUID: ");
        more_printf("0x%08X%08X\n",
            pTokenStatistics->TokenId.HighPart,
            pTokenStatistics->TokenId.LowPart);
        //
        // The AuthenticationId is unique per logon.  It is used for establishing
        // network connections (SMB/NETLOGON/RPC).  It is the basis
        // for generating a per-connection 'session' encryption-key.
        // The session key is created by encrypting the AuthenticationId
        // with the user's logon password credentials.
        //
        // Assigned by the domain controller for the logon session.
        //
        more_printf("Token AuthenticationId: ");
        more_printf("0x%08X%08X  (Logon session ID)\n",
            pTokenStatistics->AuthenticationId.HighPart,
            pTokenStatistics->AuthenticationId.LowPart);
        //
        // The ModifiedId is a serial number that increments (randomly)
        // if the token is modified is any way.  Used by security-sensitive
        // applications to detect any modification/tampering of the token.
        //
        more_printf("Token ModifiedID: ");
        more_printf("0x%08X%08X\n",
            pTokenStatistics->ModifiedId.HighPart,
            pTokenStatistics->ModifiedId.LowPart);
        switch (pTokenStatistics->TokenType) {
            case TokenPrimary:
                more_printf("Token Type: Primary\n");
                break;
            case TokenImpersonation:
                more_printf("Token Type: Impersonation\n");
                break;
            default:
                more_printf("Token Type: Unknown\n");
                break;
        }
        // TokenType is undefined for a primary token
        if (pTokenStatistics->TokenType != TokenPrimary) {
            switch ((int)pTokenStatistics->TokenType) {
                case SecurityAnonymous:
                    more_printf("Token Impersonation Level: Anonymous\n");
                    break;
                case SecurityIdentification:
                    more_printf("Token Impersonation Level: Identification\n");
                    break;
                case SecurityImpersonation:
                    more_printf("Token Impersonation Level: Impersonation\n");
                    break;
                case SecurityDelegation:
                    more_printf("Token Impersonation Level: Delegation\n");
                    break;
                default:
                    more_printf("Token Impersonation Level: Unknown\n");
                    break;
            }
        }
    }

    //
    // Impersonation flag
    //
    if (::GetTokenInformation(hToken, TokenType, Buffer, sizeof(Buffer), &dwBufferSize)) {
        if (*(TOKEN_TYPE*)Buffer != TokenPrimary) {
            more_printf("Token is an Impersonation token.\n");
        }
    }

    //
    // Terminal Services session ID
    //
    if (::GetTokenInformation(hToken, TokenSessionId, Buffer, sizeof(Buffer), &dwBufferSize)) {
        more_printf("Terminal Services Session ID: %u\n", *(PDWORD)Buffer);
    }

    //
    // SandBoxInert flag.  Exists on W2K.  Appears to be unused.
    // Not used for Vista low elevation in MSIE 7.
    //
    *(PDWORD)Buffer = 0;
    if (::GetTokenInformation(hToken, TokenSandBoxInert, Buffer, sizeof(Buffer), &dwBufferSize)) {
        if (*(PDWORD)Buffer != 0) {
            more_printf("Token is in the inert sandbox.\n");
        }
    }

    //
    // Token elevation flag
    //
    if (::GetTokenInformation(hToken, TokenElevation, Buffer, sizeof(Buffer), &dwBufferSize)) {
        if (((PTOKEN_ELEVATION)Buffer)->TokenIsElevated != 0) {
            more_printf("Token is elevated.\n");
        }
    }

    //
    // Token elevation type
    //
    if (::GetTokenInformation(hToken, TokenElevationType, Buffer, sizeof(Buffer), &dwBufferSize)) {
        pTokenElevationType = (PTOKEN_ELEVATION_TYPE)Buffer;
        more_fputs("Token Elevation Type: ", stdmore);
        switch (*pTokenElevationType) {
            //
            // UAC disabled or non-admin user.
            //
            case TokenElevationTypeDefault:
                more_fputs("Default\n", stdmore);
                break;
            //
            // Elevated admin user (UAC enabled).
            //
            case TokenElevationTypeFull:
                more_fputs("Full\n", stdmore);
                break;
            //
            // Non-elevated admin user (UAC enabled).
            //
            case TokenElevationTypeLimited:
                more_fputs("Limited\n", stdmore);
                break;
            default:
                more_fputs("???\n", stdmore);
                break;
        }
    }

    //
    // Restrictions flag.  The flag is set if the token has been
    // filtered (e.g., a non-elevated admin user).
    //
    *(PDWORD)Buffer = 0;
    if (::GetTokenInformation(hToken, TokenHasRestrictions, Buffer, sizeof(Buffer), &dwBufferSize)) {
        if (*(PDWORD)Buffer != 0) {
            more_printf("Token has been filtered (restricted).\n");
        }
    }

    //
    // VirtualizationAllowed flag
    //
    // Typically set if UAC is running.
    //
    *(PDWORD)Buffer = 0;
    if (::GetTokenInformation(hToken, TokenVirtualizationAllowed, Buffer, sizeof(Buffer), &dwBufferSize)) {
        if (*(PDWORD)Buffer != 0) {
            more_printf("File/Registry virtualization is allowed.\n");
        }
    }

    //
    // VirtualizationEnabled flag.   VirtualizationAllowed must be set first.
    //
    *(PDWORD)Buffer = 0;
    if (::GetTokenInformation(hToken, TokenVirtualizationEnabled, Buffer, sizeof(Buffer), &dwBufferSize)) {
        if (*(PDWORD)Buffer != 0) {
            more_printf("File/Registry virtualization is enabled.\n");
        }
    }

    //
    // Integrity level
    //
    *(PDWORD)Buffer = 0;
    if (::GetTokenInformation(hToken, TokenIntegrityLevel, Buffer, sizeof(Buffer), &dwBufferSize)) {
        PTOKEN_MANDATORY_LABEL pTml = (PTOKEN_MANDATORY_LABEL)Buffer;
        // pTml->Label.Attributes = SE_GROUP_INTEGRITY (0x20)
        if (!LookupSidName(pTml->Label.Sid, szBuf, sizeof(szBuf), sids_format)) {
            strcpy(szBuf, "???");
        }
        more_printf("Token Integrity Level: %s\n", szBuf);
    }

    //
    // UIAccess.  This permits injecting SendKeys and mouse movements
    // into other GUI apps on the same desktop, even if they are at a higher
    // integrity level.  Rare.  The program must be installed in
    // C:\Program Files and have UIAccess="True" in the manifest.
    //
    *(PDWORD)Buffer = 0;
    if (::GetTokenInformation(hToken, TokenUIAccess, Buffer, sizeof(Buffer), &dwBufferSize)) {
        if (*(PDWORD)Buffer != 0) {
            more_printf("Token has UIAccess enabled.\n");
        }
    }

    //
    // Mandatory policy
    //
    *(PDWORD)Buffer = 0;
    if (::GetTokenInformation(hToken, TokenMandatoryPolicy, Buffer, sizeof(Buffer), &dwBufferSize)) {
        PTOKEN_MANDATORY_POLICY pPolicy;
        pPolicy = (PTOKEN_MANDATORY_POLICY)Buffer;
        //
        // All accounts including SYSTEM enforce integrity levels
        // via TOKEN_MANDATORY_POLICY_NO_WRITE_UP.
        //
        // The only way to disable enforcement of integrity levels
        // is to hack a custom token using NtCreateToken() and omit
        // TOKEN_MANDATORY_POLICY_NO_WRITE_UP.
        //
        if (pPolicy->Policy == 0) { // should never happen on non-hacked system
            more_printf("Token overrides integrity levels.\n");
        }
        if (pPolicy->Policy & TOKEN_MANDATORY_POLICY_NO_WRITE_UP) {
            more_printf("Token has TOKEN_MANDATORY_POLICY_NO_WRITE_UP.\n");
        }
        //
        // Set the integrity level to the minimum of the token's current
        // integrity level and the integrity level in the manifest.
        //
        // Rarely if ever used, as no <requestedExecutionLevel>
        // tag ever reduces the integrity level.
        //
        //   level="asInvoker"  -- Leave the integrity level unchanged.
        //   level="highestAvailable" -- Elevate to 3 but ok if denied.
        //   level="requireAdministrator" -- Elevate to 3, fail if denied.
        //
        // All accounts except SYSTEM set this bit.
        //
        if (pPolicy->Policy & TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN) {
            more_printf("Token has TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN.\n");
        }
    }

    //
    // Get owner for newly created objects
    //
    if (!::GetTokenInformation(hToken, TokenOwner, Buffer, sizeof(Buffer), &dwBufferSize)) {
        error(EXIT_FAILURE, 0, "Unable to query the token owner.  Error %d",
            GetLastError());
    }
    pUserSid = ((PTOKEN_OWNER)Buffer)->Owner;
    if (!LookupSidName(pUserSid, szBuf, sizeof(szBuf), sids_format)) {
        strcpy(szBuf, "???");
    }
    more_printf("Owner of new objects: ");
    more_printf("%-33s\n", szBuf);

    ///////////////////////////////////////////////////////////////////////
    //
    // Dump the linked token.  Do this last.
    //
    // Linked token - dump recursively.  The elevated and the non-elevated
    // tokens are cross-linked, so we need to be careful to avoid infinite
    // recursion.
    //
    // Note: A non-elevated process can't simply grab the linked elevated
    // token and use it in CreateProcess to bypass security.  This is
    // because the linked token is returned with only
    // TOKEN_QUERY|TOKEN_QUERY_SOURCE permission, not TOKEN_ASSIGN_PRIMARY
    // or TOKEN_IMPERSONATE permission.
    //
    if (bRecurseOk) {
        //
        // BUG: TokenLinkedToken requires a buffer size of at least
        // sizeof(TOKEN_LINKED_TOKEN), otherwise ERROR_BAD_LENGTH.
        //
        dwBufferSize = sizeof(Buffer);
        if (::GetTokenInformation(hToken, TokenLinkedToken, Buffer, sizeof(TOKEN_LINKED_TOKEN), &dwBufferSize)) {
            pTokenLinkedToken = (PTOKEN_LINKED_TOKEN)Buffer;
            more_fputs("\n----------------------------------------------------------------\n\nLinked Token Information:", stdmore);
            _DumpToken(pTokenLinkedToken->LinkedToken, FALSE/*bRecurseOk*/);
            CloseHandle(pTokenLinkedToken->LinkedToken);
        } else {
            dwError = ::GetLastError();
            //
            // TokenLinkedToken fails with ERROR_NO_SUCH_LOGON_SESSION if
            // the token is not linked.
            //
            // Earlier OSes fail with ERROR_INVALID_PARAMETER.
            //
            if (dwError != ERROR_NO_SUCH_LOGON_SESSION
                    && dwError != ERROR_INVALID_PARAMETER) {
                more_printf("Unable to query the linked token.  Error %d\n",
                    dwError);
            }
        }
    } // bRecurseOk

    return 0; // success
}

extern "C" int // exit status, 0 = success
DumpToken()
{
    HANDLE hToken;
    int iResult;

    //
    // Note: If somehow we are running under an Impersonation Token
    // this will still return correct info.
    //
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_READ|TOKEN_QUERY_SOURCE, &hToken)) {
        error(EXIT_FAILURE, 0, "Unable to query the process token.  Error %d",
            GetLastError());
        /*NOTREACHED*/
    }

    iResult = _DumpToken(hToken, TRUE/*bRecurseOk*/);
    CloseHandle(hToken);
    return iResult;
}


/////////////////////////////////////////////////////////////////////////////
//
// Set the process virtual mode for viewing the files and the registry.
//
// Also declared in Registry.cpp
//
BOOL SetVirtualView(BOOL bEnable, BOOL bVerify)
{
    HANDLE hToken;
    DWORD dwFlag = (DWORD)bEnable;
    DWORD dwBufferSize = 0;

    if (!IsVista) {
        if (bVerify) {
            error(EXIT_FAILURE, 0, "The --virtual option requires Windows Vista or later.");
            /*NOTREACHED*/
        }
        return FALSE;
    }

    //
    // Note: If somehow we are running under an Impersonation Token
    // this will still return correct info.
    //
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_READ|TOKEN_ADJUST_DEFAULT, &hToken)) {
        if (bVerify) {
            error(EXIT_FAILURE, 0, "Unable to open the process token.  Error %d",
                GetLastError());
            /*NOTREACHED*/
        }
        return FALSE;
    }

    if (!SetTokenInformation(hToken, TokenVirtualizationEnabled,
            (PVOID)&dwFlag, sizeof(dwFlag))) {
        CloseHandle(hToken);
        if (bVerify) {
            error(EXIT_FAILURE, 0, "Unable to enter virtual mode (%d).  Either UAC is not running or you are already running in elevated mode.",
                GetLastError());
            /*NOTREACHED*/
        }
        return FALSE;
    }

    if (bVerify) {
        //
        // BUG: TokenVirtualizationEnabled fails silently if
        // TokenVirtualizationAllowed==FALSE
        //
        // WORKAROUND: Re-query TokenVirtualizationEnabled to verify it is set.
        //
        dwFlag = 0;
        if (GetTokenInformation(hToken, TokenVirtualizationEnabled, &dwFlag, sizeof(dwFlag), &dwBufferSize)) {
            if (dwFlag != (DWORD)bEnable) {
                CloseHandle(hToken);
                error(EXIT_FAILURE, 0, "Unable to enter virtual mode.  Either UAC is not running or you are already running in elevated mode.");
                /*NOTREACHED*/
                return FALSE;
            }
        }
    }

    CloseHandle(hToken);
    return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
//
// Enable process virtual mode for viewing the files and the registry
//
extern "C" BOOL
VirtualView()
{
    return SetVirtualView(TRUE/*bEnable*/, TRUE/*bVerify*/);
}
/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

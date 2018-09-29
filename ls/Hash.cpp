//
// Hash.cpp - Hash template class
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//
// Mostly implemented in hash.h
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

#include <crtdbg.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <wchar.h>

#include "more.h"

#define NEED_CSTR_H
#define NEED_HASH_H
#include "windows-support.h"


#ifdef _DEBUG // test

#ifdef __AFX_H__
#define CHASH CHash<CHData<int>, CHData<CString> >
IMPLEMENT_SERIALx(Hash1, CHASH, CObject, 1)
#undef CHASH
#endif

void TestHash()
{
    CHash<CHData<int>, CHData<CString> > MyHash;
    int i;
    MyHash.SetAt(3, _T("test"));
    int iKey; CString strVal;
    if (MyHash.Lookup(iKey, strVal)) { }
    MyHash.RemoveKey(3);
    MyHash[5] = _T("boo");
    i = MyHash.GetCount();
    if (MyHash.IsEmpty()) { }

    POSITION pos = MyHash.GetStartPosition();
    while (pos != NULL) {
        MyHash.GetNextAssoc(pos, iKey, strVal);
        //use(key, value)
    }
}
#endif // _DEBUG


//
// Table of primes suitable as keys, in ascending order.
// The first line is the largest primes less than some powers of two,
// the second line is the largest prime less than 6000,
// the third line is a selection from Knuth, Vol. 3, Sec. 6.1, Table 1,
// and the next two lines were suggested by Steve Kirsch.
//
static const LONG HashPrimes[] = {
    7, 13, 31, 61, 127, 251, 509, 1021, 2017, 4093,
    5987,
    9551, 15683, 19609, 31397,
    65521L, 131071L, 262139L, 524287L, 1048573L, 2097143L, 4194301L,
    //8388593L, 16777213L, 33554393L, 67108859L,
    //134217689L, 268435399L, 536870909L, 1073741789L,
    0
};

//
// We must come up with (i,incr) such that 0 <= 1 < cSize
// and 0 < incr < cSize and both are a function of lHashVal.
// The incr is guaranteed to be relatively prime so all
// locations in the hash table will eventually be tested.
//
EXPORT ULONG CalcHashIncr(LONG lHashVal, register int cSize)
{
    register ULONG uSum, uIncr;

    ASSERT(lHashVal != 0 && lHashVal != -1);
    uSum = (ULONG)lHashVal;
    do {
        uSum = 3*uSum + 1; // somewhat arbitrary
        uIncr = uSum % (ULONG)cSize;
    } while (uIncr == 0);
    return uIncr;
}

EXPORT LONG NewPrimeSize(int cSize)
{
    register int i;
    ASSERT(cSize > 0);
    for (i=0; ; ++i) {
        if (HashPrimes[i] == 0) {
            DLL_ENTRY;

#ifdef UNDEFINED
            ThrowTSException(AEMSG,
                AE_FATAL_ERROR, AE_CATEGORY_FATAL,
_T("Hash table too large: %lu entries"), (ULONG)cSize);
#else
            fputs("Hash table too large.\n", stderr);
            exit(1);
#endif
        }
        if (HashPrimes[i] > (LONG)cSize)
            return HashPrimes[i];
    }
}
/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

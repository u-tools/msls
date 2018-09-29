//
// Hash template class
//
// Copyright (c) 2004-2018, U-Tools Software LLC
// Written by Alan Klietz
// Distributed under GNU General Public License version 2.
//

//
// WARNING: HACKED TO COMPILE WITH VS6 TEMPLATE BRAIN-DAMAGE AND WITH
// VS2005/VS2008.  NOT GURANTEED TO COMPILE WITH FUTURE IMPLEMENTATIONS
// OF THE ANSI C++ STANDARD.
//

////////////////////////////////////////////////////////////////////////
//
// Example:
//
// CHash<CHData<int>, CHData<CString> > MyHash;
//
// MyHash.SetAt(3, _T("test"));
//
// int iKey; CString strVal;
// if (MyHash.Lookup(iKey, strVal)) { found(iKey, strVal); }
//
// MyHash.RemoveKey(3);
// i = MyHash.GetCount();
// if (MyHash.IsEmpty()) { .. }
//
// Unsorted enumeration:
//
// {
//   CGrabLock w(Hash.m_WriteLock);
//   POSITION pos = Hash.GetStartPosition();
//   while (pos != NULL) {
//      Hash.GetNextAssoc(pos, key, val);
//      use(key, val);
//   }
// }
//
////////////////////////////////////////////////////////////////////////

#pragma warning(disable: 4710) // ignore failure to inline under /EHa

// CHData<T>

template<class T>
class CHData {
public:
    typedef T DATATYPE;

    // Must never hash to 0 or -1
    static LONG HashVal(const T& d);
    static BOOL Equal(const T& d1, const T& d2);
#ifdef _DEBUG
    static void Trace(const T& d);
#endif
};

//
// CHData<int> explicit user specialization
//
template<> inline LONG CHData<int>::HashVal(const int& d)
    { return (d == 0 || d == -1) ? -2L : d; }
template<> inline BOOL CHData<int>::Equal(const int& d1, const int& d2)
    { return d1 == d2; }
#ifdef _DEBUG
template<> inline void CHData<int>::Trace(const int& d)
    { TRACE1(_T("%d"), d); }
#endif

//
// CHData<DWORD> explicit user specialization
//
template<> inline LONG CHData<DWORD>::HashVal(const DWORD& d)
    { return (d == 0 || (long)d == -1L) ? (DWORD)-2L : d; }
template<> inline BOOL CHData<DWORD>::Equal(const DWORD& d1, const DWORD& d2)
    { return d1 == d2; }
#ifdef _DEBUG
template<> inline void CHData<DWORD>::Trace(const DWORD& d)
    { TRACE1(_T("%lu"), d); }
#endif

//
// CHData<UINT> explicit user specialization
//
template<> inline LONG CHData<UINT>::HashVal(const UINT& d)
    { return (d == 0 || (long)d == -1) ? (UINT)-2L : d; }
template<> inline BOOL CHData<UINT>::Equal(const UINT& d1, const UINT& d2)
    { return d1 == d2; }
#ifdef _DEBUG
template<> inline void CHData<UINT>::Trace(const UINT& d)
    { TRACE1(_T("%u"), d); }
#endif

//
// CHData<PVOID> explicit user specialization
//
template<> inline LONG CHData<PVOID>::HashVal(const PVOID& d)
    { return (!d || ((LONG)d) == -1) ? -2L : (LONG)d; }
template<> inline BOOL CHData<PVOID>::Equal(const PVOID& d1, const PVOID& d2)
    { return d1 == d2; }
#ifdef _DEBUG
template<> inline void CHData<PVOID>::Trace(const PVOID& d)
    { TRACE1(_T("%#x"), d); }
#endif

//
// CHData<CString> explicit user specialization
//
template<> inline LONG CHData<CString>::HashVal(const CString& d)
{
// The hash algorithm requires unsigned char.
    int iLen = d.GetLength();
#ifndef _UNICODE
# define _STYPE const unsigned char*
#else
# define _STYPE LPCWSTR  // const unsigned short*
    iLen <<= 1;
#endif
    register _STYPE p = (_STYPE)(LPCTSTR)d;
#undef _STYPE
    register LONG x;
    x = *p << 7;
    for (register int i=iLen; --i >= 0;) {
        x = (1000003*x) ^ *p++;
    }
    x ^= iLen;
    if (x == 0 || x == -1)
        x = -2;
    return x;
}

template<> inline BOOL CHData<CString>::Equal(const CString& d1, const CString& d2)
    { return d1 == d2; }
#ifdef _DEBUG
template<> inline void CHData<CString>::Trace(const CString& d)
    { TRACE1(_T("%s"), (LPCTSTR)d); }
#endif

////////////////////////////////////////////////////////////////////////
// CHashEntry< CHData<KeyType>, CHData<ValueType> >
////////////////////////////////////////////////////////////////////////

template<class HDATAKEY, class HDATAVALUE>
class CHashEntry {
public:

    //
    // Microsoft Visual C++ compiler BUG:
    //
    // The compiler generates free(p-1) if the class has non-empty
    // destructors.  Otherwise it generates free(p).
    // The address at (p-1) holds the count of the number of elements
    // in the array.
    //
    // BUG: The compiler wrongly generates free(p-1) instead of free(p)
    // for CHashEntry<CHData<int>, CHData<int> >.
    // Therefore we use this dummy destructor to force p=malloc(len+1)+1
    // instead of p=malloc(len), so that free(p-1) does not GPF.
    //
    ~CHashEntry() { m_lHashVal = 0; };

public:
    LONG m_lHashVal; // 0 means empty, -1 means deleted

    typedef typename HDATAKEY::DATATYPE KEYTYPE;
    typedef typename HDATAVALUE::DATATYPE DATATYPE;

    KEYTYPE m_Key;
    DATATYPE m_Value;
};

////////////////////////////////////////////////////////////////////////////

EXPORT ULONG CalcHashIncr(LONG lHashVal, int cSize);
EXPORT LONG NewPrimeSize(int cSize);

////////////////////////////////////////////////////////////////////////
// CHash< CHData<KeyType>, CHData<ValueType> >
////////////////////////////////////////////////////////////////////////

template<class HDATAKEY, class HDATAVALUE>
class CHash
#ifdef __AFX_H__
: public CObject
#endif
{
#ifdef __AFX_H__
#define CHASH CHash<HDATAKEY, HDATAVALUE>
    DECLARE_SERIALx(CHASH)
#undef CHASH
#endif __AFX_H__
public:

    typedef typename HDATAKEY::DATATYPE KEYTYPE;
    typedef typename HDATAVALUE::DATATYPE DATATYPE;

    CHash(int cSize=6) {
        m_cSize = NewPrimeSize(cSize);
        //TRACE(_T("Creating hash table, size %d.\n"), m_cSize);
        m_pTable = new CHashEntry<HDATAKEY, HDATAVALUE>[m_cSize];
        for (register int i=0; i < m_cSize; ++i) {
            m_pTable[i].m_lHashVal = 0;
        }
        m_cFill = 0;
        m_cUsed = 0;
    };

    ~CHash() {
        delete [] m_pTable;
        m_pTable = NULL;
    };

    int GetCount() const { return m_cUsed; };

    BOOL IsEmpty() const { return m_cUsed == 0; };

    UINT GetHashTableSize() const { return m_cSize; };

    BOOL Lookup(const KEYTYPE& rKey, DATATYPE& rValue) {
        CHashEntry<HDATAKEY, HDATAVALUE>* pHashEntry;
#ifdef LOCKING
        CGrabLock w(m_WriteLock);
#endif
        pHashEntry = LookMapping(rKey, HDATAKEY::HashVal(rKey));
        if (pHashEntry->m_lHashVal != 0 && pHashEntry->m_lHashVal != -1) {
            rValue = pHashEntry->m_Value;
            return TRUE;
        } else {
            return FALSE;
        }
    };

    //
    // Dangerous because the lock is lost prematurely: Hash["key"]=val.
    //
    DATATYPE& operator[](const KEYTYPE& rKey) {
#ifdef LOCKING
        CGrabLock w(m_WriteLock);
#endif
        //
        // A readlock is useless because the assignment happens
        // after the fact.
        //
        LONG lHashVal = HDATAKEY::HashVal(rKey);
        CHashEntry<HDATAKEY, HDATAVALUE>* pHashEntry;
        pHashEntry = LookMapping(rKey, lHashVal);
        if (pHashEntry->m_lHashVal != 0 && pHashEntry->m_lHashVal != -1) {
            // found
            return pHashEntry->m_Value;
        }
        if (((m_cFill<<1)+m_cFill) >= (m_cSize<<1)) { // m_cFill*3 >= m_cSize*2
            MappingResize();
            pHashEntry = LookMapping(rKey, lHashVal);
            ASSERT(pHashEntry->m_lHashVal == 0);
        }
        if (pHashEntry->m_lHashVal == 0) {
            m_cFill++;
        }
        pHashEntry->m_lHashVal = lHashVal;
        pHashEntry->m_Key = rKey;
        m_cUsed++;
        return pHashEntry->m_Value;
    };

    void SetAt(const KEYTYPE& rKey, const DATATYPE& rValue) {
#ifdef LOCKING
        CGrabLock w(m_WriteLock);
        CGrabLock r(m_ReadLock);
#endif
        if (((m_cFill<<1)+m_cFill) >= (m_cSize<<1)) { // m_cFill*3 >= m_cSize*2
            MappingResize();
        }
        InsertMapping(rKey, HDATAKEY::HashVal(rKey), rValue);
    };

    BOOL RemoveKey(const KEYTYPE& rKey) {
        CHashEntry<HDATAKEY, HDATAVALUE>* pHashEntry;
#ifdef LOCKING
        CGrabLock w(m_WriteLock);
        CGrabLock r(m_ReadLock);
#endif
        pHashEntry = LookMapping(rKey, HDATAKEY::HashVal(rKey));
        if (pHashEntry->m_lHashVal == 0 || pHashEntry->m_lHashVal == -1) {
            return FALSE;
        }
        pHashEntry->m_lHashVal = -1; // mark deleted
        m_cUsed--;
        return TRUE;
    };

    void RemoveAll() {
#ifdef LOCKING
        CGrabLock w(m_WriteLock);
        CGrabLock r(m_ReadLock);
#endif
        delete [] m_pTable;
        m_cFill = 0;
        m_cUsed = 0;
        m_cSize = NewPrimeSize(6);
        m_pTable = new CHashEntry<HDATAKEY, HDATAVALUE>[m_cSize];
        for (register int i=0; i < m_cSize; ++i) {
            m_pTable[i].m_lHashVal = 0;
        }
        return;
    };

    POSITION GetStartPosition() const {
        return (m_cUsed == 0 ? NULL : BEFORE_START_POSITION);
    };

    void GetNextAssoc(POSITION& rNextPosition,
            KEYTYPE& rKey, DATATYPE& rValue) const {
        register int i = 0;
        if (rNextPosition == BEFORE_START_POSITION) {
            i = 0;
        } else if (rNextPosition == NULL ) {
#ifdef UNDEFINED
            ThrowTSException(AEMSG, AE_FATAL_ERROR, AE_CATEGORY_FATAL,
_T("Tried to go beyond the end of the hash table."));
#else
            more_fputs("Tried to go beyond the end of the hash table.\n", stdmore_err);
            exit(1);
#endif
        } else {
            i = (int)rNextPosition;
        }
        ASSERT(i >= 0);
        while (i < m_cSize && (m_pTable[i].m_lHashVal == 0 || m_pTable[i].m_lHashVal == -1)) {
            ++i;
        }
        ASSERT(i < m_cSize);
        rKey = m_pTable[i].m_Key;
        rValue = m_pTable[i].m_Value;
        ++i;
        while (i < m_cSize && (m_pTable[i].m_lHashVal == 0 || m_pTable[i].m_lHashVal == -1)) {
            ++i;
        }
        if (i >= m_cSize) {
            rNextPosition = NULL;
        } else {
            rNextPosition = (POSITION)i;
        }
        return;
    };

#ifdef __AFX_H__
    void Serialize(CArchive& ar) {
      DWORD dwCount;
      KEYTYPE key;
      DATATYPE val;
      CObject::Serialize(ar);
      if (ar.IsStoring()) {
#ifdef LOCKING
        CGrabLock w(m_WriteLock);
#endif
        ar.WriteCount((DWORD)m_cUsed);
#ifdef _DEBUG
        dwCount = 0;
#endif
        POSITION pos = GetStartPosition();
        while (pos != NULL) {
            GetNextAssoc(pos, key, val);
            ar << key;
            ar << val;
#ifdef _DEBUG
            ++dwCount;
#endif
        }
        ASSERT(dwCount == (DWORD)m_cUsed);
      } else {
#ifdef LOCKING
        CGrabLock w(m_WriteLock);
        CGrabLock r(m_ReadLock);
#endif
        dwCount = ar.ReadCount();
        while (dwCount--) {
#pragma warning(push)
#pragma warning(disable: 4701) // ignore warning about use before set
            ar >> key;
            ar >> val;
#pragma warning(pop)
            if (((m_cFill<<1)+m_cFill) >= (m_cSize<<1)) { // m_cFill*3 >= m_cSize*2
                MappingResize();
            }
            InsertMapping(key, HDATAKEY::HashVal(key), val);
        }
      }
    }
#endif __AFX_H__

#if defined(__AFX_H__) && defined(_DEBUG)
    //
    // To display, call Hash.Dump(afxDump) from the debugger.
    //
    void Dump(CDumpContext& dc) {
        CObject::Dump(dc);

        dc << "with " << m_cUsed << " elements";
        // if (dc.GetDepth() > 0)  // dc.SetDepth(1);
        {
            KEYTYPE key;
            DATATYPE val;
            POSITION pos = GetStartPosition();
            while (pos != NULL) {
                GetNextAssoc(pos, key, val);
                dc << "\n    map[";
                //
                // We cannot send hash elements to the dc because
                // hash elements cannot be not CObjects.
                // Hash elements cannot be CObjects because CObjects
                // cannot be copied nor assigned to.
                //
                HDATAKEY::Trace(key);
                dc << "] = ";
                HDATAVALUE::Trace(val);
            }
        }
        dc << "\n";
    };
#endif

    //
    // Public to allow explicit locking for GetNextAssoc() loops.
    //
#ifdef LOCKING
    CLock m_ReadLock;
    CLock m_WriteLock;
#endif

private:
    int m_cFill; // number of non-empty keys
    int m_cUsed; // number of non-empty, non-deleted keys
    int m_cSize;
    CHashEntry<HDATAKEY, HDATAVALUE>* m_pTable;

    CHashEntry<HDATAKEY, HDATAVALUE>* LookMapping(const KEYTYPE& rKey, long lHashVal) {
        //
        // Returns a pointer to a free slot if no match
        //
        register ULONG uPos, uIncr;
        register CHashEntry<HDATAKEY, HDATAVALUE> *pHashEntry, *pFreeSlot=NULL;
        uPos = (ULONG)lHashVal % (ULONG)m_cSize;
        uIncr = CalcHashIncr(lHashVal, m_cSize);
        for (;;) {
            ASSERT(((int)uPos) >= 0 && ((int)uPos) < m_cSize);
            pHashEntry = &m_pTable[uPos];
            if (pHashEntry->m_lHashVal == 0) { // if end of chain
                return pFreeSlot ? pFreeSlot : pHashEntry;
            }
            if (pHashEntry->m_lHashVal == -1) { // if deleted
                if (pFreeSlot == NULL) {
                    pFreeSlot = pHashEntry;
                }
            } else if (pHashEntry->m_lHashVal == lHashVal &&
                    HDATAKEY::Equal(pHashEntry->m_Key, rKey)) {
                return pHashEntry;
            }
            uPos = (uPos + uIncr) % (ULONG)m_cSize;
        }
    };

    void InsertMapping(const KEYTYPE& rKey, long lHashVal,
            const DATATYPE& rValue) {
        CHashEntry<HDATAKEY, HDATAVALUE>* pHashEntry;

        pHashEntry = LookMapping(rKey, lHashVal);
        if (pHashEntry->m_lHashVal != 0 && pHashEntry->m_lHashVal != -1) {
            // found
            pHashEntry->m_Value = rValue;
        } else {
            if (pHashEntry->m_lHashVal == 0) {
                m_cFill++;
            }
            pHashEntry->m_lHashVal = lHashVal;
            pHashEntry->m_Key = rKey;
            pHashEntry->m_Value = rValue;
            m_cUsed++;
        }
    };

    void MappingResize() {
        register int cOldSize = m_cSize;
        register int cNewSize = NewPrimeSize(m_cSize<<1); // cSize*2
        register CHashEntry<HDATAKEY, HDATAVALUE> *pOldTable, *pNewTable;
        register int i;
        TRACE(_T("Growing hash table to %d entries.\n"), cNewSize);
        pOldTable = m_pTable;
        pNewTable = new CHashEntry<HDATAKEY, HDATAVALUE>[cNewSize];
        m_pTable = pNewTable;
        m_cSize = cNewSize;
        m_cFill = 0;
        m_cUsed = 0;
        for (i=0; i < m_cSize; ++i) {
            m_pTable[i].m_lHashVal = 0;
        }
        CHashEntry<HDATAKEY, HDATAVALUE>* pHashEntry = &pOldTable[0];
        for (i=0; i < cOldSize; ++i, ++pHashEntry) {
            if (pHashEntry->m_lHashVal != 0 && pHashEntry->m_lHashVal != -1) {
                InsertMapping(pHashEntry->m_Key, pHashEntry->m_lHashVal,
                    pHashEntry->m_Value);
            }
        }
        delete [] pOldTable;
    };
};

////////////////////////////////////////////////////////////////////////////

/*
vim:tabstop=4:shiftwidth=4:expandtab
*/

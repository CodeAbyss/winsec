
#ifndef CACHE_H
#define CACHE_H

#include <windows.h>

#include "Lsa.h"

#include "crypto/md4.h"
#include "crypto/des.h"

#include "crypto/md5.h"
#include "crypto/rc4.h"

#include "crypto/sha.h"
#include "crypto/aes.h"

#define MD5_BLOCK_LENGTH  64
#define MD5_DIGEST_LENGTH 16

#define SHA1_BLOCK_LENGTH  64
#define SHA1_DIGEST_LENGTH 20

#define DEFAULT_ITERATION_COUNT 10

typedef struct _CACHE_PASSWORDS {
    USER_INTERNAL1_INFORMATION SecretPasswords;
} CACHE_PASSWORDS, *PCACHE_PASSWORDS;

// If Ptr is not already aligned, then round it up until it is.

/*#define ROUND_UP_POINTER(Ptr,Pow2) \
        ( (PUCHAR) ( (((DWORD)(Ptr))+(Pow2)-1) & (~((Pow2)-1)) ) )

  */
//new offset = align + ((offset - 1) & ~(align - 1))
//padding = (align + ((offset - 1) & ~(align - 1))) - offset

struct CACHE_ENTRY {
    USHORT  UserNameLength;
    USHORT  DomainNameLength;
    USHORT  EffectiveNameLength;
    USHORT  FullNameLength;

    USHORT  LogonScriptLength;
    USHORT  ProfilePathLength;
    USHORT  HomeDirectoryLength;
    USHORT  HomeDirectoryDriveLength;

    ULONG   UserId;
    ULONG   PrimaryGroupId;
    ULONG   GroupCount;
    USHORT  LogonDomainNameLength;

    //
    // The following fields are present in NT1.0A release and later
    // systems.
    //

    USHORT          LogonDomainIdLength; // was Unused1
    LARGE_INTEGER   Time;
    ULONG           Revision;
    ULONG           SidCount;   // was Unused2
    BOOLEAN         Valid;

    //
    // The following fields are present for NT 3.51 since build 622
    //

    CHAR            Unused[3];
    ULONG           SidLength;

    //
    // The following fields have been present (but zero) since NT 3.51.
    //  We started filling it in in NT 5.0
    //
    ULONG           LogonPackage; // The RPC ID of the package doing the logon.
    USHORT          DnsDomainNameLength;
    USHORT          UpnLength;

    //
    // The following fields were added for NT5.0 build 2053.
    //

    //
    // define a 128bit random key for this cache entry.  This is used
    // in conjunction with a per-machine LSA secret to derive an encryption
    // key used to encrypt CachePasswords & Opaque data.
    //

    CHAR            RandomKey[ 16 ];
    CHAR            MAC[ 16 ];      // encrypted data integrity check.

    //
    // store the CACHE_PASSWORDS with the cache entry, encrypted using
    // the RandomKey & per-machine LSA secret.
    // this improves performance and eliminates problems with storing data
    // in 2 locations.
    //
    // note: data from this point forward is encrypted and protected from
    // tampering via HMAC.  This includes the data marshalled beyond the
    // structure.
    //

    CACHE_PASSWORDS CachePasswords;

    //
    // Length of opaque supplemental cache data.
    //

    ULONG           SupplementalCacheDataLength;

    //
    // offset from LOGON_CACHE_ENTRY to SupplementalCacheData.
    //


    ULONG           SupplementalCacheDataOffset;

    //
    // spare slots for future data, to potentially avoid revising the structure
    //

    ULONG           Spare1;
    ULONG           Spare2;
    ULONG           Spare3;
    ULONG           Spare4;
    ULONG           Spare5;
    ULONG           Spare6;


};

/*
struct CACHE_ENTRY {
  WORD  UserNameLength;                  // 0
  WORD  DomainNameLength;                // 2
  WORD  EffectiveNameLength;             // 4
  WORD  FullNameLength;                  // 6

  WORD  LogonScriptLength;               // 8
  WORD  ProfilePathLength;               // 10
  WORD  HomeDirectoryLength;             // 12
  WORD  HomeDirectoryDriveLength;        // 14

  DWORD UserId;                          // 18
  DWORD PrimaryGroupId;                  // 22
  DWORD GroupCount;                      // 26
  WORD  LogonDomainNameLength;           // 28

  WORD          LogonDomainIdLength;     // 30
  LARGE_INTEGER Time;                    // 38  64-bit UTC of last time user logged in
  DWORD         Revision;                // 42
  DWORD         SidCount;                // 46
  BOOLEAN       Valid;                   // 47

  BYTE          Unused[3];               // 50
  DWORD         SidLength;               // 54

  DWORD         LogonPackage;            // 58
  WORD          DnsDomainNameLength;     // 60
  WORD          UpnLength;               // 62

  BYTE          RandomKey[16];           // 64  random 16 bytes used to derive cipher key
  BYTE          MAC[16];                 // 80  hmac of plaintext before encryption
                                         //     use to verify integrity of decrypted data
  // everything from here is encrypted
  CACHE_PASSWORDS CachePasswords;        // 96  contains LM/NTLM cached credentials

  //
  // Length of opaque supplemental cache data.
  //
  ULONG   SupplementalCacheDataLength;   // 131

  //
  // offset from LOGON_CACHE_ENTRY to SupplementalCacheData.
  //
  ULONG   SupplementalCacheDataOffset;   // 135

  //
  // spare slots for future data, to potentially avoid revising the structure
  //
  ULONG   Spare1;
  ULONG   Spare2;
  ULONG   Spare3;
  ULONG   Spare4;
  ULONG   Spare5;
  ULONG   Spare6;
};
     */
struct USER_ENTRY {
  wchar_t domain[128];
  wchar_t id[128];
  wchar_t fullName[128];
  SYSTEMTIME time;
  CACHE_PASSWORDS hashes;
};

struct CACHE_LIST {
  USER_ENTRY *entry;
  CACHE_LIST *next;
};

// NL$Control structure
struct CONTROL_INFO {
  DWORD dwRevision;
  DWORD dwEntries;
};

class Cache : virtual public Lsa {
  private:
    bool decryptEntry_v1(CACHE_ENTRY *pEntry,DWORD dwSize);
    bool decryptEntry_v2(CACHE_ENTRY *pEntry,DWORD dwSize);

    void AddEntryToList(CACHE_ENTRY *cached_entry);
    void ClearEntries();

    CACHE_LIST *cache_list;
    CACHE_LIST *current;

  protected:
    unsigned char cachekey[64];
  public:
    Cache();
    Cache(wchar_t [], wchar_t []);
    Cache(wchar_t [], wchar_t [], wchar_t []);
    ~Cache();

    DWORD GetIterationCount();
    DWORD GetCachedCount();
    
    CACHE_LIST* GetCachedEntries();
    bool GetCachedKey();

    void GetNtlmHash(const wchar_t [],unsigned char []);
    void GetCachedHash_v1(const wchar_t [],const wchar_t [],unsigned char []);
    void GetCachedHash_v2(const wchar_t [],const wchar_t [],unsigned int,unsigned char []);
};

#endif

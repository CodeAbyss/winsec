
#ifndef LSA_H
#define LSA_H

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS

#include <windows.h>
#include <Ntsecapi.h>
//#include <ddk/ntifs.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) 
#define STATUS_UNKNOWN_REVISION ((NTSTATUS)0xC0000058L)
#define STATUS_INVALID_PARAMETER_2 ((NTSTATUS)0xC00000F0L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#include "Syskey.h"

#include "crypto/des.h"
#include "crypto/aes.h"
#include "crypto/sha.h"

#include "crypto/rc4.h"
#include "crypto/md5.h"

#define CLEAR_BLOCK_LENGTH 8

typedef struct _CLEAR_BLOCK {
    BYTE   data[CLEAR_BLOCK_LENGTH];
} CLEAR_BLOCK,  *PCLEAR_BLOCK;

#define CYPHER_BLOCK_LENGTH 8

typedef struct _CYPHER_BLOCK {
    BYTE   data[CYPHER_BLOCK_LENGTH];
} CYPHER_BLOCK, *PCYPHER_BLOCK;

#define BLOCK_KEY_LENGTH            7

typedef struct _BLOCK_KEY {
    BYTE   data[BLOCK_KEY_LENGTH];
} BLOCK_KEY, *PBLOCK_KEY;

//
// Version number of encrypted data
// Update this number if the method used encrypt the data changes
//
#define DATA_ENCRYPTION_VERSION     1

//
// Private data types
//
typedef struct _CRYPTP_BUFFER {
    DWORD   Length;         // Number of valid bytes in buffer
    DWORD   MaximumLength;  // Number of bytes pointed to by buffer
    PBYTE   Buffer;
    PBYTE   Pointer;        // Points into buffer
} CRYPTP_BUFFER, *PCRYPTP_BUFFER;

struct CRYPT_BUFFER {
    DWORD   Length;         // Number of valid bytes in buffer
    DWORD   MaximumLength;  // Number of bytes pointed to by Buffer
    PBYTE   Buffer;
};

typedef CRYPT_BUFFER *PCRYPT_BUFFER;
typedef CRYPT_BUFFER DATA_KEY;
typedef CRYPT_BUFFER *PDATA_KEY;
typedef CRYPT_BUFFER CYPHER_DATA;
typedef CRYPT_BUFFER *PCYPHER_DATA;
typedef CRYPT_BUFFER CLEAR_DATA;
typedef CRYPT_BUFFER *PCLEAR_DATA;

struct LSA_DATA {
    DWORD   dwSize;
    PBYTE   Buffer;
};

struct LSA_ENTRY {
    wchar_t    szKeyName[MAX_KEY_LENGTH];
    LSA_DATA   LsaData;
};

struct LSA_LIST {
    LSA_ENTRY *entry;
    LSA_LIST *next;
};

class Lsa : virtual public Syskey {
  private:
    // decrypt the LSA Database key
    void DecryptLsaKey_v1(LSA_DATA*);
    void DecryptLsaKey_v2(LSA_DATA*);

    // decrypt LSA data
    bool DecryptLsaData_v1(LSA_DATA*,LSA_DATA*);
    bool DecryptLsaData_v2(LSA_DATA*,LSA_DATA*);

    void ClearEntries();
    void AddEntryToList(LSA_ENTRY*);

    LSA_LIST *lsa_list;
    LSA_LIST *current;
  protected:
    unsigned char lsakey[32];
    DWORD nLsaKeyLen;
    DWORD dwVersion;
  public:
    Lsa();
    ~Lsa();

    LSA_LIST* GetLsaEntries();
    bool GetLsaEntry(LSA_ENTRY* entry);
    bool GetLsaKey();
};

#endif

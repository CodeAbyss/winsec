

// structure found on http://www.passcape.com/index.php?page=1056

#define CRYPTPROTECT_UI_FORBIDDEN 0x1
   // Used when user interface is not available. For example, when using remote access.
#define CRYPTPROTECT_LOCAL_MACHINE 0x4
   // Data is protected using local computer account. 
   // Any user of the system may be able to decrypt it.
#define CRYPTPROTECT_CRED_SYNC 0x8
   // Forces synchronizing user's credentals. 
   // Normally runs automatically upon user password change.
#define CRYPTPROTECT_AUDIT 0x10
   // Enables audit during encryption/dectyption
#define CRYPTPROTECT_VERIFY_PROTECTION 0x40
   // The flag checks security level of DPAPI blob. 
   // If the default security level is higher than current security level of the blob, 
   // the function returns error CRYPT_I_NEW_PROTECTION_REQUIRED as advice to reset securiry for the source data.
#define CRYPTPROTECT_CRED_REGENERATE 0x80
   // Regenerate local computer passwords.
#define CRYPTPROTECT_SYSTEM 0x20000000
   // Indicates that only system processes can encrypt/decrypt data.
   
typedef struct _tagDpapiEntry {
  DWORD dwVersion;
  GUID guidDefaultProvider;
  GUID guidMasterKey;
  DWORD dwFlags;
  WCHAR szDataDescription;
  ALG_ID algCrypt;
  DWORD dwCryptAlgLen;
  BYTE pHMACKey;
} DPAPI_ENTRY, *PDPAPI_ENTRY;

// DPAPI header
#pragma pack(push, 1)
typedef struct _tagDpapi_Header {
  DWORD dwProviders;
  UUID provider;
  DWORD dwVersion;
  UUID masterKey;
  DWORD dwFlags;
  DWORD dwDescription;
  WCHAR szDescription[1];
} DPAPI_HEADER, *PDPAPI_HEADER;
#pragma pack(pop)

// Cipher parameters
#pragma pack(push, 1)
typedef struct _tagDpapi_Cipher {
  ALG_ID id;
  DWORD dwBlock;
  DWORD dwSalt;
  BYTE bSalt[1];
  DWORD dwExport;
} DPAPI_CIPHER, *PDPAPI_CIPHER;
#pragma pack(pop)

// PBKDF information
#pragma pack(push, 1)
typedef struct _tagDpapi_Key {
  ALG_ID id;
  DWORD dwHashLen;
  DWORD dwSize;
  BYTE bValue[1];
} DPAPI_KEY, *PDPAPI_KEY;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _tagDpapi_Data {
  DWORD dwSize;
  BYTE bValue[1];
} DPAPI_CIPHERTEXT, *PDPAPI_CIPHERTEXT;
#pragma pack(pop)

typedef struct _tagDpapi_Hmac {
  DWORD dwSize;
  BYTE bValue[1];
} DPAPI_HMAC, *PDPAPI_HMAC;

typedef struct _tagPreferredMasterKey {
	GUID guidMasterKey;
	FILETIME ftCreated;
} PREFERREDMASTERKEY, *PPREFERREDMASTERKEY;

typedef struct _tagMasterKey1Base {
	DWORD dwVersion;
	BYTE pSalt[16];
	BYTE pKey[];
} MASTERKEY1BASE, *PMASTERKEY1BASE;

typedef struct _tagMasterKey2Base {
	DWORD dwVersion;
	BYTE pSalt[16];
	DWORD dwPBKDF2IterationCount;
	ALG_ID HMACAlgId;
	ALG_ID CryptAlgId;
	BYTE pKey[];
} MASTERKEY2BASE, *PMASTERKEY2BASE;

typedef struct _tagMasterKey3Base {
	DWORD dwVersion;
	GUID guidCredhist;
} MASTERKEY3BASE, *PMASTERKEY3BASE;

#pragma pack(push, 1)
typedef struct _tagCREDENTIAL_HEADER {  
  DWORD dwVersion;
  GUID guidLink;
  DWORD dwNextLinkSize;	
} CREDENTIAL_HEADER, *PCREDENTIAL_HEADER;
#pragma pack(pop)

#pragma pack(push, 1)  
typedef struct _tagMasterKey {
	DWORD dwVersion;
	DWORD dwReserved[2];
	WCHAR szGuid[36];
	DWORD dwUnused[2];
	DWORD dwPolicy;
	DWORD dwUserKeySize[2];
	DWORD dwLocalEncKeySize[2];
	DWORD dwLocalKeySize[2];
	DWORD dwDomainKeySize[2];
} MASTERKEY, *PMASTERKEY;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _tagCREDENTIAL_ENTRY {	
  DWORD dwCredLinkType;
  ALG_ID algHash;
  DWORD dwPbkdf2IterationCount;
  DWORD dwSidSize;
  ALG_ID algCrypt;
  DWORD dwShaHashSize;
  DWORD dwNtHashSize;
  BYTE pSalt[16];
} CREDENTIAL_ENTRY, *PCREDENTIAL_ENTRY;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _tagUserKey {
  DWORD dwVersion;
  BYTE pSalt[16];
  DWORD dwPbkdf2IterationCount;
  ALG_ID algHash;
  ALG_ID algCrypt;
} USER_KEY, *PUSER_KEY;
#pragma pack(pop)

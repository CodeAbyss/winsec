
/**
 *
 *  class for obtaining cached credentials
 */

#include "Cache.h"

Cache::Cache()
{
  cache_list = NULL;
}

Cache::~Cache()
{
  ClearEntries();
}

/**
 *
 *   used for integrity check of cached credentials on win2k/xp/2k3 systems
 *
 */
void hmac_md5(unsigned char text[], unsigned int text_len,
     unsigned char key[], int key_len, unsigned char digest[])
{
  MD5_CTX ctx;
  unsigned char k_ipad[MD5_BLOCK_LENGTH+1],k_opad[MD5_BLOCK_LENGTH+1];
  unsigned char tk[MD5_DIGEST_LENGTH];

  if (key_len > MD5_BLOCK_LENGTH) {
      MD5_Init(&ctx);
      MD5_Update(&ctx,key,key_len);
      MD5_Final(tk,&ctx);

      key = tk;
      key_len = MD5_DIGEST_LENGTH;
  }

  memset(k_ipad,0x36,MD5_BLOCK_LENGTH);
  memset(k_opad,0x5c,MD5_BLOCK_LENGTH);

  for (int i(0);i < key_len;i++) {
       k_ipad[i] ^= key[i];
       k_opad[i] ^= key[i];
  }

  MD5_Init(&ctx);
  MD5_Update(&ctx,k_ipad,MD5_BLOCK_LENGTH);
  MD5_Update(&ctx,text,text_len);
  MD5_Final(tk,&ctx);

  MD5_Init(&ctx);
  MD5_Update(&ctx,k_opad,MD5_BLOCK_LENGTH);
  MD5_Update(&ctx,tk,MD5_DIGEST_LENGTH);
  MD5_Final(digest,&ctx);
}

/**
 *
 *  used for integrity check of cached credentials on vista/wk8/7 systems
 *  and also hashing the ntlm v1 cached credential providing extra security
 *  against password recovery attacks
 *
 */
void hmac_sha1(unsigned char text[], unsigned int text_len,
     unsigned char key[], int key_len, unsigned char digest[])
{
  SHA_CTX ctx;
  unsigned char k_ipad[SHA1_BLOCK_LENGTH+1],k_opad[SHA1_BLOCK_LENGTH+1];
  unsigned char tk[SHA1_DIGEST_LENGTH];

  if (key_len > SHA1_BLOCK_LENGTH) {
      SHA1_Init(&ctx);
      SHA1_Update(&ctx,key,key_len);
      SHA1_Final(tk,&ctx);

      key = tk;
      key_len = SHA1_DIGEST_LENGTH;
  }

  memset(k_ipad,0x36,SHA1_BLOCK_LENGTH);
  memset(k_opad,0x5c,SHA1_BLOCK_LENGTH);

  for (int i(0);i < key_len;i++) {
       k_ipad[i] ^= key[i];
       k_opad[i] ^= key[i];
  }

  SHA1_Init(&ctx);
  SHA1_Update(&ctx,k_ipad,SHA1_BLOCK_LENGTH);
  SHA1_Update(&ctx,text,text_len);
  SHA1_Final(tk,&ctx);

  SHA1_Init(&ctx);
  SHA1_Update(&ctx,k_opad,SHA1_BLOCK_LENGTH);
  SHA1_Update(&ctx,tk,SHA1_DIGEST_LENGTH);
  SHA1_Final(digest,&ctx);
}

/**
 *
 *  AES-CTS-128 is used in CTS mode to decrypt cached credential entries
 *  on vista/2k8/7 systems but not available in OpenSSL
 *
 */
void AES_cts_decrypt(PBYTE pCipherText, PBYTE pPlainText,
     DWORD dwSize, const AES_KEY *key,BYTE ivec[])
{
  BYTE tmp1[AES_BLOCK_SIZE];
  BYTE tmp2[AES_BLOCK_SIZE];
  BYTE tmp3[AES_BLOCK_SIZE];

  while (dwSize > AES_BLOCK_SIZE * 2)
  {
    memcpy(tmp1, pCipherText, AES_BLOCK_SIZE);
    AES_decrypt(pCipherText, pPlainText, key);

    for (DWORD i = 0; i < AES_BLOCK_SIZE; i++)
         pPlainText[i] ^= ivec[i];

    memcpy(ivec, tmp1, AES_BLOCK_SIZE);

    dwSize       -= AES_BLOCK_SIZE;
    pCipherText  += AES_BLOCK_SIZE;
    pPlainText   += AES_BLOCK_SIZE;
  }

  dwSize -= AES_BLOCK_SIZE;

  memcpy(tmp1, pCipherText, AES_BLOCK_SIZE);
  AES_decrypt(pCipherText, tmp2, key);

  memcpy(tmp3, pCipherText + AES_BLOCK_SIZE, dwSize);
  memcpy(tmp3 + dwSize, tmp2 + dwSize, AES_BLOCK_SIZE - dwSize);

  for (DWORD i = 0; i < dwSize; i++)
       pPlainText[i + AES_BLOCK_SIZE] = tmp2[i] ^ tmp3[i];

  AES_decrypt(tmp3, pPlainText, key);

  for (DWORD i = 0; i < AES_BLOCK_SIZE; i++)
       pPlainText[i] ^= ivec[i];

  memcpy(ivec, tmp1, AES_BLOCK_SIZE);
}

/**
 *
 *  win2k/xp/win2k3 code
 *
 */
bool Cache::decryptEntry_v1(CACHE_ENTRY *pEntry, DWORD dwSize)
{
  RC4_KEY key;
  BYTE hmac[MD5_DIGEST_LENGTH];
  PBYTE pCipherText = reinterpret_cast<PBYTE>(&pEntry->CachePasswords);

  // calculate cipher key from random 16 bytes and random 64-bytes NL$KM secret
  hmac_md5(reinterpret_cast<unsigned char*>(pEntry->RandomKey),16,cachekey,64,hmac);
  RC4_set_key(&key,MD5_DIGEST_LENGTH,hmac);

  // decrypt ciphertext
  RC4(&key,dwSize - 96,pCipherText,pCipherText);

  // calculate checksum of plaintext
  hmac_md5(pCipherText,dwSize - 96,hmac,MD5_DIGEST_LENGTH,hmac);

  // ensure successful decryption
  return (memcmp(hmac,pEntry->MAC,16) == 0);
}

/**
 *
 *  vista/win2k8/7 code
 *
 */
bool Cache::decryptEntry_v2(CACHE_ENTRY *pEntry, DWORD dwSize)
{
  AES_KEY key;
  BYTE hmac[SHA_DIGEST_LENGTH];
  PBYTE pCipherText = reinterpret_cast<PBYTE>(&pEntry->CachePasswords);

  // calculate 128-bit decryption key
  AES_set_decrypt_key(cachekey,128,&key);

  // decrypt ciphertext  C        P
  AES_cts_decrypt(pCipherText,pCipherText,dwSize - 96,&key,reinterpret_cast<unsigned char*>(pEntry->RandomKey));

  // calculate checksum of plaintext
  hmac_sha1(pCipherText,dwSize - 96,cachekey,16,hmac);

  // ensure successful decryption
  return (memcmp(hmac,pEntry->MAC,16) == 0);
}

/**
    the structure is padded
    
    if a string is 6 bytes or 3 unicode characters, 2 null bytes are added to end
 */
PUCHAR round_up(PUCHAR &ptr, size_t len)
{
  if (len == 0) {
    return ptr;
  }

  if (((len / 2) % 2) == 1) {
    len += 2;
  }

  return ptr + len;
}

/**
 *
 *   using simple linked list procedure
 *
 */
void Cache::AddEntryToList(CACHE_ENTRY *cached_entry)
{   
  ULONG uLength;

  // add only if valid cached entry
  if (cached_entry->Valid != TRUE)
      return;                                // return ERROR_INVALID_DATA

  // allocate new user entry
  USER_ENTRY *user_entry = new USER_ENTRY;

  if (user_entry == NULL)                    // return ERROR_NOT_ENOUGH_MEMORY
      return;

  // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  // zero initialize..not sure if new() does this already
  ZeroMemory(user_entry,sizeof(USER_ENTRY));

  // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  // copy the hashes
  memcpy(&user_entry->hashes,&cached_entry->CachePasswords,sizeof(CACHE_PASSWORDS));

  // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  // convert LARGE_INTEGER to SYSTEMTIME
  FILETIME ft,lt;

  memcpy(&ft,&cached_entry->Time,sizeof(LARGE_INTEGER));
  FileTimeToLocalFileTime(&ft,&lt);
  FileTimeToSystemTime(&lt,&user_entry->time);

  // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  // get pointer to decrypted personal information
  PUCHAR dataptr = (PUCHAR)(cached_entry + 1);

  // get the user id
  uLength = cached_entry->UserNameLength;
  memcpy(&user_entry->id,dataptr,uLength);
  dataptr = round_up(dataptr , uLength);

  // get the domain
  uLength = cached_entry->DomainNameLength;
  memcpy(&user_entry->domain,dataptr,uLength);
  dataptr = round_up(dataptr, uLength);

  // skip dns domain name
  uLength = cached_entry->DnsDomainNameLength;
  dataptr = round_up(dataptr , uLength);

  // skip upn
  uLength = cached_entry->UpnLength;
  dataptr = round_up(dataptr , uLength);

  // skip effective name
  uLength = cached_entry->EffectiveNameLength;
  dataptr = round_up(dataptr , uLength);

  // get the full name
  uLength = cached_entry->FullNameLength;
  memcpy(&user_entry->fullName,dataptr,uLength);

  // make sure username is lowercase
  CharLowerW(user_entry->id);

  // add user entry to linked list
  CACHE_LIST *list_entry = new CACHE_LIST;

  if (list_entry == NULL) {
      delete user_entry;
      return;                                  // return ERROR_NOT_ENOUGH_MEMORY
  }

  // initialize new list entry
  list_entry->entry = user_entry;
  list_entry->next  = NULL;

  // add list entry to cached list
  if (cache_list == NULL) {
      cache_list   = list_entry;
      current = list_entry;
  }
  else
  {
    current->next = list_entry;
    current       = list_entry;
  }
}

/**
 *
 * clear previous entries saved
 *
 */
void Cache::ClearEntries()
{
  while(cache_list != NULL)
  {
    USER_ENTRY *user_entry = cache_list->entry;
    delete user_entry;

    CACHE_LIST *list_entry = cache_list->next;
    delete cache_list;
    cache_list = list_entry;
  }
  current = NULL;
}

/**
 *
 *  dump cached credentials
 *
 *  return NULL pointer if none found or error..
 *
 */
CACHE_LIST* Cache::GetCachedEntries()
{
  // remove previous entries if they existed..incase our registry location has changed
  ClearEntries();

  // try open path to cached entries
  HKEY hSubKey;
  wchar_t path[MAX_PATH];

  wsprintfW(path,L"%s\\Cache",lpszHiveNames[SECURITY_KEY]);

  if ((dwError = RegCreateKeyExW(hRegistry,path,0,NULL,REG_OPTION_BACKUP_RESTORE,KEY_QUERY_VALUE,NULL,&hSubKey,NULL)) == ERROR_SUCCESS)
  {
    CONTROL_INFO info = {0,0};
    DWORD dwSize = sizeof(CONTROL_INFO);

    // get NL$Control information which will tell us the exact number of entries available
    // if this value didn't exist and caching of credentials was enabled, windows would automatically create it.
    if ((dwError = RegQueryValueExW(hSubKey,L"NL$Control",NULL,0,reinterpret_cast<BYTE*>(&info),&dwSize)) == ERROR_SUCCESS)
    {
      // read each available entry
      for (DWORD i = 0;i < info.dwEntries;i++)
      {
        LSA_DATA pCipherText;

        // format an entry name
        wsprintfW(path,L"NL$%i",i+1);

        // if read ciphertext good
        if ((dwError = RegQueryValueExW(hSubKey,path,NULL,0,NULL,&pCipherText.dwSize)) == ERROR_SUCCESS)
        {
          // read error or empty entry?
          if (pCipherText.dwSize == 0 || pCipherText.dwSize == 168)
              continue;

          // allocate memory for read..i had a method for this before. bah..it's not needed
          if ((pCipherText.Buffer = new BYTE[pCipherText.dwSize]) != NULL)
          {
            // now do read again
            if ((dwError = RegQueryValueExW(hSubKey,path,NULL,0,pCipherText.Buffer,&pCipherText.dwSize)) == ERROR_SUCCESS)
            {
              bool bStatus;

              // try decrypt it
              if (dwVersion == 0)
              {
                bStatus = decryptEntry_v1((CACHE_ENTRY*)pCipherText.Buffer,pCipherText.dwSize);
              }
              else if (dwVersion == 1)
              {
                bStatus = decryptEntry_v2((CACHE_ENTRY*)pCipherText.Buffer,pCipherText.dwSize);
              }

              // was decryption successful? add it to list
              if (bStatus)
              {
                //dump_hex(path,pCipherText.Buffer,pCipherText.dwSize);
                AddEntryToList((CACHE_ENTRY*)pCipherText.Buffer);
              }
            }
            delete []pCipherText.Buffer;
          } else dwError = ERROR_NOT_ENOUGH_MEMORY;
        }
      }
    }
    RegCloseKey(hSubKey);
  }
  return cache_list;
}

/**
 *
 *  grab the key used to encrypt/decrypt cached credentials
 *  pre-requisite is that we already have Syskey and LSA database key
 *
 */
bool Cache::GetCachedKey()
{
  LSA_ENTRY secret;

  lstrcpyW(secret.szKeyName,L"NL$KM");
  secret.LsaData.dwSize = 0;
  secret.LsaData.Buffer = NULL;

  if (GetLsaEntry(&secret))
  {
    if (secret.LsaData.dwSize == 64)
    {
#ifdef DEBUG
     dump_hex(L"NL$KM",secret.LsaData.Buffer,64);
#endif

      memcpy(&cachekey,secret.LsaData.Buffer,64);
      dwError = ERROR_SUCCESS;      // we really only assume it was success based on 64-byte length

    } else dwError = ERROR_BAD_LENGTH;   // unlikely to get here, but possible

    delete []secret.LsaData.Buffer;      // release memory
  }
  return dwError == ERROR_SUCCESS;
}

void Cache::GetNtlmHash(const wchar_t password[],unsigned char hash[])
{
  MD4_CTX ctx;

  MD4_Init(&ctx);
  MD4_Update(&ctx,password,wcslen(password)*2);
  MD4_Final(hash,&ctx);
}

void Cache::GetCachedHash_v1(const wchar_t username[], const wchar_t password[],unsigned char hash[])
{
  MD4_CTX ctx;

  GetNtlmHash(password,hash);

  MD4_Init(&ctx);
  MD4_Update(&ctx,hash,16);
  MD4_Update(&ctx,username,wcslen(username)*2);
  MD4_Final(hash,&ctx);
}

#define MIN(X, Y)  ((X) < (Y) ? (X) : (Y))

/**
 *
 * Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
 * Code based on IEEE Std 802.11-2007, Annex H.4.2.
 *
 */
void pkcs5_pbkdf2(unsigned char pass[], size_t pass_len, unsigned char salt[], size_t salt_len,
    unsigned char key[], size_t key_len, unsigned int rounds)
{
  unsigned char obuf[SHA_DIGEST_LENGTH];
  unsigned char d1[SHA_DIGEST_LENGTH], d2[SHA_DIGEST_LENGTH];
  size_t r;
  unsigned char asalt[128+4];

  memcpy(asalt, salt, salt_len);

  for (unsigned int count = 1; key_len > 0; count++)
  {
    asalt[salt_len + 0] = (count >> 24) & 0xff;
    asalt[salt_len + 1] = (count >> 16) & 0xff;
    asalt[salt_len + 2] = (count >>  8) & 0xff;
    asalt[salt_len + 3] = (count >>  0) & 0xff;

    hmac_sha1(asalt, salt_len + 4, pass, pass_len, d1);
    memcpy(obuf, d1, sizeof(obuf));

    for(unsigned int i = 1; i < rounds; i++)
    {
      hmac_sha1(d1, sizeof(d1), (unsigned char*)pass, pass_len, d2);
      memcpy(d1, d2, sizeof(d1));

      for(unsigned int j = 0; j < sizeof(obuf); j++)
          obuf[j] ^= d1[j];
    }

    r = MIN(key_len, SHA1_DIGEST_LENGTH);
    memcpy(key, obuf, r);
    key += r;
    key_len -= r;
  }
}

/**
 * 
 *  Generate 2nd version of cached hash
 *
 */
void Cache::GetCachedHash_v2(const wchar_t username[], const wchar_t password[], unsigned int iterations,unsigned char hash[])
{
  unsigned char v1_hash[MD4_DIGEST_LENGTH];

  GetCachedHash_v1(username,password,v1_hash);

  if(iterations > 10240)
     iterations >>= 10;

  size_t salt_len = wcslen(username)*2;
  salt_len = (salt_len > 128 - 1) ? 128-1 : salt_len;
  pkcs5_pbkdf2(v1_hash,16,(unsigned char*)username,salt_len,hash,16,iterations << 10);
}

/**
 * 
 *  retrieve the number of PBKDF iterations
 *  if the value doesn't exist, use default of 10 * 1024
 *
 */
DWORD Cache::GetIterationCount()
{
  DWORD dwIterationCount = DEFAULT_ITERATION_COUNT;
  DWORD dwSize = sizeof(dwIterationCount);
  wchar_t path[MAX_PATH];
  HKEY hSubKey;

  // if win2k/XP/win2k3, there is no iteration count required
  if (dwVersion == 0) return 0;

  wsprintfW(path,L"%s\\Cache",lpszHiveNames[SECURITY_KEY]);

  if((dwError = RegCreateKeyExW(hRegistry,path,0,NULL,REG_OPTION_BACKUP_RESTORE,KEY_QUERY_VALUE,NULL,&hSubKey,NULL)) == ERROR_SUCCESS)
  {
    dwError = RegQueryValueExW(hSubKey,L"NL$IterationCount",NULL,NULL,reinterpret_cast<BYTE*>(&dwIterationCount),&dwSize);

    if(dwIterationCount > 10240)
       dwIterationCount >>= DEFAULT_ITERATION_COUNT;

    RegCloseKey(hSubKey);
  }
  return dwIterationCount;
}

/**
 * 
 *  retrieve the number of Cached Logons remembered by the operating system
 *  if the returned value is -1, the key couldn't be opened.
 *
 */
DWORD Cache::GetCachedCount()
{
  DWORD dwCachedCount = ~0;
  DWORD dwSize = sizeof(dwCachedCount);
  wchar_t path[MAX_PATH];
  HKEY hSubKey;

  wsprintfW(path,L"%s\\Microsoft\\Windows NT\\Current Version\\Winlogon",lpszHiveNames[SOFTWARE_KEY]);

  if((dwError = RegCreateKeyExW(hRegistry,path,0,NULL,REG_OPTION_BACKUP_RESTORE,KEY_QUERY_VALUE,NULL,&hSubKey,NULL)) == ERROR_SUCCESS)
  {
    dwError = RegQueryValueExW(hSubKey,L"CachedLogonsCount",NULL,NULL,reinterpret_cast<BYTE*>(&dwCachedCount),&dwSize);
    RegCloseKey(hSubKey);
  }
  return dwCachedCount;
}

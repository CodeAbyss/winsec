
/**
 *
 *  class for obtaining SAM NTLM/LM hashes
 *
 *
 */

#include "Sam.h"

Sam::Sam()
{
  slist   = NULL;
  current = NULL;
}

Sam::~Sam()
{
  ClearEntries();
}

/**
 *
 * Convert a 7 byte array into an 8 byte des key with odd parity.
 *
 */

void str_to_key(unsigned char *str, unsigned char *key)
{
  key[0] =   str[0] >> 1;
  key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2);
  key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);
  key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4);
  key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5);
  key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6);
  key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7);
  key[7] =   str[6] & 0x7F;
    
  for (int i = 0;i < 8;i++) {
    key[i] = (key[i] << 1);
  }
  DES_set_odd_parity((DES_cblock *)key);
}

/**
 *
 * Function to convert the RID to the first decrypt key.
 *
 */

void sid_to_key1(unsigned long sid, unsigned char deskey[8])
{
  unsigned char s[7];

  s[0] = (unsigned char)((sid >>  0) & 0xFF);
  s[1] = (unsigned char)((sid >>  8) & 0xFF);
  s[2] = (unsigned char)((sid >> 16) & 0xFF);
  s[3] = (unsigned char)((sid >> 24) & 0xFF);
  s[4] = s[0];
  s[5] = s[1];
  s[6] = s[2];

  str_to_key(s,deskey);
}

/**
 *
 * Function to convert the RID to the second decrypt key.
 *
 */

void sid_to_key2(unsigned long sid,unsigned char deskey[8])
{
  unsigned char s[7];

  s[0] = (unsigned char)((sid >> 24) & 0xFF);
  s[1] = (unsigned char)((sid >>  0) & 0xFF);
  s[2] = (unsigned char)((sid >>  8) & 0xFF);
  s[3] = (unsigned char)((sid >> 16) & 0xFF);
  s[4] = s[0];
  s[5] = s[1];
  s[6] = s[2];

  str_to_key(s,deskey);
}

/**
 *
 * PEK decryption algorithm, found in SAMSRV.DLL
 *
 */
void Sam::DecryptHash_v1(unsigned long rid, char input_key[],
     unsigned char ciphertext[], unsigned char plaintext[])
{
  MD5_CTX ctx;
  RC4_KEY key;

  unsigned char md5hash[MD5_DIGEST_LENGTH];
  unsigned char obfkey[16];

  memset(obfkey,0,sizeof(obfkey));

  // decrypt the ciphertext
  MD5_Init(&ctx);
  MD5_Update(&ctx,samkey,16);
  MD5_Update(&ctx,&rid,4);
  MD5_Update(&ctx,input_key,strlen(input_key) + 1);
  MD5_Final(md5hash,&ctx);

  RC4_set_key(&key,16,md5hash );
  RC4(&key,16,ciphertext,obfkey);

  // decrypt hashes
  DES_key_schedule ks1, ks2;
  DES_cblock key1, key2;

  sid_to_key1(rid,(unsigned char*)key1);
  DES_set_key_checked((DES_cblock*)key1,&ks1);

  sid_to_key2(rid,(unsigned char*)key2);
  DES_set_key_unchecked((DES_cblock*)key2,&ks2);

  DES_ecb_encrypt((DES_cblock*)&obfkey[0],(DES_cblock*)&plaintext[0],&ks1,DES_DECRYPT);
  DES_ecb_encrypt((DES_cblock*)&obfkey[8],(DES_cblock*)&plaintext[8],&ks2,DES_DECRYPT);
}

int get_int( unsigned char *array )
{
  return ((array[0] & 0xff) + ((array[1] << 8) & 0xff00) +
         ((array[2] << 16) & 0xff0000) +
         ((array[3] << 24) & 0xff000000));
}

/**
 *
 * read and decrypt sam entry
 *
 */
bool Sam::GetEntry(SAM_REG_ENTRY *pEntry)
{
  HKEY hSubKey;
  wchar_t path[MAX_PATH];

  wsprintfW(path,L"%s\\SAM\\Domains\\Account\\Users\\%s",lpszHiveNames[SAM_KEY],pEntry->szKeyName);

  if ((dwError = RegCreateKeyExW(hRegistry,path,0,NULL,
               REG_OPTION_BACKUP_RESTORE,KEY_QUERY_VALUE,NULL,&hSubKey,NULL)) == ERROR_SUCCESS)
  {
    // get the size of buffer required for successful read
    if ((dwError = RegQueryValueExW(hSubKey,L"V",NULL,0,NULL,&pEntry->SamData.dwSize)) == ERROR_SUCCESS)
    {
      // allocate memory
      if ((pEntry->SamData.Buffer = new BYTE[pEntry->SamData.dwSize]) != NULL)
      {
        // get the data this time
        if ((dwError = RegQueryValueExW(hSubKey,L"V",NULL,0,pEntry->SamData.Buffer,&pEntry->SamData.dwSize)) == ERROR_SUCCESS)
        {
          unsigned long rid = wcstoul(pEntry->szKeyName, 0, 16);
          unsigned char *vp = pEntry->SamData.Buffer;

          int lm_size   = get_int(vp + 0xA0);
          int lm_offset = get_int(vp + 0x9C);

          int nt_size   = get_int(vp + 0xAC);
          int nt_offset = get_int(vp + 0xA8);

          lm_offset += 0xCC;
          nt_offset += 0xCC;

          if (lm_size == 20)
              DecryptHash_v1(rid,"LMPASSWORD\0",&vp[lm_offset + 4],&vp[lm_offset + 4]);

          if (nt_size == 20)
              DecryptHash_v1(rid,"NTPASSWORD\0",&vp[nt_offset + 4],&vp[nt_offset + 4]);
              
        } else delete []pEntry->SamData.Buffer;
      } else dwError = ERROR_NOT_ENOUGH_MEMORY;
    }
    RegCloseKey(hSubKey);
  }
  return (dwError == ERROR_SUCCESS);
}

/**
 *
 * add entry to linked list
 *
 */

void Sam::AddEntryToList(SAM_REG_ENTRY *pEntry)
{
  SAM_ENTRY *user_entry = new SAM_ENTRY;

  if (user_entry == NULL)
      return;                                       // ERROR_NOT_ENOUGH_MEMORY

  ZeroMemory(user_entry,sizeof(SAM_ENTRY));

  user_entry->Rid = wcstoul(pEntry->szKeyName, 0, 16);

  unsigned char *vp = pEntry->SamData.Buffer;

  int lm_size         = get_int(vp + 0xA0);
  int lm_offset       = get_int(vp + 0x9C);

  int nt_size         = get_int(vp + 0xAC);
  int nt_offset       = get_int(vp + 0xA8);

  int username_offset = get_int(vp + 0x0C);
  int username_len    = get_int(vp + 0x10);

  int fullname_offset = get_int(vp + 0x18);
  int fullname_len    = get_int(vp + 0x1c);

  int comment_offset  = get_int(vp + 0x24);
  int comment_len     = get_int(vp + 0x28);

  int homedir_offset  = get_int(vp + 0x48);
  int homedir_len     = get_int(vp + 0x4c);

  username_offset += 0xCC;
  fullname_offset += 0xCC;
  comment_offset  += 0xCC;
  homedir_offset  += 0xCC;

  nt_offset       += 0xCC;
  lm_offset       += 0xCC;

  memcpy(&user_entry->UserName,&vp[username_offset],username_len);
  memcpy(&user_entry->FullName,&vp[fullname_offset],fullname_len);
  memcpy(&user_entry->Comment, &vp[comment_offset], comment_len);
  memcpy(&user_entry->HomeDir, &vp[homedir_offset], homedir_len);

  if (lm_size == 20)
  {
    memcpy(&user_entry->SamPasswords.SecretPasswords.EncryptedLmOwfPassword,&vp[lm_offset + 4],16);
    user_entry->SamPasswords.SecretPasswords.LmPasswordPresent = true;
  }
  else user_entry->SamPasswords.SecretPasswords.LmPasswordPresent = false;

  if (nt_size == 20)
  {
    memcpy(&user_entry->SamPasswords.SecretPasswords.EncryptedNtOwfPassword,&vp[nt_offset + 4],16);
    user_entry->SamPasswords.SecretPasswords.NtPasswordPresent = true;
  }
  else user_entry->SamPasswords.SecretPasswords.NtPasswordPresent = false;

  SAM_LIST *list_entry = new SAM_LIST;

  if (list_entry == NULL)
  {
    delete user_entry;
    return;                            // ERROR_NOT_ENOUGH_MEMORY;
  }
  else
  {
    // initialize new list entry
    list_entry->entry = user_entry;
    list_entry->next  = NULL;

    // add list entry to sam list
    if(slist == NULL) {
      slist   = list_entry;
      current = list_entry;
    }
    else
    {
      current->next = list_entry;
      current       = list_entry;
    }
  }
}

/**
 *  
 *  remove any SAM_USER entries
 *
 *
 */

void Sam::ClearEntries()
{
  while (slist != NULL)
  {
    SAM_ENTRY *user_entry = slist->entry;
    delete user_entry;

    SAM_LIST *list_entry = slist->next;
    delete slist;
    slist = list_entry;
  }
}

/**
 *
 *  try dumping SAM NTLM/LM hashes, return pointer to list of entries or NULL
 *
 */
SAM_LIST* Sam::GetSamEntries()
{
  HKEY hSubKey;

  // clear any previous entries
  ClearEntries();

  wchar_t path[MAX_PATH];
  
  wsprintfW(path,L"%s\\SAM\\Domains\\Account\\Users",lpszHiveNames[SAM_KEY]);

  if ((dwError = RegCreateKeyExW(hRegistry,path,0,NULL,REG_OPTION_BACKUP_RESTORE,KEY_QUERY_VALUE,NULL,&hSubKey,NULL)) == ERROR_SUCCESS)
  {
    SAM_REG_ENTRY Entry;

    DWORD dwIndex = 0;
    DWORD cbName  = MAX_KEY_LENGTH;

    // enumerate all keys/subkeys
    while((dwError = RegEnumKeyExW(hSubKey,dwIndex,Entry.szKeyName,&cbName,NULL,NULL,NULL,NULL)) != ERROR_NO_MORE_ITEMS)
    {
      if (dwError == ERROR_SUCCESS)
      {
        // skip names entry
        if(!lstrcmpiW(Entry.szKeyName,L"Names"))
           continue;

        Entry.SamData.dwSize = 0;
        Entry.SamData.Buffer = NULL;

        // try read and decrypt hashes for this key
        if (GetEntry(&Entry)) {
            AddEntryToList(&Entry);
            delete []Entry.SamData.Buffer;
        }
      }
      cbName = MAX_KEY_LENGTH;
      dwIndex++;
    }
    RegCloseKey(hSubKey);
  }
  return slist;
}

/**
 *
 * get the key required to decrypt SAM entries
 * return true if we got it, else false
 *
 */
bool Sam::GetSamKey()
{
  char aqwerty[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
  char anum[]    = "0123456789012345678901234567890123456789\0";

  MD5_CTX ctx;
  RC4_KEY key;

  unsigned char md5_hash[MD5_DIGEST_LENGTH];
  HKEY hSubKey;
  wchar_t path[MAX_PATH];

  wsprintfW(path,L"%s\\SAM\\Domains\\Account",lpszHiveNames[SAM_KEY]);

  if ((dwError = RegCreateKeyExW(hRegistry,path,0,NULL,
               REG_OPTION_BACKUP_RESTORE,KEY_QUERY_VALUE,NULL,&hSubKey,NULL)) == ERROR_SUCCESS)
  {
    SAM_DATA pCipherText;

    // get the size of buffer required for successful read
    if ((dwError = RegQueryValueExW(hSubKey,L"F",NULL,0,NULL,&pCipherText.dwSize)) == ERROR_SUCCESS)
    {
      // allocate memory
      if ((pCipherText.Buffer = new BYTE[pCipherText.dwSize]) != NULL)
      {
        // get the data this time
        if ((dwError = RegQueryValueExW(hSubKey,L"F",NULL,0,pCipherText.Buffer,&pCipherText.dwSize)) == ERROR_SUCCESS)
        {
          MD5_Init(&ctx);
          MD5_Update(&ctx,&pCipherText.Buffer[0x70],16);
          MD5_Update(&ctx,aqwerty,strlen(aqwerty) + 1);
          MD5_Update(&ctx,syskey,16);
          MD5_Update(&ctx,anum,strlen(anum) + 1);
          MD5_Final(md5_hash,&ctx );

          RC4_set_key(&key,16,md5_hash);
          RC4(&key,32,&pCipherText.Buffer[0x80],samkey);       // why 32 bytes?

          dwError = ERROR_SUCCESS;                        // we're assuming it was ok
        }                                                 // maybe there's a checksum somewhere..never looked
        delete []pCipherText.Buffer;

      } else dwError = ERROR_NOT_ENOUGH_MEMORY;
    }
    RegCloseKey(hSubKey);
  }
  return dwError == ERROR_SUCCESS;
}

void DesEncrypt(unsigned char Clear[], unsigned char Key[], unsigned char Cypher[])
{
  unsigned char des_key[8]={0};
	DES_key_schedule ks;

	des_key[0] = ((Key[0] >> 1));
	des_key[1] = ((Key[0] & 0x01) << 6) | (Key[1] >> 2);
	des_key[2] = ((Key[1] & 0x03) << 5) | (Key[2] >> 3);
	des_key[3] = ((Key[2] & 0x07) << 4) | (Key[3] >> 4);
	des_key[4] = ((Key[3] & 0x0f) << 3) | (Key[4] >> 5);
	des_key[5] = ((Key[4] & 0x1f) << 2) | (Key[5] >> 6);
	des_key[6] = ((Key[5] & 0x3f) << 1) | (Key[6] >> 7);
	des_key[7] = ((Key[6] & 0x7f));

	for (int i = 0;i < 8;i++)
    des_key[i] = (des_key[i] << 1);

	DES_set_odd_parity((DES_cblock*)des_key);

	DES_set_key_unchecked((DES_cblock*)&des_key,&ks);
	DES_ecb_encrypt((DES_cblock*)Clear,(DES_cblock*)Cypher,&ks,DES_ENCRYPT);
}

void Sam::GetLMHash(const wchar_t password[], unsigned char lm_hash[])
{
  unsigned char OEM_password[32]={0};
  
  CharToOemW(password,reinterpret_cast<char*>(OEM_password));
  CharUpperA(reinterpret_cast<char*>(OEM_password));
  
  DesEncrypt((unsigned char*)"KGS!@#$%”",&OEM_password[0],&lm_hash[0]);
  DesEncrypt((unsigned char*)"KGS!@#$%”",&OEM_password[7],&lm_hash[8]);
}

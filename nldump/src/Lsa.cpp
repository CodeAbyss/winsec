
/**
 *
 */

#include "Lsa.h"

Lsa::Lsa()
{
  lsa_list = NULL;
}

Lsa::~Lsa()
{
  ClearEntries();
}

/**
 *
 * decrypt the LSA database key with syskey
 *
 * Windows 2000/XP/2003 version
 *
 * based on description given by mao
 *
 *   http://oxid.netsons.org/phpBB3/viewtopic.php?p=572#p572
 *
 * if you analyse LSASRV.DLL
 * you'll find this function called LsapDbDecryptKeyWithSYSKey()
 *
 */

void Lsa::DecryptLsaKey_v1(LSA_DATA* pCipherText)
{
  MD5_CTX ctx;
  RC4_KEY key;

  unsigned char dgst[MD5_DIGEST_LENGTH];
  PBYTE pPlainText;

  if((pPlainText = new BYTE[pCipherText->dwSize]) != NULL)
  {
    MD5_Init(&ctx);
    MD5_Update(&ctx,syskey,MD5_DIGEST_LENGTH);

    for(int i(0);i < 1000;i++)
      MD5_Update(&ctx,&pCipherText->Buffer[60],MD5_DIGEST_LENGTH);

    MD5_Final(dgst,&ctx);

    RC4_set_key(&key,sizeof(dgst),dgst);
    RC4(&key,48,&pCipherText->Buffer[12],pPlainText);

    memcpy(lsakey,&pPlainText[16],16);

    delete []pPlainText;
    dwError = ERROR_SUCCESS;

  } else dwError = ERROR_NOT_ENOUGH_MEMORY;
}

/**
 *
 * decrypt the LSA database key with syskey
 *
 * Windows Vista/Win2k8/Win7 version
 *
 * based on code/description given by mao
 *
 *   http://oxid.netsons.org/phpBB3/viewtopic.php?p=10574#p10574
 *
 */
void Lsa::DecryptLsaKey_v2(LSA_DATA* pCipherText)
{
  SHA256_CTX ctx;
  AES_KEY key;

  unsigned char dgst[SHA256_DIGEST_LENGTH];
  PBYTE pPlainText;
  
  if((pPlainText = new BYTE[pCipherText->dwSize]) != NULL)
  {
    SHA256_Init(&ctx);
    SHA256_Update(&ctx,syskey,16);

    for(DWORD i(0);i < 1000;i++)
        SHA256_Update(&ctx,&pCipherText->Buffer[28],SHA256_DIGEST_LENGTH);

    SHA256_Final(dgst,&ctx);

    // decrypt data
    AES_set_decrypt_key(dgst,256,&key);

    DWORD dec_len;
    unsigned char zero16[16];
    ZeroMemory(&zero16,16);

    for (dec_len = 0; dec_len < (pCipherText->dwSize - 60); dec_len += 16)
    {
      if (memcmp(&pCipherText->Buffer[60+dec_len],zero16,16) == 0) break;
      AES_decrypt(&pCipherText->Buffer[60+dec_len], &pPlainText[dec_len], &key);
    }
    memcpy(lsakey,&pPlainText[68],SHA256_DIGEST_LENGTH);

    delete []pPlainText;
    dwError = ERROR_SUCCESS;

  } else dwError = ERROR_NOT_ENOUGH_MEMORY;
}

/**
 *
 *  the LSA database key is required to decrypt LSA secrets
 *  on version 5 of windows, it is a 16-byte value decrypted by the 16-byte syskey
 *  on version 6 of windows, it is a 32-byte value decrypted by same 16-byte syskey
 *
 */
bool Lsa::GetLsaKey()
{
  const wchar_t v1[] = L"%s\\Policy\\PolSecretEncryptionKey";  // Windows 2000/XP/2003
  const wchar_t v2[] = L"%s\\Policy\\PolEKList";               // Windows Vista/2008/7

  const wchar_t *keys[2]  = { v1, v2 };

  HKEY hSubKey;

  // we check atleast 2
  for (DWORD i = 0;i < 2;i++)
  {
    wchar_t path[MAX_PATH];
    wsprintfW(path,keys[i],lpszHiveNames[SECURITY_KEY]);

    if ((dwError = RegCreateKeyExW(hRegistry,path,0,NULL,REG_OPTION_BACKUP_RESTORE,KEY_QUERY_VALUE,NULL,&hSubKey,NULL)) == ERROR_SUCCESS)
    {
      dwVersion = i;                 // we determine version based on what path was opened
      LSA_DATA pCipherText;

      if ((dwError = RegQueryValueExW(hSubKey,NULL,NULL,0,NULL,&pCipherText.dwSize)) == ERROR_SUCCESS)
      {
        if ((pCipherText.Buffer = new BYTE[pCipherText.dwSize]) != NULL)
        {
          if ((dwError = RegQueryValueExW(hSubKey,NULL,NULL,0,pCipherText.Buffer,&pCipherText.dwSize)) == ERROR_SUCCESS)
          {
            // i had used pointers for this before, but this might be better.
            if (dwVersion == 0)
            {
              DecryptLsaKey_v1(&pCipherText);
              nLsaKeyLen = 16;
            }
            else if (dwVersion == 1)
            {
              DecryptLsaKey_v2(&pCipherText);
              nLsaKeyLen = 32;
            }
          }
          
          // if we opened one of the keys but failed to read the value of it
          // function will return false
          delete []pCipherText.Buffer;
          RegCloseKey(hSubKey);
          break;

        } else dwError = ERROR_NOT_ENOUGH_MEMORY;
      }
      RegCloseKey(hSubKey);
    }
  }
  return (dwError == ERROR_SUCCESS);        // if it returns false, use GetErrorCode()
}

//
// Internal helper macros
#define AdvanceCypherData(p) p->Pointer += sizeof(CYPHER_BLOCK) //((PCYPHER_BLOCK)(((PCRYPTP_BUFFER)p)->Pointer))++
#define AdvanceClearData(p)  p->Pointer += sizeof(CLEAR_BLOCK)  //((PCLEAR_BLOCK)(((PCRYPTP_BUFFER)p)->Pointer))++

//
// Private routines
//
VOID InitializeBuffer(PCRYPTP_BUFFER PrivateBuffer,PCRYPT_BUFFER PublicBuffer)
{
  PrivateBuffer->Length        = PublicBuffer->Length;
  PrivateBuffer->MaximumLength = PublicBuffer->MaximumLength;
  PrivateBuffer->Buffer        = PublicBuffer->Buffer;
  PrivateBuffer->Pointer       = PublicBuffer->Buffer;
}

BOOLEAN ValidateDataKey(PCRYPTP_BUFFER DataKey,PBLOCK_KEY BlockKey)
{
  if (DataKey->Length == 0) 
  {
    return(FALSE);
  }
  
  if (DataKey->Length < BLOCK_KEY_LENGTH) 
  {
    DWORD DataIndex, BlockIndex;
    DataIndex = 0;
    
    for (BlockIndex = 0; BlockIndex < BLOCK_KEY_LENGTH; BlockIndex ++) \
    {
      ((PBYTE)BlockKey)[BlockIndex] = DataKey->Buffer[DataIndex];
      DataIndex++;
      
      if (DataIndex >= DataKey->Length) 
      {
        DataIndex = 0;
      }
    }
    DataKey->Buffer        = (PBYTE)BlockKey;
    DataKey->Pointer       = (PBYTE)BlockKey;
    DataKey->Length        = BLOCK_KEY_LENGTH;
    DataKey->MaximumLength = BLOCK_KEY_LENGTH;
  }
  return(TRUE);
}


VOID AdvanceDataKey(PCRYPTP_BUFFER DataKey)
{
  if (DataKey->Length > BLOCK_KEY_LENGTH) 
  {
    PBYTE EndPointer;

    DataKey->Pointer += BLOCK_KEY_LENGTH;
    EndPointer       = DataKey->Pointer + BLOCK_KEY_LENGTH;

    if (EndPointer > &(DataKey->Buffer[DataKey->Length]))
    {
      DWORD Overrun;
      
      Overrun = EndPointer - &(DataKey->Buffer[DataKey->Length]);
      DataKey->Pointer = DataKey->Buffer + (BLOCK_KEY_LENGTH - Overrun);
    }
  }
}

/**
 *
 * basic des decryption (ECB mode) of 64-bit blocks
 *
 */
void decrypt_block(BYTE key[], BYTE input[], BYTE output[])
{
  unsigned char des_key[8]={0};
  DES_key_schedule ks;

  des_key[0] = ((key[0] >> 1));
  des_key[1] = ((key[0] & 0x01) << 6) | (key[1] >> 2);
  des_key[2] = ((key[1] & 0x03) << 5) | (key[2] >> 3);
  des_key[3] = ((key[2] & 0x07) << 4) | (key[3] >> 4);
  des_key[4] = ((key[3] & 0x0f) << 3) | (key[4] >> 5);
  des_key[5] = ((key[4] & 0x1f) << 2) | (key[5] >> 6);
  des_key[6] = ((key[5] & 0x3f) << 1) | (key[6] >> 7);
  des_key[7] = ((key[6] & 0x7f));

  for (int i = 0;i < 8;i++)
       des_key[i] = (des_key[i] << 1);

  DES_set_odd_parity((DES_cblock*)des_key);

  DES_set_key_unchecked((DES_cblock*)&des_key,&ks);
  DES_ecb_encrypt((DES_cblock*)input,(DES_cblock*)output,&ks,DES_DECRYPT);
}

#define CRYPT_OK ERROR_SUCCESS

NTSTATUS RtlDecryptBlock(PCYPHER_BLOCK CypherBlock,PBLOCK_KEY BlockKey,PCLEAR_BLOCK ClearBlock)
{
  decrypt_block((BYTE*)BlockKey,(BYTE*)CypherBlock,(BYTE*)ClearBlock);
  return STATUS_SUCCESS;
}

NTSTATUS DecryptDataLength(PCRYPTP_BUFFER CypherData,PCRYPTP_BUFFER DataKey,PCRYPTP_BUFFER Data)
{
  NTSTATUS    Status;
  CLEAR_BLOCK ClearBlock;
  DWORD       Version;

  Status = RtlDecryptBlock((PCYPHER_BLOCK)(CypherData->Pointer),(PBLOCK_KEY)(DataKey->Pointer),&ClearBlock);

  if (!NT_SUCCESS(Status)) {
      return(Status);
  }

  // Advance pointers
  AdvanceCypherData(CypherData);
  AdvanceDataKey(DataKey);

  // Copy the decrypted length into the data structure.
  Data->Length = ((DWORD *)&ClearBlock)[0];

  // Check the version
  Version = ((DWORD *)&ClearBlock)[1];

  if (Version != DATA_ENCRYPTION_VERSION) {
      return(STATUS_UNKNOWN_REVISION);
  }
  return(STATUS_SUCCESS);
}


NTSTATUS DecryptFullBlock(PCRYPTP_BUFFER CypherData,PCRYPTP_BUFFER DataKey,PCRYPTP_BUFFER ClearData)
{
  NTSTATUS    Status;

  Status = RtlDecryptBlock((PCYPHER_BLOCK)(CypherData->Pointer),(PBLOCK_KEY)(DataKey->Pointer),(PCLEAR_BLOCK)(ClearData->Pointer));

  // Advance pointers
  AdvanceClearData(ClearData);
  AdvanceCypherData(CypherData);
  AdvanceDataKey(DataKey);

  return(Status);
}


NTSTATUS DecryptPartialBlock(PCRYPTP_BUFFER CypherData,PCRYPTP_BUFFER DataKey,PCRYPTP_BUFFER ClearData,DWORD Remaining)
{
  NTSTATUS     Status;
  CLEAR_BLOCK  ClearBlockBuffer;
  PCLEAR_BLOCK ClearBlock = &ClearBlockBuffer;

  // Decrypt the block into a local clear block
  Status = RtlDecryptBlock((PCYPHER_BLOCK)(CypherData->Pointer),(PBLOCK_KEY)(DataKey->Pointer),&ClearBlockBuffer);

  if (!NT_SUCCESS(Status)) {
      return(Status);
  }

  // Copy the decrypted bytes into the cleardata buffer.
  for(DWORD i = 0;i < Remaining;i++)
      ClearData->Pointer[i] = ClearBlock->data[i];

  // Advance pointers
  AdvanceClearData(ClearData);
  AdvanceCypherData(CypherData);
  AdvanceDataKey(DataKey);

  return(Status);
}

NTSTATUS SystemFunction005(PCYPHER_DATA CypherData,PDATA_KEY DataKey,PCLEAR_DATA ClearData)
{
  NTSTATUS        Status;
  DWORD           Remaining;
  CRYPTP_BUFFER   CypherDataBuffer;
  CRYPTP_BUFFER   ClearDataBuffer;
  CRYPTP_BUFFER   DataKeyBuffer;
  BLOCK_KEY       BlockKey; // Only used if datakey less than a block long

  InitializeBuffer(&ClearDataBuffer, reinterpret_cast<PCRYPT_BUFFER>(ClearData));
  InitializeBuffer(&CypherDataBuffer,reinterpret_cast<PCRYPT_BUFFER>(CypherData));
  InitializeBuffer(&DataKeyBuffer,   reinterpret_cast<PCRYPT_BUFFER>(DataKey));

  // Check the key is OK
  if (!ValidateDataKey(&DataKeyBuffer, &BlockKey)) {
      return(STATUS_INVALID_PARAMETER_2);
  }

  //
  // Decrypt the clear data length from the start of the cypher data.
  //
  Status = DecryptDataLength(&CypherDataBuffer, &DataKeyBuffer, &ClearDataBuffer);

  if (!NT_SUCCESS(Status)) {
      return(Status);
  }

  // Fail if clear data buffer too small
  if (ClearData->MaximumLength < ClearDataBuffer.Length) {
      ClearData->Length = ClearDataBuffer.Length;
      return(STATUS_BUFFER_TOO_SMALL);
  }

  //
  // Decrypt the clear data a block at a time.
  //
  Remaining = ClearDataBuffer.Length;

  while (Remaining >= CLEAR_BLOCK_LENGTH) 
  {
    Status = DecryptFullBlock(&CypherDataBuffer, &DataKeyBuffer, &ClearDataBuffer);

    if (!NT_SUCCESS(Status)) 
    {
      return(Status);
    }
    Remaining -= CLEAR_BLOCK_LENGTH;
  }

  //
  // Decrypt any partial block that remains
  //
  if (Remaining > 0) 
  {
    Status = DecryptPartialBlock(&CypherDataBuffer, &DataKeyBuffer, &ClearDataBuffer, Remaining);
    
    if (!NT_SUCCESS(Status)) 
    {
      return(Status);
    }
  }

  // Return the length of the decrypted data
  ClearData->Length = ClearDataBuffer.Length;

  return(STATUS_SUCCESS);
}

/**
 *
 * decrypt data from Win2k/XP and 2k3 systems
 *
 */
bool Lsa::DecryptLsaData_v1(LSA_DATA* pPlainText, LSA_DATA* pCipherText)
{
  CYPHER_DATA input;
  CLEAR_DATA  output;
  DATA_KEY    key;

  key.Length           = 16;
  key.MaximumLength    = 16;
  key.Buffer           = lsakey;

  input.Length         = pCipherText->dwSize - 12;
  input.MaximumLength  = pCipherText->dwSize - 12;
  input.Buffer         = &pCipherText->Buffer[12];

  output.Length        = 0;
  output.MaximumLength = 0;
  output.Buffer        = NULL;
  
  // get size of data required first
  if ((SystemFunction005(&input,&key,&output)) == STATUS_BUFFER_TOO_SMALL)
  {
    if ((pPlainText->Buffer = new BYTE[output.Length + 16]) != NULL)
    {
      output.Buffer        = pPlainText->Buffer;
      output.Length        = output.Length + 16;
      output.MaximumLength = output.Length;

      key.Length           = 16;
      key.MaximumLength    = 16;
      key.Buffer           = lsakey;

      dwError = (SystemFunction005(&input,&key,&output) == STATUS_SUCCESS) ? ERROR_SUCCESS : ERROR_INVALID_DATA;

    } else dwError = ERROR_NOT_ENOUGH_MEMORY;
  } else dwError = ERROR_INSUFFICIENT_BUFFER;

  pPlainText->dwSize = output.Length;

  return (dwError == ERROR_SUCCESS);
}

/**
 *
 * decrypt LSA secret for Windows Vista/2008/7 version
 *
 * this is minor modification of code by mao
 *    LspAES256DecryptData
 *   http://oxid.netsons.org/phpBB3/viewtopic.php?p=10574#p10574
 *
 */

bool Lsa::DecryptLsaData_v2(LSA_DATA* pPlainText, LSA_DATA* pCipherText)
{
  SHA256_CTX ctx;
  AES_KEY key;

  unsigned char dgst[SHA256_DIGEST_LENGTH];

  SHA256_Init(&ctx);
  SHA256_Update(&ctx,lsakey,32);

  for(DWORD i = 0;i < 1000;i++)
      SHA256_Update(&ctx,&pCipherText->Buffer[28],SHA256_DIGEST_LENGTH);

  SHA256_Final(dgst,&ctx);

  // decrypt data
  AES_set_decrypt_key(dgst,256,&key);

  // decrypt length
  unsigned char Length[16]={0};
  AES_decrypt(&pCipherText->Buffer[60],Length,&key);

  // 1st 32-bits appear to be length of decrypted data
  DWORD dwDataLen = ((DWORD*)Length)[0];

  if (dwDataLen < pCipherText->dwSize)
  {
    if ((pPlainText->Buffer = new BYTE[dwDataLen]) != NULL)
    {
      pPlainText->dwSize = dwDataLen;

      for(DWORD i = 0;i < dwDataLen;i += 16)
          AES_decrypt(&pCipherText->Buffer[76 + i],&pPlainText->Buffer[i],&key);

      dwError = ERROR_SUCCESS;
      
    } else dwError = ERROR_NOT_ENOUGH_MEMORY;
  } else dwError = ERROR_BAD_LENGTH;                  // this would indicate the syskey we got is wrong

  return (dwError == ERROR_SUCCESS);
}

/**
 *
 *  read and decrypt LSA secret value
 *
 */

bool Lsa::GetLsaEntry(LSA_ENTRY* pPlainText)
{
  wchar_t path[MAX_PATH];
  HKEY hSubKey;

  wsprintfW(path,L"%s\\Policy\\Secrets\\%s\\CurrVal",lpszHiveNames[SECURITY_KEY],pPlainText->szKeyName);

  if ((dwError = RegCreateKeyExW(hRegistry,path,0,NULL,REG_OPTION_BACKUP_RESTORE,KEY_QUERY_VALUE,NULL,&hSubKey,NULL)) == ERROR_SUCCESS)
  {
    LSA_DATA pCipherText;

    // if read ciphertext good
    if ((dwError = RegQueryValueExW(hSubKey,NULL,NULL,0,NULL,&pCipherText.dwSize)) == ERROR_SUCCESS)
    {
      if ((pCipherText.Buffer = new BYTE[pCipherText.dwSize]) != NULL)
      {
        if ((dwError = RegQueryValueExW(hSubKey,NULL,NULL,0,pCipherText.Buffer,&pCipherText.dwSize)) == ERROR_SUCCESS)
        {
          // try decrypt it
          if (dwVersion == 0)
          {
            DecryptLsaData_v1(&pPlainText->LsaData,&pCipherText);
          }
          else if (dwVersion == 1)
          {
            DecryptLsaData_v2(&pPlainText->LsaData,&pCipherText);
          }
        }
        delete []pCipherText.Buffer;
      } else dwError = ERROR_NOT_ENOUGH_MEMORY;
    }
    RegCloseKey(hSubKey);
  }
  return (dwError == ERROR_SUCCESS);
}


void Lsa::AddEntryToList(LSA_ENTRY *secret)
{
  // create and populate secret
  LSA_ENTRY *entry = new LSA_ENTRY;

  lstrcpynW(entry->szKeyName,secret->szKeyName,MAX_KEY_LENGTH);

  entry->LsaData.dwSize = secret->LsaData.dwSize;
  entry->LsaData.Buffer = secret->LsaData.Buffer;

  // create and populate list entry
  LSA_LIST *list_entry = new LSA_LIST;

  list_entry->entry = entry;
  list_entry->next  = NULL;

  if (lsa_list == NULL)
  {
    lsa_list = list_entry;
    current  = list_entry;
  }
  else
  {
    current->next = list_entry;
    current       = list_entry;
  }
}

/**
 *  
 *  remove any LSA_ENTRY entries
 *
 *
 */

void Lsa::ClearEntries()
{
  while (lsa_list != NULL)
  {
    LSA_ENTRY *entry = lsa_list->entry;
    delete []entry->LsaData.Buffer;
    delete entry;

    LSA_LIST *list_entry = lsa_list->next;
    delete lsa_list;
    lsa_list = list_entry;
  }
}

/**
 *
 *  function to read and decrypt LSA secrets
 *  returning pointer to linked list of LSA_ENTRY* or NULL if unsuccessful
 *
 */

LSA_LIST* Lsa::GetLsaEntries()
{
  // clean out incase reading different hive
  ClearEntries();

  // open path to secrets for enumeration
  wchar_t path[MAX_PATH];
  HKEY hSubKey;

  wsprintfW(path,L"%s\\Policy\\Secrets",lpszHiveNames[SECURITY_KEY]);

  if ((dwError = RegCreateKeyExW(hRegistry,path,0,NULL,REG_OPTION_BACKUP_RESTORE,KEY_QUERY_VALUE,NULL,&hSubKey,NULL)) == ERROR_SUCCESS)
  {
    LSA_ENTRY Entry;
    DWORD dwIndex = 0;
    DWORD cbName  = MAX_KEY_LENGTH;

    // enumerate all keys/subkeys
    while ((dwError = RegEnumKeyExW(hSubKey,dwIndex,Entry.szKeyName,&cbName,NULL,NULL,NULL,NULL)) != ERROR_NO_MORE_ITEMS)
    {
      if (dwError == ERROR_SUCCESS)
      {
        Entry.LsaData.dwSize = 0;
        Entry.LsaData.Buffer = NULL;

        // get decrypted secret
        GetLsaEntry(&Entry);

        // add it, even if we didn't get any data
        AddEntryToList(&Entry);
      }
      cbName = MAX_KEY_LENGTH;
      dwIndex++;
    }
    dwError = ERROR_SUCCESS;
    RegCloseKey(hSubKey);
  }
  return lsa_list;
}

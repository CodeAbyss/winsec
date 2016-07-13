/**
    March 2010 - Odzhan
    
    DPAPI password change algorithm using DES3 / PBKDF2

    the version i reversed used 4000 rounds but vista
    uses 24000 rounds while windows 7 uses something similar
 */
#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <Sddl.h>
#include <shellapi.h>
#include <intrin.h>

#include <openssl/md4.h>
#include <openssl/sha.h>
#include <openssl/des.h>

#include <cstdio>

DWORD dwError;

bool GetTextualSid(wchar_t * &strSid)
{
  bool bResult = false;
  HANDLE hToken = NULL;

  if (OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hToken))
  {
    //printf("\nToken handle aquired..");
    DWORD dwTokenSize = 0;
    if (!GetTokenInformation(hToken,TokenUser,NULL,0,&dwTokenSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
      //printf("\nAllocating memory for token..");
      PBYTE pTokenUser = NULL;
      if ((pTokenUser = new BYTE[dwTokenSize]) != NULL)
      {
        //printf("done\nGetting user token information..");
        if (GetTokenInformation(hToken,TokenUser,pTokenUser,dwTokenSize,&dwTokenSize))
        {
          //printf("done\nConverting to string..");

          ConvertSidToStringSidW(reinterpret_cast<PTOKEN_USER>(pTokenUser)->User.Sid,(LPWSTR*)&strSid);
          dwError = GetLastError();
        } else dwError = GetLastError();
        delete []pTokenUser;
      } else dwError = ERROR_NOT_ENOUGH_MEMORY;
    } else dwError = GetLastError();
    CloseHandle(hToken);
  } else dwError = GetLastError();
  return (dwError == ERROR_SUCCESS);
}

#define SHA_BLOCK_LENGTH 64

void hmac_sha1(unsigned char text[], unsigned int text_len,
     unsigned char key[], int key_len, unsigned char digest[])
{
  SHA_CTX ctx;
  unsigned char k_ipad[SHA_BLOCK_LENGTH+1],k_opad[SHA_BLOCK_LENGTH+1];
  unsigned char tk[SHA_DIGEST_LENGTH];

  if (key_len > SHA_BLOCK_LENGTH) {
      SHA1_Init(&ctx);
      SHA1_Update(&ctx,key,key_len);
      SHA1_Final(tk,&ctx);

      key = tk;
      key_len = SHA_DIGEST_LENGTH;
  }

  memset(k_ipad,0x36,SHA_BLOCK_LENGTH);
  memset(k_opad,0x5c,SHA_BLOCK_LENGTH);

  for (int i(0);i < key_len;i++) {
       k_ipad[i] ^= key[i];
       k_opad[i] ^= key[i];
  }

  SHA1_Init(&ctx);
  SHA1_Update(&ctx,k_ipad,SHA_BLOCK_LENGTH);
  SHA1_Update(&ctx,text,text_len);
  SHA1_Final(tk,&ctx);

  SHA1_Init(&ctx);
  SHA1_Update(&ctx,k_opad,SHA_BLOCK_LENGTH);
  SHA1_Update(&ctx,tk,SHA_DIGEST_LENGTH);
  SHA1_Final(digest,&ctx);
}

void dump_hex(char *desc, unsigned char buffer[],size_t len)
{
  printf("\n%15s = ",desc);

  for(size_t i(0);i < len;i++)
      printf("%02x",buffer[i]);
}

#define MIN(X, Y)  ((X) < (Y) ? (X) : (Y))

int pkcs5_pbkdf2_MS(unsigned char pass[], size_t pass_len, unsigned char salt[], size_t salt_len,
    unsigned char key[], size_t key_len, unsigned int rounds)
{
    unsigned char obuf[SHA_DIGEST_LENGTH];
    unsigned char d1[SHA_DIGEST_LENGTH], d2[SHA_DIGEST_LENGTH];
    size_t r;
    unsigned char asalt[128+4];
  
    memset(asalt,0,sizeof(asalt));

    if (rounds < 1 || key_len == 0)
        return -1;

    if (salt_len == 0 || salt_len > 128 - 1)
        return -1;

        // http://tools.ietf.org/html/rfc2898#section-5.1
        
    memcpy(asalt, salt, salt_len);

    for (unsigned int count = 1; key_len > 0; count++)
    {
      asalt[salt_len + 0] = (count >> 24) & 0xff;
      asalt[salt_len + 1] = (count >> 16) & 0xff;
      asalt[salt_len + 2] = (count >>  8) & 0xff;
      asalt[salt_len + 3] = (count >>  0) & 0xff;

      hmac_sha1(asalt, salt_len + 4, pass, pass_len, d1); // hash is generated here as d1
      memcpy(obuf, d1, sizeof(obuf));                     // copied into obuf
    
      for (unsigned int i = 1; i < rounds; i++)
      {
        hmac_sha1(d1, sizeof(d1), (unsigned char*)pass, pass_len, d2);
        memcpy(d1, d2, sizeof(d1));

        for (unsigned int j = 0; j < 20; j++)
             obuf[j] ^= d1[j];                            // here is exploit
             
        // M$ does this...
        memcpy(d1,obuf,20);            // copy back
      }
    
      r = MIN(key_len, SHA_DIGEST_LENGTH);
      memcpy(key, obuf, r);
      key += r;
      key_len -= r;
    }
    return 0;
}

extern "C" void PKCS5DervivePBKDF2(unsigned char hmac_hash[],unsigned int hmac_len,
     unsigned char salt[],unsigned int salt_len,unsigned int dwType,unsigned int iterations,unsigned int count,unsigned char buffer[]);

int main()
{
  int argc;
  wchar_t **argv = CommandLineToArgvW(GetCommandLineW(),&argc);

  if (argc != 3)
  {
    printf("\nUsage:changepass <current password> <new password\n");
    return 0;
  }

  unsigned char new_password[SHA_DIGEST_LENGTH];
  unsigned char old_password[SHA_DIGEST_LENGTH];
  unsigned char ntlm_hash[MD4_DIGEST_LENGTH];
  unsigned char hmac_hash[SHA_DIGEST_LENGTH];
  unsigned char old_passwords[40];
  unsigned char pbkdf2_hash[SHA_DIGEST_LENGTH*2]={0};

  wchar_t *sid = L"S-1-5-21-507921405-879983540-1417001333-500\0";

  //unsigned char salt[16]={0x6c,0xc3,0x6e,0x00,0x11,0xc8,0xea,0x18,0x14,0x40,0x3a,0x29,0xc6,0x1d,0x26,0x42};
  unsigned char salt[20]={0xc9,0x38,0x97,0xb6,0xf4,0xe2,0x3d,0x2c,0xab,0x61,0x1d,0xb7,0x90,0x1c,0xfa,0xf5,0x00,0x00,0x00,0x01};

  SHA_CTX ctx1;
  MD4_CTX ctx2;


  SHA1_Init(&ctx1);
  SHA1_Update(&ctx1,argv[1],wcslen(argv[1])*2);
  SHA1_Final(old_password,&ctx1);
  dump_hex("Old SHA-1 hash",old_password,20);


  MD4_Init(&ctx2);
  MD4_Update(&ctx2,argv[1],wcslen(argv[1])*2);
  MD4_Final(ntlm_hash,&ctx2);
  dump_hex("Old NTLM hash",ntlm_hash,16);


  SHA1_Init(&ctx1);
  SHA1_Update(&ctx1,argv[2],wcslen(argv[2])*2);
  SHA1_Final(new_password,&ctx1);
  dump_hex("New SHA-1 hash",new_password,20);


  printf("\n%18s","User Sid = ");
  wprintf(L"%s",sid);

  // create hmac from string sid and sha-1 of password
  hmac_sha1((unsigned char*)sid,2+wcslen(sid)*2,new_password,20,hmac_hash);
  dump_hex("HMAC",hmac_hash,20);

  // use variation of PBKDF2 with M$ modifications
  pkcs5_pbkdf2_MS(hmac_hash,20,salt,16,pbkdf2_hash,40,4000);
  dump_hex("PBKDF2",pbkdf2_hash,40);
  
  // use the pbkdf2 hash to generate 3 DES key schedules
  // then use these key schedules to encrypt old_password + ntlm_hash with last 16 bytes of pbkdf2_hash as IV
  DES_key_schedule ks1,ks2,ks3;

  DES_set_key_unchecked((const_DES_cblock*)&pbkdf2_hash[0],&ks1);
  DES_set_key_unchecked((const_DES_cblock*)&pbkdf2_hash[8],&ks2);
  DES_set_key_unchecked((const_DES_cblock*)&pbkdf2_hash[16],&ks3);

  unsigned char ciphertext[64];

  memset(&old_passwords,0,sizeof(old_passwords));
  memset(&ciphertext,0,sizeof(ciphertext));

  memcpy(&old_passwords[0],old_password,20);
  memcpy(&old_passwords[20],ntlm_hash,16);

  DES_ede3_cbc_encrypt(old_passwords,ciphertext,40,&ks1,&ks2,&ks3,(const_DES_cblock*)&pbkdf2_hash[24],DES_ENCRYPT);

  dump_hex("CIPHERTEXT",&pbkdf2_hash[24],16);

  return 0;
}

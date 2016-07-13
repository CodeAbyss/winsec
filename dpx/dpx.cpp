/**
  Copyright (C) 2016 Odzhan.
  
  All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>

#include <windows.h>
#include <shlwapi.h>

#pragma comment (lib, "shlwapi.lib")
#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "crypt32.lib")

#include "dpapi.h"

FILE *file_in=NULL;
uint8_t *mem=NULL;
size_t file_size=0;

typedef struct ALG_INFO {
  ALG_ID id;
  char* str;
} ALG_INFO, *PALG_INFO;

ALG_INFO alg_ids[] = 
{ CALG_DES,      "DES",
  CALG_3DES,     "3DES", 
  CALG_3DES_112, "3DES-112",
  CALG_AES_128,  "AES-128",
  CALG_AES_192,  "AES-192",
  CALG_AES_256,  "AES-256", 
  CALG_HMAC,     "HMAC",
  CALG_MAC,      "MAC",
  CALG_MD2,      "MD2",
  CALG_MD5,      "MD5",
  CALG_RC2,      "RC2",
  CALG_RC4,      "RC4",
  CALG_RSA_KEYX, "RSA-KEYX",
  CALG_RSA_SIGN, "RSA-SIGN",
  CALG_SHA,      "SHA",
  CALG_SHA1,     "SHA-1",
  CALG_SHA_256,  "SHA-256",
  CALG_SHA_384,  "SHA-284",
  CALG_SHA_512,  "SHA-512"
};

char *alg2str (uint32_t alg)
{
  int i;
  char *str="Unknown";
  
  for (i=0; i<sizeof(alg_ids)/sizeof(ALG_INFO); i++)
  {
    if (alg==alg_ids[i].id) {
      str=alg_ids[i].str;
      break;
    }
  }
  return str;
}

typedef struct FLAG_INFO {
  int id;
  char* str;
} FLAG_INFO, *PFLAG_INFO;
   
FLAG_INFO flag_ids[] =
{ CRYPTPROTECT_UI_FORBIDDEN,      "CRYPTPROTECT_UI_FORBIDDEN",
  CRYPTPROTECT_LOCAL_MACHINE,     "CRYPTPROTECT_LOCAL_MACHINE",
  CRYPTPROTECT_CRED_SYNC,         "CRYPTPROTECT_CRED_SYNC",
  CRYPTPROTECT_AUDIT,             "CRYPTPROTECT_AUDIT",
  CRYPTPROTECT_VERIFY_PROTECTION, "CRYPTPROTECT_VERIFY_PROTECTION",
  CRYPTPROTECT_CRED_REGENERATE,   "CRYPTPROTECT_CRED_REGENERATE",
  CRYPTPROTECT_SYSTEM,            "CRYPTPROTECT_SYSTEM"
};

char *flags2str (uint32_t flags)
{
  int i;
  static char flag_str[256];
  
  flag_str[0]=0;
  
  for (i=0; i<sizeof(flag_ids)/sizeof(FLAG_INFO); i++)
  {
    if (flags & flag_ids[i].id) 
    {
      if (flag_str[0]!=0) {
        strcat (flag_str, "| ");
      }
      strcat (flag_str, flag_ids[i].str);
      break;
    }
  }
  if (flag_str[0]==0) {
    strcat (flag_str, "None");
  }
  return flag_str;
}

/**F*****************************************************************/
void xstrerror (char *fmt, ...) 
/**
 * PURPOSE : Display windows error
 *
 * RETURN :  Nothing
 *
 * NOTES :   None
 *
 *F*/
{
  char    *error=NULL;
  va_list arglist;
  char    buffer[2048];
  DWORD   dwError=GetLastError();
  
  va_start (arglist, fmt);
  wvnsprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
  
  if (FormatMessage (
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
      (LPSTR)&error, 0, NULL))
  {
    printf ("\n  [ %s : %s", buffer, error);
    LocalFree (error);
  } else {
    printf ("\n  [ %s : %i", buffer, dwError);
  }
}

char *bin2hex (uint8_t bin[], size_t len)
{
  static char hex[64];
  size_t i;
  
  len=(len > sizeof(hex)-1) ? sizeof(hex)-1 : len;
  
  for (i=0; i<len; i++) {
    sprintf (&hex[i*2], "%02x", bin[i]);
  }
  return hex;
}

char *bin2uuid (void *bin)
{
  static char uuid[64];
  GUID *id=(GUID*)bin;
  
  sprintf (uuid, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      id->Data1, id->Data2, id->Data3,
      id->Data4[0], id->Data4[1], 
      id->Data4[2], id->Data4[3], id->Data4[4], 
      id->Data4[5], id->Data4[6], id->Data4[7]);
      
  return uuid;
}

void dump_credhist (void) 
{
  PCREDENTIAL_HEADER hdr;
  PCREDENTIAL_ENTRY ce;
  uint8_t *p=(uint8_t*) (mem + file_size);
  uint8_t *sid, *sha1_hash, *ntlm1_hash;
  int i;
  
  if (file_size > sizeof (CREDENTIAL_HEADER))
  {
    printf ("\n  * * * CREDHIST INFORMATION * * *\n");
    
    try {
      do {
        p -= sizeof(CREDENTIAL_HEADER);
        hdr = (PCREDENTIAL_HEADER)p;
        
        if (hdr->dwNextLinkSize < sizeof(CREDENTIAL_ENTRY)) {
          break;
        }  
        p -= hdr->dwNextLinkSize - sizeof(CREDENTIAL_HEADER);
        ce = (PCREDENTIAL_ENTRY)p;
        sid=(p + sizeof(CREDENTIAL_ENTRY));
        sha1_hash=(p + sizeof(CREDENTIAL_ENTRY) + ce->dwSidSize);
        ntlm1_hash=(sha1_hash + ce->dwShaHashSize);
        
        printf ("\n  %-20s : %s", "Hash",             alg2str (ce->algHash));
        printf ("\n  %-20s : %i", "PBKDF Iterations", ce->dwPbkdf2IterationCount);
        printf ("\n  %-20s : %s", "Cipher",           alg2str (ce->algCrypt));
        printf ("\n  %-20s : %s", "Salt",             bin2hex (ce->pSalt, 16));
        printf ("\n  %-20s : %s", "Sid",              bin2hex (sid, ce->dwSidSize));
        printf ("\n  %-20s : %s", "SHA-1 Hash",       bin2hex (sha1_hash, ce->dwShaHashSize));
        printf ("\n  %-20s : %s", "NTLM Hash",        bin2hex (ntlm1_hash, ce->dwNtHashSize));
        putchar ('\n');
      } while (1);
    } catch (...) {};
  } else {
    printf ("\n  Size mismatch");
  }
}

// dump info about DPAPI master key
void dump_mkey (void) 
{
  PMASTERKEY pKey;
  PUSER_KEY pUser;
  uint8_t *p=mem;
  uint32_t key_size;
  
  if (file_size >= sizeof (MASTERKEY))
  {
    printf ("\n  * * * MASTERKEY INFORMATION * * *\n");
    
    try {
      pKey = (PMASTERKEY)p;
      
	    // dump header info
      printf ("\n  %-20s : %i",  "Version",            pKey->dwVersion);
      printf ("\n  %-20s : %ws", "GUID",               pKey->szGuid);
      printf ("\n  %-20s : %i",  "Policy",             pKey->dwPolicy);
      printf ("\n  %-20s : %i",  "User Key Size",      pKey->dwUserKeySize[0]);
      printf ("\n  %-20s : %i",  "Local Enc Key Size", pKey->dwLocalEncKeySize[0]);
      printf ("\n  %-20s : %i",  "Local Key Size",     pKey->dwLocalKeySize[0]);
      printf ("\n  %-20s : %i\n","Domain Key Size",    pKey->dwDomainKeySize[0]);
	  
	    p += sizeof(MASTERKEY);
	    pUser = (PUSER_KEY)p;
	  
	    // dump user key
	    printf ("\n  %-20s : %i", "Version",    pUser->dwVersion);
	    printf ("\n  %-20s : %s", "User Salt",  bin2hex (pUser->pSalt, 16));
	    printf ("\n  %-20s : %i", "PBKDF",      pUser->dwPbkdf2IterationCount);
	    printf ("\n  %-20s : %s", "Hash",       alg2str (pUser->algHash));
	    printf ("\n  %-20s : %s", "Crypt",      alg2str (pUser->algCrypt));
	  
	    p += sizeof(USER_KEY);
	    key_size = pKey->dwUserKeySize[0] - sizeof(USER_KEY);
	  
	    printf ("\n  %-20s : %s\n", "User Key", bin2hex (p, key_size)); 
	    p += key_size;
	  
	    // dump key
	    pUser = (PUSER_KEY)p;
	  
	    // dump user key
	    printf ("\n  %-20s : %i", "Version",    pUser->dwVersion);
	    printf ("\n  %-20s : %s", "User Salt",  bin2hex (pUser->pSalt, 16));
	    printf ("\n  %-20s : %i", "PBKDF",      pUser->dwPbkdf2IterationCount);
	    printf ("\n  %-20s : %s", "Hash",       alg2str (pUser->algHash));
	    printf ("\n  %-20s : %s", "Crypt",      alg2str (pUser->algCrypt));
	  
	    p += sizeof(USER_KEY);
	    key_size = pKey->dwLocalEncKeySize[0] - sizeof(USER_KEY);
	  
	    printf ("\n  %-20s : %s\n", "User Key", bin2hex (p, key_size)); 
	    p += key_size;
    } catch (...) {};
  } else {
    printf ("\n  Size mismatch");
  }
}

// dump info about DPAPI blob
uint32_t dump_blob (uint8_t *p, uint32_t len) 
{
  PDPAPI_HEADER     dhdr;
  PDPAPI_CIPHER     dc;
  PDPAPI_CIPHERTEXT dct;
  PDPAPI_KEY        dkey;
  PDPAPI_HMAC       dmac;
  uint32_t i=0;

  if (len > sizeof (DPAPI_HEADER))
  {
    printf ("\n  * * * DPAPI BLOB INFORMATION * * *\n");
    try {
      dhdr = (PDPAPI_HEADER) p;
      dc   = (PDPAPI_CIPHER) ((uint8_t*)dhdr->szDescription + dhdr->dwDescription);
      dkey = (PDPAPI_KEY) ((uint8_t*)dc + sizeof(DPAPI_CIPHER) + dc->dwSalt - 1);
      dct  = (PDPAPI_CIPHERTEXT) ((uint8_t*)dkey + sizeof(DPAPI_KEY) + dkey->dwSize - 1);
      dmac = (PDPAPI_HMAC) ((uint8_t*)dct + sizeof(DPAPI_CIPHERTEXT) + dct->dwSize - 1);
  
      // process header
      printf ("\n  %-20s : %i",  "Version",     dhdr->dwProviders);
      printf ("\n  %-20s : %s",  "Provider",    bin2uuid (&dhdr->provider));
      printf ("\n  %-20s : %i",  "Version",     dhdr->dwVersion);
      printf ("\n  %-20s : %s",  "Master Key",  bin2uuid (&dhdr->masterKey));
      printf ("\n  %-20s : %s",  "Flags",       flags2str (dhdr->dwFlags));
      printf ("\n  %-20s : %ws", "Description", dhdr->dwDescription <= 2 ? L"(null)" : dhdr->szDescription);  
      printf ("\n  %-20s : %s",  "Cipher",      alg2str (dc->id));
      printf ("\n  %-20s : %s",  "Salt",        bin2hex (dc->bSalt, dc->dwSalt));
      printf ("\n  %-20s : %s",  "Key Alg",     alg2str (dkey->id));
      printf ("\n  %-20s : %s",  "Key",         bin2hex (dkey->bValue, dkey->dwSize));  
      printf ("\n  %-20s : %s",  "Ciphertext",  bin2hex (dct->bValue, dct->dwSize));  
      printf ("\n  %-20s : %s\n","Hmac",        bin2hex (dmac->bValue, dmac->dwSize));
      i=(((uint8_t*)dmac + dmac->dwSize + 4) - p);
    } catch (...) {};
  } else {
    printf ("\n  Size mismatch");
  }
  return i;
}

#define MIN_BLOB_SIZE sizeof (DPAPI_HEADER) + \
  sizeof (DPAPI_CIPHER) + \
  sizeof (DPAPI_KEY) + \
  sizeof (DPAPI_CIPHERTEXT) + \
  sizeof (DPAPI_HMAC)

void dump_pref (void)
{
  if (file_size == sizeof (PREFERREDMASTERKEY))
  {
    printf ("\n  * * * PREFERRED MASTERKEY INFORMATION * * *\n");
    printf ("\n  %-5s : %s\n", "GUID", bin2uuid (mem));
  } else {
    printf ("\n  Size mismatch");
  }
}

void dump_hex_short (void)
{
  int i, ofs=0;
  
  for (i=0; i<file_size; i++)
  {
    if ((i & 15)==0) {
      printf ("\n%08x ", ofs);
    }
    printf ("%02x ", mem[i]);
    ofs++;
  }
}

void dump_hex (uint8_t *mem, int file_size) 
{
  int i, ofs;
  uint8_t c;
  
  for (ofs=0; ofs<file_size; ofs+=16) 
  {
    printf ("\n%08X", ofs);
    for (i=0; i<16 && ofs+i < file_size; i++) {
      printf (" %02x", mem[ofs + i]);
    }
    while (i++ < 16) {
      printf ("   ");
    }
    printf ("    ");

    for (i=0; i<16 && ofs+i < file_size; i++) {
      c=mem[ofs+i];
      printf ("%c", (c=='\t' || !isprint (c)) ? '.' : c);
    }
  }
}

void save_hex (uint8_t *mem, int file_size) 
{
  int i, ofs;
  uint8_t c;
  FILE *fd;
  
  fd=fopen("hex.txt", "a");
  if (fd==NULL) return;
  
  for (ofs=0; ofs<file_size; ofs+=16) 
  {
    fprintf (fd, "\n%08X", ofs);
    for (i=0; i<16 && ofs+i < file_size; i++) {
      fprintf (fd, " %02x", mem[ofs + i]);
    }
    while (i++ < 16) {
      fprintf (fd, "   ");
    }
    fprintf (fd, "    ");

    for (i=0; i<16 && ofs+i < file_size; i++) {
      c=mem[ofs+i];
      fprintf (fd, "%c", (c=='\t' || !isprint (c)) ? '.' : c);
    }
  }
  fclose(fd);
}

// returns 1 if blob is probably a DPAPI blob else 0
int is_dpapi (uint8_t blob[], uint32_t mem_len)
{
  PDPAPI_HEADER     dhdr;
  PDPAPI_CIPHER     dc;
  PDPAPI_CIPHERTEXT dct;
  PDPAPI_KEY        dkey;
  int r = 0;
  
  if (mem_len > sizeof(DPAPI_HEADER))
  {
    try {
      dhdr = (PDPAPI_HEADER) blob;
      
      // if version is 1 or 2
      if (dhdr->dwVersion == 1 || dhdr->dwVersion == 2)
      {
        printf("\nok version");
        dc = (PDPAPI_CIPHER) ((uint8_t*)dhdr->szDescription + dhdr->dwDescription);
        if (IsBadReadPtr(dc, sizeof(DPAPI_CIPHER))) return 0;
        // if salt length is 16
        if (dc->dwSalt == 16 || dc->dwSalt == 32)
        {
          printf("\nok salt");
          // if valid cipher
          if (dc->id == CALG_AES_256 || dc->id == CALG_3DES)
          {
            printf("\nok algorithm");
            dkey = (PDPAPI_KEY) ((uint8_t*)dc + sizeof(DPAPI_CIPHER) + dc->dwSalt - 1);
            if (IsBadReadPtr(dkey, sizeof(DPAPI_KEY))) return 0;
            // if valid key
            if (dkey->id == CALG_HMAC || dkey->id == CALG_SHA_512)
            {
              printf("\nok blob");
              r=1;
            }
          }
        }
      }
    } catch (...) {};
  }
  return r;
}

void save_blob (uint8_t *p, uint32_t len)
{
  char path[MAX_PATH];
  static int cnt=0;
  
  sprintf (path, "blob_%08X.bin", cnt++);
  FILE *out=fopen (path, "wb");
  
  if (out!=NULL) {
    fwrite (p, 1, len, out);
    fclose (out);
  }
}

// scan a file for blobs
void scan_file (int extract)
{
  uint32_t i, len;
  
  for (i=0; i<file_size; i++)
  {
    if (is_dpapi(&mem[i], file_size - i)) {
      len=dump_blob (&mem[i], file_size - i);
      if (extract) {
        save_blob (&mem[i], len);
      }
      i += len;
    }
  }
}

// try decrypt a blob
void dec_blob(void *data, DWORD len) 
{
    DATA_BLOB in, out;
    LPWSTR    *desc=NULL;
    
    in.pbData=(PBYTE)data;
    in.cbData=len;
    
    if (CryptUnprotectData(&in, desc, NULL, NULL, NULL, 0, &out)) {
      printf ("\nDecrypted %i bytes\nDescription: %s\n", 
        out.cbData, desc);
      dump_hex(out.pbData, out.cbData);
      save_hex(out.pbData, out.cbData);
      LocalFree(out.pbData);
      if (desc!=NULL) LocalFree(desc);
    } else {
      xstrerror("CryptProtectData");
    }
}

void scan_value (HKEY hKey, char name[], int xtract, int dec) 
{
  DWORD err, idx, type, name_len, data_len;
  BYTE  reg_data[8192];
  char  sub_name[256], path[1024];

  for (idx=0;;idx++) {
    name_len=256;
    data_len=8192;
    
    err = RegEnumValue (hKey, idx, sub_name, &name_len,
        0, &type, reg_data, &data_len);

    if (err == ERROR_NO_MORE_ITEMS) break;
    if (err != ERROR_SUCCESS) break;
    
    if (type==REG_BINARY && data_len!=0) {
      if (data_len >= MIN_BLOB_SIZE) {
        sprintf (path, "%s\\%s", name, sub_name);
        printf ("\rChecking blob for %-260s", path);
        if (is_dpapi (reg_data, data_len)) {
          printf ("\nFound blob at %s", path);
          dump_blob (reg_data, data_len);
          if (xtract) save_blob(reg_data, data_len);
          if (dec) dec_blob(reg_data, data_len);
        }
      }
    }
  }
}

void scan_key (HKEY hKey, char *name, int xtract, int dec)
{
  DWORD err, idx, name_len;
  HKEY hSubKey;
  char sub_name[256], path[512];
  
  for (idx=0;;idx++) {
    err=RegEnumKey (hKey, idx, sub_name, sizeof(sub_name));

    if (err==ERROR_NO_MORE_ITEMS) break;    
    if (err!=ERROR_SUCCESS) break;
    
    err=RegOpenKey (hKey, sub_name, &hSubKey);
    
    if (err!=ERROR_SUCCESS) continue;
      
    sprintf (path, "%s\\%s", name, sub_name);
    printf ("\rChecking values for %-260s", path);
    scan_value (hSubKey, path, xtract, dec);
    printf ("\rChecking keys for %-260s", path);
    scan_key (hSubKey, path, xtract, dec);
    RegCloseKey (hSubKey);
  }
}

typedef struct _reg_t {
  HKEY hKey;
  char *s;
} reg_t;

/**F*****************************************************************/
LONG WINAPI MyUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionPtrs)
{
  PEXCEPTION_RECORD er=pExceptionPtrs->ExceptionRecord;
  PCONTEXT ctx=pExceptionPtrs->ContextRecord;
  
  printf ("\nException at %p", er->ExceptionAddress);
  printf ("\nEBX : %08lX | ESI : %08lX | ECX : %08lX", ctx->Ebx, ctx->Esi, ctx->Ecx);
  
  return EXCEPTION_CONTINUE_EXECUTION; 
} 

// scan registry for blobs
void scan_reg (int xtract, int dec)
{
  //SetUnhandledExceptionFilter (MyUnhandledExceptionFilter);
  
  reg_t keys[]={{HKEY_CURRENT_USER, "HKCU"}, {HKEY_CLASSES_ROOT,"HKCR"},{HKEY_LOCAL_MACHINE,"HKLM"},{HKEY_USERS,"HKU"}};
  int i;
  
  for (i=0; i<sizeof(keys)/sizeof(reg_t); i++) {
    printf ("\nScanning %s...", keys[i].s);
    scan_key (keys[i].hKey, keys[i].s, xtract, dec);
  }
}

int open_file (char fn[])
{ 
  int r=0;
  struct stat st;
  
  // open file for read
  file_in=fopen (fn, "rb");
  
  if (file_in!=NULL) {
    stat (fn, &st);
    file_size=st.st_size;
    // allocate memory for data
    mem=(uint8_t*)malloc (st.st_size);
    if (mem!=NULL) {
      // read into memory
      fread (mem, 1, st.st_size, file_in);
      r=1;
    }
  }
  return r;
}

void close_file (void)
{
  // free memory
  if (mem!=NULL) {
    free (mem);
    mem=NULL;
  }
  // close file
  if (file_in!=NULL) {
    fclose (file_in);
    file_in=NULL;
  }
}

void usage (void)
{
  printf ("    /b <file>  File containing DPAPI blob\n");
  printf ("    /c <file>  CREDHIST file\n");
  printf ("    /d         Try to decrypt blob\n");
  printf ("    /h         Dump hexadecimal values\n");
  printf ("    /p <file>  Preferred master key file\n");
  printf ("    /m <file>  Master key file\n");
  printf ("    /r         Scan registry for DPAPI blobs\n");
  printf ("    /s <file>  Scan file for DPAPI data\n");
  printf ("    /x         Extract DPAPI data to file\n\n");
  exit (0);
}
   
int main (int argc, char *argv[]) 
{
  int i, ch=0, pref=0, hex=0, mkey=0, file=0, scan=0, xtract=0, reg=0, decrypt=0;
  char opt;
  char *fn=NULL;
  
  puts ("\n  dpx v0.1 - DPAPI Structure Info\n");
  
  for (i=1; i<argc; i++) 
  {
    if (argv[i][0]=='/' || argv[i][0]=='-')
    {
      opt=argv[i][1];
      switch (opt)
      {
        // DPAPI blob
        case 'b':
          file=1;
          break;
        // CREDHIST
        case 'c':
          ch=1;
          break;
        // attempt to decrypt blobs
        case 'd':
          decrypt=1;
          break;
        // dump hex
        case 'h':
          hex=1;
          break;
        // Preferred
        case 'p':
          pref=1;
          break;
        // Master Key
        case 'm':
          mkey=1;
          break;
        // extract blobs if scanning files or registry
        case 'x':
          xtract=1;
          break;
        // scan registry
        case 'r':
          reg=1;
          break;
        // scan file
        case 's':
          scan=1;
          break;
        default:
          usage();
          break;
      }
    } else {
      fn=argv[i];
    }
  }
  if ((file | ch | pref | mkey | hex | scan | reg)==0) {
    usage();
  }

  if (reg) {
    scan_reg (xtract, decrypt);
  } 
  else if (open_file (fn))
  {
    if (ch) {
      dump_credhist();
    }
    if (pref) {
      dump_pref();
    }
    if (mkey) {
      dump_mkey();
    }
    if (file) {
      printf ("\nDump size %i", dump_blob(mem, file_size));
    }
    if (hex) {
      dump_hex(mem, file_size);
    }
    if (scan) {
      scan_file(xtract);
    }
    if (decrypt) {
      dec_blob(mem, file_size);
    }
  }
  close_file();
}


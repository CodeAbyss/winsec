
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "md4.h"
#include <windows.h>

PBYTE img=NULL;
ULONGLONG img_base;
HANDLE hFile, hMap;
LPBYTE lpAddress;

#define API_HASH_LEN 8

typedef union _hash_t {
  uint8_t   v8[API_HASH_LEN];
  uint16_t v16[API_HASH_LEN/2];
  uint32_t v32[API_HASH_LEN/4];
} hash_t;

// hash, string and address
typedef struct _api_t {
  char     *api;         // api string
  size_t   len;          // length of api string
  hash_t   hash;         // 32-bit hash
  uint64_t addr;         // address
} api_t;

DWORD cnt=0, min_len=0, max_len=0;
api_t ptrs[5000];

api_t *apis[5000];
uint8_t dgst[MD4_DIGEST_LENGTH];

//char *api_strings[]={"WSAStartup", "WSASocketA", "connect", "send", "recv", "WSACleanup", "bind", "listen", "accept", NULL};
//char *api_strings[]=
//{"CreateFileA", "WriteFile", "ReadFile", "CloseHandle", NULL};

char *api_strings[]={"CryptGenKey", "CryptHashData", "CryptImportKey", "CryptExportKey", "CryptDecrypt", "CryptEncrypt", NULL};
int getStringLen(void)
{
  int i;
  for (i=0; api_strings[i]!=NULL; i++);
  return i;
}

void dump_api (int b[])
{
  int i;
  for (i=0; i<getStringLen(); i++) {
    uint64_t x=apis[b[i]]->adr;
    printf ("\n%016llX : %s", x, apis[b[i]]->api);
    uint64_t t=(uint64_t)GetProcAddress (LoadLibraryA("advapi32.dll"), apis[b[i]]->api);
    printf (" %016llX", t);
  }
}

#define MAX_N (100)
#define MAX_K (100)

void swap_int(int *a, int *b)
{
  int tmp = *a;
  *a = *b;
  *b = tmp;
}

void perm_recursive(api_t *a[], int b[], int j, int k)
{
  int i;
  char *s;
  MD4_CTX ctx;
  uint8_t t[MD4_DIGEST_LENGTH];
  char pwd[512];
  
  if (j >= k) {
    MD4_Init (&ctx);
    memset (pwd, 0, sizeof (pwd));
    for (i = 0; i < getStringLen(); i++) {
      MD4_Update (&ctx, a[b[i]]->api, a[b[i]]->len);
    }
    MD4_Final (t, &ctx);
    if ((memcmp (dgst, t, MD4_DIGEST_LENGTH)==0)) {
      dump_api (b);
      exit (0);
    }
  } else {
    for (i = j; i < k; i++) {
      swap_int(&b[i], &b[j]);
      perm_recursive(a, b, j+1, k);
      swap_int(&b[i], &b[j]);
    }
  }
}

void comb_recursive(api_t *a[], int n, int m, int b[], const int k)
{
  int i, j;
  for (i = n; i >= m; i--) {
    b[m-1] = i-1;
    if (m > 1) {
      comb_recursive(a, i-1, m-1, b, k);
    } else {
      perm_recursive(a, b, 0, k);
    }
  }
}

void set_hash (void)
{
  MD4_CTX ctx;
  int i, slen;
  
  MD4_Init (&ctx);
  for (i=0; api_strings[i]!=NULL; i++) {
    MD4_Update (&ctx, api_strings[i], strlen(api_strings[i]));
  }
  MD4_Final (dgst, &ctx);
}

// start and end characters are the same
// and length is same
int valid_len (char *s) {
  char start, end;
  int i, len1, len2=strlen (s);
  
  start = s[0];
  end   = s[len2-1];
  
  for (i=0; api_strings[i]!=NULL; i++) {
    len1=strlen (api_strings[i]);
    if (start==api_strings[i][0] && 
        end==api_strings[i][len1-1] &&
        len1==len2) {
      return 1;
    }
  }
  return 0;
}

// return pointer to DOS header
IMAGE_DOS_HEADER *GetDosHdr (void) {
  return (IMAGE_DOS_HEADER*)lpAddress;
}

// return pointer to NT header
IMAGE_NT_HEADERS *GetNtHdr (void) {
  return (IMAGE_NT_HEADERS*) (lpAddress + GetDosHdr()->e_lfanew);
}

// return optional header
LPVOID GetOptHdr (void) {
  return (LPVOID)&GetNtHdr()->OptionalHeader;
}

// determines CPU architecture of binary
BOOL is64 (void) {
  return GetNtHdr()->FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64;
}

// return section header
IMAGE_SECTION_HEADER* GetSecHdr(void)
{
  IMAGE_NT_HEADERS *nt=GetNtHdr();
  
  return (IMAGE_SECTION_HEADER*)((LPBYTE)&nt->OptionalHeader + 
      nt->FileHeader.SizeOfOptionalHeader);
}
     
DWORD GetDirSize (void)
{
  IMAGE_OPTIONAL_HEADER32 *x86;
  IMAGE_OPTIONAL_HEADER64 *x64;
  DWORD cnt=0;
  
  if (is64()) {
    x64=(IMAGE_OPTIONAL_HEADER64*)GetOptHdr();
    cnt=x64->NumberOfRvaAndSizes;
  } else {
    x86=(IMAGE_OPTIONAL_HEADER32*)GetOptHdr();
    cnt=x86->NumberOfRvaAndSizes;
  }
  return cnt;
}

ULONGLONG GetImgBase (void)
{
  ULONGLONG base=0;
  
  IMAGE_OPTIONAL_HEADER32 *x86;
  IMAGE_OPTIONAL_HEADER64 *x64;
  
  if (is64()) {
    x64=(IMAGE_OPTIONAL_HEADER64*)GetOptHdr();
    base=x64->ImageBase;
  } else {
    x86=(IMAGE_OPTIONAL_HEADER32*)GetOptHdr();
    base=x86->ImageBase;
  }
  return base;
}

// valid dos header?
int valid_dos_hdr (void) {
  IMAGE_DOS_HEADER *dos=GetDosHdr();
  if (dos->e_magic!=IMAGE_DOS_SIGNATURE) return 0;
  return (dos->e_lfanew != 0);
}

// valid nt headers
int valid_nt_hdr (void) {
  return GetNtHdr()->Signature==IMAGE_NT_SIGNATURE;
}

DWORD GetSecSize (void) {
  return GetNtHdr()->FileHeader.NumberOfSections;
}

DWORD rva2ofs (DWORD rva) {
  int i;
  
  IMAGE_SECTION_HEADER *sec=GetSecHdr();
  
  for (i=0; i<GetSecSize(); i++) {
    if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].SizeOfRawData)
      return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
  }
  return -1;
}

void exports (IMAGE_DATA_DIRECTORY *dir)
{
  DWORD                  ofs=0, idx, len, nbr;
  IMAGE_EXPORT_DIRECTORY *exp;
  DWORD                  *adr;
  DWORD                  *sym;
  WORD                   *ord;
  char                   *s;
  
  if (dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress!=0) 
  {
    ofs=rva2ofs(dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (ofs!=-1) 
    {
      exp=(IMAGE_EXPORT_DIRECTORY*) (ofs + lpAddress);
      
      nbr=exp->NumberOfNames;
      adr=(DWORD*) (rva2ofs(exp->AddressOfFunctions)    + lpAddress);
      sym=(DWORD*) (rva2ofs(exp->AddressOfNames)        + lpAddress);
      ord=(WORD*)  (rva2ofs(exp->AddressOfNameOrdinals) + lpAddress);
      ofs=(DWORD)  (rva2ofs(exp->Name)                  + lpAddress);
       
      if (ofs!=-1) {
        for (idx=0; idx<nbr; idx++) {
          // check length meets criteria
          ofs=rva2ofs ((DWORD)sym[idx]);
          if (ofs!=-1) {
            s=(char*)(ofs + lpAddress);
            len=strlen (s);
            if (valid_len(s)) {
              ptrs[cnt].api=s;
              ptrs[cnt].len=strlen(s);
              ptrs[cnt].adr=(DWORD_PTR)(adr[ord[idx]] + img_base);
              apis[cnt]=&ptrs[cnt];
              cnt++;
            }
          }
        }
      }
    }
  }
}

void dump_img (void)
{
  IMAGE_NT_HEADERS        *nt;
  IMAGE_OPTIONAL_HEADER32 *opt1;
  IMAGE_OPTIONAL_HEADER64 *opt2;
  IMAGE_SECTION_HEADER    *sec;
  int idx2[MAX_K];
  
  if (!valid_dos_hdr()) {
    printf ("  [ invalid dos header\n");
    return;
  }
  if (!valid_nt_hdr()) {
    printf ("  [ invalid nt header\n");
    return;
  }
  
  nt=GetNtHdr();
  
  if (nt->FileHeader.Machine==IMAGE_FILE_MACHINE_I386)
  {
    opt1=(IMAGE_OPTIONAL_HEADER32*)GetOptHdr();
    img_base=opt1->ImageBase;
    exports (opt1->DataDirectory);
    //imports (opt1->DataDirectory);
  } else if (nt->FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64) {
    opt2=(IMAGE_OPTIONAL_HEADER64*)GetOptHdr();
    img_base=opt2->ImageBase;
    exports (opt2->DataDirectory);
    //imports (opt2->DataDirectory);
  } else {
    printf ("\nunknown");
  }
  for (int i=0; i<cnt; i++) printf ("\n%s", apis[i]->api);
  if (cnt!=0) {
    printf ("\nN=%i K=%i\nSearching...", cnt, getStringLen());
    comb_recursive (apis, cnt, cnt, idx2, cnt);
  } else {
    printf ("\nNo API loaded..try different DLL");
  }
}

int open_img (char f[])
{ 
  int r=0;

  hFile=CreateFile (f, GENERIC_READ, FILE_SHARE_READ, NULL, 
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile!=INVALID_HANDLE_VALUE) {
    hMap=CreateFileMapping (hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap!=NULL) {
      lpAddress=(LPBYTE)MapViewOfFile (hMap, FILE_MAP_READ, 0, 0, 0);
      r=1;
    }
  }
  return r;
}

void close_img (void)
{
  if (lpAddress!=NULL) UnmapViewOfFile ((LPCVOID)lpAddress);
  if (hMap     !=NULL) CloseHandle (hMap);
  if (hFile    !=NULL) CloseHandle (hFile);
}

int main (int argc, char *argv[])
{
  int i;
  PVOID OldValue=NULL;
  
  Wow64DisableWow64FsRedirection (&OldValue);
  
  set_hash();

  for (i=1; argv[i]!=NULL; i++) {
    printf ("\nChecking %s", argv[i]);
    if (open_img(argv[i])) {
      dump_img ();
    }
    close_img();
  }
  return 0;
}

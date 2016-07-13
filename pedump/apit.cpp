
/*

we have 40 api strings but we only want to permutate 6 of these.
perform permutations on 6 of the api strings, then shift left or right by 1 the array
through swapping each position.

*/
// Not really suitable for using just yet...
// Odzhan

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "md4.h"
#include <windows.h>

PBYTE img=NULL;
DWORD_PTR img_base;
HANDLE hFile, hMap;
LPBYTE lpAddress;

// hash, string and address
typedef struct _api_t {
  char     *api;           // string
  int      len;
  //DWORD     hapi;          // 32-bit hash
  //DWORD_PTR adr;           // address
} api_t;

DWORD cnt=0, min_len=0, max_len=0;
api_t ptrs[5000];

api_t *apis[5000];
//char *apis[5000];

int uc=0;  // don't include unicode names
uint8_t dgst[MD4_DIGEST_LENGTH];

// what we store is first, last characters and length of api string

/*char *api_strings[]= 
{ "WriteFile", "ReadFile", "CreateFileA", "CreateProcessA", 
  "CreateFileMappingA", "CloseHandle", "FindNextFileA", "FindFirstFileA", NULL
};*/

char *api_strings[]={"WSAStartup", "WSASocketA", "connect", "send", "recv", "WSACleanup", "bind", "listen", "accept", NULL};

uint64_t apis_len=(sizeof(api_strings) / sizeof (char*)) - sizeof (char*);

int getStringLen(void)
{
  int i;
  for (i=0; api_strings[i]!=NULL; i++);
  return i;
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
      //lstrcat (pwd, a[b[i]]->api);
      //lstrcat (pwd, " ");
		}
    //printf ("\n%s", pwd);
    MD4_Final (t, &ctx);
    if ((memcmp (dgst, t, MD4_DIGEST_LENGTH)==0)) {
      printf ("\nFound");
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
			/* for combination only
			for (j = 0; j < k; j++) {
				printf(j < k - 1 ? "%d " : "%d\n", a[b[j]]);
			}
			*/
		}
	}
}

void find_hash (void) {
  uint64_t start, end, pw, idx;
  char pwd[256];
  uint64_t nlen=9, xlen=9;
  MD4_CTX ctx;
  uint64_t x, tbl_len=9;
  uint8_t t[MD4_DIGEST_LENGTH];
  uint64_t total=0;
  int idx2[MAX_K];
  
  comb_recursive (apis, cnt, cnt, idx2, cnt);
  exit (0);
  
  // compute all passwords min -> max
  for (;nlen <= xlen; nlen++) {
    // compute total for this length
    for (end=1, idx=0; idx<nlen; idx++) {
      end *= cnt;
    }
    printf ("\nCreating %llu combinations", end);
    // create all passwords for this length
    for (start=0; start<end; start++) {
      pw = start;
      // create password
      memset (pwd, 0, sizeof (pwd));
      MD4_Init (&ctx);
      // 1,291,467,969
      for (idx=0; idx<nlen; idx++) 
      {
          MD4_Update (&ctx, apis[pw % cnt]->api, apis[pw % cnt]->len);
          lstrcat (pwd, apis[pw % cnt]->api);
          lstrcat (pwd, " ");
          pw /= cnt;
      }
      MD4_Final (t, &ctx);
      if (memcmp (dgst, t, MD4_DIGEST_LENGTH)==0) {
        printf("\nFound after %i attempts", total); //: %s %s %s %s %s %s\n", total, a[0], a[1], a[2], a[3], a[4], a[5]);
        printf ("\n%s", pwd);
        exit (0);
      }
      total++;
      //printf ("\n%s", pwd);
    }
  }
}

void swap (api_t **x, api_t **y)
{
    api_t *temp;
    temp = *x;
    *x = *y;
    *y = temp;
}

int total=0;

void permute (api_t **a, int i, int n, int tbl_len) 
{
   int x, j; 
   MD4_CTX ctx;
   uint8_t t[MD4_DIGEST_LENGTH+1];
   char pwd[512];
   
   if (i == n) {
     memset (pwd, 0, sizeof (pwd));
    MD4_Init (&ctx);
    for (x=0; x<tbl_len; x++) {
      MD4_Update (&ctx, a[x]->api, a[x]->len);
      lstrcat (pwd, a[x]->api);
      lstrcat (pwd, " ");
    }
    //printf ("\n%s", pwd);
    MD4_Final (t, &ctx);
    if (memcmp (dgst, t, MD4_DIGEST_LENGTH)==0) {
      printf("\nFound after %i attempts", total); //: %s %s %s %s %s %s\n", total, a[0], a[1], a[2], a[3], a[4], a[5]);
      printf ("\n%s", pwd);
      exit (0);
    }
   }
   else
   {
        for (j = i; j < n; j++)
       {
          swap((a+i), (a+j));
          permute(a, i+1, n, tbl_len);
          swap((a+i), (a+j)); //backtrack
       }
   }
   total++;
   //printf ("\r%i", total);
} 

int api_tbl_len=0;

void set_len (void)
{
  MD4_CTX ctx;
  int i, slen;
  
  MD4_Init (&ctx);
  for (i=0; api_strings[i]!=NULL; i++) {
    api_tbl_len++;
    MD4_Update (&ctx, api_strings[i], strlen(api_strings[i]));
  }
  MD4_Final (dgst, &ctx);
  
  for (i=0; api_strings[i]!=NULL; i++) {
    slen=strlen (api_strings[i]);
    if (min_len==0) min_len=slen;
    if (max_len==0) max_len=slen;
    min_len = MIN(min_len, slen);
    max_len = MAX(max_len, slen);
  }
}

// within range of api lengths
int valid_len1 (char *s) {
  DWORD len=strlen (s);
  return (len >= min_len && len <= max_len);
}

// is exact length
int valid_len2 (char *s) {
  int i, len;
  for (i=0; api_strings[i]!=NULL; i++) {
    len=strlen(api_strings[i]);
    if (len==strlen (s)) {
      return 1;
    }
  }
  return 0;
}

// first characters are the same
int valid_len3 (char *s) {
  int i, len;
  for (i=0; api_strings[i]!=NULL; i++) {
    if (api_strings[i][0] == s[0]) {
      return 1;
    }
  }
  return 0;
}

// last characters are the same
int valid_len4 (char *s) {
  int i, len1, len2;
  for (i=0; api_strings[i]!=NULL; i++) {
    len1=strlen (s);
    len2=strlen (api_strings[i]);
    if (api_strings[i][len2-1] == s[len1-1]) {
      return 1;
    }
  }
  return 0;
}

int same_len (char *s) {
  char start, end;
  int i, len=strlen (s);
  
  start = s[0];
  end   = s[len-1];
  
  for (i=0; api_strings[i]!=NULL; i++) {
    len=strlen (api_strings[i]);
    if (start==api_strings[i][0] && end==api_strings[i][len-1]) {
      return 1;
    }
  }
  return 0;
}

// exclude unicode
// return s[len-1] == 'W'

// return pointer to DOS header
IMAGE_DOS_HEADER *GetDosHdr(void)
{
  return (IMAGE_DOS_HEADER*)lpAddress;
}

// return pointer to NT header
IMAGE_NT_HEADERS *GetNtHdr(void)
{
  return (IMAGE_NT_HEADERS*) (lpAddress + GetDosHdr()->e_lfanew);
}

// return optional header
LPVOID GetOptHdr(void)
{
  return (LPVOID)&GetNtHdr()->OptionalHeader;
}

// determines CPU architecture of binary
BOOL is64(void)
{
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

ULONGLONG GetImgBase(void)
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
int valid_dos_hdr (void)
{
  IMAGE_DOS_HEADER *dos=GetDosHdr();
  if (dos->e_magic!=IMAGE_DOS_SIGNATURE) return 0;
  return (dos->e_lfanew != 0);
}

// valid nt headers
int valid_nt_hdr (void)
{
  return GetNtHdr()->Signature==IMAGE_NT_SIGNATURE;
}

DWORD GetSecSize(void)
{
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

void imports (IMAGE_DATA_DIRECTORY *dir)
{
  DWORD cnt=0, ofs=0, i, j;
  IMAGE_IMPORT_DESCRIPTOR *imp;
  IMAGE_THUNK_DATA32      *iat32, *f32;
  IMAGE_THUNK_DATA64      *iat64, *f64;
  IMAGE_IMPORT_BY_NAME    *ibn;

  if (dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress!=0) {
    ofs=rva2ofs(dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (ofs!=-1) {
      imp=(IMAGE_IMPORT_DESCRIPTOR *) (lpAddress + ofs);
      for (i=0; ; i++) {
        if (imp[i].Name==0) break;
        ofs=rva2ofs(imp[i].Name);
        if (ofs!=-1) 
        {
          printf ("\n%s", ofs + lpAddress);
          if (imp[i].OriginalFirstThunk!=0) {
            ofs=rva2ofs(imp[i].OriginalFirstThunk);  
          } else {
            ofs=rva2ofs(imp[i].FirstThunk);
          }
          if (ofs!=-1) 
          {
            if (is64()) {
              iat64=(IMAGE_THUNK_DATA64*)(ofs + lpAddress);
              ofs=rva2ofs(imp[i].FirstThunk);
              f64=(IMAGE_THUNK_DATA64*)(ofs + lpAddress);
            } else {
              iat32=(IMAGE_THUNK_DATA32*)(ofs + lpAddress);
              ofs=rva2ofs(imp[i].FirstThunk);
              f32=(IMAGE_THUNK_DATA32*)(ofs + lpAddress);
            }
            
            for (j=0; ; j++) 
            {
              if (is64()) {
                if (iat64[j].u1.AddressOfData == 0) 
                  break;
                ofs=rva2ofs(iat64[j].u1.AddressOfData);
                if (ofs!=-1) {
                  ibn=(IMAGE_IMPORT_BY_NAME*)(ofs + lpAddress);
                  printf ("\n\t%016llX\t%s", f64[j].u1.Function, ibn->Name);
                }
              } else {
                if (iat32[j].u1.AddressOfData == 0) 
                  break;   
                ofs=rva2ofs(iat32[j].u1.AddressOfData);
                if (ofs!=-1) {
                  ibn=(IMAGE_IMPORT_BY_NAME*)(ofs + lpAddress);
                  printf ("\n\t%08X\t%s", f32[j].u1.Function , ibn->Name);
                }
              }
            }
          }
        }
      }
    }
  }
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
            if (valid_len2(s) && same_len(s)) {
              // unicode?
              //apis[cnt].api = s;
              ptrs[cnt].api=s;
              ptrs[cnt].len=strlen(s);
              apis[cnt]=&ptrs[cnt];
              //if (uc==0 && s[len-1] == 'W') continue;
              //apis[cnt].adr = (DWORD_PTR) (adr[ord[idx]] + lpAddress);
              cnt++;
            }
          }
        }
      }
    }
  }
  printf ("\nGot %i api of total %i names for %i", cnt, nbr, api_tbl_len);
  for (idx=0; idx<cnt; idx++) {
    printf ("\n%s", apis[idx]->api);
  }
  
  find_hash();
  
  //permute (apis, 0, cnt, api_tbl_len);
  
  /*find_hash();
  char *tptr[100];
  
  uint64_t pwr=1;
  for (int j=0; j<api_tbl_len; j++) {
    pwr *= cnt;
  }
  for (uint64_t x=0; x<cnt; x++) 
  {
    // copy pointers to local
    for (int j=0; j<api_tbl_len; j++) { 
      tptr[j]=apis[j];
    }
    permute (tptr, 0, api_tbl_len);
    
    // now shift apis by 1
    char *t1=apis[0]; // load a
    char *t2;
    for (int j=1; j<cnt; j++) {
      t2=apis[j];
      apis[j]=t1;
      t1=t2;
    }
    apis[0]=t1;
    
    putchar ('\n');
    for (idx=0; idx<cnt; idx++) {
      printf ("%s  ", apis[idx]);
    }
  }*/
  printf ("\nTotal = %i", total);
}

void dump_img (void)
{
  IMAGE_NT_HEADERS        *nt;
  IMAGE_OPTIONAL_HEADER32 *opt1;
  IMAGE_OPTIONAL_HEADER64 *opt2;
  IMAGE_SECTION_HEADER    *sec;
  
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
    exports (opt1->DataDirectory);
    //imports (opt1->DataDirectory);
  } else if (nt->FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64) {
    opt2=(IMAGE_OPTIONAL_HEADER64*)GetOptHdr();
    exports (opt2->DataDirectory);
    //imports (opt2->DataDirectory);
  } else {
    printf ("\nunknown");
  }
}

int open_img (char f[])
{ 
  int r=0;

  hFile=CreateFile (f, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

/* Following function is needed for library function qsort(). Refer
   http://www.cplusplus.com/reference/clibrary/cstdlib/qsort/ */
int compare (const void *a, const void * b)
{  return ( *(char *)a - *(char *)b ); }

// A utility function two swap two characters a and b
void swap (char* a, char* b)
{
    char t = *a;
    *a = *b;
    *b = t;
}

// This function finds the index of the smallest character
// which is greater than 'first' and is present in str[l..h]
int findCeil (char str[], char first, int l, int h)
{
    // initialize index of ceiling element
    int ceilIndex = l;

    // Now iterate through rest of the elements and find
    // the smallest character greater than 'first'
    for (int i = l+1; i <= h; i++)
      if (str[i] > first && str[i] < str[ceilIndex])
            ceilIndex = i;

    return ceilIndex;
}

// Print all permutations of str in sorted order
void sortedPermutations ( char str[] )
{
    // Get size of string
    int size = strlen(str);

    // Sort the string in increasing order
    qsort( str, size, sizeof( str[0] ), compare );

    // Print permutations one by one
    bool isFinished = false;
    while ( ! isFinished )
    {
        // print this permutation
        printf ("%s \n", str);

        // Find the rightmost character which is smaller than its next
        // character. Let us call it 'first char'
        int i;
        for ( i = size - 2; i >= 0; --i )
           if (str[i] < str[i+1])
              break;

        // If there is no such chracter, all are sorted in decreasing order,
        // means we just printed the last permutation and we are done.
        if ( i == -1 )
            isFinished = true;
        else
        {
            // Find the ceil of 'first char' in right of first character.
            // Ceil of a character is the smallest character greater than it
            int ceilIndex = findCeil( str, str[i], i + 1, size - 1 );

            // Swap first and second characters
            swap( &str[i], &str[ceilIndex] );

            // Sort the string on right of 'first char'
            qsort( str + i + 1, size - i - 1, sizeof(str[0]), compare );
        }
    }
}
#include <string>
using namespace std;

void sucka(char* str, int len, int mask, string temp)
{
	if(mask == 0)
	{
		printf("%s \n", temp.c_str());
		return;
	}

	for(int i=0; i<len; i++)
	{
		if(mask & (1<<i))
		{
			
			sucka( str,len, mask^(1<<i), temp+str[i]);
		}
	}
}

void swap(char *arr, int i, int j) {
     int t = arr[i]; arr[i] = arr[j]; arr[j] = t;
}
void lex_perm(char *arr, int n, int k) {
     if(k==n) {
                  printf("\n%s", arr); return;
     }
     for(int i=k; i<n;i++) {
             swap(arr, i, k);
             lex_perm(arr, n, k+1);
     }
     for(int i=n-1; i>=k;i--) {
             swap(arr, i, k);
     }
}

int main (int argc, char *argv[])
{
  int i;
  
  set_len();

  for (i=1; argv[i]!=NULL; i++) {
    printf ("\nChecking %s", argv[i]);
    if (open_img(argv[i])) {
      dump_img ();
    }
    close_img();
  }
  return 0;
}

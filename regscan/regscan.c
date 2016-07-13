

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <windows.h>

#define RS_OPT_BIN   // binary
#define RS_OPT_SZ    // string
#define RS_OPT_DW    // dword

#pragma comment (lib, "advapi32.lib")

void scan_value (HKEY hKey, char name[]) 
{
  DWORD err, idx, type, name_len, data_len;
  BYTE  reg_data[8192];
  char  sub_name[256], path[MAX_PATH];
  
  idx=0;
  
  do {
    name_len=256;
    data_len=8192;
    
    err = RegEnumValue (hKey, idx, sub_name, &name_len,
        0, &type, reg_data, &data_len);

    if (err == ERROR_SUCCESS && type==REG_BINARY) {
      if (data_len >= MIN_BLOB_SIZE) {
        if (is_dpapi (reg_data, data_len)) {
          sprintf (path, "%s\\%s", name, sub_name);
          printf ("\nFound blob at %s", path);
          dump_blob (reg_data, data_len);
        }
      }
    }
    idx++;
  } while (err != ERROR_NO_MORE_ITEMS);
}

void scan_key (HKEY hKey, char *name)
{
  DWORD err, idx, name_len;
  HKEY hSubKey;
  char sub_name[256], path[512];
  
  idx=0;
  
  do {
    err=RegEnumKey (hKey, idx, sub_name, sizeof(sub_name));
    if (err==ERROR_SUCCESS)
    {
      err=RegOpenKey (hKey, sub_name, &hSubKey);
      if (err==ERROR_SUCCESS)
      {
        sprintf (path, "%s\\%s", name, sub_name);
        scan_value (hSubKey, path);
        scan_key (hSubKey, path);
        RegCloseKey (hSubKey);
      }
    }
    idx++;
  } while (err != ERROR_NO_MORE_ITEMS);
}

typedef struct _reg_t {
  HKEY hKey;
  char *s;
} reg_t;

// scan registry for blobs
void scan_reg (void)
{
  reg_t keys[] = 
  { { HKEY_CURRENT_USER,    "HKCU"}, 
    { HKEY_CURRENT_CONFIG,  "HKCC"},
    { HKEY_CLASSES_ROOT,    "HKCR"},
    { HKEY_LOCAL_MACHINE,   "HKLM"},
    { HKEY_USERS,           "HKU" },
    { HKEY_PERFORMANCE_DATA,"HKPD"}};
    
  int i;
  
  for (i=0; i<sizeof(keys)/sizeof(reg_t); i++) {
    printf ("\nScanning %s...", keys[i].s);
    scan_key (keys[i].hKey, keys[i].s);
  }
}

int main (int argc, char *argv[])
{
  
}

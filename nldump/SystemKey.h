
#ifndef SYSTEM_KEY_H
#define SYSTEM_KEY_H

#define UNICODE

#ifdef DEBUG
#define dprintf printf
#else
#define dprintf
#endif

#include <windows.h>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>

// works similar to sprintf()
// i may revert back to C lib functions later ...
template<class T, class F> T format(F input, int width = 0, int prec = -1) {
  std::wstringstream A;
  T res;
  if (prec != -1) {
    A << std::fixed << std::setprecision(prec);
  }
  A << std::setw(width) << std::setfill(L'0') << input;
  A >> res;
  return res;
}

// works a little like sscanf()
template<class T> T convert(std::ios_base& (*f)(std::ios_base&),
    std::wstring input) {
  std::wstringstream A(input);
  T res;
  A >> f >> res;
  return res;
}

#define SYSTEM_KEY_LEN 16

enum AUTH_TYPE {
  AUTH_DISABLED = 0,
  AUTH_REGISTRY,
  AUTH_PASSWORD,
  AUTH_FILE,
  AUTH_UNKNOWN
};

class SystemKey {
  private:
    BOOL SetFromRegistry(VOID);
    BOOL SetFromFile(std::wstring);
    BOOL SetFromPassword(std::wstring);
    BOOL SetPrivilege(PWCHAR, BOOL);
    DWORD GetSelect(VOID);
    
    BOOL bLoaded, bRestore, bBackup;
    BYTE key[SYSTEM_KEY_LEN];
    DWORD dwError, dwKeyType, dwSelect, dwAuth;
    std::wstring regFile;
  public:
    SystemKey();
    ~SystemKey() {};
    
    DWORD AuthType(VOID);
    BOOL SetKey(std::wstring);  // set from file, password or registry
    DWORD GetKey(PBYTE);        // return key from buffer
    BOOL Load(std::wstring);    // load registry hive to memory
    BOOL UnLoad(VOID);          // unload hive from memory
    
    DWORD GetError(VOID) { return dwError; }
};

#endif
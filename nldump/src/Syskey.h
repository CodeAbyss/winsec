
#ifndef SYSKEY_H
#define SYSKEY_H

#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS

#include "Machine.h"
#include "crypto/md5.h"

enum SYSKEY_TYPE {
  DISABLED = 0,
  REGISTRY,
  PASSWORD,
  FLOPPY
};

class Syskey : public Machine {
  private:
    DWORD GetControlIndex();
    DWORD dwKeyType;
    DWORD dwControlIndex;
  protected:
    unsigned char syskey[16];

    bool GetFromRegistry();
    bool GetFromFile(wchar_t []);
    bool GetFromPassword(wchar_t []);
  public:
    Syskey();
    ~Syskey();

    DWORD GetKeyType();           // determine the parameter required for GetSyskey()
    bool GetSyskey(wchar_t []);   // parameter should be password,file name or NULL for registry
};

#endif

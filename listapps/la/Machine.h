
// Machine.h

#ifndef MACHINE_H
#define MACHINE_H

#ifndef UNICODE
#define UNICODE
#endif

#define _WIN32_WINNT 0x0600

#include <Ws2tcpip.h>
#include <iphlpapi.h>

#include <windows.h>
#include <Sddl.h>

#include <vector>
#include <string>
#include <windows.h>

#include <winsock2.h>
#include <icmpapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <intrin.h>

#include <vector>
#include <string>
#include <sstream>
#include <algorithm>

#include "Products.h"

struct ProductEntry;

#include "Profiles.h"

struct ProfileEntry;

#include "Network.h"

class Network;

enum {HKU=0,HKLM};

class Machine {
  private:
    class Profiles* profiles;
    class Products* products;
    class Network * network;

    std::wstring name;
    HKEY hRegistry[2];
    DWORD dwError;
  public:
    Machine(std::wstring name);
    ~Machine();

    HKEY GetHKLM() { return hRegistry[HKLM]; }
    HKEY GetHKU()  { return hRegistry[HKU ]; }

    const wchar_t* GetName();
    const wchar_t* GetHostName();
    const wchar_t* GetIP();
    const wchar_t* GetPingStatus();
    bool IsOnline();

    std::vector<ProfileEntry> *GetProfiles();
    std::vector<ProductEntry> *GetProducts();
    
    bool connect();
    DWORD GetError() { return dwError; }
    void SetError(DWORD dwError) { this->dwError = dwError; }
};

#endif
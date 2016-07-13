
#ifndef NETWORK_H
#define NETWORK_H

#ifndef UNICODE
#define UNICODE
#endif

#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <iphlpapi.h>
#include <Ws2tcpip.h>

#include <windows.h>
#include <icmpapi.h>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

class Network {
  private:
    IPAddr ip_addr;
    struct addrinfoW *aiList;
    
    DWORD dwStatus;
    
    BOOL flushdns();
    
    std::wstring hostname;
    std::wstring fqdn;
    std::wstring ip_address;
    
    bool resolve();
  public:
    Network(std::wstring host);
    ~Network();
    
    const wchar_t* name();
    const wchar_t* ip();
    const wchar_t* status();
    
    bool ping();
    
    bool bOnline;
    bool bReply;
};

#endif
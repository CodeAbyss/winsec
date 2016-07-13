
// Odzhan

#ifndef PING_H
#define PING_H

#ifndef UNICODE
#define UNICODE
#endif

#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <shlwapi.h>

#include <windows.h>
#include <icmpapi.h>

typedef struct _ICMP_REPLY {
  DWORD dwCode;
  wchar_t Message[256];
  wchar_t Dns[255];
  wchar_t Ip[255];
  struct _ICMP_REPLY *next;
} ICMP_REPLY, *PICMP_REPLY;

class Ping {
  private:
    BOOL FlushDnsCache ();
    PICMP_REPLY rlist, current;
    void Add (PICMP_REPLY);
    void Clear (void);
  public:
    Ping() { rlist=NULL; }
    ~Ping();
    
    BOOL Send (wchar_t address[]);
    BOOL Send (wchar_t address[], DWORD timeout);
    
    PICMP_REPLY GetReplies ();
};

#endif

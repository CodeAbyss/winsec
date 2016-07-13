
// Odzhan

#include "ping.h"

#include <stdio.h>

int wmain(int argc, wchar_t *argv[])
{
  WSADATA     wsa;
  PICMP_REPLY e;  
  class Ping  *ping;
  
  WSAStartup (MAKEWORD(2,0), &wsa);
  
  if (argc != 2) {
    wprintf(L"\n  pingtest <host or ip address>\n");
    return 0;
  }
  
  ping = new Ping();
  
  wprintf(L"\nPinging %s . . .", argv[1]);
  if (ping->Send(argv[1])) {
    for (e=ping->GetReplies(); e!=NULL; e=e->next)
    {
      wprintf(L"\n  Reply from %s [%s]", e->Dns, e->Ip);
    }
  } else {
    wprintf(L"\n  Unable to resolve %s", argv[1]);
  }
  delete ping;
  WSACleanup();
  return 0;
}

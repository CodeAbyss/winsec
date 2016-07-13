
// Ping class
// Odzhan

#include "ping.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

// icmp status messages
typedef struct _STATUS_MSG {
  DWORD dwCode;
  const wchar_t *pMessage;
} STATUS_MSG, *PSTATUS_MSG;

STATUS_MSG pStatus[] = 
{ 
  { IP_SUCCESS,               L"The status was success" }, 
  { IP_BUF_TOO_SMALL,         L"The reply buffer was too small" },
  { IP_DEST_NET_UNREACHABLE,  L"The destination network was unreachable" },
  { IP_DEST_HOST_UNREACHABLE, L"The destination host was unreachable" },
  { IP_DEST_PROT_UNREACHABLE, L"The destination protocol was unreachable" },
  { IP_DEST_PORT_UNREACHABLE, L"The destination port was unreachable" },
  { IP_NO_RESOURCES,          L"Insufficient IP resources were available" },
  { IP_BAD_OPTION,            L"A bad IP option was specified" },
  { IP_HW_ERROR,              L"A hardware error occurred" },
  { IP_PACKET_TOO_BIG,        L"The packet was too big" },
  { IP_REQ_TIMED_OUT,         L"The request timed out" },
  { IP_BAD_REQ,               L"A bad request" },
  { IP_BAD_ROUTE,             L"A bad route" },
  { IP_TTL_EXPIRED_TRANSIT,   L"The time to live (TTL) expired in transit" },
  { IP_TTL_EXPIRED_REASSEM,   L"The time to live expired during fragment reassembly" },
  { IP_PARAM_PROBLEM,         L"A parameter problem" },
  { IP_SOURCE_QUENCH,         L"Datagrams are arriving too fast to be processed and datagrams may have been discarded" },
  { IP_OPTION_TOO_BIG,        L"An IP option was too big" },
  { IP_BAD_DESTINATION,       L"A bad destination" },
  { IP_GENERAL_FAILURE,       L"A general failure. This error can be returned for some malformed ICMP packets" }
};

Ping::~Ping()
{
  Clear();
}

PICMP_REPLY Ping::GetReplies() {
  return rlist;
}

void Ping::Add (PICMP_REPLY r)
{
  PICMP_REPLY t=new ICMP_REPLY;
  
  StrCpy (t->Message, r->Message);
  StrCpy (t->Dns, r->Dns);
  StrCpy (t->Ip, r->Ip);
  t->next=NULL;
  
  if (rlist==NULL) {
    rlist=t;
    current=t;
  } else {
    current->next=t;
    current=t;
  }
}

// delete entries
void Ping::Clear (void)
{
  PICMP_REPLY r;
  while (rlist!=NULL)
  {
    r=rlist->next;
    delete rlist;
    rlist=r;
  }
}

/**
 *
 * Uses undocumented API from DNSAPI.DLL
 *
 * Same as : ipconfig /flushdns
 *
 */
BOOL Ping::FlushDnsCache (VOID) {
  BOOL bResult = FALSE;

  BOOL (WINAPI *Flush) ();
  HMODULE hDNS = LoadLibrary (L"dnsapi");

  if (hDNS != NULL) {
    *(FARPROC *)&Flush = GetProcAddress (hDNS, "DnsFlushResolverCache");
    
    if (Flush != NULL) {
      bResult = Flush ();
    }
    FreeLibrary (hDNS);
  }
  return bResult;
}

// ping with 1500 ms timeout
BOOL Ping::Send (wchar_t address[]) {
  return Send (address, 1500);
}

BOOL Ping::Send (wchar_t address[], DWORD timeout)
{
  ADDRINFOW        hints;
  PADDRINFOW       e, list = NULL;
  ICMP_REPLY       r;
  wchar_t          host[NI_MAXHOST], serv[NI_MAXSERV], ip[32];
  DWORD            res, size, idx;
  HANDLE           hIcmpFile;
  PICMP_ECHO_REPLY pReply;
  IPAddr           ip_addr;
  wchar_t          SendData[4];
  LPVOID           ReplyBuffer[sizeof(ICMP_ECHO_REPLY) + sizeof(SendData) * 2];
          
  // clear any previous entries
  Clear();
  
  if (FlushDnsCache ()) 
  {
    ZeroMemory (&hints, sizeof (hints));

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    // resolve all available addresses
    if (GetAddrInfo (address, NULL, &hints, &list) == NO_ERROR) 
    {    
      // loop through each entry
      for (e=list; e!=NULL; e=e->ai_next) 
      {  
        // resolve name if available
        res = GetNameInfo (e->ai_addr, sizeof (SOCKADDR), host,
            NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICSERV);
        
        StrCpy (r.Dns, (res == NO_ERROR) ? host : L"unresolved");
        size = sizeof (ip);
          
        // convert ip address to string
        res = WSAAddressToString (e->ai_addr, (DWORD)e->ai_addrlen, NULL, ip, &size);
        
        StrCpy (r.Ip, (res == NO_ERROR) ? ip : L"0.0.0.0");
            
        // see if responding to ping
        HANDLE hIcmpFile = IcmpCreateFile ();
  
        if (hIcmpFile != INVALID_HANDLE_VALUE) {
          size = sizeof(ReplyBuffer);
    
          ip_addr = *((IPAddr*)(&list->ai_addr->sa_data[2]));
          ((DWORD*)&SendData)[0] = ntons(PNS_MAGIC);
          IcmpSendEcho (hIcmpFile, ip_addr, SendData, 
              sizeof (SendData), NULL, ReplyBuffer, size, timeout);
          
          IcmpCloseHandle (hIcmpFile);
              
          pReply = (PICMP_ECHO_REPLY)ReplyBuffer;
          
          r.dwCode = pReply->Status;
          StrCpy (r.Message, L"Check status code");
          
          for (idx=0; idx<sizeof(pStatus)/sizeof(STATUS_MSG); idx++) 
          {
            if (r.dwCode == pStatus[idx].dwCode) 
            {
              StrCpy (r.Message, pStatus[idx].pMessage);
            }
          }
          Add (&r);
         }
      }
      FreeAddrInfo (list);
    }
  }
  return rlist != NULL;
}

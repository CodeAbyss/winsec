/**
  Copyright (C) 2016 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
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

// create an ICMP handle for ipv4 or ipv6
HANDLE Ping::IcmpCreate(int family) 
{
  if (family==AF_INET) {
    return IcmpCreateFile();
  } else {
    return Icmp6CreateFile();
  }
}

int Ping::SendEcho(ICMP_REPLY *r, PADDRINFOW addr, int timeout)
{
  wchar_t             req_data[4];
  PICMP_ECHO_REPLY    pReply4;
  PICMPV6_ECHO_REPLY  pReply6;
  LPVOID              reply[sizeof(ICMPV6_ECHO_REPLY) + sizeof(req_data) * 2];
  HANDLE              hIcmpFile;
  struct sockaddr_in  v4;
  struct sockaddr_in6 v6, sa;  
  DWORD               reply_size, idx;
  
  reply_size = sizeof(reply);
  
  // create icmp file handle
  hIcmpFile = IcmpCreate(addr->ai_family);
  
  if (hIcmpFile==NULL) return 0;
  
  if (addr->ai_family==AF_INET)
  {
    // send ipv4
    memcpy (&v4, addr->ai_addr, addr->ai_addrlen);
    
    IcmpSendEcho (hIcmpFile,
      (IPAddr)v4.sin_addr.S_un.S_addr, req_data, 
      sizeof(req_data), NULL, 
      reply, reply_size, timeout);
      
      pReply4 = (PICMP_ECHO_REPLY)reply;
      r->dwCode = pReply4->Status;
  } else {
    // send ipv6
    memcpy(&v6, addr->ai_addr, addr->ai_addrlen);
    
    sa.sin6_addr     = in6addr_any;
    sa.sin6_family   = AF_INET6;
    sa.sin6_flowinfo = 0;
    sa.sin6_port     = 0;
    
    Icmp6SendEcho2 (hIcmpFile, NULL, NULL, NULL, 
      &sa, &v6, req_data, sizeof(req_data),
      NULL, reply, reply_size, timeout);
          
    pReply6 = (PICMPV6_ECHO_REPLY)reply; 
    r->dwCode = pReply6->Status;    
  }
 
  StrCpy (r->Message, L"Check status code");

  for (idx=0; idx<sizeof(pStatus)/sizeof(STATUS_MSG); idx++) 
  {
    if (r->dwCode == pStatus[idx].dwCode) 
    {
      StrCpy (r->Message, pStatus[idx].pMessage);
    }
  }
  IcmpCloseHandle (hIcmpFile);
  return 1;  
}
  
// ping with 1500 ms timeout
BOOL Ping::Send (wchar_t address[], int family) {
  return Send (address, family, 1500);
}

BOOL Ping::Send (wchar_t address[], int family, DWORD timeout)
{
  ADDRINFOW  hints;
  PADDRINFOW e, list = NULL;
  ICMP_REPLY r;
  wchar_t    host[NI_MAXHOST], serv[NI_MAXSERV], ip[INET6_ADDRSTRLEN];
  DWORD      res, size, idx;
    
  // clear any previous entries
  Clear();
  
  if (FlushDnsCache ()) 
  {
    ZeroMemory (&hints, sizeof (hints));

    hints.ai_family   = family;
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
        
        // copy name to structure
        StrCpy (r.Dns, (res == NO_ERROR) ? host : L"unresolved");
        
        // convert ip address to string
        size = sizeof (ip);
        
        res = WSAAddressToString (e->ai_addr, 
            (DWORD)e->ai_addrlen, NULL, ip, &size);
        
        StrCpy (r.Ip, 
          (res == NO_ERROR) ? ip : family==AF_INET ? L"0.0.0.0" : L"::");
          
        if (SendEcho(&r, e, timeout)) {
          Add (&r);        
        }
      }
      FreeAddrInfo (list);
    } else {
      printf ("\n%i", GetLastError());
    }
  }
  return rlist != NULL;
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

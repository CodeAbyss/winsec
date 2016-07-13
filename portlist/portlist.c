/**
  Copyright (C) 2016 Odzhan.
  
  All Rights Reserved.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

typedef struct _connection_t {
  struct sockaddr *laddr; // sockaddr_in or sockaddr_in6
  struct sockaddr *raddr; // sockaddr_in or sockaddr_in6
  socklen_t       salen;
  int             state;
  int             pid;
  wchar_t         host[NI_MAXHOST];
  wchar_t         serv[NI_MAXSERV];
} connection_t;

typedef struct _module_t {
  wchar_t *pModuleName;
  wchar_t *pModulePath;
  
  wchar_t name[MAX_PATH+1];
  wchar_t path[MAX_PATH+1];
} module_t, *pmodule_t;

typedef struct _state_t {
  DWORD state;
  char *str;
} state_t;

state_t state_tbl[] =
{ { MIB_TCP_STATE_CLOSED,    "CLOSED"      },
  { MIB_TCP_STATE_LISTEN,    "LISTEN"      },
  { MIB_TCP_STATE_SYN_SENT,  "SYN_SENT"    },
  { MIB_TCP_STATE_SYN_RCVD,  "SYN_RCVD"    },
  { MIB_TCP_STATE_ESTAB,     "ESTABLISHED" },
  { MIB_TCP_STATE_FIN_WAIT1, "FIN_WAIT1"   },
  { MIB_TCP_STATE_FIN_WAIT2, "FIN_WAIT2"   },
  { MIB_TCP_STATE_CLOSE_WAIT,"CLOSE_WAIT"  },
  { MIB_TCP_STATE_CLOSING,   "CLOSING"     },
  { MIB_TCP_STATE_LAST_ACK,  "LAST_ACK"    },
  { MIB_TCP_STATE_TIME_WAIT, "TIME_WAIT"   },
  { MIB_TCP_STATE_DELETE_TCB,"DELETE_TCB"  } };

PMIB_TCPTABLE_OWNER_MODULE pxTcpTbl=NULL;
PMIB_TCP6TABLE_OWNER_MODULE pxTcp6Tbl=NULL;

void* xalloc (size_t x) {
  return HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, x);
}

void* xrealloc (void *x, size_t n) {
  return HeapReAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, x, n);
}

void xfree (void *x) {
  HeapFree (GetProcessHeap(), 0, x);
}

// return TCP tables
// AF_INET - v4
// AF_INET6 - v6
void* get_tbl (int family, int type)
{
  DWORD n=0, err;
  void *t=NULL;
  
  do {
    // ipv4?
    if (family==AF_INET) {
      // tcp?
      if (type==SOCK_STREAM) {
        err=GetTcpTable ((PMIB_TCPTABLE)t, &n, TRUE);
      // get udp instead
      } else if (type==SOCK_DGRAM) {
        err=GetUdpTable ((PMIB_UDPTABLE)t, &n, TRUE);
      }
    }    
    else if (family==AF_INET6) {
      if (type==SOCK_STREAM) {
        err=GetTcp6Table ((PMIB_TCP6TABLE)t, &n, TRUE);
      } else if (type==SOCK_DGRAM) {
        err=GetUdp6Table ((PMIB_UDP6TABLE)t, &n, TRUE);
      }
    }
    if (err==ERROR_INSUFFICIENT_BUFFER) {
      if (t==NULL) {
        t=xalloc (n);
      } else {
        t=xrealloc (t, n + 256);
      }
    }
  } while (err!=NO_ERROR);
  return t;
}

// convert address to string
char *addr2ip (void *addr, DWORD addrlen, void *str, int len)
{
    DWORD rlen=len;
    
    lstrcpy (str, "unresolved\0");
    WSAAddressToString (addr, addrlen, NULL, str, &rlen);
    return str;
}

// resolve hostname of network address
char *addr2name (void *addr, DWORD addrlen, void *str, int len)
{
    char serv[NI_MAXSERV];
    ZeroMemory (str, len);
    ZeroMemory (serv, NI_MAXSERV);
    
    lstrcpy (str, "unresolved\0");
    GetNameInfo (addr, addrlen, str, len, serv, NI_MAXSERV, 0);
    lstrcat (str, ":");
    lstrcat (str, serv);
    return str;
}

// get the state of connection
char *state2str (MIB_TCP_STATE state, char *str)
{
    int i;
    
    lstrcpy (str, "unknown\0");
    
    for (i=0; i<sizeof (state_tbl)/sizeof (state_t); i++) {
      if (state_tbl[i].state==state) {
        lstrcpy (str, state_tbl[i].str);
        str[ strlen (str)] = 0;
        break;
      }
    }
    return str;
}

// return TCP tables
// AF_INET - v4
// AF_INET6 - v6
void* get_xtbl (int family, int type)
{
    DWORD n=0, err;
    void *tbl=NULL;
    
    do {
      // tcp?
      if ((family==AF_INET || 
         family==AF_INET6) && type==SOCK_STREAM) 
      {
        err=GetExtendedTcpTable (tbl, &n, TRUE, 
          family, TCP_TABLE_OWNER_MODULE_ALL, 0);
      // else udp
      } else {
        err=GetExtendedUdpTable (tbl, &n, TRUE, 
          family, TCP_TABLE_OWNER_MODULE_ALL, 0);
      }
      // expand buffer in 256 byte blocks until we have full table
      if (err==ERROR_INSUFFICIENT_BUFFER) {
        if (tbl==NULL) {
          tbl=xalloc (n);
        } else {
          tbl=xrealloc (tbl, n + 256);
        }
      }
    } while (err!=NO_ERROR);
    return tbl;
}

/**
 *
 *  get module name for connection
 *
 */
DWORD get_module (void *mod, pmodule_t mib, int family, int type) 
{
    DWORD err, n=MAX_PATH+MAX_PATH;
    
    // tcp v4?
    if (family==AF_INET && type==SOCK_STREAM) {
      
      err=GetOwnerModuleFromTcpEntry ((PMIB_TCPROW_OWNER_MODULE)mod, 
        TCPIP_OWNER_MODULE_INFO_BASIC, mib, &n);
        
    } else
    // tcp v6?
    if (family==AF_INET6 && type==SOCK_STREAM) {
      
      err=GetOwnerModuleFromTcp6Entry ((PMIB_TCP6ROW_OWNER_MODULE)mod, 
        TCPIP_OWNER_MODULE_INFO_BASIC, mib, &n);
        
    } else 
    // udp v4?
    if (family==AF_INET && type==SOCK_DGRAM) {
      
      err=GetOwnerModuleFromUdpEntry ((PMIB_UDPROW_OWNER_MODULE)mod, 
        TCPIP_OWNER_MODULE_INFO_BASIC, mib, &n);
        
    } else {
    // udp v6
      err=GetOwnerModuleFromUdp6Entry ((PMIB_UDP6ROW_OWNER_MODULE)mod, 
        TCPIP_OWNER_MODULE_INFO_BASIC, mib, &n);
        
    }
    return err;
}

/**
 *
 *  convert process id to process name
 *
 */
DWORD pid2name (DWORD pid, module_t *mod) 
{
  PROCESSENTRY32W pe32;
  HANDLE          snap;
  BOOL            rs;
  DWORD           err=-1;
  
  snap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
  
  if (snap != INVALID_HANDLE_VALUE) {
    pe32.dwSize = sizeof (pe32);
    
    rs = Process32FirstW (snap, &pe32);

    while (rs) {
      if (pe32.th32ProcessID==pid) {
        lstrcpyW (mod->name, pe32.szExeFile);
        err=NO_ERROR;
        break;
      }
      rs = Process32NextW (snap, &pe32);
    }
    CloseHandle (snap);
  }
  return err;
}

void process_entries(int family, int type)
{
    if (family==AF_INET)
    {
      // convert local ip address to string
      sin.sin_family      = AF_INET;
      sin.sin_port        = pxTcpTbl->table[i].dwLocalPort;
    
      memcpy (&sin.sin_addr, 
        &pxTcpTbl->table[i].dwLocalAddr, 
        sizeof (struct in_addr));
    } else {
      // convert local ip address to string
      sin6.sin6_family      = AF_INET6;
      sin6.sin6_port        = pxTcp6Tbl->table[i].dwLocalPort;
      
      memcpy (&sin6.sin6_addr, &pxTcp6Tbl->table[i].ucLocalAddr, 16);
        
      addr2ip (&sin6, sizeof(sin6), local, sizeof (local));
      //addr2name (&sin, sizeof(sin), local, sizeof (local));

      // convert remote ip address to string
      sin6.sin6_port        = pxTcp6Tbl->table[i].dwRemotePort;
      
      memcpy (&sin6.sin6_addr, &pxTcp6Tbl->table[i].ucRemoteAddr, 16);
    }
    
    addr2ip (&sin, sizeof(sin), local, sizeof (local));
    //addr2name (&sin, sizeof(sin), local, sizeof (local));

    // convert remote ip address to string
    sin.sin_port        = pxTcpTbl->table[i].dwRemotePort;
    
    memcpy (&sin.sin_addr, 
      &pxTcpTbl->table[i].dwRemoteAddr, 
      sizeof (struct in_addr));
      
    addr2ip (&sin, sizeof (sin), remote, sizeof(remote));
    addr2name (&sin, sizeof (sin), host, sizeof(host));
    
    err=get_module (&pxTcpTbl->table[i], &mib, AF_INET, SOCK_STREAM);
    
    if (err!=NO_ERROR)
    {
      // try from process32first
      err=pid2name (pxTcpTbl->table[i].dwOwningPid, &mib);
    }
}
// show tables
void show_xtbl (void *tbl, int family, int type)
{
    DWORD i, plen=10, llen=36, rlen=64, slen=15, err, size; 
    DWORD raddr, rport, laddr, lport;
    module_t mib;
    char   local[64], remote[64], state[64], host[NI_MAXSERV];
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr *ai_addr;
    int    ai_addrlen;
    
    ZeroMemory (&sin, sizeof (sin));
    ZeroMemory (&sin6, sizeof (sin6));
    
    mib.pModuleName=mib.name;
    mib.pModulePath=mib.path;
    
    printf ("  %-*s %-*s %-*s %-*s\n", 
      plen, "Proto", 
      llen, "Local Address",
      rlen, "Remote Address",
      slen, "State");
    
    // print TCP v4 table  
    for (i=0; i<pxTcpTbl->dwNumEntries; i++) {

      printf ("  %-16ws ", 
        err==NO_ERROR ? mib.pModuleName : L"<unknown>");
        
      printf (" %10i %-*s %-*s %-*s %-*s %s\n", 
        pxTcpTbl->table[i].dwOwningPid,
        plen, "TCP", 
        llen, local, 
        rlen, remote,
        slen, state2str(pxTcpTbl->table[i].dwState, state),
        host);
    }
}

void show_xtbl6 (void)
{
    DWORD i, plen=10, llen=36, rlen=64, slen=15, err, size; 
    DWORD raddr, rport, laddr, lport;
    module_t mib;
    char local[64], remote[64], state[64];
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    
    ZeroMemory (&sin, sizeof (sin));
    ZeroMemory (&sin6, sizeof (sin6));
    
    mib.pModuleName=mib.name;
    mib.pModulePath=mib.path;
    
    // print TCP v4 table  
    for (i=0; i<pxTcp6Tbl->dwNumEntries; i++) {
      // convert local ip address to string
      sin6.sin6_family      = AF_INET6;
      sin6.sin6_port        = pxTcp6Tbl->table[i].dwLocalPort;
      
      memcpy (&sin6.sin6_addr, &pxTcp6Tbl->table[i].ucLocalAddr, 16);
        
      addr2ip (&sin6, sizeof(sin6), local, sizeof (local));
      //addr2name (&sin, sizeof(sin), local, sizeof (local));

      // convert remote ip address to string
      sin6.sin6_port        = pxTcp6Tbl->table[i].dwRemotePort;
      
      memcpy (&sin6.sin6_addr, &pxTcp6Tbl->table[i].ucRemoteAddr, 16);
        
      addr2ip (&sin6, sizeof (sin6), remote, sizeof(remote));
      //addr2name (&sin, sizeof (sin), remote, sizeof(remote));
      
      printf ("  %-*s %-*s %-*s %-*s ", 
        plen, "TCP", llen, local, rlen, remote,
        slen, state2str(pxTcp6Tbl->table[i].dwState, state));
        
      err=get_module (&pxTcp6Tbl->table[i], &mib, AF_INET6, SOCK_STREAM);
        
      if (err!=NO_ERROR)
      {
        // try from process32first
        err=pid2name (pxTcpTbl->table[i].dwOwningPid, &mib);
      }
      printf ("%ws:%i\n", 
        err==NO_ERROR ? mib.pModuleName : L"<unknown>", 
        pxTcp6Tbl->table[i].dwOwningPid);
    }
}

void tcp_open (void)
{
    WSADATA wsa;
    WSAStartup (MAKEWORD(2, 0), &wsa);
}

void tcp_close (void)
{
    WSACleanup();
}

VOID setw(SHORT X) 
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE                     out;
    
    out=GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(out, &csbi);
    
    if (X <= csbi.dwSize.X) return;
    csbi.dwSize.X  = X;
    SetConsoleScreenBufferSize(out, csbi.dwSize);  
}

int main (void)
{
    setw(300);
    
    tcp_open();
    
    // tcp v4 and v6
    pxTcpTbl  = get_xtbl (AF_INET, SOCK_STREAM);
    pxTcp6Tbl = get_xtbl (AF_INET6, SOCK_STREAM);
    
    if (pxTcpTbl !=NULL) {
      show_xtbl(pxTcpTbl, AF_INET, SOCK_STREAM);
    }
    if (pxTcp6Tbl!=NULL) {
      show_xtbl(pxTcp6Tbl, AF_INET6, SOCK_STREAM);
    }
    
    tcp_close();
    
    return 0;
}

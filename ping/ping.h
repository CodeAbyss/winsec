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

#include <stdio.h>

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
    int SendEcho(ICMP_REPLY*, PADDRINFOW, int);
    HANDLE IcmpCreate(int);
  public:
    Ping() { rlist=NULL; }
    ~Ping();
    
    BOOL Send (wchar_t address[], int);
    BOOL Send (wchar_t address[], int, DWORD timeout);
    
    PICMP_REPLY GetReplies (void);
};

#endif

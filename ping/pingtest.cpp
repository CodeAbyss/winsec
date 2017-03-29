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

#pragma comment(lib, "shell32.lib")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
  WSADATA     wsa;
  PICMP_REPLY e;  
  class Ping  *ping;
  int         argc, i, family=AF_INET;
  wchar_t     opt;
  wchar_t     *host=NULL;
  wchar_t     **argv;  
  
  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  
  WSAStartup (MAKEWORD(2,0), &wsa);
  
  for (i=1; i<argc; i++)
  {
    if (argv[i][0]==L'/' || argv[i][0]==L'-')
    {
      opt=argv[i][1];
      if (opt==L'4') { 
        family=AF_INET;
      } else if (opt==L'6') { 
        family=AF_INET6; }
      else { 
        printf ("\n  [ invalid option"); 
        exit(0); 
      }
    } else {
      host=argv[i];
    }
  }

  // no host?
  if (host==NULL) {
    printf ("\n  [ no host specified");
    return 0;
  }
  
  ping = new Ping();
  
  wprintf(L"\nPinging %s . . .", host);
  
  if (ping->Send(host, family)) {
    for (e=ping->GetReplies(); e!=NULL; e=e->next)
    {
      wprintf(L"\n  Reply from %s [%s]", e->Dns, e->Ip);
    }
  } else {
    wprintf(L"\n  Unable to resolve %s", host);
  }
  delete ping;
  WSACleanup();
  return 0;
}

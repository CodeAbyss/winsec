
/**
 *
 *  hash dump class
 */
#include "Machine.h"

#define EXT_MODE
#define DEBUG

wchar_t *lpszLocalNames[4]={L"SAM",L"SYSTEM",L"SECURITY",L"SOFTWARE"};
wchar_t *lpszExtNames[4]={L"$$_SAM_$$",L"$$_SYSTEM_$$",L"$$_SECURITY_$$",L"$$_SOFTWARE_$$"};

Machine::Machine()
{
  szMachine  = NULL;                  // initially NULL until Connect() method is called
  hRegistry  = HKEY_LOCAL_MACHINE;    // default is local, use RegConnectRegistry() for remote

  bDebug       = false;               // debug mode, print more output to console
  bRemote      = false;               // dump from remote machine

  for (int i(0);i < 4;i++)
    lpszHiveNames[i] = lpszLocalNames[i];

  GetSystemInfo();                    // get local o/s info

  HANDLE hProcess;
  OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hProcess);
  EnablePrivilege(hProcess,L"SeBackupPrivilege", true);  // required to open keys protected by DACL
#ifdef EXT_MODE
  EnablePrivilege(hProcess,L"SeRestorePrivilege",true);  // required to load external hives
#endif

}

Machine::~Machine()
{

}

DWORD Machine::GetErrorCode()
{
  return dwError;
}

// undefined in MINGW
#define SE_PRIVILEGE_REMOVED            (0X00000004L)

/**
 *
 * enable/disable a special privilege in a token
 * return true for success, else false
 *
 */
bool Machine::EnablePrivilege(HANDLE hToken, const wchar_t szPrivilege[], bool bFlag)
{
  LUID luid;
  TOKEN_PRIVILEGES priv;
  bool bStatus = FALSE;

  // depending on szMachine, this is enabled locally or remotely

  if(!LookupPrivilegeValueW(szMachine,szPrivilege,&luid))
  {
    dwError = GetLastError();
    return false;
  }

  priv.PrivilegeCount           = 1;
  priv.Privileges[0].Luid       = luid;
  priv.Privileges[0].Attributes = (bFlag) ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

  AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
  dwError = GetLastError();

  return (dwError == ERROR_SUCCESS);
}

#define LOGON32_LOGON_NEW_CREDENTIALS   9
#define LOGON32_PROVIDER_WINNT50        3

/**
 *
 *  this is here now incase it's required in future..at the moment it isn't used
 *
 */
bool Machine::NBConnect(wchar_t machine[], wchar_t username[], wchar_t password[])
{
  NETRESOURCEW nr;
  wchar_t disk[MAX_PATH];

  szMachine = machine;
  ZeroMemory(&nr,sizeof(NETRESOURCE));

  wsprintfW(disk,L"\\\\%s\\ADMIN$",szMachine);

  nr.lpRemoteName = disk;
  nr.dwType       = RESOURCETYPE_DISK;

  return (WNetAddConnection2W(&nr,password,username,CONNECT_TEMPORARY) == NO_ERROR);
}

/**
 *
 *  establish a connection to remote machine through ADMIN$ share
 *  then open handle to registry
 *
 */
bool Machine::CreateToken(wchar_t machine[], wchar_t domain[], wchar_t username[], wchar_t password[])
{
  // assign remote machine name locally
  szMachine = machine;
  
  // create user logon token for remote machine
  if (LogonUserW(username,domain,password,LOGON32_LOGON_NEW_CREDENTIALS,LOGON32_PROVIDER_WINNT50,&hRemoteToken))
  {
    // now impersonate that user
    if (!ImpersonateLoggedOnUser(hRemoteToken))
    {
      CloseHandle(hRemoteToken);
    }
  }

  dwError = GetLastError();

  return (dwError == ERROR_SUCCESS);
}

/**
 *
 *  open service manager of remote machine
 *
 */
bool Machine::OpenServices()
{
  hSCManager = OpenSCManagerW(szMachine,NULL,SC_MANAGER_ALL_ACCESS);
  return (hSCManager != NULL);
}

/**
 *
 *  close service manager of remote machine
 *
 */
void Machine::CloseServices()
{
  CloseServiceHandle(hSCManager);
}

DWORD Machine::GetRegistryState()
{
  SC_HANDLE hService;
  DWORD dwState;

  hService = OpenServiceW(hSCManager,L"RemoteRegistry",SERVICE_ALL_ACCESS);

  if (hService != NULL)
  {
    DWORD dwSize;
    QueryServiceStatusEx(hService,SC_STATUS_PROCESS_INFO,NULL,0,&dwSize);
    dwError = GetLastError();

    if (dwError == ERROR_INSUFFICIENT_BUFFER)
    {
      PBYTE pStatus = new BYTE[dwSize+32];
      if (pStatus != NULL)
      {
        if ((QueryServiceStatusEx(hService,SC_STATUS_PROCESS_INFO,pStatus,dwSize+32,&dwSize)) != 0)
        {
          dwState = reinterpret_cast<LPSERVICE_STATUS_PROCESS>(pStatus)->dwCurrentState;
          dwError = ERROR_SUCCESS;
        }
        delete []pStatus;
      } else dwError = ERROR_NOT_ENOUGH_MEMORY;
    }
    CloseServiceHandle(hService);
  }
  return dwState;
}
/**
 *
 *  check if remote registry running
 *
 */
bool Machine::IsRegServiceRunning()
{
  return (GetRegistryState() == SERVICE_RUNNING);
}

/**
 *
 *  check if remote registry running
 *
 */
bool Machine::StartRegService()
{
  SC_HANDLE hService;

  hService = OpenServiceW(hSCManager,L"RemoteRegistry",SERVICE_ALL_ACCESS);
  dwError = GetLastError();

  if (hService != NULL)
  {
    StartServiceW(hService,0,NULL);
    dwError = GetLastError();
    CloseServiceHandle(hService);
  }
  return dwError == ERROR_SUCCESS;
}

/**
 *
 *  try enable remote registry..ugly code that stops working after 3 attempts
 *
 */
bool Machine::EnableRemoteRegistry()
{
  bool bEnabled = false;
  DWORD nAttempts = 0;

  if (OpenServices())
  {
    do {
      bEnabled = IsRegServiceRunning(); // are we already running?

      if (!bEnabled) {                  // not enabled? try start it
        StartRegService();
      } else {
        dwError = ERROR_SUCCESS;        // else exit do loop
        break;
      }
      Sleep(1000);                      // goto sleep for second before trying again
    } while (++nAttempts < 3);          // try no more than 3 times
    CloseServices();
  } else dwError = GetLastError();
  return bEnabled;
}

bool Machine::ConnectRegistry()
{
  dwError = RegConnectRegistryW(szMachine,HKEY_LOCAL_MACHINE,&hRegistry);
  
  if (dwError == ERROR_SUCCESS)
    GetSystemInfo();

  return (dwError == ERROR_SUCCESS);
}

/**
 *
 * remove NetBIOS connection
 *
 */

bool Machine::NBDisconnect()
{
  wchar_t disk[MAX_PATH];

  wsprintfW(disk,L"\\\\%s\\ADMIN$",szMachine);
  return (WNetCancelConnection2W(disk,CONNECT_UPDATE_PROFILE,FALSE) == NO_ERROR);
}

/**
 *
 *  establish a connection to remote machine through ADMIN$ share
 *  then open handle to registry
 *
 */

bool Machine::Disconnect()
{
  //NBDisconnect();

  RegCloseKey(hRegistry);
  RevertToSelf();
  hRegistry = HKEY_LOCAL_MACHINE;            // reset to default location, the local machine
  return CloseHandle(hRemoteToken);
}

#ifdef EXT_MODE



/**
 *
 * load external system and security hives into memory
 * for dumping cached credentials
 *
 * return true for successful load
 *
 */
bool Machine::LoadHives(wchar_t szHivePath[])
{
  wchar_t szExtPath[MAX_PATH];

  for (DWORD i = 0;i < 4;i++)
  {
    wsprintfW(szExtPath,L"%s\\%s",szHivePath,lpszLocalNames[i]);

    DWORD dwAttributes = GetFileAttributesW(szExtPath);
    
    if (dwAttributes == INVALID_FILE_ATTRIBUTES)
    {
      dwError = GetLastError();
      break;
    }

    if ((dwError = RegLoadKeyW(HKEY_LOCAL_MACHINE,lpszExtNames[i],szExtPath)) == ERROR_SUCCESS)
    {
      lpszHiveNames[i] = lpszExtNames[i];
    } else break;
    
    if (dwError == ERROR_SUCCESS)
      GetSystemInfo();
  }
  return (dwError == ERROR_SUCCESS);
}

/**
 *
 * unload external system and security hives from memory
 *
 * return true for success else false
 *
 */
void Machine::UnloadHives()
{
  for (DWORD i = 0;i < 4;i++)
  {
    dwError = RegUnLoadKeyW(HKEY_LOCAL_MACHINE,lpszExtNames[i]);
    if (dwError == ERROR_SUCCESS) lpszHiveNames[i] = lpszLocalNames[i];
  }
}

bool Machine::GetOS(wchar_t product[])
{
  lstrcpyW(product,ProductName);
  return true;
}

#endif

bool Machine::GetSystemInfo()
{
  HKEY hSubKey;
  DWORD dwSize = MAX_PATH;
  wchar_t path[MAX_PATH];
  
  wsprintfW(path,L"%s\\Microsoft\\Windows NT\\CurrentVersion",lpszHiveNames[SOFTWARE_KEY]);

  if ((dwError = RegOpenKeyExW(hRegistry,path,0,KEY_QUERY_VALUE,&hSubKey)) == ERROR_SUCCESS)
  {
    if ((dwError = RegQueryValueExW(hSubKey,L"SystemRoot",NULL,NULL,reinterpret_cast<BYTE*>(SystemRoot),&dwSize)) == ERROR_SUCCESS)
    {
      dwSize = MAX_PATH;
      dwError = RegQueryValueExW(hSubKey,L"ProductName",NULL,NULL,reinterpret_cast<BYTE*>(ProductName),&dwSize);
    }
    RegCloseKey(hSubKey);
  }
  return (dwError == ERROR_SUCCESS);
}

#ifdef DEBUG
// simple function to dump hexadecimal and printable values
// only intended for buffer sizes <= 256
void Machine::dump_hex(const wchar_t str[], unsigned char pData[], size_t nDataSize)
{
    wprintf(L"\n%s\n",str);
    size_t i,j;

    for (i = 0;i < nDataSize;i += 16)
    {
      // display hexadecimal values
      for(j = 0;j < 16 && i+j < nDataSize;j++)
          wprintf(L" %02x",pData[i+j]);

      while(j++ < 16)
            wprintf(L"   ");

      wprintf(L"\t");

      // display printable values
      for (j = 0;j < 16 && i+j < nDataSize;j++) {
           if (pData[i+j] == 0x09 || !iswprint(pData[i+j]))
               wprintf(L".");
           else
               wprintf(L"%c",pData[i+j]);
      }
      wprintf(L"\n");
    }
}

#endif

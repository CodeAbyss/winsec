// Odzhan

#include "wmi.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "mpr.lib")

// need to figure out way of testing if ip or hostname is loopback
BOOL IsLocal(std::wstring host) {
  if (host == L"." || host.empty()) return TRUE;
  
  return FALSE;
}

// get integer
INT GetVarInt(IWbemClassObject *pObj, std::wstring property) {
  VARIANT var;
  INT iValue = 0;
  HRESULT hr = pObj->Get(property.c_str(), 0, &var, 0, 0);
  if (SUCCEEDED(hr) && var.vt == VT_I4) {
    iValue = var.lVal;
    VariantClear(&var);
  }
  return iValue;
}

// get string
std::wstring GetVarString(IWbemClassObject *pObj, std::wstring property) {
  VARIANT var;
  std::wstring s = L"<undefined>";
  HRESULT hr = pObj->Get(property.c_str(), 0, &var, 0, 0);
  if (SUCCEEDED(hr) && var.vt == VT_BSTR) {
    s = var.bstrVal;
    VariantClear(&var);
  }
  return s;
}

/**********************************************************
 *
 *  Set the string value of a property
 *  
 **********************************************************/
HRESULT SetVarString(IWbemClassObject *pObj, 
    std::wstring property, std::wstring value) {
  VARIANT var;
  HRESULT hr;
  
  VariantInit(&var);
  V_VT(&var) = VT_BSTR;
  V_BSTR(&var) = SysAllocString(value.c_str());
  
  hr = pObj->Put(property.c_str(), 0, &var, CIM_EMPTY);
  VariantClear(&var);
  return hr;
}

// Win32_Volume.DriveType
#define DRIVE_TYPE_UNKNOWN   0
#define DRIVE_TYPE_NO_ROOT   1
#define DRIVE_TYPE_REMOVABLE 2
#define DRIVE_TYPE_LOCAL     3
#define DRIVE_TYPE_NETWORK   4
#define DRIVE_TYPE_COMPACT   5
#define DRIVE_TYPE_RAM       6

std::wstring GetDriveType(INT iType) {
  std::wstring s;
  
  switch (iType) {
    case DRIVE_TYPE_UNKNOWN  : 
      s = L"Unknown";
      break;
    case DRIVE_TYPE_NO_ROOT  :
      s = L"No Root Directory";
      break;
    case DRIVE_TYPE_REMOVABLE :
      s = L"Removable Disk";
      break;
    case DRIVE_TYPE_LOCAL :
      s = L"Local Disk";
      break;
    case DRIVE_TYPE_NETWORK :
      s = L"Network Drive";
      break;
    case DRIVE_TYPE_COMPACT :
      s = L"Compact Disk";
      break;
    case DRIVE_TYPE_RAM :
      s = L"RAM Disk";
      break;
    default:
      s = L"Unknown";
      break;
  }
  return s;
}

template<class T, class F> T format(F input, int width = 0, int prec = -1) {
  std::wstringstream A;
  T res;
  if (prec != -1) {
    A << std::fixed << std::setprecision(prec);
  }
  A << std::setw(width) << std::setfill(L'0') << input;
  A >> res;
  return res;
}

std::wstring GetSizeAsString(std::wstring sSize) {
  float fSize = _wtof(sSize.c_str());

  // construct string to represent size of volume
  std::wstring sUnits = L" B";
        
  if (fSize > 1024) {
    fSize /= 1024;
    sUnits = L" KB";
    if (fSize > 1024) {
      fSize /= 1024;
      sUnits = L" MB";
      if (fSize > 1024) {
        fSize /= 1024;
        sUnits = L" GB";
        if (fSize > 1024) {
          fSize /= 1024;
          sUnits = L" TB";
          if (fSize > 1024) {
            fSize /= 1024;
            sUnits = L" PB";
          }
        }
      }
    }
  }
  return format<std::wstring, float>(fSize, -1, 2) + sUnits;
}

/********************************************************************
 *
 *  Convert a windows error code to human readable message and display
 *
 ********************************************************************/
VOID WMI::ShowWin32Error(PWCHAR pFmt, ...) {
  PWCHAR pDetails;
  WCHAR buffer[2048];
  
  if (pFmt != NULL) {
    va_list arglist;
    va_start(arglist, pFmt);
		wvsprintf(buffer, pFmt, arglist);
		va_end(arglist);
  }
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
      (LPWSTR)&pDetails, 0, NULL);

  wprintf(L"\n  %s : %s", buffer, pDetails);
  LocalFree(pDetails);
}

/**********************************************************
 *
 *  Constructor
 *  
 **********************************************************/
WMI::WMI() {
  dprintf(L"\n  Entering WMI()");
  
  pContext  = NULL;   // required for 32-bit code accessing 64-bit provider
  pLocator  = NULL;   
  pServices = NULL;
  pAuth     = NULL;
  
  ZeroMemory(&auth, sizeof(COAUTHIDENTITY));
  auth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
  
  machine = L".";   // local machine by default
  
  // initialize COM
  hr = CoInitializeEx(0, COINIT_MULTITHREADED);
  if (SUCCEEDED(hr)) {
    // create a context for 64-bit providers
    hr = CoCreateInstance(CLSID_WbemContext, 0, CLSCTX_INPROC_SERVER, 
        IID_IWbemContext, (LPVOID *) &pContext);
        
    if (SUCCEEDED(hr)) {
      VARIANT vArch;
      VariantInit(&vArch);
      V_VT(&vArch) = VT_I4;
      V_INT(&vArch) = 64;
      
      // This doesn't warrant an exit but could cause issues.
      // Specifically executing 32-bit code against a 64-bit system or vice versa.
      hr = pContext->SetValue(_bstr_t(L"__ProviderArchitecture"), 0, &vArch);
      if (FAILED(hr)) {
        dprintf(L"\n  Failed to set provider architecture");
      }
      VariantClear(&vArch);
      
      // initialize locator..we do need this
      hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, 
          IID_IWbemLocator, (LPVOID *)&pLocator);
    } else {
      dprintf(L"\n  CoCreateInstance(CLSID_WbemContext) failed");
    }
  } else {
    dprintf(L"\n  CoInitializeEx() failed");
  }
  dprintf(L"\n  Leaving WMI()");
}

/**********************************************************
 *
 *  Destructor
 *  
 **********************************************************/
WMI::~WMI() {
  dprintf(L"\n  Entering ~WMI()");
  
  if (!remote.empty()) {
    dwError = WNetCancelConnection(remote.c_str(), TRUE);
  }
  if (pServices != NULL) pServices->Release();
  if (pLocator  != NULL) pLocator->Release();
  if (pContext  != NULL) pContext->Release();
  
  CoUninitialize();

  dprintf(L"\n  Leaving ~WMI()");
}

/**********************************************************
 *
 *  Open WMI connection to local or remote machine
 *  
 **********************************************************/
BOOL WMI::Open(std::wstring machine, std::wstring username, std::wstring password) {

  // we only connect to SMB if remote machine
  dwError = NO_ERROR;
  
  // only assign these properties if machine is remote
  if (!machine.empty() && !IsLocal(machine)) {
    this->machine  = machine;
    this->username = username;
    this->password = password;
  }

  // connect to service
  hr = pLocator->ConnectServer(BSTR((std::wstring(L"\\\\") + 
      this->machine + L"\\root\\cimv2").c_str()), 
      _bstr_t(username.empty() ? NULL : username.c_str()), 
      _bstr_t(password.empty() ? NULL : password.c_str()), 
      NULL, NULL, NULL, pContext, &pServices);
  
  // if we have a connection established
  if (SUCCEEDED(hr)) {
    // set the security levels for this object
    if (SetBlanket(pServices)) {
      // if this is remote, connect to ADMIN$ share for file transfers
      if (!IsLocal(machine)) {   
        // construct remote path
        remote = std::wstring(L"\\\\") + this->machine + L"\\ADMIN$";
        
        NETRESOURCE nr;
        ZeroMemory(&nr, sizeof(NETRESOURCE));

        nr.dwType = RESOURCETYPE_ANY;
        nr.lpRemoteName = (LPWSTR)remote.c_str();

        dwError = WNetAddConnection2(&nr, password.c_str(), 
            username.c_str(), CONNECT_TEMPORARY);
      } else {
        dprintf(L"\n  Machine is Local");
      }
    } else {
      dprintf(L"\n  WMI::Open->SetBlanket() failed");
    }
  } else {
    dprintf(L"\n  WMI::Open->ConnectServer() failed");
  }
  return SUCCEEDED(hr) && dwError == NO_ERROR;
}

/**********************************************************
 *
 *  Set the authentication levels for this object
 *  
 **********************************************************/
BOOL WMI::SetBlanket(IUnknown *pUnknown) {

  // if we have username and pAuth isn't set
  if (!username.empty() && pAuth == NULL) {
    
    // see if domain provided
    size_t pos = username.find_first_of(L'\\');

    if (pos != std::wstring::npos) {
      domain = username.substr(0, pos);
      username = username.substr(pos+1, username.length() - pos);
    }
    
    // why Microsoft used PUSHORT for string is a mystery
    auth.Domain         = (PUSHORT)domain.c_str();
    auth.DomainLength   = domain.length();

    auth.User           = (PUSHORT)username.c_str();
    auth.UserLength     = username.length();

    auth.Password       = (PUSHORT)password.c_str();
    auth.PasswordLength = password.length();
    
    pAuth = &auth;
  }
  hr = CoSetProxyBlanket(pUnknown, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, 
      NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, pAuth, EOAC_NONE);
  return SUCCEEDED(hr);
}

/**********************************************************
 *
 *  List the available volumes we can create shadow copy for
 *  
 **********************************************************/
VOID WMI::ListVolumes(VOID) {

  // get all volumes on system
  IEnumWbemClassObject* pEnumerator = NULL;
  std::wstring query = L"SELECT * FROM Win32_Volume";
  HRESULT hr = pServices->ExecQuery(BSTR(L"WQL"), BSTR(query.c_str()),
      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
  
  // if query succeeded
  if (SUCCEEDED(hr)) { 
    // set security levels for this object  
    if (SetBlanket(pEnumerator)) {
      IWbemClassObject *pclsObj = NULL;
      ULONG uReturn = 0;
      
      // print column headers
      wprintf(L"\n  %-15s  %-30s  %-20s  %-10s  %-10s", 
          std::wstring(15, L'-').c_str(),
          std::wstring(30, L'-').c_str(),
          std::wstring(20, L'-').c_str(),      
          std::wstring(10, L'-').c_str(),      
          std::wstring(10, L'-').c_str());
          
      wprintf(L"\n  %-15s  %-30s  %-20s  %-10s  %-10s", 
          L"Drive Letter", L"Label", L"Drive Type", L"Capacity", L"Free Space");
          
      wprintf(L"\n  %-15s  %-30s  %-20s  %-8s  %-10s", 
          std::wstring(15, L'-').c_str(),
          std::wstring(30, L'-').c_str(),
          std::wstring(20, L'-').c_str(),
          std::wstring(10, L'-').c_str(),
          std::wstring(10, L'-').c_str());
      
      // enumerate through objects returned from query
      while (pEnumerator) {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        
        // if failure or no objects returned, break
        if (FAILED(hr) || uReturn == 0) {
          break;
        }
        
        // get drive letter
        std::wstring drive     = GetVarString(pclsObj, L"DriveLetter");
        // drive type
        std::wstring sType     = GetDriveType(GetVarInt(pclsObj, L"DriveType"));
        // drive label
        std::wstring label     = GetVarString(pclsObj, L"Label");
        // capacity
        std::wstring capacity  = GetVarString(pclsObj, L"Capacity");
        // free space
        std::wstring freespace = GetVarString(pclsObj, L"FreeSpace");
        
        // format size as something we can read
        capacity  = GetSizeAsString(capacity);
        freespace = GetSizeAsString(freespace);

        wprintf(L"\n  %-15s  %-30s  %-20s  %10s  %10s", 
            drive.c_str(), label.c_str(), sType.c_str(), capacity.c_str(), freespace.c_str());
        pclsObj->Release();
        pclsObj = NULL; 
      }
    }
    putchar('\n');
    pEnumerator->Release();
  }
}

/**********************************************************
 *
 *  Wait for a process to end
 *  
 **********************************************************/
VOID WMI::WaitOnProcess(std::wstring processId) {
  // execute until we can't find this process id anymore
  while (TRUE) {    
    IEnumWbemClassObject* pEnumerator = NULL;
    ULONG uCount = 0;
    
    hr = pServices->ExecQuery(BSTR(L"WQL"), 
        BSTR((L"SELECT * FROM Win32_Process WHERE ProcessId = '" + processId + L"'").c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    
    if (SUCCEEDED(pEnumerator)) {
      if (SetBlanket(pEnumerator)) {
        IWbemClassObject *pclsObj = NULL;
        
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uCount);
          
        if (pclsObj != NULL) {
          pclsObj->Release();
        }
      }
      pEnumerator->Release();
    }
    // if nothing returned, just exit
    if (uCount == 0) break;
    // otherwise, sleep for 1 second before next call
    // TODO: put in a time limit just incase we end up waiting infinitely
    // add some way to monitor progress of command?
    Sleep(1000);
  }
}

/**********************************************************
 *
 *  Execute command on local or remote machine
 *  
 **********************************************************/
DWORD WMI::ExecCommand(std::wstring CmdLine, BOOL bShow, BOOL bWait) {
  
  DWORD returnCode = -1;
  
  dprintf(L"\n  Entering WMI::ExecCommand(\"%s\" - Show Window : %s, Wait for Termination: %s)", 
      CmdLine.c_str(), bShow ? L"Yes" : L"No", bWait ? L"Yes" : L"No");
  
  // obtain Win32_Process object
  IWbemClassObject* process = NULL;
  hr = pServices->GetObject(BSTR(L"Win32_Process"), 0, NULL, &process, NULL);
  
  // obtain the Create method
  if (SUCCEEDED(hr)) {          
    IWbemClassObject* pInParams = NULL;
    hr = process->GetMethod(BSTR(L"Create"), 0, &pInParams, NULL);
    
    // spawn an instance for input parameters
    if (SUCCEEDED(hr)) {
      IWbemClassObject* createInstance = NULL;
      hr = pInParams->SpawnInstance(0, &createInstance);
      
      // set the command line
      if (SUCCEEDED(hr)) {
        hr = SetVarString(createInstance, L"CommandLine", CmdLine);

        // get Win32_ProcessStartup object
        if (SUCCEEDED(hr)) {
          IWbemClassObject *startup = NULL;
          hr = pServices->GetObject(BSTR(L"Win32_ProcessStartup"), 0, 
              NULL, &startup, NULL); 
          
          // spawn an instance for input parameters
          if (SUCCEEDED(hr)) {
            IWbemClassObject *startupInstance = NULL;
            hr = startup->SpawnInstance(0, &startupInstance);
            
            // set the ShowWindow attribute
            if (SUCCEEDED(hr)) {
              VARIANT varShow;
              V_VT(&varShow) = VT_UI1;
              V_UI1(&varShow) = bShow ? SW_SHOWNORMAL : SW_HIDE;
              hr = startupInstance->Put(BSTR(L"ShowWindow"), 0, &varShow, 0);
              
              // set the startup information for Win32_Process::Create instance
              if (SUCCEEDED(hr)) {
                VARIANT varStartup;
                V_VT(&varStartup) = VT_UNKNOWN;
                V_UNKNOWN(&varStartup) = startupInstance;
                hr = createInstance->Put(BSTR(L"ProcessStartupInformation"), 0, &varStartup, 0);   
                
                // execute the Create method with above parameters
                if (SUCCEEDED(hr)) {
                  IWbemClassObject *pOutParams = NULL;
                  hr = pServices->ExecMethod(BSTR(L"Win32_Process"), BSTR(L"Create"), 0, 
                      NULL, createInstance, &pOutParams, NULL);
                  
                  // if Create succeeded...
                  if (SUCCEEDED(hr) && pOutParams != NULL) {                    
                    // wait for process to terminate?
                    
                    if (bWait) {
                      // okay, get the process id as a string
                      std::wstring sProcessId = GetVarString(process, L"ProcessId");
                      // wait for it to finish..
                      WaitOnProcess(sProcessId);
                    }
                    
                    // get the result of Create
                    returnCode = GetVarInt(pOutParams, L"ReturnValue");
                    
                    // release object
                    pOutParams->Release();
                  } else {
                    dprintf(L"\n  Win32_Process::ExecMethod failed");
                  }
                } else {
                  dprintf(L"\n  Win32_Process::Create::Instance->Put(\"ProcessStartupInformation\")");
                }
              } else {
                dprintf(L"\n  Win32_ProcessStartup::SpawnInstance");
              }
              startupInstance->Release();
            } else {
              dprintf(L"\nGetObject(\"Win32_ProcessStartup::SpawnInstance\") failed");
            }
            startup->Release();
          } else {
            dprintf(L"\nGetObject(\"Win32_ProcessStartup\") failed");
          }
        } else {
          dprintf(L"\nsetPropertyValue() failed");
        }
        createInstance->Release();
      } else {
        dprintf(L"\nGetMethod(\"Win32_Process::Create::SpawnInstance\") failed");
      }
      pInParams->Release();
    } else {
      dprintf(L"\nGetMethod(\"Win32_Process::Create\") failed");
    }
    process->Release();
  } else {
    dprintf(L"\nGetObject(\"Win32_Process\") failed");
  }
  dprintf(L"\n  Leaving WMI::ExecCommand()");
  return SUCCEEDED(hr);
}

/**********************************************************
 *
 *  Get the DeviceObject for newly created Shadow Copy
 *  
 **********************************************************/
VOID WMI::GetDeviceObject(VOID) {
  
  IEnumWbemClassObject* pEnumerator = NULL;
  hr = pServices->ExecQuery(BSTR(L"WQL"), 
      BSTR(std::wstring(L"SELECT * FROM Win32_ShadowCopy WHERE ID = '" + shadowID + L"'").c_str()),
      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
  
  if (SUCCEEDED(hr)) {
    if (SetBlanket(pEnumerator)) {
      IWbemClassObject *pclsObj = NULL;
      ULONG uCount = 0;
      
      // just get the first returned...if any
      hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uCount);
      
      // anything?
      if (uCount != 0) {
        // get the string
        shadowObj = GetVarString(pclsObj, L"DeviceObject");
        pclsObj->Release();
      }
    }
    pEnumerator->Release();
  }
}

/**********************************************************
 *
 *  Create shadow copy for specified volume
 *  
 **********************************************************/
BOOL WMI::CreateShadow(std::wstring volume) {
  dprintf(L"\n  Entering WMI::CreateShadow()");
  
  // get Win32_ShadowCopy object
  IWbemClassObject* shadowObject = NULL;
  hr = pServices->GetObject(L"Win32_ShadowCopy", 0, NULL, &shadowObject, NULL);
  
  // get the Create method
  if (SUCCEEDED(hr)) {          
    IWbemClassObject* paramsObj = NULL;
    IWbemClassObject* resultsObj = NULL;
    hr = shadowObject->GetMethod(L"Create", 0, &paramsObj, &resultsObj);
    
    // spawn an instance
    if (SUCCEEDED(hr)) {
      IWbemClassObject* params = NULL;
      hr = paramsObj->SpawnInstance(0, &params);
      
      // set the volume we want to backup
      if (SUCCEEDED(hr)) {
        hr = SetVarString(params, L"Volume", volume);
        
        // set the context...unsure if this required
        if (SUCCEEDED(hr)) {
          hr = SetVarString(params, L"Context", L"ClientAccessible"); 
          
          // get the path of our object, mightn't be required either
          if (SUCCEEDED(hr)) {
          
            // get our path
            std::wstring path = GetVarString(shadowObject, L"__PATH");
            
            // execute the Create method with our above parameters
            if (SUCCEEDED(hr)) {
              hr = pServices->ExecMethod(BSTR(path.c_str()),  L"Create", 0, 
                  NULL, params, &resultsObj, NULL);
              
              // if create method succeeded, obtain the return code first
              // and if that's good, we have valid shadow copy made
              dwError = GetVarInt(resultsObj, L"ReturnValue");
              
              // if we're good, grab the shadow id + device object
              if (dwError == ERROR_SUCCESS) {
                shadowID  = GetVarString(resultsObj, L"ShadowID");
                // device object requires finding object first..
                GetDeviceObject();
              }
            }
          }
        }
        params->Release();
      }
      paramsObj->Release();
      resultsObj->Release();
    }
    shadowObject->Release();
  }
  dprintf(L"\n  Leaving WMI::CreateShadow()");
  return dwError == ERROR_SUCCESS;
}

/**********************************************************
 *
 *  Convert WMI error code into readable string
 *  
 **********************************************************/
const PWCHAR WMI::GetWMIError(VOID) {
  PWCHAR pErrorString = L"<undefined>";
  
  for (size_t i = 0; i < sizeof(wmiErrorTable) / sizeof(WMI_ERROR); i++) {
    if (hr == wmiErrorTable[i].hr) {
      pErrorString = wmiErrorTable[i].wstrError;
      break;
    }
  }
  return pErrorString;
}

DWORD copyProgress(
  LARGE_INTEGER TotalFileSize, LARGE_INTEGER TotalBytesTransferred,
  LARGE_INTEGER StreamSize, LARGE_INTEGER StreamBytesTransferred,
  DWORD dwStreamNumber, DWORD dwCallbackReason, HANDLE hSourceFile,
  HANDLE hDestinationFile, LPVOID lpData) {

  LARGE_INTEGER sizeRemaining;
  
  // calculate a percentage
  sizeRemaining.QuadPart = (TotalFileSize.QuadPart - TotalBytesTransferred.QuadPart) * 100;
  sizeRemaining.QuadPart /= TotalFileSize.QuadPart;
  
  return PROGRESS_CONTINUE;
}

/***************************************************************************
 *  
 *  Function to recursively copy source folder to destination
 *  What to copy is based on fileSpec  
 *  wildcards are supported
 *
 ***************************************************************************/
VOID WMI::CopyFolder(std::wstring destination, 
    std::wstring source, std::wstring fileSpec) {
  dprintf(L"\n  Inside %s", source.c_str());
  // ensure source has backslash
  size_t pos = source.find_last_of(L'\\');
  if (pos != source.length() - 1) {
    source += L'\\';
  }
  // ensure destination has backslash
  pos = destination.find_last_of(L'\\');
  if (pos != destination.length() - 1) {
    destination += L'\\';
  }
  // find all files that match fileSpec parameter
  WIN32_FIND_DATA wfd;
  HANDLE hFind;
  
  hFind = FindFirstFile((source + fileSpec).c_str(), &wfd);
  if (hFind != INVALID_HANDLE_VALUE) {
    do {
      // get the filename
      std::wstring fileName = wfd.cFileName;
      std::wstring existing = source + fileName;
      std::wstring newfile  = destination + source.substr(3) + fileName;
      // skip parent directories
      if (fileName != L"." && fileName != L"..") {
        // is this a directory?
        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          // create in destination
          wprintf(L"\n  Creating %s . . .", newfile.c_str());
          if (CreateDirectory(newfile.c_str(), NULL) != 0) {
            // and copy it's contents, according to file fileSpec
            CopyFolder(newfile, existing, fileSpec);
          }
        } else {          
          wprintf(L"\nCopying %s to %s . . .", existing.c_str(), newfile.c_str());
          BOOL bCopied = CopyFileEx(existing.c_str(), newfile.c_str(), 
              (LPPROGRESS_ROUTINE)copyProgress, NULL, FALSE, 
              COPY_FILE_COPY_SYMLINK | COPY_FILE_ALLOW_DECRYPTED_DESTINATION);
          wprintf(L"%s", bCopied ? L"Completed" : L"Failed");
        }
      }
    } while (FindNextFile(hFind, &wfd));
    FindClose(hFind);
  }
  dprintf(L"\n  Leaving %s", source.c_str()); 
}

/***************************************************************************
 *  
 *  Function to recursively copy source folder to destination
 *  What to copy is based on fSpec  
 *  wildcards are supported
 *
 ***************************************************************************/
BOOL WMI::Backup(std::vector<std::wstring> destination, 
    std::vector<std::wstring> source, std::vector<std::wstring> files) {
  
  // create shadow on system
  wprintf(L"\n  Creating shadow . . . ");
  
  if (CreateShadow(volume)) {
    dprintf(L"\n  Shadow ID = %s\n  Object = %s", shadowID.c_str(), shadowObj.c_str());
    
    /***************************************************************************
     * if remote, copy files to temp location and set local path to remote share
     ****************************************************************************/
    if (!remote.empty()) {
      // construct command line for copying files to temporary location
      std::wstring sCmdLine;
      
      // execute command to create junction for copying files remotely
      //
      // EXECUTE REMOTE: cmd /c mklink /J C:\shadow2 "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy75"
      // EXECUTE LOCAL:  net use X: \\REMOTE_COMPUTER\C$\shadow2
      // EXECUTE LOCAL:  copy X:\Windows\system32\SYSTEM
      // EXECUTE LOCAL:  copy X:\Windows\NTDS\ntds.dit
      
      if (ExecCommand(sCmdLine, FALSE, TRUE)) {
        // looks good
      }
    }
    
    /****************************************************************
     * copy the files
     ****************************************************************/ 
    if (bFolder) {
      // copy all from folder
    } else {
      // copy just the file
    }    
    // delete the shadow and remove any files copied to temporary locations
    hr = pServices->DeleteInstance(BSTR(std::wstring(L"Win32_ShadowCopy.ID='" 
        + shadowID + L"'").c_str()), 0, pContext, NULL);
    if (FAILED(hr)) {
      wprintf(L"\n  ERROR: Couldn't delete shadow copy . . .");
    }

  } else {
    ShowWin32Error(L"Createshadow failed");
  }
  return SUCCEEDED(hr);
}

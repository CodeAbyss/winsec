
#include "Machine.h"
#include "AppList.h"

Machine::Machine(wstring host)
{
  // if computer provided
  if (!host.empty()) {
    name = host;
    ResolveHost();
  } else {
    // get the local computer name    
    DWORD dwSize = 0;
    GetComputerNameEx(ComputerNameNetBIOS,NULL,&dwSize);
    wchar_t *comp = new wchar_t[dwSize+1];
    GetComputerNameEx(ComputerNameNetBIOS,comp,&dwSize);
    name = comp;
    host_entry entry;
    entry.bOnline = true;
    entry.dwStatus = IP_SUCCESS;
    entry.name = comp;
    delete []comp;
  }
  
  hRegistry = HKEY_LOCAL_MACHINE;
  pList = new AppList(this);
}

// disconnect from machine
Machine::~Machine()
{
  // if not local machine, close
  if (hRegistry != HKEY_LOCAL_MACHINE) {
    RegCloseKey(hRegistry);
  }
  delete pList;
}

HKEY Machine::GetRegHandle()
{
  return hRegistry;
}

bool Machine::RegConnect() {
  dwError = RegConnectRegistry(name.c_str(),HKEY_LOCAL_MACHINE,&hRegistry);
  return (dwError == ERROR_SUCCESS);
}

const wchar_t* Machine::getName() {
  return name.c_str();
}

bool Machine::isOnline() {
  if(hostlist.empty()) return false;
  return hostlist[0].bOnline;
}

bool Machine::isResponding() {
  if(hostlist.empty()) return false;
  return hostlist[0].bResponse;
}

const wchar_t* Machine::getHost() {
  if(hostlist.empty()) return L"N/A";
  return hostlist[0].name.c_str();
}

const wchar_t* Machine::getStatus() {
  if(hostlist.empty()) return L"N/A";
  return hostlist[0].status.c_str();
}

const wchar_t* Machine::getIp() {
  if(hostlist.empty()) return L"N/A";
  return hostlist[0].ip.c_str();
}

class AppList* Machine::GetAppList() {
  return pList;
}
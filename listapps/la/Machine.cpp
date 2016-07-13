
/**
 *
 *  Main class to represent a machine
 *
 *  Copyright (c) 2010 -   <???@???>
 *
 */

#include "Products.h"
#include "Profiles.h"
#include "Network.h"
#include "Machine.h"

Machine::Machine(std::wstring name)
{
  this->name = name;

  if(name.empty()) {
    // get local computer name
    DWORD dwSize = 0;
    GetComputerNameEx(ComputerNameNetBIOS,NULL,&dwSize);
    wchar_t *nbt_name = new wchar_t[dwSize+1];
    GetComputerNameEx(ComputerNameNetBIOS,nbt_name,&dwSize);
    this->name = nbt_name;
    delete []nbt_name;
  }
  
  profiles = new Profiles(this);
  products = new Products(this);
  network  = new Network (this);

  hRegistry[HKU ] = HKEY_USERS;
  hRegistry[HKLM] = HKEY_LOCAL_MACHINE;
}

Machine::~Machine()
{
  delete network;
  delete products;  // products first!
  delete profiles;

  if(hRegistry[HKLM] != HKEY_LOCAL_MACHINE)
    RegCloseKey(hRegistry[HKLM]);

  if(hRegistry[HKU] != HKEY_USERS)
    RegCloseKey(hRegistry[HKU]);
}

// connect to remote registry
bool Machine::connect()
{
  dwError = RegConnectRegistry(name.c_str(),HKEY_USERS,&hRegistry[HKU]);
  if(dwError != ERROR_SUCCESS) return false;

  dwError = RegConnectRegistry(name.c_str(),HKEY_LOCAL_MACHINE,&hRegistry[HKLM]);
  return (dwError == ERROR_SUCCESS);
}

std::vector<ProfileEntry> *Machine::GetProfiles()
{
  return profiles->get();
}

std::vector<ProductEntry> *Machine::GetProducts()
{
  return products->get();
}


const wchar_t* Machine::GetName()
{
  return name.c_str();
}

const wchar_t* Machine::GetHostName()
{
  return network->name();
}

const wchar_t* Machine::GetIP()
{
  return network->ip();
}

const wchar_t* Machine::GetPingStatus()
{
  return network->status(); 
}

bool Machine::IsOnline()
{
  return network->ping();
}

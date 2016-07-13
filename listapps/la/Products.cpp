
/**
 *
 *  Gather list of applications installed on computer
 *  Works similar to Add/Remove Programs applet - appwiz.cpl
 *
 *  Copyright (c) 2010 -   <???@???>
 *
 */

#include "Products.h"

Products::Products(class Machine* host)
{
  this->host = host;
  dwTotal = 0;
}

Products::~Products()
{
  std::vector<ProfileEntry>* profiles = host->GetProfiles();
  for(std::vector<ProfileEntry>::iterator p = profiles->begin();p != profiles->end();p++) {
    for(std::vector<DWORD>::size_type i = 0;i < p->dwEntries.size();i++) {
      RegCloseKey(p->hKeys[i]);
    }
    p->hKeys.clear();
    p->dwEntries.clear();
    p->products.clear();
  }
  products.clear();
}

/**
 *
 *  Search the existing list of entries and determine if the new entry is already present
 *
 */
bool Products::isListed(std::vector<ProductEntry> entries, ProductEntry entry)
{
  bool bFound = false;
  
  for(std::vector<ProductEntry>::iterator it = entries.begin();it != entries.end();it++) {
    // app names are equal?
    if(it->name == entry.name) {
      bFound = true;

      // versions are the same? or new entry is empty - skip it
      if(it->version == entry.version || entry.version.empty()) break;

      // list version empty? - replace with new entry and skip
      if(it->version.empty()) {
        it->version = entry.version;
        break;
      }

      // new entry is different - keep searching
      bFound = false;
    }
  }
  return bFound;
}

bool Products::getEntry(HKEY hAppKey, std::wstring regKey, ProductEntry &entry)
{
  DWORD dwError;
  HKEY hEntry;
  bool bValid = false;

  // try open the application as just itself
  dwError = RegOpenKeyEx(hAppKey,regKey.c_str(),0,KEY_QUERY_VALUE | KEY_WOW64_64KEY,&hEntry);
  if(dwError != ERROR_SUCCESS) {
    // assume it's MSI entry - should be able to remove this later
    dwError = RegOpenKeyEx(hAppKey,(regKey + L"\\InstallProperties").c_str(),0,KEY_QUERY_VALUE | KEY_WOW64_64KEY,&hEntry);
    if(dwError != ERROR_SUCCESS) return false;
  }
  
  // exclude system components
  DWORD dwValue = 0;
  DWORD dwSize = sizeof(DWORD);
  DWORD dwResult = RegQueryValueEx(hEntry,L"SystemComponent",NULL,NULL,(LPBYTE)&dwValue,&dwSize);

  //if((dwResult != ERROR_SUCCESS) && (dwValue != 1)) {
  if(dwValue != 1) {
    // exclude WindowsInstaller entries
    dwSize = sizeof(DWORD);
    dwValue = 0;
    //RegQueryValueEx(hEntry,L"WindowsInstaller1",NULL,NULL,(LPBYTE)&dwValue,&dwSize);

    if(dwValue == 0) {
      // exclude child applications
      wchar_t wszParentDisplayName[MAX_PATH];
      DWORD dwSize = MAX_PATH;

      if((dwError = RegQueryValueEx(hEntry,L"ParentDisplayName",NULL,NULL,(LPBYTE)&wszParentDisplayName,&dwSize)) != ERROR_SUCCESS) {

        // we need a displayname atleast
        wchar_t wszDisplayName[MAX_PATH];
        dwSize = MAX_PATH;

        if((dwError = RegQueryValueEx(hEntry,L"DisplayName",NULL,NULL,(LPBYTE)&wszDisplayName,&dwSize)) == ERROR_SUCCESS) {

          entry.name = wszDisplayName;

          // query the version - not compulsory
          wchar_t wszVersion[MAX_PATH];
          dwSize = MAX_PATH;

          if((dwError = RegQueryValueEx(hEntry,L"DisplayVersion",NULL,NULL,(LPBYTE)&wszVersion,&dwSize)) == ERROR_SUCCESS)
            entry.version = wszVersion;

          // query the publisher - not compulsory
          wchar_t wszPublisher[MAX_PATH];
          dwSize = MAX_PATH;

          if(RegQueryValueEx(hEntry,L"Publisher",NULL,NULL,(LPBYTE)&wszPublisher,&dwSize) == ERROR_SUCCESS)
            entry.publisher = wszPublisher;

          bValid = true;
        }
      }
    }
  }
  return bValid;
}

void Products::getKeyCount(HKEY hRootKey,std::wstring path,ProfileEntry* p)
{
  HKEY hAppKey;
  if(RegOpenKeyEx(hRootKey,path.c_str(),0,KEY_ENUMERATE_SUB_KEYS |
                                          KEY_QUERY_VALUE |
                                          KEY_WOW64_64KEY,&hAppKey) == ERROR_SUCCESS) {
    DWORD dwCount = 0;
    RegQueryInfoKey(hAppKey,NULL,NULL,NULL,&dwCount,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
    // if we got entries, save the amount and key handle
    if(dwCount != 0) {
      p->hKeys.push_back(hAppKey);           // key handle to enumerate
      p->dwEntries.push_back(dwCount);       // number of entries if required
      dwTotal += dwCount;                    // update total for the thread
    } else {                                 // we didn't return anything
      RegCloseKey(hAppKey);
    }
  }
}

DWORD Products::getTotal()
{
  if(dwTotal != 0) return dwTotal;
  
  std::vector<ProfileEntry>* profiles = host->GetProfiles();

  // in old locations for each user
  for(std::vector<ProfileEntry>::size_type idx = 0;idx < profiles->size();idx++) {
    ProfileEntry* p = &profiles->at(idx);
    if(p->wszSid == L"S-1-5-18") {      // system profile?
      getKeyCount(host->GetHKLM(),L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",p);
      getKeyCount(host->GetHKLM(),L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",p);
    } else {
      getKeyCount(host->GetHKU(),p->wszSid + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",p);
      //getKeyCount(hRegistry[1],L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\" + p->wszSid + L"\\Products",p);
    }
  }
  return dwTotal;
}

// sort in names of applications in ascending order
bool SortByName(ProductEntry rpStart, ProductEntry rpEnd)
{
  return(lstrcmpi(rpStart.name.c_str(),rpEnd.name.c_str()) < 0);
}

/**
 *
 *  get applications for each profile
 *
 */
std::vector<ProductEntry>* Products::get()
{
  // get total entries if zero
  if(dwTotal == 0)
    getTotal();

  std::vector<ProfileEntry>* profiles = host->GetProfiles();
  for(std::vector<ProfileEntry>::iterator p = profiles->begin();p != profiles->end();p++) {
    for(std::vector<DWORD>::size_type i = 0;i < p->dwEntries.size();i++) {
      for(std::vector<DWORD>::size_type j = 0;j < p->dwEntries[i];j++) {
        DWORD dwSize = MAX_PATH;
        wchar_t wszKeyName[MAX_PATH];

        if((RegEnumKeyEx(p->hKeys[i],j,wszKeyName,&dwSize,NULL,NULL,NULL,NULL)) == ERROR_NO_MORE_ITEMS)
          break;

        std::wstring key = wszKeyName;
        //if(key.find(L"KB") == std::wstring::npos) {
          ProductEntry entry;

          if(getEntry(p->hKeys[i],wszKeyName,entry)) {
            if(!isListed(p->products,entry)) {
              p->products.push_back(entry);
            }
          }
        //}
      }
    }
    products.insert(products.end(),p->products.begin(),p->products.end());
  }
  std::sort(products.begin(),products.end(),SortByName);
  return &products;
}


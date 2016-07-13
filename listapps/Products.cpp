/**
 *
 *    <>
 *  August 2010
 *
 */

#define _CRT_SECURE_NO_DEPRECATE

#include "Products.h"

Products::Products(std::wstring computer)
{
  dwIndex    = 0;
  dwTotal    = 0;
  dwStart    = 0;
  dwFiltered = 0;

  nName      = 0;
  nPublisher = 0;
  nVersion   = 0;
  
  lRunning  = THREAD_STOPPED;
  host      = computer;

  if(host.empty()) {
    // get local computer name
    DWORD dwSize = 0;
    GetComputerNameEx(ComputerNameNetBIOS,NULL,&dwSize);
    wchar_t *comp = new wchar_t[dwSize+1];
    GetComputerNameEx(ComputerNameNetBIOS,comp,&dwSize);
    host = comp;
    delete []comp;
  }
  hRegistry = HKEY_LOCAL_MACHINE;
}

Products::~Products()
{
  if(hRegistry != HKEY_LOCAL_MACHINE)
    RegCloseKey(hRegistry);
    
  entries.clear();
}

wchar_t *lpszAppKeys[2]={APPS_KEY_A,APPS_KEY_B};

/**
 *
 *  Query the total number of application entries available.
 *  Including 32 and 64-bit products
 *
 */
void Products::getTotalEntries(DWORD dwEntries[])
{
  for (DWORD i = 0;i < 2;i++) {
    HKEY hApplications;

    if ((RegOpenKeyEx(hRegistry,lpszAppKeys[i],0,KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY,&hApplications)) == ERROR_SUCCESS) {
      
      dwEntries[i] = 0;

      RegQueryInfoKey(hApplications,NULL,NULL,NULL,&dwEntries[i],NULL,NULL,NULL,NULL,NULL,NULL,NULL);
      RegCloseKey(hApplications);
      dwTotal += dwEntries[i];
    }
  }
}

/**
 *
 *  Search the existing list of entries and determine if the new entry is there
 *
 */
bool Products::isListed(ProductEntry entry)
{
  bool bFound = false;
  
  for (std::vector<ProductEntry>::iterator it = entries.begin();it != entries.end();it++) 
  {
    // app names are equal?
    // check other attributes before saving
    if (it->name == entry.name) {
      bFound = true;

      // both versions are the same?
      // we don't want duplicates - skip it
      if (it->version == entry.version) break;

      // versions aren't same
      // is the entry version empty? - skip it
      if (entry.version.empty()) break;

      // is the list version empty? - replace with new entry
      if (it->version.empty()) {
        it->version = entry.version;
        break;      // return found
      }

      // this new version is different, keep searching
      bFound = false;
      // we can stop searching at this point
      // we don't save apps with empty version numbers anymore than once
      //break;
    }
  }
  return bFound;
}

/**
 *
 *  Enumerate all 32 and 64-bit products installed
 *
 */
void Products::enumEntries()
{
  // record when we start
  dwStart = GetTickCount();

  // set to a running state
  _InterlockedExchange(&lRunning,THREAD_RUNNING);

  HKEY hApplications;

  DWORD dwEntries[2];
  getTotalEntries(dwEntries);

  // enumerate 32 and 64-bit applications
  for (DWORD i = 0;i < 2;i++) {

    // stop listing? safely exit loop
    if (!isRunning()) break;

    // open key for enumerate and query access
    if ((dwError = RegOpenKeyEx(hRegistry,lpszAppKeys[i],0,KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY,&hApplications)) == ERROR_SUCCESS) {
           
      // loop through each entry for this key
      for (DWORD dwKeyIndex = 0;i < dwEntries[i];dwKeyIndex++) {

        // stop listing? safely exit loop
        if (!isRunning()) break;

        // get key name
        DWORD cbName = MAX_KEY_LEN;
        wchar_t wszKeyName[MAX_KEY_LEN];

        if ((dwError = RegEnumKeyEx(hApplications,dwKeyIndex,wszKeyName,&cbName,NULL,NULL,NULL,NULL)) == ERROR_NO_MORE_ITEMS)
          break;

        // increase total entries processed
        _InterlockedIncrement(reinterpret_cast<volatile long*>(&dwIndex));

        HKEY hEntry;
        std::wstring keyName = wszKeyName;

        // if not a name with "KB" in it
        // could be a problem since other applications could have KB in it
        if (keyName.find(L"KB") == std::wstring::npos) {

          // open to query values
          if ((dwError = RegOpenKeyEx(hApplications,wszKeyName,0,KEY_QUERY_VALUE,&hEntry)) == ERROR_SUCCESS) {
            
            // exclude SystemComponents
            DWORD dwValue = 0;
            DWORD dwSize = sizeof(DWORD);
            RegQueryValueEx(hEntry,L"SystemComponent",NULL,NULL,(LPBYTE)&dwValue,&dwSize);
            
            if (dwValue != 1) {
              
              ProductEntry entry;
            
              // clear string values incase set from previous entry
              entry.name.clear();
              entry.publisher.clear();
              entry.version.clear();

              // query display name, if we don't get this value, we don't save anything and continue to next entry
              wchar_t wszDisplayName[MAX_KEY_LEN];
              dwSize = MAX_KEY_LEN;

              if ((dwError = RegQueryValueEx(hEntry,L"DisplayName",NULL,0,(LPBYTE)&wszDisplayName,&dwSize)) == ERROR_SUCCESS) {
              
                // if display name doesn't have "KB" in it
                // could be a problem since other applications could have KB in it
                entry.name = wszDisplayName;
                if (entry.name.find(L"KB") == std::wstring::npos) {

                  // query the version
                  wchar_t wszVersion[MAX_KEY_LEN];
                  dwSize = MAX_KEY_LEN;
                
                  // just continue if we don't get it
                  if ((dwError = RegQueryValueEx(hEntry,L"DisplayVersion",NULL,0,(LPBYTE)&wszVersion,&dwSize)) == ERROR_SUCCESS)
                    entry.version = wszVersion;

                  // if not listed get the publisher and save
                  if (!isListed(entry)) {

                    // query the publisher value
                    wchar_t wszPublisher[MAX_KEY_LEN];
                    dwSize = MAX_KEY_LEN;
                  
                    if (RegQueryValueEx(hEntry,L"Publisher",NULL,0,(LPBYTE)&wszPublisher,&dwSize) == ERROR_SUCCESS)
                      entry.publisher = wszPublisher;

                    // find the max length of strings so far
                    nName      = max(entry.name.length(),     nName);
                    nPublisher = max(entry.publisher.length(),nPublisher);
                    nVersion   = max(entry.version.length(),  nVersion);
                  
                    entry.bFilter = false;     // assume this isn't part of image

                    // add to list
                    entries.push_back(entry);
                  } // end if !bFound
                } // we found "KB" in display value..don't want these.
              } // end query of display
            } // SystemComponent
            RegCloseKey(hEntry);
          } // end if of open entry
        } // we found "KB" in key name, don't want these
      } // end for          
      RegCloseKey(hApplications);
    } // end open
  } // end for
  
  sortEntries();
  _InterlockedExchange(&lRunning,THREAD_STOPPED);
}

// check and replace any characters/symbols that cause problems in HTML format
// replace with HTML code equivilant
// not a complete list, but includes most encountered to date..
void rep_sym(std::wstring &str)
{
  std::wstring c = L"©";
  std::wstring t = L"™";
  std::wstring a = L"&";
  std::wstring r = L"®";

  if(str.find(r) != std::wstring::npos)
     str.replace(str.find(r),r.length(),L"&reg;");

  if(str.find(a) != std::wstring::npos)
     str.replace(str.find(a),a.length(),L"&amp;");

  if(str.find(c) != std::wstring::npos)
     str.replace(str.find(c),c.length(),L"&copy;");

  if(str.find(t) != std::wstring::npos)
     str.replace(str.find(t),t.length(),L"&#8482;");
}

bool Products::writeToHTML(std::wstring filename)
{
  // return if nothing to save
  if(entries.size() == 0) {
    dwError = ERROR_BAD_LENGTH;
    return false;
  }

  // open file for write access
  FILE *out = _wfopen(((filename.empty() ? host : filename) + L".html").c_str(),L"w");
  
  // return if not opened
  if(out == NULL) {
    dwError = GetLastError();
    return false;
  }
  
  // format the header
  std::wstring header = L"<html><head><title>"
                      + filename
                      + L"</title></head><body><table border=\"1\">"
                      + L"<tr>"
                      + L"<th>Application Name</th>"
                      + L"<th>Publisher</th>"
                      + L"<th>Version</th>"
                      + L"</tr>";
  fwprintf(out,header.c_str());
  
  int i = 0;

  // print the list
  for(std::vector<ProductEntry>::iterator it = entries.begin();it != entries.end();it++) {

    if(it->bFilter) continue;

    std::wstring name      = it->name;
    std::wstring publisher = it->publisher;

    // replace any copyright/trademark/registered symbols with html code
    rep_sym(name);
    rep_sym(publisher);

    std::wstring entry = ((i++ % 2) ? L"\n<tr>" : L"\n<tr bgcolor=#cccccc>")
                         + (L"<td>" + name      + L"</td>")
                         + (L"<td>" + (publisher.empty()   ? L"unspecified" : publisher)   + L"</td>")
                         + (L"<td>" + (it->version.empty() ? L"unspecified" : it->version) + L"</td>")
                         +  L"</tr>";

    fwprintf(out,entry.c_str());
  }
  fwprintf(out,L"</body></html>");
  fclose(out);
  dwError = ERROR_SUCCESS;
  
  return true;
}

// write the list of products to a text file
bool Products::writeToTXT(std::wstring filename)
{
  // return if nothing to save
  if(entries.size() == 0) {
    dwError = ERROR_BAD_LENGTH;
    return false;
  }

  // open file for write access
  // if no filename is specified, use the hostname
  FILE *out = _wfopen(((filename.empty() ? host : filename) + L".txt").c_str(),L"w");
  
  // return if not opened
  if(out == NULL) {
    dwError = GetLastError();
    return false;
  }

  writeToFile(out);
  fclose(out);
  
  dwError = ERROR_SUCCESS;
  return true;
}

// be careful to set nPublisher, nVersion and nName before calling this..
void Products::writeToFile(FILE* out)
{
  wchar_t *fmt = new wchar_t[nPublisher + nVersion + nName + 32];

  swprintf(fmt,L"\n%%-%ds  %%-%ds  %%-%ds",nName,nPublisher,nVersion);
  
  fwprintf(out,fmt,L"Application Name",L"Publisher",L"Version");
  fwprintf(out,fmt,L"================",L"=========",L"=======");

  for(std::vector<ProductEntry>::const_iterator it = entries.begin();it != entries.end();it++) {
    if (it->bFilter) continue;

    fwprintf(out,fmt,it->name.c_str(),it->publisher.c_str(),it->version.c_str());
  }
  delete []fmt;
}

// connect to remote registry
bool Products::connect()
{
  dwError = RegConnectRegistry(host.c_str(),HKEY_LOCAL_MACHINE,&hRegistry);
  return (dwError == ERROR_SUCCESS);
}

// sort in names of applications in ascending order
bool SortByName(ProductEntry rpStart, ProductEntry rpEnd)
{
  return ( lstrcmp( rpStart.name.c_str(), rpEnd.name.c_str() ) < 0);
}


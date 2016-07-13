
#ifndef PROFILES_H
#define PROFILES_H

#ifndef UNICODE
#define UNICODE
#endif

#include "Machine.h"
#include "Products.h"

struct ProductEntry;

struct OutlookEntry {
  std::wstring name;
  std::vector<std::wstring> mailbox;        // list of potential mailboxes
  std::vector<std::wstring> pst;            // list of potential pst files
};

struct ProfileEntry {
  std::wstring wszSid;
  std::wstring wszDomain;
  std::wstring wszId;
  std::wstring wszPath;

  std::vector<DWORD> dwEntries;           // per key, not total
  std::vector<HKEY> hKeys;

  std::vector<ProductEntry> products;
  std::vector<OutlookEntry> mail;
};

class Profiles {
  private:
    std::vector<ProfileEntry> profiles;
    class Machine* host;
    DWORD dwError;
    void getOutlookInfo(ProfileEntry &entry);
    bool getOutlookEntry(HKEY hProfiles,wchar_t* wszName,OutlookEntry &entry);
  public:
    Profiles(class Machine*);
    ~Profiles();
    
    std::vector<ProfileEntry> *get();
    DWORD GetError() { return dwError; }
};

#endif
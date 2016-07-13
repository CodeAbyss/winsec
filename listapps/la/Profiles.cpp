
/**
 *
 *  Gather list of user profiles on computer
 *  Works similar to System Device Manager applet -> Advanced -> User Profiles - sysdm.cpl
 *
 *  Copyright (c) 2010 -   <???@???>
 *
 */

#include "Profiles.h"

Profiles::Profiles(class Machine* host)
{
  this->host = host;
}

Profiles::~Profiles()
{
  for(std::vector<ProfileEntry>::iterator p = profiles.begin();p != profiles.end();p++) {
    for(std::vector<OutlookEntry>::iterator it = p->mail.begin();it != p->mail.end();it++) {
      it->mailbox.clear();
      it->pst.clear();
    }
  }
  profiles.clear();
}

std::vector<ProfileEntry>* Profiles::get()
{
  HKEY hProfiles;

  if(profiles.size() != 0) return &profiles;

  if ((dwError = RegOpenKeyEx(host->GetHKLM(),L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",0,
                              KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_WOW64_64KEY,&hProfiles)) == ERROR_SUCCESS) {
    DWORD dwUserIndex = 0;
    wchar_t wszUserSid[MAX_PATH];

    for(;;) {

      DWORD dwSize = MAX_PATH;
      dwError = RegEnumKeyEx(hProfiles,dwUserIndex++,wszUserSid,&dwSize,NULL,NULL,NULL,NULL);
      
      if(dwError == ERROR_NO_MORE_ITEMS) break;

      std::wstring sid = wszUserSid;
      // if local service or network, skip it
      if(sid == L"S-1-5-19" || sid == L"S-1-5-20") continue;

      PSID pSid;
      BOOL bResult = ConvertStringSidToSid(wszUserSid,&pSid);
      if(!bResult) continue;

      SID_NAME_USE snu;
      wchar_t* domain = NULL;
      DWORD domSize = 0;

      wchar_t* id = NULL;
      DWORD idSize = 0;

      LookupAccountSid(host->GetName(),pSid,id,&idSize,domain,&domSize,&snu);

      dwError = GetLastError();
      if(dwError != ERROR_NONE_MAPPED) {

        domain = new wchar_t[domSize];
        id = new wchar_t[idSize];

        bResult = LookupAccountSid(host->GetName(),pSid,id,&idSize,domain,&domSize,&snu);
        if(bResult) {
          HKEY hEntry;
          if((dwError = RegOpenKeyEx(hProfiles,wszUserSid,0,KEY_QUERY_VALUE,&hEntry)) == ERROR_SUCCESS) {
            DWORD dwSize = MAX_PATH;
            wchar_t path[MAX_PATH];
            if((dwError = RegQueryValueEx(hEntry,L"ProfileImagePath",NULL,0,(LPBYTE)&path,&dwSize)) == ERROR_SUCCESS) {
              ProfileEntry entry;

              entry.wszSid    = wszUserSid;
              entry.wszDomain = domain;
              entry.wszId     = id;
              entry.wszPath   = path;

              if(snu == SidTypeUser)
                getOutlookInfo(entry);
              
              profiles.push_back(entry);
            }
            RegCloseKey(hEntry);
          }
        }
        delete []domain;
        delete []id;
      }
      LocalFree(pSid);
    }
    RegCloseKey(hProfiles);
  }
  return &profiles;
}

bool Profiles::getOutlookEntry(HKEY hProfiles,wchar_t* wszName,OutlookEntry &entry)
{
  HKEY hEntry;

  if((dwError = RegOpenKeyEx(hProfiles,wszName,0,KEY_ENUMERATE_SUB_KEYS |
                                                 KEY_QUERY_VALUE |
                                                 KEY_WOW64_64KEY,&hEntry)) == ERROR_SUCCESS) {

    DWORD dwTotal = 0;
    RegQueryInfoKey(hEntry,NULL,NULL,NULL,&dwTotal,NULL,NULL,NULL,NULL,NULL,NULL,NULL);

    for(DWORD dwIndex = 0;dwIndex < dwTotal;dwIndex++) {
      wchar_t wszKeyName[MAX_PATH];
      DWORD dwSize = MAX_PATH;

      DWORD dwError = RegEnumKeyEx(hEntry,dwIndex,wszKeyName,&dwSize,NULL,NULL,NULL,NULL);
      if(dwError == ERROR_NO_MORE_ITEMS) break;

      HKEY hValue;
      if((dwError = RegOpenKeyEx(hEntry,wszKeyName,0,KEY_ENUMERATE_SUB_KEYS |
                                                     KEY_QUERY_VALUE |
                                                     KEY_WOW64_64KEY,&hValue)) == ERROR_SUCCESS) {

        DWORD dwTotalValues = 0;
        RegQueryInfoKey(hValue,NULL,NULL,NULL,NULL,NULL,NULL,&dwTotalValues,NULL,NULL,NULL,NULL);

        for(DWORD vIndex = 0;vIndex < dwTotalValues;vIndex++) {
          wchar_t wszValue[MAX_PATH];
          dwSize = MAX_PATH;
          dwError = RegEnumValue(hValue,vIndex,wszValue,&dwSize,NULL,NULL,NULL,NULL);
          if(dwError == ERROR_NO_MORE_ITEMS) break;

          std::wstring key = wszValue;
          // if ansi pst or unicode pst or mailbox
          if(key == L"001e6700" || key == L"001f6700" || key == L"001f3001") {   // 001e6600 = PAB
            wchar_t wszData[MAX_PATH];
            dwSize = MAX_PATH;
            dwError = RegQueryValueEx(hValue,wszValue,NULL,NULL,(LPBYTE)&wszData,&dwSize);
            if(dwError == ERROR_SUCCESS) {
              entry.name = wszName;
              std::wstring data = wszData;
              if(key == L"001f3001") {
                if(data.substr(0,7) == L"Mailbox") {
                  entry.mailbox.push_back(data);
                }
              } else {
                entry.pst.push_back(data);
              }
            }
          }
        }
        RegCloseKey(hValue);
      }
    }
    RegCloseKey(hEntry);
  }
  return (dwError == ERROR_SUCCESS || dwError == ERROR_NO_MORE_ITEMS);
}

void Profiles::getOutlookInfo(ProfileEntry &entry)
{
  std::wstring path = entry.wszSid + L"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles";

  HKEY hProfiles;

  if((dwError = RegOpenKeyEx(host->GetHKU(),path.c_str(),0,KEY_ENUMERATE_SUB_KEYS |
                                                           KEY_QUERY_VALUE |
                                                           KEY_WOW64_64KEY,&hProfiles)) == ERROR_SUCCESS) {

    // count how many profile entries exist
    DWORD dwTotal = 0;
    RegQueryInfoKey(hProfiles,NULL,NULL,NULL,&dwTotal,NULL,NULL,NULL,NULL,NULL,NULL,NULL);

    wchar_t wszName[MAX_PATH];
    DWORD dwSize = MAX_PATH;
    
    // for each profile found
    for(DWORD dwIndex = 0;dwIndex < dwTotal;dwIndex++) {
      DWORD dwError = RegEnumKeyEx(hProfiles,dwIndex,wszName,&dwSize,NULL,NULL,NULL,NULL);
      if(dwError == ERROR_NO_MORE_ITEMS) break;

      OutlookEntry mail_entry;

      // obtain PST files and mailbox names
      if(getOutlookEntry(hProfiles,wszName,mail_entry)) {
          entry.mail.push_back(mail_entry);
      }
    }
    RegCloseKey(hProfiles);
  } else printf("%d",dwError);
}


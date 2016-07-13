/*
  during the hardware lifecycle or M&A process, Outlook 2003 which my employer had built into the base operating system
  image had a wonderful habit of breaking down for some reasons the company couldn't investigate.
  
  it wasn't considered of high importance because the fix usually only took 5 minutes.
  however on some occasions it would take longer because the user had mailboxes or pst files going back 10 years
  so while it wasn't possible to investigate what corrupted the profiles after migration, it was possible
  to determine what PST files and Mailboxes the user had before hand which is what i'll describe in some detail before
  providing code to demonstrate the retrieval of PST and Mailbox values.
  
  we can list all profiles and the pst/mailboxes associated with each profile found
  or we can just list for 1 specific profile which for time sake, i'll show how to do.
  
  when we want to lookup outlook details for just 1 user id, we convert the name to string sid.

        convert the id to an SID and into string SID
        connect to remote registry on machine opening \\MACHINE\\HKEY_USERS\<SID>
        if this doesn't succeed, the user isn't logged in so we need to load hive in offline mode

        query %SystemDrive% from the registry
        open \\MACHINE\\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>
        query the ProfileImagePath value
        replace %SystemDrive% value in image path with result we got
        map image path folder e.g: \\MACHINE\C$\Documents and Settings\kdevin4
        load ntuser.dat and read the PST values if they exist
 */
#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <sddl.h>
#include <cstdio>
#include <string>

void error(DWORD errCode)
{
  wchar_t* msg;

  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                NULL,
                errCode,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&msg,
                0,
                NULL);

  wprintf(L"%s",msg);
  LocalFree(msg);
}

bool getSid(std::wstring machine, std::wstring id, std::wstring &domain, std::wstring &sid)
{
  DWORD cbSid = 0;
  DWORD cbDomain = 0;

  PSID pSid = NULL;
  wchar_t* pszDomain = NULL;

  SID_NAME_USE snu;

  LookupAccountName(machine.c_str(),id.c_str(),pSid,&cbSid,pszDomain,&cbDomain,&snu);
  
  if((pSid = new BYTE[cbSid]) != NULL) 
  {
    if((pszDomain = new wchar_t[cbDomain]) != NULL) 
    {
      if(LookupAccountName(machine.c_str(),id.c_str(),pSid,&cbSid,pszDomain,&cbDomain,&snu)) 
      {
        wchar_t* pszSid = NULL;
        if(ConvertSidToStringSid(pSid,&pszSid)) 
        {
          sid = pszSid;
          domain = pszDomain;
          LocalFree(pszSid);
        }
      }
      delete []pszDomain;
    } else SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    delete []pSid;
  } else SetLastError(ERROR_NOT_ENOUGH_MEMORY);

  return sid.length() != 0;
}

void wmain(int argc, wchar_t *argv[])
{
  if(argc != 3) {
    wprintf(L"\nUsage: %s <MACHINE> <USERID>\n",argv[0]);
    return;
  }

  std::wstring sid;
  std::wstring domain;

  if(getSid(argv[1],argv[2],domain,sid)) {
    wprintf(L"\nThe SID for %s on %s domain is %s\n",argv[2],domain.c_str(),sid.c_str());
  } else {
    wprintf(L"\nError getting SID: ");
    error(GetLastError());
  }
}

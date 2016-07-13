

#include "machine.h"

// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Printers
// Name, Location, Printer Driver

//

void error(DWORD);

void wmain(int argc, wchar_t *argv[])
{
  std::wstring host;

  if(argc == 2) host = argv[1];
  Machine* pc = new Machine(host);

  // display network info
  bool bOnline = pc->IsOnline();
  wprintf(L"\n%s is online: %s\nIp: %s\nHost: %s\n",pc->GetName(),bOnline ? L"Yes" : L"No",pc->GetIP(),pc->GetHostName());

  if(bOnline) {
    bool bConnected = true;
    // is computer remote? try connect
    if(argc == 2) {
      wprintf(L"\nConnecting to %s...",pc->GetName());
      bConnected = pc->connect();
      wprintf(L"%s - ", bConnected ? L"connected" : L"failed");
    }

    if(bConnected) {
      // display profiles
      std::vector<ProfileEntry> *q = pc->GetProfiles();
      if(q != NULL) {
        for(std::vector<ProfileEntry>::iterator it = q->begin();it != q->end();it++) {
          wprintf(L"\n%s\\%s",it->wszDomain.c_str(),it->wszId.c_str());

          // display outlook profiles if present
          for(std::vector<OutlookEntry>::iterator m = it->mail.begin();m != it->mail.end();m++) {
            wprintf(L"\n\tProfile: %s",m->name.c_str());
            // dump mailboxes
            for(std::vector<std::wstring>::size_type i(0);i < m->mailbox.size();i++) {
              wprintf(L"\nMailbox: %s",m->mailbox.at(i).c_str());
            }
            // dump pst files
            for(std::vector<std::wstring>::size_type i(0);i < m->pst.size();i++) {
              wprintf(L"\nPST: %s",m->pst.at(i).c_str());
            }
          }
        }
        // display products
        std::vector<ProductEntry> *p = pc->GetProducts();
        wprintf(L"\n\nApplications Found:%d\n",p->size());
        for(std::vector<ProductEntry>::iterator it = p->begin();it != p->end();it++) {
          wprintf(L"\n%s | %s | %s",it->name.c_str(),it->publisher.c_str(),it->version.c_str());
        }
      } else error(pc->GetError());
    } else error(pc->GetError());
  } // machine is offline
  delete pc;
}

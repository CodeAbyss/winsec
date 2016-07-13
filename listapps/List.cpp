
#include "network.h"
#include "console.h"
#include "products.h"

#include <sstream>

// global scope
Products* pc[2];
void startup();
const wchar_t* GetError(DWORD errCode, std::wstring &result);

/**
 *
 * main thread which calls EnumList()
 *
 */
DWORD ListAppsThread(LPVOID lpParameter)
{
  Products* apps = reinterpret_cast<Products*>(lpParameter);
  apps->enumEntries();
  return 0;
}

/**
 *
 * if the thread is currently running
 * get the total entries, current position and time started
 * calculate the percentage complete
 * then display to the user
 *
 */
void ShowProgress(Products* pList)
{
  DWORD dwSeconds,dwMinutes;
  dwSeconds = dwMinutes = 0;

  // if thread is still running
  if (pList->isRunning()) {
    DWORD dwIndex = pList->getCurrent();
    DWORD dwTotal = pList->getTotal();
    DWORD dwTick  = GetTickCount() - pList->getStart();
    
    if(dwIndex == 0 || dwTotal == 0) return;
    
    // ensure more than 1 second elapsed
    if (dwTick > 1000) {
      dwSeconds = dwTick / 1000;

      // calculate average speed for processing 1 entry
      DWORD dwSpeed = (dwSeconds / dwIndex);
      
      // ensure atleast 1 second per entry
      if (dwSpeed == 0) dwSpeed++;

      // calculate how many seconds remaining
      dwSeconds  = (dwTotal - dwIndex) * dwSpeed;

      // calculate the minutes and seconds - for such small numbers
      // it's not very useful here.
      if (dwSeconds >= 60) {
        dwMinutes = dwSeconds / 60;
        dwSeconds %= 60;
      }
    }
    
    double percentage = (100.0f * dwIndex) / (1.0f * dwTotal);
    
    print(L"\nProcessed %d out of %d entries on %s: %0.f%% complete. ETA: %02d:%02d",
      dwIndex,dwTotal,pList->host.c_str(),percentage,dwMinutes,dwSeconds);
  }
}

/**
 *
 *  confirms machine is online and if not prompts user what action to take
 *
 */
bool confirm(std::wstring computer)
{
  Network *net = new Network(computer);
  
  net->ping();
  std::wstring status = net->status();
  
  // if not resolved, computer name is probably invalid
  if(status == L"unresolved") {
    print(L"\nPing request could not find host \"%s\". Please check the name and try again.",computer.c_str());
    delete net;
    return false;
  }
  
  bool bReply = net->bReply;
  bool bOnline = net->bOnline;
  std::wstring host = net->name();
  std::wstring ip = net->ip();
  delete net;
  
  // if we have a ping status but not online, ask user if they want to continue
  if(!bOnline) {    
    print(L"\n%s [%s] appears to be offline at the moment.",host.c_str(),ip.c_str());
    print(L"\nPing status is: %s",status.c_str());
    print(L"\nConnect anyway? [Y/N]: ");
    wchar_t option;
    
    do {
      option = Console::getchar();
      option = toupper(option);
    } while(option != L'Y' && option != L'N');
    
    return option == L'Y';
  }
  return true;
}

bool openreg(Products* pList) {

  print(L"\nConnecting to %s...",pList->host.c_str());
  
  if(pList->connect()) {
    print(L"connected.");
    return true;
  }
  print(L"failed.");
  return false;
}

void menu(Products* pList)
{
  if(pList->entries.size() > 0)
  {
    Console::setBufWidth(pList->maxName() + pList->maxPublisher() + pList->maxVersion() + 32);
    pList->writeToFile(stdout);
    
    // ask user how to process entries
    print(L"\n\n\t1. Save to TXT file.");
    print(L"\n\t2. Save to HTML file.");
    print(L"\n\t3. Save to LAF file.");
    print(L"\n\t4. Exit.");
    print(L"\n\n\tEnter choice: ");
    
    wchar_t c;
    
    do {
       c = Console::getchar();
    } while (c < L'1' || c > L'4');
    
    if (c == L'1') {
      print(L"\n\tSaving to %s.txt : ",pList->host.c_str());
      pList->writeToTXT(pList->host);
    } else if (c == L'2') {
      print(L"\n\tSaving to %s.html : ",pList->host.c_str());
      pList->writeToHTML(pList->host);
    } else if (c == L'3') {
      print(L"\n\tSaving to %s.laf : ",pList->host.c_str());
      pList->writeToLAF(pList->host);
    } else {
      return;
    }
    std::wstring t;
    print(L"%s\n", GetError(pList->dwError,t)); 
  }
}

// list apps on local or remote computer
void list(std::wstring a)
{  
  startup();
  
  // if computer supplied, see if it's online
  if(!a.empty() && !confirm(a)) {
    print(L"Aborting..\n");
    return;
  }
  
  Products *apps = new Products(a);
  
  apps->loadLAF();
  
  if(openreg(apps)) {
    HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ListAppsThread,(LPVOID)apps,0,NULL);
  
    DWORD Y = Console::gety();
    Console::cursor(FALSE);
    //Console::clear();
    
    do {
      Console::sety(Y+1);
      DWORD dwStatus = WaitForSingleObject(hThread,1000);
      if(dwStatus == WAIT_OBJECT_0) break;
      ShowProgress(apps);  
    }while(true);
    
    Console::sety(Y+2);
    Console::cursor(TRUE);
    CloseHandle(hThread);
    
    print(L"\nThere are %d filtered and %d new applications to report.\n",apps->dwFiltered,apps->dwNew);
    if(apps->dwNew != 0) {
      menu(apps);
    }
  }
  delete apps;
}

// compare apps on 2 computers and display the differences
void compare(std::wstring a, std::wstring b)
{
  startup();
  
  if(a == b) {
    print(L"\nBoth machines are the same.\n");
    return;
  }
  
  // we assume both computer names present
  // if we can't connect to one, abort
  if(!confirm(a) || !confirm(b)) {
    print(L"\nAborting..\n");
    return;
  }
  
  pc[0] = new Products(a);
  pc[1] = new Products(b);
  
  if(pc[0]->host == pc[1]->host) {
    print(L"\nBoth machines are the same.\n");
    return;
  }
  
  print(L"\n\nWill list applications on old machine: %s which are missing from new machine: %s\n",
        pc[0]->host.c_str(),pc[1]->host.c_str());
  
  pc[0]->loadLAF();
  pc[1]->loadLAF();
  
  if(openreg(pc[0]) && openreg(pc[1])) {
    HANDLE hThreads[2];
    
    hThreads[0] = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ListAppsThread,(LPVOID)pc[0],0,NULL);
    hThreads[1] = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ListAppsThread,(LPVOID)pc[1],0,NULL);
  
    DWORD Y = Console::gety();
    Console::cursor(FALSE);

    //Console::clear();
    
    DWORD count = 0;
    do {
      Sleep(1000);
      
      DWORD idx;
      count = 0;
      for(idx = 0;idx < 2;idx++) {
        if(pc[idx]->isRunning()) {
          Console::sety(Y + idx + 1);
          ShowProgress(pc[idx]);
          count++;
        }
      }
      
    }while(count != 0);
    
    Console::sety(Y + 4);
    Console::cursor(TRUE);
    
    CloseHandle(hThreads[1]);
    CloseHandle(hThreads[0]);
    
    // remove applications found in list b from list a
    Products *c = new Products(pc[0]->host);
    c->remove(c,pc[0],pc[1]);
    
    print(L"\nThere are %d applications to report.\n",c->entries.size());
    if(c->entries.size() != 0) {
      menu(c);
    }
    delete c;
  }
  delete pc[0];
  delete pc[1];
}
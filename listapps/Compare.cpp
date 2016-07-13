
#include "machine.h"

class Machine* new_machine;
class Machine* old_machine;

/*
 * if the app name and version from old machine doesn't exist on new machine, display it.
 *
 */
void GetDifferences(vector<product_info> &products)
{
  product_info entry;
  
  for (vector<product_info>::iterator old_it = machines[0]->GetAppList()->products.begin();old_it != machines[0]->GetAppList()->products.end();old_it++) {
    if(old_it->bImage) continue;
    
    bool bFound = false;
    for (vector<product_info>::iterator new_it = machines[1]->GetAppList()->products.begin();new_it != machines[1]->GetAppList()->products.end();new_it++) {
      
      // names are the same, so the application exists on the new machine
      if(old_it->name == new_it->name) {
        
        // but are they the same versions?
        // yes, break out of loop
        if(old_it->version == new_it->version) {
          bFound = true;
          break;
        }
        
        // if either version is empty, don't report this either.
        if(old_it->version.empty() || new_it->version.empty()) {
          bFound = true;
          break;
        }
        
        // the versions are different, but it's possible we might find it later in the list
        // check the remaining in list
        for(vector<product_info>::iterator cur_it = new_it;cur_it != machines[1]->GetAppList()->products.end();cur_it++) {
          if(old_it->name == cur_it->name && old_it->version == cur_it->version) {
            bFound = true;
            break;
          }
        }
        
        // if we didn't find in remaining list, save newer version in old entry
        if(!bFound) {
          old_it->versions.push_back(new_it->version);
          //entry.bImage = false;
          //entry.bNewer = true;
          //entry.name = new_it->name;
          //entry.version = new_it->version;
          //entry.publisher = new_it->publisher;
          //products.push_back(entry);
        }
      }
    }
    // old entry wasn't found, save it
    if(!bFound) {
      entry.bImage = false;
      entry.bNewer = old_it->bNewer;
      entry.name = old_it->name;
      entry.publisher = old_it->publisher;
      entry.version = old_it->version;
      entry.versions = old_it->versions;
      products.push_back(entry);
    }
  }
  if(products.size() > 1) sort(products.begin(),products.end(),SortByName2);
}

/*
 * the file contains a list of apps to exclude in compare
 *
 */
void load_filter(wstring file) {

  FILE* in;
  in = _wfopen(file.c_str(),"rb");
  if(in != NULL) {
    DWORD line_number = 0;
    wchar_t delim = L'\0xFFFF';
    while(!feof(in)) {
      line_number++;
      fgetws(line,BUFSIZE,in);
      wchar_t *tokens = wcstok(line,delim);
      if(tokens == NULL) {
        wprintf(L"\nError reading line in %s at %d",file.c_str(),line_number);
      } else {
        product_info entry;
        
        entry.bImage = true;
        entry.name = wcstok(NULL,delim);
        entry.publisher = wcstok(NULL,delim);
        entry.version = wcstok(NULL,delim);
        
        new_machine->GetAppList()->products.push_back(entry);
        old_machine->GetAppList()->products.push_back(entry);
      }
    }
  }
}

/*
 * get list of applications on both machines and display list of differences
 *
 * 
 */
bool compare(wstring machine_a, wstring machine_b) {
  
  old_machine = new Machine(machine_a);
  new_machine = new Machine(machine_b);
  
  // verify both machines are online
  if(confirm(old_machine) && confirm(new_machine)) {
    
    // ensure connection to registry on both machines available
    if(connect(old_machine) && connect(new_machine)) {
      HANDLE hThreads[2];
      
      // create thread for old machine
      hThreads[0] = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ListAppsThread,(LPVOID)machines[0],CREATE_SUSPENDED,NULL);
      if(hThreads[0] != NULL) {
        // create thread for new machine
        hThreads[1] = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)ListAppsThread,(LPVOID)machines[1],CREATE_SUSPENDED,NULL);
        if(hThreads[1] != NULL) {
          SetConsoleCtrlHandler((PHANDLER_ROUTINE)HandlerRoutine,TRUE);
          
          // resume threads
          ResumeThread(hThreads[0]);
          ResumeThread(hThreads[1]);
          
          wprintf(L"\n");
          
          CONSOLE_SCREEN_BUFFER_INFO csbi;
          GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
          
          CONSOLE_CURSOR_INFO cci;
          GetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE),&cci);
          
          cci.bVisible = FALSE;
          SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE),&cci);
          
          do {
            DWORD dwTotal = 0;
            Sleep(1000);          // wait for 1 second to pass
            
            for(DWORD idx = 0;idx < 2;idx++) {
              COORD pos;
              pos.X = csbi.dwCursorPosition.X;
              pos.Y = csbi.dwCursorPosition.Y + (idx + 1);
              SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE),pos);
                  
              if(machines[idx]->GetAppList()->isRunning()) {
                dwTotal++;
                ShowProgress(machines[idx]);
              }
            }
            if(dwTotal == 0) break;
          } while(true);
              
          cci.bVisible = TRUE;
          SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE),&cci);
                
          // compare lists
          vector<product_info> products;
          GetDifferences(products);
          
          if(products.size() > 0) {
            wprintf(L"\nListing %d applications on %s that weren't found on %s\n"
                    L"Note some of the applications might be part of the image or have different versions.\n",
                    products.size(),machines[0]->getName(),machines[1]->getName());
              
            ListOnScreen(products);
          } else {
            wprintf(L"\n\tNo differences found");
          }
          
          wprintf(L"\n\n");
          
          CloseHandle(hThreads[1]);
        }
        CloseHandle(hThreads[0]);
      }
    }
  }
  
  delete machines[0];
  delete machines[1];
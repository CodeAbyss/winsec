
#ifndef MACHINE_H
#define MACHINE_H

#ifndef UNICODE
#define UNICODE
#endif

#include <intrin.h>

// C++ libs
#include <string>
#include <vector>
#include <algorithm>

using namespace std;

class Machine {
  private:
    BOOL FlushDnsCache();
    VOID ResolveHost();
    VOID ResolveStatus(host_entry& entry);
    HKEY hRegistry;
    class AppList* pList; 
    
    wstring name;     // supplied by user when created
    
    vector<host_entry> hostlist;   
  public:
    Machine(wstring computer);
    ~Machine();
    
    bool isOnline();
    bool isResponding();
    
    DWORD dwError;
    
    HKEY GetRegHandle();
    bool RegConnect();
    
    class AppList* GetAppList();
};

#endif
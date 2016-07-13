
// Products.h

#ifndef PRODUCTS_H
#define PRODUCTS_H

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <intrin.h>

#include <vector>
#include <string>
#include <sstream>
#include <algorithm>

enum {THREAD_STOPPED=1,THREAD_RUNNING};

// 32-bit key
#define APPS_KEY_A L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
// 64-bit key
#define APPS_KEY_B L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

#define MAX_KEY_LEN   260

// structure for each application found
struct ProductEntry {
  std::wstring name;
  std::wstring publisher;
  std::wstring version;
  
  // below only used during comparison of machines
  bool bFilter;                         // exclude from processing
  std::vector<std::wstring> versions;   // different versions
};

bool SortByName(ProductEntry rpStart, ProductEntry rpEnd);

class Products {
  private:
    size_t nName;
    size_t nVersion;
    size_t nPublisher;
    
    DWORD dwStart;
    DWORD dwTotal;
    DWORD dwIndex;
    
    HKEY hRegistry;
    long lRunning;

  public:
    Products(std::wstring);
    ~Products();
    
    DWORD dwFiltered;              // number of apps in list filtered

    bool writeToTXT(std::wstring);
    bool writeToHTML(std::wstring);
    void writeToFile(FILE*);

    std::vector<ProductEntry> entries;
    void sortEntries() { sort(entries.begin(),entries.end(),SortByName); }
    void enumEntries();
    void getTotalEntries(DWORD dwEntries[]);
    void remove(Products* c, Products* a, Products* b);
    bool isListed(ProductEntry entry);

    // progress related functions
    bool isRunning() { return _InterlockedCompareExchange(&lRunning,0,0) == THREAD_RUNNING; }
    void stop()      { _InterlockedExchange(&lRunning,THREAD_STOPPED);                      }
    bool connect();

    DWORD getStart()      { return _InterlockedCompareExchange(reinterpret_cast<volatile long*>(&dwStart),0,0); }
    DWORD getTotal()      { return _InterlockedCompareExchange(reinterpret_cast<volatile long*>(&dwTotal),0,0); }
    DWORD getCurrent()    { return _InterlockedCompareExchange(reinterpret_cast<volatile long*>(&dwIndex),0,0); }

    size_t maxName()      { return nName;      }
    size_t maxVersion()   { return nVersion;   }
    size_t maxPublisher() { return nPublisher; }
    
    std::wstring host;
    DWORD dwError;
};

#endif

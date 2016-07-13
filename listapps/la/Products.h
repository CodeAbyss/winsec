
// Products.h

#ifndef PRODUCTS_H
#define PRODUCTS_H

#ifndef UNICODE
#define UNICODE
#endif

#include "Machine.h"
#include "Profiles.h"

struct ProfileEntry;

// structure for each application found
struct ProductEntry {
  std::wstring name;
  std::wstring publisher;
  std::wstring version;
  
  // below only used during comparison of machines
  bool bFilter;                         // exclude from processing
  std::vector<std::wstring> versions;   // different versions
};

class Products {
  private:
    std::vector<ProductEntry> products;              // internal list that represents machine

    bool isListed(std::vector<ProductEntry> entries, ProductEntry entry);
    bool getEntry(HKEY hAppKey, std::wstring regKey, ProductEntry &entry);
    void getKeyCount(HKEY hRootKey,std::wstring path,ProfileEntry* p);

    DWORD dwError;
    DWORD dwTotal;

    class Machine* host;
  public:
    Products(class Machine*);
    ~Products();
    
    DWORD getTotal();
    std::vector<ProductEntry> *get();
    DWORD GetError() { return dwError; }
};

#endif

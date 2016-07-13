
#ifndef NETWORK_H
#define NETWORK_H

#ifndef UNICODE
#define UNICODE
#endif

#include "Machine.h"

class Network {
  private:
    IPAddr ip_addr;
    struct addrinfoW *aiList;
    
    DWORD dwStatus;
    
    BOOL flushdns();
    
    std::wstring hostname;
    std::wstring fqdn;
    std::wstring ip_address;
    
    bool resolve();
    class Machine* host;
  public:
    Network(class Machine*);
    ~Network();
    
    const wchar_t* name();
    const wchar_t* ip();
    const wchar_t* status();
    
    bool ping();
    
    bool bOnline;
    bool bReply;
};

#endif
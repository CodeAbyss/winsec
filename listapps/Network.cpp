
#include "network.h"

Network::Network(std::wstring computerName) 
{
  hostname = computerName;
  bReply = false;
  bOnline = false;
  aiList = NULL;
  
  WSADATA wsa;
  WSAStartup(MAKEWORD(2,0),&wsa);
}

Network::~Network()
{
  WSACleanup();
}

/**
 *
 *  return the hostname of computer
 *
 */
const wchar_t* Network::name()
{
  if(aiList == NULL)
    if(!resolve()) return L"unknown";
  
  wchar_t nameinfo[NI_MAXHOST]={0};
  GetNameInfo(aiList->ai_addr,sizeof(struct sockaddr),nameinfo,NI_MAXHOST,NULL,0,0);
  fqdn = nameinfo[0] == 0 ? L"unknown" : nameinfo;
  return fqdn.c_str();
}

/**
 *
 *  return the ip address of computer
 *
 */
const wchar_t* Network::ip() 
{
  if(aiList == NULL)
    if(!resolve()) return L"0.0.0.0";
    
  DWORD addr_size = 64;
  wchar_t address[64]={0};
  if(WSAAddressToString(aiList->ai_addr,(DWORD)aiList->ai_addrlen,NULL,address,&addr_size) != SOCKET_ERROR) {
    ip_address = address;
    return ip_address.c_str();
  }
  return L"0.0.0.0";
}

/**
 *
 *  ping computer and see if any response
 *
 */
bool Network::ping()
{
  bReply = false;
  bOnline = false;
  
  if(aiList == NULL)
    if(!resolve()) return false;
    
  HANDLE hIcmpFile = IcmpCreateFile();
  
  if(hIcmpFile != INVALID_HANDLE_VALUE)
  {
    // setup packet data
    wchar_t SendData[4];
    LPVOID ReplyBuffer[sizeof(ICMP_ECHO_REPLY) + sizeof(SendData)*2];
    DWORD ReplySize = sizeof(ReplyBuffer);
    
    // send packet with 1 second timeout
    // the return value is number of replies
    bReply = IcmpSendEcho(hIcmpFile,ip_addr,SendData,sizeof(SendData),NULL,ReplyBuffer,ReplySize,1500) != 0;
    
    // save the status code
    dwStatus  = ((PICMP_ECHO_REPLY)ReplyBuffer)->Status;
    bOnline   = (dwStatus == IP_SUCCESS);
    
    IcmpCloseHandle(hIcmpFile);
  }
  return bOnline;
}

/**
 *
 *  see if we can resolve a computer name to network address
 *
 */
bool Network::resolve() 
{ 
  // if this isn't our first call, free the previous list
  if(aiList != NULL) {
    FreeAddrInfo(aiList);
    aiList = NULL;
  }
 
  // try flush the dns cache
  flushdns();
  
  // setup hints
  struct addrinfoW aiHints;
  ZeroMemory(&aiHints, sizeof(aiHints));

  aiHints.ai_family   = AF_INET;      // only return TCP IPv4 addresses
  aiHints.ai_socktype = SOCK_STREAM;
  aiHints.ai_protocol = IPPROTO_TCP;

  // get all resolvable addresses
  if(GetAddrInfo(hostname.c_str(),NULL,&aiHints,&aiList) == 0) {
  
    // if we get anything, save the first address in list
    if(aiList != NULL) {
      ip_addr = *((IPAddr*)(&aiList->ai_addr->sa_data[2]));
    }
  }
  return (aiList != NULL);
}
    
/**
 *
 * Uses undocumented API from DNSAPI.DLL
 *
 * Same as : ipconfig /flushdns
 *
 */
BOOL Network::flushdns()
{
  BOOL bResult = FALSE;

  BOOL (WINAPI *DoDnsFlushResolverCache)();
  HMODULE hDNS = LoadLibrary(L"dnsapi");

  if (hDNS != NULL) 
  {
    *(FARPROC *)&DoDnsFlushResolverCache = GetProcAddress(hDNS, "DnsFlushResolverCache");
    
    if (DoDnsFlushResolverCache != NULL) 
    {
      bResult = DoDnsFlushResolverCache();
    }
    FreeLibrary(hDNS);
  }
  return bResult;
}

// icmp status messages
struct ip_status {
  DWORD dwCode;
  const wchar_t *pMessage;
};

ip_status pStatus[20]={ 
  { IP_SUCCESS,               L"The status was success" }, 
  { IP_BUF_TOO_SMALL,         L"The reply buffer was too small" },
  { IP_DEST_NET_UNREACHABLE,  L"The destination network was unreachable" },
  { IP_DEST_HOST_UNREACHABLE, L"The destination host was unreachable" },
  { IP_DEST_PROT_UNREACHABLE, L"The destination protocol was unreachable" },
  { IP_DEST_PORT_UNREACHABLE, L"The destination port was unreachable" },
  { IP_NO_RESOURCES,          L"Insufficient IP resources were available" },
  { IP_BAD_OPTION,            L"A bad IP option was specified" },
  { IP_HW_ERROR,              L"A hardware error occurred" },
  { IP_PACKET_TOO_BIG,        L"The packet was too big" },
  { IP_REQ_TIMED_OUT,         L"The request timed out" },
  { IP_BAD_REQ,               L"A bad request" },
  { IP_BAD_ROUTE,             L"A bad route" },
  { IP_TTL_EXPIRED_TRANSIT,   L"The time to live (TTL) expired in transit" },
  { IP_TTL_EXPIRED_REASSEM,   L"The time to live expired during fragment reassembly" },
  { IP_PARAM_PROBLEM,         L"A parameter problem" },
  { IP_SOURCE_QUENCH,         L"Datagrams are arriving too fast to be processed and datagrams may have been discarded" },
  { IP_OPTION_TOO_BIG,        L"An IP option was too big" },
  { IP_BAD_DESTINATION,       L"A bad destination" },
  { IP_GENERAL_FAILURE,       L"A general failure. This error can be returned for some malformed ICMP packets" }
};

// translate status code to something friendly
const wchar_t* Network::status() {

  if(aiList == NULL)
    if(!resolve()) return L"unresolved";
    
  for(int i(0);i < sizeof(pStatus) / sizeof(ip_status);i++) {
    if(dwStatus == pStatus[i].dwCode) {
      return pStatus[i].pMessage;
    }
  }
  return L"Status is unknown";
}
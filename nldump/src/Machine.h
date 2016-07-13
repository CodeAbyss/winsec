
#ifndef MACHINE_H
#define MACHINE_H

//#pragma pack(push)  /* push current alignment to stack */
//#pragma pack(1)     /* set alignment to 1 byte boundary */

#include <windows.h>
#include <winsvc.h>

#include <cstdio>
#include <cstdlib>
#include <cctype>

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

#define LOGON32_LOGON_NEW_CREDENTIALS   9
#define LOGON32_PROVIDER_WINNT50        3

#define SAM_KEY      0
#define SYSTEM_KEY   1
#define SECURITY_KEY 2
#define SOFTWARE_KEY 3

typedef struct _ENCRYPTED_LM_OWF_PASSWORD {
    unsigned char data[16];
} ENCRYPTED_LM_OWF_PASSWORD, *PENCRYPTED_LM_OWF_PASSWORD,
  ENCRYPTED_NT_OWF_PASSWORD, *PENCRYPTED_NT_OWF_PASSWORD;

typedef struct _USER_INTERNAL1_INFORMATION {
    ENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword;
    ENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword;
    unsigned char NtPasswordPresent;
    unsigned char LmPasswordPresent;
    unsigned char PasswordExpired;
} USER_INTERNAL1_INFORMATION, *PUSER_INTERNAL1_INFORMATION;

class Machine {
  private:
    // these routines use the ADMIN$ for establishing connection with alternate
    // credentials..however they don't seem to work for Vista/Win2k8 and Win7
    wchar_t *szMachine;
    SC_HANDLE hSCManager;

    wchar_t SystemRoot[MAX_PATH];
    wchar_t ProductName[MAX_PATH];

    bool NBDisconnect();
    bool NBConnect(wchar_t machine[], wchar_t username[], wchar_t password[]);
    bool EnablePrivilege(HANDLE hToken, const wchar_t szPrivilege[], bool bFlag);
    bool GetSystemInfo();

    bool OpenServices();
    void CloseServices();
    bool IsRegServiceRunning();
    bool StartRegService();

    HANDLE hRemoteToken;                // when working remotely, a token returned by LogonUser()
  protected:
    wchar_t *lpszHiveNames[4];

    DWORD dwError;                      // used by any class to record the last error
    HKEY hRegistry;                     // HKEY_LOCAL_MACHINE or handle returned by RegConnectRegistry()

    bool bDebug;                        // only relevant to command line, prints extra output
    bool bRemote;                       // connection is remote

    void dump_hex(const wchar_t str[], unsigned char pData[], size_t nDataSize);

  public:
    Machine();
    ~Machine();

    bool CreateToken(wchar_t machine[], wchar_t domain[], wchar_t username[], wchar_t password[]);
    bool Disconnect();

    // external methods
    bool LoadHives(wchar_t[]);
    void UnloadHives();

    bool EnableRemoteRegistry();
    bool ConnectRegistry();
    DWORD GetRegistryState();

    DWORD GetErrorCode();               // return the last error
    bool GetOS(wchar_t product[]);
};

#endif

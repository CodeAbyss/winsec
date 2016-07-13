
#ifndef SAM_H
#define SAM_H

#include "crypto/rc4.h"
#include "crypto/md5.h"
#include "crypto/des.h"

#include "Syskey.h"

typedef struct _SAM_PASSWORDS {
    USER_INTERNAL1_INFORMATION SecretPasswords;
} SAM_PASSWORDS, *PSAM_PASSWORDS;

struct SAM_DATA {
  DWORD   dwSize;
  PBYTE   Buffer;
};

struct SAM_REG_ENTRY {
  wchar_t    szKeyName[MAX_KEY_LENGTH];
  SAM_DATA   SamData;
};

struct SAM_ENTRY {
  wchar_t UserName[260];
  unsigned long Rid;
  SAM_PASSWORDS SamPasswords;
  wchar_t FullName[260];
  wchar_t Comment[260];
  wchar_t HomeDir[260];
  wchar_t PassHint[260];
};

struct SAM_LIST {
  SAM_ENTRY *entry;
  SAM_LIST  *next;
};

class Sam : virtual public Syskey
{
  private:
    void ClearEntries();
    void AddEntryToList(SAM_REG_ENTRY*);
    bool GetEntry(SAM_REG_ENTRY*);

    void DecryptHash_v1(unsigned long rid,char input_key[],unsigned char ciphertext[],unsigned char plaintext[]);

    SAM_LIST *slist;
    SAM_LIST *current;
  protected:
    unsigned char samkey[32];
  public:
    Sam();
    ~Sam();
    bool GetSamKey();                       // required before calling GetSamEntries()
    SAM_LIST* GetSamEntries();
    void GetLMHash(const wchar_t [],unsigned char []);
};

#endif

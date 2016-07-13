

// SHA-1 in C
// Odzhan

#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <string.h>

#define SHA1_CBLOCK        64
#define SHA1_DIGEST_LENGTH 20
#define SHA1_LBLOCK        SHA1_DIGEST_LENGTH/4

#pragma pack(push, 1)
typedef struct _SHA1_CTX {
  union {
    uint8_t  v8[SHA1_DIGEST_LENGTH];
    uint32_t v32[SHA1_DIGEST_LENGTH/4];
  } state;
  union {
    uint8_t v8[SHA1_CBLOCK];
    uint32_t v32[SHA1_CBLOCK/4];
    uint64_t v64[SHA1_CBLOCK/8];
  } buffer;
  uint64_t len;
} SHA1_CTX;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

  void SHA1_Init (SHA1_CTX*);
  void SHA1_Update (SHA1_CTX*, void*, size_t);
  void SHA1_Final (void*, SHA1_CTX*);

#ifdef __cplusplus
}
#endif

#endif

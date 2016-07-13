

// SHA-2 in C
// Odzhan

#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>
#include <string.h>

#define SHA256_CBLOCK        64
#define SHA256_DIGEST_LENGTH 32
#define SHA256_LBLOCK        SHA256_DIGEST_LENGTH/4

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#pragma pack(push, 1)
typedef struct _SHA256_CTX {
  union {
    uint8_t  v8[SHA256_DIGEST_LENGTH];
    uint32_t v32[SHA256_LBLOCK];
  }state;
  union {
    uint8_t  v8[SHA256_CBLOCK];
    uint32_t v32[SHA256_CBLOCK/4];
    uint64_t v64[SHA256_CBLOCK/8];
  } buffer;
  uint64_t len;
} SHA256_CTX;
#pragma pack(pop)

#define SHA512_CBLOCK        128
#define SHA512_DIGEST_LENGTH 64
#define SHA512_LBLOCK        SHA512_DIGEST_LENGTH/4

#pragma pack(push, 1)
typedef struct _SHA512_CTX {
  union {
    uint8_t  v8[SHA512_DIGEST_LENGTH];
    uint32_t v32[SHA512_LBLOCK];
  }state;
  union {
    uint8_t  v8[SHA512_CBLOCK];
    uint32_t v32[SHA512_CBLOCK/4];
    uint64_t v64[SHA512_CBLOCK/8];
  } buffer;
  uint64_t len[2];
} SHA512_CTX;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

  void SHA256_Init (SHA256_CTX*);
  void SHA256_Update (SHA256_CTX*, void*, size_t);
  void SHA256_Final (void*, SHA256_CTX*);

  void SHA512_Init (SHA512_CTX*);
  void SHA512_Update (SHA512_CTX*, void *, size_t);
  void SHA512_Final (void*, SHA512_CTX*);
  
#ifdef __cplusplus
}
#endif

#endif
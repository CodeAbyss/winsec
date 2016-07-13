

// MD5 in C
// Odzhan

#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <string.h>

#define MD5_CBLOCK  64
#define MD5_DIGEST_LENGTH 16
#define MD5_LBLOCK MD5_DIGEST_LENGTH/4

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#pragma pack(push, 1)
typedef struct _MD5_CTX {
  union {
    uint8_t v8[MD5_DIGEST_LENGTH];
    uint32_t v32[MD5_DIGEST_LENGTH/4];
  } state;
  union {
    uint8_t v8[MD5_CBLOCK];
    uint32_t v32[MD5_CBLOCK/4];
    uint64_t v64[MD5_CBLOCK/8];
  } data;
  uint64_t len;
} MD5_CTX;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

  void MD5_Init (MD5_CTX*);
  void MD5_Update (MD5_CTX*, void *, size_t);
  void MD5_Final (void*, MD5_CTX*);

#ifdef __cplusplus
}
#endif

#endif

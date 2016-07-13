

// MD4 in C
// Odzhan

#ifndef MD4_H
#define MD4_H

#include <stdint.h>
#include <string.h>

#define MD4_CBLOCK        64
#define MD4_DIGEST_LENGTH 16
#define MD4_LBLOCK        MD4_DIGEST_LENGTH/4

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

#pragma pack(push, 1)
typedef struct _MD4_CTX {
  union {
    uint8_t   v8[MD4_DIGEST_LENGTH];
    uint16_t v16[MD4_DIGEST_LENGTH/2];
    uint32_t v32[MD4_DIGEST_LENGTH/4];
    uint64_t v64[MD4_DIGEST_LENGTH/8];
  } state;
  union {
    uint8_t   v8[MD4_CBLOCK];
    uint16_t v16[MD4_CBLOCK/2];
    uint32_t v32[MD4_CBLOCK/4];
    uint64_t v64[MD4_CBLOCK/8];
  } buffer;
  uint64_t len;
} MD4_CTX;
#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

  void MD4_Init (MD4_CTX*);
  void MD4_Update (MD4_CTX*, void*, size_t);
  void MD4_Final (void*, MD4_CTX*);
  
#ifdef __cplusplus
}
#endif

#endif

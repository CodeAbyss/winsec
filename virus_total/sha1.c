

// SHA-1
// Odzhan

#include "sha1.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#define U8V(v)  ((uint8_t)(v)  & 0xFFU)
#define U16V(v) ((uint16_t)(v) & 0xFFFFU)
#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFFUL)
#define U64V(v) ((uint64_t)(v) & 0xFFFFFFFFFFFFFFFFULL)

#define ROTL8(v, n) \
  (U8V((v) << (n)) | ((v) >> (8 - (n))))

#define ROTL16(v, n) \
  (U16V((v) << (n)) | ((v) >> (16 - (n))))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define ROTL64(v, n) \
  (U64V((v) << (n)) | ((v) >> (64 - (n))))

#define ROTR8(v, n) ROTL8(v, 8 - (n))
#define ROTR16(v, n) ROTL16(v, 16 - (n))
#define ROTR32(v, n) ROTL32(v, 32 - (n))
#define ROTR64(v, n) ROTL64(v, 64 - (n))

#define SWAP16(v) \
  ROTL16(v, 8)

#define SWAP32(v) \
  ((ROTL32(v,  8) & 0x00FF00FFUL) | \
   (ROTL32(v, 24) & 0xFF00FF00UL))

#define SWAP64(v) \
  ((ROTL64(v,  8) & 0x000000FF000000FFULL) | \
   (ROTL64(v, 24) & 0x0000FF000000FF00ULL) | \
   (ROTL64(v, 40) & 0x00FF000000FF0000ULL) | \
   (ROTL64(v, 56) & 0xFF000000FF000000ULL))

/************************************************
*
* transform a block of data.
*
************************************************/
void SHA1_Transform (SHA1_CTX *ctx) 
{
  uint32_t a, b, c, d, e, t, i;
  uint32_t w[80];

  // copy buffer to local
  for (i=0; i<16; i++) {
    w[i] = SWAP32(ctx->buffer.v32[i]);
  }
  
  // expand it
  for (i=16; i<80; i++) {
    w[i] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
  }
  
  // load state
  a = ctx->state.v32[0];
  b = ctx->state.v32[1];
  c = ctx->state.v32[2];
  d = ctx->state.v32[3];
  e = ctx->state.v32[4];
  
  // for 80 rounds
  for (i=0; i<80; i++) {
    if (i<20) {
      t = (d ^ (b & (c ^ d))) + 0x5A827999L;
    } else if (i<40) {
      t = (b ^ c ^ d) + 0x6ED9EBA1L;
    } else if (i<60) {
      t = ((b & c) | (d & (b | c))) + 0x8F1BBCDCL;
    } else {
      t = (b ^ c ^ d) + 0xCA62C1D6L;
    }
    t += ROTL32(a, 5) + e + w[i];
    e = d;
    d = c;
    c = ROTL32(b, 30);
    b = a;
    a = t;
  }
  
  // update state
  ctx->state.v32[0] += a;
  ctx->state.v32[1] += b;
  ctx->state.v32[2] += c;
  ctx->state.v32[3] += d;
  ctx->state.v32[4] += e;
}

/************************************************
*
* initialize context
*
************************************************/
void SHA1_Init (SHA1_CTX *ctx) {
  ctx->len  = 0;
  ctx->state.v32[0] = 0x67452301;
  ctx->state.v32[1] = 0xefcdab89;
  ctx->state.v32[2] = 0x98badcfe;
  ctx->state.v32[3] = 0x10325476;
  ctx->state.v32[4] = 0xc3d2e1f0;
}

/************************************************
*
* update state with input
*
************************************************/
void SHA1_Update (SHA1_CTX *ctx, void *in, size_t len) {
  uint8_t *p = (uint8_t*)in;
  size_t  r, idx;
  
  // get buffer index
  idx = ctx->len & SHA1_CBLOCK - 1;
  
  // update length
  ctx->len += len;
  
  do {
    r = MIN(len, SHA1_CBLOCK - idx);
    memcpy ((void*)&ctx->buffer.v8[idx], p, r);
    if ((idx + r) < SHA1_CBLOCK) break;
    
    SHA1_Transform (ctx);
    len -= r;
    idx = 0;
    p += r;
  } while (1);
}

/************************************************
*
* finalize.
*
************************************************/
void SHA1_Final (void* dgst, SHA1_CTX *ctx)
{
  int i;
  // see what length we have ere..
  uint32_t len=ctx->len & SHA1_CBLOCK - 1;
  // fill remaining space with zeros
  memset (&ctx->buffer.v8[len], 0, SHA1_CBLOCK - len);
  // add the end bit
  ctx->buffer.v8[len] = 0x80;
  // if exceeding 56 bytes, transform it
  if (len >= 56) {
    SHA1_Transform (ctx);
    // clear buffer
    memset (&ctx->buffer.v8, 0, SHA1_CBLOCK);
  }
  // add total bits
  ctx->buffer.v64[7] = SWAP64(ctx->len * 8);
  // compress
  SHA1_Transform(ctx);
  // swap byte order
  for (i=0; i<SHA1_LBLOCK; i++) {
    ctx->state.v32[i] = SWAP32(ctx->state.v32[i]);
  }
  // copy digest to buffer
  memcpy (dgst, ctx->state.v8, SHA1_DIGEST_LENGTH);
}

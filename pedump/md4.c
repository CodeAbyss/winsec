

// MD4 in C
// Odzhan

#include "md4.h"

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define ROL32(a, n)(((a) << (n)) | (((a) & 0xffffffff) >> (32 - (n))))
#define ROR32(a, n)((((a) & 0xffffffff) >> (n)) | ((a) << (32 - (n))))

uint8_t rotf[]= { 3, 7, 11, 19 };
uint8_t rotg[]= { 3, 5,  9, 13 };
uint8_t roth[]= { 3, 9, 11, 15 };

uint8_t idxg[]= { 0, 4, 8, 12, 1,  5, 9, 13, 2, 6, 10, 14,  3,  7, 11, 15 };
uint8_t idxh[]= { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9,  5, 13,  3, 11,  7, 15 };

/************************************************
*
* Transform block of data.
*
************************************************/
void MD4_Transform (MD4_CTX *ctx) 
{
  uint32_t a, b, c, d, i, t, s;
  
  a=ctx->state.v32[0];
  b=ctx->state.v32[1];
  c=ctx->state.v32[2];
  d=ctx->state.v32[3];
  
  // for 48 rounds
  for (i=0; i<16; i++) {
    /*if (i < 16) {*/
      a += F(b, c, d) + ctx->buffer.v32[i];
      s = rotf[i%4];
    /*} else if (i < 32) {
      a += G(b, c, d) + ctx->data.v32[idxg[i%16]] + 0x5a827999L;
      s = rotg[i%4];
    } else {
      a += H(b, c, d) + ctx->data.v32[idxh[i%16]] + 0x6ed9eba1L;
      s = roth[i%4];
    }*/
    t=ROL32(a, s);
    a=d;
    d=c;
    c=b;
    b=t;
  }

  ctx->state.v32[0] += a;
  ctx->state.v32[1] += b;
  ctx->state.v32[2] += c;
  ctx->state.v32[3] += d;
}

/************************************************
*
* initialize state
*
************************************************/
void MD4_Init (MD4_CTX *ctx) {
  ctx->len  = 0;
  ctx->state.v32[0] = 0x67452301;
  ctx->state.v32[1] = 0xefcdab89;
  ctx->state.v32[2] = 0x98badcfe;
  ctx->state.v32[3] = 0x10325476;
}

/************************************************
*
* update state with input
*
************************************************/
void MD4_Update (MD4_CTX *ctx, void *in, size_t len) {
  uint8_t *p = (uint8_t*)in;
  size_t  r, idx;
  
  // get buffer index
  idx = ctx->len & MD4_CBLOCK - 1;
  
  // update length
  ctx->len += len;
  
  do {
    r = MIN (len, MD4_CBLOCK - idx);
    memcpy ((void*)&ctx->buffer.v8[idx], p, r);
    if ((idx + r) < MD4_CBLOCK) break;
    
    MD4_Transform (ctx);
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
void MD4_Final (void* dgst, MD4_CTX * ctx)
{
  // see what length we have ere..
  uint64_t len=ctx->len & MD4_CBLOCK - 1;
  // fill with zeros
  memset (&ctx->buffer.v8[len], 0, MD4_CBLOCK - len);
  // add the end bit
  ctx->buffer.v8[len] = 0x80;
  // if exceeding 56 bytes, transform it
  if (len >= 56) {
    MD4_Transform (ctx);
    // clear
    memset (ctx->buffer.v8, 0, MD4_CBLOCK);
  }
  // add total bits
  ctx->buffer.v64[7] = ctx->len * 8;
  // compress
  MD4_Transform(ctx);
  // copy digest to buffer
  memcpy (dgst, ctx->state.v8, MD4_DIGEST_LENGTH);
}

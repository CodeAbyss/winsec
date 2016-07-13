

// SHA-256 in C
// Odzhan

#include "sha2.h"

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

#ifdef DYNAMIC

#include <math.h>
#pragma intrinsic(fabs,pow,sqrt)

uint16_t primes[64] =
{  2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
  59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311
};

// square root of integer, return fractional part as integer
uint32_t sqrt2int (uint32_t x) {
  uint32_t r;
  r = (uint32_t)(fabs(sqrt((double)primes[x]))*pow(2,32));
  return r;
}

// cube root of integer, return fractional part as integer
uint32_t cbr2int (uint32_t x) {
  uint32_t r;
  r = (uint32_t)(fabs(pow((double)primes[x],1.0/3.0))*pow(2,32));
  return r;
}

#else

uint32_t k[64]=
{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

uint32_t h[SHA256_LBLOCK]=
{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

#endif

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define EP1(x) (ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SIG0(x) (ROTR32(x,7) ^ ROTR32(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))

/************************************************
*
* update state with block of data
*
************************************************/
void SHA256_Transform (SHA256_CTX *ctx) 
{
  uint32_t t1, t2, i, j, t;
  uint32_t w[64], s[8];
  
  // load data in big endian format
  for (i=0; i<16; i++) {
    w[i] = SWAP32(ctx->buffer.v32[i]);
  }

  // expand data into 512-bit buffer
  for (i=16; i<64; i++) {
    w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
  }
  
  // load state into local buffer
  for (i=0; i<8; i++) {
    s[i] = ctx->state.v32[i];
  }
  
  // for 64 rounds
  for (i=0; i<64; i++)
  {
    t1 = s[7] + EP1(s[4]) + CH(s[4], s[5], s[6]) + w[i];
    #ifdef DYNAMIC
    t1 += cbr2int (i);
    #else
    t1 += k[i];
    #endif
    t2 = EP0(s[0]) + MAJ(s[0], s[1], s[2]);
    s[7]  = t1 + t2;
    s[3] += t1;
    // rotate "right" 32-bits
    t1=s[0]; // load a
    for (j=1; j<8; j++) {
      t2=s[j];
      s[j]=t1;
      t1=t2;
    }
    s[0]=t1;
  }
  
  // save state
  for (i=0; i<8; i++) {
    ctx->state.v32[i] += s[i];
  }
}

/************************************************
*
* initialize context
*
************************************************/
void SHA256_Init (SHA256_CTX *ctx) {
  int i;
  
  ctx->len = 0;
  for (i=0; i<SHA256_LBLOCK; i++) {
    #ifdef DYNAMIC
    ctx->state.v32[i] = sqrt2int(i);
    #else
    ctx->state.v32[i] = h[i];
    #endif
  }
}

/************************************************
*
* update state with input
*
************************************************/
void SHA256_Update (SHA256_CTX *ctx, void *in, size_t len) {
  uint8_t *p = (uint8_t*)in;
  size_t r, idx;
  
  // get buffer index
  idx = ctx->len & SHA256_CBLOCK - 1;
  
  // update length
  ctx->len += len;
  
  do {
    r = MIN(len, SHA256_CBLOCK - idx);
    memcpy (&ctx->buffer.v8[idx], p, r);
    if ((idx + r) < SHA256_CBLOCK) break;
    
    SHA256_Transform (ctx);
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
void SHA256_Final (void* dgst, SHA256_CTX *ctx)
{
  int i;
  
  // see what length we have ere..
  uint64_t len=ctx->len & SHA256_CBLOCK - 1;
  // fill remaining with zeros
  memset (&ctx->buffer.v8[len], 0, SHA256_CBLOCK - len);
  // add the end bit
  ctx->buffer.v8[len] = 0x80;
  // if exceeding 56 bytes, transform it
  if (len >= 56) {
    SHA256_Transform (ctx);
    // clear buffer
    memset (ctx->buffer.v8, 0, SHA256_CBLOCK);
  }
  // add total bits
  ctx->buffer.v64[7] = SWAP64(ctx->len * 8);
  // compress
  SHA256_Transform(ctx);
  
  // swap byte order
  for (i=0; i<SHA256_LBLOCK; i++) {
    ctx->state.v32[i] = SWAP32(ctx->state.v32[i]);
  }
  // copy digest to buffer
  memcpy (dgst, ctx->state.v8, SHA256_DIGEST_LENGTH);
}

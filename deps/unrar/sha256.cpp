#include "rar.hpp"
#include "sha256.hpp"

static const uint32 K[64] = 
{
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
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
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 functions. We could optimize Ch and Maj a little,
// but with no visible speed benefit.
#define Ch(x, y, z)  ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

// Sigma functions.
#define Sg0(x) (rotr32(x, 2) ^ rotr32(x,13) ^ rotr32(x, 22))
#define Sg1(x) (rotr32(x, 6) ^ rotr32(x,11) ^ rotr32(x, 25))
#define sg0(x) (rotr32(x, 7) ^ rotr32(x,18) ^ (x >> 3))
#define sg1(x) (rotr32(x,17) ^ rotr32(x,19) ^ (x >> 10))

void sha256_init(sha256_context *ctx)
{
  ctx->H[0] = 0x6a09e667; // Set the initial hash value.
  ctx->H[1] = 0xbb67ae85;
  ctx->H[2] = 0x3c6ef372;
  ctx->H[3] = 0xa54ff53a;
  ctx->H[4] = 0x510e527f;
  ctx->H[5] = 0x9b05688c;
  ctx->H[6] = 0x1f83d9ab;
  ctx->H[7] = 0x5be0cd19;
  ctx->Count    = 0;      // Processed data counter.
}


static void sha256_transform(sha256_context *ctx)
{
  uint32 W[64]; // Words of message schedule.
  uint32 v[8];  // FIPS a, b, c, d, e, f, g, h working variables.

  // Prepare message schedule.
  for (uint I = 0; I < 16; I++)
    W[I] = RawGetBE4(ctx->Buffer + I * 4);
  for (uint I = 16; I < 64; I++)
    W[I] = sg1(W[I-2]) + W[I-7] + sg0(W[I-15]) + W[I-16];

  uint32 *H=ctx->H;
  v[0]=H[0]; v[1]=H[1]; v[2]=H[2]; v[3]=H[3];
  v[4]=H[4]; v[5]=H[5]; v[6]=H[6]; v[7]=H[7];

  for (uint I = 0; I < 64; I++)
  {
    uint T1 = v[7] + Sg1(v[4]) + Ch(v[4], v[5], v[6]) + K[I] + W[I];

    // It is possible to eliminate variable copying if we unroll loop
    // and rename variables every time. But my test did not show any speed
    // gain on i7 for such full or partial unrolling.
    v[7] = v[6];
    v[6] = v[5];
    v[5] = v[4];
    v[4] = v[3] + T1;

    // It works a little faster when moved here from beginning of loop.
    uint T2 = Sg0(v[0]) + Maj(v[0], v[1], v[2]);

    v[3] = v[2];
    v[2] = v[1];
    v[1] = v[0];
    v[0] = T1 + T2;
  }

  H[0]+=v[0]; H[1]+=v[1]; H[2]+=v[2]; H[3]+=v[3];
  H[4]+=v[4]; H[5]+=v[5]; H[6]+=v[6]; H[7]+=v[7];
}


void sha256_process(sha256_context *ctx, const void *Data, size_t Size)
{
  const byte *Src=(const byte *)Data;
  size_t BufPos = (uint)ctx->Count & 0x3f;
  ctx->Count+=Size;
  while (Size > 0)
  {
    size_t BufSpace=sizeof(ctx->Buffer)-BufPos;
    size_t CopySize=Size>BufSpace ? BufSpace:Size;

    memcpy(ctx->Buffer+BufPos,Src,CopySize);

    Src+=CopySize;
    BufPos+=CopySize;
    Size-=CopySize;
    if (BufPos == 64)
    {
      BufPos = 0;
      sha256_transform(ctx);
    }
  }
}


void sha256_done(sha256_context *ctx, byte *Digest)
{
  uint64 BitLength = ctx->Count * 8;
  uint BufPos = (uint)ctx->Count & 0x3f;
  ctx->Buffer[BufPos++] = 0x80; // Padding the message with "1" bit.

  if (BufPos!=56) // We need 56 bytes block followed by 8 byte length.
  {
    if (BufPos>56)
    {
      while (BufPos<64)
        ctx->Buffer[BufPos++] = 0;
      BufPos=0;
    }
    if (BufPos==0)
      sha256_transform(ctx);
    memset(ctx->Buffer+BufPos,0,56-BufPos);
  }

  RawPutBE4((uint32)(BitLength>>32), ctx->Buffer + 56);
  RawPutBE4((uint32)(BitLength), ctx->Buffer + 60);

  sha256_transform(ctx);

  RawPutBE4(ctx->H[0], Digest +  0);
  RawPutBE4(ctx->H[1], Digest +  4);
  RawPutBE4(ctx->H[2], Digest +  8);
  RawPutBE4(ctx->H[3], Digest + 12);
  RawPutBE4(ctx->H[4], Digest + 16);
  RawPutBE4(ctx->H[5], Digest + 20);
  RawPutBE4(ctx->H[6], Digest + 24);
  RawPutBE4(ctx->H[7], Digest + 28);

  sha256_init(ctx);
}

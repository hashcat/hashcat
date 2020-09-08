#ifndef _RAR_SHA256_
#define _RAR_SHA256_

#define SHA256_DIGEST_SIZE 32

typedef struct
{
  uint32 H[8];
  uint64 Count;
  byte Buffer[64];
} sha256_context;

void sha256_init(sha256_context *ctx);
void sha256_process(sha256_context *ctx, const void *Data, size_t Size);
void sha256_done(sha256_context *ctx, byte *Digest);

#endif

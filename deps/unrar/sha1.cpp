#include "rar.hpp"

/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#ifndef SFX_MODULE
#define SHA1_UNROLL
#endif

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#ifdef LITTLE_ENDIAN
#define blk0(i) (block->l[i] = ByteSwap32(block->l[i]))
#else
#define blk0(i) block->l[i]
#endif
#define blk(i) (block->l[i&15] = rotl32(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) {z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rotl32(v,5);w=rotl32(w,30);}
#define R1(v,w,x,y,z,i) {z+=((w&(x^y))^y)+blk(i)+0x5A827999+rotl32(v,5);w=rotl32(w,30);}
#define R2(v,w,x,y,z,i) {z+=(w^x^y)+blk(i)+0x6ED9EBA1+rotl32(v,5);w=rotl32(w,30);}
#define R3(v,w,x,y,z,i) {z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rotl32(v,5);w=rotl32(w,30);}
#define R4(v,w,x,y,z,i) {z+=(w^x^y)+blk(i)+0xCA62C1D6+rotl32(v,5);w=rotl32(w,30);}

/* Hash a single 512-bit block. This is the core of the algorithm. */
void SHA1Transform(uint32 state[5], uint32 workspace[16], const byte buffer[64], bool inplace)
{
  uint32 a, b, c, d, e;

  union CHAR64LONG16
  {
    unsigned char c[64];
    uint32 l[16];
  } *block;

  if (inplace)
    block = (CHAR64LONG16*)buffer;
  else
  {
    block = (CHAR64LONG16*)workspace;
    memcpy(block, buffer, 64);
  }

  /* Copy context->state[] to working vars */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

#ifdef SHA1_UNROLL
  /* 4 rounds of 20 operations each. Loop unrolled. */
  R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
  R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
  R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
  R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
  R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
  R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
  R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
  R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
  R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
  R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
  R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
  R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
  R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
  R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
  R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
  R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
  R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
  R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
#else
  for (uint I=0;;I+=5)
  {
    R0(a,b,c,d,e, I+0); if (I==15) break;
    R0(e,a,b,c,d, I+1); R0(d,e,a,b,c, I+2);
    R0(c,d,e,a,b, I+3); R0(b,c,d,e,a, I+4);
  }
  R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
  for (uint I=20;I<=35;I+=5)
  {
    R2(a,b,c,d,e,I+0); R2(e,a,b,c,d,I+1); R2(d,e,a,b,c,I+2);
    R2(c,d,e,a,b,I+3); R2(b,c,d,e,a,I+4);
  }
  for (uint I=40;I<=55;I+=5)
  {
    R3(a,b,c,d,e,I+0); R3(e,a,b,c,d,I+1); R3(d,e,a,b,c,I+2);
    R3(c,d,e,a,b,I+3); R3(b,c,d,e,a,I+4);
  }
  for (uint I=60;I<=75;I+=5)
  {
    R4(a,b,c,d,e,I+0); R4(e,a,b,c,d,I+1); R4(d,e,a,b,c,I+2);
    R4(c,d,e,a,b,I+3); R4(b,c,d,e,a,I+4);
  }
#endif
  /* Add the working vars back into context.state[] */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}


/* Initialize new context */
void sha1_init(sha1_context* context)
{
  context->count = 0;
  /* SHA1 initialization constants */
  context->state[0] = 0x67452301;
  context->state[1] = 0xEFCDAB89;
  context->state[2] = 0x98BADCFE;
  context->state[3] = 0x10325476;
  context->state[4] = 0xC3D2E1F0;
}


/* Run your data through this. */
void sha1_process( sha1_context * context, const unsigned char * data, size_t len)
{
  size_t i, j = (size_t)(context->count & 63);
  context->count += len;

  if ((j + len) > 63)
  {
    memcpy(context->buffer+j, data, (i = 64-j));
    uint32 workspace[16];
    SHA1Transform(context->state, workspace, context->buffer, true);
    for ( ; i + 63 < len; i += 64)
      SHA1Transform(context->state, workspace, data+i, false);
    j = 0;
  }
  else
    i = 0;
  if (len > i)
    memcpy(context->buffer+j, data+i, len - i);
}


void sha1_process_rar29(sha1_context *context, const unsigned char *data, size_t len)
{
  size_t i, j = (size_t)(context->count & 63);
  context->count += len;

  if ((j + len) > 63)
  {
    memcpy(context->buffer+j, data, (i = 64-j));
    uint32 workspace[16];
    SHA1Transform(context->state, workspace, context->buffer, true);
    for ( ; i + 63 < len; i += 64)
    {
      SHA1Transform(context->state, workspace, data+i, false);
      for (uint k = 0; k < 16; k++)
        RawPut4(workspace[k],(void*)(data+i+k*4));
    }
    j = 0;
  }
  else
    i = 0;
  if (len > i)
    memcpy(context->buffer+j, data+i, len - i);
}


/* Add padding and return the message digest. */
void sha1_done( sha1_context* context, uint32 digest[5])
{
  uint32 workspace[16];
  uint64 BitLength = context->count * 8;
  uint BufPos = (uint)context->count & 0x3f;
  context->buffer[BufPos++] = 0x80; // Padding the message with "1" bit.

  if (BufPos!=56) // We need 56 bytes block followed by 8 byte length.
  {
    if (BufPos>56)
    {
      while (BufPos<64)
        context->buffer[BufPos++] = 0;
      BufPos=0;
    }
    if (BufPos==0)
      SHA1Transform(context->state, workspace, context->buffer, true);
    memset(context->buffer+BufPos,0,56-BufPos);
  }

  RawPutBE4((uint32)(BitLength>>32), context->buffer + 56);
  RawPutBE4((uint32)(BitLength), context->buffer + 60);

  SHA1Transform(context->state, workspace, context->buffer, true);

  for (uint i = 0; i < 5; i++)
    digest[i] = context->state[i];

  /* Wipe variables */
  sha1_init(context);
}



// Based on public domain code written in 2012 by Samuel Neves

#include "rar.hpp"

#ifdef USE_SSE
#include "blake2s_sse.cpp"
#endif

static void blake2s_init_param( blake2s_state *S, uint32 node_offset, uint32 node_depth);
static void blake2s_update( blake2s_state *S, const byte *in, size_t inlen );
static void blake2s_final( blake2s_state *S, byte *digest );

#include "blake2sp.cpp"

static const uint32 blake2s_IV[8] =
{
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const byte blake2s_sigma[10][16] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

static inline void blake2s_set_lastnode( blake2s_state *S )
{
  S->f[1] = ~0U;
}


/* Some helper functions, not necessarily useful */
static inline void blake2s_set_lastblock( blake2s_state *S )
{
  if( S->last_node ) blake2s_set_lastnode( S );

  S->f[0] = ~0U;
}


static inline void blake2s_increment_counter( blake2s_state *S, const uint32 inc )
{
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
}


/* init2 xors IV with input parameter block */
void blake2s_init_param( blake2s_state *S, uint32 node_offset, uint32 node_depth)
{
#ifdef USE_SSE
  if (_SSE_Version>=SSE_SSE2)
    blake2s_init_sse();
#endif

  S->init(); // Clean data.
  for( int i = 0; i < 8; ++i )
    S->h[i] = blake2s_IV[i];

  S->h[0] ^= 0x02080020; // We use BLAKE2sp parameters block.
  S->h[2] ^= node_offset;
  S->h[3] ^= (node_depth<<16)|0x20000000;
}


#define G(r,i,m,a,b,c,d) \
  a = a + b + m[blake2s_sigma[r][2*i+0]]; \
  d = rotr32(d ^ a, 16); \
  c = c + d; \
  b = rotr32(b ^ c, 12); \
  a = a + b + m[blake2s_sigma[r][2*i+1]]; \
  d = rotr32(d ^ a, 8); \
  c = c + d; \
  b = rotr32(b ^ c, 7);


static void blake2s_compress( blake2s_state *S, const byte block[BLAKE2S_BLOCKBYTES] )
{
  uint32 m[16];
  uint32 v[16];

  for( size_t i = 0; i < 16; ++i )
    m[i] = RawGet4( block + i * 4 );

  for( size_t i = 0; i < 8; ++i )
    v[i] = S->h[i];

  v[ 8] = blake2s_IV[0];
  v[ 9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = S->t[0] ^ blake2s_IV[4];
  v[13] = S->t[1] ^ blake2s_IV[5];
  v[14] = S->f[0] ^ blake2s_IV[6];
  v[15] = S->f[1] ^ blake2s_IV[7];

  for ( uint r = 0; r <= 9; ++r ) // No gain on i7 if unrolled, but exe size grows.
  {
    G(r,0,m,v[ 0],v[ 4],v[ 8],v[12]);
    G(r,1,m,v[ 1],v[ 5],v[ 9],v[13]);
    G(r,2,m,v[ 2],v[ 6],v[10],v[14]);
    G(r,3,m,v[ 3],v[ 7],v[11],v[15]);
    G(r,4,m,v[ 0],v[ 5],v[10],v[15]);
    G(r,5,m,v[ 1],v[ 6],v[11],v[12]);
    G(r,6,m,v[ 2],v[ 7],v[ 8],v[13]);
    G(r,7,m,v[ 3],v[ 4],v[ 9],v[14]);
  }

  for( size_t i = 0; i < 8; ++i )
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}


void blake2s_update( blake2s_state *S, const byte *in, size_t inlen )
{
  while( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = 2 * BLAKE2S_BLOCKBYTES - left;

    if( inlen > fill )
    {
      memcpy( S->buf + left, in, fill ); // Fill buffer
      S->buflen += fill;
      blake2s_increment_counter( S, BLAKE2S_BLOCKBYTES );

#ifdef USE_SSE
#ifdef _WIN_32 // We use SSSE3 _mm_shuffle_epi8 only in x64 mode.
      if (_SSE_Version>=SSE_SSE2)
#else
      if (_SSE_Version>=SSE_SSSE3)
#endif
        blake2s_compress_sse( S, S->buf );
      else
        blake2s_compress( S, S->buf ); // Compress
#else
      blake2s_compress( S, S->buf ); // Compress
#endif
      
      memcpy( S->buf, S->buf + BLAKE2S_BLOCKBYTES, BLAKE2S_BLOCKBYTES ); // Shift buffer left
      S->buflen -= BLAKE2S_BLOCKBYTES;
      in += fill;
      inlen -= fill;
    }
    else // inlen <= fill
    {
      memcpy( S->buf + left, in, (size_t)inlen );
      S->buflen += (size_t)inlen; // Be lazy, do not compress
      in += inlen;
      inlen = 0;
    }
  }
}


void blake2s_final( blake2s_state *S, byte *digest )
{
  if( S->buflen > BLAKE2S_BLOCKBYTES )
  {
    blake2s_increment_counter( S, BLAKE2S_BLOCKBYTES );
    blake2s_compress( S, S->buf );
    S->buflen -= BLAKE2S_BLOCKBYTES;
    memcpy( S->buf, S->buf + BLAKE2S_BLOCKBYTES, S->buflen );
  }

  blake2s_increment_counter( S, ( uint32 )S->buflen );
  blake2s_set_lastblock( S );
  memset( S->buf + S->buflen, 0, 2 * BLAKE2S_BLOCKBYTES - S->buflen ); /* Padding */
  blake2s_compress( S, S->buf );

  for( int i = 0; i < 8; ++i ) /* Output full hash  */
    RawPut4( S->h[i], digest + 4 * i );
}


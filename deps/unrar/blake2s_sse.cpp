// Based on public domain code written in 2012 by Samuel Neves

extern const byte blake2s_sigma[10][16];

// Initialization vector.
static __m128i blake2s_IV_0_3, blake2s_IV_4_7;

#ifdef _WIN_64
// Constants for cyclic rotation. Used in 64-bit mode in mm_rotr_epi32 macro.
static __m128i crotr8, crotr16;
#endif

static void blake2s_init_sse()
{
  // We cannot initialize these 128 bit variables in place when declaring
  // them globally, because global scope initialization is performed before
  // our SSE check and it would make code incompatible with older non-SSE2
  // CPUs. Also we cannot initialize them as static inside of function
  // using these variables, because SSE static initialization is not thread
  // safe: first thread starts initialization and sets "init done" flag even
  // if it is not done yet, second thread can attempt to access half-init
  // SSE data. So we moved init code here.

  blake2s_IV_0_3 = _mm_setr_epi32( 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A );
  blake2s_IV_4_7 = _mm_setr_epi32( 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 );

#ifdef _WIN_64
  crotr8 = _mm_set_epi8( 12, 15, 14, 13, 8, 11, 10, 9, 4, 7, 6, 5, 0, 3, 2, 1 );
  crotr16 = _mm_set_epi8( 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2 );
#endif
}


#define LOAD(p)  _mm_load_si128( (__m128i *)(p) )
#define STORE(p,r) _mm_store_si128((__m128i *)(p), r)

#ifdef _WIN_32
// 32-bit mode has less SSE2 registers and in MSVC2008 it is more efficient
// to not use _mm_shuffle_epi8 here.
#define mm_rotr_epi32(r, c) ( \
              _mm_xor_si128(_mm_srli_epi32( (r), c ),_mm_slli_epi32( (r), 32-c )) )
#else
#define mm_rotr_epi32(r, c) ( \
                c==8 ? _mm_shuffle_epi8(r,crotr8) \
              : c==16 ? _mm_shuffle_epi8(r,crotr16) \
              : _mm_xor_si128(_mm_srli_epi32( (r), c ),_mm_slli_epi32( (r), 32-c )) )
#endif


#define G1(row1,row2,row3,row4,buf) \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 ); \
  row4 =  mm_rotr_epi32(row4, 16); \
  row3 = _mm_add_epi32( row3, row4 );   \
  row2 = _mm_xor_si128( row2, row3 ); \
  row2 =  mm_rotr_epi32(row2, 12);

#define G2(row1,row2,row3,row4,buf) \
  row1 = _mm_add_epi32( _mm_add_epi32( row1, buf), row2 ); \
  row4 = _mm_xor_si128( row4, row1 ); \
  row4 =  mm_rotr_epi32(row4, 8); \
  row3 = _mm_add_epi32( row3, row4 );   \
  row2 = _mm_xor_si128( row2, row3 ); \
  row2 =  mm_rotr_epi32(row2, 7);

#define DIAGONALIZE(row1,row2,row3,row4) \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(2,1,0,3) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(1,0,3,2) ); \
  row2 = _mm_shuffle_epi32( row2, _MM_SHUFFLE(0,3,2,1) );

#define UNDIAGONALIZE(row1,row2,row3,row4) \
  row4 = _mm_shuffle_epi32( row4, _MM_SHUFFLE(0,3,2,1) ); \
  row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE(1,0,3,2) ); \
  row2 = _mm_shuffle_epi32( row2, _MM_SHUFFLE(2,1,0,3) );

#ifdef _WIN_64
  // MSVC 2008 in x64 mode expands _mm_set_epi32 to store to stack and load
  // from stack operations, which are slower than this code.
  #define _mm_set_epi32(i3,i2,i1,i0) \
    _mm_unpacklo_epi32(_mm_unpacklo_epi32(_mm_cvtsi32_si128(i0),_mm_cvtsi32_si128(i2)), \
                       _mm_unpacklo_epi32(_mm_cvtsi32_si128(i1),_mm_cvtsi32_si128(i3)))
#endif

// Original BLAKE2 SSE4.1 message loading code was a little slower in x86 mode
// and about the same in x64 mode in our test. Perhaps depends on compiler.
// We also tried _mm_i32gather_epi32 and _mm256_i32gather_epi32 AVX2 gather
// instructions here, but they did not show any speed gain on i7-6700K.
#define SSE_ROUND(m,row,r) \
{ \
  __m128i buf; \
  buf=_mm_set_epi32(m[blake2s_sigma[r][6]],m[blake2s_sigma[r][4]],m[blake2s_sigma[r][2]],m[blake2s_sigma[r][0]]); \
  G1(row[0],row[1],row[2],row[3],buf); \
  buf=_mm_set_epi32(m[blake2s_sigma[r][7]],m[blake2s_sigma[r][5]],m[blake2s_sigma[r][3]],m[blake2s_sigma[r][1]]); \
  G2(row[0],row[1],row[2],row[3],buf); \
  DIAGONALIZE(row[0],row[1],row[2],row[3]); \
  buf=_mm_set_epi32(m[blake2s_sigma[r][14]],m[blake2s_sigma[r][12]],m[blake2s_sigma[r][10]],m[blake2s_sigma[r][8]]); \
  G1(row[0],row[1],row[2],row[3],buf); \
  buf=_mm_set_epi32(m[blake2s_sigma[r][15]],m[blake2s_sigma[r][13]],m[blake2s_sigma[r][11]],m[blake2s_sigma[r][9]]); \
  G2(row[0],row[1],row[2],row[3],buf); \
  UNDIAGONALIZE(row[0],row[1],row[2],row[3]); \
}


static int blake2s_compress_sse( blake2s_state *S, const byte block[BLAKE2S_BLOCKBYTES] )
{
  __m128i row[4];
  __m128i ff0, ff1;
  
  const uint32  *m = ( uint32 * )block;

  row[0] = ff0 = LOAD( &S->h[0] );
  row[1] = ff1 = LOAD( &S->h[4] );

  row[2] = blake2s_IV_0_3;
  row[3] = _mm_xor_si128( blake2s_IV_4_7, LOAD( &S->t[0] ) );
  SSE_ROUND( m, row, 0 );
  SSE_ROUND( m, row, 1 );
  SSE_ROUND( m, row, 2 );
  SSE_ROUND( m, row, 3 );
  SSE_ROUND( m, row, 4 );
  SSE_ROUND( m, row, 5 );
  SSE_ROUND( m, row, 6 );
  SSE_ROUND( m, row, 7 );
  SSE_ROUND( m, row, 8 );
  SSE_ROUND( m, row, 9 );
  STORE( &S->h[0], _mm_xor_si128( ff0, _mm_xor_si128( row[0], row[2] ) ) );
  STORE( &S->h[4], _mm_xor_si128( ff1, _mm_xor_si128( row[1], row[3] ) ) );
  return 0;
}

/*
   BLAKE2 reference source code package - reference C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#define PARALLELISM_DEGREE 8

void blake2sp_init( blake2sp_state *S )
{
  memset( S->buf, 0, sizeof( S->buf ) );
  S->buflen = 0;

  blake2s_init_param( &S->R, 0, 1 ); // Init root.

  for( uint i = 0; i < PARALLELISM_DEGREE; ++i )
    blake2s_init_param( &S->S[i], i, 0 ); // Init leaf.

  S->R.last_node = 1;
  S->S[PARALLELISM_DEGREE - 1].last_node = 1;
}


struct Blake2ThreadData
{
  void Update();
  blake2s_state *S;
  const byte *in;
  size_t inlen;
};


void Blake2ThreadData::Update()
{
  size_t inlen__ = inlen;
  const byte *in__ = ( const byte * )in;

  while( inlen__ >= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES )
  {
#ifdef USE_SSE
    // We gain 5% in i7 SSE mode by prefetching next data block.
    if (_SSE_Version>=SSE_SSE && inlen__ >= 2 * PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES)
      _mm_prefetch((char*)(in__ +  PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES), _MM_HINT_T0);
#endif
    blake2s_update( S, in__, BLAKE2S_BLOCKBYTES );
    in__ += PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
    inlen__ -= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
  }
}

#ifdef RAR_SMP
THREAD_PROC(Blake2Thread)
{
  Blake2ThreadData *td=(Blake2ThreadData *)Data;
  td->Update();
}
#endif


void blake2sp_update( blake2sp_state *S, const byte *in, size_t inlen )
{
  size_t left = S->buflen;
  size_t fill = sizeof( S->buf ) - left;

  if( left && inlen >= fill )
  {
    memcpy( S->buf + left, in, fill );

    for( size_t i = 0; i < PARALLELISM_DEGREE; ++i )
      blake2s_update( &S->S[i], S->buf + i * BLAKE2S_BLOCKBYTES, BLAKE2S_BLOCKBYTES );

    in += fill;
    inlen -= fill;
    left = 0;
  }

  Blake2ThreadData btd_array[PARALLELISM_DEGREE];

#ifdef RAR_SMP
  uint ThreadNumber = inlen < 0x1000 ? 1 : S->MaxThreads;
  
  if (ThreadNumber==6 || ThreadNumber==7) // 6 and 7 threads work slower than 4 here.
    ThreadNumber=4;
#else
  uint ThreadNumber=1;
#endif

  for (size_t id__=0;id__<PARALLELISM_DEGREE;)
  {
    for (uint Thread=0;Thread<ThreadNumber && id__<PARALLELISM_DEGREE;Thread++)
    {
      Blake2ThreadData *btd=btd_array+Thread;

      btd->inlen = inlen;
      btd->in = in + id__ * BLAKE2S_BLOCKBYTES;
      btd->S = &S->S[id__];
  
#ifdef RAR_SMP
      if (ThreadNumber>1)
        S->ThPool->AddTask(Blake2Thread,(void*)btd);
      else
        btd->Update();
#else
      btd->Update();
#endif
      id__++;
    }
#ifdef RAR_SMP
    if (S->ThPool!=NULL) // Can be NULL in -mt1 mode.
      S->ThPool->WaitDone();
#endif // RAR_SMP
  }

  in += inlen - inlen % ( PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES );
  inlen %= PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;

  if( inlen > 0 )
    memcpy( S->buf + left, in, (size_t)inlen );

  S->buflen = left + (size_t)inlen;
}


void blake2sp_final( blake2sp_state *S, byte *digest )
{
  byte hash[PARALLELISM_DEGREE][BLAKE2S_OUTBYTES];

  for( size_t i = 0; i < PARALLELISM_DEGREE; ++i )
  {
    if( S->buflen > i * BLAKE2S_BLOCKBYTES )
    {
      size_t left = S->buflen - i * BLAKE2S_BLOCKBYTES;

      if( left > BLAKE2S_BLOCKBYTES ) left = BLAKE2S_BLOCKBYTES;

      blake2s_update( &S->S[i], S->buf + i * BLAKE2S_BLOCKBYTES, left );
    }

    blake2s_final( &S->S[i], hash[i] );
  }

  for( size_t i = 0; i < PARALLELISM_DEGREE; ++i )
    blake2s_update( &S->R, hash[i], BLAKE2S_OUTBYTES );

  blake2s_final( &S->R, digest );
}

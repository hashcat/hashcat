/**************************************************************************
 * This code is based on Szymon Stefanek public domain AES implementation *
 **************************************************************************/
#include "rar.hpp"

#ifdef USE_SSE
#include <wmmintrin.h>
#endif

static byte S[256]=
{
   99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118, 
  202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 
  183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21, 
    4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117, 
    9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132, 
   83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207, 
  208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168, 
   81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210, 
  205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115, 
   96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219, 
  224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121, 
  231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8, 
  186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138, 
  112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158, 
  225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223, 
  140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22
};

static byte S5[256];

// Round constants. 10 items are used by AES-128, 8 by AES-192, 7 by AES-256.
static byte rcon[]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static byte T1[256][4],T2[256][4],T3[256][4],T4[256][4];
static byte T5[256][4],T6[256][4],T7[256][4],T8[256][4];
static byte U1[256][4],U2[256][4],U3[256][4],U4[256][4];

inline void Xor128(void *dest,const void *arg1,const void *arg2)
{
#ifdef ALLOW_MISALIGNED
  ((uint32*)dest)[0]=((uint32*)arg1)[0]^((uint32*)arg2)[0];
  ((uint32*)dest)[1]=((uint32*)arg1)[1]^((uint32*)arg2)[1];
  ((uint32*)dest)[2]=((uint32*)arg1)[2]^((uint32*)arg2)[2];
  ((uint32*)dest)[3]=((uint32*)arg1)[3]^((uint32*)arg2)[3];
#else
  for (int I=0;I<16;I++)
    ((byte*)dest)[I]=((byte*)arg1)[I]^((byte*)arg2)[I];
#endif
}


inline void Xor128(byte *dest,const byte *arg1,const byte *arg2,
                   const byte *arg3,const byte *arg4)
{
#ifdef ALLOW_MISALIGNED
  (*(uint32*)dest)=(*(uint32*)arg1)^(*(uint32*)arg2)^(*(uint32*)arg3)^(*(uint32*)arg4);
#else
  for (int I=0;I<4;I++)
    dest[I]=arg1[I]^arg2[I]^arg3[I]^arg4[I];
#endif
}


inline void Copy128(byte *dest,const byte *src)
{
#ifdef ALLOW_MISALIGNED
  ((uint32*)dest)[0]=((uint32*)src)[0];
  ((uint32*)dest)[1]=((uint32*)src)[1];
  ((uint32*)dest)[2]=((uint32*)src)[2];
  ((uint32*)dest)[3]=((uint32*)src)[3];
#else
  for (int I=0;I<16;I++)
    dest[I]=src[I];
#endif
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// API
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Rijndael::Rijndael()
{
  if (S5[0]==0)
    GenerateTables();
  CBCMode = true; // Always true for RAR.
}


void Rijndael::Init(bool Encrypt,const byte *key,uint keyLen,const byte * initVector)
{
  // Check SIMD here instead of constructor, so if object is a part of some
  // structure memset'ed before use, these variables are not lost.
#if defined(USE_SSE)
  int CPUInfo[4];
  __cpuid(CPUInfo, 0);
  if (CPUInfo[0]>=1) // Check the maximum supported cpuid function.
  {
    __cpuid(CPUInfo, 1);
    AES_NI=(CPUInfo[2] & 0x2000000)!=0;
  }
  else
    AES_NI=false;
#elif defined(USE_NEON)
  AES_Neon=(getauxval(AT_HWCAP) & HWCAP_AES)!=0;
#endif

  // Other developers asked us to initialize it to suppress "may be used
  // uninitialized" warning in code below in some compilers.
  uint uKeyLenInBytes=0;

  switch(keyLen)
  {
    case 128:
      uKeyLenInBytes = 16;
      m_uRounds = 10;
      break;
    case 192:
      uKeyLenInBytes = 24;
      m_uRounds = 12;
      break;
    case 256:
      uKeyLenInBytes = 32;
      m_uRounds = 14;
      break;
  }

  byte keyMatrix[_MAX_KEY_COLUMNS][4];

  for(uint i = 0; i < uKeyLenInBytes; i++)
    keyMatrix[i >> 2][i & 3] = key[i]; 

  if (initVector==NULL)
    memset(m_initVector, 0, sizeof(m_initVector));
  else
    for(int i = 0; i < MAX_IV_SIZE; i++)
      m_initVector[i] = initVector[i];

  keySched(keyMatrix);

  if(!Encrypt)
    keyEncToDec();
}


void Rijndael::blockEncrypt(const byte *input,size_t inputLen,byte *outBuffer)
{
  if (inputLen <= 0)
    return;

  size_t numBlocks = inputLen/16;
#if defined(USE_SSE)
  if (AES_NI)
  {
    blockEncryptSSE(input,numBlocks,outBuffer);
    return;
  }
#elif defined(USE_NEON)
  if (AES_Neon)
  {
    blockEncryptNeon(input,numBlocks,outBuffer);
    return;
  }
#endif
  
  byte *prevBlock = m_initVector;
  for(size_t i = numBlocks;i > 0;i--)
  {
    byte block[16];
    if (CBCMode)
      Xor128(block,prevBlock,input);
    else
      Copy128(block,input);

    byte temp[4][4];

    Xor128(temp,block,m_expandedKey[0]);
    Xor128(outBuffer,   T1[temp[0][0]],T2[temp[1][1]],T3[temp[2][2]],T4[temp[3][3]]);
    Xor128(outBuffer+4, T1[temp[1][0]],T2[temp[2][1]],T3[temp[3][2]],T4[temp[0][3]]);
    Xor128(outBuffer+8, T1[temp[2][0]],T2[temp[3][1]],T3[temp[0][2]],T4[temp[1][3]]);
    Xor128(outBuffer+12,T1[temp[3][0]],T2[temp[0][1]],T3[temp[1][2]],T4[temp[2][3]]);

    for(int r = 1; r < m_uRounds-1; r++)
    {
      Xor128(temp,outBuffer,m_expandedKey[r]);
      Xor128(outBuffer,   T1[temp[0][0]],T2[temp[1][1]],T3[temp[2][2]],T4[temp[3][3]]);
      Xor128(outBuffer+4, T1[temp[1][0]],T2[temp[2][1]],T3[temp[3][2]],T4[temp[0][3]]);
      Xor128(outBuffer+8, T1[temp[2][0]],T2[temp[3][1]],T3[temp[0][2]],T4[temp[1][3]]);
      Xor128(outBuffer+12,T1[temp[3][0]],T2[temp[0][1]],T3[temp[1][2]],T4[temp[2][3]]);
    }
    Xor128(temp,outBuffer,m_expandedKey[m_uRounds-1]);
    outBuffer[ 0] = T1[temp[0][0]][1];
    outBuffer[ 1] = T1[temp[1][1]][1];
    outBuffer[ 2] = T1[temp[2][2]][1];
    outBuffer[ 3] = T1[temp[3][3]][1];
    outBuffer[ 4] = T1[temp[1][0]][1];
    outBuffer[ 5] = T1[temp[2][1]][1];
    outBuffer[ 6] = T1[temp[3][2]][1];
    outBuffer[ 7] = T1[temp[0][3]][1];
    outBuffer[ 8] = T1[temp[2][0]][1];
    outBuffer[ 9] = T1[temp[3][1]][1];
    outBuffer[10] = T1[temp[0][2]][1];
    outBuffer[11] = T1[temp[1][3]][1];
    outBuffer[12] = T1[temp[3][0]][1];
    outBuffer[13] = T1[temp[0][1]][1];
    outBuffer[14] = T1[temp[1][2]][1];
    outBuffer[15] = T1[temp[2][3]][1];
    Xor128(outBuffer,outBuffer,m_expandedKey[m_uRounds]);
    prevBlock=outBuffer;

    outBuffer += 16;
    input += 16;
  }
  Copy128(m_initVector,prevBlock);
}


#ifdef USE_SSE
void Rijndael::blockEncryptSSE(const byte *input,size_t numBlocks,byte *outBuffer)
{
  __m128i v = _mm_loadu_si128((__m128i*)m_initVector);
  __m128i *src=(__m128i*)input;
  __m128i *dest=(__m128i*)outBuffer;
  __m128i *rkey=(__m128i*)m_expandedKey;
  while (numBlocks > 0)
  {
    __m128i d = _mm_loadu_si128(src++);
    if (CBCMode)
      v = _mm_xor_si128(v, d);
    else
      v = d;
    __m128i r0 = _mm_loadu_si128(rkey);
    v = _mm_xor_si128(v, r0);
    
    for (int i=1; i<m_uRounds; i++)
    {
      __m128i ri = _mm_loadu_si128(rkey + i);
      v = _mm_aesenc_si128(v, ri);
    }

    __m128i rl = _mm_loadu_si128(rkey + m_uRounds);
    v = _mm_aesenclast_si128(v, rl);
    _mm_storeu_si128(dest++,v);
    numBlocks--;
  }
  _mm_storeu_si128((__m128i*)m_initVector,v);
}
#endif


#ifdef USE_NEON
void Rijndael::blockEncryptNeon(const byte *input,size_t numBlocks,byte *outBuffer)
{
  byte *prevBlock = m_initVector;
  while (numBlocks > 0)
  {
    byte block[16];
    if (CBCMode)
      vst1q_u8(block, veorq_u8(vld1q_u8(prevBlock), vld1q_u8(input)));
    else
      vst1q_u8(block, vld1q_u8(input));

    uint8x16_t data = vld1q_u8(block);
    for (uint i = 0; i < m_uRounds-1; i++)
    {
      data = vaeseq_u8(data, vld1q_u8((byte *)m_expandedKey[i]));
      data = vaesmcq_u8(data);
    }
    data = vaeseq_u8(data, vld1q_u8((byte *)(m_expandedKey[m_uRounds-1])));
    data = veorq_u8(data, vld1q_u8((byte *)(m_expandedKey[m_uRounds])));
    vst1q_u8(outBuffer, data);

    prevBlock=outBuffer;

    outBuffer += 16;
    input += 16;
    numBlocks--;
  }
  vst1q_u8(m_initVector, vld1q_u8(prevBlock));
  return;
}
#endif

  
void Rijndael::blockDecrypt(const byte *input, size_t inputLen, byte *outBuffer)
{
  if (inputLen <= 0)
    return;

  size_t numBlocks=inputLen/16;
#if defined(USE_SSE)
  if (AES_NI)
  {
    blockDecryptSSE(input,numBlocks,outBuffer);
    return;
  }
#elif defined(USE_NEON)
  if (AES_Neon)
  {
    blockDecryptNeon(input,numBlocks,outBuffer);
    return;
  }
#endif

  byte block[16], iv[4][4];
  memcpy(iv,m_initVector,16); 

  for (size_t i = numBlocks; i > 0; i--)
  {
    byte temp[4][4];
    
    Xor128(temp,input,m_expandedKey[m_uRounds]);

    Xor128(block,   T5[temp[0][0]],T6[temp[3][1]],T7[temp[2][2]],T8[temp[1][3]]);
    Xor128(block+4, T5[temp[1][0]],T6[temp[0][1]],T7[temp[3][2]],T8[temp[2][3]]);
    Xor128(block+8, T5[temp[2][0]],T6[temp[1][1]],T7[temp[0][2]],T8[temp[3][3]]);
    Xor128(block+12,T5[temp[3][0]],T6[temp[2][1]],T7[temp[1][2]],T8[temp[0][3]]);

    for(int r = m_uRounds-1; r > 1; r--)
    {
      Xor128(temp,block,m_expandedKey[r]);
      Xor128(block,   T5[temp[0][0]],T6[temp[3][1]],T7[temp[2][2]],T8[temp[1][3]]);
      Xor128(block+4, T5[temp[1][0]],T6[temp[0][1]],T7[temp[3][2]],T8[temp[2][3]]);
      Xor128(block+8, T5[temp[2][0]],T6[temp[1][1]],T7[temp[0][2]],T8[temp[3][3]]);
      Xor128(block+12,T5[temp[3][0]],T6[temp[2][1]],T7[temp[1][2]],T8[temp[0][3]]);
    }
   
    Xor128(temp,block,m_expandedKey[1]);
    block[ 0] = S5[temp[0][0]];
    block[ 1] = S5[temp[3][1]];
    block[ 2] = S5[temp[2][2]];
    block[ 3] = S5[temp[1][3]];
    block[ 4] = S5[temp[1][0]];
    block[ 5] = S5[temp[0][1]];
    block[ 6] = S5[temp[3][2]];
    block[ 7] = S5[temp[2][3]];
    block[ 8] = S5[temp[2][0]];
    block[ 9] = S5[temp[1][1]];
    block[10] = S5[temp[0][2]];
    block[11] = S5[temp[3][3]];
    block[12] = S5[temp[3][0]];
    block[13] = S5[temp[2][1]];
    block[14] = S5[temp[1][2]];
    block[15] = S5[temp[0][3]];
    Xor128(block,block,m_expandedKey[0]);

    if (CBCMode)
      Xor128(block,block,iv);

    Copy128((byte*)iv,input);
    Copy128(outBuffer,block);

    input += 16;
    outBuffer += 16;
  }

  memcpy(m_initVector,iv,16);
}


#ifdef USE_SSE
void Rijndael::blockDecryptSSE(const byte *input, size_t numBlocks, byte *outBuffer)
{
  __m128i initVector = _mm_loadu_si128((__m128i*)m_initVector);
  __m128i *src=(__m128i*)input;
  __m128i *dest=(__m128i*)outBuffer;
  __m128i *rkey=(__m128i*)m_expandedKey;
  while (numBlocks > 0)
  {
    __m128i rl = _mm_loadu_si128(rkey + m_uRounds);
    __m128i d = _mm_loadu_si128(src++);
    __m128i v = _mm_xor_si128(rl, d);

    for (int i=m_uRounds-1; i>0; i--)
    {
      __m128i ri = _mm_loadu_si128(rkey + i);
      v = _mm_aesdec_si128(v, ri);
    }
    
    __m128i r0 = _mm_loadu_si128(rkey);
    v = _mm_aesdeclast_si128(v, r0);

    if (CBCMode)
      v = _mm_xor_si128(v, initVector);
    initVector = d;
    _mm_storeu_si128(dest++,v);
    numBlocks--;
  }
  _mm_storeu_si128((__m128i*)m_initVector,initVector);
}
#endif


#ifdef USE_NEON
void Rijndael::blockDecryptNeon(const byte *input, size_t numBlocks, byte *outBuffer)
{
  byte iv[16];
  memcpy(iv,m_initVector,16);

  while (numBlocks > 0)
  {
    uint8x16_t data = vld1q_u8(input);

    for (int i=m_uRounds-1; i>0; i--)
    {
      data = vaesdq_u8(data, vld1q_u8((byte *)m_expandedKey[i+1]));
      data = vaesimcq_u8(data);
    }

    data = vaesdq_u8(data, vld1q_u8((byte *)m_expandedKey[1]));
    data = veorq_u8(data, vld1q_u8((byte *)m_expandedKey[0]));

    if (CBCMode)
      data = veorq_u8(data, vld1q_u8(iv));

    vst1q_u8(iv, vld1q_u8(input));
    vst1q_u8(outBuffer, data);

    input += 16;
    outBuffer += 16;
    numBlocks--;
  }

  memcpy(m_initVector,iv,16);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ALGORITHM
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void Rijndael::keySched(byte key[_MAX_KEY_COLUMNS][4])
{
  int j,rconpointer = 0;

  // Calculate the necessary round keys
  // The number of calculations depends on keyBits and blockBits
  int uKeyColumns = m_uRounds - 6;

  byte tempKey[_MAX_KEY_COLUMNS][4];

  // Copy the input key to the temporary key matrix

  memcpy(tempKey,key,sizeof(tempKey));

  int r = 0;
  int t = 0;

  // copy values into round key array
  for(j = 0;(j < uKeyColumns) && (r <= m_uRounds); )
  {
    for(;(j < uKeyColumns) && (t < 4); j++, t++)
      for (int k=0;k<4;k++)
        m_expandedKey[r][t][k]=tempKey[j][k];

    if(t == 4)
    {
      r++;
      t = 0;
    }
  }
    
  while(r <= m_uRounds)
  {
    tempKey[0][0] ^= S[tempKey[uKeyColumns-1][1]];
    tempKey[0][1] ^= S[tempKey[uKeyColumns-1][2]];
    tempKey[0][2] ^= S[tempKey[uKeyColumns-1][3]];
    tempKey[0][3] ^= S[tempKey[uKeyColumns-1][0]];
    tempKey[0][0] ^= rcon[rconpointer++];

    if (uKeyColumns != 8)
      for(j = 1; j < uKeyColumns; j++)
        for (int k=0;k<4;k++)
          tempKey[j][k] ^= tempKey[j-1][k];
    else
    {
      for(j = 1; j < uKeyColumns/2; j++)
        for (int k=0;k<4;k++)
          tempKey[j][k] ^= tempKey[j-1][k];

      tempKey[uKeyColumns/2][0] ^= S[tempKey[uKeyColumns/2 - 1][0]];
      tempKey[uKeyColumns/2][1] ^= S[tempKey[uKeyColumns/2 - 1][1]];
      tempKey[uKeyColumns/2][2] ^= S[tempKey[uKeyColumns/2 - 1][2]];
      tempKey[uKeyColumns/2][3] ^= S[tempKey[uKeyColumns/2 - 1][3]];
      for(j = uKeyColumns/2 + 1; j < uKeyColumns; j++)
        for (int k=0;k<4;k++)
          tempKey[j][k] ^= tempKey[j-1][k];
    }
    for(j = 0; (j < uKeyColumns) && (r <= m_uRounds); )
    {
      for(; (j < uKeyColumns) && (t < 4); j++, t++)
        for (int k=0;k<4;k++)
          m_expandedKey[r][t][k] = tempKey[j][k];
      if(t == 4)
      {
        r++;
        t = 0;
      }
    }
  }   
}

void Rijndael::keyEncToDec()
{
  for(int r = 1; r < m_uRounds; r++)
  {
    byte n_expandedKey[4][4];
    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++)
      {
        byte *w=m_expandedKey[r][j];
        n_expandedKey[j][i]=U1[w[0]][i]^U2[w[1]][i]^U3[w[2]][i]^U4[w[3]][i];
      }
    memcpy(m_expandedKey[r],n_expandedKey,sizeof(m_expandedKey[0]));
  }
} 


static byte gmul(byte a, byte b) // Galois field "peasant's algorithm" multiplication.
{
  const byte poly=0x1b; // Lower byte of AES 0x11b irreducible polynomial.
  byte result = 0;
  while (b>0)
  {
    if ((b & 1) != 0) 
      result ^= a;
    a = (a & 0x80) ? (a<<1)^poly : a<<1;
    b >>= 1;
  }
  return result;
}


// 2021-09-24: changed to slower and simpler code without interim tables.
// It is still fast enough for our purpose.
void Rijndael::GenerateTables()
{
  for (int I=0;I<256;I++)
    S5[S[I]]=I;

  for (int I=0;I<256;I++)
  {   
    byte s=S[I];
    T1[I][1]=T1[I][2]=T2[I][2]=T2[I][3]=T3[I][0]=T3[I][3]=T4[I][0]=T4[I][1]=s;
    T1[I][0]=T2[I][1]=T3[I][2]=T4[I][3]=gmul(s,2);
    T1[I][3]=T2[I][0]=T3[I][1]=T4[I][2]=gmul(s,3);

    byte b=S5[I];
    U1[b][3]=U2[b][0]=U3[b][1]=U4[b][2]=T5[I][3]=T6[I][0]=T7[I][1]=T8[I][2]=gmul(b,0xb);
    U1[b][1]=U2[b][2]=U3[b][3]=U4[b][0]=T5[I][1]=T6[I][2]=T7[I][3]=T8[I][0]=gmul(b,0x9);
    U1[b][2]=U2[b][3]=U3[b][0]=U4[b][1]=T5[I][2]=T6[I][3]=T7[I][0]=T8[I][1]=gmul(b,0xd);
    U1[b][0]=U2[b][1]=U3[b][2]=U4[b][3]=T5[I][0]=T6[I][1]=T7[I][2]=T8[I][3]=gmul(b,0xe);
  }
}


#if 0
static void TestRijndael();
struct TestRij {TestRij() {TestRijndael();exit(0);}} GlobalTestRij;

// Test CBC encryption according to NIST 800-38A.
void TestRijndael()
{
  byte IV[16]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  byte PT[64]={
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10,
  };

  byte Key128[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
  byte Chk128[16]={0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7};
  byte Key192[24]={0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b};
  byte Chk192[16]={0x08,0xb0,0xe2,0x79,0x88,0x59,0x88,0x81,0xd9,0x20,0xa9,0xe6,0x4f,0x56,0x15,0xcd};
  byte Key256[32]={0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
  byte Chk256[16]={0xb2,0xeb,0x05,0xe2,0xc3,0x9b,0xe9,0xfc,0xda,0x6c,0x19,0x07,0x8c,0x6a,0x9d,0x1b};
  byte *Key[3]={Key128,Key192,Key256};
  byte *Chk[3]={Chk128,Chk192,Chk256};

  Rijndael rij; // Declare outside of loop to test re-initialization.
  for (uint L=0;L<3;L++)
  {
    byte Out[16];
    wchar Str[sizeof(Out)*2+1];

    uint KeyLength=128+L*64;
    rij.Init(true,Key[L],KeyLength,IV);
    for (uint I=0;I<sizeof(PT);I+=16)
      rij.blockEncrypt(PT+I,16,Out);
    BinToHex(Chk[L],16,NULL,Str,ASIZE(Str));
    mprintf(L"\nAES-%d expected: %s",KeyLength,Str);
    BinToHex(Out,sizeof(Out),NULL,Str,ASIZE(Str));
    mprintf(L"\nAES-%d result:   %s",KeyLength,Str);
    if (memcmp(Out,Chk[L],16)==0)
      mprintf(L" OK");
    else
    {
      mprintf(L" FAILED");
      getchar();
    }
  }
}
#endif

#include "rar.hpp"

// We used "Screaming Fast Galois Field Arithmetic Using Intel SIMD
// Instructions" paper by James S. Plank, Kevin M. Greenan
// and Ethan L. Miller for fast SSE based multiplication.
// Also we are grateful to Artem Drobanov and Bulat Ziganshin
// for samples and ideas allowed to make Reed-Solomon codec more efficient.

RSCoder16::RSCoder16()
{
  Decoding=false;
  ND=NR=NE=0;
  ValidFlags=NULL;
  MX=NULL;
  DataLog=NULL;
  DataLogSize=0;

  gfInit();
}


RSCoder16::~RSCoder16()
{
  delete[] gfExp;
  delete[] gfLog;
  delete[] DataLog;
  delete[] MX;
  delete[] ValidFlags;
}


// Initialize logarithms and exponents Galois field tables.
void RSCoder16::gfInit()
{
  gfExp=new uint[4*gfSize+1];
  gfLog=new uint[gfSize+1];

  for (uint L=0,E=1;L<gfSize;L++)
  {
    gfLog[E]=L;
    gfExp[L]=E;
    gfExp[L+gfSize]=E;  // Duplicate the table to avoid gfExp overflow check.
    E<<=1;
    if (E>gfSize)
      E^=0x1100B; // Irreducible field-generator polynomial.
  }

  // log(0)+log(x) must be outside of usual log table, so we can set it
  // to 0 and avoid check for 0 in multiplication parameters.
  gfLog[0]= 2*gfSize;
  for (uint I=2*gfSize;I<=4*gfSize;I++) // Results for log(0)+log(x).
    gfExp[I]=0;
}


uint RSCoder16::gfAdd(uint a,uint b) // Addition in Galois field.
{
  return a^b;
}


uint RSCoder16::gfMul(uint a,uint b) // Multiplication in Galois field.
{
  return gfExp[gfLog[a]+gfLog[b]];
}


uint RSCoder16::gfInv(uint a) // Inverse element in Galois field.
{
  return a==0 ? 0:gfExp[gfSize-gfLog[a]];
}


bool RSCoder16::Init(uint DataCount, uint RecCount, bool *ValidityFlags)
{
  ND = DataCount;
  NR = RecCount;
  NE = 0;

  Decoding=ValidityFlags!=NULL;
  if (Decoding)
  {
    delete[] ValidFlags;
    ValidFlags=new bool[ND + NR];

    for (uint I = 0; I < ND + NR; I++)
      ValidFlags[I]=ValidityFlags[I];
    for (uint I = 0; I < ND; I++)
      if (!ValidFlags[I])
        NE++;
    uint ValidECC=0;
    for (uint I = ND; I < ND + NR; I++)
      if (ValidFlags[I])
        ValidECC++;
    if (NE > ValidECC || NE == 0 || ValidECC == 0)
      return false;
  }
  if (ND + NR > gfSize || NR > ND || ND == 0 || NR == 0)
    return false;

  delete[] MX;
  if (Decoding)
  {
    MX=new uint[NE * ND];
    MakeDecoderMatrix();
    InvertDecoderMatrix();
  }
  else
  {
    MX=new uint[NR * ND];
    MakeEncoderMatrix();
  }
  return true;
}


void RSCoder16::MakeEncoderMatrix()
{
  // Create Cauchy encoder generator matrix. Skip trivial "1" diagonal rows,
  // which would just copy source data to destination.
  for (uint I = 0; I < NR; I++)
    for (uint J = 0; J < ND; J++)
      MX[I * ND + J] = gfInv( gfAdd( (I+ND), J) );
}


void RSCoder16::MakeDecoderMatrix()
{
  // Create Cauchy decoder matrix. Skip trivial rows matching valid data
  // units and containing "1" on main diagonal. Such rows would just copy
  // source data to destination and they have no real value for us.
  // Include rows only for broken data units and replace them by first
  // available valid recovery code rows.
  for (uint Flag=0, R=ND, Dest=0; Flag < ND; Flag++)
    if (!ValidFlags[Flag]) // For every broken data unit.
    {
      while (!ValidFlags[R]) // Find a valid recovery unit.
        R++;
      for (uint J = 0; J < ND; J++) // And place its row to matrix.
        MX[Dest*ND + J] = gfInv( gfAdd(R,J) );
      Dest++;
      R++;
    }
}


// Apply Gauss–Jordan elimination to find inverse of decoder matrix.
// We have the square NDxND matrix, but we do not store its trivial
// diagonal "1" rows matching valid data, so we work with NExND matrix.
// Our original Cauchy matrix does not contain 0, so we skip search
// for non-zero pivot.
void RSCoder16::InvertDecoderMatrix()
{
  uint *MI=new uint[NE * ND]; // We'll create inverse matrix here.
  memset(MI, 0, ND * NE * sizeof(*MI)); // Initialize to identity matrix.
  for (uint Kr = 0, Kf = 0; Kr < NE; Kr++, Kf++)
  {
    while (ValidFlags[Kf]) // Skip trivial rows.
      Kf++;
    MI[Kr * ND + Kf] = 1;  // Set diagonal 1.
  }

  // Kr is the number of row in our actual reduced NE x ND matrix,
  // which does not contain trivial diagonal 1 rows.
  // Kf is the number of row in full ND x ND matrix with all trivial rows
  // included.
  for (uint Kr = 0, Kf = 0; Kf < ND; Kr++, Kf++) // Select pivot row.
  {
    while (ValidFlags[Kf] && Kf < ND)
    {
      // Here we process trivial diagonal 1 rows matching valid data units.
      // Their processing can be simplified comparing to usual rows.
      // In full version of elimination we would set MX[I * ND + Kf] to zero
      // after MI[..]^=, but we do not need it for matrix inversion.
      for (uint I = 0; I < NE; I++)
        MI[I * ND + Kf] ^= MX[I * ND + Kf];
      Kf++;
    }

    if (Kf == ND)
      break;

    uint *MXk = MX + Kr * ND; // k-th row of main matrix.
    uint *MIk = MI + Kr * ND; // k-th row of inversion matrix.

    uint PInv = gfInv( MXk[Kf] ); // Pivot inverse.
    // Divide the pivot row by pivot, so pivot cell contains 1.
    for (uint I = 0; I < ND; I++)
    {
      MXk[I] = gfMul( MXk[I], PInv );
      MIk[I] = gfMul( MIk[I], PInv );
    }

    for (uint I = 0; I < NE; I++)
      if (I != Kr) // For all rows except containing the pivot cell.
      {
        // Apply Gaussian elimination Mij -= Mkj * Mik / pivot.
        // Since pivot is already 1, it is reduced to Mij -= Mkj * Mik.
        uint *MXi = MX + I * ND; // i-th row of main matrix.
        uint *MIi = MI + I * ND; // i-th row of inversion matrix.
        uint Mik = MXi[Kf]; // Cell in pivot position.
        for (uint J = 0; J < ND; J++)
        {
          MXi[J] ^= gfMul(MXk[J] , Mik);
          MIi[J] ^= gfMul(MIk[J] , Mik);
        }
      }
  }

  // Copy data to main matrix.
  for (uint I = 0; I < NE * ND; I++)
    MX[I] = MI[I];

  delete[] MI;
}


#if 0
// Multiply matrix to data vector. When encoding, it contains data in Data
// and stores error correction codes in Out. When decoding it contains
// broken data followed by ECC in Data and stores recovered data to Out.
// We do not use this function now, everything is moved to UpdateECC.
void RSCoder16::Process(const uint *Data, uint *Out)
{
  uint ProcData[gfSize];

  for (uint I = 0; I < ND; I++)
    ProcData[I]=Data[I];

  if (Decoding)
  {
    // Replace broken data units with first available valid recovery codes.
    // 'Data' array must contain recovery codes after data.
    for (uint I=0, R=ND, Dest=0; I < ND; I++)
      if (!ValidFlags[I]) // For every broken data unit.
      {
        while (!ValidFlags[R]) // Find a valid recovery unit.
          R++;
        ProcData[I]=Data[R];
        R++;
      }
  }

  uint H=Decoding ? NE : NR;
  for (uint I = 0; I < H; I++)
  {
    uint R = 0; // Result of matrix row multiplication to data.

    uint *MXi=MX + I * ND;
    for (uint J = 0; J < ND; J++)
      R ^= gfMul(MXi[J], ProcData[J]);

    Out[I] = R;
  }
}
#endif


// We update ECC in blocks by applying every data block to all ECC blocks.
// This function applies one data block to one ECC block.
void RSCoder16::UpdateECC(uint DataNum, uint ECCNum, const byte *Data, byte *ECC, size_t BlockSize)
{
  if (DataNum==0) // Init ECC data.
    memset(ECC, 0, BlockSize);

  bool DirectAccess;
#ifdef LITTLE_ENDIAN
  // We can access data and ECC directly if we have little endian 16 bit uint.
  DirectAccess=sizeof(ushort)==2;
#else
  DirectAccess=false;
#endif

#ifdef USE_SSE
  if (DirectAccess && SSE_UpdateECC(DataNum,ECCNum,Data,ECC,BlockSize))
    return;
#endif

  if (ECCNum==0)
  {
    if (DataLogSize!=BlockSize)
    {
      delete[] DataLog;
      DataLog=new uint[BlockSize];
      DataLogSize=BlockSize;

    }
    if (DirectAccess)
      for (size_t I=0; I<BlockSize; I+=2)
        DataLog[I] = gfLog[ *(ushort*)(Data+I) ];
    else
      for (size_t I=0; I<BlockSize; I+=2)
      {
        uint D=Data[I]+Data[I+1]*256;
        DataLog[I] = gfLog[ D ];
      }
  }

  uint ML = gfLog[ MX[ECCNum * ND + DataNum] ];

  if (DirectAccess)
    for (size_t I=0; I<BlockSize; I+=2)
      *(ushort*)(ECC+I) ^= gfExp[ ML + DataLog[I] ];
  else
    for (size_t I=0; I<BlockSize; I+=2)
    {
      uint R=gfExp[ ML + DataLog[I] ];
      ECC[I]^=byte(R);
      ECC[I+1]^=byte(R/256);
    }
}


#ifdef USE_SSE
// Data and ECC addresses must be properly aligned for SSE.
// AVX2 did not provide a noticeable speed gain on i7-6700K here.
bool RSCoder16::SSE_UpdateECC(uint DataNum, uint ECCNum, const byte *Data, byte *ECC, size_t BlockSize)
{
  // Check data alignment and SSSE3 support.
  if ((size_t(Data) & (SSE_ALIGNMENT-1))!=0 || (size_t(ECC) & (SSE_ALIGNMENT-1))!=0 ||
      _SSE_Version<SSE_SSSE3)
    return false;

  uint M=MX[ECCNum * ND + DataNum];

  // Prepare tables containing products of M and 4, 8, 12, 16 bit length
  // numbers, which have 4 high bits in 0..15 range and other bits set to 0.
  // Store high and low bytes of resulting 16 bit product in separate tables.
  __m128i T0L,T1L,T2L,T3L; // Low byte tables.
  __m128i T0H,T1H,T2H,T3H; // High byte tables.

  for (uint I=0;I<16;I++)
  {
    ((byte *)&T0L)[I]=gfMul(I,M);
    ((byte *)&T0H)[I]=gfMul(I,M)>>8;
    ((byte *)&T1L)[I]=gfMul(I<<4,M);
    ((byte *)&T1H)[I]=gfMul(I<<4,M)>>8;
    ((byte *)&T2L)[I]=gfMul(I<<8,M);
    ((byte *)&T2H)[I]=gfMul(I<<8,M)>>8;
    ((byte *)&T3L)[I]=gfMul(I<<12,M);
    ((byte *)&T3H)[I]=gfMul(I<<12,M)>>8;
  }

  size_t Pos=0;

  __m128i LowByteMask=_mm_set1_epi16(0xff);     // 00ff00ff...00ff
  __m128i Low4Mask=_mm_set1_epi8(0xf);          // 0f0f0f0f...0f0f
  __m128i High4Mask=_mm_slli_epi16(Low4Mask,4); // f0f0f0f0...f0f0

  for (; Pos+2*sizeof(__m128i)<=BlockSize; Pos+=2*sizeof(__m128i))
  {
    // We process two 128 bit chunks of source data at once.
    __m128i *D=(__m128i *)(Data+Pos);

    // Place high bytes of both chunks to one variable and low bytes to
    // another, so we can use the table lookup multiplication for 16 values
    // 4 bit length each at once.
    __m128i HighBytes0=_mm_srli_epi16(D[0],8);
    __m128i LowBytes0=_mm_and_si128(D[0],LowByteMask);
    __m128i HighBytes1=_mm_srli_epi16(D[1],8);
    __m128i LowBytes1=_mm_and_si128(D[1],LowByteMask);
    __m128i HighBytes=_mm_packus_epi16(HighBytes0,HighBytes1);
    __m128i LowBytes=_mm_packus_epi16(LowBytes0,LowBytes1);

    // Multiply bits 0..3 of low bytes. Store low and high product bytes
    // separately in cumulative sum variables.
    __m128i LowBytesLow4=_mm_and_si128(LowBytes,Low4Mask);
    __m128i LowBytesMultSum=_mm_shuffle_epi8(T0L,LowBytesLow4);
    __m128i HighBytesMultSum=_mm_shuffle_epi8(T0H,LowBytesLow4);

    // Multiply bits 4..7 of low bytes. Store low and high product bytes separately.
    __m128i LowBytesHigh4=_mm_and_si128(LowBytes,High4Mask);
            LowBytesHigh4=_mm_srli_epi16(LowBytesHigh4,4);
    __m128i LowBytesHigh4MultLow=_mm_shuffle_epi8(T1L,LowBytesHigh4);
    __m128i LowBytesHigh4MultHigh=_mm_shuffle_epi8(T1H,LowBytesHigh4);

    // Add new product to existing sum, low and high bytes separately.
    LowBytesMultSum=_mm_xor_si128(LowBytesMultSum,LowBytesHigh4MultLow);
    HighBytesMultSum=_mm_xor_si128(HighBytesMultSum,LowBytesHigh4MultHigh);

    // Multiply bits 0..3 of high bytes. Store low and high product bytes separately.
    __m128i HighBytesLow4=_mm_and_si128(HighBytes,Low4Mask);
    __m128i HighBytesLow4MultLow=_mm_shuffle_epi8(T2L,HighBytesLow4);
    __m128i HighBytesLow4MultHigh=_mm_shuffle_epi8(T2H,HighBytesLow4);

    // Add new product to existing sum, low and high bytes separately.
    LowBytesMultSum=_mm_xor_si128(LowBytesMultSum,HighBytesLow4MultLow);
    HighBytesMultSum=_mm_xor_si128(HighBytesMultSum,HighBytesLow4MultHigh);

    // Multiply bits 4..7 of high bytes. Store low and high product bytes separately.
    __m128i HighBytesHigh4=_mm_and_si128(HighBytes,High4Mask);
            HighBytesHigh4=_mm_srli_epi16(HighBytesHigh4,4);
    __m128i HighBytesHigh4MultLow=_mm_shuffle_epi8(T3L,HighBytesHigh4);
    __m128i HighBytesHigh4MultHigh=_mm_shuffle_epi8(T3H,HighBytesHigh4);

    // Add new product to existing sum, low and high bytes separately.
    LowBytesMultSum=_mm_xor_si128(LowBytesMultSum,HighBytesHigh4MultLow);
    HighBytesMultSum=_mm_xor_si128(HighBytesMultSum,HighBytesHigh4MultHigh);

    // Combine separate low and high cumulative sum bytes to 16-bit words.
    __m128i HighBytesHigh4Mult0=_mm_unpacklo_epi8(LowBytesMultSum,HighBytesMultSum);
    __m128i HighBytesHigh4Mult1=_mm_unpackhi_epi8(LowBytesMultSum,HighBytesMultSum);

    // Add result to ECC.
    __m128i *StoreECC=(__m128i *)(ECC+Pos);

    StoreECC[0]=_mm_xor_si128(StoreECC[0],HighBytesHigh4Mult0);
    StoreECC[1]=_mm_xor_si128(StoreECC[1],HighBytesHigh4Mult1);
  }

  // If we have non 128 bit aligned data in the end of block, process them
  // in a usual way. We cannot do the same in the beginning of block,
  // because Data and ECC can have different alignment offsets.
  for (; Pos<BlockSize; Pos+=2)
    *(ushort*)(ECC+Pos) ^= gfMul( M, *(ushort*)(Data+Pos) );

  return true;
}
#endif

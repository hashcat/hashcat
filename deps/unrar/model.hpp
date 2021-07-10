#ifndef _RAR_PPMMODEL_
#define _RAR_PPMMODEL_

#include "coder.hpp"
#include "suballoc.hpp"

#ifdef ALLOW_MISALIGNED
#pragma pack(1)
#endif

struct RARPPM_DEF
{
  static const int INT_BITS=7, PERIOD_BITS=7, TOT_BITS=INT_BITS+PERIOD_BITS,
    INTERVAL=1 << INT_BITS, BIN_SCALE=1 << TOT_BITS, MAX_FREQ=124;
};

struct RARPPM_SEE2_CONTEXT : RARPPM_DEF
{ // SEE-contexts for PPM-contexts with masked symbols
  ushort Summ;
  byte Shift, Count;
  void init(int InitVal)
  {
    Summ=InitVal << (Shift=PERIOD_BITS-4);
    Count=4;
  }
  uint getMean()
  {
    uint RetVal=GET_SHORT16(Summ) >> Shift;
    Summ -= RetVal;
    return RetVal+(RetVal == 0);
  }
  void update()
  {
    if (Shift < PERIOD_BITS && --Count == 0)
    {
      Summ += Summ;
      Count=3 << Shift++;
    }
  }
};


class ModelPPM;
struct RARPPM_CONTEXT;

struct RARPPM_STATE
{
  byte Symbol;
  byte Freq;
  RARPPM_CONTEXT* Successor;
};


struct RARPPM_CONTEXT : RARPPM_DEF
{
    ushort NumStats;

    struct FreqData
    {
      ushort SummFreq;
      RARPPM_STATE RARPPM_PACK_ATTR * Stats;
    };
    
    union
    {
      FreqData U;
      RARPPM_STATE OneState;
    };

    RARPPM_CONTEXT* Suffix;
    inline void encodeBinSymbol(ModelPPM *Model,int symbol);  // MaxOrder:
    inline void encodeSymbol1(ModelPPM *Model,int symbol);    //  ABCD    context
    inline void encodeSymbol2(ModelPPM *Model,int symbol);    //   BCD    suffix
    inline void decodeBinSymbol(ModelPPM *Model);  //   BCDE   successor
    inline bool decodeSymbol1(ModelPPM *Model);    // other orders:
    inline bool decodeSymbol2(ModelPPM *Model);    //   BCD    context
    inline void update1(ModelPPM *Model,RARPPM_STATE* p); //    CD    suffix
    inline void update2(ModelPPM *Model,RARPPM_STATE* p); //   BCDE   successor
    void rescale(ModelPPM *Model);
    inline RARPPM_CONTEXT* createChild(ModelPPM *Model,RARPPM_STATE* pStats,RARPPM_STATE& FirstState);
    inline RARPPM_SEE2_CONTEXT* makeEscFreq2(ModelPPM *Model,int Diff);
};

#ifdef ALLOW_MISALIGNED
#ifdef _AIX
#pragma pack(pop)
#else
#pragma pack()
#endif
#endif

class ModelPPM : RARPPM_DEF
{
  private:
    friend struct RARPPM_CONTEXT;
    
    RARPPM_SEE2_CONTEXT SEE2Cont[25][16], DummySEE2Cont;
    
    struct RARPPM_CONTEXT *MinContext, *MedContext, *MaxContext;
    RARPPM_STATE* FoundState;      // found next state transition
    int NumMasked, InitEsc, OrderFall, MaxOrder, RunLength, InitRL;
    byte CharMask[256], NS2Indx[256], NS2BSIndx[256], HB2Flag[256];
    byte EscCount, PrevSuccess, HiBitsFlag;
    ushort BinSumm[128][64];               // binary SEE-contexts

    RangeCoder Coder;
    SubAllocator SubAlloc;

    void RestartModelRare();
    void StartModelRare(int MaxOrder);
    inline RARPPM_CONTEXT* CreateSuccessors(bool Skip,RARPPM_STATE* p1);

    inline void UpdateModel();
    inline void ClearMask();
  public:
    ModelPPM();
    void CleanUp(); // reset PPM variables after data error
    bool DecodeInit(Unpack *UnpackRead,int &EscChar,byte *hcppm);
    int DecodeChar();
};

#endif

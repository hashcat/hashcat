/****************************************************************************
 *  This file is part of PPMd project                                       *
 *  Written and distributed to public domain by Dmitry Shkarin 1997,        *
 *  1999-2000                                                               *
 *  Contents: model description and encoding/decoding routines              *
 ****************************************************************************/

static const int MAX_O=64; /* maximum allowed model order */
const uint TOP=1 << 24, BOT=1 << 15;

template <class T>
inline void _PPMD_SWAP(T& t1,T& t2) { T tmp=t1; t1=t2; t2=tmp; }


inline RARPPM_CONTEXT* RARPPM_CONTEXT::createChild(ModelPPM *Model,RARPPM_STATE* pStats,
                                             RARPPM_STATE& FirstState)
{
  RARPPM_CONTEXT* pc = (RARPPM_CONTEXT*) Model->SubAlloc.AllocContext();
  if ( pc ) 
  {
    pc->NumStats=1;                     
    pc->OneState=FirstState;
    pc->Suffix=this;                    
    pStats->Successor=pc;
  }
  return pc;
}


ModelPPM::ModelPPM()
{
  MinContext=NULL;
  MaxContext=NULL;
  MedContext=NULL;
}


void ModelPPM::RestartModelRare()
{
  int i, k, m;
  memset(CharMask,0,sizeof(CharMask));
  SubAlloc.InitSubAllocator();
  InitRL=-(MaxOrder < 12 ? MaxOrder:12)-1;
  MinContext = MaxContext = (RARPPM_CONTEXT*) SubAlloc.AllocContext();
  if (MinContext == NULL)
    throw std::bad_alloc();
  MinContext->Suffix=NULL;
  OrderFall=MaxOrder;
  MinContext->U.SummFreq=(MinContext->NumStats=256)+1;
  FoundState=MinContext->U.Stats=(RARPPM_STATE*)SubAlloc.AllocUnits(256/2);
  if (FoundState == NULL)
    throw std::bad_alloc();
  for (RunLength=InitRL, PrevSuccess=i=0;i < 256;i++) 
  {
    MinContext->U.Stats[i].Symbol=i;      
    MinContext->U.Stats[i].Freq=1;
    MinContext->U.Stats[i].Successor=NULL;
  }
  
  static const ushort InitBinEsc[]={
    0x3CDD,0x1F3F,0x59BF,0x48F3,0x64A1,0x5ABC,0x6632,0x6051
  };

  for (i=0;i < 128;i++)
    for (k=0;k < 8;k++)
      for (m=0;m < 64;m += 8)
        BinSumm[i][k+m]=BIN_SCALE-InitBinEsc[k]/(i+2);
  for (i=0;i < 25;i++)
    for (k=0;k < 16;k++)            
      SEE2Cont[i][k].init(5*i+10);
}


void ModelPPM::StartModelRare(int MaxOrder)
{
  int i, k, m ,Step;
  EscCount=1;
/*
  if (MaxOrder < 2) 
  {
    memset(CharMask,0,sizeof(CharMask));
    OrderFall=ModelPPM::MaxOrder;
    MinContext=MaxContext;
    while (MinContext->Suffix != NULL)
    {
      MinContext=MinContext->Suffix;
      OrderFall--;
    }
    FoundState=MinContext->U.Stats;
    MinContext=MaxContext;
  } 
  else 
*/
  {
    ModelPPM::MaxOrder=MaxOrder;
    RestartModelRare();
    NS2BSIndx[0]=2*0;
    NS2BSIndx[1]=2*1;
    memset(NS2BSIndx+2,2*2,9);
    memset(NS2BSIndx+11,2*3,256-11);
    for (i=0;i < 3;i++)
      NS2Indx[i]=i;
    for (m=i, k=Step=1;i < 256;i++) 
    {
      NS2Indx[i]=m;
      if ( !--k ) 
      { 
        k = ++Step;
        m++; 
      }
    }
    memset(HB2Flag,0,0x40);
    memset(HB2Flag+0x40,0x08,0x100-0x40);
    DummySEE2Cont.Shift=PERIOD_BITS;
  }
}


void RARPPM_CONTEXT::rescale(ModelPPM *Model)
{
  int OldNS=NumStats, i=NumStats-1, Adder, EscFreq;
  RARPPM_STATE* p1, * p;
  for (p=Model->FoundState;p != U.Stats;p--)
    _PPMD_SWAP(p[0],p[-1]);
  U.Stats->Freq += 4;
  U.SummFreq += 4;
  EscFreq=U.SummFreq-p->Freq;
  Adder=(Model->OrderFall != 0);
  U.SummFreq = (p->Freq=(p->Freq+Adder) >> 1);
  do 
  {
    EscFreq -= (++p)->Freq;
    U.SummFreq += (p->Freq=(p->Freq+Adder) >> 1);
    if (p[0].Freq > p[-1].Freq) 
    {
      RARPPM_STATE tmp=*(p1=p);
      do 
      { 
        p1[0]=p1[-1]; 
      } while (--p1 != U.Stats && tmp.Freq > p1[-1].Freq);
      *p1=tmp;
    }
  } while ( --i );
  if (p->Freq == 0) 
  {
    do 
    { 
      i++; 
    } while ((--p)->Freq == 0);
    EscFreq += i;
    if ((NumStats -= i) == 1) 
    {
      RARPPM_STATE tmp=*U.Stats;
      do 
      { 
        tmp.Freq-=(tmp.Freq >> 1); 
        EscFreq>>=1; 
      } while (EscFreq > 1);
      Model->SubAlloc.FreeUnits(U.Stats,(OldNS+1) >> 1);
      *(Model->FoundState=&OneState)=tmp;  return;
    }
  }
  U.SummFreq += (EscFreq -= (EscFreq >> 1));
  int n0=(OldNS+1) >> 1, n1=(NumStats+1) >> 1;
  if (n0 != n1)
    U.Stats = (RARPPM_STATE*) Model->SubAlloc.ShrinkUnits(U.Stats,n0,n1);
  Model->FoundState=U.Stats;
}


inline RARPPM_CONTEXT* ModelPPM::CreateSuccessors(bool Skip,RARPPM_STATE* p1)
{
  RARPPM_STATE UpState;
  RARPPM_CONTEXT* pc=MinContext, * UpBranch=FoundState->Successor;
  RARPPM_STATE * p, * ps[MAX_O], ** pps=ps;
  if ( !Skip ) 
  {
    *pps++ = FoundState;
    if ( !pc->Suffix )
      goto NO_LOOP;
  }
  if ( p1 ) 
  {
    p=p1;
    pc=pc->Suffix;
    goto LOOP_ENTRY;
  }
  do 
  {
    pc=pc->Suffix;
    if (pc->NumStats != 1) 
    {
      if ((p=pc->U.Stats)->Symbol != FoundState->Symbol)
        do 
        {
          p++; 
        } while (p->Symbol != FoundState->Symbol);
    } 
    else
      p=&(pc->OneState);
LOOP_ENTRY:
    if (p->Successor != UpBranch) 
    {
      pc=p->Successor;
      break;

    }
    // We ensure that PPM order input parameter does not exceed MAX_O (64),
    // so we do not really need this check and added it for extra safety.
    // See CVE-2017-17969 for details.
    if (pps>=ps+ASIZE(ps))
      return NULL;

    *pps++ = p;
  } while ( pc->Suffix );
NO_LOOP:
  if (pps == ps)
    return pc;
  UpState.Symbol=*(byte*) UpBranch;
  UpState.Successor=(RARPPM_CONTEXT*) (((byte*) UpBranch)+1);
  if (pc->NumStats != 1) 
  {
    if ((byte*) pc <= SubAlloc.pText)
      return(NULL);
    if ((p=pc->U.Stats)->Symbol != UpState.Symbol)
    do 
    { 
      p++; 
    } while (p->Symbol != UpState.Symbol);
    uint cf=p->Freq-1;
    uint s0=pc->U.SummFreq-pc->NumStats-cf;
    UpState.Freq=1+((2*cf <= s0)?(5*cf > s0):((2*cf+3*s0-1)/(2*s0)));
  } 
  else
    UpState.Freq=pc->OneState.Freq;
  do 
  {
    pc = pc->createChild(this,*--pps,UpState);
    if ( !pc )
      return NULL;
  } while (pps != ps);
  return pc;
}


inline void ModelPPM::UpdateModel()
{
  RARPPM_STATE fs = *FoundState, *p = NULL;
  RARPPM_CONTEXT *pc, *Successor;
  uint ns1, ns, cf, sf, s0;
  if (fs.Freq < MAX_FREQ/4 && (pc=MinContext->Suffix) != NULL) 
  {
    if (pc->NumStats != 1) 
    {
      if ((p=pc->U.Stats)->Symbol != fs.Symbol) 
      {
        do 
        { 
          p++; 
        } while (p->Symbol != fs.Symbol);
        if (p[0].Freq >= p[-1].Freq) 
        {
          _PPMD_SWAP(p[0],p[-1]); 
          p--;
        }
      }
      if (p->Freq < MAX_FREQ-9) 
      {
        p->Freq += 2;               
        pc->U.SummFreq += 2;
      }
    } 
    else 
    {
      p=&(pc->OneState);
      p->Freq += (p->Freq < 32);
    }
  }
  if ( !OrderFall ) 
  {
    MinContext=MaxContext=FoundState->Successor=CreateSuccessors(TRUE,p);
    if ( !MinContext )
      goto RESTART_MODEL;
    return;
  }
  *SubAlloc.pText++ = fs.Symbol;                   
  Successor = (RARPPM_CONTEXT*) SubAlloc.pText;
  if (SubAlloc.pText >= SubAlloc.FakeUnitsStart)                
    goto RESTART_MODEL;
  if ( fs.Successor ) 
  {
    if ((byte*) fs.Successor <= SubAlloc.pText &&
        (fs.Successor=CreateSuccessors(FALSE,p)) == NULL)
      goto RESTART_MODEL;
    if ( !--OrderFall ) 
    {
      Successor=fs.Successor;
      SubAlloc.pText -= (MaxContext != MinContext);
    }
  } 
  else 
  {
    FoundState->Successor=Successor;
    fs.Successor=MinContext;
  }
  s0=MinContext->U.SummFreq-(ns=MinContext->NumStats)-(fs.Freq-1);
  for (pc=MaxContext;pc != MinContext;pc=pc->Suffix) 
  {
    if ((ns1=pc->NumStats) != 1) 
    {
      if ((ns1 & 1) == 0) 
      {
        pc->U.Stats=(RARPPM_STATE*) SubAlloc.ExpandUnits(pc->U.Stats,ns1 >> 1);
        if ( !pc->U.Stats )           
          goto RESTART_MODEL;
      }
      pc->U.SummFreq += (2*ns1 < ns)+2*((4*ns1 <= ns) & (pc->U.SummFreq <= 8*ns1));
    } 
    else 
    {
      p=(RARPPM_STATE*) SubAlloc.AllocUnits(1);
      if ( !p )
        goto RESTART_MODEL;
      *p=pc->OneState;
      pc->U.Stats=p;
      if (p->Freq < MAX_FREQ/4-1)
        p->Freq += p->Freq;
      else
        p->Freq  = MAX_FREQ-4;
      pc->U.SummFreq=p->Freq+InitEsc+(ns > 3);
    }
    cf=2*fs.Freq*(pc->U.SummFreq+6);
    sf=s0+pc->U.SummFreq;
    if (cf < 6*sf) 
    {
      cf=1+(cf > sf)+(cf >= 4*sf);
      pc->U.SummFreq += 3;
    }
    else 
    {
      cf=4+(cf >= 9*sf)+(cf >= 12*sf)+(cf >= 15*sf);
      pc->U.SummFreq += cf;
    }
    p=pc->U.Stats+ns1;
    p->Successor=Successor;
    p->Symbol = fs.Symbol;
    p->Freq = cf;
    pc->NumStats=++ns1;
  }
  MaxContext=MinContext=fs.Successor;
  return;
RESTART_MODEL:
  RestartModelRare();
  EscCount=0;
}


// Tabulated escapes for exponential symbol distribution
static const byte ExpEscape[16]={ 25,14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2 };
#define GET_MEAN(SUMM,SHIFT,ROUND) ((SUMM+(1 << (SHIFT-ROUND))) >> (SHIFT))



inline void RARPPM_CONTEXT::decodeBinSymbol(ModelPPM *Model)
{
  RARPPM_STATE& rs=OneState;
  Model->HiBitsFlag=Model->HB2Flag[Model->FoundState->Symbol];
  ushort& bs=Model->BinSumm[rs.Freq-1][Model->PrevSuccess+
           Model->NS2BSIndx[Suffix->NumStats-1]+
           Model->HiBitsFlag+2*Model->HB2Flag[rs.Symbol]+
           ((Model->RunLength >> 26) & 0x20)];
  if (Model->Coder.GetCurrentShiftCount(TOT_BITS) < bs) 
  {
    Model->FoundState=&rs;
    rs.Freq += (rs.Freq < 128);
    Model->Coder.SubRange.LowCount=0;
    Model->Coder.SubRange.HighCount=bs;
    bs = GET_SHORT16(bs+INTERVAL-GET_MEAN(bs,PERIOD_BITS,2));
    Model->PrevSuccess=1;
    Model->RunLength++;
  } 
  else 
  {
    Model->Coder.SubRange.LowCount=bs;
    bs = GET_SHORT16(bs-GET_MEAN(bs,PERIOD_BITS,2));
    Model->Coder.SubRange.HighCount=BIN_SCALE;
    Model->InitEsc=ExpEscape[bs >> 10];
    Model->NumMasked=1;
    Model->CharMask[rs.Symbol]=Model->EscCount;
    Model->PrevSuccess=0;
    Model->FoundState=NULL;
  }
}


inline void RARPPM_CONTEXT::update1(ModelPPM *Model,RARPPM_STATE* p)
{
  (Model->FoundState=p)->Freq += 4;              
  U.SummFreq += 4;
  if (p[0].Freq > p[-1].Freq) 
  {
    _PPMD_SWAP(p[0],p[-1]);                   
    Model->FoundState=--p;
    if (p->Freq > MAX_FREQ)             
      rescale(Model);
  }
}




inline bool RARPPM_CONTEXT::decodeSymbol1(ModelPPM *Model)
{
  Model->Coder.SubRange.scale=U.SummFreq;
  RARPPM_STATE* p=U.Stats;
  int i, HiCnt;
  int count=Model->Coder.GetCurrentCount();
  if (count>=(int)Model->Coder.SubRange.scale)
    return(false);
  if (count < (HiCnt=p->Freq)) 
  {
    Model->PrevSuccess=(2*(Model->Coder.SubRange.HighCount=HiCnt) > Model->Coder.SubRange.scale);
    Model->RunLength += Model->PrevSuccess;
    (Model->FoundState=p)->Freq=(HiCnt += 4);
    U.SummFreq += 4;
    if (HiCnt > MAX_FREQ)
      rescale(Model);
    Model->Coder.SubRange.LowCount=0;
    return(true);
  }
  else
    if (Model->FoundState==NULL)
      return(false);
  Model->PrevSuccess=0;
  i=NumStats-1;
  while ((HiCnt += (++p)->Freq) <= count)
    if (--i == 0) 
    {
      Model->HiBitsFlag=Model->HB2Flag[Model->FoundState->Symbol];
      Model->Coder.SubRange.LowCount=HiCnt;
      Model->CharMask[p->Symbol]=Model->EscCount;
      i=(Model->NumMasked=NumStats)-1;
      Model->FoundState=NULL;
      do 
      { 
        Model->CharMask[(--p)->Symbol]=Model->EscCount; 
      } while ( --i );
      Model->Coder.SubRange.HighCount=Model->Coder.SubRange.scale;
      return(true);
    }
  Model->Coder.SubRange.LowCount=(Model->Coder.SubRange.HighCount=HiCnt)-p->Freq;
  update1(Model,p);
  return(true);
}


inline void RARPPM_CONTEXT::update2(ModelPPM *Model,RARPPM_STATE* p)
{
  (Model->FoundState=p)->Freq += 4;              
  U.SummFreq += 4;
  if (p->Freq > MAX_FREQ)                 
    rescale(Model);
  Model->EscCount++;
  Model->RunLength=Model->InitRL;
}


inline RARPPM_SEE2_CONTEXT* RARPPM_CONTEXT::makeEscFreq2(ModelPPM *Model,int Diff)
{
  RARPPM_SEE2_CONTEXT* psee2c;
  if (NumStats != 256) 
  {
    psee2c=Model->SEE2Cont[Model->NS2Indx[Diff-1]]+
           (Diff < Suffix->NumStats-NumStats)+
           2*(U.SummFreq < 11*NumStats)+4*(Model->NumMasked > Diff)+
           Model->HiBitsFlag;
    Model->Coder.SubRange.scale=psee2c->getMean();
  }
  else 
  {
    psee2c=&Model->DummySEE2Cont;
    Model->Coder.SubRange.scale=1;
  }
  return psee2c;
}




inline bool RARPPM_CONTEXT::decodeSymbol2(ModelPPM *Model)
{
  int count, HiCnt, i=NumStats-Model->NumMasked;
  RARPPM_SEE2_CONTEXT* psee2c=makeEscFreq2(Model,i);
  RARPPM_STATE* ps[256], ** pps=ps, * p=U.Stats-1;
  HiCnt=0;
  do 
  {
    do 
    { 
      p++; 
    } while (Model->CharMask[p->Symbol] == Model->EscCount);
    HiCnt += p->Freq;

    // We do not reuse PPMd coder in unstable state, so we do not really need
    // this check and added it for extra safety. See CVE-2017-17969 for details.
    if (pps>=ps+ASIZE(ps))
      return false;

    *pps++ = p;
  } while ( --i );
  Model->Coder.SubRange.scale += HiCnt;
  count=Model->Coder.GetCurrentCount();
  if (count>=(int)Model->Coder.SubRange.scale)
    return(false);
  p=*(pps=ps);
  if (count < HiCnt) 
  {
    HiCnt=0;
    while ((HiCnt += p->Freq) <= count) 
    {
      pps++;
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      p=*pps;
    }
    Model->Coder.SubRange.LowCount = (Model->Coder.SubRange.HighCount=HiCnt)-p->Freq;
    psee2c->update();
    update2(Model,p);
  }
  else
  {
    Model->Coder.SubRange.LowCount=HiCnt;
    Model->Coder.SubRange.HighCount=Model->Coder.SubRange.scale;
    i=NumStats-Model->NumMasked;
    pps--;
    do 
    { 
      pps++;
      if (pps>=ps+ASIZE(ps)) // Extra safety check.
        return false;
      Model->CharMask[(*pps)->Symbol]=Model->EscCount; 
    } while ( --i );
    psee2c->Summ += Model->Coder.SubRange.scale;
    Model->NumMasked = NumStats;
  }
  return true;
}


inline void ModelPPM::ClearMask()
{
  EscCount=1;                             
  memset(CharMask,0,sizeof(CharMask));
}




// reset PPM variables after data error allowing safe resuming
// of further data processing
void ModelPPM::CleanUp()
{
  SubAlloc.StopSubAllocator();
  SubAlloc.StartSubAllocator(1);
  StartModelRare(2);
}


bool ModelPPM::DecodeInit(Unpack *UnpackRead,int &EscChar,byte *hcppm)
{
  int MaxOrder=UnpackRead->GetChar();
  bool Reset=(MaxOrder & 0x20)!=0;

  int MaxMB;
  if (Reset)
  {
    MaxMB=UnpackRead->GetChar();
    if (MaxMB>128) return(false);
  }
  else
    if (SubAlloc.GetAllocatedMemory()==0)
      return(false);
  if (MaxOrder & 0x40)
    EscChar=UnpackRead->GetChar();
  Coder.InitDecoder(UnpackRead);
  if (Reset)
  {
    MaxOrder=(MaxOrder & 0x1f)+1;
    if (MaxOrder>16)
      MaxOrder=16+(MaxOrder-16)*3;
    if (MaxOrder==1)
    {
      SubAlloc.StopSubAllocator();
      return(false);
    }
    SubAlloc.SetHeapStartFixed(hcppm);
    SubAlloc.StartSubAllocator(MaxMB+1);
    StartModelRare(MaxOrder);
  }
  return(MinContext!=NULL);
}


int ModelPPM::DecodeChar()
{
  if ((byte*)MinContext <= SubAlloc.pText || (byte*)MinContext>SubAlloc.HeapEnd)
    return(-1);
  if (MinContext->NumStats != 1)      
  {
    if ((byte*)MinContext->U.Stats <= SubAlloc.pText || (byte*)MinContext->U.Stats>SubAlloc.HeapEnd)
      return(-1);
    if (!MinContext->decodeSymbol1(this))
      return(-1);
  }
  else                                
    MinContext->decodeBinSymbol(this);
  Coder.Decode();
  while ( !FoundState ) 
  {
    ARI_DEC_NORMALIZE(Coder.code,Coder.low,Coder.range,Coder.UnpackRead);
    do
    {
      OrderFall++;                
      MinContext=MinContext->Suffix;
      if ((byte*)MinContext <= SubAlloc.pText || (byte*)MinContext>SubAlloc.HeapEnd)
        return(-1);
    } while (MinContext->NumStats == NumMasked);
    if (!MinContext->decodeSymbol2(this))
      return(-1);
    Coder.Decode();
  }
  int Symbol=FoundState->Symbol;
  if (!OrderFall && (byte*) FoundState->Successor > SubAlloc.pText)
    MinContext=MaxContext=FoundState->Successor;
  else
  {
    UpdateModel();
    if (EscCount == 0)
      ClearMask();
  }
  ARI_DEC_NORMALIZE(Coder.code,Coder.low,Coder.range,Coder.UnpackRead);
  return(Symbol);
}



inline unsigned int RangeCoder::GetChar()
{
  return(UnpackRead->GetChar());
}


void RangeCoder::InitDecoder(Unpack *UnpackRead)
{
  RangeCoder::UnpackRead=UnpackRead;

  low=code=0;
  range=uint(-1);
  for (int i=0;i < 4;i++)
    code=(code << 8) | GetChar();
}


// (int) cast before "low" added only to suppress compiler warnings.
#define ARI_DEC_NORMALIZE(code,low,range,read)                           \
{                                                                        \
  while ((low^(low+range))<TOP || range<BOT && ((range=-(int)low&(BOT-1)),1)) \
  {                                                                      \
    code=(code << 8) | read->GetChar();                                  \
    range <<= 8;                                                         \
    low <<= 8;                                                           \
  }                                                                      \
}


inline int RangeCoder::GetCurrentCount() 
{
  return (code-low)/(range /= SubRange.scale);
}


inline uint RangeCoder::GetCurrentShiftCount(uint SHIFT) 
{
  return (code-low)/(range >>= SHIFT);
}


inline void RangeCoder::Decode()
{
  low += range*SubRange.LowCount;
  range *= SubRange.HighCount-SubRange.LowCount;
}

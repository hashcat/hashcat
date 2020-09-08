/****************************************************************************
 *  Contents: 'Carryless rangecoder' by Dmitry Subbotin                     *
 ****************************************************************************/


class RangeCoder
{
  public:
    void InitDecoder(Unpack *UnpackRead);
    inline int GetCurrentCount();
    inline uint GetCurrentShiftCount(uint SHIFT);
    inline void Decode();
    inline void PutChar(unsigned int c);
    inline unsigned int GetChar();

    uint low, code, range;
    struct SUBRANGE 
    {
      uint LowCount, HighCount, scale;
    } SubRange;

    Unpack *UnpackRead;
};

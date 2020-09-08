#ifndef _RAR_VM_
#define _RAR_VM_

#define VM_MEMSIZE                  0x40000
#define VM_MEMMASK           (VM_MEMSIZE-1)

enum VM_StandardFilters {
  VMSF_NONE, VMSF_E8, VMSF_E8E9, VMSF_ITANIUM, VMSF_RGB, VMSF_AUDIO, 
  VMSF_DELTA
};

struct VM_PreparedProgram
{
  VM_PreparedProgram() 
  {
    FilteredDataSize=0;
    Type=VMSF_NONE;
  }
  VM_StandardFilters Type;
  uint InitR[7];
  byte *FilteredData;
  uint FilteredDataSize;
};

class RarVM
{
  private:
    bool ExecuteStandardFilter(VM_StandardFilters FilterType);
    uint FilterItanium_GetBits(byte *Data,uint BitPos,uint BitCount);
    void FilterItanium_SetBits(byte *Data,uint BitField,uint BitPos,uint BitCount);

    byte *Mem;
    uint R[8];
  public:
    RarVM();
    ~RarVM();
    void Init();
    void Prepare(byte *Code,uint CodeSize,VM_PreparedProgram *Prg);
    void Execute(VM_PreparedProgram *Prg);
    void SetMemory(size_t Pos,byte *Data,size_t DataSize);
    static uint ReadData(BitInput &Inp);
};

#endif

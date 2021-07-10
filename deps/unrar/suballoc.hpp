/****************************************************************************
 *  This file is part of PPMd project                                       *
 *  Written and distributed to public domain by Dmitry Shkarin 1997,        *
 *  1999-2000                                                               *
 *  Contents: interface to memory allocation routines                       *
 ****************************************************************************/
#if !defined(_SUBALLOC_H_)
#define _SUBALLOC_H_

#if defined(__GNUC__) && defined(ALLOW_MISALIGNED)
#define RARPPM_PACK_ATTR __attribute__ ((packed))
#else
#define RARPPM_PACK_ATTR
#endif /* defined(__GNUC__) */

#ifdef ALLOW_MISALIGNED
#pragma pack(1)
#endif

struct RARPPM_MEM_BLK 
{
  ushort Stamp, NU;
  RARPPM_MEM_BLK* next, * prev;
  void insertAt(RARPPM_MEM_BLK* p) 
  {
    next=(prev=p)->next;
    p->next=next->prev=this;
  }
  void remove() 
  {
    prev->next=next;
    next->prev=prev;
  }
} RARPPM_PACK_ATTR;

#ifdef ALLOW_MISALIGNED
#ifdef _AIX
#pragma pack(pop)
#else
#pragma pack()
#endif
#endif


class SubAllocator
{
  private:
    static const int N1=4, N2=4, N3=4, N4=(128+3-1*N1-2*N2-3*N3)/4;
    static const int N_INDEXES=N1+N2+N3+N4;

    struct RAR_NODE
    {
      RAR_NODE* next;
    };

    inline void InsertNode(void* p,int indx);
    inline void* RemoveNode(int indx);
    inline uint U2B(int NU);
    inline void SplitBlock(void* pv,int OldIndx,int NewIndx);
    inline void GlueFreeBlocks();
    void* AllocUnitsRare(int indx);
    inline RARPPM_MEM_BLK* MBPtr(RARPPM_MEM_BLK *BasePtr,int Items);

    long SubAllocatorSize;
    byte Indx2Units[N_INDEXES], Units2Indx[128], GlueCount;
    byte *HeapStart,*LoUnit, *HiUnit;
    struct RAR_NODE FreeList[N_INDEXES];
  public:
    SubAllocator();
    ~SubAllocator() {StopSubAllocator();}
    void Clean();
    bool StartSubAllocator(int SASize);
    void StopSubAllocator();
    void  InitSubAllocator();
    inline void* AllocContext();
    inline void* AllocUnits(int NU);
    inline void* ExpandUnits(void* ptr,int OldNU);
    inline void* ShrinkUnits(void* ptr,int OldNU,int NewNU);
    inline void  FreeUnits(void* ptr,int OldNU);
    long GetAllocatedMemory() {return(SubAllocatorSize);}

    byte *pText, *UnitsStart,*HeapEnd,*FakeUnitsStart;

    byte *HeapStartFixed;
    void SetHeapStartFixed(byte *p) {HeapStartFixed=p;}
};


#endif /* !defined(_SUBALLOC_H_) */

/****************************************************************************
 *  This file is part of PPMd project                                       *
 *  Written and distributed to public domain by Dmitry Shkarin 1997,        *
 *  1999-2000                                                               *
 *  Contents: memory allocation routines                                    *
 ****************************************************************************/

static const uint UNIT_SIZE=Max(sizeof(RARPPM_CONTEXT),sizeof(RARPPM_MEM_BLK));
static const uint FIXED_UNIT_SIZE=12;

SubAllocator::SubAllocator()
{
  Clean();
}


void SubAllocator::Clean()
{
  SubAllocatorSize=0;
}


inline void SubAllocator::InsertNode(void* p,int indx) 
{
  ((RAR_NODE*) p)->next=FreeList[indx].next;
  FreeList[indx].next=(RAR_NODE*) p;
}


inline void* SubAllocator::RemoveNode(int indx) 
{
  RAR_NODE* RetVal=FreeList[indx].next;
  FreeList[indx].next=RetVal->next;
  return RetVal;
}


inline uint SubAllocator::U2B(int NU) 
{ 
  // We calculate the size of units in bytes based on real UNIT_SIZE.
  // In original implementation it was 8*NU+4*NU.
  return UNIT_SIZE*NU;
}



// Calculate RARPPM_MEM_BLK+Items address. Real RARPPM_MEM_BLK size must be
// equal to UNIT_SIZE, so we cannot just add Items to RARPPM_MEM_BLK address.
inline RARPPM_MEM_BLK* SubAllocator::MBPtr(RARPPM_MEM_BLK *BasePtr,int Items)
{
  return((RARPPM_MEM_BLK*)( ((byte *)(BasePtr))+U2B(Items) ));
}


inline void SubAllocator::SplitBlock(void* pv,int OldIndx,int NewIndx)
{
  int i, UDiff=Indx2Units[OldIndx]-Indx2Units[NewIndx];
  byte* p=((byte*) pv)+U2B(Indx2Units[NewIndx]);
  if (Indx2Units[i=Units2Indx[UDiff-1]] != UDiff) 
  {
    InsertNode(p,--i);
    p += U2B(i=Indx2Units[i]);
    UDiff -= i;
  }
  InsertNode(p,Units2Indx[UDiff-1]);
}


void SubAllocator::StopSubAllocator()
{
  if ( SubAllocatorSize ) 
  {
    SubAllocatorSize=0;
    //free(HeapStart);
  }
}


bool SubAllocator::StartSubAllocator(int SASize)
{
  uint t=SASize << 20;
  if (SubAllocatorSize == t)
    return true;
  StopSubAllocator();

  // Original algorithm expects FIXED_UNIT_SIZE, but actual structure size
  // can be larger. So let's recalculate the allocated size and add two more
  // units: one as reserve for HeapEnd overflow checks and another
  // to provide the space to correctly align UnitsStart.
  uint AllocSize=t/FIXED_UNIT_SIZE*UNIT_SIZE+2*UNIT_SIZE;
  //if ((HeapStart=(byte *)malloc(AllocSize)) == NULL)
  if ((HeapStart=(byte *)HeapStartFixed) == NULL)
  {
    ErrHandler.MemoryError();
    return false;
  }

  // HeapEnd did not present in original algorithm. We added it to control
  // invalid memory access attempts when processing corrupt archived data.
  HeapEnd=HeapStart+AllocSize-UNIT_SIZE;

  SubAllocatorSize=t;
  return true;
}


void SubAllocator::InitSubAllocator()
{
  int i, k;
  memset(FreeList,0,sizeof(FreeList));
  pText=HeapStart;

  // Original algorithm operates with 12 byte FIXED_UNIT_SIZE, but actual
  // size of RARPPM_MEM_BLK and RARPPM_CONTEXT structures can exceed this value
  // because of alignment and larger pointer fields size.
  // So we define UNIT_SIZE for this larger size and adjust memory
  // pointers accordingly.

  // Size2 is (HiUnit-LoUnit) memory area size to allocate as originally
  // supposed by compression algorithm. It is 7/8 of total allocated size.
  uint Size2=FIXED_UNIT_SIZE*(SubAllocatorSize/8/FIXED_UNIT_SIZE*7);

  // RealSize2 is the real adjusted size of (HiUnit-LoUnit) memory taking
  // into account that our UNIT_SIZE can be larger than FIXED_UNIT_SIZE.
  uint RealSize2=Size2/FIXED_UNIT_SIZE*UNIT_SIZE;

  // Size1 is the size of memory area from HeapStart to FakeUnitsStart
  // as originally supposed by compression algorithm. This area can contain
  // different data types, both single symbols and structures.
  uint Size1=SubAllocatorSize-Size2;

  // Real size of this area. We correct it according to UNIT_SIZE vs
  // FIXED_UNIT_SIZE difference. Also we add one more UNIT_SIZE
  // to compensate a possible reminder from Size1/FIXED_UNIT_SIZE,
  // which would be lost otherwise. We add UNIT_SIZE instead of 
  // this Size1%FIXED_UNIT_SIZE reminder, because it allows to align
  // UnitsStart easily and adding more than reminder is ok for algorithm.
  uint RealSize1=Size1/FIXED_UNIT_SIZE*UNIT_SIZE+UNIT_SIZE;

  // RealSize1 must be divided by UNIT_SIZE without a reminder, so UnitsStart
  // is aligned to UNIT_SIZE. It is important for those architectures,
  // where a proper memory alignment is mandatory. Since we produce RealSize1
  // multiplying by UNIT_SIZE, this condition is always true. So LoUnit,
  // UnitsStart, HeapStart are properly aligned,
  LoUnit=UnitsStart=HeapStart+RealSize1;

  // When we reach FakeUnitsStart, we restart the model. It is where
  // the original algorithm expected to see UnitsStart. Real UnitsStart
  // can have a larger value.
  FakeUnitsStart=HeapStart+Size1;

  HiUnit=LoUnit+RealSize2;
  for (i=0,k=1;i < N1     ;i++,k += 1)
    Indx2Units[i]=k;
  for (k++;i < N1+N2      ;i++,k += 2)
    Indx2Units[i]=k;
  for (k++;i < N1+N2+N3   ;i++,k += 3)
    Indx2Units[i]=k;
  for (k++;i < N1+N2+N3+N4;i++,k += 4)
    Indx2Units[i]=k;
  for (GlueCount=k=i=0;k < 128;k++)
  {
    i += (Indx2Units[i] < k+1);
    Units2Indx[k]=i;
  }
}


inline void SubAllocator::GlueFreeBlocks()
{
  RARPPM_MEM_BLK s0, * p, * p1;
  int i, k, sz;
  if (LoUnit != HiUnit)
    *LoUnit=0;
  for (i=0, s0.next=s0.prev=&s0;i < N_INDEXES;i++)
    while ( FreeList[i].next )
    {
      p=(RARPPM_MEM_BLK*)RemoveNode(i);
      p->insertAt(&s0);
      p->Stamp=0xFFFF;
      p->NU=Indx2Units[i];
    }
  for (p=s0.next;p != &s0;p=p->next)
    while ((p1=MBPtr(p,p->NU))->Stamp == 0xFFFF && int(p->NU)+p1->NU < 0x10000)
    {
      p1->remove();
      p->NU += p1->NU;
    }
  while ((p=s0.next) != &s0)
  {
    for (p->remove(), sz=p->NU;sz > 128;sz -= 128, p=MBPtr(p,128))
      InsertNode(p,N_INDEXES-1);
    if (Indx2Units[i=Units2Indx[sz-1]] != sz)
    {
      k=sz-Indx2Units[--i];
      InsertNode(MBPtr(p,sz-k),k-1);
    }
    InsertNode(p,i);
  }
}

void* SubAllocator::AllocUnitsRare(int indx)
{
  if ( !GlueCount )
  {
    GlueCount = 255;
    GlueFreeBlocks();
    if ( FreeList[indx].next )
      return RemoveNode(indx);
  }
  int i=indx;
  do
  {
    if (++i == N_INDEXES)
    {
      GlueCount--;
      i=U2B(Indx2Units[indx]);
      int j=FIXED_UNIT_SIZE*Indx2Units[indx];
      if (FakeUnitsStart - pText > j)
      {
        FakeUnitsStart -= j;
        UnitsStart -= i;
        return UnitsStart;
      }
      return NULL;
    }
  } while ( !FreeList[i].next );
  void* RetVal=RemoveNode(i);
  SplitBlock(RetVal,i,indx);
  return RetVal;
}


inline void* SubAllocator::AllocUnits(int NU)
{
  int indx=Units2Indx[NU-1];
  if ( FreeList[indx].next )
    return RemoveNode(indx);
  void* RetVal=LoUnit;
  LoUnit += U2B(Indx2Units[indx]);
  if (LoUnit <= HiUnit)
    return RetVal;
  LoUnit -= U2B(Indx2Units[indx]);
  return AllocUnitsRare(indx);
}


void* SubAllocator::AllocContext()
{
  if (HiUnit != LoUnit)
    return (HiUnit -= UNIT_SIZE);
  if ( FreeList->next )
    return RemoveNode(0);
  return AllocUnitsRare(0);
}


void* SubAllocator::ExpandUnits(void* OldPtr,int OldNU)
{
  int i0=Units2Indx[OldNU-1], i1=Units2Indx[OldNU-1+1];
  if (i0 == i1)
    return OldPtr;
  void* ptr=AllocUnits(OldNU+1);
  if ( ptr ) 
  {
    memcpy(ptr,OldPtr,U2B(OldNU));
    InsertNode(OldPtr,i0);
  }
  return ptr;
}


void* SubAllocator::ShrinkUnits(void* OldPtr,int OldNU,int NewNU)
{
  int i0=Units2Indx[OldNU-1], i1=Units2Indx[NewNU-1];
  if (i0 == i1)
    return OldPtr;
  if ( FreeList[i1].next )
  {
    void* ptr=RemoveNode(i1);
    memcpy(ptr,OldPtr,U2B(NewNU));
    InsertNode(OldPtr,i0);
    return ptr;
  } 
  else 
  {
    SplitBlock(OldPtr,i0,i1);
    return OldPtr;
  }
}


void SubAllocator::FreeUnits(void* ptr,int OldNU)
{
  InsertNode(ptr,Units2Indx[OldNU-1]);
}

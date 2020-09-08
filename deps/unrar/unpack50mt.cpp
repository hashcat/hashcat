#define UNP_READ_SIZE_MT        0x400000
#define UNP_BLOCKS_PER_THREAD          2


struct UnpackThreadDataList
{
  UnpackThreadData *D;
  uint BlockCount;
};


THREAD_PROC(UnpackDecodeThread)
{
  UnpackThreadDataList *DL=(UnpackThreadDataList *)Data;
  for (uint I=0;I<DL->BlockCount;I++)
    DL->D->UnpackPtr->UnpackDecode(DL->D[I]);
}


void Unpack::InitMT()
{
  if (ReadBufMT==NULL)
  {
    // Even getbits32 can read up to 3 additional bytes after current
    // and our block header and table reading code can look much further.
    // Let's allocate the additional space here, so we do not need to check
    // bounds for every bit field access.
    const size_t Overflow=1024;

    ReadBufMT=new byte[UNP_READ_SIZE_MT+Overflow];
    memset(ReadBufMT,0,UNP_READ_SIZE_MT+Overflow);
  }
  if (UnpThreadData==NULL)
  {
    uint MaxItems=MaxUserThreads*UNP_BLOCKS_PER_THREAD;
    UnpThreadData=new UnpackThreadData[MaxItems];
    memset(UnpThreadData,0,sizeof(UnpackThreadData)*MaxItems);

    for (uint I=0;I<MaxItems;I++)
    {
      UnpackThreadData *CurData=UnpThreadData+I;
      if (CurData->Decoded==NULL)
      {
        // Typical number of items in RAR blocks does not exceed 0x4000.
        CurData->DecodedAllocated=0x4100;
        // It will be freed in the object destructor, not in this file.
        CurData->Decoded=(UnpackDecodedItem *)malloc(CurData->DecodedAllocated*sizeof(UnpackDecodedItem));
        if (CurData->Decoded==NULL)
          ErrHandler.MemoryError();
      }
    }
  }
}


void Unpack::Unpack5MT(bool Solid)
{
  InitMT();
  UnpInitData(Solid);

  for (uint I=0;I<MaxUserThreads*UNP_BLOCKS_PER_THREAD;I++)
  {
    UnpackThreadData *CurData=UnpThreadData+I;
    CurData->LargeBlock=false;
    CurData->Incomplete=false;
  }

  UnpThreadData[0].BlockHeader=BlockHeader;
  UnpThreadData[0].BlockTables=BlockTables;
  uint LastBlockNum=0;

  int DataSize=0;
  int BlockStart=0;


  // 'true' if we found a block too large for multithreaded extraction,
  // so we switched to single threaded mode until the end of file.
  // Large blocks could cause too high memory use in multithreaded mode.
  bool LargeBlock=false;

  bool Done=false;
  while (!Done)
  {
    // Data amount, which is guaranteed to fit block header and tables,
    // so we can safely read them without additional checks.
    const int TooSmallToProcess=1024;

    int ReadSize=UnpIO->UnpRead(ReadBufMT+DataSize,(UNP_READ_SIZE_MT-DataSize)&~0xf);
    if (ReadSize<0)
      break;
    DataSize+=ReadSize;
    if (DataSize==0)
      break;

    // First read chunk can be small if we are near the end of volume
    // and we want it to fit block header and tables.
    if (ReadSize>0 && DataSize<TooSmallToProcess)
      continue;

    while (BlockStart<DataSize && !Done)
    {
      uint BlockNumber=0,BlockNumberMT=0;
      while (BlockNumber<MaxUserThreads*UNP_BLOCKS_PER_THREAD)
      {
        UnpackThreadData *CurData=UnpThreadData+BlockNumber;
        LastBlockNum=BlockNumber;
        CurData->UnpackPtr=this;

        // 'Incomplete' thread is present. This is a thread processing block
        // in the end of buffer, split between two read operations.
        if (CurData->Incomplete)
          CurData->DataSize=DataSize;
        else
        {
          CurData->Inp.SetExternalBuffer(ReadBufMT+BlockStart);
          CurData->Inp.InitBitInput();
          CurData->DataSize=DataSize-BlockStart;
          if (CurData->DataSize==0)
            break;
          CurData->DamagedData=false;
          CurData->HeaderRead=false;
          CurData->TableRead=false;
        }

        // We should not use 'last block in file' block flag here unless
        // we'll check the block size, because even if block is last in file,
        // it can exceed the current buffer and require more reading.
        CurData->NoDataLeft=(ReadSize==0);

        CurData->Incomplete=false;
        CurData->ThreadNumber=BlockNumber;

        if (!CurData->HeaderRead)
        {
          CurData->HeaderRead=true;
          if (!ReadBlockHeader(CurData->Inp,CurData->BlockHeader) ||
              !CurData->BlockHeader.TablePresent && !TablesRead5)
          {
            Done=true;
            break;
          }
          TablesRead5=true;
        }

        // To prevent too high memory use we switch to single threaded mode
        // if block exceeds this size. Typically RAR blocks do not exceed
        // 64 KB, so this protection should not affect most of valid archives.
        const int LargeBlockSize=0x20000;
        if (LargeBlock || CurData->BlockHeader.BlockSize>LargeBlockSize)
          LargeBlock=CurData->LargeBlock=true;
        else
          BlockNumberMT++; // Number of normal blocks processed in MT mode.

        BlockStart+=CurData->BlockHeader.HeaderSize+CurData->BlockHeader.BlockSize;

        BlockNumber++;

        int DataLeft=DataSize-BlockStart;
        if (DataLeft>=0 && CurData->BlockHeader.LastBlockInFile)
          break;

        // For second and following threads we move smaller blocks to buffer
        // start to ensure that we have enough data to fit block header
        // and tables.
        if (DataLeft<TooSmallToProcess)
          break;
      }

//#undef USE_THREADS
      UnpackThreadDataList UTDArray[MaxPoolThreads];
      uint UTDArrayPos=0;

      uint MaxBlockPerThread=BlockNumberMT/MaxUserThreads;
      if (BlockNumberMT%MaxUserThreads!=0)
        MaxBlockPerThread++;

      // Decode all normal blocks until the first 'large' if any.
      for (uint CurBlock=0;CurBlock<BlockNumberMT;CurBlock+=MaxBlockPerThread)
      {
        UnpackThreadDataList *UTD=UTDArray+UTDArrayPos++;
        UTD->D=UnpThreadData+CurBlock;
        UTD->BlockCount=Min(MaxBlockPerThread,BlockNumberMT-CurBlock);

#ifdef USE_THREADS
        if (BlockNumber==1)
          UnpackDecode(*UTD->D);
        else
          UnpThreadPool->AddTask(UnpackDecodeThread,(void*)UTD);
#else
        for (uint I=0;I<UTD->BlockCount;I++)
          UnpackDecode(UTD->D[I]);
#endif
      }

      if (BlockNumber==0)
        break;

#ifdef USE_THREADS
      UnpThreadPool->WaitDone();
#endif

      bool IncompleteThread=false;

      for (uint Block=0;Block<BlockNumber;Block++)
      {
        UnpackThreadData *CurData=UnpThreadData+Block;
        if (!CurData->LargeBlock && !ProcessDecoded(*CurData) ||
            CurData->LargeBlock && !UnpackLargeBlock(*CurData) ||
            CurData->DamagedData)
        {
          Done=true;
          break;
        }
        if (CurData->Incomplete)
        {
          int BufPos=int(CurData->Inp.InBuf+CurData->Inp.InAddr-ReadBufMT);
          if (DataSize<=BufPos) // Thread exceeded input buffer boundary.
          {
            Done=true;
            break;
          }
          IncompleteThread=true;
          memmove(ReadBufMT,ReadBufMT+BufPos,DataSize-BufPos);
          CurData->BlockHeader.BlockSize-=CurData->Inp.InAddr-CurData->BlockHeader.BlockStart;
          CurData->BlockHeader.HeaderSize=0;
          CurData->BlockHeader.BlockStart=0;
          CurData->Inp.InBuf=ReadBufMT;
          CurData->Inp.InAddr=0;

          if (Block!=0)
          {
            // Move the incomplete thread entry to the first position,
            // so we'll start processing from it. Preserve the original
            // buffer for decoded data.
            UnpackDecodedItem *Decoded=UnpThreadData[0].Decoded;
            uint DecodedAllocated=UnpThreadData[0].DecodedAllocated;
            UnpThreadData[0]=*CurData;
            UnpThreadData[0].Decoded=Decoded;
            UnpThreadData[0].DecodedAllocated=DecodedAllocated;
            CurData->Incomplete=false;
          }

          BlockStart=0;
          DataSize-=BufPos;
          break;
        }
        else
          if (CurData->BlockHeader.LastBlockInFile)
          {
            Done=true;
            break;
          }
      }

      if (IncompleteThread || Done)
        break; // Current buffer is done, read more data or quit.
      else
      {
        int DataLeft=DataSize-BlockStart;
        if (DataLeft<TooSmallToProcess)
        {
          if (DataLeft<0) // Invalid data, must not happen in valid archive.
          {
            Done=true;
            break;
          }

          // If we do not have incomplete thread and have some data
          // in the end of buffer, too small for single thread,
          // let's move it to beginning of next buffer.
          if (DataLeft>0)
            memmove(ReadBufMT,ReadBufMT+BlockStart,DataLeft);
          DataSize=DataLeft;
          BlockStart=0;
          break; // Current buffer is done, try to read more data.
        }
      }
    }
  }
  UnpPtr&=MaxWinMask; // ProcessDecoded and maybe others can leave UnpPtr > MaxWinMask here.
  UnpWriteBuf();

  BlockHeader=UnpThreadData[LastBlockNum].BlockHeader;
  BlockTables=UnpThreadData[LastBlockNum].BlockTables;
}


// Decode Huffman block and save decoded data to memory.
void Unpack::UnpackDecode(UnpackThreadData &D)
{
  if (!D.TableRead)
  {
    D.TableRead=true;
    if (!ReadTables(D.Inp,D.BlockHeader,D.BlockTables))
    {
      D.DamagedData=true;
      return;
    }
  }

  if (D.Inp.InAddr>D.BlockHeader.HeaderSize+D.BlockHeader.BlockSize)
  {
    D.DamagedData=true;
    return;
  }

  D.DecodedSize=0;
  int BlockBorder=D.BlockHeader.BlockStart+D.BlockHeader.BlockSize-1;

  // Reserve enough space even for filter entry.
  int DataBorder=D.DataSize-16;
  int ReadBorder=Min(BlockBorder,DataBorder);

  while (true)
  {
    if (D.Inp.InAddr>=ReadBorder)
    {
      if (D.Inp.InAddr>BlockBorder || D.Inp.InAddr==BlockBorder && 
          D.Inp.InBit>=D.BlockHeader.BlockBitSize)
        break;

      // If we do not have any more data in file to read, we must process
      // what we have until last byte. Otherwise we can return and append
      // more data to unprocessed few bytes.
      if ((D.Inp.InAddr>=DataBorder) && !D.NoDataLeft || D.Inp.InAddr>=D.DataSize)
      {
        D.Incomplete=true;
        break;
      }
    }
    if (D.DecodedSize>D.DecodedAllocated-8) // Filter can use several slots.
    {
      D.DecodedAllocated=D.DecodedAllocated*2;
      void *Decoded=realloc(D.Decoded,D.DecodedAllocated*sizeof(UnpackDecodedItem));
      if (Decoded==NULL)
        ErrHandler.MemoryError(); // D.Decoded will be freed in the destructor.
      D.Decoded=(UnpackDecodedItem *)Decoded;
    }

    UnpackDecodedItem *CurItem=D.Decoded+D.DecodedSize++;

    uint MainSlot=DecodeNumber(D.Inp,&D.BlockTables.LD);
    if (MainSlot<256)
    {
      if (D.DecodedSize>1)
      {
        UnpackDecodedItem *PrevItem=CurItem-1;
        if (PrevItem->Type==UNPDT_LITERAL && PrevItem->Length<3)
        {
          PrevItem->Length++;
          PrevItem->Literal[PrevItem->Length]=(byte)MainSlot;
          D.DecodedSize--;
          continue;
        }
      }
      CurItem->Type=UNPDT_LITERAL;
      CurItem->Literal[0]=(byte)MainSlot;
      CurItem->Length=0;
      continue;
    }
    if (MainSlot>=262)
    {
      uint Length=SlotToLength(D.Inp,MainSlot-262);

      uint DBits,Distance=1,DistSlot=DecodeNumber(D.Inp,&D.BlockTables.DD);
      if (DistSlot<4)
      {
        DBits=0;
        Distance+=DistSlot;
      }
      else
      {
        DBits=DistSlot/2 - 1;
        Distance+=(2 | (DistSlot & 1)) << DBits;
      }

      if (DBits>0)
      {
        if (DBits>=4)
        {
          if (DBits>4)
          {
            Distance+=((D.Inp.getbits32()>>(36-DBits))<<4);
            D.Inp.addbits(DBits-4);
          }
          uint LowDist=DecodeNumber(D.Inp,&D.BlockTables.LDD);
          Distance+=LowDist;
        }
        else
        {
          Distance+=D.Inp.getbits32()>>(32-DBits);
          D.Inp.addbits(DBits);
        }
      }

      if (Distance>0x100)
      {
        Length++;
        if (Distance>0x2000)
        {
          Length++;
          if (Distance>0x40000)
            Length++;
        }
      }

      CurItem->Type=UNPDT_MATCH;
      CurItem->Length=(ushort)Length;
      CurItem->Distance=Distance;
      continue;
    }
    if (MainSlot==256)
    {
      UnpackFilter Filter;
      ReadFilter(D.Inp,Filter);

      CurItem->Type=UNPDT_FILTER;
      CurItem->Length=Filter.Type;
      CurItem->Distance=Filter.BlockStart;

      CurItem=D.Decoded+D.DecodedSize++;

      CurItem->Type=UNPDT_FILTER;
      CurItem->Length=Filter.Channels;
      CurItem->Distance=Filter.BlockLength;

      continue;
    }
    if (MainSlot==257)
    {
      CurItem->Type=UNPDT_FULLREP;
      continue;
    }
    if (MainSlot<262)
    {
      CurItem->Type=UNPDT_REP;
      CurItem->Distance=MainSlot-258;
      uint LengthSlot=DecodeNumber(D.Inp,&D.BlockTables.RD);
      uint Length=SlotToLength(D.Inp,LengthSlot);
      CurItem->Length=(ushort)Length;
      continue;
    }
  }
}


// Process decoded Huffman block data.
bool Unpack::ProcessDecoded(UnpackThreadData &D)
{
  UnpackDecodedItem *Item=D.Decoded,*Border=D.Decoded+D.DecodedSize;
  while (Item<Border)
  {
    UnpPtr&=MaxWinMask;
    if (((WriteBorder-UnpPtr) & MaxWinMask)<MAX_INC_LZ_MATCH && WriteBorder!=UnpPtr)
    {
      UnpWriteBuf();
      if (WrittenFileSize>DestUnpSize)
        return false;
    }

    if (Item->Type==UNPDT_LITERAL)
    {
#if defined(LITTLE_ENDIAN) && defined(ALLOW_MISALIGNED)
      if (Item->Length==3 && UnpPtr<MaxWinSize-4)
      {
        *(uint32 *)(Window+UnpPtr)=*(uint32 *)Item->Literal;
        UnpPtr+=4;
      }
      else
#endif
        for (uint I=0;I<=Item->Length;I++)
          Window[UnpPtr++ & MaxWinMask]=Item->Literal[I];
    }
    else
      if (Item->Type==UNPDT_MATCH)
      {
        InsertOldDist(Item->Distance);
        LastLength=Item->Length;
        CopyString(Item->Length,Item->Distance);
      }
      else
        if (Item->Type==UNPDT_REP)
        {
          uint Distance=OldDist[Item->Distance];
          for (uint I=Item->Distance;I>0;I--)
            OldDist[I]=OldDist[I-1];
          OldDist[0]=Distance;
          LastLength=Item->Length;
          CopyString(Item->Length,Distance);
        }
        else
          if (Item->Type==UNPDT_FULLREP)
          {
            if (LastLength!=0)
              CopyString(LastLength,OldDist[0]);
          }
          else
            if (Item->Type==UNPDT_FILTER)
            {
              UnpackFilter Filter;

              Filter.Type=(byte)Item->Length;
              Filter.BlockStart=Item->Distance;

              Item++;

              Filter.Channels=(byte)Item->Length;
              Filter.BlockLength=Item->Distance;

              AddFilter(Filter);
            }
    Item++;
  }
  return true;
}


// For large blocks we decode and process in same function in single threaded
// mode, so we do not need to store intermediate data in memory.
bool Unpack::UnpackLargeBlock(UnpackThreadData &D)
{
  if (!D.TableRead)
  {
    D.TableRead=true;
    if (!ReadTables(D.Inp,D.BlockHeader,D.BlockTables))
    {
      D.DamagedData=true;
      return false;
    }
  }

  if (D.Inp.InAddr>D.BlockHeader.HeaderSize+D.BlockHeader.BlockSize)
  {
    D.DamagedData=true;
    return false;
  }

  int BlockBorder=D.BlockHeader.BlockStart+D.BlockHeader.BlockSize-1;

  // Reserve enough space even for filter entry.
  int DataBorder=D.DataSize-16;
  int ReadBorder=Min(BlockBorder,DataBorder);

  while (true)
  {
    UnpPtr&=MaxWinMask;
    if (D.Inp.InAddr>=ReadBorder)
    {
      if (D.Inp.InAddr>BlockBorder || D.Inp.InAddr==BlockBorder && 
          D.Inp.InBit>=D.BlockHeader.BlockBitSize)
        break;

      // If we do not have any more data in file to read, we must process
      // what we have until last byte. Otherwise we can return and append
      // more data to unprocessed few bytes.
      if ((D.Inp.InAddr>=DataBorder) && !D.NoDataLeft || D.Inp.InAddr>=D.DataSize)
      {
        D.Incomplete=true;
        break;
      }
    }
    if (((WriteBorder-UnpPtr) & MaxWinMask)<MAX_INC_LZ_MATCH && WriteBorder!=UnpPtr)
    {
      UnpWriteBuf();
      if (WrittenFileSize>DestUnpSize)
        return false;
    }

    uint MainSlot=DecodeNumber(D.Inp,&D.BlockTables.LD);
    if (MainSlot<256)
    {
      Window[UnpPtr++]=(byte)MainSlot;
      continue;
    }
    if (MainSlot>=262)
    {
      uint Length=SlotToLength(D.Inp,MainSlot-262);

      uint DBits,Distance=1,DistSlot=DecodeNumber(D.Inp,&D.BlockTables.DD);
      if (DistSlot<4)
      {
        DBits=0;
        Distance+=DistSlot;
      }
      else
      {
        DBits=DistSlot/2 - 1;
        Distance+=(2 | (DistSlot & 1)) << DBits;
      }

      if (DBits>0)
      {
        if (DBits>=4)
        {
          if (DBits>4)
          {
            Distance+=((D.Inp.getbits32()>>(36-DBits))<<4);
            D.Inp.addbits(DBits-4);
          }
          uint LowDist=DecodeNumber(D.Inp,&D.BlockTables.LDD);
          Distance+=LowDist;
        }
        else
        {
          Distance+=D.Inp.getbits32()>>(32-DBits);
          D.Inp.addbits(DBits);
        }
      }

      if (Distance>0x100)
      {
        Length++;
        if (Distance>0x2000)
        {
          Length++;
          if (Distance>0x40000)
            Length++;
        }
      }

      InsertOldDist(Distance);
      LastLength=Length;
      CopyString(Length,Distance);
      continue;
    }
    if (MainSlot==256)
    {
      UnpackFilter Filter;
      if (!ReadFilter(D.Inp,Filter) || !AddFilter(Filter))
        break;
      continue;
    }
    if (MainSlot==257)
    {
      if (LastLength!=0)
        CopyString(LastLength,OldDist[0]);
      continue;
    }
    if (MainSlot<262)
    {
      uint DistNum=MainSlot-258;
      uint Distance=OldDist[DistNum];
      for (uint I=DistNum;I>0;I--)
        OldDist[I]=OldDist[I-1];
      OldDist[0]=Distance;

      uint LengthSlot=DecodeNumber(D.Inp,&D.BlockTables.RD);
      uint Length=SlotToLength(D.Inp,LengthSlot);
      LastLength=Length;
      CopyString(Length,Distance);
      continue;
    }
  }
  return true;
}

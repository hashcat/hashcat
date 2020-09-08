void Unpack::Unpack5(bool Solid)
{
  FileExtracted=true;

  if (!Suspended)
  {
    UnpInitData(Solid);
    if (!UnpReadBuf())
      return;

    // Check TablesRead5 to be sure that we read tables at least once
    // regardless of current block header TablePresent flag.
    // So we can safefly use these tables below.
    if (!ReadBlockHeader(Inp,BlockHeader) ||
        !ReadTables(Inp,BlockHeader,BlockTables) || !TablesRead5)
      return;
  }

  while (true)
  {
    UnpPtr&=MaxWinMask;

    if (Inp.InAddr>=ReadBorder)
    {
      bool FileDone=false;

      // We use 'while', because for empty block containing only Huffman table,
      // we'll be on the block border once again just after reading the table.
      while (Inp.InAddr>BlockHeader.BlockStart+BlockHeader.BlockSize-1 || 
             Inp.InAddr==BlockHeader.BlockStart+BlockHeader.BlockSize-1 && 
             Inp.InBit>=BlockHeader.BlockBitSize)
      {
        if (BlockHeader.LastBlockInFile)
        {
          FileDone=true;
          break;
        }
        if (!ReadBlockHeader(Inp,BlockHeader) || !ReadTables(Inp,BlockHeader,BlockTables))
          return;
      }
      if (FileDone || !UnpReadBuf())
        break;
    }

    if (((WriteBorder-UnpPtr) & MaxWinMask)<MAX_INC_LZ_MATCH && WriteBorder!=UnpPtr)
    {
      UnpWriteBuf();
      if (WrittenFileSize>DestUnpSize)
        return;
      if (Suspended)
      {
        FileExtracted=false;
        return;
      }
    }

    uint MainSlot=DecodeNumber(Inp,&BlockTables.LD);
    if (MainSlot<256)
    {
      if (Fragmented)
        FragWindow[UnpPtr++]=(byte)MainSlot;
      else
        Window[UnpPtr++]=(byte)MainSlot;
      continue;
    }
    if (MainSlot>=262)
    {
      uint Length=SlotToLength(Inp,MainSlot-262);

      uint DBits,Distance=1,DistSlot=DecodeNumber(Inp,&BlockTables.DD);
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
            Distance+=((Inp.getbits32()>>(36-DBits))<<4);
            Inp.addbits(DBits-4);
          }
          uint LowDist=DecodeNumber(Inp,&BlockTables.LDD);
          Distance+=LowDist;
        }
        else
        {
          Distance+=Inp.getbits32()>>(32-DBits);
          Inp.addbits(DBits);
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
      if (Fragmented)
        FragWindow.CopyString(Length,Distance,UnpPtr,MaxWinMask);
      else
        CopyString(Length,Distance);
      continue;
    }
    if (MainSlot==256)
    {
      UnpackFilter Filter;
      if (!ReadFilter(Inp,Filter) || !AddFilter(Filter))
        break;
      continue;
    }
    if (MainSlot==257)
    {
      if (LastLength!=0)
        if (Fragmented)
          FragWindow.CopyString(LastLength,OldDist[0],UnpPtr,MaxWinMask);
        else
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

      uint LengthSlot=DecodeNumber(Inp,&BlockTables.RD);
      uint Length=SlotToLength(Inp,LengthSlot);
      LastLength=Length;
      if (Fragmented)
        FragWindow.CopyString(Length,Distance,UnpPtr,MaxWinMask);
      else
        CopyString(Length,Distance);
      continue;
    }
  }
  UnpWriteBuf();
}


uint Unpack::ReadFilterData(BitInput &Inp)
{
  uint ByteCount=(Inp.fgetbits()>>14)+1;
  Inp.addbits(2);

  uint Data=0;
  for (uint I=0;I<ByteCount;I++)
  {
    Data+=(Inp.fgetbits()>>8)<<(I*8);
    Inp.addbits(8);
  }
  return Data;
}


bool Unpack::ReadFilter(BitInput &Inp,UnpackFilter &Filter)
{
  if (!Inp.ExternalBuffer && Inp.InAddr>ReadTop-16)
    if (!UnpReadBuf())
      return false;

  Filter.BlockStart=ReadFilterData(Inp);
  Filter.BlockLength=ReadFilterData(Inp);
  if (Filter.BlockLength>MAX_FILTER_BLOCK_SIZE)
    Filter.BlockLength=0;

  Filter.Type=Inp.fgetbits()>>13;
  Inp.faddbits(3);

  if (Filter.Type==FILTER_DELTA)
  {
    Filter.Channels=(Inp.fgetbits()>>11)+1;
    Inp.faddbits(5);
  }

  return true;
}


bool Unpack::AddFilter(UnpackFilter &Filter)
{
  if (Filters.Size()>=MAX_UNPACK_FILTERS)
  {
    UnpWriteBuf(); // Write data, apply and flush filters.
    if (Filters.Size()>=MAX_UNPACK_FILTERS)
      InitFilters(); // Still too many filters, prevent excessive memory use.
  }

  // If distance to filter start is that large that due to circular dictionary
  // mode now it points to old not written yet data, then we set 'NextWindow'
  // flag and process this filter only after processing that older data.
  Filter.NextWindow=WrPtr!=UnpPtr && ((WrPtr-UnpPtr)&MaxWinMask)<=Filter.BlockStart;

  Filter.BlockStart=uint((Filter.BlockStart+UnpPtr)&MaxWinMask);
  Filters.Push(Filter);
  return true;
}


bool Unpack::UnpReadBuf()
{
  int DataSize=ReadTop-Inp.InAddr; // Data left to process.
  if (DataSize<0)
    return false;
  BlockHeader.BlockSize-=Inp.InAddr-BlockHeader.BlockStart;
  if (Inp.InAddr>BitInput::MAX_SIZE/2)
  {
    // If we already processed more than half of buffer, let's move
    // remaining data into beginning to free more space for new data
    // and ensure that calling function does not cross the buffer border
    // even if we did not read anything here. Also it ensures that read size
    // is not less than CRYPT_BLOCK_SIZE, so we can align it without risk
    // to make it zero.
    if (DataSize>0)
      memmove(Inp.InBuf,Inp.InBuf+Inp.InAddr,DataSize);
    Inp.InAddr=0;
    ReadTop=DataSize;
  }
  else
    DataSize=ReadTop;
  int ReadCode=0;
  if (BitInput::MAX_SIZE!=DataSize)
    ReadCode=UnpIO->UnpRead(Inp.InBuf+DataSize,BitInput::MAX_SIZE-DataSize);
  if (ReadCode>0) // Can be also -1.
    ReadTop+=ReadCode;
  ReadBorder=ReadTop-30;
  BlockHeader.BlockStart=Inp.InAddr;
  if (BlockHeader.BlockSize!=-1) // '-1' means not defined yet.
  {
    // We may need to quit from main extraction loop and read new block header
    // and trees earlier than data in input buffer ends.
    ReadBorder=Min(ReadBorder,BlockHeader.BlockStart+BlockHeader.BlockSize-1);
  }
  return ReadCode!=-1;
}


void Unpack::UnpWriteBuf()
{
  size_t WrittenBorder=WrPtr;
  size_t FullWriteSize=(UnpPtr-WrittenBorder)&MaxWinMask;
  size_t WriteSizeLeft=FullWriteSize;
  bool NotAllFiltersProcessed=false;
  for (size_t I=0;I<Filters.Size();I++)
  {
    // Here we apply filters to data which we need to write.
    // We always copy data to another memory block before processing.
    // We cannot process them just in place in Window buffer, because
    // these data can be used for future string matches, so we must
    // preserve them in original form.

    UnpackFilter *flt=&Filters[I];
    if (flt->Type==FILTER_NONE)
      continue;
    if (flt->NextWindow)
    {
      // Here we skip filters which have block start in current data range
      // due to address wrap around in circular dictionary, but actually
      // belong to next dictionary block. If such filter start position
      // is included to current write range, then we reset 'NextWindow' flag.
      // In fact we can reset it even without such check, because current
      // implementation seems to guarantee 'NextWindow' flag reset after
      // buffer writing for all existing filters. But let's keep this check
      // just in case. Compressor guarantees that distance between
      // filter block start and filter storing position cannot exceed
      // the dictionary size. So if we covered the filter block start with
      // our write here, we can safely assume that filter is applicable
      // to next block on no further wrap arounds is possible.
      if (((flt->BlockStart-WrPtr)&MaxWinMask)<=FullWriteSize)
        flt->NextWindow=false;
      continue;
    }
    uint BlockStart=flt->BlockStart;
    uint BlockLength=flt->BlockLength;
    if (((BlockStart-WrittenBorder)&MaxWinMask)<WriteSizeLeft)
    {
      if (WrittenBorder!=BlockStart)
      {
        UnpWriteArea(WrittenBorder,BlockStart);
        WrittenBorder=BlockStart;
        WriteSizeLeft=(UnpPtr-WrittenBorder)&MaxWinMask;
      }
      if (BlockLength<=WriteSizeLeft)
      {
        if (BlockLength>0) // We set it to 0 also for invalid filters.
        {
          uint BlockEnd=(BlockStart+BlockLength)&MaxWinMask;

          FilterSrcMemory.Alloc(BlockLength);
          byte *Mem=&FilterSrcMemory[0];
          if (BlockStart<BlockEnd || BlockEnd==0)
          {
            if (Fragmented)
              FragWindow.CopyData(Mem,BlockStart,BlockLength);
            else
              memcpy(Mem,Window+BlockStart,BlockLength);
          }
          else
          {
            size_t FirstPartLength=size_t(MaxWinSize-BlockStart);
            if (Fragmented)
            {
              FragWindow.CopyData(Mem,BlockStart,FirstPartLength);
              FragWindow.CopyData(Mem+FirstPartLength,0,BlockEnd);
            }
            else
            {
              memcpy(Mem,Window+BlockStart,FirstPartLength);
              memcpy(Mem+FirstPartLength,Window,BlockEnd);
            }
          }

          byte *OutMem=ApplyFilter(Mem,BlockLength,flt);

          Filters[I].Type=FILTER_NONE;

          if (OutMem!=NULL)
            UnpIO->UnpWrite(OutMem,BlockLength);

          UnpSomeRead=true;
          WrittenFileSize+=BlockLength;
          WrittenBorder=BlockEnd;
          WriteSizeLeft=(UnpPtr-WrittenBorder)&MaxWinMask;
        }
      }
      else
      {
        // Current filter intersects the window write border, so we adjust
        // the window border to process this filter next time, not now.
        WrPtr=WrittenBorder;

        // Since Filter start position can only increase, we quit processing
        // all following filters for this data block and reset 'NextWindow'
        // flag for them.
        for (size_t J=I;J<Filters.Size();J++)
        {
          UnpackFilter *flt=&Filters[J];
          if (flt->Type!=FILTER_NONE)
            flt->NextWindow=false;
        }

        // Do not write data left after current filter now.
        NotAllFiltersProcessed=true;
        break;
      }
    }
  }

  // Remove processed filters from queue.
  size_t EmptyCount=0;
  for (size_t I=0;I<Filters.Size();I++)
  {
    if (EmptyCount>0)
      Filters[I-EmptyCount]=Filters[I];
    if (Filters[I].Type==FILTER_NONE)
      EmptyCount++;
  }
  if (EmptyCount>0)
    Filters.Alloc(Filters.Size()-EmptyCount);

  if (!NotAllFiltersProcessed) // Only if all filters are processed.
  {
    // Write data left after last filter.
    UnpWriteArea(WrittenBorder,UnpPtr);
    WrPtr=UnpPtr;
  }

  // We prefer to write data in blocks not exceeding UNPACK_MAX_WRITE
  // instead of potentially huge MaxWinSize blocks. It also allows us
  // to keep the size of Filters array reasonable.
  WriteBorder=(UnpPtr+Min(MaxWinSize,UNPACK_MAX_WRITE))&MaxWinMask;

  // Choose the nearest among WriteBorder and WrPtr actual written border.
  // If border is equal to UnpPtr, it means that we have MaxWinSize data ahead.
  if (WriteBorder==UnpPtr || 
      WrPtr!=UnpPtr && ((WrPtr-UnpPtr)&MaxWinMask)<((WriteBorder-UnpPtr)&MaxWinMask))
    WriteBorder=WrPtr;
}


byte* Unpack::ApplyFilter(byte *Data,uint DataSize,UnpackFilter *Flt)
{
  byte *SrcData=Data;
  switch(Flt->Type)
  {
    case FILTER_E8:
    case FILTER_E8E9:
      {
        uint FileOffset=(uint)WrittenFileSize;

        const uint FileSize=0x1000000;
        byte CmpByte2=Flt->Type==FILTER_E8E9 ? 0xe9:0xe8;
        // DataSize is unsigned, so we use "CurPos+4" and not "DataSize-4"
        // to avoid overflow for DataSize<4.
        for (uint CurPos=0;CurPos+4<DataSize;)
        {
          byte CurByte=*(Data++);
          CurPos++;
          if (CurByte==0xe8 || CurByte==CmpByte2)
          {
            uint Offset=(CurPos+FileOffset)%FileSize;
            uint Addr=RawGet4(Data);

            // We check 0x80000000 bit instead of '< 0' comparison
            // not assuming int32 presence or uint size and endianness.
            if ((Addr & 0x80000000)!=0)              // Addr<0
            {
              if (((Addr+Offset) & 0x80000000)==0)   // Addr+Offset>=0
                RawPut4(Addr+FileSize,Data);
            }
            else
              if (((Addr-FileSize) & 0x80000000)!=0) // Addr<FileSize
                RawPut4(Addr-Offset,Data);

            Data+=4;
            CurPos+=4;
          }
        }
      }
      return SrcData;
    case FILTER_ARM:
      // 2019-11-15: we turned off ARM filter by default when compressing,
      // mostly because it is inefficient for modern 64 bit ARM binaries.
      // It was turned on by default in 5.0 - 5.80b3 , so we still need it
      // here for compatibility with some of previously created archives.
      {
        uint FileOffset=(uint)WrittenFileSize;
        // DataSize is unsigned, so we use "CurPos+3" and not "DataSize-3"
        // to avoid overflow for DataSize<3.
        for (uint CurPos=0;CurPos+3<DataSize;CurPos+=4)
        {
          byte *D=Data+CurPos;
          if (D[3]==0xeb) // BL command with '1110' (Always) condition.
          {
            uint Offset=D[0]+uint(D[1])*0x100+uint(D[2])*0x10000;
            Offset-=(FileOffset+CurPos)/4;
            D[0]=(byte)Offset;
            D[1]=(byte)(Offset>>8);
            D[2]=(byte)(Offset>>16);
          }
        }
      }
      return SrcData;
    case FILTER_DELTA:
      {
        // Unlike RAR3, we do not need to reject excessive channel
        // values here, since RAR5 uses only 5 bits to store channel.
        uint Channels=Flt->Channels,SrcPos=0;

        FilterDstMemory.Alloc(DataSize);
        byte *DstData=&FilterDstMemory[0];

        // Bytes from same channels are grouped to continual data blocks,
        // so we need to place them back to their interleaving positions.
        for (uint CurChannel=0;CurChannel<Channels;CurChannel++)
        {
          byte PrevByte=0;
          for (uint DestPos=CurChannel;DestPos<DataSize;DestPos+=Channels)
            DstData[DestPos]=(PrevByte-=Data[SrcPos++]);
        }
        return DstData;
      }

  }
  return NULL;
}


void Unpack::UnpWriteArea(size_t StartPtr,size_t EndPtr)
{
  if (EndPtr!=StartPtr)
    UnpSomeRead=true;
  if (EndPtr<StartPtr)
    UnpAllBuf=true;

  if (Fragmented)
  {
    size_t SizeToWrite=(EndPtr-StartPtr) & MaxWinMask;
    while (SizeToWrite>0)
    {
      size_t BlockSize=FragWindow.GetBlockSize(StartPtr,SizeToWrite);
      UnpWriteData(&FragWindow[StartPtr],BlockSize);
      SizeToWrite-=BlockSize;
      StartPtr=(StartPtr+BlockSize) & MaxWinMask;
    }
  }
  else
    if (EndPtr<StartPtr)
    {
      UnpWriteData(Window+StartPtr,MaxWinSize-StartPtr);
      UnpWriteData(Window,EndPtr);
    }
    else
      UnpWriteData(Window+StartPtr,EndPtr-StartPtr);
}


void Unpack::UnpWriteData(byte *Data,size_t Size)
{
  if (WrittenFileSize>=DestUnpSize)
    return;
  size_t WriteSize=Size;
  int64 LeftToWrite=DestUnpSize-WrittenFileSize;
  if ((int64)WriteSize>LeftToWrite)
    WriteSize=(size_t)LeftToWrite;
  UnpIO->UnpWrite(Data,WriteSize);
  WrittenFileSize+=Size;
}


void Unpack::UnpInitData50(bool Solid)
{
  if (!Solid)
    TablesRead5=false;
}


bool Unpack::ReadBlockHeader(BitInput &Inp,UnpackBlockHeader &Header)
{
  Header.HeaderSize=0;

  if (!Inp.ExternalBuffer && Inp.InAddr>ReadTop-7)
    if (!UnpReadBuf())
      return false;
  Inp.faddbits((8-Inp.InBit)&7);

  byte BlockFlags=Inp.fgetbits()>>8;
  Inp.faddbits(8);
  uint ByteCount=((BlockFlags>>3)&3)+1; // Block size byte count.

  if (ByteCount==4)
    return false;

  Header.HeaderSize=2+ByteCount;

  Header.BlockBitSize=(BlockFlags&7)+1;

  byte SavedCheckSum=Inp.fgetbits()>>8;
  Inp.faddbits(8);

  int BlockSize=0;
  for (uint I=0;I<ByteCount;I++)
  {
    BlockSize+=(Inp.fgetbits()>>8)<<(I*8);
    Inp.addbits(8);
  }

  Header.BlockSize=BlockSize;
  byte CheckSum=byte(0x5a^BlockFlags^BlockSize^(BlockSize>>8)^(BlockSize>>16));
  if (CheckSum!=SavedCheckSum)
    return false;

  Header.BlockStart=Inp.InAddr;
  ReadBorder=Min(ReadBorder,Header.BlockStart+Header.BlockSize-1);

  Header.LastBlockInFile=(BlockFlags & 0x40)!=0;
  Header.TablePresent=(BlockFlags & 0x80)!=0;
  return true;
}


bool Unpack::ReadTables(BitInput &Inp,UnpackBlockHeader &Header,UnpackBlockTables &Tables)
{
  if (!Header.TablePresent)
    return true;

  if (!Inp.ExternalBuffer && Inp.InAddr>ReadTop-25)
    if (!UnpReadBuf())
      return false;

  byte BitLength[BC];
  for (uint I=0;I<BC;I++)
  {
    uint Length=(byte)(Inp.fgetbits() >> 12);
    Inp.faddbits(4);
    if (Length==15)
    {
      uint ZeroCount=(byte)(Inp.fgetbits() >> 12);
      Inp.faddbits(4);
      if (ZeroCount==0)
        BitLength[I]=15;
      else
      {
        ZeroCount+=2;
        while (ZeroCount-- > 0 && I<ASIZE(BitLength))
          BitLength[I++]=0;
        I--;
      }
    }
    else
      BitLength[I]=Length;
  }

  MakeDecodeTables(BitLength,&Tables.BD,BC);

  byte Table[HUFF_TABLE_SIZE];
  const uint TableSize=HUFF_TABLE_SIZE;
  for (uint I=0;I<TableSize;)
  {
    if (!Inp.ExternalBuffer && Inp.InAddr>ReadTop-5)
      if (!UnpReadBuf())
        return false;
    uint Number=DecodeNumber(Inp,&Tables.BD);
    if (Number<16)
    {
      Table[I]=Number;
      I++;
    }
    else
      if (Number<18)
      {
        uint N;
        if (Number==16)
        {
          N=(Inp.fgetbits() >> 13)+3;
          Inp.faddbits(3);
        }
        else
        {
          N=(Inp.fgetbits() >> 9)+11;
          Inp.faddbits(7);
        }
        if (I==0)
        {
          // We cannot have "repeat previous" code at the first position.
          // Multiple such codes would shift Inp position without changing I,
          // which can lead to reading beyond of Inp boundary in mutithreading
          // mode, where Inp.ExternalBuffer disables bounds check and we just
          // reserve a lot of buffer space to not need such check normally.
          return false;
        }
        else
          while (N-- > 0 && I<TableSize)
          {
            Table[I]=Table[I-1];
            I++;
          }
      }
      else
      {
        uint N;
        if (Number==18)
        {
          N=(Inp.fgetbits() >> 13)+3;
          Inp.faddbits(3);
        }
        else
        {
          N=(Inp.fgetbits() >> 9)+11;
          Inp.faddbits(7);
        }
        while (N-- > 0 && I<TableSize)
          Table[I++]=0;
      }
  }
  TablesRead5=true;
  if (!Inp.ExternalBuffer && Inp.InAddr>ReadTop)
    return false;
  MakeDecodeTables(&Table[0],&Tables.LD,NC);
  MakeDecodeTables(&Table[NC],&Tables.DD,DC);
  MakeDecodeTables(&Table[NC+DC],&Tables.LDD,LDC);
  MakeDecodeTables(&Table[NC+DC+LDC],&Tables.RD,RC);
  return true;
}


void Unpack::InitFilters()
{
  Filters.SoftReset();
}

#include "rar.hpp"

RarVM::RarVM()
{
  Mem=NULL;
}


RarVM::~RarVM()
{
  delete[] Mem;
}


void RarVM::Init()
{
  if (Mem==NULL)
    Mem=new byte[VM_MEMSIZE+4];
}


void RarVM::Execute(VM_PreparedProgram *Prg)
{
  memcpy(R,Prg->InitR,sizeof(Prg->InitR));
  Prg->FilteredData=NULL;
  if (Prg->Type!=VMSF_NONE)
  {
    bool Success=ExecuteStandardFilter(Prg->Type);
    uint BlockSize=Prg->InitR[4] & VM_MEMMASK;
    Prg->FilteredDataSize=BlockSize;
    if (Prg->Type==VMSF_DELTA || Prg->Type==VMSF_RGB || Prg->Type==VMSF_AUDIO)
      Prg->FilteredData=2*BlockSize>VM_MEMSIZE || !Success ? Mem:Mem+BlockSize;
    else
      Prg->FilteredData=Mem;
  }
}


void RarVM::Prepare(byte *Code,uint CodeSize,VM_PreparedProgram *Prg)
{
  // Calculate the single byte XOR checksum to check validity of VM code.
  byte XorSum=0;
  for (uint I=1;I<CodeSize;I++)
    XorSum^=Code[I];

  if (XorSum!=Code[0])
    return;

  struct StandardFilters
  {
    uint Length;
    uint CRC;
    VM_StandardFilters Type;
  } static StdList[]={
    53, 0xad576887, VMSF_E8,
    57, 0x3cd7e57e, VMSF_E8E9,
   120, 0x3769893f, VMSF_ITANIUM,
    29, 0x0e06077d, VMSF_DELTA,
   149, 0x1c2c5dc8, VMSF_RGB,
   216, 0xbc85e701, VMSF_AUDIO
  };
  uint CodeCRC=CRC32(0xffffffff,Code,CodeSize)^0xffffffff;
  for (uint I=0;I<ASIZE(StdList);I++)
    if (StdList[I].CRC==CodeCRC && StdList[I].Length==CodeSize)
    {
      Prg->Type=StdList[I].Type;
      break;
    }
}


uint RarVM::ReadData(BitInput &Inp)
{
  uint Data=Inp.fgetbits();
  switch(Data&0xc000)
  {
    case 0:
      Inp.faddbits(6);
      return (Data>>10)&0xf;
    case 0x4000:
      if ((Data&0x3c00)==0)
      {
        Data=0xffffff00|((Data>>2)&0xff);
        Inp.faddbits(14);
      }
      else
      {
        Data=(Data>>6)&0xff;
        Inp.faddbits(10);
      }
      return Data;
    case 0x8000:
      Inp.faddbits(2);
      Data=Inp.fgetbits();
      Inp.faddbits(16);
      return Data;
    default:
      Inp.faddbits(2);
      Data=(Inp.fgetbits()<<16);
      Inp.faddbits(16);
      Data|=Inp.fgetbits();
      Inp.faddbits(16);
      return Data;
  }
}


void RarVM::SetMemory(size_t Pos,byte *Data,size_t DataSize)
{
  if (Pos<VM_MEMSIZE && Data!=Mem+Pos)
  {
    // We can have NULL Data for invalid filters with DataSize==0. While most
    // sensible memmove implementations do not care about data if size is 0,
    // let's follow the standard and check the size first.
    size_t CopySize=Min(DataSize,VM_MEMSIZE-Pos);
    if (CopySize!=0)
      memmove(Mem+Pos,Data,CopySize);
  }
}


bool RarVM::ExecuteStandardFilter(VM_StandardFilters FilterType)
{
  switch(FilterType)
  {
    case VMSF_E8:
    case VMSF_E8E9:
      {
        byte *Data=Mem;
        uint DataSize=R[4],FileOffset=R[6];

        if (DataSize>VM_MEMSIZE || DataSize<4)
          return false;

        const uint FileSize=0x1000000;
        byte CmpByte2=FilterType==VMSF_E8E9 ? 0xe9:0xe8;
        for (uint CurPos=0;CurPos<DataSize-4;)
        {
          byte CurByte=*(Data++);
          CurPos++;
          if (CurByte==0xe8 || CurByte==CmpByte2)
          {
            uint Offset=CurPos+FileOffset;
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
      break;
    case VMSF_ITANIUM:
      {
        byte *Data=Mem;
        uint DataSize=R[4],FileOffset=R[6];

        if (DataSize>VM_MEMSIZE || DataSize<21)
          return false;

        uint CurPos=0;

        FileOffset>>=4;

        while (CurPos<DataSize-21)
        {
          int Byte=(Data[0]&0x1f)-0x10;
          if (Byte>=0)
          {
            static byte Masks[16]={4,4,6,6,0,0,7,7,4,4,0,0,4,4,0,0};
            byte CmdMask=Masks[Byte];
            if (CmdMask!=0)
              for (uint I=0;I<=2;I++)
                if (CmdMask & (1<<I))
                {
                  uint StartPos=I*41+5;
                  uint OpType=FilterItanium_GetBits(Data,StartPos+37,4);
                  if (OpType==5)
                  {
                    uint Offset=FilterItanium_GetBits(Data,StartPos+13,20);
                    FilterItanium_SetBits(Data,(Offset-FileOffset)&0xfffff,StartPos+13,20);
                  }
                }
          }
          Data+=16;
          CurPos+=16;
          FileOffset++;
        }
      }
      break;
    case VMSF_DELTA:
      {
        uint DataSize=R[4],Channels=R[0],SrcPos=0,Border=DataSize*2;
        if (DataSize>VM_MEMSIZE/2 || Channels>MAX3_UNPACK_CHANNELS || Channels==0)
          return false;

        // Bytes from same channels are grouped to continual data blocks,
        // so we need to place them back to their interleaving positions.
        for (uint CurChannel=0;CurChannel<Channels;CurChannel++)
        {
          byte PrevByte=0;
          for (uint DestPos=DataSize+CurChannel;DestPos<Border;DestPos+=Channels)
            Mem[DestPos]=(PrevByte-=Mem[SrcPos++]);
        }
      }
      break;
    case VMSF_RGB:
      {
        uint DataSize=R[4],Width=R[0]-3,PosR=R[1];
        if (DataSize>VM_MEMSIZE/2 || DataSize<3 || Width>DataSize || PosR>2)
          return false;
        byte *SrcData=Mem,*DestData=SrcData+DataSize;
        const uint Channels=3;
        for (uint CurChannel=0;CurChannel<Channels;CurChannel++)
        {
          uint PrevByte=0;

          for (uint I=CurChannel;I<DataSize;I+=Channels)
          {
            uint Predicted;
            if (I>=Width+3)
            {
              byte *UpperData=DestData+I-Width;
              uint UpperByte=*UpperData;
              uint UpperLeftByte=*(UpperData-3);
              Predicted=PrevByte+UpperByte-UpperLeftByte;
              int pa=abs((int)(Predicted-PrevByte));
              int pb=abs((int)(Predicted-UpperByte));
              int pc=abs((int)(Predicted-UpperLeftByte));
              if (pa<=pb && pa<=pc)
                Predicted=PrevByte;
              else
                if (pb<=pc)
                  Predicted=UpperByte;
                else
                  Predicted=UpperLeftByte;
            }
            else
              Predicted=PrevByte;
            DestData[I]=PrevByte=(byte)(Predicted-*(SrcData++));
          }
        }
        for (uint I=PosR,Border=DataSize-2;I<Border;I+=3)
        {
          byte G=DestData[I+1];
          DestData[I]+=G;
          DestData[I+2]+=G;
        }
      }
      break;
    case VMSF_AUDIO:
      {
        uint DataSize=R[4],Channels=R[0];
        byte *SrcData=Mem,*DestData=SrcData+DataSize;
        // In fact, audio channels never exceed 4.
        if (DataSize>VM_MEMSIZE/2 || Channels>128 || Channels==0)
          return false;
        for (uint CurChannel=0;CurChannel<Channels;CurChannel++)
        {
          uint PrevByte=0,PrevDelta=0,Dif[7];
          int D1=0,D2=0,D3;
          int K1=0,K2=0,K3=0;
          memset(Dif,0,sizeof(Dif));

          for (uint I=CurChannel,ByteCount=0;I<DataSize;I+=Channels,ByteCount++)
          {
            D3=D2;
            D2=PrevDelta-D1;
            D1=PrevDelta;

            uint Predicted=8*PrevByte+K1*D1+K2*D2+K3*D3;
            Predicted=(Predicted>>3) & 0xff;

            uint CurByte=*(SrcData++);

            Predicted-=CurByte;
            DestData[I]=Predicted;
            PrevDelta=(signed char)(Predicted-PrevByte);
            PrevByte=Predicted;

            int D=(signed char)CurByte;
            // Left shift of negative value is undefined behavior in C++,
            // so we cast it to unsigned to follow the standard.
            D=(uint)D<<3;

            Dif[0]+=abs(D);
            Dif[1]+=abs(D-D1);
            Dif[2]+=abs(D+D1);
            Dif[3]+=abs(D-D2);
            Dif[4]+=abs(D+D2);
            Dif[5]+=abs(D-D3);
            Dif[6]+=abs(D+D3);

            if ((ByteCount & 0x1f)==0)
            {
              uint MinDif=Dif[0],NumMinDif=0;
              Dif[0]=0;
              for (uint J=1;J<ASIZE(Dif);J++)
              {
                if (Dif[J]<MinDif)
                {
                  MinDif=Dif[J];
                  NumMinDif=J;
                }
                Dif[J]=0;
              }
              switch(NumMinDif)
              {
                case 1: if (K1>=-16) K1--; break;
                case 2: if (K1 < 16) K1++; break;
                case 3: if (K2>=-16) K2--; break;
                case 4: if (K2 < 16) K2++; break;
                case 5: if (K3>=-16) K3--; break;
                case 6: if (K3 < 16) K3++; break;
              }
            }
          }
        }
      }
      break;
  }
  return true;
}


uint RarVM::FilterItanium_GetBits(byte *Data,uint BitPos,uint BitCount)
{
  uint InAddr=BitPos/8;
  uint InBit=BitPos&7;
  uint BitField=(uint)Data[InAddr++];
  BitField|=(uint)Data[InAddr++] << 8;
  BitField|=(uint)Data[InAddr++] << 16;
  BitField|=(uint)Data[InAddr] << 24;
  BitField >>= InBit;
  return BitField & (0xffffffff>>(32-BitCount));
}


void RarVM::FilterItanium_SetBits(byte *Data,uint BitField,uint BitPos,uint BitCount)
{
  uint InAddr=BitPos/8;
  uint InBit=BitPos&7;
  uint AndMask=0xffffffff>>(32-BitCount);
  AndMask=~(AndMask<<InBit);

  BitField<<=InBit;

  for (uint I=0;I<4;I++)
  {
    Data[InAddr+I]&=AndMask;
    Data[InAddr+I]|=BitField;
    AndMask=(AndMask>>8)|0xff000000;
    BitField>>=8;
  }
}

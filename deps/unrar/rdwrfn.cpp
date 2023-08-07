#include "rar.hpp"

ComprDataIO::ComprDataIO()
{
#ifndef RAR_NOCRYPT
  Crypt=new CryptData;
  Decrypt=new CryptData;
#endif

  Init();
}


void ComprDataIO::Init()
{
  UnpackFromMemory=false;
  UnpackToMemory=false;
  UnpPackedSize=0;
  UnpPackedLeft=0;
  ShowProgress=true;
  TestMode=false;
  SkipUnpCRC=false;
  NoFileHeader=false;
  PackVolume=false;
  UnpVolume=false;
  NextVolumeMissing=false;
  SrcFile=NULL;
  DestFile=NULL;
  UnpWrAddr=NULL;
  UnpWrSize=0;
  Command=NULL;
  Encryption=false;
  Decryption=false;
  CurPackRead=CurPackWrite=CurUnpRead=CurUnpWrite=0;
  LastPercent=-1;
  SubHead=NULL;
  SubHeadPos=NULL;
  CurrentCommand=0;
  ProcessedArcSize=0;
  LastArcSize=0;
  TotalArcSize=0;
}


ComprDataIO::~ComprDataIO()
{
#ifndef RAR_NOCRYPT
  delete Crypt;
  delete Decrypt;
#endif
}




int ComprDataIO::UnpRead(byte *Addr,size_t Count)
{
#ifndef RAR_NOCRYPT
  // In case of encryption we need to align read size to encryption 
  // block size. We can do it by simple masking, because unpack read code
  // always reads more than CRYPT_BLOCK_SIZE, so we do not risk to make it 0.
  if (Decryption)
    Count &= ~CRYPT_BLOCK_MASK;
#endif
  
  int ReadSize=0,TotalRead=0;
  byte *ReadAddr;
  ReadAddr=Addr;
  while (Count > 0)
  {
    Archive *SrcArc=(Archive *)SrcFile;

    if (UnpackFromMemory)
    {
      memcpy(Addr,UnpackFromMemoryAddr,UnpackFromMemorySize);
      ReadSize=(int)UnpackFromMemorySize;
      UnpackFromMemorySize=0;
    }
    else
    {
      size_t SizeToRead=((int64)Count>UnpPackedLeft) ? (size_t)UnpPackedLeft:Count;
      if (SizeToRead > 0)
      {
        if (UnpVolume && Decryption && (int64)Count>UnpPackedLeft)
        {
          // We need aligned blocks for decryption and we want "Keep broken
          // files" to work efficiently with missing encrypted volumes.
          // So for last data block in volume we adjust the size to read to
          // next equal or smaller block producing aligned total block size.
          // So we'll ask for next volume only when processing few unaligned
          // bytes left in the end, when most of data is already extracted.
          size_t NewTotalRead = TotalRead + SizeToRead;
          size_t Adjust = NewTotalRead - (NewTotalRead  & ~CRYPT_BLOCK_MASK);
          size_t NewSizeToRead = SizeToRead - Adjust;
          if ((int)NewSizeToRead > 0)
            SizeToRead = NewSizeToRead;
        }

        if (!SrcFile->IsOpened())
          return -1;
        ReadSize=SrcFile->Read(ReadAddr,SizeToRead);
        FileHeader *hd=SubHead!=NULL ? SubHead:&SrcArc->FileHead;
        if (!NoFileHeader && hd->SplitAfter)
          PackedDataHash.Update(ReadAddr,ReadSize);
      }
    }
    CurUnpRead+=ReadSize;
    TotalRead+=ReadSize;
#ifndef NOVOLUME
    // These variable are not used in NOVOLUME mode, so it is better
    // to exclude commands below to avoid compiler warnings.
    ReadAddr+=ReadSize;
    Count-=ReadSize;
#endif
    UnpPackedLeft-=ReadSize;

    // Do not ask for next volume if we read something from current volume.
    // If next volume is missing, we need to process all data from current
    // volume before aborting. It helps to recover all possible data
    // in "Keep broken files" mode. But if we process encrypted data,
    // we ask for next volume also if we have non-aligned encryption block.
    // Since we adjust data size for decryption earlier above,
    // it does not hurt "Keep broken files" mode efficiency.
    if (UnpVolume && UnpPackedLeft == 0 && 
        (ReadSize==0 || Decryption && (TotalRead & CRYPT_BLOCK_MASK) != 0) )
    {
#ifndef NOVOLUME
      if (!MergeArchive(*SrcArc,this,true,CurrentCommand))
#endif
      {
        NextVolumeMissing=true;
        return -1;
      }
    }
    else
      break;
  }
  Archive *SrcArc=(Archive *)SrcFile;
  if (SrcArc!=NULL)
    ShowUnpRead(SrcArc->NextBlockPos-UnpPackedSize+CurUnpRead,TotalArcSize);
  if (ReadSize!=-1)
  {
    ReadSize=TotalRead;
#ifndef RAR_NOCRYPT
    if (Decryption)
      Decrypt->DecryptBlock(Addr,ReadSize);
#endif
  }
  Wait();
  return ReadSize;
}


void ComprDataIO::UnpWrite(byte *Addr,size_t Count)
{

#ifdef RARDLL
  CommandData *Cmd=((Archive *)SrcFile)->GetCommandData();
  if (Cmd->DllOpMode!=RAR_SKIP)
  {
    if (Cmd->Callback!=NULL &&
        Cmd->Callback(UCM_PROCESSDATA,Cmd->UserData,(LPARAM)Addr,Count)==-1)
      ErrHandler.Exit(RARX_USERBREAK);
    if (Cmd->ProcessDataProc!=NULL)
    {
      int RetCode=Cmd->ProcessDataProc(Addr,(int)Count);
      if (RetCode==0)
        ErrHandler.Exit(RARX_USERBREAK);
    }
  }
#endif // RARDLL

  UnpWrAddr=Addr;
  UnpWrSize=Count;
  if (UnpackToMemory)
  {
    if (Count <= UnpackToMemorySize)
    {
      //memcpy(UnpackToMemoryAddr,Addr,Count);
      UnpackToMemoryAddr+=Count;
      UnpackToMemorySize-=Count;
    }
  }
  else
    if (!TestMode)
      DestFile->Write(Addr,Count);
  CurUnpWrite+=Count;
  if (!SkipUnpCRC)
    UnpHash.Update(Addr,Count);
  ShowUnpWrite();
  Wait();
}






void ComprDataIO::ShowUnpRead(int64 ArcPos,int64 ArcSize)
{
  if (ShowProgress && SrcFile!=NULL)
  {
    // Important when processing several archives or multivolume archive.
    ArcPos+=ProcessedArcSize;

    Archive *SrcArc=(Archive *)SrcFile;
    CommandData *Cmd=SrcArc->GetCommandData();

    int CurPercent=ToPercent(ArcPos,ArcSize);
    if (!Cmd->DisablePercentage && CurPercent!=LastPercent)
    {
      uiExtractProgress(CurUnpWrite,SrcArc->FileHead.UnpSize,ArcPos,ArcSize);
      LastPercent=CurPercent;
    }
  }
}


void ComprDataIO::ShowUnpWrite()
{
}










void ComprDataIO::SetFiles(File *SrcFile,File *DestFile)
{
  if (SrcFile!=NULL)
    ComprDataIO::SrcFile=SrcFile;
  if (DestFile!=NULL)
    ComprDataIO::DestFile=DestFile;
  LastPercent=-1;
}


void ComprDataIO::GetUnpackedData(byte **Data,size_t *Size)
{
  *Data=UnpWrAddr;
  *Size=UnpWrSize;
}


void ComprDataIO::SetEncryption(bool Encrypt,CRYPT_METHOD Method,
     SecPassword *Password,const byte *Salt,const byte *InitV,
     uint Lg2Cnt,byte *HashKey,byte *PswCheck)
{
#ifndef RAR_NOCRYPT
  if (Encrypt)
    Encryption=Crypt->SetCryptKeys(true,Method,Password,Salt,InitV,Lg2Cnt,HashKey,PswCheck);
  else
    Decryption=Decrypt->SetCryptKeys(false,Method,Password,Salt,InitV,Lg2Cnt,HashKey,PswCheck);
#endif
}

void ComprDataIO::InitRijindal(byte *Key,byte *InitV)
{
#ifndef RAR_NOCRYPT
  Decryption=true;
  Decrypt->SetRijndalDecryptKey(Key,InitV);
#endif
}

#if !defined(SFX_MODULE) && !defined(RAR_NOCRYPT)
void ComprDataIO::SetAV15Encryption()
{
  Decryption=true;
  Decrypt->SetAV15Encryption();
}
#endif


#if !defined(SFX_MODULE) && !defined(RAR_NOCRYPT)
void ComprDataIO::SetCmt13Encryption()
{
  Decryption=true;
  Decrypt->SetCmt13Encryption();
}
#endif




void ComprDataIO::SetUnpackToMemory(byte *Addr,uint Size)
{
  UnpackToMemory=true;
  UnpackToMemoryAddr=Addr;
  UnpackToMemorySize=Size;
}

void ComprDataIO::SetUnpackFromMemory(byte *Addr,uint Size)
{
  UnpackFromMemory=true;
  UnpackFromMemoryAddr=Addr;
  UnpackFromMemorySize=Size;
}

// Extraction progress is based on the position in archive and we adjust 
// the total archives size here, so trailing blocks do not prevent progress
// reaching 100% at the end of extraction. Alternatively we could print "100%"
// after completing the entire archive extraction, but then we would need
// to take into account possible messages like the checksum error after
// last file percent progress.
void ComprDataIO::AdjustTotalArcSize(Archive *Arc)
{
  // If we know a position of QO or RR blocks, use them to adjust the total
  // packed size to beginning of these blocks. Earlier we already calculated
  // the total size based on entire archive sizes. We also set LastArcSize
  // to start of first trailing block, to add it later to ProcessedArcSize.
  int64 ArcLength=Arc->IsSeekable() ? Arc->FileLength() : 0;
  if (Arc->MainHead.QOpenOffset!=0) // QO is always preceding RR record.
    LastArcSize=Arc->MainHead.QOpenOffset;
  else
    if (Arc->MainHead.RROffset!=0)
      LastArcSize=Arc->MainHead.RROffset;
    else
    {
      // If neither QO nor RR are found, exclude the approximate size of
      // end of archive block.
      // We select EndBlock to be larger than typical 8 bytes HEAD_ENDARC,
      // but to not exceed the smallest 22 bytes HEAD_FILE with 1 byte file
      // name, so we do not have two files with 100% at the end of archive.
      const uint EndBlock=23;

      if (ArcLength>EndBlock)
        LastArcSize=ArcLength-EndBlock;
    }

  TotalArcSize-=ArcLength-LastArcSize;
}

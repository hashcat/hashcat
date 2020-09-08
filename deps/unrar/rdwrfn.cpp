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
  ProcessedArcSize=TotalArcSize=0;
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
      size_t SizeToRead=((int64)Count>UnpPackedSize) ? (size_t)UnpPackedSize:Count;
      if (SizeToRead > 0)
      {
        if (UnpVolume && Decryption && (int64)Count>UnpPackedSize)
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
    UnpPackedSize-=ReadSize;

    // Do not ask for next volume if we read something from current volume.
    // If next volume is missing, we need to process all data from current
    // volume before aborting. It helps to recover all possible data
    // in "Keep broken files" mode. But if we process encrypted data,
    // we ask for next volume also if we have non-aligned encryption block.
    // Since we adjust data size for decryption earlier above,
    // it does not hurt "Keep broken files" mode efficiency.
    if (UnpVolume && UnpPackedSize == 0 && 
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
    ShowUnpRead(SrcArc->CurBlockPos+CurUnpRead,UnpArcSize);
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


#if defined(RARDLL) && defined(_MSC_VER) && !defined(_WIN_64)
// Disable the run time stack check for unrar.dll, so we can manipulate
// with ProcessDataProc call type below. Run time check would intercept
// a wrong ESP before we restore it.
#pragma runtime_checks( "s", off )
#endif

void ComprDataIO::UnpWrite(byte *Addr,size_t Count)
{

#ifdef RARDLL
  RAROptions *Cmd=((Archive *)SrcFile)->GetRAROptions();
  if (Cmd->DllOpMode!=RAR_SKIP)
  {
    if (Cmd->Callback!=NULL &&
        Cmd->Callback(UCM_PROCESSDATA,Cmd->UserData,(LPARAM)Addr,Count)==-1)
      ErrHandler.Exit(RARX_USERBREAK);
    if (Cmd->ProcessDataProc!=NULL)
    {
      // Here we preserve ESP value. It is necessary for those developers,
      // who still define ProcessDataProc callback as "C" type function,
      // even though in year 2001 we announced in unrar.dll whatsnew.txt
      // that it will be PASCAL type (for compatibility with Visual Basic).
#if defined(_MSC_VER)
#ifndef _WIN_64
      __asm mov ebx,esp
#endif
#elif defined(_WIN_ALL) && defined(__BORLANDC__)
      _EBX=_ESP;
#endif
      int RetCode=Cmd->ProcessDataProc(Addr,(int)Count);

      // Restore ESP after ProcessDataProc with wrongly defined calling
      // convention broken it.
#if defined(_MSC_VER)
#ifndef _WIN_64
      __asm mov esp,ebx
#endif
#elif defined(_WIN_ALL) && defined(__BORLANDC__)
      _ESP=_EBX;
#endif
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
      memcpy(UnpackToMemoryAddr,Addr,Count);
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

#if defined(RARDLL) && defined(_MSC_VER) && !defined(_WIN_64)
// Restore the run time stack check for unrar.dll.
#pragma runtime_checks( "s", restore )
#endif






void ComprDataIO::ShowUnpRead(int64 ArcPos,int64 ArcSize)
{
  if (ShowProgress && SrcFile!=NULL)
  {
    if (TotalArcSize!=0)
    {
      // important when processing several archives or multivolume archive
      ArcSize=TotalArcSize;
      ArcPos+=ProcessedArcSize;
    }

    Archive *SrcArc=(Archive *)SrcFile;
    RAROptions *Cmd=SrcArc->GetRAROptions();

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

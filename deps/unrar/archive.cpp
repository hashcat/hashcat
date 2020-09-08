#include "rar.hpp"

#include "arccmt.cpp"


Archive::Archive(RAROptions *InitCmd)
{
  Cmd=NULL; // Just in case we'll have an exception in 'new' below.

  DummyCmd=(InitCmd==NULL);
  Cmd=DummyCmd ? (new RAROptions):InitCmd;

  OpenShared=Cmd->OpenShared;
  Format=RARFMT15;
  Solid=false;
  Volume=false;
  MainComment=false;
  Locked=false;
  Signed=false;
  FirstVolume=false;
  NewNumbering=false;
  SFXSize=0;
  LatestTime.Reset();
  Protected=false;
  Encrypted=false;
  FailedHeaderDecryption=false;
  BrokenHeader=false;
  LastReadBlock=0;

  CurBlockPos=0;
  NextBlockPos=0;


  memset(&MainHead,0,sizeof(MainHead));
  memset(&CryptHead,0,sizeof(CryptHead));
  memset(&EndArcHead,0,sizeof(EndArcHead));

  VolNumber=0;
  VolWrite=0;
  AddingFilesSize=0;
  AddingHeadersSize=0;
  *FirstVolumeName=0;

  Splitting=false;
  NewArchive=false;

  SilentOpen=false;

#ifdef USE_QOPEN
  ProhibitQOpen=false;
#endif

}


Archive::~Archive()
{
  if (DummyCmd)
    delete Cmd;
}


void Archive::CheckArc(bool EnableBroken)
{
  if (!IsArchive(EnableBroken))
  {
    // If FailedHeaderDecryption is set, we already reported that archive
    // password is incorrect.
    if (!FailedHeaderDecryption)
      uiMsg(UIERROR_BADARCHIVE,FileName);
    ErrHandler.Exit(RARX_FATAL);
  }
}


#if !defined(SFX_MODULE)
void Archive::CheckOpen(const wchar *Name)
{
  TOpen(Name);
  CheckArc(false);
}
#endif


bool Archive::WCheckOpen(const wchar *Name)
{
  if (!WOpen(Name))
    return false;
  if (!IsArchive(false))
  {
    uiMsg(UIERROR_BADARCHIVE,FileName);
    Close();
    return false;
  }
  return true;
}


RARFORMAT Archive::IsSignature(const byte *D,size_t Size)
{
  RARFORMAT Type=RARFMT_NONE;
  if (Size>=1 && D[0]==0x52)
#ifndef SFX_MODULE
    if (Size>=4 && D[1]==0x45 && D[2]==0x7e && D[3]==0x5e)
      Type=RARFMT14;
    else
#endif
      if (Size>=7 && D[1]==0x61 && D[2]==0x72 && D[3]==0x21 && D[4]==0x1a && D[5]==0x07)
      {
        // We check the last signature byte, so we can return a sensible
        // warning in case we'll want to change the archive format
        // sometimes in the future.
        if (D[6]==0)
          Type=RARFMT15;
        else
          if (D[6]==1)
            Type=RARFMT50;
          else
            if (D[6]>1 && D[6]<5)
              Type=RARFMT_FUTURE;
      }
  return Type;
}


bool Archive::IsArchive(bool EnableBroken)
{
  Encrypted=false;
  BrokenHeader=false; // Might be left from previous volume.
  
#ifndef SFX_MODULE
  if (IsDevice())
  {
    uiMsg(UIERROR_INVALIDNAME,FileName,FileName);
    return false;
  }
#endif
  if (Read(MarkHead.Mark,SIZEOF_MARKHEAD3)!=SIZEOF_MARKHEAD3)
    return false;
  SFXSize=0;
  
  RARFORMAT Type;
  if ((Type=IsSignature(MarkHead.Mark,SIZEOF_MARKHEAD3))!=RARFMT_NONE)
  {
    Format=Type;
    if (Format==RARFMT14)
      Seek(Tell()-SIZEOF_MARKHEAD3,SEEK_SET);
  }
  else
  {
    Array<char> Buffer(MAXSFXSIZE);
    long CurPos=(long)Tell();
    int ReadSize=Read(&Buffer[0],Buffer.Size()-16);
    for (int I=0;I<ReadSize;I++)
      if (Buffer[I]==0x52 && (Type=IsSignature((byte *)&Buffer[I],ReadSize-I))!=RARFMT_NONE)
      {
        Format=Type;
        if (Format==RARFMT14 && I>0 && CurPos<28 && ReadSize>31)
        {
          char *D=&Buffer[28-CurPos];
          if (D[0]!=0x52 || D[1]!=0x53 || D[2]!=0x46 || D[3]!=0x58)
            continue;
        }
        SFXSize=CurPos+I;
        Seek(SFXSize,SEEK_SET);
        if (Format==RARFMT15 || Format==RARFMT50)
          Read(MarkHead.Mark,SIZEOF_MARKHEAD3);
        break;
      }
    if (SFXSize==0)
      return false;
  }
  if (Format==RARFMT_FUTURE)
  {
    uiMsg(UIERROR_NEWRARFORMAT,FileName);
    return false;
  }
  if (Format==RARFMT50) // RAR 5.0 signature is by one byte longer.
  {
    if (Read(MarkHead.Mark+SIZEOF_MARKHEAD3,1)!=1 || MarkHead.Mark[SIZEOF_MARKHEAD3]!=0)
      return false;
    MarkHead.HeadSize=SIZEOF_MARKHEAD5;
  }
  else
    MarkHead.HeadSize=SIZEOF_MARKHEAD3;

#ifdef RARDLL
  // If callback function is not set, we cannot get the password,
  // so we skip the initial header processing for encrypted header archive.
  // It leads to skipped archive comment, but the rest of archive data
  // is processed correctly.
  if (Cmd->Callback==NULL)
    SilentOpen=true;
#endif

  bool HeadersLeft; // Any headers left to read.
  bool StartFound=false; // Main or encryption headers found.
  // Skip the archive encryption header if any and read the main header.
  while ((HeadersLeft=(ReadHeader()!=0))==true) // Additional parentheses to silence Clang.
  {
    SeekToNext();

    HEADER_TYPE Type=GetHeaderType();
    // In RAR 5.0 we need to quit after reading HEAD_CRYPT if we wish to
    // avoid the password prompt.
    StartFound=Type==HEAD_MAIN || SilentOpen && Type==HEAD_CRYPT;
    if (StartFound)
      break;
  }

  
  // We should not do it for EnableBroken or we'll get 'not RAR archive'
  // messages when extracting encrypted archives with wrong password.
  if (FailedHeaderDecryption && !EnableBroken)
    return false;

  if (BrokenHeader || !StartFound) // Main archive header is corrupt or missing.
  {
    if (!FailedHeaderDecryption) // If not reported a wrong password already.
      uiMsg(UIERROR_MHEADERBROKEN,FileName);
    if (!EnableBroken)
      return false;
  }

  MainComment=MainHead.CommentInHeader;

  // If we process non-encrypted archive or can request a password,
  // we set 'first volume' flag based on file attributes below.
  // It is necessary for RAR 2.x archives, which did not have 'first volume'
  // flag in main header. Also for all RAR formats we need to scan until
  // first file header to set "comment" flag when reading service header.
  // Unless we are in silent mode, we need to know about presence of comment
  // immediately after IsArchive call.
  if (HeadersLeft && (!SilentOpen || !Encrypted))
  {
    int64 SavePos=Tell();
    int64 SaveCurBlockPos=CurBlockPos,SaveNextBlockPos=NextBlockPos;
    HEADER_TYPE SaveCurHeaderType=CurHeaderType;

    while (ReadHeader()!=0)
    {
      HEADER_TYPE HeaderType=GetHeaderType();
      if (HeaderType==HEAD_SERVICE)
      {
        // If we have a split service headers, it surely indicates non-first
        // volume. But not split service header does not guarantee the first
        // volume, because we can have split file after non-split archive
        // comment. So we do not quit from loop here.
        FirstVolume=Volume && !SubHead.SplitBefore;
      }
      else
        if (HeaderType==HEAD_FILE)
        {
          FirstVolume=Volume && !FileHead.SplitBefore;
          break;
        }
        else
          if (HeaderType==HEAD_ENDARC) // Might happen if archive contains only a split service header.
            break;
      SeekToNext();
    }
    CurBlockPos=SaveCurBlockPos;
    NextBlockPos=SaveNextBlockPos;
    CurHeaderType=SaveCurHeaderType;
    Seek(SavePos,SEEK_SET);
  }
  if (!Volume || FirstVolume)
    wcsncpyz(FirstVolumeName,FileName,ASIZE(FirstVolumeName));

  return true;
}




void Archive::SeekToNext()
{
  Seek(NextBlockPos,SEEK_SET);
}






// Calculate the block size including encryption fields and padding if any.
uint Archive::FullHeaderSize(size_t Size)
{
  if (Encrypted)
  {
    Size = ALIGN_VALUE(Size, CRYPT_BLOCK_SIZE); // Align to encryption block size.
    if (Format == RARFMT50)
      Size += SIZE_INITV;
    else
      Size += SIZE_SALT30;
  }
  return uint(Size);
}




#ifdef USE_QOPEN
bool Archive::Open(const wchar *Name,uint Mode)
{
  // Important if we reuse Archive object and it has virtual QOpen
  // file position not matching real. For example, for 'l -v volname'.
  QOpen.Unload();

  return File::Open(Name,Mode);
}


int Archive::Read(void *Data,size_t Size)
{
  size_t Result;
  if (QOpen.Read(Data,Size,Result))
    return (int)Result;
  return File::Read(Data,Size);
}


void Archive::Seek(int64 Offset,int Method)
{
  if (!QOpen.Seek(Offset,Method))
    File::Seek(Offset,Method);
}


int64 Archive::Tell()
{
  int64 QPos;
  if (QOpen.Tell(&QPos))
    return QPos;
  return File::Tell();
}
#endif


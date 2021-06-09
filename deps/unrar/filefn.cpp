#include "rar.hpp"

MKDIR_CODE MakeDir(const wchar *Name,bool SetAttr,uint Attr)
{
#ifdef _WIN_ALL
  // Windows automatically removes dots and spaces in the end of directory
  // name. So we detect such names and process them with \\?\ prefix.
  wchar *LastChar=PointToLastChar(Name);
  bool Special=*LastChar=='.' || *LastChar==' ';
  BOOL RetCode=Special ? FALSE : CreateDirectory(Name,NULL);
  if (RetCode==0 && !FileExist(Name))
  {
    wchar LongName[NM];
    if (GetWinLongPath(Name,LongName,ASIZE(LongName)))
      RetCode=CreateDirectory(LongName,NULL);
  }
  if (RetCode!=0) // Non-zero return code means success for CreateDirectory.
  {
    if (SetAttr)
      SetFileAttr(Name,Attr);
    return MKDIR_SUCCESS;
  }
  int ErrCode=GetLastError();
  if (ErrCode==ERROR_FILE_NOT_FOUND || ErrCode==ERROR_PATH_NOT_FOUND)
    return MKDIR_BADPATH;
  return MKDIR_ERROR;
#elif defined(_UNIX)
  char NameA[NM];
  WideToChar(Name,NameA,ASIZE(NameA));
  mode_t uattr=SetAttr ? (mode_t)Attr:0777;
  int ErrCode=mkdir(NameA,uattr);
  if (ErrCode==-1)
    return errno==ENOENT ? MKDIR_BADPATH:MKDIR_ERROR;
  return MKDIR_SUCCESS;
#else
  return MKDIR_ERROR;
#endif
}


bool CreatePath(const wchar *Path,bool SkipLastName,bool Silent)
{
  if (Path==NULL || *Path==0)
    return false;

#if defined(_WIN_ALL) || defined(_EMX)
  uint DirAttr=0;
#else
  uint DirAttr=0777;
#endif
  
  bool Success=true;

  for (const wchar *s=Path;*s!=0;s++)
  {
    wchar DirName[NM];
    if (s-Path>=ASIZE(DirName))
      break;

    // Process all kinds of path separators, so user can enter Unix style
    // path in Windows or Windows in Unix. s>Path check avoids attempting
    // creating an empty directory for paths starting from path separator.
    if (IsPathDiv(*s) && s>Path)
    {
#ifdef _WIN_ALL
      // We must not attempt to create "D:" directory, because first
      // CreateDirectory will fail, so we'll use \\?\D:, which forces Wine
      // to create "D:" directory.
      if (s==Path+2 && Path[1]==':')
        continue;
#endif
      wcsncpy(DirName,Path,s-Path);
      DirName[s-Path]=0;

      Success=MakeDir(DirName,true,DirAttr)==MKDIR_SUCCESS;
      if (Success && !Silent)
      {
        mprintf(St(MCreatDir),DirName);
        mprintf(L" %s",St(MOk));
      }
    }
  }
  if (!SkipLastName && !IsPathDiv(*PointToLastChar(Path)))
    Success=MakeDir(Path,true,DirAttr)==MKDIR_SUCCESS;
  return Success;
}


void SetDirTime(const wchar *Name,RarTime *ftm,RarTime *ftc,RarTime *fta)
{
#if defined(_WIN_ALL)
  bool sm=ftm!=NULL && ftm->IsSet();
  bool sc=ftc!=NULL && ftc->IsSet();
  bool sa=fta!=NULL && fta->IsSet();

  uint DirAttr=GetFileAttr(Name);
  bool ResetAttr=(DirAttr!=0xffffffff && (DirAttr & FILE_ATTRIBUTE_READONLY)!=0);
  if (ResetAttr)
    SetFileAttr(Name,0);

  HANDLE hFile=CreateFile(Name,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
                          NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);
  if (hFile==INVALID_HANDLE_VALUE)
  {
    wchar LongName[NM];
    if (GetWinLongPath(Name,LongName,ASIZE(LongName)))
      hFile=CreateFile(LongName,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
                       NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL);
  }

  if (hFile==INVALID_HANDLE_VALUE)
    return;
  FILETIME fm,fc,fa;
  if (sm)
    ftm->GetWinFT(&fm);
  if (sc)
    ftc->GetWinFT(&fc);
  if (sa)
    fta->GetWinFT(&fa);
  SetFileTime(hFile,sc ? &fc:NULL,sa ? &fa:NULL,sm ? &fm:NULL);
  CloseHandle(hFile);
  if (ResetAttr)
    SetFileAttr(Name,DirAttr);
#endif
#if defined(_UNIX) || defined(_EMX)
  File::SetCloseFileTimeByName(Name,ftm,fta);
#endif
}


bool IsRemovable(const wchar *Name)
{
#if defined(_WIN_ALL)
  wchar Root[NM];
  GetPathRoot(Name,Root,ASIZE(Root));
  int Type=GetDriveType(*Root!=0 ? Root:NULL);
  return Type==DRIVE_REMOVABLE || Type==DRIVE_CDROM;
#else
  return false;
#endif
}


#ifndef SFX_MODULE
int64 GetFreeDisk(const wchar *Name)
{
#ifdef _WIN_ALL
  wchar Root[NM];
  GetFilePath(Name,Root,ASIZE(Root));

  ULARGE_INTEGER uiTotalSize,uiTotalFree,uiUserFree;
  uiUserFree.u.LowPart=uiUserFree.u.HighPart=0;
  if (GetDiskFreeSpaceEx(*Root!=0 ? Root:NULL,&uiUserFree,&uiTotalSize,&uiTotalFree) &&
      uiUserFree.u.HighPart<=uiTotalFree.u.HighPart)
    return INT32TO64(uiUserFree.u.HighPart,uiUserFree.u.LowPart);
  return 0;
#elif defined(_UNIX)
  wchar Root[NM];
  GetFilePath(Name,Root,ASIZE(Root));
  char RootA[NM];
  WideToChar(Root,RootA,ASIZE(RootA));
  struct statvfs sfs;
  if (statvfs(*RootA!=0 ? RootA:".",&sfs)!=0)
    return 0;
  int64 FreeSize=sfs.f_bsize;
  FreeSize=FreeSize*sfs.f_bavail;
  return FreeSize;
#else
  return 0;
#endif
}
#endif


#if defined(_WIN_ALL) && !defined(SFX_MODULE) && !defined(SILENT)
// Return 'true' for FAT and FAT32, so we can adjust the maximum supported
// file size to 4 GB for these file systems.
bool IsFAT(const wchar *Name)
{
  wchar Root[NM];
  GetPathRoot(Name,Root,ASIZE(Root));
  wchar FileSystem[MAX_PATH+1];
  if (GetVolumeInformation(Root,NULL,0,NULL,NULL,NULL,FileSystem,ASIZE(FileSystem)))
    return wcscmp(FileSystem,L"FAT")==0 || wcscmp(FileSystem,L"FAT32")==0;
  return false;
}
#endif


bool FileExist(const wchar *Name)
{
#ifdef _WIN_ALL
  return GetFileAttr(Name)!=0xffffffff;
#elif defined(ENABLE_ACCESS)
  char NameA[NM];
  WideToChar(Name,NameA,ASIZE(NameA));
  return access(NameA,0)==0;
#else
  FindData FD;
  return FindFile::FastFind(Name,&FD);
#endif
}
 

bool WildFileExist(const wchar *Name)
{
  if (IsWildcard(Name))
  {
    FindFile Find;
    Find.SetMask(Name);
    FindData fd;
    return Find.Next(&fd);
  }
  return FileExist(Name);
}


bool IsDir(uint Attr)
{
#ifdef _WIN_ALL
  return Attr!=0xffffffff && (Attr & FILE_ATTRIBUTE_DIRECTORY)!=0;
#endif
#if defined(_UNIX)
  return (Attr & 0xF000)==0x4000;
#endif
}


bool IsUnreadable(uint Attr)
{
#if defined(_UNIX) && defined(S_ISFIFO) && defined(S_ISSOCK) && defined(S_ISCHR)
  return S_ISFIFO(Attr) || S_ISSOCK(Attr) || S_ISCHR(Attr);
#endif
  return false;
}


bool IsLink(uint Attr)
{
#ifdef _UNIX
  return (Attr & 0xF000)==0xA000;
#elif defined(_WIN_ALL)
  return (Attr & FILE_ATTRIBUTE_REPARSE_POINT)!=0;
#else
  return false;
#endif
}






bool IsDeleteAllowed(uint FileAttr)
{
#ifdef _WIN_ALL
  return (FileAttr & (FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN))==0;
#else
  return (FileAttr & (S_IRUSR|S_IWUSR))==(S_IRUSR|S_IWUSR);
#endif
}


void PrepareToDelete(const wchar *Name)
{
#if defined(_WIN_ALL) || defined(_EMX)
  SetFileAttr(Name,0);
#endif
#ifdef _UNIX
  if (Name!=NULL)
  {
    char NameA[NM];
    WideToChar(Name,NameA,ASIZE(NameA));
    chmod(NameA,S_IRUSR|S_IWUSR|S_IXUSR);
  }
#endif
}


uint GetFileAttr(const wchar *Name)
{
#ifdef _WIN_ALL
  DWORD Attr=GetFileAttributes(Name);
  if (Attr==0xffffffff)
  {
    wchar LongName[NM];
    if (GetWinLongPath(Name,LongName,ASIZE(LongName)))
      Attr=GetFileAttributes(LongName);
  }
  return Attr;
#else
  char NameA[NM];
  WideToChar(Name,NameA,ASIZE(NameA));
  struct stat st;
  if (stat(NameA,&st)!=0)
    return 0;
  return st.st_mode;
#endif
}


bool SetFileAttr(const wchar *Name,uint Attr)
{
#ifdef _WIN_ALL
  bool Success=SetFileAttributes(Name,Attr)!=0;
  if (!Success)
  {
    wchar LongName[NM];
    if (GetWinLongPath(Name,LongName,ASIZE(LongName)))
      Success=SetFileAttributes(LongName,Attr)!=0;
  }
  return Success;
#elif defined(_UNIX)
  char NameA[NM];
  WideToChar(Name,NameA,ASIZE(NameA));
  return chmod(NameA,(mode_t)Attr)==0;
#else
  return false;
#endif
}


#if 0
wchar *MkTemp(wchar *Name,size_t MaxSize)
{
  size_t Length=wcslen(Name);

  RarTime CurTime;
  CurTime.SetCurrentTime();

  // We cannot use CurTime.GetWin() as is, because its lowest bits can
  // have low informational value, like being a zero or few fixed numbers.
  uint Random=(uint)(CurTime.GetWin()/100000);

  // Using PID we guarantee that different RAR copies use different temp names
  // even if started in exactly the same time.
  uint PID=0;
#ifdef _WIN_ALL
  PID=(uint)GetCurrentProcessId();
#elif defined(_UNIX)
  PID=(uint)getpid();
#endif

  for (uint Attempt=0;;Attempt++)
  {
    uint Ext=Random%50000+Attempt;
    wchar RndText[50];
    swprintf(RndText,ASIZE(RndText),L"%u.%03u",PID,Ext);
    if (Length+wcslen(RndText)>=MaxSize || Attempt==1000)
      return NULL;
    wcsncpyz(Name+Length,RndText,MaxSize-Length);
    if (!FileExist(Name))
      break;
  }
  return Name;
}
#endif


#if !defined(SFX_MODULE)
void CalcFileSum(File *SrcFile,uint *CRC32,byte *Blake2,uint Threads,int64 Size,uint Flags)
{
  int64 SavePos=SrcFile->Tell();
#ifndef SILENT
  int64 FileLength=Size==INT64NDF ? SrcFile->FileLength() : Size;
#endif

  if ((Flags & (CALCFSUM_SHOWTEXT|CALCFSUM_SHOWPERCENT))!=0)
    uiMsg(UIEVENT_FILESUMSTART);

  if ((Flags & CALCFSUM_CURPOS)==0)
    SrcFile->Seek(0,SEEK_SET);

  const size_t BufSize=0x100000;
  Array<byte> Data(BufSize);


  DataHash HashCRC,HashBlake2;
  HashCRC.Init(HASH_CRC32,Threads);
  HashBlake2.Init(HASH_BLAKE2,Threads);

  int64 BlockCount=0;
  int64 TotalRead=0;
  while (true)
  {
    size_t SizeToRead;
    if (Size==INT64NDF)   // If we process the entire file.
      SizeToRead=BufSize; // Then always attempt to read the entire buffer.
    else
      SizeToRead=(size_t)Min((int64)BufSize,Size);
    int ReadSize=SrcFile->Read(&Data[0],SizeToRead);
    if (ReadSize==0)
      break;
    TotalRead+=ReadSize;

    if ((++BlockCount & 0xf)==0)
    {
#ifndef SILENT
      if ((Flags & CALCFSUM_SHOWPROGRESS)!=0)
        uiExtractProgress(TotalRead,FileLength,TotalRead,FileLength);
      else
      {
        if ((Flags & CALCFSUM_SHOWPERCENT)!=0)
          uiMsg(UIEVENT_FILESUMPROGRESS,ToPercent(TotalRead,FileLength));
      }
#endif
      Wait();
    }

    if (CRC32!=NULL)
      HashCRC.Update(&Data[0],ReadSize);
    if (Blake2!=NULL)
      HashBlake2.Update(&Data[0],ReadSize);

    if (Size!=INT64NDF)
      Size-=ReadSize;
  }
  SrcFile->Seek(SavePos,SEEK_SET);

  if ((Flags & CALCFSUM_SHOWPERCENT)!=0)
    uiMsg(UIEVENT_FILESUMEND);

  if (CRC32!=NULL)
    *CRC32=HashCRC.GetCRC32();
  if (Blake2!=NULL)
  {
    HashValue Result;
    HashBlake2.Result(&Result);
    memcpy(Blake2,Result.Digest,sizeof(Result.Digest));
  }
}
#endif


bool RenameFile(const wchar *SrcName,const wchar *DestName)
{
#ifdef _WIN_ALL
  bool Success=MoveFile(SrcName,DestName)!=0;
  if (!Success)
  {
    wchar LongName1[NM],LongName2[NM];
    if (GetWinLongPath(SrcName,LongName1,ASIZE(LongName1)) &&
        GetWinLongPath(DestName,LongName2,ASIZE(LongName2)))
      Success=MoveFile(LongName1,LongName2)!=0;
  }
  return Success;
#else
  char SrcNameA[NM],DestNameA[NM];
  WideToChar(SrcName,SrcNameA,ASIZE(SrcNameA));
  WideToChar(DestName,DestNameA,ASIZE(DestNameA));
  bool Success=rename(SrcNameA,DestNameA)==0;
  return Success;
#endif
}


bool DelFile(const wchar *Name)
{
#ifdef _WIN_ALL
  bool Success=DeleteFile(Name)!=0;
  if (!Success)
  {
    wchar LongName[NM];
    if (GetWinLongPath(Name,LongName,ASIZE(LongName)))
      Success=DeleteFile(LongName)!=0;
  }
  return Success;
#else
  char NameA[NM];
  WideToChar(Name,NameA,ASIZE(NameA));
  bool Success=remove(NameA)==0;
  return Success;
#endif
}


bool DelDir(const wchar *Name)
{
#ifdef _WIN_ALL
  bool Success=RemoveDirectory(Name)!=0;
  if (!Success)
  {
    wchar LongName[NM];
    if (GetWinLongPath(Name,LongName,ASIZE(LongName)))
      Success=RemoveDirectory(LongName)!=0;
  }
  return Success;
#else
  char NameA[NM];
  WideToChar(Name,NameA,ASIZE(NameA));
  bool Success=rmdir(NameA)==0;
  return Success;
#endif
}


#if defined(_WIN_ALL) && !defined(SFX_MODULE)
bool SetFileCompression(const wchar *Name,bool State)
{
  HANDLE hFile=CreateFile(Name,FILE_READ_DATA|FILE_WRITE_DATA,
                 FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,
                 FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
  if (hFile==INVALID_HANDLE_VALUE)
  {
    wchar LongName[NM];
    if (GetWinLongPath(Name,LongName,ASIZE(LongName)))
      hFile=CreateFile(LongName,FILE_READ_DATA|FILE_WRITE_DATA,
                 FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,
                 FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_SEQUENTIAL_SCAN,NULL);
  }
  if (hFile==INVALID_HANDLE_VALUE)
    return false;
  SHORT NewState=State ? COMPRESSION_FORMAT_DEFAULT:COMPRESSION_FORMAT_NONE;
  DWORD Result;
  int RetCode=DeviceIoControl(hFile,FSCTL_SET_COMPRESSION,&NewState,
                              sizeof(NewState),NULL,0,&Result,NULL);
  CloseHandle(hFile);
  return RetCode!=0;
}
#endif











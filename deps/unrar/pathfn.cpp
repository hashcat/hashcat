#include "rar.hpp"

wchar* PointToName(const wchar *Path)
{
  for (int I=(int)wcslen(Path)-1;I>=0;I--)
    if (IsPathDiv(Path[I]))
      return (wchar*)&Path[I+1];
  return (wchar*)((*Path && IsDriveDiv(Path[1])) ? Path+2:Path);
}


wchar* PointToLastChar(const wchar *Path)
{
  size_t Length=wcslen(Path);
  return (wchar*)(Length>0 ? Path+Length-1:Path);
}


wchar* ConvertPath(const wchar *SrcPath,wchar *DestPath,size_t DestSize)
{
  const wchar *DestPtr=SrcPath;

  // Prevent \..\ in any part of path string.
  for (const wchar *s=DestPtr;*s!=0;s++)
    if (IsPathDiv(s[0]) && s[1]=='.' && s[2]=='.' && IsPathDiv(s[3]))
      DestPtr=s+4;

  // Remove any amount of <d>:\ and any sequence of . and \ in the beginning of path string.
  while (*DestPtr!=0)
  {
    const wchar *s=DestPtr;
    if (s[0]!=0 && IsDriveDiv(s[1]))
      s+=2;
    if (s[0]=='\\' && s[1]=='\\')
    {
      const wchar *Slash=wcschr(s+2,'\\');
      if (Slash!=NULL && (Slash=wcschr(Slash+1,'\\'))!=NULL)
        s=Slash+1;
    }
    for (const wchar *t=s;*t!=0;t++)
      if (IsPathDiv(*t))
        s=t+1;
      else
        if (*t!='.')
          break;
    if (s==DestPtr)
      break;
    DestPtr=s;
  }

  // Code above does not remove last "..", doing here.
  if (DestPtr[0]=='.' && DestPtr[1]=='.' && DestPtr[2]==0)
    DestPtr+=2;
  
  if (DestPath!=NULL)
  {
    // SrcPath and DestPath can point to same memory area,
    // so we use the temporary buffer for copying.
    wchar TmpStr[NM];
    wcsncpyz(TmpStr,DestPtr,ASIZE(TmpStr));
    wcsncpyz(DestPath,TmpStr,DestSize);
  }
  return (wchar *)DestPtr;
}


void SetName(wchar *FullName,const wchar *Name,size_t MaxSize)
{
  wchar *NamePtr=PointToName(FullName);
  wcsncpyz(NamePtr,Name,MaxSize-(NamePtr-FullName));
}


void SetExt(wchar *Name,const wchar *NewExt,size_t MaxSize)
{
  if (Name==NULL || *Name==0)
    return;
  wchar *Dot=GetExt(Name);
  if (Dot!=NULL)
    *Dot=0;
  if (NewExt!=NULL)
  {
    wcsncatz(Name,L".",MaxSize);
    wcsncatz(Name,NewExt,MaxSize);
  }
}


#ifndef SFX_MODULE
void SetSFXExt(wchar *SFXName,size_t MaxSize)
{
  if (SFXName==NULL || *SFXName==0)
    return;

#ifdef _UNIX
  SetExt(SFXName,L"sfx",MaxSize);
#endif

#if defined(_WIN_ALL) || defined(_EMX)
  SetExt(SFXName,L"exe",MaxSize);
#endif
}
#endif


// 'Ext' is an extension with the leading dot, like L".rar".
wchar *GetExt(const wchar *Name)
{
  return Name==NULL ? NULL:wcsrchr(PointToName(Name),'.');
}


// 'Ext' is an extension without the leading dot, like L"rar".
bool CmpExt(const wchar *Name,const wchar *Ext)
{
  wchar *NameExt=GetExt(Name);
  return NameExt!=NULL && wcsicomp(NameExt+1,Ext)==0;
}


bool IsWildcard(const wchar *Str)
{
  if (Str==NULL)
    return false;
#ifdef _WIN_ALL
  // Not treat the special NTFS \\?\d: path prefix as a wildcard.
  if (Str[0]=='\\' && Str[1]=='\\' && Str[2]=='?' && Str[3]=='\\')
    Str+=4;
#endif
  return wcspbrk(Str,L"*?")!=NULL;
}


bool IsPathDiv(int Ch)
{
#ifdef _WIN_ALL
  return Ch=='\\' || Ch=='/';
#else
  return Ch==CPATHDIVIDER;
#endif
}


bool IsDriveDiv(int Ch)
{
#ifdef _UNIX
  return false;
#else
  return Ch==':';
#endif
}


bool IsDriveLetter(const wchar *Path)
{
  wchar Letter=etoupperw(Path[0]);
  return Letter>='A' && Letter<='Z' && IsDriveDiv(Path[1]);
}


int GetPathDisk(const wchar *Path)
{
  if (IsDriveLetter(Path))
    return etoupperw(*Path)-'A';
  else
    return -1;
}


void AddEndSlash(wchar *Path,size_t MaxLength)
{
  size_t Length=wcslen(Path);
  if (Length>0 && Path[Length-1]!=CPATHDIVIDER && Length+1<MaxLength)
  {
    Path[Length]=CPATHDIVIDER;
    Path[Length+1]=0;
  }
}


void MakeName(const wchar *Path,const wchar *Name,wchar *Pathname,size_t MaxSize)
{
  // 'Path', 'Name' and 'Pathname' can point to same memory area. So we use
  // the temporary buffer instead of constructing the name in 'Pathname'.
  wchar OutName[NM];
  wcsncpyz(OutName,Path,ASIZE(OutName));
  AddEndSlash(OutName,ASIZE(OutName));
  wcsncatz(OutName,Name,ASIZE(OutName));
  wcsncpyz(Pathname,OutName,MaxSize);
}


// Returns file path including the trailing path separator symbol.
void GetFilePath(const wchar *FullName,wchar *Path,size_t MaxLength)
{
  if (MaxLength==0)
    return;
  size_t PathLength=Min(MaxLength-1,size_t(PointToName(FullName)-FullName));
  wcsncpy(Path,FullName,PathLength);
  Path[PathLength]=0;
}


// Removes name and returns file path without the trailing
// path separator symbol.
void RemoveNameFromPath(wchar *Path)
{
  wchar *Name=PointToName(Path);
  if (Name>=Path+2 && (!IsDriveDiv(Path[1]) || Name>=Path+4))
    Name--;
  *Name=0;
}


#if defined(_WIN_ALL) && !defined(SFX_MODULE)
bool GetAppDataPath(wchar *Path,size_t MaxSize,bool Create)
{
  LPMALLOC g_pMalloc;
  SHGetMalloc(&g_pMalloc);
  LPITEMIDLIST ppidl;
  *Path=0;
  bool Success=false;
  if (SHGetSpecialFolderLocation(NULL,CSIDL_APPDATA,&ppidl)==NOERROR &&
      SHGetPathFromIDList(ppidl,Path) && *Path!=0)
  {
    AddEndSlash(Path,MaxSize);
    wcsncatz(Path,L"WinRAR",MaxSize);
    Success=FileExist(Path);
    if (!Success && Create)
      Success=MakeDir(Path,false,0)==MKDIR_SUCCESS;
  }
  g_pMalloc->Free(ppidl);
  return Success;
}
#endif


#if defined(_WIN_ALL) && !defined(SFX_MODULE)
void GetRarDataPath(wchar *Path,size_t MaxSize,bool Create)
{
  *Path=0;

  HKEY hKey;
  if (RegOpenKeyEx(HKEY_CURRENT_USER,L"Software\\WinRAR\\Paths",0,
                   KEY_QUERY_VALUE,&hKey)==ERROR_SUCCESS)
  {
    DWORD DataSize=(DWORD)MaxSize,Type;
    RegQueryValueEx(hKey,L"AppData",0,&Type,(BYTE *)Path,&DataSize);
    RegCloseKey(hKey);
  }

  if (*Path==0 || !FileExist(Path))
    if (!GetAppDataPath(Path,MaxSize,Create))
    {
      GetModuleFileName(NULL,Path,(DWORD)MaxSize);
      RemoveNameFromPath(Path);
    }
}
#endif


#ifndef SFX_MODULE
bool EnumConfigPaths(uint Number,wchar *Path,size_t MaxSize,bool Create)
{
#ifdef _UNIX
  static const wchar *ConfPath[]={
    L"/etc", L"/etc/rar", L"/usr/lib", L"/usr/local/lib", L"/usr/local/etc"
  };
  if (Number==0)
  {
    char *EnvStr=getenv("HOME");
    if (EnvStr!=NULL)
      CharToWide(EnvStr,Path,MaxSize);
    else
      wcsncpyz(Path,ConfPath[0],MaxSize);
    return true;
  }
  Number--;
  if (Number>=ASIZE(ConfPath))
    return false;
  wcsncpyz(Path,ConfPath[Number], MaxSize);
  return true;
#elif defined(_WIN_ALL)
  if (Number>1)
    return false;
  if (Number==0)
    GetRarDataPath(Path,MaxSize,Create);
  else
  {
    GetModuleFileName(NULL,Path,(DWORD)MaxSize);
    RemoveNameFromPath(Path);
  }
  return true;
#else
  return false;
#endif
}
#endif


#ifndef SFX_MODULE
void GetConfigName(const wchar *Name,wchar *FullName,size_t MaxSize,bool CheckExist,bool Create)
{
  *FullName=0;
  for (uint I=0;EnumConfigPaths(I,FullName,MaxSize,Create);I++)
  {
    AddEndSlash(FullName,MaxSize);
    wcsncatz(FullName,Name,MaxSize);
    if (!CheckExist || WildFileExist(FullName))
      break;
  }
}
#endif


// Returns a pointer to rightmost digit of volume number or to beginning
// of file name if numeric part is missing.
wchar* GetVolNumPart(const wchar *ArcName)
{
  if (*ArcName==0)
    return (wchar *)ArcName;

  // Pointing to last name character.
  const wchar *ChPtr=ArcName+wcslen(ArcName)-1;

  // Skipping the archive extension.
  while (!IsDigit(*ChPtr) && ChPtr>ArcName)
    ChPtr--;

  // Skipping the numeric part of name.
  const wchar *NumPtr=ChPtr;
  while (IsDigit(*NumPtr) && NumPtr>ArcName)
    NumPtr--;

  // Searching for first numeric part in names like name.part##of##.rar.
  // Stop search on the first dot.
  while (NumPtr>ArcName && *NumPtr!='.')
  {
    if (IsDigit(*NumPtr))
    {
      // Validate the first numeric part only if it has a dot somewhere 
      // before it.
      wchar *Dot=wcschr(PointToName(ArcName),'.');
      if (Dot!=NULL && Dot<NumPtr)
        ChPtr=NumPtr;
      break;
    }
    NumPtr--;
  }
  return (wchar *)ChPtr;
}


void NextVolumeName(wchar *ArcName,uint MaxLength,bool OldNumbering)
{
  wchar *ChPtr;
  if ((ChPtr=GetExt(ArcName))==NULL)
  {
    wcsncatz(ArcName,L".rar",MaxLength);
    ChPtr=GetExt(ArcName);
  }
  else
    if (ChPtr[1]==0 || wcsicomp(ChPtr,L".exe")==0 || wcsicomp(ChPtr,L".sfx")==0)
      wcsncpyz(ChPtr,L".rar",MaxLength-(ChPtr-ArcName));

  if (ChPtr==NULL || *ChPtr!='.' || ChPtr[1]==0)
  {
    // Normally we shall have some extension here. If we don't, it means
    // the name has no extension and buffer has no free space to append one.
    // Let's clear the name to prevent a new call with same name and return.
    *ArcName=0;
    return;
  }

  if (!OldNumbering)
  {
    ChPtr=GetVolNumPart(ArcName);

    // We should not check for IsDigit(*ChPtr) here and should increment
    // even non-digits. If we got a corrupt archive with volume flag,
    // but without numeric part, we still need to modify its name somehow,
    // so while (exist(name)) {NextVolumeName()} loops do not run infinitely.
    while ((++(*ChPtr))=='9'+1)
    {
      *ChPtr='0';
      ChPtr--;
      if (ChPtr<ArcName || !IsDigit(*ChPtr))
      {
        // Convert .part:.rar (.part9.rar after increment) to part10.rar.
        for (wchar *EndPtr=ArcName+wcslen(ArcName);EndPtr!=ChPtr;EndPtr--)
          *(EndPtr+1)=*EndPtr;
        *(ChPtr+1)='1';
        break;
      }
    }
  }
  else
    if (!IsDigit(ChPtr[2]) || !IsDigit(ChPtr[3]))
      wcsncpyz(ChPtr+2,L"00",MaxLength-(ChPtr-ArcName)-2); // From .rar to .r00.
    else
    {
      ChPtr+=wcslen(ChPtr)-1; // Set to last character.
      while (++(*ChPtr)=='9'+1)
        if (ChPtr<=ArcName || *(ChPtr-1)=='.')
        {
          *ChPtr='a'; // From .999 to .a00 if started from .001 or for too short names.
          break;
        }
        else
        {
          *ChPtr='0';
          ChPtr--;
        }
    }
}


bool IsNameUsable(const wchar *Name)
{
#ifndef _UNIX
  if (Name[0] && Name[1] && wcschr(Name+2,':')!=NULL)
    return false;
  for (const wchar *s=Name;*s!=0;s++)
  {
    if ((uint)*s<32)
      return false;
    if ((*s==' ' || *s=='.') && IsPathDiv(s[1]))
      return false;
  }
#endif
  return *Name!=0 && wcspbrk(Name,L"?*<>|\"")==NULL;
}


void MakeNameUsable(char *Name,bool Extended)
{
#ifdef _WIN_ALL
  // In Windows we also need to convert characters not defined in current
  // code page. This double conversion changes them to '?', which is
  // catched by code below.
  size_t NameLength=strlen(Name);
  wchar NameW[NM];
  CharToWide(Name,NameW,ASIZE(NameW));
  WideToChar(NameW,Name,NameLength+1);
  Name[NameLength]=0;
#endif
  for (char *s=Name;*s!=0;s=charnext(s))
  {
    if (strchr(Extended ? "?*<>|\"":"?*",*s)!=NULL || Extended && (byte)*s<32)
      *s='_';
#ifdef _EMX
    if (*s=='=')
      *s='_';
#endif
#ifndef _UNIX
    if (s-Name>1 && *s==':')
      *s='_';
    // Remove ' ' and '.' before path separator, but allow .\ and ..\.
    if ((*s==' ' || *s=='.' && s>Name && !IsPathDiv(s[-1]) && s[-1]!='.') && IsPathDiv(s[1]))
      *s='_';
#endif
  }
}


void MakeNameUsable(wchar *Name,bool Extended)
{
  for (wchar *s=Name;*s!=0;s++)
  {
    if (wcschr(Extended ? L"?*<>|\"":L"?*",*s)!=NULL || Extended && (uint)*s<32)
      *s='_';
#ifndef _UNIX
    if (s-Name>1 && *s==':')
      *s='_';
#if 0  // We already can create such files.
    // Remove ' ' and '.' before path separator, but allow .\ and ..\.
    if (IsPathDiv(s[1]) && (*s==' ' || *s=='.' && s>Name &&
        !IsPathDiv(s[-1]) && (s[-1]!='.' || s>Name+1 && !IsPathDiv(s[-2]))))
      *s='_';
#endif
#endif
  }
}


void UnixSlashToDos(const char *SrcName,char *DestName,size_t MaxLength)
{
  size_t Copied=0;
  for (;Copied<MaxLength-1 && SrcName[Copied]!=0;Copied++)
    DestName[Copied]=SrcName[Copied]=='/' ? '\\':SrcName[Copied];
  DestName[Copied]=0;
}


void DosSlashToUnix(const char *SrcName,char *DestName,size_t MaxLength)
{
  size_t Copied=0;
  for (;Copied<MaxLength-1 && SrcName[Copied]!=0;Copied++)
    DestName[Copied]=SrcName[Copied]=='\\' ? '/':SrcName[Copied];
  DestName[Copied]=0;
}


void UnixSlashToDos(const wchar *SrcName,wchar *DestName,size_t MaxLength)
{
  size_t Copied=0;
  for (;Copied<MaxLength-1 && SrcName[Copied]!=0;Copied++)
    DestName[Copied]=SrcName[Copied]=='/' ? '\\':SrcName[Copied];
  DestName[Copied]=0;
}


void DosSlashToUnix(const wchar *SrcName,wchar *DestName,size_t MaxLength)
{
  size_t Copied=0;
  for (;Copied<MaxLength-1 && SrcName[Copied]!=0;Copied++)
    DestName[Copied]=SrcName[Copied]=='\\' ? '/':SrcName[Copied];
  DestName[Copied]=0;
}


void ConvertNameToFull(const wchar *Src,wchar *Dest,size_t MaxSize)
{
  if (Src==NULL || *Src==0)
  {
    if (MaxSize>0)
      *Dest=0;
    return;
  }
#ifdef _WIN_ALL
  {
    wchar FullName[NM],*NamePtr;
    DWORD Code=GetFullPathName(Src,ASIZE(FullName),FullName,&NamePtr);
    if (Code==0 || Code>ASIZE(FullName))
    {
      wchar LongName[NM];
      if (GetWinLongPath(Src,LongName,ASIZE(LongName)))
        Code=GetFullPathName(LongName,ASIZE(FullName),FullName,&NamePtr);
    }
    if (Code!=0 && Code<ASIZE(FullName))
      wcsncpyz(Dest,FullName,MaxSize);
    else
      if (Src!=Dest)
        wcsncpyz(Dest,Src,MaxSize);
  }
#elif defined(_UNIX)
  if (IsFullPath(Src))
    *Dest=0;
  else
  {
    char CurDirA[NM];
    if (getcwd(CurDirA,ASIZE(CurDirA))==NULL)
      *CurDirA=0;
    CharToWide(CurDirA,Dest,MaxSize);
    AddEndSlash(Dest,MaxSize);
  }
  wcsncatz(Dest,Src,MaxSize);
#else
  wcsncpyz(Dest,Src,MaxSize);
#endif
}


bool IsFullPath(const wchar *Path)
{
/*
  wchar PathOnly[NM];
  GetFilePath(Path,PathOnly,ASIZE(PathOnly));
  if (IsWildcard(PathOnly))
    return true;
*/
#if defined(_WIN_ALL) || defined(_EMX)
  return Path[0]=='\\' && Path[1]=='\\' || IsDriveLetter(Path) && IsPathDiv(Path[2]);
#else
  return IsPathDiv(Path[0]);
#endif
}


bool IsFullRootPath(const wchar *Path)
{
  return IsFullPath(Path) || IsPathDiv(Path[0]);
}


void GetPathRoot(const wchar *Path,wchar *Root,size_t MaxSize)
{
  *Root=0;
  if (IsDriveLetter(Path))
    swprintf(Root,MaxSize,L"%c:\\",*Path);
  else
    if (Path[0]=='\\' && Path[1]=='\\')
    {
      const wchar *Slash=wcschr(Path+2,'\\');
      if (Slash!=NULL)
      {
        size_t Length;
        if ((Slash=wcschr(Slash+1,'\\'))!=NULL)
          Length=Slash-Path+1;
        else
          Length=wcslen(Path);
        if (Length>=MaxSize)
          Length=0;
        wcsncpy(Root,Path,Length);
        Root[Length]=0;
      }
    }
}


int ParseVersionFileName(wchar *Name,bool Truncate)
{
  int Version=0;
  wchar *VerText=wcsrchr(Name,';');
  if (VerText!=NULL)
  {
    Version=atoiw(VerText+1);
    if (Truncate)
      *VerText=0;
  }
  return Version;
}


#if !defined(SFX_MODULE)
// Get the name of first volume. Return the leftmost digit of volume number.
wchar* VolNameToFirstName(const wchar *VolName,wchar *FirstName,size_t MaxSize,bool NewNumbering)
{
  if (FirstName!=VolName)
    wcsncpyz(FirstName,VolName,MaxSize);
  wchar *VolNumStart=FirstName;
  if (NewNumbering)
  {
    wchar N='1';

    // From the rightmost digit of volume number to the left.
    for (wchar *ChPtr=GetVolNumPart(FirstName);ChPtr>FirstName;ChPtr--)
      if (IsDigit(*ChPtr))
      {
        *ChPtr=N; // Set the rightmost digit to '1' and others to '0'.
        N='0';
      }
      else
        if (N=='0')
        {
          VolNumStart=ChPtr+1; // Store the position of leftmost digit in volume number.
          break;
        }
  }
  else
  {
    // Old volume numbering scheme. Just set the extension to ".rar".
    SetExt(FirstName,L"rar",MaxSize);
    VolNumStart=GetExt(FirstName);
  }
  if (!FileExist(FirstName))
  {
    // If the first volume, which name we just generated, does not exist,
    // check if volume with same name and any other extension is available.
    // It can help in case of *.exe or *.sfx first volume.
    wchar Mask[NM];
    wcsncpyz(Mask,FirstName,ASIZE(Mask));
    SetExt(Mask,L"*",ASIZE(Mask));
    FindFile Find;
    Find.SetMask(Mask);
    FindData FD;
    while (Find.Next(&FD))
    {
      Archive Arc;
      if (Arc.Open(FD.Name,0) && Arc.IsArchive(true) && Arc.FirstVolume)
      {
        wcsncpyz(FirstName,FD.Name,MaxSize);
        break;
      }
    }
  }
  return VolNumStart;
}
#endif


#ifndef SFX_MODULE
static void GenArcName(wchar *ArcName,size_t MaxSize,const wchar *GenerateMask,uint ArcNumber,bool &ArcNumPresent)
{
  bool Prefix=false;
  if (*GenerateMask=='+')
  {
    Prefix=true;    // Add the time string before the archive name.
    GenerateMask++; // Skip '+' in the beginning of time mask.
  }

  wchar Mask[MAX_GENERATE_MASK];
  wcsncpyz(Mask,*GenerateMask!=0 ? GenerateMask:L"yyyymmddhhmmss",ASIZE(Mask));

  bool QuoteMode=false,Hours=false;
  for (uint I=0;Mask[I]!=0;I++)
  {
    if (Mask[I]=='{' || Mask[I]=='}')
    {
      QuoteMode=(Mask[I]=='{');
      continue;
    }
    if (QuoteMode)
      continue;
    int CurChar=toupperw(Mask[I]);
    if (CurChar=='H')
      Hours=true;

    if (Hours && CurChar=='M')
    {
      // Replace minutes with 'I'. We use 'M' both for months and minutes,
      // so we treat as minutes only those 'M' which are found after hours.
      Mask[I]='I';
    }
    if (CurChar=='N')
    {
      uint Digits=GetDigits(ArcNumber);
      uint NCount=0;
      while (toupperw(Mask[I+NCount])=='N')
        NCount++;

      // Here we ensure that we have enough 'N' characters to fit all digits
      // of archive number. We'll replace them by actual number later
      // in this function.
      if (NCount<Digits)
      {
        wmemmove(Mask+I+Digits,Mask+I+NCount,wcslen(Mask+I+NCount)+1);
        wmemset(Mask+I,'N',Digits);
      }
      I+=Max(Digits,NCount)-1;
      ArcNumPresent=true;
      continue;
    }
  }

  RarTime CurTime;
  CurTime.SetCurrentTime();
  RarLocalTime rlt;
  CurTime.GetLocal(&rlt);

  wchar Ext[NM],*Dot=GetExt(ArcName);
  *Ext=0;
  if (Dot==NULL)
    wcsncpyz(Ext,*PointToName(ArcName)==0 ? L".rar":L"",ASIZE(Ext));
  else
  {
    wcsncpyz(Ext,Dot,ASIZE(Ext));
    *Dot=0;
  }

  int WeekDay=rlt.wDay==0 ? 6:rlt.wDay-1;
  int StartWeekDay=rlt.yDay-WeekDay;
  if (StartWeekDay<0)
    if (StartWeekDay<=-4)
      StartWeekDay+=IsLeapYear(rlt.Year-1) ? 366:365;
    else
      StartWeekDay=0;
  int CurWeek=StartWeekDay/7+1;
  if (StartWeekDay%7>=4)
    CurWeek++;

  char Field[10][6];

  sprintf(Field[0],"%04u",rlt.Year);
  sprintf(Field[1],"%02u",rlt.Month);
  sprintf(Field[2],"%02u",rlt.Day);
  sprintf(Field[3],"%02u",rlt.Hour);
  sprintf(Field[4],"%02u",rlt.Minute);
  sprintf(Field[5],"%02u",rlt.Second);
  sprintf(Field[6],"%02u",(uint)CurWeek);
  sprintf(Field[7],"%u",(uint)WeekDay+1);
  sprintf(Field[8],"%03u",rlt.yDay+1);
  sprintf(Field[9],"%05u",ArcNumber);

  const wchar *MaskChars=L"YMDHISWAEN";

  int CField[sizeof(Field)/sizeof(Field[0])];
  memset(CField,0,sizeof(CField));
  QuoteMode=false;
  for (uint I=0;Mask[I]!=0;I++)
  {
    if (Mask[I]=='{' || Mask[I]=='}')
    {
      QuoteMode=(Mask[I]=='{');
      continue;
    }
    if (QuoteMode)
      continue;
    const wchar *ChPtr=wcschr(MaskChars,toupperw(Mask[I]));
    if (ChPtr!=NULL)
      CField[ChPtr-MaskChars]++;
   }

  wchar DateText[MAX_GENERATE_MASK];
  *DateText=0;
  QuoteMode=false;
  for (size_t I=0,J=0;Mask[I]!=0 && J<ASIZE(DateText)-1;I++)
  {
    if (Mask[I]=='{' || Mask[I]=='}')
    {
      QuoteMode=(Mask[I]=='{');
      continue;
    }
    const wchar *ChPtr=wcschr(MaskChars,toupperw(Mask[I]));
    if (ChPtr==NULL || QuoteMode)
    {
      DateText[J]=Mask[I];
#ifdef _WIN_ALL
      // We do not allow ':' in Windows because of NTFS streams.
      // Users had problems after specifying hh:mm mask.
      if (DateText[J]==':')
        DateText[J]='_';
#endif
    }
    else
    {
      size_t FieldPos=ChPtr-MaskChars;
      int CharPos=(int)strlen(Field[FieldPos])-CField[FieldPos]--;
      if (FieldPos==1 && toupperw(Mask[I+1])=='M' && toupperw(Mask[I+2])=='M')
      {
        wcsncpyz(DateText+J,GetMonthName(rlt.Month-1),ASIZE(DateText)-J);
        J=wcslen(DateText);
        I+=2;
        continue;
      }
      if (CharPos<0)
        DateText[J]=Mask[I];
      else
        DateText[J]=Field[FieldPos][CharPos];
    }
    DateText[++J]=0;
  }

  if (Prefix)
  {
    wchar NewName[NM];
    GetFilePath(ArcName,NewName,ASIZE(NewName));
    AddEndSlash(NewName,ASIZE(NewName));
    wcsncatz(NewName,DateText,ASIZE(NewName));
    wcsncatz(NewName,PointToName(ArcName),ASIZE(NewName));
    wcsncpyz(ArcName,NewName,MaxSize);
  }
  else
    wcsncatz(ArcName,DateText,MaxSize);
  wcsncatz(ArcName,Ext,MaxSize);
}


void GenerateArchiveName(wchar *ArcName,size_t MaxSize,const wchar *GenerateMask,bool Archiving)
{
  wchar NewName[NM];

  uint ArcNumber=1;
  while (true) // Loop for 'N' (archive number) processing.
  {
    wcsncpyz(NewName,ArcName,ASIZE(NewName));
    
    bool ArcNumPresent=false;

    GenArcName(NewName,ASIZE(NewName),GenerateMask,ArcNumber,ArcNumPresent);
    
    if (!ArcNumPresent)
      break;
    if (!FileExist(NewName))
    {
      if (!Archiving && ArcNumber>1)
      {
        // If we perform non-archiving operation, we need to use the last
        // existing archive before the first unused name. So we generate
        // the name for (ArcNumber-1) below.
        wcsncpyz(NewName,NullToEmpty(ArcName),ASIZE(NewName));
        GenArcName(NewName,ASIZE(NewName),GenerateMask,ArcNumber-1,ArcNumPresent);
      }
      break;
    }
    ArcNumber++;
  }
  wcsncpyz(ArcName,NewName,MaxSize);
}
#endif


wchar* GetWideName(const char *Name,const wchar *NameW,wchar *DestW,size_t DestSize)
{
  if (NameW!=NULL && *NameW!=0)
  {
    if (DestW!=NameW)
      wcsncpy(DestW,NameW,DestSize);
  }
  else
    if (Name!=NULL)
      CharToWide(Name,DestW,DestSize);
    else
      *DestW=0;

  // Ensure that we return a zero terminate string for security reasons.
  if (DestSize>0)
    DestW[DestSize-1]=0;

  return DestW;
}


#ifdef _WIN_ALL
// We should return 'true' even if resulting path is shorter than MAX_PATH,
// because we can also use this function to open files with non-standard
// characters, even if their path length is normal.
bool GetWinLongPath(const wchar *Src,wchar *Dest,size_t MaxSize)
{
  if (*Src==0)
    return false;
  const wchar *Prefix=L"\\\\?\\";
  const size_t PrefixLength=4;
  bool FullPath=IsDriveLetter(Src) && IsPathDiv(Src[2]);
  size_t SrcLength=wcslen(Src);
  if (IsFullPath(Src)) // Paths in d:\path\name format.
  {
    if (IsDriveLetter(Src))
    {
      if (MaxSize<=PrefixLength+SrcLength)
        return false;
      wcsncpyz(Dest,Prefix,MaxSize);
      wcsncatz(Dest,Src,MaxSize); // "\\?\D:\very long path".
      return true;
    }
    else
      if (Src[0]=='\\' && Src[1]=='\\')
      {
        if (MaxSize<=PrefixLength+SrcLength+2)
          return false;
        wcsncpyz(Dest,Prefix,MaxSize);
        wcsncatz(Dest,L"UNC",MaxSize);
        wcsncatz(Dest,Src+1,MaxSize); // "\\?\UNC\server\share".
        return true;
      }
    // We may be here only if we modify IsFullPath in the future.
    return false;
  }
  else
  {
    wchar CurDir[NM];
    DWORD DirCode=GetCurrentDirectory(ASIZE(CurDir)-1,CurDir);
    if (DirCode==0 || DirCode>ASIZE(CurDir)-1)
      return false;

    if (IsPathDiv(Src[0])) // Paths in \path\name format.
    {
      if (MaxSize<=PrefixLength+SrcLength+2)
        return false;
      wcsncpyz(Dest,Prefix,MaxSize);
      CurDir[2]=0;
      wcsncatz(Dest,CurDir,MaxSize); // Copy drive letter 'd:'.
      wcsncatz(Dest,Src,MaxSize);
      return true;
    }
    else  // Paths in path\name format.
    {
      AddEndSlash(CurDir,ASIZE(CurDir));
      if (MaxSize<=PrefixLength+wcslen(CurDir)+SrcLength)
        return false;
      wcsncpyz(Dest,Prefix,MaxSize);
      wcsncatz(Dest,CurDir,MaxSize);

      if (Src[0]=='.' && IsPathDiv(Src[1])) // Remove leading .\ in pathname.
        Src+=2;

      wcsncatz(Dest,Src,MaxSize);
      return true;
    }
  }
  return false;
}


// Convert Unix, OS X and Android decomposed chracters to Windows precomposed.
void ConvertToPrecomposed(wchar *Name,size_t NameSize)
{
  wchar FileName[NM];
  if (WinNT()>=WNT_VISTA && // MAP_PRECOMPOSED is not supported in XP.
      FoldString(MAP_PRECOMPOSED,Name,-1,FileName,ASIZE(FileName))!=0)
  {
    FileName[ASIZE(FileName)-1]=0;
    wcsncpyz(Name,FileName,NameSize);
  }
}


// Remove trailing spaces and dots in file name and in dir names in path.
void MakeNameCompatible(wchar *Name)
{
  int Src=0,Dest=0;
  while (true)
  {
    if (IsPathDiv(Name[Src]) || Name[Src]==0)
      for (int I=Dest-1;I>0 && (Name[I]==' ' || Name[I]=='.');I--)
      {
        // Permit path1/./path2 and ../path1 paths.
        if (Name[I]=='.' && (IsPathDiv(Name[I-1]) || Name[I-1]=='.' && I==1))
          break;
        Dest--;
      }
    Name[Dest]=Name[Src];
    if (Name[Src]==0)
      break;
    Src++;
    Dest++;
  }
}
#endif

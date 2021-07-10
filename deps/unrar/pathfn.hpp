#ifndef _RAR_PATHFN_
#define _RAR_PATHFN_

wchar* PointToName(const wchar *Path);
wchar* PointToLastChar(const wchar *Path);
wchar* ConvertPath(const wchar *SrcPath,wchar *DestPath,size_t DestSize);
void SetName(wchar *FullName,const wchar *Name,size_t MaxSize);
void SetExt(wchar *Name,const wchar *NewExt,size_t MaxSize);
void SetSFXExt(wchar *SFXName,size_t MaxSize);
wchar *GetExt(const wchar *Name);
bool CmpExt(const wchar *Name,const wchar *Ext);
bool IsWildcard(const wchar *Str);
bool IsPathDiv(int Ch);
bool IsDriveDiv(int Ch);
bool IsDriveLetter(const wchar *Path);
int GetPathDisk(const wchar *Path);
void AddEndSlash(wchar *Path,size_t MaxLength);
void MakeName(const wchar *Path,const wchar *Name,wchar *Pathname,size_t MaxSize);
void GetFilePath(const wchar *FullName,wchar *Path,size_t MaxLength);
void RemoveNameFromPath(wchar *Path);
#if defined(_WIN_ALL) && !defined(SFX_MODULE)
bool GetAppDataPath(wchar *Path,size_t MaxSize,bool Create);
void GetRarDataPath(wchar *Path,size_t MaxSize,bool Create);
#endif
#ifndef SFX_MODULE
bool EnumConfigPaths(uint Number,wchar *Path,size_t MaxSize,bool Create);
void GetConfigName(const wchar *Name,wchar *FullName,size_t MaxSize,bool CheckExist,bool Create);
#endif
wchar* GetVolNumPart(const wchar *ArcName);
void NextVolumeName(wchar *ArcName,uint MaxLength,bool OldNumbering);
bool IsNameUsable(const wchar *Name);
void MakeNameUsable(char *Name,bool Extended);
void MakeNameUsable(wchar *Name,bool Extended);

void UnixSlashToDos(const char *SrcName,char *DestName,size_t MaxLength);
void DosSlashToUnix(const char *SrcName,char *DestName,size_t MaxLength);
void UnixSlashToDos(const wchar *SrcName,wchar *DestName,size_t MaxLength);
void DosSlashToUnix(const wchar *SrcName,wchar *DestName,size_t MaxLength);

inline void SlashToNative(const char *SrcName,char *DestName,size_t MaxLength)
{
#ifdef _WIN_ALL
  UnixSlashToDos(SrcName,DestName,MaxLength);
#else
  DosSlashToUnix(SrcName,DestName,MaxLength);
#endif
}

inline void SlashToNative(const wchar *SrcName,wchar *DestName,size_t MaxLength)
{
#ifdef _WIN_ALL
  UnixSlashToDos(SrcName,DestName,MaxLength);
#else
  DosSlashToUnix(SrcName,DestName,MaxLength);
#endif
}

void ConvertNameToFull(const wchar *Src,wchar *Dest,size_t MaxSize);
bool IsFullPath(const wchar *Path);
bool IsFullRootPath(const wchar *Path);
void GetPathRoot(const wchar *Path,wchar *Root,size_t MaxSize);
int ParseVersionFileName(wchar *Name,bool Truncate);
wchar* VolNameToFirstName(const wchar *VolName,wchar *FirstName,size_t MaxSize,bool NewNumbering);
wchar* GetWideName(const char *Name,const wchar *NameW,wchar *DestW,size_t DestSize);

#ifndef SFX_MODULE
void GenerateArchiveName(wchar *ArcName,size_t MaxSize,const wchar *GenerateMask,bool Archiving);
#endif

#ifdef _WIN_ALL
bool GetWinLongPath(const wchar *Src,wchar *Dest,size_t MaxSize);
void ConvertToPrecomposed(wchar *Name,size_t NameSize);
void MakeNameCompatible(wchar *Name);
#endif

#endif

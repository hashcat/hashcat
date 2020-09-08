#include "rar.hpp"

FindFile::FindFile()
{
  *FindMask=0;
  FirstCall=true;
#ifdef _WIN_ALL
  hFind=INVALID_HANDLE_VALUE;
#else
  dirp=NULL;
#endif
}


FindFile::~FindFile()
{
#ifdef _WIN_ALL
  if (hFind!=INVALID_HANDLE_VALUE)
    FindClose(hFind);
#else
  if (dirp!=NULL)
    closedir(dirp);
#endif
}


void FindFile::SetMask(const wchar *Mask)
{
  wcsncpyz(FindMask,Mask,ASIZE(FindMask));
  FirstCall=true;
}


bool FindFile::Next(FindData *fd,bool GetSymLink)
{
  fd->Error=false;
  if (*FindMask==0)
    return false;
#ifdef _WIN_ALL
  if (FirstCall)
  {
    if ((hFind=Win32Find(INVALID_HANDLE_VALUE,FindMask,fd))==INVALID_HANDLE_VALUE)
      return false;
  }
  else
    if (Win32Find(hFind,FindMask,fd)==INVALID_HANDLE_VALUE)
      return false;
#else
  if (FirstCall)
  {
    wchar DirName[NM];
    wcsncpyz(DirName,FindMask,ASIZE(DirName));
    RemoveNameFromPath(DirName);
    if (*DirName==0)
      wcsncpyz(DirName,L".",ASIZE(DirName));
    char DirNameA[NM];
    WideToChar(DirName,DirNameA,ASIZE(DirNameA));
    if ((dirp=opendir(DirNameA))==NULL)
    {
      fd->Error=(errno!=ENOENT);
      return false;
    }
  }
  while (1)
  {
    wchar Name[NM];
    struct dirent *ent=readdir(dirp);
    if (ent==NULL)
      return false;
    if (strcmp(ent->d_name,".")==0 || strcmp(ent->d_name,"..")==0)
      continue;
    if (!CharToWide(ent->d_name,Name,ASIZE(Name)))
      uiMsg(UIERROR_INVALIDNAME,UINULL,Name);

    if (CmpName(FindMask,Name,MATCH_NAMES))
    {
      wchar FullName[NM];
      wcsncpyz(FullName,FindMask,ASIZE(FullName));
      *PointToName(FullName)=0;
      if (wcslen(FullName)+wcslen(Name)>=ASIZE(FullName)-1)
      {
        uiMsg(UIERROR_PATHTOOLONG,FullName,L"",Name);
        return false;
      }
      wcsncatz(FullName,Name,ASIZE(FullName));
      if (!FastFind(FullName,fd,GetSymLink))
      {
        ErrHandler.OpenErrorMsg(FullName);
        continue;
      }
      wcsncpyz(fd->Name,FullName,ASIZE(fd->Name));
      break;
    }
  }
#endif
  fd->Flags=0;
  fd->IsDir=IsDir(fd->FileAttr);
  fd->IsLink=IsLink(fd->FileAttr);

  FirstCall=false;
  wchar *NameOnly=PointToName(fd->Name);
  if (wcscmp(NameOnly,L".")==0 || wcscmp(NameOnly,L"..")==0)
    return Next(fd);
  return true;
}


bool FindFile::FastFind(const wchar *FindMask,FindData *fd,bool GetSymLink)
{
  fd->Error=false;
#ifndef _UNIX
  if (IsWildcard(FindMask))
    return false;
#endif    
#ifdef _WIN_ALL
  HANDLE hFind=Win32Find(INVALID_HANDLE_VALUE,FindMask,fd);
  if (hFind==INVALID_HANDLE_VALUE)
    return false;
  FindClose(hFind);
#else
  char FindMaskA[NM];
  WideToChar(FindMask,FindMaskA,ASIZE(FindMaskA));

  struct stat st;
  if (GetSymLink)
  {
#ifdef SAVE_LINKS
    if (lstat(FindMaskA,&st)!=0)
#else
    if (stat(FindMaskA,&st)!=0)
#endif
    {
      fd->Error=(errno!=ENOENT);
      return false;
    }
  }
  else
    if (stat(FindMaskA,&st)!=0)
    {
      fd->Error=(errno!=ENOENT);
      return false;
    }
  fd->FileAttr=st.st_mode;
  fd->Size=st.st_size;

#ifdef UNIX_TIME_NS
  fd->mtime.SetUnixNS(st.st_mtim.tv_sec*(uint64)1000000000+st.st_mtim.tv_nsec);
  fd->atime.SetUnixNS(st.st_atim.tv_sec*(uint64)1000000000+st.st_atim.tv_nsec);
  fd->ctime.SetUnixNS(st.st_ctim.tv_sec*(uint64)1000000000+st.st_ctim.tv_nsec);
#else
  fd->mtime.SetUnix(st.st_mtime);
  fd->atime.SetUnix(st.st_atime);
  fd->ctime.SetUnix(st.st_ctime);
#endif

  wcsncpyz(fd->Name,FindMask,ASIZE(fd->Name));
#endif
  fd->Flags=0;
  fd->IsDir=IsDir(fd->FileAttr);
  fd->IsLink=IsLink(fd->FileAttr);

  return true;
}


#ifdef _WIN_ALL
HANDLE FindFile::Win32Find(HANDLE hFind,const wchar *Mask,FindData *fd)
{
  WIN32_FIND_DATA FindData;
  if (hFind==INVALID_HANDLE_VALUE)
  {
    hFind=FindFirstFile(Mask,&FindData);
    if (hFind==INVALID_HANDLE_VALUE)
    {
      wchar LongMask[NM];
      if (GetWinLongPath(Mask,LongMask,ASIZE(LongMask)))
        hFind=FindFirstFile(LongMask,&FindData);
    }
    if (hFind==INVALID_HANDLE_VALUE)
    {
      int SysErr=GetLastError();
      // We must not issue an error for "file not found" and "path not found",
      // because it is normal to not find anything for wildcard mask when
      // archiving. Also searching for non-existent file is normal in some
      // other modules, like WinRAR scanning for winrar_theme_description.txt
      // to check if any themes are available.
      fd->Error=SysErr!=ERROR_FILE_NOT_FOUND && 
                SysErr!=ERROR_PATH_NOT_FOUND &&
                SysErr!=ERROR_NO_MORE_FILES;
    }
  }
  else
    if (!FindNextFile(hFind,&FindData))
    {
      hFind=INVALID_HANDLE_VALUE;
      fd->Error=GetLastError()!=ERROR_NO_MORE_FILES;
    }

  if (hFind!=INVALID_HANDLE_VALUE)
  {
    wcsncpyz(fd->Name,Mask,ASIZE(fd->Name));
    SetName(fd->Name,FindData.cFileName,ASIZE(fd->Name));
    fd->Size=INT32TO64(FindData.nFileSizeHigh,FindData.nFileSizeLow);
    fd->FileAttr=FindData.dwFileAttributes;
    fd->ftCreationTime=FindData.ftCreationTime;
    fd->ftLastAccessTime=FindData.ftLastAccessTime;
    fd->ftLastWriteTime=FindData.ftLastWriteTime;
    fd->mtime.SetWinFT(&FindData.ftLastWriteTime);
    fd->ctime.SetWinFT(&FindData.ftCreationTime);
    fd->atime.SetWinFT(&FindData.ftLastAccessTime);


  }
  fd->Flags=0;
  return hFind;
}
#endif


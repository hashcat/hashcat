

static bool UnixSymlink(CommandData *Cmd,const char *Target,const wchar *LinkName,RarTime *ftm,RarTime *fta)
{
  CreatePath(LinkName,true,Cmd->DisableNames);

  // Overwrite prompt was already issued and confirmed earlier, so we can
  // remove existing symlink or regular file here. PrepareToDelete was also
  // called earlier inside of uiAskReplaceEx.
  DelFile(LinkName);

  char LinkNameA[NM];
  WideToChar(LinkName,LinkNameA,ASIZE(LinkNameA));
  if (symlink(Target,LinkNameA)==-1) // Error.
  {
    if (errno==EEXIST)
      uiMsg(UIERROR_ULINKEXIST,LinkName);
    else
    {
      uiMsg(UIERROR_SLINKCREATE,UINULL,LinkName);
      ErrHandler.SetErrorCode(RARX_WARNING);
    }
    return false;
  }
#ifdef USE_LUTIMES
#ifdef UNIX_TIME_NS
  timespec times[2];
  times[0].tv_sec=fta->GetUnix();
  times[0].tv_nsec=fta->IsSet() ? long(fta->GetUnixNS()%1000000000) : UTIME_NOW;
  times[1].tv_sec=ftm->GetUnix();
  times[1].tv_nsec=ftm->IsSet() ? long(ftm->GetUnixNS()%1000000000) : UTIME_NOW;
  utimensat(AT_FDCWD,LinkNameA,times,AT_SYMLINK_NOFOLLOW);
#else
  struct timeval tv[2];
  tv[0].tv_sec=fta->GetUnix();
  tv[0].tv_usec=long(fta->GetUnixNS()%1000000000/1000);
  tv[1].tv_sec=ftm->GetUnix();
  tv[1].tv_usec=long(ftm->GetUnixNS()%1000000000/1000);
  lutimes(LinkNameA,tv);
#endif
#endif

  return true;
}


static bool IsFullPath(const char *PathA) // Unix ASCII version.
{
  return *PathA==CPATHDIVIDER;
}


// For security purpose we prefer to be sure that CharToWide completed
// successfully and even if it truncated a string for some reason,
// it didn't affect the number of path related characters we analyze
// in IsRelativeSymlinkSafe later.
// This check is likely to be excessive, but let's keep it anyway.
static bool SafeCharToWide(const char *Src,wchar *Dest,size_t DestSize)
{
  if (!CharToWide(Src,Dest,DestSize) || *Dest==0)
    return false;
  uint SrcChars=0,DestChars=0;
  for (uint I=0;Src[I]!=0;I++)
    if (Src[I]=='/' || Src[I]=='.')
      SrcChars++;
  for (uint I=0;Dest[I]!=0;I++)
    if (Dest[I]=='/' || Dest[I]=='.')
      DestChars++;
  return SrcChars==DestChars;
}


static bool ExtractUnixLink30(CommandData *Cmd,ComprDataIO &DataIO,Archive &Arc,
                              const wchar *LinkName,bool &UpLink)
{
  char Target[NM];
  if (IsLink(Arc.FileHead.FileAttr))
  {
    size_t DataSize=(size_t)Arc.FileHead.PackSize;
    if (DataSize>ASIZE(Target)-1)
      return false;
    if ((size_t)DataIO.UnpRead((byte *)Target,DataSize)!=DataSize)
      return false;
    Target[DataSize]=0;

    DataIO.UnpHash.Init(Arc.FileHead.FileHash.Type,1);
    DataIO.UnpHash.Update(Target,strlen(Target));
    DataIO.UnpHash.Result(&Arc.FileHead.FileHash);

    // Return true in case of bad checksum, so link will be processed further
    // and extraction routine will report the checksum error.
    if (!DataIO.UnpHash.Cmp(&Arc.FileHead.FileHash,Arc.FileHead.UseHashKey ? Arc.FileHead.HashKey:NULL))
      return true;

    wchar TargetW[NM];
    if (!SafeCharToWide(Target,TargetW,ASIZE(TargetW)))
      return false;
    // Use Arc.FileHead.FileName instead of LinkName, since LinkName
    // can include the destination path as a prefix, which can
    // confuse IsRelativeSymlinkSafe algorithm.
    if (!Cmd->AbsoluteLinks && (IsFullPath(TargetW) ||
        !IsRelativeSymlinkSafe(Cmd,Arc.FileHead.FileName,LinkName,TargetW)))
      return false;
    UpLink=strstr(Target,"..")!=NULL;
    return UnixSymlink(Cmd,Target,LinkName,&Arc.FileHead.mtime,&Arc.FileHead.atime);
  }
  return false;
}


static bool ExtractUnixLink50(CommandData *Cmd,const wchar *Name,FileHeader *hd)
{
  char Target[NM];
  WideToChar(hd->RedirName,Target,ASIZE(Target));
  if (hd->RedirType==FSREDIR_WINSYMLINK || hd->RedirType==FSREDIR_JUNCTION)
  {
    // Cannot create Windows absolute path symlinks in Unix. Only relative path
    // Windows symlinks can be created here. RAR 5.0 used \??\ prefix
    // for Windows absolute symlinks, since RAR 5.1 /??/ is used.
    // We escape ? as \? to avoid "trigraph" warning
    if (strncmp(Target,"\\??\\",4)==0 || strncmp(Target,"/\?\?/",4)==0)
      return false;
    DosSlashToUnix(Target,Target,ASIZE(Target));
  }

  wchar TargetW[NM];
  if (!SafeCharToWide(Target,TargetW,ASIZE(TargetW)))
    return false;
  // Use hd->FileName instead of LinkName, since LinkName can include
  // the destination path as a prefix, which can confuse
  // IsRelativeSymlinkSafe algorithm.
  if (!Cmd->AbsoluteLinks && (IsFullPath(TargetW) ||
      !IsRelativeSymlinkSafe(Cmd,hd->FileName,Name,TargetW)))
    return false;
  return UnixSymlink(Cmd,Target,Name,&hd->mtime,&hd->atime);
}

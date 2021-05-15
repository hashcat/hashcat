#include "rar.hpp"

// If NewFile==NULL, we delete created file after user confirmation.
// It is useful we we need to overwrite an existing folder or file,
// but need user confirmation for that.
bool FileCreate(RAROptions *Cmd,File *NewFile,wchar *Name,size_t MaxNameSize,
                bool *UserReject,int64 FileSize,RarTime *FileTime,bool WriteOnly)
{
  if (UserReject!=NULL)
    *UserReject=false;
#ifdef _WIN_ALL
  bool ShortNameChanged=false;
#endif
  while (FileExist(Name))
  {
#if defined(_WIN_ALL)
    if (!ShortNameChanged)
    {
      // Avoid the infinite loop if UpdateExistingShortName returns
      // the same name.
      ShortNameChanged=true;

      // Maybe our long name matches the short name of existing file.
      // Let's check if we can change the short name.
      if (UpdateExistingShortName(Name))
        continue;
    }
    // Allow short name check again. It is necessary, because rename and
    // autorename below can change the name, so we need to check it again.
    ShortNameChanged=false;
#endif
    UIASKREP_RESULT Choice=uiAskReplaceEx(Cmd,Name,MaxNameSize,FileSize,FileTime,(NewFile==NULL ? UIASKREP_F_NORENAME:0));

    if (Choice==UIASKREP_R_REPLACE)
      break;
    if (Choice==UIASKREP_R_SKIP)
    {
      if (UserReject!=NULL)
        *UserReject=true;
      return false;
    }
    if (Choice==UIASKREP_R_CANCEL)
      ErrHandler.Exit(RARX_USERBREAK);
  }

  // Try to truncate the existing file first instead of delete,
  // so we preserve existing file permissions such as NTFS permissions.
  uint FileMode=WriteOnly ? FMF_WRITE|FMF_SHAREREAD:FMF_UPDATE|FMF_SHAREREAD;
  if (NewFile!=NULL && NewFile->Create(Name,FileMode))
    return true;

  CreatePath(Name,true,Cmd->DisableNames);
  return NewFile!=NULL ? NewFile->Create(Name,FileMode):DelFile(Name);
}


bool GetAutoRenamedName(wchar *Name,size_t MaxNameSize)
{
  wchar NewName[NM];
  size_t NameLength=wcslen(Name);
  wchar *Ext=GetExt(Name);
  if (Ext==NULL)
    Ext=Name+NameLength;
  for (uint FileVer=1;;FileVer++)
  {
    swprintf(NewName,ASIZE(NewName),L"%.*ls(%u)%ls",uint(Ext-Name),Name,FileVer,Ext);
    if (!FileExist(NewName))
    {
      wcsncpyz(Name,NewName,MaxNameSize);
      break;
    }
    if (FileVer>=1000000)
      return false;
  }
  return true;
}


#if defined(_WIN_ALL)
// If we find a file, which short name is equal to 'Name', we try to change
// its short name, while preserving the long name. It helps when unpacking
// an archived file, which long name is equal to short name of already
// existing file. Otherwise we would overwrite the already existing file,
// even though its long name does not match the name of unpacking file.
bool UpdateExistingShortName(const wchar *Name)
{
  wchar LongPathName[NM];
  DWORD Res=GetLongPathName(Name,LongPathName,ASIZE(LongPathName));
  if (Res==0 || Res>=ASIZE(LongPathName))
    return false;
  wchar ShortPathName[NM];
  Res=GetShortPathName(Name,ShortPathName,ASIZE(ShortPathName));
  if (Res==0 || Res>=ASIZE(ShortPathName))
    return false;
  wchar *LongName=PointToName(LongPathName);
  wchar *ShortName=PointToName(ShortPathName);

  // We continue only if file has a short name, which does not match its
  // long name, and this short name is equal to name of file which we need
  // to create.
  if (*ShortName==0 || wcsicomp(LongName,ShortName)==0 ||
      wcsicomp(PointToName(Name),ShortName)!=0)
    return false;

  // Generate the temporary new name for existing file.
  wchar NewName[NM];
  *NewName=0;
  for (int I=0;I<10000 && *NewName==0;I+=123)
  {
    // Here we copy the path part of file to create. We'll make the temporary
    // file in the same folder.
    wcsncpyz(NewName,Name,ASIZE(NewName));

    // Here we set the random name part.
    swprintf(PointToName(NewName),ASIZE(NewName),L"rtmp%d",I);
    
    // If such file is already exist, try next random name.
    if (FileExist(NewName))
      *NewName=0;
  }

  // If we could not generate the name not used by any other file, we return.
  if (*NewName==0)
    return false;
  
  // FastFind returns the name without path, but we need the fully qualified
  // name for renaming, so we use the path from file to create and long name
  // from existing file.
  wchar FullName[NM];
  wcsncpyz(FullName,Name,ASIZE(FullName));
  SetName(FullName,LongName,ASIZE(FullName));
  
  // Rename the existing file to randomly generated name. Normally it changes
  // the short name too.
  if (!MoveFile(FullName,NewName))
    return false;

  // Now we need to create the temporary empty file with same name as
  // short name of our already existing file. We do it to occupy its previous
  // short name and not allow to use it again when renaming the file back to
  // its original long name.
  File KeepShortFile;
  bool Created=false;
  if (!FileExist(Name))
    Created=KeepShortFile.Create(Name,FMF_WRITE|FMF_SHAREREAD);

  // Now we rename the existing file from temporary name to original long name.
  // Since its previous short name is occupied by another file, it should
  // get another short name.
  MoveFile(NewName,FullName);

  if (Created)
  {
    // Delete the temporary zero length file occupying the short name,
    KeepShortFile.Close();
    KeepShortFile.Delete();
  }
  // We successfully changed the short name. Maybe sometimes we'll simplify
  // this function by use of SetFileShortName Windows API call.
  // But SetFileShortName is not available in older Windows.
  return true;
}
#endif

// Return 'true' if we need to exclude the file from processing as result
// of -x switch. If CheckInclList is true, we also check the file against
// the include list created with -n switch.
bool CommandData::ExclCheck(const wchar *CheckName,bool Dir,bool CheckFullPath,bool CheckInclList)
{
  if (CheckArgs(&ExclArgs,Dir,CheckName,CheckFullPath,MATCH_WILDSUBPATH))
    return true;
  if (!CheckInclList || InclArgs.ItemsCount()==0)
    return false;
  if (CheckArgs(&InclArgs,Dir,CheckName,CheckFullPath,MATCH_WILDSUBPATH))
    return false;
  return true;
}


bool CommandData::CheckArgs(StringList *Args,bool Dir,const wchar *CheckName,bool CheckFullPath,int MatchMode)
{
  wchar *Name=ConvertPath(CheckName,NULL,0);
  wchar FullName[NM];
  wchar CurMask[NM];
  *FullName=0;
  Args->Rewind();
  while (Args->GetString(CurMask,ASIZE(CurMask)))
  {
    wchar *LastMaskChar=PointToLastChar(CurMask);
    bool DirMask=IsPathDiv(*LastMaskChar); // Mask for directories only.

    if (Dir)
    {
      // CheckName is a directory.
      if (DirMask)
      {
        // We process the directory and have the directory exclusion mask.
        // So let's convert "mask\" to "mask" and process it normally.
        
        *LastMaskChar=0;
      }
      else
      {
        // REMOVED, we want -npath\* to match empty folders too.
        // If mask has wildcards in name part and does not have the trailing
        // '\' character, we cannot use it for directories.
      
        // if (IsWildcard(PointToName(CurMask)))
        //  continue;
      }
    }
    else
    {
      // If we process a file inside of directory excluded by "dirmask\".
      // we want to exclude such file too. So we convert "dirmask\" to
      // "dirmask\*". It is important for operations other than archiving
      // with -x. When archiving with -x, directory matched by "dirmask\"
      // is excluded from further scanning.

      if (DirMask)
        wcsncatz(CurMask,L"*",ASIZE(CurMask));
    }

#ifndef SFX_MODULE
    if (CheckFullPath && IsFullPath(CurMask))
    {
      // We do not need to do the special "*\" processing here, because
      // unlike the "else" part of this "if", now we convert names to full
      // format, so they all include the path, which is matched by "*\"
      // correctly. Moreover, removing "*\" from mask would break
      // the comparison, because now all names have the path.

      if (*FullName==0)
        ConvertNameToFull(CheckName,FullName,ASIZE(FullName));
      if (CmpName(CurMask,FullName,MatchMode))
        return true;
    }
    else
#endif
    {
      wchar NewName[NM+2],*CurName=Name;

      // Important to convert before "*\" check below, so masks like
      // d:*\something are processed properly.
      wchar *CmpMask=ConvertPath(CurMask,NULL,0);

      if (CmpMask[0]=='*' && IsPathDiv(CmpMask[1]))
      {
        // We want "*\name" to match 'name' not only in subdirectories,
        // but also in the current directory. We convert the name
        // from 'name' to '.\name' to be matched by "*\" part even if it is
        // in current directory.
        NewName[0]='.';
        NewName[1]=CPATHDIVIDER;
        wcsncpyz(NewName+2,Name,ASIZE(NewName)-2);
        CurName=NewName;
      }

      if (CmpName(CmpMask,CurName,MatchMode))
        return true;
    }
  }
  return false;
}




#ifndef SFX_MODULE
// Now this function performs only one task and only in Windows version:
// it skips symlinks to directories if -e1024 switch is specified.
// Symlinks are skipped in ScanTree class, so their entire contents
// is skipped too. Without this function we would check the attribute
// only directly before archiving, so we would skip the symlink record,
// but not the contents of symlinked directory.
bool CommandData::ExclDirByAttr(uint FileAttr)
{
#ifdef _WIN_ALL
  if ((FileAttr & FILE_ATTRIBUTE_REPARSE_POINT)!=0 &&
      (ExclFileAttr & FILE_ATTRIBUTE_REPARSE_POINT)!=0)
    return true;
#endif
  return false;
}
#endif




#if !defined(SFX_MODULE)
void CommandData::SetTimeFilters(const wchar *Mod,bool Before,bool Age)
{
  bool ModeOR=false,TimeMods=false;
  const wchar *S=Mod;
  // Check if any 'mca' modifiers are present, set OR mode if 'o' is present,
  // skip modifiers and set S to beginning of time string. Be sure to check
  // *S!=0, because termination 0 is a part of string for wcschr.
  for (;*S!=0 && wcschr(L"MCAOmcao",*S)!=NULL;S++)
    if (*S=='o' || *S=='O')
      ModeOR=true;
    else
      TimeMods=true;

  if (!TimeMods) // Assume 'm' if no modifiers are specified.
    Mod=L"m";

  // Set the specified time for every modifier. Be sure to check *Mod!=0,
  // because termination 0 is a part of string for wcschr. This check is
  // important when we set Mod to "m" above.
  for (;*Mod!=0 && wcschr(L"MCAOmcao",*Mod)!=NULL;Mod++)
    switch(toupperw(*Mod))
    {
      case 'M': 
        if (Before)
        {
          Age ? FileMtimeBefore.SetAgeText(S):FileMtimeBefore.SetIsoText(S);
          FileMtimeBeforeOR=ModeOR;
        }
        else
        {
          Age ? FileMtimeAfter.SetAgeText(S):FileMtimeAfter.SetIsoText(S);
          FileMtimeAfterOR=ModeOR;
        }
        break;
      case 'C':
        if (Before)
        {
          Age ? FileCtimeBefore.SetAgeText(S):FileCtimeBefore.SetIsoText(S);
          FileCtimeBeforeOR=ModeOR;
        }
        else
        {
          Age ? FileCtimeAfter.SetAgeText(S):FileCtimeAfter.SetIsoText(S);
          FileCtimeAfterOR=ModeOR;
        }
        break;
      case 'A':
        if (Before)
        {
          Age ? FileAtimeBefore.SetAgeText(S):FileAtimeBefore.SetIsoText(S);
          FileAtimeBeforeOR=ModeOR;
        }
        else
        {
          Age ? FileAtimeAfter.SetAgeText(S):FileAtimeAfter.SetIsoText(S);
          FileAtimeAfterOR=ModeOR;
        }
        break;
    }
}
#endif


#ifndef SFX_MODULE
// Return 'true' if we need to exclude the file from processing.
bool CommandData::TimeCheck(RarTime &ftm,RarTime &ftc,RarTime &fta)
{
  bool FilterOR=false;

  if (FileMtimeBefore.IsSet()) // Filter present.
    if (ftm>=FileMtimeBefore) // Condition not matched.
      if (FileMtimeBeforeOR) 
        FilterOR=true; // Not matched OR filter is present.
      else
        return true; // Exclude file in AND mode.
    else  // Condition matched.
      if (FileMtimeBeforeOR) 
        return false; // Include file in OR mode.

  if (FileMtimeAfter.IsSet()) // Filter present.
    if (ftm<FileMtimeAfter) // Condition not matched.
      if (FileMtimeAfterOR) 
        FilterOR=true; // Not matched OR filter is present.
      else
        return true; // Exclude file in AND mode.
    else  // Condition matched.
      if (FileMtimeAfterOR) 
        return false; // Include file in OR mode.

  if (FileCtimeBefore.IsSet()) // Filter present.
    if (ftc>=FileCtimeBefore) // Condition not matched.
      if (FileCtimeBeforeOR) 
        FilterOR=true; // Not matched OR filter is present.
      else
        return true; // Exclude file in AND mode.
    else  // Condition matched.
      if (FileCtimeBeforeOR) 
        return false; // Include file in OR mode.

  if (FileCtimeAfter.IsSet()) // Filter present.
    if (ftc<FileCtimeAfter) // Condition not matched.
      if (FileCtimeAfterOR) 
        FilterOR=true; // Not matched OR filter is present.
      else
        return true; // Exclude file in AND mode.
    else  // Condition matched.
      if (FileCtimeAfterOR) 
        return false; // Include file in OR mode.

  if (FileAtimeBefore.IsSet()) // Filter present.
    if (fta>=FileAtimeBefore) // Condition not matched.
      if (FileAtimeBeforeOR) 
        FilterOR=true; // Not matched OR filter is present.
      else
        return true; // Exclude file in AND mode.
    else  // Condition matched.
      if (FileAtimeBeforeOR) 
        return false; // Include file in OR mode.

  if (FileAtimeAfter.IsSet()) // Filter present.
    if (fta<FileAtimeAfter) // Condition not matched.
      if (FileAtimeAfterOR) 
        FilterOR=true; // Not matched OR filter is present.
      else
        return true; // Exclude file in AND mode.
    else  // Condition matched.
      if (FileAtimeAfterOR) 
        return false; // Include file in OR mode.

  return FilterOR; // Exclude if all OR filters are not matched.
}
#endif


#ifndef SFX_MODULE
// Return 'true' if we need to exclude the file from processing.
bool CommandData::SizeCheck(int64 Size)
{
  if (FileSizeLess!=INT64NDF && Size>=FileSizeLess)
    return true;
  if (FileSizeMore!=INT64NDF && Size<=FileSizeMore)
    return true;
  return false;
}
#endif




// Return 0 if file must not be processed or a number of matched parameter otherwise.
int CommandData::IsProcessFile(FileHeader &FileHead,bool *ExactMatch,int MatchType,
                               bool Flags,wchar *MatchedArg,uint MatchedArgSize)
{
  if (MatchedArg!=NULL && MatchedArgSize>0)
    *MatchedArg=0;
  bool Dir=FileHead.Dir;
  if (ExclCheck(FileHead.FileName,Dir,false,true))
    return 0;
#ifndef SFX_MODULE
  if (TimeCheck(FileHead.mtime,FileHead.ctime,FileHead.atime))
    return 0;
  if ((FileHead.FileAttr & ExclFileAttr)!=0 || FileHead.Dir && ExclDir)
    return 0;
  if (InclAttrSet && (!FileHead.Dir && (FileHead.FileAttr & InclFileAttr)==0 ||
      FileHead.Dir && !InclDir))
    return 0;
  if (!Dir && SizeCheck(FileHead.UnpSize))
    return 0;
#endif
  wchar *ArgName;
  FileArgs.Rewind();
  for (int StringCount=1;(ArgName=FileArgs.GetString())!=NULL;StringCount++)
    if (CmpName(ArgName,FileHead.FileName,MatchType))
    {
      if (ExactMatch!=NULL)
        *ExactMatch=wcsicompc(ArgName,FileHead.FileName)==0;
      if (MatchedArg!=NULL)
        wcsncpyz(MatchedArg,ArgName,MatchedArgSize);
      return StringCount;
    }
  return 0;
}


#if !defined(SFX_MODULE)
void CommandData::SetStoreTimeMode(const wchar *S)
{
  if (*S==0 || IsDigit(*S) || *S=='-' || *S=='+')
  {
    // Apply -ts, -ts1, -ts-, -ts+ to all 3 times.
    // Handle obsolete -ts[2,3,4] as ts+.
    EXTTIME_MODE Mode=EXTTIME_MAX;
    if (*S=='-')
      Mode=EXTTIME_NONE;
    if (*S=='1')
      Mode=EXTTIME_1S;
    xmtime=xctime=xatime=Mode;
    S++;
  }

  while (*S!=0)
  {
    EXTTIME_MODE Mode=EXTTIME_MAX;
    if (S[1]=='-')
      Mode=EXTTIME_NONE;
    if (S[1]=='1')
      Mode=EXTTIME_1S;
    switch(toupperw(*S))
    {
      case 'M':
        xmtime=Mode;
        break;
      case 'C':
        xctime=Mode;
        break;
      case 'A':
        xatime=Mode;
        break;
      case 'P':
        PreserveAtime=true;
        break;
    }
    S++;
  }
}
#endif

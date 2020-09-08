static SOUND_NOTIFY_MODE uiSoundNotify;

void uiInit(SOUND_NOTIFY_MODE Sound)
{
  uiSoundNotify = Sound;
}


// Additionally to handling user input, it analyzes and sets command options.
// Returns only 'replace', 'skip' and 'cancel' codes.
UIASKREP_RESULT uiAskReplaceEx(RAROptions *Cmd,wchar *Name,size_t MaxNameSize,int64 FileSize,RarTime *FileTime,uint Flags)
{
  if (Cmd->Overwrite==OVERWRITE_NONE)
    return UIASKREP_R_SKIP;

#if !defined(SFX_MODULE) && !defined(SILENT)
  // Must be before Cmd->AllYes check or -y switch would override -or.
  if (Cmd->Overwrite==OVERWRITE_AUTORENAME && GetAutoRenamedName(Name,MaxNameSize))
    return UIASKREP_R_REPLACE;
#endif

  // This check must be after OVERWRITE_AUTORENAME processing or -y switch
  // would override -or.
  if (Cmd->AllYes || Cmd->Overwrite==OVERWRITE_ALL)
  {
    PrepareToDelete(Name);
    return UIASKREP_R_REPLACE;
  }

  wchar NewName[NM];
  wcsncpyz(NewName,Name,ASIZE(NewName));
  UIASKREP_RESULT Choice=uiAskReplace(NewName,ASIZE(NewName),FileSize,FileTime,Flags);

  if (Choice==UIASKREP_R_REPLACE || Choice==UIASKREP_R_REPLACEALL)
    PrepareToDelete(Name);

  if (Choice==UIASKREP_R_REPLACEALL)
  {
    Cmd->Overwrite=OVERWRITE_ALL;
    return UIASKREP_R_REPLACE;
  }
  if (Choice==UIASKREP_R_SKIPALL)
  {
    Cmd->Overwrite=OVERWRITE_NONE;
    return UIASKREP_R_SKIP;
  }
  if (Choice==UIASKREP_R_RENAME)
  {
    if (PointToName(NewName)==NewName)
      SetName(Name,NewName,MaxNameSize);
    else
      wcsncpyz(Name,NewName,MaxNameSize);
    if (FileExist(Name))
      return uiAskReplaceEx(Cmd,Name,MaxNameSize,FileSize,FileTime,Flags);
    return UIASKREP_R_REPLACE;
  }
#if !defined(SFX_MODULE) && !defined(SILENT)
  if (Choice==UIASKREP_R_RENAMEAUTO && GetAutoRenamedName(Name,MaxNameSize))
  {
    Cmd->Overwrite=OVERWRITE_AUTORENAME;
    return UIASKREP_R_REPLACE;
  }
#endif
  return Choice;
}

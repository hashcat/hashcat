static bool AnyMessageDisplayed=false; // For console -idn switch.

// Purely user interface function. Gets and returns user input.
UIASKREP_RESULT uiAskReplace(wchar *Name,size_t MaxNameSize,int64 FileSize,RarTime *FileTime,uint Flags)
{
  wchar SizeText1[20],DateStr1[50],SizeText2[20],DateStr2[50];

  FindData ExistingFD;
  memset(&ExistingFD,0,sizeof(ExistingFD)); // In case find fails.
  FindFile::FastFind(Name,&ExistingFD);
  itoa(ExistingFD.Size,SizeText1,ASIZE(SizeText1));
  ExistingFD.mtime.GetText(DateStr1,ASIZE(DateStr1),false);

  if (FileSize==INT64NDF || FileTime==NULL)
  {
    eprintf(L"\n");
    eprintf(St(MAskOverwrite),Name);
  }
  else
  {
    itoa(FileSize,SizeText2,ASIZE(SizeText2));
    FileTime->GetText(DateStr2,ASIZE(DateStr2),false);
    if ((Flags & UIASKREP_F_EXCHSRCDEST)==0)
      eprintf(St(MAskReplace),Name,SizeText1,DateStr1,SizeText2,DateStr2);
    else
      eprintf(St(MAskReplace),Name,SizeText2,DateStr2,SizeText1,DateStr1);
  }

  bool AllowRename=(Flags & UIASKREP_F_NORENAME)==0;
  int Choice=0;
  do
  {
    Choice=Ask(St(AllowRename ? MYesNoAllRenQ : MYesNoAllQ));
  } while (Choice==0); // 0 means invalid input.
  switch(Choice)
  {
    case 1:
      return UIASKREP_R_REPLACE;
    case 2:
      return UIASKREP_R_SKIP;
    case 3:
      return UIASKREP_R_REPLACEALL;
    case 4:
      return UIASKREP_R_SKIPALL;
  }
  if (AllowRename && Choice==5)
  {
    mprintf(St(MAskNewName));
    if (getwstr(Name,MaxNameSize))
      return UIASKREP_R_RENAME;
    else
      return UIASKREP_R_SKIP; // Process fwgets failure as if user answered 'No'.
  }
  return UIASKREP_R_CANCEL;
}




void uiStartArchiveExtract(bool Extract,const wchar *ArcName)
{
  mprintf(St(Extract ? MExtracting : MExtrTest), ArcName);
}


bool uiStartFileExtract(const wchar *FileName,bool Extract,bool Test,bool Skip)
{
  return true;
}


void uiExtractProgress(int64 CurFileSize,int64 TotalFileSize,int64 CurSize,int64 TotalSize)
{
  int CurPercent=ToPercent(CurSize,TotalSize);
  mprintf(L"\b\b\b\b%3d%%",CurPercent);
}


void uiProcessProgress(const char *Command,int64 CurSize,int64 TotalSize)
{
  int CurPercent=ToPercent(CurSize,TotalSize);
  mprintf(L"\b\b\b\b%3d%%",CurPercent);
}


void uiMsgStore::Msg()
{
  // When creating volumes, AnyMessageDisplayed must be reset for UIEVENT_NEWARCHIVE,
  // so it ignores this and all earlier messages like UIEVENT_PROTECTEND
  // and UIEVENT_PROTECTEND, because they precede "Creating archive" message
  // and do not interfere with -idn and file names. If we do not ignore them,
  // uiEolAfterMsg() in uiStartFileAddit() can cause unneeded carriage return
  // in archiving percent after creating a new volume with -v -idn (and -rr
  // for UIEVENT_PROTECT*) switches. AnyMessageDisplayed is set for messages
  // after UIEVENT_NEWARCHIVE, so archiving percent with -idn is moved to
  // next line and does not delete their last characters.
  // Similarly we ignore UIEVENT_RRTESTINGEND for volumes, because it is issued
  // before "Testing archive" and would add an excessive \n otherwise.
  AnyMessageDisplayed=(Code!=UIEVENT_NEWARCHIVE && Code!=UIEVENT_RRTESTINGEND);

  switch(Code)
  {
    case UIERROR_SYSERRMSG:
    case UIERROR_GENERALERRMSG:
      Log(NULL,L"\n%ls",Str[0]);
      break;
    case UIERROR_CHECKSUM:
      Log(Str[0],St(MCRCFailed),Str[1]);
      break;
    case UIERROR_CHECKSUMENC:
      Log(Str[0],St(MEncrBadCRC),Str[1]);
      break;
    case UIERROR_CHECKSUMPACKED:
      Log(Str[0],St(MDataBadCRC),Str[1],Str[0]);
      break;
    case UIERROR_BADPSW:
      Log(Str[0],St(MWrongFilePassword),Str[1]);
      break;
    case UIWAIT_BADPSW:
      Log(Str[0],St(MWrongPassword));
      break;
    case UIERROR_MEMORY:
      mprintf(L"\n");
      Log(NULL,St(MErrOutMem));
      break;
    case UIERROR_FILEOPEN:
      Log(Str[0],St(MCannotOpen),Str[1]);
      break;
    case UIERROR_FILECREATE:
      Log(Str[0],St(MCannotCreate),Str[1]);
      break;
    case UIERROR_FILECLOSE:
      Log(NULL,St(MErrFClose),Str[0]);
      break;
    case UIERROR_FILESEEK:
      Log(NULL,St(MErrSeek),Str[0]);
      break;
    case UIERROR_FILEREAD:
      mprintf(L"\n");
      Log(Str[0],St(MErrRead),Str[1]);
      break;
    case UIERROR_FILEWRITE:
      Log(Str[0],St(MErrWrite),Str[1]);
      break;
#ifndef SFX_MODULE
    case UIERROR_FILEDELETE:
      Log(Str[0],St(MCannotDelete),Str[1]);
      break;
    case UIERROR_RECYCLEFAILED:
      Log(Str[0],St(MRecycleFailed));
      break;
    case UIERROR_FILERENAME:
      Log(Str[0],St(MErrRename),Str[1],Str[2]);
      break;
#endif
    case UIERROR_FILEATTR:
      Log(Str[0],St(MErrChangeAttr),Str[1]);
      break;
    case UIERROR_FILECOPY:
      Log(Str[0],St(MCopyError),Str[1],Str[2]);
      break;
    case UIERROR_FILECOPYHINT:
      Log(Str[0],St(MCopyErrorHint));
      mprintf(L"     "); // For progress percent.
      break;
    case UIERROR_DIRCREATE:
      Log(Str[0],St(MExtrErrMkDir),Str[1]);
      break;
    case UIERROR_SLINKCREATE:
      Log(Str[0],St(MErrCreateLnkS),Str[1]);
      break;
    case UIERROR_HLINKCREATE:
      Log(NULL,St(MErrCreateLnkH),Str[0]);
      break;
    case UIERROR_NOLINKTARGET:
      Log(NULL,St(MErrLnkTarget));
      mprintf(L"     "); // For progress percent.
      break;
    case UIERROR_NEEDADMIN:
      Log(NULL,St(MNeedAdmin));
      break;
    case UIERROR_ARCBROKEN:
      Log(Str[0],St(MErrBrokenArc));
      break;
    case UIERROR_HEADERBROKEN:
      Log(Str[0],St(MHeaderBroken));
      break;
    case UIERROR_MHEADERBROKEN:
      Log(Str[0],St(MMainHeaderBroken));
      break;
    case UIERROR_FHEADERBROKEN:
      Log(Str[0],St(MLogFileHead),Str[1]);
      break;
    case UIERROR_SUBHEADERBROKEN:
      Log(Str[0],St(MSubHeadCorrupt));
      break;
    case UIERROR_SUBHEADERUNKNOWN:
      Log(Str[0],St(MSubHeadUnknown));
      break;
    case UIERROR_SUBHEADERDATABROKEN:
      Log(Str[0],St(MSubHeadDataCRC),Str[1]);
      break;
    case UIERROR_RRDAMAGED:
      Log(Str[0],St(MRRDamaged));
      break;
    case UIERROR_UNKNOWNMETHOD:
      Log(Str[0],St(MUnknownMeth),Str[1]);
      break;
    case UIERROR_UNKNOWNENCMETHOD:
      {
        wchar Msg[256];
        swprintf(Msg,ASIZE(Msg),St(MUnkEncMethod),Str[1]);
        Log(Str[0],L"%s: %s",Msg,Str[2]);
      }
      break;
#ifndef SFX_MODULE
   case UIERROR_RENAMING:
      Log(Str[0],St(MRenaming),Str[1],Str[2]);
      break;
    case UIERROR_NEWERRAR:
      Log(Str[0],St(MNewerRAR));
      break;
#endif
    case UIERROR_RECVOLDIFFSETS:
      Log(NULL,St(MRecVolDiffSets),Str[0],Str[1]);
      break;
    case UIERROR_RECVOLALLEXIST:
      mprintf(St(MRecVolAllExist));
      break;
    case UIERROR_RECONSTRUCTING:
      mprintf(St(MReconstructing));
      break;
    case UIERROR_RECVOLCANNOTFIX:
      mprintf(St(MRecVolCannotFix));
      break;
    case UIERROR_UNEXPEOF:
      Log(Str[0],St(MLogUnexpEOF));
      break;
    case UIERROR_BADARCHIVE:
      Log(Str[0],St(MBadArc),Str[0]);
      break;
    case UIERROR_CMTBROKEN:
      Log(Str[0],St(MLogCommBrk));
      break;
    case UIERROR_INVALIDNAME:
      Log(Str[0],St(MInvalidName),Str[1]);
      mprintf(L"\n"); // Needed when called from CmdExtract::ExtractCurrentFile.
      break;
#ifndef SFX_MODULE
    case UIERROR_NEWRARFORMAT:
      Log(Str[0],St(MNewRarFormat));
      break;
#endif
    case UIERROR_NOFILESTOEXTRACT:
      mprintf(St(MExtrNoFiles));
      break;
    case UIERROR_MISSINGVOL:
      Log(Str[0],St(MAbsNextVol),Str[0]);
      break;
#ifndef SFX_MODULE
    case UIERROR_NEEDPREVVOL:
      Log(Str[0],St(MUnpCannotMerge),Str[1]);
      break;
    case UIERROR_UNKNOWNEXTRA:
      Log(Str[0],St(MUnknownExtra),Str[1]);
      break;
    case UIERROR_CORRUPTEXTRA:
      Log(Str[0],St(MCorruptExtra),Str[1],Str[2]);
      break;
#endif
#if !defined(SFX_MODULE) && defined(_WIN_ALL)
    case UIERROR_NTFSREQUIRED:
      Log(NULL,St(MNTFSRequired),Str[0]);
      break;
#endif
#if !defined(SFX_MODULE) && defined(_WIN_ALL)
    case UIERROR_ACLBROKEN:
      Log(Str[0],St(MACLBroken),Str[1]);
      break;
    case UIERROR_ACLUNKNOWN:
      Log(Str[0],St(MACLUnknown),Str[1]);
      break;
    case UIERROR_ACLSET:
      Log(Str[0],St(MACLSetError),Str[1]);
      break;
    case UIERROR_STREAMBROKEN:
      Log(Str[0],St(MStreamBroken),Str[1]);
      break;
    case UIERROR_STREAMUNKNOWN:
      Log(Str[0],St(MStreamUnknown),Str[1]);
      break;
#endif
    case UIERROR_INCOMPATSWITCH:
      mprintf(St(MIncompatSwitch),Str[0],Num[0]);
      break;
    case UIERROR_PATHTOOLONG:
      Log(NULL,L"\n%ls%ls%ls",Str[0],Str[1],Str[2]);
      Log(NULL,St(MPathTooLong));
      break;
#ifndef SFX_MODULE
    case UIERROR_DIRSCAN:
      Log(NULL,St(MScanError),Str[0]);
      break;
#endif
    case UIERROR_UOWNERBROKEN:
      Log(Str[0],St(MOwnersBroken),Str[1]);
      break;
    case UIERROR_UOWNERGETOWNERID:
      Log(Str[0],St(MErrGetOwnerID),Str[1]);
      break;
    case UIERROR_UOWNERGETGROUPID:
      Log(Str[0],St(MErrGetGroupID),Str[1]);
      break;
    case UIERROR_UOWNERSET:
      Log(Str[0],St(MSetOwnersError),Str[1]);
      break;
    case UIERROR_ULINKREAD:
      Log(NULL,St(MErrLnkRead),Str[0]);
      break;
    case UIERROR_ULINKEXIST:
      Log(NULL,St(MSymLinkExists),Str[0]);
      break;
    case UIERROR_READERRTRUNCATED:
      Log(NULL,St(MErrReadTrunc),Str[0]);
      break;
    case UIERROR_READERRCOUNT:
      Log(NULL,St(MErrReadCount),Num[0]);
      break;
    case UIERROR_DIRNAMEEXISTS:
      Log(NULL,St(MDirNameExists));
      break;

#ifndef SFX_MODULE
    case UIMSG_STRING:
      mprintf(L"\n%s",Str[0]);
      break;
#endif
    case UIMSG_CORRECTINGNAME:
      Log(Str[0],St(MCorrectingName));
      break;
    case UIMSG_BADARCHIVE:
      mprintf(St(MBadArc),Str[0]);
      break;
    case UIMSG_CREATING:
      mprintf(St(MCreating),Str[0]);
      break;
    case UIMSG_RENAMING:
      mprintf(St(MRenaming),Str[0],Str[1]);
      break;
    case UIMSG_RECVOLCALCCHECKSUM:
      mprintf(St(MCalcCRCAllVol));
      break;
    case UIMSG_RECVOLFOUND:
      mprintf(St(MRecVolFound),Num[0]);
      break;
    case UIMSG_RECVOLMISSING:
      mprintf(St(MRecVolMissing),Num[0]);
      break;
    case UIMSG_MISSINGVOL:
      mprintf(St(MAbsNextVol),Str[0]);
      break;
    case UIMSG_RECONSTRUCTING:
      mprintf(St(MReconstructing));
      break;
    case UIMSG_CHECKSUM:
      mprintf(St(MCRCFailed),Str[0]);
      break;
    case UIMSG_FAT32SIZE:
      mprintf(St(MFAT32Size));
      mprintf(L"     "); // For progress percent.
      break;



    case UIEVENT_RRTESTINGSTART:
      mprintf(L"%s      ",St(MTestingRR));
      break;
  }
}


bool uiGetPassword(UIPASSWORD_TYPE Type,const wchar *FileName,SecPassword *Password)
{
  // Unlike GUI we cannot provide Cancel button here, so we use the empty
  // password to abort. Otherwise user not knowing a password would need to
  // press Ctrl+C multiple times to quit from infinite password request loop.
  return GetConsolePassword(Type,FileName,Password) && Password->IsSet();
}


bool uiIsGlobalPasswordSet()
{
  return false;
}


void uiAlarm(UIALARM_TYPE Type)
{
  if (uiSoundNotify==SOUND_NOTIFY_ON)
  {
    static clock_t LastTime=-10; // Negative to always beep first time.
    if ((MonoClock()-LastTime)/CLOCKS_PER_SEC>5)
    {
#ifdef _WIN_ALL
      MessageBeep(-1);
#else
      putwchar('\007');
#endif
      LastTime=MonoClock();
    }
  }
}




bool uiAskNextVolume(wchar *VolName,size_t MaxSize)
{
  eprintf(St(MAskNextVol),VolName);
  return Ask(St(MContinueQuit))!=2;
}


void uiAskRepeatRead(const wchar *FileName,bool &Ignore,bool &All,bool &Retry,bool &Quit)
{
  eprintf(St(MErrReadInfo));
  int Code=Ask(St(MIgnoreAllRetryQuit));

  Ignore=(Code==1);
  All=(Code==2);
  Quit=(Code==4);
  Retry=!Ignore && !All && !Quit; // Default also for invalid input, not just for 'Retry'.
}


bool uiAskRepeatWrite(const wchar *FileName,bool DiskFull)
{
  mprintf(L"\n");
  Log(NULL,St(DiskFull ? MNotEnoughDisk:MErrWrite),FileName);
  return Ask(St(MRetryAbort))==1;
}


#ifndef SFX_MODULE
const wchar *uiGetMonthName(int Month)
{
  static MSGID MonthID[12]={
         MMonthJan,MMonthFeb,MMonthMar,MMonthApr,MMonthMay,MMonthJun,
         MMonthJul,MMonthAug,MMonthSep,MMonthOct,MMonthNov,MMonthDec
  };
  return St(MonthID[Month]);
}
#endif


void uiEolAfterMsg()
{
  if (AnyMessageDisplayed)
  {
    // Avoid deleting several last characters of any previous error message
    // with percentage indicator in -idn mode.
    AnyMessageDisplayed=false;
    mprintf(L"\n");
  }
}

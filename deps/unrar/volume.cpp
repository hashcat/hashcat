#include "rar.hpp"

#ifdef RARDLL
static bool DllVolChange(CommandData *Cmd,wchar *NextName,size_t NameSize);
static bool DllVolNotify(CommandData *Cmd,wchar *NextName);
#endif



bool MergeArchive(Archive &Arc,ComprDataIO *DataIO,bool ShowFileName,wchar Command)
{
  CommandData *Cmd=Arc.GetCommandData();

  HEADER_TYPE HeaderType=Arc.GetHeaderType();
  FileHeader *hd=HeaderType==HEAD_SERVICE ? &Arc.SubHead:&Arc.FileHead;
  bool SplitHeader=(HeaderType==HEAD_FILE || HeaderType==HEAD_SERVICE) &&
                   hd->SplitAfter;

  if (DataIO!=NULL && SplitHeader)
  {
    bool PackedHashPresent=Arc.Format==RARFMT50 || 
         hd->UnpVer>=20 && hd->FileHash.CRC32!=0xffffffff;
    if (PackedHashPresent && 
        !DataIO->PackedDataHash.Cmp(&hd->FileHash,hd->UseHashKey ? hd->HashKey:NULL))
      uiMsg(UIERROR_CHECKSUMPACKED, Arc.FileName, hd->FileName);
  }

  bool PrevVolEncrypted=Arc.Encrypted;

  int64 PosBeforeClose=Arc.Tell();

  if (DataIO!=NULL)
    DataIO->ProcessedArcSize+=DataIO->LastArcSize;


  Arc.Close();

  wchar NextName[NM];
  wcsncpyz(NextName,Arc.FileName,ASIZE(NextName));
  NextVolumeName(NextName,ASIZE(NextName),!Arc.NewNumbering);

#if !defined(SFX_MODULE) && !defined(RARDLL)
  bool RecoveryDone=false;
#endif
  bool OldSchemeTested=false;

  bool FailedOpen=false; // No more next volume open attempts if true.
#if !defined(SILENT)
  // In -vp mode we force the pause before next volume even if it is present
  // and even if we are on the hard disk. It is important when user does not
  // want to process partially downloaded volumes preliminary.
  // 2022.01.11: In WinRAR 6.10 beta versions we tried to ignore VolumePause
  // if we could open the next volume with FMF_OPENEXCLUSIVE. But another
  // developer asked us to return the previous behavior and always prompt
  // for confirmation. They want to control when unrar continues, because
  // the next file might not be fully decoded yet. They write chunks of data
  // and then close the file again until the next chunk comes in.

  if (Cmd->VolumePause && !uiAskNextVolume(NextName,ASIZE(NextName)))
    FailedOpen=true;
#endif

  uint OpenMode = Cmd->OpenShared ? FMF_OPENSHARED : 0;

  if (!FailedOpen)
    while (!Arc.Open(NextName,OpenMode))
    {
      // We need to open a new volume which size was not calculated
      // in total size before, so we cannot calculate the total progress
      // anymore. Let's reset the total size to zero and stop 
      // the total progress.
      if (DataIO!=NULL)
        DataIO->TotalArcSize=0;

      if (!OldSchemeTested)
      {
        // Checking for new style volumes renamed by user to old style
        // name format. Some users did it for unknown reason.
        wchar AltNextName[NM];
        wcsncpyz(AltNextName,Arc.FileName,ASIZE(AltNextName));
        NextVolumeName(AltNextName,ASIZE(AltNextName),true);
        OldSchemeTested=true;
        if (Arc.Open(AltNextName,OpenMode))
        {
          wcsncpyz(NextName,AltNextName,ASIZE(NextName));
          break;
        }
      }
#ifdef RARDLL
      if (!DllVolChange(Cmd,NextName,ASIZE(NextName)))
      {
        FailedOpen=true;
        break;
      }
#else // !RARDLL

#ifndef SFX_MODULE
      if (!RecoveryDone)
      {
        RecVolumesRestore(Cmd,Arc.FileName,true);
        RecoveryDone=true;
        continue;
      }
#endif

      if (!Cmd->VolumePause && !IsRemovable(NextName))
      {
        FailedOpen=true;
        break;
      }
#ifndef SILENT
      if (Cmd->AllYes || !uiAskNextVolume(NextName,ASIZE(NextName)))
#endif
      {
        FailedOpen=true;
        break;
      }

#endif // RARDLL
    }
  
  if (FailedOpen)
  {
    uiMsg(UIERROR_MISSINGVOL,NextName);
    Arc.Open(Arc.FileName,OpenMode);
    Arc.Seek(PosBeforeClose,SEEK_SET);
    return false;
  }

  if (Command=='T' || Command=='X' || Command=='E')
    mprintf(St(Command=='T' ? MTestVol:MExtrVol),Arc.FileName);


  Arc.CheckArc(true);
#ifdef RARDLL
  if (!DllVolNotify(Cmd,NextName))
    return false;
#endif

  if (Arc.Encrypted!=PrevVolEncrypted)
  {
    // There is no legitimate reason for encrypted header state to be
    // changed in the middle of volume sequence. So we abort here to prevent
    // replacing an encrypted header volume to unencrypted and adding
    // unexpected files by third party to encrypted extraction.
    uiMsg(UIERROR_BADARCHIVE,Arc.FileName);
    ErrHandler.Exit(RARX_FATAL);
  }

  if (SplitHeader)
    Arc.SearchBlock(HeaderType);
  else
    Arc.ReadHeader();
  if (Arc.GetHeaderType()==HEAD_FILE)
  {
    Arc.ConvertAttributes();
    Arc.Seek(Arc.NextBlockPos-Arc.FileHead.PackSize,SEEK_SET);
  }
  if (ShowFileName && !Cmd->DisableNames)
  {
    mprintf(St(MExtrPoints),Arc.FileHead.FileName);
    if (!Cmd->DisablePercentage)
      mprintf(L"     ");
  }
  if (DataIO!=NULL)
  {
    if (HeaderType==HEAD_ENDARC)
      DataIO->UnpVolume=false;
    else
    {
      DataIO->UnpVolume=hd->SplitAfter;
      DataIO->SetPackedSizeToRead(hd->PackSize);
    }

    DataIO->AdjustTotalArcSize(&Arc);
      
    // Reset the size of packed data read from current volume. It is used
    // to display the total progress and preceding volumes are already
    // compensated with ProcessedArcSize, so we need to reset this variable.
    DataIO->CurUnpRead=0;

    DataIO->PackedDataHash.Init(hd->FileHash.Type,Cmd->Threads);
  }
  return true;
}






#ifdef RARDLL
bool DllVolChange(CommandData *Cmd,wchar *NextName,size_t NameSize)
{
  bool DllVolChanged=false,DllVolAborted=false;

  if (Cmd->Callback!=NULL)
  {
    wchar OrgNextName[NM];
    wcsncpyz(OrgNextName,NextName,ASIZE(OrgNextName));
    if (Cmd->Callback(UCM_CHANGEVOLUMEW,Cmd->UserData,(LPARAM)NextName,RAR_VOL_ASK)==-1)
      DllVolAborted=true;
    else
      if (wcscmp(OrgNextName,NextName)!=0)
        DllVolChanged=true;
      else
      {
        char NextNameA[NM],OrgNextNameA[NM];
        WideToChar(NextName,NextNameA,ASIZE(NextNameA));
        strncpyz(OrgNextNameA,NextNameA,ASIZE(OrgNextNameA));
        if (Cmd->Callback(UCM_CHANGEVOLUME,Cmd->UserData,(LPARAM)NextNameA,RAR_VOL_ASK)==-1)
          DllVolAborted=true;
        else
          if (strcmp(OrgNextNameA,NextNameA)!=0)
          {
            // We can damage some Unicode characters by U->A->U conversion,
            // so set Unicode name only if we see that ANSI name is changed.
            CharToWide(NextNameA,NextName,NameSize);
            DllVolChanged=true;
          }
      }
  }
  if (!DllVolChanged && Cmd->ChangeVolProc!=NULL)
  {
    char NextNameA[NM];
    WideToChar(NextName,NextNameA,ASIZE(NextNameA));
    int RetCode=Cmd->ChangeVolProc(NextNameA,RAR_VOL_ASK);
    if (RetCode==0)
      DllVolAborted=true;
    else
      CharToWide(NextNameA,NextName,NameSize);
  }

  // We quit only on 'abort' condition, but not on 'name not changed'.
  // It is legitimate for program to return the same name when waiting
  // for currently non-existent volume.
  // Also we quit to prevent an infinite loop if no callback is defined.
  if (DllVolAborted || Cmd->Callback==NULL && Cmd->ChangeVolProc==NULL)
  {
    Cmd->DllError=ERAR_EOPEN;
    return false;
  }
  return true;
}
#endif


#ifdef RARDLL
bool DllVolNotify(CommandData *Cmd,wchar *NextName)
{
  char NextNameA[NM];
  WideToChar(NextName,NextNameA,ASIZE(NextNameA));
  if (Cmd->Callback!=NULL)
  {
    if (Cmd->Callback(UCM_CHANGEVOLUMEW,Cmd->UserData,(LPARAM)NextName,RAR_VOL_NOTIFY)==-1)
      return false;
    if (Cmd->Callback(UCM_CHANGEVOLUME,Cmd->UserData,(LPARAM)NextNameA,RAR_VOL_NOTIFY)==-1)
      return false;
  }
  if (Cmd->ChangeVolProc!=NULL)
  {
    int RetCode=Cmd->ChangeVolProc(NextNameA,RAR_VOL_NOTIFY);
    if (RetCode==0)
      return false;
  }
  return true;
}
#endif

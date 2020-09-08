#include "rar.hpp"

#ifdef RARDLL
static bool DllVolChange(RAROptions *Cmd,wchar *NextName,size_t NameSize);
static bool DllVolNotify(RAROptions *Cmd,wchar *NextName);
#endif



bool MergeArchive(Archive &Arc,ComprDataIO *DataIO,bool ShowFileName,wchar Command)
{
  RAROptions *Cmd=Arc.GetRAROptions();

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

  int64 PosBeforeClose=Arc.Tell();

  if (DataIO!=NULL)
    DataIO->ProcessedArcSize+=Arc.FileLength();


  Arc.Close();

  wchar NextName[NM];
  wcsncpyz(NextName,Arc.FileName,ASIZE(NextName));
  NextVolumeName(NextName,ASIZE(NextName),!Arc.NewNumbering);

#if !defined(SFX_MODULE) && !defined(RARDLL)
  bool RecoveryDone=false;
#endif
  bool FailedOpen=false,OldSchemeTested=false;

#if !defined(SILENT)
  // In -vp mode we force the pause before next volume even if it is present
  // and even if we are on the hard disk. It is important when user does not
  // want to process partially downloaded volumes preliminary.
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

  if (SplitHeader)
    Arc.SearchBlock(HeaderType);
  else
    Arc.ReadHeader();
  if (Arc.GetHeaderType()==HEAD_FILE)
  {
    Arc.ConvertAttributes();
    Arc.Seek(Arc.NextBlockPos-Arc.FileHead.PackSize,SEEK_SET);
  }
  if (ShowFileName)
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
#ifdef SFX_MODULE
    DataIO->UnpArcSize=Arc.FileLength();
#endif
    
    // Reset the size of packed data read from current volume. It is used
    // to display the total progress and preceding volumes are already
    // compensated with ProcessedArcSize, so we need to reset this variable.
    DataIO->CurUnpRead=0;

    DataIO->PackedDataHash.Init(hd->FileHash.Type,Cmd->Threads);
  }
  return true;
}






#ifdef RARDLL
#if defined(RARDLL) && defined(_MSC_VER) && !defined(_WIN_64)
// Disable the run time stack check for unrar.dll, so we can manipulate
// with ChangeVolProc call type below. Run time check would intercept
// a wrong ESP before we restore it.
#pragma runtime_checks( "s", off )
#endif

bool DllVolChange(RAROptions *Cmd,wchar *NextName,size_t NameSize)
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
    // Here we preserve ESP value. It is necessary for those developers,
    // who still define ChangeVolProc callback as "C" type function,
    // even though in year 2001 we announced in unrar.dll whatsnew.txt
    // that it will be PASCAL type (for compatibility with Visual Basic).
#if defined(_MSC_VER)
#ifndef _WIN_64
    __asm mov ebx,esp
#endif
#elif defined(_WIN_ALL) && defined(__BORLANDC__)
    _EBX=_ESP;
#endif
    int RetCode=Cmd->ChangeVolProc(NextNameA,RAR_VOL_ASK);

    // Restore ESP after ChangeVolProc with wrongly defined calling
    // convention broken it.
#if defined(_MSC_VER)
#ifndef _WIN_64
    __asm mov esp,ebx
#endif
#elif defined(_WIN_ALL) && defined(__BORLANDC__)
    _ESP=_EBX;
#endif
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
bool DllVolNotify(RAROptions *Cmd,wchar *NextName)
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
#if defined(_WIN_ALL) && !defined(_MSC_VER) && !defined(__MINGW32__)
    _EBX=_ESP;
#endif
    int RetCode=Cmd->ChangeVolProc(NextNameA,RAR_VOL_NOTIFY);
#if defined(_WIN_ALL) && !defined(_MSC_VER) && !defined(__MINGW32__)
    _ESP=_EBX;
#endif
    if (RetCode==0)
      return false;
  }
  return true;
}

#if defined(RARDLL) && defined(_MSC_VER) && !defined(_WIN_64)
// Restore the run time stack check for unrar.dll.
#pragma runtime_checks( "s", restore )
#endif
#endif

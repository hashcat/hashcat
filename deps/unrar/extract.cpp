#include "rar.hpp"

CmdExtract::CmdExtract(CommandData *Cmd)
{
  CmdExtract::Cmd=Cmd;

  *ArcName=0;

  *DestFileName=0;

  TotalFileCount=0;
  Unp=new Unpack(&DataIO);
#ifdef RAR_SMP
  Unp->SetThreads(Cmd->Threads);
#endif
}


CmdExtract::~CmdExtract()
{
  delete Unp;
}


void CmdExtract::DoExtract()
{
#if defined(_WIN_ALL) && !defined(SFX_MODULE) && !defined(SILENT)
  Fat32=NotFat32=false;
#endif
  PasswordCancelled=false;
  DataIO.SetCurrentCommand(Cmd->Command[0]);

  FindData FD;
  while (Cmd->GetArcName(ArcName,ASIZE(ArcName)))
    if (FindFile::FastFind(ArcName,&FD))
      DataIO.TotalArcSize+=FD.Size;

  Cmd->ArcNames.Rewind();
  while (Cmd->GetArcName(ArcName,ASIZE(ArcName)))
  {
    if (Cmd->ManualPassword)
      Cmd->Password.Clean(); // Clean user entered password before processing next archive.
  
    ReconstructDone=false; // Must be reset here, not in ExtractArchiveInit().
    UseExactVolName=false; // Must be reset here, not in ExtractArchiveInit().
    while (true)
    {
      EXTRACT_ARC_CODE Code=ExtractArchive();
      if (Code!=EXTRACT_ARC_REPEAT)
        break;
    }
    if (FindFile::FastFind(ArcName,&FD))
      DataIO.ProcessedArcSize+=FD.Size;
  }

  // Clean user entered password. Not really required, just for extra safety.
  if (Cmd->ManualPassword)
    Cmd->Password.Clean();

  if (TotalFileCount==0 && Cmd->Command[0]!='I' && 
      ErrHandler.GetErrorCode()!=RARX_BADPWD) // Not in case of wrong archive password.
  {
    if (!PasswordCancelled)
      uiMsg(UIERROR_NOFILESTOEXTRACT,ArcName);

    // Other error codes may explain a reason of "no files extracted" clearer,
    // so set it only if no other errors found (wrong mask set by user).
    if (ErrHandler.GetErrorCode()==RARX_SUCCESS)
      ErrHandler.SetErrorCode(RARX_NOFILES);
  }
  else
    if (!Cmd->DisableDone)
      if (Cmd->Command[0]=='I')
        mprintf(St(MDone));
      else
        if (ErrHandler.GetErrorCount()==0)
          mprintf(St(MExtrAllOk));
        else
          mprintf(St(MExtrTotalErr),ErrHandler.GetErrorCount());
}


void CmdExtract::ExtractArchiveInit(Archive &Arc)
{
  DataIO.UnpArcSize=Arc.FileLength();

  FileCount=0;
  MatchedArgs=0;
#ifndef SFX_MODULE
  FirstFile=true;
#endif

  GlobalPassword=Cmd->Password.IsSet() || uiIsGlobalPasswordSet();

  DataIO.UnpVolume=false;

  PrevProcessed=false;
  AllMatchesExact=true;
  AnySolidDataUnpackedWell=false;

  StartTime.SetCurrentTime();
}


EXTRACT_ARC_CODE CmdExtract::ExtractArchive()
{
  Archive Arc(Cmd);
  if (!Arc.WOpen(ArcName))
    return EXTRACT_ARC_NEXT;

  if (!Arc.IsArchive(true))
  {
#if !defined(SFX_MODULE) && !defined(RARDLL)
    if (CmpExt(ArcName,L"rev"))
    {
      wchar FirstVolName[NM];
      VolNameToFirstName(ArcName,FirstVolName,ASIZE(FirstVolName),true);

      // If several volume names from same volume set are specified
      // and current volume is not first in set and first volume is present
      // and specified too, let's skip the current volume.
      if (wcsicomp(ArcName,FirstVolName)!=0 && FileExist(FirstVolName) &&
          Cmd->ArcNames.Search(FirstVolName,false))
        return EXTRACT_ARC_NEXT;
      RecVolumesTest(Cmd,NULL,ArcName);
      TotalFileCount++; // Suppress "No files to extract" message.
      return EXTRACT_ARC_NEXT;
    }
#endif

    mprintf(St(MNotRAR),ArcName);

#ifndef SFX_MODULE
    if (CmpExt(ArcName,L"rar"))
#endif
      ErrHandler.SetErrorCode(RARX_WARNING);
    return EXTRACT_ARC_NEXT;
  }

  if (Arc.FailedHeaderDecryption) // Bad archive password.
    return EXTRACT_ARC_NEXT;

#ifndef SFX_MODULE
  if (Arc.Volume && !Arc.FirstVolume && !UseExactVolName)
  {
    wchar FirstVolName[NM];
    VolNameToFirstName(ArcName,FirstVolName,ASIZE(FirstVolName),Arc.NewNumbering);

    // If several volume names from same volume set are specified
    // and current volume is not first in set and first volume is present
    // and specified too, let's skip the current volume.
    if (wcsicomp(ArcName,FirstVolName)!=0 && FileExist(FirstVolName) &&
        Cmd->ArcNames.Search(FirstVolName,false))
      return EXTRACT_ARC_NEXT;
  }
#endif

  int64 VolumeSetSize=0; // Total size of volumes after the current volume.

  if (Arc.Volume)
  {
#ifndef SFX_MODULE
    // Try to speed up extraction for independent solid volumes by starting
    // extraction from non-first volume if we can.
    if (!UseExactVolName && Arc.Solid && DetectStartVolume(Arc.FileName,Arc.NewNumbering))
    {
      UseExactVolName=true;
      return EXTRACT_ARC_REPEAT;
    }
#endif

    // Calculate the total size of all accessible volumes.
    // This size is necessary to display the correct total progress indicator.

    wchar NextName[NM];
    wcsncpyz(NextName,Arc.FileName,ASIZE(NextName));

    while (true)
    {
      // First volume is already added to DataIO.TotalArcSize 
      // in initial TotalArcSize calculation in DoExtract.
      // So we skip it and start from second volume.
      NextVolumeName(NextName,ASIZE(NextName),!Arc.NewNumbering);
      FindData FD;
      if (FindFile::FastFind(NextName,&FD))
        VolumeSetSize+=FD.Size;
      else
        break;
    }
    DataIO.TotalArcSize+=VolumeSetSize;
  }

  ExtractArchiveInit(Arc);

  if (*Cmd->Command=='T' || *Cmd->Command=='I')
    Cmd->Test=true;


  if (*Cmd->Command=='I')
  {
    Cmd->DisablePercentage=true;
  }
  else
    uiStartArchiveExtract(!Cmd->Test,ArcName);

  Arc.ViewComment();


  while (1)
  {
    size_t Size=Arc.ReadHeader();


    bool Repeat=false;
    if (!ExtractCurrentFile(Arc,Size,Repeat))
      if (Repeat)
      {
        // If we started extraction from not first volume and need to
        // restart it from first, we must correct DataIO.TotalArcSize
        // for correct total progress display. We subtract the size
        // of current volume and all volumes after it and add the size
        // of new (first) volume.
        FindData OldArc,NewArc;
        if (FindFile::FastFind(Arc.FileName,&OldArc) &&
            FindFile::FastFind(ArcName,&NewArc))
          DataIO.TotalArcSize-=VolumeSetSize+OldArc.Size-NewArc.Size;
        return EXTRACT_ARC_REPEAT;
      }
      else
        break;
  }


#if !defined(SFX_MODULE) && !defined(RARDLL)
  if (Cmd->Test && Arc.Volume)
    RecVolumesTest(Cmd,&Arc,ArcName);
#endif

  return EXTRACT_ARC_NEXT;
}


bool CmdExtract::ExtractCurrentFile(Archive &Arc,size_t HeaderSize,bool &Repeat)
{
  wchar Command=Cmd->Command[0];
  if (HeaderSize==0)
    if (DataIO.UnpVolume)
    {
#ifdef NOVOLUME
      return false;
#else
      // Supposing we unpack an old RAR volume without the end of archive
      // record and last file is not split between volumes.
      if (!MergeArchive(Arc,&DataIO,false,Command))
      {
        ErrHandler.SetErrorCode(RARX_WARNING);
        return false;
      }
#endif
    }
    else
      return false;

  HEADER_TYPE HeaderType=Arc.GetHeaderType();
  if (HeaderType!=HEAD_FILE)
  {
#ifndef SFX_MODULE
    if (Arc.Format==RARFMT15 && HeaderType==HEAD3_OLDSERVICE && PrevProcessed)
      SetExtraInfo20(Cmd,Arc,DestFileName);
#endif
    if (HeaderType==HEAD_SERVICE && PrevProcessed)
      SetExtraInfo(Cmd,Arc,DestFileName);
    if (HeaderType==HEAD_ENDARC)
      if (Arc.EndArcHead.NextVolume)
      {
#ifdef NOVOLUME
        return false;
#else
        if (!MergeArchive(Arc,&DataIO,false,Command))
        {
          ErrHandler.SetErrorCode(RARX_WARNING);
          return false;
        }
        Arc.Seek(Arc.CurBlockPos,SEEK_SET);
        return true;
#endif
      }
      else
        return false;
    Arc.SeekToNext();
    return true;
  }
  PrevProcessed=false;

  // We can get negative sizes in corrupt archive and it is unacceptable
  // for size comparisons in ComprDataIO::UnpRead, where we cast sizes
  // to size_t and can exceed another read or available size. We could fix it
  // when reading an archive. But we prefer to do it here, because this
  // function is called directly in unrar.dll, so we fix bad parameters
  // passed to dll. Also we want to see real negative sizes in the listing
  // of corrupt archive. To prevent uninitialized data access perform
  // these checks after rejecting zero length and non-file headers above.
  if (Arc.FileHead.PackSize<0)
    Arc.FileHead.PackSize=0;
  if (Arc.FileHead.UnpSize<0)
    Arc.FileHead.UnpSize=0;

  if (!Cmd->Recurse && MatchedArgs>=Cmd->FileArgs.ItemsCount() && AllMatchesExact)
    return false;

  int MatchType=MATCH_WILDSUBPATH;

  bool EqualNames=false;
  wchar MatchedArg[NM];
  int MatchNumber=Cmd->IsProcessFile(Arc.FileHead,&EqualNames,MatchType,0,MatchedArg,ASIZE(MatchedArg));
  bool MatchFound=MatchNumber!=0;
#ifndef SFX_MODULE
  if (Cmd->ExclPath==EXCL_BASEPATH)
  {
    wcsncpyz(Cmd->ArcPath,MatchedArg,ASIZE(Cmd->ArcPath));
    *PointToName(Cmd->ArcPath)=0;
    if (IsWildcard(Cmd->ArcPath)) // Cannot correctly process path*\* masks here.
      *Cmd->ArcPath=0;
  }
#endif
  if (MatchFound && !EqualNames)
    AllMatchesExact=false;

  Arc.ConvertAttributes();

#if !defined(SFX_MODULE) && !defined(RARDLL)
  if (Arc.FileHead.SplitBefore && FirstFile && !UseExactVolName)
  {
    wchar CurVolName[NM];
    wcsncpyz(CurVolName,ArcName,ASIZE(CurVolName));
    GetFirstVolIfFullSet(ArcName,Arc.NewNumbering,ArcName,ASIZE(ArcName));

    if (wcsicomp(ArcName,CurVolName)!=0 && FileExist(ArcName))
    {
      wcsncpyz(Cmd->ArcName,ArcName,ASIZE(ArcName)); // For GUI "Delete archive after extraction".
      // If first volume name does not match the current name and if such
      // volume name really exists, let's unpack from this first volume.
      Repeat=true;
      return false;
    }
#ifndef RARDLL
    if (!ReconstructDone)
    {
      ReconstructDone=true;
      if (RecVolumesRestore(Cmd,Arc.FileName,true))
      {
        Repeat=true;
        return false;
      }
    }
#endif
    wcsncpyz(ArcName,CurVolName,ASIZE(ArcName));
  }
#endif

  wchar ArcFileName[NM];
  ConvertPath(Arc.FileHead.FileName,ArcFileName,ASIZE(ArcFileName));

  if (Arc.FileHead.Version)
  {
    if (Cmd->VersionControl!=1 && !EqualNames)
    {
      if (Cmd->VersionControl==0)
        MatchFound=false;
      int Version=ParseVersionFileName(ArcFileName,false);
      if (Cmd->VersionControl-1==Version)
        ParseVersionFileName(ArcFileName,true);
      else
        MatchFound=false;
    }
  }
  else
    if (!Arc.IsArcDir() && Cmd->VersionControl>1)
      MatchFound=false;

  DataIO.UnpVolume=Arc.FileHead.SplitAfter;
  DataIO.NextVolumeMissing=false;

  Arc.Seek(Arc.NextBlockPos-Arc.FileHead.PackSize,SEEK_SET);

  bool ExtrFile=false;
  bool SkipSolid=false;

#ifndef SFX_MODULE
  if (FirstFile && (MatchFound || Arc.Solid) && Arc.FileHead.SplitBefore)
  {
    if (MatchFound)
    {
      uiMsg(UIERROR_NEEDPREVVOL,Arc.FileName,ArcFileName);
#ifdef RARDLL
      Cmd->DllError=ERAR_BAD_DATA;
#endif
      ErrHandler.SetErrorCode(RARX_OPEN);
    }
    MatchFound=false;
  }

  FirstFile=false;
#endif

  if (MatchFound || (SkipSolid=Arc.Solid)!=0)
  {
    // First common call of uiStartFileExtract. It is done before overwrite
    // prompts, so if SkipSolid state is changed below, we'll need to make
    // additional uiStartFileExtract calls with updated parameters.
    if (!uiStartFileExtract(ArcFileName,!Cmd->Test,Cmd->Test && Command!='I',SkipSolid))
      return false;

    ExtrPrepareName(Arc,ArcFileName,DestFileName,ASIZE(DestFileName));

    // DestFileName can be set empty in case of excessive -ap switch.
    ExtrFile=!SkipSolid && *DestFileName!=0 && !Arc.FileHead.SplitBefore;

    if ((Cmd->FreshFiles || Cmd->UpdateFiles) && (Command=='E' || Command=='X'))
    {
      FindData FD;
      if (FindFile::FastFind(DestFileName,&FD))
      {
        if (FD.mtime >= Arc.FileHead.mtime)
        {
          // If directory already exists and its modification time is newer 
          // than start of extraction, it is likely it was created 
          // when creating a path to one of already extracted items. 
          // In such case we'll better update its time even if archived 
          // directory is older.

          if (!FD.IsDir || FD.mtime<StartTime)
            ExtrFile=false;
        }
      }
      else
        if (Cmd->FreshFiles)
          ExtrFile=false;
    }

    if (!CheckUnpVer(Arc,ArcFileName))
    {
      ErrHandler.SetErrorCode(RARX_FATAL);
#ifdef RARDLL
      Cmd->DllError=ERAR_UNKNOWN_FORMAT;
#endif
      Arc.SeekToNext();
      return !Arc.Solid; // Can try extracting next file only in non-solid archive.
    }

    while (true) // Repeat the password prompt for wrong and empty passwords.
    {
      if (Arc.FileHead.Encrypted)
      {
        // Stop archive extracting if user cancelled a password prompt.
#ifdef RARDLL
        if (!ExtrDllGetPassword())
        {
          Cmd->DllError=ERAR_MISSING_PASSWORD;
          return false;
        }
#else
        if (!ExtrGetPassword(Arc,ArcFileName))
        {
          PasswordCancelled=true;
          return false;
        }
#endif
      }

      // Set a password before creating the file, so we can skip creating
      // in case of wrong password.
      SecPassword FilePassword=Cmd->Password;
#if defined(_WIN_ALL) && !defined(SFX_MODULE)
      ConvertDosPassword(Arc,FilePassword);
#endif

      byte PswCheck[SIZE_PSWCHECK];
      DataIO.SetEncryption(false,Arc.FileHead.CryptMethod,&FilePassword,
             Arc.FileHead.SaltSet ? Arc.FileHead.Salt:NULL,
             Arc.FileHead.InitV,Arc.FileHead.Lg2Count,
             Arc.FileHead.HashKey,PswCheck);

      // If header is damaged, we cannot rely on password check value,
      // because it can be damaged too.
      if (Arc.FileHead.Encrypted && Arc.FileHead.UsePswCheck &&
          memcmp(Arc.FileHead.PswCheck,PswCheck,SIZE_PSWCHECK)!=0 &&
          !Arc.BrokenHeader)
      {
        if (GlobalPassword) // For -p<pwd> or Ctrl+P to avoid the infinite loop.
        {
          // This message is used by Android GUI to reset cached passwords.
          // Update appropriate code if changed.
          uiMsg(UIERROR_BADPSW,Arc.FileName,ArcFileName);
        }
        else // For passwords entered manually.
        {
          // This message is used by Android GUI and Windows GUI and SFX to
          // reset cached passwords. Update appropriate code if changed.
          uiMsg(UIWAIT_BADPSW,Arc.FileName,ArcFileName);
          Cmd->Password.Clean();

          // Avoid new requests for unrar.dll to prevent the infinite loop
          // if app always returns the same password.
#ifndef RARDLL
          continue; // Request a password again.
#endif
        }
#ifdef RARDLL
        // If we already have ERAR_EOPEN as result of missing volume,
        // we should not replace it with less precise ERAR_BAD_PASSWORD.
        if (Cmd->DllError!=ERAR_EOPEN)
          Cmd->DllError=ERAR_BAD_PASSWORD;
#endif
        ErrHandler.SetErrorCode(RARX_BADPWD);
        ExtrFile=false;
      }
      break;
    }

#ifdef RARDLL
    if (*Cmd->DllDestName!=0)
      wcsncpyz(DestFileName,Cmd->DllDestName,ASIZE(DestFileName));
#endif

    File CurFile;

    bool LinkEntry=Arc.FileHead.RedirType!=FSREDIR_NONE;
    if (LinkEntry && Arc.FileHead.RedirType!=FSREDIR_FILECOPY)
    {
      if (ExtrFile && Command!='P' && !Cmd->Test)
      {
        // Overwrite prompt for symbolic and hard links.
        bool UserReject=false;
        if (FileExist(DestFileName) && !UserReject)
          FileCreate(Cmd,NULL,DestFileName,ASIZE(DestFileName),&UserReject,Arc.FileHead.UnpSize,&Arc.FileHead.mtime);
        if (UserReject)
          ExtrFile=false;
      }
    }
    else
      if (Arc.IsArcDir())
      {
        if (!ExtrFile || Command=='P' || Command=='I' || Command=='E' || Cmd->ExclPath==EXCL_SKIPWHOLEPATH)
          return true;
        TotalFileCount++;
        ExtrCreateDir(Arc,ArcFileName);
        // It is important to not increment MatchedArgs here, so we extract
        // dir with its entire contents and not dir record only even if
        // dir record precedes files.
        return true;
      }
      else
        if (ExtrFile) // Create files and file copies (FSREDIR_FILECOPY).
          ExtrFile=ExtrCreateFile(Arc,CurFile);

    if (!ExtrFile && Arc.Solid)
    {
      SkipSolid=true;
      ExtrFile=true;

      // We changed SkipSolid, so we need to call uiStartFileExtract
      // with "Skip" parameter to change the operation status 
      // from "extracting" to "skipping". For example, it can be necessary
      // if user answered "No" to overwrite prompt when unpacking
      // a solid archive.
      if (!uiStartFileExtract(ArcFileName,false,false,true))
        return false;
    }
    if (ExtrFile)
    {
      // Set it in test mode, so we also test subheaders such as NTFS streams
      // after tested file.
      if (Cmd->Test)
        PrevProcessed=true;

      bool TestMode=Cmd->Test || SkipSolid; // Unpack to memory, not to disk.

      if (!SkipSolid)
      {
        if (!TestMode && Command!='P' && CurFile.IsDevice())
        {
          uiMsg(UIERROR_INVALIDNAME,Arc.FileName,DestFileName);
          ErrHandler.WriteError(Arc.FileName,DestFileName);
        }
        TotalFileCount++;
      }
      FileCount++;
      if (Command!='I' && !Cmd->DisableNames)
        if (SkipSolid)
          mprintf(St(MExtrSkipFile),ArcFileName);
        else
          switch(Cmd->Test ? 'T':Command) // "Test" can be also enabled by -t switch.
          {
            case 'T':
              mprintf(St(MExtrTestFile),ArcFileName);
              break;
#ifndef SFX_MODULE
            case 'P':
              mprintf(St(MExtrPrinting),ArcFileName);
              break;
#endif
            case 'X':
            case 'E':
              mprintf(St(MExtrFile),DestFileName);
              break;
          }
      if (!Cmd->DisablePercentage && !Cmd->DisableNames)
        mprintf(L"     ");
      if (Cmd->DisableNames)
        uiEolAfterMsg(); // Avoid erasing preceding messages by percentage indicator in -idn mode.

      DataIO.CurUnpRead=0;
      DataIO.CurUnpWrite=0;
      DataIO.UnpHash.Init(Arc.FileHead.FileHash.Type,Cmd->Threads);
      DataIO.PackedDataHash.Init(Arc.FileHead.FileHash.Type,Cmd->Threads);
      DataIO.SetPackedSizeToRead(Arc.FileHead.PackSize);
      DataIO.SetFiles(&Arc,&CurFile);
      DataIO.SetTestMode(TestMode);
      DataIO.SetSkipUnpCRC(SkipSolid);

#if defined(_WIN_ALL) && !defined(SFX_MODULE) && !defined(SILENT)
      if (!TestMode && !Arc.BrokenHeader &&
          Arc.FileHead.UnpSize>0xffffffff && (Fat32 || !NotFat32))
      {
        if (!Fat32) // Not detected yet.
          NotFat32=!(Fat32=IsFAT(Cmd->ExtrPath));
        if (Fat32)
          uiMsg(UIMSG_FAT32SIZE); // Inform user about FAT32 size limit.
      }
#endif

      uint64 Preallocated=0;
      if (!TestMode && !Arc.BrokenHeader && Arc.FileHead.UnpSize>1000000 &&
          Arc.FileHead.PackSize*1024>Arc.FileHead.UnpSize &&
          (Arc.FileHead.UnpSize<100000000 || Arc.FileLength()>Arc.FileHead.PackSize))
      {
        CurFile.Prealloc(Arc.FileHead.UnpSize);
        Preallocated=Arc.FileHead.UnpSize;
      }
      CurFile.SetAllowDelete(!Cmd->KeepBroken);

      bool FileCreateMode=!TestMode && !SkipSolid && Command!='P';
      bool ShowChecksum=true; // Display checksum verification result.

      bool LinkSuccess=true; // Assume success for test mode.
      if (LinkEntry)
      {
        FILE_SYSTEM_REDIRECT Type=Arc.FileHead.RedirType;

        if (Type==FSREDIR_HARDLINK || Type==FSREDIR_FILECOPY)
        {
          wchar NameExisting[NM];
          ExtrPrepareName(Arc,Arc.FileHead.RedirName,NameExisting,ASIZE(NameExisting));
          if (FileCreateMode && *NameExisting!=0) // *NameExisting can be 0 in case of excessive -ap switch.
            if (Type==FSREDIR_HARDLINK)
              LinkSuccess=ExtractHardlink(Cmd,DestFileName,NameExisting,ASIZE(NameExisting));
            else
              LinkSuccess=ExtractFileCopy(CurFile,Arc.FileName,DestFileName,NameExisting,ASIZE(NameExisting));
        }
        else
          if (Type==FSREDIR_UNIXSYMLINK || Type==FSREDIR_WINSYMLINK || Type==FSREDIR_JUNCTION)
          {
            if (FileCreateMode)
              LinkSuccess=ExtractSymlink(Cmd,DataIO,Arc,DestFileName);
          }
          else
          {
            uiMsg(UIERROR_UNKNOWNEXTRA,Arc.FileName,DestFileName);
            LinkSuccess=false;
          }
          
          if (!LinkSuccess || Arc.Format==RARFMT15 && !FileCreateMode)
          {
            // RAR 5.x links have a valid data checksum even in case of
            // failure, because they do not store any data.
            // We do not want to display "OK" in this case.
            // For 4.x symlinks we verify the checksum only when extracting,
            // but not when testing an archive.
            ShowChecksum=false;
          }
          PrevProcessed=FileCreateMode && LinkSuccess;
      }
      else
        if (!Arc.FileHead.SplitBefore)
          if (Arc.FileHead.Method==0)
            UnstoreFile(DataIO,Arc.FileHead.UnpSize);
          else
          {
            Unp->Init(Arc.FileHead.WinSize,Arc.FileHead.Solid);
            Unp->SetDestSize(Arc.FileHead.UnpSize);
#ifndef SFX_MODULE
            if (Arc.Format!=RARFMT50 && Arc.FileHead.UnpVer<=15)
              Unp->DoUnpack(15,FileCount>1 && Arc.Solid);
            else
#endif
              Unp->DoUnpack(Arc.FileHead.UnpVer,Arc.FileHead.Solid);
          }

      Arc.SeekToNext();

      // We check for "split after" flag to detect partially extracted files
      // from incomplete volume sets. For them file header contains packed
      // data hash, which must not be compared against unpacked data hash
      // to prevent accidental match. Moreover, for -m0 volumes packed data
      // hash would match truncated unpacked data hash and lead to fake "OK"
      // in incomplete volume set.
      bool ValidCRC=!Arc.FileHead.SplitAfter && DataIO.UnpHash.Cmp(&Arc.FileHead.FileHash,Arc.FileHead.UseHashKey ? Arc.FileHead.HashKey:NULL);

      // We set AnySolidDataUnpackedWell to true if we found at least one
      // valid non-zero solid file in preceding solid stream. If it is true
      // and if current encrypted file is broken, we do not need to hint
      // about a wrong password and can report CRC error only.
      if (!Arc.FileHead.Solid)
        AnySolidDataUnpackedWell=false; // Reset the flag, because non-solid file is found.
      else
        if (Arc.FileHead.Method!=0 && Arc.FileHead.UnpSize>0 && ValidCRC)
          AnySolidDataUnpackedWell=true;
 
      bool BrokenFile=false;
      
      // Checksum is not calculated in skip solid mode for performance reason.
      if (!SkipSolid && ShowChecksum)
      {
        if (ValidCRC)
        {
          if (Command!='P' && Command!='I' && !Cmd->DisableNames)
            mprintf(L"%s%s ",Cmd->DisablePercentage ? L" ":L"\b\b\b\b\b ",
              Arc.FileHead.FileHash.Type==HASH_NONE ? L"  ?":St(MOk));
        }
        else
        {
          if (Arc.FileHead.Encrypted && (!Arc.FileHead.UsePswCheck || 
              Arc.BrokenHeader) && !AnySolidDataUnpackedWell)
            uiMsg(UIERROR_CHECKSUMENC,Arc.FileName,ArcFileName);
          else
            uiMsg(UIERROR_CHECKSUM,Arc.FileName,ArcFileName);
          BrokenFile=true;
          ErrHandler.SetErrorCode(RARX_CRC);
#ifdef RARDLL
          // If we already have ERAR_EOPEN as result of missing volume
          // or ERAR_BAD_PASSWORD for RAR5 wrong password,
          // we should not replace it with less precise ERAR_BAD_DATA.
          if (Cmd->DllError!=ERAR_EOPEN && Cmd->DllError!=ERAR_BAD_PASSWORD)
            Cmd->DllError=ERAR_BAD_DATA;
#endif
        }
      }
      else
      {
        // We check SkipSolid to remove percent for skipped solid files only.
        // We must not apply these \b to links with ShowChecksum==false
        // and their possible error messages.
        if (SkipSolid) 
          mprintf(L"\b\b\b\b\b     ");
      }

      // If we successfully unpacked a hard link, we wish to set its file
      // attributes. Hard link shares file metadata with link target,
      // so we do not need to set link time or owner. But when we overwrite
      // an existing link, we can call PrepareToDelete(), which affects
      // link target attributes as well. So we set link attributes to restore
      // both target and link attributes if PrepareToDelete() changed them.
      bool SetAttrOnly=LinkEntry && Arc.FileHead.RedirType==FSREDIR_HARDLINK && LinkSuccess;

      if (!TestMode && (Command=='X' || Command=='E') &&
          (!LinkEntry || SetAttrOnly || Arc.FileHead.RedirType==FSREDIR_FILECOPY && LinkSuccess) && 
          (!BrokenFile || Cmd->KeepBroken))
      {
        // Below we use DestFileName instead of CurFile.FileName,
        // so we can set file attributes also for hard links, which do not
        // have the open CurFile. These strings are the same for other items.

        if (!SetAttrOnly)
        {
          // We could preallocate more space that really written to broken file
          // or file with crafted header.
          if (Preallocated>0 && (BrokenFile || DataIO.CurUnpWrite!=Preallocated))
            CurFile.Truncate();


          CurFile.SetOpenFileTime(
            Cmd->xmtime==EXTTIME_NONE ? NULL:&Arc.FileHead.mtime,
            Cmd->xctime==EXTTIME_NONE ? NULL:&Arc.FileHead.ctime,
            Cmd->xatime==EXTTIME_NONE ? NULL:&Arc.FileHead.atime);
          CurFile.Close();

          SetFileHeaderExtra(Cmd,Arc,DestFileName);

          CurFile.SetCloseFileTime(
            Cmd->xmtime==EXTTIME_NONE ? NULL:&Arc.FileHead.mtime,
            Cmd->xatime==EXTTIME_NONE ? NULL:&Arc.FileHead.atime);
        }
        
#if defined(_WIN_ALL) && !defined(SFX_MODULE)
        if (Cmd->SetCompressedAttr &&
            (Arc.FileHead.FileAttr & FILE_ATTRIBUTE_COMPRESSED)!=0)
          SetFileCompression(DestFileName,true);
        if (Cmd->ClearArc)
          Arc.FileHead.FileAttr&=~FILE_ATTRIBUTE_ARCHIVE;
#endif
        if (!Cmd->IgnoreGeneralAttr && !SetFileAttr(DestFileName,Arc.FileHead.FileAttr))
        {
          uiMsg(UIERROR_FILEATTR,Arc.FileName,DestFileName);
          // Android cannot set file attributes and while UIERROR_FILEATTR
          // above is handled by Android RAR silently, this call would cause
          // "Operation not permitted" message for every unpacked file.
          ErrHandler.SysErrMsg();
        }

        PrevProcessed=true;
      }
    }
  }
  // It is important to increment it for files, but not dirs. So we extract
  // dir with its entire contents, not just dir record only even if dir
  // record precedes files.
  if (MatchFound)
    MatchedArgs++;
  if (DataIO.NextVolumeMissing)
    return false;
  if (!ExtrFile)
    if (!Arc.Solid)
      Arc.SeekToNext();
    else
      if (!SkipSolid)
        return false;
  return true;
}


void CmdExtract::UnstoreFile(ComprDataIO &DataIO,int64 DestUnpSize)
{
  Array<byte> Buffer(File::CopyBufferSize());
  while (true)
  {
    int ReadSize=DataIO.UnpRead(&Buffer[0],Buffer.Size());
    if (ReadSize<=0)
      break;
    int WriteSize=ReadSize<DestUnpSize ? ReadSize:(int)DestUnpSize;
    if (WriteSize>0)
    {
      DataIO.UnpWrite(&Buffer[0],WriteSize);
      DestUnpSize-=WriteSize;
    }
  }
}


bool CmdExtract::ExtractFileCopy(File &New,wchar *ArcName,wchar *NameNew,wchar *NameExisting,size_t NameExistingSize)
{
  SlashToNative(NameExisting,NameExisting,NameExistingSize); // Not needed for RAR 5.1+ archives.

  File Existing;
  if (!Existing.WOpen(NameExisting))
  {
    uiMsg(UIERROR_FILECOPY,ArcName,NameExisting,NameNew);
    uiMsg(UIERROR_FILECOPYHINT,ArcName);
#ifdef RARDLL
    Cmd->DllError=ERAR_EREFERENCE;
#endif
    return false;
  }

  Array<char> Buffer(0x100000);
  int64 CopySize=0;

  while (true)
  {
    Wait();
    int ReadSize=Existing.Read(&Buffer[0],Buffer.Size());
    if (ReadSize==0)
      break;
    New.Write(&Buffer[0],ReadSize);
    CopySize+=ReadSize;
  }

  return true;
}


void CmdExtract::ExtrPrepareName(Archive &Arc,const wchar *ArcFileName,wchar *DestName,size_t DestSize)
{
  wcsncpyz(DestName,Cmd->ExtrPath,DestSize);

  if (*Cmd->ExtrPath!=0)
  {
     wchar LastChar=*PointToLastChar(Cmd->ExtrPath);
    // We need IsPathDiv check here to correctly handle Unix forward slash
    // in the end of destination path in Windows: rar x arc dest/
    // IsDriveDiv is needed for current drive dir: rar x arc d:
    if (!IsPathDiv(LastChar) && !IsDriveDiv(LastChar))
    {
      // Destination path can be without trailing slash if it come from GUI shell.
      AddEndSlash(DestName,DestSize);
    }
  }

#ifndef SFX_MODULE
  if (Cmd->AppendArcNameToPath!=APPENDARCNAME_NONE)
  {
    switch(Cmd->AppendArcNameToPath)
    {
      case APPENDARCNAME_DESTPATH: // To subdir of destination path.
        wcsncatz(DestName,PointToName(Arc.FirstVolumeName),DestSize);
        SetExt(DestName,NULL,DestSize);
        break;
      case APPENDARCNAME_OWNSUBDIR: // To subdir of archive own dir.
        wcsncpyz(DestName,Arc.FirstVolumeName,DestSize);
        SetExt(DestName,NULL,DestSize);
        break;
      case APPENDARCNAME_OWNDIR:  // To archive own dir.
        wcsncpyz(DestName,Arc.FirstVolumeName,DestSize);
        RemoveNameFromPath(DestName);
        break;
    }
    AddEndSlash(DestName,DestSize);
  }
#endif

#ifndef SFX_MODULE
  size_t ArcPathLength=wcslen(Cmd->ArcPath);
  if (ArcPathLength>0)
  {
    size_t NameLength=wcslen(ArcFileName);

    // Earlier we compared lengths only here, but then noticed a cosmetic bug
    // in WinRAR. When extracting a file reference from subfolder with
    // "Extract relative paths", so WinRAR sets ArcPath, if reference target
    // is missing, error message removed ArcPath both from reference and target
    // names. If target was stored in another folder, its name looked wrong.
    if (NameLength>=ArcPathLength && 
        wcsnicompc(Cmd->ArcPath,ArcFileName,ArcPathLength)==0 &&
        (IsPathDiv(Cmd->ArcPath[ArcPathLength-1]) || 
         IsPathDiv(ArcFileName[ArcPathLength]) || ArcFileName[ArcPathLength]==0))
    {
      ArcFileName+=Min(ArcPathLength,NameLength);
      while (IsPathDiv(*ArcFileName))
        ArcFileName++;
      if (*ArcFileName==0) // Excessive -ap switch.
      {
        *DestName=0;
        return;
      }
    }
  }
#endif

  wchar Command=Cmd->Command[0];
  // Use -ep3 only in systems, where disk letters are exist, not in Unix.
  bool AbsPaths=Cmd->ExclPath==EXCL_ABSPATH && Command=='X' && IsDriveDiv(':');

  // We do not use any user specified destination paths when extracting
  // absolute paths in -ep3 mode.
  if (AbsPaths)
    *DestName=0;

  if (Command=='E' || Cmd->ExclPath==EXCL_SKIPWHOLEPATH)
    wcsncatz(DestName,PointToName(ArcFileName),DestSize);
  else
    wcsncatz(DestName,ArcFileName,DestSize);

#ifdef _WIN_ALL
  // Must do after Cmd->ArcPath processing above, so file name and arc path
  // trailing spaces are in sync.
  if (!Cmd->AllowIncompatNames)
    MakeNameCompatible(DestName);
#endif

  wchar DiskLetter=toupperw(DestName[0]);

  if (AbsPaths)
  {
    if (DestName[1]=='_' && IsPathDiv(DestName[2]) &&
        DiskLetter>='A' && DiskLetter<='Z')
      DestName[1]=':';
    else
      if (DestName[0]=='_' && DestName[1]=='_')
      {
        // Convert __server\share to \\server\share.
        DestName[0]=CPATHDIVIDER;
        DestName[1]=CPATHDIVIDER;
      }
  }
}


#ifdef RARDLL
bool CmdExtract::ExtrDllGetPassword()
{
  if (!Cmd->Password.IsSet())
  {
    if (Cmd->Callback!=NULL)
    {
      wchar PasswordW[MAXPASSWORD];
      *PasswordW=0;
      if (Cmd->Callback(UCM_NEEDPASSWORDW,Cmd->UserData,(LPARAM)PasswordW,ASIZE(PasswordW))==-1)
        *PasswordW=0;
      if (*PasswordW==0)
      {
        char PasswordA[MAXPASSWORD];
        *PasswordA=0;
        if (Cmd->Callback(UCM_NEEDPASSWORD,Cmd->UserData,(LPARAM)PasswordA,ASIZE(PasswordA))==-1)
          *PasswordA=0;
        GetWideName(PasswordA,NULL,PasswordW,ASIZE(PasswordW));
        cleandata(PasswordA,sizeof(PasswordA));
      }
      Cmd->Password.Set(PasswordW);
      cleandata(PasswordW,sizeof(PasswordW));
      Cmd->ManualPassword=true;
    }
    if (!Cmd->Password.IsSet())
      return false;
  }
  return true;
}
#endif


#ifndef RARDLL
bool CmdExtract::ExtrGetPassword(Archive &Arc,const wchar *ArcFileName)
{
  if (!Cmd->Password.IsSet())
  {
    if (!uiGetPassword(UIPASSWORD_FILE,ArcFileName,&Cmd->Password)/* || !Cmd->Password.IsSet()*/)
    {
      // Suppress "test is ok" message if user cancelled the password prompt.
// 2019.03.23: If some archives are tested ok and prompt is cancelled for others,
// do we really need to suppress "test is ok"? Also if we set an empty password
// and "Use for all archives" in WinRAR Ctrl+P and skip some encrypted archives.
// We commented out this UIERROR_INCERRCOUNT for now.
//      uiMsg(UIERROR_INCERRCOUNT);
      return false;
    }
    Cmd->ManualPassword=true;
  }
#if !defined(SILENT)
  else
    if (!GlobalPassword && !Arc.FileHead.Solid)
    {
      eprintf(St(MUseCurPsw),ArcFileName);
      switch(Cmd->AllYes ? 1 : Ask(St(MYesNoAll)))
      {
        case -1:
          ErrHandler.Exit(RARX_USERBREAK);
        case 2:
          if (!uiGetPassword(UIPASSWORD_FILE,ArcFileName,&Cmd->Password))
            return false;
          break;
        case 3:
          GlobalPassword=true;
          break;
      }
    }
#endif
  return true;
}
#endif


#if defined(_WIN_ALL) && !defined(SFX_MODULE)
void CmdExtract::ConvertDosPassword(Archive &Arc,SecPassword &DestPwd)
{
  if (Arc.Format==RARFMT15 && Arc.FileHead.HostOS==HOST_MSDOS)
  {
    // We need the password in OEM encoding if file was encrypted by
    // native RAR/DOS (not extender based). Let's make the conversion.
    wchar PlainPsw[MAXPASSWORD];
    Cmd->Password.Get(PlainPsw,ASIZE(PlainPsw));
    char PswA[MAXPASSWORD];
    CharToOemBuffW(PlainPsw,PswA,ASIZE(PswA));
    PswA[ASIZE(PswA)-1]=0;
    CharToWide(PswA,PlainPsw,ASIZE(PlainPsw));
    DestPwd.Set(PlainPsw);
    cleandata(PlainPsw,sizeof(PlainPsw));
    cleandata(PswA,sizeof(PswA));
  }
}
#endif


void CmdExtract::ExtrCreateDir(Archive &Arc,const wchar *ArcFileName)
{
  if (Cmd->Test)
  {
    if (!Cmd->DisableNames)
    {
      mprintf(St(MExtrTestFile),ArcFileName);
      mprintf(L" %s",St(MOk));
    }
    return;
  }

  MKDIR_CODE MDCode=MakeDir(DestFileName,!Cmd->IgnoreGeneralAttr,Arc.FileHead.FileAttr);
  bool DirExist=false;
  if (MDCode!=MKDIR_SUCCESS)
  {
    DirExist=FileExist(DestFileName);
    if (DirExist && !IsDir(GetFileAttr(DestFileName)))
    {
      // File with name same as this directory exists. Propose user
      // to overwrite it.
      bool UserReject;
      FileCreate(Cmd,NULL,DestFileName,ASIZE(DestFileName),&UserReject,Arc.FileHead.UnpSize,&Arc.FileHead.mtime);
      DirExist=false;
    }
    if (!DirExist)
    {
      CreatePath(DestFileName,true,Cmd->DisableNames);
      MDCode=MakeDir(DestFileName,!Cmd->IgnoreGeneralAttr,Arc.FileHead.FileAttr);
      if (MDCode!=MKDIR_SUCCESS && !IsNameUsable(DestFileName))
      {
        uiMsg(UIMSG_CORRECTINGNAME,Arc.FileName);
        wchar OrigName[ASIZE(DestFileName)];
        wcsncpyz(OrigName,DestFileName,ASIZE(OrigName));
        MakeNameUsable(DestFileName,true);
#ifndef SFX_MODULE
        uiMsg(UIERROR_RENAMING,Arc.FileName,OrigName,DestFileName);
#endif
        DirExist=FileExist(DestFileName) && IsDir(GetFileAttr(DestFileName));
        if (!DirExist)
        {
          CreatePath(DestFileName,true,Cmd->DisableNames);
          MDCode=MakeDir(DestFileName,!Cmd->IgnoreGeneralAttr,Arc.FileHead.FileAttr);
        }
      }
    }
  }
  if (MDCode==MKDIR_SUCCESS)
  {
    if (!Cmd->DisableNames)
    {
      mprintf(St(MCreatDir),DestFileName);
      mprintf(L" %s",St(MOk));
    }
    PrevProcessed=true;
  }
  else
    if (DirExist)
    {
      if (!Cmd->IgnoreGeneralAttr)
        SetFileAttr(DestFileName,Arc.FileHead.FileAttr);
      PrevProcessed=true;
    }
    else
    {
      uiMsg(UIERROR_DIRCREATE,Arc.FileName,DestFileName);
      ErrHandler.SysErrMsg();
#ifdef RARDLL
      Cmd->DllError=ERAR_ECREATE;
#endif
      ErrHandler.SetErrorCode(RARX_CREATE);
    }
  if (PrevProcessed)
  {
#if defined(_WIN_ALL) && !defined(SFX_MODULE)
    if (Cmd->SetCompressedAttr &&
        (Arc.FileHead.FileAttr & FILE_ATTRIBUTE_COMPRESSED)!=0 && WinNT()!=WNT_NONE)
      SetFileCompression(DestFileName,true);
#endif
    SetFileHeaderExtra(Cmd,Arc,DestFileName);
    SetDirTime(DestFileName,
      Cmd->xmtime==EXTTIME_NONE ? NULL:&Arc.FileHead.mtime,
      Cmd->xctime==EXTTIME_NONE ? NULL:&Arc.FileHead.ctime,
      Cmd->xatime==EXTTIME_NONE ? NULL:&Arc.FileHead.atime);
  }
}


bool CmdExtract::ExtrCreateFile(Archive &Arc,File &CurFile)
{
  bool Success=true;
  wchar Command=Cmd->Command[0];
#if !defined(SFX_MODULE)
  if (Command=='P')
    CurFile.SetHandleType(FILE_HANDLESTD);
#endif
  if ((Command=='E' || Command=='X') && !Cmd->Test)
  {
    bool UserReject;
    // Specify "write only" mode to avoid OpenIndiana NAS problems
    // with SetFileTime and read+write files.
    if (!FileCreate(Cmd,&CurFile,DestFileName,ASIZE(DestFileName),&UserReject,Arc.FileHead.UnpSize,&Arc.FileHead.mtime,true))
    {
      Success=false;
      if (!UserReject)
      {
        ErrHandler.CreateErrorMsg(Arc.FileName,DestFileName);
        if (FileExist(DestFileName) && IsDir(GetFileAttr(DestFileName)))
          uiMsg(UIERROR_DIRNAMEEXISTS);

#ifdef RARDLL
        Cmd->DllError=ERAR_ECREATE;
#endif
        if (!IsNameUsable(DestFileName))
        {
          uiMsg(UIMSG_CORRECTINGNAME,Arc.FileName);

          wchar OrigName[ASIZE(DestFileName)];
          wcsncpyz(OrigName,DestFileName,ASIZE(OrigName));

          MakeNameUsable(DestFileName,true);

          CreatePath(DestFileName,true,Cmd->DisableNames);
          if (FileCreate(Cmd,&CurFile,DestFileName,ASIZE(DestFileName),&UserReject,Arc.FileHead.UnpSize,&Arc.FileHead.mtime,true))
          {
#ifndef SFX_MODULE
            uiMsg(UIERROR_RENAMING,Arc.FileName,OrigName,DestFileName);
#endif
            Success=true;
          }
          else
            ErrHandler.CreateErrorMsg(Arc.FileName,DestFileName);
        }
      }
    }
  }
  return Success;
}


bool CmdExtract::CheckUnpVer(Archive &Arc,const wchar *ArcFileName)
{
  bool WrongVer;
  if (Arc.Format==RARFMT50) // Both SFX and RAR can unpack RAR 5.0 archives.
    WrongVer=Arc.FileHead.UnpVer>VER_UNPACK5;
  else
  {
#ifdef SFX_MODULE   // SFX can unpack only RAR 2.9 archives.
    WrongVer=Arc.FileHead.UnpVer!=VER_UNPACK;
#else               // All formats since 1.3 for RAR.
    WrongVer=Arc.FileHead.UnpVer<13 || Arc.FileHead.UnpVer>VER_UNPACK;
#endif
  }

  // We can unpack stored files regardless of compression version field.
  if (Arc.FileHead.Method==0)
    WrongVer=false;

  if (WrongVer)
  {
    ErrHandler.UnknownMethodMsg(Arc.FileName,ArcFileName);
    uiMsg(UIERROR_NEWERRAR,Arc.FileName);
  }
  return !WrongVer;
}


#ifndef SFX_MODULE
// To speed up solid volumes extraction, try to find a non-first start volume,
// which still allows to unpack all files. It is possible for independent
// solid volumes with solid statistics reset in the beginning.
bool CmdExtract::DetectStartVolume(const wchar *VolName,bool NewNumbering)
{
  wchar *ArgName=Cmd->FileArgs.GetString();
  Cmd->FileArgs.Rewind();
  if (ArgName!=NULL && (wcscmp(ArgName,L"*")==0 || wcscmp(ArgName,L"*.*")==0))
    return false; // No need to check further for * and *.* masks.

  wchar StartName[NM];
  *StartName=0;
  
  // Start search from first volume if all volumes preceding current are available.
  wchar NextName[NM];
  GetFirstVolIfFullSet(VolName,NewNumbering,NextName,ASIZE(NextName));

  bool Matched=false;
  while (!Matched)
  {
    Archive Arc(Cmd);
    if (!Arc.Open(NextName) || !Arc.IsArchive(false) || !Arc.Volume)
      break;

    bool OpenNext=false;
    while (Arc.ReadHeader()>0)
    {
      Wait();

      HEADER_TYPE HeaderType=Arc.GetHeaderType();
      if (HeaderType==HEAD_ENDARC)
      {
        OpenNext|=Arc.EndArcHead.NextVolume; // Allow open next volume.
        break;
      }
      if (HeaderType==HEAD_FILE)
      {
        if (!Arc.FileHead.SplitBefore)
        {
          if (!Arc.FileHead.Solid) // Can start extraction from here.
            wcsncpyz(StartName,NextName,ASIZE(StartName));

          if (Cmd->IsProcessFile(Arc.FileHead,NULL,MATCH_WILDSUBPATH,0,NULL,0)!=0)
          {
            Matched=true; // First matched file found, must stop further scan.
            break;
          }
        }
        if (Arc.FileHead.SplitAfter)
        {
          OpenNext=true; // Allow open next volume.
          break;
        }
      }
      Arc.SeekToNext();
    }
    Arc.Close();

    if (!OpenNext)
      break;

    NextVolumeName(NextName,ASIZE(NextName),!Arc.NewNumbering);
  }
  bool NewStartFound=wcscmp(VolName,StartName)!=0;
  if (NewStartFound) // Found a new volume to start extraction.
    wcsncpyz(ArcName,StartName,ASIZE(ArcName));
  
  return NewStartFound;
}
#endif


#ifndef SFX_MODULE
// Return the first volume name if all volumes preceding the specified
// are available. Otherwise return the specified volume name.
void CmdExtract::GetFirstVolIfFullSet(const wchar *SrcName,bool NewNumbering,wchar *DestName,size_t DestSize)
{
  wchar FirstVolName[NM];
  VolNameToFirstName(SrcName,FirstVolName,ASIZE(FirstVolName),NewNumbering);
  wchar NextName[NM];
  wcsncpyz(NextName,FirstVolName,ASIZE(NextName));
  wchar ResultName[NM];
  wcsncpyz(ResultName,SrcName,ASIZE(ResultName));
  while (true)
  {
    if (wcscmp(SrcName,NextName)==0)
    {
      wcsncpyz(ResultName,FirstVolName,DestSize);
      break;
    }
    if (!FileExist(NextName))
      break;
    NextVolumeName(NextName,ASIZE(NextName),!NewNumbering);
  }
  wcsncpyz(DestName,ResultName,DestSize);
}

#endif
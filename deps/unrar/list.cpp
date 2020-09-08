#include "rar.hpp"

static void ListFileHeader(Archive &Arc,FileHeader &hd,bool &TitleShown,bool Verbose,bool Technical,bool Bare);
static void ListSymLink(Archive &Arc);
static void ListFileAttr(uint A,HOST_SYSTEM_TYPE HostType,wchar *AttrStr,size_t AttrSize);
static void ListOldSubHeader(Archive &Arc);
static void ListNewSubHeader(CommandData *Cmd,Archive &Arc);

void ListArchive(CommandData *Cmd)
{
  int64 SumPackSize=0,SumUnpSize=0;
  uint ArcCount=0,SumFileCount=0;
  bool Technical=(Cmd->Command[1]=='T');
  bool ShowService=Technical && Cmd->Command[2]=='A';
  bool Bare=(Cmd->Command[1]=='B');
  bool Verbose=(Cmd->Command[0]=='V');

  wchar ArcName[NM];
  while (Cmd->GetArcName(ArcName,ASIZE(ArcName)))
  {
    if (Cmd->ManualPassword)
      Cmd->Password.Clean(); // Clean user entered password before processing next archive.

    Archive Arc(Cmd);
#ifdef _WIN_ALL
    Arc.RemoveSequentialFlag();
#endif
    if (!Arc.WOpen(ArcName))
      continue;
    bool FileMatched=true;
    while (1)
    {
      int64 TotalPackSize=0,TotalUnpSize=0;
      uint FileCount=0;
      if (Arc.IsArchive(true))
      {
        bool TitleShown=false;
        if (!Bare)
        {
          Arc.ViewComment();
          mprintf(L"\n%s: %s",St(MListArchive),Arc.FileName);
          mprintf(L"\n%s: ",St(MListDetails));
          uint SetCount=0;
          const wchar *Fmt=Arc.Format==RARFMT14 ? L"RAR 1.4":(Arc.Format==RARFMT15 ? L"RAR 4":L"RAR 5");
          mprintf(L"%s%s", SetCount++ > 0 ? L", ":L"", Fmt);
          if (Arc.Solid)
            mprintf(L"%s%s", SetCount++ > 0 ? L", ":L"", St(MListSolid));
          if (Arc.SFXSize>0)
            mprintf(L"%s%s", SetCount++ > 0 ? L", ":L"", St(MListSFX));
          if (Arc.Volume)
            if (Arc.Format==RARFMT50)
            {
              // RAR 5.0 archives store the volume number in main header,
              // so it is already available now.
              if (SetCount++ > 0)
                mprintf(L", ");
              mprintf(St(MVolumeNumber),Arc.VolNumber+1);
            }
            else
              mprintf(L"%s%s", SetCount++ > 0 ? L", ":L"", St(MListVolume));
          if (Arc.Protected)
            mprintf(L"%s%s", SetCount++ > 0 ? L", ":L"", St(MListRR));
          if (Arc.Locked)
            mprintf(L"%s%s", SetCount++ > 0 ? L", ":L"", St(MListLock));
          if (Arc.Encrypted)
            mprintf(L"%s%s", SetCount++ > 0 ? L", ":L"", St(MListEncHead));
          mprintf(L"\n");
        }

        wchar VolNumText[50];
        *VolNumText=0;
        while(Arc.ReadHeader()>0)
        {
          Wait(); // Allow quit listing with Ctrl+C.
          HEADER_TYPE HeaderType=Arc.GetHeaderType();
          if (HeaderType==HEAD_ENDARC)
          {
#ifndef SFX_MODULE
            // Only RAR 1.5 archives store the volume number in end record.
            if (Arc.EndArcHead.StoreVolNumber && Arc.Format==RARFMT15)
              swprintf(VolNumText,ASIZE(VolNumText),L"%.10ls %u",St(MListVolume),Arc.VolNumber+1);
#endif
            if (Technical && ShowService)
            {
              mprintf(L"\n%12ls: %ls",St(MListService),L"EOF");
              if (*VolNumText!=0)
                mprintf(L"\n%12ls: %ls",St(MListFlags),VolNumText);
              mprintf(L"\n");
            }
            break;
          }
          switch(HeaderType)
          {
            case HEAD_FILE:
              FileMatched=Cmd->IsProcessFile(Arc.FileHead,NULL,MATCH_WILDSUBPATH,0,NULL,0)!=0;
              if (FileMatched)
              {
                ListFileHeader(Arc,Arc.FileHead,TitleShown,Verbose,Technical,Bare);
                if (!Arc.FileHead.SplitBefore)
                {
                  TotalUnpSize+=Arc.FileHead.UnpSize;
                  FileCount++;
                }
                TotalPackSize+=Arc.FileHead.PackSize;
              }
              break;
            case HEAD_SERVICE:
              if (FileMatched && !Bare)
              {
                if (Technical && ShowService)
                  ListFileHeader(Arc,Arc.SubHead,TitleShown,Verbose,true,false);
              }
              break;
          }
          Arc.SeekToNext();
        }
        if (!Bare && !Technical)
          if (TitleShown)
          {
            wchar UnpSizeText[20];
            itoa(TotalUnpSize,UnpSizeText,ASIZE(UnpSizeText));
        
            wchar PackSizeText[20];
            itoa(TotalPackSize,PackSizeText,ASIZE(PackSizeText));
        
            if (Verbose)
            {
              mprintf(L"\n----------- ---------  -------- ----- ---------- -----  --------  ----");
              mprintf(L"\n%21ls %9ls %3d%%  %-27ls %u",UnpSizeText,
                      PackSizeText,ToPercentUnlim(TotalPackSize,TotalUnpSize),
                      VolNumText,FileCount);
            }
            else
            {
              mprintf(L"\n----------- ---------  ---------- -----  ----");
              mprintf(L"\n%21ls  %-16ls  %u",UnpSizeText,VolNumText,FileCount);
            }

            SumFileCount+=FileCount;
            SumUnpSize+=TotalUnpSize;
            SumPackSize+=TotalPackSize;
            mprintf(L"\n");
          }
          else
            mprintf(St(MListNoFiles));

        ArcCount++;

#ifndef NOVOLUME
        if (Cmd->VolSize!=0 && (Arc.FileHead.SplitAfter ||
            Arc.GetHeaderType()==HEAD_ENDARC && Arc.EndArcHead.NextVolume) &&
            MergeArchive(Arc,NULL,false,Cmd->Command[0]))
          Arc.Seek(0,SEEK_SET);
        else
#endif
          break;
      }
      else
      {
        if (Cmd->ArcNames.ItemsCount()<2 && !Bare)
          mprintf(St(MNotRAR),Arc.FileName);
        break;
      }
    }
  }

  // Clean user entered password. Not really required, just for extra safety.
  if (Cmd->ManualPassword)
    Cmd->Password.Clean();

  if (ArcCount>1 && !Bare && !Technical)
  {
    wchar UnpSizeText[20],PackSizeText[20];
    itoa(SumUnpSize,UnpSizeText,ASIZE(UnpSizeText));
    itoa(SumPackSize,PackSizeText,ASIZE(PackSizeText));

    if (Verbose)
      mprintf(L"%21ls %9ls %3d%% %28ls %u",UnpSizeText,PackSizeText,
              ToPercentUnlim(SumPackSize,SumUnpSize),L"",SumFileCount);
    else
      mprintf(L"%21ls %18s %lu",UnpSizeText,L"",SumFileCount);
  }
}


enum LISTCOL_TYPE {
  LCOL_NAME,LCOL_ATTR,LCOL_SIZE,LCOL_PACKED,LCOL_RATIO,LCOL_CSUM,LCOL_ENCR
};


void ListFileHeader(Archive &Arc,FileHeader &hd,bool &TitleShown,bool Verbose,bool Technical,bool Bare)
{
  wchar *Name=hd.FileName;
  RARFORMAT Format=Arc.Format;

  if (Bare)
  {
    mprintf(L"%s\n",Name);
    return;
  }

  if (!TitleShown && !Technical)
  {
    if (Verbose)
    {
      mprintf(L"\n%ls",St(MListTitleV));
      mprintf(L"\n----------- ---------  -------- ----- ---------- -----  --------  ----");
    }
    else
    {
      mprintf(L"\n%ls",St(MListTitleL));
      mprintf(L"\n----------- ---------  ---------- -----  ----");
    }
    TitleShown=true;
  }

  wchar UnpSizeText[30],PackSizeText[30];
  if (hd.UnpSize==INT64NDF)
    wcsncpyz(UnpSizeText,L"?",ASIZE(UnpSizeText));
  else
    itoa(hd.UnpSize,UnpSizeText,ASIZE(UnpSizeText));
  itoa(hd.PackSize,PackSizeText,ASIZE(PackSizeText));

  wchar AttrStr[30];
  if (hd.HeaderType==HEAD_SERVICE)
    swprintf(AttrStr,ASIZE(AttrStr),L"%cB",hd.Inherited ? 'I' : '.');
  else
    ListFileAttr(hd.FileAttr,hd.HSType,AttrStr,ASIZE(AttrStr));

  wchar RatioStr[10];

  if (hd.SplitBefore && hd.SplitAfter)
    wcsncpyz(RatioStr,L"<->",ASIZE(RatioStr));
  else
    if (hd.SplitBefore)
      wcsncpyz(RatioStr,L"<--",ASIZE(RatioStr));
    else
      if (hd.SplitAfter)
        wcsncpyz(RatioStr,L"-->",ASIZE(RatioStr));
      else
        swprintf(RatioStr,ASIZE(RatioStr),L"%d%%",ToPercentUnlim(hd.PackSize,hd.UnpSize));

  wchar DateStr[50];
  hd.mtime.GetText(DateStr,ASIZE(DateStr),Technical);

  if (Technical)
  {
    mprintf(L"\n%12s: %s",St(MListName),Name);

    bool FileBlock=hd.HeaderType==HEAD_FILE;

    if (!FileBlock && Arc.SubHead.CmpName(SUBHEAD_TYPE_STREAM))
    {
      mprintf(L"\n%12ls: %ls",St(MListType),St(MListStream));
      wchar StreamName[NM];
      GetStreamNameNTFS(Arc,StreamName,ASIZE(StreamName));
      mprintf(L"\n%12ls: %ls",St(MListTarget),StreamName);
    }
    else
    {
      const wchar *Type=St(FileBlock ? (hd.Dir ? MListDir:MListFile):MListService);
    
      if (hd.RedirType!=FSREDIR_NONE)
        switch(hd.RedirType)
        {
          case FSREDIR_UNIXSYMLINK:
            Type=St(MListUSymlink); break;
          case FSREDIR_WINSYMLINK:
            Type=St(MListWSymlink); break;
          case FSREDIR_JUNCTION:
            Type=St(MListJunction); break;
          case FSREDIR_HARDLINK:
            Type=St(MListHardlink); break;
          case FSREDIR_FILECOPY:
            Type=St(MListCopy);     break;
        }
      mprintf(L"\n%12ls: %ls",St(MListType),Type);
      if (hd.RedirType!=FSREDIR_NONE)
        if (Format==RARFMT15)
        {
          char LinkTargetA[NM];
          if (Arc.FileHead.Encrypted)
          {
            // Link data are encrypted. We would need to ask for password
            // and initialize decryption routine to display the link target.
            strncpyz(LinkTargetA,"*<-?->",ASIZE(LinkTargetA));
          }
          else
          {
            int DataSize=(int)Min(hd.PackSize,ASIZE(LinkTargetA)-1);
            Arc.Read(LinkTargetA,DataSize);
            LinkTargetA[DataSize > 0 ? DataSize : 0] = 0;
          }
          wchar LinkTarget[NM];
          CharToWide(LinkTargetA,LinkTarget,ASIZE(LinkTarget));
          mprintf(L"\n%12ls: %ls",St(MListTarget),LinkTarget);
        }
        else
          mprintf(L"\n%12ls: %ls",St(MListTarget),hd.RedirName);
    }
    if (!hd.Dir)
    {
      mprintf(L"\n%12ls: %ls",St(MListSize),UnpSizeText);
      mprintf(L"\n%12ls: %ls",St(MListPacked),PackSizeText);
      mprintf(L"\n%12ls: %ls",St(MListRatio),RatioStr);
    }
    if (hd.mtime.IsSet())
      mprintf(L"\n%12ls: %ls",St(MListMtime),DateStr);
    if (hd.ctime.IsSet())
    {
      hd.ctime.GetText(DateStr,ASIZE(DateStr),true);
      mprintf(L"\n%12ls: %ls",St(MListCtime),DateStr);
    }
    if (hd.atime.IsSet())
    {
      hd.atime.GetText(DateStr,ASIZE(DateStr),true);
      mprintf(L"\n%12ls: %ls",St(MListAtime),DateStr);
    }
    mprintf(L"\n%12ls: %ls",St(MListAttr),AttrStr);
    if (hd.FileHash.Type==HASH_CRC32)
      mprintf(L"\n%12ls: %8.8X",
        hd.UseHashKey ? L"CRC32 MAC":hd.SplitAfter ? L"Pack-CRC32":L"CRC32",
        hd.FileHash.CRC32);
    if (hd.FileHash.Type==HASH_BLAKE2)
    {
      wchar BlakeStr[BLAKE2_DIGEST_SIZE*2+1];
      BinToHex(hd.FileHash.Digest,BLAKE2_DIGEST_SIZE,NULL,BlakeStr,ASIZE(BlakeStr));
      mprintf(L"\n%12ls: %ls",
        hd.UseHashKey ? L"BLAKE2 MAC":hd.SplitAfter ? L"Pack-BLAKE2":L"BLAKE2",
        BlakeStr);
    }

    const wchar *HostOS=L"";
    if (Format==RARFMT50 && hd.HSType!=HSYS_UNKNOWN)
      HostOS=hd.HSType==HSYS_WINDOWS ? L"Windows":L"Unix";
    if (Format==RARFMT15)
    {
      static const wchar *RarOS[]={
        L"DOS",L"OS/2",L"Windows",L"Unix",L"Mac OS",L"BeOS",L"WinCE",L"",L"",L""
      };
      if (hd.HostOS<ASIZE(RarOS))
        HostOS=RarOS[hd.HostOS];
    }
    if (*HostOS!=0)
      mprintf(L"\n%12ls: %ls",St(MListHostOS),HostOS);

    mprintf(L"\n%12ls: RAR %ls(v%d) -m%d -md=%d%s",St(MListCompInfo),
            Format==RARFMT15 ? L"1.5":L"5.0",
            hd.UnpVer==VER_UNKNOWN ? 0 : hd.UnpVer,hd.Method,
            hd.WinSize>=0x100000 ? hd.WinSize/0x100000:hd.WinSize/0x400,
            hd.WinSize>=0x100000 ? L"M":L"K");

    if (hd.Solid || hd.Encrypted)
    {
      mprintf(L"\n%12ls: ",St(MListFlags));
      if (hd.Solid)
        mprintf(L"%ls ",St(MListSolid));
      if (hd.Encrypted)
        mprintf(L"%ls ",St(MListEnc));
    }

    if (hd.Version)
    {
      uint Version=ParseVersionFileName(Name,false);
      if (Version!=0)
        mprintf(L"\n%12ls: %u",St(MListFileVer),Version);
    }

    if (hd.UnixOwnerSet)
    {
      mprintf(L"\n%12ls: ",L"Unix owner");
      if (*hd.UnixOwnerName!=0)
        mprintf(L"%ls:",GetWide(hd.UnixOwnerName));
      if (*hd.UnixGroupName!=0)
        mprintf(L"%ls",GetWide(hd.UnixGroupName));
      if ((*hd.UnixOwnerName!=0 || *hd.UnixGroupName!=0) && (hd.UnixOwnerNumeric || hd.UnixGroupNumeric))
        mprintf(L"  ");
      if (hd.UnixOwnerNumeric)
        mprintf(L"#%d:",hd.UnixOwnerID);
      if (hd.UnixGroupNumeric)
        mprintf(L"#%d:",hd.UnixGroupID);
    }

    mprintf(L"\n");
    return;
  }

  mprintf(L"\n%c%10ls %9ls ",hd.Encrypted ? '*' : ' ',AttrStr,UnpSizeText);

  if (Verbose)
    mprintf(L"%9ls %4ls ",PackSizeText,RatioStr);

  mprintf(L" %ls  ",DateStr);

  if (Verbose)
  {
    if (hd.FileHash.Type==HASH_CRC32)
      mprintf(L"%8.8X  ",hd.FileHash.CRC32);
    else
      if (hd.FileHash.Type==HASH_BLAKE2)
      {
        byte *S=hd.FileHash.Digest;
        mprintf(L"%02x%02x..%02x  ",S[0],S[1],S[31]);
      }
      else
        mprintf(L"????????  ");
  }
  mprintf(L"%ls",Name);
}

/*
void ListSymLink(Archive &Arc)
{
  if (Arc.FileHead.HSType==HSYS_UNIX && (Arc.FileHead.FileAttr & 0xF000)==0xA000)
    if (Arc.FileHead.Encrypted)
    {
      // Link data are encrypted. We would need to ask for password
      // and initialize decryption routine to display the link target.
      mprintf(L"\n%22ls %ls",L"-->",L"*<-?->");
    }
    else
    {
      char FileName[NM];
      uint DataSize=(uint)Min(Arc.FileHead.PackSize,sizeof(FileName)-1);
      Arc.Read(FileName,DataSize);
      FileName[DataSize]=0;
      mprintf(L"\n%22ls %ls",L"-->",GetWide(FileName));
    }
}
*/

void ListFileAttr(uint A,HOST_SYSTEM_TYPE HostType,wchar *AttrStr,size_t AttrSize)
{
  switch(HostType)
  {
    case HSYS_WINDOWS:
      swprintf(AttrStr,AttrSize,L"%c%c%c%c%c%c%c",
              (A & 0x2000)!=0 ? 'I' : '.',  // Not content indexed.
              (A & 0x0800)!=0 ? 'C' : '.',  // Compressed.
              (A & 0x0020)!=0 ? 'A' : '.',  // Archive.
              (A & 0x0010)!=0 ? 'D' : '.',  // Directory.
              (A & 0x0004)!=0 ? 'S' : '.',  // System.
              (A & 0x0002)!=0 ? 'H' : '.',  // Hidden.
              (A & 0x0001)!=0 ? 'R' : '.'); // Read-only.
      break;
    case HSYS_UNIX:
      switch (A & 0xF000)
      {
        case 0x4000:
          AttrStr[0]='d';
          break;
        case 0xA000:
          AttrStr[0]='l';
          break;
        default:
          AttrStr[0]='-';
          break;
      }
      swprintf(AttrStr+1,AttrSize-1,L"%c%c%c%c%c%c%c%c%c",
              (A & 0x0100) ? 'r' : '-',
              (A & 0x0080) ? 'w' : '-',
              (A & 0x0040) ? ((A & 0x0800)!=0 ? 's':'x'):((A & 0x0800)!=0 ? 'S':'-'),
              (A & 0x0020) ? 'r' : '-',
              (A & 0x0010) ? 'w' : '-',
              (A & 0x0008) ? ((A & 0x0400)!=0 ? 's':'x'):((A & 0x0400)!=0 ? 'S':'-'),
              (A & 0x0004) ? 'r' : '-',
              (A & 0x0002) ? 'w' : '-',
              (A & 0x0001) ? ((A & 0x200)!=0 ? 't' : 'x') : '-');
      break;
    case HSYS_UNKNOWN:
      wcsncpyz(AttrStr,L"?",AttrSize);
      break;
  }
}

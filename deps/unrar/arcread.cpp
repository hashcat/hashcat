#include "rar.hpp"

size_t Archive::ReadHeader()
{
  // Once we failed to decrypt an encrypted block, there is no reason to
  // attempt to do it further. We'll never be successful and only generate
  // endless errors.
  if (FailedHeaderDecryption)
    return 0;

  CurBlockPos=Tell();

  // Other developers asked us to initialize it to suppress "may be used
  // uninitialized" warning in code below in some compilers.
  size_t ReadSize=0;

  switch(Format)
  {
#ifndef SFX_MODULE
    case RARFMT14:
      ReadSize=ReadHeader14();
      break;
#endif
    case RARFMT15:
      ReadSize=ReadHeader15();
      break;
    case RARFMT50:
      ReadSize=ReadHeader50();
      break;
  }

  // It is important to check ReadSize>0 here, because it is normal
  // for RAR2 and RAR3 archives without end of archive block to have
  // NextBlockPos==CurBlockPos after the end of archive has reached.
  if (ReadSize>0 && NextBlockPos<=CurBlockPos)
  {
    BrokenHeaderMsg();
    ReadSize=0;
  }

  if (ReadSize==0)
    CurHeaderType=HEAD_UNKNOWN;

  return ReadSize;
}


size_t Archive::SearchBlock(HEADER_TYPE HeaderType)
{
  size_t Size,Count=0;
  while ((Size=ReadHeader())!=0 &&
         (HeaderType==HEAD_ENDARC || GetHeaderType()!=HEAD_ENDARC))
  {
    if ((++Count & 127)==0)
      Wait();
    if (GetHeaderType()==HeaderType)
      return Size;
    SeekToNext();
  }
  return 0;
}


size_t Archive::SearchSubBlock(const wchar *Type)
{
  size_t Size,Count=0;
  while ((Size=ReadHeader())!=0 && GetHeaderType()!=HEAD_ENDARC)
  {
    if ((++Count & 127)==0)
      Wait();
    if (GetHeaderType()==HEAD_SERVICE && SubHead.CmpName(Type))
      return Size;
    SeekToNext();
  }
  return 0;
}


size_t Archive::SearchRR()
{
  // If locator extra field is available for recovery record, let's utilize it.
  if (MainHead.Locator && MainHead.RROffset!=0)
  {
    uint64 CurPos=Tell();
    Seek(MainHead.RROffset,SEEK_SET);
    size_t Size=ReadHeader();
    if (Size!=0 && !BrokenHeader && GetHeaderType()==HEAD_SERVICE && SubHead.CmpName(SUBHEAD_TYPE_RR))
      return Size;
    Seek(CurPos,SEEK_SET);
  }
  // Otherwise scan the entire archive to find the recovery record.
  return SearchSubBlock(SUBHEAD_TYPE_RR);
}


void Archive::UnexpEndArcMsg()
{
  int64 ArcSize=FileLength();

  // If block positions are equal to file size, this is not an error.
  // It can happen when we reached the end of older RAR 1.5 archive,
  // which did not have the end of archive block.
  if (CurBlockPos!=ArcSize || NextBlockPos!=ArcSize)
  {
    uiMsg(UIERROR_UNEXPEOF,FileName);
    ErrHandler.SetErrorCode(RARX_WARNING);
  }
}


void Archive::BrokenHeaderMsg()
{
  uiMsg(UIERROR_HEADERBROKEN,FileName);
  BrokenHeader=true;
  ErrHandler.SetErrorCode(RARX_CRC);
}


void Archive::UnkEncVerMsg(const wchar *Name,const wchar *Info)
{
  uiMsg(UIERROR_UNKNOWNENCMETHOD,FileName,Name,Info);
  ErrHandler.SetErrorCode(RARX_WARNING);
}


// Return f in case of signed integer overflow or negative parameters
// or v1+v2 otherwise. We use it for file offsets, which are signed
// for compatibility with off_t in POSIX file functions and third party code.
// Signed integer overflow is the undefined behavior according to
// C++ standard and it causes fuzzers to complain.
inline int64 SafeAdd(int64 v1,int64 v2,int64 f)
{
  return v1>=0 && v2>=0 && v1<=MAX_INT64-v2 ? v1+v2 : f;
}


size_t Archive::ReadHeader15()
{
  RawRead Raw(this);

  bool Decrypt=Encrypted && CurBlockPos>(int64)SFXSize+SIZEOF_MARKHEAD3;

  if (Decrypt)
  {
#ifdef RAR_NOCRYPT // For rarext.dll and unrar_nocrypt.dll.
    return 0;
#else
    RequestArcPassword();

    byte Salt[SIZE_SALT30];
    if (Read(Salt,SIZE_SALT30)!=SIZE_SALT30)
    {
      UnexpEndArcMsg();
      return 0;
    }
    HeadersCrypt.SetCryptKeys(false,CRYPT_RAR30,&Cmd->Password,Salt,NULL,0,NULL,NULL);
    Raw.SetCrypt(&HeadersCrypt);
#endif
  }

  Raw.Read(SIZEOF_SHORTBLOCKHEAD);
  if (Raw.Size()==0)
  {
    UnexpEndArcMsg();
    return 0;
  }

  ShortBlock.HeadCRC=Raw.Get2();

  ShortBlock.Reset();

  uint HeaderType=Raw.Get1();
  ShortBlock.Flags=Raw.Get2();
  ShortBlock.SkipIfUnknown=(ShortBlock.Flags & SKIP_IF_UNKNOWN)!=0;
  ShortBlock.HeadSize=Raw.Get2();

  ShortBlock.HeaderType=(HEADER_TYPE)HeaderType;
  if (ShortBlock.HeadSize<SIZEOF_SHORTBLOCKHEAD)
  {
    BrokenHeaderMsg();
    return 0;
  }

  // For simpler further processing we map header types common
  // for RAR 1.5 and 5.0 formats to RAR 5.0 values. It does not include
  // header types specific for RAR 1.5 - 4.x only.
  switch(ShortBlock.HeaderType)
  {
    case HEAD3_MAIN:    ShortBlock.HeaderType=HEAD_MAIN;     break;
    case HEAD3_FILE:    ShortBlock.HeaderType=HEAD_FILE;     break;
    case HEAD3_SERVICE: ShortBlock.HeaderType=HEAD_SERVICE;  break;
    case HEAD3_ENDARC:  ShortBlock.HeaderType=HEAD_ENDARC;   break;
  }
  CurHeaderType=ShortBlock.HeaderType;

  if (ShortBlock.HeaderType==HEAD3_CMT)
  {
    // Old style (up to RAR 2.9) comment header embedded into main
    // or file header. We must not read the entire ShortBlock.HeadSize here
    // to not break the comment processing logic later.
    Raw.Read(SIZEOF_COMMHEAD-SIZEOF_SHORTBLOCKHEAD);
  }
  else
    if (ShortBlock.HeaderType==HEAD_MAIN && (ShortBlock.Flags & MHD_COMMENT)!=0)
    {
      // Old style (up to RAR 2.9) main archive comment embedded into
      // the main archive header found. While we can read the entire
      // ShortBlock.HeadSize here and remove this part of "if", it would be
      // waste of memory, because we'll read and process this comment data
      // in other function anyway and we do not need them here now.
      Raw.Read(SIZEOF_MAINHEAD3-SIZEOF_SHORTBLOCKHEAD);
    }
    else
      Raw.Read(ShortBlock.HeadSize-SIZEOF_SHORTBLOCKHEAD);

  NextBlockPos=CurBlockPos+FullHeaderSize(ShortBlock.HeadSize);

  switch(ShortBlock.HeaderType)
  {
    case HEAD_MAIN:
      MainHead.Reset();
      *(BaseBlock *)&MainHead=ShortBlock;
      MainHead.HighPosAV=Raw.Get2();
      MainHead.PosAV=Raw.Get4();

      Volume=(MainHead.Flags & MHD_VOLUME)!=0;
      Solid=(MainHead.Flags & MHD_SOLID)!=0;
      Locked=(MainHead.Flags & MHD_LOCK)!=0;
      Protected=(MainHead.Flags & MHD_PROTECT)!=0;
      Encrypted=(MainHead.Flags & MHD_PASSWORD)!=0;
      Signed=MainHead.PosAV!=0 || MainHead.HighPosAV!=0;
      MainHead.CommentInHeader=(MainHead.Flags & MHD_COMMENT)!=0;

      // Only for encrypted 3.0+ archives. 2.x archives did not have this
      // flag, so for non-encrypted archives, we'll set it later based on
      // file attributes.
      FirstVolume=(MainHead.Flags & MHD_FIRSTVOLUME)!=0;

      NewNumbering=(MainHead.Flags & MHD_NEWNUMBERING)!=0;
      break;
    case HEAD_FILE:
    case HEAD_SERVICE:
      {
        bool FileBlock=ShortBlock.HeaderType==HEAD_FILE;
        FileHeader *hd=FileBlock ? &FileHead:&SubHead;
        hd->Reset();

        *(BaseBlock *)hd=ShortBlock;

        hd->SplitBefore=(hd->Flags & LHD_SPLIT_BEFORE)!=0;
        hd->SplitAfter=(hd->Flags & LHD_SPLIT_AFTER)!=0;
        hd->Encrypted=(hd->Flags & LHD_PASSWORD)!=0;
        hd->SaltSet=(hd->Flags & LHD_SALT)!=0;
        hd->Solid=FileBlock && (hd->Flags & LHD_SOLID)!=0;
        hd->SubBlock=!FileBlock && (hd->Flags & LHD_SOLID)!=0;
        hd->Dir=(hd->Flags & LHD_WINDOWMASK)==LHD_DIRECTORY;
        hd->WinSize=hd->Dir ? 0:0x10000<<((hd->Flags & LHD_WINDOWMASK)>>5);
        hd->CommentInHeader=(hd->Flags & LHD_COMMENT)!=0;
        hd->Version=(hd->Flags & LHD_VERSION)!=0;

        hd->DataSize=Raw.Get4();
        uint LowUnpSize=Raw.Get4();
        hd->HostOS=Raw.Get1();

        hd->FileHash.Type=HASH_CRC32;
        hd->FileHash.CRC32=Raw.Get4();

        uint FileTime=Raw.Get4();
        hd->UnpVer=Raw.Get1();

        hd->Method=Raw.Get1()-0x30;
        size_t NameSize=Raw.Get2();
        hd->FileAttr=Raw.Get4();

        // RAR15 did not use the special dictionary size to mark dirs.
        if (hd->UnpVer<20 && (hd->FileAttr & 0x10)!=0)
          hd->Dir=true;

        hd->CryptMethod=CRYPT_NONE;
        if (hd->Encrypted)
          switch(hd->UnpVer)
          {
            case 13: hd->CryptMethod=CRYPT_RAR13; break;
            case 15: hd->CryptMethod=CRYPT_RAR15; break;
            case 20:
            case 26: hd->CryptMethod=CRYPT_RAR20; break;
            default: hd->CryptMethod=CRYPT_RAR30; break;
          }

        hd->HSType=HSYS_UNKNOWN;
        if (hd->HostOS==HOST_UNIX || hd->HostOS==HOST_BEOS)
          hd->HSType=HSYS_UNIX;
        else
          if (hd->HostOS<HOST_MAX)
            hd->HSType=HSYS_WINDOWS;

        hd->RedirType=FSREDIR_NONE;

        // RAR 4.x Unix symlink.
        if (hd->HostOS==HOST_UNIX && (hd->FileAttr & 0xF000)==0xA000)
        {
          hd->RedirType=FSREDIR_UNIXSYMLINK;
          *hd->RedirName=0;
        }

        hd->Inherited=!FileBlock && (hd->SubFlags & SUBHEAD_FLAGS_INHERITED)!=0;

        hd->LargeFile=(hd->Flags & LHD_LARGE)!=0;

        uint HighPackSize,HighUnpSize;
        if (hd->LargeFile)
        {
          HighPackSize=Raw.Get4();
          HighUnpSize=Raw.Get4();
          hd->UnknownUnpSize=(LowUnpSize==0xffffffff && HighUnpSize==0xffffffff);
        }
        else
        {
          HighPackSize=HighUnpSize=0;
          // UnpSize equal to 0xffffffff without LHD_LARGE flag indicates
          // that we do not know the unpacked file size and must unpack it
          // until we find the end of file marker in compressed data.
          hd->UnknownUnpSize=(LowUnpSize==0xffffffff);
        }
        hd->PackSize=INT32TO64(HighPackSize,hd->DataSize);
        hd->UnpSize=INT32TO64(HighUnpSize,LowUnpSize);
        if (hd->UnknownUnpSize)
          hd->UnpSize=INT64NDF;

        char FileName[NM*4];
        size_t ReadNameSize=Min(NameSize,ASIZE(FileName)-1);
        Raw.GetB((byte *)FileName,ReadNameSize);
        FileName[ReadNameSize]=0;

        if (FileBlock)
        {
          *hd->FileName=0;
          if ((hd->Flags & LHD_UNICODE)!=0)
          {
            EncodeFileName NameCoder;
            size_t Length=strlen(FileName);
            Length++;
            if (ReadNameSize>Length)
              NameCoder.Decode(FileName,ReadNameSize,(byte *)FileName+Length,
                               ReadNameSize-Length,hd->FileName,
                               ASIZE(hd->FileName));
          }

          if (*hd->FileName==0)
            ArcCharToWide(FileName,hd->FileName,ASIZE(hd->FileName),ACTW_OEM);

#ifndef SFX_MODULE
          ConvertNameCase(hd->FileName);
#endif
          ConvertFileHeader(hd);
        }
        else
        {
          CharToWide(FileName,hd->FileName,ASIZE(hd->FileName));

          // Calculate the size of optional data.
          int DataSize=int(hd->HeadSize-NameSize-SIZEOF_FILEHEAD3);
          if ((hd->Flags & LHD_SALT)!=0)
            DataSize-=SIZE_SALT30;

          if (DataSize>0)
          {
            // Here we read optional additional fields for subheaders.
            // They are stored after the file name and before salt.
            hd->SubData.Alloc(DataSize);
            Raw.GetB(&hd->SubData[0],DataSize);

          }

          if (hd->CmpName(SUBHEAD_TYPE_CMT))
            MainComment=true;
        }
        if ((hd->Flags & LHD_SALT)!=0)
          Raw.GetB(hd->Salt,SIZE_SALT30);
        hd->mtime.SetDos(FileTime);
        if ((hd->Flags & LHD_EXTTIME)!=0)
        {
          ushort Flags=Raw.Get2();
          RarTime *tbl[4];
          tbl[0]=&FileHead.mtime;
          tbl[1]=&FileHead.ctime;
          tbl[2]=&FileHead.atime;
          tbl[3]=NULL; // Archive time is not used now.
          for (int I=0;I<4;I++)
          {
            RarTime *CurTime=tbl[I];
            uint rmode=Flags>>(3-I)*4;
            if ((rmode & 8)==0 || CurTime==NULL)
              continue;
            if (I!=0)
            {
              uint DosTime=Raw.Get4();
              CurTime->SetDos(DosTime);
            }
            RarLocalTime rlt;
            CurTime->GetLocal(&rlt);
            if (rmode & 4)
              rlt.Second++;
            rlt.Reminder=0;
            uint count=rmode&3;
            for (uint J=0;J<count;J++)
            {
              byte CurByte=Raw.Get1();
              rlt.Reminder|=(((uint)CurByte)<<((J+3-count)*8));
            }
            // Convert from 100ns RAR precision to REMINDER_PRECISION.
            rlt.Reminder*=RarTime::REMINDER_PRECISION/10000000;
            CurTime->SetLocal(&rlt);
          }
        }
        // Set to 0 in case of overflow, so end of ReadHeader cares about it.
        NextBlockPos=SafeAdd(NextBlockPos,hd->PackSize,0);

        bool CRCProcessedOnly=hd->CommentInHeader;
        ushort HeaderCRC=Raw.GetCRC15(CRCProcessedOnly);
        if (hd->HeadCRC!=HeaderCRC)
        {
          BrokenHeader=true;
          ErrHandler.SetErrorCode(RARX_WARNING);

          // If we have a broken encrypted header, we do not need to display
          // the error message here, because it will be displayed for such
          // headers later in this function. Also such headers are unlikely
          // to have anything sensible in file name field, so it is useless
          // to display the file name.
          if (!Decrypt)
            uiMsg(UIERROR_FHEADERBROKEN,Archive::FileName,hd->FileName);
        }
      }
      break;
    case HEAD_ENDARC:
      *(BaseBlock *)&EndArcHead=ShortBlock;
      EndArcHead.NextVolume=(EndArcHead.Flags & EARC_NEXT_VOLUME)!=0;
      EndArcHead.DataCRC=(EndArcHead.Flags & EARC_DATACRC)!=0;
      EndArcHead.RevSpace=(EndArcHead.Flags & EARC_REVSPACE)!=0;
      EndArcHead.StoreVolNumber=(EndArcHead.Flags & EARC_VOLNUMBER)!=0;
      if (EndArcHead.DataCRC)
        EndArcHead.ArcDataCRC=Raw.Get4();
      if (EndArcHead.StoreVolNumber)
        VolNumber=EndArcHead.VolNumber=Raw.Get2();
      break;
#ifndef SFX_MODULE
    case HEAD3_CMT:
      *(BaseBlock *)&CommHead=ShortBlock;
      CommHead.UnpSize=Raw.Get2();
      CommHead.UnpVer=Raw.Get1();
      CommHead.Method=Raw.Get1();
      CommHead.CommCRC=Raw.Get2();
      break;
    case HEAD3_PROTECT:
      *(BaseBlock *)&ProtectHead=ShortBlock;
      ProtectHead.DataSize=Raw.Get4();
      ProtectHead.Version=Raw.Get1();
      ProtectHead.RecSectors=Raw.Get2();
      ProtectHead.TotalBlocks=Raw.Get4();
      Raw.GetB(ProtectHead.Mark,8);
      NextBlockPos+=ProtectHead.DataSize;
      break;
    case HEAD3_OLDSERVICE: // RAR 2.9 and earlier.
      *(BaseBlock *)&SubBlockHead=ShortBlock;
      SubBlockHead.DataSize=Raw.Get4();
      NextBlockPos+=SubBlockHead.DataSize;
      SubBlockHead.SubType=Raw.Get2();
      SubBlockHead.Level=Raw.Get1();
      switch(SubBlockHead.SubType)
      {
        case UO_HEAD:
          *(SubBlockHeader *)&UOHead=SubBlockHead;
          UOHead.OwnerNameSize=Raw.Get2();
          UOHead.GroupNameSize=Raw.Get2();
          if (UOHead.OwnerNameSize>=ASIZE(UOHead.OwnerName))
            UOHead.OwnerNameSize=ASIZE(UOHead.OwnerName)-1;
          if (UOHead.GroupNameSize>=ASIZE(UOHead.GroupName))
            UOHead.GroupNameSize=ASIZE(UOHead.GroupName)-1;
          Raw.GetB(UOHead.OwnerName,UOHead.OwnerNameSize);
          Raw.GetB(UOHead.GroupName,UOHead.GroupNameSize);
          UOHead.OwnerName[UOHead.OwnerNameSize]=0;
          UOHead.GroupName[UOHead.GroupNameSize]=0;
          break;
        case NTACL_HEAD:
          *(SubBlockHeader *)&EAHead=SubBlockHead;
          EAHead.UnpSize=Raw.Get4();
          EAHead.UnpVer=Raw.Get1();
          EAHead.Method=Raw.Get1();
          EAHead.EACRC=Raw.Get4();
          break;
        case STREAM_HEAD:
          *(SubBlockHeader *)&StreamHead=SubBlockHead;
          StreamHead.UnpSize=Raw.Get4();
          StreamHead.UnpVer=Raw.Get1();
          StreamHead.Method=Raw.Get1();
          StreamHead.StreamCRC=Raw.Get4();
          StreamHead.StreamNameSize=Raw.Get2();
          if (StreamHead.StreamNameSize>=ASIZE(StreamHead.StreamName))
            StreamHead.StreamNameSize=ASIZE(StreamHead.StreamName)-1;
          Raw.GetB(StreamHead.StreamName,StreamHead.StreamNameSize);
          StreamHead.StreamName[StreamHead.StreamNameSize]=0;
          break;
      }
      break;
#endif
    default:
      if (ShortBlock.Flags & LONG_BLOCK)
        NextBlockPos+=Raw.Get4();
      break;
  }

  ushort HeaderCRC=Raw.GetCRC15(false);

  // Old AV header does not have header CRC properly set.
  if (ShortBlock.HeadCRC!=HeaderCRC && ShortBlock.HeaderType!=HEAD3_SIGN &&
      ShortBlock.HeaderType!=HEAD3_AV)
  {
    bool Recovered=false;
    if (ShortBlock.HeaderType==HEAD_ENDARC && EndArcHead.RevSpace)
    {
      // Last 7 bytes of recovered volume can contain zeroes, because
      // REV files store its own information (volume number, etc.) here.
      int64 Length=Tell();
      Seek(Length-7,SEEK_SET);
      Recovered=true;
      for (int J=0;J<7;J++)
        if (GetByte()!=0)
          Recovered=false;
    }
    if (!Recovered)
    {
      BrokenHeader=true;
      ErrHandler.SetErrorCode(RARX_CRC);

      if (Decrypt)
      {
        uiMsg(UIERROR_CHECKSUMENC,FileName,FileName);
        FailedHeaderDecryption=true;
        return 0;
      }
    }
  }

  return Raw.Size();
}


size_t Archive::ReadHeader50()
{
  RawRead Raw(this);

  bool Decrypt=Encrypted && CurBlockPos>(int64)SFXSize+SIZEOF_MARKHEAD5;

  if (Decrypt)
  {
#if defined(RAR_NOCRYPT)
    return 0;
#else

    byte HeadersInitV[SIZE_INITV];
    if (Read(HeadersInitV,SIZE_INITV)!=SIZE_INITV)
    {
      UnexpEndArcMsg();
      return 0;
    }

    // We repeat the password request only for manually entered passwords
    // and not for -p<pwd>. Wrong password can be intentionally provided
    // in -p<pwd> to not stop batch processing for encrypted archives.
    bool GlobalPassword=Cmd->Password.IsSet() || uiIsGlobalPasswordSet();

    while (true) // Repeat the password prompt for wrong passwords.
    {
      RequestArcPassword();

      byte PswCheck[SIZE_PSWCHECK];
      HeadersCrypt.SetCryptKeys(false,CRYPT_RAR50,&Cmd->Password,CryptHead.Salt,HeadersInitV,CryptHead.Lg2Count,NULL,PswCheck);
      // Verify password validity.
      if (CryptHead.UsePswCheck && memcmp(PswCheck,CryptHead.PswCheck,SIZE_PSWCHECK)!=0)
      {
        if (GlobalPassword) // For -p<pwd> or Ctrl+P.
        {
          // This message is used by Android GUI to reset cached passwords.
          // Update appropriate code if changed.
          uiMsg(UIERROR_BADPSW,FileName,FileName);
          FailedHeaderDecryption=true;
          ErrHandler.SetErrorCode(RARX_BADPWD);
          return 0;
        }
        else // For passwords entered manually.
        {
          // This message is used by Android GUI and Windows GUI and SFX to
          // reset cached passwords. Update appropriate code if changed.
          uiMsg(UIWAIT_BADPSW,FileName,FileName);
          Cmd->Password.Clean();
        }

#ifdef RARDLL
        // Avoid new requests for unrar.dll to prevent the infinite loop
        // if app always returns the same password.
        ErrHandler.SetErrorCode(RARX_BADPWD);
        Cmd->DllError=ERAR_BAD_PASSWORD;
        ErrHandler.Exit(RARX_BADPWD);
#else
        continue; // Request a password again.
#endif
      }
      break;
    }

    Raw.SetCrypt(&HeadersCrypt);
#endif
  }

  // Header size must not occupy more than 3 variable length integer bytes
  // resulting in 2 MB maximum header size (MAX_HEADER_SIZE_RAR5),
  // so here we read 4 byte CRC32 followed by 3 bytes or less of header size.
  const size_t FirstReadSize=7; // Smallest possible block size.
  if (Raw.Read(FirstReadSize)<FirstReadSize)
  {
    UnexpEndArcMsg();
    return 0;
  }

  ShortBlock.Reset();
  ShortBlock.HeadCRC=Raw.Get4();
  uint SizeBytes=Raw.GetVSize(4);
  uint64 BlockSize=Raw.GetV();

  if (BlockSize==0 || SizeBytes==0)
  {
    BrokenHeaderMsg();
    return 0;
  }

  int SizeToRead=int(BlockSize);
  SizeToRead-=FirstReadSize-SizeBytes-4; // Adjust overread size bytes if any.
  uint HeaderSize=4+SizeBytes+(uint)BlockSize;

  if (SizeToRead<0 || HeaderSize<SIZEOF_SHORTBLOCKHEAD5)
  {
    BrokenHeaderMsg();
    return 0;
  }

  Raw.Read(SizeToRead);

  if (Raw.Size()<HeaderSize)
  {
    UnexpEndArcMsg();
    return 0;
  }

  uint HeaderCRC=Raw.GetCRC50();

  ShortBlock.HeaderType=(HEADER_TYPE)Raw.GetV();
  ShortBlock.Flags=(uint)Raw.GetV();
  ShortBlock.SkipIfUnknown=(ShortBlock.Flags & HFL_SKIPIFUNKNOWN)!=0;
  ShortBlock.HeadSize=HeaderSize;

  CurHeaderType=ShortBlock.HeaderType;

  bool BadCRC=(ShortBlock.HeadCRC!=HeaderCRC);
  if (BadCRC)
  {
    BrokenHeaderMsg(); // Report, but attempt to process.

    BrokenHeader=true;
    ErrHandler.SetErrorCode(RARX_CRC);

    if (Decrypt)
    {
      uiMsg(UIERROR_CHECKSUMENC,FileName,FileName);
      FailedHeaderDecryption=true;
      return 0;
    }
  }

  uint64 ExtraSize=0;
  if ((ShortBlock.Flags & HFL_EXTRA)!=0)
  {
    ExtraSize=Raw.GetV();
    if (ExtraSize>=ShortBlock.HeadSize)
    {
      BrokenHeaderMsg();
      return 0;
    }
  }

  uint64 DataSize=0;
  if ((ShortBlock.Flags & HFL_DATA)!=0)
    DataSize=Raw.GetV();

  NextBlockPos=CurBlockPos+FullHeaderSize(ShortBlock.HeadSize);
  // Set to 0 in case of overflow, so end of ReadHeader cares about it.
  NextBlockPos=SafeAdd(NextBlockPos,DataSize,0);

  switch(ShortBlock.HeaderType)
  {
    case HEAD_CRYPT:
      {
        *(BaseBlock *)&CryptHead=ShortBlock;
        uint CryptVersion=(uint)Raw.GetV();
        if (CryptVersion>CRYPT_VERSION)
        {
          wchar Info[20];
          swprintf(Info,ASIZE(Info),L"h%u",CryptVersion);
          UnkEncVerMsg(FileName,Info);
          return 0;
        }
        uint EncFlags=(uint)Raw.GetV();
        CryptHead.UsePswCheck=(EncFlags & CHFL_CRYPT_PSWCHECK)!=0;
        CryptHead.Lg2Count=Raw.Get1();
        if (CryptHead.Lg2Count>CRYPT5_KDF_LG2_COUNT_MAX)
        {
          wchar Info[20];
          swprintf(Info,ASIZE(Info),L"hc%u",CryptHead.Lg2Count);
          UnkEncVerMsg(FileName,Info);
          return 0;
        }

        Raw.GetB(CryptHead.Salt,SIZE_SALT50);
        if (CryptHead.UsePswCheck)
        {
          Raw.GetB(CryptHead.PswCheck,SIZE_PSWCHECK);

          byte csum[SIZE_PSWCHECK_CSUM];
          Raw.GetB(csum,SIZE_PSWCHECK_CSUM);

          sha256_context ctx;
          sha256_init(&ctx);
          sha256_process(&ctx, CryptHead.PswCheck, SIZE_PSWCHECK);

          byte Digest[SHA256_DIGEST_SIZE];
          sha256_done(&ctx, Digest);

          CryptHead.UsePswCheck=memcmp(csum,Digest,SIZE_PSWCHECK_CSUM)==0;
        }
        Encrypted=true;
      }
      break;
    case HEAD_MAIN:
      {
        MainHead.Reset();
        *(BaseBlock *)&MainHead=ShortBlock;
        uint ArcFlags=(uint)Raw.GetV();

        Volume=(ArcFlags & MHFL_VOLUME)!=0;
        Solid=(ArcFlags & MHFL_SOLID)!=0;
        Locked=(ArcFlags & MHFL_LOCK)!=0;
        Protected=(ArcFlags & MHFL_PROTECT)!=0;
        Signed=false;
        NewNumbering=true;

        if ((ArcFlags & MHFL_VOLNUMBER)!=0)
          VolNumber=(uint)Raw.GetV();
        else
          VolNumber=0;
        FirstVolume=Volume && VolNumber==0;

        if (ExtraSize!=0)
          ProcessExtra50(&Raw,(size_t)ExtraSize,&MainHead);

#ifdef USE_QOPEN
        if (!ProhibitQOpen && MainHead.Locator && MainHead.QOpenOffset>0 && Cmd->QOpenMode!=QOPEN_NONE)
        {
          // We seek to QO block in the end of archive when processing
          // QOpen.Load, so we need to preserve current block positions
          // to not break normal archive processing by calling function.
          int64 SaveCurBlockPos=CurBlockPos,SaveNextBlockPos=NextBlockPos;
          HEADER_TYPE SaveCurHeaderType=CurHeaderType;

          QOpen.Init(this,false);
          QOpen.Load(MainHead.QOpenOffset);

          CurBlockPos=SaveCurBlockPos;
          NextBlockPos=SaveNextBlockPos;
          CurHeaderType=SaveCurHeaderType;
        }
#endif
      }
      break;
    case HEAD_FILE:
    case HEAD_SERVICE:
      {
        FileHeader *hd=ShortBlock.HeaderType==HEAD_FILE ? &FileHead:&SubHead;
        hd->Reset(); // Clear hash, time fields and other stuff like flags.
        *(BaseBlock *)hd=ShortBlock;

        bool FileBlock=ShortBlock.HeaderType==HEAD_FILE;

        hd->LargeFile=true;

        hd->PackSize=DataSize;
        hd->FileFlags=(uint)Raw.GetV();
        hd->UnpSize=Raw.GetV();

        hd->UnknownUnpSize=(hd->FileFlags & FHFL_UNPUNKNOWN)!=0;
        if (hd->UnknownUnpSize)
          hd->UnpSize=INT64NDF;

        hd->MaxSize=Max(hd->PackSize,hd->UnpSize);
        hd->FileAttr=(uint)Raw.GetV();
        if ((hd->FileFlags & FHFL_UTIME)!=0)
          hd->mtime.SetUnix((time_t)Raw.Get4());

        hd->FileHash.Type=HASH_NONE;
        if ((hd->FileFlags & FHFL_CRC32)!=0)
        {
          hd->FileHash.Type=HASH_CRC32;
          hd->FileHash.CRC32=Raw.Get4();
        }

        hd->RedirType=FSREDIR_NONE;

        uint CompInfo=(uint)Raw.GetV();
        hd->Method=(CompInfo>>7) & 7;

        // "+ 50" to not mix with old RAR format algorithms. For example,
        // we may need to use the compression algorithm 15 in the future,
        // but it was already used in RAR 1.5 and Unpack needs to distinguish
        // them.
        hd->UnpVer=(CompInfo & 0x3f) + 50;
        if (hd->UnpVer!=50) // Only 5.0 compression is known now.
          hd->UnpVer=VER_UNKNOWN;

        hd->HostOS=(byte)Raw.GetV();
        size_t NameSize=(size_t)Raw.GetV();
        hd->Inherited=(ShortBlock.Flags & HFL_INHERITED)!=0;

        hd->HSType=HSYS_UNKNOWN;
        if (hd->HostOS==HOST5_UNIX)
          hd->HSType=HSYS_UNIX;
        else
          if (hd->HostOS==HOST5_WINDOWS)
            hd->HSType=HSYS_WINDOWS;

        hd->SplitBefore=(hd->Flags & HFL_SPLITBEFORE)!=0;
        hd->SplitAfter=(hd->Flags & HFL_SPLITAFTER)!=0;
        hd->SubBlock=(hd->Flags & HFL_CHILD)!=0;
        hd->Solid=FileBlock && (CompInfo & FCI_SOLID)!=0;
        hd->Dir=(hd->FileFlags & FHFL_DIRECTORY)!=0;
        hd->WinSize=hd->Dir ? 0:size_t(0x20000)<<((CompInfo>>10)&0xf);

        hd->CryptMethod=hd->Encrypted ? CRYPT_RAR50:CRYPT_NONE;

        char FileName[NM*4];
        size_t ReadNameSize=Min(NameSize,ASIZE(FileName)-1);
        Raw.GetB((byte *)FileName,ReadNameSize);
        FileName[ReadNameSize]=0;

        UtfToWide(FileName,hd->FileName,ASIZE(hd->FileName));

        // Should do it before converting names, because extra fields can
        // affect name processing, like in case of NTFS streams.
        if (ExtraSize!=0)
          ProcessExtra50(&Raw,(size_t)ExtraSize,hd);

        if (FileBlock)
        {
#ifndef SFX_MODULE
          ConvertNameCase(hd->FileName);
#endif
          ConvertFileHeader(hd);
        }

        if (!FileBlock && hd->CmpName(SUBHEAD_TYPE_CMT))
          MainComment=true;

#if 0
        // For RAR5 format we read the user specified recovery percent here.
        // It would be useful to do it for shell extension too, so we display
        // the correct recovery record size in archive properties. But then
        // we would need to include the entire recovery record processing
        // code to shell extension, which is not done now.
        if (!FileBlock && hd->CmpName(SUBHEAD_TYPE_RR) && hd->SubData.Size()>0)
        {
          RecoveryPercent=hd->SubData[0];
          RSBlockHeader Header;
          GetRRInfo(this,&Header);
          RecoverySize=Header.RecSectionSize*Header.RecCount;
        }
#endif

        if (BadCRC) // Add the file name to broken header message displayed above.
          uiMsg(UIERROR_FHEADERBROKEN,Archive::FileName,hd->FileName);
      }
      break;
    case HEAD_ENDARC:
      {
        *(BaseBlock *)&EndArcHead=ShortBlock;
        uint ArcFlags=(uint)Raw.GetV();
        EndArcHead.NextVolume=(ArcFlags & EHFL_NEXTVOLUME)!=0;
        EndArcHead.StoreVolNumber=false;
        EndArcHead.DataCRC=false;
        EndArcHead.RevSpace=false;
      }
      break;
  }

  return Raw.Size();
}


#if !defined(RAR_NOCRYPT)
void Archive::RequestArcPassword()
{
  if (!Cmd->Password.IsSet())
  {
#ifdef RARDLL
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
    }
    if (!Cmd->Password.IsSet())
    {
      Close();
      Cmd->DllError=ERAR_MISSING_PASSWORD;
      ErrHandler.Exit(RARX_USERBREAK);
    }
#else
    if (!uiGetPassword(UIPASSWORD_ARCHIVE,FileName,&Cmd->Password))
    {
      Close();
      uiMsg(UIERROR_INCERRCOUNT); // Prevent archive deleting if delete after extraction is on.
      ErrHandler.Exit(RARX_USERBREAK);
    }
#endif
    Cmd->ManualPassword=true;
  }
}
#endif


void Archive::ProcessExtra50(RawRead *Raw,size_t ExtraSize,BaseBlock *bb)
{
  // Read extra data from the end of block skipping any fields before it.
  size_t ExtraStart=Raw->Size()-ExtraSize;
  if (ExtraStart<Raw->GetPos())
    return;
  Raw->SetPos(ExtraStart);
  while (Raw->DataLeft()>=2)
  {
    int64 FieldSize=Raw->GetV(); // Needs to be signed for check below and can be negative.
    if (FieldSize<=0 || Raw->DataLeft()==0 || FieldSize>(int64)Raw->DataLeft())
      break;
    size_t NextPos=size_t(Raw->GetPos()+FieldSize);
    uint64 FieldType=Raw->GetV();

    FieldSize=int64(NextPos-Raw->GetPos()); // Field size without size and type fields.

    if (FieldSize<0) // FieldType is longer than expected extra field size.
      break;

    if (bb->HeaderType==HEAD_MAIN)
    {
      MainHeader *hd=(MainHeader *)bb;
      if (FieldType==MHEXTRA_LOCATOR)
      {
        hd->Locator=true;
        uint Flags=(uint)Raw->GetV();
        if ((Flags & MHEXTRA_LOCATOR_QLIST)!=0)
        {
          uint64 Offset=Raw->GetV();
          if (Offset!=0) // 0 means that reserved space was not enough to write the offset.
            hd->QOpenOffset=Offset+CurBlockPos;
        }
        if ((Flags & MHEXTRA_LOCATOR_RR)!=0)
        {
          uint64 Offset=Raw->GetV();
          if (Offset!=0) // 0 means that reserved space was not enough to write the offset.
            hd->RROffset=Offset+CurBlockPos;
        }
      }
    }

    if (bb->HeaderType==HEAD_FILE || bb->HeaderType==HEAD_SERVICE)
    {
      FileHeader *hd=(FileHeader *)bb;
      switch(FieldType)
      {
        case FHEXTRA_CRYPT:
          {
            FileHeader *hd=(FileHeader *)bb;
            uint EncVersion=(uint)Raw->GetV();
            if (EncVersion>CRYPT_VERSION)
            {
              wchar Info[20];
              swprintf(Info,ASIZE(Info),L"x%u",EncVersion);
              UnkEncVerMsg(hd->FileName,Info);
            }
            else
            {
              uint Flags=(uint)Raw->GetV();
              hd->UsePswCheck=(Flags & FHEXTRA_CRYPT_PSWCHECK)!=0;
              hd->UseHashKey=(Flags & FHEXTRA_CRYPT_HASHMAC)!=0;
              hd->Lg2Count=Raw->Get1();
              if (hd->Lg2Count>CRYPT5_KDF_LG2_COUNT_MAX)
              {
                wchar Info[20];
                swprintf(Info,ASIZE(Info),L"xc%u",hd->Lg2Count);
                UnkEncVerMsg(hd->FileName,Info);
              }
              Raw->GetB(hd->Salt,SIZE_SALT50);
              Raw->GetB(hd->InitV,SIZE_INITV);
              if (hd->UsePswCheck)
              {
                Raw->GetB(hd->PswCheck,SIZE_PSWCHECK);

                // It is important to know if password check data is valid.
                // If it is damaged and header CRC32 fails to detect it,
                // archiver would refuse to decompress a possibly valid file.
                // Since we want to be sure distinguishing a wrong password
                // or corrupt file data, we use 64-bit password check data
                // and to control its validity we use 32 bits of password
                // check data SHA-256 additionally to 32-bit header CRC32.
                byte csum[SIZE_PSWCHECK_CSUM];
                Raw->GetB(csum,SIZE_PSWCHECK_CSUM);

                sha256_context ctx;
                sha256_init(&ctx);
                sha256_process(&ctx, hd->PswCheck, SIZE_PSWCHECK);

                byte Digest[SHA256_DIGEST_SIZE];
                sha256_done(&ctx, Digest);

                hd->UsePswCheck=memcmp(csum,Digest,SIZE_PSWCHECK_CSUM)==0;

                // RAR 5.21 and earlier set PswCheck field in service records to 0
                // even if UsePswCheck was present.
                if (bb->HeaderType==HEAD_SERVICE && memcmp(hd->PswCheck,"\0\0\0\0\0\0\0\0",SIZE_PSWCHECK)==0)
                  hd->UsePswCheck=0;
              }
              hd->SaltSet=true;
              hd->CryptMethod=CRYPT_RAR50;
              hd->Encrypted=true;
            }
          }
          break;
        case FHEXTRA_HASH:
          {
            FileHeader *hd=(FileHeader *)bb;
            uint Type=(uint)Raw->GetV();
            if (Type==FHEXTRA_HASH_BLAKE2)
            {
              hd->FileHash.Type=HASH_BLAKE2;
              Raw->GetB(hd->FileHash.Digest,BLAKE2_DIGEST_SIZE);
            }
          }
          break;
        case FHEXTRA_HTIME:
          if (FieldSize>=5)
          {
            byte Flags=(byte)Raw->GetV();
            bool UnixTime=(Flags & FHEXTRA_HTIME_UNIXTIME)!=0;
            if ((Flags & FHEXTRA_HTIME_MTIME)!=0)
              if (UnixTime)
                hd->mtime.SetUnix(Raw->Get4());
              else
                hd->mtime.SetWin(Raw->Get8());
            if ((Flags & FHEXTRA_HTIME_CTIME)!=0)
              if (UnixTime)
                hd->ctime.SetUnix(Raw->Get4());
              else
                hd->ctime.SetWin(Raw->Get8());
            if ((Flags & FHEXTRA_HTIME_ATIME)!=0)
              if (UnixTime)
                hd->atime.SetUnix((time_t)Raw->Get4());
              else
                hd->atime.SetWin(Raw->Get8());
            if (UnixTime && (Flags & FHEXTRA_HTIME_UNIX_NS)!=0) // Add nanoseconds.
            {
              uint ns;
              if ((Flags & FHEXTRA_HTIME_MTIME)!=0 && (ns=(Raw->Get4() & 0x3fffffff))<1000000000)
                hd->mtime.Adjust(ns);
              if ((Flags & FHEXTRA_HTIME_CTIME)!=0 && (ns=(Raw->Get4() & 0x3fffffff))<1000000000)
                hd->ctime.Adjust(ns);
              if ((Flags & FHEXTRA_HTIME_ATIME)!=0 && (ns=(Raw->Get4() & 0x3fffffff))<1000000000)
                hd->atime.Adjust(ns);
            }
          }
          break;
        case FHEXTRA_VERSION:
          if (FieldSize>=1)
          {
            Raw->GetV(); // Skip flags field.
            uint Version=(uint)Raw->GetV();
            if (Version!=0)
            {
              hd->Version=true;

              wchar VerText[20];
              swprintf(VerText,ASIZE(VerText),L";%u",Version);
              wcsncatz(hd->FileName,VerText,ASIZE(hd->FileName));
            }
          }
          break;
        case FHEXTRA_REDIR:
          {
            hd->RedirType=(FILE_SYSTEM_REDIRECT)Raw->GetV();
            uint Flags=(uint)Raw->GetV();
            hd->DirTarget=(Flags & FHEXTRA_REDIR_DIR)!=0;
            size_t NameSize=(size_t)Raw->GetV();

            char UtfName[NM*4];
            *UtfName=0;
            if (NameSize<ASIZE(UtfName)-1)
            {
              Raw->GetB(UtfName,NameSize);
              UtfName[NameSize]=0;
            }
#ifdef _WIN_ALL
            UnixSlashToDos(UtfName,UtfName,ASIZE(UtfName));
#endif
            UtfToWide(UtfName,hd->RedirName,ASIZE(hd->RedirName));
          }
          break;
        case FHEXTRA_UOWNER:
          {
            uint Flags=(uint)Raw->GetV();
            hd->UnixOwnerNumeric=(Flags & FHEXTRA_UOWNER_NUMUID)!=0;
            hd->UnixGroupNumeric=(Flags & FHEXTRA_UOWNER_NUMGID)!=0;
            *hd->UnixOwnerName=*hd->UnixGroupName=0;
            if ((Flags & FHEXTRA_UOWNER_UNAME)!=0)
            {
              size_t Length=(size_t)Raw->GetV();
              Length=Min(Length,ASIZE(hd->UnixOwnerName)-1);
              Raw->GetB(hd->UnixOwnerName,Length);
              hd->UnixOwnerName[Length]=0;
            }
            if ((Flags & FHEXTRA_UOWNER_GNAME)!=0)
            {
              size_t Length=(size_t)Raw->GetV();
              Length=Min(Length,ASIZE(hd->UnixGroupName)-1);
              Raw->GetB(hd->UnixGroupName,Length);
              hd->UnixGroupName[Length]=0;
            }
#ifdef _UNIX
            if (hd->UnixOwnerNumeric)
              hd->UnixOwnerID=(uid_t)Raw->GetV();
            if (hd->UnixGroupNumeric)
              hd->UnixGroupID=(gid_t)Raw->GetV();
#else
            // Need these fields in Windows too for 'list' command,
            // but uid_t and gid_t are not defined.
            if (hd->UnixOwnerNumeric)
              hd->UnixOwnerID=(uint)Raw->GetV();
            if (hd->UnixGroupNumeric)
              hd->UnixGroupID=(uint)Raw->GetV();
#endif
            hd->UnixOwnerSet=true;
          }
          break;
        case FHEXTRA_SUBDATA:
          {
            // RAR 5.21 and earlier set FHEXTRA_SUBDATA size to 1 less than
            // required. It did not hurt extraction, because UnRAR 5.21
            // and earlier ignored this field and set FieldSize as data left
            // in entire extra area. But now we set the correct field size
            // and set FieldSize based on the actual extra record size,
            // so we need to adjust it for those older archives here.
            // FHEXTRA_SUBDATA in those archives always belongs to HEAD_SERVICE
            // and always is last in extra area. So since its size is by 1
            // less than needed, we always have 1 byte left in extra area,
            // which fact we use here to detect such archives.
            if (bb->HeaderType==HEAD_SERVICE && Raw->Size()-NextPos==1)
              FieldSize++;

            // We cannot allocate too much memory here, because above
            // we check FieldSize againt Raw size and we control that Raw size
            // is sensible when reading headers.
            hd->SubData.Alloc((size_t)FieldSize);
            Raw->GetB(hd->SubData.Addr(0),(size_t)FieldSize);
          }
          break;
      }
    }

    Raw->SetPos(NextPos);
  }
}


#ifndef SFX_MODULE
size_t Archive::ReadHeader14()
{
  RawRead Raw(this);
  if (CurBlockPos<=(int64)SFXSize)
  {
    Raw.Read(SIZEOF_MAINHEAD14);
    MainHead.Reset();
    byte Mark[4];
    Raw.GetB(Mark,4);
    uint HeadSize=Raw.Get2();
    if (HeadSize<7)
      return false;
    byte Flags=Raw.Get1();
    NextBlockPos=CurBlockPos+HeadSize;
    CurHeaderType=HEAD_MAIN;

    Volume=(Flags & MHD_VOLUME)!=0;
    Solid=(Flags & MHD_SOLID)!=0;
    Locked=(Flags & MHD_LOCK)!=0;
    MainHead.CommentInHeader=(Flags & MHD_COMMENT)!=0;
    MainHead.PackComment=(Flags & MHD_PACK_COMMENT)!=0;
  }
  else
  {
    Raw.Read(SIZEOF_FILEHEAD14);
    FileHead.Reset();

    FileHead.HeaderType=HEAD_FILE;
    FileHead.DataSize=Raw.Get4();
    FileHead.UnpSize=Raw.Get4();
    FileHead.FileHash.Type=HASH_RAR14;
    FileHead.FileHash.CRC32=Raw.Get2();
    FileHead.HeadSize=Raw.Get2();
    if (FileHead.HeadSize<21)
      return false;
    uint FileTime=Raw.Get4();
    FileHead.FileAttr=Raw.Get1();
    FileHead.Flags=Raw.Get1()|LONG_BLOCK;
    FileHead.UnpVer=(Raw.Get1()==2) ? 13 : 10;
    size_t NameSize=Raw.Get1();
    FileHead.Method=Raw.Get1();

    FileHead.SplitBefore=(FileHead.Flags & LHD_SPLIT_BEFORE)!=0;
    FileHead.SplitAfter=(FileHead.Flags & LHD_SPLIT_AFTER)!=0;
    FileHead.Encrypted=(FileHead.Flags & LHD_PASSWORD)!=0;
    FileHead.CryptMethod=FileHead.Encrypted ? CRYPT_RAR13:CRYPT_NONE;

    FileHead.PackSize=FileHead.DataSize;
    FileHead.WinSize=0x10000;
    FileHead.Dir=(FileHead.FileAttr & 0x10)!=0;

    FileHead.HostOS=HOST_MSDOS;
    FileHead.HSType=HSYS_WINDOWS;

    FileHead.mtime.SetDos(FileTime);

    Raw.Read(NameSize);

    char FileName[NM];
    size_t ReadNameSize=Min(NameSize,ASIZE(FileName)-1);
    Raw.GetB((byte *)FileName,ReadNameSize);
    FileName[ReadNameSize]=0;
    IntToExt(FileName,FileName,ASIZE(FileName));
    CharToWide(FileName,FileHead.FileName,ASIZE(FileHead.FileName));
    ConvertNameCase(FileHead.FileName);
    ConvertFileHeader(&FileHead);

    if (Raw.Size()!=0)
      NextBlockPos=CurBlockPos+FileHead.HeadSize+FileHead.PackSize;
    CurHeaderType=HEAD_FILE;
  }
  return NextBlockPos>CurBlockPos ? Raw.Size() : 0;
}
#endif


#ifndef SFX_MODULE
void Archive::ConvertNameCase(wchar *Name)
{
  if (Cmd->ConvertNames==NAMES_UPPERCASE)
    wcsupper(Name);
  if (Cmd->ConvertNames==NAMES_LOWERCASE)
    wcslower(Name);
}
#endif


bool Archive::IsArcDir()
{
  return FileHead.Dir;
}


void Archive::ConvertAttributes()
{
#if defined(_WIN_ALL) || defined(_EMX)
  if (FileHead.HSType!=HSYS_WINDOWS)
    FileHead.FileAttr=FileHead.Dir ? 0x10 : 0x20;
#endif
#ifdef _UNIX
  // umask defines which permission bits must not be set by default
  // when creating a file or directory. The typical default value
  // for the process umask is S_IWGRP | S_IWOTH (octal 022),
  // resulting in 0644 mode for new files.
  // Normally umask is applied automatically when creating a file,
  // but we set attributes with chmod later, so we need to calculate
  // resulting attributes here. We do it only for non-Unix archives.
  // We restore native Unix attributes as is, because it can be backup.
  static mode_t mask = (mode_t) -1;

  if (mask == (mode_t) -1)
  {
    // umask call returns the current umask value. Argument (022) is not
    // really important here.
    mask = umask(022);

    // Restore the original umask value, which was changed to 022 above.
    umask(mask);
  }

  switch(FileHead.HSType)
  {
    case HSYS_WINDOWS:
      {
        // Mapping MSDOS, OS/2 and Windows file attributes to Unix.

        if (FileHead.FileAttr & 0x10) // FILE_ATTRIBUTE_DIRECTORY
        {
          // For directories we use 0777 mask.
          FileHead.FileAttr=0777 & ~mask;
        }
        else
          if (FileHead.FileAttr & 1)  // FILE_ATTRIBUTE_READONLY
          {
            // For read only files we use 0444 mask with 'w' bits turned off.
            FileHead.FileAttr=0444 & ~mask;
          }
          else
          {
            // umask does not set +x for regular files, so we use 0666
            // instead of 0777 as for directories.
            FileHead.FileAttr=0666 & ~mask;
          }
      }
      break;
    case HSYS_UNIX:
      break;
    default:
      if (FileHead.Dir)
        FileHead.FileAttr=0x41ff & ~mask;
      else
        FileHead.FileAttr=0x81b6 & ~mask;
      break;
  }
#endif
}


void Archive::ConvertFileHeader(FileHeader *hd)
{
  if (hd->HSType==HSYS_UNKNOWN)
    if (hd->Dir)
      hd->FileAttr=0x10;
    else
      hd->FileAttr=0x20;

#ifdef _WIN_ALL
  if (hd->HSType==HSYS_UNIX) // Convert Unix, OS X and Android decomposed chracters to Windows precomposed.
    ConvertToPrecomposed(hd->FileName,ASIZE(hd->FileName));
#endif

  for (wchar *s=hd->FileName;*s!=0;s++)
  {
#ifdef _UNIX
    // Backslash is the invalid character for Windows file headers,
    // but it can present in Unix file names extracted in Unix.
    if (*s=='\\' && Format==RARFMT50 && hd->HSType==HSYS_WINDOWS)
      *s='_';
#endif

#if defined(_WIN_ALL) || defined(_EMX)
    // RAR 5.0 archives do not use '\' as path separator, so if we see it,
    // it means that it is a part of Unix file name, which we cannot
    // extract in Windows.
    if (*s=='\\' && Format==RARFMT50)
      *s='_';

    // ':' in file names is allowed in Unix, but not in Windows.
    // Even worse, file data will be written to NTFS stream on NTFS,
    // so automatic name correction on file create error in extraction
    // routine does not work. In Windows and DOS versions we better
    // replace ':' now.
    if (*s==':')
      *s='_';
#endif

    // This code must be performed only after other path separator checks,
    // because it produces backslashes illegal for some of checks above.
    // Backslash is allowed in file names in Unix, but not in Windows.
    // Still, RAR 4.x uses backslashes as path separator even in Unix.
    // Forward slash is not allowed in both systems. In RAR 5.0 we use
    // the forward slash as universal path separator.
    if (*s=='/' || *s=='\\' && Format!=RARFMT50)
      *s=CPATHDIVIDER;
  }
}


int64 Archive::GetStartPos()
{
  int64 StartPos=SFXSize+MarkHead.HeadSize;
  if (Format==RARFMT15)
    StartPos+=MainHead.HeadSize;
  else // RAR 5.0.
    StartPos+=CryptHead.HeadSize+FullHeaderSize(MainHead.HeadSize);
  return StartPos;
}


bool Archive::ReadSubData(Array<byte> *UnpData,File *DestFile,bool TestMode)
{
  if (BrokenHeader)
  {
    uiMsg(UIERROR_SUBHEADERBROKEN,FileName);
    ErrHandler.SetErrorCode(RARX_CRC);
    return false;
  }
  if (SubHead.Method>5 || SubHead.UnpVer>(Format==RARFMT50 ? VER_UNPACK5:VER_UNPACK))
  {
    uiMsg(UIERROR_SUBHEADERUNKNOWN,FileName);
    return false;
  }

  if (SubHead.PackSize==0 && !SubHead.SplitAfter)
    return true;

  SubDataIO.Init();
  Unpack Unpack(&SubDataIO);
  Unpack.Init(SubHead.WinSize,false);

  if (DestFile==NULL)
  {
    if (SubHead.UnpSize>0x1000000)
    {
      // So huge allocation must never happen in valid archives.
      uiMsg(UIERROR_SUBHEADERUNKNOWN,FileName);
      return false;
    }
    if (UnpData==NULL)
      SubDataIO.SetTestMode(true);
    else
    {
      UnpData->Alloc((size_t)SubHead.UnpSize);
      SubDataIO.SetUnpackToMemory(&(*UnpData)[0],(uint)SubHead.UnpSize);
    }
  }
  if (SubHead.Encrypted)
    if (Cmd->Password.IsSet())
      SubDataIO.SetEncryption(false,SubHead.CryptMethod,&Cmd->Password,
                SubHead.SaltSet ? SubHead.Salt:NULL,SubHead.InitV,
                SubHead.Lg2Count,SubHead.HashKey,SubHead.PswCheck);
    else
      return false;
  SubDataIO.UnpHash.Init(SubHead.FileHash.Type,1);
  SubDataIO.SetPackedSizeToRead(SubHead.PackSize);
  SubDataIO.EnableShowProgress(false);
  SubDataIO.SetFiles(this,DestFile);
  SubDataIO.SetTestMode(TestMode);
  SubDataIO.UnpVolume=SubHead.SplitAfter;
  SubDataIO.SetSubHeader(&SubHead,NULL);
  Unpack.SetDestSize(SubHead.UnpSize);
  if (SubHead.Method==0)
    CmdExtract::UnstoreFile(SubDataIO,SubHead.UnpSize);
  else
    Unpack.DoUnpack(SubHead.UnpVer,false);

  if (!SubDataIO.UnpHash.Cmp(&SubHead.FileHash,SubHead.UseHashKey ? SubHead.HashKey:NULL))
  {
    uiMsg(UIERROR_SUBHEADERDATABROKEN,FileName,SubHead.FileName);
    ErrHandler.SetErrorCode(RARX_CRC);
    if (UnpData!=NULL)
      UnpData->Reset();
    return false;
  }
  return true;
}

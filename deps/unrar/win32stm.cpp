

#if !defined(SFX_MODULE) && defined(_WIN_ALL)
void ExtractStreams20(Archive &Arc,const wchar *FileName)
{
  if (Arc.BrokenHeader)
  {
    uiMsg(UIERROR_STREAMBROKEN,Arc.FileName,FileName);
    ErrHandler.SetErrorCode(RARX_CRC);
    return;
  }

  if (Arc.StreamHead.Method<0x31 || Arc.StreamHead.Method>0x35 || Arc.StreamHead.UnpVer>VER_PACK)
  {
    uiMsg(UIERROR_STREAMUNKNOWN,Arc.FileName,FileName);
    ErrHandler.SetErrorCode(RARX_WARNING);
    return;
  }

  wchar StreamName[NM+2];
  if (FileName[0]!=0 && FileName[1]==0)
  {
    // Convert single character names like f:stream to .\f:stream to
    // resolve the ambiguity with drive letters.
    wcsncpyz(StreamName,L".\\",ASIZE(StreamName));
    wcsncatz(StreamName,FileName,ASIZE(StreamName));
  }
  else
    wcsncpyz(StreamName,FileName,ASIZE(StreamName));
  if (wcslen(StreamName)+strlen(Arc.StreamHead.StreamName)>=ASIZE(StreamName) ||
      Arc.StreamHead.StreamName[0]!=':')
  {
    uiMsg(UIERROR_STREAMBROKEN,Arc.FileName,FileName);
    ErrHandler.SetErrorCode(RARX_CRC);
    return;
  }

  wchar StoredName[NM];
  CharToWide(Arc.StreamHead.StreamName,StoredName,ASIZE(StoredName));
  ConvertPath(StoredName+1,StoredName+1,ASIZE(StoredName)-1);

  wcsncatz(StreamName,StoredName,ASIZE(StreamName));

  FindData fd;
  bool Found=FindFile::FastFind(FileName,&fd);

  if ((fd.FileAttr & FILE_ATTRIBUTE_READONLY)!=0)
    SetFileAttr(FileName,fd.FileAttr & ~FILE_ATTRIBUTE_READONLY);

  File CurFile;
  if (CurFile.WCreate(StreamName))
  {
    ComprDataIO DataIO;
    Unpack Unpack(&DataIO);
    Unpack.Init(0x10000,false);

    DataIO.SetPackedSizeToRead(Arc.StreamHead.DataSize);
    DataIO.EnableShowProgress(false);
    DataIO.SetFiles(&Arc,&CurFile);
    DataIO.UnpHash.Init(HASH_CRC32,1);
    Unpack.SetDestSize(Arc.StreamHead.UnpSize);
    Unpack.DoUnpack(Arc.StreamHead.UnpVer,false);

    if (Arc.StreamHead.StreamCRC!=DataIO.UnpHash.GetCRC32())
    {
      uiMsg(UIERROR_STREAMBROKEN,Arc.FileName,StreamName);
      ErrHandler.SetErrorCode(RARX_CRC);
    }
    else
      CurFile.Close();
  }
  File HostFile;
  if (Found && HostFile.Open(FileName,FMF_OPENSHARED|FMF_UPDATE))
    SetFileTime(HostFile.GetHandle(),&fd.ftCreationTime,&fd.ftLastAccessTime,
                &fd.ftLastWriteTime);
  if ((fd.FileAttr & FILE_ATTRIBUTE_READONLY)!=0)
    SetFileAttr(FileName,fd.FileAttr);
}
#endif


#ifdef _WIN_ALL
void ExtractStreams(Archive &Arc,const wchar *FileName,bool TestMode)
{
  wchar FullName[NM+2];
  if (FileName[0]!=0 && FileName[1]==0)
  {
    // Convert single character names like f:stream to .\f:stream to
    // resolve the ambiguity with drive letters.
    wcsncpyz(FullName,L".\\",ASIZE(FullName));
    wcsncatz(FullName,FileName,ASIZE(FullName));
  }
  else
    wcsncpyz(FullName,FileName,ASIZE(FullName));

  wchar StreamName[NM];
  GetStreamNameNTFS(Arc,StreamName,ASIZE(StreamName));
  if (*StreamName!=':')
  {
    uiMsg(UIERROR_STREAMBROKEN,Arc.FileName,FileName);
    ErrHandler.SetErrorCode(RARX_CRC);
    return;
  }

  if (TestMode)
  {
    File CurFile;
    Arc.ReadSubData(NULL,&CurFile,true);
    return;
  }

  wcsncatz(FullName,StreamName,ASIZE(FullName));

  FindData fd;
  bool Found=FindFile::FastFind(FileName,&fd);

  if ((fd.FileAttr & FILE_ATTRIBUTE_READONLY)!=0)
    SetFileAttr(FileName,fd.FileAttr & ~FILE_ATTRIBUTE_READONLY);
  File CurFile;
  if (CurFile.WCreate(FullName) && Arc.ReadSubData(NULL,&CurFile,false))
    CurFile.Close();
  File HostFile;
  if (Found && HostFile.Open(FileName,FMF_OPENSHARED|FMF_UPDATE))
    SetFileTime(HostFile.GetHandle(),&fd.ftCreationTime,&fd.ftLastAccessTime,
                &fd.ftLastWriteTime);

  // Restoring original file attributes. Important if file was read only
  // or did not have "Archive" attribute
  SetFileAttr(FileName,fd.FileAttr);
}
#endif


void GetStreamNameNTFS(Archive &Arc,wchar *StreamName,size_t MaxSize)
{
  byte *Data=&Arc.SubHead.SubData[0];
  size_t DataSize=Arc.SubHead.SubData.Size();
  if (Arc.Format==RARFMT15)
  {
    size_t DestSize=Min(DataSize/2,MaxSize-1);
    RawToWide(Data,StreamName,DestSize);
    StreamName[DestSize]=0;
  }
  else
  {
    char UtfString[NM*4];
    size_t DestSize=Min(DataSize,ASIZE(UtfString)-1);
    memcpy(UtfString,Data,DestSize);
    UtfString[DestSize]=0;
    UtfToWide(UtfString,StreamName,MaxSize);
  }
}

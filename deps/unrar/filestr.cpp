#include "rar.hpp"

bool ReadTextFile(
  const wchar *Name,
  StringList *List,
  bool Config,
  bool AbortOnError,
  RAR_CHARSET SrcCharset,
  bool Unquote,
  bool SkipComments,
  bool ExpandEnvStr)
{
  wchar FileName[NM];
  *FileName=0;

  if (Name!=NULL)
    if (Config)
      GetConfigName(Name,FileName,ASIZE(FileName),true,false);
    else
      wcsncpyz(FileName,Name,ASIZE(FileName));

  File SrcFile;
  if (*FileName!=0)
  {
    bool OpenCode=AbortOnError ? SrcFile.WOpen(FileName):SrcFile.Open(FileName,0);

    if (!OpenCode)
    {
      if (AbortOnError)
        ErrHandler.Exit(RARX_OPEN);
      return false;
    }
  }
  else
    SrcFile.SetHandleType(FILE_HANDLESTD);

  uint DataSize=0,ReadSize;
  const int ReadBlock=4096;

  Array<byte> Data(ReadBlock);
  while ((ReadSize=SrcFile.Read(&Data[DataSize],ReadBlock))!=0)
  {
    DataSize+=ReadSize;
    Data.Add(ReadSize); // Always have ReadBlock available for next data.
  }
  // Set to really read size, so we can zero terminate it correctly.
  Data.Alloc(DataSize);

  int LittleEndian=DataSize>=2 && Data[0]==255 && Data[1]==254 ? 1:0;
  int BigEndian=DataSize>=2 && Data[0]==254 && Data[1]==255 ? 1:0;
  bool Utf8=DataSize>=3 && Data[0]==0xef && Data[1]==0xbb && Data[2]==0xbf;

  if (SrcCharset==RCH_DEFAULT)
    SrcCharset=DetectTextEncoding(&Data[0],DataSize);

  Array<wchar> DataW;

  if (SrcCharset==RCH_DEFAULT || SrcCharset==RCH_OEM || SrcCharset==RCH_ANSI)
  {
    Data.Push(0); // Zero terminate.
#if defined(_WIN_ALL)
    if (SrcCharset==RCH_OEM)
      OemToCharA((char *)&Data[0],(char *)&Data[0]);
#endif
    DataW.Alloc(Data.Size());
    CharToWide((char *)&Data[0],&DataW[0],DataW.Size());
  }

  if (SrcCharset==RCH_UNICODE)
  {
    size_t Start=2; // Skip byte order mark.
    if (!LittleEndian && !BigEndian) // No byte order mask.
    {
      Start=0;
      LittleEndian=1;
    }
    
    DataW.Alloc(Data.Size()/2+1);
    size_t End=Data.Size() & ~1; // We need even bytes number for UTF-16.
    for (size_t I=Start;I<End;I+=2)
      DataW[(I-Start)/2]=Data[I+BigEndian]+Data[I+LittleEndian]*256;
    DataW[(End-Start)/2]=0;
  }

  if (SrcCharset==RCH_UTF8)
  {
    Data.Push(0); // Zero terminate data.
    DataW.Alloc(Data.Size());
    UtfToWide((const char *)(Data+(Utf8 ? 3:0)),&DataW[0],DataW.Size());
  }

  wchar *CurStr=&DataW[0];

  while (*CurStr!=0)
  {
    wchar *NextStr=CurStr,*CmtPtr=NULL;
    while (*NextStr!='\r' && *NextStr!='\n' && *NextStr!=0)
    {
      if (SkipComments && NextStr[0]=='/' && NextStr[1]=='/')
      {
        *NextStr=0;
        CmtPtr=NextStr;
      }
      NextStr++;
    }
    bool Done=*NextStr==0;

    *NextStr=0;
    for (wchar *SpacePtr=(CmtPtr!=NULL ? CmtPtr:NextStr)-1;SpacePtr>=CurStr;SpacePtr--)
    {
      if (*SpacePtr!=' ' && *SpacePtr!='\t')
        break;
      *SpacePtr=0;
    }
    
    if (Unquote && *CurStr=='\"')
    {
      size_t Length=wcslen(CurStr);
      if (CurStr[Length-1]=='\"')
      {
        CurStr[Length-1]=0;
        CurStr++;
      }
    }

    bool Expanded=false;
#if defined(_WIN_ALL)
    if (ExpandEnvStr && *CurStr=='%') // Expand environment variables in Windows.
    {
      wchar ExpName[NM];
      *ExpName=0;
      DWORD Result=ExpandEnvironmentStrings(CurStr,ExpName,ASIZE(ExpName));
      Expanded=Result!=0 && Result<ASIZE(ExpName);
      if (Expanded && *ExpName!=0)
        List->AddString(ExpName);
    }
#endif
    if (!Expanded && *CurStr!=0)
      List->AddString(CurStr);

    if (Done)
      break;
    CurStr=NextStr+1;
    while (*CurStr=='\r' || *CurStr=='\n')
      CurStr++;
  }
  return true;
}


RAR_CHARSET DetectTextEncoding(const byte *Data,size_t DataSize)
{
  if (DataSize>3 && Data[0]==0xef && Data[1]==0xbb && Data[2]==0xbf &&
      IsTextUtf8(Data+3,DataSize-3))
    return RCH_UTF8;

  bool LittleEndian=DataSize>2 && Data[0]==255 && Data[1]==254;
  bool BigEndian=DataSize>2 && Data[0]==254 && Data[1]==255;

  if (LittleEndian || BigEndian)  
    for (size_t I=LittleEndian ? 3 : 2;I<DataSize;I+=2)
      if (Data[I]<32 && Data[I]!='\r' && Data[I]!='\n')
        return RCH_UNICODE; // High byte in UTF-16 char is found.

  return RCH_DEFAULT;
}

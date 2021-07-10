#include "rar.hpp"
#include "log.cpp"

static MESSAGE_TYPE MsgStream=MSG_STDOUT;
static RAR_CHARSET RedirectCharset=RCH_DEFAULT;

const int MaxMsgSize=2*NM+2048;

static bool StdoutRedirected=false,StderrRedirected=false,StdinRedirected=false;

#ifdef _WIN_ALL
static bool IsRedirected(DWORD nStdHandle)
{
  HANDLE hStd=GetStdHandle(nStdHandle);
  DWORD Mode;
  return GetFileType(hStd)!=FILE_TYPE_CHAR || GetConsoleMode(hStd,&Mode)==0;
}
#endif


void InitConsole()
{
#ifdef _WIN_ALL
  // We want messages like file names or progress percent to be printed
  // immediately. Use only in Windows, in Unix they can cause wprintf %ls
  // to fail with non-English strings.
  setbuf(stdout,NULL);
  setbuf(stderr,NULL);

  // Detect if output is redirected and set output mode properly.
  // We do not want to send Unicode output to files and especially to pipes
  // like '|more', which cannot handle them correctly in Windows.
  // In Unix console output is UTF-8 and it is handled correctly
  // when redirecting, so no need to perform any adjustments.
  StdoutRedirected=IsRedirected(STD_OUTPUT_HANDLE);
  StderrRedirected=IsRedirected(STD_ERROR_HANDLE);
  StdinRedirected=IsRedirected(STD_INPUT_HANDLE);
#ifdef _MSC_VER
  if (!StdoutRedirected)
    _setmode(_fileno(stdout), _O_U16TEXT);
  if (!StderrRedirected)
    _setmode(_fileno(stderr), _O_U16TEXT);
#endif
#elif defined(_UNIX)
  StdoutRedirected=!isatty(fileno(stdout));
  StderrRedirected=!isatty(fileno(stderr));
  StdinRedirected=!isatty(fileno(stdin));
#endif
}


void SetConsoleMsgStream(MESSAGE_TYPE MsgStream)
{
  ::MsgStream=MsgStream;
}


void SetConsoleRedirectCharset(RAR_CHARSET RedirectCharset)
{
  ::RedirectCharset=RedirectCharset;
}


#ifndef SILENT
static void cvt_wprintf(FILE *dest,const wchar *fmt,va_list arglist)
{
  // This buffer is for format string only, not for entire output,
  // so it can be short enough.
  wchar fmtw[1024];
  PrintfPrepareFmt(fmt,fmtw,ASIZE(fmtw));
#ifdef _WIN_ALL
  safebuf wchar Msg[MaxMsgSize];
  if (dest==stdout && StdoutRedirected || dest==stderr && StderrRedirected)
  {
    HANDLE hOut=GetStdHandle(dest==stdout ? STD_OUTPUT_HANDLE:STD_ERROR_HANDLE);
    vswprintf(Msg,ASIZE(Msg),fmtw,arglist);
    DWORD Written;
    if (RedirectCharset==RCH_UNICODE)
      WriteFile(hOut,Msg,(DWORD)wcslen(Msg)*sizeof(*Msg),&Written,NULL);
    else
    {
      // Avoid Unicode for redirect in Windows, it does not work with pipes.
      safebuf char MsgA[MaxMsgSize];
      if (RedirectCharset==RCH_UTF8)
        WideToUtf(Msg,MsgA,ASIZE(MsgA));
      else
        WideToChar(Msg,MsgA,ASIZE(MsgA));
      if (RedirectCharset==RCH_DEFAULT || RedirectCharset==RCH_OEM)
        CharToOemA(MsgA,MsgA); // Console tools like 'more' expect OEM encoding.

      // We already converted \n to \r\n above, so we use WriteFile instead
      // of C library to avoid unnecessary additional conversion.
      WriteFile(hOut,MsgA,(DWORD)strlen(MsgA),&Written,NULL);
    }
    return;
  }
  // MSVC2008 vfwprintf writes every character to console separately
  // and it is too slow. We use direct WriteConsole call instead.
  vswprintf(Msg,ASIZE(Msg),fmtw,arglist);
  HANDLE hOut=GetStdHandle(dest==stderr ? STD_ERROR_HANDLE:STD_OUTPUT_HANDLE);
  DWORD Written;
  WriteConsole(hOut,Msg,(DWORD)wcslen(Msg),&Written,NULL);
#else
  vfwprintf(dest,fmtw,arglist);
  // We do not use setbuf(NULL) in Unix (see comments in InitConsole).
  fflush(dest);
#endif
}


void mprintf(const wchar *fmt,...)
{
  if (MsgStream==MSG_NULL || MsgStream==MSG_ERRONLY)
    return;

  fflush(stderr); // Ensure proper message order.

  va_list arglist;
  va_start(arglist,fmt);
  FILE *dest=MsgStream==MSG_STDERR ? stderr:stdout;
  cvt_wprintf(dest,fmt,arglist);
  va_end(arglist);
}
#endif


#ifndef SILENT
void eprintf(const wchar *fmt,...)
{
  if (MsgStream==MSG_NULL)
    return;

  fflush(stdout); // Ensure proper message order.

  va_list arglist;
  va_start(arglist,fmt);
  cvt_wprintf(stderr,fmt,arglist);
  va_end(arglist);
}
#endif


#ifndef SILENT
static void GetPasswordText(wchar *Str,uint MaxLength)
{
  if (MaxLength==0)
    return;
  if (StdinRedirected)
    getwstr(Str,MaxLength); // Read from pipe or redirected file.
  else
  {
#ifdef _WIN_ALL
    HANDLE hConIn=GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hConOut=GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD ConInMode,ConOutMode;
    DWORD Read=0;
    GetConsoleMode(hConIn,&ConInMode);
    GetConsoleMode(hConOut,&ConOutMode);
    SetConsoleMode(hConIn,ENABLE_LINE_INPUT);
    SetConsoleMode(hConOut,ENABLE_PROCESSED_OUTPUT|ENABLE_WRAP_AT_EOL_OUTPUT);

    ReadConsole(hConIn,Str,MaxLength-1,&Read,NULL);
    Str[Read]=0;
    SetConsoleMode(hConIn,ConInMode);
    SetConsoleMode(hConOut,ConOutMode);
#else
    char StrA[MAXPASSWORD*4]; // "*4" for multibyte UTF-8 characters.
#if defined(_EMX) || defined (__VMS)
    fgets(StrA,ASIZE(StrA)-1,stdin);
#elif defined(__sun)
    strncpyz(StrA,getpassphrase(""),ASIZE(StrA));
#else
    strncpyz(StrA,getpass(""),ASIZE(StrA));
#endif
    CharToWide(StrA,Str,MaxLength);
    cleandata(StrA,sizeof(StrA));
#endif
  }
  Str[MaxLength-1]=0;
  RemoveLF(Str);
}
#endif


#ifndef SILENT
bool GetConsolePassword(UIPASSWORD_TYPE Type,const wchar *FileName,SecPassword *Password)
{
  if (!StdinRedirected)
    uiAlarm(UIALARM_QUESTION);
  
  while (true)
  {
    if (!StdinRedirected)
      if (Type==UIPASSWORD_GLOBAL)
        eprintf(L"\n%s: ",St(MAskPsw));
      else
        eprintf(St(MAskPswFor),FileName);

    wchar PlainPsw[MAXPASSWORD];
    GetPasswordText(PlainPsw,ASIZE(PlainPsw));
    if (*PlainPsw==0 && Type==UIPASSWORD_GLOBAL)
      return false;
    if (!StdinRedirected && Type==UIPASSWORD_GLOBAL)
    {
      eprintf(St(MReAskPsw));
      wchar CmpStr[MAXPASSWORD];
      GetPasswordText(CmpStr,ASIZE(CmpStr));
      if (*CmpStr==0 || wcscmp(PlainPsw,CmpStr)!=0)
      {
        eprintf(St(MNotMatchPsw));
        cleandata(PlainPsw,sizeof(PlainPsw));
        cleandata(CmpStr,sizeof(CmpStr));
        continue;
      }
      cleandata(CmpStr,sizeof(CmpStr));
    }
    Password->Set(PlainPsw);
    cleandata(PlainPsw,sizeof(PlainPsw));
    break;
  }
  return true;
}
#endif


#ifndef SILENT
bool getwstr(wchar *str,size_t n)
{
  // Print buffered prompt title function before waiting for input.
  fflush(stderr);

  *str=0;
#if defined(_WIN_ALL)
  // fgetws does not work well with non-English text in Windows,
  // so we do not use it.
  if (StdinRedirected) // ReadConsole does not work if redirected.
  {
    // fgets does not work well with pipes in Windows in our test.
    // Let's use files.
    Array<char> StrA(n*4); // Up to 4 UTF-8 characters per wchar_t.
    File SrcFile;
    SrcFile.SetHandleType(FILE_HANDLESTD);
    int ReadSize=SrcFile.Read(&StrA[0],StrA.Size()-1);
    if (ReadSize<=0)
    {
      // Looks like stdin is a null device. We can enter to infinite loop
      // calling Ask(), so let's better exit.
      ErrHandler.Exit(RARX_USERBREAK);
    }
    StrA[ReadSize]=0;

    // We expect ANSI encoding here, but "echo text|rar ..." to pipe to RAR,
    // such as send passwords, we get OEM encoding by default, unless we
    // use "chcp" in console. But we avoid OEM to ANSI conversion,
    // because we also want to handle ANSI files redirection correctly,
    // like "rar ... < ansifile.txt".
    CharToWide(&StrA[0],str,n);
    cleandata(&StrA[0],StrA.Size()); // We can use this function to enter passwords.
  }
  else
  {
    DWORD ReadSize=0;
    if (ReadConsole(GetStdHandle(STD_INPUT_HANDLE),str,DWORD(n-1),&ReadSize,NULL)==0)
      return false;
    str[ReadSize]=0;
  }
#else
  if (fgetws(str,n,stdin)==NULL)
    ErrHandler.Exit(RARX_USERBREAK); // Avoid infinite Ask() loop.
#endif
  RemoveLF(str);
  return true;
}
#endif


#ifndef SILENT
// We allow this function to return 0 in case of invalid input,
// because it might be convenient to press Enter to some not dangerous
// prompts like "insert disk with next volume". We should call this function
// again in case of 0 in dangerous prompt such as overwriting file.
int Ask(const wchar *AskStr)
{
  uiAlarm(UIALARM_QUESTION);

  const int MaxItems=10;
  wchar Item[MaxItems][40];
  int ItemKeyPos[MaxItems],NumItems=0;

  for (const wchar *NextItem=AskStr;NextItem!=NULL;NextItem=wcschr(NextItem+1,'_'))
  {
    wchar *CurItem=Item[NumItems];
    wcsncpyz(CurItem,NextItem+1,ASIZE(Item[0]));
    wchar *EndItem=wcschr(CurItem,'_');
    if (EndItem!=NULL)
      *EndItem=0;
    int KeyPos=0,CurKey;
    while ((CurKey=CurItem[KeyPos])!=0)
    {
      bool Found=false;
      for (int I=0;I<NumItems && !Found;I++)
        if (toupperw(Item[I][ItemKeyPos[I]])==toupperw(CurKey))
          Found=true;
      if (!Found && CurKey!=' ')
        break;
      KeyPos++;
    }
    ItemKeyPos[NumItems]=KeyPos;
    NumItems++;
  }

  for (int I=0;I<NumItems;I++)
  {
    eprintf(I==0 ? (NumItems>3 ? L"\n":L" "):L", ");
    int KeyPos=ItemKeyPos[I];
    for (int J=0;J<KeyPos;J++)
      eprintf(L"%c",Item[I][J]);
    eprintf(L"[%c]%ls",Item[I][KeyPos],&Item[I][KeyPos+1]);
  }
  eprintf(L" ");
  wchar Str[50];
  getwstr(Str,ASIZE(Str));
  wchar Ch=toupperw(Str[0]);
  for (int I=0;I<NumItems;I++)
    if (Ch==Item[I][ItemKeyPos[I]])
      return I+1;
  return 0;
}
#endif


static bool IsCommentUnsafe(const wchar *Data,size_t Size)
{
  for (size_t I=0;I<Size;I++)
    if (Data[I]==27 && Data[I+1]=='[')
      for (size_t J=I+2;J<Size;J++)
      {
        // Return true for <ESC>[{key};"{string}"p used to redefine
        // a keyboard key on some terminals.
        if (Data[J]=='\"')
          return true;
        if (!IsDigit(Data[J]) && Data[J]!=';')
          break;
      }
  return false;
}


void OutComment(const wchar *Comment,size_t Size)
{
  if (IsCommentUnsafe(Comment,Size))
    return;
  const size_t MaxOutSize=0x400;
  for (size_t I=0;I<Size;I+=MaxOutSize)
  {
    wchar Msg[MaxOutSize+1];
    size_t CopySize=Min(MaxOutSize,Size-I);
    wcsncpy(Msg,Comment+I,CopySize);
    Msg[CopySize]=0;
    mprintf(L"%s",Msg);
  }
  mprintf(L"\n");
}

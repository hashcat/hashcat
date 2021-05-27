#include "rar.hpp"

ErrorHandler::ErrorHandler()
{
  Clean();
}


void ErrorHandler::Clean()
{
  ExitCode=RARX_SUCCESS;
  ErrCount=0;
  EnableBreak=true;
  Silent=false;
  UserBreak=false;
  MainExit=false;
  DisableShutdown=false;
  ReadErrIgnoreAll=false;
}


void ErrorHandler::MemoryError()
{
  MemoryErrorMsg();
  Exit(RARX_MEMORY);
}


void ErrorHandler::OpenError(const wchar *FileName)
{
#ifndef SILENT
  OpenErrorMsg(FileName);
  Exit(RARX_OPEN);
#endif
}


void ErrorHandler::CloseError(const wchar *FileName)
{
  if (!UserBreak)
  {
    uiMsg(UIERROR_FILECLOSE,FileName);
    SysErrMsg();
  }
  // We must not call Exit and throw an exception here, because this function
  // is called from File object destructor and can be invoked when stack
  // unwinding while handling another exception. Throwing a new exception
  // when stack unwinding is prohibited and terminates a program.
  // If necessary, we can check std::uncaught_exception() before throw.
  SetErrorCode(RARX_FATAL);
}


void ErrorHandler::ReadError(const wchar *FileName)
{
#ifndef SILENT
  ReadErrorMsg(FileName);
#endif
#if !defined(SILENT) || defined(RARDLL)
  Exit(RARX_READ);
#endif
}


void ErrorHandler::AskRepeatRead(const wchar *FileName,bool &Ignore,bool &Retry,bool &Quit)
{
  SetErrorCode(RARX_READ);
#if !defined(SILENT) && !defined(SFX_MODULE)
  if (!Silent)
  {
    uiMsg(UIERROR_FILEREAD,UINULL,FileName);
    SysErrMsg();
    if (ReadErrIgnoreAll)
      Ignore=true;
    else
    {
      bool All=false;
      uiAskRepeatRead(FileName,Ignore,All,Retry,Quit);
      if (All)
        ReadErrIgnoreAll=Ignore=true;
      if (Quit) // Disable shutdown if user select Quit in read error prompt.
        DisableShutdown=true;
    }
    return;
  }
#endif
  Ignore=true; // Saving the file part for -y or -inul or "Ignore all" choice.
}


void ErrorHandler::WriteError(const wchar *ArcName,const wchar *FileName)
{
#ifndef SILENT
  WriteErrorMsg(ArcName,FileName);
#endif
#if !defined(SILENT) || defined(RARDLL)
  Exit(RARX_WRITE);
#endif
}


#ifdef _WIN_ALL
void ErrorHandler::WriteErrorFAT(const wchar *FileName)
{
  SysErrMsg();
  uiMsg(UIERROR_NTFSREQUIRED,FileName);
#if !defined(SILENT) && !defined(SFX_MODULE) || defined(RARDLL)
  Exit(RARX_WRITE);
#endif
}
#endif


bool ErrorHandler::AskRepeatWrite(const wchar *FileName,bool DiskFull)
{
#ifndef SILENT
  if (!Silent)
  {
    // We do not display "repeat write" prompt in Android, so we do not
    // need the matching system error message.
    SysErrMsg();
    bool Repeat=uiAskRepeatWrite(FileName,DiskFull);
    if (!Repeat) // Disable shutdown if user pressed Cancel in error dialog.
      DisableShutdown=true;
    return Repeat;
  }
#endif
  return false;
}


void ErrorHandler::SeekError(const wchar *FileName)
{
  if (!UserBreak)
  {
    uiMsg(UIERROR_FILESEEK,FileName);
    SysErrMsg();
  }
#if !defined(SILENT) || defined(RARDLL)
  Exit(RARX_FATAL);
#endif
}


void ErrorHandler::GeneralErrMsg(const wchar *fmt,...)
{
  va_list arglist;
  va_start(arglist,fmt);
  wchar Msg[1024];
  vswprintf(Msg,ASIZE(Msg),fmt,arglist);
  uiMsg(UIERROR_GENERALERRMSG,Msg);
  SysErrMsg();
  va_end(arglist);
}


void ErrorHandler::MemoryErrorMsg()
{
  uiMsg(UIERROR_MEMORY);
  SetErrorCode(RARX_MEMORY);
}


void ErrorHandler::OpenErrorMsg(const wchar *FileName)
{
  OpenErrorMsg(NULL,FileName);
}


void ErrorHandler::OpenErrorMsg(const wchar *ArcName,const wchar *FileName)
{
  Wait(); // Keep GUI responsive if many files cannot be opened when archiving.
  uiMsg(UIERROR_FILEOPEN,ArcName,FileName);
  SysErrMsg();
  SetErrorCode(RARX_OPEN);
}


void ErrorHandler::CreateErrorMsg(const wchar *FileName)
{
  CreateErrorMsg(NULL,FileName);
}


void ErrorHandler::CreateErrorMsg(const wchar *ArcName,const wchar *FileName)
{
  uiMsg(UIERROR_FILECREATE,ArcName,FileName);
  SysErrMsg();
  SetErrorCode(RARX_CREATE);
}


void ErrorHandler::ReadErrorMsg(const wchar *FileName)
{
  ReadErrorMsg(NULL,FileName);
}


void ErrorHandler::ReadErrorMsg(const wchar *ArcName,const wchar *FileName)
{
  uiMsg(UIERROR_FILEREAD,ArcName,FileName);
  SysErrMsg();
  SetErrorCode(RARX_READ);
}


void ErrorHandler::WriteErrorMsg(const wchar *ArcName,const wchar *FileName)
{
  uiMsg(UIERROR_FILEWRITE,ArcName,FileName);
  SysErrMsg();
  SetErrorCode(RARX_WRITE);
}


void ErrorHandler::ArcBrokenMsg(const wchar *ArcName)
{
  uiMsg(UIERROR_ARCBROKEN,ArcName);
  SetErrorCode(RARX_CRC);
}


void ErrorHandler::ChecksumFailedMsg(const wchar *ArcName,const wchar *FileName)
{
  uiMsg(UIERROR_CHECKSUM,ArcName,FileName);
  SetErrorCode(RARX_CRC);
}


void ErrorHandler::UnknownMethodMsg(const wchar *ArcName,const wchar *FileName)
{
  uiMsg(UIERROR_UNKNOWNMETHOD,ArcName,FileName);
  ErrHandler.SetErrorCode(RARX_FATAL);
}


void ErrorHandler::Exit(RAR_EXIT ExitCode)
{
  uiAlarm(UIALARM_ERROR);
  Throw(ExitCode);
}


void ErrorHandler::SetErrorCode(RAR_EXIT Code)
{
  switch(Code)
  {
    case RARX_WARNING:
    case RARX_USERBREAK:
      if (ExitCode==RARX_SUCCESS)
        ExitCode=Code;
      break;
    case RARX_CRC:
      if (ExitCode!=RARX_BADPWD)
        ExitCode=Code;
      break;
    case RARX_FATAL:
      if (ExitCode==RARX_SUCCESS || ExitCode==RARX_WARNING)
        ExitCode=RARX_FATAL;
      break;
    default:
      ExitCode=Code;
      break;
  }
  ErrCount++;
}


#ifdef _WIN_ALL
BOOL __stdcall ProcessSignal(DWORD SigType)
#else
#if defined(__sun)
extern "C"
#endif
void _stdfunction ProcessSignal(int SigType)
#endif
{
#ifdef _WIN_ALL
  // When a console application is run as a service, this allows the service
  // to continue running after the user logs off. 
  if (SigType==CTRL_LOGOFF_EVENT)
    return TRUE;
#endif

  ErrHandler.UserBreak=true;
  ErrHandler.SetDisableShutdown();
  mprintf(St(MBreak));

#ifdef _WIN_ALL
  // Let the main thread to handle 'throw' and destroy file objects.
  for (uint I=0;!ErrHandler.MainExit && I<50;I++)
    Sleep(100);
#if defined(USE_RC) && !defined(SFX_MODULE) && !defined(RARDLL)
  ExtRes.UnloadDLL();
#endif
  exit(RARX_USERBREAK);
#endif

#ifdef _UNIX
  static uint BreakCount=0;
  // User continues to press Ctrl+C, exit immediately without cleanup.
  if (++BreakCount>1)
    exit(RARX_USERBREAK);
  // Otherwise return from signal handler and let Wait() function to close
  // files and quit. We cannot use the same approach as in Windows,
  // because Unix signal handler can block execution of our main code.
#endif

#if defined(_WIN_ALL) && !defined(_MSC_VER)
  // Never reached, just to avoid a compiler warning
  return TRUE;
#endif
}


void ErrorHandler::SetSignalHandlers(bool Enable)
{
  EnableBreak=Enable;
#ifdef _WIN_ALL
  SetConsoleCtrlHandler(Enable ? ProcessSignal:NULL,TRUE);
#else
  signal(SIGINT,Enable ? ProcessSignal:SIG_IGN);
  signal(SIGTERM,Enable ? ProcessSignal:SIG_IGN);
#endif
}


void ErrorHandler::Throw(RAR_EXIT Code)
{
  if (Code==RARX_USERBREAK && !EnableBreak)
    return;
#if !defined(SILENT)
  // Do not write "aborted" when just displaying online help.
  if (Code!=RARX_SUCCESS && Code!=RARX_USERERROR)
    mprintf(L"\n%s\n",St(MProgAborted));
#endif
  SetErrorCode(Code);
  throw Code;
}


bool ErrorHandler::GetSysErrMsg(wchar *Msg,size_t Size)
{
#ifndef SILENT
#ifdef _WIN_ALL
  int ErrType=GetLastError();
  if (ErrType!=0)
    return FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                         NULL,ErrType,MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
                         Msg,(DWORD)Size,NULL)!=0;
#endif

#if defined(_UNIX) || defined(_EMX)
  if (errno!=0)
  {
    char *err=strerror(errno);
    if (err!=NULL)
    {
      CharToWide(err,Msg,Size);
      return true;
    }
  }
#endif
#endif
  return false;
}


void ErrorHandler::SysErrMsg()
{
#if !defined(SFX_MODULE) && !defined(SILENT)
  wchar Msg[1024];
  if (!GetSysErrMsg(Msg,ASIZE(Msg)))
    return;
#ifdef _WIN_ALL
  wchar *CurMsg=Msg;
  while (CurMsg!=NULL) // Print string with \r\n as several strings to multiple lines.
  {
    while (*CurMsg=='\r' || *CurMsg=='\n')
      CurMsg++;
    if (*CurMsg==0)
      break;
    wchar *EndMsg=wcschr(CurMsg,'\r');
    if (EndMsg==NULL)
      EndMsg=wcschr(CurMsg,'\n');
    if (EndMsg!=NULL)
    {
      *EndMsg=0;
      EndMsg++;
    }
    uiMsg(UIERROR_SYSERRMSG,CurMsg);
    CurMsg=EndMsg;
  }
#endif

#if defined(_UNIX) || defined(_EMX)
  uiMsg(UIERROR_SYSERRMSG,Msg);
#endif

#endif
}


int ErrorHandler::GetSystemErrorCode()
{
#ifdef _WIN_ALL
  return GetLastError();
#else
  return errno;
#endif
}


void ErrorHandler::SetSystemErrorCode(int Code)
{
#ifdef _WIN_ALL
  SetLastError(Code);
#else
  errno=Code;
#endif
}

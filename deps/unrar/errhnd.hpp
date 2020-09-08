#ifndef _RAR_ERRHANDLER_
#define _RAR_ERRHANDLER_

enum RAR_EXIT // RAR exit code.
{ 
  RARX_SUCCESS   =   0,
  RARX_WARNING   =   1,
  RARX_FATAL     =   2,
  RARX_CRC       =   3,
  RARX_LOCK      =   4,
  RARX_WRITE     =   5,
  RARX_OPEN      =   6,
  RARX_USERERROR =   7,
  RARX_MEMORY    =   8,
  RARX_CREATE    =   9,
  RARX_NOFILES   =  10,
  RARX_BADPWD    =  11,
  RARX_USERBREAK = 255
};

class ErrorHandler
{
  private:
    RAR_EXIT ExitCode;
    uint ErrCount;
    bool EnableBreak;
    bool Silent;
    bool DisableShutdown; // Shutdown is not suitable after last error.
  public:
    ErrorHandler();
    void Clean();
    void MemoryError();
    void OpenError(const wchar *FileName);
    void CloseError(const wchar *FileName);
    void ReadError(const wchar *FileName);
    bool AskRepeatRead(const wchar *FileName);
    void WriteError(const wchar *ArcName,const wchar *FileName);
    void WriteErrorFAT(const wchar *FileName);
    bool AskRepeatWrite(const wchar *FileName,bool DiskFull);
    void SeekError(const wchar *FileName);
    void GeneralErrMsg(const wchar *fmt,...);
    void MemoryErrorMsg();
    void OpenErrorMsg(const wchar *FileName);
    void OpenErrorMsg(const wchar *ArcName,const wchar *FileName);
    void CreateErrorMsg(const wchar *FileName);
    void CreateErrorMsg(const wchar *ArcName,const wchar *FileName);
    void ReadErrorMsg(const wchar *FileName);
    void ReadErrorMsg(const wchar *ArcName,const wchar *FileName);
    void WriteErrorMsg(const wchar *ArcName,const wchar *FileName);
    void ArcBrokenMsg(const wchar *ArcName);
    void ChecksumFailedMsg(const wchar *ArcName,const wchar *FileName);
    void UnknownMethodMsg(const wchar *ArcName,const wchar *FileName);
    void Exit(RAR_EXIT ExitCode);
    void SetErrorCode(RAR_EXIT Code);
    RAR_EXIT GetErrorCode() {return ExitCode;}
    uint GetErrorCount() {return ErrCount;}
    void SetSignalHandlers(bool Enable);
    void Throw(RAR_EXIT Code);
    void SetSilent(bool Mode) {Silent=Mode;}
    bool GetSysErrMsg(wchar *Msg,size_t Size);
    void SysErrMsg();
    int GetSystemErrorCode();
    void SetSystemErrorCode(int Code);
    void SetDisableShutdown() {DisableShutdown=true;}
    bool IsShutdownEnabled() {return !DisableShutdown;}

    bool UserBreak; // Ctrl+Break is pressed.
    bool MainExit; // main() is completed.
};


#endif

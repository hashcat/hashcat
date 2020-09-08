// Purely user interface function. Gets and returns user input.
UIASKREP_RESULT uiAskReplace(wchar *Name,size_t MaxNameSize,int64 FileSize,RarTime *FileTime,uint Flags)
{
  return UIASKREP_R_REPLACE;
}




void uiStartArchiveExtract(bool Extract,const wchar *ArcName)
{
}


bool uiStartFileExtract(const wchar *FileName,bool Extract,bool Test,bool Skip)
{
  return true;
}


void uiExtractProgress(int64 CurFileSize,int64 TotalFileSize,int64 CurSize,int64 TotalSize)
{
}


void uiProcessProgress(const char *Command,int64 CurSize,int64 TotalSize)
{
}


void uiMsgStore::Msg()
{
}


bool uiGetPassword(UIPASSWORD_TYPE Type,const wchar *FileName,SecPassword *Password)
{
  return false;
}


bool uiIsGlobalPasswordSet()
{
  return false;
}


void uiAlarm(UIALARM_TYPE Type)
{
}


bool uiIsAborted()
{
  return false;
}


void uiGiveTick()
{
}


#ifndef SFX_MODULE
const wchar *uiGetMonthName(int Month)
{
  return L"";
}
#endif

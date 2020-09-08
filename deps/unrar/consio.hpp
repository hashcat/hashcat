#ifndef _RAR_CONSIO_
#define _RAR_CONSIO_

void InitConsole();
void SetConsoleMsgStream(MESSAGE_TYPE MsgStream);
void SetConsoleRedirectCharset(RAR_CHARSET RedirectCharset);
void OutComment(const wchar *Comment,size_t Size);

#ifndef SILENT
bool GetConsolePassword(UIPASSWORD_TYPE Type,const wchar *FileName,SecPassword *Password);
#endif

#ifdef SILENT
  inline void mprintf(const wchar *fmt,...) {}
  inline void eprintf(const wchar *fmt,...) {}
  inline void Alarm() {}
  inline int Ask(const wchar *AskStr) {return 0;}
  inline bool getwstr(wchar *str,size_t n) {return false;}
#else
  void mprintf(const wchar *fmt,...);
  void eprintf(const wchar *fmt,...);
  void Alarm();
  int Ask(const wchar *AskStr);
  bool getwstr(wchar *str,size_t n);
#endif

#endif

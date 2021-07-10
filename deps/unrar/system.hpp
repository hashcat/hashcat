#ifndef _RAR_SYSTEM_
#define _RAR_SYSTEM_

#ifdef _WIN_ALL
#ifndef BELOW_NORMAL_PRIORITY_CLASS
#define BELOW_NORMAL_PRIORITY_CLASS     0x00004000
#define ABOVE_NORMAL_PRIORITY_CLASS     0x00008000
#endif
#ifndef PROCESS_MODE_BACKGROUND_BEGIN
#define PROCESS_MODE_BACKGROUND_BEGIN   0x00100000
#define PROCESS_MODE_BACKGROUND_END     0x00200000
#endif
#ifndef SHTDN_REASON_MAJOR_APPLICATION
#define SHTDN_REASON_MAJOR_APPLICATION  0x00040000
#define SHTDN_REASON_FLAG_PLANNED       0x80000000
#define SHTDN_REASON_MINOR_MAINTENANCE  0x00000001
#endif
#endif

void InitSystemOptions(int SleepTime);
void SetPriority(int Priority);
clock_t MonoClock();
void Wait();
bool EmailFile(const wchar *FileName,const wchar *MailToW);
void Shutdown(POWER_MODE Mode);
bool ShutdownCheckAnother(bool Open);

#ifdef _WIN_ALL
HMODULE WINAPI LoadSysLibrary(const wchar *Name);
bool IsUserAdmin();
#endif


#ifdef USE_SSE
enum SSE_VERSION {SSE_NONE,SSE_SSE,SSE_SSE2,SSE_SSSE3,SSE_SSE41,SSE_AVX2};
SSE_VERSION GetSSEVersion();
extern SSE_VERSION _SSE_Version;
#endif

#endif

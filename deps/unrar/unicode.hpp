#ifndef _RAR_UNICODE_
#define _RAR_UNICODE_

#if defined( _WIN_ALL)
#define DBCS_SUPPORTED
#endif

bool WideToChar(const wchar *Src,char *Dest,size_t DestSize);
bool CharToWide(const char *Src,wchar *Dest,size_t DestSize);
byte* WideToRaw(const wchar *Src,byte *Dest,size_t SrcSize);
wchar* RawToWide(const byte *Src,wchar *Dest,size_t DestSize);
void WideToUtf(const wchar *Src,char *Dest,size_t DestSize);
size_t WideToUtfSize(const wchar *Src);
bool UtfToWide(const char *Src,wchar *Dest,size_t DestSize);
bool IsTextUtf8(const byte *Src);
bool IsTextUtf8(const byte *Src,size_t SrcSize);

int wcsicomp(const wchar *s1,const wchar *s2);
int wcsnicomp(const wchar *s1,const wchar *s2,size_t n);
const wchar_t* wcscasestr(const wchar_t *str, const wchar_t *search);
#ifndef SFX_MODULE
wchar* wcslower(wchar *s);
wchar* wcsupper(wchar *s);
#endif
int toupperw(int ch);
int tolowerw(int ch);
int atoiw(const wchar *s);
int64 atoilw(const wchar *s);

#ifdef DBCS_SUPPORTED
class SupportDBCS
{
  public:
    SupportDBCS();
    void Init();

    char* charnext(const char *s);
    size_t strlend(const char *s);
    char *strchrd(const char *s, int c);
    char *strrchrd(const char *s, int c);
    void copychrd(char *dest,const char *src);

    bool IsLeadByte[256];
    bool DBCSMode;
};

extern SupportDBCS gdbcs;

inline char* charnext(const char *s) {return (char *)(gdbcs.DBCSMode ? gdbcs.charnext(s):s+1);}
inline size_t strlend(const char *s) {return (uint)(gdbcs.DBCSMode ? gdbcs.strlend(s):strlen(s));}
inline char* strchrd(const char *s, int c) {return (char *)(gdbcs.DBCSMode ? gdbcs.strchrd(s,c):strchr(s,c));}
inline char* strrchrd(const char *s, int c) {return (char *)(gdbcs.DBCSMode ? gdbcs.strrchrd(s,c):strrchr(s,c));}
inline void copychrd(char *dest,const char *src) {if (gdbcs.DBCSMode) gdbcs.copychrd(dest,src); else *dest=*src;}
inline bool IsDBCSMode() {return(gdbcs.DBCSMode);}
inline void InitDBCS() {gdbcs.Init();}

#else
#define charnext(s) ((s)+1)
#define strlend strlen
#define strchrd strchr
#define strrchrd strrchr
#define IsDBCSMode() (true)
inline void copychrd(char *dest,const char *src) {*dest=*src;}
#endif


#endif

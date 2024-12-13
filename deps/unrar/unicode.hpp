#ifndef _RAR_UNICODE_
#define _RAR_UNICODE_

#if defined( _WIN_ALL)
#define DBCS_SUPPORTED
#endif

bool WideToChar(const wchar *Src,char *Dest,size_t DestSize);
bool CharToWide(const char *Src,wchar *Dest,size_t DestSize);
byte* WideToRaw(const wchar *Src,size_t SrcSize,byte *Dest,size_t DestSize);
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

    bool IsLeadByte[256];
    bool DBCSMode;
};
extern SupportDBCS gdbcs;

inline char* charnext(const char *s) {return (char *)(gdbcs.DBCSMode ? gdbcs.charnext(s):s+1);}
inline bool IsDBCSMode() {return gdbcs.DBCSMode;}

#else
#define charnext(s) ((s)+1)
#define IsDBCSMode() (false)
#endif


#endif

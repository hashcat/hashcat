#ifndef _RAR_STRFN_
#define _RAR_STRFN_

const char* NullToEmpty(const char *Str);
const wchar* NullToEmpty(const wchar *Str);
void IntToExt(const char *Src,char *Dest,size_t DestSize);

enum ACTW_ENCODING { ACTW_DEFAULT, ACTW_OEM, ACTW_UTF8};
void ArcCharToWide(const char *Src,wchar *Dest,size_t DestSize,ACTW_ENCODING Encoding);


int stricomp(const char *s1,const char *s2);
int strnicomp(const char *s1,const char *s2,size_t n);
wchar* RemoveEOL(wchar *Str);
wchar* RemoveLF(wchar *Str);
unsigned char loctolower(unsigned char ch);
unsigned char loctoupper(unsigned char ch);

void strncpyz(char *dest, const char *src, size_t maxlen);
void wcsncpyz(wchar *dest, const wchar *src, size_t maxlen);
void strncatz(char* dest, const char* src, size_t maxlen);
void wcsncatz(wchar* dest, const wchar* src, size_t maxlen);

unsigned char etoupper(unsigned char ch);
wchar etoupperw(wchar ch);

bool IsDigit(int ch);
bool IsSpace(int ch);
bool IsAlpha(int ch);

void BinToHex(const byte *Bin,size_t BinSize,char *Hex,wchar *HexW,size_t HexSize);

#ifndef SFX_MODULE
uint GetDigits(uint Number);
#endif

bool LowAscii(const char *Str);
bool LowAscii(const wchar *Str);

int wcsicompc(const wchar *s1,const wchar *s2);
int wcsnicompc(const wchar *s1,const wchar *s2,size_t n);

void itoa(int64 n,char *Str,size_t MaxSize);
void itoa(int64 n,wchar *Str,size_t MaxSize);
const wchar* GetWide(const char *Src);
const wchar* GetCmdParam(const wchar *CmdLine,wchar *Param,size_t MaxSize);
#ifndef RARDLL
void PrintfPrepareFmt(const wchar *Org,wchar *Cvt,size_t MaxSize);
#endif

#endif

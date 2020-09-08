#ifndef _RAR_FILEFN_
#define _RAR_FILEFN_

enum MKDIR_CODE {MKDIR_SUCCESS,MKDIR_ERROR,MKDIR_BADPATH};

MKDIR_CODE MakeDir(const wchar *Name,bool SetAttr,uint Attr);
bool CreatePath(const wchar *Path,bool SkipLastName);
void SetDirTime(const wchar *Name,RarTime *ftm,RarTime *ftc,RarTime *fta);
bool IsRemovable(const wchar *Name);

#ifndef SFX_MODULE
int64 GetFreeDisk(const wchar *Name);
#endif

#if defined(_WIN_ALL) && !defined(SFX_MODULE) && !defined(SILENT)
bool IsFAT(const wchar *Root);
#endif

bool FileExist(const wchar *Name);
bool WildFileExist(const wchar *Name);
bool IsDir(uint Attr);
bool IsUnreadable(uint Attr);
bool IsLink(uint Attr);
void SetSFXMode(const wchar *FileName);
void EraseDiskContents(const wchar *FileName);
bool IsDeleteAllowed(uint FileAttr);
void PrepareToDelete(const wchar *Name);
uint GetFileAttr(const wchar *Name);
bool SetFileAttr(const wchar *Name,uint Attr);
#if 0
wchar* MkTemp(wchar *Name,size_t MaxSize);
#endif

enum CALCFSUM_FLAGS {CALCFSUM_SHOWTEXT=1,CALCFSUM_SHOWPERCENT=2,CALCFSUM_SHOWPROGRESS=4,CALCFSUM_CURPOS=8};

void CalcFileSum(File *SrcFile,uint *CRC32,byte *Blake2,uint Threads,int64 Size=INT64NDF,uint Flags=0);

bool RenameFile(const wchar *SrcName,const wchar *DestName);
bool DelFile(const wchar *Name);
bool DelDir(const wchar *Name);

#if defined(_WIN_ALL) && !defined(SFX_MODULE)
bool SetFileCompression(const wchar *Name,bool State);
#endif





#endif

#ifndef _RAR_FINDDATA_
#define _RAR_FINDDATA_

enum FINDDATA_FLAGS {
  FDDF_SECONDDIR=1  // Second encounter of same directory in SCAN_GETDIRSTWICE ScanTree mode.
};

struct FindData
{
  wchar Name[NM];
  uint64 Size;
  uint FileAttr;
  bool IsDir;
  bool IsLink;
  RarTime mtime;
  RarTime ctime;
  RarTime atime;
#ifdef _WIN_ALL
  FILETIME ftCreationTime; 
  FILETIME ftLastAccessTime; 
  FILETIME ftLastWriteTime; 
#endif
  uint Flags;
  bool Error;
};

class FindFile
{
  private:
#ifdef _WIN_ALL
    static HANDLE Win32Find(HANDLE hFind,const wchar *Mask,FindData *fd);
#endif

    wchar FindMask[NM];
    bool FirstCall;
#ifdef _WIN_ALL
    HANDLE hFind;
#else
    DIR *dirp;
#endif
  public:
    FindFile();
    ~FindFile();
    void SetMask(const wchar *Mask);
    bool Next(FindData *fd,bool GetSymLink=false);
    static bool FastFind(const wchar *FindMask,FindData *fd,bool GetSymLink=false);
};

#endif

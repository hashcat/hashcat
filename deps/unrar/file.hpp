#ifndef _RAR_FILE_
#define _RAR_FILE_

#define FILE_USE_OPEN

#ifdef _WIN_ALL
  typedef HANDLE FileHandle;
  #define FILE_BAD_HANDLE INVALID_HANDLE_VALUE
#elif defined(FILE_USE_OPEN)
  typedef off_t FileHandle;
  #define FILE_BAD_HANDLE -1
#else
  typedef FILE* FileHandle;
  #define FILE_BAD_HANDLE NULL
#endif

class RAROptions;

enum FILE_HANDLETYPE {FILE_HANDLENORMAL,FILE_HANDLESTD};

enum FILE_ERRORTYPE {FILE_SUCCESS,FILE_NOTFOUND,FILE_READERROR};

enum FILE_MODE_FLAGS {
  // Request read only access to file. Default for Open.
  FMF_READ=0,

  // Request both read and write access to file. Default for Create.
  FMF_UPDATE=1,

  // Request write only access to file.
  FMF_WRITE=2,

  // Open files which are already opened for write by other programs.
  FMF_OPENSHARED=4,

  // Open files only if no other program is opened it even in shared mode.
  FMF_OPENEXCLUSIVE=8,

  // Provide read access to created file for other programs.
  FMF_SHAREREAD=16,

  // Use standard NTFS names without trailing dots and spaces.
  FMF_STANDARDNAMES=32,

  // Mode flags are not defined yet.
  FMF_UNDEFINED=256
};


class File
{
  private:
    FileHandle hFile;
    bool LastWrite;
    FILE_HANDLETYPE HandleType;
    bool SkipClose;
    bool IgnoreReadErrors;
    bool NewFile;
    bool AllowDelete;
    bool AllowExceptions;
#ifdef _WIN_ALL
    bool NoSequentialRead;
    uint CreateMode;
#endif
    bool PreserveAtime;
  protected:
    bool OpenShared; // Set by 'Archive' class.
  public:
    wchar FileName[NM];

    FILE_ERRORTYPE ErrorType;
  public:
    File();
    virtual ~File();
    void operator = (File &SrcFile);

    // Several functions below are 'virtual', because they are redefined
    // by Archive for QOpen and by MultiFile for split files in WinRAR.
    virtual bool Open(const wchar *Name,uint Mode=FMF_READ);
    void TOpen(const wchar *Name);
    bool WOpen(const wchar *Name);
    bool Create(const wchar *Name,uint Mode=FMF_UPDATE|FMF_SHAREREAD);
    void TCreate(const wchar *Name,uint Mode=FMF_UPDATE|FMF_SHAREREAD);
    bool WCreate(const wchar *Name,uint Mode=FMF_UPDATE|FMF_SHAREREAD);
    virtual bool Close(); // 'virtual' for MultiFile class.
    bool Delete();
    bool Rename(const wchar *NewName);
    bool Write(const void *Data,size_t Size);
    virtual int Read(void *Data,size_t Size);
    int DirectRead(void *Data,size_t Size);
    virtual void Seek(int64 Offset,int Method);
    bool RawSeek(int64 Offset,int Method);
    virtual int64 Tell();
    void Prealloc(int64 Size);
    byte GetByte();
    void PutByte(byte Byte);
    bool Truncate();
    void Flush();
    void SetOpenFileTime(RarTime *ftm,RarTime *ftc=NULL,RarTime *fta=NULL);
    void SetCloseFileTime(RarTime *ftm,RarTime *fta=NULL);
    static void SetCloseFileTimeByName(const wchar *Name,RarTime *ftm,RarTime *fta);
    void GetOpenFileTime(RarTime *ft);
    virtual bool IsOpened() {return hFile!=FILE_BAD_HANDLE;} // 'virtual' for MultiFile class.
    int64 FileLength();
    void SetHandleType(FILE_HANDLETYPE Type) {HandleType=Type;}
    FILE_HANDLETYPE GetHandleType() {return HandleType;}
    bool IsDevice();
    static bool RemoveCreated();
    FileHandle GetHandle() {return hFile;}
    void SetHandle(FileHandle Handle) {Close();hFile=Handle;}
    void SetIgnoreReadErrors(bool Mode) {IgnoreReadErrors=Mode;}
    int64 Copy(File &Dest,int64 Length=INT64NDF);
    void SetAllowDelete(bool Allow) {AllowDelete=Allow;}
    void SetExceptions(bool Allow) {AllowExceptions=Allow;}
#ifdef _WIN_ALL
    void RemoveSequentialFlag() {NoSequentialRead=true;}
#endif
    void SetPreserveAtime(bool Preserve) {PreserveAtime=Preserve;}
#ifdef _UNIX
    int GetFD()
    {
#ifdef FILE_USE_OPEN
      return hFile;
#else
      return fileno(hFile);
#endif
    }
#endif
    static size_t CopyBufferSize()
    {
#ifdef _WIN_ALL
      // USB flash performance is poor with 64 KB buffer, 256+ KB resolved it.
      // For copying from HDD to same HDD the best performance was with 256 KB
      // buffer in XP and with 1 MB buffer in Win10.
      return WinNT()==WNT_WXP ? 0x40000:0x100000;
#else
      return 0x100000;
#endif
    }
};

#endif

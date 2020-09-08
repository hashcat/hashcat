#ifndef _RAR_RECVOL_
#define _RAR_RECVOL_

#define REV5_SIGN      "Rar!\x1aRev"
#define REV5_SIGN_SIZE             8

class RecVolumes3
{
  private:
    File *SrcFile[256];
    Array<byte> Buf;

#ifdef RAR_SMP
    ThreadPool *RSThreadPool;
#endif
  public:
    RecVolumes3(RAROptions *Cmd,bool TestOnly);
    ~RecVolumes3();
    void Make(RAROptions *Cmd,wchar *ArcName);
    bool Restore(RAROptions *Cmd,const wchar *Name,bool Silent);
    void Test(RAROptions *Cmd,const wchar *Name);
};


struct RecVolItem
{
  File *f;
  wchar Name[NM];
  uint CRC;
  uint64 FileSize;
  bool New;   // Newly created RAR volume.
  bool Valid; // If existing RAR volume is valid.
};


class RecVolumes5;
struct RecRSThreadData
{
  RecVolumes5 *RecRSPtr;
  RSCoder16 *RS;
  bool Encode;
  uint DataNum;
  const byte *Data;
  size_t StartPos;
  size_t Size;
};

class RecVolumes5
{
  private:
    void ProcessRS(RAROptions *Cmd,uint DataNum,const byte *Data,uint MaxRead,bool Encode);
    void ProcessRS(RAROptions *Cmd,uint MaxRead,bool Encode);
    uint ReadHeader(File *RecFile,bool FirstRev);

    Array<RecVolItem> RecItems;

    byte *RealReadBuffer; // Real pointer returned by 'new'.
    byte *ReadBuffer;     // Pointer aligned for SSE instructions.

    byte *RealBuf;        // Real pointer returned by 'new'.
    byte *Buf;            // Store ECC or recovered data here, aligned for SSE.
    size_t RecBufferSize; // Buffer area allocated for single volume.

    uint DataCount;   // Number of archives.
    uint RecCount;    // Number of recovery volumes.
    uint TotalCount;  // Total number of archives and recovery volumes.

    bool *ValidFlags; // Volume validity flags for recovering.
    uint MissingVolumes; // Number of missing or bad RAR volumes.

#ifdef RAR_SMP
    ThreadPool *RecThreadPool;
#endif
    uint MaxUserThreads; // Maximum number of threads defined by user.
    RecRSThreadData *ThreadData; // Array to store thread parameters.
  public: // 'public' only because called from thread functions.
    void ProcessAreaRS(RecRSThreadData *td);
  public:
    RecVolumes5(RAROptions *Cmd,bool TestOnly);
    ~RecVolumes5();
    bool Restore(RAROptions *Cmd,const wchar *Name,bool Silent);
    void Test(RAROptions *Cmd,const wchar *Name);
};

bool RecVolumesRestore(RAROptions *Cmd,const wchar *Name,bool Silent);
void RecVolumesTest(RAROptions *Cmd,Archive *Arc,const wchar *Name);

#endif

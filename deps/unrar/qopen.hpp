#ifndef _RAR_QOPEN_
#define _RAR_QOPEN_

struct QuickOpenItem
{
  byte *Header;
  size_t HeaderSize;
  uint64 ArcPos;
  QuickOpenItem *Next;
};


class Archive;
class RawRead;

class QuickOpen
{
  private:
    void Close();


    uint ReadBuffer();
    bool ReadRaw(RawRead &Raw);
    bool ReadNext();

    Archive *Arc;
    bool WriteMode;

    QuickOpenItem *ListStart;
    QuickOpenItem *ListEnd;
    
    byte *Buf; // Read quick open data here.
    static const size_t MaxBufSize=0x10000; // Buf size, must be multiple of CRYPT_BLOCK_SIZE.
    size_t CurBufSize; // Current size of buffered data in write mode.
#ifndef RAR_NOCRYPT // For shell extension.
    CryptData Crypt;
#endif

    bool Loaded;
    uint64 QOHeaderPos;  // Main QO header position.
    uint64 RawDataStart; // Start of QO data, just after the main header.
    uint64 RawDataSize;  // Size of entire QO data.
    uint64 RawDataPos;   // Current read position in QO data.
    size_t ReadBufSize;  // Size of Buf data currently read from QO.
    size_t ReadBufPos;   // Current read position in Buf data.
    Array<byte> LastReadHeader;
    uint64 LastReadHeaderPos;
    uint64 SeekPos;
    bool UnsyncSeekPos;  // QOpen SeekPos does not match an actual file pointer.
  public:
    QuickOpen();
    ~QuickOpen();
    void Init(Archive *Arc,bool WriteMode);
    void Load(uint64 BlockPos);
    void Unload() { Loaded=false; }
    bool Read(void *Data,size_t Size,size_t &Result);
    bool Seek(int64 Offset,int Method);
    bool Tell(int64 *Pos);
};

#endif

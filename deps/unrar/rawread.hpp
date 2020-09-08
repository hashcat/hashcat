#ifndef _RAR_RAWREAD_
#define _RAR_RAWREAD_

class RawRead
{
  private:
    Array<byte> Data;
    File *SrcFile;
    size_t DataSize;
    size_t ReadPos;
    CryptData *Crypt;
  public:
    RawRead();
    RawRead(File *SrcFile);
    void Reset();
    size_t Read(size_t Size);
    void Read(byte *SrcData,size_t Size);
    byte   Get1();
    ushort Get2();
    uint   Get4();
    uint64 Get8();
    uint64 GetV();
    uint   GetVSize(size_t Pos);
    size_t GetB(void *Field,size_t Size);
    void GetW(wchar *Field,size_t Size);
    uint GetCRC15(bool ProcessedOnly);
    uint GetCRC50();
    byte* GetDataPtr() {return &Data[0];}
    size_t Size() {return DataSize;}
    size_t PaddedSize() {return Data.Size()-DataSize;}
    size_t DataLeft() {return DataSize-ReadPos;}
    size_t GetPos() {return ReadPos;}
    void SetPos(size_t Pos) {ReadPos=Pos;}
    void Skip(size_t Size) {ReadPos+=Size;}
    void Rewind() {SetPos(0);}
    void SetCrypt(CryptData *Crypt) {RawRead::Crypt=Crypt;}
};

uint64 RawGetV(const byte *Data,uint &ReadPos,uint DataSize,bool &Overflow);

#endif

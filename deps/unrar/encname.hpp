#ifndef _RAR_ENCNAME_
#define _RAR_ENCNAME_

class EncodeFileName
{
  private:
    void AddFlags(int Value);

    byte *EncName;
    byte Flags;
    uint FlagBits;
    size_t FlagsPos;
    size_t DestSize;
  public:
    EncodeFileName();
    size_t Encode(char *Name,wchar *NameW,byte *EncName);
    void Decode(char *Name,size_t NameSize,byte *EncName,size_t EncSize,wchar *NameW,size_t MaxDecSize);
};

#endif

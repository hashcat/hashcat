#ifndef _RAR_DATAHASH_
#define _RAR_DATAHASH_

enum HASH_TYPE {HASH_NONE,HASH_RAR14,HASH_CRC32,HASH_BLAKE2};

struct HashValue
{
  void Init(HASH_TYPE Type);
  bool operator == (const HashValue &cmp);
  bool operator != (const HashValue &cmp) {return !(*this==cmp);}

  HASH_TYPE Type;
  union
  {
    uint CRC32;
    byte Digest[SHA256_DIGEST_SIZE];
  };
};


#ifdef RAR_SMP
class ThreadPool;
class DataHash;
#endif


class DataHash
{
  private:
    HASH_TYPE HashType;
    uint CurCRC32;
    blake2sp_state *blake2ctx;

#ifdef RAR_SMP
    ThreadPool *ThPool;

    uint MaxThreads;
    // Upper limit for maximum threads to prevent wasting threads in pool.
    static const uint MaxHashThreads=8;
#endif
  public:
    DataHash();
    ~DataHash();
    void Init(HASH_TYPE Type,uint MaxThreads);
    void Update(const void *Data,size_t DataSize);
    void Result(HashValue *Result);
    uint GetCRC32();
    bool Cmp(HashValue *CmpValue,byte *Key);
    HASH_TYPE Type() {return HashType;}
};

#endif

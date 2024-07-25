#ifndef _RAR_DATAHASH_
#define _RAR_DATAHASH_

enum HASH_TYPE {HASH_NONE,HASH_RAR14,HASH_CRC32,HASH_BLAKE2};

struct HashValue
{
  void Init(HASH_TYPE Type);

  // Use the const member, so types on both sides of "==" match.
  // Otherwise clang -std=c++20 issues "ambiguity is between a regular call
  // to this operator and a call with the argument order reversed" warning.
  bool operator == (const HashValue &cmp) const;

  // Not actually used now. Const member for same reason as operator == above.
  bool operator != (const HashValue &cmp) const {return !(*this==cmp);}

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

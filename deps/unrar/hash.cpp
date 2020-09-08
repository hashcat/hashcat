#include "rar.hpp"

void HashValue::Init(HASH_TYPE Type)
{
  HashValue::Type=Type;

  // Zero length data CRC32 is 0. It is important to set it when creating
  // headers with no following data like directories or symlinks.
  if (Type==HASH_RAR14 || Type==HASH_CRC32)
    CRC32=0;
  if (Type==HASH_BLAKE2)
  {
    // dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f
    // is BLAKE2sp hash of empty data. We init the structure to this value,
    // so if we create a file or service header with no following data like
    // "file copy" or "symlink", we set the checksum to proper value avoiding
    // additional header type or size checks when extracting.
    static byte EmptyHash[32]={
      0xdd, 0x0e, 0x89, 0x17, 0x76, 0x93, 0x3f, 0x43,
      0xc7, 0xd0, 0x32, 0xb0, 0x8a, 0x91, 0x7e, 0x25,
      0x74, 0x1f, 0x8a, 0xa9, 0xa1, 0x2c, 0x12, 0xe1,
      0xca, 0xc8, 0x80, 0x15, 0x00, 0xf2, 0xca, 0x4f
    };
    memcpy(Digest,EmptyHash,sizeof(Digest));
  }
}


bool HashValue::operator == (const HashValue &cmp)
{
  if (Type==HASH_NONE || cmp.Type==HASH_NONE)
    return true;
  if (Type==HASH_RAR14 && cmp.Type==HASH_RAR14 || 
      Type==HASH_CRC32 && cmp.Type==HASH_CRC32)
    return CRC32==cmp.CRC32;
  if (Type==HASH_BLAKE2 && cmp.Type==HASH_BLAKE2)
    return memcmp(Digest,cmp.Digest,sizeof(Digest))==0;
  return false;
}


DataHash::DataHash()
{
  blake2ctx=NULL;
  HashType=HASH_NONE;
#ifdef RAR_SMP
  ThPool=NULL;
  MaxThreads=0;
#endif
}


DataHash::~DataHash()
{
#ifdef RAR_SMP
  delete ThPool;
#endif
  cleandata(&CurCRC32, sizeof(CurCRC32));
  if (blake2ctx!=NULL)
  {
    cleandata(blake2ctx, sizeof(blake2sp_state));
    delete blake2ctx;
  }
}


void DataHash::Init(HASH_TYPE Type,uint MaxThreads)
{
  if (blake2ctx==NULL)
    blake2ctx=new blake2sp_state;
  HashType=Type;
  if (Type==HASH_RAR14)
    CurCRC32=0;
  if (Type==HASH_CRC32)
    CurCRC32=0xffffffff; // Initial CRC32 value.
  if (Type==HASH_BLAKE2)
    blake2sp_init(blake2ctx);
#ifdef RAR_SMP
  DataHash::MaxThreads=Min(MaxThreads,MaxHashThreads);
#endif
}


void DataHash::Update(const void *Data,size_t DataSize)
{
#ifndef SFX_MODULE
  if (HashType==HASH_RAR14)
    CurCRC32=Checksum14((ushort)CurCRC32,Data,DataSize);
#endif
  if (HashType==HASH_CRC32)
    CurCRC32=CRC32(CurCRC32,Data,DataSize);

  if (HashType==HASH_BLAKE2)
  {
#ifdef RAR_SMP
    if (MaxThreads>1 && ThPool==NULL)
      ThPool=new ThreadPool(BLAKE2_THREADS_NUMBER);
    blake2ctx->ThPool=ThPool;
    blake2ctx->MaxThreads=MaxThreads;
#endif
    blake2sp_update( blake2ctx, (byte *)Data, DataSize);
  }
}


void DataHash::Result(HashValue *Result)
{
  Result->Type=HashType;
  if (HashType==HASH_RAR14)
    Result->CRC32=CurCRC32;
  if (HashType==HASH_CRC32)
    Result->CRC32=CurCRC32^0xffffffff;
  if (HashType==HASH_BLAKE2)
  {
    // Preserve the original context, so we can continue hashing if necessary.
    blake2sp_state res=*blake2ctx;
    blake2sp_final(&res,Result->Digest);
  }
}


uint DataHash::GetCRC32()
{
  return HashType==HASH_CRC32 ? CurCRC32^0xffffffff : 0;
}


bool DataHash::Cmp(HashValue *CmpValue,byte *Key)
{
  HashValue Final;
  Result(&Final);
  if (Key!=NULL)
    ConvertHashToMAC(&Final,Key);
  return Final==*CmpValue;
}

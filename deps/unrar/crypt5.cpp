static void hmac_sha256(const byte *Key,size_t KeyLength,const byte *Data,
                        size_t DataLength,byte *ResDigest,
                        sha256_context *ICtxOpt,bool *SetIOpt,
                        sha256_context *RCtxOpt,bool *SetROpt)
{
  const size_t Sha256BlockSize=64; // As defined in RFC 4868.

  byte KeyHash[SHA256_DIGEST_SIZE];
  if (KeyLength > Sha256BlockSize) // Convert longer keys to key hash.
  {
    sha256_context KCtx;
    sha256_init(&KCtx);
    sha256_process(&KCtx, Key, KeyLength);
    sha256_done(&KCtx, KeyHash);

    Key = KeyHash;
    KeyLength = SHA256_DIGEST_SIZE;
  }

  byte KeyBuf[Sha256BlockSize]; // Store the padded key here.
  sha256_context ICtx;

  if (ICtxOpt!=NULL && *SetIOpt)
    ICtx=*ICtxOpt; // Use already calculated first block context.
  else
  {
    // This calculation is the same for all iterations with same password.
    // So for PBKDF2 we can calculate it only for first block and then reuse
    // to improve performance. 

    for (size_t I = 0; I < KeyLength; I++) // Use 0x36 padding for inner digest.
      KeyBuf[I] = Key[I] ^ 0x36;
    for (size_t I = KeyLength; I < Sha256BlockSize; I++)
      KeyBuf[I] = 0x36;

    sha256_init(&ICtx);
    sha256_process(&ICtx, KeyBuf, Sha256BlockSize); // Hash padded key.
  }

  if (ICtxOpt!=NULL && !*SetIOpt) // Store constant context for further reuse.
  {
    *ICtxOpt=ICtx;
    *SetIOpt=true;
  }

  sha256_process(&ICtx, Data, DataLength); // Hash data.

  byte IDig[SHA256_DIGEST_SIZE]; // Internal digest for padded key and data.
  sha256_done(&ICtx, IDig);

  sha256_context RCtx;

  if (RCtxOpt!=NULL && *SetROpt)
    RCtx=*RCtxOpt; // Use already calculated first block context.
  else
  {
    // This calculation is the same for all iterations with same password.
    // So for PBKDF2 we can calculate it only for first block and then reuse
    // to improve performance. 

    for (size_t I = 0; I < KeyLength; I++) // Use 0x5c for outer key padding.
      KeyBuf[I] = Key[I] ^ 0x5c;
    for (size_t I = KeyLength; I < Sha256BlockSize; I++)
      KeyBuf[I] = 0x5c;

    sha256_init(&RCtx);
    sha256_process(&RCtx, KeyBuf, Sha256BlockSize); // Hash padded key.
  }

  if (RCtxOpt!=NULL && !*SetROpt) // Store constant context for further reuse.
  {
    *RCtxOpt=RCtx;
    *SetROpt=true;
  }

  sha256_process(&RCtx, IDig, SHA256_DIGEST_SIZE); // Hash internal digest.

  sha256_done(&RCtx, ResDigest);
}


// PBKDF2 for 32 byte key length. We generate the key for specified number
// of iteration count also as two supplementary values (key for checksums
// and password verification) for iterations+16 and iterations+32.
void pbkdf2(const byte *Pwd, size_t PwdLength, 
            const byte *Salt, size_t SaltLength,
            byte *Key, byte *V1, byte *V2, uint Count)
{
  const size_t MaxSalt=64;
  byte SaltData[MaxSalt+4];
  memcpy(SaltData, Salt, Min(SaltLength,MaxSalt));

  SaltData[SaltLength + 0] = 0; // Salt concatenated to 1.
  SaltData[SaltLength + 1] = 0;
  SaltData[SaltLength + 2] = 0;
  SaltData[SaltLength + 3] = 1;

  // First iteration: HMAC of password, salt and block index (1).
  byte U1[SHA256_DIGEST_SIZE];
  hmac_sha256(Pwd, PwdLength, SaltData, SaltLength + 4, U1, NULL, NULL, NULL, NULL);
  byte Fn[SHA256_DIGEST_SIZE]; // Current function value.
  memcpy(Fn, U1, sizeof(Fn)); // Function at first iteration.

  uint  CurCount[] = { Count-1, 16, 16 };
  byte *CurValue[] = { Key    , V1, V2 };
  
  sha256_context ICtxOpt,RCtxOpt;
  bool SetIOpt=false,SetROpt=false;
  
  byte U2[SHA256_DIGEST_SIZE];
  for (uint I = 0; I < 3; I++) // For output key and 2 supplementary values.
  {
    for (uint J = 0; J < CurCount[I]; J++) 
    {
      // U2 = PRF (P, U1).
      hmac_sha256(Pwd, PwdLength, U1, sizeof(U1), U2, &ICtxOpt, &SetIOpt, &RCtxOpt, &SetROpt);
      memcpy(U1, U2, sizeof(U1));
      for (uint K = 0; K < sizeof(Fn); K++) // Function ^= U.
        Fn[K] ^= U1[K];
    }
    memcpy(CurValue[I], Fn, SHA256_DIGEST_SIZE);
  }

  cleandata(SaltData, sizeof(SaltData));
  cleandata(Fn, sizeof(Fn));
  cleandata(U1, sizeof(U1));
  cleandata(U2, sizeof(U2));
}


void CryptData::SetKey50(bool Encrypt,SecPassword *Password,const wchar *PwdW,
     const byte *Salt,const byte *InitV,uint Lg2Cnt,byte *HashKey,
     byte *PswCheck)
{
  if (Lg2Cnt>CRYPT5_KDF_LG2_COUNT_MAX)
    return;

  byte Key[32],PswCheckValue[SHA256_DIGEST_SIZE],HashKeyValue[SHA256_DIGEST_SIZE];
  bool Found=false;
  for (uint I=0;I<ASIZE(KDF5Cache);I++)
  {
    KDF5CacheItem *Item=KDF5Cache+I;
    if (Item->Lg2Count==Lg2Cnt && Item->Pwd==*Password &&
        memcmp(Item->Salt,Salt,SIZE_SALT50)==0)
    {
      memcpy(Key,Item->Key,sizeof(Key));
      SecHideData(Key,sizeof(Key),false,false);

      memcpy(PswCheckValue,Item->PswCheckValue,sizeof(PswCheckValue));
      memcpy(HashKeyValue,Item->HashKeyValue,sizeof(HashKeyValue));
      Found=true;
      break;
    }
  }

  if (!Found)
  {
    char PwdUtf[MAXPASSWORD*4];
    WideToUtf(PwdW,PwdUtf,ASIZE(PwdUtf));
    
    pbkdf2((byte *)PwdUtf,strlen(PwdUtf),Salt,SIZE_SALT50,Key,HashKeyValue,PswCheckValue,(1<<Lg2Cnt));
    cleandata(PwdUtf,sizeof(PwdUtf));

    KDF5CacheItem *Item=KDF5Cache+(KDF5CachePos++ % ASIZE(KDF5Cache));
    Item->Lg2Count=Lg2Cnt;
    Item->Pwd=*Password;
    memcpy(Item->Salt,Salt,SIZE_SALT50);
    memcpy(Item->Key,Key,sizeof(Item->Key));
    memcpy(Item->PswCheckValue,PswCheckValue,sizeof(PswCheckValue));
    memcpy(Item->HashKeyValue,HashKeyValue,sizeof(HashKeyValue));
    SecHideData(Item->Key,sizeof(Item->Key),true,false);
  }
  if (HashKey!=NULL)
    memcpy(HashKey,HashKeyValue,SHA256_DIGEST_SIZE);
  if (PswCheck!=NULL)
  {
    memset(PswCheck,0,SIZE_PSWCHECK);
    for (uint I=0;I<SHA256_DIGEST_SIZE;I++)
      PswCheck[I%SIZE_PSWCHECK]^=PswCheckValue[I];
    cleandata(PswCheckValue,sizeof(PswCheckValue));
  }

  // NULL initialization vector is possible if we only need the password
  // check value for archive encryption header.
  if (InitV!=NULL)
    rin.Init(Encrypt, Key, 256, InitV);

  cleandata(Key,sizeof(Key));
}


void ConvertHashToMAC(HashValue *Value,byte *Key)
{
  if (Value->Type==HASH_CRC32)
  {
    byte RawCRC[4];
    RawPut4(Value->CRC32,RawCRC);
    byte Digest[SHA256_DIGEST_SIZE];
    hmac_sha256(Key,SHA256_DIGEST_SIZE,RawCRC,sizeof(RawCRC),Digest,NULL,NULL,NULL,NULL);
    Value->CRC32=0;
    for (uint I=0;I<ASIZE(Digest);I++)
      Value->CRC32^=Digest[I] << ((I & 3) * 8);
  }
  if (Value->Type==HASH_BLAKE2)
  {
    byte Digest[BLAKE2_DIGEST_SIZE];
    hmac_sha256(Key,BLAKE2_DIGEST_SIZE,Value->Digest,sizeof(Value->Digest),Digest,NULL,NULL,NULL,NULL);
    memcpy(Value->Digest,Digest,sizeof(Value->Digest));
  }
}


#if 0
static void TestPBKDF2();
struct TestKDF {TestKDF() {TestPBKDF2();exit(0);}} GlobalTestKDF;

void TestPBKDF2() // Test PBKDF2 HMAC-SHA256
{
  byte Key[32],V1[32],V2[32];

  pbkdf2((byte *)"password", 8, (byte *)"salt", 4, Key, V1, V2, 1);
  byte Res1[32]={0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b };
  mprintf(L"\nPBKDF2 test1: %s", memcmp(Key,Res1,32)==0 ? L"OK":L"Failed");

  pbkdf2((byte *)"password", 8, (byte *)"salt", 4, Key, V1, V2, 4096);
  byte Res2[32]={0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a };
  mprintf(L"\nPBKDF2 test2: %s", memcmp(Key,Res2,32)==0 ? L"OK":L"Failed");

  pbkdf2((byte *)"just some long string pretending to be a password", 49, (byte *)"salt, salt, salt, a lot of salt", 31, Key, V1, V2, 65536);
  byte Res3[32]={0x08, 0x0f, 0xa3, 0x1d, 0x42, 0x2d, 0xb0, 0x47, 0x83, 0x9b, 0xce, 0x3a, 0x3b, 0xce, 0x49, 0x51, 0xe2, 0x62, 0xb9, 0xff, 0x76, 0x2f, 0x57, 0xe9, 0xc4, 0x71, 0x96, 0xce, 0x4b, 0x6b, 0x6e, 0xbf};
  mprintf(L"\nPBKDF2 test3: %s", memcmp(Key,Res3,32)==0 ? L"OK":L"Failed");
}
#endif

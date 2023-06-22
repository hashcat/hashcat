#ifndef _RAR_CRYPT_
#define _RAR_CRYPT_


enum CRYPT_METHOD {
  CRYPT_NONE,CRYPT_RAR13,CRYPT_RAR15,CRYPT_RAR20,CRYPT_RAR30,CRYPT_RAR50
};

#define SIZE_SALT50              16
#define SIZE_SALT30               8
#define SIZE_INITV               16
#define SIZE_PSWCHECK             8
#define SIZE_PSWCHECK_CSUM        4

#define CRYPT_BLOCK_SIZE         16
#define CRYPT_BLOCK_MASK         (CRYPT_BLOCK_SIZE-1) // 0xf

#define CRYPT5_KDF_LG2_COUNT     15 // LOG2 of PDKDF2 iteration count.
#define CRYPT5_KDF_LG2_COUNT_MAX 24 // LOG2 of maximum accepted iteration count.
#define CRYPT_VERSION             0 // Supported encryption version.


class CryptData
{
  struct KDF5CacheItem
  {
    SecPassword Pwd;
    byte Salt[SIZE_SALT50];
    byte Key[32];
    uint Lg2Count; // Log2 of PBKDF2 repetition count.
    byte PswCheckValue[SHA256_DIGEST_SIZE];
    byte HashKeyValue[SHA256_DIGEST_SIZE];

    KDF5CacheItem() {Clean();}
    ~KDF5CacheItem() {Clean();}

    void Clean()
    {
      cleandata(Salt,sizeof(Salt));
      cleandata(Key,sizeof(Key));
      cleandata(&Lg2Count,sizeof(Lg2Count));
      cleandata(PswCheckValue,sizeof(PswCheckValue));
      cleandata(HashKeyValue,sizeof(HashKeyValue));
    }
  };

  struct KDF3CacheItem
  {
    SecPassword Pwd;
    byte Salt[SIZE_SALT30];
    byte Key[16];
    byte Init[16];
    bool SaltPresent;

    KDF3CacheItem() {Clean();}
    ~KDF3CacheItem() {Clean();}

    void Clean()
    {
      cleandata(Salt,sizeof(Salt));
      cleandata(Key,sizeof(Key));
      cleandata(Init,sizeof(Init));
      cleandata(&SaltPresent,sizeof(SaltPresent));
    }
  };


  private:
    void SetKey13(const char *Password);
    void Decrypt13(byte *Data,size_t Count);

    void SetKey15(const char *Password);
    void Crypt15(byte *Data,size_t Count);

    void SetKey20(const char *Password);
    void Swap20(byte *Ch1,byte *Ch2);
    void UpdKeys20(byte *Buf);
    void EncryptBlock20(byte *Buf);
    void DecryptBlock20(byte *Buf);

    void SetKey30(bool Encrypt,SecPassword *Password,const wchar *PwdW,const byte *Salt);
    void SetKey50(bool Encrypt,SecPassword *Password,const wchar *PwdW,const byte *Salt,const byte *InitV,uint Lg2Cnt,byte *HashKey,byte *PswCheck);

    KDF3CacheItem KDF3Cache[4];
    uint KDF3CachePos;
    
    KDF5CacheItem KDF5Cache[4];
    uint KDF5CachePos;

    CRYPT_METHOD Method;

    Rijndael rin;

    uint CRCTab[256]; // For RAR 1.5 and RAR 2.0 encryption.
    
    byte SubstTable20[256];
    uint Key20[4];

    byte Key13[3];
    ushort Key15[4];
  public:
    CryptData();
    bool SetCryptKeys(bool Encrypt,CRYPT_METHOD Method,SecPassword *Password,
         const byte *Salt,const byte *InitV,uint Lg2Cnt,
         byte *HashKey,byte *PswCheck);
    void SetRijndalDecryptKey(byte *Key,byte *InitV);
    void SetAV15Encryption();
    void SetCmt13Encryption();
    void EncryptBlock(byte *Buf,size_t Size);
    void DecryptBlock(byte *Buf,size_t Size);
    static void SetSalt(byte *Salt,size_t SaltSize);
};


class CheckPassword
{
  public:
    enum CONFIDENCE {CONFIDENCE_HIGH,CONFIDENCE_MEDIUM,CONFIDENCE_LOW};
    virtual CONFIDENCE GetConfidence()=0;
    virtual bool Check(SecPassword *Password)=0;
};

class RarCheckPassword:public CheckPassword
{
  private:
    CryptData *Crypt;
    uint Lg2Count;
    byte Salt[SIZE_SALT50];
    byte InitV[SIZE_INITV];
    byte PswCheck[SIZE_PSWCHECK];
  public:
    RarCheckPassword()
    {
      Crypt=NULL;
    }
    ~RarCheckPassword()
    {
      delete Crypt;
    }
    void Set(byte *Salt,byte *InitV,uint Lg2Count,byte *PswCheck)
    {
      if (Crypt==NULL)
        Crypt=new CryptData;
      memcpy(this->Salt,Salt,sizeof(this->Salt));
      memcpy(this->InitV,InitV,sizeof(this->InitV));
      this->Lg2Count=Lg2Count;
      memcpy(this->PswCheck,PswCheck,sizeof(this->PswCheck));
    }
    bool IsSet() {return Crypt!=NULL;}

    // RAR5 provides the higly reliable 64 bit password verification value.
    CONFIDENCE GetConfidence() {return CONFIDENCE_HIGH;}

    bool Check(SecPassword *Password)
    {
      byte PswCheck[SIZE_PSWCHECK];
      Crypt->SetCryptKeys(false,CRYPT_RAR50,Password,Salt,InitV,Lg2Count,NULL,PswCheck);
      return memcmp(PswCheck,this->PswCheck,sizeof(this->PswCheck))==0;
    }
};

void GetRnd(byte *RndBuf,size_t BufSize);

void hmac_sha256(const byte *Key,size_t KeyLength,const byte *Data,
                 size_t DataLength,byte *ResDigest);
void pbkdf2(const byte *pass, size_t pass_len, const byte *salt,
            size_t salt_len,byte *key, byte *Value1, byte *Value2,
            uint rounds);

void ConvertHashToMAC(HashValue *Value,byte *Key);

#endif

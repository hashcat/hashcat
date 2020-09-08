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
  };

  struct KDF3CacheItem
  {
    SecPassword Pwd;
    byte Salt[SIZE_SALT30];
    byte Key[16];
    byte Init[16];
    bool SaltPresent;
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
    ~CryptData();
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

void GetRnd(byte *RndBuf,size_t BufSize);

void hmac_sha256(const byte *Key,size_t KeyLength,const byte *Data,
                 size_t DataLength,byte *ResDigest);
void pbkdf2(const byte *pass, size_t pass_len, const byte *salt,
            size_t salt_len,byte *key, byte *Value1, byte *Value2,
            uint rounds);

void ConvertHashToMAC(HashValue *Value,byte *Key);

#endif

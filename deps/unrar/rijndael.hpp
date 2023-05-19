#ifndef _RIJNDAEL_H_
#define _RIJNDAEL_H_

/**************************************************************************
 * This code is based on Szymon Stefanek public domain AES implementation *
 **************************************************************************/

#define _MAX_KEY_COLUMNS (256/32)
#define _MAX_ROUNDS      14
#define MAX_IV_SIZE      16

class Rijndael
{ 
  private:
#ifdef USE_SSE
    void blockEncryptSSE(const byte *input,size_t numBlocks,byte *outBuffer);
    void blockDecryptSSE(const byte *input, size_t numBlocks, byte *outBuffer);

    bool AES_NI;
#endif
#ifdef USE_NEON
    // Set "crypto" attribute as replacement of -march=armv8-a+crypto switch.
    __attribute__((target("crypto")))
    void blockEncryptNeon(const byte *input,size_t numBlocks,byte *outBuffer);
    __attribute__((target("crypto")))
    void blockDecryptNeon(const byte *input, size_t numBlocks, byte *outBuffer);

    bool AES_Neon;
#endif

    void keySched(byte key[_MAX_KEY_COLUMNS][4]);
    void keyEncToDec();
    void GenerateTables();

    // RAR always uses CBC, but we may need to turn it off when calling
    // this code from other archive formats with CTR and other modes.
    bool     CBCMode;
    
    int      m_uRounds;
    byte     m_initVector[MAX_IV_SIZE];
    byte     m_expandedKey[_MAX_ROUNDS+1][4][4];
  public:
    Rijndael();
    void Init(bool Encrypt,const byte *key,uint keyLen,const byte *initVector);
    void blockEncrypt(const byte *input, size_t inputLen, byte *outBuffer);
    void blockDecrypt(const byte *input, size_t inputLen, byte *outBuffer);
    void SetCBCMode(bool Mode) {CBCMode=Mode;}
};
  
#endif // _RIJNDAEL_H_

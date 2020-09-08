#include "rar.hpp"

#ifndef SFX_MODULE
#include "crypt1.cpp"
#include "crypt2.cpp"
#endif
#include "crypt3.cpp"
#include "crypt5.cpp"


CryptData::CryptData()
{
  Method=CRYPT_NONE;
  memset(KDF3Cache,0,sizeof(KDF3Cache));
  memset(KDF5Cache,0,sizeof(KDF5Cache));
  KDF3CachePos=0;
  KDF5CachePos=0;
  memset(CRCTab,0,sizeof(CRCTab));
}


CryptData::~CryptData()
{
  cleandata(KDF3Cache,sizeof(KDF3Cache));
  cleandata(KDF5Cache,sizeof(KDF5Cache));
}




void CryptData::DecryptBlock(byte *Buf,size_t Size)
{
  switch(Method)
  {
#ifndef SFX_MODULE
    case CRYPT_RAR13:
      Decrypt13(Buf,Size);
      break;
    case CRYPT_RAR15:
      Crypt15(Buf,Size);
      break;
    case CRYPT_RAR20:
      for (size_t I=0;I<Size;I+=CRYPT_BLOCK_SIZE)
        DecryptBlock20(Buf+I);
      break;
#endif
    case CRYPT_RAR30:
    case CRYPT_RAR50:
      rin.blockDecrypt(Buf,Size,Buf);
      break;
  }
}


bool CryptData::SetCryptKeys(bool Encrypt,CRYPT_METHOD Method,
     SecPassword *Password,const byte *Salt,
     const byte *InitV,uint Lg2Cnt,byte *HashKey,byte *PswCheck)
{
  if (!Password->IsSet() || Method==CRYPT_NONE)
    return false;

  CryptData::Method=Method;

  wchar PwdW[MAXPASSWORD];
  Password->Get(PwdW,ASIZE(PwdW));
  char PwdA[MAXPASSWORD];
  WideToChar(PwdW,PwdA,ASIZE(PwdA));

  switch(Method)
  {
#ifndef SFX_MODULE
    case CRYPT_RAR13:
      SetKey13(PwdA);
      break;
    case CRYPT_RAR15:
      SetKey15(PwdA);
      break;
    case CRYPT_RAR20:
      SetKey20(PwdA);
      break;
#endif
    case CRYPT_RAR30:
      SetKey30(Encrypt,Password,PwdW,Salt);
      break;
    case CRYPT_RAR50:
      SetKey50(Encrypt,Password,PwdW,Salt,InitV,Lg2Cnt,HashKey,PswCheck);
      break;
  }
  cleandata(PwdA,sizeof(PwdA));
  cleandata(PwdW,sizeof(PwdW));
  return true;
}

void CryptData::SetRijndalDecryptKey(byte *Key,byte *InitV)
{
  CryptData::Method=CRYPT_RAR30;
  rin.Init(false,Key,128,InitV);
}

// Use the current system time to additionally randomize data.
static void TimeRandomize(byte *RndBuf,size_t BufSize)
{
  static uint Count=0;
  RarTime CurTime;
  CurTime.SetCurrentTime();
  uint64 Random=CurTime.GetWin()+clock();
  for (size_t I=0;I<BufSize;I++)
  {
    byte RndByte = byte (Random >> ( (I & 7) * 8 ));
    RndBuf[I]=byte( (RndByte ^ I) + Count++);
  }
}




// Fill buffer with random data.
void GetRnd(byte *RndBuf,size_t BufSize)
{
  bool Success=false;
#if defined(_WIN_ALL)
  HCRYPTPROV hProvider = 0;
  if (CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
  {
    Success=CryptGenRandom(hProvider, (DWORD)BufSize, RndBuf) == TRUE;
    CryptReleaseContext(hProvider, 0);
  }
#elif defined(_UNIX)
  FILE *rndf = fopen("/dev/urandom", "r");
  if (rndf!=NULL)
  {
    Success=fread(RndBuf, BufSize, 1, rndf) == BufSize;
    fclose(rndf);
  }
#endif
  // We use this code only as the last resort if code above failed.
  if (!Success)
    TimeRandomize(RndBuf,BufSize);
}

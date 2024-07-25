void CryptData::SetKey30(bool Encrypt,SecPassword *Password,const wchar *PwdW,const byte *Salt)
{
  byte AESKey[16],AESInit[16];

  bool Cached=false;
  for (uint I=0;I<ASIZE(KDF3Cache);I++)
    if (KDF3Cache[I].Pwd==*Password &&
        (Salt==NULL && !KDF3Cache[I].SaltPresent || Salt!=NULL &&
        KDF3Cache[I].SaltPresent && memcmp(KDF3Cache[I].Salt,Salt,SIZE_SALT30)==0))
    {
      memcpy(AESKey,KDF3Cache[I].Key,sizeof(AESKey));
      SecHideData(AESKey,sizeof(AESKey),false,false);
      memcpy(AESInit,KDF3Cache[I].Init,sizeof(AESInit));
      Cached=true;
      break;
    }

  if (!Cached)
  {
    byte RawPsw[2*MAXPASSWORD+SIZE_SALT30];
    size_t PswLength=wcslen(PwdW);
    size_t RawLength=2*PswLength;
    WideToRaw(PwdW,PswLength,RawPsw,RawLength);
    if (Salt!=NULL)
    {
      memcpy(RawPsw+RawLength,Salt,SIZE_SALT30);
      RawLength+=SIZE_SALT30;
    }
    sha1_context c;
    sha1_init(&c);

    const uint HashRounds=0x40000;
    for (uint I=0;I<HashRounds;I++)
    {
      sha1_process_rar29( &c, RawPsw, RawLength );
      byte PswNum[3];
      PswNum[0]=(byte)I;
      PswNum[1]=(byte)(I>>8);
      PswNum[2]=(byte)(I>>16);
      sha1_process(&c, PswNum, 3);
      if (I%(HashRounds/16)==0)
      {
        sha1_context tempc=c;
        uint32 digest[5];
        sha1_done( &tempc, digest );
        AESInit[I/(HashRounds/16)]=(byte)digest[4];
      }
    }
    uint32 digest[5];
    sha1_done( &c, digest );
    for (uint I=0;I<4;I++)
      for (uint J=0;J<4;J++)
        AESKey[I*4+J]=(byte)(digest[I]>>(J*8));

    KDF3Cache[KDF3CachePos].Pwd=*Password;
    if ((KDF3Cache[KDF3CachePos].SaltPresent=(Salt!=NULL))==true)
      memcpy(KDF3Cache[KDF3CachePos].Salt,Salt,SIZE_SALT30);
    memcpy(KDF3Cache[KDF3CachePos].Key,AESKey,sizeof(AESKey));
    SecHideData(KDF3Cache[KDF3CachePos].Key,sizeof(KDF3Cache[KDF3CachePos].Key),true,false);
    memcpy(KDF3Cache[KDF3CachePos].Init,AESInit,sizeof(AESInit));
    KDF3CachePos=(KDF3CachePos+1)%ASIZE(KDF3Cache);

    cleandata(RawPsw,sizeof(RawPsw));
  }
  rin.Init(Encrypt, AESKey, 128, AESInit);
  cleandata(AESKey,sizeof(AESKey));
  cleandata(AESInit,sizeof(AESInit));
}


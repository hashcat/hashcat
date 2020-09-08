extern uint CRCTab[256];

void CryptData::SetKey13(const char *Password)
{
  Key13[0]=Key13[1]=Key13[2]=0;
  for (size_t I=0;Password[I]!=0;I++)
  {
    byte P=Password[I];
    Key13[0]+=P;
    Key13[1]^=P;
    Key13[2]+=P;
    Key13[2]=(byte)rotls(Key13[2],1,8);
  }
}


void CryptData::SetKey15(const char *Password)
{
  InitCRC32(CRCTab);
  uint PswCRC=CRC32(0xffffffff,Password,strlen(Password));
  Key15[0]=PswCRC&0xffff;
  Key15[1]=(PswCRC>>16)&0xffff;
  Key15[2]=Key15[3]=0;
  for (size_t I=0;Password[I]!=0;I++)
  {
    byte P=Password[I];
    Key15[2]^=P^CRCTab[P];
    Key15[3]+=P+(CRCTab[P]>>16);
  }
}


void CryptData::SetAV15Encryption()
{
  InitCRC32(CRCTab);
  Method=CRYPT_RAR15;
  Key15[0]=0x4765;
  Key15[1]=0x9021;
  Key15[2]=0x7382;
  Key15[3]=0x5215;
}


void CryptData::SetCmt13Encryption()
{
  Method=CRYPT_RAR13;
  Key13[0]=0;
  Key13[1]=7;
  Key13[2]=77;
}


void CryptData::Decrypt13(byte *Data,size_t Count)
{
  while (Count--)
  {
    Key13[1]+=Key13[2];
    Key13[0]+=Key13[1];
    *Data-=Key13[0];
    Data++;
  }
}


void CryptData::Crypt15(byte *Data,size_t Count)
{
  while (Count--)
  {
    Key15[0]+=0x1234;
    Key15[1]^=CRCTab[(Key15[0] & 0x1fe)>>1];
    Key15[2]-=CRCTab[(Key15[0] & 0x1fe)>>1]>>16;
    Key15[0]^=Key15[2];
    Key15[3]=rotrs(Key15[3]&0xffff,1,16)^Key15[1];
    Key15[3]=rotrs(Key15[3]&0xffff,1,16);
    Key15[0]^=Key15[3];
    *Data^=(byte)(Key15[0]>>8);
    Data++;
  }
}

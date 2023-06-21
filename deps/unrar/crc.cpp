// This CRC function is based on Intel Slicing-by-8 algorithm.
//
// Original Intel Slicing-by-8 code is available here:
//
//    http://sourceforge.net/projects/slicing-by-8/
//
// Original Intel Slicing-by-8 code is licensed as:
//    
//    Copyright (c) 2004-2006 Intel Corporation - All Rights Reserved
//    
//    This software program is licensed subject to the BSD License, 
//    available at http://www.opensource.org/licenses/bsd-license.html


#include "rar.hpp"

#ifndef SFX_MODULE
// User suggested to avoid BSD license in SFX module, so they do not need
// to include the license to SFX archive.
#define USE_SLICING
#endif

static uint crc_tables[8][256]; // Tables for Slicing-by-8.


// Build the classic CRC32 lookup table.
// We also provide this function to legacy RAR and ZIP decryption code.
void InitCRC32(uint *CRCTab)
{
  if (CRCTab[1]!=0)
    return;
  for (uint I=0;I<256;I++)
  {
    uint C=I;
    for (uint J=0;J<8;J++)
      C=(C & 1) ? (C>>1)^0xEDB88320 : (C>>1);
    CRCTab[I]=C;
  }
}


static void InitTables()
{
  InitCRC32(crc_tables[0]);

#ifdef USE_SLICING
  for (uint I=0;I<256;I++) // Build additional lookup tables.
  {
    uint C=crc_tables[0][I];
    for (uint J=1;J<8;J++)
    {
      C=crc_tables[0][(byte)C]^(C>>8);
      crc_tables[J][I]=C;
    }
  }
#endif
}


struct CallInitCRC {CallInitCRC() {InitTables();}} static CallInit32;

uint CRC32(uint StartCRC,const void *Addr,size_t Size)
{
  byte *Data=(byte *)Addr;

#ifdef USE_SLICING
  // Align Data to 8 for better performance.
  for (;Size>0 && ((size_t)Data & 7);Size--,Data++)
    StartCRC=crc_tables[0][(byte)(StartCRC^Data[0])]^(StartCRC>>8);

  for (;Size>=8;Size-=8,Data+=8)
  {
#ifdef BIG_ENDIAN
    StartCRC ^= Data[0]|(Data[1] << 8)|(Data[2] << 16)|(Data[3] << 24);
    uint NextData = Data[4]|(Data[5] << 8)|(Data[6] << 16)|(Data[7] << 24);
#else
    StartCRC ^= *(uint32 *) Data;
    uint NextData = *(uint32 *) (Data+4);
#endif
    StartCRC = crc_tables[7][(byte) StartCRC       ] ^
               crc_tables[6][(byte)(StartCRC >> 8) ] ^
               crc_tables[5][(byte)(StartCRC >> 16)] ^
               crc_tables[4][(byte)(StartCRC >> 24)] ^
               crc_tables[3][(byte) NextData       ] ^
               crc_tables[2][(byte)(NextData >> 8) ] ^
               crc_tables[1][(byte)(NextData >> 16)] ^
               crc_tables[0][(byte)(NextData >> 24)];
  }
#endif

  for (;Size>0;Size--,Data++) // Process left data.
    StartCRC=crc_tables[0][(byte)(StartCRC^Data[0])]^(StartCRC>>8);

  return StartCRC;
}


#ifndef SFX_MODULE
// For RAR 1.4 archives in case somebody still has them.
ushort Checksum14(ushort StartCRC,const void *Addr,size_t Size)
{
  byte *Data=(byte *)Addr;
  for (size_t I=0;I<Size;I++)
  {
    StartCRC=(StartCRC+Data[I])&0xffff;
    StartCRC=((StartCRC<<1)|(StartCRC>>15))&0xffff;
  }
  return StartCRC;
}
#endif


#if 0
static uint64 crc64_tables[8][256]; // Tables for Slicing-by-8 for CRC64.

void InitCRC64(uint64 *CRCTab)
{
  const uint64 poly=INT32TO64(0xC96C5795, 0xD7870F42); // 0xC96C5795D7870F42;
  for (uint I=0;I<256;I++)
  {
    uint64 C=I;
    for (uint J=0;J<8;J++)
      C=(C & 1) ? (C>>1)^poly: (C>>1);
    CRCTab[I]=C;
  }
}


static void InitTables64()
{
  InitCRC64(crc64_tables[0]);

  for (uint I=0;I<256;I++) // Build additional lookup tables.
  {
    uint64 C=crc64_tables[0][I];
    for (uint J=1;J<8;J++)
    {
      C=crc64_tables[0][(byte)C]^(C>>8);
      crc64_tables[J][I]=C;
    }
  }
}


// We cannot place the intialization to CRC64(), because we use this function
// in multithreaded mode and it conflicts with multithreading.
struct CallInitCRC64 {CallInitCRC64() {InitTables64();}} static CallInit64;

uint64 CRC64(uint64 StartCRC,const void *Addr,size_t Size)
{
  byte *Data=(byte *)Addr;

  // Align Data to 8 for better performance.
  for (;Size>0 && ((size_t)Data & 7)!=0;Size--,Data++)
    StartCRC=crc64_tables[0][(byte)(StartCRC^Data[0])]^(StartCRC>>8);

  for (byte *DataEnd=Data+Size/8*8; Data<DataEnd; Data+=8 )
  {
    uint64 Index=StartCRC;
#ifdef BIG_ENDIAN
    Index ^= (uint64(Data[0])|(uint64(Data[1])<<8)|(uint64(Data[2])<<16)|(uint64(Data[3])<<24))|
             (uint64(Data[4])<<32)|(uint64(Data[5])<<40)|(uint64(Data[6])<<48)|(uint64(Data[7])<<56);
#else
    Index ^= *(uint64 *)Data;
#endif
    StartCRC = crc64_tables[ 7 ] [ ( byte ) (Index       ) ] ^
               crc64_tables[ 6 ] [ ( byte ) (Index >>  8 ) ] ^
               crc64_tables[ 5 ] [ ( byte ) (Index >> 16 ) ] ^
               crc64_tables[ 4 ] [ ( byte ) (Index >> 24 ) ] ^
               crc64_tables[ 3 ] [ ( byte ) (Index >> 32 ) ] ^
               crc64_tables[ 2 ] [ ( byte ) (Index >> 40 ) ] ^
               crc64_tables[ 1 ] [ ( byte ) (Index >> 48 ) ] ^
               crc64_tables[ 0 ] [ ( byte ) (Index >> 56 ) ] ;
  }

  for (Size%=8;Size>0;Size--,Data++) // Process left data.
    StartCRC=crc64_tables[0][(byte)(StartCRC^Data[0])]^(StartCRC>>8);

  return StartCRC;
}


#if 0
static void TestCRC();
struct TestCRCStruct {TestCRCStruct() {TestCRC();exit(0);}} GlobalTesCRC;

void TestCRC()
{
  const uint FirstSize=300;
  byte b[FirstSize];

  if ((CRC32(0xffffffff,(byte*)"testtesttest",12)^0xffffffff)==0x44608e84)
    mprintf(L"\nCRC32 test1 OK");
  else
    mprintf(L"\nCRC32 test1 FAILED");

  if (CRC32(0,(byte*)"te\x80st",5)==0xB2E5C5AE)
    mprintf(L"\nCRC32 test2 OK");
  else
    mprintf(L"\nCRC32 test2 FAILED");

  for (uint I=0;I<14;I++) // Check for possible int sign extension.
    b[I]=(byte)0x7f+I;
  if ((CRC32(0xffffffff,b,14)^0xffffffff)==0x1DFA75DA)
    mprintf(L"\nCRC32 test3 OK");
  else
    mprintf(L"\nCRC32 test3 FAILED");

  for (uint I=0;I<FirstSize;I++)
    b[I]=(byte)I;
  uint r32=CRC32(0xffffffff,b,FirstSize);
  for (uint I=FirstSize;I<1024;I++)
  {
    b[0]=(byte)I;
    r32=CRC32(r32,b,1);
  }
  if ((r32^0xffffffff)==0xB70B4C26)
    mprintf(L"\nCRC32 test4 OK");
  else
    mprintf(L"\nCRC32 test4 FAILED");

  if ((CRC64(0xffffffffffffffff,(byte*)"testtesttest",12)^0xffffffffffffffff)==0x7B1C2D230EDEB436)
    mprintf(L"\nCRC64 test1 OK");
  else
    mprintf(L"\nCRC64 test1 FAILED");

  if (CRC64(0,(byte*)"te\x80st",5)==0xB5DBF9583A6EED4A)
    mprintf(L"\nCRC64 test2 OK");
  else
    mprintf(L"\nCRC64 test2 FAILED");

  for (uint I=0;I<14;I++) // Check for possible int sign extension.
    b[I]=(byte)0x7f+I;
  if ((CRC64(0xffffffffffffffff,b,14)^0xffffffffffffffff)==0xE019941C05B2820C)
    mprintf(L"\nCRC64 test3 OK");
  else
    mprintf(L"\nCRC64 test3 FAILED");

  for (uint I=0;I<FirstSize;I++)
    b[I]=(byte)I;
  uint64 r64=CRC64(0xffffffffffffffff,b,FirstSize);
  for (uint I=FirstSize;I<1024;I++)
  {
    b[0]=(byte)I;
    r64=CRC64(r64,b,1);
  }
  if ((r64^0xffffffffffffffff)==0xD51FB58DC789C400)
    mprintf(L"\nCRC64 test4 OK");
  else
    mprintf(L"\nCRC64 test4 FAILED");

  const size_t BufSize=0x100000;
  byte *Buf=new byte[BufSize];
  memset(Buf,0,BufSize);

  clock_t StartTime=clock();
  r32=0xffffffff;
  const uint BufCount=5000;
  for (uint I=0;I<BufCount;I++)
    r32=CRC32(r32,Buf,BufSize);
  if (r32!=0) // Otherwise compiler optimizer removes CRC calculation.
    mprintf(L"\nCRC32 speed: %d MB/s",BufCount*1000/(clock()-StartTime));

  StartTime=clock();
  r64=0xffffffffffffffff;
  for (uint I=0;I<BufCount;I++)
    r64=CRC64(r64,Buf,BufSize);
  if (r64!=0) // Otherwise compiler optimizer removes CRC calculation.
    mprintf(L"\nCRC64 speed: %d MB/s",BufCount*1000/(clock()-StartTime));
}
#endif

#endif

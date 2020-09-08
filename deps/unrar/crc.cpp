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

  for (uint I=0;I<256;I++) // Build additional lookup tables.
  {
    uint C=crc_tables[0][I];
    for (uint J=1;J<8;J++)
    {
      C=crc_tables[0][(byte)C]^(C>>8);
      crc_tables[J][I]=C;
    }
  }
}


struct CallInitCRC {CallInitCRC() {InitTables();}} static CallInit32;

uint CRC32(uint StartCRC,const void *Addr,size_t Size)
{
  byte *Data=(byte *)Addr;

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



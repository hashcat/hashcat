#ifndef _RAR_CRC_
#define _RAR_CRC_

// This function is only to intialize external CRC tables. We do not need to
// call it before calculating CRC32.
void InitCRC32(uint *CRCTab);

uint CRC32(uint StartCRC,const void *Addr,size_t Size);

#ifndef SFX_MODULE
ushort Checksum14(ushort StartCRC,const void *Addr,size_t Size);
#endif


#endif

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// CREDITS go to the UnRAR project from rarlab.com
// see license.txt file

#include "rar.hpp"

#define WINSIZE 0x100000 // minimum window size 0x20000 (MinAllocSize is 0x40000), 1 MiB
#define SOLID   false
#define METHOD  VER_UNPACK // 29 for RAR3 archives

extern "C" unsigned int hc_decompress_rar (unsigned char *Win, unsigned char *Inp, unsigned char *VM, unsigned char *PPM, const unsigned int OutputSize, const unsigned char *Input, const unsigned int PackSize, const unsigned int UnpackSize, const unsigned char *Key, const unsigned char *IV)
{
  ComprDataIO DataIO;

  DataIO.InitRijindal ((byte *) Key, (byte *) IV);

  DataIO.SetPackedSizeToRead (PackSize);

  DataIO.SetTestMode   (false);
  DataIO.SetSkipUnpCRC (false); // or 'true', if we use our own crc32 code
  DataIO.UnpHash.Init  (HASH_CRC32, 1); // 1: 1 single thread ?

  DataIO.SetUnpackFromMemory ((byte *) Input,  PackSize);
  DataIO.SetUnpackToMemory   ((byte *) NULL, UnpackSize);

  Unpack Unp = Unpack (&DataIO);

  // not needed in our tests (no false positives):
  // memset (Win, 0, UnpackSize);
  // #define INPSIZE 0x50000
  // memset (Inp, 0, INPSIZE);
  // memset (VM,  0, INPSIZE);
  // #define PPMSIZE 216 * 1024 * 1024
  // memset (PPM,  0, PPMSIZE);

  Unp.SetWin (Win);
  Unp.SetPPM (PPM);

  Unp.Init (WINSIZE, SOLID);
  Unp.SetDestSize (UnpackSize);

  Unp.SetExternalBuffer (Inp, VM);

  Unp.DoUnpack (METHOD, SOLID); // sets output

  unsigned int crc32 = (unsigned int) DataIO.UnpHash.GetCRC32 ();

  return crc32;
}

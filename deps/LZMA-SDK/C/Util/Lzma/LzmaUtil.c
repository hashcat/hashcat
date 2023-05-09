/* LzmaUtil.c -- Test application for LZMA compression
2021-11-01 : Igor Pavlov : Public domain */

#include "../../Precomp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../CpuArch.h"

#include "../../Alloc.h"
#include "../../7zFile.h"
#include "../../7zVersion.h"
#include "../../LzFind.h"
#include "../../LzmaDec.h"
#include "../../LzmaEnc.h"

static const char * const kCantReadMessage = "Cannot read input file";
static const char * const kCantWriteMessage = "Cannot write output file";
static const char * const kCantAllocateMessage = "Cannot allocate memory";
static const char * const kDataErrorMessage = "Data error";

static void PrintHelp(char *buffer)
{
  strcat(buffer,
    "\nLZMA-C " MY_VERSION_CPU " : " MY_COPYRIGHT_DATE "\n\n"
    "Usage:  lzma <e|d> inputFile outputFile\n"
    "  e: encode file\n"
    "  d: decode file\n");
}

static int PrintError(char *buffer, const char *message)
{
  strcat(buffer, "\nError: ");
  strcat(buffer, message);
  strcat(buffer, "\n");
  return 1;
}

static int PrintError_WRes(char *buffer, const char *message, WRes wres)
{
  strcat(buffer, "\nError: ");
  strcat(buffer, message);
  sprintf(buffer + strlen(buffer), "\nSystem error code: %d", (unsigned)wres);
  #ifndef _WIN32
  {
    const char *s = strerror(wres);
    if (s)
      sprintf(buffer + strlen(buffer), " : %s", s);
  }
  #endif
  strcat(buffer, "\n");
  return 1;
}

static int PrintErrorNumber(char *buffer, SRes val)
{
  sprintf(buffer + strlen(buffer), "\n7-Zip error code: %d\n", (unsigned)val);
  return 1;
}

static int PrintUserError(char *buffer)
{
  return PrintError(buffer, "Incorrect command");
}


#define IN_BUF_SIZE (1 << 16)
#define OUT_BUF_SIZE (1 << 16)


static SRes Decode2(CLzmaDec *state, ISeqOutStream *outStream, ISeqInStream *inStream,
    UInt64 unpackSize)
{
  int thereIsSize = (unpackSize != (UInt64)(Int64)-1);
  Byte inBuf[IN_BUF_SIZE];
  Byte outBuf[OUT_BUF_SIZE];
  size_t inPos = 0, inSize = 0, outPos = 0;
  LzmaDec_Init(state);
  for (;;)
  {
    if (inPos == inSize)
    {
      inSize = IN_BUF_SIZE;
      RINOK(inStream->Read(inStream, inBuf, &inSize));
      inPos = 0;
    }
    {
      SRes res;
      SizeT inProcessed = inSize - inPos;
      SizeT outProcessed = OUT_BUF_SIZE - outPos;
      ELzmaFinishMode finishMode = LZMA_FINISH_ANY;
      ELzmaStatus status;
      if (thereIsSize && outProcessed > unpackSize)
      {
        outProcessed = (SizeT)unpackSize;
        finishMode = LZMA_FINISH_END;
      }
      
      res = LzmaDec_DecodeToBuf(state, outBuf + outPos, &outProcessed,
        inBuf + inPos, &inProcessed, finishMode, &status);
      inPos += inProcessed;
      outPos += outProcessed;
      unpackSize -= outProcessed;
      
      if (outStream)
        if (outStream->Write(outStream, outBuf, outPos) != outPos)
          return SZ_ERROR_WRITE;
        
      outPos = 0;
      
      if (res != SZ_OK || (thereIsSize && unpackSize == 0))
        return res;
      
      if (inProcessed == 0 && outProcessed == 0)
      {
        if (thereIsSize || status != LZMA_STATUS_FINISHED_WITH_MARK)
          return SZ_ERROR_DATA;
        return res;
      }
    }
  }
}


static SRes Decode(ISeqOutStream *outStream, ISeqInStream *inStream)
{
  UInt64 unpackSize;
  int i;
  SRes res = 0;

  CLzmaDec state;

  /* header: 5 bytes of LZMA properties and 8 bytes of uncompressed size */
  unsigned char header[LZMA_PROPS_SIZE + 8];

  /* Read and parse header */

  RINOK(SeqInStream_Read(inStream, header, sizeof(header)));

  unpackSize = 0;
  for (i = 0; i < 8; i++)
    unpackSize += (UInt64)header[LZMA_PROPS_SIZE + i] << (i * 8);

  LzmaDec_Construct(&state);
  RINOK(LzmaDec_Allocate(&state, header, LZMA_PROPS_SIZE, &g_Alloc));
  res = Decode2(&state, outStream, inStream, unpackSize);
  LzmaDec_Free(&state, &g_Alloc);
  return res;
}

static SRes Encode(ISeqOutStream *outStream, ISeqInStream *inStream, UInt64 fileSize, char *rs)
{
  CLzmaEncHandle enc;
  SRes res;
  CLzmaEncProps props;

  UNUSED_VAR(rs);

  enc = LzmaEnc_Create(&g_Alloc);
  if (enc == 0)
    return SZ_ERROR_MEM;

  LzmaEncProps_Init(&props);
  res = LzmaEnc_SetProps(enc, &props);

  if (res == SZ_OK)
  {
    Byte header[LZMA_PROPS_SIZE + 8];
    size_t headerSize = LZMA_PROPS_SIZE;
    int i;

    res = LzmaEnc_WriteProperties(enc, header, &headerSize);
    for (i = 0; i < 8; i++)
      header[headerSize++] = (Byte)(fileSize >> (8 * i));
    if (outStream->Write(outStream, header, headerSize) != headerSize)
      res = SZ_ERROR_WRITE;
    else
    {
      if (res == SZ_OK)
        res = LzmaEnc_Encode(enc, outStream, inStream, NULL, &g_Alloc, &g_Alloc);
    }
  }
  LzmaEnc_Destroy(enc, &g_Alloc, &g_Alloc);
  return res;
}


static int main2(int numArgs, const char *args[], char *rs)
{
  CFileSeqInStream inStream;
  CFileOutStream outStream;
  char c;
  int res;
  int encodeMode;
  BoolInt useOutFile = False;

  LzFindPrepare();

  FileSeqInStream_CreateVTable(&inStream);
  File_Construct(&inStream.file);
  inStream.wres = 0;

  FileOutStream_CreateVTable(&outStream);
  File_Construct(&outStream.file);
  outStream.wres = 0;

  if (numArgs == 1)
  {
    PrintHelp(rs);
    return 0;
  }

  if (numArgs < 3 || numArgs > 4 || strlen(args[1]) != 1)
    return PrintUserError(rs);

  c = args[1][0];
  encodeMode = (c == 'e' || c == 'E');
  if (!encodeMode && c != 'd' && c != 'D')
    return PrintUserError(rs);

  {
    size_t t4 = sizeof(UInt32);
    size_t t8 = sizeof(UInt64);
    if (t4 != 4 || t8 != 8)
      return PrintError(rs, "Incorrect UInt32 or UInt64");
  }

  {
    WRes wres = InFile_Open(&inStream.file, args[2]);
    if (wres != 0)
      return PrintError_WRes(rs, "Cannot open input file", wres);
  }

  if (numArgs > 3)
  {
    WRes wres;
    useOutFile = True;
    wres = OutFile_Open(&outStream.file, args[3]);
    if (wres != 0)
      return PrintError_WRes(rs, "Cannot open output file", wres);
  }
  else if (encodeMode)
    PrintUserError(rs);

  if (encodeMode)
  {
    UInt64 fileSize;
    WRes wres = File_GetLength(&inStream.file, &fileSize);
    if (wres != 0)
      return PrintError_WRes(rs, "Cannot get file length", wres);
    res = Encode(&outStream.vt, &inStream.vt, fileSize, rs);
  }
  else
  {
    res = Decode(&outStream.vt, useOutFile ? &inStream.vt : NULL);
  }

  if (useOutFile)
    File_Close(&outStream.file);
  File_Close(&inStream.file);

  if (res != SZ_OK)
  {
    if (res == SZ_ERROR_MEM)
      return PrintError(rs, kCantAllocateMessage);
    else if (res == SZ_ERROR_DATA)
      return PrintError(rs, kDataErrorMessage);
    else if (res == SZ_ERROR_WRITE)
      return PrintError_WRes(rs, kCantWriteMessage, outStream.wres);
    else if (res == SZ_ERROR_READ)
      return PrintError_WRes(rs, kCantReadMessage, inStream.wres);
    return PrintErrorNumber(rs, res);
  }
  return 0;
}


int MY_CDECL main(int numArgs, const char *args[])
{
  char rs[1000] = { 0 };
  int res = main2(numArgs, args, rs);
  fputs(rs, stdout);
  return res;
}

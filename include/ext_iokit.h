/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_IOKIT_H
#define _EXT_IOKIT_H

// key values
#define SMC_KEY_CPU_TEMP "TC0P"
#define SMC_KEY_GPU_TEMP "TG0P"
#define SMC_KEY_GPU_INT_TEMP "TCGC"
#define SMC_KEY_FAN0_RPM_CUR "F0Ac"

#ifdef __APPLE__
#include <IOKit/IOKitLib.h>

#define VERSION "0.01"

#define KERNEL_INDEX_SMC 2

#define SMC_CMD_READ_BYTES 5
#define SMC_CMD_WRITE_BYTES 6
#define SMC_CMD_READ_INDEX 8
#define SMC_CMD_READ_KEYINFO 9
#define SMC_CMD_READ_PLIMIT 11
#define SMC_CMD_READ_VERS 12

#define DATATYPE_FPE2 "fpe2"
#define DATATYPE_UINT8 "ui8 "
#define DATATYPE_UINT16 "ui16"
#define DATATYPE_UINT32 "ui32"
#define DATATYPE_SP78 "sp78"

typedef struct
{
  char   major;
  char   minor;
  char   build;
  char   reserved[1];
  UInt16 release;

} SMCKeyData_vers_t;

typedef struct
{
  UInt16 version;
  UInt16 length;
  UInt32 cpuPLimit;
  UInt32 gpuPLimit;
  UInt32 memPLimit;

} SMCKeyData_pLimitData_t;

typedef struct
{
  UInt32 dataSize;
  UInt32 dataType;

  char   dataAttributes;

} SMCKeyData_keyInfo_t;

typedef char SMCBytes_t[32];

typedef struct
{
  UInt32 key;

  SMCKeyData_vers_t vers;
  SMCKeyData_pLimitData_t pLimitData;
  SMCKeyData_keyInfo_t keyInfo;

  char   result;
  char   status;
  char   data8;

  UInt32       data32;
  SMCBytes_t   bytes;

} SMCKeyData_t;

typedef char UInt32Char_t[5];

typedef struct
{
  UInt32Char_t key;
  UInt32       dataSize;
  UInt32Char_t dataType;
  SMCBytes_t   bytes;

} SMCVal_t;

#endif // __APPLE__

typedef int HM_ADAPTER_IOKIT;

typedef void *IOKIT_LIB;

typedef struct hm_iokit_lib
{
  #if defined(__APPLE__)
  io_connect_t conn;
  #endif // __APPLE__

} hm_iokit_lib_t;

typedef hm_iokit_lib_t IOKIT_PTR;

#endif // _EXT_IOKIT_H

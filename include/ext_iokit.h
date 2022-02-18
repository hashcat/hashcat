/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_IOKIT_H
#define _EXT_IOKIT_H

#if defined(__APPLE__)
#include <IOKit/IOKitLib.h>

// Apple SMC Keys
#define HM_IOKIT_SMC_SENSOR_GRAPHICS_HOT "SGHT"
#define HM_IOKIT_SMC_CPU_PROXIMITY       "TC0P"
#define HM_IOKIT_SMC_GPU_PROXIMITY       "TG0P"
#define HM_IOKIT_SMC_PECI_GPU            "TCGC"

#define KERNEL_INDEX_SMC 2

#define DATATYPE_FPE2   "fpe2"
#define DATATYPE_FLT    "flt "
#define DATATYPE_UINT8  "ui8 "
#define DATATYPE_UINT16 "ui16"
#define DATATYPE_UINT32 "ui32"
#define DATATYPE_SP78   "sp78"

typedef enum
{
  SMC_CMD_READ_BYTES   =  5,
  SMC_CMD_WRITE_BYTES  =  6,
  SMC_CMD_READ_INDEX   =  8,
  SMC_CMD_READ_KEYINFO =  9,
  SMC_CMD_READ_PLIMIT  = 11,
  SMC_CMD_READ_VERS    = 12

} SMCCommands_t;

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

#if defined(__APPLE__)
UInt32 hm_IOKIT_strtoul (const char *str, int size, int base);
void hm_IOKIT_ultostr (char *str, UInt32 val);
kern_return_t hm_IOKIT_SMCOpen (void *hashcat_ctx, io_connect_t *conn);
kern_return_t hm_IOKIT_SMCClose (io_connect_t conn);
kern_return_t hm_IOKIT_SMCCall (int index, SMCKeyData_t *inData, SMCKeyData_t *outData, io_connect_t conn);
kern_return_t hm_IOKIT_SMCReadKey (UInt32Char_t key, SMCVal_t *val, io_connect_t conn);
int hm_IOKIT_SMCGetSensorGraphicHot (void *hashcat_ctx);
int hm_IOKIT_SMCGetTemperature (void *hashcat_ctx, char *key, double *temp);
bool hm_IOKIT_SMCGetFanRPM (char *key, io_connect_t conn, float *ret);
int hm_IOKIT_get_fan_speed_current (void *hashcat_ctx, char *fan_speed_buf);
int hm_IOKIT_get_utilization_current (void *hashcat_ctx, int *utilization);
bool iokit_init (void *hashcat_ctx);
bool iokit_close (void *hashcat_ctx);
#endif // __APPLE__

#endif // _EXT_IOKIT_H

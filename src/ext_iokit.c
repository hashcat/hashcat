/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "event.h"
#include "ext_iokit.h"

#if defined (__APPLE__)
#include <IOKit/IOKitLib.h>

UInt32 hm_IOKIT_strtoul (const char *str, int size, int base)
{
  int i;

  UInt32 total = 0;

  for (i = 0; i < size; i++)
  {
    if (base == 16)
    {
      total += str[i] << (size - 1 - i) * 8;
    }
    else
    {
      total += (unsigned char) (str[i] << (size - 1 - i) * 8);
    }
  }
  return total;
}

void hm_IOKIT_ultostr (char *str, UInt32 val)
{
  str[0] = '\0';

  sprintf (str, "%c%c%c%c", (unsigned int) (val >> 24), (unsigned int) (val >> 16), (unsigned int) (val >> 8), (unsigned int) (val));
}

kern_return_t hm_IOKIT_SMCOpen (void *hashcat_ctx, io_connect_t *conn)
{
  kern_return_t result;
  io_iterator_t iterator;
  io_object_t device;

  CFMutableDictionaryRef matchingDictionary = IOServiceMatching ("AppleSMC");

  result = IOServiceGetMatchingServices (kIOMasterPortDefault, matchingDictionary, &iterator);

  if (result != kIOReturnSuccess)
  {
    event_log_error (hashcat_ctx, "IOServiceGetMatchingServices(): %08x", result);

    return 1;
  }

  device = IOIteratorNext (iterator);

  IOObjectRelease (iterator);

  if (device == 0)
  {
    event_log_error (hashcat_ctx, "hm_IOKIT_SMCOpen(): no SMC found.");

    return 1;
  }

  result = IOServiceOpen (device, mach_task_self (), 0, conn);

  IOObjectRelease (device);

  if (result != kIOReturnSuccess)
  {
    event_log_error (hashcat_ctx, "IOServiceOpen(): %08x", result);

    return 1;
  }

  return kIOReturnSuccess;
}

kern_return_t hm_IOKIT_SMCClose (io_connect_t conn)
{
  return IOServiceClose (conn);
}

kern_return_t hm_IOKIT_SMCCall (int index, SMCKeyData_t *inData, SMCKeyData_t *outData, io_connect_t conn)
{
  size_t inDataSize  = sizeof (SMCKeyData_t);
  size_t outDataSize = sizeof (SMCKeyData_t);

  #if MAC_OS_X_VERSION_10_5
  return IOConnectCallStructMethod (conn, index, inData, inDataSize, outData, &outDataSize);
  #else
  return IOConnectMethodStructureIStructureO (conn, index, inDataSize, &outDataSize, inData, outData);
  #endif
}

kern_return_t hm_IOKIT_SMCReadKey (UInt32Char_t key, SMCVal_t *val, io_connect_t conn)
{
  SMCKeyData_t inData;
  SMCKeyData_t outData;

  memset (&inData,  0, sizeof (SMCKeyData_t));
  memset (&outData, 0, sizeof (SMCKeyData_t));
  memset (val,      0, sizeof (SMCVal_t));

  inData.key = hm_IOKIT_strtoul (key, 4, 16);

  inData.data8 = SMC_CMD_READ_KEYINFO;

  if (hm_IOKIT_SMCCall (KERNEL_INDEX_SMC, &inData, &outData, conn) != kIOReturnSuccess) return 1;

  val->dataSize = outData.keyInfo.dataSize;

  hm_IOKIT_ultostr (val->dataType, outData.keyInfo.dataType);

  inData.keyInfo.dataSize = val->dataSize;

  inData.data8 = SMC_CMD_READ_BYTES;

  if (hm_IOKIT_SMCCall (KERNEL_INDEX_SMC, &inData, &outData, conn) != kIOReturnSuccess) return 1;

  memcpy (val->bytes, outData.bytes, sizeof (outData.bytes));

  return kIOReturnSuccess;
}

int hm_IOKIT_SMCGetSensorGraphicHot (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  IOKIT_PTR *iokit = hwmon_ctx->hm_iokit;

  SMCVal_t val;

  memset (&val, 0, sizeof (SMCVal_t));

  if (hm_IOKIT_SMCReadKey (HM_IOKIT_SMC_SENSOR_GRAPHICS_HOT, &val, iokit->conn) == kIOReturnSuccess)
  {
    int alarm = -1;

    if (val.dataSize > 0)
    {
      if (strcmp (val.dataType, DATATYPE_UINT8) == 0)
      {
        alarm = hm_IOKIT_strtoul ((char *) val.bytes, val.dataSize, 10);
      }
    }

    return alarm;
  }

  return -1;
}

int hm_IOKIT_SMCGetTemperature (void *hashcat_ctx, char *key, double *temp)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  IOKIT_PTR *iokit = hwmon_ctx->hm_iokit;

  SMCVal_t val;

  memset (&val, 0, sizeof (SMCVal_t));

  if (hm_IOKIT_SMCReadKey (key, &val, iokit->conn) == kIOReturnSuccess)
  {
    if (val.dataSize > 0)
    {
      if (strcmp (val.dataType, DATATYPE_SP78) == 0)
      {
        // convert sp78 value to temperature
        int intValue = val.bytes[0] * 256 + (unsigned char)val.bytes[1];

        *temp = (intValue / 256.0);

        return 1;
      }
    }
  }

  // read failed

  *temp = 0.0;

  return -1;
}

bool hm_IOKIT_SMCGetFanRPM (char *key, io_connect_t conn, float *ret)
{
  SMCVal_t val;

  memset (&val, 0, sizeof (SMCVal_t));

  if (hm_IOKIT_SMCReadKey (key, &val, conn) == kIOReturnSuccess)
  {
    if (val.dataSize > 0)
    {
      if (strcmp (val.dataType, DATATYPE_FLT) == 0)
      {
        *ret = *(float *) val.bytes;

        return true;
      }

      if (strcmp (val.dataType, DATATYPE_FPE2) == 0)
      {
        // convert fpe2 value to RPM
        *ret = ntohs (*(UInt16*) val.bytes) / 4.0;

        return true;
      }
    }
  }

  // read failed
  *ret = -1.f;

  return false;
}

int hm_IOKIT_get_utilization_current (void *hashcat_ctx, int *utilization)
{
  bool rc = false;

  io_iterator_t iterator;

  CFMutableDictionaryRef matching = IOServiceMatching ("IOAccelerator");

  if (IOServiceGetMatchingServices (kIOMasterPortDefault, matching, &iterator) != kIOReturnSuccess)
  {
    event_log_error (hashcat_ctx, "IOServiceGetMatchingServices(): failure");

    return rc;
  }

  io_registry_entry_t regEntry;

  while ((regEntry = IOIteratorNext (iterator)))
  {
    // Put this services object into a dictionary object.
    CFMutableDictionaryRef serviceDictionary;

    if (IORegistryEntryCreateCFProperties (regEntry, &serviceDictionary, kCFAllocatorDefault, kNilOptions) != kIOReturnSuccess)
    {
      // Service dictionary creation failed.
      IOObjectRelease (regEntry);

      continue;
    }

    CFMutableDictionaryRef perf_properties = (CFMutableDictionaryRef) CFDictionaryGetValue (serviceDictionary, CFSTR ("PerformanceStatistics"));

    if (perf_properties)
    {
      static ssize_t gpuCoreUtil = 0;

      const void *gpuCoreUtilization = CFDictionaryGetValue (perf_properties, CFSTR ("Device Utilization %"));

      if (gpuCoreUtilization != NULL)
      {
        CFNumberGetValue (gpuCoreUtilization, kCFNumberSInt64Type, &gpuCoreUtil);

        *utilization = gpuCoreUtil;

        rc = true;
      }
    }

    CFRelease (serviceDictionary);

    IOObjectRelease (regEntry);

    if (rc == true) break;
  }

  IOObjectRelease (iterator);

  return rc;
}

int hm_IOKIT_get_fan_speed_current (void *hashcat_ctx, char *fan_speed_buf)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  IOKIT_PTR *iokit = hwmon_ctx->hm_iokit;

  SMCVal_t val;

  UInt32Char_t key;

  memset (&val, 0, sizeof (SMCVal_t));

  if (hm_IOKIT_SMCReadKey ("FNum", &val, iokit->conn) == kIOReturnSuccess)
  {
    int totalFans = hm_IOKIT_strtoul ((char *)val.bytes, val.dataSize, 10);

    if (totalFans <= 0) return -1;

    char tmp_buf[16];

    for (int i = 0; i < totalFans; i++)
    {
      int fan_speed = 0;
      float actual_speed  = 0.0f;
      float maximum_speed = 0.0f;

      memset (&key, 0, sizeof (UInt32Char_t));
      sprintf (key, "F%dAc", i);
      hm_IOKIT_SMCGetFanRPM (key, iokit->conn, &actual_speed);
      if (actual_speed < 0.f) continue;

      memset (&key, 0, sizeof (UInt32Char_t));
      sprintf (key, "F%dMx", i);
      hm_IOKIT_SMCGetFanRPM (key, iokit->conn, &maximum_speed);
      if (maximum_speed < 0.f) continue;

      fan_speed = (actual_speed / maximum_speed) * 100.f;

      memset   (tmp_buf, 0, sizeof (tmp_buf));
      snprintf (tmp_buf, sizeof (tmp_buf) - 1, "Fan%d: %d%%, ", i, fan_speed);
      strncat  (fan_speed_buf, tmp_buf, strlen (tmp_buf));
    }

    // remove last two bytes
    size_t out_len = strlen (fan_speed_buf);
    if (out_len > 2) fan_speed_buf[out_len-2] = '\0';
  }

  return 1;
}

bool iokit_init (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  IOKIT_PTR *iokit = hwmon_ctx->hm_iokit;

  memset (iokit, 0, sizeof (IOKIT_PTR));

  if (hm_IOKIT_SMCOpen (hashcat_ctx, &iokit->conn) == kIOReturnSuccess) return true;

  hcfree (hwmon_ctx->hm_iokit);

  hwmon_ctx->hm_iokit = NULL;

  return false;
}

bool iokit_close (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  IOKIT_PTR *iokit = hwmon_ctx->hm_iokit;

  hm_IOKIT_SMCClose (iokit->conn);

  return true;
}

#endif // __APPLE__

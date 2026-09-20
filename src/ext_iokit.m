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
#include <mach/mach_time.h>
#include <IOKit/IOKitLib.h>
#include <Foundation/Foundation.h>

typedef CFDictionaryRef IOReportSampleRef;

typedef int (^ioreportiterateblock) (IOReportSampleRef ch);

extern CFDictionaryRef IOReportCreateSamples (IOReportSubscriptionRef iorsub, CFMutableDictionaryRef subbedChannels, CFTypeRef a);
extern void IOReportIterate (CFDictionaryRef samples, ioreportiterateblock);
extern NSString* IOReportChannelGetChannelName (CFDictionaryRef);
extern int IOReportChannelGetFormat (CFDictionaryRef samples);
extern long IOReportSimpleGetIntegerValue (CFDictionaryRef, int);
extern CFMutableDictionaryRef IOReportCopyAllChannels (uint64_t, uint64_t);
extern IOReportSubscriptionRef IOReportCreateSubscription (void *a, CFMutableDictionaryRef desiredChannels, CFMutableDictionaryRef* subbedChannels, uint64_t channel_id, CFTypeRef b);

enum
{
  kIOReportFormatSimple = 1,
};

static void moving_avg_init (moving_avg_t *avg)
{
  memset (avg, 0, sizeof (moving_avg_t));
}

static void moving_avg_add (moving_avg_t *avg, int64_t value)
{
  avg->buffer[avg->index] = value;

  avg->index = (avg->index + 1) % MAX_WINDOW;

  if (avg->count < MAX_WINDOW) avg->count++;
}

static int64_t moving_avg_get (const moving_avg_t *avg)
{
  int64_t sum = 0;

  for (int i = 0; i < avg->count; i++)
  {
    sum += avg->buffer[i];
  }

  return (avg->count > 0) ? sum / avg->count : 0;
}

static void moving_avg_reset (moving_avg_t *avg)
{
  if (avg == NULL) return;

  avg->index = 0;
  avg->count = 0;

  for (int i = 0; i < MAX_WINDOW; i++)
  {
    avg->buffer[i] = 0;
  }
}

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

  snprintf (str, 5, "%c%c%c%c", (unsigned int) (val >> 24), (unsigned int) (val >> 16), (unsigned int) (val >> 8), (unsigned int) (val));
}

kern_return_t hm_IOKIT_SMCOpen (void *hashcat_ctx, io_connect_t *conn)
{
  kern_return_t result;
  io_iterator_t iterator;
  io_object_t   device;

  CFMutableDictionaryRef matchingDictionary = IOServiceMatching ("AppleSMC");

  result = IOServiceGetMatchingServices (hc_IOMasterPortDefault, matchingDictionary, &iterator);

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

u64 hm_IOKIT_IOReport_get_gpu_energy (IOReportSubscriptionRef sub, CFMutableDictionaryRef subscribed)
{
  __block uint64_t energy = 0;

  CFDictionaryRef samples = IOReportCreateSamples(sub, subscribed, NULL);

  if (!samples) return -1;

  IOReportIterate(samples, ^int(IOReportSampleRef ch)
  {
    NSString* channelName = IOReportChannelGetChannelName(ch);

    if ([channelName isEqualToString:@"GPU Energy"])
    {
      if (IOReportChannelGetFormat(ch) == kIOReportFormatSimple)
      {
        energy = IOReportSimpleGetIntegerValue(ch, 0);

        return 0;
      }
    }

    return 0;
  });

  CFRelease (samples);

  return energy;
}

int hm_IOKIT_get_power_current (void *hashcat_ctx, int64_t *power)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  IOKIT_PTR *iokit = hwmon_ctx->hm_iokit;

  // get last saved timestamp and power

  uint64_t t1 = iokit->pwr_t1;
  uint64_t e1 = iokit->pwr_e1;

  uint64_t t2 = mach_absolute_time();
  uint64_t e2 = hm_IOKIT_IOReport_get_gpu_energy (iokit->sub, iokit->subscribed);

  // update values for the next call

  iokit->pwr_t1 = t2;
  iokit->pwr_e1 = e2;

  mach_timebase_info_data_t timebase;
  mach_timebase_info (&timebase);

  // elapsed time in nanoseconds

  int64_t delta_mach = (int64_t) (t2 - t1);

  double delta_ns = (double) (delta_mach * timebase.numer / timebase.denom);

  // nanoseconds to seconds as a double for precision

  double delta_sc = delta_ns / 1e9;

  // calculate energy difference in nanojoules

  uint64_t delta_e_nJ = e2 - e1;

  double delta_e_J = (double) (delta_e_nJ / 1e9);

  // check for negative energy delta which can happen on counter reset or overflow

  double power_W = 0.0;

  if (delta_sc > 0.0)
  {
    power_W = delta_e_J / delta_sc;
  }

  // Convert power to milliwatts for your output

  int64_t raw_power_mW = (int64_t)(power_W * 1000.0);

  // add new power sample to moving average filter

  moving_avg_add (&iokit->avg_power, raw_power_mW);

  // return filtered power value

  *power = moving_avg_get (&iokit->avg_power);

  return 0;
}

int hm_IOKIT_get_utilization_current (void *hashcat_ctx, int *utilization)
{
  bool rc = false;

  io_iterator_t iterator;

  CFMutableDictionaryRef matching = IOServiceMatching ("IOAccelerator");

  if (IOServiceGetMatchingServices (hc_IOMasterPortDefault, matching, &iterator) != kIOReturnSuccess)
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

    // limit totalFans to 10

    if (totalFans > 10) totalFans = 10;

    char tmp_buf[16];

    for (int i = 0; i < totalFans; i++)
    {
      int fan_speed = 0;
      float actual_speed  = 0.0f;
      float maximum_speed = 0.0f;

      memset   (&key, 0, sizeof (UInt32Char_t));
      snprintf (key,  5, "F%dAc", i);

      hm_IOKIT_SMCGetFanRPM (key, iokit->conn, &actual_speed);

      if (actual_speed < 0.f) continue;

      memset   (&key, 0, sizeof (UInt32Char_t));
      snprintf (key,  5, "F%dMx", i);

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

  moving_avg_reset (&iokit->avg_power);

  if (hm_IOKIT_SMCOpen (hashcat_ctx, &iokit->conn) != kIOReturnSuccess)
  {
    hcfree (hwmon_ctx->hm_iokit);

    hwmon_ctx->hm_iokit = NULL;

    return false;
  }

  CFMutableDictionaryRef allChannels = IOReportCopyAllChannels (0,0);

  if (!allChannels)
  {
    hcfree (hwmon_ctx->hm_iokit);

    hwmon_ctx->hm_iokit = NULL;

    return false;
  }

  iokit->subscribed = NULL;

  iokit->sub = IOReportCreateSubscription (NULL, allChannels, &iokit->subscribed, 0, NULL);

  CFRelease (allChannels);

  if (!iokit->sub)
  {
    hcfree (hwmon_ctx->hm_iokit);

    hwmon_ctx->hm_iokit = NULL;

    return false;
  }

  if (!iokit->subscribed)
  {
    CFRelease (iokit->sub);

    hcfree (hwmon_ctx->hm_iokit);

    hwmon_ctx->hm_iokit = NULL;

    return false;
  }

  moving_avg_init (&iokit->avg_power);

  iokit->pwr_t1 = mach_absolute_time();

  iokit->pwr_e1 = hm_IOKIT_IOReport_get_gpu_energy (iokit->sub, iokit->subscribed);

  return true;
}

bool iokit_close (void *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = ((hashcat_ctx_t *) hashcat_ctx)->hwmon_ctx;

  IOKIT_PTR *iokit = hwmon_ctx->hm_iokit;

  hm_IOKIT_SMCClose (iokit->conn);

  moving_avg_reset (&iokit->avg_power);

  CFRelease (iokit->subscribed);

  iokit->subscribed = NULL;

  CFRelease (iokit->sub);

  iokit->sub = NULL;

  // iokit_init () gives this pointer back on each of its four failure paths, and this is the same
  // hand on the success path, where every other hm_ close frees the struct it was given.

  hcfree (iokit);

  return true;
}

#endif // __APPLE__

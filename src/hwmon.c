/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "dynloader.h"
#include "shared.h"
#include "folder.h"
#include "hwmon.h"

// general functions

static int get_adapters_num_adl (hashcat_ctx_t *hashcat_ctx, int *iNumberAdapters)
{
  if (hm_ADL_Adapter_NumberOfAdapters_Get (hashcat_ctx, iNumberAdapters) == -1) return -1;

  if (iNumberAdapters == NULL)
  {
    event_log_error (hashcat_ctx, "No ADL adapters found.");

    return -1;
  }

  return 0;
}

static int hm_get_adapter_index_nvapi (hashcat_ctx_t *hashcat_ctx, HM_ADAPTER_NVAPI *nvapiGPUHandle)
{
  NvU32 pGpuCount;

  if (hm_NvAPI_EnumPhysicalGPUs (hashcat_ctx, nvapiGPUHandle, &pGpuCount) == -1) return 0;

  if (pGpuCount == 0)
  {
    event_log_error (hashcat_ctx, "No NvAPI adapters found.");

    return 0;
  }

  return (pGpuCount);
}

static int hm_get_adapter_index_nvml (hashcat_ctx_t *hashcat_ctx, HM_ADAPTER_NVML *nvmlGPUHandle)
{
  unsigned int deviceCount = 0;

  hm_NVML_nvmlDeviceGetCount (hashcat_ctx, &deviceCount);

  if (deviceCount == 0)
  {
    event_log_error (hashcat_ctx, "No NVML adapters found.");

    return 0;
  }

  for (u32 i = 0; i < deviceCount; i++)
  {
    if (hm_NVML_nvmlDeviceGetHandleByIndex (hashcat_ctx, i, &nvmlGPUHandle[i]) == -1) break;

    // can be used to determine if the device by index matches the cuda device by index
    // char name[100]; memset (name, 0, sizeof (name));
    // hm_NVML_nvmlDeviceGetName (hashcat_ctx, nvGPUHandle[i], name, sizeof (name) - 1);
  }

  return (deviceCount);
}

// Do two backend devices sit on the same piece of physical hardware?
//
// They often do. --backend-devices-virtmulti clones one device into several, and a bridge clones the
// candidate feeder once per bridge unit. Every clone reports the same sensors, because there is only
// one thermometer.
//
// This can report a duplicate that is not one, and that only costs a repeated line. It can never
// claim two different devices are the same, which would hide one.

static bool hm_same_hardware (hashcat_ctx_t *hashcat_ctx, const hc_device_param_t *device_param_a, const hc_device_param_t *device_param_b)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;

  // With a bridge the device that does the work is the bridge unit, not the feeder, so the unit is
  // what identifies the hardware. The startup listing already tells units apart by comparing the
  // strings from get_unit_info, so use the same rule here and the two displays cannot disagree.

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->get_unit_info == NULL) return true;

    const char *info_a = bridge_ctx->get_unit_info (hashcat_ctx, bridge_ctx->platform_context, device_param_a->bridge_link_device);
    const char *info_b = bridge_ctx->get_unit_info (hashcat_ctx, bridge_ctx->platform_context, device_param_b->bridge_link_device);

    if (info_a == NULL) return true;
    if (info_b == NULL) return true;

    const bool same = (strcmp (info_a, info_b) == 0);

    return same;
  }

  // One piece of hardware can also be reached through two different runtimes, for instance a GPU
  // offered by both HIP and OpenCL, or a CPU offered by both the Intel OpenCL and the PoCL drivers.
  // Those arrive as separate devices with separate native handles, so comparing handles alone would
  // count the same processor twice.
  //
  // In practice one of the two is skipped as an alias before it ever gets here, so this rarely
  // decides anything today. It is kept because hashcat already knows the relationship, and asking
  // it is free and stays correct if which alias survives ever changes.

  for (int i = 0; i < device_param_a->device_id_alias_cnt; i++)
  {
    if (device_param_a->device_id_alias_buf[i] == device_param_b->device_id) return true;
  }

  // Without a bridge, compare the native device handle. A virtual clone is built from the same real
  // device index as its host, so it resolves to the very same handle, while two genuinely different
  // devices can never share one.

  if ((device_param_a->is_cuda   == true) && (device_param_b->is_cuda   == true)) return device_param_a->cuda_device   == device_param_b->cuda_device;
  if ((device_param_a->is_hip    == true) && (device_param_b->is_hip    == true)) return device_param_a->hip_device    == device_param_b->hip_device;
  if ((device_param_a->is_opencl == true) && (device_param_b->is_opencl == true)) return device_param_a->opencl_device == device_param_b->opencl_device;
  #if defined (__APPLE__)
  if ((device_param_a->is_metal  == true) && (device_param_b->is_metal  == true)) return device_param_a->metal_device  == device_param_b->metal_device;
  #endif

  return false;
}

// Ask the bridge for one of its unit's sensors.
//
// Under a bridge the backend device only feeds candidates. The work happens on the bridge unit, so
// that is the thing worth reporting, and a bridge that knows its hardware answers here.
//
// This runs before the hwmon_ctx->enabled test in every caller, on purpose. That flag says whether a
// GPU vendor library loaded, and a machine whose real compute is a bridge device may well have none.
// Waiting for it would hide the readings on exactly the machines that need them. --hwmon-disable is
// still honoured, because it is checked here instead.

// Fall through to the vendor backends, the bridge has nothing to say about this device at all.
#define HM_BRIDGE_PASS       (-3)

// The bridge owns this device but cannot give this particular reading. Report nothing.
#define HM_BRIDGE_NO_READING (-2)

static bool hm_bridge_has_sensors (const bridge_ctx_t *bridge_ctx)
{
  const void *funcs[] =
  {
    (const void *) bridge_ctx->get_unit_temperature,
    (const void *) bridge_ctx->get_unit_temperature_str,
    (const void *) bridge_ctx->get_unit_temperature_abort,
    (const void *) bridge_ctx->get_unit_fanspeed,
    (const void *) bridge_ctx->get_unit_utilization,
    (const void *) bridge_ctx->get_unit_corespeed,
    (const void *) bridge_ctx->get_unit_memoryspeed,
    (const void *) bridge_ctx->get_unit_buslanes,
    (const void *) bridge_ctx->get_unit_power,
  };

  for (size_t i = 0; i < (sizeof (funcs) / sizeof (funcs[0])); i++)
  {
    if (funcs[i] == NULL)           continue;
    if (funcs[i] == MODULE_DEFAULT) continue;

    return true;
  }

  return false;
}

static int hm_get_bridge_unit (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, const void *func)
{
  bridge_ctx_t   *bridge_ctx   = hashcat_ctx->bridge_ctx;
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->hwmon == false) return HM_BRIDGE_PASS;

  if (bridge_ctx->enabled == false) return HM_BRIDGE_PASS;

  // A bridge that reports even one sensor owns the whole line for its units. The backend device is
  // only the candidate feeder, so mixing in its fan speed and memory clock would describe two
  // different pieces of hardware on one line and read as though it described one.

  if (hm_bridge_has_sensors (bridge_ctx) == false) return HM_BRIDGE_PASS;

  const int unit = backend_ctx->devices_param[backend_device_idx].bridge_link_device;

  if (unit < 0) return HM_BRIDGE_PASS;

  if (func == NULL)           return HM_BRIDGE_NO_READING;
  if (func == MODULE_DEFAULT) return HM_BRIDGE_NO_READING;

  return unit;
}

// Does this device's sensor reporting belong to a bridge unit rather than to the backend device?
//
// Callers that treat the backend device as the thing being measured need to know, because under a
// bridge it is not. What kind of device the backend one is says nothing about the hardware the
// readings describe.

bool hm_bridge_owns_device (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;

  const int unit = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) bridge_ctx->get_unit_temperature);

  const bool result = (unit != HM_BRIDGE_PASS);

  return result;
}

// Is this device the one that should carry the hwmon line for its hardware?
//
// The lowest numbered device of each group answers yes. Everything else is a clone of it and would
// print the same sensor readings again.

bool hm_is_hwmon_group_leader (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  const hc_device_param_t *device_param = &backend_ctx->devices_param[backend_device_idx];

  for (int i = 0; i < backend_device_idx; i++)
  {
    const hc_device_param_t *device_param_prev = &backend_ctx->devices_param[i];

    if (device_param_prev->skipped         == true) continue;
    if (device_param_prev->skipped_warning == true) continue;

    if (hm_same_hardware (hashcat_ctx, device_param_prev, device_param) == true) return false;
  }

  return true;
}

int hm_get_threshold_slowdown_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].threshold_slowdown_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int target = 0;

      if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, (unsigned int *) &target) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].threshold_slowdown_get_supported = false;

        return -1;
      }

      return target;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
          {

          }
          else if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
          {

          }
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          int target = 0;

          if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, (unsigned int *) &target) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].threshold_slowdown_get_supported = false;

            return -1;
          }

          return target;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].threshold_slowdown_get_supported = false;

  return -1;
}

int hm_get_threshold_shutdown_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].threshold_shutdown_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int target = 0;

      if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_THRESHOLD_SHUTDOWN, (unsigned int *) &target) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].threshold_shutdown_get_supported = false;

        return -1;
      }

      return target;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
          {

          }
          else if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
          {

          }
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          int target = 0;

          if (hm_NVML_nvmlDeviceGetTemperatureThreshold (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_THRESHOLD_SHUTDOWN, (unsigned int *) &target) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].threshold_shutdown_get_supported = false;

            return -1;
          }

          return target;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].threshold_shutdown_get_supported = false;

  return -1;
}

// A bridge unit's own rendering of its temperature field, when it has more to say than one number.

bool hm_get_bridge_buslanes_str (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, char *buf, const size_t len)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;

  if (bridge_ctx->get_unit_buslanes_str == NULL)           return false;
  if (bridge_ctx->get_unit_buslanes_str == MODULE_DEFAULT) return false;

  const int unit = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) bridge_ctx->get_unit_buslanes_str);

  if (unit == HM_BRIDGE_NO_READING) return false;
  if (unit == HM_BRIDGE_PASS)       return false;

  const bool result = bridge_ctx->get_unit_buslanes_str (hashcat_ctx, bridge_ctx->platform_context, unit, buf, len);

  return result;
}

bool hm_get_bridge_temperature_str (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx, char *buf, const size_t len)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;

  if (bridge_ctx->get_unit_temperature_str == NULL)           return false;
  if (bridge_ctx->get_unit_temperature_str == MODULE_DEFAULT) return false;

  const int unit = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) bridge_ctx->get_unit_temperature_str);

  if (unit == HM_BRIDGE_NO_READING) return false;
  if (unit == HM_BRIDGE_PASS)       return false;

  const bool result = bridge_ctx->get_unit_temperature_str (hashcat_ctx, bridge_ctx->platform_context, unit, buf, len);

  return result;
}

// What this device must not get hotter than, according to the BRIDGE. Zero means the unit has nothing
// to say and the user's setting stands on its own.
//
// This is not the final answer. A unit limit and the user's setting are combined by taking the
// stricter of the two, and that is done by the callers, so a unit cannot be used to loosen a limit
// the user asked for. See monitor.c.

u32 hm_get_bridge_temperature_abort (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;

  if (bridge_ctx->get_unit_temperature_abort == NULL)           return 0;
  if (bridge_ctx->get_unit_temperature_abort == MODULE_DEFAULT) return 0;

  const int unit = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) bridge_ctx->get_unit_temperature_abort);

  if (unit == HM_BRIDGE_NO_READING) return 0;
  if (unit == HM_BRIDGE_PASS)       return 0;

  const u32 result = bridge_ctx->get_unit_temperature_abort (hashcat_ctx, bridge_ctx->platform_context, unit);

  return result;
}

// Name the limits the watchdog will really enforce, for the units that carry one of their own. The
// user's setting is not the number that applies to those, so it is worth saying which is.
//
// Returns how many devices named a limit, so the caller can tell whether the watchdog is really off.

// Formats a set of unit numbers as compactly as it can, "#1-#4" rather than "#1, #2, #3, #4", and
// keeps runs that are not adjacent apart, "#1-#3, #7".

static void hm_unit_list_str (const int *idx_buf, const int idx_cnt, char *out, const size_t out_sz)
{
  size_t off = 0;

  out[0] = 0;

  int i = 0;

  while (i < idx_cnt)
  {
    int j = i;

    while (((j + 1) < idx_cnt) && (idx_buf[j + 1] == (idx_buf[j] + 1))) j++;

    if (off >= out_sz) return;

    const char *sep = (off == 0) ? "" : ", ";

    if (j > i) off += snprintf (out + off, out_sz - off, "%s#%d-#%d", sep, idx_buf[i] + 1, idx_buf[j] + 1);
    else       off += snprintf (out + off, out_sz - off, "%s#%d",     sep, idx_buf[i] + 1);

    i = j + 1;
  }
}

// The whole temperature part of the watchdog banner, headline and detail together.
//
// One function because the two have to agree. The detail lines are indented under the headline, so
// printing them without one leaves them hanging, and announcing a threshold when nothing can actually
// be watched is worse than saying nothing.
//
// The detail is one line per distinct OUTCOME, not one per unit. Six units carrying two limits used to
// print seven near-identical lines and a machine with twenty-four would have printed twenty-five. What
// a reader needs is which units differ from the headline, and which are not watched at all.

void hm_temperature_abort_banner (hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  const u32 user_abort = user_options->hwmon_temp_abort;

  // The user asked for no abort at all, so nothing is watched and no unit limit changes that. Listing
  // the limits units carry would name thresholds that will never be applied.

  if (user_abort == 0)
  {
    event_log_info (hashcat_ctx, "Watchdog: Temperature abort trigger disabled.");

    return;
  }

  // Collected before anything is printed, because a line describes a GROUP and no group is known
  // until every unit has been looked at, and because the headline depends on what was found.

  int idx_buf[DEVICES_MAX];
  int lim_buf[DEVICES_MAX];   // -1 marks a unit with no sensor, which cannot be watched at all

  int cnt = 0;
  int watched_cnt = 0;
  int compute_cnt = 0;

  if (backend_ctx->enabled == true)
  {
    for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
    {
      const hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

      if (device_param->skipped == true) continue;
      if (device_param->skipped_warning == true) continue;

      // What the watchdog itself watches: a bridge unit, or a GPU. Counted so the banner can name the
      // two kinds apart, and only when there really are two. Under a bridge every backend device IS a
      // unit, so a machine can easily have no compute device being watched at all, and naming a kind
      // that is not there would invent a category rather than clarify one.

      if (hm_bridge_owns_device (hashcat_ctx, backend_devices_idx) == false)
      {
        if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) != 0) compute_cnt++;

        continue;
      }

      // Devices that share one piece of hardware share its limit too, so only the device that carries
      // the hwmon line for that hardware names it. Otherwise a bridge with many units on one device
      // would report the same hardware once per unit.

      if (hm_is_hwmon_group_leader (hashcat_ctx, backend_devices_idx) == false) continue;

      const u32 temp_abort_unit = hm_get_bridge_temperature_abort (hashcat_ctx, backend_devices_idx);

      if (temp_abort_unit == 0) continue;

      if (cnt == DEVICES_MAX) break;

      idx_buf[cnt] = backend_devices_idx;

      // A limit is only a limit if something can measure against it. The watchdog compares a reading
      // of -1 against the threshold and -1 is never greater, so naming a number for a unit with no
      // sensor would tell the user they are protected when they are not.

      if (hm_get_temperature_with_devices_idx (hashcat_ctx, backend_devices_idx) < 0)
      {
        lim_buf[cnt] = -1;
      }
      else
      {
        // The same rule the watchdog itself applies, so this names the number that will really be
        // enforced. Printing the unit's own limit was a lie whenever the user asked for a stricter one.

        lim_buf[cnt] = (int) MIN (temp_abort_unit, user_abort);

        watched_cnt++;
      }

      cnt++;
    }
  }

  // A vendor library means the compute devices are watched. Without one, the only things being watched
  // are the bridge units that reported a sensor, and if there are none then nothing is.

  // The candidate generator is a piece of hardware nobody else is watching. Under a bridge it appears
  // only as the virtual devices linked to units, so every reading taken through them describes the
  // UNIT, and the GPU itself, which is running flat out producing candidates, goes unwatched. Ask it
  // directly. One line, not one per virtual device, because they are all the same physical device.

  int feeder_idx = -1;

  if ((cnt > 0) && (backend_ctx->enabled == true))
  {
    for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
    {
      const hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

      if (device_param->skipped == true) continue;
      if (device_param->skipped_warning == true) continue;

      const int temp = hm_get_device_temperature (hashcat_ctx, backend_devices_idx);

      if (temp < 0) continue;

      feeder_idx = backend_devices_idx;

      break;
    }
  }

  const bool watched = ((compute_cnt > 0) || (watched_cnt > 0) || (feeder_idx >= 0));

  // The headline only carries a number when it is the WHOLE answer. With units listed underneath it
  // is not: the limit actually enforced is per unit, and a number in the headline would assert a
  // threshold that applies to nothing. There is no "compute devices" line to sit beside the bridge
  // ones either, because the two can never both appear: a unit only carries its own limit if its
  // bridge reports sensors, and a bridge that reports sensors owns the reading for EVERY backend
  // device, since under a bridge every backend device is one of its units. So a run has bridge units
  // to list, or compute devices watched at the one setting, never both.

  // The two single-answer forms stay on the `Watchdog:` prefix, because they ARE one line and they
  // sit beside the other `Watchdog:` lines. The plural heads a list and is punctuated as one.

  if (watched == false)     event_log_info (hashcat_ctx, "Watchdog: Temperature abort trigger disabled.");
  else if (cnt == 0)        event_log_info (hashcat_ctx, "Watchdog: Temperature abort trigger set to %uc", user_abort);
  else                      event_log_info (hashcat_ctx, "Temperature abort Watchdogs:");

  // Named rather than numbered on purpose. Its device number is one of the virtual ones, so "#1" here
  // would collide with "Bridge unit #1" on the next line while meaning something else entirely.

  if (feeder_idx >= 0) event_log_info (hashcat_ctx, "* Candidate generator aborts at %uc", user_abort);

  bool emitted[DEVICES_MAX];

  memset (emitted, 0, sizeof (emitted));

  for (int i = 0; i < cnt; i++)
  {
    if (emitted[i] == true) continue;

    int group_buf[DEVICES_MAX];
    int group_cnt = 0;

    for (int j = i; j < cnt; j++)
    {
      if (emitted[j] == true) continue;
      if (lim_buf[j] != lim_buf[i]) continue;

      emitted[j] = true;

      group_buf[group_cnt] = idx_buf[j];

      group_cnt++;
    }

    char units[256];

    hm_unit_list_str (group_buf, group_cnt, units, sizeof (units));

    const bool many = (group_cnt > 1);

    // One list item per outcome, marked the same way the device inventories above are.

    if (lim_buf[i] < 0)
    {
      if (many == true) event_log_info (hashcat_ctx, "* Bridge units %s have no temperature sensor and are not watched", units);
      else              event_log_info (hashcat_ctx, "* Bridge unit %s has no temperature sensor and is not watched",    units);
    }
    else
    {
      if (many == true) event_log_info (hashcat_ctx, "* Bridge units %s abort at %dc", units, lim_buf[i]);
      else              event_log_info (hashcat_ctx, "* Bridge unit %s aborts at %dc", units, lim_buf[i]);
    }
  }
}

int hm_get_temperature_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  const int bridge_unit_temperature = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) hashcat_ctx->bridge_ctx->get_unit_temperature);

  if (bridge_unit_temperature == HM_BRIDGE_NO_READING) return -1;

  if (bridge_unit_temperature != HM_BRIDGE_PASS)
  {
    const int val = hashcat_ctx->bridge_ctx->get_unit_temperature (hashcat_ctx, hashcat_ctx->bridge_ctx->platform_context, bridge_unit_temperature);

    return val;
  }

  const int result = hm_get_device_temperature (hashcat_ctx, backend_device_idx);

  return result;
}

// The BACKEND device's own temperature, asking the vendor library and never the bridge.
//
// Split out because under a bridge the two are different pieces of hardware and both matter. The
// reading below describes the card doing the hashing; this one describes the device generating the
// candidates, which is a GPU running flat out that nothing else would be watching.

int hm_get_device_temperature (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int temperature = 0;

      if (hm_NVML_nvmlDeviceGetTemperature (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_GPU, (u32 *) &temperature) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

        return -1;
      }

      return temperature;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_CPU)
    {
      #if defined (__APPLE__)
      if (backend_ctx->devices_param[backend_device_idx].opencl_platform_vendor_id == VENDOR_ID_APPLE)
      {
        if (hwmon_ctx->hm_iokit)
        {
          double temperature = 0.0;

          char *key = HM_IOKIT_SMC_CPU_PROXIMITY;

          if (hm_IOKIT_SMCGetTemperature (hashcat_ctx, key, &temperature) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

            return -1;
          }

          return (int) temperature;
        }
      }
      #endif

      if (hwmon_ctx->hm_sysfs_cpu)
      {
        int temperature = 0;

        if (hm_SYSFS_CPU_get_temperature_current (hashcat_ctx, &temperature) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

          return -1;
        }

        return temperature;
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      #if defined (__APPLE__)
      if (backend_ctx->devices_param[backend_device_idx].opencl_platform_vendor_id == VENDOR_ID_APPLE)
      {
        if (hwmon_ctx->hm_iokit)
        {
          double temperature = 0.0;

          char *key = HM_IOKIT_SMC_GPU_PROXIMITY;

          if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_INTEL_BEIGNET)
          {
            key = HM_IOKIT_SMC_PECI_GPU;
          }

          if (hm_IOKIT_SMCGetTemperature (hashcat_ctx, key, &temperature) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

            return -1;
          }

          return (int) temperature;
        }
      }
      #endif

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_INTEL_SDK)
      {
        if (hwmon_ctx->hm_sysfs_intelgpu)
        {
          int temperature = 0;

          if (hm_SYSFS_INTELGPU_get_temperature_current (hashcat_ctx, backend_device_idx, &temperature) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

            return -1;
          }

          return temperature;
        }
      }

      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
          {
            ADLTemperature Temperature;

            Temperature.iSize = sizeof (ADLTemperature);

            if (hm_ADL_Overdrive5_Temperature_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, 0, &Temperature) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

              return -1;
            }

            return Temperature.iTemperature / 1000;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
          {
            int Temperature = 0;

            if (hm_ADL_Overdrive6_Temperature_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &Temperature) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

              return -1;
            }

            return Temperature / 1000;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 8)
          {
            ADLPMLogDataOutput odlpDataOutput;

            memset (&odlpDataOutput, 0, sizeof (ADLPMLogDataOutput));

            if (hm_ADL2_New_QueryPMLogData_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &odlpDataOutput) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

              return -1;
            }

            return odlpDataOutput.sensors[PMLOG_TEMPERATURE_EDGE].value;
          }
        }

        if (hwmon_ctx->hm_sysfs_amdgpu)
        {
          int temperature = 0;

          if (hm_SYSFS_AMDGPU_get_temperature_current (hashcat_ctx, backend_device_idx, &temperature) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

            return -1;
          }

          return temperature;
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          int temperature = 0;

          if (hm_NVML_nvmlDeviceGetTemperature (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_TEMPERATURE_GPU, (u32 *) &temperature) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

            return -1;
          }

          return temperature;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].temperature_get_supported = false;

  return -1;
}

int hm_get_fanpolicy_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].fanpolicy_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    return 1;
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
          {
            ADLFanSpeedValue lpFanSpeedValue;

            memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

            lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
            lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;

            if (hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, 0, &lpFanSpeedValue) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].fanpolicy_get_supported = false;
              hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported  = false;

              return -1;
            }

            return (lpFanSpeedValue.iFanSpeed & ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED) ? 0 : 1;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
          {
            ADLOD6FanSpeedInfo lpFanSpeedInfo;

            memset (&lpFanSpeedInfo, 0, sizeof (lpFanSpeedInfo));

            if (hm_ADL_Overdrive6_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &lpFanSpeedInfo) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].fanpolicy_get_supported = false;
              hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported  = false;

              return -1;
            }

            return 1;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 8)
          {
            ADLPMLogDataOutput odlpDataOutput;

            memset (&odlpDataOutput, 0, sizeof (ADLPMLogDataOutput));

            if (hm_ADL2_New_QueryPMLogData_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &odlpDataOutput) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].fanpolicy_get_supported = false;
              hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported  = false;

              return -1;
            }

            return odlpDataOutput.sensors[PMLOG_FAN_PERCENTAGE].supported;
          }
        }

        if (hwmon_ctx->hm_sysfs_amdgpu)
        {
          return 1;
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        return 1;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].fanpolicy_get_supported = false;
  hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported  = false;

  return -1;
}

#if defined (__APPLE__)
int hm_get_fanspeed_apple (hashcat_ctx_t *hashcat_ctx, char *fan_speed_buf)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_iokit)
  {
    if (hm_IOKIT_get_fan_speed_current (hashcat_ctx, fan_speed_buf) == 0)
    {
      return 1;
    }
  }

  return -1;
}
#endif

int hm_get_fanspeed_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  const int bridge_unit_fanspeed = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) hashcat_ctx->bridge_ctx->get_unit_fanspeed);

  if (bridge_unit_fanspeed == HM_BRIDGE_NO_READING) return -1;

  if (bridge_unit_fanspeed != HM_BRIDGE_PASS)
  {
    const int val = hashcat_ctx->bridge_ctx->get_unit_fanspeed (hashcat_ctx, hashcat_ctx->bridge_ctx->platform_context, bridge_unit_fanspeed);

    return val;
  }

  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      int speed = 0;

      if (hm_NVML_nvmlDeviceGetFanSpeed (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, (u32 *) &speed) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

        return -1;
      }

      return speed;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_INTEL_SDK)
      {
        if (hwmon_ctx->hm_sysfs_intelgpu)
        {
          int speed = 0;

          if (hm_SYSFS_INTELGPU_get_fan_speed_current (hashcat_ctx, backend_device_idx, &speed) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

            return -1;
          }

          return speed;
        }
      }

      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
          {
            ADLFanSpeedValue lpFanSpeedValue;

            memset (&lpFanSpeedValue, 0, sizeof (lpFanSpeedValue));

            lpFanSpeedValue.iSize      = sizeof (lpFanSpeedValue);
            lpFanSpeedValue.iSpeedType = ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
            lpFanSpeedValue.iFlags     = ADL_DL_FANCTRL_FLAG_USER_DEFINED_SPEED;

            if (hm_ADL_Overdrive5_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, 0, &lpFanSpeedValue) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

              return -1;
            }

            return lpFanSpeedValue.iFanSpeed;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 6)
          {
            ADLOD6FanSpeedInfo faninfo;

            memset (&faninfo, 0, sizeof (faninfo));

            if (hm_ADL_Overdrive6_FanSpeed_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &faninfo) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

              return -1;
            }

            return faninfo.iFanSpeedPercent;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 8)
          {
            ADLPMLogDataOutput odlpDataOutput;

            memset (&odlpDataOutput, 0, sizeof (ADLPMLogDataOutput));

            if (hm_ADL2_New_QueryPMLogData_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &odlpDataOutput) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

              return -1;
            }

            return odlpDataOutput.sensors[PMLOG_FAN_PERCENTAGE].value;
          }
        }

        if (hwmon_ctx->hm_sysfs_amdgpu)
        {
          int speed = 0;

          if (hm_SYSFS_AMDGPU_get_fan_speed_current (hashcat_ctx, backend_device_idx, &speed) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

            return -1;
          }

          return speed;
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          int speed = 0;

          if (hm_NVML_nvmlDeviceGetFanSpeed (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, (u32 *) &speed) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

            return -1;
          }

          return speed;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].fanspeed_get_supported = false;

  return -1;
}

int hm_get_buslanes_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  const int bridge_unit_buslanes = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) hashcat_ctx->bridge_ctx->get_unit_buslanes);

  if (bridge_unit_buslanes == HM_BRIDGE_NO_READING) return -1;

  if (bridge_unit_buslanes != HM_BRIDGE_PASS)
  {
    const int val = hashcat_ctx->bridge_ctx->get_unit_buslanes (hashcat_ctx, hashcat_ctx->bridge_ctx->platform_context, bridge_unit_buslanes);

    return val;
  }

  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int currLinkWidth;

      if (hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &currLinkWidth) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

        return -1;
      }

      return currLinkWidth;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
          {
            ADLPMActivity PMActivity;

            PMActivity.iSize = sizeof (ADLPMActivity);

            if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &PMActivity) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

              return -1;
            }

            return PMActivity.iCurrentBusLanes;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 8)
          {
            ADLPMLogDataOutput odlpDataOutput;

            memset (&odlpDataOutput, 0, sizeof (ADLPMLogDataOutput));

            if (hm_ADL2_New_QueryPMLogData_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &odlpDataOutput) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

              return -1;
            }

            return odlpDataOutput.sensors[PMLOG_BUS_LANES].value;
          }
        }

        if (hwmon_ctx->hm_sysfs_amdgpu)
        {
          int lanes;

          if (hm_SYSFS_AMDGPU_get_pp_dpm_pcie (hashcat_ctx, backend_device_idx, &lanes) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

            return -1;
          }

          return lanes;
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          unsigned int currLinkWidth;

          if (hm_NVML_nvmlDeviceGetCurrPcieLinkWidth (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &currLinkWidth) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

            return -1;
          }

          return currLinkWidth;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].buslanes_get_supported = false;

  return -1;
}

int hm_get_utilization_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  const int bridge_unit_utilization = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) hashcat_ctx->bridge_ctx->get_unit_utilization);

  if (bridge_unit_utilization == HM_BRIDGE_NO_READING) return -1;

  if (bridge_unit_utilization != HM_BRIDGE_PASS)
  {
    const int val = hashcat_ctx->bridge_ctx->get_unit_utilization (hashcat_ctx, hashcat_ctx->bridge_ctx->platform_context, bridge_unit_utilization);

    return val;
  }

  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      nvmlUtilization_t utilization;

      if (hm_NVML_nvmlDeviceGetUtilizationRates (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &utilization) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

        return -1;
      }

      return utilization.gpu;
    }
  }

  #if defined (__APPLE__)
  if (backend_ctx->devices_param[backend_device_idx].is_metal == true || backend_ctx->devices_param[backend_device_idx].is_opencl == true)
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_platform_vendor_id == VENDOR_ID_APPLE)
    {
      if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
      {
        if (hwmon_ctx->hm_iokit)
        {
          int utilization = 0;

          if (hm_IOKIT_get_utilization_current (hashcat_ctx, &utilization) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

            return -1;
          }

          return utilization;
        }
      }
    }
  }
  #endif

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
          {
            ADLPMActivity PMActivity;

            PMActivity.iSize = sizeof (ADLPMActivity);

            if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &PMActivity) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

              return -1;
            }

            return PMActivity.iActivityPercent;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 8)
          {
            ADLPMLogDataOutput odlpDataOutput;

            memset (&odlpDataOutput, 0, sizeof (ADLPMLogDataOutput));

            if (hm_ADL2_New_QueryPMLogData_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &odlpDataOutput) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

              return -1;
            }

            return odlpDataOutput.sensors[PMLOG_INFO_ACTIVITY_GFX].value;
          }
        }

        if (hwmon_ctx->hm_sysfs_amdgpu)
        {
          int util;

          if (hm_SYSFS_AMDGPU_get_gpu_busy_percent (hashcat_ctx, backend_device_idx, &util) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

            return -1;
          }

          return util;
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          nvmlUtilization_t utilization;

          if (hm_NVML_nvmlDeviceGetUtilizationRates (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &utilization) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

            return -1;
          }

          return utilization.gpu;
        }
      }
    }

    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_CPU)
    {
      if (hwmon_ctx->hm_sysfs_cpu)
      {
        int utilization = 0;

        if (hm_SYSFS_CPU_get_utilization_current (hashcat_ctx, &utilization) == -1)
        {
          hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

          return -1;
        }

        return utilization;
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].utilization_get_supported = false;

  return -1;
}

int hm_get_memoryspeed_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  const int bridge_unit_memoryspeed = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) hashcat_ctx->bridge_ctx->get_unit_memoryspeed);

  if (bridge_unit_memoryspeed == HM_BRIDGE_NO_READING) return -1;

  if (bridge_unit_memoryspeed != HM_BRIDGE_PASS)
  {
    const int val = hashcat_ctx->bridge_ctx->get_unit_memoryspeed (hashcat_ctx, hashcat_ctx->bridge_ctx->platform_context, bridge_unit_memoryspeed);

    return val;
  }

  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int clockfreq;

      if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_CLOCK_MEM, &clockfreq) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

        return -1;
      }

      return clockfreq;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
          {
            ADLPMActivity PMActivity;

            PMActivity.iSize = sizeof (ADLPMActivity);

            if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &PMActivity) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

              return -1;
            }

            return PMActivity.iMemoryClock / 100;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 8)
          {
            ADLPMLogDataOutput odlpDataOutput;

            memset (&odlpDataOutput, 0, sizeof (ADLPMLogDataOutput));

            if (hm_ADL2_New_QueryPMLogData_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &odlpDataOutput) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

              return -1;
            }

            return odlpDataOutput.sensors[PMLOG_CLK_MEMCLK].value;
          }
        }

        if (hwmon_ctx->hm_sysfs_amdgpu)
        {
          int clockfreq;

          if (hm_SYSFS_AMDGPU_get_pp_dpm_mclk (hashcat_ctx, backend_device_idx, &clockfreq) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

            return -1;
          }

          return clockfreq;
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          unsigned int clockfreq;

          if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_CLOCK_MEM, &clockfreq) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

            return -1;
          }

          return clockfreq;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].memoryspeed_get_supported = false;

  return -1;
}

int hm_get_corespeed_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  const int bridge_unit_corespeed = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) hashcat_ctx->bridge_ctx->get_unit_corespeed);

  if (bridge_unit_corespeed == HM_BRIDGE_NO_READING) return -1;

  if (bridge_unit_corespeed != HM_BRIDGE_PASS)
  {
    const int val = hashcat_ctx->bridge_ctx->get_unit_corespeed (hashcat_ctx, hashcat_ctx->bridge_ctx->platform_context, bridge_unit_corespeed);

    return val;
  }

  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int clockfreq;

      if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_CLOCK_SM, &clockfreq) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

        return -1;
      }

      return clockfreq;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_adl)
        {
          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 5)
          {
            ADLPMActivity PMActivity;

            PMActivity.iSize = sizeof (ADLPMActivity);

            if (hm_ADL_Overdrive_CurrentActivity_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &PMActivity) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

              return -1;
            }

            return PMActivity.iEngineClock / 100;
          }

          if (hwmon_ctx->hm_device[backend_device_idx].od_version == 8)
          {
            ADLPMLogDataOutput odlpDataOutput;

            memset (&odlpDataOutput, 0, sizeof (ADLPMLogDataOutput));

            if (hm_ADL2_New_QueryPMLogData_Get (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].adl, &odlpDataOutput) == -1)
            {
              hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

              return -1;
            }

            return odlpDataOutput.sensors[PMLOG_CLK_GFXCLK].value;
          }
        }

        if (hwmon_ctx->hm_sysfs_amdgpu)
        {
          int clockfreq;

          if (hm_SYSFS_AMDGPU_get_pp_dpm_sclk (hashcat_ctx, backend_device_idx, &clockfreq) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

            return -1;
          }

          return clockfreq;
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          unsigned int clockfreq;

          if (hm_NVML_nvmlDeviceGetClockInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, NVML_CLOCK_SM, &clockfreq) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

            return -1;
          }

          return clockfreq;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].corespeed_get_supported = false;

  return -1;
}

int hm_get_throttle_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].throttle_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      /* this is triggered by mask generator, too. therefore useless
      unsigned long long clocksThrottleReasons = 0;
      unsigned long long supportedThrottleReasons = 0;

      if (hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons   (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &clocksThrottleReasons)    == -1) return -1;
      if (hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &supportedThrottleReasons) == -1) return -1;

      clocksThrottleReasons &=  supportedThrottleReasons;
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonGpuIdle;
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonApplicationsClocksSetting;
      clocksThrottleReasons &= ~nvmlClocksThrottleReasonUnknown;

      if (backend_ctx->kernel_power_final)
      {
        clocksThrottleReasons &= ~nvmlClocksThrottleReasonHwSlowdown;
      }

      return (clocksThrottleReasons != nvmlClocksThrottleReasonNone);
      */
    }

    if (hwmon_ctx->hm_nvapi)
    {
      NV_GPU_PERF_POLICIES_INFO_PARAMS_V1   perfPolicies_info;
      NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 perfPolicies_status;

      memset (&perfPolicies_info,   0, sizeof (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1));
      memset (&perfPolicies_status, 0, sizeof (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1));

      perfPolicies_info.version   = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1, 1);
      perfPolicies_status.version = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1, 1);

      hm_NvAPI_GPU_GetPerfPoliciesInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvapi, &perfPolicies_info);

      perfPolicies_status.info_value = perfPolicies_info.info_value;

      hm_NvAPI_GPU_GetPerfPoliciesStatus (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvapi, &perfPolicies_status);

      return perfPolicies_status.throttle & 2;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          /* this is triggered by mask generator, too. therefore useless
          unsigned long long clocksThrottleReasons = 0;
          unsigned long long supportedThrottleReasons = 0;

          if (hm_NVML_nvmlDeviceGetCurrentClocksThrottleReasons   (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &clocksThrottleReasons)    == -1) return -1;
          if (hm_NVML_nvmlDeviceGetSupportedClocksThrottleReasons (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &supportedThrottleReasons) == -1) return -1;

          clocksThrottleReasons &=  supportedThrottleReasons;
          clocksThrottleReasons &= ~nvmlClocksThrottleReasonGpuIdle;
          clocksThrottleReasons &= ~nvmlClocksThrottleReasonApplicationsClocksSetting;
          clocksThrottleReasons &= ~nvmlClocksThrottleReasonUnknown;

          if (backend_ctx->kernel_power_final)
          {
            clocksThrottleReasons &= ~nvmlClocksThrottleReasonHwSlowdown;
          }

          return (clocksThrottleReasons != nvmlClocksThrottleReasonNone);
          */
        }

        if (hwmon_ctx->hm_nvapi)
        {
          NV_GPU_PERF_POLICIES_INFO_PARAMS_V1   perfPolicies_info;
          NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 perfPolicies_status;

          memset (&perfPolicies_info,   0, sizeof (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1));
          memset (&perfPolicies_status, 0, sizeof (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1));

          perfPolicies_info.version   = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1, 1);
          perfPolicies_status.version = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1, 1);

          hm_NvAPI_GPU_GetPerfPoliciesInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvapi, &perfPolicies_info);

          perfPolicies_status.info_value = perfPolicies_info.info_value;

          hm_NvAPI_GPU_GetPerfPoliciesStatus (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvapi, &perfPolicies_status);

          return perfPolicies_status.throttle & 2;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].throttle_get_supported = false;

  return -1;
}

int64_t hm_get_power_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  const int bridge_unit_power = hm_get_bridge_unit (hashcat_ctx, backend_device_idx, (const void *) hashcat_ctx->bridge_ctx->get_unit_power);

  if (bridge_unit_power == HM_BRIDGE_NO_READING) return -1;

  if (bridge_unit_power != HM_BRIDGE_PASS)
  {
    // an unsigned reading cannot use -1, so a bridge reports no reading as 0
    const u64 val = hashcat_ctx->bridge_ctx->get_unit_power (hashcat_ctx, hashcat_ctx->bridge_ctx->platform_context, bridge_unit_power);

    if (val) return (int64_t) val;
  }

  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].power_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int milliwatts;

      if (hm_NVML_nvmlDeviceGetPowerUsage (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &milliwatts) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].power_get_supported = false;

        return -1;
      }

      return (int64_t) milliwatts;
    }
  }

  #if defined (__APPLE__)
  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_metal == true))
  {
    if (hwmon_ctx->hm_iokit)
    {
      int64_t power = 0;

      if (hm_IOKIT_get_power_current (hashcat_ctx, &power) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].power_get_supported = false;

        return 0;
      }

      return power;
    }
  }
  #endif

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          unsigned int milliwatts;

          if (hm_NVML_nvmlDeviceGetPowerUsage (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &milliwatts) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].power_get_supported = false;

            return -1;
          }

          return (int64_t) milliwatts;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].power_get_supported = false;

  return -1;
}

int64_t hm_get_power_limit_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].power_limit_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int milliwatts;

      if (hm_NVML_nvmlDeviceGetPowerManagementLimit (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &milliwatts) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].power_limit_get_supported = false;

        return -1;
      }

      return (int64_t) milliwatts;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          unsigned int milliwatts;

          if (hm_NVML_nvmlDeviceGetPowerManagementLimit (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &milliwatts) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].power_limit_get_supported = false;

            return -1;
          }

          return (int64_t) milliwatts;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].power_limit_get_supported = false;

  return -1;
}

int hm_get_pcie_gen_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return -1;

  if (hwmon_ctx->hm_device[backend_device_idx].pcie_gen_get_supported == false) return -1;

  if (backend_ctx->devices_param[backend_device_idx].is_cuda == true)
  {
    if (hwmon_ctx->hm_nvml)
    {
      unsigned int currLinkGen;

      if (hm_NVML_nvmlDeviceGetCurrPcieLinkGeneration (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &currLinkGen) == -1)
      {
        hwmon_ctx->hm_device[backend_device_idx].pcie_gen_get_supported = false;

        return -1;
      }

      return currLinkGen;
    }
  }

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          unsigned int currLinkGen;

          if (hm_NVML_nvmlDeviceGetCurrPcieLinkGeneration (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &currLinkGen) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].pcie_gen_get_supported = false;

            return -1;
          }

          return currLinkGen;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].pcie_gen_get_supported = false;

  return -1;
}

u64 hm_get_memoryused_with_devices_idx (hashcat_ctx_t *hashcat_ctx, const int backend_device_idx)
{
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (hwmon_ctx->enabled == false) return 0;

  if (hwmon_ctx->hm_device[backend_device_idx].memoryused_get_supported == false) return 0;

  if ((backend_ctx->devices_param[backend_device_idx].is_opencl == true) || (backend_ctx->devices_param[backend_device_idx].is_hip == true) || (backend_ctx->devices_param[backend_device_idx].is_cuda == true))
  {
    if (backend_ctx->devices_param[backend_device_idx].opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD) || (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
        if (hwmon_ctx->hm_sysfs_amdgpu)
        {
          u64 used = 0;

          if (hm_SYSFS_AMDGPU_get_mem_info_vram_used (hashcat_ctx, backend_device_idx, &used) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].memoryused_get_supported = false;

            return 0;
          }

          return used;
        }
      }

      if (backend_ctx->devices_param[backend_device_idx].opencl_device_vendor_id == VENDOR_ID_NV)
      {
        if (hwmon_ctx->hm_nvml)
        {
          nvmlMemory_t mem;

          if (hm_NVML_nvmlDeviceGetMemoryInfo (hashcat_ctx, hwmon_ctx->hm_device[backend_device_idx].nvml, &mem) == -1)
          {
            hwmon_ctx->hm_device[backend_device_idx].memoryused_get_supported = false;

            return 0;
          }

          return mem.used;
        }
      }
    }
  }

  hwmon_ctx->hm_device[backend_device_idx].memoryused_get_supported = false;

  return 0;
}

static void hwmon_ctx_init_nvml (hashcat_ctx_t *hashcat_ctx, hm_attrs_t *hm_adapters_nvml, int backend_devices_cnt)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->hm_nvml)
  {
    if (hm_NVML_nvmlInit (hashcat_ctx) == 0)
    {
      HM_ADAPTER_NVML *nvmlGPUHandle = (HM_ADAPTER_NVML *) hccalloc (DEVICES_MAX, sizeof (HM_ADAPTER_NVML));

      int tmp_in = hm_get_adapter_index_nvml (hashcat_ctx, nvmlGPUHandle);

      for (int backend_devices_idx = 0; backend_devices_idx < backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        if (device_param->is_cuda == true)
        {
          for (int i = 0; i < tmp_in; i++)
          {
            nvmlPciInfo_t pci;

            if (hm_NVML_nvmlDeviceGetPciInfo (hashcat_ctx, nvmlGPUHandle[i], &pci) == -1) continue;

            if ((device_param->pcie_bus      == pci.bus)
             && (device_param->pcie_device   == (pci.device >> 3))
             && (device_param->pcie_function == (pci.device & 7)))
            {
              const u32 device_id = device_param->device_id;

              hm_adapters_nvml[device_id].nvml = nvmlGPUHandle[i];

              hm_adapters_nvml[device_id].buslanes_get_supported            = true;
              hm_adapters_nvml[device_id].corespeed_get_supported           = true;
              hm_adapters_nvml[device_id].fanspeed_get_supported            = true;
              hm_adapters_nvml[device_id].memoryspeed_get_supported         = true;
              hm_adapters_nvml[device_id].temperature_get_supported         = true;
              hm_adapters_nvml[device_id].threshold_shutdown_get_supported  = true;
              hm_adapters_nvml[device_id].threshold_slowdown_get_supported  = true;
              hm_adapters_nvml[device_id].utilization_get_supported         = true;
              hm_adapters_nvml[device_id].memoryused_get_supported          = true;
              hm_adapters_nvml[device_id].power_get_supported               = true;
              hm_adapters_nvml[device_id].power_limit_get_supported         = true;
              hm_adapters_nvml[device_id].pcie_gen_get_supported            = true;
            }
          }
        }

        if (device_param->is_opencl == true)
        {
          if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

          if (device_param->opencl_device_vendor_id != VENDOR_ID_NV) continue;

          for (int i = 0; i < tmp_in; i++)
          {
            nvmlPciInfo_t pci;

            if (hm_NVML_nvmlDeviceGetPciInfo (hashcat_ctx, nvmlGPUHandle[i], &pci) == -1) continue;

            if ((device_param->pcie_bus      == pci.bus)
             && (device_param->pcie_device   == (pci.device >> 3))
             && (device_param->pcie_function == (pci.device & 7)))
            {
              const u32 device_id = device_param->device_id;

              hm_adapters_nvml[device_id].nvml = nvmlGPUHandle[i];

              hm_adapters_nvml[device_id].buslanes_get_supported            = true;
              hm_adapters_nvml[device_id].corespeed_get_supported           = true;
              hm_adapters_nvml[device_id].fanspeed_get_supported            = true;
              hm_adapters_nvml[device_id].memoryspeed_get_supported         = true;
              hm_adapters_nvml[device_id].temperature_get_supported         = true;
              hm_adapters_nvml[device_id].threshold_shutdown_get_supported  = true;
              hm_adapters_nvml[device_id].threshold_slowdown_get_supported  = true;
              hm_adapters_nvml[device_id].utilization_get_supported         = true;
              hm_adapters_nvml[device_id].memoryused_get_supported          = true;
              hm_adapters_nvml[device_id].power_get_supported               = true;
              hm_adapters_nvml[device_id].power_limit_get_supported         = true;
              hm_adapters_nvml[device_id].pcie_gen_get_supported            = true;
            }
          }
        }
      }

      hcfree (nvmlGPUHandle);
    }
  }
}

static void hwmon_ctx_init_nvapi (hashcat_ctx_t *hashcat_ctx, hm_attrs_t *hm_adapters_nvapi, int backend_devices_cnt)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->hm_nvapi)
  {
    if (hm_NvAPI_Initialize (hashcat_ctx) == 0)
    {
      HM_ADAPTER_NVAPI *nvGPUHandle = (HM_ADAPTER_NVAPI *) hccalloc (NVAPI_MAX_PHYSICAL_GPUS, sizeof (HM_ADAPTER_NVAPI));

      int tmp_in = hm_get_adapter_index_nvapi (hashcat_ctx, nvGPUHandle);

      for (int backend_devices_idx = 0; backend_devices_idx < backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        if (device_param->is_cuda == true)
        {
          for (int i = 0; i < tmp_in; i++)
          {
            NvU32 BusId     = 0;
            NvU32 BusSlotId = 0;

            if (hm_NvAPI_GPU_GetBusId (hashcat_ctx, nvGPUHandle[i], &BusId) == -1) continue;

            if (hm_NvAPI_GPU_GetBusSlotId (hashcat_ctx, nvGPUHandle[i], &BusSlotId) == -1) continue;

            if ((device_param->pcie_bus      == BusId)
             && (device_param->pcie_device   == (BusSlotId >> 3))
             && (device_param->pcie_function == (BusSlotId & 7)))
            {
              const u32 device_id = device_param->device_id;

              hm_adapters_nvapi[device_id].nvapi = nvGPUHandle[i];

              hm_adapters_nvapi[device_id].fanpolicy_get_supported  = true;
              hm_adapters_nvapi[device_id].throttle_get_supported   = true;
            }
          }
        }

        if (device_param->is_opencl == true)
        {
          if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

          if (device_param->opencl_device_vendor_id != VENDOR_ID_NV) continue;

          for (int i = 0; i < tmp_in; i++)
          {
            NvU32 BusId     = 0;
            NvU32 BusSlotId = 0;

            if (hm_NvAPI_GPU_GetBusId (hashcat_ctx, nvGPUHandle[i], &BusId) == -1) continue;

            if (hm_NvAPI_GPU_GetBusSlotId (hashcat_ctx, nvGPUHandle[i], &BusSlotId) == -1) continue;

            if ((device_param->pcie_bus      == BusId)
             && (device_param->pcie_device   == (BusSlotId >> 3))
             && (device_param->pcie_function == (BusSlotId & 7)))
            {
              const u32 device_id = device_param->device_id;

              hm_adapters_nvapi[device_id].nvapi = nvGPUHandle[i];

              hm_adapters_nvapi[device_id].fanpolicy_get_supported  = true;
              hm_adapters_nvapi[device_id].throttle_get_supported   = true;
            }
          }
        }
      }

      hcfree (nvGPUHandle);
    }
  }
}

static int hwmon_ctx_init_adl (hashcat_ctx_t *hashcat_ctx, hm_attrs_t *hm_adapters_adl, int backend_devices_cnt)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->hm_adl)
  {
    if (hm_ADL_Main_Control_Create (hashcat_ctx, ADL_Main_Memory_Alloc, 0) == 0)
    {
      // total number of adapters

      int tmp_in;

      if (get_adapters_num_adl (hashcat_ctx, &tmp_in) == -1) return -1;

      // adapter info

      LPAdapterInfo lpAdapterInfo = (LPAdapterInfo) hccalloc (tmp_in, sizeof (AdapterInfo));

      if (hm_ADL_Adapter_AdapterInfo_Get (hashcat_ctx, lpAdapterInfo, tmp_in * sizeof (AdapterInfo)) == -1) return -1;

      for (int backend_devices_idx = 0; backend_devices_idx < backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        if (device_param->is_cuda == true)
        {
          // nothing to do
        }

        if ((device_param->is_opencl == true) || (device_param->is_hip == true))
        {
          if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

          if ((device_param->opencl_device_vendor_id != VENDOR_ID_AMD) && (device_param->opencl_device_vendor_id != VENDOR_ID_AMD_USE_HIP)) continue;

          for (int i = 0; i < tmp_in; i++)
          {
            if ((device_param->pcie_bus      == lpAdapterInfo[i].iBusNumber)
             && (device_param->pcie_device   == (lpAdapterInfo[i].iDeviceNumber >> 3))
             && (device_param->pcie_function == (lpAdapterInfo[i].iDeviceNumber & 7)))
            {
              const u32 device_id = device_param->device_id;

              int od_supported = 0;
              int od_enabled   = 0;
              int od_version   = 0;

              hm_ADL2_Overdrive_Caps (hashcat_ctx, lpAdapterInfo[i].iAdapterIndex, &od_supported, &od_enabled, &od_version);

              if (od_version < 8) od_version = 5;

              hm_adapters_adl[device_id].od_version = od_version;

              hm_adapters_adl[device_id].adl = lpAdapterInfo[i].iAdapterIndex;

              hm_adapters_adl[device_id].buslanes_get_supported            = true;
              hm_adapters_adl[device_id].corespeed_get_supported           = true;
              hm_adapters_adl[device_id].fanspeed_get_supported            = true;
              hm_adapters_adl[device_id].fanpolicy_get_supported           = true;
              hm_adapters_adl[device_id].memoryspeed_get_supported         = true;
              hm_adapters_adl[device_id].temperature_get_supported         = true;
              hm_adapters_adl[device_id].threshold_slowdown_get_supported  = true;
              hm_adapters_adl[device_id].utilization_get_supported         = true;
              hm_adapters_adl[device_id].power_get_supported               = false;
            }
          }
        }
      }

      hcfree (lpAdapterInfo);
    }
  }

  return 0;
}

static void hwmon_ctx_init_sysfs_intelgpu (hashcat_ctx_t *hashcat_ctx, hm_attrs_t *hm_adapters_sysfs_intelgpu, int backend_devices_cnt)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->hm_sysfs_amdgpu || hwmon_ctx->hm_iokit)
  {
    for (int backend_devices_idx = 0; backend_devices_idx < backend_devices_cnt; backend_devices_idx++)
    {
      hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

      if (device_param->skipped == true) continue;

      if (device_param->is_opencl == true)
      {
        const u32 device_id = device_param->device_id;

        if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        if (hwmon_ctx->hm_sysfs_intelgpu)
        {
          hm_adapters_sysfs_intelgpu[device_id].buslanes_get_supported    = false;
          hm_adapters_sysfs_intelgpu[device_id].corespeed_get_supported   = false;
          hm_adapters_sysfs_intelgpu[device_id].fanspeed_get_supported    = true;
          hm_adapters_sysfs_intelgpu[device_id].fanpolicy_get_supported   = false;
          hm_adapters_sysfs_intelgpu[device_id].memoryspeed_get_supported = false;
          hm_adapters_sysfs_intelgpu[device_id].temperature_get_supported = true;
          hm_adapters_sysfs_intelgpu[device_id].utilization_get_supported = false;
          hm_adapters_sysfs_intelgpu[device_id].memoryused_get_supported  = false;
          hm_adapters_sysfs_intelgpu[device_id].power_get_supported       = false;
        }
      }
    }
  }
}

static void hwmon_ctx_init_sysfs_amdgpu_iokit (hashcat_ctx_t *hashcat_ctx, hm_attrs_t *hm_adapters_sysfs_amdgpu, hm_attrs_t *hm_adapters_iokit, int backend_devices_cnt)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->hm_sysfs_amdgpu || hwmon_ctx->hm_iokit || hwmon_ctx->hm_sysfs_intelgpu)
  {
    for (int backend_devices_idx = 0; backend_devices_idx < backend_devices_cnt; backend_devices_idx++)
    {
      hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

      if (device_param->skipped == true) continue;

      if (device_param->is_cuda == true)
      {
        // nothing to do
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        const u32 device_id = device_param->device_id;

        if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (hwmon_ctx->hm_iokit))
        {
          hm_adapters_iokit[device_id].buslanes_get_supported    = false;
          hm_adapters_iokit[device_id].corespeed_get_supported   = false;
          hm_adapters_iokit[device_id].fanspeed_get_supported    = true;
          hm_adapters_iokit[device_id].fanpolicy_get_supported   = false;
          hm_adapters_iokit[device_id].memoryspeed_get_supported = false;
          hm_adapters_iokit[device_id].temperature_get_supported = true;
          hm_adapters_iokit[device_id].utilization_get_supported = true;
          hm_adapters_iokit[device_id].power_get_supported       = true;
        }
      }
      #endif

      if ((device_param->is_opencl == true) || (device_param->is_hip == true))
      {
        const u32 device_id = device_param->device_id;

        if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (hwmon_ctx->hm_iokit))
        {
          hm_adapters_iokit[device_id].buslanes_get_supported    = false;
          hm_adapters_iokit[device_id].corespeed_get_supported   = false;
          hm_adapters_iokit[device_id].fanspeed_get_supported    = true;
          hm_adapters_iokit[device_id].fanpolicy_get_supported   = false;
          hm_adapters_iokit[device_id].memoryspeed_get_supported = false;
          hm_adapters_iokit[device_id].temperature_get_supported = true;
          hm_adapters_iokit[device_id].utilization_get_supported = true;
          hm_adapters_iokit[device_id].power_get_supported       = true;
        }

        if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        if (hwmon_ctx->hm_sysfs_amdgpu)
        {
          hm_adapters_sysfs_amdgpu[device_id].buslanes_get_supported    = true;
          hm_adapters_sysfs_amdgpu[device_id].corespeed_get_supported   = true;
          hm_adapters_sysfs_amdgpu[device_id].fanspeed_get_supported    = true;
          hm_adapters_sysfs_amdgpu[device_id].fanpolicy_get_supported   = true;
          hm_adapters_sysfs_amdgpu[device_id].memoryspeed_get_supported = true;
          hm_adapters_sysfs_amdgpu[device_id].temperature_get_supported = true;
          hm_adapters_sysfs_amdgpu[device_id].utilization_get_supported = true;
          hm_adapters_sysfs_amdgpu[device_id].memoryused_get_supported  = true;
          hm_adapters_sysfs_amdgpu[device_id].power_get_supported       = false;
        }
      }
    }
  }
}

static void hwmon_ctx_init_sysfs_cpu (hashcat_ctx_t *hashcat_ctx, hm_attrs_t *hm_adapters_sysfs_cpu, int backend_devices_cnt)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  hwmon_ctx_t   *hwmon_ctx   = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->hm_sysfs_cpu)
  {
    for (int backend_devices_idx = 0; backend_devices_idx < backend_devices_cnt; backend_devices_idx++)
    {
      hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

      if (device_param->skipped == true) continue;

      if (device_param->is_cuda == true)
      {
          // nothing to do
      }

      if ((device_param->is_opencl == true) || (device_param->is_hip == true))
      {
        const u32 device_id = device_param->device_id;

        if ((device_param->opencl_device_type & CL_DEVICE_TYPE_CPU) == 0) continue;

        if (hwmon_ctx->hm_sysfs_cpu)
        {
          hm_adapters_sysfs_cpu[device_id].buslanes_get_supported    = false;
          hm_adapters_sysfs_cpu[device_id].corespeed_get_supported   = false;
          hm_adapters_sysfs_cpu[device_id].fanspeed_get_supported    = false;
          hm_adapters_sysfs_cpu[device_id].fanpolicy_get_supported   = false;
          hm_adapters_sysfs_cpu[device_id].memoryspeed_get_supported = false;
          hm_adapters_sysfs_cpu[device_id].temperature_get_supported = true;
          hm_adapters_sysfs_cpu[device_id].utilization_get_supported = true;
          hm_adapters_sysfs_cpu[device_id].power_get_supported       = false;
        }
      }
    }
  }
}

int hwmon_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t    *hwmon_ctx    = hashcat_ctx->hwmon_ctx;
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  hwmon_ctx->enabled = false;

  // Every device is probed and filled, including the clones that share hardware with an earlier one.
  // The probes match on PCI address and write to a slot keyed by device, so running them again for a
  // clone writes the same handle to that clone's slot. Repeating them costs a little work once, at
  // startup, and it means every device can be asked for its readings later.
  //
  // Collapsing the display is a separate job, and it belongs to the display. hm_is_hwmon_group_leader
  // decides which device carries the line for its hardware.

  int backend_devices_cnt = backend_ctx->backend_devices_cnt;

  //#if !defined (WITH_HWMON)
  //return 0;
  //#endif // WITH_HWMON

  if (user_options->usage          > 0)     return 0;
  if (user_options->hash_info      > 0)     return 0;
  //if (user_options->backend_info   > 0)     return 0;

  if (user_options->keyspace      == true)  return 0;
  if (user_options->left          == true)  return 0;
  if (user_options->show          == true)  return 0;
  if (user_options->stdout_flag   == true)  return 0;
  if (user_options->version       == true)  return 0;
  if (user_options->identify      == true)  return 0;
  if (user_options->hwmon         == false) return 0;

  hwmon_ctx->hm_device = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  /**
   * Initialize shared libraries
   */

  hm_attrs_t *hm_adapters_adl             = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvapi           = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_nvml            = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_sysfs_amdgpu    = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_sysfs_intelgpu  = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_sysfs_cpu       = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));
  hm_attrs_t *hm_adapters_iokit           = (hm_attrs_t *) hccalloc (DEVICES_MAX, sizeof (hm_attrs_t));

  if (backend_ctx->need_nvml == true)
  {
    hwmon_ctx->hm_nvml = (NVML_PTR *) hcmalloc (sizeof (NVML_PTR));

    if (nvml_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_nvml);

      hwmon_ctx->hm_nvml = NULL;
    }
  }

  if ((backend_ctx->need_nvapi == true) && (hwmon_ctx->hm_nvml)) // nvapi can't work alone, we need nvml, too
  {
    hwmon_ctx->hm_nvapi = (NVAPI_PTR *) hcmalloc (sizeof (NVAPI_PTR));

    if (nvapi_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_nvapi);

      hwmon_ctx->hm_nvapi = NULL;
    }
  }

  if (backend_ctx->need_adl == true)
  {
    hwmon_ctx->hm_adl = (ADL_PTR *) hcmalloc (sizeof (ADL_PTR));

    if (adl_init (hashcat_ctx) == -1)
    {
      hcfree (hwmon_ctx->hm_adl);

      hwmon_ctx->hm_adl = NULL;
    }
  }

  if (backend_ctx->need_sysfs_amdgpu == true)
  {
    hwmon_ctx->hm_sysfs_amdgpu = (SYSFS_AMDGPU_PTR *) hcmalloc (sizeof (SYSFS_AMDGPU_PTR));

    if (sysfs_amdgpu_init (hashcat_ctx) == false)
    {
      hcfree (hwmon_ctx->hm_sysfs_amdgpu);

      hwmon_ctx->hm_sysfs_amdgpu = NULL;
    }
  }

  if (backend_ctx->need_sysfs_intelgpu == true)
  {
    hwmon_ctx->hm_sysfs_intelgpu = (SYSFS_INTELGPU_PTR *) hcmalloc (sizeof (SYSFS_INTELGPU_PTR));

    if (sysfs_intelgpu_init (hashcat_ctx) == false)
    {
      hcfree (hwmon_ctx->hm_sysfs_intelgpu);

      hwmon_ctx->hm_sysfs_intelgpu = NULL;
    }
  }

  if (backend_ctx->need_sysfs_cpu == true)
  {
    hwmon_ctx->hm_sysfs_cpu = (SYSFS_CPU_PTR *) hcmalloc (sizeof (SYSFS_CPU_PTR));

    if (sysfs_cpu_init (hashcat_ctx) == false)
    {
      hcfree (hwmon_ctx->hm_sysfs_cpu);

      hwmon_ctx->hm_sysfs_cpu = NULL;
    }
  }

  #if defined (__APPLE__)
  if (backend_ctx->need_iokit == true)
  {
    hwmon_ctx->hm_iokit = (IOKIT_PTR *) hcmalloc (sizeof (IOKIT_PTR));

    if (iokit_init (hashcat_ctx) == false)
    {
      hcfree (hwmon_ctx->hm_iokit);

      hwmon_ctx->hm_iokit = NULL;
    }
  }
  #endif

  hwmon_ctx_init_nvml  (hashcat_ctx, hm_adapters_nvml,  backend_devices_cnt);

  hwmon_ctx_init_nvapi (hashcat_ctx, hm_adapters_nvapi, backend_devices_cnt);

  // if ADL init fail, disable

  if (hwmon_ctx_init_adl (hashcat_ctx, hm_adapters_adl, backend_devices_cnt) == -1)
  {
    hcfree (hwmon_ctx->hm_adl);

    hwmon_ctx->hm_adl = NULL;
  }

  // if there's ADL, we don't need sysfs_amdgpu

  if (hwmon_ctx->hm_adl)
  {
    hcfree (hwmon_ctx->hm_sysfs_amdgpu);

    hwmon_ctx->hm_sysfs_amdgpu = NULL;
  }

  hwmon_ctx_init_sysfs_amdgpu_iokit (hashcat_ctx, hm_adapters_sysfs_amdgpu, hm_adapters_iokit, backend_devices_cnt);

  hwmon_ctx_init_sysfs_intelgpu (hashcat_ctx, hm_adapters_sysfs_intelgpu, backend_devices_cnt);

  hwmon_ctx_init_sysfs_cpu (hashcat_ctx, hm_adapters_sysfs_cpu, backend_devices_cnt);

  #if defined (__APPLE__)
  if (backend_ctx->need_iokit == true)
  {
    hwmon_ctx->hm_iokit = (IOKIT_PTR *) hcmalloc (sizeof (IOKIT_PTR));

    if (iokit_init (hashcat_ctx) == false)
    {
      hcfree (hwmon_ctx->hm_iokit);

      hwmon_ctx->hm_iokit = NULL;
    }
  }
  #endif

  if (hwmon_ctx->hm_adl == NULL && hwmon_ctx->hm_nvml == NULL && hwmon_ctx->hm_sysfs_amdgpu == NULL && hwmon_ctx->hm_sysfs_intelgpu == NULL && hwmon_ctx->hm_sysfs_cpu == NULL && hwmon_ctx->hm_iokit == NULL)
  {
    hcfree (hm_adapters_adl);
    hcfree (hm_adapters_nvapi);
    hcfree (hm_adapters_nvml);
    hcfree (hm_adapters_sysfs_amdgpu);
    hcfree (hm_adapters_sysfs_intelgpu);
    hcfree (hm_adapters_sysfs_cpu);
    hcfree (hm_adapters_iokit);

    return 0;
  }

  /**
   * looks like we have some manageable device
   */

  hwmon_ctx->enabled = true;

  /**
   * HM devices: copy
   */

  for (int backend_devices_idx = 0; backend_devices_idx < backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;

    const u32 device_id = device_param->device_id;

    hwmon_ctx->hm_device[backend_devices_idx].adl             = 0;
    hwmon_ctx->hm_device[backend_devices_idx].sysfs_amdgpu    = 0;
    hwmon_ctx->hm_device[backend_devices_idx].sysfs_intelgpu  = 0;
    hwmon_ctx->hm_device[backend_devices_idx].sysfs_cpu       = 0;
    hwmon_ctx->hm_device[backend_devices_idx].iokit           = 0;
    hwmon_ctx->hm_device[backend_devices_idx].nvapi           = 0;
    hwmon_ctx->hm_device[backend_devices_idx].nvml            = 0;
    hwmon_ctx->hm_device[backend_devices_idx].od_version      = 0;

    if (device_param->is_cuda == true)
    {
      hwmon_ctx->hm_device[backend_devices_idx].nvapi       = hm_adapters_nvapi[device_id].nvapi;
      hwmon_ctx->hm_device[backend_devices_idx].nvml        = hm_adapters_nvml[device_id].nvml;

      if (hwmon_ctx->hm_nvml)
      {
        hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_nvml[device_id].buslanes_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_nvml[device_id].corespeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_nvml[device_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_nvml[device_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_nvml[device_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_nvml[device_id].temperature_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_nvml[device_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_nvml[device_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_nvml[device_id].throttle_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_nvml[device_id].utilization_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].memoryused_get_supported          |= hm_adapters_nvml[device_id].memoryused_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_nvml[device_id].power_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].power_limit_get_supported         |= hm_adapters_nvml[device_id].power_limit_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].pcie_gen_get_supported            |= hm_adapters_nvml[device_id].pcie_gen_get_supported;
      }

      if (hwmon_ctx->hm_nvapi)
      {
        hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_nvapi[device_id].buslanes_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_nvapi[device_id].corespeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_nvapi[device_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_nvapi[device_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_nvapi[device_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_nvapi[device_id].temperature_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_nvapi[device_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_nvapi[device_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_nvapi[device_id].throttle_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_nvapi[device_id].utilization_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_nvapi[device_id].power_get_supported;
      }
    }

    if (device_param->is_metal == true)
    {
      if (hwmon_ctx->hm_iokit)
      {
        hwmon_ctx->hm_device[backend_devices_idx].iokit                              = hm_adapters_iokit[device_id].iokit;
        hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_iokit[device_id].buslanes_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_iokit[device_id].corespeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_iokit[device_id].fanspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_iokit[device_id].fanpolicy_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_iokit[device_id].memoryspeed_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_iokit[device_id].temperature_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_iokit[device_id].threshold_shutdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_iokit[device_id].threshold_slowdown_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_iokit[device_id].throttle_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_iokit[device_id].utilization_get_supported;
        hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_iokit[device_id].power_get_supported;
      }
    }

    if ((device_param->is_opencl == true) || (device_param->is_hip == true))
    {
      if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
      {
        #if defined (__APPLE__)
        if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
        {
          if (hwmon_ctx->hm_iokit)
          {
            hwmon_ctx->hm_device[backend_devices_idx].iokit                              = hm_adapters_iokit[device_id].iokit;
            hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_iokit[device_id].buslanes_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_iokit[device_id].corespeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_iokit[device_id].fanspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_iokit[device_id].fanpolicy_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_iokit[device_id].memoryspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_iokit[device_id].temperature_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_iokit[device_id].threshold_shutdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_iokit[device_id].threshold_slowdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_iokit[device_id].throttle_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_iokit[device_id].utilization_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_iokit[device_id].power_get_supported;
          }
        }
        #endif

        if (hwmon_ctx->hm_sysfs_cpu)
        {
          hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_sysfs_cpu[device_id].buslanes_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_sysfs_cpu[device_id].corespeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_sysfs_cpu[device_id].fanspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_sysfs_cpu[device_id].fanpolicy_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_sysfs_cpu[device_id].memoryspeed_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_sysfs_cpu[device_id].temperature_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_sysfs_cpu[device_id].threshold_shutdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_sysfs_cpu[device_id].threshold_slowdown_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_sysfs_cpu[device_id].throttle_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_sysfs_cpu[device_id].utilization_get_supported;
          hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_sysfs_cpu[device_id].power_get_supported;
        }
      }

      if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
      {
        #if defined (__APPLE__)
        if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
        {
          if (hwmon_ctx->hm_iokit)
          {
            hwmon_ctx->hm_device[backend_devices_idx].iokit                              = hm_adapters_iokit[device_id].iokit;
            hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_iokit[device_id].buslanes_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_iokit[device_id].corespeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_iokit[device_id].fanspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_iokit[device_id].fanpolicy_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_iokit[device_id].memoryspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_iokit[device_id].temperature_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_iokit[device_id].threshold_shutdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_iokit[device_id].threshold_slowdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_iokit[device_id].throttle_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_iokit[device_id].utilization_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_iokit[device_id].power_get_supported;
          }
        }
        #endif

        if (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK)
        {
          hwmon_ctx->hm_device[backend_devices_idx].sysfs_intelgpu  = hm_adapters_sysfs_amdgpu[device_id].sysfs_intelgpu;

          if (hwmon_ctx->hm_sysfs_intelgpu)
          {
            //hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_sysfs_intelgpu[device_id].buslanes_get_supported;
            //hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_sysfs_intelgpu[device_id].corespeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_sysfs_intelgpu[device_id].fanspeed_get_supported;
            //hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_sysfs_intelgpu[device_id].fanpolicy_get_supported;
            //hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_sysfs_intelgpu[device_id].memoryspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_sysfs_intelgpu[device_id].temperature_get_supported;
            //hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_sysfs_intelgpu[device_id].threshold_shutdown_get_supported;
            //hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_sysfs_intelgpu[device_id].threshold_slowdown_get_supported;
            //hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_sysfs_intelgpu[device_id].throttle_get_supported;
            //hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_sysfs_intelgpu[device_id].utilization_get_supported;
            //hwmon_ctx->hm_device[backend_devices_idx].memoryused_get_supported          |= hm_adapters_sysfs_intelgpu[device_id].memoryused_get_supported;
          }
        }

        if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) || (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
        {
          hwmon_ctx->hm_device[backend_devices_idx].adl           = hm_adapters_adl[device_id].adl;
          hwmon_ctx->hm_device[backend_devices_idx].sysfs_amdgpu  = hm_adapters_sysfs_amdgpu[device_id].sysfs_amdgpu;

          if (hwmon_ctx->hm_adl)
          {
            hwmon_ctx->hm_device[backend_devices_idx].od_version = hm_adapters_adl[device_id].od_version;

            hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_adl[device_id].buslanes_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_adl[device_id].corespeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_adl[device_id].fanspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_adl[device_id].fanpolicy_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_adl[device_id].memoryspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_adl[device_id].temperature_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_adl[device_id].threshold_shutdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_adl[device_id].threshold_slowdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_adl[device_id].throttle_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_adl[device_id].utilization_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_adl[device_id].power_get_supported;
          }

          if (hwmon_ctx->hm_sysfs_amdgpu)
          {
            hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_sysfs_amdgpu[device_id].buslanes_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_sysfs_amdgpu[device_id].corespeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_sysfs_amdgpu[device_id].fanspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_sysfs_amdgpu[device_id].fanpolicy_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_sysfs_amdgpu[device_id].memoryspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_sysfs_amdgpu[device_id].temperature_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_sysfs_amdgpu[device_id].threshold_shutdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_sysfs_amdgpu[device_id].threshold_slowdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_sysfs_amdgpu[device_id].throttle_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_sysfs_amdgpu[device_id].utilization_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].memoryused_get_supported          |= hm_adapters_sysfs_amdgpu[device_id].memoryused_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_sysfs_amdgpu[device_id].power_get_supported;
          }
        }

        if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
        {
          hwmon_ctx->hm_device[backend_devices_idx].nvapi       = hm_adapters_nvapi[device_id].nvapi;
          hwmon_ctx->hm_device[backend_devices_idx].nvml        = hm_adapters_nvml[device_id].nvml;

          if (hwmon_ctx->hm_nvml)
          {
            hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_nvml[device_id].buslanes_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_nvml[device_id].corespeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_nvml[device_id].fanspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_nvml[device_id].fanpolicy_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_nvml[device_id].memoryspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_nvml[device_id].temperature_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_nvml[device_id].threshold_shutdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_nvml[device_id].threshold_slowdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_nvml[device_id].throttle_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_nvml[device_id].utilization_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].memoryused_get_supported          |= hm_adapters_nvml[device_id].memoryused_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_nvml[device_id].power_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].power_limit_get_supported         |= hm_adapters_nvml[device_id].power_limit_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].pcie_gen_get_supported            |= hm_adapters_nvml[device_id].pcie_gen_get_supported;
          }

          if (hwmon_ctx->hm_nvapi)
          {
            hwmon_ctx->hm_device[backend_devices_idx].buslanes_get_supported            |= hm_adapters_nvapi[device_id].buslanes_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].corespeed_get_supported           |= hm_adapters_nvapi[device_id].corespeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanspeed_get_supported            |= hm_adapters_nvapi[device_id].fanspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].fanpolicy_get_supported           |= hm_adapters_nvapi[device_id].fanpolicy_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].memoryspeed_get_supported         |= hm_adapters_nvapi[device_id].memoryspeed_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].temperature_get_supported         |= hm_adapters_nvapi[device_id].temperature_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_shutdown_get_supported  |= hm_adapters_nvapi[device_id].threshold_shutdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].threshold_slowdown_get_supported  |= hm_adapters_nvapi[device_id].threshold_slowdown_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].throttle_get_supported            |= hm_adapters_nvapi[device_id].throttle_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].utilization_get_supported         |= hm_adapters_nvapi[device_id].utilization_get_supported;
            hwmon_ctx->hm_device[backend_devices_idx].power_get_supported               |= hm_adapters_nvapi[device_id].power_get_supported;
          }
        }
      }
    }

    // by calling the different functions here this will disable them in case they will error out
    // this will also reduce the error itself printed to the user to a single print on startup

    hm_get_buslanes_with_devices_idx           (hashcat_ctx, backend_devices_idx);
    hm_get_corespeed_with_devices_idx          (hashcat_ctx, backend_devices_idx);
    hm_get_fanpolicy_with_devices_idx          (hashcat_ctx, backend_devices_idx);
    hm_get_fanspeed_with_devices_idx           (hashcat_ctx, backend_devices_idx);
    hm_get_memoryspeed_with_devices_idx        (hashcat_ctx, backend_devices_idx);
    hm_get_temperature_with_devices_idx        (hashcat_ctx, backend_devices_idx);
    hm_get_threshold_shutdown_with_devices_idx (hashcat_ctx, backend_devices_idx);
    hm_get_threshold_slowdown_with_devices_idx (hashcat_ctx, backend_devices_idx);
    hm_get_throttle_with_devices_idx           (hashcat_ctx, backend_devices_idx);
    hm_get_utilization_with_devices_idx        (hashcat_ctx, backend_devices_idx);
    hm_get_memoryused_with_devices_idx         (hashcat_ctx, backend_devices_idx);
    hm_get_power_with_devices_idx              (hashcat_ctx, backend_devices_idx);
  }

  hcfree (hm_adapters_adl);
  hcfree (hm_adapters_nvapi);
  hcfree (hm_adapters_nvml);
  hcfree (hm_adapters_sysfs_amdgpu);
  hcfree (hm_adapters_sysfs_intelgpu);
  hcfree (hm_adapters_sysfs_cpu);
  hcfree (hm_adapters_iokit);

  return 0;
}

void hwmon_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hwmon_ctx_t *hwmon_ctx = hashcat_ctx->hwmon_ctx;

  if (hwmon_ctx->enabled == false) return;

  // unload shared libraries

  if (hwmon_ctx->hm_nvml)
  {
    hm_NVML_nvmlShutdown (hashcat_ctx);

    nvml_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_nvapi)
  {
    hm_NvAPI_Unload (hashcat_ctx);

    nvapi_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_adl)
  {
    hm_ADL_Main_Control_Destroy (hashcat_ctx);

    adl_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_sysfs_amdgpu)
  {
    sysfs_amdgpu_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_sysfs_intelgpu)
  {
    sysfs_intelgpu_close (hashcat_ctx);
  }

  if (hwmon_ctx->hm_sysfs_cpu)
  {
    sysfs_cpu_close (hashcat_ctx);
  }

  #if defined (__APPLE__)
  if (hwmon_ctx->hm_iokit)
  {
    iokit_close (hashcat_ctx);
  }
  #endif

  // free memory

  hcfree (hwmon_ctx->hm_device);

  memset (hwmon_ctx, 0, sizeof (hwmon_ctx_t));
}

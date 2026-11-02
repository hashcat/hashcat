/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bridges.h"
#include "memory.h"
#include "shared.h"
#include "event.h"

#include <time.h>

#if defined (_WIN)
#include <windows.h>
#endif

static const u32 PHANTOM_UNITS = 64;

static const u32 PHANTOM_CORES = 496;

static const u32 PHANTOM_CAPACITY = 32736;

static const u32 PHANTOM_WAVE_US = 4036;

static const u32 PHANTOM_FIXED_US = 1750;

static const u32 PHANTOM_DIGEST[6] = { 0xcb7e2934, 0xbbeb274f, 0x0529c580, 0x2c2a6c2d, 0x615abab2, 0x44010c00 };

static const u32 PHANTOM_FAIL_UNIT = 0;

static const u32 PHANTOM_FAIL_AFTER = 4;

#define PHANTOM_MAX_UNITS 256

typedef struct bcrypt_bridge_tmp
{
  u32 pw_len;

  u32 pw_buf[18];

  u32 digest[6];

} bcrypt_bridge_tmp_t;

typedef struct phantom
{
  int units_cnt;

  u32 cores;
  u32 capacity;
  u32 wave_us;
  u32 fixed_us;

  bool nosleep;

  u32 fail_unit;
  u32 fail_after;

  u32 launches[PHANTOM_MAX_UNITS];

  char unit_info[PHANTOM_MAX_UNITS][128];

  char unit_class[128];

} phantom_t;

static u32 env_u32 (const char *name, const u32 fallback)
{
  const char *env = getenv (name);

  if (env == NULL) return fallback;

  const int n = atoi (env);

  if (n <= 0) return fallback;

  const u32 result = (u32) n;

  return result;
}

void *platform_init (hashcat_ctx_t *hashcat_ctx)
{
  phantom_t *ctx = (phantom_t *) hcmalloc (sizeof (phantom_t));

  if (ctx == NULL) return NULL;

  ctx->units_cnt = (int) MIN (env_u32 ("HCPHANTOM_UNITS", PHANTOM_UNITS), PHANTOM_MAX_UNITS);

  ctx->cores    = env_u32 ("HCPHANTOM_CORES",    PHANTOM_CORES);
  ctx->capacity = env_u32 ("HCPHANTOM_CAPACITY", PHANTOM_CAPACITY);
  ctx->wave_us  = env_u32 ("HCPHANTOM_WAVE_US",  PHANTOM_WAVE_US);

  ctx->fixed_us = env_u32 ("HCPHANTOM_FIXED_US", PHANTOM_FIXED_US);

  ctx->nosleep = (getenv ("HCPHANTOM_NOSLEEP") != NULL) ? true : false;

  ctx->fail_unit  = env_u32 ("HCPHANTOM_FAIL_UNIT",  PHANTOM_FAIL_UNIT);
  ctx->fail_after = env_u32 ("HCPHANTOM_FAIL_AFTER", PHANTOM_FAIL_AFTER);

  for (int i = 0; i < ctx->units_cnt; i++) ctx->launches[i] = 0;

  for (int i = 0; i < ctx->units_cnt; i++)
  {
    snprintf (ctx->unit_info[i], sizeof (ctx->unit_info[i]), "phantom board #%02d, %u cores", i + 1, ctx->cores);
  }

  snprintf (ctx->unit_class, sizeof (ctx->unit_class), "phantom, %u cores, %u us per wave, %u us fixed", ctx->cores, ctx->wave_us, ctx->fixed_us);

  event_log_warning (hashcat_ctx, "PHANTOM BRIDGE: %d simulated boards, %u cores, %u us per wave plus %u us per launch.", ctx->units_cnt, ctx->cores, ctx->wave_us, ctx->fixed_us);
  event_log_warning (hashcat_ctx, "This simulator computes no hashes; it measures the host workload for the configured fleet.");

  if (ctx->fail_unit > 0)
  {
    event_log_warning (hashcat_ctx, "Unit #%02d will fail after %u launches.", ctx->fail_unit, ctx->fail_after);
  }

  event_log_warning (hashcat_ctx, NULL);

  return ctx;
}

void platform_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  if (platform_context == NULL) return;

  hcfree (platform_context);
}

int get_unit_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  phantom_t *ctx = platform_context;

  return ctx->units_cnt;
}

int get_workitem_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, MAYBE_UNUSED const int unit_idx)
{
  phantom_t *ctx = platform_context;

  return (int) ctx->capacity;
}

int get_workitem_multiple (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, MAYBE_UNUSED const int unit_idx)
{
  phantom_t *ctx = platform_context;

  return (int) ctx->cores;
}

char *get_unit_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  phantom_t *ctx = platform_context;

  return ctx->unit_info[unit_idx];
}

char *get_unit_class (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, MAYBE_UNUSED const int unit_idx)
{
  phantom_t *ctx = platform_context;

  return ctx->unit_class;
}

bool launch_loop (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, hashes_t *hashes, const u32 salt_pos, const u64 pws_cnt)
{
  phantom_t *ctx = platform_context;

  bcrypt_bridge_tmp_t *tmps = (bcrypt_bridge_tmp_t *) device_param->h_tmps;

  const salt_t *salt = &hashes->salts_buf[salt_pos];

  const u64 loop_end = MIN ((u64) device_param->kernel_param.loop_pos + device_param->kernel_param.loop_cnt, (u64) salt->salt_iter);
  const u64 loop_pos = MIN ((u64) device_param->kernel_param.loop_pos, loop_end);

  const u64 pw_from = (pws_cnt * loop_pos) / salt->salt_iter;
  const u64 pw_to   = (pws_cnt * loop_end) / salt->salt_iter;

  const u64 pw_cnt = pw_to - pw_from;

  if (pw_cnt == 0) return true;

  const int unit_idx = device_param->bridge_link_device;

  if (ctx->fail_unit == (u32) (unit_idx + 1))
  {
    ctx->launches[unit_idx]++;

    if (ctx->launches[unit_idx] > ctx->fail_after)
    {
      event_log_error (hashcat_ctx, "PHANTOM BRIDGE: injected failure on unit #%02d; it will accept no more work.", unit_idx + 1);

      return false;
    }
  }

  const u64 waves = (pw_cnt + ctx->cores - 1) / ctx->cores;

  if (ctx->nosleep == false)
  {
    const u64 sleep_ns = ((waves * (u64) ctx->wave_us) + ctx->fixed_us) * 1000ull;

    #if defined (_WIN)

    const u64 sleep_ms = sleep_ns / 1000000ull;

    Sleep ((DWORD) ((sleep_ms == 0) ? 1 : sleep_ms));

    #else

    struct timespec ts;

    ts.tv_sec  = (time_t) (sleep_ns / 1000000000ull);
    ts.tv_nsec = (long)   (sleep_ns % 1000000000ull);

    nanosleep (&ts, NULL);

    #endif
  }

  for (u64 i = pw_from; i < pw_to; i++)
  {
    for (u32 k = 0; k < 6; k++) tmps[i].digest[k] = PHANTOM_DIGEST[k];
  }

  return true;
}

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  bridge_ctx->bridge_context_size       = BRIDGE_CONTEXT_SIZE_CURRENT;
  bridge_ctx->bridge_interface_version  = BRIDGE_INTERFACE_VERSION_CURRENT;

  bridge_ctx->platform_init         = platform_init;
  bridge_ctx->platform_term         = platform_term;
  bridge_ctx->get_unit_count        = get_unit_count;
  bridge_ctx->get_unit_info         = get_unit_info;
  bridge_ctx->get_unit_class        = get_unit_class;
  bridge_ctx->get_workitem_count    = get_workitem_count;
  bridge_ctx->get_workitem_multiple = get_workitem_multiple;
  bridge_ctx->get_unit_tuning       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_member_count = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_member_info  = BRIDGE_DEFAULT;
  bridge_ctx->salt_prepare          = BRIDGE_DEFAULT;
  bridge_ctx->salt_destroy          = BRIDGE_DEFAULT;
  bridge_ctx->thread_init           = BRIDGE_DEFAULT;
  bridge_ctx->thread_term           = BRIDGE_DEFAULT;
  bridge_ctx->launch_loop           = launch_loop;
  bridge_ctx->launch_loop2          = BRIDGE_DEFAULT;
  bridge_ctx->st_update_hash        = BRIDGE_DEFAULT;
  bridge_ctx->st_update_pass        = BRIDGE_DEFAULT;

  bridge_ctx->get_unit_temperature           = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_str       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_abort     = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_unwatched = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_buslanes_str          = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_fanspeed              = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_utilization           = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_corespeed             = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_memoryspeed           = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_buslanes              = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_power                 = BRIDGE_DEFAULT;
}

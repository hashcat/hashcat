/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bridges.h"
#include "memory.h"
#include "shared.h"
#include "system.h"
#include "cpu_features.h"

#include "code/scrypt-jane-portable.h"
#include "code/scrypt-jane-hash.h"
#include "code/scrypt-jane-romix.h"

// good: we can use this multiplier do reduce copy overhead to increase the guessing speed,
// bad: but we also increase the password candidate batch size.
// slow hashes which make use of this bridge probably are used with smaller wordlists,
// and therefore it's easier for hashcat to parallelize if this multiplier is low.
// in the end, it's a trade-off.

#define N_ACCEL 8

#define SCRYPT_R_MAX 16
#define SCRYPT_P_MAX 16

#define SCRYPT_TMP_SIZE (128ULL * SCRYPT_R_MAX * SCRYPT_P_MAX)
#define SCRYPT_TMP_SIZE4 (SCRYPT_TMP_SIZE / 4)

typedef struct
{
  u32 P[SCRYPT_TMP_SIZE4];

} scrypt_tmp_t;

typedef struct
{
  void *V;
  //void *X;
  void *Y;

  // V and Y hold ROMix state that has to survive between chunks, so each candidate in a
  // launch needs its own. these are the per candidate strides into the two allocations.

  size_t V_stride;
  size_t Y_stride;

  // implementation specific

  char    unit_info_buf[1024];
  int     unit_info_len;

  u64     workitem_count;
  size_t  workitem_size;

} unit_t;

typedef struct
{
  unit_t *units_buf;
  int     units_cnt;

} bridge_scrypt_jane_t;

static bool units_init (bridge_scrypt_jane_t *bridge_scrypt_jane)
{
  #if defined (_WIN)

  SYSTEM_INFO sysinfo;

  GetSystemInfo (&sysinfo);

  int num_devices = sysinfo.dwNumberOfProcessors;

  #else

  int num_devices = sysconf (_SC_NPROCESSORS_ONLN);

  #endif

  unit_t *units_buf = (unit_t *) hccalloc (num_devices, sizeof (unit_t));

  int units_cnt = 0;

  for (int i = 0; i < num_devices; i++)
  {
    unit_t *unit_buf = &units_buf[i];

    unit_buf->unit_info_len = snprintf (unit_buf->unit_info_buf, sizeof (unit_buf->unit_info_buf) - 1,
      "%s",
      "Scrypt-Jane ROMix");

    unit_buf->unit_info_buf[unit_buf->unit_info_len] = 0;

    unit_buf->workitem_count = N_ACCEL;

    units_cnt++;
  }

  bridge_scrypt_jane->units_buf = units_buf;
  bridge_scrypt_jane->units_cnt = units_cnt;

  return true;
}

static void units_term (bridge_scrypt_jane_t *bridge_scrypt_jane)
{
  if (bridge_scrypt_jane)
  {
    hcfree (bridge_scrypt_jane->units_buf);
  }
}

void *platform_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  // Verify CPU features

  if (cpu_chipset_test () == -1) return NULL;

  // Allocate platform context

  bridge_scrypt_jane_t *bridge_scrypt_jane = (bridge_scrypt_jane_t *) hcmalloc (sizeof (bridge_scrypt_jane_t));

  if (units_init (bridge_scrypt_jane) == false)
  {
    hcfree (bridge_scrypt_jane);

    return NULL;
  }

  return bridge_scrypt_jane;
}

void platform_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  if (bridge_scrypt_jane)
  {
    units_term (bridge_scrypt_jane);

    hcfree (bridge_scrypt_jane);
  }
}

int get_unit_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  return bridge_scrypt_jane->units_cnt;
}

// we support units of mixed speed, that's why the workitem count is unit specific

int get_workitem_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

  return unit_buf->workitem_count;
}

// The multiple this bridge computes in.
//
// One unit here is one CPU thread working through its batch sequentially, so there is no width to fill
// and no partial wave to waste: a batch of N costs N hashes whatever N is. Parallelism is expressed as
// UNITS, not as width inside a unit, which is the structural difference from an accelerator that holds
// many cores behind a single unit.
int get_workitem_multiple (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED const int unit_idx)
{
  return 1;
}

char *get_unit_info (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

  return unit_buf->unit_info_buf;
}

bool salt_prepare (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  // selftest hash

  salt_t *scrypt_st = (salt_t *) hashes->st_salts_buf;

  const size_t chunk_bytes = 64 * 2 * scrypt_st->scrypt_r;

  size_t largest_V = chunk_bytes * scrypt_st->scrypt_N;
  //size_t largest_X = chunk_bytes * scrypt_st->scrypt_p;
  size_t largest_Y = chunk_bytes;

  // from here regular hashes

  salt_t *scrypt = (salt_t *) hashes->salts_buf;

  for (u32 salt_idx = 0; salt_idx < hashes->salts_cnt; salt_idx++, scrypt++)
  {
    const size_t chunk_bytes = 64 * 2 * scrypt->scrypt_r;

    const size_t sz_V = chunk_bytes * scrypt->scrypt_N;
    //const size_t sz_X = chunk_bytes * scrypt->scrypt_p;
    const size_t sz_Y = chunk_bytes;

    if (sz_V > largest_V) largest_V = sz_V;
    //if (sz_X > largest_X) largest_X = sz_X;
    if (sz_Y > largest_Y) largest_Y = sz_Y;
  }

  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  // How many candidates one launch carries. Now that V is per candidate rather than per unit,
  // the batch size costs real memory: 128 * r * N for every candidate, on every unit. So the
  // honest bound is what the host has free, not a fixed constant. N_ACCEL stays only as a
  // ceiling, so this can never end up slower than it was before.
  //
  // A quarter of free memory is the budget. hashcat still has its own host buffers to allocate
  // after this, and being wrong here costs the user an out of memory kill rather than a warning.

  u64 free_memory = 0;

  u64 workitem_count = N_ACCEL;

  if (get_free_memory (&free_memory) == true)
  {
    const u64 per_candidate = (u64) largest_V + (u64) largest_Y;

    const u64 budget = (free_memory / 4) / (u64) bridge_scrypt_jane->units_cnt;

    const u64 fits = budget / per_candidate;

    workitem_count = MAX (MIN (fits, (u64) N_ACCEL), 1);
  }

  for (int unit_idx = 0; unit_idx < bridge_scrypt_jane->units_cnt; unit_idx++)
  {
    unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

    unit_buf->workitem_count = workitem_count;

    unit_buf->V_stride = largest_V;
    unit_buf->Y_stride = largest_Y;

    unit_buf->V = hcmalloc_bridge_aligned (largest_V * workitem_count, 64);
    //unit_buf->X = hcmalloc_bridge_aligned (largest_X, 64);
    unit_buf->Y = hcmalloc_bridge_aligned (largest_Y * workitem_count, 64);

    if (unit_buf->V == NULL) return false;
    if (unit_buf->Y == NULL) return false;
  }

  return true;
}

void salt_destroy (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  for (int unit_idx = 0; unit_idx < bridge_scrypt_jane->units_cnt; unit_idx++)
  {
    unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

    hcfree_bridge_aligned (unit_buf->V);
    //hcfree_bridge_aligned (unit_buf->X);
    hcfree_bridge_aligned (unit_buf->Y);
  }
}

bool launch_loop (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

  salt_t *salts_buf = (salt_t *) hashes->salts_buf;

  salt_t *salt_buf = &salts_buf[salt_pos];

  scrypt_tmp_t *scrypt_tmp = (scrypt_tmp_t *) device_param->h_tmps;

  const u32 N = salt_buf->scrypt_N;
  const u32 r = salt_buf->scrypt_r;
  const u32 p = salt_buf->scrypt_p;

  const size_t chunk_bytes = 64 * 2 * r;

  // One ROMix takes 2N steps, N to fill V and N to mix. The p of them run back to back, so the
  // iteration space is p * 2N, which is what the module reports as salt_iter. hashcat hands us a
  // slice of that space and we advance every candidate through it by exactly that much.

  const u32 steps_per_romix = N * 2;

  const u32 loop_pos = (u32) device_param->kernel_param.loop_pos;
  const u32 loop_cnt = (u32) device_param->kernel_param.loop_cnt;

  // hashcat guarantees h_tmps[] is 64 byte aligned

  for (u64 pw_cnt = 0; pw_cnt < pws_cnt; pw_cnt++)
  {
    u8 *X = (u8 *) scrypt_tmp->P;

    u8 *V = (u8 *) unit_buf->V + (unit_buf->V_stride * pw_cnt);
    u8 *Y = (u8 *) unit_buf->Y + (unit_buf->Y_stride * pw_cnt);

    u32 pos  = loop_pos;
    u32 left = loop_cnt;

    // a slice can straddle the boundary between two consecutive ROMix runs, so walk it

    while (left)
    {
      const u32 romix_idx = pos / steps_per_romix;
      const u32 local_pos = pos % steps_per_romix;

      if (romix_idx >= p) break;

      const u32 take = MIN (left, steps_per_romix - local_pos);

      scrypt_ROMix_range ((scrypt_mix_word_t *) (X + (chunk_bytes * romix_idx)), (scrypt_mix_word_t *) Y, (scrypt_mix_word_t *) V, N, r, local_pos, take);

      pos  += take;
      left -= take;
    }

    scrypt_tmp++;
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
  bridge_ctx->get_workitem_count    = get_workitem_count;
  bridge_ctx->get_workitem_multiple = get_workitem_multiple;
  bridge_ctx->thread_init           = BRIDGE_DEFAULT;
  bridge_ctx->thread_term           = BRIDGE_DEFAULT;
  bridge_ctx->salt_prepare          = salt_prepare;
  bridge_ctx->salt_destroy          = salt_destroy;
  bridge_ctx->launch_loop           = launch_loop;
  bridge_ctx->launch_loop2          = BRIDGE_DEFAULT;
  bridge_ctx->st_update_hash        = BRIDGE_DEFAULT;
  bridge_ctx->st_update_pass        = BRIDGE_DEFAULT;

  bridge_ctx->get_unit_temperature       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_str   = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_abort = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_fanspeed          = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_utilization       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_corespeed         = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_memoryspeed       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_buslanes          = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_power             = BRIDGE_DEFAULT;
}

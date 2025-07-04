/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bridges.h"
#include "memory.h"
#include "shared.h"
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

void *platform_init ()
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

void platform_term (void *platform_context)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  if (bridge_scrypt_jane)
  {
    units_term (bridge_scrypt_jane);

    hcfree (bridge_scrypt_jane);
  }
}

int get_unit_count (void *platform_context)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  return bridge_scrypt_jane->units_cnt;
}

// we support units of mixed speed, that's why the workitem count is unit specific

int get_workitem_count (void *platform_context, const int unit_idx)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

  return unit_buf->workitem_count;
}

char *get_unit_info (void *platform_context, const int unit_idx)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

  return unit_buf->unit_info_buf;
}

bool salt_prepare (void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
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

  for (int unit_idx = 0; unit_idx < bridge_scrypt_jane->units_cnt; unit_idx++)
  {
    unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

    unit_buf->V = hcmalloc_aligned (largest_V, 64);
    //unit_buf->X = hcmalloc_aligned (largest_X, 64);
    unit_buf->Y = hcmalloc_aligned (largest_Y, 64);
  }

  return true;
}

void salt_destroy (void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  for (int unit_idx = 0; unit_idx < bridge_scrypt_jane->units_cnt; unit_idx++)
  {
    unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

    hcfree_aligned (unit_buf->V);
    //hcfree_aligned (unit_buf->X);
    hcfree_aligned (unit_buf->Y);
  }
}

bool launch_loop (MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  bridge_scrypt_jane_t *bridge_scrypt_jane = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &bridge_scrypt_jane->units_buf[unit_idx];

  salt_t *salts_buf = (salt_t *) hashes->salts_buf;

  salt_t *salt_buf = &salts_buf[salt_pos];

  scrypt_tmp_t *scrypt_tmp = (scrypt_tmp_t *) device_param->h_tmps;

	scrypt_mix_word_t *V = unit_buf->V;
	//scrypt_mix_word_t *X = unit_buf->X;
	scrypt_mix_word_t *Y = unit_buf->Y;

	const u32 N = salt_buf->scrypt_N;
	const u32 r = salt_buf->scrypt_r;
	const u32 p = salt_buf->scrypt_p;

	const size_t chunk_bytes = 64 * 2 * r;

  // hashcat guarantees h_tmps[] is 64 byte aligned

  for (u64 pw_cnt = 0; pw_cnt < pws_cnt; pw_cnt++)
  {
    u8 *X = (u8 *) scrypt_tmp->P;

    for (u32 i = 0; i < p; i++)
    {
      scrypt_ROMix ((scrypt_mix_word_t *) (X + (chunk_bytes * i)), (scrypt_mix_word_t *) Y, (scrypt_mix_word_t *) V, N, r);
    }

    scrypt_tmp++;
  }

  return true;
}

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  bridge_ctx->bridge_context_size       = BRIDGE_CONTEXT_SIZE_CURRENT;
  bridge_ctx->bridge_interface_version  = BRIDGE_INTERFACE_VERSION_CURRENT;

  bridge_ctx->platform_init       = platform_init;
  bridge_ctx->platform_term       = platform_term;
  bridge_ctx->get_unit_count      = get_unit_count;
  bridge_ctx->get_unit_info       = get_unit_info;
  bridge_ctx->get_workitem_count  = get_workitem_count;
  bridge_ctx->thread_init         = BRIDGE_DEFAULT;
  bridge_ctx->thread_term         = BRIDGE_DEFAULT;
  bridge_ctx->salt_prepare        = salt_prepare;
  bridge_ctx->salt_destroy        = salt_destroy;
  bridge_ctx->launch_loop         = launch_loop;
  bridge_ctx->launch_loop2        = BRIDGE_DEFAULT;
  bridge_ctx->st_update_hash      = BRIDGE_DEFAULT;
  bridge_ctx->st_update_pass      = BRIDGE_DEFAULT;
}

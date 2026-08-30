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

#include "yescrypt.h"

void smix(uint8_t *B, size_t r, uint32_t N, uint32_t p, uint32_t t,
          yescrypt_flags_t flags,
          void *V, uint32_t NROM, const void *VROM,
          void *XY, uint8_t *S, uint8_t *passwd);

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
  u32 B[SCRYPT_TMP_SIZE4];

} scrypt_tmp_t;

typedef struct
{
  void *V;
  void *XY;

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

} bridge_scrypt_yescrypt_t;

static bool units_init (bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt)
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
      "Scrypt-Yescrypt");

    unit_buf->unit_info_buf[unit_buf->unit_info_len] = 0;

    unit_buf->workitem_count = N_ACCEL;

    units_cnt++;
  }

  bridge_scrypt_yescrypt->units_buf = units_buf;
  bridge_scrypt_yescrypt->units_cnt = units_cnt;

  return true;
}

static void units_term (bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt)
{
  if (bridge_scrypt_yescrypt)
  {
    hcfree (bridge_scrypt_yescrypt->units_buf);
  }
}

void *platform_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  // Verify CPU features

  if (cpu_chipset_test () == -1) return NULL;

  // Allocate platform context

  bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt = (bridge_scrypt_yescrypt_t *) hcmalloc (sizeof (bridge_scrypt_yescrypt_t));

  if (units_init (bridge_scrypt_yescrypt) == false)
  {
    hcfree (bridge_scrypt_yescrypt);

    return NULL;
  }

  return bridge_scrypt_yescrypt;
}

void platform_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt = platform_context;

  if (bridge_scrypt_yescrypt)
  {
    units_term (bridge_scrypt_yescrypt);

    hcfree (bridge_scrypt_yescrypt);
  }
}

int get_unit_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt = platform_context;

  return bridge_scrypt_yescrypt->units_cnt;
}

// we support units of mixed speed, that's why the workitem count is unit specific

int get_workitem_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt = platform_context;

  unit_t *unit_buf = &bridge_scrypt_yescrypt->units_buf[unit_idx];

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
  bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt = platform_context;

  unit_t *unit_buf = &bridge_scrypt_yescrypt->units_buf[unit_idx];

  return unit_buf->unit_info_buf;
}

bool salt_prepare (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  // selftest hash

  salt_t *scrypt_st = (salt_t *) hashes->st_salts_buf;

  // The literal was an int and both operands are u32, so these products were evaluated in 32 bits
  // and a large N wrapped one before it ever reached the size_t it is assigned to. The buffer was
  // then allocated at the remainder and smix wrote the full 128rN bytes into it.

  size_t largest_V  = 128ULL * scrypt_st->scrypt_r * scrypt_st->scrypt_N; // yescrypt: the temporary storage V must be 128rN bytes in length
  size_t largest_XY = 256ULL * scrypt_st->scrypt_r * scrypt_st->scrypt_p; // yescrypt: the temporary storage XY must be 256r or 256rp bytes in length

  // from here regular hashes

  salt_t *scrypt = (salt_t *) hashes->salts_buf;

  for (u32 salt_idx = 0; salt_idx < hashes->salts_cnt; salt_idx++, scrypt++)
  {
    const size_t sz_V  = 128ULL * scrypt->scrypt_r * scrypt->scrypt_N; // yescrypt: the temporary storage V must be 128rN bytes in length
    const size_t sz_XY = 256ULL * scrypt->scrypt_r * scrypt->scrypt_p; // yescrypt: the temporary storage XY must be 256r or 256rp bytes in length

    if (sz_V  > largest_V)  largest_V  = sz_V;
    if (sz_XY > largest_XY) largest_XY = sz_XY;
  }

  bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt = platform_context;

  for (int unit_idx = 0; unit_idx < bridge_scrypt_yescrypt->units_cnt; unit_idx++)
  {
    unit_t *unit_buf = &bridge_scrypt_yescrypt->units_buf[unit_idx];

    unit_buf->V  = hcmalloc_bridge_aligned (largest_V,  64);
    unit_buf->XY = hcmalloc_bridge_aligned (largest_XY, 64);

    // A cost parameter out of a hash file decides both sizes, so the allocation can fail. Nothing
    // checked it, and smix wrote through the null pointer that came back.

    if (unit_buf->V  == NULL) return false;
    if (unit_buf->XY == NULL) return false;
  }

  return true;
}

void salt_destroy (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt = platform_context;

  for (int unit_idx = 0; unit_idx < bridge_scrypt_yescrypt->units_cnt; unit_idx++)
  {
    unit_t *unit_buf = &bridge_scrypt_yescrypt->units_buf[unit_idx];

    hcfree_bridge_aligned (unit_buf->V);
    hcfree_bridge_aligned (unit_buf->XY);
  }
}

bool launch_loop (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  bridge_scrypt_yescrypt_t *bridge_scrypt_yescrypt = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &bridge_scrypt_yescrypt->units_buf[unit_idx];

  salt_t *salts_buf = (salt_t *) hashes->salts_buf;

  salt_t *salt_buf = &salts_buf[salt_pos];

  // hashcat guarantees h_tmps[] is 64 byte aligned, so is *B

  scrypt_tmp_t *scrypt_tmp = (scrypt_tmp_t *) device_param->h_tmps;

  for (u64 pw_cnt = 0; pw_cnt < pws_cnt; pw_cnt++)
  {
    u8 *B = (u8 *) scrypt_tmp->B;

    // We could use p-based parallelization from yescrypt instead,
    // but since we're already multi-threading, there's no need to run OpenMP.
    // With that in mind, we can optimize by using a constant p=1,
    // allowing the compiler to eliminate branches in smix().

    for (u32 i = 0; i < salt_buf->scrypt_p; i++)
    {
      // Same here: using constants allows the compiler to optimize away branches in smix(),
      // so there's no need to call smix1()/smix2() directly and unnecessarily complicate the code.

      smix (B, salt_buf->scrypt_r, salt_buf->scrypt_N, 1, 0, 0, unit_buf->V, 0, NULL, unit_buf->XY, NULL, NULL);

      B += 128 * salt_buf->scrypt_r;
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

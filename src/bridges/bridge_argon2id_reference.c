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

// argon2 reference

#undef _DEFAULT_SOURCE

#include "argon2.c"
#include "core.c"
#include "blake2/blake2b.c"
#include "opt.c"

// good: we can use this multiplier do reduce copy overhead to increase the guessing speed,
// bad: but we also increase the password candidate batch size.
// slow hashes which make use of this bridge probably are used with smaller wordlists,
// and therefore it's easier for hashcat to parallelize if this multiplier is low.
// in the end, it's a trade-off.

#define N_ACCEL 8

typedef struct
{
  // input

  u32 pw_buf[64];
  u32 pw_len;

  // output

  u32 h[64];

} argon2_reference_tmp_t;

typedef struct
{
  u32 salt_buf[64];
  u32 salt_len;

  u32 digest_buf[64];
  u32 digest_len;

  u32 m;
  u32 t;
  u32 p;

} argon2_t;

typedef struct
{
  // template

  char    unit_info_buf[1024];
  int     unit_info_len;

  u64     workitem_count;
  size_t  workitem_size;

  // implementation specific

  void   *memory;

} unit_t;

typedef struct
{
  unit_t *units_buf;
  int     units_cnt;

} bridge_argon2id_t;

static bool units_init (bridge_argon2id_t *bridge_argon2id)
{
  #if defined (_WIN)

  SYSTEM_INFO sysinfo;

  GetSystemInfo (&sysinfo);

  int num_devices = sysinfo.dwNumberOfProcessors;

  #else

  int num_devices = sysconf (_SC_NPROCESSORS_ONLN);

  #endif

  // this works really good for me, I think is because of register pressure on SIMD enabled code
  num_devices /= 2;

  // this is just a wild guess, but memory bus will probably bottleneck if we
  // have too many cores using it. we set some upper limit which is not ideal, but good enough for now.
  //num_devices = MIN (num_devices, 8);

  unit_t *units_buf = (unit_t *) hccalloc (num_devices, sizeof (unit_t));

  int units_cnt = 0;

  for (int i = 0; i < num_devices; i++)
  {
    unit_t *unit_buf = &units_buf[i];

    unit_buf->unit_info_len = snprintf (unit_buf->unit_info_buf, sizeof (unit_buf->unit_info_buf) - 1,
      "%s",
      "Argon2 reference implementation + tunings");

    unit_buf->unit_info_buf[unit_buf->unit_info_len] = 0;

    unit_buf->workitem_count = N_ACCEL;

    units_cnt++;
  }

  bridge_argon2id->units_buf = units_buf;
  bridge_argon2id->units_cnt = units_cnt;

  return true;
}

static void units_term (bridge_argon2id_t *bridge_argon2id)
{
  if (bridge_argon2id->units_buf)
  {
    hcfree (bridge_argon2id->units_buf);
  }
}

void *platform_init ()
{
  // Verify CPU features

  if (cpu_chipset_test () == -1) return NULL;

  // Allocate platform context

  bridge_argon2id_t *bridge_argon2id = (bridge_argon2id_t *) hcmalloc (sizeof (bridge_argon2id_t));

  if (units_init (bridge_argon2id) == false)
  {
    hcfree (bridge_argon2id);

    return NULL;
  }

  return bridge_argon2id;
}

void platform_term (void *platform_context)
{
  bridge_argon2id_t *bridge_argon2id = platform_context;

  if (bridge_argon2id)
  {
    units_term (bridge_argon2id);

    hcfree (bridge_argon2id);
  }
}

int get_unit_count (void *platform_context)
{
  bridge_argon2id_t *bridge_argon2id = platform_context;

  return bridge_argon2id->units_cnt;
}

// we support units of mixed speed, that's why the workitem count is unit specific

int get_workitem_count (void *platform_context, const int unit_idx)
{
  bridge_argon2id_t *bridge_argon2id = platform_context;

  unit_t *unit_buf = &bridge_argon2id->units_buf[unit_idx];

  return unit_buf->workitem_count;
}

char *get_unit_info (void *platform_context, const int unit_idx)
{
  bridge_argon2id_t *bridge_argon2id = platform_context;

  unit_t *unit_buf = &bridge_argon2id->units_buf[unit_idx];

  return unit_buf->unit_info_buf;
}

bool salt_prepare (void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  // we can use self-test hash as base

  argon2_t *argon2_st = (argon2_t *) hashes->st_esalts_buf;

  size_t largest_m = argon2_st->m;

  // from here regular hashes

  argon2_t *argon2 = (argon2_t *) hashes->esalts_buf;

  for (u32 salt_idx = 0; salt_idx < hashes->salts_cnt; salt_idx++, argon2++)
  {
    if (argon2->m > largest_m) largest_m = argon2->m;
  }

  bridge_argon2id_t *bridge_argon2id = platform_context;

  for (int unit_idx = 0; unit_idx < bridge_argon2id->units_cnt; unit_idx++)
  {
    unit_t *unit_buf = &bridge_argon2id->units_buf[unit_idx];

    unit_buf->memory = hcmalloc_aligned ((largest_m * 1024), 32); // because AVX2
  }

  return true;
}

void salt_destroy (void *platform_context, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  bridge_argon2id_t *bridge_argon2id = platform_context;

  for (int unit_idx = 0; unit_idx < bridge_argon2id->units_cnt; unit_idx++)
  {
    unit_t *unit_buf = &bridge_argon2id->units_buf[unit_idx];

    hcfree_aligned (unit_buf->memory);
  }
}

bool launch_loop (MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  bridge_argon2id_t *bridge_argon2id = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &bridge_argon2id->units_buf[unit_idx];

  argon2_t *esalts_buf = (argon2_t *) hashes->esalts_buf;

  argon2_t *argon2id = &esalts_buf[salt_pos];

  argon2_reference_tmp_t *argon2_reference_tmp = (argon2_reference_tmp_t *) device_param->h_tmps;

  argon2_context context;

  context.out           = (uint8_t *) NULL;
  context.outlen        = (uint32_t)  0;
  context.pwd           = (uint8_t *) NULL;
  context.pwdlen        = (uint32_t)  0;
  context.salt          = (uint8_t *) argon2id->salt_buf;
  context.saltlen       = (uint32_t)  argon2id->salt_len;
  context.secret        = NULL;
  context.secretlen     = 0;
  context.ad            = NULL;
  context.adlen         = 0;
  context.t_cost        = argon2id->t;
  context.m_cost        = argon2id->m;
  context.lanes         = argon2id->p;
  context.threads       = 1;
  context.allocate_cbk  = NULL;
  context.free_cbk      = NULL;
  context.flags         = ARGON2_DEFAULT_FLAGS;
  context.version       = ARGON2_VERSION_NUMBER;
  context.memory        = unit_buf->memory;

  for (u64 i = 0; i < pws_cnt; i++)
  {
    context.out    = (uint8_t *) argon2_reference_tmp->h;
    context.outlen = (uint32_t)  argon2id->digest_len;
    context.pwd    = (uint8_t *) argon2_reference_tmp->pw_buf;
    context.pwdlen = (uint32_t)  argon2_reference_tmp->pw_len;

    argon2_ctx (&context, Argon2_id);

    argon2_reference_tmp++;
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

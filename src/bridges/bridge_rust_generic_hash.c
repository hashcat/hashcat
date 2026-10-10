/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "bridges.h"
#include "memory.h"
#include "shared.h"
#include "path.h"
#include "cpu_features.h"
#include "dynloader.h"
#include "emu_inc_hash_md4.h"

#if defined (_WIN)
#include "processenv.h"
#endif

// The largest batch one unit can be handed. backend_session_begin () derives kernel_accel_max from it
// and lowers that again where the candidate buffers would not fit the device.
//
// Mode 74000 declares BRIDGE_TYPE_REPLACE_LOOP, so autotune times the bridge itself, transfers
// included, and picks the batch below this ceiling by time. A cheap expression gets a large batch and
// a slow one, such as bcrypt, a small one. The ceiling only bounds memory: the device buffer and its
// host mirror hold sizeof (generic_io_dgst_tmp_t) per candidate per unit, 776 bytes, so 16384 is
// 12.7 MB a unit.

#define WORKITEM_COUNT_MAX 16384

typedef struct
{
  // input

  u32 pw_buf[64];
  u32 pw_len;

  // output

  u32 out_buf[32][64];
  u32 out_len[32];
  u32 out_cnt;

} generic_io_tmp_t;

// What the device holds for one candidate, and what crosses the bus in both directions on every
// launch. The full record above is 8584 bytes, almost all of it output slots that are rarely used,
// and moving it was what limited this mode. The comparison only ever needs the MD4 of each output, so
// the crate's outputs are hashed here and only their digests go back, which is 776 bytes. Sync with
// src/modules/module_74000.c and OpenCL/m72000-pure.cl.

typedef struct
{
  u32 pw_buf[64];
  u32 pw_len;

  u32 out_cnt;
  u32 out_dgst[32][4];

} generic_io_dgst_tmp_t;

// The crate still works on full records, so a launch is converted through a buffer of this many of
// them. It keeps the host memory a unit needs independent of the launch size.

#define IO_CHUNK 1024

typedef struct bridge_context bridge_context_t;

typedef int   (*RS_GET_INFO)(char *, int);
typedef bool  (*RS_GLOBAL_INIT)(const bridge_context_t *);
typedef void  (*RS_GLOBAL_TERM)(const bridge_context_t *);
typedef void  (*RS_THREAD_INIT)(void *);
typedef void  (*RS_THREAD_TERM)(void *);
typedef bool  (*RS_KERNEL_LOOP)(void *, generic_io_tmp_t *, u64, int, bool);

typedef void *(*RS_NEW_CONTEXT)(
  const char *module_name,

  int salts_cnt,
  int salts_size,
  const salt_t *salts_buf,

  int esalts_cnt,
  int esalts_size,
  const char *esalts_buf,

  int st_salts_cnt,
  int st_salts_size,
  const salt_t *st_salts_buf,

  int st_esalts_cnt,
  int st_esalts_size,
  const char *st_esalts_buf,

  const char *bridge_parameter1,
  const char *bridge_parameter2,
  const char *bridge_parameter3,
  const char *bridge_parameter4,

  bool salt_per_pw
);

typedef void  (*RS_DROP_CONTEXT)(void *);

typedef struct
{
  // template

  char unit_info_buf[1024];
  int unit_info_len;

  u64 workitem_count;
  size_t workitem_size;

  // implementation specific

  void *unit_context;

  generic_io_tmp_t *io_buf;

} unit_t;

struct bridge_context
{
  unit_t *units_buf;
  int units_cnt;

  char *dynlib_filename;
  hc_dynlib_t lib;

  RS_GET_INFO     get_info;
  RS_GLOBAL_INIT  global_init;
  RS_GLOBAL_TERM  global_term;
  RS_THREAD_INIT  thread_init;
  RS_THREAD_TERM  thread_term;
  RS_KERNEL_LOOP  kernel_loop;
  RS_NEW_CONTEXT  new_context;
  RS_DROP_CONTEXT drop_context;

  const char *bridge_parameter1;
  const char *bridge_parameter2;
  const char *bridge_parameter3;
  const char *bridge_parameter4;
};

static const char *extract_module_name (const char *path)
{
  char *filename = strdup (path);

  #if defined (_WIN)
  remove_file_suffix (filename, ".dll");
  #else
  remove_file_suffix (filename, ".so");
  #endif

  const char *slash = strrchr (filename, '/');
  const char *backslash = strrchr (filename, '\\');

  const char *module_name = NULL;

  if (slash)
  {
    module_name = slash + 1;
  }
  else if (backslash)
  {
    module_name = backslash + 1;
  }
  else
  {
    module_name = filename;
  }

  // The caller gets an allocation whose base is the pointer it was handed. This used to return a
  // pointer into filename, so the free () the call site suggests would have been handed something
  // that is not the start of an allocation whenever the path holds a separator.

  const char *module_name_buf = strdup (module_name);

  free (filename);

  return module_name_buf;
}

static bool units_init (bridge_context_t *bridge_context)
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

    unit_buf->unit_info_len = bridge_context->get_info (unit_buf->unit_info_buf, sizeof (unit_buf->unit_info_buf) - 1);
    unit_buf->unit_info_buf[unit_buf->unit_info_len] = 0;

    unit_buf->workitem_count = WORKITEM_COUNT_MAX;

    units_cnt++;
  }

  bridge_context->units_buf = units_buf;
  bridge_context->units_cnt = units_cnt;

  return true;
}

static void units_term (bridge_context_t *bridge_context)
{
  unit_t *units_buf = bridge_context->units_buf;

  if (units_buf)
  {
    hcfree (bridge_context->units_buf);
    bridge_context->units_buf = NULL;
  }
}

// Both names are resolved against hashcat's shared folder, which is the hashcat directory for a source
// build and $PREFIX/share/hashcat for an installed one. The crate is built into
// Rust/bridges/generic_hash/target and the build then copies it into bridges/subs, which is what make
// install ships, so a source tree finds the cargo output and an installed build finds the copy. These
// were relative to the current working directory before, so an installed build could not load the
// library at all and a source build could only do it from the hashcat directory.

#if defined (_WIN)
#define DEFAULT_DYNLIB_FILENAME          "Rust/bridges/generic_hash/target/x86_64-pc-windows-gnu/release/generic_hash.dll"
#define DEFAULT_DYNLIB_FILENAME_FALLBACK "bridges/subs/generic_hash.dll"
#else
#define DEFAULT_DYNLIB_FILENAME          "Rust/bridges/generic_hash/target/release/libgeneric_hash.so"
#define DEFAULT_DYNLIB_FILENAME_FALLBACK "bridges/subs/generic_hash.so"
#endif

void *platform_init (hashcat_ctx_t *hashcat_ctx)
{
  MAYBE_UNUSED user_options_t  *user_options  = hashcat_ctx->user_options;

  // Verify CPU features

  if (cpu_chipset_test() == -1) return NULL;

  // Allocate platform context

  bridge_context_t *bridge_context = hcmalloc(sizeof(bridge_context_t));

  if (user_options->bridge_parameter1 != NULL)
  {
    bridge_context->dynlib_filename = hcstrdup (user_options->bridge_parameter1);
  }
  else
  {
    const folder_config_t *folder_config = hashcat_ctx->folder_config;

    hc_asprintf (&bridge_context->dynlib_filename, "%s/%s", folder_config->shared_dir, DEFAULT_DYNLIB_FILENAME);

    if (hc_path_exist (bridge_context->dynlib_filename) == false)
    {
      hcfree (bridge_context->dynlib_filename);

      hc_asprintf (&bridge_context->dynlib_filename, "%s/%s", folder_config->shared_dir, DEFAULT_DYNLIB_FILENAME_FALLBACK);
    }
  }

  bridge_context->lib = hc_dlopen (bridge_context->dynlib_filename);

  if (!bridge_context->lib)
  {
    event_log_error (hashcat_ctx, "ERROR: %s: %s", bridge_context->dynlib_filename, strerror (errno));

    hcfree (bridge_context->dynlib_filename);
    hcfree (bridge_context);

    return NULL;
  }

  #define HC_LOAD_FUNC_RUST(ptr, name, type)                                                    \
  do                                                                                            \
  {                                                                                             \
    (ptr)->name = (type) hc_dlsym ((ptr)->lib, #name);                                          \
    if (!(ptr)->name)                                                                           \
    {                                                                                           \
      event_log_error (hashcat_ctx, "%s is missing from %s shared library.", #name, (ptr)->dynlib_filename); \
      hcfree (bridge_context->dynlib_filename);                                                 \
      hcfree (bridge_context);                                                                  \
      return NULL;                                                                              \
    }                                                                                           \
  } while (0)

  HC_LOAD_FUNC_RUST(bridge_context, get_info, RS_GET_INFO);
  HC_LOAD_FUNC_RUST(bridge_context, global_init, RS_GLOBAL_INIT);
  HC_LOAD_FUNC_RUST(bridge_context, global_term, RS_GLOBAL_TERM);
  HC_LOAD_FUNC_RUST(bridge_context, thread_init, RS_THREAD_INIT);
  HC_LOAD_FUNC_RUST(bridge_context, thread_term, RS_THREAD_TERM);
  HC_LOAD_FUNC_RUST(bridge_context, kernel_loop, RS_KERNEL_LOOP);
  HC_LOAD_FUNC_RUST(bridge_context, new_context, RS_NEW_CONTEXT);
  HC_LOAD_FUNC_RUST(bridge_context, drop_context, RS_DROP_CONTEXT);

  bridge_context->bridge_parameter1 = user_options->bridge_parameter1;
  bridge_context->bridge_parameter2 = user_options->bridge_parameter2;
  bridge_context->bridge_parameter3 = user_options->bridge_parameter3;
  bridge_context->bridge_parameter4 = user_options->bridge_parameter4;

  if (!bridge_context->global_init (bridge_context))
  {
    hcfree (bridge_context->dynlib_filename);
    hcfree (bridge_context);

    return NULL;
  }


  if (!units_init (bridge_context))
  {
    hcfree (bridge_context->dynlib_filename);
    hcfree (bridge_context);

    return NULL;
  }

  return bridge_context;
}

void platform_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_context_t *bridge_context = platform_context;

  bridge_context->global_term (bridge_context);

  units_term (bridge_context);

  hcfree (bridge_context->dynlib_filename);
  hcfree (bridge_context);
}

bool thread_init (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  bridge_context_t *bridge_context = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &bridge_context->units_buf[unit_idx];

  const char *module_name = extract_module_name (bridge_context->dynlib_filename);

  // A plugin that exports no ST_HASH, such as dynamic_hash, leaves the run without a self-test, and
  // then there is no self-test salt to hand over.

  const int st_cnt = (hashes->st_salts_buf == NULL) ? 0 : 1;

  unit_buf->unit_context = bridge_context->new_context(
    module_name,

    hashes->salts_cnt,
    sizeof (salt_t),
    hashes->salts_buf,

    hashes->digests_cnt,
    hashconfig->esalt_size,
    (const char *) hashes->esalts_buf,

    st_cnt,
    sizeof (salt_t),
    hashes->st_salts_buf,

    st_cnt,
    hashconfig->esalt_size,
    (const char *) hashes->st_esalts_buf,

    bridge_context->bridge_parameter1,
    bridge_context->bridge_parameter2,
    bridge_context->bridge_parameter3,
    bridge_context->bridge_parameter4,

    hashcat_ctx->user_options->attack_mode == ATTACK_MODE_ASSOCIATION
  );

  // We should free module_name, but if a user changes the Rust code to
  // use it without copying, we could get a dangling pointer. So we are
  // leaking it. The pointer is now the base of its own allocation, so
  // enabling this line is safe for anyone whose Rust side copies it, as
  // both bridges in this tree do with String::to_string ().
  // free ((void *) module_name);

  if (!unit_buf->unit_context) return false;

  unit_buf->io_buf = (generic_io_tmp_t *) hcmalloc (IO_CHUNK * sizeof (generic_io_tmp_t));

  if (unit_buf->io_buf == NULL)
  {
    bridge_context->drop_context (unit_buf->unit_context);

    unit_buf->unit_context = NULL;

    return false;
  }

  bridge_context->thread_init (unit_buf->unit_context);

  return true;
}

void thread_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  bridge_context_t *bridge_context = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &bridge_context->units_buf[unit_idx];

  bridge_context->thread_term (unit_buf->unit_context);

  bridge_context->drop_context (unit_buf->unit_context);

  hcfree (unit_buf->io_buf);

  unit_buf->io_buf = NULL;
}

int get_unit_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context)
{
  bridge_context_t *bridge_context = platform_context;

  return bridge_context->units_cnt;
}

// we support units of mixed speed, that's why the workitem count is unit specific

int get_workitem_count (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx)
{
  bridge_context_t *bridge_context = platform_context;

  unit_t *unit_buf = &bridge_context->units_buf[unit_idx];

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
  bridge_context_t *bridge_context = platform_context;

  unit_t *unit_buf = &bridge_context->units_buf[unit_idx];

  return unit_buf->unit_info_buf;
}

bool launch_loop (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  bridge_context_t *bridge_context = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &bridge_context->units_buf[unit_idx];

  generic_io_dgst_tmp_t *dgst_tmp = (generic_io_dgst_tmp_t *) device_param->h_tmps;

  generic_io_tmp_t *io_buf = unit_buf->io_buf;

  const bool is_selftest = (hashes->salts_buf == hashes->st_salts_buf);

  for (u64 chunk_pos = 0; chunk_pos < pws_cnt; chunk_pos += IO_CHUNK)
  {
    const u64 chunk_cnt = MIN (pws_cnt - chunk_pos, IO_CHUNK);

    for (u64 i = 0; i < chunk_cnt; i++)
    {
      const generic_io_dgst_tmp_t *src = &dgst_tmp[chunk_pos + i];

      generic_io_tmp_t *dst = &io_buf[i];

      memcpy (dst->pw_buf, src->pw_buf, sizeof (dst->pw_buf));

      dst->pw_len  = MIN (src->pw_len, sizeof (dst->pw_buf));
      dst->out_cnt = 0;
    }

    // The Rust side is handed the salt the chunk starts at and adds the position of the candidate
    // within it. The salt_per_pw it was built with tells it to add.

    const u32 chunk_salt_pos = bridge_salt_pos (hashcat_ctx, device_param, hashes, salt_pos, chunk_pos);

    if (bridge_context->kernel_loop (unit_buf->unit_context, io_buf, chunk_cnt, chunk_salt_pos, is_selftest) == false) return false;

    for (u64 i = 0; i < chunk_cnt; i++)
    {
      const generic_io_tmp_t *src = &io_buf[i];

      generic_io_dgst_tmp_t *dst = &dgst_tmp[chunk_pos + i];

      const u32 out_cnt = MIN (src->out_cnt, 32);

      for (u32 j = 0; j < out_cnt; j++)
      {
        const u32 out_len = MIN (src->out_len[j], sizeof (src->out_buf[j]));

        md4_ctx_t ctx;

        md4_init   (&ctx);
        md4_update (&ctx, src->out_buf[j], (int) out_len);
        md4_final  (&ctx);

        dst->out_dgst[j][0] = ctx.h[0];
        dst->out_dgst[j][1] = ctx.h[1];
        dst->out_dgst[j][2] = ctx.h[2];
        dst->out_dgst[j][3] = ctx.h[3];
      }

      dst->out_cnt = out_cnt;
    }
  }

  return true;
}

const char *st_update_hash (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context)
{
  bridge_context_t *bridge_context = platform_context;

  const char **constant = (const char **) hc_dlsym (bridge_context->lib, "ST_HASH");

  if (!constant) return NULL;

  return *constant;
}

const char *st_update_pass (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context)
{
  bridge_context_t *bridge_context = platform_context;

  const char **constant = (const char **) hc_dlsym (bridge_context->lib, "ST_PASS");

  if (!constant) return NULL;

  return *constant;
}

void bridge_init (bridge_ctx_t *bridge_ctx)
{
  bridge_ctx->bridge_context_size = BRIDGE_CONTEXT_SIZE_CURRENT;
  bridge_ctx->bridge_interface_version = BRIDGE_INTERFACE_VERSION_CURRENT;

  bridge_ctx->platform_init         = platform_init;
  bridge_ctx->platform_term         = platform_term;
  bridge_ctx->get_unit_count        = get_unit_count;
  bridge_ctx->get_unit_info         = get_unit_info;
  bridge_ctx->get_workitem_count    = get_workitem_count;
  bridge_ctx->get_workitem_multiple = get_workitem_multiple;
  bridge_ctx->thread_init           = thread_init;
  bridge_ctx->thread_term           = thread_term;
  bridge_ctx->salt_prepare          = BRIDGE_DEFAULT;
  bridge_ctx->salt_destroy          = BRIDGE_DEFAULT;
  bridge_ctx->launch_loop           = launch_loop;
  bridge_ctx->launch_loop2          = BRIDGE_DEFAULT;
  bridge_ctx->st_update_hash        = st_update_hash;
  bridge_ctx->st_update_pass        = st_update_pass;

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

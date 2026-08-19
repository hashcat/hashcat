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

#if defined (_WIN)
#include "processenv.h"
#endif

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

  u32 out_buf[32][64];
  u32 out_len[32];
  u32 out_cnt;

} generic_io_tmp_t;

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
  const char *bridge_parameter4
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

  return module_name;
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

    unit_buf->workitem_count = N_ACCEL;

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

#if defined (_WIN)
static char *DEFAULT_DYNLIB_FILENAME = "./Rust/bridges/generic_hash/target/x86_64-pc-windows-gnu/release/generic_hash.dll";
static char *DEFAULT_DYNLIB_FILENAME_FALLBACK = "./bridges/subs/generic_hash.dll";
#else
static char *DEFAULT_DYNLIB_FILENAME = "./Rust/bridges/generic_hash/target/release/libgeneric_hash.so";
static char *DEFAULT_DYNLIB_FILENAME_FALLBACK = "./bridges/subs/generic_hash.so";
#endif

void *platform_init (hashcat_ctx_t *hashcat_ctx)
{
  MAYBE_UNUSED user_options_t  *user_options  = hashcat_ctx->user_options;

  // Verify CPU features

  if (cpu_chipset_test() == -1) return NULL;

  // Allocate platform context

  bridge_context_t *bridge_context = hcmalloc(sizeof(bridge_context_t));

  char *filename = DEFAULT_DYNLIB_FILENAME;

  if (user_options->bridge_parameter1 != NULL)
  {
    filename = user_options->bridge_parameter1;
  }
  else
  {
    if (!hc_path_exist (filename))
    {
      filename = DEFAULT_DYNLIB_FILENAME_FALLBACK;
    }
  }

  bridge_context->dynlib_filename = filename;

  bridge_context->lib = hc_dlopen (bridge_context->dynlib_filename);

  if (!bridge_context->lib)
  {
    event_log_error (hashcat_ctx, "ERROR: %s: %s", bridge_context->dynlib_filename, strerror (errno));

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
    hcfree (bridge_context);

    return NULL;
  }


  if (!units_init (bridge_context))
  {
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

  hcfree (bridge_context);
}

bool thread_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes)
{
  bridge_context_t *bridge_context = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &bridge_context->units_buf[unit_idx];

  const char *module_name = extract_module_name (bridge_context->dynlib_filename);

  unit_buf->unit_context = bridge_context->new_context(
    module_name,

    hashes->salts_cnt,
    sizeof (salt_t),
    hashes->salts_buf,

    hashes->digests_cnt,
    hashconfig->esalt_size,
    (const char *) hashes->esalts_buf,

    1,
    sizeof (salt_t),
    hashes->st_salts_buf,

    1,
    hashconfig->esalt_size,
    (const char *) hashes->st_esalts_buf,

    bridge_context->bridge_parameter1,
    bridge_context->bridge_parameter2,
    bridge_context->bridge_parameter3,
    bridge_context->bridge_parameter4
  );

  // We should free module_name, but if a user changes the Rust code to
  // use it without copying, we could get a dangling pointer. So we are
  // leaking it.
  // free(module_name);

  if (!unit_buf->unit_context) return false;

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

bool launch_loop (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED void *platform_context, MAYBE_UNUSED hc_device_param_t *device_param, MAYBE_UNUSED hashconfig_t *hashconfig, MAYBE_UNUSED hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u64 pws_cnt)
{
  bridge_context_t *bridge_context = platform_context;

  const int unit_idx = device_param->bridge_link_device;

  unit_t *unit_buf = &bridge_context->units_buf[unit_idx];

  generic_io_tmp_t *generic_io_tmp = (generic_io_tmp_t *) device_param->h_tmps;

  if (!bridge_context->kernel_loop (unit_buf->unit_context, generic_io_tmp, pws_cnt, salt_pos, hashes->salts_buf == hashes->st_salts_buf))
  {
    return false;
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

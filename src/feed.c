/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Everything a feed calls that is not its own.
//
// The subsystem grew one piece at a time and each piece landed wherever there was already a file.
// The setting parser went into shared.c, because shared.c is where a plugin facing helper with no
// other home goes. The device access a feed needs to run a kernel of its own was written inside the
// one feed that needed it first, where about nine tenths of it is not about that feed at all. A
// second feed that wanted either would have had to copy it, and a copy of the device half would
// have meant making the same twenty decisions again, most of which are only obvious after getting
// them wrong once.
//
// So the setting parser moves here unchanged, and the device half is written here once, in the shape
// two real callers need: a filter, which sends a range of indices to the device and reads a verdict
// back, and a generator, which fills a buffer the device already holds.

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "event.h"
#include "folder.h"
#include "path.h"
#include "system.h"
#include "filehandling.h"
#include "emu_inc_hash_md5.h"
#include "ext_cuda.h"
#include "ext_hip.h"
#include "ext_nvrtc.h"
#include "ext_hiprtc.h"
#include "ext_OpenCL.h"
#include "feed.h"
#include "feed_ctx.h"

#include <errno.h>
#include <inttypes.h>

#if defined (_WIN)
#include <process.h>
#define FEED_GETPID _getpid
#else
#define FEED_GETPID getpid
#endif

// ---------------------------------------------------------------------------------------------
// saying things
// ---------------------------------------------------------------------------------------------

// event_log_info () and event_log_warning () both end up in main_log (hashcat_ctx, stdout, ...) and
// neither is guarded by --quiet. Under --stdout that stream is the candidate list, so a line
// explaining that a feed fell back to the host would be handed to whatever is on the other end of
// the pipe as a password to try.
//
// Everything a feed has to say goes through here, and here knows where to put it: nowhere under
// --quiet, on stderr under --stdout, and on the screen otherwise. The thing most worth saying is
// usually that a device was declined and the run is now a great deal slower, and swallowing that is
// how a session silently takes a week.
//
// The order of those two tests is the whole of it. --stdout sets quiet itself
// (src/user_options.c:2605), so a --quiet test that came first would silence every --stdout run,
// which is the one case where there is something worth saying and a safe place to say it. So
// --stdout decides where the line goes, and --quiet only silences when --stdout did not already
// move the line off the candidate stream.

static bool feed_say_stderr (const user_options_t *user_options)
{
  return (user_options->stdout_flag == true);
}

static bool feed_say_silent (const user_options_t *user_options)
{
  return (user_options->quiet == true) && (feed_say_stderr (user_options) == false);
}

void feed_say (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...)
{
  if (hashcat_ctx == NULL) return;

  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options == NULL) return;

  if (feed_say_silent (user_options) == true) return;

  char buf[512];

  va_list ap;
  va_start (ap, fmt);

  vsnprintf (buf, sizeof (buf), fmt, ap);

  va_end (ap);

  if (feed_say_stderr (user_options) == true)
  {
    event_log_error (hashcat_ctx, "%s", buf);
  }
  else
  {
    event_log_warning (hashcat_ctx, "%s", buf);
  }
}

// The device compiler's own words, multi line, so they go out whole rather than through the event
// formatter, which is what hashcat does with its own build logs. Same rule about which stream:
// never the one someone is reading candidates off.

static void feed_say_log (hashcat_ctx_t *hashcat_ctx, const char *log)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options == NULL) return;

  if (feed_say_silent (user_options) == true) return;

  if (feed_say_stderr (user_options) == true)
  {
    fputs (log, stderr);
    fputc ('\n', stderr);
    fflush (stderr);

    return;
  }

  puts (log);
}

// ---------------------------------------------------------------------------------------------
// a feed's own settings
// ---------------------------------------------------------------------------------------------

// A feed's settings, read out of the feed's own work arguments. What a setting is and why it is an
// argument rather than an option is written at feed_param_t in feed.h.
//
// A work argument is a setting when it is key=value with a key that could not be a path: a letter
// followed by letters, digits, dash or underscore, and no directory separator anywhere in front of
// the '='. Everything else is a source, so a feed splits its own arguments by asking. A file whose
// name really does look like a setting is still reachable, as ./mode=2, because that has a
// separator in it.
//
// The test is deliberately about shape and not about which keys a feed knows, so that a misspelled
// setting is still recognised as a setting and can be reported as an unknown one. A rule that fell
// back to "not a key I know, so it must be a filename" would turn every typo into a missing file.

bool feed_param_is_setting (const char *arg)
{
  if (arg == NULL) return false;

  if ((arg[0] >= 'a' && arg[0] <= 'z') == false && (arg[0] >= 'A' && arg[0] <= 'Z') == false) return false;

  for (const char *p = arg; *p; p++)
  {
    if (*p == '=') return (p != arg) ? true : false;

    if (*p >= 'a' && *p <= 'z') continue;
    if (*p >= 'A' && *p <= 'Z') continue;
    if (*p >= '0' && *p <= '9') continue;
    if (*p == '-') continue;
    if (*p == '_') continue;

    return false;
  }

  return false;
}

// The value a setting was given, or NULL when the feed's arguments do not carry it. workv[0] is the
// plugin's own name and is skipped, the same way every feed skips it when reading its sources.

const char *feed_param_lookup (const int workc, char * const *workv, const char *key)
{
  if (workv == NULL) return NULL;
  if (key   == NULL) return NULL;

  const size_t key_len = strlen (key);

  for (int i = 1; i < workc; i++)
  {
    const char *arg = workv[i];

    if (feed_param_is_setting (arg) == false) continue;

    if (strncmp (arg, key, key_len) != 0) continue;

    if (arg[key_len] != '=') continue;

    return arg + key_len + 1;
  }

  return NULL;
}

static int feed_param_key_list (const feed_param_t *params, char *out_buf, const size_t out_size)
{
  int out_len = 0;

  for (const feed_param_t *p = params; p->key != NULL; p++)
  {
    const int rc = snprintf (out_buf + out_len, out_size - (size_t) out_len, "%s%s", (out_len == 0) ? "" : ", ", p->key);

    if (rc < 0) break;

    out_len += rc;

    if ((size_t) out_len >= out_size) return (int) out_size - 1;
  }

  return out_len;
}

static bool feed_param_store (const feed_param_t *param, const char *value, char *err_buf, const size_t err_size)
{
  switch (param->type)
  {
    case FEED_PARAM_TYPE_STR:
    {
      *((const char **) param->dst) = value;

      return true;
    }

    case FEED_PARAM_TYPE_BOOL:
    {
      if ((strcmp (value, "1") == 0) || (strcmp (value, "yes")   == 0) || (strcmp (value, "true")  == 0) || (strcmp (value, "on")  == 0))
      {
        *((bool *) param->dst) = true;

        return true;
      }

      if ((strcmp (value, "0") == 0) || (strcmp (value, "no")    == 0) || (strcmp (value, "false") == 0) || (strcmp (value, "off") == 0))
      {
        *((bool *) param->dst) = false;

        return true;
      }

      snprintf (err_buf, err_size, "%s: '%s' is not a yes or a no", param->key, value);

      return false;
    }

    case FEED_PARAM_TYPE_U64:
    {
      // strtoull takes a leading '-' and wraps it, so a negative number would arrive as a very large
      // one and pass any upper bound the feed set. It is rejected before the conversion sees it.

      if (value[0] == 0)
      {
        snprintf (err_buf, err_size, "%s: needs a number", param->key);

        return false;
      }

      if (value[0] == '-')
      {
        snprintf (err_buf, err_size, "%s: '%s' is negative", param->key, value);

        return false;
      }

      char *endptr = NULL;

      errno = 0;

      const unsigned long long v = strtoull (value, &endptr, 10);

      if ((endptr == value) || (*endptr != 0))
      {
        snprintf (err_buf, err_size, "%s: '%s' is not a number", param->key, value);

        return false;
      }

      if (errno == ERANGE)
      {
        snprintf (err_buf, err_size, "%s: '%s' does not fit", param->key, value);

        return false;
      }

      // A pair left at zero is a feed that did not want a range, not a range of nothing.

      if ((param->min != 0) || (param->max != 0))
      {
        if (((u64) v < param->min) || ((u64) v > param->max))
        {
          snprintf (err_buf, err_size, "%s: %s is outside %" PRIu64 " to %" PRIu64, param->key, value, param->min, param->max);

          return false;
        }
      }

      *((u64 *) param->dst) = (u64) v;

      return true;
    }

    case FEED_PARAM_TYPE_DBL:
    {
      char *endptr = NULL;

      errno = 0;

      const double v = strtod (value, &endptr);

      if ((endptr == value) || (*endptr != 0))
      {
        snprintf (err_buf, err_size, "%s: '%s' is not a number", param->key, value);

        return false;
      }

      if (errno == ERANGE)
      {
        snprintf (err_buf, err_size, "%s: '%s' does not fit", param->key, value);

        return false;
      }

      *((double *) param->dst) = v;

      return true;
    }
  }

  snprintf (err_buf, err_size, "%s: unknown setting type", param->key);

  return false;
}

// Read every setting in a feed's arguments into the variables the feed named, and refuse anything
// it did not name. Whatever the feed left in its variables before the call is the default, because
// an argument that is not there is not written.
//
// Refusing an unknown key is the point of the call. A feed's settings are invisible to --help and to
// tab completion, so a mistyped one has nothing else to catch it, and a feed that quietly ignored
// what it did not recognise would run a different attack than the one that was asked for and say
// nothing. A key given twice is refused for the same reason: last-one-wins reads as a preference
// being applied when it is a mistake.
//
// err_buf is written only on failure. Point it at global_ctx->error_msg and set global_ctx->error.

bool feed_param_parse (const int workc, char * const *workv, const feed_param_t *params, char *err_buf, const size_t err_size)
{
  if (params == NULL) return true;

  for (int i = 1; i < workc; i++)
  {
    const char *arg = workv[i];

    if (feed_param_is_setting (arg) == false) continue;

    const char *eq = strchr (arg, '=');

    const size_t key_len = (size_t) (eq - arg);

    const feed_param_t *found = NULL;

    for (const feed_param_t *p = params; p->key != NULL; p++)
    {
      if (strlen (p->key) != key_len) continue;
      if (strncmp (p->key, arg, key_len) != 0) continue;

      found = p;

      break;
    }

    if (found == NULL)
    {
      char keys[512];

      keys[0] = 0;

      feed_param_key_list (params, keys, sizeof (keys));

      snprintf (err_buf, err_size, "%.*s: no such setting. this feed takes: %s", (int) key_len, arg, keys);

      return false;
    }

    for (int j = 1; j < i; j++)
    {
      if (feed_param_is_setting (workv[j]) == false) continue;

      if (strncmp (workv[j], arg, key_len + 1) == 0)
      {
        snprintf (err_buf, err_size, "%s: given more than once", found->key);

        return false;
      }
    }

    if (feed_param_store (found, eq + 1, err_buf, err_size) == false) return false;
  }

  return true;
}

// The settings a feed takes, one per line, for the feed to print when its arguments make no sense.
// Returns the length written.

int feed_param_usage (const feed_param_t *params, char *out_buf, const size_t out_size)
{
  if (params == NULL) return 0;

  int out_len = 0;

  for (const feed_param_t *p = params; p->key != NULL; p++)
  {
    const char *type = "";

    switch (p->type)
    {
      case FEED_PARAM_TYPE_STR:  type = "=<str>";  break;
      case FEED_PARAM_TYPE_BOOL: type = "=<yes|no>"; break;
      case FEED_PARAM_TYPE_U64:  type = "=<num>";  break;
      case FEED_PARAM_TYPE_DBL:  type = "=<real>"; break;
    }

    char lhs[128];

    snprintf (lhs, sizeof (lhs), "%s%s", p->key, type);

    const int rc = snprintf (out_buf + out_len, out_size - (size_t) out_len, "  %-28s %s\n", lhs, (p->help == NULL) ? "" : p->help);

    if (rc < 0) break;

    out_len += rc;

    if ((size_t) out_len >= out_size) return (int) out_size - 1;
  }

  return out_len;
}

// ---------------------------------------------------------------------------------------------
// finding the device a feed thread belongs to
// ---------------------------------------------------------------------------------------------

// hashcat's own record for one device, borrowed. thread_ctx->device_id is the index into it, and
// devices_param[i].device_id is i (src/backend.c:6369), so the id a feed is handed addresses the
// array directly.
//
// It is a function rather than a documented field walk because everything a feed reads out of that
// record has to be read fresh. backend_session_context_reset () destroys and recreates every CUDA
// context on each outer loop iteration after the first (src/backend.c:14682, from src/hashcat.c:773),
// so a device_param cached by a feed is fine but a CUcontext copied out of one is not.

hc_device_param_t *feed_device_param (hashcat_ctx_t *hashcat_ctx, const int device_id)
{
  if (hashcat_ctx == NULL) return NULL;

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx == NULL) return NULL;
  if (backend_ctx->enabled == false) return NULL;
  if (backend_ctx->devices_param == NULL) return NULL;

  if (device_id < 0) return NULL;
  if (device_id >= backend_ctx->backend_devices_cnt) return NULL;

  return &backend_ctx->devices_param[device_id];
}

// ---------------------------------------------------------------------------------------------
// making a device current for a feed
// ---------------------------------------------------------------------------------------------

// A feed that wants to talk to the device it is feeding needs that device to be current on the
// thread it was called on, and there are four such threads. thread_calc () makes it current for
// itself at src/dispatch.c:1123 and always has. The other three did not, so the one feed that has
// tried this so far carried a push and a pop around every single call it made, and got there by
// finding out the hard way which of the several plausible ways to write that push are wrong.
//
// The core does it instead, at the coarsest place on each thread, so a feed may simply assume the
// device is current. Coarse matters: thread_next () is called once per candidate, and a driver call
// per candidate on a path that already tops out at about 80 MH/s would be a real cost. Once per
// producer thread, and once per device around thread_init (), is free.
//
// A push is used and never cuCtxSetCurrent (), which replaces the top of the stack instead of
// pushing one onto it. The pop goes into a local and never into device_param->cuda_context, because
// thread_calc () writes that exact field from its own thread at src/dispatch.c:1140 and a second
// writer would be two threads racing on hashcat's own handle.
//
// HIP has no context to push. device_param->hip_context is dead, include/types.h:1852 is its only
// occurrence in the tree, and hipSetDevice () is thread local, so binding is a property of the
// thread and there is nothing to unbind.

bool feed_device_bind (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  if (device_param == NULL) return false;

  if (device_param->is_cuda == true)
  {
    if (device_param->cuda_context == NULL) return false;

    return (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == 0);
  }

  if (device_param->is_hip == true)
  {
    return (hc_hipSetDevice (hashcat_ctx, device_param->hip_device) == 0);
  }

  return true;
}

void feed_device_unbind (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  if (device_param == NULL) return;

  if (device_param->is_cuda == false) return;

  CUcontext popped = NULL;

  hc_cuCtxPopCurrent (hashcat_ctx, &popped);
}

// The same pair by device id, for the callers that have one and not the device record. An id that
// names no device binds nothing and says so, rather than reaching past the end of the array.

bool feed_device_bind_id (hashcat_ctx_t *hashcat_ctx, const int device_id)
{
  hc_device_param_t *device_param = feed_device_param (hashcat_ctx, device_id);

  return feed_device_bind (hashcat_ctx, device_param);
}

void feed_device_unbind_id (hashcat_ctx_t *hashcat_ctx, const int device_id)
{
  hc_device_param_t *device_param = feed_device_param (hashcat_ctx, device_id);

  feed_device_unbind (hashcat_ctx, device_param);
}

// ---------------------------------------------------------------------------------------------
// a feed's own kernel: what one looks like from in here
// ---------------------------------------------------------------------------------------------

// One of these per (feed, device). A feed holds the pointer and nothing else needs to see inside,
// which is why the type is opaque in feed.h: everything below is a backend detail and none of it is
// a promise.

#define FEED_GPU_OPTV_MAX    64
#define FEED_GPU_THREADS_DEF 64

typedef struct feed_gpu_slot
{
  CUdeviceptr    cu;
  hipDeviceptr_t hip;
  cl_mem         cl;

  size_t         size;

} feed_gpu_slot_t;

struct feed_gpu
{
  hashcat_ctx_t *hashcat_ctx;

  // Which device, and which backend it is. The device record itself is looked up fresh on every
  // call rather than kept, for the reason feed_device_param () gives.

  int  device_id;

  bool is_cuda;
  bool is_hip;
  bool is_opencl;

  // What the kernel was built from and what it is called, copied rather than borrowed, because the
  // descriptor a feed passed to feed_gpu_init () may be a local.

  char name[64];
  char kernel_name[128];

  // CUDA

  CUmodule   cu_module;
  CUfunction cu_function;
  CUstream   cu_stream;

  // HIP

  hipModule_t   hip_module;
  hipFunction_t hip_function;
  hipStream_t   hip_stream;

  // OpenCL. cl_program may be a retained borrow from a sibling device that shares the context and
  // built the same thing, which is the trick hashcat plays for its own kernels at
  // src/backend.c:10332. The kernel object is always this one's own, because clSetKernelArg () is
  // the one OpenCL call that is not thread safe and is only safe across different kernel objects.

  cl_program       cl_program_h;
  cl_kernel        cl_kernel_h;
  cl_command_queue cl_queue;

  feed_gpu_slot_t slot[FEED_GPU_SLOTS_MAX];

  u32 threads;
};

// Handing a finished OpenCL program to the next device on the same context. NVIDIA's OpenCL
// "binary" is PTX, so loading it from the cache re-runs ptxas and saves almost nothing; this is the
// difference between three seconds per device and three seconds per rig.
//
// One slot rather than a table, because feed_gpu_init () walks devices in order and the sibling
// that wants the program is always the next one. A feed whose key does not match simply builds its
// own, which is a missed saving and not a wrong answer.
//
// Written only from feed_gpu_init () and feed_gpu_term (), which feed.h says are to be called from
// thread_init () and thread_term (). The core runs those one device at a time on the main thread,
// so there is one writer. live_cnt is what says when the last borrower has gone and the extra
// reference this holds can be given back.

static cl_program feed_gpu_share_program = NULL;
static cl_context feed_gpu_share_context = NULL;
static char       feed_gpu_share_key[64];
static int        feed_gpu_live_cnt      = 0;

// ---------------------------------------------------------------------------------------------
// build options
// ---------------------------------------------------------------------------------------------

typedef struct feed_optv
{
  char *v[FEED_GPU_OPTV_MAX];
  int   c;

  // Set when an option did not fit. A dropped -D is a kernel built with a different constant than the
  // one it was asked for, and since the options go into the cache key as well it would be cached
  // under the name of the build that was wanted rather than the one that happened.

  bool  ovf;

} feed_optv_t;

// Options are collected one argv element at a time rather than as one flat string. NVRTC and HIPRTC
// take an array, and hashcat's own comment at src/backend.c says why that matters: a path with a
// space in it cannot survive being split on whitespace afterwards. OpenCL wants one string, so the
// array is joined for it, with the include path quoted the way hashcat quotes it.

static void feed_optv_add (feed_optv_t *o, const char *fmt, ...)
{
  if (o->c >= FEED_GPU_OPTV_MAX)
  {
    o->ovf = true;

    return;
  }

  char buf[1024];

  va_list ap;
  va_start (ap, fmt);

  vsnprintf (buf, sizeof (buf), fmt, ap);

  va_end (ap);

  o->v[o->c] = hcstrdup (buf);

  o->c++;
}

static void feed_optv_free (feed_optv_t *o)
{
  for (int i = 0; i < o->c; i++) hcfree (o->v[i]);

  o->c = 0;
}

static char *feed_optv_join (const feed_optv_t *o)
{
  size_t len = 1;

  for (int i = 0; i < o->c; i++) len += strlen (o->v[i]) + 1;

  char *buf = (char *) hcmalloc (len);

  size_t off = 0;

  for (int i = 0; i < o->c; i++)
  {
    const size_t l = strlen (o->v[i]);

    memcpy (buf + off, o->v[i], l);

    off += l;

    buf[off] = ' ';

    off++;
  }

  buf[(off > 0) ? off - 1 : 0] = 0;

  return buf;
}

// A feed's extra options arrive as one string and are split here, because that is the form NVRTC
// and HIPRTC want. One consequence is worth stating rather than discovering: a value containing a
// space does not survive the split. A feed that needs one has to pass it another way.

static void feed_optv_add_split (feed_optv_t *o, const char *opts)
{
  if (opts == NULL) return;

  const char *p = opts;

  while (*p)
  {
    while ((*p == ' ') || (*p == '\t')) p++;

    if (*p == 0) break;

    const char *start = p;

    while ((*p != 0) && (*p != ' ') && (*p != '\t')) p++;

    const size_t len = (size_t) (p - start);

    if (len >= 1024)
    {
      o->ovf = true;

      continue;
    }

    char buf[1024];

    memcpy (buf, start, len);

    buf[len] = 0;

    feed_optv_add (o, "%s", buf);
  }
}

// Everything a kernel included from OpenCL/ needs and nothing hashcat passes for reasons a feed does
// not share.
//
// KERNEL_STATIC types u32 on the device. DGST_ELEM sizes digest_t and DGST_R0..R3 index d2[] in
// hash_comp (), which a feed kernel does not call, so they are fixed rather than taken from a hash
// mode the feed has nothing to do with. Otherwise the cache key would move with the mode.
//
// The whole HAS_* block is emitted verbatim, because hc_swap32 () and hc_swap64 () in inc_common.cl
// pick vendor assembly on IS_NV && HAS_PRMT and fall back to rotate (), which is commented out for
// CUDA and HIP. That is not a slower path, it is a build failure, the same one hashcat's own kernels
// would hit.
//
// Left out on purpose: KERN_TYPE and ATTACK_*, which nothing here reads; VECT_SIZE, forced to 1 as
// long as NEW_SIMD_CODE is undefined; and ATTACK_EXEC, which is left undefined deliberately because
// inc_platform.cl declares 32 KB of constant memory under ATTACK_EXEC == 11.

static void feed_optv_common (feed_optv_t *o, const hc_device_param_t *device_param)
{
  feed_optv_add (o, "-D KERNEL_STATIC");
  feed_optv_add (o, "-D XM2S(x)=#x");
  feed_optv_add (o, "-D M2S(x)=XM2S(x)");

  feed_optv_add (o, "-D DGST_R0=0");
  feed_optv_add (o, "-D DGST_R1=1");
  feed_optv_add (o, "-D DGST_R2=2");
  feed_optv_add (o, "-D DGST_R3=3");
  feed_optv_add (o, "-D DGST_ELEM=4");

  feed_optv_add (o, "-D LOCAL_MEM_TYPE=%d", device_param->device_local_mem_type);
  feed_optv_add (o, "-D DEVICE_TYPE=%u", (u32) device_param->opencl_device_type);
  feed_optv_add (o, "-D VENDOR_ID=%u", device_param->opencl_platform_vendor_id);
  feed_optv_add (o, "-D CUDA_ARCH=%u", (device_param->sm_major * 100) + (device_param->sm_minor * 10));

  feed_optv_add (o, "-D HAS_ADD=%u",      device_param->has_add);
  feed_optv_add (o, "-D HAS_ADDC=%u",     device_param->has_addc);
  feed_optv_add (o, "-D HAS_SUB=%u",      device_param->has_sub);
  feed_optv_add (o, "-D HAS_SUBC=%u",     device_param->has_subc);
  feed_optv_add (o, "-D HAS_VADD=%u",     device_param->has_vadd);
  feed_optv_add (o, "-D HAS_VADDC=%u",    device_param->has_vaddc);
  feed_optv_add (o, "-D HAS_VADD_CO=%u",  device_param->has_vadd_co);
  feed_optv_add (o, "-D HAS_VADDC_CO=%u", device_param->has_vaddc_co);
  feed_optv_add (o, "-D HAS_VSUB=%u",     device_param->has_vsub);
  feed_optv_add (o, "-D HAS_VSUBB=%u",    device_param->has_vsubb);
  feed_optv_add (o, "-D HAS_VSUB_CO=%u",  device_param->has_vsub_co);
  feed_optv_add (o, "-D HAS_VSUBB_CO=%u", device_param->has_vsubb_co);
  feed_optv_add (o, "-D HAS_VPERM=%u",    device_param->has_vperm);
  feed_optv_add (o, "-D HAS_VADD3=%u",    device_param->has_vadd3);
  feed_optv_add (o, "-D HAS_VBFE=%u",     device_param->has_vbfe);
  feed_optv_add (o, "-D HAS_BFE=%u",      device_param->has_bfe);
  feed_optv_add (o, "-D HAS_LOP3=%u",     device_param->has_lop3);
  feed_optv_add (o, "-D HAS_MOV64=%u",    device_param->has_mov64);
  feed_optv_add (o, "-D HAS_PRMT=%u",     device_param->has_prmt);
  feed_optv_add (o, "-D HAS_SHFW=%u",     device_param->has_shfw);
}

// Where the #include lines resolve from. Three cases, all of them hashcat's, and the reason for the
// third is that cpath_real is a POSIX path on a Cygwin or MSYS build while the compiler underneath
// is native and cannot open one.

static void feed_optv_include_path (feed_optv_t *o, const folder_config_t *folder_config, MAYBE_UNUSED const hc_device_param_t *device_param, MAYBE_UNUSED const bool quote)
{
  #if defined (_WIN) || defined (__CYGWIN__) || defined (__MSYS__)

  if (device_param->is_hip == true)
  {
    // HIPRTC changes the current working folder to its temporary compile folder, so a relative path
    // does not survive it.

    feed_optv_add (o, "-D INCLUDE_PATH=%s/OpenCL/", folder_config->cwd);
  }
  else
  {
    feed_optv_add (o, "-D INCLUDE_PATH=%s", "OpenCL");
  }

  #else

  if ((quote == true) && (strchr (folder_config->cpath_real, ' ') != NULL))
  {
    feed_optv_add (o, "-D INCLUDE_PATH=\"%s\"", folder_config->cpath_real);
  }
  else
  {
    feed_optv_add (o, "-D INCLUDE_PATH=%s", folder_config->cpath_real);
  }

  #endif
}

// ---------------------------------------------------------------------------------------------
// the compiled kernel cache
// ---------------------------------------------------------------------------------------------

// A name is used to build a file path and to key a cache entry, so it may not be free text. Two
// feeds that both wrote "kernel.bin" would overwrite each other's builds, and a name with a
// separator in it would write outside the cache directory entirely. Refusing here is cheaper than
// any of the ways that goes wrong later.

static bool feed_name_is_safe (const char *s, const size_t max)
{
  if (s == NULL) return false;
  if (s[0] == 0) return false;

  const size_t len = strlen (s);

  if (len >= max) return false;

  for (size_t i = 0; i < len; i++)
  {
    const char c = s[i];

    if ((c >= 'a') && (c <= 'z')) continue;
    if ((c >= 'A') && (c <= 'Z')) continue;
    if ((c >= '0') && (c <= '9')) continue;
    if (c == '_') continue;
    if (c == '-') continue;
    if (c == '.') continue;

    return false;
  }

  // ".." would climb out of the cache directory even without a separator in it.

  if (strstr (s, "..") != NULL) return false;

  return true;
}

// Keyed on everything hashcat keys its own kernels on, plus three things hashcat gets for free and a
// feed does not: the feed's name, so that two feeds cannot collide; the build options, because
// hashcat's are a function of what is already in the key and a feed's are not; and the kernel source
// itself, because comptime is the build timestamp of the binary and does not move when an editable
// data file next to it changes. Hashing the source rather than its size and mtime is both cheaper to
// be sure about and immune to a filesystem with a coarse clock.

static void feed_gpu_cache_key (hashcat_ctx_t *hashcat_ctx, const hc_device_param_t *device_param, const char *name, const char *opts, const char *source, const size_t source_len, char *out, const size_t out_size)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  char ident[HCBUFSIZ_TINY];

  const int ident_len = snprintf (ident, sizeof (ident), "%s-%d-%d-%d-%u-%u-%u-%s-%d-%u-%s-%s-%s-%d",
    name,
    backend_ctx->comptime,
    backend_ctx->cuda_driver_version,
    backend_ctx->hip_runtimeVersion,
    backend_ctx->metal_runtimeVersion,
    device_param->sm_major,
    device_param->sm_minor,
    (device_param->is_hip == true) ? device_param->gcnArchName : "",
    device_param->is_opencl,
    device_param->opencl_platform_vendor_id,
    device_param->device_name,
    device_param->opencl_device_version,
    device_param->opencl_driver_version,
    get_current_arch ());

  const size_t opts_len = strlen (opts);

  // One buffer rather than three md5_update () calls, because the three pieces have to be hashed as
  // one string anyway.
  //
  // The 64 bytes of slack are not padding for a rounding: md5_update () reads a whole 64 byte block
  // for the tail whatever length it was given, which is what hashcat allocates for at
  // src/backend.c:864. Eight bytes of slack is enough for the u32 rounding and not enough for that,
  // and the difference does not crash. It reads whatever the allocator left behind, so the key comes
  // out different for the same kernel on the same device and every run is a cold build.

  const size_t all_len = (size_t) ident_len + opts_len + source_len;

  char *all = (char *) hcmalloc (all_len + 64);

  memcpy (all,                                 ident,  (size_t) ident_len);
  memcpy (all + ident_len,                     opts,   opts_len);
  memcpy (all + (size_t) ident_len + opts_len, source, source_len);

  md5_ctx_t md5_ctx;

  md5_init   (&md5_ctx);
  md5_update (&md5_ctx, (u32 *) all, (int) all_len);
  md5_final  (&md5_ctx);

  hcfree (all);

  snprintf (out, out_size, "%08x%08x%08x%08x", md5_ctx.h[0], md5_ctx.h[1], md5_ctx.h[2], md5_ctx.h[3]);
}

static char *feed_file_read (const char *path, size_t *out_len)
{
  if (hc_path_read (path) == false) return NULL;
  if (hc_path_is_empty (path) == true) return NULL;

  struct stat st;

  if (stat (path, &st) != 0) return NULL;

  const size_t len = (size_t) st.st_size;

  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) return NULL;

  char *buf = (char *) hcmalloc (len + 1);

  const size_t got = hc_fread (buf, 1, len, &fp);

  hc_fclose (&fp);

  if (got != len)
  {
    hcfree (buf);

    return NULL;
  }

  buf[len] = 0;

  *out_len = len;

  return buf;
}

// write_kernel_binary () in src/backend.c opens "wb", which truncates, before it takes its advisory
// lock, and read_kernel_binary () takes no lock at all, so two hashcat processes sharing one cache
// directory can read a half written file. That is a race worth not copying: the binary is written
// under a name nobody looks for and renamed into place, which is atomic on every filesystem this
// runs on. A cache entry that fails to load is treated as absent, never as a build failure.

static void feed_gpu_cache_write (const char *path, const void *buf, const size_t len)
{
  if (len == 0) return;

  char tmp[1024];

  snprintf (tmp, sizeof (tmp), "%s.tmp.%d", path, (int) FEED_GETPID ());

  HCFILE fp;

  if (hc_fopen (&fp, tmp, "wb") == false) return;

  const size_t put = hc_fwrite (buf, 1, len, &fp);

  hc_fflush (&fp);
  hc_fclose (&fp);

  if (put != len)
  {
    remove (tmp);

    return;
  }

  // rename () refuses an existing target on Windows, where POSIX replaces it silently.

  #if defined (_WIN)
  remove (path);
  #endif

  if (rename (tmp, path) != 0) remove (tmp);
}

// Read through cpath_real rather than through INCLUDE_PATH, because those two are deliberately
// different on Cygwin and MSYS: INCLUDE_PATH is what the device compiler can open, cpath_real is
// what this process can.

static char *feed_gpu_source_read (hashcat_ctx_t *hashcat_ctx, const char *kernel_file, size_t *out_len)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  char path[1024];

  snprintf (path, sizeof (path), "%s/%s", folder_config->cpath_real, kernel_file);

  return feed_file_read (path, out_len);
}

// ---------------------------------------------------------------------------------------------
// bringing the kernel up, per backend
// ---------------------------------------------------------------------------------------------

static bool feed_gpu_build_cuda (feed_gpu_t *gp, const char *source, const char *kernel_file, const char *cache_file, const feed_optv_t *o, char *reason, const size_t reason_size)
{
  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  size_t cached_len = 0;

  char *cached = feed_file_read (cache_file, &cached_len);

  if (cached != NULL)
  {
    if (hc_cuModuleLoadDataEx (hashcat_ctx, &gp->cu_module, cached, 0, NULL, NULL) == 0)
    {
      hcfree (cached);

      return true;
    }

    // A cache entry that will not load is stale or damaged, not a build failure. Fall through and
    // compile; the good one overwrites it on the way out.

    hcfree (cached);

    gp->cu_module = NULL;
  }

  if (backend_ctx->nvrtc == NULL)
  {
    snprintf (reason, reason_size, "NVRTC is not loaded");

    return false;
  }

  nvrtcProgram program;

  if (hc_nvrtcCreateProgram (hashcat_ctx, &program, source, kernel_file, 0, NULL, NULL) == -1)
  {
    snprintf (reason, reason_size, "nvrtcCreateProgram failed");

    return false;
  }

  if (hc_nvrtcCompileProgram (hashcat_ctx, program, o->c, (const char * const *) o->v) == -1)
  {
    size_t log_size = 0;

    hc_nvrtcGetProgramLogSize (hashcat_ctx, program, &log_size);

    char *log = (char *) hcmalloc (log_size + 1);

    if (hc_nvrtcGetProgramLog (hashcat_ctx, program, log) == 0)
    {
      log[log_size] = 0;

      feed_say_log (hashcat_ctx, log);
    }

    hcfree (log);

    hc_nvrtcDestroyProgram (hashcat_ctx, &program);

    snprintf (reason, reason_size, "the kernel did not compile");

    return false;
  }

  size_t ptx_size = 0;

  if (hc_nvrtcGetPTXSize (hashcat_ctx, program, &ptx_size) == -1)
  {
    hc_nvrtcDestroyProgram (hashcat_ctx, &program);

    snprintf (reason, reason_size, "nvrtcGetPTXSize failed");

    return false;
  }

  char *ptx = (char *) hcmalloc (ptx_size);

  if (hc_nvrtcGetPTX (hashcat_ctx, program, ptx) == -1)
  {
    hcfree (ptx);

    hc_nvrtcDestroyProgram (hashcat_ctx, &program);

    snprintf (reason, reason_size, "nvrtcGetPTX failed");

    return false;
  }

  hc_nvrtcDestroyProgram (hashcat_ctx, &program);

  #if defined (WITH_CUBIN)

  // cuLinkCreate and friends are resolved only inside #if defined (WITH_CUBIN), and the hc_cuLink*
  // wrappers do not check the pointer they dlopen'd, so calling them on a build made with
  // ENABLE_CUBIN=0 is a segfault rather than an error. hashcat guards this and so does this.

  CUlinkState state;

  if (hc_cuLinkCreate (hashcat_ctx, 0, NULL, NULL, &state) == -1)
  {
    hcfree (ptx);

    snprintf (reason, reason_size, "cuLinkCreate failed");

    return false;
  }

  if (hc_cuLinkAddData (hashcat_ctx, state, CU_JIT_INPUT_PTX, ptx, ptx_size, kernel_file, 0, NULL, NULL) == -1)
  {
    hc_cuLinkDestroy (hashcat_ctx, state);

    hcfree (ptx);

    snprintf (reason, reason_size, "cuLinkAddData failed");

    return false;
  }

  void *cubin = NULL;

  size_t cubin_size = 0;

  if (hc_cuLinkComplete (hashcat_ctx, state, &cubin, &cubin_size) == -1)
  {
    hc_cuLinkDestroy (hashcat_ctx, state);

    hcfree (ptx);

    snprintf (reason, reason_size, "cuLinkComplete failed");

    return false;
  }

  const bool rc_load = (hc_cuModuleLoadDataEx (hashcat_ctx, &gp->cu_module, cubin, 0, NULL, NULL) == 0);

  // The cubin belongs to the link state and is freed by cuLinkDestroy (), so the cache copy has to
  // happen while the state is still alive.

  if (rc_load == true) feed_gpu_cache_write (cache_file, cubin, cubin_size);

  hc_cuLinkDestroy (hashcat_ctx, state);

  hcfree (ptx);

  if (rc_load == false)
  {
    snprintf (reason, reason_size, "cuModuleLoadDataEx failed");

    return false;
  }

  #else

  const bool rc_load = (hc_cuModuleLoadDataEx (hashcat_ctx, &gp->cu_module, ptx, 0, NULL, NULL) == 0);

  if (rc_load == true) feed_gpu_cache_write (cache_file, ptx, ptx_size);

  hcfree (ptx);

  if (rc_load == false)
  {
    snprintf (reason, reason_size, "cuModuleLoadDataEx failed");

    return false;
  }

  #endif

  return true;
}

static bool feed_gpu_build_hip (feed_gpu_t *gp, const char *source, const char *kernel_file, const char *cache_file, const feed_optv_t *o, char *reason, const size_t reason_size)
{
  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  size_t cached_len = 0;

  char *cached = feed_file_read (cache_file, &cached_len);

  if (cached != NULL)
  {
    if (hc_hipModuleLoadDataEx (hashcat_ctx, &gp->hip_module, cached, 0, NULL, NULL) == 0)
    {
      hcfree (cached);

      return true;
    }

    hcfree (cached);

    gp->hip_module = NULL;
  }

  if (backend_ctx->hiprtc == NULL)
  {
    snprintf (reason, reason_size, "HIPRTC is not loaded");

    return false;
  }

  hiprtcProgram program;

  if (hc_hiprtcCreateProgram (hashcat_ctx, &program, source, kernel_file, 0, NULL, NULL) == -1)
  {
    snprintf (reason, reason_size, "hiprtcCreateProgram failed");

    return false;
  }

  if (hc_hiprtcCompileProgram (hashcat_ctx, program, o->c, (const char * const *) o->v) == -1)
  {
    size_t log_size = 0;

    hc_hiprtcGetProgramLogSize (hashcat_ctx, program, &log_size);

    char *log = (char *) hcmalloc (log_size + 1);

    if (hc_hiprtcGetProgramLog (hashcat_ctx, program, log) == 0)
    {
      log[log_size] = 0;

      feed_say_log (hashcat_ctx, log);
    }

    hcfree (log);

    hc_hiprtcDestroyProgram (hashcat_ctx, &program);

    snprintf (reason, reason_size, "the kernel did not compile");

    return false;
  }

  size_t code_size = 0;

  if (hc_hiprtcGetCodeSize (hashcat_ctx, program, &code_size) == -1)
  {
    hc_hiprtcDestroyProgram (hashcat_ctx, &program);

    snprintf (reason, reason_size, "hiprtcGetCodeSize failed");

    return false;
  }

  char *code = (char *) hcmalloc (code_size);

  if (hc_hiprtcGetCode (hashcat_ctx, program, code) == -1)
  {
    hcfree (code);

    hc_hiprtcDestroyProgram (hashcat_ctx, &program);

    snprintf (reason, reason_size, "hiprtcGetCode failed");

    return false;
  }

  hc_hiprtcDestroyProgram (hashcat_ctx, &program);

  // HIPRTC emits a finished code object, so there is no link step to mirror the CUDA one.

  const bool rc_load = (hc_hipModuleLoadDataEx (hashcat_ctx, &gp->hip_module, code, 0, NULL, NULL) == 0);

  if (rc_load == true) feed_gpu_cache_write (cache_file, code, code_size);

  hcfree (code);

  if (rc_load == false)
  {
    snprintf (reason, reason_size, "hipModuleLoadDataEx failed");

    return false;
  }

  return true;
}

// Hand the finished program to whoever comes next on this context. One extra reference is taken and
// held until the last feed_gpu_t goes, so a borrow cannot outlive the lender's own release.

static void feed_gpu_share_offer (feed_gpu_t *gp, const hc_device_param_t *device_param, const char *key)
{
  if (feed_gpu_share_program != NULL) return;

  if (hc_clRetainProgram (gp->hashcat_ctx, gp->cl_program_h) == -1) return;

  feed_gpu_share_program = gp->cl_program_h;
  feed_gpu_share_context = device_param->opencl_context;

  snprintf (feed_gpu_share_key, sizeof (feed_gpu_share_key), "%s", key);
}

static bool feed_gpu_build_opencl (feed_gpu_t *gp, hc_device_param_t *device_param, const char *source, const char *cache_file, const char *opts, const char *key, char *reason, const size_t reason_size)
{
  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;

  // A sibling device that shares this context and built the same thing already has the answer.

  if ((feed_gpu_share_program != NULL) && (feed_gpu_share_context == device_param->opencl_context) && (strcmp (feed_gpu_share_key, key) == 0))
  {
    if (hc_clRetainProgram (hashcat_ctx, feed_gpu_share_program) == 0)
    {
      // Owned or borrowed, this holds one reference and feed_gpu_term () gives back one reference,
      // so the two cases need no telling apart after this point.

      gp->cl_program_h = feed_gpu_share_program;

      return true;
    }
  }

  size_t cached_len = 0;

  char *cached = feed_file_read (cache_file, &cached_len);

  if (cached != NULL)
  {
    const unsigned char *bin = (const unsigned char *) cached;

    cl_int binary_status = CL_SUCCESS;

    cl_program prog = NULL;

    if (hc_clCreateProgramWithBinary (hashcat_ctx, device_param->opencl_context, 1, &device_param->opencl_device, &cached_len, &bin, &binary_status, &prog) == 0)
    {
      if (hc_clBuildProgram (hashcat_ctx, prog, 1, &device_param->opencl_device, opts, NULL, NULL) == 0)
      {
        hcfree (cached);

        gp->cl_program_h = prog;

        feed_gpu_share_offer (gp, device_param, key);

        return true;
      }

      hc_clReleaseProgramPtr (hashcat_ctx, &prog);
    }

    hcfree (cached);
  }

  cl_program p1 = NULL;

  if (hc_clCreateProgramWithSource (hashcat_ctx, device_param->opencl_context, 1, (const char **) &source, NULL, &p1) == -1)
  {
    snprintf (reason, reason_size, "clCreateProgramWithSource failed");

    return false;
  }

  // Apple Silicon cannot do the separate compile and link, exactly as hashcat notes for its own.

  const bool apple_silicon = (strncmp (device_param->device_name, "Apple M", 7) == 0);

  int rc_build;

  if (apple_silicon == true)
  {
    rc_build = hc_clBuildProgram (hashcat_ctx, p1, 1, &device_param->opencl_device, opts, NULL, NULL);
  }
  else
  {
    rc_build = hc_clCompileProgram (hashcat_ctx, p1, 1, &device_param->opencl_device, opts, 0, NULL, NULL, NULL, NULL);
  }

  if (rc_build == -1)
  {
    size_t log_size = 0;

    hc_clGetProgramBuildInfo (hashcat_ctx, p1, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);

    char *log = (char *) hcmalloc (log_size + 1);

    if (hc_clGetProgramBuildInfo (hashcat_ctx, p1, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, log_size, log, NULL) == 0)
    {
      log[log_size] = 0;

      feed_say_log (hashcat_ctx, log);
    }

    hcfree (log);

    hc_clReleaseProgramPtr (hashcat_ctx, &p1);

    snprintf (reason, reason_size, "the kernel did not compile");

    return false;
  }

  if (apple_silicon == true)
  {
    gp->cl_program_h = p1;
  }
  else
  {
    cl_program fin = NULL;

    if (hc_clLinkProgram (hashcat_ctx, device_param->opencl_context, 1, &device_param->opencl_device, NULL, 1, &p1, NULL, NULL, &fin) == -1)
    {
      hc_clReleaseProgramPtr (hashcat_ctx, &p1);

      snprintf (reason, reason_size, "clLinkProgram failed");

      return false;
    }

    hc_clReleaseProgramPtr (hashcat_ctx, &p1);

    gp->cl_program_h = fin;
  }

  size_t binary_size = 0;

  if (hc_clGetProgramInfo (hashcat_ctx, gp->cl_program_h, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL) == 0)
  {
    if (binary_size > 0)
    {
      char *binary = (char *) hcmalloc (binary_size);

      if (hc_clGetProgramInfo (hashcat_ctx, gp->cl_program_h, CL_PROGRAM_BINARIES, sizeof (char *), &binary, NULL) == 0)
      {
        feed_gpu_cache_write (cache_file, binary, binary_size);
      }

      hcfree (binary);
    }
  }

  feed_gpu_share_offer (gp, device_param, key);

  return true;
}

// ---------------------------------------------------------------------------------------------
// teardown
// ---------------------------------------------------------------------------------------------

void feed_gpu_term (feed_gpu_t *gp)
{
  if (gp == NULL) return;

  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;

  hc_device_param_t *device_param = feed_device_param (hashcat_ctx, gp->device_id);

  // Releasing touches the device, so the same borrow discipline applies here as anywhere else. A
  // bind that fails leaves the objects behind rather than freeing them into a context that is not
  // current, which would be worse than leaking them.

  if (feed_device_bind (hashcat_ctx, device_param) == true)
  {
    if (gp->is_cuda == true)
    {
      for (int i = 0; i < FEED_GPU_SLOTS_MAX; i++)
      {
        if (gp->slot[i].cu != 0) hc_cuMemFree (hashcat_ctx, gp->slot[i].cu);
      }

      if (gp->cu_stream != NULL) hc_cuStreamDestroy (hashcat_ctx, gp->cu_stream);
      if (gp->cu_module != NULL) hc_cuModuleUnload  (hashcat_ctx, gp->cu_module);
    }

    if (gp->is_hip == true)
    {
      for (int i = 0; i < FEED_GPU_SLOTS_MAX; i++)
      {
        if (gp->slot[i].hip != 0) hc_hipMemFree (hashcat_ctx, gp->slot[i].hip);
      }

      if (gp->hip_stream != NULL) hc_hipStreamDestroy (hashcat_ctx, gp->hip_stream);
      if (gp->hip_module != NULL) hc_hipModuleUnload  (hashcat_ctx, gp->hip_module);
    }

    if (gp->is_opencl == true)
    {
      for (int i = 0; i < FEED_GPU_SLOTS_MAX; i++)
      {
        if (gp->slot[i].cl != NULL) hc_clReleaseMemObject (hashcat_ctx, gp->slot[i].cl);
      }

      if (gp->cl_kernel_h  != NULL) hc_clReleaseKernel       (hashcat_ctx, gp->cl_kernel_h);
      if (gp->cl_program_h != NULL) hc_clReleaseProgram      (hashcat_ctx, gp->cl_program_h);
      if (gp->cl_queue     != NULL) hc_clReleaseCommandQueue (hashcat_ctx, gp->cl_queue);

      // opencl_context is never released here. opencl_context_is_clone means one cl_context can
      // belong to several devices_param entries, and it is hashcat's to destroy.
    }

    feed_device_unbind (hashcat_ctx, device_param);
  }

  if (feed_gpu_live_cnt > 0) feed_gpu_live_cnt--;

  if ((feed_gpu_live_cnt == 0) && (feed_gpu_share_program != NULL))
  {
    hc_clReleaseProgram (hashcat_ctx, feed_gpu_share_program);

    feed_gpu_share_program = NULL;
    feed_gpu_share_context = NULL;

    feed_gpu_share_key[0] = 0;
  }

  hcfree (gp);
}

// ---------------------------------------------------------------------------------------------
// bringing one device up
// ---------------------------------------------------------------------------------------------

// Returns NULL for every reason there is not to use this device, and fills reason with a sentence
// the caller can put on the screen with feed_say (). None of them is fatal by itself, and that is
// the point of the shape: a feed keeps its host path as the fallback and as the reference the device
// is checked against, and returning NULL with a sentence is what makes doing that the natural thing
// to write instead of the disciplined thing.

feed_gpu_t *feed_gpu_init (hashcat_ctx_t *hashcat_ctx, const int device_id, const feed_gpu_desc_t *desc, char *reason, const size_t reason_size)
{
  if (reason_size > 0) reason[0] = 0;

  if (hashcat_ctx == NULL)
  {
    snprintf (reason, reason_size, "there is no hashcat context");

    return NULL;
  }

  if (desc == NULL)
  {
    snprintf (reason, reason_size, "there is no kernel description");

    return NULL;
  }

  // The name keys the cache file and the kernel file names the source, so both are part of a path
  // and neither may be free text.

  if (feed_name_is_safe (desc->name, 64) == false)
  {
    snprintf (reason, reason_size, "the feed name is not a plain name");

    return NULL;
  }

  if (feed_name_is_safe (desc->kernel_file, 256) == false)
  {
    snprintf (reason, reason_size, "the kernel file is not a plain name in the kernel folder");

    return NULL;
  }

  if ((desc->kernel_name == NULL) || (desc->kernel_name[0] == 0) || (strlen (desc->kernel_name) >= 128))
  {
    snprintf (reason, reason_size, "the kernel has no usable name");

    return NULL;
  }

  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  hc_device_param_t *device_param = feed_device_param (hashcat_ctx, device_id);

  if (device_param == NULL)
  {
    snprintf (reason, reason_size, "device id %d is not a device this run has", device_id);

    return NULL;
  }

  if (device_param->skipped == true)
  {
    snprintf (reason, reason_size, "this device was skipped");

    return NULL;
  }

  if (device_param->skipped_warning == true)
  {
    snprintf (reason, reason_size, "this device was skipped for this round");

    return NULL;
  }

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  // Every hc_cu*/hc_hip*/hc_cl* wrapper dereferences one of these on its second line, so these are
  // not optional checks. --backend-ignore-* never allocates them and a failed init sets them back
  // to NULL.

  if ((device_param->is_cuda == true) && (backend_ctx->cuda == NULL))
  {
    snprintf (reason, reason_size, "the CUDA runtime is not loaded");

    return NULL;
  }

  if ((device_param->is_hip == true) && (backend_ctx->hip == NULL))
  {
    snprintf (reason, reason_size, "the HIP runtime is not loaded");

    return NULL;
  }

  if ((device_param->is_opencl == true) && (backend_ctx->ocl == NULL))
  {
    snprintf (reason, reason_size, "the OpenCL runtime is not loaded");

    return NULL;
  }

  if ((device_param->is_cuda == false) && (device_param->is_hip == false) && (device_param->is_opencl == false))
  {
    // Metal, today. hc_mtlBuildOptionsToDict () does not hand the option string to a compiler: it
    // strips "-D ", splits on whitespace and drops anything that is not a name=value pair. And
    // load_kernel () never writes a .metallib, so there would be a full cold build at every session
    // start with no cache to fall back on.

    snprintf (reason, reason_size, "this backend cannot build a feed kernel");

    return NULL;
  }

  // An OpenCL CPU device is the same silicon the host fallback already runs on, and the fallback
  // needs no cold build to get there. --stdout forces exactly these devices, and thread_init () walks
  // devices serially on the main thread, so without this the first --stdout run on a box with an
  // Intel or pocl runtime stalls with nothing on screen for longer than the whole attack would take.
  //
  // A feed whose kernel really is worth running on a CPU device says so in the descriptor.

  if ((device_param->is_opencl == true) && (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU) && (desc->allow_opencl_cpu == false))
  {
    snprintf (reason, reason_size, "this is a CPU device, so the host path is the same thing without the compile");

    return NULL;
  }

  size_t source_len = 0;

  char *source = feed_gpu_source_read (hashcat_ctx, desc->kernel_file, &source_len);

  if (source == NULL)
  {
    snprintf (reason, reason_size, "%s/%s could not be read", folder_config->cpath_real, desc->kernel_file);

    return NULL;
  }

  const u32 threads = (desc->threads > 0) ? desc->threads : FEED_GPU_THREADS_DEF;

  feed_optv_t o;

  memset (&o, 0, sizeof (o));

  feed_optv_common (&o, device_param);

  if (device_param->is_cuda == true)
  {
    if (backend_ctx->nvrtc_driver_version >= 12000) feed_optv_add (&o, "--std=c++14");

    feed_optv_add (&o, "--gpu-architecture=compute_%d", (device_param->sm_major * 10) + device_param->sm_minor);

    feed_optv_include_path (&o, folder_config, device_param, false);
  }
  else if (device_param->is_hip == true)
  {
    // Without --gpu-max-threads-per-block the compiler budgets registers for a 1024 thread block,
    // which on a register hungry kernel means heavy spilling.

    feed_optv_add (&o, "-D MAX_THREADS_PER_BLOCK=%u", threads);
    feed_optv_add (&o, "--gpu-architecture=%s", device_param->gcnArchName);
    feed_optv_add (&o, "--gpu-max-threads-per-block=%u", threads);

    feed_optv_include_path (&o, folder_config, device_param, false);
  }
  else
  {
    if (device_param->use_opencl12 == true)      feed_optv_add (&o, "-cl-std=CL1.2");
    else if (device_param->use_opencl20 == true) feed_optv_add (&o, "-cl-std=CL2.0");
    else if (device_param->use_opencl30 == true) feed_optv_add (&o, "-cl-std=CL3.0");

    #if defined (__APPLE__)
    if (is_apple_silicon () == true) feed_optv_add (&o, "-D IS_APPLE_SILICON");
    #endif

    feed_optv_include_path (&o, folder_config, device_param, true);

    feed_optv_add (&o, "-w");
  }

  feed_optv_add_split (&o, desc->build_options);

  if (o.ovf == true)
  {
    snprintf (reason, reason_size, "the build options do not fit in %d entries of %d bytes", FEED_GPU_OPTV_MAX, 1024);

    feed_optv_free (&o);

    hcfree (source);

    return NULL;
  }

  char *opts = feed_optv_join (&o);

  char key[64];

  feed_gpu_cache_key (hashcat_ctx, device_param, desc->name, opts, source, source_len, key, sizeof (key));

  char cache_file[1024];

  snprintf (cache_file, sizeof (cache_file), "%s/kernels/feed_%s.%s.kernel", folder_config->cache_dir, desc->name, key);

  feed_gpu_t *gp = (feed_gpu_t *) hcmalloc (sizeof (feed_gpu_t));

  memset (gp, 0, sizeof (feed_gpu_t));

  gp->hashcat_ctx = hashcat_ctx;
  gp->device_id   = device_id;
  gp->is_cuda     = device_param->is_cuda;
  gp->is_hip      = device_param->is_hip;
  gp->is_opencl   = device_param->is_opencl;
  gp->threads     = threads;

  snprintf (gp->name,        sizeof (gp->name),        "%s", desc->name);
  snprintf (gp->kernel_name, sizeof (gp->kernel_name), "%s", desc->kernel_name);

  // feed_gpu_term () decrements this, and it has to be counted from here so that the error paths
  // below, which all go through feed_gpu_term (), balance.

  feed_gpu_live_cnt++;

  bool ok = false;

  if (feed_device_bind (hashcat_ctx, device_param) == false)
  {
    snprintf (reason, reason_size, "the device could not be made current");
  }
  else
  {
    if (gp->is_cuda == true)
    {
      if (feed_gpu_build_cuda (gp, source, desc->kernel_file, cache_file, &o, reason, reason_size) == true)
      {
        if (hc_cuModuleGetFunction (hashcat_ctx, &gp->cu_function, gp->cu_module, gp->kernel_name) == -1)
        {
          snprintf (reason, reason_size, "%s is not in the module", gp->kernel_name);
        }
        else if (hc_cuStreamCreate (hashcat_ctx, &gp->cu_stream, CU_STREAM_NON_BLOCKING) == -1)
        {
          snprintf (reason, reason_size, "cuStreamCreate failed");
        }
        else
        {
          int max_threads = 0;

          if (hc_cuFuncGetAttribute (hashcat_ctx, &max_threads, CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK, gp->cu_function) == 0)
          {
            if ((max_threads > 0) && ((u32) max_threads < gp->threads)) gp->threads = (u32) max_threads;
          }

          ok = true;
        }
      }
    }
    else if (gp->is_hip == true)
    {
      if (feed_gpu_build_hip (gp, source, desc->kernel_file, cache_file, &o, reason, reason_size) == true)
      {
        if (hc_hipModuleGetFunction (hashcat_ctx, &gp->hip_function, gp->hip_module, gp->kernel_name) == -1)
        {
          snprintf (reason, reason_size, "%s is not in the module", gp->kernel_name);
        }
        else if (hc_hipStreamCreateWithFlags (hashcat_ctx, &gp->hip_stream, hipStreamNonBlocking) == -1)
        {
          snprintf (reason, reason_size, "hipStreamCreateWithFlags failed");
        }
        else
        {
          ok = true;
        }
      }
    }
    else
    {
      if (feed_gpu_build_opencl (gp, device_param, source, cache_file, opts, key, reason, reason_size) == true)
      {
        if (hc_clCreateKernel (hashcat_ctx, gp->cl_program_h, gp->kernel_name, &gp->cl_kernel_h) == -1)
        {
          snprintf (reason, reason_size, "%s is not in the program", gp->kernel_name);
        }
        else if (hc_clCreateCommandQueue (hashcat_ctx, device_param->opencl_context, device_param->opencl_device, 0, &gp->cl_queue) == -1)
        {
          // No CL_QUEUE_PROFILING_ENABLE. hashcat asks for it on its own queue because run_kernel ()
          // reads profiling info off it; this one is never measured that way and the flag costs per
          // command.

          snprintf (reason, reason_size, "clCreateCommandQueue failed");
        }
        else
        {
          size_t wgs = 0;

          if (hc_clGetKernelWorkGroupInfo (hashcat_ctx, gp->cl_kernel_h, device_param->opencl_device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (wgs), &wgs, NULL) == 0)
          {
            if ((wgs > 0) && (wgs < gp->threads)) gp->threads = (u32) wgs;
          }

          ok = true;
        }
      }
    }

    feed_device_unbind (hashcat_ctx, device_param);
  }

  hcfree (opts);
  hcfree (source);

  feed_optv_free (&o);

  if (ok == false)
  {
    feed_gpu_term (gp);

    return NULL;
  }

  return gp;
}

u32 feed_gpu_threads (const feed_gpu_t *gp)
{
  if (gp == NULL) return 0;

  return gp->threads;
}

// ---------------------------------------------------------------------------------------------
// the buffers a feed kernel reads and writes
// ---------------------------------------------------------------------------------------------

// Numbered rather than named, because a slot number is what a kernel argument list refers to and a
// name would have to be looked up on a path that runs per launch.

bool feed_gpu_alloc (feed_gpu_t *gp, const int slot, const size_t size, const feed_gpu_mem_t kind)
{
  if (gp == NULL) return false;

  if ((slot < 0) || (slot >= FEED_GPU_SLOTS_MAX)) return false;
  if (size == 0) return false;

  // Re-allocating a live slot would leak the old buffer, so it is refused rather than silently
  // replaced. A feed that wants a different size terminates and starts again.

  if (gp->slot[slot].size != 0) return false;

  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;

  hc_device_param_t *device_param = feed_device_param (hashcat_ctx, gp->device_id);

  if (feed_device_bind (hashcat_ctx, device_param) == false) return false;

  bool ok = false;

  if (gp->is_cuda == true)
  {
    ok = (hc_cuMemAlloc (hashcat_ctx, &gp->slot[slot].cu, size) == 0);
  }
  else if (gp->is_hip == true)
  {
    ok = (hc_hipMemAlloc (hashcat_ctx, &gp->slot[slot].hip, size) == 0);
  }
  else if (gp->is_opencl == true)
  {
    cl_mem_flags flags = CL_MEM_READ_WRITE;

    if (kind == FEED_GPU_MEM_READ)  flags = CL_MEM_READ_ONLY;
    if (kind == FEED_GPU_MEM_WRITE) flags = CL_MEM_WRITE_ONLY;

    ok = (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, flags, size, NULL, &gp->slot[slot].cl) == 0);
  }

  feed_device_unbind (hashcat_ctx, device_param);

  if (ok == true) gp->slot[slot].size = size;

  return ok;
}

bool feed_gpu_write (feed_gpu_t *gp, const int slot, const void *src, const size_t size)
{
  if (gp == NULL) return false;
  if (src == NULL) return false;

  if ((slot < 0) || (slot >= FEED_GPU_SLOTS_MAX)) return false;
  if (size == 0) return false;
  if (size > gp->slot[slot].size) return false;

  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;

  hc_device_param_t *device_param = feed_device_param (hashcat_ctx, gp->device_id);

  if (feed_device_bind (hashcat_ctx, device_param) == false) return false;

  bool ok = false;

  // On this feed's own stream, and then waited for, which is the same discipline feed_gpu_read ()
  // follows and for a sharper reason than symmetry. The synchronous cuMemcpyHtoD () is a NULL stream
  // operation, and a stream created CU_STREAM_NON_BLOCKING has no ordering edge to the NULL stream by
  // definition. For a pageable source the call may return with the transfer still outstanding, and
  // the launch that follows would then have no guarantee of seeing it. Putting the copy on the same
  // stream as the launch is what orders the two.

  if (gp->is_cuda == true)
  {
    ok = (hc_cuMemcpyHtoDAsync (hashcat_ctx, gp->slot[slot].cu, src, size, gp->cu_stream) == 0);

    if (ok == true) ok = (hc_cuStreamSynchronize (hashcat_ctx, gp->cu_stream) == 0);
  }
  else if (gp->is_hip == true)
  {
    ok = (hc_hipMemcpyHtoDAsync (hashcat_ctx, gp->slot[slot].hip, src, size, gp->hip_stream) == 0);

    if (ok == true) ok = (hc_hipStreamSynchronize (hashcat_ctx, gp->hip_stream) == 0);
  }
  else if (gp->is_opencl == true)
  {
    ok = (hc_clEnqueueWriteBuffer (hashcat_ctx, gp->cl_queue, gp->slot[slot].cl, CL_TRUE, 0, size, src, 0, NULL, NULL) == 0);
  }

  feed_device_unbind (hashcat_ctx, device_param);

  return ok;
}

// Reads back on this feed's own stream and waits for that stream alone. cuCtxSynchronize () is never
// called: it takes no stream and would wait on hashcat's work as well.

bool feed_gpu_read (feed_gpu_t *gp, const int slot, void *dst, const size_t size)
{
  if (gp == NULL) return false;
  if (dst == NULL) return false;

  if ((slot < 0) || (slot >= FEED_GPU_SLOTS_MAX)) return false;
  if (size == 0) return false;
  if (size > gp->slot[slot].size) return false;

  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;

  hc_device_param_t *device_param = feed_device_param (hashcat_ctx, gp->device_id);

  if (feed_device_bind (hashcat_ctx, device_param) == false) return false;

  bool ok = false;

  if (gp->is_cuda == true)
  {
    ok = (hc_cuMemcpyDtoHAsync (hashcat_ctx, dst, gp->slot[slot].cu, size, gp->cu_stream) == 0);

    if (ok == true) ok = (hc_cuStreamSynchronize (hashcat_ctx, gp->cu_stream) == 0);
  }
  else if (gp->is_hip == true)
  {
    ok = (hc_hipMemcpyDtoHAsync (hashcat_ctx, dst, gp->slot[slot].hip, size, gp->hip_stream) == 0);

    if (ok == true) ok = (hc_hipStreamSynchronize (hashcat_ctx, gp->hip_stream) == 0);
  }
  else if (gp->is_opencl == true)
  {
    ok = (hc_clEnqueueReadBuffer (hashcat_ctx, gp->cl_queue, gp->slot[slot].cl, CL_TRUE, 0, size, dst, 0, NULL, NULL) == 0);
  }

  feed_device_unbind (hashcat_ctx, device_param);

  return ok;
}

// ---------------------------------------------------------------------------------------------
// running one pass
// ---------------------------------------------------------------------------------------------

static bool feed_gpu_run_cuda (feed_gpu_t *gp, const u32 blocks, const feed_gpu_arg_t *args, const u32 arg_cnt)
{
  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;

  void *argv[FEED_GPU_ARGS_MAX];

  for (u32 i = 0; i < arg_cnt; i++)
  {
    if (args[i].kind == FEED_GPU_ARG_MEM)
    {
      argv[i] = &gp->slot[args[i].slot].cu;
    }
    else
    {
      argv[i] = (void *) args[i].val;
    }
  }

  if (hc_cuLaunchKernel (hashcat_ctx, gp->cu_function, blocks, 1, 1, gp->threads, 1, 1, 0, gp->cu_stream, argv, NULL) == -1) return false;

  if (hc_cuStreamSynchronize (hashcat_ctx, gp->cu_stream) == -1) return false;

  return true;
}

static bool feed_gpu_run_hip (feed_gpu_t *gp, const u32 blocks, const feed_gpu_arg_t *args, const u32 arg_cnt)
{
  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;

  void *argv[FEED_GPU_ARGS_MAX];

  for (u32 i = 0; i < arg_cnt; i++)
  {
    if (args[i].kind == FEED_GPU_ARG_MEM)
    {
      argv[i] = &gp->slot[args[i].slot].hip;
    }
    else
    {
      argv[i] = (void *) args[i].val;
    }
  }

  if (hc_hipLaunchKernel (hashcat_ctx, gp->hip_function, blocks, 1, 1, gp->threads, 1, 1, 0, gp->hip_stream, argv, NULL) == -1) return false;

  if (hc_hipStreamSynchronize (hashcat_ctx, gp->hip_stream) == -1) return false;

  return true;
}

static bool feed_gpu_run_opencl (feed_gpu_t *gp, const u32 blocks, const feed_gpu_arg_t *args, const u32 arg_cnt)
{
  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;

  for (u32 i = 0; i < arg_cnt; i++)
  {
    if (args[i].kind == FEED_GPU_ARG_MEM)
    {
      if (hc_clSetKernelArg (hashcat_ctx, gp->cl_kernel_h, i, sizeof (cl_mem), &gp->slot[args[i].slot].cl) == -1) return false;
    }
    else
    {
      if (hc_clSetKernelArg (hashcat_ctx, gp->cl_kernel_h, i, args[i].size, args[i].val) == -1) return false;
    }
  }

  const size_t local_work_size[1]  = { gp->threads };
  const size_t global_work_size[1] = { (size_t) blocks * (size_t) gp->threads };

  if (hc_clEnqueueNDRangeKernel (hashcat_ctx, gp->cl_queue, gp->cl_kernel_h, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return false;

  if (hc_clFinish (hashcat_ctx, gp->cl_queue) == -1) return false;

  return true;
}

// One launch of items work items, on this feed's own stream, waited for before returning.
//
// The stream is the feed's own and never hashcat's. hashcat's cuda_stream does not exist when
// thread_init () runs and is already destroyed when thread_term () runs, and sharing it would put
// these launches inside the cuEventRecord pair run_kernel () uses to time the cracking kernel, which
// is the Exec column, --spin-damp and the TDR abort.
//
// A launch is refused while autotune is measuring. Nothing can reach here during that window today,
// because autotune joins its own threads before any calc thread exists and every producer thread is
// started from a calc thread. Checking rather than commenting is what keeps that true when somebody
// adds a background warm up.

bool feed_gpu_run (feed_gpu_t *gp, const u64 items, const feed_gpu_arg_t *args, const u32 arg_cnt)
{
  if (gp == NULL) return false;
  if (items == 0) return false;

  if (arg_cnt > FEED_GPU_ARGS_MAX) return false;
  if ((arg_cnt > 0) && (args == NULL)) return false;

  for (u32 i = 0; i < arg_cnt; i++)
  {
    if (args[i].kind == FEED_GPU_ARG_MEM)
    {
      if ((args[i].slot < 0) || (args[i].slot >= FEED_GPU_SLOTS_MAX)) return false;
      if (gp->slot[args[i].slot].size == 0) return false;
    }
    else
    {
      if (args[i].val  == NULL) return false;
      if (args[i].size == 0) return false;
    }
  }

  hashcat_ctx_t *hashcat_ctx = gp->hashcat_ctx;

  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (status_ctx != NULL)
  {
    if (status_ctx->devices_status == STATUS_AUTOTUNE) return false;
  }

  // One launch is one grid, a grid is counted in 32 bit blocks, and the work item count the kernel is
  // told about is a 32 bit number too. A feed with more work than that splits it, which it has to do
  // anyway to have somewhere to put the answer.
  //
  // Both bounds are checked and not just the block count, and the block count is then handed down
  // rather than worked out again per backend. Computing it a second time in 32 bit is what defeats
  // the check: for an item count within the top gp->threads values of the range, items + threads - 1
  // wraps to less than threads and the quotient is zero, so the launch is a grid of nothing. A
  // correct kernel then writes nothing, the runtime reports success, and the feed reads whatever was
  // in the buffer before as the answer.

  if (items > 0xffffffffULL) return false;

  const u64 blocks = (items + gp->threads - 1) / gp->threads;

  if (blocks > 0x7fffffffULL) return false;

  hc_device_param_t *device_param = feed_device_param (hashcat_ctx, gp->device_id);

  if (feed_device_bind (hashcat_ctx, device_param) == false) return false;

  bool ok = false;

  if (gp->is_cuda == true)
  {
    ok = feed_gpu_run_cuda (gp, (u32) blocks, args, arg_cnt);
  }
  else if (gp->is_hip == true)
  {
    ok = feed_gpu_run_hip (gp, (u32) blocks, args, arg_cnt);
  }
  else if (gp->is_opencl == true)
  {
    ok = feed_gpu_run_opencl (gp, (u32) blocks, args, arg_cnt);
  }

  feed_device_unbind (hashcat_ctx, device_param);

  return ok;
}

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_FEED_H
#define HC_FEED_H

// What a feed is, from the feed's side. This header is the whole of the contract and a feed
// includes nothing else of the subsystem.
//
// The core's own driver functions live in feed_ctx.h and are not visible here on purpose. Both
// halves would otherwise sit in one header, letting every feed see and call the functions hashcat uses to
// drive feeds, and a feed that called one of them would be reaching into the core's own bookkeeping
// from a plugin thread. Splitting the header by audience is what makes that impossible to write by
// accident rather than merely wrong.
//
// The generic_* names are named for the attack mode, ATTACK_MODE_GENERIC, and they stay.

// The oldest plugin interface hashcat still accepts. A feed declares which interface it was built
// against with GENERIC_PLUGIN_VERSION, and it takes that number from FEEDS_INTERFACE_VERSION_CURRENT
// on the compile line, the same way a module takes MODULE_INTERFACE_VERSION_CURRENT. A feed must not
// declare this constant instead, because then a rebuild would re-declare compatibility that the
// source has not earned.

#if defined (HC_PLUGIN_ABI_MISSING)
#error "a feed names the plugin interface it is built against: -DHC_PLUGIN_ABI_VERSION=<n>, see docs/hashcat-plugin-development-guide.md"
#endif

// What a call into a feed did. thread_next () returns the candidate length on success, so only the
// negative values are listed here and they must stay negative.
//
// Telling an empty feed apart from a broken one matters: a feed that has run out has finished the
// attack, and a feed that has failed has abandoned it. Reporting the second as the first ends the
// session with "Exhausted" and an exit status that says everything went fine.

#define GENERIC_RC_EOF   -1
#define GENERIC_RC_ERROR -2

// What global_keyspace () may say. A feed that cannot count itself returns GENERIC_KEYSPACE_UNKNOWN
// and hashcat runs it without a denominator. GENERIC_KEYSPACE_ERROR is hashcat's own value and a
// plugin never returns it, it is what the wrapper reports when the plugin failed. The two were the
// same value once, so a feed that could not open its input became an endless feed instead of a
// stopped session.

#define GENERIC_KEYSPACE_UNKNOWN ((u64) -1)
#define GENERIC_KEYSPACE_ERROR   ((u64) -2)

typedef enum generic_plugin_options
{
  GENERIC_PLUGIN_OPTIONS_AUTOHEX   = 1 << 0,
  GENERIC_PLUGIN_OPTIONS_ICONV     = 1 << 1,
  GENERIC_PLUGIN_OPTIONS_RULES     = 1 << 2,

  // The feed can amplify on the device. It then also exports global_dev_init () and
  // thread_next_dev (), and hashcat runs the device engine kernel instead of the straight one.

  GENERIC_PLUGIN_OPTIONS_DEVICE       = 1 << 3,

  GENERIC_PLUGIN_OPTIONS_UNDEFINED = 0,

} generic_plugin_options_t;

// What a feed hands the core. A feed is the one plugin the core still resolves by name rather than
// through a context it was given, so this is the list, and it is ten names instead of one. They are
// declared here so that a feed and the loader read the same shapes out of one file, and so that a
// built feed exports these and nothing else.
//
// generic_global_ctx_t and generic_thread_ctx_t are in types.h rather than here, because
// generic_ctx_t holds both of them and sits inside hashcat_ctx_t. A feed includes types.h anyway.

HC_PLUGIN_ENTRY extern const int GENERIC_PLUGIN_VERSION;
HC_PLUGIN_ENTRY extern const int GENERIC_PLUGIN_OPTIONS;

HC_PLUGIN_ENTRY bool global_init     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx);
HC_PLUGIN_ENTRY void global_term     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx);
HC_PLUGIN_ENTRY u64  global_keyspace (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx);

HC_PLUGIN_ENTRY bool thread_init     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx);
HC_PLUGIN_ENTRY void thread_term     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx);
HC_PLUGIN_ENTRY int  thread_next     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size);
HC_PLUGIN_ENTRY bool thread_seek     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u64 offset);

// The two a feed only exports when it advertises GENERIC_PLUGIN_OPTIONS_DEVICE.
//
// global_dev_init () hands over the read only pool every cell indexes into, and says how wide the
// device side inner loop should be. thread_next_dev () answers with a base candidate and the cell
// that extends it, where thread_next () would have answered with one finished candidate.
//
// maxword is how many words the kernel must give a candidate, which the feed settles from the ruleset
// because the right answer is a property of the ruleset. It reaches the kernel as a build option, so
// it has to be known before the backend compiles anything, and it is: this runs from
// generic_ctx_init (), which is ahead of backend_session_begin ().
//
// One call to thread_next_dev () therefore stands for il_cnt candidates, and the feed's own position
// advances by that many. Its keyspace, its seek and its ordering are the same object either way.

// varlen says whether a slot's bucket may hold entries of more than one byte length, which decides how
// the kernel reaches an entry and whether the candidate's length is a constant of the cell. Like
// maxword it is a property of the ruleset, it reaches the kernel as a build option, and it has to be
// in the kernel cache key. See PCFG_DEV_VARLEN.

// probe is a cell for the autotuner to search the accel with. It is one the feed actually emitted
// rather than one assembled out of averages, because a zeroed or invented cell makes the accel search
// tune a launch that never runs and nothing downstream can tell.

HC_PLUGIN_ENTRY bool global_dev_init (generic_global_ctx_t *global_ctx, const u32 **pool, u64 *pool_size, u32 *il_cnt, u32 *avg, u32 *maxword, u32 *front, u32 *step, u32 *varlen, pcfg_cell_t *probe);

HC_PLUGIN_ENTRY int  thread_next_dev (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size, pcfg_cell_t *cell);

// A third one beside those two, and the only one a feed may leave out once it has said it runs on
// the device: how many candidates lie between two base words, which is what a run bounded by --skip
// and --limit is measured against. A feed that does not export it is measured against the mean cell
// instead, and a mean is short wherever the window is not an average one.

HC_PLUGIN_ENTRY u64  global_dev_span (generic_global_ctx_t *global_ctx, const u64 from, const u64 upto);

// ---------------------------------------------------------------------------------------------
// what the device is doing while a feed runs
// ---------------------------------------------------------------------------------------------

// The device a feed's thread belongs to is current inside thread_init (), thread_term (),
// thread_next () and thread_seek (), whichever of the four core threads made the call. A feed that
// wants to talk to that device may simply do so.
//
// This is a promise the core makes rather than a rule a feed follows, because the ways to get it
// wrong are not diagnosable by whoever gets it wrong. Popping a CUDA context into
// device_param->cuda_context rather than into a local corrupts hashcat's own handle from another
// thread, and it surfaces later as an unrelated failure in the calc thread.
//
// Two things the core cannot do on a feed's behalf, and a feed still has to respect both.
//
// A context must never be cached across calls. backend_session_context_reset () destroys and
// recreates every CUDA context on each outer loop iteration after the first, so a CUcontext read
// once and kept is a stale handle. Read device_param->cuda_context each time it is needed, or let
// the feed_gpu_* helpers below do it.
//
// HIP has no context handle at all. device_param->hip_context is dead, and hipSetDevice () is
// thread local rather than per call, so what makes a HIP device current is a property of the thread
// and not of a handle a feed could hold.

// hashcat's own record for the device a feed thread belongs to, borrowed. Pass
// thread_ctx->device_id. Returns NULL when there is no backend or the id names no device.

HC_PLUGIN_API hc_device_param_t *feed_device_param (hashcat_ctx_t *hashcat_ctx, const int device_id);

// ---------------------------------------------------------------------------------------------
// saying things
// ---------------------------------------------------------------------------------------------

// Where a feed says anything it has to say. event_log_info () and event_log_warning () both write to
// stdout and neither is guarded by --quiet, and under --stdout that stream is the candidate list, so
// a helpful line would be handed to whatever is on the other end of the pipe as a password to try.
//
// This knows where to put it instead: nowhere under --quiet, on stderr under --stdout, and on the
// screen otherwise. The line most worth saying is usually that a device was declined and the run is
// now a great deal slower, and swallowing that is how a session silently takes a week.

// Named here as well as in shared.h, because a feed includes this header and need not include that
// one. mingw's printf is not the C library's, so the format attribute has to name which one.

#ifndef __MINGW_PRINTF_FORMAT
#define __MINGW_PRINTF_FORMAT printf
#endif

HC_PLUGIN_API __attribute__ ((format (__MINGW_PRINTF_FORMAT, 2, 3))) void feed_say (hashcat_ctx_t *hashcat_ctx, const char *fmt, ...);

// ---------------------------------------------------------------------------------------------
// a feed's own kernel
// ---------------------------------------------------------------------------------------------

// A feed that has work the device can do better than the host writes one .cl file and calls the six
// functions below. CUDA, HIP and OpenCL do not appear in it, and neither does the cache, the build
// options, the stream, or the twenty reasons a device may turn out not to be usable.
//
// The shape this serves is a feed that has an index range and wants an answer per index: a filter
// that says which candidates are worth trying, or a generator that fills a buffer. What it does not
// serve is a feed that wants to write into a buffer hashcat owns, because nothing on this side of
// the boundary can be given one.
//
// One of these belongs to one (feed, device) pair. Build it in thread_init () and give it back in
// thread_term (), which the core runs one device at a time on the main thread; that is what makes
// the shared program borrow below safe without a lock.

typedef struct feed_gpu feed_gpu_t;

#define FEED_GPU_SLOTS_MAX 8
#define FEED_GPU_ARGS_MAX  16

// What the kernel does with a buffer. It picks the OpenCL memory flags and is ignored by CUDA and
// HIP, which have no equivalent.

typedef enum feed_gpu_mem
{
  FEED_GPU_MEM_READ  = 0, // the kernel reads it and the host writes it
  FEED_GPU_MEM_WRITE = 1, // the kernel writes it and the host reads it
  FEED_GPU_MEM_RW    = 2,

} feed_gpu_mem_t;

typedef enum feed_gpu_arg_kind
{
  FEED_GPU_ARG_MEM = 0, // one of this feed's slots
  FEED_GPU_ARG_VAL = 1, // an immediate: size bytes read through val at launch

} feed_gpu_arg_kind_t;

// One kernel argument. The array is positional, so args[i] is the kernel's i'th parameter. An
// immediate is read through val at launch and the launch is waited for before the call returns, so
// pointing it at a local is safe.

typedef struct feed_gpu_arg
{
  feed_gpu_arg_kind_t kind;

  int                 slot; // FEED_GPU_ARG_MEM
  const void         *val;  // FEED_GPU_ARG_VAL
  size_t              size; // FEED_GPU_ARG_VAL

} feed_gpu_arg_t;

typedef struct feed_gpu_desc
{
  // Names the cache entry, so that two feeds building two different kernels cannot collide over one
  // file. Letters, digits, dash, underscore and dot only, because it becomes part of a path.

  const char *name;

  // The kernel source, a plain file name in hashcat's own kernel folder beside hashcat's own. It is
  // read through cpath_real, and its contents go into the cache key, so editing it in place is
  // enough to invalidate the build.

  const char *kernel_file;

  // The entry point inside it.

  const char *kernel_name;

  // Extra -D and friends, split on whitespace because NVRTC and HIPRTC take an array. A value
  // containing a space does not survive that split. May be NULL.

  const char *build_options;

  // Work items per group. Zero takes the layer's default. It is also what HIP is told to budget
  // registers for, so it is fixed before the build rather than after, and the real value may come
  // back lower: ask feed_gpu_threads () once the kernel is up.

  u32 threads;

  // An OpenCL CPU device is the same silicon a feed's host path already runs on, plus a cold build
  // to get there, so it is declined unless a feed says its kernel is worth it there anyway.

  bool allow_opencl_cpu;

} feed_gpu_desc_t;

// Returns NULL and a sentence in reason for every reason not to use this device, and none of them is
// fatal: a feed keeps its host path as the fallback and as the reference the device is checked
// against. Say the sentence with feed_say ().

HC_PLUGIN_API feed_gpu_t *feed_gpu_init (hashcat_ctx_t *hashcat_ctx, const int device_id, const feed_gpu_desc_t *desc, char *reason, const size_t reason_size);
HC_PLUGIN_API void        feed_gpu_term (feed_gpu_t *gp);

// What the kernel actually got, which is the descriptor's threads or the lower number the device
// said it would run.

HC_PLUGIN_API u32 feed_gpu_threads (const feed_gpu_t *gp);

// One device buffer per slot. A slot cannot be re-allocated while it holds a buffer, because that
// would leak the old one; a feed that wants a different size terminates and starts again.

HC_PLUGIN_API bool feed_gpu_alloc (feed_gpu_t *gp, const int slot, const size_t size, const feed_gpu_mem_t kind);
HC_PLUGIN_API bool feed_gpu_write (feed_gpu_t *gp, const int slot, const void *src, const size_t size);
HC_PLUGIN_API bool feed_gpu_read  (feed_gpu_t *gp, const int slot, void *dst, const size_t size);

// One launch of items work items, on a stream this feed owns, waited for before returning. Refused
// while autotune is measuring, so that a launch cannot land inside hashcat's own timing window.

HC_PLUGIN_API bool feed_gpu_run (feed_gpu_t *gp, const u64 items, const feed_gpu_arg_t *args, const u32 arg_cnt);

// ---------------------------------------------------------------------------------------------
// a feed's own settings
// ---------------------------------------------------------------------------------------------

// How a feed says what it takes. A feed is handed its arguments as strings and nothing parses them
// for it: hashcat's own getopt stops at the plugin name, because it cannot know which plugin that is
// until long after the command line has been read. So a feed that wants named settings reads them
// out of its own arguments, and this is the shape they are declared in so that every feed reads
// them the same way and none of them has to write a parser.
//
// A setting is written key=value among the sources, "myfeed model.dat mode=2 pwlen=6:16". They are
// arguments and not options on purpose: the brain hashes every one of them into the attack id
// (src/brain.c), and the restore file records them, so two runs that differ only in a setting are
// two attacks and a resumed run gets the settings it started with. A named option outside the work
// arguments would have neither, and getting that wrong is silent.
//
// min and max bound a FEED_PARAM_TYPE_U64 and are ignored by the other types.

typedef enum feed_param_type
{
  FEED_PARAM_TYPE_STR  = 0, // dst is a const char **, and it points into the argument
  FEED_PARAM_TYPE_BOOL = 1, // dst is a bool *, value is 1/0, yes/no, true/false, on/off
  FEED_PARAM_TYPE_U64  = 2, // dst is a u64 *
  FEED_PARAM_TYPE_DBL  = 3, // dst is a double *

} feed_param_type_t;

typedef struct feed_param
{
  const char        *key;
  feed_param_type_t  type;
  void              *dst;

  u64                min;
  u64                max;

  const char        *help;

} feed_param_t;

HC_PLUGIN_API bool        feed_param_is_setting (const char *arg);
HC_PLUGIN_API const char *feed_param_lookup     (const int workc, char * const *workv, const char *key);
HC_PLUGIN_API bool        feed_param_parse      (const int workc, char * const *workv, const feed_param_t *params, char *err_buf, const size_t err_size);
HC_PLUGIN_API int         feed_param_usage      (const feed_param_t *params, char *out_buf, const size_t out_size);

#endif // HC_FEED_H

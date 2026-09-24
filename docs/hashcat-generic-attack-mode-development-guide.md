
# Attack mode 8 feed development guide

---

## General

Attack mode 8 provides a standard interface for extending hashcat with custom candidate generators. The assimilation bridge replaces or supplements hash computation, while a feed operates on the input side of the pipeline and supplies password candidates.

Candidate generators are often standalone tools connected through standard input. The user guide, `docs/hashcat-generic-attack-mode.md`, explains the limitations of that approach and should be read before this development guide.

This document explains how to implement a feed for attack mode 8.

## What is a feed?

From a technical perspective, a feed is a dynamically loaded library (`.so`, `.dll`, `.dylib`) that hashcat loads at startup. Attack mode 8 itself does not provide generator logic. Instead, the user selects a feed by name as the first parameter on the command line, the same way `-m` selects a module.

hashcat looks for that name under the `feeds/` directory in its shared data path, trying `feed_<name>`, then `rust_<name>`, then `<name>`. So `hashcat -a 8 hashes.txt wordlist mydict.txt` finds the shipped wordlist feed. If none of those exist, the name is used as a path, which is what you want while developing a feed that is not installed yet.

This design supports any number of feeds, including plugins bundled with hashcat and private feeds for specialized workflows.

## Example feeds

Four small feeds serve as interface examples. Between them they cover the three shapes a feed can have: one that can seek freely, one that can only start over, and one that cannot go back at all.

Other shipped feeds implement complete attacks. The PCFG and table feeds run `-a 4` and `-a 5`, while the association feed supplies account-derived candidates to `-a 9`. The mask and hybrid feeds handle the rule-bearing forms of `-a 3` and the hybrid attacks. The wordlist feed also supplies the word-based legacy modes, including `-a 0`.

1. `feed_wordlist`

	- The seekable wordlist loader that ordinary `-a 0` now uses
	- Takes any number of wordlists and directories, laid end to end into a single keyspace
	- Because it is one keyspace rather than one attack per file, `--skip` and `--limit` address the whole set rather than each file
	- Uses a seek database instead of the traditional dictstat file, allowing efficient random access without repeatedly calling `thread_next()`
	- Direct range seeking is especially useful on multi-GPU systems

2. `feed_stdin`

	- Reads candidates from a pipe, and is what `-a 0` with no wordlist runs
	- The only shipped feed that **cannot seek directly**. The candidate at offset N is whichever value arrives next, so the offset does not refer to persistent input
	- Callback `thread_seek()` accepts the requested offset and continues reading. Refusing would cause a hard error, so a second device joining the attack would terminate the run
	- A mutex inside the plugin distributes each line exactly once regardless of how many devices request input. Unlike a seekable feed where each thread opens its own resources, a socket, queue or other single stream must be shared
	- One form of seek requires special handling. When a transform can shorten an overlength candidate, hashcat seeks back to the offset it just read and calls `thread_next()` again with a larger buffer. The plugin retains that line and returns it again instead of consuming the following candidate
	- Reports an unknown keyspace
	- Options `--skip`, `--limit` and `--restore` still work because hashcat reaches a stream offset by reading and discarding every preceding candidate. The same stream must be supplied again in the same order

3. `feed_random`

	- A random password generator, and the smallest feed that is still correct, in C
	- Generates a deterministic pseudorandom sequence. Candidate N exists only after the preceding N candidates have been produced, making this the simplest replay-based feed
	- Callback `thread_seek()` reseeds and replays the sequence, as any deterministic probabilistic generator must
	- Because the sequence is a pure function of a fixed seed, every device produces the same word for the same offset, so hashcat can split the range across devices and `--restore` lands on the word it left off at. A generator seeded from the clock or from a thread id can do neither
	- Reports an unknown keyspace

4. `rust_random`

	- Reimplements the same generator in Rust and produces byte-identical candidates
	- Demonstrates two things:
	  a) a feed that does not report a keyspace
	  b) feeds do not need to be written in C to be efficient
	- Because it matches `feed_random` word for word, the two can be diffed against each other to check a port

## Dedicated attack-mode numbers

A feed is normally named on the command line after `-a 8`. A feed that ships with hashcat can instead be given an attack-mode number, so that the user never types the plugin name.

Attack mode 4 is the dedicated alias for the PCFG feed. Function `user_options_alias_attack_mode()` in `src/user_options.c` rewrites the command line before downstream code reads it:

```
./hashcat -m 0 -a 4 hashes.txt ruleset            what the user types
./hashcat -m 0 -a 8 hashes.txt pcfg ruleset       what hashcat runs
```

The rewrite inserts the plugin name and leaves everything else where it was, so `workv[0]` still holds the plugin name and the feed cannot determine which spelling the user used. Both spellings therefore produce the same run and the same brain session.

Alias `-a 5` performs the same rewrite for the table feed, rewritten into `-a 8 hashes.txt table wordlist table-file`. The function also expresses `-a 1`, `-a 6` and `-a 7` as the unified hybrid mode `-a 12`. If rules are supplied, those modes and `-a 12` use the hybrid feed, while `-a 3` uses the mask feed. Without rules, `-a 3` keeps its device-side mask engine and the hybrid modes remain `-a 12`.

Other modes select feeds without this command-line rewrite. The wordlist and stdin feeds supply the word-based attacks, and `-a 9` selects the association, PCFG or wordlist feed for each phase of the account-aware attack.

## Design philosophy

The interface is intentionally small so feed authors can focus on candidate generation without requiring extensive knowledge of hashcat internals.

Feeds can also restore or replace legacy attack modes. Early implementations reproduced the former permutation and table attacks. An unused legacy number can become a feed alias. For example, attack mode 4 previously selected toggle-case and now selects PCFG.

## Required functions

Every feed must export the seven functions below. The loader refuses a feed if any one is missing. Callback `thread_next()` is the hot path that produces candidates. The other functions define its lifetime, keyspace and positioning.

### Main function

```
int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
```

This function is called whenever hashcat needs the next password candidate. Write it into `out_buf`, never writing more than `out_size` bytes, and return its length. The two custom data types are simple structures holding only basic primitives.

### Full function set

```
bool global_init     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx);
void global_term     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx);
u64  global_keyspace (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx);
bool thread_init     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx);
void thread_term     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx);
int  thread_next     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size);
bool thread_seek     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u64 offset);
```

### The hashcat context

hashcat passes the complete `hashcat_ctx_t` to all three global functions. Most feeds do not need to inspect it. Use `feed_say()` for user-facing messages so output follows `--quiet` and `--stdout`. The section on output routing below explains why.

### The global feed context

Structure `generic_global_ctx_t` provides storage shared by every feed thread.

```
typedef struct generic_global_ctx
{
  bool   quiet;

  int    workc;
  char **workv;

  char  *profile_dir;
  char  *cache_dir;
  char  *shared_dir;

  char   guess_base[256];

  u64          segments_cnt;
  const char **segment_names;
  const u64   *segment_first;

  u64 source_ident;
  u64 dev_total;

  bool dev_enable;
  bool described;

  bool   error;
  char   error_msg[256];

  void  *gbldata; // super generic

} generic_global_ctx_t;
```

Notes:

- The feed interface version identifies the structure layout. hashcat rejects a library built for an incompatible version instead of interpreting fields at incorrect offsets.
- Fields `workc` and `workv` contain the positional command-line arguments for attack mode 8. A wordlist feed, for example, can retrieve its filename from these fields. The feed name is always in `workv[0]`, placing the first feed argument in `workv[1]`. This also applies to a feed with a dedicated attack-mode number because hashcat inserts the feed name during alias expansion.
- Field `cache_dir` identifies storage for data hashcat can rebuild. It is `<cache directory>/cache` by default and follows `--cache-path` when set, allowing several systems to share one cache. Store feed data under `cache_dir/feeds/<feed name>` so its owner is clear.

  The `feeds` directory may not exist, so create it with `hc_mkdir_rec()` only when writing. A cache filename should include every input that determines its contents, allowing another system to validate and reuse it. Treat the directory as potentially read-only. Write only after rebuilding data, continue using the in-memory result if the write fails and do not turn a cache-write failure into a session error.
- `shared_dir` is where hashcat keeps shipped data such as feeds and rulesets.
- Field `guess_base` supplies the text inside `Guess.Base.......: Feed (...)`. Set it during `global_init()` when the plugin name alone is not informative. For example, `Feed (rockyou.pcfg)` identifies the active ruleset while `Feed (pcfg)` does not. Leave it empty to use the plugin name.
- The three `segment_*` fields describe several named sources concatenated into one keyspace. Publish each starting offset in ascending order and the status display identifies the active source, for example `Guess.Base.......: Feed ([6/18] d06.txt)`. Leave `segments_cnt` at zero when the feed has no segments.

  Populate these fields only after the offsets are known. The wordlist feed does so in `global_keyspace()` rather than `global_init()` because each starting offset depends on the counts of all earlier sources. The arrays and strings must remain valid until `global_term()`, where the feed releases them.
- Field `source_ident` identifies the data read by the feed without exposing its format. Set it during `global_init()` or `global_keyspace()` when possible. The brain includes this value in the attack identity, preventing changed input at the same path from being mistaken for completed work.

  A path alone is insufficient because its contents can change. The wordlist feed combines fingerprints derived from each file's size, beginning and end, reusing the data that names its seek database. Leave the field at zero when the source cannot be identified, as the stdin feed does.
- `dev_total` can provide the exact candidate total for a device-amplifying feed when an integer average would lose information.
- `dev_enable` indicates before `global_init()` whether the feed's device engine will be used.
- `described` lets a feed report that it answered a descriptive query and no candidate loop should start.
- The global error field belongs only to the three global functions. Per-device functions report failures through their thread context. Set the field only for an actual error, not for end of input, and place an explanatory message in `error_msg`.
- Use `feed_say()` for user-facing messages. It handles `--quiet` and routes output safely when `--stdout` is active.

### The thread feed context

Global functions receive the complete array of thread contexts. Thread functions receive only the context for the current thread.

## Describing how a candidate was made

Option `--debug-mode` records how a base word became a cracked candidate. Its first five modes name a rule, which a feed that generates candidates itself has none of. A feed declaring `GENERIC_PLUGIN_OPTIONS_EXPLAIN` also exports `global_explain()`, which hashcat calls to fill the rule field. Mode 6 always asks it. Modes 1, 3, 4 and 5 ask it when the run has no rules, which is why those work in a feed attack without `-r`.

Callback `global_explain()` receives the same four inputs used by `pcfg_expand()` to reconstruct a candidate: the cell the base word was given, the pool that cell points into, the base word, and which of the cell's candidates this was. Decompose `il_pos` into digits exactly as `pcfg_expand ()` does, or the two will disagree about which entry was used, and then write what those digits mean in your own terms. The table feed writes the substitutions that fired, `football->basketball,man->woman`. The pcfg feed writes the terminals it picked.

It runs once per crack rather than once per candidate, so it may take its time: searching a few hundred buckets to map a slot back to what produced it is cheaper than carrying that mapping through the hot loop.

Report only what a reader could not already see. An unchanged token conveys no additional information, and naming it for every token the word happens to contain buries the ones that mattered.

hashcat rejects an unsupported debug mode with an explanatory message instead of creating an empty file. That covers mode 6 and, when there are no rules, the modes that carry a rule field: 1, 3, 4 and 5. Mode 2 writes the base word alone, so it is allowed either way.

The thread context is feed-defined. Its default definition is:

```
typedef struct generic_thread_ctx
{
  bool   error;
  char   error_msg[256];

  int    device_id;

  void  *thrdata; // super generic

} generic_thread_ctx_t;
```

Callbacks `thread_init()`, `thread_term()`, `thread_next()` and `thread_seek()` report failures through the thread context rather than the global context. Each runs on one device thread, and a shared flag could incorrectly attribute one device's failure to all devices. hashcat prints the message and clears the flag after each call.

### Functions

hashcat can use multiple compute devices. Each device has its own candidate generator thread. This improves performance and keeps the design simple. hashcat coordinates their positions through the feed's `thread_seek()` callback.

For example, if your feed reads from a wordlist, the normal way is to open the file once per thread. Each thread maintains its own file handle. hashcat calls `thread_seek()` with the offset where each thread should start.

It is also possible to open the file only once in the global function and then distribute data to threads using pipes. This approach is more complex but can support a source that must be shared.

- `global_init()`

Callback `global_init()` runs once at startup before thread creation. Allocate shared resources here and store their pointers in `gbldata`.

- `global_term()`

Callback `global_term()` runs once before hashcat exits. Close files, free memory and release all resources created by `global_init()`.

- `global_keyspace()`

Required callback `global_keyspace()` runs once at startup. Return the total number of candidates produced from the command-line arguments, such as the number of words in a wordlist.

Count every position the feed will emit, including candidates that hashcat later rejects for length or a failed encoding conversion. Rejections belong in the `Rejected` counter, not in a smaller keyspace, and a keyspace that skips them cannot support offset-based seeking.

If the number cannot be calculated easily, return `GENERIC_KEYSPACE_UNKNOWN`. In that case, hashcat will not display progress or ETA. You still need to signal the end of candidates later in `thread_next()`.

If the keyspace cannot be determined because something went wrong, set the error flag instead. Reporting an unknown keyspace for a failure turns a broken feed into an endless one.

- `thread_init()`

Callback `thread_init()` runs once for each device thread before cracking begins. Allocate thread-local state here and store it in `thrdata`. Field `device_id` already identifies the backend device supplied by this thread.

- `thread_term()`

Callback `thread_term()` runs once for each thread during shutdown. Close and free the resources created by `thread_init()`.

- `thread_seek()`

Callback `thread_seek()` positions a thread's generator at an absolute offset. After it returns, hashcat calls `thread_next()` to request candidates beginning at that position.

If the generator cannot seek directly, advance its state until it reaches the requested offset. Store the current position in the per-thread data. Feed `feed_random` is a worked example of this approach.

hashcat does not call this function when the generator is already at the requested offset, so a sequential single-device run requires only one seek. Handle a backward offset anyway. With several devices the offsets interleave, and a `--skip` or a `--restore` can land anywhere.

On failure, return false and set the error flag with a reason. A failed seek terminates the session and must not be reported as end of input.

- `thread_next()`

Callback `thread_next()` is mandatory and follows these rules:

* Copy the next candidate into `out_buf[]`.
* Never write more than `out_size` bytes. hashcat usually provides a pointer directly into the device upload buffer, leaving no additional space and no later bounds check.
* Return the candidate length. The explicit length makes a terminating zero unnecessary.
* If the candidate is longer than `out_size`, write the first `out_size` bytes and still return the real length. Returning the clipped length instead would hand hashcat a candidate that your generator never produced.
* Parameter `out_size` is not constant and must not be cached. Its normal value is 256. When an overlength input can be shortened by a transform, such as hex wordlist decoding, `$HEX[]` interpretation or character-set conversion, hashcat seeks back and requests the candidate again with a larger buffer. This allows a 512-byte hexadecimal line to represent a 256-byte password. Without a shortening transform, an overlength candidate is rejected and counted under `Rejected`.
* If you reach the end of your keyspace, return `GENERIC_RC_EOF`. Do not set the error flag in this case.
* Return `GENERIC_RC_SKIP` when a counted position produces no candidate. The position remains consumed, the next call advances to the following offset and hashcat includes the skipped position in `Rejected`.

  This return code supports generators that know the number of positions before resolving the candidate at each one. Stable positions are required by `--skip`, `--limit` and restore. A generator that produces a candidate at every position does not need it. Attack mode 9 rejects this result because candidate N must pair with salt N and an empty position has no valid substitute.
* Set the error flag when generation fails. hashcat then ends the session with an error status. Returning `GENERIC_RC_EOF` would incorrectly report a truncated run as cleanly exhausted.

## Global and thread contexts

hashcat supports compute devices with very different performance characteristics. For example, a session may include one CPU and five GPUs, each with different speeds. To feed each device efficiently, hashcat creates a separate thread per device.

This is why there are two context structures:

- `global_ctx` is shared by all threads.
- `thread_ctx` belongs to one thread.

## Global and thread functions

There are two categories of functions:

- Global functions handle initialization, termination and keyspace reporting.
- Thread functions handle initialization, termination, seeking and candidate generation.

Examples:

- Global initialization performs setup shared by every thread, such as building a table of byte offsets for a wordlist.
- Thread initialization prepares per-thread resources. Each thread can open its own file handle, for example, avoiding synchronization around one global handle.

A feed can centralize shared work in global functions and leave independent resources to each thread. The appropriate division depends on the candidate source.

## Using the device

A feed normally runs on the host, while its compute device can remain idle during expensive candidate generation. A feed can use that device for work it performs more efficiently.

### The device is current

The device this thread feeds is current inside `thread_init()`, `thread_term()`, `thread_next()` and `thread_seek()`. You do not have to make it current yourself and you should not try.

The core provides this guarantee because manual context management can fail in ways that are difficult to diagnose. Four different hashcat threads can call a feed, and historically only one made the device current. A feed therefore had to push and pop the context around every device call. Storing a popped CUDA context in `device_param->cuda_context` instead of a local variable could corrupt a handle owned by another thread and surface later as an unrelated failure.

Two requirements still apply:

* **Never cache a context across calls.** hashcat destroys and recreates each CUDA context on every outer-loop iteration after the first. A retained `CUcontext` therefore becomes stale. Read it for each call or use the helpers below.
* **HIP has no context handle.** The current HIP device is a property of the calling thread, not a persistent handle.

Helper `feed_device_param(hashcat_ctx, thread_ctx->device_id)` returns hashcat's record for the device supplied by the current thread, or `NULL` when no backend is available.

### Running your own kernel

Place one `.cl` file beside hashcat's kernels and use the following six functions:

```c
feed_gpu_t *feed_gpu_init (hashcat_ctx_t *hashcat_ctx, const int device_id, const feed_gpu_desc_t *desc, char *reason, const size_t reason_size);
void        feed_gpu_term (feed_gpu_t *gp);

bool feed_gpu_alloc (feed_gpu_t *gp, const int slot, const size_t size, const feed_gpu_mem_t kind);
bool feed_gpu_write (feed_gpu_t *gp, const int slot, const void *src, const size_t size);
bool feed_gpu_read  (feed_gpu_t *gp, const int slot, void *dst, const size_t size);
bool feed_gpu_run   (feed_gpu_t *gp, const u64 items, const feed_gpu_arg_t *args, const u32 arg_cnt);
```

The feed does not handle CUDA, HIP or OpenCL directly. The helper layer also manages compiled-kernel caching, build options, streams and backend-specific reasons a device may be unavailable. Describe the kernel once:

```c
const feed_gpu_desc_t desc =
{
  .name             = "myfeed",          // names the cache entry, so two feeds cannot collide
  .kernel_file      = "feed_myfeed.cl",  // a plain name in hashcat's kernel folder
  .kernel_name      = "myfeed_filter",   // the entry point inside it
  .build_options    = NULL,              // extra -D, split on whitespace, may be NULL
  .threads          = 64,                // work items per group, 0 takes the default
  .allow_opencl_cpu = false,             // an OpenCL CPU device is your host path with a build in front
};

char reason[256];

feed_gpu_t *gp = feed_gpu_init (hashcat_ctx, thread_ctx->device_id, &desc, reason, sizeof (reason));

if (gp == NULL)
{
  feed_say (hashcat_ctx, "myfeed: device %d declined: %s", thread_ctx->device_id + 1, reason);
}
```

Create the helper in `thread_init()` and release it in `thread_term()`. hashcat runs both callbacks for one device at a time on one thread.

**A `NULL` return from `feed_gpu_init()` is not a session failure.** The function returns `NULL` with a reason whenever the device path is unsuitable. The host implementation can still perform the same work more slowly. Retaining it as a fallback also provides a reference against which the device result can be checked.

Buffers use numeric slots because kernel arguments refer to slots by number. Kernel arguments are positional, so `args[i]` defines parameter i as either a buffer slot or an immediate value read at launch:

```c
const u64 arg_first = first;
const u32 arg_cnt   = len;

const feed_gpu_arg_t args[] =
{
  { FEED_GPU_ARG_MEM, MYFEED_SLOT_OUT, NULL,       0                  },
  { FEED_GPU_ARG_VAL, 0,               &arg_first, sizeof (arg_first) },
  { FEED_GPU_ARG_VAL, 0,               &arg_cnt,   sizeof (arg_cnt)   },
};

feed_gpu_run (gp, len, args, 3);
feed_gpu_read (gp, MYFEED_SLOT_OUT, verdict, len);
```

Function `feed_gpu_run()` launches on a feed-owned stream and waits for completion before returning. Its work therefore remains outside the timing used for hashcat kernels. The function refuses launches during autotune. Use `feed_gpu_threads()` to obtain the actual work-group size, which may be lower than requested.

### Responsibilities of the helper layer

The helper layer makes six important policy decisions:

**The compiled kernel cache.** Your kernel is cached under hashcat's own cache directory, keyed on your feed's name, the device, the build options and a hash of the source. The name is in the key so that two feeds building two different kernels cannot collide over one file. The source is in the key because the build timestamp does not move when an editable `.cl` next to the binary changes, so editing your kernel in place is enough to invalidate the build. An entry is written under a temporary name and renamed into place, so two hashcat processes sharing a cache directory cannot read a half written file.

**Metal is declined.** `hc_mtlBuildOptionsToDict()` does not hand the option string to a compiler, and `load_kernel()` writes no `.metallib`, so a Metal feed kernel would be a full cold build at every session start with no cache to fall back on.

**An OpenCL CPU device is declined** unless your descriptor asks for it. That device is the same silicon your host path already runs on, with a cold kernel build in front of it. `--stdout` forces exactly those devices, and `thread_init()` walks devices one at a time, so without this the first `--stdout` run on a machine with an Intel or pocl runtime can leave the screen unchanged for longer than the complete attack would have taken.

**The stream is yours, never hashcat's.** hashcat's own stream does not exist when `thread_init()` runs and is already destroyed when `thread_term()` runs, so neither lifecycle callback has a stream available to borrow. Sharing it would also put your launches inside the event pair hashcat uses to time the cracking kernel, which is what feeds the `Exec` column, `--spin-damp` and the TDR abort, so your work would be counted as hashcat's. The layer creates one for you and waits on that one alone, and never calls `cuCtxSynchronize()`, which takes no stream and would wait on hashcat's work as well.

**No launch reaches the card while autotune is measuring.** `feed_gpu_run()` refuses during that window. No launch can reach it today because autotune joins its own threads before any device thread exists, but the check preserves that guarantee if a background warm-up path is added later.

**Output routing.** The next section describes how feed messages avoid interfering with candidate output.

### User-facing messages

Use `feed_say(hashcat_ctx, fmt, ...)` for every user-facing message instead of `event_log_info()` or `event_log_warning()`. Both of those write to stdout and neither is guarded by `--quiet`, and under `--stdout` that stream is the candidate list, so a helpful line would be handed to whatever is reading as a password to try. Function `feed_say()` suppresses the message under `--quiet`, writes it to standard error under `--stdout`, and displays it normally otherwise.

In particular, report when the device path is declined and the feed falls back to a much slower host implementation. Hiding that condition can turn an unexpectedly long run into an apparent hang.

## Advantages over a pipe

A pipe is a feed too, `feed_stdin` above, so this is not a comparison between a feed and something else. It is what a feed written for the job can do that one reading a single shared stream cannot:

- Independent threads per compute device
- No mutex bottlenecks on shared pipes
- The option for each thread to open its own resources (files, sockets, databases)
- Higher performance and scalability

## Skeleton

Attack mode 8 includes C and Rust skeletons. Place an implementation in the appropriate directory to build it automatically as a cross-platform library.

### C

Put your code in `src/feeds/` and prefix it with `feed_`, for example `src/feeds/feed_wordlist.c`. It will be compiled automatically. Adding a matching header file such as `feed_wordlist.h` is recommended.

C skeleton: `src/feeds/feed_random.c`

A feed includes `include/feed.h`, and that one header is the whole contract: the functions above, the return codes, the options below, the settings parser, and the device helpers further down. There is a second header, `include/feed_ctx.h`, which holds the functions hashcat uses to drive feeds. A feed must not include it and cannot: it refuses to compile outside the core.

### Rust

Create your project with `cargo init myfeed --lib` and move it into the `Rust/feeds/` folder. It will be compiled automatically.

Rust skeleton: `Rust/feeds/random`

## Options

Two global variables must be set:

- `GENERIC_PLUGIN_VERSION`
- `GENERIC_PLUGIN_OPTIONS`

Variable `GENERIC_PLUGIN_VERSION` identifies the supported interface version.

For a C feed, set it to `FEEDS_INTERFACE_VERSION_CURRENT`, which the build passes in on the compile line from `FEEDS_INTERFACE_VERSION` in `src/Makefile`. Modules do the same thing with `MODULE_INTERFACE_VERSION_CURRENT`. You cannot set it to `GENERIC_PLUGIN_VERSION_REQ`, which is the minimum hashcat accepts: that constant lives in `feed_ctx.h` and a feed cannot see it. A feed declaring it would re-declare compatibility on every rebuild without the source having earned it, and the check could never fail, so it is out of reach rather than merely discouraged.

Do not write the number out in your source either, for the same reason. It would survive an interface change and go on claiming a compatibility the source no longer has, which is a silent failure rather than a loud one. A Rust feed reads it from the environment variable `FEEDS_INTERFACE_VERSION_CURRENT`, which `src/feeds/rust_support.mk` sets when it invokes cargo, and `Rust/feeds/random` shows how to parse it in a const context. When built by hand without that environment variable, it resolves to 0 and hashcat refuses the feed, which is the intended outcome.

Variable `GENERIC_PLUGIN_OPTIONS` declares the optional processing and interface features supported by the feed:

- `GENERIC_PLUGIN_OPTIONS_AUTOHEX`: Allow hashcat to decode `$HEX[]` candidates.
- `GENERIC_PLUGIN_OPTIONS_ICONV`: Allow `--encoding-from` and `--encoding-to`.
- `GENERIC_PLUGIN_OPTIONS_RULES`: Allow hashcat's rule engine, including `-r`, `-j` and generated rules.
- `GENERIC_PLUGIN_OPTIONS_DEVICE`: Export `global_dev_init()` and `thread_next_dev()` to amplify candidates in a device kernel.
- `GENERIC_PLUGIN_OPTIONS_EXPLAIN`: Export `global_explain()` so `--debug-mode` can describe how a candidate was made.

Set the value to `0` when no options apply, or combine only the flags implemented by the feed. Advertising `DEVICE` or `EXPLAIN` makes the corresponding extra exports mandatory.


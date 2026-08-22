
# Development Guide For Attack-Mode 8: Generic Password Candidate Generator Mode

---

## General

The new attack mode 8 is similar to the assimilation bridge in that we have added a standardized interface that allows users to easily add new functions and extend the customization of hashcat. Unlike the assimilation bridge, which operates on the output channel, this plugin interface operates on the input channel, the password candidate generator side.

Such generators are often implemented as standalone tools and connected to hashcat through the stdin interface. However, that approach comes with limitations and bottlenecks, which are discussed in the user guide: `docs/hashcat-generic-attack-mode.md`. If you have not read it yet, start there.

This document explains how to add your own "feed" to be used with attack mode 8.

## What is a Feed?

From a technical perspective, a feed is a dynamically loaded library (`.so`, `.dll`, `.dylib`) that hashcat loads at startup. Attack mode 8 itself does not provide generator logic. Instead, the user selects a feed by name as the first parameter on the command line, the same way `-m` selects a module.

Hashcat looks for that name under the `feeds/` folder of its shared directory, trying `feed_<name>`, then `rust_<name>`, then `<name>`. So `hashcat -a 8 hashes.txt wordlist mydict.txt` finds the shipped wordlist feed. If none of those exist, the name is used as a path, which is what you want while developing a feed that is not installed yet.

This open design allows for:

- An unlimited number of plugins that can ship with hashcat core
- Custom feeds for specialized workflows or client requirements

## Example Feeds

We provide four sample feeds. Between them they cover the three shapes a feed can have: one that can seek freely, one that can only start over, and one that cannot go back at all.

1. `feed_wordlist`

	- A simple wordlist loader, and the feed -a 0 itself is built on
	- Takes any number of wordlists and directories, laid end to end into a single keyspace
	- Because it is one keyspace rather than one attack per file, `--skip` and `--limit` address the whole set rather than each file
	- Much higher performance than classical -a 0 due to improved seeking
	- Uses a seek database instead of the traditional dictstat file, allowing efficient random access without repeatedly calling next()
	- Especially beneficial on multi-GPU systems

2. `feed_stdin`

	- Reads candidates from a pipe, and is what `-a 0` with no wordlist runs
	- The one shipped feed that **cannot seek at all**. The word at offset N is whichever word arrives next, so an offset is not a position in anything that still exists
	- `thread_seek()` therefore accepts what it is told and reads on. Refusing would be worse than useless: hashcat treats a refused seek as a hard error, so a second device joining the attack would kill the run
	- One mutex inside the plugin hands every line out exactly once however many devices are asking. This is the opposite of the advice further down about each thread opening its own resources, and it is what a feed over a socket, a queue or any other single shared stream has to do
	- There is one seek it must honour: hashcat re-reads a candidate when a transform could make it shorter, by seeking back to the offset it just read and calling `thread_next()` again. A seek that did nothing would swallow the following line instead. The plugin keeps the line in its buffer and hands that one back
	- Reports an unknown keyspace
	- `--skip`, `--limit` and `--restore` still work on it, because hashcat reaches a position in a stream by reading and throwing away everything before it. That costs the user nothing but feeding the same candidates in the same order

3. `feed_random`

	- A random password generator, and the smallest feed that is still correct, in C
	- Generates from a deterministic pseudo random sequence, so it is the simplest kind of feed that cannot seek: word number N only exists once the N words before it have been produced
	- `thread_seek()` therefore reseeds and replays, which is what any probabilistic generator has to do
	- Because the sequence is a pure function of a fixed seed, every device produces the same word for the same offset, so hashcat can split the range across devices and `--restore` lands on the word it left off at. A generator seeded from the clock or from a thread id can do neither
	- Reports an unknown keyspace

4. `rust_random`

	- The same generator again, in Rust, producing byte identical words
	- Demonstrates two things:
	  a) a feed that does not report a keyspace
	  b) feeds do not need to be written in C to be efficient
	- Because it matches `feed_random` word for word, the two can be diffed against each other to check a port

## Design Philosophy

The interface was intentionally designed to be as simple and straightforward as possible. This allows you to focus on generating high-quality password candidates without needing deep knowledge of hashcat internals. The simplicity also makes it easy to integrate with code-generation tools or AI assistants.

Early experiments showed success reimplementing legacy hashcat attacks such as -a 2 (permutation attack) and -a 5 (table attack).

## Required Functions

There are seven functions you can implement. In theory, only one `thread_next()` is mandatory, but for a proper implementation you will likely want to define several functions.

### Main Function

```
int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
```

This function is called whenever hashcat needs the next password candidate. Write it into `out_buf`, never writing more than `out_size` bytes, and return its length. The two custom data types are simple structures holding only basic primitives.

### Full Function Set

```
bool global_init     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx);
void global_term     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx);
u64  global_keyspace (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx);
bool thread_init     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
void thread_term     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
int  thread_next     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
bool thread_seek     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u64 offset)
```

### hashcat_ctx_t

Hashcat will provide the full `hashcat_ctx_t` context. In most cases you do not need it. It is complex and not suitable for wrapper languages. For that reason it is only optionally available to global functions.

If you do use it, you can call the `EVENT_DATA()` functions to write messages that follow the hashcat API format. This allows external applications that use the hashcat API to receive callbacks. This is optional.

### generic_global_ctx_t

The `generic_global_ctx_t` is a globally available data structure that can be used as shared buffer between threads.

```
typedef struct generic_global_ctx
{
  bool   quiet;

  int    workc;
  char **workv;

  char  *profile_dir;
  char  *cache_dir;
  char  *seekdb_dir;

  char   guess_base[256];

  u64          segments_cnt;
  const char **segment_names;
  const u64   *segment_first;

  u64 source_ident;

  bool   error;
  char   error_msg[256];

  void  *gbldata; // super generic

} generic_global_ctx_t;
```

Notes:

- This structure may change over time as we learn more about what developers need.
- To handle compatibility, your feed library will be built with a version string. Hashcat will use this to check if your feed matches the current structures.
- Attributes `workc` and `workv` contain the command line arguments that belong to attack mode -a 8. For example, if your feed reads a wordlist, the filename can be passed on the hashcat command line and you can retrieve it from these variables. The feed plugin name is always workv[0], so for the wordlist example you would find this in workv[1].
- `seekdb_dir` is the directory the user named with `--seekdb-path`, or NULL when they did not. It exists because a feed that caches something per input can be pointed at storage several machines share, so the cache is built once for a cluster rather than once per host. If your feed keeps no such cache, ignore it. If it does, treat NULL as "pick your own place under `cache_dir`", do not create the directory yourself since hashcat has already checked that it is there, and expect it to be read only: write only when you had to build something, and carry on with what is in memory when the write fails.
- `guess_base` is what the status display puts inside `Guess.Base.......: Feed (...)`. Write your own during `global_init()` if the plugin name alone is not informative: `Feed (rockyou.pcfg)` tells the user something that `Feed (pcfg)` does not. Leave it empty and hashcat uses the plugin name.
- The three `segment_*` fields are optional and only worth filling if your feed draws from several named sources laid end to end. Publish where each one begins in the keyspace, ascending, and the status display names the source the run has reached instead of whatever `guess_base` holds: `Guess.Base.......: Feed ([6/18] d06.txt)`. Leave `segments_cnt` at zero and nothing changes. Fill these once the offsets are actually known, which for the wordlist feed means in `global_keyspace()` and not in `global_init()`, because the offset a source starts at is only known after every earlier source has been counted. The arrays and the strings they point at have to stay valid until `global_term()`, and freeing them is your job.
- `source_ident` is one number saying what your feed reads from, so that something which has to tell two runs apart can do it without knowing what a source is. Fill it during `global_init()` or `global_keyspace()` if you can. The brain is what needs it: it keys its record of covered keyspace on the attack, so a feed whose inputs have changed since the last run has to come out different or that run is told its work was already done. A path is not enough, because the same path holds different words on different days. The wordlist feed already has the answer for free: it names its seek database after a hash of each file's size, modification time and both of its ends, and folds those together. Leave it at zero if your feed cannot say, which is what the stdin feed does.
- The error field on this structure is for the three global functions only. The four per device functions report through their own thread context, see below. Set it only if a real error occurs. An end of file condition is not an error. When you set this field, you may also provide an error message in error_msg.
- If you print messages to the console, check the quiet flag first. This flag is set when the user runs hashcat with `--quiet`.

### generic_thread_ctx_t

This structure is always available.

In global functions you receive the full array of thread structures. In thread functions you receive the structure of the current thread only.

You are free to design the contents. The default definition is:

```
typedef struct generic_thread_ctx
{
  bool   error;
  char   error_msg[256];

  void  *thrdata; // super generic

} generic_thread_ctx_t;
```

`thread_init()`, `thread_term()`, `thread_next()` and `thread_seek()` report a failure here and not in the global context. Those four run on one device thread each, and a shared flag would let one device's failure speak for all of them. Hashcat prints the message and clears the flag after every call, so you never have to clear it yourself.

### Functions

Some explanations:

Hashcat can use multiple compute devices. Each device has its own candidate generator thread. This improves performance and keeps the design simple. Hashcat will handle synchronization by calling your `thread_seek()` function.

For example, if your feed reads from a wordlist, the normal way is to open the file once per thread. Each thread maintains its own file handle. Hashcat calls `thread_seek()` with the offset where each thread should start.

It is also possible to open the file only once in the global function and then distribute data to threads using pipes. This is more complex but can be done if needed.

- global_init()

This function is called once at startup before threads are created. Use it to allocate global resources and store pointers to them in `gbldata`.

- global_term()

This function is called once before hashcat exits. Use it to close files, free memory, and release anything that was created in `global_init()`.

- global_keyspace()

This function is called once at startup. It is optional but important. Return the total number of candidates that your implementation will produce, based on the command line arguments. For example, return the number of words in a wordlist.

Count everything you will hand out, including candidates hashcat will go on to reject for being too long or for failing an encoding conversion. Rejections belong in the `Rejected` counter, not in a smaller keyspace, and a keyspace that skips them cannot be seeked by offset.

If the number cannot be calculated easily, return `GENERIC_KEYSPACE_UNKNOWN`. In that case, hashcat will not display progress or ETA. You still need to signal the end of candidates later in `thread_next()`.

If the keyspace cannot be determined because something went wrong, set the error flag instead. Reporting an unknown keyspace for a failure turns a broken feed into an endless one.

- thread_init()

This function is called only once when hashcat is starting up and before it starts it main cracking activity and specific to the called thread. You probably want to use this opportunity to allocate storage space that will be accessible for this thread and store it in `thrdata`.

- thread_term()

This function is called once for each thread at shutdown. Use it to close and free resources created in `thread_init()`.

- thread_seek()

This function is used by hashcat for synchronization. You are given an absolute offset. You must seek your generator for this thread to that position. After a seek call, hashcat will call `thread_next()` to request candidates starting from that position.

If your generator cannot seek directly, you must advance your state step by step until you reach the requested offset. Tip: store the current position in your per thread data structure. `feed_random` is a worked example of exactly that.

Hashcat does not call this when the offset is already where your generator sits, so a straight run through the keyspace on one device costs a single seek. Handle a backward offset anyway. With several devices the offsets interleave, and a `--skip` or a `--restore` can land anywhere.

Return false on failure and set the error flag with a reason. A failed seek ends the session, it is not an end of input.

- thread_next()

This function is mandatory.

* Copy the next candidate into `out_buf[]`.
* Never write more than `out_size` bytes. Hashcat usually hands you a pointer straight into the buffer it uploads to the device, so there is no room past that and nothing checks afterwards.
* Return the length of the candidate. It is not needed to zero terminate the buffer, because you return the length.
* If the candidate is longer than `out_size`, write the first `out_size` bytes and still return the real length. Returning the clipped length instead would hand hashcat a candidate that your generator never produced.
* `out_size` is not a constant, which is why it is a parameter rather than something you can cache. It is normally 256. When hashcat sees an over-length candidate and the run has a transform that shortens one, such as a hex wordlist, `$HEX[]` decoding or an encoding conversion, it seeks back and asks for that one candidate again with a much larger buffer. A 256 byte password written as hex is a 512 byte line, and this is how it survives. If nothing in the run can shorten a candidate, an over-length one is simply rejected and counted under `Rejected`.
* If you reach the end of your keyspace, return `GENERIC_RC_EOF`. Do not set the error flag in this case.
* If something went wrong, set the error flag. Hashcat ends the session with an error status. Returning `GENERIC_RC_EOF` for a failure would report it as a clean exhaustion, and the user would never know the run was cut short.

## Global vs Thread Context

Hashcat supports compute devices of very different performance levels. For example, a session may include one CPU and five GPUs, each with different speeds. To feed each device efficiently, hashcat creates a separate thread per device.

This is why there are two context structures:

- global_ctx: shared across all threads
- thread_ctx: unique to each thread

## Global vs Thread Functions

There are two categories of functions:

- Global functions: initialization, termination, and keyspace reporting
- Thread functions: initialization, termination, seeking, and producing the next candidate

Examples:

- Global init: Used for setup work that all threads can share. For example, building a lookup table of byte offsets for each word in a wordlist. Each thread then benefits from this shared data.
- Thread init: Used for thread-specific setup. For example, each thread could open its own file handle instead of sharing one global handle. This avoids synchronization overhead and boosts performance.

This model gives you flexibility. You can centralize some work in the global functions or let each thread manage its own resources. Both approaches are valid depending on your use case.

## Using The Device

A feed runs on the host, but the device hashcat is feeding is right there and is often idle while the
feed thinks. A feed that has work the device could do better may simply do it.

### The device is current

The device this thread feeds is current inside `thread_init()`, `thread_term()`, `thread_next()` and
`thread_seek()`. You do not have to make it current yourself and you should not try.

That is a promise the core makes rather than a rule you follow, because the ways to get it wrong are
not diagnosable by whoever gets them wrong. There are four different hashcat threads that can call
into a feed and only one of them used to make the device current, so a feed that wanted to talk to
the device carried a push and a pop around every call it made. Popping a CUDA context into
`device_param->cuda_context` rather than into a local corrupts hashcat's own handle from another
thread, and it surfaces much later as an unrelated failure somewhere else.

Two things the core cannot do for you, and both still apply:

* **Never cache a context across calls.** hashcat destroys and recreates every CUDA context on each
  outer loop iteration after the first, so a `CUcontext` read once and kept is a stale handle. Read
  it fresh each time, or let the helpers below do it.
* **HIP has no context handle at all.** What makes a HIP device current is a property of the thread,
  not a handle you could hold.

`feed_device_param (hashcat_ctx, thread_ctx->device_id)` gives you hashcat's own record for the
device this thread feeds, or NULL if there is no backend.

### Running your own kernel

Write one `.cl` file, put it in hashcat's kernel folder beside hashcat's own, and call six functions:

```c
feed_gpu_t *feed_gpu_init (hashcat_ctx_t *hashcat_ctx, const int device_id, const feed_gpu_desc_t *desc, char *reason, const size_t reason_size);
void        feed_gpu_term (feed_gpu_t *gp);

bool feed_gpu_alloc (feed_gpu_t *gp, const int slot, const size_t size, const feed_gpu_mem_t kind);
bool feed_gpu_write (feed_gpu_t *gp, const int slot, const void *src, const size_t size);
bool feed_gpu_read  (feed_gpu_t *gp, const int slot, void *dst, const size_t size);
bool feed_gpu_run   (feed_gpu_t *gp, const u64 items, const feed_gpu_arg_t *args, const u32 arg_cnt);
```

CUDA, HIP and OpenCL do not appear in your feed, and neither does the compiled kernel cache, the build
option list, the stream, or the twenty reasons a device may turn out not to be usable. You describe
the kernel once:

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

Build it in `thread_init()` and give it back in `thread_term()`, which hashcat runs one device at a
time on one thread.

**`feed_gpu_init()` returning NULL is not a failure.** It returns NULL and a sentence for every reason
not to use that device, and none of them is fatal by itself, because your host path answers the same
question more slowly. Keeping the host path as the fallback also keeps it as the reference the device
is checked against, which is the only cheap way to find out that a kernel and a host function have
stopped agreeing.

Buffers are numbered slots rather than names, because a slot number is what a kernel argument list
refers to. Kernel arguments are positional, so `args[i]` is the kernel's i'th parameter, and each one
is either one of your slots or an immediate read at launch:

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

`feed_gpu_run()` launches on a stream your feed owns and waits for it before returning, so it never
lands inside the timing hashcat keeps for its own kernels. It is refused while hashcat is autotuning.
Ask `feed_gpu_threads()` for the work group size you actually got, which may be lower than the one you
asked for.

### What the layer takes care of, and why

Six of the things it does for you are worth knowing about, because every one of them is a decision
somebody had to make once and each one has a reason that is not obvious from the outside.

**The compiled kernel cache.** Your kernel is cached under hashcat's own cache directory, keyed on
your feed's name, the device, the build options and a hash of the source. The name is in the key so
that two feeds building two different kernels cannot collide over one file. The source is in the key
because the build timestamp does not move when an editable `.cl` next to the binary changes, so
editing your kernel in place is enough to invalidate the build. An entry is written under a temporary
name and renamed into place, so two hashcat processes sharing a cache directory cannot read a half
written file.

**Metal is declined.** `hc_mtlBuildOptionsToDict()` does not hand the option string to a compiler,
and `load_kernel()` writes no `.metallib`, so a Metal feed kernel would be a full cold build at every
session start with no cache to fall back on.

**An OpenCL CPU device is declined** unless your descriptor asks for it. That device is the same
silicon your host path already runs on, with a cold kernel build in front of it. `--stdout` forces
exactly those devices, and `thread_init()` walks devices one at a time, so without this the first
`--stdout` run on a machine with an Intel or pocl runtime stalls with nothing on screen for longer
than the whole attack would have taken.

**The stream is yours, never hashcat's.** hashcat's own stream does not exist when `thread_init()`
runs and is already destroyed when `thread_term()` runs, so there is nothing to borrow at either end.
Sharing it would also put your launches inside the event pair hashcat uses to time the cracking
kernel, which is what feeds the `Exec` column, `--spin-damp` and the TDR abort, so your work would be
counted as hashcat's. The layer creates one for you and waits on that one alone, and never calls
`cuCtxSynchronize()`, which takes no stream and would wait on hashcat's work as well.

**No launch reaches the card while autotune is measuring.** `feed_gpu_run()` refuses during that
window. Nothing can reach it today, because autotune joins its own threads before any device thread
exists, but checking is what keeps that true when somebody adds a background warm up later.

**Output routing**, which is the next section.

### Saying things

Use `feed_say (hashcat_ctx, fmt, ...)` for anything your feed has to tell the user, rather than
`event_log_info()` or `event_log_warning()`. Both of those write to stdout and neither is guarded by
`--quiet`, and under `--stdout` that stream is the candidate list, so a helpful line would be handed
to whatever is reading as a password to try. `feed_say()` says nothing under `--quiet`, puts it on
stderr under `--stdout`, and on the screen otherwise.

The line most worth saying is usually that a device was declined and the run is now a great deal
slower. Swallowing that is how a session silently takes a week.

## Advantages Over A Pipe

A pipe is a feed too, `feed_stdin` above, so this is not a comparison between a feed and something else. It is what a feed written for the job can do that one reading a single shared stream cannot:

- Independent threads per compute device
- No mutex bottlenecks on shared pipes
- The option for each thread to open its own resources (files, sockets, databases)
- Higher performance and scalability

## Skeleton

Attack mode 8 includes two skeletons: one in `C` and one in `Rust`. Place your implementation in the correct folder and it will be built automatically as a cross platform library.

### C

Put your code in `src/feeds/` and prefix it with `feed_`, for example `src/feeds/feed_wordlist.c`. It will be compiled automatically. Adding a matching header file such as `feed_wordlist.h` is recommended.

C Skeleton: `src/feeds/feed_random.c`

A feed includes `include/feed.h`, and that one header is the whole contract: the functions above, the
return codes, the options below, the settings parser, and the device helpers further down. There is a
second header, `include/feed_ctx.h`, which holds the functions hashcat uses to drive feeds. A feed
must not include it and cannot: it refuses to compile outside the core.

### Rust

Create your project with `cargo init myfeed --lib` and move it into the `Rust/feeds/` folder. It will be compiled automatically.

Rust Skeleton: `Rust/feeds/random`

## Options

Two global variables must be set:

- `GENERIC_PLUGIN_VERSION`
- `GENERIC_PLUGIN_OPTIONS`

The first defines which interface version your implementation supports.

For a C feed, set it to `FEEDS_INTERFACE_VERSION_CURRENT`, which the build passes in on the compile line from `FEEDS_INTERFACE_VERSION` in `src/Makefile`. Modules do the same thing with `MODULE_INTERFACE_VERSION_CURRENT`. You cannot set it to `GENERIC_PLUGIN_VERSION_REQ`, which is the minimum hashcat accepts: that constant lives in `feed_ctx.h` and a feed cannot see it. A feed declaring it would re-declare compatibility on every rebuild without the source having earned it, and the check could never fail, so it is out of reach rather than merely discouraged.

Do not write the number out in your source either, for the same reason. It would survive an interface change and go on claiming a compatibility the source no longer has, which is a silent failure rather than a loud one. A Rust feed reads it from the environment variable `FEEDS_INTERFACE_VERSION_CURRENT`, which `src/feeds/rust_support.mk` sets when it invokes cargo, and `Rust/feeds/random` shows how to parse it in a const context. Built by hand with nothing in the environment it comes out as 0 and hashcat refuses the feed, which is the intended outcome.

The second defines which post processing features of hashcat your feed should allow. Current options are:

- `GENERIC_PLUGIN_OPTIONS_AUTOHEX`: Allow hashcat to decode `$HEX[]` encoded candidates.
- `GENERIC_PLUGIN_OPTIONS_ICONV`: Allow encoding conversion with `--encoding-from` and `--encoding-to`.
- `GENERIC_PLUGIN_OPTIONS_RULES`: Allow application of rules defined with `-j`.

You can disable all three by setting the value to 0 for a small speed boost. This makes sense for feeds where none of these options apply. You can also enable or disable individual features depending on your feed.


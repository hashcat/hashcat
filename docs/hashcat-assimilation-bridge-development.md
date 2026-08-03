# Assimilation Bridge Plugin Development

## Developer Section

The following section is for plugin and bridge developers. It contains low-level implementation details.

## Update existing plugins

In case you have written a hashcat plugin, you need to update the init function and add the following two lines:

+  module_ctx->module_bridge_name = MODULE_DEFAULT;
+  module_ctx->module_bridge_type = MODULE_DEFAULT;

Existing modules on hashcat repository will be automatically updated.

## Plugin Integration and Bridge Registration

Plugins can opt in to bridge support by adding:

```c
static const u64   BRIDGE_TYPE = BRIDGE_TYPE_LAUNCH_LOOP;
static const char *BRIDGE_NAME = "scrypt_jane";
```

* `BRIDGE_NAME` tells hashcat which bridge to load (e.g., `bridge_scrypt_jane.so`).
* `BRIDGE_TYPE` indicates which backend kernel functions the bridge will override:

  * `BRIDGE_TYPE_LAUNCH_LOOP`:   Entry point for all bridges that register to run after `RUN_LOOP`
  * `BRIDGE_TYPE_LAUNCH_LOOP2`:  Entry point for all bridges that register to run after `RUN_LOOP2`
  * `BRIDGE_TYPE_REPLACE_LOOP`:  Same as BRIDGE_TYPE_LAUNCH_LOOP, but deactivates `RUN_LOOP`
  * `BRIDGE_TYPE_REPLACE_LOOP2`: Same as BRIDGE_TYPE_LAUNCH_LOOP2, but deactivates `RUN_LOOP2`

hashcat loads the bridge dynamically and uses it for any declared invocation.

Note that bridges only load for outside kernel, aka "slow hash" kernels. In "fast hash" kernels, such as MD5, they are ignored. In case you want to implement a "fast hash" + bridge hybrid, you can move the "fast hash" code into a new "slow hash" kernel.

Here's a high-level view on how hashcat executes several key points during a password batch:

```
ATTACK_EXEC_OUTSIDE_KERNEL:
  COPY_AMPLIFIER_MATERIAL
  RUN_AMPLIFIER
  RUN_UTF16_CONVERT
  RUN_INIT
  COPY_HOOK_DATA_TO_HOST
  CALL_HOOK12
  COPY_HOOK_DATA_TO_DEVICE
  SALT_REPEATS (default 1):
    RUN_PREPARE
    ITER_REPEATS:
      RUN_LOOP
      RUN_EXTENDED
    COPY_BRIDGE_MATERIAL_TO_HOST
    BRIDGE_LAUNCH_LOOP
    COPY_BRIDGE_MATERIAL_TO_DEVICE
    COPY_HOOK_DATA_TO_HOST
    CALL_HOOK23
    COPY_HOOK_DATA_TO_DEVICE
  RUN_INIT2
  SALT_REPEATS (default 1):
    RUN_PREPARE2
    ITER2_REPEATS:
      RUN_LOOP2
    COPY_BRIDGE_MATERIAL_TO_HOST
    BRIDGE_LAUNCH_LOOP2
    COPY_BRIDGE_MATERIAL_TO_DEVICE
  DEEP_COMP_KERNEL:
    RUN_AUX1/2/3/4
  RUN_COMP
  CLEAN_HOOK_DATA
```

- RUN_* refers to compute kernel executions, such as "init" kernel, but also "amplifier" (typically base-word * modifier-word multiplication).
- COPY_* refers to host-to-device or device-to-host copies and typically involve PCIe data transfer.
- CALL_* are code functions executed on the host CPU. They are plugin-specific and defined in a module. They were the predecessor of bridges but are still usable.
- SALT_* typically are optional steps which allow certain algorithms specific optimizations. For instance in Scrypt with P > 1, the V and XY buffer can be reused and allow temporary storage of result values into B. This saves memory requirement, improving parallelization
- ITER_* is the main loop that chunks what typically is defined as "iterations" in a algorithm computation. For instance a PBKDF2 function is called with 10,000 iterations, which would take a while to compute. The time this takes could be longer than a GPU drivers watchdog allows (before it resets the compute engine.). hashcat will divide the 10,000 into chunks of let's say 1,000 and call the same kernel 10 times
- BRIDGE_* existing bridge entry points. During the "lifetime" of a hash computation the tmps[] variable is used (algorithm specific, so defined in the specific plugin module and kernel). This variable is which we refer to as bridge material, but it's possible we add other types of variables to "material" in the future
- ITER2/LOOP2: Optional entry points in case the algorithm consists of two types of long running (high iterated) sub-components. For instance one iteration of 10k loops sha256 followed by 100k loops of sha512, or bcrypt followed by scrypt

  * `BRIDGE_TYPE_LAUNCH_INIT`
  * `BRIDGE_TYPE_LAUNCH_COMP`

hashcat devs will add support on request.

As mentioned in the BRIDGE_* entry points, it's the developer's responsibility to ensure compatibility. That typically means the handling of the `tmps` variable relevant in the `kernel_loop` and how it changes over algorithm computations lifetime. hashcat will take care of copying the data from and to the compute backend buffers (bridge material).

But the bridge developer must ensure data transformation compatibility. For instance, if we replace the loop section in SCRYPT (8900), the long running part is the smix() activity. But SCRYPT implements the PBKDF2 handling in both init and comp kernels, preparing the values in B[] after the init kernel, and expecting modified values in B[] before running comp kernel. If you want to replace the smix() section with let's say FPGA code, the bridge needs to understand the structure of the tmps[] variable. In this case tmps[] just reflect SCRYPT B[], making this simple, but other algorithms may require more than just one large buffer array. That means the structure itself (datatypes), but also the amount of workitems, because there's almost always more than one workitem (to reduce overhead times).

There's some more BRIDGE PARAMETERs that you should know:

+  BRIDGE_TYPE_UPDATE_SELFTEST     = updates the selftest configured in the module. Can be useful for generic hash modes such as the python plugin
+  BRIDGE_TYPE_LOOP_CHUNKED        = launch_loop() honours kernel_param.loop_pos and .loop_cnt, so hashcat may split the salt's iteration space into chunks and call the bridge once per chunk. Without it the bridge is handed the whole range in a single call, which is what a one-shot implementation needs. Set this only if your compute can stop and resume mid-iteration, which means keeping any per candidate state alive between calls

There is no flag to match tunings any more. hashcat derives the workitem count from what
`get_workitem_count()` reports, for every bridge, and sizes the launch and the device buffers from
that. The count is treated as a maximum the bridge will never be asked to exceed.

It is only the maximum, though, not the size hashcat will use. Autotune searches the range between one
workitem multiple and that maximum, and picks the launch size that measures fastest, so a bridge no
longer has to guess a good size and report it. `-n` sets the size directly and is clamped into the same
range.

That is what `get_workitem_multiple()` is for, and it is mandatory. It reports the granularity your unit
computes in. Return `1` if a batch of N candidates simply costs N, which is the case when one unit is
one thread working through its batch sequentially. Return the internal width if your unit processes
candidates in parallel waves, as an accelerator holding many cores behind a single unit does. hashcat
rounds every launch size down to a whole multiple of it, which matters more than it looks: a unit that
computes in waves of W is occupied for `ceil(N / W)` waves whatever N is, so a batch that is not a whole
number of waves pays for capacity it never used, and a larger batch can be strictly slower than a
smaller one in both throughput and latency.

Note the multiple describes your unit's internal width, not a DMA or buffer convenience. Reporting a
transfer granularity instead will look like it works, because the launch sizes stay legal, and it will
quietly cost throughput whenever the real width does not divide it.

## How Bridges Work

When hashcat starts with a plugin that specifies a bridge, it loads the bridge and invokes its initialization function. The bridge must then discover its internal compute units, called *bridge units*. Handling the units must be implemented by the bridge developer, and typically involves loading some library, init it, and retrieve some resources available, for instances loading XRT, asking how many FPGA are available. If there's two FPGA, then the bridge unit count would be two. You also need to provide some detailed information on the unit itself, for instance the name of the device, or version or your software solution if it's not a hardware.

Each of these bridge unit maps to one virtual backend device, which allows asynchronous and independent parallel execution, and this were virtual backend devices become relevant. Read section about virtual backend devices for a better understanding

From the bridge_init() function you have access to the following generic parameters, set on the command line by the user:

```c
+  "     --bridge-parameter1        | Str  | Sets the generic parameter 1 for a Bridge          |",
+  "     --bridge-parameter2        | Str  | Sets the generic parameter 2 for a Bridge          |",
+  "     --bridge-parameter3        | Str  | Sets the generic parameter 3 for a Bridge          |",
+  "     --bridge-parameter4        | Str  | Sets the generic parameter 4 for a Bridge          |",
```

## Virtual Backend Devices

This feature is available also outside of bridges, eg in order to increase some workload on a compute device, but it was added in the first place to support bridges. The main problem is that it's possible that a bridge return 2 bridge units which may have different speeds (clocking), or an ideal batch size. The time it takes to compute a certain batch of passwords would be different, so there was a need for an asynchronous execution strategy. hashcat supports mixed speed device types, but that typically mean "backend" devices. To solve the issue, we partition (virtualize) one physical backend device into multiple virtual backend devices (done internally by hashcat), and "link" each of the virtual backend device to a bridge unit. Due to this binding we can support bridge units of different speed. There's two flags a user can control in regard to virtual device backend:

* Use `-Y` to define how many virtual backend devices to create.
* Use `-R` to bind these virtual devices to a physical backend host (new in v7).

Note that if a bridge is used, the user's `-Y` parameter is overridden with the bridge unit count. If no bridge is used for a hash mode, then -Y can be manually specified. `-R` works in both cases. The default is device `1`, unless overridden.

Because each virtual backend device IS one bridge unit, **`-d` selects bridge units**. `-d 2` runs
unit 2 and nothing else, `-d 1,3` runs units 1 and 3, and a number naming no unit is refused the same
way an unknown compute device is. This is independent of `-R`, which still chooses the physical
device that generates the candidates.

The numbering is shared, so `-d N`, `Speed.#NN`, `Hardware.Mon.#NN` and the watchdog's `bridge unit
#N` all refer to the same unit. A unit keeps its own index whatever else is filtered out, so `-d 3`
always drives unit 3 rather than whichever unit happened to survive the filter first. Bridge
developers get this for free; there is nothing to implement for it.

## Writing a Bridge

### File Layout

Bridges live in the `src/bridges/` directory and consist of a `.c` file and a `.mk` build rule:

```
src/bridges/bridge_scrypt_jane.c
src/bridges/bridge_scrypt_jane.mk
```

The target output should be named like this: `bridges/bridge_scrypt_jane.so` and `bridges/bridge_scrypt_jane.dll`. Use any of the existing `.mk` files as template.

When hashcat starts, it finds the plugin using this pathfinder:

```
  #if defined (_WIN) || defined (__CYGWIN__)
  return snprintf (out_buf, out_size, "%s/bridges/bridge_%s.dll", folder_config->shared_dir, bridge_name);
  #else
  return snprintf (out_buf, out_size, "%s/bridges/bridge_%s.so", folder_config->shared_dir, bridge_name);
  #endif
```

### Required Function Exports

```c
bridge_ctx->platform_init         = platform_init;
bridge_ctx->platform_term         = platform_term;
bridge_ctx->get_unit_count        = get_unit_count;
bridge_ctx->get_unit_info         = get_unit_info;
bridge_ctx->get_workitem_count    = get_workitem_count;
bridge_ctx->get_workitem_multiple = get_workitem_multiple;
bridge_ctx->get_unit_class        = BRIDGE_DEFAULT;
bridge_ctx->thread_init           = BRIDGE_DEFAULT;
bridge_ctx->thread_term           = BRIDGE_DEFAULT;
bridge_ctx->salt_prepare          = salt_prepare;
bridge_ctx->salt_destroy          = salt_destroy;
bridge_ctx->launch_loop           = launch_loop;
bridge_ctx->launch_loop2          = BRIDGE_DEFAULT;
bridge_ctx->st_update_hash        = BRIDGE_DEFAULT;
bridge_ctx->st_update_pass        = BRIDGE_DEFAULT;
```

They are defined like this:

```c
  void     *(*platform_init)      (hashcat_ctx_t *);
  void      (*platform_term)      (hashcat_ctx_t *, void *);
  int       (*get_unit_count)        (hashcat_ctx_t *, void *);
  char     *(*get_unit_info)         (hashcat_ctx_t *, void *, const int);
  int       (*get_workitem_count)    (hashcat_ctx_t *, void *, const int);
  int       (*get_workitem_multiple) (hashcat_ctx_t *, void *, const int);
  char     *(*get_unit_class)        (hashcat_ctx_t *, void *, const int);
  bool      (*salt_prepare)       (hashcat_ctx_t *, void *, hashconfig_t *, hashes_t *);
  void      (*salt_destroy)       (hashcat_ctx_t *, void *, hashconfig_t *, hashes_t *);
  bool      (*thread_init)        (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *);
  void      (*thread_term)        (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *);
  bool      (*launch_loop)        (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);
  bool      (*launch_loop2)       (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);
  const char *(*st_update_pass)  (hashcat_ctx_t *, void *);
  const char *(*st_update_hash)  (hashcat_ctx_t *, void *);
```

**Note**: Use `BRIDGE_DEFAULT` when no function implementation is required.

### Every entry takes `hashcat_ctx_t *` first

Interface version 720 carries this change. A bridge written against an older interface has the wrong
signature on every single entry, and `platform_init`'s parameters are gone entirely: `user_options_t`
and `folder_config_t` are both reachable through the context now.

The reason is logging. A bridge that has the context can call `event_log_info`, `event_log_warning`
and `event_log_error` exactly as hashcat's own code does, so its messages go through hashcat's event
system, honour `--quiet`, and appear in the right order with everything else. Writing to `stderr`
from a bridge does none of that, and on Windows a DLL's `stderr` is not even the host's.

No wrapper or callback is needed. Every `event_log_*` symbol is already linked into every bridge.

Two things to know before reaching through the context:

- **`event_log_error` prints a BLANK LINE after its message.** It is a paragraph printer, not a line
  printer, because hashcat's own errors are single sentences. Use ONE `event_log_error` for the
  headline and `event_log_info` for each body line, and do not add your own blank line after the
  headline. A headline must also fit on one line or the blank splits the sentence in half.
- **Never read `hashcat_ctx->hashes`.** The self test hands `launch_loop` and friends a `hashes_t`
  that is a LOCAL COPY, with the digest, salt, esalt and hook salt buffers swapped for the self
  test's own. That is why these functions still take `hashconfig` and `hashes` explicitly even though
  both are reachable from the context. Reading the context instead silently computes against the
  user's real hashes during the self test.

### Mandatory Functions

The following functions must be defined:

```c
CHECK_MANDATORY (bridge_ctx->platform_init);
CHECK_MANDATORY (bridge_ctx->platform_term);
CHECK_MANDATORY (bridge_ctx->get_unit_count);
CHECK_MANDATORY (bridge_ctx->get_unit_info);
CHECK_MANDATORY (bridge_ctx->get_workitem_count);
CHECK_MANDATORY (bridge_ctx->get_workitem_multiple);
```

`get_workitem_multiple` is new and mandatory, so a bridge written against an earlier version will not
load until it is added. It is also a struct field, so an older bridge is refused by the
`bridge_context_size` check before anything else is looked at, with "bridge context size is invalid.
Old template?". Rebuild the bridge against the current headers.

### Function Roles

- platform_init: Called at startup. Responsible for initialization. This might include loading libraries, connecting to remote endpoints, or setting up hardware APIs. Returns a context pointer. `hashcat_ctx->folder_config` gives access to hashcat's resolved paths (`cache_dir`, `profile_dir`, `shared_dir`, ...), which already account for whether hashcat is running installed or from an unpacked directory. Use these instead of building paths yourself, otherwise a portable install will write to the wrong place, and a file you ship beside the binary will not be found once the same build is installed.
- platform_term: Final cleanup logic. Frees any context data allocated during initialization.
- get_unit_count: Returns the number of available units. For example, return `2` if two FPGAs are detected.
- get_unit_info: Returns a human-readable description of a unit, like "Python v3.13.3".
- get_workitem_count: Returns the largest number of password candidates the unit can be handed in one invocation. This is an upper limit, not a request: autotune searches below it and picks the size that measures fastest.
- get_workitem_multiple: Returns the granularity the unit computes in. Return `1` when a batch of N candidates costs N, which is the case for one thread working through its batch sequentially. Return the internal width when the unit processes candidates in parallel waves, so hashcat never hands it a partial wave.
- get_unit_class: Optional. Returns a string naming what KIND of thing a unit is, so hashcat can tell which units are interchangeable. See the section below.
- thread_init: Optional. Use for per-thread setup, such as creating a new Python interpreter.
- thread_term: Optional. Use for per-thread cleanup.
- salt_prepare: Called once per salt. Useful for preprocessing or storing large salt/esalt buffers.
- salt_destroy: Optional cleanup routine for any salt-specific memory.
- launch_loop: Main compute function. Replaces the traditional `_loop` kernel.
- launch_loop2: Secondary compute function. Replaces `_loop2` if needed.
- st_update_hash: Optionally override the module's default self-test hash.
- st_update_pass: Optionally override the module's default self-test password.

### Unit class: which of your units are interchangeable

`get_unit_class` is optional. It returns a string that is EQUAL for two units whenever the same
tuning is right for both.

hashcat aligns `-n`, `-u` and `-T` across devices of the same type, so a machine full of identical
cards does not show neighbouring devices running different batch sizes for no visible reason. That
test asks the BACKEND what a device is, and for a bridge it cannot work: every unit is one virtual
backend device cloned from the same physical one, so the answer is identical for all of them however
different the units really are. It cannot tell two units apart, and it cannot tell two units together
either. Only the bridge knows.

```c
char *get_unit_class (hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx);
```

Return the KIND, never the instance:

```
"Acme A100 accelerator, 64 lanes @ 400 MHz"                 // good
"Acme A100 accelerator, 64 lanes @ 400 MHz (/dev/acme2)"    // WRONG, no two units ever match
```

**No device path, no serial number, no index.** That is the whole difference between this and
`get_unit_info`, which names the individual device on purpose so a user can tell two cards apart.

Leave it as `BRIDGE_DEFAULT` and hashcat compares `get_unit_info` instead. That is correct when your
units really are identical, which is the normal case for a bridge whose units are CPU threads and
whose info strings are all the same string. You need `get_unit_class` only when your info string
names the individual unit.

Two units that cannot be described do not compare equal. A bridge that returns NULL gets no alignment
rather than being assumed uniform, because copying one unit's tuning onto a unit nobody could
identify is worse than leaving it alone.

### Reporting sensors

All optional. Implement the ones your hardware can answer and leave the rest as `BRIDGE_DEFAULT`.

```c
  int  (*get_unit_temperature)       (hashcat_ctx_t *, void *, const int);
  bool (*get_unit_temperature_str)   (hashcat_ctx_t *, void *, const int, char *, const size_t);
  bool (*get_unit_buslanes_str)      (hashcat_ctx_t *, void *, const int, char *, const size_t);
  u32  (*get_unit_temperature_abort) (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_fanspeed)          (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_utilization)       (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_corespeed)         (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_memoryspeed)       (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_buslanes)          (hashcat_ctx_t *, void *, const int);
  u64  (*get_unit_power)             (hashcat_ctx_t *, void *, const int);
```

Implementing ANY of these makes the bridge own the `Hardware.Mon` line for its units. That is
deliberate: without it the line describes the backend device, which under a bridge is only the
candidate feeder and is usually close to idle while the unit does the work, so its temperature and
clocks describe the wrong piece of hardware.

- Return a negative value for "no reading". The status line then shows `Temp: N/A` rather than
  dropping the field, because a line that silently omits what its neighbours show reads as breakage.
- `get_unit_temperature_str` is for a unit that is one piece of hardware carrying SEVERAL sensors, a
  board of four dies for instance. Write the whole field, `Temp: 34/36/34/37c`, so all of them appear
  on one line. `get_unit_temperature` should still return the HOTTEST, because that is what the abort
  watchdog must act on and an average would hide exactly the case that matters.
- `get_unit_temperature_abort` is the limit the part survives, which for anything that is not a GPU
  is rarely the 90 C default. hashcat applies the STRICTER of this and the user's
  `--hwmon-temp-abort`, so a cautious user setting is honoured and a reckless one still cannot run a
  part past what it survives. Zero means the unit has no opinion.
- A unit that reports no temperature is NOT watched, and hashcat says so rather than printing a
  threshold it can never enforce.
- `get_unit_buslanes_str` is for a unit whose link cannot be described by a lane count. Lanes are a
  PCIe idea, so a unit reached over USB has none and would otherwise leave the field empty, which
  beside a unit that DOES show lanes reads as a unit attached to nothing. Write what the link really
  is. Write the WHOLE field including its own label, `USB: 480Mb/s`, the same way a multi sensor
  temperature does: the label is part of the answer, and a fixed `Bus:` in front of it would say bus
  twice. Return false and hashcat falls back to `get_unit_buslanes`, then to `Bus: N/A`.

### The watchdog and status lines name units, not devices

Because one virtual backend device IS one bridge unit, `-d N`, `Speed.#NN`, `Hardware.Mon.#NN` and
the watchdog line all mean the same N. The watchdog says `bridge unit #N` where a compute device
would say `device #N`, so the two kinds cannot be confused on lines that sit next to each other.

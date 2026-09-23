# Assimilation Bridge Plugin Development

## Developer Section

The following section is for plugin and bridge developers. It contains low-level implementation details.

## Update existing plugins

A module written before bridge support was added must initialize the two bridge fields. Use the defaults unless the module actually selects a bridge:

```c
module_ctx->module_bridge_name = MODULE_DEFAULT;
module_ctx->module_bridge_type = MODULE_DEFAULT;
```

Current in-tree modules already contain these assignments. External modules need the same update when rebuilt against the current `module_ctx_t`.

## Plugin Integration and Bridge Registration

Plugins can opt in to bridge support by adding:

```c
static const u64   BRIDGE_TYPE = BRIDGE_TYPE_LAUNCH_LOOP;
static const char *BRIDGE_NAME = "scrypt_jane";
```

* `BRIDGE_NAME` tells hashcat which bridge to load, for example `bridge_scrypt_jane.so`.
* `BRIDGE_TYPE` selects where the bridge runs:

  * `BRIDGE_TYPE_LAUNCH_LOOP`: run the bridge after `RUN_LOOP`
  * `BRIDGE_TYPE_LAUNCH_LOOP2`: run the bridge after `RUN_LOOP2`
  * `BRIDGE_TYPE_REPLACE_LOOP`: replace `RUN_LOOP` with the bridge
  * `BRIDGE_TYPE_REPLACE_LOOP2`: replace `RUN_LOOP2` with the bridge

hashcat loads the bridge dynamically and uses it for any declared invocation.

Bridges are active only for `ATTACK_EXEC_OUTSIDE_KERNEL` modes. An inside-kernel, or "fast hash", mode ignores them. A hybrid therefore needs an outside-kernel implementation of the mode.

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

- `RUN_*` denotes a compute-kernel launch, including initialization and candidate amplification.
- `COPY_*` denotes a host-to-device or device-to-host transfer, normally over PCIe.
- `CALL_*` denotes a module hook executed on the host CPU. Hooks remain supported alongside bridges.
- `SALT_REPEATS` lets an algorithm reuse storage across salt-specific passes. Scrypt with `p > 1`, for example, can reuse its V and XY buffers while storing intermediate B values.
- `ITER_REPEATS` divides a long iteration count into watchdog-safe kernel launches. A 10,000-round operation may run as ten launches of 1,000 rounds.
- `BRIDGE_*` denotes a bridge callback. Hashcat copies the module-defined `tmps[]` buffer, called bridge material, to the host before the callback and back afterwards.
- `LOOP2` and `ITER2_REPEATS` support algorithms with a second long-running iterative component.

The bridge developer is responsible for interpreting `tmps[]` exactly as the surrounding kernels do. Hashcat performs the transfers, but it does not transform the data. If a bridge replaces scrypt's SMix loop, for example, it must accept the B state produced by the init kernel and return the form expected by the comp kernel. The structure, field representation and number of work items must all agree.

Two additional flags affect that contract:

* `BRIDGE_TYPE_UPDATE_SELFTEST` lets the bridge replace the module's self-test hash and password. Generic language bridges use this when the loaded script supplies its own test.
* `BRIDGE_TYPE_LOOP_CHUNKED` tells hashcat that `launch_loop()` honours `kernel_param.loop_pos` and `loop_cnt`. Set it only when the bridge can preserve candidate state across chunks. Without it, hashcat hands the bridge the complete iteration range in one call.

Two sets of flags were removed with no substitute, so a bridge written against the older interface names a symbol that no longer exists and does not compile: `BRIDGE_TYPE_MATCH_TUNINGS`, and the nine `BRIDGE_TYPE_FORCE_WORKITEMS_001` through `BRIDGE_TYPE_FORCE_WORKITEMS_256`. Delete them from your `BRIDGE_TYPE`. What replaced them is described next.

There is no flag to match tunings any more. hashcat derives the workitem count from what `get_workitem_count()` reports, for every bridge, and sizes the launch and the device buffers from that. The count is treated as a maximum the bridge will never be asked to exceed.

It is only the maximum, though, not the size hashcat will use. Autotune searches the range between one workitem multiple and that maximum, and picks the launch size that measures fastest, so a bridge no longer has to guess a good size and report it. `-n` sets the size directly and is clamped into the same range.

That is what `get_workitem_multiple()` is for, and it is mandatory. It reports the granularity your unit computes in. Return `1` if a batch of N candidates simply costs N, which is the case when one unit is one thread working through its batch sequentially. Return the internal width if your unit processes candidates in parallel waves, as an accelerator holding many cores behind a single unit does. hashcat rounds every launch size down to a whole multiple of it, which matters more than it looks: a unit that computes in waves of W is occupied for `ceil(N / W)` waves whatever N is, so a batch that is not a whole number of waves pays for capacity it never used, and a larger batch can be strictly slower than a smaller one in both throughput and latency.

Note the multiple describes your unit's internal width, not a DMA or buffer convenience. Reporting a transfer granularity instead will look like it works, because the launch sizes stay legal, and it will quietly cost throughput whenever the real width does not divide it.

## How Bridges Work

When hashcat starts a mode that declares a bridge, it loads the bridge and calls its platform initializer. The bridge then discovers its compute resources, called *bridge units*. A hardware bridge might load a vendor library and enumerate two accelerator cards. A software bridge might expose interpreters or worker pools instead. Each unit also provides a human-readable description.

Every bridge unit maps to one virtual backend device. This gives each unit an independent worker and launch size even when several units share one physical backend device. See the virtual backend device section below.

A bridge can accept four generic string parameters from the command line:

```
--bridge-parameter1
--bridge-parameter2
--bridge-parameter3
--bridge-parameter4
```

Callbacks read them from `hashcat_ctx->user_options->bridge_parameter1` through `bridge_parameter4`. An unset parameter is NULL.

## Virtual Backend Devices

Virtual backend devices can also be used without a bridge, but they were introduced so bridge units with different speeds or ideal batch sizes can run asynchronously. Hashcat partitions a physical backend device into virtual devices and links each one to a bridge unit. Two options control that mapping:

* Use `-Y` to define how many virtual backend devices to create.
* Use `-R` to bind the virtual devices to a physical backend device.

Note that if a bridge is used, the user's `-Y` parameter is overridden with the bridge unit count. If no bridge is used for a hash mode, then -Y can be manually specified. `-R` works in both cases. The default is device `1`, unless overridden.

Because each virtual backend device IS one bridge unit, **`-d` selects bridge units**. `-d 2` runs unit 2 and nothing else, `-d 1,3` runs units 1 and 3, and a number naming no unit is refused the same way an unknown compute device is. This is independent of `-R`, which still chooses the physical device that generates the candidates.

The numbering is shared, so `-d N`, `Speed.#NN`, `Hardware.Mon.#NN` and the watchdog's `bridge unit
#N` all refer to the same unit. A unit keeps its own index whatever else is filtered out, so `-d 3`
always drives unit 3 rather than whichever unit happened to survive the filter first. Bridge developers get this for free. There is nothing to implement for it.

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

### Bridge Initializer

A bridge exports only `bridge_init()`. The initializer records the interface it was built against and fills the callback table. Assign `BRIDGE_DEFAULT` to callbacks the bridge does not implement. Do not leave the older required-defined fields as null pointers.

```c
void bridge_init (bridge_ctx_t *bridge_ctx)
{
  bridge_ctx->bridge_context_size      = BRIDGE_CONTEXT_SIZE_CURRENT;
  bridge_ctx->bridge_interface_version = BRIDGE_INTERFACE_VERSION_CURRENT;

  bridge_ctx->platform_init         = platform_init;
  bridge_ctx->platform_term         = platform_term;
  bridge_ctx->get_unit_count        = get_unit_count;
  bridge_ctx->get_unit_info         = get_unit_info;
  bridge_ctx->get_workitem_count    = get_workitem_count;
  bridge_ctx->get_workitem_multiple = get_workitem_multiple;
  bridge_ctx->get_unit_class        = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_member_count = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_member_info  = BRIDGE_DEFAULT;

  bridge_ctx->thread_init  = BRIDGE_DEFAULT;
  bridge_ctx->thread_term  = BRIDGE_DEFAULT;
  bridge_ctx->salt_prepare = BRIDGE_DEFAULT;
  bridge_ctx->salt_destroy = BRIDGE_DEFAULT;
  bridge_ctx->launch_loop  = launch_loop;
  bridge_ctx->launch_loop2 = BRIDGE_DEFAULT;
  bridge_ctx->st_update_hash = BRIDGE_DEFAULT;
  bridge_ctx->st_update_pass = BRIDGE_DEFAULT;

  bridge_ctx->get_unit_temperature           = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_str       = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_abort     = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_temperature_unwatched = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_fanspeed              = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_utilization           = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_corespeed             = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_memoryspeed           = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_buslanes              = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_buslanes_str          = BRIDGE_DEFAULT;
  bridge_ctx->get_unit_power                 = BRIDGE_DEFAULT;
}
```

The principal callbacks are declared as follows:

```c
  void     *(*platform_init)      (hashcat_ctx_t *);
  void      (*platform_term)      (hashcat_ctx_t *, void *);
  int       (*get_unit_count)        (hashcat_ctx_t *, void *);
  char     *(*get_unit_info)         (hashcat_ctx_t *, void *, const int);
  int       (*get_workitem_count)    (hashcat_ctx_t *, void *, const int);
  int       (*get_workitem_multiple) (hashcat_ctx_t *, void *, const int);
  char     *(*get_unit_class)        (hashcat_ctx_t *, void *, const int);
  int       (*get_unit_member_count) (hashcat_ctx_t *, void *, const int);
  char     *(*get_unit_member_info)  (hashcat_ctx_t *, void *, const int, const int);
  bool      (*salt_prepare)       (hashcat_ctx_t *, void *, hashconfig_t *, hashes_t *);
  void      (*salt_destroy)       (hashcat_ctx_t *, void *, hashconfig_t *, hashes_t *);
  bool      (*thread_init)        (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *);
  void      (*thread_term)        (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *);
  bool      (*launch_loop)        (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);
  bool      (*launch_loop2)       (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);
  const char *(*st_update_pass)  (hashcat_ctx_t *, void *);
  const char *(*st_update_hash)  (hashcat_ctx_t *, void *);
```

The complete structure, including sensor callbacks, is defined in `include/types.h`.

### Every entry takes `hashcat_ctx_t *` first

Interface version 720 carries this change. A bridge written against an older interface has the wrong signature on every single entry, and `platform_init`'s parameters are gone entirely: `user_options_t` and `folder_config_t` are both reachable through the context now.

The reason is logging. A bridge that has the context can call `event_log_info`, `event_log_warning` and `event_log_error` exactly as hashcat's own code does, so its messages go through hashcat's event system, honour `--quiet`, and appear in the right order with everything else. Writing to `stderr` from a bridge does none of that, and on Windows a DLL's `stderr` is not even the host's.

No wrapper or callback is needed. Every `event_log_*` symbol is already linked into every bridge.

Two things to know before reaching through the context:

- **`event_log_error` prints a BLANK LINE after its message.** It is a paragraph printer, not a line printer, because hashcat's own errors are single sentences. Use ONE `event_log_error` for the headline and `event_log_info` for each body line, and do not add your own blank line after the headline. A headline must also fit on one line or the blank splits the sentence in half.
- **Never read `hashcat_ctx->hashes`.** The self test hands `launch_loop` and friends a `hashes_t` that is a LOCAL COPY, with the digest, salt, esalt and hook salt buffers swapped for the self test's own. That is why these functions still take `hashconfig` and `hashes` explicitly even though both are reachable from the context. Reading the context instead silently computes against the user's real hashes during the self test.

### Mandatory Functions

The following six callbacks must have implementations:

```c
platform_init
platform_term
get_unit_count
get_unit_info
get_workitem_count
get_workitem_multiple
```

In addition, every loop named by the module's `BRIDGE_TYPE` must be implemented: `launch_loop` for a launch or replacement of `LOOP`, and `launch_loop2` for `LOOP2`. Other callbacks use `BRIDGE_DEFAULT` when they are not needed.

`get_workitem_multiple` is mandatory in the current interface. An older bridge is normally refused first by the `bridge_context_size` check with "bridge context size is invalid. Old template?". Rebuild it against the current headers and update the initializer.

### Function Roles

- platform_init: Called at startup. Responsible for initialization. This might include loading libraries, connecting to remote endpoints, or setting up hardware APIs. Returns a context pointer. `hashcat_ctx->folder_config` gives access to hashcat's resolved paths (`cache_dir`, `profile_dir`, `shared_dir`, ...), which already account for whether hashcat is running installed or from an unpacked directory. Use these instead of building paths yourself, otherwise a portable install will write to the wrong place, and a file you ship beside the binary will not be found once the same build is installed.
- platform_term: Final cleanup logic. Frees any context data allocated during initialization.
- get_unit_count: Returns the number of available units. For example, return `2` if two FPGAs are detected.
- get_unit_info: Returns a human-readable description of a unit, like "Python v3.13.3".
- get_workitem_count: Returns the largest number of password candidates the unit can be handed in one invocation. This is an upper limit, not a request: autotune searches below it and picks the size that measures fastest.
- get_workitem_multiple: Returns the granularity the unit computes in. Return `1` when a batch of N candidates costs N, which is the case for one thread working through its batch sequentially. Return the internal width when the unit processes candidates in parallel waves, so hashcat never hands it a partial wave.
- get_unit_class: Optional. Returns a string naming what KIND of thing a unit is, so hashcat can tell which units are interchangeable. See the section below.
- get_unit_member_count and get_unit_member_info: Optional. Describe the hardware members combined into one unit. Implement both or neither.
- thread_init: Optional. Use for per-thread setup, such as creating a new Python interpreter.
- thread_term: Optional. Use for per-thread cleanup.
- salt_prepare: Called once after the hashes are loaded. Use it to preprocess salt or esalt data for the whole hash set.
- salt_destroy: Matching cleanup for data allocated by `salt_prepare`.
- launch_loop: Compute callback associated with `_loop`. It runs after the kernel or replaces it, according to `BRIDGE_TYPE`.
- launch_loop2: Equivalent callback for `_loop2`.
- st_update_hash: Optionally override the module's default self-test hash.
- st_update_pass: Optionally override the module's default self-test password.

### Unit class: which of your units are interchangeable

`get_unit_class` is optional. It returns a string that is EQUAL for two units whenever the same tuning is right for both.

hashcat aligns `-n`, `-u` and `-T` across devices of the same type, so a machine full of identical cards does not show neighbouring devices running different batch sizes for no visible reason. That test asks the BACKEND what a device is, and for a bridge it cannot work: every unit is one virtual backend device cloned from the same physical one, so the answer is identical for all of them however different the units really are. It cannot tell two units apart, and it cannot tell two units together either. Only the bridge knows.

```c
char *get_unit_class (hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx);
```

Return the KIND, never the instance:

```
"Acme A100 accelerator, 64 lanes @ 400 MHz"                 // good
"Acme A100 accelerator, 64 lanes @ 400 MHz (/dev/acme2)"    // WRONG, no two units ever match
```

**No device path, no serial number, no index.** That is the whole difference between this and `get_unit_info`, which names the individual device on purpose so a user can tell two cards apart.

Leave it as `BRIDGE_DEFAULT` and hashcat compares `get_unit_info` instead. That is correct when your units really are identical, which is the normal case for a bridge whose units are CPU threads and whose info strings are all the same string. You need `get_unit_class` only when your info string names the individual unit.

Two units that cannot be described do not compare equal. A bridge that returns NULL gets no alignment rather than being assumed uniform, because copying one unit's tuning onto a unit nobody could identify is worse than leaving it alone.

### Units made of several members

A bridge may combine several hardware components into one scheduling unit. Implement both `get_unit_member_count` and `get_unit_member_info` so the startup and `--backend-info` displays can show what that unit contains. A bridge whose units are individual devices leaves both callbacks at `BRIDGE_DEFAULT`.

```c
int get_unit_member_count (hashcat_ctx_t *hashcat_ctx, void *platform_context,
                           const int unit_idx);
char *get_unit_member_info (hashcat_ctx_t *hashcat_ctx, void *platform_context,
                            const int unit_idx, const int member_idx);
```

Member indices start at zero and must match any numbering the bridge uses elsewhere. Return NULL from `get_unit_member_info` for an invalid index. These callbacks describe composition, not scheduling: `-d` still selects the containing bridge unit.

### Reporting sensors

All optional. Implement the ones your hardware can answer and leave the rest as `BRIDGE_DEFAULT`.

```c
  int  (*get_unit_temperature)       (hashcat_ctx_t *, void *, const int);
  bool (*get_unit_temperature_str)   (hashcat_ctx_t *, void *, const int, char *, const size_t);
  bool (*get_unit_buslanes_str)      (hashcat_ctx_t *, void *, const int, char *, const size_t);
  u32  (*get_unit_temperature_abort)     (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_temperature_unwatched) (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_fanspeed)          (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_utilization)       (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_corespeed)         (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_memoryspeed)       (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_buslanes)          (hashcat_ctx_t *, void *, const int);
  u64  (*get_unit_power)             (hashcat_ctx_t *, void *, const int);
```

Implementing any primary sensor callback, or `get_unit_temperature_str`, makes the bridge own the `Hardware.Mon` line for its units. The bus description and unwatched-member count supplement that line but do not activate it by themselves. Without bridge-owned monitoring, the line describes the backend device, which under a bridge is only the candidate feeder and is usually close to idle while the unit does the work.

- Return a negative value for "no reading". The status line then shows `Temp: N/A` rather than dropping the field, because a line that silently omits what its neighbours show reads as breakage.
- `get_unit_temperature_str` is for a unit that is one piece of hardware carrying SEVERAL sensors, a board of four dies for instance. Write the whole field, `Temp: 34/36/34/37c`, so all of them appear on one line. `get_unit_temperature` should still return the HOTTEST, because that is what the abort watchdog must act on and an average would hide exactly the case that matters.
- `get_unit_temperature_abort` is the limit the part survives, which for anything that is not a GPU is rarely the 90 C default. hashcat applies the STRICTER of this and the user's `--hwmon-temp-abort`, so a cautious user setting is honoured and a reckless one still cannot run a part past what it survives. Zero means the unit has no opinion.
- A unit that reports no temperature is NOT watched, and hashcat says so rather than printing a threshold it can never enforce. For a grouped unit, `get_unit_temperature_unwatched` returns how many members have no sensor. Return zero when every member is covered.
- `get_unit_buslanes_str` is for a unit whose link cannot be described by a lane count. Lanes are a PCIe idea, so a unit reached over USB has none and would otherwise leave the field empty, which beside a unit that DOES show lanes reads as a unit attached to nothing. Write what the link really is. Write the WHOLE field including its own label, `USB: 480Mb/s`, the same way a multi sensor temperature does: the label is part of the answer, and a fixed `Bus:` in front of it would say bus twice. Return false and hashcat falls back to `get_unit_buslanes`, then to `Bus: N/A`.

### The watchdog and status lines name units, not devices

Because one virtual backend device IS one bridge unit, `-d N`, `Speed.#NN`, `Hardware.Mon.#NN` and the watchdog line all mean the same N. The watchdog says `bridge unit #N` where a compute device would say `device #N`, so the two kinds cannot be confused on lines that sit next to each other.

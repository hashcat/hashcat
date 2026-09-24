# Assimilation Bridge Plugin Development

## Updating existing plugins

A module written before bridge support was added must initialize the two bridge fields. Use the defaults unless the module actually selects a bridge:

```c
module_ctx->module_bridge_name = MODULE_DEFAULT;
module_ctx->module_bridge_type = MODULE_DEFAULT;
```

Current in-tree modules already contain these assignments. External modules need the same update when rebuilt against the current `module_ctx_t`.

## Plugin integration and bridge registration

Plugins can opt in to bridge support by adding:

```c
static const u64   BRIDGE_TYPE = BRIDGE_TYPE_LAUNCH_LOOP;
static const char *BRIDGE_NAME = "scrypt_jane";
```

* `BRIDGE_NAME` identifies the bridge to load, for example `bridge_scrypt_jane.so`.
* `BRIDGE_TYPE` selects where the bridge runs:

  * `BRIDGE_TYPE_LAUNCH_LOOP`: run the bridge after `RUN_LOOP`
  * `BRIDGE_TYPE_LAUNCH_LOOP2`: run the bridge after `RUN_LOOP2`
  * `BRIDGE_TYPE_REPLACE_LOOP`: replace `RUN_LOOP` with the bridge
  * `BRIDGE_TYPE_REPLACE_LOOP2`: replace `RUN_LOOP2` with the bridge

hashcat loads the bridge dynamically and uses it for any declared invocation.

Bridges are active only for `ATTACK_EXEC_OUTSIDE_KERNEL` modes. An inside-kernel, or "fast hash", mode ignores them. A hybrid therefore needs an outside-kernel implementation of the mode.

The following outline shows the main stages hashcat executes for a batch of candidates:

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
- `BRIDGE_*` denotes a bridge callback. hashcat copies the module-defined `tmps[]` buffer, called bridge material, to the host before the callback and returns it to the device afterward.
- `LOOP2` and `ITER2_REPEATS` support algorithms with a second long-running iterative component.

The bridge developer is responsible for interpreting `tmps[]` exactly as the surrounding kernels do. hashcat performs the transfers, but it does not transform the data. If a bridge replaces scrypt's SMix loop, for example, it must accept the B state produced by the init kernel and return the form expected by the comp kernel. The structure, field representation and number of work items must all agree.

Two additional flags affect that contract:

* `BRIDGE_TYPE_UPDATE_SELFTEST` lets the bridge replace the module's self-test hash and password. Generic language bridges use this when the loaded script supplies its own test.
* `BRIDGE_TYPE_LOOP_CHUNKED` indicates that `launch_loop()` honours `kernel_param.loop_pos` and `loop_cnt`. Set it only when the bridge can preserve candidate state across chunks. Without it, hashcat hands the bridge the complete iteration range in one call.

Two sets of flags were removed without direct replacements: `BRIDGE_TYPE_MATCH_TUNINGS` and the nine flags from `BRIDGE_TYPE_FORCE_WORKITEMS_001` through `BRIDGE_TYPE_FORCE_WORKITEMS_256`. A bridge using the old symbols no longer compiles. Remove them from `BRIDGE_TYPE` and use the work-item callbacks described below.

Tuning no longer requires an opt-in flag. For every bridge, hashcat sizes launches and device buffers from the value returned by `get_workitem_count()`. This value is an upper bound that hashcat never exceeds.

The reported count is not necessarily the launch size. Autotune searches from one work-item multiple up to that maximum and selects the fastest measured size, so the bridge does not need to predict an ideal value. Option `-n` sets the size directly and is clamped to the same range.

Mandatory callback `get_workitem_multiple()` reports the granularity at which a unit computes. Return `1` when processing N candidates costs N units of work, as it does for one thread handling a batch sequentially. Return the internal width when the unit processes candidates in parallel waves, as an accelerator with many cores behind one unit would.

hashcat rounds every launch size down to a whole multiple of this value. A unit with a wave width of W remains occupied for `ceil(N / W)` waves, so a partial wave consumes capacity without processing useful candidates. A larger but misaligned batch can therefore have worse throughput and latency than a smaller aligned batch.

The multiple describes the unit's computational width, not a convenient DMA or buffer size. Reporting a transfer granularity can produce valid launches while silently reducing throughput whenever it is not divisible by the actual width.

## How bridges work

When hashcat starts a mode that declares a bridge, it loads the bridge and calls its platform initializer. The bridge then discovers its compute resources, called *bridge units*. A hardware bridge might load a vendor library and enumerate two accelerator cards. A software bridge might expose interpreters or worker pools instead. Each unit also provides a human-readable description.

Every bridge unit maps to one virtual backend device. This gives each unit an independent worker and launch size even when several units share one physical backend device. See the virtual backend device section below.

A bridge can accept four generic string parameters from the command line:

```
--bridge-parameter1
--bridge-parameter2
--bridge-parameter3
--bridge-parameter4
```

Callbacks read them from `hashcat_ctx->user_options->bridge_parameter1` through `bridge_parameter4`. An unset parameter is `NULL`.

## Virtual backend devices

Virtual backend devices can also be used without a bridge, but they were introduced so bridge units with different speeds or ideal batch sizes can run asynchronously. hashcat partitions a physical backend device into virtual devices and links each one to a bridge unit. Two options control that mapping:

* Use `-Y` to define how many virtual backend devices to create.
* Use `-R` to bind the virtual devices to a physical backend device.

When a bridge is active, its unit count overrides the value supplied with `-Y`. Without a bridge, the user can set `-Y` directly. Option `-R` works in both cases and defaults to device `1`.

Because each virtual backend device represents one bridge unit, **option `-d` selects bridge units**. Command `-d 2` runs only unit 2, while `-d 1,3` runs units 1 and 3. hashcat rejects an unknown unit number in the same way it rejects an unknown compute device. This selection is independent of `-R`, which chooses the physical device that generates candidates.

The numbering is shared, so `-d N`, `Speed.#NN`, `Hardware.Mon.#NN` and the watchdog's `bridge unit #N` all refer to the same unit. A unit retains its index when other units are filtered out, so `-d 3` always selects unit 3 rather than the third surviving unit. This behavior requires no bridge-specific implementation.

## Writing a bridge

### File layout

Bridges live in the `src/bridges/` directory and consist of a `.c` file and a `.mk` build rule:

```
src/bridges/bridge_scrypt_jane.c
src/bridges/bridge_scrypt_jane.mk
```

The output should be named `bridges/bridge_scrypt_jane.so` on Unix-like systems or `bridges/bridge_scrypt_jane.dll` on Windows. Use an existing `.mk` file as a template.

At startup, hashcat resolves the plugin path as follows:

```
  #if defined (_WIN) || defined (__CYGWIN__)
  return snprintf (out_buf, out_size, "%s/bridges/bridge_%s.dll", folder_config->shared_dir, bridge_name);
  #else
  return snprintf (out_buf, out_size, "%s/bridges/bridge_%s.so", folder_config->shared_dir, bridge_name);
  #endif
```

### Bridge initializer

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

  bridge_ctx->thread_init    = BRIDGE_DEFAULT;
  bridge_ctx->thread_term    = BRIDGE_DEFAULT;
  bridge_ctx->salt_prepare   = BRIDGE_DEFAULT;
  bridge_ctx->salt_destroy   = BRIDGE_DEFAULT;
  bridge_ctx->launch_loop    = launch_loop;
  bridge_ctx->launch_loop2   = BRIDGE_DEFAULT;
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
  void       *(*platform_init)         (hashcat_ctx_t *);
  void        (*platform_term)         (hashcat_ctx_t *, void *);
  int         (*get_unit_count)        (hashcat_ctx_t *, void *);
  char       *(*get_unit_info)         (hashcat_ctx_t *, void *, const int);
  int         (*get_workitem_count)    (hashcat_ctx_t *, void *, const int);
  int         (*get_workitem_multiple) (hashcat_ctx_t *, void *, const int);
  char       *(*get_unit_class)        (hashcat_ctx_t *, void *, const int);
  int         (*get_unit_member_count) (hashcat_ctx_t *, void *, const int);
  char       *(*get_unit_member_info)  (hashcat_ctx_t *, void *, const int, const int);
  bool        (*salt_prepare)          (hashcat_ctx_t *, void *, hashconfig_t *, hashes_t *);
  void        (*salt_destroy)          (hashcat_ctx_t *, void *, hashconfig_t *, hashes_t *);
  bool        (*thread_init)           (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *);
  void        (*thread_term)           (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *);
  bool        (*launch_loop)           (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);
  bool        (*launch_loop2)          (hashcat_ctx_t *, void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);
  const char *(*st_update_pass)        (hashcat_ctx_t *, void *);
  const char *(*st_update_hash)        (hashcat_ctx_t *, void *);
```

The complete structure, including sensor callbacks, is defined in `include/types.h`.

### Every callback receives `hashcat_ctx_t *` first

Interface version 720 introduced this change. Every callback in an older bridge has an incompatible signature. The previous parameters of `platform_init` were also removed because both `user_options_t` and `folder_config_t` are now available through the context.

The primary reason is logging. With access to the context, a bridge can use `event_log_info`, `event_log_warning` and `event_log_error` like hashcat's own code. Its messages then pass through the event system, honor `--quiet` and remain correctly ordered. Direct output to `stderr` provides none of these guarantees, and a Windows DLL may not share the host process's `stderr`.

No wrapper or callback is needed. Every `event_log_*` symbol is already linked into every bridge.

Two things to know before reaching through the context:

- **Function `event_log_error` prints a blank line after its message.** It prints a complete error paragraph rather than an individual line. Use one call for the headline and `event_log_info` for each body line. Do not add another blank line, and keep the headline on one line so the automatic spacing does not split a sentence.
- **Never read `hashcat_ctx->hashes`.** The self-test passes `launch_loop` and related callbacks a local `hashes_t` copy whose digest, salt, esalt and hook-salt buffers contain the self-test data. These callbacks receive `hashconfig` and `hashes` explicitly for this reason, even though both are accessible through the context. Reading the context instead silently computes against the user's hashes during the self-test.

### Mandatory functions

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

Callback `get_workitem_multiple` is mandatory in the current interface. An older bridge is normally refused first by the `bridge_context_size` check with "bridge context size is invalid. Old template?". Rebuild it against the current headers and update the initializer.

### Function roles

- Callback `platform_init` runs at startup and returns a context pointer. It can load libraries, connect to remote endpoints or initialize hardware APIs. Structure member `hashcat_ctx->folder_config` gives access to hashcat's resolved paths (`cache_dir`, `profile_dir`, `shared_dir`, ...), which already account for whether hashcat is running installed or from an unpacked directory. Use these instead of building paths yourself, otherwise a portable install will write to the wrong place, and a file you ship beside the binary will not be found once the same build is installed.
- Callback `platform_term` performs final cleanup and frees context data allocated during initialization.
- Callback `get_unit_count` returns the number of available units. For example, return `2` when two FPGAs are detected.
- Callback `get_unit_info` returns a human-readable unit description, such as `Python v3.13.3`.
- Callback `get_workitem_count` returns the maximum number of candidates a unit can receive in one invocation. This is an upper bound, not a requested launch size. Autotune searches below it and selects the fastest measured value.
- Callback `get_workitem_multiple` returns the computational granularity of the unit. Return `1` when processing N candidates costs N units of work, as it does for one thread handling a batch sequentially. Return the internal width for parallel waves so hashcat never supplies a partial wave.
- Optional callback `get_unit_class` identifies the type of unit so hashcat can determine which units are interchangeable. See the section below.
- Optional callbacks `get_unit_member_count` and `get_unit_member_info` describe the hardware members combined into one unit. Implement both or neither.
- Optional callback `thread_init` performs per-thread setup, such as creating a Python interpreter.
- Optional callback `thread_term` performs per-thread cleanup.
- Callback `salt_prepare` runs once after the hashes are loaded and can preprocess salt or esalt data for the complete hash set.
- Callback `salt_destroy` releases data allocated by `salt_prepare`.
- Callback `launch_loop` is associated with `_loop`. Depending on `BRIDGE_TYPE`, it runs after the kernel or replaces it.
- Callback `launch_loop2` provides the equivalent operation for `_loop2`.
- Optional callback `st_update_hash` overrides the module's default self-test hash.
- Optional callback `st_update_pass` overrides the module's default self-test password.

### Unit classes and interchangeable units

Optional callback `get_unit_class` returns the same string for any two units that should share tuning values.

hashcat aligns `-n`, `-u` and `-T` across devices of the same type so identical devices do not use visibly different batch sizes. For ordinary devices, the backend supplies that identity.

A bridge cannot use the backend identity because every unit is represented by a virtual device cloned from the same physical device. The backend therefore reports the same identity even when the bridge units differ. Only the bridge can classify them correctly.

```c
char *get_unit_class (hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx);
```

Return the unit type, never the individual instance:

```
"Acme A100 accelerator, 64 lanes @ 400 MHz"                 // good
"Acme A100 accelerator, 64 lanes @ 400 MHz (/dev/acme2)"    // WRONG, no two units ever match
```

**Do not include a device path, serial number or index.** Unlike the class callback, `get_unit_info` deliberately identifies an individual device so users can distinguish otherwise identical units.

When the callback is left as `BRIDGE_DEFAULT`, hashcat compares `get_unit_info` instead. That is correct when your units really are identical, which is the normal case for a bridge whose units are CPU threads and whose info strings are all the same string. You need `get_unit_class` only when your info string names the individual unit.

Units that cannot be described do not compare as equal. If a bridge returns `NULL`, hashcat leaves their tunings independent instead of assuming that unidentified units are interchangeable.

### Units made of several members

A bridge may combine several hardware components into one scheduling unit. Implement both `get_unit_member_count` and `get_unit_member_info` so the startup and `--backend-info` displays can show what that unit contains. A bridge whose units are individual devices leaves both callbacks at `BRIDGE_DEFAULT`.

```c
int   get_unit_member_count (hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx);
char *get_unit_member_info  (hashcat_ctx_t *hashcat_ctx, void *platform_context, const int unit_idx, const int member_idx);
```

Member indices start at zero and must match any numbering used elsewhere by the bridge. Return `NULL` from `get_unit_member_info` for an invalid index. These callbacks describe composition, not scheduling: `-d` still selects the containing bridge unit.

### Reporting sensors

All sensor callbacks are optional. Implement those supported by the hardware and leave the rest as `BRIDGE_DEFAULT`.

```c
  int  (*get_unit_temperature)           (hashcat_ctx_t *, void *, const int);
  bool (*get_unit_temperature_str)       (hashcat_ctx_t *, void *, const int, char *, const size_t);
  bool (*get_unit_buslanes_str)          (hashcat_ctx_t *, void *, const int, char *, const size_t);
  u32  (*get_unit_temperature_abort)     (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_temperature_unwatched) (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_fanspeed)              (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_utilization)           (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_corespeed)             (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_memoryspeed)           (hashcat_ctx_t *, void *, const int);
  int  (*get_unit_buslanes)              (hashcat_ctx_t *, void *, const int);
  u64  (*get_unit_power)                 (hashcat_ctx_t *, void *, const int);
```

Implementing any primary sensor callback, or `get_unit_temperature_str`, makes the bridge own the `Hardware.Mon` line for its units. The bus description and unwatched-member count supplement that line but do not activate it by themselves. Without bridge-owned monitoring, the line describes the backend device, which under a bridge is only the candidate feeder and is usually close to idle while the unit does the work.

- Return a negative value when no reading is available. The status line then shows `Temp: N/A` instead of omitting a field displayed for neighboring units.
- Callback `get_unit_temperature_str` supports a single hardware unit with several sensors, such as a board containing four dies. Write the complete field, for example `Temp: 34/36/34/37c`, so all readings appear on one line. Callback `get_unit_temperature` should still return the highest temperature because the abort watchdog must act on the hottest component.
- Callback `get_unit_temperature_abort` reports the safe limit for the component, which may differ from the 90 C GPU default. hashcat applies the lower of this value and the user's `--hwmon-temp-abort` setting. A value of zero means that the unit specifies no limit.
- A unit that reports no temperature cannot be monitored by the watchdog. hashcat reports this condition instead of displaying an unenforceable threshold. For a grouped unit, `get_unit_temperature_unwatched` returns the number of members without a sensor. Return zero when every member is covered.
- Callback `get_unit_buslanes_str` describes a connection that cannot be expressed as a PCIe lane count, such as USB. Write the complete field including its label, for example `USB: 480Mb/s`. Return false to fall back first to `get_unit_buslanes` and then to `Bus: N/A`.

### Watchdog and status output identifies units

Because each virtual backend device represents one bridge unit, `-d N`, `Speed.#NN`, `Hardware.Mon.#NN` and the watchdog all use the same unit number. The watchdog reports `bridge unit #N` rather than `device #N`, clearly distinguishing bridge units from compute devices in adjacent output.

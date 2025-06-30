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
static const u64   BRIDGE_TYPE = BRIDGE_TYPE_MATCH_TUNINGS
                               | BRIDGE_TYPE_LAUNCH_LOOP;
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

+  BRIDGE_TYPE_MATCH_TUNINGS       = Disables autotune and adjusts -n, -u and -T for the backend device according to match the bridge's dimensions
+  BRIDGE_TYPE_UPDATE_SELFTEST     = updates the selftest configured in the module. Can be useful for generic hash modes such as the python plugin

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
```

They are defined like this:

```c
  void     *(*platform_init)      (user_options_t *);
  void      (*platform_term)      (void *);
  int       (*get_unit_count)     (void *);
  char     *(*get_unit_info)      (void *, const int);
  int       (*get_workitem_count) (void *, const int);
  bool      (*salt_prepare)       (void *, hashconfig_t *, hashes_t *);
  void      (*salt_destroy)       (void *, hashconfig_t *, hashes_t *);
  bool      (*thread_init)        (void *, hc_device_param_t *, hashconfig_t *, hashes_t *);
  void      (*thread_term)        (void *, hc_device_param_t *, hashconfig_t *, hashes_t *);
  bool      (*launch_loop)        (void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);
  bool      (*launch_loop2)       (void *, hc_device_param_t *, hashconfig_t *, hashes_t *, const u32, const u64);
  const char *(*st_update_pass)  (void *);
  const char *(*st_update_hash)  (void *);
```

**Note**: Use `BRIDGE_DEFAULT` when no function implementation is required.

### Mandatory Functions

The following functions must be defined:

```c
CHECK_MANDATORY (bridge_ctx->platform_init);
CHECK_MANDATORY (bridge_ctx->platform_term);
CHECK_MANDATORY (bridge_ctx->get_unit_count);
CHECK_MANDATORY (bridge_ctx->get_unit_info);
CHECK_MANDATORY (bridge_ctx->get_workitem_count);
```

### Function Roles

- platform_init: Called at startup. Responsible for initialization. This might include loading libraries, connecting to remote endpoints, or setting up hardware APIs. Returns a context pointer.
- platform_term: Final cleanup logic. Frees any context data allocated during initialization.
- get_unit_count: Returns the number of available units. For example, return `2` if two FPGAs are detected.
- get_unit_info: Returns a human-readable description of a unit, like "Python v3.13.3".
- get_workitem_count: Returns the number of password candidates to process per invocation.
- thread_init: Optional. Use for per-thread setup, such as creating a new Python interpreter.
- thread_term: Optional. Use for per-thread cleanup.
- salt_prepare: Called once per salt. Useful for preprocessing or storing large salt/esalt buffers.
- salt_destroy: Optional cleanup routine for any salt-specific memory.
- launch_loop: Main compute function. Replaces the traditional `_loop` kernel.
- launch_loop2: Secondary compute function. Replaces `_loop2` if needed.
- st_update_hash: Optionally override the module's default self-test hash.
- st_update_pass: Optionally override the module's default self-test password.

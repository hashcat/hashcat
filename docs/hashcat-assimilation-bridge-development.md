
## Developer Section

The following section is for plugin and bridge developers. It contains low-level implementation details. It's a first draft, expect more details to fill in soon.

---

## Plugin Integration and Bridge Registration

Plugins can opt in to bridge support by adding:

```c
static const u64   BRIDGE_TYPE = BRIDGE_TYPE_MATCH_TUNINGS
                               | BRIDGE_TYPE_LAUNCH_LOOP;
static const char *BRIDGE_NAME = "scrypt_jane";
```

* `BRIDGE_NAME` tells Hashcat which bridge to load (e.g., `bridge_scrypt_jane.so`).
* `BRIDGE_TYPE` indicates which backend kernel functions the bridge will override:

  * `BRIDGE_TYPE_LAUNCH_LOOP`
  * `BRIDGE_TYPE_LAUNCH_LOOP2`

Hashcat loads the bridge dynamically and uses it for any declared replacements. It's the developer's responsibility to ensure compatibility. That typically means the handling of the `tmps` variable relevant in the `kernel_loop` and how it changes over time. Hashcat will take care of copying the data from and to the compute backend (GPU) buffers.

---

## How Bridges Work

When Hashcat starts with a plugin that specifies a bridge, it loads the bridge and invokes its initialization function. The bridge must then discover its internal compute units, called *bridge units*. This is done manually by the bridge developer.

Each bridge unit maps to one virtual backend device, which allows asynchronous and independent parallel execution.

### Virtual Backend Devices

* Use `-Y` to define how many virtual backend devices to create.
* Use `-R` to bind these virtual devices to a physical backend host (new in v7).

This structure supports mixed-performance hardware without bottlenecks.

---

## Writing a Bridge

### File Layout

Bridges live in the `src/bridges/` directory and consist of a `.c` file and a `.mk` build rule:

```
src/bridges/bridge_scrypt_jane.c
src/bridges/bridge_scrypt_jane.mk
```

Example build rule:

```
bridges/bridge_scrypt_jane.so: src/bridges/bridge_scrypt_jane.c
```

Hashcat will automatically load this shared object based on the plugin's `BRIDGE_NAME`.

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

> Use `BRIDGE_DEFAULT` when no function implementation is required.

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

**platform\_init**
Called at startup. Responsible for initialization. This might include loading libraries, connecting to remote endpoints, or setting up hardware APIs. Returns a context pointer.

**platform\_term**
Final cleanup logic. Frees any context data allocated during initialization.

**get\_unit\_count**
Returns the number of available units. For example, return `2` if two FPGAs are detected.

**get\_unit\_info**
Returns a human-readable description of a unit, like "Python v3.13.3".

**get\_workitem\_count**
Returns the number of password candidates to process per invocation.

**thread\_init**
Optional. Use for per-thread setup, such as creating a new Python interpreter.

**thread\_term**
Optional. Use for per-thread cleanup.

**salt\_prepare**
Called once per salt. Useful for preprocessing or storing large salt/esalt buffers.

**salt\_destroy**
Optional cleanup routine for any salt-specific memory.

**launch\_loop**
Main compute function. Replaces the traditional `_loop` kernel.

**launch\_loop2**
Secondary compute function. Replaces `_loop2` if needed.

**st\_update\_hash**
Optionally override the module's default self-test hash.

**st\_update\_pass**
Optionally override the module's default self-test password.

# hashcat Plugin Development Guide #

This guide explains how to develop hash-mode plugins for hashcat. It covers the module and kernel interfaces, the test suite, and the design choices required for both simple and complex modes.

The current plugin interface was introduced with hashcat 6.0.0 to make new hash modes easier to add and maintain.

The interface separates hash-mode code from the core. hashcat loads modules from `.so`, `.dll` or `.dylib` files at startup, allowing authors to distribute source code or compiled plugins without modifying the core. Every included hash mode uses this interface.

The interface changes only when a real need justifies it. A compile-time interface version lets hashcat reject an incompatible binary before calling into it. Rebuild an external binary plugin whenever that version changes. Source plugins are compiled against the installed headers.

The kernel library provides GPU-optimized cryptographic interfaces modeled after OpenSSL. They follow the familiar sequence of context initialization, update and finalization functions. Refactored pure kernels use this design throughout, making existing kernels useful references for new implementations.

A first plugin can appear complex, but most modes follow the same development sequence. Work through the module, reference implementation and kernel as separate, verifiable stages.

## Plugin structure ##

A hashcat plugin normally consists of two source files:

* **Module:** Host-side C code that configures the hash mode, decodes hash lines and stores their fields in standard hashcat structures. Optional callbacks support format-specific parsing, encoding and workflow behavior. Modules are stored in `src/modules/`.
* **Kernel:** The compute-intensive implementation of the hash mode. Kernels are stored in `OpenCL/`. The CUDA backend also compiles these `.cl` sources through NVRTC.

Together, the module and kernel form a hashcat hash-mode plugin.

An optional third file is the test module. It implements the algorithm in a high-level language for use by hashcat's test suite. The suite generates passwords, salts and hashes, then compares the reference results with the plugin across attack modes and boundary conditions.

## Before the code ##

Module development requires C. Experience implementing cryptographic algorithms in another language is also useful, but this guide cannot cover every rarely used callback or kernel feature. Existing plugins remain an essential source of examples.

Understand the algorithm completely before implementing it. Develop in small stages and verify intermediate values at each boundary. For `md5(sha1($p))`, implement and validate `sha1($p)` before adding MD5.

Obtain reference values from existing proof-of-concept code or write a reference implementation first. Its language does not matter as long as it can expose every intermediate value required to diagnose a mismatch.

Before implementation, classify the algorithm as a fast or slow kernel type. This structural decision is difficult to change later, but can usually be derived from the algorithm's iteration count and expected throughput.

As a rule of thumb:

* More than 100 iterations of a cryptographic primitive usually means a slow kernel.
* Expected throughput below 10 million guesses per second per GPU usually means a slow kernel.

Otherwise, use a fast kernel. Most common fast primitives already have implementations. A new fast kernel must avoid the PCIe bottleneck by generating candidate variations inside attack-mode-specific kernels. See https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#does_the_pci-express_speed_have_any_influence_on_cracking_speed for a bandwidth explanation.

Fast kernels add the algorithm inside an inner candidate-modification loop. Much of the remaining implementation resembles a slow kernel, but each supported attack kernel needs its own entry point.

Slow kernels are usually easier to implement because they use one candidate-generation path. Existing kernels and the GPU cryptographic library often provide most primitive operations, leaving format-specific state handling and final verification.

Choose a hash-mode number before creating the files:

* For a private plugin, choose a number from 90000 through 99998. Upstream reserves this range for private use except for the stock Plaintext mode 99999, preventing collisions with future public modes.
* For an upstream contribution, inspect `src/modules/` on the current master branch and choose a temporary number ending in `00`, roughly 1,000 to 2,000 above the highest assigned mode. If the highest mode is 21500, for example, 22800 is a suitable temporary number. Maintainers assign the final number during pull-request review.

## Development environment ##

Plugin development requires no special hardware, but the development system should resemble the intended deployment environment:

* Test on hardware representative of the intended users. A penetration-testing format such as Kerberos may need mobile-GPU coverage, a consumer wallet format a mid-range discrete GPU, and a digital-forensics format such as TrueCrypt a high-end GPU.
* An NVIDIA GPU lets you test the same kernel through both CUDA and OpenCL. The CUDA backend needs the CUDA Toolkit because the driver can execute compiled code but cannot compile the CUDA C source. NVRTC, supplied by the toolkit, performs that compilation. OpenCL obtains its compiler from the vendor runtime.
* For an AMD GPU, use ROCm on Linux or the Adrenalin driver with the AMD HIP SDK on Windows. Testing through both HIP and OpenCL is useful when both runtimes are available.
* For CPU testing, use the Intel CPU Runtime for OpenCL or PoCL 5.0 or newer, and test both where practical. A GPU runtime such as Intel NEO is not a CPU substitute. CPU local memory does not behave like dedicated GPU shared memory, so it cannot reveal every performance effect of a local-memory-heavy kernel.

Choose a compute API and runtime that supports `printf()` inside kernels. Current OpenCL runtimes generally support it, making `printf()` a primary tool for inspecting intermediate values during kernel development.

Plugins can be developed on Linux, macOS or Windows. The supported runtimes provide debugging facilities on each platform.

Additional development-system guidance:

* Kernel development triggers frequent JIT compilation, so a high-clocked CPU reduces iteration time. Core count is less important for this workload.
* Begin with one GPU. hashcat compiles for every selected GPU type and allocates memory for every selected device, increasing startup time. Add multi-GPU testing after the implementation works on one device.
* A high-end GPU can hide portability problems through specialized instructions and aggressive JIT optimization.
* A low-end GPU can encourage unnecessary resource restrictions that reduce performance on high-end devices.

Before implementing the mode, build and run the current master branch successfully. Use a clean tree without artifacts from an older installation.

## Test suite ##

The optional test module automates plugin verification. It is deliberately written in Python rather than C, providing an independent implementation of the algorithm. Matching results increase confidence that the module and kernel are correct.

A proof of concept that exposes intermediate values is essential for low-level debugging. When none exists, write the test module first and use it as the reference implementation. The same Python file later becomes the permanent test, avoiding duplicate work. See [m17010.py](/tools/test_modules/m17010.py) for an example.

The main program, `tools/test_module_runner.py`, loads the mode-specific Python code at runtime through a standard interface. Existing test modules are useful references. In many cases you can copy a test module for a similar format, change its algorithm and parsing, and use it both as the proof of concept and as the permanent test.

The test suite itself consists of four files:

* `tools/test_module_runner.py` generates random passwords and salts, then loads the Python test module.
* `tools/test_module_runner.pl` provides the same interface for older modes whose test module remains `m[hash_mode].pm`. The shell scripts below select the available implementation automatically.
* `tools/test.sh` compares reference hashes with hashcat output across several option combinations.
* `tools/test_edge.sh` exercises password and salt length boundaries. It reads `module_constraints()`, generates the claimed minimum and maximum values, then tests every supported attack and kernel type.

Name the test module `tools/test_modules/m[hash_mode].py`. It defines `module_constraints()`, `module_generate_hash()` and `module_verify_hash()`. Passwords use `bytes`, while hashes and salts use `str`, because `$HEX[...]` can decode to password bytes that are not text.

The suite still supports Perl modules named `m[hash_mode].pm` for older modes, but new test modules use Python. Shared helpers live in the `tools/test_modules/lib` package and can be imported with statements such as `from lib.test_helpers import random_bytes` or `from lib import gpg`.

### test_module_runner.py ###

Script `tools/test_module_runner.py` supports six modes:

* Edge
* Single (default)
* Password
* Passthrough
* Potthrough
* Verify

The first command-line argument selects `edge`, `single`, `password`, `passthrough`, `potthrough` or `verify`.

The three described below are the ones you will use while writing a module. Of the others, "edge" writes one comma separated record per length edge case, which tools/test_edge.sh consumes, "password" prints one random password for the mode, which tools/test.sh uses to build its containers, and "potthrough" is passthrough with the output written as hash:plain, the shape a potfile takes.

Every Python test module implements three functions used by all runner modes:

* module_constraints()
* module_generate_hash()
* module_verify_hash()

The second argument is the hash-mode number. Verify mode takes additional arguments. Run `tools/test_module_runner.py` without arguments to display the complete syntax.

The Python dependencies are listed in `tools/requirements.txt` and installed by `tools/install_modules.sh`. Review the script before running it.

#### Single mode ####

Single mode generates random passwords for the selected hash mode and passes each to `module_generate_hash()`. It writes the password and complete hash line, including any salt, as executable test commands. Generated inputs cover different lengths and always include the declared minimum and maximum.

Function `module_generate_hash()` must return the complete hash line as a string in exactly the format accepted by hashcat.

Length-dependent optimizations, including padding and zero-byte assumptions, must be tested across every supported password length. Function `module_constraints()` defines those boundaries.

Function `module_constraints()` returns five minimum-and-maximum integer pairs in this order:

* Pure-Mode-PW-Constraints
* Pure-Mode-Salt-Constraints
* Optimized-Mode-PW-Constraints
* Optimized-Mode-Salt-Constraints
* Optimized-Combined-PW-and-Salt-Constraints

Use `-1` for both values when a pair is not applicable. Pure and optimized kernels can have different constraints, as described later. Most slow hash modes provide only pure kernels because iteration count, rather than register pressure, dominates their performance.

In test modules, *salt* can also represent iteration counts, initialization vectors and other randomized format data. These formats are too diverse for one automatic generator. The runner supplies simple random salts using the declared length constraints. For a structured format, generate the necessary fields inside `module_generate_hash()` with the provided helper functions.

Example:

```
from lib.test_helpers import random_hex_string

def module_generate_hash (word, salt, iterations = None):
  if not iterations or iterations <= 0:
    iterations = 10000

  user_salt = random_hex_string (128)
  ck_salt   = random_hex_string (128)
  user_iv   = random_hex_string (32)
```

#### Passthrough mode ####

Passthrough mode reads passwords from standard input instead of generating them. Each password is passed to `module_generate_hash()` and the resulting hash is written to standard output. All other behavior matches single mode.

Example:

```
$ echo hashcat | tools/test_module_runner.py passthrough 1000
b4b9b02e6f09a9bd760f388b67351e2b
```

The newline after the password is a record delimiter and is not part of the password. This differs from commands such as `echo hashcat | md5sum`, where the newline is included in the hashed input unless `echo -n` is used.

#### Verify mode ####

Verify mode compares an original hash list with a second file containing the same hashes and their recovered passwords. The runner regenerates each hash through `module_generate_hash()`. If the result matches the original list, it writes the verified line to a third file.

Function `module_verify_hash()` parses the hash line into every component needed to reconstruct it, including salts and iteration counts, then calls `module_generate_hash()` with those values.

What makes this work is that module_verify_hash() rebuilds the hash out of the hash. Everything the derivation needs is carried in the string, so the salt, the iteration count and anything else random are read back from it rather than drawn again. A hook that generated a fresh salt here could never reproduce its own output, and tools/test_module_runner.py refuses to print a vector whose module_verify_hash() does not round trip it.

The following example comes from the Password Safe v3 test module (tools/test_modules/m05200.py)

```
def module_verify_hash (line):
  idx = line.find (b":")

  if idx < 1:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  try:
    raw = base64.b64decode (hash_in)
  except Exception:
    return None

  if len (raw) < 72 or raw[:4] != b"PWS3":
    return None

  salt_raw   = raw[4:36]
  iterations = struct.unpack ("<I", raw[36:40])[0]

  # the tail is whatever the artifact carried, so the hash rebuilds byte for byte

  return (_psafe3 (word, salt_raw, iterations, raw[72:]), word)
```

The script is called with the following command line parameters:

```
python3 tools/test_module_runner.py verify 5200 hash_list.txt cracked_list.txt verified_list.txt
```

After `verify`, specify the mode number, the original hash list, the file containing hash-and-password pairs, and the output file. The cracked input uses hashcat's `hash[:salt]:password` format and may contain several lines. The output contains only correctly regenerated hashes also present in the original list.

Check that `test_module_runner.py` exits with status 0. A failure may leave an older output file unchanged.

Verify mode can serve as the proof of concept when no separate reference implementation exists.

### test.sh ###

Script `test.sh` uses single-mode output from `test_module_runner.py` to run the hashcat binary and compare its results with the reference values. It checks that all hashes crack with their corresponding passwords and that hash output retains the expected format.

Command-line options can restrict the test scope. Use them during development because a complete run across all hash modes can take several days.

The main options:

* Select hash type (`-m`): test one hash mode.
* Select test mode (`-t`): test either the single-hash or multi-hash kernel.
* Select attack mode (`-a`): test one attack mode. A slow hash automatically uses a straight attack because it has no attack-specific kernels.
* Minimal mode (`-M`): test 24 representative hash types covering the distinct code paths and logic branches.

Without these options, the script runs attack mode 0 for hash mode 0. Run `tools/test.sh --help` for the complete interface.

### test_edge.sh ###

Script `test_edge.sh` complements the randomized tests by generating boundary cases from each test module's constraints. It covers minimum and maximum password and salt lengths along with other declared limits.

It runs every kernel type supplied by a mode and every attack supported by that kernel. Options `-M` and `--minimal` restrict the run to the same 24 representative modes used by `test.sh -M`.

Run `tools/test_edge.sh --help` to list all options.

## Module ##

The first required part of a hash-mode plugin is its module. A module is one `.c` source file that assigns the interface functions it needs and may add its own helpers. Most interface functions cover special cases and remain at `MODULE_DEFAULT`. A simple mode may need only a few.

The module is compiled as a `.so` shared object on Linux and macOS or a `.dll` on Windows. At startup, hashcat loads the module selected by `-m`, which defaults to mode 0.

Store the module as `src/modules/module_XXXXX.c`, where `XXXXX` is the zero-padded hash-mode number. The build automatically finds it and writes `module_XXXXX.[so|dll]` under `$(SHARED_FOLDER)/modules/`. No core-source change is required.

When running an uninstalled build from its source directory on Linux or macOS, `$SHARED_FOLDER` is normally the current working directory. Windows also uses the current directory because its Makefile has no install target.

Only unusual requirements, such as an external module library, should require Makefile changes. Coordinate those dependencies with the maintainers before submitting an upstream contribution.

A module links against the core library installed beside the hashcat binary rather than containing its own core copy. This requires no special handling during normal development, but it matters when distributing compiled plugins. See "The core library" below.

A module defines the following hash-mode properties and behaviors:

* Attack type (fast hash or slow hash)
* Digest size and orderings
* Salt type
* Hash name and category
* Kernel number
* Various optimizers and workflow options
* Hash and password for the self-test
* Decoder and encoder
* Password and salt length limits
* Hook functions
* JIT compiler options

Modules expose these values through callback functions. The mandatory callbacks are:

* module_init()
* module_hash_decode()
* module_hash_encode()
* module_attack_exec()
* module_dgst_pos0()
* module_dgst_pos1()
* module_dgst_pos2()
* module_dgst_pos3()
* module_dgst_size()
* module_hash_category()
* module_hash_name()
* module_kern_type()
* module_opti_type()
* module_opts_type()
* module_salt_type()
* module_st_hash()
* module_st_pass()

Most mandatory callbacks return static configuration values. Functions are used instead of fixed macros so a mode can vary its configuration at runtime, such as enabling an optimization only for GPU devices. A typical callback remains simple:

```
static const char *HASH_NAME = "MD5";
...
const char *module_hash_name (...) { return HASH_NAME; }
...
module_ctx->module_hash_name = module_hash_name;
```

Structure `module_ctx` registers every callback implemented by the module. Header `include/modules.h` declares the complete interface.

hashcat calls `module_init()` when loading the module. This function assigns every implemented callback to `module_ctx`.

Example:

```
module_ctx->module_hash_name = module_hash_name;
```

Assign `MODULE_DEFAULT` to every unused callback. The sentinel allows hashcat to validate the `module_ctx_t` layout of a compiled plugin. If a later interface adds a field, an older structure is shorter and leaves that entry `NULL`, allowing hashcat to reject the incompatible binary safely.

For a minimal plugin, the two mandatory functions that normally require substantial code are `module_hash_decode()` and `module_hash_encode()`. Most other mandatory functions return static configuration values. The following sections explain each one.

### module_attack_exec() ###

Callback `module_attack_exec()` classifies the mode as a slow or fast hash:

* `ATTACK_EXEC_OUTSIDE_KERNEL` selects a slow hash.
* `ATTACK_EXEC_INSIDE_KERNEL` selects a fast hash.

The names describe where candidate generation occurs. For a slow hash, reading a candidate from device memory is not a meaningful bottleneck. A standalone straight, combinator or mask kernel can generate candidates first and store them in device memory. The hash-mode-specific `_init` kernel then loads them.

For a fast hash, repeatedly reading complete candidates from device memory would limit throughput. The attack kernel instead loads one base candidate into registers in its outer loop, then applies a bounded set of modifications in an inner loop. These iterations are the kernel loops. Straight, combinator and mask attacks each require an attack-specific kernel because they modify the base candidate differently.

The kernel section covers this design in more detail. A slow hash is usually simpler because it needs one hash kernel rather than separate attack kernels.

Example:

```
static const u32 ATTACK_EXEC = ATTACK_EXEC_OUTSIDE_KERNEL;
```

### module_dgst_pos0() - module_dgst_pos3() ###

hashcat uses 128 bits of each digest for high-speed lookup because practical attacks cannot exhaust a keyspace large enough for the omitted bits to affect candidate selection. The complete digest remains available for parsing and output, but kernels can compare four 32-bit words before performing any format-specific final verification.

Callbacks `module_dgst_pos0()` through `module_dgst_pos3()` select those four 32-bit words and the order in which they become available. A fast kernel can test an early word against the lookup data and stop before completing the remaining algorithm when no target can match. For MD5, word 0 is available first, followed by word 3 rather than word 1.

Choose the positions by tracing when each 32-bit output word becomes final in the algorithm.

Example:

```
static const u32 DGST_POS0 = 0;
static const u32 DGST_POS1 = 3;
static const u32 DGST_POS2 = 2;
static const u32 DGST_POS3 = 1;
```

Slow hashes normally use positions 0, 1, 2 and 3 because early digest rejection provides little benefit.

### module_dgst_size() ###

Although lookup uses 128 bits, hashcat stores the complete digest so the encoder can reconstruct the original format. Callback `module_dgst_size()` reports the allocation size.

hashcat passes a buffer of this size to the decoder and encoder as `digest_buf`.

Header `include/types.h` defines macros for common digest sizes.

Example:

```
static const u32 DGST_SIZE = DGST_SIZE_4_4;
```

Macro `DGST_SIZE_4_4` means four values of four bytes each, producing a 16-byte, 128-bit digest buffer.

When the target is encrypted data rather than a digest, store the complete structured value in an esalt and place a high-entropy portion, such as the first 16 ciphertext bytes, in the digest buffer for lookup. The section on salt structures explains esalts in detail.

### module_hash_category() ###

The hash category affects display and documentation only. Option `--help` groups modes by category, while `--hash-info` reports it in plain and JSON output. A list of the categories already defined can be found in `include/types.h`.

Example:

```
static const u32 HASH_CATEGORY = HASH_CATEGORY_RAW_HASH;
```

Adding a category changes the hashcat core and should be submitted as a separate pull request.

### module_hash_name() ###

The hash name is a descriptive string shown in the status display and `--help` output. It does not affect processing.

Keep the name within 48 characters so it fits the `--help` column.

Example:

```
static const char *HASH_NAME = "MD5";
```

### module_kern_type() ###

Callback `module_kern_type()` selects the kernel number loaded by the module. A fast hash using `ATTACK_EXEC_INSIDE_KERNEL` loads `OpenCL/mXXXXX_a[0|1|3|4]-[optimized|pure].cl`: `a0` for straight, `a1` for combinator, `a3` for brute force, and optional `a4` for the PCFG device engine. A slow hash using `ATTACK_EXEC_OUTSIDE_KERNEL` loads `OpenCL/mXXXXX-[optimized|pure].cl` without an attack-mode suffix. For example, kernel type 7100 loads `OpenCL/m07100-pure.cl`. Multiple modules may select the same kernel, as the GRUB2 and macOS 10.8 modes do for PBKDF2-HMAC-SHA512.

Several modules can share one kernel implementation, but combining unrelated modes creates branches that reduce performance and maintainability. Performance-sensitive modes therefore usually have dedicated kernels, as the `OpenCL/` directory demonstrates.

Example:

```
static const u64 KERN_TYPE = 7100;
```

### module_opti_type() ###

The optimization type is a bitmask. Set only flags whose contracts the kernel satisfies because an incorrect flag can produce wrong results. Header `include/types.h` contains the complete list. The principal flags are described below:

* `OPTI_TYPE_OPTIMIZED_KERNEL`: Selects the optimized kernel instead of the pure kernel. hashcat manages this flag from option `-O` and the kernel files available for the mode. Do not set it in the module.
* `OPTI_TYPE_ZERO_BYTE`: Documents use of the zero-byte optimization described at https://hashcat.net/events/p13/js-ocohaaaa.pdf. Modern OpenCL and CUDA JIT compilers perform many such optimizations automatically, so this flag affects startup reporting rather than kernel behavior. Function `module_jit_build_options()` can pass compiler options, although low-level compiler optimizations generally cannot be disabled individually.
* `OPTI_TYPE_PRECOMPUTE_INIT`: Like `OPTI_TYPE_ZERO_BYTE`, this flag documents an active optimization.
* `OPTI_TYPE_MEET_IN_MIDDLE`: Like `OPTI_TYPE_ZERO_BYTE`, this flag documents an active optimization.
* `OPTI_TYPE_EARLY_SKIP`: Like `OPTI_TYPE_ZERO_BYTE`, this flag documents an active optimization.
* `OPTI_TYPE_NOT_SALTED`: Like `OPTI_TYPE_ZERO_BYTE`, this flag documents an active optimization.
* `OPTI_TYPE_NOT_ITERATED`: Like `OPTI_TYPE_ZERO_BYTE`, this flag documents an active optimization.
* `OPTI_TYPE_PREPENDED_SALT`: Like `OPTI_TYPE_ZERO_BYTE`, this flag documents an active optimization.
* `OPTI_TYPE_APPENDED_SALT`: Lets a raw primitive such as `sha1($p.$s)` treat an appended salt as a static suffix during attack mode 3. hashcat adds it to the mask so the kernel can omit the salt-append branch, then removes it when reporting a cracked password.
* `OPTI_TYPE_SINGLE_HASH`: Selects the fast single-hash `sXX` kernels instead of the multi-hash `mXX` kernels. The single-hash kernels keep the target digest in registers and avoid the bitmap prefilter and binary search. hashcat sets this flag automatically. Do not set it in the module.
* `OPTI_TYPE_SINGLE_SALT`: Like `OPTI_TYPE_ZERO_BYTE`, this flag documents an active optimization.
* `OPTI_TYPE_BRUTE_FORCE`: Enables optimizations that require brute-force candidate generation, including `OPTI_TYPE_APPENDED_SALT`. hashcat sets this flag automatically. Do not set it in the module.
* `OPTI_TYPE_RAW_HASH`: Marks a kernel as eligible for raw-hash optimizations such as `OPTI_TYPE_APPENDED_SALT`. Set it in the module only when the kernel satisfies that contract.
* `OPTI_TYPE_SLOW_HASH_SIMD_INIT`: Indicates that the `_init` kernel uses vector data types, causing hashcat to adjust the work-item count by the vector width. This can improve CPU performance through SIMD instructions but normally adds complexity without helping modern scalar GPUs. It is rarely worthwhile for a kernel called only once per candidate.
* `OPTI_TYPE_SLOW_HASH_SIMD_LOOP`: Applies the SIMD contract to `_loop`. Vectorization is recommended when the loop has no data-dependent branches.
* `OPTI_TYPE_SLOW_HASH_SIMD_COMP`: Applies the SIMD contract to `_comp`.
* `OPTI_TYPE_SLOW_HASH_SIMD_INIT2`: Applies the SIMD contract to `_init2`.
* `OPTI_TYPE_SLOW_HASH_SIMD_LOOP2`: Applies the SIMD contract to `_loop2`.
* `OPTI_TYPE_SLOW_HASH_DIMY_INIT`: Launches `_init` over two work dimensions, using `salt_dimy` for the second dimension. Use it only when initialization divides cleanly across a second axis.
* `OPTI_TYPE_SLOW_HASH_DIMY_LOOP`: The same for the _loop kernel.
* `OPTI_TYPE_SLOW_HASH_DIMY_COMP`: The same for the _comp kernel.
* `OPTI_TYPE_USES_BITS_8`: Indicates to the JIT compiler that the underlying primitive uses 8-bit operations, allowing compile-time optimization of GPU library functions.
* `OPTI_TYPE_USES_BITS_16`: Applies the same contract to a 16-bit primitive.
* `OPTI_TYPE_USES_BITS_32`: Applies the same contract to a 32-bit primitive. This is the default when no `OPTI_TYPE_USES_BITS_*` flag is set and covers primitives such as MD4, MD5, SHA1, SHA256 and RIPEMD-160.
* `OPTI_TYPE_USES_BITS_64`: Applies the same contract to a 64-bit primitive, such as SHA512, BLAKE2, SHA3 or Streebog.
* `OPTI_TYPE_REGISTER_LIMIT`: Limits the NVIDIA compiler to 128 registers. Only a few algorithms benefit, so enable it only after measuring an improvement.

### module_hash_decode() ###

hashcat calls `module_hash_decode()` for each hash line. The function parses the format and stores its components in standard hashcat structures.

Text hash files normally contain one hash per line. hashcat first counts the lines and preallocates arrays for each digest, `salt_t`, esalt and any less common structures such as a hook salt. Their element sizes come from callbacks including `module_dgst_size()`, `module_esalt_size()` and `module_hook_salt_size()`.

After allocation, hashcat rewinds the file and calls `module_hash_decode()` for each line. The input points to the current line and the output pointers already address the corresponding array elements, so the decoder writes directly to them. Any additional allocation performed by the decoder remains the module's responsibility to free.

hashcat distinguishes fixed `salt_t` data from module-specific esalt data. Read the section "About salts" before implementing a salted decoder.

For a format such as `MD5(MD5($pass.$salt))`, each line contains both a digest and salt. The decoder normally uses the tokenizer described below to separate and validate them before copying the values into hashcat structures.

The decoder remains responsible for format-specific bounds and semantic checks beyond the tokenizer. Return a descriptive parser code such as `PARSER_HASH_VALUE` on failure and `PARSER_OK` on success. Header `include/types.h` lists the available codes.

A salted decoder must set `salt_buf[]` and `salt_len`. A slow iterative mode must also set `salt_iter`. See "Salt data" below for details.

The decoder also receives configuration structures such as `hashconfig`. This allows parsing behavior to depend on active options. For example, `hashconfig->opti_type` contains `OPTI_TYPE_OPTIMIZED_KERNEL` when `-O` is active. Module `src/modules/module_00000.c` uses that guarantee to reverse the Merkle-Damgard construction for optimized passwords no longer than 55 characters.

A decoder normally performs the following applicable steps:

* Cast the esalt and digest buffers to their mode-specific types.
* Initialize the tokenizer and configure each field in the hash format.
* Run the tokenizer and return its error code on failure.
* Convert token pointers to field-specific types and perform additional semantic or bounds checks.
* Decode values into local variables.
* Set the iteration count for a slow hash.
* Copy IVs, salts, digests, and other values into hashcat buffers.
* Apply required byte swaps, precomputations, or option-dependent transformations.
* Return `PARSER_OK`.

### module_hash_encode() ###

Callback `module_hash_encode()` reconstructs the original hash representation for cracked output and single-hash status displays. It commonly uses `snprintf()` to write the result into `line_buf[]` and returns the number of bytes written.

Encoder input buffers may be reused later. Never modify them in place. Copy any value that needs adjustment into a local buffer first.

Keep repeated transformations such as byte swaps out of performance-critical kernel loops when the decoder can precompute them or the encoder can reverse them. These host callbacks run infrequently enough for output-oriented transformations.

### module_hash_decode_postprocess() ###

Callback `module_hash_decode_postprocess()` applies option-dependent changes after decoding. For example, option `--hccapx-message-pair` adds filters that can exclude selected hashes from the input list.

### module_hash_hints() ###

Callback `module_hash_hints()` exposes contextual words associated with whoever chose the password. Attack mode 9 pairs one hash with one candidate set and can use names, network identifiers, principals, or other human-selected values stored in the salt or esalt.

The callback is optional. `MODULE_DEFAULT` splits the account name preceding the hash into words, preserving the behavior of modules written before this interface existed. Implement the callback when the hash contains stronger context or has no useful account name.

```
u32 module_hash_hints (const hashconfig_t *hashconfig, const salt_t *salt, const void *esalt_buf, const hashinfo_t *hash_info, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size)
```

Fill at most `out_max` entries in `out_words` and return the number written. Each entry contains a pointer and length. The pointer may refer to the salt or esalt, which outlive the call, or to the per-thread `scratch` buffer of `scratch_size` bytes when the word must be constructed. Do not allocate memory or return a pointer to stack storage.

Order hints by their likelihood of forming a password stem because each later word adds work. Mode 22000 returns the human-selected network name first, followed by both MAC addresses in the 12-digit form used by router key generators. It omits a nonprintable network name because users could not have typed those bytes into a password.

hashcat calls this function once per candidate, so keep its work limited to short strings. See `docs/hashcat-association.md` for how the attack uses the result.

### module_opts_type() ###

Callback `module_opts_type()` returns a bitmask of general workflow options, while `module_opti_type()` describes optimization contracts. Header `include/types.h` defines the complete flag set. The principal flags are described below:

* `OPTS_TYPE_PT_UTF16LE`: Generates mask candidates in a simplified UTF-16LE form by inserting zero bytes between characters. It covers single-byte characters such as the built-in `?a` set but does not perform full Unicode conversion. The flag affects only fast attack-mode 3 kernels. Other kernels must call the appropriate `*_utf16le()` helper or, for optimized kernels, `make_utf16le()`.
* `OPTS_TYPE_PT_UTF16BE`: Applies the `OPTS_TYPE_PT_UTF16LE` behavior in big-endian byte order.
* `OPTS_TYPE_PT_UPPER`: Uppercases every password before hashing, as required by LM. It applies to every attack and kernel type, although a later rule can lowercase the result.
* `OPTS_TYPE_PT_LOWER`: Applies the `OPTS_TYPE_PT_UPPER` behavior using lowercase conversion.
* `OPTS_TYPE_PT_ADD01`: Appends byte `0x01` as an algorithm-specific terminator. The flag affects only fast attack-mode 3 kernels. Other fast kernels must append it explicitly, for example with `append_0x01_4x4_S()`. The crypto library normally handles it for slow hashes.
* `OPTS_TYPE_PT_ADD80`: Applies the `OPTS_TYPE_PT_ADD01` behavior with byte `0x80`.
* `OPTS_TYPE_PT_ADDBITS14`: Stores the password bit length in the 14th 32-bit word, as used by little-endian primitives such as MD4, MD5 and RIPEMD-160.
* `OPTS_TYPE_PT_ADDBITS15`: Stores the password bit length in the 15th 32-bit word, as used by big-endian primitives such as SHA1 and SHA256.
* `OPTS_TYPE_PT_GENERATE_LE`: Generates mask candidates in little-endian byte order. This is the default when no `OPTS_TYPE_PT_GENERATE_*` flag is set.
* `OPTS_TYPE_PT_GENERATE_BE`: Generates mask candidates in big-endian byte order.
* `OPTS_TYPE_PT_NEVERCRACK`: Continues testing a target after a match, which is useful for collision-prone formats and false positives. Option `--keep-guessing` adds this flag automatically. Do not set it in the module.
* `OPTS_TYPE_PT_ALWAYS_ASCII`: Prevents automatic `$HEX[...]` encoding, including when a password contains the hash-line separator.
* `OPTS_TYPE_PT_ALWAYS_HEXIFY`: Prints every cracked password as raw hexadecimal without the `$HEX[` and `]` wrapper.
* `OPTS_TYPE_PT_LM`: Applies LM-specific plaintext handling, including lowercase output and a maximum length of seven characters per half.
* `OPTS_TYPE_PT_HEX`: Interprets wordlist entries as hexadecimal data.
* `OPTS_TYPE_ST_UTF16LE`: Same as OPTS_TYPE_PT_UTF16LE but applied on the salt buffer.
* `OPTS_TYPE_ST_UTF16BE`: Same as OPTS_TYPE_PT_UTF16BE but applied on the salt buffer.
* `OPTS_TYPE_ST_UPPER`: Same as OPTS_TYPE_PT_UPPER but applied on the salt buffer.
* `OPTS_TYPE_ST_LOWER`: Same as OPTS_TYPE_PT_LOWER but applied on the salt buffer.
* `OPTS_TYPE_ST_ADD01`: Same as OPTS_TYPE_PT_ADD01 but applied on the salt buffer.
* `OPTS_TYPE_ST_ADD02`: Applies the `OPTS_TYPE_PT_ADD01` behavior to the salt buffer with byte `0x02`.
* `OPTS_TYPE_ST_ADD80`: Same as OPTS_TYPE_PT_ADD80 but applied on the salt buffer.
* `OPTS_TYPE_ST_ADDBITS14`: Same as OPTS_TYPE_PT_ADDBITS14 but applied on the salt buffer.
* `OPTS_TYPE_ST_ADDBITS15`: Same as OPTS_TYPE_PT_ADDBITS15 but applied on the salt buffer.
* `OPTS_TYPE_ST_HEX`: Same as OPTS_TYPE_PT_HEX but applied on the salt buffer.
* `OPTS_TYPE_ST_BASE64`: Decodes the salt buffer from Base64 instead of hexadecimal.
* `OPTS_TYPE_MT_HEX`: Interprets the mask as hexadecimal data.
* `OPTS_TYPE_HASH_COPY`: Preserves the original input line in `hash_info->orighash` for formats that contain unused data not stored in `salt_t` or the esalt. Use it only when reconstruction is impractical. Reconstructing a line normally verifies that the decoder retained every required field, while copying every original line consumes additional host memory.
* `OPTS_TYPE_HASH_SPLIT`: Marks a line that contains multiple independent hashes, such as an LM value stored as one 128-bit string but composed of two 64-bit hashes.
* `OPTS_TYPE_LOOP_PREPARE`: Adds an `_loop_prepare` kernel. hashcat runs it once before the `_loop` sequence for each salt repeat, making it useful for state that must be reset before the iteration chunks begin.
* `OPTS_TYPE_LOOP_EXTENDED`: Runs a `_loop_extended` kernel after every `_loop` invocation, before the final value is ready. This exposes intermediate values between bounded iteration chunks for algorithms that can use them.
* `OPTS_TYPE_HOOK12`: Runs a device hook kernel and a host callback between `_init` and `_loop`. The device kernel copies selected intermediate data into a transfer buffer, hashcat moves it to the host, and worker threads run the module callback before copying the updated data back. Use this for required processing that has no device implementation. Nonconstant buffers are thread-safe.
* `OPTS_TYPE_HOOK23`: Provides the same device-to-host hook between `_loop` and `_comp`, after the final loop values are available. Most hook-based modes use this position.
* `OPTS_TYPE_INIT2`: Adds a second initialization and loop sequence for formats with two expensive derivation stages. iTunes 10+, for example, feeds the output of the older 10,000-round SHA256 KDF into a new 10,000,000-round KDF. `OPTS_TYPE_INIT2` and `OPTS_TYPE_LOOP2` let both stages run in bounded chunks that preserve responsiveness and avoid driver watchdog timeouts.
* `OPTS_TYPE_LOOP2_PREPARE`: Adds an `_loop2_prepare` kernel with the same role before the secondary `_loop2` sequence.
* `OPTS_TYPE_LOOP2`: Adds the secondary loop sequence described under `OPTS_TYPE_INIT2`.
* `OPTS_TYPE_AUX1`: Adds an auxiliary verification kernel for formats that share a KDF but use its result differently by version. Separating these branches can reduce instruction-cache pressure, improve JIT output, and avoid combining incompatible shared-memory requirements. The regular `_comp` kernel still runs but should remain empty.
* `OPTS_TYPE_AUX2`: See OPTS_TYPE_AUX1, but for a different branch.
* `OPTS_TYPE_AUX3`: See OPTS_TYPE_AUX1, but for a different branch.
* `OPTS_TYPE_AUX4`: See OPTS_TYPE_AUX1, but for a different branch.
* `OPTS_TYPE_AUX5`: See OPTS_TYPE_AUX1, but for a different branch. This one sits on bit 5, which OPTS_TYPE_PT_ADD02 used to hold. That flag was removed because no module set it and no code read it, while every high bit was already occupied. A plugin outside the tree that still sets OPTS_TYPE_PT_ADD02 will not fail to compile if it defines the name itself, it will quietly ask for an AUX5 kernel that does not exist, so remove the flag rather than carrying it forward.
* `OPTS_TYPE_BINARY_HASHFILE`: Enables binary hash input. The default path presents the file as one value in `line_buf[]` and therefore supports one hash. For multiple hashes, implement `module_hash_binary_count()` so hashcat can allocate storage, then implement `module_hash_binary_parse()` to split the file. Keep `module_hash_decode()` as the common decoder for each extracted record. See `src/modules/module_05200.c` for a single-hash example and `src/modules/module_02500.c` for multiple hashes.
* `OPTS_TYPE_BINARY_HASHFILE_OPTIONAL`: Allows a mode with `OPTS_TYPE_BINARY_HASHFILE` to accept either binary files or text hashes, including hashes on the command line. The binary path converts its records into the form consumed by the text decoder. Mode 22000 is an example.
* `OPTS_TYPE_PT_ADD06`: Same as OPTS_TYPE_PT_ADD01 but use 0x06 byte instead, which is the SHA-3 domain separation byte. See `src/modules/module_17300.c` for an example.
* `OPTS_TYPE_KEYBOARD_MAPPING`: Enables kernel-side character remapping from a table loaded by the host. See `docs/keyboard-layout-mapping.md`.
* `OPTS_TYPE_DEEP_COMP_KERNEL`: Makes hashcat iterate through the esalts associated with each `salt_t` during `_comp`. See "Choosing between salt_t and an esalt" and `src/modules/module_22000.c`.
* `OPTS_TYPE_TM_KERNEL`: Runs a preprocessing kernel before each fast-hash kernel invocation. Bitsliced implementations commonly use it to transpose modifier data, such as a 32-by-32 matrix. Set identical values through `module_kernel_loops_min()` and `module_kernel_loops_max()` when the transformation requires fixed-size blocks.
* `OPTS_TYPE_SUGGEST_KG`: Warns that the mode can produce collisions or false positives and suggests option `--keep-guessing`. It does not enable that option because no inverse option exists.
* `OPTS_TYPE_COPY_TMPS`: Copies `tmps` from the device after a crack so `module_build_plain_postprocess()` can reconstruct additional password data. PKZIP mode `src/modules/module_20510.c` uses leaked password bytes, while VeraCrypt uses the value to report the cracked PIM with the password.
* `OPTS_TYPE_POTFILE_NOPASS`: Omits the password when recording a cracked hash in the potfile. Use it when overlapping formats make password parsing ambiguous or when the recovered value is not directly usable, as with a WPA PMK.
* `OPTS_TYPE_DYNAMIC_SHARED`: Queries and registers the shared-memory capacity available to a kernel. On NVIDIA devices this permits allocations beyond the fixed 48 KB region when the kernel is prepared to use dynamic shared memory. See `OpenCL/m03200-pure.cl`.
* `OPTS_TYPE_SELF_TEST_DISABLE`: Disables the mode self-test when it would create an invalid cached kernel or make startup impractical. Examples include target-specific compile-time salts in DEScrypt, primitives derived from the target in JWT, and very expensive modes such as Ethereum Wallet scrypt.
* `OPTS_TYPE_MP_MULTI_DISABLE`: Prevents hashcat from multiplying kernel acceleration by the device multiprocessor count, allowing finer workload control.
* `OPTS_TYPE_NATIVE_THREADS`: Selects the native thread count: one on a CPU or the preferred workgroup-size multiple reported by a GPU backend. It does not override a user-defined `-u` value.
* `OPTS_TYPE_POST_AMP_UTF16LE`: Runs a complete UTF-8-to-UTF-16LE conversion after amplifier processing. This flag applies only to slow-hash kernels.
* `OPTS_TYPE_AUTODETECT_DISABLE`: Excludes the hash mode from automatic detection.

### module_salt_type() ###

Callback `module_salt_type()` selects the storage and input rules for salted and unsalted hashes:

* `SALT_TYPE_NONE`: Selects an unsalted hash.
* `SALT_TYPE_EMBEDDED`: Selects a strict format in which the salt is parsed from the hash line and option `--hex-salt` is unnecessary. Use it for formats produced by a dedicated or controlled extraction tool.
* `SALT_TYPE_GENERIC`: Selects a user-supplied salt format that may vary between exporting tools and enables option `--hex-salt`.
* `SALT_TYPE_VIRTUAL`: Supplies a fixed synthetic salt, normally empty, so an unsalted format variant can reuse a kernel that expects salt data. For example, `md5(md5($p))` shares a kernel with vBulletin `md5(md5($p).$s)`.

### module_st_hash() ###

Callback `module_st_hash()` returns an artificial self-test hash, normally generated for the password `hashcat` with `test_module_runner.py` in passthrough mode. Callback `module_st_pass()` supplies its matching password.

Benchmark mode also uses this hash. For an unusually expensive format, choose a representative iteration count that keeps startup practical. See `src/modules/module_14800.c` for an example.

Option `--example-hashes` with a specific `-m` value displays the example hash and password.

### module_st_pass() ###

Callback `module_st_pass()` returns the password for the self-test hash from `module_st_hash()`.

### module_hook_extra_param_init() and module_hook_extra_param_term() ###

Callbacks `module_hook_extra_param_init()` and `module_hook_extra_param_term()` manage per-hook-thread resources whose setup should occur only at startup and shutdown. A common use is a third-party library handle, but the buffer can contain any module-defined state.

Hooks run concurrently, and hashcat cannot assume the resource is thread-safe. It therefore allocates one buffer per hook thread, allowing modules to use libraries that cannot share one context safely.

Callback `module_hook_extra_param_size()` reports the allocation size. At startup, hashcat supplies a separate zeroed `hook_extra_param` buffer to each call of `module_hook_extra_param_init()`. It later calls `module_hook_extra_param_term()` for every instance and frees the memory during shutdown.

Both callbacks receive `hashcat_ctx_t *` first and can use the event logging functions. Initialization can therefore report why it failed, while termination can summarize information collected during the run. Because termination runs once per hook thread, a module that wants one summary line must aggregate the per-thread values and log them on the final call.

See `src/modules/module_11600.c` and `src/modules/module_23800.c` for examples.

### module_benchmark_mask() ###

Callback `module_benchmark_mask()` supplies a mode-specific benchmark mask when a particular length or pattern is required. Prefer a static string named `BENCHMARK_MASK` when the value is fixed.

### module_benchmark_charset() ###

Callback `module_benchmark_charset()` supplies custom character set 1 for `--benchmark`. Keep it synchronized with the mask from `module_benchmark_mask()` or the default benchmark mask, which can reference it as `?1`. Prefer a static string named `BENCHMARK_CHARSET`.

### module_benchmark_salt() ###

Callback `module_benchmark_salt()` fills a mode-specific `salt_t` for benchmarks that require particular iteration counts or salt lengths.

## Kernel ##

The kernel is the second required part of a plugin. Kernel compilation is relatively expensive, so hashcat and the compute runtimes cache compiled binaries to reduce startup time.

Editing a kernel invalidates its cached binary automatically. The cache key carries a digest of the kernel source that is about to be compiled and a digest of every other file in the kernel folder, so a change to your .cl file or to any inc_ file it includes is noticed and the cached binary for it is not used.

If you want to clear the cache anyway, delete the folder:

```
$ rm -rf cache/kernels/
```

Command `make clean` also removes cached kernels but rebuilds the rest of hashcat on the next `make`. Removing only `cache/kernels/` is faster during kernel development.

A GPU executes many work items in parallel, so an unguarded `printf()` runs hundreds or thousands of times and can flood the terminal. Restrict debug output to one work item or loop position.

Self-test and autotune launch the kernel with inputs different from the command-line candidate, which can confuse debug output. Disable them while tracing a kernel, then re-enable and test both before considering the implementation complete.

Some development-only controls, including the autotune override below, require `DEBUG=1` in `src/Makefile`. Run `make clean` after changing the setting.

Reduce unrelated variables while developing. Store the hash and candidate in separate files instead of placing them directly on the command line. This avoids shell interpretation of characters such as `$` and makes the reproduction command stable.

The following command-line options are useful during kernel development:

* Option `--potfile-disable` prevents a successful test from entering the potfile. You can then rerun the same target after fixing output or verification code without removing a potfile entry.
* Option `--self-test-disable` prevents the startup self-test from producing an expected failure or unexpected debug output while the kernel is incomplete. Re-enable it before final validation.
* Options `-n 1 -u 1 -T 1` together bypass the autotune search. This development-only combination requires `--force`.
* Option `--quiet` reduces hashcat output without suppressing kernel `printf()` calls.
* Option `--backend-vector-width 1` simplifies CPU debugging by disabling vector-width effects on values and `printf()` output.
* Option `-d 1` limits the run to one compute device, reducing startup and JIT compilation time.

Typically a developer command line for hashcat looks the following:

```
$ rm -rf cache/kernels/
$ ./hashcat -m XXXXX hash.txt word.txt --potfile-disable --self-test-disable -n 1 -u 1 -T 1 --quiet --backend-vector-width 1 -d 1 --force
```

Guard each print statement with a specific loop or work-item condition to prevent every parallel work item from writing it. For a `_loop` kernel, use:

```
if ((loop_pos + i) == 0) printf ("%08x\n", a);
```

For a kernel without `_loop`, use:

```
if ((gid == 0) && (lid == 0)) printf ("%08x\n", a);
```

Avoid `%s` while debugging kernel data. Missing terminators and byte order can make string output misleading. Printing each word with `%08x` exposes unexpected nonzero bytes and gives an unambiguous representation.

Use an optimized kernel when one or more of these conditions apply:

* Restricting password or salt length enables meaningful optimizations. Retain a pure kernel for longer inputs unless the format itself imposes the limit.
* The format has a short fixed maximum, such as eight characters. An optimized kernel already supports passwords up to 31 bytes, so a pure implementation adds no coverage.
* Exploiting an algorithm-specific weakness requires a custom primitive instead of the generic crypto library, as with the NTLM meet-in-the-middle optimization.
* The implementation can exploit attack-mode-specific properties and therefore needs custom inner-loop code.

These recommendations apply for both fast and slow hashes.

When the same hash implementation works for all lengths and attacks, a pure kernel is usually sufficient.

### Kernel parameters ###

hashcat calls every kernel with the same parameter list. Most kernels use only a few of these parameters, but the unused parameters do not affect performance. The fixed prototype provides consistent access to the buffers and makes unfamiliar kernels easier to read.

Do not modify shared buffers directly unless the interface explicitly permits it. Use the provided macros for writes and focus on the parameters relevant to the selected kernel type.

* `pw_t *pws`: Holds the base passwords for fast hashes and the complete passwords for slow hashes, with one entry per work item.
* `kernel_rule_t *rules_buf`: Holds the rule operations read by the inner loop of fast `_a0` kernels.
* `pw_t *combs_buf`: Holds the modifier passwords read by the inner loop of fast `_a1` kernels.
* `void *bfs_buf`: Holds the mask modifiers read by the inner loop of fast `_a3` kernels.
* `void *tmps`: Provides a read-write context buffer for slow hashes, with one entry per work item.
* `void *hooks`: Provides a read-write hook buffer for slow hashes when hooks are enabled, with one entry per work item.
* u32 *bitmaps_buf_s1_a: This is part of the bitmap prefilter used by a fast-hash multi-hash kernel.
* u32 *bitmaps_buf_s1_b: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s1_c: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s1_d: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s2_a: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s2_b: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s2_c: See bitmaps_buf_s1_a.
* u32 *bitmaps_buf_s2_d: See bitmaps_buf_s1_a.
* `plain_t *plains_buf`: Stores the base-password and modifier indices for cracked hashes. hashcat uses these indices to reconstruct each password on the host. The buffer has one entry per unique digest.
* `digest_t *digests_buf`: Holds all unique digests. A candidate that passes the bitmap prefilter is searched for in this buffer with a binary search.
* `u32 *hashes_shown`: Marks digests as cracked so that hashcat reports each one only once.
* `salt_t *salt_bufs`: Holds fixed-size salt data. Use `SALT_POS_HOST` to index the current entry. See the `salt_t` section below for details.
* `void *esalt_bufs`: Holds extended salt data and must be cast to the mode-specific type inside the kernel. Use `DIGESTS_OFFSET_HOST` to index the current entry.
* `u32 *d_return_buf`: Signals that a hash has been cracked and should be reported.
* void *d_extra0_buf: This and the other extra buffers let a memory-hard mode split storage across several allocations when one allocation cannot hold the required amount.
* void *d_extra1_buf: See d_extra0_buf.
* void *d_extra2_buf: See d_extra0_buf.
* void *d_extra3_buf: See d_extra0_buf.
* `kernel_param_t *kernel_param`: Carries the scalar kernel parameters. Access its members through the macros in `OpenCL/inc_types.h`, not through field names. Some macros expand differently for association attacks, where each work item owns its salt and digest. Direct field access can therefore select the wrong entry.

These are the members, with the macro to read each one:

* u32 bitmap_mask (BITMAP_MASK): This mask indexes the bitmap prefilter. hashcat derives it from the selected bitmap size at startup.
* u32 salt_pos_host (SALT_POS_HOST): This is used to index the current salt_t entry. You want to use this when you access the salt_bufs buffer. Under attack mode 9 the macro expands to the work item's own position instead. Use SALT_POS_HOST_BID where the index has to follow the block id rather than the global id.
* `u64 loop_pos (LOOP_POS)`: Identifies the first iteration in the current slow-hash loop invocation. When an algorithm requires more iterations than one invocation can execute, this value lets the next invocation resume at the correct position.
* `u64 loop_cnt (LOOP_CNT)`: Gives the number of iterations to execute in the current slow-hash loop invocation, typically no more than 1024.
* `u64 il_cnt (IL_CNT)`: Gives the number of modifier iterations in a fast-hash inner loop, typically no more than 1024. The modifier buffers need no offset because hashcat keeps them small enough for device constant memory.
* u32 digests_cnt (DIGESTS_CNT): This is the total number of unique digests in the digests_buf array of the current salt. It is important for the binary search. Under attack mode 9 the macro is the constant 1, because there the work item has exactly one digest to compare against.
* u32 digests_offset_host (DIGESTS_OFFSET_HOST): This is the offset to the first unique digest in the digests_buf array of the current salt. It is important for the binary search, and it is what indexes esalt_bufs. Under attack mode 9 the macro expands to the work item's own position. Use DIGESTS_OFFSET_HOST_BID where the index comes from the block id.
* u32 combs_mode (COMBS_MODE): This is a specific configuration for combinator based attack in slow hash mode. It defines which side (left or right) is the base and which is the modifier side. You want to access this variable from your _a1 kernels.
* u32 salt_repeat (SALT_REPEAT): A salt can ask hashcat to run it more than once, and this is which of those runs the launch is. A kernel that has to vary its behaviour between the repeats reads it here.
* u64 pws_pos (PWS_POS): This is where the current batch starts in the password buffer. Under attack mode 9 it is also what places the work item on its own salt and digest.
* `u64 gid_max (GID_CNT)`: Gives the number of valid work items. Each kernel must compare `get_global_id (0)` with this value because the launch size may be rounded up to a multiple of the workgroup size. Processing a padded work item can produce an out-of-bounds host read when hashcat reconstructs the corresponding password.
* u32 pre_len, u32 mid_len, u32 post_len, u32 has_q (COMBS_PRE_LEN, COMBS_MID_LEN, COMBS_POST_LEN, COMBS_HAS_Q): These describe where the word markers sit in an attack mode 12 mask, counted in mask positions. The mask is cut into three pieces: the positions before `?w`, the mid_len positions after it, and whatever is left after `?q`. Field `has_q` indicates whether the mask contains `?q`. The optimized kernels take these as numbers because they are the same for every amplifier item, which makes the shift cheaper than reading it per item.
* u64 pcfg_lane_stride (PCFG_LANE_STRIDE): This is how many candidates one lane covers in a PCFG device engine launch. It is only meaningful in an _a4 kernel.

Kernel attribute macros provide the fixed prototype. Choose the macro appropriate for the kernel type:

* KERN_ATTR_BASIC(): Use this in your fast hash kernel if this is attack mode 1 or 3 and not using vector data types.
* KERN_ATTR_BITSLICE(): Use this when the fast-hash kernel has a bitsliced implementation. The modifier buffers must first be preprocessed by a TM kernel.
* KERN_ATTR_ESALT(e): Use this if your fast hash kernel uses an esalt structure.
* KERN_ATTR_RULES(): Use this in your fast hash kernel if this is attack mode 0.
* KERN_ATTR_RULES_ESALT(e): Use this in your fast hash kernel if this is attack mode 0 and uses an esalt structure.
* KERN_ATTR_TMPS(t): Use this if your slow hash kernel only uses a tmps structure.
* KERN_ATTR_TMPS_ESALT(t,e): Use this if your slow hash kernel uses a tmps structure and an esalt structure.
* KERN_ATTR_TMPS_HOOKS(t,h): Use this if your slow hash kernel uses a tmps structure and a hook structure.
* KERN_ATTR_TMPS_HOOKS_ESALT(t,h,e): Use this if your slow hash kernel uses a tmps structure, a hook structure and an esalt structure.
* KERN_ATTR_VECTOR(): Use this if your fast hash kernel uses vector data types in the inner loop. Note: Only valid for -a 3 kernels.
* KERN_ATTR_VECTOR_ESALT(e): Use this if your fast hash kernel uses vector data types in the inner loop and uses an esalt structure. Note: Only valid for -a 3 kernels.

### Kernel: fast hash type ###

Use the fast-hash kernel type when transferring candidates over PCI Express would take longer than computing the hashes. These algorithms typically use arithmetic and bitwise operations with little or no memory access, so much of the implementation can remain in registers. A fast-hash kernel therefore loads a base candidate into registers and modifies it repeatedly inside an inner loop.

Candidate modification depends on the attack mode. Attack modes 1, 6, 7, and 12 share one kernel family, while attack modes 8 and 9 use the attack-mode 0 kernels. A complete fast-hash implementation therefore needs source files for kernel families 0, 1, and 3. hashcat loads the appropriate family for the selected attack.

Attack-mode 4, the PCFG attack, is a fourth kernel and it is optional. See the section on it below.

The file name convention for fast hashes is `OpenCL/mXXXXX_a[0|1|3|4]-[pure|optimized].cl`. The attack-mode 4 file is optional.

#### Kernel: fast hash type (optimized) ####

A fully featured fast hash mode provides pure and optimized kernels for all three required kernel families, for a total of six source files. A mode may instead provide only pure or only optimized kernels, but it must still cover all three families. An optional seventh kernel gives attack mode 4 a device implementation instead of the host fallback. Name it `a4-optimized` when the mode has no pure kernel, because that is the name selected by its hash configuration.

The three implementations reflect the different candidate-generation paths. Combining them behind runtime branches would significantly reduce performance.

Each fast hash kernel source in optimized mode has to provide the following kernel functions with this convention: `mXXXXX_[m|s][04|08|16]`.

The `XXXXX` portion is the zero-padded hash mode. The `m` and `s` variants implement multiple- and single-hash comparisons. A single-hash kernel can often keep its target digest in registers, while a multi-hash kernel uses a bitmap prefilter followed by a binary search. Use `COMPARE_M_SIMD()` for the `m` variant and `COMPARE_S_SIMD()` for the `s` variant. Both macros accept four 32-bit words in the order configured by `module_dgst_pos0()` through `module_dgst_pos3()`, regardless of the full digest size.

The `[04|08|16]` suffix gives the maximum candidate length in four-byte words: 16, 32, or 64 bytes. Only brute-force `a3` kernels need all three implementations. The `a0` and `a1` families should implement `04` and provide empty `08` and `16` stubs. Their candidate generation is slow enough that the longer optimized variants provide little benefit over the pure kernel.

Vector data types can improve some kernels even on devices without native vector instructions. NTLM is one example: the outer loop precomputes scalar values from the unchanged base password, while only the inner loop is vectorized. This arrangement reduces both instructions and resource use, and the compiler performs the resulting optimization automatically.

#### Kernel: fast hash type (pure) ####

Pure kernels support passwords and salts up to 256 bytes and are generally easier to write than optimized kernels. They require only single- and multi-hash functions and normally use the hashcat crypto library, such as `OpenCL/inc_hash_sha256.cl`. See the crypto library section below before implementing one.

Each fast hash kernel source in pure mode has to provide the following kernel functions with this convention: `mXXXXX_[mxx|sxx]`.

Pure kernels are usually slower, but the difference depends on the available optimization. NTLM gains substantially from its meet-in-the-middle implementation, while pure and optimized SHA256-HMAC kernels perform similarly.

#### Kernel: fast hash type (attack-mode 4) ####

Attack-mode 4 is the PCFG attack, and on a fast hash it amplifies inside the hash kernel the way the rules engine does for attack-mode 0. The file name convention is `OpenCL/mXXXXX_a4-pure.cl`, and `OpenCL/mXXXXX_a4-optimized.cl` for a mode that has no pure kernel of its own. The name is the digest convention rather than the candidate layout: the engine hands the candidate over as an array either way, so the optimized file differs only where the mode's own optimized kernel differs, which for a raw hash is the initial state the module already subtracted out of the stored digest.

This kernel is optional. A hash mode without one runs the PCFG attack on the host instead, which is correct and much slower, and hashcat reports that fallback at startup rather than failing.

You do not write the kernel. You write four hooks and include the engine, which walks the candidates and does the comparing:

* `pcfg_hash_init ()`: pick up what the mode needs from the kernel's own parameters, which for a salted mode is its salt and for an esalt mode its esalt. Store it on `pcfg_hash_ctx_t`, which is the mode's own struct.
* `pcfg_hash_setup ()`: what the hash wants written into the candidate array once, before any candidate exists. Most modes leave it empty.
* `pcfg_hash ()`: the candidate array, a byte length, and the four words a comparison needs. This is the body of the attack-mode 0 loop with the base word paste removed.
* `pcfg_hash_global ()`: the same for a base word too long for the array, which is read straight out of global memory.

File `OpenCL/inc_pcfg_kernel.cl` documents all four hooks and is worth reading before writing one. Files `OpenCL/m00100_a4-pure.cl` and `OpenCL/m00200_a4-optimized.cl` are the smallest complete examples of the two variants. One name is not yours to choose: `inc_vendor.h` maps `s0` to `s3` onto `x` to `w` under Metal, and `w` is the parameter the hooks are handed the candidate in, so a local called `s3` becomes a second `w` in the same scope and the file builds everywhere except Apple. Existing kernels use `s0` to `s3` as vector components, where the rewrite maps a name onto the component it already meant, and do not declare a local called `s3`. Name word buffers `w0` to `w3`, as the existing PCFG kernels commonly do.

### Kernel: slow hash type ###

A slow-hash kernel is for an algorithm demanding enough that PCI Express transfer overhead is no longer a performance constraint.

The slow hash kernel also supports pure and optimized kernel implementations.

Most slow hashes need only a pure kernel. An optimized implementation is useful when the `_loop` kernel reads original input such as a password or salt and can exploit length-specific optimizations. Such kernels are uncommon. Compare `OpenCL/m00500-optimized.cl` with `OpenCL/m00500-pure.cl` for an example.

Most slow-hash modes do not use length-specific variants such as `s04` or `s08`. They also do not need separate single- and multi-hash kernels because that distinction provides no meaningful performance benefit.

Split the algorithm across three kernels: initialization, the repeated work that makes the algorithm slow, and the final verification.

* `mXXXXX_init`: Loads each candidate, performs any required encoding or byte-order conversion, initializes crypto contexts, and writes the initial state to `tmps`.
* `mXXXXX_loop`: Performs the expensive repeated computation. hashcat divides large iteration counts across multiple kernel invocations to keep the interface responsive and avoid driver watchdog timeouts. Each invocation reads the current state from `tmps`, executes a bounded number of iterations, and writes the updated state back until `salt->salt_iter` is reached.
* `mXXXXX_comp`: Reads the final state after the last loop invocation and verifies the derived key. It may compare a digest through the standard macros or decrypt data and test a known pattern. This kernel is often the most format-specific part of the implementation, but usually contributes little runtime compared with `_loop`.

The kernels execute in this order: `mXXXXX_init`, `mXXXXX_loop` one or more times, and `mXXXXX_comp`.

All three kernels can access the read-write `tmps` context buffer. Cast its `void *` value to the mode-specific structure inside the kernel and return that structure's size from `module_tmp_size()`. hashcat allocates one entry per work item according to the maximum concurrency found by autotune, so each candidate has independent state and needs no locking.

The normal access pattern is:

* The `mXXXXX_init` kernel writes `tmps` at the end.
* The `mXXXXX_loop` kernel reads `tmps` at the beginning and writes it at the end.
* The `mXXXXX_comp` kernel reads `tmps` at the beginning.

Use vector data types for slow hashes when the algorithm permits it, but confine them to the `_loop` kernel and set the corresponding `opts_type` flag described in the module section.

## hashcat crypto library ##

The hashcat crypto library resembles the OpenSSL interface, with the usual `Init()`, `Update()`, and `Final()` calls, but differs in several important ways:

* OpenSSL targets devices with 8-, 32-, and 64-bit operations. The hashcat crypto library is designed around 32-bit operations suitable for GPUs.
* OpenSSL has no vector-data interface because its common use cases do not derive several keys in parallel. The hashcat library supports both scalar and vector inputs so that the runtime can use instructions such as SSE2 and AVX2. Vector code uses a separate context type, such as `sha1_ctx_vector_t` instead of `sha1_ctx_t`.

The library favors predictable device performance over a conventional implementation. Update functions must track offsets for variable input, but pointer-based indexing would consume extra registers and instructions. Large `switch()` statements instead let the kernel compiler keep more work in registers. See `OpenCL/inc_common.cl` for the implementation details.

The most important limits are the following:

* Functions do not convert input to the byte order used by the selected primitive. Perform any required conversion explicitly, usually with `hc_swap32()` or `hc_swap64()`. Little-endian primitives such as MD5 normally need no swap on supported devices, while big-endian primitives such as SHA1 do. Verify intermediate values against a reference implementation.
* The buffer you provide only has to hold the words your length covers, which is `(len + 3) / 4` of them. For instance `sha1_update (&ctx, buf, 5);` reads 2 words, so `u32 buf[2]` is enough, and a third word is never read. The last word is read whole and then masked, so the bytes between your length and the end of that word have to exist but you do not have to set them. Two rules that used to live here are gone with that: the buffer no longer has to be a multiple of the block size of the primitive, and the bytes after the length no longer have to be zero. A buffer that is still block sized and zero padded keeps working exactly as before.
* Inside the context hashcat still appends with switch(), a shift to the final offset and an OR, because in OpenCL/CUDA there is no memcpy() and writing one costs the performance explained above. The difference is that the update functions now zero the part of the block you did not supply, instead of trusting you to have done it.
* Buffer-shifting functions modify private or local input buffers, so reinitialize them before reuse. Global-memory input buffers are not modified.
* The library does not validate these preconditions. Violating them can cause unexpected values or out-of-bounds memory access.

Choose the update function that matches the input address space. Local- and global-memory arrays use different functions.

Many primitives provide byte-swapping variants with matching prototypes, such as `sha1_update_swap()` alongside `sha1_update()`, and `sha1_update_utf16le_swap()` alongside `sha1_update_utf16le()`. Add a missing helper in a separate pull request rather than as part of a new hash mode.

Host code can use the same library through the emulation headers. Include the appropriate header, such as `emu_inc_hash_sha1.h`, and observe the same preconditions as device code. See `src/feed.c` or `src/modules/module_12600.c` for examples.

## Salt data ##

hashcat separates salt-related data into the fixed-layout `salt_t` structure and an optional mode-specific extended salt, or esalt. This arrangement supports both simple salts and formats with complex auxiliary data.

### salt_t ###

The `salt_t` fixed-size structure is defined in `OpenCL/inc_types.h`. Its buffers and configuration fields use 32-bit integers, giving host code and every compute backend the same stable, device-friendly layout. Kernels generally process these buffers as `u32` words, but this does not mean every GPU register is limited to 32 bits. The fields are described below:

* `u32 salt_buf[64]`: Stores up to 256 bytes of salt data as 64 32-bit words. Use an esalt when the required data exceeds this capacity.
* `u32 salt_buf_pc[64]`: Stores values precomputed from the salt. For example, `sha1($p.md5($s))` can store `md5($s)` here instead of recomputing it for every candidate.
* `u32 salt_len`: Gives the number of valid bytes in `salt_buf`. hashcat includes this length when grouping salts, so set it meaningfully even for a synthetic salt.
* `u32 salt_len_pc`: Gives the number of valid bytes in `salt_buf_pc`. Leave it at the default value of zero when the precomputed buffer is unused.
* `u32 salt_iter`: Gives the slow-hash iteration count consumed by the `_loop` kernel. KDFs such as PBKDF2 count initialization as their first round, so store one fewer loop iteration for those algorithms.
* `u32 salt_iter2`: Gives the iteration count for a secondary loop kernel when `OPTS_TYPE_LOOP2` is set.
* u32 salt_dimy: The size of a second work dimension for the kernel launch. It is only read where the module's opti_type carries one of the OPTI_TYPE_SLOW_HASH_DIMY_INIT, _LOOP or _COMP flags, and it is the module that sets it.
* `u32 salt_sign[2]`: Preserves information needed to reproduce an ambiguous original hash, such as an encoded iteration count or noncanonical trailing digest bits. DEScrypt, for example, encodes a 64-bit digest in 11 base64 characters. Some implementations retain nonzero values in the two unused bits, so the decoder must preserve them for exact output.
* `u32 digests_cnt`: Gives the number of digests grouped under this salt. hashcat maintains this field while sorting and deduplicating hashes. Do not modify it.
* `u32 digests_done`: Gives the number of cracked digests under this salt. Once it equals `digests_cnt`, hashcat can omit the salt from later kernel invocations. hashcat maintains this field. Do not modify it.
* `u32 digests_offset`: Gives the starting position of this salt's digests in the shared sorted digest buffer. The kernel uses it during lookup. hashcat maintains this field. Do not modify it.
* `u32 scrypt_N`: Retains the scrypt cost parameter in the historical fixed salt layout. hashcat maintains this field. Do not modify it.
* u32 scrypt_r: See scrypt_N.
* u32 scrypt_p: See scrypt_N.

### esalt ###

Use an esalt for additional data such as encrypted blocks, IVs, or salts too large for `salt_t`. Define the same structure in the module and kernel, keep both definitions synchronized, and return its fixed allocation size from `module_esalt_size()`. Fields within the structure may still describe variable-length content. hashcat provides a fresh `void *esalt_buf` for each `module_hash_decode()` call, which the decoder and encoder can cast to the mode-specific type:

```
wpa_eapol_t *wpa_eapol = (wpa_eapol_t *) esalt_buf;
```

The encoder accesses the esalt through the same cast.

Every mode must populate `salt_buf` and set `salt_len`, even when it also uses an esalt. A slow hash must also set `salt_iter`, and any mode with an esalt must implement `module_esalt_size()`.

## Choosing between salt_t and an esalt ##

Use `salt_t` for a binary salt of up to 256 bytes and an esalt when the format needs a custom structure. The distinction also controls grouping. hashcat first groups digests by `salt_t`, then distinguishes the hashes within each group by their esalt data. In SQL-like terms:

`SELECT digest FROM hashes GROUP BY salt_t, esalt`

This hierarchy is an optimization. Put data shared by expensive derivations in `salt_t` and consume it in `_init` and `_loop`. Put per-hash verification data in the esalt and consume it in `_comp`.

WPA illustrates the benefit. PMK derivation needs only the ESSID, while each handshake also has IVs, MAC addresses, and encrypted data. Storing the ESSID in `salt_t` and the handshake-specific values in the esalt lets 100 handshakes from one network share a single expensive derivation. The `_comp` kernel then verifies the result against each handshake.

The preferred `_comp` design performs a digest lookup. Hashes that share one `salt_t` need only one `_init` and `_loop` sequence. hashcat sorts their decoded `digest_t` values into a lookup structure, and `_comp` passes `r0` through `r3` to the `COMPARE_M` macro. Its bitmap prefilter and binary search scale efficiently to large hash sets. See `OpenCL/m00500-pure.cl` for a simple example.

Some formats have no final digest to look up and must instead decrypt data and test a pattern. One approach is to make `salt_t` as unique as the esalt, for example by copying part of the encrypted data into `salt_buf`. hashcat then invokes `_comp` separately for each target and advances `digests_offset`, allowing the kernel to index each hash individually. See `OpenCL/m14700-pure.cl` for an example.

The `OPTS_TYPE_DEEP_COMP_KERNEL` flag provides a third design. It makes hashcat invoke `_comp` for every esalt associated with a shared `salt_t`, preserving optimizations such as shared WPA derivation without forcing both structures to be equally unique. Use it only when the format requires this behavior. See `OpenCL/m22000-pure.cl` for an example.

Prefer the digest-lookup design whenever possible. If the plaintext is fully known, encrypting it and looking up the result may avoid a per-target decryption and pattern check.

## Tokenizer ##

The tokenizer parses delimited hash lines while handling common extraction-tool output that does not follow strict CSV rules. It also performs initial character and length validation.

A dedicated tokenizer is faster than regular expressions on files with millions of hashes, and its configuration gives reviewers a consistent description of the hash format. A single line may combine fixed- and variable-length fields, and each field may use a different separator. Configure separators per field for this reason.

After declaring the tokenizer context, set the required `token_cnt` field to the number of columns in the hash line. The fixed limit is 128 columns. A format with a variable column count can try multiple tokenizer configurations in sequence.

```
hc_token_t token;

token.token_cnt = 1;
```

A simple unsalted MD5 hash has one field containing exactly 32 hexadecimal characters. Configure that field as follows:

```
token.len_min[0] = 32;
token.len_max[0] = 32;
token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                 | TOKEN_ATTR_VERIFY_HEX;
```

Fields `len_min` and `len_max` define the valid byte-length range. Setting both to 32 requires an exact length. Attribute `TOKEN_ATTR_VERIFY_LENGTH` enforces that range, while `TOKEN_ATTR_VERIFY_HEX` accepts hexadecimal characters in either case and rejects odd lengths because two characters encode one byte. Use `TOKEN_ATTR_VERIFY_BASE16` when the token is read as text or as a base-16 number rather than decoded into bytes. See `include/types.h` for the other verification attributes.

Call the tokenizer after configuring all fields. A failed validation returns one of the parser error codes defined in `include/types.h`.

```
const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);
```

This is sufficient to produce a useful error message. When the tokenizer rejects a line it also records which part of the line it choked on, and hashcat reports that instead of the bare error name, for example `Separator unmatched near 'abcdefgh' (expected '$')`. A plugin that returns a parser error on its own, without going through the tokenizer, is reported with the plain error name.

On success, `token.buf[]` points to the start of each field and `token.len[]` contains the corresponding lengths. Existing modules provide useful examples for complex hash lines.

For a multi-field hash line, either mark a field with `TOKEN_ATTR_FIXED_LENGTH` or configure the single-byte separator in `token.sep`.

```
token.sep[0]     = ':';
token.len_min[0] = 32;
token.len_max[0] = 32;
token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                 | TOKEN_ATTR_VERIFY_HEX;

token.len_min[1] = 0;
token.len_max[1] = 32;
token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;
```

This example fixes the separator to `:` and rejects a line that omits it. Use `hashconfig->separator` instead when the format should honor the separator selected with option `-p`, which defaults to `:`.

* `TOKEN_ATTR_FIXED_LENGTH`: Use this for a field with a known exact length that is not followed by a separator. Set `token.len` rather than `token.len_min` and `token.len_max`. When adapting another module, update both the field names and their indices.

## The core library ##

This section describes how plugins are built and loaded. It is most relevant when distributing a compiled plugin or updating one for a new hashcat release.

A module does not carry its own copy of the hashcat core. The core is built once as a library, and the frontend, modules, bridges, and feeds link against it. This substantially reduces plugin and package size without changing module source or the normal `make` workflow.

The library is `libhashcat.so.7` on Linux, `libhashcat.7.dylib` on macOS, and `hashcat.dll` on Windows. It resides beside the hashcat executable, one directory above `modules/`. Linux and macOS plugins carry an rpath to that parent directory. On Windows, the executable imports the DLL from its own directory before loading plugins. No environment variable is required. An external plugin build should follow the library naming and link settings in `src/Makefile`, with the library one directory above the module.

The library does not export everything it defines. Most names are internal machinery that plugins must not call. An exported name is part of an interface a plugin can bind to, so its visibility is declared explicitly rather than inferred from whether a current module happens to use it.

File `include/export.h` defines two visibility macros. A function without either macro is private:

* `HC_API` marks the session interface used by programs that embed hashcat, including `hashcat_init()`, `hashcat_session_execute()`, and `status_display()`. Its compatibility follows the major version encoded in the library name.
* `HC_PLUGIN_API` marks the functions available to modules, bridges, and feeds, including parser, conversion, memory, file, hash, and cipher helpers. Its compatibility follows `MODULE_INTERFACE_VERSION`, which the module reports through `module_interface_version`. Existing prototypes, behavior, and the shape of `module_ctx_t` remain stable while that version remains unchanged, although new names may be added.

Host-side hash and cipher entry points are declared through `DECLSPEC` in the kernel headers. On a device, this macro selects the calling convention. On the host, it makes the function part of the export contract, including functions not currently used by an in-tree module.

The core is compiled with hidden visibility, so these declarations are enforced by the linker. Calling a core function marked by neither macro produces an undefined-symbol error:

```
/usr/bin/ld: /tmp/ccIMTvGO.o: in function `module_hash_decode':
module_12345.c:(.text+0x184): undefined reference to `hashes_init_stage1'
```

This link-time failure prevents an undefined symbol from surfacing only when `dlopen()` loads the plugin during a run. If plugins should be allowed to call the function, explain that need in the pull request and add the appropriate macro to its declaration.

A module exports `module_init`, a bridge exports `bridge_init`, and a feed exports two constants plus its required and advertised callbacks. Plugins also use hidden visibility, so their other definitions remain private. Module callbacks are reached through `module_ctx_t`, not by exported name.

The development installation includes the public headers, their dependencies, and the vendored headers they require. Installation of a declaration does not make its function public. The visibility macro on that declaration remains authoritative, so a plugin can compile against a private declaration but will fail to link.

An external plugin can use the following compile command. The interface version has no default, so omitting it is a compile-time error:

```
gcc -O2 -fPIC -shared -fvisibility=hidden \
    -DHC_PLUGIN_ABI_VERSION=720 -DMODULE_INTERFACE_VERSION_CURRENT=720 \
    -I/usr/local/include/hashcat -I/usr/local/share/hashcat/OpenCL \
    module_80000.c -o module_80000.so \
    -L/usr/local/lib -lhashcat -Wl,-rpath,'$ORIGIN/..' -Wl,-z,defs
```

Keep `-Wl,-z,defs` so the link fails when the core does not export a referenced name, rather than deferring the error until `dlopen()`.

A source-distributed plugin is compiled against the user's installed core and needs no separate compatibility build. A binary-distributed plugin must be rebuilt for each plugin interface version. hashcat rejects an incompatible binary before running any plugin code.

Compatibility is enforced through a versioned exported symbol such as `HASHCAT_PLUGIN_720`. Every C plugin holds a pointer to that symbol through `include/export.h`, although the function is never called. Raising `MODULE_INTERFACE_VERSION` changes the symbol name, so an older plugin cannot resolve it. This check works before `module_init()` on Linux, macOS, and Windows.

Compile-time definition `HC_PLUGIN_ABI_VERSION` supplies the version number. Headers `include/modules.h`, `include/bridges.h`, and `include/feed.h` require it so that no C plugin can be built without the compatibility reference.

The Rust feed is the one plugin here that is not built this way. It calls no core functions, cargo never sees a link line, and it declares its interface version in `GENERIC_PLUGIN_VERSION` instead, which the core reads after loading it.

An incompatible plugin produces the same diagnostic on every platform:

```
Module modules/module_12345.so was built for plugin interface 719, this hashcat provides 720
```

hashcat then stops. Native loader errors differ by platform, so hashcat reads the version from the plugin and reports a consistent message. Rebuild the named plugin against the current hashcat version.

Building a plugin against a core whose number has already moved does not get that far on Windows. The link fails there, because an import has to resolve at link time, and it names the same symbol. On Linux and macOS the link succeeds and the refusal happens at load.

A module can also report the current interface version while retaining an outdated `module_ctx_t` initializer. hashcat checks its shape immediately after `module_init()`:

```
Module context size in 'module_init()' for hash-mode '12345' is invalid. Is this module based on an old template?
Interface version in module context in 'module_init()' for hash-mode '12345' is outdated. Please recompile.
Module context missing field 'module_hash_decode' in 'module_init()' for hash-mode '12345'. Is this module based on an old template?
```

The first two messages require a rebuild. The last means that `module_init()` omits a field. Assign every field either a callback or `MODULE_DEFAULT`.

Command `make SHARED=0` restores the static arrangement in which every plugin contains its own core copy. This can be useful on platforms where shared loading is unsuitable. Do not combine static plugins with a shared frontend because that loads two core copies with independent global state. Switching through `make` is safe because the build relinks the affected targets. Copying individual binaries between differently configured trees is not.

The loader cannot detect this mixture because a static plugin is self-contained. Run `tools/test_package.sh` before shipping a package so every included plugin is checked for the expected core-library dependency. `SHARED` defaults to 0 outside Linux and macOS, including MSYS2, while official Windows releases use shared plugins. Pass `SHARED=1` when building a native Windows plugin for a downloaded release.

## Feed settings ##

This section describes how `-a 8` feed plugins accept settings from the user.

A feed receives its arguments as unparsed strings. hashcat processes its own options before it knows which feed will be loaded, so feed-specific options cannot participate in the main `getopt` pass. Every argument after the plugin name belongs to the feed and arrives in `global_ctx->workv`, with `workv[0]` containing the name used to select the feed.

Write feed settings as `key=value` arguments among the sources:

```
hashcat -a 8 -m 0 hashes.txt myfeed model.dat mode=2 pwlen=6:16
```

Do not use a hashcat-style option such as `--myfeed-mode 2`. Work arguments are required for two functional reasons.

First, work arguments are part of the attack identity. The brain includes every argument in the attack ID used to track covered keyspace, so runs with `mode=2` and `mode=4` remain distinct. Restore files also record these arguments so a resumed session keeps its original settings.

Second, hashcat stops parsing its own options at the plugin name. The `mode=2` argument therefore reaches the feed unchanged and cannot conflict with a current or future hashcat option.

You do not have to write the parser. Declare what your feed takes and let `feed_param_parse()` read it:

```c
static const char *model   = NULL;
static u64         mode    = 0;
static u64         burst   = 50000;
static bool        shuffle = false;

static const feed_param_t PARAMS[] =
{
  { "model",   FEED_PARAM_TYPE_STR,  &model,   0, 0,       "path to the trained model" },
  { "mode",    FEED_PARAM_TYPE_U64,  &mode,    0, 7,       "generator to use, 0-7" },
  { "burst",   FEED_PARAM_TYPE_U64,  &burst,   1, 1000000, "candidates per burst" },
  { "shuffle", FEED_PARAM_TYPE_BOOL, &shuffle, 0, 0,       "reorder tokens within a structure" },
  { NULL, 0, NULL, 0, 0, NULL }
};

bool global_init (generic_global_ctx_t *global_ctx, generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx)
{
  if (feed_param_parse (global_ctx->workc, global_ctx->workv, PARAMS, global_ctx->error_msg, sizeof (global_ctx->error_msg)) == false)
  {
    global_ctx->error = true;

    return false;
  }

  ...
}
```

The initial value of each variable is its default because an omitted setting leaves the variable unchanged. Fields `min` and `max` constrain `FEED_PARAM_TYPE_U64` values and are ignored for other types. Two zero bounds mean that no range is enforced.

An unknown or repeated key is an error. Feed settings do not appear in hashcat's `--help` output or tab completion, so strict validation is the only reliable way to catch a misspelling. Rejecting `mode=2 mode=4` also prevents an accidental duplicate from silently becoming a last-value-wins override.

Three additional helpers cover cases outside the declaration table:

* Function `feed_param_is_setting()` identifies setting arguments so a feed can skip them while collecting source paths.
* Function `feed_param_lookup()` returns one setting value as a string without requiring a declaration.
* Function `feed_param_usage()` formats the declaration table as one setting per line for an error or usage message.

An argument is a setting when it has the form `key=value`, where the key starts with a letter, continues with letters, digits, dashes, or underscores, and has no directory separator before `=`. Other arguments are sources. Prefix a filename that resembles a setting with a path, such as `./mode=2`, to classify it as a source.

## Porting a plugin from 7.1.2 ##

The following source changes are relevant when porting a working plugin from hashcat 7.1.2.

A feed must include `feed.h` instead of the removed `generic.h`. Candidate-only feeds need no other change because their contract is unchanged. The internal functions used by hashcat to drive feeds moved to `feed_ctx.h`, which plugins cannot include. A feed that called those functions was accessing internal bookkeeping and must remove that dependency.

`feed_param_t` and the `feed_param_*` functions moved out of `types.h` and `shared.h` into `feed.h` with their signatures unchanged, so a feed that already includes `feed.h` needs no further edit for them.

Remove the `module_dictstat_disable` registration from `module_init()`. Three optional hooks were added. Hooks `module_usage_notice` and `module_advice_notice` let a module print format-specific guidance, while `module_hash_hints` exposes account context used by attack mode 9. Assigning all three to `MODULE_DEFAULT` preserves the previous behavior.

The following command applies all four changes when `module_init()` still follows the in-tree template. It matches field names rather than line numbers:

```
sed -i -e '/module_ctx->module_dictstat_disable/d' \
       -e '/module_ctx->module_attack_exec/i\  module_ctx->module_advice_notice            = MODULE_DEFAULT;' \
       -e '/module_ctx->module_hash_init_selftest/i\  module_ctx->module_hash_hints               = MODULE_DEFAULT;' \
       -e '/module_ctx->module_unstable_warning/a\  module_ctx->module_usage_notice             = MODULE_DEFAULT;' \
       src/modules/module_*.c
```

Callbacks `module_hook_extra_param_init()` and `module_hook_extra_param_term()` now take `hashcat_ctx_t *` as their first parameter. Add it to either implemented callback so its definition matches the interface type. Most plugins do not implement these hooks. The new context also gives them access to `event_log_warning()` and the other logging functions described above.

Header `shared.h` was split, so include the header that now owns each helper. Parser functions such as `input_tokenizer`, `hc_strchr_next`, `hc_strchr_last`, `generic_salt_decode`, `generic_salt_encode`, and `strparser` are in `parser.h`. Path helpers are in `path.h`, system queries are in `system.h`, and `file_to_buffer` plus `hc_same_files` are in `filehandling.h`. No new header is included implicitly. Leaving only `shared.h` can produce implicit declarations and, for pointer-returning functions, truncated values at runtime.

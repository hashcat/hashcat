# hashcat Python Plugin Development Guide

This guide explains how to implement custom hash modes in Python through hashcat's assimilation bridge.

## 1. Introduction

The assimilation bridge supports hash-mode logic written in languages other than C, including Python. A conventional hashcat mode requires a C module and an OpenCL or CUDA kernel. The bridge allows the hash calculation itself to be implemented in Python.

The bridge provides two ways to run Python code:

- `-m 72000` uses a free-threaded Python 3.13 or newer and creates one bridge unit per logical processor.
- `-m 73000` uses standard Python 3.10 or newer and a single multiprocessing pool.

They expose the same Python module interface, but their runtime and extension-module compatibility differs. See `hashcat-python-plugin-requirements.md`.

## 2. Requirements

Start with `hashcat-python-plugin-quickstart.md` for a working example. Runtime and build dependencies are documented in `hashcat-python-plugin-requirements.md`.

## 3. Python bridge basics

hashcat loads the CPython shared library at runtime with `dlopen()` or `LoadLibrary()`. Users of a precompiled hashcat package need a compatible Python runtime, but not the development headers. The build needs headers for the bridge it produces, and mode 72000 requires Python 3.13 or newer headers even when the build-time interpreter itself is not free-threaded. Runtime compatibility is checked when the bridge starts.

Each hash mode selects one assimilation bridge. The Python bridge loads the CPython library, initializes the interpreter and selects the Python module to execute. This relationship is important when adding an upstream implementation or assigning a dedicated hash-mode number.

You can use a generic hash mode and supply only your `.py` implementation, or create a dedicated module and bridge. The generic route is simpler. A dedicated mode gives you control over parsing, binary data and workload tuning, and provides a stable mode number for tests.

hashcat includes a top-level `Python/` directory containing bridge helpers and example modules. The three helper modules are relevant to both generic and dedicated hash modes. Import them from your implementation rather than modifying them:

```text
- hcsp.py: Runs a batch in the current interpreter and manages context propagation.
- hcmp.py: Provides the multiprocessing counterpart, splitting batches across a worker pool.
- hcshared.py: Unpacks common structures and provides shared batch and debugging utilities.
```

The generic hash modes use two additional files:

```text
- generic_hash_mp.py
- generic_hash_sp.py
```

They are also useful templates for a dedicated mode. Section 6 describes them in more detail.

## 4. Required functions in a Python module

Modes 72000 and 73000 call the same three bridge entry points, so one module can normally run under either mode:

```python
def init(ctx):
def term(ctx):
def kernel_loop(ctx,passwords,salt_id,is_selftest):
```

- `init(ctx)`: Called once for each bridge unit. Use it to unpack salts and initialize the helper.
- `term(ctx)`: Called when that unit shuts down. Use it to release files, sockets or other resources.
- `kernel_loop(...)`: Processes a batch of password candidates and is called repeatedly while cracking.

A module using `hcsp` or `hcmp` also provides `calc_hash(password, salt)`. The helper imports it from the same Python module and calls it once for each password and salt.

A typical `init()` might look like this:

```python
def init(ctx):
  hcsp.init(ctx, extract_esalts)
```

The supporting functions have the following roles:

- `calc_hash(password, salt)` implements one password-and-salt calculation. In a generic mode, it returns the encoded value found before the separator in the hash line. A dedicated module can define a binary representation instead.
- `extract_esalts()` converts the module-specific esalt buffer into Python objects. If the mode has no esalt, it can return an empty list.
- `hcsp.init()` unpacks the fixed salts and calls `extract_esalts()` once. Later, `handle_queue()` imports `calc_hash()` from the module and applies it to each item in the batch.

The context contains the salts and esalts for the loaded hashes. Before calling `calc_hash()`, the helper selects one salt and merges its esalt into the same dictionary.

A typical `term()` might look like this:

```python
def term(ctx):
  hcsp.term(ctx)
```

Use this function to close files, network connections and any other resources owned by the bridge unit.

The main work happens in `kernel_loop()`:

```python
def kernel_loop(ctx,passwords,salt_id,is_selftest):
  return hcsp.handle_queue(ctx,passwords,salt_id,is_selftest)
```

hashcat sends candidates in batches. The helper loops over `passwords`, selects the correct salt and calls your `calc_hash(password, salt)` function. If you need full control, implement that batching directly in `kernel_loop()` instead of calling `handle_queue()`. In that case:

- `salt_id` identifies the salt for the batch. Under association attack (`-a 9`), the candidate at index `i` uses salt `salt_id + i`. Otherwise every candidate in the batch uses `salt_id`.
- `ctx["salt_per_pw"]` identifies which of those two layouts is active.
- `is_selftest` selects the separate self-test salt data rather than the salts loaded from the hash list.

## 5. Esalts, structured binary blobs and fixed salts

Salt handling is one of the less obvious parts of bridge development. The default helpers are sufficient for simple modes, while more complex formats require an understanding of fixed salts and extended salts.

A complex format can pass a module-specific binary structure, or esalt, from its C module to Python. Because each hash mode defines its own layout, the Python implementation can provide code to unpack it.

### C structure

To transfer a salt value to Python, define an exact structure in the module. The generic hash modes use this structure:

```c
typedef struct {
  u32 hash_buf[256];
  u32 hash_len;
  u32 salt_buf[256];
  u32 salt_len;
} generic_io_t;
```

### Unpacking esalts

Unpack the data into Python objects before using it:

```python
def extract_esalts(esalts_buf):
  esalts = []
  for hash_buf, hash_len, salt_buf, salt_len in struct.iter_unpack("1024s I 1024s I", esalts_buf):
    hash_buf = hash_buf[0:hash_len]
    salt_buf = salt_buf[0:salt_len]
    esalts.append({ "hash_buf": hash_buf, "salt_buf": salt_buf })
  return esalts
```

The `extract_esalts()` function is passed to `hcsp.init()`. Its unpacking format must exactly match the esalt structure defined by the C module.

### Salts use 32-bit binary fields

hashcat uses fixed-width integer fields extensively in host and device structures. The Python helpers convert byte buffers into `bytes` objects and scalar fields into integers. In the example above, each 256-element `u32` array occupies 1024 bytes.

### Fixed salt fields

Every hash mode uses the fixed `salt_t` structure from `OpenCL/inc_types.h`. An esalt is optional and module-specific. `hcshared.extract_salts()` exposes the fixed fields directly in the dictionary passed to `calc_hash()`:

```python
salt_buf     = salt["salt_buf"]
salt_buf_pc  = salt["salt_buf_pc"]
salt_iter    = salt["salt_iter"]
salt_iter2   = salt["salt_iter2"]
salt_sign    = salt["salt_sign"]
salt_repeats = salt["salt_repeats"]
```

The generic Python modes are a special case. Their C modules store the original string salt in the generic esalt and use a 16-byte MD4 surrogate in the fixed `salt_buf` for grouping. For those modes, `hcshared.get_salt_buf(salt)` returns the original salt from `salt["esalt"]["salt_buf"]`:

```python
def calc_hash(password: bytes, salt: dict) -> str:
  original_salt = hcshared.get_salt_buf(salt)
```

Do not confuse that helper with the fixed `salt["salt_buf"]` value. A dedicated mode can define its own esalt layout and should read fixed fields directly from the dictionary.

If the complete keyspace is exhausted, `calc_hash()` is normally called once for each candidate and each active salt. Association attack is the exception: each candidate is paired with one salt. In either case, the function implements exactly one password-and-salt calculation.


### Merging Salts and Esalts into a Single Object

Finally, after unpacking both salts and esalts from their binary blob form, they are explicitly combined into a single dictionary object to simplify access:

```python
for salt, esalt in zip(salts, esalts):
  salt["esalt"] = esalt
```

Salts and esalts are unpacked separately. Each salt entry contains the standard fields from `salt_t`, while each esalt has the structure chosen by its module. The merge keeps the two namespaces distinct: fixed fields remain at the top level and module-specific fields live under `salt["esalt"]`.

## 6. Generic Python hash modes `-m 72000` and `-m 73000`

The generic hash modes are intended for rapid prototyping in Python. The most straightforward starting point is one of these files:

- `generic_hash_sp.py` for the single-process helper used by mode 72000.
- `generic_hash_mp.py` for the multiprocessing helper used by mode 73000.

Notes:

- Mode 72000 creates one free-threaded Python subinterpreter and bridge unit per logical processor.
- On Windows and macOS, mode 73000 reports that multiprocessing is unsupported and loads `generic_hash_sp.py` instead. Edit that file on those platforms, or use mode 72000 for parallel execution with a free-threaded runtime.

The generic files are templates and remain unchanged in the upstream repository. Keep a custom implementation in a separate file if it may be shared or contributed later.

The Python bridge uses the first generic bridge parameter to select an alternative module. Option `--bridge-parameter1` loads a custom file without modifying the template:

```
$ ./hashcat -m 73000 --bridge-parameter1 ./Python/myimplementation.py hash.txt wordlist.txt ...
```

This command loads `Python/myimplementation.py` instead of the default `generic_hash_mp.py`. A generic implementation has no dedicated hash-mode number, so users must select it with `--bridge-parameter1`. A contributed implementation can later be paired with a dedicated module and mode number.

### Design tradeoffs and format considerations

The generic modes use a common binary esalt to avoid mode-specific C decoding and encoding logic. Values returned by Python must therefore match the **original encoded format** exactly, which can be inefficient for a complex format. Instead of decoding each field into a dedicated structure, the examples append the salt after an asterisk (`*`):

```
hash-with-embedded-salt*salt
```

This convention makes each hash line unique when several salts are present and keeps the prototype parser simple.

A dedicated mode should normally implement proper hash-line decoding and encoding rather than retain this generic convention. For example, a production yescrypt mode would decode the digest, salt and parameters into separate fields, then reconstruct the correct format after a successful crack.

The simplified generic format is intended for rapid prototyping and unfamiliar hash formats. It demonstrates a format-independent bridge without requiring mode-specific parsing code.

For production use, implement proper hash decoding and encoding to improve accuracy, efficiency and maintainability.

## 7. Debugging without hashcat

A plugin can also run as a standalone script:

```
echo "password" | python3 generic_hash_mp.py
```

The script reads passwords from standard input and prints the result of `calc_hash()`.

For salted hashes, first dump hashcat's context because only hashcat has decoded the hash list and its salts. The standalone script does not repeat that parsing. See the `main` section of `generic_hash_mp.py` for the context dump and load workflow.


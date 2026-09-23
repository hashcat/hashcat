# Hashcat Python Plugin Development Guide

This document is a comprehensive guide for writing custom hash modes in Python via Hashcat's Assimilation Bridge plugin.

## 1. Introduction

The Assimilation Bridge enables developers to implement complete hash mode logic in languages other than C, most notably Python. Traditionally, customizing Hashcat required writing a module in C and a kernel in OpenCL/CUDA. With the bridge, you can now implement a complete hash mode in Python.

The bridge provides two ways to run Python code:

- `-m 72000` uses a free-threaded Python 3.13 or newer and creates one bridge unit per logical processor.
- `-m 73000` uses an ordinary Python 3.10 or newer and one multiprocessing pool.

They expose the same Python module interface, but their runtime and extension-module compatibility differs. See `hashcat-python-plugin-requirements.md`.

## 2. Requirements

Ideally, start by walking through `hashcat-python-plugin-quickstart.md`, or read `hashcat-python-plugin-requirements.md`.

## 3. Python Bridge basics

Hashcat loads the CPython shared library at runtime with `dlopen()` or `LoadLibrary()`. Users of a precompiled hashcat package need a compatible Python runtime, but not the development headers. The build needs headers for the bridge it produces, and mode 72000 requires Python 3.13 or newer headers even when the build-time interpreter itself is not free-threaded. Runtime compatibility is checked when the bridge starts.

In general, when using any assimilation bridge "application" (such as the Python bridge), the hash mode determines which bridge plugin is loaded (this is a 1:1 relationship). From there, the bridge decides how to proceed. In the case of the Python bridge, it loads the Python library, sets up the interpreter, and finally selects which Python script to execute. Understanding this flow is essential, especially if you plan to contribute to upstream Hashcat on GitHub or want to register a dedicated hash mode number.

You can use a generic hash mode and supply only your `.py` implementation, or create a dedicated module and bridge. The generic route is simpler. A dedicated mode gives you control over parsing, binary data and workload tuning, and provides a stable mode number for tests.

Hashcat includes a top-level `Python/` directory with bridge helpers and example modules. The three helper modules are relevant to both generic and dedicated hash modes. Import them from your implementation rather than modifying them:

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

## 4. Required Functions in a Python Module

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

Here:

- `calc_hash(password, salt)` is your main implementation for one password and one salt. In a generic mode it returns the encoded value found before the separator in the hash line. A dedicated module can instead define a binary representation.
- `extract_esalts()` converts the module-specific esalt buffer into Python objects. If the mode has no esalt, it can return an empty list.
- `hcsp.init()` unpacks the fixed salts and calls `extract_esalts()` once. `handle_queue()` later imports `calc_hash()` from your module and applies it to each item in the batch.

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

Hashcat sends candidates in batches. The helper loops over `passwords`, selects the correct salt and calls your `calc_hash(password, salt)` function. If you need full control, implement that batching directly in `kernel_loop()` instead of calling `handle_queue()`. In that case:

- `salt_id` identifies the salt for the batch. Under association attack (`-a 9`), the candidate at index `i` uses salt `salt_id + i`. Otherwise every candidate in the batch uses `salt_id`.
- `ctx["salt_per_pw"]` tells you which of those two layouts is active.
- `is_selftest` selects the separate self-test salt data rather than the salts loaded from the hash list.

## 5. Esalts, Structured Binary Blobs and Fixed Salts

One of the most confusing parts for developers new to hashcat is salt handling. While simple hash modes may work out-of-the-box with default helpers, dealing with salts in real-world formats requires deeper understanding.

For complex formats, you may need a structured binary blob ("esalt") passed from the C plugin to Python. Since only you as the developer know the structures of your hash mode, structures vary. For that reason you can optionally write Python code to unpack it.

### Some C Structure

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

### Salts Use 32-bit Binary Fields

Hashcat uses fixed-width integer fields extensively in host and device structures. The Python helpers convert byte buffers into `bytes` objects and scalar fields into integers. In the example above, each 256-element `u32` array occupies 1024 bytes.

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

## 6. Python generic hash mode `-m 72000` and `-m 73000`

The generic hash modes are intended for rapid prototyping in Python. The most straightforward starting point is one of these files:

- `generic_hash_sp.py` for single-threaded (SP), typically when the user is using `-m 72000`.
- `generic_hash_mp.py` for multiprocessing (MP), typically when the user is using `-m 73000`.

Notes:

- Mode 72000 creates one free-threaded Python subinterpreter and bridge unit per logical processor.
- On Windows and macOS, mode 73000 reports that multiprocessing is unsupported and loads `generic_hash_sp.py` instead. Edit that file on those platforms, or use mode 72000 for parallel execution with a free-threaded runtime.

If you modify one of these plugin files, there's a trade-off: you won't be able to contribute that code directly to the upstream Hashcat repository, since those files are meant to remain clean for demonstration purposes.

To address this, the assimilation bridge provides a generic parameter that users can specify via the command line. In the case of the Python bridge, only the first parameter is used. Using `--bridge-parameter1` allows you to override the Python script to be loaded:

```
$ ./hashcat -m 73000 --bridge-parameter1 ./Python/myimplementation.py hash.txt wordlist.txt ...
```

This tells the Python bridge plugin to load `myimplementation.py` located in the local `Python` subdirectory instead of the default `generic_hash_mp.py`. This approach is especially useful if you plan to contribute `myimplementation.py` to the upstream Hashcat repository. If you choose to stay within the generic mode, your Python code won't have a dedicated hash mode, and you'll need to instruct users to use the `--bridge-parameter1` flag to load your implementation.

### Design Tradeoffs and Format Considerations

In the generic hash mode, we are using a generic binary esalt to avoid writing complex C encode/decode logic. However, guesses returned from Python must match the **original encoded format** exactly. This can be inefficient if encoding is complex. The hash lines are intentionally not decoded and re-encoded in a structured way. Instead, a simple trick such as appending the salt after an asterisk (`*`) is used:

```
hash-with-embedded-salt*salt
```

This technique makes each hash appear unique, especially when multiple salts are involved, and simplifies initial parsing and processing.

However, it is crucial to highlight:

- You are **not obligated to follow this generic approach**. In fact, it's generally preferable to implement proper hash line decoding and encoding logic.
- For instance, a proper Yescrypt implementation (unlike the quickstart document) would ideally decode hash lines into clear, separate components (digest, salt, parameters) and encode them accordingly upon successful cracking.

The reason the generic hash mode provided by Hashcat employs a simplified approach is to:

- Demonstrate a flexible, format-agnostic solution suitable for initial prototyping or unfamiliar hash formats.
- Avoid complexity and make it easy for plugin developers to get started quickly without deep understanding of specific hash format parsing logic.

In summary, while the generic mode is quick and easy, robust real-world plugins **should implement proper hash decoding and encoding logic** to ensure accuracy, efficiency, and maintainability.

## 7. Debugging Without Hashcat

You can run your plugin as a standalone script:
```
echo "password" | python3 generic_hash_mp.py
```
It reads passwords from stdin and prints the result of `calc_hash()`.

For salted hashes, first dump hashcat's context because only hashcat has decoded the hash list and its salts. The standalone script does not repeat that parsing. See the `main` section of `generic_hash_mp.py` for the context dump and load workflow.


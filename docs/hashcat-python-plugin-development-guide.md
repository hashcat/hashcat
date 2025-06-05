# Hashcat Python Plugin Development Guide

This document is a comprehensive guide for writing custom hash modes in Python via Hashcat's Assimilation Bridge plugin.

## 1. Introduction

The Assimilation Bridge enables developers to implement complete hash mode logic in languages other than C, most notably Python. Traditionally, customizing Hashcat required writing a module in C and a kernel in OpenCL/CUDA. With the bridge, you can now implement a complete hash mode in Python.

The bridge supports two hash modes to run python code:

- `-m 72000`: Uses single-threaded Python interpreter and hashcat controlling the multi-threading.
- `-m 73000`: Uses classic multiprocessing module controlling multi-threaded support.

Having two hash modes is currently a workaround; future Python developments toward a fully GIL-free mode should eventually resolve this. The single-threaded Python route is the way to go, and when Python will be totally GIL-free, we will remove the multiprocessing support completely. For now, we must work around platform-specific behavior (see `hashcat-python-plugin-requirements.md`).

## 2. Requirements

Ideally, start by walking through `hashcat-python-plugin-quickstart.md`, or read `hashcat-python-plugin-requirements.md`.

## 3. Python Bridge basics

Hashcat implements the CPython interface, loading the embedded interpreter via dynamic loading mechanisms (`dlopen()`, `LoadLibrary()`, etc). This enables runtime flexibility, allowing Hashcat to use whatever Python version is installed on the system. Users of the precompiled Hashcat binaries don’t need Python headers and just a working Python interpreter. Compatibility is checked at runtime, not compile time. If hashcat detect an invalid python version it will stop and print informative instructions on what to do next.

In general, when using any assimilation bridge "application" (such as the Python bridge), the hash mode determines which bridge plugin is loaded (this is a 1:1 relationship). From there, the bridge decides how to proceed. In the case of the Python bridge, it loads the Python library, sets up the interpreter, and finally selects which Python script to execute. Understanding this flow is essential, especially if you plan to contribute to upstream Hashcat on GitHub or want to register a dedicated hash mode number.

You can decide to use the generic hash mode and only contribute the .py file itself with your implementation, or you copy the bridge code and hardcode the path to you .py implementation in there. The advantage in the generic mode is that it's super simple, but it will run a little slower and you have less control about workload tuning. Also having a dedicated mode allows you to implement a unit test, because you have a dedicated hash mode that you can refer to.

Hashcat includes a top-level `Python/` directory with standard helpers and bridge modules:

The following three files are relevant regardless of whether you plan to create a generic or a dedicated hash mode. These modules do the heavy lifting to interact with Hashcat internals from Python. Basically you should not need to change them, and instead you import them from your implementation:

```text
- hcsp.py: Helper for single-threaded mode. Manages queue handling, function invocation, and context propagation.
- hcmp.py: Extends `hcsp.py` to support multiprocessing. It spawns worker processes and routes password batches via queues.
- hcshared.py: Shared utility functions between SP and MP, for instance some getter function for salt data retrieval.
```

There are two additional files, and they are mainly relevant in case you plan to make use of the generic hash mode. But even if you plan to make a dedicated hash mode have a look into them, most likely they will be a very good template for your non-generic mode

```text
- generic_hash_mp.py
- generic_hash_sp.py
```

We will discuss these two in more detail in the `generic hash mode` section.

## 4. Required Functions in a Python Module

Both `-m 72000` and `-m 73000` follow the same requirements, with the idea that your python code will run in both hash-modes, whatever your user decides to use.

The requirements are to implement the following three functions:

```python
def init(ctx):
def term(ctx):
def kernel_loop(ctx, passwords, salt_id, is_selftest):
```

- `init(ctx)`: Called once during plugin startup. All salts and esalts are copied at this stage. You use it to wire up callbacks to helper modules.
- `term(ctx)`: Called once at shutdown. Use it to clean up resources like file handles or sockets if you use them.
- `kernel_loop(...)`: Main function for processing password batches. This is called many times during cracking.

A typical `init()` might look like this:

```python
def init(ctx):
  hcsp.init(ctx, calc_hash, extract_esalts)
```

Here:
- `calc_hash()` is your main implementation that processes one password (with one specific salt). You return the result in the format that hashcat requires. In generic hash mode that would be just the same format as in your hashlist. Instead, if you write your own decoder and encoder in the module, this can also be in binary for better performance.
- `extract_esalts()` is an optional function to deserialize binary esalt blobs. Depends on your hash, if esalts (such as binary blobs for decryption) are required.
- `hcsp.init()` stores these so that `handle_queue()` (described later) can call `calc_hash()` for each password in a batch.

Note the the ctx will hold your salt data from all hashes. Whenever calc_hash() is called, this context is given. If you have multiple hashes with multiple salts, the context will have all of them. The helper module hcsp.init() will deserialze the static salt and the dynamic salt and store the data in your context.

A typical `term()` might look like this:

```python
def term(ctx):
  hcsp.term(ctx)
```

This should be used in case you had open files, open networking connection, or similar. We are good citizens!

Here's our main function `kernel_loop()` where we spend almost all our time:

```python
def kernel_loop(ctx,passwords,salt_id,is_selftest):
  return hcsp.handle_queue(ctx,passwords,salt_id,is_selftest)
```

Hashcat optimizes performance by sending password candidates in batches. The `passwords` parameter in `kernel_loop()` is a list. Instead of manually looping over them, the helper module will queue them, and call your callback function which you had specified in the `init()` function before. The idea is that whenever your calc_hash() is called, it will always be only about one password and one salt (and optional some binary blobs), and you do not have to deal with queuing, whatever it is threaded or not threaded.

Of course, you can also fully control this yourself:

```python
def calc_hash(ctx, password, salt_id, is_selftest):
    # Your custom logic here
    return encoded_guess
```

If you want to control all by youself, here's what's important to know:

- salt_id: Basically a index number which tells you about which salt your calculation is about. When you initially receive the context, it will hold all salts at once, and you need to store them in the context. The helper scripts do that for your, but just for you to know, its the salt_id which tells the handle_queue() which salt data to pick before it calls your hash_calc() function.
- is_selftest: Historically hashcat keeps two parallel structures for the the selftest hash and real hash. As such they arrive in the context buffer, and you need to make a decision on that `is_selftest` flag which salt buffer to pick.

## 5. Esalts and Structured Binary Blobs, and fixed Salts

One of the most confusing parts for developers new to hashcat is salt handling. While simple hash modes may work out-of-the-box with default helpers, dealing with salts in real-world formats requires deeper understanding.

For complex formats, you may need a structured binary blob ("esalt") passed from the C plugin to Python. Since only you as the developer know the structures of your hash mode, structures vary. For that reason you can optionally write Python code to unpack it.

### Some C Structure

Let's say you need to transfer a salt value to python. You can specify an exact structure in the module to do so. Or, as in this example, this is how we had designed a generic hash mode:

```c
typedef struct {
  u32 hash_buf[16384];
  u32 hash_len;
  u32 salt_buf[16384];
  u32 salt_len;
} generic_io_t;
```

### Unpacking esalts

To access the data, we typically want to unpack it so it's easier to access from python:

```python
def extract_esalts(esalts_buf):
  esalts = []
  for hash_buf, hash_len, salt_buf, salt_len in struct.iter_unpack("65536s I 65536s I", esalts_buf):
    hash_buf = hash_buf[0:hash_len]
    salt_buf = salt_buf[0:salt_len]
    esalts.append({ "hash_buf": hash_buf, "salt_buf": salt_buf })
  return esalts
```

Remember, the extract_esalts() was given as function pointer to hcsp.init(). That's how the helper can include your code from outside the helper code. The esalt format is based on what is defined in the module struct.

### Salts Appear as Binary Blobs using 32 bit datatypes

Hashcat is optimized for performance, especially on GPUs. To improve performance, it mostly works on 32 bit datatypes instead of 8 bit datatypes. In python the helper scripts convert these binary blobs into byte[] objects that are easier to work with. As you can see from the above example: `16384 * 4 = 65536`

### Fixed salt datatypes

In general, in all hashcat hash modes:

- The `salt_t` structure is **fixed and consistent**.
- The esalt (extra salt) is **custom and plugin-specific**.

Since `salt_t` is a fixed structure, the helper mode come with a salt unpacker code and in addition, it provides getter functions:

```python
def get_salt_buf(salt: dict) -> bytes:
def get_salt_buf_pc(salt: dict) -> bytes:
def get_salt_iter(salt: dict) -> int:
def get_salt_iter2(salt: dict) -> int:
def get_salt_sign(salt: dict) -> bytes:
def get_salt_repeats(salt: dict) -> int:
def get_orig_pos(salt: dict) -> int:
def get_digests_cnt(salt: dict) -> int:
def get_digests_done(salt: dict) -> int:
def get_digests_offset(salt: dict) -> int:
def get_scrypt_N(salt: dict) -> int:
def get_scrypt_r(salt: dict) -> int:
```

These go back to the `salt_t` fixed structure you can find in `OpenCL/inc_types.h`. As an example on how to use these, here's a snippet from the `yescrypt`:

```python
settings=hcshared.get_salt_buf(salt)
```

The `salt` variable is one of the parameters from the calc_hash():

```python
def calc_hash(password: bytes, salt: dict) -> str:
```

Note that if you fully exhaust the Hashcat keyspace, your function has been called X times Y.. X is the number of candidates, and Y is all the salts (except if a salt has been cracked). What's important to realize that within your function, you implement hashing logic only for precisely that situation where you have one password and one salt.


### Merging Salts and Esalts into a Single Object

Finally, after unpacking both salts and esalts from their binary blob form, they are explicitly combined into a single dictionary object to simplify access:

```python
for salt, esalt in zip(salts, esalts):
  salt["esalt"] = esalt
```

Initially, salts and esalts are unpacked separately from their respective binary structures. Each salt entry contains standardized fields defined by the fixed `salt_t` structure and each esalt is dynamically structured and plugin-specific. Merging the esalt dictionary into the salt dictionary makes accessing all related data straightforward and intuitive within Python.

## 6. Python generic hash mode `-m 72000` and `-m 73000`

The "generic hash" support in hashcat is using python. The main idea behind "generic" is to write freely. Ideal for rapid prototyping and achieving your goal.

The most straight-forward way is to edit the following files directly:

- `generic_hash_sp.py` for single-threaded (SP), typically when the user is using `-m 72000`.
- `generic_hash_mp.py` for multiprocessing (MP), typically when the user is using `-m 73000`.

Notes:

- Even though `-m 72000` uses single-threaded Python, the bridge plugin above it manages multiple Python interpreters (one per thread) making it effectively multi-threaded.
- On Windows/macOS, if `-m 73000` is selected, it silently falls back to `generic_hash_sp.py` due to limitations with multiprocessing. This behavior is important to understand and you might otherwise wonder why your code changes have no effect.

If you modify one of these plugin files, there's a trade-off: you won’t be able to contribute that code directly to the upstream Hashcat repository, since those files are meant to remain clean for demonstration purposes.

To address this, the assimilation bridge provides a generic parameter that users can specify via the command line. In the case of the Python bridge, only the first parameter is used. You can override the Python script to be loaded using `--bridge-parameter1`:

```
$ ./hashcat -m 73000 --bridge-parameter1 myimplementation.py hash.txt wordlist.txt ...
```

This tells the Python bridge plugin to load `myimplementation.py` instead of the default `generic_hash_mp.py`. This approach is especially useful if you plan to contribute `myimplementation.py` to the upstream Hashcat repository. If you choose to stay within the generic mode, your Python code won’t have a dedicated hash mode, and you'll need to instruct users to use the `--bridge-parameter1` flag to load your implementation.

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
python3 generic_hash.py
```

It reads passwords from stdin and prints the result of `calc_hash()`:

```
echo "password" | python3 generic_hash_mp.py
```

Note that you probably want to inline the correct salt value, see the `main` section in the code. TBD: Add some sample


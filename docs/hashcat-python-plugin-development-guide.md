# hashcat Python Plugin Development Guide

This guide covers writing a hash mode in Python through hashcat's assimilation bridge. Start with
`hashcat-python-plugin-quickstart.md` for a working example, and
`hashcat-python-plugin-requirements.md` for what the machine needs.

If you are moving a plugin from hashcat 7, read section 8 first. It is a short list and the changes
are all simplifications.

## 1. How the bridge runs your plugin

hashcat starts one Python process per CPU thread. Each one loads your plugin and then answers batches
of candidates over a pipe until the run ends. hashcat itself links no Python library and is built
without Python headers.

Each process is an ordinary interpreter started from `PATH`, so your plugin runs under the environment
you activated, imports whatever an ordinary script could import, and needs no locking of its own. The
processes share nothing, which is what lets them use every core whatever your plugin imports.

```
hashcat                           Python/hcworker.py x N
  |                                 |
  | INIT   salts and esalts, once   |  loads your plugin, calls init()
  | BATCH  candidates               |  calls calc_hash() for each one
  | RESULT the hashes               |
```

The salts travel once, at startup. A batch after that carries nothing but candidates, and its size is
chosen by autotune.

## 2. What your plugin must define

One function and two constants:

```python
def calc_hash(password: bytes, salt: dict) -> str:
```

```python
ST_HASH = "<a hash line>"
ST_PASS = "<the password that produces it>"
```

`calc_hash()` computes one password against one salt and returns the part of the hash line before the
`*`, as hashcat will compare it. Returning a list of up to 32 values instead is allowed, for a
password that can match in more than one form.

`ST_HASH` and `ST_PASS` are the self-test pair. hashcat runs it on every unit before the run and
refuses to start without them, because a plugin that computes the wrong thing otherwise looks like a
run that cracks nothing.

## 3. What your plugin may define

```python
def extract_esalts(esalts_buf: bytes) -> list:
```

Converts the mode's esalt buffer into one Python object per hash. The generic modes keep the hash line
and its salt there, and the shipped plugin has the unpacking for it. A mode with no esalt can leave
this out.

```python
def init(ctx: dict) -> None:
def term(ctx: dict) -> None:
```

Called once per worker, after the salts arrive and before it exits. Use them for a file, a socket or a
connection your `calc_hash()` needs. Both are optional, and `ctx` carries:

```python
ctx["salts"]              # the run's salts, each with its esalt merged in
ctx["st_salts"]           # the self-test salt
ctx["salt_per_pw"]        # True under an association attack
ctx["bridge_parameter1"]  # --bridge-parameter1 .. 4, or None
```

An exception from any of these, or from `calc_hash()`, reaches the terminal as a traceback and stops
the run.

## 4. Salts

### The fixed fields

Every hash mode has the `salt_t` structure from `OpenCL/inc_types.h`. `hcshared.extract_salts()`
unpacks it and the fields sit at the top level of the dictionary your `calc_hash()` receives:

```python
salt["salt_buf"]      salt["salt_buf_pc"]   salt["salt_iter"]    salt["salt_iter2"]
salt["salt_sign"]     salt["salt_repeats"]  salt["orig_pos"]     salt["digests_cnt"]
salt["scrypt_N"]      salt["scrypt_r"]      salt["scrypt_p"]
```

`hcshared` has a reader for each, for example `hcshared.get_salt_iter(salt)`.

### The esalt

Anything the fixed fields cannot hold goes in the mode's own esalt, whose layout the mode's C module
defines. `extract_esalts()` turns it into Python objects, and the result lands under `salt["esalt"]`.
Fixed fields stay at the top level, so the two namespaces do not collide.

The generic modes are the case worth knowing. Their C module stores the real salt in the esalt and
keeps only a 16 byte surrogate in `salt_buf` for grouping hashes. For them the salt you want is the
esalt's, which is what `hcshared.get_salt_buf()` returns:

```python
def calc_hash(password: bytes, salt: dict) -> str:
  real_salt = hcshared.get_salt_buf(salt)     # the esalt's, for a generic mode
  grouping  = salt["salt_buf"]                # the surrogate, almost never what you want
```

A mode of your own defines its own esalt and should read the fixed fields directly.

### Which salt a candidate gets

Normally every candidate in a batch uses one salt, and hashcat works through the salts in turn. An
association attack (`-a 9`) is the exception: it pairs candidate `i` with salt `i`. The worker already
does that arithmetic, so `calc_hash()` receives the right salt either way. `ctx["salt_per_pw"]` says
which layout is in force, for a plugin that needs to know.

### A worked esalt

The generic modes pass this structure from C:

```c
typedef struct {
  u32 hash_buf[256];
  u32 hash_len;
  u32 salt_buf[256];
  u32 salt_len;
} generic_io_t;
```

Each `u32` array is 1024 bytes, so the format string is:

```python
def extract_esalts(esalts_buf: bytes) -> list:
  esalts = []

  for hash_buf, hash_len, salt_buf, salt_len in struct.iter_unpack("1024s I 1024s I", esalts_buf):
    esalts.append({ "hash_buf": hash_buf[0:hash_len], "salt_buf": salt_buf[0:salt_len] })

  return esalts
```

The format has to match the C structure exactly. `iter_unpack` refuses a buffer that is not a whole
number of records, which catches most mistakes on the first run.

## 5. Choosing the plugin

Mode 73000 loads `Python/generic_hash.py` unless `--bridge-parameter1` names another file:

```
hashcat -m 73000 --bridge-parameter1 ./myplugin.py hash.txt wordlist.txt
```

The path can be anywhere. The worker puts the plugin's own directory on `sys.path`, so a plugin split
over several files works, and `Python/` is on `sys.path` too, so `import hcshared` resolves from
either place.

Keep your work in a file of your own. `Python/generic_hash.py` is a template that an upgrade replaces.

## 6. A generic mode or a mode of your own

A generic mode is for prototyping. It avoids writing any C, at the cost of a hash line that carries
the original encoded format on both sides of a `*`, and of having no mode number of its own.

A dedicated mode is a C module plus this bridge. It decodes the hash line into fields, reassembles the
correct format after a crack, gets a mode number that tests can name, and can tune its own workload.
That is what a contributed mode should become, and the generic route is how it starts.

## 7. Running a plugin outside hashcat

A plugin is a plain module whose only hashcat import is `hcshared`, so you can call it directly. The
salt is a dictionary, and for a generic mode `get_salt_buf()` reads one key of it:

```python
import sys

sys.path.insert(0, "Python")

import myplugin

salt = {"esalt": {"salt_buf": b"9348746780603343"}}

print(myplugin.calc_hash(b"hashcat", salt))
```

That is the whole harness. For a mode with a real esalt, build the same dictionary your
`extract_esalts()` would have produced.

Inside hashcat there is nothing to turn on: an exception prints its traceback and stops the run, and
anything your plugin prints goes to standard error rather than into the protocol.

## 8. Upgrading from hashcat 7

hashcat 7 had two Python modes with different parallel designs, and a plugin had to be written against
one of them. There is one bridge now, which starts an ordinary interpreter per CPU thread. The
following is what that changes.

### Your command line

```
hashcat -m 72000 ...      becomes      hashcat -m 73000 ...
```

Mode 72000 is removed, so `-m 72000` reports an unknown hash-mode. The hash line format and the plugin
interface are 73000's, which were always the same, so the mode number is the only thing to change.

There is no longer a choice to make. 73000 uses every CPU thread on Linux, macOS and Windows, with a
standard or a free-threaded interpreter, so the old advice to pick a mode per platform is gone. A
free-threaded build is now the slower of the two, which is the reason 72000 had nothing left to offer.

### Your plugin file

`kernel_loop()`, `init()` and `term()` were all required, and `kernel_loop()` existed to hand the batch
to `hcsp` or `hcmp`. The worker now loops over the batch itself, so:

- `kernel_loop()` is **removed**. Delete it.
- `init()` and `term()` are **optional**. Delete them unless they do something of yours.
- `hcsp` and `hcmp` are **gone**. Nothing imports them.
- `calc_hash()` and `extract_esalts()` are **unchanged**.

A hashcat 7 plugin therefore becomes a current one by deleting code:

```python
# hashcat 7
import hcsp

def kernel_loop(ctx, passwords, salt_id, is_selftest):
  return hcsp.handle_queue(ctx, passwords, salt_id, is_selftest)

def init(ctx):
  hcsp.init(ctx, extract_esalts)

def term(ctx):
  hcsp.term(ctx)
```

```python
# now: none of it is needed
```

`ST_HASH` and `ST_PASS` are now required rather than merely expected. A plugin without them is refused
at startup. In hashcat 7 a missing `ST_HASH` left the self-test hash empty, which ended in a segfault.

### What `calc_hash()` does when it fails

In hashcat 7 an exception from `calc_hash()` was printed and the candidate was recorded as
`invalid-password`. The run then continued at full speed and exited 0, which looks exactly like a
wordlist that did not contain the password.

It now stops the run and reports the traceback. If your plugin has candidates it legitimately cannot
hash, such as a password longer than the algorithm accepts, catch that in `calc_hash()` and return a
value that cannot match.

### Your environment

The old bridge loaded a Python shared library into hashcat, so the library had to be found and had to
match the headers hashcat was built against. That is what made a virtual environment or a pyenv
selection need `PYTHONPATH`, `DYLD_LIBRARY_PATH` or `PYENV_VERSION` to be set by hand.

An interpreter started from `PATH` needs none of that. Activate the environment, or name the
interpreter with `--bridge-parameter2`, and that is the whole of it.

An extension module no longer needs free-threaded support. Mode 72000 ran the plugin on a
free-threaded interpreter inside hashcat, where a module without free-threaded support would not load,
and one that did load often held a lock that serialized the units. A worker is an ordinary process, so
an ordinary wheel is all that is needed.

### Building hashcat

`make` no longer looks for Python. The `WIN_PYTHON` variable is gone, the MSYS2 Python package is not
needed to cross compile for Windows, and no `python3-dev` is needed on Linux.

### What it is worth

Measured with the shipped plugin, which is `sha256(salt + password)` and then 10000 rounds of sha256.
Each figure is the range over three runs, and the interpreter is the same on both sides of a row.

```
                                                    hashcat 7         now
i7-14700K, 28 threads, Python 3.14.7                4750-4770   6210-6390   H/s
i7-14700K, 28 threads, Python 3.14.7t                 600-609   6060-6070   H/s
i9-13900K, 32 threads, Python 3.14.7, Windows         270-279   4285-4390   H/s
Xeon W-3223, 16 threads, Python 3.14.0b2t, macOS        284-294   1015-1021   H/s
Xeon W-3223, 16 threads, the system Python 3.9.6      not built   1019-1021   H/s
```

The two free-threaded rows are 72000 against 73000, because 72000 was the only hashcat 7 mode that
would load a free-threaded interpreter. On such an interpreter hashcat 7's 73000 did not run at all, and
72000's figure was not hashcat's fault: hashlib's OpenSSL bindings hold a lock, so free threads inside
one interpreter ran barely faster than one. Every other row is 73000 against 73000.

Windows moved most. Mode 73000's `multiprocessing` pool could not be used there, so it reported
"falling back to single-threaded mode" and ran on one core. macOS had the same fallback, which is why
its only hashcat 7 figure comes from 72000.

The last row has no before figure because there was nothing to run. With only the system Python present,
hashcat 7's build skipped both Python bridges and said "Python headers not found", so the mode did not
exist on that machine. It runs there now, and as fast as it does on the pyenv interpreter above it.

A plugin whose candidates are cheap gains more again, from the batch size rather than from the process
model. Mode 72000 handed a unit 8 candidates per launch, and one launch is one round trip, so a plugin
computing a single sha256 spent its time in the protocol. The limit is 1024 now. On the same 28 threads
that is 611 kH/s against 16 kH/s under a limit of 8, and mode 74000's Rust bridge had the same limit and
gains the same way.

Worth knowing if you are tuning: autotune settles at about seven tenths of that limit, and it gets there
by timing the mode's loop kernel, which for a bridged mode is empty. So the figure does not depend on
what your plugin costs, and `-n` with `--force` is what overrides it.

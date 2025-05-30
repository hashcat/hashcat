
# Hashcat Python Plugin Developer Guide

## Introduction

This guide walks you through building custom hash modes in **pure Python** using Hashcat v7's Python plugin from the new assimilation bridge. Whether you're experimenting with a new algorithm, supporting a proprietary format, hacking a prototype, or just writing hashing logic in a high-level language, this plugin interface makes it fast and easy.

No C required. No recompilation. Just write your logic in pure python code in `calc_hash()`.

You can use any python modules you want.

---

## Quick Start

Hashcat mode `73000` is preconfigured to load a generic Python plugin source file from `Python/generic_hash_mp.py`:

```
hashcat -m 73000 -b
```

You can edit the `Python/generic_hash_mp.py`, or override the plugin source file with:

```
hashcat -m 73000 --bridge-parameter1=my_hash.py hash.txt wordlist.txt ...
```

---

## Yescrypt in One Line

### Generate a Yescrypt Test Hash

```
echo password | mkpasswd -s -m yescrypt
```

Example output:

```
$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0
```

### Prepare Hash Line for Hashcat

```
$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0*$y$j9T$uxVFACnNnGBakt9MLrpFf0$
```

(Use the full hash before the `*`, and the salt portion after the `*`.)

### Plugin Code

Install the module:

```
pip install pyescrypt
```

Then in your plugin (either `generic_hash_mp.py` for -m 73000 or `generic_hash_sp.py` for -m 72000)

```python
from pyescrypt import Yescrypt,Mode

# Self-Test pair
ST_HASH = "$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0*$y$j9T$uxVFACnNnGBakt9MLrpFf0$"
ST_PASS = "password"

def calc_hash(password: bytes, salt: dict) -> str:
  return Yescrypt(n=4096, r=32, p=1, mode=Mode.MCF).digest(password=password, settings=hcshared.get_salt_buf(salt)).decode('utf8')
```

That's it - full Yescrypt support in Hashcat with a single line of code.

### Run

```
hashcat -m 73000 yescrypt.hash wordlist.txt
```

---

## Debugging Without Hashcat

You can run your plugin as a standalone script:

```
python3 generic_hash.py
```

It reads passwords from stdin and prints the result of `calc_hash()`:

```
echo "password" | python3 generic_hash_mp.py
```

Note that you probably want to inline the correct salt value, see the `main` section in the code.

---

## Windows and Linux/macOS

There are significant differences between Windows and Linux/macOS when embedding Python as done here. It's a complex issue, and we hope future Python developments toward a fully GIL-free mode will resolve it. For now, we must work around platform-specific behavior.

### On Windows

The `multiprocessing` module is not fully supported in this embedded setup. As a result, only one thread can run effectively. While the `threading` module does work, most cryptographic functions like `sha256()` block the GIL. CPU-intensive algorithms such as 10,000 iterations of `sha256()` will monopolize the GIL, making the program effectively single-threaded.

### On Linux/macOS

The `multiprocessing` module works correctly, enabling full CPU utilization through parallel worker processes.

### Free-threaded Python (3.13+)

Python 3.13 introduces optional GIL-free support. This allows multithreading to work even in embedded Python, both on Linux and Windows. Hashcat leverages this through two modes:

- `-m 72000`: Uses free-threaded Python (no multiprocessing)
- `-m 73000`: Uses GIL-bound Python with multiprocessing

Multiprocessing (73000) supports most modules and is generally better for real-world workloads, but it works only on Linux. Developers may use `-m 73000` on Linux for performance and `-m 72000` on Windows for development, provided their code does not rely on modules that require `cffi` because this as of now lacks support for running with Python free-treaded ABI.

---

## Python 3.13 Requirement

The `-m 72000` mode requires Python 3.13 due to its reliance on the new free-threading feature. This feature is not available in earlier versions.

### Why Python 3.13 Isn't Preinstalled

Several Linux distributions, including Ubuntu 24.04, do not ship with Python 3.13 because it was released after the distro’s feature freeze. You will likely need to install it manually.

### Installing Python 3.13

**On Windows**: Use the official installer and ensure you check the "Install free-threaded" option - it's disabled by default.

**On Linux/macOS**: Use `pyenv`. It's the easiest way to install and manage Python versions:

```
pyenv install 3.13t
pyenv local 3.13t
```

This makes it easy to manage `pip` packages without global installs or virtual environments.


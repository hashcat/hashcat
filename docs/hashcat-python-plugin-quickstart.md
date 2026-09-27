# hashcat Python Plugin Quickstart

## Introduction

Modes 72000 and 73000 use the Python assimilation bridge to run custom hash-matching algorithms written in Python. The bridge fits into the regular cracking workflow by replacing or extending internal kernel routines.

hashcat calls the plugin's `calc_hash()` function to compute candidate hashes for verification. This makes it possible to experiment with new or uncommon algorithms without modifying the core C code or writing OpenCL or CUDA kernels.

This guide shows how to customize the generic plugin in pure Python for prototyping a hash mode, supporting a proprietary format or using an existing Python implementation.

Implement the required logic in `calc_hash()`. No C code or hashcat rebuild is required.

You can use any importable Python module that is compatible with the selected Python runtime.

## Quick Start

A benchmark is a good way to verify that your setup is working correctly.

Mode `73000` is configured to load the generic Python plugin from `Python/generic_hash_mp.py`:

```
hashcat -m 73000 -b
```

If you encounter issues with your Python installation, refer to `hashcat-python-plugin-requirements.md`.

To learn how to modify the plugin source, see `hashcat-python-plugin-development-guide.md`.

## Yescrypt in One Line

### Generate a Yescrypt Test Hash

```
echo password | mkpasswd -s -m yescrypt
```

Example output:

```
$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0
```

### Prepare the hash line for hashcat

```
$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0*$y$j9T$uxVFACnNnGBakt9MLrpFf0$
```

(Use the full hash before the `*` and the salt portion after the `*`.)

Modes `72000` and `73000` do not parse the hash themselves, so the input line contains both the complete hash and the settings passed to the plugin.

See `hashcat-python-plugin-development-guide.md` for details about developing a generic hash plugin.

### Plugin Code

Install the required module:

```
pip install pyescrypt
```

Then in your plugin (either `generic_hash_mp.py` for `-m 73000` or `generic_hash_sp.py` for `-m 72000`):

**Note for Windows and macOS users:** Mode `73000` automatically switches to `generic_hash_sp.py`, so be sure to edit that file.

```python
from pyescrypt import Yescrypt, Mode

# Self-test pair
ST_HASH = "$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0*$y$j9T$uxVFACnNnGBakt9MLrpFf0$"
ST_PASS = "password"

def calc_hash(password: bytes, salt: dict) -> str:
    return Yescrypt(n=4096, r=32, p=1, mode=Mode.MCF).digest(
        password=password,
        settings=hcshared.get_salt_buf(salt)
    ).decode("utf-8")
```

### Run Regularly

```
hashcat -m 73000 yescrypt.hash wordlist.txt
```

# Hashcat Python Plugin Quickstart

## Introduction

Hashcat v7 introduces a `Python plugin bridge` that allows you to write and integrate custom hash-matching algorithms directly in Python. This plugin system fits into the regular cracking workflow by replacing or extending internal kernel routines.

When enabled, Hashcat uses the plugin’s `calc_hash()` function to compute hash candidates for verification, making it easy to experiment with new or obscure algorithms without modifying core C code or writing OpenCL/CUDA kernels.

This guide demonstrates how to quickly customize such an algorithm using pure Python. Whether you're prototyping a new hash mode, supporting a proprietary format, or simply prefer high-level development, Python plugins make the process fast and straightforward.

No C required. No recompilation. Just write your logic in Python using `calc_hash()`, and you're ready to crack.

You can use any Python modules you like.

## Quick Start

A benchmark is a good way to verify that your setup is working correctly.

Hashcat mode `73000` is preconfigured to load a generic Python plugin from the source file `Python/generic_hash_mp.py`:

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

### Prepare the Hash Line for Hashcat

```
$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0*$y$j9T$uxVFACnNnGBakt9MLrpFf0$
```

(Use the full hash before the `*` and the salt portion after the `*`.)

Hashcat modes `73000` and `72000` are generic modes that do not parse the hash, which can lead to redundancy.

Refer to `hashcat-python-plugin-development-guide.md` to learn how to develop plugins for the generic hash mode.

### Plugin Code

Install the required module:

```
pip install pyescrypt
```

Then in your plugin (either `generic_hash_mp.py` for `-m 73000` or `generic_hash_sp.py` for `-m 72000`):

**Note for Windows and MacOS users:** Mode `73000` automatically switches to `generic_hash_sp.py`, so be sure to edit that file.

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

That’s it.

### Run Regularly

```
hashcat -m 73000 yescrypt.hash wordlist.txt
```

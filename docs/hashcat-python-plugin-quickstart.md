
# Hashcat Python Plugin Quickstart

## Introduction

This guide walks you through building custom hash modes in **pure Python** using Hashcat v7's Python plugin interface via the new assimilation bridge.

Whether you're experimenting with a new algorithm, supporting a proprietary format, prototyping a new feature, or simply prefer writing in a high-level language, this plugin interface makes development fast and straightforward.

No C required. No recompilation. Just write your logic in Python in the `calc_hash()` function.

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

**Note for Windows users:** Mode `73000` automatically switches to `generic_hash_sp.py`, so be sure to edit that file.

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

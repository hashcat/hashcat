# hashcat Python Plugin Quickstart

## Introduction

Mode `73000` cracks with a hash function you write in Python. hashcat does the parsing, the candidate
generation, the salt handling, the status display and the outfile, and asks your code for one thing:
the hash of a candidate under a salt.

That makes it a way to attack a format hashcat has no mode for, a proprietary format, or a format you
are still working out, without writing C and without writing a kernel. An existing Python
implementation can often be used as it stands.

You need a `python3` that hashcat can find. See `hashcat-python-plugin-requirements.md` if that is in
doubt.

Mode `72000` is gone. It ran the same plugin on a free-threaded interpreter, which mode 73000 no longer
needs, so `-m 73000` is the only Python mode.

## Quick start

A benchmark proves the setup works end to end:

```
hashcat -m 73000 -b
```

It loads `Python/generic_hash.py`, which computes `sha256(salt + password)` and then 10000 more
rounds of sha256. The startup banner names the interpreter it started and how many workers it runs:

```
* Unit #01 -> #28: Python 3.14.7 worker
```

## The hash line

Mode 73000 does not parse your format. It splits a line at the first `*` and hands both halves to
Python:

```
<the hash as you will compare it>*<everything your code needs to compute it>
```

The left half is what `calc_hash()` returns and what hashcat compares against. The right half is the
salt, and `hcshared.get_salt_buf(salt)` reads it back. Putting the settings in the right half is also
what makes each line unique when a list has several salts.

## yescrypt in one plugin

### A test hash

```
echo password | mkpasswd -s -m yescrypt
```

```
$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0
```

### The hash line for hashcat

The whole hash on the left, the settings prefix on the right:

```
$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0*$y$j9T$uxVFACnNnGBakt9MLrpFf0$
```

### The plugin

```
pip install pyescrypt
```

Copy `Python/generic_hash.py` to `yescrypt.py` and replace `calc_hash()` and the self-test pair:

```python
import hcshared

from pyescrypt import Yescrypt, Mode

ST_HASH = "$y$j9T$uxVFACnNnGBakt9MLrpFf0$SmbSZAge5oa1BfHPBxYGq3mITgHeO/iG2Mdfgo93UN0*$y$j9T$uxVFACnNnGBakt9MLrpFf0$"
ST_PASS = "password"


def calc_hash(password: bytes, salt: dict) -> str:
  settings = hcshared.get_salt_buf(salt)

  return Yescrypt(n=4096, r=32, p=1, mode=Mode.MCF).digest(password=password, settings=settings).decode("utf-8")
```

`ST_HASH` and `ST_PASS` are a line and the password that produces it. hashcat checks that pair before
every run, so a mistake in `calc_hash()` is reported as a failed self-test rather than as a run that
cracks nothing.

Keep your plugin in a file of your own rather than editing the shipped one. An upgrade replaces
`Python/generic_hash.py`.

### Run it

```
hashcat -m 73000 --bridge-parameter1 ./yescrypt.py yescrypt.hash wordlist.txt
```

## When something is wrong

An error in your plugin reaches the terminal as the Python traceback, naming the line, and the run
stops. There is nothing to turn on for that.

`hashcat-python-plugin-development-guide.md` covers salts, esalts, the optional hooks and what
changed since hashcat 7.

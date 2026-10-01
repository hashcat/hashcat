# hashcat Python Plugin Requirements

## What you need

A Python 3 interpreter that the operating system can find. That is the whole requirement.

hashcat does not load Python into its own process. It starts the interpreter as a separate program,
one process per CPU thread, and talks to each one over a pipe. Nothing about the build depends on
Python: there are no headers to install and no runtime library to match against them.

Mode `73000` is the one Python mode. Mode `72000` is gone.

```
-m 73000   a python3 on PATH, nothing at build time
```

Python 3.9 is the oldest build the bridge has been run on. The worker it runs uses only the standard
library, so an interpreter old enough to be in use at all is old enough for it. Your own plugin's
requirements are a separate matter and are whatever its imports ask for.

## Which interpreter hashcat starts

The name it looks for is `python3` on Linux and macOS, and `python` on Windows, resolved through
`PATH` the same way a shell resolves it. An environment you have already activated therefore applies
with nothing set for hashcat:

- An activated virtual environment, because `activate` puts its `bin` or `Scripts` directory first on
  `PATH`.
- A pyenv version, whether it came from `pyenv local`, `pyenv global`, `pyenv shell` or an exported
  `PYENV_VERSION`.
- A conda environment, for the same reason as a virtual environment.

To use an interpreter that is not on `PATH`, name it with `--bridge-parameter2`:

```
hashcat -m 73000 --bridge-parameter2 /opt/python3.14/bin/python3 hash.txt wordlist.txt
```

The startup banner names what it found, so there is no guessing:

```
* Unit #01 -> #28: Python 3.14.7 worker
```

## Extension modules

Anything that works in an ordinary Python process works here, because that is what a worker is. A
wheel from PyPI needs no special build and no special ABI.

This is a change from hashcat 7, where mode 72000 ran the plugin inside hashcat's own process on a
free-threaded interpreter. An extension module had to support the free-threaded ABI to load there at
all, and one that did load often serialized the threads it was supposed to run in parallel. Neither
applies any more. See the upgrade section of
`hashcat-python-plugin-development-guide.md`.

## Virtual environments

Activate it and run hashcat:

```
python3 -m venv ~/venv
. ~/venv/bin/activate
pip install pyescrypt
hashcat -m 73000 --bridge-parameter1 ./myplugin.py hash.txt wordlist.txt
```

The workers inherit the activated environment, so a module installed only in the venv imports.

If you would rather not activate it, name its interpreter instead. That is equivalent:

```
hashcat -m 73000 --bridge-parameter2 ~/venv/bin/python3 --bridge-parameter1 ./myplugin.py hash.txt wordlist.txt
```

## Per operating system

### Linux

The distribution's `python3` package is enough. Ubuntu, Debian, Fedora and Arch all ship one new
enough.

### macOS

The `python3` that comes with the Command Line Tools is enough. Nothing has to be installed, and no
`DYLD_LIBRARY_PATH` or `PYTHONPATH` has to be set.

### Windows

Install Python from https://www.python.org/downloads/windows/ and leave "Add python.exe to PATH"
ticked, which is the default. The free-threaded option that mode 72000 used to need is no longer
relevant, so leave it alone.

A Windows installation that is not on `PATH` is reached with `--bridge-parameter2`, for example an
MSYS2 one at `C:\msys64\mingw64\bin\python.exe`.

Beware the Microsoft Store stub. On a Windows that has never had Python installed, typing `python`
opens the Store instead of running an interpreter. If hashcat reports that it cannot start `python`,
check that `python --version` prints a version in the same shell.

## Standard or free-threaded

Either. A worker is a plain process, so the interpreter's threading model does not reach hashcat.

A standard build is the faster of the two. Measured on 28 units of an i7-14700K with the shipped
plugin, a standard 3.14.7 reaches 6210 to 6390 H/s and a free-threaded 3.14.7t reaches 6060 to 6070
H/s, because the free-threaded build is slower at running one thread and the bridge never asks it for
more than one.

## Where the files live

`Python/hcworker.py` and `Python/generic_hash.py` are read from hashcat's shared folder, which is the
hashcat directory for a source build and `$PREFIX/share/hashcat` for an installed one. hashcat can
therefore be started from any directory. A plugin named with `--bridge-parameter1` is read from
wherever you point it.

## How many processes

One per CPU thread, which the startup banner reports as the unit count. Each is a unit in the sense
of `docs/hashcat-assimilation-bridge.md`, so `-d` selects among them.

Each worker holds its own copy of the salts as Python objects, so a large hash list costs that much
memory per unit. Measured on 28 units with the shipped plugin, a worker is 19 MB at 100 salts, 28 MB at
2000 and 167 MB at 20000, so 20000 salts over 28 units comes to about 4.7 GB. A few thousand salts is
nothing. Tens of thousands is worth checking your memory for, and `-d` runs fewer units.

# Hashcat Python Plugin Requirements

## The two Python modes

Hashcat ships two Python bridges with the same module interface but different parallel execution models.

- Mode `72000` loads a free-threaded Python 3.13 or newer. It creates one bridge unit per online logical processor, with a separate subinterpreter for each unit. Python extension modules used by the plugin must support the free-threaded ABI.
- Mode `73000` loads an ordinary Python 3.10 or newer. On Linux it creates one bridge unit backed by a `multiprocessing` pool sized to the online logical processors.

On Windows and macOS, mode 73000 cannot use that multiprocessing design. The bridge reports the fallback and loads `Python/generic_hash_sp.py`, so it effectively runs single-threaded. Use mode 72000 there when its extension-module requirements can be met.

## Build and runtime requirements

```
-m 72000   Python 3.13+ headers to build, a free-threaded Python 3.13+ to run
-m 73000   Python headers to build, an ordinary Python 3.10+ to run
```

The mode 72000 build checks for Python 3.13 or newer headers. The headers themselves may come from an ordinary build. Only the shared library loaded at runtime must be free-threaded. Mode 73000 requires an ordinary, non-free-threaded shared library.

Hashcat loads Python dynamically. A precompiled hashcat package therefore needs the matching runtime library and any Python modules imported by the selected plugin, but it does not need development headers.

Ubuntu 24.04 carries Python 3.12, so its distribution packages cannot provide the mode 72000 runtime. `pyenv` can install both runtime variants without changing the system Python.

### Windows

Use the installer from https://www.python.org/downloads/windows/. Enable the optional free-threaded runtime for mode 72000. Leave it disabled for mode 73000.

### Linux and macOS with pyenv

See https://github.com/pyenv/pyenv for installation instructions. For mode 73000, select an ordinary build:

```
pyenv install 3.13
pyenv local 3.13
```

For mode 72000, select a free-threaded build whose version ends in `t`:

```
pyenv install 3.13t
pyenv local 3.13t
```

The ordinary and free-threaded runtimes are separate installations. Use `pyenv versions` to see which one is active before starting hashcat.

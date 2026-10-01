
# Hashcat Build Documentation

**Revision**: 1.8  
**Author**: See `docs/credits.txt`

---

## Requirements

A C compiler and `make`. Nothing else has to be installed to build the program and every plugin it
ships.

Two optional hash modes need a language toolchain, and a build without one skips that mode, says why,
and produces everything else:

- Mode `74000` needs Rust 1.85 or newer, which `rustup` provides. See
  `docs/hashcat-rust-plugin-requirements.md`.
- Mode `73000` needs no toolchain at all. It starts `python3` as a separate program at run time, so a
  Python 3 on `PATH` is all it asks for, and only when you use it. See
  `docs/hashcat-python-plugin-requirements.md`.

---

## Building Hashcat, step by step

### Step 1: Clone the Hashcat repository

```bash
$ git clone https://github.com/hashcat/hashcat.git
$ cd hashcat
```

---

### Step 2: Build Hashcat

```bash
$ make clean && make
```

The build produces `libhashcat.so.7` next to the `hashcat` binary. It holds the core, and the binary,
the modules, the bridges and the feeds all link against it. It has to travel with them when the tree
is copied somewhere else, and it is found beside the binary without anything set in the environment.
`make SHARED=0` builds the older arrangement instead, where every plugin carries its own copy of the
core.

---

### Step 3 (Optional): Check the build

```bash
$ tools/test_package.sh
```

The binary is started, made to load every module, made to produce candidates through a feed, and
made to compile a kernel and crack a hash. It reads the directory you give it, the current one by
default, so it checks an unpacked archive the same way it checks a build tree. The last group of
checks needs one OpenCL device and a CPU is enough for all of them, `--no-device` leaves that group
out.

---

### Step 4 (Optional): Install Hashcat (Linux only)

```bash
$ make install
```

Hashcat will use the following locations depending on your environment:

| Condition                                   | Session Files                          | Kernel Cache                          | Potfiles                              |
|--------------------------------------------|----------------------------------------|---------------------------------------|----------------------------------------|
| `$XDG_DATA_HOME` and `$XDG_CACHE_HOME` set | `$XDG_DATA_HOME/hashcat/sessions/`     | `$XDG_CACHE_HOME/hashcat/cache/kernels/`    | `$XDG_DATA_HOME/hashcat/`              |
| Only `$XDG_DATA_HOME` set                  | `$XDG_DATA_HOME/hashcat/sessions/`     | `$HOME/.cache/hashcat/cache/`               | `$XDG_DATA_HOME/hashcat/`              |
| Only `$XDG_CACHE_HOME` set                 | `$HOME/.local/share/hashcat/sessions/` | `$XDG_CACHE_HOME/hashcat/cache/kernels/`    | `$HOME/.local/share/hashcat/`          |
| None of the above                          | `$HOME/.local/share/hashcat/sessions/` | `$HOME/.cache/hashcat/cache/`               | `$HOME/.local/share/hashcat/`          |

---
## Building Hashcat for Android

See: [BUILD_Android.md](BUILD_Android.md)

---

## Building Hashcat with Docker

See: [BUILD_Docker.md](BUILD_Docker.md)

---

## Building Hashcat for Windows

| Method                                 | Documentation                        |
|----------------------------------------|--------------------------------------|
| From macOS                             | [BUILD_macOS.md](BUILD_macOS.md)     |
| Using Windows Subsystem for Linux (WSL)| [BUILD_WSL.md](BUILD_WSL.md)         |
| Using Cygwin                           | [BUILD_CYGWIN.md](BUILD_CYGWIN.md)   |
| Using MSYS2                            | [BUILD_MSYS2.md](BUILD_MSYS2.md)     |
| From Linux                             | Run: `make win`                      |

The Windows build produces `hashcat.dll` beside `hashcat.exe`. It holds the core, and the executable,
the modules, the bridges and the feeds all import from it, so it has to travel with them. Windows
searches the directory of the executable, so nothing has to be set in the environment.
`make win SHARED=0` builds the older arrangement instead, where every plugin carries its own copy of
the core.

---

## Done

Enjoy your fresh **Hashcat** binaries!

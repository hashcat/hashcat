# Assimilation Bridge in hashcat v7

## Overview

hashcat normally runs hash kernels through its CUDA, HIP, OpenCL and Metal backends. An assimilation bridge lets a hash-mode module replace or supplement part of that pipeline with a shared-library plugin. The plugin can run reference CPU code, an embedded language runtime, remote hardware, or another compute system that does not fit the normal backend interface.

Bridges are optional and selected by the hash-mode module. Modes that do not declare one continue to use the normal backend path.

## Shipped examples

### Embedded language runtimes

- Modes `72000` and `73000` run generic Python hash implementations. See `hashcat-python-plugin-quickstart.md` and `hashcat-python-plugin-requirements.md`.
- Mode `74000` provides the same generic model through Rust.

These bridges execute Python or Rust code on the host. They do not translate it into GPU code.

### CPU reference and hybrid modes

- Mode `70000` runs the reference Argon2id implementation through a C bridge.
- Mode `70100` keeps PBKDF2 on the normal backend and runs the memory-intensive scrypt `smix()` stage through the scrypt-jane bridge.
- Mode `70200` demonstrates yescrypt in scrypt-emulation mode through a CPU bridge.

Mode 70100 shows the hybrid design: a normal backend and a bridge can own different stages of one hash computation. The same interface can support another accelerator or a remote service, but no FPGA bridge currently ships with hashcat.

## Other possible uses

A bridge can support hardware-backed operations such as TPM requests, delegate work to a remote service, or wrap a compatible implementation from another project. These are possible uses of the interface, not features included in the current package.

## Selecting units

A bridge reports one or more *bridge units*, and each becomes one virtual backend device. Device options therefore operate on units:

- Option `-d` selects which units run. For example, `-d 2` runs unit 2 alone, while `-d 1,3` runs units 1 and 3.
- `-R` selects the physical backend device that generates candidates, which is a separate choice.

`hashcat -I -m <hash mode>` lists the units that mode would use, and the `Assimilation Bridge` block at startup lists them again. A bridge is selected by its hash mode, so `-I` without `-m` cannot enumerate bridge units. The same unit numbering is used by `-d`, `Speed.#NN`, `Hardware.Mon.#NN` and the watchdog.

Units of the same class share tuning. Units that report different classes, such as two board models, keep independently measured launch sizes.

## Development

See `hashcat-assimilation-bridge-development.md` for the interface, lifecycle, virtual-device model and shipped bridge examples.

# Assimilation Bridge in Hashcat v7

## Overview

Hashcat has historically optimized password cracking GPU and CPU compute backends. However, other types of hardware compute systems or pure software solutions were not supported. The Assimilation Bridge is a feature introduced in Hashcat v7 that extends the compute pipeline beyond traditional backends. It enables the integration of additional compute resources and software solutions such as FPGAs, remote TPMs, CPU reference implementations, or embedded runtimes into new or existing hash mode plugins.

All existing hash-mode plugins continue to function as before. Bridges are optional and only active when explicitly declared within a plugin's configuration. This ensures full backward compatibility with existing setups.

## Use Cases

### Embedded Language Runtimes

Hashcat v7 introduces support for an embedded Python interpreter as its premier demonstration example:

- Hash modes `-m 72000` and `-m 73000` use embedded Python; start with `-m 73000`.
- These demonstrate a "generic hash" model, enabling full hash mode creation in Python.
- Users don’t need to recompile when making changes.
- Python’s crypto ecosystem helps developers or AI generate new hash mode code easily and efficiently.
- Here's a sample how a user can add `yescrypt` (`$y$...`) support with just one line of code:

```python
from pyescrypt import Yescrypt,Mode

def calc_hash(password: bytes, salt: dict) -> str:
  return Yescrypt(n=4096, r=32, p=1, mode=Mode.MCF).digest(password=password, settings=hcshared.get_salt_buf(salt)).decode('utf8')
```

This is just a preview. See `docs/hashcat-python-plugin-quickstart.md` for details about hashing formats, self-test pairs, or when to use `-m 72000` vs. `-m 73000`.

### Hybrid Architecture

Note that in the Python example, only CPU resources are used and Hashcat does not transform Python into GPU code. However, the Bridge supports hybrid setups, where part of the workload runs on a traditional backend and another part on the Bridge. This model allows performance-critical components to be handled by the most suitable type of compute unit.

For example, in hash mode `-m 70100`, a demonstration of SCRYPT, the PBKDF2 stage runs on a GPU using OpenCL/CUDA/HIP/Metal, while the memory-intensive `smix()` runs on the CPU through a bridge using the scrypt-jane implementation. This could just as easily be offloaded to an FPGA instead, which would benefit from reduced code complexity and increased parallelization boosting performance significantly.

A mix of traditional backend compute on GPU and embedded Python is also possible.

### CPU-Based Reference Code

Bridges can also be used to quickly integrate reference implementations of new algorithms. We will provide initial examples for Argon2 and SCRYPT. These can run entirely on CPU or form part of a hybrid setup.

- Mode `-m 70000` uses the official Argon2 implementation from the Password Hashing Competition (PHC).
- Mode `-m 70200` demonstrates Yescrypt in its scrypt-emulation mode and benefits from AVX512 acceleration on capable CPUs.

### Secure Distributed Cracking

In scenarios where raw password data must remain local, bridges can enable remote processing of depersonalized intermediate keys. This allows secure password cracking using external compute infrastructure without compromising sensitive input.

A working proof-of-concept exists, but it's not yet confirmed for inclusion in the v7 release.

## Other Ideas for Use Cases (Not Yet Implemented)

### Remote Hardware

A bridge could be built to interact with TPMs on mobile devices or laptops, accessed through networked agents. This enables secure challenge/response flows with hardware-backed key storage.

### Project Interoperability

Depending on interface compatibility, code from other password cracking tools (e.g., JtR) could be wrapped in bridges, allowing functionality reuse and deeper collaboration.

## Limitations and Status

- Bridges are optional and configured on a per-plugin basis.
- Hashcat v7 includes working bridges for CPU and Python.
- FPGA support has been verified internally but is excluded from this release due to licensing issues.

> **Call to FPGA Developers**: Contribute an open FPGA implementation and bitstream and the Hashcat Developer Team will support in integrating it into a bridge. Please contact us on Discord.

## Conclusion

The Assimilation Bridge introduces a highly extensible mechanism to integrate custom compute resources and logic into Hashcat.

For hands-on examples and developer guidance, refer to the accompanying documentation in `docs/hashcat-assimilation-bridge-development.md` (first draft).

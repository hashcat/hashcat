# Requirements

What hashcat needs from a machine, for someone installing it and for someone packaging it.

Everything here is what hashcat checks at startup. A device that does not meet a requirement is
either skipped, with the reason printed, or handed to a backend that can drive it.

## The short answer

```
NVIDIA GPU     the NVIDIA driver, plus the CUDA Toolkit
AMD GPU        Linux: ROCm.  Windows: the Adrenalin driver, plus the AMD HIP SDK
Intel GPU      the Intel Graphics Compute Runtime, known as NEO
CPU            the Intel CPU Runtime for OpenCL, or PoCL
Apple          nothing, macOS carries Metal and OpenCL itself
```

## Two packages, not one, on NVIDIA and AMD

hashcat compiles its kernels while it runs, and on NVIDIA and AMD the compiler is not in the driver.

```
backend   runtime library                          compiler library              same package?
------------------------------------------------------------------------------------------------
CUDA      libcuda.so.1, nvcuda.dll                 libnvrtc.so.N, nvrtc64_XY.dll      no
HIP       libamdhip64.so.N, amdhip64_N.dll         libhiprtc.so.N, hiprtcXXYY.dll     no
OpenCL    libOpenCL.so.1, OpenCL.dll               inside the vendor's driver         yes
Metal     Metal.framework                          inside the framework               yes
```

A machine with the NVIDIA driver and no CUDA Toolkit has no CUDA backend. The same card still works
through OpenCL, which is slower, and hardware monitoring is unaffected. The same is true of an AMD
machine with the graphics driver and no HIP.

For a package maintainer that means the CUDA and HIP compiler libraries are runtime dependencies of
the corresponding backend, not of hashcat, and hashcat runs without any of them as long as one
OpenCL runtime is present.

## Minimum versions

```
component                      minimum     what happens below it
------------------------------------------------------------------------------------------------
CUDA driver                    12.0        the CUDA backend is disabled, OpenCL is used instead
NVRTC, from the CUDA Toolkit   12.0        same
HIP runtime, Linux and Windows 6.2.0       the HIP backend is disabled, OpenCL is used instead
macOS, for Metal               13.0        the Metal backend is disabled, OpenCL is used instead
macOS, for Apple OpenCL        13.0        the device is skipped, --force overrides
OpenCL platform                1.2         the device is skipped
OpenCL C, per device           1.2         the device is skipped
PoCL                           5.0         the device is skipped, --force overrides
PoCL's LLVM                    10.0        the device is skipped, --force overrides
Intel CPU Runtime for OpenCL   2020        the device is skipped, --force overrides
AMD OpenCL driver              3000        the device is skipped, --force overrides
NVIDIA OpenCL driver           500         the device is skipped, --force overrides
```

The CUDA and HIP minimums are set by what a current distribution can install rather than by what the
vendor still lists as supported. Ubuntu 24.04 is the oldest release targeted. Its own archive carries
nvidia-cuda-toolkit 12.0.140 and offers driver 535, which is CUDA 12.2, so CUDA 12.0 is met there
with nothing added. It ships no ROCm, and AMD publishes 6.2.4 for it, so HIP 6.2.0 is reachable.
PoCL stays at 5.0 because that is exactly what 24.04 ships.

Every number in that table is defined once, in `include/requirements.h`, and used from there by the
runtime checks and by the headers that set the API level the build targets. Changing a floor means
changing that file and this page together.

PoCL stays at 5.0 for a second reason beyond what 24.04 ships. No PoCL release has been good for
hashcat, because of the compilers it has been built against, so asking for a newer one would refuse
installs without making anything work better.

## Runtimes with no enforced minimum

hashcat checks no version for Intel's Graphics Compute Runtime, for Mesa's rusticl, or for any
runtime it does not recognise. They are used on a best effort basis. If one of them misbehaves,
check its version by hand, because hashcat will not do it for you.

A version string hashcat cannot parse is not treated as an old driver. It says so once and uses the
device anyway.

## What a device needs whatever the runtime

These are properties of the device rather than of the driver, and `--force` does not override them,
because a run that ignored them could not produce correct results.

```
constant memory     at least 65536 bytes
local memory        at least 32768 bytes, where the device has real local memory
byte order          little endian
compiler            the runtime must report one for the device
compute units       more than one
```

## What --force does

It overrides the driver version checks in the table above, and nothing else. It does not override the
OpenCL 1.2 minimum, the OpenCL C 1.2 minimum, or any of the device requirements. Results from a run
that needed `--force` should not be reported as bugs.

`--backend-info` skips the driver checks entirely, so it lists devices that a real run would refuse.

## The Python and Rust plugins

4 hash-modes are not compiled into hashcat and reach a language runtime instead. They are optional in
both directions: hashcat runs without any of them, and the toolchains below are needed to build them,
not to run the rest of hashcat.

```
mode     needs                          minimum   why that number
------------------------------------------------------------------------------------------------
72000    Python, free-threaded          3.13      free-threaded builds start there
73000    Python, multiprocessing        3.10      the oldest carrying every symbol it loads
74000    Rust                           1.85      the crates are edition 2024
-a 4     the Rust feed                  1.85      same crates
```

Both minimums are above what Ubuntu 24.04 delivers, which is Python 3.12 and Rust 1.75, so these come
from pyenv and rustup rather than from a distribution. That is the documented way to install them
anyway, and it is the one case in this page where the distribution is not the anchor.

A build without the toolchain still succeeds. The plugin is skipped, the build says which one and
why, and everything else is produced as usual.

`docs/hashcat-python-plugin-requirements.md` and `docs/hashcat-rust-plugin-requirements.md` cover
each in full.

## Hardware monitoring

Optional everywhere. hashcat cracks without it and loses the temperature, fan, clock and bus columns
of the status display.

```
              Linux            Windows          macOS
NVIDIA        NVML             NVML             not applicable
AMD           sysfs            ADL              not applicable
Intel GPU     sysfs            nothing          not applicable
Apple         not applicable   not applicable   IOKit
```

NVML comes from the NVIDIA driver, so a maintainer should treat libnvidia-ml as an optional runtime
dependency rather than a required one. On AMD under Linux nothing needs installing, because the
readings come from sysfs.

What is reported is temperature, fan speed, utilisation, core and memory clocks and bus width. On an
NVIDIA card there is also a warning when the card is being slowed down by heat or by a power brake,
which comes from NVML and therefore works wherever NVML does.

## Building

See BUILD.md. The build requirements are separate from everything above: a machine that builds
hashcat does not need any GPU runtime, and a machine that runs it does not need a compiler toolchain.

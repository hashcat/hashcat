# sse2neon
![GitHub Actions](https://github.com/DLTcollab/sse2neon/workflows/GitHub%20Actions/badge.svg)

A C/C++ header file that converts Intel SSE intrinsics to Arm/Aarch64 NEON intrinsics.

## Introduction

`sse2neon` is a translator of Intel SSE (Streaming SIMD Extensions) intrinsics
to [Arm NEON](https://developer.arm.com/architectures/instruction-sets/simd-isas/neon),
shortening the time needed to get an Arm working program that then can be used to
extract profiles and to identify hot paths in the code.
The header file `sse2neon.h` contains several of the functions provided by Intel
intrinsic headers such as `<xmmintrin.h>`, only implemented with NEON-based counterparts
to produce the exact semantics of the intrinsics.

## Mapping and Coverage

Header file | Extension |
---|---|
`<mmintrin.h>` | MMX |
`<xmmintrin.h>` | SSE |
`<emmintrin.h>` | SSE2 |
`<pmmintrin.h>` | SSE3 |
`<tmmintrin.h>` | SSSE3 |
`<smmintrin.h>` | SSE4.1 |
`<nmmintrin.h>` | SSE4.2 |
`<wmmintrin.h>` | AES  |

`sse2neon` aims to support SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2 and AES extension.

In order to deliver NEON-equivalent intrinsics for all SSE intrinsics used widely,
please be aware that some SSE intrinsics exist a direct mapping with a concrete
NEON-equivalent intrinsic. Others, unfortunately, lack a 1:1 mapping, meaning that
their equivalents are built utilizing a number of NEON intrinsics.

For example, SSE intrinsic `_mm_loadu_si128` has a direct NEON mapping (`vld1q_s32`),
but SSE intrinsic `_mm_maddubs_epi16` has to be implemented with 13+ NEON instructions.

### Floating-point compatibility

Some conversions require several NEON intrinsics, which may produce inconsistent results
compared to their SSE counterparts due to differences in the arithmetic rules of IEEE-754.

Taking a possible conversion of `_mm_rsqrt_ps` as example:

```c
__m128 _mm_rsqrt_ps(__m128 in)
{
    float32x4_t out = vrsqrteq_f32(vreinterpretq_f32_m128(in));

    out = vmulq_f32(
        out, vrsqrtsq_f32(vmulq_f32(vreinterpretq_f32_m128(in), out), out));

    return vreinterpretq_m128_f32(out);
}
```

The `_mm_rsqrt_ps` conversion will produce NaN if a source value is `0.0` (first INF for the
reciprocal square root of `0.0`, then INF * `0.0` using `vmulq_f32`). In contrast,
the SSE counterpart produces INF if a source value is `0.0`.
As a result, additional treatments should be applied to ensure consistency between the conversion and its SSE counterpart.

## Requirement

Developers are advised to utilize sse2neon.h with GCC version 10 or higher, or Clang version 11 or higher. While sse2neon.h might be compatible with earlier versions, certain vector operation errors have been identified in those versions. For further details, refer to the discussion in issue [#622](https://github.com/DLTcollab/sse2neon/issues/622).

## Usage

- Put the file `sse2neon.h` in to your source code directory.

- Locate the following SSE header files included in the code:
```C
#include <xmmintrin.h>
#include <emmintrin.h>
```
  {p,t,s,n,w}mmintrin.h could be replaceable as well.

- Replace them with:
```C
#include "sse2neon.h"
```
- If you target Windows Arm64EC, pass `/D_DISABLE_SOFTINTRIN_=1` to MSVC or add `#define _DISABLE_SOFTINTRIN_ 1` in before `#include` any Windows header files to disable implicit inclusion of SSE header files.
- Explicitly specify platform-specific options to gcc/clang compilers.
  * On ARMv8-A 64-bit targets, you should specify the following compiler option: (Remove `crypto` and/or `crc` if your architecture does not support cryptographic and/or CRC32 extensions)
  ```shell
  -march=armv8-a+fp+simd+crypto+crc
  ```
  * On ARMv8-A 32-bit targets, you should specify the following compiler option:
  ```shell
  -mfpu=neon-fp-armv8
  ```
  * On ARMv7-A targets, you need to append the following compiler option:
  ```shell
  -mfpu=neon
  ```

## Compile-time Configurations

Though floating-point operations in NEON use the IEEE single-precision format, NEON does not fully comply to the IEEE standard when inputs or results are denormal or NaN values for minimizing power consumption as well as maximizing performance.
Considering the balance between correctness and performance, `sse2neon` recognizes the following compile-time configurations:
* `SSE2NEON_PRECISE_MINMAX`: Enable precise implementation of `_mm_min_{ps,pd}` and `_mm_max_{ps,pd}`. If you need consistent results such as handling with NaN values, enable it.
* `SSE2NEON_PRECISE_DIV`: Enable precise implementation of `_mm_rcp_ps` and `_mm_div_ps` by additional Netwon-Raphson iteration for accuracy.
* `SSE2NEON_PRECISE_SQRT`: Enable precise implementation of `_mm_sqrt_ps` and `_mm_rsqrt_ps` by additional Netwon-Raphson iteration for accuracy.
* `SSE2NEON_PRECISE_DP`: Enable precise implementation of `_mm_dp_pd`. When the conditional bit is not set, the corresponding multiplication would not be executed.
* `SSE2NEON_SUPPRESS_WARNINGS`: Set this macro to disable the warning which is emitted by default when optimizations are enabled.

The above are turned off by default, and you should define the corresponding macro(s) as `1` before including `sse2neon.h` if you need the precise implementations.

## Run Built-in Test Suite

`sse2neon` provides a unified interface for developing test cases. These test
cases are located in `tests` directory, and the input data is specified at
runtime. Use the following commands to perform test cases:
```shell
$ make check
```

For running check with enabling features, you can use assign the features with `FEATURE` command.
If `none` is assigned, then the command will be the same as simply calling `make check`.
The following command enable `crypto` and `crc` features in the tests.
```
$ make FEATURE=crypto+crc check
```

For running check on certain CPU, setting the mode of FPU, etc.,
you can also assign the desired options with `ARCH_CFLAGS` command.
If `none` is assigned, the command acts as same as calling `make check`.
For instance, to run tests on Cortex-A53 with enabling ARM VFPv4 extension and NEON:
```
$ make ARCH_CFLAGS="-mcpu=cortex-a53 -mfpu=neon-vfpv4" check
```

### Running tests on hosts other than ARM platform

For running tests on hosts other than ARM platform,
you can specify GNU toolchain for cross compilation with `CROSS_COMPILE` command.
[QEMU](https://www.qemu.org/) should be installed in advance.

For ARMv8-A running in 64-bit mode type:
```shell
$ make CROSS_COMPILE=aarch64-linux-gnu- check # ARMv8-A
```

For ARMv7-A type:
```shell
$ make CROSS_COMPILE=arm-linux-gnueabihf- check # ARMv7-A
```

For ARMv8-A running in 32-bit mode (A32 instruction set) type:
```shell
$ make \
  CROSS_COMPILE=arm-linux-gnueabihf- \
  ARCH_CFLAGS="-mcpu=cortex-a32 -mfpu=neon-fp-armv8" \
  check 
```

Check the details via [Test Suite for SSE2NEON](tests/README.md).

### Optimization

The SSE2NEON project is designed with performance-sensitive scenarios in mind, and as such, optimization options (e.g. `O1`, `O2`) can lead to misbehavior under specific circumstances. For example, frequent changes to the rounding mode or repeated calls to `_MM_SET_DENORMALS_ZERO_MODE()` may introduce unintended behavior.

Enforcing no optimizations for specific intrinsics could solve these boundary cases but may negatively impact general performance. Therefore, we have decided to prioritize performance and shift the responsibility for handling such edge cases to developers.

It is important to be aware of these potential pitfalls when enabling optimizations and ensure that your code accounts for these scenarios if necessary.


## Adoptions
Here is a partial list of open source projects that have adopted `sse2neon` for Arm/Aarch64 support.
* [Aaru Data Preservation Suite](https://www.aaru.app/) is a fully-featured software package to preserve all storage media from the very old to the cutting edge, as well as to give detailed information about any supported image file (whether from Aaru or not) and to extract the files from those images.
* [aether-game-utils](https://github.com/johnhues/aether-game-utils) is a collection of cross platform utilities for quickly creating small game prototypes in C++.
* [ALE](https://github.com/sc932/ALE), aka Assembly Likelihood Evaluation, is a tool for evaluating accuracy of assemblies without the need of a reference genome.
* [AnchorWave](https://github.com/baoxingsong/AnchorWave), Anchored Wavefront Alignment, identifies collinear regions via conserved anchors (full-length CDS and full-length exon have been implemented currently) and breaks collinear regions into shorter fragments, i.e., anchor and inter-anchor intervals.
* [ATAK-CIV](https://github.com/deptofdefense/AndroidTacticalAssaultKit-CIV), Android Tactical Assault Kit for Civilian Use, is the official geospatial-temporal and situational awareness tool used by the US Government.
* [Apache Doris](https://doris.apache.org/) is a Massively Parallel Processing (MPP) based interactive SQL data warehousing for reporting and analysis.
* [Apache Impala](https://impala.apache.org/) is a lightning-fast, distributed SQL queries for petabytes of data stored in Apache Hadoop clusters.
* [Apache Kudu](https://kudu.apache.org/) completes Hadoop's storage layer to enable fast analytics on fast data.
* [apollo](https://github.com/ApolloAuto/apollo) is a high performance, flexible architecture which accelerates the development of Autonomous Vehicles.
* [ares](https://github.com/ares-emulator/ares) is a cross-platform, open source, multi-system emulator, focusing on accuracy and preservation.
* [ART](https://github.com/dinosaure/art) is an implementation in OCaml of [Adaptive Radix Tree](https://db.in.tum.de/~leis/papers/ART.pdf) (ART).
* [Async](https://github.com/romange/async) is a set of c++ primitives that allows efficient and rapid development in C++17 on GNU/Linux systems.
* [avec](https://github.com/unevens/avec) is a little library for using SIMD instructions on both x86 and Arm.
* [BEAGLE](https://github.com/beagle-dev/beagle-lib) is a high-performance library that can perform the core calculations at the heart of most Bayesian and Maximum Likelihood phylogenetics packages.
* [BitMagic](https://github.com/tlk00/BitMagic) implements compressed bit-vectors and containers (vectors) based on ideas of bit-slicing transform and Rank-Select compression, offering sets of method to architect your applications to use HPC techniques to save memory (thus be able to fit more data in one compute unit) and improve storage and traffic patterns when storing data vectors and models in files or object stores.
* [bipartite\_motif\_finder](https://github.com/soedinglab/bipartite_motif_finder) as known as BMF (Bipartite Motif Finder) is an open source tool for finding co-occurences of sequence motifs in genomic sequences.
* [Blender](https://www.blender.org/) is the free and open source 3D creation suite, supporting the entirety of the 3D pipeline.
* [Boo](https://github.com/AxioDL/boo) is a cross-platform windowing and event manager similar to SDL or SFML, with additional 3D rendering functionality.
* [Brickworks](https://github.com/sdangelo/brickworks) is a music DSP toolkit that supplies with the fundamental building blocks for creating and enhancing audio engines on any platform.
* [CARTA](https://github.com/CARTAvis/carta-backend) is a new visualization tool designed for viewing radio astronomy images in CASA, FITS, MIRIAD, and HDF5 formats (using the IDIA custom schema for HDF5).
* [Catcoon](https://github.com/i-evi/catcoon) is a [feedforward neural network](https://en.wikipedia.org/wiki/Feedforward_neural_network) implementation in C.
* [compute-runtime](https://github.com/intel/compute-runtime), the Intel Graphics Compute Runtime for oneAPI Level Zero and OpenCL Driver, provides compute API support (Level Zero, OpenCL) for Intel graphics hardware architectures (HD Graphics, Xe).
* [contour](https://github.com/contour-terminal/contour) is a modern and actually fast virtual terminal emulator.
* [Cog](https://github.com/losnoco/Cog) is a free and open source audio player for macOS.
* [dab-cmdline](https://github.com/JvanKatwijk/dab-cmdline) provides entries for the functionality to handle Digital audio broadcasting (DAB)/DAB+ through some simple calls.
* [DISTRHO](https://distrho.sourceforge.io/) is an open-source project for Cross-Platform Audio Plugins.
* [Dragonfly](https://github.com/dragonflydb/dragonfly) is a modern in-memory datastore, fully compatible with Redis and Memcached APIs.
* [EDGE](https://github.com/3dfxdev/EDGE) is an advanced OpenGL source port spawned from the DOOM engine, with focus on easy development and expansion for modders and end-users.
* [Embree](https://github.com/embree/embree) is a collection of high-performance ray tracing kernels. Its target users are graphics application engineers who want to improve the performance of their photo-realistic rendering application by leveraging Embree's performance-optimized ray tracing kernels.
* [emp-tool](https://github.com/emp-toolkit/emp-tool) aims to provide a benchmark for secure computation and allowing other researchers to experiment and extend.
* [Exudyn](https://github.com/jgerstmayr/EXUDYN) is a C++ based Python library for efficient simulation of flexible multibody dynamics systems.
* [FoundationDB](https://www.foundationdb.org) is a distributed database designed to handle large volumes of structured data across clusters of commodity servers.
* [fsrc](https://github.com/elsamuko/fsrc) is capable of searching large codebases for text snippets.
* [GDAL](https://gdal.org) is a translator library for raster and vector geospatial data formats that comes with a variety of useful command line utilities for data translation and processing.
* [gmmlib](https://github.com/intel/gmmlib) is the Intel Graphics Memory Management Library that provides device specific and buffer management for the Intel Graphics Compute Runtime for OpenCL and the Intel Media Driver for VAAPI.
* [HISE](https://github.com/christophhart/HISE) is a cross-platform open source audio application for building virtual instruments, emphasizing on sampling, but includes some basic synthesis features for making hybrid instruments as well as audio effects.
* [iqtree2](https://github.com/iqtree/iqtree2) is an efficient and versatile stochastic implementation to infer phylogenetic trees by maximum likelihood.
* [indelPost](https://github.com/stjude/indelPost) is a Python library for indel processing via realignment and read-based phasing to resolve alignment ambiguities.
* [IResearch](https://github.com/iresearch-toolkit/iresearch) is a cross-platform, high-performance document oriented search engine library written entirely in C++ with the focus on a pluggability of different ranking/similarity models.
* [Kraken](https://github.com/Wabi-Studios/Kraken) is a 3D animation platform redefining animation composition, collaborative workflows, simulation engines, skeletal rigging systems, and look development from storyboard to final render.
* [kram](https://github.com/alecazam/kram) is a wrapper to several popular encoders to and from PNG/[KTX](https://www.khronos.org/opengles/sdk/tools/KTX/file_format_spec/) files with [LDR/HDR and BC/ASTC/ETC2](https://developer.arm.com/solutions/graphics-and-gaming/developer-guides/learn-the-basics/adaptive-scalable-texture-compression/single-page).
* [Krita](https://invent.kde.org/graphics/krita) is a cross-platform application that offers an end-to-end solution for creating digital art files from scratch built on the KDE and Qt frameworks.
* [libCML](https://github.com/belosthomas/libCML) is a SLAM library and scientific tool, which include a novel fast thread-safe graph map implementation.
* [libhdfs3](https://github.com/ClickHouse/libhdfs3) is implemented based on native Hadoop RPC protocol and Hadoop Distributed File System (HDFS), a highly fault-tolerant distributed fs, data transfer protocol.
* [libpostal](https://github.com/openvenues/libpostal) is a C library for parsing/normalizing street addresses around the world using statistical NLP and open data.
* [libscapi](https://github.com/cryptobiu/libscapi) stands for the "Secure Computation API", providing  reliable, efficient, and highly flexible cryptographic infrastructure.
* [libstreamvbyte](https://github.com/wst24365888/libstreamvbyte) is a C++ implementation of [StreamVByte](https://arxiv.org/abs/1709.08990).
* [libmatoya](https://github.com/matoya/libmatoya) is a cross-platform application development library, providing various features such as common cryptography tasks.
* [Loosejaw](https://github.com/TheHolyDiver/Loosejaw) provides deep hybrid CPU/GPU digital signal processing.
* [Madronalib](https://github.com/madronalabs/madronalib) enables efficient audio DSP on SIMD processors with readable and brief C++ code.
* [minimap2](https://github.com/lh3/minimap2) is a versatile sequence alignment program that aligns DNA or mRNA sequences against a large reference database.
* [mixed-fem](https://github.com/tytrusty/mixed-fem) is an open source reference implementation of Mixed Variational Finite Elements for Implicit Simulation of Deformables.
* [MMseqs2](https://github.com/soedinglab/MMseqs2) (Many-against-Many sequence searching) is a software suite to search and cluster huge protein and nucleotide sequence sets.
* [MRIcroGL](https://github.com/rordenlab/MRIcroGL) is a cross-platform tool for viewing NIfTI, DICOM, MGH, MHD, NRRD, AFNI format medical images.
* [N2](https://github.com/oddconcepts/n2o) is an approximate nearest neighborhoods algorithm library written in C++, providing a much faster search speed than other implementations when modeling large dataset.
* [nanors](https://github.com/sleepybishop/nanors) is a tiny, performant implementation of [Reed-Solomon codes](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction), capable of reaching multi-gigabit speeds on a single core.
* [niimath](https://github.com/rordenlab/niimath) is a general image calculator with superior performance.
* [NVIDIA GameWorks](https://developer.nvidia.com/gameworks-source-github) has been already used in a lot of games. These repositories are public on GitHub.
* [Nx Meta Platform Open Source Components](https://github.com/networkoptix/nx_open) are used to build all Powered-by-Nx products including Nx Witness Video Management System (VMS).
* [ofxNDI](https://github.com/leadedge/ofxNDI) is an [openFrameworks](https://openframeworks.cc/) addon to allow sending and receiving images over a network using the [NewTek](https://en.wikipedia.org/wiki/NewTek) Network Device Protocol.
* [OGRE](https://github.com/OGRECave/ogre) is a scene-oriented, flexible 3D engine written in C++ designed to make it easier and more intuitive for developers to produce games and demos utilising 3D hardware.
* [Olive](https://github.com/olive-editor/olive) is a free non-linear video editor for Windows, macOS, and Linux.
* [OpenColorIO](https://github.com/AcademySoftwareFoundation/OpenColorIO) a complete color management solution geared towards motion picture production with an emphasis on visual effects and computer animation.
* [OpenXRay](https://github.com/OpenXRay/xray-16) is an improved version of the X-Ray engine, used in world famous S.T.A.L.K.E.R. game series by GSC Game World.
* [parallel-n64](https://github.com/libretro/parallel-n64) is an optimized/rewritten Nintendo 64 emulator made specifically for [Libretro](https://www.libretro.com/).
* [Pathfinder C++](https://github.com/floppyhammer/pathfinder-cpp) is a fast, practical, GPU-based rasterizer for fonts and vector graphics using Vulkan and C++.
* [PFFFT](https://github.com/marton78/pffft) does 1D Fast Fourier Transforms, of single precision real and complex vectors.
* [pixaccess](https://github.com/oliverue/pixaccess) provides the abstractions for integer and float bitmaps, pixels, and aliased (nearest neighbor) and anti-aliased (bi-linearly interpolated) pixel access.
* [PlutoSDR Firmware](https://github.com/seanstone/plutosdr-fw) is the customized firmware for the [PlutoSDR](https://wiki.analog.com/university/tools/pluto) that can be used to introduce fundamentals of Software Defined Radio (SDR) or Radio Frequency (RF) or Communications as advanced topics in electrical engineering in a self or instructor lead setting.
* [PowerToys](https://github.com/microsoft/PowerToys) is a set of utilities for power users to tune and streamline their Windows experience for greater productivity.
* [Pygame](https://www.pygame.org) is cross-platform and designed to make it easy to write multimedia software, such as games, in Python.
* [R:RandomFieldsUtils](https://cran.r-project.org/web/packages/RandomFieldsUtils) provides various utilities might be used in spatial statistics and elsewhere. (CRAN)
* [RAxML](https://github.com/stamatak/standard-RAxML) is tool for Phylogenetic Analysis and Post-Analysis of Large Phylogenies.
* [ReHLDS](https://github.com/gennadykataev/rehlds) is fully compatible with latest Half-Life Dedicated Server (HLDS) with a lot of defects and (potential) bugs fixed.
* [rkcommon](https://github.com/ospray/rkcommon) represents a common set of C++ infrastructure and CMake utilities used by various components of [Intel oneAPI Rendering Toolkit](https://www.intel.com/content/www/us/en/developer/tools/oneapi/rendering-toolkit.html).
* [RPCS3](https://github.com/RPCS3/rpcs3) is the world's first free and open-source PlayStation 3 emulator/debugger, written in C++.
* [simd\_utils](https://github.com/JishinMaster/simd_utils) is a header-only library implementing common mathematical functions using SIMD intrinsics.
* [Sire](https://github.com/OpenBioSim/sire) is a molecular modelling framework that provides extensive functionality to manipulate representations of biomolecular systems.
* [SMhasher](https://github.com/rurban/smhasher) provides comprehensive Hash function quality and speed tests.
* [SNN++](https://github.com/ianmkim/snnpp) implements a single layer non linear Spiking Neural Network for images classification and generation.
* [Spack](https://github.com/spack/spack) is a multi-platform package manager that builds and installs multiple versions and configurations of software.
* [SRA](https://github.com/ncbi/sra-tools) is a collection of tools and libraries for using data in the [INSDC Sequence Read Archives](https://www.ncbi.nlm.nih.gov/sra/docs/).
* [srsLTE](https://github.com/srsLTE/srsLTE) is an open source SDR LTE software suite.
* [SSW](https://github.com/mengyao/Complete-Striped-Smith-Waterman-Library) is a fast implementation of the [Smith-Waterman algorithm](https://en.wikipedia.org/wiki/Smith%E2%80%93Waterman_algorithm), which uses the SIMD instructions to parallelize the algorithm at the instruction level.
* [Surge](https://github.com/surge-synthesizer/surge) is an open source digital synthesizer.
* [The Forge](https://github.com/ConfettiFX/The-Forge) is a cross-platform rendering framework, providing building blocks to write your own game engine.
* [Typesense](https://github.com/typesense/typesense) is a fast, typo-tolerant search engine for building delightful search experiences.
* [Vcpkg](https://github.com/microsoft/vcpkg) is a C++ Library Manager for Windows, Linux, and macOS.
* [VelocyPack](https://github.com/arangodb/velocypack) is a fast and compact format for serialization and storage.
* [VOLK](https://github.com/gnuradio/volk), Vector-Optimized Library of Kernel, is a sub-project of [GNU Radio](https://www.gnuradio.org/).
* [Vowpal Wabbit](https://github.com/VowpalWabbit/vowpal_wabbit) is a machine learning system which pushes the frontier of machine learning with techniques such as online, hashing, allreduce, reductions, learning2search, active, and interactive learning.
* [Winter](https://github.com/rosenthj/Winter) is the top rated chess engine from Switzerland and has competed at top invite only computer chess events.
* [XEVE](https://github.com/mpeg5/xeve) (eXtra-fast Essential Video Encoder) is an open sourced and fast MPEG-5 EVC encoder.
* [XMRig](https://github.com/xmrig/xmrig) is an open source CPU miner for [Monero](https://web.getmonero.org/) cryptocurrency.
* [xsimd](https://github.com/xtensor-stack/xsimd) provides a unified means for using SIMD intrinsics and parallelized, optimized mathematical functions.
* [YACL](https://github.com/secretflow/yasl) is a C++ library contains modules and utilities which [SecretFlow](https://github.com/secretflow) code depends on.

## Related Projects
* [SIMDe](https://github.com/simd-everywhere/simde): fast and portable implementations of SIMD
  intrinsics on hardware which doesn't natively support them, such as calling SSE functions on ARM.
* [CatBoost's sse2neon](https://github.com/catboost/catboost/blob/master/library/cpp/sse/sse2neon.h)
* [ARM\_NEON\_2\_x86\_SSE](https://github.com/intel/ARM_NEON_2_x86_SSE)
* [AvxToNeon](https://github.com/kunpengcompute/AvxToNeon)
* [sse2rvv](https://github.com/FeddrickAquino/sse2rvv): C header file that converts Intel SSE intrinsics to RISC-V Vector intrinsic.
* [sse2msa](https://github.com/i-evi/sse2msa): A C/C++ header file that converts Intel SSE intrinsics to MIPS/MIPS64 MSA intrinsics.
* [sse2zig](https://github.com/aqrit/sse2zig): Intel SSE intrinsics mapped to [Zig](https://ziglang.org/) vector extensions.
* [POWER/PowerPC support for GCC](https://github.com/gcc-mirror/gcc/blob/master/gcc/config/rs6000) contains a series of headers simplifying porting x86\_64 code that makes explicit use of Intel intrinsics to powerpc64le (pure little-endian mode that has been introduced with the [POWER8](https://en.wikipedia.org/wiki/POWER8)).
    - implementation: [xmmintrin.h](https://github.com/gcc-mirror/gcc/blob/master/gcc/config/rs6000/xmmintrin.h), [emmintrin.h](https://github.com/gcc-mirror/gcc/blob/master/gcc/config/rs6000/emmintrin.h), [pmmintrin.h](https://github.com/gcc-mirror/gcc/blob/master/gcc/config/rs6000/pmmintrin.h), [tmmintrin.h](https://github.com/gcc-mirror/gcc/blob/master/gcc/config/rs6000/tmmintrin.h), [smmintrin.h](https://github.com/gcc-mirror/gcc/blob/master/gcc/config/rs6000/smmintrin.h)

## Reference
* [Intel Intrinsics Guide](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html)
* [Microsoft: x86 intrinsics list](https://learn.microsoft.com/en-us/cpp/intrinsics/x86-intrinsics-list)
* [Arm Neon Intrinsics Reference](https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/intrinsics)
* [Neon Programmer's Guide for Armv8-A](https://developer.arm.com/architectures/instruction-sets/simd-isas/neon/neon-programmers-guide-for-armv8-a)
* [NEON Programmer's Guide](https://static.docs.arm.com/den0018/a/DEN0018A_neon_programmers_guide_en.pdf)
* [qemu/target/i386/ops\_sse.h](https://github.com/qemu/qemu/blob/master/target/i386/ops_sse.h): Comprehensive SSE instruction emulation in C. Ideal for semantic checks.
* [Porting Takua Renderer to 64-bit ARM- Part 1](https://blog.yiningkarlli.com/2021/05/porting-takua-to-arm-pt1.html)
* [Porting Takua Renderer to 64-bit ARM- Part 2](https://blog.yiningkarlli.com/2021/07/porting-takua-to-arm-pt2.html)
* [Comparing SIMD on x86-64 and arm64](https://blog.yiningkarlli.com/2021/09/neon-vs-sse.html)
* [Port with SSE2Neon and SIMDe](https://developer.arm.com/documentation/102581/0200/Port-with-SSE2Neon-and-SIMDe)
* [Genomics: Optimizing the BWA aligner for Arm Servers](https://community.arm.com/arm-community-blogs/b/high-performance-computing-blog/posts/optimizing-genomics-and-the-bwa-aligner-for-arm-servers)
* [Bit twiddling with Arm Neon: beating SSE movemasks, counting bits and more](https://community.arm.com/arm-community-blogs/b/infrastructure-solutions-blog/posts/porting-x86-vector-bitmask-optimizations-to-arm-neon)
* [C/C++ on Graviton](https://github.com/aws/aws-graviton-getting-started/blob/main/c-c%2B%2B.md)
* [C/C++ on NVIDIA Grace](https://nvidia.github.io/grace-cpu-benchmarking-guide/developer/languages/c-c++.html)
* [Tune graphics-intensive games for Apple silicon](https://developer.apple.com/games/pathway/)
* [Benchmarking and Testing of Qualcomm Snapdragon System-on-Chip for JPL Space Applications and Missions](https://ieeexplore.ieee.org/abstract/document/9843518)
* [Spotlight: Petrobras Speeds Up Linear Solvers for Reservoir Simulation Using NVIDIA Grace CPU](https://developer.nvidia.com/blog/spotlight-petrobras-accelerates-linear-solvers-for-reservoir-simulation-using-nvidia-grace-cpu/)

## Licensing

`sse2neon` is freely redistributable under the MIT License.

# AddressSanitizer tooling for hashcat's host C

`tools/compute_sanitizer/` checks the CUDA kernels. This checks everything else:
the hash-line parsers, the core string/convert helpers, and hashcat's own
allocation handling under a real workload.

That split matters because the two halves fail differently. Compute Sanitizer
answers "did a kernel leave its allocation" — and on this codebase it answers
"no" very consistently. The host side is where hand-written C meets fully
attacker-controlled input: a hash file from an untrusted source is parsed with
pointer arithmetic, hex decoding and fixed-size buffers.

## Prerequisite: `make DEBUG=2` must link

`-fsanitize=address` is added to `CFLAGS` only, never to the link flags, so
every target that pulls in `deps/unrar` fails with undefined `__asan_*`
references. One line in `src/Makefile`'s `DEBUG=2` block fixes it:

```make
LFLAGS                  += -fsanitize=address
```

Without that, nothing here can be built.

## Two entry points

### 1. Parser sweep (no GPU)

The high-yield one. Runs every module's `module_hash_decode()` on its own
example hash plus a family of mutations — every truncation, a length that lies
about the buffer, separator storms, an oversized trailing field.

```
make DEBUG=2 -j$(nproc)
tools/asan/build.sh
tools/asan/sweep.sh
```

~25 minutes for all 594 modules. Findings land in `asan-sweep/findings/m<mode>/`
with the full ASan report; `asan-sweep/sweep.log` is the summary.

No GPU, no backend, no CUDA driver involved.

### 2. End-to-end sweep (real GPU)

Runs `tools/test.sh` against an ASan-instrumented hashcat, one hash type at a
time. The real kernels execute on the GPU, unchecked; hashcat's host C is
checked around them.

```
make DEBUG=2 -j$(nproc)
tools/asan/gpu_sweep.sh              # or --from 6050 to resume
```

Slow — budget a few minutes per hash type.

### 3. Single-mode reproduction

For a known bug, or when you want a small self-contained binary:

```
tools/asan/repro.sh 32100 --hash '$krb5asrep$17$'
TOOL=msan tools/asan/repro.sh 32100 --hash '$krb5asrep$17$'
```

This compiles the module directly into the harness, so it needs only a
`make DEBUG=1` core. See the caveat under "Instrument the whole tree" below.

## Checking that a binary really is ASan-instrumented

Worth doing before trusting a "clean" result — a harness built against an
uninstrumented core reports real bugs as `rc=0`.

```
ldd ./hashcat | grep -i asan       # libasan.so.6 => ... when shared-linked
nm -D ./libhashcat.so.7 | grep -c asan
nm -a ./your_harness | grep -o '__asan_[a-z_]*' | sort -u | head
```

Check all three of `hashcat`, `libhashcat.so.7` and `modules/module_*.so` —
they are separate link steps and can disagree, which is the whole reason the
`DEBUG=2` link bug mattered.

`ldd` is the quickest test but not sufficient on its own: a toolchain that
statically links the ASan runtime shows nothing there while still being fully
instrumented. `nm` catches both cases; `strings -a <bin> | grep -q
AddressSanitizer` works even on a stripped binary.

To tell ASan from MSan, look at the symbol prefix — `__asan_*` vs `__msan_*`.

Runtime check, if you would rather ask the binary than the ELF:

```
ASAN_OPTIONS=protect_shadow_gap=0:verbosity=1 ./hashcat --version
```

An instrumented build prints ASan runtime chatter (interceptor and shadow-setup
lines) before hashcat's own output. A plain build prints only the version.

Example of what disagreement looks like:

```
                          ldd   nm
DEBUG=2 hashcat           yes   yes      <- instrumented
DEBUG=1 hashcat           no    no       <- not
```

## Things that will waste your time if you don't know them

### `protect_shadow_gap=0` is mandatory for the GPU path

ASan maps its shadow gap `PROT_NONE`; CUDA's unified virtual addressing needs
that range. Without it `cuInit()` fails with `out of memory` and hashcat
reports:

```
ATTENTION! No OpenCL, HIP or CUDA compatible platform found.
```

which looks exactly like a missing driver and is not. `gpu_sweep.sh` sets it.

On WSL you may also see three `double-free` reports inside `libcuda.so.1.1`
during adapter enumeration. Those are driver-internal, not hashcat's, and they
disappear once the shadow gap is unprotected.

### Instrument the whole tree, not just the module

`build.sh` links the ASan-built `libhashcat.so.7` and `dlopen`s the ASan-built
plugins, so core *and* modules are checked.

This is not a nicety. Several real bugs have their bad access inside a core
helper rather than in the module that calls it — an out-of-bounds read in
`hex_to_u32()` (`src/convert.c`), a `memcpy` overread in
`generic_salt_decode()` (`src/parser.c`), a `stack-use-after-scope` that
surfaces inside `hc_strchr_next()` from a pointer a module handed it. A harness
linked against an uninstrumented core reports every one of those runs as
**clean, `rc=0`**.

`repro.sh` deliberately does the narrow thing instead, because MSan cannot
share a process with an ASan-built plugin. Pass `EXTRA="src/convert.c"` to widen
it. Use `build.sh` + `sweep.sh` when looking for *unknown* bugs.

### The harness and the libhashcat it *loads* must agree

If you see this, every run dies before reaching any hashcat code:

```
Your application is linked against incompatible ASan runtimes.
```

The usual cause is not the compiler. It is that the `libhashcat.so.7` resolved
at **run** time is not the one linked at **build** time — typically an
ASan-instrumented copy getting pulled into a harness built against a plain
`DEBUG=1` core, or the reverse. ASan cannot have its runtime initialised twice
that way.

Both scripts pin the loader to the core they linked against
(`LD_LIBRARY_PATH` / `-Wl,-rpath`) for exactly this reason. If you build by
hand, do the same, and check with `ldd ./your_harness | grep hashcat`.

(Compiler choice is *not* the issue on a stock Ubuntu toolchain: gcc and
clang there both link the same shared `libasan.so.6`, so they interoperate
fine. `build.sh` defaults to gcc only to match how the tree itself was built;
`CC=clang` works. A clang that statically links its own ASan runtime — some
non-distro builds do — would genuinely conflict with a gcc-built core, so
verify with `ldd` rather than assuming either way.)

### `halt_on_error=0`

Both sweeps set it. Without it ASan stops at the first report, and a module
with two distinct defects hides the second behind the first — which is exactly
what happens in at least one module, where the less serious heap overread masks
a `stack-use-after-scope`.

### The harness copies `--hash` into an exact-size allocation

Deliberate and load-bearing. Passing the `argv` pointer straight through would
put any overread inside the environment block, where neither ASan nor Valgrind
can bound-check it, and buggy code would look clean.

## ASan vs Valgrind vs MSan

The same harness runs under Valgrind with no special build — drop
`-fsanitize=address`, build against a `DEBUG=1` tree, and run it under
`valgrind`. That is worth knowing, but ASan is the better default here:

- **ASan** catches heap and stack overflows and `stack-use-after-scope`, with
  the exact offending line and the allocation the access belongs to. Fast
  enough to sweep all 594 modules in ~25 minutes.
- **Valgrind** needs no rebuild and instruments everything including the
  system libraries, which is genuinely useful when you suspect the build. But
  it is 20–50x slower — slow enough that a dozen expensive parsers time out —
  and it **cannot detect `stack-use-after-scope` at all**: the memory is still
  valid stack, and memcheck has no notion of a C block's lifetime.
- **MSan** answers a different question — *uses of uninitialized values*, not
  out-of-bounds accesses. For a bug where bytes are read past a buffer and then
  compared, MSan is silent by design, and where it does fire it tends to be a
  bare `SIGSEGV` whose appearance depends on heap layout. Supported via
  `TOOL=msan` for comparison; not the tool to reach for first.

## Interpreting a finding

The harness feeds truncated and corrupted input directly to
`module_hash_decode()`. Some modes are declared `OPTS_TYPE_BINARY_HASHFILE`,
where the production caller reads whole fixed-size records with `fread` and a
short read yields zero — those parsers are entitled to assume a full record,
and a truncation-driven report against them is a harness artifact, not a bug.
Check the mode's `opts_type` before filing anything.

Everything else — a parser reached with a short or malformed *line* — is real:
that is precisely the input a hash file provides.

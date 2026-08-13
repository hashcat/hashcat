# tools/compute_sanitizer/ — NVIDIA Compute Sanitizer testing for hashcat

Runs hashcat's real CUDA kernels on real GPU hardware under NVIDIA's own
Compute Sanitizer, triaging every finding down to a **hashcat/OpenCL source
location** (`OpenCL/m17010-pure.cl:527` in `m17010_loop()`), instead of
leaving you to read a raw `compute-sanitizer` log by hand.

This is the CUDA-kernel counterpart to `DEBUG=2` (hashcat's own ASan mode,
host-side C only) and replaces an earlier PoCL+Valgrind approach that
emulated GPU kernels on the CPU under full Valgrind instrumentation — real
hardware is both faster and catches exactly the class of bug (GPU kernel
memory-safety) that emulation was only approximating. This tool is
**CUDA-only** by design; it does not touch OpenCL/HIP/Metal kernels.

## Why `--generate-line-info`, not `-G`

hashcat's default release build passes no debug flags to NVRTC — a
Compute Sanitizer finding resolves only to a raw kernel name and instruction
offset. A `DEBUG=1` build adds `--generate-line-info` to the CUDA/NVRTC
compile options (`src/backend.c`, `load_kernel()`'s CUDA branch), which
keeps kernels **optimized** but embeds line-table debug info, so a finding
resolves to `<file>:<line>`. This is deliberately not `-G` (full
device-debug), which disables kernel optimization entirely and would change
the very memory-access patterns you're trying to test.

`DEBUG=1` builds also pass NVRTC the real `.cl` source filename as the
compiled program's name (instead of the generic `main_kernel`/
`shared_kernel`/`mp_kernel`/`amp_kernel` literal used in release builds) —
NVRTC compiles from an in-memory string, so unlike a real `nvcc` compile of
an on-disk `.cu` file, there's no filesystem path for the line-info table to
reference unless the program is explicitly named. Confirmed via a real
throwaway kernel during development: without this, Compute Sanitizer reports
`main_kernel:527`; with it, `m17010-pure.cl:527`.

No kernel-cache-key changes were needed: hashcat's kernel cache is keyed in
part on `COMPTIME` (`src/Makefile:233`, a fresh Unix timestamp baked in at
every link), which is already the first field hashed into both cache-key
formulas in `src/backend.c` — so a `make clean && make DEBUG=1` rebuild
naturally invalidates any previously-cached kernel binary, DEBUG or not.

## `run.py build`

```
tools/compute_sanitizer/run.py build
```

`make clean && make DEBUG=1 -j$(nproc)`, then copies `./hashcat` to a
stable, explicitly-named `./hashcat-sanitizer` sibling (same directory as
`modules/*.so`, resolved via hashcat's own binary-relative module lookup —
no separate module tree needed). Runs a hard sanity check
(`./hashcat-sanitizer --version`) before declaring success.

**Note**: `DEBUG=1` rebuilds `./hashcat` itself and every `modules/*.so` too
(one `obj/` tree, unavoidable). Restore the release build afterward with:

```
make clean && make -j$(nproc)
```

## `run.py check`

```
tools/compute_sanitizer/run.py check
```

Reports a found/missing table: `compute-sanitizer`, `nvcc`, hashcat debug
info, and a visible CUDA device (parsed from `hashcat-sanitizer -I`'s "CUDA
Info:" section — confirmed this environment reports it as a `Backend Device
ID` entry).

## `run.py exec` — run one command

```
tools/compute_sanitizer/run.py exec <test-name> [--tool memcheck|racecheck|synccheck|initcheck] [--leak-check no|full] [--padding N] -- <hashcat-command...>
```

- Everything after `--` is the exact hashcat command, passed through as a
  real argument list (never `eval`'d).
- Forces CUDA-only device selection (`--backend-ignore-opencl
  --backend-ignore-hip[--backend-ignore-metal on macOS]`) so a run never
  silently falls back to PoCL or another backend where Compute Sanitizer
  can't see anything. Fails clearly if no CUDA device is visible.
- Before touching the sanitizer at all, runs the same build-sanity check as
  `run.py build`, and warns (but does not block) if the binary has no debug
  info — a release-build repro run is still legitimate, it just won't
  resolve to source lines.
- Invokes `compute-sanitizer --tool <tool> --check-exit-code no --leak-check
  <no|full> --show-backtrace device --print-limit 20 --log-file ...`.
  **Never `--error-exitcode`**: hashcat's own exit code and the sanitizer's
  verdict are tracked completely separately (same principle as the earlier
  Valgrind tool, now re-confirmed empirically here — `--check-exit-code no`
  plus no `--error-exitcode` means the sanitizer's own process exit code
  reflects nothing about what it found, so hashcat's real `$?` is what gets
  captured, and the sanitizer verdict comes purely from parsing the log).
- Every run gets its own timestamped
  `tools/compute_sanitizer/results/<timestamp>-<test-name>/` directory
  (never overwritten) with `command.txt`, `environment.txt`,
  `sanitizer.log`, `summary.txt`, `summary.json`.
- `--padding N` (default **128**) passes Compute Sanitizer's own `--padding`:
  N bytes of tracked redzone appended after every device allocation. Without
  it, a read/write that overshoots one buffer but happens to land inside
  whatever real allocation the CUDA allocator placed next door goes
  undetected — not because nothing is wrong, but because memcheck only
  flags accesses outside *every* allocation, and an adjacent live buffer
  still counts as "inside an allocation." `--padding` closes exactly that
  gap: an overshoot into the redzone is flagged even when the real neighbor
  would otherwise have absorbed it silently. Pass `--padding 0` to fall back
  to Compute Sanitizer's own default (no redzone) if you need to compare.

### A real memory fault cascades

A genuine kernel memory-safety fault poisons the CUDA context: every
subsequent CUDA API call in the same process (`cudaDeviceSynchronize`,
`cudaFree`, ...) reports its own `Program hit cudaErrorLaunchFailure ...`
block. These are real Compute Sanitizer errors but are *consequences* of the
first fault, not independent findings. `triage.py` classifies the first
non-`CudaAPIError` finding (or, if there genuinely isn't one, the first
`CudaAPIError`) as `primary`, and any `CudaAPIError` blocks that follow a
real primary fault as `secondary` — kept in the JSON for context, excluded
from the primary PASS/FAIL count and from the terminal summary's main
listing (a one-line note reports how many were omitted).

## `run.py selftest` — the ground-truth baseline

```
tools/compute_sanitizer/run.py selftest
```

Three small, permanent, one-bug-each `.cu` fixtures under `modules/`
(built via `nvcc -lineinfo`, same flag `run.py build` uses for hashcat
itself), each checked against an exact expected finding kind in
`modules/expected.json`:

- `oob_write.cu` — `InvalidGlobalWrite` (`memcheck`)
- `oob_read.cu` — `InvalidGlobalRead` (`memcheck`)
- `uninit_global.cu` — `UninitializedDeviceMemory` (`initcheck`)

All three were run against a real GPU during development and verified to
produce exactly the expected finding, including the `initcheck`-specific log
shape (`Address 0x...` instead of `memcheck`'s `Access at ... is out of
bounds` / `and is N bytes after the nearest allocation ...` pair) and the
`--print-limit`-truncation follow-up line (`N errors were not printed. Use
--print-limit ...`), which `triage.py` recognizes and discards rather than
treating as a spurious extra finding.

Run this after touching `triage.py`'s parsing/classification logic, or any
time you want to confirm the tool itself is still correct before trusting it
against real hashcat+GPU output.

## `report.py` — aggregate past runs

```
tools/compute_sanitizer/report.py                    # all runs in tools/compute_sanitizer/results/
tools/compute_sanitizer/report.py --test <name>       # filter by test name
tools/compute_sanitizer/report.py --failed             # only runs with primary findings or a wrapper failure
tools/compute_sanitizer/report.py --latest 5             # last 5, after other filters
tools/compute_sanitizer/report.py --dir <sweep-dir>        # a test.sh/test_edge.sh sweep's own results directory
```

Prints a `RUN / HC_RC / SANITIZER / PRIMARY_ERR / FIRST LOCATION` table. A
missing or malformed `summary.json` shows up as a flagged row (`?` /
`<malformed>`) rather than crashing the whole listing.

## Running from `tools/test.sh` / `tools/test_edge.sh`

```
tools/test_edge.sh -m 17010 -a 3 -V 1 --compute-sanitizer
tools/test_edge.sh -m 17010 --compute-sanitizer=initcheck
tools/test.sh --compute-sanitizer
```

Requires `tools/compute_sanitizer/run.py build` to have been run first (both
scripts check for `./hashcat-sanitizer` and exit with a clear error if it's
missing). Each hashcat invocation is transparently routed through
`tools/compute_sanitizer/sweep_shim.sh`, which wraps it in `run.py exec
--sweep`: hashcat's own stdout/stderr/exit code pass through completely
untouched, so the scripts' existing pass/fail parsing is unaffected —
Compute Sanitizer's own findings are written to a
`tools/compute_sanitizer/results/sweep-<timestamp>/` directory instead,
printed as a pointer at the end of the run.

**Performance, measured**: the same GPG mode 17010 example hash that took
18+ minutes under the earlier PoCL+Valgrind fast tier ran in **~13 seconds**
end to end here (`run.py exec` wall-clock, real GPU, `memcheck`, one
candidate) — roughly 80x faster, running on real hardware instead of
emulating a GPU kernel on the CPU under Valgrind instrumentation. Ordinary
kernel compiles (`ptxas`) were tens to hundreds of ms each, not minutes, and
a full MD5 crack completed in under a second end to end. Use the existing
scoping flags (`-m`/`-a`/`-V`) to bound a run when sweeping many modes —
Compute Sanitizer's own overhead is still real (it instruments every device
memory access), just nowhere near what CPU emulation cost.

## Layout

```
tools/compute_sanitizer/
├── run.py          # CLI: build / check / exec / selftest
├── triage.py         # compute-sanitizer log parsing, classification, JSON schema
├── report.py           # aggregates past runs into a table
├── sweep_shim.sh          # BIN indirection target for test.sh/test_edge.sh --compute-sanitizer
├── modules/                 # ground-truth self-test fixtures (see `run.py selftest` above)
└── results/                   # gitignored; one directory per run, never overwritten
```

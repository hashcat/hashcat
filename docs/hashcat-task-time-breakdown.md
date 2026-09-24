# Task time breakdown

`--task-time-breakdown` prints where a run's wall clock went, once the run is over. It is off by default and does not alter the run itself.

It answers one question: when a run takes longer than expected and cracking is not responsible, where was the time spent?

```
hashcat -m 0 -a 0 --task-time-breakdown hashes.txt wordlist.txt
```

The report is suppressed by `--quiet`, `--machine-readable`, `--keyspace`, `--stdout`, `--show`, `--left`, `--identify`, `--help`, `--hash-info` and `--backend-info`, so no existing script output changes.

## How to read it

The report is hierarchical. An indented line belongs to the line above it, and every percentage is relative to the measured total rather than to the parent. An indented value therefore cannot exceed its parent.

Every section ends with an `Other` line for time not accounted for by its detailed entries. The line is printed even when it is zero because unclassified time is important. If `Other` dominates a section, the available instrumentation cannot identify where most of that time was spent.

A line for a stage that never ran is not printed at all. A run with `-m` given prints no autodetection line, and a run with no rules prints no rule loading line.

## The three top-level sections

Section `BEFORE ATTACK` covers everything up to the first candidate being tried. On a short run this is usually most of the clock.

Section `ATTACK` covers the cracking itself, from the first candidate to the last.

Section `AFTER ATTACK` covers shutdown, including stopping monitors, flushing output and releasing devices.

## What the individual lines mean

**Program and options setup.** Parsing the command line and finding the install and session folders. This is microseconds. If it is not, something is wrong with the filesystem underneath.

**Session initialization.** Loading the backend runtimes and enumerating devices. Its detail lines split that into bridges and plugins, the runtime libraries themselves, and per device setup. A slow runtime load usually means a driver installation problem. Slow device setup on a system with many GPUs is normal and scales roughly with the device count.

**Attack preparation.** Everything between having devices and being able to try a candidate. This is where a slow startup almost always lives, and its detail lines are the useful part of the report.

**Read and parse hash input.** Reading the hash file and turning each line into a digest. Scales with the hash count. Its `Count hash input lines` child is a separate pass used to size the allocation, so a very large hash list shows the two costs separately.

**Sort hashes**, **Sort salts** and **Remove duplicate hashes.** Scale with the hash count. On tens of millions of hashes these become visible.

**Check potfile.** Matches potfile entries against the loaded hashes and scales with both counts. This line identifies the cost of checking an already large potfile.

**Prepare wordlists, masks and rules.** Setting up the candidate source. Its `Load and validate rules` child is the one to watch: a large rule file is compiled once here, and a few million rules is seconds.

**Build hash lookup bitmaps.** Sizing and filling the filter tables. Grows with the hash count.

**Allocate attack and device session.** Loads kernels onto the devices and allocates their buffers. On a cold start, kernel compilation accounts for almost all of this stage and is therefore shown separately:

  - **Compile kernels, cached afterwards.** Compiles kernels for the selected device and options, then writes them to the `kernels` folder. This is usually the largest startup cost of the first run and can take several seconds.

    A later run with the same mode, device and options loads the cached binary. This line then disappears and the parent stage usually falls to milliseconds. If compilation occurs on every run, either the cache folder does not persist or an input to the cache key has changed.

    The cache key includes the hash mode, attack mode, `-O` setting, device, driver and module-specific build options. General workload settings such as `-w`, kernel loops and kernel acceleration do not force a rebuild. Mode 1500 is the exception: it builds a kernel around the salt and therefore compiles on every run.
  - **Other device session setup.** Allocates buffers and prepares kernel arguments. Its cost grows with the hash and device counts.

**Kernel self-test** and **Kernel autotune.** Verifying the kernel produces a known answer, then measuring the best workload size. Both are small on fast hashes. On a very slow hash mode the autotune has to run real work to measure it, so seconds there are expected. Option `--force` does not skip autotune. Fixing all three values with `-T`, `-n` and `-u` skips the search, but the warm-up launches still run unless the module disables them.

## What is not measured yet

The outfile check runs in its own thread rather than as a startup step, so time spent reading `--outfile-check-dir` does not have its own line. It lands in `Other attack preparation`.

A run that fails during startup still prints a report. The failed stage can show inflated time because hashcat closes any unfinished measurement at the end. Interpret the timing of a failed run accordingly.

## An example

A first run on an empty kernel cache:

```
BEFORE ATTACK                               2.460 s   71.09%
  Session initialization                      0.076 s    2.19%
  Attack preparation                          2.384 s   68.89%
    Allocate attack and device session          2.341 s   67.52%
      Compile kernels, cached afterwards          2.334 s   67.29%
      Other device session setup                  0.008 s    0.23%
ATTACK                                      0.229 s    6.62%
AFTER ATTACK                                0.771 s   22.30%

MEASURED TOTAL                              3.460 s  100.00%
```

Two thirds of that run was compiling kernels. The same command again spends 0.014 s there.

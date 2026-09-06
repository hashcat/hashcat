# Task time breakdown

`--task-time-breakdown` prints where a run's wall clock went, once the run is over. It is off by
default and it changes nothing about the run itself.

It exists to answer one question: a run took longer than expected, and the time did not go into
cracking. Where did it go?

```
hashcat -m 0 -a 0 --task-time-breakdown hashes.txt wordlist.txt
```

The report is suppressed by `--quiet`, `--machine-readable`, `--keyspace`, `--stdout`, `--show`,
`--left`, `--identify`, `--help`, `--hash-info` and `--backend-info`, so no existing script output
changes.

## How to read it

Lines are nested. An indented line is part of the line above it, and the percentages are all of the
measured total, not of the parent. So an indented line can never be more than its parent.

Every section ends with an `Other` line. That line is the part of the section its detail lines did
not account for. It is printed even when it is zero, because unclassified time is the thing worth
seeing. If a section is mostly `Other`, the report is telling you honestly that it does not know.

A line for a stage that never ran is not printed at all. A run with `-m` given prints no
autodetection line, and a run with no rules prints no rule loading line.

## The three top-level sections

`BEFORE ATTACK` is everything up to the first candidate being tried. On a short run this is usually
most of the clock.

`ATTACK` is the cracking itself, from the first candidate to the last.

`AFTER ATTACK` is shutting down: stopping the monitors, flushing output, releasing devices.

## What the individual lines mean

**Program and options setup.** Parsing the command line and finding the install and session folders.
This is microseconds. If it is not, something is wrong with the filesystem underneath.

**Session initialization.** Loading the backend runtimes and enumerating devices. Its detail lines
split that into bridges and plugins, the runtime libraries themselves, and per device setup. A slow
runtime load usually means a driver installation problem. Slow device setup on a many GPU box is
normal and is roughly linear in the device count.

**Attack preparation.** Everything between having devices and being able to try a candidate. This is
where a slow startup almost always lives, and its detail lines are the useful part of the report.

**Read and parse hash input.** Reading the hash file and turning each line into a digest. Scales with
the hash count. Its `Count hash input lines` child is a separate pass over the file to size the
allocation, so on a very large hash list you will see the two costs separately.

**Sort hashes**, **Sort salts** and **Remove duplicate hashes.** Scale with the hash count. On tens of
millions of hashes these become visible.

**Check potfile.** Matching the potfile against the loaded hashes. Scales with both, and with an
already large potfile it is worth knowing this is where the time went.

**Prepare wordlists, masks and rules.** Setting up the candidate source. Its `Load and validate rules`
child is the one to watch: a large rule file is compiled once here, and a few million rules is
seconds.

**Build hash lookup bitmaps.** Sizing and filling the filter tables. Grows with the hash count.

**Allocate attack and device session.** Getting the kernels onto the devices and allocating their
buffers. On a cold start this is almost entirely kernel compilation, which is why it is broken out:

  - **Compile kernels, cached afterwards.** The kernels are compiled for your specific device and
    options, then written to the `kernels` folder. This is the single largest startup cost on a first
    run and it is usually seconds. It does not happen again. The second run with the same mode,
    device and options loads the cached binary instead, this line disappears from the report, and the
    parent line drops to milliseconds. Nothing needs fixing.
    If you are seeing it on every run, either the cache folder is not surviving between runs,
    or something in the cache key changed. The key is the hash mode, the attack mode, whether
    `-O` is on, the device and its driver, and the build options the module itself asks for. The
    general build options are not part of it, so changing `-w` or the loop and accel settings does
    not force a rebuild. One mode never caches: `-m 1500` builds its kernel around the salt, so it
    compiles on every run by design.
  - **Other device session setup.** Buffer allocation and kernel argument setup. Grows with the hash
    count and the device count rather than with time.

**Kernel self-test** and **Kernel autotune.** Verifying the kernel produces a known answer, then
measuring the best workload size. Both are small on fast hashes. On a very slow hash mode the
autotune has to run real work to measure it, so seconds there are expected and `--force` or fixed
`-n` and `-u` values are the way to skip it, at the cost of a worse choice.

## What is not measured yet

The outfile check runs in its own thread rather than as a startup step, so time spent reading
`--outfile-check-dir` does not have its own line. It lands in `Other attack preparation`.

A run that fails during startup still prints a report, but the stage it failed in will show inflated
time, because a stage that was never closed is closed at the end. Read a failed run's numbers with
that in mind.

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

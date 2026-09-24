### Coverage guided fuzzing ###

Everything that reads attacker controlled text in hashcat runs through three functions, and none of
them had direct coverage. `module_hash_decode ()` reads a hash line for one mode.
`input_tokenizer ()` splits that line into the fields the parser reads. `cpu_rule_to_kernel_rule ()`
compiles one line of a rule file. All three walk a buffer by hand with a length the caller supplies,
and hash files and rule files are both downloaded and used without review.

`tools/fuzz` builds one libFuzzer target for each:

| target | entry point | what the input is |
| --- | --- | --- |
| `fuzz_rule` | `cpu_rule_to_kernel_rule ()` in `src/rp.c` | the rule, byte for byte |
| `fuzz_tokenizer` | `input_tokenizer ()` in `src/parser.c` | a token spec, then the line |
| `fuzz_parse_<mode>` | `module_hash_decode ()` of that mode | the hash line, byte for byte |

#### Build and run ####

    tools/fuzz/build.sh
    ./fuzz_out/fuzz_rule corpus/rule fuzz_out/work/seeds/rule -dict=tools/fuzz/fuzz_rule.dict

Needs clang, because libFuzzer is a clang feature. The script builds with AddressSanitizer unless
`CFLAGS` says otherwise, and it takes `CC`, `CFLAGS`, `LIB_FUZZING_ENGINE`, `OUT` and `WORK` from
the environment where they are set, so the engine and the sanitizer can be swapped without editing it.

One target across every core is `-fork`, which runs that many workers against one shared corpus:

    ./fuzz_out/fuzz_rule corpus/rule fuzz_out/work/seeds/rule -dict=tools/fuzz/fuzz_rule.dict \
        -fork=$(nproc) -ignore_crashes=0 -artifact_prefix=crashes/

Measured here on an idle core count of 12, twenty seconds on one mode: 5.2 million executions
without it, 15.5 million with `-fork=6`. A finding still stops the run and still lands in
`crashes/`, because `-ignore_crashes` stays off. With it on, the run keeps going and collects
every distinct crash instead, which is what a long overnight run wants.

Use `-fork` when fuzzing one target, and the loop below when fuzzing many: both fill the machine,
and running both at once only splits it.

Reproducing one input is the same binary with the input as an argument:

    ./fuzz_out/fuzz_rule crashes/crash-3cdf2936da2fc556bfa533ab1eb59ce710ac80e5

#### What a finding means ####

Both targets hand the function an allocation of exactly the length they pass with it, so a read
past that length is a read past the allocation and the sanitizer reports it. hashcat's own callers
pass a NUL terminated line buffer, so the same read lands on the terminator there rather than off
the end.

That makes these findings correctness findings rather than crashes, and they still have to be
fixed: the byte read is not part of the rule or the line, the function was told how long its input
is, and the next caller to pass a slice of a larger buffer gets the over read for real. Build with
`-DFUZZ_NUL_TERMINATE` to reproduce the caller's buffer and report only reads past the terminator,
which is the conservative view of the same run.

#### Seeds and dictionaries ####

`tools/fuzz/seeds.sh` writes both corpora out of the tree itself, so they cost nothing to carry and
they stay in step with what hashcat accepts: the rules ship in `rules/`, and the example hash of
every mode is the `ST_HASH` in its module. The dictionaries hold the rule commands and the
signatures, separators and field shapes the formats are built out of, so the fuzzer does not spend
executions rediscovering which bytes are syntax.

#### One parser target per mode ####

Every `src/modules/module_XXXXX.c` defines `module_init`, `module_hash_decode` and the rest of the
API with external linkage, so two modules cannot be linked into one binary. Each parser target
links its own module statically and takes the mode from `-DFUZZ_HASH_MODE`, which means no
`dlopen ()` and no plugin to ship beside the binary. It also means one corpus per mode, which is
what a per mode format deserves: an input that reaches deep into the pkzip parser says nothing
about sha256crypt.

`FUZZ_MODES` in `build.sh` holds the list, four to begin with rather than all 600: 17225 and 22000
have both needed a memory safety fix in their parsers, 29100 is the mode whose overflow the
structural harness in `tools/asan/` only reached by accident, and 7400 carries a rounds field. Add
a mode by putting it in that list. ci_matrix.py reads the same list, so nothing else needs changing.

    FUZZ_MODES="07400 13600" tools/fuzz/build.sh

Every mode at once is the same variable, filled from the tree:

    FUZZ_MODES="$(ls src/modules/module_*.c | sed 's#.*module_##;s#\.c##')" tools/fuzz/build.sh

That is about 13 minutes of building here and 6 GB of binaries, one per mode at roughly 10 MB, and
running each of them for a minute takes ten hours in a row. In parallel it is closer to an hour:

    tools/fuzz/seeds.sh fuzz_out/work/seeds $(ls src/modules/module_*.c | sed 's#.*module_##;s#\.c##')

    ls fuzz_out/fuzz_parse_* | grep -v '\.' | xargs -P "$(nproc)" -I{} sh -c '
      mode=$(basename {} | sed "s/fuzz_parse_//")
      mkdir -p corpus/$mode crashes
      {} corpus/$mode fuzz_out/work/seeds/parse_$mode -dict=fuzz_out/fuzz_parse.dict \
         -artifact_prefix=crashes/$mode- -max_total_time=60 -timeout=20 > /dev/null 2>&1 ||
        echo "$mode reported something"'

A mode whose target exits non zero has written its input into `crashes/`, and running that binary
on that file again is the whole reproduction.

Buffers are sized from the module's own `dgst_size`, `esalt_size` and `hook_salt_size`, so an
overflow in a target is an overflow of what hashcat would allocate. The `hashconfig` the parser
reads is built from the module's own getters, the way `interface.c` builds it, by
[hashconfig.c](../asan/hashconfig.c), which the harness in `tools/asan/` uses for the same reason.

A target links the code the entry points reach and nothing else. The file layer, the folder layout
and the random generator behind `generate_random_rule ()` are stubbed in
[stubs.c](stubs.c) rather than linked, because no target opens a file or generates a rule, and
stubbing them keeps the compression libraries and the rest of the tool out of the binary.

#### The token spec is part of the input ####

A module declares how many fields its format has, what separates them, how long each may be and
what it must look like. `fuzz_tokenizer` takes that spec from the first bytes of the input and the
line from the rest, which reaches combinations no module in the tree declares today.

Two specs are held back, both of which say something about the spec rather than about the line: a
token with no separator and no length, which leaves the next token pointing at nothing, and one
whose length the tokenizer never measures against what is left of the line, which walks the next
token past the end of a short line. `module_34300.c` declares the second one and guards it with its
own `line_len` check before the tokenizer is called. Fuzzing either would report the same non
finding for the length of the campaign. They would both stop being reachable at all if the
tokenizer bounded that advance the way it already bounds a fixed length token.

#### In CI ####

`.github/workflows/fuzz.yml` runs at three sizes, and
[ci_matrix.py](../../.github/workflows/ci_matrix.py) picks the modes for each:

* a pull request replays the saved corpus and the seeds, once each (`-runs=0`), through the parser
  of every mode it changes, at most 20. One that changes host code the targets link also gets
  `rule`, `tokenizer` and the four starting modes. It generates no new inputs, so a rerun gives the
  same answer. Exploring is what the weekly and manual runs are for.
* once a week, if master has had a commit in the last seven days, every mode in 16 shards for 60
  seconds each, so about 40 minutes a shard.
* by hand, with the modes and the seconds a target as inputs, for a longer run before a release.
  The seconds a target are cut down when a shard would not fit the job, so its corpus still gets
  saved.

Each shard keeps its corpus in the actions cache between runs. A campaign that starts from the seed
corpus every time relearns the same paths and never reaches past them, so the cache is not an
optimisation here, it is the thing that makes a scheduled run worth more than the run before it. A
mode lands in the shard its number hashes to, so it keeps its corpus when other modes come and go.

Three cache rules decide whether this works:

* an entry cannot be written twice under one key, so the key carries the run id and the restore
  falls back to the newest entry with the same prefix.
* an entry is evicted after seven days without a read, which a weekly run only just beats and a
  quiet week does not, so a second schedule on Thursday reads every shard's corpus and does nothing
  else.
* the repository holds 10 GB of cache and evicts the least recently used entry when full, which is
  why every run merges the corpus down before it saves.

Only a scheduled or manual run on master saves, because a cache written by a pull request lives in
that pull request's scope and is deleted with it.

A crash fails the job and the input is uploaded as an artifact, so a finding arrives as a red cross
with a reproducer attached. A module that does not build as a target fails its shard too, after the
rest of the shard has run.

#### What is not covered ####

Anything past the parser: a target stops where `module_hash_decode ()` returns.

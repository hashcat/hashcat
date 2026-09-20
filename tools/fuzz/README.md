### Coverage guided fuzzing ###

Two entry points sit under everything that reads attacker controlled text in hashcat, and neither
had direct coverage: `cpu_rule_to_kernel_rule ()` compiles one line of a rule file, and
`input_tokenizer ()` splits one hash line into fields for a module parser. Both walk a buffer by
hand with a length that the caller supplies.

`tools/fuzz` builds one libFuzzer target for each:

| target | entry point | what the input is |
| --- | --- | --- |
| `fuzz_rule` | `cpu_rule_to_kernel_rule ()` in `src/rp.c` | the rule, byte for byte |
| `fuzz_tokenizer` | `input_tokenizer ()` in `src/parser.c` | a token spec, then the line |

#### Build and run ####

    tools/fuzz/build.sh
    ./fuzz_out/fuzz_rule corpus/rule fuzz_out/work/seeds/rule -dict=tools/fuzz/fuzz_rule.dict

Needs clang, because libFuzzer is a clang feature. The script builds with AddressSanitizer unless
`CFLAGS` says otherwise, and it takes `CC`, `CFLAGS`, `LIB_FUZZING_ENGINE`, `OUT` and `WORK` from
the environment where they are set, which is how the same script serves OSS-Fuzz.

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

`.github/workflows/fuzz.yml` runs both targets nightly and keeps each corpus in the actions cache
between runs. A campaign that starts from the seed corpus every time relearns the same paths and
never reaches past them, so the cache is not an optimisation here, it is the thing that makes a
scheduled run worth more than the run before it.

The cache rules that decide whether this works: an entry cannot be written twice under one key, so
the key carries the run id and the restore falls back to the newest entry with the same prefix; an
entry is evicted after seven days without a read, which is why this is nightly and not weekly; and
the repository holds 10 GB of cache and evicts the least recently used entry when full, which is
why every run merges the corpus down before it saves. Only the scheduled run saves, because a cache
written by a pull request lives in that pull request's scope and is deleted with it.

A crash fails the job and the input is uploaded as an artifact, so a finding arrives as a red cross
with a reproducer attached.

#### OSS-Fuzz ####

`tools/fuzz/oss-fuzz/` holds the three files OSS-Fuzz needs, ready to be copied into
`projects/hashcat/` in a pull request against `google/oss-fuzz`. That buys continuous fuzzing on
Google's hardware, a corpus that is kept for us, crash deduplication and bisection to the commit
that introduced a finding.

Two things have to be settled before that pull request is worth opening. `primary_contact` must be
a hashcat maintainer with a Google account, because that address is how OSS-Fuzz verifies the
integration is wanted and it is who gets the reports. And OSS-Fuzz publishes a bug 30 days after it
is fixed or 90 days after it is reported, whichever comes first, which is a policy decision for the
project rather than a detail of the integration.

#### What is not covered ####

`module_hash_decode ()` itself, which is the parser these two functions serve. A target for it
needs a `hashconfig` built the way `interface.c` builds one, and the harness in `tools/asan/` does
that already, so the target belongs there rather than here.

It also needs a decision this integration does not make. Every `src/modules/module_XXXXX.c` defines
`module_init`, `module_hash_decode` and the rest of the API with external linkage, so two modules
cannot be linked into one binary: it is one target per mode, 600 corpora, or a binary that
`dlopen ()`s the module the way `tools/asan/parse_harness.c` does. A handful of hand picked modes
is the sane way in.

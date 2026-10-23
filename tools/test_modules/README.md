### Hashcat test modules ###

A test module is `mXXXXX.py`, where XXXXX is the hash mode padded to five digits. It provides the
functions `module_constraints`, `module_generate_hash` and `module_verify_hash`.

* `module_constraints` returns the minimum and maximum length of the password, the salt and the
combination of password and salt, in this order: password (pure), salt (pure), password
(optimized), salt (optimized), combination (optimized). A pair is -1, -1 where the field does not
apply, so a mode without a salt sets both salt pairs that way. The last pair matters where the
password and the salt share one kernel buffer, which is typically raw hashes only.
* `module_generate_hash` takes the password as `bytes`, the salt as `str`, and an iteration count
that is None unless the caller pins one. It returns the hash line as `str`, in the exact format
hashcat accepts, or None where the mode cannot produce one for that input.
* `module_verify_hash` takes one line of the cracks file as `bytes`, without the newline, and
returns a `(hash, password)` pair, or None if the line is not one this mode can account for.

The password is `bytes` because it really is arbitrary bytes: it carries multi byte UTF-8, and once
`$HEX[...]` is unwrapped it can be bytes that are not text at all. `tools/test_module_runner.py`
unwraps that notation before a module sees the line, so no module handles it.

During `single` and `passthrough`, `module_generate_hash` generates whatever the hash needs that is
random, a salt for instance. `lib/test_helpers.py` offers `random_hex_string`,
`random_numeric_string`, `random_bytes` and `random_number`, and a module reaches them as
`from lib.test_helpers import random_bytes`. Write your own generator where the mode needs
something those do not cover.

During `verify`, `module_verify_hash` rebuilds the hash out of the hash. Everything the derivation
needs is carried in the string, so the salt, the iteration count and anything else that was drawn
at random are read back from it rather than drawn again. A module that generated a fresh salt here
could never reproduce its own output, and `tools/test_module_runner.py` refuses to print a vector
whose `module_verify_hash` does not round trip it.

A module may also define `module_get_random_password`, which takes the generated password and
returns the one the mode actually needs. That is for a mode whose candidate is a seed phrase, a
challenge response or anything else with a shape of its own rather than a free string.

Where a family of modes shares a body, it lives in `lib` beside the helpers, and a module reaches
it as `from lib import gpg`.

#### Examples ####

* For a basic unsalted mode, see [m01000.py](m01000.py)
* For a mode whose artifact is a file rather than a hash string, see [m40011.py](m40011.py)
* For a body shared across a family, see [m17010.py](m17010.py) and [lib/gpg.py](lib/gpg.py)
* For a mode that drives its own cipher chaining, see [m20011.py](m20011.py) and
[lib/diskcryptor.py](lib/diskcryptor.py)

#### Reproducible runs ####

`HCTEST_SEED` is worth knowing about. Set it, and a run repeats: the same salts, the same passwords,
the same lengths. Leave it unset and the oracle draws at random, which is what the suite wants,
because a mode that only works for one salt is a mode that is broken.

#### Running an oracle inside hashcat ####

`tools/test_bridge.py` loads any oracle into hashcat's Python bridge, so hashcat cracks with the
oracle's own `module_generate_hash`/`module_verify_hash` instead of a kernel. It is a way to exercise
a mode's reference implementation through hashcat's real parser and candidate handling, or to step
through it, with no kernel involved:

    python3 tools/test_bridge.py vectors 1000 /tmp/b.hash /tmp/b.words
    ./hashcat -m 73000 --bridge-parameter1 tools/test_bridge.py /tmp/b.hash /tmp/b.words

The first command writes vectors for a mode (here 1000): `-P` picks the pure family, otherwise
optimized. A bridge line is `sha256(H)*MODE:FAMILY:base64(H)`, where H is the oracle's own hash line.
The bridge splits a line at its first `*` and many hash formats carry one, so H travels base64 encoded
in the salt half and the hash half is a fixed length digest of it; for each candidate the bridge calls
the oracle's `module_verify_hash` to regenerate H and digests the result, which equals the hash half
only when the candidate is the password. A hash line longer than the bridge's 1024 byte salt does not
fit and is skipped, which the `vectors` command reports.

The bridge runs each oracle in an ordinary Python process, so an oracle that imports pycryptodome
works the same as a hashlib-only one, on Linux, macOS and Windows alike. It needs a `python3` on PATH
and nothing else. See
[docs/hashcat-python-plugin-requirements.md](/docs/hashcat-python-plugin-requirements.md).

#### Reduced iteration counts ####

Normal runs, including `-S`, retain their original iteration counts. Set `ARTIFICIALLY_LOW_ITERATION_COUNT=true` to enable the reduced settings declared in each Python oracle module. Unset the variable or set it to `false` to keep normal behavior. The value is a boolean, not a numeric limit.

For formats with a supported encoded count, the oracle generates a hash containing the reduced value and hashcat decodes it normally. Policies name each parameter explicitly, including secondary iteration stages, logarithmic costs and memory costs. The policy retains format and kernel minimums, such as GPG's 1024 input bytes and 7-Zip's 4096-round batches. Explicit iteration arguments to `passthrough` and `potthrough` take precedence over these encoded defaults.

A module opts in with `module_reduced_iteration_constraints()`, returning a literal dictionary. Its optional `parameters` dictionary describes costs encoded in the generated hash. Its optional `runtime_limits` dictionary describes internal limits passed through `HASHCAT_ITER_OVERRIDE`. Both use `parameter -> inclusive bounds`. The hook must contain a single return statement with literal values, so the manager can read its policy without importing the oracle or its optional dependencies. For example, mode 2100 uses `{'iterations': (2, 16)}` and fixed-format scrypt modes use `{'scrypt_N': (1024, 2048, 'power2')}`. A third integer specifies a step, such as `(3, 15, 2)` for odd counts. Logarithmic costs use exponent units. Equal bounds select a fixed value.

`HCTEST_SEED` selects reproducible values independently for each mode and parameter. A reduced `test.py` run without a seed creates and reports one. The same selection reaches generation, verification and hashcat, including association batches. Sampling does not depend on worker order or on how often a policy is queried.

Each affected Python module declares its policy ranges and normal settings and selects overrides at the top of the file. A module whose reduced costs change compiled kernels also returns `'compiled_cost': True`, so the manager skips the incompatible startup self-test. Encoded defaults are exposed through `ITERATION_PARAMETERS` and passed as generator keyword arguments. Fixed-format KDFs select their effective compute count before their hashing functions are defined. A verifier uses counts decoded from the hash wherever the format supports them.

For formats without a supported encoded count, the manager supplies that mode's numeric `HASHCAT_ITER_OVERRIDE` to hashcat and the matching Python oracle. Hashcat caps the loaded `salt_iter` and `salt_iter2` loop counters after decoding, without changing the input hash text or the startup self-test salt. A PBKDF2 oracle includes the additional first iteration performed by its init kernel. These artificial vectors require the same override during verification. Some SSPR decoders require an exact count in their signature, so their synthetic vectors retain that signature and use the runtime hook. Symfony retains 5001 loop iterations to exercise its salt-dependent branch.

`OPTS_TYPE_ITER_OVERRIDE_UNSUPPORTED` tells hashcat to ignore the generic runtime override for a mode whose kernel needs its original schedule. These modes can still use a supported encoded-parameter policy. `OPTS_TYPE_TEST_ITERATIONS_SCRYPT` selects fixed-format scrypt handling: the override lowers N and the matching loop count before allocation and compilation, with a power-of-two N of at least 1024. The MD5crypt stage of the convoluted Cisco format remains unchanged.

With reduced testing enabled, `-S` generates a matching vector where an oracle is available. Otherwise it retains the published self-test vector at its normal count and reports the reason. Missing oracle dependencies also fall back to the published vector with the runtime override cleared. Other oracle errors fail the test. Reduced generated vectors whose compiled cost differs from the startup self-test disable that incompatible startup check. Real archives and containers produced with `-g` retain their application's normal costs.

The manager reports the selected parameters or the reason a mode retains its normal count. Crack commands in failure logs include the effective numeric runtime override, with zero meaning no override. The reduced setting also applies to the ordinary and edge suites.

An oracle with variants that need different kernel schedules can define `module_association_parameters()`, returning generator keyword dictionaries. The edge runner tests each variant, and association multi tests keep variants in separate groups.

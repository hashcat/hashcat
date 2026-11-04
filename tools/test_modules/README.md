### Hashcat test modules ###

A test module is `mXXXXX.py`, where XXXXX is the hash mode padded to five digits. It provides the functions `module_test_properties`, `module_generate_hash` and `module_verify_hash`.

* `module_test_properties` returns a dictionary containing `constraints` and optional `normal` and `reduced` metadata. The constraints name the `pure` and `optimized` kernel families. Each available family declares `password_length` and `salt_length` as minimum-and-maximum pairs. A family is `None` when its kernel is unavailable. Salt bounds are `None` when no supplied salt is needed. The separate `combined_length` pair bounds the combined password and salt length, typically where they share a kernel buffer, or is `None` when no bound applies.
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

Normal runs, including `-S`, retain their original iteration counts. Pass `--artificially-low-iteration-count` to `tools/test.py`, or set `ARTIFICIALLY_LOW_ITERATION_COUNT=true`, to generate supported test vectors with a fixed count of 2. The generated hash stores that count in its real format, and hashcat decodes it normally. No hashcat runtime override is used.

A supported oracle adds a literal `reduced` section to `module_test_properties()`, containing `{'parameters': {'iterations': 2}}`. The manager reads this declaration without importing optional dependencies. Each oracle child reads its own properties to initialize `ITERATION_PARAMETERS`. Verification uses the count decoded from the hash. Explicit iteration arguments to `passthrough` and `potthrough` take precedence over the reduced default.

Only formats whose generators support an encoded count of 2 opt in. Other formats, missing test modules, and external archives or containers keep their normal costs. The modes 13733, 13772, 13773, 29433, 29472 and 29473 reported in issue 5003 have no Python test module and are not covered by this option.

With this option, `-S` generates a supported reduced vector instead of using the published self-test vector. Missing oracle dependencies fall back to the published vector. Other oracle errors fail the test. The setting also applies to ordinary and edge tests. Manual CI runs expose an unchecked checkbox. Scheduled and PR runs retain their original counts.

`module_test_properties()` requires `constraints` and may contain `normal.parameters` for generator defaults and `reduced.parameters` for the fixed reduced count. `test_iteration_parameters(module_test_properties())` reads those properties inside the oracle process and applies reduced parameters when `ARTIFICIALLY_LOW_ITERATION_COUNT=true`. Explicit generator arguments take precedence. The manager reads the literal iteration declarations without importing crypto dependencies or evaluating constraints that may refer to module constants.

```python
def module_test_properties():
  return {
    'constraints': {
      'pure': {'password_length': [0, 256], 'salt_length': [0, 64]},
      'optimized': None,
      'combined_length': None,
    },
    'normal': {
      'parameters': {'iterations': 40000},
    },
    'reduced': {
      'parameters': {'iterations': 2},
    },
  }
```

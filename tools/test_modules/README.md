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
* For a mode whose artifact is a file rather than a hash string, see [m05200.py](m05200.py)
* For a body shared across a family, see [m17010.py](m17010.py) and [lib/gpg.py](lib/gpg.py)
* For a mode that drives its own cipher chaining, see [m20011.py](m20011.py) and
[lib/diskcryptor.py](lib/diskcryptor.py)

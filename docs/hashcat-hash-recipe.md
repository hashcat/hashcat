# Hash recipes, hash-mode 4000

Hash-mode 4000 cracks hashes defined by a recipe that combines hash functions, the password and the
salt. Examples include `md5(md5(salt) . pass)` and `sha512(salt . sha512(pass))`. Provide the recipe
with `--hash-recipe`. hashcat compiles it into the kernel when the run starts. Most recipes run close
to the speed of the matching built-in pure kernel on both GPUs and CPUs.

```
hashcat -m 4000 --hash-recipe 'md5(md5(salt) . pass)' hashes.txt wordlist.txt
```

Recipes use the expression syntax of [hx](https://github.com/Cynosureprime/hx), the hash expression
language. Mode 4000 supports the subset listed below and follows hx's evaluation rules.

In a Unix shell, quote the recipe with single quotes and write strings inside it with double quotes.

## Hash line

Each hash line contains the recipe's hex output, followed by `*` and the salt. Keep the `*` even
when the recipe does not use a salt:

```
ab8faf3c7835359d3a2f1ba736f3b3a3*x7Qp
a930da511a48094f9d543d349a3d329c*
```

Only the first 16 bytes of the digest are compared. Cracking accepts either hex case. The outfile
and output from `--show` preserve the original hash line.

## Syntax

| Element | Meaning |
|---|---|
| `pass` | The password candidate |
| `salt` | The salt from the hash line |
| `"text"`, `'text'` | A string. Double quotes support the escapes `\\` `\"` `\'` `\n` `\r` `\t` `\0` and `\xHH`. Single quotes preserve every byte |
| `a . b` | Concatenation |
| `md4(x)` `md5(x)` `sha1(x)` `sha224(x)` `sha256(x)` `sha384(x)` `sha512(x)` | Hash of `x`, as lowercase hex |
| `rmd160(x)` `blake2b512(x)` `blake2b256(x)` `blake2s256(x)` `sm3(x)` | RIPEMD-160, BLAKE2b-512, BLAKE2b-256, BLAKE2s-256 and SM3, as lowercase hex |
| `md5_bin(x)` | The digest as raw bytes |
| `md5_hex(x)` | Lowercase hex, the same as `md5(x)` |
| `md5_uc(x)` | Uppercase hex |
| `hmac_md5(key, x)` | HMAC of `x` with `key`. All families support HMAC with the same suffixes, as in `hmac_sha256_bin(key, x)`. The alias `hmac_blake2s` means `hmac_blake2s256` |
| `md5^3(x)` | Equivalent to `md5(md5(md5(x)))`. The suffix sets the output format for each round. For example, `md5_bin^3` chains raw bytes and `md5_uc^3` chains uppercase hex |
| `upper(x)`, `lower(x)` | Converts ASCII letters to uppercase or lowercase. Applying `upper` to `md5^3(x)` changes only the final result, while `md5_uc^3(x)` uses uppercase hex in every round |
| `hex(x)` | Encodes raw bytes as hex. For example, `hex(md5_bin(x))` is equivalent to `md5(x)` |
| `cut(x, start, length)` | Selects `length` bytes from the zero-based position `start`. A negative start counts from the end. Omitting the length selects the rest of `x` |
| `trunc(x, length)` | `cut(x, 0, length)` |
| `rev(x)` | The bytes in reverse order |
| `rotate(x, N)` | Moves the last N bytes to the front. A negative N moves the first N bytes to the end |
| `cap(x)`, `cap(x, N)` | Converts the first lowercase letter to uppercase, or the letter at the zero-based position N |
| `rot13(x)` | Applies ROT13 to ASCII letters |
| `pad(x, N)` | Pads with zero bytes or truncates to N bytes |
| `bswap32(x)` | Reverses each complete group of 4 bytes and leaves any trailing bytes unchanged |
| `wperm(x, w0, w1, ...)` | Reorders the 4-byte words of `x` using the given zero-based indices |
| `utf16le(x)` | Converts `x` to UTF-16LE. Passwords and salts are decoded from UTF-8. Hex output and ASCII strings get a zero byte after each byte |
| `( ... )` | Grouping |
| `# ...` | A comment to the end of the line |

All hash families support the same suffixes and `^N` syntax. When applied to a concatenation, the
transforms `upper`, `lower`, `hex`, `rot13` and `utf16le` act on each element.

## Examples

| Recipe | Same as |
|---|---|
| `md5(md5(pass))` | mode 2600 |
| `md5^3(pass)` | mode 3500 |
| `md5(salt . md5(pass))` | mode 3710 |
| `md5(md5(pass) . md5(salt))` | mode 3910 |
| `md5(upper(md5(pass)))` | mode 4300 |
| `sha1(md5(pass))` | mode 4700 |
| `upper(sha1(sha1_bin(pass)))` | mode 300 |
| `sha256(salt . pass)` | mode 1420 |
| `md4(utf16le(pass))` | mode 1000 |
| `md5(utf16le(pass) . salt)` | mode 30 |
| `sha1(salt . utf16le(pass))` | mode 140 |
| `sha512(utf16le(pass) . salt)` | mode 1730 |
| `rmd160(pass)` | mode 6000 |
| `blake2b512(pass . salt)` | mode 610 |
| `hmac_md5(pass, salt)` | mode 50 |
| `hmac_sha256(salt, pass)` | mode 1460 |
| `md5(pad(pass, 100))` | mode 9900 |
| `md5(md5(salt) . pass)` | |
| `sha256("#" . salt . "-" . pass)` | |
| `sha224(sha224_bin(pass))` | |
| `trunc(sha512(pass), 32)` | the first 32 hex characters of a SHA-512 digest |
| `sha1(upper(pass) . salt)` | |

## Limits

- A recipe supports up to 8 hash calls, 8 concatenated parts per call and 4 strings. Each string
  can contain up to 16 bytes after its transforms are applied.
- Passwords and salts can contain up to 256 bytes. Applying `hex` reduces the limit for that input
  to 128 bytes.
- A recipe supports up to 4 transformed copies of `pass` and `salt`, such as `upper(pass)` or
  `pad(salt, 16)`, with up to 4 transforms per copy. `utf16le` must be the outermost transform.
- The transforms `rev`, `rotate`, `cap`, `rot13`, `pad`, `bswap32` and `wperm` accept `pass`, `salt`
  and strings. Hash outputs are not supported yet. Except for `rot13`, these transforms and `cut`
  accept a single element rather than a concatenation.
- `pad` accepts N from 0 to 256. `wperm` accepts up to 16 word indices from 0 to 15. A word beyond
  the end of `x` contributes 4 zero bytes.
- `^N` accepts N from 1 to 100000.
- A `cut` of a hash output must start at a multiple of 4 bytes of that output. A `cut` of its
  `utf16le` form must preserve whole characters.
- The key of an `hmac_` call must be a single part: `pass`, `salt`, a transformed copy of either, a
  string or a hash call. Concatenations and `utf16le` keys are not supported. Keys longer than the
  hash family's block size are hashed first, as HMAC requires.
- `utf16le` accepts `pass`, `salt`, hex output and ASCII strings. It does not accept raw bytes or
  feed the BLAKE2 families yet. A password or salt with invalid UTF-8 cannot match a recipe
  that applies `utf16le` to it.
- The result must be a hash call in hex, optionally wrapped in `upper`, `lower`, `hex`, `cut` or
  `trunc`. It must retain at least the first 32 hex characters.

## Not supported yet

Mode 4000 supports only part of hx. It does not support statements, loops, `if`, key derivation,
ciphers or character encodings other than `utf16le`. Hash families such as Whirlpool, Streebog,
SHA-3 and Keccak are also unsupported, as are `xor`, `and`, `or`, `length` and `fromhex`. A recipe
that uses an unsupported feature is rejected at startup with the reason and position of the error.

Mode 74000's dynamic plugin supports PBKDF2 and bcrypt. It runs on the CPU and is much slower for
fast hashes.

## Notes

- Attack modes 0, 1, 3, 4, 5, 6, 7, 8, 9 and 12 are supported. Mode 4000 uses pure kernels, so
  `-O` is not available.
- Before the attack starts, each device checks its compiled kernel against a self-test hash computed
  from the same recipe on the host.
- Each recipe compiles to a separate kernel and uses the usual kernel cache.
- Work that does not depend on the candidate runs once per salt. This includes calls on `salt` and
  strings alone, leading parts such as the salt in `sha256(salt . pass)`, and HMAC key pads when
  the key is `salt`.
- A recipe must use `pass`. Otherwise, every candidate would produce the same hash.
- UTF-8 decoding can give candidates different lengths. The SIMD mask kernel on CPUs cannot track
  a separate length for each candidate. It hashes candidates together when all are ASCII and
  processes them individually otherwise.

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

Each hash line contains the recipe's output, followed by `*` and the salt. The output uses hex
unless the recipe produces a base64 result. In that case, it uses base64. Keep the `*` even when the
recipe does not use a salt:

```
ab8faf3c7835359d3a2f1ba736f3b3a3*x7Qp
a930da511a48094f9d543d349a3d329c*
```

A recipe that uses `iter` adds a `*` and the iteration count after the salt:

```
3d1e5ee7417951b10852c0ceb6ccc2ab*x7Qp*5000
```

Only the first 16 bytes of the digest are compared. Cracking accepts either hex case, and base64
with or without `=` padding. The outfile and output from `--show` preserve the original hash line.

A recipe whose result is a comparison needs no digest in its hash line. The line therefore starts
with the `*` before the salt. See [Comparisons](#comparisons) for the format.

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
| `md5_b64(x)` | Standard base64 of the digest, with `=` padding |
| `pbkdf2_sha256(key, salt, N, len)` | PBKDF2 with HMAC-SHA256, N iterations and a derived key of len bytes, as lowercase hex. The variants `pbkdf2_md5`, `pbkdf2_sha1` and `pbkdf2_sha512` use the other families. All 4 variants accept the same output suffixes as a hash call, as in `pbkdf2_sha1_bin`. See [Key derivation](#key-derivation) |
| `aes_cbc_decrypt(key, iv, x)` | AES-CBC decryption of `x`, as lowercase hex. A key of 16, 24 or 32 bytes selects AES-128, AES-192 or AES-256. No padding is added or removed. The calls `aes_cbc_encrypt(key, iv, x)` and `aes_ecb_encrypt(key, x)` encrypt data. The call `aes_unwrap(kek, x)` unwraps a key according to RFC 3394. All 4 calls accept the same output suffixes as a hash call. See [Ciphers](#ciphers) |
| `hmac_md5(key, x)` | HMAC of `x` with `key`. All families support HMAC with the same suffixes, as in `hmac_sha256_bin(key, x)`. The alias `hmac_blake2s` means `hmac_blake2s256` |
| `md5^3(x)` | Equivalent to `md5(md5(md5(x)))`. The suffix sets the output format for each round. For example, `md5_bin^3` chains raw bytes and `md5_uc^3` chains uppercase hex |
| `upper(x)`, `lower(x)` | Converts ASCII letters to uppercase or lowercase. Applying `upper` to `md5^3(x)` changes only the final result, while `md5_uc^3(x)` uses uppercase hex in every round |
| `hex(x)` | Encodes raw bytes as hex. For example, `hex(md5_bin(x))` is equivalent to `md5(x)` |
| `base64(x)` | Encodes raw bytes as standard base64. For example, `base64(md5_bin(x))` is equivalent to `md5_b64(x)` |
| `fromhex(x)` | Decodes hex to bytes. For example, `fromhex(md5(x))` is equivalent to `md5_bin(x)` |
| `frombase64(x)` | Decodes standard base64 to bytes. The `=` padding is optional |
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
| `h = x` | Assigns `x` to the variable `h`, for the statements that follow |
| `a; b` | Statements, separated by `;` or a line break. The last one is the result |
| `for i = 1 to N { ... }` | Runs the statements inside the braces N times. See [Loops](#loops) for the supported loop forms |
| `iter` | The iteration count from the hash line, as the last value of a loop or the count of `pbkdf2` |
| `a == b` | As the last statement, compares raw bytes with a constant to determine the result. See [Comparisons](#comparisons) for the supported forms |
| `length(x) > 0` | As the last statement, true when `x`, an `aes_unwrap` call, passes its integrity check |

All hash families support the same suffixes and `^N` syntax. When applied to a concatenation, the
transforms `upper`, `lower`, `hex`, `rot13` and `utf16le` act on each element.

A variable stands for the expression assigned to it, and the last statement must be an expression.
A hash call that appears more than once, for example through a variable, is computed once:

```
h = md5_bin(salt . pass)
sha256(h . salt . h)
```

## Loops

A recipe can contain one `for` loop. Its body runs once for each value from the first bound through
the last bound, including both bounds. This example implements phpass without its final encoding:

```
h = md5_bin(salt . pass)
for i = 1 to 2047 { h = md5_bin(h . pass) }
hex(h)
```

The last value can be `iter` instead of a number. Each hash line then carries its own iteration
count, and hashes with different counts can share a hash file:

```
h = md5_bin(salt . pass)
for i = 1 to iter { h = md5_bin(h . pass) }
hex(h)
```

A recipe with a loop runs as a slow hash, so the iteration count determines the cost of each
candidate. The body can contain only variable assignments, and each assignment must assign a hash
call. A variable that the body reads before assigning it contains its value from the previous
iteration. On the first iteration, it contains its value from before the loop. The result can be a
hash call or a carried variable, used directly or wrapped in `hex` or `base64` for raw bytes, or
`upper` or `lower` for hex output.

## Key derivation

A recipe with a `pbkdf2` call also runs as a slow hash. Its iteration count can be a fixed number or
`iter`, which uses the count stored on each hash line:

```
pbkdf2_sha256(pass, salt, iter, 32)
```

The derived key can be the result, or the input of further calls:

```
dk = pbkdf2_sha1_bin(sha256_bin(pass), salt, 1000, 32)
sha256(dk)
```

A call to `cut` selects part of a derived key in its `_bin` form. This allows one derivation call to
provide both an AES key and its IV. Each cut must start and end at a multiple of 4 bytes:

```
dk = pbkdf2_sha256_bin(pass, cut(fromhex(salt), 0, 16), iter, 48)
aes_cbc_decrypt(cut(dk, 0, 32), cut(dk, 32, 16), cut(fromhex(salt), 16, 16))
```

## Ciphers

AES calls run after a `pbkdf2` call or a loop. When the salt is stored in hex, `cut` separates its
fields according to the format. This example derives a key from the first 8 bytes. It decrypts the
last 16 bytes using the IV stored between them. The hash line contains the plaintext produced by
the correct password:

```
dk = pbkdf2_sha1_bin(pass, cut(fromhex(salt), 0, 8), iter, 16)
aes_cbc_decrypt(dk, cut(fromhex(salt), 8, 16), cut(fromhex(salt), 24, 16))
```

The key, IV and each data part must have fixed lengths. They can be `_bin` hash calls, `pbkdf2`,
strings, a `cut` with a specified length, a `pad`, or a variable assigned a hash call in a loop. If
a part is shorter on a particular hash line, it is padded with zero bytes to its fixed length. This
includes a salt that is too short for the range selected by its `cut`.

## Comparisons

The last statement can compare raw bytes with a constant instead of producing a value. In this
case, the hash line contains only its salt and iteration count. A candidate cracks the hash
when the comparison is true. This example decrypts the last block of the salt and checks for 16
bytes of PKCS#7 padding:

```
dk = pbkdf2_sha1_bin(pass, cut(fromhex(salt), 0, 8), iter, 16)
pt = aes_cbc_decrypt_bin(dk, cut(fromhex(salt), 8, 16), cut(fromhex(salt), 24, 16))
pt == fromhex('10101010101010101010101010101010')
```

The password `Rp!#!t!koKs471JpOHydnXTBS` cracks this hash line:

```
*3f6747237b1d2fdd5a944330e309c6d8bf7c2aae80b9c7f8b85c8a5aea581fe4b7d80e5419415f83*15
```

The left side is a `_bin` hash or AES call, or a `cut` of one that starts at a multiple of 4 bytes.
The right side is a string, decoded with `fromhex` or `frombase64` if needed, of the same length and
at least 8 bytes long. Mode 4000 compares the first 16 bytes of both.

The comparison `length(aes_unwrap(kek, x)) > 0` is true when the key unwrap passes
its integrity check:

```
length(aes_unwrap(pbkdf2_sha256_bin(pass, cut(fromhex(salt), 0, 16), iter, 32), cut(fromhex(salt), 16, 40))) > 0
```

A hash line can still include a digest: the 16 compared bytes in hex, padded with zeros. The
self-test hash includes such a digest, containing the bytes that the self-test password
produces from its salt.

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
| `sha1(utf16le(pass) . frombase64(salt))` | a salt stored in base64 |
| `sha256(pass . fromhex(salt))` | a salt stored in hex |
| `h = md5(salt); md5(h . pass)` | `md5(md5(salt) . pass)` |
| `sha1_b64(pass)` | mode 101 without the `{SHA}` prefix |
| `md5(md5_b64(pass) . salt)` | |

## Limits

- A recipe supports up to 8 hash calls, 8 concatenated parts per call and 4 strings. Each string
  can contain up to 16 bytes after its transforms are applied.
- A recipe supports up to 16 variables. Assignments cannot use the reserved names `pass`, `salt`,
  `salt2`, `pepper`, `user`, `iter`, `for`, `to`, `if` and `else`. The value `iter` can only be used
  as the last bound of a loop or as the iteration count of `pbkdf2`.
- A recipe supports one loop with integer bounds, running from 1 to 10000000 times. Up to 4
  variables can be carried through it. The body cannot yet read the loop counter or apply a
  transform to a variable carried through the loop. The self-test runs the loop on the host, so a
  long loop delays the start of the attack.
- A recipe supports up to 3 different cuts of its derived key. A cut cannot be the result yet.
- A recipe supports one `pbkdf2` call and cannot combine it with a loop. Its key and salt must each
  be a single value, as required for a variable carried through a loop. The derived key's length
  must be a multiple of 4, from 4 to 64 bytes. When used as the result, the derived key must be at
  least 16 bytes long. The call runs from 1 to 10000000 iterations, or up to 999999999 when the
  count comes from the hash line.
- A comparison has to be the last statement. It compares with `==` and has a string on its right
  side, or it is `length(aes_unwrap(kek, x)) > 0`. Comparing two computed values, or a variable
  carried through a loop, is not supported yet.
- An AES call requires a `pbkdf2` call or a loop in the recipe. It cannot yet run inside the loop or
  provide input to `pbkdf2`. Its key must be 16, 24 or 32 bytes long, and its IV must be 16 bytes.
  ECB and CBC data must be 16 to 64 bytes long, a multiple of 16. The input to `aes_unwrap` must be
  16 to 72 bytes long, a multiple of 8. If its integrity check fails, `aes_unwrap` gives an all-zero
  key instead of hx's empty string.
- A loop up to `iter` has to start at 0 or 1. The hash line can give `iter` up to 999999999, and
  the self-test uses 1000.
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
- The decoders `fromhex` and `frombase64` accept `salt` itself and strings. The decoder `fromhex`
  also accepts hex hash output. A recipe can decode its salt using only one encoding. Applying
  `utf16le` to a decoded salt is not supported. The hash line preserves the salt as encoded text. A
  salt with invalid hex or base64 is rejected when the hash file is loaded. A string with an invalid
  encoding in the recipe is rejected at startup.
- `base64` accepts a whole `_bin` hash call and strings, not `pass`, `salt`, a concatenation or a
  cut of a digest. `upper`, `lower`, `hex` and `fromhex` do not accept base64 output.
- The result must be a hash call or an AES call in hex or base64, optionally wrapped in `upper`,
  `lower`, `hex`, `base64`, `cut` or `trunc`. It must retain at least the first 32 hex characters or
  22 base64 characters. A `pbkdf2` call or a variable carried through a loop can be the result as
  well, wrapped only in `hex` or `base64` of raw bytes or in `upper` or `lower` of hex. The result
  can also be a comparison. See [Comparisons](#comparisons).

## Not supported yet

Mode 4000 supports only part of hx. It does not support nested or several loops, `if`, `emit`, key
derivation other than `pbkdf2`, ciphers other than AES or character encodings other than `utf16le`.
Hash families such as Whirlpool, Streebog, SHA-3 and Keccak are also unsupported, as are `xor`,
`and` and `or`. `length` is supported only in `length(aes_unwrap(kek, x)) > 0`. A recipe that uses
an unsupported feature is rejected at startup with the reason and position of the error.

Mode 74000's dynamic plugin supports bcrypt. It runs on the CPU and is much slower for fast hashes.

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

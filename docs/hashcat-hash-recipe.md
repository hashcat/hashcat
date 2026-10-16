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
unless the recipe produces a base64 result. In that case, it uses base64. For a recipe that does
not use a salt, the `*` after the digest is optional, so the second and third lines are the same
hash:

```
ab8faf3c7835359d3a2f1ba736f3b3a3*x7Qp
a930da511a48094f9d543d349a3d329c*
a930da511a48094f9d543d349a3d329c
```

A recipe that uses `iter` adds a `*` and the iteration count after the salt:

```
3d1e5ee7417951b10852c0ceb6ccc2ab*x7Qp*5000
```

A recipe that uses `salt2`, `pepper` or `user` adds each of them after the salt, in that order and
before the iteration count. A line carries only the fields its recipe uses. These fields cannot
contain a `*`, while the salt can. This line is for `md5(pass . user)` with an empty salt:

```
0a245ea64f49f9aa79fa9c79bbd95c8d**admin
```

With `--username`, `user` comes from the hash list instead. Hashcat splits it off each input line,
so the hash line has no user field. Together with lines that contain only the digest, this lets
hashcat read the hash list formats that `--username` supports, such as `user:hash` and passwd
files. With
`md5(pass . user)` and `--username`, this line represents the same hash as the one above:

```
admin:0a245ea64f49f9aa79fa9c79bbd95c8d
```

The potfile always writes the user on the line, so a potfile entry matches with and without
`--username`.

Only the first 16 bytes of the digest are compared. Cracking accepts either hex case, and base64
with or without `=` padding. The outfile and output from `--show` preserve the original hash line.

A recipe whose result is a comparison needs no digest in its hash line. The line therefore starts
with the `*` before the salt. See [Comparisons](#comparisons) for the format.

## Syntax

| Element | Meaning |
|---|---|
| `pass` | The password candidate |
| `salt` | The salt from the hash line |
| `salt2`, `pepper`, `user` | Further fields from the hash line, see [Hash line](#hash-line) |
| `"text"`, `'text'` | A string. Double quotes support the escapes `\\` `\"` `\'` `\n` `\r` `\t` `\0` and `\xHH`. Single quotes preserve every byte |
| `a . b` | Concatenation |
| `md2(x)` `md4(x)` `md5(x)` `sha0(x)` `sha1(x)` `sha224(x)` `sha256(x)` `sha384(x)` `sha512(x)` | Hash of `x`, as lowercase hex. `ed2k(x)` is an alias for `md4(x)` and `aich(x)` is an alias for `sha1(x)`. Each equals its corresponding hash for every input shorter than its first block |
| `rmd128(x)` `rmd160(x)` `rmd256(x)` `rmd320(x)` `blake2b512(x)` `blake2b256(x)` `blake2s256(x)` `sm3(x)` | RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320, BLAKE2b-512, BLAKE2b-256, BLAKE2s-256 and SM3, as lowercase hex |
| `wrl(x)` | Whirlpool, as lowercase hex. `whirlpool(x)` is the same call |
| `sha3_224(x)` `sha3_256(x)` `sha3_384(x)` `sha3_512(x)` | SHA-3, as lowercase hex |
| `keccak224(x)` `keccak256(x)` `keccak384(x)` `keccak512(x)` | Keccak with its original padding, as Ethereum uses it, as lowercase hex |
| `streebog_32(x)` `streebog_64(x)` | Streebog-256 and Streebog-512 (GOST R 34.11-2012), as lowercase hex in the byte order hashcat's modes 11700 and 11800 print. `streebog256(x)`, `streebog512(x)`, `gost2012_32(x)` and `gost2012_64(x)` are the same calls |
| `hav128(x)` `hav160_4(x)` `hav256_5(x)` | HAVAL, as lowercase hex. `havN_P` names the digest size N (128, 160, 192, 224 or 256 bits) and the pass count P (3, 4 or 5). `hav128`, `hav160`, `hav192`, `hav224` and `hav256` use 3 passes, the same as `hav128_3` to `hav256_3` |
| `tiger(x)` `tiger128(x)` `tiger160(x)` `tiger2(x)` `tth(x)` | Tiger with 3 passes, as lowercase hex in the byte order printed by PHP and the reference implementation. `tiger128` and `tiger160` keep its first 16 and 20 bytes, `tiger192` is `tiger`, and `tiger2` is Tiger2, which pads with 0x80 instead of 0x01. `tth(x)` is the Tiger tree hash of one leaf, Tiger over a 0x00 byte and `x`. It matches TTH for inputs of up to 1024 bytes. A longer input gives an inverted digest, so it cannot crack the TTH of that input. It has no `hmac_` form |
| `mysql3(x)` | The password hash of MySQL before 4.1, 8 bytes as lowercase hex. It skips spaces and tabs as MySQL does. It is too short to be the result, which needs 16 bytes, so it appears inside another call, as in `md5(mysql3(pass))`. It has no `hmac_` form |
| `sne128(x)` `sne256(x)` | Snefru-128 and Snefru-256 with 8 rounds, as lowercase hex. `snefru128(x)` and `snefru256(x)` are the same calls. Their HMAC blocks are 48 and 32 bytes, the data each block takes |
| `skein224(x)` `skein256(x)` `skein384(x)` `skein512(x)` | Skein-512 (Skein 1.3) with a digest of 224, 256, 384 or 512 bits, as lowercase hex. The Skein paper calls these Skein-512-224 to Skein-512-512 |
| `panama(x)` | PANAMA in the little endian convention, as lowercase hex. Its HMAC block is 32 bytes |
| `gost(x)` `gost_crypto(x)` | GOST R 34.11-94, as lowercase hex. `gost` uses the S-box of the test parameter set, as hashcat's mode 6900 does. `gost_crypto` uses the S-box of the CryptoPro parameter set |
| `md5_bin(x)` | The digest as raw bytes |
| `md5_hex(x)` | Lowercase hex, the same as `md5(x)` |
| `md5_uc(x)` | Uppercase hex |
| `md5_b64(x)` | Standard base64 of the digest, with `=` padding |
| `pbkdf2_sha256(key, salt, N, len)` | PBKDF2 with HMAC-SHA256, N iterations and a derived key of len bytes, as lowercase hex. The variants `pbkdf2_md5`, `pbkdf2_sha1` and `pbkdf2_sha512` use the other families. All 4 variants accept the same output suffixes as a hash call, as in `pbkdf2_sha1_bin`. See [Key derivation](#key-derivation) |
| `aes_cbc_decrypt(key, iv, x)` | AES-CBC decryption of `x`, as lowercase hex. A key of 16, 24 or 32 bytes selects AES-128, AES-192 or AES-256. No padding is added or removed. The calls `aes_cbc_encrypt(key, iv, x)` and `aes_ecb_encrypt(key, x)` encrypt data. The call `aes_unwrap(kek, x)` unwraps a key according to RFC 3394. All 4 calls accept the same output suffixes as a hash call. See [Ciphers](#ciphers) |
| `hmac_md5(key, x)` | HMAC of `x` with `key`. All families except `mysql3` and `tth` support HMAC with the same suffixes, as in `hmac_sha256_bin(key, x)`. The alias `hmac_blake2s` means `hmac_blake2s256`. SHA-3 and Keccak use their rate as the HMAC block, GOST R 34.11-94 its 32-byte block and MD2 its 16-byte block. `hmac_streebog256` and `hmac_streebog512` give the results of hashcat's modes 11750 to 11860 |
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
| `utf16be(x)` | Converts `x` from UTF-8 to UTF-16BE. A value that is not well-formed UTF-8 gives an empty result |
| `zext16(x)` | Appends a zero byte after each input byte, without decoding the input. For ASCII, it produces the same bytes as `utf16le(x)` |
| `xor(a, b)` `and(a, b)` `or(a, b)` | Combines `a` and `b` byte by byte, as raw bytes. The shorter value repeats to the length of the longer one. An empty value gives an empty result |
| `( ... )` | Grouping |
| `# ...` | A comment to the end of the line |
| `h = x` | Assigns `x` to the variable `h`, for the statements that follow |
| `a; b` | Statements, separated by `;` or a line break. The last one is the result |
| `for i = 1 to N { ... }` | Runs the statements inside the braces N times. See [Loops](#loops) for the supported loop forms |
| `iter` | The iteration count from the hash line, as the last value of a loop or the count of `pbkdf2` |
| `a == b` | As the last statement, compares raw bytes with a constant to determine the result. See [Comparisons](#comparisons) for the supported forms |
| `length(x) > 0` | As the last statement, true when `x`, an `aes_unwrap` call, passes its integrity check |

All hash families support the same suffixes and `^N` syntax. When applied to a concatenation, the
transforms `upper`, `lower`, `hex`, `rot13`, `zext16` and `utf16le` act on each element.

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
call, an `xor`, `and` or `or` call, or a transformed value such as `rev(h)`. A variable that the
body reads before assigning it contains its value from the previous iteration. On the first
iteration, it contains its value from before the loop. The result can be a hash call or a carried
variable, used directly or wrapped in `hex` or `base64` for raw bytes, or `upper` or `lower` for
hex output.

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

Other transforms of a derived key, such as `rev`, `hex` of the `_bin` form or a cut that does not
start and end at a multiple of 4 bytes, apply to the whole key as they apply to a hash output.

A format may store only part of its derived key. For such a format, a cut can also be the recipe's
result. Write it as `hex` or `base64` of a cut of the `_bin` form, or cut the hex form using offsets
and lengths counted in hex characters. The result must retain at least 16 bytes. Both examples below
return the last 32 bytes of a 64 byte key:

```
hex(cut(pbkdf2_sha256_bin(pass, salt, iter, 64), 32, 32))
cut(pbkdf2_sha256(pass, salt, iter, 64), 64, 64)
```

PBKDF2 computes its derived key in blocks the size of its hash digest. Mode 4000 computes only the
blocks from the first to the last one that the recipe reads. A cut skips the blocks before its
selected range, as the 2 examples above
skip the first block. When the whole key is the result, only the block containing its first 16 bytes
is needed. Those are the bytes compared, so using a longer key does not make the recipe slower.
Transforms other than such cuts read every block.

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

Both sides can also be computed, as in `cut(sha256_bin(pass), 0, 16) == md5_bin(salt . pass)`. In
this form, each side must be a single value, as required for `xor`, and both must have the same
fixed length of at least 8 bytes. A salt has a fixed length only when a transform sets it, such as
`cut(pad(fromhex(salt), 16), 0, 16)`. A variable carried through a loop, a `pbkdf2` key or a `cut`
of either can be the left side in either kind of comparison. When that value is compared with a
string, it is limited to the 16 bytes a string can hold.

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
| `md5(xor(sha1_bin(pass), salt))` | the salt repeats over the 20 digest bytes |
| `hex(xor(md5_bin(pass), md5_bin(salt)))` | |
| `md5(rev(md5(pass)))` | |
| `sha1(pad(md5_bin(pass), 32))` | |

## John's dynamic formats

John the Ripper writes many of its formats as `$dynamic_N$` hashes. With `--dynamic-x`, hashcat
reads the format from the first hash and runs it in mode 4000 with the recipe for that format, so
neither `-m` nor `--hash-recipe` is needed:

```
hashcat --dynamic-x hashes.txt wordlist.txt
```

This covers John's built-in formats and the formats that ship in John's `dynamic.conf`, except
phpass and HTTP digest authentication. John's second salt (`$$2`) and user name (`$$U`) become the
`salt2` and `user` fields of the hash line. `--show`, `--left` and `--remove` write each hash back
in John's format.

Mode 4000 has no optimized kernels. With `-O`, a format that a hash-mode with optimized kernels also
computes runs in that hash-mode instead, such as mode 0 for `$dynamic_0$`. That hash-mode loads only
the lines it can parse. The two Cisco formats, `$dynamic_19$` and `$dynamic_20$`, always run in
modes 2400 and 2410.

Formats whose salt is binary, such as RADIUS, Telegram and net-md5, read it with `fromhex(salt)`.
A salt with a null byte loads that way, and it can hold up to 128 bytes. These formats have no
`-O` route.

A format that hashcat does not know, such as one defined in a local copy of `dynamic.conf`, can
still be loaded with `-m 4000` and a recipe for what it computes:

```
hashcat --dynamic-x -m 4000 --hash-recipe 'sha1(salt . md5(pass))' hashes.txt wordlist.txt
```

## Limits

- A recipe supports up to 8 hash calls, 8 concatenated parts per call and 4 strings. Each string
  can contain up to 16 bytes after its transforms are applied.
- A recipe supports up to 16 variables. Assignments cannot use the reserved names `pass`, `salt`,
  `salt2`, `pepper`, `user`, `iter`, `for`, `to`, `if` and `else`. The value `iter` can only be used
  as the last bound of a loop or as the iteration count of `pbkdf2`.
- A recipe supports one loop with integer bounds, running from 1 to 10000000 times. Up to 4
  variables can be carried through it. The body cannot yet read the loop counter. The self-test
  runs the loop on the host, so a long loop delays the start of the attack.
- A recipe supports up to 3 different cuts of its derived key, including a cut used as the
  recipe's result. A cut of the derived key's base64 form is not supported.
- A recipe supports one `pbkdf2` call and cannot combine it with a loop. Its key and salt must each
  be a single value, as required for a variable carried through a loop. The derived key's length
  must be a multiple of 4, from 4 to 64 bytes. When used as the result, the derived key must be at
  least 16 bytes long. The call runs from 1 to 10000000 iterations, or up to 999999999 when the
  count comes from the hash line.
- A comparison must be the last statement. It compares with `==`, or it is
  `length(aes_unwrap(kek, x)) > 0`. Both sides of `==` must have the same fixed length. For a
  comparison between 2 computed sides, each must be a single value of up to 64 bytes, as required for
  the values of `xor`.
- An AES call requires a `pbkdf2` call or a loop in the recipe. It cannot yet run inside the loop or
  provide input to `pbkdf2`. Its key must be 16, 24 or 32 bytes long, and its IV must be 16 bytes.
  ECB and CBC data must be 16 to 64 bytes long, a multiple of 16. The input to `aes_unwrap` must be
  16 to 72 bytes long, a multiple of 8. If its integrity check fails, `aes_unwrap` gives an all-zero
  key instead of hx's empty string.
- A loop up to `iter` has to start at 0 or 1. The hash line can give `iter` up to 999999999, and
  the self-test uses 1000.
- Passwords and salts can contain up to 256 bytes. Applying `hex`, `zext16` or `utf16be` reduces
  the limit for that input to 128 bytes.
- `salt2`, `pepper` and `user` can contain up to 84 bytes each. A transformed copy can lower that
  limit, as it does for passwords and salts. `fromhex`, `frombase64` and `base64` do not accept them
  yet.
- A recipe supports up to 4 transformed copies of `pass`, `salt` and the fields, such as
  `upper(pass)` or `pad(salt, 16)`, with up to 4 transforms per copy. `utf16le` must be the
  outermost transform.
- The transforms `rev`, `rotate`, `cap`, `rot13`, `pad`, `bswap32`, `wperm`, `zext16` and `utf16be`
  accept `pass`, `salt`, the fields, strings and hash outputs. Except for `rot13` and `zext16`,
  these transforms and `cut` accept a single element rather than a concatenation.
- A hash output, a variable carried through a loop or the derived key of `pbkdf2` can have up to 4
  transforms applied to it. The transformed result can contain up to 128 bytes, or up to 64 bytes
  before a final `hex` or `base64` encoding. Applying `utf16be` to raw bytes is not supported, nor
  is applying it to a carried variable that can hold raw bytes. Applying a transform to `utf16le`
  output is also unsupported.
- `pad` accepts N from 0 to 256. `wperm` accepts up to 16 word indices from 0 to 15. A word beyond
  the end of `x` contributes 4 zero bytes.
- `^N` accepts N from 1 to 100000.
- A `cut` of a hash output can start anywhere. One that does not start at a multiple of 4 bytes of
  that output is applied as a transform, which counts toward its 4 transforms. A `cut` of its
  `utf16le` form must preserve whole characters and start at a multiple of 4 bytes.
- The key of an `hmac_` call must be a single part: `pass`, `salt`, a transformed copy of either, a
  string or a hash call. Concatenations and `utf16le` keys are not supported. Keys longer than the
  hash family's block size are hashed first, as HMAC requires.
- `utf16le` accepts `pass`, `salt`, hex output and ASCII strings. It does not accept raw bytes or
  feed the BLAKE2 and Streebog families yet. A password or salt with invalid UTF-8 cannot match a
  recipe that applies `utf16le` to it.
- `utf16be` decodes UTF-8 strictly: overlong forms, surrogates, code points above U+10FFFF and
  truncated sequences make the result empty. A string given to `utf16be` in the recipe must be
  well-formed. `utf16be` cannot apply to a decoded salt or be inside `utf16le`.
- `xor`, `and` and `or` take 2 single values: `pass`, `salt`, a field, a transformed copy, a
  string, a hash call or a variable carried through a loop. A concatenation or a `utf16le` value
  is not supported. Each value can contain up to 64 bytes. Using `pass`, `salt` or a field as a
  value therefore limits that input to 64 bytes. The result has a fixed length when both values
  have fixed lengths, as hash calls, strings and copies such as `pad(salt, 16)` do. Only a result
  with a fixed length can be cut or used as the recipe's result. A variable carried through a loop
  whose length changes between iterations has no fixed length.
- The decoders `fromhex` and `frombase64` accept `salt` itself and strings. The decoder `fromhex`
  also accepts hex hash output. A recipe can decode its salt using only one encoding. Applying
  `utf16le` to a decoded salt is not supported. The hash line preserves the salt as encoded text. A
  salt with invalid hex or base64 is rejected when the hash file is loaded. A string with an invalid
  encoding in the recipe is rejected at startup.
- `base64` accepts hash outputs and strings, not `pass`, `salt` or a concatenation. Applied to
  anything but a whole `_bin` output, as in `base64(md5(pass))`, it has to be the outermost
  transform of that output. `fromhex` does not accept base64 output.
- The result must be a hash, AES, `xor`, `and` or `or` call in hex or base64, optionally wrapped in
  `upper`, `lower`, `hex`, `base64`, `cut` or `trunc`. It must retain at least the first 32 hex
  characters or 22 base64 characters. A `pbkdf2` call or a variable carried through a loop can be
  the result as well, wrapped in `hex` or `base64` of raw bytes or in `upper` or `lower` of hex. A
  `pbkdf2` call can also be cut. See [Key derivation](#key-derivation). Such a cut can start at any
  offset that is a multiple of 4 bytes. A transformed hash output, carried variable or derived key
  can be the result when its transforms end in `hex` or `base64` and its length is fixed, as in
  `hex(rev(md5_bin(pass)))`. The result can also be a comparison. See [Comparisons](#comparisons).

## Not supported yet

Mode 4000 supports only part of hx. It does not support nested or several loops, `if`, `emit`, key
derivation other than `pbkdf2`, ciphers other than AES or character encodings other than `utf16le`
and `utf16be`. Hash families that are not listed under [Syntax](#syntax) are also unsupported.
`length` is supported only in `length(aes_unwrap(kek, x)) > 0`. A recipe that uses an unsupported
feature is rejected at startup with the reason and position of the error.

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

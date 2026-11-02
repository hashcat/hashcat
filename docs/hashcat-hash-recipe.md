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

On Windows it is the other way round. Quote the recipe with double quotes and write strings inside
it with single quotes, which works in cmd and in PowerShell:

```
hashcat -m 4000 --hash-recipe "md5('abc' . pass)" hashes.txt wordlist.txt
```

Windows PowerShell 5.1 removes double quotes inside an argument before hashcat receives it, so the
Unix form `'md5("abc" . pass)'` arrives without its string quotes and is rejected.

Both shells still act on a few characters inside double quotes. PowerShell expands `$name` and
backtick escapes, and cmd expands `%NAME%`. A recipe holding a `$` needs it written as `` `$ `` in
PowerShell, as in `` "md5('`$1' . pass)" ``.

## Hash line

Each hash line contains the recipe's output, followed by `*` and the salt. The output uses hex
unless the recipe produces a base64 result. In that case, it uses base64. A result of raw bytes,
such as `sha256_bin(salt . pass)`, is written in hex, as hx writes binary output. For a recipe that
does not use a salt, the `*` after the digest is optional, so the second and third lines are the
same hash:

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

Only the first 16 bytes of the digest are compared, but the line holds the whole result, which
takes up to 512 characters for a long `pbkdf2` key. A shorter result, such as the 8 bytes of
`mysql3(pass)` or the last 16 hex characters that `cut(md5(md5(pass) . salt), -16)` keeps, is
compared in full. A result needs at least 8 bytes, because a shorter one would match too many
candidates by chance. Cracking accepts either hex case, and base64 with or without `=` padding.
The outfile and output from `--show` preserve the original hash line. Because hex compares in
either case, `cap`, `upper` and `lower` around a hex result, as in `cap(md5(pass))`, do not change
which lines crack.

Strings before and after the result are part of each hash line. With
`"{SHA}" . base64(sha1_bin(pass))`, every line starts with `{SHA}`, and a line without it is
rejected. Only the computed part is compared. The outfile, the potfile and `--show` write the strings
back, so they reproduce the original line. This line is MySQL's hash of the password `hashcat`,
with the recipe `"*" . upper(sha1(sha1_bin(pass)))`:

```
*FCF7C1B8749CF99D88E5F34271D636178FB5D130
```

LDAP's `{SSHA}` stores base64 of the digest followed by the salt. With
`"{SSHA}" . base64(sha1_bin(pass . salt) . salt)`, a hash line needs no salt field, because the
salt is the part of the decoded text after the digest. A line can still give the salt after a `*`,
and it must then match. The password `hashcat` cracks this line:

```
{SSHA}FLzWcQqyle6Mo7NvrwXCMAmRzXQxNjYxMTYzNw==
```

Such a line in the potfile or with further fields leaves the salt field empty, as in
`{SSHA}FLzWcQqyle6Mo7NvrwXCMAmRzXQxNjYxMTYzNw==*`.

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
| `mysql3(x)` | The password hash of MySQL before 4.1, 8 bytes as lowercase hex. It skips spaces and tabs as MySQL does. It can be the result, as in mode 200, or appear inside another call, as in `md5(mysql3(pass))`. It has no `hmac_` form |
| `lm(x)` | The LM hash, 16 bytes as lowercase hex. It keeps the first 14 bytes of `x`, converts ASCII letters to uppercase and pads with zero bytes. Each half of 7 bytes is a DES key that encrypts `KGS!@#$%`. It has no `hmac_` form |
| `mdc2(x)` | MDC-2 with DES, 16 bytes as lowercase hex, as OpenSSL computes it. It has no `hmac_` form, because its 8-byte block is shorter than its digest |
| `sne128(x)` `sne256(x)` | Snefru-128 and Snefru-256 with 8 rounds, as lowercase hex. `snefru128(x)` and `snefru256(x)` are the same calls. Their HMAC blocks are 48 and 32 bytes, the data each block takes |
| `skein224(x)` `skein256(x)` `skein384(x)` `skein512(x)` | Skein-512 (Skein 1.3) with a digest of 224, 256, 384 or 512 bits, as lowercase hex. The Skein paper calls these Skein-512-224 to Skein-512-512 |
| `panama(x)` | PANAMA in the little endian convention, as lowercase hex. Its HMAC block is 32 bytes |
| `blake224(x)` `blake256(x)` `blake384(x)` `blake512(x)` | BLAKE, the SHA-3 finalist, with a digest of 224, 256, 384 or 512 bits, as lowercase hex. It is not BLAKE2 |
| `bmw224(x)` `bmw256(x)` `bmw384(x)` `bmw512(x)` | Blue Midnight Wish with the tweak of the second SHA-3 round, as lowercase hex |
| `cube224(x)` `cube256(x)` `cube384(x)` `cube512(x)` | CubeHash16/32, as lowercase hex. Its HMAC block is 32 bytes. A longer key is hashed first, and for `cube384` and `cube512` the pads then cover all 48 or 64 bytes of the hashed key |
| `echo224(x)` `echo256(x)` `echo384(x)` `echo512(x)` | ECHO, as lowercase hex. Its HMAC blocks are 192 bytes for `echo224` and `echo256` and 128 bytes for `echo384` and `echo512` |
| `fugue224(x)` `fugue256(x)` `fugue384(x)` `fugue512(x)` | Fugue, as lowercase hex. It has no `hmac_` form |
| `groestl224(x)` `groestl256(x)` `groestl384(x)` `groestl512(x)` | Groestl, as lowercase hex |
| `hamsi224(x)` `hamsi256(x)` `hamsi384(x)` `hamsi512(x)` | Hamsi, as lowercase hex. It has no `hmac_` form |
| `jh224(x)` `jh256(x)` `jh384(x)` `jh512(x)` | JH in the version of the third SHA-3 round, as lowercase hex |
| `luffa224(x)` `luffa256(x)` `luffa384(x)` `luffa512(x)` | Luffa, as lowercase hex. Its HMAC block is 32 bytes, and a hashed key keeps all of its bytes, as for CubeHash |
| `shabal224(x)` `shabal256(x)` `shabal384(x)` `shabal512(x)` | Shabal, as lowercase hex |
| `shavite224(x)` `shavite256(x)` `shavite384(x)` `shavite512(x)` | SHAvite-3 with the tweak of the second SHA-3 round, as lowercase hex |
| `simd224(x)` `simd256(x)` `simd384(x)` `simd512(x)` | SIMD, as lowercase hex |
| `has160(x)` | HAS-160, as lowercase hex |
| `edon256(x)` `edon512(x)` | EDON-R with 256 or 512 bits, as lowercase hex |
| `md6(x)` `md6256(x)` `md6512(x)` | MD6 with the default parameters and a digest of 128, 256 or 512 bits, as lowercase hex. `md6128(x)` is the same call as `md6(x)`. It has no `hmac_` form |
| `radiogatun32(x)` `radiogatun64(x)` | RadioGatun with 32 or 64 bit words, as lowercase hex. `radiogatun32` gives the first 16 bytes of the RadioGatun[32] digest, as hx does, and `radiogatun64` all 32 bytes of the RadioGatun[64] digest. They have no `hmac_` form |
| `ripemd(x)` | The original RIPEMD with 128 bits, as lowercase hex. It differs from RIPEMD-128, which is `rmd128(x)` |
| `wrl0(x)` `wrl1(x)` | Whirlpool-0 and Whirlpool-T, the 2 versions that preceded Whirlpool, as lowercase hex |
| `gost(x)` `gost_crypto(x)` | GOST R 34.11-94, as lowercase hex. `gost` uses the S-box of the test parameter set, as hashcat's mode 6900 does. `gost_crypto` uses the S-box of the CryptoPro parameter set |
| `md5_bin(x)` | The digest as raw bytes |
| `md5_hex(x)` | Lowercase hex, the same as `md5(x)` |
| `md5_uc(x)` | Uppercase hex |
| `md5_b64(x)` | Standard base64 of the digest, with `=` padding |
| `pbkdf2_sha256(key, salt, N, len)` | PBKDF2 with HMAC-SHA256, N iterations and a derived key of len bytes, as lowercase hex. The variants `pbkdf2_md5`, `pbkdf2_sha1` and `pbkdf2_sha512` use the other families. All 4 variants accept the same output suffixes as a hash call, as in `pbkdf2_sha1_bin`. See [Key derivation](#key-derivation) |
| `aes_cbc_decrypt(key, iv, x)` | AES-CBC decryption of `x`, as lowercase hex. A key of 16, 24 or 32 bytes selects AES-128, AES-192 or AES-256. No padding is added or removed. The calls `aes_cbc_encrypt(key, iv, x)` and `aes_ecb_encrypt(key, x)` encrypt data. The call `aes_unwrap(kek, x)` unwraps a key according to RFC 3394. All 4 calls accept the same output suffixes as a hash call. See [Ciphers](#ciphers) |
| `des(key, x)` | DES encryption of one 8-byte block, as lowercase hex. It encrypts the first 8 bytes of `x` with the first 8 bytes of `key`, each padded with zero bytes if shorter. `des3(key, x)` takes the first 24 bytes of `key` as 3 keys and encrypts, decrypts and encrypts with them. `des_block(key, x)` spreads the first 7 bytes of `key` over the 8 bytes of a DES key, as NetNTLMv1 does. All 3 calls accept the same output suffixes as a hash call. See [Ciphers](#ciphers) |
| `hmac_md5(key, x)` | HMAC of `x` with `key`. All families except `mysql3`, `tth`, `lm`, `mdc2`, Fugue, Hamsi, MD6 and RadioGatun support HMAC with the same suffixes, as in `hmac_sha256_bin(key, x)`. Fugue, Hamsi and RadioGatun take blocks shorter than their digest, and MD6 is a tree hash. The alias `hmac_blake2s` means `hmac_blake2s256`. SHA-3 and Keccak use their rate as the HMAC block, GOST R 34.11-94 its 32-byte block and MD2 its 16-byte block. `hmac_streebog256` and `hmac_streebog512` give the results of hashcat's modes 40027 to 40030 |
| `md5^3(x)` | Equivalent to `md5(md5(md5(x)))`. The suffix sets the output format for each round. For example, `md5_bin^3` chains raw bytes and `md5_uc^3` chains uppercase hex |
| `upper(x)`, `lower(x)` | Converts ASCII letters to uppercase or lowercase. Applying `upper` to `md5^3(x)` changes only the final result, while `md5_uc^3(x)` uses uppercase hex in every round |
| `hex(x)` | Encodes raw bytes as hex. For example, `hex(md5_bin(x))` is equivalent to `md5(x)` |
| `base64(x)` | Encodes raw bytes as standard base64 with `=` padding. For example, `base64(md5_bin(x))` is equivalent to `md5_b64(x)` |
| `fromhex(x)` | Decodes hex to bytes. For example, `fromhex(md5(x))` is equivalent to `md5_bin(x)`. See [Limits](#limits) for input that is not valid hex |
| `frombase64(x)` | Decodes standard base64 to bytes. The `=` padding is optional. See [Limits](#limits) for input that is not valid base64 |
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
transforms `upper`, `lower`, `hex`, `rot13`, `zext16` and `utf16le` act on each element. `cut` and
`trunc` select bytes of the whole concatenation, as in
`md5(cut("*" . upper(sha1(sha1_bin(pass))), 0, 40))`. See [Limits](#limits) for the elements they
accept.

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

The key and the salt can each be `utf16le` of a single value. This recipe computes DCC2, as
hashcat's mode 2100 does, with the user name as the salt:

```
pbkdf2_sha1(md4_bin(md4_bin(utf16le(pass)) . utf16le(lower(salt))), utf16le(lower(salt)), iter, 16)
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
and lengths counted in hex characters. The result must retain at least 8 bytes. Both examples below
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

The key can be up to 256 bytes long, as in macOS's `pbkdf2_sha512(pass, salt, iter, 128)`. The
bytes the recipe reads have to lie within 64 bytes from the start of the first block they touch.
A call or transform that reads the whole key therefore needs a key of up to 64 bytes, while the
whole key as the result and cuts within one such range work for any length. The hash line holds the
whole key as hx writes it, 256 hex characters for this example.

## Ciphers

AES calls run in every kernel, with or without a loop or `pbkdf2`. This example encrypts the block
stored in hex in the salt with the password, padded with zero bytes to 16 bytes, as the AES-128 key:

```
aes_ecb_encrypt(pad(pass, 16), fromhex(salt))
```

When the salt is stored in hex, `cut` separates its fields according to the format. This example
derives a key from the first 8 bytes. It decrypts the last 16 bytes using the IV stored between
them. The hash line contains the plaintext produced by the correct password:

```
dk = pbkdf2_sha1_bin(pass, cut(fromhex(salt), 0, 8), iter, 16)
aes_cbc_decrypt(dk, cut(fromhex(salt), 8, 16), cut(fromhex(salt), 24, 16))
```

The key, IV and each data part must have fixed lengths. They can be `_bin` hash calls, `pbkdf2`,
strings, a `cut` with a specified length, a `pad`, or a variable assigned a hash call in a loop. If
a part is shorter on a particular hash line, it is padded with zero bytes to its fixed length. This
includes a salt that is too short for the range selected by its `cut`.

One part of the data can instead be `salt`, `fromhex(salt)` or `frombase64(salt)` at its own
length, as in the first example. The output then has the length of the data, which depends on the
salt. A hash line whose salt gives the data a length the call cannot take is rejected when the hash
file is loaded. The self-test uses a salt of the shortest length that suits every such call.

DES calls run in every kernel, with or without a loop or `pbkdf2`. Their key and their data are
single values, as for `xor`. Their output of 8 bytes can be the result, which mode 4000 then
compares in full, or appear inside another call or on the left side of a comparison. This example
encrypts the plaintext stored in hex in the salt with the password as the key:

```
des(pass, fromhex(salt))
```

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

The left side is a `_bin` hash, AES or DES call, or a `cut` of one that starts at a multiple of 4
bytes. The right side is a string, decoded with `fromhex` or `frombase64` if needed, of the same
length and at least 8 bytes long. Mode 4000 compares the first 16 bytes of both.

Both sides can also be computed, as in `cut(sha256_bin(pass), 0, 16) == md5_bin(salt . pass)`. In
this form, each side must be a single value, as required for `xor`, and both must have the same
fixed length of at least 8 bytes. A salt has a fixed length only when a transform sets it, such as
`cut(pad(fromhex(salt), 16), 0, 16)`. A variable carried through a loop, a `pbkdf2` key or a `cut`
of either can be the left side in either kind of comparison. When that value is compared with a
string, it is limited to the 64 bytes a string can hold.

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
| `hmac_sha1_b64(utf16le(pass), utf16le(pass))` | mode 24800 |
| `md5(pad(pass, 100))` | mode 9900 |
| `md5(md5(salt) . pass)` | |
| `sha256("#" . salt . "-" . pass)` | |
| `sha224(sha224_bin(pass))` | |
| `trunc(sha512(pass), 32)` | the first 32 hex characters of a SHA-512 digest |
| `cut(md5(md5(pass) . salt), -16)` | the last 16 hex characters of the digest |
| `sha1(upper(pass) . salt)` | |
| `sha1(utf16le(pass) . frombase64(salt))` | a salt stored in base64 |
| `sha256(pass . fromhex(salt))` | a salt stored in hex |
| `h = md5(salt); md5(h . pass)` | `md5(md5(salt) . pass)` |
| `"{SHA}" . sha1_b64(pass)` | mode 101 |
| `"{SSHA}" . base64(sha1_bin(pass . salt) . salt)` | mode 111 |
| `"*" . upper(sha1(sha1_bin(pass)))` | mode 300 with MySQL's leading `*` |
| `sha256_bin(salt . pass)` | mode 1420, the hash line holds the raw digest in hex |
| `mysql3(pass)` | mode 200 |
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

## Hash-modes with a stored recipe

Many of hashcat's own hash-modes compute their hash with a recipe stored in the hash-mode, rather
than with a kernel of their own. Hash-mode 1450, for example, runs `hmac_sha256(pass, salt)`. Such
a hash-mode reads its own hash format and needs no `--hash-recipe`. Its pure kernels are the recipe
kernels of mode 4000. Where the hash-mode also has optimized kernels, `-O` runs those instead.

Hash-modes 40000 to 44000 are reserved for hash-modes that are defined only by a stored recipe and
have no optimized kernels. A new hash-mode of that kind takes the next free number in this range.

The existing hash-modes of that kind moved into this range. Their old numbers still work with `-m`
and are never given to another hash-mode. `-hh`, `--identify`, `--example-hashes` and
`--benchmark-all` list only the new numbers, and a hash-mode detected without `-m` runs under its
new number.

| Old | New | Name |
|---|---|---|
| 1310 | 40009 | `sha224($pass.$salt)` |
| 1320 | 40010 | `sha224($salt.$pass)` |
| 5200 | 40011 | `Password Safe v3` |
| 5720 | 40012 | `Cisco-ISE Hashed Password (SHA256)` |
| 6050 | 40013 | `HMAC-RIPEMD160 (key = $pass)` |
| 6060 | 40014 | `HMAC-RIPEMD160 (key = $salt)` |
| 6400 | 40015 | `AIX {ssha256}` |
| 6500 | 40016 | `AIX {ssha512}` |
| 6700 | 40017 | `AIX {ssha1}` |
| 7100 | 40018 | `macOS v10.8+ (PBKDF2-SHA512)` |
| 7200 | 40019 | `GRUB 2` |
| 7900 | 40020 | `Drupal7` |
| 9200 | 40021 | `Cisco-IOS $8$ (PBKDF2-SHA256)` |
| 10000 | 40022 | `Django (PBKDF2-SHA256)` |
| 10300 | 40023 | `SAP CODVN H (PWDSALTEDHASH) iSSHA-1` |
| 10900 | 40024 | `PBKDF2-HMAC-SHA256` |
| 10901 | 40025 | `RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)` |
| 11000 | 40026 | `PrestaShop` |
| 11750 | 40027 | `HMAC-Streebog-256 (key = $pass), big-endian` |
| 11760 | 40028 | `HMAC-Streebog-256 (key = $salt), big-endian` |
| 11850 | 40029 | `HMAC-Streebog-512 (key = $pass), big-endian` |
| 11860 | 40030 | `HMAC-Streebog-512 (key = $salt), big-endian` |
| 11900 | 40031 | `PBKDF2-HMAC-MD5` |
| 12000 | 40032 | `PBKDF2-HMAC-SHA1` |
| 12001 | 40033 | `Atlassian (PBKDF2-HMAC-SHA1)` |
| 12100 | 40034 | `PBKDF2-HMAC-SHA512` |
| 12150 | 40035 | `Apache Shiro 1 SHA-512` |
| 12300 | 40036 | `Oracle T: Type (Oracle 12+)` |
| 12800 | 40037 | `MS-AzureSync PBKDF2-HMAC-SHA256` |
| 15100 | 40038 | `Juniper/NetBSD sha1crypt` |
| 18500 | 40039 | `sha1(md5(md5($pass)))` |
| 18800 | 40040 | `Blockchain, My Wallet, Second Password (SHA256)` |
| 19210 | 40041 | `QNX 7 /etc/shadow (SHA512)` |
| 20200 | 40042 | `Python passlib pbkdf2-sha512` |
| 20300 | 40043 | `Python passlib pbkdf2-sha256` |
| 20400 | 40044 | `Python passlib pbkdf2-sha1` |
| 20600 | 40045 | `Oracle Transportation Management (SHA256)` |
| 20720 | 40046 | `sha256($salt.sha256($pass))` |
| 20730 | 40047 | `sha256(sha256($pass.$salt))` |
| 21300 | 40048 | `md5($salt.sha1($salt.$pass))` |
| 21420 | 40049 | `sha256($salt.sha256_bin($pass))` |
| 21600 | 40050 | `Web2py pbkdf2-sha512` |
| 22800 | 40051 | `Simpla CMS - md5($salt.$pass.md5($pass))` |
| 23200 | 40052 | `XMPP SCRAM PBKDF2-SHA1` |
| 24200 | 40053 | `MongoDB ServerKey SCRAM-SHA-256` |
| 26300 | 40054 | `FortiGate256 (FortiOS256)` |
| 28600 | 40055 | `PostgreSQL SCRAM-SHA-256` |
| 29100 | 40056 | `Flask Session Cookie ($salt.$salt.$pass)` |
| 32000 | 40057 | `NetIQ SSPR (MD5)` |
| 32010 | 40058 | `NetIQ SSPR (SHA1)` |
| 32020 | 40059 | `NetIQ SSPR (SHA-1 with Salt)` |
| 32030 | 40060 | `NetIQ SSPR (SHA-256 with Salt)` |
| 32031 | 40061 | `Adobe AEM (SSPR, SHA-256 with Salt)` |
| 32040 | 40062 | `NetIQ SSPR (SHA-512 with Salt)` |
| 32041 | 40063 | `Adobe AEM (SSPR, SHA-512 with Salt)` |
| 32050 | 40064 | `NetIQ SSPR (PBKDF2WithHmacSHA1)` |
| 32060 | 40065 | `NetIQ SSPR (PBKDF2WithHmacSHA256)` |
| 32070 | 40066 | `NetIQ SSPR (PBKDF2WithHmacSHA512)` |
| 32410 | 40067 | `sha512(sha512($pass).$salt)` |
| 32420 | 40068 | `sha512(sha512_bin($pass).$salt)` |
| 32600 | 40069 | `CubeCart (whirlpool($salt.$pass.$salt))` |
| 32900 | 40070 | `PBKDF1-SHA1` |
| 33100 | 40071 | `md5($salt.md5($pass).$salt)` |
| 33300 | 40072 | `HMAC-BLAKE2S (key = $pass)` |
| 33650 | 40073 | `HMAC-RIPEMD320 (key = $pass)` |
| 33660 | 40074 | `HMAC-RIPEMD320 (key = $salt)` |
| 33900 | 40075 | `Citrix NetScaler (PBKDF2-HMAC-SHA256)` |
| 34400 | 40076 | `sha224(sha224($pass))` |
| 34500 | 40077 | `sha224(sha1($pass))` |
| 35000 | 40078 | `SAP CODVN H (PWDSALTEDHASH) isSHA512` |
| 35700 | 40079 | `phpass(md5($pass))` |
| 36500 | 40080 | `NTLM(NTLM_bin($pass))` |
| 37300 | 40081 | `SAP CODVN H (PWDSALTEDHASH) iSSHA-256` |
| 37301 | 40082 | `SAP CODVN H (PWDSALTEDHASH) iSSHA-384` |

Every hash function of the recipe language that has no hash-mode of its own also has a raw hash-mode,
which hashes the password alone and takes the hex digest as its hash line. These are hash-modes 40084
to 40175, so they appear in `-hh` and `--example-hashes` like any other hash-mode.
MD6-256 is not among them, because hash-mode 34600 already covers it and uses `md6256(pass)` for its
pure kernels.

| Mode | Name | Recipe |
|---|---|---|
| 40084 | `MD2` | `md2(pass)` |
| 40085 | `SHA-0` | `sha0(pass)` |
| 40086 | `RIPEMD-128` | `rmd128(pass)` |
| 40087 | `RIPEMD-256` | `rmd256(pass)` |
| 40088 | `GOST R 34.11-94 (CryptoPro)` | `gost_crypto(pass)` |
| 40089 | `Tiger` | `tiger(pass)` |
| 40090 | `Tiger-128` | `tiger128(pass)` |
| 40091 | `Tiger-160` | `tiger160(pass)` |
| 40092 | `Tiger2` | `tiger2(pass)` |
| 40093 | `TTH (Tiger Tree Hash, single leaf)` | `tth(pass)` |
| 40094 | `Snefru-128` | `sne128(pass)` |
| 40095 | `Snefru-256` | `sne256(pass)` |
| 40096 | `Skein-512-224` | `skein224(pass)` |
| 40097 | `Skein-512-256` | `skein256(pass)` |
| 40098 | `Skein-512-384` | `skein384(pass)` |
| 40099 | `Skein-512-512` | `skein512(pass)` |
| 40100 | `PANAMA` | `panama(pass)` |
| 40101 | `MDC-2` | `mdc2(pass)` |
| 40102 | `HAVAL-128 (3 passes)` | `hav128(pass)` |
| 40103 | `HAVAL-128 (4 passes)` | `hav128_4(pass)` |
| 40104 | `HAVAL-128 (5 passes)` | `hav128_5(pass)` |
| 40105 | `HAVAL-160 (3 passes)` | `hav160_3(pass)` |
| 40106 | `HAVAL-160 (4 passes)` | `hav160_4(pass)` |
| 40107 | `HAVAL-160 (5 passes)` | `hav160_5(pass)` |
| 40108 | `HAVAL-192 (3 passes)` | `hav192_3(pass)` |
| 40109 | `HAVAL-192 (4 passes)` | `hav192_4(pass)` |
| 40110 | `HAVAL-192 (5 passes)` | `hav192_5(pass)` |
| 40111 | `HAVAL-224 (3 passes)` | `hav224_3(pass)` |
| 40112 | `HAVAL-224 (4 passes)` | `hav224_4(pass)` |
| 40113 | `HAVAL-224 (5 passes)` | `hav224_5(pass)` |
| 40114 | `HAVAL-256 (3 passes)` | `hav256(pass)` |
| 40115 | `HAVAL-256 (4 passes)` | `hav256_4(pass)` |
| 40116 | `HAVAL-256 (5 passes)` | `hav256_5(pass)` |
| 40117 | `BLAKE-224` | `blake224(pass)` |
| 40118 | `BLAKE-256` | `blake256(pass)` |
| 40119 | `BLAKE-384` | `blake384(pass)` |
| 40120 | `BLAKE-512` | `blake512(pass)` |
| 40121 | `BMW-224` | `bmw224(pass)` |
| 40122 | `BMW-256` | `bmw256(pass)` |
| 40123 | `BMW-384` | `bmw384(pass)` |
| 40124 | `BMW-512` | `bmw512(pass)` |
| 40125 | `CubeHash-224` | `cube224(pass)` |
| 40126 | `CubeHash-256` | `cube256(pass)` |
| 40127 | `CubeHash-384` | `cube384(pass)` |
| 40128 | `CubeHash-512` | `cube512(pass)` |
| 40129 | `ECHO-224` | `echo224(pass)` |
| 40130 | `ECHO-256` | `echo256(pass)` |
| 40131 | `ECHO-384` | `echo384(pass)` |
| 40132 | `ECHO-512` | `echo512(pass)` |
| 40133 | `Fugue-224` | `fugue224(pass)` |
| 40134 | `Fugue-256` | `fugue256(pass)` |
| 40135 | `Fugue-384` | `fugue384(pass)` |
| 40136 | `Fugue-512` | `fugue512(pass)` |
| 40137 | `Groestl-224` | `groestl224(pass)` |
| 40138 | `Groestl-256` | `groestl256(pass)` |
| 40139 | `Groestl-384` | `groestl384(pass)` |
| 40140 | `Groestl-512` | `groestl512(pass)` |
| 40141 | `Hamsi-224` | `hamsi224(pass)` |
| 40142 | `Hamsi-256` | `hamsi256(pass)` |
| 40143 | `Hamsi-384` | `hamsi384(pass)` |
| 40144 | `Hamsi-512` | `hamsi512(pass)` |
| 40145 | `JH-224` | `jh224(pass)` |
| 40146 | `JH-256` | `jh256(pass)` |
| 40147 | `JH-384` | `jh384(pass)` |
| 40148 | `JH-512` | `jh512(pass)` |
| 40149 | `Luffa-224` | `luffa224(pass)` |
| 40150 | `Luffa-256` | `luffa256(pass)` |
| 40151 | `Luffa-384` | `luffa384(pass)` |
| 40152 | `Luffa-512` | `luffa512(pass)` |
| 40153 | `Shabal-224` | `shabal224(pass)` |
| 40154 | `Shabal-256` | `shabal256(pass)` |
| 40155 | `Shabal-384` | `shabal384(pass)` |
| 40156 | `Shabal-512` | `shabal512(pass)` |
| 40157 | `SHAvite-3-224` | `shavite224(pass)` |
| 40158 | `SHAvite-3-256` | `shavite256(pass)` |
| 40159 | `SHAvite-3-384` | `shavite384(pass)` |
| 40160 | `SHAvite-3-512` | `shavite512(pass)` |
| 40161 | `SIMD-224` | `simd224(pass)` |
| 40162 | `SIMD-256` | `simd256(pass)` |
| 40163 | `SIMD-384` | `simd384(pass)` |
| 40164 | `SIMD-512` | `simd512(pass)` |
| 40165 | `HAS-160` | `has160(pass)` |
| 40166 | `EDON-R-256` | `edon256(pass)` |
| 40167 | `EDON-R-512` | `edon512(pass)` |
| 40168 | `MD6-128` | `md6(pass)` |
| 40170 | `MD6-512` | `md6512(pass)` |
| 40171 | `RadioGatun[32] (first 128 bits)` | `radiogatun32(pass)` |
| 40172 | `RadioGatun[64]` | `radiogatun64(pass)` |
| 40173 | `RIPEMD (original)` | `ripemd(pass)` |
| 40174 | `Whirlpool-0` | `wrl0(pass)` |
| 40175 | `Whirlpool-T` | `wrl1(pass)` |

## Limits

- A recipe supports up to 16 hash, AES, DES, `xor`, `and` and `or` calls, 8 concatenated parts per
  call and 4 strings. A transform of a hash output that its call cannot apply itself, such as `rev`
  in `rev(md5(pass))`, counts as a call. Each string can contain up to 128 bytes as written and up
  to 64 bytes after its transforms are applied, so `fromhex` can give a string of 64 bytes. A recipe
  holds up to 160 elements, where each call, concatenation, string, transform and use of `pass`,
  `salt` or a field counts as one. The recipe's kernel build options can take up to 12000 bytes,
  which 16 calls exceed only with many transforms, parts or long strings. A recipe that needs more
  is rejected at startup.
- A recipe supports up to 16 variables. Assignments cannot use the reserved names `pass`, `salt`,
  `salt2`, `pepper`, `user`, `iter`, `for`, `to`, `if` and `else`. The value `iter` can only be used
  as the last bound of a loop or as the iteration count of `pbkdf2`.
- A recipe supports one loop with integer bounds, running from 1 to 10000000 times. Up to 4
  variables can be carried through it. The body cannot yet read the loop counter. The self-test
  runs the loop on the host, so a long loop delays the start of the attack.
- A recipe supports up to 3 different cuts of its derived key, including a cut used as the
  recipe's result. A cut of the derived key's base64 form is not supported.
- A recipe supports one `pbkdf2` call and cannot combine it with a loop. Its key and salt must each
  be a single value, as required for a variable carried through a loop, or `utf16le` of one. The
  derived key's length must be a multiple of 4, from 4 to 256 bytes. The bytes the recipe reads
  must lie within 64 bytes from the start of the first hash block they touch, so a call can read a
  whole key of up to 64 bytes. When used as the result, the derived key must be at least 8 bytes
  long. The call runs from 1 to 10000000 iterations, or up to 999999999 when the count comes from
  the hash line.
- A comparison must be the last statement. It compares with `==`, or it is
  `length(aes_unwrap(kek, x)) > 0`. Both sides of `==` must have the same fixed length. For a
  comparison between 2 computed sides, each must be a single value of up to 64 bytes, as required for
  the values of `xor`.
- An AES call cannot yet run inside a loop or provide input to `pbkdf2`. Its key must be 16, 24 or
  32 bytes long, and its IV must be 16 bytes. ECB and CBC data must be 16 to 64 bytes long, a
  multiple of 16. The input to `aes_unwrap` must be 16 to 72 bytes long, a multiple of 8. If its
  integrity check fails, `aes_unwrap` gives an all-zero key instead of hx's empty string.
- The data of an AES call can hold one part of the salt's length, `salt`, `fromhex(salt)` or
  `frombase64(salt)`. A salt that leaves the data at a length the call cannot take is rejected when
  the hash file is loaded, where hx would give an empty result. As the result, `aes_unwrap` then
  needs at least 24 bytes of data, for the 16 bytes mode 4000 compares. Such a call cannot be cut,
  be the left side of `==`, be followed by `salt` in a base64 result, or provide the key, IV or data
  of another AES call.
- `des`, `des3` and `des_block` take 2 single values, the key and the data: `pass`, `salt`, a
  field, a transformed copy, a string, a hash call or a variable carried through a loop. A
  concatenation or a `utf16le` value is not supported.
- A loop up to `iter` has to start at 0 or 1. The hash line can give `iter` up to 999999999, and
  the self-test uses 1000.
- Passwords and salts can contain up to 256 bytes. Applying `hex`, `zext16` or `utf16be` reduces
  the limit for that input to 128 bytes, and applying `base64` reduces it to 192 bytes. Each
  further transform that grows the value lowers the limit again, so `base64(base64(pass))` takes
  passwords of up to 144 bytes.
- `salt2`, `pepper` and `user` can contain up to 84 bytes each. A transformed copy can lower that
  limit, as it does for passwords and salts.
- A recipe supports up to 4 transformed copies of `pass`, `salt` and the fields, such as
  `upper(pass)` or `pad(salt, 16)`, with up to 4 transforms per copy. `utf16le` must be the
  outermost transform.
- The transforms `rev`, `rotate`, `cap`, `rot13`, `pad`, `bswap32`, `wperm`, `zext16` and `utf16be`
  accept `pass`, `salt`, the fields, strings and hash outputs. Except for `rot13` and `zext16`,
  these transforms accept a single element rather than a concatenation.
- `cut` and `trunc` of a concatenation need fixed lengths for the elements up to the end of the cut,
  as strings and hash calls have, and for every element when the start counts from the end. An
  element past the end is left out, and a cut without a length keeps the rest whole, so
  `cut("ab" . pass, 1)` works. A concatenation can have one such cut. A carried variable is not a
  fixed-length element yet.
- A hash output, a variable carried through a loop or the derived key of `pbkdf2` can have up to 4
  transforms applied to it. The transformed result can contain up to 128 bytes, or up to 64 bytes
  before a final `hex` or `base64` encoding, and no transform on the way can make it longer than 256
  bytes. Applying `utf16be` to raw bytes is not supported, nor is applying it to a carried variable
  that can hold raw bytes. Applying a transform to `utf16le` output is also unsupported.
- `pad` accepts N from 0 to 256. `wperm` accepts up to 16 word indices from 0 to 15. A word beyond
  the end of `x` contributes 4 zero bytes.
- `^N` accepts N from 1 to 100000.
- A `cut` of a hash output can start anywhere. One that does not start at a multiple of 4 bytes of
  that output is applied as a transform, which counts toward its 4 transforms. A `cut` of its
  `utf16le` form must preserve whole characters and start at a multiple of 4 bytes.
- The key of an `hmac_` call must be a single part: `pass`, `salt`, a field, a transformed copy of
  one of them, a string or a hash call, or `utf16le` of one of these. Concatenations are not
  supported. Keys longer than the hash family's block size are hashed first, as HMAC requires. For a
  `utf16le` key, that is the length of its UTF-16LE form.
- `utf16le` accepts `pass`, `salt`, hex output and ASCII strings. It does not accept raw bytes or
  feed the BLAKE2 and Streebog families yet, not even as an HMAC key. A password or salt with
  invalid UTF-8 cannot match a recipe that applies `utf16le` to it, including as an HMAC key or as
  the key or salt of `pbkdf2`.
- `utf16be` decodes UTF-8 strictly: overlong forms, surrogates, code points above U+10FFFF and
  truncated sequences make the result empty. A string given to `utf16be` in the recipe must be
  well-formed. `utf16be` cannot apply to a decoded salt, password or field or be inside `utf16le`.
- `xor`, `and` and `or` take 2 single values: `pass`, `salt`, a field, a transformed copy, a
  string, a hash call or a variable carried through a loop. A concatenation or a `utf16le` value
  is not supported. Each value can contain up to 64 bytes. Using `pass`, `salt` or a field as a
  value therefore limits that input to 64 bytes. The result has a fixed length when both values
  have fixed lengths, as hash calls, strings and copies such as `pad(salt, 16)` do. Only a result
  with a fixed length can be cut or used as the recipe's result. A variable carried through a loop
  whose length changes between iterations has no fixed length.
- The decoders `fromhex` and `frombase64` accept `pass`, `salt` itself, the fields, strings and hex
  hash output. `frombase64` also accepts a whole base64 hash output. `fromhex` accepts any
  transformed hash output, variable carried through a loop or derived key of `pbkdf2` as well.
  `frombase64` accepts only a transformed hash output that consists of hex digits, such as
  `rev(md5(pass))`. A recipe can decode its salt using only one encoding. Applying `utf16le` to a
  decoded salt, password or field is not supported. The hash line preserves the salt as encoded
  text. A salt with invalid hex or base64 is rejected when the hash file is loaded. A string with an
  invalid encoding in the recipe is rejected at startup.
- Passwords and fields are decoded as hx decodes them, whatever they contain. `fromhex` reads a
  character that is not a hex digit as 0 and ignores an odd last character. `frombase64` stops at
  the first group of 4 characters whose first or second character is not base64, and `=` ends a
  group early. A password that is not valid hex or base64 therefore cracks the hash that hx computes
  for it.
- `base64` accepts `pass`, `salt`, the fields, strings and hash outputs, but not a concatenation.
  `fromhex` does not accept base64 output.
- The result must be a hash, AES, DES, `xor`, `and` or `or` call in hex, base64 or raw bytes,
  optionally wrapped in `upper`, `lower`, `hex`, `base64`, `cut` or `trunc`. In hex, it must retain
  an even number of at least 16 hex characters from an offset that is a multiple of 8, as in
  `cut(sha1(pass), 8)`. In base64, it must retain at least the first 11 characters. Raw bytes must
  retain 8 to 64 bytes. Mode 4000 compares 16 bytes of a longer result. A `pbkdf2` call or a
  variable carried through a loop can be the result as well, as raw bytes, wrapped in `hex` or
  `base64` of raw bytes or in `upper` or `lower` of hex. Like a call, such a variable must hold 8 to
  64 bytes, and in hex an even number of characters. A `pbkdf2` key as the result can have any
  length up to 256 bytes, and the hash line holds all of it. A `pbkdf2` call can also be cut. See
  [Key derivation](#key-derivation). Such a cut can start at any offset that is a multiple of 4
  bytes. A transformed hash output, carried variable or derived key can be the result when its length
  is fixed and its transforms end in `hex` or `base64` or leave raw bytes, as in
  `hex(rev(md5_bin(pass)))` or `rev(md5_bin(pass))`. Transforms that leave text, as in
  `rev(md5(pass))`, are not supported. Raw bytes of `xor`, `and` or `or` are accepted only when both
  values are raw hash output. The result can also be a comparison. See [Comparisons](#comparisons).
- `cap` around the result, as in `cap(md5(pass))`, needs a hex result. Together with the `upper`
  and `lower` calls next to it, up to 4 such calls can wrap the result.
- Strings before and after the result can contain up to 64 bytes each, all printable ASCII. A
  string after the result cannot contain `*`. A raw result cannot have strings around it, because hx
  would write the whole line in hex.
- `base64` of a concatenation can be the result only as 8 to 64 raw bytes of a hash, AES, DES,
  `xor`, `and` or `or` call followed by `salt`, as in `base64(sha1_bin(pass . salt) . salt)`. A
  variable or a `pbkdf2` call cannot be that output yet. Its base64 text can contain up to 128
  characters.
- Under CUDA, a recipe that combines 2 table families, such as Streebog with Streebog or
  Whirlpool, can exceed the constant memory of the `-a 0` kernel, which then fails to build.

## Not supported yet

Mode 4000 supports only part of hx. It does not support nested or several loops, `if`, `emit`, key
derivation other than `pbkdf2`, ciphers other than AES and DES or character encodings other than
`utf16le` and `utf16be`. Hash families that are not listed under [Syntax](#syntax) are also
unsupported. `length` is supported only in `length(aes_unwrap(kek, x)) > 0`. A recipe that uses an
unsupported feature is rejected at startup with the reason and position of the error.

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
- `rev`, `rotate`, `bswap32`, `rot13`, a `wperm` of all words and an `xor` with a string around
  the result, as in `hex(rev(md5_bin(pass)))`, are undone once for each hash line as it loads. The
  kernel compares the hash output inside them, so they cost nothing per candidate. This applies to
  recipes without a loop or `pbkdf2` when nothing cuts the result. `rev` and `bswap32` of SHA-1,
  SHA-2 and some other families stay in the kernel, where they undo a byte swap the kernel makes
  anyway and cost nothing.
- In a loop, an HMAC of MD4, MD5, SHA-1, SHA-2, RIPEMD-160 or SM3 whose key the loop does not
  change, such as `pass`, computes its key pads before the loop rather than in every iteration.
- In a loop, a call of one of those families whose input fits one block, such as `md5_bin(h . pass)`
  or `sha1_bin(pass . h)`, lays out its block once per kernel launch. Each iteration then replaces
  only the words that change.
- A recipe must use `pass`. Otherwise, every candidate would produce the same hash.
- UTF-8 decoding can give candidates different lengths. The SIMD mask kernel on CPUs cannot track
  a separate length for each candidate. It hashes candidates together when all are ASCII and
  processes them individually otherwise.

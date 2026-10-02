# Cisco "Convoluted Type 9" ($14$) hash mode - design

## Background

Cisco IOS XE Gibraltar 16.12.x (and later) auto-converts legacy Type 5
(MD5-crypt) `enable secret` / user `secret` values to Type 9 (scrypt) the
first time the config is rewritten after an upgrade from 16.9.x/16.10.x/
16.11.x. Because the plaintext is gone (only the Type 5 hash ever existed),
the conversion can't re-derive scrypt from the original password - instead
it runs scrypt over the *existing Type 5 hash string*. Cisco calls the
result a "convoluted Type 9 secret"; on the wire it's distinguished from a
freshly-set Type 9 secret by a `$14$` prefix instead of `$9$`.

Confirmed against Cisco's own documentation (IOS XE Gibraltar 16.12.x
Catalyst 9600 security config guide) and an independent PoC
(`EmilCodes/CiscoConvoluted9Cracker`), and cross-checked against a real
sample hash:

```
$14$pVDA$bfv6.ILwk7uBI.$TZXJ9TEST892XVfmmEc89TESTlf/YlT8TESTZ4vPdF.
```

Cisco's documented conversion example:

```
Type 5:  $1$dNmW$7jWhqdtZ2qBVz2R4CSZZC0
Type 9:  $14$dNmW$QykGZEEGmiEGrE$C9D/fD0czicOtgaZAa1CTa2sgygi0Leyw3/cLqPY426
```

The plaintext for Cisco's example isn't published, so it can't serve as
hashcat's self-test vector; the design below generates a fresh one from the
verified algorithm instead (the same thing every scrypt-based module in
hashcat already does).

## Wire format

```
$14$<type5_salt:4>$<type9_salt:14>$<digest:43, Cisco base64>
```

- `type5_salt`: the original Type 5 salt, standard crypt(3) itoa64 alphabet
  (`./0-9A-Za-z`), always 4 characters (matches hashcat's existing mode 500
  salt length).
- `type9_salt`: a freshly generated scrypt salt, same alphabet, 14
  characters - identical in length and alphabet to mode 9300's salt field.
- `digest`: 43-character Cisco-base64 encoding of a 32-byte scrypt output -
  byte-for-byte the same encoding mode 9300 already produces.

## Algorithm

```
h      = md5_crypt(password, salt = type5_salt)        // "$1$<salt>$<22-char hash>", 30 bytes ASCII
digest = scrypt(password = h, salt = type9_salt,
                 N = 16384, r = 1, p = 1, dklen = 32)
```

`md5_crypt` here is exactly hashcat mode 500's algorithm (1000 rounds).
`scrypt` here is exactly hashcat mode 9300's algorithm. The only new thing
is that stage 2's "password" is stage 1's full hash string, not the
candidate itself.

## Approach

Reuse hashcat's existing two-stage chained-kernel plumbing (`_init`/`_loop`
-> `_init2`/`_loop2_prepare`/`_loop2` -> `_comp`), the same pattern mode
14800 (iTunes backup >= 10.0) already uses to chain PBKDF2-SHA1 into
PBKDF2-SHA256. No new primitive code is needed - stage 1 reuses mode 500's
MD5-crypt kernel logic, stage 2 reuses mode 9300's scrypt kernel logic
(`inc_hash_scrypt.cl`); the only new code is the glue that serializes stage
1's digest into the 30-byte ASCII string stage 2 consumes as its password.

**Rejected alternative:** compute the whole chain CPU-side via a hook or
bridge, avoiding new kernel code entirely. Scrypt is the expensive,
GPU-parallel part of this hash; routing every candidate's scrypt input
through a CPU-side preprocessing step would serialize on the CPU and
defeat the purpose of a GPU-accelerated mode. Not pursued.

## Mode number

**9301** - free, and reads naturally as a Type 9 variant alongside the
existing Cisco cluster (9200 = Type 8 PBKDF2-SHA256, 9300 = Type 9 scrypt).

## Components

- `src/modules/module_09301.c` - new module. Parser clones 9300's 3-token
  structure with an extra leading salt field; decodes `type5_salt` into
  `salt->salt_buf_pc`/`salt_len_pc` (the second salt slot `salt_t` already
  provides) and `type9_salt`/digest exactly as 9300 does into
  `salt->salt_buf`/`salt_len`/`digest_buf`. Fixed scrypt config
  (N=16384, r=1, p=1) same as 9300. `OPTS_TYPE_INIT2 | OPTS_TYPE_LOOP2_PREPARE
  | OPTS_TYPE_LOOP2` added on top of 9300's `OPTS_TYPE`. Reuses
  `scrypt_common.c` for the tuning-db/buffer-sizing helpers.
- `OpenCL/m09301-pure.cl` - new kernel.
  - `m09301_init`/`m09301_loop`: mode 500's MD5-crypt logic verbatim,
    salted from `salt_bufs[SALT_POS_HOST].salt_buf_pc` instead of
    `salt_buf`, written into a combined tmp struct.
  - End of stage 1 (in `_init2`): base64-encode the 16-byte MD5 digest into
    the 22-char crypt string (same regrouping mode 500's host-side
    `module_hash_encode` already does, done here on the GPU) and assemble
    the 30-byte ASCII string `$1$<salt_pc>$<hash>` into the tmp buffer that
    scrypt's PBKDF2 stage reads as "password".
  - `m09301_init2`/`m09301_loop2_prepare`/`m09301_loop2`: mode 9300's
    scrypt pipeline (`scrypt_pbkdf2_ggg`, `scrypt_blockmix_in`,
    `scrypt_smix_init`/`scrypt_smix_loop`), fed the assembled 30-byte
    buffer instead of `pws[gid].i`/`pw_len`, against `salt_buf`/`salt_len`.
  - `m09301_comp`: mode 9300's final PBKDF2 (`scrypt_pbkdf2_ggp`) and
    digest compare, same substitution.
  - Combined tmp struct holds mode 500's `digest_buf[4]` plus mode 9300's
    `scrypt_tmp_t` fields (`in`/`out`), sized via `module_tmp_size`/
    `module_extra_tmp_size` the way 9300 already computes them.
- `tools/test_modules/m09301.pm` - Perl test module (per AGENTS.md),
  written and run against a self-generated vector.

## Self-test vector

Generated from the verified algorithm (independent of Cisco's own
undisclosed-plaintext example), reproduced with `passlib` (md5_crypt) and
the `scrypt` PyPI package:

```
ST_PASS = "hashcat"
ST_HASH = "$14$ZeF0$Yh3cTZvrtSWBcT$6ImC5D6iNVvt4fwM14oDbj.Vd5KWkpl8WjUffnRdH5E"
```

## Testing

- Self-test runs automatically on every hashcat invocation; this is the
  primary correctness gate, same as for every other mode.
- `rm -rf cache/kernels/ && ./tools/test_edge.sh -m 9301 -D 1 -f` for full
  attack-type/vector-width coverage on the CPU backend (per AGENTS.md; no
  GPU available in this environment).
- The real `$14$` sample from the field can't be cracked as part of
  verification - its plaintext is unknown - so it's not part of the
  automated test; it only shaped the parser's field-length assumptions.
- ASCII-only check on the diff before sending a PR (per AGENTS.md).

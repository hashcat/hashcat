# Cisco Convoluted Type 9 ($14$, mode 9301) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add hashcat mode 9301, cracking Cisco IOS XE "convoluted Type 9" secrets (`$14$<type5_salt>$<type9_salt>$<digest>`) — `scrypt(md5_crypt(password, type5_salt), type9_salt, N=16384, r=1, p=1)`.

**Architecture:** New module `src/modules/module_09301.c` parses the 3-field format into `salt->salt_buf_pc` (type5 salt) and `salt->salt_buf` (type9 salt). New kernel `OpenCL/m09301-pure.cl` chains two existing, already-proven kernel stages via hashcat's `_init`/`_loop` → `_init2`/`_loop2_prepare`/`_loop2` → `_comp` plumbing (the same pattern mode 14800 already uses to chain two different KDFs): stage 1 is mode 500's MD5-crypt logic verbatim (against `salt_buf_pc`); stage 2 is mode 9300's scrypt logic verbatim (`inc_hash_scrypt.cl`), fed the stage-1 output string instead of the raw candidate.

**Tech Stack:** C (host module), OpenCL C (kernel, JIT-compiled for OpenCL/CUDA/HIP/Metal from the same source), Python (reference implementation + fuzz-test module).

**Spec:** `docs/superpowers/specs/2026-10-02-cisco-convoluted-type9-design.md`

## Global Constraints

- Wire format: `$14$<type5_salt>$<type9_salt:14>$<digest:43>`, all fields in the crypt(3)/Cisco itoa64 alphabet (`./0-9A-Za-z`).
- Algorithm: `h = md5_crypt(password, type5_salt)` (full `"$1$<salt>$<22-char-hash>"` string, 1000 rounds) → `digest = scrypt(password=h, salt=type9_salt, N=16384, r=1, p=1, dklen=32)`.
- Mode number: **9301**. `KERN_TYPE` is also 9301 (not shared with any other mode, so the kernel filename is `m09301-pure.cl`).
- Self-test vector (verified independently against both `passlib`+PyPI `scrypt` and hashcat's own `tools/test_modules/lib/md5crypt.py`+`hashlib.scrypt`):
  `ST_PASS = "hashcat"`, `ST_HASH = "$14$ZeF0$Yh3cTZvrtSWBcT$6ImC5D6iNVvt4fwM14oDbj.Vd5KWkpl8WjUffnRdH5E"`.
- Per AGENTS.md: clear `cache/kernels/` before measuring any kernel change; run `./tools/test_edge.sh -m 9301 -D 1 -f` (CPU backend, no GPU in this environment); run the ASCII check on the diff before sending a PR; never report a command's output without having run it.

## Review Focus

- A line whose type5-salt or type9-salt field is the wrong length (truncated, or padded with extra bytes before the next `$`) must be rejected by the tokenizer (`PARSER_SEPARATOR_UNMATCHED`/`PARSER_SALT_LENGTH`), not silently misparsed into the next field — neither salt field is alphabet-checked (mode 9300, which this mirrors, doesn't alphabet-check its salt either; only the digest field's base64 alphabet is enforced), so length is the actual invariant worth pinning.
- The empty-password candidate (`pw_len == 0`) must not crash the MD5-crypt stage — mode 500's own loop structure already handles this (the "weird" bit-test loop at the end of `_init` simply never executes), so the test exists to confirm the combined kernel preserves that, not to fix new logic.
- A candidate password at or near the kernel's maximum length must not overflow the 64-word `w[]` buffer or the fixed-size assembled password buffer in `_init2` — the assembled buffer's size depends only on the salt, not the candidate, so this specifically checks the MD5-crypt stage's own bounds.
- Two hashes in the same job with different `type5_salt` values (but the same or different `type9_salt`) must each use their own `salt_buf_pc` — not cross-contaminate — since `salt_buf_pc` lives in the per-salt `salt_t`, not a global.
- `module_hash_encode` must round-trip a decoded `$14$` line byte-for-byte (including the original `type5_salt`), since potfile show/left in `test_edge.sh` depends on it.

---

## Task 1: Reference implementation and fuzz-test module

**Files:**
- Create: `tools/test_modules/m09301.py`
- Test: run the module directly via `python3`

**Interfaces:**
- Produces: `module_constraints()`, `module_generate_hash(word, salt, iterations=None)`, `module_verify_hash(line)` — the three functions `test_edge.sh`'s fuzzer calls on every custom mode, matching the shape of `tools/test_modules/m09300.py` and `tools/test_modules/m00500.py`.

- [ ] **Step 1: Write the test module**

```python
#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import hashlib

from lib.md5crypt import md5_crypt
from lib.test_helpers import split_hash_word

# Cisco IOS XE "convoluted Type 9": $14$<type5 salt>$<type9 salt>$<digest>.
# scrypt(md5_crypt(password, type5_salt), type9_salt, N=16384, r=1, p=1) -- IOS XE
# auto-converts a Type 5 (MD5-crypt) secret to this on upgrade to Gibraltar 16.12.x+,
# running scrypt over the existing Type 5 hash string because the plaintext is gone.

CISCO = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def module_constraints():
  return [[0, 256], [14, 14], [-1, -1], [-1, -1], [-1, -1]]


def module_generate_hash(word, type5_salt, type9_salt=None):
  if type9_salt is None:
    type9_salt = "Yh3cTZvrtSWBcT"

  h = md5_crypt(b"$1$", 1000, word, type5_salt.encode("latin-1")).encode("latin-1")

  key = hashlib.scrypt(h, salt=type9_salt.encode(), n=16384, r=1, p=1, dklen=32, maxmem=(128 * 16384 * 2))

  digest = base64.b64encode(key).decode()[:43].translate(CISCO)

  return "$14$%s$%s$%s" % (type5_salt, type9_salt, digest)


def module_verify_hash(line):
  parts = split_hash_word(line)

  if parts is None or not parts[0].startswith("$14$"):
    return None

  hash_in, word = parts

  fields = hash_in.split("$")

  if len(fields) < 5 or len(fields[3]) != 14:
    return None

  type5_salt = fields[2]
  type9_salt = fields[3]

  return (module_generate_hash(word, type5_salt, type9_salt), word)
```

- [ ] **Step 2: Run it against the self-test vector to confirm it reproduces the design doc's digest**

Run:
```bash
cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat/tools/test_modules
python3 -c "
import m09301
print(m09301.module_generate_hash(b'hashcat', 'ZeF0', 'Yh3cTZvrtSWBcT'))
"
```
Expected: `$14$ZeF0$Yh3cTZvrtSWBcT$6ImC5D6iNVvt4fwM14oDbj.Vd5KWkpl8WjUffnRdH5E` (matches the Global Constraints self-test vector exactly).

- [ ] **Step 3: Run `module_verify_hash` round-trip on the same line**

Run:
```bash
cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat/tools/test_modules
python3 -c "
import m09301
line = b'\$14\$ZeF0\$Yh3cTZvrtSWBcT\$6ImC5D6iNVvt4fwM14oDbj.Vd5KWkpl8WjUffnRdH5E:hashcat'
print(m09301.module_verify_hash(line))
"
```
Expected: a tuple whose first element is the identical `$14$...` string and whose second element is `b'hashcat'`.

- [ ] **Step 4: Commit**

```bash
cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat
git add tools/test_modules/m09301.py
git commit -m "test: add Python fuzz-test module for Cisco Convoluted Type 9 (\$14\$)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

## Task 2: Host module (parser, encoder, mode registration)

**Files:**
- Create: `src/modules/module_09301.c`
- Test: build hashcat and run it against mode 9301

**Interfaces:**
- Consumes: `scrypt_module_extra_buffer_size`, `scrypt_module_extra_tuningdb_block`, `scrypt_module_jit_build_options`, `scrypt_module_kernel_loops_min`, `scrypt_module_kernel_loops_max` from `src/modules/scrypt_common.c` (included verbatim, same as `module_09300.c` does).
- Produces: `salt->salt_buf_pc`/`salt_len_pc` holding the type5 salt, `salt->salt_buf`/`salt_len` holding the type9 salt, `digest_buf` holding the 32-byte scrypt digest — the exact layout Task 3's kernel reads.

- [ ] **Step 1: Write the module**

```c
/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "Cisco-IOS $14$ (MD5 (Type 5) + scrypt, Convoluted)";
static const u64   KERN_TYPE      = 9301;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_LOOP_PREPARE
                                  | OPTS_TYPE_INIT2
                                  | OPTS_TYPE_LOOP2_PREPARE
                                  | OPTS_TYPE_LOOP2;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$14$ZeF0$Yh3cTZvrtSWBcT$6ImC5D6iNVvt4fwM14oDbj.Vd5KWkpl8WjUffnRdH5E";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

static const char *SIGNATURE_CISCO14 = "$14$";

static const u32 SCRYPT_THREADS = 32;

#include "scrypt_common.c"

u64 module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  const u64 scrypt_tmp_size = scrypt_module_extra_tmp_size (hashconfig, user_options, user_options_extra, hashes);

  // bits 62/63 are error sentinels (mixed configuration / self-test mismatch); propagate as-is

  if (scrypt_tmp_size & (3ULL << 62)) return scrypt_tmp_size;

  // + md5crypt digest_buf[4] (16 bytes) + assembled "$1$<salt>$<hash>" buffer (32 bytes, 30 used)

  return scrypt_tmp_size + 16 + 32;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CISCO14;

  token.len[0]     = 4;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 8;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '$';
  token.len[2]     = 14;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH;

  token.sep[3]     = '$';
  token.len[3]     = 43;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type5 salt (the original Type 5 / $1$ salt) -- not encoded

  const u8 *salt_pc_pos = token.buf[1];
  const int salt_pc_len = token.len[1];

  u8 *salt_buf_pc_ptr = (u8 *) salt->salt_buf_pc;

  memcpy (salt_buf_pc_ptr, salt_pc_pos, salt_pc_len);

  salt->salt_len_pc = salt_pc_len;

  // type9 (scrypt) salt -- not encoded

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len = salt_len;

  // fixed scrypt configuration, same as mode 9300

  salt->scrypt_N  = 16384;
  salt->scrypt_r  = 1;
  salt->scrypt_p  = 1;

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  // base64 decode hash

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  u8 tmp_buf[100] = { 0 };

  const int tmp_len = base64_decode (itoa64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  char tmp_buf[64];

  base64_encode (int_to_itoa64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

  tmp_buf[43] = 0; // cut it here

  const int line_len = snprintf (line_buf, line_size, "%s%s$%s$%s", SIGNATURE_CISCO14, (const unsigned char *) salt->salt_buf_pc, (const unsigned char *) salt->salt_buf, tmp_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_esalt_size               = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = scrypt_module_extra_tuningdb_block;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_hints               = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = scrypt_module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
```

- [ ] **Step 2: Build**

Run: `cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat && make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"`
Expected: builds cleanly (the new `.c` file is picked up by the Makefile's existing `src/modules/*.c` glob — no Makefile edit needed, same as every other module).

- [ ] **Step 3: Confirm the module registers and reaches the kernel-load stage**

Run: `rm -rf cache/kernels/ && ./hashcat -m 9301 --example-hashes`
Expected: hashcat prints mode 9301's name (`Cisco-IOS $14$ (MD5 (Type 5) + scrypt, Convoluted)`) and the `ST_HASH` value — this confirms the parser/registration is correct. It will then fail with a "file not found" / kernel compile error for `OpenCL/m09301-pure.cl`, which does not exist yet — that failure is expected at this point and is resolved by Task 3, not this task.

- [ ] **Step 4: Commit**

```bash
cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat
git add src/modules/module_09301.c
git commit -m "feat: add host module for Cisco Convoluted Type 9 (\$14\$), mode 9301

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

## Task 3: OpenCL kernel (MD5-crypt → scrypt chain)

**Files:**
- Create: `OpenCL/m09301-pure.cl`
- Test: build + run hashcat's self-test against mode 9301

**Interfaces:**
- Consumes: `salt_bufs[SALT_POS_HOST].salt_buf_pc`/`salt_len_pc` (type5 salt), `.salt_buf`/`.salt_len` (type9 salt) from Task 2; `md5_ctx_t`/`md5_init`/`md5_update`/`md5_final`/`truncate_block_4x4_le_S` from `inc_hash_md5.cl`; `scrypt_pbkdf2_ggg`/`scrypt_blockmix_in`/`scrypt_smix_init`/`scrypt_smix_loop`/`scrypt_blockmix_out`/`scrypt_pbkdf2_ggp` from `inc_hash_scrypt.cl`.
- Produces: the compiled kernel entry points `m09301_init`, `m09301_loop`, `m09301_init2`, `m09301_loop2_prepare`, `m09301_loop2`, `m09301_comp` that `OPTS_TYPE_LOOP_PREPARE | OPTS_TYPE_INIT2 | OPTS_TYPE_LOOP2_PREPARE | OPTS_TYPE_LOOP2` (set in Task 2) tell hashcat's backend to call, in that order, per salt.

- [ ] **Step 1: Write the kernel**

```c
/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define md5crypt_magic 0x00243124u

// byte p into word-packed array a, little-endian within each u32 -- same convention pws[].i uses

#define PUTCHAR_LE(a,p,c) ((a)[(p) / 4] = (((a)[(p) / 4] & ~(0xffu << (((p) & 3) * 8))) | ((u32) (c) << (((p) & 3) * 8))))

CONSTANT_AS u8 CISCO9301_ITOA64[64] =
{
  '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

DECLSPEC u8 cisco9301_itoa64 (const u32 v)
{
  return CISCO9301_ITOA64[v & 0x3f];
}

typedef struct cisco9301_tmp
{
  u32 digest_buf[4]; // md5crypt (Type 5) running / final digest
  u32 pw_buf[8];     // assembled "$1$<salt>$<hash>" string fed to scrypt as its password

  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  u32 in[SCRYPT_TMP_ELEM / 2];
  u32 out[SCRYPT_TMP_ELEM / 2];

} cisco9301_tmp_t;

KERNEL_FQ KERNEL_FA void m09301_init (KERN_ATTR_TMPS (cisco9301_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf_pc[idx];
  }

  md5_ctx_t md5_ctx1;

  md5_init (&md5_ctx1);

  md5_update (&md5_ctx1, w, pw_len);
  md5_update (&md5_ctx1, s, salt_len);
  md5_update (&md5_ctx1, w, pw_len);

  md5_final (&md5_ctx1);

  u32 final[16] = { 0 };

  final[0] = md5_ctx1.h[0];
  final[1] = md5_ctx1.h[1];
  final[2] = md5_ctx1.h[2];
  final[3] = md5_ctx1.h[3];

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update (&md5_ctx, w, pw_len);

  u32 m[16] = { 0 };

  m[0] = md5crypt_magic;

  md5_update (&md5_ctx, m, 3);
  md5_update (&md5_ctx, s, salt_len);

  int pl;

  for (pl = pw_len; pl > 16; pl -= 16)
  {
    md5_update (&md5_ctx, final, 16);
  }

  truncate_block_4x4_le_S (final, pl);

  md5_update (&md5_ctx, final, pl);

  for (int i = pw_len; i != 0; i >>= 1)
  {
    u32 t[16] = { 0 };

    if (i & 1)
    {
      t[0] = 0;
    }
    else
    {
      t[0] = w[0] & 0xff;
    }

    md5_update (&md5_ctx, t, 1);
  }

  md5_final (&md5_ctx);

  tmps[gid].digest_buf[0] = md5_ctx.h[0];
  tmps[gid].digest_buf[1] = md5_ctx.h[1];
  tmps[gid].digest_buf[2] = md5_ctx.h[2];
  tmps[gid].digest_buf[3] = md5_ctx.h[3];
}

KERNEL_FQ KERNEL_FA void m09301_loop (KERN_ATTR_TMPS (cisco9301_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf_pc[idx];
  }

  u32 digest[16] = { 0 };

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    md5_ctx_t md5_ctx;

    md5_init (&md5_ctx);

    if (j & 1)
    {
      md5_update (&md5_ctx, w, pw_len);
    }
    else
    {
      md5_update (&md5_ctx, digest, 16);
    }

    if (j % 3)
    {
      md5_update (&md5_ctx, s, salt_len);
    }

    if (j % 7)
    {
      md5_update (&md5_ctx, w, pw_len);
    }

    if (j & 1)
    {
      md5_update (&md5_ctx, digest, 16);
    }
    else
    {
      md5_update (&md5_ctx, w, pw_len);
    }

    md5_final (&md5_ctx);

    digest[0] = md5_ctx.h[0];
    digest[1] = md5_ctx.h[1];
    digest[2] = md5_ctx.h[2];
    digest[3] = md5_ctx.h[3];
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ KERNEL_FA void m09301_init2 (KERN_ATTR_TMPS (cisco9301_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // unpack the 16-byte md5crypt digest to individual bytes

  u8 d[16];

  d[ 0] = (tmps[gid].digest_buf[0] >>  0) & 0xff;
  d[ 1] = (tmps[gid].digest_buf[0] >>  8) & 0xff;
  d[ 2] = (tmps[gid].digest_buf[0] >> 16) & 0xff;
  d[ 3] = (tmps[gid].digest_buf[0] >> 24) & 0xff;
  d[ 4] = (tmps[gid].digest_buf[1] >>  0) & 0xff;
  d[ 5] = (tmps[gid].digest_buf[1] >>  8) & 0xff;
  d[ 6] = (tmps[gid].digest_buf[1] >> 16) & 0xff;
  d[ 7] = (tmps[gid].digest_buf[1] >> 24) & 0xff;
  d[ 8] = (tmps[gid].digest_buf[2] >>  0) & 0xff;
  d[ 9] = (tmps[gid].digest_buf[2] >>  8) & 0xff;
  d[10] = (tmps[gid].digest_buf[2] >> 16) & 0xff;
  d[11] = (tmps[gid].digest_buf[2] >> 24) & 0xff;
  d[12] = (tmps[gid].digest_buf[3] >>  0) & 0xff;
  d[13] = (tmps[gid].digest_buf[3] >>  8) & 0xff;
  d[14] = (tmps[gid].digest_buf[3] >> 16) & 0xff;
  d[15] = (tmps[gid].digest_buf[3] >> 24) & 0xff;

  // crypt(3)/md5crypt's byte regrouping: groups of (i, i+6, i+12) plus a final lone byte

  u8 enc[22];

  int l;

  l = (d[0] << 16) | (d[6] << 8) | d[12];
  enc[0] = cisco9301_itoa64 (l); l >>= 6; enc[1] = cisco9301_itoa64 (l); l >>= 6; enc[2] = cisco9301_itoa64 (l); l >>= 6; enc[3] = cisco9301_itoa64 (l);

  l = (d[1] << 16) | (d[7] << 8) | d[13];
  enc[4] = cisco9301_itoa64 (l); l >>= 6; enc[5] = cisco9301_itoa64 (l); l >>= 6; enc[6] = cisco9301_itoa64 (l); l >>= 6; enc[7] = cisco9301_itoa64 (l);

  l = (d[2] << 16) | (d[8] << 8) | d[14];
  enc[8] = cisco9301_itoa64 (l); l >>= 6; enc[9] = cisco9301_itoa64 (l); l >>= 6; enc[10] = cisco9301_itoa64 (l); l >>= 6; enc[11] = cisco9301_itoa64 (l);

  l = (d[3] << 16) | (d[9] << 8) | d[15];
  enc[12] = cisco9301_itoa64 (l); l >>= 6; enc[13] = cisco9301_itoa64 (l); l >>= 6; enc[14] = cisco9301_itoa64 (l); l >>= 6; enc[15] = cisco9301_itoa64 (l);

  l = (d[4] << 16) | (d[10] << 8) | d[5];
  enc[16] = cisco9301_itoa64 (l); l >>= 6; enc[17] = cisco9301_itoa64 (l); l >>= 6; enc[18] = cisco9301_itoa64 (l); l >>= 6; enc[19] = cisco9301_itoa64 (l);

  l = d[11];
  enc[20] = cisco9301_itoa64 (l); l >>= 6; enc[21] = cisco9301_itoa64 (l);

  // assemble "$1$<type5 salt>$<enc>", zero padded, into tmps[gid].pw_buf

  tmps[gid].pw_buf[0] = 0;
  tmps[gid].pw_buf[1] = 0;
  tmps[gid].pw_buf[2] = 0;
  tmps[gid].pw_buf[3] = 0;
  tmps[gid].pw_buf[4] = 0;
  tmps[gid].pw_buf[5] = 0;
  tmps[gid].pw_buf[6] = 0;
  tmps[gid].pw_buf[7] = 0;

  const u32 salt_len_pc = salt_bufs[SALT_POS_HOST].salt_len_pc;

  u32 pos = 0;

  PUTCHAR_LE (tmps[gid].pw_buf, pos, '$'); pos++;
  PUTCHAR_LE (tmps[gid].pw_buf, pos, '1'); pos++;
  PUTCHAR_LE (tmps[gid].pw_buf, pos, '$'); pos++;

  for (u32 i = 0; i < salt_len_pc; i++)
  {
    const u32 w_idx = i / 4;
    const u32 b_idx = i % 4;

    const u8 c = (salt_bufs[SALT_POS_HOST].salt_buf_pc[w_idx] >> (b_idx * 8)) & 0xff;

    PUTCHAR_LE (tmps[gid].pw_buf, pos, c); pos++;
  }

  PUTCHAR_LE (tmps[gid].pw_buf, pos, '$'); pos++;

  for (u32 i = 0; i < 22; i++)
  {
    PUTCHAR_LE (tmps[gid].pw_buf, pos, enc[i]); pos++;
  }

  // stage 2: scrypt (N=16384, r=1, p=1) over the assembled string, salted with the type9 salt

  scrypt_pbkdf2_ggg (tmps[gid].pw_buf, pos, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m09301_loop2_prepare (KERN_ATTR_TMPS (cisco9301_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_init (P, X, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m09301_loop2 (KERN_ATTR_TMPS (cisco9301_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_loop (P, X, T, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m09301_comp (KERN_ATTR_TMPS (cisco9301_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  // the assembled password's length depends only on the salt, not the candidate, so recompute it
  // here rather than storing it: 3 ("$1$") + type5 salt + 1 ("$") + 22 (encoded md5crypt hash)

  const u32 pw_len = 3 + salt_bufs[SALT_POS_HOST].salt_len_pc + 1 + 22;

  u32 out[4];

  scrypt_pbkdf2_ggp (tmps[gid].pw_buf, pw_len, tmps[gid].in, SCRYPT_SZ, out, 16);

  const u32 r0 = out[0];
  const u32 r1 = out[1];
  const u32 r2 = out[2];
  const u32 r3 = out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
```

- [ ] **Step 2: Clear the kernel cache and run the self-test**

Run: `cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat && rm -rf cache/kernels/ && ./hashcat -m 9301 --example-hashes -D 1 --force`
Expected: the kernel JIT-compiles without error, and the self-test line for mode 9301 reports `OK` (hashcat runs its self-test — comparing the compiled kernel's output for `ST_PASS`/`ST_HASH` — automatically before anything else; `-D 1 --force` selects the CPU backend, since AGENTS.md notes this environment has no GPU). If the self-test reports a mismatch, do not edit the self-test vector to make it pass — the vector was independently verified twice in the design doc; a mismatch here means a bug in the kernel code above, most likely in the byte-order/regrouping of the `enc[]` assembly or the `PUTCHAR_LE` packing. Use `systematic-debugging` to isolate which stage is wrong (e.g. temporarily write `tmps[gid].digest_buf` or the assembled `pw_buf` to the comparison digest to inspect intermediate values).

- [ ] **Step 3: Crack a hash generated by Task 1's reference implementation, to confirm agreement independent of the self-test vector**

Run:
```bash
cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat
python3 -c "
import sys
sys.path.insert(0, 'tools/test_modules')
import m09301
print(m09301.module_generate_hash(b'Testing123!', 'abCD', 'ScryptSaltHere'))
" > /tmp/cisco9301_hash.txt
echo 'Testing123!' > /tmp/cisco9301_wordlist.txt
cat /tmp/cisco9301_hash.txt
rm -rf cache/kernels/
./hashcat -m 9301 -a 0 -D 1 --force /tmp/cisco9301_hash.txt /tmp/cisco9301_wordlist.txt --potfile-disable -o /tmp/cisco9301_cracked.txt
cat /tmp/cisco9301_cracked.txt
```
Expected: the final `cat` prints the hash from `/tmp/cisco9301_hash.txt` followed by `:Testing123!` — a successful crack, confirming the kernel and the independent Python reference agree on a hash the self-test vector never exercised (different salts, different password).

- [ ] **Step 4: Commit**

```bash
cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat
git add OpenCL/m09301-pure.cl
git commit -m "feat: add OpenCL kernel for Cisco Convoluted Type 9 (\$14\$), mode 9301

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

## Task 4: Full attack-mode coverage, potfile round-trip, and cleanup

**Files:**
- Modify: none (verification only)
- Test: `tools/test_edge.sh`, `git diff` ASCII check

**Interfaces:**
- Consumes: Task 1's `m09301.py` (used internally by `test_edge.sh`'s fuzzer), Task 2/3's module and kernel.

- [ ] **Step 1: Run the full edge-case suite for mode 9301 on the CPU backend**

Run: `cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat && rm -rf cache/kernels/ && ./tools/test_edge.sh -m 9301 -D 1 -f`
Expected: every attack type/vector-width combination `test_edge.sh` exercises for mode 9301 reports success. This is also what exercises the Review Focus items (malformed salt-field lengths, empty password, long password, multi-salt jobs, potfile round-trip) — `test_edge.sh`'s fuzzer draws these cases using `module_constraints()`/`module_generate_hash()`/`module_verify_hash()` from Task 1. If any case fails, fix the module or kernel (not the test module) and re-run this exact command before moving on — do not weaken a Review Focus case to make it pass.

- [ ] **Step 2: Specifically confirm the potfile round-trip preserves the type5 salt**

Run:
```bash
cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat
rm -rf cache/kernels/
./hashcat -m 9301 -a 0 -D 1 --force /tmp/cisco9301_hash.txt /tmp/cisco9301_wordlist.txt --potfile-disable --show
```
(uses the hash file from Task 3 Step 3)
Expected: prints the exact same `$14$abCD$ScryptSaltHere$...` line from `/tmp/cisco9301_hash.txt`, byte-for-byte including the `abCD` type5 salt, followed by `:Testing123!`.

- [ ] **Step 3: ASCII check on the full diff**

Run: `cd /Users/spoonman/Downloads/Pentest/Passwords/hashcat && git diff -U0 master...HEAD | grep '^+' | grep -nP '[^\x09\x20-\x7E]'`
Expected: no output (no non-ASCII byte in any added line). If this prints matches, find and fix each one (most likely an em dash, en dash, or curly quote introduced in a comment) and re-run.

- [ ] **Step 4: Final review of the branch**

Run the project's code review (per CONTRIBUTING.md and this session's own standards, at full reasoning effort) over the three commits from Tasks 2-3 before considering this done; this is a from-scratch C/OpenCL contribution to a security tool and deserves the same adversarial self-review AGENTS.md asks of every hashcat PR.

- [ ] **Step 5: Clean up scratch files**

Run: `rm -f /tmp/cisco9301_hash.txt /tmp/cisco9301_wordlist.txt /tmp/cisco9301_cracked.txt`

(No commit for this task — it's verification-only. If Step 1 or 2 required fixes, those fixes were already committed as part of whichever Task 2/3 step they belong to; amend those commits rather than adding a separate "fix review findings" commit, per AGENTS.md's "write less" / no process-narration guidance.)

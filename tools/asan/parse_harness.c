/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Host-side hash-parser harness for AddressSanitizer / Valgrind.
 *
 * Why this exists
 * ---------------
 * The Compute Sanitizer harness in tools/compute_sanitizer/ can only see CUDA
 * kernels. hashcat's hash-line parsers (module_hash_decode) run entirely on the
 * host in plain C, so the sanitizer is structurally blind to them -- and they
 * are the part of hashcat that consumes fully attacker-controlled input: a
 * hash file from an untrusted source is parsed by hand-written C with a lot of
 * pointer arithmetic, hex decoding and fixed-size buffers.
 *
 * That makes them the highest-value target for a memory checker, and unlike
 * running the whole binary, this needs no GPU, no backend, and no CUDA driver
 * (Valgrind and the CUDA driver do not get along, and the driver alone would
 * bury any real finding in noise).
 *
 * See tools/asan/README.md for how to build and run it.
 *
 * What it does
 * ------------
 * dlopen()s a module .so, calls module_init() exactly the way interface.c
 * does, builds a hashconfig from the module's own getters, then calls
 * module_hash_decode() on the module's own example hash plus a family of
 * mutations of it (truncations, separator corruption, oversized fields).
 * Buffer sizes come from the module's declared dgst_size/esalt_size/etc, so an
 * overflow of those buffers is a real overflow of what hashcat would allocate.
 *
 * Usage:
 *   parse_harness <module.so> <hash-mode> [--mutate] [--hash <line>]
 */

#include "common.h"
#include "types.h"
#include "memory.h"

#include "modules.h"

#include <dlfcn.h>
#include <inttypes.h>

// interface.c calls these through the module context; we resolve the same way

typedef void (*MODULE_INIT_FN) (module_ctx_t *);

#define IS_SET(f) ((f) != NULL && (f) != MODULE_DEFAULT)

static int g_findings = 0;

static void *xalloc (const size_t sz)
{
  // deliberately NOT calloc: hashcat's own buffers are calloc'd, but for
  // parser testing malloc means Valgrind can also tell us when a parser reads
  // a field it never wrote, which calloc would silently hide behind zeros.
  void *p = malloc (sz ? sz : 1);

  if (p == NULL)
  {
    fprintf (stderr, "harness: out of memory\n");
    exit (2);
  }

  return p;
}

static void build_hashconfig (hashconfig_t *hashconfig, module_ctx_t *m,
                              user_options_t *uo, user_options_extra_t *uoe,
                              const int hash_mode)
{
  memset (hashconfig, 0, sizeof (hashconfig_t));

  hashconfig->hash_mode = (u32) hash_mode;

  // Mirrors the subset of hashconfig_init() that a parser can actually
  // observe. Anything a parser reads that is not set here would be read as
  // zero -- which is why the harness reports a parser that depends on
  // something it should not, rather than silently guessing a value.

  if (IS_SET (m->module_separator))       hashconfig->separator      = m->module_separator       (hashconfig, uo, uoe);
  else                                    hashconfig->separator      = ':';

  if (IS_SET (m->module_dgst_size))       hashconfig->dgst_size      = m->module_dgst_size       (hashconfig, uo, uoe);
  if (IS_SET (m->module_salt_type))       hashconfig->salt_type      = m->module_salt_type       (hashconfig, uo, uoe);
  if (IS_SET (m->module_opts_type))       hashconfig->opts_type      = m->module_opts_type       (hashconfig, uo, uoe);
  if (IS_SET (m->module_opti_type))       hashconfig->opti_type      = m->module_opti_type       (hashconfig, uo, uoe);
  if (IS_SET (m->module_kern_type))       hashconfig->kern_type      = m->module_kern_type       (hashconfig, uo, uoe);
  if (IS_SET (m->module_esalt_size))      hashconfig->esalt_size     = m->module_esalt_size      (hashconfig, uo, uoe);
  if (IS_SET (m->module_hook_salt_size))  hashconfig->hook_salt_size = m->module_hook_salt_size  (hashconfig, uo, uoe);
  if (IS_SET (m->module_tmp_size))        hashconfig->tmp_size       = m->module_tmp_size        (hashconfig, uo, uoe);
  // Defaults, mirroring default_pw_max()/default_salt_max() in interface.c.
  // These are NOT optional: most modules leave these fields to the defaults,
  // and a zero salt_max makes every generic salted parser reject its own
  // example hash with PARSER_SALT_LENGTH -- which would look like the harness
  // "passing" while never exercising a single line of parser code.
  // The interface.c versions are not exported (-fvisibility=hidden), so the
  // logic is restated here; keep in sync with src/interface.c:820,910.

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) != 0;
  const bool utf16_salt       = (hashconfig->opts_type & (OPTS_TYPE_ST_UTF16LE | OPTS_TYPE_ST_UTF16BE)) != 0;

  if (IS_SET (m->module_pw_min))   hashconfig->pw_min   = m->module_pw_min   (hashconfig, uo, uoe);
  else                             hashconfig->pw_min   = PW_MIN;

  if (IS_SET (m->module_pw_max))   hashconfig->pw_max   = m->module_pw_max   (hashconfig, uo, uoe);
  else                             hashconfig->pw_max   = optimized_kernel ? PW_MAX_OLD : PW_MAX;

  if (IS_SET (m->module_salt_min)) hashconfig->salt_min = m->module_salt_min (hashconfig, uo, uoe);
  else                             hashconfig->salt_min = SALT_MIN;

  if (IS_SET (m->module_salt_max))
  {
    hashconfig->salt_max = m->module_salt_max (hashconfig, uo, uoe);
  }
  else
  {
    u32 salt_max = SALT_MAX;

    if (optimized_kernel == true)
    {
      salt_max = SALT_MAX_OLD;

      if (utf16_salt == true) salt_max /= 2;
    }

    if (hashconfig->salt_type == SALT_TYPE_GENERIC)
    {
      if (hashconfig->opts_type & OPTS_TYPE_ST_HEX) salt_max *= 2;
    }

    hashconfig->salt_max = salt_max;
  }

  if (hashconfig->dgst_size == 0) hashconfig->dgst_size = 64;
}

static int parse_one (module_ctx_t *m, hashconfig_t *hashconfig,
                      const char *line, const int line_len, const char *label)
{
  // Buffers sized exactly as hashcat would size them, so any overflow the
  // parser commits here is an overflow it commits in production too.

  void   *digest_buf    = xalloc (hashconfig->dgst_size);
  salt_t *salt          = (salt_t *) xalloc (sizeof (salt_t));
  void   *esalt_buf     = hashconfig->esalt_size     ? xalloc (hashconfig->esalt_size)     : NULL;
  void   *hook_salt_buf = hashconfig->hook_salt_size ? xalloc (hashconfig->hook_salt_size) : NULL;

  hashinfo_t *hash_info = (hashinfo_t *) xalloc (sizeof (hashinfo_t));

  // hashcat zeroes these before parsing (hashes.c), so the harness does too --
  // otherwise every parser that writes only some fields would look like a bug.
  memset (digest_buf, 0, hashconfig->dgst_size);
  memset (salt, 0, sizeof (salt_t));
  if (esalt_buf)     memset (esalt_buf,     0, hashconfig->esalt_size);
  if (hook_salt_buf) memset (hook_salt_buf, 0, hashconfig->hook_salt_size);
  memset (hash_info, 0, sizeof (hashinfo_t));

  const int rc = m->module_hash_decode (hashconfig, digest_buf, salt, esalt_buf,
                                        hook_salt_buf, hash_info, line, line_len);

  printf ("  [%-18s] len=%-5d rc=%d\n", label, line_len, rc);

  free (digest_buf);
  free (salt);
  free (esalt_buf);
  free (hook_salt_buf);
  free (hash_info);

  return rc;
}

/**
 * Mutations. Deliberately conservative and structural rather than random: the
 * point is reproducibility, not fuzz volume. A real fuzzing campaign belongs
 * behind libFuzzer/AFL with this same entry point.
 */
static void mutate (module_ctx_t *m, hashconfig_t *hashconfig, const char *hash)
{
  const int len = (int) strlen (hash);

  // 1. every truncation -- catches parsers that read a field before checking
  //    that the line is long enough to contain it
  for (int i = 0; i <= len; i++)
  {
    char *buf = (char *) xalloc ((size_t) i + 1);
    memcpy (buf, hash, (size_t) i);
    buf[i] = 0;

    char label[32];
    snprintf (label, sizeof (label), "trunc:%d", i);

    parse_one (m, hashconfig, buf, i, label);

    free (buf);
  }

  // 2. a length that lies about the buffer -- parsers must trust line_len, not
  //    a NUL terminator. Passing a longer len than the data is exactly what a
  //    truncated read from a hash file looks like.
  {
    char *buf = (char *) xalloc ((size_t) len + 1);
    memcpy (buf, hash, (size_t) len);
    buf[len] = 0;

    parse_one (m, hashconfig, buf, len / 2, "len-lies-short");

    free (buf);
  }

  // 3. separator storms -- field-splitting parsers that index token.buf[N]
  //    without checking token.cnt
  for (int extra = 1; extra <= 3; extra++)
  {
    const size_t sz = (size_t) len + (size_t) extra + 1;

    char *buf = (char *) xalloc (sz);
    memcpy (buf, hash, (size_t) len);
    for (int i = 0; i < extra; i++) buf[len + i] = hashconfig->separator;
    buf[len + extra] = 0;

    char label[32];
    snprintf (label, sizeof (label), "sep+%d", extra);

    parse_one (m, hashconfig, buf, len + extra, label);

    free (buf);
  }

  // 4. oversized final field -- classic fixed-buffer overflow shape
  {
    const size_t pad = 4096;
    const size_t sz  = (size_t) len + pad + 1;

    char *buf = (char *) xalloc (sz);
    memcpy (buf, hash, (size_t) len);
    memset (buf + len, 'a', pad);
    buf[len + pad] = 0;

    parse_one (m, hashconfig, buf, (int) ((size_t) len + pad), "oversized+4096");

    free (buf);
  }

  // 5. lengthen one interior field at a time, keeping the line's structure
  //    intact.
  //
  //    Truncation finds parsers that read a field before checking the line is
  //    long enough. This finds the opposite shape: a parser that computes a
  //    length from one field and applies it at another offset, which stays in
  //    bounds only while the fields happen to be similarly sized. The example
  //    hash is usually balanced enough to hide that, so the defect only
  //    appears once one field is much longer than the rest -- m29100 needed a
  //    120-character first field against a 20-character last one, and the
  //    mutations above reached it only by accident.
  //
  //    Fields are split on the characters hashcat's own tokenizers use as
  //    separators, plus the mode's declared one.
  {
    const char *seps = "$*:.#";

    for (int f = 0; f < len; f++)
    {
      const char c = hash[f];

      const bool is_sep = (strchr (seps, c) != NULL)
                       || ((hashconfig->separator != 0) && (c == hashconfig->separator));

      // start of a field: position 0, or just after a separator
      if ((f != 0) && (is_sep == false)) continue;

      const int start = (f == 0) ? 0 : f + 1;
      if (start >= len) break;

      // extent of this field
      int end = start;
      while (end < len)
      {
        const char e = hash[end];
        if (strchr (seps, e) != NULL) break;
        if ((hashconfig->separator != 0) && (e == hashconfig->separator)) break;
        end++;
      }

      const int field_len = end - start;
      if (field_len <= 0) continue;

      for (int mult = 2; mult <= 8; mult *= 4) // 2x and 8x
      {
        const size_t grown = (size_t) field_len * (size_t) mult;
        const size_t sz    = (size_t) len + grown + 1;

        char *buf = (char *) xalloc (sz);

        memcpy (buf, hash, (size_t) start);

        // repeat the field's own bytes, so character-class checks
        // (VERIFY_HEX, VERIFY_DIGIT, VERIFY_BASE64) still pass and the input
        // reaches the parser body instead of being rejected up front
        for (size_t r = 0; r < (size_t) mult; r++)
        {
          memcpy (buf + start + (r * (size_t) field_len), hash + start, (size_t) field_len);
        }

        const size_t tail_at = (size_t) start + grown;

        memcpy (buf + tail_at, hash + end, (size_t) (len - end));

        const int new_len = (int) (tail_at + (size_t) (len - end));

        buf[new_len] = 0;

        char label[48];
        snprintf (label, sizeof (label), "field@%d x%d", start, mult);

        parse_one (m, hashconfig, buf, new_len, label);

        free (buf);
      }
    }
  }
}

int main (int argc, char **argv)
{
  if (argc < 3)
  {
    fprintf (stderr, "usage: %s <module.so> <hash-mode> [--mutate] [--hash <line>]\n", argv[0]);
    return 2;
  }

  const char *so_path   = argv[1];
  const int   hash_mode = atoi (argv[2]);

  bool do_mutate = false;
  const char *override_hash = NULL;

  for (int i = 3; i < argc; i++)
  {
    if (strcmp (argv[i], "--mutate") == 0) do_mutate = true;
    else if ((strcmp (argv[i], "--hash") == 0) && (i + 1 < argc)) override_hash = argv[++i];
  }

  #if defined (STATIC_MODULE)

  // The module .c is compiled straight into this binary instead of being
  // dlopen()ed. MemorySanitizer and AddressSanitizer cannot coexist in one
  // process, so an MSan harness must not load a plugin out of an ASan-built
  // tree. Linking the single module under test directly avoids the conflict
  // and keeps instrumentation on exactly the code being tested.
  extern void module_init (module_ctx_t *);

  (void) so_path;

  void *handle = NULL;

  #else

  void *handle = dlopen (so_path, RTLD_NOW);

  if (handle == NULL)
  {
    fprintf (stderr, "harness: dlopen(%s): %s\n", so_path, dlerror ());
    return 2;
  }

  MODULE_INIT_FN module_init = (MODULE_INIT_FN) dlsym (handle, "module_init");

  if (module_init == NULL)
  {
    fprintf (stderr, "harness: no module_init in %s\n", so_path);
    return 2;
  }

  #endif

  module_ctx_t module_ctx;

  memset (&module_ctx, 0, sizeof (module_ctx));

  module_ctx.module_usage_notice  = MODULE_DEFAULT;
  module_ctx.module_advice_notice = MODULE_DEFAULT;

  module_init (&module_ctx);

  if (module_ctx.module_context_size != MODULE_CONTEXT_SIZE_CURRENT)
  {
    fprintf (stderr, "harness: module context size mismatch for -m %d "
                     "(got %zu, expected %zu) -- rebuild the plugins\n",
             hash_mode, module_ctx.module_context_size, (size_t) MODULE_CONTEXT_SIZE_CURRENT);
    return 2;
  }

  if (!IS_SET (module_ctx.module_hash_decode))
  {
    printf ("-m %d: no module_hash_decode (nothing host-side to test)\n", hash_mode);
    return 0;
  }

  user_options_t       uo;
  user_options_extra_t uoe;

  memset (&uo,  0, sizeof (uo));
  memset (&uoe, 0, sizeof (uoe));

  uo.hash_mode = (u32) hash_mode;
  uo.hex_salt  = false;

  hashconfig_t hashconfig;

  build_hashconfig (&hashconfig, &module_ctx, &uo, &uoe, hash_mode);

  const char *hash = override_hash;

  if (hash == NULL)
  {
    if (!IS_SET (module_ctx.module_st_hash))
    {
      printf ("-m %d: no example hash available, skipping\n", hash_mode);
      return 0;
    }

    hash = module_ctx.module_st_hash (&hashconfig, &uo, &uoe);
  }

  if (hash == NULL)
  {
    printf ("-m %d: example hash is NULL, skipping\n", hash_mode);
    return 0;
  }

  printf ("-m %d (%s): esalt=%llu hook_salt=%llu dgst=%u sep='%c'\n",
          hash_mode,
          IS_SET (module_ctx.module_hash_name) ? module_ctx.module_hash_name (&hashconfig, &uo, &uoe) : "?",
          (unsigned long long) hashconfig.esalt_size, (unsigned long long) hashconfig.hook_salt_size, hashconfig.dgst_size,
          hashconfig.separator ? hashconfig.separator : '?');

  // Copy the input into an exactly-sized heap buffer. When the caller passes
  // --hash, the string lives in argv, and a read past its end is not something
  // ASan or Valgrind can bound-check -- an exact malloc makes the overread land
  // on a redzone and get reported, which is the whole point of a repro.
  const int hash_len = (int) strlen (hash);

  char *hash_exact = (char *) xalloc ((size_t) hash_len);
  memcpy (hash_exact, hash, (size_t) hash_len);

  parse_one (&module_ctx, &hashconfig, hash_exact, hash_len, "example");

  free (hash_exact);

  if (do_mutate) mutate (&module_ctx, &hashconfig, hash);

  if (handle != NULL) dlclose (handle);

  return g_findings ? 1 : 0;
}

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "filehandling.h"
#include "folder.h"
#include "modules.h"
#include "interface.h"
#include "module_options.h"
#include "module_options_cache.h"

#include <inttypes.h>
#include <stdarg.h>

// The rows every module registers, kept so that a start does not have to load every module to learn
// its options. The file is text, one record per line, the fields of a record separated by tabs:
//
//   hashcat module options cache   format
//   build    version  comptime  plugin interface  module context size  interface minimum  pointer size  platform
//   module   file name  size  mtime seconds  mtime nanoseconds  rows
//   row      name  type  flags  min  max  def  brain slot  check  alias  le  requires  excludes  help type  help  help example
//   end      modules
//
// A row holds what the register hook returned, unchecked, so that reading it back goes through the
// same checks in module_options_add () that loading the module goes through. Of a check callback only
// whether there is one is kept: the callback itself runs from the loaded module of the hash-mode in
// use, the only one whose options are checked. A string is "-" for none and "=" and the text
// otherwise, with a backslash and every byte outside printable ASCII written as \xHH.

#define MODULE_CACHE_MAGIC    "hashcat module options cache"
#define MODULE_CACHE_FORMAT   1
#define MODULE_CACHE_SIZE_MAX (16 * 1024 * 1024)
#define MODULE_CACHE_FIELDS   16

#if defined (_WIN)
#define MODULE_CACHE_OS "windows"
#elif defined (__CYGWIN__)
#define MODULE_CACHE_OS "cygwin"
#elif defined (__APPLE__)
#define MODULE_CACHE_OS "macos"
#elif defined (__linux__)
#define MODULE_CACHE_OS "linux"
#elif defined (__FreeBSD__)
#define MODULE_CACHE_OS "freebsd"
#else
#define MODULE_CACHE_OS "posix"
#endif

#if defined (__x86_64__) || defined (_M_X64)
#define MODULE_CACHE_CPU "x86_64"
#elif defined (__aarch64__) || defined (_M_ARM64)
#define MODULE_CACHE_CPU "arm64"
#elif defined (__i386__) || defined (_M_IX86)
#define MODULE_CACHE_CPU "x86"
#else
#define MODULE_CACHE_CPU "cpu"
#endif

typedef struct module_cache_text
{
  char   *buf;
  size_t  len;
  size_t  size;

} module_cache_text_t;

struct module_cache_writer
{
  module_cache_text_t text;

  u32                 modules_cnt;
};

// Stands for the check callback of a row read back from the file. module_options_add () only tests
// whether a row has one, and never calls it.

static bool module_cache_check (MAYBE_UNUSED const char *value, MAYBE_UNUSED char *err, MAYBE_UNUSED const size_t err_sz)
{
  return true;
}

bool module_cache_identity (const char *path, module_cache_id_t *id)
{
  #if defined (_WIN)

  WIN32_FILE_ATTRIBUTE_DATA data;

  if (GetFileAttributesExA (path, GetFileExInfoStandard, &data) == 0) return false;

  const u64 ticks = ((u64) data.ftLastWriteTime.dwHighDateTime << 32) | ((u64) data.ftLastWriteTime.dwLowDateTime << 0);

  id->size       = ((u64) data.nFileSizeHigh << 32) | ((u64) data.nFileSizeLow << 0);
  id->mtime_sec  = ticks / 10000000;
  id->mtime_nsec = (ticks % 10000000) * 100;

  #else

  struct stat st;

  if (stat (path, &st) == -1) return false;

  id->size      = (u64) st.st_size;
  id->mtime_sec = (u64) st.st_mtime;

  #if defined (__APPLE__)
  id->mtime_nsec = (u64) st.st_mtimespec.tv_nsec;
  #elif defined (__linux__) || defined (__CYGWIN__) || defined (__FreeBSD__) || defined (__NetBSD__) || defined (__OpenBSD__) || defined (__DragonFly__)
  id->mtime_nsec = (u64) st.st_mtim.tv_nsec;
  #else
  id->mtime_nsec = 0;
  #endif

  #endif

  return true;
}

static void module_cache_text_add (module_cache_text_t *text, const char *s, const size_t len)
{
  if ((text->len + len + 1) > text->size)
  {
    const size_t add = MAX (len + 1, (size_t) 65536);

    text->buf = (char *) hcrealloc (text->buf, text->size, add);

    text->size += add;
  }

  memcpy (&text->buf[text->len], s, len);

  text->len += len;

  text->buf[text->len] = 0;
}

static void module_cache_text_printf (module_cache_text_t *text, const char *format, ...)
{
  char line[256];

  va_list ap;

  va_start (ap, format);

  const int len = vsnprintf (line, sizeof (line), format, ap);

  va_end (ap);

  if (len < 0) return;

  module_cache_text_add (text, line, MIN ((size_t) len, sizeof (line) - 1));
}

static void module_cache_text_string (module_cache_text_t *text, const char *s)
{
  if (s == NULL)
  {
    module_cache_text_add (text, "\t-", 2);

    return;
  }

  module_cache_text_add (text, "\t=", 2);

  const size_t len = strlen (s);

  for (size_t i = 0; i < len; i++)
  {
    const u8 c = (u8) s[i];

    if ((c < 0x20) || (c > 0x7e) || (c == '\\'))
    {
      module_cache_text_printf (text, "\\x%02x", c);

      continue;
    }

    module_cache_text_add (text, &s[i], 1);
  }
}

// Everything other than the modules themselves that a scan of the modules depends on: the binary, the
// interface a module has to be built for, and the platform.

static void module_cache_text_build (module_cache_text_t *text, const char *version, const int comptime)
{
  module_cache_text_add (text, "build", 5);

  module_cache_text_string (text, version);

  module_cache_text_printf (text, "\t%d\t%d\t%u\t%d\t%u\t%s-%s\n", comptime, HC_PLUGIN_ABI_VERSION, (u32) MODULE_CONTEXT_SIZE_CURRENT, MODULE_INTERFACE_VERSION_MINIMUM, (u32) sizeof (void *), MODULE_CACHE_OS, MODULE_CACHE_CPU);
}

module_cache_writer_t *module_cache_write_begin (const char *version, const int comptime)
{
  module_cache_writer_t *writer = (module_cache_writer_t *) hccalloc (1, sizeof (module_cache_writer_t));

  module_cache_text_printf (&writer->text, "%s\t%d\n", MODULE_CACHE_MAGIC, MODULE_CACHE_FORMAT);

  module_cache_text_build (&writer->text, version, comptime);

  return writer;
}

void module_cache_write_rows (module_cache_writer_t *writer, const char *base, const module_cache_id_t *id, const module_option_t *rows)
{
  u32 rows_cnt = 0;

  if (rows != NULL)
  {
    while (rows[rows_cnt].name != NULL) rows_cnt++;
  }

  module_cache_text_t *text = &writer->text;

  module_cache_text_add (text, "module", 6);

  module_cache_text_string (text, base);

  module_cache_text_printf (text, "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%u\n", id->size, id->mtime_sec, id->mtime_nsec, rows_cnt);

  for (u32 i = 0; i < rows_cnt; i++)
  {
    const module_option_t *row = &rows[i];

    module_cache_text_add (text, "row", 3);

    module_cache_text_string (text, row->name);

    module_cache_text_printf (text, "\t%u\t%u\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%u\t%u", (u32) row->type, row->flags, row->min, row->max, row->def, row->brain_slot, (u32) ((row->check != NULL) ? 1 : 0));

    module_cache_text_string (text, row->alias);
    module_cache_text_string (text, row->le);
    module_cache_text_string (text, row->requires);
    module_cache_text_string (text, row->excludes);
    module_cache_text_string (text, row->help_type);
    module_cache_text_string (text, row->help);
    module_cache_text_string (text, row->help_example);

    module_cache_text_add (text, "\n", 1);
  }

  writer->modules_cnt++;
}

// Written beside its name and moved onto it, so that a start never reads half a file, and two starts
// that write it at once do not write into each other. A directory that cannot be written to is a
// normal way to run, so a failure leaves no file and the next start scans again.

bool module_cache_write_end (module_cache_writer_t *writer, const char *dir, const bool make_dir, const bool keep)
{
  bool ok = keep;

  char *path = NULL;
  char *tmp  = NULL;

  if (ok == true)
  {
    module_cache_text_printf (&writer->text, "end\t%u\n", writer->modules_cnt);

    // the default cache directory is made the way folder_config_init () makes it, one named by
    // --cache-path is taken as given

    if (make_dir == true) hc_mkdir_rec (dir, 0700);

    hc_asprintf (&path, "%s/%s", dir, MODULE_CACHE_FILE);
    hc_asprintf (&tmp,  "%s/%s.%016" PRIx64 ".tmp", dir, MODULE_CACHE_FILE, hc_tmp_tag ());

    ok = (path != NULL) && (tmp != NULL);
  }

  if (ok == true)
  {
    HCFILE fp;

    ok = hc_fopen_raw (&fp, tmp, "wb");

    if (ok == true)
    {
      ok = (hc_fwrite (writer->text.buf, 1, writer->text.len, &fp) == writer->text.len);

      hc_fclose (&fp);

      // a full disk can let every write succeed and lose the end at the close

      module_cache_id_t id;

      if (ok == true) ok = (module_cache_identity (tmp, &id) == true) && (id.size == (u64) writer->text.len);

      // rename () refuses an existing target on Windows, where POSIX replaces it

      #if defined (_WIN)
      if (ok == true) remove (path);
      #endif

      if (ok == true) ok = (rename (tmp, path) == 0);

      if (ok == false) unlink (tmp);
    }
  }

  hcfree (tmp);
  hcfree (path);

  hcfree (writer->text.buf);
  hcfree (writer);

  return ok;
}

static u32 module_cache_split (char *line, char **fields, const u32 fields_max)
{
  u32 cnt = 0;

  fields[cnt] = line;

  cnt++;

  const size_t len = strlen (line);

  for (size_t i = 0; i < len; i++)
  {
    if (line[i] != '\t') continue;

    // one field more than any record has makes the record wrong rather than silently shorter

    if (cnt == fields_max) return fields_max + 1;

    line[i] = 0;

    fields[cnt] = &line[i + 1];

    cnt++;
  }

  return cnt;
}

static bool module_cache_u64 (const char *s, u64 *value)
{
  if (s[0] == 0) return false;

  u64 v = 0;

  const size_t len = strlen (s);

  for (size_t i = 0; i < len; i++)
  {
    if ((s[i] < '0') || (s[i] > '9')) return false;

    const u64 digit = (u64) (s[i] - '0');

    if (v > ((UINT64_MAX - digit) / 10)) return false;

    v = (v * 10) + digit;
  }

  *value = v;

  return true;
}

static bool module_cache_u32 (const char *s, u32 *value)
{
  u64 v = 0;

  if (module_cache_u64 (s, &v) == false) return false;

  if (v > UINT32_MAX) return false;

  *value = (u32) v;

  return true;
}

static int module_cache_hex (const char c)
{
  if ((c >= '0') && (c <= '9')) return c - '0';
  if ((c >= 'a') && (c <= 'f')) return c - 'a' + 10;

  return -1;
}

// A string field decoded where it stands, which only ever makes it shorter.

static bool module_cache_string (char *field, const char **value)
{
  if (strcmp (field, "-") == 0)
  {
    *value = NULL;

    return true;
  }

  if (field[0] != '=') return false;

  const size_t len = strlen (field);

  size_t out = 0;

  size_t i = 1;

  while (i < len)
  {
    if (field[i] != '\\')
    {
      field[out] = field[i];

      out++;

      i++;

      continue;
    }

    if ((i + 3) >= len) return false;

    if (field[i + 1] != 'x') return false;

    const int hi = module_cache_hex (field[i + 2]);
    const int lo = module_cache_hex (field[i + 3]);

    if ((hi == -1) || (lo == -1)) return false;

    field[out] = (char) ((hi << 4) | (lo << 0));

    out++;

    i += 4;
  }

  field[out] = 0;

  *value = field;

  return true;
}

void module_cache_free (module_cache_t *cache)
{
  if (cache == NULL) return;

  for (u32 i = 0; i < cache->modules_cnt; i++) hcfree (cache->modules[i].rows);

  hcfree (cache->modules);
  hcfree (cache->buf);
  hcfree (cache);
}

static bool module_cache_parse_row (char **fields, module_option_t *row)
{
  u32 type  = 0;
  u32 check = 0;

  if (module_cache_string (fields[1], &row->name) == false) return false;

  if (row->name == NULL) return false;

  if (module_cache_u32 (fields[2], &type)            == false) return false;
  if (module_cache_u32 (fields[3], &row->flags)      == false) return false;
  if (module_cache_u64 (fields[4], &row->min)        == false) return false;
  if (module_cache_u64 (fields[5], &row->max)        == false) return false;
  if (module_cache_u64 (fields[6], &row->def)        == false) return false;
  if (module_cache_u32 (fields[7], &row->brain_slot) == false) return false;
  if (module_cache_u32 (fields[8], &check)           == false) return false;

  if (check > 1) return false;

  row->type  = (module_option_type_t) type;
  row->check = (check == 1) ? module_cache_check : NULL;

  if (module_cache_string (fields[9],  &row->alias)        == false) return false;
  if (module_cache_string (fields[10], &row->le)           == false) return false;
  if (module_cache_string (fields[11], &row->requires)     == false) return false;
  if (module_cache_string (fields[12], &row->excludes)     == false) return false;
  if (module_cache_string (fields[13], &row->help_type)    == false) return false;
  if (module_cache_string (fields[14], &row->help)         == false) return false;
  if (module_cache_string (fields[15], &row->help_example) == false) return false;

  return true;
}

// The file as it is on disk, or NULL for a file that is not there, not readable, not complete, not
// in this format, or written by another build or for another platform. Whether its modules are the
// ones in modules/ now is checked by the caller.

module_cache_t *module_cache_load (const char *dir, const char *version, const int comptime)
{
  char *path = NULL;

  hc_asprintf (&path, "%s/%s", dir, MODULE_CACHE_FILE);

  if (path == NULL) return NULL;

  HCFILE fp;

  const bool open = hc_fopen_raw (&fp, path, "rb");

  hcfree (path);

  if (open == false) return NULL;

  struct stat st;

  if ((hc_fstat (&fp, &st) == -1) || (st.st_size <= 0) || (st.st_size > MODULE_CACHE_SIZE_MAX))
  {
    hc_fclose (&fp);

    return NULL;
  }

  const size_t size = (size_t) st.st_size;

  char *buf = (char *) hcmalloc (size + 1);

  const size_t got = hc_fread (buf, 1, size, &fp);

  hc_fclose (&fp);

  if (got != size)
  {
    hcfree (buf);

    return NULL;
  }

  buf[size] = 0;

  module_cache_t *cache = (module_cache_t *) hccalloc (1, sizeof (module_cache_t));

  cache->buf = buf;

  // the first two lines are compared as text with the ones this build would write

  module_cache_text_t want;

  memset (&want, 0, sizeof (want));

  module_cache_text_printf (&want, "%s\t%d\n", MODULE_CACHE_MAGIC, MODULE_CACHE_FORMAT);

  module_cache_text_build (&want, version, comptime);

  const bool head = (want.len <= size) && (memcmp (buf, want.buf, want.len) == 0);

  size_t pos = want.len;

  hcfree (want.buf);

  bool ok = head;

  bool done = false;

  module_cache_module_t *module = NULL;

  u32 rows_left = 0;

  while ((ok == true) && (pos < size))
  {
    char *line = &buf[pos];

    char *eol = strchr (line, '\n');

    if (eol == NULL)
    {
      ok = false;

      break;
    }

    *eol = 0;

    pos += strlen (line) + 1;

    // nothing may follow the end record

    if (done == true)
    {
      ok = false;

      break;
    }

    char *fields[MODULE_CACHE_FIELDS];

    const u32 cnt = module_cache_split (line, fields, MODULE_CACHE_FIELDS);

    if (rows_left > 0)
    {
      ok = (cnt == MODULE_CACHE_FIELDS) && (strcmp (fields[0], "row") == 0) && (module_cache_parse_row (fields, &module->rows[module->rows_cnt]) == true);

      module->rows_cnt++;

      rows_left--;

      continue;
    }

    if ((cnt == 2) && (strcmp (fields[0], "end") == 0))
    {
      u32 modules = 0;

      ok = (module_cache_u32 (fields[1], &modules) == true) && (modules == cache->modules_cnt);

      done = true;

      continue;
    }

    if ((cnt != 6) || (strcmp (fields[0], "module") != 0))
    {
      ok = false;

      break;
    }

    cache->modules = (module_cache_module_t *) hcrealloc (cache->modules, cache->modules_cnt * sizeof (module_cache_module_t), sizeof (module_cache_module_t));

    module = &cache->modules[cache->modules_cnt];

    cache->modules_cnt++;

    u32 rows = 0;

    if (module_cache_string (fields[1], &module->base)      == false) ok = false;
    if (module_cache_u64    (fields[2], &module->id.size)       == false) ok = false;
    if (module_cache_u64    (fields[3], &module->id.mtime_sec)  == false) ok = false;
    if (module_cache_u64    (fields[4], &module->id.mtime_nsec) == false) ok = false;
    if (module_cache_u32    (fields[5], &rows)               == false) ok = false;

    if ((ok == true) && (module->base == NULL)) ok = false;

    if ((ok == true) && (rows > MODULE_OPTIONS_MAX)) ok = false;

    if (ok == false) break;

    // one more row than the module registered, left empty: the end of the list, as the hook ends it

    module->rows = (module_option_t *) hccalloc (rows + 1, sizeof (module_option_t));

    rows_left = rows;
  }

  if ((ok == false) || (done == false) || (rows_left > 0))
  {
    module_cache_free (cache);

    return NULL;
  }

  return cache;
}

/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_MODULE_OPTIONS_CACHE_H
#define HC_MODULE_OPTIONS_CACHE_H

// The rows every module registers, kept in the cache directory so that a start reads one file instead
// of loading every module. The file belongs to one kind of module file, so a Linux and a Windows build
// that share a tree each keep their own.

#if defined (_WIN) || defined (__CYGWIN__)
#define MODULE_CACHE_FILE "module_options.dll.cache"
#else
#define MODULE_CACHE_FILE "module_options.so.cache"
#endif

// What distinguishes one state of a module file from another: a module rebuilt, replaced or touched
// changes at least one of these.

typedef struct module_cache_id
{
  u64 size;
  u64 mtime_sec;
  u64 mtime_nsec;

} module_cache_id_t;

// One module file as the cache holds it: its name in modules/, its identity, and the rows its
// register hook returned, ended by a row whose name is NULL. The strings point into the buffer the
// file was read into.

typedef struct module_cache_module
{
  const char        *base;
  module_cache_id_t  id;
  module_option_t   *rows;
  u32                rows_cnt;

} module_cache_module_t;

typedef struct module_cache
{
  char                  *buf;
  module_cache_module_t *modules;
  u32                    modules_cnt;

} module_cache_t;

typedef struct module_cache_writer module_cache_writer_t;

bool                   module_cache_identity    (const char *path, module_cache_id_t *id);
module_cache_t        *module_cache_load        (const char *dir, const char *version, const int comptime);
void                   module_cache_free        (module_cache_t *cache);
module_cache_writer_t *module_cache_write_begin (const char *version, const int comptime);
void                   module_cache_write_rows  (module_cache_writer_t *writer, const char *base, const module_cache_id_t *id, const module_option_t *rows);
bool                   module_cache_write_end   (module_cache_writer_t *writer, const char *dir, const bool make_dir, const bool keep);

#endif // HC_MODULE_OPTIONS_CACHE_H

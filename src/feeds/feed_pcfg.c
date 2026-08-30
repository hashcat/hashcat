/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "filehandling.h"
#include "path.h"
#include "shared.h"
#include "convert.h"
#include "system.h"
#include "feed.h"
#include "event.h"

#include <math.h>
#include <limits.h>
#include <inttypes.h>
// The prefetch workers, on both platforms hashcat builds for.
//
// A feed is a plugin and links against nothing but the core, and the core reaches Windows threads
// through its own macros in a header a plugin does not include. Windows also has no pthread unless a
// runtime DLL is shipped beside the binary, which hashcat deliberately does not do. So the handful of
// primitives used here are named once and mapped to whichever platform this is built for.

#if defined (_WIN) || defined (__CYGWIN__)

#include <windows.h>

typedef CRITICAL_SECTION   pcfg_mux_t;
typedef CONDITION_VARIABLE pcfg_cv_t;
typedef HANDLE             pcfg_os_thread_t;

#define pcfg_mux_init(m)     InitializeCriticalSection (m)
#define pcfg_mux_destroy(m)  DeleteCriticalSection (m)
#define pcfg_mux_lock(m)     EnterCriticalSection (m)
#define pcfg_mux_unlock(m)   LeaveCriticalSection (m)

#define pcfg_cv_init(c)      InitializeConditionVariable (c)
#define pcfg_cv_destroy(c)   ((void) (c))
#define pcfg_cv_wait(c,m)    SleepConditionVariableCS (c, m, INFINITE)
#define pcfg_cv_broadcast(c) WakeAllConditionVariable (c)

#define pcfg_thread_ret           DWORD WINAPI
#define pcfg_thread_done          0

#define pcfg_thread_create(t,f,a) (((t) = CreateThread (NULL, 0, f, a, 0, NULL)) != NULL)
#define pcfg_thread_join(t)       do { WaitForSingleObject ((t), INFINITE); CloseHandle (t); } while (0)

#else

#include <pthread.h>
#include <unistd.h>

typedef pthread_mutex_t pcfg_mux_t;
typedef pthread_cond_t  pcfg_cv_t;
typedef pthread_t       pcfg_os_thread_t;

#define pcfg_mux_init(m)     pthread_mutex_init (m, NULL)
#define pcfg_mux_destroy(m)  pthread_mutex_destroy (m)
#define pcfg_mux_lock(m)     pthread_mutex_lock (m)
#define pcfg_mux_unlock(m)   pthread_mutex_unlock (m)

#define pcfg_cv_init(c)      pthread_cond_init (c, NULL)
#define pcfg_cv_destroy(c)   pthread_cond_destroy (c)
#define pcfg_cv_wait(c,m)    pthread_cond_wait (c, m)
#define pcfg_cv_broadcast(c) pthread_cond_broadcast (c)

#define pcfg_thread_ret           void *
#define pcfg_thread_done          NULL

#define pcfg_thread_create(t,f,a) (pthread_create (&(t), NULL, f, a) == 0)
#define pcfg_thread_join(t)       pthread_join ((t), NULL)

#endif

// How many threads are worth starting. A caller caps this against its own work, so what is wanted
// here is the machine and not a policy.

static u32 pcfg_cpu_online (void)
{
#if defined (_WIN) || defined (__CYGWIN__)

  SYSTEM_INFO si;

  GetSystemInfo (&si);

  const u32 n = (u32) si.dwNumberOfProcessors;

#else

  const long got = sysconf (_SC_NPROCESSORS_ONLN);

  const u32 n = (got > 0) ? (u32) got : 1;

#endif

  if (n == 0) return 1;

  return n;
}

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;
const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_RULES | GENERIC_PLUGIN_OPTIONS_DEVICE;

#define PCFG_MAXTOK   24
#define PCFG_MAXSLOT  (PCFG_MAXTOK * 2)

// How many distinct terminal lists one ruleset may bring. The cache that maps a (type, length) key
// to a loaded list is indexed by the list number, so the two have to agree.

#define PCFG_LIST_CACHE 4096
#define PCFG_COSTCAP  64

#define PCFG_MAXROOT  16

#define PCFG_FRONT_UNITS    100000000

#define PCFG_PROBE_UNITS    4000000

#define PCFG_STEP_UNITS     100000

#define PCFG_DEV_KBITS_DEF  0
#define PCFG_DEV_KBITS_MIN  18

#define PCFG_DEV_KBITS_PROBE 22
#define PCFG_DEV_KBITS_MAX  27

#define PCFG_DEV_RECT_WANT  (PCFG_DEV_LANES * 16)

typedef struct
{
  u32  cnt;
  u32 *off;
  u8  *buf;

  u8  *ubuf;

  u32  nb;
  u32 *b_cost;
  u32 *b_start;
  u32 *b_cnt;
  u32 *b_len;

  u32  fixed_len;
  u32  max_len;

  // What the grammar called this list, kept only so that a structure can be written back out the way
  // its line in grammar.txt read it. Nothing in the enumeration reads them.

  u8   ty;
  u32  ln;

} pcfg_tlist_t;

typedef enum
{
  PCFG_SLOT_TERM = 0,
  PCFG_SLOT_MASK = 1,

} pcfg_slot_kind_t;

typedef struct
{
  u32 nslot;
  u8  kind[PCFG_MAXSLOT];
  int list[PCFG_MAXSLOT];

  // Characters this slot contributes, which is the number the structure's token carried. The list
  // handle alone cannot say it: a flat X or Y token of any length shares one list, and a candidate
  // cannot be cut back into segments without knowing where the cuts go.

  u16 tlen[PCFG_MAXSLOT];

  u32 cost;
  u32 cmin;
  u32 cmax;

  u64 *suf;

  u64 *usuf;

  u64 *udev;
  u32  cut;

  u32 total_len;

} pcfg_struct_t;

#define PCFG_OMEN_MAXLVL   10
#define PCFG_OMEN_MAXNGRAM 8
#define PCFG_OMEN_MAXK     56
#define PCFG_OMEN_MAXBYTE  256

typedef struct
{
  u32 dst;
  u32 coff;
  u8  clen;
  u8  lvl;

} pcfg_omen_tr_t;

typedef struct
{
  u32  clen;
  bool utf8;
  u32  kmax;
  u32  bmax;

  u32  nctx;
  u32 *ctx_off;
  pcfg_omen_tr_t *tr;
  u32  tr_cnt;

  u8  *cbuf;
  u32  cbuf_len;

  u32 *ip_ctx;
  u32 *ip_off;
  u8  *ip_len;
  u32  ip_lvl_off[PCFG_OMEN_MAXLVL + 2];
  u32  nip;

  u8  *ln_lvl;
  u8  *ln_k;
  u32  ln_cnt;

  u64 *w;

  u64 *ipsum;

  double *tprob;
  u64    *tcnt;

  u64 bytes;

} pcfg_omen_t;

typedef struct
{
  u32 mi;
  u32 lvl;
  u32 cost;
  u64 cnt;

} pcfg_omen_lvl_t;

typedef struct
{
  pcfg_tlist_t *lists;
  u32           lists_cnt;

  pcfg_struct_t *structs;
  u32            structs_cnt;

  pcfg_omen_t     *omen;
  u32              omen_cnt;

  pcfg_omen_lvl_t *omen_lvl;
  u32              omen_lvl_cnt;

  u64              omen_keyspace;
  u64              omen_bytes;

  u32              m_lines;
  bool             omen_want;

  // The candidate lookup= was asked about, pointing into the argument it came from, so it is not
  // freed. NULL when the run was asked to crack rather than to describe.

  const char      *lookup;

  u32 *lvl_cost;
  u64 *lvl_pref;
  u32  lvl_cnt;

  u32 **ls_struct;
  u64 **ls_pref;
  u32  *ls_cnt;

  u64 keyspace;

  u64 scale;
  u64 costmax;
  u32 kbits;
  u32 threads;
  bool walk;

  u32 maxword;
  u32 maxbyte;

  u64 front_rect;

  // Which pair the per structure suffix arrays currently hold, so a caller that wants the same pair
  // again reuses them instead of building them a second time.

  bool built;
  u32  built_maxword;
  u32  built_kbits;

  double maxgain;

  u32 *pool;
  u64  pool_size;
  u32 *pool_base;

  u32 *ent_base;
  bool varlen;

  hashcat_ctx_t *hcctx;

  u32 *pool_ubase;

  u32  il_cnt;

  u32 *ulvl_cost;
  u64 *ulvl_pref;
  u32  ulvl_cnt;

  u32 **uls_struct;
  u64 **uls_pref;
  u32  *uls_cnt;

  u64  units;

} pcfg_global_t;

typedef struct
{
  u32 oi;
  u32 lni;
  u32 ipi;
  u32 k;

  u32 ipl;

  u32 ctx  [PCFG_OMEN_MAXK + 1];
  u32 ti   [PCFG_OMEN_MAXK];
  u32 bud  [PCFG_OMEN_MAXK + 1];
  u32 boff [PCFG_OMEN_MAXK + 1];

  u8  buf[PCFG_OMEN_MAXBYTE];
  u32 len;

} pcfg_omen_walk_t;

typedef struct
{
  u64 pos;
  bool valid;

  bool omen;

  pcfg_omen_walk_t om;

  u32 si;
  u32 cost;
  u32 idx[PCFG_MAXSLOT];

  u32 inner;
  u32 inner_end;

  u32 buck[PCFG_MAXSLOT];

  u32 devstart;

  // These are indexed by the token number, and a structure's token count is bounded by its slot
  // count rather than by PCFG_MAXTOK: a token of one slot gives one token per slot, so a structure
  // at the PCFG_MAXSLOT limit has that many tokens. Sizing them for slots costs a few hundred bytes
  // per thread and removes the mismatch.

  u32  tcnt;
  u32  tslot[PCFG_MAXSLOT];
  u32  tba[PCFG_MAXSLOT];
  u32  tbm[PCFG_MAXSLOT];
  u32  trem[PCFG_MAXSLOT];
  u32  tcap[PCFG_MAXSLOT];
  u32  tfcap[PCFG_MAXSLOT];
  bool tdev[PCFG_MAXSLOT];
  u64  te[PCFG_MAXSLOT];

  struct pcfg_pf *pf;

} pcfg_thread_t;

static void pmsg (const pcfg_global_t *pg, const char *fmt, ...)
{
  char buf[HCBUFSIZ_TINY];

  va_list ap;

  va_start (ap, fmt);

  vsnprintf (buf, sizeof (buf), fmt, ap);

  va_end (ap);

  if (pg->hcctx != NULL)
  {
    event_log_info (pg->hcctx, "%s", buf);

    return;
  }

  printf ("%s\n", buf);
}

static void gerr (generic_global_ctx_t *g, const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  vsnprintf (g->error_msg, sizeof (g->error_msg), fmt, ap);
  va_end (ap);

  g->error = true;
}

// A ruleset large enough to matter drives the suffix counts to the top of u64, so every add and
// every multiply on them saturates. The two overflow tests are the ones libhashcat exports, written
// out here instead of called. These sit in the innermost loop of the suffix build, and a call into
// another shared object there cannot be inlined, so it costs a spill of the loop registers on every
// single addition.

static u64 sat_mul (const u64 a, const u64 b)
{
  if (a == 0) return 0;
  if (b == 0) return 0;

  if (a > (UINT64_MAX / b)) return UINT64_MAX - 1;

  const u64 r = a * b;

  return r;
}

static u64 sat_add (const u64 a, const u64 b)
{
  if (a > (UINT64_MAX - b)) return UINT64_MAX - 1;

  const u64 r = a + b;

  return r;
}

static bool pcfg_fopen (HCFILE *fp, const char *path)
{
  if (hc_fopen (fp, path, "rb") == true) return true;

  char xz[PATH_MAX + 1];

  const int len = snprintf (xz, sizeof (xz), "%s.xz", path);

  if (len < 0) return false;
  if (len >= (int) sizeof (xz)) return false;

  const bool rc = hc_fopen (fp, xz, "rb");

  return rc;
}

#define PCFG_TAR_BLOCK 512
#define PCFG_ARC_NAME  257

typedef struct
{
  char   name[PCFG_ARC_NAME];

  size_t off;
  size_t len;

} pcfg_arc_ent_t;

typedef struct
{
  u8 *buf;

  size_t len;

  pcfg_arc_ent_t *ent;

  u32 ent_cnt;

} pcfg_arc_t;

static u64 tar_octal (const char *s, const u32 n)
{
  u64 v = 0;

  for (u32 i = 0; i < n; i++)
  {
    const char c = s[i];

    if (c < '0') continue;
    if (c > '7') continue;

    v = (v * 8) + (u64) (c - '0');
  }

  return v;
}

static bool arc_is_ruleset_dir (const char *s, const size_t n)
{
  static const char *own[] = { "Grammar", "Alpha", "Capitalization", "Digits", "Other", "Keyboard", "Context", "Years", "Omen" };

  for (u32 i = 0; i < (sizeof (own) / sizeof (own[0])); i++)
  {
    if (strlen (own[i]) != n) continue;

    if (strncmp (s, own[i], n) == 0) return true;
  }

  return false;
}

static void arc_free (pcfg_arc_t *a)
{
  if (a == NULL) return;

  hcfree (a->buf);
  hcfree (a->ent);

  hcfree (a);
}

static pcfg_arc_t *arc_load (const char *path)
{
  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) return NULL;

  size_t cap = 1024 * 1024;
  size_t len = 0;

  u8 *buf = (u8 *) hcmalloc (cap);

  if (buf == NULL)
  {
    hc_fclose (&fp);

    return NULL;
  }

  while (true)
  {
    if (len == cap)
    {
      cap *= 2;

      u8 *nb = (u8 *) hcrealloc (buf, len, cap - len);

      if (nb == NULL)
      {
        hcfree (buf);
        hc_fclose (&fp);

        return NULL;
      }

      buf = nb;
    }

    const size_t got = hc_fread (buf + len, 1, cap - len, &fp);

    if (got == 0) break;
    if (got == (size_t) -1) break;

    len += got;
  }

  hc_fclose (&fp);

  pcfg_arc_t *a = (pcfg_arc_t *) hccalloc (1, sizeof (pcfg_arc_t));

  if (a == NULL)
  {
    hcfree (buf);

    return NULL;
  }

  a->buf = buf;
  a->len = len;

  u32 room = 64;

  a->ent = (pcfg_arc_ent_t *) hcmalloc (room * sizeof (pcfg_arc_ent_t));

  if (a->ent == NULL)
  {
    arc_free (a);

    return NULL;
  }

  size_t at = 0;

  while ((at + PCFG_TAR_BLOCK) <= len)
  {
    const char *h = (const char *) (buf + at);

    if (h[0] == 0) break;

    const u64 size = tar_octal (h + 124, 12);

    const char type = h[156];

    at += PCFG_TAR_BLOCK;

    if ((type == '0') || (type == 0))
    {
      if ((at + size) <= len)
      {
        char name[PCFG_ARC_NAME];

        const char *pre = h + 345;

        if (pre[0] != 0)
        {
          snprintf (name, sizeof (name), "%.155s/%.100s", pre, h);
        }
        else
        {
          snprintf (name, sizeof (name), "%.100s", h);
        }

        const char *rel = name;

        if ((rel[0] == '.') && (rel[1] == '/')) rel += 2;

        if (a->ent_cnt == room)
        {
          const u32 was = room;

          room *= 2;

          pcfg_arc_ent_t *ne = (pcfg_arc_ent_t *) hcrealloc (a->ent, was * sizeof (pcfg_arc_ent_t), (room - was) * sizeof (pcfg_arc_ent_t));

          if (ne == NULL)
          {
            arc_free (a);

            return NULL;
          }

          a->ent = ne;
        }

        pcfg_arc_ent_t *e = &a->ent[a->ent_cnt];

        snprintf (e->name, sizeof (e->name), "%s", rel);

        e->off = at;
        e->len = (size_t) size;

        a->ent_cnt++;
      }
    }

    at += ((size_t) size + PCFG_TAR_BLOCK - 1) & ~((size_t) PCFG_TAR_BLOCK - 1);
  }

  if (a->ent_cnt > 0)
  {
    const char *slash = strchr (a->ent[0].name, '/');

    if (slash != NULL)
    {
      const size_t n = (size_t) (slash - a->ent[0].name);

      bool strip = true;

      if (arc_is_ruleset_dir (a->ent[0].name, n) == true) strip = false;

      for (u32 i = 1; i < a->ent_cnt; i++)
      {
        if (strncmp (a->ent[i].name, a->ent[0].name, n + 1) != 0) strip = false;
      }

      if (strip == true)
      {
        for (u32 i = 0; i < a->ent_cnt; i++)
        {
          memmove (a->ent[i].name, a->ent[i].name + n + 1, strlen (a->ent[i].name + n + 1) + 1);
        }
      }
    }
  }

  return a;
}

static const char *PCFG_DEFAULT_ROOT[] = { "default-passwords" };

#define PCFG_DEFAULT_ROOTS 1

static bool pcfg_has_sep (const char *s)
{
  if (strchr (s, '/')  != NULL) return true;

  #if defined (_WIN) || defined (__CYGWIN__)
  if (strchr (s, '\\') != NULL) return true;
  #endif

  return false;
}

static char *pcfg_resolve_root (const generic_global_ctx_t *global_ctx, const char *name, bool *by_name)
{
  if (by_name) *by_name = false;

  if (pcfg_has_sep (name) == true) return hcstrdup (name);

  const char *roots[] = { global_ctx->profile_dir, global_ctx->shared_dir };

  for (u32 i = 0; i < 2; i++)
  {
    if (roots[i] == NULL) continue;

    const char *forms[] = { "%s/pcfg/%s", "%s/pcfg/%s.tar.xz" };

    for (u32 k = 0; k < 2; k++)
    {
      char *path = (char *) hcmalloc (HCBUFSIZ_TINY);

      snprintf (path, HCBUFSIZ_TINY, forms[k], roots[i], name);

      if (hc_path_exist (path) == true)
      {
        if (by_name) *by_name = true;

        return path;
      }

      hcfree (path);
    }
  }

  return hcstrdup (name);
}

static bool arc_open (const pcfg_arc_t *a, const char *rel, HCFILE *fp)
{
  for (u32 i = 0; i < a->ent_cnt; i++)
  {
    const pcfg_arc_ent_t *e = &a->ent[i];

    if (strcmp (e->name, rel) != 0) continue;

    const bool rc = hc_fopen_mem (fp, a->buf + e->off, e->len);

    return rc;
  }

  return false;
}

typedef struct
{
  u32 lo;
  u32 hi;
  u32 step;
  int delta;

} pcfg_uc_range_t;

static const pcfg_uc_range_t PCFG_UC[] =
{
  { 0x00061, 0x0007a, 1,    -32 },
  { 0x000b5, 0x000b5, 1,    743 },
  { 0x000e0, 0x000f6, 1,    -32 },
  { 0x000f8, 0x000fe, 1,    -32 },
  { 0x000ff, 0x000ff, 1,    121 },
  { 0x00101, 0x0012f, 2,     -1 },
  { 0x00133, 0x00137, 2,     -1 },
  { 0x0013a, 0x00148, 2,     -1 },
  { 0x0014b, 0x00177, 2,     -1 },
  { 0x0017a, 0x0017e, 2,     -1 },
  { 0x00180, 0x00180, 1,    195 },
  { 0x00183, 0x00185, 2,     -1 },
  { 0x00188, 0x00188, 1,     -1 },
  { 0x0018c, 0x0018c, 1,     -1 },
  { 0x00192, 0x00192, 1,     -1 },
  { 0x00195, 0x00195, 1,     97 },
  { 0x00199, 0x00199, 1,     -1 },
  { 0x0019a, 0x0019a, 1,    163 },
  { 0x0019e, 0x0019e, 1,    130 },
  { 0x001a1, 0x001a5, 2,     -1 },
  { 0x001a8, 0x001a8, 1,     -1 },
  { 0x001ad, 0x001ad, 1,     -1 },
  { 0x001b0, 0x001b0, 1,     -1 },
  { 0x001b4, 0x001b6, 2,     -1 },
  { 0x001b9, 0x001b9, 1,     -1 },
  { 0x001bd, 0x001bd, 1,     -1 },
  { 0x001bf, 0x001bf, 1,     56 },
  { 0x001c5, 0x001c5, 1,     -1 },
  { 0x001c6, 0x001c6, 1,     -2 },
  { 0x001c8, 0x001c8, 1,     -1 },
  { 0x001c9, 0x001c9, 1,     -2 },
  { 0x001cb, 0x001cb, 1,     -1 },
  { 0x001cc, 0x001cc, 1,     -2 },
  { 0x001ce, 0x001dc, 2,     -1 },
  { 0x001dd, 0x001dd, 1,    -79 },
  { 0x001df, 0x001ef, 2,     -1 },
  { 0x001f2, 0x001f2, 1,     -1 },
  { 0x001f3, 0x001f3, 1,     -2 },
  { 0x001f5, 0x001f5, 1,     -1 },
  { 0x001f9, 0x0021f, 2,     -1 },
  { 0x00223, 0x00233, 2,     -1 },
  { 0x0023c, 0x0023c, 1,     -1 },
  { 0x00242, 0x00242, 1,     -1 },
  { 0x00247, 0x0024f, 2,     -1 },
  { 0x00253, 0x00253, 1,   -210 },
  { 0x00254, 0x00254, 1,   -206 },
  { 0x00256, 0x00257, 1,   -205 },
  { 0x00259, 0x00259, 1,   -202 },
  { 0x0025b, 0x0025b, 1,   -203 },
  { 0x00260, 0x00260, 1,   -205 },
  { 0x00263, 0x00263, 1,   -207 },
  { 0x00268, 0x00268, 1,   -209 },
  { 0x00269, 0x00269, 1,   -211 },
  { 0x0026f, 0x0026f, 1,   -211 },
  { 0x00272, 0x00272, 1,   -213 },
  { 0x00275, 0x00275, 1,   -214 },
  { 0x00280, 0x00280, 1,   -218 },
  { 0x00283, 0x00283, 1,   -218 },
  { 0x00288, 0x00288, 1,   -218 },
  { 0x00289, 0x00289, 1,    -69 },
  { 0x0028a, 0x0028b, 1,   -217 },
  { 0x0028c, 0x0028c, 1,    -71 },
  { 0x00292, 0x00292, 1,   -219 },
  { 0x00345, 0x00345, 1,     84 },
  { 0x00371, 0x00373, 2,     -1 },
  { 0x00377, 0x00377, 1,     -1 },
  { 0x0037b, 0x0037d, 1,    130 },
  { 0x003ac, 0x003ac, 1,    -38 },
  { 0x003ad, 0x003af, 1,    -37 },
  { 0x003b1, 0x003c1, 1,    -32 },
  { 0x003c2, 0x003c2, 1,    -31 },
  { 0x003c3, 0x003cb, 1,    -32 },
  { 0x003cc, 0x003cc, 1,    -64 },
  { 0x003cd, 0x003ce, 1,    -63 },
  { 0x003d0, 0x003d0, 1,    -62 },
  { 0x003d1, 0x003d1, 1,    -57 },
  { 0x003d5, 0x003d5, 1,    -47 },
  { 0x003d6, 0x003d6, 1,    -54 },
  { 0x003d7, 0x003d7, 1,     -8 },
  { 0x003d9, 0x003ef, 2,     -1 },
  { 0x003f0, 0x003f0, 1,    -86 },
  { 0x003f1, 0x003f1, 1,    -80 },
  { 0x003f2, 0x003f2, 1,      7 },
  { 0x003f3, 0x003f3, 1,   -116 },
  { 0x003f5, 0x003f5, 1,    -96 },
  { 0x003f8, 0x003f8, 1,     -1 },
  { 0x003fb, 0x003fb, 1,     -1 },
  { 0x00430, 0x0044f, 1,    -32 },
  { 0x00450, 0x0045f, 1,    -80 },
  { 0x00461, 0x00481, 2,     -1 },
  { 0x0048b, 0x004bf, 2,     -1 },
  { 0x004c2, 0x004ce, 2,     -1 },
  { 0x004cf, 0x004cf, 1,    -15 },
  { 0x004d1, 0x0052f, 2,     -1 },
  { 0x00561, 0x00586, 1,    -48 },
  { 0x010d0, 0x010fa, 1,   3008 },
  { 0x010fd, 0x010ff, 1,   3008 },
  { 0x013f8, 0x013fd, 1,     -8 },
  { 0x01c88, 0x01c88, 1,  35266 },
  { 0x01d79, 0x01d79, 1,  35332 },
  { 0x01d7d, 0x01d7d, 1,   3814 },
  { 0x01d8e, 0x01d8e, 1,  35384 },
  { 0x01e01, 0x01e95, 2,     -1 },
  { 0x01e9b, 0x01e9b, 1,    -59 },
  { 0x01ea1, 0x01eff, 2,     -1 },
  { 0x01f00, 0x01f07, 1,      8 },
  { 0x01f10, 0x01f15, 1,      8 },
  { 0x01f20, 0x01f27, 1,      8 },
  { 0x01f30, 0x01f37, 1,      8 },
  { 0x01f40, 0x01f45, 1,      8 },
  { 0x01f51, 0x01f57, 2,      8 },
  { 0x01f60, 0x01f67, 1,      8 },
  { 0x01f70, 0x01f71, 1,     74 },
  { 0x01f72, 0x01f75, 1,     86 },
  { 0x01f76, 0x01f77, 1,    100 },
  { 0x01f78, 0x01f79, 1,    128 },
  { 0x01f7a, 0x01f7b, 1,    112 },
  { 0x01f7c, 0x01f7d, 1,    126 },
  { 0x01fb0, 0x01fb1, 1,      8 },
  { 0x01fd0, 0x01fd1, 1,      8 },
  { 0x01fe0, 0x01fe1, 1,      8 },
  { 0x01fe5, 0x01fe5, 1,      7 },
  { 0x0214e, 0x0214e, 1,    -28 },
  { 0x02170, 0x0217f, 1,    -16 },
  { 0x02184, 0x02184, 1,     -1 },
  { 0x024d0, 0x024e9, 1,    -26 },
  { 0x02c30, 0x02c5f, 1,    -48 },
  { 0x02c61, 0x02c61, 1,     -1 },
  { 0x02c68, 0x02c6c, 2,     -1 },
  { 0x02c73, 0x02c73, 1,     -1 },
  { 0x02c76, 0x02c76, 1,     -1 },
  { 0x02c81, 0x02ce3, 2,     -1 },
  { 0x02cec, 0x02cee, 2,     -1 },
  { 0x02cf3, 0x02cf3, 1,     -1 },
  { 0x02d00, 0x02d25, 1,  -7264 },
  { 0x02d27, 0x02d27, 1,  -7264 },
  { 0x02d2d, 0x02d2d, 1,  -7264 },
  { 0x0a641, 0x0a66d, 2,     -1 },
  { 0x0a681, 0x0a69b, 2,     -1 },
  { 0x0a723, 0x0a72f, 2,     -1 },
  { 0x0a733, 0x0a76f, 2,     -1 },
  { 0x0a77a, 0x0a77c, 2,     -1 },
  { 0x0a77f, 0x0a787, 2,     -1 },
  { 0x0a78c, 0x0a78c, 1,     -1 },
  { 0x0a791, 0x0a793, 2,     -1 },
  { 0x0a794, 0x0a794, 1,     48 },
  { 0x0a797, 0x0a7a9, 2,     -1 },
  { 0x0a7b5, 0x0a7c3, 2,     -1 },
  { 0x0a7c8, 0x0a7ca, 2,     -1 },
  { 0x0a7d1, 0x0a7d1, 1,     -1 },
  { 0x0a7d7, 0x0a7d9, 2,     -1 },
  { 0x0a7f6, 0x0a7f6, 1,     -1 },
  { 0x0ab53, 0x0ab53, 1,   -928 },
  { 0x0ab70, 0x0abbf, 1, -38864 },
  { 0x0ff41, 0x0ff5a, 1,    -32 },
  { 0x10428, 0x1044f, 1,    -40 },
  { 0x104d8, 0x104fb, 1,    -40 },
  { 0x10597, 0x105a1, 1,    -39 },
  { 0x105a3, 0x105b1, 1,    -39 },
  { 0x105b3, 0x105b9, 1,    -39 },
  { 0x105bb, 0x105bc, 1,    -39 },
  { 0x10cc0, 0x10cf2, 1,    -64 },
  { 0x118c0, 0x118df, 1,    -32 },
  { 0x16e60, 0x16e7f, 1,    -32 },
  { 0x1e922, 0x1e943, 1,    -34 },
};

static u32 pcfg_cp_upper (const u32 cp)
{
  u32 lo = 0;
  u32 hi = (sizeof (PCFG_UC) / sizeof (PCFG_UC[0]));

  while (lo < hi)
  {
    const u32 mid = lo + ((hi - lo) / 2);

    if (cp > PCFG_UC[mid].hi) { lo = mid + 1; continue; }
    if (cp < PCFG_UC[mid].lo) { hi = mid; continue; }

    if (((cp - PCFG_UC[mid].lo) % PCFG_UC[mid].step) != 0) return cp;

    return (u32) ((int) cp + PCFG_UC[mid].delta);
  }

  return cp;
}

static u32 pcfg_utf8_get (const u8 *s, const u32 len, u32 *cp)
{
  const u8 b0 = s[0];

  if (b0 < 0x80) { cp[0] = b0; return 1; }

  u32 need = 0;
  u32 acc  = 0;

  if      ((b0 & 0xe0) == 0xc0) { need = 1; acc = b0 & 0x1f; }
  else if ((b0 & 0xf0) == 0xe0) { need = 2; acc = b0 & 0x0f; }
  else if ((b0 & 0xf8) == 0xf0) { need = 3; acc = b0 & 0x07; }
  else                          { cp[0] = b0; return 1; }

  if ((1 + need) > len) { cp[0] = b0; return 1; }

  for (u32 i = 1; i <= need; i++)
  {
    if ((s[i] & 0xc0) != 0x80) { cp[0] = b0; return 1; }

    acc = (acc << 6) | (u32) (s[i] & 0x3f);
  }

  cp[0] = acc;

  return 1 + need;
}

static u32 pcfg_utf8_put (u8 *d, const u32 cp)
{
  if (cp < 0x80)    { d[0] = (u8) cp; return 1; }

  if (cp < 0x800)   { d[0] = (u8) (0xc0 | (cp >> 6)); d[1] = (u8) (0x80 | (cp & 0x3f)); return 2; }

  if (cp < 0x10000) { d[0] = (u8) (0xe0 | (cp >> 12)); d[1] = (u8) (0x80 | ((cp >> 6) & 0x3f)); d[2] = (u8) (0x80 | (cp & 0x3f)); return 3; }

  d[0] = (u8) (0xf0 | (cp >> 18));
  d[1] = (u8) (0x80 | ((cp >> 12) & 0x3f));
  d[2] = (u8) (0x80 | ((cp >> 6) & 0x3f));
  d[3] = (u8) (0x80 | (cp & 0x3f));

  return 4;
}

static void pcfg_upper_image (u8 *dst, const u8 *src, const u32 len)
{
  u32 at = 0;

  while (at < len)
  {
    u32 cp = 0;

    const u32 n = pcfg_utf8_get (src + at, len - at, &cp);

    const u32 up = pcfg_cp_upper (cp);

    u8 tmp[4];

    const u32 m = (up == cp) ? 0 : pcfg_utf8_put (tmp, up);

    if (m == n)
    {
      for (u32 i = 0; i < n; i++) dst[at + i] = tmp[i];
    }
    else
    {
      for (u32 i = 0; i < n; i++) dst[at + i] = src[at + i];
    }

    at += n;
  }
}

typedef struct
{
  u32 off;
  u32 len;
  u32 seq;

  u64 h;

  double p;

} pcfg_ment_t;

typedef struct
{
  u8 *buf;
  u64 buf_len;
  u64 buf_cap;

  pcfg_ment_t *ent;
  u32          cnt;
  u32          cap;

  u32 *seat;
  u32  mask;

  bool dedup;

} pcfg_merge_t;

typedef struct
{

  char *dir;

  const char *given;

  bool own;

  pcfg_arc_t *arc;

  double w;

} pcfg_root_t;

static void roots_free (pcfg_root_t *roots, const u32 nroots)
{
  for (u32 i = 0; i < nroots; i++)
  {
    arc_free (roots[i].arc);

    roots[i].arc = NULL;

    if (roots[i].own == true) hcfree (roots[i].dir);

    roots[i].dir = NULL;
    roots[i].own = false;
  }
}

static bool root_open (const pcfg_root_t *r, const char *rel, HCFILE *fp)
{
  if (r->arc != NULL)
  {
    const bool rc = arc_open (r->arc, rel, fp);

    return rc;
  }

  char path[HCBUFSIZ_TINY];

  snprintf (path, sizeof (path), "%s/%s", r->dir, rel);

  const bool rc = pcfg_fopen (fp, path);

  return rc;
}

static u64 merge_hash (const u8 *v, const u32 len)
{
  u64 h = 14695981039346656037ULL;

  for (u32 i = 0; i < len; i++)
  {
    h ^= (u64) v[i];
    h *= 1099511628211ULL;
  }

  return h;
}

static void merge_rehash (pcfg_merge_t *m, const u32 want)
{
  u32 cap = 64;

  while (cap < (want * 2)) cap *= 2;

  hcfree (m->seat);

  m->seat = (u32 *) hccalloc (cap, sizeof (u32));
  m->mask = cap - 1;

  for (u32 i = 0; i < m->cnt; i++)
  {
    u32 at = (u32) m->ent[i].h & m->mask;

    while (m->seat[at] != 0) at = (at + 1) & m->mask;

    m->seat[at] = i + 1;
  }
}

static void merge_init (pcfg_merge_t *m, const bool dedup)
{
  memset (m, 0, sizeof (pcfg_merge_t));

  m->dedup = dedup;

  if (dedup == true) merge_rehash (m, 1);
}

static void merge_free (pcfg_merge_t *m)
{
  hcfree (m->buf);
  hcfree (m->ent);
  hcfree (m->seat);

  memset (m, 0, sizeof (pcfg_merge_t));
}

static void merge_push (pcfg_merge_t *m, const u8 *v, const u32 len, const double p, const u64 h)
{

  if (m->cnt == m->cap)
  {
    const u32 old = m->cap;

    m->cap = (old == 0) ? 1024 : (old * 2);

    m->ent = (pcfg_ment_t *) hcrealloc (m->ent, (size_t) old * sizeof (pcfg_ment_t), (size_t) (m->cap - old) * sizeof (pcfg_ment_t));
  }

  while ((m->buf_len + len) > m->buf_cap)
  {
    const u64 old = m->buf_cap;

    m->buf_cap = (old == 0) ? 65536 : (old * 2);

    m->buf = (u8 *) hcrealloc (m->buf, old, m->buf_cap - old);
  }

  memcpy (m->buf + m->buf_len, v, len);

  pcfg_ment_t *e = &m->ent[m->cnt];

  e->off = (u32) m->buf_len;
  e->len = len;
  e->seq = m->cnt;
  e->h   = h;
  e->p   = p;

  m->buf_len += len;

  m->cnt++;
}

static void merge_add (pcfg_merge_t *m, const u8 *v, const u32 len, const double p)
{
  if (m->dedup == false)
  {
    merge_push (m, v, len, p, 0);

    return;
  }

  if ((m->cnt + 1) > ((m->mask + 1) / 2)) merge_rehash (m, m->cnt + 1);

  const u64 h = merge_hash (v, len);

  u32 at = (u32) h & m->mask;

  while (m->seat[at] != 0)
  {
    pcfg_ment_t *e = &m->ent[m->seat[at] - 1];

    if ((e->h == h) && (e->len == len) && (memcmp (m->buf + e->off, v, len) == 0))
    {
      e->p += p;

      return;
    }

    at = (at + 1) & m->mask;
  }

  m->seat[at] = m->cnt + 1;

  merge_push (m, v, len, p, h);
}

static int merge_cmp (const void *p1, const void *p2)
{
  const pcfg_ment_t *a = (const pcfg_ment_t *) p1;
  const pcfg_ment_t *b = (const pcfg_ment_t *) p2;

  if (a->p < b->p) return  1;
  if (a->p > b->p) return -1;

  if (a->seq > b->seq) return  1;
  if (a->seq < b->seq) return -1;

  return 0;
}

static void merge_sort (pcfg_merge_t *m)
{
  qsort (m->ent, m->cnt, sizeof (pcfg_ment_t), merge_cmp);

  hcfree (m->seat);

  m->seat  = NULL;
  m->mask  = 0;
  m->dedup = false;
}

static bool merge_read (pcfg_merge_t *m, const pcfg_root_t *r, const char *rel)
{
  const double w = r->w;

  HCFILE fp;

  if (root_open (r, rel, &fp) == false) return false;

  // A ruleset worth giving to the device engine runs to tens of millions of lines, and the library
  // call that fetches one line at a time costs more than parsing the line does. The whole file is
  // read in one piece and the lines are cut out of memory instead.
  //
  // The cut is the one fgets () was making, buffer size included: a line longer than the buffer was
  // handed over in pieces and each piece went through the parse on its own, so that still happens
  // here and the same terminals come out of the same file.

  size_t cap = 1 << 20;
  size_t len = 0;

  char *img = (char *) hcmalloc (cap + 1);

  while (true)
  {
    if (len == cap)
    {
      const size_t old = cap;

      cap = old * 2;

      img = (char *) hcrealloc (img, old + 1, cap - old);
    }

    const size_t got = hc_fread (img + len, 1, cap - len, &fp);

    if (got == 0) break;
    if (got == (size_t) -1) break;

    len += got;
  }

  hc_fclose (&fp);

  img[len] = 0;

  size_t at = 0;

  while (at < len)
  {
    const size_t stop = ((len - at) < (HCBUFSIZ_TINY - 1)) ? len : (at + HCBUFSIZ_TINY - 1);

    size_t end = at;

    while ((end < stop) && (img[end] != '\n')) end++;

    if (end < stop) end++;

    // The line is terminated where it ends rather than copied out, so that the search below stops in
    // the same place it used to and an embedded zero byte still hides the rest of the line.

    const char keep = img[end];

    img[end] = 0;

    char *line = img + at;

    char *tab = strchr (line, '\t');

    if (tab != NULL)
    {
      *tab = 0;

      const size_t vlen = strlen (line);
      const double p    = strtod (tab + 1, NULL);

      if ((vlen > 0) && (p > 0.0)) merge_add (m, (const u8 *) line, (u32) vlen, p * w);

      *tab = '\t';
    }

    img[end] = keep;

    at = end;
  }

  hcfree (img);

  return true;
}

static void roots_join (char *out, const size_t out_size, const pcfg_root_t *roots, const u32 nroots)
{
  size_t at = 0;

  out[0] = 0;

  for (u32 i = 0; i < nroots; i++)
  {
    const int rc = snprintf (out + at, out_size - at, "%s%s", (i == 0) ? "" : "+", roots[i].dir);

    if (rc < 0) break;

    if ((size_t) rc >= (out_size - at)) { at = out_size - 1; break; }

    at += (size_t) rc;
  }
}

static bool root_weights (generic_global_ctx_t *global_ctx, pcfg_root_t *roots, const u32 nroots, const char *spec)
{
  if (spec != NULL)
  {
    const char *at = spec;

    u32 n = 0;

    for (;;)
    {
      char *end = NULL;

      const double w = strtod (at, &end);

      if (end == at)
      {
        gerr (global_ctx, "weights: '%s' is not a colon separated list of numbers", spec);

        return false;
      }

      if (w <= 0.0)
      {
        gerr (global_ctx, "weights: every share has to be greater than zero");

        return false;
      }

      if (n < nroots) roots[n].w = w;

      n++;

      if (*end == 0) break;

      if (*end != ':')
      {
        gerr (global_ctx, "weights: '%s' is not a colon separated list of numbers", spec);

        return false;
      }

      at = end + 1;
    }

    if (n != nroots)
    {
      gerr (global_ctx, "weights: %u given for %u ruleset%s", n, nroots, (nroots == 1) ? "" : "s");

      return false;
    }
  }

  double sum = 0.0;

  for (u32 i = 0; i < nroots; i++) sum += roots[i].w;

  for (u32 i = 0; i < nroots; i++) roots[i].w /= sum;

  return true;
}

typedef struct
{
  const u32 *off;
  const u32 *seat;

} tlist_sort_t;

static int tlist_cmp_len (const void *p1, const void *p2, void *arg)
{
  const tlist_sort_t *c = (const tlist_sort_t *) arg;

  const u32 ia = ((const u32 *) p1)[0];
  const u32 ib = ((const u32 *) p2)[0];

  const u32 la = c->off[ia + 1] - c->off[ia];
  const u32 lb = c->off[ib + 1] - c->off[ib];

  if (la != lb)
  {
    if (c->seat[la] > c->seat[lb]) return  1;
    if (c->seat[la] < c->seat[lb]) return -1;
  }

  if (ia > ib) return  1;
  if (ia < ib) return -1;

  return 0;
}

static int pcfg_lensplit_state = -1;

static bool pcfg_lensplit (void)
{
  if (pcfg_lensplit_state < 0)
  {
    const char *env = getenv ("PCFG_LENSPLIT");

    pcfg_lensplit_state = (env != NULL) ? atoi (env) : 0;
  }

  return (pcfg_lensplit_state != 0);
}

static int tlist_build (pcfg_tlist_t *t, const pcfg_merge_t *m, const u64 scale, const u64 costmax, const bool want_upper)
{
  if (m->cnt == 0) return -1;

  t->off = (u32 *) hcmalloc (((size_t) m->cnt + 1) * sizeof (u32));
  t->buf = (u8 *)  hcmalloc (m->buf_len + 1);

  u32 *cost = (u32 *) hcmalloc ((size_t) m->cnt * sizeof (u32));

  t->cnt    = 0;
  t->off[0] = 0;

  for (u32 i = 0; i < m->cnt; i++)
  {
    const double q = -log2 (m->ent[i].p) * (double) scale;

    if (q < 0.0) continue;

    const u64 c = (u64) (q + 0.5);

    if (c > costmax) continue;

    const u32 vlen = m->ent[i].len;

    // Every offset into a terminal list is a u32, here and in the reordered copy further down and in
    // the bucket tables built from it, while the backing buffer is sized from a u64. A ruleset whose
    // kept terminals sum past 4 GiB wrapped the running offset, so the reordered buffer was sized
    // from the remainder and the copy into it walked far past the allocation.

    if (vlen > (0xffffffff - t->off[t->cnt]))
    {
      hcfree (cost);
      hcfree (t->off);
      hcfree (t->buf);

      t->off = NULL;
      t->buf = NULL;

      return -1;
    }

    memcpy (t->buf + t->off[t->cnt], m->buf + m->ent[i].off, vlen);

    cost[t->cnt] = (u32) c;

    t->off[t->cnt + 1] = t->off[t->cnt] + vlen;

    t->cnt++;
  }

  if (t->cnt == 0)
  {
    hcfree (cost);
    hcfree (t->off);
    hcfree (t->buf);

    t->off = NULL;
    t->buf = NULL;

    return -1;
  }

  {
    u32 *ord = (u32 *) hcmalloc (t->cnt * sizeof (u32));

    for (u32 i = 0; i < t->cnt; i++) ord[i] = i;

    u32 widest = 0;

    for (u32 i = 0; i < t->cnt; i++)
    {
      const u32 len = t->off[i + 1] - t->off[i];

      if (len > widest) widest = len;
    }

    u32 *seat = (u32 *) hcmalloc ((widest + 1) * sizeof (u32));

    tlist_sort_t ctx;

    ctx.off  = t->off;
    ctx.seat = seat;

    u32 i = 0;

    while (i < t->cnt)
    {
      u32 j = i;

      while ((j < t->cnt) && (cost[j] == cost[i])) j++;

      if ((j - i) > 1)
      {
        for (u32 k = 0; k <= widest; k++) seat[k] = 0xffffffff;

        for (u32 k = i; k < j; k++)
        {
          const u32 len = t->off[k + 1] - t->off[k];

          if (seat[len] == 0xffffffff) seat[len] = k;
        }

        hc_qsort_r (ord + i, j - i, sizeof (u32), tlist_cmp_len, &ctx);
      }

      i = j;
    }

    hcfree (seat);

    const u32 total = t->off[t->cnt];

    u8  *nbuf  = (u8 *)  hcmalloc (total);
    u32 *noff  = (u32 *) hcmalloc ((t->cnt + 1) * sizeof (u32));
    u32 *ncost = (u32 *) hcmalloc (t->cnt * sizeof (u32));

    noff[0] = 0;

    for (u32 k = 0; k < t->cnt; k++)
    {
      const u32 v = ord[k];
      const u32 l = t->off[v + 1] - t->off[v];

      memcpy (nbuf + noff[k], t->buf + t->off[v], l);

      noff[k + 1] = noff[k] + l;
      ncost[k]    = cost[v];
    }

    hcfree (t->buf);
    hcfree (t->off);
    hcfree (cost);

    t->buf = nbuf;
    t->off = noff;
    cost   = ncost;

    hcfree (ord);
  }

  t->b_cost  = (u32 *) hcmalloc (t->cnt * sizeof (u32));
  t->b_start = (u32 *) hcmalloc (t->cnt * sizeof (u32));
  t->b_cnt   = (u32 *) hcmalloc (t->cnt * sizeof (u32));
  t->b_len   = (u32 *) hcmalloc (t->cnt * sizeof (u32));
  t->nb      = 0;

  const bool lensplit = pcfg_lensplit ();

  const char *capenv = getenv ("PCFG_BUCKETCAP");

  const u32 bcap = (capenv != NULL) ? (u32) strtoul (capenv, NULL, 10) : 0;

  for (u32 i = 0; i < t->cnt; i++)
  {
    const u32 len = t->off[i + 1] - t->off[i];

    const bool room = (t->nb > 0) && ((bcap == 0) || (t->b_cnt[t->nb - 1] < bcap)) && (t->b_cnt[t->nb - 1] < PCFG_ODO_MAXDIGIT);

    if ((room == true) && (t->b_cost[t->nb - 1] == cost[i]) && ((lensplit == false) || (t->b_len[t->nb - 1] == len)))
    {

      if (t->b_len[t->nb - 1] != len) t->b_len[t->nb - 1] = 0;

      t->b_cnt[t->nb - 1]++;
    }
    else
    {
      t->b_cost[t->nb]  = cost[i];
      t->b_start[t->nb] = i;
      t->b_cnt[t->nb]   = 1;
      t->b_len[t->nb]   = len;
      t->nb++;
    }
  }

  t->fixed_len = t->off[1] - t->off[0];
  t->max_len   = t->off[1] - t->off[0];

  for (u32 i = 1; i < t->cnt; i++)
  {
    const u32 len = t->off[i + 1] - t->off[i];

    if (len != t->fixed_len) t->fixed_len = 0;

    if (len > t->max_len) t->max_len = len;
  }

  hcfree (cost);

  if (want_upper == true)
  {
    const u32 total = t->off[t->cnt];

    t->ubuf = (u8 *) hcmalloc (total + 1);

    for (u32 i = 0; i < t->cnt; i++)
    {
      const u32 at  = t->off[i];
      const u32 len = t->off[i + 1] - at;

      pcfg_upper_image (t->ubuf + at, t->buf + at, len);
    }
  }

  return 0;
}

static u32 tlist_split_count (const pcfg_tlist_t *t)
{
  u32 n = 0;

  for (u32 b = 0; b < t->nb; b++)
  {
    const u32 start = t->b_start[b];
    const u32 end   = start + t->b_cnt[b];

    u32 run = 0;

    for (u32 i = start; i < end; i++)
    {
      const u32 len = t->off[i + 1] - t->off[i];

      if ((i > start) && (len == run)) continue;

      run = len;

      n++;
    }
  }

  return n;
}

static void tlist_split_bylen (pcfg_tlist_t *t)
{
  const u32 nb = t->nb;

  u32 *o_cost  = (u32 *) hcmalloc (nb * sizeof (u32));
  u32 *o_start = (u32 *) hcmalloc (nb * sizeof (u32));
  u32 *o_cnt   = (u32 *) hcmalloc (nb * sizeof (u32));

  memcpy (o_cost,  t->b_cost,  nb * sizeof (u32));
  memcpy (o_start, t->b_start, nb * sizeof (u32));
  memcpy (o_cnt,   t->b_cnt,   nb * sizeof (u32));

  t->nb = 0;

  for (u32 b = 0; b < nb; b++)
  {
    const u32 start = o_start[b];
    const u32 end   = start + o_cnt[b];

    for (u32 i = start; i < end; i++)
    {
      const u32 len = t->off[i + 1] - t->off[i];

      if ((i > start) && (t->b_len[t->nb - 1] == len))
      {
        t->b_cnt[t->nb - 1]++;

        continue;
      }

      t->b_cost[t->nb]  = o_cost[b];
      t->b_start[t->nb] = i;
      t->b_cnt[t->nb]   = 1;
      t->b_len[t->nb]   = len;
      t->nb++;
    }
  }

  hcfree (o_cost);
  hcfree (o_start);
  hcfree (o_cnt);
}

static int tlist_load (pcfg_tlist_t *t, const pcfg_root_t *roots, const u32 nroots, const char *rel, const u64 scale, const u64 costmax, const bool want_upper)
{
  pcfg_merge_t m;

  merge_init (&m, (nroots > 1));

  u32 got = 0;

  for (u32 i = 0; i < nroots; i++)
  {
    if (merge_read (&m, &roots[i], rel) == true) got++;
  }

  int rc = -1;

  if (got > 0)
  {
    if (nroots > 1) merge_sort (&m);

    rc = tlist_build (t, &m, scale, costmax, want_upper);
  }

  merge_free (&m);

  return rc;
}

static const char *type_dir (const char t)
{
  switch (t)
  {
    case 'A': return "Alpha";
    case 'C': return "Capitalization";
    case 'D': return "Digits";
    case 'O': return "Other";
    case 'K': return "Keyboard";
    case 'X': return "Context";
    case 'Y': return "Years";
  }

  return NULL;
}

static bool type_is_flat (const char t)
{
  return (t == 'X' || t == 'Y');
}

static int list_get (pcfg_global_t *pg, const pcfg_root_t *roots, const u32 nroots, const char t, const u32 len, int *cache)
{
  const int key = ((int) (u8) t << 8) | (int) len;

  for (u32 i = 0; i < pg->lists_cnt; i++) if (cache[i] == key) return (int) i;

  const char *dir = type_dir (t);

  if (dir == NULL) return -1;

  char rel[64];

  snprintf (rel, sizeof (rel), "%s/%u.txt", dir, type_is_flat (t) ? 1 : len);

  // cache holds PCFG_LIST_CACHE entries and is indexed by lists_cnt, which grows with the ruleset

  if (pg->lists_cnt >= PCFG_LIST_CACHE) return -1;

  pcfg_tlist_t tmp;

  memset (&tmp, 0, sizeof (tmp));

  if (tlist_load (&tmp, roots, nroots, rel, pg->scale, pg->costmax, (t == 'A')) == -1) return -1;

  tmp.ty = (u8) t;
  tmp.ln = len;

  pg->lists = (pcfg_tlist_t *) hcrealloc (pg->lists, pg->lists_cnt * sizeof (pcfg_tlist_t), (pg->lists_cnt + 1) * sizeof (pcfg_tlist_t));

  pg->lists[pg->lists_cnt] = tmp;

  cache[pg->lists_cnt] = key;

  return (int) pg->lists_cnt++;
}

static void build_suffix (pcfg_global_t *pg, pcfg_struct_t *s)
{
  const u32 span = pg->costmax - s->cost + 1;

  s->suf = (u64 *) hccalloc ((size_t) (s->nslot + 1) * span, sizeof (u64));

  s->suf[(size_t) s->nslot * span + 0] = 1;

  for (int j = (int) s->nslot - 1; j >= 0; j--)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];

    u64 *dst = s->suf + (size_t) j * span;
    u64 *src = s->suf + (size_t) (j + 1) * span;

    for (u32 b = 0; b < t->nb; b++)
    {
      const u32 cb = t->b_cost[b];

      if (cb >= span) continue;

      for (u32 r = 0; r + cb < span; r++)
      {
        if (src[r] == 0) continue;

        dst[r + cb] = sat_add (dst[r + cb], sat_mul (t->b_cnt[b], src[r]));
      }
    }
  }

  s->cmin = 0;
  s->cmax = 0;

  bool seen = false;

  for (u32 r = 0; r < span; r++)
  {
    if (s->suf[r] == 0) continue;

    if (seen == false) { s->cmin = s->cost + r; seen = true; }

    s->cmax = s->cost + r;
  }
}

// Both suffix builds are the same shape: one call per structure, and no structure reads or writes
// another. The grammar itself is only read. So both are swept across cores from here.
//
// The split is by chunk and taken as a thread becomes free. The cost of one structure varies by more
// than an order of magnitude with its cost span and how many buckets its lists hold, and a fixed
// slice each would leave most of the cores waiting on one unlucky slice.

#define PCFG_BUILD_MAXW  32
#define PCFG_BUILD_CHUNK 128

typedef void (*pcfg_struct_fn) (pcfg_global_t *pg, pcfg_struct_t *s);

typedef struct
{
  pcfg_global_t *pg;

  pcfg_struct_fn fn;

  pcfg_mux_t mux;

  u32 next;

} pcfg_sweep_t;

static pcfg_thread_ret sweep_worker (void *arg)
{
  pcfg_sweep_t *sw = (pcfg_sweep_t *) arg;

  pcfg_global_t *pg = sw->pg;

  while (true)
  {
    pcfg_mux_lock (&sw->mux);

    const u32 from = sw->next;

    sw->next = from + PCFG_BUILD_CHUNK;

    pcfg_mux_unlock (&sw->mux);

    if (from >= pg->structs_cnt) break;

    u32 upto = from + PCFG_BUILD_CHUNK;

    if (upto > pg->structs_cnt) upto = pg->structs_cnt;

    for (u32 i = from; i < upto; i++) sw->fn (pg, &pg->structs[i]);
  }

  return pcfg_thread_done;
}

static void structs_sweep (pcfg_global_t *pg, pcfg_struct_fn fn)
{
  // One less than the machine has, because the calling thread takes chunks too.

  u32 nworker = pcfg_cpu_online () - 1;

  const char *env = getenv ("PCFG_BUILD_THREADS");

  if (env != NULL) nworker = (u32) strtoul (env, NULL, 10);

  if (nworker > PCFG_BUILD_MAXW) nworker = PCFG_BUILD_MAXW;

  pcfg_sweep_t sw;

  sw.pg   = pg;
  sw.fn   = fn;
  sw.next = 0;

  pcfg_mux_init (&sw.mux);

  pcfg_os_thread_t worker[PCFG_BUILD_MAXW];

  u32 started = 0;

  for (u32 i = 0; i < nworker; i++)
  {
    if (pcfg_thread_create (worker[started], sweep_worker, &sw) == false) continue;

    started++;
  }

  // The calling thread takes chunks as well. That is one more core on the work, and it is also what
  // makes a machine that would not give out a single thread still finish the sweep.

  sweep_worker (&sw);

  for (u32 i = 0; i < started; i++) pcfg_thread_join (worker[i]);

  pcfg_mux_destroy (&sw.mux);
}

static void pcfg_pick_varlen (pcfg_global_t *pg)
{
  u64 merged = 0;
  u64 split  = 0;

  for (u32 i = 0; i < pg->lists_cnt; i++)
  {
    merged += pg->lists[i].nb;
    split  += tlist_split_count (&pg->lists[i]);
  }

  double want = 0.0;

  const char *gainenv = getenv ("PCFG_VARLEN_GAIN");

  if (gainenv != NULL) want = strtod (gainenv, NULL);

  bool varlen = (split > 0) && (want > 0.0) && ((double) merged <= (double) split * want);

  const char *env = getenv ("PCFG_VARLEN");

  if (env != NULL) varlen = (atoi (env) != 0);

  if (pcfg_lensplit () == true) varlen = false;

  if (getenv ("PCFG_BUCKET_STATS") != NULL)
  {
    fprintf (stderr, "varlen: merged_buckets=%" PRIu64 " split_buckets=%" PRIu64 " ratio=%.3f varlen=%d\n",
      merged, split, (split > 0) ? (double) merged / (double) split : 1.0, (int) varlen);
  }

  pg->varlen = varlen;

  if (varlen == true) return;

  pcfg_lensplit_state = 1;

  for (u32 i = 0; i < pg->lists_cnt; i++) tlist_split_bylen (&pg->lists[i]);
}

static int grammar_load (generic_global_ctx_t *global_ctx, pcfg_global_t *pg, const pcfg_root_t *roots, const u32 nroots)
{

  pcfg_merge_t gm;

  merge_init (&gm, (nroots > 1));

  for (u32 i = 0; i < nroots; i++)
  {
    if (merge_read (&gm, &roots[i], "Grammar/grammar.txt") == true) continue;

    gerr (global_ctx, "%s: cannot read Grammar/grammar.txt. expected a pcfg_cracker ruleset directory, or one archived into a single file", roots[i].dir);

    merge_free (&gm);

    return -1;
  }

  if (nroots > 1) merge_sort (&gm);

  int *cache = (int *) hcmalloc (PCFG_LIST_CACHE * sizeof (int));

  for (int i = 0; i < PCFG_LIST_CACHE; i++) cache[i] = -1;

  size_t cap = 1024;

  pg->structs = (pcfg_struct_t *) hccalloc (cap, sizeof (pcfg_struct_t));

  char line[HCBUFSIZ_TINY];

  u32 dropped_m = 0;
  u32 dropped_t = 0;

  for (u32 e = 0; e < gm.cnt; e++)
  {
    const u32 vlen = gm.ent[e].len;

    if (vlen == 0) continue;
    if (vlen >= sizeof (line)) continue;

    memcpy (line, gm.buf + gm.ent[e].off, vlen);

    line[vlen] = 0;

    const double p = gm.ent[e].p;

    if (line[0] == 'M') { dropped_m++; continue; }

    pcfg_struct_t s;

    memset (&s, 0, sizeof (s));

    const double q = -log2 (p) * (double) pg->scale;

    if (q < 0.0) continue;

    s.cost = (u32) (q + 0.5);

    if (s.cost > pg->costmax) continue;

    bool ok = true;

    for (const char *c = line; *c && ok; )
    {
      const char ty = *c++;

      u32 len = 0;

      while (*c >= '0' && *c <= '9') len = len * 10 + (u32) (*c++ - '0');

      if (len == 0 || len > 0xffff || s.nslot + 2 > PCFG_MAXSLOT) { ok = false; break; }

      const int li = list_get (pg, roots, nroots, ty, len, cache);

      if (li == -1) { ok = false; break; }

      s.kind[s.nslot] = PCFG_SLOT_TERM;
      s.list[s.nslot] = li;

      // Zero for a flat token, whose entries vary in length so the structure cannot say how many
      // characters this slot contributes. Everything that reads tlen tells the two apart by it.

      s.tlen[s.nslot] = type_is_flat (ty) ? 0 : (u16) len;

      s.nslot++;

      s.total_len += type_is_flat (ty) ? 0 : len;

      if (ty == 'A')
      {
        const int ci = list_get (pg, roots, nroots, 'C', len, cache);

        if (ci == -1) { ok = false; break; }

        s.kind[s.nslot] = PCFG_SLOT_MASK;
        s.list[s.nslot] = ci;
        s.tlen[s.nslot] = (u16) len;
        s.nslot++;
      }
    }

    if (ok == false) { dropped_t++; continue; }

    if (pg->structs_cnt == cap)
    {
      const size_t old = cap;

      cap *= 2;

      pg->structs = (pcfg_struct_t *) hcrealloc (pg->structs, old * sizeof (pcfg_struct_t), cap * sizeof (pcfg_struct_t));

      memset (pg->structs + old, 0, (cap - old) * sizeof (pcfg_struct_t));
    }

    pg->structs[pg->structs_cnt++] = s;
  }

  merge_free (&gm);

  hcfree (cache);

  if (pg->structs_cnt == 0)
  {
    char named[256];

    roots_join (named, sizeof (named), roots, nroots);

    gerr (global_ctx, "%s: no usable structures", named);

    return -1;
  }

  pcfg_pick_varlen (pg);

  structs_sweep (pg, build_suffix);

  pg->m_lines = dropped_m;

  if (global_ctx->quiet == false)
  {
    char extra[128];

    extra[0] = 0;

    if (dropped_t) snprintf (extra + strlen (extra), sizeof (extra) - strlen (extra), ", %u unusable dropped", dropped_t);

    pmsg (pg, "pcfg: %u structures, %u terminal lists%s", pg->structs_cnt, pg->lists_cnt, extra);
  }

  return 0;
}

typedef struct
{
  u8  *buf;
  u64  buf_len;
  u64  buf_cap;

  u32 *off;
  u32  cnt;
  u32  cap;

  u32 *slot;
  u32  mask;

} pcfg_intern_t;

static u64 intern_hash (const u8 *v, const u32 len)
{
  u64 h = 14695981039346656037ULL;

  for (u32 i = 0; i < len; i++)
  {
    h ^= v[i];
    h *= 1099511628211ULL;
  }

  return h;
}

static void intern_init (pcfg_intern_t *in)
{
  in->buf_cap = 1 << 16;
  in->buf     = (u8 *) hcmalloc (in->buf_cap);
  in->buf_len = 0;

  in->cap = 1 << 12;
  in->off = (u32 *) hcmalloc ((in->cap + 1) * sizeof (u32));
  in->cnt = 0;

  in->off[0] = 0;

  in->mask = (1 << 13) - 1;
  in->slot = (u32 *) hccalloc (in->mask + 1, sizeof (u32));
}

static void intern_free (pcfg_intern_t *in)
{
  hcfree (in->buf);
  hcfree (in->off);
  hcfree (in->slot);

  in->buf  = NULL;
  in->off  = NULL;
  in->slot = NULL;
}

static void intern_rehash (pcfg_intern_t *in)
{
  const u32 old = in->mask + 1;

  hcfree (in->slot);

  in->mask = (old * 2) - 1;
  in->slot = (u32 *) hccalloc (in->mask + 1, sizeof (u32));

  for (u32 i = 0; i < in->cnt; i++)
  {
    const u8 *v = in->buf + in->off[i];

    const u64 h = intern_hash (v, in->off[i + 1] - in->off[i]);

    u32 at = (u32) (h & in->mask);

    while (in->slot[at] != 0) at = (at + 1) & in->mask;

    in->slot[at] = i + 1;
  }
}

static u32 intern_get (pcfg_intern_t *in, const u8 *v, const u32 len)
{
  const u64 h = intern_hash (v, len);

  u32 at = (u32) (h & in->mask);

  while (in->slot[at] != 0)
  {
    const u32 id = in->slot[at] - 1;

    const u32 l = in->off[id + 1] - in->off[id];

    if ((l == len) && (memcmp (in->buf + in->off[id], v, len) == 0)) return id;

    at = (at + 1) & in->mask;
  }

  if (in->buf_len + len > in->buf_cap)
  {
    const u64 old = in->buf_cap;

    while (in->buf_len + len > in->buf_cap) in->buf_cap *= 2;

    in->buf = (u8 *) hcrealloc (in->buf, old, in->buf_cap);
  }

  if (in->cnt == in->cap)
  {
    const u32 old = in->cap;

    in->cap *= 2;

    in->off = (u32 *) hcrealloc (in->off, (old + 1) * sizeof (u32), (in->cap + 1) * sizeof (u32));
  }

  memcpy (in->buf + in->buf_len, v, len);

  const u32 id = in->cnt++;

  in->buf_len += len;

  in->off[id + 1] = (u32) in->buf_len;

  in->slot[at] = id + 1;

  if ((in->cnt * 4) > (in->mask * 3)) intern_rehash (in);

  return id;
}

static u32 omen_clen1 (const bool utf8, const u8 *s, const u32 len)
{
  if (utf8 == false) return 1;

  u32 cp = 0;

  const u32 n = pcfg_utf8_get (s, len, &cp);

  return n;
}

static u32 omen_split (const bool utf8, const u8 *s, const u32 len, u32 *off, const u32 maxn)
{
  u32 n  = 0;
  u32 at = 0;

  while (at < len)
  {
    if (n >= maxn) return 0;

    off[n++] = at;

    at += omen_clen1 (utf8, s + at, len - at);
  }

  off[n] = at;

  return n;
}

static const u8 *omen_line (char *line, u32 *lvl, u32 *glen)
{
  char *tab = strchr (line, '\t');

  if (tab == NULL) return NULL;

  tab[0] = 0;

  char *end = NULL;

  const long v = strtol (line, &end, 10);

  if ((end == line) || (v < 0)) return NULL;

  char *gram = tab + 1;

  size_t n = strlen (gram);

  while ((n > 0) && ((gram[n - 1] == '\n') || (gram[n - 1] == '\r'))) n--;

  if (n == 0) return NULL;

  lvl[0]  = (u32) v;
  glen[0] = (u32) n;

  return (const u8 *) gram;
}

typedef struct
{
  u32 src;
  u32 dst;
  u32 chr;
  u32 lvl;

} pcfg_omen_raw_t;

static int omen_load_one (generic_global_ctx_t *global_ctx, pcfg_omen_t *om, const pcfg_root_t *r)
{
  char path[HCBUFSIZ_TINY];
  char line[HCBUFSIZ_TINY];

  HCFILE fp;

  const char *rel = "Omen/config.txt";

  snprintf (path, sizeof (path), "%s/%s", r->dir, rel);

  if (root_open (r, rel, &fp) == false) return 1;

  u32 ngram = 0;

  om->utf8 = false;

  while (hc_fgets (line, sizeof (line), &fp) != NULL)
  {
    char *eq = strchr (line, '=');

    if (eq == NULL) continue;

    eq[0] = 0;

    char *key = line;
    char *val = eq + 1;

    while ((key[0] == ' ') || (key[0] == '\t')) key++;

    size_t kn = strlen (key);

    while ((kn > 0) && ((key[kn - 1] == ' ') || (key[kn - 1] == '\t'))) key[--kn] = 0;

    while ((val[0] == ' ') || (val[0] == '\t')) val++;

    size_t vn = strlen (val);

    while ((vn > 0) && ((val[vn - 1] == '\n') || (val[vn - 1] == '\r') || (val[vn - 1] == ' '))) val[--vn] = 0;

    if (strcmp (key, "ngram") == 0) ngram = (u32) strtoul (val, NULL, 10);

    if (strcmp (key, "encoding") == 0) om->utf8 = ((strcmp (val, "utf8") == 0) || (strcmp (val, "utf-8") == 0));
  }

  hc_fclose (&fp);

  if ((ngram < 2) || (ngram > PCFG_OMEN_MAXNGRAM))
  {
    gerr (global_ctx, "%s: ngram is %u, which this feed does not carry (2 to %u)", path, ngram, PCFG_OMEN_MAXNGRAM);

    return -1;
  }

  om->clen = ngram - 1;

  pcfg_intern_t ctxi;
  pcfg_intern_t chri;

  intern_init (&ctxi);
  intern_init (&chri);

  size_t rcap = 1 << 16;
  size_t rcnt = 0;

  pcfg_omen_raw_t *raw = (pcfg_omen_raw_t *) hcmalloc (rcap * sizeof (pcfg_omen_raw_t));

  rel = "Omen/CP.level";

  snprintf (path, sizeof (path), "%s/%s", r->dir, rel);

  if (root_open (r, rel, &fp) == false)
  {
    gerr (global_ctx, "%s: cannot read, but %s/Omen/config.txt is there", path, r->dir);

    hcfree (raw);

    intern_free (&ctxi);
    intern_free (&chri);

    return -1;
  }

  u32 coff[PCFG_OMEN_MAXNGRAM + 1];

  while (hc_fgets (line, sizeof (line), &fp) != NULL)
  {
    u32 lvl  = 0;
    u32 glen = 0;

    const u8 *gram = omen_line (line, &lvl, &glen);

    if (gram == NULL) continue;

    if (lvl > PCFG_OMEN_MAXLVL) continue;

    if (omen_split (om->utf8, gram, glen, coff, PCFG_OMEN_MAXNGRAM) != ngram) continue;

    if (rcnt == rcap)
    {
      const size_t old = rcap;

      rcap *= 2;

      raw = (pcfg_omen_raw_t *) hcrealloc (raw, old * sizeof (pcfg_omen_raw_t), rcap * sizeof (pcfg_omen_raw_t));
    }

    raw[rcnt].src = intern_get (&ctxi, gram,               coff[om->clen]);
    raw[rcnt].dst = intern_get (&ctxi, gram + coff[1],     coff[ngram] - coff[1]);
    raw[rcnt].chr = intern_get (&chri, gram + coff[ngram - 1], coff[ngram] - coff[ngram - 1]);
    raw[rcnt].lvl = lvl;

    rcnt++;
  }

  hc_fclose (&fp);

  rel = "Omen/IP.level";

  snprintf (path, sizeof (path), "%s/%s", r->dir, rel);

  if (root_open (r, rel, &fp) == false)
  {
    gerr (global_ctx, "%s: cannot read, but %s/Omen/config.txt is there", path, r->dir);

    hcfree (raw);

    intern_free (&ctxi);
    intern_free (&chri);

    return -1;
  }

  size_t icap = 1 << 12;

  u32 *ip_ctx = (u32 *) hcmalloc (icap * sizeof (u32));
  u32 *ip_chr = (u32 *) hcmalloc (icap * sizeof (u32));
  u8  *ip_lvl = (u8  *) hcmalloc (icap * sizeof (u8));

  u32 nip = 0;

  while (hc_fgets (line, sizeof (line), &fp) != NULL)
  {
    u32 lvl  = 0;
    u32 glen = 0;

    const u8 *gram = omen_line (line, &lvl, &glen);

    if (gram == NULL) continue;

    if (lvl > PCFG_OMEN_MAXLVL) continue;

    if (omen_split (om->utf8, gram, glen, coff, PCFG_OMEN_MAXNGRAM) != om->clen) continue;

    if (nip == icap)
    {
      const size_t old = icap;

      icap *= 2;

      ip_ctx = (u32 *) hcrealloc (ip_ctx, old * sizeof (u32), icap * sizeof (u32));
      ip_chr = (u32 *) hcrealloc (ip_chr, old * sizeof (u32), icap * sizeof (u32));
      ip_lvl = (u8  *) hcrealloc (ip_lvl, old * sizeof (u8),  icap * sizeof (u8));
    }

    ip_ctx[nip] = intern_get (&ctxi, gram, glen);
    ip_chr[nip] = intern_get (&chri, gram, glen);
    ip_lvl[nip] = (u8) lvl;

    nip++;
  }

  hc_fclose (&fp);

  rel = "Omen/LN.level";

  snprintf (path, sizeof (path), "%s/%s", r->dir, rel);

  if (root_open (r, rel, &fp) == false)
  {
    gerr (global_ctx, "%s: cannot read, but %s/Omen/config.txt is there", path, r->dir);

    hcfree (raw);
    hcfree (ip_ctx);
    hcfree (ip_chr);
    hcfree (ip_lvl);

    intern_free (&ctxi);
    intern_free (&chri);

    return -1;
  }

  u8 ln_lvl_of[PCFG_OMEN_MAXK + 1];

  for (u32 k = 0; k <= PCFG_OMEN_MAXK; k++) ln_lvl_of[k] = 0xff;

  u32 ln_seen = 0;

  {
    u32 length = 0;

    while (hc_fgets (line, sizeof (line), &fp) != NULL)
    {
      length++;

      char *end = NULL;

      const long v = strtol (line, &end, 10);

      if (end == line) continue;

      if (length < ngram) continue;

      const u32 k = length - om->clen;

      if (k > PCFG_OMEN_MAXK) continue;

      if ((v < 0) || (v > PCFG_OMEN_MAXLVL)) continue;

      ln_lvl_of[k] = (u8) v;

      if (k > ln_seen) ln_seen = k;
    }
  }

  hc_fclose (&fp);

  om->kmax = ln_seen;

  rel = "Omen/pcfg_omen_prob.txt";

  snprintf (path, sizeof (path), "%s/%s", r->dir, rel);

  double prob[PCFG_OMEN_MAXLVL * 8 + 2];

  const u32 lvlcap = (u32) (sizeof (prob) / sizeof (prob[0])) - 1;

  for (u32 i = 0; i <= lvlcap; i++) prob[i] = 0.0;

  u32 bmax = 0;

  if (root_open (r, rel, &fp) == true)
  {
    while (hc_fgets (line, sizeof (line), &fp) != NULL)
    {
      char *tab = strchr (line, '\t');

      if (tab == NULL) continue;

      tab[0] = 0;

      const u32    t = (u32) strtoul (line, NULL, 10);
      const double p = strtod (tab + 1, NULL);

      if (t > lvlcap) continue;
      if (p <= 0.0)   continue;

      prob[t] = p;

      if (t > bmax) bmax = t;
    }

    hc_fclose (&fp);
  }

  om->bmax = bmax;
  om->nctx = ctxi.cnt;
  om->nip  = nip;

  intern_free (&ctxi);

  if ((bmax == 0) || (om->kmax == 0) || (nip == 0) || (rcnt == 0))
  {
    hcfree (raw);
    hcfree (ip_ctx);
    hcfree (ip_chr);
    hcfree (ip_lvl);

    intern_free (&chri);

    return 1;
  }

  om->cbuf     = chri.buf;
  om->cbuf_len = (u32) chri.buf_len;

  u32 *chr_off = chri.off;

  chri.buf = NULL;
  chri.off = NULL;

  intern_free (&chri);

  om->tr_cnt = (u32) rcnt;
  om->ctx_off = (u32 *) hccalloc (om->nctx + 2, sizeof (u32));
  om->tr      = (pcfg_omen_tr_t *) hcmalloc (rcnt * sizeof (pcfg_omen_tr_t));

  for (size_t i = 0; i < rcnt; i++) om->ctx_off[raw[i].src + 1]++;

  for (u32 c = 0; c < om->nctx; c++) om->ctx_off[c + 1] += om->ctx_off[c];

  {
    u32 *cur = (u32 *) hcmalloc (om->nctx * sizeof (u32));

    for (u32 c = 0; c < om->nctx; c++) cur[c] = om->ctx_off[c];

    u32 head[PCFG_OMEN_MAXLVL + 2];

    for (u32 l = 0; l <= PCFG_OMEN_MAXLVL + 1; l++) head[l] = 0;

    for (size_t i = 0; i < rcnt; i++) head[raw[i].lvl + 1]++;

    for (u32 l = 0; l <= PCFG_OMEN_MAXLVL; l++) head[l + 1] += head[l];

    pcfg_omen_raw_t *bylvl = (pcfg_omen_raw_t *) hcmalloc (rcnt * sizeof (pcfg_omen_raw_t));

    for (size_t i = 0; i < rcnt; i++) bylvl[head[raw[i].lvl]++] = raw[i];

    for (size_t i = 0; i < rcnt; i++)
    {
      const u32 at = cur[bylvl[i].src]++;

      om->tr[at].dst  = bylvl[i].dst;
      om->tr[at].coff = chr_off[bylvl[i].chr];
      om->tr[at].clen = (u8) (chr_off[bylvl[i].chr + 1] - chr_off[bylvl[i].chr]);
      om->tr[at].lvl  = (u8) bylvl[i].lvl;
    }

    hcfree (bylvl);
    hcfree (cur);
  }

  hcfree (raw);

  om->ip_ctx = (u32 *) hcmalloc (nip * sizeof (u32));
  om->ip_off = (u32 *) hcmalloc (nip * sizeof (u32));
  om->ip_len = (u8  *) hcmalloc (nip * sizeof (u8));

  {
    u32 head[PCFG_OMEN_MAXLVL + 2];

    for (u32 l = 0; l <= PCFG_OMEN_MAXLVL + 1; l++) head[l] = 0;

    for (u32 i = 0; i < nip; i++) head[ip_lvl[i] + 1]++;

    for (u32 l = 0; l <= PCFG_OMEN_MAXLVL; l++) head[l + 1] += head[l];

    for (u32 l = 0; l <= PCFG_OMEN_MAXLVL + 1; l++) om->ip_lvl_off[l] = head[l];

    for (u32 i = 0; i < nip; i++)
    {
      const u32 at = head[ip_lvl[i]]++;

      om->ip_ctx[at] = ip_ctx[i];
      om->ip_off[at] = chr_off[ip_chr[i]];
      om->ip_len[at] = (u8) (chr_off[ip_chr[i] + 1] - chr_off[ip_chr[i]]);
    }
  }

  hcfree (ip_ctx);
  hcfree (ip_chr);
  hcfree (ip_lvl);
  hcfree (chr_off);

  om->ln_lvl = (u8 *) hcmalloc ((om->kmax + 1) * sizeof (u8));
  om->ln_k   = (u8 *) hcmalloc ((om->kmax + 1) * sizeof (u8));
  om->ln_cnt = 0;

  for (u32 l = 0; l <= PCFG_OMEN_MAXLVL; l++)
  {
    for (u32 k = 1; k <= om->kmax; k++)
    {
      if (ln_lvl_of[k] != l) continue;

      om->ln_lvl[om->ln_cnt] = (u8) l;
      om->ln_k  [om->ln_cnt] = (u8) k;

      om->ln_cnt++;
    }
  }

  const size_t plane = (size_t) om->nctx;
  const size_t nplan = (size_t) (om->kmax + 1) * (om->bmax + 1);

  om->w = (u64 *) hccalloc (nplan * plane, sizeof (u64));

  om->bytes += nplan * plane * sizeof (u64);

  for (u32 c = 0; c < om->nctx; c++) om->w[c] = 1;

  for (u32 m = 1; m <= om->kmax; m++)
  {
    for (u32 b = 0; b <= om->bmax; b++)
    {
      u64 *dst = om->w + ((size_t) (m * (om->bmax + 1) + b)) * plane;

      const u64 *prv = om->w + ((size_t) ((m - 1) * (om->bmax + 1))) * plane;

      for (u32 c = 0; c < om->nctx; c++)
      {
        const u32 e0 = om->ctx_off[c];
        const u32 e1 = om->ctx_off[c + 1];

        u64 acc = 0;

        for (u32 e = e0; e < e1; e++)
        {
          const u32 l = om->tr[e].lvl;

          if (l > b) break;

          acc = sat_add (acc, prv[((size_t) (b - l) * plane) + om->tr[e].dst]);
        }

        dst[c] = acc;
      }
    }
  }

  const size_t isz = (size_t) (PCFG_OMEN_MAXLVL + 1) * (om->kmax + 1) * (om->bmax + 1);

  om->ipsum = (u64 *) hccalloc (isz, sizeof (u64));

  om->bytes += isz * sizeof (u64);

  for (u32 l = 0; l <= PCFG_OMEN_MAXLVL; l++)
  {
    for (u32 i = om->ip_lvl_off[l]; i < om->ip_lvl_off[l + 1]; i++)
    {
      const u32 c = om->ip_ctx[i];

      for (u32 m = 0; m <= om->kmax; m++)
      {
        u64 *dst = om->ipsum + ((size_t) (l * (om->kmax + 1) + m)) * (om->bmax + 1);

        const u64 *src = om->w + ((size_t) (m * (om->bmax + 1))) * plane;

        for (u32 b = 0; b <= om->bmax; b++) dst[b] = sat_add (dst[b], src[((size_t) b * plane) + c]);
      }
    }
  }

  om->tprob = (double *) hccalloc (om->bmax + 1, sizeof (double));
  om->tcnt  = (u64 *)    hccalloc (om->bmax + 1, sizeof (u64));

  for (u32 t = 1; t <= om->bmax; t++)
  {
    if (prob[t] <= 0.0) continue;

    u64 cnt = 0;

    for (u32 n = 0; n < om->ln_cnt; n++)
    {
      const u32 lnl = om->ln_lvl[n];
      const u32 k   = om->ln_k[n];

      if (lnl > t) continue;

      for (u32 l = 0; (l + lnl <= t) && (l <= PCFG_OMEN_MAXLVL); l++)
      {
        const u32 b = t - lnl - l;

        cnt = sat_add (cnt, om->ipsum[(((size_t) (l * (om->kmax + 1) + k)) * (om->bmax + 1)) + b]);
      }
    }

    om->tprob[t] = prob[t];
    om->tcnt[t]  = cnt;
  }

  return 0;
}

static void omen_free (pcfg_omen_t *om)
{
  hcfree (om->ctx_off);
  hcfree (om->tr);
  hcfree (om->cbuf);
  hcfree (om->ip_ctx);
  hcfree (om->ip_off);
  hcfree (om->ip_len);
  hcfree (om->ln_lvl);
  hcfree (om->ln_k);
  hcfree (om->w);
  hcfree (om->ipsum);
  hcfree (om->tprob);
  hcfree (om->tcnt);
}

static double omen_mass (const pcfg_root_t *r)
{
  char path[HCBUFSIZ_TINY];
  char line[HCBUFSIZ_TINY];

  const char *rel = "Grammar/grammar.txt";

  snprintf (path, sizeof (path), "%s/%s", r->dir, rel);

  HCFILE fp;

  if (root_open (r, rel, &fp) == false) return 0.0;

  double p = 0.0;

  while (hc_fgets (line, sizeof (line), &fp) != NULL)
  {
    if (line[0] != 'M')  continue;
    if (line[1] != '\t') continue;

    p = strtod (line + 2, NULL);

    break;
  }

  hc_fclose (&fp);

  if (p < 0.0) return 0.0;

  return p;
}

// What the M line is worth across every ruleset in the run, as a percentage. A run that drops the
// escape gives up exactly this much of the probability the grammar was trained to describe. The
// trainer's coverage setting decides it, not hashcat, so a reader who sees the figure knows which
// setting to change.

static double omen_mass_pct (const pcfg_root_t *roots, const u32 nroots)
{
  double mass = 0.0;

  for (u32 i = 0; i < nroots; i++)
  {
    mass += omen_mass (&roots[i]) * roots[i].w;
  }

  if (mass <= 0.0) return 0.0;

  if (mass > 1.0) mass = 1.0;

  const double pct = mass * 100.0;

  return pct;
}

static bool omen_load (generic_global_ctx_t *global_ctx, pcfg_global_t *pg, const pcfg_root_t *roots, const u32 nroots)
{
  if (global_ctx->dev_enable == true)
  {
    if ((pg->m_lines > 0) && (global_ctx->quiet == false))
    {
      pmsg (pg, "pcfg: OMEN escape dropped, the device engine cannot walk a trellis. %.0f%% of the mass, set by coverage", omen_mass_pct (roots, nroots));
    }

    return true;
  }

  if (pg->omen_want == false)
  {
    if ((pg->m_lines > 0) && (global_ctx->quiet == false))
    {
      pmsg (pg, "pcfg: OMEN escape dropped, omen=0. %.0f%% of the mass, set by coverage", omen_mass_pct (roots, nroots));
    }

    return true;
  }

  pg->omen = (pcfg_omen_t *) hccalloc (nroots, sizeof (pcfg_omen_t));

  u32 with_dir = 0;

  for (u32 i = 0; i < nroots; i++)
  {
    pcfg_omen_t *om = &pg->omen[pg->omen_cnt];

    const int rc = omen_load_one (global_ctx, om, &roots[i]);

    if (rc == -1) return false;

    if (rc == 1) continue;

    with_dir++;

    const double mass = omen_mass (&roots[i]) * roots[i].w;

    if (mass <= 0.0)
    {
      omen_free (om);

      memset (om, 0, sizeof (pcfg_omen_t));

      continue;
    }

    for (u32 t = 1; t <= om->bmax; t++)
    {
      if (om->tcnt[t] == 0) continue;

      const double q = -log2 (mass * om->tprob[t]) * (double) pg->scale;

      if (q < 0.0) continue;

      const u32 cost = (u32) (q + 0.5);

      if (cost > pg->costmax) continue;

      pg->omen_lvl = (pcfg_omen_lvl_t *) hcrealloc (pg->omen_lvl, pg->omen_lvl_cnt * sizeof (pcfg_omen_lvl_t), (pg->omen_lvl_cnt + 1) * sizeof (pcfg_omen_lvl_t));

      pg->omen_lvl[pg->omen_lvl_cnt].mi   = pg->omen_cnt;
      pg->omen_lvl[pg->omen_lvl_cnt].lvl  = t;
      pg->omen_lvl[pg->omen_lvl_cnt].cost = cost;
      pg->omen_lvl[pg->omen_lvl_cnt].cnt  = om->tcnt[t];

      pg->omen_lvl_cnt++;

      pg->omen_keyspace = sat_add (pg->omen_keyspace, om->tcnt[t]);
    }

    pg->omen_bytes += om->bytes;

    pg->omen_cnt++;
  }

  if (global_ctx->quiet == true) return true;

  if (pg->omen_lvl_cnt > 0)
  {
    pmsg (pg, "pcfg: OMEN escape carried, %u level%s over %u model%s, %" PRIu64 " guesses, %" PRIu64 " MiB of tables",
      pg->omen_lvl_cnt, (pg->omen_lvl_cnt == 1) ? "" : "s",
      pg->omen_cnt,     (pg->omen_cnt == 1) ? "" : "s",
      pg->omen_keyspace, pg->omen_bytes / (1024 * 1024));

    return true;
  }

  if (pg->m_lines > 0)
  {
    if (with_dir == 0)
    {
      pmsg (pg, "pcfg: OMEN escape dropped, the ruleset has an M line but no Omen directory");
    }
    else
    {
      pmsg (pg, "pcfg: OMEN escape dropped, no level of it lands at or below costmax");
    }
  }

  return true;
}

static u32 omen_live (const pcfg_omen_t *om, const pcfg_omen_walk_t *ow, const u32 p, const u32 from)
{
  const u32 c = ow->ctx[p];
  const u32 b = ow->bud[p];

  const u32 e1 = om->ctx_off[c + 1];

  const u64 *plane = om->w + ((size_t) ((ow->k - p - 1) * (om->bmax + 1))) * om->nctx;

  for (u32 e = from; e < e1; e++)
  {
    const u32 l = om->tr[e].lvl;

    if (l > b) break;

    if (plane[((size_t) (b - l) * om->nctx) + om->tr[e].dst] == 0) continue;

    return e;
  }

  return e1;
}

static void omen_take (const pcfg_omen_t *om, pcfg_omen_walk_t *ow, const u32 p, const u32 e)
{
  const pcfg_omen_tr_t *t = &om->tr[e];

  ow->ti[p] = e;

  const u32 at = ow->boff[p];

  memcpy (ow->buf + at, om->cbuf + t->coff, t->clen);

  ow->ctx [p + 1] = t->dst;
  ow->bud [p + 1] = ow->bud[p] - t->lvl;
  ow->boff[p + 1] = at + t->clen;
}

static void omen_fill (const pcfg_omen_t *om, pcfg_omen_walk_t *ow, const u32 p)
{
  for (u32 q = p; q < ow->k; q++) omen_take (om, ow, q, omen_live (om, ow, q, om->ctx_off[ow->ctx[q]]));

  ow->len = ow->boff[ow->k];
}

static void omen_seed (const pcfg_omen_t *om, pcfg_omen_walk_t *ow, const u32 ipi, const u32 b, u64 n)
{
  ow->ipi = ipi;

  memcpy (ow->buf, om->cbuf + om->ip_off[ipi], om->ip_len[ipi]);

  ow->ctx [0] = om->ip_ctx[ipi];
  ow->bud [0] = b;
  ow->boff[0] = om->ip_len[ipi];

  for (u32 p = 0; p < ow->k; p++)
  {
    const u32 c  = ow->ctx[p];
    const u32 bb = ow->bud[p];

    const u64 *plane = om->w + ((size_t) ((ow->k - p - 1) * (om->bmax + 1))) * om->nctx;

    const u32 e1 = om->ctx_off[c + 1];

    u32 e = om->ctx_off[c];

    for (; e < e1; e++)
    {
      const u32 l = om->tr[e].lvl;

      if (l > bb) break;

      const u64 w = plane[((size_t) (bb - l) * om->nctx) + om->tr[e].dst];

      if (w == 0) continue;
      if (n < w)  break;

      n -= w;
    }

    omen_take (om, ow, p, e);
  }

  ow->len = ow->boff[ow->k];
}

static bool omen_unrank (pcfg_global_t *pg, pcfg_thread_t *th, const u32 oi, u64 n)
{
  const pcfg_omen_lvl_t *ol = &pg->omen_lvl[oi];
  const pcfg_omen_t     *om = &pg->omen[ol->mi];

  const u32 t = ol->lvl;

  pcfg_omen_walk_t *ow = &th->om;

  for (u32 lni = 0; lni < om->ln_cnt; lni++)
  {
    const u32 lnl = om->ln_lvl[lni];
    const u32 k   = om->ln_k[lni];

    for (u32 l = 0; (l <= PCFG_OMEN_MAXLVL) && ((l + lnl) <= t); l++)
    {
      const u32 b = t - lnl - l;

      const u64 w = om->ipsum[(((size_t) (l * (om->kmax + 1) + k)) * (om->bmax + 1)) + b];

      if (w == 0) continue;

      if (n >= w) { n -= w; continue; }

      const u64 *plane = om->w + ((size_t) (k * (om->bmax + 1) + b)) * om->nctx;

      for (u32 i = om->ip_lvl_off[l]; i < om->ip_lvl_off[l + 1]; i++)
      {
        const u64 wi = plane[om->ip_ctx[i]];

        if (wi == 0) continue;

        if (n >= wi) { n -= wi; continue; }

        ow->oi  = oi;
        ow->lni = lni;
        ow->ipl = l;
        ow->k   = k;

        omen_seed (om, ow, i, b, n);

        return true;
      }

      return false;
    }
  }

  return false;
}

static bool omen_next (const pcfg_global_t *pg, pcfg_thread_t *th)
{
  const pcfg_omen_lvl_t *ol = &pg->omen_lvl[th->om.oi];
  const pcfg_omen_t     *om = &pg->omen[ol->mi];

  pcfg_omen_walk_t *ow = &th->om;

  for (u32 p = ow->k; p > 0; p--)
  {
    const u32 q = p - 1;

    const u32 e = omen_live (om, ow, q, ow->ti[q] + 1);

    if (e >= om->ctx_off[ow->ctx[q] + 1]) continue;

    omen_take (om, ow, q, e);

    omen_fill (om, ow, q + 1);

    return true;
  }

  const u32 t = ol->lvl;

  u32 lni = ow->lni;
  u32 l   = ow->ipl;
  u32 i   = ow->ipi + 1;

  while (lni < om->ln_cnt)
  {
    const u32 lnl = om->ln_lvl[lni];
    const u32 k   = om->ln_k[lni];

    while ((l <= PCFG_OMEN_MAXLVL) && ((l + lnl) <= t))
    {
      const u32 b = t - lnl - l;

      const u64 *plane = om->w + ((size_t) (k * (om->bmax + 1) + b)) * om->nctx;

      while (i < om->ip_lvl_off[l + 1])
      {
        if (plane[om->ip_ctx[i]] > 0)
        {
          ow->lni = lni;
          ow->ipl = l;
          ow->k   = k;

          omen_seed (om, ow, i, b, 0);

          return true;
        }

        i++;
      }

      l++;

      i = om->ip_lvl_off[l];
    }

    lni++;

    l = 0;
    i = om->ip_lvl_off[0];
  }

  return false;
}

static void build_index (pcfg_global_t *pg)
{
  u32 cmax = 0;

  for (u32 i = 0; i < pg->structs_cnt; i++) if (pg->structs[i].cmax > cmax) cmax = pg->structs[i].cmax;

  for (u32 i = 0; i < pg->omen_lvl_cnt; i++) if (pg->omen_lvl[i].cost > cmax) cmax = pg->omen_lvl[i].cost;

  u64 *tot = (u64 *) hccalloc (cmax + 1, sizeof (u64));

  for (u32 i = 0; i < pg->structs_cnt; i++)
  {
    const pcfg_struct_t *s = &pg->structs[i];
    const u32 span = pg->costmax - s->cost + 1;

    for (u32 r = 0; r < span; r++)
    {
      if (s->suf[r] == 0) continue;

      tot[s->cost + r] = sat_add (tot[s->cost + r], s->suf[r]);
    }
  }

  for (u32 i = 0; i < pg->omen_lvl_cnt; i++)
  {
    tot[pg->omen_lvl[i].cost] = sat_add (tot[pg->omen_lvl[i].cost], pg->omen_lvl[i].cnt);
  }

  pg->lvl_cnt = 0;

  {
    const u64 safe = (u64) 1 << 62;

    u64 acc = 0;

    for (u32 c = 0; c <= cmax; c++)
    {
      if (tot[c] == 0) continue;

      if (tot[c] >= safe || acc > safe - tot[c]) break;

      acc += tot[c];

      pg->lvl_cnt++;
    }
  }

  if (pg->lvl_cnt == 0) return;

  pg->lvl_cost  = (u32 *)  hcmalloc (pg->lvl_cnt * sizeof (u32));
  pg->lvl_pref  = (u64 *)  hcmalloc ((pg->lvl_cnt + 1) * sizeof (u64));
  pg->ls_struct = (u32 **) hcmalloc (pg->lvl_cnt * sizeof (u32 *));
  pg->ls_pref   = (u64 **) hcmalloc (pg->lvl_cnt * sizeof (u64 *));
  pg->ls_cnt    = (u32 *)  hcmalloc (pg->lvl_cnt * sizeof (u32));

  u32 li  = 0;
  u64 run = 0;

  const u64 safe = (u64) 1 << 62;

  for (u32 c = 0; c <= cmax; c++)
  {
    if (tot[c] == 0) continue;

    if (tot[c] >= safe || run > safe - tot[c]) break;

    pg->lvl_cost[li] = c;
    pg->lvl_pref[li] = run;

    u32 n = 0;

    for (u32 i = 0; i < pg->structs_cnt; i++)
    {
      const pcfg_struct_t *s = &pg->structs[i];

      if (c < s->cost || c > s->cmax) continue;
      if (s->suf[c - s->cost] == 0)   continue;

      n++;
    }

    for (u32 i = 0; i < pg->omen_lvl_cnt; i++)
    {
      if (pg->omen_lvl[i].cost != c) continue;
      if (pg->omen_lvl[i].cnt == 0)  continue;

      n++;
    }

    pg->ls_struct[li] = (u32 *) hcmalloc (n * sizeof (u32));
    pg->ls_pref[li]   = (u64 *) hcmalloc (n * sizeof (u64));
    pg->ls_cnt[li]    = n;

    u32 k = 0;
    u64 acc = 0;

    for (u32 i = 0; i < pg->structs_cnt; i++)
    {
      const pcfg_struct_t *s = &pg->structs[i];

      if (c < s->cost || c > s->cmax) continue;

      const u64 w = s->suf[c - s->cost];

      if (w == 0) continue;

      pg->ls_struct[li][k] = i;
      pg->ls_pref[li][k]   = acc;

      acc = sat_add (acc, w);

      k++;
    }

    for (u32 i = 0; i < pg->omen_lvl_cnt; i++)
    {
      if (pg->omen_lvl[i].cost != c) continue;
      if (pg->omen_lvl[i].cnt == 0)  continue;

      pg->ls_struct[li][k] = pg->structs_cnt + i;
      pg->ls_pref[li][k]   = acc;

      acc = sat_add (acc, pg->omen_lvl[i].cnt);

      k++;
    }

    run = sat_add (run, tot[c]);

    li++;
  }

  pg->lvl_pref[pg->lvl_cnt] = run;
  pg->keyspace = run;

  hcfree (tot);
}

static bool unrank (pcfg_global_t *pg, u64 n, pcfg_thread_t *th)
{
  if (n >= pg->keyspace) return false;

  u32 lo = 0;
  u32 hi = pg->lvl_cnt - 1;

  while (lo < hi)
  {
    const u32 mid = (lo + hi + 1) / 2;

    if (pg->lvl_pref[mid] <= n) lo = mid; else hi = mid - 1;
  }

  const u32 li = lo;
  const u32 c  = pg->lvl_cost[li];

  n -= pg->lvl_pref[li];

  const u32 *ss = pg->ls_struct[li];
  const u64 *sp = pg->ls_pref[li];

  lo = 0;
  hi = pg->ls_cnt[li] - 1;

  while (lo < hi)
  {
    const u32 mid = (lo + hi + 1) / 2;

    if (sp[mid] <= n) lo = mid; else hi = mid - 1;
  }

  const u32 si = ss[lo];

  n -= sp[lo];

  if (si >= pg->structs_cnt)
  {
    if (omen_unrank (pg, th, si - pg->structs_cnt, n) == false) return false;

    th->cost  = c;
    th->omen  = true;
    th->valid = true;

    return true;
  }

  th->omen = false;

  pcfg_struct_t *s = &pg->structs[si];

  const u32 span = pg->costmax - s->cost + 1;

  u32 r = c - s->cost;

  for (u32 j = 0; j < s->nslot; j++)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];
    const u64 *nxt = s->suf + (size_t) (j + 1) * span;

    bool placed = false;

    for (u32 b = 0; b < t->nb; b++)
    {
      const u32 cb = t->b_cost[b];

      if (cb > r) continue;

      const u64 w = nxt[r - cb];

      if (w == 0) continue;

      const u64 blk = sat_mul (t->b_cnt[b], w);

      if (n < blk)
      {
        th->idx[j] = t->b_start[b] + (u32) (n / w);

        n = n % w;
        r = r - cb;

        th->inner     = j;
        th->inner_end = t->b_start[b] + t->b_cnt[b];

        placed = true;

        break;
      }

      n -= blk;
    }

    if (placed == false) return false;
  }

  th->si    = si;
  th->cost  = c;
  th->valid = true;

  return true;
}

// The seat a cost takes in the level index, or -1 when build_index () never made that level: either
// nothing in the grammar lands on it, or it sits past the point the build truncated at. Same search
// as the one unrank () opens with (3288-3296), only asking for an exact cost instead of the level a
// position falls in.

static int level_of (const pcfg_global_t *pg, const u32 c)
{
  if (pg->lvl_cnt == 0) return -1;

  u32 lo = 0;
  u32 hi = pg->lvl_cnt - 1;

  while (lo < hi)
  {
    const u32 mid = (lo + hi + 1) / 2;

    if (pg->lvl_cost[mid] <= c) lo = mid; else hi = mid - 1;
  }

  if (pg->lvl_cost[lo] != c) return -1;

  return (int) lo;
}

// The seat a member takes inside one level, or -1 when it takes none. A structure is named by its
// own index and an OMEN level by structs_cnt + its index, which is how build_index () writes them
// (3247-3272), and ls_struct is ascending in that name, so the search is the same shape as the
// second one in unrank () (3303-3312).

static int level_seat (const pcfg_global_t *pg, const u32 li, const u32 id)
{
  const u32 *ss = pg->ls_struct[li];

  u32 lo = 0;
  u32 hi = pg->ls_cnt[li] - 1;

  while (lo < hi)
  {
    const u32 mid = (lo + hi + 1) / 2;

    if (ss[mid] <= id) lo = mid; else hi = mid - 1;
  }

  if (ss[lo] != id) return -1;

  return (int) lo;
}

// The bucket that holds one entry of a terminal list. tlist_build () cuts the list into buckets that
// tile it end to end (1578-1594), so b_start is ascending and a search over it names the bucket. The
// per entry cost array does not survive the build, it is freed at 1607, so this is also the only way
// back to what an entry costs.

static u32 tlist_bucket_of (const pcfg_tlist_t *t, const u32 i)
{
  u32 lo = 0;
  u32 hi = t->nb - 1;

  while (lo < hi)
  {
    const u32 mid = (lo + hi + 1) / 2;

    if (t->b_start[mid] <= i) lo = mid; else hi = mid - 1;
  }

  return lo;
}

// The exact inverse of unrank (): hand it a structure and the entry each of its slots picked, and it
// hands back the position that unrank () turns back into that same pick. It walks the same tables in
// the same order and simply adds up what unrank () would have stepped over.
//
// The per slot part keeps unrank ()'s bucket loop rather than reducing to a sum over costs. The
// reduction is sound, every entry of a cost run shares its cost and therefore its weight and b_start
// is absolute, so how the run is cut cannot move a rank. But it would need a per cost histogram of
// the list, and that table does not exist here: tlist_build () frees the per entry costs at 1607 and
// leaves only the buckets. Walking the buckets reads what is actually stored, and it stays mirrored
// for free when PCFG_BUCKETCAP, PCFG_LENSPLIT or tlist_split_bylen () re-cut them.
//
// out_cost is written as soon as the cost is known, including on the two failure paths that have one
// to report, so a caller can tell "costs too much" from "not in this grammar at all".

static bool pcfg_rank (const pcfg_global_t *pg, const u32 si, const u32 *idx, u64 *out_pos, u32 *out_cost)
{
  if (si >= pg->structs_cnt) return false;

  const pcfg_struct_t *s = &pg->structs[si];

  u64 c = s->cost;

  for (u32 j = 0; j < s->nslot; j++)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];

    if (idx[j] >= t->cnt) return false;

    c += t->b_cost[tlist_bucket_of (t, idx[j])];
  }

  if (out_cost != NULL) *out_cost = (u32) c;

  if (c > pg->costmax) return false;

  const int li = level_of (pg, (u32) c);

  if (li == -1) return false;

  const int seat = level_seat (pg, (u32) li, si);

  if (seat == -1) return false;

  u64 n = sat_add (pg->lvl_pref[li], pg->ls_pref[li][seat]);

  const u32 span = pg->costmax - s->cost + 1;

  u32 r = (u32) c - s->cost;

  for (u32 j = 0; j < s->nslot; j++)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];
    const u64 *nxt = s->suf + (size_t) (j + 1) * span;

    const u32 hit = tlist_bucket_of (t, idx[j]);
    const u32 cb  = t->b_cost[hit];

    if (cb > r) return false;

    const u64 w = nxt[r - cb];

    if (w == 0) return false;

    for (u32 b = 0; b < hit; b++)
    {
      const u32 cbb = t->b_cost[b];

      if (cbb > r) continue;

      const u64 wb = nxt[r - cbb];

      if (wb == 0) continue;

      n = sat_add (n, sat_mul (t->b_cnt[b], wb));
    }

    n = sat_add (n, sat_mul (idx[j] - t->b_start[hit], w));

    r = r - cb;
  }

  if (r != 0) return false;

  if (n >= pg->keyspace) return false;

  *out_pos = n;

  return true;
}

static int assemble (pcfg_global_t *pg, const pcfg_thread_t *th, u8 *out, const int out_size)
{

  if (th->omen == true)
  {
    const int len  = (int) th->om.len;
    const int room = (len < out_size) ? len : out_size;

    memcpy (out, th->om.buf, (size_t) room);

    return len;
  }

  const pcfg_struct_t *s = &pg->structs[th->si];

  int pos = 0;
  int last_off = 0;
  int last_len = 0;

  for (u32 j = 0; j < s->nslot; j++)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];
    const u32 i = th->idx[j];

    if (i >= t->cnt) return GENERIC_RC_ERROR;

    const u8 *v = t->buf + t->off[i];
    const int l = (int) (t->off[i + 1] - t->off[i]);

    if (s->kind[j] == PCFG_SLOT_TERM)
    {

      if (pos < out_size)
      {
        const int room = out_size - pos;
        const int cp   = (l < room) ? l : room;

        memcpy (out + pos, v, cp);
      }

      last_off = pos;
      last_len = l;

      pos += l;
    }
    else
    {

      const pcfg_tlist_t *ta = &pg->lists[s->list[j - 1]];

      const u8 *up = (ta->ubuf != NULL) ? (ta->ubuf + ta->off[th->idx[j - 1]]) : NULL;

      int ci = 0;
      int at = 0;

      while ((at < last_len) && (ci < l))
      {
        const bool hit = (v[ci] == 'U') && (up != NULL);

        if ((last_off + at) >= out_size) break;

        if (hit == true) out[last_off + at] = up[at];

        at++;

        while (at < last_len)
        {
          if ((last_off + at) >= out_size) break;

          if ((out[last_off + at] & 0xc0) != 0x80) break;

          if (hit == true) out[last_off + at] = up[at];

          at++;
        }

        ci++;
      }
    }
  }

  return pos;
}

// ---------------------------------------------------------------------------------------------
// pcfg_parse (): a password back into every derivation that produces it.
//
// The inverse of assemble () at 3387. A structure is a fixed sequence of slots, so the walk is the
// same walk with the candidate chosen by the password instead of by a rank: each slot eats a piece
// of the password, and a slot that cannot eat one backtracks into the slot before it. What comes
// out is a (structure, slot index tuple) for every derivation, which is exactly what rank_of ()
// wants; a password can be reached by several structures ("password" is A8 and also A4A4), and they
// do not rank the same, so the caller takes the lowest.
//
// The OMEN escape is not searched here. It does not go through a structure at all, so it is asked
// separately, the way omen_unrank () at 3027 sits beside unrank ().
// ---------------------------------------------------------------------------------------------

static u32 pcfg_utf8_len (const u8 *s, const u32 len)
{
  u32 at = 0;
  u32 n  = 0;

  while (at < len)
  {
    u32 cp = 0;

    at += pcfg_utf8_get (s + at, len - at, &cp);

    n++;
  }

  return n;
}

// How many bytes the next nchar characters take, or 0xffffffff when the string runs out first. A
// non flat token's length is a count of characters, not of bytes, so every slot that is pinned by
// the structure measures its piece of the password with this.

static u32 pcfg_utf8_span (const u8 *s, const u32 len, const u32 nchar)
{
  u32 at = 0;

  for (u32 i = 0; i < nchar; i++)
  {
    if (at >= len) return 0xffffffff;

    u32 cp = 0;

    at += pcfg_utf8_get (s + at, len - at, &cp);
  }

  return at;
}

// The value -> index direction of a terminal list. A list is ordered by cost and not by value, so a
// lookup needs a table of its own. It is built for a list the first time a slot asks one of it and
// dropped when the lookup is over. Open addressing with a linear probe, the same shape as
// merge_rehash () at 1093, except that every entry takes a seat rather than every distinct value,
// so a key that several entries share is walked by probing on from the first hit.
//
// An alpha list carries the uppercase image of each entry in ubuf (tlist_build (), 1612, fed by the
// want_upper that list_get () at 1765 only passes for 'A'), and the mask slot that follows picks per
// character which of the two is shown. So an alpha list is keyed on its upper image and asked with
// the upper image of the segment: that finds every entry the mask could still reach, and
// mask_match () then decides whether it really does.

typedef struct
{
  u32 *seat;
  u32  mask;
  bool built;

} pcfg_vidx_t;

static const u8 *tlist_key (const pcfg_tlist_t *t, const u32 i)
{
  const u8 *b = (t->ubuf != NULL) ? t->ubuf : t->buf;

  return b + t->off[i];
}

static void vidx_build (pcfg_vidx_t *v, const pcfg_tlist_t *t)
{
  if (v->built == true) return;

  u32 cap = 64;

  while ((u64) cap < ((u64) t->cnt * 2)) cap *= 2;

  v->seat = (u32 *) hccalloc (cap, sizeof (u32));
  v->mask = cap - 1;

  for (u32 i = 0; i < t->cnt; i++)
  {
    const u64 h = merge_hash (tlist_key (t, i), t->off[i + 1] - t->off[i]);

    u32 at = (u32) (h & v->mask);

    while (v->seat[at] != 0) at = (at + 1) & v->mask;

    v->seat[at] = i + 1;
  }

  v->built = true;
}

// The next entry carrying this key, at[0] being the probe the caller stopped at. Entries come out in
// probe order and not in index order, which costs nothing: the caller keeps every hit and ranks them
// all.

static u32 vidx_next (const pcfg_vidx_t *v, const pcfg_tlist_t *t, const u8 *key, const u32 key_len, u32 *at)
{
  while (v->seat[at[0]] != 0)
  {
    const u32 i = v->seat[at[0]] - 1;

    at[0] = (at[0] + 1) & v->mask;

    if ((t->off[i + 1] - t->off[i]) != key_len) continue;

    if (memcmp (tlist_key (t, i), key, key_len) == 0) return i;
  }

  return 0xffffffff;
}

// Does entry mi of the mask list turn entry wi of the alpha list into seg? This is the else branch of
// assemble () at 3434 run forward and compared instead of written, so it inherits all of it: a
// character is a lead byte and the continuation bytes behind it, 'U' takes the byte from the upper
// image and anything else leaves it alone, and a mask that runs out before the word does leaves the
// rest of the word as it is.
//
// Asking the list this way instead of building the masks and looking them up is what keeps a long
// alpha token cheap: a segment whose characters are each uppercase and lowercase at once has 2^n
// masks, and the mask list is the smallest list in the ruleset.

static bool mask_match (const pcfg_tlist_t *ta, const u32 wi, const pcfg_tlist_t *tc, const u32 mi, const u8 *seg)
{
  const u8 *v  = ta->buf + ta->off[wi];
  const u8 *up = (ta->ubuf != NULL) ? (ta->ubuf + ta->off[wi]) : NULL;

  const u32 vlen = ta->off[wi + 1] - ta->off[wi];

  const u8 *m = tc->buf + tc->off[mi];

  const u32 mlen = tc->off[mi + 1] - tc->off[mi];

  u32 ci = 0;
  u32 at = 0;

  while ((at < vlen) && (ci < mlen))
  {
    const bool hit = (m[ci] == 'U') && (up != NULL);

    const u8 *src = (hit == true) ? up : v;

    if (seg[at] != src[at]) return false;

    at++;

    while (at < vlen)
    {
      if ((v[at] & 0xc0) != 0x80) break;

      if (seg[at] != src[at]) return false;

      at++;
    }

    ci++;
  }

  while (at < vlen)
  {
    if (seg[at] != v[at]) return false;

    at++;
  }

  return true;
}

static u32 pcfg_parse (pcfg_global_t *pg, const u8 *pw, const u32 pw_len, u32 *out_si, u32 (*out_idx)[PCFG_MAXSLOT], const u32 max_hits)
{
  if (max_hits == 0) return 0;

  const u32 pw_chars = pcfg_utf8_len (pw, pw_len);

  pcfg_vidx_t *vidx = (pcfg_vidx_t *) hccalloc (pg->lists_cnt, sizeof (pcfg_vidx_t));

  u8 *key = (u8 *) hcmalloc (pw_len + 1);

  u32 spos[PCFG_MAXSLOT + 1];
  u32 cur [PCFG_MAXSLOT + 1];
  u32 idx [PCFG_MAXSLOT];

  u32 hits = 0;

  for (u32 si = 0; si < pg->structs_cnt; si++)
  {
    const pcfg_struct_t *s = &pg->structs[si];

    // A structure with no flat token pins the length of what it produces, so only the ones that come
    // out at exactly this many characters are worth walking. A flat token's own length is not in the
    // structure, so those are walked whenever the pinned part alone is not already too long.

    bool flat = false;

    for (u32 j = 0; j < s->nslot; j++)
    {
      if (s->kind[j] != PCFG_SLOT_TERM) continue;

      if (s->tlen[j] == 0) flat = true;
    }

    if (flat == false)
    {
      if (s->total_len != pw_chars) continue;
    }
    else
    {
      if (s->total_len > pw_chars) continue;
    }

    spos[0] = 0;
    cur[0]  = 0xffffffff;

    u32 j = 0;

    while (true)
    {
      if (j == s->nslot)
      {
        if (spos[j] == pw_len)
        {
          out_si[hits] = si;

          for (u32 k = 0; k < s->nslot; k++) out_idx[hits][k] = idx[k];

          hits++;
        }

        if (hits == max_hits) break;

        if (j == 0) break;

        j--;

        continue;
      }

      const pcfg_tlist_t *t = &pg->lists[s->list[j]];

      bool got = false;

      if (s->kind[j] == PCFG_SLOT_MASK)
      {
        // The mask eats nothing of its own. It decides the case of the word the slot before it put
        // down, so every mask that reproduces that piece of the password is a candidate, and they do
        // not rank the same.

        const pcfg_tlist_t *ta = &pg->lists[s->list[j - 1]];

        u32 i = (cur[j] == 0xffffffff) ? 0 : cur[j];

        while (i < t->cnt)
        {
          if (mask_match (ta, idx[j - 1], t, i, pw + spos[j - 1]) == true) break;

          i++;
        }

        if (i < t->cnt)
        {
          idx[j]      = i;
          cur[j]      = i + 1;
          spos[j + 1] = spos[j];

          got = true;
        }
      }
      else if (s->tlen[j] == 0)
      {
        // A flat token's entries vary in length, so the structure does not say how much of the
        // password this slot takes and every entry that prefixes the rest has to be tried. X and Y
        // are the small lists in a ruleset, so this stays a scan; it also keeps the candidates in
        // list order, which is the order they rank in.

        const u32 room = pw_len - spos[j];

        u32 i = (cur[j] == 0xffffffff) ? 0 : cur[j];

        while (i < t->cnt)
        {
          const u32 l = t->off[i + 1] - t->off[i];

          if ((l <= room) && (memcmp (t->buf + t->off[i], pw + spos[j], l) == 0)) break;

          i++;
        }

        if (i < t->cnt)
        {
          idx[j]      = i;
          cur[j]      = i + 1;
          spos[j + 1] = spos[j] + (t->off[i + 1] - t->off[i]);

          got = true;
        }
      }
      else
      {
        const u32 span = pcfg_utf8_span (pw + spos[j], pw_len - spos[j], s->tlen[j]);

        if (span != 0xffffffff)
        {
          pcfg_vidx_t *v = &vidx[s->list[j]];

          vidx_build (v, t);

          if (t->ubuf != NULL)
          {
            pcfg_upper_image (key, pw + spos[j], span);
          }
          else
          {
            memcpy (key, pw + spos[j], span);
          }

          u32 at = cur[j];

          if (at == 0xffffffff) at = (u32) (merge_hash (key, span) & v->mask);

          const u32 i = vidx_next (v, t, key, span, &at);

          if (i != 0xffffffff)
          {
            idx[j]      = i;
            cur[j]      = at;
            spos[j + 1] = spos[j] + span;

            got = true;
          }
        }
      }

      if (got == false)
      {
        if (j == 0) break;

        j--;

        continue;
      }

      j++;

      cur[j] = 0xffffffff;
    }

    if (hits == max_hits) break;
  }

  for (u32 i = 0; i < pg->lists_cnt; i++) hcfree (vidx[i].seat);

  hcfree (vidx);
  hcfree (key);

  return hits;
}

// Where an OMEN level sits in the global candidate order. build_index () already laid the answer
// out: inside a cost level it appends every structure that reaches the cost and then every OMEN
// level with that cost, storing an OMEN level as structs_cnt + oi and its exclusive prefix sum
// alongside. So the base is a lookup, not a second summation. Mirrors build_index () 3234-3271.
// A cost that build_index () truncated away has no level here and the guess is never enumerated.

static bool pcfg_omen_base (const pcfg_global_t *pg, const u32 oi, u64 *out_base)
{
  if (pg->lvl_cnt == 0) return false;

  const u32 cost = pg->omen_lvl[oi].cost;

  for (u32 li = 0; li < pg->lvl_cnt; li++)
  {
    if (pg->lvl_cost[li] < cost) continue;
    if (pg->lvl_cost[li] > cost) break;

    for (u32 k = 0; k < pg->ls_cnt[li]; k++)
    {
      if (pg->ls_struct[li][k] != (pg->structs_cnt + oi)) continue;

      *out_base = sat_add (pg->lvl_pref[li], pg->ls_pref[li][k]);

      return true;
    }

    return false;
  }

  return false;
}

// The index this guess carries inside its own OMEN level: everything omen_unrank () would have
// skipped on the way to it. The three loops line up one for one with omen_unrank () 3027 - the
// (length entry, ip level) loop over ipsum, the IP loop over the w plane, and then, per position,
// the transition loop that omen_seed () 2986 walks. A cell the enumeration skips because its count
// is zero is skipped here too, before the target test, or the sums would not agree.

static bool pcfg_omen_index (const pcfg_omen_t *om, const u32 t, const pcfg_omen_walk_t *ow, u64 *out_idx)
{
  const u32 k   = ow->k;
  const u32 lnl = om->ln_lvl[ow->lni];
  const u32 l   = ow->ipl;

  u64 idx = 0;

  bool found = false;

  for (u32 lni = 0; (lni < om->ln_cnt) && (found == false); lni++)
  {
    const u32 lnl2 = om->ln_lvl[lni];
    const u32 k2   = om->ln_k[lni];

    for (u32 l2 = 0; (l2 <= PCFG_OMEN_MAXLVL) && ((l2 + lnl2) <= t); l2++)
    {
      const u32 b2 = t - lnl2 - l2;

      const u64 w = om->ipsum[(((size_t) (l2 * (om->kmax + 1) + k2)) * (om->bmax + 1)) + b2];

      if (w == 0) continue;

      if ((lni == ow->lni) && (l2 == l)) { found = true; break; }

      idx = sat_add (idx, w);
    }
  }

  if (found == false) return false;

  const u32 b = t - lnl - l;

  {
    const u64 *plane = om->w + ((size_t) (k * (om->bmax + 1) + b)) * om->nctx;

    bool hit = false;

    for (u32 i = om->ip_lvl_off[l]; i < om->ip_lvl_off[l + 1]; i++)
    {
      const u64 wi = plane[om->ip_ctx[i]];

      if (wi == 0) continue;

      if (i == ow->ipi) { hit = true; break; }

      idx = sat_add (idx, wi);
    }

    if (hit == false) return false;
  }

  for (u32 p = 0; p < k; p++)
  {
    const u32 c  = ow->ctx[p];
    const u32 bb = ow->bud[p];

    const u64 *plane = om->w + ((size_t) ((k - p - 1) * (om->bmax + 1))) * om->nctx;

    const u32 e1 = om->ctx_off[c + 1];

    bool hit = false;

    for (u32 e = om->ctx_off[c]; e < e1; e++)
    {
      const u32 lv = om->tr[e].lvl;

      if (lv > bb) break;

      const u64 w = plane[((size_t) (bb - lv) * om->nctx) + om->tr[e].dst];

      if (w == 0) continue;

      if (e == ow->ti[p]) { hit = true; break; }

      idx = sat_add (idx, w);
    }

    if (hit == false) return false;
  }

  *out_idx = idx;

  return true;
}

// One pass of omen_seed () 2986 read backwards: instead of picking a transition by rank, take the
// one whose characters are the next characters of the password. The first match wins, which is what
// the forward walk would have reached first as well.

static bool pcfg_omen_tail (const pcfg_omen_t *om, const u8 *pw, const u32 *off, const u32 k, pcfg_omen_walk_t *ow, u32 *out_spent)
{
  u32 spent = 0;

  for (u32 p = 0; p < k; p++)
  {
    const u32 c = ow->ctx[p];

    const u8 *ch  = pw + off[om->clen + p];
    const u32 len = off[om->clen + p + 1] - off[om->clen + p];

    const u32 e1 = om->ctx_off[c + 1];

    u32 e = om->ctx_off[c];

    for (; e < e1; e++)
    {
      if (om->tr[e].clen != len) continue;

      if (memcmp (om->cbuf + om->tr[e].coff, ch, len) == 0) break;
    }

    if (e == e1) return false;

    ow->ti [p]     = e;
    ow->ctx[p + 1] = om->tr[e].dst;

    spent += om->tr[e].lvl;

    if (spent > om->bmax) return false;
  }

  *out_spent = spent;

  return true;
}

// Can the Markov escape produce this password, and where. The password is split into characters the
// way omen_split () 2235 splits a gram, the character count fixes k and with it the length entry,
// every IP entry whose bytes are the first clen characters is a possible start, and the rest of the
// password has to be a run of transitions out of it. The total level is the length level plus the
// IP level plus every transition's level, which is the OMEN level that carries the guess.
//
// A model can reach the same password from more than one IP entry, and two models can both reach
// it, so every hit is priced and the earliest one wins. On success out_oi is the omen_lvl entry
// (its lvl and cost describe the hit), out_idx the index inside that level, out_pos the global
// candidate position.
//
// Nothing here has a device engine counterpart on purpose: omen_load () 2836 drops the escape when
// dev_enable is set, so omen_lvl_cnt is zero and the very first test refuses.

static bool pcfg_omen_lookup (const pcfg_global_t *pg, const u8 *pw, const u32 pw_len, u32 *out_oi, u64 *out_idx, u64 *out_pos)
{
  if (pg->omen_lvl_cnt == 0)      return false;
  if (pw_len > PCFG_OMEN_MAXBYTE) return false;

  u32 off[PCFG_OMEN_MAXK + PCFG_OMEN_MAXNGRAM + 1];

  pcfg_omen_walk_t ow;

  bool have = false;

  u32 best_oi  = 0;
  u64 best_idx = 0;
  u64 best_pos = 0;

  for (u32 mi = 0; mi < pg->omen_cnt; mi++)
  {
    const pcfg_omen_t *om = &pg->omen[mi];

    if (om->nctx == 0) continue;

    const u32 nchars = omen_split (om->utf8, pw, pw_len, off, PCFG_OMEN_MAXK + om->clen);

    if (nchars <= om->clen) continue;

    const u32 k = nchars - om->clen;

    if (k > om->kmax) continue;

    u32 lni = om->ln_cnt;

    for (u32 n = 0; n < om->ln_cnt; n++)
    {
      if (om->ln_k[n] != k) continue;

      lni = n;

      break;
    }

    if (lni == om->ln_cnt) continue;

    const u32 lnl  = om->ln_lvl[lni];
    const u32 plen = off[om->clen];

    for (u32 l = 0; l <= PCFG_OMEN_MAXLVL; l++)
    {
      for (u32 i = om->ip_lvl_off[l]; i < om->ip_lvl_off[l + 1]; i++)
      {
        if (om->ip_len[i] != plen) continue;

        if (memcmp (om->cbuf + om->ip_off[i], pw, plen) != 0) continue;

        ow.lni    = lni;
        ow.ipl    = l;
        ow.ipi    = i;
        ow.k      = k;
        ow.ctx[0] = om->ip_ctx[i];

        u32 spent = 0;

        if (pcfg_omen_tail (om, pw, off, k, &ow, &spent) == false) continue;

        const u32 t = lnl + l + spent;

        if (t > om->bmax) continue;

        // The budget the forward walk would have started with is exactly what the transitions
        // spend, so the descent omen_take () 2964 does can be replayed here.

        ow.bud[0] = spent;

        for (u32 p = 0; p < k; p++) ow.bud[p + 1] = ow.bud[p] - om->tr[ow.ti[p]].lvl;

        u32 oj = pg->omen_lvl_cnt;

        for (u32 j = 0; j < pg->omen_lvl_cnt; j++)
        {
          if (pg->omen_lvl[j].mi  != mi) continue;
          if (pg->omen_lvl[j].lvl != t)  continue;
          if (pg->omen_lvl[j].cnt == 0)  continue;

          oj = j;

          break;
        }

        if (oj == pg->omen_lvl_cnt) continue;

        u64 idx = 0;

        if (pcfg_omen_index (om, t, &ow, &idx) == false) continue;

        u64 base = 0;

        if (pcfg_omen_base (pg, oj, &base) == false) continue;

        const u64 at = sat_add (base, idx);

        if ((have == false) || (at < best_pos))
        {
          have = true;

          best_oi  = oj;
          best_idx = idx;
          best_pos = at;
        }
      }
    }
  }

  if (have == false) return false;

  *out_oi  = best_oi;
  *out_idx = best_idx;
  *out_pos = best_pos;

  return true;
}

static void slot_geometry (const pcfg_global_t *pg, const pcfg_struct_t *s, const u32 *idx, u32 *off, u32 *wid)
{
  u32 pos = 0;

  u32 last_off = 0;
  u32 last_len = 0;

  for (u32 j = 0; j < s->nslot; j++)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];

    const u32 i = idx[j];
    const u32 l = t->off[i + 1] - t->off[i];

    if (s->kind[j] == PCFG_SLOT_TERM)
    {
      off[j] = pos;
      wid[j] = l;

      last_off = pos;
      last_len = l;

      pos += l;
    }
    else
    {
      off[j] = last_off;
      wid[j] = (l < last_len) ? l : last_len;
    }
  }
}

static u32 token_len (const pcfg_struct_t *s, const u32 j)
{
  if ((j + 1) < s->nslot)
  {
    if (s->kind[j + 1] == PCFG_SLOT_MASK) return 2;
  }

  return 1;
}

static u32 bitlen (const u64 x)
{
  u32 b = 0;

  while ((((u64) 1) << b) < x) b++;

  return b;
}

static bool bucket_uni (const pcfg_global_t *pg, const pcfg_tlist_t *t, const u32 b)
{
  if (pg->varlen == true) return true;

  const bool uni = (t->b_len[b] != 0);

  return uni;
}

static void choose_cut (const pcfg_global_t *pg, pcfg_struct_t *s)
{
  u32 cut = 0;

  if (s->nslot > PCFG_DEV_MAXSLOT) cut = s->nslot - PCFG_DEV_MAXSLOT;

  u32 wide = 0;

  for (u32 j = 0; j < s->nslot; j++)
  {
    if (s->kind[j] == PCFG_SLOT_MASK) continue;

    wide += pg->lists[s->list[j]].max_len;
  }

  if (wide > pg->maxbyte)
  {
    s->cut = s->nslot;

    return;
  }

  while (cut < s->nslot)
  {
    if (s->kind[cut] != PCFG_SLOT_MASK) break;

    cut++;
  }

  s->cut = cut;
}

static void build_unit_suffix (pcfg_global_t *pg, pcfg_struct_t *s)
{
  const u32 span = pg->costmax - s->cost + 1;
  const u32 nb   = pg->kbits + 1;

  s->usuf = (u64 *) hccalloc ((size_t) (s->nslot + 1) * span, sizeof (u64));
  s->udev = (u64 *) hccalloc ((size_t) (s->nslot + 1) * span * nb, sizeof (u64));

  s->usuf[(size_t) s->nslot * span + 0] = 1;

  for (u32 b = 0; b < nb; b++) s->udev[((size_t) s->nslot * span + 0) * nb + b] = 1;

  for (int j = (int) s->nslot - 1; j >= 0; j--)
  {
    if (s->kind[j] == PCFG_SLOT_MASK) continue;

    const u32 len = token_len (s, (u32) j);
    const u32 nxt = (u32) j + len;

    const pcfg_tlist_t *ta = &pg->lists[s->list[j]];
    const pcfg_tlist_t *tm = (len == 2) ? &pg->lists[s->list[j + 1]] : NULL;

    u64 *tdst = s->usuf + (size_t) j * span;
    u64 *ddst = s->udev + (size_t) j * span * nb;

    const u64 *tsrc = s->usuf + (size_t) nxt * span;
    const u64 *dsrc = s->udev + (size_t) nxt * span * nb;

    const bool may = ((u32) j >= s->cut);

    for (u32 ba = 0; ba < ta->nb; ba++)
    {
      const u32 nbm = (len == 2) ? tm->nb : 1;

      for (u32 bm = 0; bm < nbm; bm++)
      {
        const u32 cb = ta->b_cost[ba] + ((len == 2) ? tm->b_cost[bm] : 0);

        if (cb >= span) continue;

        const u64 prod = sat_mul (ta->b_cnt[ba], (len == 2) ? tm->b_cnt[bm] : 1);

        bool uni = bucket_uni (pg, ta, ba);

        if (len == 2) uni = uni && bucket_uni (pg, tm, bm);

        const u32 bl = bitlen (prod);

        const bool dev = (may == true) && (uni == true) && (bl <= pg->kbits);

        for (u32 r = 0; r + cb < span; r++)
        {
          const u64 t = tsrc[r];

          if (t == 0) continue;

          if (dev == true)
          {

            const u64 room = dsrc[(size_t) r * nb + (pg->kbits - bl)];

            for (u32 b = bl; b < nb; b++)
            {
              ddst[(size_t) (r + cb) * nb + b] = sat_add (ddst[(size_t) (r + cb) * nb + b], dsrc[(size_t) r * nb + (b - bl)]);
            }

            tdst[r + cb] = sat_add (tdst[r + cb], sat_add (room, sat_mul (prod, t - room)));
          }
          else
          {
            tdst[r + cb] = sat_add (tdst[r + cb], sat_mul (prod, t));
          }
        }
      }
    }
  }
}

static u64 count_units (const pcfg_global_t *pg)
{
  u64 run = 0;

  for (u32 li = 0; li < pg->lvl_cnt; li++)
  {
    const u32 c = pg->lvl_cost[li];

    for (u32 i = 0; i < pg->structs_cnt; i++)
    {
      const pcfg_struct_t *s = &pg->structs[i];

      if (c < s->cost) continue;
      if (c > s->cmax) continue;

      run = sat_add (run, s->usuf[c - s->cost]);
    }
  }

  return run;
}

static u64 front_rect (const pcfg_global_t *pg, const u64 want)
{
  u64 units = 0;
  u64 cands = 0;

  for (u32 li = 0; li < pg->lvl_cnt; li++)
  {
    const u32 c = pg->lvl_cost[li];

    for (u32 i = 0; i < pg->structs_cnt; i++)
    {
      const pcfg_struct_t *s = &pg->structs[i];

      if (c < s->cost) continue;
      if (c > s->cmax) continue;

      units = sat_add (units, s->usuf[c - s->cost]);
      cands = sat_add (cands, s->suf[c - s->cost]);
    }

    if (units >= want) break;
  }

  if (units == 0) return 0;

  return cands / units;
}

static void unit_suffix_free (pcfg_global_t *pg)
{
  for (u32 i = 0; i < pg->structs_cnt; i++)
  {
    hcfree (pg->structs[i].usuf);
    hcfree (pg->structs[i].udev);

    pg->structs[i].usuf = NULL;
    pg->structs[i].udev = NULL;
  }

  pg->built = false;
}

// Building the suffix arrays is the most expensive thing the device engine does at startup, so what
// a call leaves behind is kept rather than thrown away. The next call frees it, and a caller that
// wants the pair already in hand skips the work entirely.

static void unit_suffix_build (pcfg_global_t *pg)
{
  if ((pg->built == true) && (pg->built_maxword == pg->maxword) && (pg->built_kbits == pg->kbits)) return;

  unit_suffix_free (pg);

  for (u32 i = 0; i < pg->structs_cnt; i++) choose_cut (pg, &pg->structs[i]);

  structs_sweep (pg, build_unit_suffix);

  pg->built         = true;
  pg->built_maxword = pg->maxword;
  pg->built_kbits   = pg->kbits;
}

static u64 cut_and_count (pcfg_global_t *pg, const u32 maxword, const u32 kbits)
{
  pg->maxword = maxword;
  pg->maxbyte = (maxword * 4) - 1;

  pg->kbits  = kbits;
  pg->il_cnt = (u32) 1 << kbits;

  unit_suffix_build (pg);

  const u64 units = count_units (pg);

  pg->front_rect = front_rect (pg, PCFG_FRONT_UNITS);

  return units;
}

static void build_unit_index (pcfg_global_t *pg)
{
  if (pg->lvl_cnt == 0) return;

  pg->ulvl_cnt   = pg->lvl_cnt;
  pg->ulvl_cost  = (u32 *)  hcmalloc (pg->ulvl_cnt * sizeof (u32));
  pg->ulvl_pref  = (u64 *)  hcmalloc ((pg->ulvl_cnt + 1) * sizeof (u64));
  pg->uls_struct = (u32 **) hcmalloc (pg->ulvl_cnt * sizeof (u32 *));
  pg->uls_pref   = (u64 **) hcmalloc (pg->ulvl_cnt * sizeof (u64 *));
  pg->uls_cnt    = (u32 *)  hcmalloc (pg->ulvl_cnt * sizeof (u32));

  u64 run = 0;

  for (u32 li = 0; li < pg->ulvl_cnt; li++)
  {
    const u32 c = pg->lvl_cost[li];

    pg->ulvl_cost[li] = c;
    pg->ulvl_pref[li] = run;

    u32 n = 0;

    for (u32 i = 0; i < pg->structs_cnt; i++)
    {
      const pcfg_struct_t *s = &pg->structs[i];

      if (c < s->cost || c > s->cmax) continue;
      if (s->usuf[c - s->cost] == 0)  continue;

      n++;
    }

    pg->uls_struct[li] = (u32 *) hcmalloc (n * sizeof (u32));
    pg->uls_pref[li]   = (u64 *) hcmalloc (n * sizeof (u64));
    pg->uls_cnt[li]    = n;

    u32 k = 0;
    u64 acc = 0;

    for (u32 i = 0; i < pg->structs_cnt; i++)
    {
      const pcfg_struct_t *s = &pg->structs[i];

      if (c < s->cost || c > s->cmax) continue;

      const u64 w = s->usuf[c - s->cost];

      if (w == 0) continue;

      pg->uls_struct[li][k] = i;
      pg->uls_pref[li][k]   = acc;

      acc = sat_add (acc, w);

      k++;
    }

    run = sat_add (run, acc);
  }

  pg->ulvl_pref[pg->ulvl_cnt] = run;
  pg->units = run;
}

#define PCFG_NOFCAP 0xffffffff

static u64 taken_in_front (const u64 *dsrc, const u32 nb, const u32 r, const u32 fcap, const u32 bl)
{
  if (fcap == PCFG_NOFCAP) return 0;

  if (bl > fcap) return 0;

  return dsrc[(size_t) r * nb + (fcap - bl)];
}

static u32 fcap_behind (const u32 fcap, const u32 bl)
{
  if (fcap == PCFG_NOFCAP) return PCFG_NOFCAP;

  if (fcap < bl) return PCFG_NOFCAP;

  return fcap - bl;
}

static bool unrank_unit (pcfg_global_t *pg, u64 n, pcfg_thread_t *th)
{
  if (n >= pg->units) return false;

  u32 lo = 0;
  u32 hi = pg->ulvl_cnt - 1;

  while (lo < hi)
  {
    const u32 mid = (lo + hi + 1) / 2;

    if (pg->ulvl_pref[mid] <= n) lo = mid; else hi = mid - 1;
  }

  const u32 li = lo;
  const u32 c  = pg->ulvl_cost[li];

  n -= pg->ulvl_pref[li];

  const u32 *ss = pg->uls_struct[li];
  const u64 *sp = pg->uls_pref[li];

  lo = 0;
  hi = pg->uls_cnt[li] - 1;

  while (lo < hi)
  {
    const u32 mid = (lo + hi + 1) / 2;

    if (sp[mid] <= n) lo = mid; else hi = mid - 1;
  }

  const u32 si = ss[lo];

  n -= sp[lo];

  pcfg_struct_t *s = &pg->structs[si];

  const u32 span = pg->costmax - s->cost + 1;
  const u32 nb   = pg->kbits + 1;

  u32 r = c - s->cost;

  bool devmode = false;

  u32 bcap = pg->kbits;
  u32 fcap = PCFG_NOFCAP;

  th->devstart = s->nslot;
  th->tcnt     = 0;

  u32 j = 0;

  while (j < s->nslot)
  {
    const u32 len = token_len (s, j);
    const u32 nxt = j + len;

    const u32 ti = th->tcnt;

    th->tslot[ti] = j;
    th->trem[ti]  = r;
    th->tcap[ti]  = bcap;
    th->tfcap[ti] = fcap;

    th->tcnt++;

    const pcfg_tlist_t *ta = &pg->lists[s->list[j]];
    const pcfg_tlist_t *tm = (len == 2) ? &pg->lists[s->list[j + 1]] : NULL;

    const u64 *tsrc = s->usuf + (size_t) nxt * span;
    const u64 *dsrc = s->udev + (size_t) nxt * span * nb;

    const bool may = (j >= s->cut);

    bool placed = false;

    for (u32 ba = 0; ba < ta->nb && placed == false; ba++)
    {
      const u32 nbm = (len == 2) ? tm->nb : 1;

      for (u32 bm = 0; bm < nbm; bm++)
      {
        const u32 cb = ta->b_cost[ba] + ((len == 2) ? tm->b_cost[bm] : 0);

        if (cb > r) continue;

        const u64 prod = sat_mul (ta->b_cnt[ba], (len == 2) ? tm->b_cnt[bm] : 1);

        bool uni = bucket_uni (pg, ta, ba);

        if (len == 2) uni = uni && bucket_uni (pg, tm, bm);

        const u32 bl = bitlen (prod);

        const bool dev = (may == true) && (uni == true) && (bl <= bcap);

        const u64 t = tsrc[r - cb];

        u64 blk  = 0;
        u64 room = 0;
        u64 dblk = 0;

        if (devmode == true)
        {
          if (dev == false) continue;

          room = dsrc[(size_t) (r - cb) * nb + (bcap - bl)];

          blk = room - taken_in_front (dsrc, nb, r - cb, fcap, bl);
        }
        else
        {
          if (dev == true)
          {
            room = dsrc[(size_t) (r - cb) * nb + (pg->kbits - bl)];

            dblk = room - taken_in_front (dsrc, nb, r - cb, fcap, bl);

            blk = sat_add (dblk, sat_mul (prod, t - room));
          }
          else
          {
            blk = sat_mul (prod, t);
          }
        }

        if (blk == 0) continue;

        if (n >= blk) { n -= blk; continue; }

        th->buck[j] = ba;

        if (len == 2) th->buck[j + 1] = bm;

        th->tba[ti] = ba;
        th->tbm[ti] = bm;
        th->te[ti]  = 0;

        if ((devmode == false) && (dev == true) && (n < dblk))
        {
          devmode = true;

          th->devstart = j;
        }

        th->tdev[ti] = devmode;

        if (devmode == true)
        {
          fcap = fcap_behind (fcap, bl);
          bcap = bcap - bl;

          th->idx[j] = ta->b_start[ba];

          if (len == 2) th->idx[j + 1] = tm->b_start[bm];
        }
        else
        {
          if (dev == true) n -= dblk;

          fcap = (dev == true) ? (pg->kbits - bl) : PCFG_NOFCAP;

          const u64 w = (dev == true) ? (t - room) : t;

          const u64 e = n / w;

          n = n % w;

          const u32 mcnt = (len == 2) ? tm->b_cnt[bm] : 1;

          th->te[ti] = e;

          th->idx[j] = ta->b_start[ba] + (u32) (e / mcnt);

          if (len == 2) th->idx[j + 1] = tm->b_start[bm] + (u32) (e % mcnt);
        }

        r = r - cb;

        placed = true;

        break;
      }
    }

    if (placed == false) return false;

    j = nxt;
  }

  th->si    = si;
  th->cost  = c;
  th->valid = true;

  return true;
}

// The inverse of unrank_unit () the way pcfg_rank () is the inverse of unrank (): hand it a structure
// and the entry each of its slots picked, and it hands back the unit that holds that candidate, which
// is the number the device engine counts -s in. It walks the same tokens in the same order as
// unrank_unit () (4724-4855) and simply adds up what unrank_unit () would have stepped over.
//
// The map is many to one, and where it folds is not s->cut. cut is only the first slot a cell is
// allowed to reach (may, 4745). What is actually folded is the tail from devstart on, and
// unrank_unit () opens devmode at the first token whose whole remaining tail is one cell: every token
// from there on has to be allowed (j >= s->cut), has to sit in buckets that are uniform in length
// (bucket_uni (), 4761-4763), and the bit lengths of their bucket products have to sum to no more
// than pg->kbits (dev, 4767, bcap counting down at 4823). At that token unrank_unit () takes the
// n < dblk branch (4811) and keeps only the bucket, writing th->idx[j] = ta->b_start[ba] (4825-4827).
// unit_emit () then hands the kernel exactly those buckets, one cell slot per structure slot from
// devstart on, with radix b_cnt[buck[j]] and pool_off at the bucket start (4992, 5006-5013), so the
// kernel enumerates the full cross product of the tail buckets and nothing else. So the slots below
// devstart select the unit, and the entry offset inside the bucket at and above devstart is absorbed
// by the cell. build_unit_suffix () counts it the same way: a bucket that may fold contributes
// room + prod * (t - room) (4476), room being the tail choices that are one cell and the prod copies
// going only to the (t - room) tail choices that are not.
//
// So devstart is found by walking the tokens backwards before ranking and taking the earliest token
// whose tail still fits, which is what "the first token where n < dblk" comes to once the tail is
// already fixed. Earliest and not any later one: a tail that also fits under the previous token's
// budget was counted in that token's room block instead, and taken_in_front () (4654) subtracts it
// here so it is not counted twice. That same argument says our own tail is never one of the ones
// taken_in_front () removes, at any depth, so mirroring the arithmetic is enough.
//
// Mask slots are not slots of their own on this side. build_unit_suffix () skips them as loop heads
// (4424) and folds them into the alpha slot in front of them through tm (4429-4430), which is what
// token_len () (4350) says, so this walks tokens and never raw slots. Their cost and their bucket
// count still count, through cb and prod. The cost pass below is the only place slots are read one by
// one, and it is the same sum pcfg_rank () makes (3495-3505).
//
// The seat search is written out rather than calling level_seat () (3438): that one reads ls_struct,
// the candidate side table, which carries the OMEN levels and filters on s->suf. The unit side has
// its own uls_struct, structures only, filtered on s->usuf (4623-4643). The level search does carry
// over, because build_unit_index () copies lvl_cost into ulvl_cost one for one (4592, 4604).

static bool pcfg_rank_unit (const pcfg_global_t *pg, const u32 si, const u32 *idx, u64 *out_unit)
{
  if (si >= pg->structs_cnt) return false;

  if (pg->ulvl_cnt == 0) return false;

  if (pg->built == false) return false;

  const pcfg_struct_t *s = &pg->structs[si];

  if (s->usuf == NULL) return false;
  if (s->udev == NULL) return false;

  // The bucket every slot picked, the cost that makes, and where the tokens start.

  u32 buck[PCFG_MAXSLOT];
  u32 tok[PCFG_MAXSLOT];

  u64 c = s->cost;

  for (u32 j = 0; j < s->nslot; j++)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];

    if (idx[j] >= t->cnt) return false;

    buck[j] = tlist_bucket_of (t, idx[j]);

    c += t->b_cost[buck[j]];
  }

  u32 ntok = 0;

  for (u32 j = 0; j < s->nslot; j += token_len (s, j))
  {
    tok[ntok] = j;

    ntok++;
  }

  if (c > pg->costmax) return false;

  const int li = level_of (pg, (u32) c);

  if (li == -1) return false;

  if (pg->uls_cnt[li] == 0) return false;

  const u32 *ss = pg->uls_struct[li];

  u32 lo = 0;
  u32 hi = pg->uls_cnt[li] - 1;

  while (lo < hi)
  {
    const u32 mid = (lo + hi + 1) / 2;

    if (ss[mid] <= si) lo = mid; else hi = mid - 1;
  }

  if (ss[lo] != si) return false;

  u64 n = sat_add (pg->ulvl_pref[li], pg->uls_pref[li][lo]);

  // Where the cell begins. Walk the tokens back to front while the tail is still one cell, and stop
  // at the first token that breaks it, because no token in front of that one can start a cell either.

  u32 devstart = s->nslot;

  {
    u32 bsum = 0;

    for (int ti = (int) ntok - 1; ti >= 0; ti--)
    {
      const u32 j   = tok[ti];
      const u32 len = token_len (s, j);

      if (j < s->cut) break;

      const pcfg_tlist_t *ta = &pg->lists[s->list[j]];
      const pcfg_tlist_t *tm = (len == 2) ? &pg->lists[s->list[j + 1]] : NULL;

      bool uni = bucket_uni (pg, ta, buck[j]);

      if (len == 2) uni = uni && bucket_uni (pg, tm, buck[j + 1]);

      if (uni == false) break;

      const u64 prod = sat_mul (ta->b_cnt[buck[j]], (len == 2) ? tm->b_cnt[buck[j + 1]] : 1);

      const u32 bl = bitlen (prod);

      if ((bsum + bl) > pg->kbits) break;

      bsum += bl;

      devstart = j;
    }
  }

  const u32 span = pg->costmax - s->cost + 1;
  const u32 nb   = pg->kbits + 1;

  u32 r = (u32) c - s->cost;

  bool devmode = false;

  u32 bcap = pg->kbits;
  u32 fcap = PCFG_NOFCAP;

  u32 j = 0;

  while (j < s->nslot)
  {
    const u32 len = token_len (s, j);
    const u32 nxt = j + len;

    const pcfg_tlist_t *ta = &pg->lists[s->list[j]];
    const pcfg_tlist_t *tm = (len == 2) ? &pg->lists[s->list[j + 1]] : NULL;

    const u64 *tsrc = s->usuf + (size_t) nxt * span;
    const u64 *dsrc = s->udev + (size_t) nxt * span * nb;

    const bool may = (j >= s->cut);

    const u32 hita = buck[j];
    const u32 hitm = (len == 2) ? buck[j + 1] : 0;

    bool placed = false;

    for (u32 ba = 0; ba < ta->nb && placed == false; ba++)
    {
      const u32 nbm = (len == 2) ? tm->nb : 1;

      for (u32 bm = 0; bm < nbm; bm++)
      {
        const bool self = (ba == hita) && (bm == hitm);

        const u32 cb = ta->b_cost[ba] + ((len == 2) ? tm->b_cost[bm] : 0);

        if (cb > r)
        {
          if (self == true) return false;

          continue;
        }

        const u64 prod = sat_mul (ta->b_cnt[ba], (len == 2) ? tm->b_cnt[bm] : 1);

        bool uni = bucket_uni (pg, ta, ba);

        if (len == 2) uni = uni && bucket_uni (pg, tm, bm);

        const u32 bl = bitlen (prod);

        const bool dev = (may == true) && (uni == true) && (bl <= bcap);

        const u64 t = tsrc[r - cb];

        u64 blk  = 0;
        u64 room = 0;
        u64 dblk = 0;

        if (devmode == true)
        {
          if (dev == false)
          {
            if (self == true) return false;

            continue;
          }

          room = dsrc[(size_t) (r - cb) * nb + (bcap - bl)];

          blk = room - taken_in_front (dsrc, nb, r - cb, fcap, bl);
        }
        else
        {
          if (dev == true)
          {
            room = dsrc[(size_t) (r - cb) * nb + (pg->kbits - bl)];

            dblk = room - taken_in_front (dsrc, nb, r - cb, fcap, bl);

            blk = sat_add (dblk, sat_mul (prod, t - room));
          }
          else
          {
            blk = sat_mul (prod, t);
          }
        }

        if (blk == 0)
        {
          if (self == true) return false;

          continue;
        }

        if (self == false)
        {
          n = sat_add (n, blk);

          continue;
        }

        if ((devmode == false) && (j == devstart))
        {
          if (dev == false) return false;

          devmode = true;
        }

        if (devmode == true)
        {
          // The cell holds the whole bucket, so the entry this slot picked adds nothing here. What is
          // left of n is the rank of the tail inside the cell, and the tokens behind carry it.

          fcap = fcap_behind (fcap, bl);
          bcap = bcap - bl;
        }
        else
        {
          if (dev == true) n = sat_add (n, dblk);

          fcap = (dev == true) ? (pg->kbits - bl) : PCFG_NOFCAP;

          const u64 w = (dev == true) ? (t - room) : t;

          if (w == 0) return false;

          const u32 mcnt = (len == 2) ? tm->b_cnt[bm] : 1;

          const u64 e = ((u64) (idx[j] - ta->b_start[ba]) * mcnt) + ((len == 2) ? (u64) (idx[j + 1] - tm->b_start[bm]) : 0);

          n = sat_add (n, sat_mul (e, w));
        }

        r = r - cb;

        placed = true;

        break;
      }
    }

    if (placed == false) return false;

    j = nxt;
  }

  if (r != 0) return false;

  if (n >= pg->units) return false;

  *out_unit = n;

  return true;
}

static bool advance_unit (pcfg_global_t *pg, pcfg_thread_t *th)
{
  if (th->tcnt == 0) return false;

  const pcfg_struct_t *s = &pg->structs[th->si];

  const u32 ti = th->tcnt - 1;
  const u32 j  = th->tslot[ti];

  const u32 len = token_len (s, j);

  const pcfg_tlist_t *ta = &pg->lists[s->list[j]];
  const pcfg_tlist_t *tm = (len == 2) ? &pg->lists[s->list[j + 1]] : NULL;

  const u32 mcnt = (len == 2) ? tm->b_cnt[th->tbm[ti]] : 1;

  if (th->tdev[ti] == false)
  {
    const u64 prod = sat_mul (ta->b_cnt[th->tba[ti]], mcnt);

    if ((th->te[ti] + 1) < prod)
    {
      th->te[ti]++;

      const u64 e = th->te[ti];

      th->idx[j] = ta->b_start[th->tba[ti]] + (u32) (e / mcnt);

      if (len == 2) th->idx[j + 1] = tm->b_start[th->tbm[ti]] + (u32) (e % mcnt);

      return true;
    }

    return false;
  }

  const u32 rem  = th->trem[ti];
  const u32 cap  = th->tcap[ti];
  const u32 fcap = th->tfcap[ti];

  u32 ba = th->tba[ti];
  u32 bm = th->tbm[ti];

  for (;;)
  {
    if (len == 2)
    {
      bm++;

      if (bm >= tm->nb) { bm = 0; ba++; }
    }
    else
    {
      ba++;
    }

    if (ba >= ta->nb) return false;

    const u32 cb = ta->b_cost[ba] + ((len == 2) ? tm->b_cost[bm] : 0);

    if (cb != rem) continue;

    if (bucket_uni (pg, ta, ba) == false) return false;

    if (len == 2)
    {
      if (bucket_uni (pg, tm, bm) == false) return false;
    }

    const u64 prod = sat_mul (ta->b_cnt[ba], (len == 2) ? tm->b_cnt[bm] : 1);

    const u32 bl = bitlen (prod);

    if (bl > cap) return false;

    if ((fcap != PCFG_NOFCAP) && (bl <= fcap)) continue;

    th->tba[ti] = ba;
    th->tbm[ti] = bm;

    th->buck[j] = ba;

    if (len == 2) th->buck[j + 1] = bm;

    th->idx[j] = ta->b_start[ba];

    if (len == 2) th->idx[j + 1] = tm->b_start[bm];

    return true;
  }
}

static int unit_emit (pcfg_global_t *pg, pcfg_thread_t *th, u8 *out_buf, const int out_size, pcfg_cell_t *cell)
{
  if (th->pos >= pg->units) return GENERIC_RC_EOF;

  if (th->valid == false)
  {
    if (unrank_unit (pg, th->pos, th) == false) return GENERIC_RC_ERROR;
  }

  const int len = assemble (pg, th, out_buf, out_size);

  if (len < 0) return len;

  const pcfg_struct_t *s = &pg->structs[th->si];

  u32 off[PCFG_MAXSLOT];
  u32 wid[PCFG_MAXSLOT];

  slot_geometry (pg, s, th->idx, off, wid);

  cell->slot_cnt = s->nslot - th->devstart;

  cell->flags = (pg->varlen == true) ? PCFG_CELL_VARLEN : 0;

  u64 rect = 1;

  for (u32 j = th->devstart; j < s->nslot; j++)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];

    rect = sat_mul (rect, t->b_cnt[th->buck[j]]);
  }

  cell->rect = (rect < pg->il_cnt) ? (u32) rect : pg->il_cnt;

  u32 from = 0;

  for (u32 j = th->devstart; j < s->nslot; j++)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];

    const u32 b = th->buck[j];
    const u32 k = j - th->devstart;

    if (s->kind[j] != PCFG_SLOT_MASK) from = k;

    cell->slots[k].pool_off = (pg->varlen == true)
                            ? pg->ent_base[s->list[j]] + t->b_start[b]
                            : pg->pool_base[s->list[j]] + t->off[t->b_start[b]];

    cell->slots[k].radix    = t->b_cnt[b];
    cell->slots[k].packed   = (wid[j] & 0xff) | ((off[j] & 0xff) << 8) | (((s->kind[j] == PCFG_SLOT_MASK) ? PCFG_SLOT_KIND_CASE : PCFG_SLOT_KIND_BYTES) << 16) | ((from & 0xff) << 24);

    if (s->kind[j] == PCFG_SLOT_MASK)
    {
      const u32 aj = th->devstart + from;

      const pcfg_tlist_t *ta = &pg->lists[s->list[aj]];

      cell->slots[k].digit = (pg->varlen == true)
                           ? pg->pool_ubase[s->list[aj]] - pg->pool_base[s->list[aj]]
                           : pg->pool_ubase[s->list[aj]] + ta->off[ta->b_start[th->buck[aj]]];
    }
    else
    {
      cell->slots[k].digit = 0;
    }
  }

  th->pos++;

  th->valid = false;

  if (pg->walk == true)
  {
    if (advance_unit (pg, th) == true) th->valid = true;
  }

  return len;
}

static int plain_emit (pcfg_global_t *pg, pcfg_thread_t *th, u8 *out_buf, const int out_size)
{
  if (th->pos >= pg->keyspace) return GENERIC_RC_EOF;

  if (th->valid == false)
  {
    if (unrank (pg, th->pos, th) == false) return GENERIC_RC_EOF;
  }

  const int len = assemble (pg, th, out_buf, out_size);

  if (len < 0) return len;

  th->pos++;

  if (th->omen == true)
  {
    if (omen_next (pg, th) == false) th->valid = false;
  }
  else if (th->idx[th->inner] + 1 < th->inner_end)
  {
    th->idx[th->inner]++;
  }
  else
  {
    th->valid = false;
  }

  return len;
}

#define PCFG_PF_CHUNK   4096

#define PCFG_PF_SLOTS_DEF 16
#define PCFG_PF_SLOTS_MAX 256
#define PCFG_PF_MAXW    16

#define PCFG_PF_WORKERS_AUTO 0xffffffff

#define PCFG_PF_WORKERS_PLAIN 8

#define PCFG_PF_WLEN    256

#define PCFG_PF_EMPTY   0
#define PCFG_PF_FILLING 1
#define PCFG_PF_READY   2

typedef struct
{
  u8          *pool;
  u32         *off;
  int         *wlen;
  pcfg_cell_t *cell;

  u32 cnt;
  u64 seq;
  u32 gen;
  int state;

} pcfg_pf_slot_t;

typedef struct pcfg_pf
{
  pcfg_global_t *pg;

  pcfg_mux_t mux;
  pcfg_cv_t  cv;

  u64  assign;
  u64  take;
  u64  base;
  u32  gen;
  bool stop;

  pcfg_pf_slot_t slot[PCFG_PF_SLOTS_MAX];

  u32 slots;

  u32       nworker;
  pcfg_os_thread_t worker[PCFG_PF_MAXW];

  bool amp;

  int held;
  u32 held_at;

} pcfg_pf_t;

static pcfg_thread_ret pf_worker (void *arg)
{
  pcfg_pf_t *pf = (pcfg_pf_t *) arg;

  pcfg_global_t *pg  = pf->pg;
  const bool     amp = pf->amp;

  pcfg_thread_t *th = (pcfg_thread_t *) hccalloc (1, sizeof (pcfg_thread_t));

  pcfg_mux_lock (&pf->mux);

  while (pf->stop == false)
  {
    const u32 si = (u32) (pf->assign % pf->slots);

    pcfg_pf_slot_t *sl = &pf->slot[si];

    if (sl->state != PCFG_PF_EMPTY)
    {
      pcfg_cv_wait (&pf->cv, &pf->mux);

      continue;
    }

    const u64 seq = pf->assign++;
    const u32 gen = pf->gen;
    const u64 pos = pf->base + (seq * PCFG_PF_CHUNK);

    sl->state = PCFG_PF_FILLING;
    sl->seq   = seq;
    sl->gen   = gen;

    pcfg_mux_unlock (&pf->mux);

    th->pos   = pos;
    th->valid = false;

    u32 n    = 0;
    u32 used = 0;

    for (; n < PCFG_PF_CHUNK; n++)
    {

      if ((used + PCFG_PF_WLEN) > (PCFG_PF_CHUNK * PCFG_PF_WLEN)) break;

      u8 *at = sl->pool + used;

      sl->off[n] = used;

      const int len = (amp == true)
                    ? unit_emit  (pg, th, at, PCFG_PF_WLEN, &sl->cell[n])
                    : plain_emit (pg, th, at, PCFG_PF_WLEN);

      if (len < 0) { sl->wlen[n] = len; n++; break; }

      sl->wlen[n] = len;

      used += (len < PCFG_PF_WLEN) ? (u32) len : PCFG_PF_WLEN;
    }

    pcfg_mux_lock (&pf->mux);

    sl->cnt = n;

    sl->state = (sl->gen == pf->gen) ? PCFG_PF_READY : PCFG_PF_EMPTY;

    pcfg_cv_broadcast (&pf->cv);
  }

  pcfg_mux_unlock (&pf->mux);

  hcfree (th);

  return pcfg_thread_done;
}

static void pf_reset (pcfg_pf_t *pf, const u64 pos)
{
  pcfg_mux_lock (&pf->mux);

  if (pf->held >= 0)
  {
    pf->slot[pf->held].state = PCFG_PF_EMPTY;

    pf->held = -1;
  }

  for (u32 i = 0; i < pf->slots; i++)
  {
    if (pf->slot[i].state == PCFG_PF_READY) pf->slot[i].state = PCFG_PF_EMPTY;
  }

  pf->gen++;
  pf->base   = pos;
  pf->assign = 0;
  pf->take   = 0;

  pcfg_cv_broadcast (&pf->cv);
  pcfg_mux_unlock (&pf->mux);
}

static bool pcfg_pf_early (void)
{
  static int early = -1;

  if (early < 0)
  {
    const char *env = getenv ("PCFG_PF_EARLY");

    early = (env != NULL) ? atoi (env) : 1;
  }

  return (early != 0);
}

static pcfg_pf_t *pf_start (pcfg_global_t *pg, const u32 nworker, const bool amp)
{
  pcfg_pf_t *pf = (pcfg_pf_t *) hccalloc (1, sizeof (pcfg_pf_t));

  pf->pg   = pg;
  pf->held = -1;
  pf->amp  = amp;

  pf->slots = PCFG_PF_SLOTS_DEF;

  const char *slotsenv = getenv ("PCFG_PF_SLOTS");

  if (slotsenv != NULL) pf->slots = (u32) strtoul (slotsenv, NULL, 10);

  if (pf->slots < nworker + 1)     pf->slots = nworker + 1;
  if (pf->slots > PCFG_PF_SLOTS_MAX) pf->slots = PCFG_PF_SLOTS_MAX;

  pcfg_mux_init (&pf->mux);
  pcfg_cv_init  (&pf->cv);

  for (u32 i = 0; i < pf->slots; i++)
  {
    pf->slot[i].pool = (u8 *)  hcmalloc ((size_t) PCFG_PF_CHUNK * PCFG_PF_WLEN);
    pf->slot[i].off  = (u32 *) hcmalloc ((size_t) PCFG_PF_CHUNK * sizeof (u32));
    pf->slot[i].wlen = (int *) hcmalloc ((size_t) PCFG_PF_CHUNK * sizeof (int));

    pf->slot[i].cell = (amp == true) ? (pcfg_cell_t *) hcmalloc ((size_t) PCFG_PF_CHUNK * sizeof (pcfg_cell_t)) : NULL;
  }

  // Only the workers that really started are counted, because pf_stop () joins that many, and a
  // handle that was never handed out is not one to wait on.

  pf->nworker = 0;

  for (u32 i = 0; i < nworker; i++)
  {
    if (pcfg_thread_create (pf->worker[pf->nworker], pf_worker, pf) == false) continue;

    pf->nworker++;
  }

  return pf;
}

static void pf_stop (pcfg_pf_t *pf)
{
  pcfg_mux_lock (&pf->mux);

  pf->stop = true;

  pcfg_cv_broadcast (&pf->cv);
  pcfg_mux_unlock (&pf->mux);

  for (u32 i = 0; i < pf->nworker; i++) pcfg_thread_join (pf->worker[i]);

  for (u32 i = 0; i < pf->slots; i++)
  {
    hcfree (pf->slot[i].pool);
    hcfree (pf->slot[i].off);
    hcfree (pf->slot[i].wlen);
    hcfree (pf->slot[i].cell);
  }

  pcfg_mux_destroy (&pf->mux);
  pcfg_cv_destroy  (&pf->cv);

  hcfree (pf);
}

static int pf_next (pcfg_pf_t *pf, u8 *out_buf, const int out_size, pcfg_cell_t *cell, u64 *pos)
{
  if (pf->held < 0)
  {
    pcfg_mux_lock (&pf->mux);

    const u32 si = (u32) (pf->take % pf->slots);

    while ((pf->slot[si].state != PCFG_PF_READY) || (pf->slot[si].seq != pf->take))
    {
      pcfg_cv_wait (&pf->cv, &pf->mux);
    }

    pf->held    = (int) si;
    pf->held_at = 0;

    pcfg_mux_unlock (&pf->mux);
  }

  pcfg_pf_slot_t *sl = &pf->slot[pf->held];

  if (pf->held_at >= sl->cnt)
  {
    pcfg_mux_lock (&pf->mux);

    sl->state = PCFG_PF_EMPTY;

    pf->held = -1;
    pf->take++;

    pcfg_cv_broadcast (&pf->cv);
    pcfg_mux_unlock (&pf->mux);

    return pf_next (pf, out_buf, out_size, cell, pos);
  }

  const u32 at = pf->held_at++;

  if (pos != NULL) pos[0] = pf->base + (sl->seq * PCFG_PF_CHUNK) + at;

  const int len = sl->wlen[at];

  if (len < 0) return len;

  int cp = (len < out_size) ? len : out_size;

  if (cp > PCFG_PF_WLEN) cp = PCFG_PF_WLEN;

  memcpy (out_buf, sl->pool + sl->off[at], cp);

  if (cell != NULL) cell[0] = sl->cell[at];

  return len;
}

// How many ways one candidate is allowed to be spelled before the search stops looking for more. A
// password with several derivations is ordinary, "password" is both A8 and A4A4, but the ones past a
// handful are all deeper in the run than the ones already found and cannot change the answer.

#define PCFG_LOOKUP_MAXHIT 16

typedef struct
{
  bool found;
  bool ranked;
  bool omen;

  u32 si;
  u32 idx[PCFG_MAXSLOT];

  u32 oi;

  u32 cost;
  u64 pos;

  bool has_unit;
  u64  unit;

} pcfg_hit_t;

// The lowest position this grammar reaches a candidate at, over every structure that spells it and
// over the escape as well.
//
// Lowest and not first: a candidate the grammar spells twice is emitted twice, and the run finds it
// at the earlier of the two. The escape competes on the same terms, so a password a structure spells
// late and the trellis reaches early is reported where the run actually meets it.
//
// found without ranked is a real answer and not a failure: the grammar does spell it, and the cost
// of spelling it lands past the last level build_index () laid down.

static bool lookup_find (pcfg_global_t *pg, const u8 *pw, const u32 pwlen, pcfg_hit_t *hit)
{
  u32 si[PCFG_LOOKUP_MAXHIT];
  u32 idx[PCFG_LOOKUP_MAXHIT][PCFG_MAXSLOT];

  const u32 cnt = pcfg_parse (pg, pw, pwlen, si, idx, PCFG_LOOKUP_MAXHIT);

  for (u32 i = 0; i < cnt; i++)
  {
    u64 pos  = 0;
    u32 cost = 0;

    const bool ok = pcfg_rank (pg, si[i], idx[i], &pos, &cost);

    if (hit->found == false)
    {
      hit->found = true;
      hit->si    = si[i];
      hit->cost  = cost;

      memcpy (hit->idx, idx[i], sizeof (hit->idx));
    }

    if (ok == false) continue;

    if ((hit->ranked == false) || (pos < hit->pos))
    {
      hit->ranked = true;
      hit->omen   = false;
      hit->si     = si[i];
      hit->cost   = cost;
      hit->pos    = pos;

      memcpy (hit->idx, idx[i], sizeof (hit->idx));
    }
  }

  if (pg->omen_lvl_cnt > 0)
  {
    u32 oi   = 0;
    u64 oidx = 0;
    u64 opos = 0;

    if (pcfg_omen_lookup (pg, pw, pwlen, &oi, &oidx, &opos) == true)
    {
      hit->found = true;

      if ((hit->ranked == false) || (opos < hit->pos))
      {
        hit->ranked = true;
        hit->omen   = true;
        hit->oi     = oi;
        hit->cost   = pg->omen_lvl[oi].cost;
        hit->pos    = opos;
      }
    }
  }

  if ((hit->ranked == true) && (hit->omen == false) && (pg->ulvl_cnt > 0))
  {
    u64 unit = 0;

    if (pcfg_rank_unit (pg, hit->si, hit->idx, &unit) == true)
    {
      hit->has_unit = true;
      hit->unit     = unit;
    }
  }

  return hit->found;
}

static void lookup_struct_name (const pcfg_global_t *pg, const u32 si, char *out_buf, const size_t out_size)
{
  const pcfg_struct_t *s = &pg->structs[si];

  int at = 0;

  out_buf[0] = 0;

  for (u32 j = 0; j < s->nslot; j++)
  {
    if (s->kind[j] == PCFG_SLOT_MASK) continue;

    const pcfg_tlist_t *t = &pg->lists[s->list[j]];

    const int rc = snprintf (out_buf + at, out_size - (size_t) at, "%c%u", t->ty, t->ln);

    if (rc < 0) break;

    at += rc;

    if ((size_t) at >= out_size) break;
  }
}

// The derivation itself, one slot at a time, "A8=Password C8=ULLLLLLL D3=123". The mask slot is
// shown here and not in the name, because it is half of what the candidate is made of and leaving
// it out would make the parts fail to spell the whole.
//
// A terminal is printed as the bytes it holds. A grammar holds whatever its training data held, so
// a terminal is not always printable, and turning it into something that is would be showing the
// user a candidate the run does not produce.

static void lookup_slots (const pcfg_global_t *pg, const pcfg_hit_t *hit, char *out_buf, const size_t out_size)
{
  const pcfg_struct_t *s = &pg->structs[hit->si];

  int at = 0;

  out_buf[0] = 0;

  for (u32 j = 0; j < s->nslot; j++)
  {
    const pcfg_tlist_t *t = &pg->lists[s->list[j]];

    const u32 e   = hit->idx[j];
    const u32 off = t->off[e];
    const u32 len = t->off[e + 1] - off;

    const int rc = snprintf (out_buf + at, out_size - (size_t) at, "%s%c%u=%.*s", (at == 0) ? "" : " ", t->ty, t->ln, (int) len, (const char *) (t->buf + off));

    if (rc < 0) break;

    at += rc;

    if ((size_t) at >= out_size) break;
  }
}

// The answer to lookup=, and the whole of what this run does.
//
// It is printed whatever --quiet says. The question is the run, and a run that answers nothing has
// done nothing. --stdout sets quiet itself and is the natural way to ask when there is no hash to
// hand, so a quiet gate here would silence the common case.
//
// Every number below is about the run that was typed, which is the point of answering from in here.
// The engine decides whether -s counts candidates or base words, and it decides whether the OMEN
// escape is part of the attack at all, and the feed was told which engine it got before global_init
// () ran (generic_global_ctx_t::dev_enable, settled at src/generic.c:463).

static void lookup_report (generic_global_ctx_t *global_ctx, pcfg_global_t *pg)
{
  global_ctx->described = true;

  const bool dev = global_ctx->dev_enable;

  pmsg (pg, "lookup: '%s'", pg->lookup);

  // A candidate is bytes, and a grammar trained on real passwords derives words no shell can pass.
  // $HEX[...] is how the potfile and --show write such a word, and how -a 0 and -a 3 already take
  // one, so it is taken here as well. The line above echoes what was typed rather than what it
  // decodes to, so a hex string that is not the one meant is visible in the answer.
  //
  // The length is bounded here and not only in user_options.c, because lookup= is a setting a
  // command line can hand to the feed directly, and that route passes no option validation.

  const u8 *arg     = (const u8 *) pg->lookup;
  const u32 arg_len = (u32) strlen (pg->lookup);

  u8 cand[PW_MAX];

  u32 cand_len = 0;

  if (is_hexify (arg, arg_len) == true)
  {
    if (((arg_len - 6) / 2) > PW_MAX)
    {
      pmsg (pg, "lookup: that decodes to more than %d bytes, which is longer than any candidate", PW_MAX);

      return;
    }

    cand_len = (u32) exec_unhexify (arg, arg_len, cand, sizeof (cand));
  }
  else
  {
    if (arg_len > PW_MAX)
    {
      pmsg (pg, "lookup: that is longer than %d bytes, which is longer than any candidate", PW_MAX);

      return;
    }

    memcpy (cand, arg, arg_len);

    cand_len = arg_len;
  }

  pcfg_hit_t hit;

  memset (&hit, 0, sizeof (hit));

  const bool found = lookup_find (pg, cand, cand_len, &hit);

  if (found == false)
  {
    // Case 3, and the reason the setting exists. No structure spells this password, so the OMEN
    // escape is the only route left, and this run does not carry it. There is nothing here to
    // search either: a run that dropped the escape never built its tables, so what can be said is
    // that this attack does not contain the password, not where in it the password would be.

    if ((pg->m_lines > 0) && (pg->omen_lvl_cnt == 0))
    {
      pmsg (pg, "lookup: no structure in this grammar derives it, so the OMEN escape is the only route to it");

      if (dev == true)
      {
        pmsg (pg, "lookup: and this run drops the escape, because the device engine cannot walk a trellis");
        pmsg (pg, "lookup: so this attack never tries this password. no -s reaches it and no runtime finds it");
        pmsg (pg, "lookup: -S runs the same grammar on the host engine, which carries the escape. ask again with it for the offset");
      }
      else if (pg->omen_want == false)
      {
        pmsg (pg, "lookup: and this run drops the escape, because omen=0 was given");
        pmsg (pg, "lookup: so this attack never tries this password. ask again without omen=0 for the offset");
      }
      else
      {
        pmsg (pg, "lookup: and this run has no escape to carry, for the reason given above");
        pmsg (pg, "lookup: so this attack never tries this password");
      }

      return;
    }

    // Not derivable at all. Every structure was tried and so was the escape, where one is carried.

    pmsg (pg, "lookup: not derivable. nothing in this grammar produces it, at any cost and at any -s");
    pmsg (pg, "lookup: it needs a ruleset trained on its parts, named alongside this one to merge the two");

    return;
  }

  // Derivable, but the run stops short of it. The structure is in the grammar and the terminals are
  // in their lists, and the costs add up past the last level build_index () laid down.

  if (hit.ranked == false)
  {
    char name[PCFG_MAXTOK * 8];

    lookup_struct_name (pg, hit.si, name, sizeof (name));

    const u32 want = (u32) ((hit.cost + pg->scale - 1) / pg->scale);

    pmsg (pg, "lookup: structure %s derives it, at cost %u, and this run stops at costmax %" PRIu64, name, hit.cost, pg->costmax);
    pmsg (pg, "lookup: so it is past the end of the run, whatever -s and whatever the runtime");
    pmsg (pg, "lookup: costmax=%u reaches it, and every level below it as well, which is a much larger keyspace", want);

    return;
  }

  if (hit.omen == false)
  {
    char name[PCFG_MAXTOK * 8];
    char slots[HCBUFSIZ_TINY];

    lookup_struct_name (pg, hit.si, name, sizeof (name));

    lookup_slots (pg, &hit, slots, sizeof (slots));

    pmsg (pg, "lookup: derived by structure %s, at cost %u of costmax %" PRIu64, name, hit.cost, pg->costmax);
    pmsg (pg, "lookup: %s", slots);
  }
  else
  {
    // Case 2. No structure spells it, the escape does, and this run carries the escape.

    pmsg (pg, "lookup: no structure derives it, the OMEN escape does, at level %u and cost %u of costmax %" PRIu64,
      pg->omen_lvl[hit.oi].lvl, hit.cost, pg->costmax);
  }

  if (dev == true)
  {
    // The device engine counts -s in base words rather than candidates, so the number it is given
    // here is the unit that holds the candidate, and one cell of it is what -l 1 then runs.

    if (hit.has_unit == false)
    {
      pmsg (pg, "lookup: this run reaches it, but its base word could not be placed in the device index");

      return;
    }

    const double pct = (pg->units > 0) ? ((double) hit.unit * 100.0 / (double) pg->units) : 0.0;

    pmsg (pg, "lookup: base word %" PRIu64 " of %" PRIu64 ", %.4f%% into the run, which is candidate %" PRIu64 " of %" PRIu64,
      hit.unit, pg->units, pct, hit.pos, pg->keyspace);

    pmsg (pg, "lookup: this run reaches it at -s %" PRIu64 ", because the device engine counts -s in base words", hit.unit);
    pmsg (pg, "lookup: -s %" PRIu64 " -l 1 runs the one cell that holds it", hit.unit);

    return;
  }

  else
  {
    const double pct = (pg->keyspace > 0) ? ((double) hit.pos * 100.0 / (double) pg->keyspace) : 0.0;

    pmsg (pg, "lookup: candidate %" PRIu64 " of %" PRIu64 ", %.4f%% into the run", hit.pos, pg->keyspace, pct);

    pmsg (pg, "lookup: this run reaches it at -s %" PRIu64 ", because the host engine counts -s in candidates", hit.pos);
    pmsg (pg, "lookup: -s %" PRIu64 " -l 1 runs that one candidate and nothing else", hit.pos);
  }
}

bool global_init (generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  if (global_ctx->workc < 1)
  {
    gerr (global_ctx, "usage: %s [ruleset ..] [scale=1] [costmax=64] [weights=1:1]", "pcfg");

    return false;
  }

  pcfg_global_t *pg = (pcfg_global_t *) hccalloc (1, sizeof (pcfg_global_t));

  global_ctx->gbldata = pg;

  pg->hcctx = hashcat_ctx;

  u64 scale   = 1;
  u64 costmax = PCFG_COSTCAP;
  u64 kbits   = PCFG_DEV_KBITS_DEF;
  u64 threads = PCFG_PF_WORKERS_AUTO;
  u64 walk    = 1;

  u64 omen = 1;

  u64    maxword = 0;
  double maxgain = 1.5;

  const char *weights = NULL;
  const char *lookup  = NULL;

  const feed_param_t params[] =
  {
    { "scale",   FEED_PARAM_TYPE_U64, &scale,   1, 64, "quantisation steps per bit" },
    { "costmax", FEED_PARAM_TYPE_U64, &costmax, 1, 64, "highest cost level to enumerate" },
    { "kbits",   FEED_PARAM_TYPE_U64, &kbits,   0, PCFG_DEV_KBITS_MAX, "bits of inner loop one cell may span, 0 to pick from the ruleset" },
    { "threads", FEED_PARAM_TYPE_U64, &threads, 0, PCFG_PF_MAXW, "cores that generate base words, 0 to generate inline, unset to pick from the rectangle" },
    { "walk",    FEED_PARAM_TYPE_U64, &walk,    0, 1, "step the last token instead of unranking it where the ordering allows" },
    { "omen",    FEED_PARAM_TYPE_U64, &omen,    0, 1, "carry the OMEN escape where the attack allows, which is every hash the device engine is off for" },
    { "maxword", FEED_PARAM_TYPE_U64, &maxword, 0, PCFG_DEV_MAXWORD_HI, "words the kernel gives a candidate, 0 to pick from the ruleset" },
    { "maxgain", FEED_PARAM_TYPE_DBL, &maxgain, 1.0, 64.0, "how much wider the rectangle must get before the larger array is taken" },
    { "weights", FEED_PARAM_TYPE_STR, &weights, 0, 0, "share of the grammar each ruleset carries, colon separated, one per ruleset" },
    { "lookup",  FEED_PARAM_TYPE_STR, &lookup,  0, 0, "ask where this attack reaches a candidate instead of running it" },
    { NULL, 0, NULL, 0, 0, NULL }
  };

  if (feed_param_parse (global_ctx->workc, global_ctx->workv, params, global_ctx->error_msg, sizeof (global_ctx->error_msg)) == false)
  {
    global_ctx->error = true;

    return false;
  }

  if ((maxword != 0) && ((maxword % 16) != 0))
  {
    gerr (global_ctx, "maxword must be a multiple of 16, which is one hash block");

    return false;
  }

  pg->scale   = scale;
  pg->costmax = costmax * scale;
  pg->kbits   = (u32) kbits;
  pg->threads = (u32) threads;
  pg->maxword = (u32) maxword;
  pg->maxgain = maxgain;
  pg->walk    = (walk != 0);
  pg->omen_want = (omen != 0);
  pg->lookup    = lookup;

  pcfg_root_t roots[PCFG_MAXROOT];

  u32 nroots = 0;

  for (int i = 1; i < global_ctx->workc; i++)
  {
    if (feed_param_is_setting (global_ctx->workv[i]) == true) continue;

    if (nroots == PCFG_MAXROOT)
    {
      gerr (global_ctx, "at most %u rulesets", PCFG_MAXROOT);

      return false;
    }

    bool by_name = false;

    roots[nroots].dir   = pcfg_resolve_root (global_ctx, global_ctx->workv[i], &by_name);
    roots[nroots].given = global_ctx->workv[i];
    roots[nroots].own   = true;
    roots[nroots].arc = NULL;
    roots[nroots].w   = 1.0;

    if ((by_name == true) && (global_ctx->quiet == false))
    {
      pmsg (pg, "pcfg: %s is %s", roots[nroots].given, roots[nroots].dir);
    }

    nroots++;
  }

  if (nroots == 0)
  {
    for (u32 i = 0; i < PCFG_DEFAULT_ROOTS; i++)
    {
      bool by_name = false;

      roots[nroots].dir   = pcfg_resolve_root (global_ctx, PCFG_DEFAULT_ROOT[i], &by_name);
      roots[nroots].given = PCFG_DEFAULT_ROOT[i];
      roots[nroots].own   = true;
      roots[nroots].arc   = NULL;
      roots[nroots].w     = 1.0;

      nroots++;

      if (by_name == true) continue;

      gerr (global_ctx, "%s: hashcat's own ruleset is not installed, so there is nothing to run without naming one. it belongs in %s/pcfg", PCFG_DEFAULT_ROOT[i], global_ctx->shared_dir);

      roots_free (roots, nroots);

      return false;
    }

    if (global_ctx->quiet == false)
    {
      pmsg (pg, "pcfg: no ruleset named, running hashcat's own %s", PCFG_DEFAULT_ROOT[0]);
    }
  }

  if (root_weights (global_ctx, roots, nroots, weights) == false)
  {
    roots_free (roots, nroots);

    return false;
  }

  for (u32 i = 0; i < nroots; i++)
  {
    if (hc_path_is_directory (roots[i].dir) == true) continue;

    if (hc_path_exist (roots[i].dir) == false)
    {
      if (pcfg_has_sep (roots[i].given) == true)
      {
        gerr (global_ctx, "%s: no such ruleset", roots[i].given);
      }
      else if (strcmp (global_ctx->profile_dir, global_ctx->shared_dir) == 0)
      {
        gerr (global_ctx, "%s: no such ruleset. a name is looked for in %s/pcfg, and anything holding a slash is taken as a path", roots[i].given, global_ctx->shared_dir);
      }
      else
      {
        gerr (global_ctx, "%s: no such ruleset. a name is looked for in %s/pcfg and then %s/pcfg, and anything holding a slash is taken as a path", roots[i].given, global_ctx->profile_dir, global_ctx->shared_dir);
      }

      roots_free (roots, nroots);

      return false;
    }

    roots[i].arc = arc_load (roots[i].dir);

    if (roots[i].arc == NULL)
    {
      gerr (global_ctx, "%s: not a ruleset directory and not a readable ruleset archive", roots[i].dir);

      roots_free (roots, nroots);

      return false;
    }

    if (global_ctx->quiet == false)
    {
      pmsg (pg, "pcfg: %s, %u files in one archive", roots[i].dir, roots[i].arc->ent_cnt);
    }
  }

  if ((global_ctx->quiet == false) && (nroots > 1))
  {
    char line[HCBUFSIZ_TINY];

    int at = snprintf (line, sizeof (line), "pcfg: merging %u rulesets:", nroots);

    for (u32 i = 0; i < nroots; i++)
    {
      if (at < 0) break;
      if ((size_t) at >= sizeof (line)) break;

      at += snprintf (line + at, sizeof (line) - (size_t) at, " %s (%.3f)", roots[i].dir, roots[i].w);
    }

    pmsg (pg, "%s", line);
  }

  if (grammar_load (global_ctx, pg, roots, nroots) == -1)
  {
    roots_free (roots, nroots);

    return false;
  }

  if (global_ctx->quiet == false)
  {
    if (global_ctx->dev_enable == true)
    {
      pmsg (pg, "pcfg: device engine, one base word becomes many candidates inside the hash kernel");
    }
    else
    {
      pmsg (pg, "pcfg: host engine, every candidate is built here and copied over");
    }
  }

  if (omen_load (global_ctx, pg, roots, nroots) == false)
  {
    roots_free (roots, nroots);

    return false;
  }

  build_index (pg);

  // lookup= is answered here and not earlier, because it reads the grammar grammar_load () parsed,
  // the terminal lists list_get () pulled in behind it, the suffix counts build_suffix () left, the
  // OMEN tables omen_load () built and the level index build_index () has just finished. This is the
  // first point at which all five exist.

  if ((pg->lookup != NULL) && (global_ctx->dev_enable == false)) lookup_report (global_ctx, pg);

  if ((global_ctx->dev_enable == false) && (pg->threads == PCFG_PF_WORKERS_AUTO))
  {
    const int cpus = hc_get_processor_count ();

    u32 want = PCFG_PF_WORKERS_PLAIN;

    if ((cpus > 1) && ((u32) cpus < (want * 2))) want = (u32) (cpus / 2);
    if (want < 1) want = 1;

    pg->threads = want;
  }

  const char *half = "host";

  if (global_ctx->dev_enable  == true) half = "device";
  else if (pg->omen_lvl_cnt   >  0)    half = "host, OMEN";

  char named[192];

  roots_join (named, sizeof (named), roots, nroots);

  snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s (scale %" PRIu64 ", %s)", named, scale, half);

  roots_free (roots, nroots);

  global_ctx->source_ident = pg->keyspace ^ ((u64) pg->structs_cnt << 32) ^ (scale * 1099511628211ULL) ^ (kbits * 14695981039346656037ULL);

  if (nroots > 1)
  {
    global_ctx->source_ident ^= (u64) nroots * 0x9e3779b97f4a7c15ULL;

    for (u32 i = 0; i < nroots; i++)
    {
      u64 bits = 0;

      memcpy (&bits, &roots[i].w, sizeof (bits));

      global_ctx->source_ident ^= (bits + i) * 0x9e3779b97f4a7c15ULL;
    }
  }

  return true;
}

void global_term (generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  pcfg_global_t *pg = (pcfg_global_t *) global_ctx->gbldata;

  if (pg == NULL) return;

  for (u32 i = 0; i < pg->lists_cnt; i++)
  {
    hcfree (pg->lists[i].off);
    hcfree (pg->lists[i].buf);
    hcfree (pg->lists[i].ubuf);
    hcfree (pg->lists[i].b_cost);
    hcfree (pg->lists[i].b_start);
    hcfree (pg->lists[i].b_cnt);
    hcfree (pg->lists[i].b_len);
  }

  hcfree (pg->lists);

  for (u32 i = 0; i < pg->structs_cnt; i++) hcfree (pg->structs[i].suf);
  for (u32 i = 0; i < pg->structs_cnt; i++) hcfree (pg->structs[i].usuf);
  for (u32 i = 0; i < pg->structs_cnt; i++) hcfree (pg->structs[i].udev);

  for (u32 i = 0; i < pg->ulvl_cnt; i++)
  {
    hcfree (pg->uls_struct[i]);
    hcfree (pg->uls_pref[i]);
  }

  hcfree (pg->uls_struct);
  hcfree (pg->uls_pref);
  hcfree (pg->uls_cnt);
  hcfree (pg->ulvl_cost);
  hcfree (pg->ulvl_pref);
  hcfree (pg->pool);
  hcfree (pg->pool_base);
  hcfree (pg->pool_ubase);
  hcfree (pg->ent_base);

  for (u32 i = 0; i < pg->omen_cnt; i++) omen_free (&pg->omen[i]);

  hcfree (pg->omen);
  hcfree (pg->omen_lvl);

  hcfree (pg->structs);

  for (u32 i = 0; i < pg->lvl_cnt; i++)
  {
    hcfree (pg->ls_struct[i]);
    hcfree (pg->ls_pref[i]);
  }

  hcfree (pg->ls_struct);
  hcfree (pg->ls_pref);
  hcfree (pg->ls_cnt);
  hcfree (pg->lvl_cost);
  hcfree (pg->lvl_pref);

  hcfree (pg);

  global_ctx->gbldata = NULL;
}

u64 global_keyspace (generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  const pcfg_global_t *pg = (const pcfg_global_t *) global_ctx->gbldata;

  if (pg->keyspace >= UINT64_MAX - 1) return UINT64_MAX - 2;

  if (pg->units > 0) return pg->units;

  return pg->keyspace;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  pcfg_thread_t *th = (pcfg_thread_t *) hccalloc (1, sizeof (pcfg_thread_t));

  th->pos   = 0;
  th->valid = false;

  thread_ctx->thrdata = th;

  pcfg_global_t *pg = (pcfg_global_t *) global_ctx->gbldata;

  if (pg == NULL) return true;

  const bool amp = global_ctx->dev_enable;

  if (pg->threads == 0) return true;
  if (pg->threads == PCFG_PF_WORKERS_AUTO) return true;

  if ((amp == true) && (pcfg_pf_early () == false)) return true;

  th->pf = pf_start (pg, pg->threads, amp);

  pf_reset (th->pf, th->pos);

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  pcfg_thread_t *th = (pcfg_thread_t *) thread_ctx->thrdata;

  if (th != NULL)
  {
    if (th->pf != NULL) pf_stop (th->pf);
  }

  hcfree (thread_ctx->thrdata);

  thread_ctx->thrdata = NULL;
}

int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  pcfg_global_t *pg = (pcfg_global_t *) global_ctx->gbldata;
  pcfg_thread_t *th = (pcfg_thread_t *) thread_ctx->thrdata;

  if ((th->pf == NULL) || (th->pf->amp == true)) return plain_emit (pg, th, out_buf, out_size);

  u64 pos = 0;

  const int len = pf_next (th->pf, out_buf, out_size, NULL, &pos);

  if (len <= PCFG_PF_WLEN)   return len;
  if (out_size <= PCFG_PF_WLEN) return len;

  if (unrank (pg, pos, th) == false) return GENERIC_RC_EOF;

  const int full = assemble (pg, th, out_buf, out_size);

  th->valid = false;

  return full;
}

bool global_dev_init (generic_global_ctx_t *global_ctx, const u32 **pool, u64 *pool_size, u32 *il_cnt, u32 *avg, u32 *maxword, u32 *front, u32 *step, u32 *varlen, pcfg_cell_t *probe)
{
  pcfg_global_t *pg = (pcfg_global_t *) global_ctx->gbldata;

  pg->il_cnt = (u32) 1 << pg->kbits;

  pg->pool_base  = (u32 *) hcmalloc (pg->lists_cnt * sizeof (u32));
  pg->pool_ubase = (u32 *) hccalloc (pg->lists_cnt, sizeof (u32));

  u64 need = 4;

  for (u32 i = 0; i < pg->lists_cnt; i++)
  {
    const pcfg_tlist_t *t = &pg->lists[i];

    pg->pool_base[i] = (u32) need;

    need += t->off[t->cnt];

    need = (need + 3) & ~((u64) 3);

    if (t->ubuf == NULL) continue;

    pg->pool_ubase[i] = (u32) need;

    need += t->off[t->cnt];

    need = (need + 3) & ~((u64) 3);
  }

  if (need == 4)
  {
    gerr (global_ctx, "no terminals, nothing to amplify");

    return false;
  }

  pg->ent_base = (u32 *) hccalloc (pg->lists_cnt, sizeof (u32));

  u64 ent_at = 0;

  if (pg->varlen == true)
  {
    ent_at = need;

    for (u32 i = 0; i < pg->lists_cnt; i++)
    {
      pg->ent_base[i] = (u32) (need / 4);

      need += ((u64) pg->lists[i].cnt + 1) * 4;
    }
  }

  pg->pool_size = need + 8;
  pg->pool      = (u32 *) hccalloc (pg->pool_size / 4, sizeof (u32));

  u8 *bytes = (u8 *) pg->pool;

  for (u32 i = 0; i < pg->lists_cnt; i++)
  {
    const pcfg_tlist_t *t = &pg->lists[i];

    memcpy (bytes + pg->pool_base[i], t->buf, t->off[t->cnt]);

    if (t->ubuf == NULL) continue;

    memcpy (bytes + pg->pool_ubase[i], t->ubuf, t->off[t->cnt]);
  }

  if (pg->varlen == true)
  {
    for (u32 i = 0; i < pg->lists_cnt; i++)
    {
      const pcfg_tlist_t *t = &pg->lists[i];

      u32 *tab = pg->pool + pg->ent_base[i];

      for (u32 n = 0; n <= t->cnt; n++) tab[n] = pg->pool_base[i] + t->off[n];
    }

    if (global_ctx->quiet == false)
    {
      pmsg (pg, "pcfg: per entry offsets, %" PRIu64 " KiB of table behind %" PRIu64 " KiB of terminals",
        (pg->pool_size - 8 - ent_at) / 1024, ent_at / 1024);
    }
  }

  const bool auto_maxword = (pg->maxword == 0);
  const bool auto_kbits   = (pg->kbits == 0);

  if (auto_maxword == true)
  {

    const u32 probe = (auto_kbits == false) ? pg->kbits : PCFG_DEV_KBITS_PROBE;

    const u64 lo = cut_and_count (pg, PCFG_DEV_MAXWORD_LO, probe);
    const u64 hi = cut_and_count (pg, PCFG_DEV_MAXWORD_HI, probe);

    const double gain = (hi > 0) ? ((double) lo / (double) hi) : 1.0;

    pg->maxword = (gain >= pg->maxgain) ? PCFG_DEV_MAXWORD_HI : PCFG_DEV_MAXWORD_LO;

    if (global_ctx->quiet == false)
    {
      pmsg (pg, "pcfg: candidate bound %u bytes, %u word array (rectangle gain %.2fx at %u words, taken at %.2fx)",
        (pg->maxword * 4) - 1, pg->maxword, gain, PCFG_DEV_MAXWORD_HI, pg->maxgain);
    }
  }

  pg->maxbyte = (pg->maxword * 4) - 1;

  if (auto_kbits == true)
  {

    const bool trace = (getenv ("PCFG_KBITS_TRACE") != NULL);

    u32 best = PCFG_DEV_KBITS_MAX;

    if (trace == true)
    {
      for (u32 k = PCFG_DEV_KBITS_MIN; k <= PCFG_DEV_KBITS_MAX; k++)
      {
        cut_and_count (pg, pg->maxword, k);

        fprintf (stderr, "kbits=%u front_rect=%" PRIu64 "\n", k, pg->front_rect);
      }
    }

    // The rectangle only grows with the bit count, so the widest setting decides whether there is
    // anything to search for. A large ruleset spreads the front of the run across many cheap
    // structures and never reaches the width that is wanted, and then the answer is the widest
    // setting and one measurement has just found it. That is also the ruleset where a measurement
    // costs the most, so the case that used to be the slowest is now the cheapest.

    cut_and_count (pg, pg->maxword, PCFG_DEV_KBITS_MAX);

    if (pg->front_rect >= PCFG_DEV_RECT_WANT)
    {
      u32 lo = PCFG_DEV_KBITS_MIN;
      u32 hi = PCFG_DEV_KBITS_MAX;

      while (lo < hi)
      {
        const u32 mid = lo + ((hi - lo) / 2);

        cut_and_count (pg, pg->maxword, mid);

        if (pg->front_rect >= PCFG_DEV_RECT_WANT) hi = mid;
        else                                      lo = mid + 1;
      }

      best = lo;
    }

    pg->kbits = best;

    if (global_ctx->quiet == false)
    {
      cut_and_count (pg, pg->maxword, pg->kbits);

      pmsg (pg, "pcfg: inner loop %u bits, %u candidates to a cell at the front of the run", pg->kbits, (u32) pg->front_rect);
    }
  }

  pg->il_cnt = (u32) 1 << pg->kbits;

  global_ctx->source_ident ^= (u64) pg->maxword * 0x9e3779b97f4a7c15ULL;

  if (pg->varlen == true) global_ctx->source_ident ^= 0x5ecf6a1d3b2c9e77ULL;

  unit_suffix_build (pg);

  if (getenv ("PCFG_BUCKET_STATS") != NULL)
  {
    u64 ents = 0;
    u64 bucks = 0;
    u64 sqsum = 0;
    u32 widest = 0;

    for (u32 i = 0; i < pg->lists_cnt; i++)
    {
      const pcfg_tlist_t *t = &pg->lists[i];

      ents  += t->cnt;
      bucks += t->nb;

      for (u32 b = 0; b < t->nb; b++)
      {
        sqsum += (u64) t->b_cnt[b] * (u64) t->b_cnt[b];

        if (t->b_cnt[b] > widest) widest = t->b_cnt[b];
      }
    }

    fprintf (stderr, "bucket stats: lists=%u entries=%" PRIu64 " buckets=%" PRIu64 " mean=%.2f entry_weighted_mean=%.2f widest=%u\n",
      pg->lists_cnt, ents, bucks, (bucks > 0) ? (double) ents / (double) bucks : 0.0, (ents > 0) ? (double) sqsum / (double) ents : 0.0, widest);

  }

  if (getenv ("PCFG_CUT_STATS") != NULL)
  {
    u32 none = 0, some = 0, blen = 0, wide = 0;

    for (u32 i = 0; i < pg->structs_cnt; i++)
    {
      const pcfg_struct_t *cs = &pg->structs[i];

      if (cs->cut == cs->nslot) none++; else some++;

      u32 nc = cs->nslot - 1;
      if (cs->kind[nc] == PCFG_SLOT_MASK && nc > 0) nc--;
      bool bad = false; u64 g = 1;
      for (u32 j = nc; j < cs->nslot; j++)
      {
        const pcfg_tlist_t *t = &pg->lists[cs->list[j]];
        u32 w = 0;
        for (u32 b = 0; b < t->nb; b++) { if (bucket_uni (pg, t, b) == false) bad = true; if (t->b_cnt[b] > w) w = t->b_cnt[b]; }
        g *= w;
      }
      if (cs->cut == cs->nslot) { if (bad) blen++; else if (g > pg->il_cnt) wide++; }
    }

    fprintf (stderr, "cut stats: structs=%u amplified=%u none=%u (blen_refused=%u too_wide=%u)\n", pg->structs_cnt, some, none, blen, wide);
  }

  build_unit_index (pg);

  if (pg->units == 0)
  {
    gerr (global_ctx, "device engine index is empty");

    return false;
  }

  // The device engine's half of lookup=, answered here rather than beside the host engine's. A base
  // word only has a number once build_unit_index () has laid the unit levels down, and the rectangle
  // those are counted against is not chosen until this function runs, so this is the earliest the
  // answer exists. It is also the last thing this run does, which is why the report reads last.

  if (pg->lookup != NULL) lookup_report (global_ctx, pg);

  pool[0]      = pg->pool;
  pool_size[0] = pg->pool_size;
  il_cnt[0]    = pg->il_cnt;
  maxword[0]   = pg->maxword;

  avg[0] = (u32) (pg->keyspace / pg->units);

  if (avg[0] == 0) avg[0] = 1;

  // The mean above is what a launch is sized with and it is an integer, so units times it is short of
  // the real number of candidates by whatever the division dropped. The real number is already known
  // here, so it is published rather than reconstructed.

  global_ctx->dev_total = pg->keyspace;

  if (pg->threads == PCFG_PF_WORKERS_AUTO) pg->threads = PCFG_PF_MAXW;

  const u64 probe_rect = front_rect (pg, PCFG_PROBE_UNITS);

  front[0] = (probe_rect > 0) ? (u32) probe_rect : avg[0];

  if (front[0] == 0) front[0] = 1;

  pcfg_thread_t *pth = (pcfg_thread_t *) hccalloc (1, sizeof (pcfg_thread_t));

  u64 seen = 0;
  u64 wide = 0;
  u64 dsum = 0;

  for (u64 u = 0; u < PCFG_STEP_UNITS; u++)
  {
    u8 bw[256];

    pcfg_cell_t cell;

    memset (&cell, 0, sizeof (cell));

    if (unit_emit (pg, pth, bw, sizeof (bw), &cell) < 0) break;

    if (cell.slot_cnt > 0)
    {
      const u32 last = (cell.slot_cnt < PCFG_DEV_MAXSLOT) ? (cell.slot_cnt - 1) : (PCFG_DEV_MAXSLOT - 1);

      wide += PCFG_SLOT_ENT_LEN (cell.slots[last].packed);
      dsum += PCFG_SLOT_DST_OFF (cell.slots[last].packed);
    }

    seen++;
  }

  hcfree (pth);

  step[0] = (seen > 0) ? (u32) (wide / seen) : 1;

  if (step[0] == 0) step[0] = 1;

  const u64 room = (pg->pool_size > 8) ? (pg->pool_size - 8) : 1;

  u64 wide_b = step[0];

  if (wide_b < 1)   wide_b = 1;
  if (wide_b > 255) wide_b = 255;

  u64 prect = (front[0] > 0) ? front[0] : 1;

  if (prect > pg->il_cnt) prect = pg->il_cnt;

  memset (probe, 0, sizeof (pcfg_cell_t));

  if (pg->varlen == false)
  {
    const u64 span = room / wide_b;

    if (prect > span) prect = (span > 0) ? span : 1;

    probe->slots[0].pool_off = 4;
    probe->slots[0].packed   = (u32) wide_b | (0 << 8) | (PCFG_SLOT_KIND_BYTES << 16);
  }
  else
  {
    u32 best_l = 0;
    u32 best_b = 0;
    u32 best_n = 0;

    for (u32 i = 0; i < pg->lists_cnt; i++)
    {
      const pcfg_tlist_t *t = &pg->lists[i];

      for (u32 b = 0; b < t->nb; b++)
      {
        if (t->b_cnt[b] <= best_n) continue;

        best_l = i;
        best_b = b;
        best_n = t->b_cnt[b];
      }
    }

    if (prect > best_n) prect = (best_n > 0) ? best_n : 1;

    probe->slots[0].pool_off = pg->ent_base[best_l] + pg->lists[best_l].b_start[best_b];
    probe->slots[0].packed   = (u32) wide_b | ((u32) (dsum / ((seen > 0) ? seen : 1)) << 8) | (PCFG_SLOT_KIND_BYTES << 16);
  }

  probe->slot_cnt       = 1;
  probe->rect           = (u32) prect;
  probe->slots[0].radix = (u32) prect;
  probe->flags          = (pg->varlen == true) ? PCFG_CELL_VARLEN : 0;

  varlen[0] = (pg->varlen == true) ? 1 : 0;

  if (getenv ("PCFG_BUCKET_STATS") != NULL)
  {
    fprintf (stderr, "probe cell: rect=%u radix=%u ent_len=%u dst_off=%u mean_step=%u mean_dst=%u\n",
      probe->rect, probe->slots[0].radix, PCFG_SLOT_ENT_LEN (probe->slots[0].packed), PCFG_SLOT_DST_OFF (probe->slots[0].packed),
      step[0], (seen > 0) ? (u32) (dsum / seen) : 0);
  }

  if (getenv ("PCFG_BUCKET_STATS") != NULL)
  {
    fprintf (stderr, "index stats: keyspace=%" PRIu64 " units=%" PRIu64 " kbits=%u candidates_a_unit=%.1f\n",
      pg->keyspace, pg->units, pg->kbits, (pg->units > 0) ? (double) pg->keyspace / (double) pg->units : 0.0);
  }

  const char *rectenv = getenv ("PCFG_RECT_STATS");

  if (rectenv != NULL)
  {
    const u64 want = strtoull (rectenv, NULL, 10);

    pcfg_thread_t *rp = (pcfg_thread_t *) hccalloc (1, sizeof (pcfg_thread_t));

    const char *cndenv = getenv ("PCFG_RECT_CANDS");

    const u64 wantc = (cndenv != NULL) ? strtoull (cndenv, NULL, 10) : 0;

    u64 cells = 0;
    u64 ones  = 0;
    u64 none  = 0;
    u64 rsum  = 0;
    u64 lsum  = 0;
    u64 rmax  = 0;

    u64 hist[33];

    memset (hist, 0, sizeof (hist));

    for (u64 u = 0; u < want; u++)
    {
      if ((wantc > 0) && (rsum >= wantc)) break;

      u8 bw[256];

      pcfg_cell_t cell;

      memset (&cell, 0, sizeof (cell));

      if (unit_emit (pg, rp, bw, sizeof (bw), &cell) < 0) break;

      const u64 rect = (cell.rect > 0) ? cell.rect : 1;

      cells++;

      if (rect == 1) ones++;

      if (cell.slot_cnt == 0) none++;

      rsum += rect;

      if (rect > rmax) rmax = rect;

      hist[bitlen (rect)]++;

      const u64 span  = (u64) PCFG_DEV_BLOCK * PCFG_DEV_WARP;
      const u64 asked = (rect + span - 1) / span;
      const u64 nwave = (asked < PCFG_DEV_FLOOR) ? PCFG_DEV_FLOOR : asked;

      lsum += nwave * PCFG_DEV_WARP;
    }

    hcfree (rp);

    fprintf (stderr, "rect stats: cells=%" PRIu64 " candidates=%" PRIu64 " rect_one=%.2f%% no_dev_slot=%.2f%% mean_rect=%.1f max_rect=%" PRIu64 " work_items_a_cell=%.1f candidates_a_work_item=%.3f\n",
      cells,
      rsum,
      (cells > 0) ? 100.0 * (double) ones / (double) cells : 0.0,
      (cells > 0) ? 100.0 * (double) none / (double) cells : 0.0,
      (cells > 0) ? (double) rsum / (double) cells : 0.0,
      rmax,
      (cells > 0) ? (double) lsum / (double) cells : 0.0,
      (lsum > 0) ? (double) rsum / (double) lsum : 0.0);

    for (u32 b = 0; b < 33; b++)
    {
      if (hist[b] == 0) continue;

      fprintf (stderr, "  rect 2^%-2u %10" PRIu64 "  %5.2f%%\n", b, hist[b], 100.0 * (double) hist[b] / (double) cells);
    }
  }

  if (global_ctx->quiet == false)
  {
    pmsg (pg, "pcfg: device engine il=%u, terminal pool %" PRIu64 " KiB, %" PRIu64 " base words for %" PRIu64 " candidates (x%.0f)",
      pg->il_cnt, pg->pool_size / 1024, pg->units, pg->keyspace, (double) pg->keyspace / (double) pg->units);
  }

  return true;
}

int thread_next_dev (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size, pcfg_cell_t *cell)
{
  pcfg_global_t *pg = (pcfg_global_t *) global_ctx->gbldata;
  pcfg_thread_t *th = (pcfg_thread_t *) thread_ctx->thrdata;

  if ((th->pf == NULL) && (pg->threads > 0) && (pg->threads != PCFG_PF_WORKERS_AUTO))
  {
    th->pf = pf_start (pg, pg->threads, true);

    pf_reset (th->pf, th->pos);
  }

  if ((th->pf != NULL) && (th->pf->amp == true)) return pf_next (th->pf, out_buf, out_size, cell, NULL);

  return unit_emit (pg, th, out_buf, out_size, cell);
}

bool thread_seek (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  pcfg_global_t *pg = (pcfg_global_t *) global_ctx->gbldata;
  pcfg_thread_t *th = (pcfg_thread_t *) thread_ctx->thrdata;

  th->pos   = offset;
  th->valid = false;

  if (th->pf != NULL)
  {
    pf_reset (th->pf, offset);

    return true;
  }

  if (pg->units > 0)
  {
    if (offset >= pg->units) return true;

    return unrank_unit (pg, offset, th);
  }

  if (offset >= pg->keyspace) return true;

  return unrank (pg, offset, th);
}

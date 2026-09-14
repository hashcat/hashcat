/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// rule_lookup: which word and which rule of an "-a 0 wordlist -r rules" attack produce a given
// candidate, and at which -s offset the attack reaches it.
//
// Build it with the makefile beside it, from the repository root:
//
//   make -f tools/rule_lookup.mk
//
// which is one compiler call:
//
//   gcc -std=gnu99 -O2 -Iinclude -IOpenCL -Ideps/OpenCL-Headers
//       tools/rule_lookup.c src/rp.c libhashcat.so.7 -o tools/rule_lookup
//       -lpthread -lm -ldl -lrt -Wl,-rpath,'$ORIGIN/..'
//
// Why this is a separate tool and not part of hashcat: answering it means building every candidate
// the attack builds, which is one pass per rule rather than one pass over the input. Every other
// --lookup question costs a single pass, and a mask is ranked without reading anything, so putting
// this behind the same option would make one combination behave unlike all the others. Here the cost
// is the point of the program, so it is spent openly: the work is divided over every core, the
// progress line says how much is left, and a run can be split across machines with --skip and
// --limit.
//
// What it does NOT do is invert a rule. There is no reading of "sa@ $1 c" that turns a candidate
// back into the word it came from, and writing one would be a fourth implementation of the rule
// language beside src/rp_cpu.c and the two device engines, which would have to agree with them
// forever. So the candidates are built forwards with hashcat's own engine, linked out of
// libhashcat: apply_rules () for a normal run and apply_rules_optimized () for -O, which are the
// host builds of OpenCL/inc_rp.cl and OpenCL/inc_rp_optimized.cl, the same two --stdout uses.
//
// An answer is therefore exact, and so is a refusal. If this says nothing produces the candidate,
// no word and no rule in that attack produces it.

#include "common.h"
#include "types.h"
#include "rp.h"
#include "rp_cpu.h"
#include "convert.h"
#include "filehandling.h"
#include "emu_inc_rp.h"
#include "emu_inc_rp_optimized.h"

#include <dirent.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define TOOLNAME "rule_lookup"

// The pure engine is written for a buffer under 256 bytes, see the comment on apply_rules () in
// OpenCL/inc_rp.cl. The optimized one keeps a candidate in two 16 byte halves and cannot see past
// them. A word longer than its engine holds is passed over rather than cut to fit, because a real
// run rejects such a base word before any rule touches it.

#define WORD_MAX_PURE 255
#define WORD_MAX_OPT  31

// A batch is sized by the work in it, not by the number of words. One word against a 98670 rule set
// is already a hundred thousand rule applications, so a batch counted in words would hand one thread
// the whole run and leave the rest idle. Counted in rule applications instead, a batch is a slice of
// work whatever the rule set costs, and every core gets one.

#define JOB_APPLIED   (4 * 1024 * 1024)
#define JOB_WORDS_MAX 32768
#define JOB_WORDS_MIN 1
#define READ_BYTES    (1 * 1024 * 1024)

//
// what was asked
//

typedef struct
{
  u8  buf[PW_MAX];
  u32 len;

  char *spelling;               // as it was given on the command line or in the file

  bool  found;
  u64   word;                   // global base word index
  u64   rule;                   // rule index within the chained set
  u8    word_buf[PW_MAX];       // the base word that makes it
  u32   word_len;

} cand_t;

//
// one rule as it was written, kept so the answer can name it and point at its line
//

typedef struct
{
  char *text;
  u32   line;

} rule_src_t;

typedef struct
{
  char       *path;
  rule_src_t *src;
  u32         cnt;

  kernel_rule_t *kern;

} rule_file_t;

//
// one wordlist, and where its words sit in the global keyspace
//

typedef struct
{
  char *path;
  u64   first;                  // global index of its first word
  u64   words;

} source_t;

//
// a batch of words handed to a worker
//

typedef struct
{
  u64  first;
  u32  cnt;
  u32  data_len;

  u8  *data;
  u32 *off;                     // cnt + 1 offsets into data

} job_t;

//
// the run
//

typedef struct
{
  cand_t *cands;
  u32     cands_cnt;

  // Candidates bucketed by length, so a rule's output is looked up by its length instead of being
  // compared against every candidate. One pass answers as many questions as were asked.

  u32    *by_len[PW_MAX + 1];
  u32     by_len_cnt[PW_MAX + 1];

  kernel_rule_t *rules;
  u64            rules_cnt;

  rule_file_t *rule_files;
  u32          rule_files_cnt;

  bool optimized;
  bool autohex;
  bool find_all;

  u32 word_max;

  // the job queue

  job_t          *jobs;
  u32             jobs_cnt;
  u32             q_head;
  u32             q_tail;
  u32             q_used;
  bool            q_done;
  pthread_mutex_t q_lock;
  pthread_cond_t  q_more;
  pthread_cond_t  q_room;

  pthread_mutex_t hit_lock;
  u32             hits;         // how many candidates have been answered

  u32 job_words;                // words per batch, from JOB_APPLIED and the size of the rule set
  u32 job_bytes;

  u64 words_done;
  u64 applied;

} ctx_t;

static void usage (void)
{
  printf ("\n");
  printf ("%s: which word and which rule of an -a 0 attack produce a candidate\n", TOOLNAME);
  printf ("\n");
  printf ("  %s [options] <candidate> <wordlist|directory>...\n", TOOLNAME);
  printf ("  %s [options] -c <candidate>      <wordlist|directory>...\n", TOOLNAME);
  printf ("  %s [options] -f <candidate file> <wordlist|directory>...\n", TOOLNAME);
  printf ("\n");
  printf ("options:\n");
  printf ("\n");
  printf ("  -r <file>    rule file, repeatable. Several are chained exactly as hashcat chains them\n");
  printf ("  -c <str>     the candidate, for one that begins with a hyphen or comes from a script\n");
  printf ("  -f <file>    read candidates from a file, one per line, and answer all of them in one pass\n");
  printf ("  -O           use the optimized rule engine, for an attack that runs with -O\n");
  printf ("  -t <n>       threads, default is one per core\n");
  printf ("  -s <n>       start at this base word, as hashcat --skip does\n");
  printf ("  -l <n>       stop after this many base words, as hashcat --limit does\n");
  printf ("  -a           report every word and rule that produce a candidate, not just the first\n");
  printf ("  -q           no progress line and no summary\n");
  printf ("  -h           this help\n");
  printf ("\n");
  printf ("  --wordlist-autohex-disable   do not decode $HEX[...] wordlist lines\n");
  printf ("\n");
  printf ("Options and file names may be given in any order. A candidate that begins with a hyphen\n");
  printf ("is passed with -c, since \"--\" would take the rule file for a wordlist as well.\n");
  printf ("\n");
  printf ("A candidate that no command line can carry is written as $HEX[...], the spelling the\n");
  printf ("potfile and --show use. Wordlists may be gzip, xz or zstd compressed, and a directory\n");
  printf ("becomes every file in it sorted by name, both exactly as -a 0 reads them.\n");
  printf ("\n");
  printf ("The reported word index is in hashcat --skip units, so \"-s N -l 1\" runs the one word\n");
  printf ("that produces the candidate, with every rule applied to it.\n");
  printf ("\n");
  printf ("Without -a the search stops at the first word and rule that produce a candidate, which is\n");
  printf ("the pair the attack reaches first. With -a it reads everything and reports the pairs as the\n");
  printf ("threads find them, so pipe that through \"sort -k2 -n\" if the order matters.\n");
  printf ("\n");
  printf ("It exits 0 when every candidate was found and 1 when any was not.\n");
  printf ("\n");
  printf ("examples:\n");
  printf ("\n");
  printf ("  %s merche03123 example.dict -r rules/best66.rule\n", TOOLNAME);
  printf ("  %s -f wanted.txt /wordlists -r rules/best66.rule -r rules/leetspeak.rule\n", TOOLNAME);
  printf ("  %s '$HEX[6101627a]' example.dict -r rules/best66.rule\n", TOOLNAME);
  printf ("\n");
}

static void die (const char *fmt, ...)
{
  va_list ap;

  fprintf (stderr, "%s: ", TOOLNAME);

  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);

  fprintf (stderr, "\n");

  exit (1);
}

static double now_sec (void)
{
  struct timespec ts;

  clock_gettime (CLOCK_MONOTONIC, &ts);

  return (double) ts.tv_sec + ((double) ts.tv_nsec / 1e9);
}

// A word can hold bytes no terminal should be handed. $HEX[...] is how the potfile and --show write
// one, so it is how this writes one back.

static void spell (char *out, const size_t out_sz, const u8 *buf, const u32 len)
{
  if (need_hexify (buf, len, 0, false) == false)
  {
    const size_t n = (len < out_sz - 1) ? len : out_sz - 1;

    memcpy (out, buf, n);

    out[n] = 0;

    return;
  }

  if (out_sz < 8) { out[0] = 0; return; }

  size_t n = len;

  if ((n * 2) > (out_sz - 8)) n = (out_sz - 8) / 2;

  memcpy (out, "$HEX[", 5);

  const size_t hex_len = exec_hexify (buf, n, (u8 *) out + 5);

  out[5 + hex_len + 0] = ']';
  out[5 + hex_len + 1] = 0;
}

// A candidate is taken the way --lookup takes one: as it stands, or decoded from $HEX[...].

static bool cand_decode (const char *arg, u8 *out, u32 *out_len)
{
  const u32 arg_len = (u32) strlen (arg);

  if (arg_len == 0) return false;

  if (is_hexify ((const u8 *) arg, arg_len) == true)
  {
    if (((arg_len - 6) / 2) > PW_MAX) return false;

    *out_len = (u32) exec_unhexify ((const u8 *) arg, arg_len, out, PW_MAX);

    return (*out_len > 0);
  }

  if (arg_len > PW_MAX) return false;

  memcpy (out, arg, arg_len);

  *out_len = arg_len;

  return true;
}

//
// rules
//

// Read one rule file the way kernel_rules_load () reads it: a blank line and a line starting with #
// are not rules, a rule the CPU engine refuses is dropped with a warning, and so is one the kernel
// form cannot hold. Unlike hashcat this also keeps the text and the line number, because hashcat
// only ever has to run a rule and this has to name it.

static void rules_load_file (rule_file_t *rf, const char *path)
{
  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) die ("%s: %s", path, hc_fopen_strerror ());

  rf->path = strdup (path);
  rf->cnt  = 0;

  u32 avail = 4096;

  rf->src  = (rule_src_t    *) malloc (avail * sizeof (rule_src_t));
  rf->kern = (kernel_rule_t *) malloc (avail * sizeof (kernel_rule_t));

  if ((rf->src == NULL) || (rf->kern == NULL)) die ("out of memory reading %s", path);

  char  *line = (char *) malloc (HCBUFSIZ_LARGE);
  u32    line_no = 0;

  if (line == NULL) die ("out of memory reading %s", path);

  while (hc_feof (&fp) == 0)
  {
    const size_t len = fgetl (&fp, line, HCBUFSIZ_LARGE);

    // fgetl () cannot tell an empty line from the end of the file, and neither can hc_feof () until
    // a read has been tried past the last one. A blank line is not a rule either way, so the two
    // cases need not be told apart here.

    line_no++;

    if (len == 0)   continue;
    if (line[0] == '#') continue;

    char in[RP_PASSWORD_SIZE];
    char out[RP_PASSWORD_SIZE];

    memset (in,  0, sizeof (in));
    memset (out, 0, sizeof (out));

    if (_old_apply_rule (line, (int) len, in, 1, out) == -1)
    {
      fprintf (stderr, "%s: %s:%u: skipping unsupported rule: %s\n", TOOLNAME, path, line_no, line);

      continue;
    }

    if (rf->cnt == avail)
    {
      avail *= 2;

      rf->src  = (rule_src_t    *) realloc (rf->src,  avail * sizeof (rule_src_t));
      rf->kern = (kernel_rule_t *) realloc (rf->kern, avail * sizeof (kernel_rule_t));

      if ((rf->src == NULL) || (rf->kern == NULL)) die ("out of memory reading %s", path);
    }

    memset (&rf->kern[rf->cnt], 0, sizeof (kernel_rule_t));

    if (cpu_rule_to_kernel_rule (line, (u32) len, &rf->kern[rf->cnt]) == -1)
    {
      fprintf (stderr, "%s: %s:%u: skipping rule the kernel form cannot hold: %s\n", TOOLNAME, path, line_no, line);

      continue;
    }

    rf->src[rf->cnt].text = strdup (line);
    rf->src[rf->cnt].line = line_no;

    rf->cnt++;
  }

  free (line);

  hc_fclose (&fp);

  if (rf->cnt == 0) die ("%s: no valid rules left", path);
}

// Chain the rule files into one set, with the same arithmetic kernel_rules_load () uses so that the
// rule index this reports is the index that attack really has. A chain longer than the kernel form
// holds is dropped and the set closes up behind it, again as hashcat does.

static void rules_chain (ctx_t *ctx)
{
  const u32 files = ctx->rule_files_cnt;

  if (files == 1)
  {
    ctx->rules     = ctx->rule_files[0].kern;
    ctx->rules_cnt = ctx->rule_files[0].cnt;

    return;
  }

  u64 *repeats = (u64 *) calloc (files + 1, sizeof (u64));

  if (repeats == NULL) die ("out of memory chaining rules");

  u64 total = 1;

  repeats[0] = 1;

  for (u32 i = 0; i < files; i++)
  {
    total *= ctx->rule_files[i].cnt;

    if (total > 0xffffffffULL) die ("chaining these %u rule files gives %" PRIu64 " rules, which is more than hashcat itself would run", files, total);

    repeats[i + 1] = total;
  }

  kernel_rule_t *buf = (kernel_rule_t *) calloc (total, sizeof (kernel_rule_t));

  if (buf == NULL) die ("out of memory for %" PRIu64 " chained rules", total);

  u64 invalid = 0;

  for (u64 i = 0; i < total; i++)
  {
    kernel_rule_t *out = &buf[i - invalid];

    memset (out, 0, sizeof (kernel_rule_t));

    u32  out_pos  = 0;
    bool overflow = false;

    for (u32 j = 0; j < files; j++)
    {
      const u64 in_off = (i / repeats[j]) % ctx->rule_files[j].cnt;

      const kernel_rule_t *in = &ctx->rule_files[j].kern[in_off];

      for (u32 in_pos = 0; in->cmds[in_pos]; in_pos++, out_pos++)
      {
        if (out_pos == RULES_MAX - 1) { overflow = true; break; }

        out->cmds[out_pos] = in->cmds[in_pos];
      }

      if (overflow == true) break;
    }

    if (overflow == true) invalid++;
  }

  free (repeats);

  if (invalid > 0)
  {
    fprintf (stderr, "%s: %" PRIu64 " chains exceeded the maximum functions per rule and were dropped\n", TOOLNAME, invalid);
  }

  ctx->rules     = buf;
  ctx->rules_cnt = total - invalid;
}

// The text of one rule of the chained set, rebuilt from the files rather than stored. Storing it per
// chain would cost more than the rules themselves for a large chained set, and the index says
// everything needed to find the parts again.

static void rule_spell (const ctx_t *ctx, const u64 rule, char *text, const size_t text_sz, char *src, const size_t src_sz)
{
  text[0] = 0;
  src[0]  = 0;

  if (ctx->rule_files_cnt == 1)
  {
    snprintf (text, text_sz, "%s", ctx->rule_files[0].src[rule].text);
    snprintf (src,  src_sz,  "%s:%u", ctx->rule_files[0].path, ctx->rule_files[0].src[rule].line);

    return;
  }

  // Which rule of each file this chain took, by the same arithmetic that built it. The dropped
  // chains make this approximate for a set that overflowed, which is why that case is reported when
  // it happens.

  u64 repeat = 1;

  size_t text_len = 0;
  size_t src_len  = 0;

  for (u32 j = 0; j < ctx->rule_files_cnt; j++)
  {
    const u64 in_off = (rule / repeat) % ctx->rule_files[j].cnt;

    repeat *= ctx->rule_files[j].cnt;

    text_len += (size_t) snprintf (text + text_len, (text_len < text_sz) ? text_sz - text_len : 0, "%s%s", (j > 0) ? " " : "", ctx->rule_files[j].src[in_off].text);
    src_len  += (size_t) snprintf (src  + src_len,  (src_len  < src_sz)  ? src_sz  - src_len  : 0, "%s%s:%u", (j > 0) ? " + " : "", ctx->rule_files[j].path, ctx->rule_files[j].src[in_off].line);
  }
}

//
// wordlists
//

static int cmp_str (const void *a, const void *b)
{
  return strcmp (*(const char **) a, *(const char **) b);
}

// A directory becomes every file in it sorted by name, which is what straight_ctx_add_workv () does,
// and sorting is what makes the keyspace the same on every machine.

static void sources_add (source_t **list, u32 *cnt, u32 *avail, const char *path)
{
  struct stat st;

  if (stat (path, &st) == -1) die ("%s: %s", path, strerror (errno));

  if (S_ISDIR (st.st_mode))
  {
    DIR *d = opendir (path);

    if (d == NULL) die ("%s: %s", path, strerror (errno));

    char **names = NULL;
    u32    names_cnt = 0;
    u32    names_avail = 0;

    struct dirent *e;

    while ((e = readdir (d)) != NULL)
    {
      if (strcmp (e->d_name, ".")  == 0) continue;
      if (strcmp (e->d_name, "..") == 0) continue;

      char *full = NULL;

      if (asprintf (&full, "%s/%s", path, e->d_name) == -1) die ("out of memory");

      if ((stat (full, &st) == -1) || (S_ISDIR (st.st_mode))) { free (full); continue; }

      if (names_cnt == names_avail)
      {
        names_avail = (names_avail == 0) ? 32 : names_avail * 2;

        names = (char **) realloc (names, names_avail * sizeof (char *));

        if (names == NULL) die ("out of memory");
      }

      names[names_cnt++] = full;
    }

    closedir (d);

    qsort (names, names_cnt, sizeof (char *), cmp_str);

    for (u32 i = 0; i < names_cnt; i++)
    {
      sources_add (list, cnt, avail, names[i]);

      free (names[i]);
    }

    free (names);

    return;
  }

  if (*cnt == *avail)
  {
    *avail = (*avail == 0) ? 8 : *avail * 2;

    *list = (source_t *) realloc (*list, *avail * sizeof (source_t));

    if (*list == NULL) die ("out of memory");
  }

  (*list)[*cnt].path  = strdup (path);
  (*list)[*cnt].first = 0;
  (*list)[*cnt].words = 0;

  (*cnt)++;
}

//
// the search
//

// One word against every rule, in the order the attack applies them.

static void test_word (ctx_t *ctx, const u64 index, const u8 *word, const u32 len, u32 *rule_buf)
{
  u8 *const rule_ptr = (u8 *) rule_buf;

  for (u64 rule = 0; rule < ctx->rules_cnt; rule++)
  {
    memset (rule_buf, 0, PW_MAX);

    memcpy (rule_ptr, word, len);

    int out_len;

    if (ctx->optimized == true)
    {
      out_len = (int) apply_rules_optimized (ctx->rules[rule].cmds, &rule_buf[0], &rule_buf[4], len);
    }
    else
    {
      out_len = apply_rules (ctx->rules[rule].cmds, rule_buf, (int) len);
    }

    if (out_len < 0)      continue;
    if (out_len > PW_MAX) continue;

    const u32 n = ctx->by_len_cnt[out_len];

    if (n == 0) continue;

    const u32 *bucket = ctx->by_len[out_len];

    for (u32 b = 0; b < n; b++)
    {
      cand_t *c = &ctx->cands[bucket[b]];

      if (memcmp (rule_ptr, c->buf, c->len) != 0) continue;

      pthread_mutex_lock (&ctx->hit_lock);

      // The attack walks base words on the outside and the rule set on the inside, so the earliest
      // pair in that order is the one it reaches first. Threads see the pairs out of order, so the
      // smallest is kept rather than the first seen.

      const bool better = (c->found == false) || (index < c->word) || ((index == c->word) && (rule < c->rule));

      if (ctx->find_all == true)
      {
        char text[RP_RULE_SIZE * 4];
        char src[1024];
        char wbuf[(PW_MAX * 2) + 8];

        rule_spell (ctx, rule, text, sizeof (text), src, sizeof (src));

        spell (wbuf, sizeof (wbuf), word, len);

        printf ("  word %-12" PRIu64 " %-24s rule %-8" PRIu64 " %-24s (%s)\n", index, wbuf, rule, text, src);

        if (c->found == false) { c->found = true; ctx->hits++; }
      }

      if (better == true)
      {
        if (c->found == false) ctx->hits++;

        c->found    = true;
        c->word     = index;
        c->rule     = rule;
        c->word_len = (len < PW_MAX) ? len : PW_MAX;

        memcpy (c->word_buf, word, c->word_len);
      }

      pthread_mutex_unlock (&ctx->hit_lock);
    }
  }
}

static void *worker (void *p)
{
  ctx_t *ctx = (ctx_t *) p;

  u32 *rule_buf = (u32 *) malloc (PW_MAX);

  if (rule_buf == NULL) die ("out of memory in a worker");

  while (true)
  {
    pthread_mutex_lock (&ctx->q_lock);

    while ((ctx->q_used == 0) && (ctx->q_done == false)) pthread_cond_wait (&ctx->q_more, &ctx->q_lock);

    if ((ctx->q_used == 0) && (ctx->q_done == true))
    {
      pthread_mutex_unlock (&ctx->q_lock);

      break;
    }

    job_t job = ctx->jobs[ctx->q_tail];

    ctx->q_tail = (ctx->q_tail + 1) % ctx->jobs_cnt;
    ctx->q_used--;

    pthread_cond_signal (&ctx->q_room);
    pthread_mutex_unlock (&ctx->q_lock);

    // A batch that begins after every candidate's best pair cannot improve on any of them. After the
    // first hit that drains the rest of the queue almost at once.

    bool useful = ctx->find_all;

    if (useful == false)
    {
      pthread_mutex_lock (&ctx->hit_lock);

      for (u32 i = 0; i < ctx->cands_cnt; i++)
      {
        if ((ctx->cands[i].found == false) || (job.first <= ctx->cands[i].word)) { useful = true; break; }
      }

      pthread_mutex_unlock (&ctx->hit_lock);
    }

    if (useful == true)
    {
      for (u32 i = 0; i < job.cnt; i++)
      {
        const u32 len = job.off[i + 1] - job.off[i];

        if ((len > 0) && (len <= ctx->word_max)) test_word (ctx, job.first + i, job.data + job.off[i], len, rule_buf);
      }

      __sync_fetch_and_add (&ctx->applied, (u64) job.cnt * ctx->rules_cnt);
    }

    __sync_fetch_and_add (&ctx->words_done, (u64) job.cnt);

    free (job.data);
    free (job.off);
  }

  free (rule_buf);

  return NULL;
}

//
// reading, on the main thread
//

typedef struct
{
  ctx_t *ctx;

  job_t job;                    // the batch being filled, empty when cnt is 0
  bool  open;

  u64 index;                    // global index of the next word to be read
  u64 skip;
  u64 limit;
  u64 taken;

  bool stop;

} reader_t;

static void job_flush (reader_t *r)
{
  ctx_t *ctx = r->ctx;

  if (r->open == false) return;

  // An empty batch is nothing to run, and its buffers would otherwise be dropped on the floor by the
  // job_open () that follows.

  if (r->job.cnt == 0)
  {
    free (r->job.data);
    free (r->job.off);

    r->open = false;

    return;
  }

  pthread_mutex_lock (&ctx->q_lock);

  while (ctx->q_used == ctx->jobs_cnt) pthread_cond_wait (&ctx->q_room, &ctx->q_lock);

  ctx->jobs[ctx->q_head] = r->job;

  ctx->q_head = (ctx->q_head + 1) % ctx->jobs_cnt;
  ctx->q_used++;

  pthread_cond_signal (&ctx->q_more);
  pthread_mutex_unlock (&ctx->q_lock);

  // The batch owns its buffers until a worker has run it, and the worker frees them. Handing them on
  // is what makes the reader done with them.

  r->open = false;
}

static void job_open (reader_t *r, const u64 first)
{
  const ctx_t *ctx = r->ctx;

  r->job.first    = first;
  r->job.cnt      = 0;
  r->job.data_len = 0;
  r->job.data     = (u8  *) malloc (ctx->job_bytes);
  r->job.off      = (u32 *) malloc (((size_t) ctx->job_words + 1) * sizeof (u32));

  if ((r->job.data == NULL) || (r->job.off == NULL)) die ("out of memory");

  r->job.off[0] = 0;

  r->open = true;
}

static void word_push (reader_t *r, const u8 *word, const u32 len)
{
  const ctx_t *ctx = r->ctx;

  const u64 index = r->index++;

  if (index < r->skip) return;

  if ((r->limit > 0) && (r->taken >= r->limit)) { r->stop = true; return; }

  r->taken++;

  if (r->open == false) job_open (r, index);

  const u32 keep = (len > PW_MAX) ? PW_MAX : len;

  if ((r->job.cnt == ctx->job_words) || ((r->job.data_len + keep) > ctx->job_bytes))
  {
    job_flush (r);

    job_open (r, index);
  }

  job_t *job = &r->job;

  memcpy (job->data + job->data_len, word, keep);

  job->data_len += keep;
  job->cnt++;
  job->off[job->cnt] = job->data_len;
}

// Split a file into words the way the wordlist feed does: on "\n", with every trailing "\r" taken
// off, and every line counted whether the attack can use it or not. That is what makes the index
// this reports the same number --skip means.

static u64 read_source (reader_t *r, const char *path)
{
  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) die ("%s: %s", path, hc_fopen_strerror ());

  u8    *buf   = (u8 *) malloc (READ_BYTES + PW_MAX + 1);
  u8    *carry = (u8 *) malloc (HCBUFSIZ_LARGE);
  size_t carry_len = 0;
  u64    words = 0;
  bool   over  = false;         // the line in hand is longer than carry can hold

  if ((buf == NULL) || (carry == NULL)) die ("out of memory reading %s", path);

  while (true)
  {
    const size_t nread = hc_fread (buf, 1, READ_BYTES, &fp);

    if (nread == 0) break;

    size_t pos = 0;

    while (pos < nread)
    {
      u8 *nl = memchr (buf + pos, '\n', nread - pos);

      const size_t chunk = (nl != NULL) ? (size_t) (nl - (buf + pos)) : (nread - pos);

      if (nl == NULL)
      {
        if ((carry_len + chunk) > HCBUFSIZ_LARGE) over = true;
        else { memcpy (carry + carry_len, buf + pos, chunk); carry_len += chunk; }

        break;
      }

      size_t len;

      if ((carry_len == 0) && (over == false))
      {
        len = chunk;

        while ((len > 0) && (buf[pos + len - 1] == '\r')) len--;

        word_push (r, buf + pos, (u32) len);
      }
      else
      {
        if ((carry_len + chunk) > HCBUFSIZ_LARGE) over = true;
        else { memcpy (carry + carry_len, buf + pos, chunk); carry_len += chunk; }

        len = carry_len;

        while ((len > 0) && (carry[len - 1] == '\r')) len--;

        // An oversized line is still one line, so it still moves the index on. It cannot match
        // anything either way, since no candidate is longer than PW_MAX.

        word_push (r, carry, over ? (u32) (PW_MAX + 1) : (u32) len);

        carry_len = 0;
        over      = false;
      }

      words++;

      pos += chunk + 1;

      if (r->stop == true) break;
    }

    if (r->stop == true) break;

    // Nothing more can improve on what is already found, so there is no reason to keep reading.

    if (r->ctx->find_all == false)
    {
      pthread_mutex_lock (&r->ctx->hit_lock);
      const bool all = (r->ctx->hits == r->ctx->cands_cnt);
      pthread_mutex_unlock (&r->ctx->hit_lock);

      if (all == true) { r->stop = true; break; }
    }
  }

  // A last line with no line ending is a line, which is what count_lines () counts too.

  if ((r->stop == false) && ((carry_len > 0) || (over == true)))
  {
    size_t len = carry_len;

    while ((len > 0) && (carry[len - 1] == '\r')) len--;

    word_push (r, carry, over ? (u32) (PW_MAX + 1) : (u32) len);

    words++;
  }

  free (buf);
  free (carry);

  hc_fclose (&fp);

  return words;
}

static u64 count_source (const char *path)
{
  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) die ("%s: %s", path, hc_fopen_strerror ());

  const u64 n = count_lines (&fp);

  hc_fclose (&fp);

  return n;
}

//
// main
//

int main (int argc, char **argv)
{
  ctx_t ctx;

  memset (&ctx, 0, sizeof (ctx));

  ctx.autohex = true;

  char **rule_paths = NULL;
  u32    rule_paths_cnt = 0;

  char *cand_file = NULL;
  char *cand_arg  = NULL;

  long threads = 0;
  u64  skip    = 0;
  u64  limit   = 0;
  bool quiet   = false;

  // Options and file names may be mixed in any order, as they may on a hashcat command line, so the
  // two are sorted out in one pass rather than by position. "--" ends the options, for a candidate
  // that begins with a hyphen.

  char **pos = (char **) malloc ((size_t) argc * sizeof (char *));

  int pos_cnt = 0;

  if (pos == NULL) die ("out of memory");

  bool no_more_options = false;

  for (int i = 1; i < argc; i++)
  {
    char *a = argv[i];

    if ((no_more_options == true) || (a[0] != '-') || (a[1] == 0))
    {
      pos[pos_cnt++] = a;

      continue;
    }

    if (strcmp (a, "--") == 0) { no_more_options = true; continue; }

    if (strcmp (a, "-h") == 0 || strcmp (a, "--help") == 0) { usage (); return 0; }

    if (strcmp (a, "-O") == 0) { ctx.optimized = true; continue; }
    if (strcmp (a, "-a") == 0) { ctx.find_all  = true; continue; }
    if (strcmp (a, "-q") == 0) { quiet         = true; continue; }

    if (strcmp (a, "--wordlist-autohex-disable") == 0) { ctx.autohex = false; continue; }

    if (i + 1 >= argc) die ("%s needs a value, try -h", a);

    char *v = argv[++i];

    if (strcmp (a, "-r") == 0)
    {
      rule_paths = (char **) realloc (rule_paths, (rule_paths_cnt + 1) * sizeof (char *));

      if (rule_paths == NULL) die ("out of memory");

      rule_paths[rule_paths_cnt++] = v;

      continue;
    }

    if (strcmp (a, "-c") == 0) { cand_arg  = v; continue; }
    if (strcmp (a, "-f") == 0) { cand_file = v; continue; }
    if (strcmp (a, "-t") == 0) { threads = strtol (v, NULL, 10); continue; }
    if (strcmp (a, "-s") == 0) { skip  = strtoull (v, NULL, 10); continue; }
    if (strcmp (a, "-l") == 0) { limit = strtoull (v, NULL, 10); continue; }

    die ("unknown option %s, try -h", a);
  }

  int p = 0;

  //
  // the candidates
  //

  u32 cands_avail = 0;

  if (cand_file == NULL)
  {
    if ((cand_arg == NULL) && (p >= pos_cnt)) { usage (); return 1; }

    const char *arg = (cand_arg != NULL) ? cand_arg : pos[p++];

    ctx.cands = (cand_t *) calloc (1, sizeof (cand_t));

    if (ctx.cands == NULL) die ("out of memory");

    if (cand_decode (arg, ctx.cands[0].buf, &ctx.cands[0].len) == false) die ("'%s' is not a candidate this can look for, it must be 1 to %d bytes", arg, PW_MAX);

    ctx.cands[0].spelling = strdup (arg);
    ctx.cands_cnt = 1;
  }
  else
  {
    HCFILE fp;

    if (hc_fopen (&fp, cand_file, "rb") == false) die ("%s: %s", cand_file, hc_fopen_strerror ());

    char *line = (char *) malloc (HCBUFSIZ_LARGE);

    if (line == NULL) die ("out of memory");

    while (hc_feof (&fp) == 0)
    {
      const size_t len = fgetl (&fp, line, HCBUFSIZ_LARGE);

      if (len == 0) continue;

      if (ctx.cands_cnt == cands_avail)
      {
        cands_avail = (cands_avail == 0) ? 64 : cands_avail * 2;

        ctx.cands = (cand_t *) realloc (ctx.cands, cands_avail * sizeof (cand_t));

        if (ctx.cands == NULL) die ("out of memory");
      }

      cand_t *c = &ctx.cands[ctx.cands_cnt];

      memset (c, 0, sizeof (cand_t));

      if (cand_decode (line, c->buf, &c->len) == false)
      {
        fprintf (stderr, "%s: %s: skipping a line that is not a candidate: %s\n", TOOLNAME, cand_file, line);

        continue;
      }

      c->spelling = strdup (line);

      ctx.cands_cnt++;
    }

    free (line);

    hc_fclose (&fp);

    if (ctx.cands_cnt == 0) die ("%s holds no candidates", cand_file);
  }

  //
  // the wordlists
  //

  source_t *sources = NULL;
  u32       sources_cnt = 0;
  u32       sources_avail = 0;

  if (p >= pos_cnt) die ("no wordlist given, try -h");

  for (; p < pos_cnt; p++) sources_add (&sources, &sources_cnt, &sources_avail, pos[p]);

  if (rule_paths_cnt == 0) die ("no rule file given. Without -r this question is just grep, try -h");

  //
  // the rules
  //

  ctx.rule_files     = (rule_file_t *) calloc (rule_paths_cnt, sizeof (rule_file_t));
  ctx.rule_files_cnt = rule_paths_cnt;

  if (ctx.rule_files == NULL) die ("out of memory");

  for (u32 j = 0; j < rule_paths_cnt; j++) rules_load_file (&ctx.rule_files[j], rule_paths[j]);

  rules_chain (&ctx);

  ctx.word_max = ctx.optimized ? WORD_MAX_OPT : WORD_MAX_PURE;

  // Candidates bucketed by length. A rule output of a length nobody asked about costs one array read
  // and nothing else, which is what makes many candidates almost free.

  for (u32 c = 0; c < ctx.cands_cnt; c++) ctx.by_len_cnt[ctx.cands[c].len]++;

  for (u32 n = 0; n <= PW_MAX; n++)
  {
    if (ctx.by_len_cnt[n] == 0) continue;

    ctx.by_len[n] = (u32 *) malloc (ctx.by_len_cnt[n] * sizeof (u32));

    if (ctx.by_len[n] == NULL) die ("out of memory");

    ctx.by_len_cnt[n] = 0;
  }

  for (u32 c = 0; c < ctx.cands_cnt; c++)
  {
    const u32 n = ctx.cands[c].len;

    ctx.by_len[n][ctx.by_len_cnt[n]++] = c;
  }

  //
  // how much there is to do
  //

  u64 words_total = 0;

  for (u32 s = 0; s < sources_cnt; s++)
  {
    sources[s].first = words_total;
    sources[s].words = count_source (sources[s].path);

    words_total += sources[s].words;
  }

  u64 words_range = (words_total > skip) ? (words_total - skip) : 0;

  if ((limit > 0) && (limit < words_range)) words_range = limit;

  if (threads <= 0) threads = sysconf (_SC_NPROCESSORS_ONLN);
  if (threads <= 0) threads = 1;

  // The live progress line rewrites itself with a carriage return, which only erases anything on a
  // terminal. Redirected to a file or a pipe it would just be noise in front of the answer, so there
  // it is left out and only the summary is written.

  const bool tty = isatty (fileno (stderr)) ? true : false;

  if (quiet == false)
  {
    fprintf (stderr, "%s: %" PRIu64 " words in %u file%s, %" PRIu64 " rules from %u file%s, %s engine\n",
      TOOLNAME, words_total, sources_cnt, (sources_cnt == 1) ? "" : "s",
      ctx.rules_cnt, ctx.rule_files_cnt, (ctx.rule_files_cnt == 1) ? "" : "s",
      ctx.optimized ? "optimized" : "pure");

    fprintf (stderr, "%s: %" PRIu64 " candidates to build, %u candidate%s to look for, %ld thread%s\n",
      TOOLNAME, words_range * ctx.rules_cnt, ctx.cands_cnt, (ctx.cands_cnt == 1) ? "" : "s",
      threads, (threads == 1) ? "" : "s");
  }

  //
  // run
  //

  // Words per batch, so that a batch is about JOB_APPLIED rule applications whatever the rule set
  // costs. Without this a small wordlist and a large rule set are one batch, which one thread runs
  // while the rest wait.

  u64 per_job = JOB_APPLIED / ctx.rules_cnt;

  if (per_job < JOB_WORDS_MIN) per_job = JOB_WORDS_MIN;
  if (per_job > JOB_WORDS_MAX) per_job = JOB_WORDS_MAX;

  ctx.job_words = (u32) per_job;
  ctx.job_bytes = ctx.job_words * 64;

  if (ctx.job_bytes < (PW_MAX + 1)) ctx.job_bytes = PW_MAX + 1;

  ctx.jobs_cnt = (u32) threads * 4;
  ctx.jobs     = (job_t *) calloc (ctx.jobs_cnt, sizeof (job_t));

  if (ctx.jobs == NULL) die ("out of memory");

  pthread_mutex_init (&ctx.q_lock,   NULL);
  pthread_mutex_init (&ctx.hit_lock, NULL);
  pthread_cond_init  (&ctx.q_more,   NULL);
  pthread_cond_init  (&ctx.q_room,   NULL);

  pthread_t *tids = (pthread_t *) calloc (threads, sizeof (pthread_t));

  if (tids == NULL) die ("out of memory");

  if (ctx.find_all == true) printf ("%s\n", (ctx.cands_cnt == 1) ? ctx.cands[0].spelling : "every word and rule that produce a candidate:");

  const double t0 = now_sec ();

  for (long t = 0; t < threads; t++)
  {
    if (pthread_create (&tids[t], NULL, worker, &ctx) != 0) die ("could not start thread %ld", t + 1);
  }

  reader_t r;

  memset (&r, 0, sizeof (r));

  r.ctx   = &ctx;
  r.skip  = skip;
  r.limit = limit;

  double t_last = t0;

  for (u32 s = 0; s < sources_cnt; s++)
  {
    if (r.stop == true) break;

    // A file entirely below --skip needs no reading, only its word count, which is already known.

    if ((skip > 0) && ((sources[s].first + sources[s].words) <= skip))
    {
      r.index = sources[s].first + sources[s].words;

      continue;
    }

    r.index = sources[s].first;

    read_source (&r, sources[s].path);

    const double t_now = now_sec ();

    if ((quiet == false) && (tty == true) && ((t_now - t_last) > 1.0))
    {
      const u64    done = __sync_fetch_and_add (&ctx.words_done, 0);
      const double rate = (double) done / (t_now - t0);

      fprintf (stderr, "%s: %" PRIu64 " of %" PRIu64 " words, %.1f%%, %.0f words/s\r",
        TOOLNAME, done, words_range, (words_range > 0) ? ((double) done * 100.0 / (double) words_range) : 0.0, rate);

      t_last = t_now;
    }
  }

  job_flush (&r);

  pthread_mutex_lock (&ctx.q_lock);
  ctx.q_done = true;
  pthread_cond_broadcast (&ctx.q_more);
  pthread_mutex_unlock (&ctx.q_lock);

  for (long t = 0; t < threads; t++) pthread_join (tids[t], NULL);

  const double t1 = now_sec ();

  if ((quiet == false) && (tty == true)) fprintf (stderr, "\r%*s\r", 78, "");

  //
  // report
  //

  u32 found = 0;

  if (ctx.find_all == false)
  {
    for (u32 c = 0; c < ctx.cands_cnt; c++)
    {
      cand_t *cand = &ctx.cands[c];

      printf ("%s\n", cand->spelling);

      if (cand->found == false)
      {
        if (words_range == words_total)
        {
          printf ("  not produced: no rule makes it out of any of the %" PRIu64 " words\n", words_range);
        }
        else
        {
          printf ("  not produced: no rule makes it out of any of the %" PRIu64 " words searched, which is not the whole of the %" PRIu64 " here\n", words_range, words_total);
        }

        continue;
      }

      found++;

      char text[RP_RULE_SIZE * 4];
      char src[1024];
      char wbuf[(PW_MAX * 2) + 8];

      rule_spell (&ctx, cand->rule, text, sizeof (text), src, sizeof (src));

      spell (wbuf, sizeof (wbuf), cand->word_buf, cand->word_len);

      // Which file the word is in, and its line in that file, because a global index is not something
      // anyone can look up by hand.

      const source_t *in = &sources[0];

      for (u32 s = 0; s < sources_cnt; s++) if (sources[s].first <= cand->word) in = &sources[s];

      printf ("  word %-10" PRIu64 " %s  (%s:%" PRIu64 ")\n", cand->word, wbuf, in->path, cand->word - in->first + 1);
      printf ("  rule %-10" PRIu64 " %s  (%s)\n", cand->rule, text, src);
      printf ("  reached at -s %" PRIu64 " of %" PRIu64 ", %.4f%% into the run\n", cand->word, words_total, (words_total > 0) ? ((double) cand->word * 100.0 / (double) words_total) : 0.0);

      continue;
    }
  }
  else
  {
    for (u32 c = 0; c < ctx.cands_cnt; c++) if (ctx.cands[c].found == true) found++;
  }

  if (quiet == false)
  {
    const u64    applied = __sync_fetch_and_add (&ctx.applied, 0);
    const double secs    = t1 - t0;

    // The answer is on stdout and the summary on stderr, so the two are only in the right order if
    // the buffered one is pushed out first.

    fflush (stdout);

    fprintf (stderr, "%s: %u of %u found, %" PRIu64 " rule applications in %.2fs", TOOLNAME, found, ctx.cands_cnt, applied, secs);

    if (secs >= 0.01) fprintf (stderr, ", %.1fM/s", (double) applied / secs / 1e6);

    fprintf (stderr, "\n");
  }

  // Given back rather than left to exit, so that a run under a leak checker is quiet and the next
  // person to change this can tell a real leak from the tool's own working set.

  for (u32 j = 0; j < ctx.rule_files_cnt; j++)
  {
    for (u32 k = 0; k < ctx.rule_files[j].cnt; k++) free (ctx.rule_files[j].src[k].text);

    free (ctx.rule_files[j].src);
    free (ctx.rule_files[j].path);

    if (ctx.rules != ctx.rule_files[j].kern) free (ctx.rule_files[j].kern);
  }

  free (ctx.rules);
  free (ctx.rule_files);
  free (rule_paths);

  for (u32 n = 0; n <= PW_MAX; n++) free (ctx.by_len[n]);

  for (u32 c = 0; c < ctx.cands_cnt; c++) free (ctx.cands[c].spelling);

  free (ctx.cands);

  for (u32 t = 0; t < sources_cnt; t++) free (sources[t].path);

  free (sources);
  free (ctx.jobs);
  free (tids);
  free (pos);

  return (found == ctx.cands_cnt) ? 0 : 1;
}

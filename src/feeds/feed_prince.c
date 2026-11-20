/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The PRINCE feed. It reads one wordlist the way princeprocessor (pp) does: words go into buckets by
// length, duplicates are dropped on load, and a candidate is a chain of one or more bucket entries
// whose lengths add up to the candidate's length. The lengths run largest bucket first, the chains of
// one length run by the candidates they reach, and inside a chain the first element runs fastest.
//
// The candidate ORDER is pp's, word for word, slicing included: pp spreads the candidates of one
// output length over rounds, giving every length at most wordlen_dist[len] candidates per round
// before the next length gets its turn, so a chain longer than the quota is emitted in slices with
// the other lengths' slices in between. This feed replays the same schedule: round by round, length
// by length in the sorted order, each length's stream cut at multiples of its quota.
//
// How a slice lands on the device engine. A chain is a mixed radix odometer, which is what a
// pcfg_cell_t is, but a slice starts at an arbitrary position of the chain and the cell's odometer
// always starts at zero. Two properties of the cell make the start expressible anyway:
//
// A slot reads its entry as pool_off + digit * ent_len, so rotating a bucket costs nothing: the pool
// holds every bucket twice, back to back, and a slot that points s entries into it walks the bucket
// as if entry s came first. That fixes the VALUE each digit produces.
//
// What it does not fix is the carry: in the true walk from X, digit e increments when the true
// digit below it wraps, which is R_e - (X mod R_e) candidates away, while the cell's odometer
// carries every R_e. The two walks agree until the first true carry, so one unit covers
// B = min over the element levels of that distance, and the next unit is rotated again from the
// position it lands on. Each cut strictly raises the alignment, so a slice breaks into at most
// elem_cnt + 1 units, and the common case is one: whole chain, quota-sized slice, or a position
// whose low digits are all zero.
//
// A chain of more than PCFG_DEV_MAXSLOT elements cannot be handed to a cell. pp defaults to at most
// 8, which is exactly the slot count, so this bites only where the run asks for more; those chains
// are skipped and their share of the keyspace is reported.
//
// What a position is here. On the device engine one position is one unit (a base word with its
// cell), the same convention the table feed keeps, so --skip, --limit and a restore point count
// units, not candidates; --total-candidates is exact either way. On the host engine one position is
// one candidate, and there the position decomposes arithmetically, the same division pp's own
// --skip performs. A device engine seek to a position the thread has passed replays from the start;
// a deep restore on a large keyspace pays that walk once per device.

#include "common.h"
#include "types.h"
#include "memory.h"
#include "filehandling.h"
#include "paw64.h"
#include "feed.h"

#include "feed_error.h"

// pp's own bounds: words of 1..32 bytes in, candidates of 1..32 bytes out.

#define PRINCE_IN_LEN_MAX  32
#define PRINCE_OUT_LEN_MAX 32

#define PRINCE_PW_MIN_DEF        1
#define PRINCE_PW_MAX_DEF       16
#define PRINCE_ELEM_CNT_MIN_DEF  1
#define PRINCE_WL_MAX_DEF   10000000

// How wide one unit may be, as a power of two. A cell's rectangle is a u32, so 31 is the ceiling,
// and 20 covers the largest quota the default distribution asks for.

#define PRINCE_KBITS_DEF 20
#define PRINCE_KBITS_MAX 31

// pp reads its wordlist with fgets () into a BUFSIZ buffer. A line longer than the buffer comes out
// as more than one word, so the buffer size is part of the input format and not an implementation
// detail.

#define PRINCE_IOBUF 8192

// pp's default word length distribution, from its README: the first million lines of rockyou.txt.
// A length past the table gets a quota of one candidate per round.

static const u64 PRINCE_WORDLEN_DIST[25] =
{
  0, 15, 56, 350, 3315, 43721, 276252, 201748, 226412, 119885,
  75075, 26323, 13373, 6353, 3540, 1877, 972, 311, 151, 81,
  66, 21, 16, 13, 13
};

// Counting the unit stream exactly means walking it at unit granularity, which is worth doing only
// while the walk is short. A length whose quota is one emits one candidate per unit, so the gate is
// on the unit estimate, not on the candidate count. Past the bound the feed reports its keyspace as
// unknown; the exact candidate count still reaches the status line through dev_total_u128.

#define PRINCE_COUNT_MAX_UNITS (((u128) 1) << 31)

typedef struct prince_bucket
{
  u32  cnt;

  // the words, cnt * len bytes, in first seen order, which is the order the odometer walks them in

  u8  *words;
  u64  words_alloc; // in entries, not bytes

  // the dedup index over words, open addressing, holding an entry index plus one so zero means empty

  u32 *hmap;
  u32  hmap_size;

  // where the bucket's entries start in the pool, in bytes; the pool holds the bucket twice, so the
  // second copy sits at pool_off + cnt * len

  u32  pool_off;

} prince_bucket_t;

typedef struct prince_chain
{
  u8    elems[PRINCE_OUT_LEN_MAX]; // one byte per element: the length its bucket holds
  u32   elem_cnt;

  u128  ks;        // candidates the chain reaches, the product of its bucket sizes
  u64   radix[PCFG_DEV_MAXSLOT];  // bucket size per element
  u128  R[PCFG_DEV_MAXSLOT];      // R[e] = product of the radices in front of element e

  u128  cand_off;  // where the chain starts in the whole candidate stream

} prince_chain_t;

typedef struct prince_group
{
  u32  pw_len;
  u64  quota;      // how much of this length's stream one round emits, pp's wordlen_dist[len]

  prince_chain_t *chains;
  u32             chains_cnt;

  u128 cand_len;   // the whole stream of the length, in candidates
  u128 cand_off;   // where the group starts in the candidate stream (main groups, then tail groups)

} prince_group_t;

typedef struct prince_global
{
  hashcat_ctx_t *hcctx;

  // which engine this run is, settled before global_init () runs and mirrored here because the walk
  // needs it on every step

  bool dev;

  u32 pw_min;
  u32 pw_max;

  u32 elem_cnt_min;
  u32 elem_cnt_max;  // as resolved, pp's default of min(pw-max, 8) included

  u64 wl_max;
  u32 il_cnt;

  bool wl_dist_len;

  prince_bucket_t buckets[PRINCE_IN_LEN_MAX + 1];

  u64 words_kept;
  u64 words_dupe;
  u64 words_long;

  // groups with a quota, in pp's order, which are the ones the round schedule interleaves, and
  // groups without one, which pp would never reach (it spins on them); this feed emits them last
  // rather than hanging the same way

  prince_group_t *groups;
  u32             groups_cnt;

  prince_group_t *tail;
  u32             tail_cnt;

  u128 cand_total;   // every candidate, main and tail
  u128 main_total;   // the candidates the round schedule covers
  u128 units_total;  // exact while counted, zero when it was not

  bool counted;      // whether units_total is exact

  // set when a product or a sum saturated the u128 along the way, which turns the keyspace answer
  // into "unknown", the way pp's 128-bit build warns and carries on. It is reachable: a length
  // window far above the word lengths (pw-min = pw-max = 28 over a four-letter list) runs the
  // per-length totals into the ceiling, so the check stays.

  bool sat;

  // chains that had more elements than a cell has slots, and what they would have been worth

  u64  chains_skipped;
  u128 cands_skipped;

  u32 *pool;
  u64  pool_size; // bytes

  // the hash mode's length window, or zeros where no hashconfig was given; a chain whose output
  // length cannot produce a candidate the mode accepts is not built

  u32 hc_pwmin;
  u32 hc_pwmax;

  // what global_init () works out for global_dev_init () once the unit stream exists

  u32         dev_avg;
  u32         dev_front;
  u32         dev_step;
  pcfg_cell_t probe;

} prince_global_t;

// Where a thread is in the schedule. pos is the feed position: a unit on the device engine, a
// candidate on the host engine. The rest names the candidate the next unit starts at: which group,
// where in its stream, and where in the chain that spot falls in.

typedef struct prince_thread
{
  u128 pos;

  u32  g;
  u128 round;

  u128 x;          // candidate offset inside the group's stream
  u128 slice_end;  // where this round's slice of the group ends

  u32  c;
  u128 X;          // candidate offset inside the chain

  bool tail;       // past the schedule, in the quota-less groups
  u32  tg;

} prince_thread_t;

/**
 * helpers
 */

static u128 prince_sat_add (prince_global_t *pg, const u128 a, const u128 b)
{
  if (overflow_check_u128_add (a, b) == true)
  {
    pg->sat = true;

    const u128 r = U128_MAX;

    return r;
  }

  const u128 r = a + b;

  return r;
}

static u128 prince_sat_mul (prince_global_t *pg, const u128 a, const u128 b)
{
  if (overflow_check_u128_mul (a, b) == true)
  {
    pg->sat = true;

    const u128 r = U128_MAX;

    return r;
  }

  const u128 r = a * b;

  return r;
}

// The same saturation for the unit estimate below, without touching pg->sat: an estimate that ran
// out of bits just means "too long to count", which is the answer the gate needs

static u128 prince_est_add (const u128 a, const u128 b)
{
  if (overflow_check_u128_add (a, b) == true) return U128_MAX;

  const u128 r = a + b;

  return r;
}

// The dedup hash over one word. Any function would do; this one is pp's own, h * 33 + c.

static u32 prince_word_hash (const u8 *buf, const u32 len)
{
  u32 h = 0;

  for (u32 i = 0; i < len; i++)
  {
    h = (h * 33) + buf[i];
  }

  return h;
}

static bool prince_bucket_rehash (prince_bucket_t *bk, const u32 len)
{
  const u32 new_size = bk->hmap_size * 2;

  if (new_size < bk->hmap_size) return false;

  u32 *new_map = (u32 *) hccalloc (new_size, sizeof (u32));

  if (new_map == NULL) return false;

  for (u32 i = 0; i < bk->cnt; i++)
  {
    const u8 *ent = &bk->words[(u64) i * len];

    u32 h = prince_word_hash (ent, len) & (new_size - 1);

    while (new_map[h] != 0)
    {
      h = (h + 1) & (new_size - 1);
    }

    new_map[h] = i + 1;
  }

  hcfree (bk->hmap);

  bk->hmap      = new_map;
  bk->hmap_size = new_size;

  return true;
}

// One word into its bucket, dropped when the bucket has it already. The bucket keeps first seen
// order, because that is the order pp's odometer walks a bucket in.

static bool prince_bucket_add (prince_bucket_t *bk, const u8 *word, const u32 len, bool *dupe)
{
  dupe[0] = false;

  if (bk->hmap_size == 0)
  {
    bk->hmap_size = 1024;

    bk->hmap = (u32 *) hccalloc (bk->hmap_size, sizeof (u32));

    if (bk->hmap == NULL) return false;
  }

  // grow before the load passes one in two

  if (((bk->cnt + 1) * 2) > bk->hmap_size)
  {
    if (prince_bucket_rehash (bk, len) == false) return false;
  }

  u32 h = prince_word_hash (word, len) & (bk->hmap_size - 1);

  while (bk->hmap[h] != 0)
  {
    const u32 idx = bk->hmap[h] - 1;

    const u8 *ent = &bk->words[(u64) idx * len];

    bool same = true;

    for (u32 i = 0; i < len; i++)
    {
      if (ent[i] != word[i])
      {
        same = false;

        break;
      }
    }

    if (same == true)
    {
      dupe[0] = true;

      return true;
    }

    h = (h + 1) & (bk->hmap_size - 1);
  }

  if (bk->cnt == bk->words_alloc)
  {
    const u64 want = (bk->words_alloc == 0) ? 256 : (bk->words_alloc * 2);

    bk->words = (u8 *) hcrealloc (bk->words, bk->words_alloc * len, (want - bk->words_alloc) * len);

    if (bk->words == NULL) return false;

    bk->words_alloc = want;
  }

  u8 *dst = &bk->words[(u64) bk->cnt * len];

  for (u32 i = 0; i < len; i++) dst[i] = word[i];

  bk->hmap[h] = bk->cnt + 1;

  bk->cnt++;

  return true;
}

/**
 * chains
 */

// pp's chain_gen_with_idx (): bit b of idx says whether a cut follows position b, so the 2^(len-1)
// values of idx walk every composition of len in the same order pp walks them.

static u32 prince_chain_gen (u8 *elems, const u32 pw_len, const u64 idx)
{
  u32 cnt = 0;

  u32 db_key = 1;

  for (u32 b = 0; b < (pw_len - 1); b++)
  {
    if (((idx >> b) & 1) != 0)
    {
      elems[cnt] = (u8) db_key;

      cnt++;

      db_key = 1;
    }
    else
    {
      db_key++;
    }
  }

  elems[cnt] = (u8) db_key;

  cnt++;

  return cnt;
}

static u128 prince_chain_ks (prince_global_t *pg, const u8 *elems, const u32 elem_cnt)
{
  u128 ks = 1;

  for (u32 i = 0; i < elem_cnt; i++)
  {
    ks = prince_sat_mul (pg, ks, pg->buckets[elems[i]].cnt);
  }

  return ks;
}

// A stable sort of the chains of one group by the candidates they reach, ties keep generation order,
// which is what pp's qsort () lands on. The sort walks an index so the chains themselves move once.

static bool prince_chain_sort (prince_chain_t *chains, const u32 chains_cnt)
{
  if (chains_cnt < 2) return true;

  u32 *idx = (u32 *) hcmalloc (chains_cnt * sizeof (u32));
  u32 *tmp = (u32 *) hcmalloc (chains_cnt * sizeof (u32));

  prince_chain_t *sorted = (prince_chain_t *) hcmalloc (chains_cnt * sizeof (prince_chain_t));

  if ((idx == NULL) || (tmp == NULL) || (sorted == NULL))
  {
    hcfree (idx);
    hcfree (tmp);
    hcfree (sorted);

    return false;
  }

  for (u32 i = 0; i < chains_cnt; i++) idx[i] = i;

  for (u32 span = 1; span < chains_cnt; span *= 2)
  {
    u32 out = 0;

    for (u64 base = 0; base < chains_cnt; base += ((u64) 2 * span))
    {
      u32 a_lo = (u32) base;
      u32 a_hi = (u32) MIN (base + span, chains_cnt);
      u32 b_lo = a_hi;
      u32 b_hi = (u32) MIN (a_hi + span, chains_cnt);

      while ((a_lo < a_hi) && (b_lo < b_hi))
      {
        const u32 ia = idx[a_lo];
        const u32 ib = idx[b_lo];

        // ascending by ks, and a tie takes the earlier chain, which is what makes the sort stable

        if (chains[ib].ks < chains[ia].ks)
        {
          tmp[out] = ib;

          b_lo++;
        }
        else
        {
          tmp[out] = ia;

          a_lo++;
        }

        out++;
      }

      while (a_lo < a_hi) { tmp[out] = idx[a_lo]; a_lo++; out++; }
      while (b_lo < b_hi) { tmp[out] = idx[b_lo]; b_lo++; out++; }
    }

    u32 *swap = idx;

    idx = tmp;
    tmp = swap;
  }

  for (u32 i = 0; i < chains_cnt; i++) sorted[i] = chains[idx[i]];

  for (u32 i = 0; i < chains_cnt; i++) chains[i] = sorted[i];

  hcfree (sorted);
  hcfree (idx);
  hcfree (tmp);

  return true;
}

// Build every chain of one output length, pp's validity rules and all: every element's bucket has to
// hold something, and the element count has to sit inside the asked-for range. Chains past the slot
// ceiling are counted rather than built, so the report can say what was left out.

static bool prince_group_build (prince_global_t *pg, const u32 pw_len, prince_group_t *grp)
{
  grp->pw_len = pw_len;

  const u64 eff_max = pg->elem_cnt_max;

  if (eff_max < pg->elem_cnt_min) return true;

  const u64 chains_lim = 1ULL << (pw_len - 1);

  u32 chains_alloc = 0;

  u8 elems[PRINCE_OUT_LEN_MAX];

  for (u64 idx = 0; idx < chains_lim; idx++)
  {
    const u32 elem_cnt = prince_chain_gen (elems, pw_len, idx);

    if (elem_cnt < pg->elem_cnt_min) continue;

    if (elem_cnt > eff_max) continue;

    bool have = true;

    for (u32 i = 0; i < elem_cnt; i++)
    {
      if (pg->buckets[elems[i]].cnt == 0)
      {
        have = false;

        break;
      }
    }

    if (have == false) continue;

    if (elem_cnt > PCFG_DEV_MAXSLOT)
    {
      pg->chains_skipped++;

      const u128 ks = prince_chain_ks (pg, elems, elem_cnt);

      pg->cands_skipped = prince_sat_add (pg, pg->cands_skipped, ks);

      continue;
    }

    if (grp->chains_cnt == chains_alloc)
    {
      const u32 want = (chains_alloc == 0) ? 16 : (chains_alloc * 2);

      grp->chains = (prince_chain_t *) hcrealloc (grp->chains, chains_alloc * sizeof (prince_chain_t), (want - chains_alloc) * sizeof (prince_chain_t));

      if (grp->chains == NULL) return false;

      chains_alloc = want;
    }

    prince_chain_t *ch = &grp->chains[grp->chains_cnt];

    memset (ch, 0, sizeof (prince_chain_t));

    ch->elem_cnt = elem_cnt;

    for (u32 i = 0; i < elem_cnt; i++) ch->elems[i] = elems[i];

    ch->ks = prince_chain_ks (pg, elems, elem_cnt);

    u128 R = 1;

    for (u32 i = 0; i < elem_cnt; i++)
    {
      ch->R[i]     = R;
      ch->radix[i] = pg->buckets[elems[i]].cnt;

      R = prince_sat_mul (pg, R, ch->radix[i]);
    }

    grp->cand_len = prince_sat_add (pg, grp->cand_len, ch->ks);

    grp->chains_cnt++;
  }

  if (prince_chain_sort (grp->chains, grp->chains_cnt) == false) return false;

  return true;
}

/**
 * the walk
 */

// How far the cell's odometer, started at zero over buckets rotated to X, agrees with the chain's
// own walk from X. Digit e of the candidate at X + t is entry (s_e + u_e) mod r_e of its bucket,
// where u_e is the odometer digit, and that stays the true entry until a true carry fires ahead of
// the odometer's own, which first happens R_e - (X mod R_e) ahead at the lowest level whose X mod
// R_e is not zero. Returns zero distance never; a position always has at least one candidate in it.

static u128 prince_bmax (const prince_chain_t *ch, const u128 X)
{
  u128 best = ch->ks - X;

  for (u32 e = 1; e < ch->elem_cnt; e++)
  {
    const u128 a = X % ch->R[e];

    if (a == 0) continue;

    const u128 dist = ch->R[e] - a;

    if (dist < best) best = dist;
  }

  return best;
}

// Enter group g of the round the thread is on: where its slice of this round starts and ends, and
// where the slice start falls in the group's chains.

static void prince_enter_group (const prince_global_t *pg, prince_thread_t *pt)
{
  const prince_group_t *grp = &pg->groups[pt->g];

  pt->x = pt->round * grp->quota;

  pt->slice_end = pt->x + grp->quota;

  if (pt->slice_end > grp->cand_len) pt->slice_end = grp->cand_len;

  const u128 base = grp->cand_off;

  const u128 abs = base + pt->x;

  u32 lo = 0;
  u32 hi = grp->chains_cnt;

  while ((lo + 1) < hi)
  {
    const u32 mid = lo + ((hi - lo) / 2);

    if (grp->chains[mid].cand_off > abs) hi = mid;
    else                                 lo = mid;
  }

  pt->c = lo;

  pt->X = abs - grp->chains[lo].cand_off;
}

// Enter tail group tg: no quota, the whole stream in one go.

static void prince_enter_tail (const prince_global_t *pg, prince_thread_t *pt)
{
  const prince_group_t *grp = &pg->tail[pt->tg];

  pt->x         = 0;
  pt->slice_end = grp->cand_len;

  pt->c = 0;
  pt->X = 0;
}

// Move to the next group of the round, or to the next round, skipping lengths whose stream this
// round no longer reaches. Returns false when a whole round went by with every length exhausted;
// the quota-less tail groups follow the schedule.

static bool prince_next_group (const prince_global_t *pg, prince_thread_t *pt)
{
  while (1)
  {
    pt->g++;

    if (pt->g >= pg->groups_cnt)
    {
      pt->g = 0;

      pt->round++;

      // a fresh round with nothing left in any group is the end of the schedule

      bool any = false;

      for (u32 i = 0; i < pg->groups_cnt; i++)
      {
        if ((pt->round * pg->groups[i].quota) < pg->groups[i].cand_len)
        {
          any = true;

          break;
        }
      }

      if (any == false) return false;
    }

    if ((pt->round * pg->groups[pt->g].quota) < pg->groups[pt->g].cand_len) return true;
  }
}

// Set the thread at the start of the stream: round zero of the first group that has one, or the
// tail when the schedule is empty.

static void prince_rewind (const prince_global_t *pg, prince_thread_t *pt)
{
  pt->pos = 0;

  pt->g     = 0;
  pt->round = 0;

  pt->tail = false;
  pt->tg   = 0;

  while (pt->g < pg->groups_cnt)
  {
    if (pg->groups[pt->g].cand_len > 0) break;

    pt->g++;
  }

  if (pt->g < pg->groups_cnt)
  {
    prince_enter_group (pg, pt);

    return;
  }

  pt->tail = true;

  if (pt->tg < pg->tail_cnt) prince_enter_tail (pg, pt);
}

// One step of the walk past B candidates, shared by both engines and by the counting pass.

static void prince_walk_past (const prince_global_t *pg, prince_thread_t *pt, const u128 B)
{
  pt->pos++;

  pt->x += B;
  pt->X += B;

  const prince_group_t *grp = (pt->tail == true) ? &pg->tail[pt->tg] : &pg->groups[pt->g];

  if (pt->X == grp->chains[pt->c].ks)
  {
    pt->c++;
    pt->X = 0;
  }

  if (pt->x < pt->slice_end) return;

  if (pt->tail == true)
  {
    pt->tg++;

    if (pt->tg < pg->tail_cnt) prince_enter_tail (pg, pt);

    return;
  }

  if (prince_next_group (pg, pt) == true)
  {
    prince_enter_group (pg, pt);

    return;
  }

  pt->tail = true;
  pt->tg   = 0;

  if (pt->tg < pg->tail_cnt) prince_enter_tail (pg, pt);
}

// The cell of one unit: every element of the chain is a slot, the fastest in the last slot because
// pcfg_odo_seed () decomposes il_pos from the last slot up, and each bucket is entered s entries in,
// which is what the doubled pool is for. The base word is the candidate's length of zero bytes; the
// slots cover every byte of it.

static void prince_cell_build (const prince_global_t *pg, const prince_chain_t *ch, const u128 X, const u128 B, pcfg_cell_t *cell)
{
  memset (cell, 0, sizeof (pcfg_cell_t));

  cell->slot_cnt = ch->elem_cnt;

  cell->rect = (u32) B;

  u32 dst_off = 0;

  for (u32 e = 0; e < ch->elem_cnt; e++)
  {
    const u32 len = ch->elems[e];

    const prince_bucket_t *bk = &pg->buckets[len];

    const u64 s = u128_lo ((X / ch->R[e]) % ch->radix[e]);

    const u32 j = ch->elem_cnt - 1 - e;

    cell->slots[j].pool_off = bk->pool_off + (u32) (s * len);
    cell->slots[j].radix    = (u32) ch->radix[e];
    cell->slots[j].digit    = 0;
    cell->slots[j].packed   = (len & 0xff) | ((dst_off & 0xff) << 8) | (PCFG_SLOT_KIND_BYTES << 16) | ((j & 0xff) << 24);

    dst_off += len;
  }
}

// One unit of the device engine: the most the walk can take from where the thread is, bounded by the
// slice, the chain, the carry horizon and the inner loop. Fills the cell and the base word when they
// are given, and returns the base word's length, 0 at the end of the stream, or -1 when the base
// word would not fit the buffer it was offered.

static int prince_walk_unit (prince_global_t *pg, prince_thread_t *pt, pcfg_cell_t *cell, u8 *base, const int base_size)
{
  if (pt->tail == true)
  {
    if (pt->tg >= pg->tail_cnt) return 0;
  }
  else
  {
    if (pt->g >= pg->groups_cnt) return 0;
  }

  const prince_group_t *grp = (pt->tail == true) ? &pg->tail[pt->tg] : &pg->groups[pt->g];

  if ((base != NULL) && (grp->pw_len > (u32) base_size)) return -1;

  const prince_chain_t *ch = &grp->chains[pt->c];

  u128 B = pt->slice_end - pt->x;

  const u128 chain_left = ch->ks - pt->X;

  if (chain_left < B) B = chain_left;

  const u128 bm = prince_bmax (ch, pt->X);

  if (bm < B) B = bm;

  if (B > pg->il_cnt) B = pg->il_cnt;

  if (cell != NULL)
  {
    memset (base, 0, grp->pw_len);

    prince_cell_build (pg, ch, pt->X, B, cell);
  }

  prince_walk_past (pg, pt, B);

  return grp->pw_len;
}

// One candidate of the host engine, built straight out of the buckets. Returns its length, 0 at the
// end of the stream, or -1 when the candidate would not fit the buffer it was offered.

static int prince_walk_cand (prince_global_t *pg, prince_thread_t *pt, u8 *out_buf, const int out_size)
{
  if (pt->tail == true)
  {
    if (pt->tg >= pg->tail_cnt) return 0;
  }
  else
  {
    if (pt->g >= pg->groups_cnt) return 0;
  }

  const prince_group_t *grp = (pt->tail == true) ? &pg->tail[pt->tg] : &pg->groups[pt->g];

  if (grp->pw_len > (u32) out_size) return -1;

  const prince_chain_t *ch = &grp->chains[pt->c];

  u32 len = 0;

  for (u32 e = 0; e < ch->elem_cnt; e++)
  {
    const prince_bucket_t *bk = &pg->buckets[ch->elems[e]];

    const u64 d = u128_lo ((pt->X / ch->R[e]) % ch->radix[e]);

    const u8 *word = &bk->words[d * ch->elems[e]];

    for (u32 i = 0; i < ch->elems[e]; i++) out_buf[len + i] = word[i];

    len += ch->elems[e];
  }

  prince_walk_past (pg, pt, 1);

  return len;
}

// The host engine's seek: a position is a candidate, and pp's own skip lands on one
// arithmetically. Whole rounds are counted off in a division per pass, each pass advancing every
// length by as many full rounds as the remainder can pay for, and the last partial round is walked
// slice by slice.

static void prince_place (prince_global_t *pg, prince_thread_t *pt, const u128 pos)
{
  prince_rewind (pg, pt);

  if (pos == 0)
  {
    pt->pos = pos;

    return;
  }

  u128 x[PRINCE_OUT_LEN_MAX + 1];

  memset (x, 0, sizeof (x));

  u128 rem = pos;

  if (rem < pg->main_total)
  {
    while (1)
    {
      u128 opml = 0;

      for (u32 g = 0; g < pg->groups_cnt; g++)
      {
        if (x[g] < pg->groups[g].cand_len) opml += pg->groups[g].quota;
      }

      const u128 ml = rem / opml;

      if (ml == 0) break;

      for (u32 g = 0; g < pg->groups_cnt; g++)
      {
        if (x[g] >= pg->groups[g].cand_len) continue;

        const u128 add = ml * pg->groups[g].quota;

        x[g] += add;
        rem  -= add;

        if (x[g] > pg->groups[g].cand_len)
        {
          rem  += x[g] - pg->groups[g].cand_len;
          x[g]  = pg->groups[g].cand_len;
        }
      }
    }

    // the last partial round, one slice at a time, in the order the schedule emits them

    for (u32 g = 0; g < pg->groups_cnt; g++)
    {
      const prince_group_t *grp = &pg->groups[g];

      if (x[g] >= grp->cand_len) continue;

      u128 s = grp->quota;

      if (s > (grp->cand_len - x[g])) s = grp->cand_len - x[g];

      if (rem < s)
      {
        pt->g     = g;
        pt->round = x[g] / grp->quota;

        prince_enter_group (pg, pt);

        const u128 at = pt->x;

        pt->x = at + rem;

        // the chain the landing point falls in

        const u128 abs = grp->cand_off + pt->x;

        u32 lo = 0;
        u32 hi = grp->chains_cnt;

        while ((lo + 1) < hi)
        {
          const u32 mid = lo + ((hi - lo) / 2);

          if (grp->chains[mid].cand_off > abs) hi = mid;
          else                                 lo = mid;
        }

        pt->c = lo;

        pt->X = abs - grp->chains[lo].cand_off;

        pt->pos = pos;

        return;
      }

      rem  -= s;
      x[g] += s;
    }
  }

  // past the schedule: the quota-less groups, laid end to end

  rem = pos - pg->main_total;

  for (u32 g = 0; g < pg->tail_cnt; g++)
  {
    const prince_group_t *grp = &pg->tail[g];

    if (rem >= grp->cand_len)
    {
      rem -= grp->cand_len;

      continue;
    }

    pt->tail = true;
    pt->tg   = g;

    prince_enter_tail (pg, pt);

    pt->x = rem;

    const u128 abs = grp->cand_off + rem;

    u32 lo = 0;
    u32 hi = grp->chains_cnt;

    while ((lo + 1) < hi)
    {
      const u32 mid = lo + ((hi - lo) / 2);

      if (grp->chains[mid].cand_off > abs) hi = mid;
      else                                 lo = mid;
    }

    pt->c = lo;

    pt->X = abs - grp->chains[lo].cand_off;

    pt->pos = pos;

    return;
  }

  // past the end of the stream: the walk reports the end when it is read

  pt->tail = true;
  pt->tg   = pg->tail_cnt;

  pt->pos = pos;
}

/**
 * interface
 */

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

// No AUTOHEX and no ICONV: pp reads its words as bytes and so does this feed, and both would apply
// to the finished candidate rather than to the words that went into it. No RULES: with rules the run
// moves to the host engine and the candidates are the base words, which this feed already produces
// whole there.

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_DEVICE
                                 | GENERIC_PLUGIN_OPTIONS_EXPLAIN;

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx)
{
  prince_global_t *pg = hccalloc (1, sizeof (prince_global_t));

  if (pg == NULL)
  {
    error_set (global_ctx, "hccalloc failed");

    return false;
  }

  global_ctx->gbldata = pg;

  pg->hcctx = hashcat_ctx;

  pg->dev = global_ctx->dev_enable;

  u64 pw_min       = PRINCE_PW_MIN_DEF;
  u64 pw_max       = PRINCE_PW_MAX_DEF;
  u64 elem_cnt_min = PRINCE_ELEM_CNT_MIN_DEF;
  u64 elem_cnt_max = 0; // unset here, so that pp's default of min(pw-max, 8) can follow pw-max
  u64 wl_max       = PRINCE_WL_MAX_DEF;
  u64 kbits        = PRINCE_KBITS_DEF;

  bool wl_dist_len = false;

  const feed_param_t params[] =
  {
    { "pw-min",       FEED_PARAM_TYPE_U64,  &pw_min,       1, PRINCE_OUT_LEN_MAX,    "shortest candidate" },
    { "pw-max",       FEED_PARAM_TYPE_U64,  &pw_max,       1, PRINCE_OUT_LEN_MAX,    "longest candidate, 16 by default as in pp" },
    { "elem-cnt-min", FEED_PARAM_TYPE_U64,  &elem_cnt_min, 1, PRINCE_OUT_LEN_MAX,    "fewest elements per chain" },
    { "elem-cnt-max", FEED_PARAM_TYPE_U64,  &elem_cnt_max, 0, PRINCE_OUT_LEN_MAX,    "most elements per chain, 0 for the default of min(pw-max, 8); past 8 the longer chains are skipped" },
    { "wl-max",       FEED_PARAM_TYPE_U64,  &wl_max,       0, 0xffffffffffffffffULL, "most words to read, 0 for all of them" },
    { "wl-dist-len",  FEED_PARAM_TYPE_BOOL, &wl_dist_len,  0, 0,                     "take the per length quotas from the wordlist, as in pp" },
    { "kbits",        FEED_PARAM_TYPE_U64,  &kbits,        4, PRINCE_KBITS_MAX,      "inner loop width as a power of two" },
    { NULL, 0, NULL, 0, 0, NULL }
  };

  if (feed_param_parse (global_ctx->workc, global_ctx->workv, params, global_ctx->error_msg, sizeof (global_ctx->error_msg)) == false)
  {
    global_ctx->error = true;

    return false;
  }

  // One positional argument, the wordlist, the same shape pp takes.

  int pos_cnt = 0;

  const char *wl_path = NULL;

  for (int i = 1; i < global_ctx->workc; i++)
  {
    if (feed_param_is_setting (global_ctx->workv[i]) == true) continue;

    if (pos_cnt == 0) wl_path = global_ctx->workv[i];

    pos_cnt++;
  }

  if ((pos_cnt != 1) || (wl_path == NULL))
  {
    error_set (global_ctx, "usage: prince <wordlist> [pw-min=%d] [pw-max=%d] [elem-cnt-min=%d] [elem-cnt-max=N] [wl-max=N] [wl-dist-len=1] [kbits=%d]", PRINCE_PW_MIN_DEF, PRINCE_PW_MAX_DEF, PRINCE_ELEM_CNT_MIN_DEF, PRINCE_KBITS_DEF);

    return false;
  }

  if (pw_min > pw_max)
  {
    error_set (global_ctx, "prince: pw-min (%" PRIu64 ") must be smaller or equal than pw-max (%" PRIu64 ")", pw_min, pw_max);

    return false;
  }

  if (elem_cnt_max == 0) elem_cnt_max = MIN (pw_max, PCFG_DEV_MAXSLOT);

  if (elem_cnt_min > elem_cnt_max)
  {
    error_set (global_ctx, "prince: elem-cnt-min (%" PRIu64 ") must be smaller or equal than elem-cnt-max (%" PRIu64 ")", elem_cnt_min, elem_cnt_max);

    return false;
  }

  pg->pw_min       = (u32) pw_min;
  pg->pw_max       = (u32) pw_max;
  pg->elem_cnt_min = (u32) elem_cnt_min;
  pg->elem_cnt_max = (u32) elem_cnt_max;
  pg->wl_max       = wl_max;
  pg->il_cnt       = (u32) 1 << kbits;
  pg->wl_dist_len  = wl_dist_len;

  // The hash mode's length window, where there is one. A chain whose output length cannot produce a
  // candidate the mode accepts is left out, so the count the feed reports is the count the run can
  // use; the same judgment the table feed makes per word.

  if (hashcat_ctx != NULL)
  {
    const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

    if (hashconfig != NULL)
    {
      pg->hc_pwmin = hashconfig->pw_min;
      pg->hc_pwmax = hashconfig->pw_max;
    }
  }

  // The wordlist, read the way pp reads it: a fgets () sized buffer, every trailing CR and LF off,
  // words of 1..32 bytes that fit pw-max, duplicates dropped on the way in.

  HCFILE fp;

  if (hc_fopen (&fp, wl_path, "rb") == false)
  {
    error_set (global_ctx, "prince: %s: %s", wl_path, hc_fopen_strerror ());

    return false;
  }

  char buf[PRINCE_IOBUF];

  u64 ident = 0;

  u64 wl_cnt = 0;

  bool wl_done = false;

  while (wl_done == false)
  {
    char *line = hc_fgets (buf, sizeof (buf), &fp);

    if (line == NULL) break;

    // strlen semantics on purpose: pp works on C strings, so a NUL ends the word the same way here

    const size_t raw_len = strlen (line);

    ident = paw64 (line, raw_len, ident);

    size_t len = raw_len;

    while (len > 0)
    {
      if ((line[len - 1] != '\n') && (line[len - 1] != '\r')) break;

      len--;
    }

    if (len == 0)                 continue;
    if (len >  PRINCE_IN_LEN_MAX) continue;

    if (len > pg->pw_max)
    {
      pg->words_long++;

      continue;
    }

    bool dupe = false;

    if (prince_bucket_add (&pg->buckets[len], (const u8 *) line, (u32) len, &dupe) == false)
    {
      error_set (global_ctx, "prince: out of memory loading the wordlist");

      hc_fclose (&fp);

      return false;
    }

    if (dupe == true) pg->words_dupe++;
    else              pg->words_kept++;

    wl_cnt++;

    if ((pg->wl_max > 0) && (wl_cnt == pg->wl_max)) wl_done = true;
  }

  hc_fclose (&fp);

  // What this run is, for the brain: the bytes read, then what was asked of them.

  ident = paw64 (&pw_min,       sizeof (pw_min),       ident);
  ident = paw64 (&pw_max,       sizeof (pw_max),       ident);
  ident = paw64 (&elem_cnt_min, sizeof (elem_cnt_min), ident);
  ident = paw64 (&elem_cnt_max, sizeof (elem_cnt_max), ident);

  global_ctx->source_ident = ident;

  // The chains, one output length at a time, skipping lengths the hash mode could not take anyway.
  // Built on the stack and moved over, so a failure below frees what is already built.

  prince_group_t groups[PRINCE_OUT_LEN_MAX + 1];

  memset (groups, 0, sizeof (groups));

  u32 groups_cnt = 0;

  bool build_ok = true;

  for (u32 pw_len = pg->pw_min; pw_len <= pg->pw_max; pw_len++)
  {
    if ((pg->hc_pwmax > 0) && (pw_len > pg->hc_pwmax)) continue;
    if (pw_len < pg->hc_pwmin) continue;

    if (prince_group_build (pg, pw_len, &groups[groups_cnt]) == false)
    {
      build_ok = false;

      break;
    }

    if (groups[groups_cnt].chains_cnt == 0) continue;

    groups_cnt++;
  }

  if (build_ok == false)
  {
    for (u32 g = 0; g <= groups_cnt; g++) hcfree (groups[g].chains);

    error_set (global_ctx, "prince: out of memory building the chains");

    return false;
  }

  // The quota of each length, pp's wordlen_dist: the table, or the bucket sizes themselves under
  // wl-dist-len=1. A quota of zero is a length pp would never emit and never finish; those groups
  // leave the schedule here and run at the end instead.

  for (u32 g = 0; g < groups_cnt; g++)
  {
    const u32 pw_len = groups[g].pw_len;

    u64 quota = 0;

    if (wl_dist_len == true)
    {
      quota = (pw_len <= PRINCE_IN_LEN_MAX) ? pg->buckets[pw_len].cnt : 1;
    }
    else
    {
      quota = (pw_len < 25) ? PRINCE_WORDLEN_DIST[pw_len] : 1;
    }

    groups[g].quota = quota;
  }

  // The lengths in pp's order: by bucket size, largest first, ties by length, which a stable sort of
  // at most 32 entries gets by comparing strictly.

  for (u32 i = 1; i < groups_cnt; i++)
  {
    const prince_group_t cur = groups[i];

    u32 j = i;

    while (j > 0)
    {
      const u32 have = pg->buckets[groups[j - 1].pw_len].cnt;
      const u32 want = pg->buckets[cur.pw_len].cnt;

      if (want <= have) break;

      groups[j] = groups[j - 1];

      j--;
    }

    groups[j] = cur;
  }

  // And the split into the schedule and the tail.

  u32 main_cnt = 0;
  u32 tail_cnt = 0;

  for (u32 g = 0; g < groups_cnt; g++)
  {
    if (groups[g].quota > 0) main_cnt++;
    else                     tail_cnt++;
  }

  pg->groups = (prince_group_t *) hcmalloc ((main_cnt + 1) * sizeof (prince_group_t));
  pg->tail   = (prince_group_t *) hcmalloc ((tail_cnt + 1) * sizeof (prince_group_t));

  if ((pg->groups == NULL) || (pg->tail == NULL))
  {
    for (u32 g = 0; g < groups_cnt; g++) hcfree (groups[g].chains);

    error_set (global_ctx, "prince: out of memory building the chains");

    return false;
  }

  u128 cand_run = 0;

  for (u32 g = 0; g < groups_cnt; g++)
  {
    if (groups[g].quota == 0) continue;

    groups[g].cand_off = cand_run;

    u128 chain_run = cand_run;

    for (u32 c = 0; c < groups[g].chains_cnt; c++)
    {
      groups[g].chains[c].cand_off = chain_run;

      chain_run = prince_sat_add (pg, chain_run, groups[g].chains[c].ks);
    }

    cand_run = prince_sat_add (pg, cand_run, groups[g].cand_len);

    pg->groups[pg->groups_cnt] = groups[g];

    pg->groups_cnt++;
  }

  pg->main_total = cand_run;

  for (u32 g = 0; g < groups_cnt; g++)
  {
    if (groups[g].quota > 0) continue;

    groups[g].cand_off = cand_run;

    u128 chain_run = cand_run;

    for (u32 c = 0; c < groups[g].chains_cnt; c++)
    {
      groups[g].chains[c].cand_off = chain_run;

      chain_run = prince_sat_add (pg, chain_run, groups[g].chains[c].ks);
    }

    cand_run = prince_sat_add (pg, cand_run, groups[g].cand_len);

    pg->tail[pg->tail_cnt] = groups[g];

    pg->tail_cnt++;
  }

  pg->cand_total = cand_run;

  // The pool: every bucket's entries laid end to end, twice per bucket, so that a slot pointed s
  // entries into a bucket walks it as if entry s came first. That is what lets a unit start at any
  // position of a chain.

  u64 pool_bytes = 0;

  for (u32 len = 1; len <= PRINCE_IN_LEN_MAX; len++)
  {
    const u64 need = 2 * (u64) pg->buckets[len].cnt * len;

    if ((pool_bytes + need) > 0xfffffffcULL)
    {
      for (u32 g = 0; g < groups_cnt; g++) hcfree (groups[g].chains);

      error_set (global_ctx, "prince: the pool needs more than 4 GiB, which is what a slot can address");

      return false;
    }

    pool_bytes += need;
  }

  // one u32 of slack, so a read at the very end stays inside the allocation

  pg->pool = (u32 *) hccalloc ((pool_bytes / 4) + 2, sizeof (u32));

  if (pg->pool == NULL)
  {
    for (u32 g = 0; g < groups_cnt; g++) hcfree (groups[g].chains);

    error_set (global_ctx, "prince: out of memory building the pool");

    return false;
  }

  pg->pool_size = pool_bytes;

  u8 *pb = (u8 *) pg->pool;

  u64 at = 0;

  for (u32 len = 1; len <= PRINCE_IN_LEN_MAX; len++)
  {
    prince_bucket_t *bk = &pg->buckets[len];

    bk->pool_off = (u32) at;

    const u64 need = (u64) bk->cnt * len;

    for (u64 i = 0; i < need; i++) pb[at + i] = bk->words[i];

    at += need;

    for (u64 i = 0; i < need; i++) pb[at + i] = bk->words[i];

    at += need;
  }

  // The exact unit count, where the walk to get it is short enough to be worth it. A unit ends at
  // a slice end, a chain end or the il_cnt horizon, so the honest bound is all three kinds of
  // boundary added up. It saturates instead of wrapping: a saturated candidate count collapses the
  // quota to one, and a plain sum of these pieces wraps small and lets a huge walk through the
  // gate. The walk itself stops at the same cap regardless, because a bound is a bound until the
  // walk proves it.

  pg->counted = false;

  u128 units_est = 0;

  for (u32 g = 0; g < pg->groups_cnt; g++)
  {
    const prince_group_t *grp = &pg->groups[g];

    units_est = prince_est_add (units_est, grp->cand_len / pg->il_cnt);
    units_est = prince_est_add (units_est, grp->cand_len / grp->quota);
    units_est = prince_est_add (units_est, grp->chains_cnt + 2);
  }

  for (u32 g = 0; g < pg->tail_cnt; g++)
  {
    const prince_group_t *grp = &pg->tail[g];

    units_est = prince_est_add (units_est, grp->cand_len / pg->il_cnt);
    units_est = prince_est_add (units_est, grp->chains_cnt + 1);
  }

  if (units_est <= PRINCE_COUNT_MAX_UNITS)
  {
    prince_thread_t wt;

    memset (&wt, 0, sizeof (wt));

    prince_rewind (pg, &wt);

    u128 units = 0;

    while ((units < PRINCE_COUNT_MAX_UNITS) && (prince_walk_unit (pg, &wt, NULL, NULL, 0) > 0)) units++;

    if (units < PRINCE_COUNT_MAX_UNITS)
    {
      pg->units_total = units;
      pg->counted     = true;
    }
  }

  // What the device engine is told: the mean and front rectangles and the first real cell as the
  // autotuner's probe. The front is measured over the first units rather than assumed, because the
  // first slices of a round are not necessarily wide.

  pg->dev_avg   = 1;
  pg->dev_front = 1;
  pg->dev_step  = 1;

  memset (&pg->probe, 0, sizeof (pcfg_cell_t));

  if (pg->cand_total > 0)
  {
    if (pg->counted == true)
    {
      const u128 mean = pg->cand_total / pg->units_total;

      if (mean > 0xffffffffULL) pg->dev_avg = 0xffffffff;
      else                      pg->dev_avg = (u32) mean;
    }
    else
    {
      pg->dev_avg = MIN (276252, pg->il_cnt);
    }

    prince_thread_t ft;

    memset (&ft, 0, sizeof (ft));

    prince_rewind (pg, &ft);

    u64 front_sum = 0;
    u64 front_cnt = 0;

    pcfg_cell_t cell;

    u8 base[PRINCE_OUT_LEN_MAX];

    while (front_cnt < 4096)
    {
      memset (&cell, 0, sizeof (pcfg_cell_t));

      const int rc = prince_walk_unit (pg, &ft, &cell, base, sizeof (base));

      if (rc <= 0) break;

      if (front_cnt == 0) memcpy (&pg->probe, &cell, sizeof (pcfg_cell_t));

      // the width of the unit in candidates, not the base word's length the call returns

      if ((front_sum + cell.rect) < front_sum)
      {
        front_sum = 0xffffffffffffffffULL;
      }
      else
      {
        front_sum += cell.rect;
      }

      front_cnt++;
    }

    if (front_cnt > 0)
    {
      const u64 front = front_sum / front_cnt;

      if (front > 0xffffffffULL) pg->dev_front = 0xffffffff;
      else                       pg->dev_front = (u32) front;
    }

    if (pg->groups_cnt > 0) pg->dev_step = pg->groups[0].chains[0].elems[0];
    else                    pg->dev_step = pg->tail[0].chains[0].elems[0];
  }

  // What the status line calls this attack.

  snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s", wl_path);

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  prince_global_t *pg = global_ctx->gbldata;

  if (pg == NULL) return;

  for (u32 len = 1; len <= PRINCE_IN_LEN_MAX; len++)
  {
    hcfree (pg->buckets[len].words);
    hcfree (pg->buckets[len].hmap);
  }

  for (u32 g = 0; g < pg->groups_cnt; g++) hcfree (pg->groups[g].chains);
  for (u32 g = 0; g < pg->tail_cnt;   g++) hcfree (pg->tail[g].chains);

  hcfree (pg->groups);
  hcfree (pg->tail);
  hcfree (pg->pool);

  hcfree (pg);

  global_ctx->gbldata = NULL;
}

bool global_dev_init (generic_global_ctx_t *global_ctx, const u32 **pool, u64 *pool_size, u32 *il_cnt, u32 *avg, u32 *maxword, u32 *front, u32 *step, u32 *varlen, pcfg_cell_t *probe)
{
  prince_global_t *pg = global_ctx->gbldata;

  pool[0]      = pg->pool;
  pool_size[0] = pg->pool_size;
  il_cnt[0]    = pg->il_cnt;
  avg[0]       = pg->dev_avg;
  maxword[0]   = PCFG_DEV_MAXWORD;
  front[0]     = pg->dev_front;
  step[0]      = pg->dev_step;
  varlen[0]    = 0;

  memcpy (probe, &pg->probe, sizeof (pcfg_cell_t));

  // A pool the weakest device cannot hold turns the run into a host engine run rather than an error.

  if ((global_ctx->dev_pool_max > 0) && (pg->pool_size > global_ctx->dev_pool_max))
  {
    feed_say (pg->hcctx, "prince: the pool needs %" PRIu64 " MiB and the weakest device offers %" PRIu64 " MiB, so the host engine takes the run", pg->pool_size / (1024 * 1024), global_ctx->dev_pool_max / (1024 * 1024));

    il_cnt[0] = 0;

    pg->dev = false;
  }

  return true;
}

u128 global_keyspace_u128 (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  prince_global_t *pg = global_ctx->gbldata;

  pg->dev = global_ctx->dev_enable;

  feed_say (pg->hcctx, "prince: %" PRIu64 " words kept, %" PRIu64 " duplicates dropped", pg->words_kept, pg->words_dupe);

  if (pg->words_long > 0)
  {
    feed_say (pg->hcctx, "prince: %" PRIu64 " words longer than pw-max left out", pg->words_long);
  }

  if (pg->chains_skipped > 0)
  {
    char skip_buf[U128_DEC_SIZE];

    feed_say (pg->hcctx, "prince: %" PRIu64 " chains have more than %d elements and were skipped, %s candidates left out", pg->chains_skipped, PCFG_DEV_MAXSLOT, u128_to_dec (skip_buf, pg->cands_skipped));
  }

  if (pg->tail_cnt > 0)
  {
    feed_say (pg->hcctx, "prince: %u lengths have a quota of zero (pp would not finish them); they run last", pg->tail_cnt);
  }

  if (pg->sat == true)
  {
    feed_say (pg->hcctx, "prince: the keyspace does not fit 128 bits, so the run goes without a total");

    return GENERIC_KEYSPACE_UNKNOWN_U128;
  }

  char cand_buf[U128_DEC_SIZE];

  if (global_ctx->dev_enable == true)
  {
    // The exact candidate count, so the run is measured against the truth rather than against the
    // keyspace times a rounded mean.

    global_ctx->dev_total_u128 = pg->cand_total;

    if (pg->counted == true)
    {
      char unit_buf[U128_DEC_SIZE];

      feed_say (pg->hcctx, "prince: device engine, %s base words for %s candidates", u128_to_dec (unit_buf, pg->units_total), u128_to_dec (cand_buf, pg->cand_total));

      const u128 r = pg->units_total;

      return r;
    }

    feed_say (pg->hcctx, "prince: device engine, %s candidates, unit count not tracked at this size", u128_to_dec (cand_buf, pg->cand_total));

    return GENERIC_KEYSPACE_UNKNOWN_U128;
  }

  feed_say (pg->hcctx, "prince: host engine, %s candidates", u128_to_dec (cand_buf, pg->cand_total));

  const u128 r = pg->cand_total;

  return r;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  prince_thread_t *pt = hccalloc (1, sizeof (prince_thread_t));

  if (pt == NULL)
  {
    thread_error_set (thread_ctx, "hccalloc failed");

    return false;
  }

  prince_global_t *pg = global_ctx->gbldata;

  prince_rewind (pg, pt);

  thread_ctx->thrdata = pt;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  hcfree (thread_ctx->thrdata);

  thread_ctx->thrdata = NULL;
}

int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  prince_global_t *pg = global_ctx->gbldata;
  prince_thread_t *pt = thread_ctx->thrdata;

  const int len = prince_walk_cand (pg, pt, out_buf, out_size);

  if (len == 0) return GENERIC_RC_EOF;

  if (len < 0) return GENERIC_RC_ERROR;

  return len;
}

int thread_next_dev (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size, pcfg_cell_t *cell)
{
  prince_global_t *pg = global_ctx->gbldata;
  prince_thread_t *pt = thread_ctx->thrdata;

  const int len = prince_walk_unit (pg, pt, cell, out_buf, out_size);

  if (len == 0) return GENERIC_RC_EOF;

  if (len < 0) return GENERIC_RC_ERROR;

  return len;
}

bool thread_seek_u128 (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u128 offset)
{
  prince_global_t *pg = global_ctx->gbldata;
  prince_thread_t *pt = thread_ctx->thrdata;

  if (pg->dev == true)
  {
    // Units do not decompose arithmetically, so a seek walks. Forward from where the thread is,
    // from the start when the target is behind it.

    if (offset < pt->pos) prince_rewind (pg, pt);

    while (pt->pos < offset)
    {
      const int len = prince_walk_unit (pg, pt, NULL, NULL, 0);

      if (len <= 0) break;
    }

    return true;
  }

  prince_place (pg, pt, offset);

  return true;
}

// How this candidate was made, for --debug-mode: the words the cell chose, joined the way the
// candidate joins them.

int global_explain_u128 (generic_global_ctx_t *global_ctx, const pcfg_cell_t *cell, MAYBE_UNUSED const u32 *pool, MAYBE_UNUSED const u8 *base, MAYBE_UNUSED const int base_len, const u32 il_pos, MAYBE_UNUSED const u128 pos, char *out_buf, const int out_size)
{
  if (cell == NULL) return -1;

  prince_global_t *pg = global_ctx->gbldata;

  if (pg == NULL) return -1;

  const u32 slot_cnt = (cell->slot_cnt < PCFG_DEV_MAXSLOT) ? cell->slot_cnt : PCFG_DEV_MAXSLOT;

  if (slot_cnt == 0) return 0;

  const u8 *pb = (const u8 *) pg->pool;

  u32 digit[PCFG_DEV_MAXSLOT];

  u64 carry = il_pos;

  for (int j = (int) slot_cnt - 1; j >= 0; j--)
  {
    const u32 radix = cell->slots[j].radix;

    if (radix == 0) return -1;

    digit[j] = (u32) (carry % radix);

    carry = carry / radix;
  }

  if (carry != 0) return -1;

  int len = 0;

  // candidate order is element order, and the fastest element sits in the last slot

  for (int j = (int) slot_cnt - 1; j >= 0; j--)
  {
    const u32 ent_len = PCFG_SLOT_ENT_LEN (cell->slots[j].packed);

    const u32 src = cell->slots[j].pool_off + (digit[j] * ent_len);

    if (len > 0)
    {
      if (len >= out_size) break;

      out_buf[len] = '+';

      len++;
    }

    for (u32 i = 0; i < ent_len; i++)
    {
      if (len >= out_size) break;

      out_buf[len] = (char) pb[src + i];

      len++;
    }
  }

  return len;
}

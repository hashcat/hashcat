/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The escape's walk over the packed pool, in one place.
//
// Two things walk it and they have to agree exactly: the kernel, which decides which candidate
// matched a hash, and pcfg_expand () on the host, which says what that candidate was. Written twice,
// whichever copy was edited alone would quietly put a wrong password in the potfile.
//
// So this file is the order, once. The kernel includes it as device code and src/emu_inc_pcfg_omen.c
// includes it as host code, the same arrangement hashcat uses for the rule engine. inc_vendor.h
// empties the address space qualifiers for a host build and turns DECLSPEC into the export macro,
// so the same text compiles both ways.

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_pcfg_pool.h"
#include "inc_pcfg.h"
#include "inc_pcfg_omen.h"

// The escape is walked a candidate at a time.
//
// The escape is a ranked space, so a candidate can be found from its rank alone, and that is what
// omen_unrank () in the feed and pcfg_expand () in src/shared.c do. Doing it per candidate is what
// made the device pay about twenty times a candidate of the grammar: the rank has to be spent again
// on every choice, and every read depends on the one before it, so none of it overlaps.
//
// A cell walks consecutive ranks, and consecutive ranks differ in almost nothing. So the rank is spent
// once, on the first candidate of the cell, and after that the walk is stepped like the odometer the
// grammar's cells use: find the last position with another transition left, take it, and refill what
// comes after with the cheapest live one. That is omen_next () in the feed, and it holds the same
// order, because the order the odometer walks is the order the ranks were numbered in.
//
// What the walk holds is ti, which transition each position took, and beside it the context each
// position starts from and the budget left there. Those two follow from ti, but the step asks them of
// one position rather than of the first, so keeping them costs less than walking up to them.

// Everything the model's tables are reached through, resolved once per cell.

DECLSPEC void pcfg_omen_model (PCFG_POOL_ARGS, const u32 dir_at, const u32 model_idx, PRIVATE_AS pcfg_omen_model_t *m)
{
  const u32 dir = dir_at;

  const u32 model = dir + pcfg_pool_u32 (PCFG_POOL_PASS, dir + PCFG_OMEN_DIR_AT (model_idx));

  m->ctx_cnt = pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_CTX_CNT);
  m->len_cnt = pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_LEN_CNT);

  // both tables are indexed from zero up to and including the max, so the strides are one more

  m->budget_span = pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_BUDGET_MAX) + 1;
  m->step_span   = pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_STEP_MAX) + 1;

  m->ctx_at    = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_CTX_AT);
  m->trans     = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_TRANS_AT);
  m->start_ctx = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_START_CTX_AT);
  m->start_off = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_START_OFF_AT);
  m->start_len = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_START_LEN_AT);
  m->start_lvl = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_START_LVL_AT);
  m->len_cost  = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_LEN_COST_AT);
  m->len_steps = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_LEN_STEPS_AT);
  m->weight    = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_WEIGHT_AT);
  m->start_sum = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_STARTSUM_AT);

  m->chars = (model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_CHARS_AT)) * 4;
  m->wbit  = model + pcfg_pool_u32 (PCFG_POOL_PASS, model + PCFG_OMEN_WBIT_AT);
}

// How many candidates finish from this context with these steps and this budget left. Zero means the
// walk cannot end here, which is what makes a transition dead.

DECLSPEC u64 pcfg_omen_weight (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const int left, const int budget, const u32 ctx)
{
  const u32 at = (u32) ((left * m->budget_span + budget) * m->ctx_cnt + ctx);

  const u64 v = pcfg_pool_u64 (PCFG_POOL_PASS, m->weight + (at * 2));

  return v;
}

// Whether anything finishes from here at all, which is all the walk asks between one candidate and the
// next. One bit rather than eight bytes, so the question is answered out of a table that is a sixty
// fourth of the counts and stands a chance of staying in cache.

DECLSPEC bool pcfg_omen_alive (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const int left, const int budget, const u32 ctx)
{
  const u32 at = (u32) ((left * m->budget_span + budget) * m->ctx_cnt + ctx);

  const bool set = ((pcfg_pool_lo (PCFG_POOL_PASS, m->wbit + (at / 32)) >> (at % 32)) & 1) == 1;

  return set;
}

// One transition: four adjacent words off the first buffer.
//
// The transition table is written ahead of the weights, so it is always in the first buffer and the
// read does not go through the search. That matters here more than anywhere: the walk reads a
// transition every step of every candidate, and going through the search made each of the four
// words its own region the compiler could neither merge nor hoist out of the innermost loop, which
// costs an order of magnitude in instructions and in global reads per candidate. Read off one
// pointer they are four ordinary loads again.

DECLSPEC void pcfg_omen_trans (PCFG_POOL_ARGS, const u32 t, PRIVATE_AS u32 *v)
{
  GLOBAL_AS const u32 *p = pool0 + t;

  v[PCFG_OMEN_TRANS_DST]  = p[PCFG_OMEN_TRANS_DST];
  v[PCFG_OMEN_TRANS_OFF]  = p[PCFG_OMEN_TRANS_OFF];
  v[PCFG_OMEN_TRANS_LEN]  = p[PCFG_OMEN_TRANS_LEN];
  v[PCFG_OMEN_TRANS_COST] = p[PCFG_OMEN_TRANS_COST];
}

// The first transition out of this context, at or after from, that the budget can pay for and that
// something finishes from. The list is ordered by cost, so it stops at the first one too dear.

DECLSPEC u32 pcfg_omen_live (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const u32 ctx, const int budget, const int left, const u32 from)
{
  const u32 last = pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx + 1));

  for (u32 e = from; e < last; e++)
  {
    u32 tv[PCFG_OMEN_TRANS_WORDS];

    pcfg_omen_trans (PCFG_POOL_PASS, m->trans + (e * PCFG_OMEN_TRANS_WORDS), tv);

    const int cost = (int) tv[PCFG_OMEN_TRANS_COST];

    if (cost > budget) break;

    if (pcfg_omen_alive (PCFG_POOL_PASS, m, left, budget - cost, tv[PCFG_OMEN_TRANS_DST]) == false) continue;

    return e;
  }

  return last;
}

// Every position from p onwards takes the first live transition, which is the lowest ranked candidate
// under whatever was chosen before p.

DECLSPEC bool pcfg_omen_fill (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, PRIVATE_AS pcfg_omen_walk_t *ow, const int p, u32 ctx, int budget)
{
  #if PCFG_OMEN_TOPREG

  // The last position written is the deepest one, and it lives in the scalars. It is handled after
  // the loop rather than behind a test inside it: lanes of a wave reach it at different trips, so a
  // test would make every trip carry both the array write and the scalar one.

  const int top = ow->steps - 1;

  for (int q = p; q < top; q++)
  {
    const u32 e = pcfg_omen_live (PCFG_POOL_PASS, m, ctx, budget, ow->steps - q - 1, pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx)));

    if (e >= pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx + 1))) return false;

    ow->ti[q]  = e;
    ow->ctx[q] = ctx;
    ow->bud[q] = (u8) budget;

    u32 tv[PCFG_OMEN_TRANS_WORDS];

    pcfg_omen_trans (PCFG_POOL_PASS, m->trans + (e * PCFG_OMEN_TRANS_WORDS), tv);

    ctx     = tv[PCFG_OMEN_TRANS_DST];
    budget -= (int) tv[PCFG_OMEN_TRANS_COST];
  }

  if (p <= top)
  {
    const u32 e = pcfg_omen_live (PCFG_POOL_PASS, m, ctx, budget, 0, pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx)));

    if (e >= pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx + 1))) return false;

    ow->top_ti  = e;
    ow->top_ctx = ctx;
    ow->top_bud = (u8) budget;
  }

  #else

  for (int q = p; q < ow->steps; q++)
  {
    const u32 e = pcfg_omen_live (PCFG_POOL_PASS, m, ctx, budget, ow->steps - q - 1, pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx)));

    if (e >= pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx + 1))) return false;

    ow->ti[q]  = e;
    ow->ctx[q] = ctx;
    ow->bud[q] = (u8) budget;

    u32 tv[PCFG_OMEN_TRANS_WORDS];

    pcfg_omen_trans (PCFG_POOL_PASS, m->trans + (e * PCFG_OMEN_TRANS_WORDS), tv);

    ctx     = tv[PCFG_OMEN_TRANS_DST];
    budget -= (int) tv[PCFG_OMEN_TRANS_COST];
  }

  #endif

  return true;
}

// The first candidate of a work item, found from its rank.
//
// Spending a rank from the head of the model means scanning the openings of a level one at a time, and
// a large model has hundreds of thousands of them, each one costing a read of the count table. That
// scan was the whole cost of the escape on the device, and every lane of a cell paid it to arrive at
// the same place: the lanes hold consecutive ranks a cell apart, while a single opening covers
// billions, so they all land where the cell's first candidate landed.
//
// So the host hands the landing over with the cell. It already unranks that first candidate, to judge
// its length against the mode, so the landing costs it nothing. A lane starts there and walks forward
// by its own offset into the cell. Forward is all it ever needs: its rank is never below the base's,
// and the order is the order the ranks were numbered in.

DECLSPEC bool pcfg_omen_seed (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const int cost, PRIVATE_AS const pcfg_omen_land_t *ld, const u64 skip, PRIVATE_AS pcfg_omen_walk_t *ow)
{
  u64 rank = ld->rank + skip;

  u32 li   = ld->li;
  u32 sc   = ld->sc;
  u32 from = ld->i;

  // The first group is entered part way through, at the opening the landing names, and its weight was
  // already spent by whoever found it. Every group after it is entered at its head, like a walk from
  // the top of the model would.

  bool head = true;

  for (; li < m->len_cnt; li++)
  {
    const int this_len_cost = (int) pcfg_pool_lo (PCFG_POOL_PASS, m->len_cost + (li));
    const int steps         = (int) pcfg_pool_lo (PCFG_POOL_PASS, m->len_steps + (li));

    for (; ((int) sc <= PCFG_OMEN_MAXLVL) && (((int) sc + this_len_cost) <= cost); sc++)
    {
      const int budget = cost - this_len_cost - (int) sc;

      if (head == false)
      {
        const u32 group_at   = (u32) (((int) sc * m->step_span + steps) * m->budget_span + budget);
        const u64 group_span = pcfg_pool_u64 (PCFG_POOL_PASS, m->start_sum + (group_at * 2));

        if (group_span == 0) continue;

        if (rank >= group_span) { rank -= group_span; continue; }

        from = pcfg_pool_lo (PCFG_POOL_PASS, m->start_lvl + (sc));
      }

      head = false;

      for (u32 i = from; i < pcfg_pool_lo (PCFG_POOL_PASS, m->start_lvl + (sc + 1)); i++)
      {
        const u64 start_span = pcfg_omen_weight (PCFG_POOL_PASS, m, steps, budget, pcfg_pool_lo (PCFG_POOL_PASS, m->start_ctx + (i)));

        if (start_span == 0) continue;

        if (rank >= start_span) { rank -= start_span; continue; }

        ow->li         = li;
        ow->start_cost = (int) sc;
        ow->steps      = steps;
        ow->start      = i;
        ow->from       = 0;

        // and now one transition at a time, each taking the share of the rank that finishes behind it

        u32 ctx = pcfg_pool_lo (PCFG_POOL_PASS, m->start_ctx + (i));
        int bud = budget;

        for (int p = 0; p < steps; p++)
        {
          const u32 last = pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx + 1));

          u32 e = pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx));

          for (; e < last; e++)
          {
            const u32 t = m->trans + (e * PCFG_OMEN_TRANS_WORDS);

            const int tc = (int) pcfg_pool_lo (PCFG_POOL_PASS, t + PCFG_OMEN_TRANS_COST);

            if (tc > bud) break;

            const u64 span = pcfg_omen_weight (PCFG_POOL_PASS, m, steps - p - 1, bud - tc, pcfg_pool_lo (PCFG_POOL_PASS, t + PCFG_OMEN_TRANS_DST));

            if (span == 0) continue;
            if (rank < span) break;

            rank -= span;
          }

          // last is one past this context's own range, and consistent tables never leave e there

          if (e >= last) return false;

          #if PCFG_OMEN_TOPREG

          // Once per cell, so the test costs nothing worth restructuring the loop for.

          if (p == (steps - 1))
          {
            ow->top_ti  = e;
            ow->top_ctx = ctx;
            ow->top_bud = (u8) bud;
          }
          else
          {
            ow->ti[p]  = e;
            ow->ctx[p] = ctx;
            ow->bud[p] = (u8) bud;
          }

          #else

          ow->ti[p]  = e;
          ow->ctx[p] = ctx;
          ow->bud[p] = (u8) bud;

          #endif

          const u32 t = m->trans + (e * PCFG_OMEN_TRANS_WORDS);

          ctx  = pcfg_pool_lo (PCFG_POOL_PASS, t + PCFG_OMEN_TRANS_DST);
          bud -= (int) pcfg_pool_lo (PCFG_POOL_PASS, t + PCFG_OMEN_TRANS_COST);
        }

        return true;
      }
    }

    sc = 0;
  }

  return false;
}

// The next candidate after the one the walk holds, in the order the ranks were numbered in.
//
// The last position that has another transition left takes it, and everything behind it is refilled
// with the cheapest live one. When the trellis under this opening is spent the walk moves to the next
// opening, and then to the next length, which is where omen_next () in the feed goes too.

DECLSPEC bool pcfg_omen_step (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const int cost, PRIVATE_AS pcfg_omen_walk_t *ow)
{
  #if PCFG_OMEN_TOPREG

  // The deepest position first, from the scalars. Another transition there leaves nothing behind it
  // to refill, so the common case is the whole of this block and it touches no private memory.

  const int top = ow->steps - 1;

  if (top >= 0)
  {
    const u32 ctx = ow->top_ctx;
    const int bud = (int) ow->top_bud;

    const u32 e = pcfg_omen_live (PCFG_POOL_PASS, m, ctx, bud, 0, ow->top_ti + 1);

    if (e < pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx + 1)))
    {
      ow->top_ti = e;
      ow->from   = (u32) top;

      return true;
    }
  }

  for (int p = top - 1; p >= 0; p--)

  #else

  for (int p = ow->steps - 1; p >= 0; p--)

  #endif
  {
    const u32 ctx = ow->ctx[p];
    const int bud = (int) ow->bud[p];

    const u32 e = pcfg_omen_live (PCFG_POOL_PASS, m, ctx, bud, ow->steps - p - 1, ow->ti[p] + 1);

    if (e >= pcfg_pool_lo (PCFG_POOL_PASS, m->ctx_at + (ctx + 1))) continue;

    ow->ti[p] = e;

    const u32 t = m->trans + (e * PCFG_OMEN_TRANS_WORDS);

    u32 tv[PCFG_OMEN_TRANS_WORDS];

    pcfg_omen_trans (PCFG_POOL_PASS, t, tv);

    const u32 dst   = tv[PCFG_OMEN_TRANS_DST];
    const int tcost = (int) tv[PCFG_OMEN_TRANS_COST];
    const int next  = p + 1;
    const int left  = bud - tcost;

    // A dead end behind this position is not the end of the walk: go back one and take the next
    // transition there instead, which is what omen_next () in the feed does at the same point.

    if (pcfg_omen_fill (PCFG_POOL_PASS, m, ow, next, dst, left) == true)
    {
      ow->from = (u32) p;

      return true;
    }
  }

  // the trellis is spent, so on to the next opening of this cost, then the next cost, then the next
  // length, exactly the order the seed above numbered them in

  u32 li = ow->li;
  int l  = ow->start_cost;
  u32 i  = ow->start + 1;

  while (li < m->len_cnt)
  {
    const int this_len_cost = (int) pcfg_pool_lo (PCFG_POOL_PASS, m->len_cost + (li));
    const int steps         = (int) pcfg_pool_lo (PCFG_POOL_PASS, m->len_steps + (li));

    while ((l <= PCFG_OMEN_MAXLVL) && ((l + this_len_cost) <= cost))
    {
      const int budget = cost - this_len_cost - l;

      while (i < pcfg_pool_lo (PCFG_POOL_PASS, m->start_lvl + (l + 1)))
      {
        if (pcfg_omen_alive (PCFG_POOL_PASS, m, steps, budget, pcfg_pool_lo (PCFG_POOL_PASS, m->start_ctx + (i))) == true)
        {
          ow->li         = li;
          ow->start_cost = l;
          ow->steps      = steps;
          ow->start      = i;
          ow->from       = 0;

          if (pcfg_omen_fill (PCFG_POOL_PASS, m, ow, 0, pcfg_pool_lo (PCFG_POOL_PASS, m->start_ctx + (i)), budget) == true) return true;
        }

        i++;
      }

      l++;

      i = pcfg_pool_lo (PCFG_POOL_PASS, m->start_lvl + (l));
    }

    li++;

    l = 0;
    i = pcfg_pool_lo (PCFG_POOL_PASS, m->start_lvl + (0));
  }

  return false;
}

#if PCFG_OMEN_TOPREG

// One step of the walk laid into the word at len, giving back the new length, or -1 if it would not
// fit. Shared by the loop below and by the deepest position it leaves to the block after it.

DECLSPEC int pcfg_omen_put (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const u32 ti, PRIVATE_AS u32 *w, const int len, const int maxbyte)
{
  u32 tv[PCFG_OMEN_TRANS_WORDS];

  pcfg_omen_trans (PCFG_POOL_PASS, m->trans + (ti * PCFG_OMEN_TRANS_WORDS), tv);

  const int char_len = (int) tv[PCFG_OMEN_TRANS_LEN];
  const int char_off = (int) tv[PCFG_OMEN_TRANS_OFF];

  // The array is sized by the hash block and the model is not: a character is one step of the walk
  // however many bytes it takes, so a ruleset trained outside ASCII overruns without this.

  if ((len + char_len) > maxbyte) return -1;

  for (int q = 0; q < char_len; q++) pcfg_put_byte (w, len + q, pcfg_pool_byte_lo (PCFG_POOL_PASS, m->chars + (char_off + q)));

  const int len_out = len + char_len;

  return len_out;
}

#endif

// Laying the candidate the walk holds into the hash array.
//
// Returns its length in bytes, or -1 when it does not fit. It fails to fit only where the bound was
// forced below what the model needs. Left alone the feed picks a bound that holds it, and says so
// when it cannot.
//
// The bound is asked for rather than read off PCFG_DEV_MAXBYTE, because the two callers do not have
// the same one. The kernel's is the array the hash is built in, which the run's maxword sizes. The
// host copy is compiled once, with no build option, so that constant is the default there whatever
// the run chose: reading it would have the host refuse a candidate the device had just produced, and
// report the base word for a crack the escape found.

DECLSPEC int pcfg_omen_emit (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, PRIVATE_AS pcfg_omen_walk_t *ow, PRIVATE_AS u32 *w, const u32 words, const int maxbyte)
{
  const u32 from = ow->from;

  int len;

  if (from == 0)
  {
    const int open_len = (int) pcfg_pool_lo (PCFG_POOL_PASS, m->start_len + (ow->start));
    const int open_off = (int) pcfg_pool_lo (PCFG_POOL_PASS, m->start_off + (ow->start));

    if (open_len > maxbyte) return -1;

    for (u32 i = 0; i < words; i++) w[i] = 0;

    for (int q = 0; q < open_len; q++) pcfg_put_byte (w, q, pcfg_pool_byte_lo (PCFG_POOL_PASS, m->chars + (open_off + q)));

    len = open_len;
  }
  else
  {
    // What is in front of the changed position is the word that was laid out last time, so it is
    // already in the array and only the tail is written again.

    len = (int) ow->boff[from];
  }

  #if PCFG_OMEN_TOPREG

  // As in fill, the deepest position comes after the loop rather than behind a test inside it: lanes
  // of a wave reach it at different trips, and a test would make every trip carry both reads.

  const int top = ow->steps - 1;

  for (int p = (int) from; p < top; p++)
  {
    ow->boff[p] = (u16) len;

    len = pcfg_omen_put (PCFG_POOL_PASS, m, ow->ti[p], w, len, maxbyte);

    // The positions behind this one are already written and the ones in front of it are not, so the
    // array holds this candidate as far as it got. Laying the next one out from the opening is right
    // whatever this one left behind, and it costs nothing because this candidate is given up anyway.
    //
    // pcfg_omen_step () writes ow->from again before the next emit, so the zero here does not survive
    // to be read. It does not have to. A position appends at least one byte, so the length grows with
    // the depth of the walk: once a prefix has overrun, every deeper continuation overruns as well,
    // and the next candidate that is emitted at all changes a position at or above the one that gave
    // up. boff for that position was written by the loop above before the put that failed, and the
    // positions in front of it were not touched, so the array and the offsets agree either way.
    //
    // The run that checks it on a model mixing a one byte and a four byte character is in the pull
    // request: what overruns the array is lost and nothing below the bound is.

    if (len < 0) { ow->from = 0; return -1; }
  }

  if ((int) from <= top)
  {
    ow->boff[top] = (u16) len;

    len = pcfg_omen_put (PCFG_POOL_PASS, m, ow->top_ti, w, len, maxbyte);

    if (len < 0) { ow->from = 0; return -1; }
  }

  #else

  for (int p = (int) from; p < ow->steps; p++)
  {
    ow->boff[p] = (u16) len;

    const u32 t = m->trans + (ow->ti[p] * PCFG_OMEN_TRANS_WORDS);

    u32 tv[PCFG_OMEN_TRANS_WORDS];

    pcfg_omen_trans (PCFG_POOL_PASS, t, tv);

    const int char_len = (int) tv[PCFG_OMEN_TRANS_LEN];
    const int char_off = (int) tv[PCFG_OMEN_TRANS_OFF];

    // The array is sized by the hash block and the model is not: a character is one step of the walk
    // however many bytes it takes, so a ruleset trained outside ASCII overruns without this. What is
    // in the array when that happens belongs to neither candidate, so the next one is laid out from
    // the opening rather than from the step that changed.

    if ((len + char_len) > maxbyte) { ow->from = 0; return -1; }

    for (int q = 0; q < char_len; q++) pcfg_put_byte (w, len + q, pcfg_pool_byte_lo (PCFG_POOL_PASS, m->chars + (char_off + q)));

    len += char_len;
  }

  #endif

  ow->boff[ow->steps] = (u16) len;

  // A shorter candidate than the one before it would leave that one's tail behind, and the hash is
  // built out of whole words, so what follows the length is cleared rather than left. Only where the
  // tail alone was written: a word laid out from the opening was cleared before it was written, and
  // clearing it twice is what a candidate costs on a backend that always takes that path.

  if (from != 0)
  {
    for (int q = len; (q & 3) != 0; q++) pcfg_put_byte (w, q, 0);

    for (u32 i = (u32) ((len + 3) >> 2); i < words; i++) w[i] = 0;
  }

  return len;
}

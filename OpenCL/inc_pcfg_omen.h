/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_PCFG_OMEN_H
#define INC_PCFG_OMEN_H

// bud[] and top_bud hold a budget, and a budget never exceeds the model's ceiling, which
// omen_load_one () caps at the size of its prob[] table. The two are set in different files and
// nothing ties them together, so tie them here: raise PCFG_OMEN_MAXLVL far enough and these fields
// truncate without a word, which is the host and the device walking two different trellises.

#if (((PCFG_OMEN_MAXLVL) * 8) + 1) > 255
#error "PCFG_OMEN_MAXLVL is too large for the u8 budget in pcfg_omen_walk_t"
#endif

// One walk through the trellis: li is the length being built, start the opening it began at and
// start_cost what that opening spent, and steps how many transitions the length takes. from is the
// lowest step whose character has changed since the word was last laid out, and boff where each
// step's character begins in it. A step of the walk moves one position and refills behind it, so
// everything in front of that position is the word that was already written: laying it out again
// from the opening rewrote the whole candidate to change its last letter.

typedef struct
{
  u32 li;
  int start_cost;
  int steps;
  u32 start;
  u32 from;

  #if PCFG_OMEN_TOPREG

  // The deepest position of the walk, held here rather than at the end of the arrays below. It is at
  // one fixed offset for every lane of a wave, where ti[steps - 1] is at an offset that differs from
  // lane to lane.

  u32 top_ti;
  u32 top_ctx;
  u8  top_bud;

  #endif

  u32 ti  [PCFG_OMEN_MAXK];
  u32 ctx [PCFG_OMEN_MAXK];
  u8  bud [PCFG_OMEN_MAXK];

  // Where each step's character begins, which is what lets the word be written again from the step that
  // changed rather than from the opening. Sixteen bits each, which is what the wider of the two bounds
  // needs: the kernel stops a candidate at PCFG_DEV_MAXBYTE, 255 on the widest array, and the host copy at
  // PCFG_OMEN_MAXBYTE, 256. A row of words would be four times the size for nothing, and this state is
  // private memory, which one runtime throttles the dispatch over once there is enough of it.

  u16 boff[PCFG_OMEN_MAXK + 1];

} pcfg_omen_walk_t;

typedef struct
{
  // Words from the start of the pool, and chars in bytes. A u32 reaches all of it: the pool cannot
  // pass 2^32 words, which is what a cell addresses and what the feed refuses to exceed. Held any
  // wider these twelve take twenty-four registers instead of twelve, and every address they build
  // costs 64 bit arithmetic, in a kernel that has no registers to spare.

  u32 ctx_at;
  u32 trans;
  u32 start_ctx;
  u32 start_off;
  u32 start_len;
  u32 start_lvl;
  u32 len_cost;
  u32 len_steps;
  u32 weight;
  u32 start_sum;
  u32 chars;
  u32 wbit;

  u32 ctx_cnt;
  u32 budget_span;
  u32 step_span;
  u32 len_cnt;

} pcfg_omen_model_t;

// Where the rank of a cell's first candidate came to rest: which length and opening cost it chose,
// which opening, and what was left of it at the head of that opening.

typedef struct
{
  u32 li;
  u32 sc;
  u32 i;
  u64 rank;

} pcfg_omen_land_t;

DECLSPEC void pcfg_omen_model (PCFG_POOL_ARGS, const u32 dir_at, const u32 model_idx, PRIVATE_AS pcfg_omen_model_t *m);
DECLSPEC u64 pcfg_omen_weight (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const int left, const int budget, const u32 ctx);
DECLSPEC bool pcfg_omen_alive (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const int left, const int budget, const u32 ctx);
DECLSPEC u32 pcfg_omen_live (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const u32 ctx, const int budget, const int left, const u32 from);

#if PCFG_OMEN_TOPREG
DECLSPEC int pcfg_omen_put (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const u32 ti, PRIVATE_AS u32 *w, const int len, const int maxbyte);
#endif

DECLSPEC bool pcfg_omen_fill (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, PRIVATE_AS pcfg_omen_walk_t *ow, const int p, u32 ctx, int budget);
DECLSPEC bool pcfg_omen_seed (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const int cost, PRIVATE_AS const pcfg_omen_land_t *ld, const u64 skip, PRIVATE_AS pcfg_omen_walk_t *ow);
DECLSPEC bool pcfg_omen_step (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, const int cost, PRIVATE_AS pcfg_omen_walk_t *ow);
DECLSPEC int pcfg_omen_emit (PCFG_POOL_ARGS, PRIVATE_AS const pcfg_omen_model_t *m, PRIVATE_AS pcfg_omen_walk_t *ow, PRIVATE_AS u32 *w, const u32 words, const int maxbyte);

#endif // INC_PCFG_OMEN_H

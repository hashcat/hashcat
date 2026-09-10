/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_pcfg.h"

DECLSPEC u32 pcfg_pool_byte (PCFG_POOL_ARGS, const u32 off)
{
  // A byte is loaded as a byte. Reading the word around it and shifting the byte out, together with a
  // copy that accumulates words, measured 54.3 ms of kernel time against 48.5 on an RX 6900 XT under
  // HIP at identical work, and the same either way on CUDA.

  #if PCFG_POOL_SPLIT == 0

  GLOBAL_AS const u8 *pb = (GLOBAL_AS const u8 *) pool0;

  const u32 b = pb[off];

  return b;

  #else

  u32 base = 0;
  u32 end  = 0;

  GLOBAL_AS const u32 *p = pcfg_pool_span (PCFG_POOL_PASS, off / 4, &base, &end);

  GLOBAL_AS const u8 *pb = (GLOBAL_AS const u8 *) p;

  const u32 b = pb[off - (base * 4)];

  return b;

  #endif
}

DECLSPEC void pcfg_put_byte (PRIVATE_AS u32 *w, const u32 off, const u32 b)
{
  PRIVATE_AS u8 *wb = (PRIVATE_AS u8 *) w;

  wb[off] = (u8) b;
}

DECLSPEC u32 pcfg_get_byte (PRIVATE_AS const u32 *w, const u32 off)
{
  PRIVATE_AS const u8 *wb = (PRIVATE_AS const u8 *) w;

  const u32 b = wb[off];

  return b;
}

DECLSPEC GLOBAL_AS const u32 *pcfg_pool_span (PCFG_POOL_ARGS, MAYBE_UNUSED const u32 at, PRIVATE_AS u32 *base, PRIVATE_AS u32 *end)
{
  #if PCFG_POOL_SPLIT == 0

  base[0] = 0;
  end[0]  = 0xffffffff;

  return pool0;

  #else

  if (at < pool_at2)
  {
    if (at < pool_at1) { base[0] = 0;         end[0] = pool_at1; return pool0; }

    base[0] = pool_at1; end[0] = pool_at2; return pool1;
  }

  if (at < pool_at3) { base[0] = pool_at2;  end[0] = pool_at3; return pool2; }

  base[0] = pool_at3;
  end[0]  = 0xffffffff;

  return pool3;

  #endif
}

// The part is found once for the whole run rather than once a byte. Accumulating words and shifting
// the bytes out saves loads but puts a branch in the innermost loop of the write path, and where the
// pool is split that measured 3.3% on AMD and nothing on CUDA.

DECLSPEC void pcfg_pool_copy (PCFG_POOL_ARGS, PRIVATE_AS u32 *w, const u32 dst, const u32 src, const u32 len)
{
  if (len == 0) return;

  #if PCFG_POOL_SPLIT == 0

  GLOBAL_AS const u8 *pb = (GLOBAL_AS const u8 *) pool0;

  for (u32 k = 0; k < len; k++) pcfg_put_byte (w, dst + k, pb[src + k]);

  #else

  u32 base = 0;
  u32 end  = 0;

  GLOBAL_AS const u32 *p = pcfg_pool_span (PCFG_POOL_PASS, src / 4, &base, &end);

  // A run that ends in the part it began in is every run but the few that straddle a boundary.

  if (((src + len - 1) / 4) < end)
  {
    GLOBAL_AS const u8 *pb = (GLOBAL_AS const u8 *) p;

    const u32 off = src - (base * 4);

    for (u32 k = 0; k < len; k++) pcfg_put_byte (w, dst + k, pb[off + k]);

    return;
  }

  for (u32 k = 0; k < len; k++) pcfg_put_byte (w, dst + k, pcfg_pool_byte (PCFG_POOL_PASS, src + k));

  #endif
}

DECLSPEC u32 pcfg_pool_u32 (PCFG_POOL_ARGS, const u32 at)
{
  // The comparisons nest rather than chain. A read here is divergent, so a GPU turns each one into a
  // region under its own exec mask, and nested a lane walks two of them where chained it walks four.
  // On this kernel the two measure the same, because a part is found once per slot and not once per
  // byte, so this is the shape that has nothing to lose.

  #if PCFG_POOL_SPLIT == 0

  const u32 v = pool0[at];

  return v;

  #else

  if (at < pool_at2)
  {
    if (at < pool_at1)
    {
      const u32 v0 = pool0[at];

      return v0;
    }

    const u32 v1 = pool1[at - pool_at1];

    return v1;
  }

  if (at < pool_at3)
  {
    const u32 v2 = pool2[at - pool_at2];

    return v2;
  }

  const u32 v3 = pool3[at - pool_at3];

  return v3;

  #endif
}

DECLSPEC u32 pcfg_ent_off (LOCAL_AS const pcfg_cell_t *cell, PCFG_POOL_ARGS, const u32 j, const u32 n)
{
  #if PCFG_DEV_VARLEN

  const u32 off = pcfg_pool_u32 (PCFG_POOL_PASS, cell->slots[j].pool_off + n);

  return off;

  #else

  const u32 off = cell->slots[j].pool_off + (n * PCFG_SLOT_ENT_LEN (cell->slots[j].packed));

  return off;

  #endif
}

DECLSPEC u32 pcfg_ent_len (LOCAL_AS const pcfg_cell_t *cell, PCFG_POOL_ARGS, const u32 j, const u32 n)
{
  #if PCFG_DEV_VARLEN

  const u32 hi = pcfg_pool_u32 (PCFG_POOL_PASS, cell->slots[j].pool_off + n + 1);
  const u32 lo = pcfg_pool_u32 (PCFG_POOL_PASS, cell->slots[j].pool_off + n);

  const u32 len = hi - lo;

  return len;

  #else

  const u32 len = PCFG_SLOT_ENT_LEN (cell->slots[j].packed);

  return len;

  #endif
}

DECLSPEC void pcfg_case_slot (LOCAL_AS const pcfg_cell_t *cell, PCFG_POOL_ARGS, LOCAL_AS const u32 *digit, PRIVATE_AS u32 *w, const u32 j)
{
  const u32 packed = cell->slots[j].packed;

  const u32 from = PCFG_SLOT_FROM (packed);

  const u32 dj = PCFG_ODO_DIGIT (digit[j]);
  const u32 df = PCFG_ODO_DIGIT (digit[from]);

  const u32 mask_len = pcfg_ent_len (cell, PCFG_POOL_PASS, j,    dj);
  const u32 tok_len  = pcfg_ent_len (cell, PCFG_POOL_PASS, from, df);

  const u32 mask_src = pcfg_ent_off (cell, PCFG_POOL_PASS, j, dj);

  #if PCFG_DEV_VARLEN

  const u32 dst_off = PCFG_ODO_POS (digit[from]);
  const u32 up_src  = pcfg_ent_off (cell, PCFG_POOL_PASS, from, df) + cell->slots[j].digit;

  #else

  const u32 dst_off = PCFG_SLOT_DST_OFF (packed);
  const u32 up_src  = cell->slots[j].digit + (df * tok_len);

  #endif

  u32 ci = 0;
  u32 at = 0;

  while ((at < tok_len) && (ci < mask_len))
  {
    if (pcfg_pool_byte (PCFG_POOL_PASS, mask_src + ci) == 'U')
    {
      pcfg_put_byte (w, dst_off + at, pcfg_pool_byte (PCFG_POOL_PASS, up_src + at));
    }

    at++;

    while (at < tok_len)
    {
      if ((pcfg_get_byte (w, dst_off + at) & 0xc0) != 0x80) break;

      if (pcfg_pool_byte (PCFG_POOL_PASS, mask_src + ci) == 'U')
      {
        pcfg_put_byte (w, dst_off + at, pcfg_pool_byte (PCFG_POOL_PASS, up_src + at));
      }

      at++;
    }

    ci++;
  }
}

DECLSPEC bool pcfg_odo_seed (LOCAL_AS const pcfg_cell_t *cell, const u32 il_pos, LOCAL_AS u32 *digit)
{
  const u32 slot_cnt = (cell->slot_cnt < PCFG_DEV_MAXSLOT) ? cell->slot_cnt : PCFG_DEV_MAXSLOT;

  u32 carry = il_pos;

  for (int j = (int) slot_cnt - 1; j >= 0; j--)
  {
    const u32 radix = cell->slots[j].radix;

    if (radix == 0) return false;

    if (carry < radix)
    {
      digit[j] = carry;

      carry = 0;
    }
    else
    {
      digit[j] = carry % radix;

      carry = carry / radix;
    }
  }

  #if PCFG_DEV_VARLEN

  if (slot_cnt > 0) digit[0] = PCFG_ODO_PACK (digit[0], PCFG_SLOT_DST_OFF (cell->slots[0].packed));

  #endif

  if (carry != 0) return false;

  return true;
}

DECLSPEC int pcfg_odo_next (LOCAL_AS const pcfg_cell_t *cell, LOCAL_AS u32 *digit)
{
  const u32 slot_cnt = (cell->slot_cnt < PCFG_DEV_MAXSLOT) ? cell->slot_cnt : PCFG_DEV_MAXSLOT;

  for (int j = (int) slot_cnt - 1; j >= 0; j--)
  {
    const u32 radix = cell->slots[j].radix;

    #if PCFG_DEV_VARLEN
    const u32 t = PCFG_ODO_DIGIT (digit[j]) + 1;
    #else
    const u32 t = digit[j] + 1;
    #endif

    if (t == radix)
    {
      digit[j] = 0;

      continue;
    }

    #if PCFG_DEV_VARLEN
    digit[j] = PCFG_ODO_PACK (t, PCFG_ODO_POS (digit[j]));
    #else
    digit[j] = t;
    #endif

    return (int) PCFG_SLOT_FROM (cell->slots[j].packed);
  }

  return -1;
}

DECLSPEC u32 pcfg_write_from (LOCAL_AS const pcfg_cell_t *cell, PCFG_POOL_ARGS, LOCAL_AS u32 *digit, PRIVATE_AS u32 *w, const u32 from)
{
  const u32 slot_cnt = (cell->slot_cnt < PCFG_DEV_MAXSLOT) ? cell->slot_cnt : PCFG_DEV_MAXSLOT;

  #if PCFG_DEV_VARLEN

  u32 pos = PCFG_ODO_POS (digit[from]);

  #endif

  for (u32 j = from; j < slot_cnt; j++)
  {
    const u32 packed = cell->slots[j].packed;

    const u32 kind = PCFG_SLOT_KIND (packed);

    if (kind == PCFG_SLOT_KIND_BYTES)
    {
      #if PCFG_DEV_VARLEN

      const u32 d = PCFG_ODO_DIGIT (digit[j]);

      digit[j] = PCFG_ODO_PACK (d, pos);

      const u32 src     = pcfg_ent_off (cell, PCFG_POOL_PASS, j, d);
      const u32 ent_len = pcfg_ent_len (cell, PCFG_POOL_PASS, j, d);
      const u32 dst_off = pos;

      pos += ent_len;

      #else

      const u32 ent_len = PCFG_SLOT_ENT_LEN (packed);
      const u32 dst_off = PCFG_SLOT_DST_OFF (packed);

      const u32 src = cell->slots[j].pool_off + (digit[j] * ent_len);

      #endif

      pcfg_pool_copy (PCFG_POOL_PASS, w, dst_off, src, ent_len);
    }
    else
    {
      pcfg_case_slot (cell, PCFG_POOL_PASS, digit, w, j);
    }
  }

  #if PCFG_DEV_VARLEN
  return pos;
  #else
  return 0;
  #endif
}

DECLSPEC u32 pcfg_write (LOCAL_AS const pcfg_cell_t *cell, PCFG_POOL_ARGS, LOCAL_AS u32 *digit, PRIVATE_AS u32 *w)
{
  const u32 len = pcfg_write_from (cell, PCFG_POOL_PASS, digit, w, 0);

  return len;
}
